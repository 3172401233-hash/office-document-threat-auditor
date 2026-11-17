"""Static OOXML threat auditor.

Parses ``[Content_Types].xml``, relationship parts, VBA projects, external
targets, embedded OLE objects and suspicious field instructions, and builds
an object reference graph. Purely static: nothing is executed or fetched.
"""

from __future__ import annotations

import posixpath
import re
import xml.etree.ElementTree as ET

from .model import (
    SEVERITY_ERROR,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    AuditReport,
    Relationship,
)
from .safezip import ContainerError, PathTraversalError, SafeZip, resolve_target


CONTENT_TYPES_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
PACKAGE_RELS_NS = "http://schemas.openxmlformats.org/package/2006/relationships"

ALLOWED_REL_NAMESPACES = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/",
    "http://purl.oclc.org/ooxml/officeDocument/relationships/",
    "http://schemas.openxmlformats.org/package/2006/relationships/",
)

VBA_PROJECT_CONTENT_TYPE = "application/vnd.ms-office.vbaProject"
OLE_OBJECT_CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.oleObject"
MACRO_ENABLED_MARKERS = ("macroEnabled",)

REL_TYPE_VBA = "vbaProject"
REL_TYPE_OLE = "oleObject"
REL_TYPE_PACKAGE = "package"
REL_TYPE_TEMPLATE = "attachedTemplate"
REL_TYPE_HYPERLINK = "hyperlink"
REL_TYPE_IMAGE = "image"

EXTERNAL_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
FIELD_INSTRUCTION_RE = re.compile(r"\b(DDEAUTO|DDE|INCLUDETEXT|INCLUDEPICTURE|HYPERLINK|LINK|IMPORT)\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://|\\\\", re.IGNORECASE)

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
STORY_PART_RE = re.compile(
    r"^word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$"
)


def _rel_type_tail(rel_type: str) -> str:
    return rel_type.rstrip("/").rsplit("/", 1)[-1]


def _source_part_for_rels(rels_file: str) -> str:
    if rels_file == "_rels/.rels":
        return ""
    directory, name = posixpath.split(rels_file)
    if not name.endswith(".rels"):
        raise ContainerError(f"not a relationship part: {rels_file!r}")
    base = posixpath.dirname(directory)
    source_name = name[: -len(".rels")]
    return posixpath.join(base, source_name) if base else source_name


def _is_rels_part(name: str) -> bool:
    if name == "_rels/.rels":
        return True
    directory, base = posixpath.split(name)
    return base.endswith(".rels") and posixpath.basename(directory) == "_rels"


class OoxmlAuditor:
    def __init__(self, max_xml_bytes: int = 32 * 1024 * 1024):
        self.max_xml_bytes = max_xml_bytes

    def audit(self, source, path: str = "<memory>") -> AuditReport:
        report = AuditReport(path=path)
        try:
            container = SafeZip(source)
        except ContainerError as exc:
            report.ok = False
            report.errors.append(str(exc))
            report.add_finding(SEVERITY_ERROR, "CONTAINER", str(exc))
            return report
        with container:
            self._parse_content_types(container, report)
            self._parse_relationships(container, report)
            self._inspect_parts(container, report)
            self._scan_field_instructions(container, report)
        return report

    def _parse_xml(self, data: bytes, part: str, report: AuditReport):
        if len(data) > self.max_xml_bytes:
            report.add_finding(
                SEVERITY_MEDIUM, "OVERSIZED_XML",
                f"XML part exceeds {self.max_xml_bytes} bytes, skipped",
                source_part=part,
            )
            return None
        try:
            return ET.fromstring(data)
        except ET.ParseError as exc:
            report.add_finding(
                SEVERITY_LOW, "MALFORMED_XML", f"XML parse error: {exc}",
                source_part=part,
            )
            return None

    def _parse_content_types(self, container: SafeZip, report: AuditReport) -> None:
        if "[Content_Types].xml" not in container:
            report.ok = False
            report.add_finding(
                SEVERITY_ERROR, "CONTAINER", "missing [Content_Types].xml"
            )
            return
        root = self._parse_xml(container.read("[Content_Types].xml"), "[Content_Types].xml", report)
        if root is None:
            report.ok = False
            return
        defaults = {}
        for child in root:
            tag = child.tag.rsplit("}", 1)[-1]
            if tag == "Default":
                defaults[child.get("Extension", "").lower()] = child.get("ContentType", "")
            elif tag == "Override":
                part = child.get("PartName", "").lstrip("/")
                report.content_types[part] = child.get("ContentType", "")
        for name in container.names():
            if name not in report.content_types:
                ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
                if ext in defaults:
                    report.content_types[name] = defaults[ext]

    def _parse_relationships(self, container: SafeZip, report: AuditReport) -> None:
        for name in container.names():
            if not _is_rels_part(name):
                continue
            root = self._parse_xml(container.read(name), name, report)
            if root is None:
                continue
            try:
                source_part = _source_part_for_rels(name)
            except ContainerError as exc:
                report.add_finding(SEVERITY_LOW, "RELS", str(exc), source_part=name)
                continue
            for rel_el in root:
                if rel_el.tag.rsplit("}", 1)[-1] != "Relationship":
                    continue
                rel = Relationship(
                    rels_file=name,
                    source_part=source_part,
                    rel_id=rel_el.get("Id", ""),
                    rel_type=rel_el.get("Type", ""),
                    target=rel_el.get("Target", ""),
                    target_mode=rel_el.get("TargetMode", "Internal"),
                )
                self._check_relationship(rel, container, report)
                report.relationships.append(rel)
                source_label = source_part or "<package>"
                target_label = rel.resolved_target or rel.target
                report.graph.setdefault(source_label, []).append(
                    (rel.rel_id, _rel_type_tail(rel.rel_type), target_label)
                )

    def _check_relationship(self, rel: Relationship, container: SafeZip, report: AuditReport) -> None:
        if not any(rel.rel_type.startswith(ns) for ns in ALLOWED_REL_NAMESPACES):
            report.add_finding(
                SEVERITY_MEDIUM, "UNKNOWN_REL_NAMESPACE",
                f"relationship type outside allowed namespaces: {rel.rel_type!r}",
                source_part=rel.source_part, target=rel.target,
            )
        tail = _rel_type_tail(rel.rel_type)
        external = rel.is_external or bool(EXTERNAL_SCHEME_RE.match(rel.target))
        if external:
            self._check_external(rel, tail, report)
            return
        try:
            rel.resolved_target = resolve_target(rel.source_part, rel.target)
        except PathTraversalError as exc:
            report.add_finding(
                SEVERITY_HIGH, "PATH_TRAVERSAL", str(exc),
                source_part=rel.source_part, target=rel.target,
            )
            return
        if rel.resolved_target not in container:
            report.add_finding(
                SEVERITY_LOW, "DANGLING_REL",
                f"relationship target not present in container: {rel.resolved_target}",
                source_part=rel.source_part, target=rel.resolved_target,
            )
        if tail == REL_TYPE_VBA:
            report.add_finding(
                SEVERITY_HIGH, "MACRO",
                "VBA project referenced via relationship",
                source_part=rel.source_part, target=rel.resolved_target,
            )
        elif tail in (REL_TYPE_OLE, REL_TYPE_PACKAGE):
            report.add_finding(
                SEVERITY_MEDIUM, "EMBEDDED_OLE",
                f"embedded object relationship ({tail})",
                source_part=rel.source_part, target=rel.resolved_target,
            )

    def _check_external(self, rel: Relationship, tail: str, report: AuditReport) -> None:
        if tail == REL_TYPE_TEMPLATE:
            report.add_finding(
                SEVERITY_HIGH, "REMOTE_TEMPLATE",
                "remote template injection candidate (attachedTemplate)",
                source_part=rel.source_part, target=rel.target,
            )
        elif tail == REL_TYPE_HYPERLINK:
            report.add_finding(
                SEVERITY_INFO, "EXTERNAL_HYPERLINK", "external hyperlink",
                source_part=rel.source_part, target=rel.target,
            )
        elif tail == REL_TYPE_IMAGE:
            report.add_finding(
                SEVERITY_MEDIUM, "EXTERNAL_IMAGE",
                "externally hosted image (tracking / fetch on open)",
                source_part=rel.source_part, target=rel.target,
            )
        elif tail in (REL_TYPE_OLE, REL_TYPE_PACKAGE):
            report.add_finding(
                SEVERITY_HIGH, "REMOTE_OLE",
                "external OLE/package object reference",
                source_part=rel.source_part, target=rel.target,
            )
        else:
            report.add_finding(
                SEVERITY_LOW, "EXTERNAL_REL",
                f"external relationship of type {tail}",
                source_part=rel.source_part, target=rel.target,
            )

    def _inspect_parts(self, container: SafeZip, report: AuditReport) -> None:
        for name in container.names():
            ctype = report.content_types.get(name, "")
            base = posixpath.basename(name)
            if ctype == VBA_PROJECT_CONTENT_TYPE or base.lower() == "vbaproject.bin":
                report.add_finding(
                    SEVERITY_HIGH, "MACRO",
                    f"VBA project part present (content-type {ctype or 'unknown'})",
                    source_part=name,
                )
            elif ctype == OLE_OBJECT_CONTENT_TYPE or "/embeddings/" in f"/{name}":
                report.add_finding(
                    SEVERITY_MEDIUM, "EMBEDDED_OLE",
                    f"embedded object part (content-type {ctype or 'unknown'})",
                    source_part=name,
                )
            if any(marker in ctype for marker in MACRO_ENABLED_MARKERS):
                report.add_finding(
                    SEVERITY_MEDIUM, "MACRO_ENABLED_FORMAT",
                    f"macro-enabled content type: {ctype}",
                    source_part=name,
                )

    def _scan_field_instructions(self, container: SafeZip, report: AuditReport) -> None:
        for name in container.names():
            if not STORY_PART_RE.match(name):
                continue
            root = self._parse_xml(container.read(name), name, report)
            if root is None:
                continue
            instructions = []
            for el in root.iter():
                tag = el.tag.rsplit("}", 1)[-1]
                if tag == "instrText" and el.text:
                    instructions.append(el.text)
                elif tag == "fldSimple":
                    instr = el.get(f"{{{W_NS}}}instr") or el.get("instr")
                    if instr:
                        instructions.append(instr)
            for raw in instructions:
                self._check_field_instruction(name, raw.strip(), report)

    def _check_field_instruction(self, part: str, instruction: str, report: AuditReport) -> None:
        match = FIELD_INSTRUCTION_RE.search(instruction)
        if not match:
            return
        keyword = match.group(1).upper()
        has_remote = bool(URL_RE.search(instruction))
        if keyword in ("DDE", "DDEAUTO"):
            report.add_finding(
                SEVERITY_HIGH, "DDE_FIELD",
                f"DDE field instruction: {instruction[:80]!r}",
                source_part=part,
            )
        elif keyword in ("INCLUDETEXT", "INCLUDEPICTURE", "IMPORT", "LINK") and has_remote:
            report.add_finding(
                SEVERITY_HIGH, "REMOTE_FIELD",
                f"{keyword} field pulls remote content: {instruction[:80]!r}",
                source_part=part,
            )
        elif keyword == "HYPERLINK" and has_remote:
            report.add_finding(
                SEVERITY_INFO, "HYPERLINK_FIELD",
                f"hyperlink field: {instruction[:80]!r}",
                source_part=part,
            )
