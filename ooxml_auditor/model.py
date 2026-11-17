"""Data model for OOXML threat audit results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


SEVERITY_INFO = "INFO"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_ERROR = "ERROR"


@dataclass
class Relationship:
    """One entry parsed from a ``.rels`` relationship part."""

    rels_file: str
    source_part: str
    rel_id: str
    rel_type: str
    target: str
    target_mode: str = "Internal"
    resolved_target: Optional[str] = None

    @property
    def is_external(self) -> bool:
        return self.target_mode.lower() == "external"


@dataclass
class Finding:
    severity: str
    category: str
    message: str
    source_part: str = ""
    target: str = ""

    def __str__(self) -> str:
        location = self.source_part or "<package>"
        detail = f" -> {self.target}" if self.target else ""
        return f"[{self.severity}] {self.category}: {self.message} ({location}{detail})"


@dataclass
class AuditReport:
    path: str = "<memory>"
    ok: bool = True
    content_types: dict = field(default_factory=dict)
    relationships: list = field(default_factory=list)
    graph: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def add_finding(self, severity, category, message, source_part="", target=""):
        self.findings.append(Finding(severity, category, message, source_part, target))

    def findings_at(self, severity):
        return [f for f in self.findings if f.severity == severity]

    @property
    def max_severity(self) -> str:
        order = [SEVERITY_ERROR, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]
        present = {f.severity for f in self.findings}
        for level in order:
            if level in present:
                return level
        return "CLEAN"
