"""Static OOXML (Office Open XML) threat auditor.

Inspects Office documents as ZIP containers and reports macros, remote
templates, external relationships, embedded OLE objects and suspicious
field instructions. Static analysis only: macros and Office content are
never executed, and no external target is ever fetched.
"""

from .auditor import OoxmlAuditor
from .model import AuditReport, Finding, Relationship
from .safezip import ContainerError, PathTraversalError, SafeZip

__all__ = [
    "OoxmlAuditor",
    "AuditReport",
    "Finding",
    "Relationship",
    "SafeZip",
    "ContainerError",
    "PathTraversalError",
    "audit",
]

__version__ = "0.1.0"


def audit(path: str) -> AuditReport:
    """Audit an OOXML file on disk and return an :class:`AuditReport`."""
    return OoxmlAuditor().audit(path, path=path)
