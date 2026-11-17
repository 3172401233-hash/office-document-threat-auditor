"""Command line entry point: ``python -m ooxml_auditor <file>``."""

from __future__ import annotations

import argparse
import sys

from .auditor import OoxmlAuditor


def _render(report) -> str:
    lines = [f"file: {report.path}", f"verdict: {report.max_severity}", ""]
    lines.append("== relationships ==")
    if not report.relationships:
        lines.append("  (none)")
    for rel in report.relationships:
        source = rel.source_part or "<package>"
        target = rel.resolved_target or rel.target
        mode = "external" if rel.is_external else "internal"
        lines.append(
            f"  {rel.rels_file}: {source} --{rel.rel_id}:{rel.rel_type.rsplit('/', 1)[-1]}--> {target} [{mode}]"
        )
    lines.append("")
    lines.append("== reference graph ==")
    if not report.graph:
        lines.append("  (empty)")
    for source, edges in sorted(report.graph.items()):
        lines.append(f"  {source}")
        for rel_id, tail, target in edges:
            lines.append(f"    [{rel_id}] {tail} -> {target}")
    lines.append("")
    lines.append("== findings ==")
    if not report.findings:
        lines.append("  (no findings)")
    for finding in report.findings:
        lines.append(f"  {finding}")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="ooxml_auditor",
        description="Static OOXML threat auditor (no macro execution, no network fetches).",
    )
    parser.add_argument("files", nargs="+", help="Office documents to audit")
    args = parser.parse_args(argv)
    auditor = OoxmlAuditor()
    worst = 0
    for path in args.files:
        report = auditor.audit(path, path=path)
        print(_render(report))
        print()
        if not report.ok:
            worst = max(worst, 2)
        elif report.max_severity in ("HIGH", "ERROR"):
            worst = max(worst, 1)
    return worst


if __name__ == "__main__":
    sys.exit(main())
