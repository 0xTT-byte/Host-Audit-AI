from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import jinja2

from host_audit.schema import Finding, TriageReport

TEMPLATE_DIR = Path(__file__).parent / "templates"


def generate_markdown_report(
    host: str,
    findings: list[Finding],
    diff: dict[str, list[Any]],
    triage: TriageReport | None = None,
) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.md.j2")

    summary = {
        "total_open": len(findings),
        "new_this_run": len(diff.get("new", [])),
        "persisting": len(diff.get("persisting", [])),
        "resolved_since_last": len(diff.get("resolved_ids", [])),
        "critical": sum(1 for f in findings if f.severity == "critical"),
        "high": sum(1 for f in findings if f.severity == "high"),
        "medium": sum(1 for f in findings if f.severity == "medium"),
        "low": sum(1 for f in findings if f.severity == "low"),
    }

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    rendered = template.render(
        host=host,
        timestamp=timestamp,
        findings=findings,
        diff=diff,
        summary=summary,
        triage=triage,
    )
    return rendered
