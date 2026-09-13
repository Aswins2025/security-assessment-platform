import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from app.models.models import ScanRun, Project

TEMPLATE_DIR = Path(__file__).parent
OUTPUT_DIR = Path(__file__).parent / "generated"
OUTPUT_DIR.mkdir(exist_ok=True)


def _severity_counts(findings):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def render_html_report(scan: ScanRun, project: Project) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template("template.html")
    html = template.render(
        project=project,
        scan=scan,
        findings=sorted(scan.findings, key=lambda f: -f.risk_score),
        counts=_severity_counts(scan.findings),
    )
    out_path = OUTPUT_DIR / f"scan_{scan.id}_report.html"
    out_path.write_text(html, encoding="utf-8")
    return str(out_path)


def render_pdf_report(scan: ScanRun, project: Project) -> str:
    """Requires the `weasyprint` package and its system dependencies (see README)."""
    from weasyprint import HTML  # imported lazily so the app still runs without it

    html_path = render_html_report(scan, project)
    pdf_path = OUTPUT_DIR / f"scan_{scan.id}_report.pdf"
    HTML(filename=html_path).write_pdf(str(pdf_path))
    return str(pdf_path)
