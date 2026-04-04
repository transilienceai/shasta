"""PDF report generation using xhtml2pdf.

Converts the HTML report to a professional PDF suitable for
sharing with auditors, investors, or board members.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from xhtml2pdf import pisa

from transilience_compliance.evidence.models import ScanResult
from transilience_compliance.reports.generator import generate_html_report

# CSS variable values — must match the HTML template's :root block
CSS_VARS = {
    "--pass": "#10b981",
    "--fail": "#ef4444",
    "--partial": "#f59e0b",
    "--critical": "#991b1b",
    "--high": "#dc2626",
    "--medium": "#d97706",
    "--low": "#2563eb",
    "--info": "#6b7280",
    "--bg": "#ffffff",
    "--text": "#1e293b",
    "--muted": "#64748b",
    "--border": "#e2e8f0",
    "--surface": "#f8fafc",
}


def _resolve_css_vars(html: str) -> str:
    """Replace CSS var() references with literal values for xhtml2pdf compatibility."""
    # Remove the :root block (xhtml2pdf can't parse it)
    html = re.sub(r':root\s*\{[^}]+\}', '', html)

    # Replace var(--name) with the literal value
    def replace_var(match: re.Match) -> str:
        var_name = match.group(1).strip()
        return CSS_VARS.get(var_name, "#000000")

    html = re.sub(r'var\(([^)]+)\)', replace_var, html)
    return html


def save_pdf_report(scan: ScanResult, output_path: Path | str = "data/reports") -> Path:
    """Generate and save a PDF compliance report."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filepath = output_dir / f"gap-analysis-{scan.account_id}-{timestamp}.pdf"

    html_content = generate_html_report(scan)
    html_content = _resolve_css_vars(html_content)

    with open(filepath, "wb") as f:
        result = pisa.CreatePDF(html_content, dest=f)

    if result.err:
        raise RuntimeError(f"PDF generation failed with {result.err} error(s)")

    return filepath
