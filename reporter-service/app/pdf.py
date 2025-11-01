from __future__ import annotations

from io import BytesIO
from typing import Dict, Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer


def build_pdf(analysis: Dict[str, Any]) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    styles = getSampleStyleSheet()
    elems = []

    title = analysis.get("title") or f"ZORBOX Report: {analysis.get('id','unknown')}"
    elems.append(Paragraph(title, styles['Title']))
    elems.append(Spacer(1, 12))

    summary = analysis.get("summary") or "Executive Summary: This is an MVP auto-generated report."
    elems.append(Paragraph(summary, styles['Normal']))
    elems.append(Spacer(1, 12))

    score = analysis.get("score", {})
    total = score.get("total", 0)
    elems.append(Paragraph(f"Final Score: {total}", styles['Heading2']))
    elems.append(Spacer(1, 8))

    rules = score.get("rules", [])
    if rules:
        elems.append(Paragraph("Triggered Rules:", styles['Heading3']))
        for r in rules[:20]:
            desc = r.get('desc', 'rule')
            hit = r.get('hit', False)
            elems.append(Paragraph(f"- {desc}: {'HIT' if hit else 'MISS'}", styles['Normal']))

    doc.build(elems)
    return buf.getvalue()

