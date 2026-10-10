#!/usr/bin/env python3
"""
Build PDF manuals from markdown sources using reportlab.

Usage: python tools/build_manuals.py
Output: USER_MANUAL.pdf, DEVELOPER_MANUAL.pdf
"""

import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Preformatted,
    Table, TableStyle, HRFlowable, PageBreak, KeepTogether,
)


ROOT = Path(__file__).resolve().parent.parent


def escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def inline(text: str) -> str:
    text = escape(text)
    text = re.sub(r"`([^`]+)`", r'<font face="Courier" color="#c7254e">\1</font>', text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    return text


def build_styles():
    ss = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle(
            "DocTitle", parent=ss["Title"], fontSize=26,
            textColor=colors.HexColor("#0b3d91"), spaceAfter=6,
        ),
        "subtitle": ParagraphStyle(
            "DocSub", parent=ss["Normal"], fontSize=12,
            textColor=colors.HexColor("#57606a"), spaceAfter=18,
        ),
        "h1": ParagraphStyle(
            "H1", parent=ss["Heading1"], fontSize=18,
            textColor=colors.HexColor("#0b3d91"),
            spaceBefore=18, spaceAfter=8, borderPadding=0,
        ),
        "h2": ParagraphStyle(
            "H2", parent=ss["Heading2"], fontSize=14,
            textColor=colors.HexColor("#1f6feb"),
            spaceBefore=14, spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "H3", parent=ss["Heading3"], fontSize=12,
            textColor=colors.HexColor("#24292f"),
            spaceBefore=10, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "Body", parent=ss["BodyText"], fontSize=9.5, leading=14,
            alignment=TA_LEFT, spaceAfter=6,
        ),
        "code": ParagraphStyle(
            "Code", parent=ss["Code"], fontName="Courier", fontSize=8,
            leading=11, textColor=colors.HexColor("#24292f"),
            backColor=colors.HexColor("#f6f8fa"), borderPadding=6,
            spaceBefore=4, spaceAfter=8, leftIndent=4,
        ),
        "bullet": ParagraphStyle(
            "Bullet", parent=ss["BodyText"], fontSize=9.5, leading=14,
            leftIndent=16, bulletIndent=6, spaceAfter=2,
        ),
    }
    return styles


def make_table(rows, styles):
    data = []
    for r in rows:
        data.append([Paragraph(inline(c), styles["body"]) for c in r])
    t = Table(data, hAlign="LEFT", colWidths=None)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d91")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d7de")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f6f8fa")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def parse_markdown(text: str, styles):
    flow = []
    lines = text.splitlines()
    i = 0
    in_code = False
    code_buf = []
    table_buf = []

    def flush_table():
        nonlocal table_buf
        if table_buf:
            rows = [r for r in table_buf if not re.match(r"^\s*\|?[\s:\-|]+\|?\s*$", r)]
            parsed = []
            for r in rows:
                cells = [c.strip() for c in r.strip().strip("|").split("|")]
                parsed.append(cells)
            if parsed:
                flow.append(Spacer(1, 4))
                flow.append(make_table(parsed, styles))
                flow.append(Spacer(1, 8))
            table_buf = []

    while i < len(lines):
        line = lines[i]

        # Code fences
        if line.strip().startswith("```"):
            if in_code:
                flow.append(Preformatted("\n".join(code_buf), styles["code"]))
                code_buf = []
                in_code = False
            else:
                flush_table()
                in_code = True
            i += 1
            continue
        if in_code:
            code_buf.append(line)
            i += 1
            continue

        # Tables
        if line.strip().startswith("|") and line.strip().endswith("|"):
            table_buf.append(line)
            i += 1
            continue
        else:
            flush_table()

        stripped = line.strip()
        if not stripped:
            i += 1
            continue

        # Horizontal rule
        if re.match(r"^-{3,}$", stripped) or re.match(r"^\*{3,}$", stripped):
            flow.append(Spacer(1, 6))
            flow.append(HRFlowable(width="100%", thickness=0.6,
                                   color=colors.HexColor("#d0d7de")))
            flow.append(Spacer(1, 6))
            i += 1
            continue

        # Headings
        m = re.match(r"^(#{1,4})\s+(.*)$", stripped)
        if m:
            level = len(m.group(1))
            txt = inline(m.group(2))
            key = "h1" if level == 1 else "h2" if level == 2 else "h3"
            flow.append(Paragraph(txt, styles[key]))
            i += 1
            continue

        # Numbered list
        m = re.match(r"^(\d+)\.\s+(.*)$", stripped)
        if m:
            flow.append(Paragraph(inline(m.group(2)), styles["bullet"],
                                  bulletText=f"{m.group(1)}."))
            i += 1
            continue

        # Bullet list
        if stripped.startswith("- ") or stripped.startswith("* "):
            flow.append(Paragraph(inline(stripped[2:]), styles["bullet"],
                                  bulletText="•"))
            i += 1
            continue

        # Blockquote
        if stripped.startswith(">"):
            flow.append(Paragraph(inline(stripped.lstrip("> ").strip()),
                                  styles["body"]))
            i += 1
            continue

        # Normal paragraph
        flow.append(Paragraph(inline(stripped), styles["body"]))
        i += 1

    if in_code and code_buf:
        flow.append(Preformatted("\n".join(code_buf), styles["code"]))
    flush_table()
    return flow


def build_pdf(source_md: Path, output_pdf: Path, title: str, subtitle: str):
    styles = build_styles()
    text = source_md.read_text(encoding="utf-8")

    doc = BaseDocTemplate(
        str(output_pdf), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=title, author="DjangoSentinel Contributors",
    )

    frame = Frame(
        doc.leftMargin, doc.bottomMargin,
        doc.width, doc.height, id="main",
    )

    def on_page(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#8b949e"))
        canvas.drawString(18 * mm, 10 * mm, f"DjangoSentinel v1.0.0 — {title}")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc_.page}")
        canvas.setStrokeColor(colors.HexColor("#d0d7de"))
        canvas.line(18 * mm, 12 * mm, A4[0] - 18 * mm, 12 * mm)
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="all", frames=[frame], onPage=on_page)])

    story = [
        Spacer(1, 40),
        Paragraph(inline(title), styles["title"]),
        Paragraph(inline(subtitle), styles["subtitle"]),
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0b3d91")),
        Spacer(1, 16),
    ]
    story.extend(parse_markdown(text, styles))

    doc.build(story)
    print(f"✅ Generated {output_pdf}")


def main():
    build_pdf(
        ROOT / "USER_MANUAL.md",
        ROOT / "USER_MANUAL.pdf",
        "DjangoSentinel User Manual",
        "Enterprise AI Security Scanner for Python/Django — End-user guide",
    )
    build_pdf(
        ROOT / "DEVELOPER_MANUAL.md",
        ROOT / "DEVELOPER_MANUAL.pdf",
        "DjangoSentinel Developer Manual",
        "Architecture, extension points, and contribution guide",
    )


if __name__ == "__main__":
    main()
