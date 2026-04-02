from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.graphics.shapes import Drawing, Circle, String
from io import BytesIO
from datetime import datetime

# Brand colors
CYAN   = colors.HexColor("#0077cc")
DARK   = colors.HexColor("#0f1923")
LIGHT  = colors.HexColor("#f0f4f8")
CRIT   = colors.HexColor("#d9002e")
HIGH   = colors.HexColor("#c44b00")
MED    = colors.HexColor("#8a6000")
LOW    = colors.HexColor("#007a33")
GRAY   = colors.HexColor("#7a8fa6")
BORDER = colors.HexColor("#d0d9e3")

SEV_COLORS = {"critical": CRIT, "high": HIGH, "medium": MED, "low": LOW}

def grade_color(grade: str):
    return {"A": LOW, "B": LOW, "C": MED, "D": HIGH, "F": CRIT}.get(grade, GRAY)

def generate_pdf(scan_data: dict) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=20*mm, rightMargin=20*mm,
                            topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    story  = []

    # Custom styles
    title_style = ParagraphStyle("Title", parent=styles["Heading1"],
                                 fontSize=26, textColor=DARK, spaceAfter=4, fontName="Helvetica-Bold")
    h2_style    = ParagraphStyle("H2", parent=styles["Heading2"],
                                 fontSize=14, textColor=DARK, spaceAfter=6, spaceBefore=12, fontName="Helvetica-Bold")
    body_style  = ParagraphStyle("Body", parent=styles["Normal"],
                                 fontSize=10, textColor=colors.HexColor("#3a4a5c"), leading=16)
    small_style = ParagraphStyle("Small", parent=styles["Normal"],
                                 fontSize=8, textColor=GRAY, leading=12)
    fix_style   = ParagraphStyle("Fix", parent=styles["Normal"],
                                 fontSize=9, textColor=colors.HexColor("#007a33"),
                                 leading=14, leftIndent=8)

    hostname = scan_data.get("hostname", "unknown")
    score    = scan_data.get("score", 0)
    grade    = scan_data.get("grade", "F")
    sev      = scan_data.get("severity_counts", {})
    cats     = scan_data.get("categories", [])
    ai_text  = scan_data.get("ai_summary", "")
    scanned  = datetime.now().strftime("%B %d, %Y at %H:%M UTC")

    # ── Header ────────────────────────────────────────────────────────────────
    story.append(Paragraph("⚡ SECURESCAN", ParagraphStyle("Logo", fontSize=10, textColor=CYAN,
                           fontName="Helvetica-Bold", letterSpacing=2)))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(f"Security Report: {hostname}", title_style))
    story.append(Paragraph(f"Generated {scanned}", small_style))
    story.append(Spacer(1, 6*mm))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER))
    story.append(Spacer(1, 6*mm))

    # ── Score summary table ───────────────────────────────────────────────────
    gc = grade_color(grade)
    summary_data = [
        ["Security Grade", "Score", "Critical", "High", "Medium", "Low"],
        [grade, f"{score}/100",
         str(sev.get("critical",0)), str(sev.get("high",0)),
         str(sev.get("medium",0)),   str(sev.get("low",0))],
    ]
    summary_table = Table(summary_data, colWidths=[35*mm, 30*mm, 25*mm, 25*mm, 25*mm, 25*mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,0), DARK),
        ("TEXTCOLOR",    (0,0), (-1,0), colors.white),
        ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,0), 9),
        ("ALIGN",        (0,0), (-1,-1), "CENTER"),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("ROWHEIGHT",    (0,1), (-1,1), 14*mm),
        ("FONTNAME",     (0,1), (-1,1), "Helvetica-Bold"),
        ("FONTSIZE",     (0,1), (0,1),  28),
        ("FONTSIZE",     (1,1), (1,1),  18),
        ("FONTSIZE",     (2,1), (-1,1), 16),
        ("TEXTCOLOR",    (0,1), (0,1),  gc),
        ("TEXTCOLOR",    (2,1), (2,1),  CRIT),
        ("TEXTCOLOR",    (3,1), (3,1),  HIGH),
        ("TEXTCOLOR",    (4,1), (4,1),  MED),
        ("TEXTCOLOR",    (5,1), (5,1),  LOW),
        ("GRID",         (0,0), (-1,-1), 0.5, BORDER),
        ("ROUNDEDCORNERS", [4]),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 6*mm))

    # ── AI Summary ────────────────────────────────────────────────────────────
    if ai_text:
        story.append(Paragraph("AI Remediation Summary", h2_style))
        story.append(Paragraph(ai_text, ParagraphStyle("AI", parent=body_style,
                     backColor=colors.HexColor("#e8f3fb"), borderPadding=8,
                     borderColor=CYAN, borderWidth=1, borderRadius=4)))
        story.append(Spacer(1, 4*mm))

    # ── Category breakdown ────────────────────────────────────────────────────
    story.append(Paragraph("Detailed Findings by Category", h2_style))

    for cat in cats:
        fails  = [f for f in cat.get("findings",[]) if f.get("status")=="fail"]
        passes = [f for f in cat.get("findings",[]) if f.get("status")=="pass"]
        if not cat.get("findings"):
            continue

        cat_score = cat.get("score", 0)
        cat_color = grade_color("A" if cat_score>=80 else "B" if cat_score>=70 else "C" if cat_score>=60 else "F")

        # Category header
        cat_data = [[f"{cat.get('icon','')} {cat.get('name','')}", f"{len(fails)} issues", f"Score: {cat_score}/100"]]
        ct = Table(cat_data, colWidths=[90*mm, 40*mm, 35*mm])
        ct.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,-1), colors.HexColor("#f0f4f8")),
            ("TEXTCOLOR",   (0,0), (0,0),   DARK),
            ("FONTNAME",    (0,0), (-1,-1), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 10),
            ("TEXTCOLOR",   (2,0), (2,0),   cat_color),
            ("ALIGN",       (1,0), (-1,0),  "RIGHT"),
            ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
            ("ROWHEIGHT",   (0,0), (-1,-1), 8*mm),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
            ("GRID",        (0,0), (-1,-1), 0.5, BORDER),
        ]))
        story.append(cat_data and ct or Spacer(1,0))
        story.append(Spacer(1, 2*mm))

        # Failures
        for f in fails:
            sc  = f.get("severity","low")
            col = SEV_COLORS.get(sc, GRAY)
            row_data = [[f"[{sc.upper()}]  {f.get('title','')}"],
                        [f.get("detail","")]]
            if f.get("fix"):
                row_data.append([f"→ FIX: {f.get('fix','')}"])
            ft = Table(row_data, colWidths=[165*mm])
            ft_styles = [
                ("FONTNAME",    (0,0), (0,0), "Helvetica-Bold"),
                ("FONTSIZE",    (0,0), (0,0), 9),
                ("TEXTCOLOR",   (0,0), (0,0), col),
                ("FONTSIZE",    (0,1), (0,1), 8),
                ("TEXTCOLOR",   (0,1), (0,1), colors.HexColor("#3a4a5c")),
                ("LEFTPADDING", (0,0), (-1,-1), 8),
                ("BACKGROUND",  (0,0), (-1,-1), colors.white),
                ("GRID",        (0,0), (-1,-1), 0.3, BORDER),
                ("BOTTOMPADDING",(0,-1),(-1,-1), 4),
            ]
            if f.get("fix"):
                ft_styles += [
                    ("FONTSIZE",   (0,2), (0,2), 8),
                    ("TEXTCOLOR",  (0,2), (0,2), LOW),
                    ("FONTNAME",   (0,2), (0,2), "Helvetica-Oblique"),
                    ("BACKGROUND", (0,2), (0,2), colors.HexColor("#edfff4")),
                ]
            ft.setStyle(TableStyle(ft_styles))
            story.append(ft)
            story.append(Spacer(1, 1*mm))

        if passes:
            story.append(Paragraph(f"  ✓ {len(passes)} check{'s' if len(passes)>1 else ''} passed", small_style))
        story.append(Spacer(1, 4*mm))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        "Generated by SecureScan · securescan.io · "
        "This report is for the sole use of the account holder. "
        "Only scan websites you own or have explicit permission to test.",
        small_style))

    doc.build(story)
    return buf.getvalue()
