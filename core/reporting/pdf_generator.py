import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing, Rect, String

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, 'static')
REPORTS_DIR = os.path.join(STATIC_DIR, 'reports')
IMG_DIR = os.path.join(STATIC_DIR, 'img')

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(IMG_DIR, exist_ok=True)


def get_provider_badge(is_aws=False):
    """
    Attempts to load the PNG image from static/img/.
    Falls back to a geometrically centered vector badge.
    """
    filename = "aws_logo.png" if is_aws else "azure_logo.png"
    img_path = os.path.join(IMG_DIR, filename)

    if os.path.exists(img_path) and os.path.getsize(img_path) > 100:
        try:
            return Image(img_path, width=44, height=44)
        except Exception:
            pass

    # Precision-centered vector badge (44x44 pt)
    d = Drawing(44, 44)
    if is_aws:
        d.add(Rect(0, 0, 44, 44, rx=8, ry=8, fillColor=colors.HexColor('#232F3E'), strokeColor=None))
        d.add(String(22, 17, "AWS", fontName="Helvetica-Bold", fontSize=12, fillColor=colors.HexColor('#FF9900'), textAnchor="middle"))
    else:
        d.add(Rect(0, 0, 44, 44, rx=8, ry=8, fillColor=colors.HexColor('#0078D4'), strokeColor=None))
        d.add(String(22, 18, "AZURE", fontName="Helvetica-Bold", fontSize=9.5, fillColor=colors.white, textAnchor="middle"))
    return d


def generate_pdf_report(scan_id, scores, findings, tx_hash, report_hash, azure_meta=None, threshold=70):
    pdf_filename = f"{scan_id}.pdf"
    pdf_path = os.path.join(REPORTS_DIR, pdf_filename)

    meta = azure_meta or {}
    provider_str = meta.get('provider', '').lower()
    is_aws = 'aws' in provider_str or 'amazon' in provider_str or any('CIS-AWS' in f.get('cis_rule_id', '') for f in findings)

    # Resolve active compliance threshold (from argument or embedded score dictionary)
    pass_threshold = float(scores.get('compliance_threshold', scores.get('threshold', threshold)))
    global_score = float(scores.get('global_score', 0))
    is_threshold_met = global_score >= pass_threshold

    # Cloud-specific theme variables
    primary_theme = colors.HexColor('#FF9900') if is_aws else colors.HexColor('#0078D4')
    primary_dark  = colors.HexColor('#232F3E') if is_aws else colors.HexColor('#0F172A')
    banner_accent = colors.HexColor('#FFFBEB') if is_aws else colors.HexColor('#F0F9FF')
    banner_border = colors.HexColor('#FDE68A') if is_aws else colors.HexColor('#BAE6FD')

    # Printable width: 612 - (32 * 2) = 548 pt
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        leftMargin=32,
        rightMargin=32,
        topMargin=32,
        bottomMargin=32
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=15.5,
        textColor=primary_dark,
        leading=19
    )
    meta_label = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        textColor=colors.HexColor('#475569'),
        leading=11
    )
    meta_val = ParagraphStyle(
        'MetaVal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        textColor=colors.HexColor('#0F172A'),
        leading=11
    )
    hash_val = ParagraphStyle(
        'HashVal',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        textColor=colors.HexColor('#1E293B'),
        leading=9
    )
    summary_text = ParagraphStyle(
        'SummaryText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        textColor=colors.HexColor('#1E293B'),
        leading=12
    )
    verdict_text_style = ParagraphStyle(
        'VerdictTextStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        textColor=colors.HexColor('#0F172A'),
        leading=12
    )
    table_header = ParagraphStyle(
        'THeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        textColor=colors.white,
        leading=11,
        alignment=1
    )
    cell_style = ParagraphStyle(
        'TCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        textColor=colors.HexColor('#0F172A'),
        leading=11
    )
    cell_center = ParagraphStyle(
        'TCellCenter',
        parent=cell_style,
        alignment=1
    )
    remediation_style = ParagraphStyle(
        'RemCell',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=7.5,
        textColor=colors.HexColor('#334155'),
        leading=10
    )

    elements = []

    # 1. Header Banner
    logo = get_provider_badge(is_aws=is_aws)
    if is_aws:
        brand_title = "<b>Amazon Web Services (AWS) Cloud Security Posture Report</b>"
        scope_text = "<font color='#FF9900'><b>Audit Scope:</b> Live AWS Boto3 Connector</font>"
        framework_text = "<b>Frameworks:</b> NIST CSF v1.1 & CIS AWS Foundations v2.0"
        id_label = "AWS Account / Key"
        scope_label = "Target Region Scope"
    else:
        brand_title = "<b>Microsoft Azure Cloud Security Posture Report</b>"
        scope_text = "<font color='#0078D4'><b>Audit Scope:</b> Live Azure Resource Manager (ARM)</font>"
        framework_text = "<b>Frameworks:</b> NIST CSF v1.1 & CIS Azure Benchmark v2.0"
        id_label = "Subscription ID"
        scope_label = "Resource Group"

    header_text = [
        Paragraph(brand_title, title_style),
        Spacer(1, 3),
        Paragraph(
            f"{scope_text} &nbsp;|&nbsp; {framework_text} &nbsp;|&nbsp; "
            f"<b>Timestamp:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            meta_val
        )
    ]
    header_table = Table([[logo, header_text]], colWidths=[50, 498])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (1, 0), (1, 0), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 8))

    # 2. Scope & Cryptographic Provenance
    sub_id = meta.get('subscription_id', 'N/A')
    rg_scope = meta.get('resource_group', 'Entire Subscription (All Groups)')
    scanned_res = sorted(list(set([f.get('resource_name', 'N/A') for f in findings])))
    res_str = ", ".join(scanned_res) if scanned_res else "None identified"

    scope_data = [
        [
            Paragraph(id_label, meta_label), Paragraph(f"<code>{sub_id}</code>", hash_val),
            Paragraph("Scan ID", meta_label), Paragraph(f"<b>{scan_id}</b>", meta_val)
        ],
        [
            Paragraph(scope_label, meta_label), Paragraph(f"<b>{rg_scope}</b>", meta_val),
            Paragraph("Resources Scanned", meta_label), Paragraph(res_str, meta_val)
        ],
        [
            Paragraph("EVM TX Hash", meta_label), Paragraph(f"<code>{tx_hash}</code>", hash_val),
            Paragraph("Report SHA-256", meta_label), Paragraph(f"<code>{report_hash}</code>", hash_val)
        ]
    ]
    t_scope = Table(scope_data, colWidths=[92, 182, 94, 180])
    t_scope.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
    ]))
    elements.append(t_scope)
    elements.append(Spacer(1, 7))

    # 3. SPECIAL SECTION: Global Security Threshold Status
    verdict_badge = "MET & COMPLIANT" if is_threshold_met else "NOT MET & NON-COMPLIANT"
    verdict_badge_color = "#15803D" if is_threshold_met else "#B91C1C"
    verdict_box_bg = colors.HexColor('#F0FDF4') if is_threshold_met else colors.HexColor('#FEF2F2')
    verdict_box_border = colors.HexColor('#86EFAC') if is_threshold_met else colors.HexColor('#FCA5A5')

    if is_threshold_met:
        threshold_detail = (
            f"The environment scored <b>{global_score:.2f}%</b>, successfully satisfying the organizational security baseline "
            f"requirement (<b>Target Threshold: {pass_threshold:.1f}%</b>). No critical policy breaches block production operation."
        )
    else:
        threshold_detail = (
            f"The environment scored <b>{global_score:.2f}%</b>, failing to achieve the minimum governance threshold "
            f"(<b>Target Threshold: {pass_threshold:.1f}%</b>). Corrective action is required for high-severity violations before compliance approval."
        )

    verdict_html = (
        f"<b>Global Security Posture Threshold Status:</b> &nbsp; "
        f"<font color='{verdict_badge_color}'><b>[{verdict_badge}]</b></font><br/>"
        f"{threshold_detail}"
    )

    t_verdict = Table([[Paragraph(verdict_html, verdict_text_style)]], colWidths=[548])
    t_verdict.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), verdict_box_bg),
        ('BOX', (0, 0), (-1, -1), 1, verdict_box_border),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(t_verdict)
    elements.append(Spacer(1, 7))

    # 4. Executive Summary Card
    passed_rules = scores.get('passed_rules', sum(1 for f in findings if f.get('status') == 'PASS'))
    failed_rules = scores.get('failed_rules', sum(1 for f in findings if f.get('status') == 'FAIL'))
    total_rules  = scores.get('total_rules', len(findings))

    high_fails = sum(1 for f in findings if f.get('status') == 'FAIL' and f.get('severity') == 'HIGH')
    med_fails  = sum(1 for f in findings if f.get('status') == 'FAIL' and f.get('severity') == 'MEDIUM')

    if failed_rules == 0:
        remed_summary = "All evaluated cloud controls fully satisfied established baseline hardening rules. No remediation required."
    else:
        remed_summary = (
            f"Remediation attention required for <b>{failed_rules} failed controls</b> "
            f"({high_fails} High, {med_fails} Medium severity). Priorities include public access restrictions and encryption enforcement."
        )

    chain_note = "Anchored to EVM Smart Contract with SHA-256 state proof." if tx_hash and tx_hash.startswith("0x") else "Local off-chain audit record."

    summary_html = (
        f"<b>Audit Overview:</b> Evaluated <b>{total_rules} controls</b> across {len(scanned_res)} target resources in {rg_scope}. "
        f"The environment achieved <b>{passed_rules} Passed</b> and <b>{failed_rules} Failed</b>. {remed_summary} "
        f"<font color='#475569'><i>{chain_note}</i></font>"
    )

    t_summary = Table([[Paragraph(summary_html, summary_text)]], colWidths=[548])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), banner_accent),
        ('BOX', (0, 0), (-1, -1), 0.75, banner_border),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(t_summary)
    elements.append(Spacer(1, 8))

    # 5. Compliance Framework Scoring
    identify_score = scores.get('identify_score', 100.0)
    protect_score = scores.get('protect_score', 100.0)
    detect_score = scores.get('detect_score', 100.0)
    cis_score = scores.get('cis_score', global_score)

    status_label = "COMPLIANT" if is_threshold_met else "NON-COMPLIANT"
    status_color = "#16A34A" if is_threshold_met else "#DC2626"
    benchmark_label = "CIS AWS v2.0" if is_aws else "CIS Azure v2.0"

    scores_data = [
        [
            Paragraph("Composite Posture Score", table_header),
            Paragraph("NIST: IDENTIFY", table_header),
            Paragraph("NIST: PROTECT", table_header),
            Paragraph("NIST: DETECT", table_header),
            Paragraph(benchmark_label, table_header)
        ],
        [
            Paragraph(f"<font size='10'><b>{global_score:.2f}%</b></font><br/><font color='{status_color}' size='6.5'><b>{status_label}</b> (Target &gt;= {pass_threshold:.0f}%)</font>", cell_center),
            Paragraph(f"<b>{identify_score:.1f}%</b>", cell_center),
            Paragraph(f"<b>{protect_score:.1f}%</b>", cell_center),
            Paragraph(f"<b>{detect_score:.1f}%</b>", cell_center),
            Paragraph(f"<b>{cis_score:.1f}%</b>", cell_center)
        ]
    ]
    t_scores = Table(scores_data, colWidths=[132, 104, 104, 104, 104])
    t_scores.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), primary_dark),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#FFFFFF')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(t_scores)
    elements.append(Spacer(1, 9))

    # 6. Detailed Security Findings & Actionable Remediations Matrix
    elements.append(Paragraph("<b>Evaluated Controls & Prescriptive Remediation Matrix</b>", meta_label))
    elements.append(Spacer(1, 3))

    findings_table_data = [
        [
            Paragraph("Status", table_header),
            Paragraph("Resource", table_header),
            Paragraph("Rule ID", table_header),
            Paragraph("Sev.", table_header),
            Paragraph("NIST", table_header),
            Paragraph("Remediation / Compliance Action Required", table_header)
        ]
    ]

    for f in findings:
        is_pass = (f.get('status') == 'PASS')
        badge_color = "#16A34A" if is_pass else "#DC2626"
        status_html = f"<font color='{badge_color}'><b>{f.get('status')}</b></font>"

        remediation_text = f.get('remediation')
        if not remediation_text:
            remediation_text = "Configuration validated against security baseline." if is_pass else "Apply security hardening immediately."

        findings_table_data.append([
            Paragraph(status_html, cell_center),
            Paragraph(f.get('resource_name', 'N/A'), cell_style),
            Paragraph(f.get('cis_rule_id', 'N/A'), cell_style),
            Paragraph(f.get('severity', 'MED'), cell_center),
            Paragraph(f.get('nist_function', 'N/A'), cell_center),
            Paragraph(remediation_text, remediation_style)
        ])

    t_findings = Table(findings_table_data, colWidths=[42, 118, 72, 40, 52, 224], repeatRows=1)
    t_findings.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), primary_dark),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')])
    ]))

    elements.append(t_findings)

    doc.build(elements)
    return pdf_filename