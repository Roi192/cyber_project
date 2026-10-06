# ==================================================
# PHASE 11E: SECURITY REPORT PDF RENDERER
# ==================================================
#
# Consumes ONLY a stored security_reports.snapshot_json dict -
# never queries live telemetry. This guarantees the PDF and the
# HTML detail view always show byte-identical numbers, since both
# read the exact same immutable snapshot (see app.py's
# security_report_detail()/security_report_pdf() routes).
#
# Uses the project's existing ReportLab dependency only - same
# SimpleDocTemplate/platypus pattern already used for the scanner
# assessment PDF in app.py. The one new capability added here is
# a small NumberedCanvas (a standard, well-documented ReportLab
# pattern) for "Page X of Y" footers - no new dependency.
# ==================================================

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)
from reportlab.pdfgen import canvas as pdfcanvas


class NumberedCanvas(pdfcanvas.Canvas):
    # Standard ReportLab two-pass page-numbering pattern: buffer
    # every page, then on save() go back and draw "Page X of Y" on
    # each one now that the total is known. Draws only a page
    # number and a static product label - never a local file path,
    # username, or secret.

    def __init__(self, *args, **kwargs):
        pdfcanvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        page_count = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_footer(page_count)
            pdfcanvas.Canvas.showPage(self)
        pdfcanvas.Canvas.save(self)

    def _draw_footer(self, page_count):
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.grey)
        self.drawString(2 * cm, 1.2 * cm, "CyberSec SOC — Security Report")
        self.drawRightString(
            A4[0] - 2 * cm, 1.2 * cm,
            f"Page {self._pageNumber} of {page_count}"
        )


def _kv_table(rows, col_widths=(6 * cm, 10 * cm)):
    table = Table(rows, colWidths=list(col_widths))
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 6)
    ]))
    return table


def _data_table(header, rows, col_widths, small=False):
    data = [header] + rows
    table = Table(data, colWidths=col_widths, repeatRows=1)
    font_size = 7.5 if small else 8.5
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), font_size),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 4)
    ]))
    return table


def _dict_rows(d):
    return [[str(k), str(v)] for k, v in d.items()]


def _pdf_escape(value):
    # ReportLab's Paragraph interprets a small XML-like markup
    # language - any "&"/"<"/">" appearing in DATA-derived text
    # (alert titles, process names, destinations, reasons, etc.,
    # which ultimately trace back to Agent/analyst-provided
    # strings, not fixed constants) must be escaped before being
    # wrapped in Paragraph(), or it can break rendering/parsing.
    text = "" if value is None else str(value)
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def build_security_report_pdf(snapshot):
    # snapshot is the dict decoded from security_reports.snapshot_json
    # (schema_version == 1). No live database access happens here.

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2.2 * cm
    )

    styles = getSampleStyleSheet()
    note_style = ParagraphStyle(
        "Note", parent=styles["Normal"], fontSize=8.5,
        textColor=colors.grey, spaceAfter=4
    )
    center_title = ParagraphStyle(
        "CenterTitle", parent=styles["Title"], alignment=TA_CENTER
    )

    story = []

    # ---------------- TITLE ----------------
    story.append(Paragraph("CyberSec Security Monitoring &amp; Response System", center_title))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Security Report", styles["Heading1"]))
    story.append(Paragraph(
        f"{snapshot['report_type'].title()} Report — {snapshot['display_period']}",
        styles["Heading2"]
    ))
    story.append(Spacer(1, 12))

    # ---------------- 1. REPORT INFORMATION ----------------
    story.append(Paragraph("1. Report Information", styles["Heading2"]))
    story.append(_kv_table([
        ["Report Type", snapshot["report_type"]],
        ["Period", snapshot["display_period"]],
        ["Period Start (inclusive)", snapshot["period_start"]],
        ["Period End (exclusive)", snapshot["period_end"]],
        ["Generated At", snapshot["generated_at"]],
        ["Generated By", snapshot["generated_by"]],
        ["Timezone Basis", snapshot["timezone_basis"]],
        ["Trusted Endpoints Observed", str(snapshot["report_information"]["trusted_endpoints_observed"])],
        ["Events Analyzed", str(snapshot["report_information"]["events_analyzed"])],
    ]))
    story.append(Paragraph(
        "Database queries use an inclusive start and exclusive end boundary.",
        note_style
    ))
    story.append(Spacer(1, 14))

    # ---------------- 2. EXECUTIVE SUMMARY ----------------
    story.append(Paragraph("2. Executive Security Summary", styles["Heading2"]))
    story.append(Paragraph(snapshot["executive_summary"]["label"], note_style))
    for sentence in snapshot["executive_summary"]["sentences"]:
        story.append(Paragraph(sentence, styles["Normal"]))
    story.append(Spacer(1, 14))

    # ---------------- 3. COVERAGE ----------------
    story.append(Paragraph("3. Environment / Coverage", styles["Heading2"]))
    cov = snapshot["coverage"]
    story.append(_kv_table([
        ["Trusted Endpoint Identities Observed", str(cov["trusted_endpoint_identities_observed"])],
        ["Analyzed Trusted Events", str(cov["analyzed_trusted_events"])],
        ["Active Observation Days", str(cov["active_observation_days"])],
        ["Behavioral Evaluation Coverage", f"{cov['behavioral_evaluation_coverage_pct']}%"],
        ["OS User Telemetry Coverage", f"{cov['os_user_telemetry_coverage_pct']}%"],
        ["SHA-256 Telemetry Coverage", f"{cov['sha256_telemetry_coverage_pct']}%"],
    ]))
    story.append(Paragraph(cov["identity_caveat"], note_style))
    if cov["baseline_maturity_as_of_generation"]:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Baseline Maturity — As of Report Generation", styles["Heading3"]))
        rows = [[r["endpoint_ip"], r["hostname"] or "-", r["maturity_state"], r["confidence"]]
                for r in cov["baseline_maturity_as_of_generation"]]
        story.append(_data_table(["Endpoint", "Hostname", "Maturity", "Confidence"], rows,
                                  [4 * cm, 5 * cm, 3.5 * cm, 3.5 * cm]))
    story.append(Spacer(1, 14))

    # ---------------- 4. THREAT RISK OVERVIEW ----------------
    story.append(Paragraph("4. Threat Risk Overview", styles["Heading2"]))
    tr = snapshot["threat_risk"]
    story.append(_kv_table([
        ["Analyzed Events", str(tr["analyzed_events"])],
        ["Events with Risk &gt; 0", str(tr["events_with_risk_gt_0"])],
        ["Highest Observed Event Risk", f"{tr['highest_observed_event_risk']}/100 ({tr['highest_observed_event_severity']})"],
        ["Events with Local IOC Evidence", str(tr["events_with_local_ioc_evidence"])],
        ["Distinct Risky Destinations", str(tr["distinct_risky_destinations"])],
    ]))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Severity Distribution", styles["Heading3"]))
    story.append(_data_table(["Severity", "Count"], _dict_rows(tr["severity_distribution"]), [6 * cm, 4 * cm]))
    story.append(Spacer(1, 14))

    # ---------------- 5. BEHAVIORAL ANALYTICS ----------------
    story.append(Paragraph("5. Behavioral Analytics", styles["Heading2"]))
    beh = snapshot["behavioral"]
    story.append(_kv_table([
        ["Behaviorally Unusual Events", str(beh["behaviorally_unusual_events"])],
        ["Endpoints with Unusual Activity", str(beh["endpoints_with_unusual_activity"])],
        ["Behavioral Evaluation Coverage", f"{beh['behavioral_evaluation_coverage_pct']}%"],
    ]))
    story.append(Spacer(1, 6))
    story.append(_data_table(["Evaluation", "Count"], _dict_rows(beh["evaluation_status_distribution"]), [6 * cm, 4 * cm]))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Baseline Inventory — As of Report Generation", styles["Heading3"]))
    story.append(Paragraph(
        "The following counts describe the endpoint's LEARNED baseline inventory to date; "
        "they are not novelty discovered specifically during this report period.",
        note_style
    ))
    bi = beh["baseline_inventory_as_of_generation"]
    story.append(_kv_table([
        ["Distinct Processes in Baseline", str(bi["distinct_processes_in_baseline"])],
        ["Distinct Destinations in Baseline", str(bi["distinct_destinations_in_baseline"])],
        ["Distinct Process-Destination Relationships in Baseline", str(bi["distinct_process_destination_in_baseline"])],
    ]))
    story.append(Spacer(1, 14))

    # ---------------- 6. THREAT INTELLIGENCE ----------------
    story.append(Paragraph("6. Threat Intelligence", styles["Heading2"]))
    ti = snapshot["threat_intelligence"]
    story.append(Paragraph(ti["disclosure"], note_style))
    story.append(_data_table(["Outcome", "Count"], _dict_rows(ti["event_correlation"]), [6 * cm, 4 * cm]))
    story.append(Spacer(1, 4))
    story.append(_kv_table([["Indicators Enriched During Period", str(ti["indicators_enriched_during_period"])]]))
    story.append(Spacer(1, 14))

    # ---------------- 7. ALERTS & INCIDENTS ----------------
    story.append(Paragraph("7. Alerts &amp; Incidents", styles["Heading2"]))
    ai = snapshot["alerts_incidents"]
    story.append(_kv_table([
        ["Security Alerts", str(ai["alerts_total"])],
        ["Security Incidents", str(ai["incidents_total"])],
    ]))
    if ai["alerts"]:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Alerts (most recent first)", styles["Heading3"]))
        rows = [[a.get("created_at", "-"), a.get("severity", "-"), a.get("status", "-"),
                 Paragraph(_pdf_escape(a.get("title", "-")), styles["Normal"])] for a in ai["alerts"]]
        story.append(_data_table(["Created", "Severity", "Status", "Title"], rows,
                                  [3 * cm, 2.2 * cm, 2.5 * cm, 8.3 * cm], small=True))
        if ai["alerts_truncated_count"]:
            story.append(Paragraph(f"{ai['alerts_truncated_count']} additional records not shown in this summary.", note_style))
    else:
        story.append(Paragraph("No Security Alerts were recorded during this reporting period.", styles["Normal"]))
    if ai["incidents"]:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Incidents (most recent first)", styles["Heading3"]))
        rows = [[i.get("event_time", "-"), i.get("event_type", "-"), i.get("status", "-")] for i in ai["incidents"]]
        story.append(_data_table(["Time", "Type", "Status"], rows, [4 * cm, 6 * cm, 4 * cm], small=True))
        if ai["incidents_truncated_count"]:
            story.append(Paragraph(f"{ai['incidents_truncated_count']} additional records not shown in this summary.", note_style))
    else:
        story.append(Paragraph("No Security Incidents were recorded during this reporting period.", styles["Normal"]))
    story.append(Spacer(1, 14))

    # ---------------- 8. INVESTIGATION PRIORITY ----------------
    story.append(Paragraph("8. Investigation Priority", styles["Heading2"]))
    ip_data = snapshot["investigation_priority"]
    story.append(Paragraph(ip_data["disclosure"], note_style))
    story.append(_data_table(["Priority", "Count"], _dict_rows(ip_data["priority_distribution"]), [6 * cm, 4 * cm]))
    story.append(Spacer(1, 14))

    # ---------------- 9. RESPONSE ACTIONS ----------------
    story.append(Paragraph("9. Response Actions", styles["Heading2"]))
    ra = snapshot["response_actions"]
    if ra["total"]:
        story.append(_kv_table([["Total Response Actions", str(ra["total"])]]))
        story.append(Spacer(1, 6))
        story.append(_data_table(["Command Type", "Count"], _dict_rows(ra["by_command_type"]), [6 * cm, 4 * cm]))
        story.append(Spacer(1, 4))
        story.append(_data_table(["Status", "Count"], _dict_rows(ra["by_status"]), [6 * cm, 4 * cm]))
        if ra["by_mode"]:
            story.append(Spacer(1, 4))
            story.append(_data_table(["Mode (Agent-reported)", "Count"], _dict_rows(ra["by_mode"]), [6 * cm, 4 * cm]))
    else:
        story.append(Paragraph("No response actions were recorded during this reporting period.", styles["Normal"]))
    story.append(Spacer(1, 14))

    story.append(PageBreak())

    # ---------------- 10. TOP ENDPOINTS ----------------
    story.append(Paragraph("10. Top Endpoints by Risk Activity", styles["Heading2"]))
    if snapshot["top_endpoints"]:
        rows = [[e["endpoint_ip"], e["hostname"] or "-", str(e["analyzed_events"]), str(e["risky_events"]),
                 f"{e['highest_observed_event_risk']}/100", str(e["alerts"]), str(e["unusual_events"])]
                for e in snapshot["top_endpoints"]]
        story.append(_data_table(
            ["Endpoint", "Hostname", "Analyzed", "Risky", "Highest Risk", "Alerts", "Unusual"],
            rows, [3 * cm, 3.2 * cm, 2 * cm, 1.8 * cm, 2.5 * cm, 1.8 * cm, 1.8 * cm], small=True
        ))
    else:
        story.append(Paragraph("No endpoint risk activity was recorded during this reporting period.", styles["Normal"]))
    story.append(Spacer(1, 14))

    # ---------------- 11. TOP DESTINATIONS ----------------
    story.append(Paragraph("11. Top Risky Destinations", styles["Heading2"]))
    story.append(Paragraph(snapshot["destination_caveat"], note_style))
    if snapshot["top_destinations"]:
        rows = [[Paragraph(_pdf_escape(d["destination"]), styles["Normal"]), str(d["observed_events"]),
                 f"{d['highest_observed_event_risk']}/100", d["highest_observed_event_severity"],
                 str(d["endpoints_observed"]), "Yes" if d["threatfox_match"] else "-"]
                for d in snapshot["top_destinations"]]
        story.append(_data_table(
            ["Destination", "Events", "Highest Risk", "Severity", "Endpoints", "ThreatFox"],
            rows, [5.5 * cm, 1.8 * cm, 2.2 * cm, 2 * cm, 2 * cm, 1.8 * cm], small=True
        ))
    else:
        story.append(Paragraph("No risky destinations were recorded during this reporting period.", styles["Normal"]))
    story.append(Spacer(1, 14))

    # ---------------- 12. PERIOD COMPARISON ----------------
    story.append(Paragraph("12. Period-over-Period Comparison", styles["Heading2"]))
    pc = snapshot["period_comparison"]
    rows = [[k.replace("_", " ").title(), str(v["current"]), str(v["previous"]),
             str(v["absolute_change"]), v["change_label"]]
            for k, v in pc.items()]
    story.append(_data_table(
        ["Metric", "Current", "Previous", "Change", "Label"],
        rows, [4.5 * cm, 2.3 * cm, 2.3 * cm, 2.3 * cm, 3.5 * cm], small=True
    ))
    story.append(Spacer(1, 14))

    # ---------------- 13. ANALYST REVIEW ----------------
    story.append(Paragraph("13. Items for Analyst Review", styles["Heading2"]))
    story.append(Paragraph(snapshot["analyst_review_label"], note_style))
    if snapshot["analyst_review_items"]:
        rows = []
        for item in snapshot["analyst_review_items"]:
            reasons_text = "; ".join(item.get("reasons", []))
            rows.append([
                item.get("priority", "-"), item.get("timestamp", "-"),
                Paragraph(_pdf_escape(item.get("summary", "-")), styles["Normal"]),
                Paragraph(_pdf_escape(reasons_text), styles["Normal"])
            ])
        story.append(_data_table(
            ["Priority", "Time", "Summary", "Reasons"],
            rows, [2 * cm, 3 * cm, 4.5 * cm, 5.5 * cm], small=True
        ))
        if snapshot["analyst_review_truncated_count"]:
            story.append(Paragraph(
                f"{snapshot['analyst_review_truncated_count']} additional records not shown in this summary.",
                note_style
            ))
    else:
        story.append(Paragraph("No items require analyst review for this reporting period.", styles["Normal"]))
    story.append(Spacer(1, 14))

    # ---------------- 14. SCOPE & LIMITATIONS ----------------
    story.append(Paragraph("14. Scope &amp; Limitations", styles["Heading2"]))
    for line in snapshot["scope_and_limitations"]:
        story.append(Paragraph(f"• {line}", styles["Normal"]))

    document.build(story, canvasmaker=NumberedCanvas)

    buffer.seek(0)
    return buffer
