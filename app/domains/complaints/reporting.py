from __future__ import annotations

import io
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfgen import canvas

from app.domains.complaints import service
from app.domains.complaints.schemas import ComplaintCaseRead


REPORT_TYPE_LABELS: dict[str, str] = {
    "all": "전체",
    "building": "동별",
    "complaint": "민원",
    "category": "분류별",
    "unresolved": "미처리",
    "closed": "종결",
}
ACTIVE_STATUSES = {"received", "assigned", "visit_scheduled", "in_progress", "reopened"}
CLOSED_STATUSES = {"resolved", "resident_confirmed", "closed"}
HEADER_FILL = PatternFill(fill_type="solid", fgColor="1F4E78")
HEADER_FONT = Font(color="FFFFFF", bold=True)
PDF_FONT_NAME = "HYSMyeongJo-Medium"
_PDF_FONT_READY = False


@dataclass(slots=True)
class ComplaintExportReport:
    report_type: str
    report_label: str
    site: str | None
    building: str | None
    generated_at: datetime
    summary_rows: list[tuple[str, str]]
    headers: list[str]
    rows: list[list[str]]
    primary_sheet_name: str
    file_stem: str


def normalize_report_type(value: str | None) -> str:
    normalized = service.normalize_description(value).lower()
    if normalized not in REPORT_TYPE_LABELS:
        return "all"
    return normalized


def _format_datetime(value: datetime | None) -> str:
    if value is None:
        return ""
    return value.astimezone().strftime("%Y-%m-%d %H:%M")


def _autosize(ws: object) -> None:
    for column_cells in ws.columns:
        letter = get_column_letter(column_cells[0].column)
        width = 10
        for cell in column_cells:
            text = "" if cell.value is None else str(cell.value)
            width = max(width, min(len(text) + 2, 48))
        ws.column_dimensions[letter].width = width


def _style_table_sheet(ws: object) -> None:
    for cell in ws[1]:
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
    ws.freeze_panes = "A2"
    if ws.max_row >= 1 and ws.max_column >= 1:
        ws.auto_filter.ref = ws.dimensions
    _autosize(ws)


def _summary_rows(cases: list[ComplaintCaseRead], *, site: str | None, building: str | None, report_label: str) -> list[tuple[str, str]]:
    building_count = len({(row.building, row.unit_number) for row in cases})
    recurrence_count = sum(1 for row in cases if row.recurrence_flag)
    active_count = sum(1 for row in cases if row.status in ACTIVE_STATUSES)
    closed_count = sum(1 for row in cases if row.status in CLOSED_STATUSES)
    latest_report = max((row.reported_at for row in cases), default=None)
    return [
        ("출력구분", report_label),
        ("단지", site or "전체"),
        ("동 필터", building or "전체"),
        ("민원건수", str(len(cases))),
        ("세대수", str(building_count)),
        ("미처리건수", str(active_count)),
        ("종결건수", str(closed_count)),
        ("재민원건수", str(recurrence_count)),
        ("최근접수", _format_datetime(latest_report) or "-"),
    ]


def _detail_rows(cases: Iterable[ComplaintCaseRead]) -> list[list[str]]:
    rows: list[list[str]] = []
    for row in cases:
        rows.append(
            [
                str(row.id),
                row.building,
                row.unit_number,
                row.complaint_type_label,
                row.status_label,
                row.assignee or "미배정",
                _format_datetime(row.reported_at),
                row.contact_phone or "",
                row.description,
            ]
        )
    return rows


def _building_rows(cases: list[ComplaintCaseRead]) -> list[list[str]]:
    grouped: dict[str, dict[str, object]] = {}
    for row in cases:
        bucket = grouped.setdefault(
            row.building,
            {
                "total": 0,
                "active": 0,
                "closed": 0,
                "recurrence": 0,
                "households": set(),
                "latest_reported_at": None,
            },
        )
        bucket["total"] = int(bucket["total"]) + 1
        if row.status in ACTIVE_STATUSES:
            bucket["active"] = int(bucket["active"]) + 1
        if row.status in CLOSED_STATUSES:
            bucket["closed"] = int(bucket["closed"]) + 1
        if row.recurrence_flag:
            bucket["recurrence"] = int(bucket["recurrence"]) + 1
        households = bucket["households"]
        assert isinstance(households, set)
        households.add((row.building, row.unit_number))
        latest_reported_at = bucket["latest_reported_at"]
        if latest_reported_at is None or row.reported_at > latest_reported_at:
            bucket["latest_reported_at"] = row.reported_at

    ordered_keys = sorted(grouped.keys(), key=lambda item: (int("".join(ch for ch in item if ch.isdigit()) or "999999"), item))
    rows: list[list[str]] = []
    for building in ordered_keys:
        bucket = grouped[building]
        households = bucket["households"]
        assert isinstance(households, set)
        rows.append(
            [
                building,
                str(bucket["total"]),
                str(len(households)),
                str(bucket["active"]),
                str(bucket["closed"]),
                str(bucket["recurrence"]),
                _format_datetime(bucket["latest_reported_at"]),
            ]
        )
    return rows


def _category_rows(cases: list[ComplaintCaseRead]) -> list[list[str]]:
    grouped: dict[str, dict[str, object]] = {}
    for row in cases:
        bucket = grouped.setdefault(
            row.complaint_type,
            {
                "label": row.complaint_type_label,
                "total": 0,
                "active": 0,
                "closed": 0,
                "recurrence": 0,
                "households": set(),
            },
        )
        bucket["total"] = int(bucket["total"]) + 1
        if row.status in ACTIVE_STATUSES:
            bucket["active"] = int(bucket["active"]) + 1
        if row.status in CLOSED_STATUSES:
            bucket["closed"] = int(bucket["closed"]) + 1
        if row.recurrence_flag:
            bucket["recurrence"] = int(bucket["recurrence"]) + 1
        households = bucket["households"]
        assert isinstance(households, set)
        households.add((row.building, row.unit_number))

    ordered_keys = sorted(grouped.keys(), key=lambda item: (-int(grouped[item]["total"]), grouped[item]["label"]))  # type: ignore[arg-type]
    rows: list[list[str]] = []
    for complaint_type in ordered_keys:
        bucket = grouped[complaint_type]
        households = bucket["households"]
        assert isinstance(households, set)
        rows.append(
            [
                str(bucket["label"]),
                str(bucket["total"]),
                str(len(households)),
                str(bucket["active"]),
                str(bucket["closed"]),
                str(bucket["recurrence"]),
            ]
        )
    return rows


def build_complaint_export_report(
    *,
    site: str | None,
    report_type: str | None,
    building: str | None = None,
    allowed_sites: list[str] | None = None,
) -> ComplaintExportReport:
    normalized_type = normalize_report_type(report_type)
    normalized_building = service.normalize_building(building) if service.normalize_description(building) else None
    cases = service.list_cases(site=site, building=normalized_building, allowed_sites=allowed_sites)
    if normalized_type == "unresolved":
        cases = [row for row in cases if row.status in ACTIVE_STATUSES]
    elif normalized_type == "closed":
        cases = [row for row in cases if row.status in CLOSED_STATUSES]
    report_label = REPORT_TYPE_LABELS[normalized_type]
    summary_rows = _summary_rows(cases, site=site, building=normalized_building, report_label=report_label)

    if normalized_type == "building":
        headers = ["동", "총건수", "세대수", "미처리", "종결", "재민원", "최근접수"]
        rows = _building_rows(cases)
        sheet_name = "동별현황"
    elif normalized_type == "category":
        headers = ["분류", "총건수", "세대수", "미처리", "종결", "재민원"]
        rows = _category_rows(cases)
        sheet_name = "분류별현황"
    else:
        headers = ["민원ID", "동", "호수", "민원유형", "상태", "담당자", "접수일시", "연락처", "민원내용"]
        rows = _detail_rows(cases)
        sheet_name = "민원목록"

    file_stem = f"complaints-{normalized_type}-{service.normalize_description(site or 'all').replace(' ', '_') or 'all'}"
    return ComplaintExportReport(
        report_type=normalized_type,
        report_label=report_label,
        site=site,
        building=normalized_building,
        generated_at=datetime.now().astimezone(),
        summary_rows=summary_rows,
        headers=headers,
        rows=rows,
        primary_sheet_name=sheet_name,
        file_stem=file_stem,
    )


def build_complaint_export_xlsx(report: ComplaintExportReport) -> bytes:
    workbook = Workbook()
    summary_ws = workbook.active
    summary_ws.title = "요약"
    summary_ws.append(["항목", "값"])
    for label, value in report.summary_rows:
        summary_ws.append([label, value])
    _style_table_sheet(summary_ws)

    detail_ws = workbook.create_sheet(report.primary_sheet_name)
    detail_ws.append(report.headers)
    for row in report.rows:
        detail_ws.append(row)
    _style_table_sheet(detail_ws)

    buffer = io.BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()


def _ensure_pdf_font() -> str:
    global _PDF_FONT_READY
    if not _PDF_FONT_READY:
        try:
            pdfmetrics.registerFont(UnicodeCIDFont(PDF_FONT_NAME))
        except Exception:
            return "Helvetica"
        _PDF_FONT_READY = True
    return PDF_FONT_NAME


def _draw_summary_block(pdf: canvas.Canvas, report: ComplaintExportReport, *, width: float, height: float) -> float:
    font_name = _ensure_pdf_font()
    y = height - 54
    pdf.setFont(font_name, 18)
    pdf.drawString(42, y, f"세대 민원관리 {report.report_label} 출력")
    y -= 22
    pdf.setFont(font_name, 10)
    for label, value in report.summary_rows:
        pdf.drawString(42, y, f"{label}: {value}")
        y -= 14
    y -= 8
    pdf.setFont(font_name, 9)
    pdf.drawString(42, y, "출력일시: " + report.generated_at.strftime("%Y-%m-%d %H:%M:%S"))
    return y - 18


def build_complaint_export_pdf(report: ComplaintExportReport) -> bytes:
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    font_name = _ensure_pdf_font()
    y = _draw_summary_block(pdf, report, width=width, height=height)
    pdf.setFont(font_name, 9)
    header_text = " | ".join(report.headers)
    pdf.drawString(42, y, header_text[:150])
    y -= 16
    for index, row in enumerate(report.rows, start=1):
        row_text = " | ".join(row)
        for chunk_start in range(0, len(row_text), 100):
            if y < 44:
                pdf.showPage()
                y = height - 42
                pdf.setFont(font_name, 9)
            prefix = f"{index}. " if chunk_start == 0 else "    "
            pdf.drawString(42, y, (prefix + row_text[chunk_start : chunk_start + 100])[:110])
            y -= 14
    pdf.save()
    return buffer.getvalue()
