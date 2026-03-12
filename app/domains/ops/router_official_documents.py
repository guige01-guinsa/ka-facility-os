"""Official document management and closure report routes."""

from __future__ import annotations

import csv
import html
import io
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import HTMLResponse
from sqlalchemy import insert, select, update

from app import main as main_module
from app.database import get_conn, inspections, official_documents, work_orders
from app.schemas import (
    OfficialDocumentCloseRequest,
    OfficialDocumentClosureReportEntryRead,
    OfficialDocumentClosureReportRead,
    OfficialDocumentCreate,
    OfficialDocumentRead,
    OfficialDocumentUpdate,
)

router = APIRouter(tags=["official-documents"])

_allowed_sites_for_principal = main_module._allowed_sites_for_principal
_require_site_access = main_module._require_site_access
_to_utc = main_module._to_utc
_write_audit_log = main_module._write_audit_log
require_permission = main_module.require_permission

_DOC_STATUSES = {"received", "in_progress", "closed", "canceled"}
_DOC_PRIORITIES = {"low", "medium", "high", "critical"}


def _normalize_doc_status(value: Any) -> str:
    normalized = str(value or "received").strip().lower() or "received"
    if normalized not in _DOC_STATUSES:
        raise HTTPException(status_code=422, detail="status must be received, in_progress, closed, or canceled")
    return normalized


def _normalize_doc_priority(value: Any) -> str:
    normalized = str(value or "medium").strip().lower() or "medium"
    if normalized not in _DOC_PRIORITIES:
        raise HTTPException(status_code=422, detail="priority must be low, medium, high, or critical")
    return normalized


def _normalize_month_label(value: str) -> str:
    normalized = (value or "").strip()
    try:
        datetime.strptime(normalized, "%Y-%m")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="month must be YYYY-MM") from exc
    return normalized


def _period_bounds(*, period_type: str, month: str | None = None, year: int | None = None) -> tuple[datetime, datetime, str]:
    if period_type == "monthly":
        normalized_month = _normalize_month_label(month or datetime.now(timezone.utc).strftime("%Y-%m"))
        start = datetime.strptime(normalized_month, "%Y-%m").replace(tzinfo=timezone.utc)
        if start.month == 12:
            end = datetime(start.year + 1, 1, 1, tzinfo=timezone.utc)
        else:
            end = datetime(start.year, start.month + 1, 1, tzinfo=timezone.utc)
        return start, end, normalized_month

    target_year = int(year or datetime.now(timezone.utc).year)
    if target_year < 2000 or target_year > 2100:
        raise HTTPException(status_code=422, detail="year must be between 2000 and 2100")
    start = datetime(target_year, 1, 1, tzinfo=timezone.utc)
    end = datetime(target_year + 1, 1, 1, tzinfo=timezone.utc)
    return start, end, str(target_year)


def _row_to_official_document_model(row: dict[str, Any]) -> OfficialDocumentRead:
    return OfficialDocumentRead(
        id=int(row["id"]),
        site=str(row["site"]),
        organization=str(row["organization"]),
        document_number=str(row["document_number"]) if row.get("document_number") else None,
        title=str(row["title"]),
        document_type=str(row.get("document_type") or "general"),
        status=_normalize_doc_status(row.get("status")),
        priority=_normalize_doc_priority(row.get("priority")),
        received_at=_to_utc(row["received_at"]),
        due_at=_to_utc(row["due_at"]) if row.get("due_at") else None,
        required_action=str(row.get("required_action") or ""),
        summary=str(row.get("summary") or ""),
        linked_inspection_id=int(row["linked_inspection_id"]) if row.get("linked_inspection_id") is not None else None,
        linked_work_order_id=int(row["linked_work_order_id"]) if row.get("linked_work_order_id") is not None else None,
        closed_report_title=str(row["closed_report_title"]) if row.get("closed_report_title") else None,
        closure_summary=str(row.get("closure_summary") or ""),
        closure_result=str(row.get("closure_result") or ""),
        closed_at=_to_utc(row["closed_at"]) if row.get("closed_at") else None,
        created_by=str(row.get("created_by") or "system"),
        created_at=_to_utc(row["created_at"]),
        updated_at=_to_utc(row["updated_at"]),
    )


def _load_official_document_or_404(document_id: int, principal: dict[str, Any]) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute(
            select(official_documents).where(official_documents.c.id == document_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Official document not found")
    _require_site_access(principal, str(row["site"]))
    return dict(row)


def _validate_linked_resources(
    conn: Any,
    *,
    site: str,
    linked_inspection_id: int | None,
    linked_work_order_id: int | None,
    principal: dict[str, Any],
) -> None:
    if linked_inspection_id is not None:
        inspection_row = conn.execute(
            select(inspections).where(inspections.c.id == int(linked_inspection_id)).limit(1)
        ).mappings().first()
        if inspection_row is None:
            raise HTTPException(status_code=404, detail="linked_inspection_id not found")
        inspection_site = str(inspection_row["site"])
        _require_site_access(principal, inspection_site)
        if inspection_site != site:
            raise HTTPException(status_code=400, detail="linked_inspection_id site must match document site")
    if linked_work_order_id is not None:
        work_order_row = conn.execute(
            select(work_orders).where(work_orders.c.id == int(linked_work_order_id)).limit(1)
        ).mappings().first()
        if work_order_row is None:
            raise HTTPException(status_code=404, detail="linked_work_order_id not found")
        work_order_site = str(work_order_row["site"])
        _require_site_access(principal, work_order_site)
        if work_order_site != site:
            raise HTTPException(status_code=400, detail="linked_work_order_id site must match document site")


def _build_official_document_report(
    *,
    period_type: str,
    site: str | None,
    month: str | None = None,
    year: int | None = None,
    allowed_sites: list[str] | None = None,
) -> OfficialDocumentClosureReportRead:
    start, end, period_label = _period_bounds(period_type=period_type, month=month, year=year)
    stmt = select(official_documents).where(official_documents.c.received_at < end)
    if site:
        stmt = stmt.where(official_documents.c.site == site)
    elif allowed_sites is not None:
        stmt = stmt.where(official_documents.c.site.in_(allowed_sites))
    stmt = stmt.order_by(
        official_documents.c.status.asc(),
        official_documents.c.due_at.asc(),
        official_documents.c.received_at.desc(),
        official_documents.c.id.desc(),
    )
    with get_conn() as conn:
        rows = [dict(row) for row in conn.execute(stmt).mappings().all()]

    entries: list[OfficialDocumentClosureReportEntryRead] = []
    organization_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    closed_in_period = 0
    open_documents = 0
    overdue_open_documents = 0
    linked_inspection_documents = 0
    linked_work_order_documents = 0

    for row in rows:
        status = _normalize_doc_status(row.get("status"))
        received_at = _to_utc(row["received_at"])
        due_at = _to_utc(row["due_at"]) if row.get("due_at") else None
        closed_at = _to_utc(row["closed_at"]) if row.get("closed_at") else None
        received_in_period = start <= received_at < end
        closed_in_period_flag = closed_at is not None and start <= closed_at < end
        open_as_of_period_end = status != "closed" and received_at < end
        if not (received_in_period or closed_in_period_flag or open_as_of_period_end):
            continue

        is_overdue = status != "closed" and due_at is not None and due_at < end
        organization = str(row.get("organization") or "unknown")
        organization_counts[organization] = organization_counts.get(organization, 0) + 1
        status_counts[status] = status_counts.get(status, 0) + 1
        if closed_in_period_flag:
            closed_in_period += 1
        if status != "closed":
            open_documents += 1
        if is_overdue:
            overdue_open_documents += 1
        if row.get("linked_inspection_id") is not None:
            linked_inspection_documents += 1
        if row.get("linked_work_order_id") is not None:
            linked_work_order_documents += 1

        entries.append(
            OfficialDocumentClosureReportEntryRead(
                id=int(row["id"]),
                site=str(row["site"]),
                organization=organization,
                document_number=str(row["document_number"]) if row.get("document_number") else None,
                title=str(row["title"]),
                document_type=str(row.get("document_type") or "general"),
                status=status,
                priority=_normalize_doc_priority(row.get("priority")),
                received_at=received_at,
                due_at=due_at,
                linked_inspection_id=int(row["linked_inspection_id"]) if row.get("linked_inspection_id") is not None else None,
                linked_work_order_id=int(row["linked_work_order_id"]) if row.get("linked_work_order_id") is not None else None,
                closed_report_title=str(row["closed_report_title"]) if row.get("closed_report_title") else None,
                closure_summary=str(row.get("closure_summary") or ""),
                closure_result=str(row.get("closure_result") or ""),
                closed_at=closed_at,
                is_overdue=is_overdue,
            )
        )

    return OfficialDocumentClosureReportRead(
        generated_at=datetime.now(timezone.utc),
        site=site,
        period_type="monthly" if period_type == "monthly" else "annual",
        period_label=period_label,
        total_documents=len(entries),
        closed_in_period=closed_in_period,
        open_documents=open_documents,
        overdue_open_documents=overdue_open_documents,
        linked_inspection_documents=linked_inspection_documents,
        linked_work_order_documents=linked_work_order_documents,
        organization_counts=organization_counts,
        status_counts=status_counts,
        entries=entries,
    )


def _build_official_document_report_csv(report: OfficialDocumentClosureReportRead) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["period_type", report.period_type])
    writer.writerow(["period_label", report.period_label])
    writer.writerow(["site", report.site or "ALL"])
    writer.writerow(["generated_at", report.generated_at.isoformat()])
    writer.writerow(["total_documents", report.total_documents])
    writer.writerow(["closed_in_period", report.closed_in_period])
    writer.writerow(["open_documents", report.open_documents])
    writer.writerow(["overdue_open_documents", report.overdue_open_documents])
    writer.writerow(["linked_inspection_documents", report.linked_inspection_documents])
    writer.writerow(["linked_work_order_documents", report.linked_work_order_documents])
    writer.writerow([])
    writer.writerow(["organization", "count"])
    for key, value in sorted(report.organization_counts.items()):
        writer.writerow([key, value])
    writer.writerow([])
    writer.writerow(["status", "count"])
    for key, value in sorted(report.status_counts.items()):
        writer.writerow([key, value])
    writer.writerow([])
    writer.writerow([
        "id", "site", "organization", "document_number", "title", "document_type", "status", "priority",
        "received_at", "due_at", "linked_inspection_id", "linked_work_order_id", "closed_report_title",
        "closure_summary", "closure_result", "closed_at", "is_overdue",
    ])
    for entry in report.entries:
        writer.writerow([
            entry.id,
            entry.site,
            entry.organization,
            entry.document_number or "",
            entry.title,
            entry.document_type,
            entry.status,
            entry.priority,
            entry.received_at.isoformat(),
            entry.due_at.isoformat() if entry.due_at else "",
            entry.linked_inspection_id or "",
            entry.linked_work_order_id or "",
            entry.closed_report_title or "",
            entry.closure_summary,
            entry.closure_result,
            entry.closed_at.isoformat() if entry.closed_at else "",
            "yes" if entry.is_overdue else "no",
        ])
    return buffer.getvalue()


def _build_official_document_report_print_html(report: OfficialDocumentClosureReportRead) -> str:
    summary_rows = [
        ("Period Type", report.period_type),
        ("Period", report.period_label),
        ("Site", report.site or "ALL"),
        ("Generated At", report.generated_at.isoformat()),
        ("Total Documents", str(report.total_documents)),
        ("Closed In Period", str(report.closed_in_period)),
        ("Open Documents", str(report.open_documents)),
        ("Overdue Open Documents", str(report.overdue_open_documents)),
        ("Linked Inspections", str(report.linked_inspection_documents)),
        ("Linked Work Orders", str(report.linked_work_order_documents)),
    ]
    org_rows = "".join(
        f"<tr><td>{html.escape(key)}</td><td>{value}</td></tr>"
        for key, value in sorted(report.organization_counts.items())
    ) or "<tr><td colspan='2'>No data</td></tr>"
    status_rows = "".join(
        f"<tr><td>{html.escape(key)}</td><td>{value}</td></tr>"
        for key, value in sorted(report.status_counts.items())
    ) or "<tr><td colspan='2'>No data</td></tr>"
    entry_rows = "".join(
        (
            "<tr>"
            f"<td>{entry.id}</td>"
            f"<td>{html.escape(entry.organization)}</td>"
            f"<td>{html.escape(entry.document_number or '-')}</td>"
            f"<td>{html.escape(entry.title)}</td>"
            f"<td>{html.escape(entry.status)}</td>"
            f"<td>{html.escape(entry.priority)}</td>"
            f"<td>{html.escape(entry.received_at.isoformat())}</td>"
            f"<td>{html.escape(entry.due_at.isoformat() if entry.due_at else '-')}</td>"
            f"<td>{html.escape(str(entry.linked_inspection_id or '-'))}</td>"
            f"<td>{html.escape(str(entry.linked_work_order_id or '-'))}</td>"
            f"<td>{html.escape(entry.closed_report_title or '-')}</td>"
            f"<td>{html.escape(entry.closure_summary or '-')}</td>"
            f"<td>{html.escape(entry.closed_at.isoformat() if entry.closed_at else '-')}</td>"
            f"<td>{'YES' if entry.is_overdue else 'NO'}</td>"
            "</tr>"
        )
        for entry in report.entries
    ) or "<tr><td colspan='14'>No entries</td></tr>"

    return f"""
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Official Document Closure Report {html.escape(report.period_label)}</title>
  <style>
    @page {{ size: A4 landscape; margin: 10mm; }}
    body {{ font-family: Arial, sans-serif; color: #111; }}
    h1 {{ margin-bottom: 8px; font-size: 20px; }}
    h2 {{ margin-top: 16px; margin-bottom: 6px; font-size: 15px; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 10px; }}
    th, td {{ border: 1px solid #d8dee8; padding: 6px; font-size: 12px; vertical-align: top; text-align: left; }}
    th {{ background: #f5f8fc; }}
    .summary td:first-child {{ width: 32%; background: #f5f8fc; font-weight: 700; }}
  </style>
</head>
<body>
  <h1>Official Document Closure Report ({html.escape(report.period_label)})</h1>
  <table class=\"summary\">
    {''.join(f'<tr><td>{html.escape(label)}</td><td>{html.escape(value)}</td></tr>' for label, value in summary_rows)}
  </table>
  <h2>Organization Counts</h2>
  <table>
    <thead><tr><th>Organization</th><th>Count</th></tr></thead>
    <tbody>{org_rows}</tbody>
  </table>
  <h2>Status Counts</h2>
  <table>
    <thead><tr><th>Status</th><th>Count</th></tr></thead>
    <tbody>{status_rows}</tbody>
  </table>
  <h2>Entries</h2>
  <table>
    <thead>
      <tr>
        <th>ID</th><th>Organization</th><th>Doc No</th><th>Title</th><th>Status</th><th>Priority</th>
        <th>Received At</th><th>Due At</th><th>Inspection</th><th>Work Order</th>
        <th>Closure Title</th><th>Closure Summary</th><th>Closed At</th><th>Overdue</th>
      </tr>
    </thead>
    <tbody>{entry_rows}</tbody>
  </table>
</body>
</html>
"""


@router.get("/api/official-documents", response_model=list[OfficialDocumentRead])
def list_official_documents(
    site: str | None = None,
    status: str | None = None,
    organization: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: dict[str, Any] = Depends(require_permission("official_docs:read")),
) -> list[OfficialDocumentRead]:
    _require_site_access(principal, site)
    stmt = select(official_documents)
    if site:
        stmt = stmt.where(official_documents.c.site == site)
    else:
        allowed_sites = _allowed_sites_for_principal(principal)
        if allowed_sites is not None:
            stmt = stmt.where(official_documents.c.site.in_(allowed_sites))
    if status:
        stmt = stmt.where(official_documents.c.status == _normalize_doc_status(status))
    if organization:
        stmt = stmt.where(official_documents.c.organization == organization)
    stmt = stmt.order_by(official_documents.c.updated_at.desc(), official_documents.c.id.desc()).limit(limit).offset(offset)
    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_official_document_model(dict(row)) for row in rows]


@router.post("/api/official-documents", response_model=OfficialDocumentRead, status_code=201)
def create_official_document(
    payload: OfficialDocumentCreate,
    principal: dict[str, Any] = Depends(require_permission("official_docs:write")),
) -> OfficialDocumentRead:
    _require_site_access(principal, payload.site)
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        _validate_linked_resources(
            conn,
            site=payload.site,
            linked_inspection_id=payload.linked_inspection_id,
            linked_work_order_id=payload.linked_work_order_id,
            principal=principal,
        )
        result = conn.execute(
            insert(official_documents).values(
                site=payload.site,
                organization=payload.organization.strip(),
                document_number=(payload.document_number or "").strip() or None,
                title=payload.title.strip(),
                document_type=payload.document_type.strip(),
                status="received",
                priority=_normalize_doc_priority(payload.priority),
                received_at=payload.received_at,
                due_at=payload.due_at,
                required_action=payload.required_action.strip(),
                summary=payload.summary.strip(),
                linked_inspection_id=payload.linked_inspection_id,
                linked_work_order_id=payload.linked_work_order_id,
                created_by=str(principal.get("username") or "system"),
                created_at=now,
                updated_at=now,
            )
        )
        document_id = result.inserted_primary_key[0]
        row = conn.execute(
            select(official_documents).where(official_documents.c.id == document_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to load created official document")
    model = _row_to_official_document_model(dict(row))
    _write_audit_log(
        principal=principal,
        action="official_document_create",
        resource_type="official_document",
        resource_id=str(model.id),
        detail={
            "site": model.site,
            "organization": model.organization,
            "document_number": model.document_number,
            "linked_inspection_id": model.linked_inspection_id,
            "linked_work_order_id": model.linked_work_order_id,
        },
    )
    return model


@router.get("/api/official-documents/{document_id}", response_model=OfficialDocumentRead)
def get_official_document(
    document_id: int,
    principal: dict[str, Any] = Depends(require_permission("official_docs:read")),
) -> OfficialDocumentRead:
    return _row_to_official_document_model(_load_official_document_or_404(document_id, principal))


@router.patch("/api/official-documents/{document_id}", response_model=OfficialDocumentRead)
def update_official_document(
    document_id: int,
    payload: OfficialDocumentUpdate,
    principal: dict[str, Any] = Depends(require_permission("official_docs:write")),
) -> OfficialDocumentRead:
    current = _load_official_document_or_404(document_id, principal)
    if current.get("status") == "closed" and payload.status not in {None, "closed"}:
        raise HTTPException(status_code=400, detail="Closed official document must be changed by closure policy")
    values: dict[str, Any] = {"updated_at": datetime.now(timezone.utc)}
    if payload.organization is not None:
        values["organization"] = payload.organization.strip()
    if payload.document_number is not None:
        values["document_number"] = payload.document_number.strip() or None
    if payload.title is not None:
        values["title"] = payload.title.strip()
    if payload.document_type is not None:
        values["document_type"] = payload.document_type.strip()
    if payload.status is not None:
        values["status"] = _normalize_doc_status(payload.status)
    if payload.priority is not None:
        values["priority"] = _normalize_doc_priority(payload.priority)
    if payload.received_at is not None:
        values["received_at"] = payload.received_at
    if "due_at" in payload.model_fields_set:
        values["due_at"] = payload.due_at
    if payload.required_action is not None:
        values["required_action"] = payload.required_action
    if payload.summary is not None:
        values["summary"] = payload.summary
    if "linked_inspection_id" in payload.model_fields_set:
        values["linked_inspection_id"] = payload.linked_inspection_id
    if "linked_work_order_id" in payload.model_fields_set:
        values["linked_work_order_id"] = payload.linked_work_order_id

    with get_conn() as conn:
        _validate_linked_resources(
            conn,
            site=str(current["site"]),
            linked_inspection_id=values.get("linked_inspection_id", current.get("linked_inspection_id")),
            linked_work_order_id=values.get("linked_work_order_id", current.get("linked_work_order_id")),
            principal=principal,
        )
        conn.execute(
            update(official_documents).where(official_documents.c.id == document_id).values(**values)
        )
        row = conn.execute(
            select(official_documents).where(official_documents.c.id == document_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to load updated official document")
    model = _row_to_official_document_model(dict(row))
    _write_audit_log(
        principal=principal,
        action="official_document_update",
        resource_type="official_document",
        resource_id=str(model.id),
        detail={"status": model.status},
    )
    return model


@router.post("/api/official-documents/{document_id}/close", response_model=OfficialDocumentRead)
def close_official_document(
    document_id: int,
    payload: OfficialDocumentCloseRequest,
    principal: dict[str, Any] = Depends(require_permission("official_docs:close")),
) -> OfficialDocumentRead:
    current = _load_official_document_or_404(document_id, principal)
    closed_at = payload.closed_at or datetime.now(timezone.utc)
    with get_conn() as conn:
        conn.execute(
            update(official_documents)
            .where(official_documents.c.id == document_id)
            .values(
                status="closed",
                closed_report_title=payload.closed_report_title.strip(),
                closure_summary=payload.closure_summary.strip(),
                closure_result=payload.closure_result.strip(),
                closed_at=closed_at,
                updated_at=datetime.now(timezone.utc),
            )
        )
        row = conn.execute(
            select(official_documents).where(official_documents.c.id == document_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to load closed official document")
    model = _row_to_official_document_model(dict(row))
    _write_audit_log(
        principal=principal,
        action="official_document_close",
        resource_type="official_document",
        resource_id=str(model.id),
        detail={
            "site": model.site,
            "closed_report_title": model.closed_report_title,
            "linked_inspection_id": model.linked_inspection_id,
            "linked_work_order_id": model.linked_work_order_id,
        },
    )
    return model


@router.get("/api/reports/official-documents/monthly", response_model=OfficialDocumentClosureReportRead)
def get_official_document_monthly_report(
    month: str | None = Query(default=None, description="YYYY-MM"),
    site: str | None = None,
    principal: dict[str, Any] = Depends(require_permission("reports:read")),
) -> OfficialDocumentClosureReportRead:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    return _build_official_document_report(period_type="monthly", month=month, site=site, allowed_sites=allowed_sites)


@router.get("/api/reports/official-documents/monthly/csv")
def get_official_document_monthly_report_csv(
    month: str | None = Query(default=None, description="YYYY-MM"),
    site: str | None = None,
    principal: dict[str, Any] = Depends(require_permission("reports:export")),
) -> Response:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = _build_official_document_report(period_type="monthly", month=month, site=site, allowed_sites=allowed_sites)
    csv_text = _build_official_document_report_csv(report)
    site_label = (report.site or "all").replace(" ", "_")
    file_name = f"official-document-monthly-report-{report.period_label}-{site_label}.csv"
    _write_audit_log(
        principal=principal,
        action="official_document_report_monthly_export_csv",
        resource_type="report",
        resource_id=f"monthly:{report.period_label}:{report.site or 'ALL'}",
        detail={"month": report.period_label, "site": report.site},
    )
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.get("/reports/official-documents/monthly/print", response_class=HTMLResponse)
def print_official_document_monthly_report(
    month: str | None = Query(default=None, description="YYYY-MM"),
    site: str | None = None,
    principal: dict[str, Any] = Depends(require_permission("reports:read")),
) -> str:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = _build_official_document_report(period_type="monthly", month=month, site=site, allowed_sites=allowed_sites)
    return _build_official_document_report_print_html(report)


@router.get("/api/reports/official-documents/annual", response_model=OfficialDocumentClosureReportRead)
def get_official_document_annual_report(
    year: int | None = Query(default=None, ge=2000, le=2100),
    site: str | None = None,
    principal: dict[str, Any] = Depends(require_permission("reports:read")),
) -> OfficialDocumentClosureReportRead:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    return _build_official_document_report(period_type="annual", year=year, site=site, allowed_sites=allowed_sites)


@router.get("/api/reports/official-documents/annual/csv")
def get_official_document_annual_report_csv(
    year: int | None = Query(default=None, ge=2000, le=2100),
    site: str | None = None,
    principal: dict[str, Any] = Depends(require_permission("reports:export")),
) -> Response:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = _build_official_document_report(period_type="annual", year=year, site=site, allowed_sites=allowed_sites)
    csv_text = _build_official_document_report_csv(report)
    site_label = (report.site or "all").replace(" ", "_")
    file_name = f"official-document-annual-report-{report.period_label}-{site_label}.csv"
    _write_audit_log(
        principal=principal,
        action="official_document_report_annual_export_csv",
        resource_type="report",
        resource_id=f"annual:{report.period_label}:{report.site or 'ALL'}",
        detail={"year": report.period_label, "site": report.site},
    )
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.get("/reports/official-documents/annual/print", response_class=HTMLResponse)
def print_official_document_annual_report(
    year: int | None = Query(default=None, ge=2000, le=2100),
    site: str | None = None,
    principal: dict[str, Any] = Depends(require_permission("reports:read")),
) -> str:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = _build_official_document_report(period_type="annual", year=year, site=site, allowed_sites=allowed_sites)
    return _build_official_document_report_print_html(report)

