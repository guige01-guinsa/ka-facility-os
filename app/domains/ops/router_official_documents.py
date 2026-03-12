"""Official document management and closure report routes."""

from __future__ import annotations

import csv
import html
import io
import json
import re
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile
from fastapi.responses import HTMLResponse
from sqlalchemy import func, insert, select, update

from app import main as main_module
from app.database import (
    get_conn,
    inspections,
    official_document_attachments,
    official_documents,
    utility_billing_statements,
    work_orders,
)
from app.schemas import (
    IntegratedMonthlyFacilityReportRead,
    OfficialDocumentAttachmentRead,
    OfficialDocumentCloseRequest,
    OfficialDocumentClosureReportEntryRead,
    OfficialDocumentClosureReportRead,
    OfficialDocumentCreate,
    OfficialDocumentOverdueSyncRead,
    OfficialDocumentRead,
    OfficialDocumentUpdate,
)

router = APIRouter(tags=["official-documents"])

_allowed_sites_for_principal = main_module._allowed_sites_for_principal
_append_work_order_event = main_module._append_work_order_event
_as_optional_datetime = main_module._as_optional_datetime
_is_allowed_evidence_content_type = main_module._is_allowed_evidence_content_type
_normalize_evidence_storage_backend = main_module._normalize_evidence_storage_backend
_read_evidence_blob = main_module._read_evidence_blob
_require_site_access = main_module._require_site_access
_row_to_work_order_model = main_module._row_to_work_order_model
_safe_download_filename = main_module._safe_download_filename
_scan_evidence_bytes = main_module._scan_evidence_bytes
_to_utc = main_module._to_utc
_write_audit_log = main_module._write_audit_log
_write_job_run = main_module._write_job_run
_write_evidence_blob = main_module._write_evidence_blob
run_sla_escalation_job = main_module.run_sla_escalation_job
require_permission = main_module.require_permission

_DOC_STATUSES = {"received", "in_progress", "closed", "canceled"}
_DOC_PRIORITIES = {"low", "medium", "high", "critical"}
_ATTACHMENT_CONTENT_TYPES = {"application/pdf", "image/jpeg", "image/png"}
_OFFICIAL_DOCUMENT_OVERDUE_JOB_NAME = "official_document_overdue_sync"


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


def _normalize_org_code(value: str | None, *, organization: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        candidate = str(organization or "").strip()
    candidate = re.sub(r"[^0-9A-Za-z가-힣]+", "", candidate).upper()
    candidate = candidate[:16]
    if not candidate:
        candidate = "ORG"
    return candidate


def _next_registry_number(
    conn: Any,
    *,
    site: str,
    organization_code: str,
    received_at: datetime,
) -> str:
    year_label = _to_utc(received_at).strftime("%Y")
    prefix = f"{organization_code}-{site.strip()}-{year_label}-"
    rows = conn.execute(
        select(official_documents.c.registry_number)
        .where(official_documents.c.site == site)
        .where(official_documents.c.organization_code == organization_code)
        .where(official_documents.c.received_at >= datetime(int(year_label), 1, 1, tzinfo=timezone.utc))
        .where(official_documents.c.received_at < datetime(int(year_label) + 1, 1, 1, tzinfo=timezone.utc))
        .order_by(official_documents.c.id.desc())
    ).all()
    max_seq = 0
    for row in rows:
        value = str(row[0] or "").strip()
        if not value.startswith(prefix):
            continue
        try:
            max_seq = max(max_seq, int(value.rsplit("-", 1)[1]))
        except (IndexError, ValueError):
            continue
    return f"{prefix}{max_seq + 1:04d}"


def _attachment_count_map(conn: Any, document_ids: list[int]) -> dict[int, int]:
    if not document_ids:
        return {}
    rows = conn.execute(
        select(
            official_document_attachments.c.document_id,
            func.count(official_document_attachments.c.id).label("attachment_count"),
        )
        .where(official_document_attachments.c.document_id.in_(document_ids))
        .group_by(official_document_attachments.c.document_id)
    ).all()
    return {int(row[0]): int(row[1] or 0) for row in rows}


def _row_to_attachment_model(row: dict[str, Any]) -> OfficialDocumentAttachmentRead:
    return OfficialDocumentAttachmentRead(
        id=int(row["id"]),
        document_id=int(row["document_id"]),
        site=str(row["site"]),
        file_name=str(row["file_name"]),
        content_type=str(row.get("content_type") or "application/octet-stream"),
        file_size=int(row.get("file_size") or 0),
        storage_backend=_normalize_evidence_storage_backend(str(row.get("storage_backend") or "db")),
        sha256=str(row.get("sha256") or ""),
        malware_scan_status=str(row.get("malware_scan_status") or "unknown"),
        malware_scan_engine=row.get("malware_scan_engine"),
        malware_scanned_at=_to_utc(row["malware_scanned_at"]) if row.get("malware_scanned_at") else None,
        note=str(row.get("note") or ""),
        uploaded_by=str(row.get("uploaded_by") or "system"),
        uploaded_at=_to_utc(row["uploaded_at"]),
    )


def _normalize_month_label(value: str) -> str:
    normalized = (value or "").strip()
    try:
        datetime.strptime(normalized, "%Y-%m")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="month must be YYYY-MM") from exc
    return normalized


def _normalize_period_filters(month: str | None, year: int | None) -> tuple[str | None, int | None]:
    if month and year is not None:
        raise HTTPException(status_code=422, detail="month and year cannot be used together")
    normalized_month = _normalize_month_label(month) if month else None
    normalized_year = int(year) if year is not None else None
    if normalized_year is not None and (normalized_year < 2000 or normalized_year > 2100):
        raise HTTPException(status_code=422, detail="year must be between 2000 and 2100")
    return normalized_month, normalized_year


def _zip_safe_segment(value: str | None, *, default: str) -> str:
    normalized = re.sub(r"[^0-9A-Za-z가-힣._-]+", "_", str(value or "").strip())
    normalized = normalized.strip("._-")
    return normalized or default


def _download_safe_segment(value: str | None, *, default: str) -> str:
    normalized = re.sub(r"[^0-9A-Za-z._-]+", "_", str(value or "").strip())
    normalized = normalized.strip("._-")
    return normalized or default


def _json_or_scalar(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    if value is None:
        return ""
    return str(value)


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


def _build_official_document_automation_principal(*, site: str | None = None) -> dict[str, Any]:
    scope = [site] if site else [main_module.SITE_SCOPE_ALL]
    return {
        "user_id": None,
        "username": "official-doc-automation",
        "display_name": "Official Document Automation",
        "role": "owner",
        "permissions": ["*"],
        "site_scope": scope,
        "is_legacy": False,
    }


def _row_to_official_document_model(row: dict[str, Any]) -> OfficialDocumentRead:
    return OfficialDocumentRead(
        id=int(row["id"]),
        site=str(row["site"]),
        organization=str(row["organization"]),
        organization_code=str(row["organization_code"]) if row.get("organization_code") else None,
        registry_number=str(row["registry_number"]) if row.get("registry_number") else None,
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
        attachment_count=int(row.get("attachment_count") or 0),
        created_by=str(row.get("created_by") or "system"),
        created_at=_to_utc(row["created_at"]),
        updated_at=_to_utc(row["updated_at"]),
    )


def _load_official_document_or_404(document_id: int, principal: dict[str, Any]) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute(
            select(official_documents).where(official_documents.c.id == document_id).limit(1)
        ).mappings().first()
        count_map = _attachment_count_map(conn, [document_id])
    if row is None:
        raise HTTPException(status_code=404, detail="Official document not found")
    payload = dict(row)
    payload["attachment_count"] = count_map.get(document_id, 0)
    _require_site_access(principal, str(payload["site"]))
    return payload


def _load_official_document_attachment_or_404(attachment_id: int, principal: dict[str, Any]) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute(
            select(official_document_attachments).where(official_document_attachments.c.id == attachment_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Official document attachment not found")
    payload = dict(row)
    _require_site_access(principal, str(payload["site"]))
    return payload


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


def _ensure_registry_fields(conn: Any, row: dict[str, Any]) -> dict[str, Any]:
    payload = dict(row)
    next_values: dict[str, Any] = {}
    organization_code = str(payload.get("organization_code") or "").strip()
    if not organization_code:
        organization_code = _normalize_org_code(None, organization=str(payload.get("organization") or ""))
        next_values["organization_code"] = organization_code
    registry_number = str(payload.get("registry_number") or "").strip()
    if not registry_number:
        registry_number = _next_registry_number(
            conn,
            site=str(payload["site"]),
            organization_code=organization_code,
            received_at=_to_utc(payload["received_at"]),
        )
        next_values["registry_number"] = registry_number
    if next_values:
        next_values["updated_at"] = datetime.now(timezone.utc)
        conn.execute(
            update(official_documents)
            .where(official_documents.c.id == int(payload["id"]))
            .values(**next_values)
        )
        payload.update(next_values)
    payload["organization_code"] = organization_code
    payload["registry_number"] = registry_number
    return payload


def _create_overdue_work_order_for_document(
    conn: Any,
    *,
    row: dict[str, Any],
    principal: dict[str, Any],
    now: datetime,
) -> int:
    actor_username = str(principal.get("username") or "unknown")
    due_at = _to_utc(row["due_at"]) if row.get("due_at") else now - timedelta(minutes=1)
    work_order_priority = "critical" if str(row.get("priority") or "medium") == "critical" else "high"
    title = f"[공문기한초과] {str(row.get('title') or '').strip()[:160]}"
    description_lines = [
        f"기관: {str(row.get('organization') or '').strip()}",
        f"접수대장번호: {str(row.get('registry_number') or '-').strip() or '-'}",
        f"공문번호: {str(row.get('document_number') or '-').strip() or '-'}",
        f"요구조치: {str(row.get('required_action') or '').strip()}",
        f"진행메모: {str(row.get('summary') or '').strip()}",
        "자동생성 사유: 공문 기한 초과",
    ]
    result = conn.execute(
        insert(work_orders).values(
            title=title,
            description="\n".join(item for item in description_lines if item),
            site=str(row["site"]),
            location=f"기관공문/{str(row.get('organization') or '미상')[:80]}",
            priority=work_order_priority,
            status="open",
            assignee=None,
            reporter=actor_username,
            inspection_id=row.get("linked_inspection_id"),
            due_at=due_at,
            acknowledged_at=None,
            completed_at=None,
            resolution_notes="",
            is_escalated=False,
            created_at=now,
            updated_at=now,
        )
    )
    work_order_id = int(result.inserted_primary_key[0])
    _append_work_order_event(
        conn,
        work_order_id=work_order_id,
        event_type="created",
        actor_username=actor_username,
        from_status=None,
        to_status="open",
        note="공문 기한 초과로 자동 생성",
        detail={
            "source": "official_document_overdue",
            "official_document_id": int(row["id"]),
            "registry_number": row.get("registry_number"),
            "organization": row.get("organization"),
        },
    )
    conn.execute(
        update(official_documents)
        .where(official_documents.c.id == int(row["id"]))
        .values(
            linked_work_order_id=work_order_id,
            status="in_progress" if str(row.get("status") or "received") == "received" else row.get("status"),
            updated_at=now,
        )
    )
    return work_order_id


def _run_official_document_overdue_sync(
    *,
    principal: dict[str, Any],
    site: str | None,
    allowed_sites: list[str] | None,
    dry_run: bool,
    limit: int,
) -> OfficialDocumentOverdueSyncRead:
    now = datetime.now(timezone.utc)
    stmt = (
        select(official_documents)
        .where(official_documents.c.due_at.is_not(None))
        .where(official_documents.c.due_at < now)
        .where(official_documents.c.status.in_(["received", "in_progress"]))
        .order_by(official_documents.c.due_at.asc(), official_documents.c.id.asc())
        .limit(limit)
    )
    if site is not None:
        stmt = stmt.where(official_documents.c.site == site)
    elif allowed_sites is not None:
        if not allowed_sites:
            return OfficialDocumentOverdueSyncRead(
                checked_at=now,
                site=site,
                dry_run=dry_run,
                candidate_count=0,
                work_order_created_count=0,
                linked_existing_work_order_count=0,
                document_ids=[],
                work_order_ids=[],
                alert_run={},
            )
        stmt = stmt.where(official_documents.c.site.in_(allowed_sites))

    created_work_order_ids: list[int] = []
    linked_existing_count = 0
    candidate_document_ids: list[int] = []

    with get_conn() as conn:
        rows = [dict(item) for item in conn.execute(stmt).mappings().all()]
        for raw_row in rows:
            row = _ensure_registry_fields(conn, raw_row)
            linked_work_order_id = row.get("linked_work_order_id")
            linked_row = None
            if linked_work_order_id is not None:
                linked_row = conn.execute(
                    select(work_orders).where(work_orders.c.id == int(linked_work_order_id)).limit(1)
                ).mappings().first()
            if linked_work_order_id is not None and linked_row is not None:
                candidate_document_ids.append(int(row["id"]))
                linked_existing_count += 1
                continue
            candidate_document_ids.append(int(row["id"]))
            if dry_run:
                continue
            created_work_order_ids.append(
                _create_overdue_work_order_for_document(conn, row=row, principal=principal, now=now)
            )

    alert_run: dict[str, Any] = {}
    if not dry_run and candidate_document_ids:
        sla_result = run_sla_escalation_job(
            site=site,
            dry_run=False,
            limit=max(limit, len(candidate_document_ids)),
            allowed_sites=allowed_sites,
            trigger="official_document_overdue",
        )
        if hasattr(sla_result, "model_dump"):
            alert_run = sla_result.model_dump(mode="json")
        else:
            alert_run = sla_result.dict()

    return OfficialDocumentOverdueSyncRead(
        checked_at=now,
        site=site,
        dry_run=dry_run,
        candidate_count=len(candidate_document_ids),
        work_order_created_count=len(created_work_order_ids),
        linked_existing_work_order_count=linked_existing_count,
        document_ids=candidate_document_ids,
        work_order_ids=created_work_order_ids,
        alert_run=alert_run,
    )


def run_official_document_overdue_sync_job(
    *,
    site: str | None = None,
    dry_run: bool = False,
    limit: int = 100,
    trigger: str = "manual",
    principal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    actor = principal or _build_official_document_automation_principal(site=site)
    status = "success"
    detail: dict[str, Any] = {
        "site": site,
        "dry_run": dry_run,
        "limit": limit,
    }
    try:
        allowed_sites = _allowed_sites_for_principal(actor) if site is None else None
        result = _run_official_document_overdue_sync(
            principal=actor,
            site=site,
            allowed_sites=allowed_sites,
            dry_run=dry_run,
            limit=limit,
        )
        detail.update(result.model_dump(mode="json"))
        return detail
    except Exception as exc:
        status = "failed"
        detail["error"] = str(exc)
        raise
    finally:
        finished_at = datetime.now(timezone.utc)
        detail.update(
            {
                "job_name": _OFFICIAL_DOCUMENT_OVERDUE_JOB_NAME,
                "trigger": trigger,
                "actor_username": str(actor.get("username") or "unknown"),
            }
        )
        _write_job_run(
            job_name=_OFFICIAL_DOCUMENT_OVERDUE_JOB_NAME,
            trigger=trigger,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            detail=detail,
        )


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
        rows = [_ensure_registry_fields(conn, dict(row)) for row in conn.execute(stmt).mappings().all()]
        count_map = _attachment_count_map(conn, [int(row["id"]) for row in rows])

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
                organization_code=str(row["organization_code"]) if row.get("organization_code") else None,
                registry_number=str(row["registry_number"]) if row.get("registry_number") else None,
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
                attachment_count=count_map.get(int(row["id"]), 0),
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
        "id", "site", "organization", "organization_code", "registry_number", "document_number", "title", "document_type", "status", "priority",
        "received_at", "due_at", "linked_inspection_id", "linked_work_order_id", "closed_report_title",
        "closure_summary", "closure_result", "closed_at", "attachment_count", "is_overdue",
    ])
    for entry in report.entries:
        writer.writerow([
            entry.id,
            entry.site,
            entry.organization,
            entry.organization_code or "",
            entry.registry_number or "",
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
            entry.attachment_count,
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
            f"<td>{html.escape(entry.registry_number or '-')}</td>"
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
            f"<td>{entry.attachment_count}</td>"
            f"<td>{'YES' if entry.is_overdue else 'NO'}</td>"
            "</tr>"
        )
        for entry in report.entries
    ) or "<tr><td colspan='16'>No entries</td></tr>"

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
        <th>ID</th><th>Organization</th><th>Registry No</th><th>Doc No</th><th>Title</th><th>Status</th><th>Priority</th>
        <th>Received At</th><th>Due At</th><th>Inspection</th><th>Work Order</th>
        <th>Closure Title</th><th>Closure Summary</th><th>Closed At</th><th>Attachments</th><th>Overdue</th>
      </tr>
    </thead>
    <tbody>{entry_rows}</tbody>
  </table>
</body>
</html>
"""


def _build_period_ops_summary(
    *,
    start: datetime,
    end: datetime,
    period_label: str,
    site: str | None,
    allowed_sites: list[str] | None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    inspections_stmt = (
        select(inspections)
        .where(inspections.c.inspected_at >= start)
        .where(inspections.c.inspected_at < end)
    )
    work_orders_stmt = (
        select(work_orders)
        .where(work_orders.c.created_at >= start)
        .where(work_orders.c.created_at < end)
    )
    if site is not None:
        inspections_stmt = inspections_stmt.where(inspections.c.site == site)
        work_orders_stmt = work_orders_stmt.where(work_orders.c.site == site)
    elif allowed_sites is not None:
        if not allowed_sites:
            return {
                "generated_at": now,
                "period_label": period_label,
                "site": site,
                "inspections": {
                    "total": 0,
                    "risk_counts": {"normal": 0, "warning": 0, "danger": 0},
                    "top_risk_flags": {},
                },
                "work_orders": {
                    "total": 0,
                    "status_counts": {"open": 0, "acked": 0, "completed": 0, "canceled": 0},
                    "escalated_count": 0,
                    "overdue_open_count": 0,
                    "completion_rate_percent": 0.0,
                    "avg_resolution_hours": None,
                },
            }
        inspections_stmt = inspections_stmt.where(inspections.c.site.in_(allowed_sites))
        work_orders_stmt = work_orders_stmt.where(work_orders.c.site.in_(allowed_sites))

    with get_conn() as conn:
        inspection_rows = conn.execute(inspections_stmt).mappings().all()
        work_order_rows = conn.execute(work_orders_stmt).mappings().all()

    risk_counts = {"normal": 0, "warning": 0, "danger": 0}
    flag_counts: dict[str, int] = {}
    for row in inspection_rows:
        risk_level = str(row.get("risk_level") or "normal")
        risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        for flag in str(row.get("risk_flags") or "").split(","):
            normalized_flag = flag.strip()
            if not normalized_flag:
                continue
            flag_counts[normalized_flag] = flag_counts.get(normalized_flag, 0) + 1

    status_counts = {"open": 0, "acked": 0, "completed": 0, "canceled": 0}
    escalated_count = 0
    overdue_open_count = 0
    resolution_hours: list[float] = []
    for row in work_order_rows:
        status = str(row.get("status") or "open")
        status_counts[status] = status_counts.get(status, 0) + 1
        if row.get("is_escalated"):
            escalated_count += 1

        due_at = _as_optional_datetime(row.get("due_at"))
        if due_at is not None and status not in {"completed", "canceled"} and due_at < now:
            overdue_open_count += 1

        created_at = _as_optional_datetime(row.get("created_at"))
        completed_at = _as_optional_datetime(row.get("completed_at"))
        if created_at is not None and completed_at is not None:
            hours = (completed_at - created_at).total_seconds() / 3600
            if hours >= 0:
                resolution_hours.append(hours)

    total_work_orders = len(work_order_rows)
    completed_count = status_counts.get("completed", 0)
    completion_rate = round((completed_count / total_work_orders * 100), 2) if total_work_orders else 0.0
    avg_resolution_hours = round(sum(resolution_hours) / len(resolution_hours), 2) if resolution_hours else None
    return {
        "generated_at": now,
        "period_label": period_label,
        "site": site,
        "inspections": {
            "total": len(inspection_rows),
            "risk_counts": risk_counts,
            "top_risk_flags": dict(sorted(flag_counts.items(), key=lambda item: item[1], reverse=True)[:10]),
        },
        "work_orders": {
            "total": total_work_orders,
            "status_counts": status_counts,
            "escalated_count": escalated_count,
            "overdue_open_count": overdue_open_count,
            "completion_rate_percent": completion_rate,
            "avg_resolution_hours": avg_resolution_hours,
        },
    }


def _build_integrated_billing_summary(
    *,
    start: datetime,
    end: datetime,
    site: str | None,
    allowed_sites: list[str] | None,
) -> dict[str, Any]:
    start_label = start.strftime("%Y-%m")
    end_label = end.strftime("%Y-%m")
    stmt = (
        select(
            utility_billing_statements.c.utility_type,
            func.count(utility_billing_statements.c.id).label("statement_count"),
            func.sum(utility_billing_statements.c.total_amount).label("total_amount"),
            func.sum(utility_billing_statements.c.common_fee).label("common_fee_total"),
        )
        .where(utility_billing_statements.c.billing_month >= start_label)
        .where(utility_billing_statements.c.billing_month < end_label)
    )
    if site is not None:
        stmt = stmt.where(utility_billing_statements.c.site == site)
    elif allowed_sites is not None:
        if allowed_sites:
            stmt = stmt.where(utility_billing_statements.c.site.in_(allowed_sites))
        else:
            return {
                "statement_count": 0,
                "utility_totals": {},
                "total_amount": 0.0,
                "common_fee_total": 0.0,
            }

    billing_summary: dict[str, Any] = {
        "statement_count": 0,
        "utility_totals": {},
        "total_amount": 0.0,
        "common_fee_total": 0.0,
    }
    with get_conn() as conn:
        rows = conn.execute(stmt.group_by(utility_billing_statements.c.utility_type)).all()
    for row in rows:
        utility_type = str(row[0] or "unknown")
        statement_count = int(row[1] or 0)
        total_amount = round(float(row[2] or 0), 2)
        common_fee_total = round(float(row[3] or 0), 2)
        billing_summary["statement_count"] += statement_count
        billing_summary["total_amount"] = round(float(billing_summary["total_amount"]) + total_amount, 2)
        billing_summary["common_fee_total"] = round(
            float(billing_summary["common_fee_total"]) + common_fee_total,
            2,
        )
        billing_summary["utility_totals"][utility_type] = {
            "statement_count": statement_count,
            "total_amount": total_amount,
            "common_fee_total": common_fee_total,
        }
    return billing_summary


def _build_integrated_report(
    *,
    period_type: str,
    site: str | None,
    month: str | None = None,
    year: int | None = None,
    allowed_sites: list[str] | None,
) -> IntegratedMonthlyFacilityReportRead:
    start, end, period_label = _period_bounds(period_type=period_type, month=month, year=year)
    ops_summary = _build_period_ops_summary(
        start=start,
        end=end,
        period_label=period_label,
        site=site,
        allowed_sites=allowed_sites,
    )
    official_report = _build_official_document_report(
        period_type=period_type,
        month=month,
        year=year,
        site=site,
        allowed_sites=allowed_sites,
    )
    billing_summary = _build_integrated_billing_summary(
        start=start,
        end=end,
        site=site,
        allowed_sites=allowed_sites,
    )
    return IntegratedMonthlyFacilityReportRead(
        generated_at=ops_summary["generated_at"],
        period_type="monthly" if period_type == "monthly" else "annual",
        period_label=period_label,
        month=period_label if period_type == "monthly" else None,
        year=int(period_label) if period_type == "annual" else None,
        site=site,
        merged_sections=["ops_inspections", "ops_work_orders", "official_documents", "utility_billing"],
        inspections=ops_summary["inspections"],
        work_orders=ops_summary["work_orders"],
        official_documents={
            "total_documents": official_report.total_documents,
            "closed_in_period": official_report.closed_in_period,
            "open_documents": official_report.open_documents,
            "overdue_open_documents": official_report.overdue_open_documents,
            "organization_counts": official_report.organization_counts,
            "status_counts": official_report.status_counts,
        },
        billing=billing_summary,
    )


def _build_integrated_report_csv(report: IntegratedMonthlyFacilityReportRead) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["period_type", report.period_type])
    writer.writerow(["period_label", report.period_label])
    writer.writerow(["month", report.month or ""])
    writer.writerow(["year", report.year or ""])
    writer.writerow(["site", report.site or "ALL"])
    writer.writerow(["generated_at", report.generated_at.isoformat()])
    writer.writerow(["merged_sections", ",".join(report.merged_sections)])
    writer.writerow([])
    writer.writerow(["section", "key", "value"])
    for section_name, section_payload in (
        ("inspections", report.inspections),
        ("work_orders", report.work_orders),
        ("official_documents", report.official_documents),
        ("billing", report.billing),
    ):
        for key, value in section_payload.items():
            writer.writerow([section_name, key, _json_or_scalar(value)])
    return buffer.getvalue()


def _build_integrated_report_print_html(report: IntegratedMonthlyFacilityReportRead) -> str:
    def _render_rows(section: dict[str, Any]) -> str:
        return "".join(
            f"<tr><td>{html.escape(str(key))}</td><td>{html.escape(_json_or_scalar(value))}</td></tr>"
            for key, value in section.items()
        ) or "<tr><td colspan='2'>No data</td></tr>"

    title_label = "Integrated Monthly Facility Report" if report.period_type == "monthly" else "Integrated Annual Facility Report"
    month_or_year_label = report.month or str(report.year or report.period_label)
    return f"""
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{html.escape(title_label)} {html.escape(month_or_year_label)}</title>
  <style>
    @page {{ size: A4; margin: 12mm; }}
    body {{ font-family: Arial, sans-serif; color: #111; }}
    h1 {{ margin-bottom: 8px; font-size: 22px; }}
    h2 {{ margin-top: 18px; margin-bottom: 6px; font-size: 15px; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 10px; }}
    th, td {{ border: 1px solid #d8dee8; padding: 6px; font-size: 12px; vertical-align: top; text-align: left; }}
    th {{ background: #f5f8fc; }}
    .summary td:first-child {{ width: 32%; background: #f5f8fc; font-weight: 700; }}
  </style>
</head>
<body>
  <h1>{html.escape(title_label)} ({html.escape(month_or_year_label)})</h1>
  <table class=\"summary\">
    <tr><td>Period Type</td><td>{html.escape(report.period_type)}</td></tr>
    <tr><td>Period</td><td>{html.escape(report.period_label)}</td></tr>
    <tr><td>Site</td><td>{html.escape(report.site or 'ALL')}</td></tr>
    <tr><td>Generated At</td><td>{html.escape(report.generated_at.isoformat())}</td></tr>
    <tr><td>Merged Sections</td><td>{html.escape(', '.join(report.merged_sections))}</td></tr>
  </table>
  <h2>법정점검 / OPS 점검</h2>
  <table><tbody>{_render_rows(report.inspections)}</tbody></table>
  <h2>작업지시 / SLA</h2>
  <table><tbody>{_render_rows(report.work_orders)}</tbody></table>
  <h2>공문 종결보고</h2>
  <table><tbody>{_render_rows(report.official_documents)}</tbody></table>
  <h2>관리비 부과(전기/수도)</h2>
  <table><tbody>{_render_rows(report.billing)}</tbody></table>
</body>
</html>
"""


def _build_integrated_report_pdf(report: IntegratedMonthlyFacilityReportRead) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise HTTPException(status_code=500, detail="PDF generator dependency not installed") from exc

    def _flatten_section_lines(title: str, payload: dict[str, Any], *, indent: int = 0) -> list[str]:
        lines = [title]
        prefix = "  " * indent
        for key, value in payload.items():
            if isinstance(value, dict):
                lines.append(f"{prefix}{key}:")
                lines.extend(_flatten_section_lines("", value, indent=indent + 1)[1:])
                continue
            lines.append(f"{prefix}{key}: {_json_or_scalar(value)}")
        return lines

    title = "Integrated Monthly Facility Report" if report.period_type == "monthly" else "Integrated Annual Facility Report"
    period_value = report.month or str(report.year or report.period_label)
    lines = [
        f"{title} ({period_value})",
        "",
        f"Period Type: {report.period_type}",
        f"Period Label: {report.period_label}",
        f"Site: {report.site or 'ALL'}",
        f"Generated At: {report.generated_at.isoformat()}",
        f"Merged Sections: {', '.join(report.merged_sections)}",
        "",
    ]
    for section_title, payload in (
        ("[Inspection Summary]", report.inspections),
        ("[Work Order Summary]", report.work_orders),
        ("[Official Document Summary]", report.official_documents),
        ("[Utility Billing Summary]", report.billing),
    ):
        lines.extend(_flatten_section_lines(section_title, payload))
        lines.append("")

    buf = io.BytesIO()
    pdf = canvas.Canvas(buf, pagesize=A4)
    _, height = A4
    margin_left = 36
    y = height - 40
    pdf.setFont("Helvetica", 10)
    for line in lines:
        if y < 40:
            pdf.showPage()
            pdf.setFont("Helvetica", 10)
            y = height - 40
        pdf.drawString(margin_left, y, line[:180])
        y -= 14
    pdf.save()
    return buf.getvalue()


def _load_filtered_official_document_rows(
    *,
    site: str | None,
    organization: str | None,
    status: str | None,
    month: str | None,
    year: int | None,
    allowed_sites: list[str] | None,
) -> list[dict[str, Any]]:
    normalized_month, normalized_year = _normalize_period_filters(month, year)
    stmt = select(official_documents)
    if site is not None:
        stmt = stmt.where(official_documents.c.site == site)
    elif allowed_sites is not None:
        if not allowed_sites:
            return []
        stmt = stmt.where(official_documents.c.site.in_(allowed_sites))
    if organization:
        stmt = stmt.where(official_documents.c.organization == organization)
    if status:
        stmt = stmt.where(official_documents.c.status == _normalize_doc_status(status))
    if normalized_month is not None:
        start, end, _ = _period_bounds(period_type="monthly", month=normalized_month)
        stmt = stmt.where(official_documents.c.received_at >= start).where(official_documents.c.received_at < end)
    elif normalized_year is not None:
        start, end, _ = _period_bounds(period_type="annual", year=normalized_year)
        stmt = stmt.where(official_documents.c.received_at >= start).where(official_documents.c.received_at < end)
    stmt = stmt.order_by(
        official_documents.c.organization.asc(),
        official_documents.c.received_at.desc(),
        official_documents.c.id.desc(),
    )
    with get_conn() as conn:
        rows = [_ensure_registry_fields(conn, dict(row)) for row in conn.execute(stmt).mappings().all()]
        count_map = _attachment_count_map(conn, [int(row["id"]) for row in rows])
    return [{**row, "attachment_count": count_map.get(int(row["id"]), 0)} for row in rows]


def _load_attachment_rows_for_documents(document_ids: list[int]) -> list[dict[str, Any]]:
    if not document_ids:
        return []
    with get_conn() as conn:
        rows = conn.execute(
            select(official_document_attachments)
            .where(official_document_attachments.c.document_id.in_(document_ids))
            .order_by(
                official_document_attachments.c.document_id.asc(),
                official_document_attachments.c.uploaded_at.asc(),
                official_document_attachments.c.id.asc(),
            )
        ).mappings().all()
    return [dict(row) for row in rows]


def _build_official_document_registry_csv(rows: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "id",
            "site",
            "organization",
            "organization_code",
            "registry_number",
            "document_number",
            "title",
            "document_type",
            "status",
            "priority",
            "received_at",
            "due_at",
            "linked_inspection_id",
            "linked_work_order_id",
            "attachment_count",
            "closed_at",
        ]
    )
    for row in rows:
        writer.writerow(
            [
                int(row["id"]),
                str(row["site"]),
                str(row.get("organization") or ""),
                str(row.get("organization_code") or ""),
                str(row.get("registry_number") or ""),
                str(row.get("document_number") or ""),
                str(row.get("title") or ""),
                str(row.get("document_type") or ""),
                _normalize_doc_status(row.get("status")),
                _normalize_doc_priority(row.get("priority")),
                _to_utc(row["received_at"]).isoformat(),
                _to_utc(row["due_at"]).isoformat() if row.get("due_at") else "",
                row.get("linked_inspection_id") or "",
                row.get("linked_work_order_id") or "",
                int(row.get("attachment_count") or 0),
                _to_utc(row["closed_at"]).isoformat() if row.get("closed_at") else "",
            ]
        )
    return buffer.getvalue()


def _build_official_document_attachments_zip(
    *,
    document_rows: list[dict[str, Any]],
    attachment_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    if not attachment_rows:
        raise HTTPException(status_code=404, detail="No official document attachments matched the filters")
    document_map = {int(row["id"]): row for row in document_rows}
    manifest_buffer = io.StringIO()
    manifest_writer = csv.writer(manifest_buffer)
    manifest_writer.writerow(
        [
            "document_id",
            "site",
            "organization",
            "registry_number",
            "document_number",
            "attachment_id",
            "file_name",
            "content_type",
            "file_size",
            "sha256",
            "zip_path",
            "blob_status",
        ]
    )
    payload = io.BytesIO()
    archived_count = 0
    missing_blob_count = 0
    with zipfile.ZipFile(payload, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for row in attachment_rows:
            document_row = document_map.get(int(row["document_id"]))
            if document_row is None:
                continue
            folder_name = "/".join(
                [
                    _zip_safe_segment(str(document_row.get("site") or "site"), default="site"),
                    _zip_safe_segment(str(document_row.get("organization") or "organization"), default="organization"),
                    _zip_safe_segment(str(document_row.get("registry_number") or document_row["id"]), default="registry"),
                ]
            )
            file_name = _safe_download_filename(str(row.get("file_name") or f"attachment-{row['id']}.bin"))
            zip_path = f"{folder_name}/{int(row['id'])}_{file_name}"
            file_bytes = _read_evidence_blob(row=row)
            blob_status = "ok"
            if file_bytes is None:
                blob_status = "missing_blob"
                missing_blob_count += 1
            else:
                archive.writestr(zip_path, file_bytes)
                archived_count += 1
            manifest_writer.writerow(
                [
                    int(document_row["id"]),
                    str(document_row["site"]),
                    str(document_row.get("organization") or ""),
                    str(document_row.get("registry_number") or ""),
                    str(document_row.get("document_number") or ""),
                    int(row["id"]),
                    file_name,
                    str(row.get("content_type") or "application/octet-stream"),
                    int(row.get("file_size") or 0),
                    str(row.get("sha256") or ""),
                    zip_path,
                    blob_status,
                ]
            )
        archive.writestr("manifest.csv", manifest_buffer.getvalue().encode("utf-8"))
    if archived_count <= 0:
        raise HTTPException(status_code=404, detail="Attachment blobs were not available for ZIP export")
    return {
        "file_bytes": payload.getvalue(),
        "attachment_count": archived_count,
        "missing_blob_count": missing_blob_count,
        "document_count": len(document_rows),
    }


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
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    _run_official_document_overdue_sync(
        principal=principal,
        site=site,
        allowed_sites=allowed_sites,
        dry_run=False,
        limit=min(limit, 50),
    )
    stmt = select(official_documents)
    if site:
        stmt = stmt.where(official_documents.c.site == site)
    else:
        if allowed_sites is not None:
            stmt = stmt.where(official_documents.c.site.in_(allowed_sites))
    if status:
        stmt = stmt.where(official_documents.c.status == _normalize_doc_status(status))
    if organization:
        stmt = stmt.where(official_documents.c.organization == organization)
    stmt = stmt.order_by(official_documents.c.updated_at.desc(), official_documents.c.id.desc()).limit(limit).offset(offset)
    with get_conn() as conn:
        rows = [_ensure_registry_fields(conn, dict(row)) for row in conn.execute(stmt).mappings().all()]
        count_map = _attachment_count_map(conn, [int(row["id"]) for row in rows])
    return [_row_to_official_document_model({**row, "attachment_count": count_map.get(int(row["id"]), 0)}) for row in rows]


@router.post("/api/official-documents", response_model=OfficialDocumentRead, status_code=201)
def create_official_document(
    payload: OfficialDocumentCreate,
    principal: dict[str, Any] = Depends(require_permission("official_docs:write")),
) -> OfficialDocumentRead:
    _require_site_access(principal, payload.site)
    now = datetime.now(timezone.utc)
    actor_username = str(principal.get("username") or "unknown")
    with get_conn() as conn:
        _validate_linked_resources(
            conn,
            site=payload.site,
            linked_inspection_id=payload.linked_inspection_id,
            linked_work_order_id=payload.linked_work_order_id,
            principal=principal,
        )
        organization_code = _normalize_org_code(payload.organization_code, organization=payload.organization)
        registry_number = (payload.registry_number or "").strip() or _next_registry_number(
            conn,
            site=payload.site,
            organization_code=organization_code,
            received_at=payload.received_at,
        )
        result = conn.execute(
            insert(official_documents).values(
                site=payload.site,
                organization=payload.organization.strip(),
                organization_code=organization_code,
                registry_number=registry_number,
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
                created_by=actor_username,
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
    model = _row_to_official_document_model({**dict(row), "attachment_count": 0})
    if model.due_at is not None and model.status != "closed" and model.due_at < now:
        _run_official_document_overdue_sync(
            principal=principal,
            site=model.site,
            allowed_sites=None,
            dry_run=False,
            limit=10,
        )
        model = _row_to_official_document_model(_load_official_document_or_404(int(document_id), principal))
    _write_audit_log(
        principal=principal,
        action="official_document_create",
        resource_type="official_document",
        resource_id=str(model.id),
        detail={
            "site": model.site,
            "organization": model.organization,
            "organization_code": model.organization_code,
            "registry_number": model.registry_number,
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
    if payload.organization_code is not None:
        values["organization_code"] = _normalize_org_code(payload.organization_code, organization=str(payload.organization or current["organization"]))
    if payload.registry_number is not None:
        values["registry_number"] = payload.registry_number.strip() or None
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
    model = _row_to_official_document_model(_load_official_document_or_404(document_id, principal))
    if model.due_at is not None and model.status != "closed" and model.due_at < datetime.now(timezone.utc):
        _run_official_document_overdue_sync(
            principal=principal,
            site=model.site,
            allowed_sites=None,
            dry_run=False,
            limit=10,
        )
        model = _row_to_official_document_model(_load_official_document_or_404(document_id, principal))
    _write_audit_log(
        principal=principal,
        action="official_document_update",
        resource_type="official_document",
        resource_id=str(model.id),
        detail={
            "status": model.status,
            "registry_number": model.registry_number,
            "linked_work_order_id": model.linked_work_order_id,
        },
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
    model = _row_to_official_document_model(_load_official_document_or_404(document_id, principal))
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


@router.get("/api/official-documents/{document_id}/attachments", response_model=list[OfficialDocumentAttachmentRead])
def list_official_document_attachments(
    document_id: int,
    principal: dict[str, Any] = Depends(require_permission("official_docs:read")),
) -> list[OfficialDocumentAttachmentRead]:
    current = _load_official_document_or_404(document_id, principal)
    with get_conn() as conn:
        rows = conn.execute(
            select(official_document_attachments)
            .where(official_document_attachments.c.document_id == document_id)
            .order_by(official_document_attachments.c.uploaded_at.desc(), official_document_attachments.c.id.desc())
        ).mappings().all()
    return [_row_to_attachment_model(dict(row)) for row in rows if str(row.get("site") or "") == str(current["site"])]


@router.post("/api/official-documents/{document_id}/attachments", response_model=OfficialDocumentAttachmentRead, status_code=201)
async def upload_official_document_attachment(
    document_id: int,
    file: UploadFile = File(...),
    note: str = Form(default=""),
    principal: dict[str, Any] = Depends(require_permission("official_docs:write")),
) -> OfficialDocumentAttachmentRead:
    current = _load_official_document_or_404(document_id, principal)
    content_type = (file.content_type or "").strip().lower()
    if content_type not in _ATTACHMENT_CONTENT_TYPES or not _is_allowed_evidence_content_type(content_type):
        raise HTTPException(status_code=415, detail="Only PDF/JPEG/PNG attachments are supported")
    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Attachment is empty")
    sha256 = main_module.hashlib.sha256(file_bytes).hexdigest()
    scan_status, scan_engine, scan_reason = _scan_evidence_bytes(file_bytes=file_bytes, content_type=content_type)
    storage_backend, storage_key, stored_bytes = _write_evidence_blob(
        file_name=file.filename or "official-document-attachment.bin",
        file_bytes=file_bytes,
        sha256_digest=sha256,
    )
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        result = conn.execute(
            insert(official_document_attachments).values(
                document_id=document_id,
                site=str(current["site"]),
                file_name=(file.filename or "attachment.bin").strip(),
                content_type=content_type or "application/octet-stream",
                file_size=len(file_bytes),
                storage_backend=storage_backend,
                storage_key=storage_key,
                file_bytes=stored_bytes,
                sha256=sha256,
                malware_scan_status=scan_status,
                malware_scan_engine=scan_engine,
                malware_scanned_at=now,
                note=(note or "").strip(),
                uploaded_by=str(principal.get("username") or "unknown"),
                uploaded_at=now,
            )
        )
        attachment_id = int(result.inserted_primary_key[0])
        row = conn.execute(
            select(official_document_attachments).where(official_document_attachments.c.id == attachment_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to load created attachment")
    model = _row_to_attachment_model(dict(row))
    _write_audit_log(
        principal=principal,
        action="official_document_attachment_upload",
        resource_type="official_document_attachment",
        resource_id=str(model.id),
        detail={
            "document_id": document_id,
            "site": model.site,
            "file_name": model.file_name,
            "content_type": model.content_type,
            "scan_status": model.malware_scan_status,
            "scan_reason": scan_reason,
        },
    )
    return model


@router.get("/api/official-documents/attachments/{attachment_id}/download")
def download_official_document_attachment(
    attachment_id: int,
    principal: dict[str, Any] = Depends(require_permission("official_docs:read")),
) -> Response:
    row = _load_official_document_attachment_or_404(attachment_id, principal)
    file_bytes = _read_evidence_blob(row=row)
    if file_bytes is None:
        raise HTTPException(status_code=404, detail="Attachment blob not found")
    file_name = _safe_download_filename(str(row.get("file_name") or "attachment.bin"))
    return Response(
        content=file_bytes,
        media_type=str(row.get("content_type") or "application/octet-stream"),
        headers={
            "Content-Disposition": f'attachment; filename="{file_name}"',
            "X-Attachment-SHA256": str(row.get("sha256") or ""),
        },
    )


@router.get("/api/official-documents/attachments/zip")
def download_official_document_attachments_zip(
    site: str | None = None,
    organization: str | None = None,
    status: str | None = None,
    month: str | None = Query(default=None, description="YYYY-MM"),
    year: int | None = Query(default=None, ge=2000, le=2100),
    principal: dict[str, Any] = Depends(require_permission("official_docs:read")),
) -> Response:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    document_rows = _load_filtered_official_document_rows(
        site=site,
        organization=organization,
        status=status,
        month=month,
        year=year,
        allowed_sites=allowed_sites,
    )
    attachment_rows = _load_attachment_rows_for_documents([int(row["id"]) for row in document_rows])
    bundle = _build_official_document_attachments_zip(
        document_rows=document_rows,
        attachment_rows=attachment_rows,
    )
    normalized_month, normalized_year = _normalize_period_filters(month, year)
    period_label = normalized_month or (str(normalized_year) if normalized_year is not None else "all")
    site_label = _download_safe_segment(site or "all", default="all")
    organization_label = _download_safe_segment(organization or "all", default="all")
    file_name = f"official-document-attachments-{site_label}-{organization_label}-{period_label}.zip"
    _write_audit_log(
        principal=principal,
        action="official_document_attachment_export_zip",
        resource_type="official_document_attachment",
        resource_id=f"{site or 'ALL'}:{organization or 'ALL'}:{period_label}",
        detail={
            "site": site,
            "organization": organization,
            "status": status,
            "month": normalized_month,
            "year": normalized_year,
            "document_count": bundle["document_count"],
            "attachment_count": bundle["attachment_count"],
            "missing_blob_count": bundle["missing_blob_count"],
        },
    )
    return Response(
        content=bundle["file_bytes"],
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{file_name}"',
            "X-Document-Count": str(bundle["document_count"]),
            "X-Attachment-Count": str(bundle["attachment_count"]),
        },
    )


@router.get("/api/official-documents/registry/csv")
def export_official_document_registry_csv(
    site: str | None = None,
    organization: str | None = None,
    status: str | None = None,
    month: str | None = Query(default=None, description="YYYY-MM"),
    year: int | None = Query(default=None, ge=2000, le=2100),
    principal: dict[str, Any] = Depends(require_permission("reports:export")),
) -> Response:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    rows = _load_filtered_official_document_rows(
        site=site,
        organization=organization,
        status=status,
        month=month,
        year=year,
        allowed_sites=allowed_sites,
    )
    csv_text = _build_official_document_registry_csv(rows)
    normalized_month, normalized_year = _normalize_period_filters(month, year)
    period_label = normalized_month or (str(normalized_year) if normalized_year is not None else "all")
    site_label = _download_safe_segment(site or "all", default="all")
    organization_label = _download_safe_segment(organization or "all", default="all")
    file_name = f"official-document-registry-{site_label}-{organization_label}-{period_label}.csv"
    _write_audit_log(
        principal=principal,
        action="official_document_registry_export_csv",
        resource_type="report",
        resource_id=f"{site or 'ALL'}:{organization or 'ALL'}:{period_label}",
        detail={
            "site": site,
            "organization": organization,
            "status": status,
            "month": normalized_month,
            "year": normalized_year,
            "row_count": len(rows),
        },
    )
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.post("/api/official-documents/overdue/run", response_model=OfficialDocumentOverdueSyncRead)
def run_official_document_overdue_sync(
    site: str | None = Query(default=None),
    dry_run: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=300),
    principal: dict[str, Any] = Depends(require_permission("official_docs:write")),
) -> OfficialDocumentOverdueSyncRead:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    result = _run_official_document_overdue_sync(
        principal=principal,
        site=site,
        allowed_sites=allowed_sites,
        dry_run=dry_run,
        limit=limit,
    )
    _write_audit_log(
        principal=principal,
        action="official_document_overdue_sync",
        resource_type="official_document",
        resource_id=site or "ALL",
        detail={
            "site": site,
            "dry_run": dry_run,
            "candidate_count": result.candidate_count,
            "work_order_created_count": result.work_order_created_count,
        },
    )
    return result


@router.get("/api/reports/official-documents/monthly", response_model=OfficialDocumentClosureReportRead)
def get_official_document_monthly_report(
    month: str | None = Query(default=None, description="YYYY-MM"),
    site: str | None = None,
    principal: dict[str, Any] = Depends(require_permission("reports:read")),
) -> OfficialDocumentClosureReportRead:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    _run_official_document_overdue_sync(
        principal=principal,
        site=site,
        allowed_sites=allowed_sites,
        dry_run=False,
        limit=50,
    )
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
    _run_official_document_overdue_sync(
        principal=principal,
        site=site,
        allowed_sites=allowed_sites,
        dry_run=False,
        limit=50,
    )
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


@router.get("/api/reports/monthly/integrated", response_model=IntegratedMonthlyFacilityReportRead)
def get_integrated_monthly_report(
    month: str | None = Query(default=None, description="YYYY-MM"),
    site: str | None = None,
    principal: dict[str, Any] = Depends(require_permission("reports:read")),
) -> IntegratedMonthlyFacilityReportRead:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    _run_official_document_overdue_sync(
        principal=principal,
        site=site,
        allowed_sites=allowed_sites,
        dry_run=False,
        limit=50,
    )
    return _build_integrated_report(
        period_type="monthly",
        month=month,
        site=site,
        allowed_sites=allowed_sites,
    )


@router.get("/api/reports/monthly/integrated/csv")
def get_integrated_monthly_report_csv(
    month: str | None = Query(default=None, description="YYYY-MM"),
    site: str | None = None,
    principal: dict[str, Any] = Depends(require_permission("reports:export")),
) -> Response:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = _build_integrated_report(
        period_type="monthly",
        month=month,
        site=site,
        allowed_sites=allowed_sites,
    )
    csv_text = _build_integrated_report_csv(report)
    site_label = (report.site or "all").replace(" ", "_")
    file_name = f"integrated-monthly-report-{report.period_label}-{site_label}.csv"
    _write_audit_log(
        principal=principal,
        action="integrated_monthly_report_export_csv",
        resource_type="report",
        resource_id=f"integrated:monthly:{report.period_label}:{report.site or 'ALL'}",
        detail={"month": report.month, "site": report.site},
    )
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename=\"{file_name}\"'},
    )


@router.get("/api/reports/monthly/integrated/pdf")
def get_integrated_monthly_report_pdf(
    month: str | None = Query(default=None, description="YYYY-MM"),
    site: str | None = None,
    principal: dict[str, Any] = Depends(require_permission("reports:export")),
) -> Response:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = _build_integrated_report(
        period_type="monthly",
        month=month,
        site=site,
        allowed_sites=allowed_sites,
    )
    pdf_bytes = _build_integrated_report_pdf(report)
    site_label = (report.site or "all").replace(" ", "_")
    file_name = f"integrated-monthly-report-{report.period_label}-{site_label}.pdf"
    _write_audit_log(
        principal=principal,
        action="integrated_monthly_report_export_pdf",
        resource_type="report",
        resource_id=f"integrated:monthly:{report.period_label}:{report.site or 'ALL'}",
        detail={"month": report.month, "site": report.site},
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.get("/reports/monthly/integrated/print", response_class=HTMLResponse)
def print_integrated_monthly_report(
    month: str | None = Query(default=None, description="YYYY-MM"),
    site: str | None = None,
    principal: dict[str, Any] = Depends(require_permission("reports:read")),
) -> str:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = _build_integrated_report(
        period_type="monthly",
        month=month,
        site=site,
        allowed_sites=allowed_sites,
    )
    return _build_integrated_report_print_html(report)


@router.get("/api/reports/annual/integrated", response_model=IntegratedMonthlyFacilityReportRead)
def get_integrated_annual_report(
    year: int | None = Query(default=None, ge=2000, le=2100),
    site: str | None = None,
    principal: dict[str, Any] = Depends(require_permission("reports:read")),
) -> IntegratedMonthlyFacilityReportRead:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    _run_official_document_overdue_sync(
        principal=principal,
        site=site,
        allowed_sites=allowed_sites,
        dry_run=False,
        limit=50,
    )
    return _build_integrated_report(
        period_type="annual",
        year=year,
        site=site,
        allowed_sites=allowed_sites,
    )


@router.get("/api/reports/annual/integrated/csv")
def get_integrated_annual_report_csv(
    year: int | None = Query(default=None, ge=2000, le=2100),
    site: str | None = None,
    principal: dict[str, Any] = Depends(require_permission("reports:export")),
) -> Response:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = _build_integrated_report(
        period_type="annual",
        year=year,
        site=site,
        allowed_sites=allowed_sites,
    )
    csv_text = _build_integrated_report_csv(report)
    site_label = (report.site or "all").replace(" ", "_")
    file_name = f"integrated-annual-report-{report.period_label}-{site_label}.csv"
    _write_audit_log(
        principal=principal,
        action="integrated_annual_report_export_csv",
        resource_type="report",
        resource_id=f"integrated:annual:{report.period_label}:{report.site or 'ALL'}",
        detail={"year": report.year, "site": report.site},
    )
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.get("/api/reports/annual/integrated/pdf")
def get_integrated_annual_report_pdf(
    year: int | None = Query(default=None, ge=2000, le=2100),
    site: str | None = None,
    principal: dict[str, Any] = Depends(require_permission("reports:export")),
) -> Response:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = _build_integrated_report(
        period_type="annual",
        year=year,
        site=site,
        allowed_sites=allowed_sites,
    )
    pdf_bytes = _build_integrated_report_pdf(report)
    site_label = (report.site or "all").replace(" ", "_")
    file_name = f"integrated-annual-report-{report.period_label}-{site_label}.pdf"
    _write_audit_log(
        principal=principal,
        action="integrated_annual_report_export_pdf",
        resource_type="report",
        resource_id=f"integrated:annual:{report.period_label}:{report.site or 'ALL'}",
        detail={"year": report.year, "site": report.site},
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.get("/reports/annual/integrated/print", response_class=HTMLResponse)
def print_integrated_annual_report(
    year: int | None = Query(default=None, ge=2000, le=2100),
    site: str | None = None,
    principal: dict[str, Any] = Depends(require_permission("reports:read")),
) -> str:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = _build_integrated_report(
        period_type="annual",
        year=year,
        site=site,
        allowed_sites=allowed_sites,
    )
    return _build_integrated_report_print_html(report)

