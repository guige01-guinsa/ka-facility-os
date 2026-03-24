"""Complaint routes."""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile
from fastapi.responses import HTMLResponse

from app.domains.complaints import reporting, service
from app.domains.complaints.schemas import (
    ComplaintAdminBulkDeleteRequest,
    ComplaintAdminBulkMutationResultRead,
    ComplaintAdminBulkUpdateRequest,
    ComplaintAdminRecordListRead,
    ComplaintAttachmentRead,
    ComplaintAttachmentUpdate,
    ComplaintCaseCreate,
    ComplaintCaseRead,
    ComplaintCaseUpdate,
    ComplaintCostItemCreate,
    ComplaintCostItemRead,
    ComplaintCostItemUpdate,
    ComplaintDetailRead,
    ComplaintEventCreate,
    ComplaintEventRead,
    ComplaintEventUpdate,
    ComplaintHouseholdHistoryRead,
    ComplaintMessageRead,
    ComplaintMessageSend,
    ComplaintMessageUpdate,
    ComplaintPdfExportRequest,
    ComplaintReportCoverDefaultRead,
    ComplaintReportCoverDefaultUpdate,
)
from app.domains.iam.core import _principal_site_scope
from app.domains.iam.security import _require_global_site_scope, _require_site_access, require_permission
from app.domains.iam.service import _write_audit_log
from app.web.complaints import build_complaints_mobile_html, complaints_script_text, complaints_script_version


router = APIRouter(tags=["complaints"])


def _allowed_sites_for_principal(principal: dict[str, Any]) -> list[str] | None:
    scope = _principal_site_scope(principal)
    if "*" in scope:
        return None
    return scope


def _safe_download_filename(value: str) -> str:
    normalized = re.sub(r"[^0-9A-Za-z._-]+", "_", str(value or "").strip())
    normalized = normalized.strip("._-")
    return normalized or "complaint-attachment.bin"


def _secure_html_response(content: str) -> HTMLResponse:
    return HTMLResponse(
        content,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "X-Robots-Tag": "noindex, nofollow",
        },
    )


@router.get("/web/complaints", response_model=None)
def complaints_mobile_page() -> HTMLResponse:
    return _secure_html_response(build_complaints_mobile_html())


@router.get("/web/complaints/app.js", response_model=None)
def complaints_mobile_script() -> Response:
    return Response(
        content=complaints_script_text(),
        media_type="application/javascript",
        headers={
            "Cache-Control": "public, max-age=31536000, immutable",
            "ETag": complaints_script_version(),
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/api/complaints/households/history", response_model=ComplaintHouseholdHistoryRead)
def get_household_history(
    site: str,
    building: str,
    unit_number: str,
    principal: dict[str, Any] = Depends(require_permission("complaints:read")),
) -> ComplaintHouseholdHistoryRead:
    _require_site_access(principal, site)
    return service.get_household_history(
        site=site,
        building=building,
        unit_number=unit_number,
        allowed_sites=_allowed_sites_for_principal(principal),
    )


@router.get("/api/complaints", response_model=list[ComplaintCaseRead])
def list_complaints(
    site: Annotated[str | None, Query()] = None,
    building: Annotated[str | None, Query()] = None,
    unit_number: Annotated[str | None, Query()] = None,
    status: Annotated[str | None, Query()] = None,
    complaint_type: Annotated[str | None, Query()] = None,
    assignee: Annotated[str | None, Query()] = None,
    recurrence_flag: Annotated[bool | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("complaints:read")),
) -> list[ComplaintCaseRead]:
    _require_site_access(principal, site)
    return service.list_cases(
        site=site,
        building=building,
        unit_number=unit_number,
        status=status,
        complaint_type=complaint_type,
        assignee=assignee,
        recurrence_flag=recurrence_flag,
        allowed_sites=_allowed_sites_for_principal(principal) if site is None else None,
    )


@router.get("/api/complaints/admin/records", response_model=ComplaintAdminRecordListRead)
def list_complaint_admin_records(
    site: str,
    record_type: Annotated[str, Query()],
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    q: Annotated[str | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("complaints:read")),
) -> ComplaintAdminRecordListRead:
    _require_site_access(principal, site)
    return service.list_admin_records(
        site=site,
        record_type=record_type,
        limit=limit,
        q=q,
        allowed_sites=_allowed_sites_for_principal(principal),
    )


@router.post("/api/complaints/admin/records/bulk-update", response_model=ComplaintAdminBulkMutationResultRead)
def bulk_update_complaint_admin_records(
    payload: ComplaintAdminBulkUpdateRequest,
    principal: dict[str, Any] = Depends(require_permission("complaints:write")),
) -> ComplaintAdminBulkMutationResultRead:
    _require_site_access(principal, payload.site)
    return service.bulk_update_admin_records(
        payload=payload,
        principal=principal,
        allowed_sites=_allowed_sites_for_principal(principal),
    )


@router.post("/api/complaints/admin/records/bulk-delete", response_model=ComplaintAdminBulkMutationResultRead)
def bulk_delete_complaint_admin_records(
    payload: ComplaintAdminBulkDeleteRequest,
    principal: dict[str, Any] = Depends(require_permission("complaints:write")),
) -> ComplaintAdminBulkMutationResultRead:
    _require_site_access(principal, payload.site)
    return service.bulk_delete_admin_records(
        payload=payload,
        principal=principal,
        allowed_sites=_allowed_sites_for_principal(principal),
    )


@router.get("/api/complaints/reports/xlsx", response_model=None)
def export_complaints_xlsx(
    site: Annotated[str | None, Query()] = None,
    report_type: Annotated[str | None, Query()] = None,
    building: Annotated[str | None, Query()] = None,
    sort_by: Annotated[str | None, Query()] = None,
    group_by: Annotated[str | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("complaints:read")),
) -> Response:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = reporting.build_complaint_export_report(
        site=site,
        report_type=report_type,
        building=building,
        sort_by=sort_by,
        group_by=group_by,
        allowed_sites=allowed_sites,
    )
    file_name = _safe_download_filename(f"{report.file_stem}.xlsx")
    _write_audit_log(
        principal=principal,
        action="complaints.report.export.xlsx",
        resource_type="complaint_report",
        resource_id=f"{report.report_type}:{report.site or 'ALL'}:{report.building or 'ALL'}",
        detail={"site": report.site, "building": report.building, "report_type": report.report_type, "sort_by": report.sort_by, "group_by": report.group_by},
    )
    return Response(
        content=reporting.build_complaint_export_xlsx(report),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.get("/api/complaints/reports/pdf", response_model=None)
def export_complaints_pdf(
    site: Annotated[str | None, Query()] = None,
    report_type: Annotated[str | None, Query()] = None,
    building: Annotated[str | None, Query()] = None,
    sort_by: Annotated[str | None, Query()] = None,
    group_by: Annotated[str | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("complaints:read")),
) -> Response:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = reporting.build_complaint_export_report(
        site=site,
        report_type=report_type,
        building=building,
        sort_by=sort_by,
        group_by=group_by,
        allowed_sites=allowed_sites,
        cover_options=service.resolve_effective_report_cover_options(site=site, allowed_sites=allowed_sites),
    )
    file_name = _safe_download_filename(f"{report.file_stem}.pdf")
    _write_audit_log(
        principal=principal,
        action="complaints.report.export.pdf",
        resource_type="complaint_report",
        resource_id=f"{report.report_type}:{report.site or 'ALL'}:{report.building or 'ALL'}",
        detail={"site": report.site, "building": report.building, "report_type": report.report_type, "sort_by": report.sort_by, "group_by": report.group_by},
    )
    return Response(
        content=reporting.build_complaint_export_pdf(report),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.post("/api/complaints/reports/pdf", response_model=None)
def export_complaints_pdf_with_cover(
    payload: ComplaintPdfExportRequest,
    principal: dict[str, Any] = Depends(require_permission("complaints:read")),
) -> Response:
    _require_site_access(principal, payload.site)
    allowed_sites = _allowed_sites_for_principal(principal) if payload.site is None else None
    effective_cover = service.resolve_effective_report_cover_options(site=payload.site, override=payload.cover, allowed_sites=allowed_sites)
    report = reporting.build_complaint_export_report(
        site=payload.site,
        report_type=payload.report_type,
        building=payload.building,
        sort_by=payload.sort_by,
        group_by=payload.group_by,
        allowed_sites=allowed_sites,
        cover_options=effective_cover,
    )
    file_name = _safe_download_filename(f"{report.file_stem}.pdf")
    _write_audit_log(
        principal=principal,
        action="complaints.report.export.pdf",
        resource_type="complaint_report",
        resource_id=f"{report.report_type}:{report.site or 'ALL'}:{report.building or 'ALL'}",
        detail={
            "site": report.site,
            "building": report.building,
            "report_type": report.report_type,
            "sort_by": report.sort_by,
            "group_by": report.group_by,
            "custom_cover": bool(report.cover_settings),
        },
    )
    return Response(
        content=reporting.build_complaint_export_pdf(report),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.get("/api/complaints/report-cover/default", response_model=ComplaintReportCoverDefaultRead)
def get_complaint_report_cover_default(
    site: Annotated[str | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("complaints:read")),
) -> ComplaintReportCoverDefaultRead:
    _require_site_access(principal, site)
    return service.get_effective_report_cover_default(
        site=site,
        allowed_sites=_allowed_sites_for_principal(principal) if site is not None else None,
    )


@router.put("/api/complaints/report-cover/default", response_model=ComplaintReportCoverDefaultRead)
def update_complaint_report_cover_default(
    payload: ComplaintReportCoverDefaultUpdate,
    principal: dict[str, Any] = Depends(require_permission("complaints:write")),
) -> ComplaintReportCoverDefaultRead:
    if payload.scope_type == "global":
        _require_global_site_scope(principal)
        return service.save_report_cover_default(payload=payload, principal=principal)
    _require_site_access(principal, payload.site)
    return service.save_report_cover_default(
        payload=payload,
        principal=principal,
        allowed_sites=_allowed_sites_for_principal(principal),
    )


@router.delete("/api/complaints/report-cover/default", response_model=None)
def delete_complaint_report_cover_default(
    scope_type: Annotated[str, Query()],
    site: Annotated[str | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("complaints:write")),
) -> Response:
    normalized_scope = str(scope_type or "").strip().lower()
    if not normalized_scope:
        raise HTTPException(status_code=422, detail="scope_type is required")
    if normalized_scope == "global":
        _require_global_site_scope(principal)
        service.delete_report_cover_default(scope_type=normalized_scope, site=None)
    else:
        _require_site_access(principal, site)
        service.delete_report_cover_default(
            scope_type=normalized_scope,
            site=site,
            allowed_sites=_allowed_sites_for_principal(principal),
        )
    return Response(status_code=204)


@router.post("/api/complaints", response_model=ComplaintCaseRead, status_code=201)
def create_complaint(
    payload: ComplaintCaseCreate,
    principal: dict[str, Any] = Depends(require_permission("complaints:write")),
) -> ComplaintCaseRead:
    _require_site_access(principal, payload.site)
    return service.create_case(payload=payload, principal=principal)


@router.get("/api/complaints/{complaint_id}", response_model=ComplaintDetailRead)
def get_complaint_detail(
    complaint_id: int,
    principal: dict[str, Any] = Depends(require_permission("complaints:read")),
) -> ComplaintDetailRead:
    detail = service.get_case_detail(complaint_id=complaint_id)
    _require_site_access(principal, detail.case.site)
    return detail


@router.patch("/api/complaints/{complaint_id}", response_model=ComplaintCaseRead)
def update_complaint(
    complaint_id: int,
    payload: ComplaintCaseUpdate,
    principal: dict[str, Any] = Depends(require_permission("complaints:write")),
) -> ComplaintCaseRead:
    existing = service.get_case_detail(complaint_id=complaint_id)
    _require_site_access(principal, existing.case.site)
    return service.update_case(complaint_id=complaint_id, payload=payload, principal=principal)


@router.delete("/api/complaints/{complaint_id}")
def delete_complaint(
    complaint_id: int,
    principal: dict[str, Any] = Depends(require_permission("complaints:write")),
) -> dict[str, Any]:
    existing = service.get_case_detail(complaint_id=complaint_id)
    _require_site_access(principal, existing.case.site)
    return service.delete_case(complaint_id=complaint_id, principal=principal)


@router.get("/api/complaints/{complaint_id}/events", response_model=list[ComplaintEventRead])
def list_complaint_events(
    complaint_id: int,
    principal: dict[str, Any] = Depends(require_permission("complaints:read")),
) -> list[ComplaintEventRead]:
    detail = service.get_case_detail(complaint_id=complaint_id)
    _require_site_access(principal, detail.case.site)
    return detail.events


@router.post("/api/complaints/{complaint_id}/events", response_model=ComplaintEventRead, status_code=201)
def add_complaint_event(
    complaint_id: int,
    payload: ComplaintEventCreate,
    principal: dict[str, Any] = Depends(require_permission("complaints:write")),
) -> ComplaintEventRead:
    detail = service.get_case_detail(complaint_id=complaint_id)
    _require_site_access(principal, detail.case.site)
    return service.add_event(complaint_id=complaint_id, payload=payload, principal=principal)


@router.patch("/api/complaints/events/{event_id}", response_model=ComplaintEventRead)
def update_complaint_event(
    event_id: int,
    payload: ComplaintEventUpdate,
    principal: dict[str, Any] = Depends(require_permission("complaints:write")),
) -> ComplaintEventRead:
    event = service.get_event(event_id=event_id)
    detail = service.get_case_detail(complaint_id=event.complaint_id)
    _require_site_access(principal, detail.case.site)
    return service.update_event(event_id=event_id, payload=payload, principal=principal)


@router.delete("/api/complaints/events/{event_id}")
def delete_complaint_event(
    event_id: int,
    principal: dict[str, Any] = Depends(require_permission("complaints:write")),
) -> dict[str, Any]:
    event = service.get_event(event_id=event_id)
    detail = service.get_case_detail(complaint_id=event.complaint_id)
    _require_site_access(principal, detail.case.site)
    return service.delete_event(event_id=event_id, principal=principal)


@router.get("/api/complaints/{complaint_id}/attachments", response_model=list[ComplaintAttachmentRead])
def list_complaint_attachments(
    complaint_id: int,
    principal: dict[str, Any] = Depends(require_permission("complaints:read")),
) -> list[ComplaintAttachmentRead]:
    detail = service.get_case_detail(complaint_id=complaint_id)
    _require_site_access(principal, detail.case.site)
    return detail.attachments


@router.post("/api/complaints/{complaint_id}/attachments", response_model=ComplaintAttachmentRead, status_code=201)
async def upload_complaint_attachment(
    complaint_id: int,
    attachment_kind: str = Form(default="intake"),
    note: str = Form(default=""),
    file: UploadFile = File(...),
    principal: dict[str, Any] = Depends(require_permission("complaints:write")),
) -> ComplaintAttachmentRead:
    detail = service.get_case_detail(complaint_id=complaint_id)
    _require_site_access(principal, detail.case.site)
    file_bytes = await file.read()
    return service.add_attachment(
        complaint_id=complaint_id,
        attachment_kind=attachment_kind,
        note=note,
        file_name=file.filename or "upload.bin",
        content_type=file.content_type or "application/octet-stream",
        file_bytes=file_bytes,
        principal=principal,
    )


@router.patch("/api/complaints/attachments/{attachment_id}", response_model=ComplaintAttachmentRead)
def update_complaint_attachment(
    attachment_id: int,
    payload: ComplaintAttachmentUpdate,
    principal: dict[str, Any] = Depends(require_permission("complaints:write")),
) -> ComplaintAttachmentRead:
    attachment = service.get_attachment(attachment_id=attachment_id)
    _require_site_access(principal, attachment.site)
    return service.update_attachment(attachment_id=attachment_id, payload=payload, principal=principal)


@router.delete("/api/complaints/attachments/{attachment_id}")
def delete_complaint_attachment(
    attachment_id: int,
    principal: dict[str, Any] = Depends(require_permission("complaints:write")),
) -> dict[str, Any]:
    attachment = service.get_attachment(attachment_id=attachment_id)
    _require_site_access(principal, attachment.site)
    return service.delete_attachment(attachment_id=attachment_id, principal=principal)


@router.get("/api/complaints/attachments/{attachment_id}/download", response_model=None)
def download_complaint_attachment(
    attachment_id: int,
    principal: dict[str, Any] = Depends(require_permission("complaints:read")),
) -> Response:
    payload = service.get_attachment_download_payload(attachment_id=attachment_id)
    row = payload["row"]
    _require_site_access(principal, row["site"])
    return Response(
        content=payload["file_bytes"],
        media_type=str(row.get("content_type") or "application/octet-stream"),
        headers={
            "Content-Disposition": f'attachment; filename="{_safe_download_filename(str(row["file_name"]))}"',
            "X-Complaint-Sha256": str(row.get("sha256") or ""),
        },
    )


@router.get("/api/complaints/{complaint_id}/messages", response_model=list[ComplaintMessageRead])
def list_complaint_messages(
    complaint_id: int,
    principal: dict[str, Any] = Depends(require_permission("complaints:read")),
) -> list[ComplaintMessageRead]:
    detail = service.get_case_detail(complaint_id=complaint_id)
    _require_site_access(principal, detail.case.site)
    return detail.messages


@router.post("/api/complaints/{complaint_id}/messages", response_model=ComplaintMessageRead, status_code=201)
def send_complaint_message(
    complaint_id: int,
    payload: ComplaintMessageSend,
    principal: dict[str, Any] = Depends(require_permission("complaints:message")),
) -> ComplaintMessageRead:
    detail = service.get_case_detail(complaint_id=complaint_id)
    _require_site_access(principal, detail.case.site)
    return service.send_case_message(complaint_id=complaint_id, payload=payload, principal=principal)


@router.patch("/api/complaints/messages/{message_id}", response_model=ComplaintMessageRead)
def update_complaint_message(
    message_id: int,
    payload: ComplaintMessageUpdate,
    principal: dict[str, Any] = Depends(require_permission("complaints:message")),
) -> ComplaintMessageRead:
    message = service.get_message(message_id=message_id)
    _require_site_access(principal, message.site)
    return service.update_message(message_id=message_id, payload=payload, principal=principal)


@router.delete("/api/complaints/messages/{message_id}")
def delete_complaint_message(
    message_id: int,
    principal: dict[str, Any] = Depends(require_permission("complaints:message")),
) -> dict[str, Any]:
    message = service.get_message(message_id=message_id)
    _require_site_access(principal, message.site)
    return service.delete_message(message_id=message_id, principal=principal)


@router.get("/api/complaints/{complaint_id}/cost-items", response_model=list[ComplaintCostItemRead])
def list_complaint_cost_items(
    complaint_id: int,
    principal: dict[str, Any] = Depends(require_permission("complaints:read")),
) -> list[ComplaintCostItemRead]:
    detail = service.get_case_detail(complaint_id=complaint_id)
    _require_site_access(principal, detail.case.site)
    return detail.cost_items


@router.post("/api/complaints/{complaint_id}/cost-items", response_model=ComplaintCostItemRead, status_code=201)
def add_complaint_cost_item(
    complaint_id: int,
    payload: ComplaintCostItemCreate,
    principal: dict[str, Any] = Depends(require_permission("complaints:costs")),
) -> ComplaintCostItemRead:
    detail = service.get_case_detail(complaint_id=complaint_id)
    _require_site_access(principal, detail.case.site)
    return service.add_cost_item(complaint_id=complaint_id, payload=payload, principal=principal)


@router.patch("/api/complaints/cost-items/{cost_item_id}", response_model=ComplaintCostItemRead)
def update_complaint_cost_item(
    cost_item_id: int,
    payload: ComplaintCostItemUpdate,
    principal: dict[str, Any] = Depends(require_permission("complaints:costs")),
) -> ComplaintCostItemRead:
    cost_item = service.get_cost_item(cost_item_id=cost_item_id)
    detail = service.get_case_detail(complaint_id=cost_item.complaint_id)
    _require_site_access(principal, detail.case.site)
    return service.update_cost_item(cost_item_id=cost_item_id, payload=payload, principal=principal)


@router.delete("/api/complaints/cost-items/{cost_item_id}")
def delete_complaint_cost_item(
    cost_item_id: int,
    principal: dict[str, Any] = Depends(require_permission("complaints:costs")),
) -> dict[str, Any]:
    cost_item = service.get_cost_item(cost_item_id=cost_item_id)
    detail = service.get_case_detail(complaint_id=cost_item.complaint_id)
    _require_site_access(principal, detail.case.site)
    return service.delete_cost_item(cost_item_id=cost_item_id, principal=principal)
