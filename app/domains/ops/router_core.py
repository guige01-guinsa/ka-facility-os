"""OPS core routes extracted from app.main."""

from __future__ import annotations

from app import main as main_module
from app.domains.ops.schemas import (
    InspectionCreate,
    InspectionEvidenceRead,
    InspectionRead,
    WorkOrderAck,
    WorkOrderCancel,
    WorkOrderCommentCreate,
    WorkOrderComplete,
    WorkOrderCreate,
    WorkOrderEventRead,
    WorkOrderRead,
    WorkOrderReopen,
    WorkflowLockCreate,
    WorkflowLockDraftUpdate,
    WorkflowLockRead,
    WorkflowLockTransitionRequest,
)

APIRouter = main_module.APIRouter
router = APIRouter(tags=["ops-core"])
app = router

Annotated = main_module.Annotated
Any = main_module.Any
Depends = main_module.Depends
EVIDENCE_SCAN_BLOCK_SUSPICIOUS = main_module.EVIDENCE_SCAN_BLOCK_SUSPICIOUS
File = main_module.File
Form = main_module.Form
HTMLResponse = main_module.HTMLResponse
HTTPException = main_module.HTTPException
INSPECTION_EVIDENCE_MAX_BYTES = main_module.INSPECTION_EVIDENCE_MAX_BYTES
MonthlyReportRead = main_module.MonthlyReportRead
Query = main_module.Query
Response = main_module.Response
SLA_DEFAULT_DUE_HOURS = main_module.SLA_DEFAULT_DUE_HOURS
SlaEscalationRunRequest = main_module.SlaEscalationRunRequest
SlaEscalationRunResponse = main_module.SlaEscalationRunResponse
UploadFile = main_module.UploadFile
WORKFLOW_LOCK_STATUS_APPROVED = main_module.WORKFLOW_LOCK_STATUS_APPROVED
WORKFLOW_LOCK_STATUS_DRAFT = main_module.WORKFLOW_LOCK_STATUS_DRAFT
WORKFLOW_LOCK_STATUS_LOCKED = main_module.WORKFLOW_LOCK_STATUS_LOCKED
WORKFLOW_LOCK_STATUS_REVIEW = main_module.WORKFLOW_LOCK_STATUS_REVIEW
WORKFLOW_LOCK_STATUS_SET = main_module.WORKFLOW_LOCK_STATUS_SET
_allowed_sites_for_principal = main_module._allowed_sites_for_principal
_append_work_order_event = main_module._append_work_order_event
_as_optional_datetime = main_module._as_optional_datetime
_build_monthly_report_csv = main_module._build_monthly_report_csv
_build_monthly_report_pdf = main_module._build_monthly_report_pdf
_calculate_risk = main_module._calculate_risk
_derive_inspection_work_order_sla_context = main_module._derive_inspection_work_order_sla_context
_extract_ops_snapshot_values = main_module._extract_ops_snapshot_values
_higher_priority = main_module._higher_priority
_inspection_to_work_order_sla_rule_payload = main_module._inspection_to_work_order_sla_rule_payload
_is_allowed_evidence_content_type = main_module._is_allowed_evidence_content_type
_load_sla_policy = main_module._load_sla_policy
_normalize_evidence_storage_backend = main_module._normalize_evidence_storage_backend
_ops_snapshot_values_from_inspection_row = main_module._ops_snapshot_values_from_inspection_row
_read_evidence_blob = main_module._read_evidence_blob
_resolve_ops_master_asset_ids = main_module._resolve_ops_master_asset_ids
_require_site_access = main_module._require_site_access
_require_workflow_lock_action = main_module._require_workflow_lock_action
_row_to_inspection_evidence_model = main_module._row_to_inspection_evidence_model
_row_to_read_model = main_module._row_to_read_model
_row_to_work_order_event_model = main_module._row_to_work_order_event_model
_row_to_work_order_model = main_module._row_to_work_order_model
_row_to_workflow_lock_model = main_module._row_to_workflow_lock_model
_safe_download_filename = main_module._safe_download_filename
_scan_evidence_bytes = main_module._scan_evidence_bytes
_to_json_text = main_module._to_json_text
_to_utc = main_module._to_utc
_validate_ops_inspection_payload = main_module._validate_ops_inspection_payload
_validate_work_order_transition = main_module._validate_work_order_transition
_write_audit_log = main_module._write_audit_log
_write_evidence_blob = main_module._write_evidence_blob
build_monthly_report = main_module.build_monthly_report
datetime = main_module.datetime
get_conn = main_module.get_conn
get_current_admin = main_module.get_current_admin
hashlib = main_module.hashlib
insert = main_module.insert
inspection_evidence_files = main_module.inspection_evidence_files
inspections = main_module.inspections
require_permission = main_module.require_permission
run_sla_escalation_job = main_module.run_sla_escalation_job
select = main_module.select
timedelta = main_module.timedelta
timezone = main_module.timezone
update = main_module.update
work_order_events = main_module.work_order_events
work_orders = main_module.work_orders
workflow_locks = main_module.workflow_locks
@app.get("/api/workflow-locks", response_model=list[WorkflowLockRead])
def list_workflow_locks(
    site: Annotated[str | None, Query()] = None,
    status: Annotated[str | None, Query()] = None,
    workflow_key: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    principal: dict[str, Any] = Depends(get_current_admin),
) -> list[WorkflowLockRead]:
    _require_workflow_lock_action(principal, action="read")
    _require_site_access(principal, site)
    normalized_status = status.strip().lower() if status is not None else None
    if normalized_status is not None and normalized_status not in WORKFLOW_LOCK_STATUS_SET:
        raise HTTPException(status_code=400, detail="Invalid workflow lock status")

    stmt = select(workflow_locks)
    if site is not None:
        stmt = stmt.where(workflow_locks.c.site == site)
    else:
        allowed_sites = _allowed_sites_for_principal(principal)
        if allowed_sites is not None:
            if not allowed_sites:
                return []
            stmt = stmt.where(workflow_locks.c.site.in_(allowed_sites))
    if normalized_status is not None:
        stmt = stmt.where(workflow_locks.c.status == normalized_status)
    if workflow_key is not None:
        stmt = stmt.where(workflow_locks.c.workflow_key == workflow_key)
    stmt = stmt.order_by(workflow_locks.c.created_at.desc(), workflow_locks.c.id.desc()).limit(limit).offset(offset)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_workflow_lock_model(row) for row in rows]

@app.post("/api/workflow-locks", response_model=WorkflowLockRead, status_code=201)
def create_workflow_lock(
    payload: WorkflowLockCreate,
    principal: dict[str, Any] = Depends(get_current_admin),
) -> WorkflowLockRead:
    _require_site_access(principal, payload.site)
    _require_workflow_lock_action(principal, action="create", status=WORKFLOW_LOCK_STATUS_DRAFT)
    actor_username = str(principal.get("username") or "unknown")
    now = datetime.now(timezone.utc)

    with get_conn() as conn:
        result = conn.execute(
            insert(workflow_locks).values(
                site=payload.site,
                workflow_key=payload.workflow_key,
                status=WORKFLOW_LOCK_STATUS_DRAFT,
                content_json=_to_json_text(payload.content),
                requested_ticket=payload.requested_ticket,
                last_comment="",
                lock_reason=None,
                unlock_reason=None,
                created_by=actor_username,
                updated_by=actor_username,
                reviewed_by=None,
                approved_by=None,
                locked_by=None,
                unlocked_by=None,
                created_at=now,
                updated_at=now,
                reviewed_at=None,
                approved_at=None,
                locked_at=None,
                unlocked_at=None,
            )
        )
        workflow_lock_id = int(result.inserted_primary_key[0])
        row = conn.execute(
            select(workflow_locks).where(workflow_locks.c.id == workflow_lock_id).limit(1)
        ).mappings().first()

    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create workflow lock")
    model = _row_to_workflow_lock_model(row)
    _write_audit_log(
        principal=principal,
        action="workflow_lock_create",
        resource_type="workflow_lock",
        resource_id=str(model.id),
        detail={
            "site": model.site,
            "workflow_key": model.workflow_key,
            "status": model.status,
            "requested_ticket": model.requested_ticket,
        },
    )
    return model

@app.get("/api/workflow-locks/{workflow_lock_id}", response_model=WorkflowLockRead)
def get_workflow_lock(
    workflow_lock_id: int,
    principal: dict[str, Any] = Depends(get_current_admin),
) -> WorkflowLockRead:
    _require_workflow_lock_action(principal, action="read")
    with get_conn() as conn:
        row = conn.execute(
            select(workflow_locks).where(workflow_locks.c.id == workflow_lock_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Workflow lock not found")
    _require_site_access(principal, str(row["site"]))
    return _row_to_workflow_lock_model(row)

@app.patch("/api/workflow-locks/{workflow_lock_id}/draft", response_model=WorkflowLockRead)
def update_workflow_lock_draft(
    workflow_lock_id: int,
    payload: WorkflowLockDraftUpdate,
    principal: dict[str, Any] = Depends(get_current_admin),
) -> WorkflowLockRead:
    actor_username = str(principal.get("username") or "unknown")
    now = datetime.now(timezone.utc)

    with get_conn() as conn:
        row = conn.execute(
            select(workflow_locks).where(workflow_locks.c.id == workflow_lock_id).limit(1)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Workflow lock not found")
        _require_site_access(principal, str(row["site"]))
        _require_workflow_lock_action(principal, action="update_draft", status=str(row["status"]))

        next_content_json = row["content_json"]
        if payload.content is not None:
            next_content_json = _to_json_text(payload.content)
        next_ticket = row["requested_ticket"] if payload.requested_ticket is None else payload.requested_ticket
        next_comment = payload.comment or str(row.get("last_comment") or "")

        conn.execute(
            update(workflow_locks)
            .where(workflow_locks.c.id == workflow_lock_id)
            .values(
                content_json=next_content_json,
                requested_ticket=next_ticket,
                last_comment=next_comment,
                updated_by=actor_username,
                updated_at=now,
            )
        )
        updated = conn.execute(
            select(workflow_locks).where(workflow_locks.c.id == workflow_lock_id).limit(1)
        ).mappings().first()

    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to update workflow lock draft")
    model = _row_to_workflow_lock_model(updated)
    _write_audit_log(
        principal=principal,
        action="workflow_lock_update_draft",
        resource_type="workflow_lock",
        resource_id=str(model.id),
        detail={"status": model.status, "requested_ticket": model.requested_ticket},
    )
    return model

@app.post("/api/workflow-locks/{workflow_lock_id}/submit", response_model=WorkflowLockRead)
def submit_workflow_lock_for_review(
    workflow_lock_id: int,
    payload: WorkflowLockTransitionRequest,
    principal: dict[str, Any] = Depends(get_current_admin),
) -> WorkflowLockRead:
    actor_username = str(principal.get("username") or "unknown")
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(workflow_locks).where(workflow_locks.c.id == workflow_lock_id).limit(1)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Workflow lock not found")
        _require_site_access(principal, str(row["site"]))
        _require_workflow_lock_action(principal, action="submit", status=str(row["status"]))

        next_comment = payload.comment or str(row.get("last_comment") or "")
        next_ticket = row["requested_ticket"] if payload.requested_ticket is None else payload.requested_ticket
        conn.execute(
            update(workflow_locks)
            .where(workflow_locks.c.id == workflow_lock_id)
            .values(
                status=WORKFLOW_LOCK_STATUS_REVIEW,
                requested_ticket=next_ticket,
                last_comment=next_comment,
                updated_by=actor_username,
                updated_at=now,
            )
        )
        updated = conn.execute(
            select(workflow_locks).where(workflow_locks.c.id == workflow_lock_id).limit(1)
        ).mappings().first()

    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to submit workflow lock")
    model = _row_to_workflow_lock_model(updated)
    _write_audit_log(
        principal=principal,
        action="workflow_lock_submit",
        resource_type="workflow_lock",
        resource_id=str(model.id),
        detail={"status": model.status, "requested_ticket": model.requested_ticket, "comment": payload.comment},
    )
    return model

@app.post("/api/workflow-locks/{workflow_lock_id}/approve", response_model=WorkflowLockRead)
def approve_workflow_lock(
    workflow_lock_id: int,
    payload: WorkflowLockTransitionRequest,
    principal: dict[str, Any] = Depends(get_current_admin),
) -> WorkflowLockRead:
    actor_username = str(principal.get("username") or "unknown")
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(workflow_locks).where(workflow_locks.c.id == workflow_lock_id).limit(1)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Workflow lock not found")
        _require_site_access(principal, str(row["site"]))
        _require_workflow_lock_action(principal, action="approve", status=str(row["status"]))

        next_comment = payload.comment or str(row.get("last_comment") or "")
        conn.execute(
            update(workflow_locks)
            .where(workflow_locks.c.id == workflow_lock_id)
            .values(
                status=WORKFLOW_LOCK_STATUS_APPROVED,
                last_comment=next_comment,
                reviewed_by=actor_username,
                reviewed_at=now,
                approved_by=actor_username,
                approved_at=now,
                updated_by=actor_username,
                updated_at=now,
            )
        )
        updated = conn.execute(
            select(workflow_locks).where(workflow_locks.c.id == workflow_lock_id).limit(1)
        ).mappings().first()

    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to approve workflow lock")
    model = _row_to_workflow_lock_model(updated)
    _write_audit_log(
        principal=principal,
        action="workflow_lock_approve",
        resource_type="workflow_lock",
        resource_id=str(model.id),
        detail={"status": model.status, "comment": payload.comment},
    )
    return model

@app.post("/api/workflow-locks/{workflow_lock_id}/reject", response_model=WorkflowLockRead)
def reject_workflow_lock(
    workflow_lock_id: int,
    payload: WorkflowLockTransitionRequest,
    principal: dict[str, Any] = Depends(get_current_admin),
) -> WorkflowLockRead:
    actor_username = str(principal.get("username") or "unknown")
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(workflow_locks).where(workflow_locks.c.id == workflow_lock_id).limit(1)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Workflow lock not found")
        _require_site_access(principal, str(row["site"]))
        _require_workflow_lock_action(principal, action="reject", status=str(row["status"]))

        next_comment = payload.comment or "Rejected in review"
        conn.execute(
            update(workflow_locks)
            .where(workflow_locks.c.id == workflow_lock_id)
            .values(
                status=WORKFLOW_LOCK_STATUS_DRAFT,
                last_comment=next_comment,
                reviewed_by=actor_username,
                reviewed_at=now,
                approved_by=None,
                approved_at=None,
                locked_by=None,
                locked_at=None,
                lock_reason=None,
                unlocked_by=None,
                unlocked_at=None,
                unlock_reason=None,
                updated_by=actor_username,
                updated_at=now,
            )
        )
        updated = conn.execute(
            select(workflow_locks).where(workflow_locks.c.id == workflow_lock_id).limit(1)
        ).mappings().first()

    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to reject workflow lock")
    model = _row_to_workflow_lock_model(updated)
    _write_audit_log(
        principal=principal,
        action="workflow_lock_reject",
        resource_type="workflow_lock",
        resource_id=str(model.id),
        detail={"status": model.status, "comment": payload.comment},
    )
    return model

@app.post("/api/workflow-locks/{workflow_lock_id}/lock", response_model=WorkflowLockRead)
def lock_workflow_lock(
    workflow_lock_id: int,
    payload: WorkflowLockTransitionRequest,
    principal: dict[str, Any] = Depends(get_current_admin),
) -> WorkflowLockRead:
    actor_username = str(principal.get("username") or "unknown")
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(workflow_locks).where(workflow_locks.c.id == workflow_lock_id).limit(1)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Workflow lock not found")
        _require_site_access(principal, str(row["site"]))
        _require_workflow_lock_action(principal, action="lock", status=str(row["status"]))

        next_comment = payload.comment or str(row.get("last_comment") or "")
        next_ticket = row["requested_ticket"] if payload.requested_ticket is None else payload.requested_ticket
        lock_reason = payload.reason.strip() or "Approved workflow lock"
        conn.execute(
            update(workflow_locks)
            .where(workflow_locks.c.id == workflow_lock_id)
            .values(
                status=WORKFLOW_LOCK_STATUS_LOCKED,
                requested_ticket=next_ticket,
                lock_reason=lock_reason,
                last_comment=next_comment,
                locked_by=actor_username,
                locked_at=now,
                updated_by=actor_username,
                updated_at=now,
            )
        )
        updated = conn.execute(
            select(workflow_locks).where(workflow_locks.c.id == workflow_lock_id).limit(1)
        ).mappings().first()

    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to lock workflow")
    model = _row_to_workflow_lock_model(updated)
    _write_audit_log(
        principal=principal,
        action="workflow_lock_lock",
        resource_type="workflow_lock",
        resource_id=str(model.id),
        detail={"status": model.status, "lock_reason": model.lock_reason, "requested_ticket": model.requested_ticket},
    )
    return model

@app.post("/api/workflow-locks/{workflow_lock_id}/unlock", response_model=WorkflowLockRead)
def unlock_workflow_lock(
    workflow_lock_id: int,
    payload: WorkflowLockTransitionRequest,
    principal: dict[str, Any] = Depends(get_current_admin),
) -> WorkflowLockRead:
    actor_username = str(principal.get("username") or "unknown")
    now = datetime.now(timezone.utc)
    reason = payload.reason.strip()
    ticket = (payload.requested_ticket or "").strip()
    if not reason:
        raise HTTPException(status_code=400, detail="Unlock reason is required")
    if not ticket:
        raise HTTPException(status_code=400, detail="Unlock request ticket is required")

    with get_conn() as conn:
        row = conn.execute(
            select(workflow_locks).where(workflow_locks.c.id == workflow_lock_id).limit(1)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Workflow lock not found")
        _require_site_access(principal, str(row["site"]))
        _require_workflow_lock_action(principal, action="unlock", status=str(row["status"]))

        next_comment = payload.comment or str(row.get("last_comment") or "")
        conn.execute(
            update(workflow_locks)
            .where(workflow_locks.c.id == workflow_lock_id)
            .values(
                status=WORKFLOW_LOCK_STATUS_APPROVED,
                requested_ticket=ticket,
                unlock_reason=reason,
                last_comment=next_comment,
                unlocked_by=actor_username,
                unlocked_at=now,
                updated_by=actor_username,
                updated_at=now,
            )
        )
        updated = conn.execute(
            select(workflow_locks).where(workflow_locks.c.id == workflow_lock_id).limit(1)
        ).mappings().first()

    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to unlock workflow")
    model = _row_to_workflow_lock_model(updated)
    _write_audit_log(
        principal=principal,
        action="workflow_lock_unlock",
        resource_type="workflow_lock",
        resource_id=str(model.id),
        detail={
            "status": model.status,
            "unlock_reason": reason,
            "requested_ticket": ticket,
            "comment": payload.comment,
        },
    )
    return model

@app.post("/api/inspections", response_model=InspectionRead, status_code=201)
def create_inspection(
    payload: InspectionCreate,
    principal: dict[str, Any] = Depends(require_permission("inspections:write")),
) -> InspectionRead:
    _require_site_access(principal, payload.site)
    parsed_ops_notes = _validate_ops_inspection_payload(payload)
    risk_level, flags = _calculate_risk(payload, parsed_ops_notes=parsed_ops_notes)
    ops_snapshot = _extract_ops_snapshot_values(parsed_ops_notes)
    resolved_master_ids = _resolve_ops_master_asset_ids(
        payload=payload,
        parsed_ops_notes=parsed_ops_notes,
        ops_snapshot=ops_snapshot,
    )
    now = datetime.now(timezone.utc)
    inspected_at = _to_utc(payload.inspected_at)

    with get_conn() as conn:
        result = conn.execute(
            insert(inspections).values(
                site=payload.site,
                location=payload.location,
                cycle=payload.cycle,
                inspector=payload.inspector,
                inspected_at=inspected_at,
                equipment_id=resolved_master_ids["equipment_id"],
                qr_asset_id=resolved_master_ids["qr_asset_id"],
                equipment_snapshot=ops_snapshot["equipment_snapshot"],
                equipment_location_snapshot=ops_snapshot["equipment_location_snapshot"],
                qr_id=ops_snapshot["qr_id"],
                checklist_set_id=ops_snapshot["checklist_set_id"],
                checklist_version=ops_snapshot["checklist_version"],
                transformer_kva=payload.transformer_kva,
                voltage_r=payload.voltage_r,
                voltage_s=payload.voltage_s,
                voltage_t=payload.voltage_t,
                current_r=payload.current_r,
                current_s=payload.current_s,
                current_t=payload.current_t,
                winding_temp_c=payload.winding_temp_c,
                grounding_ohm=payload.grounding_ohm,
                insulation_mohm=payload.insulation_mohm,
                notes=payload.notes,
                risk_level=risk_level,
                risk_flags=",".join(flags),
                created_at=now,
            )
        )
        inspection_id = result.inserted_primary_key[0]
        if inspection_id is None:
            raise HTTPException(status_code=500, detail="Failed to create inspection")

        row = conn.execute(
            select(inspections).where(inspections.c.id == inspection_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=500, detail="Failed to load created inspection")

    model = _row_to_read_model(row)
    _write_audit_log(
        principal=principal,
        action="inspection_create",
        resource_type="inspection",
        resource_id=str(model.id),
        detail={
            "site": model.site,
            "location": model.location,
            "risk_level": model.risk_level,
            "equipment_id": model.equipment_id,
            "qr_asset_id": model.qr_asset_id,
            "equipment_snapshot": model.equipment_snapshot,
            "qr_id": model.qr_id,
            "checklist_set_id": model.checklist_set_id,
        },
    )
    return model

@app.get("/api/inspections", response_model=list[InspectionRead])
def list_inspections(
    site: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    principal: dict[str, Any] = Depends(require_permission("inspections:read")),
) -> list[InspectionRead]:
    _require_site_access(principal, site)
    stmt = select(inspections)
    if site is not None:
        stmt = stmt.where(inspections.c.site == site)
    else:
        allowed_sites = _allowed_sites_for_principal(principal)
        if allowed_sites is not None:
            if not allowed_sites:
                return []
            stmt = stmt.where(inspections.c.site.in_(allowed_sites))

    with get_conn() as conn:
        rows = conn.execute(
            stmt.order_by(inspections.c.inspected_at.desc(), inspections.c.id.desc()).limit(limit).offset(offset)
        ).mappings().all()
    return [_row_to_read_model(r) for r in rows]

@app.get("/api/inspections/{inspection_id}", response_model=InspectionRead)
def get_inspection(
    inspection_id: int,
    principal: dict[str, Any] = Depends(require_permission("inspections:read")),
) -> InspectionRead:
    with get_conn() as conn:
        row = conn.execute(
            select(inspections).where(inspections.c.id == inspection_id)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Inspection not found")
    _require_site_access(principal, str(row["site"]))
    return _row_to_read_model(row)

@app.post("/api/inspections/{inspection_id}/evidence", response_model=InspectionEvidenceRead, status_code=201)
async def upload_inspection_evidence(
    inspection_id: int,
    file: UploadFile = File(...),
    note: str = Form(default=""),
    principal: dict[str, Any] = Depends(require_permission("inspections:write")),
) -> InspectionEvidenceRead:
    file_name = _safe_download_filename(file.filename or "", fallback="inspection-evidence.bin", max_length=120)
    content_type = (file.content_type or "application/octet-stream").strip() or "application/octet-stream"
    content_type = content_type[:120].lower()
    if not _is_allowed_evidence_content_type(content_type):
        raise HTTPException(status_code=415, detail="Unsupported evidence content type")

    file_bytes = await file.read(INSPECTION_EVIDENCE_MAX_BYTES + 1)
    await file.close()
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Empty evidence file is not allowed")
    if len(file_bytes) > INSPECTION_EVIDENCE_MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Evidence file too large (max {INSPECTION_EVIDENCE_MAX_BYTES} bytes)",
        )

    sha256_digest = hashlib.sha256(file_bytes).hexdigest()
    scan_status, scan_engine, scan_reason = _scan_evidence_bytes(
        file_bytes=file_bytes,
        content_type=content_type,
    )
    if scan_status == "infected" or (scan_status == "suspicious" and EVIDENCE_SCAN_BLOCK_SUSPICIOUS):
        raise HTTPException(status_code=422, detail=f"Evidence scan blocked upload: {scan_reason or scan_status}")

    storage_backend, storage_key, stored_bytes = _write_evidence_blob(
        file_name=file_name,
        file_bytes=file_bytes,
        sha256_digest=sha256_digest,
    )

    actor_username = str(principal.get("username") or "unknown")
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        inspection_row = conn.execute(
            select(inspections).where(inspections.c.id == inspection_id).limit(1)
        ).mappings().first()
        if inspection_row is None:
            raise HTTPException(status_code=404, detail="Inspection not found")

        site = str(inspection_row["site"])
        _require_site_access(principal, site)

        result = conn.execute(
            insert(inspection_evidence_files).values(
                inspection_id=inspection_id,
                site=site,
                file_name=file_name,
                content_type=content_type,
                file_size=len(file_bytes),
                file_bytes=stored_bytes,
                storage_backend=storage_backend,
                storage_key=storage_key,
                sha256=sha256_digest,
                malware_scan_status=scan_status,
                malware_scan_engine=scan_engine,
                malware_scanned_at=now,
                note=note.strip(),
                uploaded_by=actor_username,
                uploaded_at=now,
            )
        )
        evidence_id = int(result.inserted_primary_key[0])
        evidence_row = conn.execute(
            select(inspection_evidence_files).where(inspection_evidence_files.c.id == evidence_id).limit(1)
        ).mappings().first()

    if evidence_row is None:
        raise HTTPException(status_code=500, detail="Failed to save inspection evidence")
    model = _row_to_inspection_evidence_model(evidence_row)
    _write_audit_log(
        principal=principal,
        action="inspection_evidence_upload",
        resource_type="inspection_evidence",
        resource_id=str(model.id),
        detail={
            "inspection_id": model.inspection_id,
            "site": model.site,
            "file_name": model.file_name,
            "file_size": model.file_size,
            "storage_backend": model.storage_backend,
            "sha256": model.sha256,
            "malware_scan_status": model.malware_scan_status,
            "scan_reason": scan_reason,
        },
    )
    return model

@app.get("/api/inspections/{inspection_id}/evidence", response_model=list[InspectionEvidenceRead])
def list_inspection_evidence(
    inspection_id: int,
    principal: dict[str, Any] = Depends(require_permission("inspections:read")),
) -> list[InspectionEvidenceRead]:
    with get_conn() as conn:
        inspection_row = conn.execute(
            select(inspections).where(inspections.c.id == inspection_id).limit(1)
        ).mappings().first()
        if inspection_row is None:
            raise HTTPException(status_code=404, detail="Inspection not found")

        _require_site_access(principal, str(inspection_row["site"]))
        rows = conn.execute(
            select(inspection_evidence_files)
            .where(inspection_evidence_files.c.inspection_id == inspection_id)
            .order_by(inspection_evidence_files.c.uploaded_at.desc(), inspection_evidence_files.c.id.desc())
        ).mappings().all()
    return [_row_to_inspection_evidence_model(row) for row in rows]

@app.get("/api/inspections/evidence/{evidence_id}/download", response_model=None)
def download_inspection_evidence(
    evidence_id: int,
    principal: dict[str, Any] = Depends(require_permission("inspections:read")),
) -> Response:
    with get_conn() as conn:
        row = conn.execute(
            select(inspection_evidence_files).where(inspection_evidence_files.c.id == evidence_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Inspection evidence not found")

    site = str(row["site"])
    _require_site_access(principal, site)
    content_type = str(row.get("content_type") or "application/octet-stream")
    file_name = _safe_download_filename(
        str(row.get("file_name") or ""),
        fallback="inspection-evidence.bin",
        max_length=120,
    )
    data = _read_evidence_blob(row=row)
    if data is None:
        raise HTTPException(status_code=410, detail="Evidence file is unavailable")
    sha256_digest = hashlib.sha256(data).hexdigest()
    stored_sha = str(row.get("sha256") or "").strip().lower()
    if stored_sha and stored_sha != sha256_digest:
        raise HTTPException(status_code=409, detail="Evidence integrity check failed")
    storage_backend = _normalize_evidence_storage_backend(str(row.get("storage_backend") or "db"))

    _write_audit_log(
        principal=principal,
        action="inspection_evidence_download",
        resource_type="inspection_evidence",
        resource_id=str(evidence_id),
        detail={"site": site, "file_name": file_name, "sha256": sha256_digest, "storage_backend": storage_backend},
    )
    return Response(
        content=data,
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{file_name}"',
            "X-Download-Options": "noopen",
            "X-Evidence-SHA256": sha256_digest,
        },
    )

@app.get("/inspections/{inspection_id}/print", response_class=HTMLResponse)
def print_inspection(
    inspection_id: int,
    principal: dict[str, Any] = Depends(require_permission("inspections:read")),
) -> str:
    with get_conn() as conn:
        row = conn.execute(
            select(inspections).where(inspections.c.id == inspection_id)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Inspection not found")
    _require_site_access(principal, str(row["site"]))

    data = _row_to_read_model(row)
    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Inspection #{data.id}</title>
  <style>
    @page {{ size: A4; margin: 12mm; }}
    body {{ font-family: Arial, sans-serif; color: #111; }}
    h1 {{ margin-bottom: 10px; font-size: 20px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td {{ border: 1px solid #ddd; padding: 6px; font-size: 13px; }}
    .k {{ width: 30%; background: #f7f7f7; font-weight: 600; }}
  </style>
</head>
<body>
  <h1>Inspection Report #{data.id}</h1>
  <table>
    <tr><td class="k">Site</td><td>{data.site}</td></tr>
    <tr><td class="k">Location</td><td>{data.location}</td></tr>
    <tr><td class="k">Cycle</td><td>{data.cycle}</td></tr>
    <tr><td class="k">Inspector</td><td>{data.inspector}</td></tr>
    <tr><td class="k">Inspected At</td><td>{data.inspected_at.isoformat()}</td></tr>
    <tr><td class="k">Risk Level</td><td>{data.risk_level}</td></tr>
    <tr><td class="k">Risk Flags</td><td>{", ".join(data.risk_flags) or "-"}</td></tr>
    <tr><td class="k">Transformer (kVA)</td><td>{data.transformer_kva or "-"}</td></tr>
    <tr><td class="k">Voltage (R/S/T)</td><td>{data.voltage_r or "-"} / {data.voltage_s or "-"} / {data.voltage_t or "-"}</td></tr>
    <tr><td class="k">Current (R/S/T)</td><td>{data.current_r or "-"} / {data.current_s or "-"} / {data.current_t or "-"}</td></tr>
    <tr><td class="k">Winding Temp (C)</td><td>{data.winding_temp_c or "-"}</td></tr>
    <tr><td class="k">Grounding (ohm)</td><td>{data.grounding_ohm or "-"}</td></tr>
    <tr><td class="k">Insulation (Mohm)</td><td>{data.insulation_mohm or "-"}</td></tr>
    <tr><td class="k">Notes</td><td>{data.notes or "-"}</td></tr>
    <tr><td class="k">Created At</td><td>{data.created_at.isoformat()}</td></tr>
  </table>
</body>
</html>
"""

@app.get("/api/work-orders/sla/rules")
def get_work_order_sla_rules(
    principal: dict[str, Any] = Depends(require_permission("work_orders:read")),
) -> dict[str, Any]:
    payload = _inspection_to_work_order_sla_rule_payload()
    _write_audit_log(
        principal=principal,
        action="work_order_sla_rules_view",
        resource_type="work_order_sla",
        resource_id="rules",
        detail=payload,
    )
    return payload

@app.post("/api/work-orders", response_model=WorkOrderRead, status_code=201)
def create_work_order(
    payload: WorkOrderCreate,
    principal: dict[str, Any] = Depends(require_permission("work_orders:write")),
) -> WorkOrderRead:
    _require_site_access(principal, payload.site)
    now = datetime.now(timezone.utc)
    actor_username = str(principal.get("username") or "unknown")
    due_at = _as_optional_datetime(payload.due_at)
    auto_due_applied = False
    policy_source = "manual"
    due_hours_applied: int | None = None
    requested_priority = str(payload.priority or "medium").strip().lower() or "medium"
    effective_priority = requested_priority
    priority_upgraded = False
    priority_upgrade_reasons: list[str] = []
    inspection_sla_context: dict[str, Any] | None = None
    inspection_ops_snapshot: dict[str, str | int | None] = {
        "equipment_id": None,
        "qr_asset_id": None,
        "equipment_snapshot": None,
        "equipment_location_snapshot": None,
        "qr_id": None,
        "checklist_set_id": None,
        "checklist_version": None,
    }

    with get_conn() as conn:
        if payload.inspection_id is not None:
            inspection_row = conn.execute(
                select(inspections)
                .where(inspections.c.id == int(payload.inspection_id))
                .limit(1)
            ).mappings().first()
            if inspection_row is None:
                raise HTTPException(status_code=404, detail="Inspection not found")
            inspection_site = str(inspection_row["site"])
            _require_site_access(principal, inspection_site)
            if inspection_site != payload.site:
                raise HTTPException(status_code=400, detail="inspection_id site must match work order site")
            inspection_sla_context = _derive_inspection_work_order_sla_context(inspection_row)
            inspection_ops_snapshot = _ops_snapshot_values_from_inspection_row(inspection_row)
            floor_priority = str(inspection_sla_context.get("priority_floor") or "medium").strip().lower() or "medium"
            upgraded_priority = _higher_priority(effective_priority, floor_priority)
            if upgraded_priority != effective_priority:
                effective_priority = upgraded_priority
                priority_upgraded = True
            priority_upgrade_reasons = [
                str(item).strip()
                for item in (inspection_sla_context.get("rules_applied") or [])
                if str(item).strip()
            ]
        if due_at is None:
            policy, _, source, _, _ = _load_sla_policy(site=payload.site)
            due_hours_applied = int(
                policy["default_due_hours"].get(effective_priority, SLA_DEFAULT_DUE_HOURS["medium"])
            )
            due_at = now + timedelta(hours=due_hours_applied)
            auto_due_applied = True
            policy_source = source

        result = conn.execute(
            insert(work_orders).values(
                title=payload.title,
                description=payload.description,
                site=payload.site,
                location=payload.location,
                priority=effective_priority,
                status="open",
                assignee=payload.assignee,
                reporter=payload.reporter,
                inspection_id=payload.inspection_id,
                equipment_id=inspection_ops_snapshot["equipment_id"],
                qr_asset_id=inspection_ops_snapshot["qr_asset_id"],
                equipment_snapshot=inspection_ops_snapshot["equipment_snapshot"],
                equipment_location_snapshot=inspection_ops_snapshot["equipment_location_snapshot"],
                qr_id=inspection_ops_snapshot["qr_id"],
                checklist_set_id=inspection_ops_snapshot["checklist_set_id"],
                due_at=due_at,
                acknowledged_at=None,
                completed_at=None,
                resolution_notes="",
                is_escalated=False,
                created_at=now,
                updated_at=now,
            )
        )
        work_order_id = result.inserted_primary_key[0]
        _append_work_order_event(
            conn,
            work_order_id=int(work_order_id),
            event_type="created",
            actor_username=actor_username,
            from_status=None,
            to_status="open",
            note=payload.description or "",
            detail={
                "priority": effective_priority,
                "requested_priority": requested_priority,
                "priority_upgraded": priority_upgraded,
                "priority_upgrade_reasons": priority_upgrade_reasons,
                "assignee": payload.assignee,
                "reporter": payload.reporter,
                "inspection_id": payload.inspection_id,
                "inspection_sla_context": inspection_sla_context,
                "equipment_id": inspection_ops_snapshot["equipment_id"],
                "qr_asset_id": inspection_ops_snapshot["qr_asset_id"],
                "equipment_snapshot": inspection_ops_snapshot["equipment_snapshot"],
                "qr_id": inspection_ops_snapshot["qr_id"],
                "checklist_set_id": inspection_ops_snapshot["checklist_set_id"],
                "auto_due_applied": auto_due_applied,
                "due_hours_applied": due_hours_applied,
                "policy_source": policy_source,
            },
        )
        row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()

    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create work order")
    model = _row_to_work_order_model(row)
    _write_audit_log(
        principal=principal,
        action="work_order_create",
        resource_type="work_order",
        resource_id=str(model.id),
        detail={
            "site": model.site,
            "priority": model.priority,
            "requested_priority": requested_priority,
            "priority_upgraded": priority_upgraded,
            "priority_upgrade_reasons": priority_upgrade_reasons,
            "due_at": model.due_at,
            "auto_due_applied": auto_due_applied,
            "due_hours_applied": due_hours_applied,
            "policy_source": policy_source,
            "inspection_id": payload.inspection_id,
            "inspection_sla_context": inspection_sla_context,
            "equipment_id": model.equipment_id,
            "qr_asset_id": model.qr_asset_id,
            "equipment_snapshot": model.equipment_snapshot,
            "qr_id": model.qr_id,
            "checklist_set_id": model.checklist_set_id,
        },
    )
    return model

@app.get("/api/work-orders", response_model=list[WorkOrderRead])
def list_work_orders(
    status: Annotated[str | None, Query()] = None,
    site: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    principal: dict[str, Any] = Depends(require_permission("work_orders:read")),
) -> list[WorkOrderRead]:
    _require_site_access(principal, site)
    stmt = select(work_orders)
    if status is not None:
        stmt = stmt.where(work_orders.c.status == status)
    if site is not None:
        stmt = stmt.where(work_orders.c.site == site)
    else:
        allowed_sites = _allowed_sites_for_principal(principal)
        if allowed_sites is not None:
            if not allowed_sites:
                return []
            stmt = stmt.where(work_orders.c.site.in_(allowed_sites))

    stmt = stmt.order_by(work_orders.c.created_at.desc(), work_orders.c.id.desc()).limit(limit).offset(offset)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_work_order_model(r) for r in rows]

@app.get("/api/work-orders/{work_order_id}", response_model=WorkOrderRead)
def get_work_order(
    work_order_id: int,
    principal: dict[str, Any] = Depends(require_permission("work_orders:read")),
) -> WorkOrderRead:
    with get_conn() as conn:
        row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Work order not found")
    _require_site_access(principal, str(row["site"]))
    return _row_to_work_order_model(row)

@app.patch("/api/work-orders/{work_order_id}/ack", response_model=WorkOrderRead)
def ack_work_order(
    work_order_id: int,
    payload: WorkOrderAck,
    principal: dict[str, Any] = Depends(require_permission("work_orders:write")),
) -> WorkOrderRead:
    now = datetime.now(timezone.utc)
    actor_username = str(principal.get("username") or "unknown")
    with get_conn() as conn:
        row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Work order not found")
        _require_site_access(principal, str(row["site"]))
        _validate_work_order_transition(str(row["status"]), "acked")

        assignee = payload.assignee if payload.assignee is not None else row["assignee"]
        conn.execute(
            update(work_orders)
            .where(work_orders.c.id == work_order_id)
            .values(
                status="acked",
                assignee=assignee,
                acknowledged_at=now,
                updated_at=now,
            )
        )
        _append_work_order_event(
            conn,
            work_order_id=work_order_id,
            event_type="status_changed",
            actor_username=actor_username,
            from_status=str(row["status"]),
            to_status="acked",
            note="Acknowledged work order",
            detail={"assignee": assignee},
        )
        updated_row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()

    if updated_row is None:
        raise HTTPException(status_code=500, detail="Failed to update work order")
    model = _row_to_work_order_model(updated_row)
    _write_audit_log(
        principal=principal,
        action="work_order_ack",
        resource_type="work_order",
        resource_id=str(model.id),
        detail={"status": model.status, "assignee": model.assignee},
    )
    return model

@app.patch("/api/work-orders/{work_order_id}/complete", response_model=WorkOrderRead)
def complete_work_order(
    work_order_id: int,
    payload: WorkOrderComplete,
    principal: dict[str, Any] = Depends(require_permission("work_orders:write")),
) -> WorkOrderRead:
    now = datetime.now(timezone.utc)
    actor_username = str(principal.get("username") or "unknown")
    with get_conn() as conn:
        row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Work order not found")
        _require_site_access(principal, str(row["site"]))
        if row["status"] == "completed":
            return _row_to_work_order_model(row)
        _validate_work_order_transition(str(row["status"]), "completed")

        conn.execute(
            update(work_orders)
            .where(work_orders.c.id == work_order_id)
            .values(
                status="completed",
                completed_at=now,
                resolution_notes=payload.resolution_notes,
                updated_at=now,
            )
        )
        _append_work_order_event(
            conn,
            work_order_id=work_order_id,
            event_type="status_changed",
            actor_username=actor_username,
            from_status=str(row["status"]),
            to_status="completed",
            note=payload.resolution_notes,
            detail={"resolution_notes": payload.resolution_notes},
        )
        updated_row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()

    if updated_row is None:
        raise HTTPException(status_code=500, detail="Failed to complete work order")
    model = _row_to_work_order_model(updated_row)
    _write_audit_log(
        principal=principal,
        action="work_order_complete",
        resource_type="work_order",
        resource_id=str(model.id),
        detail={"status": model.status},
    )
    return model

@app.patch("/api/work-orders/{work_order_id}/cancel", response_model=WorkOrderRead)
def cancel_work_order(
    work_order_id: int,
    payload: WorkOrderCancel,
    principal: dict[str, Any] = Depends(require_permission("work_orders:write")),
) -> WorkOrderRead:
    now = datetime.now(timezone.utc)
    actor_username = str(principal.get("username") or "unknown")
    with get_conn() as conn:
        row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Work order not found")
        _require_site_access(principal, str(row["site"]))
        _validate_work_order_transition(str(row["status"]), "canceled")

        conn.execute(
            update(work_orders)
            .where(work_orders.c.id == work_order_id)
            .values(
                status="canceled",
                resolution_notes=payload.reason or row["resolution_notes"] or "",
                updated_at=now,
            )
        )
        _append_work_order_event(
            conn,
            work_order_id=work_order_id,
            event_type="status_changed",
            actor_username=actor_username,
            from_status=str(row["status"]),
            to_status="canceled",
            note=payload.reason or "Canceled work order",
            detail={"reason": payload.reason},
        )
        updated_row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()

    if updated_row is None:
        raise HTTPException(status_code=500, detail="Failed to cancel work order")
    model = _row_to_work_order_model(updated_row)
    _write_audit_log(
        principal=principal,
        action="work_order_cancel",
        resource_type="work_order",
        resource_id=str(model.id),
        detail={"status": model.status, "reason": payload.reason},
    )
    return model

@app.patch("/api/work-orders/{work_order_id}/reopen", response_model=WorkOrderRead)
def reopen_work_order(
    work_order_id: int,
    payload: WorkOrderReopen,
    principal: dict[str, Any] = Depends(require_permission("work_orders:write")),
) -> WorkOrderRead:
    now = datetime.now(timezone.utc)
    actor_username = str(principal.get("username") or "unknown")
    with get_conn() as conn:
        row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Work order not found")
        _require_site_access(principal, str(row["site"]))
        _validate_work_order_transition(str(row["status"]), "open")

        conn.execute(
            update(work_orders)
            .where(work_orders.c.id == work_order_id)
            .values(
                status="open",
                completed_at=None,
                acknowledged_at=None,
                is_escalated=False,
                updated_at=now,
            )
        )
        _append_work_order_event(
            conn,
            work_order_id=work_order_id,
            event_type="status_changed",
            actor_username=actor_username,
            from_status=str(row["status"]),
            to_status="open",
            note=payload.reason or "Reopened work order",
            detail={"reason": payload.reason},
        )
        updated_row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()

    if updated_row is None:
        raise HTTPException(status_code=500, detail="Failed to reopen work order")
    model = _row_to_work_order_model(updated_row)
    _write_audit_log(
        principal=principal,
        action="work_order_reopen",
        resource_type="work_order",
        resource_id=str(model.id),
        detail={"status": model.status, "reason": payload.reason},
    )
    return model

@app.post("/api/work-orders/{work_order_id}/comments", response_model=WorkOrderEventRead, status_code=201)
def add_work_order_comment(
    work_order_id: int,
    payload: WorkOrderCommentCreate,
    principal: dict[str, Any] = Depends(require_permission("work_orders:write")),
) -> WorkOrderEventRead:
    actor_username = str(principal.get("username") or "unknown")
    with get_conn() as conn:
        row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Work order not found")
        _require_site_access(principal, str(row["site"]))

        result = conn.execute(
            insert(work_order_events).values(
                work_order_id=work_order_id,
                event_type="comment",
                actor_username=actor_username,
                from_status=row["status"],
                to_status=row["status"],
                note=payload.comment,
                detail_json=_to_json_text({"comment": payload.comment}),
                created_at=datetime.now(timezone.utc),
            )
        )
        event_id = int(result.inserted_primary_key[0])
        event_row = conn.execute(
            select(work_order_events).where(work_order_events.c.id == event_id)
        ).mappings().first()

    if event_row is None:
        raise HTTPException(status_code=500, detail="Failed to create work order comment")
    model = _row_to_work_order_event_model(event_row)
    _write_audit_log(
        principal=principal,
        action="work_order_comment_add",
        resource_type="work_order",
        resource_id=str(work_order_id),
        detail={"event_id": model.id},
    )
    return model

@app.get("/api/work-orders/{work_order_id}/events", response_model=list[WorkOrderEventRead])
def list_work_order_events(
    work_order_id: int,
    limit: Annotated[int, Query(ge=1, le=300)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    principal: dict[str, Any] = Depends(require_permission("work_orders:read")),
) -> list[WorkOrderEventRead]:
    with get_conn() as conn:
        row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Work order not found")
        _require_site_access(principal, str(row["site"]))

        rows = conn.execute(
            select(work_order_events)
            .where(work_order_events.c.work_order_id == work_order_id)
            .order_by(work_order_events.c.created_at.asc(), work_order_events.c.id.asc())
            .limit(limit)
            .offset(offset)
        ).mappings().all()
    return [_row_to_work_order_event_model(item) for item in rows]

@app.post("/api/work-orders/escalations/run", response_model=SlaEscalationRunResponse)
def run_sla_escalation(
    payload: SlaEscalationRunRequest,
    principal: dict[str, Any] = Depends(require_permission("work_orders:escalate")),
) -> SlaEscalationRunResponse:
    _require_site_access(principal, payload.site)
    allowed_sites = _allowed_sites_for_principal(principal) if payload.site is None else None
    result = run_sla_escalation_job(
        site=payload.site,
        dry_run=payload.dry_run,
        limit=payload.limit,
        allowed_sites=allowed_sites,
        trigger="api",
    )
    _write_audit_log(
        principal=principal,
        action="work_order_sla_escalation_run",
        resource_type="work_order",
        resource_id="batch",
        detail={
            "site": payload.site,
            "allowed_sites": allowed_sites,
            "dry_run": payload.dry_run,
            "limit": payload.limit,
            "candidate_count": result.candidate_count,
            "escalated_count": result.escalated_count,
            "alert_dispatched": result.alert_dispatched,
            "alert_error": result.alert_error,
        },
    )
    return result

@app.get("/api/reports/monthly", response_model=MonthlyReportRead)
def get_monthly_report(
    month: Annotated[str | None, Query(description="YYYY-MM", pattern=r"^\d{4}-\d{2}$")] = None,
    site: Annotated[str | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("reports:read")),
) -> MonthlyReportRead:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    return build_monthly_report(month=month, site=site, allowed_sites=allowed_sites)

@app.get("/api/reports/monthly/csv")
def get_monthly_report_csv(
    month: Annotated[str | None, Query(description="YYYY-MM", pattern=r"^\d{4}-\d{2}$")] = None,
    site: Annotated[str | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("reports:export")),
) -> Response:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = build_monthly_report(month=month, site=site, allowed_sites=allowed_sites)
    csv_text = _build_monthly_report_csv(report)
    site_label = (report.site or "all").replace(" ", "_")
    file_name = f"monthly-report-{report.month}-{site_label}.csv"
    response = Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )
    _write_audit_log(
        principal=principal,
        action="report_monthly_export_csv",
        resource_type="report",
        resource_id=f"{report.month}:{report.site or 'ALL'}",
        detail={"month": report.month, "site": report.site},
    )
    return response

@app.get("/api/reports/monthly/pdf")
def get_monthly_report_pdf(
    month: Annotated[str | None, Query(description="YYYY-MM", pattern=r"^\d{4}-\d{2}$")] = None,
    site: Annotated[str | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("reports:export")),
) -> Response:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = build_monthly_report(month=month, site=site, allowed_sites=allowed_sites)
    pdf_bytes = _build_monthly_report_pdf(report)
    site_label = (report.site or "all").replace(" ", "_")
    file_name = f"monthly-report-{report.month}-{site_label}.pdf"
    response = Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )
    _write_audit_log(
        principal=principal,
        action="report_monthly_export_pdf",
        resource_type="report",
        resource_id=f"{report.month}:{report.site or 'ALL'}",
        detail={"month": report.month, "site": report.site},
    )
    return response

@app.get("/reports/monthly/print", response_class=HTMLResponse)
def print_monthly_report(
    month: Annotated[str | None, Query(description="YYYY-MM", pattern=r"^\d{4}-\d{2}$")] = None,
    site: Annotated[str | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("reports:read")),
) -> str:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = build_monthly_report(month=month, site=site, allowed_sites=allowed_sites)
    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Monthly Audit Report {report.month}</title>
  <style>
    @page {{ size: A4; margin: 12mm; }}
    body {{ font-family: Arial, sans-serif; color: #111; }}
    h1 {{ margin-bottom: 8px; font-size: 20px; }}
    h2 {{ margin-top: 14px; margin-bottom: 6px; font-size: 16px; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 8px; }}
    td {{ border: 1px solid #ddd; padding: 6px; font-size: 13px; }}
    .k {{ width: 40%; background: #f7f7f7; font-weight: 600; }}
  </style>
</head>
<body>
  <h1>Monthly Audit Report ({report.month})</h1>
  <table>
    <tr><td class="k">Site</td><td>{report.site or "ALL"}</td></tr>
    <tr><td class="k">Generated At</td><td>{report.generated_at.isoformat()}</td></tr>
  </table>
  <h2>Inspection Summary</h2>
  <table>
    <tr><td class="k">Total</td><td>{report.inspections["total"]}</td></tr>
    <tr><td class="k">Risk Counts</td><td>{report.inspections["risk_counts"]}</td></tr>
    <tr><td class="k">Top Risk Flags</td><td>{report.inspections["top_risk_flags"]}</td></tr>
  </table>
  <h2>Work Order Summary</h2>
  <table>
    <tr><td class="k">Total</td><td>{report.work_orders["total"]}</td></tr>
    <tr><td class="k">Status Counts</td><td>{report.work_orders["status_counts"]}</td></tr>
    <tr><td class="k">Escalated Count</td><td>{report.work_orders["escalated_count"]}</td></tr>
    <tr><td class="k">Overdue Open Count</td><td>{report.work_orders["overdue_open_count"]}</td></tr>
    <tr><td class="k">Completion Rate (%)</td><td>{report.work_orders["completion_rate_percent"]}</td></tr>
    <tr><td class="k">Avg Resolution Hours</td><td>{report.work_orders["avg_resolution_hours"] or "-"}</td></tr>
  </table>
</body>
</html>
"""
