"""Adoption tracker routes extracted from app.main."""

import hashlib
from datetime import datetime, timezone
from os import getenv
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile
from sqlalchemy import insert, select, update

from app.database import (
    DATABASE_URL,
    adoption_w02_evidence_files,
    adoption_w02_site_runs,
    adoption_w02_tracker_items,
    adoption_w03_evidence_files,
    adoption_w03_site_runs,
    adoption_w03_tracker_items,
    adoption_w04_evidence_files,
    adoption_w04_site_runs,
    adoption_w04_tracker_items,
    adoption_w07_evidence_files,
    adoption_w07_site_runs,
    adoption_w07_tracker_items,
    adoption_w09_evidence_files,
    adoption_w09_site_runs,
    adoption_w09_tracker_items,
    adoption_w10_evidence_files,
    adoption_w10_site_runs,
    adoption_w10_tracker_items,
    adoption_w11_evidence_files,
    adoption_w11_site_runs,
    adoption_w11_tracker_items,
    adoption_w12_evidence_files,
    adoption_w12_site_runs,
    adoption_w12_tracker_items,
    adoption_w13_evidence_files,
    adoption_w13_site_runs,
    adoption_w13_tracker_items,
    adoption_w14_evidence_files,
    adoption_w14_site_runs,
    adoption_w14_tracker_items,
    adoption_w15_evidence_files,
    adoption_w15_site_runs,
    adoption_w15_tracker_items,
    get_conn,
)
from app.domains.adoption import tracker_service as adoption_tracker_service_module
from app.domains.adoption.content import *  # noqa: F403
from app.domains.iam.core import _principal_site_scope
from app.domains.iam.security import _has_permission, _require_site_access, require_permission
from app.domains.iam.service import _write_audit_log
from app.domains.ops.inspection_service import (
    EVIDENCE_SCAN_BLOCK_SUSPICIOUS,
    _as_optional_datetime,
    _is_allowed_evidence_content_type,
    _normalize_evidence_storage_backend,
    _read_evidence_blob,
    _safe_download_filename,
    _scan_evidence_bytes,
    _write_evidence_blob,
)
from app.domains.ops.record_service import _to_json_text
from app.schemas import (
    AuthMeRead,
    W02EvidenceRead,
    W02TrackerBootstrapRequest,
    W02TrackerBootstrapResponse,
    W02TrackerCompletionRead,
    W02TrackerCompletionRequest,
    W02TrackerItemRead,
    W02TrackerItemUpdate,
    W02TrackerOverviewRead,
    W02TrackerReadinessRead,
    W03EvidenceRead,
    W03TrackerBootstrapRequest,
    W03TrackerBootstrapResponse,
    W03TrackerCompletionRead,
    W03TrackerCompletionRequest,
    W03TrackerItemRead,
    W03TrackerItemUpdate,
    W03TrackerOverviewRead,
    W03TrackerReadinessRead,
    W04EvidenceRead,
    W04TrackerBootstrapRequest,
    W04TrackerBootstrapResponse,
    W04TrackerCompletionRead,
    W04TrackerCompletionRequest,
    W04TrackerItemRead,
    W04TrackerItemUpdate,
    W04TrackerOverviewRead,
    W04TrackerReadinessRead,
    W07EvidenceRead,
    W07TrackerBootstrapRequest,
    W07TrackerBootstrapResponse,
    W07TrackerCompletionRead,
    W07TrackerCompletionRequest,
    W07TrackerItemRead,
    W07TrackerItemUpdate,
    W07TrackerOverviewRead,
    W07TrackerReadinessRead,
    W09EvidenceRead,
    W09TrackerBootstrapRequest,
    W09TrackerBootstrapResponse,
    W09TrackerCompletionRead,
    W09TrackerCompletionRequest,
    W09TrackerItemRead,
    W09TrackerItemUpdate,
    W09TrackerOverviewRead,
    W09TrackerReadinessRead,
    W10EvidenceRead,
    W10TrackerBootstrapRequest,
    W10TrackerBootstrapResponse,
    W10TrackerCompletionRead,
    W10TrackerCompletionRequest,
    W10TrackerItemRead,
    W10TrackerItemUpdate,
    W10TrackerOverviewRead,
    W10TrackerReadinessRead,
    W11EvidenceRead,
    W11TrackerBootstrapRequest,
    W11TrackerBootstrapResponse,
    W11TrackerCompletionRead,
    W11TrackerCompletionRequest,
    W11TrackerItemRead,
    W11TrackerItemUpdate,
    W11TrackerOverviewRead,
    W11TrackerReadinessRead,
    W12EvidenceRead,
    W12TrackerBootstrapRequest,
    W12TrackerBootstrapResponse,
    W12TrackerCompletionRead,
    W12TrackerCompletionRequest,
    W12TrackerItemRead,
    W12TrackerItemUpdate,
    W12TrackerOverviewRead,
    W12TrackerReadinessRead,
    W13EvidenceRead,
    W13TrackerBootstrapRequest,
    W13TrackerBootstrapResponse,
    W13TrackerCompletionRead,
    W13TrackerCompletionRequest,
    W13TrackerItemRead,
    W13TrackerItemUpdate,
    W13TrackerOverviewRead,
    W13TrackerReadinessRead,
    W14EvidenceRead,
    W14TrackerBootstrapRequest,
    W14TrackerBootstrapResponse,
    W14TrackerCompletionRead,
    W14TrackerCompletionRequest,
    W14TrackerItemRead,
    W14TrackerItemUpdate,
    W14TrackerOverviewRead,
    W14TrackerReadinessRead,
    W15EvidenceRead,
    W15TrackerBootstrapRequest,
    W15TrackerBootstrapResponse,
    W15TrackerCompletionRead,
    W15TrackerCompletionRequest,
    W15TrackerItemRead,
    W15TrackerItemUpdate,
    W15TrackerOverviewRead,
    W15TrackerReadinessRead,
)


def _allowed_sites_for_principal(principal: dict[str, Any]) -> list[str] | None:
    scope = _principal_site_scope(principal)
    if "*" in scope:
        return None
    return scope


_TRACKER_SERVICE_PREFIXES = (
    "_adoption_w",
    "_compute_w",
    "_load_w",
    "_reset_w",
    "_row_to_w",
)


def _bind_tracker_service_symbols() -> None:
    for key, value in adoption_tracker_service_module.__dict__.items():
        if key.startswith(_TRACKER_SERVICE_PREFIXES):
            globals()[key] = value


_REQUIRED_NAMESPACE_NAMES = {
    "Annotated",
    "Any",
    "AuthMeRead",
    "Depends",
    "File",
    "Form",
    "HTTPException",
    "Query",
    "Response",
    "UploadFile",
    "_build_w07_completion_package_zip",
    "datetime",
    "get_conn",
    "insert",
    "timezone",
    "update",
}
_REQUIRED_NAMESPACE_PREFIXES = (
    "W02_",
    "W03_",
    "W04_",
    "W07_",
    "W09_",
    "W10_",
    "W11_",
    "W12_",
    "W13_",
    "W14_",
    "W15_",
)


def _bind_namespace(namespace: dict[str, object]) -> None:
    for key, value in namespace.items():
        if key in _REQUIRED_NAMESPACE_NAMES or key.startswith(_REQUIRED_NAMESPACE_PREFIXES):
            globals()[key] = value


def build_router(namespace: dict[str, object]) -> APIRouter:
    """Compatibility extraction layer until adoption services are fully split."""
    _bind_tracker_service_symbols()
    _bind_namespace(namespace)
    router = APIRouter(prefix="/api/adoption", tags=["adoption"])
    app = namespace.get("app") or router

    @router.post("/w02/tracker/bootstrap", response_model=W02TrackerBootstrapResponse)
    def bootstrap_w02_tracker_items(
        payload: W02TrackerBootstrapRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w02:write")),
    ) -> W02TrackerBootstrapResponse:
        _require_site_access(principal, payload.site)
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        catalog = _adoption_w02_catalog_items(payload.site)
        created_count = 0
    
        with get_conn() as conn:
            existing_rows = conn.execute(
                select(
                    adoption_w02_tracker_items.c.item_type,
                    adoption_w02_tracker_items.c.item_key,
                ).where(adoption_w02_tracker_items.c.site == payload.site)
            ).mappings().all()
            existing_keys = {(str(row["item_type"]), str(row["item_key"])) for row in existing_rows}
    
            for entry in catalog:
                key = (str(entry["item_type"]), str(entry["item_key"]))
                if key in existing_keys:
                    continue
                conn.execute(
                    insert(adoption_w02_tracker_items).values(
                        site=payload.site,
                        item_type=str(entry["item_type"]),
                        item_key=str(entry["item_key"]),
                        item_name=str(entry["item_name"]),
                        assignee=None,
                        status=W02_TRACKER_STATUS_PENDING,
                        completion_checked=False,
                        completion_note="",
                        due_at=entry.get("due_at"),
                        completed_at=None,
                        evidence_count=0,
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
                existing_keys.add(key)
                created_count += 1
    
            if created_count > 0:
                _reset_w02_completion_if_closed(
                    conn=conn,
                    site=payload.site,
                    actor_username=actor_username,
                    checked_at=now,
                    reason="bootstrap_added_items",
                )
    
            rows = conn.execute(
                select(adoption_w02_tracker_items)
                .where(adoption_w02_tracker_items.c.site == payload.site)
                .order_by(
                    adoption_w02_tracker_items.c.item_type.asc(),
                    adoption_w02_tracker_items.c.item_key.asc(),
                    adoption_w02_tracker_items.c.id.asc(),
                )
            ).mappings().all()
    
        items = [_row_to_w02_tracker_item_model(row) for row in rows]
        _write_audit_log(
            principal=principal,
            action="w02_tracker_bootstrap",
            resource_type="adoption_w02_tracker",
            resource_id=payload.site,
            detail={"site": payload.site, "created_count": created_count, "total_count": len(items)},
        )
        return W02TrackerBootstrapResponse(
            site=payload.site,
            created_count=created_count,
            total_count=len(items),
            items=items,
        )
    
    
    @router.get("/w02/tracker/items", response_model=list[W02TrackerItemRead])
    def list_w02_tracker_items(
        site: Annotated[str | None, Query()] = None,
        status: Annotated[str | None, Query()] = None,
        item_type: Annotated[str | None, Query()] = None,
        assignee: Annotated[str | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
        offset: Annotated[int, Query(ge=0)] = 0,
        principal: dict[str, Any] = Depends(require_permission("adoption_w02:read")),
    ) -> list[W02TrackerItemRead]:
        _require_site_access(principal, site)
        normalized_status = status.strip().lower() if status is not None else None
        if normalized_status is not None and normalized_status not in W02_TRACKER_STATUS_SET:
            raise HTTPException(status_code=400, detail="Invalid W02 tracker status")
    
        stmt = select(adoption_w02_tracker_items)
        if site is not None:
            stmt = stmt.where(adoption_w02_tracker_items.c.site == site)
        else:
            allowed_sites = _allowed_sites_for_principal(principal)
            if allowed_sites is not None:
                if not allowed_sites:
                    return []
                stmt = stmt.where(adoption_w02_tracker_items.c.site.in_(allowed_sites))
    
        if normalized_status is not None:
            stmt = stmt.where(adoption_w02_tracker_items.c.status == normalized_status)
        if item_type is not None:
            stmt = stmt.where(adoption_w02_tracker_items.c.item_type == item_type.strip())
        if assignee is not None:
            stmt = stmt.where(adoption_w02_tracker_items.c.assignee == assignee.strip())
    
        stmt = stmt.order_by(
            adoption_w02_tracker_items.c.updated_at.desc(),
            adoption_w02_tracker_items.c.id.desc(),
        ).limit(limit).offset(offset)
    
        with get_conn() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [_row_to_w02_tracker_item_model(row) for row in rows]
    
    
    @router.get("/w02/tracker/overview", response_model=W02TrackerOverviewRead)
    def get_w02_tracker_overview(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w02:read")),
    ) -> W02TrackerOverviewRead:
        _require_site_access(principal, site)
        with get_conn() as conn:
            rows = conn.execute(
                select(adoption_w02_tracker_items).where(adoption_w02_tracker_items.c.site == site)
            ).mappings().all()
        models = [_row_to_w02_tracker_item_model(row) for row in rows]
        return _compute_w02_tracker_overview(site, models)
    
    
    @router.get("/w02/tracker/readiness", response_model=W02TrackerReadinessRead)
    def get_w02_tracker_readiness(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w02:read")),
    ) -> W02TrackerReadinessRead:
        _require_site_access(principal, site)
        models = _load_w02_tracker_items_for_site(site)
        return _compute_w02_tracker_readiness(site=site, rows=models)
    
    
    @router.get("/w02/tracker/completion", response_model=W02TrackerCompletionRead)
    def get_w02_tracker_completion(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w02:read")),
    ) -> W02TrackerCompletionRead:
        _require_site_access(principal, site)
        now = datetime.now(timezone.utc)
        models = _load_w02_tracker_items_for_site(site)
        readiness = _compute_w02_tracker_readiness(site=site, rows=models, checked_at=now)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w02_site_runs).where(adoption_w02_site_runs.c.site == site).limit(1)
            ).mappings().first()
        return _row_to_w02_completion_model(site=site, readiness=readiness, row=row)
    
    
    @router.post("/w02/tracker/complete", response_model=W02TrackerCompletionRead)
    def complete_w02_tracker(
        payload: W02TrackerCompletionRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w02:write")),
    ) -> W02TrackerCompletionRead:
        _require_site_access(principal, payload.site)
        if payload.force and not _has_permission(principal, "admins:manage"):
            raise HTTPException(status_code=403, detail="force completion requires admins:manage")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        models = _load_w02_tracker_items_for_site(payload.site)
        readiness = _compute_w02_tracker_readiness(site=payload.site, rows=models, checked_at=now)
        if not readiness.ready and not payload.force:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "W02 completion gate failed",
                    "site": payload.site,
                    "ready": readiness.ready,
                    "blockers": readiness.blockers,
                    "readiness": readiness.model_dump(mode="json"),
                },
            )
    
        completion_note = (payload.completion_note or "").strip()
        next_status = (
            W02_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS
            if payload.force and not readiness.ready
            else W02_SITE_COMPLETION_STATUS_COMPLETED
        )
        with get_conn() as conn:
            existing = conn.execute(
                select(adoption_w02_site_runs).where(adoption_w02_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
            if existing is None:
                conn.execute(
                    insert(adoption_w02_site_runs).values(
                        site=payload.site,
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                conn.execute(
                    update(adoption_w02_site_runs)
                    .where(adoption_w02_site_runs.c.site == payload.site)
                    .values(
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        updated_by=actor_username,
                        updated_at=now,
                    )
                )
            row = conn.execute(
                select(adoption_w02_site_runs).where(adoption_w02_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
    
        model = _row_to_w02_completion_model(site=payload.site, readiness=readiness, row=row)
        _write_audit_log(
            principal=principal,
            action="w02_tracker_complete",
            resource_type="adoption_w02_tracker_site",
            resource_id=payload.site,
            detail={
                "site": payload.site,
                "status": model.status,
                "ready": readiness.ready,
                "force_used": model.force_used,
                "blockers": readiness.blockers,
                "completion_rate_percent": readiness.completion_rate_percent,
                "missing_required_evidence_count": readiness.missing_required_evidence_count,
            },
        )
        return model
    
    
    @router.patch("/w02/tracker/items/{tracker_item_id}", response_model=W02TrackerItemRead)
    def update_w02_tracker_item(
        tracker_item_id: int,
        payload: W02TrackerItemUpdate,
        principal: dict[str, Any] = Depends(require_permission("adoption_w02:write")),
    ) -> W02TrackerItemRead:
        has_update = (
            payload.assignee is not None
            or payload.status is not None
            or payload.completion_checked is not None
            or payload.completion_note is not None
        )
        if not has_update:
            raise HTTPException(status_code=400, detail="No update fields provided")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w02_tracker_items).where(adoption_w02_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if row is None:
                raise HTTPException(status_code=404, detail="W02 tracker item not found")
            _require_site_access(principal, str(row["site"]))
    
            next_assignee = row.get("assignee")
            if payload.assignee is not None:
                normalized_assignee = payload.assignee.strip()
                next_assignee = normalized_assignee or None
    
            next_status = str(row["status"])
            if payload.status is not None:
                next_status = str(payload.status)
    
            next_checked = bool(row.get("completion_checked", False))
            if payload.completion_checked is not None:
                next_checked = bool(payload.completion_checked)
    
            if next_status == W02_TRACKER_STATUS_DONE:
                next_checked = True
            elif payload.status is not None and payload.status != W02_TRACKER_STATUS_DONE and payload.completion_checked is None:
                next_checked = False
            if payload.completion_checked is True:
                next_status = W02_TRACKER_STATUS_DONE
            elif payload.completion_checked is False and next_status == W02_TRACKER_STATUS_DONE:
                next_status = W02_TRACKER_STATUS_IN_PROGRESS
    
            if next_status not in W02_TRACKER_STATUS_SET:
                raise HTTPException(status_code=400, detail="Invalid W02 tracker status")
    
            next_note = str(row.get("completion_note") or "")
            if payload.completion_note is not None:
                next_note = payload.completion_note.strip()
    
            existing_completed_at = _as_optional_datetime(row.get("completed_at"))
            next_completed_at = existing_completed_at
            if next_checked:
                if existing_completed_at is None:
                    next_completed_at = now
            else:
                next_completed_at = None
    
            conn.execute(
                update(adoption_w02_tracker_items)
                .where(adoption_w02_tracker_items.c.id == tracker_item_id)
                .values(
                    assignee=next_assignee,
                    status=next_status,
                    completion_checked=next_checked,
                    completion_note=next_note,
                    completed_at=next_completed_at,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w02_completion_if_closed(
                conn=conn,
                site=str(row["site"]),
                actor_username=actor_username,
                checked_at=now,
                reason="tracker_item_updated",
            )
            updated = conn.execute(
                select(adoption_w02_tracker_items).where(adoption_w02_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
    
        if updated is None:
            raise HTTPException(status_code=500, detail="Failed to update W02 tracker item")
        model = _row_to_w02_tracker_item_model(updated)
        _write_audit_log(
            principal=principal,
            action="w02_tracker_item_update",
            resource_type="adoption_w02_tracker_item",
            resource_id=str(model.id),
            detail={
                "site": model.site,
                "status": model.status,
                "assignee": model.assignee,
                "completion_checked": model.completion_checked,
            },
        )
        return model
    
    
    @router.post("/w02/tracker/items/{tracker_item_id}/evidence", response_model=W02EvidenceRead, status_code=201)
    async def upload_w02_tracker_evidence(
        tracker_item_id: int,
        file: UploadFile = File(...),
        note: str = Form(default=""),
        principal: dict[str, Any] = Depends(require_permission("adoption_w02:write")),
    ) -> W02EvidenceRead:
        file_name = _safe_download_filename(file.filename or "", fallback="evidence.bin", max_length=120)
        content_type = (file.content_type or "application/octet-stream").strip() or "application/octet-stream"
        content_type = content_type[:120].lower()
        if not _is_allowed_evidence_content_type(content_type):
            raise HTTPException(
                status_code=415,
                detail="Unsupported evidence content type",
            )
        file_bytes = await file.read(W02_EVIDENCE_MAX_BYTES + 1)
        await file.close()
        if len(file_bytes) == 0:
            raise HTTPException(status_code=400, detail="Empty evidence file is not allowed")
        if len(file_bytes) > W02_EVIDENCE_MAX_BYTES:
            raise HTTPException(status_code=413, detail=f"Evidence file too large (max {W02_EVIDENCE_MAX_BYTES} bytes)")
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
            tracker_row = conn.execute(
                select(adoption_w02_tracker_items).where(adoption_w02_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W02 tracker item not found")
            site = str(tracker_row["site"])
            _require_site_access(principal, site)
    
            result = conn.execute(
                insert(adoption_w02_evidence_files).values(
                    tracker_item_id=tracker_item_id,
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
            next_count = int(tracker_row.get("evidence_count") or 0) + 1
            conn.execute(
                update(adoption_w02_tracker_items)
                .where(adoption_w02_tracker_items.c.id == tracker_item_id)
                .values(
                    evidence_count=next_count,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            evidence_row = conn.execute(
                select(adoption_w02_evidence_files).where(adoption_w02_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
    
        if evidence_row is None:
            raise HTTPException(status_code=500, detail="Failed to save evidence file")
        model = _row_to_w02_evidence_model(evidence_row)
        _write_audit_log(
            principal=principal,
            action="w02_tracker_evidence_upload",
            resource_type="adoption_w02_evidence",
            resource_id=str(model.id),
            detail={
                "tracker_item_id": model.tracker_item_id,
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
    
    
    @router.get("/w02/tracker/items/{tracker_item_id}/evidence", response_model=list[W02EvidenceRead])
    def list_w02_tracker_evidence(
        tracker_item_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w02:read")),
    ) -> list[W02EvidenceRead]:
        with get_conn() as conn:
            tracker_row = conn.execute(
                select(adoption_w02_tracker_items).where(adoption_w02_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W02 tracker item not found")
            _require_site_access(principal, str(tracker_row["site"]))
    
            rows = conn.execute(
                select(adoption_w02_evidence_files)
                .where(adoption_w02_evidence_files.c.tracker_item_id == tracker_item_id)
                .order_by(adoption_w02_evidence_files.c.uploaded_at.desc(), adoption_w02_evidence_files.c.id.desc())
            ).mappings().all()
        return [_row_to_w02_evidence_model(row) for row in rows]
    
    
    @router.get("/w02/tracker/evidence/{evidence_id}/download", response_model=None)
    def download_w02_tracker_evidence(
        evidence_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w02:read")),
    ) -> Response:
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w02_evidence_files).where(adoption_w02_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="W02 evidence not found")
    
        site = str(row["site"])
        _require_site_access(principal, site)
        content_type = str(row.get("content_type") or "application/octet-stream")
        file_name = _safe_download_filename(str(row.get("file_name") or ""), fallback="evidence.bin", max_length=120)
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
            action="w02_tracker_evidence_download",
            resource_type="adoption_w02_evidence",
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
    
    
    @router.post("/w03/tracker/bootstrap", response_model=W03TrackerBootstrapResponse)
    def bootstrap_w03_tracker_items(
        payload: W03TrackerBootstrapRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w03:write")),
    ) -> W03TrackerBootstrapResponse:
        _require_site_access(principal, payload.site)
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        catalog = _adoption_w03_catalog_items(payload.site)
        created_count = 0
    
        with get_conn() as conn:
            existing_rows = conn.execute(
                select(
                    adoption_w03_tracker_items.c.item_type,
                    adoption_w03_tracker_items.c.item_key,
                ).where(adoption_w03_tracker_items.c.site == payload.site)
            ).mappings().all()
            existing_keys = {(str(row["item_type"]), str(row["item_key"])) for row in existing_rows}
    
            for entry in catalog:
                key = (str(entry["item_type"]), str(entry["item_key"]))
                if key in existing_keys:
                    continue
                conn.execute(
                    insert(adoption_w03_tracker_items).values(
                        site=payload.site,
                        item_type=str(entry["item_type"]),
                        item_key=str(entry["item_key"]),
                        item_name=str(entry["item_name"]),
                        assignee=None,
                        status=W03_TRACKER_STATUS_PENDING,
                        completion_checked=False,
                        completion_note="",
                        due_at=entry.get("due_at"),
                        completed_at=None,
                        evidence_count=0,
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
                existing_keys.add(key)
                created_count += 1
    
            if created_count > 0:
                _reset_w03_completion_if_closed(
                    conn=conn,
                    site=payload.site,
                    actor_username=actor_username,
                    checked_at=now,
                    reason="bootstrap_added_items",
                )
    
            rows = conn.execute(
                select(adoption_w03_tracker_items)
                .where(adoption_w03_tracker_items.c.site == payload.site)
                .order_by(
                    adoption_w03_tracker_items.c.item_type.asc(),
                    adoption_w03_tracker_items.c.item_key.asc(),
                    adoption_w03_tracker_items.c.id.asc(),
                )
            ).mappings().all()
    
        items = [_row_to_w03_tracker_item_model(row) for row in rows]
        _write_audit_log(
            principal=principal,
            action="w03_tracker_bootstrap",
            resource_type="adoption_w03_tracker",
            resource_id=payload.site,
            detail={"site": payload.site, "created_count": created_count, "total_count": len(items)},
        )
        return W03TrackerBootstrapResponse(
            site=payload.site,
            created_count=created_count,
            total_count=len(items),
            items=items,
        )
    
    
    @router.get("/w03/tracker/items", response_model=list[W03TrackerItemRead])
    def list_w03_tracker_items(
        site: Annotated[str | None, Query()] = None,
        status: Annotated[str | None, Query()] = None,
        item_type: Annotated[str | None, Query()] = None,
        assignee: Annotated[str | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
        offset: Annotated[int, Query(ge=0)] = 0,
        principal: dict[str, Any] = Depends(require_permission("adoption_w03:read")),
    ) -> list[W03TrackerItemRead]:
        _require_site_access(principal, site)
        normalized_status = status.strip().lower() if status is not None else None
        if normalized_status is not None and normalized_status not in W03_TRACKER_STATUS_SET:
            raise HTTPException(status_code=400, detail="Invalid W03 tracker status")
    
        stmt = select(adoption_w03_tracker_items)
        if site is not None:
            stmt = stmt.where(adoption_w03_tracker_items.c.site == site)
        else:
            allowed_sites = _allowed_sites_for_principal(principal)
            if allowed_sites is not None:
                if not allowed_sites:
                    return []
                stmt = stmt.where(adoption_w03_tracker_items.c.site.in_(allowed_sites))
    
        if normalized_status is not None:
            stmt = stmt.where(adoption_w03_tracker_items.c.status == normalized_status)
        if item_type is not None:
            stmt = stmt.where(adoption_w03_tracker_items.c.item_type == item_type.strip())
        if assignee is not None:
            stmt = stmt.where(adoption_w03_tracker_items.c.assignee == assignee.strip())
    
        stmt = stmt.order_by(
            adoption_w03_tracker_items.c.updated_at.desc(),
            adoption_w03_tracker_items.c.id.desc(),
        ).limit(limit).offset(offset)
    
        with get_conn() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [_row_to_w03_tracker_item_model(row) for row in rows]
    
    
    @router.get("/w03/tracker/overview", response_model=W03TrackerOverviewRead)
    def get_w03_tracker_overview(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w03:read")),
    ) -> W03TrackerOverviewRead:
        _require_site_access(principal, site)
        with get_conn() as conn:
            rows = conn.execute(
                select(adoption_w03_tracker_items).where(adoption_w03_tracker_items.c.site == site)
            ).mappings().all()
        models = [_row_to_w03_tracker_item_model(row) for row in rows]
        return _compute_w03_tracker_overview(site, models)
    
    
    @router.get("/w03/tracker/readiness", response_model=W03TrackerReadinessRead)
    def get_w03_tracker_readiness(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w03:read")),
    ) -> W03TrackerReadinessRead:
        _require_site_access(principal, site)
        models = _load_w03_tracker_items_for_site(site)
        return _compute_w03_tracker_readiness(site=site, rows=models)
    
    
    @router.get("/w03/tracker/completion", response_model=W03TrackerCompletionRead)
    def get_w03_tracker_completion(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w03:read")),
    ) -> W03TrackerCompletionRead:
        _require_site_access(principal, site)
        now = datetime.now(timezone.utc)
        models = _load_w03_tracker_items_for_site(site)
        readiness = _compute_w03_tracker_readiness(site=site, rows=models, checked_at=now)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w03_site_runs).where(adoption_w03_site_runs.c.site == site).limit(1)
            ).mappings().first()
        return _row_to_w03_completion_model(site=site, readiness=readiness, row=row)
    
    
    @router.post("/w03/tracker/complete", response_model=W03TrackerCompletionRead)
    def complete_w03_tracker(
        payload: W03TrackerCompletionRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w03:write")),
    ) -> W03TrackerCompletionRead:
        _require_site_access(principal, payload.site)
        if payload.force and not _has_permission(principal, "admins:manage"):
            raise HTTPException(status_code=403, detail="force completion requires admins:manage")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        models = _load_w03_tracker_items_for_site(payload.site)
        readiness = _compute_w03_tracker_readiness(site=payload.site, rows=models, checked_at=now)
        if not readiness.ready and not payload.force:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "W03 completion gate failed",
                    "site": payload.site,
                    "ready": readiness.ready,
                    "blockers": readiness.blockers,
                    "readiness": readiness.model_dump(mode="json"),
                },
            )
    
        completion_note = (payload.completion_note or "").strip()
        next_status = (
            W03_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS
            if payload.force and not readiness.ready
            else W03_SITE_COMPLETION_STATUS_COMPLETED
        )
        with get_conn() as conn:
            existing = conn.execute(
                select(adoption_w03_site_runs).where(adoption_w03_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
            if existing is None:
                conn.execute(
                    insert(adoption_w03_site_runs).values(
                        site=payload.site,
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                conn.execute(
                    update(adoption_w03_site_runs)
                    .where(adoption_w03_site_runs.c.site == payload.site)
                    .values(
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        updated_by=actor_username,
                        updated_at=now,
                    )
                )
            row = conn.execute(
                select(adoption_w03_site_runs).where(adoption_w03_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
    
        model = _row_to_w03_completion_model(site=payload.site, readiness=readiness, row=row)
        _write_audit_log(
            principal=principal,
            action="w03_tracker_complete",
            resource_type="adoption_w03_tracker_site",
            resource_id=payload.site,
            detail={
                "site": payload.site,
                "status": model.status,
                "ready": readiness.ready,
                "force_used": model.force_used,
                "blockers": readiness.blockers,
                "completion_rate_percent": readiness.completion_rate_percent,
                "missing_required_evidence_count": readiness.missing_required_evidence_count,
            },
        )
        return model
    
    
    @router.patch("/w03/tracker/items/{tracker_item_id}", response_model=W03TrackerItemRead)
    def update_w03_tracker_item(
        tracker_item_id: int,
        payload: W03TrackerItemUpdate,
        principal: dict[str, Any] = Depends(require_permission("adoption_w03:write")),
    ) -> W03TrackerItemRead:
        has_update = (
            payload.assignee is not None
            or payload.status is not None
            or payload.completion_checked is not None
            or payload.completion_note is not None
        )
        if not has_update:
            raise HTTPException(status_code=400, detail="No update fields provided")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w03_tracker_items).where(adoption_w03_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if row is None:
                raise HTTPException(status_code=404, detail="W03 tracker item not found")
            _require_site_access(principal, str(row["site"]))
    
            next_assignee = row.get("assignee")
            if payload.assignee is not None:
                normalized_assignee = payload.assignee.strip()
                next_assignee = normalized_assignee or None
    
            next_status = str(row["status"])
            if payload.status is not None:
                next_status = str(payload.status)
    
            next_checked = bool(row.get("completion_checked", False))
            if payload.completion_checked is not None:
                next_checked = bool(payload.completion_checked)
    
            if next_status == W03_TRACKER_STATUS_DONE:
                next_checked = True
            elif payload.status is not None and payload.status != W03_TRACKER_STATUS_DONE and payload.completion_checked is None:
                next_checked = False
            if payload.completion_checked is True:
                next_status = W03_TRACKER_STATUS_DONE
            elif payload.completion_checked is False and next_status == W03_TRACKER_STATUS_DONE:
                next_status = W03_TRACKER_STATUS_IN_PROGRESS
    
            if next_status not in W03_TRACKER_STATUS_SET:
                raise HTTPException(status_code=400, detail="Invalid W03 tracker status")
    
            next_note = str(row.get("completion_note") or "")
            if payload.completion_note is not None:
                next_note = payload.completion_note.strip()
    
            existing_completed_at = _as_optional_datetime(row.get("completed_at"))
            next_completed_at = existing_completed_at
            if next_checked:
                if existing_completed_at is None:
                    next_completed_at = now
            else:
                next_completed_at = None
    
            conn.execute(
                update(adoption_w03_tracker_items)
                .where(adoption_w03_tracker_items.c.id == tracker_item_id)
                .values(
                    assignee=next_assignee,
                    status=next_status,
                    completion_checked=next_checked,
                    completion_note=next_note,
                    completed_at=next_completed_at,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w03_completion_if_closed(
                conn=conn,
                site=str(row["site"]),
                actor_username=actor_username,
                checked_at=now,
                reason="tracker_item_updated",
            )
            updated = conn.execute(
                select(adoption_w03_tracker_items).where(adoption_w03_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
        if updated is None:
            raise HTTPException(status_code=500, detail="Failed to update W03 tracker item")
        model = _row_to_w03_tracker_item_model(updated)
        _write_audit_log(
            principal=principal,
            action="w03_tracker_item_update",
            resource_type="adoption_w03_tracker_item",
            resource_id=str(model.id),
            detail={
                "site": model.site,
                "status": model.status,
                "assignee": model.assignee,
                "completion_checked": model.completion_checked,
            },
        )
        return model
    
    
    @router.post("/w03/tracker/items/{tracker_item_id}/evidence", response_model=W03EvidenceRead, status_code=201)
    async def upload_w03_tracker_evidence(
        tracker_item_id: int,
        file: UploadFile = File(...),
        note: str = Form(default=""),
        principal: dict[str, Any] = Depends(require_permission("adoption_w03:write")),
    ) -> W03EvidenceRead:
        file_name = _safe_download_filename(file.filename or "", fallback="evidence.bin", max_length=120)
        content_type = (file.content_type or "application/octet-stream").strip() or "application/octet-stream"
        content_type = content_type[:120].lower()
        if not _is_allowed_evidence_content_type(content_type):
            raise HTTPException(
                status_code=415,
                detail="Unsupported evidence content type",
            )
        file_bytes = await file.read(W03_EVIDENCE_MAX_BYTES + 1)
        await file.close()
        if len(file_bytes) == 0:
            raise HTTPException(status_code=400, detail="Empty evidence file is not allowed")
        if len(file_bytes) > W03_EVIDENCE_MAX_BYTES:
            raise HTTPException(status_code=413, detail=f"Evidence file too large (max {W03_EVIDENCE_MAX_BYTES} bytes)")
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
            tracker_row = conn.execute(
                select(adoption_w03_tracker_items).where(adoption_w03_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W03 tracker item not found")
            site = str(tracker_row["site"])
            _require_site_access(principal, site)
    
            result = conn.execute(
                insert(adoption_w03_evidence_files).values(
                    tracker_item_id=tracker_item_id,
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
            next_count = int(tracker_row.get("evidence_count") or 0) + 1
            conn.execute(
                update(adoption_w03_tracker_items)
                .where(adoption_w03_tracker_items.c.id == tracker_item_id)
                .values(
                    evidence_count=next_count,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            evidence_row = conn.execute(
                select(adoption_w03_evidence_files).where(adoption_w03_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
    
        if evidence_row is None:
            raise HTTPException(status_code=500, detail="Failed to save evidence file")
        model = _row_to_w03_evidence_model(evidence_row)
        _write_audit_log(
            principal=principal,
            action="w03_tracker_evidence_upload",
            resource_type="adoption_w03_evidence",
            resource_id=str(model.id),
            detail={
                "tracker_item_id": model.tracker_item_id,
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
    
    
    @router.get("/w03/tracker/items/{tracker_item_id}/evidence", response_model=list[W03EvidenceRead])
    def list_w03_tracker_evidence(
        tracker_item_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w03:read")),
    ) -> list[W03EvidenceRead]:
        with get_conn() as conn:
            tracker_row = conn.execute(
                select(adoption_w03_tracker_items).where(adoption_w03_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W03 tracker item not found")
            _require_site_access(principal, str(tracker_row["site"]))
    
            rows = conn.execute(
                select(adoption_w03_evidence_files)
                .where(adoption_w03_evidence_files.c.tracker_item_id == tracker_item_id)
                .order_by(adoption_w03_evidence_files.c.uploaded_at.desc(), adoption_w03_evidence_files.c.id.desc())
            ).mappings().all()
        return [_row_to_w03_evidence_model(row) for row in rows]
    
    
    @router.get("/w03/tracker/evidence/{evidence_id}/download", response_model=None)
    def download_w03_tracker_evidence(
        evidence_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w03:read")),
    ) -> Response:
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w03_evidence_files).where(adoption_w03_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="W03 evidence not found")
    
        site = str(row["site"])
        _require_site_access(principal, site)
        content_type = str(row.get("content_type") or "application/octet-stream")
        file_name = _safe_download_filename(str(row.get("file_name") or ""), fallback="evidence.bin", max_length=120)
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
            action="w03_tracker_evidence_download",
            resource_type="adoption_w03_evidence",
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
    
    
    @router.post("/w04/tracker/bootstrap", response_model=W04TrackerBootstrapResponse)
    def bootstrap_w04_tracker_items(
        payload: W04TrackerBootstrapRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w04:write")),
    ) -> W04TrackerBootstrapResponse:
        _require_site_access(principal, payload.site)
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        catalog = _adoption_w04_catalog_items(payload.site)
        created_count = 0
    
        with get_conn() as conn:
            existing_rows = conn.execute(
                select(
                    adoption_w04_tracker_items.c.item_type,
                    adoption_w04_tracker_items.c.item_key,
                ).where(adoption_w04_tracker_items.c.site == payload.site)
            ).mappings().all()
            existing_keys = {(str(row["item_type"]), str(row["item_key"])) for row in existing_rows}
    
            for entry in catalog:
                key = (str(entry["item_type"]), str(entry["item_key"]))
                if key in existing_keys:
                    continue
                conn.execute(
                    insert(adoption_w04_tracker_items).values(
                        site=payload.site,
                        item_type=str(entry["item_type"]),
                        item_key=str(entry["item_key"]),
                        item_name=str(entry["item_name"]),
                        assignee=None,
                        status=W04_TRACKER_STATUS_PENDING,
                        completion_checked=False,
                        completion_note="",
                        due_at=entry.get("due_at"),
                        completed_at=None,
                        evidence_count=0,
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
                existing_keys.add(key)
                created_count += 1
    
            if created_count > 0:
                _reset_w04_completion_if_closed(
                    conn=conn,
                    site=payload.site,
                    actor_username=actor_username,
                    checked_at=now,
                    reason="bootstrap_added_items",
                )
    
            rows = conn.execute(
                select(adoption_w04_tracker_items)
                .where(adoption_w04_tracker_items.c.site == payload.site)
                .order_by(
                    adoption_w04_tracker_items.c.item_type.asc(),
                    adoption_w04_tracker_items.c.item_key.asc(),
                    adoption_w04_tracker_items.c.id.asc(),
                )
            ).mappings().all()
    
        items = [_row_to_w04_tracker_item_model(row) for row in rows]
        _write_audit_log(
            principal=principal,
            action="w04_tracker_bootstrap",
            resource_type="adoption_w04_tracker",
            resource_id=payload.site,
            detail={"site": payload.site, "created_count": created_count, "total_count": len(items)},
        )
        return W04TrackerBootstrapResponse(
            site=payload.site,
            created_count=created_count,
            total_count=len(items),
            items=items,
        )
    
    
    @router.get("/w04/tracker/items", response_model=list[W04TrackerItemRead])
    def list_w04_tracker_items(
        site: Annotated[str | None, Query()] = None,
        status: Annotated[str | None, Query()] = None,
        item_type: Annotated[str | None, Query()] = None,
        assignee: Annotated[str | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
        offset: Annotated[int, Query(ge=0)] = 0,
        principal: dict[str, Any] = Depends(require_permission("adoption_w04:read")),
    ) -> list[W04TrackerItemRead]:
        _require_site_access(principal, site)
        normalized_status = status.strip().lower() if status is not None else None
        if normalized_status is not None and normalized_status not in W04_TRACKER_STATUS_SET:
            raise HTTPException(status_code=400, detail="Invalid W04 tracker status")
    
        stmt = select(adoption_w04_tracker_items)
        if site is not None:
            stmt = stmt.where(adoption_w04_tracker_items.c.site == site)
        else:
            allowed_sites = _allowed_sites_for_principal(principal)
            if allowed_sites is not None:
                if not allowed_sites:
                    return []
                stmt = stmt.where(adoption_w04_tracker_items.c.site.in_(allowed_sites))
    
        if normalized_status is not None:
            stmt = stmt.where(adoption_w04_tracker_items.c.status == normalized_status)
        if item_type is not None:
            stmt = stmt.where(adoption_w04_tracker_items.c.item_type == item_type.strip())
        if assignee is not None:
            stmt = stmt.where(adoption_w04_tracker_items.c.assignee == assignee.strip())
    
        stmt = stmt.order_by(
            adoption_w04_tracker_items.c.updated_at.desc(),
            adoption_w04_tracker_items.c.id.desc(),
        ).limit(limit).offset(offset)
    
        with get_conn() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [_row_to_w04_tracker_item_model(row) for row in rows]
    
    
    @router.get("/w04/tracker/overview", response_model=W04TrackerOverviewRead)
    def get_w04_tracker_overview(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w04:read")),
    ) -> W04TrackerOverviewRead:
        _require_site_access(principal, site)
        with get_conn() as conn:
            rows = conn.execute(
                select(adoption_w04_tracker_items).where(adoption_w04_tracker_items.c.site == site)
            ).mappings().all()
        models = [_row_to_w04_tracker_item_model(row) for row in rows]
        return _compute_w04_tracker_overview(site, models)
    
    
    @router.get("/w04/tracker/readiness", response_model=W04TrackerReadinessRead)
    def get_w04_tracker_readiness(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w04:read")),
    ) -> W04TrackerReadinessRead:
        _require_site_access(principal, site)
        models = _load_w04_tracker_items_for_site(site)
        return _compute_w04_tracker_readiness(site=site, rows=models)
    
    
    @router.get("/w04/tracker/completion", response_model=W04TrackerCompletionRead)
    def get_w04_tracker_completion(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w04:read")),
    ) -> W04TrackerCompletionRead:
        _require_site_access(principal, site)
        now = datetime.now(timezone.utc)
        models = _load_w04_tracker_items_for_site(site)
        readiness = _compute_w04_tracker_readiness(site=site, rows=models, checked_at=now)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w04_site_runs).where(adoption_w04_site_runs.c.site == site).limit(1)
            ).mappings().first()
        return _row_to_w04_completion_model(site=site, readiness=readiness, row=row)
    
    
    @router.post("/w04/tracker/complete", response_model=W04TrackerCompletionRead)
    def complete_w04_tracker(
        payload: W04TrackerCompletionRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w04:write")),
    ) -> W04TrackerCompletionRead:
        _require_site_access(principal, payload.site)
        if payload.force and not _has_permission(principal, "admins:manage"):
            raise HTTPException(status_code=403, detail="force completion requires admins:manage")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        models = _load_w04_tracker_items_for_site(payload.site)
        readiness = _compute_w04_tracker_readiness(site=payload.site, rows=models, checked_at=now)
        if not readiness.ready and not payload.force:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "W04 completion gate failed",
                    "site": payload.site,
                    "ready": readiness.ready,
                    "blockers": readiness.blockers,
                    "readiness": readiness.model_dump(mode="json"),
                },
            )
    
        completion_note = (payload.completion_note or "").strip()
        next_status = (
            W04_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS
            if payload.force and not readiness.ready
            else W04_SITE_COMPLETION_STATUS_COMPLETED
        )
        with get_conn() as conn:
            existing = conn.execute(
                select(adoption_w04_site_runs).where(adoption_w04_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
            if existing is None:
                conn.execute(
                    insert(adoption_w04_site_runs).values(
                        site=payload.site,
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                conn.execute(
                    update(adoption_w04_site_runs)
                    .where(adoption_w04_site_runs.c.site == payload.site)
                    .values(
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        updated_by=actor_username,
                        updated_at=now,
                    )
                )
            row = conn.execute(
                select(adoption_w04_site_runs).where(adoption_w04_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
    
        model = _row_to_w04_completion_model(site=payload.site, readiness=readiness, row=row)
        _write_audit_log(
            principal=principal,
            action="w04_tracker_complete",
            resource_type="adoption_w04_tracker_site",
            resource_id=payload.site,
            detail={
                "site": payload.site,
                "status": model.status,
                "ready": readiness.ready,
                "force_used": model.force_used,
                "blockers": readiness.blockers,
                "completion_rate_percent": readiness.completion_rate_percent,
                "missing_required_evidence_count": readiness.missing_required_evidence_count,
            },
        )
        return model
    
    
    @router.patch("/w04/tracker/items/{tracker_item_id}", response_model=W04TrackerItemRead)
    def update_w04_tracker_item(
        tracker_item_id: int,
        payload: W04TrackerItemUpdate,
        principal: dict[str, Any] = Depends(require_permission("adoption_w04:write")),
    ) -> W04TrackerItemRead:
        has_update = (
            payload.assignee is not None
            or payload.status is not None
            or payload.completion_checked is not None
            or payload.completion_note is not None
        )
        if not has_update:
            raise HTTPException(status_code=400, detail="No update fields provided")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w04_tracker_items).where(adoption_w04_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if row is None:
                raise HTTPException(status_code=404, detail="W04 tracker item not found")
            _require_site_access(principal, str(row["site"]))
    
            next_assignee = row.get("assignee")
            if payload.assignee is not None:
                normalized_assignee = payload.assignee.strip()
                next_assignee = normalized_assignee or None
    
            next_status = str(row["status"])
            if payload.status is not None:
                next_status = str(payload.status)
    
            next_checked = bool(row.get("completion_checked", False))
            if payload.completion_checked is not None:
                next_checked = bool(payload.completion_checked)
    
            if next_status == W04_TRACKER_STATUS_DONE:
                next_checked = True
            elif payload.status is not None and payload.status != W04_TRACKER_STATUS_DONE and payload.completion_checked is None:
                next_checked = False
            if payload.completion_checked is True:
                next_status = W04_TRACKER_STATUS_DONE
            elif payload.completion_checked is False and next_status == W04_TRACKER_STATUS_DONE:
                next_status = W04_TRACKER_STATUS_IN_PROGRESS
    
            if next_status not in W04_TRACKER_STATUS_SET:
                raise HTTPException(status_code=400, detail="Invalid W04 tracker status")
    
            next_note = str(row.get("completion_note") or "")
            if payload.completion_note is not None:
                next_note = payload.completion_note.strip()
    
            existing_completed_at = _as_optional_datetime(row.get("completed_at"))
            next_completed_at = existing_completed_at
            if next_checked:
                if existing_completed_at is None:
                    next_completed_at = now
            else:
                next_completed_at = None
    
            conn.execute(
                update(adoption_w04_tracker_items)
                .where(adoption_w04_tracker_items.c.id == tracker_item_id)
                .values(
                    assignee=next_assignee,
                    status=next_status,
                    completion_checked=next_checked,
                    completion_note=next_note,
                    completed_at=next_completed_at,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w04_completion_if_closed(
                conn=conn,
                site=str(row["site"]),
                actor_username=actor_username,
                checked_at=now,
                reason="tracker_item_updated",
            )
            updated = conn.execute(
                select(adoption_w04_tracker_items).where(adoption_w04_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
        if updated is None:
            raise HTTPException(status_code=500, detail="Failed to update W04 tracker item")
        model = _row_to_w04_tracker_item_model(updated)
        _write_audit_log(
            principal=principal,
            action="w04_tracker_item_update",
            resource_type="adoption_w04_tracker_item",
            resource_id=str(model.id),
            detail={
                "site": model.site,
                "status": model.status,
                "assignee": model.assignee,
                "completion_checked": model.completion_checked,
            },
        )
        return model
    
    
    @router.post("/w04/tracker/items/{tracker_item_id}/evidence", response_model=W04EvidenceRead, status_code=201)
    async def upload_w04_tracker_evidence(
        tracker_item_id: int,
        file: UploadFile = File(...),
        note: str = Form(default=""),
        principal: dict[str, Any] = Depends(require_permission("adoption_w04:write")),
    ) -> W04EvidenceRead:
        file_name = _safe_download_filename(file.filename or "", fallback="evidence.bin", max_length=120)
        content_type = (file.content_type or "application/octet-stream").strip() or "application/octet-stream"
        content_type = content_type[:120].lower()
        if not _is_allowed_evidence_content_type(content_type):
            raise HTTPException(
                status_code=415,
                detail="Unsupported evidence content type",
            )
        file_bytes = await file.read(W04_EVIDENCE_MAX_BYTES + 1)
        await file.close()
        if len(file_bytes) == 0:
            raise HTTPException(status_code=400, detail="Empty evidence file is not allowed")
        if len(file_bytes) > W04_EVIDENCE_MAX_BYTES:
            raise HTTPException(status_code=413, detail=f"Evidence file too large (max {W04_EVIDENCE_MAX_BYTES} bytes)")
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
            tracker_row = conn.execute(
                select(adoption_w04_tracker_items).where(adoption_w04_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W04 tracker item not found")
            site = str(tracker_row["site"])
            _require_site_access(principal, site)
    
            result = conn.execute(
                insert(adoption_w04_evidence_files).values(
                    tracker_item_id=tracker_item_id,
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
            next_count = int(tracker_row.get("evidence_count") or 0) + 1
            conn.execute(
                update(adoption_w04_tracker_items)
                .where(adoption_w04_tracker_items.c.id == tracker_item_id)
                .values(
                    evidence_count=next_count,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            evidence_row = conn.execute(
                select(adoption_w04_evidence_files).where(adoption_w04_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
    
        if evidence_row is None:
            raise HTTPException(status_code=500, detail="Failed to save evidence file")
        model = _row_to_w04_evidence_model(evidence_row)
        _write_audit_log(
            principal=principal,
            action="w04_tracker_evidence_upload",
            resource_type="adoption_w04_evidence",
            resource_id=str(model.id),
            detail={
                "tracker_item_id": model.tracker_item_id,
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
    
    
    @router.get("/w04/tracker/items/{tracker_item_id}/evidence", response_model=list[W04EvidenceRead])
    def list_w04_tracker_evidence(
        tracker_item_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w04:read")),
    ) -> list[W04EvidenceRead]:
        with get_conn() as conn:
            tracker_row = conn.execute(
                select(adoption_w04_tracker_items).where(adoption_w04_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W04 tracker item not found")
            _require_site_access(principal, str(tracker_row["site"]))
    
            rows = conn.execute(
                select(adoption_w04_evidence_files)
                .where(adoption_w04_evidence_files.c.tracker_item_id == tracker_item_id)
                .order_by(adoption_w04_evidence_files.c.uploaded_at.desc(), adoption_w04_evidence_files.c.id.desc())
            ).mappings().all()
        return [_row_to_w04_evidence_model(row) for row in rows]
    
    
    @router.get("/w04/tracker/evidence/{evidence_id}/download", response_model=None)
    def download_w04_tracker_evidence(
        evidence_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w04:read")),
    ) -> Response:
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w04_evidence_files).where(adoption_w04_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="W04 evidence not found")
    
        site = str(row["site"])
        _require_site_access(principal, site)
        content_type = str(row.get("content_type") or "application/octet-stream")
        file_name = _safe_download_filename(str(row.get("file_name") or ""), fallback="evidence.bin", max_length=120)
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
            action="w04_tracker_evidence_download",
            resource_type="adoption_w04_evidence",
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
    
    
    @router.post("/w07/tracker/bootstrap", response_model=W07TrackerBootstrapResponse)
    def bootstrap_w07_tracker_items(
        payload: W07TrackerBootstrapRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:write")),
    ) -> W07TrackerBootstrapResponse:
        _require_site_access(principal, payload.site)
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        catalog = _adoption_w07_catalog_items(payload.site)
        created_count = 0
    
        with get_conn() as conn:
            existing_rows = conn.execute(
                select(
                    adoption_w07_tracker_items.c.item_type,
                    adoption_w07_tracker_items.c.item_key,
                ).where(adoption_w07_tracker_items.c.site == payload.site)
            ).mappings().all()
            existing_keys = {(str(row["item_type"]), str(row["item_key"])) for row in existing_rows}
    
            for entry in catalog:
                key = (str(entry["item_type"]), str(entry["item_key"]))
                if key in existing_keys:
                    continue
                conn.execute(
                    insert(adoption_w07_tracker_items).values(
                        site=payload.site,
                        item_type=str(entry["item_type"]),
                        item_key=str(entry["item_key"]),
                        item_name=str(entry["item_name"]),
                        assignee=None,
                        status=W07_TRACKER_STATUS_PENDING,
                        completion_checked=False,
                        completion_note="",
                        due_at=entry.get("due_at"),
                        completed_at=None,
                        evidence_count=0,
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
                existing_keys.add(key)
                created_count += 1
    
            if created_count > 0:
                _reset_w07_completion_if_closed(
                    conn=conn,
                    site=payload.site,
                    actor_username=actor_username,
                    checked_at=now,
                    reason="bootstrap_added_items",
                )
    
            rows = conn.execute(
                select(adoption_w07_tracker_items)
                .where(adoption_w07_tracker_items.c.site == payload.site)
                .order_by(
                    adoption_w07_tracker_items.c.item_type.asc(),
                    adoption_w07_tracker_items.c.item_key.asc(),
                    adoption_w07_tracker_items.c.id.asc(),
                )
            ).mappings().all()
    
        items = [_row_to_w07_tracker_item_model(row) for row in rows]
        _write_audit_log(
            principal=principal,
            action="w07_tracker_bootstrap",
            resource_type="adoption_w07_tracker",
            resource_id=payload.site,
            detail={"site": payload.site, "created_count": created_count, "total_count": len(items)},
        )
        return W07TrackerBootstrapResponse(
            site=payload.site,
            created_count=created_count,
            total_count=len(items),
            items=items,
        )
    
    
    @router.get("/w07/tracker/items", response_model=list[W07TrackerItemRead])
    def list_w07_tracker_items(
        site: Annotated[str | None, Query()] = None,
        status: Annotated[str | None, Query()] = None,
        item_type: Annotated[str | None, Query()] = None,
        assignee: Annotated[str | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
        offset: Annotated[int, Query(ge=0)] = 0,
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:read")),
    ) -> list[W07TrackerItemRead]:
        _require_site_access(principal, site)
        normalized_status = status.strip().lower() if status is not None else None
        if normalized_status is not None and normalized_status not in W07_TRACKER_STATUS_SET:
            raise HTTPException(status_code=400, detail="Invalid W07 tracker status")
    
        stmt = select(adoption_w07_tracker_items)
        if site is not None:
            stmt = stmt.where(adoption_w07_tracker_items.c.site == site)
        else:
            allowed_sites = _allowed_sites_for_principal(principal)
            if allowed_sites is not None:
                if not allowed_sites:
                    return []
                stmt = stmt.where(adoption_w07_tracker_items.c.site.in_(allowed_sites))
    
        if normalized_status is not None:
            stmt = stmt.where(adoption_w07_tracker_items.c.status == normalized_status)
        if item_type is not None:
            stmt = stmt.where(adoption_w07_tracker_items.c.item_type == item_type.strip())
        if assignee is not None:
            stmt = stmt.where(adoption_w07_tracker_items.c.assignee == assignee.strip())
    
        stmt = stmt.order_by(
            adoption_w07_tracker_items.c.updated_at.desc(),
            adoption_w07_tracker_items.c.id.desc(),
        ).limit(limit).offset(offset)
    
        with get_conn() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [_row_to_w07_tracker_item_model(row) for row in rows]
    
    
    @router.get("/w07/tracker/overview", response_model=W07TrackerOverviewRead)
    def get_w07_tracker_overview(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:read")),
    ) -> W07TrackerOverviewRead:
        _require_site_access(principal, site)
        with get_conn() as conn:
            rows = conn.execute(
                select(adoption_w07_tracker_items).where(adoption_w07_tracker_items.c.site == site)
            ).mappings().all()
        models = [_row_to_w07_tracker_item_model(row) for row in rows]
        return _compute_w07_tracker_overview(site, models)
    
    
    @router.get("/w07/tracker/readiness", response_model=W07TrackerReadinessRead)
    def get_w07_tracker_readiness(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:read")),
    ) -> W07TrackerReadinessRead:
        _require_site_access(principal, site)
        models = _load_w07_tracker_items_for_site(site)
        return _compute_w07_tracker_readiness(site=site, rows=models)
    
    
    @router.get("/w07/tracker/completion", response_model=W07TrackerCompletionRead)
    def get_w07_tracker_completion(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:read")),
    ) -> W07TrackerCompletionRead:
        _require_site_access(principal, site)
        now = datetime.now(timezone.utc)
        models = _load_w07_tracker_items_for_site(site)
        readiness = _compute_w07_tracker_readiness(site=site, rows=models, checked_at=now)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w07_site_runs).where(adoption_w07_site_runs.c.site == site).limit(1)
            ).mappings().first()
        return _row_to_w07_completion_model(site=site, readiness=readiness, row=row)
    
    
    @router.get("/w07/tracker/completion-package", response_model=None)
    def download_w07_tracker_completion_package(
        site: Annotated[str, Query(min_length=1)],
        include_evidence: Annotated[bool, Query()] = True,
        include_weekly: Annotated[bool, Query()] = True,
        weekly_limit: Annotated[int, Query(ge=1, le=104)] = 26,
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:read")),
    ) -> Response:
        _require_site_access(principal, site)
        checked_at = datetime.now(timezone.utc)
        rows = _load_w07_tracker_items_for_site(site)
        readiness = _compute_w07_tracker_readiness(site=site, rows=rows, checked_at=checked_at)
        with get_conn() as conn:
            completion_row = conn.execute(
                select(adoption_w07_site_runs).where(adoption_w07_site_runs.c.site == site).limit(1)
            ).mappings().first()
        completion = _row_to_w07_completion_model(site=site, readiness=readiness, row=completion_row)
        package_bytes, manifest = _build_w07_completion_package_zip(
            site=site,
            completion=completion,
            rows=rows,
            include_evidence=include_evidence,
            include_weekly=include_weekly,
            weekly_limit=weekly_limit,
            principal=principal,
        )
        timestamp = checked_at.strftime("%Y%m%dT%H%M%SZ")
        file_name = _safe_download_filename(
            f"ka-facility-os-w07-completion-package-{site}-{timestamp}.zip",
            fallback=f"ka-facility-os-w07-completion-package-{timestamp}.zip",
            max_length=140,
        )
        _write_audit_log(
            principal=principal,
            action="w07_completion_package_download",
            resource_type="adoption_w07_package",
            resource_id=site,
            detail={
                "site": site,
                "include_evidence": include_evidence,
                "include_weekly": include_weekly,
                "weekly_limit": weekly_limit,
                "completion_status": completion.status,
                "readiness_ready": completion.readiness.ready,
                "sha256": manifest.get("sha256"),
                "bytes": manifest.get("bytes"),
            },
        )
        return Response(
            content=package_bytes,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{file_name}"',
                "X-Archive-SHA256": str(manifest.get("sha256") or ""),
                "X-Package-Site": site,
            },
        )
    
    
    @router.post("/w07/tracker/complete", response_model=W07TrackerCompletionRead)
    def complete_w07_tracker(
        payload: W07TrackerCompletionRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:write")),
    ) -> W07TrackerCompletionRead:
        _require_site_access(principal, payload.site)
        if payload.force and not _has_permission(principal, "admins:manage"):
            raise HTTPException(status_code=403, detail="force completion requires admins:manage")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        models = _load_w07_tracker_items_for_site(payload.site)
        readiness = _compute_w07_tracker_readiness(site=payload.site, rows=models, checked_at=now)
        if not readiness.ready and not payload.force:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "W07 completion gate failed",
                    "site": payload.site,
                    "ready": readiness.ready,
                    "blockers": readiness.blockers,
                    "readiness": readiness.model_dump(mode="json"),
                },
            )
    
        completion_note = (payload.completion_note or "").strip()
        next_status = (
            W07_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS
            if payload.force and not readiness.ready
            else W07_SITE_COMPLETION_STATUS_COMPLETED
        )
        with get_conn() as conn:
            existing = conn.execute(
                select(adoption_w07_site_runs).where(adoption_w07_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
            if existing is None:
                conn.execute(
                    insert(adoption_w07_site_runs).values(
                        site=payload.site,
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                conn.execute(
                    update(adoption_w07_site_runs)
                    .where(adoption_w07_site_runs.c.site == payload.site)
                    .values(
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        updated_by=actor_username,
                        updated_at=now,
                    )
                )
            row = conn.execute(
                select(adoption_w07_site_runs).where(adoption_w07_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
    
        model = _row_to_w07_completion_model(site=payload.site, readiness=readiness, row=row)
        _write_audit_log(
            principal=principal,
            action="w07_tracker_complete",
            resource_type="adoption_w07_tracker_site",
            resource_id=payload.site,
            detail={
                "site": payload.site,
                "status": model.status,
                "ready": readiness.ready,
                "force_used": model.force_used,
                "blockers": readiness.blockers,
                "completion_rate_percent": readiness.completion_rate_percent,
                "missing_required_evidence_count": readiness.missing_required_evidence_count,
            },
        )
        return model
    
    
    @router.patch("/w07/tracker/items/{tracker_item_id}", response_model=W07TrackerItemRead)
    def update_w07_tracker_item(
        tracker_item_id: int,
        payload: W07TrackerItemUpdate,
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:write")),
    ) -> W07TrackerItemRead:
        has_update = (
            payload.assignee is not None
            or payload.status is not None
            or payload.completion_checked is not None
            or payload.completion_note is not None
        )
        if not has_update:
            raise HTTPException(status_code=400, detail="No update fields provided")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w07_tracker_items).where(adoption_w07_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if row is None:
                raise HTTPException(status_code=404, detail="W07 tracker item not found")
            _require_site_access(principal, str(row["site"]))
    
            next_assignee = row.get("assignee")
            if payload.assignee is not None:
                normalized_assignee = payload.assignee.strip()
                next_assignee = normalized_assignee or None
    
            next_status = str(row["status"])
            if payload.status is not None:
                next_status = str(payload.status)
    
            next_checked = bool(row.get("completion_checked", False))
            if payload.completion_checked is not None:
                next_checked = bool(payload.completion_checked)
    
            if next_status == W07_TRACKER_STATUS_DONE:
                next_checked = True
            elif payload.status is not None and payload.status != W07_TRACKER_STATUS_DONE and payload.completion_checked is None:
                next_checked = False
            if payload.completion_checked is True:
                next_status = W07_TRACKER_STATUS_DONE
            elif payload.completion_checked is False and next_status == W07_TRACKER_STATUS_DONE:
                next_status = W07_TRACKER_STATUS_IN_PROGRESS
    
            if next_status not in W07_TRACKER_STATUS_SET:
                raise HTTPException(status_code=400, detail="Invalid W07 tracker status")
    
            next_note = str(row.get("completion_note") or "")
            if payload.completion_note is not None:
                next_note = payload.completion_note.strip()
    
            existing_completed_at = _as_optional_datetime(row.get("completed_at"))
            next_completed_at = existing_completed_at
            if next_checked:
                if existing_completed_at is None:
                    next_completed_at = now
            else:
                next_completed_at = None
    
            conn.execute(
                update(adoption_w07_tracker_items)
                .where(adoption_w07_tracker_items.c.id == tracker_item_id)
                .values(
                    assignee=next_assignee,
                    status=next_status,
                    completion_checked=next_checked,
                    completion_note=next_note,
                    completed_at=next_completed_at,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w07_completion_if_closed(
                conn=conn,
                site=str(row["site"]),
                actor_username=actor_username,
                checked_at=now,
                reason="tracker_item_updated",
            )
            updated = conn.execute(
                select(adoption_w07_tracker_items).where(adoption_w07_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
        if updated is None:
            raise HTTPException(status_code=500, detail="Failed to update W07 tracker item")
        model = _row_to_w07_tracker_item_model(updated)
        _write_audit_log(
            principal=principal,
            action="w07_tracker_item_update",
            resource_type="adoption_w07_tracker_item",
            resource_id=str(model.id),
            detail={
                "site": model.site,
                "status": model.status,
                "assignee": model.assignee,
                "completion_checked": model.completion_checked,
            },
        )
        return model
    
    
    @router.post("/w07/tracker/items/{tracker_item_id}/evidence", response_model=W07EvidenceRead, status_code=201)
    async def upload_w07_tracker_evidence(
        tracker_item_id: int,
        file: UploadFile = File(...),
        note: str = Form(default=""),
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:write")),
    ) -> W07EvidenceRead:
        file_name = _safe_download_filename(file.filename or "", fallback="evidence.bin", max_length=120)
        content_type = (file.content_type or "application/octet-stream").strip() or "application/octet-stream"
        content_type = content_type[:120].lower()
        if not _is_allowed_evidence_content_type(content_type):
            raise HTTPException(
                status_code=415,
                detail="Unsupported evidence content type",
            )
        file_bytes = await file.read(W07_EVIDENCE_MAX_BYTES + 1)
        await file.close()
        if len(file_bytes) == 0:
            raise HTTPException(status_code=400, detail="Empty evidence file is not allowed")
        if len(file_bytes) > W07_EVIDENCE_MAX_BYTES:
            raise HTTPException(status_code=413, detail=f"Evidence file too large (max {W07_EVIDENCE_MAX_BYTES} bytes)")
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
            tracker_row = conn.execute(
                select(adoption_w07_tracker_items).where(adoption_w07_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W07 tracker item not found")
            site = str(tracker_row["site"])
            _require_site_access(principal, site)
    
            result = conn.execute(
                insert(adoption_w07_evidence_files).values(
                    tracker_item_id=tracker_item_id,
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
            next_count = int(tracker_row.get("evidence_count") or 0) + 1
            conn.execute(
                update(adoption_w07_tracker_items)
                .where(adoption_w07_tracker_items.c.id == tracker_item_id)
                .values(
                    evidence_count=next_count,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            evidence_row = conn.execute(
                select(adoption_w07_evidence_files).where(adoption_w07_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
    
        if evidence_row is None:
            raise HTTPException(status_code=500, detail="Failed to save evidence file")
        model = _row_to_w07_evidence_model(evidence_row)
        _write_audit_log(
            principal=principal,
            action="w07_tracker_evidence_upload",
            resource_type="adoption_w07_evidence",
            resource_id=str(model.id),
            detail={
                "tracker_item_id": model.tracker_item_id,
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
    
    
    @router.get("/w07/tracker/items/{tracker_item_id}/evidence", response_model=list[W07EvidenceRead])
    def list_w07_tracker_evidence(
        tracker_item_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:read")),
    ) -> list[W07EvidenceRead]:
        with get_conn() as conn:
            tracker_row = conn.execute(
                select(adoption_w07_tracker_items).where(adoption_w07_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W07 tracker item not found")
            _require_site_access(principal, str(tracker_row["site"]))
    
            rows = conn.execute(
                select(adoption_w07_evidence_files)
                .where(adoption_w07_evidence_files.c.tracker_item_id == tracker_item_id)
                .order_by(adoption_w07_evidence_files.c.uploaded_at.desc(), adoption_w07_evidence_files.c.id.desc())
            ).mappings().all()
        return [_row_to_w07_evidence_model(row) for row in rows]
    
    
    @router.get("/w07/tracker/evidence/{evidence_id}/download", response_model=None)
    def download_w07_tracker_evidence(
        evidence_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:read")),
    ) -> Response:
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w07_evidence_files).where(adoption_w07_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="W07 evidence not found")
    
        site = str(row["site"])
        _require_site_access(principal, site)
        content_type = str(row.get("content_type") or "application/octet-stream")
        file_name = _safe_download_filename(str(row.get("file_name") or ""), fallback="evidence.bin", max_length=120)
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
            action="w07_tracker_evidence_download",
            resource_type="adoption_w07_evidence",
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
    
    
    
    @router.post("/w09/tracker/bootstrap", response_model=W09TrackerBootstrapResponse)
    def bootstrap_w09_tracker_items(
        payload: W09TrackerBootstrapRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w09:write")),
    ) -> W09TrackerBootstrapResponse:
        _require_site_access(principal, payload.site)
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        catalog = _adoption_w09_catalog_items(payload.site)
        created_count = 0
    
        with get_conn() as conn:
            existing_rows = conn.execute(
                select(
                    adoption_w09_tracker_items.c.item_type,
                    adoption_w09_tracker_items.c.item_key,
                ).where(adoption_w09_tracker_items.c.site == payload.site)
            ).mappings().all()
            existing_keys = {(str(row["item_type"]), str(row["item_key"])) for row in existing_rows}
    
            for entry in catalog:
                key = (str(entry["item_type"]), str(entry["item_key"]))
                if key in existing_keys:
                    continue
                conn.execute(
                    insert(adoption_w09_tracker_items).values(
                        site=payload.site,
                        item_type=str(entry["item_type"]),
                        item_key=str(entry["item_key"]),
                        item_name=str(entry["item_name"]),
                        assignee=None,
                        status=W09_TRACKER_STATUS_PENDING,
                        completion_checked=False,
                        completion_note="",
                        due_at=entry.get("due_at"),
                        completed_at=None,
                        evidence_count=0,
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
                existing_keys.add(key)
                created_count += 1
    
            if created_count > 0:
                _reset_w09_completion_if_closed(
                    conn=conn,
                    site=payload.site,
                    actor_username=actor_username,
                    checked_at=now,
                    reason="bootstrap_added_items",
                )
    
            rows = conn.execute(
                select(adoption_w09_tracker_items)
                .where(adoption_w09_tracker_items.c.site == payload.site)
                .order_by(
                    adoption_w09_tracker_items.c.item_type.asc(),
                    adoption_w09_tracker_items.c.item_key.asc(),
                    adoption_w09_tracker_items.c.id.asc(),
                )
            ).mappings().all()
    
        items = [_row_to_w09_tracker_item_model(row) for row in rows]
        _write_audit_log(
            principal=principal,
            action="w09_tracker_bootstrap",
            resource_type="adoption_w09_tracker",
            resource_id=payload.site,
            detail={"site": payload.site, "created_count": created_count, "total_count": len(items)},
        )
        return W09TrackerBootstrapResponse(
            site=payload.site,
            created_count=created_count,
            total_count=len(items),
            items=items,
        )
    
    
    @router.get("/w09/tracker/items", response_model=list[W09TrackerItemRead])
    def list_w09_tracker_items(
        site: Annotated[str | None, Query()] = None,
        status: Annotated[str | None, Query()] = None,
        item_type: Annotated[str | None, Query()] = None,
        assignee: Annotated[str | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
        offset: Annotated[int, Query(ge=0)] = 0,
        principal: dict[str, Any] = Depends(require_permission("adoption_w09:read")),
    ) -> list[W09TrackerItemRead]:
        _require_site_access(principal, site)
        normalized_status = status.strip().lower() if status is not None else None
        if normalized_status is not None and normalized_status not in W09_TRACKER_STATUS_SET:
            raise HTTPException(status_code=400, detail="Invalid W09 tracker status")
    
        stmt = select(adoption_w09_tracker_items)
        if site is not None:
            stmt = stmt.where(adoption_w09_tracker_items.c.site == site)
        else:
            allowed_sites = _allowed_sites_for_principal(principal)
            if allowed_sites is not None:
                if not allowed_sites:
                    return []
                stmt = stmt.where(adoption_w09_tracker_items.c.site.in_(allowed_sites))
    
        if normalized_status is not None:
            stmt = stmt.where(adoption_w09_tracker_items.c.status == normalized_status)
        if item_type is not None:
            stmt = stmt.where(adoption_w09_tracker_items.c.item_type == item_type.strip())
        if assignee is not None:
            stmt = stmt.where(adoption_w09_tracker_items.c.assignee == assignee.strip())
    
        stmt = stmt.order_by(
            adoption_w09_tracker_items.c.updated_at.desc(),
            adoption_w09_tracker_items.c.id.desc(),
        ).limit(limit).offset(offset)
    
        with get_conn() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [_row_to_w09_tracker_item_model(row) for row in rows]
    
    
    @router.get("/w09/tracker/overview", response_model=W09TrackerOverviewRead)
    def get_w09_tracker_overview(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w09:read")),
    ) -> W09TrackerOverviewRead:
        _require_site_access(principal, site)
        with get_conn() as conn:
            rows = conn.execute(
                select(adoption_w09_tracker_items).where(adoption_w09_tracker_items.c.site == site)
            ).mappings().all()
        models = [_row_to_w09_tracker_item_model(row) for row in rows]
        return _compute_w09_tracker_overview(site, models)
    
    
    @router.get("/w09/tracker/readiness", response_model=W09TrackerReadinessRead)
    def get_w09_tracker_readiness(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w09:read")),
    ) -> W09TrackerReadinessRead:
        _require_site_access(principal, site)
        models = _load_w09_tracker_items_for_site(site)
        return _compute_w09_tracker_readiness(site=site, rows=models)
    
    
    @router.get("/w09/tracker/completion", response_model=W09TrackerCompletionRead)
    def get_w09_tracker_completion(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w09:read")),
    ) -> W09TrackerCompletionRead:
        _require_site_access(principal, site)
        now = datetime.now(timezone.utc)
        models = _load_w09_tracker_items_for_site(site)
        readiness = _compute_w09_tracker_readiness(site=site, rows=models, checked_at=now)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w09_site_runs).where(adoption_w09_site_runs.c.site == site).limit(1)
            ).mappings().first()
        return _row_to_w09_completion_model(site=site, readiness=readiness, row=row)
    
    
    @router.post("/w09/tracker/complete", response_model=W09TrackerCompletionRead)
    def complete_w09_tracker(
        payload: W09TrackerCompletionRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w09:write")),
    ) -> W09TrackerCompletionRead:
        _require_site_access(principal, payload.site)
        if payload.force and not _has_permission(principal, "admins:manage"):
            raise HTTPException(status_code=403, detail="force completion requires admins:manage")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        models = _load_w09_tracker_items_for_site(payload.site)
        readiness = _compute_w09_tracker_readiness(site=payload.site, rows=models, checked_at=now)
        if not readiness.ready and not payload.force:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "W09 completion gate failed",
                    "site": payload.site,
                    "ready": readiness.ready,
                    "blockers": readiness.blockers,
                    "readiness": readiness.model_dump(mode="json"),
                },
            )
    
        completion_note = (payload.completion_note or "").strip()
        next_status = (
            W09_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS
            if payload.force and not readiness.ready
            else W09_SITE_COMPLETION_STATUS_COMPLETED
        )
        with get_conn() as conn:
            existing = conn.execute(
                select(adoption_w09_site_runs).where(adoption_w09_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
            if existing is None:
                conn.execute(
                    insert(adoption_w09_site_runs).values(
                        site=payload.site,
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                conn.execute(
                    update(adoption_w09_site_runs)
                    .where(adoption_w09_site_runs.c.site == payload.site)
                    .values(
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        updated_by=actor_username,
                        updated_at=now,
                    )
                )
            row = conn.execute(
                select(adoption_w09_site_runs).where(adoption_w09_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
    
        model = _row_to_w09_completion_model(site=payload.site, readiness=readiness, row=row)
        _write_audit_log(
            principal=principal,
            action="w09_tracker_complete",
            resource_type="adoption_w09_tracker_site",
            resource_id=payload.site,
            detail={
                "site": payload.site,
                "status": model.status,
                "ready": readiness.ready,
                "force_used": model.force_used,
                "blockers": readiness.blockers,
                "completion_rate_percent": readiness.completion_rate_percent,
                "missing_required_evidence_count": readiness.missing_required_evidence_count,
            },
        )
        return model
    
    
    @router.patch("/w09/tracker/items/{tracker_item_id}", response_model=W09TrackerItemRead)
    def update_w09_tracker_item(
        tracker_item_id: int,
        payload: W09TrackerItemUpdate,
        principal: dict[str, Any] = Depends(require_permission("adoption_w09:write")),
    ) -> W09TrackerItemRead:
        has_update = (
            payload.assignee is not None
            or payload.status is not None
            or payload.completion_checked is not None
            or payload.completion_note is not None
        )
        if not has_update:
            raise HTTPException(status_code=400, detail="No update fields provided")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w09_tracker_items).where(adoption_w09_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if row is None:
                raise HTTPException(status_code=404, detail="W09 tracker item not found")
            _require_site_access(principal, str(row["site"]))
    
            next_assignee = row.get("assignee")
            if payload.assignee is not None:
                normalized_assignee = payload.assignee.strip()
                next_assignee = normalized_assignee or None
    
            next_status = str(row["status"])
            if payload.status is not None:
                next_status = str(payload.status)
    
            next_checked = bool(row.get("completion_checked", False))
            if payload.completion_checked is not None:
                next_checked = bool(payload.completion_checked)
    
            if next_status == W09_TRACKER_STATUS_DONE:
                next_checked = True
            elif payload.status is not None and payload.status != W09_TRACKER_STATUS_DONE and payload.completion_checked is None:
                next_checked = False
            if payload.completion_checked is True:
                next_status = W09_TRACKER_STATUS_DONE
            elif payload.completion_checked is False and next_status == W09_TRACKER_STATUS_DONE:
                next_status = W09_TRACKER_STATUS_IN_PROGRESS
    
            if next_status not in W09_TRACKER_STATUS_SET:
                raise HTTPException(status_code=400, detail="Invalid W09 tracker status")
    
            next_note = str(row.get("completion_note") or "")
            if payload.completion_note is not None:
                next_note = payload.completion_note.strip()
    
            existing_completed_at = _as_optional_datetime(row.get("completed_at"))
            next_completed_at = existing_completed_at
            if next_checked:
                if existing_completed_at is None:
                    next_completed_at = now
            else:
                next_completed_at = None
    
            conn.execute(
                update(adoption_w09_tracker_items)
                .where(adoption_w09_tracker_items.c.id == tracker_item_id)
                .values(
                    assignee=next_assignee,
                    status=next_status,
                    completion_checked=next_checked,
                    completion_note=next_note,
                    completed_at=next_completed_at,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w09_completion_if_closed(
                conn=conn,
                site=str(row["site"]),
                actor_username=actor_username,
                checked_at=now,
                reason="tracker_item_updated",
            )
            updated = conn.execute(
                select(adoption_w09_tracker_items).where(adoption_w09_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
        if updated is None:
            raise HTTPException(status_code=500, detail="Failed to update W09 tracker item")
        model = _row_to_w09_tracker_item_model(updated)
        _write_audit_log(
            principal=principal,
            action="w09_tracker_item_update",
            resource_type="adoption_w09_tracker_item",
            resource_id=str(model.id),
            detail={
                "site": model.site,
                "status": model.status,
                "assignee": model.assignee,
                "completion_checked": model.completion_checked,
            },
        )
        return model
    
    
    @router.post("/w09/tracker/items/{tracker_item_id}/evidence", response_model=W09EvidenceRead, status_code=201)
    async def upload_w09_tracker_evidence(
        tracker_item_id: int,
        file: UploadFile = File(...),
        note: str = Form(default=""),
        principal: dict[str, Any] = Depends(require_permission("adoption_w09:write")),
    ) -> W09EvidenceRead:
        file_name = _safe_download_filename(file.filename or "", fallback="evidence.bin", max_length=120)
        content_type = (file.content_type or "application/octet-stream").strip() or "application/octet-stream"
        content_type = content_type[:120].lower()
        if not _is_allowed_evidence_content_type(content_type):
            raise HTTPException(status_code=415, detail="Unsupported evidence content type")
        file_bytes = await file.read(W09_EVIDENCE_MAX_BYTES + 1)
        await file.close()
        if len(file_bytes) == 0:
            raise HTTPException(status_code=400, detail="Empty evidence file is not allowed")
        if len(file_bytes) > W09_EVIDENCE_MAX_BYTES:
            raise HTTPException(status_code=413, detail=f"Evidence file too large (max {W09_EVIDENCE_MAX_BYTES} bytes)")
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
            tracker_row = conn.execute(
                select(adoption_w09_tracker_items).where(adoption_w09_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W09 tracker item not found")
            site = str(tracker_row["site"])
            _require_site_access(principal, site)
    
            result = conn.execute(
                insert(adoption_w09_evidence_files).values(
                    tracker_item_id=tracker_item_id,
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
            next_count = int(tracker_row.get("evidence_count") or 0) + 1
            conn.execute(
                update(adoption_w09_tracker_items)
                .where(adoption_w09_tracker_items.c.id == tracker_item_id)
                .values(
                    evidence_count=next_count,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w09_completion_if_closed(
                conn=conn,
                site=site,
                actor_username=actor_username,
                checked_at=now,
                reason="evidence_uploaded",
            )
            evidence_row = conn.execute(
                select(adoption_w09_evidence_files).where(adoption_w09_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
    
        if evidence_row is None:
            raise HTTPException(status_code=500, detail="Failed to save evidence file")
        model = _row_to_w09_evidence_model(evidence_row)
        _write_audit_log(
            principal=principal,
            action="w09_tracker_evidence_upload",
            resource_type="adoption_w09_evidence",
            resource_id=str(model.id),
            detail={
                "tracker_item_id": model.tracker_item_id,
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
    
    
    @router.get("/w09/tracker/items/{tracker_item_id}/evidence", response_model=list[W09EvidenceRead])
    def list_w09_tracker_evidence(
        tracker_item_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w09:read")),
    ) -> list[W09EvidenceRead]:
        with get_conn() as conn:
            tracker_row = conn.execute(
                select(adoption_w09_tracker_items).where(adoption_w09_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W09 tracker item not found")
            _require_site_access(principal, str(tracker_row["site"]))
    
            rows = conn.execute(
                select(adoption_w09_evidence_files)
                .where(adoption_w09_evidence_files.c.tracker_item_id == tracker_item_id)
                .order_by(adoption_w09_evidence_files.c.uploaded_at.desc(), adoption_w09_evidence_files.c.id.desc())
            ).mappings().all()
        return [_row_to_w09_evidence_model(row) for row in rows]
    
    
    @router.get("/w09/tracker/evidence/{evidence_id}/download", response_model=None)
    def download_w09_tracker_evidence(
        evidence_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w09:read")),
    ) -> Response:
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w09_evidence_files).where(adoption_w09_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="W09 evidence not found")
    
        site = str(row["site"])
        _require_site_access(principal, site)
        content_type = str(row.get("content_type") or "application/octet-stream")
        file_name = _safe_download_filename(str(row.get("file_name") or ""), fallback="evidence.bin", max_length=120)
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
            action="w09_tracker_evidence_download",
            resource_type="adoption_w09_evidence",
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
    
    
    
    
    @router.post("/w10/tracker/bootstrap", response_model=W10TrackerBootstrapResponse)
    def bootstrap_w10_tracker_items(
        payload: W10TrackerBootstrapRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w10:write")),
    ) -> W10TrackerBootstrapResponse:
        _require_site_access(principal, payload.site)
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        catalog = _adoption_w10_catalog_items(payload.site)
        created_count = 0
    
        with get_conn() as conn:
            existing_rows = conn.execute(
                select(
                    adoption_w10_tracker_items.c.item_type,
                    adoption_w10_tracker_items.c.item_key,
                ).where(adoption_w10_tracker_items.c.site == payload.site)
            ).mappings().all()
            existing_keys = {(str(row["item_type"]), str(row["item_key"])) for row in existing_rows}
    
            for entry in catalog:
                key = (str(entry["item_type"]), str(entry["item_key"]))
                if key in existing_keys:
                    continue
                conn.execute(
                    insert(adoption_w10_tracker_items).values(
                        site=payload.site,
                        item_type=str(entry["item_type"]),
                        item_key=str(entry["item_key"]),
                        item_name=str(entry["item_name"]),
                        assignee=None,
                        status=W10_TRACKER_STATUS_PENDING,
                        completion_checked=False,
                        completion_note="",
                        due_at=entry.get("due_at"),
                        completed_at=None,
                        evidence_count=0,
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
                existing_keys.add(key)
                created_count += 1
    
            if created_count > 0:
                _reset_w10_completion_if_closed(
                    conn=conn,
                    site=payload.site,
                    actor_username=actor_username,
                    checked_at=now,
                    reason="bootstrap_added_items",
                )
    
            rows = conn.execute(
                select(adoption_w10_tracker_items)
                .where(adoption_w10_tracker_items.c.site == payload.site)
                .order_by(
                    adoption_w10_tracker_items.c.item_type.asc(),
                    adoption_w10_tracker_items.c.item_key.asc(),
                    adoption_w10_tracker_items.c.id.asc(),
                )
            ).mappings().all()
    
        items = [_row_to_w10_tracker_item_model(row) for row in rows]
        _write_audit_log(
            principal=principal,
            action="w10_tracker_bootstrap",
            resource_type="adoption_w10_tracker",
            resource_id=payload.site,
            detail={"site": payload.site, "created_count": created_count, "total_count": len(items)},
        )
        return W10TrackerBootstrapResponse(
            site=payload.site,
            created_count=created_count,
            total_count=len(items),
            items=items,
        )
    
    
    @router.get("/w10/tracker/items", response_model=list[W10TrackerItemRead])
    def list_w10_tracker_items(
        site: Annotated[str | None, Query()] = None,
        status: Annotated[str | None, Query()] = None,
        item_type: Annotated[str | None, Query()] = None,
        assignee: Annotated[str | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
        offset: Annotated[int, Query(ge=0)] = 0,
        principal: dict[str, Any] = Depends(require_permission("adoption_w10:read")),
    ) -> list[W10TrackerItemRead]:
        _require_site_access(principal, site)
        normalized_status = status.strip().lower() if status is not None else None
        if normalized_status is not None and normalized_status not in W10_TRACKER_STATUS_SET:
            raise HTTPException(status_code=400, detail="Invalid W10 tracker status")
    
        stmt = select(adoption_w10_tracker_items)
        if site is not None:
            stmt = stmt.where(adoption_w10_tracker_items.c.site == site)
        else:
            allowed_sites = _allowed_sites_for_principal(principal)
            if allowed_sites is not None:
                if not allowed_sites:
                    return []
                stmt = stmt.where(adoption_w10_tracker_items.c.site.in_(allowed_sites))
    
        if normalized_status is not None:
            stmt = stmt.where(adoption_w10_tracker_items.c.status == normalized_status)
        if item_type is not None:
            stmt = stmt.where(adoption_w10_tracker_items.c.item_type == item_type.strip())
        if assignee is not None:
            stmt = stmt.where(adoption_w10_tracker_items.c.assignee == assignee.strip())
    
        stmt = stmt.order_by(
            adoption_w10_tracker_items.c.updated_at.desc(),
            adoption_w10_tracker_items.c.id.desc(),
        ).limit(limit).offset(offset)
    
        with get_conn() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [_row_to_w10_tracker_item_model(row) for row in rows]
    
    
    @router.get("/w10/tracker/overview", response_model=W10TrackerOverviewRead)
    def get_w10_tracker_overview(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w10:read")),
    ) -> W10TrackerOverviewRead:
        _require_site_access(principal, site)
        with get_conn() as conn:
            rows = conn.execute(
                select(adoption_w10_tracker_items).where(adoption_w10_tracker_items.c.site == site)
            ).mappings().all()
        models = [_row_to_w10_tracker_item_model(row) for row in rows]
        return _compute_w10_tracker_overview(site, models)
    
    
    @router.get("/w10/tracker/readiness", response_model=W10TrackerReadinessRead)
    def get_w10_tracker_readiness(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w10:read")),
    ) -> W10TrackerReadinessRead:
        _require_site_access(principal, site)
        models = _load_w10_tracker_items_for_site(site)
        return _compute_w10_tracker_readiness(site=site, rows=models)
    
    
    @router.get("/w10/tracker/completion", response_model=W10TrackerCompletionRead)
    def get_w10_tracker_completion(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w10:read")),
    ) -> W10TrackerCompletionRead:
        _require_site_access(principal, site)
        now = datetime.now(timezone.utc)
        models = _load_w10_tracker_items_for_site(site)
        readiness = _compute_w10_tracker_readiness(site=site, rows=models, checked_at=now)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w10_site_runs).where(adoption_w10_site_runs.c.site == site).limit(1)
            ).mappings().first()
        return _row_to_w10_completion_model(site=site, readiness=readiness, row=row)
    
    
    @router.post("/w10/tracker/complete", response_model=W10TrackerCompletionRead)
    def complete_w10_tracker(
        payload: W10TrackerCompletionRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w10:write")),
    ) -> W10TrackerCompletionRead:
        _require_site_access(principal, payload.site)
        if payload.force and not _has_permission(principal, "admins:manage"):
            raise HTTPException(status_code=403, detail="force completion requires admins:manage")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        models = _load_w10_tracker_items_for_site(payload.site)
        readiness = _compute_w10_tracker_readiness(site=payload.site, rows=models, checked_at=now)
        if not readiness.ready and not payload.force:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "W10 completion gate failed",
                    "site": payload.site,
                    "ready": readiness.ready,
                    "blockers": readiness.blockers,
                    "readiness": readiness.model_dump(mode="json"),
                },
            )
    
        completion_note = (payload.completion_note or "").strip()
        next_status = (
            W10_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS
            if payload.force and not readiness.ready
            else W10_SITE_COMPLETION_STATUS_COMPLETED
        )
        with get_conn() as conn:
            existing = conn.execute(
                select(adoption_w10_site_runs).where(adoption_w10_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
            if existing is None:
                conn.execute(
                    insert(adoption_w10_site_runs).values(
                        site=payload.site,
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                conn.execute(
                    update(adoption_w10_site_runs)
                    .where(adoption_w10_site_runs.c.site == payload.site)
                    .values(
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        updated_by=actor_username,
                        updated_at=now,
                    )
                )
            row = conn.execute(
                select(adoption_w10_site_runs).where(adoption_w10_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
    
        model = _row_to_w10_completion_model(site=payload.site, readiness=readiness, row=row)
        _write_audit_log(
            principal=principal,
            action="w10_tracker_complete",
            resource_type="adoption_w10_tracker_site",
            resource_id=payload.site,
            detail={
                "site": payload.site,
                "status": model.status,
                "ready": readiness.ready,
                "force_used": model.force_used,
                "blockers": readiness.blockers,
                "completion_rate_percent": readiness.completion_rate_percent,
                "missing_required_evidence_count": readiness.missing_required_evidence_count,
            },
        )
        return model
    
    
    @router.patch("/w10/tracker/items/{tracker_item_id}", response_model=W10TrackerItemRead)
    def update_w10_tracker_item(
        tracker_item_id: int,
        payload: W10TrackerItemUpdate,
        principal: dict[str, Any] = Depends(require_permission("adoption_w10:write")),
    ) -> W10TrackerItemRead:
        has_update = (
            payload.assignee is not None
            or payload.status is not None
            or payload.completion_checked is not None
            or payload.completion_note is not None
        )
        if not has_update:
            raise HTTPException(status_code=400, detail="No update fields provided")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w10_tracker_items).where(adoption_w10_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if row is None:
                raise HTTPException(status_code=404, detail="W10 tracker item not found")
            _require_site_access(principal, str(row["site"]))
    
            next_assignee = row.get("assignee")
            if payload.assignee is not None:
                normalized_assignee = payload.assignee.strip()
                next_assignee = normalized_assignee or None
    
            next_status = str(row["status"])
            if payload.status is not None:
                next_status = str(payload.status)
    
            next_checked = bool(row.get("completion_checked", False))
            if payload.completion_checked is not None:
                next_checked = bool(payload.completion_checked)
    
            if next_status == W10_TRACKER_STATUS_DONE:
                next_checked = True
            elif payload.status is not None and payload.status != W10_TRACKER_STATUS_DONE and payload.completion_checked is None:
                next_checked = False
            if payload.completion_checked is True:
                next_status = W10_TRACKER_STATUS_DONE
            elif payload.completion_checked is False and next_status == W10_TRACKER_STATUS_DONE:
                next_status = W10_TRACKER_STATUS_IN_PROGRESS
    
            if next_status not in W10_TRACKER_STATUS_SET:
                raise HTTPException(status_code=400, detail="Invalid W10 tracker status")
    
            next_note = str(row.get("completion_note") or "")
            if payload.completion_note is not None:
                next_note = payload.completion_note.strip()
    
            existing_completed_at = _as_optional_datetime(row.get("completed_at"))
            next_completed_at = existing_completed_at
            if next_checked:
                if existing_completed_at is None:
                    next_completed_at = now
            else:
                next_completed_at = None
    
            conn.execute(
                update(adoption_w10_tracker_items)
                .where(adoption_w10_tracker_items.c.id == tracker_item_id)
                .values(
                    assignee=next_assignee,
                    status=next_status,
                    completion_checked=next_checked,
                    completion_note=next_note,
                    completed_at=next_completed_at,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w10_completion_if_closed(
                conn=conn,
                site=str(row["site"]),
                actor_username=actor_username,
                checked_at=now,
                reason="tracker_item_updated",
            )
            updated = conn.execute(
                select(adoption_w10_tracker_items).where(adoption_w10_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
        if updated is None:
            raise HTTPException(status_code=500, detail="Failed to update W10 tracker item")
        model = _row_to_w10_tracker_item_model(updated)
        _write_audit_log(
            principal=principal,
            action="w10_tracker_item_update",
            resource_type="adoption_w10_tracker_item",
            resource_id=str(model.id),
            detail={
                "site": model.site,
                "status": model.status,
                "assignee": model.assignee,
                "completion_checked": model.completion_checked,
            },
        )
        return model
    
    
    @router.post("/w10/tracker/items/{tracker_item_id}/evidence", response_model=W10EvidenceRead, status_code=201)
    async def upload_w10_tracker_evidence(
        tracker_item_id: int,
        file: UploadFile = File(...),
        note: str = Form(default=""),
        principal: dict[str, Any] = Depends(require_permission("adoption_w10:write")),
    ) -> W10EvidenceRead:
        file_name = _safe_download_filename(file.filename or "", fallback="evidence.bin", max_length=120)
        content_type = (file.content_type or "application/octet-stream").strip() or "application/octet-stream"
        content_type = content_type[:120].lower()
        if not _is_allowed_evidence_content_type(content_type):
            raise HTTPException(status_code=415, detail="Unsupported evidence content type")
        file_bytes = await file.read(W10_EVIDENCE_MAX_BYTES + 1)
        await file.close()
        if len(file_bytes) == 0:
            raise HTTPException(status_code=400, detail="Empty evidence file is not allowed")
        if len(file_bytes) > W10_EVIDENCE_MAX_BYTES:
            raise HTTPException(status_code=413, detail=f"Evidence file too large (max {W10_EVIDENCE_MAX_BYTES} bytes)")
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
            tracker_row = conn.execute(
                select(adoption_w10_tracker_items).where(adoption_w10_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W10 tracker item not found")
            site = str(tracker_row["site"])
            _require_site_access(principal, site)
    
            result = conn.execute(
                insert(adoption_w10_evidence_files).values(
                    tracker_item_id=tracker_item_id,
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
            next_count = int(tracker_row.get("evidence_count") or 0) + 1
            conn.execute(
                update(adoption_w10_tracker_items)
                .where(adoption_w10_tracker_items.c.id == tracker_item_id)
                .values(
                    evidence_count=next_count,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w10_completion_if_closed(
                conn=conn,
                site=site,
                actor_username=actor_username,
                checked_at=now,
                reason="evidence_uploaded",
            )
            evidence_row = conn.execute(
                select(adoption_w10_evidence_files).where(adoption_w10_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
    
        if evidence_row is None:
            raise HTTPException(status_code=500, detail="Failed to save evidence file")
        model = _row_to_w10_evidence_model(evidence_row)
        _write_audit_log(
            principal=principal,
            action="w10_tracker_evidence_upload",
            resource_type="adoption_w10_evidence",
            resource_id=str(model.id),
            detail={
                "tracker_item_id": model.tracker_item_id,
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
    
    
    @router.get("/w10/tracker/items/{tracker_item_id}/evidence", response_model=list[W10EvidenceRead])
    def list_w10_tracker_evidence(
        tracker_item_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w10:read")),
    ) -> list[W10EvidenceRead]:
        with get_conn() as conn:
            tracker_row = conn.execute(
                select(adoption_w10_tracker_items).where(adoption_w10_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W10 tracker item not found")
            _require_site_access(principal, str(tracker_row["site"]))
    
            rows = conn.execute(
                select(adoption_w10_evidence_files)
                .where(adoption_w10_evidence_files.c.tracker_item_id == tracker_item_id)
                .order_by(adoption_w10_evidence_files.c.uploaded_at.desc(), adoption_w10_evidence_files.c.id.desc())
            ).mappings().all()
        return [_row_to_w10_evidence_model(row) for row in rows]
    
    
    @router.get("/w10/tracker/evidence/{evidence_id}/download", response_model=None)
    def download_w10_tracker_evidence(
        evidence_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w10:read")),
    ) -> Response:
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w10_evidence_files).where(adoption_w10_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="W10 evidence not found")
    
        site = str(row["site"])
        _require_site_access(principal, site)
        content_type = str(row.get("content_type") or "application/octet-stream")
        file_name = _safe_download_filename(str(row.get("file_name") or ""), fallback="evidence.bin", max_length=120)
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
            action="w10_tracker_evidence_download",
            resource_type="adoption_w10_evidence",
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
    
    
    @router.post("/w11/tracker/bootstrap", response_model=W11TrackerBootstrapResponse)
    def bootstrap_w11_tracker_items(
        payload: W11TrackerBootstrapRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w11:write")),
    ) -> W11TrackerBootstrapResponse:
        _require_site_access(principal, payload.site)
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        catalog = _adoption_w11_catalog_items(payload.site)
        created_count = 0
    
        with get_conn() as conn:
            existing_rows = conn.execute(
                select(
                    adoption_w11_tracker_items.c.item_type,
                    adoption_w11_tracker_items.c.item_key,
                ).where(adoption_w11_tracker_items.c.site == payload.site)
            ).mappings().all()
            existing_keys = {(str(row["item_type"]), str(row["item_key"])) for row in existing_rows}
    
            for entry in catalog:
                key = (str(entry["item_type"]), str(entry["item_key"]))
                if key in existing_keys:
                    continue
                conn.execute(
                    insert(adoption_w11_tracker_items).values(
                        site=payload.site,
                        item_type=str(entry["item_type"]),
                        item_key=str(entry["item_key"]),
                        item_name=str(entry["item_name"]),
                        assignee=None,
                        status=W11_TRACKER_STATUS_PENDING,
                        completion_checked=False,
                        completion_note="",
                        due_at=entry.get("due_at"),
                        completed_at=None,
                        evidence_count=0,
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
                existing_keys.add(key)
                created_count += 1
    
            if created_count > 0:
                _reset_w11_completion_if_closed(
                    conn=conn,
                    site=payload.site,
                    actor_username=actor_username,
                    checked_at=now,
                    reason="bootstrap_added_items",
                )
    
            rows = conn.execute(
                select(adoption_w11_tracker_items)
                .where(adoption_w11_tracker_items.c.site == payload.site)
                .order_by(
                    adoption_w11_tracker_items.c.item_type.asc(),
                    adoption_w11_tracker_items.c.item_key.asc(),
                    adoption_w11_tracker_items.c.id.asc(),
                )
            ).mappings().all()
    
        items = [_row_to_w11_tracker_item_model(row) for row in rows]
        _write_audit_log(
            principal=principal,
            action="w11_tracker_bootstrap",
            resource_type="adoption_w11_tracker",
            resource_id=payload.site,
            detail={"site": payload.site, "created_count": created_count, "total_count": len(items)},
        )
        return W11TrackerBootstrapResponse(
            site=payload.site,
            created_count=created_count,
            total_count=len(items),
            items=items,
        )
    
    
    @router.get("/w11/tracker/items", response_model=list[W11TrackerItemRead])
    def list_w11_tracker_items(
        site: Annotated[str | None, Query()] = None,
        status: Annotated[str | None, Query()] = None,
        item_type: Annotated[str | None, Query()] = None,
        assignee: Annotated[str | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
        offset: Annotated[int, Query(ge=0)] = 0,
        principal: dict[str, Any] = Depends(require_permission("adoption_w11:read")),
    ) -> list[W11TrackerItemRead]:
        _require_site_access(principal, site)
        normalized_status = status.strip().lower() if status is not None else None
        if normalized_status is not None and normalized_status not in W11_TRACKER_STATUS_SET:
            raise HTTPException(status_code=400, detail="Invalid W11 tracker status")
    
        stmt = select(adoption_w11_tracker_items)
        if site is not None:
            stmt = stmt.where(adoption_w11_tracker_items.c.site == site)
        else:
            allowed_sites = _allowed_sites_for_principal(principal)
            if allowed_sites is not None:
                if not allowed_sites:
                    return []
                stmt = stmt.where(adoption_w11_tracker_items.c.site.in_(allowed_sites))
    
        if normalized_status is not None:
            stmt = stmt.where(adoption_w11_tracker_items.c.status == normalized_status)
        if item_type is not None:
            stmt = stmt.where(adoption_w11_tracker_items.c.item_type == item_type.strip())
        if assignee is not None:
            stmt = stmt.where(adoption_w11_tracker_items.c.assignee == assignee.strip())
    
        stmt = stmt.order_by(
            adoption_w11_tracker_items.c.updated_at.desc(),
            adoption_w11_tracker_items.c.id.desc(),
        ).limit(limit).offset(offset)
    
        with get_conn() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [_row_to_w11_tracker_item_model(row) for row in rows]
    
    
    @router.get("/w11/tracker/overview", response_model=W11TrackerOverviewRead)
    def get_w11_tracker_overview(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w11:read")),
    ) -> W11TrackerOverviewRead:
        _require_site_access(principal, site)
        with get_conn() as conn:
            rows = conn.execute(
                select(adoption_w11_tracker_items).where(adoption_w11_tracker_items.c.site == site)
            ).mappings().all()
        models = [_row_to_w11_tracker_item_model(row) for row in rows]
        return _compute_w11_tracker_overview(site, models)
    
    
    @router.get("/w11/tracker/readiness", response_model=W11TrackerReadinessRead)
    def get_w11_tracker_readiness(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w11:read")),
    ) -> W11TrackerReadinessRead:
        _require_site_access(principal, site)
        models = _load_w11_tracker_items_for_site(site)
        return _compute_w11_tracker_readiness(site=site, rows=models)
    
    
    @router.get("/w11/tracker/completion", response_model=W11TrackerCompletionRead)
    def get_w11_tracker_completion(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w11:read")),
    ) -> W11TrackerCompletionRead:
        _require_site_access(principal, site)
        now = datetime.now(timezone.utc)
        models = _load_w11_tracker_items_for_site(site)
        readiness = _compute_w11_tracker_readiness(site=site, rows=models, checked_at=now)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w11_site_runs).where(adoption_w11_site_runs.c.site == site).limit(1)
            ).mappings().first()
        return _row_to_w11_completion_model(site=site, readiness=readiness, row=row)
    
    
    @router.post("/w11/tracker/complete", response_model=W11TrackerCompletionRead)
    def complete_w11_tracker(
        payload: W11TrackerCompletionRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w11:write")),
    ) -> W11TrackerCompletionRead:
        _require_site_access(principal, payload.site)
        if payload.force and not _has_permission(principal, "admins:manage"):
            raise HTTPException(status_code=403, detail="force completion requires admins:manage")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        models = _load_w11_tracker_items_for_site(payload.site)
        readiness = _compute_w11_tracker_readiness(site=payload.site, rows=models, checked_at=now)
        if not readiness.ready and not payload.force:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "W11 completion gate failed",
                    "site": payload.site,
                    "ready": readiness.ready,
                    "blockers": readiness.blockers,
                    "readiness": readiness.model_dump(mode="json"),
                },
            )
    
        completion_note = (payload.completion_note or "").strip()
        next_status = (
            W11_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS
            if payload.force and not readiness.ready
            else W11_SITE_COMPLETION_STATUS_COMPLETED
        )
        with get_conn() as conn:
            existing = conn.execute(
                select(adoption_w11_site_runs).where(adoption_w11_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
            if existing is None:
                conn.execute(
                    insert(adoption_w11_site_runs).values(
                        site=payload.site,
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                conn.execute(
                    update(adoption_w11_site_runs)
                    .where(adoption_w11_site_runs.c.site == payload.site)
                    .values(
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        updated_by=actor_username,
                        updated_at=now,
                    )
                )
            row = conn.execute(
                select(adoption_w11_site_runs).where(adoption_w11_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
    
        model = _row_to_w11_completion_model(site=payload.site, readiness=readiness, row=row)
        _write_audit_log(
            principal=principal,
            action="w11_tracker_complete",
            resource_type="adoption_w11_tracker_site",
            resource_id=payload.site,
            detail={
                "site": payload.site,
                "status": model.status,
                "ready": readiness.ready,
                "force_used": model.force_used,
                "blockers": readiness.blockers,
                "completion_rate_percent": readiness.completion_rate_percent,
                "missing_required_evidence_count": readiness.missing_required_evidence_count,
            },
        )
        return model
    
    
    @router.patch("/w11/tracker/items/{tracker_item_id}", response_model=W11TrackerItemRead)
    def update_w11_tracker_item(
        tracker_item_id: int,
        payload: W11TrackerItemUpdate,
        principal: dict[str, Any] = Depends(require_permission("adoption_w11:write")),
    ) -> W11TrackerItemRead:
        has_update = (
            payload.assignee is not None
            or payload.status is not None
            or payload.completion_checked is not None
            or payload.completion_note is not None
        )
        if not has_update:
            raise HTTPException(status_code=400, detail="No update fields provided")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w11_tracker_items).where(adoption_w11_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if row is None:
                raise HTTPException(status_code=404, detail="W11 tracker item not found")
            _require_site_access(principal, str(row["site"]))
    
            next_assignee = row.get("assignee")
            if payload.assignee is not None:
                normalized_assignee = payload.assignee.strip()
                next_assignee = normalized_assignee or None
    
            next_status = str(row["status"])
            if payload.status is not None:
                next_status = str(payload.status)
    
            next_checked = bool(row.get("completion_checked", False))
            if payload.completion_checked is not None:
                next_checked = bool(payload.completion_checked)
    
            if next_status == W11_TRACKER_STATUS_DONE:
                next_checked = True
            elif payload.status is not None and payload.status != W11_TRACKER_STATUS_DONE and payload.completion_checked is None:
                next_checked = False
            if payload.completion_checked is True:
                next_status = W11_TRACKER_STATUS_DONE
            elif payload.completion_checked is False and next_status == W11_TRACKER_STATUS_DONE:
                next_status = W11_TRACKER_STATUS_IN_PROGRESS
    
            if next_status not in W11_TRACKER_STATUS_SET:
                raise HTTPException(status_code=400, detail="Invalid W11 tracker status")
    
            next_note = str(row.get("completion_note") or "")
            if payload.completion_note is not None:
                next_note = payload.completion_note.strip()
    
            existing_completed_at = _as_optional_datetime(row.get("completed_at"))
            next_completed_at = existing_completed_at
            if next_checked:
                if existing_completed_at is None:
                    next_completed_at = now
            else:
                next_completed_at = None
    
            conn.execute(
                update(adoption_w11_tracker_items)
                .where(adoption_w11_tracker_items.c.id == tracker_item_id)
                .values(
                    assignee=next_assignee,
                    status=next_status,
                    completion_checked=next_checked,
                    completion_note=next_note,
                    completed_at=next_completed_at,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w11_completion_if_closed(
                conn=conn,
                site=str(row["site"]),
                actor_username=actor_username,
                checked_at=now,
                reason="tracker_item_updated",
            )
            updated = conn.execute(
                select(adoption_w11_tracker_items).where(adoption_w11_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
        if updated is None:
            raise HTTPException(status_code=500, detail="Failed to update W11 tracker item")
        model = _row_to_w11_tracker_item_model(updated)
        _write_audit_log(
            principal=principal,
            action="w11_tracker_item_update",
            resource_type="adoption_w11_tracker_item",
            resource_id=str(model.id),
            detail={
                "site": model.site,
                "status": model.status,
                "assignee": model.assignee,
                "completion_checked": model.completion_checked,
            },
        )
        return model
    
    
    @router.post("/w11/tracker/items/{tracker_item_id}/evidence", response_model=W11EvidenceRead, status_code=201)
    async def upload_w11_tracker_evidence(
        tracker_item_id: int,
        file: UploadFile = File(...),
        note: str = Form(default=""),
        principal: dict[str, Any] = Depends(require_permission("adoption_w11:write")),
    ) -> W11EvidenceRead:
        file_name = _safe_download_filename(file.filename or "", fallback="evidence.bin", max_length=120)
        content_type = (file.content_type or "application/octet-stream").strip() or "application/octet-stream"
        content_type = content_type[:120].lower()
        if not _is_allowed_evidence_content_type(content_type):
            raise HTTPException(status_code=415, detail="Unsupported evidence content type")
        file_bytes = await file.read(W11_EVIDENCE_MAX_BYTES + 1)
        await file.close()
        if len(file_bytes) == 0:
            raise HTTPException(status_code=400, detail="Empty evidence file is not allowed")
        if len(file_bytes) > W11_EVIDENCE_MAX_BYTES:
            raise HTTPException(status_code=413, detail=f"Evidence file too large (max {W11_EVIDENCE_MAX_BYTES} bytes)")
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
            tracker_row = conn.execute(
                select(adoption_w11_tracker_items).where(adoption_w11_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W11 tracker item not found")
            site = str(tracker_row["site"])
            _require_site_access(principal, site)
    
            result = conn.execute(
                insert(adoption_w11_evidence_files).values(
                    tracker_item_id=tracker_item_id,
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
            conn.execute(
                update(adoption_w11_tracker_items)
                .where(adoption_w11_tracker_items.c.id == tracker_item_id)
                .values(
                    evidence_count=adoption_w11_tracker_items.c.evidence_count + 1,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w11_completion_if_closed(
                conn=conn,
                site=site,
                actor_username=actor_username,
                checked_at=now,
                reason="evidence_uploaded",
            )
            evidence_row = conn.execute(
                select(adoption_w11_evidence_files).where(adoption_w11_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
    
        if evidence_row is None:
            raise HTTPException(status_code=500, detail="Failed to save evidence file")
        model = _row_to_w11_evidence_model(evidence_row)
        _write_audit_log(
            principal=principal,
            action="w11_tracker_evidence_upload",
            resource_type="adoption_w11_evidence",
            resource_id=str(model.id),
            detail={
                "tracker_item_id": model.tracker_item_id,
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
    
    
    @router.get("/w11/tracker/items/{tracker_item_id}/evidence", response_model=list[W11EvidenceRead])
    def list_w11_tracker_evidence(
        tracker_item_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w11:read")),
    ) -> list[W11EvidenceRead]:
        with get_conn() as conn:
            tracker_row = conn.execute(
                select(adoption_w11_tracker_items).where(adoption_w11_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W11 tracker item not found")
            _require_site_access(principal, str(tracker_row["site"]))
    
            rows = conn.execute(
                select(adoption_w11_evidence_files)
                .where(adoption_w11_evidence_files.c.tracker_item_id == tracker_item_id)
                .order_by(adoption_w11_evidence_files.c.uploaded_at.desc(), adoption_w11_evidence_files.c.id.desc())
            ).mappings().all()
        return [_row_to_w11_evidence_model(row) for row in rows]
    
    
    @router.get("/w11/tracker/evidence/{evidence_id}/download", response_model=None)
    def download_w11_tracker_evidence(
        evidence_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w11:read")),
    ) -> Response:
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w11_evidence_files).where(adoption_w11_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="W11 evidence not found")
    
        site = str(row["site"])
        _require_site_access(principal, site)
        content_type = str(row.get("content_type") or "application/octet-stream")
        file_name = _safe_download_filename(str(row.get("file_name") or ""), fallback="evidence.bin", max_length=120)
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
            action="w11_tracker_evidence_download",
            resource_type="adoption_w11_evidence",
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
    
    
    @router.post("/w12/tracker/bootstrap", response_model=W12TrackerBootstrapResponse)
    def bootstrap_w12_tracker_items(
        payload: W12TrackerBootstrapRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w12:write")),
    ) -> W12TrackerBootstrapResponse:
        _require_site_access(principal, payload.site)
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        catalog = _adoption_w12_catalog_items(payload.site)
        created_count = 0
    
        with get_conn() as conn:
            existing_rows = conn.execute(
                select(
                    adoption_w12_tracker_items.c.item_type,
                    adoption_w12_tracker_items.c.item_key,
                ).where(adoption_w12_tracker_items.c.site == payload.site)
            ).mappings().all()
            existing_keys = {(str(row["item_type"]), str(row["item_key"])) for row in existing_rows}
    
            for entry in catalog:
                key = (str(entry["item_type"]), str(entry["item_key"]))
                if key in existing_keys:
                    continue
                conn.execute(
                    insert(adoption_w12_tracker_items).values(
                        site=payload.site,
                        item_type=str(entry["item_type"]),
                        item_key=str(entry["item_key"]),
                        item_name=str(entry["item_name"]),
                        assignee=None,
                        status=W12_TRACKER_STATUS_PENDING,
                        completion_checked=False,
                        completion_note="",
                        due_at=entry.get("due_at"),
                        completed_at=None,
                        evidence_count=0,
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
                existing_keys.add(key)
                created_count += 1
    
            if created_count > 0:
                _reset_w12_completion_if_closed(
                    conn=conn,
                    site=payload.site,
                    actor_username=actor_username,
                    checked_at=now,
                    reason="bootstrap_added_items",
                )
    
            rows = conn.execute(
                select(adoption_w12_tracker_items)
                .where(adoption_w12_tracker_items.c.site == payload.site)
                .order_by(
                    adoption_w12_tracker_items.c.item_type.asc(),
                    adoption_w12_tracker_items.c.item_key.asc(),
                    adoption_w12_tracker_items.c.id.asc(),
                )
            ).mappings().all()
    
        items = [_row_to_w12_tracker_item_model(row) for row in rows]
        _write_audit_log(
            principal=principal,
            action="w12_tracker_bootstrap",
            resource_type="adoption_w12_tracker",
            resource_id=payload.site,
            detail={"site": payload.site, "created_count": created_count, "total_count": len(items)},
        )
        return W12TrackerBootstrapResponse(
            site=payload.site,
            created_count=created_count,
            total_count=len(items),
            items=items,
        )
    
    
    @router.get("/w12/tracker/items", response_model=list[W12TrackerItemRead])
    def list_w12_tracker_items(
        site: Annotated[str | None, Query()] = None,
        status: Annotated[str | None, Query()] = None,
        item_type: Annotated[str | None, Query()] = None,
        assignee: Annotated[str | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
        offset: Annotated[int, Query(ge=0)] = 0,
        principal: dict[str, Any] = Depends(require_permission("adoption_w12:read")),
    ) -> list[W12TrackerItemRead]:
        _require_site_access(principal, site)
        normalized_status = status.strip().lower() if status is not None else None
        if normalized_status is not None and normalized_status not in W12_TRACKER_STATUS_SET:
            raise HTTPException(status_code=400, detail="Invalid W12 tracker status")
    
        stmt = select(adoption_w12_tracker_items)
        if site is not None:
            stmt = stmt.where(adoption_w12_tracker_items.c.site == site)
        else:
            allowed_sites = _allowed_sites_for_principal(principal)
            if allowed_sites is not None:
                if not allowed_sites:
                    return []
                stmt = stmt.where(adoption_w12_tracker_items.c.site.in_(allowed_sites))
    
        if normalized_status is not None:
            stmt = stmt.where(adoption_w12_tracker_items.c.status == normalized_status)
        if item_type is not None:
            stmt = stmt.where(adoption_w12_tracker_items.c.item_type == item_type.strip())
        if assignee is not None:
            stmt = stmt.where(adoption_w12_tracker_items.c.assignee == assignee.strip())
    
        stmt = stmt.order_by(
            adoption_w12_tracker_items.c.updated_at.desc(),
            adoption_w12_tracker_items.c.id.desc(),
        ).limit(limit).offset(offset)
    
        with get_conn() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [_row_to_w12_tracker_item_model(row) for row in rows]
    
    
    @router.get("/w12/tracker/overview", response_model=W12TrackerOverviewRead)
    def get_w12_tracker_overview(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w12:read")),
    ) -> W12TrackerOverviewRead:
        _require_site_access(principal, site)
        with get_conn() as conn:
            rows = conn.execute(
                select(adoption_w12_tracker_items).where(adoption_w12_tracker_items.c.site == site)
            ).mappings().all()
        models = [_row_to_w12_tracker_item_model(row) for row in rows]
        return _compute_w12_tracker_overview(site, models)
    
    
    @router.get("/w12/tracker/readiness", response_model=W12TrackerReadinessRead)
    def get_w12_tracker_readiness(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w12:read")),
    ) -> W12TrackerReadinessRead:
        _require_site_access(principal, site)
        models = _load_w12_tracker_items_for_site(site)
        return _compute_w12_tracker_readiness(site=site, rows=models)
    
    
    @router.get("/w12/tracker/completion", response_model=W12TrackerCompletionRead)
    def get_w12_tracker_completion(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w12:read")),
    ) -> W12TrackerCompletionRead:
        _require_site_access(principal, site)
        now = datetime.now(timezone.utc)
        models = _load_w12_tracker_items_for_site(site)
        readiness = _compute_w12_tracker_readiness(site=site, rows=models, checked_at=now)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w12_site_runs).where(adoption_w12_site_runs.c.site == site).limit(1)
            ).mappings().first()
        return _row_to_w12_completion_model(site=site, readiness=readiness, row=row)
    
    
    @router.post("/w12/tracker/complete", response_model=W12TrackerCompletionRead)
    def complete_w12_tracker(
        payload: W12TrackerCompletionRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w12:write")),
    ) -> W12TrackerCompletionRead:
        _require_site_access(principal, payload.site)
        if payload.force and not _has_permission(principal, "admins:manage"):
            raise HTTPException(status_code=403, detail="force completion requires admins:manage")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        models = _load_w12_tracker_items_for_site(payload.site)
        readiness = _compute_w12_tracker_readiness(site=payload.site, rows=models, checked_at=now)
        if not readiness.ready and not payload.force:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "W12 completion gate failed",
                    "site": payload.site,
                    "ready": readiness.ready,
                    "blockers": readiness.blockers,
                    "readiness": readiness.model_dump(mode="json"),
                },
            )
    
        completion_note = (payload.completion_note or "").strip()
        next_status = (
            W12_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS
            if payload.force and not readiness.ready
            else W12_SITE_COMPLETION_STATUS_COMPLETED
        )
        with get_conn() as conn:
            existing = conn.execute(
                select(adoption_w12_site_runs).where(adoption_w12_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
            if existing is None:
                conn.execute(
                    insert(adoption_w12_site_runs).values(
                        site=payload.site,
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                conn.execute(
                    update(adoption_w12_site_runs)
                    .where(adoption_w12_site_runs.c.site == payload.site)
                    .values(
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        updated_by=actor_username,
                        updated_at=now,
                    )
                )
            row = conn.execute(
                select(adoption_w12_site_runs).where(adoption_w12_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
    
        model = _row_to_w12_completion_model(site=payload.site, readiness=readiness, row=row)
        _write_audit_log(
            principal=principal,
            action="w12_tracker_complete",
            resource_type="adoption_w12_tracker_site",
            resource_id=payload.site,
            detail={
                "site": payload.site,
                "status": model.status,
                "ready": readiness.ready,
                "force_used": model.force_used,
                "blockers": readiness.blockers,
                "completion_rate_percent": readiness.completion_rate_percent,
                "missing_required_evidence_count": readiness.missing_required_evidence_count,
            },
        )
        return model
    
    
    @router.patch("/w12/tracker/items/{tracker_item_id}", response_model=W12TrackerItemRead)
    def update_w12_tracker_item(
        tracker_item_id: int,
        payload: W12TrackerItemUpdate,
        principal: dict[str, Any] = Depends(require_permission("adoption_w12:write")),
    ) -> W12TrackerItemRead:
        has_update = (
            payload.assignee is not None
            or payload.status is not None
            or payload.completion_checked is not None
            or payload.completion_note is not None
        )
        if not has_update:
            raise HTTPException(status_code=400, detail="No update fields provided")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w12_tracker_items).where(adoption_w12_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if row is None:
                raise HTTPException(status_code=404, detail="W12 tracker item not found")
            _require_site_access(principal, str(row["site"]))
    
            next_assignee = row.get("assignee")
            if payload.assignee is not None:
                normalized_assignee = payload.assignee.strip()
                next_assignee = normalized_assignee or None
    
            next_status = str(row["status"])
            if payload.status is not None:
                next_status = str(payload.status)
    
            next_checked = bool(row.get("completion_checked", False))
            if payload.completion_checked is not None:
                next_checked = bool(payload.completion_checked)
    
            if next_status == W12_TRACKER_STATUS_DONE:
                next_checked = True
            elif payload.status is not None and payload.status != W12_TRACKER_STATUS_DONE and payload.completion_checked is None:
                next_checked = False
            if payload.completion_checked is True:
                next_status = W12_TRACKER_STATUS_DONE
            elif payload.completion_checked is False and next_status == W12_TRACKER_STATUS_DONE:
                next_status = W12_TRACKER_STATUS_IN_PROGRESS
    
            if next_status not in W12_TRACKER_STATUS_SET:
                raise HTTPException(status_code=400, detail="Invalid W12 tracker status")
    
            next_note = str(row.get("completion_note") or "")
            if payload.completion_note is not None:
                next_note = payload.completion_note.strip()
    
            existing_completed_at = _as_optional_datetime(row.get("completed_at"))
            next_completed_at = existing_completed_at
            if next_checked:
                if existing_completed_at is None:
                    next_completed_at = now
            else:
                next_completed_at = None
    
            conn.execute(
                update(adoption_w12_tracker_items)
                .where(adoption_w12_tracker_items.c.id == tracker_item_id)
                .values(
                    assignee=next_assignee,
                    status=next_status,
                    completion_checked=next_checked,
                    completion_note=next_note,
                    completed_at=next_completed_at,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w12_completion_if_closed(
                conn=conn,
                site=str(row["site"]),
                actor_username=actor_username,
                checked_at=now,
                reason="tracker_item_updated",
            )
            updated = conn.execute(
                select(adoption_w12_tracker_items).where(adoption_w12_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
        if updated is None:
            raise HTTPException(status_code=500, detail="Failed to update W12 tracker item")
        model = _row_to_w12_tracker_item_model(updated)
        _write_audit_log(
            principal=principal,
            action="w12_tracker_item_update",
            resource_type="adoption_w12_tracker_item",
            resource_id=str(model.id),
            detail={
                "site": model.site,
                "status": model.status,
                "assignee": model.assignee,
                "completion_checked": model.completion_checked,
            },
        )
        return model
    
    
    @router.post("/w12/tracker/items/{tracker_item_id}/evidence", response_model=W12EvidenceRead, status_code=201)
    async def upload_w12_tracker_evidence(
        tracker_item_id: int,
        file: UploadFile = File(...),
        note: str = Form(default=""),
        principal: dict[str, Any] = Depends(require_permission("adoption_w12:write")),
    ) -> W12EvidenceRead:
        file_name = _safe_download_filename(file.filename or "", fallback="evidence.bin", max_length=120)
        content_type = (file.content_type or "application/octet-stream").strip() or "application/octet-stream"
        content_type = content_type[:120].lower()
        if not _is_allowed_evidence_content_type(content_type):
            raise HTTPException(status_code=415, detail="Unsupported evidence content type")
        file_bytes = await file.read(W12_EVIDENCE_MAX_BYTES + 1)
        await file.close()
        if len(file_bytes) == 0:
            raise HTTPException(status_code=400, detail="Empty evidence file is not allowed")
        if len(file_bytes) > W12_EVIDENCE_MAX_BYTES:
            raise HTTPException(status_code=413, detail=f"Evidence file too large (max {W12_EVIDENCE_MAX_BYTES} bytes)")
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
            tracker_row = conn.execute(
                select(adoption_w12_tracker_items).where(adoption_w12_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W12 tracker item not found")
            site = str(tracker_row["site"])
            _require_site_access(principal, site)
    
            result = conn.execute(
                insert(adoption_w12_evidence_files).values(
                    tracker_item_id=tracker_item_id,
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
            conn.execute(
                update(adoption_w12_tracker_items)
                .where(adoption_w12_tracker_items.c.id == tracker_item_id)
                .values(
                    evidence_count=adoption_w12_tracker_items.c.evidence_count + 1,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w12_completion_if_closed(
                conn=conn,
                site=site,
                actor_username=actor_username,
                checked_at=now,
                reason="evidence_uploaded",
            )
            evidence_row = conn.execute(
                select(adoption_w12_evidence_files).where(adoption_w12_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
    
        if evidence_row is None:
            raise HTTPException(status_code=500, detail="Failed to save evidence file")
        model = _row_to_w12_evidence_model(evidence_row)
        _write_audit_log(
            principal=principal,
            action="w12_tracker_evidence_upload",
            resource_type="adoption_w12_evidence",
            resource_id=str(model.id),
            detail={
                "tracker_item_id": model.tracker_item_id,
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
    
    
    @router.get("/w12/tracker/items/{tracker_item_id}/evidence", response_model=list[W12EvidenceRead])
    def list_w12_tracker_evidence(
        tracker_item_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w12:read")),
    ) -> list[W12EvidenceRead]:
        with get_conn() as conn:
            tracker_row = conn.execute(
                select(adoption_w12_tracker_items).where(adoption_w12_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W12 tracker item not found")
            _require_site_access(principal, str(tracker_row["site"]))
    
            rows = conn.execute(
                select(adoption_w12_evidence_files)
                .where(adoption_w12_evidence_files.c.tracker_item_id == tracker_item_id)
                .order_by(adoption_w12_evidence_files.c.uploaded_at.desc(), adoption_w12_evidence_files.c.id.desc())
            ).mappings().all()
        return [_row_to_w12_evidence_model(row) for row in rows]
    
    
    @router.get("/w12/tracker/evidence/{evidence_id}/download", response_model=None)
    def download_w12_tracker_evidence(
        evidence_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w12:read")),
    ) -> Response:
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w12_evidence_files).where(adoption_w12_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="W12 evidence not found")
    
        site = str(row["site"])
        _require_site_access(principal, site)
        content_type = str(row.get("content_type") or "application/octet-stream")
        file_name = _safe_download_filename(str(row.get("file_name") or ""), fallback="evidence.bin", max_length=120)
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
            action="w12_tracker_evidence_download",
            resource_type="adoption_w12_evidence",
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
    
    
    @router.post("/w13/tracker/bootstrap", response_model=W13TrackerBootstrapResponse)
    def bootstrap_w13_tracker_items(
        payload: W13TrackerBootstrapRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w13:write")),
    ) -> W13TrackerBootstrapResponse:
        _require_site_access(principal, payload.site)
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        catalog = _adoption_w13_catalog_items(payload.site)
        created_count = 0
    
        with get_conn() as conn:
            existing_rows = conn.execute(
                select(
                    adoption_w13_tracker_items.c.item_type,
                    adoption_w13_tracker_items.c.item_key,
                ).where(adoption_w13_tracker_items.c.site == payload.site)
            ).mappings().all()
            existing_keys = {(str(row["item_type"]), str(row["item_key"])) for row in existing_rows}
    
            for entry in catalog:
                key = (str(entry["item_type"]), str(entry["item_key"]))
                if key in existing_keys:
                    continue
                conn.execute(
                    insert(adoption_w13_tracker_items).values(
                        site=payload.site,
                        item_type=str(entry["item_type"]),
                        item_key=str(entry["item_key"]),
                        item_name=str(entry["item_name"]),
                        assignee=None,
                        status=W13_TRACKER_STATUS_PENDING,
                        completion_checked=False,
                        completion_note="",
                        due_at=entry.get("due_at"),
                        completed_at=None,
                        evidence_count=0,
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
                existing_keys.add(key)
                created_count += 1
    
            if created_count > 0:
                _reset_w13_completion_if_closed(
                    conn=conn,
                    site=payload.site,
                    actor_username=actor_username,
                    checked_at=now,
                    reason="bootstrap_added_items",
                )
    
            rows = conn.execute(
                select(adoption_w13_tracker_items)
                .where(adoption_w13_tracker_items.c.site == payload.site)
                .order_by(
                    adoption_w13_tracker_items.c.item_type.asc(),
                    adoption_w13_tracker_items.c.item_key.asc(),
                    adoption_w13_tracker_items.c.id.asc(),
                )
            ).mappings().all()
    
        items = [_row_to_w13_tracker_item_model(row) for row in rows]
        _write_audit_log(
            principal=principal,
            action="w13_tracker_bootstrap",
            resource_type="adoption_w13_tracker",
            resource_id=payload.site,
            detail={"site": payload.site, "created_count": created_count, "total_count": len(items)},
        )
        return W13TrackerBootstrapResponse(
            site=payload.site,
            created_count=created_count,
            total_count=len(items),
            items=items,
        )
    
    
    @router.get("/w13/tracker/items", response_model=list[W13TrackerItemRead])
    def list_w13_tracker_items(
        site: Annotated[str | None, Query()] = None,
        status: Annotated[str | None, Query()] = None,
        item_type: Annotated[str | None, Query()] = None,
        assignee: Annotated[str | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
        offset: Annotated[int, Query(ge=0)] = 0,
        principal: dict[str, Any] = Depends(require_permission("adoption_w13:read")),
    ) -> list[W13TrackerItemRead]:
        _require_site_access(principal, site)
        normalized_status = status.strip().lower() if status is not None else None
        if normalized_status is not None and normalized_status not in W13_TRACKER_STATUS_SET:
            raise HTTPException(status_code=400, detail="Invalid W13 tracker status")
    
        stmt = select(adoption_w13_tracker_items)
        if site is not None:
            stmt = stmt.where(adoption_w13_tracker_items.c.site == site)
        else:
            allowed_sites = _allowed_sites_for_principal(principal)
            if allowed_sites is not None:
                if not allowed_sites:
                    return []
                stmt = stmt.where(adoption_w13_tracker_items.c.site.in_(allowed_sites))
    
        if normalized_status is not None:
            stmt = stmt.where(adoption_w13_tracker_items.c.status == normalized_status)
        if item_type is not None:
            stmt = stmt.where(adoption_w13_tracker_items.c.item_type == item_type.strip())
        if assignee is not None:
            stmt = stmt.where(adoption_w13_tracker_items.c.assignee == assignee.strip())
    
        stmt = stmt.order_by(
            adoption_w13_tracker_items.c.updated_at.desc(),
            adoption_w13_tracker_items.c.id.desc(),
        ).limit(limit).offset(offset)
    
        with get_conn() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [_row_to_w13_tracker_item_model(row) for row in rows]
    
    
    @router.get("/w13/tracker/overview", response_model=W13TrackerOverviewRead)
    def get_w13_tracker_overview(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w13:read")),
    ) -> W13TrackerOverviewRead:
        _require_site_access(principal, site)
        with get_conn() as conn:
            rows = conn.execute(
                select(adoption_w13_tracker_items).where(adoption_w13_tracker_items.c.site == site)
            ).mappings().all()
        models = [_row_to_w13_tracker_item_model(row) for row in rows]
        return _compute_w13_tracker_overview(site, models)
    
    
    @router.get("/w13/tracker/readiness", response_model=W13TrackerReadinessRead)
    def get_w13_tracker_readiness(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w13:read")),
    ) -> W13TrackerReadinessRead:
        _require_site_access(principal, site)
        models = _load_w13_tracker_items_for_site(site)
        return _compute_w13_tracker_readiness(site=site, rows=models)
    
    
    @router.get("/w13/tracker/completion", response_model=W13TrackerCompletionRead)
    def get_w13_tracker_completion(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w13:read")),
    ) -> W13TrackerCompletionRead:
        _require_site_access(principal, site)
        now = datetime.now(timezone.utc)
        models = _load_w13_tracker_items_for_site(site)
        readiness = _compute_w13_tracker_readiness(site=site, rows=models, checked_at=now)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w13_site_runs).where(adoption_w13_site_runs.c.site == site).limit(1)
            ).mappings().first()
        return _row_to_w13_completion_model(site=site, readiness=readiness, row=row)
    
    
    @router.post("/w13/tracker/complete", response_model=W13TrackerCompletionRead)
    def complete_w13_tracker(
        payload: W13TrackerCompletionRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w13:write")),
    ) -> W13TrackerCompletionRead:
        _require_site_access(principal, payload.site)
        if payload.force and not _has_permission(principal, "admins:manage"):
            raise HTTPException(status_code=403, detail="force completion requires admins:manage")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        models = _load_w13_tracker_items_for_site(payload.site)
        readiness = _compute_w13_tracker_readiness(site=payload.site, rows=models, checked_at=now)
        if not readiness.ready and not payload.force:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "W13 completion gate failed",
                    "site": payload.site,
                    "ready": readiness.ready,
                    "blockers": readiness.blockers,
                    "readiness": readiness.model_dump(mode="json"),
                },
            )
    
        completion_note = (payload.completion_note or "").strip()
        next_status = (
            W13_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS
            if payload.force and not readiness.ready
            else W13_SITE_COMPLETION_STATUS_COMPLETED
        )
        with get_conn() as conn:
            existing = conn.execute(
                select(adoption_w13_site_runs).where(adoption_w13_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
            if existing is None:
                conn.execute(
                    insert(adoption_w13_site_runs).values(
                        site=payload.site,
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                conn.execute(
                    update(adoption_w13_site_runs)
                    .where(adoption_w13_site_runs.c.site == payload.site)
                    .values(
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        updated_by=actor_username,
                        updated_at=now,
                    )
                )
            row = conn.execute(
                select(adoption_w13_site_runs).where(adoption_w13_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
    
        model = _row_to_w13_completion_model(site=payload.site, readiness=readiness, row=row)
        _write_audit_log(
            principal=principal,
            action="w13_tracker_complete",
            resource_type="adoption_w13_tracker_site",
            resource_id=payload.site,
            detail={
                "site": payload.site,
                "status": model.status,
                "ready": readiness.ready,
                "force_used": model.force_used,
                "blockers": readiness.blockers,
                "completion_rate_percent": readiness.completion_rate_percent,
                "missing_required_evidence_count": readiness.missing_required_evidence_count,
            },
        )
        return model
    
    
    @router.patch("/w13/tracker/items/{tracker_item_id}", response_model=W13TrackerItemRead)
    def update_w13_tracker_item(
        tracker_item_id: int,
        payload: W13TrackerItemUpdate,
        principal: dict[str, Any] = Depends(require_permission("adoption_w13:write")),
    ) -> W13TrackerItemRead:
        has_update = (
            payload.assignee is not None
            or payload.status is not None
            or payload.completion_checked is not None
            or payload.completion_note is not None
        )
        if not has_update:
            raise HTTPException(status_code=400, detail="No update fields provided")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w13_tracker_items).where(adoption_w13_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if row is None:
                raise HTTPException(status_code=404, detail="W13 tracker item not found")
            _require_site_access(principal, str(row["site"]))
    
            next_assignee = row.get("assignee")
            if payload.assignee is not None:
                normalized_assignee = payload.assignee.strip()
                next_assignee = normalized_assignee or None
    
            next_status = str(row["status"])
            if payload.status is not None:
                next_status = str(payload.status)
    
            next_checked = bool(row.get("completion_checked", False))
            if payload.completion_checked is not None:
                next_checked = bool(payload.completion_checked)
    
            if next_status == W13_TRACKER_STATUS_DONE:
                next_checked = True
            elif payload.status is not None and payload.status != W13_TRACKER_STATUS_DONE and payload.completion_checked is None:
                next_checked = False
            if payload.completion_checked is True:
                next_status = W13_TRACKER_STATUS_DONE
            elif payload.completion_checked is False and next_status == W13_TRACKER_STATUS_DONE:
                next_status = W13_TRACKER_STATUS_IN_PROGRESS
    
            if next_status not in W13_TRACKER_STATUS_SET:
                raise HTTPException(status_code=400, detail="Invalid W13 tracker status")
    
            next_note = str(row.get("completion_note") or "")
            if payload.completion_note is not None:
                next_note = payload.completion_note.strip()
    
            existing_completed_at = _as_optional_datetime(row.get("completed_at"))
            next_completed_at = existing_completed_at
            if next_checked:
                if existing_completed_at is None:
                    next_completed_at = now
            else:
                next_completed_at = None
    
            conn.execute(
                update(adoption_w13_tracker_items)
                .where(adoption_w13_tracker_items.c.id == tracker_item_id)
                .values(
                    assignee=next_assignee,
                    status=next_status,
                    completion_checked=next_checked,
                    completion_note=next_note,
                    completed_at=next_completed_at,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w13_completion_if_closed(
                conn=conn,
                site=str(row["site"]),
                actor_username=actor_username,
                checked_at=now,
                reason="tracker_item_updated",
            )
            updated = conn.execute(
                select(adoption_w13_tracker_items).where(adoption_w13_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
        if updated is None:
            raise HTTPException(status_code=500, detail="Failed to update W13 tracker item")
        model = _row_to_w13_tracker_item_model(updated)
        _write_audit_log(
            principal=principal,
            action="w13_tracker_item_update",
            resource_type="adoption_w13_tracker_item",
            resource_id=str(model.id),
            detail={
                "site": model.site,
                "status": model.status,
                "assignee": model.assignee,
                "completion_checked": model.completion_checked,
            },
        )
        return model
    
    
    @router.post("/w13/tracker/items/{tracker_item_id}/evidence", response_model=W13EvidenceRead, status_code=201)
    async def upload_w13_tracker_evidence(
        tracker_item_id: int,
        file: UploadFile = File(...),
        note: str = Form(default=""),
        principal: dict[str, Any] = Depends(require_permission("adoption_w13:write")),
    ) -> W13EvidenceRead:
        file_name = _safe_download_filename(file.filename or "", fallback="evidence.bin", max_length=120)
        content_type = (file.content_type or "application/octet-stream").strip() or "application/octet-stream"
        content_type = content_type[:120].lower()
        if not _is_allowed_evidence_content_type(content_type):
            raise HTTPException(status_code=415, detail="Unsupported evidence content type")
        file_bytes = await file.read(W13_EVIDENCE_MAX_BYTES + 1)
        await file.close()
        if len(file_bytes) == 0:
            raise HTTPException(status_code=400, detail="Empty evidence file is not allowed")
        if len(file_bytes) > W13_EVIDENCE_MAX_BYTES:
            raise HTTPException(status_code=413, detail=f"Evidence file too large (max {W13_EVIDENCE_MAX_BYTES} bytes)")
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
            tracker_row = conn.execute(
                select(adoption_w13_tracker_items).where(adoption_w13_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W13 tracker item not found")
            site = str(tracker_row["site"])
            _require_site_access(principal, site)
    
            result = conn.execute(
                insert(adoption_w13_evidence_files).values(
                    tracker_item_id=tracker_item_id,
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
            conn.execute(
                update(adoption_w13_tracker_items)
                .where(adoption_w13_tracker_items.c.id == tracker_item_id)
                .values(
                    evidence_count=adoption_w13_tracker_items.c.evidence_count + 1,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w13_completion_if_closed(
                conn=conn,
                site=site,
                actor_username=actor_username,
                checked_at=now,
                reason="evidence_uploaded",
            )
            evidence_row = conn.execute(
                select(adoption_w13_evidence_files).where(adoption_w13_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
    
        if evidence_row is None:
            raise HTTPException(status_code=500, detail="Failed to save evidence file")
        model = _row_to_w13_evidence_model(evidence_row)
        _write_audit_log(
            principal=principal,
            action="w13_tracker_evidence_upload",
            resource_type="adoption_w13_evidence",
            resource_id=str(model.id),
            detail={
                "tracker_item_id": model.tracker_item_id,
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
    
    
    @router.get("/w13/tracker/items/{tracker_item_id}/evidence", response_model=list[W13EvidenceRead])
    def list_w13_tracker_evidence(
        tracker_item_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w13:read")),
    ) -> list[W13EvidenceRead]:
        with get_conn() as conn:
            tracker_row = conn.execute(
                select(adoption_w13_tracker_items).where(adoption_w13_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W13 tracker item not found")
            _require_site_access(principal, str(tracker_row["site"]))
    
            rows = conn.execute(
                select(adoption_w13_evidence_files)
                .where(adoption_w13_evidence_files.c.tracker_item_id == tracker_item_id)
                .order_by(adoption_w13_evidence_files.c.uploaded_at.desc(), adoption_w13_evidence_files.c.id.desc())
            ).mappings().all()
        return [_row_to_w13_evidence_model(row) for row in rows]
    
    
    @router.get("/w13/tracker/evidence/{evidence_id}/download", response_model=None)
    def download_w13_tracker_evidence(
        evidence_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w13:read")),
    ) -> Response:
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w13_evidence_files).where(adoption_w13_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="W13 evidence not found")
    
        site = str(row["site"])
        _require_site_access(principal, site)
        content_type = str(row.get("content_type") or "application/octet-stream")
        file_name = _safe_download_filename(str(row.get("file_name") or ""), fallback="evidence.bin", max_length=120)
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
            action="w13_tracker_evidence_download",
            resource_type="adoption_w13_evidence",
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
    
    @router.post("/w14/tracker/bootstrap", response_model=W14TrackerBootstrapResponse)
    def bootstrap_w14_tracker_items(
        payload: W14TrackerBootstrapRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w14:write")),
    ) -> W14TrackerBootstrapResponse:
        _require_site_access(principal, payload.site)
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        catalog = _adoption_w14_catalog_items(payload.site)
        created_count = 0
    
        with get_conn() as conn:
            existing_rows = conn.execute(
                select(
                    adoption_w14_tracker_items.c.item_type,
                    adoption_w14_tracker_items.c.item_key,
                ).where(adoption_w14_tracker_items.c.site == payload.site)
            ).mappings().all()
            existing_keys = {(str(row["item_type"]), str(row["item_key"])) for row in existing_rows}
    
            for entry in catalog:
                key = (str(entry["item_type"]), str(entry["item_key"]))
                if key in existing_keys:
                    continue
                conn.execute(
                    insert(adoption_w14_tracker_items).values(
                        site=payload.site,
                        item_type=str(entry["item_type"]),
                        item_key=str(entry["item_key"]),
                        item_name=str(entry["item_name"]),
                        assignee=None,
                        status=W14_TRACKER_STATUS_PENDING,
                        completion_checked=False,
                        completion_note="",
                        due_at=entry.get("due_at"),
                        completed_at=None,
                        evidence_count=0,
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
                existing_keys.add(key)
                created_count += 1
    
            if created_count > 0:
                _reset_w14_completion_if_closed(
                    conn=conn,
                    site=payload.site,
                    actor_username=actor_username,
                    checked_at=now,
                    reason="bootstrap_added_items",
                )
    
            rows = conn.execute(
                select(adoption_w14_tracker_items)
                .where(adoption_w14_tracker_items.c.site == payload.site)
                .order_by(
                    adoption_w14_tracker_items.c.item_type.asc(),
                    adoption_w14_tracker_items.c.item_key.asc(),
                    adoption_w14_tracker_items.c.id.asc(),
                )
            ).mappings().all()
    
        items = [_row_to_w14_tracker_item_model(row) for row in rows]
        _write_audit_log(
            principal=principal,
            action="w14_tracker_bootstrap",
            resource_type="adoption_w14_tracker",
            resource_id=payload.site,
            detail={"site": payload.site, "created_count": created_count, "total_count": len(items)},
        )
        return W14TrackerBootstrapResponse(
            site=payload.site,
            created_count=created_count,
            total_count=len(items),
            items=items,
        )
    
    
    @router.get("/w14/tracker/items", response_model=list[W14TrackerItemRead])
    def list_w14_tracker_items(
        site: Annotated[str | None, Query()] = None,
        status: Annotated[str | None, Query()] = None,
        item_type: Annotated[str | None, Query()] = None,
        assignee: Annotated[str | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
        offset: Annotated[int, Query(ge=0)] = 0,
        principal: dict[str, Any] = Depends(require_permission("adoption_w14:read")),
    ) -> list[W14TrackerItemRead]:
        _require_site_access(principal, site)
        normalized_status = status.strip().lower() if status is not None else None
        if normalized_status is not None and normalized_status not in W14_TRACKER_STATUS_SET:
            raise HTTPException(status_code=400, detail="Invalid W14 tracker status")
    
        stmt = select(adoption_w14_tracker_items)
        if site is not None:
            stmt = stmt.where(adoption_w14_tracker_items.c.site == site)
        else:
            allowed_sites = _allowed_sites_for_principal(principal)
            if allowed_sites is not None:
                if not allowed_sites:
                    return []
                stmt = stmt.where(adoption_w14_tracker_items.c.site.in_(allowed_sites))
    
        if normalized_status is not None:
            stmt = stmt.where(adoption_w14_tracker_items.c.status == normalized_status)
        if item_type is not None:
            stmt = stmt.where(adoption_w14_tracker_items.c.item_type == item_type.strip())
        if assignee is not None:
            stmt = stmt.where(adoption_w14_tracker_items.c.assignee == assignee.strip())
    
        stmt = stmt.order_by(
            adoption_w14_tracker_items.c.updated_at.desc(),
            adoption_w14_tracker_items.c.id.desc(),
        ).limit(limit).offset(offset)
    
        with get_conn() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [_row_to_w14_tracker_item_model(row) for row in rows]
    
    
    @router.get("/w14/tracker/overview", response_model=W14TrackerOverviewRead)
    def get_w14_tracker_overview(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w14:read")),
    ) -> W14TrackerOverviewRead:
        _require_site_access(principal, site)
        with get_conn() as conn:
            rows = conn.execute(
                select(adoption_w14_tracker_items).where(adoption_w14_tracker_items.c.site == site)
            ).mappings().all()
        models = [_row_to_w14_tracker_item_model(row) for row in rows]
        return _compute_w14_tracker_overview(site, models)
    
    
    @router.get("/w14/tracker/readiness", response_model=W14TrackerReadinessRead)
    def get_w14_tracker_readiness(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w14:read")),
    ) -> W14TrackerReadinessRead:
        _require_site_access(principal, site)
        models = _load_w14_tracker_items_for_site(site)
        return _compute_w14_tracker_readiness(site=site, rows=models)
    
    
    @router.get("/w14/tracker/completion", response_model=W14TrackerCompletionRead)
    def get_w14_tracker_completion(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w14:read")),
    ) -> W14TrackerCompletionRead:
        _require_site_access(principal, site)
        now = datetime.now(timezone.utc)
        models = _load_w14_tracker_items_for_site(site)
        readiness = _compute_w14_tracker_readiness(site=site, rows=models, checked_at=now)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w14_site_runs).where(adoption_w14_site_runs.c.site == site).limit(1)
            ).mappings().first()
        return _row_to_w14_completion_model(site=site, readiness=readiness, row=row)
    
    
    @router.post("/w14/tracker/complete", response_model=W14TrackerCompletionRead)
    def complete_w14_tracker(
        payload: W14TrackerCompletionRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w14:write")),
    ) -> W14TrackerCompletionRead:
        _require_site_access(principal, payload.site)
        if payload.force and not _has_permission(principal, "admins:manage"):
            raise HTTPException(status_code=403, detail="force completion requires admins:manage")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        models = _load_w14_tracker_items_for_site(payload.site)
        readiness = _compute_w14_tracker_readiness(site=payload.site, rows=models, checked_at=now)
        if not readiness.ready and not payload.force:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "W14 completion gate failed",
                    "site": payload.site,
                    "ready": readiness.ready,
                    "blockers": readiness.blockers,
                    "readiness": readiness.model_dump(mode="json"),
                },
            )
    
        completion_note = (payload.completion_note or "").strip()
        next_status = (
            W14_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS
            if payload.force and not readiness.ready
            else W14_SITE_COMPLETION_STATUS_COMPLETED
        )
        with get_conn() as conn:
            existing = conn.execute(
                select(adoption_w14_site_runs).where(adoption_w14_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
            if existing is None:
                conn.execute(
                    insert(adoption_w14_site_runs).values(
                        site=payload.site,
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                conn.execute(
                    update(adoption_w14_site_runs)
                    .where(adoption_w14_site_runs.c.site == payload.site)
                    .values(
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        updated_by=actor_username,
                        updated_at=now,
                    )
                )
            row = conn.execute(
                select(adoption_w14_site_runs).where(adoption_w14_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
    
        model = _row_to_w14_completion_model(site=payload.site, readiness=readiness, row=row)
        _write_audit_log(
            principal=principal,
            action="w14_tracker_complete",
            resource_type="adoption_w14_tracker_site",
            resource_id=payload.site,
            detail={
                "site": payload.site,
                "status": model.status,
                "ready": readiness.ready,
                "force_used": model.force_used,
                "blockers": readiness.blockers,
                "completion_rate_percent": readiness.completion_rate_percent,
                "missing_required_evidence_count": readiness.missing_required_evidence_count,
            },
        )
        return model
    
    
    @router.patch("/w14/tracker/items/{tracker_item_id}", response_model=W14TrackerItemRead)
    def update_w14_tracker_item(
        tracker_item_id: int,
        payload: W14TrackerItemUpdate,
        principal: dict[str, Any] = Depends(require_permission("adoption_w14:write")),
    ) -> W14TrackerItemRead:
        has_update = (
            payload.assignee is not None
            or payload.status is not None
            or payload.completion_checked is not None
            or payload.completion_note is not None
        )
        if not has_update:
            raise HTTPException(status_code=400, detail="No update fields provided")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w14_tracker_items).where(adoption_w14_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if row is None:
                raise HTTPException(status_code=404, detail="W14 tracker item not found")
            _require_site_access(principal, str(row["site"]))
    
            next_assignee = row.get("assignee")
            if payload.assignee is not None:
                normalized_assignee = payload.assignee.strip()
                next_assignee = normalized_assignee or None
    
            next_status = str(row["status"])
            if payload.status is not None:
                next_status = str(payload.status)
    
            next_checked = bool(row.get("completion_checked", False))
            if payload.completion_checked is not None:
                next_checked = bool(payload.completion_checked)
    
            if next_status == W14_TRACKER_STATUS_DONE:
                next_checked = True
            elif payload.status is not None and payload.status != W14_TRACKER_STATUS_DONE and payload.completion_checked is None:
                next_checked = False
            if payload.completion_checked is True:
                next_status = W14_TRACKER_STATUS_DONE
            elif payload.completion_checked is False and next_status == W14_TRACKER_STATUS_DONE:
                next_status = W14_TRACKER_STATUS_IN_PROGRESS
    
            if next_status not in W14_TRACKER_STATUS_SET:
                raise HTTPException(status_code=400, detail="Invalid W14 tracker status")
    
            next_note = str(row.get("completion_note") or "")
            if payload.completion_note is not None:
                next_note = payload.completion_note.strip()
    
            existing_completed_at = _as_optional_datetime(row.get("completed_at"))
            next_completed_at = existing_completed_at
            if next_checked:
                if existing_completed_at is None:
                    next_completed_at = now
            else:
                next_completed_at = None
    
            conn.execute(
                update(adoption_w14_tracker_items)
                .where(adoption_w14_tracker_items.c.id == tracker_item_id)
                .values(
                    assignee=next_assignee,
                    status=next_status,
                    completion_checked=next_checked,
                    completion_note=next_note,
                    completed_at=next_completed_at,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w14_completion_if_closed(
                conn=conn,
                site=str(row["site"]),
                actor_username=actor_username,
                checked_at=now,
                reason="tracker_item_updated",
            )
            updated = conn.execute(
                select(adoption_w14_tracker_items).where(adoption_w14_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
        if updated is None:
            raise HTTPException(status_code=500, detail="Failed to update W14 tracker item")
        model = _row_to_w14_tracker_item_model(updated)
        _write_audit_log(
            principal=principal,
            action="w14_tracker_item_update",
            resource_type="adoption_w14_tracker_item",
            resource_id=str(model.id),
            detail={
                "site": model.site,
                "status": model.status,
                "assignee": model.assignee,
                "completion_checked": model.completion_checked,
            },
        )
        return model
    
    
    @router.post("/w14/tracker/items/{tracker_item_id}/evidence", response_model=W14EvidenceRead, status_code=201)
    async def upload_w14_tracker_evidence(
        tracker_item_id: int,
        file: UploadFile = File(...),
        note: str = Form(default=""),
        principal: dict[str, Any] = Depends(require_permission("adoption_w14:write")),
    ) -> W14EvidenceRead:
        file_name = _safe_download_filename(file.filename or "", fallback="evidence.bin", max_length=120)
        content_type = (file.content_type or "application/octet-stream").strip() or "application/octet-stream"
        content_type = content_type[:120].lower()
        if not _is_allowed_evidence_content_type(content_type):
            raise HTTPException(status_code=415, detail="Unsupported evidence content type")
        file_bytes = await file.read(W14_EVIDENCE_MAX_BYTES + 1)
        await file.close()
        if len(file_bytes) == 0:
            raise HTTPException(status_code=400, detail="Empty evidence file is not allowed")
        if len(file_bytes) > W14_EVIDENCE_MAX_BYTES:
            raise HTTPException(status_code=413, detail=f"Evidence file too large (max {W14_EVIDENCE_MAX_BYTES} bytes)")
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
            tracker_row = conn.execute(
                select(adoption_w14_tracker_items).where(adoption_w14_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W14 tracker item not found")
            site = str(tracker_row["site"])
            _require_site_access(principal, site)
    
            result = conn.execute(
                insert(adoption_w14_evidence_files).values(
                    tracker_item_id=tracker_item_id,
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
            conn.execute(
                update(adoption_w14_tracker_items)
                .where(adoption_w14_tracker_items.c.id == tracker_item_id)
                .values(
                    evidence_count=adoption_w14_tracker_items.c.evidence_count + 1,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w14_completion_if_closed(
                conn=conn,
                site=site,
                actor_username=actor_username,
                checked_at=now,
                reason="evidence_uploaded",
            )
            evidence_row = conn.execute(
                select(adoption_w14_evidence_files).where(adoption_w14_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
    
        if evidence_row is None:
            raise HTTPException(status_code=500, detail="Failed to save evidence file")
        model = _row_to_w14_evidence_model(evidence_row)
        _write_audit_log(
            principal=principal,
            action="w14_tracker_evidence_upload",
            resource_type="adoption_w14_evidence",
            resource_id=str(model.id),
            detail={
                "tracker_item_id": model.tracker_item_id,
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
    
    
    @router.get("/w14/tracker/items/{tracker_item_id}/evidence", response_model=list[W14EvidenceRead])
    def list_w14_tracker_evidence(
        tracker_item_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w14:read")),
    ) -> list[W14EvidenceRead]:
        with get_conn() as conn:
            tracker_row = conn.execute(
                select(adoption_w14_tracker_items).where(adoption_w14_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W14 tracker item not found")
            _require_site_access(principal, str(tracker_row["site"]))
    
            rows = conn.execute(
                select(adoption_w14_evidence_files)
                .where(adoption_w14_evidence_files.c.tracker_item_id == tracker_item_id)
                .order_by(adoption_w14_evidence_files.c.uploaded_at.desc(), adoption_w14_evidence_files.c.id.desc())
            ).mappings().all()
        return [_row_to_w14_evidence_model(row) for row in rows]
    
    
    @router.get("/w14/tracker/evidence/{evidence_id}/download", response_model=None)
    def download_w14_tracker_evidence(
        evidence_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w14:read")),
    ) -> Response:
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w14_evidence_files).where(adoption_w14_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="W14 evidence not found")
    
        site = str(row["site"])
        _require_site_access(principal, site)
        content_type = str(row.get("content_type") or "application/octet-stream")
        file_name = _safe_download_filename(str(row.get("file_name") or ""), fallback="evidence.bin", max_length=120)
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
            action="w14_tracker_evidence_download",
            resource_type="adoption_w14_evidence",
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
    
    
    @router.post("/w15/tracker/bootstrap", response_model=W15TrackerBootstrapResponse)
    def bootstrap_w15_tracker_items(
        payload: W15TrackerBootstrapRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w15:write")),
    ) -> W15TrackerBootstrapResponse:
        _require_site_access(principal, payload.site)
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        catalog = _adoption_w15_catalog_items(payload.site)
        created_count = 0
    
        with get_conn() as conn:
            existing_rows = conn.execute(
                select(
                    adoption_w15_tracker_items.c.item_type,
                    adoption_w15_tracker_items.c.item_key,
                ).where(adoption_w15_tracker_items.c.site == payload.site)
            ).mappings().all()
            existing_keys = {(str(row["item_type"]), str(row["item_key"])) for row in existing_rows}
    
            for entry in catalog:
                key = (str(entry["item_type"]), str(entry["item_key"]))
                if key in existing_keys:
                    continue
                conn.execute(
                    insert(adoption_w15_tracker_items).values(
                        site=payload.site,
                        item_type=str(entry["item_type"]),
                        item_key=str(entry["item_key"]),
                        item_name=str(entry["item_name"]),
                        assignee=None,
                        status=W15_TRACKER_STATUS_PENDING,
                        completion_checked=False,
                        completion_note="",
                        due_at=entry.get("due_at"),
                        completed_at=None,
                        evidence_count=0,
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
                existing_keys.add(key)
                created_count += 1
    
            if created_count > 0:
                _reset_w15_completion_if_closed(
                    conn=conn,
                    site=payload.site,
                    actor_username=actor_username,
                    checked_at=now,
                    reason="bootstrap_added_items",
                )
    
            rows = conn.execute(
                select(adoption_w15_tracker_items)
                .where(adoption_w15_tracker_items.c.site == payload.site)
                .order_by(
                    adoption_w15_tracker_items.c.item_type.asc(),
                    adoption_w15_tracker_items.c.item_key.asc(),
                    adoption_w15_tracker_items.c.id.asc(),
                )
            ).mappings().all()
    
        items = [_row_to_w15_tracker_item_model(row) for row in rows]
        _write_audit_log(
            principal=principal,
            action="w15_tracker_bootstrap",
            resource_type="adoption_w15_tracker",
            resource_id=payload.site,
            detail={"site": payload.site, "created_count": created_count, "total_count": len(items)},
        )
        return W15TrackerBootstrapResponse(
            site=payload.site,
            created_count=created_count,
            total_count=len(items),
            items=items,
        )
    
    
    @router.get("/w15/tracker/items", response_model=list[W15TrackerItemRead])
    def list_w15_tracker_items(
        site: Annotated[str | None, Query()] = None,
        status: Annotated[str | None, Query()] = None,
        item_type: Annotated[str | None, Query()] = None,
        assignee: Annotated[str | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
        offset: Annotated[int, Query(ge=0)] = 0,
        principal: dict[str, Any] = Depends(require_permission("adoption_w15:read")),
    ) -> list[W15TrackerItemRead]:
        _require_site_access(principal, site)
        normalized_status = status.strip().lower() if status is not None else None
        if normalized_status is not None and normalized_status not in W15_TRACKER_STATUS_SET:
            raise HTTPException(status_code=400, detail="Invalid W15 tracker status")
    
        stmt = select(adoption_w15_tracker_items)
        if site is not None:
            stmt = stmt.where(adoption_w15_tracker_items.c.site == site)
        else:
            allowed_sites = _allowed_sites_for_principal(principal)
            if allowed_sites is not None:
                if not allowed_sites:
                    return []
                stmt = stmt.where(adoption_w15_tracker_items.c.site.in_(allowed_sites))
    
        if normalized_status is not None:
            stmt = stmt.where(adoption_w15_tracker_items.c.status == normalized_status)
        if item_type is not None:
            stmt = stmt.where(adoption_w15_tracker_items.c.item_type == item_type.strip())
        if assignee is not None:
            stmt = stmt.where(adoption_w15_tracker_items.c.assignee == assignee.strip())
    
        stmt = stmt.order_by(
            adoption_w15_tracker_items.c.updated_at.desc(),
            adoption_w15_tracker_items.c.id.desc(),
        ).limit(limit).offset(offset)
    
        with get_conn() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [_row_to_w15_tracker_item_model(row) for row in rows]
    
    
    @router.get("/w15/tracker/overview", response_model=W15TrackerOverviewRead)
    def get_w15_tracker_overview(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w15:read")),
    ) -> W15TrackerOverviewRead:
        _require_site_access(principal, site)
        with get_conn() as conn:
            rows = conn.execute(
                select(adoption_w15_tracker_items).where(adoption_w15_tracker_items.c.site == site)
            ).mappings().all()
        models = [_row_to_w15_tracker_item_model(row) for row in rows]
        return _compute_w15_tracker_overview(site, models)
    
    
    @router.get("/w15/tracker/readiness", response_model=W15TrackerReadinessRead)
    def get_w15_tracker_readiness(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w15:read")),
    ) -> W15TrackerReadinessRead:
        _require_site_access(principal, site)
        models = _load_w15_tracker_items_for_site(site)
        return _compute_w15_tracker_readiness(site=site, rows=models)
    
    
    @router.get("/w15/tracker/completion", response_model=W15TrackerCompletionRead)
    def get_w15_tracker_completion(
        site: Annotated[str, Query(min_length=1)],
        principal: dict[str, Any] = Depends(require_permission("adoption_w15:read")),
    ) -> W15TrackerCompletionRead:
        _require_site_access(principal, site)
        now = datetime.now(timezone.utc)
        models = _load_w15_tracker_items_for_site(site)
        readiness = _compute_w15_tracker_readiness(site=site, rows=models, checked_at=now)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w15_site_runs).where(adoption_w15_site_runs.c.site == site).limit(1)
            ).mappings().first()
        return _row_to_w15_completion_model(site=site, readiness=readiness, row=row)
    
    
    @router.post("/w15/tracker/complete", response_model=W15TrackerCompletionRead)
    def complete_w15_tracker(
        payload: W15TrackerCompletionRequest,
        principal: dict[str, Any] = Depends(require_permission("adoption_w15:write")),
    ) -> W15TrackerCompletionRead:
        _require_site_access(principal, payload.site)
        if payload.force and not _has_permission(principal, "admins:manage"):
            raise HTTPException(status_code=403, detail="force completion requires admins:manage")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        models = _load_w15_tracker_items_for_site(payload.site)
        readiness = _compute_w15_tracker_readiness(site=payload.site, rows=models, checked_at=now)
        if not readiness.ready and not payload.force:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "W15 completion gate failed",
                    "site": payload.site,
                    "ready": readiness.ready,
                    "blockers": readiness.blockers,
                    "readiness": readiness.model_dump(mode="json"),
                },
            )
    
        completion_note = (payload.completion_note or "").strip()
        next_status = (
            W15_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS
            if payload.force and not readiness.ready
            else W15_SITE_COMPLETION_STATUS_COMPLETED
        )
        with get_conn() as conn:
            existing = conn.execute(
                select(adoption_w15_site_runs).where(adoption_w15_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
            if existing is None:
                conn.execute(
                    insert(adoption_w15_site_runs).values(
                        site=payload.site,
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                conn.execute(
                    update(adoption_w15_site_runs)
                    .where(adoption_w15_site_runs.c.site == payload.site)
                    .values(
                        status=next_status,
                        completion_note=completion_note,
                        force_used=bool(payload.force and not readiness.ready),
                        completed_by=actor_username,
                        completed_at=now,
                        last_checked_at=readiness.checked_at,
                        readiness_json=_to_json_text(readiness.model_dump(mode="json")),
                        updated_by=actor_username,
                        updated_at=now,
                    )
                )
            row = conn.execute(
                select(adoption_w15_site_runs).where(adoption_w15_site_runs.c.site == payload.site).limit(1)
            ).mappings().first()
    
        model = _row_to_w15_completion_model(site=payload.site, readiness=readiness, row=row)
        _write_audit_log(
            principal=principal,
            action="w15_tracker_complete",
            resource_type="adoption_w15_tracker_site",
            resource_id=payload.site,
            detail={
                "site": payload.site,
                "status": model.status,
                "ready": readiness.ready,
                "force_used": model.force_used,
                "blockers": readiness.blockers,
                "completion_rate_percent": readiness.completion_rate_percent,
                "missing_required_evidence_count": readiness.missing_required_evidence_count,
            },
        )
        return model
    
    
    @router.patch("/w15/tracker/items/{tracker_item_id}", response_model=W15TrackerItemRead)
    def update_w15_tracker_item(
        tracker_item_id: int,
        payload: W15TrackerItemUpdate,
        principal: dict[str, Any] = Depends(require_permission("adoption_w15:write")),
    ) -> W15TrackerItemRead:
        has_update = (
            payload.assignee is not None
            or payload.status is not None
            or payload.completion_checked is not None
            or payload.completion_note is not None
        )
        if not has_update:
            raise HTTPException(status_code=400, detail="No update fields provided")
    
        actor_username = str(principal.get("username") or "unknown")
        now = datetime.now(timezone.utc)
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w15_tracker_items).where(adoption_w15_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if row is None:
                raise HTTPException(status_code=404, detail="W15 tracker item not found")
            _require_site_access(principal, str(row["site"]))
    
            next_assignee = row.get("assignee")
            if payload.assignee is not None:
                normalized_assignee = payload.assignee.strip()
                next_assignee = normalized_assignee or None
    
            next_status = str(row["status"])
            if payload.status is not None:
                next_status = str(payload.status)
    
            next_checked = bool(row.get("completion_checked", False))
            if payload.completion_checked is not None:
                next_checked = bool(payload.completion_checked)
    
            if next_status == W15_TRACKER_STATUS_DONE:
                next_checked = True
            elif payload.status is not None and payload.status != W15_TRACKER_STATUS_DONE and payload.completion_checked is None:
                next_checked = False
            if payload.completion_checked is True:
                next_status = W15_TRACKER_STATUS_DONE
            elif payload.completion_checked is False and next_status == W15_TRACKER_STATUS_DONE:
                next_status = W15_TRACKER_STATUS_IN_PROGRESS
    
            if next_status not in W15_TRACKER_STATUS_SET:
                raise HTTPException(status_code=400, detail="Invalid W15 tracker status")
    
            next_note = str(row.get("completion_note") or "")
            if payload.completion_note is not None:
                next_note = payload.completion_note.strip()
    
            existing_completed_at = _as_optional_datetime(row.get("completed_at"))
            next_completed_at = existing_completed_at
            if next_checked:
                if existing_completed_at is None:
                    next_completed_at = now
            else:
                next_completed_at = None
    
            conn.execute(
                update(adoption_w15_tracker_items)
                .where(adoption_w15_tracker_items.c.id == tracker_item_id)
                .values(
                    assignee=next_assignee,
                    status=next_status,
                    completion_checked=next_checked,
                    completion_note=next_note,
                    completed_at=next_completed_at,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w15_completion_if_closed(
                conn=conn,
                site=str(row["site"]),
                actor_username=actor_username,
                checked_at=now,
                reason="tracker_item_updated",
            )
            updated = conn.execute(
                select(adoption_w15_tracker_items).where(adoption_w15_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
        if updated is None:
            raise HTTPException(status_code=500, detail="Failed to update W15 tracker item")
        model = _row_to_w15_tracker_item_model(updated)
        _write_audit_log(
            principal=principal,
            action="w15_tracker_item_update",
            resource_type="adoption_w15_tracker_item",
            resource_id=str(model.id),
            detail={
                "site": model.site,
                "status": model.status,
                "assignee": model.assignee,
                "completion_checked": model.completion_checked,
            },
        )
        return model
    
    
    @router.post("/w15/tracker/items/{tracker_item_id}/evidence", response_model=W15EvidenceRead, status_code=201)
    async def upload_w15_tracker_evidence(
        tracker_item_id: int,
        file: UploadFile = File(...),
        note: str = Form(default=""),
        principal: dict[str, Any] = Depends(require_permission("adoption_w15:write")),
    ) -> W15EvidenceRead:
        file_name = _safe_download_filename(file.filename or "", fallback="evidence.bin", max_length=120)
        content_type = (file.content_type or "application/octet-stream").strip() or "application/octet-stream"
        content_type = content_type[:120].lower()
        if not _is_allowed_evidence_content_type(content_type):
            raise HTTPException(status_code=415, detail="Unsupported evidence content type")
        file_bytes = await file.read(W15_EVIDENCE_MAX_BYTES + 1)
        await file.close()
        if len(file_bytes) == 0:
            raise HTTPException(status_code=400, detail="Empty evidence file is not allowed")
        if len(file_bytes) > W15_EVIDENCE_MAX_BYTES:
            raise HTTPException(status_code=413, detail=f"Evidence file too large (max {W15_EVIDENCE_MAX_BYTES} bytes)")
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
            tracker_row = conn.execute(
                select(adoption_w15_tracker_items).where(adoption_w15_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W15 tracker item not found")
            site = str(tracker_row["site"])
            _require_site_access(principal, site)
    
            result = conn.execute(
                insert(adoption_w15_evidence_files).values(
                    tracker_item_id=tracker_item_id,
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
            conn.execute(
                update(adoption_w15_tracker_items)
                .where(adoption_w15_tracker_items.c.id == tracker_item_id)
                .values(
                    evidence_count=adoption_w15_tracker_items.c.evidence_count + 1,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            _reset_w15_completion_if_closed(
                conn=conn,
                site=site,
                actor_username=actor_username,
                checked_at=now,
                reason="evidence_uploaded",
            )
            evidence_row = conn.execute(
                select(adoption_w15_evidence_files).where(adoption_w15_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
    
        if evidence_row is None:
            raise HTTPException(status_code=500, detail="Failed to save evidence file")
        model = _row_to_w15_evidence_model(evidence_row)
        _write_audit_log(
            principal=principal,
            action="w15_tracker_evidence_upload",
            resource_type="adoption_w15_evidence",
            resource_id=str(model.id),
            detail={
                "tracker_item_id": model.tracker_item_id,
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
    
    
    @router.get("/w15/tracker/items/{tracker_item_id}/evidence", response_model=list[W15EvidenceRead])
    def list_w15_tracker_evidence(
        tracker_item_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w15:read")),
    ) -> list[W15EvidenceRead]:
        with get_conn() as conn:
            tracker_row = conn.execute(
                select(adoption_w15_tracker_items).where(adoption_w15_tracker_items.c.id == tracker_item_id).limit(1)
            ).mappings().first()
            if tracker_row is None:
                raise HTTPException(status_code=404, detail="W15 tracker item not found")
            _require_site_access(principal, str(tracker_row["site"]))
    
            rows = conn.execute(
                select(adoption_w15_evidence_files)
                .where(adoption_w15_evidence_files.c.tracker_item_id == tracker_item_id)
                .order_by(adoption_w15_evidence_files.c.uploaded_at.desc(), adoption_w15_evidence_files.c.id.desc())
            ).mappings().all()
        return [_row_to_w15_evidence_model(row) for row in rows]
    
    
    @router.get("/w15/tracker/evidence/{evidence_id}/download", response_model=None)
    def download_w15_tracker_evidence(
        evidence_id: int,
        principal: dict[str, Any] = Depends(require_permission("adoption_w15:read")),
    ) -> Response:
        with get_conn() as conn:
            row = conn.execute(
                select(adoption_w15_evidence_files).where(adoption_w15_evidence_files.c.id == evidence_id).limit(1)
            ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="W15 evidence not found")
    
        site = str(row["site"])
        _require_site_access(principal, site)
        content_type = str(row.get("content_type") or "application/octet-stream")
        file_name = _safe_download_filename(str(row.get("file_name") or ""), fallback="evidence.bin", max_length=120)
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
            action="w15_tracker_evidence_download",
            resource_type="adoption_w15_evidence",
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
    
    
    
    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}
    
    
    @app.get("/meta")
    def meta() -> dict[str, str]:
        db_backend = "postgresql" if DATABASE_URL.startswith("postgresql+") else "sqlite"
        return {"env": getenv("ENV", "local"), "db": db_backend}
    
    
    def _principal_to_auth_me_model(
        principal: dict[str, Any],
        endpoint: str = "/api/auth/me",
    ) -> AuthMeRead:
        from app.domains.iam.service import _principal_to_auth_me_model as _impl
        return _impl(principal, endpoint=endpoint)
    
    
    def _attach_auth_me_meta(profile: AuthMeRead, *, endpoint: str = "/api/auth/me") -> AuthMeRead:
        from app.domains.iam.service import _attach_auth_me_meta as _impl
        return _impl(profile, endpoint=endpoint)
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    def _enforce_active_token_quota(
        *,
        conn: Any,
        user_id: int,
        now: datetime,
        keep_token_ids: set[int] | None = None,
    ) -> list[int]:
        from app.domains.iam.service import _enforce_active_token_quota as _impl
        return _impl(conn=conn, user_id=user_id, now=now, keep_token_ids=keep_token_ids)
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    return router

