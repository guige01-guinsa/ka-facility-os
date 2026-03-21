"""IAM audit, profile, and token service helpers extracted from app.main."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any

from sqlalchemy import insert, select, update
from sqlalchemy.exc import SQLAlchemyError

from app.database import admin_audit_logs, admin_tokens, get_conn, job_runs, ops_qr_asset_revisions
from app.domains.iam.core import (
    ADMIN_TOKEN_MAX_ACTIVE_PER_USER,
    ADMIN_TOKEN_ROTATE_WARNING_DAYS,
    AUDIT_ARCHIVE_SIGNING_KEY,
    DR_REHEARSAL_ENABLED,
    DR_REHEARSAL_JOB_NAME,
    _effective_permissions,
    _month_window,
    _permission_text_to_list,
    _principal_site_scope,
    _resolve_effective_site_scope,
    _site_scope_text_to_list,
    _token_idle_due_at,
    _token_rotate_due_at,
)
from app.domains.ops.checklist_runtime import _build_ops_checklists_import_validation_report
from app.domains.ops.inspection_service import _as_datetime, _as_optional_datetime
from app.schemas import AdminAuditLogRead, AdminTokenRead, AdminUserRead, AuthMeRead

IAM_RESPONSE_SCHEMA_VERSION = "v1"
IAM_AUTH_ME_SCHEMA = "auth_profile_response"
AUDIT_ARCHIVE_FORMAT_VERSION = "v2"
AUDIT_ARCHIVE_ATTACHMENT_SCHEMA_VERSION = "v2"
AUDIT_ARCHIVE_PAYLOAD_SCHEMA = "admin_audit_archive_payload"
AUDIT_CHAIN_ADVISORY_LOCK_KEY = 84202431
AUDIT_CHAIN_WRITE_LOCK = Lock()


def _to_json_text(value: dict[str, Any] | None) -> str:
    data = value or {}
    return json.dumps(data, ensure_ascii=False, default=str)


def _iam_site_scope_type(site_scope: list[str]) -> str:
    if not site_scope:
        return "none"
    if "*" in site_scope:
        return "global"
    return "site"


def _build_auth_me_meta(
    *,
    endpoint: str,
    role: str,
    site_scope: list[str],
    is_legacy: bool,
    token_id: int | None,
) -> dict[str, Any]:
    return {
        "schema": IAM_AUTH_ME_SCHEMA,
        "schema_version": IAM_RESPONSE_SCHEMA_VERSION,
        "endpoint": endpoint,
        "role": role,
        "scope_type": _iam_site_scope_type(site_scope),
        "is_legacy": is_legacy,
        "token_bound": token_id is not None,
    }


def _attach_auth_me_meta(profile: AuthMeRead, *, endpoint: str = "/api/auth/me") -> AuthMeRead:
    profile.meta = _build_auth_me_meta(
        endpoint=endpoint,
        role=profile.role,
        site_scope=list(profile.site_scope),
        is_legacy=bool(profile.is_legacy),
        token_id=int(profile.token_id) if profile.token_id is not None else None,
    )
    return profile


def _build_audit_archive_attachment(
    *,
    attachment_key: str,
    schema: str,
    resource_type: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    return {
        "attachment_key": attachment_key,
        "schema": schema,
        "schema_version": AUDIT_ARCHIVE_ATTACHMENT_SCHEMA_VERSION,
        "resource_type": resource_type,
        **payload,
    }

def _compute_audit_entry_hash(
    *,
    prev_hash: str,
    actor_user_id: int | None,
    actor_username: str,
    action: str,
    resource_type: str,
    resource_id: str,
    status: str,
    detail_json: str,
    created_at: datetime,
) -> str:
    canonical = json.dumps(
        {
            "prev_hash": prev_hash,
            "actor_user_id": actor_user_id,
            "actor_username": actor_username,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "status": status,
            "detail_json": detail_json,
            "created_at": created_at.isoformat(),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

def _sign_payload(payload_text: str) -> str | None:
    if not AUDIT_ARCHIVE_SIGNING_KEY:
        return None
    return hmac.new(
        AUDIT_ARCHIVE_SIGNING_KEY.encode("utf-8"),
        payload_text.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _acquire_audit_chain_write_guard(conn: Any) -> None:
    dialect_name = str(getattr(getattr(conn, "dialect", None), "name", "") or "").lower()
    if dialect_name == "postgresql":
        try:
            conn.exec_driver_sql(f"SELECT pg_advisory_xact_lock({AUDIT_CHAIN_ADVISORY_LOCK_KEY})")
        except Exception:
            return

def _write_audit_log(
    *,
    principal: dict[str, Any] | None,
    action: str,
    resource_type: str,
    resource_id: str,
    status: str = "success",
    detail: dict[str, Any] | None = None,
) -> None:
    actor_user_id = None
    actor_username = "system"
    if principal is not None:
        actor_user_id = principal.get("user_id")
        actor_username = str(principal.get("username") or "unknown")
    detail_json = _to_json_text(detail)

    try:
        # Audit chain writes must be serialized; otherwise concurrent requests can branch
        # from the same previous hash and corrupt monthly integrity verification.
        with AUDIT_CHAIN_WRITE_LOCK:
            with get_conn() as conn:
                _acquire_audit_chain_write_guard(conn)
                now = datetime.now(timezone.utc)
                prev_row = conn.execute(
                    select(admin_audit_logs.c.entry_hash)
                    .order_by(admin_audit_logs.c.created_at.desc(), admin_audit_logs.c.id.desc())
                    .limit(1)
                ).mappings().first()
                prev_hash = str(prev_row.get("entry_hash") or "") if prev_row is not None else ""
                entry_hash = _compute_audit_entry_hash(
                    prev_hash=prev_hash,
                    actor_user_id=actor_user_id,
                    actor_username=actor_username,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    status=status,
                    detail_json=detail_json,
                    created_at=now,
                )
                conn.execute(
                    insert(admin_audit_logs).values(
                        actor_user_id=actor_user_id,
                        actor_username=actor_username,
                        action=action,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        status=status,
                        prev_hash=prev_hash or None,
                        entry_hash=entry_hash,
                        detail_json=detail_json,
                        created_at=now,
                    )
                )
    except SQLAlchemyError:
        # Audit log failures must not block business requests.
        return

def _row_to_admin_audit_log_model(row: dict[str, Any]) -> AdminAuditLogRead:
    raw = str(row["detail_json"] or "{}")
    try:
        detail = json.loads(raw)
    except json.JSONDecodeError:
        detail = {"raw": raw}

    return AdminAuditLogRead(
        id=int(row["id"]),
        actor_user_id=row["actor_user_id"],
        actor_username=str(row["actor_username"]),
        action=str(row["action"]),
        resource_type=str(row["resource_type"]),
        resource_id=str(row["resource_id"]),
        status=str(row["status"]),
        detail=detail if isinstance(detail, dict) else {"value": detail},
        created_at=_as_datetime(row["created_at"]),
    )

def _verify_audit_chain(rows: list[dict[str, Any]], *, initial_prev_hash: str = "") -> dict[str, Any]:
    previous_hash = initial_prev_hash
    issues: list[dict[str, Any]] = []
    checked = 0
    for row in rows:
        checked += 1
        detail_json = str(row.get("detail_json") or "{}")
        created_at = _as_datetime(row["created_at"])
        expected = _compute_audit_entry_hash(
            prev_hash=previous_hash,
            actor_user_id=row.get("actor_user_id"),
            actor_username=str(row.get("actor_username") or ""),
            action=str(row.get("action") or ""),
            resource_type=str(row.get("resource_type") or ""),
            resource_id=str(row.get("resource_id") or ""),
            status=str(row.get("status") or ""),
            detail_json=detail_json,
            created_at=created_at,
        )
        stored_prev = str(row.get("prev_hash") or "")
        stored_hash = str(row.get("entry_hash") or "")
        if stored_prev != previous_hash:
            issues.append({"id": int(row["id"]), "reason": "prev_hash_mismatch"})
        if stored_hash != expected:
            issues.append({"id": int(row["id"]), "reason": "entry_hash_mismatch"})
        previous_hash = stored_hash or expected
    return {
        "checked_count": checked,
        "issue_count": len(issues),
        "issues": issues[:100],
        "initial_prev_hash": initial_prev_hash or None,
        "last_entry_hash": previous_hash or None,
        "chain_ok": len(issues) == 0,
    }


def _load_archive_json_value(raw: Any, *, fallback: Any) -> Any:
    text = str(raw or "").strip()
    if not text:
        return fallback
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return fallback
    return value


def _row_to_ops_qr_asset_revision_archive_item(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    created_at = _as_optional_datetime(row.get("created_at"))
    before_payload = _load_archive_json_value(row.get("before_json"), fallback={})
    after_payload = _load_archive_json_value(row.get("after_json"), fallback={})
    quality_flags = _load_archive_json_value(row.get("quality_flags_json"), fallback=[])
    return {
        "id": int(row["id"]),
        "qr_asset_id": int(row.get("qr_asset_id") or 0) or None,
        "qr_id": str(row.get("qr_id") or ""),
        "change_source": str(row.get("change_source") or ""),
        "change_action": str(row.get("change_action") or ""),
        "change_note": str(row.get("change_note") or ""),
        "before": before_payload if isinstance(before_payload, dict) else {},
        "after": after_payload if isinstance(after_payload, dict) else {},
        "quality_flags": quality_flags if isinstance(quality_flags, list) else [],
        "created_by": str(row.get("created_by") or ""),
        "created_at": created_at.isoformat() if created_at is not None else None,
    }


def _build_ops_qr_asset_revisions_attachment(
    *,
    start: datetime,
    end: datetime,
    month: str,
) -> dict[str, Any]:
    with get_conn() as conn:
        month_rows = conn.execute(
            select(ops_qr_asset_revisions)
            .where(ops_qr_asset_revisions.c.created_at >= start)
            .where(ops_qr_asset_revisions.c.created_at < end)
            .order_by(ops_qr_asset_revisions.c.created_at.desc(), ops_qr_asset_revisions.c.id.desc())
        ).mappings().all()
        latest_before_window_end_row = conn.execute(
            select(ops_qr_asset_revisions)
            .where(ops_qr_asset_revisions.c.created_at < end)
            .order_by(ops_qr_asset_revisions.c.created_at.desc(), ops_qr_asset_revisions.c.id.desc())
            .limit(1)
        ).mappings().first()

    action_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    qr_ids: set[str] = set()
    quality_flag_total = 0
    recent_rows: list[dict[str, Any]] = []
    for idx, row in enumerate(month_rows):
        qr_id = str(row.get("qr_id") or "").strip()
        if qr_id:
            qr_ids.add(qr_id)
        action = str(row.get("change_action") or "unknown").strip() or "unknown"
        action_counts[action] = action_counts.get(action, 0) + 1
        source = str(row.get("change_source") or "unknown").strip() or "unknown"
        source_counts[source] = source_counts.get(source, 0) + 1
        quality_flags = _load_archive_json_value(row.get("quality_flags_json"), fallback=[])
        if isinstance(quality_flags, list):
            quality_flag_total += len(quality_flags)
        if idx < 10:
            archive_row = _row_to_ops_qr_asset_revision_archive_item(row)
            if archive_row is not None:
                recent_rows.append(archive_row)

    latest_in_month = recent_rows[0] if recent_rows else None
    latest_before_window_end = _row_to_ops_qr_asset_revision_archive_item(latest_before_window_end_row)
    return _build_audit_archive_attachment(
        attachment_key="ops_qr_asset_revisions",
        schema="audit_archive_attachment_ops_qr_asset_revisions",
        resource_type="ops_qr_asset",
        payload={
            "required": False,
            "month": month,
            "included": bool(month_rows),
            "status": "ok" if month_rows else "info",
            "message": (
                "QR asset revision history attached for target month."
                if month_rows
                else "No QR asset revision history in target month."
            ),
            "summary": {
                "revision_count": len(month_rows),
                "qr_id_count": len(qr_ids),
                "quality_flag_total": quality_flag_total,
                "change_action_counts": action_counts,
                "change_source_counts": source_counts,
            },
            "latest_in_month": latest_in_month,
            "latest_before_window_end": latest_before_window_end,
            "recent_rows": recent_rows,
        },
    )


def build_monthly_audit_archive(
    *,
    month: str | None,
    max_entries: int = 10000,
    include_entries: bool = True,
) -> dict[str, Any]:
    start, end, normalized = _month_window(month)
    with get_conn() as conn:
        anchor_row = conn.execute(
            select(admin_audit_logs.c.entry_hash)
            .where(admin_audit_logs.c.created_at < start)
            .order_by(admin_audit_logs.c.created_at.desc(), admin_audit_logs.c.id.desc())
            .limit(1)
        ).mappings().first()
        anchor_hash = str(anchor_row.get("entry_hash") or "") if anchor_row is not None else ""
        rows = conn.execute(
            select(admin_audit_logs)
            .where(admin_audit_logs.c.created_at >= start)
            .where(admin_audit_logs.c.created_at < end)
            .order_by(admin_audit_logs.c.created_at.asc(), admin_audit_logs.c.id.asc())
            .limit(max_entries)
        ).mappings().all()
        dr_month_row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == DR_REHEARSAL_JOB_NAME)
            .where(job_runs.c.finished_at >= start)
            .where(job_runs.c.finished_at < end)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
        dr_latest_row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == DR_REHEARSAL_JOB_NAME)
            .where(job_runs.c.finished_at < end)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()

    chain = _verify_audit_chain([dict(row) for row in rows], initial_prev_hash=anchor_hash)
    archive_rows: list[dict[str, Any]] = []
    if include_entries:
        for row in rows:
            detail_raw = str(row.get("detail_json") or "{}")
            try:
                detail_value = json.loads(detail_raw)
            except json.JSONDecodeError:
                detail_value = {"raw": detail_raw}
            archive_rows.append(
                {
                    "id": int(row["id"]),
                    "actor_user_id": row.get("actor_user_id"),
                    "actor_username": str(row.get("actor_username") or ""),
                    "action": str(row.get("action") or ""),
                    "resource_type": str(row.get("resource_type") or ""),
                    "resource_id": str(row.get("resource_id") or ""),
                    "status": str(row.get("status") or ""),
                    "detail": detail_value,
                    "created_at": _as_datetime(row["created_at"]).isoformat(),
                    "prev_hash": row.get("prev_hash"),
                    "entry_hash": row.get("entry_hash"),
                }
            )

    def _to_dr_attachment(row: dict[str, Any] | None) -> dict[str, Any] | None:
        if row is None:
            return None
        detail_raw = str(row.get("detail_json") or "{}")
        try:
            detail = json.loads(detail_raw)
        except json.JSONDecodeError:
            detail = {"raw": detail_raw}
        if not isinstance(detail, dict):
            detail = {"value": detail}
        started_at = _as_optional_datetime(row.get("started_at"))
        finished_at = _as_optional_datetime(row.get("finished_at"))
        counts_raw = detail.get("counts")
        counts = counts_raw if isinstance(counts_raw, dict) else {}
        return {
            "run_id": int(row["id"]),
            "status": str(row.get("status") or "unknown"),
            "trigger": str(row.get("trigger") or "unknown"),
            "started_at": started_at.isoformat() if started_at is not None else None,
            "finished_at": finished_at.isoformat() if finished_at is not None else None,
            "restore_valid": bool(detail.get("restore_valid", False)),
            "simulate_restore": bool(detail.get("simulate_restore", False)),
            "backup_file": detail.get("backup_file"),
            "pruned_files": int(detail.get("pruned_files") or 0),
            "counts": counts,
            "notes": detail.get("notes") if isinstance(detail.get("notes"), list) else [],
        }

    dr_latest_in_month = _to_dr_attachment(dr_month_row)
    dr_latest_before_window_end = _to_dr_attachment(dr_latest_row)
    dr_attachment = _build_audit_archive_attachment(
        attachment_key="dr_rehearsal",
        schema="audit_archive_attachment_dr_rehearsal",
        resource_type="ops_dr",
        payload={
        "required": DR_REHEARSAL_ENABLED,
        "month": normalized,
        "included": dr_latest_in_month is not None,
        "status": (
            "ok"
            if dr_latest_in_month is not None
            else ("warning" if DR_REHEARSAL_ENABLED else "info")
        ),
        "message": (
            "DR rehearsal result attached for target month."
            if dr_latest_in_month is not None
            else (
                "No DR rehearsal result in target month."
                if DR_REHEARSAL_ENABLED
                else "DR rehearsal is disabled by policy."
            )
        ),
        "latest_in_month": dr_latest_in_month,
        "latest_before_window_end": dr_latest_before_window_end,
        },
    )

    import_validation_report = _build_ops_checklists_import_validation_report()
    import_generated_at = _as_optional_datetime(import_validation_report.get("generated_at"))
    import_summary_raw = import_validation_report.get("summary")
    import_summary = import_summary_raw if isinstance(import_summary_raw, dict) else {}
    import_issues_raw = import_validation_report.get("issues")
    import_issues = import_issues_raw if isinstance(import_issues_raw, list) else []
    import_suggestions_raw = import_validation_report.get("suggestions")
    import_suggestions = (
        [str(item or "") for item in import_suggestions_raw if str(item or "").strip()]
        if isinstance(import_suggestions_raw, list)
        else []
    )
    import_in_month = (
        import_generated_at is not None and import_generated_at >= start and import_generated_at < end
    )
    import_attachment = _build_audit_archive_attachment(
        attachment_key="ops_checklists_import_validation",
        schema="audit_archive_attachment_ops_checklists_import_validation",
        resource_type="ops_inspection_checklists",
        payload={
        "required": True,
        "month": normalized,
        "included": True,
        "status": str(import_validation_report.get("status") or "warning"),
        "message": (
            "Checklist import validation snapshot generated in target month."
            if import_in_month
            else "Checklist import validation snapshot attached (generated outside target month)."
        ),
        "generated_at": import_generated_at.isoformat() if import_generated_at is not None else None,
        "generated_in_target_month": import_in_month,
        "source_file": str(import_validation_report.get("source_file") or ""),
        "source_file_exists": bool(import_validation_report.get("source_file_exists", False)),
        "source": str(import_validation_report.get("source") or ""),
        "version": str(import_validation_report.get("version") or ""),
        "checklist_version": str(import_validation_report.get("checklist_version") or import_validation_report.get("version") or ""),
        "applied_at": import_validation_report.get("applied_at"),
        "summary": {
            "checklist_set_count": int(import_summary.get("checklist_set_count") or 0),
            "checklist_item_count": int(import_summary.get("checklist_item_count") or 0),
            "ops_code_count": int(import_summary.get("ops_code_count") or 0),
            "qr_asset_count": int(import_summary.get("qr_asset_count") or 0),
            "task_type_count": int(import_summary.get("task_type_count") or 0),
            "error_count": int(import_summary.get("error_count") or 0),
            "warning_count": int(import_summary.get("warning_count") or 0),
            "issue_bucket_count": int(import_summary.get("issue_bucket_count") or 0),
        },
        "top_issues": [
            {
                "severity": str(item.get("severity") or ""),
                "category": str(item.get("category") or ""),
                "code": str(item.get("code") or ""),
                "count": int(item.get("count") or 0),
                "message": str(item.get("message") or ""),
                "references": item.get("references") if isinstance(item.get("references"), list) else [],
            }
            for item in import_issues[:10]
            if isinstance(item, dict)
        ],
        "suggestions": import_suggestions[:5],
        },
    )
    qr_revision_attachment = _build_ops_qr_asset_revisions_attachment(
        start=start,
        end=end,
        month=normalized,
    )

    attachments = {
        "dr_rehearsal": dr_attachment,
        "ops_checklists_import_validation": import_attachment,
        "ops_qr_asset_revisions": qr_revision_attachment,
    }

    payload = {
        "format_version": AUDIT_ARCHIVE_FORMAT_VERSION,
        "attachment_schema_version": AUDIT_ARCHIVE_ATTACHMENT_SCHEMA_VERSION,
        "meta": {
            "schema": AUDIT_ARCHIVE_PAYLOAD_SCHEMA,
            "schema_version": "v1",
            "format_version": AUDIT_ARCHIVE_FORMAT_VERSION,
            "attachment_schema_version": AUDIT_ARCHIVE_ATTACHMENT_SCHEMA_VERSION,
            "month": normalized,
            "entries_included": include_entries,
        },
        "month": normalized,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entry_count": len(rows),
        "max_entries": max_entries,
        "entries_included": include_entries,
        "attachment_count": len(attachments),
        "attachments": attachments,
        "chain": chain,
        "dr_rehearsal_attachment": dr_attachment,
        "ops_checklists_import_validation_attachment": import_attachment,
        "ops_qr_asset_revisions_attachment": qr_revision_attachment,
        "entries": archive_rows if include_entries else [],
    }
    payload_text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    signature = _sign_payload(payload_text)
    payload["archive_sha256"] = hashlib.sha256(payload_text.encode("utf-8")).hexdigest()
    payload["signature"] = signature
    payload["signature_algorithm"] = "hmac-sha256" if signature is not None else "unsigned"
    return payload

def rebaseline_admin_audit_chain(
    *,
    from_month: str | None = None,
    max_rows: int = 50000,
    dry_run: bool = False,
) -> dict[str, Any]:
    start_dt: datetime | None = None
    normalized_month: str | None = None
    if from_month is not None:
        start_dt, _, normalized_month = _month_window(from_month)

    with get_conn() as conn:
        anchor_hash = ""
        anchor_id: int | None = None
        if start_dt is not None:
            anchor = conn.execute(
                select(
                    admin_audit_logs.c.id,
                    admin_audit_logs.c.entry_hash,
                )
                .where(admin_audit_logs.c.created_at < start_dt)
                .order_by(admin_audit_logs.c.created_at.desc(), admin_audit_logs.c.id.desc())
                .limit(1)
            ).mappings().first()
            if anchor is not None:
                anchor_id = int(anchor["id"])
                anchor_hash = str(anchor.get("entry_hash") or "")

        stmt = select(admin_audit_logs).order_by(
            admin_audit_logs.c.created_at.asc(),
            admin_audit_logs.c.id.asc(),
        )
        if start_dt is not None:
            stmt = stmt.where(admin_audit_logs.c.created_at >= start_dt)
        rows = conn.execute(stmt.limit(max_rows)).mappings().all()

        scanned_count = len(rows)
        updated_count = 0
        first_updated_id: int | None = None
        last_updated_id: int | None = None
        previous_hash = anchor_hash

        for row in rows:
            row_id = int(row["id"])
            detail_json = str(row.get("detail_json") or "{}")
            created_at = _as_datetime(row["created_at"])
            expected_hash = _compute_audit_entry_hash(
                prev_hash=previous_hash,
                actor_user_id=row.get("actor_user_id"),
                actor_username=str(row.get("actor_username") or ""),
                action=str(row.get("action") or ""),
                resource_type=str(row.get("resource_type") or ""),
                resource_id=str(row.get("resource_id") or ""),
                status=str(row.get("status") or ""),
                detail_json=detail_json,
                created_at=created_at,
            )

            stored_prev = str(row.get("prev_hash") or "")
            stored_hash = str(row.get("entry_hash") or "")
            changed = stored_prev != previous_hash or stored_hash != expected_hash
            if changed:
                updated_count += 1
                if first_updated_id is None:
                    first_updated_id = row_id
                last_updated_id = row_id
                if not dry_run:
                    conn.execute(
                        update(admin_audit_logs)
                        .where(admin_audit_logs.c.id == row_id)
                        .values(
                            prev_hash=previous_hash or None,
                            entry_hash=expected_hash,
                        )
                    )
            previous_hash = expected_hash

    return {
        "from_month": normalized_month,
        "max_rows": max_rows,
        "dry_run": dry_run,
        "anchor_id": anchor_id,
        "scanned_count": scanned_count,
        "updated_count": updated_count,
        "first_updated_id": first_updated_id,
        "last_updated_id": last_updated_id,
        "last_entry_hash": previous_hash or None,
    }

def _row_to_admin_user_model(row: dict[str, Any]) -> AdminUserRead:
    role = str(row["role"])
    custom_permissions = _permission_text_to_list(row["permissions"])
    user_site_scope = _site_scope_text_to_list(row["site_scope"], default_all=True)
    return AdminUserRead(
        id=int(row["id"]),
        username=str(row["username"]),
        display_name=str(row["display_name"] or row["username"]),
        role=role,
        permissions=_effective_permissions(role, custom_permissions),
        site_scope=user_site_scope,
        is_active=bool(row["is_active"]),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )

def _row_to_admin_token_model(row: dict[str, Any]) -> AdminTokenRead:
    user_scope = _site_scope_text_to_list(row.get("user_site_scope"), default_all=True)
    token_scope_raw = row.get("token_site_scope")
    token_scope = None
    if token_scope_raw is not None:
        token_scope = _site_scope_text_to_list(token_scope_raw, default_all=True)
    effective_scope = _resolve_effective_site_scope(user_scope=user_scope, token_scope=token_scope)
    created_at = _as_datetime(row["created_at"])
    expires_at = _as_optional_datetime(row["expires_at"])
    last_used_at = _as_optional_datetime(row["last_used_at"])
    rotate_due_at = _token_rotate_due_at(created_at)
    idle_due_at = _token_idle_due_at(created_at=created_at, last_used_at=last_used_at)
    warning_due_at = None
    if rotate_due_at is not None and ADMIN_TOKEN_ROTATE_WARNING_DAYS > 0:
        warning_due_at = rotate_due_at - timedelta(days=ADMIN_TOKEN_ROTATE_WARNING_DAYS)
    must_rotate = rotate_due_at is not None and warning_due_at is not None and datetime.now(timezone.utc) >= warning_due_at
    return AdminTokenRead(
        token_id=int(row["token_id"]),
        user_id=int(row["user_id"]),
        username=str(row["username"]),
        label=str(row["label"] or ""),
        is_active=bool(row["is_active"]),
        site_scope=effective_scope,
        expires_at=expires_at,
        last_used_at=last_used_at,
        created_at=created_at,
        rotate_due_at=rotate_due_at,
        idle_due_at=idle_due_at,
        must_rotate=must_rotate,
    )

def _principal_to_auth_me_model(
    principal: dict[str, Any],
    endpoint: str = "/api/auth/me",
) -> AuthMeRead:
    profile = AuthMeRead(
        user_id=principal.get("user_id"),
        token_id=principal.get("token_id"),
        token_label=principal.get("token_label"),
        token_expires_at=principal.get("token_expires_at"),
        token_rotate_due_at=principal.get("token_rotate_due_at"),
        token_idle_due_at=principal.get("token_idle_due_at"),
        token_must_rotate=bool(principal.get("token_must_rotate", False)),
        username=str(principal.get("username") or "unknown"),
        display_name=str(principal.get("display_name") or principal.get("username") or "unknown"),
        role=str(principal.get("role") or "operator"),
        permissions=list(principal.get("permissions", [])),
        site_scope=list(_principal_site_scope(principal)),
        is_legacy=bool(principal.get("is_legacy", False)),
    )
    return _attach_auth_me_meta(profile, endpoint=endpoint)

def _enforce_active_token_quota(
    *,
    conn: Any,
    user_id: int,
    now: datetime,
    keep_token_ids: set[int] | None = None,
) -> list[int]:
    keep_ids = keep_token_ids or set()
    rows = conn.execute(
        select(admin_tokens.c.id, admin_tokens.c.created_at)
        .where(admin_tokens.c.user_id == user_id)
        .where(admin_tokens.c.is_active.is_(True))
        .order_by(admin_tokens.c.created_at.asc(), admin_tokens.c.id.asc())
    ).all()
    active_ids = [int(row[0]) for row in rows if int(row[0]) not in keep_ids]
    overflow = len(active_ids) - ADMIN_TOKEN_MAX_ACTIVE_PER_USER
    if overflow <= 0:
        return []
    revoke_ids = active_ids[:overflow]
    conn.execute(
        update(admin_tokens)
        .where(admin_tokens.c.id.in_(revoke_ids))
        .values(is_active=False, last_used_at=now)
    )
    return revoke_ids
