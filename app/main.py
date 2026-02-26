import csv
import hashlib
import hmac
import io
import json
import secrets
import time
from datetime import datetime, timezone
from datetime import timedelta
from os import getenv
from typing import Annotated, Any, Callable
from urllib import error as url_error
from urllib import request as url_request

from fastapi import Depends, FastAPI, HTTPException, Header, Query
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import insert, select, update
from sqlalchemy.exc import SQLAlchemyError

from app.database import (
    DATABASE_URL,
    admin_audit_logs,
    admin_tokens,
    admin_users,
    ensure_database,
    get_conn,
    inspections,
    job_runs,
    sla_policies,
    work_orders,
)
from app.schemas import (
    AdminAuditLogRead,
    AdminTokenIssueRequest,
    AdminTokenIssueResponse,
    AdminTokenRead,
    AdminUserActiveUpdate,
    AdminUserCreate,
    AdminUserRead,
    AuthMeRead,
    DashboardSummaryRead,
    InspectionCreate,
    InspectionRead,
    JobRunRead,
    MonthlyReportRead,
    SlaAlertChannelResult,
    SlaEscalationRunRequest,
    SlaEscalationRunResponse,
    SlaPolicyRead,
    SlaPolicyUpdate,
    WorkOrderAck,
    WorkOrderComplete,
    WorkOrderCreate,
    WorkOrderRead,
)

app = FastAPI(
    title="KA Facility OS",
    description="Inspection MVP for apartment facility operations",
    version="0.7.0",
)

ADMIN_TOKEN = getenv("ADMIN_TOKEN", "").strip()
ENV_NAME = getenv("ENV", "local").lower()
ALLOW_INSECURE_LOCAL_AUTH = getenv("ALLOW_INSECURE_LOCAL_AUTH", "1").lower() in {
    "1",
    "true",
    "yes",
    "on",
}
ALERT_WEBHOOK_URL = getenv("ALERT_WEBHOOK_URL", "").strip()
ALERT_WEBHOOK_URLS = getenv("ALERT_WEBHOOK_URLS", "").strip()
ALERT_WEBHOOK_TIMEOUT_SEC = float(getenv("ALERT_WEBHOOK_TIMEOUT_SEC", "5"))
ALERT_WEBHOOK_RETRIES = int(getenv("ALERT_WEBHOOK_RETRIES", "3"))

ROLE_PERMISSION_MAP: dict[str, set[str]] = {
    "owner": {"*"},
    "manager": {
        "inspections:read",
        "inspections:write",
        "work_orders:read",
        "work_orders:write",
        "work_orders:escalate",
        "reports:read",
        "reports:export",
    },
    "operator": {
        "inspections:read",
        "inspections:write",
        "work_orders:read",
        "work_orders:write",
    },
    "auditor": {
        "inspections:read",
        "work_orders:read",
        "reports:read",
        "reports:export",
    },
}

SLA_DEFAULT_POLICY_KEY = "default"
SLA_DEFAULT_DUE_HOURS: dict[str, int] = {
    "low": 72,
    "medium": 24,
    "high": 8,
    "critical": 2,
}


@app.on_event("startup")
def on_startup() -> None:
    ensure_database()
    ensure_legacy_admin_token_seed()


def _permission_text_to_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [x.strip() for x in value.split(",") if x.strip()]
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return []


def _permission_list_to_text(values: list[str]) -> str:
    normalized = sorted({v.strip() for v in values if v.strip()})
    return ",".join(normalized)


def _effective_permissions(role: str, custom: list[str]) -> list[str]:
    perms = set(ROLE_PERMISSION_MAP.get(role, set()))
    perms.update(custom)
    if role == "owner":
        perms.add("*")
    return sorted(perms)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _has_active_admin_tokens() -> bool:
    try:
        with get_conn() as conn:
            row = conn.execute(
                select(admin_tokens.c.id).where(admin_tokens.c.is_active.is_(True)).limit(1)
            ).first()
        return row is not None
    except SQLAlchemyError:
        return False


def ensure_legacy_admin_token_seed() -> None:
    if not ADMIN_TOKEN:
        return

    now = datetime.now(timezone.utc)
    token_hash = _hash_token(ADMIN_TOKEN)
    with get_conn() as conn:
        existing = conn.execute(
            select(admin_tokens.c.id).where(admin_tokens.c.token_hash == token_hash)
        ).first()
        if existing is not None:
            return

        user_row = conn.execute(
            select(admin_users).where(admin_users.c.username == "legacy-admin")
        ).mappings().first()
        if user_row is None:
            result = conn.execute(
                insert(admin_users).values(
                    username="legacy-admin",
                    display_name="Legacy Bootstrap Admin",
                    role="owner",
                    permissions="*",
                    is_active=True,
                    created_at=now,
                    updated_at=now,
                )
            )
            user_id = int(result.inserted_primary_key[0])
        else:
            user_id = int(user_row["id"])
            conn.execute(
                update(admin_users)
                .where(admin_users.c.id == user_id)
                .values(
                    role="owner",
                    permissions="*",
                    is_active=True,
                    updated_at=now,
                )
            )

        conn.execute(
            insert(admin_tokens).values(
                user_id=user_id,
                label="legacy-env-admin-token",
                token_hash=token_hash,
                is_active=True,
                expires_at=None,
                last_used_at=None,
                created_at=now,
            )
        )


def _calculate_risk(payload: InspectionCreate) -> tuple[str, list[str]]:
    flags: list[str] = []

    if payload.insulation_mohm is not None and payload.insulation_mohm <= 1:
        flags.append("insulation_low")
    if payload.winding_temp_c is not None and payload.winding_temp_c >= 90:
        flags.append("temp_high")

    volts = [payload.voltage_r, payload.voltage_s, payload.voltage_t]
    if all(v is not None for v in volts):
        values = [float(v) for v in volts]
        avg = sum(values) / 3
        if avg > 0:
            max_unbalance = max(abs(v - avg) / avg * 100 for v in values)
            if max_unbalance > 3:
                flags.append("voltage_unbalance")

    if "insulation_low" in flags or "temp_high" in flags:
        return "danger", flags
    if flags:
        return "warning", flags
    return "normal", flags


def _to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _as_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    raise ValueError("Unsupported datetime value")


def _as_optional_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    return _as_datetime(value)


def _row_to_read_model(row: dict[str, Any]) -> InspectionRead:
    risk_flags_raw = row["risk_flags"] or ""
    risk_flags = [x for x in risk_flags_raw.split(",") if x]

    return InspectionRead(
        id=row["id"],
        site=row["site"],
        location=row["location"],
        cycle=row["cycle"],
        inspector=row["inspector"],
        inspected_at=_as_datetime(row["inspected_at"]),
        transformer_kva=row["transformer_kva"],
        voltage_r=row["voltage_r"],
        voltage_s=row["voltage_s"],
        voltage_t=row["voltage_t"],
        current_r=row["current_r"],
        current_s=row["current_s"],
        current_t=row["current_t"],
        winding_temp_c=row["winding_temp_c"],
        grounding_ohm=row["grounding_ohm"],
        insulation_mohm=row["insulation_mohm"],
        notes=row["notes"],
        risk_level=row["risk_level"],
        risk_flags=risk_flags,
        created_at=_as_datetime(row["created_at"]),
    )


def _is_overdue(status: str, due_at: datetime | None) -> bool:
    if due_at is None:
        return False
    if status in {"completed", "canceled"}:
        return False
    return due_at < datetime.now(timezone.utc)


def _month_window(month: str | None) -> tuple[datetime, datetime, str]:
    if month is None:
        now = datetime.now(timezone.utc)
        normalized = f"{now.year:04d}-{now.month:02d}"
    else:
        normalized = month

    try:
        year, month_num = normalized.split("-")
        start = datetime(int(year), int(month_num), 1, tzinfo=timezone.utc)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="month must be YYYY-MM format") from exc

    if start.month == 12:
        end = datetime(start.year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(start.year, start.month + 1, 1, tzinfo=timezone.utc)
    return start, end, normalized


def _load_principal_by_token(token: str) -> dict[str, Any] | None:
    now = datetime.now(timezone.utc)
    token_hash = _hash_token(token)

    stmt = (
        select(
            admin_tokens.c.id.label("token_id"),
            admin_tokens.c.user_id.label("user_id"),
            admin_tokens.c.expires_at.label("expires_at"),
            admin_users.c.username.label("username"),
            admin_users.c.display_name.label("display_name"),
            admin_users.c.role.label("role"),
            admin_users.c.permissions.label("permissions"),
        )
        .where(admin_tokens.c.token_hash == token_hash)
        .where(admin_tokens.c.is_active.is_(True))
        .where(admin_users.c.id == admin_tokens.c.user_id)
        .where(admin_users.c.is_active.is_(True))
        .limit(1)
    )

    try:
        with get_conn() as conn:
            row = conn.execute(stmt).mappings().first()
            if row is None:
                return None

            expires_at = _as_optional_datetime(row["expires_at"])
            if expires_at is not None and expires_at <= now:
                return None

            conn.execute(
                update(admin_tokens)
                .where(admin_tokens.c.id == row["token_id"])
                .values(last_used_at=now)
            )
    except SQLAlchemyError:
        return None

    custom_permissions = _permission_text_to_list(row["permissions"])
    permissions = _effective_permissions(str(row["role"]), custom_permissions)
    return {
        "user_id": int(row["user_id"]),
        "username": str(row["username"]),
        "display_name": str(row["display_name"] or row["username"]),
        "role": str(row["role"]),
        "permissions": permissions,
        "is_legacy": str(row["username"]) == "legacy-admin",
    }


def _build_local_dev_principal() -> dict[str, Any]:
    return {
        "user_id": None,
        "username": "local-dev",
        "display_name": "Local Dev Bypass",
        "role": "owner",
        "permissions": ["*"],
        "is_legacy": True,
    }


def get_current_admin(
    x_admin_token: Annotated[str | None, Header(alias="X-Admin-Token")] = None,
) -> dict[str, Any]:
    if x_admin_token:
        principal = _load_principal_by_token(x_admin_token)
        if principal is not None:
            return principal

        if ADMIN_TOKEN and hmac.compare_digest(x_admin_token, ADMIN_TOKEN):
            return {
                "user_id": None,
                "username": "legacy-env-token",
                "display_name": "Legacy Env Token",
                "role": "owner",
                "permissions": ["*"],
                "is_legacy": True,
            }
        raise HTTPException(status_code=401, detail="Invalid admin token")

    if (
        ENV_NAME != "production"
        and ALLOW_INSECURE_LOCAL_AUTH
        and not ADMIN_TOKEN
        and not _has_active_admin_tokens()
    ):
        return _build_local_dev_principal()

    raise HTTPException(status_code=401, detail="Missing admin token")


def _has_permission(principal: dict[str, Any], permission: str) -> bool:
    permissions = set(principal.get("permissions", []))
    if "*" in permissions or permission in permissions:
        return True
    namespace = f"{permission.split(':', 1)[0]}:*"
    return namespace in permissions


def require_permission(permission: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def dependency(principal: dict[str, Any] = Depends(get_current_admin)) -> dict[str, Any]:
        if not _has_permission(principal, permission):
            raise HTTPException(status_code=403, detail=f"Missing permission: {permission}")
        return principal

    return dependency


def _to_json_text(value: dict[str, Any] | None) -> str:
    data = value or {}
    return json.dumps(data, ensure_ascii=False, default=str)


def _write_audit_log(
    *,
    principal: dict[str, Any] | None,
    action: str,
    resource_type: str,
    resource_id: str,
    status: str = "success",
    detail: dict[str, Any] | None = None,
) -> None:
    now = datetime.now(timezone.utc)
    actor_user_id = None
    actor_username = "system"
    if principal is not None:
        actor_user_id = principal.get("user_id")
        actor_username = str(principal.get("username") or "unknown")

    try:
        with get_conn() as conn:
            conn.execute(
                insert(admin_audit_logs).values(
                    actor_user_id=actor_user_id,
                    actor_username=actor_username,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    status=status,
                    detail_json=_to_json_text(detail),
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


def _write_job_run(
    *,
    job_name: str,
    trigger: str,
    status: str,
    started_at: datetime,
    finished_at: datetime,
    detail: dict[str, Any] | None = None,
) -> None:
    try:
        with get_conn() as conn:
            conn.execute(
                insert(job_runs).values(
                    job_name=job_name,
                    trigger=trigger,
                    status=status,
                    started_at=started_at,
                    finished_at=finished_at,
                    detail_json=_to_json_text(detail),
                )
            )
    except SQLAlchemyError:
        return


def _row_to_job_run_model(row: dict[str, Any]) -> JobRunRead:
    raw = str(row["detail_json"] or "{}")
    try:
        detail = json.loads(raw)
    except json.JSONDecodeError:
        detail = {"raw": raw}
    if not isinstance(detail, dict):
        detail = {"value": detail}

    return JobRunRead(
        id=int(row["id"]),
        job_name=str(row["job_name"]),
        trigger=str(row["trigger"]),
        status=str(row["status"]),
        started_at=_as_datetime(row["started_at"]),
        finished_at=_as_datetime(row["finished_at"]),
        detail=detail,
    )


def _normalize_sla_due_hours(value: Any) -> dict[str, int]:
    source = value if isinstance(value, dict) else {}
    normalized: dict[str, int] = {}
    for priority, default_hours in SLA_DEFAULT_DUE_HOURS.items():
        raw_hours = source.get(priority, default_hours)
        try:
            hours = int(raw_hours)
        except (TypeError, ValueError):
            hours = default_hours
        if hours < 1 or hours > 24 * 30:
            hours = default_hours
        normalized[priority] = hours
    return normalized


def _normalize_sla_policy(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    due_hours = _normalize_sla_due_hours(source.get("default_due_hours"))

    raw_grace = source.get("escalation_grace_minutes", 0)
    try:
        grace_minutes = int(raw_grace)
    except (TypeError, ValueError):
        grace_minutes = 0
    grace_minutes = max(0, min(1440, grace_minutes))

    return {
        "default_due_hours": due_hours,
        "escalation_grace_minutes": grace_minutes,
    }


def _parse_sla_policy_json(raw: Any) -> dict[str, Any]:
    try:
        loaded = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        loaded = {}
    return _normalize_sla_policy(loaded)


def _sla_policy_to_model(*, updated_at: datetime, policy: dict[str, Any]) -> SlaPolicyRead:
    return SlaPolicyRead(
        policy_key=SLA_DEFAULT_POLICY_KEY,
        default_due_hours=policy["default_due_hours"],
        escalation_grace_minutes=policy["escalation_grace_minutes"],
        updated_at=updated_at,
    )


def _load_sla_policy() -> tuple[dict[str, Any], datetime]:
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(sla_policies)
            .where(sla_policies.c.policy_key == SLA_DEFAULT_POLICY_KEY)
            .limit(1)
        ).mappings().first()
        if row is None:
            policy = _normalize_sla_policy({})
            conn.execute(
                insert(sla_policies).values(
                    policy_key=SLA_DEFAULT_POLICY_KEY,
                    policy_json=_to_json_text(policy),
                    updated_at=now,
                )
            )
            return policy, now

    policy = _parse_sla_policy_json(row["policy_json"])
    updated_at = _as_datetime(row["updated_at"]) if row["updated_at"] is not None else now
    return policy, updated_at


def _upsert_sla_policy(payload: SlaPolicyUpdate) -> SlaPolicyRead:
    now = datetime.now(timezone.utc)
    policy = _normalize_sla_policy(payload.model_dump())
    with get_conn() as conn:
        row = conn.execute(
            select(sla_policies.c.id)
            .where(sla_policies.c.policy_key == SLA_DEFAULT_POLICY_KEY)
            .limit(1)
        ).first()
        if row is None:
            conn.execute(
                insert(sla_policies).values(
                    policy_key=SLA_DEFAULT_POLICY_KEY,
                    policy_json=_to_json_text(policy),
                    updated_at=now,
                )
            )
        else:
            conn.execute(
                update(sla_policies)
                .where(sla_policies.c.policy_key == SLA_DEFAULT_POLICY_KEY)
                .values(policy_json=_to_json_text(policy), updated_at=now)
            )

    return _sla_policy_to_model(updated_at=now, policy=policy)


def _configured_alert_targets() -> list[str]:
    targets: list[str] = []
    merged_raw = ALERT_WEBHOOK_URLS.replace(";", ",").replace("\n", ",")
    for part in merged_raw.split(","):
        value = part.strip()
        if value:
            targets.append(value)
    if ALERT_WEBHOOK_URL:
        targets.append(ALERT_WEBHOOK_URL)

    deduped: list[str] = []
    seen: set[str] = set()
    for target in targets:
        if target in seen:
            continue
        seen.add(target)
        deduped.append(target)
    return deduped


def _post_json_with_retries(
    *,
    url: str,
    payload: dict[str, Any],
    retries: int,
    timeout_sec: float,
) -> tuple[bool, str | None]:
    body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    attempts = max(1, retries)
    for attempt in range(1, attempts + 1):
        req = url_request.Request(
            url=url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with url_request.urlopen(req, timeout=timeout_sec) as resp:
                status_code = int(getattr(resp, "status", 0))
                if 200 <= status_code < 300:
                    return True, None
                err = f"webhook returned status {status_code}"
        except url_error.HTTPError as exc:
            err = f"webhook http error {exc.code}"
        except url_error.URLError as exc:
            err = f"webhook url error: {exc.reason}"
        except Exception as exc:  # pragma: no cover - defensive path
            err = f"webhook unexpected error: {exc}"

        if attempt < attempts:
            time.sleep(0.5 * (2 ** (attempt - 1)))
    return False, err


def _dispatch_sla_alert(
    *,
    site: str | None,
    checked_at: datetime,
    escalated_count: int,
    work_order_ids: list[int],
) -> tuple[bool, str | None, list[SlaAlertChannelResult]]:
    if escalated_count <= 0:
        return False, None, []

    targets = _configured_alert_targets()
    if not targets:
        return False, None, []

    payload = {
        "event": "sla_escalation",
        "site": site or "ALL",
        "checked_at": checked_at.isoformat(),
        "escalated_count": escalated_count,
        "work_order_ids": work_order_ids,
    }
    results: list[SlaAlertChannelResult] = []
    success_count = 0
    failed_count = 0

    for target in targets:
        ok, err = _post_json_with_retries(
            url=target,
            payload=payload,
            retries=ALERT_WEBHOOK_RETRIES,
            timeout_sec=ALERT_WEBHOOK_TIMEOUT_SEC,
        )
        if ok:
            success_count += 1
        else:
            failed_count += 1
        results.append(SlaAlertChannelResult(target=target, success=ok, error=err))

    if failed_count == 0:
        return True, None, results
    if success_count > 0:
        return True, f"{failed_count}/{len(results)} alert channels failed", results
    return False, "all alert channels failed", results


def _row_to_admin_user_model(row: dict[str, Any]) -> AdminUserRead:
    role = str(row["role"])
    custom_permissions = _permission_text_to_list(row["permissions"])
    return AdminUserRead(
        id=int(row["id"]),
        username=str(row["username"]),
        display_name=str(row["display_name"] or row["username"]),
        role=role,
        permissions=_effective_permissions(role, custom_permissions),
        is_active=bool(row["is_active"]),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _row_to_admin_token_model(row: dict[str, Any]) -> AdminTokenRead:
    return AdminTokenRead(
        token_id=int(row["token_id"]),
        user_id=int(row["user_id"]),
        username=str(row["username"]),
        label=str(row["label"] or ""),
        is_active=bool(row["is_active"]),
        expires_at=_as_optional_datetime(row["expires_at"]),
        last_used_at=_as_optional_datetime(row["last_used_at"]),
        created_at=_as_datetime(row["created_at"]),
    )


def _row_to_work_order_model(row: dict[str, Any]) -> WorkOrderRead:
    due_at = _as_optional_datetime(row["due_at"])
    status = row["status"]
    return WorkOrderRead(
        id=row["id"],
        title=row["title"],
        description=row["description"] or "",
        site=row["site"],
        location=row["location"],
        priority=row["priority"],
        status=status,
        assignee=row["assignee"],
        reporter=row["reporter"],
        inspection_id=row["inspection_id"],
        due_at=due_at,
        acknowledged_at=_as_optional_datetime(row["acknowledged_at"]),
        completed_at=_as_optional_datetime(row["completed_at"]),
        resolution_notes=row["resolution_notes"] or "",
        is_escalated=bool(row["is_escalated"]),
        is_overdue=_is_overdue(status, due_at),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def run_sla_escalation_job(
    *,
    site: str | None = None,
    dry_run: bool = False,
    limit: int = 200,
    trigger: str = "manual",
) -> SlaEscalationRunResponse:
    started_at = datetime.now(timezone.utc)
    now = started_at
    policy, _ = _load_sla_policy()
    grace_minutes = int(policy["escalation_grace_minutes"])
    due_cutoff = now - timedelta(minutes=grace_minutes)
    stmt = (
        select(work_orders)
        .where(work_orders.c.due_at.is_not(None))
        .where(work_orders.c.due_at < due_cutoff)
        .where(work_orders.c.status.in_(["open", "acked"]))
        .where(work_orders.c.is_escalated.is_(False))
        .order_by(work_orders.c.due_at.asc())
        .limit(limit)
    )
    if site is not None:
        stmt = stmt.where(work_orders.c.site == site)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
        ids = [int(r["id"]) for r in rows]
        escalated_count = 0
        if ids and not dry_run:
            conn.execute(
                update(work_orders)
                .where(work_orders.c.id.in_(ids))
                .values(is_escalated=True, updated_at=now)
            )
            escalated_count = len(ids)

    alert_dispatched = False
    alert_error: str | None = None
    alert_channels: list[SlaAlertChannelResult] = []
    if not dry_run and escalated_count > 0:
        alert_dispatched, alert_error, alert_channels = _dispatch_sla_alert(
            site=site,
            checked_at=now,
            escalated_count=escalated_count,
            work_order_ids=ids,
        )
        _write_audit_log(
            principal=None,
            action="sla_escalation_batch",
            resource_type="work_order",
            resource_id="batch",
            status="success" if alert_error is None else "warning",
            detail={
                "site": site,
                "dry_run": dry_run,
                "candidate_count": len(ids),
                "escalated_count": escalated_count,
                "grace_minutes": grace_minutes,
                "alert_dispatched": alert_dispatched,
                "alert_error": alert_error,
                "alert_channels": [channel.model_dump() for channel in alert_channels],
                "work_order_ids": ids,
            },
        )

    finished_at = datetime.now(timezone.utc)
    _write_job_run(
        job_name="sla_escalation",
        trigger=trigger,
        status="success" if alert_error is None else "warning",
        started_at=started_at,
        finished_at=finished_at,
        detail={
            "site": site,
            "dry_run": dry_run,
            "limit": limit,
            "candidate_count": len(ids),
            "escalated_count": escalated_count,
            "grace_minutes": grace_minutes,
            "alert_dispatched": alert_dispatched,
            "alert_error": alert_error,
            "alert_channels": [channel.model_dump() for channel in alert_channels],
        },
    )

    return SlaEscalationRunResponse(
        checked_at=finished_at,
        dry_run=dry_run,
        site=site,
        candidate_count=len(ids),
        escalated_count=escalated_count,
        work_order_ids=ids,
        alert_dispatched=alert_dispatched,
        alert_error=alert_error,
        alert_channels=alert_channels,
    )


def build_monthly_report(month: str | None, site: str | None) -> MonthlyReportRead:
    start, end, month_label = _month_window(month)
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

    with get_conn() as conn:
        inspection_rows = conn.execute(inspections_stmt).mappings().all()
        work_order_rows = conn.execute(work_orders_stmt).mappings().all()

    risk_counts = {"normal": 0, "warning": 0, "danger": 0}
    flag_counts: dict[str, int] = {}
    for row in inspection_rows:
        risk_level = row["risk_level"] or "normal"
        risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        flags = (row["risk_flags"] or "").split(",")
        for flag in flags:
            if not flag:
                continue
            flag_counts[flag] = flag_counts.get(flag, 0) + 1

    status_counts = {"open": 0, "acked": 0, "completed": 0, "canceled": 0}
    escalated_count = 0
    overdue_open_count = 0
    resolution_hours: list[float] = []
    for row in work_order_rows:
        status = row["status"] or "open"
        status_counts[status] = status_counts.get(status, 0) + 1
        if row["is_escalated"]:
            escalated_count += 1

        due_at = _as_optional_datetime(row["due_at"])
        if due_at is not None and status not in {"completed", "canceled"} and due_at < now:
            overdue_open_count += 1

        created_at = _as_optional_datetime(row["created_at"])
        completed_at = _as_optional_datetime(row["completed_at"])
        if created_at is not None and completed_at is not None:
            hours = (completed_at - created_at).total_seconds() / 3600
            if hours >= 0:
                resolution_hours.append(hours)

    total_work_orders = len(work_order_rows)
    completed_count = status_counts.get("completed", 0)
    completion_rate = round((completed_count / total_work_orders * 100), 2) if total_work_orders else 0.0
    avg_resolution_hours = round(sum(resolution_hours) / len(resolution_hours), 2) if resolution_hours else None

    return MonthlyReportRead(
        month=month_label,
        site=site,
        generated_at=now,
        inspections={
            "total": len(inspection_rows),
            "risk_counts": risk_counts,
            "top_risk_flags": dict(sorted(flag_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
        },
        work_orders={
            "total": total_work_orders,
            "status_counts": status_counts,
            "escalated_count": escalated_count,
            "overdue_open_count": overdue_open_count,
            "completion_rate_percent": completion_rate,
            "avg_resolution_hours": avg_resolution_hours,
        },
    )


def build_dashboard_summary(
    *,
    site: str | None,
    days: int,
    recent_job_limit: int,
) -> DashboardSummaryRead:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)

    inspections_stmt = select(inspections).where(inspections.c.inspected_at >= start)
    work_orders_window_stmt = select(work_orders).where(work_orders.c.created_at >= start)
    work_orders_open_stmt = select(work_orders).where(work_orders.c.status.in_(["open", "acked"]))
    job_runs_stmt = (
        select(job_runs)
        .where(job_runs.c.finished_at >= start)
        .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
        .limit(recent_job_limit)
    )
    report_exports_stmt = (
        select(admin_audit_logs.c.action)
        .where(admin_audit_logs.c.created_at >= start)
        .where(admin_audit_logs.c.action.in_(["report_monthly_export_csv", "report_monthly_export_pdf"]))
    )

    if site is not None:
        inspections_stmt = inspections_stmt.where(inspections.c.site == site)
        work_orders_window_stmt = work_orders_window_stmt.where(work_orders.c.site == site)
        work_orders_open_stmt = work_orders_open_stmt.where(work_orders.c.site == site)

    with get_conn() as conn:
        inspection_rows = conn.execute(inspections_stmt).mappings().all()
        work_order_window_rows = conn.execute(work_orders_window_stmt).mappings().all()
        work_order_open_rows = conn.execute(work_orders_open_stmt).mappings().all()
        job_rows = conn.execute(job_runs_stmt).mappings().all()
        export_rows = conn.execute(report_exports_stmt).all()

    inspection_risk_counts = {"normal": 0, "warning": 0, "danger": 0}
    for row in inspection_rows:
        risk_level = str(row["risk_level"] or "normal")
        inspection_risk_counts[risk_level] = inspection_risk_counts.get(risk_level, 0) + 1

    work_order_status_counts = {"open": 0, "acked": 0, "completed": 0, "canceled": 0}
    for row in work_order_window_rows:
        status = str(row["status"] or "open")
        work_order_status_counts[status] = work_order_status_counts.get(status, 0) + 1

    overdue_open_count = 0
    escalated_open_count = 0
    for row in work_order_open_rows:
        if row["is_escalated"]:
            escalated_open_count += 1
        due_at = _as_optional_datetime(row["due_at"])
        if due_at is not None and due_at < now:
            overdue_open_count += 1

    recent_jobs = [_row_to_job_run_model(row) for row in job_rows]
    sla_recent_runs = [job for job in recent_jobs if job.job_name == "sla_escalation"]
    sla_last_run_at = sla_recent_runs[0].finished_at if sla_recent_runs else None
    sla_warning_runs = sum(1 for job in sla_recent_runs if job.status != "success")

    return DashboardSummaryRead(
        generated_at=now,
        site=site,
        window_days=days,
        inspections_total=len(inspection_rows),
        inspection_risk_counts=inspection_risk_counts,
        work_orders_total=len(work_order_window_rows),
        work_order_status_counts=work_order_status_counts,
        overdue_open_count=overdue_open_count,
        escalated_open_count=escalated_open_count,
        report_export_count=len(export_rows),
        sla_recent_runs=len(sla_recent_runs),
        sla_warning_runs=sla_warning_runs,
        sla_last_run_at=sla_last_run_at,
        recent_job_runs=recent_jobs,
    )


def _json_or_scalar(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    if value is None:
        return ""
    return str(value)


def _build_monthly_report_csv(report: MonthlyReportRead) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["section", "key", "value"])
    writer.writerow(["meta", "month", report.month])
    writer.writerow(["meta", "site", report.site or "ALL"])
    writer.writerow(["meta", "generated_at", report.generated_at.isoformat()])
    writer.writerow(["inspections", "total", report.inspections.get("total", 0)])

    risk_counts = report.inspections.get("risk_counts", {})
    for key, value in risk_counts.items():
        writer.writerow(["inspections.risk_counts", key, value])

    top_flags = report.inspections.get("top_risk_flags", {})
    for key, value in top_flags.items():
        writer.writerow(["inspections.top_risk_flags", key, value])

    writer.writerow(["work_orders", "total", report.work_orders.get("total", 0)])
    for key, value in report.work_orders.items():
        if key == "status_counts":
            continue
        writer.writerow(["work_orders", key, _json_or_scalar(value)])

    status_counts = report.work_orders.get("status_counts", {})
    for key, value in status_counts.items():
        writer.writerow(["work_orders.status_counts", key, value])
    return out.getvalue()


def _build_monthly_report_pdf(report: MonthlyReportRead) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise HTTPException(status_code=500, detail="PDF generator dependency not installed") from exc

    lines = [
        f"Monthly Audit Report ({report.month})",
        "",
        f"Site: {report.site or 'ALL'}",
        f"Generated At: {report.generated_at.isoformat()}",
        "",
        "[Inspection Summary]",
        f"Total: {report.inspections.get('total', 0)}",
        f"Risk Counts: {_json_or_scalar(report.inspections.get('risk_counts', {}))}",
        f"Top Risk Flags: {_json_or_scalar(report.inspections.get('top_risk_flags', {}))}",
        "",
        "[Work Order Summary]",
        f"Total: {report.work_orders.get('total', 0)}",
        f"Status Counts: {_json_or_scalar(report.work_orders.get('status_counts', {}))}",
        f"Escalated Count: {report.work_orders.get('escalated_count', 0)}",
        f"Overdue Open Count: {report.work_orders.get('overdue_open_count', 0)}",
        f"Completion Rate (%): {report.work_orders.get('completion_rate_percent', 0)}",
        f"Avg Resolution Hours: {report.work_orders.get('avg_resolution_hours') or '-'}",
    ]

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


@app.get("/")
def root() -> dict[str, str]:
    return {
        "service": "ka-facility-os",
        "status": "running",
        "docs": "/docs",
        "inspection_api": "/api/inspections",
        "work_order_api": "/api/work-orders",
        "escalation_api": "/api/work-orders/escalations/run",
        "monthly_report_api": "/api/reports/monthly",
        "monthly_report_csv_api": "/api/reports/monthly/csv",
        "monthly_report_pdf_api": "/api/reports/monthly/pdf",
        "auth_me_api": "/api/auth/me",
        "admin_tokens_api": "/api/admin/tokens",
        "admin_audit_api": "/api/admin/audit-logs",
        "job_runs_api": "/api/ops/job-runs",
        "dashboard_summary_api": "/api/ops/dashboard/summary",
        "sla_policy_api": "/api/admin/policies/sla",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/meta")
def meta() -> dict[str, str]:
    db_backend = "postgresql" if DATABASE_URL.startswith("postgresql+") else "sqlite"
    return {"env": getenv("ENV", "local"), "db": db_backend}


@app.get("/api/auth/me", response_model=AuthMeRead)
def auth_me(
    principal: dict[str, Any] = Depends(get_current_admin),
) -> AuthMeRead:
    return AuthMeRead(
        user_id=principal.get("user_id"),
        username=principal["username"],
        display_name=principal["display_name"],
        role=principal["role"],
        permissions=list(principal.get("permissions", [])),
        is_legacy=bool(principal.get("is_legacy", False)),
    )


@app.get("/api/admin/users", response_model=list[AdminUserRead])
def list_admin_users(
    _: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> list[AdminUserRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(admin_users).order_by(admin_users.c.created_at.desc(), admin_users.c.id.desc())
        ).mappings().all()
    return [_row_to_admin_user_model(row) for row in rows]


@app.post("/api/admin/users", response_model=AdminUserRead, status_code=201)
def create_admin_user(
    payload: AdminUserCreate,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> AdminUserRead:
    now = datetime.now(timezone.utc)
    permissions_text = _permission_list_to_text(payload.permissions)
    display_name = payload.display_name.strip() or payload.username

    with get_conn() as conn:
        existing = conn.execute(
            select(admin_users.c.id).where(admin_users.c.username == payload.username)
        ).first()
        if existing is not None:
            raise HTTPException(status_code=409, detail="username already exists")

        result = conn.execute(
            insert(admin_users).values(
                username=payload.username,
                display_name=display_name,
                role=payload.role,
                permissions=permissions_text,
                is_active=payload.is_active,
                created_at=now,
                updated_at=now,
            )
        )
        user_id = result.inserted_primary_key[0]
        row = conn.execute(select(admin_users).where(admin_users.c.id == user_id)).mappings().first()

    if row is None:
        raise HTTPException(status_code=500, detail="Failed to load created admin user")
    model = _row_to_admin_user_model(row)
    _write_audit_log(
        principal=principal,
        action="admin_user_create",
        resource_type="admin_user",
        resource_id=str(model.id),
        detail={"username": model.username, "role": model.role, "is_active": model.is_active},
    )
    return model


@app.patch("/api/admin/users/{user_id}/active", response_model=AdminUserRead)
def set_admin_user_active(
    user_id: int,
    payload: AdminUserActiveUpdate,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> AdminUserRead:
    now = datetime.now(timezone.utc)
    actor_user_id = principal.get("user_id")
    if actor_user_id is not None and int(actor_user_id) == user_id and payload.is_active is False:
        raise HTTPException(status_code=409, detail="Cannot deactivate current admin user")

    with get_conn() as conn:
        row = conn.execute(select(admin_users).where(admin_users.c.id == user_id)).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Admin user not found")

        conn.execute(
            update(admin_users)
            .where(admin_users.c.id == user_id)
            .values(is_active=payload.is_active, updated_at=now)
        )

        if payload.is_active is False:
            conn.execute(
                update(admin_tokens)
                .where(admin_tokens.c.user_id == user_id)
                .values(is_active=False)
            )

        updated = conn.execute(select(admin_users).where(admin_users.c.id == user_id)).mappings().first()

    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to update admin user")
    model = _row_to_admin_user_model(updated)
    _write_audit_log(
        principal=principal,
        action="admin_user_set_active",
        resource_type="admin_user",
        resource_id=str(model.id),
        detail={"username": model.username, "is_active": model.is_active},
    )
    return model


@app.post("/api/admin/users/{user_id}/tokens", response_model=AdminTokenIssueResponse, status_code=201)
def issue_admin_token(
    user_id: int,
    payload: AdminTokenIssueRequest,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> AdminTokenIssueResponse:
    now = datetime.now(timezone.utc)
    token_plain = f"kaos_{secrets.token_urlsafe(24)}"
    token_hash = _hash_token(token_plain)
    expires_at = _as_optional_datetime(payload.expires_at)

    with get_conn() as conn:
        user_row = conn.execute(select(admin_users).where(admin_users.c.id == user_id)).mappings().first()
        if user_row is None:
            raise HTTPException(status_code=404, detail="Admin user not found")
        if not user_row["is_active"]:
            raise HTTPException(status_code=409, detail="Inactive user cannot receive token")

        result = conn.execute(
            insert(admin_tokens).values(
                user_id=user_id,
                label=payload.label,
                token_hash=token_hash,
                is_active=True,
                expires_at=expires_at,
                last_used_at=None,
                created_at=now,
            )
        )
        token_id = int(result.inserted_primary_key[0])

    response = AdminTokenIssueResponse(
        token_id=token_id,
        user_id=user_id,
        label=payload.label,
        token=token_plain,
        expires_at=expires_at,
        created_at=now,
    )
    _write_audit_log(
        principal=principal,
        action="admin_token_issue",
        resource_type="admin_token",
        resource_id=str(token_id),
        detail={"user_id": user_id, "label": payload.label, "expires_at": expires_at},
    )
    return response


@app.get("/api/admin/tokens", response_model=list[AdminTokenRead])
def list_admin_tokens(
    user_id: Annotated[int | None, Query()] = None,
    active_only: Annotated[bool, Query()] = False,
    _: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> list[AdminTokenRead]:
    stmt = (
        select(
            admin_tokens.c.id.label("token_id"),
            admin_tokens.c.user_id.label("user_id"),
            admin_users.c.username.label("username"),
            admin_tokens.c.label.label("label"),
            admin_tokens.c.is_active.label("is_active"),
            admin_tokens.c.expires_at.label("expires_at"),
            admin_tokens.c.last_used_at.label("last_used_at"),
            admin_tokens.c.created_at.label("created_at"),
        )
        .where(admin_users.c.id == admin_tokens.c.user_id)
        .order_by(admin_tokens.c.created_at.desc(), admin_tokens.c.id.desc())
    )
    if user_id is not None:
        stmt = stmt.where(admin_tokens.c.user_id == user_id)
    if active_only:
        stmt = stmt.where(admin_tokens.c.is_active.is_(True))

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_admin_token_model(row) for row in rows]


@app.get("/api/admin/audit-logs", response_model=list[AdminAuditLogRead])
def list_admin_audit_logs(
    action: Annotated[str | None, Query()] = None,
    actor_username: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    _: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> list[AdminAuditLogRead]:
    stmt = select(admin_audit_logs).order_by(
        admin_audit_logs.c.created_at.desc(), admin_audit_logs.c.id.desc()
    )
    if action is not None:
        stmt = stmt.where(admin_audit_logs.c.action == action)
    if actor_username is not None:
        stmt = stmt.where(admin_audit_logs.c.actor_username == actor_username)
    stmt = stmt.limit(limit).offset(offset)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_admin_audit_log_model(row) for row in rows]


@app.get("/api/ops/job-runs", response_model=list[JobRunRead])
def list_job_runs(
    job_name: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    _: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> list[JobRunRead]:
    stmt = select(job_runs).order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
    if job_name is not None:
        stmt = stmt.where(job_runs.c.job_name == job_name)
    stmt = stmt.limit(limit).offset(offset)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_job_run_model(row) for row in rows]


@app.get("/api/ops/dashboard/summary", response_model=DashboardSummaryRead)
def get_dashboard_summary(
    site: Annotated[str | None, Query()] = None,
    days: Annotated[int, Query(ge=1, le=90)] = 30,
    recent_job_limit: Annotated[int, Query(alias="job_limit", ge=1, le=50)] = 10,
    _: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> DashboardSummaryRead:
    return build_dashboard_summary(site=site, days=days, recent_job_limit=recent_job_limit)


@app.get("/api/admin/policies/sla", response_model=SlaPolicyRead)
def get_sla_policy(
    _: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaPolicyRead:
    policy, updated_at = _load_sla_policy()
    return _sla_policy_to_model(updated_at=updated_at, policy=policy)


@app.put("/api/admin/policies/sla", response_model=SlaPolicyRead)
def set_sla_policy(
    payload: SlaPolicyUpdate,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaPolicyRead:
    model = _upsert_sla_policy(payload)
    _write_audit_log(
        principal=principal,
        action="sla_policy_update",
        resource_type="sla_policy",
        resource_id=model.policy_key,
        detail={
            "default_due_hours": model.default_due_hours,
            "escalation_grace_minutes": model.escalation_grace_minutes,
        },
    )
    return model


@app.post("/api/admin/tokens/{token_id}/revoke", response_model=AdminTokenRead)
def revoke_admin_token(
    token_id: int,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> AdminTokenRead:
    now = datetime.now(timezone.utc)

    with get_conn() as conn:
        row = conn.execute(
            select(
                admin_tokens.c.id.label("token_id"),
                admin_tokens.c.user_id.label("user_id"),
                admin_users.c.username.label("username"),
                admin_tokens.c.label.label("label"),
                admin_tokens.c.is_active.label("is_active"),
                admin_tokens.c.expires_at.label("expires_at"),
                admin_tokens.c.last_used_at.label("last_used_at"),
                admin_tokens.c.created_at.label("created_at"),
            )
            .where(admin_tokens.c.id == token_id)
            .where(admin_users.c.id == admin_tokens.c.user_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Admin token not found")

        actor_user_id = principal.get("user_id")
        if actor_user_id is not None and int(actor_user_id) == int(row["user_id"]):
            raise HTTPException(status_code=409, detail="Cannot revoke token of current admin user")

        conn.execute(
            update(admin_tokens)
            .where(admin_tokens.c.id == token_id)
            .values(is_active=False, last_used_at=now)
        )
        updated = conn.execute(
            select(
                admin_tokens.c.id.label("token_id"),
                admin_tokens.c.user_id.label("user_id"),
                admin_users.c.username.label("username"),
                admin_tokens.c.label.label("label"),
                admin_tokens.c.is_active.label("is_active"),
                admin_tokens.c.expires_at.label("expires_at"),
                admin_tokens.c.last_used_at.label("last_used_at"),
                admin_tokens.c.created_at.label("created_at"),
            )
            .where(admin_tokens.c.id == token_id)
            .where(admin_users.c.id == admin_tokens.c.user_id)
        ).mappings().first()

    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to revoke admin token")
    model = _row_to_admin_token_model(updated)
    _write_audit_log(
        principal=principal,
        action="admin_token_revoke",
        resource_type="admin_token",
        resource_id=str(model.token_id),
        detail={"user_id": model.user_id, "label": model.label},
    )
    return model


@app.post("/api/inspections", response_model=InspectionRead, status_code=201)
def create_inspection(
    payload: InspectionCreate,
    principal: dict[str, Any] = Depends(require_permission("inspections:write")),
) -> InspectionRead:
    risk_level, flags = _calculate_risk(payload)
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
        detail={"site": model.site, "location": model.location, "risk_level": model.risk_level},
    )
    return model


@app.get("/api/inspections", response_model=list[InspectionRead])
def list_inspections(
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    _: dict[str, Any] = Depends(require_permission("inspections:read")),
) -> list[InspectionRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(inspections)
            .order_by(inspections.c.inspected_at.desc(), inspections.c.id.desc())
            .limit(limit)
            .offset(offset)
        ).mappings().all()
    return [_row_to_read_model(r) for r in rows]


@app.get("/api/inspections/{inspection_id}", response_model=InspectionRead)
def get_inspection(
    inspection_id: int,
    _: dict[str, Any] = Depends(require_permission("inspections:read")),
) -> InspectionRead:
    with get_conn() as conn:
        row = conn.execute(
            select(inspections).where(inspections.c.id == inspection_id)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Inspection not found")
    return _row_to_read_model(row)


@app.get("/inspections/{inspection_id}/print", response_class=HTMLResponse)
def print_inspection(
    inspection_id: int,
    _: dict[str, Any] = Depends(require_permission("inspections:read")),
) -> str:
    with get_conn() as conn:
        row = conn.execute(
            select(inspections).where(inspections.c.id == inspection_id)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Inspection not found")

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


@app.post("/api/work-orders", response_model=WorkOrderRead, status_code=201)
def create_work_order(
    payload: WorkOrderCreate,
    principal: dict[str, Any] = Depends(require_permission("work_orders:write")),
) -> WorkOrderRead:
    now = datetime.now(timezone.utc)
    due_at = _as_optional_datetime(payload.due_at)
    auto_due_applied = False
    if due_at is None:
        policy, _ = _load_sla_policy()
        due_hours = int(policy["default_due_hours"].get(payload.priority, SLA_DEFAULT_DUE_HOURS["medium"]))
        due_at = now + timedelta(hours=due_hours)
        auto_due_applied = True

    with get_conn() as conn:
        result = conn.execute(
            insert(work_orders).values(
                title=payload.title,
                description=payload.description,
                site=payload.site,
                location=payload.location,
                priority=payload.priority,
                status="open",
                assignee=payload.assignee,
                reporter=payload.reporter,
                inspection_id=payload.inspection_id,
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
            "due_at": model.due_at,
            "auto_due_applied": auto_due_applied,
        },
    )
    return model


@app.get("/api/work-orders", response_model=list[WorkOrderRead])
def list_work_orders(
    status: Annotated[str | None, Query()] = None,
    site: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    _: dict[str, Any] = Depends(require_permission("work_orders:read")),
) -> list[WorkOrderRead]:
    stmt = select(work_orders)
    if status is not None:
        stmt = stmt.where(work_orders.c.status == status)
    if site is not None:
        stmt = stmt.where(work_orders.c.site == site)

    stmt = stmt.order_by(work_orders.c.created_at.desc(), work_orders.c.id.desc()).limit(limit).offset(offset)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_work_order_model(r) for r in rows]


@app.get("/api/work-orders/{work_order_id}", response_model=WorkOrderRead)
def get_work_order(
    work_order_id: int,
    _: dict[str, Any] = Depends(require_permission("work_orders:read")),
) -> WorkOrderRead:
    with get_conn() as conn:
        row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Work order not found")
    return _row_to_work_order_model(row)


@app.patch("/api/work-orders/{work_order_id}/ack", response_model=WorkOrderRead)
def ack_work_order(
    work_order_id: int,
    payload: WorkOrderAck,
    principal: dict[str, Any] = Depends(require_permission("work_orders:write")),
) -> WorkOrderRead:
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Work order not found")
        if row["status"] == "completed":
            raise HTTPException(status_code=409, detail="Completed work order cannot be acked")

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
    with get_conn() as conn:
        row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Work order not found")
        if row["status"] == "completed":
            return _row_to_work_order_model(row)

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


@app.post("/api/work-orders/escalations/run", response_model=SlaEscalationRunResponse)
def run_sla_escalation(
    payload: SlaEscalationRunRequest,
    principal: dict[str, Any] = Depends(require_permission("work_orders:escalate")),
) -> SlaEscalationRunResponse:
    result = run_sla_escalation_job(
        site=payload.site,
        dry_run=payload.dry_run,
        limit=payload.limit,
        trigger="api",
    )
    _write_audit_log(
        principal=principal,
        action="work_order_sla_escalation_run",
        resource_type="work_order",
        resource_id="batch",
        detail={
            "site": payload.site,
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
    _: dict[str, Any] = Depends(require_permission("reports:read")),
) -> MonthlyReportRead:
    return build_monthly_report(month=month, site=site)


@app.get("/api/reports/monthly/csv")
def get_monthly_report_csv(
    month: Annotated[str | None, Query(description="YYYY-MM", pattern=r"^\d{4}-\d{2}$")] = None,
    site: Annotated[str | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("reports:export")),
) -> Response:
    report = build_monthly_report(month=month, site=site)
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
    report = build_monthly_report(month=month, site=site)
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
    _: dict[str, Any] = Depends(require_permission("reports:read")),
) -> str:
    report = build_monthly_report(month=month, site=site)
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
