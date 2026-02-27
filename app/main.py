import csv
import hashlib
import hmac
import io
import json
import secrets
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
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
    alert_deliveries,
    admin_audit_logs,
    admin_tokens,
    admin_users,
    ensure_database,
    get_conn,
    inspections,
    job_runs,
    sla_policies,
    sla_policy_proposals,
    sla_policy_revisions,
    work_order_events,
    work_orders,
)
from app.schemas import (
    AlertRetryRunRequest,
    AlertRetryRunResponse,
    AlertDeliveryRead,
    AdminAuditLogRead,
    AdminTokenIssueRequest,
    AdminTokenIssueResponse,
    AdminTokenRead,
    AdminUserActiveUpdate,
    AdminUserCreate,
    AdminUserRead,
    AuthMeRead,
    DashboardSummaryRead,
    DashboardTrendPoint,
    DashboardTrendsRead,
    InspectionCreate,
    InspectionRead,
    JobRunRead,
    MonthlyReportRead,
    OpsHandoverBriefRead,
    OpsHandoverInspectionRead,
    OpsHandoverWorkOrderRead,
    SlaAlertChannelResult,
    SlaEscalationRunRequest,
    SlaEscalationRunResponse,
    SlaPolicyRead,
    SlaPolicyProposalCreate,
    SlaPolicyProposalDecision,
    SlaPolicyProposalRead,
    SlaPolicyRestoreRequest,
    SlaPolicyRevisionRead,
    SlaPolicyUpdate,
    SlaWhatIfRequest,
    SlaWhatIfResponse,
    WorkOrderAck,
    WorkOrderCancel,
    WorkOrderCommentCreate,
    WorkOrderComplete,
    WorkOrderCreate,
    WorkOrderEventRead,
    WorkOrderReopen,
    WorkOrderRead,
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
SLA_SITE_POLICY_PREFIX = "site:"
SLA_DEFAULT_DUE_HOURS: dict[str, int] = {
    "low": 72,
    "medium": 24,
    "high": 8,
    "critical": 2,
}
SITE_SCOPE_ALL = "*"
WORK_ORDER_TRANSITIONS: dict[str, set[str]] = {
    "open": {"acked", "completed", "canceled"},
    "acked": {"completed", "canceled"},
    "completed": {"open"},
    "canceled": {"open"},
}
SLA_PROPOSAL_STATUS_PENDING = "pending"
SLA_PROPOSAL_STATUS_APPROVED = "approved"
SLA_PROPOSAL_STATUS_REJECTED = "rejected"


@asynccontextmanager
async def app_lifespan(_: FastAPI) -> AsyncIterator[None]:
    ensure_database()
    ensure_legacy_admin_token_seed()
    yield


app = FastAPI(
    title="KA Facility OS",
    description="Inspection MVP for apartment facility operations",
    version="0.17.0",
    lifespan=app_lifespan,
)


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


def _site_scope_text_to_list(value: Any, *, default_all: bool = True) -> list[str]:
    if value is None:
        return [SITE_SCOPE_ALL] if default_all else []
    if isinstance(value, str):
        raw_values = [x.strip() for x in value.split(",") if x.strip()]
    elif isinstance(value, list):
        raw_values = [str(x).strip() for x in value if str(x).strip()]
    else:
        raw_values = []

    if not raw_values:
        return [SITE_SCOPE_ALL] if default_all else []
    if SITE_SCOPE_ALL in raw_values:
        return [SITE_SCOPE_ALL]
    return sorted(set(raw_values))


def _site_scope_list_to_text(values: list[str]) -> str:
    normalized = _site_scope_text_to_list(values, default_all=True)
    return ",".join(normalized)


def _resolve_effective_site_scope(
    *,
    user_scope: list[str],
    token_scope: list[str] | None,
) -> list[str]:
    normalized_user_scope = _site_scope_text_to_list(user_scope, default_all=True)
    if token_scope is None:
        return normalized_user_scope

    normalized_token_scope = _site_scope_text_to_list(token_scope, default_all=True)
    if SITE_SCOPE_ALL in normalized_user_scope:
        return normalized_token_scope
    if SITE_SCOPE_ALL in normalized_token_scope:
        return normalized_user_scope

    intersection = sorted(set(normalized_user_scope).intersection(normalized_token_scope))
    return intersection


def _principal_site_scope(principal: dict[str, Any]) -> list[str]:
    raw_scope = principal.get("site_scope", [SITE_SCOPE_ALL])
    return _site_scope_text_to_list(raw_scope, default_all=True)


def _allowed_sites_for_principal(principal: dict[str, Any]) -> list[str] | None:
    scope = _principal_site_scope(principal)
    if SITE_SCOPE_ALL in scope:
        return None
    return scope


def _has_site_access(principal: dict[str, Any], site: str | None) -> bool:
    if site is None:
        return True
    scope = _principal_site_scope(principal)
    if SITE_SCOPE_ALL in scope:
        return True
    return site in scope


def _require_site_access(principal: dict[str, Any], site: str | None) -> None:
    if not _has_site_access(principal, site):
        raise HTTPException(status_code=403, detail="Site access denied")


def _require_global_site_scope(principal: dict[str, Any]) -> None:
    if SITE_SCOPE_ALL not in _principal_site_scope(principal):
        raise HTTPException(status_code=403, detail="Global site scope required")


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
                    site_scope=SITE_SCOPE_ALL,
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
                    site_scope=SITE_SCOPE_ALL,
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
                site_scope=None,
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
            admin_tokens.c.site_scope.label("token_site_scope"),
            admin_users.c.username.label("username"),
            admin_users.c.display_name.label("display_name"),
            admin_users.c.role.label("role"),
            admin_users.c.permissions.label("permissions"),
            admin_users.c.site_scope.label("user_site_scope"),
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
    user_scope = _site_scope_text_to_list(row["user_site_scope"], default_all=True)
    token_scope_raw = row["token_site_scope"]
    token_scope = None
    if token_scope_raw is not None:
        token_scope = _site_scope_text_to_list(token_scope_raw, default_all=True)
    effective_site_scope = _resolve_effective_site_scope(user_scope=user_scope, token_scope=token_scope)
    return {
        "user_id": int(row["user_id"]),
        "username": str(row["username"]),
        "display_name": str(row["display_name"] or row["username"]),
        "role": str(row["role"]),
        "permissions": permissions,
        "site_scope": effective_site_scope,
        "is_legacy": str(row["username"]) == "legacy-admin",
    }


def _build_local_dev_principal() -> dict[str, Any]:
    return {
        "user_id": None,
        "username": "local-dev",
        "display_name": "Local Dev Bypass",
        "role": "owner",
        "permissions": ["*"],
        "site_scope": [SITE_SCOPE_ALL],
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
                "site_scope": [SITE_SCOPE_ALL],
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


def _write_alert_delivery(
    *,
    event_type: str,
    target: str,
    status: str,
    error: str | None,
    payload: dict[str, Any],
) -> int | None:
    now = datetime.now(timezone.utc)
    try:
        with get_conn() as conn:
            result = conn.execute(
                insert(alert_deliveries).values(
                    event_type=event_type,
                    target=target,
                    status=status,
                    error=error,
                    payload_json=_to_json_text(payload),
                    attempt_count=1,
                    last_attempt_at=now,
                    created_at=now,
                    updated_at=now,
                )
            )
            return int(result.inserted_primary_key[0])
    except SQLAlchemyError:
        return None


def _row_to_alert_delivery_model(row: dict[str, Any]) -> AlertDeliveryRead:
    raw = str(row["payload_json"] or "{}")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = {"raw": raw}
    if not isinstance(payload, dict):
        payload = {"value": payload}

    return AlertDeliveryRead(
        id=int(row["id"]),
        event_type=str(row["event_type"]),
        target=str(row["target"]),
        status=str(row["status"]),
        error=row["error"],
        payload=payload,
        attempt_count=int(row["attempt_count"]),
        last_attempt_at=_as_datetime(row["last_attempt_at"]),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _row_to_sla_policy_proposal_model(row: dict[str, Any]) -> SlaPolicyProposalRead:
    policy_raw = str(row["policy_json"] or "{}")
    simulation_raw = str(row["simulation_json"] or "{}")
    try:
        policy = json.loads(policy_raw)
    except json.JSONDecodeError:
        policy = {"raw": policy_raw}
    if not isinstance(policy, dict):
        policy = {"value": policy}

    try:
        simulation = json.loads(simulation_raw)
    except json.JSONDecodeError:
        simulation = {"raw": simulation_raw}
    if not isinstance(simulation, dict):
        simulation = {"value": simulation}

    return SlaPolicyProposalRead(
        id=int(row["id"]),
        site=row["site"],
        status=str(row["status"]),
        policy=policy,
        simulation=simulation,
        note=str(row["note"] or ""),
        requested_by=str(row["requested_by"]),
        decided_by=row["decided_by"],
        decision_note=row["decision_note"],
        created_at=_as_datetime(row["created_at"]),
        decided_at=_as_optional_datetime(row["decided_at"]),
        applied_at=_as_optional_datetime(row["applied_at"]),
    )


def _write_sla_policy_revision(
    *,
    site: str | None,
    policy: dict[str, Any],
    source_action: str,
    actor_username: str,
    note: str = "",
) -> None:
    now = datetime.now(timezone.utc)
    try:
        with get_conn() as conn:
            conn.execute(
                insert(sla_policy_revisions).values(
                    site=site,
                    policy_json=_to_json_text(policy),
                    source_action=source_action,
                    actor_username=actor_username,
                    note=note,
                    created_at=now,
                )
            )
    except SQLAlchemyError:
        return


def _row_to_sla_policy_revision_model(row: dict[str, Any]) -> SlaPolicyRevisionRead:
    raw = str(row["policy_json"] or "{}")
    try:
        policy = json.loads(raw)
    except json.JSONDecodeError:
        policy = {"raw": raw}
    if not isinstance(policy, dict):
        policy = {"value": policy}

    return SlaPolicyRevisionRead(
        id=int(row["id"]),
        site=row["site"],
        policy=policy,
        source_action=str(row["source_action"]),
        actor_username=str(row["actor_username"]),
        note=str(row["note"] or ""),
        created_at=_as_datetime(row["created_at"]),
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


def _normalize_site_name(site: str | None) -> str | None:
    if site is None:
        return None
    value = site.strip()
    return value or None


def _policy_key_for_site(site: str | None) -> str | None:
    normalized_site = _normalize_site_name(site)
    if normalized_site is None:
        return None
    return f"{SLA_SITE_POLICY_PREFIX}{normalized_site}"


def _get_sla_policy_row(policy_key: str) -> dict[str, Any] | None:
    with get_conn() as conn:
        return conn.execute(
            select(sla_policies).where(sla_policies.c.policy_key == policy_key).limit(1)
        ).mappings().first()


def _ensure_default_sla_policy() -> tuple[dict[str, Any], datetime]:
    now = datetime.now(timezone.utc)
    row = _get_sla_policy_row(SLA_DEFAULT_POLICY_KEY)
    if row is None:
        policy = _normalize_sla_policy({})
        with get_conn() as conn:
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


def _sla_policy_to_model(
    *,
    policy_key: str,
    site: str | None,
    source: str,
    updated_at: datetime,
    policy: dict[str, Any],
) -> SlaPolicyRead:
    return SlaPolicyRead(
        policy_key=policy_key,
        site=site,
        source=source,
        default_due_hours=policy["default_due_hours"],
        escalation_grace_minutes=policy["escalation_grace_minutes"],
        updated_at=updated_at,
    )


def _load_sla_policy(
    site: str | None = None,
) -> tuple[dict[str, Any], datetime, str, str | None, str]:
    normalized_site = _normalize_site_name(site)
    default_policy, default_updated_at = _ensure_default_sla_policy()
    site_policy_key = _policy_key_for_site(normalized_site)
    if site_policy_key is None:
        return default_policy, default_updated_at, "default", None, SLA_DEFAULT_POLICY_KEY

    row = _get_sla_policy_row(site_policy_key)
    if row is None:
        # Site requested but override does not exist: use default policy.
        return default_policy, default_updated_at, "default", normalized_site, SLA_DEFAULT_POLICY_KEY

    now = datetime.now(timezone.utc)
    policy = _parse_sla_policy_json(row["policy_json"])
    updated_at = _as_datetime(row["updated_at"]) if row["updated_at"] is not None else now
    return policy, updated_at, "site", normalized_site, site_policy_key


def _upsert_sla_policy(
    payload: SlaPolicyUpdate,
    site: str | None = None,
    *,
    source_action: str = "manual_update",
    actor_username: str = "system",
    note: str = "",
) -> SlaPolicyRead:
    now = datetime.now(timezone.utc)
    policy = _normalize_sla_policy(payload.model_dump())
    normalized_site = _normalize_site_name(site)
    policy_key = _policy_key_for_site(normalized_site) or SLA_DEFAULT_POLICY_KEY
    source = "site" if normalized_site is not None else "default"

    with get_conn() as conn:
        row = conn.execute(
            select(sla_policies.c.id)
            .where(sla_policies.c.policy_key == policy_key)
            .limit(1)
        ).first()
        if row is None:
            conn.execute(
                insert(sla_policies).values(
                    policy_key=policy_key,
                    policy_json=_to_json_text(policy),
                    updated_at=now,
                )
            )
        else:
            conn.execute(
                update(sla_policies)
                .where(sla_policies.c.policy_key == policy_key)
                .values(policy_json=_to_json_text(policy), updated_at=now)
            )

    _write_sla_policy_revision(
        site=normalized_site,
        policy=policy,
        source_action=source_action,
        actor_username=actor_username,
        note=note,
    )

    return _sla_policy_to_model(
        policy_key=policy_key,
        site=normalized_site,
        source=source,
        updated_at=now,
        policy=policy,
    )


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
        delivery_status = "success" if ok and err is None else ("warning" if ok else "failed")
        delivery_id = _write_alert_delivery(
            event_type="sla_escalation",
            target=target,
            status=delivery_status,
            error=err,
            payload=payload,
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
    return AdminTokenRead(
        token_id=int(row["token_id"]),
        user_id=int(row["user_id"]),
        username=str(row["username"]),
        label=str(row["label"] or ""),
        is_active=bool(row["is_active"]),
        site_scope=effective_scope,
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


def _validate_work_order_transition(current_status: str, next_status: str) -> None:
    allowed = WORK_ORDER_TRANSITIONS.get(current_status, set())
    if next_status not in allowed:
        raise HTTPException(status_code=409, detail=f"Invalid status transition: {current_status} -> {next_status}")


def _append_work_order_event(
    conn: Any,
    *,
    work_order_id: int,
    event_type: str,
    actor_username: str,
    from_status: str | None = None,
    to_status: str | None = None,
    note: str = "",
    detail: dict[str, Any] | None = None,
) -> None:
    conn.execute(
        insert(work_order_events).values(
            work_order_id=work_order_id,
            event_type=event_type,
            actor_username=actor_username,
            from_status=from_status,
            to_status=to_status,
            note=note,
            detail_json=_to_json_text(detail),
            created_at=datetime.now(timezone.utc),
        )
    )


def _row_to_work_order_event_model(row: dict[str, Any]) -> WorkOrderEventRead:
    raw = str(row["detail_json"] or "{}")
    try:
        detail = json.loads(raw)
    except json.JSONDecodeError:
        detail = {"raw": raw}
    if not isinstance(detail, dict):
        detail = {"value": detail}

    return WorkOrderEventRead(
        id=int(row["id"]),
        work_order_id=int(row["work_order_id"]),
        event_type=str(row["event_type"]),
        actor_username=str(row["actor_username"]),
        from_status=row["from_status"],
        to_status=row["to_status"],
        note=str(row["note"] or ""),
        detail=detail,
        created_at=_as_datetime(row["created_at"]),
    )


def run_sla_escalation_job(
    *,
    site: str | None = None,
    dry_run: bool = False,
    limit: int = 200,
    allowed_sites: list[str] | None = None,
    trigger: str = "manual",
) -> SlaEscalationRunResponse:
    started_at = datetime.now(timezone.utc)
    now = started_at
    stmt = (
        select(work_orders)
        .where(work_orders.c.due_at.is_not(None))
        .where(work_orders.c.due_at < now)
        .where(work_orders.c.status.in_(["open", "acked"]))
        .where(work_orders.c.is_escalated.is_(False))
        .order_by(work_orders.c.due_at.asc())
        .limit(limit * 5)
    )
    if site is not None:
        stmt = stmt.where(work_orders.c.site == site)
    elif allowed_sites is not None:
        if not allowed_sites:
            finished_at = datetime.now(timezone.utc)
            _write_job_run(
                job_name="sla_escalation",
                trigger=trigger,
                status="success",
                started_at=started_at,
                finished_at=finished_at,
                detail={
                    "site": site,
                    "dry_run": dry_run,
                    "limit": limit,
                    "allowed_sites": allowed_sites,
                    "candidate_count": 0,
                    "escalated_count": 0,
                    "grace_minutes_by_site": {},
                    "alert_dispatched": False,
                    "alert_error": None,
                    "alert_channels": [],
                },
            )
            return SlaEscalationRunResponse(
                checked_at=finished_at,
                dry_run=dry_run,
                site=site,
                candidate_count=0,
                escalated_count=0,
                work_order_ids=[],
                alert_dispatched=False,
                alert_error=None,
                alert_channels=[],
            )
        stmt = stmt.where(work_orders.c.site.in_(allowed_sites))

    grace_minutes_by_site: dict[str, int] = {}

    def _resolve_grace(site_name: str) -> int:
        key = site_name.strip()
        if key in grace_minutes_by_site:
            return grace_minutes_by_site[key]
        policy, _, _, _, _ = _load_sla_policy(site=key if key else None)
        grace_value = int(policy["escalation_grace_minutes"])
        grace_minutes_by_site[key] = grace_value
        return grace_value

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
        ids: list[int] = []
        for row in rows:
            due_at = _as_optional_datetime(row["due_at"])
            if due_at is None:
                continue
            row_site = str(row["site"] or "")
            row_grace = _resolve_grace(row_site)
            due_cutoff = now - timedelta(minutes=row_grace)
            if due_at < due_cutoff:
                ids.append(int(row["id"]))
            if len(ids) >= limit:
                break

        escalated_count = 0
        escalated_ids: list[int] = []
        if ids and not dry_run:
            for work_order_id in ids:
                update_result = conn.execute(
                    update(work_orders)
                    .where(work_orders.c.id == work_order_id)
                    .where(work_orders.c.status.in_(["open", "acked"]))
                    .where(work_orders.c.is_escalated.is_(False))
                    .values(is_escalated=True, updated_at=now)
                )
                if update_result.rowcount and update_result.rowcount > 0:
                    escalated_ids.append(work_order_id)
            escalated_count = len(escalated_ids)

    work_order_ids = ids if dry_run else escalated_ids

    alert_dispatched = False
    alert_error: str | None = None
    alert_channels: list[SlaAlertChannelResult] = []
    if not dry_run and escalated_count > 0:
        alert_dispatched, alert_error, alert_channels = _dispatch_sla_alert(
            site=site,
            checked_at=now,
            escalated_count=escalated_count,
            work_order_ids=work_order_ids,
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
                "allowed_sites": allowed_sites,
                "candidate_count": len(ids),
                "escalated_count": escalated_count,
                "grace_minutes_by_site": grace_minutes_by_site,
                "alert_dispatched": alert_dispatched,
                "alert_error": alert_error,
                "alert_channels": [channel.model_dump() for channel in alert_channels],
                "work_order_ids": work_order_ids,
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
            "allowed_sites": allowed_sites,
            "candidate_count": len(ids),
            "escalated_count": escalated_count,
            "grace_minutes_by_site": grace_minutes_by_site,
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
        work_order_ids=work_order_ids,
        alert_dispatched=alert_dispatched,
        alert_error=alert_error,
        alert_channels=alert_channels,
    )


def run_alert_retry_job(
    *,
    event_type: str | None = None,
    only_status: list[str] | None = None,
    limit: int = 200,
    max_attempt_count: int = 10,
    min_last_attempt_age_sec: int = 30,
    trigger: str = "manual",
) -> AlertRetryRunResponse:
    started_at = datetime.now(timezone.utc)
    now = started_at
    statuses = [s.strip().lower() for s in (only_status or ["failed", "warning"]) if s.strip()]
    if not statuses:
        statuses = ["failed", "warning"]
    statuses = sorted(set(statuses))
    normalized_limit = max(1, min(limit, 5000))
    normalized_max_attempt_count = max(1, min(max_attempt_count, 1000))
    cooldown_cutoff = now - timedelta(seconds=max(0, min(min_last_attempt_age_sec, 86400)))

    stmt = (
        select(alert_deliveries)
        .where(alert_deliveries.c.status.in_(statuses))
        .where(alert_deliveries.c.attempt_count < normalized_max_attempt_count)
        .where(alert_deliveries.c.last_attempt_at <= cooldown_cutoff)
        .order_by(alert_deliveries.c.last_attempt_at.asc(), alert_deliveries.c.id.asc())
        .limit(normalized_limit)
    )
    if event_type is not None:
        stmt = stmt.where(alert_deliveries.c.event_type == event_type)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()

    processed_count = 0
    success_count = 0
    warning_count = 0
    failed_count = 0
    delivery_ids: list[int] = []

    with get_conn() as conn:
        for row in rows:
            delivery_id = int(row["id"])
            current_status = str(row["status"] or "failed")
            current_attempt_count = int(row["attempt_count"])
            claim_result = conn.execute(
                update(alert_deliveries)
                .where(alert_deliveries.c.id == delivery_id)
                .where(alert_deliveries.c.status == current_status)
                .where(alert_deliveries.c.attempt_count == current_attempt_count)
                .values(
                    attempt_count=current_attempt_count + 1,
                    last_attempt_at=now,
                    updated_at=now,
                )
            )
            if not claim_result.rowcount or claim_result.rowcount <= 0:
                continue

            payload_raw = str(row["payload_json"] or "{}")
            try:
                payload = json.loads(payload_raw)
            except json.JSONDecodeError:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}

            ok, err = _post_json_with_retries(
                url=str(row["target"]),
                payload=payload,
                retries=1,
                timeout_sec=ALERT_WEBHOOK_TIMEOUT_SEC,
            )
            next_status = "success" if ok and err is None else ("warning" if ok else "failed")
            conn.execute(
                update(alert_deliveries)
                .where(alert_deliveries.c.id == delivery_id)
                .where(alert_deliveries.c.attempt_count == (current_attempt_count + 1))
                .values(
                    status=next_status,
                    error=err,
                    updated_at=now,
                )
            )

            processed_count += 1
            delivery_ids.append(delivery_id)
            if next_status == "success":
                success_count += 1
            elif next_status == "warning":
                warning_count += 1
            else:
                failed_count += 1

    finished_at = datetime.now(timezone.utc)
    _write_job_run(
        job_name="alert_retry",
        trigger=trigger,
        status="warning" if failed_count > 0 else "success",
        started_at=started_at,
        finished_at=finished_at,
        detail={
            "event_type": event_type,
            "statuses": statuses,
            "limit": normalized_limit,
            "max_attempt_count": normalized_max_attempt_count,
            "min_last_attempt_age_sec": min_last_attempt_age_sec,
            "processed_count": processed_count,
            "success_count": success_count,
            "warning_count": warning_count,
            "failed_count": failed_count,
            "delivery_ids": delivery_ids,
        },
    )
    return AlertRetryRunResponse(
        checked_at=finished_at,
        event_type=event_type,
        limit=normalized_limit,
        processed_count=processed_count,
        success_count=success_count,
        warning_count=warning_count,
        failed_count=failed_count,
        delivery_ids=delivery_ids,
    )


def simulate_sla_policy_change(
    *,
    policy: SlaPolicyUpdate,
    site: str | None = None,
    limit: int = 3000,
    include_work_order_ids: bool = True,
    sample_size: int = 200,
    recompute_due_from_policy: bool = False,
    allowed_sites: list[str] | None = None,
) -> SlaWhatIfResponse:
    now = datetime.now(timezone.utc)
    normalized_site = _normalize_site_name(site)
    normalized_limit = max(1, min(limit, 20000))
    normalized_sample_size = max(0, min(sample_size, 1000))
    simulated_policy = _normalize_sla_policy(policy.model_dump())

    stmt = (
        select(work_orders)
        .where(work_orders.c.status.in_(["open", "acked"]))
        .where(work_orders.c.is_escalated.is_(False))
        .order_by(work_orders.c.due_at.asc(), work_orders.c.id.asc())
        .limit(normalized_limit)
    )
    if normalized_site is not None:
        stmt = stmt.where(work_orders.c.site == normalized_site)
    elif allowed_sites is not None:
        if not allowed_sites:
            return SlaWhatIfResponse(
                checked_at=now,
                site=normalized_site,
                limit=normalized_limit,
                total_candidates=0,
                baseline_escalate_count=0,
                simulated_escalate_count=0,
                delta_escalate_count=0,
                baseline_by_site={},
                simulated_by_site={},
                newly_escalated_ids=[],
                no_longer_escalated_ids=[],
                notes=["No accessible sites in current principal scope."],
            )
        stmt = stmt.where(work_orders.c.site.in_(allowed_sites))

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()

    current_policy_cache: dict[str, dict[str, Any]] = {}

    def _current_policy_for_site(site_name: str) -> dict[str, Any]:
        key = site_name.strip()
        if key in current_policy_cache:
            return current_policy_cache[key]
        loaded, _, _, _, _ = _load_sla_policy(site=key if key else None)
        current_policy_cache[key] = loaded
        return loaded

    baseline_count = 0
    simulated_count = 0
    baseline_by_site: dict[str, int] = {}
    simulated_by_site: dict[str, int] = {}
    newly_escalated_ids: list[int] = []
    no_longer_escalated_ids: list[int] = []

    for row in rows:
        row_id = int(row["id"])
        row_site = str(row["site"] or "")
        row_priority = str(row["priority"] or "medium")

        due_at_baseline = _as_optional_datetime(row["due_at"])
        created_at = _as_optional_datetime(row["created_at"])
        if due_at_baseline is None and not recompute_due_from_policy:
            continue
        if created_at is None:
            continue

        current_policy = _current_policy_for_site(row_site)
        current_grace = int(current_policy["escalation_grace_minutes"])
        baseline_cutoff = now - timedelta(minutes=current_grace)

        simulated_applies = normalized_site is None or row_site == normalized_site
        simulated_grace = (
            int(simulated_policy["escalation_grace_minutes"])
            if simulated_applies
            else int(current_policy["escalation_grace_minutes"])
        )
        simulated_cutoff = now - timedelta(minutes=simulated_grace)

        due_at_for_baseline = due_at_baseline
        due_at_for_simulated = due_at_baseline
        if recompute_due_from_policy and simulated_applies:
            simulated_hours = int(
                simulated_policy["default_due_hours"].get(
                    row_priority, SLA_DEFAULT_DUE_HOURS.get(row_priority, SLA_DEFAULT_DUE_HOURS["medium"])
                )
            )
            due_at_for_simulated = created_at + timedelta(hours=simulated_hours)
        if due_at_for_baseline is None:
            baseline_hours = int(
                current_policy["default_due_hours"].get(
                    row_priority, SLA_DEFAULT_DUE_HOURS.get(row_priority, SLA_DEFAULT_DUE_HOURS["medium"])
                )
            )
            due_at_for_baseline = created_at + timedelta(hours=baseline_hours)
        if due_at_for_simulated is None:
            due_at_for_simulated = due_at_for_baseline

        baseline_escalates = due_at_for_baseline < baseline_cutoff
        simulated_escalates = due_at_for_simulated < simulated_cutoff

        if baseline_escalates:
            baseline_count += 1
            baseline_by_site[row_site] = baseline_by_site.get(row_site, 0) + 1
        if simulated_escalates:
            simulated_count += 1
            simulated_by_site[row_site] = simulated_by_site.get(row_site, 0) + 1

        if include_work_order_ids and normalized_sample_size > 0:
            if simulated_escalates and not baseline_escalates and len(newly_escalated_ids) < normalized_sample_size:
                newly_escalated_ids.append(row_id)
            if baseline_escalates and not simulated_escalates and len(no_longer_escalated_ids) < normalized_sample_size:
                no_longer_escalated_ids.append(row_id)

    notes = [
        "Simulation is read-only and does not mutate work-order state.",
        "Due-hours policy mainly affects future created work orders unless recompute_due_from_policy=true.",
    ]
    return SlaWhatIfResponse(
        checked_at=now,
        site=normalized_site,
        limit=normalized_limit,
        total_candidates=len(rows),
        baseline_escalate_count=baseline_count,
        simulated_escalate_count=simulated_count,
        delta_escalate_count=simulated_count - baseline_count,
        baseline_by_site=baseline_by_site,
        simulated_by_site=simulated_by_site,
        newly_escalated_ids=newly_escalated_ids,
        no_longer_escalated_ids=no_longer_escalated_ids,
        notes=notes,
    )


def build_monthly_report(
    month: str | None,
    site: str | None,
    allowed_sites: list[str] | None = None,
) -> MonthlyReportRead:
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
    elif allowed_sites is not None:
        if not allowed_sites:
            return MonthlyReportRead(
                month=month_label,
                site=site,
                generated_at=now,
                inspections={"total": 0, "risk_counts": {"normal": 0, "warning": 0, "danger": 0}, "top_risk_flags": {}},
                work_orders={
                    "total": 0,
                    "status_counts": {"open": 0, "acked": 0, "completed": 0, "canceled": 0},
                    "escalated_count": 0,
                    "overdue_open_count": 0,
                    "completion_rate_percent": 0.0,
                    "avg_resolution_hours": None,
                },
            )
        inspections_stmt = inspections_stmt.where(inspections.c.site.in_(allowed_sites))
        work_orders_stmt = work_orders_stmt.where(work_orders.c.site.in_(allowed_sites))

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
    allowed_sites: list[str] | None = None,
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
    elif allowed_sites is not None:
        if not allowed_sites:
            return DashboardSummaryRead(
                generated_at=now,
                site=site,
                window_days=days,
                inspections_total=0,
                inspection_risk_counts={"normal": 0, "warning": 0, "danger": 0},
                work_orders_total=0,
                work_order_status_counts={"open": 0, "acked": 0, "completed": 0, "canceled": 0},
                overdue_open_count=0,
                escalated_open_count=0,
                report_export_count=0,
                sla_recent_runs=0,
                sla_warning_runs=0,
                sla_last_run_at=None,
                recent_job_runs=[],
            )
        inspections_stmt = inspections_stmt.where(inspections.c.site.in_(allowed_sites))
        work_orders_window_stmt = work_orders_window_stmt.where(work_orders.c.site.in_(allowed_sites))
        work_orders_open_stmt = work_orders_open_stmt.where(work_orders.c.site.in_(allowed_sites))

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


def build_dashboard_trends(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> DashboardTrendsRead:
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)

    inspections_stmt = select(inspections.c.inspected_at, inspections.c.site).where(inspections.c.inspected_at >= start)
    work_orders_stmt = select(
        work_orders.c.created_at,
        work_orders.c.completed_at,
        work_orders.c.site,
    ).where((work_orders.c.created_at >= start) | (work_orders.c.completed_at >= start))
    escalations_stmt = (
        select(job_runs.c.finished_at, job_runs.c.detail_json)
        .where(job_runs.c.job_name == "sla_escalation")
        .where(job_runs.c.finished_at >= start)
    )

    if site is not None:
        inspections_stmt = inspections_stmt.where(inspections.c.site == site)
        work_orders_stmt = work_orders_stmt.where(work_orders.c.site == site)
    elif allowed_sites is not None:
        if not allowed_sites:
            return DashboardTrendsRead(generated_at=now, site=site, window_days=days, points=[])
        inspections_stmt = inspections_stmt.where(inspections.c.site.in_(allowed_sites))
        work_orders_stmt = work_orders_stmt.where(work_orders.c.site.in_(allowed_sites))

    with get_conn() as conn:
        inspection_rows = conn.execute(inspections_stmt).mappings().all()
        work_order_rows = conn.execute(work_orders_stmt).mappings().all()
        escalation_rows = conn.execute(escalations_stmt).mappings().all()

    buckets: dict[str, dict[str, int]] = {}
    for i in range(days):
        bucket_day = (start + timedelta(days=i)).date().isoformat()
        buckets[bucket_day] = {
            "inspections_count": 0,
            "work_orders_created_count": 0,
            "work_orders_completed_count": 0,
            "work_orders_escalated_count": 0,
        }

    for row in inspection_rows:
        inspected_at = _as_optional_datetime(row["inspected_at"])
        if inspected_at is None:
            continue
        key = inspected_at.date().isoformat()
        if key in buckets:
            buckets[key]["inspections_count"] += 1

    for row in work_order_rows:
        created_at = _as_optional_datetime(row["created_at"])
        completed_at = _as_optional_datetime(row["completed_at"])
        if created_at is not None:
            key = created_at.date().isoformat()
            if key in buckets:
                buckets[key]["work_orders_created_count"] += 1
        if completed_at is not None:
            key = completed_at.date().isoformat()
            if key in buckets:
                buckets[key]["work_orders_completed_count"] += 1

    for row in escalation_rows:
        finished_at = _as_optional_datetime(row["finished_at"])
        if finished_at is None:
            continue
        key = finished_at.date().isoformat()
        if key not in buckets:
            continue

        detail = {}
        raw = str(row["detail_json"] or "{}")
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                detail = parsed
        except json.JSONDecodeError:
            detail = {}

        detail_site = detail.get("site")
        if site is not None and detail_site not in {site, None}:
            continue
        escalated_count = int(detail.get("escalated_count", 0) or 0)
        buckets[key]["work_orders_escalated_count"] += max(0, escalated_count)

    points = [
        DashboardTrendPoint(
            date=date_key,
            inspections_count=data["inspections_count"],
            work_orders_created_count=data["work_orders_created_count"],
            work_orders_completed_count=data["work_orders_completed_count"],
            work_orders_escalated_count=data["work_orders_escalated_count"],
        )
        for date_key, data in buckets.items()
    ]
    return DashboardTrendsRead(
        generated_at=now,
        site=site,
        window_days=days,
        points=points,
    )


def build_ops_handover_brief(
    *,
    site: str | None,
    window_hours: int,
    due_soon_hours: int,
    max_items: int,
    allowed_sites: list[str] | None = None,
) -> OpsHandoverBriefRead:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=window_hours)
    due_soon_cutoff = now + timedelta(hours=due_soon_hours)
    alert_window_start = now - timedelta(hours=24)

    if site is None and allowed_sites is not None and not allowed_sites:
        return OpsHandoverBriefRead(
            generated_at=now,
            site=site,
            window_hours=window_hours,
            due_soon_hours=due_soon_hours,
            open_work_orders=0,
            overdue_open_work_orders=0,
            due_soon_work_orders=0,
            escalated_open_work_orders=0,
            unassigned_high_priority_open_work_orders=0,
            new_work_orders_in_window=0,
            high_risk_inspections_in_window=0,
            failed_alert_deliveries_24h=0,
            top_work_orders=[],
            recent_high_risk_inspections=[],
            recommended_actions=["No accessible sites in current principal scope."],
        )

    open_work_orders_stmt = select(work_orders).where(work_orders.c.status.in_(["open", "acked"]))
    new_work_orders_stmt = (
        select(work_orders.c.id, work_orders.c.site)
        .where(work_orders.c.status.in_(["open", "acked"]))
        .where(work_orders.c.created_at >= window_start)
    )
    high_risk_inspections_stmt = (
        select(inspections)
        .where(inspections.c.inspected_at >= window_start)
        .where(inspections.c.risk_level.in_(["warning", "danger"]))
    )
    alert_deliveries_stmt = (
        select(alert_deliveries.c.status, alert_deliveries.c.payload_json)
        .where(alert_deliveries.c.last_attempt_at >= alert_window_start)
        .where(alert_deliveries.c.status.in_(["failed", "warning"]))
    )

    if site is not None:
        open_work_orders_stmt = open_work_orders_stmt.where(work_orders.c.site == site)
        new_work_orders_stmt = new_work_orders_stmt.where(work_orders.c.site == site)
        high_risk_inspections_stmt = high_risk_inspections_stmt.where(inspections.c.site == site)
    elif allowed_sites is not None:
        open_work_orders_stmt = open_work_orders_stmt.where(work_orders.c.site.in_(allowed_sites))
        new_work_orders_stmt = new_work_orders_stmt.where(work_orders.c.site.in_(allowed_sites))
        high_risk_inspections_stmt = high_risk_inspections_stmt.where(inspections.c.site.in_(allowed_sites))

    with get_conn() as conn:
        open_work_order_rows = conn.execute(open_work_orders_stmt).mappings().all()
        new_work_order_rows = conn.execute(new_work_orders_stmt).all()
        high_risk_inspection_rows = conn.execute(high_risk_inspections_stmt).mappings().all()
        alert_delivery_rows = conn.execute(alert_deliveries_stmt).mappings().all()

    priority_weights = {"low": 1, "medium": 2, "high": 4, "critical": 6}
    top_work_orders: list[OpsHandoverWorkOrderRead] = []
    overdue_open_work_orders = 0
    due_soon_work_orders = 0
    escalated_open_work_orders = 0
    unassigned_high_priority_open_work_orders = 0

    for row in open_work_order_rows:
        due_at = _as_optional_datetime(row["due_at"])
        created_at = _as_optional_datetime(row["created_at"]) or now
        priority = str(row["priority"] or "medium")
        is_escalated = bool(row["is_escalated"])
        is_overdue = due_at is not None and due_at < now
        is_due_soon = due_at is not None and now <= due_at <= due_soon_cutoff
        is_unassigned_high_priority = priority in {"high", "critical"} and not row["assignee"]

        if is_overdue:
            overdue_open_work_orders += 1
        if is_due_soon:
            due_soon_work_orders += 1
        if is_escalated:
            escalated_open_work_orders += 1
        if is_unassigned_high_priority:
            unassigned_high_priority_open_work_orders += 1

        urgency_score = priority_weights.get(priority, 2)
        reasons: list[str] = [f"{priority} priority"]
        if is_overdue:
            urgency_score += 6
            reasons.append("overdue")
        elif is_due_soon:
            urgency_score += 3
            reasons.append("due soon")
        if is_escalated:
            urgency_score += 4
            reasons.append("escalated")
        if is_unassigned_high_priority:
            urgency_score += 2
            reasons.append("unassigned high priority")

        age_hours = (now - created_at).total_seconds() / 3600
        if age_hours >= 72:
            urgency_score += 2
            reasons.append("open >72h")
        elif age_hours >= 24:
            urgency_score += 1
            reasons.append("open >24h")

        due_in_minutes = None
        if due_at is not None:
            due_in_minutes = int((due_at - now).total_seconds() // 60)

        top_work_orders.append(
            OpsHandoverWorkOrderRead(
                id=int(row["id"]),
                site=str(row["site"]),
                location=str(row["location"]),
                title=str(row["title"]),
                priority=priority,  # type: ignore[arg-type]
                status=str(row["status"]),  # type: ignore[arg-type]
                assignee=row["assignee"],
                due_at=due_at,
                created_at=created_at,
                is_escalated=is_escalated,
                is_overdue=is_overdue,
                due_in_minutes=due_in_minutes,
                urgency_score=urgency_score,
                reasons=reasons,
            )
        )

    far_future = now + timedelta(days=36500)
    top_work_orders.sort(
        key=lambda item: (
            -item.urgency_score,
            item.due_at or far_future,
            item.created_at,
            item.id,
        )
    )
    top_work_orders = top_work_orders[:max_items]

    risk_weights = {"danger": 2, "warning": 1}
    recent_high_risk_inspections: list[OpsHandoverInspectionRead] = []
    for row in high_risk_inspection_rows:
        risk_flags = [flag for flag in str(row["risk_flags"] or "").split(",") if flag]
        recent_high_risk_inspections.append(
            OpsHandoverInspectionRead(
                id=int(row["id"]),
                site=str(row["site"]),
                location=str(row["location"]),
                inspector=str(row["inspector"]),
                risk_level=str(row["risk_level"] or "warning"),
                inspected_at=_as_datetime(row["inspected_at"]),
                risk_flags=risk_flags,
            )
        )
    recent_high_risk_inspections.sort(
        key=lambda item: (
            risk_weights.get(item.risk_level, 0),
            item.inspected_at,
            item.id,
        ),
        reverse=True,
    )
    high_risk_inspections_in_window = len(recent_high_risk_inspections)
    recent_high_risk_inspections = recent_high_risk_inspections[:max_items]

    failed_alert_deliveries_24h = 0
    for row in alert_delivery_rows:
        payload_raw = str(row["payload_json"] or "{}")
        payload: dict[str, Any] = {}
        try:
            parsed_payload = json.loads(payload_raw)
            if isinstance(parsed_payload, dict):
                payload = parsed_payload
        except json.JSONDecodeError:
            payload = {}

        payload_site = _normalize_site_name(str(payload.get("site"))) if payload.get("site") is not None else None
        if site is not None:
            if payload_site != site:
                continue
        elif allowed_sites is not None and payload_site not in allowed_sites:
            continue
        failed_alert_deliveries_24h += 1

    recommended_actions: list[str] = []
    if overdue_open_work_orders > 0:
        recommended_actions.append(f"Resolve or reassign {overdue_open_work_orders} overdue open work orders.")
    if unassigned_high_priority_open_work_orders > 0:
        recommended_actions.append(
            f"Assign owners for {unassigned_high_priority_open_work_orders} unassigned high/critical work orders."
        )
    if high_risk_inspections_in_window > 0:
        recommended_actions.append(
            f"Review {high_risk_inspections_in_window} warning/danger inspections from last {window_hours} hours."
        )
    if due_soon_work_orders > 0:
        recommended_actions.append(f"Preempt {due_soon_work_orders} work orders due within next {due_soon_hours} hours.")
    if failed_alert_deliveries_24h > 0:
        recommended_actions.append(
            f"Investigate {failed_alert_deliveries_24h} failed/warning alert deliveries from last 24 hours."
        )
    if not recommended_actions:
        recommended_actions.append("No urgent blockers detected for this handover window.")

    return OpsHandoverBriefRead(
        generated_at=now,
        site=site,
        window_hours=window_hours,
        due_soon_hours=due_soon_hours,
        open_work_orders=len(open_work_order_rows),
        overdue_open_work_orders=overdue_open_work_orders,
        due_soon_work_orders=due_soon_work_orders,
        escalated_open_work_orders=escalated_open_work_orders,
        unassigned_high_priority_open_work_orders=unassigned_high_priority_open_work_orders,
        new_work_orders_in_window=len(new_work_order_rows),
        high_risk_inspections_in_window=high_risk_inspections_in_window,
        failed_alert_deliveries_24h=failed_alert_deliveries_24h,
        top_work_orders=top_work_orders,
        recent_high_risk_inspections=recent_high_risk_inspections,
        recommended_actions=recommended_actions[:5],
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


def _build_handover_brief_csv(report: OpsHandoverBriefRead) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["section", "key", "value"])
    writer.writerow(["meta", "site", report.site or "ALL"])
    writer.writerow(["meta", "generated_at", report.generated_at.isoformat()])
    writer.writerow(["meta", "window_hours", report.window_hours])
    writer.writerow(["meta", "due_soon_hours", report.due_soon_hours])

    writer.writerow(["summary", "open_work_orders", report.open_work_orders])
    writer.writerow(["summary", "overdue_open_work_orders", report.overdue_open_work_orders])
    writer.writerow(["summary", "due_soon_work_orders", report.due_soon_work_orders])
    writer.writerow(["summary", "escalated_open_work_orders", report.escalated_open_work_orders])
    writer.writerow(
        [
            "summary",
            "unassigned_high_priority_open_work_orders",
            report.unassigned_high_priority_open_work_orders,
        ]
    )
    writer.writerow(["summary", "new_work_orders_in_window", report.new_work_orders_in_window])
    writer.writerow(["summary", "high_risk_inspections_in_window", report.high_risk_inspections_in_window])
    writer.writerow(["summary", "failed_alert_deliveries_24h", report.failed_alert_deliveries_24h])

    writer.writerow([])
    writer.writerow(
        [
            "top_work_orders",
            "id",
            "site",
            "location",
            "title",
            "priority",
            "status",
            "assignee",
            "due_at",
            "due_in_minutes",
            "is_overdue",
            "is_escalated",
            "urgency_score",
            "reasons",
        ]
    )
    for item in report.top_work_orders:
        writer.writerow(
            [
                "top_work_orders",
                item.id,
                item.site,
                item.location,
                item.title,
                item.priority,
                item.status,
                item.assignee or "",
                item.due_at.isoformat() if item.due_at is not None else "",
                item.due_in_minutes if item.due_in_minutes is not None else "",
                item.is_overdue,
                item.is_escalated,
                item.urgency_score,
                ", ".join(item.reasons),
            ]
        )

    writer.writerow([])
    writer.writerow(
        [
            "recent_high_risk_inspections",
            "id",
            "site",
            "location",
            "inspector",
            "risk_level",
            "inspected_at",
            "risk_flags",
        ]
    )
    for item in report.recent_high_risk_inspections:
        writer.writerow(
            [
                "recent_high_risk_inspections",
                item.id,
                item.site,
                item.location,
                item.inspector,
                item.risk_level,
                item.inspected_at.isoformat(),
                ", ".join(item.risk_flags),
            ]
        )

    writer.writerow([])
    writer.writerow(["recommended_actions", "index", "action"])
    for idx, action in enumerate(report.recommended_actions, start=1):
        writer.writerow(["recommended_actions", idx, action])

    return out.getvalue()


def _build_handover_brief_pdf(report: OpsHandoverBriefRead) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise HTTPException(status_code=500, detail="PDF generator dependency not installed") from exc

    lines = [
        "Ops Handover Brief",
        "",
        f"Site: {report.site or 'ALL'}",
        f"Generated At: {report.generated_at.isoformat()}",
        f"Window Hours: {report.window_hours}",
        f"Due Soon Hours: {report.due_soon_hours}",
        "",
        "[Summary]",
        f"Open Work Orders: {report.open_work_orders}",
        f"Overdue Open Work Orders: {report.overdue_open_work_orders}",
        f"Due Soon Work Orders: {report.due_soon_work_orders}",
        f"Escalated Open Work Orders: {report.escalated_open_work_orders}",
        f"Unassigned High Priority Open Work Orders: {report.unassigned_high_priority_open_work_orders}",
        f"New Work Orders In Window: {report.new_work_orders_in_window}",
        f"High Risk Inspections In Window: {report.high_risk_inspections_in_window}",
        f"Failed Alert Deliveries 24h: {report.failed_alert_deliveries_24h}",
        "",
        "[Top Work Orders]",
    ]
    for item in report.top_work_orders:
        due_text = item.due_at.isoformat() if item.due_at is not None else "-"
        lines.append(
            f"#{item.id} {item.priority}/{item.status} score={item.urgency_score} site={item.site} due={due_text}"
        )
        lines.append(f"  {item.title[:120]}")

    lines.append("")
    lines.append("[Recent High Risk Inspections]")
    for item in report.recent_high_risk_inspections:
        lines.append(f"#{item.id} {item.risk_level} site={item.site} inspected_at={item.inspected_at.isoformat()}")
        if item.risk_flags:
            lines.append(f"  flags={', '.join(item.risk_flags)[:140]}")

    lines.append("")
    lines.append("[Recommended Actions]")
    for idx, action in enumerate(report.recommended_actions, start=1):
        lines.append(f"{idx}. {action}")

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
        "work_order_events_api": "/api/work-orders/{id}/events",
        "escalation_api": "/api/work-orders/escalations/run",
        "monthly_report_api": "/api/reports/monthly",
        "monthly_report_csv_api": "/api/reports/monthly/csv",
        "monthly_report_pdf_api": "/api/reports/monthly/pdf",
        "auth_me_api": "/api/auth/me",
        "admin_tokens_api": "/api/admin/tokens",
        "admin_audit_api": "/api/admin/audit-logs",
        "job_runs_api": "/api/ops/job-runs",
        "dashboard_summary_api": "/api/ops/dashboard/summary",
        "dashboard_trends_api": "/api/ops/dashboard/trends",
        "handover_brief_api": "/api/ops/handover/brief",
        "handover_brief_csv_api": "/api/ops/handover/brief/csv",
        "handover_brief_pdf_api": "/api/ops/handover/brief/pdf",
        "alert_deliveries_api": "/api/ops/alerts/deliveries",
        "alert_retry_api": "/api/ops/alerts/retries/run",
        "sla_simulator_api": "/api/ops/sla/simulate",
        "sla_policy_api": "/api/admin/policies/sla",
        "sla_policy_proposals_api": "/api/admin/policies/sla/proposals",
        "sla_policy_revisions_api": "/api/admin/policies/sla/revisions",
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
        site_scope=list(_principal_site_scope(principal)),
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
    site_scope_text = _site_scope_list_to_text(payload.site_scope)
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
                site_scope=site_scope_text,
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
        detail={
            "username": model.username,
            "role": model.role,
            "site_scope": model.site_scope,
            "is_active": model.is_active,
        },
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
    token_scope_text: str | None = None
    effective_scope: list[str] = [SITE_SCOPE_ALL]

    with get_conn() as conn:
        user_row = conn.execute(select(admin_users).where(admin_users.c.id == user_id)).mappings().first()
        if user_row is None:
            raise HTTPException(status_code=404, detail="Admin user not found")
        if not user_row["is_active"]:
            raise HTTPException(status_code=409, detail="Inactive user cannot receive token")

        user_scope = _site_scope_text_to_list(user_row.get("site_scope"), default_all=True)
        token_scope = None
        if payload.site_scope is not None:
            token_scope = _site_scope_text_to_list(payload.site_scope, default_all=True)
            token_scope_text = _site_scope_list_to_text(token_scope)
        effective_scope = _resolve_effective_site_scope(user_scope=user_scope, token_scope=token_scope)
        if not effective_scope:
            raise HTTPException(status_code=409, detail="Token site scope does not overlap user site scope")

        result = conn.execute(
            insert(admin_tokens).values(
                user_id=user_id,
                label=payload.label,
                token_hash=token_hash,
                is_active=True,
                site_scope=token_scope_text,
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
        site_scope=effective_scope,
        expires_at=expires_at,
        created_at=now,
    )
    _write_audit_log(
        principal=principal,
        action="admin_token_issue",
        resource_type="admin_token",
        resource_id=str(token_id),
        detail={
            "user_id": user_id,
            "label": payload.label,
            "site_scope": effective_scope,
            "expires_at": expires_at,
        },
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
            admin_tokens.c.site_scope.label("token_site_scope"),
            admin_users.c.site_scope.label("user_site_scope"),
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
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> DashboardSummaryRead:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    return build_dashboard_summary(
        site=site,
        days=days,
        recent_job_limit=recent_job_limit,
        allowed_sites=allowed_sites,
    )


@app.get("/api/ops/dashboard/trends", response_model=DashboardTrendsRead)
def get_dashboard_trends(
    site: Annotated[str | None, Query()] = None,
    days: Annotated[int, Query(ge=1, le=90)] = 30,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> DashboardTrendsRead:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    return build_dashboard_trends(site=site, days=days, allowed_sites=allowed_sites)


@app.get("/api/ops/handover/brief", response_model=OpsHandoverBriefRead)
def get_ops_handover_brief(
    site: Annotated[str | None, Query()] = None,
    window_hours: Annotated[int, Query(ge=1, le=168)] = 12,
    due_soon_hours: Annotated[int, Query(ge=1, le=72)] = 6,
    max_items: Annotated[int, Query(ge=1, le=50)] = 10,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> OpsHandoverBriefRead:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = build_ops_handover_brief(
        site=site,
        window_hours=window_hours,
        due_soon_hours=due_soon_hours,
        max_items=max_items,
        allowed_sites=allowed_sites,
    )
    _write_audit_log(
        principal=principal,
        action="ops_handover_brief_view",
        resource_type="report",
        resource_id=site or "all",
        detail={
            "site": site,
            "window_hours": window_hours,
            "due_soon_hours": due_soon_hours,
            "max_items": max_items,
            "open_work_orders": report.open_work_orders,
            "overdue_open_work_orders": report.overdue_open_work_orders,
            "due_soon_work_orders": report.due_soon_work_orders,
        },
    )
    return report


@app.get("/api/ops/handover/brief/csv")
def get_ops_handover_brief_csv(
    site: Annotated[str | None, Query()] = None,
    window_hours: Annotated[int, Query(ge=1, le=168)] = 12,
    due_soon_hours: Annotated[int, Query(ge=1, le=72)] = 6,
    max_items: Annotated[int, Query(ge=1, le=50)] = 10,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> Response:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = build_ops_handover_brief(
        site=site,
        window_hours=window_hours,
        due_soon_hours=due_soon_hours,
        max_items=max_items,
        allowed_sites=allowed_sites,
    )
    csv_text = _build_handover_brief_csv(report)
    site_label = (report.site or "all").replace(" ", "_")
    ts = report.generated_at.strftime("%Y%m%dT%H%M%SZ")
    file_name = f"handover-brief-{site_label}-{ts}.csv"
    response = Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )
    _write_audit_log(
        principal=principal,
        action="report_handover_export_csv",
        resource_type="report",
        resource_id=f"{report.site or 'ALL'}:{ts}",
        detail={
            "site": site,
            "window_hours": window_hours,
            "due_soon_hours": due_soon_hours,
            "max_items": max_items,
        },
    )
    return response


@app.get("/api/ops/handover/brief/pdf")
def get_ops_handover_brief_pdf(
    site: Annotated[str | None, Query()] = None,
    window_hours: Annotated[int, Query(ge=1, le=168)] = 12,
    due_soon_hours: Annotated[int, Query(ge=1, le=72)] = 6,
    max_items: Annotated[int, Query(ge=1, le=50)] = 10,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> Response:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    report = build_ops_handover_brief(
        site=site,
        window_hours=window_hours,
        due_soon_hours=due_soon_hours,
        max_items=max_items,
        allowed_sites=allowed_sites,
    )
    pdf_bytes = _build_handover_brief_pdf(report)
    site_label = (report.site or "all").replace(" ", "_")
    ts = report.generated_at.strftime("%Y%m%dT%H%M%SZ")
    file_name = f"handover-brief-{site_label}-{ts}.pdf"
    response = Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )
    _write_audit_log(
        principal=principal,
        action="report_handover_export_pdf",
        resource_type="report",
        resource_id=f"{report.site or 'ALL'}:{ts}",
        detail={
            "site": site,
            "window_hours": window_hours,
            "due_soon_hours": due_soon_hours,
            "max_items": max_items,
        },
    )
    return response


@app.get("/api/ops/alerts/deliveries", response_model=list[AlertDeliveryRead])
def list_alert_deliveries(
    event_type: Annotated[str | None, Query()] = None,
    status: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=300)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    _: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> list[AlertDeliveryRead]:
    stmt = select(alert_deliveries).order_by(
        alert_deliveries.c.last_attempt_at.desc(),
        alert_deliveries.c.id.desc(),
    )
    if event_type is not None:
        stmt = stmt.where(alert_deliveries.c.event_type == event_type)
    if status is not None:
        stmt = stmt.where(alert_deliveries.c.status == status)
    stmt = stmt.limit(limit).offset(offset)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_alert_delivery_model(row) for row in rows]


@app.post("/api/ops/sla/simulate", response_model=SlaWhatIfResponse)
def simulate_sla(
    payload: SlaWhatIfRequest,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaWhatIfResponse:
    _require_site_access(principal, payload.site)
    allowed_sites = _allowed_sites_for_principal(principal) if payload.site is None else None
    result = simulate_sla_policy_change(
        policy=payload.policy,
        site=payload.site,
        limit=payload.limit,
        include_work_order_ids=payload.include_work_order_ids,
        sample_size=payload.sample_size,
        recompute_due_from_policy=payload.recompute_due_from_policy,
        allowed_sites=allowed_sites,
    )
    _write_audit_log(
        principal=principal,
        action="sla_policy_simulation_run",
        resource_type="sla_policy",
        resource_id=payload.site or "global",
        detail={
            "site": payload.site,
            "limit": payload.limit,
            "baseline_escalate_count": result.baseline_escalate_count,
            "simulated_escalate_count": result.simulated_escalate_count,
            "delta_escalate_count": result.delta_escalate_count,
        },
    )
    return result


@app.post("/api/ops/alerts/retries/run", response_model=AlertRetryRunResponse)
def run_alert_retries(
    payload: AlertRetryRunRequest,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> AlertRetryRunResponse:
    result = run_alert_retry_job(
        event_type=payload.event_type,
        only_status=payload.only_status,
        limit=payload.limit,
        max_attempt_count=payload.max_attempt_count,
        min_last_attempt_age_sec=payload.min_last_attempt_age_sec,
        trigger="api",
    )
    _write_audit_log(
        principal=principal,
        action="alert_retry_batch_run",
        resource_type="alert_delivery",
        resource_id="batch",
        detail={
            "event_type": payload.event_type,
            "statuses": payload.only_status,
            "limit": payload.limit,
            "processed_count": result.processed_count,
            "failed_count": result.failed_count,
        },
    )
    return result


@app.post("/api/admin/policies/sla/proposals", response_model=SlaPolicyProposalRead, status_code=201)
def create_sla_policy_proposal(
    payload: SlaPolicyProposalCreate,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaPolicyProposalRead:
    now = datetime.now(timezone.utc)
    normalized_site = _normalize_site_name(payload.site)
    if normalized_site is None:
        _require_global_site_scope(principal)
    else:
        _require_site_access(principal, normalized_site)

    allowed_sites = _allowed_sites_for_principal(principal) if normalized_site is None else None
    simulation = simulate_sla_policy_change(
        policy=payload.policy,
        site=normalized_site,
        limit=payload.simulation_limit,
        include_work_order_ids=payload.include_work_order_ids,
        sample_size=payload.sample_size,
        recompute_due_from_policy=payload.recompute_due_from_policy,
        allowed_sites=allowed_sites,
    )
    requested_by = str(principal.get("username") or "unknown")

    with get_conn() as conn:
        result = conn.execute(
            insert(sla_policy_proposals).values(
                site=normalized_site,
                policy_json=_to_json_text(_normalize_sla_policy(payload.policy.model_dump())),
                simulation_json=_to_json_text(simulation.model_dump()),
                note=payload.note or "",
                status=SLA_PROPOSAL_STATUS_PENDING,
                requested_by=requested_by,
                decided_by=None,
                decision_note=None,
                created_at=now,
                decided_at=None,
                applied_at=None,
            )
        )
        proposal_id = int(result.inserted_primary_key[0])
        row = conn.execute(
            select(sla_policy_proposals).where(sla_policy_proposals.c.id == proposal_id)
        ).mappings().first()

    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create SLA policy proposal")
    model = _row_to_sla_policy_proposal_model(row)
    _write_audit_log(
        principal=principal,
        action="sla_policy_proposal_create",
        resource_type="sla_policy_proposal",
        resource_id=str(model.id),
        detail={
            "site": model.site,
            "status": model.status,
            "baseline_escalate_count": simulation.baseline_escalate_count,
            "simulated_escalate_count": simulation.simulated_escalate_count,
            "delta_escalate_count": simulation.delta_escalate_count,
        },
    )
    return model


@app.get("/api/admin/policies/sla/proposals", response_model=list[SlaPolicyProposalRead])
def list_sla_policy_proposals(
    site: Annotated[str | None, Query()] = None,
    status: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=300)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> list[SlaPolicyProposalRead]:
    normalized_site = _normalize_site_name(site)
    if normalized_site is not None:
        _require_site_access(principal, normalized_site)

    stmt = select(sla_policy_proposals).order_by(
        sla_policy_proposals.c.created_at.desc(),
        sla_policy_proposals.c.id.desc(),
    )
    if normalized_site is not None:
        stmt = stmt.where(sla_policy_proposals.c.site == normalized_site)
    else:
        allowed_sites = _allowed_sites_for_principal(principal)
        if allowed_sites is not None:
            if not allowed_sites:
                return []
            stmt = stmt.where(sla_policy_proposals.c.site.in_(allowed_sites))
    if status is not None:
        stmt = stmt.where(sla_policy_proposals.c.status == status)
    stmt = stmt.limit(limit).offset(offset)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_sla_policy_proposal_model(row) for row in rows]


@app.get("/api/admin/policies/sla/proposals/{proposal_id}", response_model=SlaPolicyProposalRead)
def get_sla_policy_proposal(
    proposal_id: int,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaPolicyProposalRead:
    with get_conn() as conn:
        row = conn.execute(
            select(sla_policy_proposals).where(sla_policy_proposals.c.id == proposal_id)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="SLA policy proposal not found")

    proposal_site = row["site"]
    if proposal_site is None:
        _require_global_site_scope(principal)
    else:
        _require_site_access(principal, str(proposal_site))
    return _row_to_sla_policy_proposal_model(row)


@app.post("/api/admin/policies/sla/proposals/{proposal_id}/approve", response_model=SlaPolicyProposalRead)
def approve_sla_policy_proposal(
    proposal_id: int,
    payload: SlaPolicyProposalDecision,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaPolicyProposalRead:
    now = datetime.now(timezone.utc)
    decided_by = str(principal.get("username") or "unknown")

    with get_conn() as conn:
        row = conn.execute(
            select(sla_policy_proposals).where(sla_policy_proposals.c.id == proposal_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="SLA policy proposal not found")

        proposal_site = row["site"]
        if proposal_site is None:
            _require_global_site_scope(principal)
        else:
            _require_site_access(principal, str(proposal_site))

        if str(row["status"]) != SLA_PROPOSAL_STATUS_PENDING:
            raise HTTPException(status_code=409, detail="Only pending proposal can be approved")
        if str(row["requested_by"]) == decided_by:
            raise HTTPException(status_code=409, detail="Proposal cannot be self-approved")

    policy_raw = str(row["policy_json"] or "{}")
    try:
        policy_dict = json.loads(policy_raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="Invalid proposal policy payload") from exc
    if not isinstance(policy_dict, dict):
        raise HTTPException(status_code=500, detail="Invalid proposal policy payload")

    policy_model = SlaPolicyUpdate(**policy_dict)
    applied_policy = _upsert_sla_policy(
        policy_model,
        site=row["site"],
        source_action="proposal_approval",
        actor_username=decided_by,
        note=f"proposal_id={proposal_id}; {payload.note or ''}".strip(),
    )

    with get_conn() as conn:
        conn.execute(
            update(sla_policy_proposals)
            .where(sla_policy_proposals.c.id == proposal_id)
            .values(
                status=SLA_PROPOSAL_STATUS_APPROVED,
                decided_by=decided_by,
                decision_note=payload.note or "",
                decided_at=now,
                applied_at=now,
            )
        )
        updated_row = conn.execute(
            select(sla_policy_proposals).where(sla_policy_proposals.c.id == proposal_id)
        ).mappings().first()

    if updated_row is None:
        raise HTTPException(status_code=500, detail="Failed to approve SLA policy proposal")
    model = _row_to_sla_policy_proposal_model(updated_row)
    _write_audit_log(
        principal=principal,
        action="sla_policy_proposal_approve",
        resource_type="sla_policy_proposal",
        resource_id=str(model.id),
        detail={
            "site": model.site,
            "status": model.status,
            "applied_policy_key": applied_policy.policy_key,
            "decision_note": payload.note,
        },
    )
    return model


@app.post("/api/admin/policies/sla/proposals/{proposal_id}/reject", response_model=SlaPolicyProposalRead)
def reject_sla_policy_proposal(
    proposal_id: int,
    payload: SlaPolicyProposalDecision,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaPolicyProposalRead:
    now = datetime.now(timezone.utc)
    decided_by = str(principal.get("username") or "unknown")

    with get_conn() as conn:
        row = conn.execute(
            select(sla_policy_proposals).where(sla_policy_proposals.c.id == proposal_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="SLA policy proposal not found")

        proposal_site = row["site"]
        if proposal_site is None:
            _require_global_site_scope(principal)
        else:
            _require_site_access(principal, str(proposal_site))

        if str(row["status"]) != SLA_PROPOSAL_STATUS_PENDING:
            raise HTTPException(status_code=409, detail="Only pending proposal can be rejected")

        conn.execute(
            update(sla_policy_proposals)
            .where(sla_policy_proposals.c.id == proposal_id)
            .values(
                status=SLA_PROPOSAL_STATUS_REJECTED,
                decided_by=decided_by,
                decision_note=payload.note or "",
                decided_at=now,
                applied_at=None,
            )
        )
        updated_row = conn.execute(
            select(sla_policy_proposals).where(sla_policy_proposals.c.id == proposal_id)
        ).mappings().first()

    if updated_row is None:
        raise HTTPException(status_code=500, detail="Failed to reject SLA policy proposal")
    model = _row_to_sla_policy_proposal_model(updated_row)
    _write_audit_log(
        principal=principal,
        action="sla_policy_proposal_reject",
        resource_type="sla_policy_proposal",
        resource_id=str(model.id),
        detail={"site": model.site, "status": model.status, "decision_note": payload.note},
    )
    return model


@app.post("/api/ops/alerts/deliveries/{delivery_id}/retry", response_model=AlertDeliveryRead)
def retry_alert_delivery(
    delivery_id: int,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> AlertDeliveryRead:
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(alert_deliveries).where(alert_deliveries.c.id == delivery_id).limit(1)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Alert delivery not found")

        payload_raw = str(row["payload_json"] or "{}")
        try:
            payload = json.loads(payload_raw)
        except json.JSONDecodeError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}

        ok, err = _post_json_with_retries(
            url=str(row["target"]),
            payload=payload,
            retries=ALERT_WEBHOOK_RETRIES,
            timeout_sec=ALERT_WEBHOOK_TIMEOUT_SEC,
        )
        next_status = "success" if ok and err is None else ("warning" if ok else "failed")
        next_attempt_count = int(row["attempt_count"]) + 1
        conn.execute(
            update(alert_deliveries)
            .where(alert_deliveries.c.id == delivery_id)
            .values(
                status=next_status,
                error=err,
                attempt_count=next_attempt_count,
                last_attempt_at=now,
                updated_at=now,
            )
        )
        updated_row = conn.execute(
            select(alert_deliveries).where(alert_deliveries.c.id == delivery_id).limit(1)
        ).mappings().first()

    if updated_row is None:
        raise HTTPException(status_code=500, detail="Failed to retry alert delivery")
    model = _row_to_alert_delivery_model(updated_row)
    _write_audit_log(
        principal=principal,
        action="alert_delivery_retry",
        resource_type="alert_delivery",
        resource_id=str(model.id),
        status=model.status,
        detail={"target": model.target, "status": model.status, "attempt_count": model.attempt_count},
    )
    return model


@app.get("/api/admin/policies/sla", response_model=SlaPolicyRead)
def get_sla_policy(
    site: Annotated[str | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaPolicyRead:
    _require_site_access(principal, site)
    policy, updated_at, source, resolved_site, policy_key = _load_sla_policy(site=site)
    return _sla_policy_to_model(
        policy_key=policy_key,
        site=resolved_site,
        source=source,
        updated_at=updated_at,
        policy=policy,
    )


@app.put("/api/admin/policies/sla", response_model=SlaPolicyRead)
def set_sla_policy(
    payload: SlaPolicyUpdate,
    site: Annotated[str | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaPolicyRead:
    if site is None:
        _require_global_site_scope(principal)
    else:
        _require_site_access(principal, site)
    actor_username = str(principal.get("username") or "unknown")
    model = _upsert_sla_policy(
        payload,
        site=site,
        source_action="manual_update",
        actor_username=actor_username,
        note="direct policy update",
    )
    _write_audit_log(
        principal=principal,
        action="sla_policy_update",
        resource_type="sla_policy",
        resource_id=model.policy_key,
        detail={
            "site": model.site,
            "source": model.source,
            "default_due_hours": model.default_due_hours,
            "escalation_grace_minutes": model.escalation_grace_minutes,
        },
    )
    return model


@app.get("/api/admin/policies/sla/revisions", response_model=list[SlaPolicyRevisionRead])
def list_sla_policy_revisions(
    site: Annotated[str | None, Query()] = None,
    source_action: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> list[SlaPolicyRevisionRead]:
    normalized_site = _normalize_site_name(site)
    if normalized_site is not None:
        _require_site_access(principal, normalized_site)

    stmt = select(sla_policy_revisions).order_by(
        sla_policy_revisions.c.created_at.desc(),
        sla_policy_revisions.c.id.desc(),
    )
    if normalized_site is not None:
        stmt = stmt.where(sla_policy_revisions.c.site == normalized_site)
    else:
        allowed_sites = _allowed_sites_for_principal(principal)
        if allowed_sites is not None:
            if not allowed_sites:
                return []
            stmt = stmt.where(sla_policy_revisions.c.site.in_(allowed_sites))
    if source_action is not None:
        stmt = stmt.where(sla_policy_revisions.c.source_action == source_action)
    stmt = stmt.limit(limit).offset(offset)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_sla_policy_revision_model(row) for row in rows]


@app.post("/api/admin/policies/sla/revisions/{revision_id}/restore", response_model=SlaPolicyRead)
def restore_sla_policy_revision(
    revision_id: int,
    payload: SlaPolicyRestoreRequest,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaPolicyRead:
    with get_conn() as conn:
        row = conn.execute(
            select(sla_policy_revisions).where(sla_policy_revisions.c.id == revision_id)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="SLA policy revision not found")

    revision_site = row["site"]
    if revision_site is None:
        _require_global_site_scope(principal)
    else:
        _require_site_access(principal, str(revision_site))

    raw_policy = str(row["policy_json"] or "{}")
    try:
        policy_dict = json.loads(raw_policy)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="Invalid revision policy payload") from exc
    if not isinstance(policy_dict, dict):
        raise HTTPException(status_code=500, detail="Invalid revision policy payload")

    policy_model = SlaPolicyUpdate(**policy_dict)
    actor_username = str(principal.get("username") or "unknown")
    model = _upsert_sla_policy(
        policy_model,
        site=revision_site,
        source_action="revision_restore",
        actor_username=actor_username,
        note=f"revision_id={revision_id}; {payload.note or ''}".strip(),
    )
    _write_audit_log(
        principal=principal,
        action="sla_policy_restore",
        resource_type="sla_policy_revision",
        resource_id=str(revision_id),
        detail={
            "site": revision_site,
            "policy_key": model.policy_key,
            "decision_note": payload.note,
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
                admin_tokens.c.site_scope.label("token_site_scope"),
                admin_users.c.site_scope.label("user_site_scope"),
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
                admin_tokens.c.site_scope.label("token_site_scope"),
                admin_users.c.site_scope.label("user_site_scope"),
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
    _require_site_access(principal, payload.site)
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
    if due_at is None:
        policy, _, source, _, _ = _load_sla_policy(site=payload.site)
        due_hours = int(policy["default_due_hours"].get(payload.priority, SLA_DEFAULT_DUE_HOURS["medium"]))
        due_at = now + timedelta(hours=due_hours)
        auto_due_applied = True
        policy_source = source

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
        _append_work_order_event(
            conn,
            work_order_id=int(work_order_id),
            event_type="created",
            actor_username=actor_username,
            from_status=None,
            to_status="open",
            note=payload.description or "",
            detail={"priority": payload.priority, "assignee": payload.assignee, "reporter": payload.reporter},
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
            "due_at": model.due_at,
            "auto_due_applied": auto_due_applied,
            "policy_source": policy_source,
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
