"""IAM constants and helper functions that do not depend on app.main."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from os import getenv
from typing import Any

from fastapi import HTTPException


def _env_bool(name: str, default: bool) -> bool:
    raw = getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, min_value: int) -> int:
    raw = getenv(name)
    if raw is None:
        return max(default, min_value)
    try:
        value = int(raw.strip())
    except ValueError:
        return max(default, min_value)
    return max(value, min_value)


SITE_SCOPE_ALL = "*"
ROLE_PERMISSION_MAP: dict[str, set[str]] = {
    "owner": {"*"},
    "manager": {
        "inspections:read",
        "inspections:write",
        "work_orders:read",
        "work_orders:write",
        "work_orders:escalate",
        "official_docs:read",
        "official_docs:write",
        "official_docs:close",
        "reports:read",
        "reports:export",
        "billing:read",
        "billing:write",
        "workflow_locks:read",
        "workflow_locks:review",
        "workflow_locks:approve",
        "complaints:*",
        "team_ops:read",
        "team_ops:write",
        "adoption_w02:read",
        "adoption_w02:write",
        "adoption_w03:read",
        "adoption_w03:write",
        "adoption_w04:read",
        "adoption_w04:write",
        "adoption_w05:read",
        "adoption_w05:write",
        "adoption_w06:read",
        "adoption_w06:write",
        "adoption_w07:read",
        "adoption_w07:write",
        "adoption_w08:read",
        "adoption_w08:write",
        "adoption_w09:read",
        "adoption_w09:write",
        "adoption_w10:read",
        "adoption_w10:write",
        "adoption_w11:read",
        "adoption_w11:write",
        "adoption_w12:read",
        "adoption_w12:write",
        "adoption_w13:read",
        "adoption_w13:write",
        "adoption_w14:read",
        "adoption_w14:write",
        "adoption_w15:read",
        "adoption_w15:write",
    },
    "operator": {
        "inspections:read",
        "inspections:write",
        "work_orders:read",
        "work_orders:write",
        "official_docs:read",
        "official_docs:write",
        "official_docs:close",
        "billing:read",
        "billing:write",
        "workflow_locks:read",
        "workflow_locks:write",
        "complaints:*",
        "team_ops:read",
        "team_ops:write",
        "adoption_w02:read",
        "adoption_w02:write",
        "adoption_w03:read",
        "adoption_w03:write",
        "adoption_w04:read",
        "adoption_w04:write",
        "adoption_w05:read",
        "adoption_w05:write",
        "adoption_w06:read",
        "adoption_w06:write",
        "adoption_w07:read",
        "adoption_w07:write",
        "adoption_w08:read",
        "adoption_w08:write",
        "adoption_w09:read",
        "adoption_w09:write",
        "adoption_w10:read",
        "adoption_w10:write",
        "adoption_w11:read",
        "adoption_w11:write",
        "adoption_w12:read",
        "adoption_w12:write",
        "adoption_w13:read",
        "adoption_w13:write",
        "adoption_w14:read",
        "adoption_w14:write",
        "adoption_w15:read",
        "adoption_w15:write",
    },
    "auditor": {
        "inspections:read",
        "work_orders:read",
        "official_docs:read",
        "reports:read",
        "reports:export",
        "billing:read",
        "workflow_locks:read",
        "complaints:read",
        "team_ops:read",
        "adoption_w02:read",
        "adoption_w03:read",
        "adoption_w04:read",
        "adoption_w05:read",
        "adoption_w06:read",
        "adoption_w07:read",
        "adoption_w08:read",
        "adoption_w09:read",
        "adoption_w10:read",
        "adoption_w11:read",
        "adoption_w12:read",
        "adoption_w13:read",
        "adoption_w14:read",
        "adoption_w15:read",
    },
}
ADMIN_TOKEN = getenv("ADMIN_TOKEN", "").strip()
ENV_NAME = getenv("ENV", "local").lower()
ALLOW_INSECURE_LOCAL_AUTH = _env_bool("ALLOW_INSECURE_LOCAL_AUTH", True)
ADMIN_PASSWORD_MIN_LENGTH = _env_int("ADMIN_PASSWORD_MIN_LENGTH", 8, min_value=8)
ADMIN_PASSWORD_MAX_LENGTH = _env_int(
    "ADMIN_PASSWORD_MAX_LENGTH",
    128,
    min_value=ADMIN_PASSWORD_MIN_LENGTH,
)
ADMIN_PASSWORD_PBKDF2_ITERATIONS = _env_int(
    "ADMIN_PASSWORD_PBKDF2_ITERATIONS",
    210000,
    min_value=120000,
)
ADMIN_TOKEN_REQUIRE_EXPIRY = _env_bool("ADMIN_TOKEN_REQUIRE_EXPIRY", True)
ADMIN_TOKEN_MAX_TTL_DAYS = _env_int("ADMIN_TOKEN_MAX_TTL_DAYS", 30, min_value=1)
ADMIN_TOKEN_ROTATE_AFTER_DAYS = _env_int("ADMIN_TOKEN_ROTATE_AFTER_DAYS", 45, min_value=1)
ADMIN_TOKEN_ROTATE_WARNING_DAYS = _env_int("ADMIN_TOKEN_ROTATE_WARNING_DAYS", 7, min_value=0)
ADMIN_TOKEN_MAX_IDLE_DAYS = _env_int("ADMIN_TOKEN_MAX_IDLE_DAYS", 30, min_value=1)
ADMIN_TOKEN_MAX_ACTIVE_PER_USER = _env_int("ADMIN_TOKEN_MAX_ACTIVE_PER_USER", 5, min_value=1)
DR_REHEARSAL_ENABLED = _env_bool("DR_REHEARSAL_ENABLED", True)
DR_REHEARSAL_JOB_NAME = "dr_rehearsal"
AUDIT_ARCHIVE_SIGNING_KEY = getenv("AUDIT_ARCHIVE_SIGNING_KEY", "").strip()


def _permission_text_to_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [x.strip() for x in value.split(",") if x.strip()]
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return []


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


def _resolve_effective_site_scope(*, user_scope: list[str], token_scope: list[str] | None) -> list[str]:
    normalized_user_scope = _site_scope_text_to_list(user_scope, default_all=True)
    if token_scope is None:
        return normalized_user_scope

    normalized_token_scope = _site_scope_text_to_list(token_scope, default_all=True)
    if SITE_SCOPE_ALL in normalized_user_scope:
        return normalized_token_scope
    if SITE_SCOPE_ALL in normalized_token_scope:
        return normalized_user_scope

    return sorted(set(normalized_user_scope).intersection(normalized_token_scope))


def _principal_site_scope(principal: dict[str, Any]) -> list[str]:
    raw_scope = principal.get("site_scope", [SITE_SCOPE_ALL])
    return _site_scope_text_to_list(raw_scope, default_all=True)


def _has_site_access(principal: dict[str, Any], site: str | None) -> bool:
    if site is None:
        return True
    scope = _principal_site_scope(principal)
    if SITE_SCOPE_ALL in scope:
        return True
    return site in scope


def _effective_permissions(role: str, custom: list[str]) -> list[str]:
    perms = set(ROLE_PERMISSION_MAP.get(role, set()))
    perms.update(custom)
    if role == "owner":
        perms.add("*")
    return sorted(perms)


def _month_window(month: str | None) -> tuple[datetime, datetime, str]:
    if month is None:
        now = datetime.now(timezone.utc)
        normalized = f"{now.year:04d}-{now.month:02d}"
    else:
        normalized = month

    try:
        year_text, month_text = normalized.split("-")
        start = datetime(int(year_text), int(month_text), 1, tzinfo=timezone.utc)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="month must be YYYY-MM format") from exc

    if start.month == 12:
        end = datetime(start.year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(start.year, start.month + 1, 1, tzinfo=timezone.utc)
    return start, end, normalized


def _token_rotate_due_at(created_at: datetime) -> datetime | None:
    if ADMIN_TOKEN_ROTATE_AFTER_DAYS <= 0:
        return None
    return created_at + timedelta(days=ADMIN_TOKEN_ROTATE_AFTER_DAYS)


def _token_idle_due_at(*, created_at: datetime, last_used_at: datetime | None) -> datetime | None:
    if ADMIN_TOKEN_MAX_IDLE_DAYS <= 0:
        return None
    baseline = last_used_at or created_at
    return baseline + timedelta(days=ADMIN_TOKEN_MAX_IDLE_DAYS)
