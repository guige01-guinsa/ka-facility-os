"""IAM security and access helpers extracted from app.main."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Callable

from fastapi import Depends, Header, HTTPException
from sqlalchemy import func, insert, select, update
from sqlalchemy.exc import SQLAlchemyError

from app.database import admin_tokens, admin_users, get_conn
from app.domains.iam.core import (
    ADMIN_PASSWORD_MAX_LENGTH,
    ADMIN_PASSWORD_MIN_LENGTH,
    ADMIN_PASSWORD_PBKDF2_ITERATIONS,
    ADMIN_TOKEN,
    ADMIN_TOKEN_MAX_IDLE_DAYS,
    ADMIN_TOKEN_MAX_TTL_DAYS,
    ADMIN_TOKEN_REQUIRE_EXPIRY,
    ADMIN_TOKEN_ROTATE_AFTER_DAYS,
    ADMIN_TOKEN_ROTATE_WARNING_DAYS,
    ALLOW_INSECURE_LOCAL_AUTH,
    ENV_NAME,
    ROLE_PERMISSION_MAP,
    SITE_SCOPE_ALL,
    _has_site_access,
    _permission_text_to_list,
    _principal_site_scope,
    _resolve_effective_site_scope,
    _site_scope_text_to_list,
)
from app.domains.ops.inspection_service import _as_datetime, _as_optional_datetime


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

def _principal_role(principal: dict[str, Any]) -> str:
    return str(principal.get("role") or "").strip().lower()

def _require_user_management_access(principal: dict[str, Any]) -> None:
    role = _principal_role(principal)
    if role in {"owner", "manager"} or _has_permission(principal, "admins:manage"):
        return
    raise HTTPException(status_code=403, detail="User management requires owner or manager role")

def _contains_admin_control_permissions(permissions: list[str]) -> bool:
    for item in permissions:
        normalized = str(item or "").strip()
        if not normalized:
            continue
        if normalized == "*" or normalized.startswith("admins:"):
            return True
    return False

def _site_scope_is_subset(scope: list[str], allowed_scope: list[str]) -> bool:
    normalized_scope = _site_scope_text_to_list(scope, default_all=True)
    normalized_allowed = _site_scope_text_to_list(allowed_scope, default_all=True)
    if SITE_SCOPE_ALL in normalized_allowed:
        return True
    if SITE_SCOPE_ALL in normalized_scope:
        return False
    return set(normalized_scope).issubset(set(normalized_allowed))

def _enforce_manager_user_mutation_guardrails(
    principal: dict[str, Any],
    *,
    next_role: str,
    next_permissions: list[str],
    next_site_scope: list[str],
    target_role: str | None = None,
    target_site_scope: list[str] | None = None,
) -> None:
    if _principal_role(principal) != "manager":
        return

    actor_scope = _principal_site_scope(principal)
    if target_role == "owner":
        raise HTTPException(status_code=403, detail="Manager cannot manage owner accounts")
    if target_site_scope is not None and not _site_scope_is_subset(target_site_scope, actor_scope):
        raise HTTPException(status_code=403, detail="Manager cannot manage users outside their site scope")
    if str(next_role).strip().lower() == "owner":
        raise HTTPException(status_code=403, detail="Manager cannot assign owner role")
    if _contains_admin_control_permissions(next_permissions):
        raise HTTPException(status_code=403, detail="Manager cannot grant admin control permissions")
    if not _site_scope_is_subset(next_site_scope, actor_scope):
        raise HTTPException(status_code=403, detail="Manager cannot assign site scope outside their own scope")

def _count_active_owner_users(conn: Any, *, exclude_user_id: int | None = None) -> int:
    stmt = select(func.count()).select_from(admin_users).where(admin_users.c.role == "owner").where(admin_users.c.is_active.is_(True))
    if exclude_user_id is not None:
        stmt = stmt.where(admin_users.c.id != exclude_user_id)
    value = conn.execute(stmt).scalar_one()
    return int(value or 0)

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def _normalize_admin_username(value: str) -> str:
    return value.strip()

def _validate_admin_password_value(password: str) -> str:
    candidate = str(password or "")
    if len(candidate) < ADMIN_PASSWORD_MIN_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at least {ADMIN_PASSWORD_MIN_LENGTH} characters",
        )
    if len(candidate) > ADMIN_PASSWORD_MAX_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at most {ADMIN_PASSWORD_MAX_LENGTH} characters",
        )
    return candidate

def _b64_url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

def _b64_url_decode(value: str) -> bytes:
    text = str(value or "").strip()
    if not text:
        return b""
    padding = "=" * ((4 - (len(text) % 4)) % 4)
    return base64.urlsafe_b64decode((text + padding).encode("utf-8"))

def _hash_password(password: str) -> str:
    normalized = _validate_admin_password_value(password)
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        normalized.encode("utf-8"),
        salt,
        ADMIN_PASSWORD_PBKDF2_ITERATIONS,
    )
    return "pbkdf2_sha256${iterations}${salt}${digest}".format(
        iterations=ADMIN_PASSWORD_PBKDF2_ITERATIONS,
        salt=_b64_url_encode(salt),
        digest=_b64_url_encode(digest),
    )

def _verify_password(password: str, encoded_hash: str) -> bool:
    raw = str(encoded_hash or "").strip()
    if not raw:
        return False
    parts = raw.split("$")
    if len(parts) != 4:
        return False
    algorithm, iterations_text, salt_text, digest_text = parts
    if algorithm != "pbkdf2_sha256":
        return False
    try:
        iterations = int(iterations_text)
        if iterations <= 0:
            return False
        salt = _b64_url_decode(salt_text)
        expected_digest = _b64_url_decode(digest_text)
        if not salt or not expected_digest:
            return False
        computed_digest = hashlib.pbkdf2_hmac(
            "sha256",
            str(password or "").encode("utf-8"),
            salt,
            iterations,
        )
    except Exception:
        return False
    return hmac.compare_digest(computed_digest, expected_digest)

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

def _token_rotate_due_at(created_at: datetime) -> datetime | None:
    if ADMIN_TOKEN_ROTATE_AFTER_DAYS <= 0:
        return None
    return created_at + timedelta(days=ADMIN_TOKEN_ROTATE_AFTER_DAYS)

def _token_idle_due_at(*, created_at: datetime, last_used_at: datetime | None) -> datetime | None:
    baseline = last_used_at or created_at
    if ADMIN_TOKEN_MAX_IDLE_DAYS <= 0:
        return None
    return baseline + timedelta(days=ADMIN_TOKEN_MAX_IDLE_DAYS)

def _load_principal_by_token(token: str) -> dict[str, Any] | None:
    now = datetime.now(timezone.utc)
    token_hash = _hash_token(token)

    stmt = (
        select(
            admin_tokens.c.id.label("token_id"),
            admin_tokens.c.user_id.label("user_id"),
            admin_tokens.c.expires_at.label("expires_at"),
            admin_tokens.c.last_used_at.label("last_used_at"),
            admin_tokens.c.created_at.label("created_at"),
            admin_tokens.c.label.label("token_label"),
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

            token_id = int(row["token_id"])
            expires_at = _as_optional_datetime(row["expires_at"])
            created_at = _as_datetime(row["created_at"])
            last_used_at = _as_optional_datetime(row["last_used_at"])
            rotate_due_at = _token_rotate_due_at(created_at)
            idle_due_at = _token_idle_due_at(created_at=created_at, last_used_at=last_used_at)

            if ADMIN_TOKEN_ROTATE_AFTER_DAYS > 0:
                rotate_cutoff = now - timedelta(days=ADMIN_TOKEN_ROTATE_AFTER_DAYS)
                if created_at <= rotate_cutoff:
                    conn.execute(
                        update(admin_tokens)
                        .where(admin_tokens.c.id == token_id)
                        .values(is_active=False, last_used_at=now)
                    )
                    return None

            if idle_due_at is not None and idle_due_at <= now:
                conn.execute(
                    update(admin_tokens)
                    .where(admin_tokens.c.id == token_id)
                    .values(is_active=False, last_used_at=now)
                )
                return None

            effective_expires_at = expires_at
            if effective_expires_at is None and ADMIN_TOKEN_REQUIRE_EXPIRY:
                effective_expires_at = created_at + timedelta(days=ADMIN_TOKEN_MAX_TTL_DAYS)

            if effective_expires_at is not None and effective_expires_at <= now:
                conn.execute(
                    update(admin_tokens)
                    .where(admin_tokens.c.id == token_id)
                    .values(is_active=False, last_used_at=now)
                )
                return None

            conn.execute(
                update(admin_tokens)
                .where(admin_tokens.c.id == token_id)
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
    rotate_due_at = _token_rotate_due_at(created_at)
    warning_due_at = None
    if rotate_due_at is not None and ADMIN_TOKEN_ROTATE_WARNING_DAYS > 0:
        warning_due_at = rotate_due_at - timedelta(days=ADMIN_TOKEN_ROTATE_WARNING_DAYS)
    must_rotate = rotate_due_at is not None and warning_due_at is not None and now >= warning_due_at
    idle_due_at = _token_idle_due_at(created_at=created_at, last_used_at=last_used_at)
    return {
        "user_id": int(row["user_id"]),
        "token_id": int(row["token_id"]),
        "token_label": str(row.get("token_label") or ""),
        "token_created_at": created_at,
        "token_expires_at": effective_expires_at,
        "token_rotate_due_at": rotate_due_at,
        "token_idle_due_at": idle_due_at,
        "token_must_rotate": must_rotate,
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
        "token_id": None,
        "token_label": "local-dev",
        "token_created_at": datetime.now(timezone.utc),
        "token_expires_at": None,
        "token_rotate_due_at": None,
        "token_idle_due_at": None,
        "token_must_rotate": False,
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
                "token_id": None,
                "token_label": "legacy-env-token",
                "token_created_at": datetime.now(timezone.utc),
                "token_expires_at": None,
                "token_rotate_due_at": None,
                "token_idle_due_at": None,
                "token_must_rotate": False,
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

def _has_explicit_permission(principal: dict[str, Any], permission: str) -> bool:
    permissions = set(principal.get("permissions", []))
    return permission in permissions
