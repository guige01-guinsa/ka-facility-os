"""Auth routes extracted from app.main."""

from __future__ import annotations

from app import main as main_module

APIRouter = main_module.APIRouter
router = APIRouter(tags=["auth"])
app = router

Any = main_module.Any
AuthLoginRequest = main_module.AuthLoginRequest
AuthLoginResponse = main_module.AuthLoginResponse
AuthLogoutResponse = main_module.AuthLogoutResponse
AuthMeRead = main_module.AuthMeRead
AuthMeUpdateRequest = main_module.AuthMeUpdateRequest
AuthSelfDeactivateResponse = main_module.AuthSelfDeactivateResponse
Depends = main_module.Depends
HTTPException = main_module.HTTPException
Response = main_module.Response
SITE_SCOPE_ALL = main_module.SITE_SCOPE_ALL
ADMIN_TOKEN_MAX_ACTIVE_PER_USER = main_module.ADMIN_TOKEN_MAX_ACTIVE_PER_USER
ADMIN_TOKEN_MAX_TTL_DAYS = main_module.ADMIN_TOKEN_MAX_TTL_DAYS
ADMIN_TOKEN_REQUIRE_EXPIRY = main_module.ADMIN_TOKEN_REQUIRE_EXPIRY
AUTH_LOGIN_TOKEN_LABEL_DEFAULT = main_module.AUTH_LOGIN_TOKEN_LABEL_DEFAULT
admin_tokens = main_module.admin_tokens
admin_users = main_module.admin_users
datetime = main_module.datetime
get_conn = main_module.get_conn
insert = main_module.insert
secrets = main_module.secrets
select = main_module.select
timedelta = main_module.timedelta
timezone = main_module.timezone
update = main_module.update
_count_active_owner_users = main_module._count_active_owner_users
_effective_permissions = main_module._effective_permissions
_enforce_active_token_quota = main_module._enforce_active_token_quota
_attach_auth_me_meta = main_module._attach_auth_me_meta
_hash_password = main_module._hash_password
_hash_token = main_module._hash_token
_load_principal_by_token = main_module._load_principal_by_token
_normalize_admin_username = main_module._normalize_admin_username
_permission_text_to_list = main_module._permission_text_to_list
_principal_site_scope = main_module._principal_site_scope
_principal_to_auth_me_model = main_module._principal_to_auth_me_model
_resolve_effective_site_scope = main_module._resolve_effective_site_scope
_site_scope_text_to_list = main_module._site_scope_text_to_list
_validate_admin_password_value = main_module._validate_admin_password_value
_verify_password = main_module._verify_password
_write_audit_log = main_module._write_audit_log
get_current_admin = main_module.get_current_admin


@app.post("/api/auth/login", response_model=AuthLoginResponse)
def auth_login(
    payload: AuthLoginRequest,
    response: Response,
) -> AuthLoginResponse:
    now = datetime.now(timezone.utc)
    username = _normalize_admin_username(payload.username)
    if not username:
        raise HTTPException(status_code=400, detail="username is required")
    _validate_admin_password_value(payload.password)

    token_plain = f"kaos_{secrets.token_urlsafe(24)}"
    token_hash = _hash_token(token_plain)
    token_label = payload.token_label.strip() or AUTH_LOGIN_TOKEN_LABEL_DEFAULT
    if len(token_label) > 120:
        token_label = token_label[:120]

    max_allowed_expires_at = now + timedelta(days=ADMIN_TOKEN_MAX_TTL_DAYS)
    expires_at = max_allowed_expires_at if ADMIN_TOKEN_REQUIRE_EXPIRY else None

    revoked_ids: list[int] = []
    user_id: int | None = None
    user_scope: list[str] = [SITE_SCOPE_ALL]

    with get_conn() as conn:
        row = conn.execute(
            select(
                admin_users.c.id,
                admin_users.c.username,
                admin_users.c.site_scope,
                admin_users.c.is_active,
                admin_users.c.password_hash,
            )
            .where(admin_users.c.username == username)
            .limit(1)
        ).mappings().first()

        if row is None or not bool(row.get("is_active")):
            _write_audit_log(
                principal=None,
                action="auth_login_failed",
                resource_type="admin_user",
                resource_id=username,
                status="denied",
                detail={"username": username, "reason": "invalid_credentials"},
            )
            raise HTTPException(status_code=401, detail="Invalid username or password")

        stored_password_hash = str(row.get("password_hash") or "")
        if not _verify_password(payload.password, stored_password_hash):
            _write_audit_log(
                principal=None,
                action="auth_login_failed",
                resource_type="admin_user",
                resource_id=username,
                status="denied",
                detail={"username": username, "reason": "invalid_credentials"},
            )
            raise HTTPException(status_code=401, detail="Invalid username or password")

        user_id = int(row["id"])
        user_scope = _site_scope_text_to_list(row.get("site_scope"), default_all=True)
        conn.execute(
            insert(admin_tokens).values(
                user_id=user_id,
                label=token_label,
                token_hash=token_hash,
                is_active=True,
                site_scope=None,
                expires_at=expires_at,
                last_used_at=None,
                created_at=now,
            )
        )
        revoked_ids = _enforce_active_token_quota(conn=conn, user_id=user_id, now=now)

    principal = _load_principal_by_token(token_plain)
    if principal is None:
        raise HTTPException(status_code=500, detail="Failed to issue login token")

    _write_audit_log(
        principal=principal,
        action="auth_login_success",
        resource_type="admin_token",
        resource_id=str(principal.get("token_id") or ""),
        detail={
            "username": username,
            "token_label": token_label,
            "site_scope": _resolve_effective_site_scope(user_scope=user_scope, token_scope=None),
            "expires_at": expires_at.isoformat() if expires_at is not None else None,
        },
    )
    if revoked_ids and user_id is not None:
        _write_audit_log(
            principal=principal,
            action="admin_token_auto_revoke_quota",
            resource_type="admin_token",
            resource_id=",".join(str(tid) for tid in revoked_ids),
            detail={
                "user_id": user_id,
                "max_active_per_user": ADMIN_TOKEN_MAX_ACTIVE_PER_USER,
                "revoked_token_ids": revoked_ids,
            },
        )

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return AuthLoginResponse(
        token=token_plain,
        profile=_principal_to_auth_me_model(principal, endpoint="/api/auth/login"),
    )

@app.get("/api/auth/me", response_model=AuthMeRead)
def auth_me(
    principal: dict[str, Any] = Depends(get_current_admin),
) -> AuthMeRead:
    return _principal_to_auth_me_model(principal, endpoint="/api/auth/me")

@app.post("/api/auth/logout", response_model=AuthLogoutResponse)
def auth_logout(
    response: Response,
    principal: dict[str, Any] = Depends(get_current_admin),
) -> AuthLogoutResponse:
    now = datetime.now(timezone.utc)
    token_id_value = principal.get("token_id")
    token_id = int(token_id_value) if token_id_value is not None else None
    token_label = str(principal.get("token_label") or "")
    is_legacy = bool(principal.get("is_legacy", False))
    token_revoked = False
    is_legacy_env_token = is_legacy and token_label in {"legacy-env-admin-token", "legacy-env-token"}

    if token_id is not None and not is_legacy_env_token:
        with get_conn() as conn:
            row = conn.execute(
                select(admin_tokens.c.id).where(admin_tokens.c.id == token_id).limit(1)
            ).first()
            if row is not None:
                conn.execute(
                    update(admin_tokens)
                    .where(admin_tokens.c.id == token_id)
                    .values(is_active=False, last_used_at=now)
                )
                token_revoked = True

    _write_audit_log(
        principal=principal,
        action="auth_logout",
        resource_type="admin_token",
        resource_id=str(token_id if token_id is not None else (token_label or "current")),
        detail={
            "username": str(principal.get("username") or "unknown"),
            "token_id": token_id,
            "token_label": token_label,
            "token_revoked": token_revoked,
            "is_legacy": is_legacy,
            "is_legacy_env_token": is_legacy_env_token,
        },
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return AuthLogoutResponse(
        status="logged_out",
        token_id=token_id,
        token_label=token_label or None,
        token_revoked=token_revoked,
        is_legacy=is_legacy,
        logged_out_at=now,
    )

@app.patch("/api/auth/me/profile", response_model=AuthMeRead)
def auth_me_update_profile(
    payload: AuthMeUpdateRequest,
    principal: dict[str, Any] = Depends(get_current_admin),
) -> AuthMeRead:
    if payload.display_name is None and payload.password is None:
        raise HTTPException(status_code=400, detail="No profile update fields provided")

    user_id_raw = principal.get("user_id")
    if user_id_raw is None:
        raise HTTPException(status_code=409, detail="Legacy token cannot update profile")
    user_id = int(user_id_raw)
    now = datetime.now(timezone.utc)
    actor_username = str(principal.get("username") or "unknown")

    with get_conn() as conn:
        row = conn.execute(select(admin_users).where(admin_users.c.id == user_id).limit(1)).mappings().first()
        if row is None or not bool(row.get("is_active")):
            raise HTTPException(status_code=404, detail="Admin user not found")

        next_display_name = str(row.get("display_name") or row.get("username") or "").strip() or str(row.get("username") or "")
        values: dict[str, Any] = {"updated_at": now}

        if payload.display_name is not None:
            normalized_name = payload.display_name.strip()
            next_display_name = normalized_name or str(row.get("username") or "")
            values["display_name"] = next_display_name

        if payload.password is not None:
            values["password_hash"] = _hash_password(payload.password)
            values["password_updated_at"] = now

        conn.execute(
            update(admin_users)
            .where(admin_users.c.id == user_id)
            .values(**values)
        )

        updated = conn.execute(select(admin_users).where(admin_users.c.id == user_id).limit(1)).mappings().first()

    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to update admin profile")

    updated_role = str(updated.get("role") or "operator")
    updated_permissions = _effective_permissions(
        updated_role,
        _permission_text_to_list(updated.get("permissions")),
    )
    profile = AuthMeRead(
        user_id=user_id,
        token_id=principal.get("token_id"),
        token_label=principal.get("token_label"),
        token_expires_at=principal.get("token_expires_at"),
        token_rotate_due_at=principal.get("token_rotate_due_at"),
        token_idle_due_at=principal.get("token_idle_due_at"),
        token_must_rotate=bool(principal.get("token_must_rotate", False)),
        username=str(updated.get("username") or actor_username),
        display_name=str(updated.get("display_name") or updated.get("username") or actor_username),
        role=updated_role,
        permissions=updated_permissions,
        site_scope=list(_principal_site_scope(principal)),
        is_legacy=bool(principal.get("is_legacy", False)),
    )
    _write_audit_log(
        principal=principal,
        action="auth_profile_update",
        resource_type="admin_user",
        resource_id=str(user_id),
        detail={
            "updated_fields": sorted([key for key in ("display_name", "password") if getattr(payload, key) is not None]),
            "actor": actor_username,
        },
    )
    return _attach_auth_me_meta(profile, endpoint="/api/auth/me/profile")

@app.delete("/api/auth/me", response_model=AuthSelfDeactivateResponse)
def auth_me_deactivate(
    principal: dict[str, Any] = Depends(get_current_admin),
) -> AuthSelfDeactivateResponse:
    user_id_raw = principal.get("user_id")
    if user_id_raw is None:
        raise HTTPException(status_code=409, detail="Legacy token cannot deactivate account")
    user_id = int(user_id_raw)
    now = datetime.now(timezone.utc)

    with get_conn() as conn:
        row = conn.execute(select(admin_users).where(admin_users.c.id == user_id).limit(1)).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Admin user not found")

        role = str(row.get("role") or "operator")
        if role == "owner" and _count_active_owner_users(conn, exclude_user_id=user_id) <= 0:
            raise HTTPException(status_code=409, detail="At least one active owner must remain")

        conn.execute(
            update(admin_users)
            .where(admin_users.c.id == user_id)
            .values(is_active=False, updated_at=now)
        )
        conn.execute(
            update(admin_tokens)
            .where(admin_tokens.c.user_id == user_id)
            .values(is_active=False, last_used_at=now)
        )

    _write_audit_log(
        principal=principal,
        action="auth_self_deactivate",
        resource_type="admin_user",
        resource_id=str(user_id),
        detail={"username": str(principal.get("username") or "")},
    )
    return AuthSelfDeactivateResponse(
        status="deactivated",
        user_id=user_id,
        username=str(principal.get("username") or ""),
        deactivated_at=now,
    )
