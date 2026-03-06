"""Admin IAM routes extracted from app.main."""

from __future__ import annotations

from app import main as main_module

APIRouter = main_module.APIRouter
router = APIRouter(prefix="/api/admin", tags=["admin"])
admin_router = router

AdminAuditLogRead = main_module.AdminAuditLogRead
AdminTokenIssueRequest = main_module.AdminTokenIssueRequest
AdminTokenIssueResponse = main_module.AdminTokenIssueResponse
AdminTokenRead = main_module.AdminTokenRead
AdminUserActiveUpdate = main_module.AdminUserActiveUpdate
AdminUserCreate = main_module.AdminUserCreate
AdminUserPasswordSetRequest = main_module.AdminUserPasswordSetRequest
AdminUserRead = main_module.AdminUserRead
AdminUserUpdate = main_module.AdminUserUpdate
Annotated = main_module.Annotated
Any = main_module.Any
Depends = main_module.Depends
HTTPException = main_module.HTTPException
Query = main_module.Query
Response = main_module.Response
SITE_SCOPE_ALL = main_module.SITE_SCOPE_ALL
ADMIN_TOKEN_MAX_ACTIVE_PER_USER = main_module.ADMIN_TOKEN_MAX_ACTIVE_PER_USER
ADMIN_TOKEN_MAX_IDLE_DAYS = main_module.ADMIN_TOKEN_MAX_IDLE_DAYS
ADMIN_TOKEN_MAX_TTL_DAYS = main_module.ADMIN_TOKEN_MAX_TTL_DAYS
ADMIN_TOKEN_REQUIRE_EXPIRY = main_module.ADMIN_TOKEN_REQUIRE_EXPIRY
ADMIN_TOKEN_ROTATE_AFTER_DAYS = main_module.ADMIN_TOKEN_ROTATE_AFTER_DAYS
ADMIN_TOKEN_ROTATE_WARNING_DAYS = main_module.ADMIN_TOKEN_ROTATE_WARNING_DAYS
_as_optional_datetime = main_module._as_optional_datetime
_count_active_owner_users = main_module._count_active_owner_users
_enforce_active_token_quota = main_module._enforce_active_token_quota
_enforce_manager_user_mutation_guardrails = main_module._enforce_manager_user_mutation_guardrails
_hash_password = main_module._hash_password
_hash_token = main_module._hash_token
_normalize_admin_username = main_module._normalize_admin_username
_permission_list_to_text = main_module._permission_list_to_text
_permission_text_to_list = main_module._permission_text_to_list
_principal_role = main_module._principal_role
_principal_site_scope = main_module._principal_site_scope
_require_user_management_access = main_module._require_user_management_access
_resolve_effective_site_scope = main_module._resolve_effective_site_scope
_row_to_admin_audit_log_model = main_module._row_to_admin_audit_log_model
_row_to_admin_token_model = main_module._row_to_admin_token_model
_row_to_admin_user_model = main_module._row_to_admin_user_model
_site_scope_is_subset = main_module._site_scope_is_subset
_site_scope_list_to_text = main_module._site_scope_list_to_text
_site_scope_text_to_list = main_module._site_scope_text_to_list
_write_audit_log = main_module._write_audit_log
admin_audit_logs = main_module.admin_audit_logs
admin_tokens = main_module.admin_tokens
admin_users = main_module.admin_users
build_monthly_audit_archive = main_module.build_monthly_audit_archive
csv = main_module.csv
datetime = main_module.datetime
get_conn = main_module.get_conn
get_current_admin = main_module.get_current_admin
insert = main_module.insert
io = main_module.io
rebaseline_admin_audit_chain = main_module.rebaseline_admin_audit_chain
require_permission = main_module.require_permission
secrets = main_module.secrets
select = main_module.select
timedelta = main_module.timedelta
timezone = main_module.timezone
update = main_module.update


def _build_iam_response_meta(
    *,
    schema: str,
    endpoint: str,
    scope_type: str = "global",
    **extra: Any,
) -> dict[str, Any]:
    return {
        "schema": schema,
        "schema_version": "v1",
        "endpoint": endpoint,
        "scope_type": scope_type,
        **extra,
    }


@admin_router.get("/users", response_model=list[AdminUserRead])
def list_admin_users(
    principal: dict[str, Any] = Depends(get_current_admin),
) -> list[AdminUserRead]:
    _require_user_management_access(principal)
    with get_conn() as conn:
        rows = conn.execute(
            select(admin_users).order_by(admin_users.c.created_at.desc(), admin_users.c.id.desc())
        ).mappings().all()
    if _principal_role(principal) != "manager":
        return [_row_to_admin_user_model(row) for row in rows]

    actor_scope = _principal_site_scope(principal)
    models: list[AdminUserRead] = []
    for row in rows:
        role = str(row.get("role") or "")
        user_scope = _site_scope_text_to_list(row.get("site_scope"), default_all=True)
        if role == "owner":
            continue
        if _site_scope_is_subset(user_scope, actor_scope):
            models.append(_row_to_admin_user_model(row))
    return models

@admin_router.post("/users", response_model=AdminUserRead, status_code=201)
def create_admin_user(
    payload: AdminUserCreate,
    principal: dict[str, Any] = Depends(get_current_admin),
) -> AdminUserRead:
    _require_user_management_access(principal)
    now = datetime.now(timezone.utc)
    normalized_username = _normalize_admin_username(payload.username)
    if not normalized_username:
        raise HTTPException(status_code=400, detail="username is required")
    requested_permissions = _permission_text_to_list(payload.permissions)
    requested_site_scope = _site_scope_text_to_list(payload.site_scope, default_all=True)
    _enforce_manager_user_mutation_guardrails(
        principal,
        next_role=str(payload.role),
        next_permissions=requested_permissions,
        next_site_scope=requested_site_scope,
    )
    permissions_text = _permission_list_to_text(requested_permissions)
    site_scope_text = _site_scope_list_to_text(requested_site_scope)
    display_name = payload.display_name.strip() or normalized_username
    password_hash = _hash_password(payload.password) if payload.password is not None else None
    password_updated_at = now if password_hash else None

    with get_conn() as conn:
        existing = conn.execute(
            select(admin_users.c.id).where(admin_users.c.username == normalized_username)
        ).first()
        if existing is not None:
            raise HTTPException(status_code=409, detail="username already exists")

        result = conn.execute(
            insert(admin_users).values(
                username=normalized_username,
                display_name=display_name,
                role=payload.role,
                permissions=permissions_text,
                site_scope=site_scope_text,
                password_hash=password_hash,
                password_updated_at=password_updated_at,
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
            "password_seeded": password_hash is not None,
        },
    )
    return model

@admin_router.patch("/users/{user_id}", response_model=AdminUserRead)
def update_admin_user(
    user_id: int,
    payload: AdminUserUpdate,
    principal: dict[str, Any] = Depends(get_current_admin),
) -> AdminUserRead:
    _require_user_management_access(principal)
    if (
        payload.display_name is None
        and payload.role is None
        and payload.permissions is None
        and payload.site_scope is None
        and payload.is_active is None
    ):
        raise HTTPException(status_code=400, detail="No update fields provided")

    now = datetime.now(timezone.utc)
    actor_user_id = principal.get("user_id")
    with get_conn() as conn:
        row = conn.execute(select(admin_users).where(admin_users.c.id == user_id).limit(1)).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Admin user not found")

        current_role = str(row.get("role") or "operator")
        current_permissions = _permission_text_to_list(row.get("permissions"))
        current_site_scope = _site_scope_text_to_list(row.get("site_scope"), default_all=True)
        current_is_active = bool(row.get("is_active"))

        next_display_name = str(row.get("display_name") or row.get("username") or "").strip() or str(row.get("username") or "")
        if payload.display_name is not None:
            normalized_name = payload.display_name.strip()
            next_display_name = normalized_name or str(row.get("username") or "")

        next_role = str(payload.role or current_role)
        next_permissions = current_permissions if payload.permissions is None else _permission_text_to_list(payload.permissions)
        next_site_scope = current_site_scope if payload.site_scope is None else _site_scope_text_to_list(payload.site_scope, default_all=True)
        next_is_active = current_is_active if payload.is_active is None else bool(payload.is_active)

        _enforce_manager_user_mutation_guardrails(
            principal,
            next_role=next_role,
            next_permissions=next_permissions,
            next_site_scope=next_site_scope,
            target_role=current_role,
            target_site_scope=current_site_scope,
        )

        if actor_user_id is not None and int(actor_user_id) == user_id and next_is_active is False:
            raise HTTPException(status_code=409, detail="Cannot deactivate current admin user")
        if current_role == "owner" and (next_role != "owner" or not next_is_active):
            if _count_active_owner_users(conn, exclude_user_id=user_id) <= 0:
                raise HTTPException(status_code=409, detail="At least one active owner must remain")

        conn.execute(
            update(admin_users)
            .where(admin_users.c.id == user_id)
            .values(
                display_name=next_display_name,
                role=next_role,
                permissions=_permission_list_to_text(next_permissions),
                site_scope=_site_scope_list_to_text(next_site_scope),
                is_active=next_is_active,
                updated_at=now,
            )
        )
        if not next_is_active:
            conn.execute(
                update(admin_tokens)
                .where(admin_tokens.c.user_id == user_id)
                .values(is_active=False, last_used_at=now)
            )

        updated = conn.execute(select(admin_users).where(admin_users.c.id == user_id).limit(1)).mappings().first()

    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to update admin user")
    model = _row_to_admin_user_model(updated)
    _write_audit_log(
        principal=principal,
        action="admin_user_update",
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

@admin_router.delete("/users/{user_id}", response_model=AdminUserRead)
def delete_admin_user(
    user_id: int,
    principal: dict[str, Any] = Depends(get_current_admin),
) -> AdminUserRead:
    _require_user_management_access(principal)
    actor_user_id = principal.get("user_id")
    if actor_user_id is not None and int(actor_user_id) == user_id:
        raise HTTPException(status_code=409, detail="Current admin user must use /api/auth/me for self deactivation")

    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(select(admin_users).where(admin_users.c.id == user_id).limit(1)).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Admin user not found")

        current_role = str(row.get("role") or "operator")
        current_permissions = _permission_text_to_list(row.get("permissions"))
        current_site_scope = _site_scope_text_to_list(row.get("site_scope"), default_all=True)
        _enforce_manager_user_mutation_guardrails(
            principal,
            next_role=current_role,
            next_permissions=current_permissions,
            next_site_scope=current_site_scope,
            target_role=current_role,
            target_site_scope=current_site_scope,
        )

        if current_role == "owner" and _count_active_owner_users(conn, exclude_user_id=user_id) <= 0:
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
        updated = conn.execute(select(admin_users).where(admin_users.c.id == user_id).limit(1)).mappings().first()

    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to deactivate admin user")
    model = _row_to_admin_user_model(updated)
    _write_audit_log(
        principal=principal,
        action="admin_user_delete",
        resource_type="admin_user",
        resource_id=str(model.id),
        detail={"username": model.username, "is_active": model.is_active},
    )
    return model

@admin_router.patch("/users/{user_id}/active", response_model=AdminUserRead)
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

@admin_router.post("/users/{user_id}/password", response_model=AdminUserRead)
def set_admin_user_password(
    user_id: int,
    payload: AdminUserPasswordSetRequest,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> AdminUserRead:
    now = datetime.now(timezone.utc)
    password_hash = _hash_password(payload.password)

    with get_conn() as conn:
        row = conn.execute(select(admin_users).where(admin_users.c.id == user_id)).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Admin user not found")

        conn.execute(
            update(admin_users)
            .where(admin_users.c.id == user_id)
            .values(password_hash=password_hash, password_updated_at=now, updated_at=now)
        )
        updated = conn.execute(select(admin_users).where(admin_users.c.id == user_id)).mappings().first()

    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to update admin user password")
    model = _row_to_admin_user_model(updated)
    _write_audit_log(
        principal=principal,
        action="admin_user_set_password",
        resource_type="admin_user",
        resource_id=str(model.id),
        detail={"username": model.username},
    )
    return model

@admin_router.post("/users/{user_id}/tokens", response_model=AdminTokenIssueResponse, status_code=201)
def issue_admin_token(
    user_id: int,
    payload: AdminTokenIssueRequest,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> AdminTokenIssueResponse:
    now = datetime.now(timezone.utc)
    token_plain = f"kaos_{secrets.token_urlsafe(24)}"
    token_hash = _hash_token(token_plain)
    expires_at = _as_optional_datetime(payload.expires_at)
    max_allowed_expires_at = now + timedelta(days=ADMIN_TOKEN_MAX_TTL_DAYS)
    if expires_at is None and ADMIN_TOKEN_REQUIRE_EXPIRY:
        expires_at = max_allowed_expires_at
    if expires_at is not None and expires_at <= now:
        raise HTTPException(status_code=400, detail="Token expiry must be in the future")
    if expires_at is not None and expires_at > max_allowed_expires_at:
        raise HTTPException(
            status_code=400,
            detail=f"Token expiry exceeds max TTL ({ADMIN_TOKEN_MAX_TTL_DAYS} days)",
        )
    token_scope_text: str | None = None
    effective_scope: list[str] = [SITE_SCOPE_ALL]
    revoked_ids: list[int] = []

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
        revoked_ids = _enforce_active_token_quota(
            conn=conn,
            user_id=user_id,
            now=now,
            keep_token_ids={token_id},
        )

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
    if revoked_ids:
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
    return response

@admin_router.post("/tokens/{token_id}/rotate", response_model=AdminTokenIssueResponse)
def rotate_admin_token(
    token_id: int,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> AdminTokenIssueResponse:
    now = datetime.now(timezone.utc)
    token_plain = f"kaos_{secrets.token_urlsafe(24)}"
    token_hash = _hash_token(token_plain)
    max_allowed_expires_at = now + timedelta(days=ADMIN_TOKEN_MAX_TTL_DAYS)
    revoked_ids: list[int] = []

    with get_conn() as conn:
        row = conn.execute(
            select(
                admin_tokens.c.id.label("token_id"),
                admin_tokens.c.user_id.label("user_id"),
                admin_tokens.c.label.label("label"),
                admin_tokens.c.is_active.label("is_active"),
                admin_tokens.c.site_scope.label("token_site_scope"),
                admin_tokens.c.expires_at.label("expires_at"),
                admin_users.c.site_scope.label("user_site_scope"),
                admin_users.c.is_active.label("user_is_active"),
            )
            .where(admin_tokens.c.id == token_id)
            .where(admin_users.c.id == admin_tokens.c.user_id)
            .limit(1)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Admin token not found")
        if not bool(row.get("is_active")):
            raise HTTPException(status_code=409, detail="Admin token already inactive")
        if not bool(row.get("user_is_active")):
            raise HTTPException(status_code=409, detail="Inactive user cannot rotate token")

        user_id = int(row["user_id"])
        token_scope_raw = row.get("token_site_scope")
        token_scope = None
        if token_scope_raw is not None:
            token_scope = _site_scope_text_to_list(token_scope_raw, default_all=True)
        user_scope = _site_scope_text_to_list(row.get("user_site_scope"), default_all=True)
        effective_scope = _resolve_effective_site_scope(user_scope=user_scope, token_scope=token_scope)
        if not effective_scope:
            raise HTTPException(status_code=409, detail="Token site scope does not overlap user site scope")

        old_expires_at = _as_optional_datetime(row.get("expires_at"))
        if old_expires_at is not None:
            expires_at = min(old_expires_at, max_allowed_expires_at)
            if expires_at <= now:
                expires_at = max_allowed_expires_at
        elif ADMIN_TOKEN_REQUIRE_EXPIRY:
            expires_at = max_allowed_expires_at
        else:
            expires_at = None

        conn.execute(
            update(admin_tokens)
            .where(admin_tokens.c.id == token_id)
            .values(is_active=False, last_used_at=now)
        )
        inserted = conn.execute(
            insert(admin_tokens).values(
                user_id=user_id,
                label=str(row.get("label") or "rotated"),
                token_hash=token_hash,
                is_active=True,
                site_scope=row.get("token_site_scope"),
                expires_at=expires_at,
                last_used_at=None,
                created_at=now,
            )
        )
        new_token_id = int(inserted.inserted_primary_key[0])
        revoked_ids = _enforce_active_token_quota(
            conn=conn,
            user_id=user_id,
            now=now,
            keep_token_ids={new_token_id},
        )

    response = AdminTokenIssueResponse(
        token_id=new_token_id,
        user_id=user_id,
        label=str(row.get("label") or "rotated"),
        token=token_plain,
        site_scope=effective_scope,
        expires_at=expires_at,
        created_at=now,
    )
    _write_audit_log(
        principal=principal,
        action="admin_token_rotate",
        resource_type="admin_token",
        resource_id=str(token_id),
        detail={
            "old_token_id": token_id,
            "new_token_id": new_token_id,
            "user_id": user_id,
            "label": response.label,
            "site_scope": effective_scope,
            "expires_at": expires_at,
        },
    )
    if revoked_ids:
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
    return response

@admin_router.get("/tokens", response_model=list[AdminTokenRead])
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

@admin_router.get("/token-policy")
def get_admin_token_policy(
    _: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    return {
        "require_expiry": ADMIN_TOKEN_REQUIRE_EXPIRY,
        "max_ttl_days": ADMIN_TOKEN_MAX_TTL_DAYS,
        "rotate_after_days": ADMIN_TOKEN_ROTATE_AFTER_DAYS,
        "rotate_warning_days": ADMIN_TOKEN_ROTATE_WARNING_DAYS,
        "max_idle_days": ADMIN_TOKEN_MAX_IDLE_DAYS,
        "max_active_per_user": ADMIN_TOKEN_MAX_ACTIVE_PER_USER,
        "meta": _build_iam_response_meta(
            schema="admin_token_policy_response",
            endpoint="/api/admin/token-policy",
            policy_family="admin_token",
        ),
    }

@admin_router.get("/audit-logs", response_model=list[AdminAuditLogRead])
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

def _build_audit_archive_csv(
    entries: list[dict[str, Any]],
    *,
    archive: dict[str, Any] | None = None,
    format_version: str = "v1",
) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    normalized_format = str(format_version or "v1").strip().lower()
    include_attachment_meta = normalized_format == "v2"
    if include_attachment_meta and isinstance(archive, dict):
        chain = archive.get("chain") if isinstance(archive.get("chain"), dict) else {}
        archive_meta = archive.get("meta") if isinstance(archive.get("meta"), dict) else {}
        attachments = archive.get("attachments") if isinstance(archive.get("attachments"), dict) else {}
        writer.writerow(["section", "key", "value"])
        writer.writerow(["meta", "format_version", archive.get("format_version", "v2")])
        writer.writerow(
            ["meta", "attachment_schema_version", archive.get("attachment_schema_version", "v2")]
        )
        writer.writerow(["meta", "schema", archive_meta.get("schema", "")])
        writer.writerow(["meta", "schema_version", archive_meta.get("schema_version", "")])
        writer.writerow(["meta", "month", archive.get("month", "")])
        writer.writerow(["meta", "generated_at", archive.get("generated_at", "")])
        writer.writerow(["meta", "entry_count", archive.get("entry_count", 0)])
        writer.writerow(["meta", "entries_included", archive.get("entries_included", True)])
        writer.writerow(["meta", "chain_ok", chain.get("chain_ok", False)])

        dr_attachment = (
            attachments.get("dr_rehearsal")
            if isinstance(attachments.get("dr_rehearsal"), dict)
            else archive.get("dr_rehearsal_attachment")
            if isinstance(archive.get("dr_rehearsal_attachment"), dict)
            else {}
        )
        writer.writerow(["attachment.dr_rehearsal", "schema", dr_attachment.get("schema", "")])
        writer.writerow(["attachment.dr_rehearsal", "schema_version", dr_attachment.get("schema_version", "")])
        writer.writerow(["attachment.dr_rehearsal", "status", dr_attachment.get("status", "")])
        writer.writerow(["attachment.dr_rehearsal", "included", dr_attachment.get("included", False)])

        import_attachment = (
            attachments.get("ops_checklists_import_validation")
            if isinstance(attachments.get("ops_checklists_import_validation"), dict)
            else archive.get("ops_checklists_import_validation_attachment")
            if isinstance(archive.get("ops_checklists_import_validation_attachment"), dict)
            else {}
        )
        import_summary = import_attachment.get("summary") if isinstance(import_attachment.get("summary"), dict) else {}
        writer.writerow(
            [
                "attachment.ops_checklists_import_validation",
                "schema",
                import_attachment.get("schema", ""),
            ]
        )
        writer.writerow(
            [
                "attachment.ops_checklists_import_validation",
                "schema_version",
                import_attachment.get("schema_version", ""),
            ]
        )
        writer.writerow(["attachment.ops_checklists_import_validation", "status", import_attachment.get("status", "")])
        writer.writerow(
            ["attachment.ops_checklists_import_validation", "generated_at", import_attachment.get("generated_at", "")]
        )
        writer.writerow(
            [
                "attachment.ops_checklists_import_validation",
                "error_count",
                import_summary.get("error_count", 0),
            ]
        )
        writer.writerow(
            [
                "attachment.ops_checklists_import_validation",
                "warning_count",
                import_summary.get("warning_count", 0),
            ]
        )
        writer.writerow([])

    writer.writerow(
        [
            "id",
            "created_at",
            "actor_username",
            "action",
            "resource_type",
            "resource_id",
            "status",
            "prev_hash",
            "entry_hash",
        ]
    )
    for item in entries:
        writer.writerow(
            [
                item.get("id"),
                item.get("created_at"),
                item.get("actor_username"),
                item.get("action"),
                item.get("resource_type"),
                item.get("resource_id"),
                item.get("status"),
                item.get("prev_hash"),
                item.get("entry_hash"),
            ]
        )
    return output.getvalue()

@admin_router.get("/audit-integrity")
def get_admin_audit_integrity(
    month: Annotated[str | None, Query(description="YYYY-MM", pattern=r"^\d{4}-\d{2}$")] = None,
    max_entries: Annotated[int, Query(ge=1, le=50000)] = 10000,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    archive = build_monthly_audit_archive(
        month=month,
        max_entries=max_entries,
        include_entries=False,
    )
    _write_audit_log(
        principal=principal,
        action="admin_audit_integrity_check",
        resource_type="admin_audit_log",
        resource_id=archive["month"],
        detail={
            "month": archive["month"],
            "entry_count": archive["entry_count"],
            "chain_ok": archive["chain"]["chain_ok"],
            "issue_count": archive["chain"]["issue_count"],
        },
    )
    return {
        "format_version": archive.get("format_version"),
        "attachment_schema_version": archive.get("attachment_schema_version"),
        "month": archive["month"],
        "generated_at": archive["generated_at"],
        "entry_count": archive["entry_count"],
        "chain": archive["chain"],
        "archive_sha256": archive["archive_sha256"],
        "signature": archive["signature"],
        "signature_algorithm": archive["signature_algorithm"],
        "meta": _build_iam_response_meta(
            schema="admin_audit_integrity_response",
            endpoint="/api/admin/audit-integrity",
            scope_type="monthly",
            month=archive["month"],
            include_entries=False,
            format_version=archive.get("format_version"),
            attachment_schema_version=archive.get("attachment_schema_version"),
        ),
    }

@admin_router.post("/audit-chain/rebaseline")
def post_admin_audit_chain_rebaseline(
    from_month: Annotated[str | None, Query(description="YYYY-MM", pattern=r"^\d{4}-\d{2}$")] = None,
    max_rows: Annotated[int, Query(ge=1, le=200000)] = 50000,
    dry_run: Annotated[bool, Query()] = False,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    result = rebaseline_admin_audit_chain(
        from_month=from_month,
        max_rows=max_rows,
        dry_run=dry_run,
    )
    _write_audit_log(
        principal=principal,
        action="admin_audit_chain_rebaseline",
        resource_type="admin_audit_log",
        resource_id=result["from_month"] or "all",
        detail={
            "from_month": result["from_month"],
            "max_rows": result["max_rows"],
            "dry_run": result["dry_run"],
            "anchor_id": result["anchor_id"],
            "scanned_count": result["scanned_count"],
            "updated_count": result["updated_count"],
            "first_updated_id": result["first_updated_id"],
            "last_updated_id": result["last_updated_id"],
        },
    )
    return result

@admin_router.get("/audit-archive/monthly")
def get_admin_monthly_audit_archive(
    month: Annotated[str | None, Query(description="YYYY-MM", pattern=r"^\d{4}-\d{2}$")] = None,
    max_entries: Annotated[int, Query(ge=1, le=50000)] = 10000,
    include_entries: Annotated[bool, Query()] = True,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    archive = build_monthly_audit_archive(
        month=month,
        max_entries=max_entries,
        include_entries=include_entries,
    )
    _write_audit_log(
        principal=principal,
        action="admin_audit_archive_export_json",
        resource_type="admin_audit_log",
        resource_id=archive["month"],
        detail={
            "month": archive["month"],
            "entry_count": archive["entry_count"],
            "include_entries": include_entries,
            "chain_ok": archive["chain"]["chain_ok"],
        },
    )
    existing_meta = archive.get("meta") if isinstance(archive.get("meta"), dict) else {}
    archive["meta"] = {
        **existing_meta,
        **_build_iam_response_meta(
            schema="admin_audit_archive_response",
            endpoint="/api/admin/audit-archive/monthly",
            scope_type="monthly",
            month=archive["month"],
            include_entries=include_entries,
            format_version=archive.get("format_version"),
            attachment_schema_version=archive.get("attachment_schema_version"),
        ),
    }
    return archive

@admin_router.get("/audit-archive/monthly/csv")
def get_admin_monthly_audit_archive_csv(
    month: Annotated[str | None, Query(description="YYYY-MM", pattern=r"^\d{4}-\d{2}$")] = None,
    max_entries: Annotated[int, Query(ge=1, le=50000)] = 10000,
    format_version: Annotated[str, Query(pattern="^(v1|v2)$")] = "v1",
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> Response:
    archive = build_monthly_audit_archive(
        month=month,
        max_entries=max_entries,
        include_entries=True,
    )
    csv_text = _build_audit_archive_csv(archive["entries"], archive=archive, format_version=format_version)
    file_name = (
        f"audit-archive-{archive['month']}.csv"
        if format_version == "v1"
        else f"audit-archive-{archive['month']}-v2.csv"
    )
    _write_audit_log(
        principal=principal,
        action="admin_audit_archive_export_csv",
        resource_type="admin_audit_log",
        resource_id=archive["month"],
        detail={
            "month": archive["month"],
            "entry_count": archive["entry_count"],
            "chain_ok": archive["chain"]["chain_ok"],
            "format_version": format_version,
        },
    )
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{file_name}"',
            "X-Audit-Archive-Signature": archive["signature"] or "",
            "X-Audit-Archive-SHA256": archive["archive_sha256"],
            "X-Audit-Archive-Format-Version": format_version,
        },
    )

@admin_router.post("/tokens/{token_id}/revoke", response_model=AdminTokenRead)
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
