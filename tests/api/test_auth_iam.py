import importlib
import io
import json
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.helpers.common import _assert_adoption_policy_response_shape, _owner_headers


@pytest.mark.smoke
def test_rbac_user_and_token_lifecycle(app_client: TestClient) -> None:
    me = app_client.get("/api/auth/me", headers=_owner_headers())
    assert me.status_code == 200
    me_body = me.json()
    assert me_body["role"] == "owner"
    assert me_body["meta"]["schema"] == "auth_profile_response"
    assert me_body["meta"]["schema_version"] == "v1"
    assert me_body["meta"]["endpoint"] == "/api/auth/me"
    assert me_body["meta"]["scope_type"] == "global"
    assert me.headers.get("cache-control") == "no-store"
    assert me.headers.get("pragma") == "no-cache"
    assert me.headers.get("x-content-type-options") == "nosniff"
    assert me.headers.get("cross-origin-opener-policy") == "same-origin"
    assert me.headers.get("cross-origin-resource-policy") == "same-origin"
    assert me.headers.get("origin-agent-cluster") == "?1"

    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "ops_manager_ci",
            "display_name": "Ops Manager CI",
            "role": "manager",
            "permissions": [],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "ci-token"},
    )
    assert issued.status_code == 201
    token_id = issued.json()["token_id"]
    issued_token = issued.json()["token"]

    me2 = app_client.get("/api/auth/me", headers={"X-Admin-Token": issued_token})
    assert me2.status_code == 200
    assert me2.json()["role"] == "manager"

    revoked = app_client.post(
        f"/api/admin/tokens/{token_id}/revoke",
        headers=_owner_headers(),
    )
    assert revoked.status_code == 200
    assert revoked.json()["is_active"] is False

    me3 = app_client.get("/api/auth/me", headers={"X-Admin-Token": issued_token})
    assert me3.status_code == 401

def test_auth_login_with_seeded_password_user(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "login_seeded_ci",
            "display_name": "Login Seeded CI",
            "role": "manager",
            "permissions": [],
            "password": "SeededPass123!",
        },
    )
    assert created.status_code == 201

    login = app_client.post(
        "/api/auth/login",
        json={
            "username": "login_seeded_ci",
            "password": "SeededPass123!",
            "token_label": "web-login-ci",
        },
    )
    assert login.status_code == 200
    assert login.headers.get("cache-control") == "no-store"
    assert login.headers.get("pragma") == "no-cache"
    body = login.json()
    assert body["token"].startswith("kaos_")
    assert body["profile"]["username"] == "login_seeded_ci"
    assert body["profile"]["role"] == "manager"
    assert body["profile"]["token_label"] == "web-login-ci"
    assert body["profile"]["meta"]["schema"] == "auth_profile_response"
    assert body["profile"]["meta"]["endpoint"] == "/api/auth/login"

    me = app_client.get("/api/auth/me", headers={"X-Admin-Token": body["token"]})
    assert me.status_code == 200
    assert me.json()["username"] == "login_seeded_ci"

    wrong = app_client.post(
        "/api/auth/login",
        json={
            "username": "login_seeded_ci",
            "password": "wrong-password",
            "token_label": "web-login-ci",
        },
    )
    assert wrong.status_code == 401
    assert wrong.json()["detail"] == "Invalid username or password"

def test_auth_logout_revokes_issued_token_and_handles_legacy_token(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "logout_ci",
            "display_name": "Logout CI",
            "role": "operator",
            "permissions": [],
            "password": "LogoutPass123!",
        },
    )
    assert created.status_code == 201

    login = app_client.post(
        "/api/auth/login",
        json={
            "username": "logout_ci",
            "password": "LogoutPass123!",
            "token_label": "logout-ci-token",
        },
    )
    assert login.status_code == 200
    issued_token = login.json()["token"]
    issued_headers = {"X-Admin-Token": issued_token}
    me_before = app_client.get("/api/auth/me", headers=issued_headers)
    assert me_before.status_code == 200

    logout = app_client.post("/api/auth/logout", headers=issued_headers)
    assert logout.status_code == 200
    logout_body = logout.json()
    assert logout_body["status"] == "logged_out"
    assert logout_body["token_revoked"] is True
    assert logout_body["is_legacy"] is False
    assert logout.headers.get("cache-control") == "no-store"
    assert logout.headers.get("pragma") == "no-cache"
    assert logout.headers.get("clear-site-data") == '"cache", "storage"'

    me_after = app_client.get("/api/auth/me", headers=issued_headers)
    assert me_after.status_code == 401

    legacy_logout = app_client.post("/api/auth/logout", headers=_owner_headers())
    assert legacy_logout.status_code == 200
    legacy_body = legacy_logout.json()
    assert legacy_body["status"] == "logged_out"
    assert legacy_body["token_revoked"] is False
    assert legacy_body["is_legacy"] is True
    legacy_me_after = app_client.get("/api/auth/me", headers=_owner_headers())
    assert legacy_me_after.status_code == 200

def test_admin_set_password_then_auth_login(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "login_set_pw_ci",
            "display_name": "Login Set PW CI",
            "role": "operator",
            "permissions": [],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    missing_pw_login = app_client.post(
        "/api/auth/login",
        json={
            "username": "login_set_pw_ci",
            "password": "FirstPass123!",
            "token_label": "web-login-ci",
        },
    )
    assert missing_pw_login.status_code == 401

    set_pw = app_client.post(
        f"/api/admin/users/{user_id}/password",
        headers=_owner_headers(),
        json={"password": "FirstPass123!"},
    )
    assert set_pw.status_code == 200
    assert set_pw.json()["username"] == "login_set_pw_ci"

    login = app_client.post(
        "/api/auth/login",
        json={
            "username": "login_set_pw_ci",
            "password": "FirstPass123!",
            "token_label": "ui-login",
        },
    )
    assert login.status_code == 200
    assert login.json()["profile"]["username"] == "login_set_pw_ci"
    assert login.json()["profile"]["token_label"] == "ui-login"

def test_manager_can_create_update_and_delete_user(app_client: TestClient) -> None:
    manager_created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "mgr_user_admin_ci",
            "display_name": "Manager User Admin CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["HQ"],
            "password": "ManagerPass123!",
        },
    )
    assert manager_created.status_code == 201
    manager_id = manager_created.json()["id"]

    manager_token_issue = app_client.post(
        f"/api/admin/users/{manager_id}/tokens",
        headers=_owner_headers(),
        json={"label": "mgr-user-admin-token"},
    )
    assert manager_token_issue.status_code == 201
    manager_headers = {"X-Admin-Token": manager_token_issue.json()["token"]}

    created = app_client.post(
        "/api/admin/users",
        headers=manager_headers,
        json={
            "username": "ops_member_ci",
            "display_name": "Ops Member CI",
            "role": "operator",
            "permissions": [],
            "site_scope": ["HQ"],
            "password": "OpsMemberPass123!",
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    updated = app_client.patch(
        f"/api/admin/users/{user_id}",
        headers=manager_headers,
        json={
            "display_name": "Ops Member Updated",
            "permissions": ["work_orders:escalate"],
            "site_scope": ["HQ"],
        },
    )
    assert updated.status_code == 200
    updated_body = updated.json()
    assert updated_body["display_name"] == "Ops Member Updated"
    assert updated_body["role"] == "operator"
    assert "work_orders:escalate" in updated_body["permissions"]

    deleted = app_client.delete(
        f"/api/admin/users/{user_id}",
        headers=manager_headers,
    )
    assert deleted.status_code == 200
    assert deleted.json()["is_active"] is False

def test_manager_permission_update_guardrails(app_client: TestClient) -> None:
    manager_created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "mgr_guard_ci",
            "display_name": "Manager Guard CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["HQ"],
            "password": "ManagerGuard123!",
        },
    )
    assert manager_created.status_code == 201
    manager_id = manager_created.json()["id"]

    manager_token_issue = app_client.post(
        f"/api/admin/users/{manager_id}/tokens",
        headers=_owner_headers(),
        json={"label": "mgr-guard-token"},
    )
    assert manager_token_issue.status_code == 201
    manager_headers = {"X-Admin-Token": manager_token_issue.json()["token"]}

    owner_list = app_client.get("/api/admin/users", headers=_owner_headers())
    assert owner_list.status_code == 200
    owner_row = next(item for item in owner_list.json() if item["role"] == "owner")

    manager_edit_owner = app_client.patch(
        f"/api/admin/users/{owner_row['id']}",
        headers=manager_headers,
        json={"display_name": "blocked"},
    )
    assert manager_edit_owner.status_code == 403

    manager_grant_admin_perm = app_client.post(
        "/api/admin/users",
        headers=manager_headers,
        json={
            "username": "mgr_forbidden_perm_ci",
            "display_name": "Forbidden Perm CI",
            "role": "operator",
            "permissions": ["admins:manage"],
            "site_scope": ["HQ"],
            "password": "ForbiddenPass123!",
        },
    )
    assert manager_grant_admin_perm.status_code == 403

    manager_out_of_scope = app_client.post(
        "/api/admin/users",
        headers=manager_headers,
        json={
            "username": "mgr_scope_forbidden_ci",
            "display_name": "Scope Forbidden CI",
            "role": "operator",
            "permissions": [],
            "site_scope": ["OUTSIDE"],
            "password": "ScopeForbidden123!",
        },
    )
    assert manager_out_of_scope.status_code == 403

    owner_created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "mgr_target_ci",
            "display_name": "Manager Target CI",
            "role": "operator",
            "permissions": [],
            "site_scope": ["HQ"],
            "password": "TargetPass123!",
        },
    )
    assert owner_created.status_code == 201
    target_id = owner_created.json()["id"]

    manager_promote_owner = app_client.patch(
        f"/api/admin/users/{target_id}",
        headers=manager_headers,
        json={"role": "owner"},
    )
    assert manager_promote_owner.status_code == 403

def test_auth_me_profile_update_and_self_deactivate(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "self_manage_ci",
            "display_name": "Self Manage CI",
            "role": "operator",
            "permissions": [],
            "site_scope": ["HQ"],
            "password": "SelfManagePass123!",
        },
    )
    assert created.status_code == 201

    login_old = app_client.post(
        "/api/auth/login",
        json={
            "username": "self_manage_ci",
            "password": "SelfManagePass123!",
            "token_label": "self-token",
        },
    )
    assert login_old.status_code == 200
    token_old = login_old.json()["token"]
    auth_headers = {"X-Admin-Token": token_old}

    profile_update = app_client.patch(
        "/api/auth/me/profile",
        headers=auth_headers,
        json={"display_name": "Self Updated CI", "password": "SelfManagePass456!"},
    )
    assert profile_update.status_code == 200
    assert profile_update.json()["display_name"] == "Self Updated CI"

    old_login_fail = app_client.post(
        "/api/auth/login",
        json={
            "username": "self_manage_ci",
            "password": "SelfManagePass123!",
            "token_label": "self-token",
        },
    )
    assert old_login_fail.status_code == 401

    login_new = app_client.post(
        "/api/auth/login",
        json={
            "username": "self_manage_ci",
            "password": "SelfManagePass456!",
            "token_label": "self-token-new",
        },
    )
    assert login_new.status_code == 200
    token_new = login_new.json()["token"]
    new_headers = {"X-Admin-Token": token_new}

    deactivate = app_client.delete("/api/auth/me", headers=new_headers)
    assert deactivate.status_code == 200
    assert deactivate.json()["status"] == "deactivated"
    assert deactivate.json()["username"] == "self_manage_ci"

    me_after_deactivate = app_client.get("/api/auth/me", headers=new_headers)
    assert me_after_deactivate.status_code == 401

def test_admin_token_expiry_and_rotation_policy(app_client: TestClient) -> None:
    import app.database as db_module
    from sqlalchemy import select, update

    policy = app_client.get("/api/admin/token-policy", headers=_owner_headers())
    assert policy.status_code == 200
    policy_body = policy.json()
    assert policy_body["max_ttl_days"] == 30
    assert policy_body["max_idle_days"] == 30
    assert policy_body["meta"]["schema"] == "admin_token_policy_response"
    assert policy_body["meta"]["schema_version"] == "v1"
    assert policy_body["meta"]["endpoint"] == "/api/admin/token-policy"
    assert policy_body["meta"]["policy_family"] == "admin_token"

    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "token_policy_ci",
            "display_name": "Token Policy CI",
            "role": "manager",
            "permissions": [],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    too_far_future = (datetime.now(timezone.utc) + timedelta(days=120)).isoformat()
    rejected = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "too-long", "expires_at": too_far_future},
    )
    assert rejected.status_code == 400
    assert "max TTL" in rejected.json()["detail"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "policy-token"},
    )
    assert issued.status_code == 201
    token_id = issued.json()["token_id"]
    token_plain = issued.json()["token"]
    assert issued.json()["expires_at"] is not None

    me = app_client.get("/api/auth/me", headers={"X-Admin-Token": token_plain})
    assert me.status_code == 200
    assert me.json()["token_id"] == token_id
    assert me.json()["token_must_rotate"] is False

    very_old = datetime.now(timezone.utc) - timedelta(days=60)
    with db_module.get_conn() as conn:
        conn.execute(
            update(db_module.admin_tokens)
            .where(db_module.admin_tokens.c.id == token_id)
            .values(created_at=very_old)
        )

    me_after_rotate_window = app_client.get("/api/auth/me", headers={"X-Admin-Token": token_plain})
    assert me_after_rotate_window.status_code == 401

    with db_module.get_conn() as conn:
        row = conn.execute(
            select(db_module.admin_tokens.c.is_active).where(db_module.admin_tokens.c.id == token_id)
        ).first()
    assert row is not None
    assert row[0] is False

    issued2 = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "idle-token"},
    )
    assert issued2.status_code == 201
    token2_id = issued2.json()["token_id"]
    token2_plain = issued2.json()["token"]

    stale_last_used = datetime.now(timezone.utc) - timedelta(days=40)
    with db_module.get_conn() as conn:
        conn.execute(
            update(db_module.admin_tokens)
            .where(db_module.admin_tokens.c.id == token2_id)
            .values(last_used_at=stale_last_used)
        )

    idle_rejected = app_client.get("/api/auth/me", headers={"X-Admin-Token": token2_plain})
    assert idle_rejected.status_code == 401

    issued3 = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "rotate-me"},
    )
    assert issued3.status_code == 201
    old_token_id = issued3.json()["token_id"]
    old_token_plain = issued3.json()["token"]

    rotated = app_client.post(
        f"/api/admin/tokens/{old_token_id}/rotate",
        headers=_owner_headers(),
    )
    assert rotated.status_code == 200
    assert rotated.json()["token_id"] != old_token_id
    assert rotated.json()["token"] != old_token_plain

    old_auth = app_client.get("/api/auth/me", headers={"X-Admin-Token": old_token_plain})
    assert old_auth.status_code == 401
    new_auth = app_client.get("/api/auth/me", headers={"X-Admin-Token": rotated.json()["token"]})
    assert new_auth.status_code == 200

def test_site_scoped_rbac_enforcement(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "scope_manager_ci",
            "display_name": "Scope Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["Scope Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]
    assert created.json()["site_scope"] == ["Scope Site"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "scope-token"},
    )
    assert issued.status_code == 201
    scoped_token = issued.json()["token"]
    scoped_headers = {"X-Admin-Token": scoped_token}
    assert issued.json()["site_scope"] == ["Scope Site"]

    me = app_client.get("/api/auth/me", headers=scoped_headers)
    assert me.status_code == 200
    me_body = me.json()
    assert me_body["site_scope"] == ["Scope Site"]
    assert me_body["meta"]["scope_type"] == "site"

    outside_due = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    outside = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Outside Site WO",
            "description": "owner created outside scope",
            "site": "Outside Site",
            "location": "B1",
            "priority": "high",
            "due_at": outside_due,
        },
    )
    assert outside.status_code == 201
    outside_id = outside.json()["id"]

    allowed_due = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    allowed = app_client.post(
        "/api/work-orders",
        headers=scoped_headers,
        json={
            "title": "Scoped Site WO",
            "description": "scoped token",
            "site": "Scope Site",
            "location": "B1",
            "priority": "high",
            "due_at": allowed_due,
        },
    )
    assert allowed.status_code == 201
    allowed_id = allowed.json()["id"]

    forbidden_create = app_client.post(
        "/api/work-orders",
        headers=scoped_headers,
        json={
            "title": "Forbidden create",
            "description": "should fail",
            "site": "Outside Site",
            "location": "B1",
            "priority": "high",
            "due_at": allowed_due,
        },
    )
    assert forbidden_create.status_code == 403

    scoped_list = app_client.get("/api/work-orders", headers=scoped_headers)
    assert scoped_list.status_code == 200
    assert all(row["site"] == "Scope Site" for row in scoped_list.json())

    outside_read = app_client.get(f"/api/work-orders/{outside_id}", headers=scoped_headers)
    assert outside_read.status_code == 403

    run = app_client.post(
        "/api/work-orders/escalations/run",
        headers=scoped_headers,
        json={"dry_run": False, "limit": 200},
    )
    assert run.status_code == 200
    escalated_ids = set(run.json()["work_order_ids"])
    assert allowed_id in escalated_ids
    assert outside_id not in escalated_ids

    outside_after = app_client.get(f"/api/work-orders/{outside_id}", headers=_owner_headers())
    assert outside_after.status_code == 200
    assert outside_after.json()["is_escalated"] is False

    forbidden_report = app_client.get(
        "/api/reports/monthly?month=2099-01&site=Outside+Site",
        headers=scoped_headers,
    )
    assert forbidden_report.status_code == 403

def test_w11_auditor_read_access_and_write_block(app_client: TestClient) -> None:
    bootstrap = app_client.post(
        "/api/adoption/w11/tracker/bootstrap",
        headers=_owner_headers(),
        json={"site": "W11 Auditor Site"},
    )
    assert bootstrap.status_code == 200

    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w11_auditor_ci",
            "display_name": "W11 Auditor CI",
            "role": "auditor",
            "permissions": [],
            "site_scope": ["W11 Auditor Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w11-auditor-token"},
    )
    assert issued.status_code == 201
    auditor_headers = {"X-Admin-Token": issued.json()["token"]}

    overview = app_client.get(
        "/api/adoption/w11/tracker/overview?site=W11+Auditor+Site",
        headers=auditor_headers,
    )
    assert overview.status_code == 200
    assert overview.json()["site"] == "W11 Auditor Site"

    snapshot = app_client.get(
        "/api/ops/adoption/w11/scale-readiness?site=W11+Auditor+Site&days=30",
        headers=auditor_headers,
    )
    assert snapshot.status_code == 200
    assert snapshot.json()["site"] == "W11 Auditor Site"

    write_forbidden = app_client.post(
        "/api/adoption/w11/tracker/bootstrap",
        headers=auditor_headers,
        json={"site": "W11 Auditor Site"},
    )
    assert write_forbidden.status_code == 403

def test_w15_auditor_read_access_and_write_block(app_client: TestClient) -> None:
    bootstrap = app_client.post(
        "/api/adoption/w15/tracker/bootstrap",
        headers=_owner_headers(),
        json={"site": "W15 Auditor Site"},
    )
    assert bootstrap.status_code == 200

    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w15_auditor_ci",
            "display_name": "W15 Auditor CI",
            "role": "auditor",
            "permissions": [],
            "site_scope": ["W15 Auditor Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w15-auditor-token"},
    )
    assert issued.status_code == 201
    auditor_headers = {"X-Admin-Token": issued.json()["token"]}

    overview = app_client.get(
        "/api/adoption/w15/tracker/overview?site=W15+Auditor+Site",
        headers=auditor_headers,
    )
    assert overview.status_code == 200
    assert overview.json()["site"] == "W15 Auditor Site"

    snapshot = app_client.get(
        "/api/ops/adoption/w15/ops-efficiency?site=W15+Auditor+Site&days=30",
        headers=auditor_headers,
    )
    assert snapshot.status_code == 200
    assert snapshot.json()["site"] == "W15 Auditor Site"

    listed = app_client.get(
        "/api/adoption/w15/tracker/items?site=W15+Auditor+Site&limit=1",
        headers=auditor_headers,
    )
    assert listed.status_code == 200
    tracker_item_id = listed.json()[0]["id"]

    write_forbidden_bootstrap = app_client.post(
        "/api/adoption/w15/tracker/bootstrap",
        headers=auditor_headers,
        json={"site": "W15 Auditor Site"},
    )
    assert write_forbidden_bootstrap.status_code == 403

    write_forbidden_patch = app_client.patch(
        f"/api/adoption/w15/tracker/items/{tracker_item_id}",
        headers=auditor_headers,
        json={"status": "in_progress"},
    )
    assert write_forbidden_patch.status_code == 403

    write_forbidden_complete = app_client.post(
        "/api/adoption/w15/tracker/complete",
        headers=auditor_headers,
        json={"site": "W15 Auditor Site"},
    )
    assert write_forbidden_complete.status_code == 403
