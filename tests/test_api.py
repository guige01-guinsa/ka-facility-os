import importlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("ENV", "test")
    monkeypatch.setenv("ALLOW_INSECURE_LOCAL_AUTH", "0")
    monkeypatch.setenv("ADMIN_TOKEN", "test-owner-token")
    monkeypatch.delenv("ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("ALERT_WEBHOOK_URLS", raising=False)

    import app.database as database_module
    import app.main as main_module

    importlib.reload(database_module)
    importlib.reload(main_module)

    with TestClient(main_module.app) as client:
        yield client


def _owner_headers() -> dict[str, str]:
    return {"X-Admin-Token": "test-owner-token"}


def test_health_and_meta(app_client: TestClient) -> None:
    health = app_client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    meta = app_client.get("/meta")
    assert meta.status_code == 200
    assert meta.json()["env"] == "test"


def test_rbac_user_and_token_lifecycle(app_client: TestClient) -> None:
    me = app_client.get("/api/auth/me", headers=_owner_headers())
    assert me.status_code == 200
    assert me.json()["role"] == "owner"

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
    assert me.json()["site_scope"] == ["Scope Site"]

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


def test_work_order_escalation_and_audit_log(app_client: TestClient) -> None:
    due_at = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    created = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Escalation test",
            "description": "SLA overdue",
            "site": "CI Site",
            "location": "B1",
            "priority": "high",
            "due_at": due_at,
        },
    )
    assert created.status_code == 201

    run = app_client.post(
        "/api/work-orders/escalations/run",
        headers=_owner_headers(),
        json={"dry_run": False, "limit": 100},
    )
    assert run.status_code == 200
    assert run.json()["escalated_count"] >= 1
    assert "alert_dispatched" in run.json()
    assert "alert_channels" in run.json()

    logs = app_client.get(
        "/api/admin/audit-logs?action=work_order_sla_escalation_run",
        headers=_owner_headers(),
    )
    assert logs.status_code == 200
    assert len(logs.json()) >= 1


def test_sla_policy_auto_due_and_grace(app_client: TestClient) -> None:
    updated = app_client.put(
        "/api/admin/policies/sla",
        headers=_owner_headers(),
        json={
            "default_due_hours": {"low": 96, "medium": 1, "high": 4, "critical": 2},
            "escalation_grace_minutes": 30,
        },
    )
    assert updated.status_code == 200
    assert updated.json()["default_due_hours"]["medium"] == 1
    assert updated.json()["escalation_grace_minutes"] == 30

    wo_auto_due = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Auto due by policy",
            "description": "No due_at provided",
            "site": "Policy Site",
            "location": "B2",
            "priority": "medium",
        },
    )
    assert wo_auto_due.status_code == 201
    due_at = datetime.fromisoformat(wo_auto_due.json()["due_at"])
    now = datetime.now(timezone.utc)
    assert now + timedelta(minutes=50) <= due_at <= now + timedelta(minutes=70)

    due_not_ready = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    created_not_ready = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Within grace",
            "description": "Should not escalate yet",
            "site": "Policy Site",
            "location": "B2",
            "priority": "high",
            "due_at": due_not_ready,
        },
    )
    assert created_not_ready.status_code == 201

    run1 = app_client.post(
        "/api/work-orders/escalations/run",
        headers=_owner_headers(),
        json={"dry_run": False, "site": "Policy Site", "limit": 100},
    )
    assert run1.status_code == 200
    assert run1.json()["escalated_count"] == 0

    due_over_grace = (datetime.now(timezone.utc) - timedelta(minutes=40)).isoformat()
    created_over_grace = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Over grace",
            "description": "Should escalate",
            "site": "Policy Site",
            "location": "B2",
            "priority": "high",
            "due_at": due_over_grace,
        },
    )
    assert created_over_grace.status_code == 201

    run2 = app_client.post(
        "/api/work-orders/escalations/run",
        headers=_owner_headers(),
        json={"dry_run": False, "site": "Policy Site", "limit": 100},
    )
    assert run2.status_code == 200
    assert run2.json()["escalated_count"] >= 1


def test_sla_policy_site_override_and_fallback(app_client: TestClient) -> None:
    default_updated = app_client.put(
        "/api/admin/policies/sla",
        headers=_owner_headers(),
        json={
            "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
            "escalation_grace_minutes": 0,
        },
    )
    assert default_updated.status_code == 200

    site_updated = app_client.put(
        "/api/admin/policies/sla?site=Site%20A",
        headers=_owner_headers(),
        json={
            "default_due_hours": {"low": 72, "medium": 2, "high": 6, "critical": 1},
            "escalation_grace_minutes": 45,
        },
    )
    assert site_updated.status_code == 200
    assert site_updated.json()["source"] == "site"
    assert site_updated.json()["site"] == "Site A"
    assert site_updated.json()["default_due_hours"]["medium"] == 2

    get_site_a = app_client.get(
        "/api/admin/policies/sla?site=Site%20A",
        headers=_owner_headers(),
    )
    assert get_site_a.status_code == 200
    assert get_site_a.json()["source"] == "site"
    assert get_site_a.json()["policy_key"].startswith("site:")

    get_site_b = app_client.get(
        "/api/admin/policies/sla?site=Site%20B",
        headers=_owner_headers(),
    )
    assert get_site_b.status_code == 200
    assert get_site_b.json()["source"] == "default"
    assert get_site_b.json()["policy_key"] == "default"
    assert get_site_b.json()["default_due_hours"]["medium"] == 24

    now = datetime.now(timezone.utc)
    wo_a = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Site A auto due",
            "description": "site override",
            "site": "Site A",
            "location": "B4",
            "priority": "medium",
        },
    )
    assert wo_a.status_code == 201
    due_a = datetime.fromisoformat(wo_a.json()["due_at"])
    assert now + timedelta(minutes=100) <= due_a <= now + timedelta(minutes=140)

    wo_b = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Site B auto due",
            "description": "default fallback",
            "site": "Site B",
            "location": "B4",
            "priority": "medium",
        },
    )
    assert wo_b.status_code == 201
    due_b = datetime.fromisoformat(wo_b.json()["due_at"])
    assert now + timedelta(hours=23) <= due_b <= now + timedelta(hours=25)


def test_sla_escalation_uses_site_grace_on_global_run(app_client: TestClient) -> None:
    set_default = app_client.put(
        "/api/admin/policies/sla",
        headers=_owner_headers(),
        json={
            "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
            "escalation_grace_minutes": 0,
        },
    )
    assert set_default.status_code == 200

    set_site = app_client.put(
        "/api/admin/policies/sla?site=Grace%20Site",
        headers=_owner_headers(),
        json={
            "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
            "escalation_grace_minutes": 60,
        },
    )
    assert set_site.status_code == 200

    due_30m = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    wo_grace = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Grace protected",
            "description": "should not escalate",
            "site": "Grace Site",
            "location": "B5",
            "priority": "high",
            "due_at": due_30m,
        },
    )
    assert wo_grace.status_code == 201
    grace_id = wo_grace.json()["id"]

    wo_default = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Default escalated",
            "description": "should escalate",
            "site": "No Grace Site",
            "location": "B5",
            "priority": "high",
            "due_at": due_30m,
        },
    )
    assert wo_default.status_code == 201
    default_id = wo_default.json()["id"]

    run = app_client.post(
        "/api/work-orders/escalations/run",
        headers=_owner_headers(),
        json={"dry_run": False, "limit": 100},
    )
    assert run.status_code == 200
    escalated_ids = set(run.json()["work_order_ids"])
    assert default_id in escalated_ids
    assert grace_id not in escalated_ids


def test_monthly_report_exports(app_client: TestClient) -> None:
    month = datetime.now(timezone.utc).strftime("%Y-%m")

    csv_resp = app_client.get(
        f"/api/reports/monthly/csv?month={month}",
        headers=_owner_headers(),
    )
    assert csv_resp.status_code == 200
    assert csv_resp.headers["content-type"].startswith("text/csv")

    pdf_resp = app_client.get(
        f"/api/reports/monthly/pdf?month={month}",
        headers=_owner_headers(),
    )
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"].startswith("application/pdf")


def test_ops_dashboard_summary(app_client: TestClient) -> None:
    inspected_at = datetime.now(timezone.utc).isoformat()
    inspection = app_client.post(
        "/api/inspections",
        headers=_owner_headers(),
        json={
            "site": "Ops Site",
            "location": "B3",
            "cycle": "monthly",
            "inspector": "CI Bot",
            "inspected_at": inspected_at,
        },
    )
    assert inspection.status_code == 201

    due_at = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    work_order = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Dashboard work order",
            "description": "for summary",
            "site": "Ops Site",
            "location": "B3",
            "priority": "high",
            "due_at": due_at,
        },
    )
    assert work_order.status_code == 201

    run = app_client.post(
        "/api/work-orders/escalations/run",
        headers=_owner_headers(),
        json={"dry_run": False, "site": "Ops Site", "limit": 50},
    )
    assert run.status_code == 200

    summary = app_client.get(
        "/api/ops/dashboard/summary?site=Ops+Site&days=30&job_limit=10",
        headers=_owner_headers(),
    )
    assert summary.status_code == 200
    body = summary.json()
    assert body["site"] == "Ops Site"
    assert body["inspections_total"] >= 1
    assert body["work_orders_total"] >= 1
    assert "inspection_risk_counts" in body
    assert "work_order_status_counts" in body
    assert "recent_job_runs" in body
    assert body["sla_recent_runs"] >= 1
