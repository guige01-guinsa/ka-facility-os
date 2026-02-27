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


def test_public_main_and_adoption_plan_endpoints(app_client: TestClient) -> None:
    root_json = app_client.get("/")
    assert root_json.status_code == 200
    assert root_json.json()["service"] == "ka-facility-os"
    assert "public_adoption_plan_api" in root_json.json()
    assert "public_adoption_campaign_api" in root_json.json()
    assert "public_modules_api" in root_json.json()
    assert root_json.json()["adoption_portal_html"] == "/web/adoption"
    assert root_json.json()["facility_console_html"] == "/web/console"
    assert "public_post_mvp_plan_api" in root_json.json()
    assert "public_post_mvp_backlog_csv_api" in root_json.json()

    root_html = app_client.get("/", headers={"Accept": "text/html"})
    assert root_html.status_code == 200
    assert root_html.headers["content-type"].startswith("text/html")
    assert "시설관리시스템 메인" in root_html.text
    assert "운영요약" in root_html.text
    assert "작업지시" in root_html.text
    assert "점검" in root_html.text
    assert "월간리포트" in root_html.text
    assert "사용자 정착 계획" in root_html.text
    assert "X-Admin-Token 입력" in root_html.text
    assert "요약 새로고침" in root_html.text

    root_html_adoption_tab = app_client.get("/?tab=adoption", headers={"Accept": "text/html"})
    assert root_html_adoption_tab.status_code == 200
    assert "사용자 정착 계획" in root_html_adoption_tab.text

    service_info = app_client.get("/api/service-info")
    assert service_info.status_code == 200
    assert service_info.json()["service"] == "ka-facility-os"
    assert "public_modules_api" in service_info.json()
    assert service_info.json()["adoption_portal_html"] == "/web/adoption"
    assert service_info.json()["facility_console_html"] == "/web/console"
    assert "public_post_mvp_release_ics_api" in service_info.json()

    console_html = app_client.get("/web/console")
    assert console_html.status_code == 200
    assert console_html.headers["content-type"].startswith("text/html")
    assert "KA Facility OS 시설관리 운영 콘솔" in console_html.text
    assert "X-Admin-Token" in console_html.text
    assert "Result Viewer" in console_html.text

    adoption_html = app_client.get("/web/adoption")
    assert adoption_html.status_code == 200
    assert adoption_html.headers["content-type"].startswith("text/html")
    assert "KA Facility OS" in adoption_html.text
    assert "User Adoption Plan" in adoption_html.text
    assert "Promotion + Education + Fun Kit" in adoption_html.text
    assert "Facility Web Modules" in adoption_html.text
    assert "Operations Console HTML" in adoption_html.text
    assert "요약 모드 (핵심 5줄): OFF" in adoption_html.text
    assert "핵심 5줄 요약" in adoption_html.text
    assert "Post-MVP Execution Pack" in adoption_html.text

    modules = app_client.get("/api/public/modules")
    assert modules.status_code == 200
    modules_body = modules.json()
    assert modules_body["public"] is True
    assert modules_body["main_page"] == "/"
    assert modules_body["console_html"] == "/web/console"
    assert len(modules_body["modules"]) >= 7

    modules_html = app_client.get("/api/public/modules", headers={"Accept": "text/html"})
    assert modules_html.status_code == 200
    assert modules_html.headers["content-type"].startswith("text/html")
    assert "Facility Web Modules" in modules_html.text
    assert "Operations Console" in modules_html.text

    public_plan = app_client.get("/api/public/adoption-plan")
    assert public_plan.status_code == 200
    body = public_plan.json()
    assert body["public"] is True
    assert body["timeline"]["start_date"] == "2026-03-02"
    assert body["timeline"]["end_date"] == "2026-05-22"
    assert len(body["weekly_execution"]) == 12
    assert len(body["training_outline"]) >= 8
    assert len(body["kpi_dashboard_items"]) >= 8
    assert "campaign_kit" in body
    assert len(body["campaign_kit"]["promotion"]) >= 3
    assert len(body["campaign_kit"]["education"]) >= 3
    assert len(body["campaign_kit"]["fun"]) >= 3

    campaign_api = app_client.get("/api/public/adoption-plan/campaign")
    assert campaign_api.status_code == 200
    campaign_body = campaign_api.json()
    assert campaign_body["public"] is True
    assert len(campaign_body["campaign_kit"]["promotion"]) >= 3

    schedule_csv = app_client.get("/api/public/adoption-plan/schedule.csv")
    assert schedule_csv.status_code == 200
    assert schedule_csv.headers["content-type"].startswith("text/csv")
    assert "week,start_date,end_date,phase,focus,owner" in schedule_csv.text

    schedule_ics = app_client.get("/api/public/adoption-plan/schedule.ics")
    assert schedule_ics.status_code == 200
    assert schedule_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in schedule_ics.text
    assert "SUMMARY:[W01] Kickoff - Role workflow lock" in schedule_ics.text

    post_mvp = app_client.get("/api/public/post-mvp")
    assert post_mvp.status_code == 200
    post_body = post_mvp.json()
    assert post_body["public"] is True
    assert post_body["timeline"]["start_date"] == "2026-05-25"
    assert post_body["timeline"]["end_date"] == "2026-11-27"
    assert len(post_body["roadmap"]) >= 4
    assert len(post_body["execution_backlog"]) >= 10

    post_backlog_csv = app_client.get("/api/public/post-mvp/backlog.csv")
    assert post_backlog_csv.status_code == 200
    assert post_backlog_csv.headers["content-type"].startswith("text/csv")
    assert "id,epic,item,priority,owner,estimate_points,target_release,status,success_kpi" in post_backlog_csv.text
    assert "PMVP-01" in post_backlog_csv.text

    post_release_ics = app_client.get("/api/public/post-mvp/releases.ics")
    assert post_release_ics.status_code == 200
    assert post_release_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in post_release_ics.text
    assert "SUMMARY:[Post-MVP] R1 - Operations Stability" in post_release_ics.text

    post_kpis = app_client.get("/api/public/post-mvp/kpi-dashboard")
    assert post_kpis.status_code == 200
    assert len(post_kpis.json()["kpi_dashboard_spec"]) >= 8

    post_risks = app_client.get("/api/public/post-mvp/risks")
    assert post_risks.status_code == 200
    assert len(post_risks.json()["risk_register"]) >= 8

    post_mvp_html = app_client.get("/api/public/post-mvp", headers={"Accept": "text/html"})
    assert post_mvp_html.status_code == 200
    assert post_mvp_html.headers["content-type"].startswith("text/html")
    assert "API Browser View" in post_mvp_html.text
    assert "Raw JSON" in post_mvp_html.text

    post_mvp_raw = app_client.get("/api/public/post-mvp?raw=1", headers={"Accept": "text/html"})
    assert post_mvp_raw.status_code == 200
    assert post_mvp_raw.headers["content-type"].startswith("application/json")
    assert post_mvp_raw.json()["public"] is True


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


def test_work_order_workflow_transitions_and_events(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Workflow test",
            "description": "initial",
            "site": "Workflow Site",
            "location": "B7",
            "priority": "medium",
        },
    )
    assert created.status_code == 201
    work_order_id = created.json()["id"]
    assert created.json()["status"] == "open"

    comment = app_client.post(
        f"/api/work-orders/{work_order_id}/comments",
        headers=_owner_headers(),
        json={"comment": "Needs vendor coordination"},
    )
    assert comment.status_code == 201
    assert comment.json()["event_type"] == "comment"

    ack = app_client.patch(
        f"/api/work-orders/{work_order_id}/ack",
        headers=_owner_headers(),
        json={"assignee": "Ops Team"},
    )
    assert ack.status_code == 200
    assert ack.json()["status"] == "acked"

    cancel = app_client.patch(
        f"/api/work-orders/{work_order_id}/cancel",
        headers=_owner_headers(),
        json={"reason": "Duplicate request"},
    )
    assert cancel.status_code == 200
    assert cancel.json()["status"] == "canceled"

    invalid_complete = app_client.patch(
        f"/api/work-orders/{work_order_id}/complete",
        headers=_owner_headers(),
        json={"resolution_notes": "Should fail from canceled"},
    )
    assert invalid_complete.status_code == 409

    reopen = app_client.patch(
        f"/api/work-orders/{work_order_id}/reopen",
        headers=_owner_headers(),
        json={"reason": "Not duplicate after review"},
    )
    assert reopen.status_code == 200
    assert reopen.json()["status"] == "open"

    complete = app_client.patch(
        f"/api/work-orders/{work_order_id}/complete",
        headers=_owner_headers(),
        json={"resolution_notes": "Resolved after reopen"},
    )
    assert complete.status_code == 200
    assert complete.json()["status"] == "completed"

    events = app_client.get(
        f"/api/work-orders/{work_order_id}/events",
        headers=_owner_headers(),
    )
    assert events.status_code == 200
    body = events.json()
    assert len(body) >= 6
    event_types = [row["event_type"] for row in body]
    assert "created" in event_types
    assert "comment" in event_types
    status_changes = [row for row in body if row["event_type"] == "status_changed"]
    assert any(row["from_status"] == "open" and row["to_status"] == "acked" for row in status_changes)
    assert any(row["from_status"] == "acked" and row["to_status"] == "canceled" for row in status_changes)
    assert any(row["from_status"] == "canceled" and row["to_status"] == "open" for row in status_changes)
    assert any(row["from_status"] == "open" and row["to_status"] == "completed" for row in status_changes)


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


def test_ops_dashboard_trends(app_client: TestClient) -> None:
    inspected_at = datetime.now(timezone.utc).isoformat()
    inspection = app_client.post(
        "/api/inspections",
        headers=_owner_headers(),
        json={
            "site": "Trend Site",
            "location": "B8",
            "cycle": "monthly",
            "inspector": "Trend Bot",
            "inspected_at": inspected_at,
        },
    )
    assert inspection.status_code == 201

    work_order = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Trend work order",
            "description": "for trends",
            "site": "Trend Site",
            "location": "B8",
            "priority": "high",
        },
    )
    assert work_order.status_code == 201
    work_order_id = work_order.json()["id"]

    completed = app_client.patch(
        f"/api/work-orders/{work_order_id}/complete",
        headers=_owner_headers(),
        json={"resolution_notes": "done"},
    )
    assert completed.status_code == 200

    trends = app_client.get(
        "/api/ops/dashboard/trends?site=Trend+Site&days=7",
        headers=_owner_headers(),
    )
    assert trends.status_code == 200
    body = trends.json()
    assert body["site"] == "Trend Site"
    assert body["window_days"] == 7
    assert len(body["points"]) == 7
    assert sum(point["inspections_count"] for point in body["points"]) >= 1
    assert sum(point["work_orders_created_count"] for point in body["points"]) >= 1
    assert sum(point["work_orders_completed_count"] for point in body["points"]) >= 1


def test_ops_handover_brief_prioritization(app_client: TestClient) -> None:
    now = datetime.now(timezone.utc)

    inspection = app_client.post(
        "/api/inspections",
        headers=_owner_headers(),
        json={
            "site": "Handover Site",
            "location": "B2",
            "cycle": "monthly",
            "inspector": "Handover Bot",
            "inspected_at": now.isoformat(),
            "grounding_ohm": 30.0,
            "insulation_mohm": 0.1,
        },
    )
    assert inspection.status_code == 201
    assert inspection.json()["risk_level"] in {"warning", "danger"}

    overdue = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Critical overdue issue",
            "description": "handover priority",
            "site": "Handover Site",
            "location": "B2",
            "priority": "critical",
            "due_at": (now - timedelta(hours=2)).isoformat(),
        },
    )
    assert overdue.status_code == 201
    overdue_id = overdue.json()["id"]

    due_soon = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Due soon issue",
            "description": "needs prep",
            "site": "Handover Site",
            "location": "B2",
            "priority": "high",
            "assignee": "Ops Team",
            "due_at": (now + timedelta(minutes=45)).isoformat(),
        },
    )
    assert due_soon.status_code == 201

    normal = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Normal backlog",
            "description": "low risk",
            "site": "Handover Site",
            "location": "B3",
            "priority": "low",
        },
    )
    assert normal.status_code == 201

    run = app_client.post(
        "/api/work-orders/escalations/run",
        headers=_owner_headers(),
        json={"site": "Handover Site", "dry_run": False, "limit": 50},
    )
    assert run.status_code == 200

    brief = app_client.get(
        "/api/ops/handover/brief?site=Handover+Site&window_hours=24&due_soon_hours=2&max_items=5",
        headers=_owner_headers(),
    )
    assert brief.status_code == 200
    body = brief.json()
    assert body["site"] == "Handover Site"
    assert body["open_work_orders"] >= 3
    assert body["overdue_open_work_orders"] >= 1
    assert body["due_soon_work_orders"] >= 1
    assert body["high_risk_inspections_in_window"] >= 1
    assert len(body["top_work_orders"]) >= 1
    assert body["top_work_orders"][0]["id"] == overdue_id
    assert any("overdue" in action.lower() for action in body["recommended_actions"])


def test_ops_handover_brief_respects_site_scope(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "handover_scope_ci",
            "display_name": "Handover Scope CI",
            "role": "owner",
            "permissions": [],
            "site_scope": ["Scope Handover"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "handover-scope-token"},
    )
    assert issued.status_code == 201
    scoped_headers = {"X-Admin-Token": issued.json()["token"]}

    in_scope = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Scope visible",
            "description": "visible in scope",
            "site": "Scope Handover",
            "location": "B1",
            "priority": "high",
        },
    )
    assert in_scope.status_code == 201

    out_scope = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Scope hidden",
            "description": "hidden by scope",
            "site": "Outside Handover",
            "location": "B1",
            "priority": "high",
        },
    )
    assert out_scope.status_code == 201

    brief = app_client.get(
        "/api/ops/handover/brief?window_hours=24&due_soon_hours=6&max_items=10",
        headers=scoped_headers,
    )
    assert brief.status_code == 200
    body = brief.json()
    assert body["open_work_orders"] == 1
    assert all(item["site"] == "Scope Handover" for item in body["top_work_orders"])

    forbidden = app_client.get(
        "/api/ops/handover/brief?site=Outside+Handover",
        headers=scoped_headers,
    )
    assert forbidden.status_code == 403


def test_ops_handover_brief_exports(app_client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    seeded = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Export target",
            "description": "for handover export",
            "site": "Export Site",
            "location": "B5",
            "priority": "high",
            "due_at": (now + timedelta(hours=1)).isoformat(),
        },
    )
    assert seeded.status_code == 201

    csv_resp = app_client.get(
        "/api/ops/handover/brief/csv?site=Export+Site&window_hours=24&due_soon_hours=4&max_items=10",
        headers=_owner_headers(),
    )
    assert csv_resp.status_code == 200
    assert csv_resp.headers["content-type"].startswith("text/csv")
    assert "handover-brief-export_site" in csv_resp.headers.get("content-disposition", "").lower()
    assert "open_work_orders" in csv_resp.text

    pdf_resp = app_client.get(
        "/api/ops/handover/brief/pdf?site=Export+Site&window_hours=24&due_soon_hours=4&max_items=10",
        headers=_owner_headers(),
    )
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"].startswith("application/pdf")

    csv_logs = app_client.get(
        "/api/admin/audit-logs?action=report_handover_export_csv",
        headers=_owner_headers(),
    )
    assert csv_logs.status_code == 200
    assert len(csv_logs.json()) >= 1

    pdf_logs = app_client.get(
        "/api/admin/audit-logs?action=report_handover_export_pdf",
        headers=_owner_headers(),
    )
    assert pdf_logs.status_code == 200
    assert len(pdf_logs.json()) >= 1


def test_alert_delivery_list_and_retry(app_client: TestClient) -> None:
    import app.database as db_module
    from sqlalchemy import insert

    now = datetime.now(timezone.utc)
    with db_module.get_conn() as conn:
        result = conn.execute(
            insert(db_module.alert_deliveries).values(
                event_type="sla_escalation",
                target="http://127.0.0.1:1/hook",
                status="failed",
                error="seeded failure",
                payload_json="{}",
                attempt_count=1,
                last_attempt_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        delivery_id = int(result.inserted_primary_key[0])

    listed = app_client.get(
        "/api/ops/alerts/deliveries?status=failed",
        headers=_owner_headers(),
    )
    assert listed.status_code == 200
    ids = [row["id"] for row in listed.json()]
    assert delivery_id in ids

    retried = app_client.post(
        f"/api/ops/alerts/deliveries/{delivery_id}/retry",
        headers=_owner_headers(),
    )
    assert retried.status_code == 200
    body = retried.json()
    assert body["id"] == delivery_id
    assert body["attempt_count"] == 2
    assert body["status"] in {"success", "warning", "failed"}


def test_sla_simulator_what_if(app_client: TestClient) -> None:
    set_default = app_client.put(
        "/api/admin/policies/sla",
        headers=_owner_headers(),
        json={
            "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
            "escalation_grace_minutes": 0,
        },
    )
    assert set_default.status_code == 200

    due_old = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    wo = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Simulator target",
            "description": "simulate grace increase",
            "site": "Sim Site",
            "location": "B9",
            "priority": "high",
            "due_at": due_old,
        },
    )
    assert wo.status_code == 201

    simulated = app_client.post(
        "/api/ops/sla/simulate",
        headers=_owner_headers(),
        json={
            "site": "Sim Site",
            "policy": {
                "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
                "escalation_grace_minutes": 60,
            },
            "limit": 500,
            "include_work_order_ids": True,
            "sample_size": 50,
            "recompute_due_from_policy": False,
        },
    )
    assert simulated.status_code == 200
    body = simulated.json()
    assert body["site"] == "Sim Site"
    assert body["baseline_escalate_count"] >= 1
    assert body["simulated_escalate_count"] == 0
    assert body["delta_escalate_count"] <= 0
    assert len(body["no_longer_escalated_ids"]) >= 1


def test_sla_policy_proposal_approval_flow(app_client: TestClient) -> None:
    due_old = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    wo = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Proposal target",
            "description": "proposal approval flow",
            "site": "Approval Site",
            "location": "B10",
            "priority": "high",
            "due_at": due_old,
        },
    )
    assert wo.status_code == 201

    created = app_client.post(
        "/api/admin/policies/sla/proposals",
        headers=_owner_headers(),
        json={
            "site": "Approval Site",
            "policy": {
                "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
                "escalation_grace_minutes": 60,
            },
            "note": "Increase grace for maintenance window",
            "simulation_limit": 500,
            "sample_size": 50,
            "include_work_order_ids": True,
            "recompute_due_from_policy": False,
        },
    )
    assert created.status_code == 201
    proposal = created.json()
    proposal_id = proposal["id"]
    assert proposal["status"] == "pending"
    assert proposal["site"] == "Approval Site"
    assert proposal["simulation"]["baseline_escalate_count"] >= 1
    assert proposal["simulation"]["simulated_escalate_count"] == 0

    listed = app_client.get(
        "/api/admin/policies/sla/proposals?status=pending&site=Approval+Site",
        headers=_owner_headers(),
    )
    assert listed.status_code == 200
    ids = [row["id"] for row in listed.json()]
    assert proposal_id in ids

    approver_user = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "proposal_approver_ci",
            "display_name": "Proposal Approver CI",
            "role": "owner",
            "permissions": [],
            "site_scope": ["*"],
        },
    )
    assert approver_user.status_code == 201
    approver_user_id = approver_user.json()["id"]
    approver_token_issue = app_client.post(
        f"/api/admin/users/{approver_user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "proposal-approver"},
    )
    assert approver_token_issue.status_code == 201
    approver_headers = {"X-Admin-Token": approver_token_issue.json()["token"]}

    self_approve = app_client.post(
        f"/api/admin/policies/sla/proposals/{proposal_id}/approve",
        headers=_owner_headers(),
        json={"note": "self approve should fail"},
    )
    assert self_approve.status_code == 409

    approved = app_client.post(
        f"/api/admin/policies/sla/proposals/{proposal_id}/approve",
        headers=approver_headers,
        json={"note": "Approved for next sprint"},
    )
    assert approved.status_code == 200
    approved_body = approved.json()
    assert approved_body["status"] == "approved"
    assert approved_body["applied_at"] is not None

    policy_after = app_client.get(
        "/api/admin/policies/sla?site=Approval+Site",
        headers=_owner_headers(),
    )
    assert policy_after.status_code == 200
    assert policy_after.json()["escalation_grace_minutes"] == 60

    approve_again = app_client.post(
        f"/api/admin/policies/sla/proposals/{proposal_id}/approve",
        headers=approver_headers,
        json={"note": "should fail"},
    )
    assert approve_again.status_code == 409

    created2 = app_client.post(
        "/api/admin/policies/sla/proposals",
        headers=_owner_headers(),
        json={
            "site": "Approval Site",
            "policy": {
                "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
                "escalation_grace_minutes": 15,
            },
            "note": "Alternative proposal",
        },
    )
    assert created2.status_code == 201
    proposal2_id = created2.json()["id"]

    rejected = app_client.post(
        f"/api/admin/policies/sla/proposals/{proposal2_id}/reject",
        headers=approver_headers,
        json={"note": "Not needed"},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"


def test_site_scoped_admin_cannot_create_global_sla_proposal(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "proposal_scope_ci",
            "display_name": "Proposal Scope CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["Scoped Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "proposal-scope-token"},
    )
    assert issued.status_code == 201
    scoped_headers = {"X-Admin-Token": issued.json()["token"]}

    forbidden_global = app_client.post(
        "/api/admin/policies/sla/proposals",
        headers=scoped_headers,
        json={
            "policy": {
                "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
                "escalation_grace_minutes": 5,
            },
            "note": "global proposal should be blocked",
        },
    )
    assert forbidden_global.status_code == 403


def test_sla_policy_revisions_and_restore(app_client: TestClient) -> None:
    set_v1 = app_client.put(
        "/api/admin/policies/sla?site=Revision+Site",
        headers=_owner_headers(),
        json={
            "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
            "escalation_grace_minutes": 5,
        },
    )
    assert set_v1.status_code == 200

    set_v2 = app_client.put(
        "/api/admin/policies/sla?site=Revision+Site",
        headers=_owner_headers(),
        json={
            "default_due_hours": {"low": 72, "medium": 24, "high": 8, "critical": 2},
            "escalation_grace_minutes": 45,
        },
    )
    assert set_v2.status_code == 200

    listed = app_client.get(
        "/api/admin/policies/sla/revisions?site=Revision+Site&limit=50",
        headers=_owner_headers(),
    )
    assert listed.status_code == 200
    rows = listed.json()
    assert len(rows) >= 2

    revision_v1 = None
    for row in rows:
        if row["policy"]["escalation_grace_minutes"] == 5:
            revision_v1 = row
            break
    assert revision_v1 is not None

    restored = app_client.post(
        f"/api/admin/policies/sla/revisions/{revision_v1['id']}/restore",
        headers=_owner_headers(),
        json={"note": "rollback for test"},
    )
    assert restored.status_code == 200
    assert restored.json()["escalation_grace_minutes"] == 5

    policy_after = app_client.get(
        "/api/admin/policies/sla?site=Revision+Site",
        headers=_owner_headers(),
    )
    assert policy_after.status_code == 200
    assert policy_after.json()["escalation_grace_minutes"] == 5

    restore_rows = app_client.get(
        "/api/admin/policies/sla/revisions?site=Revision+Site&source_action=revision_restore&limit=20",
        headers=_owner_headers(),
    )
    assert restore_rows.status_code == 200
    assert len(restore_rows.json()) >= 1


def test_alert_retry_batch_api(app_client: TestClient) -> None:
    import app.database as db_module
    from sqlalchemy import insert

    now = datetime.now(timezone.utc) - timedelta(minutes=5)
    with db_module.get_conn() as conn:
        result = conn.execute(
            insert(db_module.alert_deliveries).values(
                event_type="sla_escalation",
                target="http://127.0.0.1:1/hook",
                status="failed",
                error="seeded failure",
                payload_json="{}",
                attempt_count=1,
                last_attempt_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        delivery_id = int(result.inserted_primary_key[0])

    batch = app_client.post(
        "/api/ops/alerts/retries/run",
        headers=_owner_headers(),
        json={
            "event_type": "sla_escalation",
            "only_status": ["failed"],
            "limit": 50,
            "max_attempt_count": 10,
            "min_last_attempt_age_sec": 0,
        },
    )
    assert batch.status_code == 200
    body = batch.json()
    assert body["processed_count"] >= 1
    assert delivery_id in body["delivery_ids"]

    refreshed = app_client.get(
        "/api/ops/alerts/deliveries",
        headers=_owner_headers(),
    )
    assert refreshed.status_code == 200
    rows = refreshed.json()
    target = next((row for row in rows if row["id"] == delivery_id), None)
    assert target is not None
    assert target["attempt_count"] == 2
