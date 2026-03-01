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
    evidence_path = tmp_path / "evidence"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("ENV", "test")
    monkeypatch.setenv("ALLOW_INSECURE_LOCAL_AUTH", "0")
    monkeypatch.setenv("ADMIN_TOKEN", "test-owner-token")
    monkeypatch.setenv("API_RATE_LIMIT_ENABLED", "1")
    monkeypatch.setenv("API_RATE_LIMIT_WINDOW_SEC", "60")
    monkeypatch.setenv("API_RATE_LIMIT_MAX_PUBLIC", "10000")
    monkeypatch.setenv("API_RATE_LIMIT_MAX_AUTH", "10000")
    monkeypatch.setenv("API_RATE_LIMIT_MAX_AUTH_ADMIN", "10000")
    monkeypatch.setenv("API_RATE_LIMIT_MAX_AUTH_WRITE", "10000")
    monkeypatch.setenv("API_RATE_LIMIT_STORE", "memory")
    monkeypatch.setenv("ADMIN_TOKEN_REQUIRE_EXPIRY", "1")
    monkeypatch.setenv("ADMIN_TOKEN_MAX_TTL_DAYS", "30")
    monkeypatch.setenv("ADMIN_TOKEN_ROTATE_AFTER_DAYS", "45")
    monkeypatch.setenv("ADMIN_TOKEN_ROTATE_WARNING_DAYS", "7")
    monkeypatch.setenv("ADMIN_TOKEN_MAX_IDLE_DAYS", "30")
    monkeypatch.setenv("ADMIN_TOKEN_MAX_ACTIVE_PER_USER", "5")
    monkeypatch.setenv("EVIDENCE_STORAGE_BACKEND", "fs")
    monkeypatch.setenv("EVIDENCE_STORAGE_PATH", evidence_path.as_posix())
    monkeypatch.setenv("EVIDENCE_SCAN_MODE", "basic")
    monkeypatch.setenv("EVIDENCE_SCAN_BLOCK_SUSPICIOUS", "0")
    monkeypatch.setenv("AUDIT_ARCHIVE_SIGNING_KEY", "ci-signing-key")
    monkeypatch.delenv("ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("ALERT_WEBHOOK_URLS", raising=False)

    import app.database as database_module
    import app.main as main_module

    importlib.reload(database_module)
    importlib.reload(main_module)

    with TestClient(main_module.app) as client:
        yield client


@pytest.fixture()
def strict_rate_limit_client(tmp_path, monkeypatch):
    db_path = tmp_path / "test_rate_limit.db"
    evidence_path = tmp_path / "evidence_rate_limit"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("ENV", "test")
    monkeypatch.setenv("ALLOW_INSECURE_LOCAL_AUTH", "0")
    monkeypatch.setenv("ADMIN_TOKEN", "test-owner-token")
    monkeypatch.setenv("API_RATE_LIMIT_ENABLED", "1")
    monkeypatch.setenv("API_RATE_LIMIT_WINDOW_SEC", "60")
    monkeypatch.setenv("API_RATE_LIMIT_MAX_PUBLIC", "3")
    monkeypatch.setenv("API_RATE_LIMIT_MAX_AUTH", "3")
    monkeypatch.setenv("API_RATE_LIMIT_MAX_AUTH_ADMIN", "2")
    monkeypatch.setenv("API_RATE_LIMIT_MAX_AUTH_WRITE", "2")
    monkeypatch.setenv("API_RATE_LIMIT_STORE", "memory")
    monkeypatch.setenv("ADMIN_TOKEN_REQUIRE_EXPIRY", "1")
    monkeypatch.setenv("ADMIN_TOKEN_MAX_TTL_DAYS", "30")
    monkeypatch.setenv("ADMIN_TOKEN_ROTATE_AFTER_DAYS", "45")
    monkeypatch.setenv("ADMIN_TOKEN_ROTATE_WARNING_DAYS", "7")
    monkeypatch.setenv("ADMIN_TOKEN_MAX_IDLE_DAYS", "30")
    monkeypatch.setenv("ADMIN_TOKEN_MAX_ACTIVE_PER_USER", "5")
    monkeypatch.setenv("EVIDENCE_STORAGE_BACKEND", "fs")
    monkeypatch.setenv("EVIDENCE_STORAGE_PATH", evidence_path.as_posix())
    monkeypatch.setenv("EVIDENCE_SCAN_MODE", "basic")
    monkeypatch.setenv("EVIDENCE_SCAN_BLOCK_SUSPICIOUS", "0")
    monkeypatch.setenv("AUDIT_ARCHIVE_SIGNING_KEY", "ci-signing-key")
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


def test_api_rate_limit_enforced(strict_rate_limit_client: TestClient) -> None:
    first = strict_rate_limit_client.get("/api/public/adoption-plan?raw=1")
    second = strict_rate_limit_client.get("/api/public/adoption-plan?raw=1")
    third = strict_rate_limit_client.get("/api/public/adoption-plan?raw=1")
    fourth = strict_rate_limit_client.get("/api/public/adoption-plan?raw=1")

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 200
    assert fourth.status_code == 429
    assert fourth.json()["detail"] == "Rate limit exceeded"
    assert fourth.headers.get("retry-after") is not None
    assert fourth.headers.get("x-ratelimit-limit") == "3"
    assert fourth.headers.get("x-ratelimit-remaining") == "0"
    assert fourth.headers.get("x-ratelimit-backend") == "memory"


def test_api_rate_limit_admin_policy_enforced(strict_rate_limit_client: TestClient) -> None:
    headers = _owner_headers()
    first = strict_rate_limit_client.get("/api/admin/users?raw=1", headers=headers)
    second = strict_rate_limit_client.get("/api/admin/users?raw=1", headers=headers)
    third = strict_rate_limit_client.get("/api/admin/users?raw=1", headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429
    assert third.headers.get("x-ratelimit-policy") == "auth-admin"
    assert third.headers.get("x-ratelimit-limit") == "2"


def test_public_main_and_adoption_plan_endpoints(app_client: TestClient) -> None:
    root_json = app_client.get("/")
    assert root_json.status_code == 200
    assert root_json.json()["service"] == "ka-facility-os"
    assert "public_adoption_plan_api" in root_json.json()
    assert "public_adoption_campaign_api" in root_json.json()
    assert "public_adoption_w02_api" in root_json.json()
    assert "public_adoption_w05_api" in root_json.json()
    assert "adoption_w02_tracker_items_api" in root_json.json()
    assert "adoption_w03_tracker_items_api" in root_json.json()
    assert "adoption_w04_tracker_items_api" in root_json.json()
    assert "adoption_w05_consistency_api" in root_json.json()
    assert "public_modules_api" in root_json.json()
    assert root_json.json()["adoption_portal_html"] == "/web/adoption"
    assert root_json.json()["facility_console_html"] == "/web/console"
    assert "public_post_mvp_plan_api" in root_json.json()
    assert "public_post_mvp_backlog_csv_api" in root_json.json()

    root_html = app_client.get("/", headers={"Accept": "text/html"})
    assert root_html.status_code == 200
    assert root_html.headers["content-type"].startswith("text/html")
    assert root_html.headers.get("x-content-type-options") == "nosniff"
    assert root_html.headers.get("x-frame-options") == "DENY"
    assert "default-src 'self'" in root_html.headers.get("content-security-policy", "")
    assert "시설관리시스템 메인" in root_html.text
    assert "운영요약" in root_html.text
    assert "작업지시" in root_html.text
    assert "점검" in root_html.text
    assert "월간리포트" in root_html.text
    assert "사용자 정착 계획" in root_html.text
    assert "W01 Role Workflow Lock Matrix" in root_html.text
    assert "W02 Scheduled SOP and Sandbox" in root_html.text
    assert "W03 Go-live Onboarding" in root_html.text
    assert "W04 First Success Acceleration" in root_html.text
    assert "W05 Usage Consistency" in root_html.text
    assert "W03 실행 추적" in root_html.text
    assert "W04 실행 추적" in root_html.text
    assert "W05 지표 새로고침" in root_html.text
    assert "완료 판정" in root_html.text
    assert "W02 완료 확정" in root_html.text
    assert "W04 완료 확정" in root_html.text
    assert "알림 채널 KPI" in root_html.text
    assert "알림 채널 MTTR" in root_html.text
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
    assert service_info.json()["public_adoption_w02_api"] == "/api/public/adoption-plan/w02"
    assert service_info.json()["public_adoption_w02_checklist_csv_api"] == "/api/public/adoption-plan/w02/checklist.csv"
    assert service_info.json()["public_adoption_w02_schedule_ics_api"] == "/api/public/adoption-plan/w02/schedule.ics"
    assert service_info.json()["public_adoption_w02_sample_files_api"] == "/api/public/adoption-plan/w02/sample-files"
    assert service_info.json()["public_adoption_w03_api"] == "/api/public/adoption-plan/w03"
    assert service_info.json()["public_adoption_w03_checklist_csv_api"] == "/api/public/adoption-plan/w03/checklist.csv"
    assert service_info.json()["public_adoption_w03_schedule_ics_api"] == "/api/public/adoption-plan/w03/schedule.ics"
    assert service_info.json()["public_adoption_w04_api"] == "/api/public/adoption-plan/w04"
    assert service_info.json()["public_adoption_w04_checklist_csv_api"] == "/api/public/adoption-plan/w04/checklist.csv"
    assert service_info.json()["public_adoption_w04_schedule_ics_api"] == "/api/public/adoption-plan/w04/schedule.ics"
    assert service_info.json()["public_adoption_w04_common_mistakes_api"] == "/api/public/adoption-plan/w04/common-mistakes"
    assert service_info.json()["public_adoption_w04_common_mistakes_html"] == "/web/adoption/w04/common-mistakes"
    assert service_info.json()["public_adoption_w05_api"] == "/api/public/adoption-plan/w05"
    assert service_info.json()["public_adoption_w05_missions_csv_api"] == "/api/public/adoption-plan/w05/missions.csv"
    assert service_info.json()["public_adoption_w05_schedule_ics_api"] == "/api/public/adoption-plan/w05/schedule.ics"
    assert service_info.json()["public_adoption_w05_help_docs_api"] == "/api/public/adoption-plan/w05/help-docs"
    assert service_info.json()["adoption_w02_tracker_items_api"] == "/api/adoption/w02/tracker/items"
    assert service_info.json()["adoption_w02_tracker_overview_api"] == "/api/adoption/w02/tracker/overview"
    assert service_info.json()["adoption_w02_tracker_readiness_api"] == "/api/adoption/w02/tracker/readiness"
    assert service_info.json()["adoption_w02_tracker_completion_api"] == "/api/adoption/w02/tracker/completion"
    assert service_info.json()["adoption_w02_tracker_complete_api"] == "/api/adoption/w02/tracker/complete"
    assert service_info.json()["adoption_w03_tracker_items_api"] == "/api/adoption/w03/tracker/items"
    assert service_info.json()["adoption_w03_tracker_overview_api"] == "/api/adoption/w03/tracker/overview"
    assert service_info.json()["adoption_w03_tracker_readiness_api"] == "/api/adoption/w03/tracker/readiness"
    assert service_info.json()["adoption_w03_tracker_completion_api"] == "/api/adoption/w03/tracker/completion"
    assert service_info.json()["adoption_w03_tracker_complete_api"] == "/api/adoption/w03/tracker/complete"
    assert service_info.json()["adoption_w04_funnel_api"] == "/api/ops/adoption/w04/funnel"
    assert service_info.json()["adoption_w04_blockers_api"] == "/api/ops/adoption/w04/blockers"
    assert service_info.json()["adoption_w04_tracker_items_api"] == "/api/adoption/w04/tracker/items"
    assert service_info.json()["adoption_w04_tracker_overview_api"] == "/api/adoption/w04/tracker/overview"
    assert service_info.json()["adoption_w04_tracker_readiness_api"] == "/api/adoption/w04/tracker/readiness"
    assert service_info.json()["adoption_w04_tracker_completion_api"] == "/api/adoption/w04/tracker/completion"
    assert service_info.json()["adoption_w04_tracker_complete_api"] == "/api/adoption/w04/tracker/complete"
    assert service_info.json()["adoption_w05_consistency_api"] == "/api/ops/adoption/w05/consistency"
    assert service_info.json()["admin_audit_integrity_api"] == "/api/admin/audit-integrity"
    assert service_info.json()["admin_audit_rebaseline_api"] == "/api/admin/audit-chain/rebaseline"
    assert service_info.json()["admin_token_rotate_api"] == "/api/admin/tokens/{token_id}/rotate"
    assert service_info.json()["ops_runbook_checks_api"] == "/api/ops/runbook/checks"
    assert service_info.json()["ops_runbook_checks_run_api"] == "/api/ops/runbook/checks/run"
    assert service_info.json()["ops_runbook_checks_latest_api"] == "/api/ops/runbook/checks/latest"
    assert service_info.json()["ops_security_posture_api"] == "/api/ops/security/posture"
    assert service_info.json()["alert_channel_kpi_api"] == "/api/ops/alerts/kpi/channels"
    assert service_info.json()["alert_channel_mttr_kpi_api"] == "/api/ops/alerts/kpi/mttr"
    assert service_info.json()["alert_mttr_slo_policy_api"] == "/api/ops/alerts/mttr-slo/policy"
    assert service_info.json()["alert_mttr_slo_run_api"] == "/api/ops/alerts/mttr-slo/check/run"
    assert service_info.json()["alert_mttr_slo_latest_api"] == "/api/ops/alerts/mttr-slo/check/latest"
    assert service_info.json()["alert_channel_guard_api"] == "/api/ops/alerts/channels/guard"
    assert service_info.json()["alert_channel_guard_recover_api"] == "/api/ops/alerts/channels/guard/recover"
    assert service_info.json()["alert_channel_guard_recover_batch_api"] == "/api/ops/alerts/channels/guard/recover-batch"
    assert service_info.json()["alert_channel_guard_recover_latest_api"] == "/api/ops/alerts/channels/guard/recover/latest"
    assert service_info.json()["alert_retention_policy_api"] == "/api/ops/alerts/retention/policy"
    assert service_info.json()["alert_retention_latest_api"] == "/api/ops/alerts/retention/latest"
    assert service_info.json()["alert_retention_run_api"] == "/api/ops/alerts/retention/run"

    console_html = app_client.get("/web/console")
    assert console_html.status_code == 200
    assert console_html.headers["content-type"].startswith("text/html")
    assert "KA Facility OS 시설관리 운영 콘솔" in console_html.text
    assert "X-Admin-Token" in console_html.text
    assert "Result Viewer" in console_html.text
    assert "알림 채널 KPI (7/30일)" in console_html.text
    assert "알림 데이터 보관정책" in console_html.text

    adoption_html = app_client.get("/web/adoption")
    assert adoption_html.status_code == 200
    assert adoption_html.headers["content-type"].startswith("text/html")
    assert "KA Facility OS" in adoption_html.text
    assert "User Adoption Plan" in adoption_html.text
    assert "Promotion + Education + Fun Kit" in adoption_html.text
    assert "W02 Scheduled SOP and Sandbox" in adoption_html.text
    assert "W03 Go-live Onboarding" in adoption_html.text
    assert "W04 First Success Acceleration" in adoption_html.text
    assert "W05 Usage Consistency" in adoption_html.text
    assert "W02 Sample Files" in adoption_html.text
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
    assert body["workflow_lock_matrix"]["states"] == ["DRAFT", "REVIEW", "APPROVED", "LOCKED"]
    assert len(body["workflow_lock_matrix"]["rows"]) == 4
    assert body["w02_sop_sandbox"]["timeline"]["week"] == 2
    assert len(body["w02_sop_sandbox"]["sop_runbooks"]) >= 5
    assert len(body["w02_sop_sandbox"]["sandbox_scenarios"]) >= 3
    assert len(body["w02_sop_sandbox"]["scheduled_events"]) >= 5
    assert body["w03_go_live_onboarding"]["timeline"]["week"] == 3
    assert len(body["w03_go_live_onboarding"]["kickoff_agenda"]) >= 5
    assert len(body["w03_go_live_onboarding"]["role_workshops"]) >= 4
    assert len(body["w03_go_live_onboarding"]["office_hours"]) >= 5
    assert len(body["w03_go_live_onboarding"]["scheduled_events"]) >= 8
    assert body["w04_first_success_acceleration"]["timeline"]["week"] == 4
    assert len(body["w04_first_success_acceleration"]["coaching_actions"]) >= 6
    assert len(body["w04_first_success_acceleration"]["scheduled_events"]) >= 6
    assert body["w04_first_success_acceleration"]["common_mistakes_reference"] == "/api/public/adoption-plan/w04/common-mistakes"
    assert body["w05_usage_consistency"]["timeline"]["week"] == 5
    assert len(body["w05_usage_consistency"]["role_missions"]) >= 5
    assert len(body["w05_usage_consistency"]["scheduled_events"]) >= 5
    assert len(body["w05_usage_consistency"]["help_docs"]) >= 3
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

    w02 = app_client.get("/api/public/adoption-plan/w02")
    assert w02.status_code == 200
    w02_body = w02.json()
    assert w02_body["public"] is True
    assert w02_body["timeline"]["focus"] == "SOP and sandbox"
    assert len(w02_body["sop_runbooks"]) >= 5
    assert len(w02_body["sandbox_scenarios"]) >= 3
    assert len(w02_body["scheduled_events"]) >= 5

    w02_csv = app_client.get("/api/public/adoption-plan/w02/checklist.csv")
    assert w02_csv.status_code == 200
    assert w02_csv.headers["content-type"].startswith("text/csv")
    assert "section,id,name,owner,target_or_module,trigger_or_objective,checkpoints_or_pass_criteria,duration_min,definition_of_done_or_output" in w02_csv.text
    assert "sop_runbook,SOP-INS-01" in w02_csv.text

    w02_ics = app_client.get("/api/public/adoption-plan/w02/schedule.ics")
    assert w02_ics.status_code == 200
    assert w02_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in w02_ics.text
    assert "SUMMARY:[W02] Kickoff - SOP owner assignment" in w02_ics.text

    w03 = app_client.get("/api/public/adoption-plan/w03")
    assert w03.status_code == 200
    w03_body = w03.json()
    assert w03_body["public"] is True
    assert w03_body["timeline"]["focus"] == "Go-live onboarding"
    assert len(w03_body["kickoff_agenda"]) >= 5
    assert len(w03_body["role_workshops"]) >= 4
    assert len(w03_body["office_hours"]) >= 5
    assert len(w03_body["scheduled_events"]) >= 8

    w03_csv = app_client.get("/api/public/adoption-plan/w03/checklist.csv")
    assert w03_csv.status_code == 200
    assert w03_csv.headers["content-type"].startswith("text/csv")
    assert "section,id,name_or_role,owner_or_trainer,schedule,objective_or_focus,checklist_or_channel,duration_min,expected_output_or_success" in w03_csv.text
    assert "kickoff_agenda,KICKOFF-01" in w03_csv.text

    w03_ics = app_client.get("/api/public/adoption-plan/w03/schedule.ics")
    assert w03_ics.status_code == 200
    assert w03_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in w03_ics.text
    assert "SUMMARY:[W03] Kickoff session (60m)" in w03_ics.text

    w04 = app_client.get("/api/public/adoption-plan/w04")
    assert w04.status_code == 200
    w04_body = w04.json()
    assert w04_body["public"] is True
    assert w04_body["timeline"]["focus"] == "First success acceleration"
    assert len(w04_body["coaching_actions"]) >= 6
    assert len(w04_body["scheduled_events"]) >= 6

    w04_csv = app_client.get("/api/public/adoption-plan/w04/checklist.csv")
    assert w04_csv.status_code == 200
    assert w04_csv.headers["content-type"].startswith("text/csv")
    assert "section,id,champion_role,action,owner,due_hint,objective,evidence_required,quick_fix" in w04_csv.text
    assert "coaching_action,W04-CA-01" in w04_csv.text

    w04_ics = app_client.get("/api/public/adoption-plan/w04/schedule.ics")
    assert w04_ics.status_code == 200
    assert w04_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in w04_ics.text
    assert "SUMMARY:[W04] W04 kickoff - first-success funnel review" in w04_ics.text

    w04_mistakes_json = app_client.get("/api/public/adoption-plan/w04/common-mistakes")
    assert w04_mistakes_json.status_code == 200
    mistakes_body = w04_mistakes_json.json()
    assert mistakes_body["public"] is True
    assert mistakes_body["title"] == "W04 Common Mistakes and Quick Fix Guide"
    assert isinstance(mistakes_body["items"], list)
    assert len(mistakes_body["items"]) >= 5

    w04_mistakes_html = app_client.get("/web/adoption/w04/common-mistakes")
    assert w04_mistakes_html.status_code == 200
    assert w04_mistakes_html.headers["content-type"].startswith("text/html")
    assert "W04 Common Mistakes and Quick Fix Guide" in w04_mistakes_html.text

    w05 = app_client.get("/api/public/adoption-plan/w05")
    assert w05.status_code == 200
    w05_body = w05.json()
    assert w05_body["public"] is True
    assert w05_body["timeline"]["focus"] == "Usage consistency"
    assert len(w05_body["role_missions"]) >= 5
    assert len(w05_body["scheduled_events"]) >= 5
    assert len(w05_body["help_docs"]) >= 3
    assert w05_body["usage_consistency_api"] == "/api/ops/adoption/w05/consistency"

    w05_csv = app_client.get("/api/public/adoption-plan/w05/missions.csv")
    assert w05_csv.status_code == 200
    assert w05_csv.headers["content-type"].startswith("text/csv")
    assert "section,id,role,mission,weekly_target,owner,evidence_required,evidence_hint" in w05_csv.text
    assert "role_mission,W05-M-01" in w05_csv.text

    w05_ics = app_client.get("/api/public/adoption-plan/w05/schedule.ics")
    assert w05_ics.status_code == 200
    assert w05_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in w05_ics.text
    assert "SUMMARY:[W05] W05 kickoff - weekly mission board launch" in w05_ics.text

    w05_help_docs = app_client.get("/api/public/adoption-plan/w05/help-docs")
    assert w05_help_docs.status_code == 200
    assert w05_help_docs.json()["public"] is True
    assert len(w05_help_docs.json()["items"]) >= 3

    w02_sample_files = app_client.get("/api/public/adoption-plan/w02/sample-files")
    assert w02_sample_files.status_code == 200
    w02_sample_body = w02_sample_files.json()
    assert w02_sample_body["public"] is True
    assert w02_sample_body["count"] >= 3
    assert len(w02_sample_body["items"]) >= 3
    first_sample = w02_sample_body["items"][0]
    assert first_sample["download_url"].startswith("/api/public/adoption-plan/w02/sample-files/")

    sample_download = app_client.get(first_sample["download_url"])
    assert sample_download.status_code == 200
    assert sample_download.headers["content-type"].startswith("text/plain")
    assert "W02 Sample Evidence" in sample_download.text

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
    assert me.headers.get("cache-control") == "no-store"
    assert me.headers.get("pragma") == "no-cache"

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


def test_admin_token_expiry_and_rotation_policy(app_client: TestClient) -> None:
    import app.database as db_module
    from sqlalchemy import select, update

    policy = app_client.get("/api/admin/token-policy", headers=_owner_headers())
    assert policy.status_code == 200
    assert policy.json()["max_ttl_days"] == 30
    assert policy.json()["max_idle_days"] == 30

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


def test_workflow_lock_matrix_enforcement(app_client: TestClient) -> None:
    def issue_token(
        *,
        username: str,
        display_name: str,
        role: str,
        permissions: list[str] | None = None,
        site_scope: list[str] | None = None,
    ) -> str:
        created = app_client.post(
            "/api/admin/users",
            headers=_owner_headers(),
            json={
                "username": username,
                "display_name": display_name,
                "role": role,
                "permissions": permissions or [],
                "site_scope": site_scope or ["WF Site"],
            },
        )
        assert created.status_code == 201
        user_id = created.json()["id"]
        issued = app_client.post(
            f"/api/admin/users/{user_id}/tokens",
            headers=_owner_headers(),
            json={"label": f"{username}-token"},
        )
        assert issued.status_code == 201
        return issued.json()["token"]

    operator_token = issue_token(
        username="wf_operator_ci",
        display_name="WF Operator",
        role="operator",
    )
    manager_token = issue_token(
        username="wf_manager_ci",
        display_name="WF Manager",
        role="manager",
    )
    owner_token = issue_token(
        username="wf_owner_ci",
        display_name="WF Owner",
        role="owner",
    )
    admin_token = issue_token(
        username="wf_admin_ci",
        display_name="WF Admin Override",
        role="manager",
        permissions=["workflow_locks:admin"],
    )
    auditor_token = issue_token(
        username="wf_auditor_ci",
        display_name="WF Auditor",
        role="auditor",
    )

    operator_headers = {"X-Admin-Token": operator_token}
    manager_headers = {"X-Admin-Token": manager_token}
    owner_headers = {"X-Admin-Token": owner_token}
    admin_headers = {"X-Admin-Token": admin_token}
    auditor_headers = {"X-Admin-Token": auditor_token}

    created = app_client.post(
        "/api/workflow-locks",
        headers=operator_headers,
        json={
            "site": "WF Site",
            "workflow_key": "inspection.approval",
            "content": {"step": "draft-v1"},
        },
    )
    assert created.status_code == 201
    workflow_lock_id = created.json()["id"]
    assert created.json()["status"] == "draft"

    manager_update_draft = app_client.patch(
        f"/api/workflow-locks/{workflow_lock_id}/draft",
        headers=manager_headers,
        json={"comment": "manager should not edit draft"},
    )
    assert manager_update_draft.status_code == 403

    owner_update_draft = app_client.patch(
        f"/api/workflow-locks/{workflow_lock_id}/draft",
        headers=owner_headers,
        json={"comment": "owner should not edit draft"},
    )
    assert owner_update_draft.status_code == 403

    operator_update_draft = app_client.patch(
        f"/api/workflow-locks/{workflow_lock_id}/draft",
        headers=operator_headers,
        json={
            "content": {"step": "draft-v2"},
            "requested_ticket": "REQ-1001",
            "comment": "operator update",
        },
    )
    assert operator_update_draft.status_code == 200
    assert operator_update_draft.json()["status"] == "draft"
    assert operator_update_draft.json()["content"]["step"] == "draft-v2"

    submitted = app_client.post(
        f"/api/workflow-locks/{workflow_lock_id}/submit",
        headers=operator_headers,
        json={"comment": "submit for review"},
    )
    assert submitted.status_code == 200
    assert submitted.json()["status"] == "review"

    operator_approve = app_client.post(
        f"/api/workflow-locks/{workflow_lock_id}/approve",
        headers=operator_headers,
        json={"comment": "operator cannot approve"},
    )
    assert operator_approve.status_code == 403

    approved = app_client.post(
        f"/api/workflow-locks/{workflow_lock_id}/approve",
        headers=manager_headers,
        json={"comment": "manager approve"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"

    manager_lock = app_client.post(
        f"/api/workflow-locks/{workflow_lock_id}/lock",
        headers=manager_headers,
        json={"reason": "manager cannot lock"},
    )
    assert manager_lock.status_code == 403

    locked = app_client.post(
        f"/api/workflow-locks/{workflow_lock_id}/lock",
        headers=owner_headers,
        json={"reason": "owner lock", "requested_ticket": "REQ-1001"},
    )
    assert locked.status_code == 200
    assert locked.json()["status"] == "locked"

    owner_unlock = app_client.post(
        f"/api/workflow-locks/{workflow_lock_id}/unlock",
        headers=owner_headers,
        json={"reason": "owner cannot unlock", "requested_ticket": "REQ-1002"},
    )
    assert owner_unlock.status_code == 403

    invalid_admin_unlock = app_client.post(
        f"/api/workflow-locks/{workflow_lock_id}/unlock",
        headers=admin_headers,
        json={"comment": "missing reason and ticket"},
    )
    assert invalid_admin_unlock.status_code == 400

    unlocked = app_client.post(
        f"/api/workflow-locks/{workflow_lock_id}/unlock",
        headers=admin_headers,
        json={
            "reason": "Emergency rollback",
            "requested_ticket": "REQ-1002",
            "comment": "admin override",
        },
    )
    assert unlocked.status_code == 200
    assert unlocked.json()["status"] == "approved"
    assert unlocked.json()["unlock_reason"] == "Emergency rollback"
    assert unlocked.json()["requested_ticket"] == "REQ-1002"

    auditor_read = app_client.get(
        f"/api/workflow-locks/{workflow_lock_id}",
        headers=auditor_headers,
    )
    assert auditor_read.status_code == 200
    assert auditor_read.json()["status"] == "approved"


def test_w02_tracker_execution_flow(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w02_manager_ci",
            "display_name": "W02 Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W02 Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w02-manager-token"},
    )
    assert issued.status_code == 201
    manager_headers = {"X-Admin-Token": issued.json()["token"]}

    bootstrap = app_client.post(
        "/api/adoption/w02/tracker/bootstrap",
        headers=manager_headers,
        json={"site": "W02 Site"},
    )
    assert bootstrap.status_code == 200
    bootstrap_body = bootstrap.json()
    assert bootstrap_body["site"] == "W02 Site"
    assert bootstrap_body["total_count"] >= 10

    overview = app_client.get(
        "/api/adoption/w02/tracker/overview?site=W02+Site",
        headers=manager_headers,
    )
    assert overview.status_code == 200
    overview_body = overview.json()
    assert overview_body["site"] == "W02 Site"
    assert overview_body["total_items"] >= 10
    assert overview_body["done_count"] == 0

    listed = app_client.get(
        "/api/adoption/w02/tracker/items?site=W02+Site&limit=500",
        headers=manager_headers,
    )
    assert listed.status_code == 200
    items = listed.json()
    assert len(items) >= 10
    tracker_item_id = items[0]["id"]

    updated = app_client.patch(
        f"/api/adoption/w02/tracker/items/{tracker_item_id}",
        headers=manager_headers,
        json={
            "assignee": "Ops QA",
            "status": "done",
            "completion_checked": True,
            "completion_note": "W02 checklist done",
        },
    )
    assert updated.status_code == 200
    updated_body = updated.json()
    assert updated_body["assignee"] == "Ops QA"
    assert updated_body["status"] == "done"
    assert updated_body["completion_checked"] is True
    assert updated_body["completed_at"] is not None

    blocked_upload = app_client.post(
        f"/api/adoption/w02/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
        data={"note": "blocked content type"},
        files={"file": ("poc.html", b"<script>alert(1)</script>", "text/html")},
    )
    assert blocked_upload.status_code == 415

    uploaded = app_client.post(
        f"/api/adoption/w02/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
        data={"note": "proof text"},
        files={"file": ("proof.txt", b"w02 evidence", "text/plain")},
    )
    assert uploaded.status_code == 201
    evidence = uploaded.json()
    evidence_id = evidence["id"]
    assert evidence["tracker_item_id"] == tracker_item_id
    assert evidence["file_name"] == "proof.txt"
    assert evidence["file_size"] == 12
    assert evidence["storage_backend"] in {"fs", "db"}
    assert len(evidence["sha256"]) == 64
    assert evidence["malware_scan_status"] in {"clean", "skipped", "suspicious"}

    evidence_list = app_client.get(
        f"/api/adoption/w02/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
    )
    assert evidence_list.status_code == 200
    assert len(evidence_list.json()) >= 1

    downloaded = app_client.get(
        f"/api/adoption/w02/tracker/evidence/{evidence_id}/download",
        headers=manager_headers,
    )
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"].startswith("text/plain")
    assert downloaded.content == b"w02 evidence"
    assert len(downloaded.headers["x-evidence-sha256"]) == 64

    eicar_signature = (
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
        b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    blocked_malware = app_client.post(
        f"/api/adoption/w02/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
        data={"note": "eicar"},
        files={"file": ("eicar.txt", eicar_signature, "text/plain")},
    )
    assert blocked_malware.status_code == 422

    readiness_before = app_client.get(
        "/api/adoption/w02/tracker/readiness?site=W02+Site",
        headers=manager_headers,
    )
    assert readiness_before.status_code == 200
    assert readiness_before.json()["ready"] is False
    assert readiness_before.json()["pending_count"] >= 1

    completion_before = app_client.get(
        "/api/adoption/w02/tracker/completion?site=W02+Site",
        headers=manager_headers,
    )
    assert completion_before.status_code == 200
    assert completion_before.json()["status"] == "active"
    assert completion_before.json()["readiness"]["ready"] is False

    complete_gate_fail = app_client.post(
        "/api/adoption/w02/tracker/complete",
        headers=manager_headers,
        json={"site": "W02 Site", "completion_note": "attempt normal close"},
    )
    assert complete_gate_fail.status_code == 409

    complete_force_denied = app_client.post(
        "/api/adoption/w02/tracker/complete",
        headers=manager_headers,
        json={"site": "W02 Site", "completion_note": "attempt force close", "force": True},
    )
    assert complete_force_denied.status_code == 403

    complete_force_owner = app_client.post(
        "/api/adoption/w02/tracker/complete",
        headers=_owner_headers(),
        json={"site": "W02 Site", "completion_note": "owner force close", "force": True},
    )
    assert complete_force_owner.status_code == 200
    assert complete_force_owner.json()["status"] == "completed_with_exceptions"
    assert complete_force_owner.json()["force_used"] is True

    completion_after_force = app_client.get(
        "/api/adoption/w02/tracker/completion?site=W02+Site",
        headers=manager_headers,
    )
    assert completion_after_force.status_code == 200
    assert completion_after_force.json()["status"] == "completed_with_exceptions"

    reopen_after_update = app_client.patch(
        f"/api/adoption/w02/tracker/items/{tracker_item_id}",
        headers=manager_headers,
        json={"status": "in_progress", "completion_checked": False, "completion_note": "re-opened"},
    )
    assert reopen_after_update.status_code == 200
    completion_after_reopen = app_client.get(
        "/api/adoption/w02/tracker/completion?site=W02+Site",
        headers=manager_headers,
    )
    assert completion_after_reopen.status_code == 200
    assert completion_after_reopen.json()["status"] == "active"

    listed_all = app_client.get(
        "/api/adoption/w02/tracker/items?site=W02+Site&limit=500",
        headers=manager_headers,
    )
    assert listed_all.status_code == 200
    all_items = listed_all.json()
    sandbox_item_ids: list[int] = []
    for item in all_items:
        item_id = int(item["id"])
        if item["item_type"] == "sandbox_scenario":
            sandbox_item_ids.append(item_id)
        done_update = app_client.patch(
            f"/api/adoption/w02/tracker/items/{item_id}",
            headers=manager_headers,
            json={
                "assignee": item.get("assignee") or "Ops QA",
                "status": "done",
                "completion_checked": True,
                "completion_note": "W02 finalized",
            },
        )
        assert done_update.status_code == 200

    for sandbox_item_id in sandbox_item_ids:
        sandbox_evidence_list = app_client.get(
            f"/api/adoption/w02/tracker/items/{sandbox_item_id}/evidence",
            headers=manager_headers,
        )
        assert sandbox_evidence_list.status_code == 200
        if len(sandbox_evidence_list.json()) == 0:
            sandbox_upload = app_client.post(
                f"/api/adoption/w02/tracker/items/{sandbox_item_id}/evidence",
                headers=manager_headers,
                data={"note": "sandbox proof"},
                files={
                    "file": (
                        f"sandbox-{sandbox_item_id}.txt",
                        f"sandbox evidence {sandbox_item_id}".encode("utf-8"),
                        "text/plain",
                    )
                },
            )
            assert sandbox_upload.status_code == 201

    readiness_after = app_client.get(
        "/api/adoption/w02/tracker/readiness?site=W02+Site",
        headers=manager_headers,
    )
    assert readiness_after.status_code == 200
    readiness_after_body = readiness_after.json()
    assert readiness_after_body["ready"] is True
    assert readiness_after_body["pending_count"] == 0
    assert readiness_after_body["in_progress_count"] == 0
    assert readiness_after_body["blocked_count"] == 0
    assert readiness_after_body["missing_assignee_count"] == 0
    assert readiness_after_body["missing_completion_checked_count"] == 0
    assert readiness_after_body["missing_required_evidence_count"] == 0
    assert readiness_after_body["readiness_score_percent"] == 100

    completed = app_client.post(
        "/api/adoption/w02/tracker/complete",
        headers=manager_headers,
        json={"site": "W02 Site", "completion_note": "W02 complete and signed"},
    )
    assert completed.status_code == 200
    completed_body = completed.json()
    assert completed_body["status"] == "completed"
    assert completed_body["force_used"] is False
    assert completed_body["readiness"]["ready"] is True
    assert completed_body["completed_at"] is not None

    completion_after = app_client.get(
        "/api/adoption/w02/tracker/completion?site=W02+Site",
        headers=manager_headers,
    )
    assert completion_after.status_code == 200
    assert completion_after.json()["status"] == "completed"
    assert completion_after.json()["readiness"]["ready"] is True

    owner_seed_other_site = app_client.post(
        "/api/adoption/w02/tracker/bootstrap",
        headers=_owner_headers(),
        json={"site": "Outside Site"},
    )
    assert owner_seed_other_site.status_code == 200

    forbidden_other_site = app_client.get(
        "/api/adoption/w02/tracker/overview?site=Outside+Site",
        headers=manager_headers,
    )
    assert forbidden_other_site.status_code == 403


def test_w03_tracker_execution_flow(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w03_manager_ci",
            "display_name": "W03 Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W03 Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w03-manager-token"},
    )
    assert issued.status_code == 201
    manager_headers = {"X-Admin-Token": issued.json()["token"]}

    bootstrap = app_client.post(
        "/api/adoption/w03/tracker/bootstrap",
        headers=manager_headers,
        json={"site": "W03 Site"},
    )
    assert bootstrap.status_code == 200
    bootstrap_body = bootstrap.json()
    assert bootstrap_body["site"] == "W03 Site"
    assert bootstrap_body["total_count"] >= 15

    overview = app_client.get(
        "/api/adoption/w03/tracker/overview?site=W03+Site",
        headers=manager_headers,
    )
    assert overview.status_code == 200
    overview_body = overview.json()
    assert overview_body["site"] == "W03 Site"
    assert overview_body["total_items"] >= 15
    assert overview_body["done_count"] == 0

    listed = app_client.get(
        "/api/adoption/w03/tracker/items?site=W03+Site&limit=500",
        headers=manager_headers,
    )
    assert listed.status_code == 200
    items = listed.json()
    assert len(items) >= 15
    tracker_item_id = items[0]["id"]

    updated = app_client.patch(
        f"/api/adoption/w03/tracker/items/{tracker_item_id}",
        headers=manager_headers,
        json={
            "assignee": "Ops Trainer",
            "status": "done",
            "completion_checked": True,
            "completion_note": "W03 kickoff done",
        },
    )
    assert updated.status_code == 200
    updated_body = updated.json()
    assert updated_body["assignee"] == "Ops Trainer"
    assert updated_body["status"] == "done"
    assert updated_body["completion_checked"] is True
    assert updated_body["completed_at"] is not None

    blocked_upload = app_client.post(
        f"/api/adoption/w03/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
        data={"note": "blocked content type"},
        files={"file": ("poc.html", b"<script>alert(1)</script>", "text/html")},
    )
    assert blocked_upload.status_code == 415

    uploaded = app_client.post(
        f"/api/adoption/w03/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
        data={"note": "proof text"},
        files={"file": ("proof-w03.txt", b"w03 evidence", "text/plain")},
    )
    assert uploaded.status_code == 201
    evidence = uploaded.json()
    evidence_id = evidence["id"]
    assert evidence["tracker_item_id"] == tracker_item_id
    assert evidence["file_name"] == "proof-w03.txt"
    assert evidence["storage_backend"] in {"fs", "db"}
    assert len(evidence["sha256"]) == 64
    assert evidence["malware_scan_status"] in {"clean", "skipped", "suspicious"}

    downloaded = app_client.get(
        f"/api/adoption/w03/tracker/evidence/{evidence_id}/download",
        headers=manager_headers,
    )
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"].startswith("text/plain")
    assert downloaded.content == b"w03 evidence"
    assert len(downloaded.headers["x-evidence-sha256"]) == 64

    readiness_before = app_client.get(
        "/api/adoption/w03/tracker/readiness?site=W03+Site",
        headers=manager_headers,
    )
    assert readiness_before.status_code == 200
    assert readiness_before.json()["ready"] is False
    assert readiness_before.json()["pending_count"] >= 1

    completion_before = app_client.get(
        "/api/adoption/w03/tracker/completion?site=W03+Site",
        headers=manager_headers,
    )
    assert completion_before.status_code == 200
    assert completion_before.json()["status"] == "active"
    assert completion_before.json()["readiness"]["ready"] is False

    complete_gate_fail = app_client.post(
        "/api/adoption/w03/tracker/complete",
        headers=manager_headers,
        json={"site": "W03 Site", "completion_note": "attempt normal close"},
    )
    assert complete_gate_fail.status_code == 409

    complete_force_denied = app_client.post(
        "/api/adoption/w03/tracker/complete",
        headers=manager_headers,
        json={"site": "W03 Site", "completion_note": "attempt force close", "force": True},
    )
    assert complete_force_denied.status_code == 403

    complete_force_owner = app_client.post(
        "/api/adoption/w03/tracker/complete",
        headers=_owner_headers(),
        json={"site": "W03 Site", "completion_note": "owner force close", "force": True},
    )
    assert complete_force_owner.status_code == 200
    assert complete_force_owner.json()["status"] == "completed_with_exceptions"
    assert complete_force_owner.json()["force_used"] is True

    completion_after_force = app_client.get(
        "/api/adoption/w03/tracker/completion?site=W03+Site",
        headers=manager_headers,
    )
    assert completion_after_force.status_code == 200
    assert completion_after_force.json()["status"] == "completed_with_exceptions"

    reopen_after_update = app_client.patch(
        f"/api/adoption/w03/tracker/items/{tracker_item_id}",
        headers=manager_headers,
        json={"status": "in_progress", "completion_checked": False, "completion_note": "re-opened"},
    )
    assert reopen_after_update.status_code == 200
    completion_after_reopen = app_client.get(
        "/api/adoption/w03/tracker/completion?site=W03+Site",
        headers=manager_headers,
    )
    assert completion_after_reopen.status_code == 200
    assert completion_after_reopen.json()["status"] == "active"

    listed_all = app_client.get(
        "/api/adoption/w03/tracker/items?site=W03+Site&limit=500",
        headers=manager_headers,
    )
    assert listed_all.status_code == 200
    all_items = listed_all.json()
    workshop_item_ids: list[int] = []
    for item in all_items:
        item_id = int(item["id"])
        if item["item_type"] == "role_workshop":
            workshop_item_ids.append(item_id)
        done_update = app_client.patch(
            f"/api/adoption/w03/tracker/items/{item_id}",
            headers=manager_headers,
            json={
                "assignee": item.get("assignee") or "Ops Trainer",
                "status": "done",
                "completion_checked": True,
                "completion_note": "W03 finalized",
            },
        )
        assert done_update.status_code == 200

    for workshop_item_id in workshop_item_ids:
        workshop_evidence_list = app_client.get(
            f"/api/adoption/w03/tracker/items/{workshop_item_id}/evidence",
            headers=manager_headers,
        )
        assert workshop_evidence_list.status_code == 200
        if len(workshop_evidence_list.json()) == 0:
            workshop_upload = app_client.post(
                f"/api/adoption/w03/tracker/items/{workshop_item_id}/evidence",
                headers=manager_headers,
                data={"note": "workshop proof"},
                files={
                    "file": (
                        f"workshop-{workshop_item_id}.txt",
                        f"workshop evidence {workshop_item_id}".encode("utf-8"),
                        "text/plain",
                    )
                },
            )
            assert workshop_upload.status_code == 201

    readiness_after = app_client.get(
        "/api/adoption/w03/tracker/readiness?site=W03+Site",
        headers=manager_headers,
    )
    assert readiness_after.status_code == 200
    readiness_after_body = readiness_after.json()
    assert readiness_after_body["ready"] is True
    assert readiness_after_body["pending_count"] == 0
    assert readiness_after_body["in_progress_count"] == 0
    assert readiness_after_body["blocked_count"] == 0
    assert readiness_after_body["missing_assignee_count"] == 0
    assert readiness_after_body["missing_completion_checked_count"] == 0
    assert readiness_after_body["missing_required_evidence_count"] == 0
    assert readiness_after_body["readiness_score_percent"] == 100

    completed = app_client.post(
        "/api/adoption/w03/tracker/complete",
        headers=manager_headers,
        json={"site": "W03 Site", "completion_note": "W03 complete and signed"},
    )
    assert completed.status_code == 200
    completed_body = completed.json()
    assert completed_body["status"] == "completed"
    assert completed_body["force_used"] is False
    assert completed_body["readiness"]["ready"] is True
    assert completed_body["completed_at"] is not None

    completion_after = app_client.get(
        "/api/adoption/w03/tracker/completion?site=W03+Site",
        headers=manager_headers,
    )
    assert completion_after.status_code == 200
    assert completion_after.json()["status"] == "completed"
    assert completion_after.json()["readiness"]["ready"] is True

    owner_seed_other_site = app_client.post(
        "/api/adoption/w03/tracker/bootstrap",
        headers=_owner_headers(),
        json={"site": "Outside W03 Site"},
    )
    assert owner_seed_other_site.status_code == 200

    forbidden_other_site = app_client.get(
        "/api/adoption/w03/tracker/overview?site=Outside+W03+Site",
        headers=manager_headers,
    )
    assert forbidden_other_site.status_code == 403


def test_w04_tracker_funnel_and_blockers_flow(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w04_manager_ci",
            "display_name": "W04 Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W04 Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w04-manager-token"},
    )
    assert issued.status_code == 201
    manager_headers = {"X-Admin-Token": issued.json()["token"]}

    bootstrap = app_client.post(
        "/api/adoption/w04/tracker/bootstrap",
        headers=manager_headers,
        json={"site": "W04 Site"},
    )
    assert bootstrap.status_code == 200
    bootstrap_body = bootstrap.json()
    assert bootstrap_body["site"] == "W04 Site"
    assert bootstrap_body["total_count"] >= 12

    overview = app_client.get(
        "/api/adoption/w04/tracker/overview?site=W04+Site",
        headers=manager_headers,
    )
    assert overview.status_code == 200
    overview_body = overview.json()
    assert overview_body["site"] == "W04 Site"
    assert overview_body["total_items"] >= 12
    assert overview_body["done_count"] == 0

    listed = app_client.get(
        "/api/adoption/w04/tracker/items?site=W04+Site&limit=500",
        headers=manager_headers,
    )
    assert listed.status_code == 200
    items = listed.json()
    assert len(items) >= 12
    tracker_item_id = items[0]["id"]

    updated = app_client.patch(
        f"/api/adoption/w04/tracker/items/{tracker_item_id}",
        headers=manager_headers,
        json={
            "assignee": "Site Champion",
            "status": "done",
            "completion_checked": True,
            "completion_note": "W04 first action done",
        },
    )
    assert updated.status_code == 200
    updated_body = updated.json()
    assert updated_body["assignee"] == "Site Champion"
    assert updated_body["status"] == "done"
    assert updated_body["completion_checked"] is True
    assert updated_body["completed_at"] is not None

    blocked_upload = app_client.post(
        f"/api/adoption/w04/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
        data={"note": "blocked content type"},
        files={"file": ("poc.html", b"<script>alert(1)</script>", "text/html")},
    )
    assert blocked_upload.status_code == 415

    uploaded = app_client.post(
        f"/api/adoption/w04/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
        data={"note": "proof text"},
        files={"file": ("proof-w04.txt", b"w04 evidence", "text/plain")},
    )
    assert uploaded.status_code == 201
    evidence = uploaded.json()
    evidence_id = evidence["id"]
    assert evidence["tracker_item_id"] == tracker_item_id
    assert evidence["file_name"] == "proof-w04.txt"
    assert evidence["storage_backend"] in {"fs", "db"}
    assert len(evidence["sha256"]) == 64
    assert evidence["malware_scan_status"] in {"clean", "skipped", "suspicious"}

    downloaded = app_client.get(
        f"/api/adoption/w04/tracker/evidence/{evidence_id}/download",
        headers=manager_headers,
    )
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"].startswith("text/plain")
    assert downloaded.content == b"w04 evidence"
    assert len(downloaded.headers["x-evidence-sha256"]) == 64

    readiness_before = app_client.get(
        "/api/adoption/w04/tracker/readiness?site=W04+Site",
        headers=manager_headers,
    )
    assert readiness_before.status_code == 200
    assert readiness_before.json()["ready"] is False
    assert readiness_before.json()["pending_count"] >= 1

    completion_before = app_client.get(
        "/api/adoption/w04/tracker/completion?site=W04+Site",
        headers=manager_headers,
    )
    assert completion_before.status_code == 200
    assert completion_before.json()["status"] == "active"
    assert completion_before.json()["readiness"]["ready"] is False

    complete_gate_fail = app_client.post(
        "/api/adoption/w04/tracker/complete",
        headers=manager_headers,
        json={"site": "W04 Site", "completion_note": "attempt normal close"},
    )
    assert complete_gate_fail.status_code == 409

    complete_force_denied = app_client.post(
        "/api/adoption/w04/tracker/complete",
        headers=manager_headers,
        json={"site": "W04 Site", "completion_note": "attempt force close", "force": True},
    )
    assert complete_force_denied.status_code == 403

    complete_force_owner = app_client.post(
        "/api/adoption/w04/tracker/complete",
        headers=_owner_headers(),
        json={"site": "W04 Site", "completion_note": "owner force close", "force": True},
    )
    assert complete_force_owner.status_code == 200
    assert complete_force_owner.json()["status"] == "completed_with_exceptions"
    assert complete_force_owner.json()["force_used"] is True

    completion_after_force = app_client.get(
        "/api/adoption/w04/tracker/completion?site=W04+Site",
        headers=manager_headers,
    )
    assert completion_after_force.status_code == 200
    assert completion_after_force.json()["status"] == "completed_with_exceptions"

    reopen_after_update = app_client.patch(
        f"/api/adoption/w04/tracker/items/{tracker_item_id}",
        headers=manager_headers,
        json={"status": "in_progress", "completion_checked": False, "completion_note": "re-opened"},
    )
    assert reopen_after_update.status_code == 200
    completion_after_reopen = app_client.get(
        "/api/adoption/w04/tracker/completion?site=W04+Site",
        headers=manager_headers,
    )
    assert completion_after_reopen.status_code == 200
    assert completion_after_reopen.json()["status"] == "active"

    listed_all = app_client.get(
        "/api/adoption/w04/tracker/items?site=W04+Site&limit=500",
        headers=manager_headers,
    )
    assert listed_all.status_code == 200
    all_items = listed_all.json()
    coaching_item_ids: list[int] = []
    for item in all_items:
        item_id = int(item["id"])
        if item["item_type"] == "coaching_action":
            coaching_item_ids.append(item_id)
        done_update = app_client.patch(
            f"/api/adoption/w04/tracker/items/{item_id}",
            headers=manager_headers,
            json={
                "assignee": item.get("assignee") or "Site Champion",
                "status": "done",
                "completion_checked": True,
                "completion_note": "W04 finalized",
            },
        )
        assert done_update.status_code == 200

    for coaching_item_id in coaching_item_ids:
        coaching_evidence_list = app_client.get(
            f"/api/adoption/w04/tracker/items/{coaching_item_id}/evidence",
            headers=manager_headers,
        )
        assert coaching_evidence_list.status_code == 200
        if len(coaching_evidence_list.json()) == 0:
            coaching_upload = app_client.post(
                f"/api/adoption/w04/tracker/items/{coaching_item_id}/evidence",
                headers=manager_headers,
                data={"note": "coaching proof"},
                files={
                    "file": (
                        f"coaching-{coaching_item_id}.txt",
                        f"coaching evidence {coaching_item_id}".encode("utf-8"),
                        "text/plain",
                    )
                },
            )
            assert coaching_upload.status_code == 201

    readiness_after = app_client.get(
        "/api/adoption/w04/tracker/readiness?site=W04+Site",
        headers=manager_headers,
    )
    assert readiness_after.status_code == 200
    readiness_after_body = readiness_after.json()
    assert readiness_after_body["ready"] is True
    assert readiness_after_body["pending_count"] == 0
    assert readiness_after_body["in_progress_count"] == 0
    assert readiness_after_body["blocked_count"] == 0
    assert readiness_after_body["missing_assignee_count"] == 0
    assert readiness_after_body["missing_completion_checked_count"] == 0
    assert readiness_after_body["missing_required_evidence_count"] == 0
    assert readiness_after_body["readiness_score_percent"] == 100

    completed = app_client.post(
        "/api/adoption/w04/tracker/complete",
        headers=manager_headers,
        json={"site": "W04 Site", "completion_note": "W04 complete and signed"},
    )
    assert completed.status_code == 200
    completed_body = completed.json()
    assert completed_body["status"] == "completed"
    assert completed_body["force_used"] is False
    assert completed_body["readiness"]["ready"] is True
    assert completed_body["completed_at"] is not None

    completion_after = app_client.get(
        "/api/adoption/w04/tracker/completion?site=W04+Site",
        headers=manager_headers,
    )
    assert completion_after.status_code == 200
    assert completion_after.json()["status"] == "completed"
    assert completion_after.json()["readiness"]["ready"] is True

    inspection = app_client.post(
        "/api/inspections",
        headers=manager_headers,
        json={
            "site": "W04 Site",
            "location": "B4",
            "cycle": "daily",
            "inspector": "w04_manager_ci",
            "inspected_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    assert inspection.status_code == 201

    work_order = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "W04 funnel work order",
            "description": "for funnel metrics",
            "site": "W04 Site",
            "location": "B4",
            "priority": "high",
        },
    )
    assert work_order.status_code == 201
    work_order_id = work_order.json()["id"]

    work_order_done = app_client.patch(
        f"/api/work-orders/{work_order_id}/complete",
        headers=manager_headers,
        json={"resolution_notes": "W04 complete path"},
    )
    assert work_order_done.status_code == 200

    funnel = app_client.get(
        "/api/ops/adoption/w04/funnel?site=W04+Site&days=30",
        headers=manager_headers,
    )
    assert funnel.status_code == 200
    funnel_body = funnel.json()
    assert funnel_body["site"] == "W04 Site"
    assert funnel_body["window_days"] == 30
    assert "metrics" in funnel_body
    assert "stages" in funnel_body
    assert "stage_timings_minutes" in funnel_body

    blockers = app_client.get(
        "/api/ops/adoption/w04/blockers?site=W04+Site&days=30&max_items=3",
        headers=manager_headers,
    )
    assert blockers.status_code == 200
    blockers_body = blockers.json()
    assert blockers_body["site"] == "W04 Site"
    assert blockers_body["window_days"] == 30
    assert isinstance(blockers_body["top"], list)
    assert isinstance(blockers_body["counts"], dict)

    owner_seed_other_site = app_client.post(
        "/api/adoption/w04/tracker/bootstrap",
        headers=_owner_headers(),
        json={"site": "Outside W04 Site"},
    )
    assert owner_seed_other_site.status_code == 200

    forbidden_other_site_tracker = app_client.get(
        "/api/adoption/w04/tracker/overview?site=Outside+W04+Site",
        headers=manager_headers,
    )
    assert forbidden_other_site_tracker.status_code == 403

    forbidden_other_site_funnel = app_client.get(
        "/api/ops/adoption/w04/funnel?site=Outside+W04+Site&days=30",
        headers=manager_headers,
    )
    assert forbidden_other_site_funnel.status_code == 403


def test_w05_usage_consistency_snapshot_flow(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w05_manager_ci",
            "display_name": "W05 Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W05 Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w05-manager-token"},
    )
    assert issued.status_code == 201
    manager_headers = {"X-Admin-Token": issued.json()["token"]}

    overdue_due_at = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    created_overdue = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "W05 overdue work",
            "description": "for consistency snapshot",
            "site": "W05 Site",
            "location": "C1",
            "priority": "high",
            "due_at": overdue_due_at,
        },
    )
    assert created_overdue.status_code == 201

    inspection = app_client.post(
        "/api/inspections",
        headers=manager_headers,
        json={
            "site": "W05 Site",
            "location": "C1",
            "cycle": "daily",
            "inspector": "w05_manager_ci",
            "inspected_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    assert inspection.status_code == 201

    scoped = app_client.get(
        "/api/ops/adoption/w05/consistency?site=W05+Site&days=28",
        headers=manager_headers,
    )
    assert scoped.status_code == 200
    scoped_body = scoped.json()
    assert scoped_body["site"] == "W05 Site"
    assert scoped_body["window_days"] == 28
    assert scoped_body["target_retention_percent"] == 65.0
    assert "metrics" in scoped_body
    assert scoped_body["metrics"]["open_work_orders"] >= 1
    assert scoped_body["metrics"]["overdue_open_work_orders"] >= 1
    assert isinstance(scoped_body["mission_recommendations"], list)
    assert len(scoped_body["mission_recommendations"]) >= 1

    all_visible = app_client.get(
        "/api/ops/adoption/w05/consistency?days=28",
        headers=manager_headers,
    )
    assert all_visible.status_code == 200
    all_body = all_visible.json()
    assert all_body["site"] is None
    assert isinstance(all_body["top_sites_by_overdue"], list)
    assert any(row["site"] == "W05 Site" for row in all_body["top_sites_by_overdue"])

    owner_outside = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Outside W05 scope",
            "description": "outside",
            "site": "Outside W05 Site",
            "location": "X1",
            "priority": "high",
            "due_at": overdue_due_at,
        },
    )
    assert owner_outside.status_code == 201

    forbidden = app_client.get(
        "/api/ops/adoption/w05/consistency?site=Outside+W05+Site&days=28",
        headers=manager_headers,
    )
    assert forbidden.status_code == 403


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


def test_audit_integrity_and_monthly_archive(app_client: TestClient) -> None:
    import app.database as db_module
    from sqlalchemy import select, update

    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "audit_integrity_ci",
            "display_name": "Audit Integrity CI",
            "role": "manager",
            "permissions": [],
        },
    )
    assert created.status_code == 201

    month = datetime.now(timezone.utc).strftime("%Y-%m")
    integrity = app_client.get(
        f"/api/admin/audit-integrity?month={month}",
        headers=_owner_headers(),
    )
    assert integrity.status_code == 200
    body = integrity.json()
    assert body["chain"]["chain_ok"] is True
    assert body["signature_algorithm"] in {"hmac-sha256", "unsigned"}
    assert len(body["archive_sha256"]) == 64

    archive = app_client.get(
        f"/api/admin/audit-archive/monthly?month={month}&include_entries=1",
        headers=_owner_headers(),
    )
    assert archive.status_code == 200
    archive_body = archive.json()
    assert archive_body["month"] == month
    assert archive_body["entry_count"] >= 1
    assert isinstance(archive_body["entries"], list)

    archive_csv = app_client.get(
        f"/api/admin/audit-archive/monthly/csv?month={month}",
        headers=_owner_headers(),
    )
    assert archive_csv.status_code == 200
    assert archive_csv.headers["content-type"].startswith("text/csv")
    assert len(archive_csv.headers.get("x-audit-archive-sha256", "")) == 64

    with db_module.get_conn() as conn:
        first_row = conn.execute(
            select(db_module.admin_audit_logs.c.id).order_by(
                db_module.admin_audit_logs.c.created_at.asc(),
                db_module.admin_audit_logs.c.id.asc(),
            ).limit(1)
        ).first()
        assert first_row is not None
        conn.execute(
            update(db_module.admin_audit_logs)
            .where(db_module.admin_audit_logs.c.id == int(first_row[0]))
            .values(detail_json='{"tampered":true}')
        )

    tampered_integrity = app_client.get(
        f"/api/admin/audit-integrity?month={month}",
        headers=_owner_headers(),
    )
    assert tampered_integrity.status_code == 200
    assert tampered_integrity.json()["chain"]["chain_ok"] is False

    rebaseline = app_client.post(
        f"/api/admin/audit-chain/rebaseline?from_month={month}&max_rows=50000",
        headers=_owner_headers(),
    )
    assert rebaseline.status_code == 200
    assert rebaseline.json()["from_month"] == month
    assert rebaseline.json()["scanned_count"] >= 1
    assert rebaseline.json()["updated_count"] >= 1

    repaired_integrity = app_client.get(
        f"/api/admin/audit-integrity?month={month}",
        headers=_owner_headers(),
    )
    assert repaired_integrity.status_code == 200
    assert repaired_integrity.json()["chain"]["chain_ok"] is True


def test_audit_chain_anchor_hash_support() -> None:
    import app.main as main_module

    created_at = datetime.now(timezone.utc)
    initial_prev = "abc123"
    detail_json = "{}"
    expected_hash = main_module._compute_audit_entry_hash(
        prev_hash=initial_prev,
        actor_user_id=1,
        actor_username="ci-user",
        action="ci_action",
        resource_type="ci_resource",
        resource_id="ci_id",
        status="success",
        detail_json=detail_json,
        created_at=created_at,
    )
    row = {
        "id": 1,
        "actor_user_id": 1,
        "actor_username": "ci-user",
        "action": "ci_action",
        "resource_type": "ci_resource",
        "resource_id": "ci_id",
        "status": "success",
        "detail_json": detail_json,
        "created_at": created_at,
        "prev_hash": initial_prev,
        "entry_hash": expected_hash,
    }

    ok = main_module._verify_audit_chain([row], initial_prev_hash=initial_prev)
    assert ok["chain_ok"] is True
    bad = main_module._verify_audit_chain([row], initial_prev_hash="")
    assert bad["chain_ok"] is False


def test_ops_runbook_checks_endpoint(app_client: TestClient) -> None:
    checks = app_client.get(
        "/api/ops/runbook/checks",
        headers=_owner_headers(),
    )
    assert checks.status_code == 200
    body = checks.json()
    assert body["overall_status"] in {"ok", "warning", "critical"}
    ids = {item["id"] for item in body["checks"]}
    assert "audit_chain_integrity" in ids
    assert "token_expiry_pressure" in ids
    assert "rate_limit_backend" in ids
    assert "audit_archive_signing" in ids
    assert "alert_channel_guard" in ids
    assert "alert_retention_recent" in ids
    assert "alert_guard_recovery_recent" in ids
    assert "alert_mttr_slo_recent" in ids
    assert "alert_mttr_slo_breach" in ids


def test_ops_security_posture_endpoint(app_client: TestClient) -> None:
    posture = app_client.get(
        "/api/ops/security/posture",
        headers=_owner_headers(),
    )
    assert posture.status_code == 200
    body = posture.json()
    assert body["env"] == "test"
    assert body["rate_limit"]["configured_store"] == "memory"
    assert body["rate_limit"]["active_backend"] == "memory"
    assert body["rate_limit"]["status"] == "ok"
    assert body["audit_archive_signing"]["enabled"] is True
    assert body["audit_archive_signing"]["algorithm"] == "hmac-sha256"
    assert body["alerting"]["ops_daily_check_alert_level"] == "critical"
    assert isinstance(body["alerting"]["webhook_target_count"], int)
    assert body["alerting"]["channel_guard_enabled"] is True
    assert body["alerting"]["channel_guard_fail_threshold"] == 3
    assert body["alerting"]["channel_guard_cooldown_minutes"] == 30
    assert body["alerting"]["guard_recover_max_targets"] == 30
    assert body["alerting"]["retention_days"] == 90
    assert body["alerting"]["retention_max_delete"] == 5000
    assert body["alerting"]["retention_archive_enabled"] is True
    assert body["alerting"]["mttr_slo_enabled"] is True
    assert body["alerting"]["mttr_slo_window_days"] == 30
    assert body["alerting"]["mttr_slo_threshold_minutes"] == 45
    assert body["alerting"]["mttr_slo_min_incidents"] == 5
    assert body["alerting"]["mttr_slo_auto_recover_enabled"] is True
    assert body["alerting"]["mttr_slo_recover_state"] == "quarantined"
    assert body["alerting"]["mttr_slo_recover_max_targets"] == 30
    assert body["alerting"]["mttr_slo_notify_enabled"] is True
    assert body["alerting"]["mttr_slo_notify_event_type"] == "mttr_slo_breach"
    assert body["alerting"]["mttr_slo_notify_cooldown_minutes"] == 120
    assert body["alerting"]["mttr_slo_top_channels"] == 15
    assert body["token_policy"]["max_ttl_days"] == 30


def test_ops_runbook_daily_check_run_and_latest(app_client: TestClient) -> None:
    run = app_client.post(
        "/api/ops/runbook/checks/run",
        headers=_owner_headers(),
    )
    assert run.status_code == 200
    body = run.json()
    assert body["status"] in {"success", "warning", "critical"}
    assert body["overall_status"] in {"ok", "warning", "critical"}
    assert body["check_count"] >= 4
    assert "security_posture" in body
    assert body["alert_level"] in {"off", "warning", "critical", "always"}
    assert "alert_attempted" in body
    assert "alert_dispatched" in body
    assert "alert_channels" in body
    assert "mttr_slo_check" in body
    if body["run_id"] is not None:
        assert body["run_id"] > 0

    latest = app_client.get(
        "/api/ops/runbook/checks/latest",
        headers=_owner_headers(),
    )
    assert latest.status_code == 200
    latest_body = latest.json()
    assert latest_body["job_name"] == "ops_daily_check"
    assert latest_body["overall_status"] in {"ok", "warning", "critical"}
    assert latest_body["check_count"] >= 4
    assert isinstance(latest_body["checks"], list)
    assert "security_posture" in latest_body
    assert "alert_attempted" in latest_body
    assert "alert_dispatched" in latest_body
    assert isinstance(latest_body["alert_channels"], list)
    assert "mttr_slo_check" in latest_body

    latest_without_checks = app_client.get(
        "/api/ops/runbook/checks/latest?include_checks=false",
        headers=_owner_headers(),
    )
    assert latest_without_checks.status_code == 200
    assert "checks" not in latest_without_checks.json()

    history = app_client.get(
        "/api/ops/job-runs?job_name=ops_daily_check",
        headers=_owner_headers(),
    )
    assert history.status_code == 200
    assert len(history.json()) >= 1


def test_ops_daily_check_alert_delivery_on_warning(app_client: TestClient, monkeypatch) -> None:
    import app.database as db_module
    import app.main as main_module
    from sqlalchemy import select

    monkeypatch.setattr(main_module, "OPS_DAILY_CHECK_ALERT_LEVEL", "warning")
    monkeypatch.setattr(main_module, "ALERT_WEBHOOK_URL", "http://127.0.0.1:1/hook")
    monkeypatch.setattr(main_module, "ALERT_WEBHOOK_URLS", "")

    run = app_client.post(
        "/api/ops/runbook/checks/run",
        headers=_owner_headers(),
    )
    assert run.status_code == 200
    body = run.json()
    assert body["alert_level"] == "warning"
    assert body["overall_status"] in {"warning", "critical"}
    assert body["alert_attempted"] is True
    assert body["alert_dispatched"] is False
    assert body["alert_error"] in {"all alert channels failed", "1/1 alert channels failed"}

    with db_module.get_conn() as conn:
        row = conn.execute(
            select(db_module.alert_deliveries)
            .where(db_module.alert_deliveries.c.event_type == "ops_daily_check")
            .order_by(db_module.alert_deliveries.c.id.desc())
            .limit(1)
        ).mappings().first()
    assert row is not None
    assert str(row["event_type"]) == "ops_daily_check"
    assert str(row["status"]) in {"failed", "warning", "success"}

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


def test_alert_channel_kpi_windows(app_client: TestClient) -> None:
    import app.database as db_module
    from sqlalchemy import insert

    now = datetime.now(timezone.utc)
    seed_rows = [
        {
            "event_type": "sla_escalation",
            "target": "https://chan-a.example/hook",
            "status": "success",
            "error": None,
            "payload_json": "{}",
            "attempt_count": 1,
            "last_attempt_at": now - timedelta(days=1),
        },
        {
            "event_type": "sla_escalation",
            "target": "https://chan-a.example/hook",
            "status": "failed",
            "error": "timeout",
            "payload_json": "{}",
            "attempt_count": 1,
            "last_attempt_at": now - timedelta(days=2),
        },
        {
            "event_type": "ops_daily_check",
            "target": "https://chan-b.example/hook",
            "status": "warning",
            "error": None,
            "payload_json": "{}",
            "attempt_count": 1,
            "last_attempt_at": now - timedelta(days=8),
        },
        {
            "event_type": "ops_daily_check",
            "target": "https://chan-b.example/hook",
            "status": "success",
            "error": None,
            "payload_json": "{}",
            "attempt_count": 1,
            "last_attempt_at": now - timedelta(days=20),
        },
        {
            "event_type": "sla_escalation",
            "target": "https://chan-a.example/hook",
            "status": "success",
            "error": None,
            "payload_json": "{}",
            "attempt_count": 1,
            "last_attempt_at": now - timedelta(days=31),
        },
    ]
    with db_module.get_conn() as conn:
        for row in seed_rows:
            conn.execute(
                insert(db_module.alert_deliveries).values(
                    **row,
                    created_at=row["last_attempt_at"],
                    updated_at=row["last_attempt_at"],
                )
            )

    kpi = app_client.get(
        "/api/ops/alerts/kpi/channels",
        headers=_owner_headers(),
    )
    assert kpi.status_code == 200
    body = kpi.json()
    assert body["event_type"] is None
    windows = {int(item["days"]): item for item in body["windows"]}
    assert set(windows.keys()) == {7, 30}

    window_7 = windows[7]
    assert window_7["total_deliveries"] == 2
    assert window_7["success_count"] == 1
    assert window_7["warning_count"] == 0
    assert window_7["failed_count"] == 1
    assert window_7["success_rate_percent"] == 50.0
    channels_7 = {item["target"]: item for item in window_7["channels"]}
    assert set(channels_7.keys()) == {"https://chan-a.example/hook"}
    assert channels_7["https://chan-a.example/hook"]["total_deliveries"] == 2
    assert channels_7["https://chan-a.example/hook"]["success_rate_percent"] == 50.0

    window_30 = windows[30]
    assert window_30["total_deliveries"] == 4
    assert window_30["success_count"] == 2
    assert window_30["warning_count"] == 1
    assert window_30["failed_count"] == 1
    assert window_30["success_rate_percent"] == 50.0
    channels_30 = {item["target"]: item for item in window_30["channels"]}
    assert set(channels_30.keys()) == {"https://chan-a.example/hook", "https://chan-b.example/hook"}
    assert channels_30["https://chan-a.example/hook"]["total_deliveries"] == 2
    assert channels_30["https://chan-b.example/hook"]["total_deliveries"] == 2

    filtered = app_client.get(
        "/api/ops/alerts/kpi/channels?event_type=ops_daily_check",
        headers=_owner_headers(),
    )
    assert filtered.status_code == 200
    filtered_body = filtered.json()
    filtered_windows = {int(item["days"]): item for item in filtered_body["windows"]}
    assert filtered_windows[7]["total_deliveries"] == 0
    assert filtered_windows[30]["total_deliveries"] == 2
    assert filtered_windows[30]["warning_count"] == 1
    assert filtered_windows[30]["success_count"] == 1


def test_alert_channel_mttr_kpi_api(app_client: TestClient) -> None:
    import app.database as db_module
    from sqlalchemy import insert

    now = datetime.now(timezone.utc)
    seed_rows = [
        {
            "event_type": "sla_escalation",
            "target": "https://chan-a.example/hook",
            "status": "failed",
            "error": "seed-a1",
            "payload_json": "{}",
            "attempt_count": 1,
            "last_attempt_at": now - timedelta(days=10),
        },
        {
            "event_type": "sla_escalation",
            "target": "https://chan-a.example/hook",
            "status": "success",
            "error": None,
            "payload_json": "{}",
            "attempt_count": 1,
            "last_attempt_at": now - timedelta(days=9),
        },
        {
            "event_type": "sla_escalation",
            "target": "https://chan-a.example/hook",
            "status": "failed",
            "error": "seed-a2",
            "payload_json": "{}",
            "attempt_count": 1,
            "last_attempt_at": now - timedelta(days=2),
        },
        {
            "event_type": "sla_escalation",
            "target": "https://chan-a.example/hook",
            "status": "success",
            "error": None,
            "payload_json": "{}",
            "attempt_count": 1,
            "last_attempt_at": now - timedelta(days=2) + timedelta(hours=4),
        },
        {
            "event_type": "sla_escalation",
            "target": "https://chan-b.example/hook",
            "status": "warning",
            "error": "seed-b1",
            "payload_json": "{}",
            "attempt_count": 1,
            "last_attempt_at": now - timedelta(days=3),
        },
        {
            "event_type": "ops_daily_check",
            "target": "https://chan-c.example/hook",
            "status": "failed",
            "error": "noise",
            "payload_json": "{}",
            "attempt_count": 1,
            "last_attempt_at": now - timedelta(days=1),
        },
    ]
    with db_module.get_conn() as conn:
        for row in seed_rows:
            conn.execute(
                insert(db_module.alert_deliveries).values(
                    **row,
                    created_at=row["last_attempt_at"],
                    updated_at=row["last_attempt_at"],
                )
            )

    response = app_client.get(
        "/api/ops/alerts/kpi/mttr",
        headers=_owner_headers(),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["event_type"] is None
    windows = {int(item["days"]): item for item in body["windows"]}
    assert set(windows.keys()) == {7, 30}

    win_7 = windows[7]
    assert win_7["incident_count"] == 3
    assert win_7["recovered_incidents"] == 1
    assert win_7["unresolved_incidents"] == 2
    assert win_7["mttr_minutes"] == 240.0

    win_30 = windows[30]
    assert win_30["incident_count"] == 4
    assert win_30["recovered_incidents"] == 2
    assert win_30["unresolved_incidents"] == 2
    assert win_30["mttr_minutes"] == 840.0
    assert win_30["median_recovery_minutes"] == 840.0
    assert win_30["longest_recovery_minutes"] == 1440.0

    channels_30 = {item["target"]: item for item in win_30["channels"]}
    assert set(channels_30.keys()) == {"https://chan-a.example/hook", "https://chan-b.example/hook", "https://chan-c.example/hook"}
    assert channels_30["https://chan-a.example/hook"]["incident_count"] == 2
    assert channels_30["https://chan-a.example/hook"]["recovered_incidents"] == 2
    assert channels_30["https://chan-a.example/hook"]["unresolved_incidents"] == 0
    assert channels_30["https://chan-a.example/hook"]["mttr_minutes"] == 840.0
    assert channels_30["https://chan-b.example/hook"]["recovered_incidents"] == 0
    assert channels_30["https://chan-b.example/hook"]["unresolved_incidents"] == 1
    assert channels_30["https://chan-b.example/hook"]["mttr_minutes"] is None
    assert channels_30["https://chan-c.example/hook"]["incident_count"] == 1
    assert channels_30["https://chan-c.example/hook"]["unresolved_incidents"] == 1

    filtered = app_client.get(
        "/api/ops/alerts/kpi/mttr?event_type=sla_escalation",
        headers=_owner_headers(),
    )
    assert filtered.status_code == 200
    filtered_windows = {int(item["days"]): item for item in filtered.json()["windows"]}
    assert filtered_windows[7]["incident_count"] == 2
    assert filtered_windows[30]["incident_count"] == 3
    assert filtered_windows[30]["unresolved_incidents"] == 1


def test_alert_mttr_slo_policy_and_check_api(app_client: TestClient, monkeypatch) -> None:
    import app.database as db_module
    import app.main as main_module
    from sqlalchemy import insert

    now = datetime.now(timezone.utc)
    seed_rows = [
        {
            "event_type": "sla_escalation",
            "target": "https://mttr-a.example/hook",
            "status": "failed",
            "error": "seed-fail-1",
            "payload_json": "{}",
            "attempt_count": 1,
            "last_attempt_at": now - timedelta(days=2),
        },
        {
            "event_type": "sla_escalation",
            "target": "https://mttr-a.example/hook",
            "status": "success",
            "error": None,
            "payload_json": "{}",
            "attempt_count": 1,
            "last_attempt_at": now - timedelta(days=2) + timedelta(hours=2),
        },
        {
            "event_type": "sla_escalation",
            "target": "https://mttr-b.example/hook",
            "status": "failed",
            "error": "seed-fail-2",
            "payload_json": "{}",
            "attempt_count": 1,
            "last_attempt_at": now - timedelta(days=1),
        },
    ]
    with db_module.get_conn() as conn:
        for row in seed_rows:
            conn.execute(
                insert(db_module.alert_deliveries).values(
                    **row,
                    created_at=row["last_attempt_at"],
                    updated_at=row["last_attempt_at"],
                )
            )

    policy_set = app_client.put(
        "/api/ops/alerts/mttr-slo/policy",
        headers=_owner_headers(),
        json={
            "enabled": True,
            "window_days": 30,
            "threshold_minutes": 30,
            "min_incidents": 1,
            "auto_recover_enabled": True,
            "recover_state": "all",
            "recover_max_targets": 5,
            "notify_enabled": True,
            "notify_event_type": "mttr_slo_breach_test",
            "notify_cooldown_minutes": 0,
            "top_channels": 5,
        },
    )
    assert policy_set.status_code == 200
    assert policy_set.json()["policy"]["threshold_minutes"] == 30
    assert policy_set.json()["policy"]["recover_state"] == "all"

    monkeypatch.setattr(
        main_module,
        "run_alert_guard_recover_job",
        lambda **kwargs: {
            "run_id": 987,
            "status": "success",
            "state_filter": kwargs.get("state_filter"),
            "max_targets": kwargs.get("max_targets"),
            "processed_count": 1,
            "success_count": 1,
            "failed_count": 0,
            "skipped_count": 0,
        },
    )
    monkeypatch.setattr(
        main_module,
        "_dispatch_alert_event",
        lambda **kwargs: (
            True,
            None,
            [main_module.SlaAlertChannelResult(target="https://notify.example/hook", success=True, error=None)],
        ),
    )

    run = app_client.post(
        "/api/ops/alerts/mttr-slo/check/run",
        headers=_owner_headers(),
    )
    assert run.status_code == 200
    run_body = run.json()
    assert run_body["breach"] is True
    assert run_body["window"]["mttr_minutes"] == 120.0
    assert run_body["actions"]["auto_recover_attempted"] is True
    assert run_body["actions"]["notify_attempted"] is True
    assert run_body["actions"]["notify_dispatched"] is True

    latest = app_client.get(
        "/api/ops/alerts/mttr-slo/check/latest",
        headers=_owner_headers(),
    )
    assert latest.status_code == 200
    latest_body = latest.json()
    assert latest_body["job_name"] == "alert_mttr_slo_check"
    assert latest_body["breach"] is True
    assert latest_body["window"]["mttr_minutes"] == 120.0
    assert latest_body["actions"]["auto_recover_attempted"] is True

    policy_get = app_client.get(
        "/api/ops/alerts/mttr-slo/policy",
        headers=_owner_headers(),
    )
    assert policy_get.status_code == 200
    assert policy_get.json()["policy"]["notify_event_type"] == "mttr_slo_breach_test"


def test_alert_channel_guard_and_recover_api(app_client: TestClient, monkeypatch) -> None:
    import app.database as db_module
    import app.main as main_module
    from sqlalchemy import insert, select

    target = "https://guard-target.example/hook"
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(main_module, "ALERT_CHANNEL_GUARD_FAIL_THRESHOLD", 2)
    monkeypatch.setattr(main_module, "ALERT_CHANNEL_GUARD_COOLDOWN_MINUTES", 120)

    with db_module.get_conn() as conn:
        conn.execute(
            insert(db_module.alert_deliveries).values(
                event_type="sla_escalation",
                target=target,
                status="failed",
                error="seed-1",
                payload_json="{}",
                attempt_count=1,
                last_attempt_at=now - timedelta(minutes=5),
                created_at=now - timedelta(minutes=5),
                updated_at=now - timedelta(minutes=5),
            )
        )
        conn.execute(
            insert(db_module.alert_deliveries).values(
                event_type="sla_escalation",
                target=target,
                status="failed",
                error="seed-2",
                payload_json="{}",
                attempt_count=2,
                last_attempt_at=now - timedelta(minutes=2),
                created_at=now - timedelta(minutes=2),
                updated_at=now - timedelta(minutes=2),
            )
        )

    guard = app_client.get(
        "/api/ops/alerts/channels/guard",
        params={"event_type": "sla_escalation"},
        headers=_owner_headers(),
    )
    assert guard.status_code == 200
    guard_body = guard.json()
    channel = next((item for item in guard_body["channels"] if item["target"] == target), None)
    assert channel is not None
    assert channel["state"] == "quarantined"
    assert channel["consecutive_failures"] >= 2

    monkeypatch.setattr(main_module, "_post_json_with_retries", lambda **kwargs: (True, None))
    recover = app_client.post(
        "/api/ops/alerts/channels/guard/recover",
        params={"target": target, "event_type": "sla_escalation", "note": "manual probe"},
        headers=_owner_headers(),
    )
    assert recover.status_code == 200
    recover_body = recover.json()
    assert recover_body["probe_status"] == "success"
    assert recover_body["after"]["state"] in {"healthy", "disabled"}
    assert recover_body["after"]["consecutive_failures"] == 0

    with db_module.get_conn() as conn:
        latest = conn.execute(
            select(db_module.alert_deliveries)
            .where(db_module.alert_deliveries.c.target == target)
            .where(db_module.alert_deliveries.c.event_type == "sla_escalation")
            .order_by(db_module.alert_deliveries.c.id.desc())
            .limit(1)
        ).mappings().first()
    assert latest is not None
    assert str(latest["status"]) == "success"

    with db_module.get_conn() as conn:
        conn.execute(
            insert(db_module.alert_deliveries).values(
                event_type="sla_escalation",
                target=target,
                status="failed",
                error="seed-3",
                payload_json="{}",
                attempt_count=3,
                last_attempt_at=datetime.now(timezone.utc),
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )

    batch = app_client.post(
        "/api/ops/alerts/channels/guard/recover-batch",
        params={"event_type": "sla_escalation", "state": "all", "max_targets": 10, "dry_run": "true"},
        headers=_owner_headers(),
    )
    assert batch.status_code == 200
    batch_body = batch.json()
    assert batch_body["state_filter"] == "all"
    assert batch_body["dry_run"] is True
    assert batch_body["processed_count"] >= 1
    assert batch_body["skipped_count"] >= 1

    latest_batch = app_client.get(
        "/api/ops/alerts/channels/guard/recover/latest",
        headers=_owner_headers(),
    )
    assert latest_batch.status_code == 200
    latest_batch_body = latest_batch.json()
    assert latest_batch_body["job_name"] == "alert_guard_recover"
    assert latest_batch_body["state_filter"] in {"all", "quarantined", "warning"}


def test_alert_retention_policy_run_and_latest(
    app_client: TestClient, monkeypatch, tmp_path: Path
) -> None:
    import app.database as db_module
    import app.main as main_module
    from sqlalchemy import insert, select

    monkeypatch.setattr(main_module, "ALERT_RETENTION_ARCHIVE_PATH", tmp_path.as_posix())
    monkeypatch.setattr(main_module, "ALERT_RETENTION_ARCHIVE_ENABLED", True)

    now = datetime.now(timezone.utc)
    old_target = "https://retention-old.example/hook"
    keep_target = "https://retention-keep.example/hook"
    with db_module.get_conn() as conn:
        conn.execute(
            insert(db_module.alert_deliveries).values(
                event_type="sla_escalation",
                target=old_target,
                status="failed",
                error="old",
                payload_json="{}",
                attempt_count=1,
                last_attempt_at=now - timedelta(days=40),
                created_at=now - timedelta(days=40),
                updated_at=now - timedelta(days=40),
            )
        )
        conn.execute(
            insert(db_module.alert_deliveries).values(
                event_type="sla_escalation",
                target=keep_target,
                status="success",
                error=None,
                payload_json="{}",
                attempt_count=1,
                last_attempt_at=now - timedelta(days=1),
                created_at=now - timedelta(days=1),
                updated_at=now - timedelta(days=1),
            )
        )

    policy = app_client.get(
        "/api/ops/alerts/retention/policy",
        headers=_owner_headers(),
    )
    assert policy.status_code == 200
    policy_body = policy.json()
    assert policy_body["archive_enabled"] is True
    assert policy_body["archive_path"] == tmp_path.as_posix()

    dry_run = app_client.post(
        "/api/ops/alerts/retention/run",
        params={"retention_days": 7, "max_delete": 100, "dry_run": "true", "write_archive": "false"},
        headers=_owner_headers(),
    )
    assert dry_run.status_code == 200
    dry_body = dry_run.json()
    assert dry_body["candidate_count"] == 1
    assert dry_body["deleted_count"] == 0

    run = app_client.post(
        "/api/ops/alerts/retention/run",
        params={"retention_days": 7, "max_delete": 100, "dry_run": "false", "write_archive": "true"},
        headers=_owner_headers(),
    )
    assert run.status_code == 200
    run_body = run.json()
    assert run_body["candidate_count"] == 1
    assert run_body["deleted_count"] == 1
    assert run_body["archive_file"]
    assert Path(run_body["archive_file"]).exists()

    latest = app_client.get(
        "/api/ops/alerts/retention/latest",
        headers=_owner_headers(),
    )
    assert latest.status_code == 200
    latest_body = latest.json()
    assert latest_body["job_name"] == "alert_retention"
    assert latest_body["deleted_count"] == 1

    with db_module.get_conn() as conn:
        old_row = conn.execute(
            select(db_module.alert_deliveries)
            .where(db_module.alert_deliveries.c.target == old_target)
            .limit(1)
        ).mappings().first()
        kept_row = conn.execute(
            select(db_module.alert_deliveries)
            .where(db_module.alert_deliveries.c.target == keep_target)
            .limit(1)
        ).mappings().first()
    assert old_row is None
    assert kept_row is not None


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
