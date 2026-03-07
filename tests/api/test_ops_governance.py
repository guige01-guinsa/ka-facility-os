import importlib
import io
import json
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.helpers.common import _assert_adoption_policy_response_shape, _owner_headers


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
    assert body["format_version"] == "v2"
    assert body["attachment_schema_version"] == "v2"
    assert body["chain"]["chain_ok"] is True
    assert body["signature_algorithm"] in {"hmac-sha256", "unsigned"}
    assert len(body["archive_sha256"]) == 64
    assert body["meta"]["schema"] == "admin_audit_integrity_response"
    assert body["meta"]["schema_version"] == "v1"
    assert body["meta"]["endpoint"] == "/api/admin/audit-integrity"
    assert body["meta"]["month"] == month
    assert body["meta"]["format_version"] == "v2"

    dr_run = app_client.post(
        "/api/ops/dr/rehearsal/run?simulate_restore=true",
        headers=_owner_headers(),
    )
    assert dr_run.status_code == 200
    dr_run_body = dr_run.json()

    archive = app_client.get(
        f"/api/admin/audit-archive/monthly?month={month}&include_entries=1",
        headers=_owner_headers(),
    )
    assert archive.status_code == 200
    archive_body = archive.json()
    assert archive_body["month"] == month
    assert archive_body["format_version"] == "v2"
    assert archive_body["attachment_schema_version"] == "v2"
    assert archive_body["entry_count"] >= 1
    assert isinstance(archive_body["entries"], list)
    assert archive_body["meta"]["schema"] == "admin_audit_archive_response"
    assert archive_body["meta"]["schema_version"] == "v1"
    assert archive_body["meta"]["endpoint"] == "/api/admin/audit-archive/monthly"
    assert archive_body["meta"]["month"] == month
    assert archive_body["meta"]["include_entries"] is True
    assert archive_body["meta"]["format_version"] == "v2"
    assert archive_body["meta"]["attachment_schema_version"] == "v2"
    assert isinstance(archive_body["attachments"], dict)
    assert archive_body["attachment_count"] == len(archive_body["attachments"])
    assert "dr_rehearsal" in archive_body["attachments"]
    assert "ops_checklists_import_validation" in archive_body["attachments"]
    assert "dr_rehearsal_attachment" in archive_body
    assert archive_body["dr_rehearsal_attachment"]["month"] == month
    assert archive_body["dr_rehearsal_attachment"]["included"] is True
    assert archive_body["dr_rehearsal_attachment"]["latest_in_month"]["run_id"] == dr_run_body["run_id"]
    assert archive_body["attachments"]["dr_rehearsal"]["schema"] == "audit_archive_attachment_dr_rehearsal"
    assert archive_body["attachments"]["dr_rehearsal"]["schema_version"] == "v2"
    assert "ops_checklists_import_validation_attachment" in archive_body
    import_attachment = archive_body["ops_checklists_import_validation_attachment"]
    assert import_attachment["month"] == month
    assert import_attachment["included"] is True
    assert import_attachment["status"] in {"ok", "warning", "error"}
    assert import_attachment["checklist_version"]
    assert import_attachment["source"] in {"file", "fallback", "qr_bulk_update_api"}
    assert import_attachment["applied_at"] is not None
    assert isinstance(import_attachment["summary"], dict)
    assert "error_count" in import_attachment["summary"]
    assert "warning_count" in import_attachment["summary"]
    attachments_import = archive_body["attachments"]["ops_checklists_import_validation"]
    assert attachments_import["schema"] == "audit_archive_attachment_ops_checklists_import_validation"
    assert attachments_import["schema_version"] == "v2"
    assert attachments_import["checklist_version"] == import_attachment["checklist_version"]

    archive_csv = app_client.get(
        f"/api/admin/audit-archive/monthly/csv?month={month}",
        headers=_owner_headers(),
    )
    assert archive_csv.status_code == 200
    assert archive_csv.headers["content-type"].startswith("text/csv")
    assert len(archive_csv.headers.get("x-audit-archive-sha256", "")) == 64
    assert archive_csv.headers.get("x-audit-archive-format-version") == "v1"
    assert archive_csv.text.startswith("id,created_at,actor_username,action,resource_type,resource_id,status,prev_hash,entry_hash")

    archive_csv_v2 = app_client.get(
        f"/api/admin/audit-archive/monthly/csv?month={month}&format_version=v2",
        headers=_owner_headers(),
    )
    assert archive_csv_v2.status_code == 200
    assert archive_csv_v2.headers["content-type"].startswith("text/csv")
    assert len(archive_csv_v2.headers.get("x-audit-archive-sha256", "")) == 64
    assert archive_csv_v2.headers.get("x-audit-archive-format-version") == "v2"
    assert "attachment.ops_checklists_import_validation,status" in archive_csv_v2.text
    assert "meta,format_version,v2" in archive_csv_v2.text
    assert "meta,attachment_schema_version,v2" in archive_csv_v2.text
    assert "attachment.dr_rehearsal,schema,audit_archive_attachment_dr_rehearsal" in archive_csv_v2.text

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


def test_audit_log_concurrent_writes_keep_chain_consistent() -> None:
    import app.main as main_module

    principal = {"user_id": 1, "username": "concurrency-owner"}

    def _write(index: int) -> None:
        main_module._write_audit_log(
            principal=principal,
            action="ci_audit_concurrency",
            resource_type="ci_audit",
            resource_id=str(index),
            detail={"index": index},
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(_write, range(32)))

    month = datetime.now(timezone.utc).strftime("%Y-%m")
    archive = main_module.build_monthly_audit_archive(month=month, include_entries=False, max_entries=10000)
    assert archive["chain"]["chain_ok"] is True

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
    assert "ops_daily_check_archive" in ids
    assert "startup_preflight" in ids
    assert "ops_quality_weekly_report_streak" in ids
    assert "migration_rollback_guide" in ids
    assert "alert_noise_policy_documented" in ids
    assert "dr_rehearsal_recent" in ids
    assert "ops_quality_weekly_report_recent" in ids
    assert "alert_channel_guard" in ids
    assert "alert_retention_recent" in ids
    assert "alert_guard_recovery_recent" in ids
    assert "alert_mttr_slo_recent" in ids
    assert "alert_mttr_slo_breach" in ids
    assert "w07_weekly_quality_recent" in ids
    assert "w07_quality_alert_channel" in ids
    assert "api_latency_p95" in ids
    assert "api_burn_rate" in ids
    assert "deploy_smoke_checklist" in ids
    assert "runbook_critical_monthly_review" in ids
    assert "evidence_archive_integrity_batch" in ids


def test_runbook_alert_checks_are_ok_without_pending_alert_backlog(app_client: TestClient) -> None:
    import app.main as main_module

    snapshot = main_module._build_ops_runbook_checks_snapshot()
    checks = {item["id"]: item for item in snapshot["checks"]}

    assert checks["alert_retry_recent"]["status"] == "ok"
    assert checks["alert_retry_recent"]["pending_count"] == 0
    assert checks["alert_retention_recent"]["status"] == "ok"
    assert checks["alert_retention_recent"]["candidate_count"] == 0


def test_w07_quality_alert_channel_is_ok_when_webhook_target_configured(app_client: TestClient, monkeypatch) -> None:
    import app.main as main_module

    monkeypatch.setattr(main_module, "ALERT_WEBHOOK_URL", "https://alerts.example.internal/hook")
    monkeypatch.setattr(main_module, "ALERT_WEBHOOK_URLS", "")

    snapshot = main_module._build_ops_runbook_checks_snapshot()
    checks = {item["id"]: item for item in snapshot["checks"]}

    assert checks["w07_quality_alert_channel"]["status"] == "ok"
    assert checks["w07_quality_alert_channel"]["webhook_target_count"] == 1


def test_weekly_streak_uses_recent_success_as_anchor_during_ramp_up(app_client: TestClient) -> None:
    import app.main as main_module
    from sqlalchemy import delete, insert

    now = datetime(2026, 3, 7, 12, 0, tzinfo=timezone.utc)
    with main_module.get_conn() as conn:
        conn.execute(
            delete(main_module.job_runs).where(main_module.job_runs.c.job_name == main_module.OPS_QUALITY_WEEKLY_JOB_NAME)
        )
        conn.execute(
            insert(main_module.job_runs).values(
                job_name=main_module.OPS_QUALITY_WEEKLY_JOB_NAME,
                trigger="manual",
                status="success",
                started_at=now - timedelta(days=6, minutes=10),
                finished_at=now - timedelta(days=6),
                detail_json="{}",
            )
        )

    snapshot = main_module._build_ops_quality_weekly_streak_snapshot(now=now)
    assert snapshot["current_streak_weeks"] == 1
    assert snapshot["target_weeks"] == 1
    assert snapshot["configured_target_weeks"] == 4
    assert snapshot["bootstrap_grace_active"] is True
    assert snapshot["target_met"] is True
    assert snapshot["anchor_week_start"] == "2026-02-23"


def test_api_latency_snapshot_treats_stale_and_low_traffic_targets_as_idle(app_client: TestClient, monkeypatch) -> None:
    import app.main as main_module
    from sqlalchemy import delete, insert

    now = datetime.now(timezone.utc)
    monkeypatch.setattr(main_module, "API_LATENCY_STALE_AFTER_MIN", 120)
    with main_module._API_LATENCY_LOCK:
        main_module._API_LATENCY_SAMPLES.clear()
        main_module._API_LATENCY_LAST_SEEN_AT.clear()

    with main_module.get_conn() as conn:
        conn.execute(delete(main_module.api_latency_samples))
        rows: list[dict[str, object]] = []
        for idx in range(20):
            rows.append(
                {
                    "endpoint_key": "GET /api/ops/dashboard/summary",
                    "method": "GET",
                    "path": "/api/ops/dashboard/summary",
                    "duration_ms": 700.0,
                    "status_code": 200,
                    "is_error": False,
                    "sampled_at": now - timedelta(hours=4, minutes=idx),
                }
            )
        for idx in range(2):
            rows.append(
                {
                    "endpoint_key": "GET /meta",
                    "method": "GET",
                    "path": "/meta",
                    "duration_ms": 8.0,
                    "status_code": 200,
                    "is_error": False,
                    "sampled_at": now - timedelta(minutes=30, seconds=idx),
                }
            )
        conn.execute(insert(main_module.api_latency_samples), rows)

    snapshot = main_module._build_api_latency_snapshot()
    stale_endpoint = next(item for item in snapshot["endpoints"] if item["endpoint"] == "GET /api/ops/dashboard/summary")
    meta_endpoint = next(item for item in snapshot["endpoints"] if item["endpoint"] == "GET /meta")

    assert snapshot["status"] == "ok"
    assert snapshot["burn_rate"]["status"] == "ok"
    assert stale_endpoint["status"] == "ok"
    assert stale_endpoint["is_stale"] is True
    assert "idle" in stale_endpoint["message"].lower()
    assert meta_endpoint["burn_status"] == "ok"
    assert meta_endpoint["burn_idle"] is True

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
    assert body["api_latency"]["enabled"] is True
    assert body["api_latency"]["target_count"] >= 2
    assert body["api_latency"]["burn_rate"]["short_window_minutes"] >= 1
    assert body["api_latency"]["burn_rate"]["long_window_minutes"] >= body["api_latency"]["burn_rate"]["short_window_minutes"]
    assert body["api_latency"]["burn_rate"]["status"] in {"ok", "warning", "critical"}
    assert body["deploy_smoke_policy"]["require_runbook_gate"] is True
    assert body["deploy_smoke_policy"]["recent_hours"] >= 1
    assert body["evidence_archive_integrity_policy"]["sample_per_table"] >= 1
    assert "w02" in body["evidence_archive_integrity_policy"]["modules"]
    assert body["preflight"]["overall_status"] in {"ok", "warning", "critical"}
    assert body["preflight"]["has_error"] is False
    assert body["ops_quality_reports"]["archive_enabled"] is True
    assert str(body["ops_quality_reports"]["archive_path"]).endswith("/ops_quality_reports")
    assert body["dr_rehearsal"]["enabled"] is True
    assert str(body["dr_rehearsal"]["backup_path"]).endswith("/dr_rehearsal")
    assert body["alerting"]["ops_daily_check_alert_level"] == "critical"
    assert body["alerting"]["ops_daily_check_archive_enabled"] is True
    assert str(body["alerting"]["ops_daily_check_archive_path"]).endswith("/ops_daily_check_archives")
    assert body["alerting"]["ops_daily_check_archive_retention_days"] == 60
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
    assert body["alerting"]["w07_quality_alert_enabled"] is True
    assert body["alerting"]["w07_quality_alert_cooldown_minutes"] == 180
    assert body["alerting"]["w07_quality_escalation_threshold_percent"] == 30.0
    assert body["alerting"]["w07_quality_alert_success_threshold_percent"] == 95.0
    assert isinstance(body["alerting"]["w07_quality_webhook_target_count"], int)
    assert body["alerting"]["w07_quality_archive_enabled"] is True
    assert body["token_policy"]["max_ttl_days"] == 30

def test_ops_deploy_checklist_smoke_record_and_integrity_endpoints(app_client: TestClient) -> None:
    headers = _owner_headers()

    checklist = app_client.get(
        "/api/ops/deploy/checklist",
        headers=headers,
    )
    assert checklist.status_code == 200
    checklist_body = checklist.json()
    assert checklist_body["version"]
    assert checklist_body["version_source"]
    assert checklist_body["signature"]
    assert len(checklist_body["steps"]) >= 5
    assert any(step["id"] == "smoke_02_ui_main_shell" for step in checklist_body["steps"])

    health = app_client.get("/health")
    meta = app_client.get("/meta")
    inspections = app_client.get("/api/inspections", headers=headers)
    work_orders = app_client.get("/api/work-orders", headers=headers)
    assert health.status_code == 200
    assert meta.status_code == 200
    assert inspections.status_code == 200
    assert work_orders.status_code == 200

    latency = app_client.get(
        "/api/ops/performance/api-latency",
        headers=headers,
    )
    assert latency.status_code == 200
    latency_body = latency.json()
    assert "status" in latency_body
    assert latency_body["target_count"] >= 2
    assert "burn_rate" in latency_body
    assert "status" in latency_body["burn_rate"]
    assert isinstance(latency_body["endpoints"], list)

    integrity = app_client.get(
        "/api/ops/integrity/evidence-archive?sample_per_table=1&max_issues=10",
        headers=headers,
    )
    assert integrity.status_code == 200
    integrity_body = integrity.json()
    assert integrity_body["sample_per_table"] == 1
    assert "archive" in integrity_body
    assert "chain_ok" in integrity_body["archive"]
    assert integrity_body["archive"]["archive_sha_ok"] is True
    assert integrity_body["archive"]["signature_ok"] is True

    smoke_record = app_client.post(
        "/api/ops/deploy/smoke/record",
        headers=headers,
        json={
            "deploy_id": "deploy-ci-001",
            "environment": "test",
            "status": "success",
            "base_url": "http://testserver",
            "checklist_version": checklist_body["version"],
            "rollback_reference": "docs/W15_MIGRATION_ROLLBACK.md",
            "rollback_reference_sha256": checklist_body["policy"]["rollback_guide_sha256"],
            "rollback_ready": True,
            "runbook_gate_passed": True,
            "checks": [
                {"id": "health", "status": "ok", "message": "health endpoint ok"},
                {"id": "ui_main_shell", "status": "ok", "message": "main html shell ok"},
                {"id": "runbook_gate", "status": "ok", "message": "no critical checks"},
            ],
        },
    )
    assert smoke_record.status_code == 200
    smoke_record_body = smoke_record.json()
    assert smoke_record_body["job_name"] == "deploy_smoke"
    assert smoke_record_body["status"] in {"success", "warning", "critical"}
    assert smoke_record_body["run_id"] is not None
    assert smoke_record_body["detail"]["rollback_reference_match"] is True
    assert smoke_record_body["detail"]["rollback_reference_exists"] is True
    assert smoke_record_body["detail"]["rollback_reference_sha256_match"] is True
    assert smoke_record_body["detail"]["checklist_version_match"] is True
    assert smoke_record_body["detail"]["ui_main_shell_checked"] is True
    assert smoke_record_body["detail"]["ui_main_shell_status"] == "ok"

    runbook = app_client.get(
        "/api/ops/runbook/checks",
        headers=headers,
    )
    assert runbook.status_code == 200
    runbook_body = runbook.json()
    deploy_check = next(item for item in runbook_body["checks"] if item["id"] == "deploy_smoke_checklist")
    assert deploy_check["latest_run_status"] in {"success", "warning", "critical"}
    assert deploy_check["latest_run_at"] is not None
    assert deploy_check["checklist_version_match"] is True
    assert deploy_check["ui_main_shell_status"] == "ok"

def test_ops_deploy_smoke_record_marks_warning_on_rollback_reference_mismatch(app_client: TestClient) -> None:
    headers = _owner_headers()
    checklist = app_client.get("/api/ops/deploy/checklist", headers=headers)
    assert checklist.status_code == 200
    checklist_body = checklist.json()
    smoke_record = app_client.post(
        "/api/ops/deploy/smoke/record",
        headers=headers,
        json={
            "deploy_id": "deploy-ci-rollback-mismatch",
            "environment": "test",
            "status": "success",
            "base_url": "http://testserver",
            "checklist_version": checklist_body["version"],
            "rollback_reference": "docs/NOT_EXISTING.md",
            "rollback_ready": True,
            "runbook_gate_passed": True,
            "checks": [
                {"id": "health", "status": "ok", "message": "health endpoint ok"},
                {"id": "ui_main_shell", "status": "ok", "message": "main html shell ok"},
            ],
        },
    )
    assert smoke_record.status_code == 200
    body = smoke_record.json()
    assert body["status"] == "warning"
    assert body["detail"]["rollback_reference_match"] is False

def test_api_latency_samples_persisted_beyond_memory_cache(app_client: TestClient) -> None:
    import app.main as main_module

    for _ in range(6):
        ping = app_client.get("/health")
        assert ping.status_code == 200

    with main_module._API_LATENCY_LOCK:
        main_module._API_LATENCY_SAMPLES.clear()
        main_module._API_LATENCY_LAST_SEEN_AT.clear()

    latency = app_client.get(
        "/api/ops/performance/api-latency",
        headers=_owner_headers(),
    )
    assert latency.status_code == 200
    body = latency.json()
    assert body["persist_enabled"] is True
    assert body["persist_retention_days"] >= 1
    endpoint = next(item for item in body["endpoints"] if item["endpoint"] == "GET /health")
    assert endpoint["sample_count"] >= 6
    assert endpoint["sample_source"] == "database"
    assert "p99_ms" in endpoint
    assert "burn_rate_short" in endpoint
    assert "burn_rate_long" in endpoint
    assert endpoint["burn_status"] in {"ok", "warning", "critical"}

def test_api_latency_snapshot_uses_monitor_window_for_p95(app_client: TestClient, monkeypatch) -> None:
    import app.main as main_module
    from sqlalchemy import delete, insert

    endpoint_key = "GET /api/ops/dashboard/summary"
    now = datetime.now(timezone.utc)
    monitor_window = 20
    monkeypatch.setattr(main_module, "API_LATENCY_MONITOR_WINDOW", monitor_window)

    with main_module.get_conn() as conn:
        conn.execute(
            delete(main_module.api_latency_samples).where(main_module.api_latency_samples.c.endpoint_key == endpoint_key)
        )
        rows: list[dict[str, object]] = []
        for idx in range(5):
            rows.append(
                {
                    "endpoint_key": endpoint_key,
                    "method": "GET",
                    "path": "/api/ops/dashboard/summary",
                    "duration_ms": 9000.0,
                    "status_code": 200,
                    "is_error": False,
                    "sampled_at": now - timedelta(minutes=30, seconds=idx),
                }
            )
        for idx in range(25):
            rows.append(
                {
                    "endpoint_key": endpoint_key,
                    "method": "GET",
                    "path": "/api/ops/dashboard/summary",
                    "duration_ms": float(180 + (idx % 10)),
                    "status_code": 200,
                    "is_error": False,
                    "sampled_at": now - timedelta(seconds=idx),
                }
            )
        conn.execute(insert(main_module.api_latency_samples), rows)

    latency = app_client.get(
        "/api/ops/performance/api-latency",
        headers=_owner_headers(),
    )
    assert latency.status_code == 200
    body = latency.json()
    endpoint = next(item for item in body["endpoints"] if item["endpoint"] == endpoint_key)
    assert endpoint["sample_count"] == monitor_window
    assert endpoint["status"] in {"ok", "warning"}
    assert float(endpoint["p95_ms"]) < 900.0

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
    assert body["summary"]["job_name"] == "ops_daily_check"
    assert body["summary"]["version"] == "v1"
    assert body["summary"]["check_count"] == body["check_count"]
    assert body["archive"]["enabled"] is True
    assert str(body["archive"]["path"]).endswith("/ops_daily_check_archives")
    assert body["archive"]["csv_file"]
    assert body["archive"]["json_file"]
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
    assert latest_body["summary"]["job_name"] == "ops_daily_check"
    assert latest_body["archive"]["enabled"] is True

    latest_without_checks = app_client.get(
        "/api/ops/runbook/checks/latest?include_checks=false",
        headers=_owner_headers(),
    )
    assert latest_without_checks.status_code == 200
    assert "checks" not in latest_without_checks.json()

    latest_summary_json = app_client.get(
        "/api/ops/runbook/checks/latest/summary.json",
        headers=_owner_headers(),
    )
    assert latest_summary_json.status_code == 200
    latest_summary_json_body = latest_summary_json.json()
    assert latest_summary_json_body["summary"]["job_name"] == "ops_daily_check"
    assert latest_summary_json_body["summary"]["run_id"] == latest_body["run_id"]

    latest_summary_csv = app_client.get(
        "/api/ops/runbook/checks/latest/summary.csv",
        headers=_owner_headers(),
    )
    assert latest_summary_csv.status_code == 200
    assert latest_summary_csv.headers["content-type"].startswith("text/csv")
    assert "run_id,checked_at,trigger,status,overall_status" in latest_summary_csv.text
    assert "check_id,check_status,check_message" in latest_summary_csv.text

    archive_json = app_client.get(
        "/api/ops/runbook/checks/archive.json?limit=5",
        headers=_owner_headers(),
    )
    assert archive_json.status_code == 200
    archive_json_body = archive_json.json()
    assert archive_json_body["job_name"] == "ops_daily_check"
    assert archive_json_body["count"] >= 1
    assert archive_json_body["rows"][0]["run_id"] == latest_body["run_id"]

    archive_csv = app_client.get(
        "/api/ops/runbook/checks/archive.csv?limit=5",
        headers=_owner_headers(),
    )
    assert archive_csv.status_code == 200
    assert archive_csv.headers["content-type"].startswith("text/csv")
    assert "run_id,finished_at,trigger,status,overall_status" in archive_csv.text

    history = app_client.get(
        "/api/ops/job-runs?job_name=ops_daily_check",
        headers=_owner_headers(),
    )
    assert history.status_code == 200
    assert len(history.json()) >= 1


def test_ops_runbook_critical_review_run_and_latest(app_client: TestClient) -> None:
    headers = _owner_headers()
    checklist = app_client.get("/api/ops/deploy/checklist", headers=headers)
    assert checklist.status_code == 200
    checklist_body = checklist.json()

    smoke_false_negative = app_client.post(
        "/api/ops/deploy/smoke/record",
        headers=headers,
        json={
            "deploy_id": "deploy-review-fn",
            "environment": "test",
            "status": "warning",
            "base_url": "http://testserver",
            "checklist_version": checklist_body["version"],
            "rollback_reference": "docs/W15_MIGRATION_ROLLBACK.md",
            "rollback_reference_sha256": checklist_body["policy"]["rollback_guide_sha256"],
            "rollback_ready": True,
            "runbook_gate_passed": True,
            "checks": [
                {"id": "health", "status": "ok", "message": "health endpoint ok"},
                {"id": "ui_main_shell", "status": "warning", "message": "inspection entry point degraded"},
            ],
        },
    )
    assert smoke_false_negative.status_code == 200

    smoke_false_positive = app_client.post(
        "/api/ops/deploy/smoke/record",
        headers=headers,
        json={
            "deploy_id": "deploy-review-fp",
            "environment": "test",
            "status": "critical",
            "base_url": "http://testserver",
            "checklist_version": checklist_body["version"],
            "rollback_reference": "docs/W15_MIGRATION_ROLLBACK.md",
            "rollback_reference_sha256": checklist_body["policy"]["rollback_guide_sha256"],
            "rollback_ready": True,
            "runbook_gate_passed": False,
            "checks": [
                {"id": "health", "status": "ok", "message": "health endpoint ok"},
                {"id": "ui_main_shell", "status": "ok", "message": "main html shell ok"},
                {"id": "runbook_gate", "status": "critical", "message": "critical runbook finding"},
            ],
        },
    )
    assert smoke_false_positive.status_code == 200

    runbook_snapshot = app_client.get("/api/ops/runbook/checks", headers=headers)
    assert runbook_snapshot.status_code == 200
    review_check = next(
        item for item in runbook_snapshot.json()["checks"] if item["id"] == "runbook_critical_monthly_review"
    )
    assert review_check["status"] in {"warning", "ok"}
    assert review_check["false_positive_candidate_count"] >= 1
    assert review_check["false_negative_candidate_count"] >= 1

    review_run = app_client.post("/api/ops/runbook/review/run", headers=headers)
    assert review_run.status_code == 200
    review_run_body = review_run.json()
    assert review_run_body["job_name"] == "ops_runbook_critical_review"
    assert review_run_body["status"] == "success"
    assert review_run_body["review_completed"] is True
    assert review_run_body["false_positive_candidate_count"] >= 1
    assert review_run_body["false_negative_candidate_count"] >= 1

    review_latest = app_client.get("/api/ops/runbook/review/latest", headers=headers)
    assert review_latest.status_code == 200
    review_latest_body = review_latest.json()
    assert review_latest_body["job_name"] == "ops_runbook_critical_review"
    assert review_latest_body["run_id"] == review_run_body["run_id"]
    assert review_latest_body["month"]

def test_startup_preflight_signing_key_warning_when_not_required(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "preflight_signing_warning.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("PREFLIGHT_FAIL_ON_ERROR", "1")
    monkeypatch.setenv("AUDIT_ARCHIVE_SIGNING_REQUIRED", "0")
    monkeypatch.delenv("AUDIT_ARCHIVE_SIGNING_KEY", raising=False)
    monkeypatch.setenv("OPS_DAILY_CHECK_ARCHIVE_PATH", (tmp_path / "ops_daily_check_archives").as_posix())
    monkeypatch.setenv("OPS_QUALITY_REPORT_ARCHIVE_PATH", (tmp_path / "ops_quality_reports").as_posix())
    monkeypatch.setenv("DR_REHEARSAL_BACKUP_PATH", (tmp_path / "dr_rehearsal").as_posix())

    import app.database as database_module
    import app.main as main_module

    importlib.reload(database_module)
    importlib.reload(main_module)
    snapshot = main_module._run_startup_preflight_snapshot()
    signing_check = next(item for item in snapshot["checks"] if item["id"] == "audit_archive_signing_key")

    assert signing_check["severity"] == "warning"
    assert signing_check["status"] == "warning"
    assert snapshot["has_error"] is False

def test_startup_preflight_signing_key_error_when_required(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "preflight_signing_error.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("PREFLIGHT_FAIL_ON_ERROR", "1")
    monkeypatch.setenv("AUDIT_ARCHIVE_SIGNING_REQUIRED", "1")
    monkeypatch.delenv("AUDIT_ARCHIVE_SIGNING_KEY", raising=False)
    monkeypatch.setenv("OPS_DAILY_CHECK_ARCHIVE_PATH", (tmp_path / "ops_daily_check_archives").as_posix())
    monkeypatch.setenv("OPS_QUALITY_REPORT_ARCHIVE_PATH", (tmp_path / "ops_quality_reports").as_posix())
    monkeypatch.setenv("DR_REHEARSAL_BACKUP_PATH", (tmp_path / "dr_rehearsal").as_posix())

    import app.database as database_module
    import app.main as main_module

    importlib.reload(database_module)
    importlib.reload(main_module)
    snapshot = main_module._run_startup_preflight_snapshot()
    signing_check = next(item for item in snapshot["checks"] if item["id"] == "audit_archive_signing_key")

    assert signing_check["severity"] == "error"
    assert signing_check["status"] == "error"
    assert snapshot["has_error"] is True

def test_startup_preflight_failure_reports_blocking_check_id(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "preflight_blocking_error.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("PREFLIGHT_FAIL_ON_ERROR", "1")
    monkeypatch.setenv("AUDIT_ARCHIVE_SIGNING_REQUIRED", "1")
    monkeypatch.delenv("AUDIT_ARCHIVE_SIGNING_KEY", raising=False)
    monkeypatch.setenv("OPS_DAILY_CHECK_ARCHIVE_PATH", (tmp_path / "ops_daily_check_archives").as_posix())
    monkeypatch.setenv("OPS_QUALITY_REPORT_ARCHIVE_PATH", (tmp_path / "ops_quality_reports").as_posix())
    monkeypatch.setenv("DR_REHEARSAL_BACKUP_PATH", (tmp_path / "dr_rehearsal").as_posix())

    import app.database as database_module
    import app.main as main_module

    importlib.reload(database_module)
    importlib.reload(main_module)

    with pytest.raises(RuntimeError, match="audit_archive_signing_key"):
        with TestClient(main_module.app):
            pass

def test_ops_admin_security_dashboard_endpoint(app_client: TestClient) -> None:
    dashboard = app_client.get("/api/ops/admin/security-dashboard?days=30", headers=_owner_headers())
    assert dashboard.status_code == 200
    body = dashboard.json()
    assert body["window_days"] == 30
    assert body["overall_status"] in {"ok", "warning", "critical"}
    assert body["users"]["total_users"] >= 1
    assert body["tokens"]["active_tokens"] >= 1
    assert "wildcard_scope_tokens" in body["tokens"]
    assert "non_owner_wildcard_tokens" in body["tokens"]
    assert "coverage" in body
    assert "active_users_without_token" in body["coverage"]
    assert body["actions"]["total"] >= 0
    assert "risk" in body
    assert body["risk"]["level"] in {"low", "medium", "high", "critical"}
    assert 0 <= int(body["risk"]["score"]) <= 100
    assert isinstance(body["recent_sensitive_events"], list)
    assert isinstance(body["recommendations"], list)
    assert isinstance(body["top_actors"], list)

def test_ops_quality_report_weekly_monthly_and_streak_endpoints(app_client: TestClient) -> None:
    weekly = app_client.get("/api/ops/reports/quality/weekly", headers=_owner_headers())
    assert weekly.status_code == 200
    weekly_body = weekly.json()
    assert weekly_body["template_version"] == "ops-quality-v1"
    assert weekly_body["window"] == "weekly"
    assert "summary" in weekly_body
    assert "recommendations" in weekly_body

    weekly_csv = app_client.get("/api/ops/reports/quality/weekly/csv", headers=_owner_headers())
    assert weekly_csv.status_code == 200
    assert weekly_csv.headers["content-type"].startswith("text/csv")
    assert "template_version,ops-quality-v1" in weekly_csv.text

    monthly = app_client.get("/api/ops/reports/quality/monthly?month=2026-03", headers=_owner_headers())
    assert monthly.status_code == 200
    monthly_body = monthly.json()
    assert monthly_body["window"] == "monthly"
    assert monthly_body["label"] == "2026-03"

    monthly_csv = app_client.get("/api/ops/reports/quality/monthly/csv?month=2026-03", headers=_owner_headers())
    assert monthly_csv.status_code == 200
    assert monthly_csv.headers["content-type"].startswith("text/csv")

    run_weekly = app_client.post("/api/ops/reports/quality/run?window=weekly", headers=_owner_headers())
    assert run_weekly.status_code == 200
    run_weekly_body = run_weekly.json()
    assert run_weekly_body["job_name"] == "ops_quality_report_weekly"
    assert run_weekly_body["archive"]["enabled"] is True

    run_monthly = app_client.post(
        "/api/ops/reports/quality/run?window=monthly&month=2026-03",
        headers=_owner_headers(),
    )
    assert run_monthly.status_code == 200
    run_monthly_body = run_monthly.json()
    assert run_monthly_body["job_name"] == "ops_quality_report_monthly"
    assert run_monthly_body["archive"]["enabled"] is True

    streak = app_client.get("/api/ops/reports/quality/weekly/streak", headers=_owner_headers())
    assert streak.status_code == 200
    streak_body = streak.json()
    assert streak_body["target_weeks"] >= 1
    assert streak_body["current_streak_weeks"] >= 0

def test_ops_dr_rehearsal_run_latest_history_endpoints(app_client: TestClient) -> None:
    run = app_client.post("/api/ops/dr/rehearsal/run?simulate_restore=true", headers=_owner_headers())
    assert run.status_code == 200
    run_body = run.json()
    assert run_body["job_name"] == "dr_rehearsal"
    assert run_body["status"] in {"success", "warning", "critical"}
    assert isinstance(run_body["counts"], dict)
    assert "backup_file" in run_body

    latest = app_client.get("/api/ops/dr/rehearsal/latest", headers=_owner_headers())
    assert latest.status_code == 200
    latest_body = latest.json()
    assert latest_body["job_name"] == "dr_rehearsal"
    assert latest_body["run_id"] == run_body["run_id"]

    history = app_client.get("/api/ops/dr/rehearsal/history?limit=5", headers=_owner_headers())
    assert history.status_code == 200
    history_body = history.json()
    assert history_body["count"] >= 1
    assert history_body["items"][0]["run_id"] == run_body["run_id"]

def test_ops_governance_gate_endpoints(app_client: TestClient) -> None:
    snapshot = app_client.get("/api/ops/governance/gate", headers=_owner_headers())
    assert snapshot.status_code == 200
    snapshot_body = snapshot.json()
    assert snapshot_body["decision"] in {"go", "no_go"}
    assert isinstance(snapshot_body["rules"], list)
    assert snapshot_body["summary"]["total_rules"] >= 5
    assert snapshot_body["summary"]["weighted_score_percent"] >= 0.0
    assert snapshot_body["policy"]["dr_weight"] >= 1.0
    assert snapshot_body["policy"]["min_weighted_score_percent"] >= 0.0
    assert any("weight" in item for item in snapshot_body["rules"])

    run = app_client.post("/api/ops/governance/gate/run", headers=_owner_headers())
    assert run.status_code == 200
    run_body = run.json()
    assert run_body["job_name"] == "ops_governance_gate"
    assert run_body["run_id"] is not None
    assert run_body["decision"] in {"go", "no_go"}
    assert run_body["status"] in {"success", "warning", "critical"}

    latest = app_client.get("/api/ops/governance/gate/latest", headers=_owner_headers())
    assert latest.status_code == 200
    latest_body = latest.json()
    assert latest_body["job_name"] == "ops_governance_gate"
    assert latest_body["run_id"] == run_body["run_id"]

    history = app_client.get("/api/ops/governance/gate/history?limit=5", headers=_owner_headers())
    assert history.status_code == 200
    history_body = history.json()
    assert history_body["count"] >= 1
    assert history_body["items"][0]["run_id"] == run_body["run_id"]
    assert history_body["items"][0]["decision"] in {"go", "no_go"}

def test_ops_governance_gate_remediation_endpoints(app_client: TestClient) -> None:
    plan = app_client.get(
        "/api/ops/governance/gate/remediation?include_warnings=true&max_items=20",
        headers=_owner_headers(),
    )
    assert plan.status_code == 200
    body = plan.json()
    assert body["decision"] in {"go", "no_go"}
    assert body["summary"]["item_count"] >= 0
    assert body["summary"]["fail_count"] >= 0
    assert body["summary"]["warning_count"] >= 0
    assert isinstance(body["items"], list)
    if body["items"]:
        first = body["items"][0]
        assert first["item_id"].startswith("GR-")
        assert first["rule_status"] in {"fail", "warning"}
        assert first["owner_role"]
        assert int(first["sla_hours"]) >= 1
        assert first["due_at"]
        assert first["action"]

    csv_export = app_client.get(
        "/api/ops/governance/gate/remediation/csv?include_warnings=true&max_items=20",
        headers=_owner_headers(),
    )
    assert csv_export.status_code == 200
    assert csv_export.headers["content-type"].startswith("text/csv")
    assert "item_id,rule_id,rule_status,required,priority,owner_role,sla_hours,due_at,action,reason" in csv_export.text

def test_ops_governance_gate_remediation_tracker_flow(app_client: TestClient) -> None:
    sync = app_client.post(
        "/api/ops/governance/gate/remediation/tracker/sync",
        headers=_owner_headers(),
        json={"include_warnings": True, "max_items": 30},
    )
    assert sync.status_code == 200
    sync_body = sync.json()
    assert sync_body["active_count"] >= 0
    assert isinstance(sync_body["items"], list)

    items = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/items",
        headers=_owner_headers(),
    )
    assert items.status_code == 200
    item_rows = items.json()
    assert isinstance(item_rows, list)

    overview = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/overview",
        headers=_owner_headers(),
    )
    assert overview.status_code == 200
    overview_body = overview.json()
    assert overview_body["active_count"] >= 0
    assert overview_body["completion_rate_percent"] >= 0

    readiness_before = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/readiness",
        headers=_owner_headers(),
    )
    assert readiness_before.status_code == 200
    readiness_before_body = readiness_before.json()
    assert readiness_before_body["total_items"] >= 0

    if item_rows:
        first_item_id = int(item_rows[0]["id"])
        block = app_client.patch(
            f"/api/ops/governance/gate/remediation/tracker/items/{first_item_id}",
            headers=_owner_headers(),
            json={
                "assignee": "Ops Owner",
                "status": "blocked",
                "completion_checked": False,
                "completion_note": "needs follow-up",
            },
        )
        assert block.status_code == 200
        assert block.json()["status"] == "blocked"

        complete_fail = app_client.post(
            "/api/ops/governance/gate/remediation/tracker/complete",
            headers=_owner_headers(),
            json={"completion_note": "try close"},
        )
        assert complete_fail.status_code == 409

        for row in item_rows:
            item_id = int(row["id"])
            patched = app_client.patch(
                f"/api/ops/governance/gate/remediation/tracker/items/{item_id}",
                headers=_owner_headers(),
                json={
                    "assignee": "Ops Owner",
                    "status": "done",
                    "completion_checked": True,
                    "completion_note": "closed in test",
                },
            )
            assert patched.status_code == 200
            assert patched.json()["status"] == "done"
            assert patched.json()["completion_checked"] is True

    complete = app_client.post(
        "/api/ops/governance/gate/remediation/tracker/complete",
        headers=_owner_headers(),
        json={"completion_note": "tracker close", "force": False},
    )
    assert complete.status_code == 200
    complete_body = complete.json()
    assert complete_body["status"] in {"completed", "completed_with_exceptions"}
    if complete_body["readiness"]["ready"]:
        assert complete_body["status"] == "completed"

    completion = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/completion",
        headers=_owner_headers(),
    )
    assert completion.status_code == 200
    completion_body = completion.json()
    assert completion_body["status"] in {"active", "completed", "completed_with_exceptions"}
    assert "readiness" in completion_body

def test_ops_governance_remediation_tracker_sla_escalation_endpoints(app_client: TestClient) -> None:
    sync = app_client.post(
        "/api/ops/governance/gate/remediation/tracker/sync",
        headers=_owner_headers(),
        json={"include_warnings": True, "max_items": 30},
    )
    assert sync.status_code == 200

    sla = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/sla?due_soon_hours=24",
        headers=_owner_headers(),
    )
    assert sla.status_code == 200
    sla_body = sla.json()
    assert int(sla_body["due_soon_hours"]) == 24
    assert int(sla_body["metrics"]["total_items"]) >= 0
    assert int(sla_body["metrics"]["open_items"]) >= 0
    assert int(sla_body["metrics"]["overdue_count"]) >= 0
    assert isinstance(sla_body["top_risk_items"], list)

    run = app_client.post(
        "/api/ops/governance/gate/remediation/tracker/escalate/run?dry_run=true&include_due_soon_hours=72",
        headers=_owner_headers(),
    )
    assert run.status_code == 200
    run_body = run.json()
    assert run_body["job_name"] == "ops_governance_remediation_escalation"
    assert run_body["dry_run"] is True
    assert int(run_body["due_soon_hours"]) == 72
    assert int(run_body["candidate_count"]) >= 0

    latest = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/escalate/latest",
        headers=_owner_headers(),
    )
    assert latest.status_code == 200
    latest_body = latest.json()
    assert latest_body["job_name"] == "ops_governance_remediation_escalation"
    assert latest_body["run_id"] == run_body["run_id"]
    assert int(latest_body["candidate_count"]) >= 0

def test_ops_governance_remediation_tracker_auto_assign_endpoints(app_client: TestClient) -> None:
    sync = app_client.post(
        "/api/ops/governance/gate/remediation/tracker/sync",
        headers=_owner_headers(),
        json={"include_warnings": True, "max_items": 30},
    )
    assert sync.status_code == 200

    items = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/items",
        headers=_owner_headers(),
    )
    assert items.status_code == 200
    item_rows = items.json()
    assert isinstance(item_rows, list)
    assert len(item_rows) > 0

    for row in item_rows[:10]:
        tracker_id = int(row["id"])
        reset = app_client.patch(
            f"/api/ops/governance/gate/remediation/tracker/items/{tracker_id}",
            headers=_owner_headers(),
            json={
                "assignee": "",
                "status": "pending",
                "completion_checked": False,
                "completion_note": "reset for auto-assign test",
            },
        )
        assert reset.status_code == 200
        assert reset.json()["assignee"] in {"", None}

    workload = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/workload?max_suggestions=10",
        headers=_owner_headers(),
    )
    assert workload.status_code == 200
    workload_body = workload.json()
    assert int(workload_body["total_open_items"]) >= 0
    assert int(workload_body["unassigned_open_count"]) >= 0
    assert isinstance(workload_body["assignee_open_counts"], dict)
    assert isinstance(workload_body["candidate_usernames_by_role"], dict)
    assert isinstance(workload_body["suggestions"], list)

    dry_run = app_client.post(
        "/api/ops/governance/gate/remediation/tracker/auto-assign/run?dry_run=true&limit=10",
        headers=_owner_headers(),
    )
    assert dry_run.status_code == 200
    dry_run_body = dry_run.json()
    assert dry_run_body["job_name"] == "ops_governance_remediation_auto_assign"
    assert dry_run_body["dry_run"] is True
    assert int(dry_run_body["candidate_count"]) >= 0
    assert int(dry_run_body["assigned_count"]) == 0

    run = app_client.post(
        "/api/ops/governance/gate/remediation/tracker/auto-assign/run?dry_run=false&limit=10",
        headers=_owner_headers(),
    )
    assert run.status_code == 200
    run_body = run.json()
    assert run_body["job_name"] == "ops_governance_remediation_auto_assign"
    assert run_body["dry_run"] is False
    assert int(run_body["candidate_count"]) >= 0
    assert int(run_body["assigned_count"]) >= 0
    assert isinstance(run_body["updated_ids"], list)

    latest = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/auto-assign/latest",
        headers=_owner_headers(),
    )
    assert latest.status_code == 200
    latest_body = latest.json()
    assert latest_body["job_name"] == "ops_governance_remediation_auto_assign"
    assert latest_body["run_id"] == run_body["run_id"]
    assert int(latest_body["assigned_count"]) >= 0

    if run_body["updated_ids"]:
        tracker_id = int(run_body["updated_ids"][0])
        updated = app_client.get(
            "/api/ops/governance/gate/remediation/tracker/items",
            headers=_owner_headers(),
        )
        assert updated.status_code == 200
        updated_payload = updated.json()
        assert isinstance(updated_payload, list)
        updated_rows = {int(item["id"]): item for item in updated_payload}
        assert tracker_id in updated_rows
        assert (updated_rows[tracker_id].get("assignee") or "").strip() != ""

def test_ops_governance_remediation_tracker_kpi_endpoints(app_client: TestClient) -> None:
    sync = app_client.post(
        "/api/ops/governance/gate/remediation/tracker/sync",
        headers=_owner_headers(),
        json={"include_warnings": True, "max_items": 30},
    )
    assert sync.status_code == 200

    kpi = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/kpi?window_days=14&due_soon_hours=24",
        headers=_owner_headers(),
    )
    assert kpi.status_code == 200
    kpi_body = kpi.json()
    assert int(kpi_body["window_days"]) == 14
    assert int(kpi_body["due_soon_hours"]) == 24
    assert int(kpi_body["metrics"]["open_items"]) >= 0
    assert int(kpi_body["metrics"]["overdue_count"]) >= 0
    assert int(kpi_body["metrics"]["unassigned_open_count"]) >= 0
    assert int(kpi_body["metrics"]["critical_open_count"]) >= 0
    assert isinstance(kpi_body["backlog_history"], dict)
    assert isinstance(kpi_body["recommendations"], list)

    run = app_client.post(
        "/api/ops/governance/gate/remediation/tracker/kpi/run?window_days=7&due_soon_hours=12",
        headers=_owner_headers(),
    )
    assert run.status_code == 200
    run_body = run.json()
    assert run_body["job_name"] == "ops_governance_remediation_kpi"
    assert int(run_body["window_days"]) == 7
    assert int(run_body["due_soon_hours"]) == 12
    assert int(run_body["metrics"]["open_items"]) >= 0
    assert run_body["status"] in {"success", "warning", "critical"}

    latest = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/kpi/latest",
        headers=_owner_headers(),
    )
    assert latest.status_code == 200
    latest_body = latest.json()
    assert latest_body["job_name"] == "ops_governance_remediation_kpi"
    assert latest_body["run_id"] == run_body["run_id"]
    assert latest_body["status"] in {"success", "warning", "critical"}
    assert int(latest_body["metrics"]["open_items"]) >= 0

def test_ops_governance_remediation_tracker_autopilot_endpoints(app_client: TestClient) -> None:
    sync = app_client.post(
        "/api/ops/governance/gate/remediation/tracker/sync",
        headers=_owner_headers(),
        json={"include_warnings": True, "max_items": 30},
    )
    assert sync.status_code == 200

    run_dry = app_client.post(
        "/api/ops/governance/gate/remediation/tracker/autopilot/run?dry_run=true&force=false",
        headers=_owner_headers(),
    )
    assert run_dry.status_code == 200
    dry_body = run_dry.json()
    assert dry_body["job_name"] == "ops_governance_remediation_autopilot"
    assert dry_body["dry_run"] is True
    assert isinstance(dry_body["actions"], list)
    assert "metrics" in dry_body
    assert int(dry_body["metrics"]["open_items"]) >= 0
    assert isinstance(dry_body["errors"], list)

    run_force = app_client.post(
        "/api/ops/governance/gate/remediation/tracker/autopilot/run?dry_run=false&force=true",
        headers=_owner_headers(),
    )
    assert run_force.status_code == 200
    force_body = run_force.json()
    assert force_body["job_name"] == "ops_governance_remediation_autopilot"
    assert force_body["dry_run"] is False
    assert force_body["force"] is True
    assert "auto_assign" in force_body["actions"]
    assert "escalation" in force_body["actions"]
    assert force_body["status"] in {"success", "warning", "critical"}
    assert isinstance(force_body.get("auto_assign"), dict)
    assert isinstance(force_body.get("escalation"), dict)

    latest = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/autopilot/latest",
        headers=_owner_headers(),
    )
    assert latest.status_code == 200
    latest_body = latest.json()
    assert latest_body["job_name"] == "ops_governance_remediation_autopilot"
    assert latest_body["run_id"] == force_body["run_id"]
    assert latest_body["status"] in {"success", "warning", "critical"}
    assert isinstance(latest_body["actions"], list)
    assert int(latest_body["metrics"]["open_items"]) >= 0

def test_ops_governance_remediation_tracker_autopilot_policy_preview_endpoints(app_client: TestClient) -> None:
    sync = app_client.post(
        "/api/ops/governance/gate/remediation/tracker/sync",
        headers=_owner_headers(),
        json={"include_warnings": True, "max_items": 30},
    )
    assert sync.status_code == 200

    policy_get = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/autopilot/policy",
        headers=_owner_headers(),
    )
    assert policy_get.status_code == 200
    get_body = policy_get.json()
    assert get_body["policy_key"] == "ops_governance_remediation_autopilot_policy"
    assert get_body["meta"]["version"] == "v1"
    assert get_body["meta"]["scope"] == "ops.governance.remediation.autopilot"
    assert get_body["meta"]["applies_to"] == "global"
    assert get_body["meta"]["policy_key"] == get_body["policy_key"]
    assert get_body["meta"]["updated_at"] == get_body["updated_at"]
    assert isinstance(get_body["policy"], dict)
    assert "enabled" in get_body["policy"]
    assert "kpi_window_days" in get_body["policy"]
    assert "auto_assign_max_items" in get_body["policy"]

    policy_set = app_client.put(
        "/api/ops/governance/gate/remediation/tracker/autopilot/policy",
        headers=_owner_headers(),
        json={
            "enabled": True,
            "notify_enabled": False,
            "unassigned_trigger": 0,
            "overdue_trigger": 0,
            "cooldown_minutes": 1440,
            "skip_if_no_action": True,
            "kpi_window_days": 10,
            "kpi_due_soon_hours": 18,
            "escalation_due_soon_hours": 8,
            "auto_assign_max_items": 25,
        },
    )
    assert policy_set.status_code == 200
    set_body = policy_set.json()
    assert set_body["policy_key"] == "ops_governance_remediation_autopilot_policy"
    assert set_body["meta"]["scope"] == "ops.governance.remediation.autopilot"
    assert set_body["meta"]["policy_key"] == set_body["policy_key"]
    assert set_body["meta"]["updated_at"] == set_body["updated_at"]
    assert set_body["policy"]["notify_enabled"] is False
    assert int(set_body["policy"]["unassigned_trigger"]) == 0
    assert int(set_body["policy"]["overdue_trigger"]) == 0
    assert int(set_body["policy"]["cooldown_minutes"]) == 1440
    assert set_body["policy"]["skip_if_no_action"] is True
    assert int(set_body["policy"]["kpi_window_days"]) == 10
    assert int(set_body["policy"]["kpi_due_soon_hours"]) == 18
    assert int(set_body["policy"]["escalation_due_soon_hours"]) == 8
    assert int(set_body["policy"]["auto_assign_max_items"]) == 25

    preview = app_client.post(
        "/api/ops/governance/gate/remediation/tracker/autopilot/preview",
        headers=_owner_headers(),
        json={
            "force": True,
            "policy": {
                "enabled": True,
                "notify_enabled": True,
                "unassigned_trigger": 9999,
                "overdue_trigger": 9999,
                "kpi_window_days": 7,
                "kpi_due_soon_hours": 12,
                "escalation_due_soon_hours": 6,
                "auto_assign_max_items": 12,
            },
        },
    )
    assert preview.status_code == 200
    preview_body = preview.json()
    assert preview_body["policy_key"] == "ops_governance_remediation_autopilot_policy"
    assert preview_body["force"] is True
    assert isinstance(preview_body["planned_actions"], list)
    assert "auto_assign" in preview_body["planned_actions"]
    assert "escalation" in preview_body["planned_actions"]
    assert isinstance(preview_body["guard"], dict)
    assert preview_body["guard"]["ready"] is True
    assert preview_body["guard"]["reason"] == "force_override"
    assert int(preview_body["policy"]["kpi_window_days"]) == 7
    assert int(preview_body["policy"]["auto_assign_max_items"]) == 12
    assert int(preview_body["metrics"]["open_items"]) >= 0

    guard = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/autopilot/guard?force=false",
        headers=_owner_headers(),
    )
    assert guard.status_code == 200
    guard_body = guard.json()
    assert guard_body["policy_key"] == "ops_governance_remediation_autopilot_policy"
    assert isinstance(guard_body["evaluation"], dict)
    assert isinstance(guard_body["guard"], dict)
    assert isinstance(guard_body["evaluation"]["planned_actions"], list)

    run_force = app_client.post(
        "/api/ops/governance/gate/remediation/tracker/autopilot/run?dry_run=true&force=true",
        headers=_owner_headers(),
    )
    assert run_force.status_code == 200
    run_force_body = run_force.json()
    assert run_force_body["force"] is True
    assert run_force_body["skipped"] is False
    assert "auto_assign" in run_force_body["actions"]
    assert "escalation" in run_force_body["actions"]

    run_blocked = app_client.post(
        "/api/ops/governance/gate/remediation/tracker/autopilot/run?dry_run=true&force=false",
        headers=_owner_headers(),
    )
    assert run_blocked.status_code == 200
    run_blocked_body = run_blocked.json()
    assert run_blocked_body["force"] is False
    assert run_blocked_body["skipped"] is True
    assert run_blocked_body["skip_reason"] == "cooldown_active"
    assert isinstance(run_blocked_body["guard"], dict)
    assert run_blocked_body["guard"]["blocked"] is True

    history = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/autopilot/history?limit=5",
        headers=_owner_headers(),
    )
    assert history.status_code == 200
    history_body = history.json()
    assert int(history_body["limit"]) == 5
    assert int(history_body["count"]) >= 1
    assert isinstance(history_body["items"], list)
    if history_body["items"]:
        top = history_body["items"][0]
        assert top["status"] in {"success", "warning", "critical"}
        assert isinstance(top["planned_actions"], list)
        assert isinstance(top["actions"], list)

    summary = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/autopilot/summary?days=7",
        headers=_owner_headers(),
    )
    assert summary.status_code == 200
    summary_body = summary.json()
    assert int(summary_body["window_days"]) == 7
    assert int(summary_body["total_runs"]) >= 1
    assert int(summary_body["executed_runs"]) >= 0
    assert int(summary_body["skipped_runs"]) >= 0
    assert isinstance(summary_body["status_counts"], dict)
    assert isinstance(summary_body["planned_action_counts"], dict)
    assert isinstance(summary_body["executed_action_counts"], dict)
    assert float(summary_body["success_rate_percent"]) >= 0.0
    assert float(summary_body["skipped_rate_percent"]) >= 0.0

    history_csv = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/autopilot/history.csv?limit=5",
        headers=_owner_headers(),
    )
    assert history_csv.status_code == 200
    assert history_csv.headers.get("content-type", "").startswith("text/csv")
    assert "run_id,status,trigger,started_at,finished_at,dry_run,force,skipped,skip_reason" in history_csv.text

    summary_csv = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/autopilot/summary.csv?days=7",
        headers=_owner_headers(),
    )
    assert summary_csv.status_code == 200
    assert summary_csv.headers.get("content-type", "").startswith("text/csv")
    assert "metric,value" in summary_csv.text
    assert "success_rate_percent" in summary_csv.text
    assert "latest_run_status" in summary_csv.text

    anomalies = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/autopilot/anomalies?days=14",
        headers=_owner_headers(),
    )
    assert anomalies.status_code == 200
    anomalies_body = anomalies.json()
    assert int(anomalies_body["window_days"]) == 14
    assert anomalies_body["health_status"] in {"healthy", "warning", "critical"}
    assert isinstance(anomalies_body["anomalies"], list)
    assert isinstance(anomalies_body["metrics"], dict)
    assert isinstance(anomalies_body["recommendations"], list)

    anomalies_csv = app_client.get(
        "/api/ops/governance/gate/remediation/tracker/autopilot/anomalies.csv?days=14",
        headers=_owner_headers(),
    )
    assert anomalies_csv.status_code == 200
    assert anomalies_csv.headers.get("content-type", "").startswith("text/csv")
    assert "generated_at,window_days,health_status,total_runs,success_rate_percent,skipped_rate_percent" in anomalies_csv.text
    assert "recommendation" in anomalies_csv.text
