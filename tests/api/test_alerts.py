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


def test_ops_preflight_and_alert_noise_policy_endpoints(app_client: TestClient) -> None:
    preflight = app_client.get("/api/ops/preflight", headers=_owner_headers())
    assert preflight.status_code == 200
    preflight_body = preflight.json()
    assert preflight_body["overall_status"] in {"ok", "warning", "critical"}
    assert preflight_body["has_error"] is False
    assert preflight_body["check_count"] >= 1

    preflight_refresh = app_client.get("/api/ops/preflight?refresh=true", headers=_owner_headers())
    assert preflight_refresh.status_code == 200
    assert preflight_refresh.json()["overall_status"] in {"ok", "warning", "critical"}

    noise_policy = app_client.get("/api/ops/alerts/noise-policy", headers=_owner_headers())
    assert noise_policy.status_code == 200
    noise_policy_body = noise_policy.json()
    assert noise_policy_body["review_window_days"] == 14
    assert noise_policy_body["false_positive_threshold_percent"] == 5.0
    assert noise_policy_body["false_negative_threshold_percent"] == 1.0

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


def test_internal_alert_webhook_requires_shared_token_when_configured(app_client: TestClient, monkeypatch) -> None:
    import app.main as main_module

    monkeypatch.setattr(main_module, "ALERT_WEBHOOK_SHARED_TOKEN", "shared-secret")

    forbidden = app_client.post(
        "/api/ops/alerts/webhook/internal",
        json={"event_type": "probe"},
    )
    assert forbidden.status_code == 403
    assert forbidden.json()["detail"] == "Invalid internal alert webhook token"

    accepted = app_client.post(
        "/api/ops/alerts/webhook/internal",
        json={"event_type": "probe"},
        headers={"X-Alert-Webhook-Token": "shared-secret"},
    )
    assert accepted.status_code == 202
    body = accepted.json()
    assert body["accepted"] is True
    assert body["event_type"] == "probe"


def test_post_json_with_retries_includes_shared_token_header(app_client: TestClient, monkeypatch) -> None:
    import app.main as main_module

    captured: dict[str, object] = {}

    class _DummyResponse:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def _fake_urlopen(req, timeout):
        captured["url"] = req.full_url
        captured["timeout"] = timeout
        captured["token"] = req.headers.get("X-alert-webhook-token")
        captured["content_type"] = req.headers.get("Content-type")
        return _DummyResponse()

    monkeypatch.setattr(main_module, "ALERT_WEBHOOK_SHARED_TOKEN", "shared-secret")
    monkeypatch.setattr(main_module.url_request, "urlopen", _fake_urlopen)

    ok, err = main_module._post_json_with_retries(
        url="https://alerts.example.internal/hook",
        payload={"event_type": "probe"},
        retries=1,
        timeout_sec=2,
    )

    assert ok is True
    assert err is None
    assert captured["url"] == "https://alerts.example.internal/hook"
    assert captured["timeout"] == 2
    assert captured["token"] == "shared-secret"
    assert captured["content_type"] == "application/json"

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
    assert policy_set.json()["meta"]["version"] == "v1"
    assert policy_set.json()["meta"]["scope"] == "ops.alerts.mttr_slo"
    assert policy_set.json()["meta"]["applies_to"] == "global"
    assert policy_set.json()["meta"]["policy_key"] == policy_set.json()["policy_key"]
    assert policy_set.json()["meta"]["updated_at"] == policy_set.json()["updated_at"]

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
    assert policy_get.json()["meta"]["scope"] == "ops.alerts.mttr_slo"
    assert policy_get.json()["meta"]["policy_key"] == policy_get.json()["policy_key"]

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
