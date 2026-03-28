from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def test_alert_job_modules_keep_legacy_main_imports(app_client: TestClient) -> None:
    import app.jobs.alert_guard_recover as alert_guard_recover_job
    import app.jobs.alert_retention as alert_retention_job
    import app.jobs.alert_retry as alert_retry_job
    import app.main as main_module

    importlib.reload(alert_guard_recover_job)
    importlib.reload(alert_retention_job)
    importlib.reload(alert_retry_job)

    assert callable(alert_guard_recover_job.main)
    assert callable(alert_retention_job.main)
    assert callable(alert_retry_job.main)

    recover = main_module.run_alert_guard_recover_job(dry_run=True, trigger="test")
    retention = main_module.run_alert_retention_job(dry_run=True, trigger="test")
    retry = main_module.run_alert_retry_job(limit=1, trigger="test")

    assert recover["dry_run"] is True
    assert retention["dry_run"] is True
    assert hasattr(retry, "model_dump")
