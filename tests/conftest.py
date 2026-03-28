import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

from tests.helpers.common import _seed_ops_special_checklists_json


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    evidence_path = tmp_path / "evidence"
    checklists_path = tmp_path / "apartment_facility_special_checklists.json"
    _seed_ops_special_checklists_json(checklists_path)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("ENV", "test")
    monkeypatch.setenv("ALLOW_INSECURE_LOCAL_AUTH", "0")
    monkeypatch.setenv("ADMIN_TOKEN", "test-owner-token")
    monkeypatch.setenv("API_RATE_LIMIT_ENABLED", "1")
    monkeypatch.setenv("API_RATE_LIMIT_WINDOW_SEC", "60")
    monkeypatch.setenv("API_RATE_LIMIT_MAX_PUBLIC", "10000")
    monkeypatch.setenv("API_RATE_LIMIT_MAX_AUTH", "10000")
    monkeypatch.setenv("API_RATE_LIMIT_MAX_AUTH_HEAVY", "10000")
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
    monkeypatch.delenv("ALERT_WEBHOOK_SHARED_TOKEN", raising=False)
    monkeypatch.setenv("OPS_DAILY_CHECK_ARCHIVE_PATH", (tmp_path / "ops_daily_check_archives").as_posix())
    monkeypatch.setenv("OPS_QUALITY_REPORT_ARCHIVE_PATH", (tmp_path / "ops_quality_reports").as_posix())
    monkeypatch.setenv("DEPLOY_SMOKE_ARCHIVE_PATH", (tmp_path / "deploy_smoke_archives").as_posix())
    monkeypatch.setenv("DR_REHEARSAL_BACKUP_PATH", (tmp_path / "dr_rehearsal").as_posix())
    monkeypatch.setenv("OPS_SPECIAL_CHECKLISTS_DATA_PATH", checklists_path.as_posix())
    monkeypatch.setenv("PREFLIGHT_FAIL_ON_ERROR", "0")

    import app.database as database_module
    import app.domains.complaints.router as complaints_router_module
    import app.domains.complaints.service as complaints_service_module
    import app.domains.iam.core as iam_core_module
    import app.domains.iam.security as iam_security_module
    import app.domains.team_ops.router as team_ops_router_module
    import app.domains.team_ops.service as team_ops_service_module
    import app.main as main_module
    import app.domains.ops.router_governance as ops_router_governance_module

    importlib.reload(database_module)
    importlib.reload(iam_core_module)
    importlib.reload(iam_security_module)
    importlib.reload(complaints_service_module)
    importlib.reload(complaints_router_module)
    importlib.reload(team_ops_service_module)
    importlib.reload(team_ops_router_module)
    importlib.reload(main_module)
    ops_router_governance_module.ENV_NAME = iam_core_module.ENV_NAME

    with TestClient(main_module.app) as client:
        yield client


@pytest.fixture()
def strict_rate_limit_client(tmp_path, monkeypatch):
    db_path = tmp_path / "test_rate_limit.db"
    evidence_path = tmp_path / "evidence_rate_limit"
    checklists_path = tmp_path / "apartment_facility_special_checklists.json"
    _seed_ops_special_checklists_json(checklists_path)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("ENV", "test")
    monkeypatch.setenv("ALLOW_INSECURE_LOCAL_AUTH", "0")
    monkeypatch.setenv("ADMIN_TOKEN", "test-owner-token")
    monkeypatch.setenv("API_RATE_LIMIT_ENABLED", "1")
    monkeypatch.setenv("API_RATE_LIMIT_WINDOW_SEC", "60")
    monkeypatch.setenv("API_RATE_LIMIT_MAX_PUBLIC", "3")
    monkeypatch.setenv("API_RATE_LIMIT_MAX_AUTH", "3")
    monkeypatch.setenv("API_RATE_LIMIT_MAX_AUTH_HEAVY", "2")
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
    monkeypatch.delenv("ALERT_WEBHOOK_SHARED_TOKEN", raising=False)
    monkeypatch.setenv("OPS_DAILY_CHECK_ARCHIVE_PATH", (tmp_path / "ops_daily_check_archives").as_posix())
    monkeypatch.setenv("OPS_QUALITY_REPORT_ARCHIVE_PATH", (tmp_path / "ops_quality_reports").as_posix())
    monkeypatch.setenv("DEPLOY_SMOKE_ARCHIVE_PATH", (tmp_path / "deploy_smoke_archives").as_posix())
    monkeypatch.setenv("DR_REHEARSAL_BACKUP_PATH", (tmp_path / "dr_rehearsal").as_posix())
    monkeypatch.setenv("OPS_SPECIAL_CHECKLISTS_DATA_PATH", checklists_path.as_posix())
    monkeypatch.setenv("PREFLIGHT_FAIL_ON_ERROR", "0")

    import app.database as database_module
    import app.domains.complaints.router as complaints_router_module
    import app.domains.complaints.service as complaints_service_module
    import app.domains.iam.core as iam_core_module
    import app.domains.iam.security as iam_security_module
    import app.domains.team_ops.router as team_ops_router_module
    import app.domains.team_ops.service as team_ops_service_module
    import app.main as main_module
    import app.domains.ops.router_governance as ops_router_governance_module

    importlib.reload(database_module)
    importlib.reload(iam_core_module)
    importlib.reload(iam_security_module)
    importlib.reload(complaints_service_module)
    importlib.reload(complaints_router_module)
    importlib.reload(team_ops_service_module)
    importlib.reload(team_ops_router_module)
    importlib.reload(main_module)
    ops_router_governance_module.ENV_NAME = iam_core_module.ENV_NAME

    with TestClient(main_module.app) as client:
        yield client
