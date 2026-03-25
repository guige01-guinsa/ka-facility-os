import importlib

from fastapi.testclient import TestClient

from tests.helpers.common import _seed_ops_special_checklists_json


def _configure_env(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "test_split.db"
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


def _build_split_client(tmp_path, monkeypatch, module_name: str) -> TestClient:
    _configure_env(tmp_path, monkeypatch)

    import app.database as database_module
    import app.domains.complaints.router as complaints_router_module
    import app.domains.complaints.service as complaints_service_module
    import app.domains.iam.core as iam_core_module
    import app.domains.iam.security as iam_security_module
    import app.entrypoints.split_apps as split_apps_module
    import app.main as main_module

    importlib.reload(database_module)
    importlib.reload(iam_core_module)
    importlib.reload(iam_security_module)
    importlib.reload(complaints_service_module)
    importlib.reload(complaints_router_module)
    importlib.reload(main_module)
    importlib.reload(split_apps_module)
    entrypoint_module = importlib.import_module(module_name)
    importlib.reload(entrypoint_module)
    return TestClient(entrypoint_module.app)


def test_facility_core_entrypoint_routes(tmp_path, monkeypatch) -> None:
    with _build_split_client(tmp_path, monkeypatch, "app.entrypoints.facility_core") as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        root_json = client.get("/")
        assert root_json.status_code == 200
        assert root_json.json()["service"] == "ka-facility-core"

        root_html = client.get("/", headers={"Accept": "text/html"})
        assert root_html.status_code == 200
        assert "시설 운영 코어" in root_html.text
        assert "/web/complaints" in root_html.text

        modules = client.get("/api/public/modules")
        assert modules.status_code == 200
        module_ids = {item["id"] for item in modules.json()["modules"]}
        assert "household-complaints" in module_ids
        assert "rbac-governance" not in module_ids

        complaints = client.get("/web/complaints")
        assert complaints.status_code == 200

        adoption_public = client.get("/api/public/adoption-plan")
        assert adoption_public.status_code == 404


def test_platform_admin_entrypoint_routes(tmp_path, monkeypatch) -> None:
    with _build_split_client(tmp_path, monkeypatch, "app.entrypoints.platform_admin") as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        root_json = client.get("/")
        assert root_json.status_code == 200
        assert root_json.json()["service"] == "ka-platform-admin"

        root_html = client.get("/", headers={"Accept": "text/html"})
        assert root_html.status_code == 200
        assert "플랫폼 관리 허브" in root_html.text
        assert "/web/adoption" in root_html.text

        modules = client.get("/api/public/modules")
        assert modules.status_code == 200
        module_ids = {item["id"] for item in modules.json()["modules"]}
        assert "rbac-governance" in module_ids
        assert "household-complaints" not in module_ids

        adoption_public = client.get("/api/public/adoption-plan")
        assert adoption_public.status_code == 200
        assert adoption_public.json()["title"]

        tutorial_page = client.get("/web/tutorial-simulator")
        assert tutorial_page.status_code == 200

        complaints = client.get("/api/complaints")
        assert complaints.status_code == 404
