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

def test_api_rate_limit_auth_heavy_policy_enforced(strict_rate_limit_client: TestClient) -> None:
    headers = _owner_headers()
    first = strict_rate_limit_client.get(
        "/api/adoption/w07/tracker/completion-package?site=HQ",
        headers=headers,
    )
    second = strict_rate_limit_client.get(
        "/api/adoption/w07/tracker/completion-package?site=HQ",
        headers=headers,
    )
    third = strict_rate_limit_client.get(
        "/api/adoption/w07/tracker/completion-package?site=HQ",
        headers=headers,
    )

    assert first.status_code == 200
    assert first.headers.get("content-type", "").startswith("application/zip")
    assert second.status_code == 200
    assert third.status_code == 429
    assert third.headers.get("x-ratelimit-policy") == "auth-heavy"
    assert third.headers.get("x-ratelimit-limit") == "2"

def test_evidence_storage_path_traversal_blocked(app_client: TestClient) -> None:
    import app.main as main_module

    safe = main_module._resolve_evidence_storage_abs_path("2026/03/01/sample.txt")
    assert safe is not None
    assert safe.is_absolute()

    assert main_module._resolve_evidence_storage_abs_path("../escape.txt") is None
    assert main_module._resolve_evidence_storage_abs_path("..\\escape.txt") is None
    assert main_module._resolve_evidence_storage_abs_path("/etc/passwd") is None
    assert main_module._resolve_evidence_storage_abs_path("\\\\server\\share\\file.txt") is None
