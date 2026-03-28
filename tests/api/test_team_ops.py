from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.web.team_ops import team_ops_script_version
from tests.helpers.common import _owner_headers


def test_team_ops_page_and_script_render(app_client: TestClient) -> None:
    page = app_client.get("/web/team-ops")
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert page.headers.get("cache-control") == "no-store"
    assert page.headers.get("pragma") == "no-cache"
    assert page.headers.get("x-robots-tag") == "noindex, nofollow"
    assert "시설팀 운영" in page.text
    assert "현장기록" in page.text
    assert "시설위치" in page.text
    assert "공구/자재" in page.text
    assert "보고" in page.text
    assert "연결 확인" in page.text
    assert "토큰 보기" in page.text
    assert f"/web/team-ops/app.js?v={team_ops_script_version()}" in page.text

    asset = app_client.get(f"/web/team-ops/app.js?v={team_ops_script_version()}")
    assert asset.status_code == 200
    assert asset.headers["content-type"].startswith("application/javascript")
    assert asset.headers.get("cache-control") == "public, max-age=31536000, immutable"
    assert asset.headers.get("etag") == team_ops_script_version()
    assert asset.headers.get("x-content-type-options") == "nosniff"
    assert "kaFacility.auth.token" in asset.text
    assert "Team Ops" not in asset.text  # keep implementation-only asset compact
    assert "renderDashboard" in asset.text


def test_team_ops_dashboard_and_crud(app_client: TestClient) -> None:
    headers = _owner_headers()
    dashboard = app_client.get("/api/team-ops/dashboard?site=연산더샵&range_key=week", headers=headers)
    assert dashboard.status_code == 200
    initial_dashboard = dashboard.json()
    assert initial_dashboard["site"] == "연산더샵"
    assert initial_dashboard["range_key"] == "week"
    assert isinstance(initial_dashboard["quick_links"], list)

    recorded_at = datetime(2026, 3, 29, 1, 30, tzinfo=timezone.utc).isoformat()
    created_log = app_client.post(
        "/api/team-ops/logs",
        headers=headers,
        json={
            "site": "연산더샵",
            "recorded_at": recorded_at,
            "reporter": "김팀장",
            "category": "electrical",
            "location": "101동 전기실",
            "issue": "분전반 이상음",
            "action_taken": "점검 시작",
            "status": "in_progress",
            "priority": "high",
            "photo_count": 2,
        },
    )
    assert created_log.status_code == 201
    log_body = created_log.json()
    assert log_body["category_label"] == "전기"
    assert log_body["status_label"] == "진행중"
    assert log_body["priority_label"] == "높음"

    listed_logs = app_client.get("/api/team-ops/logs?site=연산더샵&q=분전반", headers=headers)
    assert listed_logs.status_code == 200
    assert len(listed_logs.json()) == 1

    updated_log = app_client.patch(
        f"/api/team-ops/logs/{log_body['id']}",
        headers=headers,
        json={"status": "completed", "action_taken": "패널 정비 완료"},
    )
    assert updated_log.status_code == 200
    assert updated_log.json()["status"] == "completed"

    created_facility = app_client.post(
        "/api/team-ops/facilities",
        headers=headers,
        json={
            "site": "연산더샵",
            "facility_type": "전기실",
            "location": "관리동 1층",
            "detail": "메인 분전반",
            "note": "정전 시 우선 확인",
            "is_active": True,
        },
    )
    assert created_facility.status_code == 201
    facility_body = created_facility.json()
    assert facility_body["facility_type"] == "전기실"

    updated_facility = app_client.patch(
        f"/api/team-ops/facilities/{facility_body['id']}",
        headers=headers,
        json={"note": "월간 점검 대상"},
    )
    assert updated_facility.status_code == 200
    assert updated_facility.json()["note"] == "월간 점검 대상"

    created_inventory = app_client.post(
        "/api/team-ops/inventory",
        headers=headers,
        json={
            "site": "연산더샵",
            "item_kind": "tool",
            "item_name": "테스터기",
            "stock_quantity": 2,
            "unit": "개",
            "storage_place": "공구함 B",
            "status": "needs_check",
            "note": "정확도 점검 예정",
        },
    )
    assert created_inventory.status_code == 201
    inventory_body = created_inventory.json()
    assert inventory_body["item_kind_label"] == "공구"
    assert inventory_body["status_label"] == "점검필요"

    updated_inventory = app_client.patch(
        f"/api/team-ops/inventory/{inventory_body['id']}",
        headers=headers,
        json={"status": "low_stock", "stock_quantity": 1},
    )
    assert updated_inventory.status_code == 200
    assert updated_inventory.json()["status"] == "low_stock"

    dashboard_after = app_client.get("/api/team-ops/dashboard?site=연산더샵&range_key=week", headers=headers)
    assert dashboard_after.status_code == 200
    dashboard_body = dashboard_after.json()
    assert dashboard_body["log_total"] == 1
    assert dashboard_body["log_completed"] == 1
    assert dashboard_body["facility_active"] == 1
    assert dashboard_body["inventory_attention"] == 1
    assert dashboard_body["category_counts"][0]["category"] == "electrical"

    facilities = app_client.get("/api/team-ops/facilities?site=연산더샵", headers=headers)
    assert facilities.status_code == 200
    assert len(facilities.json()) == 1

    inventory = app_client.get("/api/team-ops/inventory?site=연산더샵", headers=headers)
    assert inventory.status_code == 200
    assert len(inventory.json()) == 1

    deleted_inventory = app_client.delete(f"/api/team-ops/inventory/{inventory_body['id']}", headers=headers)
    assert deleted_inventory.status_code == 200
    assert deleted_inventory.json()["deleted"] is True

    deleted_facility = app_client.delete(f"/api/team-ops/facilities/{facility_body['id']}", headers=headers)
    assert deleted_facility.status_code == 200
    assert deleted_facility.json()["deleted"] is True

    deleted_log = app_client.delete(f"/api/team-ops/logs/{log_body['id']}", headers=headers)
    assert deleted_log.status_code == 200
    assert deleted_log.json()["deleted"] is True

    empty_logs = app_client.get("/api/team-ops/logs?site=연산더샵", headers=headers)
    assert empty_logs.status_code == 200
    assert empty_logs.json() == []
