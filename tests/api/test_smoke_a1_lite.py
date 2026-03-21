from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from tests.helpers.common import _build_ops_checklist_notes, _owner_headers


def _completed_count(report: dict[str, object]) -> int:
    work_orders = report.get("work_orders")
    if not isinstance(work_orders, dict):
        return 0
    status_counts = work_orders.get("status_counts")
    if not isinstance(status_counts, dict):
        return 0
    return int(status_counts.get("completed") or 0)


@pytest.mark.smoke
def test_a1_lite_smoke_flow_updates_integrated_report(app_client: TestClient) -> None:
    headers = _owner_headers()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    month_label = now.strftime("%Y-%m")
    site = "SMOKE-A1"
    location = "B1 수변전실"

    before_report = app_client.get(
        f"/api/reports/monthly/integrated?site={site}&month={month_label}",
        headers=headers,
    )
    assert before_report.status_code == 200
    before_body = before_report.json()
    before_inspection_total = int(before_body["inspections"]["total"])
    before_work_order_total = int(before_body["work_orders"]["total"])
    before_completed_total = _completed_count(before_body)

    inspection = app_client.post(
        "/api/inspections",
        headers=headers,
        json={
            "site": site,
            "location": location,
            "cycle": "monthly",
            "inspector": "smoke_ci",
            "inspected_at": now.isoformat(),
            "notes": _build_ops_checklist_notes(),
        },
    )
    assert inspection.status_code == 201
    inspection_body = inspection.json()
    inspection_id = int(inspection_body["id"])
    assert inspection_body["equipment_snapshot"] == "변압기 1호기"
    assert inspection_body["equipment_location_snapshot"] == location
    assert inspection_body["qr_id"] == "QR-002"
    assert inspection_body["checklist_set_id"] == "electrical_60"
    assert inspection_body["checklist_version"] == "tests-fixture"
    assert int(inspection_body["equipment_id"]) > 0
    assert int(inspection_body["qr_asset_id"]) > 0

    work_order = app_client.post(
        "/api/work-orders",
        headers=headers,
        json={
            "title": "A1-lite smoke remediation",
            "description": "Smoke path legal inspection follow-up",
            "site": site,
            "location": location,
            "priority": "low",
            "inspection_id": inspection_id,
        },
    )
    assert work_order.status_code == 201
    work_order_body = work_order.json()
    work_order_id = int(work_order_body["id"])
    assert work_order_body["priority"] == "critical"
    assert work_order_body["due_at"] is not None
    assert work_order_body["equipment_snapshot"] == "변압기 1호기"
    assert work_order_body["equipment_location_snapshot"] == location
    assert work_order_body["qr_id"] == "QR-002"
    assert work_order_body["checklist_set_id"] == "electrical_60"
    assert work_order_body["equipment_id"] == inspection_body["equipment_id"]
    assert work_order_body["qr_asset_id"] == inspection_body["qr_asset_id"]

    work_order_events = app_client.get(
        f"/api/work-orders/{work_order_id}/events",
        headers=headers,
    )
    assert work_order_events.status_code == 200
    created_event = work_order_events.json()[0]
    assert created_event["event_type"] == "created"
    assert created_event["detail"]["priority_upgraded"] is True
    assert created_event["detail"]["auto_due_applied"] is True

    acknowledged = app_client.patch(
        f"/api/work-orders/{work_order_id}/ack",
        headers=headers,
        json={"assignee": "Smoke Ops"},
    )
    assert acknowledged.status_code == 200
    assert acknowledged.json()["status"] == "acked"

    completed = app_client.patch(
        f"/api/work-orders/{work_order_id}/complete",
        headers=headers,
        json={"resolution_notes": "Smoke flow verified"},
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"

    after_report = app_client.get(
        f"/api/reports/monthly/integrated?site={site}&month={month_label}",
        headers=headers,
    )
    assert after_report.status_code == 200
    after_body = after_report.json()
    assert after_body["site"] == site
    assert int(after_body["inspections"]["total"]) >= before_inspection_total + 1
    assert int(after_body["work_orders"]["total"]) >= before_work_order_total + 1
    assert _completed_count(after_body) >= before_completed_total + 1
