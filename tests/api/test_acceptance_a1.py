from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from tests.helpers.common import _build_ops_checklist_notes, _owner_headers


def _audit_rows_by_action(app_client: TestClient, action: str) -> list[dict[str, object]]:
    response = app_client.get(
        f"/api/admin/audit-logs?action={action}&limit=20",
        headers=_owner_headers(),
    )
    assert response.status_code == 200
    return response.json()


@pytest.mark.acceptance
def test_a1_legal_inspection_to_integrated_report(app_client: TestClient) -> None:
    headers = _owner_headers()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    month_label = now.strftime("%Y-%m")
    site = "A1 Acceptance Site"
    location = "B1 수변전실"

    inspection = app_client.post(
        "/api/inspections",
        headers=headers,
        json={
            "site": site,
            "location": location,
            "cycle": "monthly",
            "inspector": "owner_ci",
            "inspected_at": now.isoformat(),
            "notes": _build_ops_checklist_notes(),
        },
    )
    assert inspection.status_code == 201
    inspection_body = inspection.json()
    inspection_id = int(inspection_body["id"])
    assert inspection_body["site"] == site
    assert inspection_body["location"] == location
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
            "title": "A1 이상조치 작업지시",
            "description": "법정점검 이상 항목 후속 조치",
            "site": site,
            "location": location,
            "priority": "low",
            "inspection_id": inspection_id,
        },
    )
    assert work_order.status_code == 201
    work_order_body = work_order.json()
    work_order_id = int(work_order_body["id"])
    assert work_order_body["inspection_id"] == inspection_id
    assert work_order_body["priority"] == "critical"
    assert work_order_body["status"] == "open"
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
    assert created_event["detail"]["requested_priority"] == "low"
    assert created_event["detail"]["priority"] == "critical"
    assert created_event["detail"]["priority_upgraded"] is True
    assert created_event["detail"]["auto_due_applied"] is True
    assert int(created_event["detail"]["due_hours_applied"]) > 0

    acknowledged = app_client.patch(
        f"/api/work-orders/{work_order_id}/ack",
        headers=headers,
        json={"assignee": "Ops Team Alpha"},
    )
    assert acknowledged.status_code == 200
    assert acknowledged.json()["status"] == "acked"
    assert acknowledged.json()["assignee"] == "Ops Team Alpha"

    completed = app_client.patch(
        f"/api/work-orders/{work_order_id}/complete",
        headers=headers,
        json={"resolution_notes": "이상 조치 완료 및 재점검 예정"},
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"
    assert completed.json()["resolution_notes"] == "이상 조치 완료 및 재점검 예정"

    inspection_logs = _audit_rows_by_action(app_client, "inspection_create")
    assert any(
        row["resource_type"] == "inspection"
        and row["resource_id"] == str(inspection_id)
        and row["detail"]["site"] == site
        for row in inspection_logs
    )

    work_order_create_logs = _audit_rows_by_action(app_client, "work_order_create")
    assert any(
        row["resource_type"] == "work_order"
        and row["resource_id"] == str(work_order_id)
        and row["detail"]["priority"] == "critical"
        and row["detail"]["auto_due_applied"] is True
        for row in work_order_create_logs
    )

    work_order_ack_logs = _audit_rows_by_action(app_client, "work_order_ack")
    assert any(
        row["resource_type"] == "work_order"
        and row["resource_id"] == str(work_order_id)
        and row["detail"]["status"] == "acked"
        for row in work_order_ack_logs
    )

    work_order_complete_logs = _audit_rows_by_action(app_client, "work_order_complete")
    assert any(
        row["resource_type"] == "work_order"
        and row["resource_id"] == str(work_order_id)
        and row["detail"]["status"] == "completed"
        for row in work_order_complete_logs
    )

    integrated = app_client.get(
        f"/api/reports/monthly/integrated?site={site}&month={month_label}",
        headers=headers,
    )
    assert integrated.status_code == 200
    integrated_body = integrated.json()
    assert integrated_body["period_type"] == "monthly"
    assert integrated_body["period_label"] == month_label
    assert integrated_body["month"] == month_label
    assert integrated_body["site"] == site
    assert integrated_body["inspections"]["total"] >= 1
    assert integrated_body["work_orders"]["total"] >= 1
    assert integrated_body["work_orders"]["status_counts"]["completed"] >= 1
    assert integrated_body["work_orders"]["completion_rate_percent"] > 0
    assert integrated_body["official_documents"]["total_documents"] == 0
    assert integrated_body["billing"]["statement_count"] == 0
