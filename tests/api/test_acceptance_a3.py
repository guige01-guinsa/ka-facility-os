from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from tests.helpers.common import _owner_headers


def _audit_rows_by_action(app_client: TestClient, action: str) -> list[dict[str, object]]:
    response = app_client.get(
        f"/api/admin/audit-logs?action={action}&limit=20",
        headers=_owner_headers(),
    )
    assert response.status_code == 200
    return response.json()


@pytest.mark.acceptance
def test_a3_meter_reading_to_billing_statements(app_client: TestClient) -> None:
    headers = _owner_headers()
    month_label = datetime.now(timezone.utc).strftime("%Y-%m")
    site = "A3 Billing Site"

    for payload in [
        {
            "site": site,
            "building": "101동",
            "unit_number": "1001호",
            "occupant_name": "Kim",
            "area_sqm": 84.5,
        },
        {
            "site": site,
            "building": "101동",
            "unit_number": "1002호",
            "occupant_name": "Lee",
            "area_sqm": 59.9,
        },
    ]:
        created_unit = app_client.post("/api/billing/units", headers=headers, json=payload)
        assert created_unit.status_code == 201

    policy = app_client.post(
        "/api/billing/rate-policies",
        headers=headers,
        json={
            "site": site,
            "utility_type": "electricity",
            "effective_month": month_label,
            "basic_fee": 1000,
            "unit_rate": 100,
            "sewage_rate_per_unit": 0,
            "service_fee": 500,
            "vat_rate": 0.1,
            "tiers": [],
            "notes": "A3 acceptance electricity rate",
        },
    )
    assert policy.status_code == 201

    for payload in [
        {
            "site": site,
            "billing_month": month_label,
            "utility_type": "electricity",
            "charge_category": "산업용",
            "amount": 14440,
        },
        {
            "site": site,
            "billing_month": month_label,
            "utility_type": "electricity",
            "charge_category": "승강기",
            "amount": 7220,
        },
    ]:
        common_charge = app_client.post("/api/billing/common-charges", headers=headers, json=payload)
        assert common_charge.status_code == 201

    for payload in [
        {
            "site": site,
            "building": "101동",
            "unit_number": "1001호",
            "utility_type": "electricity",
            "reading_month": month_label,
            "previous_reading": 1200,
            "current_reading": 1300,
            "reader_name": "owner_ci",
        },
        {
            "site": site,
            "building": "101동",
            "unit_number": "1002호",
            "utility_type": "electricity",
            "reading_month": month_label,
            "previous_reading": 800,
            "current_reading": 850,
            "reader_name": "owner_ci",
        },
    ]:
        created_reading = app_client.post("/api/billing/meter-readings", headers=headers, json=payload)
        assert created_reading.status_code == 201

    generated = app_client.post(
        "/api/billing/runs/generate",
        headers=headers,
        json={
            "site": site,
            "billing_month": month_label,
            "utility_type": "electricity",
            "replace_existing": True,
        },
    )
    assert generated.status_code == 200
    generated_body = generated.json()
    assert generated_body["summary"]["statement_count"] == 2
    assert generated_body["summary"]["common_charge_total"] == pytest.approx(21660.0)
    assert generated_body["summary"]["common_rate_per_sqm"] == pytest.approx(150.0)

    statements = app_client.get(
        f"/api/billing/statements?site={site}&billing_month={month_label}&utility_type=electricity",
        headers=headers,
    )
    assert statements.status_code == 200
    statement_rows = statements.json()
    assert len(statement_rows) == 2
    statement_map = {row["unit_number"]: row for row in statement_rows}
    assert statement_map["1001호"]["common_fee"] == pytest.approx(12675.0)
    assert statement_map["1002호"]["common_fee"] == pytest.approx(8985.0)
    assert statement_map["1001호"]["total_amount"] == pytest.approx(26592.5)
    assert statement_map["1002호"]["total_amount"] == pytest.approx(17033.5)
    assert len(statement_map["1001호"]["breakdown"]["common_charge_breakdown"]) == 2

    rate_logs = _audit_rows_by_action(app_client, "billing_rate_policy_create")
    assert any(
        row["resource_type"] == "billing_rate_policy"
        and row["detail"]["site"] == site
        and row["detail"]["effective_month"] == month_label
        for row in rate_logs
    )

    common_charge_logs = _audit_rows_by_action(app_client, "billing_common_charge_create")
    assert len([row for row in common_charge_logs if row["detail"]["site"] == site]) >= 2

    meter_logs = _audit_rows_by_action(app_client, "billing_meter_reading_create")
    assert len([row for row in meter_logs if row["detail"]["site"] == site]) >= 2

    run_logs = _audit_rows_by_action(app_client, "billing_run_generate")
    assert any(
        row["resource_type"] == "billing_run"
        and row["detail"]["site"] == site
        and row["detail"]["statement_count"] == 2
        and row["detail"]["billing_month"] == month_label
        for row in run_logs
    )
