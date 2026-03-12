import pytest
from fastapi.testclient import TestClient

from tests.helpers.common import _owner_headers


@pytest.mark.smoke
def test_billing_electricity_run_allocates_common_charge_by_area(app_client: TestClient) -> None:
    headers = _owner_headers()

    for payload in [
        {
            "site": "HQ",
            "building": "101동",
            "unit_number": "1001호",
            "occupant_name": "Kim",
            "area_sqm": 84.5,
        },
        {
            "site": "HQ",
            "building": "101동",
            "unit_number": "1002호",
            "occupant_name": "Lee",
            "area_sqm": 59.9,
        },
    ]:
        created = app_client.post("/api/billing/units", headers=headers, json=payload)
        assert created.status_code == 201

    policy = app_client.post(
        "/api/billing/rate-policies",
        headers=headers,
        json={
            "site": "HQ",
            "utility_type": "electricity",
            "effective_month": "2026-03",
            "basic_fee": 1000,
            "unit_rate": 100,
            "sewage_rate_per_unit": 0,
            "service_fee": 500,
            "vat_rate": 0.1,
            "tiers": [],
            "notes": "전기 기본요금",
        },
    )
    assert policy.status_code == 201

    for payload in [
        {
            "site": "HQ",
            "billing_month": "2026-03",
            "utility_type": "electricity",
            "charge_category": "산업용",
            "amount": 14440,
        },
        {
            "site": "HQ",
            "billing_month": "2026-03",
            "utility_type": "electricity",
            "charge_category": "승강기",
            "amount": 7220,
        },
    ]:
        created = app_client.post("/api/billing/common-charges", headers=headers, json=payload)
        assert created.status_code == 201

    for payload in [
        {
            "site": "HQ",
            "building": "101동",
            "unit_number": "1001호",
            "utility_type": "electricity",
            "reading_month": "2026-03",
            "previous_reading": 1200,
            "current_reading": 1300,
            "reader_name": "owner_ci",
        },
        {
            "site": "HQ",
            "building": "101동",
            "unit_number": "1002호",
            "utility_type": "electricity",
            "reading_month": "2026-03",
            "previous_reading": 800,
            "current_reading": 850,
            "reader_name": "owner_ci",
        },
    ]:
        created = app_client.post("/api/billing/meter-readings", headers=headers, json=payload)
        assert created.status_code == 201

    generated = app_client.post(
        "/api/billing/runs/generate",
        headers=headers,
        json={
            "site": "HQ",
            "billing_month": "2026-03",
            "utility_type": "electricity",
            "replace_existing": True,
        },
    )
    assert generated.status_code == 200
    body = generated.json()
    assert body["summary"]["statement_count"] == 2
    assert body["summary"]["common_charge_total"] == pytest.approx(21660.0)
    assert body["summary"]["common_rate_per_sqm"] == pytest.approx(150.0)

    statements = {row["unit_number"]: row for row in body["statements"]}
    assert statements["1001호"]["common_fee"] == pytest.approx(12675.0)
    assert statements["1002호"]["common_fee"] == pytest.approx(8985.0)
    assert statements["1001호"]["total_amount"] == pytest.approx(26592.5)
    assert statements["1002호"]["total_amount"] == pytest.approx(17033.5)
    assert len(statements["1001호"]["breakdown"]["common_charge_breakdown"]) == 2


def test_billing_water_run_allocates_common_charge_by_area(app_client: TestClient) -> None:
    headers = _owner_headers()

    for payload in [
        {
            "site": "WATER",
            "building": "201동",
            "unit_number": "101호",
            "occupant_name": "Park",
            "area_sqm": 84,
        },
        {
            "site": "WATER",
            "building": "201동",
            "unit_number": "102호",
            "occupant_name": "Choi",
            "area_sqm": 60,
        },
    ]:
        created = app_client.post("/api/billing/units", headers=headers, json=payload)
        assert created.status_code == 201

    policy = app_client.post(
        "/api/billing/rate-policies",
        headers=headers,
        json={
            "site": "WATER",
            "utility_type": "water",
            "effective_month": "2026-03",
            "basic_fee": 0,
            "unit_rate": 700,
            "sewage_rate_per_unit": 300,
            "service_fee": 0,
            "vat_rate": 0,
            "tiers": [],
            "notes": "수도요금",
        },
    )
    assert policy.status_code == 201

    common = app_client.post(
        "/api/billing/common-charges",
        headers=headers,
        json={
            "site": "WATER",
            "billing_month": "2026-03",
            "utility_type": "water",
            "charge_category": "공용수도",
            "amount": 14400,
        },
    )
    assert common.status_code == 201

    for payload in [
        {
            "site": "WATER",
            "building": "201동",
            "unit_number": "101호",
            "utility_type": "water",
            "reading_month": "2026-03",
            "previous_reading": 50,
            "current_reading": 70,
            "reader_name": "owner_ci",
        },
        {
            "site": "WATER",
            "building": "201동",
            "unit_number": "102호",
            "utility_type": "water",
            "reading_month": "2026-03",
            "previous_reading": 30,
            "current_reading": 40,
            "reader_name": "owner_ci",
        },
    ]:
        created = app_client.post("/api/billing/meter-readings", headers=headers, json=payload)
        assert created.status_code == 201

    generated = app_client.post(
        "/api/billing/runs/generate",
        headers=headers,
        json={
            "site": "WATER",
            "billing_month": "2026-03",
            "utility_type": "water",
            "replace_existing": True,
        },
    )
    assert generated.status_code == 200
    body = generated.json()
    statements = {row["unit_number"]: row for row in body["statements"]}
    assert body["summary"]["common_rate_per_sqm"] == pytest.approx(100.0)
    assert statements["101호"]["common_fee"] == pytest.approx(8400.0)
    assert statements["102호"]["common_fee"] == pytest.approx(6000.0)
    assert statements["101호"]["total_amount"] == pytest.approx(28400.0)
    assert statements["102호"]["total_amount"] == pytest.approx(16000.0)


def test_billing_service_info_and_main_tab_exposed(app_client: TestClient) -> None:
    service_info = app_client.get("/api/service-info")
    assert service_info.status_code == 200
    body = service_info.json()
    assert body["billing_units_api"] == "/api/billing/units"
    assert body["billing_common_charges_api"] == "/api/billing/common-charges"
    assert body["billing_generate_run_api"] == "/api/billing/runs/generate"
    assert body["billing_statements_api"] == "/api/billing/statements"

    root_html = app_client.get("/", headers={"Accept": "text/html"})
    assert root_html.status_code == 200
    assert 'data-tab="billing"' in root_html.text
    assert "요금부과" in root_html.text
    assert "공용전기" in root_html.text
    assert "공용수도" in root_html.text
