from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from tests.helpers.common import _build_ops_checklist_notes, _owner_headers


def _issue_role_headers(
    app_client: TestClient,
    *,
    username: str,
    display_name: str,
    role: str,
    site_scope: list[str],
) -> dict[str, str]:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": username,
            "display_name": display_name,
            "role": role,
            "permissions": [],
            "site_scope": site_scope,
        },
    )
    assert created.status_code == 201
    user_id = int(created.json()["id"])
    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": f"{username}-token"},
    )
    assert issued.status_code == 201
    return {"X-Admin-Token": issued.json()["token"]}


def _create_inspection(
    app_client: TestClient,
    headers: dict[str, str],
    *,
    site: str,
    location: str,
) -> int:
    response = app_client.post(
        "/api/inspections",
        headers=headers,
        json={
            "site": site,
            "location": location,
            "cycle": "monthly",
            "inspector": "role_matrix",
            "inspected_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "notes": _build_ops_checklist_notes(),
        },
    )
    assert response.status_code == 201
    return int(response.json()["id"])


def _create_work_order(
    app_client: TestClient,
    headers: dict[str, str],
    *,
    site: str,
    location: str,
    inspection_id: int,
    title: str,
) -> int:
    response = app_client.post(
        "/api/work-orders",
        headers=headers,
        json={
            "title": title,
            "description": "role matrix work order",
            "site": site,
            "location": location,
            "priority": "low",
            "inspection_id": inspection_id,
        },
    )
    assert response.status_code == 201
    return int(response.json()["id"])


def _seed_billing_flow(
    app_client: TestClient,
    headers: dict[str, str],
    *,
    site: str,
    month_label: str,
    building: str,
) -> None:
    for payload in [
        {
            "site": site,
            "building": building,
            "unit_number": "1001호",
            "occupant_name": "Kim",
            "area_sqm": 84.5,
        },
        {
            "site": site,
            "building": building,
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
            "notes": "role matrix billing rate",
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
            "building": building,
            "unit_number": "1001호",
            "utility_type": "electricity",
            "reading_month": month_label,
            "previous_reading": 1200,
            "current_reading": 1300,
            "reader_name": "role_matrix",
        },
        {
            "site": site,
            "building": building,
            "unit_number": "1002호",
            "utility_type": "electricity",
            "reading_month": month_label,
            "previous_reading": 800,
            "current_reading": 850,
            "reader_name": "role_matrix",
        },
    ]:
        reading = app_client.post("/api/billing/meter-readings", headers=headers, json=payload)
        assert reading.status_code == 201

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


@pytest.mark.acceptance
def test_a1_role_matrix_by_endpoint(app_client: TestClient) -> None:
    month_label = datetime.now(timezone.utc).strftime("%Y-%m")
    manager_site = "A1 Matrix Manager Site"
    operator_site = "A1 Matrix Operator Site"
    auditor_site = "A1 Matrix Auditor Site"
    location = "B1 수변전실"

    manager_headers = _issue_role_headers(
        app_client,
        username="a1_manager_ci",
        display_name="A1 Manager CI",
        role="manager",
        site_scope=[manager_site],
    )
    operator_headers = _issue_role_headers(
        app_client,
        username="a1_operator_ci",
        display_name="A1 Operator CI",
        role="operator",
        site_scope=[operator_site],
    )
    auditor_headers = _issue_role_headers(
        app_client,
        username="a1_auditor_ci",
        display_name="A1 Auditor CI",
        role="auditor",
        site_scope=[auditor_site],
    )

    owner_inspection_id = _create_inspection(app_client, _owner_headers(), site=auditor_site, location=location)
    owner_work_order_id = _create_work_order(
        app_client,
        _owner_headers(),
        site=auditor_site,
        location=location,
        inspection_id=owner_inspection_id,
        title="A1 owner seed work order",
    )

    manager_inspection_id = _create_inspection(app_client, manager_headers, site=manager_site, location=location)
    manager_work_order_id = _create_work_order(
        app_client,
        manager_headers,
        site=manager_site,
        location=location,
        inspection_id=manager_inspection_id,
        title="A1 manager work order",
    )
    manager_ack = app_client.patch(
        f"/api/work-orders/{manager_work_order_id}/ack",
        headers=manager_headers,
        json={"assignee": "Manager Ops"},
    )
    assert manager_ack.status_code == 200
    manager_complete = app_client.patch(
        f"/api/work-orders/{manager_work_order_id}/complete",
        headers=manager_headers,
        json={"resolution_notes": "manager completed"},
    )
    assert manager_complete.status_code == 200
    manager_report = app_client.get(
        f"/api/reports/monthly/integrated?site={manager_site}&month={month_label}",
        headers=manager_headers,
    )
    assert manager_report.status_code == 200
    manager_report_csv = app_client.get(
        f"/api/reports/monthly/integrated/csv?site={manager_site}&month={month_label}",
        headers=manager_headers,
    )
    assert manager_report_csv.status_code == 200
    manager_audit_logs = app_client.get("/api/admin/audit-logs", headers=manager_headers)
    assert manager_audit_logs.status_code == 403

    operator_inspection_id = _create_inspection(app_client, operator_headers, site=operator_site, location=location)
    operator_work_order_id = _create_work_order(
        app_client,
        operator_headers,
        site=operator_site,
        location=location,
        inspection_id=operator_inspection_id,
        title="A1 operator work order",
    )
    operator_ack = app_client.patch(
        f"/api/work-orders/{operator_work_order_id}/ack",
        headers=operator_headers,
        json={"assignee": "Operator Ops"},
    )
    assert operator_ack.status_code == 200
    operator_complete = app_client.patch(
        f"/api/work-orders/{operator_work_order_id}/complete",
        headers=operator_headers,
        json={"resolution_notes": "operator completed"},
    )
    assert operator_complete.status_code == 200
    operator_report = app_client.get(
        f"/api/reports/monthly/integrated?site={operator_site}&month={month_label}",
        headers=operator_headers,
    )
    assert operator_report.status_code == 403
    operator_report_csv = app_client.get(
        f"/api/reports/monthly/integrated/csv?site={operator_site}&month={month_label}",
        headers=operator_headers,
    )
    assert operator_report_csv.status_code == 403
    operator_audit_logs = app_client.get("/api/admin/audit-logs", headers=operator_headers)
    assert operator_audit_logs.status_code == 403

    auditor_inspection = app_client.get(
        f"/api/inspections/{owner_inspection_id}",
        headers=auditor_headers,
    )
    assert auditor_inspection.status_code == 200
    auditor_work_order = app_client.get(
        f"/api/work-orders/{owner_work_order_id}",
        headers=auditor_headers,
    )
    assert auditor_work_order.status_code == 200
    auditor_report = app_client.get(
        f"/api/reports/monthly/integrated?site={auditor_site}&month={month_label}",
        headers=auditor_headers,
    )
    assert auditor_report.status_code == 200
    auditor_report_csv = app_client.get(
        f"/api/reports/monthly/integrated/csv?site={auditor_site}&month={month_label}",
        headers=auditor_headers,
    )
    assert auditor_report_csv.status_code == 200
    auditor_create_inspection = app_client.post(
        "/api/inspections",
        headers=auditor_headers,
        json={
            "site": auditor_site,
            "location": location,
            "cycle": "monthly",
            "inspector": "auditor",
            "inspected_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "notes": _build_ops_checklist_notes(),
        },
    )
    assert auditor_create_inspection.status_code == 403
    auditor_ack = app_client.patch(
        f"/api/work-orders/{owner_work_order_id}/ack",
        headers=auditor_headers,
        json={"assignee": "Auditor"},
    )
    assert auditor_ack.status_code == 403
    auditor_audit_logs = app_client.get("/api/admin/audit-logs", headers=auditor_headers)
    assert auditor_audit_logs.status_code == 403


@pytest.mark.acceptance
def test_a2_role_matrix_by_endpoint(app_client: TestClient) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    month_label = now.strftime("%Y-%m")
    manager_site = "A2 Matrix Manager Site"
    operator_site = "A2 Matrix Operator Site"
    auditor_site = "A2 Matrix Auditor Site"

    manager_headers = _issue_role_headers(
        app_client,
        username="a2_manager_ci",
        display_name="A2 Manager CI",
        role="manager",
        site_scope=[manager_site],
    )
    operator_headers = _issue_role_headers(
        app_client,
        username="a2_operator_ci",
        display_name="A2 Operator CI",
        role="operator",
        site_scope=[operator_site],
    )
    auditor_headers = _issue_role_headers(
        app_client,
        username="a2_auditor_ci",
        display_name="A2 Auditor CI",
        role="auditor",
        site_scope=[auditor_site],
    )

    owner_document = app_client.post(
        "/api/official-documents",
        headers=_owner_headers(),
        json={
            "site": auditor_site,
            "organization": "한전",
            "document_number": "A2-MATRIX-AUDITOR",
            "title": "A2 auditor seed document",
            "document_type": "electricity",
            "priority": "critical",
            "received_at": now.isoformat(),
            "due_at": (now - timedelta(days=2)).isoformat(),
            "required_action": "auditor role matrix seed",
            "summary": "auditor seed",
        },
    )
    assert owner_document.status_code == 201
    owner_document_id = int(owner_document.json()["id"])
    owner_attachment = app_client.post(
        f"/api/official-documents/{owner_document_id}/attachments",
        headers=_owner_headers(),
        data={"note": "auditor seed"},
        files={"file": ("auditor-seed.pdf", b"%PDF-1.4 auditor seed", "application/pdf")},
    )
    assert owner_attachment.status_code == 201
    owner_attachment_id = int(owner_attachment.json()["id"])
    owner_close = app_client.post(
        f"/api/official-documents/{owner_document_id}/close",
        headers=_owner_headers(),
        json={
            "closed_report_title": "Auditor seed close",
            "closure_summary": "auditor read path",
            "closure_result": "done",
            "closed_at": now.isoformat(),
        },
    )
    assert owner_close.status_code == 200

    manager_document = app_client.post(
        "/api/official-documents",
        headers=manager_headers,
        json={
            "site": manager_site,
            "organization": "한전",
            "document_number": "A2-MATRIX-MANAGER",
            "title": "A2 manager document",
            "document_type": "electricity",
            "priority": "critical",
            "received_at": now.isoformat(),
            "due_at": (now - timedelta(days=2)).isoformat(),
            "required_action": "manager overdue sync",
            "summary": "manager matrix",
        },
    )
    assert manager_document.status_code == 201
    manager_document_id = int(manager_document.json()["id"])
    manager_attachment = app_client.post(
        f"/api/official-documents/{manager_document_id}/attachments",
        headers=manager_headers,
        data={"note": "manager attachment"},
        files={"file": ("manager.pdf", b"%PDF-1.4 manager", "application/pdf")},
    )
    assert manager_attachment.status_code == 201
    manager_overdue = app_client.post(
        f"/api/official-documents/overdue/run?site={manager_site}&limit=20",
        headers=manager_headers,
    )
    assert manager_overdue.status_code == 200
    manager_close = app_client.post(
        f"/api/official-documents/{manager_document_id}/close",
        headers=manager_headers,
        json={
            "closed_report_title": "Manager close",
            "closure_summary": "manager done",
            "closure_result": "done",
            "closed_at": now.isoformat(),
        },
    )
    assert manager_close.status_code == 200
    manager_report = app_client.get(
        f"/api/reports/official-documents/monthly?site={manager_site}&month={month_label}",
        headers=manager_headers,
    )
    assert manager_report.status_code == 200
    manager_report_csv = app_client.get(
        f"/api/reports/official-documents/monthly/csv?site={manager_site}&month={month_label}",
        headers=manager_headers,
    )
    assert manager_report_csv.status_code == 200
    manager_audit_logs = app_client.get("/api/admin/audit-logs", headers=manager_headers)
    assert manager_audit_logs.status_code == 403

    operator_document = app_client.post(
        "/api/official-documents",
        headers=operator_headers,
        json={
            "site": operator_site,
            "organization": "한전",
            "document_number": "A2-MATRIX-OPERATOR",
            "title": "A2 operator document",
            "document_type": "electricity",
            "priority": "critical",
            "received_at": now.isoformat(),
            "due_at": (now - timedelta(days=2)).isoformat(),
            "required_action": "operator overdue sync",
            "summary": "operator matrix",
        },
    )
    assert operator_document.status_code == 201
    operator_document_id = int(operator_document.json()["id"])
    operator_attachment = app_client.post(
        f"/api/official-documents/{operator_document_id}/attachments",
        headers=operator_headers,
        data={"note": "operator attachment"},
        files={"file": ("operator.pdf", b"%PDF-1.4 operator", "application/pdf")},
    )
    assert operator_attachment.status_code == 201
    operator_overdue = app_client.post(
        f"/api/official-documents/overdue/run?site={operator_site}&limit=20",
        headers=operator_headers,
    )
    assert operator_overdue.status_code == 200
    operator_close = app_client.post(
        f"/api/official-documents/{operator_document_id}/close",
        headers=operator_headers,
        json={
            "closed_report_title": "Operator close",
            "closure_summary": "operator done",
            "closure_result": "done",
            "closed_at": now.isoformat(),
        },
    )
    assert operator_close.status_code == 200
    operator_report = app_client.get(
        f"/api/reports/official-documents/monthly?site={operator_site}&month={month_label}",
        headers=operator_headers,
    )
    assert operator_report.status_code == 403
    operator_report_csv = app_client.get(
        f"/api/reports/official-documents/monthly/csv?site={operator_site}&month={month_label}",
        headers=operator_headers,
    )
    assert operator_report_csv.status_code == 403
    operator_audit_logs = app_client.get("/api/admin/audit-logs", headers=operator_headers)
    assert operator_audit_logs.status_code == 403

    auditor_document = app_client.get(
        f"/api/official-documents/{owner_document_id}",
        headers=auditor_headers,
    )
    assert auditor_document.status_code == 200
    auditor_attachment_list = app_client.get(
        f"/api/official-documents/{owner_document_id}/attachments",
        headers=auditor_headers,
    )
    assert auditor_attachment_list.status_code == 200
    auditor_attachment_download = app_client.get(
        f"/api/official-documents/attachments/{owner_attachment_id}/download",
        headers=auditor_headers,
    )
    assert auditor_attachment_download.status_code == 200
    auditor_report = app_client.get(
        f"/api/reports/official-documents/monthly?site={auditor_site}&month={month_label}",
        headers=auditor_headers,
    )
    assert auditor_report.status_code == 200
    auditor_report_csv = app_client.get(
        f"/api/reports/official-documents/monthly/csv?site={auditor_site}&month={month_label}",
        headers=auditor_headers,
    )
    assert auditor_report_csv.status_code == 200
    auditor_create_document = app_client.post(
        "/api/official-documents",
        headers=auditor_headers,
        json={
            "site": auditor_site,
            "organization": "한전",
            "title": "auditor forbidden",
            "document_type": "electricity",
            "priority": "medium",
            "received_at": now.isoformat(),
            "required_action": "forbidden",
            "summary": "forbidden",
        },
    )
    assert auditor_create_document.status_code == 403
    auditor_upload = app_client.post(
        f"/api/official-documents/{owner_document_id}/attachments",
        headers=auditor_headers,
        data={"note": "forbidden"},
        files={"file": ("forbidden.pdf", b"%PDF-1.4 forbidden", "application/pdf")},
    )
    assert auditor_upload.status_code == 403
    auditor_overdue = app_client.post(
        f"/api/official-documents/overdue/run?site={auditor_site}&limit=20",
        headers=auditor_headers,
    )
    assert auditor_overdue.status_code == 403
    auditor_close = app_client.post(
        f"/api/official-documents/{owner_document_id}/close",
        headers=auditor_headers,
        json={
            "closed_report_title": "forbidden",
            "closure_summary": "forbidden",
            "closure_result": "forbidden",
            "closed_at": now.isoformat(),
        },
    )
    assert auditor_close.status_code == 403
    auditor_audit_logs = app_client.get("/api/admin/audit-logs", headers=auditor_headers)
    assert auditor_audit_logs.status_code == 403


@pytest.mark.acceptance
def test_a3_role_matrix_by_endpoint(app_client: TestClient) -> None:
    month_label = datetime.now(timezone.utc).strftime("%Y-%m")
    manager_site = "A3 Matrix Manager Site"
    operator_site = "A3 Matrix Operator Site"
    auditor_site = "A3 Matrix Auditor Site"

    manager_headers = _issue_role_headers(
        app_client,
        username="a3_manager_ci",
        display_name="A3 Manager CI",
        role="manager",
        site_scope=[manager_site],
    )
    operator_headers = _issue_role_headers(
        app_client,
        username="a3_operator_ci",
        display_name="A3 Operator CI",
        role="operator",
        site_scope=[operator_site],
    )
    auditor_headers = _issue_role_headers(
        app_client,
        username="a3_auditor_ci",
        display_name="A3 Auditor CI",
        role="auditor",
        site_scope=[auditor_site],
    )

    _seed_billing_flow(app_client, manager_headers, site=manager_site, month_label=month_label, building="201동")
    manager_statements = app_client.get(
        f"/api/billing/statements?site={manager_site}&billing_month={month_label}&utility_type=electricity",
        headers=manager_headers,
    )
    assert manager_statements.status_code == 200
    assert len(manager_statements.json()) == 2
    manager_audit_logs = app_client.get("/api/admin/audit-logs", headers=manager_headers)
    assert manager_audit_logs.status_code == 403

    _seed_billing_flow(app_client, operator_headers, site=operator_site, month_label=month_label, building="202동")
    operator_statements = app_client.get(
        f"/api/billing/statements?site={operator_site}&billing_month={month_label}&utility_type=electricity",
        headers=operator_headers,
    )
    assert operator_statements.status_code == 200
    assert len(operator_statements.json()) == 2
    operator_audit_logs = app_client.get("/api/admin/audit-logs", headers=operator_headers)
    assert operator_audit_logs.status_code == 403

    _seed_billing_flow(app_client, _owner_headers(), site=auditor_site, month_label=month_label, building="203동")
    auditor_statements = app_client.get(
        f"/api/billing/statements?site={auditor_site}&billing_month={month_label}&utility_type=electricity",
        headers=auditor_headers,
    )
    assert auditor_statements.status_code == 200
    assert len(auditor_statements.json()) == 2
    auditor_rate_policies = app_client.get(
        f"/api/billing/rate-policies?site={auditor_site}&utility_type=electricity",
        headers=auditor_headers,
    )
    assert auditor_rate_policies.status_code == 200
    auditor_meter_readings = app_client.get(
        f"/api/billing/meter-readings?site={auditor_site}&building=203동&utility_type=electricity&reading_month={month_label}",
        headers=auditor_headers,
    )
    assert auditor_meter_readings.status_code == 200
    assert len(auditor_meter_readings.json()) == 2
    auditor_create_unit = app_client.post(
        "/api/billing/units",
        headers=auditor_headers,
        json={
            "site": auditor_site,
            "building": "203동",
            "unit_number": "1003호",
            "occupant_name": "Forbidden",
            "area_sqm": 50.0,
        },
    )
    assert auditor_create_unit.status_code == 403
    auditor_create_reading = app_client.post(
        "/api/billing/meter-readings",
        headers=auditor_headers,
        json={
            "site": auditor_site,
            "building": "203동",
            "unit_number": "1001호",
            "utility_type": "electricity",
            "reading_month": month_label,
            "previous_reading": 1300,
            "current_reading": 1400,
            "reader_name": "auditor",
        },
    )
    assert auditor_create_reading.status_code == 403
    auditor_generate_run = app_client.post(
        "/api/billing/runs/generate",
        headers=auditor_headers,
        json={
            "site": auditor_site,
            "billing_month": month_label,
            "utility_type": "electricity",
            "replace_existing": True,
        },
    )
    assert auditor_generate_run.status_code == 403
    auditor_audit_logs = app_client.get("/api/admin/audit-logs", headers=auditor_headers)
    assert auditor_audit_logs.status_code == 403
