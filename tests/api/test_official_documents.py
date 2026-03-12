from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient


def _owner_headers() -> dict[str, str]:
    return {"X-Admin-Token": "test-owner-token"}


@pytest.mark.smoke
def test_official_document_flow_and_reports(app_client: TestClient) -> None:
    headers = _owner_headers()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    month_label = now.strftime("%Y-%m")
    year_value = now.year

    inspection = app_client.post(
        "/api/inspections",
        headers=headers,
        json={
            "site": "HQ",
            "location": "B1 전기실",
            "cycle": "daily",
            "inspector": "owner_ci",
            "inspected_at": now.isoformat(),
            "notes": "official document linkage test",
        },
    )
    assert inspection.status_code == 201
    inspection_id = int(inspection.json()["id"])

    work_order = app_client.post(
        "/api/work-orders",
        headers=headers,
        json={
            "title": "공문 후속 작업",
            "description": "기관 공문 조치 확인",
            "site": "HQ",
            "location": "B1 전기실",
            "priority": "high",
            "inspection_id": inspection_id,
        },
    )
    assert work_order.status_code == 201
    work_order_id = int(work_order.json()["id"])

    created = app_client.post(
        "/api/official-documents",
        headers=headers,
        json={
            "site": "HQ",
            "organization": "한전",
            "document_number": "KEPCO-2026-0312",
            "title": "수전설비 점검 이행 공문",
            "document_type": "electricity",
            "priority": "high",
            "received_at": now.isoformat(),
            "due_at": (now + timedelta(days=7)).isoformat(),
            "required_action": "수전설비 이상 여부 확인 후 결과 회신",
            "summary": "정기 공문 접수",
            "linked_inspection_id": inspection_id,
            "linked_work_order_id": work_order_id,
        },
    )
    assert created.status_code == 201
    document_id = int(created.json()["id"])
    assert created.json()["linked_inspection_id"] == inspection_id
    assert created.json()["linked_work_order_id"] == work_order_id

    listed = app_client.get("/api/official-documents?site=HQ", headers=headers)
    assert listed.status_code == 200
    assert any(int(row["id"]) == document_id for row in listed.json())

    closed = app_client.post(
        f"/api/official-documents/{document_id}/close",
        headers=headers,
        json={
            "closed_report_title": "한전 공문 종결보고",
            "closure_summary": "현장 점검 및 작업지시 완료 후 회신 준비 완료",
            "closure_result": "이상 없음 회신",
            "closed_at": now.isoformat(),
        },
    )
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"
    assert closed.json()["closed_report_title"] == "한전 공문 종결보고"

    monthly = app_client.get(
        f"/api/reports/official-documents/monthly?site=HQ&month={month_label}",
        headers=headers,
    )
    assert monthly.status_code == 200
    monthly_body = monthly.json()
    assert monthly_body["period_type"] == "monthly"
    assert monthly_body["period_label"] == month_label
    assert monthly_body["closed_in_period"] >= 1
    assert monthly_body["linked_inspection_documents"] >= 1
    assert monthly_body["linked_work_order_documents"] >= 1
    assert any(int(entry["id"]) == document_id for entry in monthly_body["entries"])

    annual = app_client.get(
        f"/api/reports/official-documents/annual?site=HQ&year={year_value}",
        headers=headers,
    )
    assert annual.status_code == 200
    annual_body = annual.json()
    assert annual_body["period_type"] == "annual"
    assert annual_body["period_label"] == str(year_value)
    assert any(int(entry["id"]) == document_id for entry in annual_body["entries"])

    monthly_csv = app_client.get(
        f"/api/reports/official-documents/monthly/csv?site=HQ&month={month_label}",
        headers=headers,
    )
    assert monthly_csv.status_code == 200
    assert monthly_csv.headers["content-type"].startswith("text/csv")
    assert "official-document-monthly-report" in monthly_csv.headers["content-disposition"]
    assert "closure_summary" in monthly_csv.text

    monthly_print = app_client.get(
        f"/reports/official-documents/monthly/print?site=HQ&month={month_label}",
        headers=headers,
    )
    assert monthly_print.status_code == 200
    assert "Official Document Closure Report" in monthly_print.text

    service_info = app_client.get("/api/service-info")
    assert service_info.status_code == 200
    service_body = service_info.json()
    assert service_body["official_documents_api"] == "/api/official-documents"
    assert service_body["official_document_monthly_report_api"] == "/api/reports/official-documents/monthly"
    assert service_body["official_document_annual_report_print_html"] == "/reports/official-documents/annual/print"

    html_page = app_client.get("/?tab=documents", headers={"Accept": "text/html"})
    assert html_page.status_code == 200
    assert 'data-tab="documents"' in html_page.text
    assert "runOfficialDocCreateBtn" in html_page.text
    assert "officialReportMonthlyPrintLink" in html_page.text


def test_official_document_report_counts_open_overdue_items(app_client: TestClient) -> None:
    headers = _owner_headers()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    month_label = now.strftime("%Y-%m")

    created = app_client.post(
        "/api/official-documents",
        headers=headers,
        json={
            "site": "HQ",
            "organization": "수도사업소",
            "document_number": "WATER-2026-01",
            "title": "저수조 청소 결과 제출 요청",
            "document_type": "water",
            "priority": "medium",
            "received_at": now.isoformat(),
            "due_at": (now - timedelta(days=1)).isoformat(),
            "required_action": "점검 결과와 사진 제출",
            "summary": "기한 임박 공문",
        },
    )
    assert created.status_code == 201

    monthly = app_client.get(
        f"/api/reports/official-documents/monthly?site=HQ&month={month_label}",
        headers=headers,
    )
    assert monthly.status_code == 200
    body = monthly.json()
    assert body["open_documents"] >= 1
    assert body["overdue_open_documents"] >= 1
    assert body["organization_counts"]["수도사업소"] >= 1
