from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient


def _owner_headers() -> dict[str, str]:
    return {"X-Admin-Token": "test-owner-token"}


def _build_asset_scoped_ops_notes(
    *,
    equipment: str,
    equipment_location: str,
    qr_id: str,
    checklist_set_id: str = "electrical_60",
    checklist_version: str = "tests-fixture",
) -> str:
    meta = {
        "task_type": "전기점검",
        "equipment": equipment,
        "equipment_location": equipment_location,
        "qr_id": qr_id,
        "checklist_set_id": checklist_set_id,
        "checklist_data_version": checklist_version,
        "summary": {"total": 3, "normal": 0, "abnormal": 3, "na": 0},
        "abnormal_action": "자산 pivot 통합리포트 검증",
    }
    checklist = [
        {"group": "설비", "item": "변압기 외관 점검", "result": "abnormal", "action": ""},
        {"group": "설비", "item": "변압기 온도 상승 여부 확인", "result": "abnormal", "action": ""},
        {"group": "설비", "item": "변압기 이상 소음 확인", "result": "abnormal", "action": ""},
    ]
    return "\n".join(
        [
            "[OPS_CHECKLIST_V1]",
            "meta=" + json.dumps(meta, ensure_ascii=False),
            "checklist=" + json.dumps(checklist, ensure_ascii=False),
        ]
    )


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
    assert created.json()["registry_number"].startswith("한전-HQ-")
    assert created.json()["organization_code"] == "한전"
    assert created.json()["linked_inspection_id"] == inspection_id
    assert created.json()["linked_work_order_id"] == work_order_id

    uploaded = app_client.post(
        f"/api/official-documents/{document_id}/attachments",
        headers=headers,
        data={"note": "원본 스캔본"},
        files={"file": ("kepco-origin.pdf", b"%PDF-1.4 official document", "application/pdf")},
    )
    assert uploaded.status_code == 201
    attachment_id = int(uploaded.json()["id"])
    assert uploaded.json()["file_name"] == "kepco-origin.pdf"

    attachments = app_client.get(
        f"/api/official-documents/{document_id}/attachments",
        headers=headers,
    )
    assert attachments.status_code == 200
    assert len(attachments.json()) == 1
    assert attachments.json()[0]["note"] == "원본 스캔본"

    downloaded = app_client.get(
        f"/api/official-documents/attachments/{attachment_id}/download",
        headers=headers,
    )
    assert downloaded.status_code == 200
    assert downloaded.content == b"%PDF-1.4 official document"
    assert len(downloaded.headers["x-attachment-sha256"]) == 64

    attachment_zip = app_client.get(
        f"/api/official-documents/attachments/zip?site=HQ&organization=%ED%95%9C%EC%A0%84&month={month_label}",
        headers=headers,
    )
    assert attachment_zip.status_code == 200
    assert attachment_zip.headers["content-type"].startswith("application/zip")
    with zipfile.ZipFile(io.BytesIO(attachment_zip.content)) as archive:
        names = archive.namelist()
        assert "manifest.csv" in names
        assert "00_cover_sheet.pdf" in names
        assert archive.read("00_cover_sheet.pdf").startswith(b"%PDF")
        assert any(name.endswith("kepco-origin.pdf") for name in names)
        assert any("/한전/" in name and f"/{month_label}/" in name for name in names)
        manifest_text = archive.read("manifest.csv").decode("utf-8")
        assert "registry_number" in manifest_text
        assert "kepco-origin.pdf" in manifest_text

    registry_csv = app_client.get(
        f"/api/official-documents/registry/csv?site=HQ&organization=%ED%95%9C%EC%A0%84&month={month_label}",
        headers=headers,
    )
    assert registry_csv.status_code == 200
    assert registry_csv.headers["content-type"].startswith("text/csv")
    assert "official-document-registry" in registry_csv.headers["content-disposition"]
    assert "registry_number" in registry_csv.text
    assert "KEPCO-2026-0312" in registry_csv.text

    listed = app_client.get("/api/official-documents?site=HQ", headers=headers)
    assert listed.status_code == 200
    assert any(int(row["id"]) == document_id for row in listed.json())
    listed_map = {int(row["id"]): row for row in listed.json()}
    assert listed_map[document_id]["attachment_count"] == 1

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
    assert any(int(entry["id"]) == document_id and int(entry["attachment_count"]) == 1 for entry in monthly_body["entries"])

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

    overdue_created = app_client.post(
        "/api/official-documents",
        headers=headers,
        json={
            "site": "HQ",
            "organization": "소방서",
            "title": "소방 펌프실 보완 요청",
            "document_type": "fire",
            "priority": "critical",
            "received_at": now.isoformat(),
            "due_at": (now - timedelta(days=2)).isoformat(),
            "required_action": "기한 초과 공문 자동화 점검",
            "summary": "자동 생성 대상",
        },
    )
    assert overdue_created.status_code == 201
    overdue_document_id = int(overdue_created.json()["id"])
    overdue_sync = app_client.post(
        "/api/official-documents/overdue/run?site=HQ&limit=20",
        headers=headers,
    )
    assert overdue_sync.status_code == 200
    overdue_body = overdue_sync.json()
    assert overdue_body["candidate_count"] >= 1
    assert overdue_body["work_order_created_count"] + overdue_body["linked_existing_work_order_count"] >= 1
    assert overdue_document_id in overdue_body["document_ids"]

    overdue_loaded = app_client.get(f"/api/official-documents/{overdue_document_id}", headers=headers)
    assert overdue_loaded.status_code == 200
    assert overdue_loaded.json()["linked_work_order_id"] is not None

    overdue_status = app_client.get(
        "/api/official-documents/overdue/status?site=HQ",
        headers=headers,
    )
    assert overdue_status.status_code == 200
    overdue_status_body = overdue_status.json()
    assert overdue_status_body["job_name"] == "official_document_overdue_sync"
    assert overdue_status_body["scheduler_mode"] in {"background", "disabled"}
    assert overdue_status_body["latest_run_status"] in {"idle", "success", "warning", "failed"}

    overdue_latest = app_client.get(
        "/api/official-documents/overdue/latest?site=HQ",
        headers=headers,
    )
    assert overdue_latest.status_code == 200
    overdue_latest_body = overdue_latest.json()
    assert overdue_latest_body["job_name"] == "official_document_overdue_sync"
    assert overdue_latest_body["exists"] in {True, False}

    for payload in [
        {
            "site": "HQ",
            "building": "101동",
            "unit_number": "1201호",
            "occupant_name": "Moon",
            "area_sqm": 84.5,
        }
    ]:
        created_unit = app_client.post("/api/billing/units", headers=headers, json=payload)
        assert created_unit.status_code == 201

    billing_policy = app_client.post(
        "/api/billing/rate-policies",
        headers=headers,
        json={
            "site": "HQ",
            "utility_type": "electricity",
            "effective_month": month_label,
            "basic_fee": 1000,
            "unit_rate": 100,
            "sewage_rate_per_unit": 0,
            "service_fee": 300,
            "vat_rate": 0.1,
            "tiers": [],
            "notes": "통합보고 테스트",
        },
    )
    assert billing_policy.status_code == 201
    billing_common = app_client.post(
        "/api/billing/common-charges",
        headers=headers,
        json={
            "site": "HQ",
            "billing_month": month_label,
            "utility_type": "electricity",
            "charge_category": "공용전기",
            "amount": 8450,
        },
    )
    assert billing_common.status_code == 201
    reading = app_client.post(
        "/api/billing/meter-readings",
        headers=headers,
        json={
            "site": "HQ",
            "building": "101동",
            "unit_number": "1201호",
            "utility_type": "electricity",
            "reading_month": month_label,
            "previous_reading": 1000,
            "current_reading": 1075,
            "reader_name": "owner_ci",
        },
    )
    assert reading.status_code == 201
    generated = app_client.post(
        "/api/billing/runs/generate",
        headers=headers,
        json={
            "site": "HQ",
            "billing_month": month_label,
            "utility_type": "electricity",
            "replace_existing": True,
        },
    )
    assert generated.status_code == 200

    integrated = app_client.get(
        f"/api/reports/monthly/integrated?site=HQ&month={month_label}",
        headers=headers,
    )
    assert integrated.status_code == 200
    integrated_body = integrated.json()
    assert integrated_body["period_type"] == "monthly"
    assert integrated_body["period_label"] == month_label
    assert integrated_body["month"] == month_label
    assert integrated_body["billing"]["statement_count"] >= 1
    assert integrated_body["official_documents"]["total_documents"] >= 2

    integrated_csv = app_client.get(
        f"/api/reports/monthly/integrated/csv?site=HQ&month={month_label}",
        headers=headers,
    )
    assert integrated_csv.status_code == 200
    assert "integrated-monthly-report" in integrated_csv.headers["content-disposition"]

    integrated_pdf = app_client.get(
        f"/api/reports/monthly/integrated/pdf?site=HQ&month={month_label}",
        headers=headers,
    )
    assert integrated_pdf.status_code == 200
    assert integrated_pdf.headers["content-type"].startswith("application/pdf")
    assert integrated_pdf.content.startswith(b"%PDF")

    integrated_print = app_client.get(
        f"/reports/monthly/integrated/print?site=HQ&month={month_label}",
        headers=headers,
    )
    assert integrated_print.status_code == 200
    assert "Integrated Monthly Facility Report" in integrated_print.text

    integrated_annual = app_client.get(
        f"/api/reports/annual/integrated?site=HQ&year={year_value}",
        headers=headers,
    )
    assert integrated_annual.status_code == 200
    integrated_annual_body = integrated_annual.json()
    assert integrated_annual_body["period_type"] == "annual"
    assert integrated_annual_body["period_label"] == str(year_value)
    assert integrated_annual_body["year"] == year_value
    assert "utility_billing" in integrated_annual_body["merged_sections"]

    integrated_annual_csv = app_client.get(
        f"/api/reports/annual/integrated/csv?site=HQ&year={year_value}",
        headers=headers,
    )
    assert integrated_annual_csv.status_code == 200
    assert "integrated-annual-report" in integrated_annual_csv.headers["content-disposition"]

    integrated_annual_pdf = app_client.get(
        f"/api/reports/annual/integrated/pdf?site=HQ&year={year_value}",
        headers=headers,
    )
    assert integrated_annual_pdf.status_code == 200
    assert integrated_annual_pdf.headers["content-type"].startswith("application/pdf")
    assert integrated_annual_pdf.content.startswith(b"%PDF")

    integrated_annual_print = app_client.get(
        f"/reports/annual/integrated/print?site=HQ&year={year_value}",
        headers=headers,
    )
    assert integrated_annual_print.status_code == 200
    assert "Integrated Annual Facility Report" in integrated_annual_print.text

    service_info = app_client.get("/api/service-info")
    assert service_info.status_code == 200
    service_body = service_info.json()
    assert service_body["official_documents_api"] == "/api/official-documents"
    assert service_body["official_document_attachments_api"] == "/api/official-documents/{document_id}/attachments"
    assert service_body["official_document_attachment_zip_api"] == "/api/official-documents/attachments/zip"
    assert service_body["official_document_registry_csv_api"] == "/api/official-documents/registry/csv"
    assert service_body["official_document_overdue_run_api"] == "/api/official-documents/overdue/run"
    assert service_body["official_document_overdue_status_api"] == "/api/official-documents/overdue/status"
    assert service_body["official_document_overdue_latest_api"] == "/api/official-documents/overdue/latest"
    assert service_body["official_document_overdue_cron_job"] == "python -m app.jobs.official_document_overdue"
    assert service_body["official_document_monthly_report_api"] == "/api/reports/official-documents/monthly"
    assert service_body["official_document_annual_report_print_html"] == "/reports/official-documents/annual/print"
    assert service_body["integrated_monthly_report_api"] == "/api/reports/monthly/integrated"
    assert service_body["integrated_monthly_report_pdf_api"] == "/api/reports/monthly/integrated/pdf"
    assert service_body["integrated_monthly_report_print_html"] == "/reports/monthly/integrated/print"
    assert service_body["integrated_annual_report_api"] == "/api/reports/annual/integrated"
    assert service_body["integrated_annual_report_pdf_api"] == "/api/reports/annual/integrated/pdf"

    html_page = app_client.get("/?tab=documents", headers={"Accept": "text/html"})
    assert html_page.status_code == 200
    assert 'data-tab="documents"' in html_page.text
    assert "runOfficialDocCreateBtn" in html_page.text
    assert "officialReportMonthlyPrintLink" in html_page.text
    assert "runOfficialAttachmentUploadBtn" in html_page.text
    assert "runOfficialOverdueSyncBtn" in html_page.text
    assert "officialReportIntegratedPrintLink" in html_page.text
    assert "officialAttachmentZipLink" in html_page.text
    assert "officialRegistryCsvLink" in html_page.text
    assert "runOfficialIntegratedAnnualReportBtn" in html_page.text
    assert "officialReportIntegratedAnnualPdfLink" in html_page.text

    overview_page = app_client.get("/?tab=overview", headers={"Accept": "text/html"})
    assert overview_page.status_code == 200
    assert "overviewOfficialAutomationCards" in overview_page.text
    assert "overviewOfficialOverdueStatusLink" in overview_page.text
    assert "overviewOfficialOverdueLatestLink" in overview_page.text


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


def test_integrated_report_asset_scope_filters_ops_and_linked_documents(app_client: TestClient) -> None:
    headers = _owner_headers()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    month_label = now.strftime("%Y-%m")

    baseline_inspection = app_client.post(
        "/api/inspections",
        headers=headers,
        json={
            "site": "HQ",
            "location": "B1 수변전실",
            "cycle": "daily",
            "inspector": "owner_ci",
            "inspected_at": now.isoformat(),
            "notes": _build_asset_scoped_ops_notes(
                equipment="변압기 1호기",
                equipment_location="B1 수변전실",
                qr_id="QR-002",
            ),
        },
    )
    assert baseline_inspection.status_code == 201
    baseline_inspection_id = int(baseline_inspection.json()["id"])
    baseline_qr_asset_id = int(baseline_inspection.json()["qr_asset_id"])

    baseline_work_order = app_client.post(
        "/api/work-orders",
        headers=headers,
        json={
            "title": "기준 자산 작업지시",
            "description": "기준 자산 후속 조치",
            "site": "HQ",
            "location": "B1 수변전실",
            "priority": "high",
            "inspection_id": baseline_inspection_id,
        },
    )
    assert baseline_work_order.status_code == 201
    baseline_work_order_id = int(baseline_work_order.json()["id"])

    baseline_document = app_client.post(
        "/api/official-documents",
        headers=headers,
        json={
            "site": "HQ",
            "organization": "한전",
            "title": "기준 자산 공문",
            "document_type": "electricity",
            "priority": "high",
            "received_at": now.isoformat(),
            "due_at": (now + timedelta(days=3)).isoformat(),
            "required_action": "기준 자산 조치 확인",
            "summary": "기준 자산 연계",
            "linked_inspection_id": baseline_inspection_id,
            "linked_work_order_id": baseline_work_order_id,
        },
    )
    assert baseline_document.status_code == 201

    created_equipment = app_client.post(
        "/api/ops/inspections/checklists/equipment-assets",
        headers=headers,
        json={
            "equipment": "변압기 9호기",
            "location": "B9 수변전실",
            "lifecycle_state": "active",
        },
    )
    assert created_equipment.status_code == 200
    scoped_equipment_id = int(created_equipment.json()["row"]["equipment_id"])

    created_qr = app_client.post(
        "/api/ops/inspections/checklists/qr-assets",
        headers=headers,
        json={
            "qr_id": "QR-INTEGRATED-SCOPE-CI",
            "equipment_id": scoped_equipment_id,
            "checklist_set_id": "electrical_60",
            "default_item": "변압기 외관 점검",
            "lifecycle_state": "active",
        },
    )
    assert created_qr.status_code == 200
    scoped_qr_asset_id = int(created_qr.json()["row"]["qr_asset_id"])

    scoped_inspection = app_client.post(
        "/api/inspections",
        headers=headers,
        json={
            "site": "HQ",
            "location": "B9 수변전실",
            "cycle": "daily",
            "inspector": "owner_ci",
            "inspected_at": now.isoformat(),
            "equipment_id": scoped_equipment_id,
            "qr_asset_id": scoped_qr_asset_id,
            "notes": _build_asset_scoped_ops_notes(
                equipment="변압기 9호기",
                equipment_location="B9 수변전실",
                qr_id="QR-INTEGRATED-SCOPE-CI",
            ),
        },
    )
    assert scoped_inspection.status_code == 201
    scoped_inspection_id = int(scoped_inspection.json()["id"])

    scoped_work_order = app_client.post(
        "/api/work-orders",
        headers=headers,
        json={
            "title": "자산 scope 작업지시",
            "description": "asset scope 통합리포트 검증",
            "site": "HQ",
            "location": "B9 수변전실",
            "priority": "high",
            "inspection_id": scoped_inspection_id,
        },
    )
    assert scoped_work_order.status_code == 201
    scoped_work_order_id = int(scoped_work_order.json()["id"])

    scoped_document = app_client.post(
        "/api/official-documents",
        headers=headers,
        json={
            "site": "HQ",
            "organization": "소방서",
            "title": "자산 scope 공문",
            "document_type": "fire",
            "priority": "critical",
            "received_at": now.isoformat(),
            "due_at": (now + timedelta(days=5)).isoformat(),
            "required_action": "자산 scope 조치 확인",
            "summary": "자산 scope 연계",
            "linked_inspection_id": scoped_inspection_id,
            "linked_work_order_id": scoped_work_order_id,
        },
    )
    assert scoped_document.status_code == 201

    unfiltered = app_client.get(
        f"/api/reports/monthly/integrated?site=HQ&month={month_label}",
        headers=headers,
    )
    assert unfiltered.status_code == 200
    unfiltered_body = unfiltered.json()
    assert unfiltered_body["inspections"]["total"] >= 2
    assert unfiltered_body["work_orders"]["total"] >= 2
    assert unfiltered_body["official_documents"]["total_documents"] >= 2

    scoped = app_client.get(
        f"/api/reports/monthly/integrated?site=HQ&month={month_label}&qr_asset_id={scoped_qr_asset_id}",
        headers=headers,
    )
    assert scoped.status_code == 200
    scoped_body = scoped.json()
    assert scoped_body["scope"]["asset_scope_active"] is True
    assert scoped_body["scope"]["qr_asset_id"] == scoped_qr_asset_id
    assert scoped_body["scope"]["equipment_id"] == scoped_equipment_id
    assert scoped_body["inspections"]["total"] == 1
    assert scoped_body["work_orders"]["total"] == 1
    assert scoped_body["official_documents"]["total_documents"] == 1
    assert scoped_body["official_documents"]["linked_asset_filter_applied"] is True
    assert scoped_body["official_documents"]["matching_linked_inspection_count"] >= 1
    assert scoped_body["official_documents"]["matching_linked_work_order_count"] >= 1
    assert scoped_body["billing"]["scope_applicable"] is False
    assert "unit-scoped" in scoped_body["billing"]["excluded_reason"]

    scoped_by_equipment = app_client.get(
        f"/api/reports/monthly/integrated?site=HQ&month={month_label}&equipment_id={scoped_equipment_id}",
        headers=headers,
    )
    assert scoped_by_equipment.status_code == 200
    equipment_body = scoped_by_equipment.json()
    assert equipment_body["scope"]["asset_scope_active"] is True
    assert equipment_body["scope"]["equipment_id"] == scoped_equipment_id
    assert equipment_body["inspections"]["total"] == 1
    assert equipment_body["work_orders"]["total"] == 1
    assert equipment_body["official_documents"]["total_documents"] == 1
    assert equipment_body["scope"]["qr_asset_id"] is None
    assert baseline_qr_asset_id != scoped_qr_asset_id


def test_official_document_overdue_cron_job_records_job_run(app_client: TestClient) -> None:
    import app.main as main_module

    headers = _owner_headers()
    now = datetime.now(timezone.utc).replace(microsecond=0)

    created = app_client.post(
        "/api/official-documents",
        headers=headers,
        json={
            "site": "HQ",
            "organization": "구청",
            "title": "배수펌프 정비 결과 제출",
            "document_type": "water",
            "priority": "high",
            "received_at": now.isoformat(),
            "due_at": (now - timedelta(days=3)).isoformat(),
            "required_action": "기한초과 자동화 검증",
            "summary": "cron job 대상",
        },
    )
    assert created.status_code == 201

    result = main_module.run_official_document_overdue_sync_job(
        site="HQ",
        dry_run=False,
        limit=20,
        trigger="cron",
    )
    assert result["candidate_count"] >= 1
    assert result["work_order_created_count"] + result["linked_existing_work_order_count"] >= 1
    assert result["job_name"] == "official_document_overdue_sync"
    assert result["trigger"] == "cron"

    job_runs = app_client.get("/api/ops/job-runs?job_name=official_document_overdue_sync", headers=headers)
    assert job_runs.status_code == 200
    rows = job_runs.json()
    assert rows
    assert rows[0]["job_name"] == "official_document_overdue_sync"
    assert rows[0]["trigger"] == "cron"
