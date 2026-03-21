from __future__ import annotations

from datetime import datetime, timedelta, timezone

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
def test_a2_official_document_to_closure_report(app_client: TestClient) -> None:
    headers = _owner_headers()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    month_label = now.strftime("%Y-%m")
    site = "A2 Acceptance Site"
    organization = "한전"

    created = app_client.post(
        "/api/official-documents",
        headers=headers,
        json={
            "site": site,
            "organization": organization,
            "document_number": "KEPCO-A2-2026-0314",
            "title": "수전설비 개선 요청 공문",
            "document_type": "electricity",
            "priority": "critical",
            "received_at": now.isoformat(),
            "due_at": (now - timedelta(days=2)).isoformat(),
            "required_action": "기한초과 공문 후속 작업 생성",
            "summary": "A2 acceptance overdue document",
        },
    )
    assert created.status_code == 201
    created_body = created.json()
    document_id = int(created_body["id"])
    assert created_body["site"] == site
    assert created_body["organization"] == organization
    assert created_body["registry_number"].startswith("한전-A2 Acceptance Site-")

    uploaded = app_client.post(
        f"/api/official-documents/{document_id}/attachments",
        headers=headers,
        data={"note": "원본 공문 PDF"},
        files={"file": ("official-origin.pdf", b"%PDF-1.4 a2 official document", "application/pdf")},
    )
    assert uploaded.status_code == 201
    uploaded_body = uploaded.json()
    attachment_id = int(uploaded_body["id"])
    assert uploaded_body["document_id"] == document_id
    assert uploaded_body["file_name"] == "official-origin.pdf"

    attachment_list = app_client.get(
        f"/api/official-documents/{document_id}/attachments",
        headers=headers,
    )
    assert attachment_list.status_code == 200
    assert len(attachment_list.json()) == 1
    assert attachment_list.json()[0]["note"] == "원본 공문 PDF"

    downloaded = app_client.get(
        f"/api/official-documents/attachments/{attachment_id}/download",
        headers=headers,
    )
    assert downloaded.status_code == 200
    assert downloaded.content == b"%PDF-1.4 a2 official document"

    overdue_sync = app_client.post(
        f"/api/official-documents/overdue/run?site={site}&limit=20",
        headers=headers,
    )
    assert overdue_sync.status_code == 200
    overdue_body = overdue_sync.json()
    assert overdue_body["candidate_count"] >= 1
    assert overdue_body["work_order_created_count"] + overdue_body["linked_existing_work_order_count"] >= 1
    assert document_id in overdue_body["document_ids"]

    loaded = app_client.get(f"/api/official-documents/{document_id}", headers=headers)
    assert loaded.status_code == 200
    loaded_body = loaded.json()
    assert loaded_body["linked_work_order_id"] is not None
    work_order_id = int(loaded_body["linked_work_order_id"])

    linked_work_order = app_client.get(f"/api/work-orders/{work_order_id}", headers=headers)
    assert linked_work_order.status_code == 200
    assert linked_work_order.json()["site"] == site
    assert linked_work_order.json()["status"] == "open"

    closed = app_client.post(
        f"/api/official-documents/{document_id}/close",
        headers=headers,
        json={
            "closed_report_title": "A2 공문 종결보고",
            "closure_summary": "기한초과 공문에 대한 작업지시 연결 및 조치 완료",
            "closure_result": "회신 완료",
            "closed_at": now.isoformat(),
        },
    )
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"
    assert closed.json()["linked_work_order_id"] == work_order_id

    monthly = app_client.get(
        f"/api/reports/official-documents/monthly?site={site}&month={month_label}",
        headers=headers,
    )
    assert monthly.status_code == 200
    monthly_body = monthly.json()
    assert monthly_body["period_type"] == "monthly"
    assert monthly_body["period_label"] == month_label
    assert monthly_body["total_documents"] >= 1
    assert monthly_body["closed_in_period"] >= 1
    assert monthly_body["linked_work_order_documents"] >= 1
    assert any(
        int(entry["id"]) == document_id and int(entry["attachment_count"]) == 1
        for entry in monthly_body["entries"]
    )

    create_logs = _audit_rows_by_action(app_client, "official_document_create")
    assert any(
        row["resource_type"] == "official_document"
        and row["resource_id"] == str(document_id)
        and row["detail"]["site"] == site
        for row in create_logs
    )

    attachment_logs = _audit_rows_by_action(app_client, "official_document_attachment_upload")
    assert any(
        row["resource_type"] == "official_document_attachment"
        and row["resource_id"] == str(attachment_id)
        and row["detail"]["document_id"] == document_id
        for row in attachment_logs
    )

    overdue_logs = _audit_rows_by_action(app_client, "official_document_overdue_sync")
    assert any(
        row["resource_type"] == "official_document"
        and row["resource_id"] == site
        and row["detail"]["candidate_count"] >= 1
        for row in overdue_logs
    )

    close_logs = _audit_rows_by_action(app_client, "official_document_close")
    assert any(
        row["resource_type"] == "official_document"
        and row["resource_id"] == str(document_id)
        and row["detail"]["linked_work_order_id"] == work_order_id
        for row in close_logs
    )
