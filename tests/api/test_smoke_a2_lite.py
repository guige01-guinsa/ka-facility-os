from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient


def _owner_headers() -> dict[str, str]:
    return {"X-Admin-Token": "test-owner-token"}


@pytest.mark.smoke
def test_a2_lite_smoke_flow_updates_monthly_report(app_client: TestClient) -> None:
    headers = _owner_headers()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    month_label = now.strftime("%Y-%m")
    site = "SMOKE-A2"

    before_report = app_client.get(
        f"/api/reports/official-documents/monthly?site={site}&month={month_label}",
        headers=headers,
    )
    assert before_report.status_code == 200
    before_body = before_report.json()
    before_total = int(before_body["total_documents"])
    before_linked = int(before_body["linked_work_order_documents"])

    created = app_client.post(
        "/api/official-documents",
        headers=headers,
        json={
            "site": site,
            "organization": "KEPCO",
            "organization_code": "KEPCO",
            "document_number": "SMOKE-A2-001",
            "title": "A2-lite overdue document",
            "document_type": "electricity",
            "priority": "critical",
            "received_at": now.isoformat(),
            "due_at": (now - timedelta(days=2)).isoformat(),
            "required_action": "Create follow-up work order",
            "summary": "A2-lite smoke candidate",
        },
    )
    assert created.status_code == 201
    created_body = created.json()
    document_id = int(created_body["id"])

    uploaded = app_client.post(
        f"/api/official-documents/{document_id}/attachments",
        headers=headers,
        data={"note": "A2-lite original"},
        files={"file": ("official-smoke.pdf", b"%PDF-1.4 a2 lite smoke", "application/pdf")},
    )
    assert uploaded.status_code == 201
    uploaded_body = uploaded.json()
    attachment_id = int(uploaded_body["id"])
    assert uploaded_body["document_id"] == document_id

    downloaded = app_client.get(
        f"/api/official-documents/attachments/{attachment_id}/download",
        headers=headers,
    )
    assert downloaded.status_code == 200
    assert downloaded.content == b"%PDF-1.4 a2 lite smoke"
    assert len(downloaded.headers["x-attachment-sha256"]) == 64

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

    monthly = app_client.get(
        f"/api/reports/official-documents/monthly?site={site}&month={month_label}",
        headers=headers,
    )
    assert monthly.status_code == 200
    monthly_body = monthly.json()
    assert int(monthly_body["total_documents"]) >= before_total + 1
    assert int(monthly_body["linked_work_order_documents"]) >= before_linked + 1
    assert any(
        int(entry["id"]) == document_id and int(entry["attachment_count"]) == 1
        for entry in monthly_body["entries"]
    )
