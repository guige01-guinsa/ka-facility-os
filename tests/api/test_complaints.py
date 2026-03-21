from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from tests.helpers.common import _owner_headers


def test_complaints_mobile_page_renders_field_console(app_client: TestClient) -> None:
    page = app_client.get("/web/complaints")
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert "Field Workflow Console" in page.text
    assert "현장 큐" in page.text
    assert "민원 신규 등록" in page.text
    assert "세대 이력" in page.text
    assert "문자 발송" in page.text
    assert "비용 입력" in page.text


def test_complaint_case_crud_and_household_history(app_client: TestClient) -> None:
    headers = _owner_headers()
    created = app_client.post(
        "/api/complaints",
        headers=headers,
        json={
            "site": "연산더샵",
            "building": "101",
            "unit_number": "503",
            "description": "방충망 페인트오염 및 난간 오염",
            "priority": "high",
            "contact_phone": "01058961551",
        },
    )
    assert created.status_code == 201
    body = created.json()
    complaint_id = body["id"]
    assert body["building"] == "101동"
    assert body["unit_number"] == "503호"
    assert body["complaint_type"] == "composite"
    assert body["priority"] == "high"
    assert body["status"] == "received"

    listed = app_client.get(
        "/api/complaints?site=연산더샵&building=101동&unit_number=503호",
        headers=headers,
    )
    assert listed.status_code == 200
    rows = listed.json()
    assert len(rows) == 1
    assert rows[0]["id"] == complaint_id

    visit_at = datetime(2026, 3, 21, 5, 0, tzinfo=timezone.utc).isoformat()
    updated = app_client.patch(
        f"/api/complaints/{complaint_id}",
        headers=headers,
        json={
            "status": "visit_scheduled",
            "assignee": "현장반장",
            "scheduled_visit_at": visit_at,
        },
    )
    assert updated.status_code == 200
    updated_body = updated.json()
    assert updated_body["status"] == "visit_scheduled"
    assert updated_body["assignee"] == "현장반장"

    event = app_client.post(
        f"/api/complaints/{complaint_id}/events",
        headers=headers,
        json={
            "event_type": "field_visit",
            "to_status": "resolved",
            "note": "방문 후 난간과 방충망 오염 제거",
            "detail": {"worker": "2인1조"},
        },
    )
    assert event.status_code == 201
    event_body = event.json()
    assert event_body["event_type"] == "field_visit"
    assert event_body["to_status"] == "resolved"

    detail = app_client.get(f"/api/complaints/{complaint_id}", headers=headers)
    assert detail.status_code == 200
    detail_body = detail.json()
    assert detail_body["case"]["status"] == "resolved"
    assert len(detail_body["events"]) >= 3

    history = app_client.get(
        "/api/complaints/households/history?site=연산더샵&building=101동&unit_number=503호",
        headers=headers,
    )
    assert history.status_code == 200
    history_body = history.json()
    assert history_body["site"] == "연산더샵"
    assert len(history_body["complaints"]) == 1
    assert history_body["complaints"][0]["id"] == complaint_id


def test_complaint_attachment_message_and_cost_workflow(app_client: TestClient) -> None:
    headers = _owner_headers()
    created = app_client.post(
        "/api/complaints",
        headers=headers,
        json={
            "site": "연산더샵",
            "building": "102동",
            "unit_number": "1204호",
            "description": "거실 방충망 오염",
            "contact_phone": "010-8529-4439",
        },
    )
    assert created.status_code == 201
    complaint_id = created.json()["id"]

    blocked_upload = app_client.post(
        f"/api/complaints/{complaint_id}/attachments",
        headers=headers,
        data={"attachment_kind": "intake", "note": "html not allowed"},
        files={"file": ("bad.html", b"<script>alert(1)</script>", "text/html")},
    )
    assert blocked_upload.status_code == 415

    uploaded = app_client.post(
        f"/api/complaints/{complaint_id}/attachments",
        headers=headers,
        data={"attachment_kind": "intake", "note": "접수 사진"},
        files={"file": ("complaint-photo.txt", b"complaint evidence", "text/plain")},
    )
    assert uploaded.status_code == 201
    attachment = uploaded.json()
    attachment_id = attachment["id"]
    assert attachment["attachment_kind"] == "intake"
    assert attachment["file_name"] == "complaint-photo.txt"

    attachments = app_client.get(
        f"/api/complaints/{complaint_id}/attachments",
        headers=headers,
    )
    assert attachments.status_code == 200
    attachment_rows = attachments.json()
    assert len(attachment_rows) == 1
    assert attachment_rows[0]["id"] == attachment_id

    downloaded = app_client.get(
        f"/api/complaints/attachments/{attachment_id}/download",
        headers=headers,
    )
    assert downloaded.status_code == 200
    assert downloaded.content == b"complaint evidence"
    assert len(downloaded.headers["x-complaint-sha256"]) == 64

    sent = app_client.post(
        f"/api/complaints/{complaint_id}/messages",
        headers=headers,
        json={"body": "민원 접수되었습니다. 방문 일정을 다시 안내드리겠습니다."},
    )
    assert sent.status_code == 201
    message = sent.json()
    assert message["delivery_status"] == "sent"
    assert message["recipient"] == "010-8529-4439"

    cost = app_client.post(
        f"/api/complaints/{complaint_id}/cost-items",
        headers=headers,
        json={
            "cost_category": "cleaning",
            "item_name": "방충망 청소",
            "quantity": 2,
            "unit_price": 10000,
            "material_cost": 3000,
            "labor_cost": 2000,
            "vendor_cost": 0,
        },
    )
    assert cost.status_code == 201
    cost_item = cost.json()
    assert cost_item["total_cost"] == 25000.0

    detail = app_client.get(f"/api/complaints/{complaint_id}", headers=headers)
    assert detail.status_code == 200
    detail_body = detail.json()
    assert len(detail_body["attachments"]) == 1
    assert len(detail_body["messages"]) == 1
    assert len(detail_body["cost_items"]) == 1
    assert detail_body["total_cost"] == 25000.0
