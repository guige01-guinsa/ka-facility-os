from __future__ import annotations

from io import BytesIO
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from openpyxl import load_workbook

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
    assert "연결 확인" in page.text
    assert "토큰 보기" in page.text
    assert "엑셀 출력" in page.text
    assert "PDF 출력" in page.text
    assert "DB 레코드 관리" in page.text


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

    updated_event = app_client.patch(
        f"/api/complaints/events/{event_body['id']}",
        headers=headers,
        json={
            "event_type": "rework",
            "note": "재방문 준비",
            "detail": {"worker": "1인1조"},
        },
    )
    assert updated_event.status_code == 200
    assert updated_event.json()["event_type"] == "rework"
    assert updated_event.json()["note"] == "재방문 준비"

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

    deleted_event = app_client.delete(
        f"/api/complaints/events/{event_body['id']}",
        headers=headers,
    )
    assert deleted_event.status_code == 200
    assert deleted_event.json()["deleted"] is True

    deleted_case = app_client.delete(
        f"/api/complaints/{complaint_id}",
        headers=headers,
    )
    assert deleted_case.status_code == 200
    assert deleted_case.json()["deleted"] is True

    after_delete = app_client.get(
        "/api/complaints?site=연산더샵&building=101동&unit_number=503호",
        headers=headers,
    )
    assert after_delete.status_code == 200
    assert after_delete.json() == []

    deleted_detail = app_client.get(f"/api/complaints/{complaint_id}", headers=headers)
    assert deleted_detail.status_code == 404


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

    updated_attachment = app_client.patch(
        f"/api/complaints/attachments/{attachment_id}",
        headers=headers,
        json={"attachment_kind": "after", "note": "작업 후 사진"},
    )
    assert updated_attachment.status_code == 200
    assert updated_attachment.json()["attachment_kind"] == "after"
    assert updated_attachment.json()["note"] == "작업 후 사진"

    updated_message = app_client.patch(
        f"/api/complaints/messages/{message['id']}",
        headers=headers,
        json={
            "recipient": "01077778888",
            "template_key": "visit_notice",
            "delivery_status": "sent",
            "body": "내일 방문 예정입니다.",
        },
    )
    assert updated_message.status_code == 200
    assert updated_message.json()["recipient"] == "010-7777-8888"
    assert updated_message.json()["template_key"] == "visit_notice"
    assert updated_message.json()["body"] == "내일 방문 예정입니다."

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

    updated_cost = app_client.patch(
        f"/api/complaints/cost-items/{cost_item['id']}",
        headers=headers,
        json={
            "quantity": 3,
            "unit_price": 9000,
            "note": "3면 작업으로 수정",
        },
    )
    assert updated_cost.status_code == 200
    assert updated_cost.json()["quantity"] == 3.0
    assert updated_cost.json()["total_cost"] == 32000.0
    assert updated_cost.json()["note"] == "3면 작업으로 수정"

    detail = app_client.get(f"/api/complaints/{complaint_id}", headers=headers)
    assert detail.status_code == 200
    detail_body = detail.json()
    assert len(detail_body["attachments"]) == 1
    assert len(detail_body["messages"]) == 1
    assert len(detail_body["cost_items"]) == 1
    assert detail_body["total_cost"] == 32000.0

    deleted_attachment = app_client.delete(
        f"/api/complaints/attachments/{attachment_id}",
        headers=headers,
    )
    assert deleted_attachment.status_code == 200
    assert deleted_attachment.json()["deleted"] is True

    deleted_message = app_client.delete(
        f"/api/complaints/messages/{message['id']}",
        headers=headers,
    )
    assert deleted_message.status_code == 200
    assert deleted_message.json()["deleted"] is True

    deleted_cost = app_client.delete(
        f"/api/complaints/cost-items/{cost_item['id']}",
        headers=headers,
    )
    assert deleted_cost.status_code == 200
    assert deleted_cost.json()["deleted"] is True

    after_delete_detail = app_client.get(f"/api/complaints/{complaint_id}", headers=headers)
    assert after_delete_detail.status_code == 200
    after_delete_body = after_delete_detail.json()
    assert after_delete_body["attachments"] == []
    assert after_delete_body["messages"] == []
    assert after_delete_body["cost_items"] == []
    assert after_delete_body["total_cost"] == 0.0


def test_complaint_report_exports(app_client: TestClient) -> None:
    headers = _owner_headers()
    first = app_client.post(
        "/api/complaints",
        headers=headers,
        json={
            "site": "연산더샵",
            "building": "103동",
            "unit_number": "901호",
            "description": "거실 방충망 오염",
            "contact_phone": "010-1111-2222",
        },
    )
    assert first.status_code == 201

    second = app_client.post(
        "/api/complaints",
        headers=headers,
        json={
            "site": "연산더샵",
            "building": "104동",
            "unit_number": "1201호",
            "description": "난간 오염",
            "contact_phone": "010-3333-4444",
        },
    )
    assert second.status_code == 201
    complaint_id = second.json()["id"]

    resolved = app_client.patch(
        f"/api/complaints/{complaint_id}",
        headers=headers,
        json={"status": "closed", "assignee": "현장3"},
    )
    assert resolved.status_code == 200

    xlsx_resp = app_client.get(
        "/api/complaints/reports/xlsx?site=연산더샵&report_type=unresolved",
        headers=headers,
    )
    assert xlsx_resp.status_code == 200
    assert xlsx_resp.headers["content-type"].startswith(
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    workbook = load_workbook(BytesIO(xlsx_resp.content))
    assert workbook.sheetnames == [
        "요약",
        "민원목록",
        "db_complaint_cases",
        "db_complaint_events",
        "db_complaint_attachments",
        "db_complaint_messages",
        "db_complaint_cost_items",
    ]
    assert workbook["요약"]["B2"].value == "미처리"
    assert workbook["민원목록"].max_row == 2
    assert workbook["db_complaint_cases"].max_row == 2
    assert workbook["db_complaint_cases"]["A2"].value == str(first.json()["id"])
    assert workbook["db_complaint_events"].max_row == 2
    assert workbook["db_complaint_events"]["B2"].value == str(first.json()["id"])
    assert workbook["db_complaint_attachments"].max_row == 1
    assert workbook["db_complaint_messages"].max_row == 1
    assert workbook["db_complaint_cost_items"].max_row == 1

    pdf_resp = app_client.get(
        "/api/complaints/reports/pdf?site=연산더샵&report_type=building",
        headers=headers,
    )
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"].startswith("application/pdf")
    assert pdf_resp.content.startswith(b"%PDF")


def test_complaint_admin_record_grid_bulk_api(app_client: TestClient) -> None:
    headers = _owner_headers()
    created = app_client.post(
        "/api/complaints",
        headers=headers,
        json={
            "site": "연산더샵",
            "building": "105동",
            "unit_number": "1102호",
            "description": "관리 탭 배치수정 테스트",
            "contact_phone": "010-1111-9999",
        },
    )
    assert created.status_code == 201
    complaint_id = created.json()["id"]

    added_event = app_client.post(
        f"/api/complaints/{complaint_id}/events",
        headers=headers,
        json={"event_type": "note", "note": "배치 수정 전", "detail": {"step": 1}},
    )
    assert added_event.status_code == 201
    event_id = added_event.json()["id"]

    attachment = app_client.post(
        f"/api/complaints/{complaint_id}/attachments",
        headers=headers,
        data={"attachment_kind": "intake", "note": "관리 탭 첨부"},
        files={"file": ("admin-grid.txt", b"admin-grid", "text/plain")},
    )
    assert attachment.status_code == 201
    attachment_id = attachment.json()["id"]

    message = app_client.post(
        f"/api/complaints/{complaint_id}/messages",
        headers=headers,
        json={"body": "관리 탭 메시지"},
    )
    assert message.status_code == 201
    message_id = message.json()["id"]

    cost = app_client.post(
        f"/api/complaints/{complaint_id}/cost-items",
        headers=headers,
        json={"cost_category": "other", "item_name": "관리 탭 비용", "quantity": 1, "unit_price": 5000},
    )
    assert cost.status_code == 201
    cost_item_id = cost.json()["id"]

    listed_cases = app_client.get(
        "/api/complaints/admin/records?site=연산더샵&record_type=cases&limit=50&q=관리 탭",
        headers=headers,
    )
    assert listed_cases.status_code == 200
    listed_cases_body = listed_cases.json()
    assert listed_cases_body["record_type"] == "cases"
    assert listed_cases_body["total_count"] >= 1
    assert any(row["id"] == complaint_id for row in listed_cases_body["rows"])

    listed_events = app_client.get(
        "/api/complaints/admin/records?site=연산더샵&record_type=events&limit=50&q=배치 수정 전",
        headers=headers,
    )
    assert listed_events.status_code == 200
    assert listed_events.json()["total_count"] >= 1

    listed_attachments = app_client.get(
        "/api/complaints/admin/records?site=연산더샵&record_type=attachments&limit=50&q=admin-grid.txt",
        headers=headers,
    )
    assert listed_attachments.status_code == 200
    assert listed_attachments.json()["total_count"] == 1

    listed_messages = app_client.get(
        "/api/complaints/admin/records?site=연산더샵&record_type=messages&limit=50&q=관리 탭 메시지",
        headers=headers,
    )
    assert listed_messages.status_code == 200
    assert listed_messages.json()["total_count"] == 1

    listed_costs = app_client.get(
        "/api/complaints/admin/records?site=연산더샵&record_type=cost_items&limit=50&q=관리 탭 비용",
        headers=headers,
    )
    assert listed_costs.status_code == 200
    assert listed_costs.json()["total_count"] == 1

    updated_cases = app_client.post(
        "/api/complaints/admin/records/bulk-update",
        headers=headers,
        json={
            "site": "연산더샵",
            "record_type": "cases",
            "rows": [
                {
                    "record_id": complaint_id,
                    "changes": {
                        "title": "관리 탭 배치수정 완료",
                        "assignee": "일괄편집반",
                        "status": "assigned",
                    },
                }
            ],
        },
    )
    assert updated_cases.status_code == 200
    assert updated_cases.json()["updated_count"] == 1

    updated_events = app_client.post(
        "/api/complaints/admin/records/bulk-update",
        headers=headers,
        json={
            "site": "연산더샵",
            "record_type": "events",
            "rows": [
                {
                    "record_id": event_id,
                    "changes": {
                        "event_type": "rework",
                        "note": "배치 수정 후",
                        "detail_json": "{\"step\": 2}",
                    },
                }
            ],
        },
    )
    assert updated_events.status_code == 200
    assert updated_events.json()["updated_count"] == 1

    case_detail = app_client.get(f"/api/complaints/{complaint_id}", headers=headers)
    assert case_detail.status_code == 200
    case_detail_body = case_detail.json()
    assert case_detail_body["case"]["title"] == "관리 탭 배치수정 완료"
    assert case_detail_body["case"]["assignee"] == "일괄편집반"
    assert case_detail_body["case"]["status"] == "assigned"
    assert any(item["id"] == event_id and item["note"] == "배치 수정 후" for item in case_detail_body["events"])

    deleted_children = app_client.post(
        "/api/complaints/admin/records/bulk-delete",
        headers=headers,
        json={
            "site": "연산더샵",
            "record_type": "attachments",
            "record_ids": [attachment_id],
        },
    )
    assert deleted_children.status_code == 200
    assert deleted_children.json()["deleted_count"] == 1

    deleted_messages = app_client.post(
        "/api/complaints/admin/records/bulk-delete",
        headers=headers,
        json={
            "site": "연산더샵",
            "record_type": "messages",
            "record_ids": [message_id],
        },
    )
    assert deleted_messages.status_code == 200
    assert deleted_messages.json()["deleted_count"] == 1

    deleted_costs = app_client.post(
        "/api/complaints/admin/records/bulk-delete",
        headers=headers,
        json={
            "site": "연산더샵",
            "record_type": "cost_items",
            "record_ids": [cost_item_id],
        },
    )
    assert deleted_costs.status_code == 200
    assert deleted_costs.json()["deleted_count"] == 1

    after_delete_detail = app_client.get(f"/api/complaints/{complaint_id}", headers=headers)
    assert after_delete_detail.status_code == 200
    after_delete_body = after_delete_detail.json()
    assert after_delete_body["attachments"] == []
    assert after_delete_body["messages"] == []
    assert after_delete_body["cost_items"] == []
