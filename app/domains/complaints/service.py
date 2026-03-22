"""Complaint services and normalization helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import delete, func, insert, select, update

from app.database import (
    complaint_attachments,
    complaint_cases,
    complaint_cost_items,
    complaint_events,
    complaint_messages,
    complaint_report_cover_defaults,
    get_conn,
    utility_billing_units,
    work_orders,
)
from app.domains.complaints import message_provider
from app.domains.complaints.schemas import (
    ComplaintAdminBulkDeleteRequest,
    ComplaintAdminBulkMutationResultRead,
    ComplaintAdminBulkUpdateRequest,
    ComplaintAdminRecordColumnRead,
    ComplaintAdminRecordListRead,
    ComplaintAttachmentRead,
    ComplaintAttachmentUpdate,
    ComplaintCaseCreate,
    ComplaintCaseRead,
    ComplaintCaseUpdate,
    ComplaintCostItemCreate,
    ComplaintCostItemRead,
    ComplaintCostItemUpdate,
    ComplaintDetailRead,
    ComplaintEventCreate,
    ComplaintEventRead,
    ComplaintEventUpdate,
    ComplaintHouseholdHistoryRead,
    ComplaintMessageRead,
    ComplaintMessageSend,
    ComplaintMessageUpdate,
    ComplaintReportCoverDefaultRead,
    ComplaintReportCoverDefaultUpdate,
    ComplaintReportCoverOptions,
)
from app.domains.iam.service import _write_audit_log
from app.domains.ops.inspection_service import (
    _as_datetime,
    _as_optional_datetime,
    _is_allowed_evidence_content_type,
    _normalize_evidence_storage_backend,
    _read_evidence_blob,
    _resolve_evidence_storage_abs_path,
    _scan_evidence_bytes,
    _write_evidence_blob,
)


COMPLAINT_TYPE_LABELS: dict[str, str] = {
    "screen_contamination": "방충망 오염",
    "screen_damage": "방충망 파손",
    "glass_contamination": "유리/창문 오염",
    "glass_damage": "유리/창문 파손",
    "railing_contamination": "난간 오염",
    "louver_issue": "루버창 불량",
    "silicone_issue": "실리콘/퍼티 불량",
    "wall_floor_contamination": "벽면/바닥 오염",
    "other_finish_issue": "기타 마감불량",
    "composite": "복합 민원",
}
STATUS_LABELS: dict[str, str] = {
    "received": "접수",
    "assigned": "배정완료",
    "visit_scheduled": "방문예정",
    "in_progress": "처리중",
    "resolved": "처리완료",
    "resident_confirmed": "세대확인완료",
    "reopened": "재민원",
    "closed": "종결",
}
PRIORITY_LABELS: dict[str, str] = {
    "low": "낮음",
    "medium": "보통",
    "high": "높음",
    "urgent": "긴급",
}
ATTACHMENT_KIND_LABELS: dict[str, str] = {
    "intake": "접수 사진",
    "before": "작업 전 사진",
    "after": "작업 후 사진",
    "other": "기타",
}
STATUS_VALUES = set(STATUS_LABELS)
PRIORITY_VALUES = set(PRIORITY_LABELS)
ATTACHMENT_KIND_VALUES = set(ATTACHMENT_KIND_LABELS)
SOURCE_CHANNEL_VALUES = {"manual", "phone", "visit", "office", "legacy_excel", "other"}
ADMIN_RECORD_LABELS: dict[str, str] = {
    "cases": "민원 본체",
    "events": "처리 이력",
    "attachments": "첨부",
    "messages": "문자 이력",
    "cost_items": "비용 항목",
}


def _choice_options(values: dict[str, str]) -> list[dict[str, str]]:
    return [{"value": key, "label": label} for key, label in values.items()]


ADMIN_RECORD_COLUMNS: dict[str, list[ComplaintAdminRecordColumnRead]] = {
    "cases": [
        ComplaintAdminRecordColumnRead(key="id", label="ID"),
        ComplaintAdminRecordColumnRead(key="building", label="동"),
        ComplaintAdminRecordColumnRead(key="unit_number", label="호수"),
        ComplaintAdminRecordColumnRead(key="title", label="제목", editable=True, input_type="text"),
        ComplaintAdminRecordColumnRead(key="description", label="민원내용", editable=True, input_type="textarea"),
        ComplaintAdminRecordColumnRead(key="status", label="상태", editable=True, input_type="select", options=_choice_options(STATUS_LABELS)),
        ComplaintAdminRecordColumnRead(key="complaint_type", label="민원유형", editable=True, input_type="select", options=_choice_options(COMPLAINT_TYPE_LABELS)),
        ComplaintAdminRecordColumnRead(key="priority", label="우선순위", editable=True, input_type="select", options=_choice_options(PRIORITY_LABELS)),
        ComplaintAdminRecordColumnRead(key="assignee", label="담당자", editable=True, input_type="text"),
        ComplaintAdminRecordColumnRead(key="resident_name", label="입주민명", editable=True, input_type="text"),
        ComplaintAdminRecordColumnRead(key="contact_phone", label="연락처", editable=True, input_type="text"),
        ComplaintAdminRecordColumnRead(key="scheduled_visit_at", label="방문예정", editable=True, input_type="datetime"),
        ComplaintAdminRecordColumnRead(key="recurrence_flag", label="재민원", editable=True, input_type="checkbox"),
        ComplaintAdminRecordColumnRead(key="linked_work_order_id", label="연결 작업지시", editable=True, input_type="number"),
        ComplaintAdminRecordColumnRead(
            key="source_channel",
            label="접수경로",
            editable=True,
            input_type="select",
            options=_choice_options({value: value for value in sorted(SOURCE_CHANNEL_VALUES)}),
        ),
        ComplaintAdminRecordColumnRead(key="updated_at", label="수정일시"),
    ],
    "events": [
        ComplaintAdminRecordColumnRead(key="id", label="ID"),
        ComplaintAdminRecordColumnRead(key="complaint_id", label="민원ID"),
        ComplaintAdminRecordColumnRead(key="building", label="동"),
        ComplaintAdminRecordColumnRead(key="unit_number", label="호수"),
        ComplaintAdminRecordColumnRead(key="event_type", label="이력유형", editable=True, input_type="text"),
        ComplaintAdminRecordColumnRead(key="note", label="메모", editable=True, input_type="textarea"),
        ComplaintAdminRecordColumnRead(key="detail_json", label="detail JSON", editable=True, input_type="textarea"),
        ComplaintAdminRecordColumnRead(key="from_status", label="이전상태"),
        ComplaintAdminRecordColumnRead(key="to_status", label="이후상태"),
        ComplaintAdminRecordColumnRead(key="actor_username", label="작성자"),
        ComplaintAdminRecordColumnRead(key="created_at", label="작성일시"),
    ],
    "attachments": [
        ComplaintAdminRecordColumnRead(key="id", label="ID"),
        ComplaintAdminRecordColumnRead(key="complaint_id", label="민원ID"),
        ComplaintAdminRecordColumnRead(key="building", label="동"),
        ComplaintAdminRecordColumnRead(key="unit_number", label="호수"),
        ComplaintAdminRecordColumnRead(key="attachment_kind", label="첨부구분", editable=True, input_type="select", options=_choice_options(ATTACHMENT_KIND_LABELS)),
        ComplaintAdminRecordColumnRead(key="file_name", label="파일명"),
        ComplaintAdminRecordColumnRead(key="content_type", label="콘텐츠유형"),
        ComplaintAdminRecordColumnRead(key="file_size", label="파일크기"),
        ComplaintAdminRecordColumnRead(key="note", label="메모", editable=True, input_type="textarea"),
        ComplaintAdminRecordColumnRead(key="uploaded_by", label="업로더"),
        ComplaintAdminRecordColumnRead(key="uploaded_at", label="업로드일시"),
    ],
    "messages": [
        ComplaintAdminRecordColumnRead(key="id", label="ID"),
        ComplaintAdminRecordColumnRead(key="complaint_id", label="민원ID"),
        ComplaintAdminRecordColumnRead(key="building", label="동"),
        ComplaintAdminRecordColumnRead(key="unit_number", label="호수"),
        ComplaintAdminRecordColumnRead(key="recipient", label="수신번호", editable=True, input_type="text"),
        ComplaintAdminRecordColumnRead(key="template_key", label="템플릿", editable=True, input_type="text"),
        ComplaintAdminRecordColumnRead(key="body", label="문자내용", editable=True, input_type="textarea"),
        ComplaintAdminRecordColumnRead(key="delivery_status", label="발송상태", editable=True, input_type="text"),
        ComplaintAdminRecordColumnRead(key="error", label="오류", editable=True, input_type="text"),
        ComplaintAdminRecordColumnRead(key="provider_name", label="업체"),
        ComplaintAdminRecordColumnRead(key="sent_by", label="발송자"),
        ComplaintAdminRecordColumnRead(key="sent_at", label="발송일시"),
        ComplaintAdminRecordColumnRead(key="created_at", label="기록일시"),
    ],
    "cost_items": [
        ComplaintAdminRecordColumnRead(key="id", label="ID"),
        ComplaintAdminRecordColumnRead(key="complaint_id", label="민원ID"),
        ComplaintAdminRecordColumnRead(key="building", label="동"),
        ComplaintAdminRecordColumnRead(key="unit_number", label="호수"),
        ComplaintAdminRecordColumnRead(key="cost_category", label="비용구분", editable=True, input_type="text"),
        ComplaintAdminRecordColumnRead(key="item_name", label="항목명", editable=True, input_type="text"),
        ComplaintAdminRecordColumnRead(key="quantity", label="수량", editable=True, input_type="number"),
        ComplaintAdminRecordColumnRead(key="unit_price", label="단가", editable=True, input_type="number"),
        ComplaintAdminRecordColumnRead(key="material_cost", label="자재비", editable=True, input_type="number"),
        ComplaintAdminRecordColumnRead(key="labor_cost", label="인건비", editable=True, input_type="number"),
        ComplaintAdminRecordColumnRead(key="vendor_cost", label="외주비", editable=True, input_type="number"),
        ComplaintAdminRecordColumnRead(key="total_cost", label="총액", editable=True, input_type="number"),
        ComplaintAdminRecordColumnRead(key="note", label="메모", editable=True, input_type="textarea"),
        ComplaintAdminRecordColumnRead(key="approved_by", label="승인자", editable=True, input_type="text"),
        ComplaintAdminRecordColumnRead(key="approved_at", label="승인일시", editable=True, input_type="datetime"),
        ComplaintAdminRecordColumnRead(key="updated_at", label="수정일시"),
    ],
}


def complaint_type_label(value: str) -> str:
    return COMPLAINT_TYPE_LABELS.get(value, COMPLAINT_TYPE_LABELS["other_finish_issue"])


def normalize_description(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").replace("\r", " ").replace("\n", " ")).strip()


def normalize_building(value: Any) -> str:
    raw = normalize_description(value).replace(" ", "")
    if not raw:
        raise HTTPException(status_code=422, detail="building is required")
    matched = re.fullmatch(r"(\d+)(동)?", raw)
    if matched:
        return f"{matched.group(1)}동"
    return raw if raw.endswith("동") else raw


def normalize_unit_number(value: Any) -> str:
    raw = normalize_description(value).replace(" ", "")
    if not raw:
        raise HTTPException(status_code=422, detail="unit_number is required")
    matched = re.fullmatch(r"(\d+)(호)?", raw)
    if matched:
        return f"{matched.group(1)}호"
    return raw if raw.endswith("호") else raw


def normalize_phone(value: Any) -> str | None:
    digits = re.sub(r"\D+", "", str(value or ""))
    if not digits:
        return None
    if digits.startswith("82") and len(digits) >= 11:
        digits = "0" + digits[2:]
    if len(digits) == 11:
        return f"{digits[:3]}-{digits[3:7]}-{digits[7:]}"
    if len(digits) == 10:
        return f"{digits[:3]}-{digits[3:6]}-{digits[6:]}"
    return digits


def _normalize_site(value: Any) -> str:
    normalized = normalize_description(value)
    if not normalized:
        raise HTTPException(status_code=422, detail="site is required")
    return normalized


def _normalize_status(value: Any) -> str:
    normalized = normalize_description(value).lower()
    if normalized not in STATUS_VALUES:
        raise HTTPException(status_code=422, detail=f"status must be one of {sorted(STATUS_VALUES)}")
    return normalized


def _normalize_priority(value: Any) -> str:
    normalized = normalize_description(value).lower() or "medium"
    if normalized not in PRIORITY_VALUES:
        raise HTTPException(status_code=422, detail=f"priority must be one of {sorted(PRIORITY_VALUES)}")
    return normalized


def _normalize_source_channel(value: Any) -> str:
    normalized = normalize_description(value).lower() or "manual"
    if normalized not in SOURCE_CHANNEL_VALUES:
        return "other"
    return normalized


def classify_complaint_type(description: str) -> str:
    text = normalize_description(description).lower()
    if not text:
        return "other_finish_issue"
    codes: set[str] = set()
    if "방충망" in text:
        if any(keyword in text for keyword in ("찢", "파손", "훼손", "소실", "없음")):
            codes.add("screen_damage")
        if any(keyword in text for keyword in ("오염", "이물질", "페인트")) or "방충망" in text:
            codes.add("screen_contamination")
    if any(keyword in text for keyword in ("유리", "창문", "창틀")):
        if any(keyword in text for keyword in ("교체", "파손", "깨", "금")):
            codes.add("glass_damage")
        else:
            codes.add("glass_contamination")
    if "난간" in text:
        codes.add("railing_contamination")
    if any(keyword in text for keyword in ("루버", "창살")):
        codes.add("louver_issue")
    if any(keyword in text for keyword in ("실리콘", "퍼티")):
        codes.add("silicone_issue")
    if any(keyword in text for keyword in ("벽면", "바닥", "복도")):
        codes.add("wall_floor_contamination")
    if any(keyword in text for keyword in ("미도색", "마감", "보수", "누수")):
        codes.add("other_finish_issue")
    if not codes:
        return "other_finish_issue"
    if len(codes) > 1:
        return "composite"
    return next(iter(codes))


def _normalize_complaint_type(value: Any, *, description: str) -> str:
    normalized = normalize_description(value).lower().replace(" ", "_")
    if not normalized:
        return classify_complaint_type(description)
    if normalized not in COMPLAINT_TYPE_LABELS:
        return classify_complaint_type(description)
    return normalized


def build_case_key(
    *,
    site: str,
    building: str,
    unit_number: str,
    description: str,
    contact_phone: str | None,
    reported_at: datetime | None,
) -> str:
    date_label = ""
    if reported_at is not None:
        date_label = _as_datetime(reported_at).astimezone(timezone.utc).strftime("%Y-%m-%d")
    phone_digits = re.sub(r"\D+", "", contact_phone or "")
    normalized_text = re.sub(r"[^0-9a-z가-힣]+", " ", normalize_description(description).lower()).strip()
    seed = "|".join([site, building, unit_number, date_label, phone_digits, normalized_text])
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _json_dumps(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False, default=str)


def _json_loads(raw: Any) -> dict[str, Any]:
    text = str(raw or "{}")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text}
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def _actor_username(principal: dict[str, Any] | None, *, fallback: str = "system") -> str:
    if principal is None:
        return fallback
    return str(principal.get("username") or fallback)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_cover_text(value: Any, *, max_length: int) -> str | None:
    normalized = normalize_description(value)
    if not normalized:
        return None
    return normalized[:max_length]


def _decode_logo_data_url(value: Any) -> tuple[bytes | None, str | None]:
    raw = str(value or "").strip()
    if not raw:
        return None, None
    matched = re.match(r"^data:(image/(png|jpeg|jpg));base64,(.+)$", raw, re.IGNORECASE)
    if matched is None:
        raise HTTPException(status_code=422, detail="logo_data_url must be a PNG or JPEG data URL")
    content_type = matched.group(1).lower().replace("jpg", "jpeg")
    try:
        payload = base64.b64decode(matched.group(3), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=422, detail="logo_data_url is not valid base64") from exc
    if len(payload) > 1_500_000:
        raise HTTPException(status_code=422, detail="logo image must be 1.5MB or smaller")
    return payload, content_type


def _logo_bytes_to_data_url(content_type: Any, payload: bytes | None) -> str | None:
    if not payload:
        return None
    normalized_type = str(content_type or "").strip().lower()
    if normalized_type not in {"image/png", "image/jpeg"}:
        normalized_type = "image/png"
    return f"data:{normalized_type};base64,{base64.b64encode(payload).decode('ascii')}"


def _build_title(*, building: str, unit_number: str, complaint_type: str, title: str | None = None) -> str:
    preferred = normalize_description(title)
    if preferred:
        return preferred[:200]
    return f"{building} {unit_number} {complaint_type_label(complaint_type)}"[:200]


def _normalize_reported_at(value: Any) -> datetime:
    return _as_optional_datetime(value) or _now()


def _load_unit_row(conn: Any, *, site: str, building: str, unit_number: str) -> dict[str, Any] | None:
    return conn.execute(
        select(utility_billing_units)
        .where(utility_billing_units.c.site == site)
        .where(utility_billing_units.c.building == building)
        .where(utility_billing_units.c.unit_number == unit_number)
        .where(utility_billing_units.c.is_active.is_(True))
        .order_by(utility_billing_units.c.id.desc())
        .limit(1)
    ).mappings().first()


def _validate_linked_work_order(conn: Any, *, linked_work_order_id: int | None, site: str) -> None:
    if linked_work_order_id is None:
        return
    row = conn.execute(
        select(work_orders.c.id, work_orders.c.site).where(work_orders.c.id == linked_work_order_id).limit(1)
    ).mappings().first()
    if row is None:
        raise HTTPException(status_code=422, detail="linked_work_order_id is unknown")
    if str(row["site"]) != site:
        raise HTTPException(status_code=422, detail="linked_work_order_id site mismatch")


def _load_case_row(conn: Any, complaint_id: int) -> dict[str, Any]:
    row = conn.execute(
        select(complaint_cases).where(complaint_cases.c.id == complaint_id).limit(1)
    ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="complaint not found")
    return row


def _load_attachment_row(conn: Any, attachment_id: int) -> dict[str, Any]:
    row = conn.execute(
        select(complaint_attachments).where(complaint_attachments.c.id == attachment_id).limit(1)
    ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="complaint attachment not found")
    return row


def _load_event_row(conn: Any, event_id: int) -> dict[str, Any]:
    row = conn.execute(
        select(complaint_events).where(complaint_events.c.id == event_id).limit(1)
    ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="complaint event not found")
    return row


def _load_message_row(conn: Any, message_id: int) -> dict[str, Any]:
    row = conn.execute(
        select(complaint_messages).where(complaint_messages.c.id == message_id).limit(1)
    ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="complaint message not found")
    return row


def _load_cost_item_row(conn: Any, cost_item_id: int) -> dict[str, Any]:
    row = conn.execute(
        select(complaint_cost_items).where(complaint_cost_items.c.id == cost_item_id).limit(1)
    ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="complaint cost item not found")
    return row


def _delete_attachment_blob(row: dict[str, Any]) -> None:
    if _normalize_evidence_storage_backend(str(row.get("storage_backend") or "db")) != "fs":
        return
    storage_key = str(row.get("storage_key") or "").strip()
    abs_path = _resolve_evidence_storage_abs_path(storage_key) if storage_key else None
    if abs_path is None or not abs_path.exists() or not abs_path.is_file():
        return
    try:
        abs_path.unlink()
    except OSError:
        pass


def _apply_status_transition_fields(existing_row: dict[str, Any], *, to_status: str, now: datetime) -> dict[str, Any]:
    current_status = str(existing_row["status"])
    if to_status == current_status:
        return {}
    updates: dict[str, Any] = {"status": to_status}
    if to_status == "resolved" and existing_row.get("resolved_at") is None:
        updates["resolved_at"] = now
    if to_status == "resident_confirmed":
        if existing_row.get("resolved_at") is None:
            updates["resolved_at"] = now
        if existing_row.get("resident_confirmed_at") is None:
            updates["resident_confirmed_at"] = now
    if to_status == "closed" and existing_row.get("closed_at") is None:
        updates["closed_at"] = now
    if to_status == "reopened":
        updates["recurrence_flag"] = True
        updates["recurrence_count"] = int(existing_row.get("recurrence_count") or 0) + 1
    return updates


def _row_to_case_model(row: dict[str, Any]) -> ComplaintCaseRead:
    status = str(row["status"])
    priority = str(row["priority"])
    complaint_type = str(row["complaint_type"])
    return ComplaintCaseRead(
        id=int(row["id"]),
        case_key=str(row["case_key"]),
        site=str(row["site"]),
        building=str(row["building"]),
        unit_number=str(row["unit_number"]),
        resident_name=str(row["resident_name"]) if row.get("resident_name") else None,
        contact_phone=str(row["contact_phone"]) if row.get("contact_phone") else None,
        complaint_type=complaint_type,
        complaint_type_label=complaint_type_label(complaint_type),
        title=str(row["title"]),
        description=str(row["description"]),
        status=status,
        status_label=STATUS_LABELS.get(status, status),
        priority=priority,
        priority_label=PRIORITY_LABELS.get(priority, priority),
        source_channel=str(row.get("source_channel") or "manual"),
        reported_at=_as_datetime(row["reported_at"]),
        scheduled_visit_at=_as_optional_datetime(row.get("scheduled_visit_at")),
        resolved_at=_as_optional_datetime(row.get("resolved_at")),
        resident_confirmed_at=_as_optional_datetime(row.get("resident_confirmed_at")),
        closed_at=_as_optional_datetime(row.get("closed_at")),
        recurrence_flag=bool(row.get("recurrence_flag")),
        recurrence_count=int(row.get("recurrence_count") or 0),
        assignee=str(row["assignee"]) if row.get("assignee") else None,
        linked_work_order_id=int(row["linked_work_order_id"]) if row.get("linked_work_order_id") is not None else None,
        import_batch_id=str(row["import_batch_id"]) if row.get("import_batch_id") else None,
        source_workbook=str(row["source_workbook"]) if row.get("source_workbook") else None,
        source_sheet=str(row["source_sheet"]) if row.get("source_sheet") else None,
        source_row_number=int(row["source_row_number"]) if row.get("source_row_number") is not None else None,
        created_by=str(row.get("created_by") or "system"),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _row_to_event_model(row: dict[str, Any]) -> ComplaintEventRead:
    return ComplaintEventRead(
        id=int(row["id"]),
        complaint_id=int(row["complaint_id"]),
        event_type=str(row["event_type"]),
        from_status=str(row["from_status"]) if row.get("from_status") else None,
        to_status=str(row["to_status"]) if row.get("to_status") else None,
        note=str(row.get("note") or ""),
        detail=_json_loads(row.get("detail_json")),
        actor_username=str(row.get("actor_username") or "system"),
        created_at=_as_datetime(row["created_at"]),
    )


def _row_to_attachment_model(row: dict[str, Any]) -> ComplaintAttachmentRead:
    attachment_kind = str(row.get("attachment_kind") or "intake")
    return ComplaintAttachmentRead(
        id=int(row["id"]),
        complaint_id=int(row["complaint_id"]),
        site=str(row["site"]),
        attachment_kind=attachment_kind,
        attachment_kind_label=ATTACHMENT_KIND_LABELS.get(attachment_kind, attachment_kind),
        file_name=str(row["file_name"]),
        content_type=str(row.get("content_type") or "application/octet-stream"),
        file_size=int(row.get("file_size") or 0),
        storage_backend=_normalize_evidence_storage_backend(str(row.get("storage_backend") or "db")),
        sha256=str(row.get("sha256") or ""),
        malware_scan_status=str(row.get("malware_scan_status") or "unknown"),
        malware_scan_engine=row.get("malware_scan_engine"),
        malware_scanned_at=_as_optional_datetime(row.get("malware_scanned_at")),
        note=str(row.get("note") or ""),
        uploaded_by=str(row.get("uploaded_by") or "system"),
        uploaded_at=_as_datetime(row["uploaded_at"]),
    )


def _row_to_message_model(row: dict[str, Any]) -> ComplaintMessageRead:
    return ComplaintMessageRead(
        id=int(row["id"]),
        complaint_id=int(row["complaint_id"]),
        site=str(row["site"]),
        delivery_kind=str(row.get("delivery_kind") or "sms"),
        template_key=str(row["template_key"]) if row.get("template_key") else None,
        recipient=str(row["recipient"]),
        body=str(row["body"]),
        provider_name=str(row.get("provider_name") or "stub"),
        provider_message_id=str(row["provider_message_id"]) if row.get("provider_message_id") else None,
        delivery_status=str(row.get("delivery_status") or "queued"),
        error=str(row["error"]) if row.get("error") else None,
        sent_by=str(row.get("sent_by") or "system"),
        sent_at=_as_optional_datetime(row.get("sent_at")),
        created_at=_as_datetime(row["created_at"]),
    )


def _row_to_cost_item_model(row: dict[str, Any]) -> ComplaintCostItemRead:
    return ComplaintCostItemRead(
        id=int(row["id"]),
        complaint_id=int(row["complaint_id"]),
        cost_category=str(row["cost_category"]),
        item_name=str(row["item_name"]),
        quantity=float(row.get("quantity") or 0.0),
        unit_price=float(row.get("unit_price") or 0.0),
        material_cost=float(row.get("material_cost") or 0.0),
        labor_cost=float(row.get("labor_cost") or 0.0),
        vendor_cost=float(row.get("vendor_cost") or 0.0),
        total_cost=float(row.get("total_cost") or 0.0),
        note=str(row.get("note") or ""),
        approved_by=str(row["approved_by"]) if row.get("approved_by") else None,
        approved_at=_as_optional_datetime(row.get("approved_at")),
        created_by=str(row.get("created_by") or "system"),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _serialize_admin_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone().isoformat() if value.tzinfo is not None else value.isoformat(sep=" ")
    return value


def _coerce_admin_change_value(value: Any) -> Any:
    if isinstance(value, str):
        normalized = value.strip()
        if normalized == "":
            return None
        if normalized.lower() == "true":
            return True
        if normalized.lower() == "false":
            return False
        return normalized
    return value


def _ensure_admin_site_allowed(site: str, allowed_sites: list[str] | None) -> str:
    normalized_site = _normalize_site(site)
    if allowed_sites is not None and normalized_site not in set(allowed_sites):
        raise HTTPException(status_code=403, detail="Site access denied")
    return normalized_site


def _scope_site_value(*, scope_type: str, site: str | None) -> str | None:
    normalized_scope = normalize_description(scope_type).lower() or "site"
    if normalized_scope == "global":
        return None
    return _normalize_site(site)


def _cover_default_row_to_model(row: dict[str, Any], *, source_scope: str) -> ComplaintReportCoverDefaultRead:
    logo_bytes = row.get("logo_bytes")
    logo_payload = bytes(logo_bytes) if isinstance(logo_bytes, (bytes, bytearray, memoryview)) else (logo_bytes if isinstance(logo_bytes, bytes) else b"")
    return ComplaintReportCoverDefaultRead(
        scope_type=str(row.get("scope_type") or "site"),
        source_scope=source_scope,
        site=str(row["site"]) if row.get("site") else None,
        company_name=str(row["company_name"]) if row.get("company_name") else None,
        contractor_name=str(row["contractor_name"]) if row.get("contractor_name") else None,
        submission_phrase=str(row["submission_phrase"]) if row.get("submission_phrase") else None,
        logo_data_url=_logo_bytes_to_data_url(row.get("logo_content_type"), logo_payload),
        logo_file_name=str(row["logo_file_name"]) if row.get("logo_file_name") else None,
        logo_content_type=str(row["logo_content_type"]) if row.get("logo_content_type") else None,
        logo_present=bool(logo_payload),
        updated_by=str(row["updated_by"]) if row.get("updated_by") else None,
        updated_at=_as_optional_datetime(row.get("updated_at")),
    )


def get_effective_report_cover_default(*, site: str | None, allowed_sites: list[str] | None = None) -> ComplaintReportCoverDefaultRead:
    normalized_site = _ensure_admin_site_allowed(site, allowed_sites) if site else None
    with get_conn() as conn:
        if normalized_site:
            row = conn.execute(
                select(complaint_report_cover_defaults)
                .where(complaint_report_cover_defaults.c.scope_type == "site")
                .where(complaint_report_cover_defaults.c.site == normalized_site)
                .limit(1)
            ).mappings().first()
            if row is not None:
                return _cover_default_row_to_model(row, source_scope="site")
        row = conn.execute(
            select(complaint_report_cover_defaults)
            .where(complaint_report_cover_defaults.c.scope_type == "global")
            .limit(1)
        ).mappings().first()
    if row is not None:
        return _cover_default_row_to_model(row, source_scope="global")
    return ComplaintReportCoverDefaultRead(scope_type="global", source_scope="none", site=normalized_site)


def resolve_effective_report_cover_options(
    *,
    site: str | None,
    override: ComplaintReportCoverOptions | None = None,
    allowed_sites: list[str] | None = None,
) -> ComplaintReportCoverOptions | None:
    default_model = get_effective_report_cover_default(site=site, allowed_sites=allowed_sites)
    default_cover = ComplaintReportCoverOptions(
        company_name=default_model.company_name,
        contractor_name=default_model.contractor_name,
        submission_phrase=default_model.submission_phrase,
        logo_data_url=default_model.logo_data_url,
        logo_file_name=default_model.logo_file_name,
    )
    if override is None:
        if any(
            (
                default_cover.company_name,
                default_cover.contractor_name,
                default_cover.submission_phrase,
                default_cover.logo_data_url,
            )
        ):
            return default_cover
        return None
    merged = ComplaintReportCoverOptions(
        company_name=_normalize_cover_text(override.company_name, max_length=120) or default_cover.company_name,
        contractor_name=_normalize_cover_text(override.contractor_name, max_length=120) or default_cover.contractor_name,
        submission_phrase=_normalize_cover_text(override.submission_phrase, max_length=500) or default_cover.submission_phrase,
        logo_data_url=str(override.logo_data_url or "").strip() or default_cover.logo_data_url,
        logo_file_name=_normalize_cover_text(override.logo_file_name, max_length=200) or default_cover.logo_file_name,
    )
    if any((merged.company_name, merged.contractor_name, merged.submission_phrase, merged.logo_data_url)):
        return merged
    return None


def save_report_cover_default(
    *,
    payload: ComplaintReportCoverDefaultUpdate,
    principal: dict[str, Any],
    allowed_sites: list[str] | None = None,
) -> ComplaintReportCoverDefaultRead:
    scope_type = normalize_description(payload.scope_type).lower() or "site"
    if scope_type not in {"site", "global"}:
        raise HTTPException(status_code=422, detail="scope_type must be site or global")
    site_value = _scope_site_value(scope_type=scope_type, site=payload.site)
    if scope_type == "site":
        _ensure_admin_site_allowed(site_value, allowed_sites)
    logo_bytes = None
    logo_content_type = None
    if str(payload.logo_data_url or "").strip():
        logo_bytes, logo_content_type = _decode_logo_data_url(payload.logo_data_url)
    now = _now()
    actor = _actor_username(principal)
    values = {
        "scope_type": scope_type,
        "site": site_value,
        "company_name": _normalize_cover_text(payload.company_name, max_length=120),
        "contractor_name": _normalize_cover_text(payload.contractor_name, max_length=120),
        "submission_phrase": _normalize_cover_text(payload.submission_phrase, max_length=500),
        "logo_file_name": _normalize_cover_text(payload.logo_file_name, max_length=200),
        "logo_content_type": logo_content_type,
        "updated_by": actor,
        "updated_at": now,
    }
    with get_conn() as conn:
        existing = conn.execute(
            select(complaint_report_cover_defaults)
            .where(complaint_report_cover_defaults.c.scope_type == scope_type)
            .where(complaint_report_cover_defaults.c.site.is_(site_value) if site_value is None else complaint_report_cover_defaults.c.site == site_value)
            .limit(1)
        ).mappings().first()
        if existing is None:
            insert_values = dict(values)
            insert_values["created_at"] = now
            insert_values["logo_bytes"] = logo_bytes or b""
            conn.execute(insert(complaint_report_cover_defaults).values(**insert_values))
        else:
            update_values = dict(values)
            if payload.clear_logo:
                update_values["logo_bytes"] = b""
                update_values["logo_content_type"] = None
                update_values["logo_file_name"] = None
            elif logo_bytes is not None:
                update_values["logo_bytes"] = logo_bytes
            conn.execute(
                update(complaint_report_cover_defaults)
                .where(complaint_report_cover_defaults.c.id == int(existing["id"]))
                .values(**update_values)
            )
    return get_effective_report_cover_default(site=site_value or payload.site, allowed_sites=allowed_sites if scope_type == "site" else None)


def delete_report_cover_default(
    *,
    scope_type: str,
    site: str | None,
    allowed_sites: list[str] | None = None,
) -> bool:
    normalized_scope = normalize_description(scope_type).lower() or "site"
    if normalized_scope not in {"site", "global"}:
        raise HTTPException(status_code=422, detail="scope_type must be site or global")
    site_value = _scope_site_value(scope_type=normalized_scope, site=site)
    if normalized_scope == "site":
        _ensure_admin_site_allowed(site_value, allowed_sites)
    with get_conn() as conn:
        stmt = delete(complaint_report_cover_defaults).where(complaint_report_cover_defaults.c.scope_type == normalized_scope)
        stmt = stmt.where(complaint_report_cover_defaults.c.site.is_(None)) if site_value is None else stmt.where(complaint_report_cover_defaults.c.site == site_value)
        result = conn.execute(stmt)
    return bool(result.rowcount)


def _search_matches(row: dict[str, Any], query: str) -> bool:
    if not query:
        return True
    haystack = " ".join(str(value or "") for value in row.values()).lower()
    return query in haystack


def _limit_records(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    normalized_limit = max(1, min(int(limit or 200), 1000))
    return rows[:normalized_limit]


def _admin_case_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "building": str(row["building"]),
        "unit_number": str(row["unit_number"]),
        "title": str(row["title"]),
        "description": str(row["description"]),
        "status": str(row["status"]),
        "complaint_type": str(row["complaint_type"]),
        "priority": str(row["priority"]),
        "assignee": str(row["assignee"]) if row.get("assignee") else None,
        "resident_name": str(row["resident_name"]) if row.get("resident_name") else None,
        "contact_phone": str(row["contact_phone"]) if row.get("contact_phone") else None,
        "scheduled_visit_at": _serialize_admin_value(_as_optional_datetime(row.get("scheduled_visit_at"))),
        "recurrence_flag": bool(row.get("recurrence_flag")),
        "linked_work_order_id": int(row["linked_work_order_id"]) if row.get("linked_work_order_id") is not None else None,
        "source_channel": str(row.get("source_channel") or "manual"),
        "updated_at": _serialize_admin_value(_as_datetime(row["updated_at"])),
    }


def _admin_event_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "complaint_id": int(row["complaint_id"]),
        "building": str(row["building"]),
        "unit_number": str(row["unit_number"]),
        "event_type": str(row["event_type"]),
        "note": str(row.get("note") or ""),
        "detail_json": str(row.get("detail_json") or "{}"),
        "from_status": str(row["from_status"]) if row.get("from_status") else None,
        "to_status": str(row["to_status"]) if row.get("to_status") else None,
        "actor_username": str(row.get("actor_username") or "system"),
        "created_at": _serialize_admin_value(_as_datetime(row["created_at"])),
    }


def _admin_attachment_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "complaint_id": int(row["complaint_id"]),
        "building": str(row["building"]),
        "unit_number": str(row["unit_number"]),
        "attachment_kind": str(row.get("attachment_kind") or "intake"),
        "file_name": str(row["file_name"]),
        "content_type": str(row.get("content_type") or "application/octet-stream"),
        "file_size": int(row.get("file_size") or 0),
        "note": str(row.get("note") or ""),
        "uploaded_by": str(row.get("uploaded_by") or "system"),
        "uploaded_at": _serialize_admin_value(_as_datetime(row["uploaded_at"])),
    }


def _admin_message_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "complaint_id": int(row["complaint_id"]),
        "building": str(row["building"]),
        "unit_number": str(row["unit_number"]),
        "recipient": str(row["recipient"]),
        "template_key": str(row["template_key"]) if row.get("template_key") else None,
        "body": str(row.get("body") or ""),
        "delivery_status": str(row.get("delivery_status") or "queued"),
        "error": str(row["error"]) if row.get("error") else None,
        "provider_name": str(row.get("provider_name") or "stub"),
        "sent_by": str(row.get("sent_by") or "system"),
        "sent_at": _serialize_admin_value(_as_optional_datetime(row.get("sent_at"))),
        "created_at": _serialize_admin_value(_as_datetime(row["created_at"])),
    }


def _admin_cost_item_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "complaint_id": int(row["complaint_id"]),
        "building": str(row["building"]),
        "unit_number": str(row["unit_number"]),
        "cost_category": str(row["cost_category"]),
        "item_name": str(row["item_name"]),
        "quantity": float(row.get("quantity") or 0.0),
        "unit_price": float(row.get("unit_price") or 0.0),
        "material_cost": float(row.get("material_cost") or 0.0),
        "labor_cost": float(row.get("labor_cost") or 0.0),
        "vendor_cost": float(row.get("vendor_cost") or 0.0),
        "total_cost": float(row.get("total_cost") or 0.0),
        "note": str(row.get("note") or ""),
        "approved_by": str(row["approved_by"]) if row.get("approved_by") else None,
        "approved_at": _serialize_admin_value(_as_optional_datetime(row.get("approved_at"))),
        "updated_at": _serialize_admin_value(_as_datetime(row["updated_at"])),
    }


def _list_admin_case_rows(conn: Any, *, site: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        select(complaint_cases)
        .where(complaint_cases.c.site == site)
        .order_by(complaint_cases.c.updated_at.desc(), complaint_cases.c.id.desc())
    ).mappings().all()
    return [_admin_case_row(row) for row in rows]


def _list_admin_event_rows(conn: Any, *, site: str) -> list[dict[str, Any]]:
    stmt = (
        select(
            complaint_events.c.id,
            complaint_events.c.complaint_id,
            complaint_events.c.event_type,
            complaint_events.c.note,
            complaint_events.c.detail_json,
            complaint_events.c.from_status,
            complaint_events.c.to_status,
            complaint_events.c.actor_username,
            complaint_events.c.created_at,
            complaint_cases.c.building,
            complaint_cases.c.unit_number,
        )
        .select_from(complaint_events.join(complaint_cases, complaint_events.c.complaint_id == complaint_cases.c.id))
        .where(complaint_cases.c.site == site)
        .order_by(complaint_events.c.created_at.desc(), complaint_events.c.id.desc())
    )
    rows = conn.execute(stmt).mappings().all()
    return [_admin_event_row(row) for row in rows]


def _list_admin_attachment_rows(conn: Any, *, site: str) -> list[dict[str, Any]]:
    stmt = (
        select(
            complaint_attachments.c.id,
            complaint_attachments.c.complaint_id,
            complaint_attachments.c.attachment_kind,
            complaint_attachments.c.file_name,
            complaint_attachments.c.content_type,
            complaint_attachments.c.file_size,
            complaint_attachments.c.note,
            complaint_attachments.c.uploaded_by,
            complaint_attachments.c.uploaded_at,
            complaint_cases.c.building,
            complaint_cases.c.unit_number,
        )
        .select_from(complaint_attachments.join(complaint_cases, complaint_attachments.c.complaint_id == complaint_cases.c.id))
        .where(complaint_cases.c.site == site)
        .order_by(complaint_attachments.c.uploaded_at.desc(), complaint_attachments.c.id.desc())
    )
    rows = conn.execute(stmt).mappings().all()
    return [_admin_attachment_row(row) for row in rows]


def _list_admin_message_rows(conn: Any, *, site: str) -> list[dict[str, Any]]:
    stmt = (
        select(
            complaint_messages.c.id,
            complaint_messages.c.complaint_id,
            complaint_messages.c.recipient,
            complaint_messages.c.template_key,
            complaint_messages.c.body,
            complaint_messages.c.delivery_status,
            complaint_messages.c.error,
            complaint_messages.c.provider_name,
            complaint_messages.c.sent_by,
            complaint_messages.c.sent_at,
            complaint_messages.c.created_at,
            complaint_cases.c.building,
            complaint_cases.c.unit_number,
        )
        .select_from(complaint_messages.join(complaint_cases, complaint_messages.c.complaint_id == complaint_cases.c.id))
        .where(complaint_cases.c.site == site)
        .order_by(complaint_messages.c.created_at.desc(), complaint_messages.c.id.desc())
    )
    rows = conn.execute(stmt).mappings().all()
    return [_admin_message_row(row) for row in rows]


def _list_admin_cost_item_rows(conn: Any, *, site: str) -> list[dict[str, Any]]:
    stmt = (
        select(
            complaint_cost_items.c.id,
            complaint_cost_items.c.complaint_id,
            complaint_cost_items.c.cost_category,
            complaint_cost_items.c.item_name,
            complaint_cost_items.c.quantity,
            complaint_cost_items.c.unit_price,
            complaint_cost_items.c.material_cost,
            complaint_cost_items.c.labor_cost,
            complaint_cost_items.c.vendor_cost,
            complaint_cost_items.c.total_cost,
            complaint_cost_items.c.note,
            complaint_cost_items.c.approved_by,
            complaint_cost_items.c.approved_at,
            complaint_cost_items.c.updated_at,
            complaint_cases.c.building,
            complaint_cases.c.unit_number,
        )
        .select_from(complaint_cost_items.join(complaint_cases, complaint_cost_items.c.complaint_id == complaint_cases.c.id))
        .where(complaint_cases.c.site == site)
        .order_by(complaint_cost_items.c.updated_at.desc(), complaint_cost_items.c.id.desc())
    )
    rows = conn.execute(stmt).mappings().all()
    return [_admin_cost_item_row(row) for row in rows]


def list_admin_records(
    *,
    site: str,
    record_type: str,
    limit: int = 200,
    q: str | None = None,
    allowed_sites: list[str] | None = None,
) -> ComplaintAdminRecordListRead:
    normalized_site = _ensure_admin_site_allowed(site, allowed_sites)
    if record_type not in ADMIN_RECORD_COLUMNS:
        raise HTTPException(status_code=422, detail=f"record_type must be one of {sorted(ADMIN_RECORD_COLUMNS)}")
    query = normalize_description(q).lower()
    with get_conn() as conn:
        if record_type == "cases":
            rows = _list_admin_case_rows(conn, site=normalized_site)
        elif record_type == "events":
            rows = _list_admin_event_rows(conn, site=normalized_site)
        elif record_type == "attachments":
            rows = _list_admin_attachment_rows(conn, site=normalized_site)
        elif record_type == "messages":
            rows = _list_admin_message_rows(conn, site=normalized_site)
        else:
            rows = _list_admin_cost_item_rows(conn, site=normalized_site)
    filtered_rows = [row for row in rows if _search_matches(row, query)]
    return ComplaintAdminRecordListRead(
        record_type=record_type,
        record_label=ADMIN_RECORD_LABELS[record_type],
        site=normalized_site,
        columns=ADMIN_RECORD_COLUMNS[record_type],
        rows=_limit_records(filtered_rows, limit),
        total_count=len(filtered_rows),
    )


def _assert_record_site(record_type: str, record_id: int, site: str) -> None:
    with get_conn() as conn:
        if record_type == "cases":
            case_row = _load_case_row(conn, record_id)
        elif record_type == "events":
            event_row = _load_event_row(conn, record_id)
            case_row = _load_case_row(conn, int(event_row["complaint_id"]))
        elif record_type == "attachments":
            attachment_row = _load_attachment_row(conn, record_id)
            if str(attachment_row["site"]) != site:
                raise HTTPException(status_code=403, detail="Site access denied")
            return
        elif record_type == "messages":
            message_row = _load_message_row(conn, record_id)
            if str(message_row["site"]) != site:
                raise HTTPException(status_code=403, detail="Site access denied")
            return
        else:
            cost_row = _load_cost_item_row(conn, record_id)
            case_row = _load_case_row(conn, int(cost_row["complaint_id"]))
    if str(case_row["site"]) != site:
        raise HTTPException(status_code=403, detail="Site access denied")


def bulk_update_admin_records(
    *,
    payload: ComplaintAdminBulkUpdateRequest,
    principal: dict[str, Any] | None = None,
    allowed_sites: list[str] | None = None,
) -> ComplaintAdminBulkMutationResultRead:
    normalized_site = _ensure_admin_site_allowed(payload.site, allowed_sites)
    updated_rows: list[dict[str, Any]] = []
    for item in payload.rows:
        _assert_record_site(payload.record_type, int(item.record_id), normalized_site)
        changes = {key: _coerce_admin_change_value(value) for key, value in dict(item.changes).items()}
        if not changes:
            continue
        if payload.record_type == "cases":
            updated = update_case(
                complaint_id=int(item.record_id),
                payload=ComplaintCaseUpdate.model_validate(changes),
                principal=principal,
            )
            updated_rows.append(_admin_case_row(updated.model_dump()))
        elif payload.record_type == "events":
            if "detail_json" in changes:
                raw_detail = changes.pop("detail_json")
                if raw_detail in {None, ""}:
                    changes["detail"] = {}
                else:
                    try:
                        changes["detail"] = json.loads(str(raw_detail))
                    except json.JSONDecodeError as exc:
                        raise HTTPException(status_code=422, detail=f"invalid detail_json for event {item.record_id}") from exc
            updated = update_event(
                event_id=int(item.record_id),
                payload=ComplaintEventUpdate.model_validate(changes),
                principal=principal,
            )
            updated_rows.append(_admin_event_row({**updated.model_dump(mode="json"), "building": "", "unit_number": "", "detail_json": json.dumps(updated.detail, ensure_ascii=False)}))
        elif payload.record_type == "attachments":
            updated = update_attachment(
                attachment_id=int(item.record_id),
                payload=ComplaintAttachmentUpdate.model_validate(changes),
                principal=principal,
            )
            updated_rows.append(_admin_attachment_row({**updated.model_dump(mode="json"), "building": "", "unit_number": ""}))
        elif payload.record_type == "messages":
            updated = update_message(
                message_id=int(item.record_id),
                payload=ComplaintMessageUpdate.model_validate(changes),
                principal=principal,
            )
            updated_rows.append(_admin_message_row({**updated.model_dump(mode="json"), "building": "", "unit_number": ""}))
        else:
            updated = update_cost_item(
                cost_item_id=int(item.record_id),
                payload=ComplaintCostItemUpdate.model_validate(changes),
                principal=principal,
            )
            updated_rows.append(_admin_cost_item_row({**updated.model_dump(mode="json"), "building": "", "unit_number": ""}))
    return ComplaintAdminBulkMutationResultRead(
        record_type=payload.record_type,
        updated_count=len(updated_rows),
        deleted_count=0,
        rows=updated_rows,
    )


def bulk_delete_admin_records(
    *,
    payload: ComplaintAdminBulkDeleteRequest,
    principal: dict[str, Any] | None = None,
    allowed_sites: list[str] | None = None,
) -> ComplaintAdminBulkMutationResultRead:
    normalized_site = _ensure_admin_site_allowed(payload.site, allowed_sites)
    deleted_count = 0
    for record_id in payload.record_ids:
        record_id_int = int(record_id)
        _assert_record_site(payload.record_type, record_id_int, normalized_site)
        if payload.record_type == "cases":
            deleted = delete_case(complaint_id=record_id_int, principal=principal)
        elif payload.record_type == "events":
            deleted = delete_event(event_id=record_id_int, principal=principal)
        elif payload.record_type == "attachments":
            deleted = delete_attachment(attachment_id=record_id_int, principal=principal)
        elif payload.record_type == "messages":
            deleted = delete_message(message_id=record_id_int, principal=principal)
        else:
            deleted = delete_cost_item(cost_item_id=record_id_int, principal=principal)
        deleted_count += 1 if deleted.get("deleted") else 0
    return ComplaintAdminBulkMutationResultRead(
        record_type=payload.record_type,
        updated_count=0,
        deleted_count=deleted_count,
        rows=[],
    )


def list_cases(
    *,
    site: str | None = None,
    building: str | None = None,
    unit_number: str | None = None,
    status: str | None = None,
    complaint_type: str | None = None,
    assignee: str | None = None,
    recurrence_flag: bool | None = None,
    allowed_sites: list[str] | None = None,
) -> list[ComplaintCaseRead]:
    stmt = select(complaint_cases)
    if site is not None:
        stmt = stmt.where(complaint_cases.c.site == _normalize_site(site))
    elif allowed_sites is not None:
        if not allowed_sites:
            return []
        stmt = stmt.where(complaint_cases.c.site.in_(allowed_sites))
    if building is not None:
        stmt = stmt.where(complaint_cases.c.building == normalize_building(building))
    if unit_number is not None:
        stmt = stmt.where(complaint_cases.c.unit_number == normalize_unit_number(unit_number))
    if status is not None:
        stmt = stmt.where(complaint_cases.c.status == _normalize_status(status))
    if complaint_type is not None:
        normalized_type = _normalize_complaint_type(complaint_type, description="")
        stmt = stmt.where(complaint_cases.c.complaint_type == normalized_type)
    if assignee is not None:
        stmt = stmt.where(complaint_cases.c.assignee == normalize_description(assignee))
    if recurrence_flag is not None:
        stmt = stmt.where(complaint_cases.c.recurrence_flag.is_(recurrence_flag))
    stmt = stmt.order_by(complaint_cases.c.reported_at.desc(), complaint_cases.c.id.desc())
    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_case_model(row) for row in rows]


def create_case(
    *,
    payload: ComplaintCaseCreate,
    principal: dict[str, Any] | None = None,
) -> ComplaintCaseRead:
    now = _now()
    actor_username = _actor_username(principal)
    site = _normalize_site(payload.site)
    building = normalize_building(payload.building)
    unit_number = normalize_unit_number(payload.unit_number)
    description = normalize_description(payload.description)
    if not description:
        raise HTTPException(status_code=422, detail="description is required")
    status = _normalize_status(payload.status)
    priority = _normalize_priority(payload.priority)
    source_channel = _normalize_source_channel(payload.source_channel)
    contact_phone = normalize_phone(payload.contact_phone)
    reported_at = _normalize_reported_at(payload.reported_at)
    complaint_type = _normalize_complaint_type(payload.complaint_type, description=description)
    case_key = build_case_key(
        site=site,
        building=building,
        unit_number=unit_number,
        description=description,
        contact_phone=contact_phone,
        reported_at=reported_at,
    )
    with get_conn() as conn:
        existing = conn.execute(
            select(complaint_cases.c.id).where(complaint_cases.c.case_key == case_key).limit(1)
        ).first()
        if existing is not None:
            raise HTTPException(status_code=409, detail="complaint case already exists")
        _validate_linked_work_order(conn, linked_work_order_id=payload.linked_work_order_id, site=site)
        unit_row = _load_unit_row(conn, site=site, building=building, unit_number=unit_number)
        resident_name = normalize_description(payload.resident_name) or (
            str(unit_row.get("occupant_name") or "").strip() if unit_row is not None else ""
        )
        title = _build_title(building=building, unit_number=unit_number, complaint_type=complaint_type, title=payload.title)
        created = conn.execute(
            insert(complaint_cases).values(
                case_key=case_key,
                site=site,
                building=building,
                unit_number=unit_number,
                resident_name=resident_name or None,
                contact_phone=contact_phone,
                complaint_type=complaint_type,
                title=title,
                description=description,
                status=status,
                priority=priority,
                source_channel=source_channel,
                reported_at=reported_at,
                scheduled_visit_at=_as_optional_datetime(payload.scheduled_visit_at),
                resolved_at=None,
                resident_confirmed_at=None,
                closed_at=None,
                recurrence_flag=bool(payload.recurrence_flag),
                recurrence_count=0,
                assignee=normalize_description(payload.assignee) or None,
                linked_work_order_id=payload.linked_work_order_id,
                import_batch_id=None,
                source_workbook=None,
                source_sheet=None,
                source_row_number=None,
                source_row_hash=None,
                created_by=actor_username,
                created_at=now,
                updated_at=now,
            )
        )
        complaint_id = int(created.inserted_primary_key[0])
        conn.execute(
            insert(complaint_events).values(
                complaint_id=complaint_id,
                event_type="created",
                from_status=None,
                to_status=status,
                note="민원 접수",
                detail_json=_json_dumps({"source_channel": source_channel}),
                actor_username=actor_username,
                created_at=now,
            )
        )
        row = _load_case_row(conn, complaint_id)
    _write_audit_log(
        principal=principal,
        action="complaints.case.create",
        resource_type="complaint_case",
        resource_id=str(complaint_id),
        detail={"site": site, "building": building, "unit_number": unit_number, "status": status},
    )
    return _row_to_case_model(row)


def update_case(
    *,
    complaint_id: int,
    payload: ComplaintCaseUpdate,
    principal: dict[str, Any] | None = None,
) -> ComplaintCaseRead:
    actor_username = _actor_username(principal)
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        with get_conn() as conn:
            return _row_to_case_model(_load_case_row(conn, complaint_id))
    now = _now()
    with get_conn() as conn:
        existing = _load_case_row(conn, complaint_id)
        updated_values: dict[str, Any] = {}
        if "resident_name" in changes:
            updated_values["resident_name"] = normalize_description(changes["resident_name"]) or None
        if "contact_phone" in changes:
            updated_values["contact_phone"] = normalize_phone(changes["contact_phone"])
        if "description" in changes:
            description = normalize_description(changes["description"])
            if not description:
                raise HTTPException(status_code=422, detail="description cannot be empty")
            updated_values["description"] = description
        else:
            description = str(existing["description"])
        if "priority" in changes:
            updated_values["priority"] = _normalize_priority(changes["priority"])
        if "source_channel" in changes:
            updated_values["source_channel"] = _normalize_source_channel(changes["source_channel"])
        if "reported_at" in changes:
            updated_values["reported_at"] = _normalize_reported_at(changes["reported_at"])
        reported_at = updated_values.get("reported_at") or _as_datetime(existing["reported_at"])
        contact_phone = updated_values.get("contact_phone")
        if contact_phone is None:
            contact_phone = str(existing["contact_phone"]) if existing.get("contact_phone") else None
        if "complaint_type" in changes:
            updated_values["complaint_type"] = _normalize_complaint_type(changes["complaint_type"], description=description)
        complaint_type = updated_values.get("complaint_type") or str(existing["complaint_type"])
        if "title" in changes and normalize_description(changes["title"]):
            updated_values["title"] = _build_title(
                building=str(existing["building"]),
                unit_number=str(existing["unit_number"]),
                complaint_type=complaint_type,
                title=changes["title"],
            )
        elif "description" in changes or "complaint_type" in changes:
            updated_values["title"] = _build_title(
                building=str(existing["building"]),
                unit_number=str(existing["unit_number"]),
                complaint_type=complaint_type,
                title=None,
            )
        if "scheduled_visit_at" in changes:
            updated_values["scheduled_visit_at"] = _as_optional_datetime(changes["scheduled_visit_at"])
        if "assignee" in changes:
            updated_values["assignee"] = normalize_description(changes["assignee"]) or None
        if "recurrence_flag" in changes:
            updated_values["recurrence_flag"] = bool(changes["recurrence_flag"])
        if "linked_work_order_id" in changes:
            _validate_linked_work_order(
                conn,
                linked_work_order_id=changes["linked_work_order_id"],
                site=str(existing["site"]),
            )
            updated_values["linked_work_order_id"] = changes["linked_work_order_id"]
        next_status = None
        if "status" in changes:
            next_status = _normalize_status(changes["status"])
            updated_values.update(_apply_status_transition_fields(existing, to_status=next_status, now=now))

        next_case_key = build_case_key(
            site=str(existing["site"]),
            building=str(existing["building"]),
            unit_number=str(existing["unit_number"]),
            description=updated_values.get("description") or str(existing["description"]),
            contact_phone=contact_phone,
            reported_at=reported_at,
        )
        if next_case_key != str(existing["case_key"]):
            conflict = conn.execute(
                select(complaint_cases.c.id)
                .where(complaint_cases.c.case_key == next_case_key)
                .where(complaint_cases.c.id != complaint_id)
                .limit(1)
            ).first()
            if conflict is not None:
                raise HTTPException(status_code=409, detail="another complaint case already uses the same key")
            updated_values["case_key"] = next_case_key

        updated_values["updated_at"] = now
        conn.execute(update(complaint_cases).where(complaint_cases.c.id == complaint_id).values(**updated_values))
        conn.execute(
            insert(complaint_events).values(
                complaint_id=complaint_id,
                event_type="status_changed" if next_status and next_status != str(existing["status"]) else "updated",
                from_status=str(existing["status"]) if next_status and next_status != str(existing["status"]) else None,
                to_status=next_status if next_status and next_status != str(existing["status"]) else None,
                note="민원 정보 수정",
                detail_json=_json_dumps({"changed_fields": sorted(updated_values.keys())}),
                actor_username=actor_username,
                created_at=now,
            )
        )
        row = _load_case_row(conn, complaint_id)
    _write_audit_log(
        principal=principal,
        action="complaints.case.update",
        resource_type="complaint_case",
        resource_id=str(complaint_id),
        detail={"changed_fields": sorted(updated_values.keys())},
    )
    return _row_to_case_model(row)


def delete_case(
    *,
    complaint_id: int,
    principal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    with get_conn() as conn:
        row = _load_case_row(conn, complaint_id)
        attachment_rows = conn.execute(
            select(complaint_attachments).where(complaint_attachments.c.complaint_id == complaint_id)
        ).mappings().all()
        event_count = int(
            conn.execute(delete(complaint_events).where(complaint_events.c.complaint_id == complaint_id)).rowcount or 0
        )
        message_count = int(
            conn.execute(delete(complaint_messages).where(complaint_messages.c.complaint_id == complaint_id)).rowcount or 0
        )
        cost_count = int(
            conn.execute(delete(complaint_cost_items).where(complaint_cost_items.c.complaint_id == complaint_id)).rowcount or 0
        )
        attachment_count = int(
            conn.execute(delete(complaint_attachments).where(complaint_attachments.c.complaint_id == complaint_id)).rowcount or 0
        )
        deleted_case_count = int(
            conn.execute(delete(complaint_cases).where(complaint_cases.c.id == complaint_id)).rowcount or 0
        )
    for attachment_row in attachment_rows:
        _delete_attachment_blob(dict(attachment_row))
    _write_audit_log(
        principal=principal,
        action="complaints.case.delete",
        resource_type="complaint_case",
        resource_id=str(complaint_id),
        detail={
            "site": str(row["site"]),
            "building": str(row["building"]),
            "unit_number": str(row["unit_number"]),
            "events_deleted": event_count,
            "attachments_deleted": attachment_count,
            "messages_deleted": message_count,
            "cost_items_deleted": cost_count,
        },
    )
    return {
        "deleted": deleted_case_count > 0,
        "complaint_id": complaint_id,
        "events_deleted": event_count,
        "attachments_deleted": attachment_count,
        "messages_deleted": message_count,
        "cost_items_deleted": cost_count,
    }


def add_event(
    *,
    complaint_id: int,
    payload: ComplaintEventCreate,
    principal: dict[str, Any] | None = None,
) -> ComplaintEventRead:
    actor_username = _actor_username(principal)
    now = _now()
    with get_conn() as conn:
        existing = _load_case_row(conn, complaint_id)
        from_status = None
        to_status = None
        if payload.to_status is not None:
            to_status = _normalize_status(payload.to_status)
            transition_values = _apply_status_transition_fields(existing, to_status=to_status, now=now)
            if transition_values:
                from_status = str(existing["status"])
                transition_values["updated_at"] = now
                conn.execute(update(complaint_cases).where(complaint_cases.c.id == complaint_id).values(**transition_values))
        created = conn.execute(
            insert(complaint_events).values(
                complaint_id=complaint_id,
                event_type=normalize_description(payload.event_type) or "note",
                from_status=from_status,
                to_status=to_status,
                note=normalize_description(payload.note),
                detail_json=_json_dumps(payload.detail),
                actor_username=actor_username,
                created_at=now,
            )
        )
        event_id = int(created.inserted_primary_key[0])
        row = conn.execute(select(complaint_events).where(complaint_events.c.id == event_id).limit(1)).mappings().first()
    _write_audit_log(
        principal=principal,
        action="complaints.event.create",
        resource_type="complaint_case",
        resource_id=str(complaint_id),
        detail={"event_type": payload.event_type, "to_status": payload.to_status},
    )
    return _row_to_event_model(row or {})


def get_event(*, event_id: int) -> ComplaintEventRead:
    with get_conn() as conn:
        row = _load_event_row(conn, event_id)
    return _row_to_event_model(row)


def update_event(
    *,
    event_id: int,
    payload: ComplaintEventUpdate,
    principal: dict[str, Any] | None = None,
) -> ComplaintEventRead:
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        return get_event(event_id=event_id)
    now = _now()
    with get_conn() as conn:
        existing = _load_event_row(conn, event_id)
        updated_values: dict[str, Any] = {}
        if "event_type" in changes:
            updated_values["event_type"] = normalize_description(changes["event_type"]) or "note"
        if "note" in changes:
            updated_values["note"] = normalize_description(changes["note"])
        if "detail" in changes:
            updated_values["detail_json"] = _json_dumps(changes["detail"])
        conn.execute(update(complaint_events).where(complaint_events.c.id == event_id).values(**updated_values))
        row = _load_event_row(conn, event_id)
    _write_audit_log(
        principal=principal,
        action="complaints.event.update",
        resource_type="complaint_case",
        resource_id=str(existing["complaint_id"]),
        detail={"event_id": event_id, "changed_fields": sorted(updated_values.keys()), "updated_at": now.isoformat()},
    )
    return _row_to_event_model(row)


def delete_event(
    *,
    event_id: int,
    principal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    with get_conn() as conn:
        existing = _load_event_row(conn, event_id)
        deleted_count = int(conn.execute(delete(complaint_events).where(complaint_events.c.id == event_id)).rowcount or 0)
    _write_audit_log(
        principal=principal,
        action="complaints.event.delete",
        resource_type="complaint_case",
        resource_id=str(existing["complaint_id"]),
        detail={"event_id": event_id, "event_type": str(existing["event_type"])},
    )
    return {"deleted": deleted_count > 0, "event_id": event_id, "complaint_id": int(existing["complaint_id"])}


def list_events(*, complaint_id: int) -> list[ComplaintEventRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(complaint_events)
            .where(complaint_events.c.complaint_id == complaint_id)
            .order_by(complaint_events.c.created_at.asc(), complaint_events.c.id.asc())
        ).mappings().all()
    return [_row_to_event_model(row) for row in rows]


def list_attachments(*, complaint_id: int) -> list[ComplaintAttachmentRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(complaint_attachments)
            .where(complaint_attachments.c.complaint_id == complaint_id)
            .order_by(complaint_attachments.c.uploaded_at.asc(), complaint_attachments.c.id.asc())
        ).mappings().all()
    return [_row_to_attachment_model(row) for row in rows]


def add_attachment(
    *,
    complaint_id: int,
    attachment_kind: str,
    note: str,
    file_name: str,
    content_type: str,
    file_bytes: bytes,
    principal: dict[str, Any] | None = None,
) -> ComplaintAttachmentRead:
    actor_username = _actor_username(principal)
    normalized_kind = normalize_description(attachment_kind).lower() or "intake"
    if normalized_kind not in ATTACHMENT_KIND_VALUES:
        raise HTTPException(status_code=422, detail=f"attachment_kind must be one of {sorted(ATTACHMENT_KIND_VALUES)}")
    if not _is_allowed_evidence_content_type(content_type):
        raise HTTPException(status_code=415, detail="unsupported complaint attachment content type")
    scan_status, scan_engine, scan_error = _scan_evidence_bytes(file_bytes=file_bytes, content_type=content_type)
    if scan_status in {"infected", "suspicious"}:
        raise HTTPException(status_code=422, detail=scan_error or "attachment scan failed")
    sha256_digest = hashlib.sha256(file_bytes).hexdigest()
    storage_backend, storage_key, stored_bytes = _write_evidence_blob(
        file_name=file_name,
        file_bytes=file_bytes,
        sha256_digest=sha256_digest,
    )
    now = _now()
    with get_conn() as conn:
        complaint_row = _load_case_row(conn, complaint_id)
        created = conn.execute(
            insert(complaint_attachments).values(
                complaint_id=complaint_id,
                site=str(complaint_row["site"]),
                attachment_kind=normalized_kind,
                file_name=file_name,
                content_type=content_type,
                file_size=len(file_bytes),
                storage_backend=storage_backend,
                storage_key=storage_key,
                file_bytes=stored_bytes,
                sha256=sha256_digest,
                malware_scan_status=scan_status,
                malware_scan_engine=scan_engine,
                malware_scanned_at=now,
                note=normalize_description(note),
                uploaded_by=actor_username,
                uploaded_at=now,
            )
        )
        attachment_id = int(created.inserted_primary_key[0])
        row = _load_attachment_row(conn, attachment_id)
    _write_audit_log(
        principal=principal,
        action="complaints.attachment.create",
        resource_type="complaint_case",
        resource_id=str(complaint_id),
        detail={"attachment_id": attachment_id, "attachment_kind": normalized_kind, "file_name": file_name},
    )
    return _row_to_attachment_model(row)


def get_attachment(*, attachment_id: int) -> ComplaintAttachmentRead:
    with get_conn() as conn:
        row = _load_attachment_row(conn, attachment_id)
    return _row_to_attachment_model(row)


def update_attachment(
    *,
    attachment_id: int,
    payload: ComplaintAttachmentUpdate,
    principal: dict[str, Any] | None = None,
) -> ComplaintAttachmentRead:
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        return get_attachment(attachment_id=attachment_id)
    with get_conn() as conn:
        existing = _load_attachment_row(conn, attachment_id)
        updated_values: dict[str, Any] = {}
        if "attachment_kind" in changes:
            attachment_kind = normalize_description(changes["attachment_kind"]).lower()
            if attachment_kind not in ATTACHMENT_KIND_VALUES:
                raise HTTPException(status_code=422, detail=f"attachment_kind must be one of {sorted(ATTACHMENT_KIND_VALUES)}")
            updated_values["attachment_kind"] = attachment_kind
        if "note" in changes:
            updated_values["note"] = normalize_description(changes["note"])
        conn.execute(update(complaint_attachments).where(complaint_attachments.c.id == attachment_id).values(**updated_values))
        row = _load_attachment_row(conn, attachment_id)
    _write_audit_log(
        principal=principal,
        action="complaints.attachment.update",
        resource_type="complaint_case",
        resource_id=str(existing["complaint_id"]),
        detail={"attachment_id": attachment_id, "changed_fields": sorted(updated_values.keys())},
    )
    return _row_to_attachment_model(row)


def delete_attachment(
    *,
    attachment_id: int,
    principal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    with get_conn() as conn:
        existing = _load_attachment_row(conn, attachment_id)
        deleted_count = int(
            conn.execute(delete(complaint_attachments).where(complaint_attachments.c.id == attachment_id)).rowcount or 0
        )
    _delete_attachment_blob(existing)
    _write_audit_log(
        principal=principal,
        action="complaints.attachment.delete",
        resource_type="complaint_case",
        resource_id=str(existing["complaint_id"]),
        detail={"attachment_id": attachment_id, "file_name": str(existing["file_name"])},
    )
    return {"deleted": deleted_count > 0, "attachment_id": attachment_id, "complaint_id": int(existing["complaint_id"])}


def get_attachment_download_payload(*, attachment_id: int) -> dict[str, Any]:
    with get_conn() as conn:
        row = _load_attachment_row(conn, attachment_id)
        file_bytes = _read_evidence_blob(row=row)
    if file_bytes is None:
        raise HTTPException(status_code=404, detail="complaint attachment blob not found")
    return {"row": row, "file_bytes": file_bytes}


def list_messages(*, complaint_id: int) -> list[ComplaintMessageRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(complaint_messages)
            .where(complaint_messages.c.complaint_id == complaint_id)
            .order_by(complaint_messages.c.created_at.asc(), complaint_messages.c.id.asc())
        ).mappings().all()
    return [_row_to_message_model(row) for row in rows]


def send_case_message(
    *,
    complaint_id: int,
    payload: ComplaintMessageSend,
    principal: dict[str, Any] | None = None,
) -> ComplaintMessageRead:
    actor_username = _actor_username(principal)
    now = _now()
    with get_conn() as conn:
        complaint_row = _load_case_row(conn, complaint_id)
        recipient = normalize_phone(payload.recipient or complaint_row.get("contact_phone"))
        if not recipient:
            raise HTTPException(status_code=422, detail="recipient phone is required")
        delivery = message_provider.send_message(
            site=str(complaint_row["site"]),
            complaint_id=complaint_id,
            recipient=recipient,
            body=payload.body,
            template_key=payload.template_key,
        )
        created = conn.execute(
            insert(complaint_messages).values(
                complaint_id=complaint_id,
                site=str(complaint_row["site"]),
                delivery_kind="sms",
                template_key=normalize_description(payload.template_key) or None,
                recipient=recipient,
                body=payload.body,
                provider_name=str(delivery.get("provider_name") or "stub"),
                provider_message_id=delivery.get("provider_message_id"),
                delivery_status=str(delivery.get("delivery_status") or "queued"),
                error=delivery.get("error"),
                sent_by=actor_username,
                sent_at=delivery.get("sent_at"),
                created_at=now,
            )
        )
        message_id = int(created.inserted_primary_key[0])
        row = conn.execute(select(complaint_messages).where(complaint_messages.c.id == message_id).limit(1)).mappings().first()
    _write_audit_log(
        principal=principal,
        action="complaints.message.send",
        resource_type="complaint_case",
        resource_id=str(complaint_id),
        detail={"message_id": message_id, "recipient": recipient, "delivery_status": delivery.get("delivery_status")},
    )
    return _row_to_message_model(row or {})


def get_message(*, message_id: int) -> ComplaintMessageRead:
    with get_conn() as conn:
        row = _load_message_row(conn, message_id)
    return _row_to_message_model(row)


def update_message(
    *,
    message_id: int,
    payload: ComplaintMessageUpdate,
    principal: dict[str, Any] | None = None,
) -> ComplaintMessageRead:
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        return get_message(message_id=message_id)
    with get_conn() as conn:
        existing = _load_message_row(conn, message_id)
        updated_values: dict[str, Any] = {}
        if "template_key" in changes:
            updated_values["template_key"] = normalize_description(changes["template_key"]) or None
        if "recipient" in changes:
            recipient = normalize_phone(changes["recipient"])
            if not recipient:
                raise HTTPException(status_code=422, detail="recipient phone is required")
            updated_values["recipient"] = recipient
        if "body" in changes:
            body = normalize_description(changes["body"])
            if not body:
                raise HTTPException(status_code=422, detail="body cannot be empty")
            updated_values["body"] = body
        if "delivery_status" in changes:
            updated_values["delivery_status"] = normalize_description(changes["delivery_status"]).lower() or "queued"
        if "error" in changes:
            updated_values["error"] = normalize_description(changes["error"]) or None
        conn.execute(update(complaint_messages).where(complaint_messages.c.id == message_id).values(**updated_values))
        row = _load_message_row(conn, message_id)
    _write_audit_log(
        principal=principal,
        action="complaints.message.update",
        resource_type="complaint_case",
        resource_id=str(existing["complaint_id"]),
        detail={"message_id": message_id, "changed_fields": sorted(updated_values.keys())},
    )
    return _row_to_message_model(row)


def delete_message(
    *,
    message_id: int,
    principal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    with get_conn() as conn:
        existing = _load_message_row(conn, message_id)
        deleted_count = int(conn.execute(delete(complaint_messages).where(complaint_messages.c.id == message_id)).rowcount or 0)
    _write_audit_log(
        principal=principal,
        action="complaints.message.delete",
        resource_type="complaint_case",
        resource_id=str(existing["complaint_id"]),
        detail={"message_id": message_id, "recipient": str(existing["recipient"])},
    )
    return {"deleted": deleted_count > 0, "message_id": message_id, "complaint_id": int(existing["complaint_id"])}


def list_cost_items(*, complaint_id: int) -> list[ComplaintCostItemRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(complaint_cost_items)
            .where(complaint_cost_items.c.complaint_id == complaint_id)
            .order_by(complaint_cost_items.c.created_at.asc(), complaint_cost_items.c.id.asc())
        ).mappings().all()
    return [_row_to_cost_item_model(row) for row in rows]


def add_cost_item(
    *,
    complaint_id: int,
    payload: ComplaintCostItemCreate,
    principal: dict[str, Any] | None = None,
) -> ComplaintCostItemRead:
    actor_username = _actor_username(principal)
    now = _now()
    total_cost = payload.total_cost
    if total_cost is None:
        total_cost = (
            float(payload.quantity) * float(payload.unit_price)
            + float(payload.material_cost)
            + float(payload.labor_cost)
            + float(payload.vendor_cost)
        )
    with get_conn() as conn:
        _load_case_row(conn, complaint_id)
        created = conn.execute(
            insert(complaint_cost_items).values(
                complaint_id=complaint_id,
                cost_category=normalize_description(payload.cost_category).lower() or "other",
                item_name=normalize_description(payload.item_name),
                quantity=float(payload.quantity),
                unit_price=float(payload.unit_price),
                material_cost=float(payload.material_cost),
                labor_cost=float(payload.labor_cost),
                vendor_cost=float(payload.vendor_cost),
                total_cost=float(total_cost),
                note=normalize_description(payload.note),
                approved_by=None,
                approved_at=None,
                created_by=actor_username,
                created_at=now,
                updated_at=now,
            )
        )
        cost_item_id = int(created.inserted_primary_key[0])
        row = conn.execute(select(complaint_cost_items).where(complaint_cost_items.c.id == cost_item_id).limit(1)).mappings().first()
    _write_audit_log(
        principal=principal,
        action="complaints.cost.create",
        resource_type="complaint_case",
        resource_id=str(complaint_id),
        detail={"cost_item_id": cost_item_id, "total_cost": float(total_cost)},
    )
    return _row_to_cost_item_model(row or {})


def get_cost_item(*, cost_item_id: int) -> ComplaintCostItemRead:
    with get_conn() as conn:
        row = _load_cost_item_row(conn, cost_item_id)
    return _row_to_cost_item_model(row)


def update_cost_item(
    *,
    cost_item_id: int,
    payload: ComplaintCostItemUpdate,
    principal: dict[str, Any] | None = None,
) -> ComplaintCostItemRead:
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        return get_cost_item(cost_item_id=cost_item_id)
    with get_conn() as conn:
        existing = _load_cost_item_row(conn, cost_item_id)
        updated_values: dict[str, Any] = {}
        if "cost_category" in changes:
            updated_values["cost_category"] = normalize_description(changes["cost_category"]).lower() or "other"
        if "item_name" in changes:
            item_name = normalize_description(changes["item_name"])
            if not item_name:
                raise HTTPException(status_code=422, detail="item_name cannot be empty")
            updated_values["item_name"] = item_name
        numeric_fields = ("quantity", "unit_price", "material_cost", "labor_cost", "vendor_cost")
        for field_name in numeric_fields:
            if field_name in changes:
                updated_values[field_name] = float(changes[field_name])
        if "note" in changes:
            updated_values["note"] = normalize_description(changes["note"])
        if "approved_by" in changes:
            updated_values["approved_by"] = normalize_description(changes["approved_by"]) or None
        if "approved_at" in changes:
            updated_values["approved_at"] = _as_optional_datetime(changes["approved_at"])
        if "total_cost" in changes:
            updated_values["total_cost"] = float(changes["total_cost"])
        elif any(field_name in changes for field_name in numeric_fields):
            updated_values["total_cost"] = (
                float(updated_values.get("quantity", existing.get("quantity") or 0.0))
                * float(updated_values.get("unit_price", existing.get("unit_price") or 0.0))
                + float(updated_values.get("material_cost", existing.get("material_cost") or 0.0))
                + float(updated_values.get("labor_cost", existing.get("labor_cost") or 0.0))
                + float(updated_values.get("vendor_cost", existing.get("vendor_cost") or 0.0))
            )
        updated_values["updated_at"] = _now()
        conn.execute(update(complaint_cost_items).where(complaint_cost_items.c.id == cost_item_id).values(**updated_values))
        row = _load_cost_item_row(conn, cost_item_id)
    _write_audit_log(
        principal=principal,
        action="complaints.cost.update",
        resource_type="complaint_case",
        resource_id=str(existing["complaint_id"]),
        detail={"cost_item_id": cost_item_id, "changed_fields": sorted(updated_values.keys())},
    )
    return _row_to_cost_item_model(row)


def delete_cost_item(
    *,
    cost_item_id: int,
    principal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    with get_conn() as conn:
        existing = _load_cost_item_row(conn, cost_item_id)
        deleted_count = int(
            conn.execute(delete(complaint_cost_items).where(complaint_cost_items.c.id == cost_item_id)).rowcount or 0
        )
    _write_audit_log(
        principal=principal,
        action="complaints.cost.delete",
        resource_type="complaint_case",
        resource_id=str(existing["complaint_id"]),
        detail={"cost_item_id": cost_item_id, "item_name": str(existing["item_name"])},
    )
    return {"deleted": deleted_count > 0, "cost_item_id": cost_item_id, "complaint_id": int(existing["complaint_id"])}


def get_case_detail(*, complaint_id: int) -> ComplaintDetailRead:
    with get_conn() as conn:
        row = _load_case_row(conn, complaint_id)
        total_cost_value = conn.execute(
            select(func.coalesce(func.sum(complaint_cost_items.c.total_cost), 0.0))
            .where(complaint_cost_items.c.complaint_id == complaint_id)
        ).scalar_one()
    return ComplaintDetailRead(
        case=_row_to_case_model(row),
        events=list_events(complaint_id=complaint_id),
        attachments=list_attachments(complaint_id=complaint_id),
        messages=list_messages(complaint_id=complaint_id),
        cost_items=list_cost_items(complaint_id=complaint_id),
        total_cost=float(total_cost_value or 0.0),
    )


def get_household_history(
    *,
    site: str,
    building: str,
    unit_number: str,
    allowed_sites: list[str] | None = None,
) -> ComplaintHouseholdHistoryRead:
    normalized_site = _normalize_site(site)
    if allowed_sites is not None and normalized_site not in set(allowed_sites):
        raise HTTPException(status_code=403, detail="Site access denied")
    normalized_building = normalize_building(building)
    normalized_unit = normalize_unit_number(unit_number)
    complaints = list_cases(
        site=normalized_site,
        building=normalized_building,
        unit_number=normalized_unit,
        allowed_sites=allowed_sites,
    )
    resident_name = next((row.resident_name for row in complaints if row.resident_name), None)
    return ComplaintHouseholdHistoryRead(
        site=normalized_site,
        building=normalized_building,
        unit_number=normalized_unit,
        resident_name=resident_name,
        complaints=complaints,
    )


def import_case_row(
    *,
    row: dict[str, Any],
    actor_username: str = "importer",
) -> dict[str, Any]:
    now = _now()
    site = _normalize_site(row["site"])
    building = normalize_building(row["building"])
    unit_number = normalize_unit_number(row["unit_number"])
    description = normalize_description(row["description"])
    contact_phone = normalize_phone(row.get("contact_phone"))
    reported_at = _normalize_reported_at(row.get("reported_at"))
    complaint_type = _normalize_complaint_type(row.get("complaint_type"), description=description)
    case_key = row.get("case_key") or build_case_key(
        site=site,
        building=building,
        unit_number=unit_number,
        description=description,
        contact_phone=contact_phone,
        reported_at=reported_at,
    )
    with get_conn() as conn:
        existing = conn.execute(
            select(complaint_cases).where(complaint_cases.c.case_key == case_key).limit(1)
        ).mappings().first()
        if existing is None:
            unit_row = _load_unit_row(conn, site=site, building=building, unit_number=unit_number)
            resident_name = str(unit_row.get("occupant_name") or "").strip() if unit_row is not None else None
            created = conn.execute(
                insert(complaint_cases).values(
                    case_key=case_key,
                    site=site,
                    building=building,
                    unit_number=unit_number,
                    resident_name=resident_name or None,
                    contact_phone=contact_phone,
                    complaint_type=complaint_type,
                    title=_build_title(building=building, unit_number=unit_number, complaint_type=complaint_type),
                    description=description,
                    status="received",
                    priority="medium",
                    source_channel=_normalize_source_channel(row.get("source_channel")),
                    reported_at=reported_at,
                    scheduled_visit_at=None,
                    resolved_at=None,
                    resident_confirmed_at=None,
                    closed_at=None,
                    recurrence_flag=False,
                    recurrence_count=0,
                    assignee=None,
                    linked_work_order_id=None,
                    import_batch_id=row.get("import_batch_id"),
                    source_workbook=row.get("source_workbook"),
                    source_sheet=row.get("source_sheet"),
                    source_row_number=row.get("source_row_number"),
                    source_row_hash=row.get("source_row_hash"),
                    created_by=actor_username,
                    created_at=now,
                    updated_at=now,
                )
            )
            complaint_id = int(created.inserted_primary_key[0])
            conn.execute(
                insert(complaint_events).values(
                    complaint_id=complaint_id,
                    event_type="imported",
                    from_status=None,
                    to_status="received",
                    note="legacy excel import",
                    detail_json=_json_dumps(
                        {
                            "source_workbook": row.get("source_workbook"),
                            "source_sheet": row.get("source_sheet"),
                            "source_row_number": row.get("source_row_number"),
                        }
                    ),
                    actor_username=actor_username,
                    created_at=now,
                )
            )
            return {"action": "created", "complaint_id": complaint_id, "case_key": case_key}

        update_values: dict[str, Any] = {}
        for key in ("contact_phone", "source_workbook", "source_sheet", "source_row_number", "source_row_hash", "import_batch_id"):
            if existing.get(key) in {None, ""} and row.get(key) not in {None, ""}:
                update_values[key] = row.get(key)
        if existing.get("reported_at") is None and reported_at is not None:
            update_values["reported_at"] = reported_at
        if update_values:
            update_values["updated_at"] = now
            conn.execute(update(complaint_cases).where(complaint_cases.c.id == int(existing["id"])).values(**update_values))
            return {"action": "updated", "complaint_id": int(existing["id"]), "case_key": case_key}
        return {"action": "duplicate", "complaint_id": int(existing["id"]), "case_key": case_key}
