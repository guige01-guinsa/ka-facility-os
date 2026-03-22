"""Complaint services and normalization helpers."""

from __future__ import annotations

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
    get_conn,
    utility_billing_units,
    work_orders,
)
from app.domains.complaints import message_provider
from app.domains.complaints.schemas import (
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
