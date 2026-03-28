"""Service layer for the team operations module."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

from fastapi import HTTPException
from sqlalchemy import String, cast, delete, func, insert, or_, select, update

from app.database import (
    complaint_cases,
    get_conn,
    inspections,
    official_documents,
    team_ops_facilities,
    team_ops_inventory_items,
    team_ops_logs,
    work_orders,
)
from app.domains.iam.service import _write_audit_log
from app.domains.team_ops.schemas import (
    TeamOpsCategoryCountRead,
    TeamOpsDashboardRead,
    TeamOpsFacilityCreate,
    TeamOpsFacilityRead,
    TeamOpsFacilityUpdate,
    TeamOpsInventoryCreate,
    TeamOpsInventoryRead,
    TeamOpsInventoryUpdate,
    TeamOpsLogCreate,
    TeamOpsLogRead,
    TeamOpsLogUpdate,
    TeamOpsQuickLinkRead,
)


LOG_CATEGORY_LABELS: dict[str, str] = {
    "electrical": "전기",
    "mechanical": "기계",
    "fire": "소방",
    "plumbing": "설비",
    "civil": "건축",
    "general": "기타",
}
LOG_STATUS_LABELS: dict[str, str] = {
    "planned": "점검예정",
    "in_progress": "진행중",
    "completed": "완료",
    "blocked": "보류",
}
LOG_PRIORITY_LABELS: dict[str, str] = {
    "low": "낮음",
    "medium": "보통",
    "high": "높음",
    "critical": "긴급",
}
INVENTORY_KIND_LABELS: dict[str, str] = {
    "tool": "공구",
    "material": "자재",
    "spare": "예비품",
    "consumable": "소모품",
}
INVENTORY_STATUS_LABELS: dict[str, str] = {
    "normal": "정상",
    "needs_check": "점검필요",
    "low_stock": "부족",
    "out_of_stock": "품절",
}
DASHBOARD_RANGE_LABELS: dict[str, str] = {
    "day": "일간",
    "week": "주간",
    "month": "월간",
    "all": "전체",
}
ACTIVE_LOG_STATUSES = {"planned", "in_progress", "blocked"}
HIGH_LOG_PRIORITIES = {"high", "critical"}
ACTIVE_COMPLAINT_STATUSES = {"received", "assigned", "visit_scheduled", "in_progress", "reopened"}
OPEN_WORK_ORDER_STATUSES = {"open", "acked"}
OPEN_OFFICIAL_DOCUMENT_STATUSES = {"received", "in_progress", "pending", "overdue"}


def _normalize_text(value: Any) -> str:
    return " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split()).strip()


def _require_site(site: Any) -> str:
    normalized = _normalize_text(site)
    if not normalized:
        raise HTTPException(status_code=422, detail="site is required")
    return normalized


def _ensure_site_allowed(site: str, allowed_sites: list[str] | None) -> None:
    if allowed_sites is None:
        return
    if site not in allowed_sites:
        raise HTTPException(status_code=403, detail="Site access denied")


def _normalize_choice(value: Any, choices: dict[str, str], field_name: str) -> str:
    normalized = _normalize_text(value).lower()
    if normalized not in choices:
        raise HTTPException(status_code=422, detail=f"{field_name} must be one of {sorted(choices)}")
    return normalized


def _normalize_non_empty(value: Any, field_name: str) -> str:
    normalized = _normalize_text(value)
    if not normalized:
        raise HTTPException(status_code=422, detail=f"{field_name} is required")
    return normalized


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_datetime(value: Any, field_name: str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    raise HTTPException(status_code=422, detail=f"{field_name} must be a datetime")


def _as_optional_datetime(value: Any, field_name: str) -> datetime | None:
    if value is None:
        return None
    return _as_datetime(value, field_name)


def _safe_float(value: Any, field_name: str) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"{field_name} must be numeric") from exc
    return numeric


def _safe_int(value: Any, field_name: str) -> int:
    try:
        numeric = int(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"{field_name} must be an integer") from exc
    return numeric


def _row_to_log_model(row: dict[str, Any]) -> TeamOpsLogRead:
    category = str(row.get("category") or "general")
    status = str(row.get("status") or "in_progress")
    priority = str(row.get("priority") or "medium")
    return TeamOpsLogRead(
        id=int(row["id"]),
        site=str(row["site"]),
        recorded_at=_as_datetime(row["recorded_at"], "recorded_at"),
        reporter=str(row["reporter"]),
        category=category,
        category_label=LOG_CATEGORY_LABELS.get(category, category),
        location=str(row["location"]),
        issue=str(row.get("issue") or ""),
        action_taken=str(row.get("action_taken") or ""),
        status=status,
        status_label=LOG_STATUS_LABELS.get(status, status),
        priority=priority,
        priority_label=LOG_PRIORITY_LABELS.get(priority, priority),
        photo_count=int(row.get("photo_count") or 0),
        linked_work_order_id=row.get("linked_work_order_id"),
        linked_complaint_id=row.get("linked_complaint_id"),
        created_by=str(row.get("created_by") or "system"),
        created_at=_as_datetime(row["created_at"], "created_at"),
        updated_at=_as_datetime(row["updated_at"], "updated_at"),
    )


def _row_to_facility_model(row: dict[str, Any]) -> TeamOpsFacilityRead:
    return TeamOpsFacilityRead(
        id=int(row["id"]),
        site=str(row["site"]),
        facility_type=str(row["facility_type"]),
        location=str(row["location"]),
        detail=str(row.get("detail") or ""),
        note=str(row.get("note") or ""),
        is_active=bool(row.get("is_active")),
        last_checked_at=_as_optional_datetime(row.get("last_checked_at"), "last_checked_at"),
        created_by=str(row.get("created_by") or "system"),
        created_at=_as_datetime(row["created_at"], "created_at"),
        updated_at=_as_datetime(row["updated_at"], "updated_at"),
    )


def _row_to_inventory_model(row: dict[str, Any]) -> TeamOpsInventoryRead:
    kind = str(row.get("item_kind") or "material")
    status = str(row.get("status") or "normal")
    return TeamOpsInventoryRead(
        id=int(row["id"]),
        site=str(row["site"]),
        item_kind=kind,
        item_kind_label=INVENTORY_KIND_LABELS.get(kind, kind),
        item_name=str(row["item_name"]),
        stock_quantity=float(row.get("stock_quantity") or 0.0),
        unit=str(row.get("unit") or ""),
        storage_place=str(row.get("storage_place") or ""),
        status=status,
        status_label=INVENTORY_STATUS_LABELS.get(status, status),
        note=str(row.get("note") or ""),
        updated_by=str(row.get("updated_by") or "system"),
        created_at=_as_datetime(row["created_at"], "created_at"),
        updated_at=_as_datetime(row["updated_at"], "updated_at"),
    )


def _search_clause(columns: list[Any], q: str | None) -> Any | None:
    normalized = _normalize_text(q).lower()
    if not normalized:
        return None
    pattern = f"%{normalized}%"
    return or_(*[func.lower(cast(column, String)).like(pattern) for column in columns])


def _load_log_row(*, log_id: int) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute(select(team_ops_logs).where(team_ops_logs.c.id == log_id).limit(1)).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Team log not found")
    return dict(row)


def _load_facility_row(*, facility_id: int) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute(
            select(team_ops_facilities).where(team_ops_facilities.c.id == facility_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Facility record not found")
    return dict(row)


def _load_inventory_row(*, item_id: int) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute(
            select(team_ops_inventory_items).where(team_ops_inventory_items.c.id == item_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Inventory item not found")
    return dict(row)


def _quick_links(site: str) -> list[TeamOpsQuickLinkRead]:
    encoded_site = quote(site)
    month = _now().strftime("%Y-%m")
    return [
        TeamOpsQuickLinkRead(label="작업지시", href=f"/api/work-orders?site={encoded_site}"),
        TeamOpsQuickLinkRead(label="세대 민원", href="/web/complaints"),
        TeamOpsQuickLinkRead(label="점검 목록", href=f"/api/inspections?site={encoded_site}"),
        TeamOpsQuickLinkRead(label="공문 월간 리포트", href=f"/api/reports/official-documents/monthly?site={encoded_site}&month={month}"),
        TeamOpsQuickLinkRead(label="통합 월간 리포트", href=f"/api/reports/monthly/integrated?site={encoded_site}&month={month}"),
    ]


def _dashboard_range_start(range_key: str) -> datetime | None:
    now = _now()
    if range_key == "day":
        return now - timedelta(days=1)
    if range_key == "week":
        return now - timedelta(days=7)
    if range_key == "month":
        return now - timedelta(days=30)
    if range_key == "all":
        return None
    raise HTTPException(status_code=422, detail=f"range_key must be one of {sorted(DASHBOARD_RANGE_LABELS)}")


def get_dashboard(*, site: str, range_key: str, allowed_sites: list[str] | None) -> TeamOpsDashboardRead:
    normalized_site = _require_site(site)
    _ensure_site_allowed(normalized_site, allowed_sites)
    range_start = _dashboard_range_start(range_key)
    now = _now()

    log_filters = [team_ops_logs.c.site == normalized_site]
    if range_start is not None:
        log_filters.append(team_ops_logs.c.recorded_at >= range_start)

    with get_conn() as conn:
        log_total = int(conn.execute(select(func.count()).select_from(team_ops_logs).where(*log_filters)).scalar_one() or 0)
        log_completed = int(
            conn.execute(
                select(func.count())
                .select_from(team_ops_logs)
                .where(*log_filters)
                .where(team_ops_logs.c.status == "completed")
            ).scalar_one()
            or 0
        )
        log_active = int(
            conn.execute(
                select(func.count())
                .select_from(team_ops_logs)
                .where(*log_filters)
                .where(team_ops_logs.c.status.in_(sorted(ACTIVE_LOG_STATUSES)))
            ).scalar_one()
            or 0
        )
        log_high_priority = int(
            conn.execute(
                select(func.count())
                .select_from(team_ops_logs)
                .where(*log_filters)
                .where(team_ops_logs.c.priority.in_(sorted(HIGH_LOG_PRIORITIES)))
            ).scalar_one()
            or 0
        )
        category_rows = conn.execute(
            select(team_ops_logs.c.category, func.count().label("count"))
            .where(*log_filters)
            .group_by(team_ops_logs.c.category)
            .order_by(func.count().desc(), team_ops_logs.c.category.asc())
        ).all()
        facility_active = int(
            conn.execute(
                select(func.count())
                .select_from(team_ops_facilities)
                .where(team_ops_facilities.c.site == normalized_site)
                .where(team_ops_facilities.c.is_active.is_(True))
            ).scalar_one()
            or 0
        )
        inventory_attention = int(
            conn.execute(
                select(func.count())
                .select_from(team_ops_inventory_items)
                .where(team_ops_inventory_items.c.site == normalized_site)
                .where(team_ops_inventory_items.c.status.in_(["needs_check", "low_stock", "out_of_stock"]))
            ).scalar_one()
            or 0
        )
        work_orders_open = int(
            conn.execute(
                select(func.count())
                .select_from(work_orders)
                .where(work_orders.c.site == normalized_site)
                .where(work_orders.c.status.in_(sorted(OPEN_WORK_ORDER_STATUSES)))
            ).scalar_one()
            or 0
        )
        complaints_active = int(
            conn.execute(
                select(func.count())
                .select_from(complaint_cases)
                .where(complaint_cases.c.site == normalized_site)
                .where(complaint_cases.c.status.in_(sorted(ACTIVE_COMPLAINT_STATUSES)))
            ).scalar_one()
            or 0
        )
        inspections_recent = int(
            conn.execute(
                select(func.count())
                .select_from(inspections)
                .where(inspections.c.site == normalized_site)
                .where(inspections.c.inspected_at >= now - timedelta(days=30))
            ).scalar_one()
            or 0
        )
        official_documents_open = int(
            conn.execute(
                select(func.count())
                .select_from(official_documents)
                .where(official_documents.c.site == normalized_site)
                .where(official_documents.c.status.in_(sorted(OPEN_OFFICIAL_DOCUMENT_STATUSES)))
            ).scalar_one()
            or 0
        )

    return TeamOpsDashboardRead(
        site=normalized_site,
        range_key=range_key,
        range_label=DASHBOARD_RANGE_LABELS[range_key],
        log_total=log_total,
        log_completed=log_completed,
        log_active=log_active,
        log_high_priority=log_high_priority,
        facility_active=facility_active,
        inventory_attention=inventory_attention,
        work_orders_open=work_orders_open,
        complaints_active=complaints_active,
        inspections_recent=inspections_recent,
        official_documents_open=official_documents_open,
        category_counts=[
            TeamOpsCategoryCountRead(
                category=str(row.category),
                category_label=LOG_CATEGORY_LABELS.get(str(row.category), str(row.category)),
                count=int(row.count or 0),
            )
            for row in category_rows
        ],
        quick_links=_quick_links(normalized_site),
    )


def list_logs(*, site: str, q: str | None, limit: int, allowed_sites: list[str] | None) -> list[TeamOpsLogRead]:
    normalized_site = _require_site(site)
    _ensure_site_allowed(normalized_site, allowed_sites)
    stmt = select(team_ops_logs).where(team_ops_logs.c.site == normalized_site)
    search_clause = _search_clause(
        [
            team_ops_logs.c.reporter,
            team_ops_logs.c.category,
            team_ops_logs.c.location,
            team_ops_logs.c.issue,
            team_ops_logs.c.action_taken,
            team_ops_logs.c.status,
            team_ops_logs.c.priority,
        ],
        q,
    )
    if search_clause is not None:
        stmt = stmt.where(search_clause)
    stmt = stmt.order_by(team_ops_logs.c.recorded_at.desc(), team_ops_logs.c.id.desc()).limit(limit)
    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_log_model(dict(row)) for row in rows]


def create_log(*, payload: TeamOpsLogCreate, principal: dict[str, Any], allowed_sites: list[str] | None) -> TeamOpsLogRead:
    site = _require_site(payload.site)
    _ensure_site_allowed(site, allowed_sites)
    actor = str(principal.get("username") or "system")
    now = _now()
    values = {
        "site": site,
        "recorded_at": _as_datetime(payload.recorded_at, "recorded_at"),
        "reporter": _normalize_non_empty(payload.reporter, "reporter"),
        "category": _normalize_choice(payload.category, LOG_CATEGORY_LABELS, "category"),
        "location": _normalize_non_empty(payload.location, "location"),
        "issue": _normalize_non_empty(payload.issue, "issue"),
        "action_taken": _normalize_text(payload.action_taken),
        "status": _normalize_choice(payload.status, LOG_STATUS_LABELS, "status"),
        "priority": _normalize_choice(payload.priority, LOG_PRIORITY_LABELS, "priority"),
        "photo_count": max(0, _safe_int(payload.photo_count, "photo_count")),
        "linked_work_order_id": payload.linked_work_order_id,
        "linked_complaint_id": payload.linked_complaint_id,
        "created_by": actor,
        "created_at": now,
        "updated_at": now,
    }
    with get_conn() as conn:
        result = conn.execute(insert(team_ops_logs).values(**values))
        log_id = int(result.inserted_primary_key[0])
        row = conn.execute(select(team_ops_logs).where(team_ops_logs.c.id == log_id).limit(1)).mappings().first()
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create team log")
    model = _row_to_log_model(dict(row))
    _write_audit_log(
        principal=principal,
        action="team_ops.log.create",
        resource_type="team_ops_log",
        resource_id=str(model.id),
        detail={"site": model.site, "category": model.category, "status": model.status},
    )
    return model


def update_log(*, log_id: int, payload: TeamOpsLogUpdate, principal: dict[str, Any], allowed_sites: list[str] | None) -> TeamOpsLogRead:
    existing = _load_log_row(log_id=log_id)
    _ensure_site_allowed(str(existing["site"]), allowed_sites)
    values: dict[str, Any] = {"updated_at": _now()}
    if payload.recorded_at is not None:
        values["recorded_at"] = _as_datetime(payload.recorded_at, "recorded_at")
    if payload.reporter is not None:
        values["reporter"] = _normalize_non_empty(payload.reporter, "reporter")
    if payload.category is not None:
        values["category"] = _normalize_choice(payload.category, LOG_CATEGORY_LABELS, "category")
    if payload.location is not None:
        values["location"] = _normalize_non_empty(payload.location, "location")
    if payload.issue is not None:
        values["issue"] = _normalize_non_empty(payload.issue, "issue")
    if payload.action_taken is not None:
        values["action_taken"] = _normalize_text(payload.action_taken)
    if payload.status is not None:
        values["status"] = _normalize_choice(payload.status, LOG_STATUS_LABELS, "status")
    if payload.priority is not None:
        values["priority"] = _normalize_choice(payload.priority, LOG_PRIORITY_LABELS, "priority")
    if payload.photo_count is not None:
        values["photo_count"] = max(0, _safe_int(payload.photo_count, "photo_count"))
    if "linked_work_order_id" in payload.model_fields_set:
        values["linked_work_order_id"] = payload.linked_work_order_id
    if "linked_complaint_id" in payload.model_fields_set:
        values["linked_complaint_id"] = payload.linked_complaint_id
    with get_conn() as conn:
        conn.execute(update(team_ops_logs).where(team_ops_logs.c.id == log_id).values(**values))
        row = conn.execute(select(team_ops_logs).where(team_ops_logs.c.id == log_id).limit(1)).mappings().first()
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to update team log")
    model = _row_to_log_model(dict(row))
    _write_audit_log(
        principal=principal,
        action="team_ops.log.update",
        resource_type="team_ops_log",
        resource_id=str(model.id),
        detail={"site": model.site, "status": model.status},
    )
    return model


def list_facilities(*, site: str, q: str | None, limit: int, allowed_sites: list[str] | None) -> list[TeamOpsFacilityRead]:
    normalized_site = _require_site(site)
    _ensure_site_allowed(normalized_site, allowed_sites)
    stmt = select(team_ops_facilities).where(team_ops_facilities.c.site == normalized_site)
    search_clause = _search_clause(
        [
            team_ops_facilities.c.facility_type,
            team_ops_facilities.c.location,
            team_ops_facilities.c.detail,
            team_ops_facilities.c.note,
        ],
        q,
    )
    if search_clause is not None:
        stmt = stmt.where(search_clause)
    stmt = stmt.order_by(team_ops_facilities.c.location.asc(), team_ops_facilities.c.id.asc()).limit(limit)
    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_facility_model(dict(row)) for row in rows]


def create_facility(*, payload: TeamOpsFacilityCreate, principal: dict[str, Any], allowed_sites: list[str] | None) -> TeamOpsFacilityRead:
    site = _require_site(payload.site)
    _ensure_site_allowed(site, allowed_sites)
    actor = str(principal.get("username") or "system")
    now = _now()
    values = {
        "site": site,
        "facility_type": _normalize_non_empty(payload.facility_type, "facility_type"),
        "location": _normalize_non_empty(payload.location, "location"),
        "detail": _normalize_text(payload.detail),
        "note": _normalize_text(payload.note),
        "is_active": bool(payload.is_active),
        "last_checked_at": _as_optional_datetime(payload.last_checked_at, "last_checked_at"),
        "created_by": actor,
        "created_at": now,
        "updated_at": now,
    }
    with get_conn() as conn:
        result = conn.execute(insert(team_ops_facilities).values(**values))
        facility_id = int(result.inserted_primary_key[0])
        row = conn.execute(
            select(team_ops_facilities).where(team_ops_facilities.c.id == facility_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create facility record")
    model = _row_to_facility_model(dict(row))
    _write_audit_log(
        principal=principal,
        action="team_ops.facility.create",
        resource_type="team_ops_facility",
        resource_id=str(model.id),
        detail={"site": model.site, "facility_type": model.facility_type},
    )
    return model


def update_facility(*, facility_id: int, payload: TeamOpsFacilityUpdate, principal: dict[str, Any], allowed_sites: list[str] | None) -> TeamOpsFacilityRead:
    existing = _load_facility_row(facility_id=facility_id)
    _ensure_site_allowed(str(existing["site"]), allowed_sites)
    values: dict[str, Any] = {"updated_at": _now()}
    if payload.facility_type is not None:
        values["facility_type"] = _normalize_non_empty(payload.facility_type, "facility_type")
    if payload.location is not None:
        values["location"] = _normalize_non_empty(payload.location, "location")
    if payload.detail is not None:
        values["detail"] = _normalize_text(payload.detail)
    if payload.note is not None:
        values["note"] = _normalize_text(payload.note)
    if payload.is_active is not None:
        values["is_active"] = bool(payload.is_active)
    if "last_checked_at" in payload.model_fields_set:
        values["last_checked_at"] = _as_optional_datetime(payload.last_checked_at, "last_checked_at")
    with get_conn() as conn:
        conn.execute(update(team_ops_facilities).where(team_ops_facilities.c.id == facility_id).values(**values))
        row = conn.execute(
            select(team_ops_facilities).where(team_ops_facilities.c.id == facility_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to update facility record")
    model = _row_to_facility_model(dict(row))
    _write_audit_log(
        principal=principal,
        action="team_ops.facility.update",
        resource_type="team_ops_facility",
        resource_id=str(model.id),
        detail={"site": model.site, "facility_type": model.facility_type},
    )
    return model


def list_inventory(*, site: str, q: str | None, limit: int, allowed_sites: list[str] | None) -> list[TeamOpsInventoryRead]:
    normalized_site = _require_site(site)
    _ensure_site_allowed(normalized_site, allowed_sites)
    stmt = select(team_ops_inventory_items).where(team_ops_inventory_items.c.site == normalized_site)
    search_clause = _search_clause(
        [
            team_ops_inventory_items.c.item_kind,
            team_ops_inventory_items.c.item_name,
            team_ops_inventory_items.c.storage_place,
            team_ops_inventory_items.c.status,
            team_ops_inventory_items.c.note,
        ],
        q,
    )
    if search_clause is not None:
        stmt = stmt.where(search_clause)
    stmt = stmt.order_by(team_ops_inventory_items.c.item_name.asc(), team_ops_inventory_items.c.id.asc()).limit(limit)
    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_inventory_model(dict(row)) for row in rows]


def create_inventory_item(*, payload: TeamOpsInventoryCreate, principal: dict[str, Any], allowed_sites: list[str] | None) -> TeamOpsInventoryRead:
    site = _require_site(payload.site)
    _ensure_site_allowed(site, allowed_sites)
    actor = str(principal.get("username") or "system")
    now = _now()
    values = {
        "site": site,
        "item_kind": _normalize_choice(payload.item_kind, INVENTORY_KIND_LABELS, "item_kind"),
        "item_name": _normalize_non_empty(payload.item_name, "item_name"),
        "stock_quantity": _safe_float(payload.stock_quantity, "stock_quantity"),
        "unit": _normalize_non_empty(payload.unit, "unit"),
        "storage_place": _normalize_text(payload.storage_place),
        "status": _normalize_choice(payload.status, INVENTORY_STATUS_LABELS, "status"),
        "note": _normalize_text(payload.note),
        "updated_by": actor,
        "created_at": now,
        "updated_at": now,
    }
    with get_conn() as conn:
        result = conn.execute(insert(team_ops_inventory_items).values(**values))
        item_id = int(result.inserted_primary_key[0])
        row = conn.execute(
            select(team_ops_inventory_items).where(team_ops_inventory_items.c.id == item_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create inventory item")
    model = _row_to_inventory_model(dict(row))
    _write_audit_log(
        principal=principal,
        action="team_ops.inventory.create",
        resource_type="team_ops_inventory_item",
        resource_id=str(model.id),
        detail={"site": model.site, "item_kind": model.item_kind, "status": model.status},
    )
    return model


def update_inventory_item(*, item_id: int, payload: TeamOpsInventoryUpdate, principal: dict[str, Any], allowed_sites: list[str] | None) -> TeamOpsInventoryRead:
    existing = _load_inventory_row(item_id=item_id)
    _ensure_site_allowed(str(existing["site"]), allowed_sites)
    values: dict[str, Any] = {"updated_at": _now(), "updated_by": str(principal.get("username") or "system")}
    if payload.item_kind is not None:
        values["item_kind"] = _normalize_choice(payload.item_kind, INVENTORY_KIND_LABELS, "item_kind")
    if payload.item_name is not None:
        values["item_name"] = _normalize_non_empty(payload.item_name, "item_name")
    if payload.stock_quantity is not None:
        values["stock_quantity"] = _safe_float(payload.stock_quantity, "stock_quantity")
    if payload.unit is not None:
        values["unit"] = _normalize_non_empty(payload.unit, "unit")
    if payload.storage_place is not None:
        values["storage_place"] = _normalize_text(payload.storage_place)
    if payload.status is not None:
        values["status"] = _normalize_choice(payload.status, INVENTORY_STATUS_LABELS, "status")
    if payload.note is not None:
        values["note"] = _normalize_text(payload.note)
    with get_conn() as conn:
        conn.execute(update(team_ops_inventory_items).where(team_ops_inventory_items.c.id == item_id).values(**values))
        row = conn.execute(
            select(team_ops_inventory_items).where(team_ops_inventory_items.c.id == item_id).limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to update inventory item")
    model = _row_to_inventory_model(dict(row))
    _write_audit_log(
        principal=principal,
        action="team_ops.inventory.update",
        resource_type="team_ops_inventory_item",
        resource_id=str(model.id),
        detail={"site": model.site, "status": model.status},
    )
    return model


def delete_log(*, log_id: int, principal: dict[str, Any], allowed_sites: list[str] | None) -> dict[str, Any]:
    existing = _load_log_row(log_id=log_id)
    _ensure_site_allowed(str(existing["site"]), allowed_sites)
    with get_conn() as conn:
        conn.execute(delete(team_ops_logs).where(team_ops_logs.c.id == log_id))
    _write_audit_log(
        principal=principal,
        action="team_ops.log.delete",
        resource_type="team_ops_log",
        resource_id=str(log_id),
        detail={"site": existing["site"], "category": existing.get("category")},
    )
    return {"deleted": True, "id": log_id}


def delete_facility(*, facility_id: int, principal: dict[str, Any], allowed_sites: list[str] | None) -> dict[str, Any]:
    existing = _load_facility_row(facility_id=facility_id)
    _ensure_site_allowed(str(existing["site"]), allowed_sites)
    with get_conn() as conn:
        conn.execute(delete(team_ops_facilities).where(team_ops_facilities.c.id == facility_id))
    _write_audit_log(
        principal=principal,
        action="team_ops.facility.delete",
        resource_type="team_ops_facility",
        resource_id=str(facility_id),
        detail={"site": existing["site"], "facility_type": existing.get("facility_type")},
    )
    return {"deleted": True, "id": facility_id}


def delete_inventory_item(*, item_id: int, principal: dict[str, Any], allowed_sites: list[str] | None) -> dict[str, Any]:
    existing = _load_inventory_row(item_id=item_id)
    _ensure_site_allowed(str(existing["site"]), allowed_sites)
    with get_conn() as conn:
        conn.execute(delete(team_ops_inventory_items).where(team_ops_inventory_items.c.id == item_id))
    _write_audit_log(
        principal=principal,
        action="team_ops.inventory.delete",
        resource_type="team_ops_inventory_item",
        resource_id=str(item_id),
        detail={"site": existing["site"], "item_name": existing.get("item_name")},
    )
    return {"deleted": True, "id": item_id}
