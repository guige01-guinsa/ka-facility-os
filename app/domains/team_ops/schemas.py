"""Pydantic schemas for the team operations module."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class TeamOpsQuickLinkRead(BaseModel):
    label: str
    href: str


class TeamOpsCategoryCountRead(BaseModel):
    category: str
    category_label: str
    count: int


class TeamOpsDashboardRead(BaseModel):
    site: str
    range_key: str
    range_label: str
    log_total: int
    log_completed: int
    log_active: int
    log_high_priority: int
    facility_active: int
    inventory_attention: int
    work_orders_open: int
    complaints_active: int
    inspections_recent: int
    official_documents_open: int
    category_counts: list[TeamOpsCategoryCountRead] = Field(default_factory=list)
    quick_links: list[TeamOpsQuickLinkRead] = Field(default_factory=list)


class TeamOpsLogCreate(BaseModel):
    site: str
    recorded_at: datetime
    reporter: str
    category: str = "general"
    location: str
    issue: str
    action_taken: str = ""
    status: str = "in_progress"
    priority: str = "medium"
    photo_count: int = 0
    linked_work_order_id: int | None = None
    linked_complaint_id: int | None = None


class TeamOpsLogUpdate(BaseModel):
    recorded_at: datetime | None = None
    reporter: str | None = None
    category: str | None = None
    location: str | None = None
    issue: str | None = None
    action_taken: str | None = None
    status: str | None = None
    priority: str | None = None
    photo_count: int | None = None
    linked_work_order_id: int | None = None
    linked_complaint_id: int | None = None


class TeamOpsLogRead(BaseModel):
    id: int
    site: str
    recorded_at: datetime
    reporter: str
    category: str
    category_label: str
    location: str
    issue: str
    action_taken: str
    status: str
    status_label: str
    priority: str
    priority_label: str
    photo_count: int
    linked_work_order_id: int | None = None
    linked_complaint_id: int | None = None
    created_by: str
    created_at: datetime
    updated_at: datetime


class TeamOpsFacilityCreate(BaseModel):
    site: str
    facility_type: str
    location: str
    detail: str = ""
    note: str = ""
    is_active: bool = True
    last_checked_at: datetime | None = None


class TeamOpsFacilityUpdate(BaseModel):
    facility_type: str | None = None
    location: str | None = None
    detail: str | None = None
    note: str | None = None
    is_active: bool | None = None
    last_checked_at: datetime | None = None


class TeamOpsFacilityRead(BaseModel):
    id: int
    site: str
    facility_type: str
    location: str
    detail: str
    note: str
    is_active: bool
    last_checked_at: datetime | None = None
    created_by: str
    created_at: datetime
    updated_at: datetime


class TeamOpsInventoryCreate(BaseModel):
    site: str
    item_kind: str = "material"
    item_name: str
    stock_quantity: float = 0.0
    unit: str = "개"
    storage_place: str = ""
    status: str = "normal"
    note: str = ""


class TeamOpsInventoryUpdate(BaseModel):
    item_kind: str | None = None
    item_name: str | None = None
    stock_quantity: float | None = None
    unit: str | None = None
    storage_place: str | None = None
    status: str | None = None
    note: str | None = None


class TeamOpsInventoryRead(BaseModel):
    id: int
    site: str
    item_kind: str
    item_kind_label: str
    item_name: str
    stock_quantity: float
    unit: str
    storage_place: str
    status: str
    status_label: str
    note: str
    updated_by: str
    created_at: datetime
    updated_at: datetime
