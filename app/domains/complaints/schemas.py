"""Complaint schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


ComplaintStatus = Literal[
    "received",
    "assigned",
    "visit_scheduled",
    "in_progress",
    "resolved",
    "resident_confirmed",
    "reopened",
    "closed",
]
ComplaintPriority = Literal["low", "medium", "high", "urgent"]
ComplaintAttachmentKind = Literal["intake", "before", "after", "other"]
ComplaintDeliveryKind = Literal["sms"]


class ComplaintCaseCreate(BaseModel):
    site: str = Field(min_length=1, max_length=120)
    building: str = Field(min_length=1, max_length=120)
    unit_number: str = Field(min_length=1, max_length=40)
    resident_name: Optional[str] = Field(default=None, max_length=120)
    contact_phone: Optional[str] = Field(default=None, max_length=40)
    complaint_type: Optional[str] = Field(default=None, max_length=80)
    title: str = Field(default="", max_length=200)
    description: str = Field(min_length=1)
    status: ComplaintStatus = "received"
    priority: ComplaintPriority = "medium"
    source_channel: str = Field(default="manual", max_length=40)
    reported_at: Optional[datetime] = None
    scheduled_visit_at: Optional[datetime] = None
    assignee: Optional[str] = Field(default=None, max_length=80)
    recurrence_flag: bool = False
    linked_work_order_id: Optional[int] = None


class ComplaintCaseUpdate(BaseModel):
    resident_name: Optional[str] = Field(default=None, max_length=120)
    contact_phone: Optional[str] = Field(default=None, max_length=40)
    complaint_type: Optional[str] = Field(default=None, max_length=80)
    title: Optional[str] = Field(default=None, max_length=200)
    description: Optional[str] = None
    status: Optional[ComplaintStatus] = None
    priority: Optional[ComplaintPriority] = None
    source_channel: Optional[str] = Field(default=None, max_length=40)
    reported_at: Optional[datetime] = None
    scheduled_visit_at: Optional[datetime] = None
    assignee: Optional[str] = Field(default=None, max_length=80)
    recurrence_flag: Optional[bool] = None
    linked_work_order_id: Optional[int] = None


class ComplaintCaseRead(BaseModel):
    id: int
    case_key: str
    site: str
    building: str
    unit_number: str
    resident_name: Optional[str] = None
    contact_phone: Optional[str] = None
    complaint_type: str
    complaint_type_label: str
    title: str
    description: str
    status: ComplaintStatus
    status_label: str
    priority: ComplaintPriority
    priority_label: str
    source_channel: str
    reported_at: datetime
    scheduled_visit_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    resident_confirmed_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    recurrence_flag: bool
    recurrence_count: int
    assignee: Optional[str] = None
    linked_work_order_id: Optional[int] = None
    import_batch_id: Optional[str] = None
    source_workbook: Optional[str] = None
    source_sheet: Optional[str] = None
    source_row_number: Optional[int] = None
    created_by: str
    created_at: datetime
    updated_at: datetime


class ComplaintEventCreate(BaseModel):
    event_type: str = Field(default="note", min_length=1, max_length=40)
    to_status: Optional[ComplaintStatus] = None
    note: str = ""
    detail: dict[str, Any] = Field(default_factory=dict)


class ComplaintEventRead(BaseModel):
    id: int
    complaint_id: int
    event_type: str
    from_status: Optional[ComplaintStatus] = None
    to_status: Optional[ComplaintStatus] = None
    note: str
    detail: dict[str, Any]
    actor_username: str
    created_at: datetime


class ComplaintAttachmentRead(BaseModel):
    id: int
    complaint_id: int
    site: str
    attachment_kind: ComplaintAttachmentKind
    attachment_kind_label: str
    file_name: str
    content_type: str
    file_size: int
    storage_backend: str
    sha256: str
    malware_scan_status: str
    malware_scan_engine: Optional[str] = None
    malware_scanned_at: Optional[datetime] = None
    note: str
    uploaded_by: str
    uploaded_at: datetime


class ComplaintMessageSend(BaseModel):
    delivery_kind: ComplaintDeliveryKind = "sms"
    template_key: Optional[str] = Field(default=None, max_length=80)
    recipient: Optional[str] = Field(default=None, max_length=40)
    body: str = Field(min_length=1)


class ComplaintMessageRead(BaseModel):
    id: int
    complaint_id: int
    site: str
    delivery_kind: ComplaintDeliveryKind
    template_key: Optional[str] = None
    recipient: str
    body: str
    provider_name: str
    provider_message_id: Optional[str] = None
    delivery_status: str
    error: Optional[str] = None
    sent_by: str
    sent_at: Optional[datetime] = None
    created_at: datetime


class ComplaintCostItemCreate(BaseModel):
    cost_category: str = Field(min_length=1, max_length=40)
    item_name: str = Field(min_length=1, max_length=120)
    quantity: float = Field(default=1.0, ge=0)
    unit_price: float = Field(default=0.0, ge=0)
    material_cost: float = Field(default=0.0, ge=0)
    labor_cost: float = Field(default=0.0, ge=0)
    vendor_cost: float = Field(default=0.0, ge=0)
    total_cost: Optional[float] = Field(default=None, ge=0)
    note: str = ""


class ComplaintCostItemRead(BaseModel):
    id: int
    complaint_id: int
    cost_category: str
    item_name: str
    quantity: float
    unit_price: float
    material_cost: float
    labor_cost: float
    vendor_cost: float
    total_cost: float
    note: str
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    created_by: str
    created_at: datetime
    updated_at: datetime


class ComplaintDetailRead(BaseModel):
    case: ComplaintCaseRead
    events: list[ComplaintEventRead]
    attachments: list[ComplaintAttachmentRead]
    messages: list[ComplaintMessageRead]
    cost_items: list[ComplaintCostItemRead]
    total_cost: float = 0.0


class ComplaintHouseholdHistoryRead(BaseModel):
    site: str
    building: str
    unit_number: str
    resident_name: Optional[str] = None
    complaints: list[ComplaintCaseRead]

