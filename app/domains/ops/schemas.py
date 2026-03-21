"""OPS schemas split out from app.schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class InspectionCreate(BaseModel):
    site: str = Field(min_length=1, max_length=120)
    location: str = Field(min_length=1, max_length=120)
    cycle: str = Field(min_length=1, max_length=40)
    inspector: str = Field(min_length=1, max_length=80)
    inspected_at: datetime
    equipment_id: Optional[int] = None
    qr_asset_id: Optional[int] = None
    transformer_kva: Optional[float] = None
    voltage_r: Optional[float] = None
    voltage_s: Optional[float] = None
    voltage_t: Optional[float] = None
    current_r: Optional[float] = None
    current_s: Optional[float] = None
    current_t: Optional[float] = None
    winding_temp_c: Optional[float] = None
    grounding_ohm: Optional[float] = None
    insulation_mohm: Optional[float] = None
    notes: str = ""


class InspectionRead(BaseModel):
    id: int
    site: str
    location: str
    cycle: str
    inspector: str
    inspected_at: datetime
    equipment_id: Optional[int] = None
    qr_asset_id: Optional[int] = None
    equipment_snapshot: Optional[str] = None
    equipment_location_snapshot: Optional[str] = None
    qr_id: Optional[str] = None
    checklist_set_id: Optional[str] = None
    checklist_version: Optional[str] = None
    transformer_kva: Optional[float] = None
    voltage_r: Optional[float] = None
    voltage_s: Optional[float] = None
    voltage_t: Optional[float] = None
    current_r: Optional[float] = None
    current_s: Optional[float] = None
    current_t: Optional[float] = None
    winding_temp_c: Optional[float] = None
    grounding_ohm: Optional[float] = None
    insulation_mohm: Optional[float] = None
    notes: str
    risk_level: str
    risk_flags: list[str]
    created_at: datetime


class InspectionEvidenceRead(BaseModel):
    id: int
    inspection_id: int
    site: str
    file_name: str
    content_type: str
    file_size: int
    storage_backend: str = "db"
    sha256: str = ""
    malware_scan_status: str = "unknown"
    malware_scan_engine: Optional[str] = None
    malware_scanned_at: Optional[datetime] = None
    note: str
    uploaded_by: str
    uploaded_at: datetime


WorkOrderPriority = Literal["low", "medium", "high", "critical"]
WorkOrderStatus = Literal["open", "acked", "completed", "canceled"]
WorkflowLockStatus = Literal["draft", "review", "approved", "locked"]


class WorkOrderCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    site: str = Field(min_length=1, max_length=120)
    location: str = Field(min_length=1, max_length=120)
    priority: WorkOrderPriority = "medium"
    assignee: Optional[str] = Field(default=None, max_length=80)
    reporter: Optional[str] = Field(default=None, max_length=80)
    inspection_id: Optional[int] = None
    due_at: Optional[datetime] = None


class WorkOrderAck(BaseModel):
    assignee: Optional[str] = Field(default=None, max_length=80)


class WorkOrderComplete(BaseModel):
    resolution_notes: str = ""


class WorkOrderCancel(BaseModel):
    reason: str = ""


class WorkOrderReopen(BaseModel):
    reason: str = ""


class WorkOrderCommentCreate(BaseModel):
    comment: str = Field(min_length=1, max_length=2000)


class WorkOrderRead(BaseModel):
    id: int
    title: str
    description: str
    site: str
    location: str
    priority: WorkOrderPriority
    status: WorkOrderStatus
    assignee: Optional[str] = None
    reporter: Optional[str] = None
    inspection_id: Optional[int] = None
    equipment_id: Optional[int] = None
    qr_asset_id: Optional[int] = None
    equipment_snapshot: Optional[str] = None
    equipment_location_snapshot: Optional[str] = None
    qr_id: Optional[str] = None
    checklist_set_id: Optional[str] = None
    due_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    resolution_notes: str
    is_escalated: bool
    is_overdue: bool
    created_at: datetime
    updated_at: datetime


class WorkOrderEventRead(BaseModel):
    id: int
    work_order_id: int
    event_type: str
    actor_username: str
    from_status: Optional[WorkOrderStatus] = None
    to_status: Optional[WorkOrderStatus] = None
    note: str
    detail: dict[str, Any]
    created_at: datetime


class WorkflowLockCreate(BaseModel):
    site: str = Field(min_length=1, max_length=120)
    workflow_key: str = Field(min_length=1, max_length=120)
    content: dict[str, Any] = Field(default_factory=dict)
    requested_ticket: Optional[str] = Field(default=None, max_length=120)


class WorkflowLockDraftUpdate(BaseModel):
    content: Optional[dict[str, Any]] = None
    requested_ticket: Optional[str] = Field(default=None, max_length=120)
    comment: str = ""


class WorkflowLockTransitionRequest(BaseModel):
    comment: str = ""
    reason: str = ""
    requested_ticket: Optional[str] = Field(default=None, max_length=120)


class WorkflowLockRead(BaseModel):
    id: int
    site: str
    workflow_key: str
    status: WorkflowLockStatus
    content: dict[str, Any]
    requested_ticket: Optional[str] = None
    last_comment: str
    lock_reason: Optional[str] = None
    unlock_reason: Optional[str] = None
    created_by: str
    updated_by: str
    reviewed_by: Optional[str] = None
    approved_by: Optional[str] = None
    locked_by: Optional[str] = None
    unlocked_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    reviewed_at: Optional[datetime] = None
    approved_at: Optional[datetime] = None
    locked_at: Optional[datetime] = None
    unlocked_at: Optional[datetime] = None

