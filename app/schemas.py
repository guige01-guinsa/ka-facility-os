from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class InspectionCreate(BaseModel):
    site: str = Field(min_length=1, max_length=120)
    location: str = Field(min_length=1, max_length=120)
    cycle: str = Field(min_length=1, max_length=40)
    inspector: str = Field(min_length=1, max_length=80)
    inspected_at: datetime
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


WorkOrderPriority = Literal["low", "medium", "high", "critical"]
WorkOrderStatus = Literal["open", "acked", "completed", "canceled"]


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
    due_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    resolution_notes: str
    is_escalated: bool
    is_overdue: bool
    created_at: datetime
    updated_at: datetime


class SlaEscalationRunRequest(BaseModel):
    site: Optional[str] = Field(default=None, max_length=120)
    dry_run: bool = False
    limit: int = Field(default=200, ge=1, le=2000)


class SlaEscalationRunResponse(BaseModel):
    checked_at: datetime
    dry_run: bool
    site: Optional[str] = None
    candidate_count: int
    escalated_count: int
    work_order_ids: list[int]


class MonthlyReportRead(BaseModel):
    month: str
    site: Optional[str] = None
    generated_at: datetime
    inspections: dict[str, Any]
    work_orders: dict[str, Any]
