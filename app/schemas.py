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
AdminRole = Literal["owner", "manager", "operator", "auditor"]
WorkflowLockStatus = Literal["draft", "review", "approved", "locked"]
W02TrackerStatus = Literal["pending", "in_progress", "done", "blocked"]
W02CompletionStatus = Literal["active", "completed", "completed_with_exceptions"]
W03TrackerStatus = Literal["pending", "in_progress", "done", "blocked"]
W03CompletionStatus = Literal["active", "completed", "completed_with_exceptions"]
W04TrackerStatus = Literal["pending", "in_progress", "done", "blocked"]
W04CompletionStatus = Literal["active", "completed", "completed_with_exceptions"]
W07TrackerStatus = Literal["pending", "in_progress", "done", "blocked"]
W07CompletionStatus = Literal["active", "completed", "completed_with_exceptions"]
W09TrackerStatus = Literal["pending", "in_progress", "done", "blocked"]
W09CompletionStatus = Literal["active", "completed", "completed_with_exceptions"]
W10TrackerStatus = Literal["pending", "in_progress", "done", "blocked"]
W10CompletionStatus = Literal["active", "completed", "completed_with_exceptions"]
W11TrackerStatus = Literal["pending", "in_progress", "done", "blocked"]
W11CompletionStatus = Literal["active", "completed", "completed_with_exceptions"]
W12TrackerStatus = Literal["pending", "in_progress", "done", "blocked"]
W12CompletionStatus = Literal["active", "completed", "completed_with_exceptions"]


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


class W02TrackerBootstrapRequest(BaseModel):
    site: str = Field(min_length=1, max_length=120)


class W02TrackerItemUpdate(BaseModel):
    assignee: Optional[str] = Field(default=None, max_length=120)
    status: Optional[W02TrackerStatus] = None
    completion_checked: Optional[bool] = None
    completion_note: Optional[str] = Field(default=None, max_length=4000)


class W02TrackerItemRead(BaseModel):
    id: int
    site: str
    item_type: str
    item_key: str
    item_name: str
    assignee: Optional[str] = None
    status: W02TrackerStatus
    completion_checked: bool
    completion_note: str
    due_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    evidence_count: int
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class W02EvidenceRead(BaseModel):
    id: int
    tracker_item_id: int
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


class W02TrackerBootstrapResponse(BaseModel):
    site: str
    created_count: int
    total_count: int
    items: list[W02TrackerItemRead]


class W02TrackerOverviewRead(BaseModel):
    site: str
    total_items: int
    pending_count: int
    in_progress_count: int
    done_count: int
    blocked_count: int
    completion_rate_percent: int
    evidence_total_count: int
    assignee_breakdown: dict[str, int]


class W02TrackerCompletionRequest(BaseModel):
    site: str = Field(min_length=1, max_length=120)
    completion_note: Optional[str] = Field(default=None, max_length=4000)
    force: bool = False


class W02TrackerReadinessRead(BaseModel):
    site: str
    checked_at: datetime
    total_items: int
    pending_count: int
    in_progress_count: int
    done_count: int
    blocked_count: int
    completion_rate_percent: int
    evidence_total_count: int
    missing_assignee_count: int
    missing_completion_checked_count: int
    missing_required_evidence_count: int
    readiness_score_percent: int
    ready: bool
    blockers: list[str]


class W02TrackerCompletionRead(BaseModel):
    site: str
    status: W02CompletionStatus
    completion_note: str
    completed_by: Optional[str] = None
    completed_at: Optional[datetime] = None
    force_used: bool = False
    last_checked_at: datetime
    readiness: W02TrackerReadinessRead


class W03TrackerBootstrapRequest(BaseModel):
    site: str = Field(min_length=1, max_length=120)


class W03TrackerItemUpdate(BaseModel):
    assignee: Optional[str] = Field(default=None, max_length=120)
    status: Optional[W03TrackerStatus] = None
    completion_checked: Optional[bool] = None
    completion_note: Optional[str] = Field(default=None, max_length=4000)


class W03TrackerItemRead(BaseModel):
    id: int
    site: str
    item_type: str
    item_key: str
    item_name: str
    assignee: Optional[str] = None
    status: W03TrackerStatus
    completion_checked: bool
    completion_note: str
    due_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    evidence_count: int
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class W03EvidenceRead(BaseModel):
    id: int
    tracker_item_id: int
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


class W03TrackerBootstrapResponse(BaseModel):
    site: str
    created_count: int
    total_count: int
    items: list[W03TrackerItemRead]


class W03TrackerOverviewRead(BaseModel):
    site: str
    total_items: int
    pending_count: int
    in_progress_count: int
    done_count: int
    blocked_count: int
    completion_rate_percent: int
    evidence_total_count: int
    assignee_breakdown: dict[str, int]


class W03TrackerCompletionRequest(BaseModel):
    site: str = Field(min_length=1, max_length=120)
    completion_note: Optional[str] = Field(default=None, max_length=4000)
    force: bool = False


class W03TrackerReadinessRead(BaseModel):
    site: str
    checked_at: datetime
    total_items: int
    pending_count: int
    in_progress_count: int
    done_count: int
    blocked_count: int
    completion_rate_percent: int
    evidence_total_count: int
    missing_assignee_count: int
    missing_completion_checked_count: int
    missing_required_evidence_count: int
    readiness_score_percent: int
    ready: bool
    blockers: list[str]


class W03TrackerCompletionRead(BaseModel):
    site: str
    status: W03CompletionStatus
    completion_note: str
    completed_by: Optional[str] = None
    completed_at: Optional[datetime] = None
    force_used: bool = False
    last_checked_at: datetime
    readiness: W03TrackerReadinessRead


class W04TrackerBootstrapRequest(BaseModel):
    site: str = Field(min_length=1, max_length=120)


class W04TrackerItemUpdate(BaseModel):
    assignee: Optional[str] = Field(default=None, max_length=120)
    status: Optional[W04TrackerStatus] = None
    completion_checked: Optional[bool] = None
    completion_note: Optional[str] = Field(default=None, max_length=4000)


class W04TrackerItemRead(BaseModel):
    id: int
    site: str
    item_type: str
    item_key: str
    item_name: str
    assignee: Optional[str] = None
    status: W04TrackerStatus
    completion_checked: bool
    completion_note: str
    due_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    evidence_count: int
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class W04EvidenceRead(BaseModel):
    id: int
    tracker_item_id: int
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


class W04TrackerBootstrapResponse(BaseModel):
    site: str
    created_count: int
    total_count: int
    items: list[W04TrackerItemRead]


class W04TrackerOverviewRead(BaseModel):
    site: str
    total_items: int
    pending_count: int
    in_progress_count: int
    done_count: int
    blocked_count: int
    completion_rate_percent: int
    evidence_total_count: int
    assignee_breakdown: dict[str, int]


class W04TrackerCompletionRequest(BaseModel):
    site: str = Field(min_length=1, max_length=120)
    completion_note: Optional[str] = Field(default=None, max_length=4000)
    force: bool = False


class W04TrackerReadinessRead(BaseModel):
    site: str
    checked_at: datetime
    total_items: int
    pending_count: int
    in_progress_count: int
    done_count: int
    blocked_count: int
    completion_rate_percent: int
    evidence_total_count: int
    missing_assignee_count: int
    missing_completion_checked_count: int
    missing_required_evidence_count: int
    readiness_score_percent: int
    ready: bool
    blockers: list[str]


class W04TrackerCompletionRead(BaseModel):
    site: str
    status: W04CompletionStatus
    completion_note: str
    completed_by: Optional[str] = None
    completed_at: Optional[datetime] = None
    force_used: bool = False
    last_checked_at: datetime
    readiness: W04TrackerReadinessRead


class W07TrackerBootstrapRequest(BaseModel):
    site: str = Field(min_length=1, max_length=120)


class W07TrackerItemUpdate(BaseModel):
    assignee: Optional[str] = Field(default=None, max_length=120)
    status: Optional[W07TrackerStatus] = None
    completion_checked: Optional[bool] = None
    completion_note: Optional[str] = Field(default=None, max_length=4000)


class W07TrackerItemRead(BaseModel):
    id: int
    site: str
    item_type: str
    item_key: str
    item_name: str
    assignee: Optional[str] = None
    status: W07TrackerStatus
    completion_checked: bool
    completion_note: str
    due_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    evidence_count: int
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class W07EvidenceRead(BaseModel):
    id: int
    tracker_item_id: int
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


class W07TrackerBootstrapResponse(BaseModel):
    site: str
    created_count: int
    total_count: int
    items: list[W07TrackerItemRead]


class W07TrackerOverviewRead(BaseModel):
    site: str
    total_items: int
    pending_count: int
    in_progress_count: int
    done_count: int
    blocked_count: int
    completion_rate_percent: int
    evidence_total_count: int
    assignee_breakdown: dict[str, int]


class W07TrackerCompletionRequest(BaseModel):
    site: str = Field(min_length=1, max_length=120)
    completion_note: Optional[str] = Field(default=None, max_length=4000)
    force: bool = False


class W07TrackerReadinessRead(BaseModel):
    site: str
    checked_at: datetime
    total_items: int
    pending_count: int
    in_progress_count: int
    done_count: int
    blocked_count: int
    completion_rate_percent: int
    evidence_total_count: int
    missing_assignee_count: int
    missing_completion_checked_count: int
    missing_required_evidence_count: int
    readiness_score_percent: int
    ready: bool
    blockers: list[str]


class W07TrackerCompletionRead(BaseModel):
    site: str
    status: W07CompletionStatus
    completion_note: str
    completed_by: Optional[str] = None
    completed_at: Optional[datetime] = None
    force_used: bool = False
    last_checked_at: datetime
    readiness: W07TrackerReadinessRead


class W09TrackerBootstrapRequest(BaseModel):
    site: str = Field(min_length=1, max_length=120)


class W09TrackerItemUpdate(BaseModel):
    assignee: Optional[str] = Field(default=None, max_length=120)
    status: Optional[W09TrackerStatus] = None
    completion_checked: Optional[bool] = None
    completion_note: Optional[str] = Field(default=None, max_length=4000)


class W09TrackerItemRead(BaseModel):
    id: int
    site: str
    item_type: str
    item_key: str
    item_name: str
    assignee: Optional[str] = None
    status: W09TrackerStatus
    completion_checked: bool
    completion_note: str
    due_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    evidence_count: int
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class W09EvidenceRead(BaseModel):
    id: int
    tracker_item_id: int
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


class W09TrackerBootstrapResponse(BaseModel):
    site: str
    created_count: int
    total_count: int
    items: list[W09TrackerItemRead]


class W09TrackerOverviewRead(BaseModel):
    site: str
    total_items: int
    pending_count: int
    in_progress_count: int
    done_count: int
    blocked_count: int
    completion_rate_percent: int
    evidence_total_count: int
    assignee_breakdown: dict[str, int]


class W09TrackerCompletionRequest(BaseModel):
    site: str = Field(min_length=1, max_length=120)
    completion_note: Optional[str] = Field(default=None, max_length=4000)
    force: bool = False


class W09TrackerReadinessRead(BaseModel):
    site: str
    checked_at: datetime
    total_items: int
    pending_count: int
    in_progress_count: int
    done_count: int
    blocked_count: int
    completion_rate_percent: int
    evidence_total_count: int
    missing_assignee_count: int
    missing_completion_checked_count: int
    missing_required_evidence_count: int
    readiness_score_percent: int
    ready: bool
    blockers: list[str]


class W09TrackerCompletionRead(BaseModel):
    site: str
    status: W09CompletionStatus
    completion_note: str
    completed_by: Optional[str] = None
    completed_at: Optional[datetime] = None
    force_used: bool = False
    last_checked_at: datetime
    readiness: W09TrackerReadinessRead


class W10TrackerBootstrapRequest(BaseModel):
    site: str = Field(min_length=1, max_length=120)


class W10TrackerItemUpdate(BaseModel):
    assignee: Optional[str] = Field(default=None, max_length=120)
    status: Optional[W10TrackerStatus] = None
    completion_checked: Optional[bool] = None
    completion_note: Optional[str] = Field(default=None, max_length=4000)


class W10TrackerItemRead(BaseModel):
    id: int
    site: str
    item_type: str
    item_key: str
    item_name: str
    assignee: Optional[str] = None
    status: W10TrackerStatus
    completion_checked: bool
    completion_note: str
    due_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    evidence_count: int
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class W10EvidenceRead(BaseModel):
    id: int
    tracker_item_id: int
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


class W10TrackerBootstrapResponse(BaseModel):
    site: str
    created_count: int
    total_count: int
    items: list[W10TrackerItemRead]


class W10TrackerOverviewRead(BaseModel):
    site: str
    total_items: int
    pending_count: int
    in_progress_count: int
    done_count: int
    blocked_count: int
    completion_rate_percent: int
    evidence_total_count: int
    assignee_breakdown: dict[str, int]


class W10TrackerCompletionRequest(BaseModel):
    site: str = Field(min_length=1, max_length=120)
    completion_note: Optional[str] = Field(default=None, max_length=4000)
    force: bool = False


class W10TrackerReadinessRead(BaseModel):
    site: str
    checked_at: datetime
    total_items: int
    pending_count: int
    in_progress_count: int
    done_count: int
    blocked_count: int
    completion_rate_percent: int
    evidence_total_count: int
    missing_assignee_count: int
    missing_completion_checked_count: int
    missing_required_evidence_count: int
    readiness_score_percent: int
    ready: bool
    blockers: list[str]


class W10TrackerCompletionRead(BaseModel):
    site: str
    status: W10CompletionStatus
    completion_note: str
    completed_by: Optional[str] = None
    completed_at: Optional[datetime] = None
    force_used: bool = False
    last_checked_at: datetime
    readiness: W10TrackerReadinessRead


class W11TrackerBootstrapRequest(BaseModel):
    site: str = Field(min_length=1, max_length=120)


class W11TrackerItemUpdate(BaseModel):
    assignee: Optional[str] = Field(default=None, max_length=120)
    status: Optional[W11TrackerStatus] = None
    completion_checked: Optional[bool] = None
    completion_note: Optional[str] = Field(default=None, max_length=4000)


class W11TrackerItemRead(BaseModel):
    id: int
    site: str
    item_type: str
    item_key: str
    item_name: str
    assignee: Optional[str] = None
    status: W11TrackerStatus
    completion_checked: bool
    completion_note: str
    due_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    evidence_count: int
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class W11EvidenceRead(BaseModel):
    id: int
    tracker_item_id: int
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


class W11TrackerBootstrapResponse(BaseModel):
    site: str
    created_count: int
    total_count: int
    items: list[W11TrackerItemRead]


class W11TrackerOverviewRead(BaseModel):
    site: str
    total_items: int
    pending_count: int
    in_progress_count: int
    done_count: int
    blocked_count: int
    completion_rate_percent: int
    evidence_total_count: int
    assignee_breakdown: dict[str, int]


class W11TrackerCompletionRequest(BaseModel):
    site: str = Field(min_length=1, max_length=120)
    completion_note: Optional[str] = Field(default=None, max_length=4000)
    force: bool = False


class W11TrackerReadinessRead(BaseModel):
    site: str
    checked_at: datetime
    total_items: int
    pending_count: int
    in_progress_count: int
    done_count: int
    blocked_count: int
    completion_rate_percent: int
    evidence_total_count: int
    missing_assignee_count: int
    missing_completion_checked_count: int
    missing_required_evidence_count: int
    readiness_score_percent: int
    ready: bool
    blockers: list[str]


class W11TrackerCompletionRead(BaseModel):
    site: str
    status: W11CompletionStatus
    completion_note: str
    completed_by: Optional[str] = None
    completed_at: Optional[datetime] = None
    force_used: bool = False
    last_checked_at: datetime
    readiness: W11TrackerReadinessRead


class W12TrackerBootstrapRequest(BaseModel):
    site: str = Field(min_length=1, max_length=120)


class W12TrackerItemUpdate(BaseModel):
    assignee: Optional[str] = Field(default=None, max_length=120)
    status: Optional[W12TrackerStatus] = None
    completion_checked: Optional[bool] = None
    completion_note: Optional[str] = Field(default=None, max_length=4000)


class W12TrackerItemRead(BaseModel):
    id: int
    site: str
    item_type: str
    item_key: str
    item_name: str
    assignee: Optional[str] = None
    status: W12TrackerStatus
    completion_checked: bool
    completion_note: str
    due_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    evidence_count: int
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class W12EvidenceRead(BaseModel):
    id: int
    tracker_item_id: int
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


class W12TrackerBootstrapResponse(BaseModel):
    site: str
    created_count: int
    total_count: int
    items: list[W12TrackerItemRead]


class W12TrackerOverviewRead(BaseModel):
    site: str
    total_items: int
    pending_count: int
    in_progress_count: int
    done_count: int
    blocked_count: int
    completion_rate_percent: int
    evidence_total_count: int
    assignee_breakdown: dict[str, int]


class W12TrackerCompletionRequest(BaseModel):
    site: str = Field(min_length=1, max_length=120)
    completion_note: Optional[str] = Field(default=None, max_length=4000)
    force: bool = False


class W12TrackerReadinessRead(BaseModel):
    site: str
    checked_at: datetime
    total_items: int
    pending_count: int
    in_progress_count: int
    done_count: int
    blocked_count: int
    completion_rate_percent: int
    evidence_total_count: int
    missing_assignee_count: int
    missing_completion_checked_count: int
    missing_required_evidence_count: int
    readiness_score_percent: int
    ready: bool
    blockers: list[str]


class W12TrackerCompletionRead(BaseModel):
    site: str
    status: W12CompletionStatus
    completion_note: str
    completed_by: Optional[str] = None
    completed_at: Optional[datetime] = None
    force_used: bool = False
    last_checked_at: datetime
    readiness: W12TrackerReadinessRead


class SlaEscalationRunRequest(BaseModel):
    site: Optional[str] = Field(default=None, max_length=120)
    dry_run: bool = False
    limit: int = Field(default=200, ge=1, le=2000)


class SlaAlertChannelResult(BaseModel):
    target: str
    success: bool
    error: Optional[str] = None


class SlaEscalationRunResponse(BaseModel):
    checked_at: datetime
    dry_run: bool
    site: Optional[str] = None
    candidate_count: int
    escalated_count: int
    work_order_ids: list[int]
    alert_dispatched: bool = False
    alert_error: Optional[str] = None
    alert_channels: list[SlaAlertChannelResult] = Field(default_factory=list)


class SlaPolicyUpdate(BaseModel):
    default_due_hours: dict[WorkOrderPriority, int] = Field(
        default_factory=lambda: {"low": 72, "medium": 24, "high": 8, "critical": 2}
    )
    escalation_grace_minutes: int = Field(default=0, ge=0, le=1440)


class SlaPolicyRead(BaseModel):
    policy_key: str
    site: Optional[str] = None
    source: str = "default"
    default_due_hours: dict[WorkOrderPriority, int]
    escalation_grace_minutes: int
    updated_at: datetime


class SlaWhatIfRequest(BaseModel):
    site: Optional[str] = Field(default=None, max_length=120)
    policy: SlaPolicyUpdate
    limit: int = Field(default=3000, ge=1, le=20000)
    include_work_order_ids: bool = True
    sample_size: int = Field(default=200, ge=0, le=1000)
    recompute_due_from_policy: bool = False


class SlaWhatIfResponse(BaseModel):
    checked_at: datetime
    site: Optional[str] = None
    limit: int
    total_candidates: int
    baseline_escalate_count: int
    simulated_escalate_count: int
    delta_escalate_count: int
    baseline_by_site: dict[str, int]
    simulated_by_site: dict[str, int]
    newly_escalated_ids: list[int]
    no_longer_escalated_ids: list[int]
    notes: list[str]


SlaPolicyProposalStatus = Literal["pending", "approved", "rejected"]


class SlaPolicyProposalCreate(BaseModel):
    site: Optional[str] = Field(default=None, max_length=120)
    policy: SlaPolicyUpdate
    note: str = ""
    simulation_limit: int = Field(default=3000, ge=1, le=20000)
    include_work_order_ids: bool = True
    sample_size: int = Field(default=200, ge=0, le=1000)
    recompute_due_from_policy: bool = False


class SlaPolicyProposalDecision(BaseModel):
    note: str = ""


class SlaPolicyProposalRead(BaseModel):
    id: int
    site: Optional[str] = None
    status: SlaPolicyProposalStatus
    policy: dict[str, Any]
    simulation: dict[str, Any]
    note: str
    requested_by: str
    decided_by: Optional[str] = None
    decision_note: Optional[str] = None
    created_at: datetime
    decided_at: Optional[datetime] = None
    applied_at: Optional[datetime] = None


class SlaPolicyRevisionRead(BaseModel):
    id: int
    site: Optional[str] = None
    policy: dict[str, Any]
    source_action: str
    actor_username: str
    note: str
    created_at: datetime


class SlaPolicyRestoreRequest(BaseModel):
    note: str = ""


class MonthlyReportRead(BaseModel):
    month: str
    site: Optional[str] = None
    generated_at: datetime
    inspections: dict[str, Any]
    work_orders: dict[str, Any]


class AuthMeRead(BaseModel):
    user_id: Optional[int] = None
    token_id: Optional[int] = None
    token_label: Optional[str] = None
    token_expires_at: Optional[datetime] = None
    token_rotate_due_at: Optional[datetime] = None
    token_idle_due_at: Optional[datetime] = None
    token_must_rotate: bool = False
    username: str
    display_name: str
    role: str
    permissions: list[str]
    site_scope: list[str]
    is_legacy: bool = False


class AdminUserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    display_name: str = Field(default="", max_length=120)
    role: AdminRole = "operator"
    permissions: list[str] = Field(default_factory=list)
    site_scope: list[str] = Field(default_factory=lambda: ["*"])
    is_active: bool = True


class AdminUserRead(BaseModel):
    id: int
    username: str
    display_name: str
    role: AdminRole
    permissions: list[str]
    site_scope: list[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime


class AdminUserActiveUpdate(BaseModel):
    is_active: bool


class AdminTokenIssueRequest(BaseModel):
    label: str = Field(default="default", min_length=1, max_length=120)
    expires_at: Optional[datetime] = None
    site_scope: Optional[list[str]] = None


class AdminTokenIssueResponse(BaseModel):
    token_id: int
    user_id: int
    label: str
    token: str
    site_scope: list[str]
    expires_at: Optional[datetime] = None
    created_at: datetime


class AdminTokenRead(BaseModel):
    token_id: int
    user_id: int
    username: str
    label: str
    is_active: bool
    site_scope: list[str]
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    created_at: datetime
    rotate_due_at: Optional[datetime] = None
    idle_due_at: Optional[datetime] = None
    must_rotate: bool = False


class AdminAuditLogRead(BaseModel):
    id: int
    actor_user_id: Optional[int] = None
    actor_username: str
    action: str
    resource_type: str
    resource_id: str
    status: str
    detail: dict[str, Any]
    created_at: datetime


class JobRunRead(BaseModel):
    id: int
    job_name: str
    trigger: str
    status: str
    started_at: datetime
    finished_at: datetime
    detail: dict[str, Any]


class DashboardSummaryRead(BaseModel):
    generated_at: datetime
    site: Optional[str] = None
    window_days: int
    inspections_total: int
    inspection_risk_counts: dict[str, int]
    work_orders_total: int
    work_order_status_counts: dict[str, int]
    overdue_open_count: int
    escalated_open_count: int
    report_export_count: int
    sla_recent_runs: int
    sla_warning_runs: int
    sla_last_run_at: Optional[datetime] = None
    recent_job_runs: list[JobRunRead]


class OpsHandoverWorkOrderRead(BaseModel):
    id: int
    site: str
    location: str
    title: str
    priority: WorkOrderPriority
    status: WorkOrderStatus
    assignee: Optional[str] = None
    due_at: Optional[datetime] = None
    created_at: datetime
    is_escalated: bool
    is_overdue: bool
    due_in_minutes: Optional[int] = None
    urgency_score: int
    reasons: list[str]


class OpsHandoverInspectionRead(BaseModel):
    id: int
    site: str
    location: str
    inspector: str
    risk_level: str
    inspected_at: datetime
    risk_flags: list[str]


class OpsHandoverBriefRead(BaseModel):
    generated_at: datetime
    site: Optional[str] = None
    window_hours: int
    due_soon_hours: int
    open_work_orders: int
    overdue_open_work_orders: int
    due_soon_work_orders: int
    escalated_open_work_orders: int
    unassigned_high_priority_open_work_orders: int
    new_work_orders_in_window: int
    high_risk_inspections_in_window: int
    failed_alert_deliveries_24h: int
    top_work_orders: list[OpsHandoverWorkOrderRead]
    recent_high_risk_inspections: list[OpsHandoverInspectionRead]
    recommended_actions: list[str]


class AlertDeliveryRead(BaseModel):
    id: int
    event_type: str
    target: str
    status: str
    error: Optional[str] = None
    payload: dict[str, Any]
    attempt_count: int
    last_attempt_at: datetime
    created_at: datetime
    updated_at: datetime


class AlertRetryRunRequest(BaseModel):
    event_type: Optional[str] = Field(default=None, max_length=80)
    only_status: list[str] = Field(default_factory=lambda: ["failed", "warning"])
    limit: int = Field(default=200, ge=1, le=5000)
    max_attempt_count: int = Field(default=10, ge=1, le=1000)
    min_last_attempt_age_sec: int = Field(default=30, ge=0, le=86400)


class AlertRetryRunResponse(BaseModel):
    checked_at: datetime
    event_type: Optional[str] = None
    limit: int
    processed_count: int
    success_count: int
    warning_count: int
    failed_count: int
    delivery_ids: list[int]


class DashboardTrendPoint(BaseModel):
    date: str
    inspections_count: int
    work_orders_created_count: int
    work_orders_completed_count: int
    work_orders_escalated_count: int


class DashboardTrendsRead(BaseModel):
    generated_at: datetime
    site: Optional[str] = None
    window_days: int
    points: list[DashboardTrendPoint]
