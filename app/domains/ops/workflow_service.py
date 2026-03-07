"""Work-order and workflow-lock helpers extracted from app.main."""

from __future__ import annotations

from app import main as main_module

globals().update(
    {
        key: value
        for key, value in main_module.__dict__.items()
        if key not in {"bind", "main_module", "_LOCAL_SYMBOLS"}
    }
)

_LOCAL_SYMBOLS = {
    "bind",
    "main_module",
    "_LOCAL_SYMBOLS",
    "_row_to_work_order_model",
    "_validate_work_order_transition",
    "_append_work_order_event",
    "_row_to_work_order_event_model",
    "_row_to_workflow_lock_model",
}


def bind(namespace: dict[str, object]) -> None:
    for key, value in namespace.items():
        if key not in _LOCAL_SYMBOLS:
            globals()[key] = value


def _row_to_work_order_model(row: dict[str, Any]) -> WorkOrderRead:
    due_at = _as_optional_datetime(row["due_at"])
    status = row["status"]
    return WorkOrderRead(
        id=row["id"],
        title=row["title"],
        description=row["description"] or "",
        site=row["site"],
        location=row["location"],
        priority=row["priority"],
        status=status,
        assignee=row["assignee"],
        reporter=row["reporter"],
        inspection_id=row["inspection_id"],
        due_at=due_at,
        acknowledged_at=_as_optional_datetime(row["acknowledged_at"]),
        completed_at=_as_optional_datetime(row["completed_at"]),
        resolution_notes=row["resolution_notes"] or "",
        is_escalated=bool(row["is_escalated"]),
        is_overdue=_is_overdue(status, due_at),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _validate_work_order_transition(current_status: str, next_status: str) -> None:
    allowed = WORK_ORDER_TRANSITIONS.get(current_status, set())
    if next_status not in allowed:
        raise HTTPException(status_code=409, detail=f"Invalid status transition: {current_status} -> {next_status}")


def _append_work_order_event(
    conn: Any,
    *,
    work_order_id: int,
    event_type: str,
    actor_username: str,
    from_status: str | None = None,
    to_status: str | None = None,
    note: str = "",
    detail: dict[str, Any] | None = None,
) -> None:
    conn.execute(
        insert(work_order_events).values(
            work_order_id=work_order_id,
            event_type=event_type,
            actor_username=actor_username,
            from_status=from_status,
            to_status=to_status,
            note=note,
            detail_json=_to_json_text(detail),
            created_at=datetime.now(timezone.utc),
        )
    )


def _row_to_work_order_event_model(row: dict[str, Any]) -> WorkOrderEventRead:
    raw = str(row["detail_json"] or "{}")
    try:
        detail = json.loads(raw)
    except json.JSONDecodeError:
        detail = {"raw": raw}
    if not isinstance(detail, dict):
        detail = {"value": detail}

    return WorkOrderEventRead(
        id=int(row["id"]),
        work_order_id=int(row["work_order_id"]),
        event_type=str(row["event_type"]),
        actor_username=str(row["actor_username"]),
        from_status=row["from_status"],
        to_status=row["to_status"],
        note=str(row["note"] or ""),
        detail=detail,
        created_at=_as_datetime(row["created_at"]),
    )


def _row_to_workflow_lock_model(row: dict[str, Any]) -> WorkflowLockRead:
    raw = str(row["content_json"] or "{}")
    try:
        content = json.loads(raw)
    except json.JSONDecodeError:
        content = {"raw": raw}
    if not isinstance(content, dict):
        content = {"value": content}

    return WorkflowLockRead(
        id=int(row["id"]),
        site=str(row["site"]),
        workflow_key=str(row["workflow_key"]),
        status=str(row["status"]),
        content=content,
        requested_ticket=row.get("requested_ticket"),
        last_comment=str(row.get("last_comment") or ""),
        lock_reason=row.get("lock_reason"),
        unlock_reason=row.get("unlock_reason"),
        created_by=str(row.get("created_by") or "system"),
        updated_by=str(row.get("updated_by") or "system"),
        reviewed_by=row.get("reviewed_by"),
        approved_by=row.get("approved_by"),
        locked_by=row.get("locked_by"),
        unlocked_by=row.get("unlocked_by"),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
        reviewed_at=_as_optional_datetime(row.get("reviewed_at")),
        approved_at=_as_optional_datetime(row.get("approved_at")),
        locked_at=_as_optional_datetime(row.get("locked_at")),
        unlocked_at=_as_optional_datetime(row.get("unlocked_at")),
    )
