"""Remediation and autopilot helpers extracted from app.main."""

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
    'bind',
    'main_module',
    '_LOCAL_SYMBOLS',
    '_normalize_w21_tracker_status',
    '_resolve_w21_completion_status',
    '_row_to_w21_remediation_item_model',
    '_load_w21_remediation_items',
    '_compute_w21_remediation_overview',
    '_compute_w21_remediation_readiness',
    '_row_to_w21_completion_model',
    '_reset_w21_completion_if_closed',
    '_sync_w21_remediation_tracker',
    '_build_w22_remediation_sla_snapshot',
    'run_ops_governance_remediation_escalation_job',
    '_latest_ops_governance_remediation_escalation_payload',
    '_w23_candidate_usernames_by_role',
    '_w23_choose_assignee',
    '_build_w23_remediation_workload_snapshot',
    'run_ops_governance_remediation_auto_assign_job',
    '_latest_ops_governance_remediation_auto_assign_payload',
    '_build_w24_remediation_backlog_history',
    '_build_w24_remediation_kpi_snapshot',
    'run_ops_governance_remediation_kpi_job',
    '_latest_ops_governance_remediation_kpi_payload',
    '_default_w26_remediation_autopilot_policy',
    '_build_policy_response_payload',
    '_normalize_w26_remediation_autopilot_policy',
    '_parse_w26_remediation_autopilot_policy_json',
    '_ensure_w26_remediation_autopilot_policy',
    '_upsert_w26_remediation_autopilot_policy',
    '_evaluate_w26_remediation_autopilot',
    '_latest_job_run_for_name',
    '_build_w27_remediation_autopilot_guard_state',
    'run_ops_governance_remediation_autopilot_job',
    '_latest_ops_governance_remediation_autopilot_payload',
    '_build_w28_remediation_autopilot_history',
    '_build_w28_remediation_autopilot_summary',
    '_build_w29_remediation_autopilot_history_csv',
    '_build_w29_remediation_autopilot_summary_csv',
    '_build_w30_remediation_autopilot_anomalies',
    '_build_w30_remediation_autopilot_anomalies_csv',
}


def bind(namespace: dict[str, object]) -> None:
    for key, value in namespace.items():
        if key not in _LOCAL_SYMBOLS:
            globals()[key] = value


def _normalize_w21_tracker_status(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    if value in W21_TRACKER_STATUS_SET:
        return value
    return W21_TRACKER_STATUS_PENDING


def _resolve_w21_completion_status(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    if value in W21_COMPLETION_STATUS_SET:
        return value
    return W21_COMPLETION_STATUS_ACTIVE


def _row_to_w21_remediation_item_model(row: dict[str, Any]) -> W21RemediationTrackerItemRead:
    raw_detail = str(row.get("detail_json") or "{}")
    try:
        detail = json.loads(raw_detail)
    except json.JSONDecodeError:
        detail = {}
    if not isinstance(detail, dict):
        detail = {}
    due_at = _as_optional_datetime(row.get("due_at")) or datetime.now(timezone.utc)
    gate_generated_at = _as_optional_datetime(row.get("gate_generated_at")) or due_at
    return W21RemediationTrackerItemRead(
        id=int(row["id"]),
        item_id=str(row.get("item_id") or ""),
        rule_id=str(row.get("rule_id") or ""),
        rule_status=str(row.get("rule_status") or "warning"),
        required=bool(row.get("required", False)),
        priority=int(row.get("priority") or 9),
        owner_role=str(row.get("owner_role") or ""),
        sla_hours=max(1, int(row.get("sla_hours") or 24)),
        due_at=due_at,
        action=str(row.get("action") or ""),
        reason=str(row.get("reason") or ""),
        detail=detail,
        assignee=row.get("assignee"),
        status=_normalize_w21_tracker_status(row.get("status")),
        completion_checked=bool(row.get("completion_checked", False)),
        completion_note=str(row.get("completion_note") or ""),
        completed_at=_as_optional_datetime(row.get("completed_at")),
        is_active=bool(row.get("is_active", True)),
        gate_generated_at=gate_generated_at,
        created_by=str(row.get("created_by") or "system"),
        updated_by=str(row.get("updated_by") or "system"),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _load_w21_remediation_items(*, include_inactive: bool = False) -> list[W21RemediationTrackerItemRead]:
    stmt = select(ops_governance_remediation_tracker_items)
    if not include_inactive:
        stmt = stmt.where(ops_governance_remediation_tracker_items.c.is_active.is_(True))
    stmt = stmt.order_by(
        ops_governance_remediation_tracker_items.c.is_active.desc(),
        ops_governance_remediation_tracker_items.c.priority.asc(),
        ops_governance_remediation_tracker_items.c.due_at.asc(),
        ops_governance_remediation_tracker_items.c.id.asc(),
    )
    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_w21_remediation_item_model(row) for row in rows]


def _compute_w21_remediation_overview(
    *,
    active_rows: list[W21RemediationTrackerItemRead],
    active_count: int,
    closed_count: int,
    checked_at: datetime | None = None,
) -> W21RemediationTrackerOverviewRead:
    now = checked_at or datetime.now(timezone.utc)
    pending_count = sum(1 for row in active_rows if row.status == W21_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in active_rows if row.status == W21_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in active_rows if row.status == W21_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in active_rows if row.status == W21_TRACKER_STATUS_BLOCKED)
    total_items = len(active_rows)
    completion_rate_percent = int(round((done_count / total_items) * 100)) if total_items > 0 else 100
    missing_assignee_count = sum(1 for row in active_rows if not (row.assignee or "").strip())
    critical_open_count = sum(
        1
        for row in active_rows
        if row.rule_status == "fail" and bool(row.required) and row.status != W21_TRACKER_STATUS_DONE
    )
    overdue_count = sum(1 for row in active_rows if row.status != W21_TRACKER_STATUS_DONE and row.due_at < now)
    return W21RemediationTrackerOverviewRead(
        generated_at=now,
        total_items=total_items,
        active_count=active_count,
        closed_count=closed_count,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate_percent,
        missing_assignee_count=missing_assignee_count,
        critical_open_count=critical_open_count,
        overdue_count=overdue_count,
    )


def _compute_w21_remediation_readiness(
    *,
    active_rows: list[W21RemediationTrackerItemRead],
    checked_at: datetime | None = None,
) -> W21RemediationTrackerReadinessRead:
    now = checked_at or datetime.now(timezone.utc)
    pending_count = sum(1 for row in active_rows if row.status == W21_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in active_rows if row.status == W21_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in active_rows if row.status == W21_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in active_rows if row.status == W21_TRACKER_STATUS_BLOCKED)
    total_items = len(active_rows)
    completion_rate_percent = int(round((done_count / total_items) * 100)) if total_items > 0 else 100
    missing_assignee_count = sum(1 for row in active_rows if not (row.assignee or "").strip())
    missing_completion_checked_count = sum(1 for row in active_rows if not bool(row.completion_checked))
    critical_open_count = sum(
        1
        for row in active_rows
        if row.rule_status == "fail" and bool(row.required) and row.status != W21_TRACKER_STATUS_DONE
    )
    overdue_count = sum(1 for row in active_rows if row.status != W21_TRACKER_STATUS_DONE and row.due_at < now)

    blockers: list[str] = []
    if pending_count > 0:
        blockers.append(f"pending 항목 {pending_count}건이 남아 있습니다.")
    if in_progress_count > 0:
        blockers.append(f"in_progress 항목 {in_progress_count}건이 남아 있습니다.")
    if blocked_count > 0:
        blockers.append(f"blocked 항목 {blocked_count}건을 해소해야 합니다.")
    if missing_assignee_count > 0:
        blockers.append(f"담당자 미지정 항목 {missing_assignee_count}건이 있습니다.")
    if missing_completion_checked_count > 0:
        blockers.append(f"완료 체크 미확정 항목 {missing_completion_checked_count}건이 있습니다.")
    if critical_open_count > 0:
        blockers.append(f"필수 fail 리메디에이션 미완료 항목 {critical_open_count}건이 있습니다.")
    if overdue_count > 0:
        blockers.append(f"SLA 기한 초과 리메디에이션 항목 {overdue_count}건이 있습니다.")

    if total_items == 0:
        readiness_score_percent = 100
        ready = True
    else:
        checks = [
            pending_count == 0,
            in_progress_count == 0,
            blocked_count == 0,
            missing_assignee_count == 0,
            missing_completion_checked_count == 0,
            critical_open_count == 0,
            overdue_count == 0,
        ]
        readiness_score_percent = int(round((sum(1 for ok in checks if ok) / len(checks)) * 100))
        readiness_score_percent = max(readiness_score_percent, completion_rate_percent)
        ready = len(blockers) == 0
        if ready:
            readiness_score_percent = 100

    return W21RemediationTrackerReadinessRead(
        generated_at=now,
        total_items=total_items,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate_percent,
        missing_assignee_count=missing_assignee_count,
        missing_completion_checked_count=missing_completion_checked_count,
        critical_open_count=critical_open_count,
        overdue_count=overdue_count,
        readiness_score_percent=readiness_score_percent,
        ready=ready,
        blockers=blockers,
    )


def _row_to_w21_completion_model(
    *,
    readiness: W21RemediationTrackerReadinessRead,
    row: dict[str, Any] | None,
) -> W21RemediationTrackerCompletionRead:
    if row is None:
        return W21RemediationTrackerCompletionRead(
            status=W21_COMPLETION_STATUS_ACTIVE,
            completion_note="",
            completed_by=None,
            completed_at=None,
            force_used=False,
            last_checked_at=readiness.generated_at,
            readiness=readiness,
        )
    return W21RemediationTrackerCompletionRead(
        status=_resolve_w21_completion_status(row.get("status")),
        completion_note=str(row.get("completion_note") or ""),
        completed_by=row.get("completed_by"),
        completed_at=_as_optional_datetime(row.get("completed_at")),
        force_used=bool(row.get("force_used", False)),
        last_checked_at=_as_optional_datetime(row.get("last_checked_at")) or readiness.generated_at,
        readiness=readiness,
    )


def _reset_w21_completion_if_closed(
    *,
    conn: Any,
    actor_username: str,
    checked_at: datetime,
    reason: str,
) -> None:
    row = conn.execute(
        select(ops_governance_remediation_tracker_runs)
        .where(ops_governance_remediation_tracker_runs.c.scope == W21_TRACKER_SCOPE_GLOBAL)
        .limit(1)
    ).mappings().first()
    if row is None:
        return
    status = _resolve_w21_completion_status(row.get("status"))
    if status == W21_COMPLETION_STATUS_ACTIVE:
        return
    conn.execute(
        update(ops_governance_remediation_tracker_runs)
        .where(ops_governance_remediation_tracker_runs.c.scope == W21_TRACKER_SCOPE_GLOBAL)
        .values(
            status=W21_COMPLETION_STATUS_ACTIVE,
            completion_note="",
            force_used=False,
            completed_by=None,
            completed_at=None,
            last_checked_at=checked_at,
            readiness_json=_to_json_text(
                {
                    "auto_reopened": True,
                    "reason": reason,
                    "checked_at": checked_at.isoformat(),
                }
            ),
            updated_by=actor_username,
            updated_at=checked_at,
        )
    )


def _sync_w21_remediation_tracker(
    *,
    actor_username: str,
    include_warnings: bool,
    max_items: int,
) -> W21RemediationTrackerSyncResponse:
    snapshot = _build_ops_governance_gate_snapshot()
    plan = _build_ops_governance_remediation_plan(
        snapshot=snapshot,
        include_warnings=include_warnings,
        max_items=max_items,
    )
    plan_items = [item for item in plan.get("items", []) if isinstance(item, dict)]
    decision = str(plan.get("decision") or "no_go")
    gate_generated_at = _as_optional_datetime(plan.get("gate_generated_at")) or datetime.now(timezone.utc)
    now = datetime.now(timezone.utc)

    created_count = 0
    reopened_count = 0
    resolved_count = 0

    with get_conn() as conn:
        existing_rows = conn.execute(select(ops_governance_remediation_tracker_items)).mappings().all()
        existing_by_rule = {
            str(row.get("rule_id") or "").strip(): row
            for row in existing_rows
            if str(row.get("rule_id") or "").strip()
        }
        seen_rule_ids: set[str] = set()

        for item in plan_items:
            rule_id = str(item.get("rule_id") or "").strip()
            if not rule_id:
                continue
            seen_rule_ids.add(rule_id)
            due_at = _as_optional_datetime(item.get("due_at")) or now
            current = existing_by_rule.get(rule_id)
            if current is None:
                conn.execute(
                    insert(ops_governance_remediation_tracker_items).values(
                        item_id=str(item.get("item_id") or ""),
                        rule_id=rule_id,
                        rule_status=str(item.get("rule_status") or "warning"),
                        required=bool(item.get("required", False)),
                        priority=max(1, int(item.get("priority") or 9)),
                        owner_role=str(item.get("owner_role") or "Ops Manager"),
                        sla_hours=max(1, int(item.get("sla_hours") or 24)),
                        due_at=due_at,
                        action=str(item.get("action") or ""),
                        reason=str(item.get("reason") or ""),
                        detail_json=_to_json_text(item.get("detail") if isinstance(item.get("detail"), dict) else {}),
                        gate_generated_at=gate_generated_at,
                        source_decision=decision,
                        assignee=None,
                        status=W21_TRACKER_STATUS_PENDING,
                        completion_checked=False,
                        completion_note="",
                        completed_at=None,
                        is_active=True,
                        created_by=actor_username,
                        updated_by=actor_username,
                        created_at=now,
                        updated_at=now,
                    )
                )
                created_count += 1
                continue

            next_status = _normalize_w21_tracker_status(current.get("status"))
            next_checked = bool(current.get("completion_checked", False))
            next_note = str(current.get("completion_note") or "")
            next_completed_at = _as_optional_datetime(current.get("completed_at"))
            was_inactive = not bool(current.get("is_active", True))
            if was_inactive and next_status == W21_TRACKER_STATUS_DONE:
                next_status = W21_TRACKER_STATUS_PENDING
                next_checked = False
                next_completed_at = None
                reopen_note = f"[auto-reopened {now.isoformat()}] governance gate rule is active again."
                next_note = f"{next_note}\n{reopen_note}".strip() if next_note else reopen_note
                reopened_count += 1

            conn.execute(
                update(ops_governance_remediation_tracker_items)
                .where(ops_governance_remediation_tracker_items.c.id == int(current["id"]))
                .values(
                    item_id=str(item.get("item_id") or ""),
                    rule_status=str(item.get("rule_status") or "warning"),
                    required=bool(item.get("required", False)),
                    priority=max(1, int(item.get("priority") or 9)),
                    owner_role=str(item.get("owner_role") or "Ops Manager"),
                    sla_hours=max(1, int(item.get("sla_hours") or 24)),
                    due_at=due_at,
                    action=str(item.get("action") or ""),
                    reason=str(item.get("reason") or ""),
                    detail_json=_to_json_text(item.get("detail") if isinstance(item.get("detail"), dict) else {}),
                    gate_generated_at=gate_generated_at,
                    source_decision=decision,
                    status=next_status,
                    completion_checked=next_checked,
                    completion_note=next_note,
                    completed_at=next_completed_at,
                    is_active=True,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )

        for row in existing_rows:
            rule_id = str(row.get("rule_id") or "").strip()
            if not rule_id or rule_id in seen_rule_ids:
                continue
            if not bool(row.get("is_active", True)):
                continue
            next_status = _normalize_w21_tracker_status(row.get("status"))
            next_checked = bool(row.get("completion_checked", False))
            next_note = str(row.get("completion_note") or "")
            next_completed_at = _as_optional_datetime(row.get("completed_at"))
            if next_status != W21_TRACKER_STATUS_DONE:
                next_status = W21_TRACKER_STATUS_DONE
                next_checked = True
                next_completed_at = now
                close_note = (
                    f"[auto-resolved {now.isoformat()}] current governance gate snapshot no longer requires this rule."
                )
                next_note = f"{next_note}\n{close_note}".strip() if next_note else close_note
            conn.execute(
                update(ops_governance_remediation_tracker_items)
                .where(ops_governance_remediation_tracker_items.c.id == int(row["id"]))
                .values(
                    is_active=False,
                    status=next_status,
                    completion_checked=next_checked,
                    completion_note=next_note,
                    completed_at=next_completed_at,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
            resolved_count += 1

        if created_count > 0 or reopened_count > 0 or resolved_count > 0:
            _reset_w21_completion_if_closed(
                conn=conn,
                actor_username=actor_username,
                checked_at=now,
                reason="tracker synchronized with latest governance remediation plan",
            )

        active_rows = conn.execute(
            select(ops_governance_remediation_tracker_items)
            .where(ops_governance_remediation_tracker_items.c.is_active.is_(True))
            .order_by(
                ops_governance_remediation_tracker_items.c.priority.asc(),
                ops_governance_remediation_tracker_items.c.due_at.asc(),
                ops_governance_remediation_tracker_items.c.id.asc(),
            )
        ).mappings().all()

    active_models = [_row_to_w21_remediation_item_model(row) for row in active_rows]
    return W21RemediationTrackerSyncResponse(
        generated_at=now,
        gate_generated_at=gate_generated_at,
        decision=decision,
        include_warnings=include_warnings,
        max_items=max(1, min(int(max_items), 200)),
        synced_count=len(active_models),
        created_count=created_count,
        reopened_count=reopened_count,
        resolved_count=resolved_count,
        active_count=len(active_models),
        items=active_models,
    )


def _build_w22_remediation_sla_snapshot(
    *,
    due_soon_hours: int = 24,
    now: datetime | None = None,
) -> dict[str, Any]:
    checked_at = now or datetime.now(timezone.utc)
    normalized_due_soon_hours = max(0, min(int(due_soon_hours), 168))
    due_soon_cutoff = checked_at + timedelta(hours=normalized_due_soon_hours)
    rows = _load_w21_remediation_items(include_inactive=False)

    pending_count = sum(1 for row in rows if row.status == W21_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W21_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W21_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W21_TRACKER_STATUS_BLOCKED)
    open_rows = [row for row in rows if row.status != W21_TRACKER_STATUS_DONE]

    overdue_rows = [row for row in open_rows if row.due_at < checked_at]
    if normalized_due_soon_hours > 0:
        due_soon_rows = [row for row in open_rows if checked_at <= row.due_at <= due_soon_cutoff]
    else:
        due_soon_rows = []
    critical_open_rows = [row for row in open_rows if row.rule_status == "fail" and bool(row.required)]
    unassigned_open_rows = [row for row in open_rows if not (row.assignee or "").strip()]

    assignee_open_counts: dict[str, int] = {}
    for row in open_rows:
        assignee = (row.assignee or "unassigned").strip() or "unassigned"
        assignee_open_counts[assignee] = assignee_open_counts.get(assignee, 0) + 1

    top_risk_rows = sorted(
        open_rows,
        key=lambda row: (int(row.priority), row.due_at, int(row.id)),
    )[:10]
    top_risk_items = [
        {
            "id": int(row.id),
            "item_id": row.item_id,
            "rule_id": row.rule_id,
            "rule_status": row.rule_status,
            "required": bool(row.required),
            "priority": int(row.priority),
            "assignee": row.assignee,
            "status": row.status,
            "due_at": row.due_at.isoformat(),
            "minutes_until_due": int(round((row.due_at - checked_at).total_seconds() / 60.0)),
        }
        for row in top_risk_rows
    ]

    completion_rate_percent = int(round((done_count / len(rows)) * 100)) if rows else 100
    return {
        "generated_at": checked_at.isoformat(),
        "due_soon_hours": normalized_due_soon_hours,
        "metrics": {
            "total_items": len(rows),
            "open_items": len(open_rows),
            "pending_count": pending_count,
            "in_progress_count": in_progress_count,
            "done_count": done_count,
            "blocked_count": blocked_count,
            "completion_rate_percent": completion_rate_percent,
            "overdue_count": len(overdue_rows),
            "due_soon_count": len(due_soon_rows),
            "critical_open_count": len(critical_open_rows),
            "unassigned_open_count": len(unassigned_open_rows),
        },
        "assignee_open_counts": assignee_open_counts,
        "top_risk_items": top_risk_items,
    }


def run_ops_governance_remediation_escalation_job(
    *,
    trigger: str = "manual",
    dry_run: bool = False,
    include_due_soon_hours: int | None = None,
    notify_enabled: bool | None = None,
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    normalized_due_soon_hours = (
        GOVERNANCE_REMEDIATION_ESCALATION_DUE_SOON_HOURS
        if include_due_soon_hours is None
        else max(0, min(int(include_due_soon_hours), 168))
    )
    effective_notify_enabled = (
        GOVERNANCE_REMEDIATION_ESCALATION_NOTIFY_ENABLED
        if notify_enabled is None
        else bool(notify_enabled)
    )
    snapshot = _build_w22_remediation_sla_snapshot(
        due_soon_hours=normalized_due_soon_hours,
        now=started_at,
    )

    rows = _load_w21_remediation_items(include_inactive=False)
    cutoff = started_at + timedelta(hours=normalized_due_soon_hours)
    if normalized_due_soon_hours > 0:
        candidate_rows = [row for row in rows if row.status != W21_TRACKER_STATUS_DONE and row.due_at <= cutoff]
    else:
        candidate_rows = [row for row in rows if row.status != W21_TRACKER_STATUS_DONE and row.due_at < started_at]

    candidate_rows.sort(key=lambda row: (int(row.priority), row.due_at, int(row.id)))
    candidate_count = len(candidate_rows)
    critical_count = sum(
        1 for row in candidate_rows if row.rule_status == "fail" and bool(row.required)
    )

    notify_attempted = False
    notify_dispatched = False
    notify_error: str | None = None
    notify_channels: list[SlaAlertChannelResult] = []

    if (
        GOVERNANCE_REMEDIATION_ESCALATION_ENABLED
        and (not dry_run)
        and effective_notify_enabled
        and candidate_count > 0
    ):
        notify_attempted = True
        payload = {
            "event": OPS_GOVERNANCE_REMEDIATION_ESCALATION_EVENT_TYPE,
            "job_name": OPS_GOVERNANCE_REMEDIATION_ESCALATION_JOB_NAME,
            "checked_at": started_at.isoformat(),
            "dry_run": bool(dry_run),
            "due_soon_hours": normalized_due_soon_hours,
            "candidate_count": candidate_count,
            "critical_count": critical_count,
            "items": [
                {
                    "id": int(row.id),
                    "item_id": row.item_id,
                    "rule_id": row.rule_id,
                    "priority": int(row.priority),
                    "due_at": row.due_at.isoformat(),
                    "assignee": row.assignee,
                    "status": row.status,
                }
                for row in candidate_rows[:20]
            ],
        }
        notify_dispatched, notify_error, notify_channels = _dispatch_alert_event(
            event_type=OPS_GOVERNANCE_REMEDIATION_ESCALATION_EVENT_TYPE,
            payload=payload,
        )

    if not GOVERNANCE_REMEDIATION_ESCALATION_ENABLED:
        status = "warning"
    elif candidate_count == 0:
        status = "success"
    elif critical_count > 0:
        status = "critical"
    else:
        status = "warning"

    finished_at = datetime.now(timezone.utc)
    detail = {
        "enabled": GOVERNANCE_REMEDIATION_ESCALATION_ENABLED,
        "due_soon_hours": normalized_due_soon_hours,
        "notify_enabled": effective_notify_enabled,
        "dry_run": bool(dry_run),
        "snapshot": snapshot,
        "candidate_count": candidate_count,
        "critical_count": critical_count,
        "notify_attempted": notify_attempted,
        "notify_dispatched": notify_dispatched,
        "notify_error": notify_error,
        "notify_channels": [item.model_dump() for item in notify_channels],
        "items": [
            {
                "id": int(row.id),
                "item_id": row.item_id,
                "rule_id": row.rule_id,
                "rule_status": row.rule_status,
                "required": bool(row.required),
                "priority": int(row.priority),
                "assignee": row.assignee,
                "status": row.status,
                "due_at": row.due_at.isoformat(),
            }
            for row in candidate_rows[:50]
        ],
    }
    run_id = _write_job_run(
        job_name=OPS_GOVERNANCE_REMEDIATION_ESCALATION_JOB_NAME,
        trigger=trigger,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        detail=detail,
    )
    return {
        "run_id": run_id,
        "job_name": OPS_GOVERNANCE_REMEDIATION_ESCALATION_JOB_NAME,
        "trigger": trigger,
        "status": status,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        **detail,
    }


def _latest_ops_governance_remediation_escalation_payload() -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == OPS_GOVERNANCE_REMEDIATION_ESCALATION_JOB_NAME)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
    if row is None:
        return None
    model = _row_to_job_run_model(row)
    detail = model.detail if isinstance(model.detail, dict) else {}
    return {
        "run_id": model.id,
        "job_name": model.job_name,
        "trigger": model.trigger,
        "status": model.status,
        "started_at": model.started_at.isoformat(),
        "finished_at": model.finished_at.isoformat(),
        **detail,
    }


def _w23_candidate_usernames_by_role() -> dict[str, list[str]]:
    with get_conn() as conn:
        rows = conn.execute(
            select(admin_users.c.username, admin_users.c.role)
            .where(admin_users.c.is_active.is_(True))
        ).mappings().all()
    grouped: dict[str, list[str]] = {"owner": [], "manager": [], "operator": []}
    for row in rows:
        role = str(row.get("role") or "").strip().lower()
        username = str(row.get("username") or "").strip()
        if not username or role not in grouped:
            continue
        grouped[role].append(username)
    for role, items in grouped.items():
        grouped[role] = sorted(set(items))
    return grouped


def _w23_choose_assignee(
    *,
    owner_role: str,
    current_loads: dict[str, int],
    by_role: dict[str, list[str]],
) -> tuple[str | None, str]:
    preferred_roles = W23_OWNER_ROLE_TO_ADMIN_ROLES.get(
        owner_role,
        ("owner", "manager", "operator"),
    )
    candidates: list[str] = []
    for role in preferred_roles:
        candidates.extend(by_role.get(role, []))
    deduped = sorted(set(candidates))
    if not deduped:
        fallback = sorted(
            set(by_role.get("owner", []) + by_role.get("manager", []) + by_role.get("operator", []))
        )
        deduped = fallback
    if not deduped:
        return None, "no active owner/manager/operator user found"
    selected = min(deduped, key=lambda username: (int(current_loads.get(username, 0)), username))
    selected_load = int(current_loads.get(selected, 0))
    reason = f"least-loaded among {','.join(preferred_roles)} (current_load={selected_load})"
    return selected, reason


def _build_w23_remediation_workload_snapshot(
    *,
    include_inactive: bool = False,
    max_suggestions: int = 20,
) -> dict[str, Any]:
    generated_at = datetime.now(timezone.utc)
    rows = _load_w21_remediation_items(include_inactive=include_inactive)
    if not include_inactive:
        rows = [row for row in rows if row.status != W21_TRACKER_STATUS_DONE]
    assignee_open_counts: dict[str, int] = {}
    owner_role_open_counts: dict[str, int] = {}
    for row in rows:
        assignee = (row.assignee or "").strip() or "unassigned"
        assignee_open_counts[assignee] = assignee_open_counts.get(assignee, 0) + 1
        owner_role_open_counts[row.owner_role] = owner_role_open_counts.get(row.owner_role, 0) + 1

    candidate_by_role = _w23_candidate_usernames_by_role()
    load_map = {
        username: int(count)
        for username, count in assignee_open_counts.items()
        if username != "unassigned"
    }

    suggestions: list[dict[str, Any]] = []
    unassigned_rows = [row for row in rows if not (row.assignee or "").strip()]
    ordered_unassigned = sorted(unassigned_rows, key=lambda row: (int(row.priority), row.due_at, int(row.id)))
    for row in ordered_unassigned[: max(1, min(int(max_suggestions), 100))]:
        suggested_assignee, reason = _w23_choose_assignee(
            owner_role=row.owner_role,
            current_loads=load_map,
            by_role=candidate_by_role,
        )
        if suggested_assignee is not None:
            load_map[suggested_assignee] = int(load_map.get(suggested_assignee, 0)) + 1
        suggestions.append(
            {
                "id": int(row.id),
                "item_id": row.item_id,
                "rule_id": row.rule_id,
                "owner_role": row.owner_role,
                "priority": int(row.priority),
                "due_at": row.due_at.isoformat(),
                "recommended_assignee": suggested_assignee,
                "reason": reason,
            }
        )

    return {
        "generated_at": generated_at.isoformat(),
        "include_inactive": bool(include_inactive),
        "total_open_items": len(rows),
        "unassigned_open_count": len(unassigned_rows),
        "assignee_open_counts": assignee_open_counts,
        "owner_role_open_counts": owner_role_open_counts,
        "candidate_usernames_by_role": candidate_by_role,
        "suggestions": suggestions,
    }


def run_ops_governance_remediation_auto_assign_job(
    *,
    trigger: str = "manual",
    dry_run: bool = False,
    limit: int | None = None,
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    normalized_limit = (
        GOVERNANCE_REMEDIATION_AUTO_ASSIGN_MAX_ITEMS
        if limit is None
        else max(1, min(int(limit), 500))
    )
    workload = _build_w23_remediation_workload_snapshot(include_inactive=False, max_suggestions=normalized_limit)
    suggestions = workload.get("suggestions") if isinstance(workload.get("suggestions"), list) else []

    assigned_count = 0
    skipped_count = 0
    no_candidate_count = 0
    updated_ids: list[int] = []
    assignment_rows: list[dict[str, Any]] = []

    if GOVERNANCE_REMEDIATION_AUTO_ASSIGN_ENABLED and (not dry_run):
        now = datetime.now(timezone.utc)
        with get_conn() as conn:
            for item in suggestions[:normalized_limit]:
                if not isinstance(item, dict):
                    continue
                tracker_id = int(item.get("id") or 0)
                assignee = item.get("recommended_assignee")
                reason = str(item.get("reason") or "")
                if tracker_id <= 0:
                    skipped_count += 1
                    continue
                if assignee is None:
                    no_candidate_count += 1
                    continue
                row = conn.execute(
                    select(ops_governance_remediation_tracker_items)
                    .where(ops_governance_remediation_tracker_items.c.id == tracker_id)
                    .limit(1)
                ).mappings().first()
                if row is None:
                    skipped_count += 1
                    continue
                current_assignee = str(row.get("assignee") or "").strip()
                current_status = _normalize_w21_tracker_status(row.get("status"))
                if current_assignee:
                    skipped_count += 1
                    continue
                next_status = current_status if current_status != W21_TRACKER_STATUS_PENDING else W21_TRACKER_STATUS_IN_PROGRESS
                note_prefix = str(row.get("completion_note") or "").strip()
                auto_note = f"[auto-assigned {now.isoformat()}] {reason}"
                completion_note = f"{note_prefix}\n{auto_note}".strip() if note_prefix else auto_note
                conn.execute(
                    update(ops_governance_remediation_tracker_items)
                    .where(ops_governance_remediation_tracker_items.c.id == tracker_id)
                    .values(
                        assignee=str(assignee),
                        status=next_status,
                        completion_note=completion_note,
                        updated_by="system",
                        updated_at=now,
                    )
                )
                assigned_count += 1
                updated_ids.append(tracker_id)
                assignment_rows.append(
                    {
                        "id": tracker_id,
                        "assignee": str(assignee),
                        "status": next_status,
                        "reason": reason,
                    }
                )
    else:
        for item in suggestions[:normalized_limit]:
            if not isinstance(item, dict):
                continue
            if item.get("recommended_assignee") is None:
                no_candidate_count += 1

    status = "success"
    if not GOVERNANCE_REMEDIATION_AUTO_ASSIGN_ENABLED:
        status = "warning"
    elif no_candidate_count > 0 and assigned_count == 0:
        status = "warning"

    finished_at = datetime.now(timezone.utc)
    detail = {
        "enabled": GOVERNANCE_REMEDIATION_AUTO_ASSIGN_ENABLED,
        "dry_run": bool(dry_run),
        "limit": normalized_limit,
        "workload": workload,
        "candidate_count": len(suggestions),
        "assigned_count": assigned_count,
        "skipped_count": skipped_count,
        "no_candidate_count": no_candidate_count,
        "updated_ids": updated_ids,
        "assignments": assignment_rows,
    }
    run_id = _write_job_run(
        job_name=OPS_GOVERNANCE_REMEDIATION_AUTO_ASSIGN_JOB_NAME,
        trigger=trigger,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        detail=detail,
    )
    return {
        "run_id": run_id,
        "job_name": OPS_GOVERNANCE_REMEDIATION_AUTO_ASSIGN_JOB_NAME,
        "trigger": trigger,
        "status": status,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        **detail,
    }


def _latest_ops_governance_remediation_auto_assign_payload() -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == OPS_GOVERNANCE_REMEDIATION_AUTO_ASSIGN_JOB_NAME)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
    if row is None:
        return None
    model = _row_to_job_run_model(row)
    detail = model.detail if isinstance(model.detail, dict) else {}
    return {
        "run_id": model.id,
        "job_name": model.job_name,
        "trigger": model.trigger,
        "status": model.status,
        "started_at": model.started_at.isoformat(),
        "finished_at": model.finished_at.isoformat(),
        **detail,
    }


def _build_w24_remediation_backlog_history(
    *,
    window_days: int,
    now: datetime,
) -> dict[str, Any]:
    normalized_window_days = max(1, min(int(window_days), 180))
    cutoff = now - timedelta(days=normalized_window_days)
    job_names = [
        OPS_GOVERNANCE_REMEDIATION_ESCALATION_JOB_NAME,
        OPS_GOVERNANCE_REMEDIATION_AUTO_ASSIGN_JOB_NAME,
        OPS_GOVERNANCE_REMEDIATION_KPI_JOB_NAME,
    ]
    with get_conn() as conn:
        rows = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name.in_(job_names))
            .where(job_runs.c.finished_at >= cutoff)
            .order_by(job_runs.c.finished_at.asc(), job_runs.c.id.asc())
            .limit(400)
        ).mappings().all()

    points: list[dict[str, Any]] = []
    for row in rows:
        model = _row_to_job_run_model(row)
        detail = model.detail if isinstance(model.detail, dict) else {}
        open_items: int | None = None
        metrics = detail.get("metrics")
        if isinstance(metrics, dict):
            raw = metrics.get("open_items")
            if isinstance(raw, (int, float)):
                open_items = int(raw)
        if open_items is None:
            snapshot = detail.get("snapshot")
            if isinstance(snapshot, dict):
                snapshot_metrics = snapshot.get("metrics")
                if isinstance(snapshot_metrics, dict):
                    raw = snapshot_metrics.get("open_items")
                    if isinstance(raw, (int, float)):
                        open_items = int(raw)
        if open_items is None:
            workload = detail.get("workload")
            if isinstance(workload, dict):
                raw = workload.get("total_open_items")
                if isinstance(raw, (int, float)):
                    open_items = int(raw)
        if open_items is None:
            continue

        points.append(
            {
                "finished_at": model.finished_at.isoformat(),
                "open_items": max(0, open_items),
                "source_job": model.job_name,
                "status": model.status,
                "run_id": model.id,
            }
        )

    trend = "flat"
    if len(points) >= 2:
        delta = int(points[-1].get("open_items") or 0) - int(points[0].get("open_items") or 0)
        if delta > 0:
            trend = "up"
        elif delta < 0:
            trend = "down"

    return {
        "window_days": normalized_window_days,
        "count": len(points),
        "trend": trend,
        "points": points,
    }


def _build_w24_remediation_kpi_snapshot(
    *,
    window_days: int = GOVERNANCE_REMEDIATION_KPI_WINDOW_DAYS,
    due_soon_hours: int = GOVERNANCE_REMEDIATION_KPI_DUE_SOON_HOURS,
    now: datetime | None = None,
) -> dict[str, Any]:
    checked_at = now or datetime.now(timezone.utc)
    normalized_window_days = max(1, min(int(window_days), 180))
    normalized_due_soon_hours = max(0, min(int(due_soon_hours), 168))
    done_cutoff = checked_at - timedelta(days=normalized_window_days)
    due_soon_cutoff = checked_at + timedelta(hours=normalized_due_soon_hours)

    all_rows = _load_w21_remediation_items(include_inactive=True)
    active_rows = [row for row in all_rows if row.is_active]
    open_rows = [row for row in active_rows if row.status != W21_TRACKER_STATUS_DONE]
    done_window_rows = [
        row
        for row in all_rows
        if row.completed_at is not None and row.completed_at >= done_cutoff
    ]

    pending_count = sum(1 for row in active_rows if row.status == W21_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in active_rows if row.status == W21_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in active_rows if row.status == W21_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in active_rows if row.status == W21_TRACKER_STATUS_BLOCKED)
    critical_open_rows = [row for row in open_rows if row.rule_status == "fail" and bool(row.required)]
    unassigned_open_rows = [row for row in open_rows if not (row.assignee or "").strip()]
    overdue_rows = [row for row in open_rows if row.due_at < checked_at]
    if normalized_due_soon_hours > 0:
        due_soon_rows = [row for row in open_rows if checked_at <= row.due_at <= due_soon_cutoff]
    else:
        due_soon_rows = []

    age_hours = [max(0.0, (checked_at - row.created_at).total_seconds() / 3600.0) for row in open_rows]
    avg_open_age_hours = round(sum(age_hours) / len(age_hours), 1) if age_hours else 0.0
    median_open_age_hours = round(float(statistics.median(age_hours)), 1) if age_hours else 0.0
    oldest_open_age_hours = round(max(age_hours), 1) if age_hours else 0.0

    completion_rate_percent = int(round((done_count / len(active_rows)) * 100)) if active_rows else 100
    throughput_per_day = round(len(done_window_rows) / max(1, normalized_window_days), 2)

    assignee_open_counts: dict[str, int] = {}
    for row in open_rows:
        assignee = (row.assignee or "unassigned").strip() or "unassigned"
        assignee_open_counts[assignee] = assignee_open_counts.get(assignee, 0) + 1

    top_overdue_rows = sorted(
        overdue_rows,
        key=lambda row: (int(row.priority), row.due_at, int(row.id)),
    )[:10]
    top_overdue_items = [
        {
            "id": int(row.id),
            "item_id": row.item_id,
            "rule_id": row.rule_id,
            "priority": int(row.priority),
            "owner_role": row.owner_role,
            "assignee": row.assignee,
            "status": row.status,
            "due_at": row.due_at.isoformat(),
            "overdue_hours": round((checked_at - row.due_at).total_seconds() / 3600.0, 1),
        }
        for row in top_overdue_rows
    ]

    backlog_history = _build_w24_remediation_backlog_history(
        window_days=normalized_window_days,
        now=checked_at,
    )

    recommendations: list[str] = []
    if len(unassigned_open_rows) > 0:
        recommendations.append("미배정 항목이 있어 /api/ops/governance/gate/remediation/tracker/auto-assign/run 실행 권장")
    if len(overdue_rows) > 0:
        recommendations.append("기한 초과 항목이 있어 /api/ops/governance/gate/remediation/tracker/escalate/run 실행 권장")
    if blocked_count > 0:
        recommendations.append("blocked 항목 owner 지정 및 선행 작업 해소 필요")
    if len(done_window_rows) == 0 and len(open_rows) > 0:
        recommendations.append("최근 처리량이 0건입니다. 담당자 재분배와 우선순위 재정렬 권장")
    if not recommendations:
        recommendations.append("현재 리메디에이션 트래커 상태가 안정적입니다. 현재 운영 정책 유지 권장")

    return {
        "generated_at": checked_at.isoformat(),
        "window_days": normalized_window_days,
        "due_soon_hours": normalized_due_soon_hours,
        "metrics": {
            "total_items": len(all_rows),
            "active_items": len(active_rows),
            "open_items": len(open_rows),
            "pending_count": pending_count,
            "in_progress_count": in_progress_count,
            "done_count": done_count,
            "blocked_count": blocked_count,
            "completion_rate_percent": completion_rate_percent,
            "critical_open_count": len(critical_open_rows),
            "unassigned_open_count": len(unassigned_open_rows),
            "overdue_count": len(overdue_rows),
            "due_soon_count": len(due_soon_rows),
            "done_last_window_count": len(done_window_rows),
            "throughput_per_day": throughput_per_day,
            "avg_open_age_hours": avg_open_age_hours,
            "median_open_age_hours": median_open_age_hours,
            "oldest_open_age_hours": oldest_open_age_hours,
        },
        "status_counts": {
            "pending": pending_count,
            "in_progress": in_progress_count,
            "done": done_count,
            "blocked": blocked_count,
        },
        "assignee_open_counts": assignee_open_counts,
        "backlog_history": backlog_history,
        "top_overdue_items": top_overdue_items,
        "recommendations": recommendations,
    }


def run_ops_governance_remediation_kpi_job(
    *,
    trigger: str = "manual",
    window_days: int | None = None,
    due_soon_hours: int | None = None,
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    normalized_window_days = (
        GOVERNANCE_REMEDIATION_KPI_WINDOW_DAYS
        if window_days is None
        else max(1, min(int(window_days), 180))
    )
    normalized_due_soon_hours = (
        GOVERNANCE_REMEDIATION_KPI_DUE_SOON_HOURS
        if due_soon_hours is None
        else max(0, min(int(due_soon_hours), 168))
    )
    snapshot = _build_w24_remediation_kpi_snapshot(
        window_days=normalized_window_days,
        due_soon_hours=normalized_due_soon_hours,
        now=started_at,
    )
    metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
    overdue_count = int(metrics.get("overdue_count") or 0)
    critical_open_count = int(metrics.get("critical_open_count") or 0)
    unassigned_open_count = int(metrics.get("unassigned_open_count") or 0)
    blocked_count = int(metrics.get("blocked_count") or 0)

    if overdue_count > 0 or critical_open_count > 0:
        status = "critical"
    elif unassigned_open_count > 0 or blocked_count > 0:
        status = "warning"
    else:
        status = "success"

    finished_at = datetime.now(timezone.utc)
    detail = {
        "window_days": normalized_window_days,
        "due_soon_hours": normalized_due_soon_hours,
        "metrics": metrics,
        "status_counts": snapshot.get("status_counts", {}),
        "assignee_open_counts": snapshot.get("assignee_open_counts", {}),
        "backlog_history": snapshot.get("backlog_history", {}),
        "top_overdue_items": snapshot.get("top_overdue_items", []),
        "recommendations": snapshot.get("recommendations", []),
    }
    run_id = _write_job_run(
        job_name=OPS_GOVERNANCE_REMEDIATION_KPI_JOB_NAME,
        trigger=trigger,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        detail=detail,
    )
    return {
        "run_id": run_id,
        "job_name": OPS_GOVERNANCE_REMEDIATION_KPI_JOB_NAME,
        "trigger": trigger,
        "status": status,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        **detail,
    }


def _latest_ops_governance_remediation_kpi_payload() -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == OPS_GOVERNANCE_REMEDIATION_KPI_JOB_NAME)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
    if row is None:
        return None
    model = _row_to_job_run_model(row)
    detail = model.detail if isinstance(model.detail, dict) else {}
    return {
        "run_id": model.id,
        "job_name": model.job_name,
        "trigger": model.trigger,
        "status": model.status,
        "started_at": model.started_at.isoformat(),
        "finished_at": model.finished_at.isoformat(),
        **detail,
    }


def _default_w26_remediation_autopilot_policy() -> dict[str, Any]:
    return {
        "enabled": GOVERNANCE_REMEDIATION_AUTOPILOT_ENABLED,
        "notify_enabled": GOVERNANCE_REMEDIATION_AUTOPILOT_NOTIFY_ENABLED,
        "unassigned_trigger": max(0, GOVERNANCE_REMEDIATION_AUTOPILOT_UNASSIGNED_TRIGGER),
        "overdue_trigger": max(0, GOVERNANCE_REMEDIATION_AUTOPILOT_OVERDUE_TRIGGER),
        "cooldown_minutes": max(0, min(GOVERNANCE_REMEDIATION_AUTOPILOT_COOLDOWN_MINUTES, 1440)),
        "skip_if_no_action": True,
        "kpi_window_days": max(1, min(GOVERNANCE_REMEDIATION_KPI_WINDOW_DAYS, 180)),
        "kpi_due_soon_hours": max(0, min(GOVERNANCE_REMEDIATION_KPI_DUE_SOON_HOURS, 168)),
        "escalation_due_soon_hours": max(0, min(GOVERNANCE_REMEDIATION_ESCALATION_DUE_SOON_HOURS, 168)),
        "auto_assign_max_items": max(1, min(GOVERNANCE_REMEDIATION_AUTO_ASSIGN_MAX_ITEMS, 500)),
    }


def _build_policy_response_payload(
    *,
    policy_key: str,
    updated_at: datetime,
    policy: dict[str, Any],
    scope: str,
    applies_to: str = "global",
    version: str = "v1",
) -> dict[str, Any]:
    updated_at_iso = updated_at.isoformat()
    return {
        "meta": {
            "version": version,
            "scope": scope,
            "applies_to": applies_to,
            "policy_key": policy_key,
            "updated_at": updated_at_iso,
        },
        "policy_key": policy_key,
        "updated_at": updated_at_iso,
        "policy": policy,
    }


def _normalize_w26_remediation_autopilot_policy(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    defaults = _default_w26_remediation_autopilot_policy()

    def _to_int(raw: Any, fallback: int, *, min_value: int, max_value: int) -> int:
        try:
            parsed = int(raw)
        except (TypeError, ValueError):
            parsed = fallback
        return max(min_value, min(parsed, max_value))

    return {
        "enabled": bool(source.get("enabled", defaults["enabled"])),
        "notify_enabled": bool(source.get("notify_enabled", defaults["notify_enabled"])),
        "unassigned_trigger": _to_int(
            source.get("unassigned_trigger"),
            int(defaults["unassigned_trigger"]),
            min_value=0,
            max_value=100000,
        ),
        "overdue_trigger": _to_int(
            source.get("overdue_trigger"),
            int(defaults["overdue_trigger"]),
            min_value=0,
            max_value=100000,
        ),
        "cooldown_minutes": _to_int(
            source.get("cooldown_minutes"),
            int(defaults["cooldown_minutes"]),
            min_value=0,
            max_value=1440,
        ),
        "skip_if_no_action": bool(source.get("skip_if_no_action", defaults["skip_if_no_action"])),
        "kpi_window_days": _to_int(
            source.get("kpi_window_days"),
            int(defaults["kpi_window_days"]),
            min_value=1,
            max_value=180,
        ),
        "kpi_due_soon_hours": _to_int(
            source.get("kpi_due_soon_hours"),
            int(defaults["kpi_due_soon_hours"]),
            min_value=0,
            max_value=168,
        ),
        "escalation_due_soon_hours": _to_int(
            source.get("escalation_due_soon_hours"),
            int(defaults["escalation_due_soon_hours"]),
            min_value=0,
            max_value=168,
        ),
        "auto_assign_max_items": _to_int(
            source.get("auto_assign_max_items"),
            int(defaults["auto_assign_max_items"]),
            min_value=1,
            max_value=500,
        ),
    }


def _parse_w26_remediation_autopilot_policy_json(raw: Any) -> dict[str, Any]:
    try:
        loaded = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        loaded = {}
    return _normalize_w26_remediation_autopilot_policy(loaded)


def _ensure_w26_remediation_autopilot_policy() -> tuple[dict[str, Any], datetime, str]:
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(sla_policies)
            .where(sla_policies.c.policy_key == OPS_GOVERNANCE_REMEDIATION_AUTOPILOT_POLICY_KEY)
            .limit(1)
        ).mappings().first()
        if row is None:
            policy = _default_w26_remediation_autopilot_policy()
            conn.execute(
                insert(sla_policies).values(
                    policy_key=OPS_GOVERNANCE_REMEDIATION_AUTOPILOT_POLICY_KEY,
                    policy_json=_to_json_text(policy),
                    updated_at=now,
                )
            )
            return policy, now, OPS_GOVERNANCE_REMEDIATION_AUTOPILOT_POLICY_KEY
    policy = _parse_w26_remediation_autopilot_policy_json(row["policy_json"])
    updated_at = _as_datetime(row["updated_at"]) if row["updated_at"] is not None else now
    return policy, updated_at, OPS_GOVERNANCE_REMEDIATION_AUTOPILOT_POLICY_KEY


def _upsert_w26_remediation_autopilot_policy(payload: dict[str, Any]) -> tuple[dict[str, Any], datetime, str]:
    current_policy, _, policy_key = _ensure_w26_remediation_autopilot_policy()
    merged = {**current_policy, **(payload if isinstance(payload, dict) else {})}
    normalized = _normalize_w26_remediation_autopilot_policy(merged)
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        conn.execute(
            update(sla_policies)
            .where(sla_policies.c.policy_key == policy_key)
            .values(
                policy_json=_to_json_text(normalized),
                updated_at=now,
            )
        )
    return normalized, now, policy_key


def _evaluate_w26_remediation_autopilot(
    *,
    force: bool,
    policy: dict[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    checked_at = now or datetime.now(timezone.utc)
    normalized_policy = _normalize_w26_remediation_autopilot_policy(policy)
    snapshot = _build_w24_remediation_kpi_snapshot(
        window_days=int(normalized_policy["kpi_window_days"]),
        due_soon_hours=int(normalized_policy["kpi_due_soon_hours"]),
        now=checked_at,
    )
    metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
    unassigned_open_count = int(metrics.get("unassigned_open_count") or 0)
    overdue_count = int(metrics.get("overdue_count") or 0)
    critical_open_count = int(metrics.get("critical_open_count") or 0)

    should_run_auto_assign = force or (
        unassigned_open_count >= int(normalized_policy["unassigned_trigger"])
    )
    should_run_escalation = force or critical_open_count > 0 or (
        overdue_count >= int(normalized_policy["overdue_trigger"])
    )

    planned_actions: list[str] = []
    if bool(normalized_policy["enabled"]):
        if should_run_auto_assign:
            planned_actions.append("auto_assign")
        if should_run_escalation:
            planned_actions.append("escalation")

    return {
        "checked_at": checked_at.isoformat(),
        "force": bool(force),
        "policy": normalized_policy,
        "metrics": metrics,
        "should_run_auto_assign": bool(should_run_auto_assign),
        "should_run_escalation": bool(should_run_escalation),
        "planned_actions": planned_actions,
        "kpi_snapshot": snapshot,
    }


def _latest_job_run_for_name(job_name: str) -> JobRunRead | None:
    with get_conn() as conn:
        row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == job_name)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
    if row is None:
        return None
    return _row_to_job_run_model(row)


def _build_w27_remediation_autopilot_guard_state(
    *,
    policy: dict[str, Any],
    now: datetime,
    force: bool,
) -> dict[str, Any]:
    normalized_policy = _normalize_w26_remediation_autopilot_policy(policy)
    cooldown_minutes = int(normalized_policy.get("cooldown_minutes") or 0)
    latest = _latest_job_run_for_name(OPS_GOVERNANCE_REMEDIATION_AUTOPILOT_JOB_NAME)
    if bool(force):
        return {
            "checked_at": now.isoformat(),
            "force": True,
            "cooldown_minutes": cooldown_minutes,
            "ready": True,
            "blocked": False,
            "reason": "force_override",
            "last_run_id": latest.id if latest is not None else None,
            "last_run_at": latest.finished_at.isoformat() if latest is not None else None,
            "next_allowed_at": None,
            "minutes_until_ready": 0,
        }
    if latest is None or cooldown_minutes <= 0:
        return {
            "checked_at": now.isoformat(),
            "force": False,
            "cooldown_minutes": cooldown_minutes,
            "ready": True,
            "blocked": False,
            "reason": "no_recent_run",
            "last_run_id": latest.id if latest is not None else None,
            "last_run_at": latest.finished_at.isoformat() if latest is not None else None,
            "next_allowed_at": None,
            "minutes_until_ready": 0,
        }

    next_allowed = latest.finished_at + timedelta(minutes=cooldown_minutes)
    remaining_minutes = int(math.ceil((next_allowed - now).total_seconds() / 60.0))
    if remaining_minutes > 0:
        return {
            "checked_at": now.isoformat(),
            "force": False,
            "cooldown_minutes": cooldown_minutes,
            "ready": False,
            "blocked": True,
            "reason": "cooldown_active",
            "last_run_id": latest.id,
            "last_run_at": latest.finished_at.isoformat(),
            "next_allowed_at": next_allowed.isoformat(),
            "minutes_until_ready": remaining_minutes,
        }
    return {
        "checked_at": now.isoformat(),
        "force": False,
        "cooldown_minutes": cooldown_minutes,
        "ready": True,
        "blocked": False,
        "reason": "cooldown_passed",
        "last_run_id": latest.id,
        "last_run_at": latest.finished_at.isoformat(),
        "next_allowed_at": next_allowed.isoformat(),
        "minutes_until_ready": 0,
    }


def run_ops_governance_remediation_autopilot_job(
    *,
    trigger: str = "manual",
    dry_run: bool = False,
    force: bool = False,
    policy_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    current_policy, policy_updated_at, policy_key = _ensure_w26_remediation_autopilot_policy()
    if isinstance(policy_override, dict) and policy_override:
        effective_policy = _normalize_w26_remediation_autopilot_policy({**current_policy, **policy_override})
    else:
        effective_policy = current_policy

    evaluation = _evaluate_w26_remediation_autopilot(
        force=force,
        policy=effective_policy,
        now=started_at,
    )
    metrics = evaluation.get("metrics", {}) if isinstance(evaluation.get("metrics"), dict) else {}
    guard = _build_w27_remediation_autopilot_guard_state(
        policy=effective_policy,
        now=started_at,
        force=force,
    )

    auto_assign_result: dict[str, Any] | None = None
    escalation_result: dict[str, Any] | None = None
    planned_actions = list(evaluation.get("planned_actions", []))
    actions: list[str] = []
    errors: list[str] = []
    skipped = False
    skip_reason: str | None = None

    if not bool(effective_policy.get("enabled", True)):
        errors.append("autopilot disabled by policy")
    elif bool(guard.get("blocked", False)):
        skipped = True
        skip_reason = str(guard.get("reason") or "guard_blocked")
    elif len(planned_actions) == 0 and bool(effective_policy.get("skip_if_no_action", True)):
        skipped = True
        skip_reason = "no_triggered_actions"
    else:
        if "auto_assign" in planned_actions:
            actions.append("auto_assign")
            try:
                auto_assign_result = run_ops_governance_remediation_auto_assign_job(
                    trigger="autopilot",
                    dry_run=dry_run,
                    limit=int(effective_policy.get("auto_assign_max_items") or 30),
                )
            except Exception as exc:
                errors.append(f"auto_assign failed: {exc}")
        if "escalation" in planned_actions:
            actions.append("escalation")
            try:
                escalation_result = run_ops_governance_remediation_escalation_job(
                    trigger="autopilot",
                    dry_run=dry_run,
                    include_due_soon_hours=int(effective_policy.get("escalation_due_soon_hours") or 12),
                    notify_enabled=bool(effective_policy.get("notify_enabled", True)),
                )
            except Exception as exc:
                errors.append(f"escalation failed: {exc}")

    overdue_count = int(metrics.get("overdue_count") or 0)
    critical_open_count = int(metrics.get("critical_open_count") or 0)
    unassigned_open_count = int(metrics.get("unassigned_open_count") or 0)

    status = "success"
    if errors:
        status = "critical"
    elif overdue_count > 0 or critical_open_count > 0:
        status = "warning"
    elif unassigned_open_count > 0 and "auto_assign" not in planned_actions:
        status = "warning"

    finished_at = datetime.now(timezone.utc)
    detail = {
        "enabled": bool(effective_policy.get("enabled", True)),
        "dry_run": bool(dry_run),
        "force": bool(force),
        "policy_key": policy_key,
        "policy_updated_at": policy_updated_at.isoformat(),
        "policy": effective_policy,
        "metrics": metrics,
        "guard": guard,
        "skipped": skipped,
        "skip_reason": skip_reason,
        "planned_actions": planned_actions,
        "actions": actions,
        "should_run_auto_assign": bool(evaluation.get("should_run_auto_assign", False)),
        "should_run_escalation": bool(evaluation.get("should_run_escalation", False)),
        "auto_assign": auto_assign_result,
        "escalation": escalation_result,
        "errors": errors,
    }
    run_id = _write_job_run(
        job_name=OPS_GOVERNANCE_REMEDIATION_AUTOPILOT_JOB_NAME,
        trigger=trigger,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        detail=detail,
    )
    return {
        "run_id": run_id,
        "job_name": OPS_GOVERNANCE_REMEDIATION_AUTOPILOT_JOB_NAME,
        "trigger": trigger,
        "status": status,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        **detail,
    }


def _latest_ops_governance_remediation_autopilot_payload() -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == OPS_GOVERNANCE_REMEDIATION_AUTOPILOT_JOB_NAME)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
    if row is None:
        return None
    model = _row_to_job_run_model(row)
    detail = model.detail if isinstance(model.detail, dict) else {}
    return {
        "run_id": model.id,
        "job_name": model.job_name,
        "trigger": model.trigger,
        "status": model.status,
        "started_at": model.started_at.isoformat(),
        "finished_at": model.finished_at.isoformat(),
        **detail,
    }


def _build_w28_remediation_autopilot_history(*, limit: int = 20) -> dict[str, Any]:
    normalized_limit = max(1, min(int(limit), 100))
    with get_conn() as conn:
        rows = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == OPS_GOVERNANCE_REMEDIATION_AUTOPILOT_JOB_NAME)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(normalized_limit)
        ).mappings().all()

    items: list[dict[str, Any]] = []
    for row in rows:
        model = _row_to_job_run_model(row)
        detail = model.detail if isinstance(model.detail, dict) else {}
        metrics = detail.get("metrics", {}) if isinstance(detail.get("metrics"), dict) else {}
        items.append(
            {
                "run_id": model.id,
                "status": model.status,
                "trigger": model.trigger,
                "started_at": model.started_at.isoformat(),
                "finished_at": model.finished_at.isoformat(),
                "dry_run": bool(detail.get("dry_run", False)),
                "force": bool(detail.get("force", False)),
                "skipped": bool(detail.get("skipped", False)),
                "skip_reason": detail.get("skip_reason"),
                "planned_actions": detail.get("planned_actions", []),
                "actions": detail.get("actions", []),
                "errors_count": len(detail.get("errors", []) if isinstance(detail.get("errors"), list) else []),
                "open_items": int(metrics.get("open_items") or 0),
                "overdue_count": int(metrics.get("overdue_count") or 0),
                "unassigned_open_count": int(metrics.get("unassigned_open_count") or 0),
                "critical_open_count": int(metrics.get("critical_open_count") or 0),
            }
        )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(items),
        "limit": normalized_limit,
        "items": items,
    }


def _build_w28_remediation_autopilot_summary(*, days: int = 7) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    normalized_days = max(1, min(int(days), 90))
    cutoff = now - timedelta(days=normalized_days)
    with get_conn() as conn:
        rows = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == OPS_GOVERNANCE_REMEDIATION_AUTOPILOT_JOB_NAME)
            .where(job_runs.c.finished_at >= cutoff)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(500)
        ).mappings().all()

    status_counts: dict[str, int] = {"success": 0, "warning": 0, "critical": 0}
    planned_action_counts: dict[str, int] = {"auto_assign": 0, "escalation": 0}
    executed_action_counts: dict[str, int] = {"auto_assign": 0, "escalation": 0}
    skipped_count = 0
    cooldown_blocked_count = 0
    error_run_count = 0
    latest_run: dict[str, Any] | None = None

    for idx, row in enumerate(rows):
        model = _row_to_job_run_model(row)
        detail = model.detail if isinstance(model.detail, dict) else {}
        status = model.status if model.status in status_counts else "warning"
        status_counts[status] = status_counts.get(status, 0) + 1
        planned_actions = detail.get("planned_actions", [])
        if isinstance(planned_actions, list):
            for action in planned_actions:
                action_name = str(action or "")
                if action_name in planned_action_counts:
                    planned_action_counts[action_name] += 1
        actions = detail.get("actions", [])
        if isinstance(actions, list):
            for action in actions:
                action_name = str(action or "")
                if action_name in executed_action_counts:
                    executed_action_counts[action_name] += 1
        if bool(detail.get("skipped", False)):
            skipped_count += 1
            if str(detail.get("skip_reason") or "") == "cooldown_active":
                cooldown_blocked_count += 1
        errors = detail.get("errors", [])
        if isinstance(errors, list) and len(errors) > 0:
            error_run_count += 1
        if idx == 0:
            metrics = detail.get("metrics", {}) if isinstance(detail.get("metrics"), dict) else {}
            latest_run = {
                "run_id": model.id,
                "status": model.status,
                "finished_at": model.finished_at.isoformat(),
                "skipped": bool(detail.get("skipped", False)),
                "skip_reason": detail.get("skip_reason"),
                "planned_actions": planned_actions if isinstance(planned_actions, list) else [],
                "actions": actions if isinstance(actions, list) else [],
                "open_items": int(metrics.get("open_items") or 0),
                "overdue_count": int(metrics.get("overdue_count") or 0),
                "unassigned_open_count": int(metrics.get("unassigned_open_count") or 0),
                "critical_open_count": int(metrics.get("critical_open_count") or 0),
            }

    total_runs = len(rows)
    executed_runs = max(0, total_runs - skipped_count)
    success_rate_percent = (
        round((status_counts.get("success", 0) / total_runs) * 100.0, 1) if total_runs > 0 else 100.0
    )
    skipped_rate_percent = (
        round((skipped_count / total_runs) * 100.0, 1) if total_runs > 0 else 0.0
    )

    return {
        "generated_at": now.isoformat(),
        "window_days": normalized_days,
        "total_runs": total_runs,
        "executed_runs": executed_runs,
        "skipped_runs": skipped_count,
        "status_counts": status_counts,
        "planned_action_counts": planned_action_counts,
        "executed_action_counts": executed_action_counts,
        "cooldown_blocked_runs": cooldown_blocked_count,
        "error_runs": error_run_count,
        "success_rate_percent": success_rate_percent,
        "skipped_rate_percent": skipped_rate_percent,
        "latest_run": latest_run,
    }


def _build_w29_remediation_autopilot_history_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "run_id",
            "status",
            "trigger",
            "started_at",
            "finished_at",
            "dry_run",
            "force",
            "skipped",
            "skip_reason",
            "planned_actions",
            "actions",
            "errors_count",
            "open_items",
            "overdue_count",
            "unassigned_open_count",
            "critical_open_count",
        ]
    )
    for item in payload.get("items", []):
        if not isinstance(item, dict):
            continue
        planned_actions = item.get("planned_actions", [])
        if isinstance(planned_actions, list):
            planned_actions_text = "|".join(str(v) for v in planned_actions)
        else:
            planned_actions_text = ""
        actions = item.get("actions", [])
        if isinstance(actions, list):
            actions_text = "|".join(str(v) for v in actions)
        else:
            actions_text = ""
        writer.writerow(
            [
                item.get("run_id"),
                item.get("status"),
                item.get("trigger"),
                item.get("started_at"),
                item.get("finished_at"),
                bool(item.get("dry_run", False)),
                bool(item.get("force", False)),
                bool(item.get("skipped", False)),
                item.get("skip_reason"),
                planned_actions_text,
                actions_text,
                int(item.get("errors_count") or 0),
                int(item.get("open_items") or 0),
                int(item.get("overdue_count") or 0),
                int(item.get("unassigned_open_count") or 0),
                int(item.get("critical_open_count") or 0),
            ]
        )
    return out.getvalue()


def _build_w29_remediation_autopilot_summary_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["metric", "value"])
    writer.writerow(["generated_at", payload.get("generated_at")])
    writer.writerow(["window_days", int(payload.get("window_days") or 0)])
    writer.writerow(["total_runs", int(payload.get("total_runs") or 0)])
    writer.writerow(["executed_runs", int(payload.get("executed_runs") or 0)])
    writer.writerow(["skipped_runs", int(payload.get("skipped_runs") or 0)])
    writer.writerow(["cooldown_blocked_runs", int(payload.get("cooldown_blocked_runs") or 0)])
    writer.writerow(["error_runs", int(payload.get("error_runs") or 0)])
    writer.writerow(["success_rate_percent", float(payload.get("success_rate_percent") or 0.0)])
    writer.writerow(["skipped_rate_percent", float(payload.get("skipped_rate_percent") or 0.0)])

    status_counts = payload.get("status_counts", {})
    if isinstance(status_counts, dict):
        writer.writerow(["status_success", int(status_counts.get("success") or 0)])
        writer.writerow(["status_warning", int(status_counts.get("warning") or 0)])
        writer.writerow(["status_critical", int(status_counts.get("critical") or 0)])

    planned_counts = payload.get("planned_action_counts", {})
    if isinstance(planned_counts, dict):
        writer.writerow(["planned_auto_assign", int(planned_counts.get("auto_assign") or 0)])
        writer.writerow(["planned_escalation", int(planned_counts.get("escalation") or 0)])

    executed_counts = payload.get("executed_action_counts", {})
    if isinstance(executed_counts, dict):
        writer.writerow(["executed_auto_assign", int(executed_counts.get("auto_assign") or 0)])
        writer.writerow(["executed_escalation", int(executed_counts.get("escalation") or 0)])

    latest_run = payload.get("latest_run", {})
    if isinstance(latest_run, dict) and latest_run:
        writer.writerow(["latest_run_id", latest_run.get("run_id")])
        writer.writerow(["latest_run_status", latest_run.get("status")])
        writer.writerow(["latest_run_finished_at", latest_run.get("finished_at")])
        writer.writerow(["latest_run_skipped", bool(latest_run.get("skipped", False))])
        writer.writerow(["latest_run_skip_reason", latest_run.get("skip_reason")])
        latest_planned = latest_run.get("planned_actions", [])
        writer.writerow(
            [
                "latest_run_planned_actions",
                "|".join(str(v) for v in latest_planned) if isinstance(latest_planned, list) else "",
            ]
        )
        latest_actions = latest_run.get("actions", [])
        writer.writerow(
            [
                "latest_run_actions",
                "|".join(str(v) for v in latest_actions) if isinstance(latest_actions, list) else "",
            ]
        )
        writer.writerow(["latest_run_open_items", int(latest_run.get("open_items") or 0)])
        writer.writerow(["latest_run_overdue_count", int(latest_run.get("overdue_count") or 0)])
        writer.writerow(["latest_run_unassigned_open_count", int(latest_run.get("unassigned_open_count") or 0)])
        writer.writerow(["latest_run_critical_open_count", int(latest_run.get("critical_open_count") or 0)])

    return out.getvalue()


def _build_w30_remediation_autopilot_anomalies(*, days: int = 14) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    normalized_days = max(1, min(int(days), 90))
    summary = _build_w28_remediation_autopilot_summary(days=normalized_days)
    history_limit = max(10, min(100, normalized_days * 6))
    history = _build_w28_remediation_autopilot_history(limit=history_limit)

    total_runs = int(summary.get("total_runs") or 0)
    success_rate_percent = float(summary.get("success_rate_percent") or 0.0)
    skipped_rate_percent = float(summary.get("skipped_rate_percent") or 0.0)
    cooldown_blocked_runs = int(summary.get("cooldown_blocked_runs") or 0)
    error_runs = int(summary.get("error_runs") or 0)
    latest_run = summary.get("latest_run") if isinstance(summary.get("latest_run"), dict) else None
    history_items = history.get("items", []) if isinstance(history.get("items"), list) else []

    anomalies: list[dict[str, Any]] = []

    def add_anomaly(
        *,
        code: str,
        severity: str,
        message: str,
        observed: Any,
        target: Any,
        recommendation: str,
    ) -> None:
        anomalies.append(
            {
                "code": code,
                "severity": severity,
                "message": message,
                "observed": observed,
                "target": target,
                "recommendation": recommendation,
            }
        )

    if total_runs == 0:
        add_anomaly(
            code="no_recent_runs",
            severity="critical",
            message="No autopilot runs found in window.",
            observed=0,
            target=">=1 run",
            recommendation="Trigger manual autopilot run and verify cron schedule.",
        )
    elif total_runs < 5:
        add_anomaly(
            code="low_sample_size",
            severity="warning",
            message="Run count is low for stable trend analysis.",
            observed=total_runs,
            target=">=5 runs",
            recommendation="Increase run cadence or expand analysis window.",
        )

    if success_rate_percent < 70.0:
        add_anomaly(
            code="low_success_rate",
            severity="critical",
            message="Autopilot success rate is below critical threshold.",
            observed=success_rate_percent,
            target=">=85.0",
            recommendation="Review autopilot errors and unblock failing actions.",
        )
    elif success_rate_percent < 85.0:
        add_anomaly(
            code="degraded_success_rate",
            severity="warning",
            message="Autopilot success rate is below target.",
            observed=success_rate_percent,
            target=">=85.0",
            recommendation="Review skipped/failed runs and tune policy thresholds.",
        )

    if skipped_rate_percent > 60.0:
        add_anomaly(
            code="high_skip_rate",
            severity="critical",
            message="Skip rate is above critical threshold.",
            observed=skipped_rate_percent,
            target="<=35.0",
            recommendation="Review cooldown and skip policy to reduce skipped runs.",
        )
    elif skipped_rate_percent > 35.0:
        add_anomaly(
            code="elevated_skip_rate",
            severity="warning",
            message="Skip rate is above target.",
            observed=skipped_rate_percent,
            target="<=35.0",
            recommendation="Tune policy thresholds and run cadence.",
        )

    if cooldown_blocked_runs >= 10:
        add_anomaly(
            code="cooldown_blocks_excessive",
            severity="critical",
            message="Cooldown blocks are frequently preventing execution.",
            observed=cooldown_blocked_runs,
            target="<10",
            recommendation="Reduce cooldown minutes or increase interval between runs.",
        )
    elif cooldown_blocked_runs >= 5:
        add_anomaly(
            code="cooldown_blocks_high",
            severity="warning",
            message="Cooldown blocks are high.",
            observed=cooldown_blocked_runs,
            target="<5",
            recommendation="Tune cooldown policy to balance safety and execution rate.",
        )

    if error_runs >= 5:
        add_anomaly(
            code="error_runs_high",
            severity="critical",
            message="Autopilot error runs exceed critical threshold.",
            observed=error_runs,
            target="<5",
            recommendation="Inspect run errors and add remediation for recurring failures.",
        )
    elif error_runs >= 1:
        add_anomaly(
            code="error_runs_detected",
            severity="warning",
            message="Autopilot error runs detected in analysis window.",
            observed=error_runs,
            target="0",
            recommendation="Review latest error payload and stabilize failing component.",
        )

    consecutive_cooldown_skips = 0
    for item in history_items:
        if not isinstance(item, dict):
            continue
        if bool(item.get("skipped", False)) and str(item.get("skip_reason") or "") == "cooldown_active":
            consecutive_cooldown_skips += 1
            continue
        break
    if consecutive_cooldown_skips >= 6:
        add_anomaly(
            code="consecutive_cooldown_skips",
            severity="critical",
            message="Consecutive cooldown skips are too high.",
            observed=consecutive_cooldown_skips,
            target="<3",
            recommendation="Run with force=true once and revisit cooldown policy.",
        )
    elif consecutive_cooldown_skips >= 3:
        add_anomaly(
            code="consecutive_cooldown_skips",
            severity="warning",
            message="Consecutive cooldown skips detected.",
            observed=consecutive_cooldown_skips,
            target="<3",
            recommendation="Check run cadence and cooldown settings.",
        )

    if isinstance(latest_run, dict):
        latest_status = str(latest_run.get("status") or "warning")
        latest_overdue = int(latest_run.get("overdue_count") or 0)
        latest_critical_open = int(latest_run.get("critical_open_count") or 0)
        if latest_status == "critical":
            add_anomaly(
                code="latest_run_critical",
                severity="critical",
                message="Latest autopilot run ended in critical state.",
                observed=latest_status,
                target="success|warning",
                recommendation="Inspect latest run errors and execute recovery actions.",
            )
        if latest_critical_open > 0:
            add_anomaly(
                code="critical_open_items",
                severity="warning",
                message="Critical open remediation items remain.",
                observed=latest_critical_open,
                target="0",
                recommendation="Prioritize critical items and rerun autopilot.",
            )
        if latest_overdue > 0:
            add_anomaly(
                code="overdue_items_open",
                severity="warning",
                message="Overdue remediation items remain open.",
                observed=latest_overdue,
                target="0",
                recommendation="Run escalation and clear overdue backlog.",
            )

    severity_order = {"info": 0, "warning": 1, "critical": 2}
    max_severity = 0
    for row in anomalies:
        level = str(row.get("severity") or "info")
        max_severity = max(max_severity, severity_order.get(level, 0))
    health_status = "healthy"
    if max_severity >= severity_order["critical"]:
        health_status = "critical"
    elif max_severity >= severity_order["warning"]:
        health_status = "warning"

    anomalies.sort(
        key=lambda row: (
            -severity_order.get(str(row.get("severity") or "info"), 0),
            str(row.get("code") or ""),
        )
    )
    recommendations = list(dict.fromkeys(str(row.get("recommendation") or "") for row in anomalies if row.get("recommendation")))

    return {
        "generated_at": now.isoformat(),
        "window_days": normalized_days,
        "health_status": health_status,
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "metrics": {
            "total_runs": total_runs,
            "executed_runs": int(summary.get("executed_runs") or 0),
            "skipped_runs": int(summary.get("skipped_runs") or 0),
            "success_rate_percent": success_rate_percent,
            "skipped_rate_percent": skipped_rate_percent,
            "cooldown_blocked_runs": cooldown_blocked_runs,
            "error_runs": error_runs,
            "consecutive_cooldown_skips": consecutive_cooldown_skips,
        },
        "latest_run": latest_run,
        "recommendations": recommendations[:5],
    }


def _build_w30_remediation_autopilot_anomalies_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "generated_at",
            "window_days",
            "health_status",
            "total_runs",
            "success_rate_percent",
            "skipped_rate_percent",
            "cooldown_blocked_runs",
            "error_runs",
            "code",
            "severity",
            "message",
            "observed",
            "target",
            "recommendation",
        ]
    )
    metrics = payload.get("metrics", {}) if isinstance(payload.get("metrics"), dict) else {}
    anomalies = payload.get("anomalies", []) if isinstance(payload.get("anomalies"), list) else []
    rows = anomalies or [
        {
            "code": "none",
            "severity": "info",
            "message": "No anomalies detected",
            "observed": "",
            "target": "",
            "recommendation": "",
        }
    ]
    for row in rows:
        if not isinstance(row, dict):
            continue
        writer.writerow(
            [
                payload.get("generated_at"),
                int(payload.get("window_days") or 0),
                payload.get("health_status"),
                int(metrics.get("total_runs") or 0),
                float(metrics.get("success_rate_percent") or 0.0),
                float(metrics.get("skipped_rate_percent") or 0.0),
                int(metrics.get("cooldown_blocked_runs") or 0),
                int(metrics.get("error_runs") or 0),
                row.get("code"),
                row.get("severity"),
                row.get("message"),
                row.get("observed"),
                row.get("target"),
                row.get("recommendation"),
            ]
        )
    return out.getvalue()
