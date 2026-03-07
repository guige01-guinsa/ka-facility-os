"""Adoption tracker helpers extracted from app.main."""

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
    "_row_to_w02_tracker_item_model",
    "_row_to_w02_evidence_model",
    "_adoption_w02_catalog_items",
    "_compute_w02_tracker_overview",
    "_compute_w02_tracker_readiness",
    "_resolve_w02_site_completion_status",
    "_row_to_w02_completion_model",
    "_load_w02_tracker_items_for_site",
    "_reset_w02_completion_if_closed",
    "_row_to_w03_tracker_item_model",
    "_row_to_w03_evidence_model",
    "_adoption_w03_catalog_items",
    "_compute_w03_tracker_overview",
    "_compute_w03_tracker_readiness",
    "_resolve_w03_site_completion_status",
    "_row_to_w03_completion_model",
    "_load_w03_tracker_items_for_site",
    "_reset_w03_completion_if_closed",
    "_row_to_w04_tracker_item_model",
    "_row_to_w04_evidence_model",
    "_adoption_w04_catalog_items",
    "_compute_w04_tracker_overview",
    "_compute_w04_tracker_readiness",
    "_resolve_w04_site_completion_status",
    "_row_to_w04_completion_model",
    "_load_w04_tracker_items_for_site",
    "_reset_w04_completion_if_closed",
    "_row_to_w07_tracker_item_model",
    "_row_to_w07_evidence_model",
    "_adoption_w07_catalog_items",
    "_compute_w07_tracker_overview",
    "_compute_w07_tracker_readiness",
    "_resolve_w07_site_completion_status",
    "_row_to_w07_completion_model",
    "_load_w07_tracker_items_for_site",
    "_reset_w07_completion_if_closed",
    "_row_to_w09_tracker_item_model",
    "_row_to_w09_evidence_model",
    "_adoption_w09_catalog_items",
    "_compute_w09_tracker_overview",
    "_compute_w09_tracker_readiness",
    "_resolve_w09_site_completion_status",
    "_row_to_w09_completion_model",
    "_load_w09_tracker_items_for_site",
    "_reset_w09_completion_if_closed",
    "_row_to_w10_tracker_item_model",
    "_row_to_w10_evidence_model",
    "_adoption_w10_catalog_items",
    "_compute_w10_tracker_overview",
    "_compute_w10_tracker_readiness",
    "_resolve_w10_site_completion_status",
    "_row_to_w10_completion_model",
    "_load_w10_tracker_items_for_site",
    "_reset_w10_completion_if_closed",
    "_row_to_w11_tracker_item_model",
    "_row_to_w11_evidence_model",
    "_adoption_w11_catalog_items",
    "_compute_w11_tracker_overview",
    "_compute_w11_tracker_readiness",
    "_resolve_w11_site_completion_status",
    "_row_to_w11_completion_model",
    "_load_w11_tracker_items_for_site",
    "_reset_w11_completion_if_closed",
    "_row_to_w12_tracker_item_model",
    "_row_to_w12_evidence_model",
    "_adoption_w12_catalog_items",
    "_compute_w12_tracker_overview",
    "_compute_w12_tracker_readiness",
    "_resolve_w12_site_completion_status",
    "_row_to_w12_completion_model",
    "_load_w12_tracker_items_for_site",
    "_reset_w12_completion_if_closed",
    "_row_to_w13_tracker_item_model",
    "_row_to_w13_evidence_model",
    "_adoption_w13_catalog_items",
    "_compute_w13_tracker_overview",
    "_compute_w13_tracker_readiness",
    "_resolve_w13_site_completion_status",
    "_row_to_w13_completion_model",
    "_load_w13_tracker_items_for_site",
    "_reset_w13_completion_if_closed",
    "_row_to_w14_tracker_item_model",
    "_row_to_w14_evidence_model",
    "_adoption_w14_catalog_items",
    "_compute_w14_tracker_overview",
    "_compute_w14_tracker_readiness",
    "_resolve_w14_site_completion_status",
    "_row_to_w14_completion_model",
    "_load_w14_tracker_items_for_site",
    "_reset_w14_completion_if_closed",
    "_row_to_w15_tracker_item_model",
    "_row_to_w15_evidence_model",
    "_adoption_w15_catalog_items",
    "_compute_w15_tracker_overview",
    "_compute_w15_tracker_readiness",
    "_resolve_w15_site_completion_status",
    "_row_to_w15_completion_model",
    "_load_w15_tracker_items_for_site",
    "_reset_w15_completion_if_closed",
}


def bind(namespace: dict[str, object]) -> None:
    for key, value in namespace.items():
        if key not in _LOCAL_SYMBOLS:
            globals()[key] = value


def _row_to_w02_tracker_item_model(row: dict[str, Any]) -> W02TrackerItemRead:
    return W02TrackerItemRead(
        id=int(row["id"]),
        site=str(row["site"]),
        item_type=str(row["item_type"]),
        item_key=str(row["item_key"]),
        item_name=str(row["item_name"]),
        assignee=row.get("assignee"),
        status=str(row["status"]),
        completion_checked=bool(row.get("completion_checked", False)),
        completion_note=str(row.get("completion_note") or ""),
        due_at=_as_optional_datetime(row.get("due_at")),
        completed_at=_as_optional_datetime(row.get("completed_at")),
        evidence_count=int(row.get("evidence_count") or 0),
        created_by=str(row.get("created_by") or "system"),
        updated_by=str(row.get("updated_by") or "system"),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _row_to_w02_evidence_model(row: dict[str, Any]) -> W02EvidenceRead:
    return W02EvidenceRead(
        id=int(row["id"]),
        tracker_item_id=int(row["tracker_item_id"]),
        site=str(row["site"]),
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


def _adoption_w02_catalog_items(site: str) -> list[dict[str, Any]]:
    payload = _adoption_w02_payload()
    timeline = payload.get("timeline", {})
    default_due_at: datetime | None = None
    end_date_raw = str(timeline.get("end_date") or "")
    if end_date_raw:
        try:
            parsed = datetime.strptime(f"{end_date_raw} 23:59", "%Y-%m-%d %H:%M")
            default_due_at = parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            default_due_at = None

    entries: list[dict[str, Any]] = []
    for item in ADOPTION_W02_SOP_RUNBOOKS:
        entries.append(
            {
                "site": site,
                "item_type": "sop_runbook",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("name", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W02_SANDBOX_SCENARIOS:
        entries.append(
            {
                "site": site,
                "item_type": "sandbox_scenario",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("objective", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W02_SCHEDULED_EVENTS:
        event_due_at = default_due_at
        try:
            event_due = datetime.strptime(
                f"{str(item.get('date', ''))} {str(item.get('end_time', '23:59'))}",
                "%Y-%m-%d %H:%M",
            )
            event_due_at = event_due.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        entries.append(
            {
                "site": site,
                "item_type": "scheduled_event",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": event_due_at,
            }
        )
    return entries


def _compute_w02_tracker_overview(site: str, rows: list[W02TrackerItemRead]) -> W02TrackerOverviewRead:
    pending_count = sum(1 for row in rows if row.status == W02_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W02_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W02_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W02_TRACKER_STATUS_BLOCKED)
    total = len(rows)
    completion_rate = int(round((done_count / total) * 100)) if total > 0 else 0
    evidence_total = sum(int(row.evidence_count) for row in rows)
    assignee_breakdown: dict[str, int] = {}
    for row in rows:
        assignee = (row.assignee or "unassigned").strip() or "unassigned"
        assignee_breakdown[assignee] = assignee_breakdown.get(assignee, 0) + 1

    return W02TrackerOverviewRead(
        site=site,
        total_items=total,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate,
        evidence_total_count=evidence_total,
        assignee_breakdown=assignee_breakdown,
    )


def _compute_w02_tracker_readiness(
    *,
    site: str,
    rows: list[W02TrackerItemRead],
    checked_at: datetime | None = None,
) -> W02TrackerReadinessRead:
    now = checked_at or datetime.now(timezone.utc)
    total_items = len(rows)
    pending_count = sum(1 for row in rows if row.status == W02_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W02_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W02_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W02_TRACKER_STATUS_BLOCKED)
    completion_rate_percent = int(round((done_count / total_items) * 100)) if total_items > 0 else 0
    evidence_total_count = sum(int(row.evidence_count) for row in rows)

    missing_assignee_count = sum(1 for row in rows if not (row.assignee or "").strip())
    missing_completion_checked_count = sum(1 for row in rows if not bool(row.completion_checked))
    missing_required_evidence_count = sum(
        1
        for row in rows
        if row.item_type in W02_EVIDENCE_REQUIRED_ITEM_TYPES and int(row.evidence_count) <= 0
    )

    blockers: list[str] = []
    if total_items == 0:
        blockers.append("트래커 항목이 없습니다. bootstrap을 먼저 실행하세요.")
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
    if missing_required_evidence_count > 0:
        blockers.append(f"필수 증빙 미업로드(sandbox_scenario) 항목 {missing_required_evidence_count}건이 있습니다.")

    rule_checks = [
        total_items > 0,
        pending_count == 0,
        in_progress_count == 0,
        blocked_count == 0,
        missing_assignee_count == 0,
        missing_completion_checked_count == 0,
        missing_required_evidence_count == 0,
    ]
    readiness_score_percent = int(round((sum(1 for ok in rule_checks if ok) / len(rule_checks)) * 100))
    if total_items > 0:
        readiness_score_percent = max(readiness_score_percent, completion_rate_percent)
    ready = len(blockers) == 0
    if ready:
        readiness_score_percent = 100

    return W02TrackerReadinessRead(
        site=site,
        checked_at=now,
        total_items=total_items,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate_percent,
        evidence_total_count=evidence_total_count,
        missing_assignee_count=missing_assignee_count,
        missing_completion_checked_count=missing_completion_checked_count,
        missing_required_evidence_count=missing_required_evidence_count,
        readiness_score_percent=readiness_score_percent,
        ready=ready,
        blockers=blockers,
    )


def _resolve_w02_site_completion_status(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    if value in W02_SITE_COMPLETION_STATUS_SET:
        return value
    return W02_SITE_COMPLETION_STATUS_ACTIVE


def _row_to_w02_completion_model(
    *,
    site: str,
    readiness: W02TrackerReadinessRead,
    row: dict[str, Any] | None,
) -> W02TrackerCompletionRead:
    if row is None:
        return W02TrackerCompletionRead(
            site=site,
            status=W02_SITE_COMPLETION_STATUS_ACTIVE,
            completion_note="",
            completed_by=None,
            completed_at=None,
            force_used=False,
            last_checked_at=readiness.checked_at,
            readiness=readiness,
        )

    status = _resolve_w02_site_completion_status(row.get("status"))
    completion_note = str(row.get("completion_note") or "")
    completed_by = row.get("completed_by")
    completed_at = _as_optional_datetime(row.get("completed_at"))
    force_used = bool(row.get("force_used", False))
    last_checked_at = _as_optional_datetime(row.get("last_checked_at")) or readiness.checked_at
    return W02TrackerCompletionRead(
        site=site,
        status=status,
        completion_note=completion_note,
        completed_by=completed_by,
        completed_at=completed_at,
        force_used=force_used,
        last_checked_at=last_checked_at,
        readiness=readiness,
    )


def _load_w02_tracker_items_for_site(site: str) -> list[W02TrackerItemRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(adoption_w02_tracker_items)
            .where(adoption_w02_tracker_items.c.site == site)
            .order_by(
                adoption_w02_tracker_items.c.item_type.asc(),
                adoption_w02_tracker_items.c.item_key.asc(),
                adoption_w02_tracker_items.c.id.asc(),
            )
        ).mappings().all()
    return [_row_to_w02_tracker_item_model(row) for row in rows]


def _reset_w02_completion_if_closed(
    *,
    conn: Any,
    site: str,
    actor_username: str,
    checked_at: datetime,
    reason: str,
) -> None:
    row = conn.execute(
        select(adoption_w02_site_runs.c.status)
        .where(adoption_w02_site_runs.c.site == site)
        .limit(1)
    ).mappings().first()
    if row is None:
        return
    status = _resolve_w02_site_completion_status(row.get("status"))
    if status == W02_SITE_COMPLETION_STATUS_ACTIVE:
        return
    conn.execute(
        update(adoption_w02_site_runs)
        .where(adoption_w02_site_runs.c.site == site)
        .values(
            status=W02_SITE_COMPLETION_STATUS_ACTIVE,
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


def _row_to_w03_tracker_item_model(row: dict[str, Any]) -> W03TrackerItemRead:
    return W03TrackerItemRead(
        id=int(row["id"]),
        site=str(row["site"]),
        item_type=str(row["item_type"]),
        item_key=str(row["item_key"]),
        item_name=str(row["item_name"]),
        assignee=row.get("assignee"),
        status=str(row["status"]),
        completion_checked=bool(row.get("completion_checked", False)),
        completion_note=str(row.get("completion_note") or ""),
        due_at=_as_optional_datetime(row.get("due_at")),
        completed_at=_as_optional_datetime(row.get("completed_at")),
        evidence_count=int(row.get("evidence_count") or 0),
        created_by=str(row.get("created_by") or "system"),
        updated_by=str(row.get("updated_by") or "system"),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _row_to_w03_evidence_model(row: dict[str, Any]) -> W03EvidenceRead:
    return W03EvidenceRead(
        id=int(row["id"]),
        tracker_item_id=int(row["tracker_item_id"]),
        site=str(row["site"]),
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


def _adoption_w03_catalog_items(site: str) -> list[dict[str, Any]]:
    payload = _adoption_w03_payload()
    timeline = payload.get("timeline", {})
    default_due_at: datetime | None = None
    end_date_raw = str(timeline.get("end_date") or "")
    if end_date_raw:
        try:
            parsed = datetime.strptime(f"{end_date_raw} 23:59", "%Y-%m-%d %H:%M")
            default_due_at = parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            default_due_at = None

    entries: list[dict[str, Any]] = []
    for item in ADOPTION_W03_KICKOFF_AGENDA:
        entries.append(
            {
                "site": site,
                "item_type": "kickoff_agenda",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("topic", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W03_ROLE_WORKSHOPS:
        entries.append(
            {
                "site": site,
                "item_type": "role_workshop",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("objective", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W03_OFFICE_HOURS:
        entries.append(
            {
                "site": site,
                "item_type": "office_hour",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("focus", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W03_SCHEDULED_EVENTS:
        event_due_at = default_due_at
        try:
            event_due = datetime.strptime(
                f"{str(item.get('date', ''))} {str(item.get('end_time', '23:59'))}",
                "%Y-%m-%d %H:%M",
            )
            event_due_at = event_due.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        entries.append(
            {
                "site": site,
                "item_type": "scheduled_event",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": event_due_at,
            }
        )
    return entries


def _compute_w03_tracker_overview(site: str, rows: list[W03TrackerItemRead]) -> W03TrackerOverviewRead:
    pending_count = sum(1 for row in rows if row.status == W03_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W03_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W03_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W03_TRACKER_STATUS_BLOCKED)
    total = len(rows)
    completion_rate = int(round((done_count / total) * 100)) if total > 0 else 0
    evidence_total = sum(int(row.evidence_count) for row in rows)
    assignee_breakdown: dict[str, int] = {}
    for row in rows:
        assignee = (row.assignee or "unassigned").strip() or "unassigned"
        assignee_breakdown[assignee] = assignee_breakdown.get(assignee, 0) + 1

    return W03TrackerOverviewRead(
        site=site,
        total_items=total,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate,
        evidence_total_count=evidence_total,
        assignee_breakdown=assignee_breakdown,
    )


def _compute_w03_tracker_readiness(
    *,
    site: str,
    rows: list[W03TrackerItemRead],
    checked_at: datetime | None = None,
) -> W03TrackerReadinessRead:
    now = checked_at or datetime.now(timezone.utc)
    total_items = len(rows)
    pending_count = sum(1 for row in rows if row.status == W03_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W03_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W03_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W03_TRACKER_STATUS_BLOCKED)
    completion_rate_percent = int(round((done_count / total_items) * 100)) if total_items > 0 else 0
    evidence_total_count = sum(int(row.evidence_count) for row in rows)

    missing_assignee_count = sum(1 for row in rows if not (row.assignee or "").strip())
    missing_completion_checked_count = sum(1 for row in rows if not bool(row.completion_checked))
    missing_required_evidence_count = sum(
        1
        for row in rows
        if row.item_type in W03_EVIDENCE_REQUIRED_ITEM_TYPES and int(row.evidence_count) <= 0
    )

    blockers: list[str] = []
    if total_items == 0:
        blockers.append("트래커 항목이 없습니다. bootstrap을 먼저 실행하세요.")
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
    if missing_required_evidence_count > 0:
        blockers.append(f"필수 증빙 미업로드(role_workshop) 항목 {missing_required_evidence_count}건이 있습니다.")

    rule_checks = [
        total_items > 0,
        pending_count == 0,
        in_progress_count == 0,
        blocked_count == 0,
        missing_assignee_count == 0,
        missing_completion_checked_count == 0,
        missing_required_evidence_count == 0,
    ]
    readiness_score_percent = int(round((sum(1 for ok in rule_checks if ok) / len(rule_checks)) * 100))
    if total_items > 0:
        readiness_score_percent = max(readiness_score_percent, completion_rate_percent)
    ready = len(blockers) == 0
    if ready:
        readiness_score_percent = 100

    return W03TrackerReadinessRead(
        site=site,
        checked_at=now,
        total_items=total_items,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate_percent,
        evidence_total_count=evidence_total_count,
        missing_assignee_count=missing_assignee_count,
        missing_completion_checked_count=missing_completion_checked_count,
        missing_required_evidence_count=missing_required_evidence_count,
        readiness_score_percent=readiness_score_percent,
        ready=ready,
        blockers=blockers,
    )


def _resolve_w03_site_completion_status(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    if value in W03_SITE_COMPLETION_STATUS_SET:
        return value
    return W03_SITE_COMPLETION_STATUS_ACTIVE


def _row_to_w03_completion_model(
    *,
    site: str,
    readiness: W03TrackerReadinessRead,
    row: dict[str, Any] | None,
) -> W03TrackerCompletionRead:
    if row is None:
        return W03TrackerCompletionRead(
            site=site,
            status=W03_SITE_COMPLETION_STATUS_ACTIVE,
            completion_note="",
            completed_by=None,
            completed_at=None,
            force_used=False,
            last_checked_at=readiness.checked_at,
            readiness=readiness,
        )

    status = _resolve_w03_site_completion_status(row.get("status"))
    completion_note = str(row.get("completion_note") or "")
    completed_by = row.get("completed_by")
    completed_at = _as_optional_datetime(row.get("completed_at"))
    force_used = bool(row.get("force_used", False))
    last_checked_at = _as_optional_datetime(row.get("last_checked_at")) or readiness.checked_at
    return W03TrackerCompletionRead(
        site=site,
        status=status,
        completion_note=completion_note,
        completed_by=completed_by,
        completed_at=completed_at,
        force_used=force_used,
        last_checked_at=last_checked_at,
        readiness=readiness,
    )


def _load_w03_tracker_items_for_site(site: str) -> list[W03TrackerItemRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(adoption_w03_tracker_items)
            .where(adoption_w03_tracker_items.c.site == site)
            .order_by(
                adoption_w03_tracker_items.c.item_type.asc(),
                adoption_w03_tracker_items.c.item_key.asc(),
                adoption_w03_tracker_items.c.id.asc(),
            )
        ).mappings().all()
    return [_row_to_w03_tracker_item_model(row) for row in rows]


def _reset_w03_completion_if_closed(
    *,
    conn: Any,
    site: str,
    actor_username: str,
    checked_at: datetime,
    reason: str,
) -> None:
    row = conn.execute(
        select(adoption_w03_site_runs.c.status)
        .where(adoption_w03_site_runs.c.site == site)
        .limit(1)
    ).mappings().first()
    if row is None:
        return
    status = _resolve_w03_site_completion_status(row.get("status"))
    if status == W03_SITE_COMPLETION_STATUS_ACTIVE:
        return
    conn.execute(
        update(adoption_w03_site_runs)
        .where(adoption_w03_site_runs.c.site == site)
        .values(
            status=W03_SITE_COMPLETION_STATUS_ACTIVE,
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


def _row_to_w04_tracker_item_model(row: dict[str, Any]) -> W04TrackerItemRead:
    return W04TrackerItemRead(
        id=int(row["id"]),
        site=str(row["site"]),
        item_type=str(row["item_type"]),
        item_key=str(row["item_key"]),
        item_name=str(row["item_name"]),
        assignee=row.get("assignee"),
        status=str(row["status"]),
        completion_checked=bool(row.get("completion_checked", False)),
        completion_note=str(row.get("completion_note") or ""),
        due_at=_as_optional_datetime(row.get("due_at")),
        completed_at=_as_optional_datetime(row.get("completed_at")),
        evidence_count=int(row.get("evidence_count") or 0),
        created_by=str(row.get("created_by") or "system"),
        updated_by=str(row.get("updated_by") or "system"),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _row_to_w04_evidence_model(row: dict[str, Any]) -> W04EvidenceRead:
    return W04EvidenceRead(
        id=int(row["id"]),
        tracker_item_id=int(row["tracker_item_id"]),
        site=str(row["site"]),
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


def _adoption_w04_catalog_items(site: str) -> list[dict[str, Any]]:
    payload = _adoption_w04_payload()
    timeline = payload.get("timeline", {})
    default_due_at: datetime | None = None
    end_date_raw = str(timeline.get("end_date") or "")
    if end_date_raw:
        try:
            parsed = datetime.strptime(f"{end_date_raw} 23:59", "%Y-%m-%d %H:%M")
            default_due_at = parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            default_due_at = None

    entries: list[dict[str, Any]] = []
    for item in ADOPTION_W04_COACHING_ACTIONS:
        entries.append(
            {
                "site": site,
                "item_type": "coaching_action",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("action", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W04_SCHEDULED_EVENTS:
        event_due_at = default_due_at
        try:
            event_due = datetime.strptime(
                f"{str(item.get('date', ''))} {str(item.get('end_time', '23:59'))}",
                "%Y-%m-%d %H:%M",
            )
            event_due_at = event_due.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        entries.append(
            {
                "site": site,
                "item_type": "scheduled_event",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": event_due_at,
            }
        )
    return entries


def _compute_w04_tracker_overview(site: str, rows: list[W04TrackerItemRead]) -> W04TrackerOverviewRead:
    pending_count = sum(1 for row in rows if row.status == W04_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W04_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W04_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W04_TRACKER_STATUS_BLOCKED)
    total = len(rows)
    completion_rate = int(round((done_count / total) * 100)) if total > 0 else 0
    evidence_total = sum(int(row.evidence_count) for row in rows)
    assignee_breakdown: dict[str, int] = {}
    for row in rows:
        assignee = (row.assignee or "unassigned").strip() or "unassigned"
        assignee_breakdown[assignee] = assignee_breakdown.get(assignee, 0) + 1

    return W04TrackerOverviewRead(
        site=site,
        total_items=total,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate,
        evidence_total_count=evidence_total,
        assignee_breakdown=assignee_breakdown,
    )


def _compute_w04_tracker_readiness(
    *,
    site: str,
    rows: list[W04TrackerItemRead],
    checked_at: datetime | None = None,
) -> W04TrackerReadinessRead:
    now = checked_at or datetime.now(timezone.utc)
    total_items = len(rows)
    pending_count = sum(1 for row in rows if row.status == W04_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W04_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W04_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W04_TRACKER_STATUS_BLOCKED)
    completion_rate_percent = int(round((done_count / total_items) * 100)) if total_items > 0 else 0
    evidence_total_count = sum(int(row.evidence_count) for row in rows)

    missing_assignee_count = sum(1 for row in rows if not (row.assignee or "").strip())
    missing_completion_checked_count = sum(1 for row in rows if not bool(row.completion_checked))
    missing_required_evidence_count = sum(
        1
        for row in rows
        if row.item_type in W04_EVIDENCE_REQUIRED_ITEM_TYPES and int(row.evidence_count) <= 0
    )

    blockers: list[str] = []
    if total_items == 0:
        blockers.append("트래커 항목이 없습니다. bootstrap을 먼저 실행하세요.")
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
    if missing_required_evidence_count > 0:
        blockers.append(f"필수 증빙 미업로드(coaching_action) 항목 {missing_required_evidence_count}건이 있습니다.")

    rule_checks = [
        total_items > 0,
        pending_count == 0,
        in_progress_count == 0,
        blocked_count == 0,
        missing_assignee_count == 0,
        missing_completion_checked_count == 0,
        missing_required_evidence_count == 0,
    ]
    readiness_score_percent = int(round((sum(1 for ok in rule_checks if ok) / len(rule_checks)) * 100))
    if total_items > 0:
        readiness_score_percent = max(readiness_score_percent, completion_rate_percent)
    ready = len(blockers) == 0
    if ready:
        readiness_score_percent = 100

    return W04TrackerReadinessRead(
        site=site,
        checked_at=now,
        total_items=total_items,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate_percent,
        evidence_total_count=evidence_total_count,
        missing_assignee_count=missing_assignee_count,
        missing_completion_checked_count=missing_completion_checked_count,
        missing_required_evidence_count=missing_required_evidence_count,
        readiness_score_percent=readiness_score_percent,
        ready=ready,
        blockers=blockers,
    )


def _resolve_w04_site_completion_status(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    if value in W04_SITE_COMPLETION_STATUS_SET:
        return value
    return W04_SITE_COMPLETION_STATUS_ACTIVE


def _row_to_w04_completion_model(
    *,
    site: str,
    readiness: W04TrackerReadinessRead,
    row: dict[str, Any] | None,
) -> W04TrackerCompletionRead:
    if row is None:
        return W04TrackerCompletionRead(
            site=site,
            status=W04_SITE_COMPLETION_STATUS_ACTIVE,
            completion_note="",
            completed_by=None,
            completed_at=None,
            force_used=False,
            last_checked_at=readiness.checked_at,
            readiness=readiness,
        )

    status = _resolve_w04_site_completion_status(row.get("status"))
    completion_note = str(row.get("completion_note") or "")
    completed_by = row.get("completed_by")
    completed_at = _as_optional_datetime(row.get("completed_at"))
    force_used = bool(row.get("force_used", False))
    last_checked_at = _as_optional_datetime(row.get("last_checked_at")) or readiness.checked_at
    return W04TrackerCompletionRead(
        site=site,
        status=status,
        completion_note=completion_note,
        completed_by=completed_by,
        completed_at=completed_at,
        force_used=force_used,
        last_checked_at=last_checked_at,
        readiness=readiness,
    )


def _load_w04_tracker_items_for_site(site: str) -> list[W04TrackerItemRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(adoption_w04_tracker_items)
            .where(adoption_w04_tracker_items.c.site == site)
            .order_by(
                adoption_w04_tracker_items.c.item_type.asc(),
                adoption_w04_tracker_items.c.item_key.asc(),
                adoption_w04_tracker_items.c.id.asc(),
            )
        ).mappings().all()
    return [_row_to_w04_tracker_item_model(row) for row in rows]


def _reset_w04_completion_if_closed(
    *,
    conn: Any,
    site: str,
    actor_username: str,
    checked_at: datetime,
    reason: str,
) -> None:
    row = conn.execute(
        select(adoption_w04_site_runs.c.status)
        .where(adoption_w04_site_runs.c.site == site)
        .limit(1)
    ).mappings().first()
    if row is None:
        return
    status = _resolve_w04_site_completion_status(row.get("status"))
    if status == W04_SITE_COMPLETION_STATUS_ACTIVE:
        return
    conn.execute(
        update(adoption_w04_site_runs)
        .where(adoption_w04_site_runs.c.site == site)
        .values(
            status=W04_SITE_COMPLETION_STATUS_ACTIVE,
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


def _row_to_w07_tracker_item_model(row: dict[str, Any]) -> W07TrackerItemRead:
    return W07TrackerItemRead(
        id=int(row["id"]),
        site=str(row["site"]),
        item_type=str(row["item_type"]),
        item_key=str(row["item_key"]),
        item_name=str(row["item_name"]),
        assignee=row.get("assignee"),
        status=str(row["status"]),
        completion_checked=bool(row.get("completion_checked", False)),
        completion_note=str(row.get("completion_note") or ""),
        due_at=_as_optional_datetime(row.get("due_at")),
        completed_at=_as_optional_datetime(row.get("completed_at")),
        evidence_count=int(row.get("evidence_count") or 0),
        created_by=str(row.get("created_by") or "system"),
        updated_by=str(row.get("updated_by") or "system"),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _row_to_w07_evidence_model(row: dict[str, Any]) -> W07EvidenceRead:
    return W07EvidenceRead(
        id=int(row["id"]),
        tracker_item_id=int(row["tracker_item_id"]),
        site=str(row["site"]),
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


def _adoption_w07_catalog_items(site: str) -> list[dict[str, Any]]:
    payload = _adoption_w07_payload()
    timeline = payload.get("timeline", {})
    default_due_at: datetime | None = None
    end_date_raw = str(timeline.get("end_date") or "")
    if end_date_raw:
        try:
            parsed = datetime.strptime(f"{end_date_raw} 23:59", "%Y-%m-%d %H:%M")
            default_due_at = parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            default_due_at = None

    entries: list[dict[str, Any]] = []
    for item in ADOPTION_W07_SLA_CHECKLIST:
        entries.append(
            {
                "site": site,
                "item_type": "sla_checklist",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("control", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W07_COACHING_PLAYS:
        entries.append(
            {
                "site": site,
                "item_type": "coaching_play",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("play", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W07_SCHEDULED_EVENTS:
        event_due_at = default_due_at
        try:
            event_due = datetime.strptime(
                f"{str(item.get('date', ''))} {str(item.get('end_time', '23:59'))}",
                "%Y-%m-%d %H:%M",
            )
            event_due_at = event_due.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        entries.append(
            {
                "site": site,
                "item_type": "scheduled_event",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": event_due_at,
            }
        )
    return entries


def _compute_w07_tracker_overview(site: str, rows: list[W07TrackerItemRead]) -> W07TrackerOverviewRead:
    pending_count = sum(1 for row in rows if row.status == W07_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W07_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W07_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W07_TRACKER_STATUS_BLOCKED)
    total = len(rows)
    completion_rate = int(round((done_count / total) * 100)) if total > 0 else 0
    evidence_total = sum(int(row.evidence_count) for row in rows)
    assignee_breakdown: dict[str, int] = {}
    for row in rows:
        assignee = (row.assignee or "unassigned").strip() or "unassigned"
        assignee_breakdown[assignee] = assignee_breakdown.get(assignee, 0) + 1

    return W07TrackerOverviewRead(
        site=site,
        total_items=total,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate,
        evidence_total_count=evidence_total,
        assignee_breakdown=assignee_breakdown,
    )


def _compute_w07_tracker_readiness(
    *,
    site: str,
    rows: list[W07TrackerItemRead],
    checked_at: datetime | None = None,
) -> W07TrackerReadinessRead:
    now = checked_at or datetime.now(timezone.utc)
    total_items = len(rows)
    pending_count = sum(1 for row in rows if row.status == W07_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W07_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W07_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W07_TRACKER_STATUS_BLOCKED)
    completion_rate_percent = int(round((done_count / total_items) * 100)) if total_items > 0 else 0
    evidence_total_count = sum(int(row.evidence_count) for row in rows)

    missing_assignee_count = sum(1 for row in rows if not (row.assignee or "").strip())
    missing_completion_checked_count = sum(1 for row in rows if not bool(row.completion_checked))
    missing_required_evidence_count = sum(
        1 for row in rows if row.item_type in W07_EVIDENCE_REQUIRED_ITEM_TYPES and int(row.evidence_count) <= 0
    )

    blockers: list[str] = []
    if total_items == 0:
        blockers.append("트래커 항목이 없습니다. bootstrap을 먼저 실행하세요.")
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
    if missing_required_evidence_count > 0:
        blockers.append(f"필수 증빙 미업로드(sla_checklist/coaching_play) 항목 {missing_required_evidence_count}건이 있습니다.")

    rule_checks = [
        total_items > 0,
        pending_count == 0,
        in_progress_count == 0,
        blocked_count == 0,
        missing_assignee_count == 0,
        missing_completion_checked_count == 0,
        missing_required_evidence_count == 0,
    ]
    readiness_score_percent = int(round((sum(1 for ok in rule_checks if ok) / len(rule_checks)) * 100))
    if total_items > 0:
        readiness_score_percent = max(readiness_score_percent, completion_rate_percent)
    ready = len(blockers) == 0
    if ready:
        readiness_score_percent = 100

    return W07TrackerReadinessRead(
        site=site,
        checked_at=now,
        total_items=total_items,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate_percent,
        evidence_total_count=evidence_total_count,
        missing_assignee_count=missing_assignee_count,
        missing_completion_checked_count=missing_completion_checked_count,
        missing_required_evidence_count=missing_required_evidence_count,
        readiness_score_percent=readiness_score_percent,
        ready=ready,
        blockers=blockers,
    )


def _resolve_w07_site_completion_status(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    if value in W07_SITE_COMPLETION_STATUS_SET:
        return value
    return W07_SITE_COMPLETION_STATUS_ACTIVE


def _row_to_w07_completion_model(
    *,
    site: str,
    readiness: W07TrackerReadinessRead,
    row: dict[str, Any] | None,
) -> W07TrackerCompletionRead:
    if row is None:
        return W07TrackerCompletionRead(
            site=site,
            status=W07_SITE_COMPLETION_STATUS_ACTIVE,
            completion_note="",
            completed_by=None,
            completed_at=None,
            force_used=False,
            last_checked_at=readiness.checked_at,
            readiness=readiness,
        )

    status = _resolve_w07_site_completion_status(row.get("status"))
    completion_note = str(row.get("completion_note") or "")
    completed_by = row.get("completed_by")
    completed_at = _as_optional_datetime(row.get("completed_at"))
    force_used = bool(row.get("force_used", False))
    last_checked_at = _as_optional_datetime(row.get("last_checked_at")) or readiness.checked_at
    return W07TrackerCompletionRead(
        site=site,
        status=status,
        completion_note=completion_note,
        completed_by=completed_by,
        completed_at=completed_at,
        force_used=force_used,
        last_checked_at=last_checked_at,
        readiness=readiness,
    )


def _load_w07_tracker_items_for_site(site: str) -> list[W07TrackerItemRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(adoption_w07_tracker_items)
            .where(adoption_w07_tracker_items.c.site == site)
            .order_by(
                adoption_w07_tracker_items.c.item_type.asc(),
                adoption_w07_tracker_items.c.item_key.asc(),
                adoption_w07_tracker_items.c.id.asc(),
            )
        ).mappings().all()
    return [_row_to_w07_tracker_item_model(row) for row in rows]


def _reset_w07_completion_if_closed(
    *,
    conn: Any,
    site: str,
    actor_username: str,
    checked_at: datetime,
    reason: str,
) -> None:
    row = conn.execute(
        select(adoption_w07_site_runs.c.status)
        .where(adoption_w07_site_runs.c.site == site)
        .limit(1)
    ).mappings().first()
    if row is None:
        return
    status = _resolve_w07_site_completion_status(row.get("status"))
    if status == W07_SITE_COMPLETION_STATUS_ACTIVE:
        return
    conn.execute(
        update(adoption_w07_site_runs)
        .where(adoption_w07_site_runs.c.site == site)
        .values(
            status=W07_SITE_COMPLETION_STATUS_ACTIVE,
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


def _row_to_w09_tracker_item_model(row: dict[str, Any]) -> W09TrackerItemRead:
    return W09TrackerItemRead(
        id=int(row["id"]),
        site=str(row["site"]),
        item_type=str(row["item_type"]),
        item_key=str(row["item_key"]),
        item_name=str(row["item_name"]),
        assignee=row.get("assignee"),
        status=str(row["status"]),
        completion_checked=bool(row.get("completion_checked", False)),
        completion_note=str(row.get("completion_note") or ""),
        due_at=_as_optional_datetime(row.get("due_at")),
        completed_at=_as_optional_datetime(row.get("completed_at")),
        evidence_count=int(row.get("evidence_count") or 0),
        created_by=str(row.get("created_by") or "system"),
        updated_by=str(row.get("updated_by") or "system"),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _row_to_w09_evidence_model(row: dict[str, Any]) -> W09EvidenceRead:
    return W09EvidenceRead(
        id=int(row["id"]),
        tracker_item_id=int(row["tracker_item_id"]),
        site=str(row["site"]),
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


def _adoption_w09_catalog_items(site: str) -> list[dict[str, Any]]:
    payload = _adoption_w09_payload()
    timeline = payload.get("timeline", {})
    default_due_at: datetime | None = None
    end_date_raw = str(timeline.get("end_date") or "")
    if end_date_raw:
        try:
            parsed = datetime.strptime(f"{end_date_raw} 23:59", "%Y-%m-%d %H:%M")
            default_due_at = parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            default_due_at = None

    entries: list[dict[str, Any]] = []
    for item in ADOPTION_W09_KPI_THRESHOLD_MATRIX:
        entries.append(
            {
                "site": site,
                "item_type": "kpi_threshold",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("kpi_name", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W09_ESCALATION_MAP:
        entries.append(
            {
                "site": site,
                "item_type": "kpi_escalation",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("action", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W09_SCHEDULED_EVENTS:
        event_due_at = default_due_at
        try:
            event_due = datetime.strptime(
                f"{str(item.get('date', ''))} {str(item.get('end_time', '23:59'))}",
                "%Y-%m-%d %H:%M",
            )
            event_due_at = event_due.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        entries.append(
            {
                "site": site,
                "item_type": "scheduled_event",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": event_due_at,
            }
        )
    return entries


def _compute_w09_tracker_overview(site: str, rows: list[W09TrackerItemRead]) -> W09TrackerOverviewRead:
    pending_count = sum(1 for row in rows if row.status == W09_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W09_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W09_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W09_TRACKER_STATUS_BLOCKED)
    total = len(rows)
    completion_rate = int(round((done_count / total) * 100)) if total > 0 else 0
    evidence_total = sum(int(row.evidence_count) for row in rows)
    assignee_breakdown: dict[str, int] = {}
    for row in rows:
        assignee = (row.assignee or "unassigned").strip() or "unassigned"
        assignee_breakdown[assignee] = assignee_breakdown.get(assignee, 0) + 1

    return W09TrackerOverviewRead(
        site=site,
        total_items=total,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate,
        evidence_total_count=evidence_total,
        assignee_breakdown=assignee_breakdown,
    )


def _compute_w09_tracker_readiness(
    *,
    site: str,
    rows: list[W09TrackerItemRead],
    checked_at: datetime | None = None,
) -> W09TrackerReadinessRead:
    now = checked_at or datetime.now(timezone.utc)
    total_items = len(rows)
    pending_count = sum(1 for row in rows if row.status == W09_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W09_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W09_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W09_TRACKER_STATUS_BLOCKED)
    completion_rate_percent = int(round((done_count / total_items) * 100)) if total_items > 0 else 0
    evidence_total_count = sum(int(row.evidence_count) for row in rows)

    missing_assignee_count = sum(1 for row in rows if not (row.assignee or "").strip())
    missing_completion_checked_count = sum(1 for row in rows if not bool(row.completion_checked))
    missing_required_evidence_count = sum(
        1 for row in rows if row.item_type in W09_EVIDENCE_REQUIRED_ITEM_TYPES and int(row.evidence_count) <= 0
    )

    blockers: list[str] = []
    if total_items == 0:
        blockers.append("트래커 항목이 없습니다. bootstrap을 먼저 실행하세요.")
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
    if missing_required_evidence_count > 0:
        blockers.append(
            f"필수 증빙 미업로드(kpi_threshold/kpi_escalation) 항목 {missing_required_evidence_count}건이 있습니다."
        )

    rule_checks = [
        total_items > 0,
        pending_count == 0,
        in_progress_count == 0,
        blocked_count == 0,
        missing_assignee_count == 0,
        missing_completion_checked_count == 0,
        missing_required_evidence_count == 0,
    ]
    readiness_score_percent = int(round((sum(1 for ok in rule_checks if ok) / len(rule_checks)) * 100))
    if total_items > 0:
        readiness_score_percent = max(readiness_score_percent, completion_rate_percent)
    ready = len(blockers) == 0
    if ready:
        readiness_score_percent = 100

    return W09TrackerReadinessRead(
        site=site,
        checked_at=now,
        total_items=total_items,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate_percent,
        evidence_total_count=evidence_total_count,
        missing_assignee_count=missing_assignee_count,
        missing_completion_checked_count=missing_completion_checked_count,
        missing_required_evidence_count=missing_required_evidence_count,
        readiness_score_percent=readiness_score_percent,
        ready=ready,
        blockers=blockers,
    )


def _resolve_w09_site_completion_status(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    if value in W09_SITE_COMPLETION_STATUS_SET:
        return value
    return W09_SITE_COMPLETION_STATUS_ACTIVE


def _row_to_w09_completion_model(
    *,
    site: str,
    readiness: W09TrackerReadinessRead,
    row: dict[str, Any] | None,
) -> W09TrackerCompletionRead:
    if row is None:
        return W09TrackerCompletionRead(
            site=site,
            status=W09_SITE_COMPLETION_STATUS_ACTIVE,
            completion_note="",
            completed_by=None,
            completed_at=None,
            force_used=False,
            last_checked_at=readiness.checked_at,
            readiness=readiness,
        )

    status = _resolve_w09_site_completion_status(row.get("status"))
    completion_note = str(row.get("completion_note") or "")
    completed_by = row.get("completed_by")
    completed_at = _as_optional_datetime(row.get("completed_at"))
    force_used = bool(row.get("force_used", False))
    last_checked_at = _as_optional_datetime(row.get("last_checked_at")) or readiness.checked_at
    return W09TrackerCompletionRead(
        site=site,
        status=status,
        completion_note=completion_note,
        completed_by=completed_by,
        completed_at=completed_at,
        force_used=force_used,
        last_checked_at=last_checked_at,
        readiness=readiness,
    )


def _load_w09_tracker_items_for_site(site: str) -> list[W09TrackerItemRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(adoption_w09_tracker_items)
            .where(adoption_w09_tracker_items.c.site == site)
            .order_by(
                adoption_w09_tracker_items.c.item_type.asc(),
                adoption_w09_tracker_items.c.item_key.asc(),
                adoption_w09_tracker_items.c.id.asc(),
            )
        ).mappings().all()
    return [_row_to_w09_tracker_item_model(row) for row in rows]


def _reset_w09_completion_if_closed(
    *,
    conn: Any,
    site: str,
    actor_username: str,
    checked_at: datetime,
    reason: str,
) -> None:
    row = conn.execute(
        select(adoption_w09_site_runs.c.status)
        .where(adoption_w09_site_runs.c.site == site)
        .limit(1)
    ).mappings().first()
    if row is None:
        return
    status = _resolve_w09_site_completion_status(row.get("status"))
    if status == W09_SITE_COMPLETION_STATUS_ACTIVE:
        return
    conn.execute(
        update(adoption_w09_site_runs)
        .where(adoption_w09_site_runs.c.site == site)
        .values(
            status=W09_SITE_COMPLETION_STATUS_ACTIVE,
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


def _row_to_w10_tracker_item_model(row: dict[str, Any]) -> W10TrackerItemRead:
    return W10TrackerItemRead(
        id=int(row["id"]),
        site=str(row["site"]),
        item_type=str(row["item_type"]),
        item_key=str(row["item_key"]),
        item_name=str(row["item_name"]),
        assignee=row.get("assignee"),
        status=str(row.get("status") or W10_TRACKER_STATUS_PENDING),
        completion_checked=bool(row.get("completion_checked", False)),
        completion_note=str(row.get("completion_note") or ""),
        due_at=_as_optional_datetime(row.get("due_at")),
        completed_at=_as_optional_datetime(row.get("completed_at")),
        evidence_count=int(row.get("evidence_count") or 0),
        created_by=str(row.get("created_by") or "system"),
        updated_by=str(row.get("updated_by") or "system"),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _row_to_w10_evidence_model(row: dict[str, Any]) -> W10EvidenceRead:
    return W10EvidenceRead(
        id=int(row["id"]),
        tracker_item_id=int(row["tracker_item_id"]),
        site=str(row["site"]),
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


def _adoption_w10_catalog_items(site: str) -> list[dict[str, Any]]:
    payload = _adoption_w10_payload()
    timeline = payload.get("timeline", {})
    default_due_at: datetime | None = None
    end_date_raw = str(timeline.get("end_date") or "")
    if end_date_raw:
        try:
            parsed = datetime.strptime(f"{end_date_raw} 23:59", "%Y-%m-%d %H:%M")
            default_due_at = parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            default_due_at = None

    entries: list[dict[str, Any]] = []
    for item in ADOPTION_W10_SELF_SERVE_GUIDES:
        entries.append(
            {
                "site": site,
                "item_type": "self_serve_guide",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W10_TROUBLESHOOTING_RUNBOOK:
        entries.append(
            {
                "site": site,
                "item_type": "troubleshooting_runbook",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("symptom", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W10_SCHEDULED_EVENTS:
        event_due_at = default_due_at
        try:
            event_due = datetime.strptime(
                f"{str(item.get('date', ''))} {str(item.get('end_time', '23:59'))}",
                "%Y-%m-%d %H:%M",
            )
            event_due_at = event_due.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        entries.append(
            {
                "site": site,
                "item_type": "scheduled_event",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": event_due_at,
            }
        )
    return entries


def _compute_w10_tracker_overview(site: str, rows: list[W10TrackerItemRead]) -> W10TrackerOverviewRead:
    pending_count = sum(1 for row in rows if row.status == W10_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W10_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W10_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W10_TRACKER_STATUS_BLOCKED)
    total = len(rows)
    completion_rate = int(round((done_count / total) * 100)) if total > 0 else 0
    evidence_total = sum(int(row.evidence_count) for row in rows)
    assignee_breakdown: dict[str, int] = {}
    for row in rows:
        assignee = (row.assignee or "unassigned").strip() or "unassigned"
        assignee_breakdown[assignee] = assignee_breakdown.get(assignee, 0) + 1

    return W10TrackerOverviewRead(
        site=site,
        total_items=total,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate,
        evidence_total_count=evidence_total,
        assignee_breakdown=assignee_breakdown,
    )


def _compute_w10_tracker_readiness(
    *,
    site: str,
    rows: list[W10TrackerItemRead],
    checked_at: datetime | None = None,
) -> W10TrackerReadinessRead:
    now = checked_at or datetime.now(timezone.utc)
    total_items = len(rows)
    pending_count = sum(1 for row in rows if row.status == W10_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W10_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W10_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W10_TRACKER_STATUS_BLOCKED)
    completion_rate_percent = int(round((done_count / total_items) * 100)) if total_items > 0 else 0
    evidence_total_count = sum(int(row.evidence_count) for row in rows)

    missing_assignee_count = sum(1 for row in rows if not (row.assignee or "").strip())
    missing_completion_checked_count = sum(1 for row in rows if not bool(row.completion_checked))
    missing_required_evidence_count = sum(
        1 for row in rows if row.item_type in W10_EVIDENCE_REQUIRED_ITEM_TYPES and int(row.evidence_count) <= 0
    )

    blockers: list[str] = []
    if total_items == 0:
        blockers.append("트래커 항목이 없습니다. bootstrap을 먼저 실행하세요.")
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
    if missing_required_evidence_count > 0:
        blockers.append(
            f"필수 증빙 미업로드(self_serve_guide/troubleshooting_runbook) 항목 {missing_required_evidence_count}건이 있습니다."
        )

    rule_checks = [
        total_items > 0,
        pending_count == 0,
        in_progress_count == 0,
        blocked_count == 0,
        missing_assignee_count == 0,
        missing_completion_checked_count == 0,
        missing_required_evidence_count == 0,
    ]
    readiness_score_percent = int(round((sum(1 for ok in rule_checks if ok) / len(rule_checks)) * 100))
    if total_items > 0:
        readiness_score_percent = max(readiness_score_percent, completion_rate_percent)
    ready = len(blockers) == 0
    if ready:
        readiness_score_percent = 100

    return W10TrackerReadinessRead(
        site=site,
        checked_at=now,
        total_items=total_items,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate_percent,
        evidence_total_count=evidence_total_count,
        missing_assignee_count=missing_assignee_count,
        missing_completion_checked_count=missing_completion_checked_count,
        missing_required_evidence_count=missing_required_evidence_count,
        readiness_score_percent=readiness_score_percent,
        ready=ready,
        blockers=blockers,
    )


def _resolve_w10_site_completion_status(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    if value in W10_SITE_COMPLETION_STATUS_SET:
        return value
    return W10_SITE_COMPLETION_STATUS_ACTIVE


def _row_to_w10_completion_model(
    *,
    site: str,
    readiness: W10TrackerReadinessRead,
    row: dict[str, Any] | None,
) -> W10TrackerCompletionRead:
    if row is None:
        return W10TrackerCompletionRead(
            site=site,
            status=W10_SITE_COMPLETION_STATUS_ACTIVE,
            completion_note="",
            completed_by=None,
            completed_at=None,
            force_used=False,
            last_checked_at=readiness.checked_at,
            readiness=readiness,
        )

    status = _resolve_w10_site_completion_status(row.get("status"))
    completion_note = str(row.get("completion_note") or "")
    completed_by = row.get("completed_by")
    completed_at = _as_optional_datetime(row.get("completed_at"))
    force_used = bool(row.get("force_used", False))
    last_checked_at = _as_optional_datetime(row.get("last_checked_at")) or readiness.checked_at
    return W10TrackerCompletionRead(
        site=site,
        status=status,
        completion_note=completion_note,
        completed_by=completed_by,
        completed_at=completed_at,
        force_used=force_used,
        last_checked_at=last_checked_at,
        readiness=readiness,
    )


def _load_w10_tracker_items_for_site(site: str) -> list[W10TrackerItemRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(adoption_w10_tracker_items)
            .where(adoption_w10_tracker_items.c.site == site)
            .order_by(
                adoption_w10_tracker_items.c.item_type.asc(),
                adoption_w10_tracker_items.c.item_key.asc(),
                adoption_w10_tracker_items.c.id.asc(),
            )
        ).mappings().all()
    return [_row_to_w10_tracker_item_model(row) for row in rows]


def _reset_w10_completion_if_closed(
    *,
    conn: Any,
    site: str,
    actor_username: str,
    checked_at: datetime,
    reason: str,
) -> None:
    row = conn.execute(
        select(adoption_w10_site_runs.c.status)
        .where(adoption_w10_site_runs.c.site == site)
        .limit(1)
    ).mappings().first()
    if row is None:
        return
    status = _resolve_w10_site_completion_status(row.get("status"))
    if status == W10_SITE_COMPLETION_STATUS_ACTIVE:
        return
    conn.execute(
        update(adoption_w10_site_runs)
        .where(adoption_w10_site_runs.c.site == site)
        .values(
            status=W10_SITE_COMPLETION_STATUS_ACTIVE,
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



def _row_to_w11_tracker_item_model(row: dict[str, Any]) -> W11TrackerItemRead:
    return W11TrackerItemRead(
        id=int(row["id"]),
        site=str(row["site"]),
        item_type=str(row["item_type"]),
        item_key=str(row["item_key"]),
        item_name=str(row["item_name"]),
        assignee=row.get("assignee"),
        status=str(row.get("status") or W11_TRACKER_STATUS_PENDING),
        completion_checked=bool(row.get("completion_checked", False)),
        completion_note=str(row.get("completion_note") or ""),
        due_at=_as_optional_datetime(row.get("due_at")),
        completed_at=_as_optional_datetime(row.get("completed_at")),
        evidence_count=int(row.get("evidence_count") or 0),
        created_by=str(row.get("created_by") or "system"),
        updated_by=str(row.get("updated_by") or "system"),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _row_to_w11_evidence_model(row: dict[str, Any]) -> W11EvidenceRead:
    return W11EvidenceRead(
        id=int(row["id"]),
        tracker_item_id=int(row["tracker_item_id"]),
        site=str(row["site"]),
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


def _adoption_w11_catalog_items(site: str) -> list[dict[str, Any]]:
    payload = _adoption_w11_payload()
    timeline = payload.get("timeline", {})
    default_due_at: datetime | None = None
    end_date_raw = str(timeline.get("end_date") or "")
    if end_date_raw:
        try:
            parsed = datetime.strptime(f"{end_date_raw} 23:59", "%Y-%m-%d %H:%M")
            default_due_at = parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            default_due_at = None

    entries: list[dict[str, Any]] = []
    for item in ADOPTION_W11_SELF_SERVE_GUIDES:
        entries.append(
            {
                "site": site,
                "item_type": "self_serve_guide",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W11_TROUBLESHOOTING_RUNBOOK:
        entries.append(
            {
                "site": site,
                "item_type": "troubleshooting_runbook",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("symptom", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W11_SCHEDULED_EVENTS:
        event_due_at = default_due_at
        try:
            event_due = datetime.strptime(
                f"{str(item.get('date', ''))} {str(item.get('end_time', '23:59'))}",
                "%Y-%m-%d %H:%M",
            )
            event_due_at = event_due.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        entries.append(
            {
                "site": site,
                "item_type": "scheduled_event",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": event_due_at,
            }
        )
    return entries


def _compute_w11_tracker_overview(site: str, rows: list[W11TrackerItemRead]) -> W11TrackerOverviewRead:
    pending_count = sum(1 for row in rows if row.status == W11_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W11_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W11_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W11_TRACKER_STATUS_BLOCKED)
    total = len(rows)
    completion_rate = int(round((done_count / total) * 100)) if total > 0 else 0
    evidence_total = sum(int(row.evidence_count) for row in rows)
    assignee_breakdown: dict[str, int] = {}
    for row in rows:
        assignee = (row.assignee or "unassigned").strip() or "unassigned"
        assignee_breakdown[assignee] = assignee_breakdown.get(assignee, 0) + 1

    return W11TrackerOverviewRead(
        site=site,
        total_items=total,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate,
        evidence_total_count=evidence_total,
        assignee_breakdown=assignee_breakdown,
    )


def _compute_w11_tracker_readiness(
    *,
    site: str,
    rows: list[W11TrackerItemRead],
    checked_at: datetime | None = None,
) -> W11TrackerReadinessRead:
    now = checked_at or datetime.now(timezone.utc)
    total_items = len(rows)
    pending_count = sum(1 for row in rows if row.status == W11_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W11_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W11_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W11_TRACKER_STATUS_BLOCKED)
    completion_rate_percent = int(round((done_count / total_items) * 100)) if total_items > 0 else 0
    evidence_total_count = sum(int(row.evidence_count) for row in rows)

    missing_assignee_count = sum(1 for row in rows if not (row.assignee or "").strip())
    missing_completion_checked_count = sum(1 for row in rows if not bool(row.completion_checked))
    missing_required_evidence_count = sum(
        1 for row in rows if row.item_type in W11_EVIDENCE_REQUIRED_ITEM_TYPES and int(row.evidence_count) <= 0
    )

    blockers: list[str] = []
    if total_items == 0:
        blockers.append("트래커 항목이 없습니다. bootstrap을 먼저 실행하세요.")
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
    if missing_required_evidence_count > 0:
        blockers.append(
            f"필수 증빙 미업로드(self_serve_guide/troubleshooting_runbook) 항목 {missing_required_evidence_count}건이 있습니다."
        )

    rule_checks = [
        total_items > 0,
        pending_count == 0,
        in_progress_count == 0,
        blocked_count == 0,
        missing_assignee_count == 0,
        missing_completion_checked_count == 0,
        missing_required_evidence_count == 0,
    ]
    readiness_score_percent = int(round((sum(1 for ok in rule_checks if ok) / len(rule_checks)) * 100))
    if total_items > 0:
        readiness_score_percent = max(readiness_score_percent, completion_rate_percent)
    ready = len(blockers) == 0
    if ready:
        readiness_score_percent = 100

    return W11TrackerReadinessRead(
        site=site,
        checked_at=now,
        total_items=total_items,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate_percent,
        evidence_total_count=evidence_total_count,
        missing_assignee_count=missing_assignee_count,
        missing_completion_checked_count=missing_completion_checked_count,
        missing_required_evidence_count=missing_required_evidence_count,
        readiness_score_percent=readiness_score_percent,
        ready=ready,
        blockers=blockers,
    )


def _resolve_w11_site_completion_status(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    if value in W11_SITE_COMPLETION_STATUS_SET:
        return value
    return W11_SITE_COMPLETION_STATUS_ACTIVE


def _row_to_w11_completion_model(
    *,
    site: str,
    readiness: W11TrackerReadinessRead,
    row: dict[str, Any] | None,
) -> W11TrackerCompletionRead:
    if row is None:
        return W11TrackerCompletionRead(
            site=site,
            status=W11_SITE_COMPLETION_STATUS_ACTIVE,
            completion_note="",
            completed_by=None,
            completed_at=None,
            force_used=False,
            last_checked_at=readiness.checked_at,
            readiness=readiness,
        )

    status = _resolve_w11_site_completion_status(row.get("status"))
    completion_note = str(row.get("completion_note") or "")
    completed_by = row.get("completed_by")
    completed_at = _as_optional_datetime(row.get("completed_at"))
    force_used = bool(row.get("force_used", False))
    last_checked_at = _as_optional_datetime(row.get("last_checked_at")) or readiness.checked_at
    return W11TrackerCompletionRead(
        site=site,
        status=status,
        completion_note=completion_note,
        completed_by=completed_by,
        completed_at=completed_at,
        force_used=force_used,
        last_checked_at=last_checked_at,
        readiness=readiness,
    )


def _load_w11_tracker_items_for_site(site: str) -> list[W11TrackerItemRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(adoption_w11_tracker_items)
            .where(adoption_w11_tracker_items.c.site == site)
            .order_by(
                adoption_w11_tracker_items.c.item_type.asc(),
                adoption_w11_tracker_items.c.item_key.asc(),
                adoption_w11_tracker_items.c.id.asc(),
            )
        ).mappings().all()
    return [_row_to_w11_tracker_item_model(row) for row in rows]


def _reset_w11_completion_if_closed(
    *,
    conn: Any,
    site: str,
    actor_username: str,
    checked_at: datetime,
    reason: str,
) -> None:
    row = conn.execute(
        select(adoption_w11_site_runs.c.status)
        .where(adoption_w11_site_runs.c.site == site)
        .limit(1)
    ).mappings().first()
    if row is None:
        return
    status = _resolve_w11_site_completion_status(row.get("status"))
    if status == W11_SITE_COMPLETION_STATUS_ACTIVE:
        return
    conn.execute(
        update(adoption_w11_site_runs)
        .where(adoption_w11_site_runs.c.site == site)
        .values(
            status=W11_SITE_COMPLETION_STATUS_ACTIVE,
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



def _row_to_w12_tracker_item_model(row: dict[str, Any]) -> W12TrackerItemRead:
    return W12TrackerItemRead(
        id=int(row["id"]),
        site=str(row["site"]),
        item_type=str(row["item_type"]),
        item_key=str(row["item_key"]),
        item_name=str(row["item_name"]),
        assignee=row.get("assignee"),
        status=str(row.get("status") or W12_TRACKER_STATUS_PENDING),
        completion_checked=bool(row.get("completion_checked", False)),
        completion_note=str(row.get("completion_note") or ""),
        due_at=_as_optional_datetime(row.get("due_at")),
        completed_at=_as_optional_datetime(row.get("completed_at")),
        evidence_count=int(row.get("evidence_count") or 0),
        created_by=str(row.get("created_by") or "system"),
        updated_by=str(row.get("updated_by") or "system"),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _row_to_w12_evidence_model(row: dict[str, Any]) -> W12EvidenceRead:
    return W12EvidenceRead(
        id=int(row["id"]),
        tracker_item_id=int(row["tracker_item_id"]),
        site=str(row["site"]),
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


def _adoption_w12_catalog_items(site: str) -> list[dict[str, Any]]:
    payload = _adoption_w12_payload()
    timeline = payload.get("timeline", {})
    default_due_at: datetime | None = None
    end_date_raw = str(timeline.get("end_date") or "")
    if end_date_raw:
        try:
            parsed = datetime.strptime(f"{end_date_raw} 23:59", "%Y-%m-%d %H:%M")
            default_due_at = parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            default_due_at = None

    entries: list[dict[str, Any]] = []
    for item in ADOPTION_W12_SELF_SERVE_GUIDES:
        entries.append(
            {
                "site": site,
                "item_type": "self_serve_guide",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W12_TROUBLESHOOTING_RUNBOOK:
        entries.append(
            {
                "site": site,
                "item_type": "troubleshooting_runbook",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("symptom", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W12_SCHEDULED_EVENTS:
        event_due_at = default_due_at
        try:
            event_due = datetime.strptime(
                f"{str(item.get('date', ''))} {str(item.get('end_time', '23:59'))}",
                "%Y-%m-%d %H:%M",
            )
            event_due_at = event_due.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        entries.append(
            {
                "site": site,
                "item_type": "scheduled_event",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": event_due_at,
            }
        )
    return entries


def _compute_w12_tracker_overview(site: str, rows: list[W12TrackerItemRead]) -> W12TrackerOverviewRead:
    pending_count = sum(1 for row in rows if row.status == W12_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W12_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W12_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W12_TRACKER_STATUS_BLOCKED)
    total = len(rows)
    completion_rate = int(round((done_count / total) * 100)) if total > 0 else 0
    evidence_total = sum(int(row.evidence_count) for row in rows)
    assignee_breakdown: dict[str, int] = {}
    for row in rows:
        assignee = (row.assignee or "unassigned").strip() or "unassigned"
        assignee_breakdown[assignee] = assignee_breakdown.get(assignee, 0) + 1

    return W12TrackerOverviewRead(
        site=site,
        total_items=total,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate,
        evidence_total_count=evidence_total,
        assignee_breakdown=assignee_breakdown,
    )


def _compute_w12_tracker_readiness(
    *,
    site: str,
    rows: list[W12TrackerItemRead],
    checked_at: datetime | None = None,
) -> W12TrackerReadinessRead:
    now = checked_at or datetime.now(timezone.utc)
    total_items = len(rows)
    pending_count = sum(1 for row in rows if row.status == W12_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W12_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W12_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W12_TRACKER_STATUS_BLOCKED)
    completion_rate_percent = int(round((done_count / total_items) * 100)) if total_items > 0 else 0
    evidence_total_count = sum(int(row.evidence_count) for row in rows)

    missing_assignee_count = sum(1 for row in rows if not (row.assignee or "").strip())
    missing_completion_checked_count = sum(1 for row in rows if not bool(row.completion_checked))
    missing_required_evidence_count = sum(
        1 for row in rows if row.item_type in W12_EVIDENCE_REQUIRED_ITEM_TYPES and int(row.evidence_count) <= 0
    )

    blockers: list[str] = []
    if total_items == 0:
        blockers.append("트래커 항목이 없습니다. bootstrap을 먼저 실행하세요.")
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
    if missing_required_evidence_count > 0:
        blockers.append(
            f"필수 증빙 미업로드(self_serve_guide/troubleshooting_runbook) 항목 {missing_required_evidence_count}건이 있습니다."
        )

    rule_checks = [
        total_items > 0,
        pending_count == 0,
        in_progress_count == 0,
        blocked_count == 0,
        missing_assignee_count == 0,
        missing_completion_checked_count == 0,
        missing_required_evidence_count == 0,
    ]
    readiness_score_percent = int(round((sum(1 for ok in rule_checks if ok) / len(rule_checks)) * 100))
    if total_items > 0:
        readiness_score_percent = max(readiness_score_percent, completion_rate_percent)
    ready = len(blockers) == 0
    if ready:
        readiness_score_percent = 100

    return W12TrackerReadinessRead(
        site=site,
        checked_at=now,
        total_items=total_items,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate_percent,
        evidence_total_count=evidence_total_count,
        missing_assignee_count=missing_assignee_count,
        missing_completion_checked_count=missing_completion_checked_count,
        missing_required_evidence_count=missing_required_evidence_count,
        readiness_score_percent=readiness_score_percent,
        ready=ready,
        blockers=blockers,
    )


def _resolve_w12_site_completion_status(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    if value in W12_SITE_COMPLETION_STATUS_SET:
        return value
    return W12_SITE_COMPLETION_STATUS_ACTIVE


def _row_to_w12_completion_model(
    *,
    site: str,
    readiness: W12TrackerReadinessRead,
    row: dict[str, Any] | None,
) -> W12TrackerCompletionRead:
    if row is None:
        return W12TrackerCompletionRead(
            site=site,
            status=W12_SITE_COMPLETION_STATUS_ACTIVE,
            completion_note="",
            completed_by=None,
            completed_at=None,
            force_used=False,
            last_checked_at=readiness.checked_at,
            readiness=readiness,
        )

    status = _resolve_w12_site_completion_status(row.get("status"))
    completion_note = str(row.get("completion_note") or "")
    completed_by = row.get("completed_by")
    completed_at = _as_optional_datetime(row.get("completed_at"))
    force_used = bool(row.get("force_used", False))
    last_checked_at = _as_optional_datetime(row.get("last_checked_at")) or readiness.checked_at
    return W12TrackerCompletionRead(
        site=site,
        status=status,
        completion_note=completion_note,
        completed_by=completed_by,
        completed_at=completed_at,
        force_used=force_used,
        last_checked_at=last_checked_at,
        readiness=readiness,
    )


def _load_w12_tracker_items_for_site(site: str) -> list[W12TrackerItemRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(adoption_w12_tracker_items)
            .where(adoption_w12_tracker_items.c.site == site)
            .order_by(
                adoption_w12_tracker_items.c.item_type.asc(),
                adoption_w12_tracker_items.c.item_key.asc(),
                adoption_w12_tracker_items.c.id.asc(),
            )
        ).mappings().all()
    return [_row_to_w12_tracker_item_model(row) for row in rows]


def _reset_w12_completion_if_closed(
    *,
    conn: Any,
    site: str,
    actor_username: str,
    checked_at: datetime,
    reason: str,
) -> None:
    row = conn.execute(
        select(adoption_w12_site_runs.c.status)
        .where(adoption_w12_site_runs.c.site == site)
        .limit(1)
    ).mappings().first()
    if row is None:
        return
    status = _resolve_w12_site_completion_status(row.get("status"))
    if status == W12_SITE_COMPLETION_STATUS_ACTIVE:
        return
    conn.execute(
        update(adoption_w12_site_runs)
        .where(adoption_w12_site_runs.c.site == site)
        .values(
            status=W12_SITE_COMPLETION_STATUS_ACTIVE,
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


def _row_to_w13_tracker_item_model(row: dict[str, Any]) -> W13TrackerItemRead:
    return W13TrackerItemRead(
        id=int(row["id"]),
        site=str(row["site"]),
        item_type=str(row["item_type"]),
        item_key=str(row["item_key"]),
        item_name=str(row["item_name"]),
        assignee=row.get("assignee"),
        status=str(row.get("status") or W13_TRACKER_STATUS_PENDING),
        completion_checked=bool(row.get("completion_checked", False)),
        completion_note=str(row.get("completion_note") or ""),
        due_at=_as_optional_datetime(row.get("due_at")),
        completed_at=_as_optional_datetime(row.get("completed_at")),
        evidence_count=int(row.get("evidence_count") or 0),
        created_by=str(row.get("created_by") or "system"),
        updated_by=str(row.get("updated_by") or "system"),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _row_to_w13_evidence_model(row: dict[str, Any]) -> W13EvidenceRead:
    return W13EvidenceRead(
        id=int(row["id"]),
        tracker_item_id=int(row["tracker_item_id"]),
        site=str(row["site"]),
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


def _adoption_w13_catalog_items(site: str) -> list[dict[str, Any]]:
    payload = _adoption_w13_payload()
    timeline = payload.get("timeline", {})
    default_due_at: datetime | None = None
    end_date_raw = str(timeline.get("end_date") or "")
    if end_date_raw:
        try:
            parsed = datetime.strptime(f"{end_date_raw} 23:59", "%Y-%m-%d %H:%M")
            default_due_at = parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            default_due_at = None

    entries: list[dict[str, Any]] = []
    for item in ADOPTION_W13_SELF_SERVE_GUIDES:
        entries.append(
            {
                "site": site,
                "item_type": "self_serve_guide",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W13_TROUBLESHOOTING_RUNBOOK:
        entries.append(
            {
                "site": site,
                "item_type": "troubleshooting_runbook",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("symptom", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W13_SCHEDULED_EVENTS:
        event_due_at = default_due_at
        try:
            event_due = datetime.strptime(
                f"{str(item.get('date', ''))} {str(item.get('end_time', '23:59'))}",
                "%Y-%m-%d %H:%M",
            )
            event_due_at = event_due.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        entries.append(
            {
                "site": site,
                "item_type": "scheduled_event",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": event_due_at,
            }
        )
    return entries


def _compute_w13_tracker_overview(site: str, rows: list[W13TrackerItemRead]) -> W13TrackerOverviewRead:
    pending_count = sum(1 for row in rows if row.status == W13_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W13_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W13_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W13_TRACKER_STATUS_BLOCKED)
    total = len(rows)
    completion_rate = int(round((done_count / total) * 100)) if total > 0 else 0
    evidence_total = sum(int(row.evidence_count) for row in rows)
    assignee_breakdown: dict[str, int] = {}
    for row in rows:
        assignee = (row.assignee or "unassigned").strip() or "unassigned"
        assignee_breakdown[assignee] = assignee_breakdown.get(assignee, 0) + 1

    return W13TrackerOverviewRead(
        site=site,
        total_items=total,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate,
        evidence_total_count=evidence_total,
        assignee_breakdown=assignee_breakdown,
    )


def _compute_w13_tracker_readiness(
    *,
    site: str,
    rows: list[W13TrackerItemRead],
    checked_at: datetime | None = None,
) -> W13TrackerReadinessRead:
    now = checked_at or datetime.now(timezone.utc)
    total_items = len(rows)
    pending_count = sum(1 for row in rows if row.status == W13_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W13_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W13_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W13_TRACKER_STATUS_BLOCKED)
    completion_rate_percent = int(round((done_count / total_items) * 100)) if total_items > 0 else 0
    evidence_total_count = sum(int(row.evidence_count) for row in rows)

    missing_assignee_count = sum(1 for row in rows if not (row.assignee or "").strip())
    missing_completion_checked_count = sum(1 for row in rows if not bool(row.completion_checked))
    missing_required_evidence_count = sum(
        1 for row in rows if row.item_type in W13_EVIDENCE_REQUIRED_ITEM_TYPES and int(row.evidence_count) <= 0
    )

    blockers: list[str] = []
    if total_items == 0:
        blockers.append("트래커 항목이 없습니다. bootstrap을 먼저 실행하세요.")
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
    if missing_required_evidence_count > 0:
        blockers.append(
            f"필수 증빙 미업로드(self_serve_guide/troubleshooting_runbook) 항목 {missing_required_evidence_count}건이 있습니다."
        )

    rule_checks = [
        total_items > 0,
        pending_count == 0,
        in_progress_count == 0,
        blocked_count == 0,
        missing_assignee_count == 0,
        missing_completion_checked_count == 0,
        missing_required_evidence_count == 0,
    ]
    readiness_score_percent = int(round((sum(1 for ok in rule_checks if ok) / len(rule_checks)) * 100))
    if total_items > 0:
        readiness_score_percent = max(readiness_score_percent, completion_rate_percent)
    ready = len(blockers) == 0
    if ready:
        readiness_score_percent = 100

    return W13TrackerReadinessRead(
        site=site,
        checked_at=now,
        total_items=total_items,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate_percent,
        evidence_total_count=evidence_total_count,
        missing_assignee_count=missing_assignee_count,
        missing_completion_checked_count=missing_completion_checked_count,
        missing_required_evidence_count=missing_required_evidence_count,
        readiness_score_percent=readiness_score_percent,
        ready=ready,
        blockers=blockers,
    )


def _resolve_w13_site_completion_status(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    if value in W13_SITE_COMPLETION_STATUS_SET:
        return value
    return W13_SITE_COMPLETION_STATUS_ACTIVE


def _row_to_w13_completion_model(
    *,
    site: str,
    readiness: W13TrackerReadinessRead,
    row: dict[str, Any] | None,
) -> W13TrackerCompletionRead:
    if row is None:
        return W13TrackerCompletionRead(
            site=site,
            status=W13_SITE_COMPLETION_STATUS_ACTIVE,
            completion_note="",
            completed_by=None,
            completed_at=None,
            force_used=False,
            last_checked_at=readiness.checked_at,
            readiness=readiness,
        )

    status = _resolve_w13_site_completion_status(row.get("status"))
    completion_note = str(row.get("completion_note") or "")
    completed_by = row.get("completed_by")
    completed_at = _as_optional_datetime(row.get("completed_at"))
    force_used = bool(row.get("force_used", False))
    last_checked_at = _as_optional_datetime(row.get("last_checked_at")) or readiness.checked_at
    return W13TrackerCompletionRead(
        site=site,
        status=status,
        completion_note=completion_note,
        completed_by=completed_by,
        completed_at=completed_at,
        force_used=force_used,
        last_checked_at=last_checked_at,
        readiness=readiness,
    )


def _load_w13_tracker_items_for_site(site: str) -> list[W13TrackerItemRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(adoption_w13_tracker_items)
            .where(adoption_w13_tracker_items.c.site == site)
            .order_by(
                adoption_w13_tracker_items.c.item_type.asc(),
                adoption_w13_tracker_items.c.item_key.asc(),
                adoption_w13_tracker_items.c.id.asc(),
            )
        ).mappings().all()
    return [_row_to_w13_tracker_item_model(row) for row in rows]


def _reset_w13_completion_if_closed(
    *,
    conn: Any,
    site: str,
    actor_username: str,
    checked_at: datetime,
    reason: str,
) -> None:
    row = conn.execute(
        select(adoption_w13_site_runs.c.status)
        .where(adoption_w13_site_runs.c.site == site)
        .limit(1)
    ).mappings().first()
    if row is None:
        return
    status = _resolve_w13_site_completion_status(row.get("status"))
    if status == W13_SITE_COMPLETION_STATUS_ACTIVE:
        return
    conn.execute(
        update(adoption_w13_site_runs)
        .where(adoption_w13_site_runs.c.site == site)
        .values(
            status=W13_SITE_COMPLETION_STATUS_ACTIVE,
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
def _row_to_w14_tracker_item_model(row: dict[str, Any]) -> W14TrackerItemRead:
    return W14TrackerItemRead(
        id=int(row["id"]),
        site=str(row["site"]),
        item_type=str(row["item_type"]),
        item_key=str(row["item_key"]),
        item_name=str(row["item_name"]),
        assignee=row.get("assignee"),
        status=str(row.get("status") or W14_TRACKER_STATUS_PENDING),
        completion_checked=bool(row.get("completion_checked", False)),
        completion_note=str(row.get("completion_note") or ""),
        due_at=_as_optional_datetime(row.get("due_at")),
        completed_at=_as_optional_datetime(row.get("completed_at")),
        evidence_count=int(row.get("evidence_count") or 0),
        created_by=str(row.get("created_by") or "system"),
        updated_by=str(row.get("updated_by") or "system"),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _row_to_w14_evidence_model(row: dict[str, Any]) -> W14EvidenceRead:
    return W14EvidenceRead(
        id=int(row["id"]),
        tracker_item_id=int(row["tracker_item_id"]),
        site=str(row["site"]),
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


def _adoption_w14_catalog_items(site: str) -> list[dict[str, Any]]:
    payload = _adoption_w14_payload()
    timeline = payload.get("timeline", {})
    default_due_at: datetime | None = None
    end_date_raw = str(timeline.get("end_date") or "")
    if end_date_raw:
        try:
            parsed = datetime.strptime(f"{end_date_raw} 23:59", "%Y-%m-%d %H:%M")
            default_due_at = parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            default_due_at = None

    entries: list[dict[str, Any]] = []
    for item in ADOPTION_W14_SELF_SERVE_GUIDES:
        entries.append(
            {
                "site": site,
                "item_type": "self_serve_guide",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W14_TROUBLESHOOTING_RUNBOOK:
        entries.append(
            {
                "site": site,
                "item_type": "troubleshooting_runbook",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("symptom", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W14_SCHEDULED_EVENTS:
        event_due_at = default_due_at
        try:
            event_due = datetime.strptime(
                f"{str(item.get('date', ''))} {str(item.get('end_time', '23:59'))}",
                "%Y-%m-%d %H:%M",
            )
            event_due_at = event_due.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        entries.append(
            {
                "site": site,
                "item_type": "scheduled_event",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": event_due_at,
            }
        )
    return entries


def _compute_w14_tracker_overview(site: str, rows: list[W14TrackerItemRead]) -> W14TrackerOverviewRead:
    pending_count = sum(1 for row in rows if row.status == W14_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W14_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W14_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W14_TRACKER_STATUS_BLOCKED)
    total = len(rows)
    completion_rate = int(round((done_count / total) * 100)) if total > 0 else 0
    evidence_total = sum(int(row.evidence_count) for row in rows)
    assignee_breakdown: dict[str, int] = {}
    for row in rows:
        assignee = (row.assignee or "unassigned").strip() or "unassigned"
        assignee_breakdown[assignee] = assignee_breakdown.get(assignee, 0) + 1

    return W14TrackerOverviewRead(
        site=site,
        total_items=total,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate,
        evidence_total_count=evidence_total,
        assignee_breakdown=assignee_breakdown,
    )


def _compute_w14_tracker_readiness(
    *,
    site: str,
    rows: list[W14TrackerItemRead],
    checked_at: datetime | None = None,
) -> W14TrackerReadinessRead:
    now = checked_at or datetime.now(timezone.utc)
    total_items = len(rows)
    pending_count = sum(1 for row in rows if row.status == W14_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W14_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W14_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W14_TRACKER_STATUS_BLOCKED)
    completion_rate_percent = int(round((done_count / total_items) * 100)) if total_items > 0 else 0
    evidence_total_count = sum(int(row.evidence_count) for row in rows)

    missing_assignee_count = sum(1 for row in rows if not (row.assignee or "").strip())
    missing_completion_checked_count = sum(1 for row in rows if not bool(row.completion_checked))
    missing_required_evidence_count = sum(
        1 for row in rows if row.item_type in W14_EVIDENCE_REQUIRED_ITEM_TYPES and int(row.evidence_count) <= 0
    )

    blockers: list[str] = []
    if total_items == 0:
        blockers.append("트래커 항목이 없습니다. bootstrap을 먼저 실행하세요.")
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
    if missing_required_evidence_count > 0:
        blockers.append(
            f"필수 증빙 미업로드(self_serve_guide/troubleshooting_runbook) 항목 {missing_required_evidence_count}건이 있습니다."
        )

    rule_checks = [
        total_items > 0,
        pending_count == 0,
        in_progress_count == 0,
        blocked_count == 0,
        missing_assignee_count == 0,
        missing_completion_checked_count == 0,
        missing_required_evidence_count == 0,
    ]
    readiness_score_percent = int(round((sum(1 for ok in rule_checks if ok) / len(rule_checks)) * 100))
    if total_items > 0:
        readiness_score_percent = max(readiness_score_percent, completion_rate_percent)
    ready = len(blockers) == 0
    if ready:
        readiness_score_percent = 100

    return W14TrackerReadinessRead(
        site=site,
        checked_at=now,
        total_items=total_items,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate_percent,
        evidence_total_count=evidence_total_count,
        missing_assignee_count=missing_assignee_count,
        missing_completion_checked_count=missing_completion_checked_count,
        missing_required_evidence_count=missing_required_evidence_count,
        readiness_score_percent=readiness_score_percent,
        ready=ready,
        blockers=blockers,
    )


def _resolve_w14_site_completion_status(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    if value in W14_SITE_COMPLETION_STATUS_SET:
        return value
    return W14_SITE_COMPLETION_STATUS_ACTIVE


def _row_to_w14_completion_model(
    *,
    site: str,
    readiness: W14TrackerReadinessRead,
    row: dict[str, Any] | None,
) -> W14TrackerCompletionRead:
    if row is None:
        return W14TrackerCompletionRead(
            site=site,
            status=W14_SITE_COMPLETION_STATUS_ACTIVE,
            completion_note="",
            completed_by=None,
            completed_at=None,
            force_used=False,
            last_checked_at=readiness.checked_at,
            readiness=readiness,
        )

    status = _resolve_w14_site_completion_status(row.get("status"))
    completion_note = str(row.get("completion_note") or "")
    completed_by = row.get("completed_by")
    completed_at = _as_optional_datetime(row.get("completed_at"))
    force_used = bool(row.get("force_used", False))
    last_checked_at = _as_optional_datetime(row.get("last_checked_at")) or readiness.checked_at
    return W14TrackerCompletionRead(
        site=site,
        status=status,
        completion_note=completion_note,
        completed_by=completed_by,
        completed_at=completed_at,
        force_used=force_used,
        last_checked_at=last_checked_at,
        readiness=readiness,
    )


def _load_w14_tracker_items_for_site(site: str) -> list[W14TrackerItemRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(adoption_w14_tracker_items)
            .where(adoption_w14_tracker_items.c.site == site)
            .order_by(
                adoption_w14_tracker_items.c.item_type.asc(),
                adoption_w14_tracker_items.c.item_key.asc(),
                adoption_w14_tracker_items.c.id.asc(),
            )
        ).mappings().all()
    return [_row_to_w14_tracker_item_model(row) for row in rows]


def _reset_w14_completion_if_closed(
    *,
    conn: Any,
    site: str,
    actor_username: str,
    checked_at: datetime,
    reason: str,
) -> None:
    row = conn.execute(
        select(adoption_w14_site_runs.c.status)
        .where(adoption_w14_site_runs.c.site == site)
        .limit(1)
    ).mappings().first()
    if row is None:
        return
    status = _resolve_w14_site_completion_status(row.get("status"))
    if status == W14_SITE_COMPLETION_STATUS_ACTIVE:
        return
    conn.execute(
        update(adoption_w14_site_runs)
        .where(adoption_w14_site_runs.c.site == site)
        .values(
            status=W14_SITE_COMPLETION_STATUS_ACTIVE,
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


def _row_to_w15_tracker_item_model(row: dict[str, Any]) -> W15TrackerItemRead:
    return W15TrackerItemRead(
        id=int(row["id"]),
        site=str(row["site"]),
        item_type=str(row["item_type"]),
        item_key=str(row["item_key"]),
        item_name=str(row["item_name"]),
        assignee=row.get("assignee"),
        status=str(row.get("status") or W15_TRACKER_STATUS_PENDING),
        completion_checked=bool(row.get("completion_checked", False)),
        completion_note=str(row.get("completion_note") or ""),
        due_at=_as_optional_datetime(row.get("due_at")),
        completed_at=_as_optional_datetime(row.get("completed_at")),
        evidence_count=int(row.get("evidence_count") or 0),
        created_by=str(row.get("created_by") or "system"),
        updated_by=str(row.get("updated_by") or "system"),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _row_to_w15_evidence_model(row: dict[str, Any]) -> W15EvidenceRead:
    return W15EvidenceRead(
        id=int(row["id"]),
        tracker_item_id=int(row["tracker_item_id"]),
        site=str(row["site"]),
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


def _adoption_w15_catalog_items(site: str) -> list[dict[str, Any]]:
    payload = _adoption_w15_payload()
    timeline = payload.get("timeline", {})
    default_due_at: datetime | None = None
    end_date_raw = str(timeline.get("end_date") or "")
    if end_date_raw:
        try:
            parsed = datetime.strptime(f"{end_date_raw} 23:59", "%Y-%m-%d %H:%M")
            default_due_at = parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            default_due_at = None

    entries: list[dict[str, Any]] = []
    for item in ADOPTION_W15_SELF_SERVE_GUIDES:
        entries.append(
            {
                "site": site,
                "item_type": "self_serve_guide",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W15_TROUBLESHOOTING_RUNBOOK:
        entries.append(
            {
                "site": site,
                "item_type": "troubleshooting_runbook",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("symptom", "")),
                "due_at": default_due_at,
            }
        )
    for item in ADOPTION_W15_SCHEDULED_EVENTS:
        event_due_at = default_due_at
        try:
            event_due = datetime.strptime(
                f"{str(item.get('date', ''))} {str(item.get('end_time', '23:59'))}",
                "%Y-%m-%d %H:%M",
            )
            event_due_at = event_due.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        entries.append(
            {
                "site": site,
                "item_type": "scheduled_event",
                "item_key": str(item.get("id", "")),
                "item_name": str(item.get("title", "")),
                "due_at": event_due_at,
            }
        )
    return entries


def _compute_w15_tracker_overview(site: str, rows: list[W15TrackerItemRead]) -> W15TrackerOverviewRead:
    pending_count = sum(1 for row in rows if row.status == W15_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W15_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W15_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W15_TRACKER_STATUS_BLOCKED)
    total = len(rows)
    completion_rate = int(round((done_count / total) * 100)) if total > 0 else 0
    evidence_total = sum(int(row.evidence_count) for row in rows)
    assignee_breakdown: dict[str, int] = {}
    for row in rows:
        assignee = (row.assignee or "unassigned").strip() or "unassigned"
        assignee_breakdown[assignee] = assignee_breakdown.get(assignee, 0) + 1

    return W15TrackerOverviewRead(
        site=site,
        total_items=total,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate,
        evidence_total_count=evidence_total,
        assignee_breakdown=assignee_breakdown,
    )


def _compute_w15_tracker_readiness(
    *,
    site: str,
    rows: list[W15TrackerItemRead],
    checked_at: datetime | None = None,
) -> W15TrackerReadinessRead:
    now = checked_at or datetime.now(timezone.utc)
    total_items = len(rows)
    pending_count = sum(1 for row in rows if row.status == W15_TRACKER_STATUS_PENDING)
    in_progress_count = sum(1 for row in rows if row.status == W15_TRACKER_STATUS_IN_PROGRESS)
    done_count = sum(1 for row in rows if row.status == W15_TRACKER_STATUS_DONE)
    blocked_count = sum(1 for row in rows if row.status == W15_TRACKER_STATUS_BLOCKED)
    completion_rate_percent = int(round((done_count / total_items) * 100)) if total_items > 0 else 0
    evidence_total_count = sum(int(row.evidence_count) for row in rows)

    missing_assignee_count = sum(1 for row in rows if not (row.assignee or "").strip())
    missing_completion_checked_count = sum(1 for row in rows if not bool(row.completion_checked))
    missing_required_evidence_count = sum(
        1 for row in rows if row.item_type in W15_EVIDENCE_REQUIRED_ITEM_TYPES and int(row.evidence_count) <= 0
    )

    blockers: list[str] = []
    if total_items == 0:
        blockers.append("트래커 항목이 없습니다. bootstrap을 먼저 실행하세요.")
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
    if missing_required_evidence_count > 0:
        blockers.append(
            f"필수 증빙 미업로드(self_serve_guide/troubleshooting_runbook) 항목 {missing_required_evidence_count}건이 있습니다."
        )

    rule_checks = [
        total_items > 0,
        pending_count == 0,
        in_progress_count == 0,
        blocked_count == 0,
        missing_assignee_count == 0,
        missing_completion_checked_count == 0,
        missing_required_evidence_count == 0,
    ]
    readiness_score_percent = int(round((sum(1 for ok in rule_checks if ok) / len(rule_checks)) * 100))
    if total_items > 0:
        readiness_score_percent = max(readiness_score_percent, completion_rate_percent)
    ready = len(blockers) == 0
    if ready:
        readiness_score_percent = 100

    return W15TrackerReadinessRead(
        site=site,
        checked_at=now,
        total_items=total_items,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        done_count=done_count,
        blocked_count=blocked_count,
        completion_rate_percent=completion_rate_percent,
        evidence_total_count=evidence_total_count,
        missing_assignee_count=missing_assignee_count,
        missing_completion_checked_count=missing_completion_checked_count,
        missing_required_evidence_count=missing_required_evidence_count,
        readiness_score_percent=readiness_score_percent,
        ready=ready,
        blockers=blockers,
    )


def _resolve_w15_site_completion_status(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    if value in W15_SITE_COMPLETION_STATUS_SET:
        return value
    return W15_SITE_COMPLETION_STATUS_ACTIVE


def _row_to_w15_completion_model(
    *,
    site: str,
    readiness: W15TrackerReadinessRead,
    row: dict[str, Any] | None,
) -> W15TrackerCompletionRead:
    if row is None:
        return W15TrackerCompletionRead(
            site=site,
            status=W15_SITE_COMPLETION_STATUS_ACTIVE,
            completion_note="",
            completed_by=None,
            completed_at=None,
            force_used=False,
            last_checked_at=readiness.checked_at,
            readiness=readiness,
        )

    status = _resolve_w15_site_completion_status(row.get("status"))
    completion_note = str(row.get("completion_note") or "")
    completed_by = row.get("completed_by")
    completed_at = _as_optional_datetime(row.get("completed_at"))
    force_used = bool(row.get("force_used", False))
    last_checked_at = _as_optional_datetime(row.get("last_checked_at")) or readiness.checked_at
    return W15TrackerCompletionRead(
        site=site,
        status=status,
        completion_note=completion_note,
        completed_by=completed_by,
        completed_at=completed_at,
        force_used=force_used,
        last_checked_at=last_checked_at,
        readiness=readiness,
    )


def _load_w15_tracker_items_for_site(site: str) -> list[W15TrackerItemRead]:
    with get_conn() as conn:
        rows = conn.execute(
            select(adoption_w15_tracker_items)
            .where(adoption_w15_tracker_items.c.site == site)
            .order_by(
                adoption_w15_tracker_items.c.item_type.asc(),
                adoption_w15_tracker_items.c.item_key.asc(),
                adoption_w15_tracker_items.c.id.asc(),
            )
        ).mappings().all()
    return [_row_to_w15_tracker_item_model(row) for row in rows]


def _reset_w15_completion_if_closed(
    *,
    conn: Any,
    site: str,
    actor_username: str,
    checked_at: datetime,
    reason: str,
) -> None:
    row = conn.execute(
        select(adoption_w15_site_runs.c.status)
        .where(adoption_w15_site_runs.c.site == site)
        .limit(1)
    ).mappings().first()
    if row is None:
        return
    status = _resolve_w15_site_completion_status(row.get("status"))
    if status == W15_SITE_COMPLETION_STATUS_ACTIVE:
        return
    conn.execute(
        update(adoption_w15_site_runs)
        .where(adoption_w15_site_runs.c.site == site)
        .values(
            status=W15_SITE_COMPLETION_STATUS_ACTIVE,
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
