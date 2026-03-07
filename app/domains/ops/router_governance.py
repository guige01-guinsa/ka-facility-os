"""Governance and control-plane routes extracted from app.main."""

from __future__ import annotations

from app import main as main_module

APIRouter = main_module.APIRouter
globals().update({key: value for key, value in main_module.__dict__.items() if key not in {"router", "ops_router", "admin_router"}})
router = APIRouter(prefix="/api/ops", tags=["ops"])
ops_router = router

@router.get("/job-runs", response_model=list[JobRunRead])
def list_job_runs(
    job_name: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    _: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> list[JobRunRead]:
    stmt = select(job_runs).order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
    if job_name is not None:
        stmt = stmt.where(job_runs.c.job_name == job_name)
    stmt = stmt.limit(limit).offset(offset)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_job_run_model(row) for row in rows]


@router.get("/performance/api-latency")
def get_ops_api_latency_snapshot(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    snapshot = _build_api_latency_snapshot()
    _write_audit_log(
        principal=principal,
        action="ops_api_latency_view",
        resource_type="ops_performance",
        resource_id="api_latency",
        detail={
            "status": snapshot.get("status"),
            "target_count": snapshot.get("target_count"),
            "critical_count": snapshot.get("critical_count"),
            "warning_count": snapshot.get("warning_count"),
            "insufficient_samples_count": snapshot.get("insufficient_samples_count"),
        },
    )
    return snapshot


@router.get("/integrity/evidence-archive")
def get_ops_evidence_archive_integrity(
    sample_per_table: Annotated[int | None, Query(ge=1, le=200)] = None,
    max_issues: Annotated[int | None, Query(ge=1, le=500)] = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    snapshot = _build_evidence_archive_integrity_batch(
        sample_per_table=sample_per_table,
        max_issues=max_issues,
    )
    _write_audit_log(
        principal=principal,
        action="ops_evidence_archive_integrity_view",
        resource_type="ops_integrity",
        resource_id="evidence_archive",
        detail={
            "status": snapshot.get("status"),
            "checked_count": snapshot.get("checked_count"),
            "digest_mismatch_count": snapshot.get("digest_mismatch_count"),
            "issue_count": snapshot.get("issue_count"),
            "sample_per_table": snapshot.get("sample_per_table"),
        },
    )
    return snapshot


@router.get("/deploy/checklist")
def get_ops_deploy_checklist(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    payload = _build_deploy_checklist_payload()
    _write_audit_log(
        principal=principal,
        action="ops_deploy_checklist_view",
        resource_type="ops_deploy",
        resource_id=payload["version"],
        detail={
            "checklist_version": payload["version"],
            "step_count": len(payload.get("steps", [])),
        },
    )
    return payload


def _normalize_smoke_check_status(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if raw in {"ok", "success", "healthy", "pass"}:
        return "ok"
    if raw in {"warning", "warn", "degraded", "skipped"}:
        return "warning" if raw != "skipped" else "skipped"
    if raw in {"critical", "failed", "error", "fatal"}:
        return "critical"
    return "unknown"


def _normalize_deploy_smoke_checks(value: Any) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    if not isinstance(value, list):
        return checks
    for item in value[:50]:
        if not isinstance(item, dict):
            continue
        checks.append(
            {
                "id": str(item.get("id") or "").strip(),
                "status": _normalize_smoke_check_status(item.get("status")),
                "message": str(item.get("message") or "").strip(),
            }
        )
    return checks


def _get_deploy_smoke_check(checks: list[dict[str, str]], check_id: str) -> dict[str, str] | None:
    for item in checks:
        if str(item.get("id") or "") == check_id:
            return item
    return None


@router.post("/deploy/smoke/record")
def post_ops_deploy_smoke_record(
    payload: dict[str, Any],
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    started_at = _as_optional_datetime(payload.get("started_at")) or now
    finished_at = _as_optional_datetime(payload.get("finished_at")) or now
    if finished_at < started_at:
        finished_at = started_at

    raw_status = str(payload.get("status") or "success").strip().lower()
    if raw_status in {"ok", "success", "healthy"}:
        status = "success"
    elif raw_status in {"warning", "warn", "degraded"}:
        status = "warning"
    elif raw_status in {"critical", "failed", "error"}:
        status = "critical"
    else:
        status = "warning"

    checks = _normalize_deploy_smoke_checks(payload.get("checks"))
    checklist_payload = _build_deploy_checklist_payload()
    checklist_policy = checklist_payload.get("policy") if isinstance(checklist_payload.get("policy"), dict) else {}
    checklist_version = str(checklist_payload.get("version") or "")
    checklist_signature = str(checklist_payload.get("signature") or "")
    expected_rollback_reference = str(
        checklist_policy.get("rollback_guide_path") or "docs/W15_MIGRATION_ROLLBACK.md"
    ).replace("\\", "/")
    expected_rollback_exists = bool(checklist_policy.get("rollback_guide_exists", False))
    expected_rollback_sha256 = str(checklist_policy.get("rollback_guide_sha256") or "").strip().lower()
    provided_rollback_reference = str(
        payload.get("rollback_reference") or expected_rollback_reference
    ).replace("\\", "/")
    provided_rollback_sha256 = str(payload.get("rollback_reference_sha256") or "").strip().lower()
    rollback_reference_match = provided_rollback_reference == expected_rollback_reference
    rollback_sha_provided = provided_rollback_sha256 != ""
    rollback_sha_match = (not rollback_sha_provided) or (provided_rollback_sha256 == expected_rollback_sha256)

    runbook_gate_passed = bool(payload.get("runbook_gate_passed", False))
    rollback_ready = bool(payload.get("rollback_ready", False))
    provided_checklist_version = str(payload.get("checklist_version") or checklist_version).strip()
    checklist_version_match = provided_checklist_version == checklist_version
    ui_main_shell_check = _get_deploy_smoke_check(checks, "ui_main_shell")
    ui_main_shell_checked = ui_main_shell_check is not None
    ui_main_shell_status = ui_main_shell_check.get("status") if ui_main_shell_check is not None else "missing"
    if status == "success" and DEPLOY_SMOKE_REQUIRE_RUNBOOK_GATE and not runbook_gate_passed:
        status = "warning"
    if status == "success" and not rollback_ready:
        status = "warning"
    if status == "success" and not checklist_version_match:
        status = "warning"
    if status == "success" and not ui_main_shell_checked:
        status = "warning"
    if status == "success" and ui_main_shell_status == "critical":
        status = "critical"
    if status == "success" and ui_main_shell_status == "warning":
        status = "warning"
    if status == "success" and not expected_rollback_exists:
        status = "critical"
    if status == "success" and not rollback_reference_match:
        status = "warning"
    if status == "success" and rollback_sha_provided and not rollback_sha_match:
        status = "warning"

    rollback_binding_status = "ok"
    rollback_binding_message = "Rollback guide binding is valid."
    if not expected_rollback_exists:
        rollback_binding_status = "critical"
        rollback_binding_message = "Rollback guide file is missing from repository."
    elif not rollback_reference_match:
        rollback_binding_status = "warning"
        rollback_binding_message = "Rollback guide reference does not match checklist policy."
    elif rollback_sha_provided and not rollback_sha_match:
        rollback_binding_status = "warning"
        rollback_binding_message = "Rollback guide checksum does not match checklist policy."
    elif not rollback_sha_provided:
        rollback_binding_status = "warning"
        rollback_binding_message = "Rollback guide checksum was not provided by smoke client."

    checks.append(
        {
            "id": "rollback_guide_binding",
            "status": rollback_binding_status,
            "message": rollback_binding_message,
        }
    )
    if not checklist_version_match:
        checks.append(
            {
                "id": "checklist_version_binding",
                "status": "warning",
                "message": f"Checklist version does not match current policy ({checklist_version}).",
            }
        )
    elif checklist_version:
        checks.append(
            {
                "id": "checklist_version_binding",
                "status": "ok",
                "message": f"Checklist version binding verified ({checklist_version}).",
            }
        )
    if not ui_main_shell_checked:
        checks.append(
            {
                "id": "ui_main_shell_binding",
                "status": "warning",
                "message": "UI core path smoke result was not provided by smoke client.",
            }
        )

    detail = {
        "deploy_id": str(payload.get("deploy_id") or ""),
        "environment": str(payload.get("environment") or ENV_NAME),
        "base_url": str(payload.get("base_url") or ""),
        "checklist_version": provided_checklist_version or checklist_version,
        "checklist_version_expected": checklist_version or None,
        "checklist_version_match": checklist_version_match,
        "checklist_signature": checklist_signature or None,
        "checklist_version_source": str(checklist_payload.get("version_source") or "unknown"),
        "rollback_reference": provided_rollback_reference,
        "rollback_reference_expected": expected_rollback_reference,
        "rollback_reference_match": rollback_reference_match,
        "rollback_reference_exists": expected_rollback_exists,
        "rollback_reference_sha256": provided_rollback_sha256 or None,
        "rollback_reference_expected_sha256": expected_rollback_sha256 or None,
        "rollback_reference_sha256_match": rollback_sha_match if rollback_sha_provided else None,
        "rollback_ready": rollback_ready,
        "runbook_gate_passed": runbook_gate_passed,
        "ui_main_shell_path": str(checklist_policy.get("ui_core_path") or "/?tab=iam"),
        "ui_main_shell_markers": checklist_policy.get("ui_core_markers", []),
        "ui_main_shell_checked": ui_main_shell_checked,
        "ui_main_shell_status": ui_main_shell_status,
        "notes": str(payload.get("notes") or ""),
        "checks": checks,
    }
    run_id = _write_job_run(
        job_name="deploy_smoke",
        trigger="api",
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        detail=detail,
    )

    _write_audit_log(
        principal=principal,
        action="ops_deploy_smoke_record",
        resource_type="ops_deploy",
        resource_id=str(run_id or "pending"),
        status="success" if status == "success" else "warning",
        detail={
            "run_id": run_id,
            "status": status,
            "deploy_id": detail["deploy_id"],
            "rollback_ready": rollback_ready,
            "runbook_gate_passed": runbook_gate_passed,
            "check_count": len(checks),
            "checklist_version": detail["checklist_version"],
        },
    )
    return {
        "run_id": run_id,
        "job_name": "deploy_smoke",
        "status": status,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "detail": detail,
    }


@router.get("/dashboard/summary", response_model=DashboardSummaryRead)
def get_dashboard_summary(
    site: Annotated[str | None, Query()] = None,
    days: Annotated[int, Query(ge=1, le=90)] = 30,
    recent_job_limit: Annotated[int, Query(alias="job_limit", ge=1, le=50)] = 10,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> DashboardSummaryRead:
    _require_site_access(principal, site)
    allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
    return build_dashboard_summary(
        site=site,
        days=days,
        recent_job_limit=recent_job_limit,
        allowed_sites=allowed_sites,
    )


def _collect_ops_runbook_critical_review_metrics(
    *,
    now: datetime | None = None,
    month: str | None = None,
    sample_limit: int | None = None,
) -> dict[str, Any]:
    generated_at = now or datetime.now(timezone.utc)
    month_label, month_start, month_end = _month_window_bounds(now=generated_at, month_label=month)
    lookback_cutoff = generated_at - timedelta(days=max(7, RUNBOOK_CRITICAL_REVIEW_LOOKBACK_DAYS))
    effective_start = max(month_start, lookback_cutoff)
    max_samples = max(1, sample_limit or RUNBOOK_CRITICAL_REVIEW_SAMPLE_LIMIT)
    with get_conn() as conn:
        rows = conn.execute(
            select(job_runs.c.id, job_runs.c.status, job_runs.c.finished_at, job_runs.c.detail_json)
            .where(job_runs.c.job_name == "deploy_smoke")
            .where(job_runs.c.finished_at >= effective_start)
            .where(job_runs.c.finished_at < month_end)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
        ).mappings().all()

    false_positive_candidates: list[dict[str, Any]] = []
    false_negative_candidates: list[dict[str, Any]] = []
    for row in rows:
        detail = _parse_job_detail_json(row.get("detail_json"))
        checks = _normalize_deploy_smoke_checks(detail.get("checks"))
        non_runbook_problem_checks = [
            item
            for item in checks
            if item.get("status") in {"warning", "critical"}
            and item.get("id") not in {"fatal", "runbook_gate", "runbook_checks"}
        ]
        finished_at = _as_optional_datetime(row.get("finished_at"))
        candidate = {
            "run_id": row.get("id"),
            "status": str(row.get("status") or "unknown"),
            "finished_at": finished_at.isoformat() if finished_at is not None else None,
            "deploy_id": str(detail.get("deploy_id") or ""),
            "checklist_version": str(detail.get("checklist_version") or ""),
            "runbook_gate_passed": bool(detail.get("runbook_gate_passed", False)),
            "problem_check_ids": [str(item.get("id") or "") for item in non_runbook_problem_checks],
        }
        if candidate["runbook_gate_passed"]:
            if candidate["status"] in {"warning", "critical"} and non_runbook_problem_checks:
                false_negative_candidates.append(candidate)
        elif not non_runbook_problem_checks:
            false_positive_candidates.append(candidate)

    return {
        "month": month_label,
        "window_start": effective_start.isoformat(),
        "window_end": month_end.isoformat(),
        "deploy_smoke_count": len(rows),
        "false_positive_candidate_count": len(false_positive_candidates),
        "false_negative_candidate_count": len(false_negative_candidates),
        "candidate_count": len(false_positive_candidates) + len(false_negative_candidates),
        "false_positive_candidates": false_positive_candidates[:max_samples],
        "false_negative_candidates": false_negative_candidates[:max_samples],
        "sample_limit": max_samples,
        "lookback_days": max(7, RUNBOOK_CRITICAL_REVIEW_LOOKBACK_DAYS),
    }


def _build_ops_runbook_critical_review_snapshot(
    *,
    now: datetime | None = None,
    month: str | None = None,
) -> dict[str, Any]:
    generated_at = now or datetime.now(timezone.utc)
    metrics = _collect_ops_runbook_critical_review_metrics(now=generated_at, month=month)
    month_label = str(metrics.get("month") or generated_at.strftime("%Y-%m"))
    _, month_start, month_end = _month_window_bounds(now=generated_at, month_label=month_label)
    with get_conn() as conn:
        review_latest = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == OPS_RUNBOOK_CRITICAL_REVIEW_JOB_NAME)
            .where(job_runs.c.finished_at >= month_start)
            .where(job_runs.c.finished_at < month_end)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
    review_latest_model = _row_to_job_run_model(review_latest) if review_latest is not None else None
    review_completed = review_latest_model is not None
    deploy_smoke_count = int(metrics.get("deploy_smoke_count") or 0)
    candidate_count = int(metrics.get("candidate_count") or 0)

    if deploy_smoke_count == 0:
        status = "ok"
        message = f"No deploy smoke run recorded for {month_label} yet."
    elif review_completed:
        status = "ok"
        message = f"Monthly runbook critical review completed for {month_label}."
    else:
        status = "warning"
        message = (
            f"Monthly runbook critical review pending for {month_label} ({candidate_count} candidate(s))."
        )

    review_detail = (
        review_latest_model.detail
        if review_latest_model is not None and isinstance(review_latest_model.detail, dict)
        else {}
    )
    return {
        "generated_at": generated_at.isoformat(),
        "status": status,
        "message": message,
        "review_completed": review_completed,
        "latest_review_at": review_latest_model.finished_at.isoformat() if review_latest_model is not None else None,
        "latest_review_status": review_latest_model.status if review_latest_model is not None else None,
        "latest_review_run_id": review_latest_model.id if review_latest_model is not None else None,
        "latest_review_notes": review_detail.get("review_notes"),
        **metrics,
    }


def run_ops_runbook_critical_review_job(*, trigger: str = "manual", month: str | None = None) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    metrics = _collect_ops_runbook_critical_review_metrics(now=started_at, month=month)
    finished_at = datetime.now(timezone.utc)
    month_label = str(metrics.get("month") or finished_at.strftime("%Y-%m"))
    candidate_count = int(metrics.get("candidate_count") or 0)
    detail = {
        **metrics,
        "review_completed": True,
        "review_completed_at": finished_at.isoformat(),
        "review_notes": (
            "No candidate found; monthly runbook critical review acknowledged."
            if candidate_count == 0
            else f"Reviewed {candidate_count} runbook false positive/negative candidate(s)."
        ),
    }
    run_id = _write_job_run(
        job_name=OPS_RUNBOOK_CRITICAL_REVIEW_JOB_NAME,
        trigger=trigger,
        status="success",
        started_at=started_at,
        finished_at=finished_at,
        detail=detail,
    )
    return {
        "run_id": run_id,
        "job_name": OPS_RUNBOOK_CRITICAL_REVIEW_JOB_NAME,
        "status": "success",
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        **detail,
    }


def _count_pending_alert_retry_candidates(
    *,
    now: datetime | None = None,
    statuses: list[str] | None = None,
    max_attempt_count: int = 10,
    min_last_attempt_age_sec: int = 30,
) -> int:
    current_time = now or datetime.now(timezone.utc)
    normalized_statuses = sorted(
        {
            str(value).strip().lower()
            for value in (statuses or ["failed", "warning"])
            if str(value).strip()
        }
    )
    if not normalized_statuses:
        normalized_statuses = ["failed", "warning"]
    cooldown_cutoff = current_time - timedelta(seconds=max(0, min(min_last_attempt_age_sec, 86400)))
    with get_conn() as conn:
        count = conn.execute(
            select(func.count())
            .select_from(alert_deliveries)
            .where(alert_deliveries.c.status.in_(normalized_statuses))
            .where(alert_deliveries.c.attempt_count < max(1, min(max_attempt_count, 1000)))
            .where(alert_deliveries.c.last_attempt_at <= cooldown_cutoff)
        ).scalar_one()
    return int(count or 0)


def _count_alert_retention_candidates(*, now: datetime | None = None, retention_days: int | None = None) -> int:
    current_time = now or datetime.now(timezone.utc)
    cutoff = current_time - timedelta(days=max(1, int(retention_days if retention_days is not None else ALERT_RETENTION_DAYS)))
    with get_conn() as conn:
        count = conn.execute(
            select(func.count())
            .select_from(alert_deliveries)
            .where(alert_deliveries.c.last_attempt_at < cutoff)
        ).scalar_one()
    return int(count or 0)


def _build_ops_runbook_checks_snapshot(
    *,
    now: datetime | None = None,
    horizon_minutes: int = 90,
) -> dict[str, Any]:
    generated_at = now or datetime.now(timezone.utc)
    horizon = generated_at - timedelta(minutes=max(1, horizon_minutes))
    deploy_checklist = _build_deploy_checklist_payload()
    runbook_review = _build_ops_runbook_critical_review_snapshot(now=generated_at)
    pending_alert_retry_count = _count_pending_alert_retry_candidates(now=generated_at)
    pending_alert_retention_count = _count_alert_retention_candidates(now=generated_at)
    with get_conn() as conn:
        sla_recent = conn.execute(
            select(job_runs.c.id)
            .where(job_runs.c.job_name == "sla_escalation")
            .where(job_runs.c.finished_at >= horizon)
            .limit(1)
        ).first()
        alert_recent = conn.execute(
            select(job_runs.c.id)
            .where(job_runs.c.job_name == "alert_retry")
            .where(job_runs.c.finished_at >= horizon)
            .limit(1)
        ).first()
        retention_recent = conn.execute(
            select(job_runs.c.id)
            .where(job_runs.c.job_name == "alert_retention")
            .where(job_runs.c.finished_at >= (generated_at - timedelta(hours=36)))
            .limit(1)
        ).first()
        guard_recover_recent = conn.execute(
            select(job_runs.c.id)
            .where(job_runs.c.job_name == "alert_guard_recover")
            .where(job_runs.c.finished_at >= (generated_at - timedelta(hours=3)))
            .limit(1)
        ).first()
        mttr_recent = conn.execute(
            select(job_runs.c.id)
            .where(job_runs.c.job_name == "alert_mttr_slo_check")
            .where(job_runs.c.finished_at >= (generated_at - timedelta(hours=6)))
            .limit(1)
        ).first()
        w07_weekly_recent = conn.execute(
            select(job_runs.c.id)
            .where(job_runs.c.job_name == W07_WEEKLY_JOB_NAME)
            .where(job_runs.c.finished_at >= (generated_at - timedelta(days=8)))
            .limit(1)
        ).first()
        quality_weekly_recent = conn.execute(
            select(job_runs.c.id)
            .where(job_runs.c.job_name == OPS_QUALITY_WEEKLY_JOB_NAME)
            .where(job_runs.c.finished_at >= (generated_at - timedelta(days=8)))
            .limit(1)
        ).first()
        dr_rehearsal_recent = conn.execute(
            select(job_runs.c.id)
            .where(job_runs.c.job_name == DR_REHEARSAL_JOB_NAME)
            .where(job_runs.c.finished_at >= (generated_at - timedelta(days=35)))
            .limit(1)
        ).first()
        mttr_latest = conn.execute(
            select(job_runs.c.finished_at, job_runs.c.detail_json)
            .where(job_runs.c.job_name == "alert_mttr_slo_check")
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
        w07_latest = conn.execute(
            select(job_runs.c.finished_at, job_runs.c.detail_json)
            .where(job_runs.c.job_name == W07_WEEKLY_JOB_NAME)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
        dr_latest = conn.execute(
            select(job_runs.c.finished_at, job_runs.c.status, job_runs.c.detail_json)
            .where(job_runs.c.job_name == DR_REHEARSAL_JOB_NAME)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
        expiring_soon_cutoff = generated_at + timedelta(days=3)
        expiring_count = conn.execute(
            select(admin_tokens.c.id)
            .where(admin_tokens.c.is_active.is_(True))
            .where(admin_tokens.c.expires_at.is_not(None))
            .where(admin_tokens.c.expires_at <= expiring_soon_cutoff)
        ).all()
        deploy_smoke_latest = conn.execute(
            select(job_runs.c.finished_at, job_runs.c.status, job_runs.c.detail_json)
            .where(job_runs.c.job_name == "deploy_smoke")
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()

    rate_limit_snapshot = _rate_limit_backend_snapshot()
    signing_snapshot = _audit_signing_snapshot()
    latency_snapshot = _build_api_latency_snapshot()
    integrity_batch = _build_evidence_archive_integrity_batch()
    guard_snapshot = _build_alert_channel_guard_snapshot(now=generated_at, lookback_days=30, max_targets=200)
    guard_summary = guard_snapshot.get("summary", {})
    mttr_policy, _, _ = _ensure_mttr_slo_policy()
    mttr_latest_detail: dict[str, Any] = {}
    mttr_latest_finished_at: datetime | None = None
    if mttr_latest is not None:
        raw = str(mttr_latest.get("detail_json") or "{}")
        try:
            loaded = json.loads(raw)
        except json.JSONDecodeError:
            loaded = {}
        if isinstance(loaded, dict):
            mttr_latest_detail = loaded
        mttr_latest_finished_at = _as_optional_datetime(mttr_latest.get("finished_at"))
    mttr_policy_from_latest = mttr_latest_detail.get("policy", {})
    if isinstance(mttr_policy_from_latest, dict):
        mttr_policy = _normalize_mttr_slo_policy(mttr_policy_from_latest)
    mttr_window = mttr_latest_detail.get("window", {})
    if not isinstance(mttr_window, dict):
        mttr_window = {}
    mttr_breach = bool(mttr_latest_detail.get("breach", False))
    w07_latest_detail: dict[str, Any] = {}
    w07_latest_finished_at: datetime | None = None
    if w07_latest is not None:
        w07_latest_detail = _parse_job_detail_json(w07_latest.get("detail_json"))
        w07_latest_finished_at = _as_optional_datetime(w07_latest.get("finished_at"))
    w07_latest_degraded = bool((w07_latest_detail.get("degradation") or {}).get("degraded", False))
    w07_alert_targets = _configured_alert_targets()
    w07_webhook_ready = len(w07_alert_targets) > 0
    preflight_snapshot = _get_startup_preflight_snapshot(refresh=False)
    weekly_streak_snapshot = _build_ops_quality_weekly_streak_snapshot()
    rollback_guide_exists = Path("docs/W15_MIGRATION_ROLLBACK.md").exists()
    alert_noise_policy_doc_exists = Path("docs/W17_ALERT_NOISE_POLICY.md").exists()

    quarantined_count = int(guard_summary.get("quarantined_count") or 0)
    guard_warning_count = int(guard_summary.get("warning_count") or 0)
    current_month_archive = build_monthly_audit_archive(month=None, include_entries=False, max_entries=10000)
    deploy_recent_hours = max(1, DEPLOY_SMOKE_RECENT_HOURS)
    deploy_smoke_finished_at: datetime | None = None
    deploy_smoke_status = "missing"
    deploy_smoke_detail: dict[str, Any] = {}
    if deploy_smoke_latest is not None:
        deploy_smoke_finished_at = _as_optional_datetime(deploy_smoke_latest.get("finished_at"))
        deploy_smoke_status = str(deploy_smoke_latest.get("status") or "unknown")
        deploy_smoke_detail = _parse_job_detail_json(deploy_smoke_latest.get("detail_json"))
    deploy_smoke_recent_cutoff = generated_at - timedelta(hours=deploy_recent_hours)
    deploy_smoke_is_recent = (
        deploy_smoke_finished_at is not None and deploy_smoke_finished_at >= deploy_smoke_recent_cutoff
    )
    deploy_smoke_rollback_ready = bool(deploy_smoke_detail.get("rollback_ready", False))
    deploy_smoke_runbook_gate_passed = bool(deploy_smoke_detail.get("runbook_gate_passed", False))
    deploy_smoke_checklist_version = str(deploy_smoke_detail.get("checklist_version") or "")
    deploy_smoke_checklist_signature = str(deploy_smoke_detail.get("checklist_signature") or "")
    deploy_smoke_checklist_current_version = str(deploy_checklist.get("version") or "")
    deploy_smoke_checklist_current_signature = str(deploy_checklist.get("signature") or "")
    deploy_smoke_version_match = (
        deploy_smoke_checklist_version != ""
        and deploy_smoke_checklist_version == deploy_smoke_checklist_current_version
    )
    deploy_smoke_ui_checked = bool(deploy_smoke_detail.get("ui_main_shell_checked", False))
    deploy_smoke_ui_status = str(deploy_smoke_detail.get("ui_main_shell_status") or "missing")
    deploy_smoke_status_value = "ok"
    if deploy_smoke_finished_at is None:
        deploy_smoke_status_value = "warning"
        deploy_smoke_message = "No deploy smoke record found."
    elif not deploy_smoke_is_recent:
        deploy_smoke_status_value = "warning"
        deploy_smoke_message = f"Latest deploy smoke is older than {deploy_recent_hours} hours."
    elif deploy_smoke_status in {"critical", "failed", "error"}:
        deploy_smoke_status_value = "critical"
        deploy_smoke_message = "Latest deploy smoke run reported critical/failure status."
    elif DEPLOY_SMOKE_REQUIRE_RUNBOOK_GATE and not deploy_smoke_runbook_gate_passed:
        deploy_smoke_status_value = "warning"
        deploy_smoke_message = "Deploy smoke recorded without passing runbook gate."
    elif not deploy_smoke_version_match:
        deploy_smoke_status_value = "warning"
        deploy_smoke_message = "Deploy smoke checklist version does not match current release policy."
    elif not deploy_smoke_ui_checked:
        deploy_smoke_status_value = "warning"
        deploy_smoke_message = "Deploy smoke did not include UI core path validation."
    elif deploy_smoke_ui_status in {"warning", "critical"}:
        deploy_smoke_status_value = "critical" if deploy_smoke_ui_status == "critical" else "warning"
        deploy_smoke_message = "Deploy smoke reported UI core path issue."
    elif not deploy_smoke_rollback_ready:
        deploy_smoke_status_value = "warning"
        deploy_smoke_message = "Deploy smoke recorded without rollback-ready confirmation."
    else:
        deploy_smoke_message = "Deploy smoke checklist and rollback readiness are healthy."
    dr_latest_finished_at: datetime | None = None
    dr_latest_status = "missing"
    dr_latest_restore_valid = False
    if dr_latest is not None:
        dr_latest_finished_at = _as_optional_datetime(dr_latest.get("finished_at"))
        dr_latest_status = str(dr_latest.get("status") or "unknown")
        dr_detail = _parse_job_detail_json(dr_latest.get("detail_json"))
        dr_latest_restore_valid = bool(dr_detail.get("restore_valid", False))

    checks = [
        {
            "id": "sla_cron_recent",
            "status": "ok" if sla_recent is not None else "warning",
            "message": "SLA escalation job observed within last 90 minutes."
            if sla_recent is not None
            else "No recent SLA escalation job run in last 90 minutes.",
        },
        {
            "id": "alert_retry_recent",
            "status": (
                "ok"
                if alert_recent is not None or pending_alert_retry_count == 0
                else "warning"
            ),
            "message": (
                "Alert retry job observed within last 90 minutes."
                if alert_recent is not None
                else (
                    "No retry-eligible alert deliveries pending."
                    if pending_alert_retry_count == 0
                    else "No recent alert retry job run in last 90 minutes."
                )
            ),
            "pending_count": pending_alert_retry_count,
        },
        {
            "id": "startup_preflight",
            "status": (
                "critical"
                if preflight_snapshot.get("has_error")
                else ("warning" if int(preflight_snapshot.get("warning_count") or 0) > 0 else "ok")
            ),
            "message": (
                "Startup preflight has blocking errors."
                if preflight_snapshot.get("has_error")
                else (
                    "Startup preflight has warnings."
                    if int(preflight_snapshot.get("warning_count") or 0) > 0
                    else "Startup preflight is healthy."
                )
            ),
            "error_count": int(preflight_snapshot.get("error_count") or 0),
            "warning_count": int(preflight_snapshot.get("warning_count") or 0),
            "generated_at": preflight_snapshot.get("generated_at"),
        },
        {
            "id": "ops_quality_weekly_report_streak",
            "status": "ok" if bool(weekly_streak_snapshot.get("target_met", False)) else "warning",
            "message": (
                (
                    "Ops quality weekly report streak target met for current ramp window."
                    if bool(weekly_streak_snapshot.get("bootstrap_grace_active", False))
                    else "Ops quality weekly report streak target met."
                )
                if bool(weekly_streak_snapshot.get("target_met", False))
                else "Ops quality weekly report streak target not met."
            ),
            "current_streak_weeks": int(weekly_streak_snapshot.get("current_streak_weeks") or 0),
            "target_weeks": int(weekly_streak_snapshot.get("target_weeks") or 0),
            "configured_target_weeks": int(weekly_streak_snapshot.get("configured_target_weeks") or 0),
            "bootstrap_grace_active": bool(weekly_streak_snapshot.get("bootstrap_grace_active", False)),
            "anchor_week_start": weekly_streak_snapshot.get("anchor_week_start"),
            "latest_success_at": weekly_streak_snapshot.get("latest_success_at"),
        },
        {
            "id": "ops_daily_check_archive",
            "status": "ok" if OPS_DAILY_CHECK_ARCHIVE_ENABLED else "warning",
            "message": (
                "Ops daily check summary archive is enabled."
                if OPS_DAILY_CHECK_ARCHIVE_ENABLED
                else "Ops daily check summary archive is disabled."
            ),
            "archive_enabled": OPS_DAILY_CHECK_ARCHIVE_ENABLED,
            "archive_path": OPS_DAILY_CHECK_ARCHIVE_PATH,
            "retention_days": max(1, OPS_DAILY_CHECK_ARCHIVE_RETENTION_DAYS),
        },
        {
            "id": "api_latency_p95",
            "status": latency_snapshot["status"],
            "message": latency_snapshot["message"],
            "target_count": latency_snapshot["target_count"],
            "warning_threshold_ms": latency_snapshot["warning_threshold_ms"],
            "critical_threshold_ms": latency_snapshot["critical_threshold_ms"],
            "min_samples": latency_snapshot["min_samples"],
            "insufficient_samples_count": latency_snapshot["insufficient_samples_count"],
            "critical_count": latency_snapshot["critical_count"],
            "warning_count": latency_snapshot["warning_count"],
            "endpoints": latency_snapshot["endpoints"],
        },
        {
            "id": "api_burn_rate",
            "status": str((latency_snapshot.get("burn_rate") or {}).get("status") or "warning"),
            "message": str((latency_snapshot.get("burn_rate") or {}).get("message") or "Burn-rate status unavailable."),
            "short_window_minutes": int((latency_snapshot.get("burn_rate") or {}).get("short_window_minutes") or 0),
            "long_window_minutes": int((latency_snapshot.get("burn_rate") or {}).get("long_window_minutes") or 0),
            "warning_threshold": float((latency_snapshot.get("burn_rate") or {}).get("warning_threshold") or 0.0),
            "critical_threshold": float((latency_snapshot.get("burn_rate") or {}).get("critical_threshold") or 0.0),
            "min_samples": int((latency_snapshot.get("burn_rate") or {}).get("min_samples") or 0),
            "error_budget_percent": float((latency_snapshot.get("burn_rate") or {}).get("error_budget_percent") or 0.0),
            "latency_budget_percent": float((latency_snapshot.get("burn_rate") or {}).get("latency_budget_percent") or 0.0),
            "critical_count": int((latency_snapshot.get("burn_rate") or {}).get("critical_count") or 0),
            "warning_count": int((latency_snapshot.get("burn_rate") or {}).get("warning_count") or 0),
            "warming_up_count": int((latency_snapshot.get("burn_rate") or {}).get("warming_up_count") or 0),
        },
        {
            "id": "audit_chain_integrity",
            "status": "ok" if current_month_archive["chain"]["chain_ok"] else "critical",
            "message": "Audit chain verified."
            if current_month_archive["chain"]["chain_ok"]
            else "Audit chain mismatch detected.",
            "issue_count": current_month_archive["chain"]["issue_count"],
        },
        {
            "id": "evidence_archive_integrity_batch",
            "status": integrity_batch["status"],
            "message": integrity_batch["message"],
            "sample_per_table": integrity_batch["sample_per_table"],
            "checked_count": integrity_batch["checked_count"],
            "missing_blob_count": integrity_batch["missing_blob_count"],
            "missing_hash_count": integrity_batch["missing_hash_count"],
            "digest_mismatch_count": integrity_batch["digest_mismatch_count"],
            "read_error_count": integrity_batch["read_error_count"],
            "archive": integrity_batch["archive"],
            "issue_count": integrity_batch["issue_count"],
        },
        {
            "id": "deploy_smoke_checklist",
            "status": deploy_smoke_status_value,
            "message": deploy_smoke_message,
            "recent_window_hours": deploy_recent_hours,
            "latest_run_at": deploy_smoke_finished_at.isoformat() if deploy_smoke_finished_at is not None else None,
            "latest_run_status": deploy_smoke_status,
            "rollback_ready": deploy_smoke_rollback_ready,
            "runbook_gate_passed": deploy_smoke_runbook_gate_passed,
            "checklist_version": deploy_smoke_checklist_version,
            "current_checklist_version": deploy_smoke_checklist_current_version,
            "checklist_signature": deploy_smoke_checklist_signature,
            "current_checklist_signature": deploy_smoke_checklist_current_signature,
            "checklist_version_match": deploy_smoke_version_match,
            "ui_main_shell_checked": deploy_smoke_ui_checked,
            "ui_main_shell_status": deploy_smoke_ui_status,
            "ui_main_shell_path": deploy_smoke_detail.get("ui_main_shell_path"),
            "require_runbook_gate": DEPLOY_SMOKE_REQUIRE_RUNBOOK_GATE,
        },
        {
            "id": "runbook_critical_monthly_review",
            "status": str(runbook_review.get("status") or "warning"),
            "message": str(runbook_review.get("message") or "Monthly runbook critical review status unavailable."),
            "month": runbook_review.get("month"),
            "review_completed": bool(runbook_review.get("review_completed", False)),
            "latest_review_at": runbook_review.get("latest_review_at"),
            "deploy_smoke_count": int(runbook_review.get("deploy_smoke_count") or 0),
            "false_positive_candidate_count": int(runbook_review.get("false_positive_candidate_count") or 0),
            "false_negative_candidate_count": int(runbook_review.get("false_negative_candidate_count") or 0),
        },
        {
            "id": "migration_rollback_guide",
            "status": "ok" if rollback_guide_exists else "critical",
            "message": (
                "Migration rollback guide is available."
                if rollback_guide_exists
                else "Migration rollback guide file is missing."
            ),
            "path": "docs/W15_MIGRATION_ROLLBACK.md",
        },
        {
            "id": "token_expiry_pressure",
            "status": "ok" if len(expiring_count) == 0 else "warning",
            "message": "No active admin tokens expiring within 3 days."
            if len(expiring_count) == 0
            else f"{len(expiring_count)} active admin token(s) expire within 3 days.",
        },
        {
            "id": "rate_limit_backend",
            "status": rate_limit_snapshot["status"],
            "message": rate_limit_snapshot["message"],
            "configured_store": rate_limit_snapshot["configured_store"],
            "active_backend": rate_limit_snapshot["active_backend"],
            "redis_ping_ok": rate_limit_snapshot["redis_ping_ok"],
        },
        {
            "id": "audit_archive_signing",
            "status": signing_snapshot["status"],
            "message": signing_snapshot["message"],
            "algorithm": signing_snapshot["algorithm"],
            "enabled": signing_snapshot["enabled"],
        },
        {
            "id": "alert_channel_guard",
            "status": str(guard_summary.get("status") or "ok"),
            "message": (
                f"{quarantined_count} alert channel(s) are quarantined."
                if quarantined_count > 0
                else (
                    f"{guard_warning_count} alert channel(s) show warning state."
                    if guard_warning_count > 0
                    else "All alert channels are healthy."
                )
            ),
            "quarantined_count": quarantined_count,
            "warning_count": guard_warning_count,
            "target_count": int(guard_summary.get("target_count") or 0),
        },
        {
            "id": "alert_retention_recent",
            "status": (
                "ok"
                if retention_recent is not None or pending_alert_retention_count == 0
                else "warning"
            ),
            "message": (
                "Alert retention job observed within last 36 hours."
                if retention_recent is not None
                else (
                    "No retention candidates older than policy window."
                    if pending_alert_retention_count == 0
                    else "No recent alert retention job run in last 36 hours."
                )
            ),
            "candidate_count": pending_alert_retention_count,
        },
        {
            "id": "alert_guard_recovery_recent",
            "status": (
                "ok"
                if quarantined_count == 0 or guard_recover_recent is not None
                else "warning"
            ),
            "message": (
                "Guard recovery job observed within last 3 hours."
                if quarantined_count > 0 and guard_recover_recent is not None
                else (
                    "No quarantined channels currently."
                    if quarantined_count == 0
                    else "Quarantined channels exist but no guard recovery job in last 3 hours."
                )
            ),
        },
        {
            "id": "alert_mttr_slo_recent",
            "status": "ok" if mttr_recent is not None else "warning",
            "message": "MTTR SLO check observed within last 6 hours."
            if mttr_recent is not None
            else "No recent MTTR SLO check run in last 6 hours.",
        },
        {
            "id": "alert_noise_policy_documented",
            "status": "ok" if alert_noise_policy_doc_exists else "warning",
            "message": (
                "Alert noise policy document is available."
                if alert_noise_policy_doc_exists
                else "Alert noise policy document is missing."
            ),
            "path": "docs/W17_ALERT_NOISE_POLICY.md",
        },
        {
            "id": "alert_mttr_slo_breach",
            "status": (
                "ok"
                if not bool(mttr_policy.get("enabled", True))
                else ("warning" if mttr_breach else "ok")
            ),
            "message": (
                "MTTR SLO policy disabled."
                if not bool(mttr_policy.get("enabled", True))
                else (
                    "MTTR SLO breach detected in latest check."
                    if mttr_breach
                    else "MTTR SLO within threshold in latest check."
                )
            ),
            "latest_checked_at": mttr_latest_finished_at.isoformat() if mttr_latest_finished_at is not None else None,
            "threshold_minutes": int(mttr_policy.get("threshold_minutes") or 0),
            "window_days": int(mttr_policy.get("window_days") or 0),
            "min_incidents": int(mttr_policy.get("min_incidents") or 0),
            "window_incident_count": int(mttr_window.get("incident_count") or 0),
            "window_mttr_minutes": mttr_window.get("mttr_minutes"),
        },
        {
            "id": "w07_weekly_quality_recent",
            "status": "ok" if w07_weekly_recent is not None else "warning",
            "message": (
                "W07 weekly SLA quality automation observed within last 8 days."
                if w07_weekly_recent is not None
                else "No recent W07 weekly SLA quality automation run within last 8 days."
            ),
            "latest_checked_at": w07_latest_finished_at.isoformat() if w07_latest_finished_at is not None else None,
            "latest_degraded": w07_latest_degraded,
        },
        {
            "id": "dr_rehearsal_recent",
            "status": (
                "ok"
                if (not DR_REHEARSAL_ENABLED) or dr_rehearsal_recent is not None
                else "warning"
            ),
            "message": (
                "DR rehearsal run observed within last 35 days."
                if dr_rehearsal_recent is not None
                else (
                    "DR rehearsal is disabled by policy."
                    if not DR_REHEARSAL_ENABLED
                    else "No recent DR rehearsal run in last 35 days."
                )
            ),
            "enabled": DR_REHEARSAL_ENABLED,
            "latest_run_at": dr_latest_finished_at.isoformat() if dr_latest_finished_at is not None else None,
            "latest_status": dr_latest_status,
            "latest_restore_valid": dr_latest_restore_valid,
        },
        {
            "id": "ops_quality_weekly_report_recent",
            "status": "ok" if quality_weekly_recent is not None else "warning",
            "message": (
                "Ops quality weekly report job observed within last 8 days."
                if quality_weekly_recent is not None
                else "No recent ops quality weekly report job run in last 8 days."
            ),
        },
        {
            "id": "w07_quality_alert_channel",
            "status": (
                "ok"
                if (not W07_QUALITY_ALERT_ENABLED) or w07_webhook_ready
                else "warning"
            ),
            "message": (
                "W07 quality alert channel configured."
                if w07_webhook_ready
                else (
                    "W07 quality alert is enabled but no webhook channel is configured."
                    if W07_QUALITY_ALERT_ENABLED
                    else "W07 quality alert is disabled."
                )
            ),
            "alert_enabled": W07_QUALITY_ALERT_ENABLED,
            "webhook_target_count": len(w07_alert_targets),
        },
    ]
    overall = "ok"
    if any(check["status"] == "critical" for check in checks):
        overall = "critical"
    elif any(check["status"] == "warning" for check in checks):
        overall = "warning"
    return {
        "generated_at": generated_at.isoformat(),
        "overall_status": overall,
        "checks": checks,
    }


def _build_ops_security_posture_snapshot(*, now: datetime | None = None) -> dict[str, Any]:
    generated_at = now or datetime.now(timezone.utc)
    rate_limit_snapshot = _rate_limit_backend_snapshot()
    signing_snapshot = _audit_signing_snapshot()
    latency_snapshot = _build_api_latency_snapshot()
    deploy_checklist = _build_deploy_checklist_payload()
    alert_targets = _configured_alert_targets()
    mttr_policy, mttr_policy_updated_at, _ = _ensure_mttr_slo_policy()
    with get_conn() as conn:
        w07_latest = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == W07_WEEKLY_JOB_NAME)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
        deploy_smoke_latest = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == "deploy_smoke")
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
    w07_latest_model = _row_to_job_run_model(w07_latest) if w07_latest is not None else None
    deploy_smoke_latest_model = _row_to_job_run_model(deploy_smoke_latest) if deploy_smoke_latest is not None else None
    deploy_smoke_latest_detail = (
        deploy_smoke_latest_model.detail
        if deploy_smoke_latest_model is not None and isinstance(deploy_smoke_latest_model.detail, dict)
        else {}
    )
    w07_latest_detail = (
        w07_latest_model.detail
        if w07_latest_model is not None and isinstance(w07_latest_model.detail, dict)
        else {}
    )
    w07_latest_degraded = bool((w07_latest_detail.get("degradation") or {}).get("degraded", False))
    preflight = _get_startup_preflight_snapshot(refresh=False)
    weekly_streak = _build_ops_quality_weekly_streak_snapshot()
    dr_latest_payload = _latest_dr_rehearsal_payload()
    return {
        "generated_at": generated_at.isoformat(),
        "env": ENV_NAME,
        "rate_limit": rate_limit_snapshot,
        "audit_archive_signing": signing_snapshot,
        "api_latency": latency_snapshot,
        "deploy_smoke_policy": {
            "checklist_version": deploy_checklist.get("version"),
            "checklist_signature": deploy_checklist.get("signature"),
            "checklist_version_source": deploy_checklist.get("version_source"),
            "recent_hours": max(1, DEPLOY_SMOKE_RECENT_HOURS),
            "require_runbook_gate": DEPLOY_SMOKE_REQUIRE_RUNBOOK_GATE,
            "latest_run_at": (
                deploy_smoke_latest_model.finished_at.isoformat()
                if deploy_smoke_latest_model is not None
                else None
            ),
            "latest_status": (
                deploy_smoke_latest_model.status
                if deploy_smoke_latest_model is not None
                else None
            ),
            "latest_runbook_gate_passed": bool(deploy_smoke_latest_detail.get("runbook_gate_passed", False)),
            "latest_rollback_ready": bool(deploy_smoke_latest_detail.get("rollback_ready", False)),
        },
        "evidence_archive_integrity_policy": {
            "sample_per_table": max(1, EVIDENCE_INTEGRITY_SAMPLE_PER_TABLE),
            "max_issues": max(1, EVIDENCE_INTEGRITY_MAX_ISSUES),
            "modules": [name for name, _ in EVIDENCE_INTEGRITY_TABLES],
        },
        "preflight": {
            "overall_status": preflight.get("overall_status"),
            "has_error": bool(preflight.get("has_error", False)),
            "error_count": int(preflight.get("error_count") or 0),
            "warning_count": int(preflight.get("warning_count") or 0),
            "fail_on_error": PREFLIGHT_FAIL_ON_ERROR,
        },
        "ops_quality_reports": {
            "archive_enabled": OPS_QUALITY_REPORT_ARCHIVE_ENABLED,
            "archive_path": OPS_QUALITY_REPORT_ARCHIVE_PATH,
            "archive_retention_days": max(1, OPS_QUALITY_REPORT_ARCHIVE_RETENTION_DAYS),
            "weekly_streak_target": max(1, OPS_QUALITY_WEEKLY_STREAK_TARGET),
            "weekly_streak_current": int(weekly_streak.get("current_streak_weeks") or 0),
            "weekly_streak_met": bool(weekly_streak.get("target_met", False)),
        },
        "dr_rehearsal": {
            "enabled": DR_REHEARSAL_ENABLED,
            "backup_path": DR_REHEARSAL_BACKUP_PATH,
            "retention_days": max(1, DR_REHEARSAL_RETENTION_DAYS),
            "latest_run_at": dr_latest_payload.get("finished_at") if isinstance(dr_latest_payload, dict) else None,
            "latest_status": dr_latest_payload.get("status") if isinstance(dr_latest_payload, dict) else None,
            "latest_restore_valid": (
                bool(dr_latest_payload.get("restore_valid", False)) if isinstance(dr_latest_payload, dict) else False
            ),
        },
        "alerting": {
            "webhook_target_count": len(alert_targets),
            "ops_daily_check_alert_level": _normalize_ops_daily_check_alert_level(OPS_DAILY_CHECK_ALERT_LEVEL),
            "ops_daily_check_archive_enabled": OPS_DAILY_CHECK_ARCHIVE_ENABLED,
            "ops_daily_check_archive_path": OPS_DAILY_CHECK_ARCHIVE_PATH,
            "ops_daily_check_archive_retention_days": max(1, OPS_DAILY_CHECK_ARCHIVE_RETENTION_DAYS),
            "channel_guard_enabled": ALERT_CHANNEL_GUARD_ENABLED,
            "channel_guard_fail_threshold": max(1, ALERT_CHANNEL_GUARD_FAIL_THRESHOLD),
            "channel_guard_cooldown_minutes": max(1, ALERT_CHANNEL_GUARD_COOLDOWN_MINUTES),
            "guard_recover_max_targets": max(1, ALERT_GUARD_RECOVER_MAX_TARGETS),
            "retention_days": max(1, ALERT_RETENTION_DAYS),
            "retention_max_delete": max(1, ALERT_RETENTION_MAX_DELETE),
            "retention_archive_enabled": ALERT_RETENTION_ARCHIVE_ENABLED,
            "mttr_slo_enabled": bool(mttr_policy.get("enabled", True)),
            "mttr_slo_window_days": int(mttr_policy.get("window_days") or 0),
            "mttr_slo_threshold_minutes": int(mttr_policy.get("threshold_minutes") or 0),
            "mttr_slo_min_incidents": int(mttr_policy.get("min_incidents") or 0),
            "mttr_slo_auto_recover_enabled": bool(mttr_policy.get("auto_recover_enabled", True)),
            "mttr_slo_recover_state": str(mttr_policy.get("recover_state") or "quarantined"),
            "mttr_slo_recover_max_targets": int(mttr_policy.get("recover_max_targets") or 0),
            "mttr_slo_notify_enabled": bool(mttr_policy.get("notify_enabled", True)),
            "mttr_slo_notify_event_type": str(mttr_policy.get("notify_event_type") or "mttr_slo_breach"),
            "mttr_slo_notify_cooldown_minutes": int(mttr_policy.get("notify_cooldown_minutes") or 0),
            "mttr_slo_top_channels": int(mttr_policy.get("top_channels") or 0),
            "mttr_slo_policy_updated_at": mttr_policy_updated_at.isoformat(),
            "w07_quality_alert_enabled": W07_QUALITY_ALERT_ENABLED,
            "w07_quality_alert_cooldown_minutes": max(0, W07_QUALITY_ALERT_COOLDOWN_MINUTES),
            "w07_quality_escalation_threshold_percent": round(max(0.0, W07_QUALITY_ALERT_ESCALATION_RATE_THRESHOLD), 2),
            "w07_quality_alert_success_threshold_percent": round(
                max(0.0, min(100.0, W07_QUALITY_ALERT_SUCCESS_RATE_THRESHOLD)),
                2,
            ),
            "w07_quality_webhook_target_count": len(alert_targets),
            "w07_quality_weekly_latest_run_at": (
                w07_latest_model.finished_at.isoformat()
                if w07_latest_model is not None
                else None
            ),
            "w07_quality_weekly_latest_status": (
                w07_latest_model.status
                if w07_latest_model is not None
                else None
            ),
            "w07_quality_weekly_latest_degraded": w07_latest_degraded,
            "w07_quality_archive_enabled": W07_WEEKLY_ARCHIVE_ENABLED,
            "w07_quality_archive_path": W07_WEEKLY_ARCHIVE_PATH,
        },
        "evidence_storage_backend": _normalize_evidence_storage_backend(EVIDENCE_STORAGE_BACKEND),
        "token_policy": {
            "require_expiry": ADMIN_TOKEN_REQUIRE_EXPIRY,
            "max_ttl_days": ADMIN_TOKEN_MAX_TTL_DAYS,
            "rotate_after_days": ADMIN_TOKEN_ROTATE_AFTER_DAYS,
            "rotate_warning_days": ADMIN_TOKEN_ROTATE_WARNING_DAYS,
            "max_idle_days": ADMIN_TOKEN_MAX_IDLE_DAYS,
            "max_active_per_user": ADMIN_TOKEN_MAX_ACTIVE_PER_USER,
        },
    }


@router.get("/runbook/checks")
def get_ops_runbook_checks(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    snapshot = _build_ops_runbook_checks_snapshot()
    checks = snapshot["checks"]
    overall = str(snapshot["overall_status"])
    rate_limit_check = next((item for item in checks if item["id"] == "rate_limit_backend"), {})
    signing_check = next((item for item in checks if item["id"] == "audit_archive_signing"), {})

    _write_audit_log(
        principal=principal,
        action="ops_runbook_checks_view",
        resource_type="ops_runbook",
        resource_id="checks",
        detail={
            "overall_status": overall,
            "checks": [{"id": item["id"], "status": item["status"]} for item in checks],
            "rate_limit": {
                "configured_store": rate_limit_check.get("configured_store"),
                "active_backend": rate_limit_check.get("active_backend"),
                "redis_ping_ok": rate_limit_check.get("redis_ping_ok"),
            },
            "audit_signing": {
                "enabled": signing_check.get("enabled"),
                "algorithm": signing_check.get("algorithm"),
            },
        },
    )
    return snapshot


@router.post("/runbook/checks/run")
def run_ops_runbook_checks(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    result = run_ops_daily_check_job(trigger="api")
    _write_audit_log(
        principal=principal,
        action="ops_runbook_daily_check_run",
        resource_type="ops_runbook",
        resource_id=str(result.get("run_id") or "pending"),
        detail={
            "run_id": result.get("run_id"),
            "status": result.get("status"),
            "overall_status": result.get("overall_status"),
            "check_count": result.get("check_count"),
            "warning_count": result.get("warning_count"),
            "critical_count": result.get("critical_count"),
            "alert_attempted": result.get("alert_attempted"),
            "alert_dispatched": result.get("alert_dispatched"),
            "alert_error": result.get("alert_error"),
            "mttr_slo_check": result.get("mttr_slo_check"),
        },
    )
    return result


@router.get("/runbook/checks/latest")
def get_ops_runbook_checks_latest(
    include_checks: Annotated[bool, Query()] = True,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == "ops_daily_check")
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="No ops_daily_check run found")
    model = _row_to_job_run_model(row)
    detail = model.detail if isinstance(model.detail, dict) else {}
    checks = detail.get("checks", [])
    if not isinstance(checks, list):
        checks = []
    try:
        check_count = int(detail.get("check_count", len(checks)))
    except (TypeError, ValueError):
        check_count = len(checks)
    try:
        warning_count = int(detail.get("warning_count", sum(1 for item in checks if item.get("status") == "warning")))
    except (TypeError, ValueError):
        warning_count = sum(1 for item in checks if item.get("status") == "warning")
    try:
        critical_count = int(detail.get("critical_count", sum(1 for item in checks if item.get("status") == "critical")))
    except (TypeError, ValueError):
        critical_count = sum(1 for item in checks if item.get("status") == "critical")
    summary = detail.get("summary") if isinstance(detail.get("summary"), dict) else None
    if summary is None:
        summary = _build_ops_daily_check_summary_from_job_run(model, detail)
    archive = detail.get("archive") if isinstance(detail.get("archive"), dict) else {}

    response: dict[str, Any] = {
        "run_id": model.id,
        "job_name": model.job_name,
        "trigger": model.trigger,
        "status": model.status,
        "started_at": model.started_at.isoformat(),
        "finished_at": model.finished_at.isoformat(),
        "overall_status": str(detail.get("overall_status") or model.status),
        "check_count": check_count,
        "warning_count": warning_count,
        "critical_count": critical_count,
        "alert_level": detail.get("alert_level"),
        "alert_attempted": bool(detail.get("alert_attempted", False)),
        "alert_dispatched": bool(detail.get("alert_dispatched", False)),
        "alert_error": detail.get("alert_error"),
        "alert_channels": detail.get("alert_channels", []),
        "security_posture": detail.get("security_posture", {}),
        "mttr_slo_check": detail.get("mttr_slo_check", {}),
        "summary": summary,
        "archive": archive,
    }
    if include_checks:
        response["checks"] = checks

    _write_audit_log(
        principal=principal,
        action="ops_runbook_daily_check_latest_view",
        resource_type="ops_runbook",
        resource_id=str(model.id),
        detail={
            "run_id": model.id,
            "status": model.status,
            "include_checks": include_checks,
        },
    )
    return response


@router.get("/runbook/checks/latest/summary.json")
def get_ops_runbook_checks_latest_summary_json(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == "ops_daily_check")
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="No ops_daily_check run found")
    model = _row_to_job_run_model(row)
    detail = model.detail if isinstance(model.detail, dict) else {}
    summary = detail.get("summary") if isinstance(detail.get("summary"), dict) else None
    if summary is None:
        summary = _build_ops_daily_check_summary_from_job_run(model, detail)
    archive = detail.get("archive") if isinstance(detail.get("archive"), dict) else {}
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "job_name": "ops_daily_check",
        "summary": summary,
        "archive": archive,
    }
    _write_audit_log(
        principal=principal,
        action="ops_runbook_daily_check_summary_json_view",
        resource_type="ops_runbook",
        resource_id=str(model.id),
        detail={
            "run_id": model.id,
            "status": model.status,
        },
    )
    return payload


@router.get("/runbook/checks/latest/summary.csv")
def get_ops_runbook_checks_latest_summary_csv(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> Response:
    with get_conn() as conn:
        row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == "ops_daily_check")
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="No ops_daily_check run found")
    model = _row_to_job_run_model(row)
    detail = model.detail if isinstance(model.detail, dict) else {}
    summary = detail.get("summary") if isinstance(detail.get("summary"), dict) else None
    if summary is None:
        summary = _build_ops_daily_check_summary_from_job_run(model, detail)
    csv_text = _build_ops_daily_check_summary_csv(summary)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    file_name = f"ops-daily-check-summary-{stamp}.csv"
    _write_audit_log(
        principal=principal,
        action="ops_runbook_daily_check_summary_csv_export",
        resource_type="ops_runbook",
        resource_id=file_name,
        detail={
            "run_id": model.id,
            "status": model.status,
        },
    )
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.get("/runbook/checks/archive.json")
def get_ops_runbook_checks_archive_json(
    limit: Annotated[int, Query(ge=1, le=365)] = 30,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    rows = _build_ops_daily_check_archive_rows(limit=limit)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "job_name": "ops_daily_check",
        "limit": limit,
        "count": len(rows),
        "rows": rows,
    }
    _write_audit_log(
        principal=principal,
        action="ops_runbook_daily_check_archive_json_view",
        resource_type="ops_runbook",
        resource_id="archive",
        detail={
            "limit": limit,
            "count": len(rows),
        },
    )
    return payload


@router.get("/runbook/checks/archive.csv")
def get_ops_runbook_checks_archive_csv(
    limit: Annotated[int, Query(ge=1, le=365)] = 90,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> Response:
    rows = _build_ops_daily_check_archive_rows(limit=limit)
    csv_text = _build_ops_daily_check_archive_csv(rows)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    file_name = f"ops-daily-check-archive-{stamp}.csv"
    _write_audit_log(
        principal=principal,
        action="ops_runbook_daily_check_archive_csv_export",
        resource_type="ops_runbook",
        resource_id=file_name,
        detail={
            "limit": limit,
            "count": len(rows),
        },
    )
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.post("/runbook/review/run")
def run_ops_runbook_critical_review(
    month: Annotated[str | None, Query(pattern=r"^\d{4}-\d{2}$")] = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    result = run_ops_runbook_critical_review_job(trigger="api", month=month)
    _write_audit_log(
        principal=principal,
        action="ops_runbook_critical_review_run",
        resource_type="ops_runbook",
        resource_id=str(result.get("run_id") or "pending"),
        detail={
            "run_id": result.get("run_id"),
            "month": result.get("month"),
            "deploy_smoke_count": result.get("deploy_smoke_count"),
            "false_positive_candidate_count": result.get("false_positive_candidate_count"),
            "false_negative_candidate_count": result.get("false_negative_candidate_count"),
        },
    )
    return result


@router.get("/runbook/review/latest")
def get_ops_runbook_critical_review_latest(
    month: Annotated[str | None, Query(pattern=r"^\d{4}-\d{2}$")] = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    with get_conn() as conn:
        stmt = (
            select(job_runs)
            .where(job_runs.c.job_name == OPS_RUNBOOK_CRITICAL_REVIEW_JOB_NAME)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
        )
        if month is not None:
            _, month_start, month_end = _month_window_bounds(month_label=month)
            stmt = stmt.where(job_runs.c.finished_at >= month_start).where(job_runs.c.finished_at < month_end)
        row = conn.execute(stmt.limit(1)).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="No ops_runbook_critical_review run found")

    model = _row_to_job_run_model(row)
    detail = model.detail if isinstance(model.detail, dict) else {}
    response = {
        "run_id": model.id,
        "job_name": model.job_name,
        "trigger": model.trigger,
        "status": model.status,
        "started_at": model.started_at.isoformat(),
        "finished_at": model.finished_at.isoformat(),
        **detail,
    }
    _write_audit_log(
        principal=principal,
        action="ops_runbook_critical_review_latest_view",
        resource_type="ops_runbook",
        resource_id=str(model.id),
        detail={
            "run_id": model.id,
            "month": detail.get("month"),
            "status": model.status,
        },
    )
    return response


@router.get("/security/posture")
def get_ops_security_posture(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    snapshot = _build_ops_security_posture_snapshot()
    rate_limit_snapshot = snapshot["rate_limit"]
    signing_snapshot = snapshot["audit_archive_signing"]
    _write_audit_log(
        principal=principal,
        action="ops_security_posture_view",
        resource_type="ops_security",
        resource_id="posture",
        detail={
            "rate_limit_store": rate_limit_snapshot["configured_store"],
            "rate_limit_backend": rate_limit_snapshot["active_backend"],
            "rate_limit_status": rate_limit_snapshot["status"],
            "audit_signing_enabled": signing_snapshot["enabled"],
            "audit_signing_status": signing_snapshot["status"],
            "api_latency_status": snapshot.get("api_latency", {}).get("status"),
            "api_latency_warning_threshold_ms": snapshot.get("api_latency", {}).get("warning_threshold_ms"),
            "api_burn_rate_status": snapshot.get("api_latency", {}).get("burn_rate", {}).get("status"),
            "api_burn_rate_warning_threshold": snapshot.get("api_latency", {}).get("burn_rate", {}).get(
                "warning_threshold"
            ),
            "deploy_smoke_latest_status": snapshot.get("deploy_smoke_policy", {}).get("latest_status"),
            "deploy_smoke_latest_run_at": snapshot.get("deploy_smoke_policy", {}).get("latest_run_at"),
            "preflight_status": snapshot.get("preflight", {}).get("overall_status"),
            "preflight_error_count": snapshot.get("preflight", {}).get("error_count"),
            "dr_rehearsal_enabled": snapshot.get("dr_rehearsal", {}).get("enabled"),
            "dr_rehearsal_latest_status": snapshot.get("dr_rehearsal", {}).get("latest_status"),
            "ops_quality_weekly_streak_met": snapshot.get("ops_quality_reports", {}).get("weekly_streak_met"),
            "evidence_storage_backend": snapshot["evidence_storage_backend"],
            "ops_daily_check_alert_level": snapshot.get("alerting", {}).get("ops_daily_check_alert_level"),
            "alert_webhook_target_count": snapshot.get("alerting", {}).get("webhook_target_count"),
            "alert_channel_guard_enabled": snapshot.get("alerting", {}).get("channel_guard_enabled"),
            "alert_channel_guard_fail_threshold": snapshot.get("alerting", {}).get("channel_guard_fail_threshold"),
            "alert_retention_days": snapshot.get("alerting", {}).get("retention_days"),
            "alert_mttr_slo_enabled": snapshot.get("alerting", {}).get("mttr_slo_enabled"),
            "alert_mttr_slo_window_days": snapshot.get("alerting", {}).get("mttr_slo_window_days"),
            "alert_mttr_slo_threshold_minutes": snapshot.get("alerting", {}).get("mttr_slo_threshold_minutes"),
            "ops_daily_check_archive_enabled": snapshot.get("alerting", {}).get("ops_daily_check_archive_enabled"),
            "ops_daily_check_archive_path": snapshot.get("alerting", {}).get("ops_daily_check_archive_path"),
            "ops_daily_check_archive_retention_days": snapshot.get("alerting", {}).get(
                "ops_daily_check_archive_retention_days"
            ),
        },
    )
    return snapshot


@router.get("/preflight")
def get_ops_preflight(
    refresh: Annotated[bool, Query()] = False,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    snapshot = _get_startup_preflight_snapshot(refresh=refresh)
    _write_audit_log(
        principal=principal,
        action="ops_preflight_view",
        resource_type="ops_preflight",
        resource_id="startup",
        detail={
            "refresh": refresh,
            "overall_status": snapshot.get("overall_status"),
            "error_count": snapshot.get("error_count"),
            "warning_count": snapshot.get("warning_count"),
        },
    )
    return snapshot


@router.get("/alerts/noise-policy")
def get_ops_alert_noise_policy(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    payload = _build_alert_noise_policy_snapshot()
    _write_audit_log(
        principal=principal,
        action="ops_alert_noise_policy_view",
        resource_type="ops_alerting",
        resource_id="noise_policy",
        detail={
            "review_window_days": payload.get("review_window_days"),
            "false_positive_threshold_percent": payload.get("false_positive_threshold_percent"),
            "false_negative_threshold_percent": payload.get("false_negative_threshold_percent"),
        },
    )
    return payload


@router.get("/admin/security-dashboard")
def get_ops_admin_security_dashboard(
    days: Annotated[int, Query(ge=1, le=180)] = 30,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    snapshot = _build_admin_security_dashboard_snapshot(days=days)
    _write_audit_log(
        principal=principal,
        action="ops_admin_security_dashboard_view",
        resource_type="ops_admin_security",
        resource_id="dashboard",
        detail={
            "window_days": snapshot.get("window_days"),
            "overall_status": snapshot.get("overall_status"),
            "anomaly_count": len(snapshot.get("anomalies", [])),
        },
    )
    return snapshot


@router.get("/reports/quality/weekly")
def get_ops_quality_report_weekly(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    payload = _build_ops_quality_report_payload(
        window="weekly",
        start=start,
        end=end,
        label=f"week-{start.date().isoformat()}-{end.date().isoformat()}",
    )
    _write_audit_log(
        principal=principal,
        action="ops_quality_report_weekly_view",
        resource_type="ops_quality_report",
        resource_id="weekly",
        detail={
            "window_start": payload.get("period", {}).get("start"),
            "window_end": payload.get("period", {}).get("end"),
            "critical_findings_total": payload.get("summary", {}).get("critical_findings_total"),
        },
    )
    return payload


@router.get("/reports/quality/weekly/csv")
def get_ops_quality_report_weekly_csv(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> Response:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    payload = _build_ops_quality_report_payload(
        window="weekly",
        start=start,
        end=end,
        label=f"week-{start.date().isoformat()}-{end.date().isoformat()}",
    )
    csv_text = _build_ops_quality_report_csv(payload)
    stamp = end.strftime("%Y%m%dT%H%M%SZ")
    file_name = f"ops-quality-weekly-{stamp}.csv"
    _write_audit_log(
        principal=principal,
        action="ops_quality_report_weekly_csv_export",
        resource_type="ops_quality_report",
        resource_id=file_name,
        detail={"window": "weekly"},
    )
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.get("/reports/quality/monthly")
def get_ops_quality_report_monthly(
    month: Annotated[str | None, Query(description="YYYY-MM", pattern=r"^\d{4}-\d{2}$")] = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    start, end, normalized_month = _month_window(month)
    payload = _build_ops_quality_report_payload(
        window="monthly",
        start=start,
        end=end,
        label=normalized_month,
    )
    _write_audit_log(
        principal=principal,
        action="ops_quality_report_monthly_view",
        resource_type="ops_quality_report",
        resource_id=normalized_month,
        detail={"month": normalized_month},
    )
    return payload


@router.get("/reports/quality/monthly/csv")
def get_ops_quality_report_monthly_csv(
    month: Annotated[str | None, Query(description="YYYY-MM", pattern=r"^\d{4}-\d{2}$")] = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> Response:
    start, end, normalized_month = _month_window(month)
    payload = _build_ops_quality_report_payload(
        window="monthly",
        start=start,
        end=end,
        label=normalized_month,
    )
    csv_text = _build_ops_quality_report_csv(payload)
    file_name = f"ops-quality-monthly-{normalized_month}.csv"
    _write_audit_log(
        principal=principal,
        action="ops_quality_report_monthly_csv_export",
        resource_type="ops_quality_report",
        resource_id=file_name,
        detail={"month": normalized_month},
    )
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.post("/reports/quality/run")
def run_ops_quality_report(
    window: Annotated[str, Query(pattern="^(weekly|monthly)$")] = "weekly",
    month: Annotated[str | None, Query(description="YYYY-MM", pattern=r"^\d{4}-\d{2}$")] = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    result = run_ops_quality_report_job(window=window, month=month, trigger="api")
    _write_audit_log(
        principal=principal,
        action="ops_quality_report_run",
        resource_type="ops_quality_report",
        resource_id=str(result.get("run_id") or "pending"),
        status=str(result.get("status") or "success"),
        detail={
            "window": result.get("window"),
            "label": result.get("label"),
            "archive_file": (result.get("archive") or {}).get("json_file"),
            "streak": result.get("streak"),
        },
    )
    return result


@router.get("/reports/quality/weekly/streak")
def get_ops_quality_report_weekly_streak(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    snapshot = _build_ops_quality_weekly_streak_snapshot()
    _write_audit_log(
        principal=principal,
        action="ops_quality_report_weekly_streak_view",
        resource_type="ops_quality_report",
        resource_id="weekly_streak",
        detail=snapshot,
    )
    return snapshot


@router.get("/inspections/checklists/import-validation")
def get_ops_inspection_checklists_import_validation(
    principal: dict[str, Any] = Depends(require_permission("inspections:read")),
) -> dict[str, Any]:
    report = _build_ops_checklists_import_validation_report()
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_inspection_checklists_import_validation_view",
        resource_type="ops_inspection_checklists",
        resource_id="import_validation",
        detail={
            "status": report.get("status"),
            "error_count": summary.get("error_count"),
            "warning_count": summary.get("warning_count"),
            "issue_bucket_count": summary.get("issue_bucket_count"),
        },
    )
    return report


@router.get("/inspections/checklists/import-validation.csv")
def get_ops_inspection_checklists_import_validation_csv(
    principal: dict[str, Any] = Depends(require_permission("inspections:read")),
) -> Response:
    report = _build_ops_checklists_import_validation_report()
    csv_text = _build_ops_checklists_import_validation_csv(report)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    file_name = f"ops-inspection-checklists-import-validation-{stamp}.csv"
    _write_audit_log(
        principal=principal,
        action="ops_inspection_checklists_import_validation_csv_export",
        resource_type="ops_inspection_checklists",
        resource_id=file_name,
        detail={"status": report.get("status")},
    )
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.get("/inspections/checklists/qr-assets/placeholders")
def get_ops_inspection_checklists_qr_asset_placeholders(
    principal: dict[str, Any] = Depends(require_permission("inspections:read")),
) -> dict[str, Any]:
    payload = _load_ops_special_checklists_payload()
    report = _build_ops_qr_placeholder_report(payload)
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_inspection_checklists_qr_placeholders_view",
        resource_type="ops_inspection_checklists",
        resource_id="qr_assets_placeholders",
        detail={
            "status": report.get("status"),
            "qr_asset_count": summary.get("qr_asset_count"),
            "placeholder_row_count": summary.get("placeholder_row_count"),
        },
    )
    return report


@router.post("/inspections/checklists/qr-assets/bulk-update")
def post_ops_inspection_checklists_qr_asset_bulk_update(
    payload: dict[str, Any] | None = None,
    principal: dict[str, Any] = Depends(require_permission("inspections:write")),
) -> dict[str, Any]:
    body = payload if isinstance(payload, dict) else {}
    result = _apply_ops_qr_asset_bulk_update_request(body)
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    placeholder_after = int(summary.get("placeholder_row_count_after") or 0)
    _write_audit_log(
        principal=principal,
        action="ops_inspection_checklists_qr_bulk_update",
        resource_type="ops_inspection_checklists",
        resource_id="qr_assets",
        status="warning" if placeholder_after > 0 else "success",
        detail={
            "dry_run": bool(result.get("dry_run", True)),
            "saved": bool(result.get("saved", False)),
            "requested_count": int(summary.get("requested_count") or 0),
            "applied_count": int(summary.get("applied_count") or 0),
            "updated_count": int(summary.get("updated_count") or 0),
            "created_count": int(summary.get("created_count") or 0),
            "invalid_count": int(summary.get("invalid_count") or 0),
            "placeholder_row_count_before": int(summary.get("placeholder_row_count_before") or 0),
            "placeholder_row_count_after": placeholder_after,
        },
    )
    return result


@router.post("/dr/rehearsal/run")
def run_ops_dr_rehearsal(
    simulate_restore: Annotated[bool, Query()] = True,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    result = run_dr_rehearsal_job(trigger="api", simulate_restore=simulate_restore)
    _write_audit_log(
        principal=principal,
        action="ops_dr_rehearsal_run",
        resource_type="ops_dr",
        resource_id=str(result.get("run_id") or "pending"),
        status=str(result.get("status") or "success"),
        detail={
            "simulate_restore": simulate_restore,
            "backup_file": result.get("backup_file"),
            "restore_valid": result.get("restore_valid"),
            "notes": result.get("notes"),
        },
    )
    return result


@router.get("/dr/rehearsal/latest")
def get_ops_dr_rehearsal_latest(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    payload = _latest_dr_rehearsal_payload()
    if payload is None:
        raise HTTPException(status_code=404, detail="No dr_rehearsal run found")
    _write_audit_log(
        principal=principal,
        action="ops_dr_rehearsal_latest_view",
        resource_type="ops_dr",
        resource_id=str(payload.get("run_id") or "unknown"),
        detail={"status": payload.get("status")},
    )
    return payload


@router.get("/dr/rehearsal/history")
def get_ops_dr_rehearsal_history(
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    with get_conn() as conn:
        rows = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == DR_REHEARSAL_JOB_NAME)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(limit)
        ).mappings().all()
    items = []
    for row in rows:
        model = _row_to_job_run_model(row)
        detail = model.detail if isinstance(model.detail, dict) else {}
        items.append(
            {
                "run_id": model.id,
                "status": model.status,
                "trigger": model.trigger,
                "finished_at": model.finished_at.isoformat(),
                "backup_file": detail.get("backup_file"),
                "restore_valid": bool(detail.get("restore_valid", False)),
                "pruned_files": int(detail.get("pruned_files") or 0),
            }
        )
    _write_audit_log(
        principal=principal,
        action="ops_dr_rehearsal_history_view",
        resource_type="ops_dr",
        resource_id="history",
        detail={"limit": limit, "count": len(items)},
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(items),
        "items": items,
    }


@router.get("/governance/gate")
def get_ops_governance_gate(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    snapshot = _build_ops_governance_gate_snapshot()
    summary = snapshot.get("summary", {}) if isinstance(snapshot.get("summary"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_governance_gate_view",
        resource_type="ops_governance_gate",
        resource_id="snapshot",
        status="success" if str(snapshot.get("decision") or "no_go") == "go" else "warning",
        detail={
            "decision": snapshot.get("decision"),
            "failure_count": int(summary.get("failure_count") or 0),
            "warning_count": int(summary.get("warning_count") or 0),
        },
    )
    return snapshot


@router.post("/governance/gate/run")
def run_ops_governance_gate(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    result = run_ops_governance_gate_job(trigger="api")
    summary = result.get("summary", {}) if isinstance(result.get("summary"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_governance_gate_run",
        resource_type="ops_governance_gate",
        resource_id=str(result.get("run_id") or "pending"),
        status="success" if str(result.get("decision") or "no_go") == "go" else "warning",
        detail={
            "decision": result.get("decision"),
            "status": result.get("status"),
            "failure_count": int(summary.get("failure_count") or 0),
            "warning_count": int(summary.get("warning_count") or 0),
        },
    )
    return result


@router.get("/governance/gate/latest")
def get_ops_governance_gate_latest(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    payload = _latest_ops_governance_gate_payload()
    if payload is None:
        raise HTTPException(status_code=404, detail="No ops_governance_gate run found")
    summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_governance_gate_latest_view",
        resource_type="ops_governance_gate",
        resource_id=str(payload.get("run_id") or "unknown"),
        detail={
            "decision": payload.get("decision"),
            "status": payload.get("status"),
            "failure_count": int(summary.get("failure_count") or 0),
            "warning_count": int(summary.get("warning_count") or 0),
        },
    )
    return payload


@router.get("/governance/gate/history")
def get_ops_governance_gate_history(
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    with get_conn() as conn:
        rows = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == OPS_GOVERNANCE_GATE_JOB_NAME)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(limit)
        ).mappings().all()
    items: list[dict[str, Any]] = []
    for row in rows:
        model = _row_to_job_run_model(row)
        detail = model.detail if isinstance(model.detail, dict) else {}
        summary = detail.get("summary", {}) if isinstance(detail.get("summary"), dict) else {}
        items.append(
            {
                "run_id": model.id,
                "status": model.status,
                "decision": detail.get("decision"),
                "failure_count": int(summary.get("failure_count") or 0),
                "warning_count": int(summary.get("warning_count") or 0),
                "finished_at": model.finished_at.isoformat(),
            }
        )
    _write_audit_log(
        principal=principal,
        action="ops_governance_gate_history_view",
        resource_type="ops_governance_gate",
        resource_id="history",
        detail={"limit": limit, "count": len(items)},
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(items),
        "items": items,
    }


@router.get("/governance/gate/remediation")
def get_ops_governance_gate_remediation(
    include_warnings: Annotated[bool, Query()] = True,
    max_items: Annotated[int, Query(ge=1, le=200)] = OPS_GOVERNANCE_REMEDIATION_DEFAULT_MAX_ITEMS,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    snapshot = _build_ops_governance_gate_snapshot()
    plan = _build_ops_governance_remediation_plan(
        snapshot=snapshot,
        include_warnings=include_warnings,
        max_items=max_items,
    )
    summary = plan.get("summary", {}) if isinstance(plan.get("summary"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_governance_gate_remediation_view",
        resource_type="ops_governance_gate",
        resource_id="remediation",
        status="success" if str(plan.get("decision") or "no_go") == "go" else "warning",
        detail={
            "decision": plan.get("decision"),
            "include_warnings": include_warnings,
            "item_count": int(summary.get("item_count") or 0),
            "fail_count": int(summary.get("fail_count") or 0),
            "warning_count": int(summary.get("warning_count") or 0),
        },
    )
    return plan


@router.get("/governance/gate/remediation/csv")
def get_ops_governance_gate_remediation_csv(
    include_warnings: Annotated[bool, Query()] = True,
    max_items: Annotated[int, Query(ge=1, le=200)] = OPS_GOVERNANCE_REMEDIATION_DEFAULT_MAX_ITEMS,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> Response:
    snapshot = _build_ops_governance_gate_snapshot()
    plan = _build_ops_governance_remediation_plan(
        snapshot=snapshot,
        include_warnings=include_warnings,
        max_items=max_items,
    )
    csv_text = _build_ops_governance_remediation_csv(plan)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    file_name = f"ops-governance-remediation-{stamp}.csv"
    summary = plan.get("summary", {}) if isinstance(plan.get("summary"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_governance_gate_remediation_csv_export",
        resource_type="ops_governance_gate",
        resource_id=file_name,
        status="success" if str(plan.get("decision") or "no_go") == "go" else "warning",
        detail={
            "decision": plan.get("decision"),
            "include_warnings": include_warnings,
            "item_count": int(summary.get("item_count") or 0),
            "fail_count": int(summary.get("fail_count") or 0),
            "warning_count": int(summary.get("warning_count") or 0),
        },
    )
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.post(
    "/governance/gate/remediation/tracker/sync",
    response_model=W21RemediationTrackerSyncResponse,
)
def sync_ops_governance_gate_remediation_tracker(
    payload: W21RemediationTrackerSyncRequest,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> W21RemediationTrackerSyncResponse:
    result = _sync_w21_remediation_tracker(
        actor_username=str(principal.get("username") or "system"),
        include_warnings=bool(payload.include_warnings),
        max_items=int(payload.max_items),
    )
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_sync",
        resource_type="ops_governance_remediation_tracker",
        resource_id=W21_TRACKER_SCOPE_GLOBAL,
        detail={
            "include_warnings": bool(payload.include_warnings),
            "max_items": int(payload.max_items),
            "active_count": int(result.active_count),
            "created_count": int(result.created_count),
            "reopened_count": int(result.reopened_count),
            "resolved_count": int(result.resolved_count),
        },
    )
    return result


@router.get(
    "/governance/gate/remediation/tracker/items",
    response_model=list[W21RemediationTrackerItemRead],
)
def list_ops_governance_gate_remediation_tracker_items(
    include_inactive: Annotated[bool, Query()] = False,
    status: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> list[W21RemediationTrackerItemRead]:
    normalized_status: str | None = None
    if status is not None:
        normalized_status = status.strip().lower()
        if normalized_status not in W21_TRACKER_STATUS_SET:
            raise HTTPException(status_code=422, detail="Invalid tracker status")

    stmt = select(ops_governance_remediation_tracker_items)
    if not include_inactive:
        stmt = stmt.where(ops_governance_remediation_tracker_items.c.is_active.is_(True))
    if normalized_status is not None:
        stmt = stmt.where(ops_governance_remediation_tracker_items.c.status == normalized_status)
    stmt = stmt.order_by(
        ops_governance_remediation_tracker_items.c.is_active.desc(),
        ops_governance_remediation_tracker_items.c.priority.asc(),
        ops_governance_remediation_tracker_items.c.due_at.asc(),
        ops_governance_remediation_tracker_items.c.id.asc(),
    ).limit(limit)
    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    models = [_row_to_w21_remediation_item_model(row) for row in rows]
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_items_view",
        resource_type="ops_governance_remediation_tracker",
        resource_id=W21_TRACKER_SCOPE_GLOBAL,
        detail={
            "include_inactive": include_inactive,
            "status": normalized_status,
            "limit": limit,
            "count": len(models),
        },
    )
    return models


@router.patch(
    "/governance/gate/remediation/tracker/items/{tracker_item_id}",
    response_model=W21RemediationTrackerItemRead,
)
def update_ops_governance_gate_remediation_tracker_item(
    tracker_item_id: int,
    payload: W21RemediationTrackerItemUpdate,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> W21RemediationTrackerItemRead:
    now = datetime.now(timezone.utc)
    actor_username = str(principal.get("username") or "system")
    with get_conn() as conn:
        existing = conn.execute(
            select(ops_governance_remediation_tracker_items)
            .where(ops_governance_remediation_tracker_items.c.id == tracker_item_id)
            .limit(1)
        ).mappings().first()
        if existing is None:
            raise HTTPException(status_code=404, detail="Remediation tracker item not found")

        next_assignee = existing.get("assignee")
        next_status = _normalize_w21_tracker_status(existing.get("status"))
        next_checked = bool(existing.get("completion_checked", False))
        next_note = str(existing.get("completion_note") or "")
        next_completed_at = _as_optional_datetime(existing.get("completed_at"))

        if payload.assignee is not None:
            assignee_text = payload.assignee.strip()
            next_assignee = assignee_text or None
        if payload.status is not None:
            next_status = _normalize_w21_tracker_status(payload.status)
        if payload.completion_checked is not None:
            next_checked = bool(payload.completion_checked)
        if payload.completion_note is not None:
            next_note = payload.completion_note.strip()

        if next_status == W21_TRACKER_STATUS_DONE:
            next_completed_at = now
            if payload.completion_checked is None and payload.status is not None:
                next_checked = True
        elif payload.status is not None and payload.status != W21_TRACKER_STATUS_DONE and payload.completion_checked is None:
            next_checked = False

        if next_checked and next_status != W21_TRACKER_STATUS_DONE:
            next_status = W21_TRACKER_STATUS_DONE
            next_completed_at = now
        elif (not next_checked) and next_status == W21_TRACKER_STATUS_DONE:
            next_status = W21_TRACKER_STATUS_IN_PROGRESS
            next_completed_at = None
        elif next_status != W21_TRACKER_STATUS_DONE:
            next_completed_at = None

        conn.execute(
            update(ops_governance_remediation_tracker_items)
            .where(ops_governance_remediation_tracker_items.c.id == tracker_item_id)
            .values(
                assignee=next_assignee,
                status=next_status,
                completion_checked=next_checked,
                completion_note=next_note,
                completed_at=next_completed_at,
                updated_by=actor_username,
                updated_at=now,
            )
        )

        _reset_w21_completion_if_closed(
            conn=conn,
            actor_username=actor_username,
            checked_at=now,
            reason=f"tracker item {tracker_item_id} updated",
        )

        updated_row = conn.execute(
            select(ops_governance_remediation_tracker_items)
            .where(ops_governance_remediation_tracker_items.c.id == tracker_item_id)
            .limit(1)
        ).mappings().first()
        if updated_row is None:
            raise HTTPException(status_code=404, detail="Remediation tracker item not found")

    model = _row_to_w21_remediation_item_model(updated_row)
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_item_update",
        resource_type="ops_governance_remediation_tracker_item",
        resource_id=str(tracker_item_id),
        detail={
            "status": model.status,
            "assignee": model.assignee,
            "completion_checked": model.completion_checked,
            "is_active": model.is_active,
        },
    )
    return model


@router.get(
    "/governance/gate/remediation/tracker/overview",
    response_model=W21RemediationTrackerOverviewRead,
)
def get_ops_governance_gate_remediation_tracker_overview(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> W21RemediationTrackerOverviewRead:
    now = datetime.now(timezone.utc)
    all_rows = _load_w21_remediation_items(include_inactive=True)
    active_rows = [row for row in all_rows if row.is_active]
    overview = _compute_w21_remediation_overview(
        active_rows=active_rows,
        active_count=len(active_rows),
        closed_count=max(0, len(all_rows) - len(active_rows)),
        checked_at=now,
    )
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_overview_view",
        resource_type="ops_governance_remediation_tracker",
        resource_id=W21_TRACKER_SCOPE_GLOBAL,
        detail={
            "active_count": overview.active_count,
            "closed_count": overview.closed_count,
            "completion_rate_percent": overview.completion_rate_percent,
        },
    )
    return overview


@router.get(
    "/governance/gate/remediation/tracker/readiness",
    response_model=W21RemediationTrackerReadinessRead,
)
def get_ops_governance_gate_remediation_tracker_readiness(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> W21RemediationTrackerReadinessRead:
    active_rows = _load_w21_remediation_items(include_inactive=False)
    readiness = _compute_w21_remediation_readiness(active_rows=active_rows)
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_readiness_view",
        resource_type="ops_governance_remediation_tracker",
        resource_id=W21_TRACKER_SCOPE_GLOBAL,
        status="success" if readiness.ready else "warning",
        detail={
            "ready": readiness.ready,
            "total_items": readiness.total_items,
            "readiness_score_percent": readiness.readiness_score_percent,
        },
    )
    return readiness


@router.get(
    "/governance/gate/remediation/tracker/completion",
    response_model=W21RemediationTrackerCompletionRead,
)
def get_ops_governance_gate_remediation_tracker_completion(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> W21RemediationTrackerCompletionRead:
    now = datetime.now(timezone.utc)
    active_rows = _load_w21_remediation_items(include_inactive=False)
    readiness = _compute_w21_remediation_readiness(active_rows=active_rows, checked_at=now)
    with get_conn() as conn:
        row = conn.execute(
            select(ops_governance_remediation_tracker_runs)
            .where(ops_governance_remediation_tracker_runs.c.scope == W21_TRACKER_SCOPE_GLOBAL)
            .limit(1)
        ).mappings().first()
    result = _row_to_w21_completion_model(readiness=readiness, row=row)
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_completion_view",
        resource_type="ops_governance_remediation_tracker",
        resource_id=W21_TRACKER_SCOPE_GLOBAL,
        detail={
            "status": result.status,
            "ready": readiness.ready,
            "readiness_score_percent": readiness.readiness_score_percent,
        },
    )
    return result


@router.post(
    "/governance/gate/remediation/tracker/complete",
    response_model=W21RemediationTrackerCompletionRead,
)
def complete_ops_governance_gate_remediation_tracker(
    payload: W21RemediationTrackerCompletionRequest,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> W21RemediationTrackerCompletionRead:
    now = datetime.now(timezone.utc)
    actor_username = str(principal.get("username") or "system")
    active_rows = _load_w21_remediation_items(include_inactive=False)
    readiness = _compute_w21_remediation_readiness(active_rows=active_rows, checked_at=now)
    if not readiness.ready and not payload.force:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Remediation tracker is not ready for completion.",
                "blockers": readiness.blockers,
                "readiness_score_percent": readiness.readiness_score_percent,
            },
        )

    status = W21_COMPLETION_STATUS_COMPLETED if readiness.ready else W21_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS
    completion_note = (payload.completion_note or "").strip()
    readiness_json = _to_json_text(
        {
            "ready": readiness.ready,
            "readiness_score_percent": readiness.readiness_score_percent,
            "blockers": readiness.blockers,
            "checked_at": now.isoformat(),
        }
    )

    with get_conn() as conn:
        existing = conn.execute(
            select(ops_governance_remediation_tracker_runs)
            .where(ops_governance_remediation_tracker_runs.c.scope == W21_TRACKER_SCOPE_GLOBAL)
            .limit(1)
        ).mappings().first()
        if existing is None:
            conn.execute(
                insert(ops_governance_remediation_tracker_runs).values(
                    scope=W21_TRACKER_SCOPE_GLOBAL,
                    status=status,
                    completion_note=completion_note,
                    force_used=bool(payload.force),
                    completed_by=actor_username,
                    completed_at=now,
                    last_checked_at=now,
                    readiness_json=readiness_json,
                    created_by=actor_username,
                    updated_by=actor_username,
                    created_at=now,
                    updated_at=now,
                )
            )
        else:
            conn.execute(
                update(ops_governance_remediation_tracker_runs)
                .where(ops_governance_remediation_tracker_runs.c.scope == W21_TRACKER_SCOPE_GLOBAL)
                .values(
                    status=status,
                    completion_note=completion_note,
                    force_used=bool(payload.force),
                    completed_by=actor_username,
                    completed_at=now,
                    last_checked_at=now,
                    readiness_json=readiness_json,
                    updated_by=actor_username,
                    updated_at=now,
                )
            )
        row = conn.execute(
            select(ops_governance_remediation_tracker_runs)
            .where(ops_governance_remediation_tracker_runs.c.scope == W21_TRACKER_SCOPE_GLOBAL)
            .limit(1)
        ).mappings().first()
    result = _row_to_w21_completion_model(readiness=readiness, row=row)
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_complete",
        resource_type="ops_governance_remediation_tracker",
        resource_id=W21_TRACKER_SCOPE_GLOBAL,
        status="success" if readiness.ready else "warning",
        detail={
            "status": result.status,
            "force": bool(payload.force),
            "ready": readiness.ready,
            "readiness_score_percent": readiness.readiness_score_percent,
            "blockers": readiness.blockers,
        },
    )
    return result


@router.get("/governance/gate/remediation/tracker/sla")
def get_ops_governance_gate_remediation_tracker_sla(
    due_soon_hours: Annotated[int, Query(ge=0, le=168)] = 24,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    snapshot = _build_w22_remediation_sla_snapshot(due_soon_hours=due_soon_hours)
    metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_sla_view",
        resource_type="ops_governance_remediation_tracker",
        resource_id=W21_TRACKER_SCOPE_GLOBAL,
        status="success",
        detail={
            "due_soon_hours": int(snapshot.get("due_soon_hours") or due_soon_hours),
            "open_items": int(metrics.get("open_items") or 0),
            "overdue_count": int(metrics.get("overdue_count") or 0),
            "critical_open_count": int(metrics.get("critical_open_count") or 0),
        },
    )
    return snapshot


@router.post("/governance/gate/remediation/tracker/escalate/run")
def run_ops_governance_gate_remediation_tracker_escalation(
    dry_run: Annotated[bool, Query()] = False,
    include_due_soon_hours: Annotated[int, Query(ge=0, le=168)] = GOVERNANCE_REMEDIATION_ESCALATION_DUE_SOON_HOURS,
    notify: Annotated[bool | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    result = run_ops_governance_remediation_escalation_job(
        trigger="api",
        dry_run=dry_run,
        include_due_soon_hours=include_due_soon_hours,
        notify_enabled=notify,
    )
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_escalation_run",
        resource_type="ops_governance_remediation_tracker",
        resource_id=str(result.get("run_id") or "pending"),
        status=str(result.get("status") or "warning"),
        detail={
            "dry_run": bool(result.get("dry_run", dry_run)),
            "due_soon_hours": int(result.get("due_soon_hours") or include_due_soon_hours),
            "candidate_count": int(result.get("candidate_count") or 0),
            "critical_count": int(result.get("critical_count") or 0),
            "notify_attempted": bool(result.get("notify_attempted", False)),
            "notify_dispatched": bool(result.get("notify_dispatched", False)),
            "notify_error": result.get("notify_error"),
        },
    )
    return result


@router.get("/governance/gate/remediation/tracker/escalate/latest")
def get_ops_governance_gate_remediation_tracker_escalation_latest(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    payload = _latest_ops_governance_remediation_escalation_payload()
    if payload is None:
        raise HTTPException(status_code=404, detail="No ops_governance_remediation_escalation run found")
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_escalation_latest_view",
        resource_type="ops_governance_remediation_tracker",
        resource_id=str(payload.get("run_id") or "unknown"),
        status=str(payload.get("status") or "warning"),
        detail={
            "candidate_count": int(payload.get("candidate_count") or 0),
            "critical_count": int(payload.get("critical_count") or 0),
            "notify_attempted": bool(payload.get("notify_attempted", False)),
            "notify_dispatched": bool(payload.get("notify_dispatched", False)),
        },
    )
    return payload


@router.get("/governance/gate/remediation/tracker/workload")
def get_ops_governance_gate_remediation_tracker_workload(
    include_inactive: Annotated[bool, Query()] = False,
    max_suggestions: Annotated[int, Query(ge=1, le=100)] = 20,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    snapshot = _build_w23_remediation_workload_snapshot(
        include_inactive=include_inactive,
        max_suggestions=max_suggestions,
    )
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_workload_view",
        resource_type="ops_governance_remediation_tracker",
        resource_id=W21_TRACKER_SCOPE_GLOBAL,
        status="success",
        detail={
            "include_inactive": bool(snapshot.get("include_inactive", include_inactive)),
            "total_open_items": int(snapshot.get("total_open_items") or 0),
            "unassigned_open_count": int(snapshot.get("unassigned_open_count") or 0),
            "suggestion_count": len(snapshot.get("suggestions") or []),
        },
    )
    return snapshot


@router.post("/governance/gate/remediation/tracker/auto-assign/run")
def run_ops_governance_gate_remediation_tracker_auto_assign(
    dry_run: Annotated[bool, Query()] = False,
    limit: Annotated[int | None, Query(ge=1, le=500)] = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    result = run_ops_governance_remediation_auto_assign_job(
        trigger="api",
        dry_run=dry_run,
        limit=limit,
    )
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_auto_assign_run",
        resource_type="ops_governance_remediation_tracker",
        resource_id=str(result.get("run_id") or "pending"),
        status=str(result.get("status") or "warning"),
        detail={
            "dry_run": bool(result.get("dry_run", dry_run)),
            "limit": int(result.get("limit") or (limit or GOVERNANCE_REMEDIATION_AUTO_ASSIGN_MAX_ITEMS)),
            "candidate_count": int(result.get("candidate_count") or 0),
            "assigned_count": int(result.get("assigned_count") or 0),
            "skipped_count": int(result.get("skipped_count") or 0),
            "no_candidate_count": int(result.get("no_candidate_count") or 0),
            "enabled": bool(result.get("enabled", GOVERNANCE_REMEDIATION_AUTO_ASSIGN_ENABLED)),
        },
    )
    return result


@router.get("/governance/gate/remediation/tracker/auto-assign/latest")
def get_ops_governance_gate_remediation_tracker_auto_assign_latest(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    payload = _latest_ops_governance_remediation_auto_assign_payload()
    if payload is None:
        raise HTTPException(status_code=404, detail="No ops_governance_remediation_auto_assign run found")
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_auto_assign_latest_view",
        resource_type="ops_governance_remediation_tracker",
        resource_id=str(payload.get("run_id") or "unknown"),
        status=str(payload.get("status") or "warning"),
        detail={
            "candidate_count": int(payload.get("candidate_count") or 0),
            "assigned_count": int(payload.get("assigned_count") or 0),
            "skipped_count": int(payload.get("skipped_count") or 0),
            "no_candidate_count": int(payload.get("no_candidate_count") or 0),
            "enabled": bool(payload.get("enabled", GOVERNANCE_REMEDIATION_AUTO_ASSIGN_ENABLED)),
        },
    )
    return payload


@router.get("/governance/gate/remediation/tracker/kpi")
def get_ops_governance_gate_remediation_tracker_kpi(
    window_days: Annotated[int, Query(ge=1, le=180)] = GOVERNANCE_REMEDIATION_KPI_WINDOW_DAYS,
    due_soon_hours: Annotated[int, Query(ge=0, le=168)] = GOVERNANCE_REMEDIATION_KPI_DUE_SOON_HOURS,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    snapshot = _build_w24_remediation_kpi_snapshot(
        window_days=window_days,
        due_soon_hours=due_soon_hours,
    )
    metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_kpi_view",
        resource_type="ops_governance_remediation_tracker",
        resource_id=W21_TRACKER_SCOPE_GLOBAL,
        status="success",
        detail={
            "window_days": int(snapshot.get("window_days") or window_days),
            "due_soon_hours": int(snapshot.get("due_soon_hours") or due_soon_hours),
            "open_items": int(metrics.get("open_items") or 0),
            "overdue_count": int(metrics.get("overdue_count") or 0),
            "unassigned_open_count": int(metrics.get("unassigned_open_count") or 0),
            "critical_open_count": int(metrics.get("critical_open_count") or 0),
        },
    )
    return snapshot


@router.post("/governance/gate/remediation/tracker/kpi/run")
def run_ops_governance_gate_remediation_tracker_kpi(
    window_days: Annotated[int, Query(ge=1, le=180)] = GOVERNANCE_REMEDIATION_KPI_WINDOW_DAYS,
    due_soon_hours: Annotated[int, Query(ge=0, le=168)] = GOVERNANCE_REMEDIATION_KPI_DUE_SOON_HOURS,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    result = run_ops_governance_remediation_kpi_job(
        trigger="api",
        window_days=window_days,
        due_soon_hours=due_soon_hours,
    )
    metrics = result.get("metrics", {}) if isinstance(result.get("metrics"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_kpi_run",
        resource_type="ops_governance_remediation_tracker",
        resource_id=str(result.get("run_id") or "pending"),
        status=str(result.get("status") or "warning"),
        detail={
            "window_days": int(result.get("window_days") or window_days),
            "due_soon_hours": int(result.get("due_soon_hours") or due_soon_hours),
            "open_items": int(metrics.get("open_items") or 0),
            "overdue_count": int(metrics.get("overdue_count") or 0),
            "unassigned_open_count": int(metrics.get("unassigned_open_count") or 0),
            "critical_open_count": int(metrics.get("critical_open_count") or 0),
        },
    )
    return result


@router.get("/governance/gate/remediation/tracker/kpi/latest")
def get_ops_governance_gate_remediation_tracker_kpi_latest(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    payload = _latest_ops_governance_remediation_kpi_payload()
    if payload is None:
        raise HTTPException(status_code=404, detail="No ops_governance_remediation_kpi run found")
    metrics = payload.get("metrics", {}) if isinstance(payload.get("metrics"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_kpi_latest_view",
        resource_type="ops_governance_remediation_tracker",
        resource_id=str(payload.get("run_id") or "unknown"),
        status=str(payload.get("status") or "warning"),
        detail={
            "window_days": int(payload.get("window_days") or GOVERNANCE_REMEDIATION_KPI_WINDOW_DAYS),
            "due_soon_hours": int(payload.get("due_soon_hours") or GOVERNANCE_REMEDIATION_KPI_DUE_SOON_HOURS),
            "open_items": int(metrics.get("open_items") or 0),
            "overdue_count": int(metrics.get("overdue_count") or 0),
            "unassigned_open_count": int(metrics.get("unassigned_open_count") or 0),
            "critical_open_count": int(metrics.get("critical_open_count") or 0),
        },
    )
    return payload


@router.post("/governance/gate/remediation/tracker/autopilot/run")
def run_ops_governance_gate_remediation_tracker_autopilot(
    dry_run: Annotated[bool, Query()] = False,
    force: Annotated[bool, Query()] = False,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    result = run_ops_governance_remediation_autopilot_job(
        trigger="api",
        dry_run=dry_run,
        force=force,
    )
    metrics = result.get("metrics", {}) if isinstance(result.get("metrics"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_autopilot_run",
        resource_type="ops_governance_remediation_tracker",
        resource_id=str(result.get("run_id") or "pending"),
        status=str(result.get("status") or "warning"),
        detail={
            "dry_run": bool(result.get("dry_run", dry_run)),
            "force": bool(result.get("force", force)),
            "skipped": bool(result.get("skipped", False)),
            "skip_reason": result.get("skip_reason"),
            "planned_actions": result.get("planned_actions", []),
            "actions": result.get("actions", []),
            "guard": result.get("guard", {}),
            "errors": result.get("errors", []),
            "open_items": int(metrics.get("open_items") or 0),
            "overdue_count": int(metrics.get("overdue_count") or 0),
            "unassigned_open_count": int(metrics.get("unassigned_open_count") or 0),
            "critical_open_count": int(metrics.get("critical_open_count") or 0),
        },
    )
    return result


@router.get("/governance/gate/remediation/tracker/autopilot/policy")
def get_ops_governance_gate_remediation_tracker_autopilot_policy(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    policy, updated_at, policy_key = _ensure_w26_remediation_autopilot_policy()
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_autopilot_policy_view",
        resource_type="ops_governance_remediation_tracker",
        resource_id=policy_key,
        status="success",
        detail={
            "policy_key": policy_key,
            "enabled": bool(policy.get("enabled", True)),
            "unassigned_trigger": int(policy.get("unassigned_trigger") or 0),
            "overdue_trigger": int(policy.get("overdue_trigger") or 0),
            "cooldown_minutes": int(policy.get("cooldown_minutes") or 0),
        },
    )
    return _build_policy_response_payload(
        policy_key=policy_key,
        updated_at=updated_at,
        policy=policy,
        scope="ops.governance.remediation.autopilot",
    )


@router.put("/governance/gate/remediation/tracker/autopilot/policy")
def set_ops_governance_gate_remediation_tracker_autopilot_policy(
    payload: dict[str, Any],
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    policy, updated_at, policy_key = _upsert_w26_remediation_autopilot_policy(payload)
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_autopilot_policy_update",
        resource_type="ops_governance_remediation_tracker",
        resource_id=policy_key,
        status="success",
        detail={
            "policy_key": policy_key,
            "enabled": bool(policy.get("enabled", True)),
            "notify_enabled": bool(policy.get("notify_enabled", True)),
            "unassigned_trigger": int(policy.get("unassigned_trigger") or 0),
            "overdue_trigger": int(policy.get("overdue_trigger") or 0),
            "cooldown_minutes": int(policy.get("cooldown_minutes") or 0),
            "skip_if_no_action": bool(policy.get("skip_if_no_action", True)),
            "kpi_window_days": int(policy.get("kpi_window_days") or 0),
            "kpi_due_soon_hours": int(policy.get("kpi_due_soon_hours") or 0),
            "escalation_due_soon_hours": int(policy.get("escalation_due_soon_hours") or 0),
            "auto_assign_max_items": int(policy.get("auto_assign_max_items") or 0),
        },
    )
    return _build_policy_response_payload(
        policy_key=policy_key,
        updated_at=updated_at,
        policy=policy,
        scope="ops.governance.remediation.autopilot",
    )


@router.post("/governance/gate/remediation/tracker/autopilot/preview")
def preview_ops_governance_gate_remediation_tracker_autopilot(
    payload: dict[str, Any] | None = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    body = payload if isinstance(payload, dict) else {}
    current_policy, _, policy_key = _ensure_w26_remediation_autopilot_policy()
    policy_override = body.get("policy") if isinstance(body.get("policy"), dict) else {}
    effective_policy = _normalize_w26_remediation_autopilot_policy({**current_policy, **policy_override})
    force = bool(body.get("force", False))
    evaluation = _evaluate_w26_remediation_autopilot(
        force=force,
        policy=effective_policy,
    )
    checked_at = _as_optional_datetime(evaluation.get("checked_at")) or datetime.now(timezone.utc)
    guard = _build_w27_remediation_autopilot_guard_state(
        policy=effective_policy,
        now=checked_at,
        force=force,
    )
    metrics = evaluation.get("metrics", {}) if isinstance(evaluation.get("metrics"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_autopilot_preview",
        resource_type="ops_governance_remediation_tracker",
        resource_id=policy_key,
        status="success",
        detail={
            "force": force,
            "planned_actions": evaluation.get("planned_actions", []),
            "guard": guard,
            "open_items": int(metrics.get("open_items") or 0),
            "overdue_count": int(metrics.get("overdue_count") or 0),
            "unassigned_open_count": int(metrics.get("unassigned_open_count") or 0),
            "critical_open_count": int(metrics.get("critical_open_count") or 0),
        },
    )
    return {
        "policy_key": policy_key,
        "guard": guard,
        **evaluation,
    }


@router.get("/governance/gate/remediation/tracker/autopilot/guard")
def get_ops_governance_gate_remediation_tracker_autopilot_guard(
    force: Annotated[bool, Query()] = False,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    policy, updated_at, policy_key = _ensure_w26_remediation_autopilot_policy()
    now = datetime.now(timezone.utc)
    evaluation = _evaluate_w26_remediation_autopilot(
        force=force,
        policy=policy,
        now=now,
    )
    guard = _build_w27_remediation_autopilot_guard_state(
        policy=policy,
        now=now,
        force=force,
    )
    metrics = evaluation.get("metrics", {}) if isinstance(evaluation.get("metrics"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_autopilot_guard_view",
        resource_type="ops_governance_remediation_tracker",
        resource_id=policy_key,
        status="success",
        detail={
            "force": force,
            "ready": bool(guard.get("ready", True)),
            "blocked": bool(guard.get("blocked", False)),
            "reason": guard.get("reason"),
            "planned_actions": evaluation.get("planned_actions", []),
            "open_items": int(metrics.get("open_items") or 0),
            "overdue_count": int(metrics.get("overdue_count") or 0),
            "unassigned_open_count": int(metrics.get("unassigned_open_count") or 0),
            "critical_open_count": int(metrics.get("critical_open_count") or 0),
        },
    )
    return {
        "policy_key": policy_key,
        "policy_updated_at": updated_at.isoformat(),
        "policy": policy,
        "evaluation": evaluation,
        "guard": guard,
    }


@router.get("/governance/gate/remediation/tracker/autopilot/history")
def get_ops_governance_gate_remediation_tracker_autopilot_history(
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    payload = _build_w28_remediation_autopilot_history(limit=limit)
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_autopilot_history_view",
        resource_type="ops_governance_remediation_tracker",
        resource_id="autopilot_history",
        status="success",
        detail={
            "limit": int(payload.get("limit") or limit),
            "count": int(payload.get("count") or 0),
        },
    )
    return payload


@router.get("/governance/gate/remediation/tracker/autopilot/history.csv")
def get_ops_governance_gate_remediation_tracker_autopilot_history_csv(
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> Response:
    payload = _build_w28_remediation_autopilot_history(limit=limit)
    csv_text = _build_w29_remediation_autopilot_history_csv(payload)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    file_name = f"ops-governance-remediation-autopilot-history-{stamp}.csv"
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_autopilot_history_csv_export",
        resource_type="ops_governance_remediation_tracker",
        resource_id=file_name,
        status="success",
        detail={
            "limit": int(payload.get("limit") or limit),
            "count": int(payload.get("count") or 0),
        },
    )
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.get("/governance/gate/remediation/tracker/autopilot/summary")
def get_ops_governance_gate_remediation_tracker_autopilot_summary(
    days: Annotated[int, Query(ge=1, le=90)] = 7,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    payload = _build_w28_remediation_autopilot_summary(days=days)
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_autopilot_summary_view",
        resource_type="ops_governance_remediation_tracker",
        resource_id="autopilot_summary",
        status="success",
        detail={
            "window_days": int(payload.get("window_days") or days),
            "total_runs": int(payload.get("total_runs") or 0),
            "executed_runs": int(payload.get("executed_runs") or 0),
            "skipped_runs": int(payload.get("skipped_runs") or 0),
            "cooldown_blocked_runs": int(payload.get("cooldown_blocked_runs") or 0),
            "success_rate_percent": float(payload.get("success_rate_percent") or 0.0),
        },
    )
    return payload


@router.get("/governance/gate/remediation/tracker/autopilot/summary.csv")
def get_ops_governance_gate_remediation_tracker_autopilot_summary_csv(
    days: Annotated[int, Query(ge=1, le=90)] = 7,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> Response:
    payload = _build_w28_remediation_autopilot_summary(days=days)
    csv_text = _build_w29_remediation_autopilot_summary_csv(payload)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    file_name = f"ops-governance-remediation-autopilot-summary-{stamp}.csv"
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_autopilot_summary_csv_export",
        resource_type="ops_governance_remediation_tracker",
        resource_id=file_name,
        status="success",
        detail={
            "window_days": int(payload.get("window_days") or days),
            "total_runs": int(payload.get("total_runs") or 0),
            "executed_runs": int(payload.get("executed_runs") or 0),
            "skipped_runs": int(payload.get("skipped_runs") or 0),
            "cooldown_blocked_runs": int(payload.get("cooldown_blocked_runs") or 0),
            "success_rate_percent": float(payload.get("success_rate_percent") or 0.0),
        },
    )
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.get("/governance/gate/remediation/tracker/autopilot/anomalies")
def get_ops_governance_gate_remediation_tracker_autopilot_anomalies(
    days: Annotated[int, Query(ge=1, le=90)] = 14,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    payload = _build_w30_remediation_autopilot_anomalies(days=days)
    metrics = payload.get("metrics", {}) if isinstance(payload.get("metrics"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_autopilot_anomalies_view",
        resource_type="ops_governance_remediation_tracker",
        resource_id="autopilot_anomalies",
        status=str(payload.get("health_status") or "healthy"),
        detail={
            "window_days": int(payload.get("window_days") or days),
            "health_status": payload.get("health_status"),
            "anomaly_count": int(payload.get("anomaly_count") or 0),
            "total_runs": int(metrics.get("total_runs") or 0),
            "success_rate_percent": float(metrics.get("success_rate_percent") or 0.0),
            "skipped_rate_percent": float(metrics.get("skipped_rate_percent") or 0.0),
        },
    )
    return payload


@router.get("/governance/gate/remediation/tracker/autopilot/anomalies.csv")
def get_ops_governance_gate_remediation_tracker_autopilot_anomalies_csv(
    days: Annotated[int, Query(ge=1, le=90)] = 14,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> Response:
    payload = _build_w30_remediation_autopilot_anomalies(days=days)
    csv_text = _build_w30_remediation_autopilot_anomalies_csv(payload)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    file_name = f"ops-governance-remediation-autopilot-anomalies-{stamp}.csv"
    metrics = payload.get("metrics", {}) if isinstance(payload.get("metrics"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_autopilot_anomalies_csv_export",
        resource_type="ops_governance_remediation_tracker",
        resource_id=file_name,
        status=str(payload.get("health_status") or "healthy"),
        detail={
            "window_days": int(payload.get("window_days") or days),
            "health_status": payload.get("health_status"),
            "anomaly_count": int(payload.get("anomaly_count") or 0),
            "total_runs": int(metrics.get("total_runs") or 0),
            "success_rate_percent": float(metrics.get("success_rate_percent") or 0.0),
            "skipped_rate_percent": float(metrics.get("skipped_rate_percent") or 0.0),
        },
    )
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@router.get("/governance/gate/remediation/tracker/autopilot/latest")
def get_ops_governance_gate_remediation_tracker_autopilot_latest(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    payload = _latest_ops_governance_remediation_autopilot_payload()
    if payload is None:
        raise HTTPException(status_code=404, detail="No ops_governance_remediation_autopilot run found")
    metrics = payload.get("metrics", {}) if isinstance(payload.get("metrics"), dict) else {}
    _write_audit_log(
        principal=principal,
        action="ops_governance_remediation_tracker_autopilot_latest_view",
        resource_type="ops_governance_remediation_tracker",
        resource_id=str(payload.get("run_id") or "unknown"),
        status=str(payload.get("status") or "warning"),
        detail={
            "skipped": bool(payload.get("skipped", False)),
            "skip_reason": payload.get("skip_reason"),
            "planned_actions": payload.get("planned_actions", []),
            "actions": payload.get("actions", []),
            "guard": payload.get("guard", {}),
            "errors": payload.get("errors", []),
            "open_items": int(metrics.get("open_items") or 0),
            "overdue_count": int(metrics.get("overdue_count") or 0),
            "unassigned_open_count": int(metrics.get("unassigned_open_count") or 0),
            "critical_open_count": int(metrics.get("critical_open_count") or 0),
        },
    )
    return payload



