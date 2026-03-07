"""Alert delivery and SLA policy routes extracted from app.main."""

from __future__ import annotations

from app import main as main_module

APIRouter = main_module.APIRouter
globals().update({key: value for key, value in main_module.__dict__.items() if key not in {"router", "ops_router", "admin_router"}})
router = APIRouter(prefix="/api/ops", tags=["ops"])
ops_router = router
admin_router = APIRouter(prefix="/api/admin", tags=["admin"])

@router.get("/alerts/deliveries", response_model=list[AlertDeliveryRead])
def list_alert_deliveries(
    event_type: Annotated[str | None, Query()] = None,
    status: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=300)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    _: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> list[AlertDeliveryRead]:
    stmt = select(alert_deliveries).order_by(
        alert_deliveries.c.last_attempt_at.desc(),
        alert_deliveries.c.id.desc(),
    )
    if event_type is not None:
        stmt = stmt.where(alert_deliveries.c.event_type == event_type)
    if status is not None:
        stmt = stmt.where(alert_deliveries.c.status == status)
    stmt = stmt.limit(limit).offset(offset)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_alert_delivery_model(row) for row in rows]


@router.post("/alerts/webhook/internal", status_code=202)
def receive_internal_alert_webhook(
    payload: dict[str, Any],
    alert_webhook_token: Annotated[str | None, Header(alias=ALERT_WEBHOOK_TOKEN_HEADER)] = None,
) -> dict[str, Any]:
    shared_token = str(getattr(main_module, "ALERT_WEBHOOK_SHARED_TOKEN", "") or "")
    if shared_token:
        provided_token = alert_webhook_token or ""
        if not secrets.compare_digest(provided_token, shared_token):
            raise HTTPException(status_code=403, detail="Invalid internal alert webhook token")
    elif ENV_NAME not in {"local", "test"}:
        raise HTTPException(status_code=503, detail="Internal alert webhook token is not configured")

    event_type = str(payload.get("event_type") or payload.get("event") or "unknown").strip() or "unknown"
    return {
        "accepted": True,
        "event_type": event_type,
        "received_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/alerts/kpi/channels")
def get_alert_channel_kpi(
    event_type: Annotated[str | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    snapshot = _build_alert_channel_kpi_snapshot(event_type=event_type, windows=[7, 30])
    summaries = [
        {
            "days": int(item.get("days") or 0),
            "total_deliveries": int(item.get("total_deliveries") or 0),
            "success_rate_percent": float(item.get("success_rate_percent") or 0.0),
        }
        for item in snapshot.get("windows", [])
        if isinstance(item, dict)
    ]
    _write_audit_log(
        principal=principal,
        action="ops_alert_channel_kpi_view",
        resource_type="alert_delivery",
        resource_id=event_type or "all",
        detail={
            "event_type": event_type,
            "windows": summaries,
        },
    )
    return snapshot


@router.get("/alerts/kpi/mttr")
def get_alert_channel_mttr_kpi(
    event_type: Annotated[str | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    snapshot = _build_alert_channel_mttr_snapshot(event_type=event_type, windows=[7, 30])
    summaries = [
        {
            "days": int(item.get("days") or 0),
            "incident_count": int(item.get("incident_count") or 0),
            "recovered_incidents": int(item.get("recovered_incidents") or 0),
            "unresolved_incidents": int(item.get("unresolved_incidents") or 0),
            "mttr_minutes": item.get("mttr_minutes"),
        }
        for item in snapshot.get("windows", [])
        if isinstance(item, dict)
    ]
    _write_audit_log(
        principal=principal,
        action="ops_alert_channel_mttr_kpi_view",
        resource_type="alert_delivery",
        resource_id=event_type or "all",
        detail={
            "event_type": event_type,
            "windows": summaries,
        },
    )
    return snapshot


@router.get("/alerts/mttr-slo/policy")
def get_alert_mttr_slo_policy(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    policy, updated_at, policy_key = _ensure_mttr_slo_policy()
    _write_audit_log(
        principal=principal,
        action="ops_alert_mttr_slo_policy_view",
        resource_type="alert_policy",
        resource_id=policy_key,
        detail={
            "policy_key": policy_key,
            "enabled": bool(policy.get("enabled", True)),
            "window_days": int(policy.get("window_days") or 0),
            "threshold_minutes": int(policy.get("threshold_minutes") or 0),
            "min_incidents": int(policy.get("min_incidents") or 0),
        },
    )
    return _build_policy_response_payload(
        policy_key=policy_key,
        updated_at=updated_at,
        policy=policy,
        scope="ops.alerts.mttr_slo",
    )


@router.put("/alerts/mttr-slo/policy")
def set_alert_mttr_slo_policy(
    payload: dict[str, Any],
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    policy, updated_at, policy_key = _upsert_mttr_slo_policy(payload)
    _write_audit_log(
        principal=principal,
        action="ops_alert_mttr_slo_policy_update",
        resource_type="alert_policy",
        resource_id=policy_key,
        detail={
            "policy_key": policy_key,
            "enabled": bool(policy.get("enabled", True)),
            "window_days": int(policy.get("window_days") or 0),
            "threshold_minutes": int(policy.get("threshold_minutes") or 0),
            "min_incidents": int(policy.get("min_incidents") or 0),
            "auto_recover_enabled": bool(policy.get("auto_recover_enabled", True)),
            "recover_state": policy.get("recover_state"),
            "recover_max_targets": int(policy.get("recover_max_targets") or 0),
            "notify_enabled": bool(policy.get("notify_enabled", True)),
            "notify_event_type": policy.get("notify_event_type"),
            "notify_cooldown_minutes": int(policy.get("notify_cooldown_minutes") or 0),
        },
    )
    return _build_policy_response_payload(
        policy_key=policy_key,
        updated_at=updated_at,
        policy=policy,
        scope="ops.alerts.mttr_slo",
    )


@router.post("/alerts/mttr-slo/check/run")
def run_alert_mttr_slo_check(
    event_type: Annotated[str | None, Query()] = None,
    force_notify: Annotated[bool, Query()] = False,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    result = run_alert_mttr_slo_check_job(
        event_type=event_type,
        force_notify=force_notify,
        trigger="api",
    )
    _write_audit_log(
        principal=principal,
        action="ops_alert_mttr_slo_check_run",
        resource_type="alert_delivery",
        resource_id=str(result.get("run_id") or "pending"),
        status=str(result.get("status") or "success"),
        detail={
            "event_type": event_type,
            "force_notify": force_notify,
            "breach": bool(result.get("breach", False)),
            "window": result.get("window", {}),
            "actions": result.get("actions", {}),
        },
    )
    return result


@router.get("/alerts/mttr-slo/check/latest")
def get_alert_mttr_slo_check_latest(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == "alert_mttr_slo_check")
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="No alert_mttr_slo_check run found")

    model = _row_to_job_run_model(row)
    detail = model.detail if isinstance(model.detail, dict) else {}
    response = {
        "run_id": model.id,
        "job_name": model.job_name,
        "trigger": model.trigger,
        "status": model.status,
        "started_at": model.started_at.isoformat(),
        "finished_at": model.finished_at.isoformat(),
        "event_type": detail.get("event_type"),
        "policy_key": detail.get("policy_key"),
        "policy_updated_at": detail.get("policy_updated_at"),
        "policy": detail.get("policy", {}),
        "window": detail.get("window", {}),
        "breach": bool(detail.get("breach", False)),
        "top_channels": detail.get("top_channels", []),
        "actions": detail.get("actions", {}),
    }
    _write_audit_log(
        principal=principal,
        action="ops_alert_mttr_slo_check_latest_view",
        resource_type="alert_delivery",
        resource_id=str(model.id),
        detail={
            "run_id": model.id,
            "status": model.status,
            "breach": bool(response["breach"]),
        },
    )
    return response


@router.get("/alerts/channels/guard")
def get_alert_channel_guard(
    event_type: Annotated[str | None, Query()] = None,
    lookback_days: Annotated[int, Query(ge=1, le=90)] = 30,
    max_targets: Annotated[int, Query(ge=1, le=200)] = 100,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    snapshot = _build_alert_channel_guard_snapshot(
        event_type=event_type,
        lookback_days=lookback_days,
        max_targets=max_targets,
    )
    summary = snapshot.get("summary", {})
    _write_audit_log(
        principal=principal,
        action="ops_alert_channel_guard_view",
        resource_type="alert_delivery",
        resource_id=event_type or "all",
        detail={
            "event_type": event_type,
            "lookback_days": lookback_days,
            "max_targets": max_targets,
            "status": summary.get("status"),
            "target_count": summary.get("target_count"),
            "warning_count": summary.get("warning_count"),
            "quarantined_count": summary.get("quarantined_count"),
        },
    )
    return snapshot


@router.post("/alerts/channels/guard/recover")
def recover_alert_channel_guard(
    target: Annotated[str, Query(min_length=3, max_length=400)],
    event_type: Annotated[str | None, Query()] = None,
    note: Annotated[str | None, Query(max_length=300)] = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    normalized_target = target.strip()
    if not normalized_target:
        raise HTTPException(status_code=400, detail="target is required")

    now = datetime.now(timezone.utc)
    before = _compute_alert_channel_guard_state(
        normalized_target,
        now=now,
        event_type=event_type,
    )
    probe_payload = {
        "event": "alert_channel_recovery_probe",
        "target": normalized_target,
        "event_type_scope": event_type,
        "checked_at": now.isoformat(),
        "requested_by": str(principal.get("username") or "unknown"),
        "note": note or "",
    }
    target_kind = _detect_alert_target_kind(normalized_target)
    ok, err = main_module._post_json_with_retries(
        url=normalized_target,
        payload=_render_alert_payload_for_target(
            event_type=event_type or "alert_channel_recovery_probe",
            payload=probe_payload,
            target_kind=target_kind,
        ),
        retries=ALERT_WEBHOOK_RETRIES,
        timeout_sec=ALERT_WEBHOOK_TIMEOUT_SEC,
    )
    probe_event_type = event_type or "alert_channel_recovery_probe"
    probe_status = "success" if ok and err is None else ("warning" if ok else "failed")
    delivery_id = _write_alert_delivery(
        event_type=probe_event_type,
        target=normalized_target,
        status=probe_status,
        error=err,
        payload=_build_alert_delivery_record_payload(
            payload={**probe_payload, "probe": True},
            target_kind=target_kind,
        ),
    )
    after = _compute_alert_channel_guard_state(
        normalized_target,
        now=datetime.now(timezone.utc),
        event_type=event_type,
    )
    _write_audit_log(
        principal=principal,
        action="ops_alert_channel_guard_recover",
        resource_type="alert_delivery",
        resource_id=normalized_target,
        status=probe_status,
        detail={
            "target": normalized_target,
            "event_type": event_type,
            "probe_delivery_id": delivery_id,
            "probe_status": probe_status,
            "probe_error": err,
            "before_state": before.get("state"),
            "after_state": after.get("state"),
            "before_consecutive_failures": before.get("consecutive_failures"),
            "after_consecutive_failures": after.get("consecutive_failures"),
        },
    )
    return {
        "target": normalized_target,
        "target_kind": target_kind,
        "event_type": event_type,
        "probe_delivery_id": delivery_id,
        "probe_status": probe_status,
        "probe_error": err,
        "before": before,
        "after": after,
        "recommended_recovery_steps": [
            "1) 채널 endpoint 접근성/인증정보를 재확인합니다.",
            "2) guard/recover probe 결과가 success인지 확인합니다.",
            "3) /api/ops/alerts/channels/guard에서 state=healthy로 복귀했는지 확인합니다.",
        ],
    }


@router.post("/alerts/channels/guard/recover-batch")
def recover_alert_channel_guard_batch(
    event_type: Annotated[str | None, Query()] = None,
    state: Annotated[str, Query(pattern=r"^(quarantined|warning|all)$")] = "quarantined",
    max_targets: Annotated[int | None, Query(ge=1, le=500)] = None,
    dry_run: Annotated[bool, Query()] = False,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    result = run_alert_guard_recover_job(
        event_type=event_type,
        state_filter=state,
        max_targets=max_targets,
        dry_run=dry_run,
        trigger="api",
    )
    _write_audit_log(
        principal=principal,
        action="ops_alert_channel_guard_recover_batch",
        resource_type="alert_delivery",
        resource_id=str(result.get("run_id") or "pending"),
        status=str(result.get("status") or "success"),
        detail={
            "event_type": event_type,
            "state_filter": state,
            "max_targets": result.get("max_targets"),
            "dry_run": dry_run,
            "selected_target_count": result.get("selected_target_count"),
            "processed_count": result.get("processed_count"),
            "success_count": result.get("success_count"),
            "warning_count": result.get("warning_count"),
            "failed_count": result.get("failed_count"),
            "skipped_count": result.get("skipped_count"),
        },
    )
    return result


@router.get("/alerts/channels/guard/recover/latest")
def get_alert_channel_guard_recover_latest(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == "alert_guard_recover")
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="No alert_guard_recover run found")
    model = _row_to_job_run_model(row)
    detail = model.detail if isinstance(model.detail, dict) else {}
    response = {
        "run_id": model.id,
        "job_name": model.job_name,
        "trigger": model.trigger,
        "status": model.status,
        "started_at": model.started_at.isoformat(),
        "finished_at": model.finished_at.isoformat(),
        "event_type": detail.get("event_type"),
        "state_filter": detail.get("state_filter"),
        "max_targets": detail.get("max_targets"),
        "dry_run": bool(detail.get("dry_run", False)),
        "selected_target_count": int(detail.get("selected_target_count") or 0),
        "processed_count": int(detail.get("processed_count") or 0),
        "success_count": int(detail.get("success_count") or 0),
        "warning_count": int(detail.get("warning_count") or 0),
        "failed_count": int(detail.get("failed_count") or 0),
        "skipped_count": int(detail.get("skipped_count") or 0),
        "results": detail.get("results", []),
    }
    _write_audit_log(
        principal=principal,
        action="ops_alert_channel_guard_recover_latest_view",
        resource_type="alert_delivery",
        resource_id=str(model.id),
        detail={
            "run_id": model.id,
            "status": model.status,
            "processed_count": response["processed_count"],
            "failed_count": response["failed_count"],
        },
    )
    return response


@router.get("/alerts/retention/policy")
def get_alert_retention_policy(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    _write_audit_log(
        principal=principal,
        action="ops_alert_retention_policy_view",
        resource_type="alert_delivery",
        resource_id="policy",
        detail={
            "retention_days": main_module.ALERT_RETENTION_DAYS,
            "max_delete": ALERT_RETENTION_MAX_DELETE,
            "archive_enabled": main_module.ALERT_RETENTION_ARCHIVE_ENABLED,
            "archive_path": main_module.ALERT_RETENTION_ARCHIVE_PATH,
        },
    )
    return {
        "retention_days": max(1, main_module.ALERT_RETENTION_DAYS),
        "max_delete": max(1, ALERT_RETENTION_MAX_DELETE),
        "archive_enabled": main_module.ALERT_RETENTION_ARCHIVE_ENABLED,
        "archive_path": main_module.ALERT_RETENTION_ARCHIVE_PATH,
    }


@router.get("/alerts/retention/latest")
def get_alert_retention_latest(
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == "alert_retention")
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="No alert_retention run found")
    model = _row_to_job_run_model(row)
    detail = model.detail if isinstance(model.detail, dict) else {}
    response = {
        "run_id": model.id,
        "job_name": model.job_name,
        "trigger": model.trigger,
        "status": model.status,
        "started_at": model.started_at.isoformat(),
        "finished_at": model.finished_at.isoformat(),
        "retention_days": detail.get("retention_days"),
        "max_delete": detail.get("max_delete"),
        "dry_run": bool(detail.get("dry_run", False)),
        "write_archive": bool(detail.get("write_archive", False)),
        "candidate_count": int(detail.get("candidate_count") or 0),
        "deleted_count": int(detail.get("deleted_count") or 0),
        "archive_file": detail.get("archive_file"),
        "archive_error": detail.get("archive_error"),
        "cutoff": detail.get("cutoff"),
    }
    _write_audit_log(
        principal=principal,
        action="ops_alert_retention_latest_view",
        resource_type="alert_delivery",
        resource_id=str(model.id),
        detail={
            "run_id": model.id,
            "status": model.status,
            "deleted_count": response["deleted_count"],
            "archive_error": response["archive_error"],
        },
    )
    return response


@router.post("/alerts/retention/run")
def run_alert_retention(
    retention_days: Annotated[int | None, Query(ge=1, le=3650)] = None,
    max_delete: Annotated[int | None, Query(ge=1, le=50000)] = None,
    dry_run: Annotated[bool, Query()] = False,
    write_archive: Annotated[bool | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> dict[str, Any]:
    result = run_alert_retention_job(
        retention_days=retention_days,
        max_delete=max_delete,
        dry_run=dry_run,
        write_archive=write_archive,
        trigger="api",
    )
    _write_audit_log(
        principal=principal,
        action="ops_alert_retention_run",
        resource_type="alert_delivery",
        resource_id=str(result.get("run_id") or "pending"),
        status=str(result.get("status") or "success"),
        detail={
            "retention_days": result.get("retention_days"),
            "max_delete": result.get("max_delete"),
            "dry_run": result.get("dry_run"),
            "write_archive": result.get("write_archive"),
            "candidate_count": result.get("candidate_count"),
            "deleted_count": result.get("deleted_count"),
            "archive_file": result.get("archive_file"),
            "archive_error": result.get("archive_error"),
        },
    )
    return result


@router.post("/sla/simulate", response_model=SlaWhatIfResponse)
def simulate_sla(
    payload: SlaWhatIfRequest,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaWhatIfResponse:
    _require_site_access(principal, payload.site)
    allowed_sites = _allowed_sites_for_principal(principal) if payload.site is None else None
    result = simulate_sla_policy_change(
        policy=payload.policy,
        site=payload.site,
        limit=payload.limit,
        include_work_order_ids=payload.include_work_order_ids,
        sample_size=payload.sample_size,
        recompute_due_from_policy=payload.recompute_due_from_policy,
        allowed_sites=allowed_sites,
    )
    _write_audit_log(
        principal=principal,
        action="sla_policy_simulation_run",
        resource_type="sla_policy",
        resource_id=payload.site or "global",
        detail={
            "site": payload.site,
            "limit": payload.limit,
            "baseline_escalate_count": result.baseline_escalate_count,
            "simulated_escalate_count": result.simulated_escalate_count,
            "delta_escalate_count": result.delta_escalate_count,
        },
    )
    return result


@router.post("/alerts/retries/run", response_model=AlertRetryRunResponse)
def run_alert_retries(
    payload: AlertRetryRunRequest,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> AlertRetryRunResponse:
    result = run_alert_retry_job(
        event_type=payload.event_type,
        only_status=payload.only_status,
        limit=payload.limit,
        max_attempt_count=payload.max_attempt_count,
        min_last_attempt_age_sec=payload.min_last_attempt_age_sec,
        trigger="api",
    )
    _write_audit_log(
        principal=principal,
        action="alert_retry_batch_run",
        resource_type="alert_delivery",
        resource_id="batch",
        detail={
            "event_type": payload.event_type,
            "statuses": payload.only_status,
            "limit": payload.limit,
            "processed_count": result.processed_count,
            "failed_count": result.failed_count,
        },
    )
    return result


@admin_router.post("/policies/sla/proposals", response_model=SlaPolicyProposalRead, status_code=201)
def create_sla_policy_proposal(
    payload: SlaPolicyProposalCreate,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaPolicyProposalRead:
    now = datetime.now(timezone.utc)
    normalized_site = _normalize_site_name(payload.site)
    if normalized_site is None:
        _require_global_site_scope(principal)
    else:
        _require_site_access(principal, normalized_site)

    allowed_sites = _allowed_sites_for_principal(principal) if normalized_site is None else None
    simulation = simulate_sla_policy_change(
        policy=payload.policy,
        site=normalized_site,
        limit=payload.simulation_limit,
        include_work_order_ids=payload.include_work_order_ids,
        sample_size=payload.sample_size,
        recompute_due_from_policy=payload.recompute_due_from_policy,
        allowed_sites=allowed_sites,
    )
    requested_by = str(principal.get("username") or "unknown")

    with get_conn() as conn:
        result = conn.execute(
            insert(sla_policy_proposals).values(
                site=normalized_site,
                policy_json=_to_json_text(_normalize_sla_policy(payload.policy.model_dump())),
                simulation_json=_to_json_text(simulation.model_dump()),
                note=payload.note or "",
                status=SLA_PROPOSAL_STATUS_PENDING,
                requested_by=requested_by,
                decided_by=None,
                decision_note=None,
                created_at=now,
                decided_at=None,
                applied_at=None,
            )
        )
        proposal_id = int(result.inserted_primary_key[0])
        row = conn.execute(
            select(sla_policy_proposals).where(sla_policy_proposals.c.id == proposal_id)
        ).mappings().first()

    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create SLA policy proposal")
    model = _row_to_sla_policy_proposal_model(row)
    _write_audit_log(
        principal=principal,
        action="sla_policy_proposal_create",
        resource_type="sla_policy_proposal",
        resource_id=str(model.id),
        detail={
            "site": model.site,
            "status": model.status,
            "baseline_escalate_count": simulation.baseline_escalate_count,
            "simulated_escalate_count": simulation.simulated_escalate_count,
            "delta_escalate_count": simulation.delta_escalate_count,
        },
    )
    return model


@admin_router.get("/policies/sla/proposals", response_model=list[SlaPolicyProposalRead])
def list_sla_policy_proposals(
    site: Annotated[str | None, Query()] = None,
    status: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=300)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> list[SlaPolicyProposalRead]:
    normalized_site = _normalize_site_name(site)
    if normalized_site is not None:
        _require_site_access(principal, normalized_site)

    stmt = select(sla_policy_proposals).order_by(
        sla_policy_proposals.c.created_at.desc(),
        sla_policy_proposals.c.id.desc(),
    )
    if normalized_site is not None:
        stmt = stmt.where(sla_policy_proposals.c.site == normalized_site)
    else:
        allowed_sites = _allowed_sites_for_principal(principal)
        if allowed_sites is not None:
            if not allowed_sites:
                return []
            stmt = stmt.where(sla_policy_proposals.c.site.in_(allowed_sites))
    if status is not None:
        stmt = stmt.where(sla_policy_proposals.c.status == status)
    stmt = stmt.limit(limit).offset(offset)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_sla_policy_proposal_model(row) for row in rows]


@admin_router.get("/policies/sla/proposals/{proposal_id}", response_model=SlaPolicyProposalRead)
def get_sla_policy_proposal(
    proposal_id: int,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaPolicyProposalRead:
    with get_conn() as conn:
        row = conn.execute(
            select(sla_policy_proposals).where(sla_policy_proposals.c.id == proposal_id)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="SLA policy proposal not found")

    proposal_site = row["site"]
    if proposal_site is None:
        _require_global_site_scope(principal)
    else:
        _require_site_access(principal, str(proposal_site))
    return _row_to_sla_policy_proposal_model(row)


@admin_router.post("/policies/sla/proposals/{proposal_id}/approve", response_model=SlaPolicyProposalRead)
def approve_sla_policy_proposal(
    proposal_id: int,
    payload: SlaPolicyProposalDecision,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaPolicyProposalRead:
    now = datetime.now(timezone.utc)
    decided_by = str(principal.get("username") or "unknown")

    with get_conn() as conn:
        row = conn.execute(
            select(sla_policy_proposals).where(sla_policy_proposals.c.id == proposal_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="SLA policy proposal not found")

        proposal_site = row["site"]
        if proposal_site is None:
            _require_global_site_scope(principal)
        else:
            _require_site_access(principal, str(proposal_site))

        if str(row["status"]) != SLA_PROPOSAL_STATUS_PENDING:
            raise HTTPException(status_code=409, detail="Only pending proposal can be approved")
        if str(row["requested_by"]) == decided_by:
            raise HTTPException(status_code=409, detail="Proposal cannot be self-approved")

    policy_raw = str(row["policy_json"] or "{}")
    try:
        policy_dict = json.loads(policy_raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="Invalid proposal policy payload") from exc
    if not isinstance(policy_dict, dict):
        raise HTTPException(status_code=500, detail="Invalid proposal policy payload")

    policy_model = SlaPolicyUpdate(**policy_dict)
    applied_policy = _upsert_sla_policy(
        policy_model,
        site=row["site"],
        source_action="proposal_approval",
        actor_username=decided_by,
        note=f"proposal_id={proposal_id}; {payload.note or ''}".strip(),
    )

    with get_conn() as conn:
        conn.execute(
            update(sla_policy_proposals)
            .where(sla_policy_proposals.c.id == proposal_id)
            .values(
                status=SLA_PROPOSAL_STATUS_APPROVED,
                decided_by=decided_by,
                decision_note=payload.note or "",
                decided_at=now,
                applied_at=now,
            )
        )
        updated_row = conn.execute(
            select(sla_policy_proposals).where(sla_policy_proposals.c.id == proposal_id)
        ).mappings().first()

    if updated_row is None:
        raise HTTPException(status_code=500, detail="Failed to approve SLA policy proposal")
    model = _row_to_sla_policy_proposal_model(updated_row)
    _write_audit_log(
        principal=principal,
        action="sla_policy_proposal_approve",
        resource_type="sla_policy_proposal",
        resource_id=str(model.id),
        detail={
            "site": model.site,
            "status": model.status,
            "applied_policy_key": applied_policy.policy_key,
            "decision_note": payload.note,
        },
    )
    return model


@admin_router.post("/policies/sla/proposals/{proposal_id}/reject", response_model=SlaPolicyProposalRead)
def reject_sla_policy_proposal(
    proposal_id: int,
    payload: SlaPolicyProposalDecision,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaPolicyProposalRead:
    now = datetime.now(timezone.utc)
    decided_by = str(principal.get("username") or "unknown")

    with get_conn() as conn:
        row = conn.execute(
            select(sla_policy_proposals).where(sla_policy_proposals.c.id == proposal_id)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="SLA policy proposal not found")

        proposal_site = row["site"]
        if proposal_site is None:
            _require_global_site_scope(principal)
        else:
            _require_site_access(principal, str(proposal_site))

        if str(row["status"]) != SLA_PROPOSAL_STATUS_PENDING:
            raise HTTPException(status_code=409, detail="Only pending proposal can be rejected")

        conn.execute(
            update(sla_policy_proposals)
            .where(sla_policy_proposals.c.id == proposal_id)
            .values(
                status=SLA_PROPOSAL_STATUS_REJECTED,
                decided_by=decided_by,
                decision_note=payload.note or "",
                decided_at=now,
                applied_at=None,
            )
        )
        updated_row = conn.execute(
            select(sla_policy_proposals).where(sla_policy_proposals.c.id == proposal_id)
        ).mappings().first()

    if updated_row is None:
        raise HTTPException(status_code=500, detail="Failed to reject SLA policy proposal")
    model = _row_to_sla_policy_proposal_model(updated_row)
    _write_audit_log(
        principal=principal,
        action="sla_policy_proposal_reject",
        resource_type="sla_policy_proposal",
        resource_id=str(model.id),
        detail={"site": model.site, "status": model.status, "decision_note": payload.note},
    )
    return model


@router.post("/alerts/deliveries/{delivery_id}/retry", response_model=AlertDeliveryRead)
def retry_alert_delivery(
    delivery_id: int,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> AlertDeliveryRead:
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(alert_deliveries).where(alert_deliveries.c.id == delivery_id).limit(1)
        ).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="Alert delivery not found")

        payload_raw = str(row["payload_json"] or "{}")
        try:
            payload = json.loads(payload_raw)
        except json.JSONDecodeError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}

        ok, err = main_module._post_json_with_retries(
            url=str(row["target"]),
            payload=payload,
            retries=ALERT_WEBHOOK_RETRIES,
            timeout_sec=ALERT_WEBHOOK_TIMEOUT_SEC,
        )
        next_status = "success" if ok and err is None else ("warning" if ok else "failed")
        next_attempt_count = int(row["attempt_count"]) + 1
        conn.execute(
            update(alert_deliveries)
            .where(alert_deliveries.c.id == delivery_id)
            .values(
                status=next_status,
                error=err,
                attempt_count=next_attempt_count,
                last_attempt_at=now,
                updated_at=now,
            )
        )
        updated_row = conn.execute(
            select(alert_deliveries).where(alert_deliveries.c.id == delivery_id).limit(1)
        ).mappings().first()

    if updated_row is None:
        raise HTTPException(status_code=500, detail="Failed to retry alert delivery")
    model = _row_to_alert_delivery_model(updated_row)
    _write_audit_log(
        principal=principal,
        action="alert_delivery_retry",
        resource_type="alert_delivery",
        resource_id=str(model.id),
        status=model.status,
        detail={"target": model.target, "status": model.status, "attempt_count": model.attempt_count},
    )
    return model


@admin_router.get("/policies/sla", response_model=SlaPolicyRead)
def get_sla_policy(
    site: Annotated[str | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaPolicyRead:
    _require_site_access(principal, site)
    policy, updated_at, source, resolved_site, policy_key = _load_sla_policy(site=site)
    return _sla_policy_to_model(
        policy_key=policy_key,
        site=resolved_site,
        source=source,
        updated_at=updated_at,
        policy=policy,
    )


@admin_router.put("/policies/sla", response_model=SlaPolicyRead)
def set_sla_policy(
    payload: SlaPolicyUpdate,
    site: Annotated[str | None, Query()] = None,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaPolicyRead:
    if site is None:
        _require_global_site_scope(principal)
    else:
        _require_site_access(principal, site)
    actor_username = str(principal.get("username") or "unknown")
    model = _upsert_sla_policy(
        payload,
        site=site,
        source_action="manual_update",
        actor_username=actor_username,
        note="direct policy update",
    )
    _write_audit_log(
        principal=principal,
        action="sla_policy_update",
        resource_type="sla_policy",
        resource_id=model.policy_key,
        detail={
            "site": model.site,
            "source": model.source,
            "default_due_hours": model.default_due_hours,
            "escalation_grace_minutes": model.escalation_grace_minutes,
        },
    )
    return model


@admin_router.get("/policies/sla/revisions", response_model=list[SlaPolicyRevisionRead])
def list_sla_policy_revisions(
    site: Annotated[str | None, Query()] = None,
    source_action: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> list[SlaPolicyRevisionRead]:
    normalized_site = _normalize_site_name(site)
    if normalized_site is not None:
        _require_site_access(principal, normalized_site)

    stmt = select(sla_policy_revisions).order_by(
        sla_policy_revisions.c.created_at.desc(),
        sla_policy_revisions.c.id.desc(),
    )
    if normalized_site is not None:
        stmt = stmt.where(sla_policy_revisions.c.site == normalized_site)
    else:
        allowed_sites = _allowed_sites_for_principal(principal)
        if allowed_sites is not None:
            if not allowed_sites:
                return []
            stmt = stmt.where(sla_policy_revisions.c.site.in_(allowed_sites))
    if source_action is not None:
        stmt = stmt.where(sla_policy_revisions.c.source_action == source_action)
    stmt = stmt.limit(limit).offset(offset)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_sla_policy_revision_model(row) for row in rows]


@admin_router.post("/policies/sla/revisions/{revision_id}/restore", response_model=SlaPolicyRead)
def restore_sla_policy_revision(
    revision_id: int,
    payload: SlaPolicyRestoreRequest,
    principal: dict[str, Any] = Depends(require_permission("admins:manage")),
) -> SlaPolicyRead:
    with get_conn() as conn:
        row = conn.execute(
            select(sla_policy_revisions).where(sla_policy_revisions.c.id == revision_id)
        ).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="SLA policy revision not found")

    revision_site = row["site"]
    if revision_site is None:
        _require_global_site_scope(principal)
    else:
        _require_site_access(principal, str(revision_site))

    raw_policy = str(row["policy_json"] or "{}")
    try:
        policy_dict = json.loads(raw_policy)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="Invalid revision policy payload") from exc
    if not isinstance(policy_dict, dict):
        raise HTTPException(status_code=500, detail="Invalid revision policy payload")

    policy_model = SlaPolicyUpdate(**policy_dict)
    actor_username = str(principal.get("username") or "unknown")
    model = _upsert_sla_policy(
        policy_model,
        site=revision_site,
        source_action="revision_restore",
        actor_username=actor_username,
        note=f"revision_id={revision_id}; {payload.note or ''}".strip(),
    )
    _write_audit_log(
        principal=principal,
        action="sla_policy_restore",
        resource_type="sla_policy_revision",
        resource_id=str(revision_id),
        detail={
            "site": revision_site,
            "policy_key": model.policy_key,
            "decision_note": payload.note,
        },
    )
    return model



































































