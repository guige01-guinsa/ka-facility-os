"""OPS record and row-model helpers extracted from app.main."""

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
    "_write_job_run",
    "_row_to_job_run_model",
    "_write_alert_delivery",
    "_row_to_alert_delivery_model",
    "_row_to_sla_policy_proposal_model",
    "_write_sla_policy_revision",
    "_row_to_sla_policy_revision_model",
}


def bind(namespace: dict[str, object]) -> None:
    for key, value in namespace.items():
        if key not in _LOCAL_SYMBOLS:
            globals()[key] = value


def _write_job_run(
    *,
    job_name: str,
    trigger: str,
    status: str,
    started_at: datetime,
    finished_at: datetime,
    detail: dict[str, Any] | None = None,
) -> int | None:
    try:
        with get_conn() as conn:
            result = conn.execute(
                insert(job_runs).values(
                    job_name=job_name,
                    trigger=trigger,
                    status=status,
                    started_at=started_at,
                    finished_at=finished_at,
                    detail_json=_to_json_text(detail),
                )
            )
            return int(result.inserted_primary_key[0])
    except SQLAlchemyError:
        return None


def _row_to_job_run_model(row: dict[str, Any]) -> JobRunRead:
    raw = str(row["detail_json"] or "{}")
    try:
        detail = json.loads(raw)
    except json.JSONDecodeError:
        detail = {"raw": raw}
    if not isinstance(detail, dict):
        detail = {"value": detail}

    return JobRunRead(
        id=int(row["id"]),
        job_name=str(row["job_name"]),
        trigger=str(row["trigger"]),
        status=str(row["status"]),
        started_at=_as_datetime(row["started_at"]),
        finished_at=_as_datetime(row["finished_at"]),
        detail=detail,
    )


def _write_alert_delivery(
    *,
    event_type: str,
    target: str,
    status: str,
    error: str | None,
    payload: dict[str, Any],
) -> int | None:
    now = datetime.now(timezone.utc)
    try:
        with get_conn() as conn:
            result = conn.execute(
                insert(alert_deliveries).values(
                    event_type=event_type,
                    target=target,
                    status=status,
                    error=error,
                    payload_json=_to_json_text(payload),
                    attempt_count=1,
                    last_attempt_at=now,
                    created_at=now,
                    updated_at=now,
                )
            )
            return int(result.inserted_primary_key[0])
    except SQLAlchemyError:
        return None


def _row_to_alert_delivery_model(row: dict[str, Any]) -> AlertDeliveryRead:
    raw = str(row["payload_json"] or "{}")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = {"raw": raw}
    if not isinstance(payload, dict):
        payload = {"value": payload}

    return AlertDeliveryRead(
        id=int(row["id"]),
        event_type=str(row["event_type"]),
        target=str(row["target"]),
        status=str(row["status"]),
        error=row["error"],
        payload=payload,
        attempt_count=int(row["attempt_count"]),
        last_attempt_at=_as_datetime(row["last_attempt_at"]),
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _row_to_sla_policy_proposal_model(row: dict[str, Any]) -> SlaPolicyProposalRead:
    policy_raw = str(row["policy_json"] or "{}")
    simulation_raw = str(row["simulation_json"] or "{}")
    try:
        policy = json.loads(policy_raw)
    except json.JSONDecodeError:
        policy = {"raw": policy_raw}
    if not isinstance(policy, dict):
        policy = {"value": policy}

    try:
        simulation = json.loads(simulation_raw)
    except json.JSONDecodeError:
        simulation = {"raw": simulation_raw}
    if not isinstance(simulation, dict):
        simulation = {"value": simulation}

    return SlaPolicyProposalRead(
        id=int(row["id"]),
        site=row["site"],
        status=str(row["status"]),
        policy=policy,
        simulation=simulation,
        note=str(row["note"] or ""),
        requested_by=str(row["requested_by"]),
        decided_by=row["decided_by"],
        decision_note=row["decision_note"],
        created_at=_as_datetime(row["created_at"]),
        decided_at=_as_optional_datetime(row["decided_at"]),
        applied_at=_as_optional_datetime(row["applied_at"]),
    )


def _write_sla_policy_revision(
    *,
    site: str | None,
    policy: dict[str, Any],
    source_action: str,
    actor_username: str,
    note: str = "",
) -> None:
    now = datetime.now(timezone.utc)
    try:
        with get_conn() as conn:
            conn.execute(
                insert(sla_policy_revisions).values(
                    site=site,
                    policy_json=_to_json_text(policy),
                    source_action=source_action,
                    actor_username=actor_username,
                    note=note,
                    created_at=now,
                )
            )
    except SQLAlchemyError:
        return


def _row_to_sla_policy_revision_model(row: dict[str, Any]) -> SlaPolicyRevisionRead:
    raw = str(row["policy_json"] or "{}")
    try:
        policy = json.loads(raw)
    except json.JSONDecodeError:
        policy = {"raw": raw}
    if not isinstance(policy, dict):
        policy = {"value": policy}

    return SlaPolicyRevisionRead(
        id=int(row["id"]),
        site=row["site"],
        policy=policy,
        source_action=str(row["source_action"]),
        actor_username=str(row["actor_username"]),
        note=str(row["note"] or ""),
        created_at=_as_datetime(row["created_at"]),
    )
