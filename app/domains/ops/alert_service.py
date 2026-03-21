"""Alert policy, dispatch, and analytics helpers extracted from app.main."""

from __future__ import annotations

import csv
import io
import json
import math
import time
import urllib.error as url_error
import urllib.parse as url_parse
import urllib.request as url_request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import delete, insert, select, update

from app.database import alert_deliveries, get_conn, job_runs, sla_policies
from app.domains.ops import config as ops_config
from app.domains.ops.inspection_service import _as_datetime, _as_optional_datetime
from app.domains.ops.record_service import _to_json_text, _write_alert_delivery, _write_job_run
from app.schemas import SlaAlertChannelResult

_LOCAL_SYMBOLS = {
    "_normalize_mttr_slo_recover_state",
    "_default_mttr_slo_policy",
    "_legacy_mttr_slo_policy",
    "_normalize_mttr_slo_policy",
    "_parse_mttr_slo_policy_json",
    "_ensure_mttr_slo_policy",
    "_upsert_mttr_slo_policy",
    "_latest_mttr_slo_breach_finished_at",
    "_detect_alert_target_kind",
    "_parse_alert_target_spec",
    "_configured_alert_target_configs",
    "_configured_alert_targets",
    "_build_alert_webhook_request_headers",
    "_truncate_alert_text",
    "_humanize_alert_event_type",
    "_build_alert_message_summary",
    "_render_alert_payload_for_target",
    "_build_alert_delivery_record_payload",
    "_normalize_ops_daily_check_alert_level",
    "_is_alert_failure_status",
    "_compute_alert_channel_guard_state",
    "_build_alert_channel_guard_snapshot",
    "_build_alert_delivery_archive_csv",
    "run_alert_retention_job",
    "run_alert_guard_recover_job",
    "run_alert_mttr_slo_check_job",
    "_post_json_with_retries",
    "_dispatch_alert_event",
    "_dispatch_sla_alert",
    "_build_alert_channel_kpi_snapshot",
    "_compute_recovery_minutes_stats",
    "_build_alert_channel_mttr_snapshot",
    "bind",
    "main_module",
    "_LOCAL_SYMBOLS",
}


def bind(namespace: dict[str, object]) -> None:
    return None


ops_runtime = ops_config.runtime

def _normalize_mttr_slo_recover_state(value: str | None) -> str:
    normalized = (value or "").strip().lower()
    if normalized in ops_runtime.ALERT_MTTR_SLO_RECOVER_STATE_SET:
        return normalized
    return "quarantined"

def _default_mttr_slo_policy() -> dict[str, Any]:
    return {
        "enabled": ops_runtime.ALERT_MTTR_SLO_ENABLED,
        "window_days": max(1, ops_runtime.ALERT_MTTR_SLO_WINDOW_DAYS),
        "threshold_minutes": max(1, ops_runtime.ALERT_MTTR_SLO_THRESHOLD_MINUTES),
        "min_incidents": max(1, ops_runtime.ALERT_MTTR_SLO_MIN_INCIDENTS),
        "auto_recover_enabled": ops_runtime.ALERT_MTTR_SLO_AUTO_RECOVER_ENABLED,
        "recover_state": _normalize_mttr_slo_recover_state(ops_runtime.ALERT_MTTR_SLO_RECOVER_STATE),
        "recover_max_targets": max(1, min(ops_runtime.ALERT_MTTR_SLO_RECOVER_MAX_TARGETS, 500)),
        "notify_enabled": ops_runtime.ALERT_MTTR_SLO_NOTIFY_ENABLED,
        "notify_event_type": ops_runtime.ALERT_MTTR_SLO_NOTIFY_EVENT_TYPE[:80],
        "notify_cooldown_minutes": max(0, min(ops_runtime.ALERT_MTTR_SLO_NOTIFY_COOLDOWN_MINUTES, 10080)),
        "top_channels": max(1, min(ops_runtime.ALERT_MTTR_SLO_TOP_CHANNELS, 50)),
    }

def _legacy_mttr_slo_policy() -> dict[str, Any]:
    # Legacy baseline before operational tuning (kept for safe one-time upgrade).
    return {
        "enabled": True,
        "window_days": 30,
        "threshold_minutes": 60,
        "min_incidents": 3,
        "auto_recover_enabled": True,
        "recover_state": "quarantined",
        "recover_max_targets": 30,
        "notify_enabled": True,
        "notify_event_type": "mttr_slo_breach",
        "notify_cooldown_minutes": 180,
        "top_channels": 10,
    }

def _normalize_mttr_slo_policy(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    defaults = _default_mttr_slo_policy()

    def _to_int(raw: Any, fallback: int, *, min_value: int, max_value: int) -> int:
        try:
            parsed = int(raw)
        except (TypeError, ValueError):
            parsed = fallback
        return max(min_value, min(parsed, max_value))

    notify_event_type = str(source.get("notify_event_type", defaults["notify_event_type"]) or "").strip()
    if not notify_event_type:
        notify_event_type = str(defaults["notify_event_type"])

    return {
        "enabled": bool(source.get("enabled", defaults["enabled"])),
        "window_days": _to_int(source.get("window_days"), int(defaults["window_days"]), min_value=1, max_value=90),
        "threshold_minutes": _to_int(
            source.get("threshold_minutes"),
            int(defaults["threshold_minutes"]),
            min_value=1,
            max_value=10080,
        ),
        "min_incidents": _to_int(source.get("min_incidents"), int(defaults["min_incidents"]), min_value=1, max_value=100000),
        "auto_recover_enabled": bool(source.get("auto_recover_enabled", defaults["auto_recover_enabled"])),
        "recover_state": _normalize_mttr_slo_recover_state(str(source.get("recover_state", defaults["recover_state"]))),
        "recover_max_targets": _to_int(
            source.get("recover_max_targets"),
            int(defaults["recover_max_targets"]),
            min_value=1,
            max_value=500,
        ),
        "notify_enabled": bool(source.get("notify_enabled", defaults["notify_enabled"])),
        "notify_event_type": notify_event_type[:80],
        "notify_cooldown_minutes": _to_int(
            source.get("notify_cooldown_minutes"),
            int(defaults["notify_cooldown_minutes"]),
            min_value=0,
            max_value=10080,
        ),
        "top_channels": _to_int(source.get("top_channels"), int(defaults["top_channels"]), min_value=1, max_value=50),
    }

def _parse_mttr_slo_policy_json(raw: Any) -> dict[str, Any]:
    try:
        loaded = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        loaded = {}
    return _normalize_mttr_slo_policy(loaded)

def _ensure_mttr_slo_policy() -> tuple[dict[str, Any], datetime, str]:
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(sla_policies).where(sla_policies.c.policy_key == ops_runtime.ALERT_MTTR_SLO_POLICY_KEY).limit(1)
        ).mappings().first()
        if row is None:
            policy = _default_mttr_slo_policy()
            conn.execute(
                insert(sla_policies).values(
                    policy_key=ops_runtime.ALERT_MTTR_SLO_POLICY_KEY,
                    policy_json=_to_json_text(policy),
                    updated_at=now,
                )
            )
            return policy, now, ops_runtime.ALERT_MTTR_SLO_POLICY_KEY

    policy = _parse_mttr_slo_policy_json(row["policy_json"])
    default_policy = _default_mttr_slo_policy()
    if policy == _legacy_mttr_slo_policy() and policy != default_policy:
        with get_conn() as conn:
            conn.execute(
                update(sla_policies)
                .where(sla_policies.c.policy_key == ops_runtime.ALERT_MTTR_SLO_POLICY_KEY)
                .values(
                    policy_json=_to_json_text(default_policy),
                    updated_at=now,
                )
            )
        return default_policy, now, ops_runtime.ALERT_MTTR_SLO_POLICY_KEY

    updated_at = _as_datetime(row["updated_at"]) if row["updated_at"] is not None else now
    return policy, updated_at, ops_runtime.ALERT_MTTR_SLO_POLICY_KEY

def _upsert_mttr_slo_policy(payload: dict[str, Any]) -> tuple[dict[str, Any], datetime, str]:
    current_policy, _, policy_key = _ensure_mttr_slo_policy()
    merged = {**current_policy, **(payload if isinstance(payload, dict) else {})}
    normalized = _normalize_mttr_slo_policy(merged)
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

def _latest_mttr_slo_breach_finished_at(max_rows: int = 50) -> datetime | None:
    with get_conn() as conn:
        rows = conn.execute(
            select(job_runs.c.finished_at, job_runs.c.detail_json)
            .where(job_runs.c.job_name == "alert_mttr_slo_check")
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(max(1, min(max_rows, 500)))
        ).mappings().all()
    for row in rows:
        raw = str(row.get("detail_json") or "{}")
        try:
            detail = json.loads(raw)
        except json.JSONDecodeError:
            detail = {}
        if not isinstance(detail, dict):
            continue
        if bool(detail.get("breach")):
            finished_at = _as_optional_datetime(row.get("finished_at"))
            if finished_at is not None:
                return finished_at
    return None

def _detect_alert_target_kind(url: str) -> str:
    host = (url_parse.urlparse(url).hostname or "").strip().lower()
    if host.endswith("hooks.slack.com") or host.endswith("hooks.slack-gov.com"):
        return "slack"
    if (
        host.endswith("webhook.office.com")
        or host.endswith("office.com")
        or host.endswith("logic.azure.com")
        or host.endswith("powerautomate.com")
    ):
        return "teams"
    return "generic"

def _parse_alert_target_spec(raw_value: str) -> dict[str, str] | None:
    value = raw_value.strip()
    if not value:
        return None

    kind = ""
    url = value
    if "::" in value:
        prefix, remainder = value.split("::", 1)
        normalized_prefix = prefix.strip().lower()
        if normalized_prefix in {"generic", "slack", "teams"}:
            kind = normalized_prefix
            url = remainder.strip()
    if not url:
        return None
    if not kind:
        kind = _detect_alert_target_kind(url)
    return {
        "raw": value,
        "url": url,
        "kind": kind,
    }

def _configured_alert_target_configs() -> list[dict[str, str]]:
    target_specs: list[str] = []
    merged_raw = ops_runtime.ALERT_WEBHOOK_URLS.replace(";", ",").replace("\n", ",")
    for part in merged_raw.split(","):
        value = part.strip()
        if value:
            target_specs.append(value)
    if ops_runtime.ALERT_WEBHOOK_URL:
        target_specs.append(ops_runtime.ALERT_WEBHOOK_URL)

    configs: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    for item in target_specs:
        parsed = _parse_alert_target_spec(item)
        if parsed is None:
            continue
        target_url = parsed["url"]
        if target_url in seen_urls:
            continue
        seen_urls.add(target_url)
        configs.append(parsed)
    return configs

def _configured_alert_targets() -> list[str]:
    return [item["url"] for item in _configured_alert_target_configs()]

def _build_alert_webhook_request_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if ops_runtime.ALERT_WEBHOOK_SHARED_TOKEN:
        headers[ops_runtime.ALERT_WEBHOOK_TOKEN_HEADER] = ops_runtime.ALERT_WEBHOOK_SHARED_TOKEN
    return headers

def _truncate_alert_text(value: Any, max_length: int = 240) -> str:
    text = str(value).strip()
    if len(text) <= max_length:
        return text
    return text[: max(0, max_length - 3)].rstrip() + "..."

def _humanize_alert_event_type(event_type: str) -> str:
    normalized = event_type.strip().lower()
    titles = {
        "sla_escalation": "SLA escalation alert",
        ops_runtime.W07_DEGRADATION_ALERT_EVENT_TYPE: "W07 quality degradation alert",
        "ops_daily_check": "Ops daily check alert",
        "mttr_slo_breach": "Alert MTTR SLO breach",
        ops_runtime.OPS_GOVERNANCE_REMEDIATION_ESCALATION_EVENT_TYPE: "Governance remediation escalation",
        "alert_channel_recovery_probe": "Alert channel recovery probe",
    }
    if normalized in titles:
        return titles[normalized]
    return normalized.replace("_", " ").strip().title() or "Alert event"

def _build_alert_message_summary(event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    title = _humanize_alert_event_type(event_type)
    facts: list[tuple[str, str]] = []

    def add_fact(label: str, value: Any) -> None:
        if value is None or value == "" or value == [] or value == {}:
            return
        if isinstance(value, list):
            rendered = ", ".join(_truncate_alert_text(item, 40) for item in value[:10])
            if len(value) > 10:
                rendered += f" (+{len(value) - 10} more)"
        elif isinstance(value, dict):
            rendered = _truncate_alert_text(json.dumps(value, ensure_ascii=False, sort_keys=True), 180)
        else:
            rendered = _truncate_alert_text(value, 180)
        if rendered:
            facts.append((label, rendered))

    add_fact("Event", title)
    add_fact("Site", payload.get("site"))
    add_fact("Checked at", payload.get("checked_at"))
    add_fact("Status", payload.get("overall_status") or payload.get("status"))
    add_fact("Escalated", payload.get("escalated_count"))
    add_fact("Work orders", payload.get("work_order_ids"))

    window = payload.get("window")
    if isinstance(window, dict):
        add_fact("Window days", window.get("days"))
        add_fact("Incident count", window.get("incident_count"))
        add_fact("MTTR (min)", window.get("mttr_minutes"))

    policy = payload.get("policy")
    if isinstance(policy, dict):
        add_fact("Policy key", policy.get("policy_key"))
        add_fact("Threshold (min)", policy.get("threshold_minutes"))

    lines: list[str] = []
    reasons = payload.get("reasons")
    if isinstance(reasons, list) and reasons:
        lines.append("Reasons: " + "; ".join(_truncate_alert_text(item, 80) for item in reasons[:3]))

    signals = payload.get("signals")
    if isinstance(signals, dict) and signals:
        signal_text = ", ".join(
            f"{key}={_truncate_alert_text(value, 40)}"
            for key, value in list(signals.items())[:5]
        )
        if signal_text:
            lines.append("Signals: " + signal_text)

    metrics = payload.get("metrics")
    if isinstance(metrics, dict) and metrics:
        metric_text = ", ".join(
            f"{key}={_truncate_alert_text(value, 40)}"
            for key, value in list(metrics.items())[:5]
        )
        if metric_text:
            lines.append("Metrics: " + metric_text)

    top_channels = payload.get("top_channels")
    if isinstance(top_channels, list) and top_channels:
        rendered_channels: list[str] = []
        for item in top_channels[:3]:
            if isinstance(item, dict):
                channel_name = str(item.get("target") or item.get("channel") or "unknown")
                channel_rate = item.get("success_rate_percent")
                if channel_rate is not None:
                    rendered_channels.append(f"{_truncate_alert_text(channel_name, 40)} ({channel_rate}%)")
                else:
                    rendered_channels.append(_truncate_alert_text(channel_name, 40))
            else:
                rendered_channels.append(_truncate_alert_text(item, 40))
        if rendered_channels:
            lines.append("Top channels: " + ", ".join(rendered_channels))

    checks = payload.get("checks")
    if isinstance(checks, list) and checks:
        warning_ids = [str(item.get("id") or "") for item in checks if isinstance(item, dict) and item.get("status") == "warning"]
        critical_ids = [str(item.get("id") or "") for item in checks if isinstance(item, dict) and item.get("status") == "critical"]
        if critical_ids:
            lines.append("Critical checks: " + ", ".join(critical_ids[:5]))
        if warning_ids:
            lines.append("Warning checks: " + ", ".join(warning_ids[:5]))

    if not lines:
        lines.append("Alert payload received by KA Facility OS.")

    summary_text = " | ".join(f"{label}: {value}" for label, value in facts if label != "Event")
    if not summary_text:
        summary_text = title

    return {
        "title": title,
        "facts": facts,
        "lines": lines,
        "summary_text": summary_text,
    }

def _render_alert_payload_for_target(
    *,
    event_type: str,
    payload: dict[str, Any],
    target_kind: str,
) -> dict[str, Any]:
    normalized_kind = target_kind.strip().lower() or "generic"
    if normalized_kind == "generic":
        return payload

    summary = _build_alert_message_summary(event_type, payload)
    title = str(summary["title"])
    facts = list(summary["facts"])
    lines = list(summary["lines"])
    summary_text = str(summary["summary_text"])

    if normalized_kind == "slack":
        fact_lines = "\n".join(f"*{label}:* {value}" for label, value in facts if label != "Event")
        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": _truncate_alert_text(title, 150)},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": _truncate_alert_text(summary_text, 2900)},
            },
        ]
        if fact_lines:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": _truncate_alert_text(fact_lines, 2900)},
                }
            )
        if lines:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": _truncate_alert_text("\n".join(f"- {line}" for line in lines), 2900),
                    },
                }
            )
        return {
            "text": _truncate_alert_text(f"{title}: {summary_text}", 2900),
            "blocks": blocks,
        }

    if normalized_kind == "teams":
        facts_payload = [{"title": label, "value": value} for label, value in facts[:10]]
        body: list[dict[str, Any]] = [
            {
                "type": "TextBlock",
                "size": "Medium",
                "weight": "Bolder",
                "text": _truncate_alert_text(title, 300),
                "wrap": True,
            },
            {
                "type": "TextBlock",
                "text": _truncate_alert_text(summary_text, 1200),
                "wrap": True,
            },
        ]
        if facts_payload:
            body.append({"type": "FactSet", "facts": facts_payload})
        if lines:
            body.append(
                {
                    "type": "TextBlock",
                    "text": _truncate_alert_text("\n".join(f"- {line}" for line in lines), 2500),
                    "wrap": True,
                }
            )
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": body,
                    },
                }
            ],
        }

    return payload

def _build_alert_delivery_record_payload(
    *,
    payload: dict[str, Any],
    target_kind: str,
) -> dict[str, Any]:
    dispatch_meta = {"channel_kind": target_kind}
    existing_dispatch = payload.get("_dispatch")
    if isinstance(existing_dispatch, dict):
        dispatch_meta = {**existing_dispatch, **dispatch_meta}
    return {**payload, "_dispatch": dispatch_meta}

def _normalize_ops_daily_check_alert_level(value: str | None) -> str:
    normalized = (value or "").strip().lower()
    if normalized in {"off", "none", "disabled"}:
        return "off"
    if normalized in {"warning", "warn"}:
        return "warning"
    if normalized in {"critical", "crit"}:
        return "critical"
    if normalized in {"always", "all", "ok"}:
        return "always"
    return "critical"

def _is_alert_failure_status(status: str) -> bool:
    return status.strip().lower() in {"failed", "warning"}

def _compute_alert_channel_guard_state(
    target: str,
    *,
    now: datetime | None = None,
    event_type: str | None = None,
    lookback_days: int = 30,
) -> dict[str, Any]:
    current_time = now or datetime.now(timezone.utc)
    normalized_lookback_days = max(1, lookback_days)
    history_start = current_time - timedelta(days=normalized_lookback_days)
    stmt = (
        select(
            alert_deliveries.c.status,
            alert_deliveries.c.error,
            alert_deliveries.c.last_attempt_at,
        )
        .where(alert_deliveries.c.target == target)
        .where(alert_deliveries.c.last_attempt_at >= history_start)
        .order_by(alert_deliveries.c.last_attempt_at.desc(), alert_deliveries.c.id.desc())
        .limit(200)
    )
    if event_type is not None:
        stmt = stmt.where(alert_deliveries.c.event_type == event_type)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()

    last_attempt_at: datetime | None = None
    last_status: str | None = None
    last_error: str | None = None
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    consecutive_failures = 0

    for idx, row in enumerate(rows):
        attempted_at = _as_optional_datetime(row.get("last_attempt_at"))
        if attempted_at is None:
            continue
        status = str(row.get("status") or "failed").strip().lower()
        error_text = str(row.get("error") or "")
        if idx == 0:
            last_attempt_at = attempted_at
            last_status = status
            last_error = error_text or None

        if status == "success":
            last_success_at = attempted_at
            # Consecutive failure run is determined from most recent attempt backward
            break
        if _is_alert_failure_status(status):
            if last_failure_at is None:
                last_failure_at = attempted_at
            consecutive_failures += 1
            continue
        break

    threshold = max(1, ops_runtime.ALERT_CHANNEL_GUARD_FAIL_THRESHOLD)
    cooldown_minutes = max(1, ops_runtime.ALERT_CHANNEL_GUARD_COOLDOWN_MINUTES)
    quarantined_until: datetime | None = None
    state = "healthy"
    if consecutive_failures >= threshold and last_failure_at is not None:
        quarantined_until = last_failure_at + timedelta(minutes=cooldown_minutes)
        if current_time < quarantined_until:
            state = "quarantined"
        else:
            state = "warning"
    elif consecutive_failures > 0:
        state = "warning"

    remaining_quarantine_minutes = 0
    if quarantined_until is not None and current_time < quarantined_until:
        remaining_quarantine_minutes = max(
            1,
            int(math.ceil((quarantined_until - current_time).total_seconds() / 60.0)),
        )

    return {
        "target": target,
        "state": state if ops_runtime.ALERT_CHANNEL_GUARD_ENABLED else "disabled",
        "state_computed": state,
        "consecutive_failures": consecutive_failures,
        "threshold": threshold,
        "cooldown_minutes": cooldown_minutes,
        "remaining_quarantine_minutes": remaining_quarantine_minutes,
        "quarantined_until": quarantined_until.isoformat() if quarantined_until is not None else None,
        "last_attempt_at": last_attempt_at.isoformat() if last_attempt_at is not None else None,
        "last_status": last_status,
        "last_error": last_error,
        "last_success_at": last_success_at.isoformat() if last_success_at is not None else None,
        "last_failure_at": last_failure_at.isoformat() if last_failure_at is not None else None,
        "delivery_count_lookback": len(rows),
    }

def _build_alert_channel_guard_snapshot(
    *,
    event_type: str | None = None,
    lookback_days: int = 30,
    max_targets: int = 100,
    now: datetime | None = None,
) -> dict[str, Any]:
    current_time = now or datetime.now(timezone.utc)
    normalized_lookback_days = max(1, lookback_days)
    normalized_max_targets = max(1, min(max_targets, 500))
    history_start = current_time - timedelta(days=normalized_lookback_days)
    target_set: set[str] = set(_configured_alert_targets())

    stmt = (
        select(alert_deliveries.c.target)
        .where(alert_deliveries.c.last_attempt_at >= history_start)
        .order_by(alert_deliveries.c.last_attempt_at.desc(), alert_deliveries.c.id.desc())
        .limit(2000)
    )
    if event_type is not None:
        stmt = stmt.where(alert_deliveries.c.event_type == event_type)
    with get_conn() as conn:
        recent_targets = conn.execute(stmt).all()
    for row in recent_targets:
        value = str(row[0] or "").strip()
        if value:
            target_set.add(value)

    channels = [
        _compute_alert_channel_guard_state(
            target,
            now=current_time,
            event_type=event_type,
            lookback_days=normalized_lookback_days,
        )
        for target in sorted(target_set)
    ]

    def _state_rank(item: dict[str, Any]) -> int:
        state = str(item.get("state_computed") or "healthy")
        if state == "quarantined":
            return 0
        if state == "warning":
            return 1
        return 2

    channels.sort(key=lambda item: (_state_rank(item), str(item.get("target") or "")))
    limited_channels = channels[:normalized_max_targets]
    quarantined_count = sum(1 for item in channels if str(item.get("state_computed")) == "quarantined")
    warning_count = sum(1 for item in channels if str(item.get("state_computed")) == "warning")
    healthy_count = sum(1 for item in channels if str(item.get("state_computed")) == "healthy")
    status = "ok"
    if quarantined_count > 0:
        status = "critical"
    elif warning_count > 0:
        status = "warning"
    if not ops_runtime.ALERT_CHANNEL_GUARD_ENABLED:
        status = "warning" if warning_count > 0 else "ok"

    return {
        "generated_at": current_time.isoformat(),
        "event_type": event_type,
        "lookback_days": normalized_lookback_days,
        "policy": {
            "enabled": ops_runtime.ALERT_CHANNEL_GUARD_ENABLED,
            "failure_threshold": max(1, ops_runtime.ALERT_CHANNEL_GUARD_FAIL_THRESHOLD),
            "cooldown_minutes": max(1, ops_runtime.ALERT_CHANNEL_GUARD_COOLDOWN_MINUTES),
            "recovery_steps": [
                "1) 원인 채널(네트워크/토큰/권한) 확인",
                "2) /api/ops/alerts/channels/guard/recover로 probe 실행",
                "3) 성공 시 채널 상태 healthy 복귀 확인",
            ],
        },
        "summary": {
            "status": status,
            "target_count": len(channels),
            "healthy_count": healthy_count,
            "warning_count": warning_count,
            "quarantined_count": quarantined_count,
            "returned_count": len(limited_channels),
        },
        "channels": limited_channels,
    }

def _build_alert_delivery_archive_csv(rows: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "id",
            "event_type",
            "target",
            "status",
            "error",
            "attempt_count",
            "last_attempt_at",
            "created_at",
            "updated_at",
            "payload_json",
        ]
    )
    for row in rows:
        writer.writerow(
            [
                int(row.get("id") or 0),
                str(row.get("event_type") or ""),
                str(row.get("target") or ""),
                str(row.get("status") or ""),
                str(row.get("error") or ""),
                int(row.get("attempt_count") or 0),
                _as_optional_datetime(row.get("last_attempt_at")).isoformat()
                if _as_optional_datetime(row.get("last_attempt_at")) is not None
                else "",
                _as_optional_datetime(row.get("created_at")).isoformat()
                if _as_optional_datetime(row.get("created_at")) is not None
                else "",
                _as_optional_datetime(row.get("updated_at")).isoformat()
                if _as_optional_datetime(row.get("updated_at")) is not None
                else "",
                str(row.get("payload_json") or "{}"),
            ]
        )
    return buffer.getvalue()

def run_alert_retention_job(
    *,
    retention_days: int | None = None,
    max_delete: int | None = None,
    dry_run: bool = False,
    write_archive: bool | None = None,
    trigger: str = "manual",
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    resolved_retention_days = max(1, int(retention_days if retention_days is not None else ops_runtime.ALERT_RETENTION_DAYS))
    resolved_max_delete = max(1, min(int(max_delete if max_delete is not None else ops_runtime.ALERT_RETENTION_MAX_DELETE), 50000))
    resolved_write_archive = ops_runtime.ALERT_RETENTION_ARCHIVE_ENABLED if write_archive is None else bool(write_archive)
    cutoff = started_at - timedelta(days=resolved_retention_days)

    archive_file: str | None = None
    archive_error: str | None = None
    deleted_count = 0
    candidate_count = 0
    candidate_ids: list[int] = []

    with get_conn() as conn:
        rows = conn.execute(
            select(alert_deliveries)
            .where(alert_deliveries.c.last_attempt_at < cutoff)
            .order_by(alert_deliveries.c.last_attempt_at.asc(), alert_deliveries.c.id.asc())
            .limit(resolved_max_delete)
        ).mappings().all()
        candidate_count = len(rows)
        candidate_ids = [int(row["id"]) for row in rows]

        can_delete = not dry_run
        if rows and not dry_run and resolved_write_archive:
            try:
                archive_dir = Path(ops_runtime.ALERT_RETENTION_ARCHIVE_PATH)
                archive_dir.mkdir(parents=True, exist_ok=True)
                stamp = started_at.strftime("%Y%m%dT%H%M%SZ")
                first_id = candidate_ids[0]
                last_id = candidate_ids[-1]
                file_path = archive_dir / f"alert-deliveries-{stamp}-{first_id}-{last_id}.csv"
                file_path.write_text(_build_alert_delivery_archive_csv([dict(row) for row in rows]), encoding="utf-8")
                archive_file = str(file_path)
            except Exception as exc:  # pragma: no cover - defensive path
                archive_error = str(exc)
                can_delete = False

        if rows and can_delete:
            delete_result = conn.execute(
                delete(alert_deliveries).where(alert_deliveries.c.id.in_(candidate_ids))
            )
            deleted_count = int(delete_result.rowcount or 0)

    finished_at = datetime.now(timezone.utc)
    status = "success" if archive_error is None else "warning"
    run_id = _write_job_run(
        job_name="alert_retention",
        trigger=trigger,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        detail={
            "retention_days": resolved_retention_days,
            "max_delete": resolved_max_delete,
            "dry_run": dry_run,
            "write_archive": resolved_write_archive,
            "cutoff": cutoff.isoformat(),
            "candidate_count": candidate_count,
            "deleted_count": deleted_count,
            "archive_file": archive_file,
            "archive_error": archive_error,
            "candidate_ids": candidate_ids[:200],
        },
    )
    return {
        "run_id": run_id,
        "checked_at": finished_at.isoformat(),
        "status": status,
        "retention_days": resolved_retention_days,
        "max_delete": resolved_max_delete,
        "dry_run": dry_run,
        "write_archive": resolved_write_archive,
        "cutoff": cutoff.isoformat(),
        "candidate_count": candidate_count,
        "deleted_count": deleted_count,
        "archive_file": archive_file,
        "archive_error": archive_error,
    }

def run_alert_guard_recover_job(
    *,
    event_type: str | None = None,
    state_filter: str = "quarantined",
    max_targets: int | None = None,
    dry_run: bool = False,
    trigger: str = "manual",
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    normalized_state_filter = (state_filter or "quarantined").strip().lower()
    if normalized_state_filter not in {"quarantined", "warning", "all"}:
        normalized_state_filter = "quarantined"
    resolved_max_targets = max(1, min(int(max_targets if max_targets is not None else ops_runtime.ALERT_GUARD_RECOVER_MAX_TARGETS), 500))

    snapshot = _build_alert_channel_guard_snapshot(
        event_type=event_type,
        lookback_days=30,
        max_targets=max(200, resolved_max_targets * 5),
        now=started_at,
    )
    channels = snapshot.get("channels", [])
    if not isinstance(channels, list):
        channels = []

    def _matches(item: dict[str, Any]) -> bool:
        state = str(item.get("state_computed") or "")
        if normalized_state_filter == "all":
            return state in {"quarantined", "warning"}
        return state == normalized_state_filter

    selected = [item for item in channels if isinstance(item, dict) and _matches(item)][:resolved_max_targets]

    processed_count = 0
    success_count = 0
    warning_count = 0
    failed_count = 0
    skipped_count = 0
    results: list[dict[str, Any]] = []

    for item in selected:
        target = str(item.get("target") or "").strip()
        if not target:
            continue
        processed_count += 1
        before_state = _compute_alert_channel_guard_state(
            target,
            event_type=event_type,
            now=datetime.now(timezone.utc),
        )
        if dry_run:
            skipped_count += 1
            results.append(
                {
                    "target": target,
                    "status": "skipped",
                    "reason": "dry_run",
                    "before_state": before_state.get("state"),
                    "after_state": before_state.get("state"),
                }
            )
            continue

        probe_payload = {
            "event": "alert_guard_recovery_batch_probe",
            "target": target,
            "event_type_scope": event_type,
            "state_filter": normalized_state_filter,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        ok, err = _post_json_with_retries(
            url=target,
            payload=probe_payload,
            retries=ops_runtime.ALERT_WEBHOOK_RETRIES,
            timeout_sec=ops_runtime.ALERT_WEBHOOK_TIMEOUT_SEC,
        )
        probe_status = "success" if ok and err is None else ("warning" if ok else "failed")
        if probe_status == "success":
            success_count += 1
        elif probe_status == "warning":
            warning_count += 1
        else:
            failed_count += 1

        delivery_id = _write_alert_delivery(
            event_type=event_type or "alert_guard_recover",
            target=target,
            status=probe_status,
            error=err,
            payload={**probe_payload, "probe": True},
        )
        after_state = _compute_alert_channel_guard_state(
            target,
            event_type=event_type,
            now=datetime.now(timezone.utc),
        )
        results.append(
            {
                "target": target,
                "status": probe_status,
                "error": err,
                "delivery_id": delivery_id,
                "before_state": before_state.get("state"),
                "after_state": after_state.get("state"),
                "before_consecutive_failures": before_state.get("consecutive_failures"),
                "after_consecutive_failures": after_state.get("consecutive_failures"),
            }
        )

    finished_at = datetime.now(timezone.utc)
    job_status = "success"
    if failed_count > 0:
        job_status = "warning"
    run_id = _write_job_run(
        job_name="alert_guard_recover",
        trigger=trigger,
        status=job_status,
        started_at=started_at,
        finished_at=finished_at,
        detail={
            "event_type": event_type,
            "state_filter": normalized_state_filter,
            "max_targets": resolved_max_targets,
            "dry_run": dry_run,
            "selected_target_count": len(selected),
            "processed_count": processed_count,
            "success_count": success_count,
            "warning_count": warning_count,
            "failed_count": failed_count,
            "skipped_count": skipped_count,
            "results": results[:200],
        },
    )

    return {
        "run_id": run_id,
        "checked_at": finished_at.isoformat(),
        "status": job_status,
        "event_type": event_type,
        "state_filter": normalized_state_filter,
        "max_targets": resolved_max_targets,
        "dry_run": dry_run,
        "selected_target_count": len(selected),
        "processed_count": processed_count,
        "success_count": success_count,
        "warning_count": warning_count,
        "failed_count": failed_count,
        "skipped_count": skipped_count,
        "results": results,
    }

def run_alert_mttr_slo_check_job(
    *,
    event_type: str | None = None,
    force_notify: bool = False,
    trigger: str = "manual",
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    policy, policy_updated_at, policy_key = _ensure_mttr_slo_policy()
    window_days = int(policy.get("window_days") or 30)
    threshold_minutes = float(policy.get("threshold_minutes") or 60)
    min_incidents = int(policy.get("min_incidents") or 1)

    snapshot = _build_alert_channel_mttr_snapshot(
        event_type=event_type,
        windows=[window_days],
        now=started_at,
    )
    windows = snapshot.get("windows", [])
    window: dict[str, Any] = windows[0] if isinstance(windows, list) and windows else {}
    incident_count = int(window.get("incident_count") or 0)
    recovered_incidents = int(window.get("recovered_incidents") or 0)
    unresolved_incidents = int(window.get("unresolved_incidents") or 0)
    mttr_minutes = window.get("mttr_minutes")
    mttr_value = float(mttr_minutes) if mttr_minutes is not None else None
    breach = (
        bool(policy.get("enabled", True))
        and incident_count >= max(1, min_incidents)
        and mttr_value is not None
        and mttr_value > threshold_minutes
    )

    channels = window.get("channels", [])
    if not isinstance(channels, list):
        channels = []
    top_channels_limit = max(1, min(int(policy.get("top_channels") or 10), 50))
    top_channels = [
        {
            "target": str(item.get("target") or ""),
            "incident_count": int(item.get("incident_count") or 0),
            "recovered_incidents": int(item.get("recovered_incidents") or 0),
            "unresolved_incidents": int(item.get("unresolved_incidents") or 0),
            "mttr_minutes": item.get("mttr_minutes"),
            "last_incident_start": item.get("last_incident_start"),
            "last_recovery_at": item.get("last_recovery_at"),
        }
        for item in channels
        if isinstance(item, dict)
    ][:top_channels_limit]

    auto_recover_attempted = False
    auto_recover_result: dict[str, Any] | None = None
    if breach and bool(policy.get("auto_recover_enabled", True)):
        auto_recover_attempted = True
        recovered = run_alert_guard_recover_job(
            event_type=event_type,
            state_filter=str(policy.get("recover_state") or "quarantined"),
            max_targets=int(policy.get("recover_max_targets") or ops_runtime.ALERT_GUARD_RECOVER_MAX_TARGETS),
            dry_run=False,
            trigger="mttr_slo_auto",
        )
        auto_recover_result = {
            "run_id": recovered.get("run_id"),
            "status": recovered.get("status"),
            "state_filter": recovered.get("state_filter"),
            "max_targets": recovered.get("max_targets"),
            "processed_count": recovered.get("processed_count"),
            "success_count": recovered.get("success_count"),
            "failed_count": recovered.get("failed_count"),
            "skipped_count": recovered.get("skipped_count"),
        }

    notify_attempted = False
    notify_dispatched = False
    notify_error: str | None = None
    notify_channels: list[dict[str, Any]] = []
    cooldown_active = False
    cooldown_remaining_minutes = 0
    last_breach_at = _latest_mttr_slo_breach_finished_at()
    cooldown_minutes = int(policy.get("notify_cooldown_minutes") or 0)
    if breach and bool(policy.get("notify_enabled", True)):
        if not force_notify and cooldown_minutes > 0 and last_breach_at is not None:
            next_allowed_at = last_breach_at + timedelta(minutes=cooldown_minutes)
            if started_at < next_allowed_at:
                cooldown_active = True
                cooldown_remaining_minutes = max(
                    1,
                    int(math.ceil((next_allowed_at - started_at).total_seconds() / 60.0)),
                )
        if force_notify or not cooldown_active:
            notify_attempted = True
            notify_dispatched, notify_error, channel_results = _dispatch_alert_event(
                event_type=str(policy.get("notify_event_type") or "mttr_slo_breach"),
                payload={
                    "event": "mttr_slo_breach",
                    "checked_at": started_at.isoformat(),
                    "event_type_scope": event_type,
                    "policy": {
                        "policy_key": policy_key,
                        "enabled": bool(policy.get("enabled", True)),
                        "window_days": window_days,
                        "threshold_minutes": threshold_minutes,
                        "min_incidents": min_incidents,
                        "auto_recover_enabled": bool(policy.get("auto_recover_enabled", True)),
                        "recover_state": str(policy.get("recover_state") or "quarantined"),
                        "recover_max_targets": int(policy.get("recover_max_targets") or ops_runtime.ALERT_GUARD_RECOVER_MAX_TARGETS),
                    },
                    "window": {
                        "days": window_days,
                        "incident_count": incident_count,
                        "recovered_incidents": recovered_incidents,
                        "unresolved_incidents": unresolved_incidents,
                        "mttr_minutes": mttr_value,
                    },
                    "top_channels": top_channels,
                    "auto_recover_result": auto_recover_result,
                },
            )
            notify_channels = [item.model_dump() for item in channel_results]

    finished_at = datetime.now(timezone.utc)
    status = "success"
    if breach:
        status = "warning"
    if notify_attempted and notify_error is not None and notify_dispatched is False:
        status = "warning"

    run_id = _write_job_run(
        job_name="alert_mttr_slo_check",
        trigger=trigger,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        detail={
            "event_type": event_type,
            "policy_key": policy_key,
            "policy_updated_at": policy_updated_at.isoformat(),
            "policy": policy,
            "window": {
                "days": window_days,
                "incident_count": incident_count,
                "recovered_incidents": recovered_incidents,
                "unresolved_incidents": unresolved_incidents,
                "mttr_minutes": mttr_value,
            },
            "breach": breach,
            "top_channels": top_channels,
            "actions": {
                "auto_recover_attempted": auto_recover_attempted,
                "auto_recover_result": auto_recover_result,
                "notify_attempted": notify_attempted,
                "notify_dispatched": notify_dispatched,
                "notify_error": notify_error,
                "notify_channels": notify_channels,
                "force_notify": force_notify,
                "cooldown_minutes": cooldown_minutes,
                "cooldown_active": cooldown_active,
                "cooldown_remaining_minutes": cooldown_remaining_minutes,
                "last_breach_at": last_breach_at.isoformat() if last_breach_at is not None else None,
            },
        },
    )

    return {
        "run_id": run_id,
        "checked_at": finished_at.isoformat(),
        "status": status,
        "event_type": event_type,
        "policy_key": policy_key,
        "policy_updated_at": policy_updated_at.isoformat(),
        "policy": policy,
        "window": {
            "days": window_days,
            "incident_count": incident_count,
            "recovered_incidents": recovered_incidents,
            "unresolved_incidents": unresolved_incidents,
            "mttr_minutes": mttr_value,
        },
        "breach": breach,
        "top_channels": top_channels,
        "actions": {
            "auto_recover_attempted": auto_recover_attempted,
            "auto_recover_result": auto_recover_result,
            "notify_attempted": notify_attempted,
            "notify_dispatched": notify_dispatched,
            "notify_error": notify_error,
            "notify_channels": notify_channels,
            "force_notify": force_notify,
            "cooldown_minutes": cooldown_minutes,
            "cooldown_active": cooldown_active,
            "cooldown_remaining_minutes": cooldown_remaining_minutes,
            "last_breach_at": last_breach_at.isoformat() if last_breach_at is not None else None,
        },
    }

def _post_json_with_retries(
    *,
    url: str,
    payload: dict[str, Any],
    retries: int,
    timeout_sec: float,
) -> tuple[bool, str | None]:
    body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    attempts = max(1, retries)
    for attempt in range(1, attempts + 1):
        req = url_request.Request(
            url=url,
            data=body,
            method="POST",
            headers=_build_alert_webhook_request_headers(),
        )
        try:
            with url_request.urlopen(req, timeout=timeout_sec) as resp:
                status_code = int(getattr(resp, "status", 0))
                if 200 <= status_code < 300:
                    return True, None
                err = f"webhook returned status {status_code}"
        except url_error.HTTPError as exc:
            err = f"webhook http error {exc.code}"
        except url_error.URLError as exc:
            err = f"webhook url error: {exc.reason}"
        except Exception as exc:  # pragma: no cover - defensive path
            err = f"webhook unexpected error: {exc}"

        if attempt < attempts:
            time.sleep(0.5 * (2 ** (attempt - 1)))
    return False, err

def _dispatch_alert_event(
    *,
    event_type: str,
    payload: dict[str, Any],
) -> tuple[bool, str | None, list[SlaAlertChannelResult]]:
    target_configs = _configured_alert_target_configs()
    if not target_configs:
        return False, None, []

    results: list[SlaAlertChannelResult] = []
    success_count = 0
    failed_count = 0

    for target_config in target_configs:
        target = target_config["url"]
        target_kind = target_config["kind"]
        guard_state = _compute_alert_channel_guard_state(target, event_type=event_type)
        if ops_runtime.ALERT_CHANNEL_GUARD_ENABLED and str(guard_state.get("state_computed")) == "quarantined":
            guard_error = (
                "channel quarantined until "
                + str(guard_state.get("quarantined_until") or "unknown")
                + " (consecutive_failures="
                + str(guard_state.get("consecutive_failures") or 0)
                + ")"
            )
            _write_alert_delivery(
                event_type=event_type,
                target=target,
                status="warning",
                error=guard_error,
                payload=_build_alert_delivery_record_payload(
                    payload={
                        **payload,
                        "guard": {
                            "state": guard_state.get("state_computed"),
                            "consecutive_failures": guard_state.get("consecutive_failures"),
                            "quarantined_until": guard_state.get("quarantined_until"),
                        },
                    },
                    target_kind=target_kind,
                ),
            )
            failed_count += 1
            results.append(SlaAlertChannelResult(target=target, success=False, error=guard_error))
            continue

        rendered_payload = _render_alert_payload_for_target(
            event_type=event_type,
            payload=payload,
            target_kind=target_kind,
        )
        ok, err = _post_json_with_retries(
            url=target,
            payload=rendered_payload,
            retries=ops_runtime.ALERT_WEBHOOK_RETRIES,
            timeout_sec=ops_runtime.ALERT_WEBHOOK_TIMEOUT_SEC,
        )
        delivery_status = "success" if ok and err is None else ("warning" if ok else "failed")
        _write_alert_delivery(
            event_type=event_type,
            target=target,
            status=delivery_status,
            error=err,
            payload=_build_alert_delivery_record_payload(payload=payload, target_kind=target_kind),
        )
        if ok:
            success_count += 1
        else:
            failed_count += 1
        results.append(SlaAlertChannelResult(target=target, success=ok, error=err))

    if failed_count == 0:
        return True, None, results
    if success_count > 0:
        return True, f"{failed_count}/{len(results)} alert channels failed", results
    return False, "all alert channels failed", results

def _dispatch_sla_alert(
    *,
    site: str | None,
    checked_at: datetime,
    escalated_count: int,
    work_order_ids: list[int],
) -> tuple[bool, str | None, list[SlaAlertChannelResult]]:
    if escalated_count <= 0:
        return False, None, []

    payload = {
        "event": "sla_escalation",
        "site": site or "ALL",
        "checked_at": checked_at.isoformat(),
        "escalated_count": escalated_count,
        "work_order_ids": work_order_ids,
    }
    return _dispatch_alert_event(event_type="sla_escalation", payload=payload)

def _build_alert_channel_kpi_snapshot(
    *,
    event_type: str | None = None,
    windows: list[int] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    generated_at = now or datetime.now(timezone.utc)
    normalized_windows = sorted({int(value) for value in (windows or [7, 30]) if int(value) > 0})
    if not normalized_windows:
        normalized_windows = [7, 30]

    max_days = max(normalized_windows)
    oldest_cutoff = generated_at - timedelta(days=max_days)
    stmt = (
        select(
            alert_deliveries.c.target,
            alert_deliveries.c.status,
            alert_deliveries.c.last_attempt_at,
        )
        .where(alert_deliveries.c.last_attempt_at >= oldest_cutoff)
        .order_by(alert_deliveries.c.last_attempt_at.desc(), alert_deliveries.c.id.desc())
    )
    if event_type is not None:
        stmt = stmt.where(alert_deliveries.c.event_type == event_type)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()

    parsed_rows: list[dict[str, Any]] = []
    for row in rows:
        attempted_at = _as_optional_datetime(row.get("last_attempt_at"))
        if attempted_at is None:
            continue
        parsed_rows.append(
            {
                "target": str(row.get("target") or "unknown"),
                "status": str(row.get("status") or "failed").lower(),
                "attempted_at": attempted_at,
            }
        )

    window_payloads: list[dict[str, Any]] = []
    for days in normalized_windows:
        cutoff = generated_at - timedelta(days=days)
        channel_counts: dict[str, dict[str, Any]] = {}
        total_deliveries = 0
        success_count = 0
        warning_count = 0
        failed_count = 0

        for row in parsed_rows:
            attempted_at = row["attempted_at"]
            if attempted_at < cutoff:
                continue

            total_deliveries += 1
            status = row["status"]
            if status == "success":
                success_count += 1
            elif status == "warning":
                warning_count += 1
            else:
                failed_count += 1

            target = row["target"]
            bucket = channel_counts.get(target)
            if bucket is None:
                bucket = {
                    "target": target,
                    "total_deliveries": 0,
                    "success_count": 0,
                    "warning_count": 0,
                    "failed_count": 0,
                    "last_attempt_at": None,
                }
                channel_counts[target] = bucket
            bucket["total_deliveries"] += 1
            if status == "success":
                bucket["success_count"] += 1
            elif status == "warning":
                bucket["warning_count"] += 1
            else:
                bucket["failed_count"] += 1
            last_attempt_at = bucket.get("last_attempt_at")
            if not isinstance(last_attempt_at, datetime) or attempted_at > last_attempt_at:
                bucket["last_attempt_at"] = attempted_at

        channels: list[dict[str, Any]] = []
        for bucket in channel_counts.values():
            channel_total = int(bucket["total_deliveries"])
            channel_success = int(bucket["success_count"])
            channel_rate = round((channel_success / channel_total * 100), 2) if channel_total > 0 else 0.0
            last_attempt_at = bucket.get("last_attempt_at")
            channels.append(
                {
                    "target": bucket["target"],
                    "total_deliveries": channel_total,
                    "success_count": channel_success,
                    "warning_count": int(bucket["warning_count"]),
                    "failed_count": int(bucket["failed_count"]),
                    "success_rate_percent": channel_rate,
                    "last_attempt_at": last_attempt_at.isoformat() if isinstance(last_attempt_at, datetime) else None,
                }
            )

        channels.sort(key=lambda item: (-int(item["total_deliveries"]), str(item["target"])))
        success_rate_percent = round((success_count / total_deliveries * 100), 2) if total_deliveries > 0 else 0.0
        window_payloads.append(
            {
                "days": days,
                "window_start": cutoff.isoformat(),
                "window_end": generated_at.isoformat(),
                "total_deliveries": total_deliveries,
                "success_count": success_count,
                "warning_count": warning_count,
                "failed_count": failed_count,
                "success_rate_percent": success_rate_percent,
                "channels": channels,
            }
        )

    return {
        "generated_at": generated_at.isoformat(),
        "event_type": event_type,
        "windows": window_payloads,
    }

def _compute_recovery_minutes_stats(recovery_minutes: list[float]) -> dict[str, float | None]:
    values: list[float] = []
    for item in recovery_minutes:
        try:
            parsed = float(item)
        except (TypeError, ValueError):
            continue
        if parsed < 0.0:
            continue
        values.append(parsed)
    if not values:
        return {
            "mttr_minutes": None,
            "median_recovery_minutes": None,
            "longest_recovery_minutes": None,
        }

    sorted_values = sorted(values)
    count = len(sorted_values)
    mid = count // 2
    if count % 2 == 1:
        median = sorted_values[mid]
    else:
        median = (sorted_values[mid - 1] + sorted_values[mid]) / 2.0

    return {
        "mttr_minutes": round(sum(sorted_values) / count, 2),
        "median_recovery_minutes": round(median, 2),
        "longest_recovery_minutes": round(sorted_values[-1], 2),
    }

def _build_alert_channel_mttr_snapshot(
    *,
    event_type: str | None = None,
    windows: list[int] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    generated_at = now or datetime.now(timezone.utc)
    normalized_windows = sorted({int(value) for value in (windows or [7, 30]) if int(value) > 0})
    if not normalized_windows:
        normalized_windows = [7, 30]

    max_days = max(normalized_windows)
    # Include pre-window history so incidents already open at window start can be tracked.
    history_start = generated_at - timedelta(days=max_days + 30)
    stmt = (
        select(
            alert_deliveries.c.target,
            alert_deliveries.c.status,
            alert_deliveries.c.last_attempt_at,
        )
        .where(alert_deliveries.c.last_attempt_at >= history_start)
        .order_by(alert_deliveries.c.target.asc(), alert_deliveries.c.last_attempt_at.asc(), alert_deliveries.c.id.asc())
    )
    if event_type is not None:
        stmt = stmt.where(alert_deliveries.c.event_type == event_type)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()

    history_by_target: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        attempted_at = _as_optional_datetime(row.get("last_attempt_at"))
        if attempted_at is None:
            continue
        target = str(row.get("target") or "unknown")
        history_by_target.setdefault(target, []).append(
            {
                "status": str(row.get("status") or "failed").strip().lower(),
                "attempted_at": attempted_at,
            }
        )

    window_payloads: list[dict[str, Any]] = []
    for days in normalized_windows:
        cutoff = generated_at - timedelta(days=days)
        channels: list[dict[str, Any]] = []
        overall_incidents = 0
        overall_recovered = 0
        overall_unresolved = 0
        overall_recovery_minutes: list[float] = []

        for target, history in history_by_target.items():
            in_incident = False
            for item in history:
                attempted_at = item["attempted_at"]
                if attempted_at >= cutoff:
                    break
                status = item["status"]
                if _is_alert_failure_status(status):
                    in_incident = True
                elif status == "success":
                    in_incident = False

            incident_start: datetime | None = cutoff if in_incident else None
            last_incident_start: datetime | None = cutoff if in_incident else None
            last_recovery_at: datetime | None = None
            incident_count = 1 if in_incident else 0
            recovered_incidents = 0
            unresolved_incidents = 0
            channel_recovery_minutes: list[float] = []

            for item in history:
                attempted_at = item["attempted_at"]
                if attempted_at < cutoff or attempted_at > generated_at:
                    continue
                status = item["status"]
                if _is_alert_failure_status(status):
                    if not in_incident:
                        in_incident = True
                        incident_start = attempted_at
                        last_incident_start = attempted_at
                        incident_count += 1
                    continue
                if status == "success" and in_incident:
                    effective_start = incident_start or cutoff
                    recovery_minutes = max((attempted_at - effective_start).total_seconds() / 60.0, 0.0)
                    channel_recovery_minutes.append(recovery_minutes)
                    recovered_incidents += 1
                    in_incident = False
                    incident_start = None
                    last_recovery_at = attempted_at

            if in_incident:
                unresolved_incidents = 1

            if incident_count == 0:
                continue

            stats = _compute_recovery_minutes_stats(channel_recovery_minutes)
            channels.append(
                {
                    "target": target,
                    "incident_count": incident_count,
                    "recovered_incidents": recovered_incidents,
                    "unresolved_incidents": unresolved_incidents,
                    "mttr_minutes": stats["mttr_minutes"],
                    "median_recovery_minutes": stats["median_recovery_minutes"],
                    "longest_recovery_minutes": stats["longest_recovery_minutes"],
                    "last_incident_start": last_incident_start.isoformat() if last_incident_start else None,
                    "last_recovery_at": last_recovery_at.isoformat() if last_recovery_at else None,
                }
            )

            overall_incidents += incident_count
            overall_recovered += recovered_incidents
            overall_unresolved += unresolved_incidents
            overall_recovery_minutes.extend(channel_recovery_minutes)

        channels.sort(
            key=lambda item: (
                -int(item.get("unresolved_incidents") or 0),
                -float(item.get("mttr_minutes") or -1.0),
                str(item.get("target") or ""),
            )
        )
        overall_stats = _compute_recovery_minutes_stats(overall_recovery_minutes)
        window_payloads.append(
            {
                "days": days,
                "window_start": cutoff.isoformat(),
                "window_end": generated_at.isoformat(),
                "incident_count": overall_incidents,
                "recovered_incidents": overall_recovered,
                "unresolved_incidents": overall_unresolved,
                "mttr_minutes": overall_stats["mttr_minutes"],
                "median_recovery_minutes": overall_stats["median_recovery_minutes"],
                "longest_recovery_minutes": overall_stats["longest_recovery_minutes"],
                "channels": channels,
            }
        )

    return {
        "generated_at": generated_at.isoformat(),
        "event_type": event_type,
        "windows": window_payloads,
    }


