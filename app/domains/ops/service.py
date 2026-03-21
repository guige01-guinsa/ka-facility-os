"""OPS service helpers extracted from app.main."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
from datetime import datetime, timedelta, timezone
from os import getenv
from pathlib import Path
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.database import (
    admin_audit_logs,
    admin_tokens,
    admin_users,
    alert_deliveries,
    api_latency_samples,
    get_conn,
    inspections,
    job_runs,
    work_order_events,
    work_orders,
)
from app.domains.iam.core import (
    ADMIN_TOKEN_ROTATE_AFTER_DAYS,
    SITE_SCOPE_ALL,
    _month_window,
    _site_scope_text_to_list,
)
from app.domains.iam.service import _sign_payload, build_monthly_audit_archive
from app.domains.ops import config as ops_config
from app.domains.ops.config import (
    _API_LATENCY_LAST_SEEN_AT,
    _API_LATENCY_LOCK,
    _API_LATENCY_SAMPLES,
    _API_LATENCY_TARGET_KEYS,
    _PREFLIGHT_LOCK,
    _PREFLIGHT_SNAPSHOT,
)
from app.domains.ops.inspection_service import _as_datetime, _as_optional_datetime, _read_evidence_blob
from app.domains.ops.record_service import _row_to_job_run_model, _to_json_text, _write_job_run

try:
    from redis import Redis
except Exception:  # pragma: no cover - optional dependency
    Redis = None

_LOCAL_SYMBOLS = {
    "bind",
    "_LOCAL_SYMBOLS",
    "_RATE_LIMIT_REDIS",
    "_rate_limit_backend_snapshot",
    "_audit_signing_snapshot",
    "_percentile_value",
    "_load_persisted_api_latency_records",
    "_build_burn_rate_window_stats",
    "_build_api_latency_snapshot",
    "_build_evidence_archive_integrity_batch",
    "_next_month_boundary",
    "_month_window_bounds",
    "_build_deploy_checklist_steps",
    "_build_deploy_checklist_policy",
    "_build_deploy_checklist_signature",
    "_parse_deploy_checklist_revision",
    "_derive_deploy_checklist_version",
    "_build_deploy_checklist_payload",
    "_week_start_utc",
    "_startup_path_writable",
    "_run_startup_preflight_snapshot",
    "_refresh_startup_preflight_snapshot",
    "_get_startup_preflight_snapshot",
    "_build_alert_noise_policy_snapshot",
    "_build_admin_security_dashboard_snapshot",
    "_build_ops_quality_job_summary",
    "_build_ops_quality_report_payload",
    "_build_ops_quality_report_csv",
    "_prune_ops_quality_report_archive_files",
    "_publish_ops_quality_report_artifacts",
    "_build_ops_quality_weekly_streak_snapshot",
    "run_ops_quality_report_job",
    "run_dr_rehearsal_job",
    "_latest_dr_rehearsal_payload",
    "_normalize_governance_risk_level",
    "_governance_risk_rank",
    "_build_ops_governance_gate_snapshot",
    "run_ops_governance_gate_job",
    "_latest_ops_governance_gate_payload",
    "_governance_remediation_owner_and_sla",
    "_governance_remediation_action",
    "_governance_rule_priority",
    "_build_ops_governance_remediation_plan",
    "_build_ops_governance_remediation_csv",
}


def bind(namespace: dict[str, object]) -> None:
    return None


_RATE_LIMIT_REDIS: Any = None
ops_runtime = ops_config.runtime


def _init_rate_limit_backend() -> None:
    global _RATE_LIMIT_REDIS
    _RATE_LIMIT_REDIS = None
    if ops_runtime.API_RATE_LIMIT_STORE not in {"redis", "auto"}:
        return
    if not ops_runtime.API_RATE_LIMIT_REDIS_URL:
        return
    if Redis is None:
        return
    try:
        client = Redis.from_url(
            ops_runtime.API_RATE_LIMIT_REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
        )
        client.ping()
        _RATE_LIMIT_REDIS = client
    except Exception:
        _RATE_LIMIT_REDIS = None


def _parse_job_detail_json(raw: Any) -> dict[str, Any]:
    try:
        loaded = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        loaded = {}
    if isinstance(loaded, dict):
        return loaded
    return {}


def _build_ops_runbook_checks_snapshot(
    *,
    now: datetime | None = None,
    horizon_minutes: int = 90,
) -> dict[str, Any]:
    from app.domains.ops.router_governance import _build_ops_runbook_checks_snapshot as _impl

    return _impl(now=now, horizon_minutes=horizon_minutes)


def _rate_limit_backend_snapshot() -> dict[str, Any]:
    if _RATE_LIMIT_REDIS is None:
        _init_rate_limit_backend()
    redis_url_configured = bool(ops_runtime.API_RATE_LIMIT_REDIS_URL.strip())
    redis_client_ready = _RATE_LIMIT_REDIS is not None
    redis_ping_ok = False
    redis_error: str | None = None
    if redis_client_ready:
        try:
            _RATE_LIMIT_REDIS.ping()
            redis_ping_ok = True
        except Exception as exc:  # pragma: no cover - network-dependent path
            redis_error = str(exc)

    active_backend = "redis" if redis_ping_ok else "memory"
    if ops_runtime.API_RATE_LIMIT_STORE == "redis":
        status = "ok" if redis_ping_ok else "critical"
        message = (
            "Redis rate limit backend is active."
            if redis_ping_ok
            else "Redis is required but unavailable; rate limit fallback is active."
        )
    elif ops_runtime.API_RATE_LIMIT_STORE == "auto":
        status = "ok" if redis_ping_ok else "warning"
        if redis_ping_ok:
            message = "Auto mode currently uses Redis backend."
        elif redis_url_configured:
            message = "Auto mode is falling back to memory because Redis is unavailable."
        else:
            message = "Auto mode is using memory backend (Redis URL not configured)."
    else:
        status = "ok" if ops_runtime.ENV_NAME != "production" else "warning"
        message = (
            "Memory rate limit backend is configured."
            if ops_runtime.ENV_NAME != "production"
            else "Production is using memory rate limit backend."
        )

    return {
        "status": status,
        "message": message,
        "configured_store": ops_runtime.API_RATE_LIMIT_STORE,
        "active_backend": active_backend,
        "redis_url_configured": redis_url_configured,
        "redis_client_ready": redis_client_ready,
        "redis_ping_ok": redis_ping_ok,
        "redis_error": redis_error,
    }

def _audit_signing_snapshot() -> dict[str, Any]:
    enabled = bool(ops_runtime.AUDIT_ARCHIVE_SIGNING_KEY.strip())
    if enabled:
        return {
            "status": "ok",
            "message": "Monthly audit archive signing is enabled.",
            "enabled": True,
            "algorithm": "hmac-sha256",
        }
    status = "warning" if ops_runtime.ENV_NAME == "production" else "ok"
    return {
        "status": status,
        "message": "Monthly audit archive signing key is not configured.",
        "enabled": False,
        "algorithm": "unsigned",
    }

def _percentile_value(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    sorted_values = sorted(values)
    if percentile <= 0:
        return float(sorted_values[0])
    if percentile >= 100:
        return float(sorted_values[-1])
    rank = (len(sorted_values) - 1) * (percentile / 100.0)
    lower = int(math.floor(rank))
    upper = int(math.ceil(rank))
    if lower == upper:
        return float(sorted_values[lower])
    weight = rank - lower
    return float(sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * weight)

def _load_persisted_api_latency_records(
    *,
    endpoint_key: str,
    limit: int,
) -> tuple[list[dict[str, Any]], str | None]:
    if not ops_runtime.API_LATENCY_PERSIST_ENABLED:
        return [], None
    try:
        with get_conn() as conn:
            rows = conn.execute(
                select(
                    api_latency_samples.c.duration_ms,
                    api_latency_samples.c.status_code,
                    api_latency_samples.c.is_error,
                    api_latency_samples.c.sampled_at,
                )
                .where(api_latency_samples.c.endpoint_key == endpoint_key)
                .order_by(api_latency_samples.c.sampled_at.desc(), api_latency_samples.c.id.desc())
                .limit(max(1, int(limit)))
            ).mappings().all()
    except SQLAlchemyError:
        return [], None
    if not rows:
        return [], None
    records = [
        {
            "duration_ms": max(0.0, float(row.get("duration_ms") or 0.0)),
            "status_code": int(row.get("status_code")) if row.get("status_code") is not None else None,
            "is_error": bool(row.get("is_error")),
            "sampled_at": _as_datetime(row.get("sampled_at")),
        }
        for row in rows
    ]
    sampled_at = rows[0].get("sampled_at")
    last_seen_at = _as_datetime(sampled_at).isoformat() if sampled_at is not None else None
    return records, last_seen_at

def _build_burn_rate_window_stats(
    *,
    records: list[dict[str, Any]],
    since_at: datetime,
    latency_warning_ms: float,
    error_budget_percent: float,
    latency_budget_percent: float,
    min_samples: int,
) -> dict[str, Any]:
    scoped = [row for row in records if _as_datetime(row.get("sampled_at")) >= since_at]
    total_count = len(scoped)
    error_count = sum(1 for row in scoped if bool(row.get("is_error")))
    slow_count = sum(1 for row in scoped if float(row.get("duration_ms") or 0.0) >= latency_warning_ms)
    error_rate_percent = round((error_count / total_count) * 100.0, 4) if total_count > 0 else 0.0
    slow_rate_percent = round((slow_count / total_count) * 100.0, 4) if total_count > 0 else 0.0
    error_burn = round(error_rate_percent / error_budget_percent, 4) if total_count > 0 else 0.0
    latency_burn = round(slow_rate_percent / latency_budget_percent, 4) if total_count > 0 else 0.0
    burn_rate = round(max(error_burn, latency_burn), 4) if total_count > 0 else 0.0
    return {
        "sample_count": total_count,
        "error_count": error_count,
        "slow_count": slow_count,
        "error_rate_percent": round(error_rate_percent, 2),
        "slow_rate_percent": round(slow_rate_percent, 2),
        "error_burn_rate": error_burn,
        "latency_burn_rate": latency_burn,
        "burn_rate": burn_rate,
        "ready": total_count >= min_samples,
    }


def _build_api_latency_snapshot() -> dict[str, Any]:
    generated_at = datetime.now(timezone.utc)
    warning_ms = max(1.0, float(ops_runtime.API_LATENCY_P95_WARNING_MS))
    critical_ms = max(warning_ms, float(ops_runtime.API_LATENCY_P95_CRITICAL_MS))
    min_samples = max(1, int(ops_runtime.API_LATENCY_MIN_SAMPLES))
    window_size = max(20, ops_runtime.API_LATENCY_MONITOR_WINDOW)
    burn_short_window_min = max(1, int(ops_runtime.API_BURN_RATE_SHORT_WINDOW_MIN))
    burn_long_window_min = max(burn_short_window_min, int(ops_runtime.API_BURN_RATE_LONG_WINDOW_MIN))
    burn_min_samples = max(1, int(ops_runtime.API_BURN_RATE_MIN_SAMPLES))
    burn_warning = max(0.1, float(ops_runtime.API_BURN_RATE_WARNING))
    burn_critical = max(burn_warning, float(ops_runtime.API_BURN_RATE_CRITICAL))
    stale_after_minutes = max(burn_long_window_min, int(ops_runtime.API_LATENCY_STALE_AFTER_MIN))
    stale_cutoff = generated_at - timedelta(minutes=stale_after_minutes)
    error_slo_percent = max(0.1, min(100.0, float(ops_runtime.API_BURN_RATE_ERROR_SLO_PERCENT)))
    latency_slo_percent = max(0.1, min(100.0, float(ops_runtime.API_BURN_RATE_LATENCY_SLO_PERCENT)))
    error_budget_percent = max(0.01, round(100.0 - error_slo_percent, 4))
    latency_budget_percent = max(0.01, round(100.0 - latency_slo_percent, 4))
    burn_sample_limit = max(window_size, int(ops_runtime.API_BURN_RATE_SAMPLE_LIMIT))
    endpoints: list[dict[str, Any]] = []

    with _API_LATENCY_LOCK:
        memory_samples = {key: list(values) for key, values in _API_LATENCY_SAMPLES.items()}
        memory_last_seen = dict(_API_LATENCY_LAST_SEEN_AT)
        for target in ops_runtime.API_LATENCY_TARGETS:
            key = target["key"]
            persisted_records, persisted_last_seen_at = _load_persisted_api_latency_records(
                endpoint_key=key,
                limit=burn_sample_limit,
            )
            sample_source = "database" if persisted_records else "memory"
            latency_records = persisted_records[:window_size] if persisted_records else []
            samples = (
                [float(row.get("duration_ms") or 0.0) for row in latency_records]
                if persisted_records
                else list(memory_samples.get(key, []))
            )
            sample_count = len(samples)
            p95_ms = _percentile_value(samples, 95.0)
            p99_ms = _percentile_value(samples, 99.0)
            last_seen_at = persisted_last_seen_at or memory_last_seen.get(key)
            last_seen_dt = _as_optional_datetime(last_seen_at)
            error_count = sum(1 for row in latency_records if bool(row.get("is_error"))) if persisted_records else 0
            error_rate_percent = round((error_count / sample_count) * 100.0, 2) if sample_count > 0 else 0.0
            is_stale = last_seen_dt is None or last_seen_dt < stale_cutoff
            low_traffic_latency = (
                sample_count < min_samples
                and error_count == 0
                and (p95_ms is None or p95_ms < warning_ms)
            )

            status = "ok"
            message = "P95 latency is within threshold."
            if is_stale:
                status = "ok"
                message = f"No recent traffic within {stale_after_minutes} minutes; target is idle."
            elif low_traffic_latency:
                status = "ok"
                message = f"Latency monitor is idle while accumulating {min_samples} samples."
            elif sample_count < min_samples:
                status = "warning"
                message = f"Insufficient samples (need >= {min_samples})."
            elif p95_ms is None:
                status = "warning"
                message = "Latency samples are unavailable."
            elif p95_ms >= critical_ms:
                status = "critical"
                message = f"P95 latency {round(p95_ms, 2)}ms exceeds critical threshold {round(critical_ms, 2)}ms."
            elif p95_ms >= warning_ms:
                status = "warning"
                message = f"P95 latency {round(p95_ms, 2)}ms exceeds warning threshold {round(warning_ms, 2)}ms."

            burn_short = {
                "sample_count": 0,
                "error_count": 0,
                "slow_count": 0,
                "error_rate_percent": 0.0,
                "slow_rate_percent": 0.0,
                "error_burn_rate": 0.0,
                "latency_burn_rate": 0.0,
                "burn_rate": 0.0,
                "ready": False,
            }
            burn_long = dict(burn_short)
            if persisted_records:
                burn_short = _build_burn_rate_window_stats(
                    records=persisted_records,
                    since_at=generated_at - timedelta(minutes=burn_short_window_min),
                    latency_warning_ms=warning_ms,
                    error_budget_percent=error_budget_percent,
                    latency_budget_percent=latency_budget_percent,
                    min_samples=burn_min_samples,
                )
                burn_long = _build_burn_rate_window_stats(
                    records=persisted_records,
                    since_at=generated_at - timedelta(minutes=burn_long_window_min),
                    latency_warning_ms=warning_ms,
                    error_budget_percent=error_budget_percent,
                    latency_budget_percent=latency_budget_percent,
                    min_samples=burn_min_samples,
                )

            burn_short_sample_count = int(burn_short.get("sample_count") or 0)
            burn_long_sample_count = int(burn_long.get("sample_count") or 0)
            burn_short_slow_count = int(burn_short.get("slow_count") or 0)
            burn_long_slow_count = int(burn_long.get("slow_count") or 0)
            burn_short_error_count = int(burn_short.get("error_count") or 0)
            burn_long_error_count = int(burn_long.get("error_count") or 0)
            burn_ready = bool(burn_short.get("ready")) and bool(burn_long.get("ready"))
            burn_idle = (
                (burn_short_sample_count + burn_long_sample_count) < burn_min_samples
                and burn_short_error_count == 0
                and burn_long_error_count == 0
                and burn_short_slow_count == 0
                and burn_long_slow_count == 0
            )
            burn_status = "ok"
            burn_message = "Burn-rate is within threshold."
            burn_rate_short = float(burn_short.get("burn_rate") or 0.0)
            burn_rate_long = float(burn_long.get("burn_rate") or 0.0)
            effective_burn = max(burn_rate_short, burn_rate_long)
            if is_stale:
                burn_status = "ok"
                burn_message = f"No recent traffic within {stale_after_minutes} minutes for burn-rate evaluation."
            elif burn_idle:
                burn_status = "ok"
                burn_message = "Burn-rate monitor is idle due to low recent traffic volume."
            elif not burn_ready:
                burn_status = "warning"
                burn_message = "Burn-rate monitor warming up due to low recent sample coverage."
            elif effective_burn >= burn_critical:
                burn_status = "critical"
                burn_message = (
                    f"Burn-rate {round(effective_burn, 2)} exceeds critical threshold {round(burn_critical, 2)}."
                )
            elif effective_burn >= burn_warning:
                burn_status = "warning"
                burn_message = (
                    f"Burn-rate {round(effective_burn, 2)} exceeds warning threshold {round(burn_warning, 2)}."
                )

            endpoints.append(
                {
                    "endpoint": key,
                    "method": target["method"],
                    "path": target["path"],
                    "sample_count": sample_count,
                    "p95_ms": None if p95_ms is None else round(float(p95_ms), 2),
                    "p99_ms": None if p99_ms is None else round(float(p99_ms), 2),
                    "error_count": error_count,
                    "error_rate_percent": error_rate_percent,
                    "status": status,
                    "message": message,
                    "last_seen_at": last_seen_dt.isoformat() if last_seen_dt is not None else None,
                    "sample_source": sample_source,
                    "is_stale": is_stale,
                    "stale_after_minutes": stale_after_minutes,
                    "burn_rate_short": round(burn_rate_short, 4),
                    "burn_rate_long": round(burn_rate_long, 4),
                    "burn_status": burn_status,
                    "burn_message": burn_message,
                    "burn_idle": burn_idle,
                    "burn_windows": {
                        "short": {
                            "window_minutes": burn_short_window_min,
                            "sample_count": burn_short_sample_count,
                            "error_count": burn_short_error_count,
                            "slow_count": burn_short_slow_count,
                            "error_rate_percent": float(burn_short.get("error_rate_percent") or 0.0),
                            "slow_rate_percent": float(burn_short.get("slow_rate_percent") or 0.0),
                            "error_burn_rate": float(burn_short.get("error_burn_rate") or 0.0),
                            "latency_burn_rate": float(burn_short.get("latency_burn_rate") or 0.0),
                            "burn_rate": float(burn_short.get("burn_rate") or 0.0),
                            "ready": bool(burn_short.get("ready")),
                        },
                        "long": {
                            "window_minutes": burn_long_window_min,
                            "sample_count": burn_long_sample_count,
                            "error_count": burn_long_error_count,
                            "slow_count": burn_long_slow_count,
                            "error_rate_percent": float(burn_long.get("error_rate_percent") or 0.0),
                            "slow_rate_percent": float(burn_long.get("slow_rate_percent") or 0.0),
                            "error_burn_rate": float(burn_long.get("error_burn_rate") or 0.0),
                            "latency_burn_rate": float(burn_long.get("latency_burn_rate") or 0.0),
                            "burn_rate": float(burn_long.get("burn_rate") or 0.0),
                            "ready": bool(burn_long.get("ready")),
                        },
                    },
                }
            )

    critical_count = sum(1 for item in endpoints if item["status"] == "critical")
    warning_count = sum(1 for item in endpoints if item["status"] == "warning")
    insufficient_count = sum(
        1
        for item in endpoints
        if (not bool(item.get("is_stale", False))) and int(item.get("sample_count") or 0) < min_samples
    )
    status = "ok"
    if critical_count > 0:
        status = "critical"
    elif warning_count > 0:
        status = "warning"

    message = "Critical API latency monitor is healthy."
    if status == "critical":
        message = f"{critical_count} endpoint(s) exceeded critical P95 threshold."
    elif status == "warning":
        if insufficient_count > 0 and warning_count == insufficient_count:
            message = f"Latency monitor is warming up ({insufficient_count} endpoint(s) below minimum samples)."
        else:
            message = f"{warning_count} endpoint(s) exceeded warning P95 threshold or have low sample coverage."

    burn_critical_count = sum(1 for item in endpoints if item.get("burn_status") == "critical")
    burn_warning_count = sum(1 for item in endpoints if item.get("burn_status") == "warning")
    burn_warming_up_count = sum(
        1
        for item in endpoints
        if item.get("burn_status") == "warning"
        and (
            bool((item.get("burn_windows") or {}).get("short", {}).get("ready")) is False
            or bool((item.get("burn_windows") or {}).get("long", {}).get("ready")) is False
        )
    )
    burn_status = "ok"
    if burn_critical_count > 0:
        burn_status = "critical"
    elif burn_warning_count > 0:
        burn_status = "warning"
    burn_message = "Burn-rate monitor is healthy."
    if burn_status == "critical":
        burn_message = f"{burn_critical_count} endpoint(s) exceeded critical burn-rate threshold."
    elif burn_status == "warning":
        if burn_warning_count == burn_warming_up_count:
            burn_message = "Burn-rate monitor warming up (insufficient sample coverage)."
        else:
            burn_message = f"{burn_warning_count} endpoint(s) exceeded burn-rate warning threshold."

    return {
        "status": status,
        "message": message,
        "enabled": ops_runtime.API_LATENCY_MONITOR_ENABLED,
        "warning_threshold_ms": round(warning_ms, 2),
        "critical_threshold_ms": round(critical_ms, 2),
        "stale_after_minutes": stale_after_minutes,
        "min_samples": min_samples,
        "window_size": window_size,
        "persist_enabled": ops_runtime.API_LATENCY_PERSIST_ENABLED,
        "persist_retention_days": ops_runtime.API_LATENCY_PERSIST_RETENTION_DAYS,
        "target_count": len(ops_runtime.API_LATENCY_TARGETS),
        "critical_count": critical_count,
        "warning_count": warning_count,
        "insufficient_samples_count": insufficient_count,
        "burn_rate": {
            "status": burn_status,
            "message": burn_message,
            "short_window_minutes": burn_short_window_min,
            "long_window_minutes": burn_long_window_min,
            "warning_threshold": round(burn_warning, 4),
            "critical_threshold": round(burn_critical, 4),
            "min_samples": burn_min_samples,
            "error_slo_percent": round(error_slo_percent, 4),
            "latency_slo_percent": round(latency_slo_percent, 4),
            "error_budget_percent": error_budget_percent,
            "latency_budget_percent": latency_budget_percent,
            "critical_count": burn_critical_count,
            "warning_count": burn_warning_count,
            "warming_up_count": burn_warming_up_count,
        },
        "endpoints": endpoints,
    }


def _build_evidence_archive_integrity_batch(
    *,
    sample_per_table: int | None = None,
    max_issues: int | None = None,
) -> dict[str, Any]:
    per_table_limit = max(1, min(int(sample_per_table or ops_runtime.EVIDENCE_INTEGRITY_SAMPLE_PER_TABLE), 200))
    issue_limit = max(1, min(int(max_issues or ops_runtime.EVIDENCE_INTEGRITY_MAX_ISSUES), 500))
    checked_count = 0
    missing_blob_count = 0
    missing_hash_count = 0
    digest_mismatch_count = 0
    read_error_count = 0
    issues: list[dict[str, Any]] = []
    table_summaries: list[dict[str, Any]] = []

    with get_conn() as conn:
        for module, table in ops_runtime.EVIDENCE_INTEGRITY_TABLES:
            rows = conn.execute(
                select(table)
                .order_by(table.c.uploaded_at.desc(), table.c.id.desc())
                .limit(per_table_limit)
            ).mappings().all()
            table_checked = 0
            table_missing_blob = 0
            table_missing_hash = 0
            table_digest_mismatch = 0
            table_read_error = 0

            for row in rows:
                table_checked += 1
                checked_count += 1
                row_id = int(row.get("id") or 0)
                site = str(row.get("site") or "")
                stored_sha = str(row.get("sha256") or "").strip().lower()
                if not stored_sha:
                    table_missing_hash += 1
                    missing_hash_count += 1
                    if len(issues) < issue_limit:
                        issues.append(
                            {
                                "module": module,
                                "evidence_id": row_id,
                                "site": site,
                                "reason": "missing_sha256",
                            }
                        )

                try:
                    blob = _read_evidence_blob(row=dict(row))
                except Exception as exc:  # pragma: no cover - defensive path
                    blob = None
                    table_read_error += 1
                    read_error_count += 1
                    if len(issues) < issue_limit:
                        issues.append(
                            {
                                "module": module,
                                "evidence_id": row_id,
                                "site": site,
                                "reason": "read_error",
                                "error": str(exc),
                            }
                        )

                if blob is None:
                    table_missing_blob += 1
                    missing_blob_count += 1
                    if len(issues) < issue_limit:
                        issues.append(
                            {
                                "module": module,
                                "evidence_id": row_id,
                                "site": site,
                                "reason": "missing_blob",
                                "storage_backend": str(row.get("storage_backend") or "db"),
                            }
                        )
                    continue

                actual_sha = hashlib.sha256(blob).hexdigest()
                if stored_sha and stored_sha != actual_sha:
                    table_digest_mismatch += 1
                    digest_mismatch_count += 1
                    if len(issues) < issue_limit:
                        issues.append(
                            {
                                "module": module,
                                "evidence_id": row_id,
                                "site": site,
                                "reason": "sha256_mismatch",
                                "stored_sha256": stored_sha,
                                "actual_sha256": actual_sha,
                            }
                        )

            table_summaries.append(
                {
                    "module": module,
                    "checked_count": table_checked,
                    "missing_blob_count": table_missing_blob,
                    "missing_hash_count": table_missing_hash,
                    "digest_mismatch_count": table_digest_mismatch,
                    "read_error_count": table_read_error,
                }
            )

    archive = build_monthly_audit_archive(month=None, include_entries=False, max_entries=10000)
    # Verify digest/signature against the exact payload shape used by build_monthly_audit_archive.
    archive_payload = {
        key: value
        for key, value in archive.items()
        if key not in {"archive_sha256", "signature", "signature_algorithm"}
    }
    archive_payload_text = json.dumps(archive_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    computed_archive_sha = hashlib.sha256(archive_payload_text.encode("utf-8")).hexdigest()
    expected_signature = _sign_payload(archive_payload_text)
    stored_signature = archive.get("signature")
    stored_signature_algorithm = str(archive.get("signature_algorithm") or "unsigned")
    archive_sha_ok = str(archive.get("archive_sha256") or "") == computed_archive_sha
    if expected_signature is None:
        archive_signature_ok = stored_signature in {None, ""}
        archive_signature_algorithm_ok = stored_signature_algorithm == "unsigned"
    else:
        archive_signature_ok = stored_signature == expected_signature
        archive_signature_algorithm_ok = stored_signature_algorithm == "hmac-sha256"

    status = "ok"
    if digest_mismatch_count > 0 or (not archive_sha_ok) or (not archive_signature_ok) or (not archive_signature_algorithm_ok):
        status = "critical"
    elif missing_blob_count > 0 or missing_hash_count > 0 or read_error_count > 0 or checked_count == 0:
        status = "warning"

    if status == "critical":
        message = "Evidence/archive integrity critical issue detected."
    elif status == "warning":
        if checked_count == 0:
            message = "No evidence rows available for integrity sampling."
        else:
            message = "Evidence/archive integrity sampling found warnings."
    else:
        message = "Evidence/archive integrity sampling is healthy."

    return {
        "status": status,
        "message": message,
        "sample_per_table": per_table_limit,
        "checked_count": checked_count,
        "missing_blob_count": missing_blob_count,
        "missing_hash_count": missing_hash_count,
        "digest_mismatch_count": digest_mismatch_count,
        "read_error_count": read_error_count,
        "issue_count": len(issues),
        "issues": issues,
        "tables": table_summaries,
        "archive": {
            "month": archive.get("month"),
            "entry_count": archive.get("entry_count"),
            "chain_ok": bool((archive.get("chain") or {}).get("chain_ok", False)),
            "archive_sha_ok": archive_sha_ok,
            "signature_ok": archive_signature_ok,
            "signature_algorithm_ok": archive_signature_algorithm_ok,
            "signature_algorithm": stored_signature_algorithm,
            "signed": expected_signature is not None,
        },
    }

def _next_month_boundary(dt: datetime) -> datetime:
    if dt.month == 12:
        return datetime(dt.year + 1, 1, 1, tzinfo=timezone.utc)
    return datetime(dt.year, dt.month + 1, 1, tzinfo=timezone.utc)

def _month_window_bounds(*, now: datetime | None = None, month_label: str | None = None) -> tuple[str, datetime, datetime]:
    reference = now or datetime.now(timezone.utc)
    if month_label:
        parts = month_label.split("-", 1)
        if len(parts) != 2:
            raise ValueError("month must use YYYY-MM format")
        try:
            year = int(parts[0])
            month = int(parts[1])
            start = datetime(year, month, 1, tzinfo=timezone.utc)
        except ValueError as exc:
            raise ValueError("month must use YYYY-MM format") from exc
    else:
        start = datetime(reference.year, reference.month, 1, tzinfo=timezone.utc)
    end = _next_month_boundary(start)
    return start.strftime("%Y-%m"), start, end

def _build_deploy_checklist_steps(
    *,
    rollback_guide_path: Path,
    rollback_guide_exists: bool,
    rollback_guide_sha256: str | None,
) -> list[dict[str, Any]]:
    return [
        {
            "phase": "pre_deploy",
            "id": "pre_01_backup",
            "required": True,
            "item": "Confirm DB backup/snapshot is available.",
        },
        {
            "phase": "pre_deploy",
            "id": "pre_02_release_note",
            "required": True,
            "item": "Record release scope and rollback owner.",
        },
        {
            "phase": "post_deploy",
            "id": "smoke_01_health",
            "required": True,
            "item": "Verify /health and /meta responses.",
        },
        {
            "phase": "post_deploy",
            "id": "smoke_02_ui_main_shell",
            "required": True,
            "item": "Verify main HTML shell exposes 인증/IAM/점검 entry points.",
            "path": "/?tab=iam",
        },
        {
            "phase": "post_deploy",
            "id": "smoke_03_auth_and_runbook",
            "required": True,
            "item": "Verify /api/auth/me and runbook checks (no critical).",
        },
        {
            "phase": "post_deploy",
            "id": "smoke_04_security",
            "required": True,
            "item": "Verify /api/ops/security/posture and expected rate-limit backend.",
        },
        {
            "phase": "rollback_ready",
            "id": "rollback_01_trigger",
            "required": True,
            "item": "Rollback command prepared (Render rollback API or dashboard).",
        },
        {
            "phase": "rollback_ready",
            "id": "rollback_02_checklist",
            "required": True,
            "item": "Use docs/W15_MIGRATION_ROLLBACK.md for verification sequence.",
            "path": str(rollback_guide_path).replace("\\", "/"),
            "exists": rollback_guide_exists,
            "sha256": rollback_guide_sha256,
        },
    ]

def _build_deploy_checklist_policy(
    *,
    rollback_guide_path: Path,
    rollback_guide_exists: bool,
    rollback_guide_sha256: str | None,
) -> dict[str, Any]:
    return {
        "deploy_smoke_recent_hours": max(1, ops_runtime.DEPLOY_SMOKE_RECENT_HOURS),
        "require_runbook_gate": ops_runtime.DEPLOY_SMOKE_REQUIRE_RUNBOOK_GATE,
        "rollback_on_failure_recommended": True,
        "rollback_guide_required": True,
        "rollback_guide_path": str(rollback_guide_path).replace("\\", "/"),
        "rollback_guide_exists": rollback_guide_exists,
        "rollback_guide_sha256": rollback_guide_sha256,
        "ui_core_path": "/?tab=iam",
        "ui_core_markers": ["ID/PW 로그인", "권한관리", "점검 이력 조회"],
        "version_rule": (
            "env_override"
            if ops_runtime.DEPLOY_CHECKLIST_VERSION_OVERRIDE
            else "current_utc_month + deploy_smoke signature sequence"
        ),
    }

def _build_deploy_checklist_signature(*, policy: dict[str, Any], steps: list[dict[str, Any]]) -> str:
    canonical = json.dumps({"policy": policy, "steps": steps}, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]

def _parse_deploy_checklist_revision(version: str, *, prefix: str) -> int | None:
    candidate = version.strip()
    expected_prefix = f"{prefix}.v"
    if not candidate.startswith(expected_prefix):
        return None
    raw_revision = candidate[len(expected_prefix):]
    if not raw_revision.isdigit():
        return None
    return int(raw_revision)

def _derive_deploy_checklist_version(*, signature: str, generated_at: datetime) -> tuple[str, str]:
    if ops_runtime.DEPLOY_CHECKLIST_VERSION_OVERRIDE:
        return ops_runtime.DEPLOY_CHECKLIST_VERSION_OVERRIDE, "env_override"

    prefix = generated_at.strftime("%Y.%m")
    month_label, month_start, month_end = _month_window_bounds(now=generated_at)
    max_revision = 0
    matched_version: str | None = None
    matched_revision = -1
    with get_conn() as conn:
        rows = conn.execute(
            select(job_runs.c.detail_json)
            .where(job_runs.c.job_name == "deploy_smoke")
            .where(job_runs.c.finished_at >= month_start)
            .where(job_runs.c.finished_at < month_end)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
        ).mappings().all()

    for row in rows:
        detail = _parse_job_detail_json(row.get("detail_json"))
        version = str(detail.get("checklist_version") or "").strip()
        revision = _parse_deploy_checklist_revision(version, prefix=prefix)
        if revision is not None:
            max_revision = max(max_revision, revision)
        detail_signature = str(detail.get("checklist_signature") or "").strip()
        if detail_signature != signature or revision is None:
            continue
        if revision > matched_revision:
            matched_version = version
            matched_revision = revision

    if matched_version:
        return matched_version, f"deploy_smoke_signature_match:{month_label}"
    return f"{prefix}.v{max_revision + 1}", f"auto_increment:{month_label}"

def _build_deploy_checklist_payload() -> dict[str, Any]:
    generated_at = datetime.now(timezone.utc)
    rollback_guide_path = Path("docs/W15_MIGRATION_ROLLBACK.md")
    rollback_guide_exists = rollback_guide_path.exists()
    rollback_guide_sha256: str | None = None
    if rollback_guide_exists:
        try:
            rollback_guide_sha256 = hashlib.sha256(rollback_guide_path.read_bytes()).hexdigest()
        except OSError:
            rollback_guide_exists = False
            rollback_guide_sha256 = None

    policy = _build_deploy_checklist_policy(
        rollback_guide_path=rollback_guide_path,
        rollback_guide_exists=rollback_guide_exists,
        rollback_guide_sha256=rollback_guide_sha256,
    )
    steps = _build_deploy_checklist_steps(
        rollback_guide_path=rollback_guide_path,
        rollback_guide_exists=rollback_guide_exists,
        rollback_guide_sha256=rollback_guide_sha256,
    )
    signature = _build_deploy_checklist_signature(policy=policy, steps=steps)
    version, version_source = _derive_deploy_checklist_version(signature=signature, generated_at=generated_at)

    return {
        "version": version,
        "version_source": version_source,
        "signature": signature,
        "generated_at": generated_at.isoformat(),
        "policy": policy,
        "steps": steps,
    }

def _week_start_utc(dt: datetime) -> datetime:
    return datetime(dt.year, dt.month, dt.day, tzinfo=timezone.utc) - timedelta(days=dt.weekday())

def _startup_path_writable(path_value: str) -> tuple[bool, str]:
    try:
        target = Path(path_value)
        target.mkdir(parents=True, exist_ok=True)
        probe = target / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True, f"Path is writable: {target}"
    except Exception as exc:  # pragma: no cover - filesystem dependent
        return False, f"Path not writable: {path_value} ({exc})"

def _run_startup_preflight_snapshot() -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    checks: list[dict[str, Any]] = []

    for env_name in sorted(ops_runtime.PREFLIGHT_REQUIRED_ENV):
        value = getenv(env_name)
        ok = value is not None and value.strip() != ""
        checks.append(
            {
                "id": f"required_env_{env_name.lower()}",
                "severity": "error",
                "status": "ok" if ok else "error",
                "message": f"{env_name} is configured." if ok else f"{env_name} is missing.",
            }
        )

    redis_required = ops_runtime.API_RATE_LIMIT_STORE == "redis"
    redis_ok = (not redis_required) or bool(ops_runtime.API_RATE_LIMIT_REDIS_URL)
    checks.append(
        {
            "id": "rate_limit_redis_config",
            "severity": "error" if redis_required else "warning",
            "status": "ok" if redis_ok else "error",
            "message": (
                "API rate-limit redis config is valid."
                if redis_ok
                else "API_RATE_LIMIT_STORE=redis requires API_RATE_LIMIT_REDIS_URL."
            ),
        }
    )

    signing_required = ops_runtime.AUDIT_ARCHIVE_SIGNING_REQUIRED
    signing_ok = bool(ops_runtime.AUDIT_ARCHIVE_SIGNING_KEY)
    checks.append(
        {
            "id": "audit_archive_signing_key",
            "severity": "error" if signing_required else "warning",
            "status": "ok" if signing_ok else ("error" if signing_required else "warning"),
            "message": (
                "Audit archive signing key is configured."
                if signing_ok
                else (
                    "AUDIT_ARCHIVE_SIGNING_KEY is required but not configured."
                    if signing_required
                    else "AUDIT_ARCHIVE_SIGNING_KEY is not configured."
                )
            ),
        }
    )

    rollback_guide = Path("docs/W15_MIGRATION_ROLLBACK.md")
    checks.append(
        {
            "id": "rollback_guide_file",
            "severity": "error",
            "status": "ok" if rollback_guide.exists() else "error",
            "message": (
                "Rollback guide file is present."
                if rollback_guide.exists()
                else "Missing docs/W15_MIGRATION_ROLLBACK.md."
            ),
        }
    )

    alert_noise_policy_doc = Path("docs/W17_ALERT_NOISE_POLICY.md")
    checks.append(
        {
            "id": "alert_noise_policy_doc",
            "severity": "warning",
            "status": "ok" if alert_noise_policy_doc.exists() else "warning",
            "message": (
                "Alert noise policy document is present."
                if alert_noise_policy_doc.exists()
                else "Alert noise policy document is missing (docs/W17_ALERT_NOISE_POLICY.md)."
            ),
        }
    )

    if ops_runtime.OPS_DAILY_CHECK_ARCHIVE_ENABLED:
        archive_ok, archive_message = _startup_path_writable(ops_runtime.OPS_DAILY_CHECK_ARCHIVE_PATH)
        checks.append(
            {
                "id": "ops_daily_archive_path",
                "severity": "error",
                "status": "ok" if archive_ok else "error",
                "message": archive_message,
            }
        )

    if ops_runtime.OPS_QUALITY_REPORT_ARCHIVE_ENABLED:
        quality_ok, quality_message = _startup_path_writable(ops_runtime.OPS_QUALITY_REPORT_ARCHIVE_PATH)
        checks.append(
            {
                "id": "ops_quality_report_archive_path",
                "severity": "error",
                "status": "ok" if quality_ok else "error",
                "message": quality_message,
            }
        )

    if ops_runtime.DEPLOY_SMOKE_ARCHIVE_ENABLED:
        deploy_smoke_ok, deploy_smoke_message = _startup_path_writable(ops_runtime.DEPLOY_SMOKE_ARCHIVE_PATH)
        checks.append(
            {
                "id": "deploy_smoke_archive_path",
                "severity": "error",
                "status": "ok" if deploy_smoke_ok else "error",
                "message": deploy_smoke_message,
            }
        )

    if ops_runtime.DR_REHEARSAL_ENABLED:
        dr_ok, dr_message = _startup_path_writable(ops_runtime.DR_REHEARSAL_BACKUP_PATH)
        checks.append(
            {
                "id": "dr_rehearsal_backup_path",
                "severity": "error",
                "status": "ok" if dr_ok else "error",
                "message": dr_message,
            }
        )

    error_count = sum(1 for item in checks if item.get("status") == "error")
    warning_count = sum(1 for item in checks if item.get("status") == "warning")
    overall_status = "critical" if error_count > 0 else ("warning" if warning_count > 0 else "ok")
    return {
        "generated_at": now.isoformat(),
        "env": ops_runtime.ENV_NAME,
        "fail_on_error": ops_runtime.PREFLIGHT_FAIL_ON_ERROR,
        "overall_status": overall_status,
        "has_error": error_count > 0,
        "error_count": error_count,
        "warning_count": warning_count,
        "check_count": len(checks),
        "checks": checks,
    }

def _refresh_startup_preflight_snapshot() -> dict[str, Any]:
    snapshot = _run_startup_preflight_snapshot()
    with _PREFLIGHT_LOCK:
        _PREFLIGHT_SNAPSHOT.clear()
        _PREFLIGHT_SNAPSHOT.update(snapshot)
    return dict(snapshot)

def _get_startup_preflight_snapshot(*, refresh: bool = False) -> dict[str, Any]:
    if refresh:
        return _refresh_startup_preflight_snapshot()
    with _PREFLIGHT_LOCK:
        if _PREFLIGHT_SNAPSHOT:
            return dict(_PREFLIGHT_SNAPSHOT)
    return _refresh_startup_preflight_snapshot()

def _build_alert_noise_policy_snapshot() -> dict[str, Any]:
    return {
        "version": "v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "review_window_days": max(1, ops_runtime.ALERT_NOISE_REVIEW_WINDOW_DAYS),
        "false_positive_threshold_percent": round(max(0.0, ops_runtime.ALERT_NOISE_FALSE_POSITIVE_THRESHOLD_PERCENT), 2),
        "false_negative_threshold_percent": round(max(0.0, ops_runtime.ALERT_NOISE_FALSE_NEGATIVE_THRESHOLD_PERCENT), 2),
        "policy_doc_path": "docs/W17_ALERT_NOISE_POLICY.md",
        "evaluation": {
            "false_positive_definition": "Dispatched alert without actionable incident confirmation.",
            "false_negative_definition": "Incident confirmed without matching alert dispatch.",
        },
    }

def _build_admin_security_dashboard_snapshot(*, days: int = 30) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_days = max(1, min(int(days), 180))
    start = now - timedelta(days=window_days)
    sensitive_actions = {
        "admin_token_issue",
        "admin_token_rotate",
        "admin_token_revoke",
        "admin_user_create",
        "admin_user_update",
        "sla_policy_update",
        "sla_policy_restore",
        "admin_audit_chain_rebaseline",
    }

    with get_conn() as conn:
        audit_rows = conn.execute(
            select(
                admin_audit_logs.c.actor_username,
                admin_audit_logs.c.action,
                admin_audit_logs.c.status,
                admin_audit_logs.c.created_at,
            ).where(admin_audit_logs.c.created_at >= start)
        ).mappings().all()
        token_rows = conn.execute(
            select(
                admin_tokens.c.id,
                admin_tokens.c.user_id,
                admin_tokens.c.expires_at,
                admin_tokens.c.last_used_at,
                admin_tokens.c.created_at,
                admin_tokens.c.site_scope,
                admin_users.c.role.label("role"),
                admin_users.c.username.label("username"),
            ).where(admin_tokens.c.is_active.is_(True))
            .where(admin_users.c.id == admin_tokens.c.user_id)
        ).mappings().all()
        user_rows = conn.execute(
            select(
                admin_users.c.id,
                admin_users.c.username,
                admin_users.c.role,
                admin_users.c.is_active,
            )
        ).mappings().all()

    user_count = len(user_rows)
    active_users = [row for row in user_rows if bool(row.get("is_active"))]
    active_user_count = len(active_users)

    total_actions = len(audit_rows)
    failed_actions = 0
    sensitive_count = 0
    actor_counts: dict[str, int] = {}
    off_hours_actions = 0
    sensitive_events: list[dict[str, Any]] = []

    for row in audit_rows:
        actor = str(row.get("actor_username") or "unknown")
        actor_counts[actor] = actor_counts.get(actor, 0) + 1
        action = str(row.get("action") or "")
        status = str(row.get("status") or "success")
        if status in {"warning", "failed", "error"}:
            failed_actions += 1
        if action in sensitive_actions:
            sensitive_count += 1
        created_at = _as_optional_datetime(row.get("created_at"))
        if created_at is not None and (created_at.hour < 6 or created_at.hour >= 22):
            off_hours_actions += 1
        if action in sensitive_actions:
            sensitive_events.append(
                {
                    "actor": actor,
                    "action": action,
                    "status": status,
                    "created_at": created_at.isoformat() if created_at is not None else None,
                    "off_hours": bool(created_at is not None and (created_at.hour < 6 or created_at.hour >= 22)),
                }
            )

    expiring_7d = 0
    stale_14d = 0
    rotate_overdue = 0
    wildcard_scope_tokens = 0
    non_owner_wildcard_tokens = 0
    dormant_30d = 0
    active_token_user_ids: set[int] = set()
    for row in token_rows:
        expires_at = _as_optional_datetime(row.get("expires_at"))
        last_used = _as_optional_datetime(row.get("last_used_at"))
        created_at = _as_optional_datetime(row.get("created_at"))
        user_id_raw = row.get("user_id")
        try:
            user_id = int(user_id_raw) if user_id_raw is not None else None
        except (TypeError, ValueError):
            user_id = None
        if user_id is not None:
            active_token_user_ids.add(user_id)
        if expires_at is not None and expires_at <= (now + timedelta(days=7)):
            expiring_7d += 1
        baseline = last_used or created_at
        if baseline is not None and baseline <= (now - timedelta(days=14)):
            stale_14d += 1
        if baseline is not None and baseline <= (now - timedelta(days=30)):
            dormant_30d += 1
        if created_at is not None and created_at <= (now - timedelta(days=max(1, ADMIN_TOKEN_ROTATE_AFTER_DAYS))):
            rotate_overdue += 1
        token_scope = _site_scope_text_to_list(row.get("site_scope"), default_all=True)
        role = str(row.get("role") or "operator").strip().lower() or "operator"
        if SITE_SCOPE_ALL in token_scope:
            wildcard_scope_tokens += 1
            if role not in {"owner", "admin"}:
                non_owner_wildcard_tokens += 1

    active_user_ids = {
        int(row["id"])
        for row in active_users
        if row.get("id") is not None
    }
    users_without_active_token = len(active_user_ids - active_token_user_ids)

    anomalies: list[dict[str, Any]] = []
    if failed_actions >= max(10, window_days):
        anomalies.append(
            {
                "id": "failed_actions_spike",
                "status": "warning",
                "metric": failed_actions,
                "threshold": max(10, window_days),
                "message": "Failed/warning admin actions are above threshold.",
            }
        )
    if sensitive_count >= max(15, window_days * 2):
        anomalies.append(
            {
                "id": "sensitive_action_volume",
                "status": "warning",
                "metric": sensitive_count,
                "threshold": max(15, window_days * 2),
                "message": "Sensitive admin action volume is elevated.",
            }
        )
    if off_hours_actions >= max(5, window_days // 2):
        anomalies.append(
            {
                "id": "off_hours_activity",
                "status": "warning",
                "metric": off_hours_actions,
                "threshold": max(5, window_days // 2),
                "message": "Off-hours admin action volume requires review.",
            }
        )
    if expiring_7d > 0:
        anomalies.append(
            {
                "id": "token_expiring_soon",
                "status": "warning",
                "metric": expiring_7d,
                "threshold": 0,
                "message": "Active admin tokens are expiring within 7 days.",
            }
        )
    if stale_14d > 0:
        anomalies.append(
            {
                "id": "stale_token_usage",
                "status": "warning",
                "metric": stale_14d,
                "threshold": 0,
                "message": "Some active tokens have not been used in 14+ days.",
            }
        )
    if rotate_overdue > 0:
        anomalies.append(
            {
                "id": "token_rotate_overdue",
                "status": "warning",
                "metric": rotate_overdue,
                "threshold": 0,
                "message": "Some active tokens exceeded rotate-after policy window.",
            }
        )
    if users_without_active_token > 0:
        anomalies.append(
            {
                "id": "users_without_active_token",
                "status": "warning",
                "metric": users_without_active_token,
                "threshold": 0,
                "message": "Some active admin users do not have any active token.",
            }
        )
    if dormant_30d > 0:
        anomalies.append(
            {
                "id": "dormant_tokens",
                "status": "warning",
                "metric": dormant_30d,
                "threshold": 0,
                "message": "Some active tokens have not been used in 30+ days.",
            }
        )
    if non_owner_wildcard_tokens > 0:
        anomalies.append(
            {
                "id": "token_wildcard_scope_non_owner",
                "status": "critical",
                "metric": non_owner_wildcard_tokens,
                "threshold": 0,
                "message": "Wildcard-scope tokens are issued to non-owner roles.",
            }
        )

    top_actors = [
        {"actor": actor, "action_count": count}
        for actor, count in sorted(actor_counts.items(), key=lambda item: item[1], reverse=True)[:10]
    ]

    risk_score = 0
    risk_score += min(25, failed_actions * 2)
    risk_score += min(15, off_hours_actions * 2)
    risk_score += min(20, expiring_7d * 3)
    risk_score += min(20, rotate_overdue * 3)
    risk_score += min(10, users_without_active_token * 2)
    risk_score += min(10, dormant_30d * 2)
    risk_score += min(40, non_owner_wildcard_tokens * 20)
    risk_score = min(100, risk_score)

    if risk_score >= 80:
        risk_level = "critical"
    elif risk_score >= 60:
        risk_level = "high"
    elif risk_score >= 30:
        risk_level = "medium"
    else:
        risk_level = "low"

    anomaly_statuses = {str(item.get("status") or "warning") for item in anomalies}
    if "critical" in anomaly_statuses or risk_level == "critical":
        overall_status = "critical"
    elif anomalies:
        overall_status = "warning"
    else:
        overall_status = "ok"

    recommendation_map = {
        "failed_actions_spike": "최근 실패/경고 관리자 액션을 감사로그에서 원인별로 분류하고 소유자를 지정하세요.",
        "sensitive_action_volume": "민감 작업(토큰/정책/체인수정) 수행자 2인 검토 절차를 적용하세요.",
        "off_hours_activity": "오프아워 작업은 Change Ticket 연동을 의무화하세요.",
        "token_expiring_soon": "7일 이내 만료 토큰을 선제 재발급하고 오래된 토큰을 폐기하세요.",
        "stale_token_usage": "14일 이상 미사용 토큰을 회수 또는 비활성화하세요.",
        "token_rotate_overdue": "회전 주기 초과 토큰을 즉시 rotate 하세요.",
        "users_without_active_token": "활성 사용자 중 토큰이 없는 계정을 점검하고 최소 권한 토큰을 발급하세요.",
        "dormant_tokens": "30일 이상 미사용 토큰은 revoke 후 필요 시 재발급하세요.",
        "token_wildcard_scope_non_owner": "비-owner wildcard 토큰을 site 범위 토큰으로 즉시 교체하세요.",
    }
    recommendations: list[str] = []
    for anomaly in anomalies:
        rec = recommendation_map.get(str(anomaly.get("id") or ""))
        if rec and rec not in recommendations:
            recommendations.append(rec)

    recent_sensitive_events = sorted(
        sensitive_events,
        key=lambda item: str(item.get("created_at") or ""),
        reverse=True,
    )[:20]

    return {
        "generated_at": now.isoformat(),
        "window_days": window_days,
        "window_start": start.isoformat(),
        "window_end": now.isoformat(),
        "overall_status": overall_status,
        "users": {
            "total_users": user_count,
            "active_users": active_user_count,
        },
        "tokens": {
            "active_tokens": len(token_rows),
            "expiring_7d": expiring_7d,
            "stale_14d": stale_14d,
            "rotate_overdue": rotate_overdue,
            "dormant_30d": dormant_30d,
            "wildcard_scope_tokens": wildcard_scope_tokens,
            "non_owner_wildcard_tokens": non_owner_wildcard_tokens,
        },
        "coverage": {
            "active_users_without_token": users_without_active_token,
        },
        "actions": {
            "total": total_actions,
            "failed_or_warning": failed_actions,
            "sensitive_total": sensitive_count,
            "off_hours_total": off_hours_actions,
            "unique_actors": len(actor_counts),
        },
        "risk": {
            "score": risk_score,
            "level": risk_level,
        },
        "anomalies": anomalies,
        "top_actors": top_actors,
        "recent_sensitive_events": recent_sensitive_events,
        "recommendations": recommendations,
    }

def _build_ops_quality_job_summary(*, start: datetime, end: datetime) -> dict[str, Any]:
    with get_conn() as conn:
        rows = conn.execute(
            select(job_runs.c.job_name, job_runs.c.status, job_runs.c.detail_json, job_runs.c.finished_at)
            .where(job_runs.c.finished_at >= start)
            .where(job_runs.c.finished_at < end)
            .order_by(job_runs.c.finished_at.asc(), job_runs.c.id.asc())
        ).mappings().all()
        deliveries = conn.execute(
            select(alert_deliveries.c.status)
            .where(alert_deliveries.c.created_at >= start)
            .where(alert_deliveries.c.created_at < end)
        ).mappings().all()

    by_job: dict[str, dict[str, int]] = {}
    total_critical_findings = 0
    for row in rows:
        job_name = str(row.get("job_name") or "unknown")
        status = str(row.get("status") or "success")
        bucket = by_job.setdefault(
            job_name,
            {
                "total": 0,
                "success": 0,
                "warning": 0,
                "critical": 0,
            },
        )
        bucket["total"] += 1
        if status in {"success", "ok"}:
            bucket["success"] += 1
        elif status in {"warning"}:
            bucket["warning"] += 1
        else:
            bucket["critical"] += 1

        if job_name == "ops_daily_check":
            detail = _parse_job_detail_json(row.get("detail_json"))
            try:
                total_critical_findings += int(detail.get("critical_count") or 0)
            except (TypeError, ValueError):
                pass

    total_alert = len(deliveries)
    alert_success = 0
    for row in deliveries:
        delivery_status = str(row.get("status") or "")
        if delivery_status == "success":
            alert_success += 1
    alert_success_rate = round((alert_success / total_alert) * 100.0, 2) if total_alert > 0 else None

    job_rows = [
        {
            "job_name": job_name,
            "total": values["total"],
            "success": values["success"],
            "warning": values["warning"],
            "critical": values["critical"],
            "success_rate_percent": round((values["success"] / values["total"]) * 100.0, 2) if values["total"] > 0 else 0.0,
        }
        for job_name, values in sorted(by_job.items())
    ]
    return {
        "job_count": len(job_rows),
        "job_runs_total": len(rows),
        "critical_findings_total": total_critical_findings,
        "alert_delivery_total": total_alert,
        "alert_delivery_success_rate_percent": alert_success_rate,
        "jobs": job_rows,
    }


def _build_ops_quality_report_payload(*, window: str, start: datetime, end: datetime, label: str) -> dict[str, Any]:
    summary = _build_ops_quality_job_summary(start=start, end=end)
    preflight = _get_startup_preflight_snapshot(refresh=False)
    admin_security = _build_admin_security_dashboard_snapshot(days=max(1, int((end - start).days)))
    weekly_streak = _build_ops_quality_weekly_streak_snapshot()
    alert_policy = _build_alert_noise_policy_snapshot()
    recommendation_items: list[str] = []
    if summary.get("critical_findings_total", 0) > 0:
        recommendation_items.append("Reduce critical runbook findings before next release.")
    if (summary.get("alert_delivery_success_rate_percent") or 0) < 95:
        recommendation_items.append("Improve alert channel reliability to >=95% success rate.")
    if admin_security.get("anomalies"):
        recommendation_items.append("Review admin security anomalies and assign owners.")
    if preflight.get("has_error"):
        recommendation_items.append("Resolve startup preflight errors immediately.")
    if not recommendation_items:
        recommendation_items.append("Maintain current operational baseline and continue weekly checks.")

    return {
        "template_version": "ops-quality-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window": window,
        "label": label,
        "period": {
            "start": start.isoformat(),
            "end": end.isoformat(),
        },
        "summary": summary,
        "preflight": {
            "overall_status": preflight.get("overall_status"),
            "error_count": preflight.get("error_count"),
            "warning_count": preflight.get("warning_count"),
        },
        "admin_security": {
            "overall_status": admin_security.get("overall_status"),
            "anomaly_count": len(admin_security.get("anomalies", [])),
            "top_actors": admin_security.get("top_actors", [])[:3],
        },
        "weekly_streak": weekly_streak,
        "alert_noise_policy": {
            "review_window_days": alert_policy.get("review_window_days"),
            "false_positive_threshold_percent": alert_policy.get("false_positive_threshold_percent"),
            "false_negative_threshold_percent": alert_policy.get("false_negative_threshold_percent"),
        },
        "recommendations": recommendation_items,
    }


def _build_ops_quality_report_csv(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
    jobs = summary.get("jobs", []) if isinstance(summary.get("jobs"), list) else []
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["template_version", payload.get("template_version")])
    writer.writerow(["generated_at", payload.get("generated_at")])
    writer.writerow(["window", payload.get("window")])
    writer.writerow(["label", payload.get("label")])
    period = payload.get("period", {}) if isinstance(payload.get("period"), dict) else {}
    writer.writerow(["period_start", period.get("start")])
    writer.writerow(["period_end", period.get("end")])
    writer.writerow(["job_runs_total", summary.get("job_runs_total")])
    writer.writerow(["critical_findings_total", summary.get("critical_findings_total")])
    writer.writerow(["alert_delivery_total", summary.get("alert_delivery_total")])
    writer.writerow(["alert_delivery_success_rate_percent", summary.get("alert_delivery_success_rate_percent")])
    writer.writerow([])
    writer.writerow(["job_name", "total", "success", "warning", "critical", "success_rate_percent"])
    for row in jobs:
        if not isinstance(row, dict):
            continue
        writer.writerow(
            [
                row.get("job_name"),
                row.get("total"),
                row.get("success"),
                row.get("warning"),
                row.get("critical"),
                row.get("success_rate_percent"),
            ]
        )
    return buffer.getvalue()


def _prune_ops_quality_report_archive_files(*, archive_dir: Path, now: datetime) -> int:
    cutoff = now - timedelta(days=max(1, ops_runtime.OPS_QUALITY_REPORT_ARCHIVE_RETENTION_DAYS))
    deleted_count = 0
    for pattern in ("ops-quality-report-*.json", "ops-quality-report-*.csv"):
        for file_path in archive_dir.glob(pattern):
            try:
                modified_at = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
            except OSError:
                continue
            if modified_at >= cutoff:
                continue
            try:
                file_path.unlink()
                deleted_count += 1
            except OSError:
                continue
    return deleted_count


def _publish_ops_quality_report_artifacts(
    *,
    payload: dict[str, Any],
    window: str,
    finished_at: datetime,
) -> dict[str, Any]:
    archive = {
        "enabled": ops_runtime.OPS_QUALITY_REPORT_ARCHIVE_ENABLED,
        "path": ops_runtime.OPS_QUALITY_REPORT_ARCHIVE_PATH,
        "retention_days": max(1, ops_runtime.OPS_QUALITY_REPORT_ARCHIVE_RETENTION_DAYS),
        "json_file": None,
        "csv_file": None,
        "pruned_files": 0,
        "error": None,
    }
    if not ops_runtime.OPS_QUALITY_REPORT_ARCHIVE_ENABLED:
        return archive
    try:
        archive_dir = Path(ops_runtime.OPS_QUALITY_REPORT_ARCHIVE_PATH)
        archive_dir.mkdir(parents=True, exist_ok=True)
        stamp = finished_at.strftime("%Y%m%dT%H%M%SZ")
        base_name = f"ops-quality-report-{window}-{stamp}"
        json_file = archive_dir / f"{base_name}.json"
        csv_file = archive_dir / f"{base_name}.csv"
        json_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        csv_file.write_text(_build_ops_quality_report_csv(payload), encoding="utf-8")
        archive["json_file"] = str(json_file)
        archive["csv_file"] = str(csv_file)
        archive["pruned_files"] = _prune_ops_quality_report_archive_files(archive_dir=archive_dir, now=finished_at)
    except Exception as exc:  # pragma: no cover - filesystem dependent
        archive["error"] = str(exc)
    return archive


def _build_ops_quality_weekly_streak_snapshot(*, now: datetime | None = None) -> dict[str, Any]:
    current_time = now or datetime.now(timezone.utc)
    configured_target = max(1, ops_runtime.OPS_QUALITY_WEEKLY_STREAK_TARGET)
    window_start = current_time - timedelta(days=max(70, configured_target * 14))
    with get_conn() as conn:
        rows = conn.execute(
            select(job_runs.c.finished_at, job_runs.c.status)
            .where(job_runs.c.job_name == ops_runtime.OPS_QUALITY_WEEKLY_JOB_NAME)
            .where(job_runs.c.finished_at >= window_start)
            .order_by(job_runs.c.finished_at.asc(), job_runs.c.id.asc())
        ).mappings().all()

    success_week_starts: list[datetime] = []
    success_weeks: set[str] = set()
    latest_success_at: datetime | None = None
    for row in rows:
        if str(row.get("status") or "") not in {"success", "ok"}:
            continue
        finished_at = _as_optional_datetime(row.get("finished_at"))
        if finished_at is None:
            continue
        week_start = _week_start_utc(finished_at)
        success_weeks.add(week_start.date().isoformat())
        success_week_starts.append(week_start)
        if latest_success_at is None or finished_at > latest_success_at:
            latest_success_at = finished_at

    anchor_week = _week_start_utc(current_time)
    if latest_success_at is not None and anchor_week.date().isoformat() not in success_weeks:
        recent_success_cutoff = current_time - timedelta(days=8)
        if latest_success_at >= recent_success_cutoff:
            anchor_week = _week_start_utc(latest_success_at)

    observed_weeks = 1
    if success_week_starts:
        earliest_success_week = min(success_week_starts)
        observed_weeks = max(1, int((anchor_week - earliest_success_week).days // 7) + 1)
    effective_target = min(configured_target, observed_weeks)
    streak = 0
    probe = anchor_week
    for _ in range(max(1, configured_target * 2, observed_weeks + 1)):
        key = probe.date().isoformat()
        if key in success_weeks:
            streak += 1
            probe = probe - timedelta(days=7)
            continue
        break

    return {
        "target_weeks": effective_target,
        "configured_target_weeks": configured_target,
        "effective_target_weeks": effective_target,
        "current_streak_weeks": streak,
        "target_met": streak >= effective_target,
        "successful_weeks_in_window": len(success_weeks),
        "bootstrap_grace_active": effective_target < configured_target,
        "anchor_week_start": anchor_week.date().isoformat(),
        "latest_success_at": latest_success_at.isoformat() if latest_success_at is not None else None,
    }


def run_ops_quality_report_job(
    *,
    window: str = "weekly",
    month: str | None = None,
    trigger: str = "manual",
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    normalized_window = window.strip().lower()
    if normalized_window not in {"weekly", "monthly"}:
        raise HTTPException(status_code=400, detail="window must be weekly or monthly")

    if normalized_window == "weekly":
        end = now
        start = end - timedelta(days=7)
        label = f"week-{start.date().isoformat()}-{end.date().isoformat()}"
        job_name = ops_runtime.OPS_QUALITY_WEEKLY_JOB_NAME
    else:
        start, end, normalized_month = _month_window(month)
        label = normalized_month
        job_name = ops_runtime.OPS_QUALITY_MONTHLY_JOB_NAME

    payload = _build_ops_quality_report_payload(window=normalized_window, start=start, end=end, label=label)
    summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
    critical_findings = int(summary.get("critical_findings_total") or 0)
    status = "warning" if critical_findings > 0 else "success"
    started_at = datetime.now(timezone.utc)
    finished_at = datetime.now(timezone.utc)
    archive = _publish_ops_quality_report_artifacts(payload=payload, window=normalized_window, finished_at=finished_at)
    detail = {
        "window": normalized_window,
        "label": label,
        "summary": summary,
        "archive": archive,
        "report": payload,
    }
    run_id = _write_job_run(
        job_name=job_name,
        trigger=trigger,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        detail=detail,
    )

    streak = _build_ops_quality_weekly_streak_snapshot()
    return {
        "run_id": run_id,
        "job_name": job_name,
        "trigger": trigger,
        "status": status,
        "window": normalized_window,
        "label": label,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "archive": archive,
        "streak": streak,
        "report": payload,
    }


def run_dr_rehearsal_job(
    *,
    trigger: str = "manual",
    simulate_restore: bool = True,
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    backup_path = Path(ops_runtime.DR_REHEARSAL_BACKUP_PATH)
    counts: dict[str, int] = {}
    status = "success"
    notes: list[str] = []
    backup_file: str | None = None
    restore_valid = False
    pruned_files = 0

    if not ops_runtime.DR_REHEARSAL_ENABLED:
        status = "warning"
        notes.append("DR rehearsal is disabled by policy.")
    else:
        with get_conn() as conn:
            table_map = {
                "inspections": inspections,
                "work_orders": work_orders,
                "work_order_events": work_order_events,
                "job_runs": job_runs,
                "admin_audit_logs": admin_audit_logs,
            }
            for table_name, table in table_map.items():
                total = conn.execute(select(func.count()).select_from(table)).scalar_one_or_none()
                counts[table_name] = int(total or 0)

        try:
            backup_path.mkdir(parents=True, exist_ok=True)
            stamp = started_at.strftime("%Y%m%dT%H%M%SZ")
            backup_file_path = backup_path / f"dr-rehearsal-{stamp}.json"
            payload = {
                "generated_at": started_at.isoformat(),
                "counts": counts,
                "trigger": trigger,
            }
            backup_file_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            backup_file = str(backup_file_path)
            if simulate_restore:
                loaded = json.loads(backup_file_path.read_text(encoding="utf-8"))
                restore_counts = loaded.get("counts", {}) if isinstance(loaded, dict) else {}
                restore_valid = (
                    isinstance(restore_counts, dict)
                    and set(restore_counts.keys()) == set(counts.keys())
                    and all(int(restore_counts.get(key, -1)) >= 0 for key in counts.keys())
                )
                if not restore_valid:
                    status = "warning"
                    notes.append("Restore simulation validation failed.")
                else:
                    notes.append("Restore simulation validation succeeded.")
            cutoff = started_at - timedelta(days=max(1, ops_runtime.DR_REHEARSAL_RETENTION_DAYS))
            for file_path in backup_path.glob("dr-rehearsal-*.json"):
                try:
                    modified_at = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
                except OSError:
                    continue
                if modified_at >= cutoff:
                    continue
                try:
                    file_path.unlink()
                    pruned_files += 1
                except OSError:
                    continue
        except Exception as exc:  # pragma: no cover - filesystem dependent
            status = "critical"
            notes.append(f"DR rehearsal backup write failed: {exc}")

    finished_at = datetime.now(timezone.utc)
    detail = {
        "enabled": ops_runtime.DR_REHEARSAL_ENABLED,
        "backup_path": ops_runtime.DR_REHEARSAL_BACKUP_PATH,
        "retention_days": max(1, ops_runtime.DR_REHEARSAL_RETENTION_DAYS),
        "counts": counts,
        "backup_file": backup_file,
        "restore_valid": restore_valid,
        "simulate_restore": simulate_restore,
        "pruned_files": pruned_files,
        "notes": notes,
    }
    run_id = _write_job_run(
        job_name=ops_runtime.DR_REHEARSAL_JOB_NAME,
        trigger=trigger,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        detail=detail,
    )
    return {
        "run_id": run_id,
        "job_name": ops_runtime.DR_REHEARSAL_JOB_NAME,
        "trigger": trigger,
        "status": status,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        **detail,
    }


def _latest_dr_rehearsal_payload() -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == ops_runtime.DR_REHEARSAL_JOB_NAME)
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


def _normalize_governance_risk_level(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if raw not in {"low", "medium", "high", "critical"}:
        return "high"
    return raw


def _governance_risk_rank(value: str) -> int:
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(_normalize_governance_risk_level(value), 3)


def _build_ops_governance_gate_snapshot(*, now: datetime | None = None) -> dict[str, Any]:
    checked_at = now or datetime.now(timezone.utc)
    max_risk_level = _normalize_governance_risk_level(ops_runtime.GOVERNANCE_GATE_MAX_SECURITY_RISK_LEVEL)
    preflight = _get_startup_preflight_snapshot(refresh=False)
    runbook = _build_ops_runbook_checks_snapshot(now=checked_at)
    deploy_checklist = _build_deploy_checklist_payload()
    security_dashboard = _build_admin_security_dashboard_snapshot(days=ops_runtime.GOVERNANCE_GATE_SECURITY_DASHBOARD_DAYS)
    weekly_streak = _build_ops_quality_weekly_streak_snapshot()
    dr_latest = _latest_dr_rehearsal_payload()

    with get_conn() as conn:
        daily_latest_row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == "ops_daily_check")
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()
        deploy_latest_row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == "deploy_smoke")
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(1)
        ).mappings().first()

    daily_latest_model = _row_to_job_run_model(daily_latest_row) if daily_latest_row is not None else None
    deploy_latest_model = _row_to_job_run_model(deploy_latest_row) if deploy_latest_row is not None else None
    deploy_latest_detail = (
        deploy_latest_model.detail
        if deploy_latest_model is not None and isinstance(deploy_latest_model.detail, dict)
        else {}
    )

    required_rules = {
        "preflight_no_error": ops_runtime.GOVERNANCE_GATE_REQUIRE_PREFLIGHT_NO_ERROR,
        "runbook_no_critical": ops_runtime.GOVERNANCE_GATE_REQUIRE_RUNBOOK_NO_CRITICAL,
        "daily_check_recent": ops_runtime.GOVERNANCE_GATE_REQUIRE_DAILY_CHECK_RECENT,
        "dr_restore_valid_recent": ops_runtime.GOVERNANCE_GATE_REQUIRE_DR_RESTORE_VALID,
        "deploy_smoke_binding_recent": ops_runtime.GOVERNANCE_GATE_REQUIRE_DEPLOY_SMOKE_BINDING,
        "weekly_streak_target_met": ops_runtime.GOVERNANCE_GATE_REQUIRE_WEEKLY_STREAK,
        "security_risk_within_max": True,
    }
    rule_weights = {
        "preflight_no_error": 1.5,
        "runbook_no_critical": 2.0,
        "daily_check_recent": 1.0,
        "dr_restore_valid_recent": max(1.0, ops_runtime.GOVERNANCE_GATE_DR_WEIGHT),
        "deploy_smoke_binding_recent": 1.5,
        "weekly_streak_target_met": 0.75,
        "security_risk_within_max": 1.25,
    }

    rules: list[dict[str, Any]] = []

    def _append_rule(
        *,
        rule_id: str,
        required: bool,
        passed: bool,
        message: str,
        detail: dict[str, Any],
    ) -> None:
        weight = float(rule_weights.get(rule_id, 1.0))
        if passed:
            status = "pass"
        elif required:
            status = "fail"
        else:
            status = "warning"
        rules.append(
            {
                "id": rule_id,
                "required": required,
                "status": status,
                "passed": passed,
                "weight": round(weight, 2),
                "message": message,
                "detail": detail,
            }
        )

    preflight_ok = not bool(preflight.get("has_error", False))
    _append_rule(
        rule_id="preflight_no_error",
        required=required_rules["preflight_no_error"],
        passed=preflight_ok,
        message=(
            "Startup preflight has no blocking errors."
            if preflight_ok
            else "Startup preflight has blocking errors."
        ),
        detail={
            "overall_status": preflight.get("overall_status"),
            "error_count": int(preflight.get("error_count") or 0),
            "warning_count": int(preflight.get("warning_count") or 0),
        },
    )

    runbook_checks = runbook.get("checks", [])
    runbook_critical_count = sum(1 for item in runbook_checks if str(item.get("status") or "") == "critical")
    runbook_ok = runbook_critical_count == 0
    _append_rule(
        rule_id="runbook_no_critical",
        required=required_rules["runbook_no_critical"],
        passed=runbook_ok,
        message=(
            "Runbook checks have no critical items."
            if runbook_ok
            else f"Runbook checks include {runbook_critical_count} critical item(s)."
        ),
        detail={
            "overall_status": runbook.get("overall_status"),
            "critical_count": runbook_critical_count,
            "check_count": len(runbook_checks),
        },
    )

    security_risk_level = _normalize_governance_risk_level((security_dashboard.get("risk") or {}).get("level"))
    security_risk_ok = _governance_risk_rank(security_risk_level) <= _governance_risk_rank(max_risk_level)
    _append_rule(
        rule_id="security_risk_within_max",
        required=required_rules["security_risk_within_max"],
        passed=security_risk_ok,
        message=(
            "Admin security risk level is within configured ceiling."
            if security_risk_ok
            else "Admin security risk level exceeds configured ceiling."
        ),
        detail={
            "risk_level": security_risk_level,
            "risk_score": int((security_dashboard.get("risk") or {}).get("score") or 0),
            "max_risk_level": max_risk_level,
            "window_days": int(security_dashboard.get("window_days") or ops_runtime.GOVERNANCE_GATE_SECURITY_DASHBOARD_DAYS),
        },
    )

    daily_cutoff = checked_at - timedelta(hours=max(1, ops_runtime.GOVERNANCE_GATE_DAILY_CHECK_MAX_AGE_HOURS))
    daily_latest_finished = (
        daily_latest_model.finished_at
        if daily_latest_model is not None
        else None
    )
    daily_recent_ok = daily_latest_finished is not None and daily_latest_finished >= daily_cutoff
    _append_rule(
        rule_id="daily_check_recent",
        required=required_rules["daily_check_recent"],
        passed=daily_recent_ok,
        message=(
            "Ops daily check has a recent run."
            if daily_recent_ok
            else f"No ops daily check run in last {max(1, ops_runtime.GOVERNANCE_GATE_DAILY_CHECK_MAX_AGE_HOURS)} hour(s)."
        ),
        detail={
            "max_age_hours": max(1, ops_runtime.GOVERNANCE_GATE_DAILY_CHECK_MAX_AGE_HOURS),
            "latest_run_at": daily_latest_finished.isoformat() if daily_latest_finished is not None else None,
            "latest_status": daily_latest_model.status if daily_latest_model is not None else None,
        },
    )

    dr_cutoff = checked_at - timedelta(days=max(1, ops_runtime.GOVERNANCE_GATE_DR_MAX_AGE_DAYS))
    dr_latest_finished = _as_optional_datetime(dr_latest.get("finished_at")) if isinstance(dr_latest, dict) else None
    dr_recent_ok = dr_latest_finished is not None and dr_latest_finished >= dr_cutoff
    dr_restore_valid = bool(dr_latest.get("restore_valid", False)) if isinstance(dr_latest, dict) else False
    dr_rule_ok = dr_recent_ok and dr_restore_valid
    if not ops_runtime.DR_REHEARSAL_ENABLED:
        dr_rule_ok = not required_rules["dr_restore_valid_recent"]
    _append_rule(
        rule_id="dr_restore_valid_recent",
        required=required_rules["dr_restore_valid_recent"],
        passed=dr_rule_ok,
        message=(
            "Recent DR rehearsal restore validation is successful."
            if dr_rule_ok
            else (
                "DR rehearsal is disabled."
                if not ops_runtime.DR_REHEARSAL_ENABLED
                else "Recent DR rehearsal with restore_valid=true is required."
            )
        ),
        detail={
            "enabled": ops_runtime.DR_REHEARSAL_ENABLED,
            "max_age_days": max(1, ops_runtime.GOVERNANCE_GATE_DR_MAX_AGE_DAYS),
            "latest_run_at": dr_latest_finished.isoformat() if dr_latest_finished is not None else None,
            "latest_status": dr_latest.get("status") if isinstance(dr_latest, dict) else None,
            "latest_restore_valid": dr_restore_valid,
        },
    )

    deploy_cutoff = checked_at - timedelta(hours=max(1, ops_runtime.GOVERNANCE_GATE_DEPLOY_SMOKE_MAX_AGE_HOURS))
    deploy_latest_finished = deploy_latest_model.finished_at if deploy_latest_model is not None else None
    deploy_recent_ok = deploy_latest_finished is not None and deploy_latest_finished >= deploy_cutoff
    deploy_rollback_ready = bool(deploy_latest_detail.get("rollback_ready", False))
    deploy_runbook_gate = bool(deploy_latest_detail.get("runbook_gate_passed", False))
    deploy_reference_match = bool(deploy_latest_detail.get("rollback_reference_match", False))
    deploy_sha_match_raw = deploy_latest_detail.get("rollback_reference_sha256_match")
    deploy_sha_match = (deploy_sha_match_raw is True) if deploy_sha_match_raw is not None else False
    deploy_current_checklist_version = str(deploy_checklist.get("version") or "")
    deploy_latest_checklist_version = str(deploy_latest_detail.get("checklist_version") or "")
    deploy_checklist_version_match = (
        deploy_latest_checklist_version != ""
        and deploy_latest_checklist_version == deploy_current_checklist_version
    )
    deploy_ui_main_shell_checked = bool(deploy_latest_detail.get("ui_main_shell_checked", False))
    deploy_ui_main_shell_status = str(deploy_latest_detail.get("ui_main_shell_status") or "missing")
    deploy_ui_main_shell_ok = deploy_ui_main_shell_checked and deploy_ui_main_shell_status == "ok"
    deploy_binding_ok = (
        deploy_recent_ok
        and deploy_rollback_ready
        and deploy_reference_match
        and deploy_sha_match
        and deploy_checklist_version_match
        and deploy_ui_main_shell_ok
        and ((not ops_runtime.DEPLOY_SMOKE_REQUIRE_RUNBOOK_GATE) or deploy_runbook_gate)
    )
    _append_rule(
        rule_id="deploy_smoke_binding_recent",
        required=required_rules["deploy_smoke_binding_recent"],
        passed=deploy_binding_ok,
        message=(
            "Recent deploy smoke rollback binding is valid."
            if deploy_binding_ok
            else "Recent deploy smoke rollback binding validation is required."
        ),
        detail={
            "max_age_hours": max(1, ops_runtime.GOVERNANCE_GATE_DEPLOY_SMOKE_MAX_AGE_HOURS),
            "latest_run_at": deploy_latest_finished.isoformat() if deploy_latest_finished is not None else None,
            "latest_status": deploy_latest_model.status if deploy_latest_model is not None else None,
            "rollback_ready": deploy_rollback_ready,
            "runbook_gate_passed": deploy_runbook_gate,
            "rollback_reference_match": deploy_reference_match,
            "rollback_reference_sha256_match": deploy_sha_match_raw,
            "current_checklist_version": deploy_current_checklist_version,
            "latest_checklist_version": deploy_latest_checklist_version,
            "checklist_version_match": deploy_checklist_version_match,
            "ui_main_shell_checked": deploy_ui_main_shell_checked,
            "ui_main_shell_status": deploy_ui_main_shell_status,
        },
    )

    streak_met = bool(weekly_streak.get("target_met", False))
    _append_rule(
        rule_id="weekly_streak_target_met",
        required=required_rules["weekly_streak_target_met"],
        passed=streak_met,
        message=(
            "Ops quality weekly streak target is met."
            if streak_met
            else "Ops quality weekly streak target is not met."
        ),
        detail={
            "current_streak_weeks": int(weekly_streak.get("current_streak_weeks") or 0),
            "target_weeks": int(weekly_streak.get("target_weeks") or 0),
        },
    )

    failure_count = sum(1 for rule in rules if rule["status"] == "fail")
    warning_count = sum(1 for rule in rules if rule["status"] == "warning")
    weighted_total = sum(float(rule.get("weight") or 0.0) for rule in rules)
    weighted_passed = sum(float(rule.get("weight") or 0.0) for rule in rules if bool(rule.get("passed")))
    weighted_score_percent = round((weighted_passed / weighted_total) * 100.0, 2) if weighted_total > 0 else 100.0
    decision = "go"
    if (
        failure_count > 0
        or (not ops_runtime.GOVERNANCE_GATE_ALLOW_WARNING and warning_count > 0)
        or weighted_score_percent < max(0.0, min(100.0, ops_runtime.GOVERNANCE_GATE_MIN_WEIGHTED_SCORE_PERCENT))
    ):
        decision = "no_go"
    summary = {
        "total_rules": len(rules),
        "required_rules": sum(1 for rule in rules if bool(rule.get("required"))),
        "passed_rules": sum(1 for rule in rules if rule["status"] == "pass"),
        "failure_count": failure_count,
        "warning_count": warning_count,
        "weighted_total": round(weighted_total, 2),
        "weighted_passed": round(weighted_passed, 2),
        "weighted_score_percent": weighted_score_percent,
    }
    return {
        "generated_at": checked_at.isoformat(),
        "decision": decision,
        "summary": summary,
        "rules": rules,
        "policy": {
            "allow_warning": ops_runtime.GOVERNANCE_GATE_ALLOW_WARNING,
            "max_security_risk_level": max_risk_level,
            "require_preflight_no_error": required_rules["preflight_no_error"],
            "require_runbook_no_critical": required_rules["runbook_no_critical"],
            "require_daily_check_recent": required_rules["daily_check_recent"],
            "daily_check_max_age_hours": max(1, ops_runtime.GOVERNANCE_GATE_DAILY_CHECK_MAX_AGE_HOURS),
            "require_dr_restore_valid_recent": required_rules["dr_restore_valid_recent"],
            "dr_max_age_days": max(1, ops_runtime.GOVERNANCE_GATE_DR_MAX_AGE_DAYS),
            "require_deploy_smoke_binding_recent": required_rules["deploy_smoke_binding_recent"],
            "deploy_smoke_max_age_hours": max(1, ops_runtime.GOVERNANCE_GATE_DEPLOY_SMOKE_MAX_AGE_HOURS),
            "require_weekly_streak_target_met": required_rules["weekly_streak_target_met"],
            "security_dashboard_days": max(7, ops_runtime.GOVERNANCE_GATE_SECURITY_DASHBOARD_DAYS),
            "dr_weight": round(max(1.0, ops_runtime.GOVERNANCE_GATE_DR_WEIGHT), 2),
            "min_weighted_score_percent": round(
                max(0.0, min(100.0, ops_runtime.GOVERNANCE_GATE_MIN_WEIGHTED_SCORE_PERCENT)),
                2,
            ),
        },
    }


def run_ops_governance_gate_job(*, trigger: str = "manual") -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    snapshot = _build_ops_governance_gate_snapshot(now=started_at)
    summary = snapshot.get("summary", {}) if isinstance(snapshot.get("summary"), dict) else {}
    failure_count = int(summary.get("failure_count") or 0)
    warning_count = int(summary.get("warning_count") or 0)
    decision = str(snapshot.get("decision") or "no_go")
    if decision == "no_go":
        status = "critical"
    elif warning_count > 0:
        status = "warning"
    else:
        status = "success"
    finished_at = datetime.now(timezone.utc)
    detail = {
        **snapshot,
        "decision": decision,
        "failure_count": failure_count,
        "warning_count": warning_count,
    }
    run_id = _write_job_run(
        job_name=ops_runtime.OPS_GOVERNANCE_GATE_JOB_NAME,
        trigger=trigger,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        detail=detail,
    )
    return {
        "run_id": run_id,
        "job_name": ops_runtime.OPS_GOVERNANCE_GATE_JOB_NAME,
        "trigger": trigger,
        "status": status,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        **snapshot,
    }


def _latest_ops_governance_gate_payload() -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == ops_runtime.OPS_GOVERNANCE_GATE_JOB_NAME)
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


def _governance_remediation_owner_and_sla(rule_id: str) -> tuple[str, int]:
    owner_sla_map: dict[str, tuple[str, int]] = {
        "preflight_no_error": ("Platform Owner", 4),
        "runbook_no_critical": ("Ops Lead", 4),
        "security_risk_within_max": ("Security Manager", 8),
        "daily_check_recent": ("Ops PM", 12),
        "dr_restore_valid_recent": ("DR Owner", 24),
        "deploy_smoke_binding_recent": ("Release Manager", 8),
        "weekly_streak_target_met": ("Operations Excellence Lead", 24),
    }
    return owner_sla_map.get(rule_id, ("Ops Manager", 24))


def _governance_remediation_action(rule_id: str, default_message: str) -> str:
    actions = {
        "preflight_no_error": "필수 ENV/스토리지 설정 오류를 즉시 수정하고 preflight 재검증",
        "runbook_no_critical": "critical 체크 항목을 담당자에게 할당하고 재실행으로 해소 확인",
        "security_risk_within_max": "보안 위험지표를 낮추기 위해 토큰/권한 이상징후를 우선 조치",
        "daily_check_recent": "ops daily check 배치 상태를 복구하고 최신 실행 이력을 확보",
        "dr_restore_valid_recent": "DR 리허설을 재실행하여 restore_valid=true 결과를 확보",
        "deploy_smoke_binding_recent": "배포 스모크를 재실행하고 롤백 가이드 경로/체크섬 바인딩을 일치",
        "weekly_streak_target_met": "주간 품질 리포트 cadence를 복구하고 streak 목표를 회복",
    }
    return actions.get(rule_id, default_message or "거버넌스 규칙 이슈를 해소하고 재판정 실행")


def _governance_rule_priority(rule_status: str, required: bool) -> int:
    if rule_status == "fail":
        return 1 if required else 2
    if rule_status == "warning":
        return 3 if required else 4
    return 9


def _build_ops_governance_remediation_plan(
    *,
    snapshot: dict[str, Any],
    include_warnings: bool = True,
    max_items: int | None = None,
) -> dict[str, Any]:
    generated_at_raw = snapshot.get("generated_at")
    generated_at = _as_optional_datetime(generated_at_raw) or datetime.now(timezone.utc)
    decision = str(snapshot.get("decision") or "no_go")
    rules = snapshot.get("rules") if isinstance(snapshot.get("rules"), list) else []
    configured_max = (
        max_items
        if max_items is not None
        else ops_runtime.OPS_GOVERNANCE_REMEDIATION_DEFAULT_MAX_ITEMS
    )
    normalized_max = max(1, min(int(configured_max), 200))

    items: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        status = str(rule.get("status") or "").strip().lower()
        if status == "pass":
            continue
        if status == "warning" and (not include_warnings):
            continue
        rule_id = str(rule.get("id") or "")
        required = bool(rule.get("required", False))
        owner_role, sla_hours = _governance_remediation_owner_and_sla(rule_id)
        due_at = generated_at + timedelta(hours=max(1, sla_hours))
        detail = rule.get("detail") if isinstance(rule.get("detail"), dict) else {}
        items.append(
            {
                "rule_id": rule_id,
                "rule_status": status,
                "required": required,
                "priority": _governance_rule_priority(status, required),
                "owner_role": owner_role,
                "sla_hours": max(1, sla_hours),
                "due_at": due_at.isoformat(),
                "action": _governance_remediation_action(rule_id, str(rule.get("message") or "")),
                "reason": str(rule.get("message") or ""),
                "detail": detail,
            }
        )

    items.sort(
        key=lambda item: (
            int(item.get("priority") or 9),
            int(item.get("sla_hours") or 24),
            str(item.get("rule_id") or ""),
        )
    )
    trimmed = items[:normalized_max]
    for idx, item in enumerate(trimmed, start=1):
        item["item_id"] = f"GR-{idx:03d}"

    fail_count = sum(1 for item in items if str(item.get("rule_status")) == "fail")
    warning_count = sum(1 for item in items if str(item.get("rule_status")) == "warning")
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "gate_generated_at": generated_at.isoformat(),
        "decision": decision,
        "include_warnings": include_warnings,
        "max_items": normalized_max,
        "summary": {
            "total_candidates": len(items),
            "fail_count": fail_count,
            "warning_count": warning_count,
            "item_count": len(trimmed),
            "critical_path_count": sum(
                1
                for item in trimmed
                if str(item.get("rule_status")) == "fail" and bool(item.get("required"))
            ),
        },
        "items": trimmed,
    }


def _build_ops_governance_remediation_csv(plan: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "item_id",
            "rule_id",
            "rule_status",
            "required",
            "priority",
            "owner_role",
            "sla_hours",
            "due_at",
            "action",
            "reason",
        ]
    )
    for item in plan.get("items", []):
        if not isinstance(item, dict):
            continue
        writer.writerow(
            [
                item.get("item_id"),
                item.get("rule_id"),
                item.get("rule_status"),
                bool(item.get("required", False)),
                item.get("priority"),
                item.get("owner_role"),
                item.get("sla_hours"),
                item.get("due_at"),
                item.get("action"),
                item.get("reason"),
            ]
        )
    return out.getvalue()


