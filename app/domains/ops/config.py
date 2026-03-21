"""OPS alert/governance configuration shared outside app.main."""

from __future__ import annotations

from collections import deque
from os import getenv
import sys
from threading import Lock
from typing import Any

from app.database import (
    adoption_w02_evidence_files,
    adoption_w03_evidence_files,
    adoption_w04_evidence_files,
    adoption_w07_evidence_files,
    adoption_w09_evidence_files,
    adoption_w10_evidence_files,
    adoption_w11_evidence_files,
    adoption_w12_evidence_files,
    adoption_w13_evidence_files,
    adoption_w14_evidence_files,
    adoption_w15_evidence_files,
    inspection_evidence_files,
)
from app.domains.iam.core import (
    ADMIN_TOKEN_ROTATE_AFTER_DAYS,
    AUDIT_ARCHIVE_SIGNING_KEY,
    ENV_NAME,
    SITE_SCOPE_ALL,
    _env_bool,
    _env_int,
)


def _env_float(name: str, default: float, *, min_value: float) -> float:
    raw = getenv(name)
    if raw is None:
        return max(default, min_value)
    try:
        value = float(raw.strip())
    except ValueError:
        return max(default, min_value)
    return max(value, min_value)


ALERT_WEBHOOK_URL = getenv("ALERT_WEBHOOK_URL", "").strip()
ALERT_WEBHOOK_URLS = getenv("ALERT_WEBHOOK_URLS", "").strip()
ALERT_WEBHOOK_SHARED_TOKEN = getenv("ALERT_WEBHOOK_SHARED_TOKEN", "").strip()
ALERT_WEBHOOK_TOKEN_HEADER = "X-Alert-Webhook-Token"
ALERT_WEBHOOK_TIMEOUT_SEC = float(getenv("ALERT_WEBHOOK_TIMEOUT_SEC", "5"))
ALERT_WEBHOOK_RETRIES = int(getenv("ALERT_WEBHOOK_RETRIES", "3"))
OPS_DAILY_CHECK_ALERT_LEVEL = getenv("OPS_DAILY_CHECK_ALERT_LEVEL", "critical").strip().lower() or "critical"
ALERT_CHANNEL_GUARD_ENABLED = _env_bool("ALERT_CHANNEL_GUARD_ENABLED", True)
ALERT_CHANNEL_GUARD_FAIL_THRESHOLD = _env_int("ALERT_CHANNEL_GUARD_FAIL_THRESHOLD", 3, min_value=1)
ALERT_CHANNEL_GUARD_COOLDOWN_MINUTES = _env_int("ALERT_CHANNEL_GUARD_COOLDOWN_MINUTES", 30, min_value=1)
ALERT_GUARD_RECOVER_MAX_TARGETS = _env_int("ALERT_GUARD_RECOVER_MAX_TARGETS", 30, min_value=1)
ALERT_RETENTION_DAYS = _env_int("ALERT_RETENTION_DAYS", 90, min_value=1)
ALERT_RETENTION_MAX_DELETE = _env_int("ALERT_RETENTION_MAX_DELETE", 5000, min_value=1)
ALERT_RETENTION_ARCHIVE_ENABLED = _env_bool("ALERT_RETENTION_ARCHIVE_ENABLED", True)
ALERT_RETENTION_ARCHIVE_PATH = getenv("ALERT_RETENTION_ARCHIVE_PATH", "data/alert-archives").strip() or "data/alert-archives"
ALERT_MTTR_SLO_ENABLED = _env_bool("ALERT_MTTR_SLO_ENABLED", True)
ALERT_MTTR_SLO_WINDOW_DAYS = _env_int("ALERT_MTTR_SLO_WINDOW_DAYS", 30, min_value=1)
ALERT_MTTR_SLO_THRESHOLD_MINUTES = _env_int("ALERT_MTTR_SLO_THRESHOLD_MINUTES", 45, min_value=1)
ALERT_MTTR_SLO_MIN_INCIDENTS = _env_int("ALERT_MTTR_SLO_MIN_INCIDENTS", 5, min_value=1)
ALERT_MTTR_SLO_AUTO_RECOVER_ENABLED = _env_bool("ALERT_MTTR_SLO_AUTO_RECOVER_ENABLED", True)
ALERT_MTTR_SLO_RECOVER_STATE = getenv("ALERT_MTTR_SLO_RECOVER_STATE", "quarantined").strip().lower() or "quarantined"
ALERT_MTTR_SLO_RECOVER_MAX_TARGETS = _env_int("ALERT_MTTR_SLO_RECOVER_MAX_TARGETS", 30, min_value=1)
ALERT_MTTR_SLO_NOTIFY_ENABLED = _env_bool("ALERT_MTTR_SLO_NOTIFY_ENABLED", True)
ALERT_MTTR_SLO_NOTIFY_EVENT_TYPE = getenv("ALERT_MTTR_SLO_NOTIFY_EVENT_TYPE", "mttr_slo_breach").strip() or "mttr_slo_breach"
ALERT_MTTR_SLO_NOTIFY_COOLDOWN_MINUTES = _env_int("ALERT_MTTR_SLO_NOTIFY_COOLDOWN_MINUTES", 120, min_value=0)
ALERT_MTTR_SLO_TOP_CHANNELS = _env_int("ALERT_MTTR_SLO_TOP_CHANNELS", 15, min_value=1)
API_RATE_LIMIT_STORE = getenv("API_RATE_LIMIT_STORE", "auto").strip().lower()
API_RATE_LIMIT_REDIS_URL = getenv("API_RATE_LIMIT_REDIS_URL", getenv("REDIS_URL", "")).strip()
API_LATENCY_MONITOR_ENABLED = _env_bool("API_LATENCY_MONITOR_ENABLED", True)
API_LATENCY_MONITOR_WINDOW = _env_int("API_LATENCY_MONITOR_WINDOW", 300, min_value=20)
API_LATENCY_MIN_SAMPLES = _env_int("API_LATENCY_MIN_SAMPLES", 8, min_value=1)
API_LATENCY_P95_WARNING_MS = _env_float("API_LATENCY_P95_WARNING_MS", 450.0, min_value=1.0)
API_LATENCY_P95_CRITICAL_MS = _env_float("API_LATENCY_P95_CRITICAL_MS", 900.0, min_value=1.0)
API_LATENCY_PERSIST_ENABLED = _env_bool("API_LATENCY_PERSIST_ENABLED", True)
API_LATENCY_PERSIST_RETENTION_DAYS = _env_int("API_LATENCY_PERSIST_RETENTION_DAYS", 30, min_value=1)
API_BURN_RATE_SHORT_WINDOW_MIN = _env_int("API_BURN_RATE_SHORT_WINDOW_MIN", 5, min_value=1)
API_BURN_RATE_LONG_WINDOW_MIN = _env_int("API_BURN_RATE_LONG_WINDOW_MIN", 60, min_value=1)
API_LATENCY_STALE_AFTER_MIN = _env_int("API_LATENCY_STALE_AFTER_MIN", max(120, API_BURN_RATE_LONG_WINDOW_MIN * 2), min_value=1)
API_BURN_RATE_MIN_SAMPLES = _env_int("API_BURN_RATE_MIN_SAMPLES", 8, min_value=1)
API_BURN_RATE_WARNING = _env_float("API_BURN_RATE_WARNING", 2.0, min_value=0.1)
API_BURN_RATE_CRITICAL = _env_float("API_BURN_RATE_CRITICAL", 10.0, min_value=0.1)
API_BURN_RATE_ERROR_SLO_PERCENT = _env_float("API_BURN_RATE_ERROR_SLO_PERCENT", 99.0, min_value=0.1)
API_BURN_RATE_LATENCY_SLO_PERCENT = _env_float("API_BURN_RATE_LATENCY_SLO_PERCENT", 95.0, min_value=0.1)
API_BURN_RATE_SAMPLE_LIMIT = _env_int("API_BURN_RATE_SAMPLE_LIMIT", 1500, min_value=20)
API_LATENCY_TARGETS_RAW = (
    getenv(
        "API_LATENCY_TARGETS",
        "GET /health,GET /meta,GET /api/inspections,GET /api/work-orders,GET /api/ops/dashboard/summary",
    ).strip()
    or "GET /health,GET /meta,GET /api/inspections,GET /api/work-orders,GET /api/ops/dashboard/summary"
)
DEPLOY_SMOKE_RECENT_HOURS = _env_int("DEPLOY_SMOKE_RECENT_HOURS", 48, min_value=1)
DEPLOY_SMOKE_REQUIRE_RUNBOOK_GATE = _env_bool("DEPLOY_SMOKE_REQUIRE_RUNBOOK_GATE", True)
DEPLOY_SMOKE_ARCHIVE_ENABLED = _env_bool("DEPLOY_SMOKE_ARCHIVE_ENABLED", True)
DEPLOY_SMOKE_ARCHIVE_PATH = getenv("DEPLOY_SMOKE_ARCHIVE_PATH", "data/deploy-smoke-archives").strip() or "data/deploy-smoke-archives"
EVIDENCE_INTEGRITY_SAMPLE_PER_TABLE = _env_int("EVIDENCE_INTEGRITY_SAMPLE_PER_TABLE", 20, min_value=1)
EVIDENCE_INTEGRITY_MAX_ISSUES = _env_int("EVIDENCE_INTEGRITY_MAX_ISSUES", 50, min_value=1)
DEPLOY_CHECKLIST_VERSION_OVERRIDE = getenv("DEPLOY_CHECKLIST_VERSION", "").strip()
PREFLIGHT_REQUIRED_ENV = {
    value.strip()
    for value in getenv("PREFLIGHT_REQUIRED_ENV", "DATABASE_URL").split(",")
    if value.strip()
}
PREFLIGHT_FAIL_ON_ERROR = _env_bool("PREFLIGHT_FAIL_ON_ERROR", ENV_NAME in {"prod", "production"})
ALERT_NOISE_REVIEW_WINDOW_DAYS = _env_int("ALERT_NOISE_REVIEW_WINDOW_DAYS", 14, min_value=1)
ALERT_NOISE_FALSE_POSITIVE_THRESHOLD_PERCENT = _env_float(
    "ALERT_NOISE_FALSE_POSITIVE_THRESHOLD_PERCENT",
    5.0,
    min_value=0.1,
)
ALERT_NOISE_FALSE_NEGATIVE_THRESHOLD_PERCENT = _env_float(
    "ALERT_NOISE_FALSE_NEGATIVE_THRESHOLD_PERCENT",
    1.0,
    min_value=0.1,
)
AUDIT_ARCHIVE_SIGNING_REQUIRED = _env_bool("AUDIT_ARCHIVE_SIGNING_REQUIRED", False)
OPS_DAILY_CHECK_ARCHIVE_ENABLED = _env_bool("OPS_DAILY_CHECK_ARCHIVE_ENABLED", True)
OPS_DAILY_CHECK_ARCHIVE_PATH = getenv("OPS_DAILY_CHECK_ARCHIVE_PATH", "data/ops-daily-check-archives").strip() or "data/ops-daily-check-archives"
OPS_QUALITY_REPORT_ARCHIVE_ENABLED = _env_bool("OPS_QUALITY_REPORT_ARCHIVE_ENABLED", True)
OPS_QUALITY_REPORT_ARCHIVE_PATH = getenv("OPS_QUALITY_REPORT_ARCHIVE_PATH", "data/ops-quality-reports").strip() or "data/ops-quality-reports"
OPS_QUALITY_REPORT_ARCHIVE_RETENTION_DAYS = _env_int("OPS_QUALITY_REPORT_ARCHIVE_RETENTION_DAYS", 180, min_value=1)
OPS_QUALITY_WEEKLY_STREAK_TARGET = _env_int("OPS_QUALITY_WEEKLY_STREAK_TARGET", 4, min_value=1)
DR_REHEARSAL_ENABLED = _env_bool("DR_REHEARSAL_ENABLED", True)
DR_REHEARSAL_BACKUP_PATH = getenv("DR_REHEARSAL_BACKUP_PATH", "data/dr-rehearsal").strip() or "data/dr-rehearsal"
DR_REHEARSAL_RETENTION_DAYS = _env_int("DR_REHEARSAL_RETENTION_DAYS", 120, min_value=1)
GOVERNANCE_GATE_ALLOW_WARNING = _env_bool("GOVERNANCE_GATE_ALLOW_WARNING", True)
GOVERNANCE_GATE_MAX_SECURITY_RISK_LEVEL = getenv("GOVERNANCE_GATE_MAX_SECURITY_RISK_LEVEL", "high").strip().lower() or "high"
GOVERNANCE_GATE_REQUIRE_PREFLIGHT_NO_ERROR = _env_bool("GOVERNANCE_GATE_REQUIRE_PREFLIGHT_NO_ERROR", True)
GOVERNANCE_GATE_REQUIRE_RUNBOOK_NO_CRITICAL = _env_bool("GOVERNANCE_GATE_REQUIRE_RUNBOOK_NO_CRITICAL", True)
GOVERNANCE_GATE_REQUIRE_DAILY_CHECK_RECENT = _env_bool("GOVERNANCE_GATE_REQUIRE_DAILY_CHECK_RECENT", False)
GOVERNANCE_GATE_DAILY_CHECK_MAX_AGE_HOURS = _env_int("GOVERNANCE_GATE_DAILY_CHECK_MAX_AGE_HOURS", 36, min_value=1)
GOVERNANCE_GATE_REQUIRE_DR_RESTORE_VALID = _env_bool("GOVERNANCE_GATE_REQUIRE_DR_RESTORE_VALID", False)
GOVERNANCE_GATE_DR_MAX_AGE_DAYS = _env_int("GOVERNANCE_GATE_DR_MAX_AGE_DAYS", 35, min_value=1)
GOVERNANCE_GATE_REQUIRE_DEPLOY_SMOKE_BINDING = _env_bool("GOVERNANCE_GATE_REQUIRE_DEPLOY_SMOKE_BINDING", False)
GOVERNANCE_GATE_DEPLOY_SMOKE_MAX_AGE_HOURS = _env_int("GOVERNANCE_GATE_DEPLOY_SMOKE_MAX_AGE_HOURS", 72, min_value=1)
GOVERNANCE_GATE_REQUIRE_WEEKLY_STREAK = _env_bool("GOVERNANCE_GATE_REQUIRE_WEEKLY_STREAK", False)
GOVERNANCE_GATE_SECURITY_DASHBOARD_DAYS = _env_int("GOVERNANCE_GATE_SECURITY_DASHBOARD_DAYS", 30, min_value=7)
GOVERNANCE_GATE_DR_WEIGHT = _env_float("GOVERNANCE_GATE_DR_WEIGHT", 2.0, min_value=1.0)
GOVERNANCE_GATE_MIN_WEIGHTED_SCORE_PERCENT = _env_float("GOVERNANCE_GATE_MIN_WEIGHTED_SCORE_PERCENT", 75.0, min_value=0.0)
ALERT_MTTR_SLO_POLICY_KEY = "alert_mttr_slo_default"
ALERT_MTTR_SLO_RECOVER_STATE_SET = {"quarantined", "warning", "all"}
OPS_QUALITY_WEEKLY_JOB_NAME = "ops_quality_report_weekly"
OPS_QUALITY_MONTHLY_JOB_NAME = "ops_quality_report_monthly"
DR_REHEARSAL_JOB_NAME = "dr_rehearsal"
OPS_GOVERNANCE_GATE_JOB_NAME = "ops_governance_gate"
OPS_GOVERNANCE_REMEDIATION_DEFAULT_MAX_ITEMS = 30
W07_DEGRADATION_ALERT_EVENT_TYPE = "adoption_w07_quality_degradation"
OPS_GOVERNANCE_REMEDIATION_ESCALATION_EVENT_TYPE = "ops_governance_remediation_escalation"
OPS_GOVERNANCE_REMEDIATION_ESCALATION_JOB_NAME = "ops_governance_remediation_escalation"
OPS_GOVERNANCE_REMEDIATION_AUTO_ASSIGN_JOB_NAME = "ops_governance_remediation_auto_assign"
OPS_GOVERNANCE_REMEDIATION_KPI_JOB_NAME = "ops_governance_remediation_kpi"
OPS_GOVERNANCE_REMEDIATION_AUTOPILOT_JOB_NAME = "ops_governance_remediation_autopilot"
OPS_GOVERNANCE_REMEDIATION_AUTOPILOT_POLICY_KEY = "ops_governance_remediation_autopilot_policy"
GOVERNANCE_REMEDIATION_ESCALATION_ENABLED = _env_bool("GOVERNANCE_REMEDIATION_ESCALATION_ENABLED", True)
GOVERNANCE_REMEDIATION_ESCALATION_DUE_SOON_HOURS = _env_int(
    "GOVERNANCE_REMEDIATION_ESCALATION_DUE_SOON_HOURS",
    12,
    min_value=0,
)
GOVERNANCE_REMEDIATION_ESCALATION_NOTIFY_ENABLED = _env_bool(
    "GOVERNANCE_REMEDIATION_ESCALATION_NOTIFY_ENABLED",
    True,
)
GOVERNANCE_REMEDIATION_AUTO_ASSIGN_ENABLED = _env_bool("GOVERNANCE_REMEDIATION_AUTO_ASSIGN_ENABLED", True)
GOVERNANCE_REMEDIATION_AUTO_ASSIGN_MAX_ITEMS = _env_int(
    "GOVERNANCE_REMEDIATION_AUTO_ASSIGN_MAX_ITEMS",
    30,
    min_value=1,
)
GOVERNANCE_REMEDIATION_KPI_WINDOW_DAYS = _env_int(
    "GOVERNANCE_REMEDIATION_KPI_WINDOW_DAYS",
    14,
    min_value=1,
)
GOVERNANCE_REMEDIATION_KPI_DUE_SOON_HOURS = _env_int(
    "GOVERNANCE_REMEDIATION_KPI_DUE_SOON_HOURS",
    24,
    min_value=0,
)
GOVERNANCE_REMEDIATION_AUTOPILOT_ENABLED = _env_bool("GOVERNANCE_REMEDIATION_AUTOPILOT_ENABLED", True)
GOVERNANCE_REMEDIATION_AUTOPILOT_NOTIFY_ENABLED = _env_bool(
    "GOVERNANCE_REMEDIATION_AUTOPILOT_NOTIFY_ENABLED",
    True,
)
GOVERNANCE_REMEDIATION_AUTOPILOT_UNASSIGNED_TRIGGER = _env_int(
    "GOVERNANCE_REMEDIATION_AUTOPILOT_UNASSIGNED_TRIGGER",
    3,
    min_value=0,
)
GOVERNANCE_REMEDIATION_AUTOPILOT_OVERDUE_TRIGGER = _env_int(
    "GOVERNANCE_REMEDIATION_AUTOPILOT_OVERDUE_TRIGGER",
    1,
    min_value=0,
)
GOVERNANCE_REMEDIATION_AUTOPILOT_COOLDOWN_MINUTES = _env_int(
    "GOVERNANCE_REMEDIATION_AUTOPILOT_COOLDOWN_MINUTES",
    60,
    min_value=0,
)


def _parse_api_latency_targets(raw: str) -> list[dict[str, str]]:
    methods = {"GET", "POST", "PUT", "PATCH", "DELETE"}
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for token in str(raw or "").split(","):
        chunk = token.strip()
        if not chunk:
            continue
        method = "GET"
        path = chunk
        if ":" in chunk:
            maybe_method, maybe_path = chunk.split(":", 1)
            maybe_method = maybe_method.strip().upper()
            if maybe_method in methods:
                method = maybe_method
                path = maybe_path.strip()
        elif " " in chunk:
            maybe_method, maybe_path = chunk.split(None, 1)
            maybe_method = maybe_method.strip().upper()
            if maybe_method in methods:
                method = maybe_method
                path = maybe_path.strip()
        if not path:
            continue
        if not path.startswith("/"):
            path = "/" + path.lstrip("/")
        key = f"{method} {path}"
        if key in seen:
            continue
        seen.add(key)
        entries.append({"key": key, "method": method, "path": path})
    if entries:
        return entries
    return [
        {"key": "GET /health", "method": "GET", "path": "/health"},
        {"key": "GET /meta", "method": "GET", "path": "/meta"},
    ]


API_LATENCY_TARGETS: list[dict[str, str]] = _parse_api_latency_targets(API_LATENCY_TARGETS_RAW)
_API_LATENCY_LOCK = Lock()
_API_LATENCY_SAMPLES: dict[str, deque[float]] = {}
_API_LATENCY_LAST_SEEN_AT: dict[str, str] = {}
_API_LATENCY_TARGET_KEYS = {entry["key"] for entry in API_LATENCY_TARGETS}
_PREFLIGHT_LOCK = Lock()
_PREFLIGHT_SNAPSHOT: dict[str, Any] = {}

EVIDENCE_INTEGRITY_TABLES: list[tuple[str, Any]] = [
    ("inspection", inspection_evidence_files),
    ("w02", adoption_w02_evidence_files),
    ("w03", adoption_w03_evidence_files),
    ("w04", adoption_w04_evidence_files),
    ("w07", adoption_w07_evidence_files),
    ("w09", adoption_w09_evidence_files),
    ("w10", adoption_w10_evidence_files),
    ("w11", adoption_w11_evidence_files),
    ("w12", adoption_w12_evidence_files),
    ("w13", adoption_w13_evidence_files),
    ("w14", adoption_w14_evidence_files),
    ("w15", adoption_w15_evidence_files),
]


def runtime_value(name: str, default: Any = None) -> Any:
    main_module = sys.modules.get("app.main")
    if main_module is not None and hasattr(main_module, name):
        return getattr(main_module, name)
    if name in globals():
        return globals()[name]
    return default


class _RuntimeConfigProxy:
    def __getattr__(self, name: str) -> Any:
        if name not in globals() and not hasattr(sys.modules.get("app.main"), name):
            raise AttributeError(name)
        return runtime_value(name)


runtime = _RuntimeConfigProxy()
