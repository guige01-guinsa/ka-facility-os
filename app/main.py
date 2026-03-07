import csv
import base64
import hashlib
import html
import hmac
import io
import json
import math
import secrets
import statistics
import string
import time
import zipfile
from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import date
from datetime import datetime, timezone
from datetime import timedelta
from os import getenv
from pathlib import Path, PurePosixPath
from threading import Lock
from typing import Annotated, Any, Callable
from urllib import error as url_error
from urllib import parse as url_parse
from urllib import request as url_request

from fastapi import APIRouter, Depends, FastAPI, File, Form, HTTPException, Header, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.exc import SQLAlchemyError

try:
    from redis import Redis
except Exception:  # pragma: no cover - optional dependency
    Redis = None  # type: ignore[assignment]

from app.database import (
    DATABASE_URL,
    adoption_w02_evidence_files,
    adoption_w02_site_runs,
    adoption_w02_tracker_items,
    adoption_w03_evidence_files,
    adoption_w03_site_runs,
    adoption_w03_tracker_items,
    adoption_w04_evidence_files,
    adoption_w04_site_runs,
    adoption_w04_tracker_items,
    adoption_w07_evidence_files,
    adoption_w07_site_runs,
    adoption_w07_tracker_items,
    adoption_w09_evidence_files,
    adoption_w09_site_runs,
    adoption_w09_tracker_items,
    adoption_w10_evidence_files,
    adoption_w10_site_runs,
    adoption_w10_tracker_items,
    adoption_w11_evidence_files,
    adoption_w11_site_runs,
    adoption_w11_tracker_items,
    adoption_w12_evidence_files,
    adoption_w12_site_runs,
    adoption_w12_tracker_items,
    adoption_w13_evidence_files,
    adoption_w13_site_runs,
    adoption_w13_tracker_items,
    adoption_w14_evidence_files,
    adoption_w14_site_runs,
    adoption_w14_tracker_items,
    adoption_w15_evidence_files,
    adoption_w15_site_runs,
    adoption_w15_tracker_items,
    ops_governance_remediation_tracker_items,
    ops_governance_remediation_tracker_runs,
    api_latency_samples,
    alert_deliveries,
    admin_audit_logs,
    admin_tokens,
    admin_users,
    ensure_database,
    get_conn,
    inspections,
    inspection_evidence_files,
    job_runs,
    sla_policies,
    sla_policy_proposals,
    sla_policy_revisions,
    workflow_locks,
    work_order_events,
    work_orders,
)

from app.web.facility_console import (
    build_facility_console_html as _web_build_facility_console_html,
    build_facility_console_guide_html as _web_build_facility_console_guide_html,
    build_public_modules_html as _web_build_public_modules_html,
)
from app.web.iam_guide import build_iam_guide_html as _web_build_iam_guide_html
from app.web.main_tabs import (
    build_shared_tracker_execution_box_html as _web_build_shared_tracker_execution_box_html,
    build_system_main_tabs_html as _web_build_system_main_tabs_html,
)
from app.web.public_pages import (
    build_public_main_page_html as _web_build_public_main_page_html,
    build_w04_common_mistakes_html as _web_build_w04_common_mistakes_html,
)
from app.web.tutorial import (
    build_tutorial_guide_html as _web_build_tutorial_guide_html,
    build_tutorial_simulator_html as _web_build_tutorial_simulator_html,
)

from app.schemas import (
    AlertRetryRunRequest,
    AlertRetryRunResponse,
    AlertDeliveryRead,
    AdminAuditLogRead,
    AdminTokenIssueRequest,
    AdminTokenIssueResponse,
    AdminTokenRead,
    AdminUserActiveUpdate,
    AdminUserCreate,
    AdminUserUpdate,
    AdminUserPasswordSetRequest,
    AdminUserRead,
    AuthMeUpdateRequest,
    AuthLoginRequest,
    AuthLoginResponse,
    AuthLogoutResponse,
    AuthMeRead,
    AuthSelfDeactivateResponse,
    DashboardSummaryRead,
    DashboardTrendPoint,
    DashboardTrendsRead,
    InspectionCreate,
    InspectionEvidenceRead,
    InspectionRead,
    JobRunRead,
    MonthlyReportRead,
    OpsHandoverBriefRead,
    OpsHandoverInspectionRead,
    OpsHandoverWorkOrderRead,
    SlaAlertChannelResult,
    SlaEscalationRunRequest,
    SlaEscalationRunResponse,
    SlaPolicyRead,
    SlaPolicyProposalCreate,
    SlaPolicyProposalDecision,
    SlaPolicyProposalRead,
    SlaPolicyRestoreRequest,
    SlaPolicyRevisionRead,
    SlaPolicyUpdate,
    SlaWhatIfRequest,
    SlaWhatIfResponse,
    W02EvidenceRead,
    W02TrackerCompletionRead,
    W02TrackerCompletionRequest,
    W02TrackerBootstrapRequest,
    W02TrackerBootstrapResponse,
    W02TrackerItemRead,
    W02TrackerItemUpdate,
    W02TrackerOverviewRead,
    W02TrackerReadinessRead,
    W03EvidenceRead,
    W03TrackerCompletionRead,
    W03TrackerCompletionRequest,
    W03TrackerBootstrapRequest,
    W03TrackerBootstrapResponse,
    W03TrackerItemRead,
    W03TrackerItemUpdate,
    W03TrackerOverviewRead,
    W03TrackerReadinessRead,
    W04EvidenceRead,
    W04TrackerCompletionRead,
    W04TrackerCompletionRequest,
    W04TrackerBootstrapRequest,
    W04TrackerBootstrapResponse,
    W04TrackerItemRead,
    W04TrackerItemUpdate,
    W04TrackerOverviewRead,
    W04TrackerReadinessRead,
    W07EvidenceRead,
    W07TrackerBootstrapRequest,
    W07TrackerBootstrapResponse,
    W07TrackerCompletionRead,
    W07TrackerCompletionRequest,
    W07TrackerItemRead,
    W07TrackerItemUpdate,
    W07TrackerOverviewRead,
    W07TrackerReadinessRead,
    W09EvidenceRead,
    W09TrackerBootstrapRequest,
    W09TrackerBootstrapResponse,
    W09TrackerCompletionRead,
    W09TrackerCompletionRequest,
    W09TrackerItemRead,
    W09TrackerItemUpdate,
    W09TrackerOverviewRead,
    W09TrackerReadinessRead,
    W10EvidenceRead,
    W10TrackerBootstrapRequest,
    W10TrackerBootstrapResponse,
    W10TrackerCompletionRead,
    W10TrackerCompletionRequest,
    W10TrackerItemRead,
    W10TrackerItemUpdate,
    W10TrackerOverviewRead,
    W10TrackerReadinessRead,
    W11EvidenceRead,
    W11TrackerBootstrapRequest,
    W11TrackerBootstrapResponse,
    W11TrackerCompletionRead,
    W11TrackerCompletionRequest,
    W11TrackerItemRead,
    W11TrackerItemUpdate,
    W11TrackerOverviewRead,
    W11TrackerReadinessRead,
    W12EvidenceRead,
    W12TrackerBootstrapRequest,
    W12TrackerBootstrapResponse,
    W12TrackerCompletionRead,
    W12TrackerCompletionRequest,
    W12TrackerItemRead,
    W12TrackerItemUpdate,
    W12TrackerOverviewRead,
    W12TrackerReadinessRead,
    W13EvidenceRead,
    W13TrackerBootstrapRequest,
    W13TrackerBootstrapResponse,
    W13TrackerCompletionRead,
    W13TrackerCompletionRequest,
    W13TrackerItemRead,
    W13TrackerItemUpdate,
    W13TrackerOverviewRead,
    W13TrackerReadinessRead,
    W14EvidenceRead,
    W14TrackerBootstrapRequest,
    W14TrackerBootstrapResponse,
    W14TrackerCompletionRead,
    W14TrackerCompletionRequest,
    W14TrackerItemRead,
    W14TrackerItemUpdate,
    W14TrackerOverviewRead,
    W14TrackerReadinessRead,
    W15EvidenceRead,
    W15TrackerBootstrapRequest,
    W15TrackerBootstrapResponse,
    W15TrackerCompletionRead,
    W15TrackerCompletionRequest,
    W15TrackerItemRead,
    W15TrackerItemUpdate,
    W15TrackerOverviewRead,
    W15TrackerReadinessRead,
    W21RemediationTrackerCompletionRead,
    W21RemediationTrackerCompletionRequest,
    W21RemediationTrackerItemRead,
    W21RemediationTrackerItemUpdate,
    W21RemediationTrackerOverviewRead,
    W21RemediationTrackerReadinessRead,
    W21RemediationTrackerSyncRequest,
    W21RemediationTrackerSyncResponse,
    WorkflowLockCreate,
    WorkflowLockDraftUpdate,
    WorkflowLockRead,
    WorkflowLockTransitionRequest,
    WorkOrderAck,
    WorkOrderCancel,
    WorkOrderCommentCreate,
    WorkOrderComplete,
    WorkOrderCreate,
    WorkOrderEventRead,
    WorkOrderReopen,
    WorkOrderRead,
)

def _env_bool(name: str, default: bool) -> bool:
    raw = getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, min_value: int = 0) -> int:
    raw = getenv(name)
    if raw is None:
        return max(default, min_value)
    try:
        value = int(raw.strip())
    except ValueError:
        return max(default, min_value)
    return max(value, min_value)


def _env_float(name: str, default: float, *, min_value: float = 0.0) -> float:
    raw = getenv(name)
    if raw is None:
        return max(default, min_value)
    try:
        value = float(raw.strip())
    except ValueError:
        return max(default, min_value)
    return max(value, min_value)


ADMIN_TOKEN = getenv("ADMIN_TOKEN", "").strip()
ENV_NAME = getenv("ENV", "local").lower()
ALLOW_INSECURE_LOCAL_AUTH = _env_bool("ALLOW_INSECURE_LOCAL_AUTH", True)
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
API_RATE_LIMIT_ENABLED = _env_bool("API_RATE_LIMIT_ENABLED", True)
API_RATE_LIMIT_WINDOW_SEC = _env_int("API_RATE_LIMIT_WINDOW_SEC", 60, min_value=1)
API_RATE_LIMIT_MAX_PUBLIC = _env_int("API_RATE_LIMIT_MAX_PUBLIC", 120, min_value=1)
API_RATE_LIMIT_MAX_PUBLIC_HEAVY = _env_int("API_RATE_LIMIT_MAX_PUBLIC_HEAVY", 60, min_value=1)
API_RATE_LIMIT_MAX_AUTH = _env_int("API_RATE_LIMIT_MAX_AUTH", 300, min_value=1)
API_RATE_LIMIT_MAX_AUTH_HEAVY = _env_int("API_RATE_LIMIT_MAX_AUTH_HEAVY", 40, min_value=1)
API_RATE_LIMIT_MAX_AUTH_ADMIN = _env_int("API_RATE_LIMIT_MAX_AUTH_ADMIN", 180, min_value=1)
API_RATE_LIMIT_MAX_AUTH_WRITE = _env_int("API_RATE_LIMIT_MAX_AUTH_WRITE", 120, min_value=1)
API_RATE_LIMIT_MAX_AUTH_UPLOAD = _env_int("API_RATE_LIMIT_MAX_AUTH_UPLOAD", 40, min_value=1)
API_RATE_LIMIT_STORE = getenv("API_RATE_LIMIT_STORE", "auto").strip().lower()
API_RATE_LIMIT_REDIS_URL = getenv("API_RATE_LIMIT_REDIS_URL", getenv("REDIS_URL", "")).strip()
API_RATE_LIMIT_REDIS_KEY_PREFIX = getenv("API_RATE_LIMIT_REDIS_KEY_PREFIX", "kaos:ratelimit").strip() or "kaos:ratelimit"
ADMIN_TOKEN_REQUIRE_EXPIRY = _env_bool("ADMIN_TOKEN_REQUIRE_EXPIRY", True)
ADMIN_TOKEN_MAX_TTL_DAYS = _env_int("ADMIN_TOKEN_MAX_TTL_DAYS", 30, min_value=1)
ADMIN_TOKEN_ROTATE_AFTER_DAYS = _env_int("ADMIN_TOKEN_ROTATE_AFTER_DAYS", 45, min_value=1)
ADMIN_TOKEN_ROTATE_WARNING_DAYS = _env_int("ADMIN_TOKEN_ROTATE_WARNING_DAYS", 7, min_value=0)
ADMIN_TOKEN_MAX_IDLE_DAYS = _env_int("ADMIN_TOKEN_MAX_IDLE_DAYS", 30, min_value=1)
ADMIN_TOKEN_MAX_ACTIVE_PER_USER = _env_int("ADMIN_TOKEN_MAX_ACTIVE_PER_USER", 5, min_value=1)
ADMIN_PASSWORD_MIN_LENGTH = _env_int("ADMIN_PASSWORD_MIN_LENGTH", 8, min_value=8)
ADMIN_PASSWORD_MAX_LENGTH = _env_int("ADMIN_PASSWORD_MAX_LENGTH", 128, min_value=ADMIN_PASSWORD_MIN_LENGTH)
ADMIN_PASSWORD_PBKDF2_ITERATIONS = _env_int("ADMIN_PASSWORD_PBKDF2_ITERATIONS", 210000, min_value=120000)
AUTH_LOGIN_TOKEN_LABEL_DEFAULT = getenv("AUTH_LOGIN_TOKEN_LABEL_DEFAULT", "web-login").strip() or "web-login"
W07_QUALITY_ALERT_ENABLED = _env_bool("W07_QUALITY_ALERT_ENABLED", True)
W07_QUALITY_ALERT_COOLDOWN_MINUTES = _env_int("W07_QUALITY_ALERT_COOLDOWN_MINUTES", 180, min_value=0)
W07_QUALITY_ALERT_MIN_WINDOW_DAYS = _env_int("W07_QUALITY_ALERT_MIN_WINDOW_DAYS", 7, min_value=7)
W07_QUALITY_ALERT_ESCALATION_RATE_THRESHOLD = float(getenv("W07_QUALITY_ALERT_ESCALATION_RATE_THRESHOLD", "30"))
W07_QUALITY_ALERT_SUCCESS_RATE_THRESHOLD = float(getenv("W07_QUALITY_ALERT_SUCCESS_RATE_THRESHOLD", "95"))
W07_WEEKLY_ARCHIVE_ENABLED = _env_bool("W07_WEEKLY_ARCHIVE_ENABLED", True)
W07_WEEKLY_ARCHIVE_PATH = getenv("W07_WEEKLY_ARCHIVE_PATH", "data/adoption-w07-archives").strip() or "data/adoption-w07-archives"
OPS_DAILY_CHECK_ARCHIVE_ENABLED = _env_bool("OPS_DAILY_CHECK_ARCHIVE_ENABLED", True)
OPS_DAILY_CHECK_ARCHIVE_PATH = (
    getenv("OPS_DAILY_CHECK_ARCHIVE_PATH", "data/ops-daily-check-archives").strip()
    or "data/ops-daily-check-archives"
)
OPS_DAILY_CHECK_ARCHIVE_RETENTION_DAYS = _env_int("OPS_DAILY_CHECK_ARCHIVE_RETENTION_DAYS", 60, min_value=1)
OPS_QUALITY_REPORT_ARCHIVE_ENABLED = _env_bool("OPS_QUALITY_REPORT_ARCHIVE_ENABLED", True)
OPS_QUALITY_REPORT_ARCHIVE_PATH = (
    getenv("OPS_QUALITY_REPORT_ARCHIVE_PATH", "data/ops-quality-reports").strip()
    or "data/ops-quality-reports"
)
OPS_QUALITY_REPORT_ARCHIVE_RETENTION_DAYS = _env_int("OPS_QUALITY_REPORT_ARCHIVE_RETENTION_DAYS", 180, min_value=1)
OPS_QUALITY_WEEKLY_STREAK_TARGET = _env_int("OPS_QUALITY_WEEKLY_STREAK_TARGET", 4, min_value=1)
DR_REHEARSAL_ENABLED = _env_bool("DR_REHEARSAL_ENABLED", True)
DR_REHEARSAL_BACKUP_PATH = getenv("DR_REHEARSAL_BACKUP_PATH", "data/dr-rehearsal").strip() or "data/dr-rehearsal"
DR_REHEARSAL_RETENTION_DAYS = _env_int("DR_REHEARSAL_RETENTION_DAYS", 120, min_value=1)
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
EVIDENCE_ALLOWED_CONTENT_TYPES = {
    value.strip().lower()
    for value in getenv(
        "EVIDENCE_ALLOWED_CONTENT_TYPES",
        ",".join(
            [
                "application/pdf",
                "text/plain",
                "text/csv",
                "application/json",
                "image/png",
                "image/jpeg",
                "image/webp",
            ]
        ),
    ).split(",")
    if value.strip()
}
EVIDENCE_STORAGE_BACKEND = getenv("EVIDENCE_STORAGE_BACKEND", "fs").strip().lower() or "fs"
EVIDENCE_STORAGE_PATH = getenv("EVIDENCE_STORAGE_PATH", "data/evidence-objects").strip() or "data/evidence-objects"
EVIDENCE_SCAN_MODE = getenv("EVIDENCE_SCAN_MODE", "basic").strip().lower() or "basic"
EVIDENCE_SCAN_BLOCK_SUSPICIOUS = _env_bool("EVIDENCE_SCAN_BLOCK_SUSPICIOUS", False)
AUDIT_ARCHIVE_SIGNING_KEY = getenv("AUDIT_ARCHIVE_SIGNING_KEY", "").strip()
AUDIT_ARCHIVE_SIGNING_REQUIRED = _env_bool("AUDIT_ARCHIVE_SIGNING_REQUIRED", False)
API_LATENCY_MONITOR_ENABLED = _env_bool("API_LATENCY_MONITOR_ENABLED", True)
API_LATENCY_MONITOR_WINDOW = _env_int("API_LATENCY_MONITOR_WINDOW", 300, min_value=20)
API_LATENCY_MIN_SAMPLES = _env_int("API_LATENCY_MIN_SAMPLES", 8, min_value=1)
API_LATENCY_P95_WARNING_MS = _env_float("API_LATENCY_P95_WARNING_MS", 450.0, min_value=1.0)
API_LATENCY_P95_CRITICAL_MS = _env_float("API_LATENCY_P95_CRITICAL_MS", 900.0, min_value=1.0)
API_LATENCY_PERSIST_ENABLED = _env_bool("API_LATENCY_PERSIST_ENABLED", True)
API_LATENCY_PERSIST_RETENTION_DAYS = _env_int("API_LATENCY_PERSIST_RETENTION_DAYS", 30, min_value=1)
API_LATENCY_PERSIST_PRUNE_INTERVAL = _env_int("API_LATENCY_PERSIST_PRUNE_INTERVAL", 200, min_value=1)
API_BURN_RATE_SHORT_WINDOW_MIN = _env_int("API_BURN_RATE_SHORT_WINDOW_MIN", 5, min_value=1)
API_BURN_RATE_LONG_WINDOW_MIN = _env_int("API_BURN_RATE_LONG_WINDOW_MIN", 60, min_value=1)
API_LATENCY_STALE_AFTER_MIN = _env_int(
    "API_LATENCY_STALE_AFTER_MIN",
    max(120, API_BURN_RATE_LONG_WINDOW_MIN * 2),
    min_value=1,
)
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
EVIDENCE_INTEGRITY_SAMPLE_PER_TABLE = _env_int("EVIDENCE_INTEGRITY_SAMPLE_PER_TABLE", 20, min_value=1)
EVIDENCE_INTEGRITY_MAX_ISSUES = _env_int("EVIDENCE_INTEGRITY_MAX_ISSUES", 50, min_value=1)
DEPLOY_CHECKLIST_VERSION_OVERRIDE = getenv("DEPLOY_CHECKLIST_VERSION", "").strip()
RUNBOOK_CRITICAL_REVIEW_LOOKBACK_DAYS = _env_int("RUNBOOK_CRITICAL_REVIEW_LOOKBACK_DAYS", 35, min_value=7)
RUNBOOK_CRITICAL_REVIEW_SAMPLE_LIMIT = _env_int("RUNBOOK_CRITICAL_REVIEW_SAMPLE_LIMIT", 8, min_value=1)
GOVERNANCE_GATE_ALLOW_WARNING = _env_bool("GOVERNANCE_GATE_ALLOW_WARNING", True)
GOVERNANCE_GATE_MAX_SECURITY_RISK_LEVEL = (
    getenv("GOVERNANCE_GATE_MAX_SECURITY_RISK_LEVEL", "high").strip().lower() or "high"
)
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
GOVERNANCE_GATE_MIN_WEIGHTED_SCORE_PERCENT = _env_float(
    "GOVERNANCE_GATE_MIN_WEIGHTED_SCORE_PERCENT",
    75.0,
    min_value=0.0,
)
SECURITY_HEADERS_BASE: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
HTML_CSP_POLICY = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'unsafe-inline'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)
_RATE_LIMIT_LOCK = Lock()
_RATE_LIMIT_BUCKETS: dict[str, deque[float]] = {}
_RATE_LIMIT_REDIS: Any = None
_API_LATENCY_LOCK = Lock()
_API_LATENCY_SAMPLES: dict[str, deque[float]] = {}
_API_LATENCY_LAST_SEEN_AT: dict[str, str] = {}
_API_LATENCY_TARGET_KEYS: set[str] = set()
_API_LATENCY_PERSIST_WRITE_COUNT = 0
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

ROLE_PERMISSION_MAP: dict[str, set[str]] = {
    "owner": {"*"},
    "manager": {
        "inspections:read",
        "inspections:write",
        "work_orders:read",
        "work_orders:write",
        "work_orders:escalate",
        "reports:read",
        "reports:export",
        "workflow_locks:read",
        "workflow_locks:review",
        "workflow_locks:approve",
        "adoption_w02:read",
        "adoption_w02:write",
        "adoption_w03:read",
        "adoption_w03:write",
        "adoption_w04:read",
        "adoption_w04:write",
        "adoption_w05:read",
        "adoption_w05:write",
        "adoption_w06:read",
        "adoption_w06:write",
        "adoption_w07:read",
        "adoption_w07:write",
        "adoption_w08:read",
        "adoption_w08:write",
        "adoption_w09:read",
        "adoption_w09:write",
        "adoption_w10:read",
        "adoption_w10:write",
        "adoption_w11:read",
        "adoption_w11:write",
        "adoption_w12:read",
        "adoption_w12:write",
        "adoption_w13:read",
        "adoption_w13:write",
        "adoption_w14:read",
        "adoption_w14:write",
        "adoption_w15:read",
        "adoption_w15:write",
    },
    "operator": {
        "inspections:read",
        "inspections:write",
        "work_orders:read",
        "work_orders:write",
        "workflow_locks:read",
        "workflow_locks:write",
        "adoption_w02:read",
        "adoption_w02:write",
        "adoption_w03:read",
        "adoption_w03:write",
        "adoption_w04:read",
        "adoption_w04:write",
        "adoption_w05:read",
        "adoption_w05:write",
        "adoption_w06:read",
        "adoption_w06:write",
        "adoption_w07:read",
        "adoption_w07:write",
        "adoption_w08:read",
        "adoption_w08:write",
        "adoption_w09:read",
        "adoption_w09:write",
        "adoption_w10:read",
        "adoption_w10:write",
        "adoption_w11:read",
        "adoption_w11:write",
        "adoption_w12:read",
        "adoption_w12:write",
        "adoption_w13:read",
        "adoption_w13:write",
        "adoption_w14:read",
        "adoption_w14:write",
        "adoption_w15:read",
        "adoption_w15:write",
    },
    "auditor": {
        "inspections:read",
        "work_orders:read",
        "reports:read",
        "reports:export",
        "workflow_locks:read",
        "adoption_w02:read",
        "adoption_w03:read",
        "adoption_w04:read",
        "adoption_w05:read",
        "adoption_w06:read",
        "adoption_w07:read",
        "adoption_w08:read",
        "adoption_w09:read",
        "adoption_w10:read",
        "adoption_w11:read",
        "adoption_w12:read",
        "adoption_w13:read",
        "adoption_w14:read",
        "adoption_w15:read",
    },
}

SLA_DEFAULT_POLICY_KEY = "default"
SLA_SITE_POLICY_PREFIX = "site:"
SLA_DEFAULT_DUE_HOURS: dict[str, int] = {
    "low": 72,
    "medium": 24,
    "high": 8,
    "critical": 2,
}
OPS_CHECKLIST_NOTE_TAGS = ("[OPS_CHECKLIST_V1]", "[OPS_ELECTRICAL_V1]")
OPS_CHECKLIST_RESULT_SET = {"normal", "abnormal", "na"}
OPS_CHECKLIST_META_REQUIRED_FIELDS = (
    "task_type",
    "equipment",
    "equipment_location",
    "checklist_set_id",
)
OPS_QR_PLACEHOLDER_VALUES = {"설비", "위치", "점검항목"}
OPS_QR_MUTABLE_FIELDS = ("equipment", "location", "default_item")
WORK_ORDER_PRIORITY_RANK: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
INSPECTION_SLA_PRIORITY_BY_RISK: dict[str, str] = {
    "normal": "medium",
    "warning": "high",
    "danger": "critical",
}
INSPECTION_SLA_PRIORITY_BY_ABNORMAL: list[tuple[int, str]] = [
    (3, "critical"),
    (1, "high"),
]
ALERT_MTTR_SLO_POLICY_KEY = "alert_mttr_slo_default"
OPS_GOVERNANCE_REMEDIATION_AUTOPILOT_POLICY_KEY = "ops_governance_remediation_autopilot_policy"
OPS_GOVERNANCE_REMEDIATION_AUTOPILOT_HEALTH_POLICY_KEY = "ops_governance_remediation_autopilot_health_policy"
ALERT_MTTR_SLO_RECOVER_STATE_SET = {"quarantined", "warning", "all"}
W09_KPI_POLICY_KEY_DEFAULT = "adoption_w09_kpi_policy:default"
W09_KPI_POLICY_KEY_SITE_PREFIX = "adoption_w09_kpi_policy:site:"
W09_KPI_STATUS_GREEN = "green"
W09_KPI_STATUS_YELLOW = "yellow"
W09_KPI_STATUS_RED = "red"
W10_SUPPORT_POLICY_KEY_DEFAULT = "adoption_w10_support_policy:default"
W10_SUPPORT_POLICY_KEY_SITE_PREFIX = "adoption_w10_support_policy:site:"
W10_SUPPORT_STATUS_GREEN = "green"
W10_SUPPORT_STATUS_YELLOW = "yellow"
W10_SUPPORT_STATUS_RED = "red"
W11_READINESS_POLICY_KEY_DEFAULT = "adoption_w11_readiness_policy:default"
W11_READINESS_POLICY_KEY_SITE_PREFIX = "adoption_w11_readiness_policy:site:"
W11_READINESS_STATUS_GREEN = "green"
W11_READINESS_STATUS_YELLOW = "yellow"
W11_READINESS_STATUS_RED = "red"
W12_HANDOFF_POLICY_KEY_DEFAULT = "adoption_w12_handoff_policy:default"
W12_HANDOFF_POLICY_KEY_SITE_PREFIX = "adoption_w12_handoff_policy:site:"
W12_HANDOFF_STATUS_GREEN = "green"
W12_HANDOFF_STATUS_YELLOW = "yellow"
W12_HANDOFF_STATUS_RED = "red"
W13_HANDOFF_POLICY_KEY_DEFAULT = "adoption_w13_handoff_policy:default"
W13_HANDOFF_POLICY_KEY_SITE_PREFIX = "adoption_w13_handoff_policy:site:"
W13_HANDOFF_STATUS_GREEN = "green"
W13_HANDOFF_STATUS_YELLOW = "yellow"
W13_HANDOFF_STATUS_RED = "red"
W14_STABILITY_POLICY_KEY_DEFAULT = "adoption_w14_stability_policy:default"
W14_STABILITY_POLICY_KEY_SITE_PREFIX = "adoption_w14_stability_policy:site:"
W14_STABILITY_STATUS_GREEN = "green"
W14_STABILITY_STATUS_YELLOW = "yellow"
W14_STABILITY_STATUS_RED = "red"
W15_EFFICIENCY_POLICY_KEY_DEFAULT = "adoption_w15_efficiency_policy:default"
W15_EFFICIENCY_POLICY_KEY_SITE_PREFIX = "adoption_w15_efficiency_policy:site:"
W15_EFFICIENCY_STATUS_GREEN = "green"
W15_EFFICIENCY_STATUS_YELLOW = "yellow"
W15_EFFICIENCY_STATUS_RED = "red"
SITE_SCOPE_ALL = "*"
WORK_ORDER_TRANSITIONS: dict[str, set[str]] = {
    "open": {"acked", "completed", "canceled"},
    "acked": {"completed", "canceled"},
    "completed": {"open"},
    "canceled": {"open"},
}
SLA_PROPOSAL_STATUS_PENDING = "pending"
SLA_PROPOSAL_STATUS_APPROVED = "approved"
SLA_PROPOSAL_STATUS_REJECTED = "rejected"
WORKFLOW_LOCK_STATUS_DRAFT = "draft"
WORKFLOW_LOCK_STATUS_REVIEW = "review"
WORKFLOW_LOCK_STATUS_APPROVED = "approved"
WORKFLOW_LOCK_STATUS_LOCKED = "locked"
WORKFLOW_LOCK_STATUS_SET = {
    WORKFLOW_LOCK_STATUS_DRAFT,
    WORKFLOW_LOCK_STATUS_REVIEW,
    WORKFLOW_LOCK_STATUS_APPROVED,
    WORKFLOW_LOCK_STATUS_LOCKED,
}
W02_TRACKER_STATUS_PENDING = "pending"
W02_TRACKER_STATUS_IN_PROGRESS = "in_progress"
W02_TRACKER_STATUS_DONE = "done"
W02_TRACKER_STATUS_BLOCKED = "blocked"
W02_TRACKER_STATUS_SET = {
    W02_TRACKER_STATUS_PENDING,
    W02_TRACKER_STATUS_IN_PROGRESS,
    W02_TRACKER_STATUS_DONE,
    W02_TRACKER_STATUS_BLOCKED,
}
W02_SITE_COMPLETION_STATUS_ACTIVE = "active"
W02_SITE_COMPLETION_STATUS_COMPLETED = "completed"
W02_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS = "completed_with_exceptions"
W02_SITE_COMPLETION_STATUS_SET = {
    W02_SITE_COMPLETION_STATUS_ACTIVE,
    W02_SITE_COMPLETION_STATUS_COMPLETED,
    W02_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS,
}
W02_EVIDENCE_REQUIRED_ITEM_TYPES = {"sandbox_scenario"}
W02_EVIDENCE_MAX_BYTES = 5 * 1024 * 1024
W03_TRACKER_STATUS_PENDING = "pending"
W03_TRACKER_STATUS_IN_PROGRESS = "in_progress"
W03_TRACKER_STATUS_DONE = "done"
W03_TRACKER_STATUS_BLOCKED = "blocked"
W03_TRACKER_STATUS_SET = {
    W03_TRACKER_STATUS_PENDING,
    W03_TRACKER_STATUS_IN_PROGRESS,
    W03_TRACKER_STATUS_DONE,
    W03_TRACKER_STATUS_BLOCKED,
}
W03_SITE_COMPLETION_STATUS_ACTIVE = "active"
W03_SITE_COMPLETION_STATUS_COMPLETED = "completed"
W03_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS = "completed_with_exceptions"
W03_SITE_COMPLETION_STATUS_SET = {
    W03_SITE_COMPLETION_STATUS_ACTIVE,
    W03_SITE_COMPLETION_STATUS_COMPLETED,
    W03_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS,
}
W03_EVIDENCE_REQUIRED_ITEM_TYPES = {"role_workshop"}
W03_EVIDENCE_MAX_BYTES = 5 * 1024 * 1024
W04_TRACKER_STATUS_PENDING = "pending"
W04_TRACKER_STATUS_IN_PROGRESS = "in_progress"
W04_TRACKER_STATUS_DONE = "done"
W04_TRACKER_STATUS_BLOCKED = "blocked"
W04_TRACKER_STATUS_SET = {
    W04_TRACKER_STATUS_PENDING,
    W04_TRACKER_STATUS_IN_PROGRESS,
    W04_TRACKER_STATUS_DONE,
    W04_TRACKER_STATUS_BLOCKED,
}
W04_SITE_COMPLETION_STATUS_ACTIVE = "active"
W04_SITE_COMPLETION_STATUS_COMPLETED = "completed"
W04_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS = "completed_with_exceptions"
W04_SITE_COMPLETION_STATUS_SET = {
    W04_SITE_COMPLETION_STATUS_ACTIVE,
    W04_SITE_COMPLETION_STATUS_COMPLETED,
    W04_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS,
}
W04_EVIDENCE_REQUIRED_ITEM_TYPES = {"coaching_action"}
W04_EVIDENCE_MAX_BYTES = 5 * 1024 * 1024
W07_TRACKER_STATUS_PENDING = "pending"
W07_TRACKER_STATUS_IN_PROGRESS = "in_progress"
W07_TRACKER_STATUS_DONE = "done"
W07_TRACKER_STATUS_BLOCKED = "blocked"
W07_TRACKER_STATUS_SET = {
    W07_TRACKER_STATUS_PENDING,
    W07_TRACKER_STATUS_IN_PROGRESS,
    W07_TRACKER_STATUS_DONE,
    W07_TRACKER_STATUS_BLOCKED,
}
W07_SITE_COMPLETION_STATUS_ACTIVE = "active"
W07_SITE_COMPLETION_STATUS_COMPLETED = "completed"
W07_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS = "completed_with_exceptions"
W07_SITE_COMPLETION_STATUS_SET = {
    W07_SITE_COMPLETION_STATUS_ACTIVE,
    W07_SITE_COMPLETION_STATUS_COMPLETED,
    W07_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS,
}
W07_EVIDENCE_REQUIRED_ITEM_TYPES = {"sla_checklist", "coaching_play"}
W07_EVIDENCE_MAX_BYTES = 5 * 1024 * 1024
W09_TRACKER_STATUS_PENDING = "pending"
W09_TRACKER_STATUS_IN_PROGRESS = "in_progress"
W09_TRACKER_STATUS_DONE = "done"
W09_TRACKER_STATUS_BLOCKED = "blocked"
W09_TRACKER_STATUS_SET = {
    W09_TRACKER_STATUS_PENDING,
    W09_TRACKER_STATUS_IN_PROGRESS,
    W09_TRACKER_STATUS_DONE,
    W09_TRACKER_STATUS_BLOCKED,
}
W09_SITE_COMPLETION_STATUS_ACTIVE = "active"
W09_SITE_COMPLETION_STATUS_COMPLETED = "completed"
W09_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS = "completed_with_exceptions"
W09_SITE_COMPLETION_STATUS_SET = {
    W09_SITE_COMPLETION_STATUS_ACTIVE,
    W09_SITE_COMPLETION_STATUS_COMPLETED,
    W09_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS,
}
W09_EVIDENCE_REQUIRED_ITEM_TYPES = {"kpi_threshold", "kpi_escalation"}
W09_EVIDENCE_MAX_BYTES = 5 * 1024 * 1024
W10_TRACKER_STATUS_PENDING = "pending"
W10_TRACKER_STATUS_IN_PROGRESS = "in_progress"
W10_TRACKER_STATUS_DONE = "done"
W10_TRACKER_STATUS_BLOCKED = "blocked"
W10_TRACKER_STATUS_SET = {
    W10_TRACKER_STATUS_PENDING,
    W10_TRACKER_STATUS_IN_PROGRESS,
    W10_TRACKER_STATUS_DONE,
    W10_TRACKER_STATUS_BLOCKED,
}
W10_SITE_COMPLETION_STATUS_ACTIVE = "active"
W10_SITE_COMPLETION_STATUS_COMPLETED = "completed"
W10_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS = "completed_with_exceptions"
W10_SITE_COMPLETION_STATUS_SET = {
    W10_SITE_COMPLETION_STATUS_ACTIVE,
    W10_SITE_COMPLETION_STATUS_COMPLETED,
    W10_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS,
}
W10_EVIDENCE_REQUIRED_ITEM_TYPES = {"self_serve_guide", "troubleshooting_runbook"}
W10_EVIDENCE_MAX_BYTES = 5 * 1024 * 1024
W11_TRACKER_STATUS_PENDING = "pending"
W11_TRACKER_STATUS_IN_PROGRESS = "in_progress"
W11_TRACKER_STATUS_DONE = "done"
W11_TRACKER_STATUS_BLOCKED = "blocked"
W11_TRACKER_STATUS_SET = {
    W11_TRACKER_STATUS_PENDING,
    W11_TRACKER_STATUS_IN_PROGRESS,
    W11_TRACKER_STATUS_DONE,
    W11_TRACKER_STATUS_BLOCKED,
}
W11_SITE_COMPLETION_STATUS_ACTIVE = "active"
W11_SITE_COMPLETION_STATUS_COMPLETED = "completed"
W11_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS = "completed_with_exceptions"
W11_SITE_COMPLETION_STATUS_SET = {
    W11_SITE_COMPLETION_STATUS_ACTIVE,
    W11_SITE_COMPLETION_STATUS_COMPLETED,
    W11_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS,
}
W11_EVIDENCE_REQUIRED_ITEM_TYPES = {"self_serve_guide", "troubleshooting_runbook"}
W11_EVIDENCE_MAX_BYTES = 5 * 1024 * 1024
W12_TRACKER_STATUS_PENDING = "pending"
W12_TRACKER_STATUS_IN_PROGRESS = "in_progress"
W12_TRACKER_STATUS_DONE = "done"
W12_TRACKER_STATUS_BLOCKED = "blocked"
W12_TRACKER_STATUS_SET = {
    W12_TRACKER_STATUS_PENDING,
    W12_TRACKER_STATUS_IN_PROGRESS,
    W12_TRACKER_STATUS_DONE,
    W12_TRACKER_STATUS_BLOCKED,
}
W12_SITE_COMPLETION_STATUS_ACTIVE = "active"
W12_SITE_COMPLETION_STATUS_COMPLETED = "completed"
W12_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS = "completed_with_exceptions"
W12_SITE_COMPLETION_STATUS_SET = {
    W12_SITE_COMPLETION_STATUS_ACTIVE,
    W12_SITE_COMPLETION_STATUS_COMPLETED,
    W12_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS,
}
W12_EVIDENCE_REQUIRED_ITEM_TYPES = {"self_serve_guide", "troubleshooting_runbook"}
W12_EVIDENCE_MAX_BYTES = 5 * 1024 * 1024
W13_TRACKER_STATUS_PENDING = "pending"
W13_TRACKER_STATUS_IN_PROGRESS = "in_progress"
W13_TRACKER_STATUS_DONE = "done"
W13_TRACKER_STATUS_BLOCKED = "blocked"
W13_TRACKER_STATUS_SET = {
    W13_TRACKER_STATUS_PENDING,
    W13_TRACKER_STATUS_IN_PROGRESS,
    W13_TRACKER_STATUS_DONE,
    W13_TRACKER_STATUS_BLOCKED,
}
W13_SITE_COMPLETION_STATUS_ACTIVE = "active"
W13_SITE_COMPLETION_STATUS_COMPLETED = "completed"
W13_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS = "completed_with_exceptions"
W13_SITE_COMPLETION_STATUS_SET = {
    W13_SITE_COMPLETION_STATUS_ACTIVE,
    W13_SITE_COMPLETION_STATUS_COMPLETED,
    W13_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS,
}
W13_EVIDENCE_REQUIRED_ITEM_TYPES = {"self_serve_guide", "troubleshooting_runbook"}
W13_EVIDENCE_MAX_BYTES = 5 * 1024 * 1024
W14_TRACKER_STATUS_PENDING = "pending"
W14_TRACKER_STATUS_IN_PROGRESS = "in_progress"
W14_TRACKER_STATUS_DONE = "done"
W14_TRACKER_STATUS_BLOCKED = "blocked"
W14_TRACKER_STATUS_SET = {
    W14_TRACKER_STATUS_PENDING,
    W14_TRACKER_STATUS_IN_PROGRESS,
    W14_TRACKER_STATUS_DONE,
    W14_TRACKER_STATUS_BLOCKED,
}
W14_SITE_COMPLETION_STATUS_ACTIVE = "active"
W14_SITE_COMPLETION_STATUS_COMPLETED = "completed"
W14_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS = "completed_with_exceptions"
W14_SITE_COMPLETION_STATUS_SET = {
    W14_SITE_COMPLETION_STATUS_ACTIVE,
    W14_SITE_COMPLETION_STATUS_COMPLETED,
    W14_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS,
}
W14_EVIDENCE_REQUIRED_ITEM_TYPES = {"self_serve_guide", "troubleshooting_runbook"}
W14_EVIDENCE_MAX_BYTES = 5 * 1024 * 1024
W15_TRACKER_STATUS_PENDING = "pending"
W15_TRACKER_STATUS_IN_PROGRESS = "in_progress"
W15_TRACKER_STATUS_DONE = "done"
W15_TRACKER_STATUS_BLOCKED = "blocked"
W15_TRACKER_STATUS_SET = {
    W15_TRACKER_STATUS_PENDING,
    W15_TRACKER_STATUS_IN_PROGRESS,
    W15_TRACKER_STATUS_DONE,
    W15_TRACKER_STATUS_BLOCKED,
}
W15_SITE_COMPLETION_STATUS_ACTIVE = "active"
W15_SITE_COMPLETION_STATUS_COMPLETED = "completed"
W15_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS = "completed_with_exceptions"
W15_SITE_COMPLETION_STATUS_SET = {
    W15_SITE_COMPLETION_STATUS_ACTIVE,
    W15_SITE_COMPLETION_STATUS_COMPLETED,
    W15_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS,
}
W15_EVIDENCE_REQUIRED_ITEM_TYPES = {"self_serve_guide", "troubleshooting_runbook"}
W15_EVIDENCE_MAX_BYTES = 5 * 1024 * 1024
INSPECTION_EVIDENCE_MAX_BYTES = 5 * 1024 * 1024
W21_TRACKER_STATUS_PENDING = "pending"
W21_TRACKER_STATUS_IN_PROGRESS = "in_progress"
W21_TRACKER_STATUS_DONE = "done"
W21_TRACKER_STATUS_BLOCKED = "blocked"
W21_TRACKER_STATUS_SET = {
    W21_TRACKER_STATUS_PENDING,
    W21_TRACKER_STATUS_IN_PROGRESS,
    W21_TRACKER_STATUS_DONE,
    W21_TRACKER_STATUS_BLOCKED,
}
W21_COMPLETION_STATUS_ACTIVE = "active"
W21_COMPLETION_STATUS_COMPLETED = "completed"
W21_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS = "completed_with_exceptions"
W21_COMPLETION_STATUS_SET = {
    W21_COMPLETION_STATUS_ACTIVE,
    W21_COMPLETION_STATUS_COMPLETED,
    W21_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS,
}
W21_TRACKER_SCOPE_GLOBAL = "global"
W07_COMPLETION_PACKAGE_MAX_EVIDENCE_FILES = _env_int(
    "W07_COMPLETION_PACKAGE_MAX_EVIDENCE_FILES",
    200,
    min_value=1,
)
W07_COMPLETION_PACKAGE_MAX_EVIDENCE_BYTES = _env_int(
    "W07_COMPLETION_PACKAGE_MAX_EVIDENCE_BYTES",
    50 * 1024 * 1024,
    min_value=1024 * 1024,
)
W07_WEEKLY_JOB_NAME = "adoption_w07_sla_quality_weekly"
W07_DEGRADATION_ALERT_EVENT_TYPE = "adoption_w07_quality_degradation"
OPS_QUALITY_WEEKLY_JOB_NAME = "ops_quality_report_weekly"
OPS_QUALITY_MONTHLY_JOB_NAME = "ops_quality_report_monthly"
DR_REHEARSAL_JOB_NAME = "dr_rehearsal"
OPS_RUNBOOK_CRITICAL_REVIEW_JOB_NAME = "ops_runbook_critical_review"
OPS_GOVERNANCE_GATE_JOB_NAME = "ops_governance_gate"
OPS_GOVERNANCE_REMEDIATION_DEFAULT_MAX_ITEMS = 30
OPS_GOVERNANCE_REMEDIATION_ESCALATION_JOB_NAME = "ops_governance_remediation_escalation"
OPS_GOVERNANCE_REMEDIATION_ESCALATION_EVENT_TYPE = "ops_governance_remediation_escalation"
OPS_GOVERNANCE_REMEDIATION_AUTO_ASSIGN_JOB_NAME = "ops_governance_remediation_auto_assign"
OPS_GOVERNANCE_REMEDIATION_KPI_JOB_NAME = "ops_governance_remediation_kpi"
OPS_GOVERNANCE_REMEDIATION_AUTOPILOT_JOB_NAME = "ops_governance_remediation_autopilot"
OPS_TUTORIAL_SIMULATOR_SESSION_JOB_NAME = "ops_tutorial_simulator_session"
TUTORIAL_SIMULATOR_DEFAULT_SITE = "Tutorial-HQ"
TUTORIAL_SIMULATOR_SAMPLE_ALLOWED_CONTENT_TYPES = {
    "application/json",
    "text/plain",
    "text/markdown",
}
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
    1,
    min_value=0,
)
GOVERNANCE_REMEDIATION_AUTOPILOT_OVERDUE_TRIGGER = _env_int(
    "GOVERNANCE_REMEDIATION_AUTOPILOT_OVERDUE_TRIGGER",
    1,
    min_value=0,
)
GOVERNANCE_REMEDIATION_AUTOPILOT_COOLDOWN_MINUTES = _env_int(
    "GOVERNANCE_REMEDIATION_AUTOPILOT_COOLDOWN_MINUTES",
    30,
    min_value=0,
)
W23_OWNER_ROLE_TO_ADMIN_ROLES: dict[str, tuple[str, ...]] = {
    "Platform Owner": ("owner", "manager"),
    "Security Manager": ("owner", "manager"),
    "Ops Lead": ("owner", "manager", "operator"),
    "Ops PM": ("owner", "manager", "operator"),
    "Release Manager": ("owner", "manager"),
    "DR Owner": ("owner", "manager"),
    "Operations Excellence Lead": ("owner", "manager", "operator"),
    "Ops Manager": ("owner", "manager", "operator"),
}

ADOPTION_PLAN_START = date(2026, 3, 2)
ADOPTION_PLAN_END = date(2026, 6, 12)

ADOPTION_WEEKLY_EXECUTION: list[dict[str, Any]] = [
    {
        "week": 1,
        "start_date": "2026-03-02",
        "end_date": "2026-03-06",
        "phase": "Preparation",
        "focus": "Role workflow lock",
        "actions": [
            "Lock 5 core workflows per role (owner/manager/operator/auditor).",
            "Define first-7-day checklist and support channel.",
            "Identify pilot users and site champions.",
        ],
        "deliverables": ["Workflow map v1", "First-7-day checklist v1", "Pilot roster"],
        "owner": "PM + Ops Lead",
        "success_metric": "Workflow agreement 100%",
    },
    {
        "week": 2,
        "start_date": "2026-03-09",
        "end_date": "2026-03-13",
        "phase": "Preparation",
        "focus": "SOP and sandbox",
        "actions": [
            "Publish one-page SOP for each critical flow.",
            "Prepare sandbox scenario for inspection/work-order/report.",
            "Finalize FAQ top 20 from pilot dry-run.",
        ],
        "deliverables": ["SOP set v1", "Sandbox script", "FAQ v1"],
        "owner": "Ops PM + QA",
        "success_metric": "Pilot dry-run pass rate >= 90%",
    },
    {
        "week": 3,
        "start_date": "2026-03-16",
        "end_date": "2026-03-20",
        "phase": "Launch",
        "focus": "Go-live onboarding",
        "actions": [
            "Run kickoff session (60m) + role-based workshop (20m x 4).",
            "Enable in-app quick links to docs and handover brief.",
            "Start daily office hours (15m) for first week.",
        ],
        "deliverables": ["Kickoff recording", "Role workshop deck", "Daily office-hour notes"],
        "owner": "Product + Training Lead",
        "success_metric": "First-week login rate >= 90%",
    },
    {
        "week": 4,
        "start_date": "2026-03-23",
        "end_date": "2026-03-27",
        "phase": "Adaptation",
        "focus": "First success acceleration",
        "actions": [
            "Track first-success funnel and remove top 3 blockers.",
            "Coach site champions on escalations and alerts.",
            "Publish common mistakes and fast fixes.",
        ],
        "deliverables": ["TTV funnel report", "Champion coaching notes", "Mistake guide v1"],
        "owner": "CS + Ops Lead",
        "success_metric": "Median TTV <= 15 minutes",
    },
    {
        "week": 5,
        "start_date": "2026-03-30",
        "end_date": "2026-04-03",
        "phase": "Adaptation",
        "focus": "Usage consistency",
        "actions": [
            "Launch weekly mission for each role.",
            "Review overdue work-order behavior by site.",
            "Tune help docs using real questions.",
        ],
        "deliverables": ["Weekly mission board", "Site behavior report", "Help docs v2"],
        "owner": "Ops PM + Site Champions",
        "success_metric": "2-week retention >= 65%",
    },
    {
        "week": 6,
        "start_date": "2026-04-06",
        "end_date": "2026-04-10",
        "phase": "Habit",
        "focus": "Operational rhythm",
        "actions": [
            "Introduce Monday planning and Friday review cadence.",
            "Use handover brief in daily operation meeting.",
            "Audit token/role setup for each site.",
        ],
        "deliverables": ["Cadence template", "Handover routine checklist", "RBAC audit report"],
        "owner": "Ops Manager",
        "success_metric": "Weekly active rate >= 75%",
    },
    {
        "week": 7,
        "start_date": "2026-04-13",
        "end_date": "2026-04-17",
        "phase": "Habit",
        "focus": "SLA quality",
        "actions": [
            "Review SLA overdue and escalation trends by site.",
            "Run targeted coaching for low-performing teams.",
            "Enforce alert retry follow-up policy.",
        ],
        "deliverables": ["SLA trend report", "Coaching action list", "Alert follow-up SOP"],
        "owner": "Ops Lead + QA",
        "success_metric": "SLA response time improves >= 10%",
    },
    {
        "week": 8,
        "start_date": "2026-04-20",
        "end_date": "2026-04-24",
        "phase": "Habit",
        "focus": "Report discipline",
        "actions": [
            "Standardize monthly report generation and distribution.",
            "Review data quality (missing fields, inconsistent statuses).",
            "Close documentation gaps from previous weeks.",
        ],
        "deliverables": ["Reporting SOP v2", "Data quality dashboard", "Docs release note"],
        "owner": "Auditor + Ops PM",
        "success_metric": "Monthly report on-time rate >= 95%",
    },
    {
        "week": 9,
        "start_date": "2026-04-27",
        "end_date": "2026-05-01",
        "phase": "Autonomy",
        "focus": "Shift to KPI operation",
        "actions": [
            "Switch management rhythm from training to KPI review.",
            "Set red/yellow/green threshold per KPI.",
            "Assign KPI owners and escalation path.",
        ],
        "deliverables": ["KPI threshold matrix", "Owner assignment table", "Escalation map"],
        "owner": "Head of Ops",
        "success_metric": "KPI owner coverage 100%",
    },
    {
        "week": 10,
        "start_date": "2026-05-04",
        "end_date": "2026-05-08",
        "phase": "Autonomy",
        "focus": "Self-serve support",
        "actions": [
            "Convert repetitive support issues to self-serve guides.",
            "Publish role-based troubleshooting runbook.",
            "Reduce office-hour dependency.",
        ],
        "deliverables": ["Self-serve KB v1", "Troubleshooting runbook", "Support reduction report"],
        "owner": "CS Lead",
        "success_metric": "Support ticket repeat rate down >= 20%",
    },
    {
        "week": 11,
        "start_date": "2026-05-11",
        "end_date": "2026-05-15",
        "phase": "Autonomy",
        "focus": "Scale readiness",
        "actions": [
            "Review process with expansion sites.",
            "Validate onboarding package in a new-site simulation.",
            "Finalize risk register and fallback playbook.",
        ],
        "deliverables": ["Scale checklist", "New-site simulation report", "Fallback playbook"],
        "owner": "Program Manager",
        "success_metric": "New-site simulation success >= 90%",
    },
    {
        "week": 12,
        "start_date": "2026-05-18",
        "end_date": "2026-05-22",
        "phase": "Autonomy",
        "focus": "Closure and handoff",
        "actions": [
            "Run 8-week/12-week closure review.",
            "Confirm independent execution ratio per core workflow.",
            "Approve next-quarter operating plan.",
        ],
        "deliverables": ["Program closure report", "Independent execution scorecard", "Q3 roadmap draft"],
        "owner": "Executive Sponsor + Ops Director",
        "success_metric": "Independent execution >= 80%",
    },
    {
        "week": 13,
        "start_date": "2026-05-25",
        "end_date": "2026-05-29",
        "phase": "Sustain",
        "focus": "Continuous improvement",
        "actions": [
            "Run weekly improvement review with site champions.",
            "Convert closure findings into tracked optimization actions.",
            "Lock next-quarter governance cadence and owners.",
        ],
        "deliverables": ["Improvement backlog v1", "Owner action board", "Quarterly governance calendar"],
        "owner": "Ops Director + PMO",
        "success_metric": "Improvement action closure >= 85%",
    },
    {
        "week": 14,
        "start_date": "2026-06-01",
        "end_date": "2026-06-05",
        "phase": "Stabilize",
        "focus": "Stability sprint",
        "actions": [
            "Measure P95 latency for critical APIs and confirm alert threshold.",
            "Run post-deploy smoke and rollback checklist as standard operation.",
            "Validate evidence/audit archive integrity batch and close findings.",
        ],
        "deliverables": ["Latency baseline v1", "Smoke/rollback checklist v1", "Archive integrity report v1"],
        "owner": "SRE + Ops QA",
        "success_metric": "Stability readiness score >= 85%",
    },
    {
        "week": 15,
        "start_date": "2026-06-08",
        "end_date": "2026-06-12",
        "phase": "Optimize",
        "focus": "Operations efficiency",
        "actions": [
            "Unify execution-tracker UI blocks for W07~W14 with shared components.",
            "Standardize policy API response envelope for adoption policy endpoints.",
            "Automate weekly operations report publication with exception digest.",
        ],
        "deliverables": ["Tracker UI common component v1", "Policy response standard v1", "Weekly ops report auto-run v1"],
        "owner": "Ops PM + Platform Engineer",
        "success_metric": "Weekly ops report on-time >= 95%",
    },
]

ADOPTION_TRAINING_OUTLINE: list[dict[str, Any]] = [
    {
        "module": "M1. Platform Quickstart",
        "audience": "All roles",
        "duration_min": 60,
        "contents": ["Login and token basics", "Navigation and docs", "Daily routine overview"],
        "format": "Live demo + guided practice",
    },
    {
        "module": "M2. Inspection Execution",
        "audience": "Operator, Manager",
        "duration_min": 45,
        "contents": ["Inspection entry", "Risk flag rules", "Print/export inspection report"],
        "format": "Scenario lab",
    },
    {
        "module": "M3. Work-Order Lifecycle",
        "audience": "Operator, Manager",
        "duration_min": 60,
        "contents": ["Create/ack/complete/cancel/reopen", "Event timeline usage", "Comment standards"],
        "format": "Hands-on lab",
    },
    {
        "module": "M4. SLA and Escalation Ops",
        "audience": "Manager, Owner",
        "duration_min": 50,
        "contents": ["SLA policy reading", "Escalation batch run", "Alert retry procedure"],
        "format": "Live operation drill",
    },
    {
        "module": "M5. Handover Brief and Daily Meeting",
        "audience": "Manager, Owner",
        "duration_min": 40,
        "contents": ["Handover brief interpretation", "Top-work-order triage", "Action logging"],
        "format": "Workshop",
    },
    {
        "module": "M6. Monthly Audit Reporting",
        "audience": "Auditor, Manager",
        "duration_min": 45,
        "contents": ["Monthly JSON read", "CSV/PDF export", "Distribution checklist"],
        "format": "Report clinic",
    },
    {
        "module": "M7. RBAC and Token Governance",
        "audience": "Owner",
        "duration_min": 35,
        "contents": ["Role/site scope design", "Token issue/revoke policy", "Audit log review"],
        "format": "Control workshop",
    },
    {
        "module": "M8. Incident and Recovery Playbook",
        "audience": "Owner, Manager",
        "duration_min": 50,
        "contents": ["Failed alert response", "SLA rollback process", "Escalation command center protocol"],
        "format": "Table-top exercise",
    },
]

ADOPTION_KPI_DASHBOARD_ITEMS: list[dict[str, str]] = [
    {
        "id": "KPI-01",
        "name": "First-week login rate",
        "formula": "users logged in at least once in first 7 days / activated users",
        "target": ">= 90%",
        "data_source": "Auth logs",
        "frequency": "Daily",
    },
    {
        "id": "KPI-02",
        "name": "First success time (TTV)",
        "formula": "median minutes from first login to first completed core action",
        "target": "<= 15 min",
        "data_source": "Audit logs + API events",
        "frequency": "Daily",
    },
    {
        "id": "KPI-03",
        "name": "Weekly active rate",
        "formula": "users active at least 3 days in week / total active users",
        "target": ">= 75%",
        "data_source": "Activity aggregation",
        "frequency": "Weekly",
    },
    {
        "id": "KPI-04",
        "name": "Two-week retention",
        "formula": "users active in week N and N+1 / users active in week N",
        "target": ">= 65%",
        "data_source": "Activity aggregation",
        "frequency": "Weekly",
    },
    {
        "id": "KPI-05",
        "name": "SLA overdue response improvement",
        "formula": "baseline overdue response time - current overdue response time",
        "target": ">= 20% improvement",
        "data_source": "Work-order + job-runs",
        "frequency": "Weekly",
    },
    {
        "id": "KPI-06",
        "name": "Alert retry success rate",
        "formula": "alert retries resolved / total alert retries",
        "target": ">= 90%",
        "data_source": "Alert deliveries",
        "frequency": "Daily",
    },
    {
        "id": "KPI-07",
        "name": "Monthly report on-time rate",
        "formula": "reports exported by due date / scheduled reports",
        "target": ">= 95%",
        "data_source": "Audit logs",
        "frequency": "Monthly",
    },
    {
        "id": "KPI-08",
        "name": "Independent execution ratio",
        "formula": "users completing all 5 core tasks without support / active users",
        "target": ">= 80%",
        "data_source": "Checklist + support records",
        "frequency": "Bi-weekly",
    },
]

ADOPTION_PROMOTION_PACK: list[dict[str, Any]] = [
    {
        "campaign": "Launch Week Wallboard",
        "goal": "Create visibility and urgency for first-week adoption.",
        "channels": ["Lobby display", "Team chat", "Email digest"],
        "assets": [
            "1-page launch poster",
            "Daily KPI snapshot card",
            "Top adopter spotlight template",
        ],
        "cadence": "Daily (week 1-2)",
    },
    {
        "campaign": "Site Champion Story",
        "goal": "Spread practical success cases across teams.",
        "channels": ["Weekly townhall", "Internal newsletter"],
        "assets": [
            "Before/after process story template",
            "3-minute demo recording format",
            "Problem-solution-result summary card",
        ],
        "cadence": "Weekly",
    },
    {
        "campaign": "Referral Sprint",
        "goal": "Increase organic peer onboarding.",
        "channels": ["Team challenge board", "Ops standup"],
        "assets": [
            "Invite checklist",
            "Referral badge image set",
            "Simple recognition leaderboard",
        ],
        "cadence": "Bi-weekly",
    },
]

ADOPTION_EDUCATION_PACK: list[dict[str, Any]] = [
    {
        "track": "Starter Track",
        "target_roles": ["Operator", "Manager"],
        "components": ["Quickstart session", "Guided sandbox", "First-success checklist"],
        "completion_rule": "Complete M1-M3 and pass hands-on check",
        "duration_weeks": 2,
    },
    {
        "track": "Control Track",
        "target_roles": ["Owner", "Auditor"],
        "components": ["RBAC governance lab", "Audit/report workshop", "Incident drill"],
        "completion_rule": "Complete M6-M8 and submit governance quiz",
        "duration_weeks": 3,
    },
    {
        "track": "Champion Track",
        "target_roles": ["Site Champion"],
        "components": ["Coaching playbook", "Weekly blocker clinic", "KPI mentoring"],
        "completion_rule": "Lead 2 weekly clinics and close top blocker",
        "duration_weeks": 4,
    },
]

ADOPTION_FUN_PACK: list[dict[str, Any]] = [
    {
        "program": "Weekly Mission Bingo",
        "how_it_works": "Each role clears 5 mission tiles per week using real operations.",
        "rewards": ["Mission badge", "Team shout-out"],
        "anti_abuse_rule": "Only audited production actions count.",
    },
    {
        "program": "SLA Rescue Challenge",
        "how_it_works": "Teams compete to reduce overdue and failed-alert counts.",
        "rewards": ["Rescue cup", "Priority coaching slot"],
        "anti_abuse_rule": "Score uses net improvement and quality checks.",
    },
    {
        "program": "Report Relay",
        "how_it_works": "Cross-role relay to finish monthly report package on time.",
        "rewards": ["Relay champion badge", "Quarterly recognition"],
        "anti_abuse_rule": "Report must pass audit checklist for points.",
    },
]

ADOPTION_WORKFLOW_LOCK_MATRIX: dict[str, Any] = {
    "states": ["DRAFT", "REVIEW", "APPROVED", "LOCKED"],
    "rows": [
        {
            "role": "점검자 (Operator)",
            "permissions": {
                "DRAFT": "수정",
                "REVIEW": "읽기",
                "APPROVED": "읽기",
                "LOCKED": "읽기",
            },
        },
        {
            "role": "팀장 (Manager)",
            "permissions": {
                "DRAFT": "읽기",
                "REVIEW": "승인/반려",
                "APPROVED": "읽기",
                "LOCKED": "읽기",
            },
        },
        {
            "role": "관리소장 (Owner)",
            "permissions": {
                "DRAFT": "읽기",
                "REVIEW": "승인/반려",
                "APPROVED": "잠금",
                "LOCKED": "읽기",
            },
        },
        {
            "role": "관리자(Admin)",
            "permissions": {
                "DRAFT": "전체 가능",
                "REVIEW": "전체 가능",
                "APPROVED": "전체 가능",
                "LOCKED": "제한적 해제(사유+요청번호 필수)",
            },
        },
    ],
}

ADOPTION_W02_SOP_RUNBOOKS: list[dict[str, Any]] = [
    {
        "id": "SOP-INS-01",
        "name": "Inspection one-page SOP",
        "target_roles": ["Operator", "Manager"],
        "owner": "Ops PM",
        "trigger": "Before daily inspection shift",
        "checkpoints": [
            "Create inspection with required fields",
            "Confirm risk flags and print view",
            "Validate audit trail and site scope",
        ],
        "definition_of_done": "3 consecutive dry-runs without validation errors",
    },
    {
        "id": "SOP-WO-01",
        "name": "Work-order lifecycle SOP",
        "target_roles": ["Operator", "Manager"],
        "owner": "Ops Lead",
        "trigger": "When work-order is created",
        "checkpoints": [
            "open -> acked -> completed transition",
            "cancel/reopen exception path verified",
            "event timeline includes actor/note",
        ],
        "definition_of_done": "All lifecycle paths verified in sandbox",
    },
    {
        "id": "SOP-SLA-01",
        "name": "SLA escalation and retry SOP",
        "target_roles": ["Manager", "Owner"],
        "owner": "QA Lead",
        "trigger": "15-minute escalation cadence",
        "checkpoints": [
            "Escalation batch run result reviewed",
            "Failed deliveries list triaged",
            "Retry batch executed with audit evidence",
        ],
        "definition_of_done": "No unresolved failed alert older than 24h",
    },
    {
        "id": "SOP-RPT-01",
        "name": "Monthly report export SOP",
        "target_roles": ["Auditor", "Owner"],
        "owner": "Audit Lead",
        "trigger": "Monthly close checklist",
        "checkpoints": [
            "Monthly summary reviewed",
            "CSV and PDF exports generated",
            "Export actions captured in audit logs",
        ],
        "definition_of_done": "Export package delivered within SLA",
    },
    {
        "id": "SOP-RBAC-01",
        "name": "RBAC token hygiene SOP",
        "target_roles": ["Owner", "Admin"],
        "owner": "Security Admin",
        "trigger": "Weekly governance review",
        "checkpoints": [
            "Role and site scope verification",
            "Unused token revoke check",
            "workflow_locks admin override review",
        ],
        "definition_of_done": "High-risk permission drift resolved <= 48h",
    },
]

ADOPTION_W02_SANDBOX_SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "SX-INS-01",
        "module": "Inspection",
        "objective": "Create high-risk inspection and confirm risk detection path.",
        "api_flow": [
            "POST /api/inspections",
            "GET /api/inspections",
            "GET /inspections/{id}/print",
        ],
        "pass_criteria": [
            "risk_level is warning or danger",
            "risk_flags includes threshold breach",
            "print endpoint renders without error",
        ],
        "duration_min": 20,
    },
    {
        "id": "SX-WO-01",
        "module": "Work-order + SLA",
        "objective": "Validate work-order state transitions and SLA escalation.",
        "api_flow": [
            "POST /api/work-orders",
            "PATCH /api/work-orders/{id}/ack",
            "POST /api/work-orders/escalations/run",
            "GET /api/work-orders/{id}/events",
        ],
        "pass_criteria": [
            "acked transition succeeds",
            "escalation result includes target id",
            "timeline includes status_changed event",
        ],
        "duration_min": 30,
    },
    {
        "id": "SX-RPT-01",
        "module": "Reporting + Audit",
        "objective": "Generate monthly report package and verify audit evidence.",
        "api_flow": [
            "GET /api/reports/monthly",
            "GET /api/reports/monthly/csv",
            "GET /api/reports/monthly/pdf",
            "GET /api/admin/audit-logs",
        ],
        "pass_criteria": [
            "monthly summary returns expected totals",
            "csv/pdf downloads succeed",
            "audit logs contain export actions",
        ],
        "duration_min": 25,
    },
]

ADOPTION_W02_SCHEDULED_EVENTS: list[dict[str, Any]] = [
    {
        "id": "W02-E01",
        "date": "2026-03-09",
        "start_time": "09:00",
        "end_time": "10:00",
        "title": "Kickoff - SOP owner assignment",
        "owner": "Ops PM + QA",
        "output": "SOP owner table v1",
    },
    {
        "id": "W02-E02",
        "date": "2026-03-10",
        "start_time": "14:00",
        "end_time": "15:00",
        "title": "Inspection sandbox drill",
        "owner": "Operator Champion",
        "output": "SX-INS-01 pass report",
    },
    {
        "id": "W02-E03",
        "date": "2026-03-11",
        "start_time": "14:00",
        "end_time": "15:30",
        "title": "Work-order/SLA sandbox drill",
        "owner": "Ops Lead",
        "output": "SX-WO-01 evidence pack",
    },
    {
        "id": "W02-E04",
        "date": "2026-03-12",
        "start_time": "16:00",
        "end_time": "17:00",
        "title": "Reporting and audit sandbox drill",
        "owner": "Audit Lead",
        "output": "SX-RPT-01 export proof",
    },
    {
        "id": "W02-E05",
        "date": "2026-03-13",
        "start_time": "17:00",
        "end_time": "17:30",
        "title": "W02 sign-off review",
        "owner": "Owner + PM",
        "output": "W02 go/no-go decision",
    },
]

W02_SAMPLE_EVIDENCE_ARTIFACTS: list[dict[str, Any]] = [
    {
        "sample_id": "sx-ins-01",
        "title": "Inspection Sandbox Evidence",
        "description": "SX-INS-01 통과 증빙 예시 텍스트 파일",
        "file_name": "w02-sample-sx-ins-01-proof.txt",
        "content_type": "text/plain",
        "tracker_item_type": "sandbox_scenario",
        "tracker_item_key": "SX-INS-01",
        "content": (
            "W02 Sample Evidence\n"
            "Scenario: SX-INS-01\n"
            "Module: Inspection\n"
            "Result: PASS\n"
            "Checked Items:\n"
            "- risk_level warning/danger 검증 완료\n"
            "- risk_flags 임계치 검증 완료\n"
            "- print view 렌더링 정상\n"
        ),
    },
    {
        "sample_id": "sx-wo-01",
        "title": "Work-Order/SLA Sandbox Evidence",
        "description": "SX-WO-01 통과 증빙 예시 텍스트 파일",
        "file_name": "w02-sample-sx-wo-01-proof.txt",
        "content_type": "text/plain",
        "tracker_item_type": "sandbox_scenario",
        "tracker_item_key": "SX-WO-01",
        "content": (
            "W02 Sample Evidence\n"
            "Scenario: SX-WO-01\n"
            "Module: Work-order + SLA\n"
            "Result: PASS\n"
            "Checked Items:\n"
            "- open->acked->completed 전이 검증 완료\n"
            "- escalation 배치 결과 타겟 포함 확인\n"
            "- timeline status_changed 이벤트 확인\n"
        ),
    },
    {
        "sample_id": "sx-rpt-01",
        "title": "Reporting/Audit Sandbox Evidence",
        "description": "SX-RPT-01 통과 증빙 예시 텍스트 파일",
        "file_name": "w02-sample-sx-rpt-01-proof.txt",
        "content_type": "text/plain",
        "tracker_item_type": "sandbox_scenario",
        "tracker_item_key": "SX-RPT-01",
        "content": (
            "W02 Sample Evidence\n"
            "Scenario: SX-RPT-01\n"
            "Module: Reporting + Audit\n"
            "Result: PASS\n"
            "Checked Items:\n"
            "- monthly summary 수치 확인\n"
            "- csv/pdf 다운로드 확인\n"
            "- export audit 로그 기록 확인\n"
        ),
    },
]


def _build_sample_evidence_artifact_catalog() -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    for row in W02_SAMPLE_EVIDENCE_ARTIFACTS:
        file_name = str(row.get("file_name") or "").strip()
        if not file_name:
            continue
        content_text = str(row.get("content") or "")
        content_bytes = content_text.encode("utf-8")
        catalog[file_name] = {
            "bytes": content_bytes,
            "sha256": hashlib.sha256(content_bytes).hexdigest(),
            "file_size": len(content_bytes),
            "sample_id": str(row.get("sample_id") or "").strip().lower(),
        }
    return catalog


SAMPLE_EVIDENCE_ARTIFACTS_BY_FILE = _build_sample_evidence_artifact_catalog()

ADOPTION_W03_KICKOFF_AGENDA: list[dict[str, Any]] = [
    {
        "id": "KICKOFF-01",
        "topic": "Why now: launch goals and target KPI",
        "owner": "Product Lead",
        "duration_min": 10,
        "objective": "Align launch urgency and weekly target",
        "expected_output": "Shared KPI board confirmed",
    },
    {
        "id": "KICKOFF-02",
        "topic": "Role mission map and first action",
        "owner": "Ops PM",
        "duration_min": 10,
        "objective": "Clarify role-by-role first action",
        "expected_output": "Role mission one-pager distributed",
    },
    {
        "id": "KICKOFF-03",
        "topic": "Live demo: inspection -> work-order -> report",
        "owner": "Solution Engineer",
        "duration_min": 15,
        "objective": "Prove end-to-end happy path",
        "expected_output": "Demo recording and quick guide",
    },
    {
        "id": "KICKOFF-04",
        "topic": "Support path: docs, handover brief, office hour",
        "owner": "Training Lead",
        "duration_min": 10,
        "objective": "Reduce first-week blocker delay",
        "expected_output": "Support channel and SLA announced",
    },
    {
        "id": "KICKOFF-05",
        "topic": "Q&A and commitment check",
        "owner": "Owner + PM",
        "duration_min": 15,
        "objective": "Confirm go-live readiness by site",
        "expected_output": "Site commitment checklist signed",
    },
]

ADOPTION_W03_ROLE_WORKSHOPS: list[dict[str, Any]] = [
    {
        "id": "WS-OPR-01",
        "role": "Operator",
        "trainer": "Training Lead",
        "duration_min": 20,
        "objective": "점검 생성과 위험 플래그 해석을 1회 완주",
        "checklist": [
            "Create inspection with required fields",
            "Review risk flags and print preview",
            "Submit first work-order escalation note",
        ],
        "success_criteria": "First inspection cycle completed under 20 minutes",
    },
    {
        "id": "WS-MGR-01",
        "role": "Manager",
        "trainer": "Ops Lead",
        "duration_min": 20,
        "objective": "작업지시 ACK/완료와 SLA 추적 루프 고정",
        "checklist": [
            "Acknowledge one incoming work-order",
            "Complete work-order with resolution note",
            "Review overdue/escalated dashboard counts",
        ],
        "success_criteria": "Manager handles full lifecycle without support",
    },
    {
        "id": "WS-OWN-01",
        "role": "Owner",
        "trainer": "Product Manager",
        "duration_min": 20,
        "objective": "주간 운영 리뷰 루틴과 승인 포인트 확정",
        "checklist": [
            "Open dashboard summary with site filter",
            "Review handover brief and top priority queue",
            "Confirm weekly KPI review cadence",
        ],
        "success_criteria": "Weekly review checklist approved",
    },
    {
        "id": "WS-AUD-01",
        "role": "Auditor",
        "trainer": "Audit Lead",
        "duration_min": 20,
        "objective": "월간 리포트 추출과 감사 로그 검증 완료",
        "checklist": [
            "Generate monthly summary report",
            "Download CSV and PDF package",
            "Verify export actions in audit log",
        ],
        "success_criteria": "Audit package reproducible within 15 minutes",
    },
]

ADOPTION_W03_OFFICE_HOURS: list[dict[str, Any]] = [
    {
        "id": "OH-2026-03-16",
        "date": "2026-03-16",
        "start_time": "17:00",
        "end_time": "17:15",
        "host": "Training Lead",
        "focus": "Launch day blocker triage",
        "channel": "#ka-facility-help",
    },
    {
        "id": "OH-2026-03-17",
        "date": "2026-03-17",
        "start_time": "17:00",
        "end_time": "17:15",
        "host": "Ops PM",
        "focus": "Role workshop Q&A follow-up",
        "channel": "#ka-facility-help",
    },
    {
        "id": "OH-2026-03-18",
        "date": "2026-03-18",
        "start_time": "17:00",
        "end_time": "17:15",
        "host": "Ops Lead",
        "focus": "Work-order/SLA issue triage",
        "channel": "#ka-facility-help",
    },
    {
        "id": "OH-2026-03-19",
        "date": "2026-03-19",
        "start_time": "17:00",
        "end_time": "17:15",
        "host": "Audit Lead",
        "focus": "Reporting and audit export questions",
        "channel": "#ka-facility-help",
    },
    {
        "id": "OH-2026-03-20",
        "date": "2026-03-20",
        "start_time": "17:00",
        "end_time": "17:15",
        "host": "Product + Training Lead",
        "focus": "Week-close retrospective and FAQ capture",
        "channel": "#ka-facility-help",
    },
]

ADOPTION_W03_SCHEDULED_EVENTS: list[dict[str, Any]] = [
    {
        "id": "W03-E01",
        "date": "2026-03-16",
        "start_time": "09:00",
        "end_time": "10:00",
        "title": "Kickoff session (60m)",
        "owner": "Product + Training Lead",
        "output": "Kickoff recording + launch KPI board",
    },
    {
        "id": "W03-E02",
        "date": "2026-03-16",
        "start_time": "10:30",
        "end_time": "10:50",
        "title": "Role workshop - Operator",
        "owner": "Training Lead",
        "output": "WS-OPR-01 completion checklist",
    },
    {
        "id": "W03-E03",
        "date": "2026-03-16",
        "start_time": "11:00",
        "end_time": "11:20",
        "title": "Role workshop - Manager",
        "owner": "Ops Lead",
        "output": "WS-MGR-01 completion checklist",
    },
    {
        "id": "W03-E04",
        "date": "2026-03-16",
        "start_time": "11:30",
        "end_time": "11:50",
        "title": "Role workshop - Owner",
        "owner": "Product Manager",
        "output": "WS-OWN-01 completion checklist",
    },
    {
        "id": "W03-E05",
        "date": "2026-03-16",
        "start_time": "14:00",
        "end_time": "14:20",
        "title": "Role workshop - Auditor",
        "owner": "Audit Lead",
        "output": "WS-AUD-01 completion checklist",
    },
    {
        "id": "W03-E06",
        "date": "2026-03-16",
        "start_time": "17:00",
        "end_time": "17:15",
        "title": "Daily office hour #1",
        "owner": "Training Lead",
        "output": "Day-1 blocker resolution log",
    },
    {
        "id": "W03-E07",
        "date": "2026-03-17",
        "start_time": "17:00",
        "end_time": "17:15",
        "title": "Daily office hour #2",
        "owner": "Ops PM",
        "output": "Day-2 FAQ update",
    },
    {
        "id": "W03-E08",
        "date": "2026-03-18",
        "start_time": "17:00",
        "end_time": "17:15",
        "title": "Daily office hour #3",
        "owner": "Ops Lead",
        "output": "SLA issue follow-up list",
    },
    {
        "id": "W03-E09",
        "date": "2026-03-19",
        "start_time": "17:00",
        "end_time": "17:15",
        "title": "Daily office hour #4",
        "owner": "Audit Lead",
        "output": "Reporting Q&A digest",
    },
    {
        "id": "W03-E10",
        "date": "2026-03-20",
        "start_time": "17:00",
        "end_time": "17:15",
        "title": "Daily office hour #5",
        "owner": "Product + Training Lead",
        "output": "W03 week-close note",
    },
]

ADOPTION_W04_COACHING_ACTIONS: list[dict[str, Any]] = [
    {
        "id": "W04-CA-01",
        "champion_role": "Site Champion",
        "action": "Run first-success funnel review per site",
        "owner": "CS + Ops Lead",
        "due_hint": "Mon 10:00",
        "objective": "Identify drop-off between login, inspection, and WO completion",
        "evidence_required": True,
        "quick_fix": "Focus first on the largest drop-off stage",
    },
    {
        "id": "W04-CA-02",
        "champion_role": "Site Champion",
        "action": "Close top blocker #1 with owner and due date",
        "owner": "Ops Lead",
        "due_hint": "Tue 15:00",
        "objective": "Remove the most frequent execution blocker in one cycle",
        "evidence_required": True,
        "quick_fix": "Assign one accountable owner and verify within 24h",
    },
    {
        "id": "W04-CA-03",
        "champion_role": "Site Champion",
        "action": "Close top blocker #2 and publish fix note",
        "owner": "QA Lead",
        "due_hint": "Wed 16:00",
        "objective": "Reduce repeated failures by documenting the fix path",
        "evidence_required": True,
        "quick_fix": "Attach screenshot + API response snippet",
    },
    {
        "id": "W04-CA-04",
        "champion_role": "Site Champion",
        "action": "Close top blocker #3 and run 1 retest",
        "owner": "Ops PM",
        "due_hint": "Thu 14:00",
        "objective": "Confirm blocker removal with one real retest",
        "evidence_required": True,
        "quick_fix": "Retest with production-like data",
    },
    {
        "id": "W04-CA-05",
        "champion_role": "Manager",
        "action": "Coach low-performing users (1:1 x 3)",
        "owner": "Site Manager",
        "due_hint": "Thu 17:00",
        "objective": "Reduce median time-to-first-success to <= 15 minutes",
        "evidence_required": True,
        "quick_fix": "Use 15-minute script + checklist",
    },
    {
        "id": "W04-CA-06",
        "champion_role": "Owner",
        "action": "Approve W04 acceleration close report",
        "owner": "Owner + PM",
        "due_hint": "Fri 17:00",
        "objective": "Decide go/no-go for W05 consistency mission",
        "evidence_required": False,
        "quick_fix": "Require blocker trend and TTV delta in one page",
    },
]

ADOPTION_W04_SCHEDULED_EVENTS: list[dict[str, Any]] = [
    {
        "id": "W04-E01",
        "date": "2026-03-23",
        "start_time": "10:00",
        "end_time": "10:30",
        "title": "W04 kickoff - first-success funnel review",
        "owner": "CS + Ops Lead",
        "output": "Site funnel baseline and top drop-off stage",
    },
    {
        "id": "W04-E02",
        "date": "2026-03-23",
        "start_time": "16:00",
        "end_time": "16:30",
        "title": "Blocker triage #1",
        "owner": "Ops Lead",
        "output": "Top blocker owner assigned",
    },
    {
        "id": "W04-E03",
        "date": "2026-03-24",
        "start_time": "16:00",
        "end_time": "16:30",
        "title": "Blocker triage #2",
        "owner": "QA Lead",
        "output": "Fix note published",
    },
    {
        "id": "W04-E04",
        "date": "2026-03-25",
        "start_time": "16:00",
        "end_time": "16:30",
        "title": "Blocker triage #3 + retest",
        "owner": "Ops PM",
        "output": "Retest evidence attached",
    },
    {
        "id": "W04-E05",
        "date": "2026-03-26",
        "start_time": "15:00",
        "end_time": "15:45",
        "title": "Site champion coaching clinic",
        "owner": "Site Manager",
        "output": "Low performer coaching log",
    },
    {
        "id": "W04-E06",
        "date": "2026-03-27",
        "start_time": "16:30",
        "end_time": "17:00",
        "title": "W04 close review",
        "owner": "Owner + PM",
        "output": "W04 close report + W05 handoff",
    },
]

W04_COMMON_MISTAKE_FIX_CATALOG: list[dict[str, str]] = [
    {
        "mistake_key": "missing_assignee",
        "mistake": "담당자 없이 항목을 생성/방치",
        "symptom": "pending/in_progress가 오래 유지되고 완료율이 정체됨",
        "quick_fix": "항목 생성 직후 assignee 지정, 24시간 내 상태 업데이트",
        "where_to_check": "W04 Tracker Overview + assignee breakdown",
    },
    {
        "mistake_key": "missing_evidence",
        "mistake": "코칭 액션 완료 후 증빙 미업로드",
        "symptom": "완료 판정에서 missing evidence blocker 발생",
        "quick_fix": "상태 저장과 동시에 txt/pdf/png 증빙 업로드",
        "where_to_check": "W04 Tracker item evidence list",
    },
    {
        "mistake_key": "slow_first_action",
        "mistake": "첫 작업 진입이 늦어 TTV가 증가",
        "symptom": "funnel에서 auth->inspection 구간 지연",
        "quick_fix": "첫 로그인 15분 내 점검 생성 과제 고정",
        "where_to_check": "W04 Funnel stage timings",
    },
    {
        "mistake_key": "wo_completion_delay",
        "mistake": "작업지시 완료 단계에서 병목",
        "symptom": "inspection->work_order_complete 전환율 하락",
        "quick_fix": "ACK 템플릿과 완료노트 템플릿 표준화",
        "where_to_check": "Work-order timeline + W04 Funnel",
    },
    {
        "mistake_key": "alert_delivery_failures",
        "mistake": "알림 실패를 방치",
        "symptom": "failed alert delivery 증가, 에스컬레이션 응답 지연",
        "quick_fix": "실패 타겟 재시도 배치 실행 + 채널 가드 확인",
        "where_to_check": "Alert deliveries / retries / guard",
    },
]

ADOPTION_W05_ROLE_MISSIONS: list[dict[str, Any]] = [
    {
        "id": "W05-M-01",
        "role": "Operator",
        "mission": "Daily first action within 15 minutes for assigned queue",
        "weekly_target": "5/5 weekdays",
        "owner": "Site Champion",
        "evidence_required": True,
        "evidence_hint": "Tracker screenshot + first action timestamp",
    },
    {
        "id": "W05-M-02",
        "role": "Manager",
        "mission": "Overdue backlog review and reassignment",
        "weekly_target": "2 review sessions",
        "owner": "Ops Manager",
        "evidence_required": True,
        "evidence_hint": "Before/after overdue list",
    },
    {
        "id": "W05-M-03",
        "role": "Auditor",
        "mission": "Data consistency spot-check (status and due_at)",
        "weekly_target": "10 sampled records",
        "owner": "Audit Lead",
        "evidence_required": True,
        "evidence_hint": "Spot-check sheet + issue notes",
    },
    {
        "id": "W05-M-04",
        "role": "Site Champion",
        "mission": "Weekly mission coaching and blocker follow-up",
        "weekly_target": "Top 3 blockers closed",
        "owner": "Ops PM",
        "evidence_required": True,
        "evidence_hint": "Coaching log + closure proof",
    },
    {
        "id": "W05-M-05",
        "role": "Owner",
        "mission": "Retention and overdue trend review sign-off",
        "weekly_target": "1 sign-off",
        "owner": "Owner + PM",
        "evidence_required": False,
        "evidence_hint": "Weekly decision memo",
    },
]

ADOPTION_W05_SCHEDULED_EVENTS: list[dict[str, Any]] = [
    {
        "id": "W05-E01",
        "date": "2026-03-30",
        "start_time": "10:00",
        "end_time": "10:30",
        "title": "W05 kickoff - weekly mission board launch",
        "owner": "Ops PM + Site Champions",
        "output": "Mission board v1",
    },
    {
        "id": "W05-E02",
        "date": "2026-03-31",
        "start_time": "16:00",
        "end_time": "16:30",
        "title": "Overdue behavior review by site",
        "owner": "Ops Manager",
        "output": "Site overdue action list",
    },
    {
        "id": "W05-E03",
        "date": "2026-04-01",
        "start_time": "15:30",
        "end_time": "16:00",
        "title": "Help docs tuning workshop",
        "owner": "QA + Training Lead",
        "output": "Help docs v2 draft",
    },
    {
        "id": "W05-E04",
        "date": "2026-04-02",
        "start_time": "16:30",
        "end_time": "17:00",
        "title": "Retention checkpoint",
        "owner": "CS + Ops Lead",
        "output": "2-week retention interim report",
    },
    {
        "id": "W05-E05",
        "date": "2026-04-03",
        "start_time": "17:00",
        "end_time": "17:30",
        "title": "W05 close review",
        "owner": "Owner + PM",
        "output": "W05 consistency close memo",
    },
]

ADOPTION_W05_HELP_DOCS: list[dict[str, Any]] = [
    {
        "doc_id": "W05-HD-01",
        "title": "작업지시 overdue 빠른 정리 가이드",
        "audience": "Manager/Operator",
        "problem": "overdue 건이 누적되어 우선순위가 흐려짐",
        "quick_steps": [
            "overdue 목록을 priority + due_at 기준으로 정렬",
            "담당자 없는 건은 즉시 reassignment",
            "48시간 내 처리 계획이 없는 건 escalated 태깅",
        ],
        "api_refs": ["/api/work-orders", "/api/work-orders/escalations/run"],
    },
    {
        "doc_id": "W05-HD-02",
        "title": "첫 액션 지연 줄이기 가이드",
        "audience": "Operator/Site Champion",
        "problem": "첫 점검/작업지시 진입이 늦어 TTV가 증가",
        "quick_steps": [
            "근무 시작 15분 내 첫 점검 1건 생성",
            "ACK 템플릿 사용으로 첫 반응 시간 단축",
            "당일 미완료 건은 종료 전 상태 업데이트",
        ],
        "api_refs": ["/api/inspections", "/api/work-orders"],
    },
    {
        "doc_id": "W05-HD-03",
        "title": "상태값 일관성 점검 가이드",
        "audience": "Auditor/Manager",
        "problem": "status와 완료 체크가 불일치하여 보고 왜곡",
        "quick_steps": [
            "done 상태 항목의 completion_checked 확인",
            "in_progress 장기 체류 항목 사유 기록",
            "미완료 증빙 누락 항목은 당일 보완",
        ],
        "api_refs": [
            "/api/adoption/w04/tracker/items",
            "/api/adoption/w04/tracker/readiness",
        ],
    },
]

ADOPTION_W06_RHYTHM_CHECKLIST: list[dict[str, Any]] = [
    {
        "id": "W06-RC-01",
        "day": "Monday",
        "routine": "Weekly planning board setup (site priorities + owners)",
        "owner_role": "Manager",
        "definition_of_done": "이번 주 우선순위 5개와 담당자 지정 완료",
        "evidence_hint": "Planning board snapshot + owner assignment",
    },
    {
        "id": "W06-RC-02",
        "day": "Daily",
        "routine": "Daily operation meeting with handover brief",
        "owner_role": "Manager/Operator",
        "definition_of_done": "handover 기반 action item 최소 3건 기록",
        "evidence_hint": "Handover brief export + action notes",
    },
    {
        "id": "W06-RC-03",
        "day": "Wednesday",
        "routine": "Mid-week cadence check and backlog rebalance",
        "owner_role": "Ops Lead",
        "definition_of_done": "overdue 상위 항목 재할당 또는 ETA 수정",
        "evidence_hint": "Before/after overdue list",
    },
    {
        "id": "W06-RC-04",
        "day": "Friday",
        "routine": "Weekly review and next-week carry-over triage",
        "owner_role": "Owner/Manager",
        "definition_of_done": "주간 회고 + 다음 주 carry-over 승인",
        "evidence_hint": "Weekly review memo",
    },
]

ADOPTION_W06_SCHEDULED_EVENTS: list[dict[str, Any]] = [
    {
        "id": "W06-E01",
        "date": "2026-04-06",
        "start_time": "09:30",
        "end_time": "10:00",
        "title": "W06 kickoff - operational rhythm launch",
        "owner": "Ops Manager",
        "output": "Cadence board v1",
    },
    {
        "id": "W06-E02",
        "date": "2026-04-07",
        "start_time": "10:00",
        "end_time": "10:20",
        "title": "Daily handover brief drill",
        "owner": "Shift Lead",
        "output": "Handover action list",
    },
    {
        "id": "W06-E03",
        "date": "2026-04-08",
        "start_time": "16:00",
        "end_time": "16:30",
        "title": "Mid-week backlog rebalance",
        "owner": "Ops Lead + QA",
        "output": "Reassigned overdue items",
    },
    {
        "id": "W06-E04",
        "date": "2026-04-09",
        "start_time": "15:30",
        "end_time": "16:00",
        "title": "RBAC/token audit checkpoint",
        "owner": "Owner + Security",
        "output": "RBAC audit delta list",
    },
    {
        "id": "W06-E05",
        "date": "2026-04-10",
        "start_time": "17:00",
        "end_time": "17:30",
        "title": "W06 close review",
        "owner": "Ops Manager + Owner",
        "output": "Operational rhythm close report",
    },
]

ADOPTION_W06_RBAC_AUDIT_CHECKLIST: list[dict[str, Any]] = [
    {
        "id": "W06-RBAC-01",
        "control": "Role coverage by site",
        "objective": "operator/manager 최소 1명 이상 배치 확인",
        "api_ref": "/api/admin/users",
        "pass_criteria": "site별 필수 역할 공석 없음",
    },
    {
        "id": "W06-RBAC-02",
        "control": "Token expiry hygiene",
        "objective": "임박 만료 토큰과 비활성 토큰 정리",
        "api_ref": "/api/admin/tokens",
        "pass_criteria": "7일 내 만료 토큰 대응 계획 100%",
    },
    {
        "id": "W06-RBAC-03",
        "control": "Site scope correctness",
        "objective": "사용자/토큰 site_scope 일치 검증",
        "api_ref": "/api/auth/me",
        "pass_criteria": "scope mismatch 0건",
    },
    {
        "id": "W06-RBAC-04",
        "control": "Audit traceability",
        "objective": "주간 주요 운영 행위 감사 로그 추적 가능",
        "api_ref": "/api/admin/audit-logs",
        "pass_criteria": "핵심 운영 action 감사 누락 0건",
    },
]

ADOPTION_W07_SLA_CHECKLIST: list[dict[str, Any]] = [
    {
        "id": "W07-SLA-01",
        "cadence": "Daily 09:00",
        "control": "Overdue/ack-delay triage by site",
        "owner_role": "Ops Lead",
        "target": "전일 overdue open 작업지시 100% owner 재확인",
        "definition_of_done": "지연 원인/대응 ETA가 모든 항목에 기록됨",
        "evidence_hint": "SLA triage board screenshot",
    },
    {
        "id": "W07-SLA-02",
        "cadence": "Daily 14:00",
        "control": "Escalation follow-up and unblock",
        "owner_role": "Manager/Operator",
        "target": "신규 escalated 항목 24시간 내 ack 100%",
        "definition_of_done": "escalated 항목마다 assignee/ETA 갱신",
        "evidence_hint": "Escalation follow-up memo",
    },
    {
        "id": "W07-SLA-03",
        "cadence": "Wednesday 16:00",
        "control": "Mid-week SLA quality review",
        "owner_role": "Ops PM + QA",
        "target": "ack median 개선 추세 유지",
        "definition_of_done": "site별 위험 순위 + 개선 액션 3건 확정",
        "evidence_hint": "SLA quality review note",
    },
    {
        "id": "W07-SLA-04",
        "cadence": "Friday 17:00",
        "control": "Weekly close and next-week hardening",
        "owner_role": "Owner/Manager",
        "target": "SLA response time 10% 개선",
        "definition_of_done": "주간 KPI 결과와 다음 주 액션 승인",
        "evidence_hint": "Weekly SLA close report",
    },
]

ADOPTION_W07_COACHING_PLAYS: list[dict[str, Any]] = [
    {
        "id": "W07-CP-01",
        "trigger": "ack median > 60분 (site)",
        "play": "긴급 triage 20분 + 담당자 재할당 + due_at 재설정",
        "owner": "Site Champion",
        "expected_impact": "ack latency 단기 하향",
        "evidence_hint": "Before/after ack median snapshot",
        "api_ref": "/api/ops/adoption/w07/sla-quality",
    },
    {
        "id": "W07-CP-02",
        "trigger": "escalation rate >= 30%",
        "play": "고위험 우선순위 분리 보드 + 하루 2회 점검",
        "owner": "Ops Lead",
        "expected_impact": "escalation rate 안정화",
        "evidence_hint": "Escalation board export",
        "api_ref": "/api/work-orders/escalations/run",
    },
    {
        "id": "W07-CP-03",
        "trigger": "alert success rate < 95%",
        "play": "실패 채널 재시도 + 타깃 URL/네트워크 점검",
        "owner": "Ops Engineer",
        "expected_impact": "Alert delivery 신뢰도 회복",
        "evidence_hint": "Retry run result + guard state",
        "api_ref": "/api/ops/alerts/retries/run",
    },
    {
        "id": "W07-CP-04",
        "trigger": "SLA run cadence < 주 1회",
        "play": "Cron 스케줄 검증 + 수동 백업 런 수행",
        "owner": "Owner/Admin",
        "expected_impact": "SLA 점검 누락 방지",
        "evidence_hint": "Job run log export",
        "api_ref": "/api/ops/job-runs",
    },
]

ADOPTION_W07_SCHEDULED_EVENTS: list[dict[str, Any]] = [
    {
        "id": "W07-E01",
        "date": "2026-04-13",
        "start_time": "09:00",
        "end_time": "09:30",
        "title": "W07 kickoff - SLA quality baseline",
        "owner": "Ops Lead + QA",
        "output": "Baseline snapshot and risk shortlist",
    },
    {
        "id": "W07-E02",
        "date": "2026-04-14",
        "start_time": "14:00",
        "end_time": "14:30",
        "title": "Escalation coaching clinic",
        "owner": "Site Champion",
        "output": "Coaching action checklist",
    },
    {
        "id": "W07-E03",
        "date": "2026-04-15",
        "start_time": "16:00",
        "end_time": "16:40",
        "title": "Mid-week SLA quality review",
        "owner": "Ops PM + QA",
        "output": "Top risk sites and mitigation owner",
    },
    {
        "id": "W07-E04",
        "date": "2026-04-16",
        "start_time": "15:30",
        "end_time": "16:00",
        "title": "Alert retry follow-up checkpoint",
        "owner": "Ops Engineer",
        "output": "Alert failure remediation log",
    },
    {
        "id": "W07-E05",
        "date": "2026-04-17",
        "start_time": "17:00",
        "end_time": "17:30",
        "title": "W07 close review",
        "owner": "Owner + Ops Manager",
        "output": "SLA quality close report",
    },
]

ADOPTION_W08_REPORT_DISCIPLINE_CHECKLIST: list[dict[str, Any]] = [
    {
        "id": "W08-RD-01",
        "cadence": "Daily 09:30",
        "discipline": "Monthly export readiness check",
        "owner_role": "Auditor",
        "target": "월간 리포트 CSV/PDF 출력 경로 점검 100%",
        "definition_of_done": "export 경로 실패/권한 오류 0건",
        "evidence_hint": "Export smoke test 결과",
        "api_ref": "/api/reports/monthly",
    },
    {
        "id": "W08-RD-02",
        "cadence": "Daily 14:30",
        "discipline": "Work-order data quality triage",
        "owner_role": "Ops PM",
        "target": "due_at 누락/상태 비정합 당일 정리",
        "definition_of_done": "품질 이슈 backlog 순증 0",
        "evidence_hint": "Data quality triage 로그",
        "api_ref": "/api/ops/adoption/w08/report-discipline",
    },
    {
        "id": "W08-RD-03",
        "cadence": "Wednesday 16:00",
        "discipline": "Site benchmark review",
        "owner_role": "Owner",
        "target": "하위 3개 site 개선 액션 지정 100%",
        "definition_of_done": "site별 개선 owner/ETA 확정",
        "evidence_hint": "Benchmark 리뷰 노트",
        "api_ref": "/api/ops/adoption/w08/site-benchmark",
    },
    {
        "id": "W08-RD-04",
        "cadence": "Friday 17:00",
        "discipline": "Weekly reporting close",
        "owner_role": "Owner + Auditor",
        "target": "report discipline score >= 85",
        "definition_of_done": "주간 점검 결과/다음주 보완안 승인",
        "evidence_hint": "Weekly close report",
        "api_ref": "/api/ops/adoption/w08/report-discipline",
    },
]

ADOPTION_W08_DATA_QUALITY_CONTROLS: list[dict[str, Any]] = [
    {
        "id": "W08-DQ-01",
        "control": "Missing due_at guard",
        "objective": "SLA 계산 불가 작업지시 제거",
        "api_ref": "/api/work-orders",
        "pass_criteria": "due_at missing rate <= 2%",
    },
    {
        "id": "W08-DQ-02",
        "control": "Invalid priority normalization",
        "objective": "우선순위 기준값 통일(low/medium/high/critical)",
        "api_ref": "/api/work-orders",
        "pass_criteria": "invalid priority 0건",
    },
    {
        "id": "W08-DQ-03",
        "control": "Completion timestamp integrity",
        "objective": "completed 상태의 timestamp 무결성 확보",
        "api_ref": "/api/work-orders/{id}/complete",
        "pass_criteria": "completed_without_completed_at 0건",
    },
    {
        "id": "W08-DQ-04",
        "control": "Report export traceability",
        "objective": "CSV/PDF 출력 감사로그 추적성 보장",
        "api_ref": "/api/admin/audit-logs",
        "pass_criteria": "report_monthly_export_* 누락 0건",
    },
]

ADOPTION_W08_SCHEDULED_EVENTS: list[dict[str, Any]] = [
    {
        "id": "W08-E01",
        "date": "2026-04-20",
        "start_time": "09:00",
        "end_time": "09:40",
        "title": "W08 kickoff - report discipline baseline",
        "owner": "Auditor + Ops PM",
        "output": "Baseline discipline snapshot",
    },
    {
        "id": "W08-E02",
        "date": "2026-04-21",
        "start_time": "14:00",
        "end_time": "14:30",
        "title": "Data quality triage clinic",
        "owner": "Ops Lead",
        "output": "Top data-quality issues and owners",
    },
    {
        "id": "W08-E03",
        "date": "2026-04-22",
        "start_time": "16:00",
        "end_time": "16:30",
        "title": "Site benchmark coaching",
        "owner": "Owner",
        "output": "Bottom-site improvement actions",
    },
    {
        "id": "W08-E04",
        "date": "2026-04-23",
        "start_time": "15:30",
        "end_time": "16:00",
        "title": "Monthly export rehearsal",
        "owner": "Audit Lead",
        "output": "CSV/PDF export rehearsal evidence",
    },
    {
        "id": "W08-E05",
        "date": "2026-04-24",
        "start_time": "17:00",
        "end_time": "17:30",
        "title": "W08 close review",
        "owner": "Owner + Auditor",
        "output": "W08 close and next-week hardening list",
    },
]

ADOPTION_W08_REPORTING_SOP: list[dict[str, Any]] = [
    {
        "step_id": "W08-SOP-01",
        "stage": "Prepare",
        "action": "월간 대상 month/site를 확정하고 데이터 범위를 잠금",
        "output": "Export parameter sheet",
        "api_ref": "/api/reports/monthly",
    },
    {
        "step_id": "W08-SOP-02",
        "stage": "Export",
        "action": "CSV/PDF를 각각 생성하고 파일 해시/크기 검증",
        "output": "CSV/PDF artifact pair",
        "api_ref": "/api/reports/monthly/csv",
    },
    {
        "step_id": "W08-SOP-03",
        "stage": "Audit",
        "action": "감사로그에서 export action 추적 및 누락 확인",
        "output": "Audit trace log",
        "api_ref": "/api/admin/audit-logs",
    },
    {
        "step_id": "W08-SOP-04",
        "stage": "Close",
        "action": "주간 discipline score 리뷰 및 하위 site 개선 오더 발행",
        "output": "Discipline close report",
        "api_ref": "/api/ops/adoption/w08/report-discipline",
    },
]

ADOPTION_W09_KPI_THRESHOLD_MATRIX: list[dict[str, Any]] = [
    {
        "id": "W09-KPI-01",
        "kpi_key": "two_week_retention_percent",
        "kpi_name": "Two-week retention",
        "direction": "higher_better",
        "owner_role": "Ops Manager",
        "green_threshold": 65.0,
        "yellow_threshold": 55.0,
        "target": ">= 65%",
        "source_api": "/api/ops/adoption/w05/consistency",
    },
    {
        "id": "W09-KPI-02",
        "kpi_key": "weekly_active_rate_percent",
        "kpi_name": "Weekly active rate",
        "direction": "higher_better",
        "owner_role": "Ops Lead",
        "green_threshold": 75.0,
        "yellow_threshold": 65.0,
        "target": ">= 75%",
        "source_api": "/api/ops/adoption/w06/rhythm",
    },
    {
        "id": "W09-KPI-03",
        "kpi_key": "escalation_rate_percent",
        "kpi_name": "Escalation rate",
        "direction": "lower_better",
        "owner_role": "Site Champion",
        "green_threshold": 20.0,
        "yellow_threshold": 30.0,
        "target": "<= 20%",
        "source_api": "/api/ops/adoption/w07/sla-quality",
    },
    {
        "id": "W09-KPI-04",
        "kpi_key": "report_discipline_score",
        "kpi_name": "Report discipline score",
        "direction": "higher_better",
        "owner_role": "Audit Lead",
        "green_threshold": 85.0,
        "yellow_threshold": 75.0,
        "target": ">= 85",
        "source_api": "/api/ops/adoption/w08/report-discipline",
    },
    {
        "id": "W09-KPI-05",
        "kpi_key": "data_quality_issue_rate_percent",
        "kpi_name": "Data quality issue rate",
        "direction": "lower_better",
        "owner_role": "Ops PM",
        "green_threshold": 5.0,
        "yellow_threshold": 10.0,
        "target": "<= 5%",
        "source_api": "/api/ops/adoption/w08/report-discipline",
    },
]

ADOPTION_W09_ESCALATION_MAP: list[dict[str, Any]] = [
    {
        "id": "W09-ESC-01",
        "kpi_key": "two_week_retention_percent",
        "condition": "status == red for 1 week",
        "escalate_to": "Head of Ops",
        "sla_hours": 24,
        "action": "Run retention recovery clinic and role mission rebalance",
    },
    {
        "id": "W09-ESC-02",
        "kpi_key": "weekly_active_rate_percent",
        "condition": "status == red for 1 week",
        "escalate_to": "Owner",
        "sla_hours": 24,
        "action": "Assign daily cadence owner and close missing role coverage",
    },
    {
        "id": "W09-ESC-03",
        "kpi_key": "escalation_rate_percent",
        "condition": "status == red for 3 consecutive days",
        "escalate_to": "Ops Lead + QA",
        "sla_hours": 8,
        "action": "Force triage window and high-risk queue split",
    },
    {
        "id": "W09-ESC-04",
        "kpi_key": "report_discipline_score",
        "condition": "status == red on weekly close",
        "escalate_to": "Audit Lead",
        "sla_hours": 24,
        "action": "Issue export remediation order and verify audit traces",
    },
]

ADOPTION_W09_SCHEDULED_EVENTS: list[dict[str, Any]] = [
    {
        "id": "W09-E01",
        "date": "2026-04-27",
        "start_time": "09:00",
        "end_time": "09:40",
        "title": "W09 kickoff - KPI ownership lock",
        "owner": "Head of Ops",
        "output": "KPI owner assignment matrix",
    },
    {
        "id": "W09-E02",
        "date": "2026-04-28",
        "start_time": "14:00",
        "end_time": "14:30",
        "title": "Threshold tuning clinic",
        "owner": "Ops PM + QA",
        "output": "Green/yellow/red threshold baseline",
    },
    {
        "id": "W09-E03",
        "date": "2026-04-29",
        "start_time": "16:00",
        "end_time": "16:30",
        "title": "Mid-week KPI red review",
        "owner": "Owner + Ops Lead",
        "output": "Top blockers and escalation owners",
    },
    {
        "id": "W09-E04",
        "date": "2026-04-30",
        "start_time": "15:00",
        "end_time": "15:30",
        "title": "Escalation map dry-run",
        "owner": "Site Champion",
        "output": "Escalation response rehearsal note",
    },
    {
        "id": "W09-E05",
        "date": "2026-05-01",
        "start_time": "17:00",
        "end_time": "17:30",
        "title": "W09 close review",
        "owner": "Head of Ops + Owner",
        "output": "KPI 운영 전환 승인",
    },
]

ADOPTION_W10_SELF_SERVE_GUIDES: list[dict[str, Any]] = [
    {
        "id": "W10-SS-01",
        "title": "Repeated Ticket Triage Guide",
        "problem_cluster": "동일 제목 반복 작업지시",
        "owner_role": "CS Lead",
        "target": "반복 티켓 20% 감축",
        "source_api": "/api/ops/adoption/w10/self-serve",
    },
    {
        "id": "W10-SS-02",
        "title": "First Response Self-Check",
        "problem_cluster": "초기 분류 지연",
        "owner_role": "Ops QA",
        "target": "첫 응답 15분 이내",
        "source_api": "/api/work-orders",
    },
    {
        "id": "W10-SS-03",
        "title": "SLA Breach Quick Fix Card",
        "problem_cluster": "SLA 초과 처리",
        "owner_role": "Ops Lead",
        "target": "SLA 위반율 10%p 개선",
        "source_api": "/api/ops/adoption/w07/sla-quality",
    },
    {
        "id": "W10-SS-04",
        "title": "Data Quality Recovery Checklist",
        "problem_cluster": "누락/불일치 데이터",
        "owner_role": "Audit Lead",
        "target": "DQ 이슈율 <= 5%",
        "source_api": "/api/ops/adoption/w08/report-discipline",
    },
    {
        "id": "W10-SS-05",
        "title": "Role-based Escalation Decision Tree",
        "problem_cluster": "에스컬레이션 경로 혼선",
        "owner_role": "Site Champion",
        "target": "경로 오분류 0건",
        "source_api": "/api/ops/adoption/w09/kpi-operation",
    },
]

ADOPTION_W10_TROUBLESHOOTING_RUNBOOK: list[dict[str, Any]] = [
    {
        "id": "W10-RB-01",
        "module": "Inspection",
        "symptom": "점검 생성 실패/필수값 누락",
        "owner_role": "Operator Champion",
        "definition_of_done": "재현, 원인, 복구, 예방항목 기록",
        "api_ref": "/api/inspections",
    },
    {
        "id": "W10-RB-02",
        "module": "Work-order",
        "symptom": "상태 전환 오류/처리 지연",
        "owner_role": "Ops Lead",
        "definition_of_done": "전환 규칙 확인 및 재발 방지",
        "api_ref": "/api/work-orders",
    },
    {
        "id": "W10-RB-03",
        "module": "Report",
        "symptom": "월간 출력 누락/지연",
        "owner_role": "Auditor",
        "definition_of_done": "CSV/PDF 출력 증빙과 감사로그 확인",
        "api_ref": "/api/reports/monthly/csv",
    },
    {
        "id": "W10-RB-04",
        "module": "Alert",
        "symptom": "알림 실패/재시도 누락",
        "owner_role": "SRE",
        "definition_of_done": "실패 원인 분류 및 guard/recover 기록",
        "api_ref": "/api/ops/alerts/deliveries",
    },
]

ADOPTION_W10_SCHEDULED_EVENTS: list[dict[str, Any]] = [
    {
        "id": "W10-E01",
        "date": "2026-05-04",
        "start_time": "09:00",
        "end_time": "09:40",
        "title": "W10 kickoff - self-serve baseline",
        "owner": "CS Lead + Ops PM",
        "output": "반복 이슈 Top list + 오너 지정",
    },
    {
        "id": "W10-E02",
        "date": "2026-05-05",
        "start_time": "14:00",
        "end_time": "14:30",
        "title": "Guide publishing sprint",
        "owner": "Operator Champion",
        "output": "Self-serve guide 1차 게시",
    },
    {
        "id": "W10-E03",
        "date": "2026-05-06",
        "start_time": "16:00",
        "end_time": "16:30",
        "title": "Runbook walkthrough drill",
        "owner": "Ops Lead",
        "output": "모듈별 트러블슈팅 시연 기록",
    },
    {
        "id": "W10-E04",
        "date": "2026-05-07",
        "start_time": "15:00",
        "end_time": "15:30",
        "title": "Office-hour dependency review",
        "owner": "CS Lead",
        "output": "의존도 감소 액션 등록",
    },
    {
        "id": "W10-E05",
        "date": "2026-05-08",
        "start_time": "17:00",
        "end_time": "17:30",
        "title": "W10 close review",
        "owner": "Head of Ops + CS Lead",
        "output": "Self-serve 운영 전환 승인",
    },
]


ADOPTION_W11_SELF_SERVE_GUIDES: list[dict[str, Any]] = [
    {
        "id": "W11-SR-01",
        "title": "Scale Readiness Checklist",
        "problem_cluster": "확장 사이트 운영 준비",
        "owner_role": "Program Manager",
        "target": "핵심 체크리스트 100%",
        "source_api": "/api/ops/adoption/w11/scale-readiness",
    },
    {
        "id": "W11-SR-02",
        "title": "New-site Token and RBAC Baseline",
        "problem_cluster": "권한/토큰 초기 설정 누락",
        "owner_role": "Security Admin",
        "target": "권한 설정 오류 0건",
        "source_api": "/api/auth/me",
    },
    {
        "id": "W11-SR-03",
        "title": "Multi-site SOP Sync",
        "problem_cluster": "사이트별 SOP 편차",
        "owner_role": "Ops Lead",
        "target": "핵심 SOP 동기화율 >= 95%",
        "source_api": "/api/public/adoption-plan/w11",
    },
    {
        "id": "W11-SR-04",
        "title": "Fallback Playbook Coverage",
        "problem_cluster": "장애/비상 시나리오 공백",
        "owner_role": "SRE",
        "target": "fallback 커버리지 >= 85%",
        "source_api": "/api/ops/security/posture",
    },
    {
        "id": "W11-SR-05",
        "title": "Expansion Go/No-go Gate",
        "problem_cluster": "확장 승인 기준 불명확",
        "owner_role": "Head of Ops",
        "target": "신규 사이트 시뮬레이션 성공률 >= 90%",
        "source_api": "/api/ops/adoption/w11/readiness-policy",
    },
]

ADOPTION_W11_TROUBLESHOOTING_RUNBOOK: list[dict[str, Any]] = [
    {
        "id": "W11-RB-01",
        "module": "New-site Onboarding",
        "symptom": "초기 설정 누락으로 첫 업무 실패",
        "owner_role": "Program Manager",
        "definition_of_done": "재현/원인/복구/검증 로그 확보",
        "api_ref": "/api/public/adoption-plan/w11",
    },
    {
        "id": "W11-RB-02",
        "module": "RBAC and Token",
        "symptom": "권한 부족/과다로 업무 중단",
        "owner_role": "Security Admin",
        "definition_of_done": "권한 매핑, 토큰 정책, 감사로그 확인",
        "api_ref": "/api/admin/users",
    },
    {
        "id": "W11-RB-03",
        "module": "Reporting and Audit",
        "symptom": "확장 사이트 월간 리포트 누락",
        "owner_role": "Audit Lead",
        "definition_of_done": "CSV/PDF 증빙 + 감사 추적 완료",
        "api_ref": "/api/reports/monthly/csv",
    },
    {
        "id": "W11-RB-04",
        "module": "Alert and Escalation",
        "symptom": "신규 사이트 알림 체계 미정착",
        "owner_role": "Ops QA",
        "definition_of_done": "채널 성공률/MTTR 기준선 충족",
        "api_ref": "/api/ops/alerts/kpi/channels",
    },
]

ADOPTION_W11_SCHEDULED_EVENTS: list[dict[str, Any]] = [
    {
        "id": "W11-E01",
        "date": "2026-05-11",
        "start_time": "09:00",
        "end_time": "09:40",
        "title": "W11 kickoff - scale readiness baseline",
        "owner": "Program Manager + Ops Lead",
        "output": "확장 준비 기준선/오너 확정",
    },
    {
        "id": "W11-E02",
        "date": "2026-05-12",
        "start_time": "14:00",
        "end_time": "14:40",
        "title": "New-site simulation drill",
        "owner": "Site Champion",
        "output": "신규 사이트 시뮬레이션 통과/실패 리포트",
    },
    {
        "id": "W11-E03",
        "date": "2026-05-13",
        "start_time": "16:00",
        "end_time": "16:30",
        "title": "Fallback playbook drill",
        "owner": "SRE",
        "output": "Fallback 실행 증빙 및 개선 항목",
    },
    {
        "id": "W11-E04",
        "date": "2026-05-14",
        "start_time": "15:00",
        "end_time": "15:30",
        "title": "Risk register triage",
        "owner": "PM + QA",
        "output": "확장 리스크 Top list 및 완화 담당자",
    },
    {
        "id": "W11-E05",
        "date": "2026-05-15",
        "start_time": "17:00",
        "end_time": "17:30",
        "title": "W11 close review",
        "owner": "Head of Ops + Program Manager",
        "output": "Scale readiness go/no-go decision",
    },
]

ADOPTION_W12_SELF_SERVE_GUIDES: list[dict[str, Any]] = [
    {
        "id": "W12-CH-01",
        "title": "Closure Review Checklist",
        "problem_cluster": "프로그램 종료 기준 미정의",
        "owner_role": "Executive Sponsor",
        "target": "종료 기준 충족 100%",
        "source_api": "/api/ops/adoption/w12/closure-handoff",
    },
    {
        "id": "W12-CH-02",
        "title": "Independent Execution Scorecard",
        "problem_cluster": "운영 자율성 검증 부족",
        "owner_role": "Head of Ops",
        "target": "독립 실행률 >= 80%",
        "source_api": "/api/ops/adoption/w12/handoff-policy",
    },
    {
        "id": "W12-CH-03",
        "title": "Quarterly Handoff Package",
        "problem_cluster": "다음 분기 인수인계 누락",
        "owner_role": "Program Manager",
        "target": "핵심 운영 패키지 100% 이관",
        "source_api": "/api/public/adoption-plan/w12",
    },
    {
        "id": "W12-CH-04",
        "title": "Runbook Ownership Transfer",
        "problem_cluster": "문서 오너 미지정",
        "owner_role": "Ops Lead",
        "target": "핵심 런북 오너 지정률 100%",
        "source_api": "/api/ops/runbook/checks",
    },
    {
        "id": "W12-CH-05",
        "title": "Post-Program Risk Ledger",
        "problem_cluster": "잔여 리스크 관리 미흡",
        "owner_role": "Audit Lead",
        "target": "고위험 잔여 이슈 0건",
        "source_api": "/api/public/post-mvp/risks",
    },
]

ADOPTION_W12_TROUBLESHOOTING_RUNBOOK: list[dict[str, Any]] = [
    {
        "id": "W12-RB-01",
        "module": "Inspection and Work-Order",
        "symptom": "핵심 워크플로우 독립 실행 실패",
        "owner_role": "Ops QA",
        "definition_of_done": "독립 실행 재현/복구/재검증 증빙 완료",
        "api_ref": "/api/work-orders",
    },
    {
        "id": "W12-RB-02",
        "module": "Reporting and Audit",
        "symptom": "월간 보고 및 감사 추적 공백",
        "owner_role": "Audit Lead",
        "definition_of_done": "CSV/PDF/감사로그 패키지 검증 완료",
        "api_ref": "/api/reports/monthly/csv",
    },
    {
        "id": "W12-RB-03",
        "module": "Security and Access",
        "symptom": "토큰/권한 만료 정책 인계 누락",
        "owner_role": "Security Admin",
        "definition_of_done": "권한 매핑·토큰 만료·회전 정책 검증",
        "api_ref": "/api/admin/tokens",
    },
    {
        "id": "W12-RB-04",
        "module": "Alert and SLA Guard",
        "symptom": "경보 품질/복구 자동화 유지 실패",
        "owner_role": "SRE",
        "definition_of_done": "Guard latest + recovery run 증빙 완료",
        "api_ref": "/api/ops/alerts/channels/guard",
    },
]

ADOPTION_W12_SCHEDULED_EVENTS: list[dict[str, Any]] = [
    {
        "id": "W12-E01",
        "date": "2026-05-18",
        "start_time": "09:00",
        "end_time": "09:40",
        "title": "W12 kickoff - closure baseline",
        "owner": "Executive Sponsor + Ops Director",
        "output": "종료 기준/오너/검증 일정 확정",
    },
    {
        "id": "W12-E02",
        "date": "2026-05-19",
        "start_time": "14:00",
        "end_time": "14:40",
        "title": "Independent execution drill",
        "owner": "Site Champions",
        "output": "핵심 워크플로우 독립 실행 증빙",
    },
    {
        "id": "W12-E03",
        "date": "2026-05-20",
        "start_time": "16:00",
        "end_time": "16:30",
        "title": "Handoff package validation",
        "owner": "Program Manager + Audit Lead",
        "output": "운영/문서/리스크 인계 체크 완료",
    },
    {
        "id": "W12-E04",
        "date": "2026-05-21",
        "start_time": "15:00",
        "end_time": "15:30",
        "title": "Q3 operating plan review",
        "owner": "Ops Director",
        "output": "다음 분기 실행계획 초안 확정",
    },
    {
        "id": "W12-E05",
        "date": "2026-05-22",
        "start_time": "17:00",
        "end_time": "17:30",
        "title": "W12 closure sign-off",
        "owner": "Executive Sponsor",
        "output": "프로그램 종료 및 handoff 승인",
    },
]

ADOPTION_W13_SELF_SERVE_GUIDES: list[dict[str, Any]] = [
    {
        "id": "W13-CH-01",
        "title": "Continuous Improvement Checklist",
        "problem_cluster": "프로그램 종료 기준 미정의",
        "owner_role": "Executive Sponsor",
        "target": "종료 기준 충족 100%",
        "source_api": "/api/ops/adoption/w13/closure-handoff",
    },
    {
        "id": "W13-CH-02",
        "title": "Stability Optimization Scorecard",
        "problem_cluster": "운영 자율성 검증 부족",
        "owner_role": "Head of Ops",
        "target": "독립 실행률 >= 80%",
        "source_api": "/api/ops/adoption/w13/handoff-policy",
    },
    {
        "id": "W13-CH-03",
        "title": "Quarterly Optimization Package",
        "problem_cluster": "다음 분기 인수인계 누락",
        "owner_role": "Program Manager",
        "target": "핵심 운영 패키지 100% 이관",
        "source_api": "/api/public/adoption-plan/w13",
    },
    {
        "id": "W13-CH-04",
        "title": "Runbook Ownership Transfer",
        "problem_cluster": "문서 오너 미지정",
        "owner_role": "Ops Lead",
        "target": "핵심 런북 오너 지정률 100%",
        "source_api": "/api/ops/runbook/checks",
    },
    {
        "id": "W13-CH-05",
        "title": "Post-Program Risk Ledger",
        "problem_cluster": "잔여 리스크 관리 미흡",
        "owner_role": "Audit Lead",
        "target": "고위험 잔여 이슈 0건",
        "source_api": "/api/public/post-mvp/risks",
    },
]

ADOPTION_W13_TROUBLESHOOTING_RUNBOOK: list[dict[str, Any]] = [
    {
        "id": "W13-RB-01",
        "module": "Inspection and Work-Order",
        "symptom": "핵심 워크플로우 독립 실행 실패",
        "owner_role": "Ops QA",
        "definition_of_done": "독립 실행 재현/복구/재검증 증빙 완료",
        "api_ref": "/api/work-orders",
    },
    {
        "id": "W13-RB-02",
        "module": "Reporting and Audit",
        "symptom": "월간 보고 및 감사 추적 공백",
        "owner_role": "Audit Lead",
        "definition_of_done": "CSV/PDF/감사로그 패키지 검증 완료",
        "api_ref": "/api/reports/monthly/csv",
    },
    {
        "id": "W13-RB-03",
        "module": "Security and Access",
        "symptom": "토큰/권한 만료 정책 인계 누락",
        "owner_role": "Security Admin",
        "definition_of_done": "권한 매핑·토큰 만료·회전 정책 검증",
        "api_ref": "/api/admin/tokens",
    },
    {
        "id": "W13-RB-04",
        "module": "Alert and SLA Guard",
        "symptom": "경보 품질/복구 자동화 유지 실패",
        "owner_role": "SRE",
        "definition_of_done": "Guard latest + recovery run 증빙 완료",
        "api_ref": "/api/ops/alerts/channels/guard",
    },
]

ADOPTION_W13_SCHEDULED_EVENTS: list[dict[str, Any]] = [
    {
        "id": "W13-E01",
        "date": "2026-05-25",
        "start_time": "09:00",
        "end_time": "09:40",
        "title": "W13 kickoff - improvement baseline",
        "owner": "Executive Sponsor + Ops Director",
        "output": "종료 기준/오너/검증 일정 확정",
    },
    {
        "id": "W13-E02",
        "date": "2026-05-26",
        "start_time": "14:00",
        "end_time": "14:40",
        "title": "Independent execution drill",
        "owner": "Site Champions",
        "output": "핵심 워크플로우 독립 실행 증빙",
    },
    {
        "id": "W13-E03",
        "date": "2026-05-27",
        "start_time": "16:00",
        "end_time": "16:30",
        "title": "Handoff package validation",
        "owner": "Program Manager + Audit Lead",
        "output": "운영/문서/리스크 인계 체크 완료",
    },
    {
        "id": "W13-E04",
        "date": "2026-05-28",
        "start_time": "15:00",
        "end_time": "15:30",
        "title": "Q3 operating plan review",
        "owner": "Ops Director",
        "output": "다음 분기 실행계획 초안 확정",
    },
    {
        "id": "W13-E05",
        "date": "2026-05-29",
        "start_time": "17:00",
        "end_time": "17:30",
        "title": "W13 improvement sign-off",
        "owner": "Executive Sponsor",
        "output": "지속 개선 운영체계 승인",
    },
]

ADOPTION_W14_SELF_SERVE_GUIDES: list[dict[str, Any]] = [
    {
        "id": "W14-ST-01",
        "title": "Critical API Latency Baseline",
        "problem_cluster": "핵심 API 성능 기준 불명확",
        "owner_role": "SRE",
        "target": "P95 latency threshold 확정 100%",
        "source_api": "/api/ops/adoption/w14/stability-sprint",
    },
    {
        "id": "W14-ST-02",
        "title": "Post-deploy Smoke Standard",
        "problem_cluster": "배포 후 검증 누락",
        "owner_role": "Ops QA",
        "target": "배포 후 smoke 체크 100%",
        "source_api": "/api/ops/adoption/w14/stability-policy",
    },
    {
        "id": "W14-ST-03",
        "title": "Rollback Decision Checklist",
        "problem_cluster": "롤백 판단 지연",
        "owner_role": "Release Manager",
        "target": "롤백 결정 SLA <= 10분",
        "source_api": "/api/public/adoption-plan/w14",
    },
    {
        "id": "W14-ST-04",
        "title": "Evidence and Audit Integrity Validation",
        "problem_cluster": "증빙/감사 무결성 점검 공백",
        "owner_role": "Audit Lead",
        "target": "무결성 검증 성공률 >= 99%",
        "source_api": "/api/admin/audit-integrity",
    },
    {
        "id": "W14-ST-05",
        "title": "Weekly Stability Exception Triage",
        "problem_cluster": "예외 항목 누적",
        "owner_role": "Ops Director",
        "target": "예외 backlog 7일 이내 해소율 >= 90%",
        "source_api": "/api/ops/handover/brief",
    },
]

ADOPTION_W14_TROUBLESHOOTING_RUNBOOK: list[dict[str, Any]] = [
    {
        "id": "W14-RB-01",
        "module": "API Performance",
        "symptom": "핵심 API 지연시간 급증",
        "owner_role": "SRE",
        "definition_of_done": "지연 구간 식별/원인/완화/재측정 완료",
        "api_ref": "/api/ops/dashboard/trends",
    },
    {
        "id": "W14-RB-02",
        "module": "Deployment Verification",
        "symptom": "배포 후 기능 이상 미감지",
        "owner_role": "Ops QA",
        "definition_of_done": "스모크 결과/실패원인/복구로그 확보",
        "api_ref": "/api/ops/job-runs",
    },
    {
        "id": "W14-RB-03",
        "module": "Rollback Control",
        "symptom": "롤백 기준 미충족 상태에서 서비스 지속",
        "owner_role": "Release Manager",
        "definition_of_done": "롤백 기준, 승인자, 실행 로그 확정",
        "api_ref": "/api/work-orders/escalations/run",
    },
    {
        "id": "W14-RB-04",
        "module": "Archive Integrity",
        "symptom": "증빙/감사 아카이브 검증 실패",
        "owner_role": "Audit Lead",
        "definition_of_done": "무결성 오류 0건 + 재검증 통과",
        "api_ref": "/api/admin/audit-archive/monthly",
    },
]

ADOPTION_W14_SCHEDULED_EVENTS: list[dict[str, Any]] = [
    {
        "id": "W14-E01",
        "date": "2026-06-01",
        "start_time": "09:00",
        "end_time": "09:40",
        "title": "W14 kickoff - stability baseline",
        "owner": "SRE Lead + Ops Director",
        "output": "성능/신뢰성/데이터 무결성 기준선 확정",
    },
    {
        "id": "W14-E02",
        "date": "2026-06-02",
        "start_time": "14:00",
        "end_time": "14:40",
        "title": "Critical API latency drill",
        "owner": "SRE",
        "output": "핵심 API P95 측정 및 임계값 제안",
    },
    {
        "id": "W14-E03",
        "date": "2026-06-03",
        "start_time": "16:00",
        "end_time": "16:30",
        "title": "Smoke and rollback simulation",
        "owner": "Release Manager + Ops QA",
        "output": "배포 검증/롤백 체크리스트 시뮬레이션 통과",
    },
    {
        "id": "W14-E04",
        "date": "2026-06-04",
        "start_time": "15:00",
        "end_time": "15:30",
        "title": "Archive integrity batch review",
        "owner": "Audit Lead",
        "output": "아카이브 무결성 점검 결과 및 개선 항목",
    },
    {
        "id": "W14-E05",
        "date": "2026-06-05",
        "start_time": "17:00",
        "end_time": "17:30",
        "title": "W14 stability sign-off",
        "owner": "Ops Director + Security Admin",
        "output": "안정화 스프린트 완료 판정",
    },
]

ADOPTION_W15_SELF_SERVE_GUIDES: list[dict[str, Any]] = [
    {
        "id": "W15-OP-01",
        "title": "Execution Tracker UI Commonization Checklist",
        "problem_cluster": "W07~W14 실행추적 UI 중복 유지보수",
        "owner_role": "Frontend Lead",
        "target": "공통 컴포넌트 적용률 100%",
        "source_api": "/api/ops/adoption/w15/ops-efficiency",
    },
    {
        "id": "W15-OP-02",
        "title": "Policy API Response Standard Checklist",
        "problem_cluster": "정책 API 응답 구조 불일치",
        "owner_role": "Platform Engineer",
        "target": "표준 응답 적용률 100%",
        "source_api": "/api/ops/adoption/w15/efficiency-policy",
    },
    {
        "id": "W15-OP-03",
        "title": "Weekly Ops Report Auto-publish",
        "problem_cluster": "주간 운영 리포트 수동 발행 지연",
        "owner_role": "Ops PM",
        "target": "주간 리포트 on-time >= 95%",
        "source_api": "/api/public/adoption-plan/w15",
    },
    {
        "id": "W15-OP-04",
        "title": "Exception Digest and Owner Routing",
        "problem_cluster": "예외 항목 오너 할당 누락",
        "owner_role": "Audit Lead",
        "target": "예외 오너 지정률 100%",
        "source_api": "/api/ops/handover/brief",
    },
    {
        "id": "W15-OP-05",
        "title": "Action Closure SLA Governance",
        "problem_cluster": "개선 액션 장기 미해결",
        "owner_role": "Ops Director",
        "target": "7일 초과 미해결 0건",
        "source_api": "/api/ops/adoption/w15/ops-efficiency",
    },
]

ADOPTION_W15_TROUBLESHOOTING_RUNBOOK: list[dict[str, Any]] = [
    {
        "id": "W15-RB-01",
        "module": "Tracker UI",
        "symptom": "주차별 실행추적 UI 동작 불일치",
        "owner_role": "Frontend Lead",
        "definition_of_done": "공통 UI 동작/검증 항목 적용 완료",
        "api_ref": "/api/public/adoption-plan/w15",
    },
    {
        "id": "W15-RB-02",
        "module": "Policy API Standard",
        "symptom": "정책 API 응답 포맷 파싱 오류",
        "owner_role": "Platform Engineer",
        "definition_of_done": "표준 schema 적용 + 회귀 통과",
        "api_ref": "/api/ops/adoption/w15/efficiency-policy",
    },
    {
        "id": "W15-RB-03",
        "module": "Weekly Ops Report",
        "symptom": "주간 리포트 미발행/지연 발행",
        "owner_role": "Ops PM",
        "definition_of_done": "자동 발행 + 예외 요약 포함",
        "api_ref": "/api/ops/adoption/w15/ops-efficiency",
    },
    {
        "id": "W15-RB-04",
        "module": "Exception Governance",
        "symptom": "예외 항목 누락 및 장기 체류",
        "owner_role": "Audit Lead",
        "definition_of_done": "예외 오너 지정/마감일/해결증빙 완료",
        "api_ref": "/api/admin/audit-logs",
    },
]

ADOPTION_W15_SCHEDULED_EVENTS: list[dict[str, Any]] = [
    {
        "id": "W15-E01",
        "date": "2026-06-08",
        "start_time": "09:00",
        "end_time": "09:40",
        "title": "W15 kickoff - efficiency baseline",
        "owner": "Ops PM + Platform Engineer",
        "output": "운영 효율화 기준선/오너 확정",
    },
    {
        "id": "W15-E02",
        "date": "2026-06-09",
        "start_time": "14:00",
        "end_time": "14:40",
        "title": "Tracker UI common component drill",
        "owner": "Frontend Lead",
        "output": "공통 컴포넌트 적용 결과/갭 리포트",
    },
    {
        "id": "W15-E03",
        "date": "2026-06-10",
        "start_time": "16:00",
        "end_time": "16:30",
        "title": "Policy response standardization review",
        "owner": "Platform Engineer",
        "output": "정책 API 표준 응답 적용 결과",
    },
    {
        "id": "W15-E04",
        "date": "2026-06-11",
        "start_time": "15:00",
        "end_time": "15:30",
        "title": "Weekly report automation dry-run",
        "owner": "Ops PM + Audit Lead",
        "output": "주간 운영 리포트 자동 발행 dry-run",
    },
    {
        "id": "W15-E05",
        "date": "2026-06-12",
        "start_time": "17:00",
        "end_time": "17:30",
        "title": "W15 efficiency sign-off",
        "owner": "Ops Director",
        "output": "운영 효율화 단계 완료 판정",
    },
]


FACILITY_WEB_MODULES: list[dict[str, Any]] = [
    {
        "id": "inspection-ops",
        "name": "Inspection Operations",
        "name_ko": "점검 관리",
        "description": "시설 점검 등록, 조회, 출력까지 점검 업무 전체를 처리합니다.",
        "kpi_hint": "High risk detection lead time",
        "links": [
            {"label": "Create Inspection", "href": "/api/inspections"},
            {"label": "List Inspections", "href": "/api/inspections"},
            {"label": "Print Inspection", "href": "/inspections/{id}/print"},
        ],
    },
    {
        "id": "work-order-ops",
        "name": "Work-Order Operations",
        "name_ko": "작업지시 관리",
        "description": "작업지시 생성부터 ACK/완료/취소/재오픈까지 라이프사이클을 관리합니다.",
        "kpi_hint": "Time-To-First-Action",
        "links": [
            {"label": "Create Work-Order", "href": "/api/work-orders"},
            {"label": "Work-Order Timeline", "href": "/api/work-orders/{id}/events"},
            {"label": "Escalation Batch Run", "href": "/api/work-orders/escalations/run"},
        ],
    },
    {
        "id": "sla-alerts",
        "name": "SLA and Alerts",
        "name_ko": "SLA/알림 운영",
        "description": "SLA 정책, 시뮬레이션, 에스컬레이션, 알림 재시도를 운영합니다.",
        "kpi_hint": "SLA on-time rate and alert success",
        "links": [
            {"label": "SLA Simulator", "href": "/api/ops/sla/simulate"},
            {"label": "Failed Deliveries", "href": "/api/ops/alerts/deliveries"},
            {"label": "Retry Batch Run", "href": "/api/ops/alerts/retries/run"},
        ],
    },
    {
        "id": "reporting-audit",
        "name": "Reporting and Audit",
        "name_ko": "리포트/감사",
        "description": "월간 리포트 조회와 CSV/PDF 내보내기, 감사 기준 운영을 지원합니다.",
        "kpi_hint": "Monthly report on-time rate",
        "links": [
            {"label": "Monthly Report", "href": "/api/reports/monthly"},
            {"label": "Monthly CSV", "href": "/api/reports/monthly/csv"},
            {"label": "Monthly PDF", "href": "/api/reports/monthly/pdf"},
        ],
    },
    {
        "id": "ops-command",
        "name": "Ops Command Center",
        "name_ko": "운영 상황실",
        "description": "대시보드 요약/추세와 핸드오버 브리프로 일일 운영 회의를 지원합니다.",
        "kpi_hint": "Open risk backlog burn-down",
        "links": [
            {"label": "Dashboard Summary", "href": "/api/ops/dashboard/summary"},
            {"label": "Dashboard Trends", "href": "/api/ops/dashboard/trends"},
            {"label": "Handover Brief", "href": "/api/ops/handover/brief"},
        ],
    },
    {
        "id": "rbac-governance",
        "name": "RBAC and Governance",
        "name_ko": "권한/거버넌스",
        "description": "사용자/토큰/RBAC/SLA 정책 변경을 통제하고 감사로그를 추적합니다.",
        "kpi_hint": "Policy drift unresolved > 7d",
        "links": [
            {"label": "Auth Me", "href": "/api/auth/me"},
            {"label": "Admin Users", "href": "/api/admin/users"},
            {"label": "Admin Audit Logs", "href": "/api/admin/audit-logs"},
            {"label": "Workflow Locks", "href": "/api/workflow-locks"},
        ],
    },
    {
        "id": "report-discipline",
        "name": "Report Discipline",
        "name_ko": "리포트 규율",
        "description": "W08 기준으로 리포트 출력 준수율, 데이터 품질, 사이트 벤치마크를 운영합니다.",
        "kpi_hint": "Report discipline score >= 85",
        "links": [
            {"label": "W08 Pack", "href": "/api/public/adoption-plan/w08"},
            {"label": "W08 Discipline", "href": "/api/ops/adoption/w08/report-discipline"},
            {"label": "W08 Benchmark", "href": "/api/ops/adoption/w08/site-benchmark"},
        ],
    },
    {
        "id": "kpi-operations",
        "name": "KPI Operations",
        "name_ko": "KPI 운영전환",
        "description": "W09 기준 KPI 임계값/오너/에스컬레이션을 운영하고 사이트별 상태를 추적합니다.",
        "kpi_hint": "KPI owner coverage 100%",
        "links": [
            {"label": "W09 Pack", "href": "/api/public/adoption-plan/w09"},
            {"label": "W09 KPI Ops", "href": "/api/ops/adoption/w09/kpi-operation"},
            {"label": "W09 KPI Policy", "href": "/api/ops/adoption/w09/kpi-policy"},
            {"label": "W09 Tracker", "href": "/api/adoption/w09/tracker/items"},
        ],
    },
    {
        "id": "self-serve-support",
        "name": "Self-serve Support",
        "name_ko": "셀프서브 지원",
        "description": "W10 기준 반복 이슈를 가이드/런북으로 전환하고 실행추적으로 정착시킵니다.",
        "kpi_hint": "Support repeat rate down >= 20%",
        "links": [
            {"label": "W10 Pack", "href": "/api/public/adoption-plan/w10"},
            {"label": "W10 Self-serve", "href": "/api/ops/adoption/w10/self-serve"},
            {"label": "W10 Support Policy", "href": "/api/ops/adoption/w10/support-policy"},
            {"label": "W10 Tracker", "href": "/api/adoption/w10/tracker/items"},
        ],
    },
    {
        "id": "scale-readiness",
        "name": "Scale Readiness",
        "name_ko": "확장 준비",
        "description": "W11 기준으로 신규 사이트 확장 준비도, 시뮬레이션, fallback playbook을 운영합니다.",
        "kpi_hint": "New-site simulation success >= 90%",
        "links": [
            {"label": "W11 Pack", "href": "/api/public/adoption-plan/w11"},
            {"label": "W11 Scale Readiness", "href": "/api/ops/adoption/w11/scale-readiness"},
            {"label": "W11 Readiness Policy", "href": "/api/ops/adoption/w11/readiness-policy"},
            {"label": "W11 Tracker", "href": "/api/adoption/w11/tracker/items"},
        ],
    },
    {
        "id": "closure-handoff",
        "name": "Closure and Handoff",
        "name_ko": "종료 및 인수인계",
        "description": "W12 기준으로 독립 실행률, 종료 검증, 분기 운영 인수인계를 점검하고 승인합니다.",
        "kpi_hint": "Independent execution >= 80%",
        "links": [
            {"label": "W12 Pack", "href": "/api/public/adoption-plan/w12"},
            {"label": "W12 Closure Handoff", "href": "/api/ops/adoption/w12/closure-handoff"},
            {"label": "W12 Handoff Policy", "href": "/api/ops/adoption/w12/handoff-policy"},
            {"label": "W12 Tracker", "href": "/api/adoption/w12/tracker/items"},
        ],
    },
    {
        "id": "continuous-improvement",
        "name": "Continuous Improvement",
        "name_ko": "지속 개선",
        "description": "W13 기준으로 개선 백로그 운영, 오너 액션 추적, 분기 거버넌스를 실행합니다.",
        "kpi_hint": "Improvement action closure >= 85%",
        "links": [
            {"label": "W13 Pack", "href": "/api/public/adoption-plan/w13"},
            {"label": "W13 Closure Handoff", "href": "/api/ops/adoption/w13/closure-handoff"},
            {"label": "W13 Handoff Policy", "href": "/api/ops/adoption/w13/handoff-policy"},
            {"label": "W13 Tracker", "href": "/api/adoption/w13/tracker/items"},
        ],
    },
    {
        "id": "stability-sprint",
        "name": "Stability Sprint",
        "name_ko": "안정화 스프린트",
        "description": "W14 기준으로 성능/신뢰성/아카이브 무결성을 점검하고 운영 표준을 마감합니다.",
        "kpi_hint": "Stability readiness score >= 85%",
        "links": [
            {"label": "W14 Pack", "href": "/api/public/adoption-plan/w14"},
            {"label": "W14 Stability Sprint", "href": "/api/ops/adoption/w14/stability-sprint"},
            {"label": "W14 Stability Policy", "href": "/api/ops/adoption/w14/stability-policy"},
            {"label": "W14 Tracker", "href": "/api/adoption/w14/tracker/items"},
        ],
    },
    {
        "id": "operations-efficiency",
        "name": "Operations Efficiency",
        "name_ko": "운영 효율화",
        "description": "W15 기준으로 실행추적 UI 공통화, 정책 API 표준화, 주간 운영 리포트 자동화를 정착합니다.",
        "kpi_hint": "Weekly ops report on-time >= 95%",
        "links": [
            {"label": "W15 Pack", "href": "/api/public/adoption-plan/w15"},
            {"label": "W15 Ops Efficiency", "href": "/api/ops/adoption/w15/ops-efficiency"},
            {"label": "W15 Efficiency Policy", "href": "/api/ops/adoption/w15/efficiency-policy"},
            {"label": "W15 Tracker", "href": "/api/adoption/w15/tracker/items"},
        ],
    },
    {
        "id": "tutorial-simulator",
        "name": "Tutorial Simulator",
        "name_ko": "튜토리얼 시뮬레이터",
        "description": "신규 사용자가 검증된 샘플데이터와 단계별 조건으로 실습하고 즉시 완료판정을 받을 수 있습니다.",
        "kpi_hint": "First successful practice <= 20 min",
        "links": [
            {"label": "튜토리얼 허브", "href": "/web/tutorial-simulator"},
            {"label": "튜토리얼 API", "href": "/api/public/tutorial-simulator"},
            {"label": "샘플 파일", "href": "/api/public/tutorial-simulator/sample-files"},
            {"label": "세션 시작", "href": "/api/ops/tutorial-simulator/sessions/start"},
        ],
    },
    {
        "id": "growth-roadmap",
        "name": "Growth and Post-MVP",
        "name_ko": "확장 로드맵",
        "description": "Post-MVP 로드맵, 백로그, 릴리즈 캘린더, 리스크 레지스터를 관리합니다.",
        "kpi_hint": "Release gate pass ratio",
        "links": [
            {"label": "Post-MVP Plan", "href": "/api/public/post-mvp"},
            {"label": "Backlog CSV", "href": "/api/public/post-mvp/backlog.csv"},
            {"label": "Release ICS", "href": "/api/public/post-mvp/releases.ics"},
        ],
    },
]

TUTORIAL_SIMULATOR_SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "ts-core-01",
        "name": "Core Lifecycle Starter",
        "name_ko": "핵심 라이프사이클 입문",
        "description": "점검 생성 -> 작업지시 ACK -> 작업지시 완료까지 실제 운영 흐름을 실습합니다.",
        "estimated_minutes": 20,
        "verified_sample_data": {
            "inspection": {
                "cycle": "daily",
                "location": "MCC-A1",
                "inspector": "Tutorial Bot",
                "transformer_kva": 1250.0,
                "winding_temp_c": 132.0,
                "grounding_ohm": 11.2,
                "insulation_mohm": 0.6,
                "notes": "Tutorial scenario seeded high-risk sample.",
            },
            "work_order": {
                "title": "Tutorial - transformer hotspot response",
                "priority": "high",
                "assignee": "Ops Trainee",
                "description": "Acknowledge and complete this tutorial work order.",
            },
        },
        "steps": [
            {
                "id": "seed_inspection_verified",
                "name": "Seed inspection verified",
                "name_ko": "샘플 점검 확인",
                "condition": "inspection exists and risk_level in [warning, danger]",
            },
            {
                "id": "seed_work_order_open",
                "name": "Seed work-order open",
                "name_ko": "샘플 작업지시 OPEN 확인",
                "condition": "work-order exists and status=open",
            },
            {
                "id": "ack_work_order",
                "name": "Acknowledge work-order",
                "name_ko": "작업지시 ACK 처리",
                "condition": "work-order status in [acked, completed] and acknowledged_at is set",
            },
            {
                "id": "complete_work_order",
                "name": "Complete work-order",
                "name_ko": "작업지시 완료 처리",
                "condition": "work-order status=completed and completed_at is set",
            },
            {
                "id": "report_data_ready",
                "name": "Report data ready",
                "name_ko": "리포트 데이터 준비 완료",
                "condition": "monthly report source has >=1 inspection and >=1 work-order for session site",
            },
        ],
        "practice_apis": [
            {"label": "Create Inspection", "href": "/api/inspections", "method": "POST"},
            {"label": "Create Work-Order", "href": "/api/work-orders", "method": "POST"},
            {"label": "ACK Work-Order", "href": "/api/work-orders/{id}/ack", "method": "PATCH"},
            {"label": "Complete Work-Order", "href": "/api/work-orders/{id}/complete", "method": "PATCH"},
            {"label": "Monthly Report", "href": "/api/reports/monthly?month=YYYY-MM&site={site}", "method": "GET"},
        ],
    }
]

TUTORIAL_SIMULATOR_SAMPLE_FILES: list[dict[str, Any]] = [
    {
        "sample_id": "ts-core-01-session-start",
        "scenario_id": "ts-core-01",
        "title": "Session Start Request (JSON)",
        "description": "세션 시작용 검증 요청 바디",
        "file_name": "tutorial-ts-core-01-session-start.json",
        "content_type": "application/json",
        "content": json.dumps(
            {
                "scenario_id": "ts-core-01",
                "site": "Tutorial-HQ",
            },
            ensure_ascii=False,
            indent=2,
        ),
    },
    {
        "sample_id": "ts-core-01-action-ack",
        "scenario_id": "ts-core-01",
        "title": "ACK Action Request (JSON)",
        "description": "ACK 실습 실행용 요청 바디",
        "file_name": "tutorial-ts-core-01-action-ack.json",
        "content_type": "application/json",
        "content": json.dumps(
            {
                "assignee": "Ops Trainee",
            },
            ensure_ascii=False,
            indent=2,
        ),
    },
    {
        "sample_id": "ts-core-01-action-complete",
        "scenario_id": "ts-core-01",
        "title": "Complete Action Request (JSON)",
        "description": "완료 실습 실행용 요청 바디",
        "file_name": "tutorial-ts-core-01-action-complete.json",
        "content_type": "application/json",
        "content": json.dumps(
            {
                "resolution_notes": "Tutorial completion by trainee",
            },
            ensure_ascii=False,
            indent=2,
        ),
    },
    {
        "sample_id": "ts-core-01-practice-checklist",
        "scenario_id": "ts-core-01",
        "title": "Practice Checklist (Markdown)",
        "description": "신규 사용자 실습 체크리스트",
        "file_name": "tutorial-ts-core-01-practice-checklist.md",
        "content_type": "text/markdown",
        "content": (
            "# Tutorial Simulator Checklist\n\n"
            "1. Start session with `ts-core-01`.\n"
            "2. Confirm seeded inspection/work-order IDs.\n"
            "3. Run `ack_work_order` action.\n"
            "4. Run `complete_work_order` action.\n"
            "5. Run session check and confirm completion_percent=100.\n"
            "6. Save run result as onboarding evidence.\n"
        ),
    },
    {
        "sample_id": "ts-core-01-expected-result",
        "scenario_id": "ts-core-01",
        "title": "Expected Completion Shape (JSON)",
        "description": "완료 판정 시 기대되는 응답 형태",
        "file_name": "tutorial-ts-core-01-expected-result.json",
        "content_type": "application/json",
        "content": json.dumps(
            {
                "progress": {"status": "completed", "completion_percent": 100},
                "steps": [
                    {"id": "seed_inspection_verified", "completed": True},
                    {"id": "seed_work_order_open", "completed": True},
                    {"id": "ack_work_order", "completed": True},
                    {"id": "complete_work_order", "completed": True},
                    {"id": "report_data_ready", "completed": True},
                ],
            },
            ensure_ascii=False,
            indent=2,
        ),
    },
]

PUBLIC_DAY1_ONBOARDING_STEPS: list[dict[str, Any]] = [
    {
        "id": "connect-auth",
        "step_no": 1,
        "title": "권한 확인과 기본 화면 연결",
        "estimated_minutes": 10,
        "recommended_role": "all",
        "goal": "로그인 또는 AdminToken 연결이 정상인지 확인하고 메인 탭 구조를 익힌다.",
        "success_check": "메인 화면에서 /api/auth/me 응답과 현재 역할(owner/manager/operator/auditor)을 확인한다.",
        "links": [
            {"label": "메인 운영 화면", "href": "/"},
            {"label": "권한 확인 API", "href": "/api/auth/me"},
        ],
    },
    {
        "id": "create-inspection",
        "step_no": 2,
        "title": "OPS 점검 1건 등록",
        "estimated_minutes": 20,
        "recommended_role": "operator",
        "goal": "전기직무고시/소방 점검 입력 구조를 실제로 한 건 저장한다.",
        "success_check": "점검 탭에서 필수값 누락 없이 저장되고 점검 이력 조회에서 방금 등록한 항목이 보인다.",
        "links": [
            {"label": "점검 입력 API", "href": "/api/inspections"},
            {"label": "점검 이력 조회 API", "href": "/api/inspections?limit=5"},
        ],
    },
    {
        "id": "tutorial-lifecycle",
        "step_no": 3,
        "title": "튜토리얼로 작업지시 ACK/완료 실습",
        "estimated_minutes": 20,
        "recommended_role": "operator",
        "goal": "튜토리얼 시뮬레이터로 점검 -> 작업지시 ACK -> 완료 흐름을 끝까지 실습한다.",
        "success_check": "세션 check 응답에서 completion_percent=100 이고 progress.status=completed 이다.",
        "links": [
            {"label": "튜토리얼 시뮬레이터", "href": "/web/tutorial-simulator"},
            {"label": "세션 시작 API", "href": "/api/ops/tutorial-simulator/sessions/start"},
        ],
    },
    {
        "id": "review-reporting",
        "step_no": 4,
        "title": "월간리포트와 출력 링크 확인",
        "estimated_minutes": 10,
        "recommended_role": "manager",
        "goal": "월간리포트 탭에서 집계 결과와 CSV/PDF/인쇄 링크를 확인한다.",
        "success_check": "월간리포트 탭에서 요약 카드가 보이고 CSV 또는 인쇄 화면을 1회 연다.",
        "links": [
            {"label": "월간리포트 API", "href": "/api/reports/monthly?month=2026-03"},
            {"label": "리포트 인쇄 화면", "href": "/reports/monthly/print"},
        ],
    },
    {
        "id": "verify-evidence-audit",
        "step_no": 5,
        "title": "증빙과 감사 흔적 확인",
        "estimated_minutes": 15,
        "recommended_role": "owner",
        "goal": "증빙 파일, 토큰 정책, 감사 로그가 남는 구조를 이해한다.",
        "success_check": "권한관리 탭에서 감사 로그 1건 이상을 조회하고 증빙/토큰 관련 API 위치를 확인한다.",
        "links": [
            {"label": "감사 무결성 API", "href": "/api/admin/audit-integrity"},
            {"label": "토큰 정책 API", "href": "/api/admin/token-policy"},
        ],
    },
]

PUBLIC_ROLE_START_GUIDES: list[dict[str, Any]] = [
    {
        "role": "owner",
        "role_ko": "소유자",
        "first_focus": "사용자/권한/토큰 정책과 감사 무결성",
        "first_actions": [
            "권한관리 탭에서 /api/auth/me, 사용자 목록, 토큰 정책을 확인한다.",
            "감사로그와 월간 아카이브가 내려받기 가능한지 확인한다.",
            "runbook/gate 상태가 go 인지 확인한다.",
        ],
        "recommended_links": [
            {"label": "권한관리 탭", "href": "/?tab=iam"},
            {"label": "거버넌스 게이트 API", "href": "/api/ops/governance/gate"},
        ],
    },
    {
        "role": "manager",
        "role_ko": "관리자",
        "first_focus": "점검 결과 검토, 작업지시 우선순위, 월간리포트",
        "first_actions": [
            "운영요약과 작업지시 탭에서 high/critical 상태를 확인한다.",
            "점검 입력 구조와 체크리스트 세트를 검토한다.",
            "월간리포트 탭에서 출력 경로를 확인한다.",
        ],
        "recommended_links": [
            {"label": "운영요약 탭", "href": "/?tab=overview"},
            {"label": "월간리포트 탭", "href": "/?tab=reports"},
        ],
    },
    {
        "role": "operator",
        "role_ko": "운영자",
        "first_focus": "점검 입력, 작업지시 ACK/완료, 증빙 업로드",
        "first_actions": [
            "튜토리얼 시뮬레이터로 ACK/완료 흐름을 1회 실습한다.",
            "점검 탭에서 OPS 법정점검 1건을 등록한다.",
            "증빙 파일과 이상조치 등록 흐름을 확인한다.",
        ],
        "recommended_links": [
            {"label": "점검 탭", "href": "/?tab=inspections"},
            {"label": "튜토리얼 탭", "href": "/?tab=tutorial"},
        ],
    },
    {
        "role": "auditor",
        "role_ko": "감사자",
        "first_focus": "감사로그, 무결성, 리포트 원본 확인",
        "first_actions": [
            "감사 무결성과 월간 아카이브 다운로드를 확인한다.",
            "월간리포트와 점검 이력의 원본 API를 조회한다.",
            "필수 메타(checklist_version/source/applied_at)가 붙는지 검토한다.",
        ],
        "recommended_links": [
            {"label": "감사 무결성 API", "href": "/api/admin/audit-integrity"},
            {"label": "점검 조회 API", "href": "/api/inspections?limit=20"},
        ],
    },
]

PUBLIC_GLOSSARY_TERMS: list[dict[str, Any]] = [
    {
        "term": "Overview",
        "term_ko": "운영요약",
        "category": "console",
        "category_ko": "화면",
        "business_meaning": "오늘 운영 상태를 한눈에 보는 첫 화면이다. SLA, 알림, 작업 현황을 먼저 확인한다.",
        "first_use": "메인 탭에서 가장 먼저 확인한다.",
    },
    {
        "term": "Inspection",
        "term_ko": "점검",
        "category": "ops",
        "category_ko": "업무",
        "business_meaning": "전기직무고시/소방 등 법정 점검 기록 한 건을 뜻한다.",
        "first_use": "점검 탭에서 설비/위치/결과/조치를 입력할 때 사용한다.",
    },
    {
        "term": "Work Order",
        "term_ko": "작업지시",
        "category": "ops",
        "category_ko": "업무",
        "business_meaning": "이상 사항이나 후속 조치를 담당자에게 배정하는 실행 단위다.",
        "first_use": "점검 이상 항목 발생 시 자동 또는 수동으로 등록한다.",
    },
    {
        "term": "ACK",
        "term_ko": "접수 확인",
        "category": "workflow",
        "category_ko": "상태",
        "business_meaning": "작업지시를 담당자가 수락하고 처리 시작 상태로 넘기는 단계다.",
        "first_use": "작업지시 API 또는 튜토리얼 액션에서 먼저 수행한다.",
    },
    {
        "term": "SLA",
        "term_ko": "처리기준시간",
        "category": "governance",
        "category_ko": "운영관리",
        "business_meaning": "응답/처리 시간이 기준 내에 있는지 판단하는 운영 약속이다.",
        "first_use": "운영요약, W07 품질, 거버넌스 게이트에서 확인한다.",
    },
    {
        "term": "OPS Code",
        "term_ko": "OPS 코드",
        "category": "master-data",
        "category_ko": "기준정보",
        "business_meaning": "설비 또는 점검 분류를 표준화하기 위한 운영 코드다.",
        "first_use": "점검 입력 시 설비코드/분류 자동화에 사용한다.",
    },
    {
        "term": "QR Asset",
        "term_ko": "QR 설비",
        "category": "master-data",
        "category_ko": "기준정보",
        "business_meaning": "QR 태그로 식별되는 설비 마스터 정보다.",
        "first_use": "점검 입력 화면에서 설비/위치/기본 항목 자동 채움에 사용한다.",
    },
    {
        "term": "Evidence",
        "term_ko": "증빙",
        "category": "compliance",
        "category_ko": "컴플라이언스",
        "business_meaning": "사진, 파일, 메모 등 점검/완료 사실을 입증하는 자료다.",
        "first_use": "점검 저장 후 파일 업로드나 트래커 증빙 첨부에서 사용한다.",
    },
    {
        "term": "Audit Log",
        "term_ko": "감사로그",
        "category": "compliance",
        "category_ko": "컴플라이언스",
        "business_meaning": "누가 언제 무엇을 변경했는지 남기는 추적 기록이다.",
        "first_use": "권한관리 탭에서 조회하고 월간 아카이브로 내려받는다.",
    },
    {
        "term": "Runbook",
        "term_ko": "운영 런북",
        "category": "governance",
        "category_ko": "운영관리",
        "business_meaning": "장애, 경고, 배포 점검을 반복 가능하게 문서화한 운영 절차다.",
        "first_use": "runbook check와 governance gate 결과 해석에 사용한다.",
    },
]

POST_MVP_PLAN_START = date(2026, 6, 1)
POST_MVP_PLAN_END = date(2026, 11, 27)

POST_MVP_ROADMAP_PHASES: list[dict[str, Any]] = [
    {
        "phase": "Phase 1 - Stabilize",
        "start_date": "2026-05-25",
        "end_date": "2026-06-19",
        "duration_weeks": 4,
        "objective": "Production hardening and operational baseline.",
        "outcomes": [
            "P95 API latency baseline and alert thresholds configured.",
            "Failure drill playbook validated with on-call rotation.",
            "Top 20 operational support issues converted to runbooks.",
        ],
        "release_gate": "R1 Operations Stability",
    },
    {
        "phase": "Phase 2 - Automate",
        "start_date": "2026-06-22",
        "end_date": "2026-08-07",
        "duration_weeks": 7,
        "objective": "Automation depth for SLA, reporting, and alert handling.",
        "outcomes": [
            "SLA assistant suggestions shipped for priority and due time.",
            "Monthly report automation with approval checklist in one flow.",
            "Retry and escalation jobs running with incident-safe guardrails.",
        ],
        "release_gate": "R2 Automation Pack",
    },
    {
        "phase": "Phase 3 - Scale",
        "start_date": "2026-08-10",
        "end_date": "2026-10-02",
        "duration_weeks": 8,
        "objective": "Multi-site scale, integrations, and governance.",
        "outcomes": [
            "Site template onboarding flow reduced to under 30 minutes.",
            "External integrations for ERP/BI delivered with audit trail.",
            "RBAC policy governance dashboard adopted by site owners.",
        ],
        "release_gate": "R3 Scale and Integration",
    },
    {
        "phase": "Phase 4 - Optimize",
        "start_date": "2026-10-05",
        "end_date": "2026-11-27",
        "duration_weeks": 8,
        "objective": "Business optimization and expansion readiness.",
        "outcomes": [
            "Cross-site benchmarking with KPI league table.",
            "Operational cost-to-close metric tracked and improved.",
            "Next-year expansion plan and staffing model finalized.",
        ],
        "release_gate": "R4 Optimization and FY Plan",
    },
]

POST_MVP_EXECUTION_BACKLOG: list[dict[str, Any]] = [
    {
        "id": "PMVP-01",
        "epic": "Reliability",
        "item": "Implement API latency/error budget dashboard",
        "priority": "P0",
        "owner": "Backend Lead",
        "estimate_points": 8,
        "target_release": "R1",
        "status": "ready",
        "success_kpi": "P95 API latency <= 450ms",
    },
    {
        "id": "PMVP-02",
        "epic": "Reliability",
        "item": "Add incident drill scenario runner and scorecard",
        "priority": "P0",
        "owner": "SRE",
        "estimate_points": 5,
        "target_release": "R1",
        "status": "ready",
        "success_kpi": "Monthly drill pass rate >= 90%",
    },
    {
        "id": "PMVP-03",
        "epic": "Automation",
        "item": "SLA due-time recommendation API and explainability log",
        "priority": "P1",
        "owner": "Backend Lead",
        "estimate_points": 8,
        "target_release": "R2",
        "status": "planned",
        "success_kpi": "Manual due-time overrides down >= 25%",
    },
    {
        "id": "PMVP-04",
        "epic": "Automation",
        "item": "One-click monthly package (JSON+CSV+PDF+approval note)",
        "priority": "P1",
        "owner": "Ops PM",
        "estimate_points": 5,
        "target_release": "R2",
        "status": "planned",
        "success_kpi": "Report preparation time down >= 40%",
    },
    {
        "id": "PMVP-05",
        "epic": "Automation",
        "item": "Escalation job anomaly detector with safe-stop switch",
        "priority": "P1",
        "owner": "SRE",
        "estimate_points": 5,
        "target_release": "R2",
        "status": "planned",
        "success_kpi": "False escalation rate <= 1%",
    },
    {
        "id": "PMVP-06",
        "epic": "Scale",
        "item": "Site onboarding template wizard",
        "priority": "P1",
        "owner": "Product",
        "estimate_points": 8,
        "target_release": "R3",
        "status": "planned",
        "success_kpi": "New site setup <= 30 minutes",
    },
    {
        "id": "PMVP-07",
        "epic": "Scale",
        "item": "ERP/BI outbound webhook connector",
        "priority": "P2",
        "owner": "Integrations",
        "estimate_points": 8,
        "target_release": "R3",
        "status": "planned",
        "success_kpi": "Data sync success rate >= 99%",
    },
    {
        "id": "PMVP-08",
        "epic": "Scale",
        "item": "Policy governance board (site-by-site RBAC drift)",
        "priority": "P1",
        "owner": "Security",
        "estimate_points": 5,
        "target_release": "R3",
        "status": "planned",
        "success_kpi": "Policy drift unresolved >7d count = 0",
    },
    {
        "id": "PMVP-09",
        "epic": "Optimization",
        "item": "Cross-site benchmark dashboard",
        "priority": "P2",
        "owner": "Data Analyst",
        "estimate_points": 5,
        "target_release": "R4",
        "status": "planned",
        "success_kpi": "Monthly benchmark review held 100%",
    },
    {
        "id": "PMVP-10",
        "epic": "Optimization",
        "item": "Cost-to-close per work-order analytics",
        "priority": "P2",
        "owner": "Finance Ops",
        "estimate_points": 5,
        "target_release": "R4",
        "status": "planned",
        "success_kpi": "Cost-to-close reduced >= 10%",
    },
    {
        "id": "PMVP-11",
        "epic": "Optimization",
        "item": "Executive expansion readiness pack automation",
        "priority": "P2",
        "owner": "Program Manager",
        "estimate_points": 3,
        "target_release": "R4",
        "status": "planned",
        "success_kpi": "Quarter planning prep time <= 2 days",
    },
    {
        "id": "PMVP-12",
        "epic": "Platform",
        "item": "Public changelog and release-note API",
        "priority": "P3",
        "owner": "Developer Experience",
        "estimate_points": 3,
        "target_release": "R4",
        "status": "backlog",
        "success_kpi": "Release notes published within 24h",
    },
]

POST_MVP_RELEASE_MILESTONES: list[dict[str, str]] = [
    {
        "release": "R1",
        "name": "Operations Stability",
        "date": "2026-06-19",
        "owner": "Backend Lead + SRE",
        "goal": "Reliability baseline and incident drill readiness",
    },
    {
        "release": "R1.5",
        "name": "Stability Retrospective",
        "date": "2026-07-03",
        "owner": "Ops PM",
        "goal": "Assess error budget and support load delta",
    },
    {
        "release": "R2",
        "name": "Automation Pack",
        "date": "2026-08-07",
        "owner": "Ops PM + Backend Lead",
        "goal": "Automated reporting and escalation quality controls",
    },
    {
        "release": "R2.5",
        "name": "Automation Adoption Check",
        "date": "2026-08-28",
        "owner": "Training Lead",
        "goal": "Verify workflow adoption and issue burn-down",
    },
    {
        "release": "R3",
        "name": "Scale and Integration",
        "date": "2026-10-02",
        "owner": "Product + Integrations",
        "goal": "Multi-site onboarding and integration reliability",
    },
    {
        "release": "R3.5",
        "name": "Scale Risk Review",
        "date": "2026-10-23",
        "owner": "Program Manager",
        "goal": "Close top scaling risks before optimization phase",
    },
    {
        "release": "R4",
        "name": "Optimization and FY Plan",
        "date": "2026-11-27",
        "owner": "Executive Sponsor",
        "goal": "KPI optimization and next-year expansion readiness",
    },
]

POST_MVP_KPI_DASHBOARD_SPEC: list[dict[str, str]] = [
    {
        "id": "OPS-01",
        "name": "SLA On-Time Completion",
        "formula": "completed_within_due / total_completed",
        "target": ">= 95%",
        "data_source": "work_orders",
        "cadence": "weekly",
        "owner": "Ops Lead",
        "alert_rule": "< 92% for 2 consecutive weeks",
    },
    {
        "id": "OPS-02",
        "name": "Median Time-To-First-Action",
        "formula": "median(first_ack_at - created_at)",
        "target": "<= 20 min",
        "data_source": "work_orders + work_order_events",
        "cadence": "weekly",
        "owner": "Site Managers",
        "alert_rule": "> 30 min in any week",
    },
    {
        "id": "OPS-03",
        "name": "Escalation Accuracy",
        "formula": "valid_escalations / total_escalations",
        "target": ">= 99%",
        "data_source": "job_runs + work_order_events",
        "cadence": "weekly",
        "owner": "SRE",
        "alert_rule": "< 98% in a week",
    },
    {
        "id": "OPS-04",
        "name": "Alert Delivery Success",
        "formula": "delivered / attempted",
        "target": ">= 99.5%",
        "data_source": "alert_deliveries",
        "cadence": "daily",
        "owner": "SRE",
        "alert_rule": "< 99.0% in 24h",
    },
    {
        "id": "OPS-05",
        "name": "Report On-Time Rate",
        "formula": "reports_submitted_on_time / reports_expected",
        "target": ">= 98%",
        "data_source": "monthly_reports",
        "cadence": "monthly",
        "owner": "Auditor",
        "alert_rule": "< 95% in month close",
    },
    {
        "id": "OPS-06",
        "name": "New Site Setup Time",
        "formula": "median(site_ready_at - site_request_at)",
        "target": "<= 30 min",
        "data_source": "admin_audit_logs",
        "cadence": "monthly",
        "owner": "Product Ops",
        "alert_rule": "> 45 min median",
    },
    {
        "id": "OPS-07",
        "name": "Policy Drift Aging",
        "formula": "count(drift_items_age_days > 7)",
        "target": "= 0",
        "data_source": "sla_policies + admin_audit_logs",
        "cadence": "weekly",
        "owner": "Security",
        "alert_rule": "> 0 for 2 weeks",
    },
    {
        "id": "OPS-08",
        "name": "Cost-To-Close",
        "formula": "sum(work_order_cost) / closed_work_orders",
        "target": "-10% QoQ",
        "data_source": "work_orders + finance export",
        "cadence": "monthly",
        "owner": "Finance Ops",
        "alert_rule": "No improvement for 2 months",
    },
]

POST_MVP_RISK_REGISTER: list[dict[str, str]] = [
    {
        "id": "RISK-01",
        "title": "Escalation noise from incorrect due-time policies",
        "probability": "medium",
        "impact": "high",
        "signal": "Escalation volume spikes > 2x baseline",
        "mitigation": "Approve policy changes only via proposal flow + simulation",
        "owner": "Ops Lead",
        "status": "open",
        "review_cycle": "weekly",
    },
    {
        "id": "RISK-02",
        "title": "Webhook reliability degradation",
        "probability": "medium",
        "impact": "high",
        "signal": "Alert delivery success < 99%",
        "mitigation": "Multi-endpoint fallback + retry batch + timeout tuning",
        "owner": "SRE",
        "status": "open",
        "review_cycle": "weekly",
    },
    {
        "id": "RISK-03",
        "title": "RBAC scope misconfiguration during scale-out",
        "probability": "medium",
        "impact": "high",
        "signal": "Unauthorized attempts increase on new sites",
        "mitigation": "Template-based site scope + monthly RBAC audit",
        "owner": "Security",
        "status": "open",
        "review_cycle": "bi-weekly",
    },
    {
        "id": "RISK-04",
        "title": "Slow report close due to manual handoffs",
        "probability": "medium",
        "impact": "medium",
        "signal": "Monthly report on-time rate < 95%",
        "mitigation": "One-click package and checklist automation",
        "owner": "Auditor",
        "status": "open",
        "review_cycle": "monthly",
    },
    {
        "id": "RISK-05",
        "title": "Data schema drift across integrations",
        "probability": "low",
        "impact": "high",
        "signal": "Integration sync errors above threshold",
        "mitigation": "Contract versioning + replay queue for failed payloads",
        "owner": "Integrations",
        "status": "monitoring",
        "review_cycle": "weekly",
    },
    {
        "id": "RISK-06",
        "title": "Adoption regression after initial launch wave",
        "probability": "medium",
        "impact": "medium",
        "signal": "Weekly active users drop > 15%",
        "mitigation": "Champion clinics + targeted mission campaigns",
        "owner": "Training Lead",
        "status": "open",
        "review_cycle": "weekly",
    },
    {
        "id": "RISK-07",
        "title": "Single-owner bottleneck for policy approvals",
        "probability": "low",
        "impact": "medium",
        "signal": "Proposal pending age > 3 business days",
        "mitigation": "Define backup approver rotation",
        "owner": "Program Manager",
        "status": "open",
        "review_cycle": "bi-weekly",
    },
    {
        "id": "RISK-08",
        "title": "Cost metrics unavailable from source systems",
        "probability": "medium",
        "impact": "medium",
        "signal": "Cost-to-close KPI missing for month close",
        "mitigation": "Interim manual import and source contract enforcement",
        "owner": "Finance Ops",
        "status": "open",
        "review_cycle": "monthly",
    },
]


@asynccontextmanager
async def app_lifespan(_: FastAPI) -> AsyncIterator[None]:
    ensure_database()
    _ensure_evidence_storage_ready()
    ensure_legacy_admin_token_seed()
    _init_rate_limit_backend()
    preflight = _refresh_startup_preflight_snapshot()
    if bool(preflight.get("has_error")) and PREFLIGHT_FAIL_ON_ERROR:
        blocking_checks = [
            str(item.get("id") or "unknown")
            for item in preflight.get("checks", [])
            if item.get("status") == "error"
        ]
        detail = ", ".join(blocking_checks) if blocking_checks else "unknown"
        raise RuntimeError(f"Startup preflight failed with blocking errors: {detail}")
    yield


app = FastAPI(
    title="KA Facility OS",
    description="Inspection MVP for apartment facility operations",
    version="0.32.0",
    lifespan=app_lifespan,
)


def _build_browser_json_view_html(path_label: str, raw_href: str, status_code: int, payload: Any) -> str:
    payload_text = json.dumps(payload, ensure_ascii=False, indent=2) if payload is not None else "null"
    return f"""
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>KA Facility OS - API 브라우저 보기</title>
  <style>
    :root {{
      --ink: #0f2139;
      --muted: #4b6282;
      --line: #d5e0ee;
      --bg: #f3f8ff;
      --card: #fff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      font-family: "SUIT", "Pretendard", "IBM Plex Sans KR", "Noto Sans KR", sans-serif;
      background:
        radial-gradient(780px 300px at 8% -20%, #e1f6ff 0%, transparent 58%),
        radial-gradient(700px 300px at 95% -20%, #ffedd8 0%, transparent 58%),
        var(--bg);
    }}
    .wrap {{ max-width: 980px; margin: 0 auto; padding: 18px 14px 42px; }}
    .hero {{
      border: 1px solid var(--line);
      border-radius: 14px;
      background: linear-gradient(145deg, #fff 0%, #eef7f5 52%, #fff4e8 100%);
      padding: 14px;
      box-shadow: 0 10px 22px rgba(15, 34, 60, 0.08);
    }}
    .hero h1 {{ margin: 0; font-size: 22px; }}
    .hero p {{ margin: 8px 0 0; color: var(--muted); font-size: 13px; }}
    .meta {{
      margin-top: 10px;
      border: 1px solid #c9d9ec;
      background: #f2f8ff;
      border-radius: 10px;
      padding: 9px;
      font-size: 12px;
      color: #24496f;
    }}
    .links {{
      margin-top: 10px;
      display: flex;
      flex-wrap: wrap;
      gap: 7px;
    }}
    .links a {{
      text-decoration: none;
      border: 1px solid #b8cee8;
      border-radius: 999px;
      padding: 6px 10px;
      font-size: 12px;
      font-weight: 700;
      color: #22507f;
      background: #f3f8ff;
    }}
    pre {{
      margin: 12px 0 0;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: var(--card);
      padding: 12px;
      max-height: 68vh;
      overflow: auto;
      font-family: "Consolas", "D2Coding", "IBM Plex Mono", monospace;
      font-size: 12px;
      line-height: 1.45;
      white-space: pre-wrap;
      word-break: break-word;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>API 브라우저 보기</h1>
      <p>브라우저 접속 시 JSON 원문 대신 사람이 읽기 쉬운 HTML 보기입니다.</p>
      <div class="meta">
        Path: {html.escape(path_label)} | HTTP: {status_code}
      </div>
      <div class="links">
        <a href="/">공개 메인</a>
        <a href="/web/console">운영 콘솔</a>
        <a href="{html.escape(raw_href)}">원본 JSON</a>
      </div>
      <pre>{html.escape(payload_text)}</pre>
    </section>
  </div>
</body>
</html>
"""


def _init_rate_limit_backend() -> None:
    global _RATE_LIMIT_REDIS
    _RATE_LIMIT_REDIS = None
    if API_RATE_LIMIT_STORE not in {"redis", "auto"}:
        return
    if not API_RATE_LIMIT_REDIS_URL:
        return
    if Redis is None:
        return
    try:
        client = Redis.from_url(
            API_RATE_LIMIT_REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
        )
        client.ping()
        _RATE_LIMIT_REDIS = client
    except Exception:
        _RATE_LIMIT_REDIS = None


def _ops_service_module() -> Any:
    from app.domains.ops import service as _service

    _service.bind(globals())
    return _service


def _ops_remediation_service_module() -> Any:
    from app.domains.ops import remediation_service as _remediation_service

    _remediation_service.bind(globals())
    return _remediation_service


def _ops_inspection_service_module() -> Any:
    from app.domains.ops import inspection_service as _inspection_service

    _inspection_service.bind(globals())
    return _inspection_service


def _ops_workflow_service_module() -> Any:
    from app.domains.ops import workflow_service as _workflow_service

    _workflow_service.bind(globals())
    return _workflow_service


def _adoption_tracker_service_module() -> Any:
    from app.domains.adoption import tracker_service as _tracker_service

    _tracker_service.bind(globals())
    return _tracker_service


def _rate_limit_backend_snapshot() -> dict[str, Any]:
    return _ops_service_module()._rate_limit_backend_snapshot()


def _audit_signing_snapshot() -> dict[str, Any]:
    return _ops_service_module()._audit_signing_snapshot()


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


API_LATENCY_TARGETS: list[dict[str, str]] = _parse_api_latency_targets(API_LATENCY_TARGETS_RAW)
_API_LATENCY_TARGET_KEYS = {entry["key"] for entry in API_LATENCY_TARGETS}


def _record_api_latency_sample(
    *,
    method: str,
    path: str,
    duration_ms: float,
    status_code: int | None,
    is_error: bool,
) -> None:
    if not API_LATENCY_MONITOR_ENABLED:
        return
    key = f"{method.upper()} {path}"
    if key not in _API_LATENCY_TARGET_KEYS:
        return
    bounded_duration = max(0.0, float(duration_ms))
    max_samples = max(20, API_LATENCY_MONITOR_WINDOW)
    sampled_at = datetime.now(timezone.utc)
    now_iso = sampled_at.isoformat()
    with _API_LATENCY_LOCK:
        bucket = _API_LATENCY_SAMPLES.get(key)
        if bucket is None:
            bucket = deque(maxlen=max_samples)
            _API_LATENCY_SAMPLES[key] = bucket
        elif bucket.maxlen != max_samples:
            bucket = deque(bucket, maxlen=max_samples)
            _API_LATENCY_SAMPLES[key] = bucket
        bucket.append(bounded_duration)
        _API_LATENCY_LAST_SEEN_AT[key] = now_iso
    _persist_api_latency_sample(
        endpoint_key=key,
        method=method.upper(),
        path=path,
        duration_ms=bounded_duration,
        status_code=status_code,
        is_error=is_error,
        sampled_at=sampled_at,
    )


def _persist_api_latency_sample(
    *,
    endpoint_key: str,
    method: str,
    path: str,
    duration_ms: float,
    status_code: int | None,
    is_error: bool,
    sampled_at: datetime,
) -> None:
    if not API_LATENCY_PERSIST_ENABLED:
        return
    global _API_LATENCY_PERSIST_WRITE_COUNT
    try:
        with get_conn() as conn:
            conn.execute(
                insert(api_latency_samples).values(
                    endpoint_key=endpoint_key,
                    method=method[:10],
                    path=path[:240],
                    duration_ms=max(0.0, float(duration_ms)),
                    status_code=status_code,
                    is_error=bool(is_error),
                    sampled_at=sampled_at,
                )
            )
            _API_LATENCY_PERSIST_WRITE_COUNT += 1
            if _API_LATENCY_PERSIST_WRITE_COUNT % API_LATENCY_PERSIST_PRUNE_INTERVAL == 0:
                cutoff = sampled_at - timedelta(days=API_LATENCY_PERSIST_RETENTION_DAYS)
                conn.execute(delete(api_latency_samples).where(api_latency_samples.c.sampled_at < cutoff))
    except SQLAlchemyError:
        # Keep request path resilient even if latency persistence is temporarily unavailable.
        return


def _build_api_latency_snapshot() -> dict[str, Any]:
    return _ops_service_module()._build_api_latency_snapshot()


def _build_evidence_archive_integrity_batch(
    *,
    sample_per_table: int | None = None,
    max_issues: int | None = None,
) -> dict[str, Any]:
    return _ops_service_module()._build_evidence_archive_integrity_batch(
        sample_per_table=sample_per_table,
        max_issues=max_issues,
    )


def _next_month_boundary(dt: datetime) -> datetime:
    return _ops_service_module()._next_month_boundary(dt)


def _month_window_bounds(*, now: datetime | None = None, month_label: str | None = None) -> tuple[str, datetime, datetime]:
    return _ops_service_module()._month_window_bounds(now=now, month_label=month_label)


def _build_deploy_checklist_steps(
    *,
    rollback_guide_path: Path,
    rollback_guide_exists: bool,
    rollback_guide_sha256: str | None,
) -> list[dict[str, Any]]:
    return _ops_service_module()._build_deploy_checklist_steps(
        rollback_guide_path=rollback_guide_path,
        rollback_guide_exists=rollback_guide_exists,
        rollback_guide_sha256=rollback_guide_sha256,
    )


def _build_deploy_checklist_policy(
    *,
    rollback_guide_path: Path,
    rollback_guide_exists: bool,
    rollback_guide_sha256: str | None,
) -> dict[str, Any]:
    return _ops_service_module()._build_deploy_checklist_policy(
        rollback_guide_path=rollback_guide_path,
        rollback_guide_exists=rollback_guide_exists,
        rollback_guide_sha256=rollback_guide_sha256,
    )


def _build_deploy_checklist_signature(*, policy: dict[str, Any], steps: list[dict[str, Any]]) -> str:
    return _ops_service_module()._build_deploy_checklist_signature(policy=policy, steps=steps)


def _parse_deploy_checklist_revision(version: str, *, prefix: str) -> int | None:
    return _ops_service_module()._parse_deploy_checklist_revision(version, prefix=prefix)


def _derive_deploy_checklist_version(*, signature: str, generated_at: datetime) -> tuple[str, str]:
    return _ops_service_module()._derive_deploy_checklist_version(signature=signature, generated_at=generated_at)


def _build_deploy_checklist_payload() -> dict[str, Any]:
    return _ops_service_module()._build_deploy_checklist_payload()


def _week_start_utc(dt: datetime) -> datetime:
    return _ops_service_module()._week_start_utc(dt)


def _startup_path_writable(path_value: str) -> tuple[bool, str]:
    return _ops_service_module()._startup_path_writable(path_value)


def _run_startup_preflight_snapshot() -> dict[str, Any]:
    return _ops_service_module()._run_startup_preflight_snapshot()


def _refresh_startup_preflight_snapshot() -> dict[str, Any]:
    return _ops_service_module()._refresh_startup_preflight_snapshot()


def _get_startup_preflight_snapshot(*, refresh: bool = False) -> dict[str, Any]:
    return _ops_service_module()._get_startup_preflight_snapshot(refresh=refresh)


def _build_alert_noise_policy_snapshot() -> dict[str, Any]:
    return _ops_service_module()._build_alert_noise_policy_snapshot()


def _build_admin_security_dashboard_snapshot(*, days: int = 30) -> dict[str, Any]:
    return _ops_service_module()._build_admin_security_dashboard_snapshot(days=days)


def _build_ops_quality_job_summary(*, start: datetime, end: datetime) -> dict[str, Any]:
    return _ops_service_module()._build_ops_quality_job_summary(start=start, end=end)


def _build_ops_quality_report_payload(*, window: str, start: datetime, end: datetime, label: str) -> dict[str, Any]:
    return _ops_service_module()._build_ops_quality_report_payload(window=window, start=start, end=end, label=label)


def _build_ops_quality_report_csv(payload: dict[str, Any]) -> str:
    return _ops_service_module()._build_ops_quality_report_csv(payload)


def _prune_ops_quality_report_archive_files(*, archive_dir: Path, now: datetime) -> int:
    return _ops_service_module()._prune_ops_quality_report_archive_files(archive_dir=archive_dir, now=now)


def _publish_ops_quality_report_artifacts(
    *,
    payload: dict[str, Any],
    window: str,
    finished_at: datetime,
) -> dict[str, Any]:
    return _ops_service_module()._publish_ops_quality_report_artifacts(
        payload=payload,
        window=window,
        finished_at=finished_at,
    )


def _build_ops_quality_weekly_streak_snapshot(*, now: datetime | None = None) -> dict[str, Any]:
    return _ops_service_module()._build_ops_quality_weekly_streak_snapshot(now=now)


def run_ops_quality_report_job(
    *,
    window: str = "weekly",
    month: str | None = None,
    trigger: str = "manual",
) -> dict[str, Any]:
    return _ops_service_module().run_ops_quality_report_job(window=window, month=month, trigger=trigger)


def run_dr_rehearsal_job(
    *,
    trigger: str = "manual",
    simulate_restore: bool = True,
) -> dict[str, Any]:
    return _ops_service_module().run_dr_rehearsal_job(trigger=trigger, simulate_restore=simulate_restore)


def _latest_dr_rehearsal_payload() -> dict[str, Any] | None:
    return _ops_service_module()._latest_dr_rehearsal_payload()


def _normalize_governance_risk_level(value: Any) -> str:
    return _ops_service_module()._normalize_governance_risk_level(value)


def _governance_risk_rank(value: str) -> int:
    return _ops_service_module()._governance_risk_rank(value)


def _build_ops_governance_gate_snapshot(*, now: datetime | None = None) -> dict[str, Any]:
    return _ops_service_module()._build_ops_governance_gate_snapshot(now=now)


def run_ops_governance_gate_job(*, trigger: str = "manual") -> dict[str, Any]:
    return _ops_service_module().run_ops_governance_gate_job(trigger=trigger)


def _latest_ops_governance_gate_payload() -> dict[str, Any] | None:
    return _ops_service_module()._latest_ops_governance_gate_payload()


def _governance_remediation_owner_and_sla(rule_id: str) -> tuple[str, int]:
    return _ops_service_module()._governance_remediation_owner_and_sla(rule_id)


def _governance_remediation_action(rule_id: str, default_message: str) -> str:
    return _ops_service_module()._governance_remediation_action(rule_id, default_message)


def _governance_rule_priority(rule_status: str, required: bool) -> int:
    return _ops_service_module()._governance_rule_priority(rule_status, required)


def _build_ops_governance_remediation_plan(
    *,
    snapshot: dict[str, Any],
    include_warnings: bool = True,
    max_items: int = OPS_GOVERNANCE_REMEDIATION_DEFAULT_MAX_ITEMS,
) -> dict[str, Any]:
    return _ops_service_module()._build_ops_governance_remediation_plan(
        snapshot=snapshot,
        include_warnings=include_warnings,
        max_items=max_items,
    )


def _build_ops_governance_remediation_csv(plan: dict[str, Any]) -> str:
    return _ops_service_module()._build_ops_governance_remediation_csv(plan)


def _normalize_w21_tracker_status(raw: Any) -> str:
    return _ops_remediation_service_module()._normalize_w21_tracker_status(
        raw,
    )
def _resolve_w21_completion_status(raw: Any) -> str:
    return _ops_remediation_service_module()._resolve_w21_completion_status(
        raw,
    )
def _row_to_w21_remediation_item_model(row: dict[str, Any]) -> W21RemediationTrackerItemRead:
    return _ops_remediation_service_module()._row_to_w21_remediation_item_model(
        row,
    )
def _load_w21_remediation_items(*, include_inactive: bool = False) -> list[W21RemediationTrackerItemRead]:
    return _ops_remediation_service_module()._load_w21_remediation_items(
        include_inactive=include_inactive,
    )
def _compute_w21_remediation_overview(
    *,
    active_rows: list[W21RemediationTrackerItemRead],
    active_count: int,
    closed_count: int,
    checked_at: datetime | None = None,
) -> W21RemediationTrackerOverviewRead:
    return _ops_remediation_service_module()._compute_w21_remediation_overview(
        active_rows=active_rows,
        active_count=active_count,
        closed_count=closed_count,
        checked_at=checked_at,
    )
def _compute_w21_remediation_readiness(
    *,
    active_rows: list[W21RemediationTrackerItemRead],
    checked_at: datetime | None = None,
) -> W21RemediationTrackerReadinessRead:
    return _ops_remediation_service_module()._compute_w21_remediation_readiness(
        active_rows=active_rows,
        checked_at=checked_at,
    )
def _row_to_w21_completion_model(
    *,
    readiness: W21RemediationTrackerReadinessRead,
    row: dict[str, Any] | None,
) -> W21RemediationTrackerCompletionRead:
    return _ops_remediation_service_module()._row_to_w21_completion_model(
        readiness=readiness,
        row=row,
    )
def _reset_w21_completion_if_closed(
    *,
    conn: Any,
    actor_username: str,
    checked_at: datetime,
    reason: str,
) -> None:
    return _ops_remediation_service_module()._reset_w21_completion_if_closed(
        conn=conn,
        actor_username=actor_username,
        checked_at=checked_at,
        reason=reason,
    )
def _sync_w21_remediation_tracker(
    *,
    actor_username: str,
    include_warnings: bool,
    max_items: int,
) -> W21RemediationTrackerSyncResponse:
    return _ops_remediation_service_module()._sync_w21_remediation_tracker(
        actor_username=actor_username,
        include_warnings=include_warnings,
        max_items=max_items,
    )
def _build_w22_remediation_sla_snapshot(
    *,
    due_soon_hours: int = 24,
    now: datetime | None = None,
) -> dict[str, Any]:
    return _ops_remediation_service_module()._build_w22_remediation_sla_snapshot(
        due_soon_hours=due_soon_hours,
        now=now,
    )
def run_ops_governance_remediation_escalation_job(
    *,
    trigger: str = "manual",
    dry_run: bool = False,
    include_due_soon_hours: int | None = None,
    notify_enabled: bool | None = None,
) -> dict[str, Any]:
    return _ops_remediation_service_module().run_ops_governance_remediation_escalation_job(
        trigger=trigger,
        dry_run=dry_run,
        include_due_soon_hours=include_due_soon_hours,
        notify_enabled=notify_enabled,
    )
def _latest_ops_governance_remediation_escalation_payload() -> dict[str, Any] | None:
    return _ops_remediation_service_module()._latest_ops_governance_remediation_escalation_payload()
def _w23_candidate_usernames_by_role() -> dict[str, list[str]]:
    return _ops_remediation_service_module()._w23_candidate_usernames_by_role()
def _w23_choose_assignee(
    *,
    owner_role: str,
    current_loads: dict[str, int],
    by_role: dict[str, list[str]],
) -> tuple[str | None, str]:
    return _ops_remediation_service_module()._w23_choose_assignee(
        owner_role=owner_role,
        current_loads=current_loads,
        by_role=by_role,
    )
def _build_w23_remediation_workload_snapshot(
    *,
    include_inactive: bool = False,
    max_suggestions: int = 20,
) -> dict[str, Any]:
    return _ops_remediation_service_module()._build_w23_remediation_workload_snapshot(
        include_inactive=include_inactive,
        max_suggestions=max_suggestions,
    )
def run_ops_governance_remediation_auto_assign_job(
    *,
    trigger: str = "manual",
    dry_run: bool = False,
    limit: int | None = None,
) -> dict[str, Any]:
    return _ops_remediation_service_module().run_ops_governance_remediation_auto_assign_job(
        trigger=trigger,
        dry_run=dry_run,
        limit=limit,
    )
def _latest_ops_governance_remediation_auto_assign_payload() -> dict[str, Any] | None:
    return _ops_remediation_service_module()._latest_ops_governance_remediation_auto_assign_payload()
def _build_w24_remediation_backlog_history(
    *,
    window_days: int,
    now: datetime,
) -> dict[str, Any]:
    return _ops_remediation_service_module()._build_w24_remediation_backlog_history(
        window_days=window_days,
        now=now,
    )
def _build_w24_remediation_kpi_snapshot(
    *,
    window_days: int = GOVERNANCE_REMEDIATION_KPI_WINDOW_DAYS,
    due_soon_hours: int = GOVERNANCE_REMEDIATION_KPI_DUE_SOON_HOURS,
    now: datetime | None = None,
) -> dict[str, Any]:
    return _ops_remediation_service_module()._build_w24_remediation_kpi_snapshot(
        window_days=window_days,
        due_soon_hours=due_soon_hours,
        now=now,
    )
def run_ops_governance_remediation_kpi_job(
    *,
    trigger: str = "manual",
    window_days: int | None = None,
    due_soon_hours: int | None = None,
) -> dict[str, Any]:
    return _ops_remediation_service_module().run_ops_governance_remediation_kpi_job(
        trigger=trigger,
        window_days=window_days,
        due_soon_hours=due_soon_hours,
    )
def _latest_ops_governance_remediation_kpi_payload() -> dict[str, Any] | None:
    return _ops_remediation_service_module()._latest_ops_governance_remediation_kpi_payload()
def _default_w26_remediation_autopilot_policy() -> dict[str, Any]:
    return _ops_remediation_service_module()._default_w26_remediation_autopilot_policy()
def _build_policy_response_payload(
    *,
    policy_key: str,
    updated_at: datetime,
    policy: dict[str, Any],
    scope: str,
    applies_to: str = "global",
    version: str = "v1",
) -> dict[str, Any]:
    return _ops_remediation_service_module()._build_policy_response_payload(
        policy_key=policy_key,
        updated_at=updated_at,
        policy=policy,
        scope=scope,
        applies_to=applies_to,
        version=version,
    )
def _normalize_w26_remediation_autopilot_policy(value: Any) -> dict[str, Any]:
    return _ops_remediation_service_module()._normalize_w26_remediation_autopilot_policy(
        value,
    )
def _parse_w26_remediation_autopilot_policy_json(raw: Any) -> dict[str, Any]:
    return _ops_remediation_service_module()._parse_w26_remediation_autopilot_policy_json(
        raw,
    )
def _ensure_w26_remediation_autopilot_policy() -> tuple[dict[str, Any], datetime, str]:
    return _ops_remediation_service_module()._ensure_w26_remediation_autopilot_policy()
def _upsert_w26_remediation_autopilot_policy(payload: dict[str, Any]) -> tuple[dict[str, Any], datetime, str]:
    return _ops_remediation_service_module()._upsert_w26_remediation_autopilot_policy(
        payload,
    )
def _evaluate_w26_remediation_autopilot(
    *,
    force: bool,
    policy: dict[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    return _ops_remediation_service_module()._evaluate_w26_remediation_autopilot(
        force=force,
        policy=policy,
        now=now,
    )
def _latest_job_run_for_name(job_name: str) -> JobRunRead | None:
    return _ops_remediation_service_module()._latest_job_run_for_name(
        job_name,
    )
def _build_w27_remediation_autopilot_guard_state(
    *,
    policy: dict[str, Any],
    now: datetime,
    force: bool,
) -> dict[str, Any]:
    return _ops_remediation_service_module()._build_w27_remediation_autopilot_guard_state(
        policy=policy,
        now=now,
        force=force,
    )
def run_ops_governance_remediation_autopilot_job(
    *,
    trigger: str = "manual",
    dry_run: bool = False,
    force: bool = False,
    policy_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _ops_remediation_service_module().run_ops_governance_remediation_autopilot_job(
        trigger=trigger,
        dry_run=dry_run,
        force=force,
        policy_override=policy_override,
    )
def _latest_ops_governance_remediation_autopilot_payload() -> dict[str, Any] | None:
    return _ops_remediation_service_module()._latest_ops_governance_remediation_autopilot_payload()
def _build_w28_remediation_autopilot_history(*, limit: int = 20) -> dict[str, Any]:
    return _ops_remediation_service_module()._build_w28_remediation_autopilot_history(
        limit=limit,
    )
def _build_w28_remediation_autopilot_summary(*, days: int = 7) -> dict[str, Any]:
    return _ops_remediation_service_module()._build_w28_remediation_autopilot_summary(
        days=days,
    )
def _build_w29_remediation_autopilot_history_csv(payload: dict[str, Any]) -> str:
    return _ops_remediation_service_module()._build_w29_remediation_autopilot_history_csv(
        payload,
    )
def _build_w29_remediation_autopilot_summary_csv(payload: dict[str, Any]) -> str:
    return _ops_remediation_service_module()._build_w29_remediation_autopilot_summary_csv(
        payload,
    )
def _build_w30_remediation_autopilot_anomalies(*, days: int = 14) -> dict[str, Any]:
    return _ops_remediation_service_module()._build_w30_remediation_autopilot_anomalies(
        days=days,
    )
def _build_w30_remediation_autopilot_anomalies_csv(payload: dict[str, Any]) -> str:
    return _ops_remediation_service_module()._build_w30_remediation_autopilot_anomalies_csv(
        payload,
    )


def _rate_limit_identity(request: Request) -> tuple[str, bool]:
    token = request.headers.get("x-admin-token", "").strip()
    if token:
        # Token hash prefix avoids storing raw secrets in keys/metrics.
        return f"auth:{_hash_token(token)[:16]}", True
    client_host = request.client.host if request.client is not None else "unknown"
    return f"ip:{client_host}", False


def _rate_limit_policy_for_request(request: Request, *, is_auth: bool) -> tuple[str, int]:
    path = request.url.path
    method = request.method.upper()
    if is_auth:
        if method == "GET" and (
            path.endswith("/completion-package")
            or path.endswith("/archive.csv")
            or path.endswith("/download")
        ):
            return "auth-heavy", API_RATE_LIMIT_MAX_AUTH_HEAVY
        if method == "POST" and (
            ("/api/adoption/w02/tracker/items/" in path and path.endswith("/evidence"))
            or ("/api/adoption/w03/tracker/items/" in path and path.endswith("/evidence"))
            or ("/api/adoption/w04/tracker/items/" in path and path.endswith("/evidence"))
            or ("/api/adoption/w07/tracker/items/" in path and path.endswith("/evidence"))
            or ("/api/adoption/w09/tracker/items/" in path and path.endswith("/evidence"))
            or ("/api/inspections/" in path and path.endswith("/evidence"))
        ):
            return "auth-upload", API_RATE_LIMIT_MAX_AUTH_UPLOAD
        if path.startswith("/api/admin/"):
            return "auth-admin", API_RATE_LIMIT_MAX_AUTH_ADMIN
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            return "auth-write", API_RATE_LIMIT_MAX_AUTH_WRITE
        return "auth-read", API_RATE_LIMIT_MAX_AUTH
    if path.endswith("/csv") or path.endswith("/pdf") or path.endswith("/ics"):
        return "public-heavy", API_RATE_LIMIT_MAX_PUBLIC_HEAVY
    return "public-read", API_RATE_LIMIT_MAX_PUBLIC


def _check_api_rate_limit_memory(*, key: str, max_requests: int, window_sec: int) -> tuple[bool, int, int]:
    now = time.monotonic()
    with _RATE_LIMIT_LOCK:
        bucket = _RATE_LIMIT_BUCKETS.get(key)
        if bucket is None:
            bucket = deque()
            _RATE_LIMIT_BUCKETS[key] = bucket

        cutoff = now - float(window_sec)
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if len(bucket) >= max_requests:
            wait = max(1, int(math.ceil(float(window_sec) - (now - bucket[0]))))
            return False, 0, wait

        bucket.append(now)
        remaining = max(0, max_requests - len(bucket))
        reset = max(1, int(math.ceil(float(window_sec) - (now - bucket[0]))))
        return True, remaining, reset


def _check_api_rate_limit_redis(*, key_base: str, max_requests: int, window_sec: int) -> tuple[bool, int, int] | None:
    if _RATE_LIMIT_REDIS is None:
        return None
    try:
        window_idx = int(time.time() // window_sec)
        redis_key = f"{key_base}:{window_idx}"
        count = int(_RATE_LIMIT_REDIS.incr(redis_key))
        ttl = int(_RATE_LIMIT_REDIS.ttl(redis_key))
        if ttl <= 0:
            _RATE_LIMIT_REDIS.expire(redis_key, window_sec + 1)
            ttl = window_sec
        allowed = count <= max_requests
        remaining = max(0, max_requests - count)
        reset = max(1, ttl)
        return allowed, remaining, reset
    except Exception:
        return None


def _check_api_rate_limit(*, key_base: str, max_requests: int, window_sec: int) -> tuple[bool, int, int, str]:
    backend = "memory"
    if API_RATE_LIMIT_STORE in {"redis", "auto"}:
        redis_result = _check_api_rate_limit_redis(
            key_base=key_base,
            max_requests=max_requests,
            window_sec=window_sec,
        )
        if redis_result is not None:
            allowed, remaining, reset = redis_result
            return allowed, remaining, reset, "redis"
    allowed, remaining, reset = _check_api_rate_limit_memory(
        key=key_base,
        max_requests=max_requests,
        window_sec=window_sec,
    )
    return allowed, remaining, reset, backend


@app.middleware("http")
async def browser_json_to_html_middleware(request: Request, call_next: Callable[[Request], Any]) -> Any:
    response = await call_next(request)
    if request.method != "GET":
        return response
    if request.query_params.get("raw") == "1":
        return response
    if not request.url.path.startswith("/api/"):
        return response

    accept = request.headers.get("accept", "").lower()
    if "text/html" not in accept:
        return response

    content_type = response.headers.get("content-type", "").lower()
    if not content_type.startswith("application/json"):
        return response

    body = b""
    async for chunk in response.body_iterator:
        body += chunk

    payload: Any
    if body:
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            payload = body.decode("utf-8", errors="replace")
    else:
        payload = None

    path_label = request.url.path
    raw_href = f"{request.url.path}?raw=1"
    if request.url.query:
        path_label = f"{request.url.path}?{request.url.query}"
        raw_href = f"{request.url.path}?{request.url.query}&raw=1"

    return HTMLResponse(_build_browser_json_view_html(path_label, raw_href, response.status_code, payload), status_code=response.status_code)


@app.middleware("http")
async def api_rate_limit_middleware(request: Request, call_next: Callable[[Request], Any]) -> Any:
    if (
        not API_RATE_LIMIT_ENABLED
        or request.method.upper() == "OPTIONS"
        or not request.url.path.startswith("/api/")
    ):
        return await call_next(request)

    identity, is_auth = _rate_limit_identity(request)
    policy_name, limit = _rate_limit_policy_for_request(request, is_auth=is_auth)
    key_base = f"{API_RATE_LIMIT_REDIS_KEY_PREFIX}:{policy_name}:{identity}"
    allowed, remaining, reset_sec, backend = _check_api_rate_limit(
        key_base=key_base,
        max_requests=limit,
        window_sec=API_RATE_LIMIT_WINDOW_SEC,
    )
    headers = {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(max(0, remaining)),
        "X-RateLimit-Reset": str(reset_sec),
        "X-RateLimit-Policy": policy_name,
        "X-RateLimit-Backend": backend,
    }
    if not allowed:
        headers["Retry-After"] = str(reset_sec)
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"},
            headers=headers,
        )

    response = await call_next(request)
    for key, value in headers.items():
        response.headers.setdefault(key, value)
    return response


@app.middleware("http")
async def api_latency_monitor_middleware(request: Request, call_next: Callable[[Request], Any]) -> Any:
    should_track = API_LATENCY_MONITOR_ENABLED and request.method.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"}
    if not should_track:
        return await call_next(request)

    path = request.url.path
    method = request.method.upper()
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        duration_ms = (time.perf_counter() - started) * 1000.0
        _record_api_latency_sample(
            method=method,
            path=path,
            duration_ms=duration_ms,
            status_code=500,
            is_error=True,
        )
        raise

    duration_ms = (time.perf_counter() - started) * 1000.0
    status_code = int(getattr(response, "status_code", 0) or 0)
    _record_api_latency_sample(
        method=method,
        path=path,
        duration_ms=duration_ms,
        status_code=status_code if status_code > 0 else None,
        is_error=status_code >= 500 if status_code > 0 else False,
    )
    response.headers.setdefault("X-Request-Duration-Ms", f"{round(duration_ms, 2)}")
    return response


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next: Callable[[Request], Any]) -> Any:
    response = await call_next(request)

    for key, value in SECURITY_HEADERS_BASE.items():
        response.headers.setdefault(key, value)

    if ENV_NAME == "production" or request.url.scheme.lower() == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

    if request.headers.get("x-admin-token", "").strip() or request.url.path == "/api/auth/login":
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Pragma", "no-cache")

    content_type = response.headers.get("content-type", "").lower()
    path = request.url.path
    if content_type.startswith("text/html") and (path == "/" or path.startswith("/web/") or path.startswith("/api/")):
        response.headers.setdefault("Content-Security-Policy", HTML_CSP_POLICY)

    return response


def _permission_text_to_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [x.strip() for x in value.split(",") if x.strip()]
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return []


def _permission_list_to_text(values: list[str]) -> str:
    normalized = sorted({v.strip() for v in values if v.strip()})
    return ",".join(normalized)


def _site_scope_text_to_list(value: Any, *, default_all: bool = True) -> list[str]:
    if value is None:
        return [SITE_SCOPE_ALL] if default_all else []
    if isinstance(value, str):
        raw_values = [x.strip() for x in value.split(",") if x.strip()]
    elif isinstance(value, list):
        raw_values = [str(x).strip() for x in value if str(x).strip()]
    else:
        raw_values = []

    if not raw_values:
        return [SITE_SCOPE_ALL] if default_all else []
    if SITE_SCOPE_ALL in raw_values:
        return [SITE_SCOPE_ALL]
    return sorted(set(raw_values))


def _site_scope_list_to_text(values: list[str]) -> str:
    normalized = _site_scope_text_to_list(values, default_all=True)
    return ",".join(normalized)


def _resolve_effective_site_scope(
    *,
    user_scope: list[str],
    token_scope: list[str] | None,
) -> list[str]:
    normalized_user_scope = _site_scope_text_to_list(user_scope, default_all=True)
    if token_scope is None:
        return normalized_user_scope

    normalized_token_scope = _site_scope_text_to_list(token_scope, default_all=True)
    if SITE_SCOPE_ALL in normalized_user_scope:
        return normalized_token_scope
    if SITE_SCOPE_ALL in normalized_token_scope:
        return normalized_user_scope

    intersection = sorted(set(normalized_user_scope).intersection(normalized_token_scope))
    return intersection


def _principal_site_scope(principal: dict[str, Any]) -> list[str]:
    raw_scope = principal.get("site_scope", [SITE_SCOPE_ALL])
    return _site_scope_text_to_list(raw_scope, default_all=True)


def _allowed_sites_for_principal(principal: dict[str, Any]) -> list[str] | None:
    scope = _principal_site_scope(principal)
    if SITE_SCOPE_ALL in scope:
        return None
    return scope


def _has_site_access(principal: dict[str, Any], site: str | None) -> bool:
    if site is None:
        return True
    scope = _principal_site_scope(principal)
    if SITE_SCOPE_ALL in scope:
        return True
    return site in scope


def _require_site_access(principal: dict[str, Any], site: str | None) -> None:
    from app.domains.iam.security import _require_site_access as _impl
    return _impl(principal, site)


def _require_global_site_scope(principal: dict[str, Any]) -> None:
    from app.domains.iam.security import _require_global_site_scope as _impl
    return _impl(principal)


def _effective_permissions(role: str, custom: list[str]) -> list[str]:
    from app.domains.iam.security import _effective_permissions as _impl
    return _impl(role, custom)


def _principal_role(principal: dict[str, Any]) -> str:
    from app.domains.iam.security import _principal_role as _impl
    return _impl(principal)


def _require_user_management_access(principal: dict[str, Any]) -> None:
    from app.domains.iam.security import _require_user_management_access as _impl
    return _impl(principal)


def _contains_admin_control_permissions(permissions: list[str]) -> bool:
    from app.domains.iam.security import _contains_admin_control_permissions as _impl
    return _impl(permissions)


def _site_scope_is_subset(scope: list[str], allowed_scope: list[str]) -> bool:
    from app.domains.iam.security import _site_scope_is_subset as _impl
    return _impl(scope, allowed_scope)


def _enforce_manager_user_mutation_guardrails(
    principal: dict[str, Any],
    *,
    next_role: str,
    next_permissions: list[str],
    next_site_scope: list[str],
    target_role: str | None = None,
    target_site_scope: list[str] | None = None,
) -> None:
    from app.domains.iam.security import _enforce_manager_user_mutation_guardrails as _impl
    return _impl(principal, next_role=next_role, next_permissions=next_permissions, next_site_scope=next_site_scope, target_role=target_role, target_site_scope=target_site_scope)


def _count_active_owner_users(conn: Any, *, exclude_user_id: int | None = None) -> int:
    from app.domains.iam.security import _count_active_owner_users as _impl
    return _impl(conn, exclude_user_id=exclude_user_id)


def _hash_token(token: str) -> str:
    from app.domains.iam.security import _hash_token as _impl
    return _impl(token)


def _normalize_admin_username(value: str) -> str:
    from app.domains.iam.security import _normalize_admin_username as _impl
    return _impl(value)


def _validate_admin_password_value(password: str) -> str:
    from app.domains.iam.security import _validate_admin_password_value as _impl
    return _impl(password)


def _b64_url_encode(raw: bytes) -> str:
    from app.domains.iam.security import _b64_url_encode as _impl
    return _impl(raw)


def _b64_url_decode(value: str) -> bytes:
    from app.domains.iam.security import _b64_url_decode as _impl
    return _impl(value)


def _hash_password(password: str) -> str:
    from app.domains.iam.security import _hash_password as _impl
    return _impl(password)


def _verify_password(password: str, encoded_hash: str) -> bool:
    from app.domains.iam.security import _verify_password as _impl
    return _impl(password, encoded_hash)


def _has_active_admin_tokens() -> bool:
    from app.domains.iam.security import _has_active_admin_tokens as _impl
    return _impl()


def ensure_legacy_admin_token_seed() -> None:
    from app.domains.iam.security import ensure_legacy_admin_token_seed as _impl
    return _impl()


def _parse_ops_checklist_notes(note_text: str) -> dict[str, Any] | None:
    text = str(note_text or "")
    if not any(tag in text for tag in OPS_CHECKLIST_NOTE_TAGS):
        return None
    meta: dict[str, Any] = {}
    checklist: list[Any] = []
    memo = ""
    parse_errors: list[str] = []
    for line in text.splitlines():
        if line.startswith("meta="):
            raw = line[5:].strip()
            try:
                parsed = json.loads(raw)
            except Exception:
                parse_errors.append("meta JSON parse failed")
                continue
            if isinstance(parsed, dict):
                meta = parsed
            else:
                parse_errors.append("meta must be a JSON object")
            continue
        if line.startswith("checklist="):
            raw = line[10:].strip()
            try:
                parsed = json.loads(raw)
            except Exception:
                parse_errors.append("checklist JSON parse failed")
                continue
            if isinstance(parsed, list):
                checklist = parsed
            else:
                parse_errors.append("checklist must be a JSON list")
            continue
        if line.startswith("memo="):
            memo = line[5:]
    return {
        "meta": meta,
        "checklist": checklist,
        "memo": memo,
        "parse_errors": parse_errors,
    }


def _priority_rank(priority: str) -> int:
    return WORK_ORDER_PRIORITY_RANK.get(str(priority or "").strip().lower(), WORK_ORDER_PRIORITY_RANK["medium"])


def _higher_priority(left: str, right: str) -> str:
    return left if _priority_rank(left) >= _priority_rank(right) else right


def _extract_ops_abnormal_count(parsed_ops_notes: dict[str, Any] | None) -> int:
    if not parsed_ops_notes:
        return 0
    meta = parsed_ops_notes.get("meta") if isinstance(parsed_ops_notes, dict) else None
    summary = meta.get("summary") if isinstance(meta, dict) else None
    if isinstance(summary, dict):
        try:
            return max(0, int(summary.get("abnormal", 0)))
        except (TypeError, ValueError):
            pass

    checklist_rows = parsed_ops_notes.get("checklist") if isinstance(parsed_ops_notes, dict) else None
    if not isinstance(checklist_rows, list):
        return 0
    abnormal_count = 0
    for row in checklist_rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("result") or "").strip().lower() == "abnormal":
            abnormal_count += 1
    return abnormal_count


def _derive_inspection_work_order_sla_context(inspection_row: dict[str, Any] | None) -> dict[str, Any]:
    if not inspection_row:
        return {
            "priority_floor": "medium",
            "risk_level": "normal",
            "abnormal_count": 0,
            "rules_applied": [],
        }
    risk_level = str(inspection_row.get("risk_level") or "normal").strip().lower()
    priority_floor = INSPECTION_SLA_PRIORITY_BY_RISK.get(risk_level, "medium")
    rules_applied: list[str] = []
    if priority_floor != "medium":
        rules_applied.append(f"risk_level={risk_level}->{priority_floor}")

    parsed_notes = _parse_ops_checklist_notes(str(inspection_row.get("notes") or ""))
    abnormal_count = _extract_ops_abnormal_count(parsed_notes)
    for threshold, target_priority in INSPECTION_SLA_PRIORITY_BY_ABNORMAL:
        if abnormal_count >= threshold:
            next_floor = _higher_priority(priority_floor, target_priority)
            if next_floor != priority_floor:
                rules_applied.append(f"abnormal_count>={threshold}->{target_priority}")
                priority_floor = next_floor
            break

    return {
        "priority_floor": priority_floor,
        "risk_level": risk_level,
        "abnormal_count": abnormal_count,
        "rules_applied": rules_applied,
    }


def _inspection_to_work_order_sla_rule_payload() -> dict[str, Any]:
    return {
        "version": "2026-03-04",
        "applies_when": {
            "inspection_id_provided": True,
            "site_must_match_inspection": True,
        },
        "priority_floor_by_risk_level": INSPECTION_SLA_PRIORITY_BY_RISK,
        "priority_floor_by_abnormal_count": [
            {"min_abnormal_count": threshold, "priority_floor": priority}
            for threshold, priority in INSPECTION_SLA_PRIORITY_BY_ABNORMAL
        ],
        "due_at_policy": {
            "manual_due_at_respected": True,
            "auto_due_at_if_missing": True,
            "auto_due_hours_source": "sla_policy.default_due_hours[effective_priority]",
        },
    }


def _qr_asset_placeholder_flags(row: dict[str, Any]) -> list[str]:
    flags: list[str] = []
    equipment = str(row.get("equipment") or "").strip()
    location = str(row.get("location") or "").strip()
    default_item = str(row.get("default_item") or "").strip()
    if not equipment:
        flags.append("missing_equipment")
    elif equipment in OPS_QR_PLACEHOLDER_VALUES:
        flags.append("placeholder_equipment")
    if not location:
        flags.append("missing_location")
    elif location in OPS_QR_PLACEHOLDER_VALUES:
        flags.append("placeholder_location")
    if not default_item:
        flags.append("missing_default_item")
    elif default_item in OPS_QR_PLACEHOLDER_VALUES:
        flags.append("placeholder_default_item")
    return flags


def _validate_ops_inspection_payload(payload: InspectionCreate) -> dict[str, Any] | None:
    parsed_notes = _parse_ops_checklist_notes(payload.notes)
    if parsed_notes is None:
        return None

    errors: list[str] = []
    parse_errors = parsed_notes.get("parse_errors")
    if isinstance(parse_errors, list):
        for parse_error in parse_errors:
            msg = str(parse_error or "").strip()
            if msg:
                errors.append(msg)

    meta = parsed_notes.get("meta") if isinstance(parsed_notes.get("meta"), dict) else {}
    checklist_rows_raw = parsed_notes.get("checklist") if isinstance(parsed_notes.get("checklist"), list) else []

    for field in OPS_CHECKLIST_META_REQUIRED_FIELDS:
        value = str(meta.get(field) or "").strip()
        if not value:
            errors.append(f"meta.{field} is required")

    equipment_location = str(meta.get("equipment_location") or "").strip()
    if equipment_location and equipment_location != payload.location:
        errors.append("meta.equipment_location must match payload.location")

    if not checklist_rows_raw:
        errors.append("checklist must contain at least one row")

    normalized_rows: list[dict[str, str]] = []
    for idx, row in enumerate(checklist_rows_raw, start=1):
        if not isinstance(row, dict):
            errors.append(f"checklist[{idx}] must be an object")
            continue
        group = str(row.get("group") or "").strip()
        item = str(row.get("item") or "").strip()
        result = str(row.get("result") or "").strip().lower() or "normal"
        action = str(row.get("action") or "").strip()
        if not group:
            errors.append(f"checklist[{idx}].group is required")
        if not item:
            errors.append(f"checklist[{idx}].item is required")
        if result not in OPS_CHECKLIST_RESULT_SET:
            errors.append(f"checklist[{idx}].result must be one of {sorted(OPS_CHECKLIST_RESULT_SET)}")
        normalized_rows.append(
            {
                "group": group,
                "item": item,
                "result": result,
                "action": action,
            }
        )

    set_id = str(meta.get("checklist_set_id") or "").strip()
    task_type = str(meta.get("task_type") or "").strip()
    checklist_catalog = _load_ops_special_checklists_payload()
    set_map: dict[str, dict[str, Any]] = {}
    for row in checklist_catalog.get("checklist_sets", []):
        if isinstance(row, dict):
            key = str(row.get("set_id") or "").strip()
            if key:
                set_map[key] = row

    set_obj = set_map.get(set_id) if set_id else None
    if set_id and set_obj is None:
        errors.append(f"meta.checklist_set_id is unknown: {set_id}")
    if set_obj is not None:
        expected_task_type = str(set_obj.get("task_type") or "").strip()
        if expected_task_type and task_type and task_type != expected_task_type:
            errors.append(
                "meta.task_type does not match checklist_set_id "
                f"(expected={expected_task_type}, received={task_type})"
            )
        allowed_items = {
            str(item.get("item") or "").strip()
            for item in set_obj.get("items", [])
            if isinstance(item, dict) and str(item.get("item") or "").strip()
        }
        for idx, row in enumerate(normalized_rows, start=1):
            item = row.get("item", "")
            if item and item not in allowed_items:
                errors.append(f"checklist[{idx}].item is not registered in checklist_set_id={set_id}")

    abnormal_action = str(meta.get("abnormal_action") or "").strip()
    abnormal_count = 0
    abnormal_missing_action_indexes: list[int] = []
    normal_count = 0
    na_count = 0
    for idx, row in enumerate(normalized_rows, start=1):
        result = row.get("result", "normal")
        if result == "abnormal":
            abnormal_count += 1
            if not row.get("action") and not abnormal_action:
                abnormal_missing_action_indexes.append(idx)
            continue
        if result == "na":
            na_count += 1
            continue
        normal_count += 1
    if abnormal_missing_action_indexes:
        errors.append(
            "abnormal checklist rows require row action or meta.abnormal_action "
            f"(rows={abnormal_missing_action_indexes})"
        )

    summary = meta.get("summary")
    if not isinstance(summary, dict):
        errors.append("meta.summary is required")
    else:
        expected = {
            "total": len(normalized_rows),
            "normal": normal_count,
            "abnormal": abnormal_count,
            "na": na_count,
        }
        for key, expected_value in expected.items():
            raw_value = summary.get(key)
            try:
                value = int(raw_value)
            except (TypeError, ValueError):
                errors.append(f"meta.summary.{key} must be an integer")
                continue
            if value != expected_value:
                errors.append(
                    f"meta.summary.{key} mismatch (expected={expected_value}, received={value})"
                )

    if errors:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "OPS checklist payload validation failed",
                "error_count": len(errors),
                "errors": errors,
            },
        )
    return {
        "meta": meta,
        "checklist": normalized_rows,
    }


def _calculate_risk(
    payload: InspectionCreate,
    *,
    parsed_ops_notes: dict[str, Any] | None = None,
) -> tuple[str, list[str]]:
    return _ops_inspection_service_module()._calculate_risk(
        payload,
        parsed_ops_notes=parsed_ops_notes,
    )
def _to_utc(dt: datetime) -> datetime:
    return _ops_inspection_service_module()._to_utc(
        dt,
    )
def _as_datetime(value: Any) -> datetime:
    return _ops_inspection_service_module()._as_datetime(
        value,
    )
def _as_optional_datetime(value: Any) -> datetime | None:
    return _ops_inspection_service_module()._as_optional_datetime(
        value,
    )
def _safe_download_filename(raw_value: str, *, fallback: str = "download.bin", max_length: int = 120) -> str:
    return _ops_inspection_service_module()._safe_download_filename(
        raw_value,
        fallback=fallback,
        max_length=max_length,
    )
def _is_allowed_evidence_content_type(content_type: str) -> bool:
    return _ops_inspection_service_module()._is_allowed_evidence_content_type(
        content_type,
    )
def _normalize_evidence_storage_backend(value: str) -> str:
    return _ops_inspection_service_module()._normalize_evidence_storage_backend(
        value,
    )
def _evidence_storage_root() -> Path:
    return _ops_inspection_service_module()._evidence_storage_root()
def _resolve_evidence_storage_abs_path(storage_key: str) -> Path | None:
    return _ops_inspection_service_module()._resolve_evidence_storage_abs_path(
        storage_key,
    )
def _ensure_evidence_storage_ready() -> None:
    return _ops_inspection_service_module()._ensure_evidence_storage_ready()
def _scan_evidence_bytes(*, file_bytes: bytes, content_type: str) -> tuple[str, str, str | None]:
    return _ops_inspection_service_module()._scan_evidence_bytes(
        file_bytes=file_bytes,
        content_type=content_type,
    )
def _write_evidence_blob(*, file_name: str, file_bytes: bytes, sha256_digest: str) -> tuple[str, str | None, bytes]:
    return _ops_inspection_service_module()._write_evidence_blob(
        file_name=file_name,
        file_bytes=file_bytes,
        sha256_digest=sha256_digest,
    )
def _resolve_sample_evidence_blob(*, row: dict[str, Any]) -> bytes | None:
    return _ops_inspection_service_module()._resolve_sample_evidence_blob(
        row=row,
    )
def _read_evidence_blob(*, row: dict[str, Any]) -> bytes | None:
    return _ops_inspection_service_module()._read_evidence_blob(
        row=row,
    )
def _row_to_read_model(row: dict[str, Any]) -> InspectionRead:
    return _ops_inspection_service_module()._row_to_read_model(
        row,
    )
def _row_to_inspection_evidence_model(row: dict[str, Any]) -> InspectionEvidenceRead:
    return _ops_inspection_service_module()._row_to_inspection_evidence_model(
        row,
    )
def _is_overdue(status: str, due_at: datetime | None) -> bool:
    return _ops_inspection_service_module()._is_overdue(
        status,
        due_at,
    )


def _month_window(month: str | None) -> tuple[datetime, datetime, str]:
    if month is None:
        now = datetime.now(timezone.utc)
        normalized = f"{now.year:04d}-{now.month:02d}"
    else:
        normalized = month

    try:
        year, month_num = normalized.split("-")
        start = datetime(int(year), int(month_num), 1, tzinfo=timezone.utc)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="month must be YYYY-MM format") from exc

    if start.month == 12:
        end = datetime(start.year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(start.year, start.month + 1, 1, tzinfo=timezone.utc)
    return start, end, normalized


def _token_rotate_due_at(created_at: datetime) -> datetime | None:
    from app.domains.iam.security import _token_rotate_due_at as _impl
    return _impl(created_at)


def _token_idle_due_at(*, created_at: datetime, last_used_at: datetime | None) -> datetime | None:
    from app.domains.iam.security import _token_idle_due_at as _impl
    return _impl(created_at=created_at, last_used_at=last_used_at)


def _load_principal_by_token(token: str) -> dict[str, Any] | None:
    from app.domains.iam.security import _load_principal_by_token as _impl
    return _impl(token)


def _build_local_dev_principal() -> dict[str, Any]:
    from app.domains.iam.security import _build_local_dev_principal as _impl
    return _impl()


def get_current_admin(
    x_admin_token: Annotated[str | None, Header(alias="X-Admin-Token")] = None,
) -> dict[str, Any]:
    from app.domains.iam.security import get_current_admin as _impl
    return _impl(x_admin_token)


def _has_permission(principal: dict[str, Any], permission: str) -> bool:
    from app.domains.iam.security import _has_permission as _impl
    return _impl(principal, permission)


def require_permission(permission: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
    from app.domains.iam.security import require_permission as _impl
    return _impl(permission)


def _has_explicit_permission(principal: dict[str, Any], permission: str) -> bool:
    from app.domains.iam.security import _has_explicit_permission as _impl
    return _impl(principal, permission)


def _is_workflow_admin_override(principal: dict[str, Any]) -> bool:
    if bool(principal.get("is_legacy", False)):
        return True
    return _has_explicit_permission(principal, "workflow_locks:admin")


def _require_workflow_lock_action(
    principal: dict[str, Any],
    *,
    action: str,
    status: str | None = None,
) -> None:
    role = str(principal.get("role") or "")
    is_admin = _is_workflow_admin_override(principal)
    allowed = False

    if action == "read":
        allowed = role in {"operator", "manager", "owner", "auditor"} or is_admin
    elif action in {"create", "update_draft", "submit"}:
        allowed = role == "operator" or is_admin
    elif action in {"approve", "reject"}:
        allowed = role in {"manager", "owner"} or is_admin
    elif action == "lock":
        allowed = role == "owner" or is_admin
    elif action == "unlock":
        allowed = is_admin

    if not allowed:
        raise HTTPException(status_code=403, detail=f"Workflow lock action denied: {action}")

    if status is None:
        return
    if action in {"update_draft", "submit"} and status != WORKFLOW_LOCK_STATUS_DRAFT:
        raise HTTPException(status_code=409, detail=f"{action} requires draft status")
    if action in {"approve", "reject"} and status != WORKFLOW_LOCK_STATUS_REVIEW:
        raise HTTPException(status_code=409, detail=f"{action} requires review status")
    if action == "lock" and status != WORKFLOW_LOCK_STATUS_APPROVED:
        raise HTTPException(status_code=409, detail="lock requires approved status")
    if action == "unlock" and status != WORKFLOW_LOCK_STATUS_LOCKED:
        raise HTTPException(status_code=409, detail="unlock requires locked status")


def _to_json_text(value: dict[str, Any] | None) -> str:
    from app.domains.iam.service import _to_json_text as _impl
    return _impl(value)


def _compute_audit_entry_hash(
    *,
    prev_hash: str,
    actor_user_id: int | None,
    actor_username: str,
    action: str,
    resource_type: str,
    resource_id: str,
    status: str,
    detail_json: str,
    created_at: datetime,
) -> str:
    from app.domains.iam.service import _compute_audit_entry_hash as _impl
    return _impl(prev_hash=prev_hash, actor_user_id=actor_user_id, actor_username=actor_username, action=action, resource_type=resource_type, resource_id=resource_id, status=status, detail_json=detail_json, created_at=created_at)


def _sign_payload(payload_text: str) -> str | None:
    from app.domains.iam.service import _sign_payload as _impl
    return _impl(payload_text)


def _write_audit_log(
    *,
    principal: dict[str, Any] | None,
    action: str,
    resource_type: str,
    resource_id: str,
    status: str = "success",
    detail: dict[str, Any] | None = None,
) -> None:
    from app.domains.iam.service import _write_audit_log as _impl
    return _impl(principal=principal, action=action, resource_type=resource_type, resource_id=resource_id, status=status, detail=detail)


def _row_to_admin_audit_log_model(row: dict[str, Any]) -> AdminAuditLogRead:
    from app.domains.iam.service import _row_to_admin_audit_log_model as _impl
    return _impl(row)


def _verify_audit_chain(rows: list[dict[str, Any]], *, initial_prev_hash: str = "") -> dict[str, Any]:
    from app.domains.iam.service import _verify_audit_chain as _impl
    return _impl(rows, initial_prev_hash=initial_prev_hash)


def build_monthly_audit_archive(
    *,
    month: str | None,
    max_entries: int = 10000,
    include_entries: bool = True,
) -> dict[str, Any]:
    from app.domains.iam.service import build_monthly_audit_archive as _impl
    return _impl(month=month, max_entries=max_entries, include_entries=include_entries)


def rebaseline_admin_audit_chain(
    *,
    from_month: str | None = None,
    max_rows: int = 50000,
    dry_run: bool = False,
) -> dict[str, Any]:
    from app.domains.iam.service import rebaseline_admin_audit_chain as _impl
    return _impl(from_month=from_month, max_rows=max_rows, dry_run=dry_run)


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


def _normalize_sla_due_hours(value: Any) -> dict[str, int]:
    source = value if isinstance(value, dict) else {}
    normalized: dict[str, int] = {}
    for priority, default_hours in SLA_DEFAULT_DUE_HOURS.items():
        raw_hours = source.get(priority, default_hours)
        try:
            hours = int(raw_hours)
        except (TypeError, ValueError):
            hours = default_hours
        if hours < 1 or hours > 24 * 30:
            hours = default_hours
        normalized[priority] = hours
    return normalized


def _normalize_sla_policy(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    due_hours = _normalize_sla_due_hours(source.get("default_due_hours"))

    raw_grace = source.get("escalation_grace_minutes", 0)
    try:
        grace_minutes = int(raw_grace)
    except (TypeError, ValueError):
        grace_minutes = 0
    grace_minutes = max(0, min(1440, grace_minutes))

    return {
        "default_due_hours": due_hours,
        "escalation_grace_minutes": grace_minutes,
    }


def _parse_sla_policy_json(raw: Any) -> dict[str, Any]:
    try:
        loaded = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        loaded = {}
    return _normalize_sla_policy(loaded)


def _normalize_site_name(site: str | None) -> str | None:
    if site is None:
        return None
    value = site.strip()
    return value or None


def _policy_key_for_site(site: str | None) -> str | None:
    normalized_site = _normalize_site_name(site)
    if normalized_site is None:
        return None
    return f"{SLA_SITE_POLICY_PREFIX}{normalized_site}"


def _get_sla_policy_row(policy_key: str) -> dict[str, Any] | None:
    with get_conn() as conn:
        return conn.execute(
            select(sla_policies).where(sla_policies.c.policy_key == policy_key).limit(1)
        ).mappings().first()


def _ensure_default_sla_policy() -> tuple[dict[str, Any], datetime]:
    now = datetime.now(timezone.utc)
    row = _get_sla_policy_row(SLA_DEFAULT_POLICY_KEY)
    if row is None:
        policy = _normalize_sla_policy({})
        with get_conn() as conn:
            conn.execute(
                insert(sla_policies).values(
                    policy_key=SLA_DEFAULT_POLICY_KEY,
                    policy_json=_to_json_text(policy),
                    updated_at=now,
                )
            )
        return policy, now

    policy = _parse_sla_policy_json(row["policy_json"])
    updated_at = _as_datetime(row["updated_at"]) if row["updated_at"] is not None else now
    return policy, updated_at


def _sla_policy_to_model(
    *,
    policy_key: str,
    site: str | None,
    source: str,
    updated_at: datetime,
    policy: dict[str, Any],
) -> SlaPolicyRead:
    return SlaPolicyRead(
        policy_key=policy_key,
        site=site,
        source=source,
        default_due_hours=policy["default_due_hours"],
        escalation_grace_minutes=policy["escalation_grace_minutes"],
        updated_at=updated_at,
    )


def _load_sla_policy(
    site: str | None = None,
) -> tuple[dict[str, Any], datetime, str, str | None, str]:
    normalized_site = _normalize_site_name(site)
    default_policy, default_updated_at = _ensure_default_sla_policy()
    site_policy_key = _policy_key_for_site(normalized_site)
    if site_policy_key is None:
        return default_policy, default_updated_at, "default", None, SLA_DEFAULT_POLICY_KEY

    row = _get_sla_policy_row(site_policy_key)
    if row is None:
        # Site requested but override does not exist: use default policy.
        return default_policy, default_updated_at, "default", normalized_site, SLA_DEFAULT_POLICY_KEY

    now = datetime.now(timezone.utc)
    policy = _parse_sla_policy_json(row["policy_json"])
    updated_at = _as_datetime(row["updated_at"]) if row["updated_at"] is not None else now
    return policy, updated_at, "site", normalized_site, site_policy_key


def _upsert_sla_policy(
    payload: SlaPolicyUpdate,
    site: str | None = None,
    *,
    source_action: str = "manual_update",
    actor_username: str = "system",
    note: str = "",
) -> SlaPolicyRead:
    now = datetime.now(timezone.utc)
    policy = _normalize_sla_policy(payload.model_dump())
    normalized_site = _normalize_site_name(site)
    policy_key = _policy_key_for_site(normalized_site) or SLA_DEFAULT_POLICY_KEY
    source = "site" if normalized_site is not None else "default"

    with get_conn() as conn:
        row = conn.execute(
            select(sla_policies.c.id)
            .where(sla_policies.c.policy_key == policy_key)
            .limit(1)
        ).first()
        if row is None:
            conn.execute(
                insert(sla_policies).values(
                    policy_key=policy_key,
                    policy_json=_to_json_text(policy),
                    updated_at=now,
                )
            )
        else:
            conn.execute(
                update(sla_policies)
                .where(sla_policies.c.policy_key == policy_key)
                .values(policy_json=_to_json_text(policy), updated_at=now)
            )

    _write_sla_policy_revision(
        site=normalized_site,
        policy=policy,
        source_action=source_action,
        actor_username=actor_username,
        note=note,
    )

    return _sla_policy_to_model(
        policy_key=policy_key,
        site=normalized_site,
        source=source,
        updated_at=now,
        policy=policy,
    )


def _normalize_mttr_slo_recover_state(value: str | None) -> str:
    normalized = (value or "").strip().lower()
    if normalized in ALERT_MTTR_SLO_RECOVER_STATE_SET:
        return normalized
    return "quarantined"


def _default_mttr_slo_policy() -> dict[str, Any]:
    return {
        "enabled": ALERT_MTTR_SLO_ENABLED,
        "window_days": max(1, ALERT_MTTR_SLO_WINDOW_DAYS),
        "threshold_minutes": max(1, ALERT_MTTR_SLO_THRESHOLD_MINUTES),
        "min_incidents": max(1, ALERT_MTTR_SLO_MIN_INCIDENTS),
        "auto_recover_enabled": ALERT_MTTR_SLO_AUTO_RECOVER_ENABLED,
        "recover_state": _normalize_mttr_slo_recover_state(ALERT_MTTR_SLO_RECOVER_STATE),
        "recover_max_targets": max(1, min(ALERT_MTTR_SLO_RECOVER_MAX_TARGETS, 500)),
        "notify_enabled": ALERT_MTTR_SLO_NOTIFY_ENABLED,
        "notify_event_type": ALERT_MTTR_SLO_NOTIFY_EVENT_TYPE[:80],
        "notify_cooldown_minutes": max(0, min(ALERT_MTTR_SLO_NOTIFY_COOLDOWN_MINUTES, 10080)),
        "top_channels": max(1, min(ALERT_MTTR_SLO_TOP_CHANNELS, 50)),
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
            select(sla_policies).where(sla_policies.c.policy_key == ALERT_MTTR_SLO_POLICY_KEY).limit(1)
        ).mappings().first()
        if row is None:
            policy = _default_mttr_slo_policy()
            conn.execute(
                insert(sla_policies).values(
                    policy_key=ALERT_MTTR_SLO_POLICY_KEY,
                    policy_json=_to_json_text(policy),
                    updated_at=now,
                )
            )
            return policy, now, ALERT_MTTR_SLO_POLICY_KEY

    policy = _parse_mttr_slo_policy_json(row["policy_json"])
    default_policy = _default_mttr_slo_policy()
    if policy == _legacy_mttr_slo_policy() and policy != default_policy:
        with get_conn() as conn:
            conn.execute(
                update(sla_policies)
                .where(sla_policies.c.policy_key == ALERT_MTTR_SLO_POLICY_KEY)
                .values(
                    policy_json=_to_json_text(default_policy),
                    updated_at=now,
                )
            )
        return default_policy, now, ALERT_MTTR_SLO_POLICY_KEY

    updated_at = _as_datetime(row["updated_at"]) if row["updated_at"] is not None else now
    return policy, updated_at, ALERT_MTTR_SLO_POLICY_KEY


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


def _w09_policy_key(site: str | None) -> tuple[str, str | None]:
    normalized_site = _normalize_site_name(site)
    if normalized_site is None:
        return W09_KPI_POLICY_KEY_DEFAULT, None
    return f"{W09_KPI_POLICY_KEY_SITE_PREFIX}{normalized_site}", normalized_site


def _default_w09_kpi_policy() -> dict[str, Any]:
    kpis: list[dict[str, Any]] = []
    for item in ADOPTION_W09_KPI_THRESHOLD_MATRIX:
        kpis.append(
            {
                "kpi_key": str(item.get("kpi_key") or ""),
                "kpi_name": str(item.get("kpi_name") or ""),
                "direction": str(item.get("direction") or "higher_better"),
                "owner_role": str(item.get("owner_role") or ""),
                "green_threshold": float(item.get("green_threshold") or 0.0),
                "yellow_threshold": float(item.get("yellow_threshold") or 0.0),
                "target": str(item.get("target") or ""),
                "source_api": str(item.get("source_api") or ""),
            }
        )
    escalation_map: list[dict[str, Any]] = []
    for item in ADOPTION_W09_ESCALATION_MAP:
        escalation_map.append(
            {
                "id": str(item.get("id") or ""),
                "kpi_key": str(item.get("kpi_key") or ""),
                "condition": str(item.get("condition") or ""),
                "escalate_to": str(item.get("escalate_to") or ""),
                "sla_hours": int(item.get("sla_hours") or 24),
                "action": str(item.get("action") or ""),
            }
        )
    return {
        "enabled": True,
        "kpis": kpis,
        "escalation_map": escalation_map,
    }


def _normalize_w09_kpi_policy(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    defaults = _default_w09_kpi_policy()
    default_kpis = defaults.get("kpis", [])
    default_map = {
        str(item.get("kpi_key") or ""): item
        for item in default_kpis
        if str(item.get("kpi_key") or "")
    }
    merged_map: dict[str, dict[str, Any]] = {}

    source_kpis = source.get("kpis", [])
    if isinstance(source_kpis, list):
        for item in source_kpis:
            if not isinstance(item, dict):
                continue
            kpi_key = str(item.get("kpi_key") or "").strip()
            if not kpi_key:
                continue
            merged_map[kpi_key] = item

    normalized_kpis: list[dict[str, Any]] = []
    for key, default_item in default_map.items():
        incoming = merged_map.get(key, {})
        if not isinstance(incoming, dict):
            incoming = {}
        direction = str(incoming.get("direction") or default_item.get("direction") or "higher_better").strip().lower()
        if direction not in {"higher_better", "lower_better"}:
            direction = str(default_item.get("direction") or "higher_better")
        try:
            green = float(incoming.get("green_threshold", default_item.get("green_threshold", 0.0)))
        except (TypeError, ValueError):
            green = float(default_item.get("green_threshold", 0.0))
        try:
            yellow = float(incoming.get("yellow_threshold", default_item.get("yellow_threshold", 0.0)))
        except (TypeError, ValueError):
            yellow = float(default_item.get("yellow_threshold", 0.0))

        normalized_kpis.append(
            {
                "kpi_key": key,
                "kpi_name": str(incoming.get("kpi_name") or default_item.get("kpi_name") or ""),
                "direction": direction,
                "owner_role": str(incoming.get("owner_role") or default_item.get("owner_role") or ""),
                "green_threshold": round(green, 2),
                "yellow_threshold": round(yellow, 2),
                "target": str(incoming.get("target") or default_item.get("target") or ""),
                "source_api": str(incoming.get("source_api") or default_item.get("source_api") or ""),
            }
        )

    escalation_source = source.get("escalation_map", defaults.get("escalation_map", []))
    normalized_escalations: list[dict[str, Any]] = []
    if isinstance(escalation_source, list):
        for item in escalation_source:
            if not isinstance(item, dict):
                continue
            kpi_key = str(item.get("kpi_key") or "").strip()
            if kpi_key and kpi_key not in default_map:
                continue
            try:
                sla_hours = int(item.get("sla_hours") or 24)
            except (TypeError, ValueError):
                sla_hours = 24
            normalized_escalations.append(
                {
                    "id": str(item.get("id") or ""),
                    "kpi_key": kpi_key,
                    "condition": str(item.get("condition") or ""),
                    "escalate_to": str(item.get("escalate_to") or ""),
                    "sla_hours": max(1, min(sla_hours, 168)),
                    "action": str(item.get("action") or ""),
                }
            )

    return {
        "enabled": bool(source.get("enabled", defaults.get("enabled", True))),
        "kpis": normalized_kpis,
        "escalation_map": normalized_escalations,
    }


def _parse_w09_kpi_policy_json(raw: Any) -> dict[str, Any]:
    try:
        loaded = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        loaded = {}
    return _normalize_w09_kpi_policy(loaded)


def _ensure_w09_kpi_policy(site: str | None) -> tuple[dict[str, Any], datetime, str, str | None]:
    policy_key, normalized_site = _w09_policy_key(site)
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(sla_policies).where(sla_policies.c.policy_key == policy_key).limit(1)
        ).mappings().first()
        if row is None:
            policy = _default_w09_kpi_policy()
            conn.execute(
                insert(sla_policies).values(
                    policy_key=policy_key,
                    policy_json=_to_json_text(policy),
                    updated_at=now,
                )
            )
            return policy, now, policy_key, normalized_site
    policy = _parse_w09_kpi_policy_json(row["policy_json"])
    updated_at = _as_datetime(row["updated_at"]) if row["updated_at"] is not None else now
    return policy, updated_at, policy_key, normalized_site


def _upsert_w09_kpi_policy(site: str | None, payload: dict[str, Any]) -> tuple[dict[str, Any], datetime, str, str | None]:
    current_policy, _, policy_key, normalized_site = _ensure_w09_kpi_policy(site)
    incoming = payload if isinstance(payload, dict) else {}
    merged: dict[str, Any] = {**current_policy}
    for key in ["enabled", "kpis", "escalation_map"]:
        if key in incoming:
            merged[key] = incoming[key]
    normalized = _normalize_w09_kpi_policy(merged)
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
    return normalized, now, policy_key, normalized_site


def _evaluate_w09_kpi_status(
    *,
    actual: float | None,
    direction: str,
    green_threshold: float,
    yellow_threshold: float,
) -> str:
    if actual is None:
        return W09_KPI_STATUS_RED
    if direction == "lower_better":
        if actual <= green_threshold:
            return W09_KPI_STATUS_GREEN
        if actual <= yellow_threshold:
            return W09_KPI_STATUS_YELLOW
        return W09_KPI_STATUS_RED
    if actual >= green_threshold:
        return W09_KPI_STATUS_GREEN
    if actual >= yellow_threshold:
        return W09_KPI_STATUS_YELLOW
    return W09_KPI_STATUS_RED


def _w10_support_policy_key(site: str | None) -> tuple[str, str | None]:
    normalized_site = _normalize_site_name(site)
    if normalized_site is None:
        return W10_SUPPORT_POLICY_KEY_DEFAULT, None
    return f"{W10_SUPPORT_POLICY_KEY_SITE_PREFIX}{normalized_site}", normalized_site


def _default_w10_support_policy() -> dict[str, Any]:
    return {
        "enabled": True,
        "repeat_rate_green_threshold": 20.0,
        "repeat_rate_yellow_threshold": 30.0,
        "guide_publish_green_threshold": 80.0,
        "guide_publish_yellow_threshold": 60.0,
        "runbook_completion_green_threshold": 80.0,
        "runbook_completion_yellow_threshold": 60.0,
        "readiness_target": 75.0,
    }


def _normalize_w10_support_policy(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    defaults = _default_w10_support_policy()

    def _float_value(key: str, fallback: float, min_value: float, max_value: float) -> float:
        try:
            raw = float(source.get(key, fallback))
        except (TypeError, ValueError):
            raw = fallback
        return round(max(min_value, min(raw, max_value)), 2)

    repeat_green = _float_value(
        "repeat_rate_green_threshold",
        float(defaults["repeat_rate_green_threshold"]),
        0.0,
        100.0,
    )
    repeat_yellow = _float_value(
        "repeat_rate_yellow_threshold",
        float(defaults["repeat_rate_yellow_threshold"]),
        0.0,
        100.0,
    )
    if repeat_yellow < repeat_green:
        repeat_yellow = repeat_green

    guide_green = _float_value(
        "guide_publish_green_threshold",
        float(defaults["guide_publish_green_threshold"]),
        0.0,
        100.0,
    )
    guide_yellow = _float_value(
        "guide_publish_yellow_threshold",
        float(defaults["guide_publish_yellow_threshold"]),
        0.0,
        100.0,
    )
    if guide_yellow > guide_green:
        guide_yellow = guide_green

    runbook_green = _float_value(
        "runbook_completion_green_threshold",
        float(defaults["runbook_completion_green_threshold"]),
        0.0,
        100.0,
    )
    runbook_yellow = _float_value(
        "runbook_completion_yellow_threshold",
        float(defaults["runbook_completion_yellow_threshold"]),
        0.0,
        100.0,
    )
    if runbook_yellow > runbook_green:
        runbook_yellow = runbook_green

    readiness_target = _float_value(
        "readiness_target",
        float(defaults["readiness_target"]),
        0.0,
        100.0,
    )

    return {
        "enabled": bool(source.get("enabled", defaults.get("enabled", True))),
        "repeat_rate_green_threshold": repeat_green,
        "repeat_rate_yellow_threshold": repeat_yellow,
        "guide_publish_green_threshold": guide_green,
        "guide_publish_yellow_threshold": guide_yellow,
        "runbook_completion_green_threshold": runbook_green,
        "runbook_completion_yellow_threshold": runbook_yellow,
        "readiness_target": readiness_target,
    }


def _parse_w10_support_policy_json(raw: Any) -> dict[str, Any]:
    try:
        loaded = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        loaded = {}
    return _normalize_w10_support_policy(loaded)


def _ensure_w10_support_policy(site: str | None) -> tuple[dict[str, Any], datetime, str, str | None]:
    policy_key, normalized_site = _w10_support_policy_key(site)
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(sla_policies).where(sla_policies.c.policy_key == policy_key).limit(1)
        ).mappings().first()
        if row is None:
            policy = _default_w10_support_policy()
            conn.execute(
                insert(sla_policies).values(
                    policy_key=policy_key,
                    policy_json=_to_json_text(policy),
                    updated_at=now,
                )
            )
            return policy, now, policy_key, normalized_site
    policy = _parse_w10_support_policy_json(row["policy_json"])
    updated_at = _as_datetime(row["updated_at"]) if row["updated_at"] is not None else now
    return policy, updated_at, policy_key, normalized_site


def _upsert_w10_support_policy(site: str | None, payload: dict[str, Any]) -> tuple[dict[str, Any], datetime, str, str | None]:
    current_policy, _, policy_key, normalized_site = _ensure_w10_support_policy(site)
    incoming = payload if isinstance(payload, dict) else {}
    merged: dict[str, Any] = {**current_policy}
    for key in [
        "enabled",
        "repeat_rate_green_threshold",
        "repeat_rate_yellow_threshold",
        "guide_publish_green_threshold",
        "guide_publish_yellow_threshold",
        "runbook_completion_green_threshold",
        "runbook_completion_yellow_threshold",
        "readiness_target",
    ]:
        if key in incoming:
            merged[key] = incoming[key]
    normalized = _normalize_w10_support_policy(merged)
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
    return normalized, now, policy_key, normalized_site


def _build_w10_self_serve_snapshot(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_days = max(14, min(int(days), 120))
    window_start = now - timedelta(days=window_days)
    policy, policy_updated_at, policy_key, policy_site = _ensure_w10_support_policy(site)

    effective_site = policy_site if policy_site is not None else _normalize_site_name(site)
    effective_allowed_sites = allowed_sites if effective_site is None else None

    stmt = select(work_orders).where(work_orders.c.created_at >= window_start)
    if effective_site is not None:
        stmt = stmt.where(work_orders.c.site == effective_site)
    elif effective_allowed_sites is not None:
        if not effective_allowed_sites:
            return {
                "generated_at": now.isoformat(),
                "site": None,
                "window_days": window_days,
                "policy": {
                    "policy_key": policy_key,
                    "updated_at": policy_updated_at.isoformat(),
                    "enabled": bool(policy.get("enabled", True)),
                },
                "metrics": {
                    "work_orders_count": 0,
                    "unique_titles": 0,
                    "repeated_work_orders_count": 0,
                    "repeat_rate_percent": 0.0,
                    "guide_total_count": len(ADOPTION_W10_SELF_SERVE_GUIDES),
                    "guide_done_count": 0,
                    "guide_publish_rate_percent": 0.0,
                    "runbook_total_count": len(ADOPTION_W10_TROUBLESHOOTING_RUNBOOK),
                    "runbook_done_count": 0,
                    "runbook_completion_rate_percent": 0.0,
                    "self_serve_readiness_score": 0.0,
                    "overall_status": W10_SUPPORT_STATUS_RED,
                    "target_met": False,
                },
                "kpis": [],
                "top_repeat_titles": [],
                "guide_coverage": ADOPTION_W10_SELF_SERVE_GUIDES,
                "runbook_modules": ADOPTION_W10_TROUBLESHOOTING_RUNBOOK,
                "recommendations": ["접근 가능한 site 범위가 비어 있습니다. site_scope를 확인하세요."],
            }
        stmt = stmt.where(work_orders.c.site.in_(effective_allowed_sites))
    with get_conn() as conn:
        wo_rows = conn.execute(stmt).mappings().all()

    title_counts: dict[str, int] = {}
    title_label: dict[str, str] = {}
    for row in wo_rows:
        title_raw = str(row.get("title") or "").strip()
        normalized = title_raw.lower() if title_raw else "(untitled)"
        title_counts[normalized] = title_counts.get(normalized, 0) + 1
        if normalized not in title_label:
            title_label[normalized] = title_raw or "(untitled)"

    total_work_orders = len(wo_rows)
    repeated_orders_count = sum(count for count in title_counts.values() if count >= 2)
    unique_titles = len(title_counts)
    repeat_rate_percent = round((repeated_orders_count / total_work_orders) * 100.0, 2) if total_work_orders > 0 else 0.0
    top_repeat_titles = sorted(
        [
            {
                "title": title_label.get(key, key),
                "count": count,
                "share_percent": round((count / total_work_orders) * 100.0, 2) if total_work_orders > 0 else 0.0,
            }
            for key, count in title_counts.items()
            if count >= 2
        ],
        key=lambda item: int(item.get("count") or 0),
        reverse=True,
    )[:10]

    tracker_stmt = select(adoption_w10_tracker_items)
    if effective_site is not None:
        tracker_stmt = tracker_stmt.where(adoption_w10_tracker_items.c.site == effective_site)
    elif effective_allowed_sites is not None:
        tracker_stmt = tracker_stmt.where(adoption_w10_tracker_items.c.site.in_(effective_allowed_sites))
    with get_conn() as conn:
        tracker_rows = conn.execute(tracker_stmt).mappings().all()

    guide_total_count = max(
        len(ADOPTION_W10_SELF_SERVE_GUIDES),
        sum(1 for row in tracker_rows if str(row.get("item_type") or "") == "self_serve_guide"),
    )
    runbook_total_count = max(
        len(ADOPTION_W10_TROUBLESHOOTING_RUNBOOK),
        sum(1 for row in tracker_rows if str(row.get("item_type") or "") == "troubleshooting_runbook"),
    )
    guide_done_count = sum(
        1
        for row in tracker_rows
        if str(row.get("item_type") or "") == "self_serve_guide" and str(row.get("status") or "") == W10_TRACKER_STATUS_DONE
    )
    runbook_done_count = sum(
        1
        for row in tracker_rows
        if str(row.get("item_type") or "") == "troubleshooting_runbook" and str(row.get("status") or "") == W10_TRACKER_STATUS_DONE
    )
    guide_publish_rate_percent = round((guide_done_count / guide_total_count) * 100.0, 2) if guide_total_count > 0 else 0.0
    runbook_completion_rate_percent = (
        round((runbook_done_count / runbook_total_count) * 100.0, 2) if runbook_total_count > 0 else 0.0
    )

    repeat_status = _evaluate_w09_kpi_status(
        actual=repeat_rate_percent,
        direction="lower_better",
        green_threshold=float(policy.get("repeat_rate_green_threshold") or 20.0),
        yellow_threshold=float(policy.get("repeat_rate_yellow_threshold") or 30.0),
    )
    guide_status = _evaluate_w09_kpi_status(
        actual=guide_publish_rate_percent,
        direction="higher_better",
        green_threshold=float(policy.get("guide_publish_green_threshold") or 80.0),
        yellow_threshold=float(policy.get("guide_publish_yellow_threshold") or 60.0),
    )
    runbook_status = _evaluate_w09_kpi_status(
        actual=runbook_completion_rate_percent,
        direction="higher_better",
        green_threshold=float(policy.get("runbook_completion_green_threshold") or 80.0),
        yellow_threshold=float(policy.get("runbook_completion_yellow_threshold") or 60.0),
    )

    status_points = {
        W09_KPI_STATUS_RED: 0.0,
        W09_KPI_STATUS_YELLOW: 50.0,
        W09_KPI_STATUS_GREEN: 100.0,
    }
    self_serve_readiness_score = round(
        (status_points.get(repeat_status, 0.0) + status_points.get(guide_status, 0.0) + status_points.get(runbook_status, 0.0))
        / 3.0,
        2,
    )

    status_set = {repeat_status, guide_status, runbook_status}
    overall_status = W10_SUPPORT_STATUS_GREEN
    if W09_KPI_STATUS_RED in status_set:
        overall_status = W10_SUPPORT_STATUS_RED
    elif W09_KPI_STATUS_YELLOW in status_set:
        overall_status = W10_SUPPORT_STATUS_YELLOW

    readiness_target = float(policy.get("readiness_target") or 75.0)
    target_met = self_serve_readiness_score >= readiness_target and overall_status != W10_SUPPORT_STATUS_RED

    kpis = [
        {
            "kpi_key": "repeat_ticket_rate_percent",
            "kpi_name": "Repeat ticket rate",
            "direction": "lower_better",
            "actual_value": repeat_rate_percent,
            "green_threshold": float(policy.get("repeat_rate_green_threshold") or 20.0),
            "yellow_threshold": float(policy.get("repeat_rate_yellow_threshold") or 30.0),
            "status": repeat_status,
            "target": f"<= {policy.get('repeat_rate_green_threshold', 20.0)}%",
        },
        {
            "kpi_key": "guide_publish_rate_percent",
            "kpi_name": "Self-serve guide publish rate",
            "direction": "higher_better",
            "actual_value": guide_publish_rate_percent,
            "green_threshold": float(policy.get("guide_publish_green_threshold") or 80.0),
            "yellow_threshold": float(policy.get("guide_publish_yellow_threshold") or 60.0),
            "status": guide_status,
            "target": f">= {policy.get('guide_publish_green_threshold', 80.0)}%",
        },
        {
            "kpi_key": "runbook_completion_rate_percent",
            "kpi_name": "Runbook completion rate",
            "direction": "higher_better",
            "actual_value": runbook_completion_rate_percent,
            "green_threshold": float(policy.get("runbook_completion_green_threshold") or 80.0),
            "yellow_threshold": float(policy.get("runbook_completion_yellow_threshold") or 60.0),
            "status": runbook_status,
            "target": f">= {policy.get('runbook_completion_green_threshold', 80.0)}%",
        },
        {
            "kpi_key": "self_serve_readiness_score",
            "kpi_name": "Self-serve readiness score",
            "direction": "higher_better",
            "actual_value": self_serve_readiness_score,
            "green_threshold": readiness_target,
            "yellow_threshold": max(0.0, readiness_target - 15.0),
            "status": _evaluate_w09_kpi_status(
                actual=self_serve_readiness_score,
                direction="higher_better",
                green_threshold=readiness_target,
                yellow_threshold=max(0.0, readiness_target - 15.0),
            ),
            "target": f">= {readiness_target}",
        },
    ]

    recommendations: list[str] = []
    if repeat_status == W09_KPI_STATUS_RED:
        recommendations.append("반복 티켓 비율이 높습니다. Top 반복 제목 3개를 FAQ/가이드로 우선 전환하세요.")
    if guide_status != W09_KPI_STATUS_GREEN:
        recommendations.append("Self-serve guide 게시율이 낮습니다. 담당자와 마감일을 지정해 게시를 완료하세요.")
    if runbook_status != W09_KPI_STATUS_GREEN:
        recommendations.append("Runbook 완료율이 낮습니다. 모듈별 실습 드릴과 증빙 업로드를 마감하세요.")
    if not recommendations:
        recommendations.append("W10 Self-serve 지원 전환 상태가 안정적입니다. 운영 리듬을 유지하세요.")

    return {
        "generated_at": now.isoformat(),
        "site": effective_site,
        "window_days": window_days,
        "policy": {
            "policy_key": policy_key,
            "updated_at": policy_updated_at.isoformat(),
            "enabled": bool(policy.get("enabled", True)),
            "readiness_target": readiness_target,
        },
        "metrics": {
            "work_orders_count": total_work_orders,
            "unique_titles": unique_titles,
            "repeated_work_orders_count": repeated_orders_count,
            "repeat_rate_percent": repeat_rate_percent,
            "guide_total_count": guide_total_count,
            "guide_done_count": guide_done_count,
            "guide_publish_rate_percent": guide_publish_rate_percent,
            "runbook_total_count": runbook_total_count,
            "runbook_done_count": runbook_done_count,
            "runbook_completion_rate_percent": runbook_completion_rate_percent,
            "self_serve_readiness_score": self_serve_readiness_score,
            "overall_status": overall_status,
            "target_met": target_met,
        },
        "kpis": kpis,
        "top_repeat_titles": top_repeat_titles,
        "guide_coverage": ADOPTION_W10_SELF_SERVE_GUIDES,
        "runbook_modules": ADOPTION_W10_TROUBLESHOOTING_RUNBOOK,
        "recommendations": recommendations,
    }



def _w11_readiness_policy_key(site: str | None) -> tuple[str, str | None]:
    normalized_site = _normalize_site_name(site)
    if normalized_site is None:
        return W11_READINESS_POLICY_KEY_DEFAULT, None
    return f"{W11_READINESS_POLICY_KEY_SITE_PREFIX}{normalized_site}", normalized_site


def _default_w11_readiness_policy() -> dict[str, Any]:
    return {
        "enabled": True,
        "risk_rate_green_threshold": 20.0,
        "risk_rate_yellow_threshold": 30.0,
        "checklist_completion_green_threshold": 80.0,
        "checklist_completion_yellow_threshold": 60.0,
        "simulation_success_green_threshold": 80.0,
        "simulation_success_yellow_threshold": 60.0,
        "readiness_target": 75.0,
    }


def _normalize_w11_readiness_policy(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    defaults = _default_w11_readiness_policy()

    def _float_value(key: str, fallback: float, min_value: float, max_value: float) -> float:
        try:
            raw = float(source.get(key, fallback))
        except (TypeError, ValueError):
            raw = fallback
        return round(max(min_value, min(raw, max_value)), 2)

    repeat_green = _float_value(
        "risk_rate_green_threshold",
        float(defaults["risk_rate_green_threshold"]),
        0.0,
        100.0,
    )
    repeat_yellow = _float_value(
        "risk_rate_yellow_threshold",
        float(defaults["risk_rate_yellow_threshold"]),
        0.0,
        100.0,
    )
    if repeat_yellow < repeat_green:
        repeat_yellow = repeat_green

    guide_green = _float_value(
        "checklist_completion_green_threshold",
        float(defaults["checklist_completion_green_threshold"]),
        0.0,
        100.0,
    )
    guide_yellow = _float_value(
        "checklist_completion_yellow_threshold",
        float(defaults["checklist_completion_yellow_threshold"]),
        0.0,
        100.0,
    )
    if guide_yellow > guide_green:
        guide_yellow = guide_green

    runbook_green = _float_value(
        "simulation_success_green_threshold",
        float(defaults["simulation_success_green_threshold"]),
        0.0,
        100.0,
    )
    runbook_yellow = _float_value(
        "simulation_success_yellow_threshold",
        float(defaults["simulation_success_yellow_threshold"]),
        0.0,
        100.0,
    )
    if runbook_yellow > runbook_green:
        runbook_yellow = runbook_green

    readiness_target = _float_value(
        "readiness_target",
        float(defaults["readiness_target"]),
        0.0,
        100.0,
    )

    return {
        "enabled": bool(source.get("enabled", defaults.get("enabled", True))),
        "risk_rate_green_threshold": repeat_green,
        "risk_rate_yellow_threshold": repeat_yellow,
        "checklist_completion_green_threshold": guide_green,
        "checklist_completion_yellow_threshold": guide_yellow,
        "simulation_success_green_threshold": runbook_green,
        "simulation_success_yellow_threshold": runbook_yellow,
        "readiness_target": readiness_target,
    }


def _parse_w11_readiness_policy_json(raw: Any) -> dict[str, Any]:
    try:
        loaded = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        loaded = {}
    return _normalize_w11_readiness_policy(loaded)


def _ensure_w11_readiness_policy(site: str | None) -> tuple[dict[str, Any], datetime, str, str | None]:
    policy_key, normalized_site = _w11_readiness_policy_key(site)
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(sla_policies).where(sla_policies.c.policy_key == policy_key).limit(1)
        ).mappings().first()
        if row is None:
            policy = _default_w11_readiness_policy()
            conn.execute(
                insert(sla_policies).values(
                    policy_key=policy_key,
                    policy_json=_to_json_text(policy),
                    updated_at=now,
                )
            )
            return policy, now, policy_key, normalized_site
    policy = _parse_w11_readiness_policy_json(row["policy_json"])
    updated_at = _as_datetime(row["updated_at"]) if row["updated_at"] is not None else now
    return policy, updated_at, policy_key, normalized_site


def _upsert_w11_readiness_policy(site: str | None, payload: dict[str, Any]) -> tuple[dict[str, Any], datetime, str, str | None]:
    current_policy, _, policy_key, normalized_site = _ensure_w11_readiness_policy(site)
    incoming = payload if isinstance(payload, dict) else {}
    merged: dict[str, Any] = {**current_policy}
    for key in [
        "enabled",
        "risk_rate_green_threshold",
        "risk_rate_yellow_threshold",
        "checklist_completion_green_threshold",
        "checklist_completion_yellow_threshold",
        "simulation_success_green_threshold",
        "simulation_success_yellow_threshold",
        "readiness_target",
    ]:
        if key in incoming:
            merged[key] = incoming[key]
    normalized = _normalize_w11_readiness_policy(merged)
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
    return normalized, now, policy_key, normalized_site


def _build_w11_scale_readiness_snapshot(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_days = max(14, min(int(days), 120))
    window_start = now - timedelta(days=window_days)
    policy, policy_updated_at, policy_key, policy_site = _ensure_w11_readiness_policy(site)

    effective_site = policy_site if policy_site is not None else _normalize_site_name(site)
    effective_allowed_sites = allowed_sites if effective_site is None else None

    stmt = select(work_orders).where(work_orders.c.created_at >= window_start)
    if effective_site is not None:
        stmt = stmt.where(work_orders.c.site == effective_site)
    elif effective_allowed_sites is not None:
        if not effective_allowed_sites:
            return {
                "generated_at": now.isoformat(),
                "site": None,
                "window_days": window_days,
                "policy": {
                    "policy_key": policy_key,
                    "updated_at": policy_updated_at.isoformat(),
                    "enabled": bool(policy.get("enabled", True)),
                },
                "metrics": {
                    "work_orders_count": 0,
                    "unique_titles": 0,
                    "repeated_work_orders_count": 0,
                    "risk_rate_percent": 0.0,
                    "guide_total_count": len(ADOPTION_W11_SELF_SERVE_GUIDES),
                    "guide_done_count": 0,
                    "checklist_completion_rate_percent": 0.0,
                    "runbook_total_count": len(ADOPTION_W11_TROUBLESHOOTING_RUNBOOK),
                    "runbook_done_count": 0,
                    "simulation_success_rate_percent": 0.0,
                    "scale_readiness_readiness_score": 0.0,
                    "overall_status": W11_READINESS_STATUS_RED,
                    "target_met": False,
                },
                "kpis": [],
                "top_repeat_titles": [],
                "scale_checklist": ADOPTION_W11_SELF_SERVE_GUIDES,
                "simulation_runbook": ADOPTION_W11_TROUBLESHOOTING_RUNBOOK,
                "recommendations": ["접근 가능한 site 범위가 비어 있습니다. site_scope를 확인하세요."],
            }
        stmt = stmt.where(work_orders.c.site.in_(effective_allowed_sites))
    with get_conn() as conn:
        wo_rows = conn.execute(stmt).mappings().all()

    title_counts: dict[str, int] = {}
    title_label: dict[str, str] = {}
    for row in wo_rows:
        title_raw = str(row.get("title") or "").strip()
        normalized = title_raw.lower() if title_raw else "(untitled)"
        title_counts[normalized] = title_counts.get(normalized, 0) + 1
        if normalized not in title_label:
            title_label[normalized] = title_raw or "(untitled)"

    total_work_orders = len(wo_rows)
    repeated_orders_count = sum(count for count in title_counts.values() if count >= 2)
    unique_titles = len(title_counts)
    risk_rate_percent = round((repeated_orders_count / total_work_orders) * 100.0, 2) if total_work_orders > 0 else 0.0
    top_repeat_titles = sorted(
        [
            {
                "title": title_label.get(key, key),
                "count": count,
                "share_percent": round((count / total_work_orders) * 100.0, 2) if total_work_orders > 0 else 0.0,
            }
            for key, count in title_counts.items()
            if count >= 2
        ],
        key=lambda item: int(item.get("count") or 0),
        reverse=True,
    )[:10]

    tracker_stmt = select(adoption_w11_tracker_items)
    if effective_site is not None:
        tracker_stmt = tracker_stmt.where(adoption_w11_tracker_items.c.site == effective_site)
    elif effective_allowed_sites is not None:
        tracker_stmt = tracker_stmt.where(adoption_w11_tracker_items.c.site.in_(effective_allowed_sites))
    with get_conn() as conn:
        tracker_rows = conn.execute(tracker_stmt).mappings().all()

    guide_total_count = max(
        len(ADOPTION_W11_SELF_SERVE_GUIDES),
        sum(1 for row in tracker_rows if str(row.get("item_type") or "") == "self_serve_guide"),
    )
    runbook_total_count = max(
        len(ADOPTION_W11_TROUBLESHOOTING_RUNBOOK),
        sum(1 for row in tracker_rows if str(row.get("item_type") or "") == "troubleshooting_runbook"),
    )
    guide_done_count = sum(
        1
        for row in tracker_rows
        if str(row.get("item_type") or "") == "self_serve_guide" and str(row.get("status") or "") == W11_TRACKER_STATUS_DONE
    )
    runbook_done_count = sum(
        1
        for row in tracker_rows
        if str(row.get("item_type") or "") == "troubleshooting_runbook" and str(row.get("status") or "") == W11_TRACKER_STATUS_DONE
    )
    checklist_completion_rate_percent = round((guide_done_count / guide_total_count) * 100.0, 2) if guide_total_count > 0 else 0.0
    simulation_success_rate_percent = (
        round((runbook_done_count / runbook_total_count) * 100.0, 2) if runbook_total_count > 0 else 0.0
    )

    repeat_status = _evaluate_w09_kpi_status(
        actual=risk_rate_percent,
        direction="lower_better",
        green_threshold=float(policy.get("risk_rate_green_threshold") or 20.0),
        yellow_threshold=float(policy.get("risk_rate_yellow_threshold") or 30.0),
    )
    guide_status = _evaluate_w09_kpi_status(
        actual=checklist_completion_rate_percent,
        direction="higher_better",
        green_threshold=float(policy.get("checklist_completion_green_threshold") or 80.0),
        yellow_threshold=float(policy.get("checklist_completion_yellow_threshold") or 60.0),
    )
    runbook_status = _evaluate_w09_kpi_status(
        actual=simulation_success_rate_percent,
        direction="higher_better",
        green_threshold=float(policy.get("simulation_success_green_threshold") or 80.0),
        yellow_threshold=float(policy.get("simulation_success_yellow_threshold") or 60.0),
    )

    status_points = {
        W09_KPI_STATUS_RED: 0.0,
        W09_KPI_STATUS_YELLOW: 50.0,
        W09_KPI_STATUS_GREEN: 100.0,
    }
    scale_readiness_readiness_score = round(
        (status_points.get(repeat_status, 0.0) + status_points.get(guide_status, 0.0) + status_points.get(runbook_status, 0.0))
        / 3.0,
        2,
    )

    status_set = {repeat_status, guide_status, runbook_status}
    overall_status = W11_READINESS_STATUS_GREEN
    if W09_KPI_STATUS_RED in status_set:
        overall_status = W11_READINESS_STATUS_RED
    elif W09_KPI_STATUS_YELLOW in status_set:
        overall_status = W11_READINESS_STATUS_YELLOW

    readiness_target = float(policy.get("readiness_target") or 75.0)
    target_met = scale_readiness_readiness_score >= readiness_target and overall_status != W11_READINESS_STATUS_RED

    kpis = [
        {
            "kpi_key": "repeat_ticket_rate_percent",
            "kpi_name": "Repeat ticket rate",
            "direction": "lower_better",
            "actual_value": risk_rate_percent,
            "green_threshold": float(policy.get("risk_rate_green_threshold") or 20.0),
            "yellow_threshold": float(policy.get("risk_rate_yellow_threshold") or 30.0),
            "status": repeat_status,
            "target": f"<= {policy.get('risk_rate_green_threshold', 20.0)}%",
        },
        {
            "kpi_key": "checklist_completion_rate_percent",
            "kpi_name": "Self-serve guide publication rate",
            "direction": "higher_better",
            "actual_value": checklist_completion_rate_percent,
            "green_threshold": float(policy.get("checklist_completion_green_threshold") or 80.0),
            "yellow_threshold": float(policy.get("checklist_completion_yellow_threshold") or 60.0),
            "status": guide_status,
            "target": f">= {policy.get('checklist_completion_green_threshold', 80.0)}%",
        },
        {
            "kpi_key": "simulation_success_rate_percent",
            "kpi_name": "Runbook completion rate",
            "direction": "higher_better",
            "actual_value": simulation_success_rate_percent,
            "green_threshold": float(policy.get("simulation_success_green_threshold") or 80.0),
            "yellow_threshold": float(policy.get("simulation_success_yellow_threshold") or 60.0),
            "status": runbook_status,
            "target": f">= {policy.get('simulation_success_green_threshold', 80.0)}%",
        },
        {
            "kpi_key": "scale_readiness_readiness_score",
            "kpi_name": "Scale readiness readiness score",
            "direction": "higher_better",
            "actual_value": scale_readiness_readiness_score,
            "green_threshold": readiness_target,
            "yellow_threshold": max(0.0, readiness_target - 15.0),
            "status": _evaluate_w09_kpi_status(
                actual=scale_readiness_readiness_score,
                direction="higher_better",
                green_threshold=readiness_target,
                yellow_threshold=max(0.0, readiness_target - 15.0),
            ),
            "target": f">= {readiness_target}",
        },
    ]

    recommendations: list[str] = []
    if repeat_status == W09_KPI_STATUS_RED:
        recommendations.append("반복 티켓 비율이 높습니다. Top 반복 제목 3개를 FAQ/가이드로 우선 전환하세요.")
    if guide_status != W09_KPI_STATUS_GREEN:
        recommendations.append("Scale readiness guide 게시율이 낮습니다. 담당자와 마감일을 지정해 게시를 완료하세요.")
    if runbook_status != W09_KPI_STATUS_GREEN:
        recommendations.append("Runbook 완료율이 낮습니다. 모듈별 실습 드릴과 증빙 업로드를 마감하세요.")
    if not recommendations:
        recommendations.append("W11 Scale readiness 지원 전환 상태가 안정적입니다. 운영 리듬을 유지하세요.")

    return {
        "generated_at": now.isoformat(),
        "site": effective_site,
        "window_days": window_days,
        "policy": {
            "policy_key": policy_key,
            "updated_at": policy_updated_at.isoformat(),
            "enabled": bool(policy.get("enabled", True)),
            "readiness_target": readiness_target,
        },
        "metrics": {
            "work_orders_count": total_work_orders,
            "unique_titles": unique_titles,
            "repeated_work_orders_count": repeated_orders_count,
            "risk_rate_percent": risk_rate_percent,
            "guide_total_count": guide_total_count,
            "guide_done_count": guide_done_count,
            "checklist_completion_rate_percent": checklist_completion_rate_percent,
            "runbook_total_count": runbook_total_count,
            "runbook_done_count": runbook_done_count,
            "simulation_success_rate_percent": simulation_success_rate_percent,
            "scale_readiness_readiness_score": scale_readiness_readiness_score,
            "overall_status": overall_status,
            "target_met": target_met,
        },
        "kpis": kpis,
        "top_repeat_titles": top_repeat_titles,
        "scale_checklist": ADOPTION_W11_SELF_SERVE_GUIDES,
        "simulation_runbook": ADOPTION_W11_TROUBLESHOOTING_RUNBOOK,
        "recommendations": recommendations,
    }



def _w12_handoff_policy_key(site: str | None) -> tuple[str, str | None]:
    normalized_site = _normalize_site_name(site)
    if normalized_site is None:
        return W12_HANDOFF_POLICY_KEY_DEFAULT, None
    return f"{W12_HANDOFF_POLICY_KEY_SITE_PREFIX}{normalized_site}", normalized_site


def _default_w12_handoff_policy() -> dict[str, Any]:
    return {
        "enabled": True,
        "risk_rate_green_threshold": 20.0,
        "risk_rate_yellow_threshold": 30.0,
        "checklist_completion_green_threshold": 80.0,
        "checklist_completion_yellow_threshold": 60.0,
        "simulation_success_green_threshold": 80.0,
        "simulation_success_yellow_threshold": 60.0,
        "readiness_target": 75.0,
    }


def _normalize_w12_handoff_policy(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    defaults = _default_w12_handoff_policy()

    def _float_value(key: str, fallback: float, min_value: float, max_value: float) -> float:
        try:
            raw = float(source.get(key, fallback))
        except (TypeError, ValueError):
            raw = fallback
        return round(max(min_value, min(raw, max_value)), 2)

    repeat_green = _float_value(
        "risk_rate_green_threshold",
        float(defaults["risk_rate_green_threshold"]),
        0.0,
        100.0,
    )
    repeat_yellow = _float_value(
        "risk_rate_yellow_threshold",
        float(defaults["risk_rate_yellow_threshold"]),
        0.0,
        100.0,
    )
    if repeat_yellow < repeat_green:
        repeat_yellow = repeat_green

    guide_green = _float_value(
        "checklist_completion_green_threshold",
        float(defaults["checklist_completion_green_threshold"]),
        0.0,
        100.0,
    )
    guide_yellow = _float_value(
        "checklist_completion_yellow_threshold",
        float(defaults["checklist_completion_yellow_threshold"]),
        0.0,
        100.0,
    )
    if guide_yellow > guide_green:
        guide_yellow = guide_green

    runbook_green = _float_value(
        "simulation_success_green_threshold",
        float(defaults["simulation_success_green_threshold"]),
        0.0,
        100.0,
    )
    runbook_yellow = _float_value(
        "simulation_success_yellow_threshold",
        float(defaults["simulation_success_yellow_threshold"]),
        0.0,
        100.0,
    )
    if runbook_yellow > runbook_green:
        runbook_yellow = runbook_green

    readiness_target = _float_value(
        "readiness_target",
        float(defaults["readiness_target"]),
        0.0,
        100.0,
    )

    return {
        "enabled": bool(source.get("enabled", defaults.get("enabled", True))),
        "risk_rate_green_threshold": repeat_green,
        "risk_rate_yellow_threshold": repeat_yellow,
        "checklist_completion_green_threshold": guide_green,
        "checklist_completion_yellow_threshold": guide_yellow,
        "simulation_success_green_threshold": runbook_green,
        "simulation_success_yellow_threshold": runbook_yellow,
        "readiness_target": readiness_target,
    }


def _parse_w12_handoff_policy_json(raw: Any) -> dict[str, Any]:
    try:
        loaded = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        loaded = {}
    return _normalize_w12_handoff_policy(loaded)


def _ensure_w12_handoff_policy(site: str | None) -> tuple[dict[str, Any], datetime, str, str | None]:
    policy_key, normalized_site = _w12_handoff_policy_key(site)
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(sla_policies).where(sla_policies.c.policy_key == policy_key).limit(1)
        ).mappings().first()
        if row is None:
            policy = _default_w12_handoff_policy()
            conn.execute(
                insert(sla_policies).values(
                    policy_key=policy_key,
                    policy_json=_to_json_text(policy),
                    updated_at=now,
                )
            )
            return policy, now, policy_key, normalized_site
    policy = _parse_w12_handoff_policy_json(row["policy_json"])
    updated_at = _as_datetime(row["updated_at"]) if row["updated_at"] is not None else now
    return policy, updated_at, policy_key, normalized_site


def _upsert_w12_handoff_policy(site: str | None, payload: dict[str, Any]) -> tuple[dict[str, Any], datetime, str, str | None]:
    current_policy, _, policy_key, normalized_site = _ensure_w12_handoff_policy(site)
    incoming = payload if isinstance(payload, dict) else {}
    merged: dict[str, Any] = {**current_policy}
    for key in [
        "enabled",
        "risk_rate_green_threshold",
        "risk_rate_yellow_threshold",
        "checklist_completion_green_threshold",
        "checklist_completion_yellow_threshold",
        "simulation_success_green_threshold",
        "simulation_success_yellow_threshold",
        "readiness_target",
    ]:
        if key in incoming:
            merged[key] = incoming[key]
    normalized = _normalize_w12_handoff_policy(merged)
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
    return normalized, now, policy_key, normalized_site


def _build_w12_closure_handoff_snapshot(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_days = max(14, min(int(days), 120))
    window_start = now - timedelta(days=window_days)
    policy, policy_updated_at, policy_key, policy_site = _ensure_w12_handoff_policy(site)

    effective_site = policy_site if policy_site is not None else _normalize_site_name(site)
    effective_allowed_sites = allowed_sites if effective_site is None else None

    stmt = select(work_orders).where(work_orders.c.created_at >= window_start)
    if effective_site is not None:
        stmt = stmt.where(work_orders.c.site == effective_site)
    elif effective_allowed_sites is not None:
        if not effective_allowed_sites:
            return {
                "generated_at": now.isoformat(),
                "site": None,
                "window_days": window_days,
                "policy": {
                    "policy_key": policy_key,
                    "updated_at": policy_updated_at.isoformat(),
                    "enabled": bool(policy.get("enabled", True)),
                },
                "metrics": {
                    "work_orders_count": 0,
                    "unique_titles": 0,
                    "repeated_work_orders_count": 0,
                    "risk_rate_percent": 0.0,
                    "guide_total_count": len(ADOPTION_W12_SELF_SERVE_GUIDES),
                    "guide_done_count": 0,
                    "checklist_completion_rate_percent": 0.0,
                    "runbook_total_count": len(ADOPTION_W12_TROUBLESHOOTING_RUNBOOK),
                    "runbook_done_count": 0,
                    "simulation_success_rate_percent": 0.0,
                    "closure_handoff_readiness_score": 0.0,
                    "overall_status": W12_HANDOFF_STATUS_RED,
                    "target_met": False,
                },
                "kpis": [],
                "top_repeat_titles": [],
                "scale_checklist": ADOPTION_W12_SELF_SERVE_GUIDES,
                "simulation_runbook": ADOPTION_W12_TROUBLESHOOTING_RUNBOOK,
                "recommendations": ["접근 가능한 site 범위가 비어 있습니다. site_scope를 확인하세요."],
            }
        stmt = stmt.where(work_orders.c.site.in_(effective_allowed_sites))
    with get_conn() as conn:
        wo_rows = conn.execute(stmt).mappings().all()

    title_counts: dict[str, int] = {}
    title_label: dict[str, str] = {}
    for row in wo_rows:
        title_raw = str(row.get("title") or "").strip()
        normalized = title_raw.lower() if title_raw else "(untitled)"
        title_counts[normalized] = title_counts.get(normalized, 0) + 1
        if normalized not in title_label:
            title_label[normalized] = title_raw or "(untitled)"

    total_work_orders = len(wo_rows)
    repeated_orders_count = sum(count for count in title_counts.values() if count >= 2)
    unique_titles = len(title_counts)
    risk_rate_percent = round((repeated_orders_count / total_work_orders) * 100.0, 2) if total_work_orders > 0 else 0.0
    top_repeat_titles = sorted(
        [
            {
                "title": title_label.get(key, key),
                "count": count,
                "share_percent": round((count / total_work_orders) * 100.0, 2) if total_work_orders > 0 else 0.0,
            }
            for key, count in title_counts.items()
            if count >= 2
        ],
        key=lambda item: int(item.get("count") or 0),
        reverse=True,
    )[:10]

    tracker_stmt = select(adoption_w12_tracker_items)
    if effective_site is not None:
        tracker_stmt = tracker_stmt.where(adoption_w12_tracker_items.c.site == effective_site)
    elif effective_allowed_sites is not None:
        tracker_stmt = tracker_stmt.where(adoption_w12_tracker_items.c.site.in_(effective_allowed_sites))
    with get_conn() as conn:
        tracker_rows = conn.execute(tracker_stmt).mappings().all()

    guide_total_count = max(
        len(ADOPTION_W12_SELF_SERVE_GUIDES),
        sum(1 for row in tracker_rows if str(row.get("item_type") or "") == "self_serve_guide"),
    )
    runbook_total_count = max(
        len(ADOPTION_W12_TROUBLESHOOTING_RUNBOOK),
        sum(1 for row in tracker_rows if str(row.get("item_type") or "") == "troubleshooting_runbook"),
    )
    guide_done_count = sum(
        1
        for row in tracker_rows
        if str(row.get("item_type") or "") == "self_serve_guide" and str(row.get("status") or "") == W12_TRACKER_STATUS_DONE
    )
    runbook_done_count = sum(
        1
        for row in tracker_rows
        if str(row.get("item_type") or "") == "troubleshooting_runbook" and str(row.get("status") or "") == W12_TRACKER_STATUS_DONE
    )
    checklist_completion_rate_percent = round((guide_done_count / guide_total_count) * 100.0, 2) if guide_total_count > 0 else 0.0
    simulation_success_rate_percent = (
        round((runbook_done_count / runbook_total_count) * 100.0, 2) if runbook_total_count > 0 else 0.0
    )

    repeat_status = _evaluate_w09_kpi_status(
        actual=risk_rate_percent,
        direction="lower_better",
        green_threshold=float(policy.get("risk_rate_green_threshold") or 20.0),
        yellow_threshold=float(policy.get("risk_rate_yellow_threshold") or 30.0),
    )
    guide_status = _evaluate_w09_kpi_status(
        actual=checklist_completion_rate_percent,
        direction="higher_better",
        green_threshold=float(policy.get("checklist_completion_green_threshold") or 80.0),
        yellow_threshold=float(policy.get("checklist_completion_yellow_threshold") or 60.0),
    )
    runbook_status = _evaluate_w09_kpi_status(
        actual=simulation_success_rate_percent,
        direction="higher_better",
        green_threshold=float(policy.get("simulation_success_green_threshold") or 80.0),
        yellow_threshold=float(policy.get("simulation_success_yellow_threshold") or 60.0),
    )

    status_points = {
        W09_KPI_STATUS_RED: 0.0,
        W09_KPI_STATUS_YELLOW: 50.0,
        W09_KPI_STATUS_GREEN: 100.0,
    }
    closure_handoff_readiness_score = round(
        (status_points.get(repeat_status, 0.0) + status_points.get(guide_status, 0.0) + status_points.get(runbook_status, 0.0))
        / 3.0,
        2,
    )

    status_set = {repeat_status, guide_status, runbook_status}
    overall_status = W12_HANDOFF_STATUS_GREEN
    if W09_KPI_STATUS_RED in status_set:
        overall_status = W12_HANDOFF_STATUS_RED
    elif W09_KPI_STATUS_YELLOW in status_set:
        overall_status = W12_HANDOFF_STATUS_YELLOW

    readiness_target = float(policy.get("readiness_target") or 75.0)
    target_met = closure_handoff_readiness_score >= readiness_target and overall_status != W12_HANDOFF_STATUS_RED

    kpis = [
        {
            "kpi_key": "repeat_ticket_rate_percent",
            "kpi_name": "Repeat ticket rate",
            "direction": "lower_better",
            "actual_value": risk_rate_percent,
            "green_threshold": float(policy.get("risk_rate_green_threshold") or 20.0),
            "yellow_threshold": float(policy.get("risk_rate_yellow_threshold") or 30.0),
            "status": repeat_status,
            "target": f"<= {policy.get('risk_rate_green_threshold', 20.0)}%",
        },
        {
            "kpi_key": "checklist_completion_rate_percent",
            "kpi_name": "Scale readiness guide publish rate",
            "direction": "higher_better",
            "actual_value": checklist_completion_rate_percent,
            "green_threshold": float(policy.get("checklist_completion_green_threshold") or 80.0),
            "yellow_threshold": float(policy.get("checklist_completion_yellow_threshold") or 60.0),
            "status": guide_status,
            "target": f">= {policy.get('checklist_completion_green_threshold', 80.0)}%",
        },
        {
            "kpi_key": "simulation_success_rate_percent",
            "kpi_name": "Runbook completion rate",
            "direction": "higher_better",
            "actual_value": simulation_success_rate_percent,
            "green_threshold": float(policy.get("simulation_success_green_threshold") or 80.0),
            "yellow_threshold": float(policy.get("simulation_success_yellow_threshold") or 60.0),
            "status": runbook_status,
            "target": f">= {policy.get('simulation_success_green_threshold', 80.0)}%",
        },
        {
            "kpi_key": "closure_handoff_readiness_score",
            "kpi_name": "Scale readiness readiness score",
            "direction": "higher_better",
            "actual_value": closure_handoff_readiness_score,
            "green_threshold": readiness_target,
            "yellow_threshold": max(0.0, readiness_target - 15.0),
            "status": _evaluate_w09_kpi_status(
                actual=closure_handoff_readiness_score,
                direction="higher_better",
                green_threshold=readiness_target,
                yellow_threshold=max(0.0, readiness_target - 15.0),
            ),
            "target": f">= {readiness_target}",
        },
    ]

    recommendations: list[str] = []
    if repeat_status == W09_KPI_STATUS_RED:
        recommendations.append("반복 티켓 비율이 높습니다. Top 반복 제목 3개를 FAQ/가이드로 우선 전환하세요.")
    if guide_status != W09_KPI_STATUS_GREEN:
        recommendations.append("Scale readiness guide 게시율이 낮습니다. 담당자와 마감일을 지정해 게시를 완료하세요.")
    if runbook_status != W09_KPI_STATUS_GREEN:
        recommendations.append("Runbook 완료율이 낮습니다. 모듈별 실습 드릴과 증빙 업로드를 마감하세요.")
    if not recommendations:
        recommendations.append("W12 Scale readiness 지원 전환 상태가 안정적입니다. 운영 리듬을 유지하세요.")

    return {
        "generated_at": now.isoformat(),
        "site": effective_site,
        "window_days": window_days,
        "policy": {
            "policy_key": policy_key,
            "updated_at": policy_updated_at.isoformat(),
            "enabled": bool(policy.get("enabled", True)),
            "readiness_target": readiness_target,
        },
        "metrics": {
            "work_orders_count": total_work_orders,
            "unique_titles": unique_titles,
            "repeated_work_orders_count": repeated_orders_count,
            "risk_rate_percent": risk_rate_percent,
            "guide_total_count": guide_total_count,
            "guide_done_count": guide_done_count,
            "checklist_completion_rate_percent": checklist_completion_rate_percent,
            "runbook_total_count": runbook_total_count,
            "runbook_done_count": runbook_done_count,
            "simulation_success_rate_percent": simulation_success_rate_percent,
            "closure_handoff_readiness_score": closure_handoff_readiness_score,
            "overall_status": overall_status,
            "target_met": target_met,
        },
        "kpis": kpis,
        "top_repeat_titles": top_repeat_titles,
        "scale_checklist": ADOPTION_W12_SELF_SERVE_GUIDES,
        "simulation_runbook": ADOPTION_W12_TROUBLESHOOTING_RUNBOOK,
        "recommendations": recommendations,
    }
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
    merged_raw = ALERT_WEBHOOK_URLS.replace(";", ",").replace("\n", ",")
    for part in merged_raw.split(","):
        value = part.strip()
        if value:
            target_specs.append(value)
    if ALERT_WEBHOOK_URL:
        target_specs.append(ALERT_WEBHOOK_URL)

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
    if ALERT_WEBHOOK_SHARED_TOKEN:
        headers[ALERT_WEBHOOK_TOKEN_HEADER] = ALERT_WEBHOOK_SHARED_TOKEN
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
        W07_DEGRADATION_ALERT_EVENT_TYPE: "W07 quality degradation alert",
        "ops_daily_check": "Ops daily check alert",
        "mttr_slo_breach": "Alert MTTR SLO breach",
        OPS_GOVERNANCE_REMEDIATION_ESCALATION_EVENT_TYPE: "Governance remediation escalation",
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

    threshold = max(1, ALERT_CHANNEL_GUARD_FAIL_THRESHOLD)
    cooldown_minutes = max(1, ALERT_CHANNEL_GUARD_COOLDOWN_MINUTES)
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
        "state": state if ALERT_CHANNEL_GUARD_ENABLED else "disabled",
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
    if not ALERT_CHANNEL_GUARD_ENABLED:
        status = "warning" if warning_count > 0 else "ok"

    return {
        "generated_at": current_time.isoformat(),
        "event_type": event_type,
        "lookback_days": normalized_lookback_days,
        "policy": {
            "enabled": ALERT_CHANNEL_GUARD_ENABLED,
            "failure_threshold": max(1, ALERT_CHANNEL_GUARD_FAIL_THRESHOLD),
            "cooldown_minutes": max(1, ALERT_CHANNEL_GUARD_COOLDOWN_MINUTES),
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
    resolved_retention_days = max(1, int(retention_days if retention_days is not None else ALERT_RETENTION_DAYS))
    resolved_max_delete = max(1, min(int(max_delete if max_delete is not None else ALERT_RETENTION_MAX_DELETE), 50000))
    resolved_write_archive = ALERT_RETENTION_ARCHIVE_ENABLED if write_archive is None else bool(write_archive)
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
                archive_dir = Path(ALERT_RETENTION_ARCHIVE_PATH)
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
    resolved_max_targets = max(1, min(int(max_targets if max_targets is not None else ALERT_GUARD_RECOVER_MAX_TARGETS), 500))

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
            retries=ALERT_WEBHOOK_RETRIES,
            timeout_sec=ALERT_WEBHOOK_TIMEOUT_SEC,
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
            max_targets=int(policy.get("recover_max_targets") or ALERT_GUARD_RECOVER_MAX_TARGETS),
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
                        "recover_max_targets": int(policy.get("recover_max_targets") or ALERT_GUARD_RECOVER_MAX_TARGETS),
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
        if ALERT_CHANNEL_GUARD_ENABLED and str(guard_state.get("state_computed")) == "quarantined":
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
            retries=ALERT_WEBHOOK_RETRIES,
            timeout_sec=ALERT_WEBHOOK_TIMEOUT_SEC,
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


def _row_to_admin_user_model(row: dict[str, Any]) -> AdminUserRead:
    from app.domains.iam.service import _row_to_admin_user_model as _impl
    return _impl(row)


def _row_to_admin_token_model(row: dict[str, Any]) -> AdminTokenRead:
    from app.domains.iam.service import _row_to_admin_token_model as _impl
    return _impl(row)


def _row_to_work_order_model(row: dict[str, Any]) -> WorkOrderRead:
    return _ops_workflow_service_module()._row_to_work_order_model(row)


def _validate_work_order_transition(current_status: str, next_status: str) -> None:
    return _ops_workflow_service_module()._validate_work_order_transition(current_status, next_status)


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
    return _ops_workflow_service_module()._append_work_order_event(
        conn,
        work_order_id=work_order_id,
        event_type=event_type,
        actor_username=actor_username,
        from_status=from_status,
        to_status=to_status,
        note=note,
        detail=detail,
    )


def _row_to_work_order_event_model(row: dict[str, Any]) -> WorkOrderEventRead:
    return _ops_workflow_service_module()._row_to_work_order_event_model(row)


def _row_to_workflow_lock_model(row: dict[str, Any]) -> WorkflowLockRead:
    return _ops_workflow_service_module()._row_to_workflow_lock_model(row)


def _row_to_w02_tracker_item_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w02_tracker_item_model(*args, **kwargs)


def _row_to_w02_evidence_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w02_evidence_model(*args, **kwargs)


def _adoption_w02_catalog_items(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._adoption_w02_catalog_items(*args, **kwargs)


def _compute_w02_tracker_overview(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w02_tracker_overview(*args, **kwargs)


def _compute_w02_tracker_readiness(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w02_tracker_readiness(*args, **kwargs)


def _resolve_w02_site_completion_status(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._resolve_w02_site_completion_status(*args, **kwargs)


def _row_to_w02_completion_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w02_completion_model(*args, **kwargs)


def _load_w02_tracker_items_for_site(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._load_w02_tracker_items_for_site(*args, **kwargs)


def _reset_w02_completion_if_closed(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._reset_w02_completion_if_closed(*args, **kwargs)


def _row_to_w03_tracker_item_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w03_tracker_item_model(*args, **kwargs)


def _row_to_w03_evidence_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w03_evidence_model(*args, **kwargs)


def _adoption_w03_catalog_items(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._adoption_w03_catalog_items(*args, **kwargs)


def _compute_w03_tracker_overview(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w03_tracker_overview(*args, **kwargs)


def _compute_w03_tracker_readiness(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w03_tracker_readiness(*args, **kwargs)


def _resolve_w03_site_completion_status(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._resolve_w03_site_completion_status(*args, **kwargs)


def _row_to_w03_completion_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w03_completion_model(*args, **kwargs)


def _load_w03_tracker_items_for_site(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._load_w03_tracker_items_for_site(*args, **kwargs)


def _reset_w03_completion_if_closed(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._reset_w03_completion_if_closed(*args, **kwargs)


def _row_to_w04_tracker_item_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w04_tracker_item_model(*args, **kwargs)


def _row_to_w04_evidence_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w04_evidence_model(*args, **kwargs)


def _adoption_w04_catalog_items(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._adoption_w04_catalog_items(*args, **kwargs)


def _compute_w04_tracker_overview(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w04_tracker_overview(*args, **kwargs)


def _compute_w04_tracker_readiness(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w04_tracker_readiness(*args, **kwargs)


def _resolve_w04_site_completion_status(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._resolve_w04_site_completion_status(*args, **kwargs)


def _row_to_w04_completion_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w04_completion_model(*args, **kwargs)


def _load_w04_tracker_items_for_site(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._load_w04_tracker_items_for_site(*args, **kwargs)


def _reset_w04_completion_if_closed(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._reset_w04_completion_if_closed(*args, **kwargs)


def _row_to_w07_tracker_item_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w07_tracker_item_model(*args, **kwargs)


def _row_to_w07_evidence_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w07_evidence_model(*args, **kwargs)


def _adoption_w07_catalog_items(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._adoption_w07_catalog_items(*args, **kwargs)


def _compute_w07_tracker_overview(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w07_tracker_overview(*args, **kwargs)


def _compute_w07_tracker_readiness(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w07_tracker_readiness(*args, **kwargs)


def _resolve_w07_site_completion_status(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._resolve_w07_site_completion_status(*args, **kwargs)


def _row_to_w07_completion_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w07_completion_model(*args, **kwargs)


def _load_w07_tracker_items_for_site(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._load_w07_tracker_items_for_site(*args, **kwargs)


def _reset_w07_completion_if_closed(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._reset_w07_completion_if_closed(*args, **kwargs)


def _row_to_w09_tracker_item_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w09_tracker_item_model(*args, **kwargs)


def _row_to_w09_evidence_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w09_evidence_model(*args, **kwargs)


def _adoption_w09_catalog_items(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._adoption_w09_catalog_items(*args, **kwargs)


def _compute_w09_tracker_overview(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w09_tracker_overview(*args, **kwargs)


def _compute_w09_tracker_readiness(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w09_tracker_readiness(*args, **kwargs)


def _resolve_w09_site_completion_status(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._resolve_w09_site_completion_status(*args, **kwargs)


def _row_to_w09_completion_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w09_completion_model(*args, **kwargs)


def _load_w09_tracker_items_for_site(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._load_w09_tracker_items_for_site(*args, **kwargs)


def _reset_w09_completion_if_closed(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._reset_w09_completion_if_closed(*args, **kwargs)


def _row_to_w10_tracker_item_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w10_tracker_item_model(*args, **kwargs)


def _row_to_w10_evidence_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w10_evidence_model(*args, **kwargs)


def _adoption_w10_catalog_items(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._adoption_w10_catalog_items(*args, **kwargs)


def _compute_w10_tracker_overview(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w10_tracker_overview(*args, **kwargs)


def _compute_w10_tracker_readiness(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w10_tracker_readiness(*args, **kwargs)


def _resolve_w10_site_completion_status(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._resolve_w10_site_completion_status(*args, **kwargs)


def _row_to_w10_completion_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w10_completion_model(*args, **kwargs)


def _load_w10_tracker_items_for_site(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._load_w10_tracker_items_for_site(*args, **kwargs)


def _reset_w10_completion_if_closed(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._reset_w10_completion_if_closed(*args, **kwargs)


def _row_to_w11_tracker_item_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w11_tracker_item_model(*args, **kwargs)


def _row_to_w11_evidence_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w11_evidence_model(*args, **kwargs)


def _adoption_w11_catalog_items(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._adoption_w11_catalog_items(*args, **kwargs)


def _compute_w11_tracker_overview(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w11_tracker_overview(*args, **kwargs)


def _compute_w11_tracker_readiness(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w11_tracker_readiness(*args, **kwargs)


def _resolve_w11_site_completion_status(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._resolve_w11_site_completion_status(*args, **kwargs)


def _row_to_w11_completion_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w11_completion_model(*args, **kwargs)


def _load_w11_tracker_items_for_site(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._load_w11_tracker_items_for_site(*args, **kwargs)


def _reset_w11_completion_if_closed(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._reset_w11_completion_if_closed(*args, **kwargs)


def _row_to_w12_tracker_item_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w12_tracker_item_model(*args, **kwargs)


def _row_to_w12_evidence_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w12_evidence_model(*args, **kwargs)


def _adoption_w12_catalog_items(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._adoption_w12_catalog_items(*args, **kwargs)


def _compute_w12_tracker_overview(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w12_tracker_overview(*args, **kwargs)


def _compute_w12_tracker_readiness(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w12_tracker_readiness(*args, **kwargs)


def _resolve_w12_site_completion_status(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._resolve_w12_site_completion_status(*args, **kwargs)


def _row_to_w12_completion_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w12_completion_model(*args, **kwargs)


def _load_w12_tracker_items_for_site(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._load_w12_tracker_items_for_site(*args, **kwargs)


def _reset_w12_completion_if_closed(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._reset_w12_completion_if_closed(*args, **kwargs)


def _row_to_w13_tracker_item_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w13_tracker_item_model(*args, **kwargs)


def _row_to_w13_evidence_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w13_evidence_model(*args, **kwargs)


def _adoption_w13_catalog_items(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._adoption_w13_catalog_items(*args, **kwargs)


def _compute_w13_tracker_overview(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w13_tracker_overview(*args, **kwargs)


def _compute_w13_tracker_readiness(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w13_tracker_readiness(*args, **kwargs)


def _resolve_w13_site_completion_status(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._resolve_w13_site_completion_status(*args, **kwargs)


def _row_to_w13_completion_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w13_completion_model(*args, **kwargs)


def _load_w13_tracker_items_for_site(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._load_w13_tracker_items_for_site(*args, **kwargs)


def _reset_w13_completion_if_closed(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._reset_w13_completion_if_closed(*args, **kwargs)


def _row_to_w14_tracker_item_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w14_tracker_item_model(*args, **kwargs)


def _row_to_w14_evidence_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w14_evidence_model(*args, **kwargs)


def _adoption_w14_catalog_items(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._adoption_w14_catalog_items(*args, **kwargs)


def _compute_w14_tracker_overview(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w14_tracker_overview(*args, **kwargs)


def _compute_w14_tracker_readiness(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w14_tracker_readiness(*args, **kwargs)


def _resolve_w14_site_completion_status(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._resolve_w14_site_completion_status(*args, **kwargs)


def _row_to_w14_completion_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w14_completion_model(*args, **kwargs)


def _load_w14_tracker_items_for_site(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._load_w14_tracker_items_for_site(*args, **kwargs)


def _reset_w14_completion_if_closed(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._reset_w14_completion_if_closed(*args, **kwargs)


def _row_to_w15_tracker_item_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w15_tracker_item_model(*args, **kwargs)


def _row_to_w15_evidence_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w15_evidence_model(*args, **kwargs)


def _adoption_w15_catalog_items(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._adoption_w15_catalog_items(*args, **kwargs)


def _compute_w15_tracker_overview(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w15_tracker_overview(*args, **kwargs)


def _compute_w15_tracker_readiness(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._compute_w15_tracker_readiness(*args, **kwargs)


def _resolve_w15_site_completion_status(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._resolve_w15_site_completion_status(*args, **kwargs)


def _row_to_w15_completion_model(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._row_to_w15_completion_model(*args, **kwargs)


def _load_w15_tracker_items_for_site(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._load_w15_tracker_items_for_site(*args, **kwargs)


def _reset_w15_completion_if_closed(*args: Any, **kwargs: Any):
    return _adoption_tracker_service_module()._reset_w15_completion_if_closed(*args, **kwargs)


def _w13_handoff_policy_key(site: str | None) -> tuple[str, str | None]:
    normalized_site = _normalize_site_name(site)
    if normalized_site is None:
        return W13_HANDOFF_POLICY_KEY_DEFAULT, None
    return f"{W13_HANDOFF_POLICY_KEY_SITE_PREFIX}{normalized_site}", normalized_site


def _default_w13_handoff_policy() -> dict[str, Any]:
    return {
        "enabled": True,
        "risk_rate_green_threshold": 20.0,
        "risk_rate_yellow_threshold": 30.0,
        "checklist_completion_green_threshold": 80.0,
        "checklist_completion_yellow_threshold": 60.0,
        "simulation_success_green_threshold": 80.0,
        "simulation_success_yellow_threshold": 60.0,
        "readiness_target": 75.0,
    }


def _normalize_w13_handoff_policy(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    defaults = _default_w13_handoff_policy()

    def _float_value(key: str, fallback: float, min_value: float, max_value: float) -> float:
        try:
            raw = float(source.get(key, fallback))
        except (TypeError, ValueError):
            raw = fallback
        return round(max(min_value, min(raw, max_value)), 2)

    repeat_green = _float_value(
        "risk_rate_green_threshold",
        float(defaults["risk_rate_green_threshold"]),
        0.0,
        100.0,
    )
    repeat_yellow = _float_value(
        "risk_rate_yellow_threshold",
        float(defaults["risk_rate_yellow_threshold"]),
        0.0,
        100.0,
    )
    if repeat_yellow < repeat_green:
        repeat_yellow = repeat_green

    guide_green = _float_value(
        "checklist_completion_green_threshold",
        float(defaults["checklist_completion_green_threshold"]),
        0.0,
        100.0,
    )
    guide_yellow = _float_value(
        "checklist_completion_yellow_threshold",
        float(defaults["checklist_completion_yellow_threshold"]),
        0.0,
        100.0,
    )
    if guide_yellow > guide_green:
        guide_yellow = guide_green

    runbook_green = _float_value(
        "simulation_success_green_threshold",
        float(defaults["simulation_success_green_threshold"]),
        0.0,
        100.0,
    )
    runbook_yellow = _float_value(
        "simulation_success_yellow_threshold",
        float(defaults["simulation_success_yellow_threshold"]),
        0.0,
        100.0,
    )
    if runbook_yellow > runbook_green:
        runbook_yellow = runbook_green

    readiness_target = _float_value(
        "readiness_target",
        float(defaults["readiness_target"]),
        0.0,
        100.0,
    )

    return {
        "enabled": bool(source.get("enabled", defaults.get("enabled", True))),
        "risk_rate_green_threshold": repeat_green,
        "risk_rate_yellow_threshold": repeat_yellow,
        "checklist_completion_green_threshold": guide_green,
        "checklist_completion_yellow_threshold": guide_yellow,
        "simulation_success_green_threshold": runbook_green,
        "simulation_success_yellow_threshold": runbook_yellow,
        "readiness_target": readiness_target,
    }


def _parse_w13_handoff_policy_json(raw: Any) -> dict[str, Any]:
    try:
        loaded = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        loaded = {}
    return _normalize_w13_handoff_policy(loaded)


def _ensure_w13_handoff_policy(site: str | None) -> tuple[dict[str, Any], datetime, str, str | None]:
    policy_key, normalized_site = _w13_handoff_policy_key(site)
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(sla_policies).where(sla_policies.c.policy_key == policy_key).limit(1)
        ).mappings().first()
        if row is None:
            policy = _default_w13_handoff_policy()
            conn.execute(
                insert(sla_policies).values(
                    policy_key=policy_key,
                    policy_json=_to_json_text(policy),
                    updated_at=now,
                )
            )
            return policy, now, policy_key, normalized_site
    policy = _parse_w13_handoff_policy_json(row["policy_json"])
    updated_at = _as_datetime(row["updated_at"]) if row["updated_at"] is not None else now
    return policy, updated_at, policy_key, normalized_site


def _upsert_w13_handoff_policy(site: str | None, payload: dict[str, Any]) -> tuple[dict[str, Any], datetime, str, str | None]:
    current_policy, _, policy_key, normalized_site = _ensure_w13_handoff_policy(site)
    incoming = payload if isinstance(payload, dict) else {}
    merged: dict[str, Any] = {**current_policy}
    for key in [
        "enabled",
        "risk_rate_green_threshold",
        "risk_rate_yellow_threshold",
        "checklist_completion_green_threshold",
        "checklist_completion_yellow_threshold",
        "simulation_success_green_threshold",
        "simulation_success_yellow_threshold",
        "readiness_target",
    ]:
        if key in incoming:
            merged[key] = incoming[key]
    normalized = _normalize_w13_handoff_policy(merged)
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
    return normalized, now, policy_key, normalized_site


def _build_w13_closure_handoff_snapshot(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_days = max(14, min(int(days), 120))
    window_start = now - timedelta(days=window_days)
    policy, policy_updated_at, policy_key, policy_site = _ensure_w13_handoff_policy(site)

    effective_site = policy_site if policy_site is not None else _normalize_site_name(site)
    effective_allowed_sites = allowed_sites if effective_site is None else None

    stmt = select(work_orders).where(work_orders.c.created_at >= window_start)
    if effective_site is not None:
        stmt = stmt.where(work_orders.c.site == effective_site)
    elif effective_allowed_sites is not None:
        if not effective_allowed_sites:
            return {
                "generated_at": now.isoformat(),
                "site": None,
                "window_days": window_days,
                "policy": {
                    "policy_key": policy_key,
                    "updated_at": policy_updated_at.isoformat(),
                    "enabled": bool(policy.get("enabled", True)),
                },
                "metrics": {
                    "work_orders_count": 0,
                    "unique_titles": 0,
                    "repeated_work_orders_count": 0,
                    "risk_rate_percent": 0.0,
                    "guide_total_count": len(ADOPTION_W13_SELF_SERVE_GUIDES),
                    "guide_done_count": 0,
                    "checklist_completion_rate_percent": 0.0,
                    "runbook_total_count": len(ADOPTION_W13_TROUBLESHOOTING_RUNBOOK),
                    "runbook_done_count": 0,
                    "simulation_success_rate_percent": 0.0,
                    "closure_handoff_readiness_score": 0.0,
                    "overall_status": W13_HANDOFF_STATUS_RED,
                    "target_met": False,
                },
                "kpis": [],
                "top_repeat_titles": [],
                "scale_checklist": ADOPTION_W13_SELF_SERVE_GUIDES,
                "simulation_runbook": ADOPTION_W13_TROUBLESHOOTING_RUNBOOK,
                "recommendations": ["접근 가능한 site 범위가 비어 있습니다. site_scope를 확인하세요."],
            }
        stmt = stmt.where(work_orders.c.site.in_(effective_allowed_sites))
    with get_conn() as conn:
        wo_rows = conn.execute(stmt).mappings().all()

    title_counts: dict[str, int] = {}
    title_label: dict[str, str] = {}
    for row in wo_rows:
        title_raw = str(row.get("title") or "").strip()
        normalized = title_raw.lower() if title_raw else "(untitled)"
        title_counts[normalized] = title_counts.get(normalized, 0) + 1
        if normalized not in title_label:
            title_label[normalized] = title_raw or "(untitled)"

    total_work_orders = len(wo_rows)
    repeated_orders_count = sum(count for count in title_counts.values() if count >= 2)
    unique_titles = len(title_counts)
    risk_rate_percent = round((repeated_orders_count / total_work_orders) * 100.0, 2) if total_work_orders > 0 else 0.0
    top_repeat_titles = sorted(
        [
            {
                "title": title_label.get(key, key),
                "count": count,
                "share_percent": round((count / total_work_orders) * 100.0, 2) if total_work_orders > 0 else 0.0,
            }
            for key, count in title_counts.items()
            if count >= 2
        ],
        key=lambda item: int(item.get("count") or 0),
        reverse=True,
    )[:10]

    tracker_stmt = select(adoption_w13_tracker_items)
    if effective_site is not None:
        tracker_stmt = tracker_stmt.where(adoption_w13_tracker_items.c.site == effective_site)
    elif effective_allowed_sites is not None:
        tracker_stmt = tracker_stmt.where(adoption_w13_tracker_items.c.site.in_(effective_allowed_sites))
    with get_conn() as conn:
        tracker_rows = conn.execute(tracker_stmt).mappings().all()

    guide_total_count = max(
        len(ADOPTION_W13_SELF_SERVE_GUIDES),
        sum(1 for row in tracker_rows if str(row.get("item_type") or "") == "self_serve_guide"),
    )
    runbook_total_count = max(
        len(ADOPTION_W13_TROUBLESHOOTING_RUNBOOK),
        sum(1 for row in tracker_rows if str(row.get("item_type") or "") == "troubleshooting_runbook"),
    )
    guide_done_count = sum(
        1
        for row in tracker_rows
        if str(row.get("item_type") or "") == "self_serve_guide" and str(row.get("status") or "") == W13_TRACKER_STATUS_DONE
    )
    runbook_done_count = sum(
        1
        for row in tracker_rows
        if str(row.get("item_type") or "") == "troubleshooting_runbook" and str(row.get("status") or "") == W13_TRACKER_STATUS_DONE
    )
    checklist_completion_rate_percent = round((guide_done_count / guide_total_count) * 100.0, 2) if guide_total_count > 0 else 0.0
    simulation_success_rate_percent = (
        round((runbook_done_count / runbook_total_count) * 100.0, 2) if runbook_total_count > 0 else 0.0
    )

    repeat_status = _evaluate_w09_kpi_status(
        actual=risk_rate_percent,
        direction="lower_better",
        green_threshold=float(policy.get("risk_rate_green_threshold") or 20.0),
        yellow_threshold=float(policy.get("risk_rate_yellow_threshold") or 30.0),
    )
    guide_status = _evaluate_w09_kpi_status(
        actual=checklist_completion_rate_percent,
        direction="higher_better",
        green_threshold=float(policy.get("checklist_completion_green_threshold") or 80.0),
        yellow_threshold=float(policy.get("checklist_completion_yellow_threshold") or 60.0),
    )
    runbook_status = _evaluate_w09_kpi_status(
        actual=simulation_success_rate_percent,
        direction="higher_better",
        green_threshold=float(policy.get("simulation_success_green_threshold") or 80.0),
        yellow_threshold=float(policy.get("simulation_success_yellow_threshold") or 60.0),
    )

    status_points = {
        W09_KPI_STATUS_RED: 0.0,
        W09_KPI_STATUS_YELLOW: 50.0,
        W09_KPI_STATUS_GREEN: 100.0,
    }
    closure_handoff_readiness_score = round(
        (status_points.get(repeat_status, 0.0) + status_points.get(guide_status, 0.0) + status_points.get(runbook_status, 0.0))
        / 3.0,
        2,
    )

    status_set = {repeat_status, guide_status, runbook_status}
    overall_status = W13_HANDOFF_STATUS_GREEN
    if W09_KPI_STATUS_RED in status_set:
        overall_status = W13_HANDOFF_STATUS_RED
    elif W09_KPI_STATUS_YELLOW in status_set:
        overall_status = W13_HANDOFF_STATUS_YELLOW

    readiness_target = float(policy.get("readiness_target") or 75.0)
    target_met = closure_handoff_readiness_score >= readiness_target and overall_status != W13_HANDOFF_STATUS_RED

    kpis = [
        {
            "kpi_key": "repeat_ticket_rate_percent",
            "kpi_name": "Repeat ticket rate",
            "direction": "lower_better",
            "actual_value": risk_rate_percent,
            "green_threshold": float(policy.get("risk_rate_green_threshold") or 20.0),
            "yellow_threshold": float(policy.get("risk_rate_yellow_threshold") or 30.0),
            "status": repeat_status,
            "target": f"<= {policy.get('risk_rate_green_threshold', 20.0)}%",
        },
        {
            "kpi_key": "checklist_completion_rate_percent",
            "kpi_name": "Scale readiness guide publish rate",
            "direction": "higher_better",
            "actual_value": checklist_completion_rate_percent,
            "green_threshold": float(policy.get("checklist_completion_green_threshold") or 80.0),
            "yellow_threshold": float(policy.get("checklist_completion_yellow_threshold") or 60.0),
            "status": guide_status,
            "target": f">= {policy.get('checklist_completion_green_threshold', 80.0)}%",
        },
        {
            "kpi_key": "simulation_success_rate_percent",
            "kpi_name": "Runbook completion rate",
            "direction": "higher_better",
            "actual_value": simulation_success_rate_percent,
            "green_threshold": float(policy.get("simulation_success_green_threshold") or 80.0),
            "yellow_threshold": float(policy.get("simulation_success_yellow_threshold") or 60.0),
            "status": runbook_status,
            "target": f">= {policy.get('simulation_success_green_threshold', 80.0)}%",
        },
        {
            "kpi_key": "closure_handoff_readiness_score",
            "kpi_name": "Scale readiness readiness score",
            "direction": "higher_better",
            "actual_value": closure_handoff_readiness_score,
            "green_threshold": readiness_target,
            "yellow_threshold": max(0.0, readiness_target - 15.0),
            "status": _evaluate_w09_kpi_status(
                actual=closure_handoff_readiness_score,
                direction="higher_better",
                green_threshold=readiness_target,
                yellow_threshold=max(0.0, readiness_target - 15.0),
            ),
            "target": f">= {readiness_target}",
        },
    ]

    recommendations: list[str] = []
    if repeat_status == W09_KPI_STATUS_RED:
        recommendations.append("반복 티켓 비율이 높습니다. Top 반복 제목 3개를 FAQ/가이드로 우선 전환하세요.")
    if guide_status != W09_KPI_STATUS_GREEN:
        recommendations.append("Scale readiness guide 게시율이 낮습니다. 담당자와 마감일을 지정해 게시를 완료하세요.")
    if runbook_status != W09_KPI_STATUS_GREEN:
        recommendations.append("Runbook 완료율이 낮습니다. 모듈별 실습 드릴과 증빙 업로드를 마감하세요.")
    if not recommendations:
        recommendations.append("W13 지속 개선 상태가 안정적입니다. 운영 리듬을 유지하세요.")

    return {
        "generated_at": now.isoformat(),
        "site": effective_site,
        "window_days": window_days,
        "policy": {
            "policy_key": policy_key,
            "updated_at": policy_updated_at.isoformat(),
            "enabled": bool(policy.get("enabled", True)),
            "readiness_target": readiness_target,
        },
        "metrics": {
            "work_orders_count": total_work_orders,
            "unique_titles": unique_titles,
            "repeated_work_orders_count": repeated_orders_count,
            "risk_rate_percent": risk_rate_percent,
            "guide_total_count": guide_total_count,
            "guide_done_count": guide_done_count,
            "checklist_completion_rate_percent": checklist_completion_rate_percent,
            "runbook_total_count": runbook_total_count,
            "runbook_done_count": runbook_done_count,
            "simulation_success_rate_percent": simulation_success_rate_percent,
            "closure_handoff_readiness_score": closure_handoff_readiness_score,
            "overall_status": overall_status,
            "target_met": target_met,
        },
        "kpis": kpis,
        "top_repeat_titles": top_repeat_titles,
        "scale_checklist": ADOPTION_W13_SELF_SERVE_GUIDES,
        "simulation_runbook": ADOPTION_W13_TROUBLESHOOTING_RUNBOOK,
        "recommendations": recommendations,
    }
def _w14_stability_policy_key(site: str | None) -> tuple[str, str | None]:
    normalized_site = _normalize_site_name(site)
    if normalized_site is None:
        return W14_STABILITY_POLICY_KEY_DEFAULT, None
    return f"{W14_STABILITY_POLICY_KEY_SITE_PREFIX}{normalized_site}", normalized_site


def _default_w14_stability_policy() -> dict[str, Any]:
    return {
        "enabled": True,
        "risk_rate_green_threshold": 20.0,
        "risk_rate_yellow_threshold": 30.0,
        "checklist_completion_green_threshold": 80.0,
        "checklist_completion_yellow_threshold": 60.0,
        "simulation_success_green_threshold": 80.0,
        "simulation_success_yellow_threshold": 60.0,
        "readiness_target": 75.0,
    }


def _normalize_w14_stability_policy(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    defaults = _default_w14_stability_policy()

    def _float_value(key: str, fallback: float, min_value: float, max_value: float) -> float:
        try:
            raw = float(source.get(key, fallback))
        except (TypeError, ValueError):
            raw = fallback
        return round(max(min_value, min(raw, max_value)), 2)

    repeat_green = _float_value(
        "risk_rate_green_threshold",
        float(defaults["risk_rate_green_threshold"]),
        0.0,
        100.0,
    )
    repeat_yellow = _float_value(
        "risk_rate_yellow_threshold",
        float(defaults["risk_rate_yellow_threshold"]),
        0.0,
        100.0,
    )
    if repeat_yellow < repeat_green:
        repeat_yellow = repeat_green

    guide_green = _float_value(
        "checklist_completion_green_threshold",
        float(defaults["checklist_completion_green_threshold"]),
        0.0,
        100.0,
    )
    guide_yellow = _float_value(
        "checklist_completion_yellow_threshold",
        float(defaults["checklist_completion_yellow_threshold"]),
        0.0,
        100.0,
    )
    if guide_yellow > guide_green:
        guide_yellow = guide_green

    runbook_green = _float_value(
        "simulation_success_green_threshold",
        float(defaults["simulation_success_green_threshold"]),
        0.0,
        100.0,
    )
    runbook_yellow = _float_value(
        "simulation_success_yellow_threshold",
        float(defaults["simulation_success_yellow_threshold"]),
        0.0,
        100.0,
    )
    if runbook_yellow > runbook_green:
        runbook_yellow = runbook_green

    readiness_target = _float_value(
        "readiness_target",
        float(defaults["readiness_target"]),
        0.0,
        100.0,
    )

    return {
        "enabled": bool(source.get("enabled", defaults.get("enabled", True))),
        "risk_rate_green_threshold": repeat_green,
        "risk_rate_yellow_threshold": repeat_yellow,
        "checklist_completion_green_threshold": guide_green,
        "checklist_completion_yellow_threshold": guide_yellow,
        "simulation_success_green_threshold": runbook_green,
        "simulation_success_yellow_threshold": runbook_yellow,
        "readiness_target": readiness_target,
    }


def _parse_w14_stability_policy_json(raw: Any) -> dict[str, Any]:
    try:
        loaded = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        loaded = {}
    return _normalize_w14_stability_policy(loaded)


def _ensure_w14_stability_policy(site: str | None) -> tuple[dict[str, Any], datetime, str, str | None]:
    policy_key, normalized_site = _w14_stability_policy_key(site)
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(sla_policies).where(sla_policies.c.policy_key == policy_key).limit(1)
        ).mappings().first()
        if row is None:
            policy = _default_w14_stability_policy()
            conn.execute(
                insert(sla_policies).values(
                    policy_key=policy_key,
                    policy_json=_to_json_text(policy),
                    updated_at=now,
                )
            )
            return policy, now, policy_key, normalized_site
    policy = _parse_w14_stability_policy_json(row["policy_json"])
    updated_at = _as_datetime(row["updated_at"]) if row["updated_at"] is not None else now
    return policy, updated_at, policy_key, normalized_site


def _upsert_w14_stability_policy(site: str | None, payload: dict[str, Any]) -> tuple[dict[str, Any], datetime, str, str | None]:
    current_policy, _, policy_key, normalized_site = _ensure_w14_stability_policy(site)
    incoming = payload if isinstance(payload, dict) else {}
    merged: dict[str, Any] = {**current_policy}
    for key in [
        "enabled",
        "risk_rate_green_threshold",
        "risk_rate_yellow_threshold",
        "checklist_completion_green_threshold",
        "checklist_completion_yellow_threshold",
        "simulation_success_green_threshold",
        "simulation_success_yellow_threshold",
        "readiness_target",
    ]:
        if key in incoming:
            merged[key] = incoming[key]
    normalized = _normalize_w14_stability_policy(merged)
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
    return normalized, now, policy_key, normalized_site


def _build_w14_stability_sprint_snapshot(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_days = max(14, min(int(days), 120))
    window_start = now - timedelta(days=window_days)
    policy, policy_updated_at, policy_key, policy_site = _ensure_w14_stability_policy(site)

    effective_site = policy_site if policy_site is not None else _normalize_site_name(site)
    effective_allowed_sites = allowed_sites if effective_site is None else None

    stmt = select(work_orders).where(work_orders.c.created_at >= window_start)
    if effective_site is not None:
        stmt = stmt.where(work_orders.c.site == effective_site)
    elif effective_allowed_sites is not None:
        if not effective_allowed_sites:
            return {
                "generated_at": now.isoformat(),
                "site": None,
                "window_days": window_days,
                "policy": {
                    "policy_key": policy_key,
                    "updated_at": policy_updated_at.isoformat(),
                    "enabled": bool(policy.get("enabled", True)),
                },
                "metrics": {
                    "incidents_count": 0,
                    "unique_titles": 0,
                    "repeated_incidents_count": 0,
                    "incident_repeat_rate_percent": 0.0,
                    "guide_total_count": len(ADOPTION_W14_SELF_SERVE_GUIDES),
                    "guide_done_count": 0,
                    "checklist_completion_rate_percent": 0.0,
                    "runbook_total_count": len(ADOPTION_W14_TROUBLESHOOTING_RUNBOOK),
                    "runbook_done_count": 0,
                    "simulation_success_rate_percent": 0.0,
                    "stability_sprint_readiness_score": 0.0,
                    "overall_status": W14_STABILITY_STATUS_RED,
                    "target_met": False,
                },
                "kpis": [],
                "top_repeat_incidents": [],
                "scale_checklist": ADOPTION_W14_SELF_SERVE_GUIDES,
                "simulation_runbook": ADOPTION_W14_TROUBLESHOOTING_RUNBOOK,
                "recommendations": ["접근 가능한 site 범위가 비어 있습니다. site_scope를 확인하세요."],
            }
        stmt = stmt.where(work_orders.c.site.in_(effective_allowed_sites))
    with get_conn() as conn:
        wo_rows = conn.execute(stmt).mappings().all()

    title_counts: dict[str, int] = {}
    title_label: dict[str, str] = {}
    for row in wo_rows:
        title_raw = str(row.get("title") or "").strip()
        normalized = title_raw.lower() if title_raw else "(untitled)"
        title_counts[normalized] = title_counts.get(normalized, 0) + 1
        if normalized not in title_label:
            title_label[normalized] = title_raw or "(untitled)"

    total_work_orders = len(wo_rows)
    repeated_orders_count = sum(count for count in title_counts.values() if count >= 2)
    unique_titles = len(title_counts)
    incident_repeat_rate_percent = round((repeated_orders_count / total_work_orders) * 100.0, 2) if total_work_orders > 0 else 0.0
    top_repeat_incidents = sorted(
        [
            {
                "title": title_label.get(key, key),
                "count": count,
                "share_percent": round((count / total_work_orders) * 100.0, 2) if total_work_orders > 0 else 0.0,
            }
            for key, count in title_counts.items()
            if count >= 2
        ],
        key=lambda item: int(item.get("count") or 0),
        reverse=True,
    )[:10]

    tracker_stmt = select(adoption_w14_tracker_items)
    if effective_site is not None:
        tracker_stmt = tracker_stmt.where(adoption_w14_tracker_items.c.site == effective_site)
    elif effective_allowed_sites is not None:
        tracker_stmt = tracker_stmt.where(adoption_w14_tracker_items.c.site.in_(effective_allowed_sites))
    with get_conn() as conn:
        tracker_rows = conn.execute(tracker_stmt).mappings().all()

    guide_total_count = max(
        len(ADOPTION_W14_SELF_SERVE_GUIDES),
        sum(1 for row in tracker_rows if str(row.get("item_type") or "") == "self_serve_guide"),
    )
    runbook_total_count = max(
        len(ADOPTION_W14_TROUBLESHOOTING_RUNBOOK),
        sum(1 for row in tracker_rows if str(row.get("item_type") or "") == "troubleshooting_runbook"),
    )
    guide_done_count = sum(
        1
        for row in tracker_rows
        if str(row.get("item_type") or "") == "self_serve_guide" and str(row.get("status") or "") == W14_TRACKER_STATUS_DONE
    )
    runbook_done_count = sum(
        1
        for row in tracker_rows
        if str(row.get("item_type") or "") == "troubleshooting_runbook" and str(row.get("status") or "") == W14_TRACKER_STATUS_DONE
    )
    checklist_completion_rate_percent = round((guide_done_count / guide_total_count) * 100.0, 2) if guide_total_count > 0 else 0.0
    simulation_success_rate_percent = (
        round((runbook_done_count / runbook_total_count) * 100.0, 2) if runbook_total_count > 0 else 0.0
    )

    repeat_status = _evaluate_w09_kpi_status(
        actual=incident_repeat_rate_percent,
        direction="lower_better",
        green_threshold=float(policy.get("risk_rate_green_threshold") or 20.0),
        yellow_threshold=float(policy.get("risk_rate_yellow_threshold") or 30.0),
    )
    guide_status = _evaluate_w09_kpi_status(
        actual=checklist_completion_rate_percent,
        direction="higher_better",
        green_threshold=float(policy.get("checklist_completion_green_threshold") or 80.0),
        yellow_threshold=float(policy.get("checklist_completion_yellow_threshold") or 60.0),
    )
    runbook_status = _evaluate_w09_kpi_status(
        actual=simulation_success_rate_percent,
        direction="higher_better",
        green_threshold=float(policy.get("simulation_success_green_threshold") or 80.0),
        yellow_threshold=float(policy.get("simulation_success_yellow_threshold") or 60.0),
    )

    status_points = {
        W09_KPI_STATUS_RED: 0.0,
        W09_KPI_STATUS_YELLOW: 50.0,
        W09_KPI_STATUS_GREEN: 100.0,
    }
    stability_sprint_readiness_score = round(
        (status_points.get(repeat_status, 0.0) + status_points.get(guide_status, 0.0) + status_points.get(runbook_status, 0.0))
        / 3.0,
        2,
    )

    status_set = {repeat_status, guide_status, runbook_status}
    overall_status = W14_STABILITY_STATUS_GREEN
    if W09_KPI_STATUS_RED in status_set:
        overall_status = W14_STABILITY_STATUS_RED
    elif W09_KPI_STATUS_YELLOW in status_set:
        overall_status = W14_STABILITY_STATUS_YELLOW

    readiness_target = float(policy.get("readiness_target") or 75.0)
    target_met = stability_sprint_readiness_score >= readiness_target and overall_status != W14_STABILITY_STATUS_RED

    kpis = [
        {
            "kpi_key": "repeat_ticket_rate_percent",
            "kpi_name": "Repeat ticket rate",
            "direction": "lower_better",
            "actual_value": incident_repeat_rate_percent,
            "green_threshold": float(policy.get("risk_rate_green_threshold") or 20.0),
            "yellow_threshold": float(policy.get("risk_rate_yellow_threshold") or 30.0),
            "status": repeat_status,
            "target": f"<= {policy.get('risk_rate_green_threshold', 20.0)}%",
        },
        {
            "kpi_key": "checklist_completion_rate_percent",
            "kpi_name": "Scale readiness guide publish rate",
            "direction": "higher_better",
            "actual_value": checklist_completion_rate_percent,
            "green_threshold": float(policy.get("checklist_completion_green_threshold") or 80.0),
            "yellow_threshold": float(policy.get("checklist_completion_yellow_threshold") or 60.0),
            "status": guide_status,
            "target": f">= {policy.get('checklist_completion_green_threshold', 80.0)}%",
        },
        {
            "kpi_key": "simulation_success_rate_percent",
            "kpi_name": "Runbook completion rate",
            "direction": "higher_better",
            "actual_value": simulation_success_rate_percent,
            "green_threshold": float(policy.get("simulation_success_green_threshold") or 80.0),
            "yellow_threshold": float(policy.get("simulation_success_yellow_threshold") or 60.0),
            "status": runbook_status,
            "target": f">= {policy.get('simulation_success_green_threshold', 80.0)}%",
        },
        {
            "kpi_key": "stability_sprint_readiness_score",
            "kpi_name": "Scale readiness readiness score",
            "direction": "higher_better",
            "actual_value": stability_sprint_readiness_score,
            "green_threshold": readiness_target,
            "yellow_threshold": max(0.0, readiness_target - 15.0),
            "status": _evaluate_w09_kpi_status(
                actual=stability_sprint_readiness_score,
                direction="higher_better",
                green_threshold=readiness_target,
                yellow_threshold=max(0.0, readiness_target - 15.0),
            ),
            "target": f">= {readiness_target}",
        },
    ]

    recommendations: list[str] = []
    if repeat_status == W09_KPI_STATUS_RED:
        recommendations.append("반복 티켓 비율이 높습니다. Top 반복 제목 3개를 FAQ/가이드로 우선 전환하세요.")
    if guide_status != W09_KPI_STATUS_GREEN:
        recommendations.append("Scale readiness guide 게시율이 낮습니다. 담당자와 마감일을 지정해 게시를 완료하세요.")
    if runbook_status != W09_KPI_STATUS_GREEN:
        recommendations.append("Runbook 완료율이 낮습니다. 모듈별 실습 드릴과 증빙 업로드를 마감하세요.")
    if not recommendations:
        recommendations.append("W14 안정화 스프린트 상태가 안정적입니다. 운영 리듬을 유지하세요.")

    return {
        "generated_at": now.isoformat(),
        "site": effective_site,
        "window_days": window_days,
        "policy": {
            "policy_key": policy_key,
            "updated_at": policy_updated_at.isoformat(),
            "enabled": bool(policy.get("enabled", True)),
            "readiness_target": readiness_target,
        },
        "metrics": {
            "incidents_count": total_work_orders,
            "unique_titles": unique_titles,
            "repeated_incidents_count": repeated_orders_count,
            "incident_repeat_rate_percent": incident_repeat_rate_percent,
            "guide_total_count": guide_total_count,
            "guide_done_count": guide_done_count,
            "checklist_completion_rate_percent": checklist_completion_rate_percent,
            "runbook_total_count": runbook_total_count,
            "runbook_done_count": runbook_done_count,
            "simulation_success_rate_percent": simulation_success_rate_percent,
            "stability_sprint_readiness_score": stability_sprint_readiness_score,
            "overall_status": overall_status,
            "target_met": target_met,
        },
        "kpis": kpis,
        "top_repeat_incidents": top_repeat_incidents,
        "scale_checklist": ADOPTION_W14_SELF_SERVE_GUIDES,
        "simulation_runbook": ADOPTION_W14_TROUBLESHOOTING_RUNBOOK,
        "recommendations": recommendations,
    }


def _w15_efficiency_policy_key(site: str | None) -> tuple[str, str | None]:
    normalized_site = _normalize_site_name(site)
    if normalized_site is None:
        return W15_EFFICIENCY_POLICY_KEY_DEFAULT, None
    return f"{W15_EFFICIENCY_POLICY_KEY_SITE_PREFIX}{normalized_site}", normalized_site


def _default_w15_efficiency_policy() -> dict[str, Any]:
    return {
        "enabled": True,
        "risk_rate_green_threshold": 20.0,
        "risk_rate_yellow_threshold": 30.0,
        "checklist_completion_green_threshold": 80.0,
        "checklist_completion_yellow_threshold": 60.0,
        "simulation_success_green_threshold": 80.0,
        "simulation_success_yellow_threshold": 60.0,
        "readiness_target": 75.0,
    }


def _normalize_w15_efficiency_policy(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    defaults = _default_w15_efficiency_policy()

    def _float_value(key: str, fallback: float, min_value: float, max_value: float) -> float:
        try:
            raw = float(source.get(key, fallback))
        except (TypeError, ValueError):
            raw = fallback
        return round(max(min_value, min(raw, max_value)), 2)

    repeat_green = _float_value(
        "risk_rate_green_threshold",
        float(defaults["risk_rate_green_threshold"]),
        0.0,
        100.0,
    )
    repeat_yellow = _float_value(
        "risk_rate_yellow_threshold",
        float(defaults["risk_rate_yellow_threshold"]),
        0.0,
        100.0,
    )
    if repeat_yellow < repeat_green:
        repeat_yellow = repeat_green

    guide_green = _float_value(
        "checklist_completion_green_threshold",
        float(defaults["checklist_completion_green_threshold"]),
        0.0,
        100.0,
    )
    guide_yellow = _float_value(
        "checklist_completion_yellow_threshold",
        float(defaults["checklist_completion_yellow_threshold"]),
        0.0,
        100.0,
    )
    if guide_yellow > guide_green:
        guide_yellow = guide_green

    runbook_green = _float_value(
        "simulation_success_green_threshold",
        float(defaults["simulation_success_green_threshold"]),
        0.0,
        100.0,
    )
    runbook_yellow = _float_value(
        "simulation_success_yellow_threshold",
        float(defaults["simulation_success_yellow_threshold"]),
        0.0,
        100.0,
    )
    if runbook_yellow > runbook_green:
        runbook_yellow = runbook_green

    readiness_target = _float_value(
        "readiness_target",
        float(defaults["readiness_target"]),
        0.0,
        100.0,
    )

    return {
        "enabled": bool(source.get("enabled", defaults.get("enabled", True))),
        "risk_rate_green_threshold": repeat_green,
        "risk_rate_yellow_threshold": repeat_yellow,
        "checklist_completion_green_threshold": guide_green,
        "checklist_completion_yellow_threshold": guide_yellow,
        "simulation_success_green_threshold": runbook_green,
        "simulation_success_yellow_threshold": runbook_yellow,
        "readiness_target": readiness_target,
    }


def _parse_w15_efficiency_policy_json(raw: Any) -> dict[str, Any]:
    try:
        loaded = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        loaded = {}
    return _normalize_w15_efficiency_policy(loaded)


def _ensure_w15_efficiency_policy(site: str | None) -> tuple[dict[str, Any], datetime, str, str | None]:
    policy_key, normalized_site = _w15_efficiency_policy_key(site)
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            select(sla_policies).where(sla_policies.c.policy_key == policy_key).limit(1)
        ).mappings().first()
        if row is None:
            policy = _default_w15_efficiency_policy()
            conn.execute(
                insert(sla_policies).values(
                    policy_key=policy_key,
                    policy_json=_to_json_text(policy),
                    updated_at=now,
                )
            )
            return policy, now, policy_key, normalized_site
    policy = _parse_w15_efficiency_policy_json(row["policy_json"])
    updated_at = _as_datetime(row["updated_at"]) if row["updated_at"] is not None else now
    return policy, updated_at, policy_key, normalized_site


def _upsert_w15_efficiency_policy(site: str | None, payload: dict[str, Any]) -> tuple[dict[str, Any], datetime, str, str | None]:
    current_policy, _, policy_key, normalized_site = _ensure_w15_efficiency_policy(site)
    incoming = payload if isinstance(payload, dict) else {}
    merged: dict[str, Any] = {**current_policy}
    for key in [
        "enabled",
        "risk_rate_green_threshold",
        "risk_rate_yellow_threshold",
        "checklist_completion_green_threshold",
        "checklist_completion_yellow_threshold",
        "simulation_success_green_threshold",
        "simulation_success_yellow_threshold",
        "readiness_target",
    ]:
        if key in incoming:
            merged[key] = incoming[key]
    normalized = _normalize_w15_efficiency_policy(merged)
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
    return normalized, now, policy_key, normalized_site


def _build_w15_ops_efficiency_snapshot(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_days = max(14, min(int(days), 120))
    window_start = now - timedelta(days=window_days)
    policy, policy_updated_at, policy_key, policy_site = _ensure_w15_efficiency_policy(site)

    effective_site = policy_site if policy_site is not None else _normalize_site_name(site)
    effective_allowed_sites = allowed_sites if effective_site is None else None

    stmt = select(work_orders).where(work_orders.c.created_at >= window_start)
    if effective_site is not None:
        stmt = stmt.where(work_orders.c.site == effective_site)
    elif effective_allowed_sites is not None:
        if not effective_allowed_sites:
            return {
                "generated_at": now.isoformat(),
                "site": None,
                "window_days": window_days,
                "policy": {
                    "policy_key": policy_key,
                    "updated_at": policy_updated_at.isoformat(),
                    "enabled": bool(policy.get("enabled", True)),
                },
                "metrics": {
                    "incidents_count": 0,
                    "unique_titles": 0,
                    "repeated_incidents_count": 0,
                    "incident_repeat_rate_percent": 0.0,
                    "guide_total_count": len(ADOPTION_W15_SELF_SERVE_GUIDES),
                    "guide_done_count": 0,
                    "checklist_completion_rate_percent": 0.0,
                    "runbook_total_count": len(ADOPTION_W15_TROUBLESHOOTING_RUNBOOK),
                    "runbook_done_count": 0,
                    "simulation_success_rate_percent": 0.0,
                    "ops_efficiency_readiness_score": 0.0,
                    "overall_status": W15_EFFICIENCY_STATUS_RED,
                    "target_met": False,
                },
                "kpis": [],
                "top_repeat_incidents": [],
                "scale_checklist": ADOPTION_W15_SELF_SERVE_GUIDES,
                "simulation_runbook": ADOPTION_W15_TROUBLESHOOTING_RUNBOOK,
                "recommendations": ["접근 가능한 site 범위가 비어 있습니다. site_scope를 확인하세요."],
            }
        stmt = stmt.where(work_orders.c.site.in_(effective_allowed_sites))
    with get_conn() as conn:
        wo_rows = conn.execute(stmt).mappings().all()

    title_counts: dict[str, int] = {}
    title_label: dict[str, str] = {}
    for row in wo_rows:
        title_raw = str(row.get("title") or "").strip()
        normalized = title_raw.lower() if title_raw else "(untitled)"
        title_counts[normalized] = title_counts.get(normalized, 0) + 1
        if normalized not in title_label:
            title_label[normalized] = title_raw or "(untitled)"

    total_work_orders = len(wo_rows)
    repeated_orders_count = sum(count for count in title_counts.values() if count >= 2)
    unique_titles = len(title_counts)
    incident_repeat_rate_percent = round((repeated_orders_count / total_work_orders) * 100.0, 2) if total_work_orders > 0 else 0.0
    top_repeat_incidents = sorted(
        [
            {
                "title": title_label.get(key, key),
                "count": count,
                "share_percent": round((count / total_work_orders) * 100.0, 2) if total_work_orders > 0 else 0.0,
            }
            for key, count in title_counts.items()
            if count >= 2
        ],
        key=lambda item: int(item.get("count") or 0),
        reverse=True,
    )[:10]

    tracker_stmt = select(adoption_w15_tracker_items)
    if effective_site is not None:
        tracker_stmt = tracker_stmt.where(adoption_w15_tracker_items.c.site == effective_site)
    elif effective_allowed_sites is not None:
        tracker_stmt = tracker_stmt.where(adoption_w15_tracker_items.c.site.in_(effective_allowed_sites))
    with get_conn() as conn:
        tracker_rows = conn.execute(tracker_stmt).mappings().all()

    guide_total_count = max(
        len(ADOPTION_W15_SELF_SERVE_GUIDES),
        sum(1 for row in tracker_rows if str(row.get("item_type") or "") == "self_serve_guide"),
    )
    runbook_total_count = max(
        len(ADOPTION_W15_TROUBLESHOOTING_RUNBOOK),
        sum(1 for row in tracker_rows if str(row.get("item_type") or "") == "troubleshooting_runbook"),
    )
    guide_done_count = sum(
        1
        for row in tracker_rows
        if str(row.get("item_type") or "") == "self_serve_guide" and str(row.get("status") or "") == W15_TRACKER_STATUS_DONE
    )
    runbook_done_count = sum(
        1
        for row in tracker_rows
        if str(row.get("item_type") or "") == "troubleshooting_runbook" and str(row.get("status") or "") == W15_TRACKER_STATUS_DONE
    )
    checklist_completion_rate_percent = round((guide_done_count / guide_total_count) * 100.0, 2) if guide_total_count > 0 else 0.0
    simulation_success_rate_percent = (
        round((runbook_done_count / runbook_total_count) * 100.0, 2) if runbook_total_count > 0 else 0.0
    )

    repeat_status = _evaluate_w09_kpi_status(
        actual=incident_repeat_rate_percent,
        direction="lower_better",
        green_threshold=float(policy.get("risk_rate_green_threshold") or 20.0),
        yellow_threshold=float(policy.get("risk_rate_yellow_threshold") or 30.0),
    )
    guide_status = _evaluate_w09_kpi_status(
        actual=checklist_completion_rate_percent,
        direction="higher_better",
        green_threshold=float(policy.get("checklist_completion_green_threshold") or 80.0),
        yellow_threshold=float(policy.get("checklist_completion_yellow_threshold") or 60.0),
    )
    runbook_status = _evaluate_w09_kpi_status(
        actual=simulation_success_rate_percent,
        direction="higher_better",
        green_threshold=float(policy.get("simulation_success_green_threshold") or 80.0),
        yellow_threshold=float(policy.get("simulation_success_yellow_threshold") or 60.0),
    )

    status_points = {
        W09_KPI_STATUS_RED: 0.0,
        W09_KPI_STATUS_YELLOW: 50.0,
        W09_KPI_STATUS_GREEN: 100.0,
    }
    ops_efficiency_readiness_score = round(
        (status_points.get(repeat_status, 0.0) + status_points.get(guide_status, 0.0) + status_points.get(runbook_status, 0.0))
        / 3.0,
        2,
    )

    status_set = {repeat_status, guide_status, runbook_status}
    overall_status = W15_EFFICIENCY_STATUS_GREEN
    if W09_KPI_STATUS_RED in status_set:
        overall_status = W15_EFFICIENCY_STATUS_RED
    elif W09_KPI_STATUS_YELLOW in status_set:
        overall_status = W15_EFFICIENCY_STATUS_YELLOW

    readiness_target = float(policy.get("readiness_target") or 75.0)
    target_met = ops_efficiency_readiness_score >= readiness_target and overall_status != W15_EFFICIENCY_STATUS_RED

    kpis = [
        {
            "kpi_key": "repeat_ticket_rate_percent",
            "kpi_name": "Repeat ticket rate",
            "direction": "lower_better",
            "actual_value": incident_repeat_rate_percent,
            "green_threshold": float(policy.get("risk_rate_green_threshold") or 20.0),
            "yellow_threshold": float(policy.get("risk_rate_yellow_threshold") or 30.0),
            "status": repeat_status,
            "target": f"<= {policy.get('risk_rate_green_threshold', 20.0)}%",
        },
        {
            "kpi_key": "checklist_completion_rate_percent",
            "kpi_name": "Scale readiness guide publish rate",
            "direction": "higher_better",
            "actual_value": checklist_completion_rate_percent,
            "green_threshold": float(policy.get("checklist_completion_green_threshold") or 80.0),
            "yellow_threshold": float(policy.get("checklist_completion_yellow_threshold") or 60.0),
            "status": guide_status,
            "target": f">= {policy.get('checklist_completion_green_threshold', 80.0)}%",
        },
        {
            "kpi_key": "simulation_success_rate_percent",
            "kpi_name": "Runbook completion rate",
            "direction": "higher_better",
            "actual_value": simulation_success_rate_percent,
            "green_threshold": float(policy.get("simulation_success_green_threshold") or 80.0),
            "yellow_threshold": float(policy.get("simulation_success_yellow_threshold") or 60.0),
            "status": runbook_status,
            "target": f">= {policy.get('simulation_success_green_threshold', 80.0)}%",
        },
        {
            "kpi_key": "ops_efficiency_readiness_score",
            "kpi_name": "Operations efficiency readiness score",
            "direction": "higher_better",
            "actual_value": ops_efficiency_readiness_score,
            "green_threshold": readiness_target,
            "yellow_threshold": max(0.0, readiness_target - 15.0),
            "status": _evaluate_w09_kpi_status(
                actual=ops_efficiency_readiness_score,
                direction="higher_better",
                green_threshold=readiness_target,
                yellow_threshold=max(0.0, readiness_target - 15.0),
            ),
            "target": f">= {readiness_target}",
        },
    ]

    recommendations: list[str] = []
    if repeat_status == W09_KPI_STATUS_RED:
        recommendations.append("반복 티켓 비율이 높습니다. Top 반복 제목 3개를 FAQ/가이드로 우선 전환하세요.")
    if guide_status != W09_KPI_STATUS_GREEN:
        recommendations.append("Self-serve guide 게시율이 낮습니다. 담당자와 마감일을 지정해 게시를 완료하세요.")
    if runbook_status != W09_KPI_STATUS_GREEN:
        recommendations.append("Runbook 완료율이 낮습니다. 모듈별 실습 드릴과 증빙 업로드를 마감하세요.")
    if not recommendations:
        recommendations.append("W15 운영 효율화 지표가 안정적입니다. 현재 운영 리듬을 유지하세요.")

    return {
        "generated_at": now.isoformat(),
        "site": effective_site,
        "window_days": window_days,
        "policy": {
            "policy_key": policy_key,
            "updated_at": policy_updated_at.isoformat(),
            "enabled": bool(policy.get("enabled", True)),
            "readiness_target": readiness_target,
        },
        "metrics": {
            "incidents_count": total_work_orders,
            "unique_titles": unique_titles,
            "repeated_incidents_count": repeated_orders_count,
            "incident_repeat_rate_percent": incident_repeat_rate_percent,
            "guide_total_count": guide_total_count,
            "guide_done_count": guide_done_count,
            "checklist_completion_rate_percent": checklist_completion_rate_percent,
            "runbook_total_count": runbook_total_count,
            "runbook_done_count": runbook_done_count,
            "simulation_success_rate_percent": simulation_success_rate_percent,
            "ops_efficiency_readiness_score": ops_efficiency_readiness_score,
            "overall_status": overall_status,
            "target_met": target_met,
        },
        "kpis": kpis,
        "top_repeat_incidents": top_repeat_incidents,
        "scale_checklist": ADOPTION_W15_SELF_SERVE_GUIDES,
        "simulation_runbook": ADOPTION_W15_TROUBLESHOOTING_RUNBOOK,
        "recommendations": recommendations,
    }




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


def _configured_alert_targets() -> list[str]:
    return [item["url"] for item in _configured_alert_target_configs()]


def _build_alert_webhook_request_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if ALERT_WEBHOOK_SHARED_TOKEN:
        headers[ALERT_WEBHOOK_TOKEN_HEADER] = ALERT_WEBHOOK_SHARED_TOKEN
    return headers


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

    threshold = max(1, ALERT_CHANNEL_GUARD_FAIL_THRESHOLD)
    cooldown_minutes = max(1, ALERT_CHANNEL_GUARD_COOLDOWN_MINUTES)
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
        "state": state if ALERT_CHANNEL_GUARD_ENABLED else "disabled",
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
    if not ALERT_CHANNEL_GUARD_ENABLED:
        status = "warning" if warning_count > 0 else "ok"

    return {
        "generated_at": current_time.isoformat(),
        "event_type": event_type,
        "lookback_days": normalized_lookback_days,
        "policy": {
            "enabled": ALERT_CHANNEL_GUARD_ENABLED,
            "failure_threshold": max(1, ALERT_CHANNEL_GUARD_FAIL_THRESHOLD),
            "cooldown_minutes": max(1, ALERT_CHANNEL_GUARD_COOLDOWN_MINUTES),
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
    resolved_retention_days = max(1, int(retention_days if retention_days is not None else ALERT_RETENTION_DAYS))
    resolved_max_delete = max(1, min(int(max_delete if max_delete is not None else ALERT_RETENTION_MAX_DELETE), 50000))
    resolved_write_archive = ALERT_RETENTION_ARCHIVE_ENABLED if write_archive is None else bool(write_archive)
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
                archive_dir = Path(ALERT_RETENTION_ARCHIVE_PATH)
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
    resolved_max_targets = max(1, min(int(max_targets if max_targets is not None else ALERT_GUARD_RECOVER_MAX_TARGETS), 500))

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
            retries=ALERT_WEBHOOK_RETRIES,
            timeout_sec=ALERT_WEBHOOK_TIMEOUT_SEC,
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
            max_targets=int(policy.get("recover_max_targets") or ALERT_GUARD_RECOVER_MAX_TARGETS),
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
                        "recover_max_targets": int(policy.get("recover_max_targets") or ALERT_GUARD_RECOVER_MAX_TARGETS),
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
        if ALERT_CHANNEL_GUARD_ENABLED and str(guard_state.get("state_computed")) == "quarantined":
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
            retries=ALERT_WEBHOOK_RETRIES,
            timeout_sec=ALERT_WEBHOOK_TIMEOUT_SEC,
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


def _row_to_admin_user_model(row: dict[str, Any]) -> AdminUserRead:
    from app.domains.iam.service import _row_to_admin_user_model as _impl
    return _impl(row)


def _row_to_admin_token_model(row: dict[str, Any]) -> AdminTokenRead:
    from app.domains.iam.service import _row_to_admin_token_model as _impl
    return _impl(row)


def _median_minutes(values: list[float]) -> float | None:
    if not values:
        return None
    try:
        return round(float(statistics.median(values)), 2)
    except statistics.StatisticsError:
        return None


def _percentile_minutes(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    if percentile <= 0:
        return round(float(min(values)), 2)
    if percentile >= 100:
        return round(float(max(values)), 2)
    sorted_values = sorted(values)
    if len(sorted_values) == 1:
        return round(float(sorted_values[0]), 2)
    rank = (len(sorted_values) - 1) * (percentile / 100.0)
    lower = int(math.floor(rank))
    upper = int(math.ceil(rank))
    if lower == upper:
        return round(float(sorted_values[lower]), 2)
    weight = rank - lower
    interpolated = sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * weight
    return round(float(interpolated), 2)


def _build_w04_funnel_snapshot(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_days = max(1, min(int(days), 90))
    start = now - timedelta(days=window_days)

    inspection_stmt = (
        select(inspections.c.inspector, inspections.c.site, inspections.c.created_at)
        .where(inspections.c.created_at >= start)
    )
    completion_stmt = (
        select(work_order_events.c.actor_username, work_orders.c.site, work_order_events.c.created_at)
        .select_from(work_order_events.join(work_orders, work_order_events.c.work_order_id == work_orders.c.id))
        .where(work_order_events.c.event_type == "status_changed")
        .where(work_order_events.c.to_status == "completed")
        .where(work_order_events.c.created_at >= start)
    )

    if site is not None:
        inspection_stmt = inspection_stmt.where(inspections.c.site == site)
        completion_stmt = completion_stmt.where(work_orders.c.site == site)
    elif allowed_sites is not None:
        if not allowed_sites:
            return {
                "generated_at": now.isoformat(),
                "site": site,
                "window_days": window_days,
                "target_ttv_minutes": 15.0,
                "metrics": {
                    "total_users": 0,
                    "inspection_converted_users": 0,
                    "work_order_completed_users": 0,
                    "inspection_conversion_rate_percent": 0.0,
                    "work_order_completion_rate_percent": 0.0,
                    "median_ttv_minutes": None,
                    "target_met": False,
                },
                "stage_timings_minutes": {
                    "auth_to_first_inspection": None,
                    "inspection_to_first_work_order_complete": None,
                    "auth_to_first_work_order_complete": None,
                },
                "stages": [],
                "actors": [],
            }
        inspection_stmt = inspection_stmt.where(inspections.c.site.in_(allowed_sites))
        completion_stmt = completion_stmt.where(work_orders.c.site.in_(allowed_sites))

    with get_conn() as conn:
        auth_rows = conn.execute(
            select(admin_audit_logs.c.actor_username, admin_audit_logs.c.created_at)
            .where(admin_audit_logs.c.created_at >= start)
            .where(admin_audit_logs.c.actor_username.is_not(None))
            .where(admin_audit_logs.c.actor_username != "system")
        ).mappings().all()
        inspection_rows = conn.execute(inspection_stmt).mappings().all()
        completion_rows = conn.execute(completion_stmt).mappings().all()

    actor_auth_first: dict[str, datetime] = {}
    for row in auth_rows:
        actor = str(row.get("actor_username") or "").strip()
        if not actor:
            continue
        created_at = _as_optional_datetime(row.get("created_at"))
        if created_at is None:
            continue
        prev = actor_auth_first.get(actor)
        if prev is None or created_at < prev:
            actor_auth_first[actor] = created_at

    considered_actors: set[str] = set()
    actor_first_inspection: dict[str, datetime] = {}
    for row in inspection_rows:
        actor = str(row.get("inspector") or "").strip()
        if not actor:
            continue
        considered_actors.add(actor)
        created_at = _as_optional_datetime(row.get("created_at"))
        if created_at is None:
            continue
        prev = actor_first_inspection.get(actor)
        if prev is None or created_at < prev:
            actor_first_inspection[actor] = created_at

    actor_first_complete: dict[str, datetime] = {}
    for row in completion_rows:
        actor = str(row.get("actor_username") or "").strip()
        if not actor or actor == "system":
            continue
        considered_actors.add(actor)
        created_at = _as_optional_datetime(row.get("created_at"))
        if created_at is None:
            continue
        prev = actor_first_complete.get(actor)
        if prev is None or created_at < prev:
            actor_first_complete[actor] = created_at

    if site is None and allowed_sites is None:
        considered_actors.update(actor_auth_first.keys())

    inspection_converted = 0
    completion_converted = 0
    auth_to_inspection_minutes: list[float] = []
    inspection_to_complete_minutes: list[float] = []
    auth_to_complete_minutes: list[float] = []
    actor_rows: list[dict[str, Any]] = []

    for actor in sorted(considered_actors):
        auth_at = actor_auth_first.get(actor)
        inspection_at = actor_first_inspection.get(actor)
        complete_at = actor_first_complete.get(actor)
        anchors = [x for x in [auth_at, inspection_at, complete_at] if x is not None]
        if not anchors:
            continue
        first_auth = auth_at or min(anchors)

        has_inspection = inspection_at is not None and inspection_at >= first_auth
        has_complete = complete_at is not None and complete_at >= first_auth
        if has_inspection:
            inspection_converted += 1
            auth_to_inspection_minutes.append((inspection_at - first_auth).total_seconds() / 60.0)
        if has_complete:
            completion_converted += 1
            auth_to_complete_minutes.append((complete_at - first_auth).total_seconds() / 60.0)
        if has_inspection and has_complete and complete_at is not None and inspection_at is not None and complete_at >= inspection_at:
            inspection_to_complete_minutes.append((complete_at - inspection_at).total_seconds() / 60.0)

        actor_rows.append(
            {
                "actor": actor,
                "first_auth_at": first_auth.isoformat() if first_auth is not None else None,
                "first_inspection_at": inspection_at.isoformat() if inspection_at is not None else None,
                "first_work_order_complete_at": complete_at.isoformat() if complete_at is not None else None,
            }
        )

    total_users = len(actor_rows)
    inspection_conversion_rate = round((inspection_converted / total_users) * 100, 2) if total_users > 0 else 0.0
    completion_conversion_rate = round((completion_converted / total_users) * 100, 2) if total_users > 0 else 0.0
    median_ttv_minutes = _median_minutes(auth_to_complete_minutes)
    target_ttv_minutes = 15.0
    target_met = median_ttv_minutes is not None and median_ttv_minutes <= target_ttv_minutes

    return {
        "generated_at": now.isoformat(),
        "site": site,
        "window_days": window_days,
        "target_ttv_minutes": target_ttv_minutes,
        "metrics": {
            "total_users": total_users,
            "inspection_converted_users": inspection_converted,
            "work_order_completed_users": completion_converted,
            "inspection_conversion_rate_percent": inspection_conversion_rate,
            "work_order_completion_rate_percent": completion_conversion_rate,
            "median_ttv_minutes": median_ttv_minutes,
            "target_met": target_met,
        },
        "stage_timings_minutes": {
            "auth_to_first_inspection": _median_minutes(auth_to_inspection_minutes),
            "inspection_to_first_work_order_complete": _median_minutes(inspection_to_complete_minutes),
            "auth_to_first_work_order_complete": median_ttv_minutes,
        },
        "stages": [
            {
                "stage_id": "authenticated",
                "label": "Authenticated Users",
                "user_count": total_users,
                "conversion_rate_percent": 100.0 if total_users > 0 else 0.0,
            },
            {
                "stage_id": "first_inspection",
                "label": "First Inspection Created",
                "user_count": inspection_converted,
                "conversion_rate_percent": inspection_conversion_rate,
            },
            {
                "stage_id": "first_work_order_complete",
                "label": "First Work-Order Completed",
                "user_count": completion_converted,
                "conversion_rate_percent": completion_conversion_rate,
            },
        ],
        "actors": actor_rows[:100],
    }


def _build_w04_blocker_snapshot(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
    max_items: int = 3,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_days = max(1, min(int(days), 90))
    start = now - timedelta(days=window_days)
    limit_items = max(1, min(int(max_items), 10))

    overdue_stmt = (
        select(work_orders.c.id)
        .where(work_orders.c.status.in_(["open", "acked"]))
        .where(work_orders.c.due_at.is_not(None))
        .where(work_orders.c.due_at < now)
    )
    alert_stmt = (
        select(alert_deliveries.c.id)
        .where(alert_deliveries.c.last_attempt_at >= start)
        .where(alert_deliveries.c.status.in_(["failed", "warning"]))
    )
    audit_fail_stmt = (
        select(admin_audit_logs.c.id)
        .where(admin_audit_logs.c.created_at >= start)
        .where(admin_audit_logs.c.status != "success")
    )
    tracker_stmt = select(adoption_w04_tracker_items.c.id).where(
        adoption_w04_tracker_items.c.status.in_(
            [
                W04_TRACKER_STATUS_PENDING,
                W04_TRACKER_STATUS_IN_PROGRESS,
                W04_TRACKER_STATUS_BLOCKED,
            ]
        )
    )

    if site is not None:
        overdue_stmt = overdue_stmt.where(work_orders.c.site == site)
        tracker_stmt = tracker_stmt.where(adoption_w04_tracker_items.c.site == site)
    elif allowed_sites is not None:
        if not allowed_sites:
            return {
                "generated_at": now.isoformat(),
                "site": site,
                "window_days": window_days,
                "top": [],
                "counts": {},
            }
        overdue_stmt = overdue_stmt.where(work_orders.c.site.in_(allowed_sites))
        tracker_stmt = tracker_stmt.where(adoption_w04_tracker_items.c.site.in_(allowed_sites))

    with get_conn() as conn:
        overdue_count = len(conn.execute(overdue_stmt).all())
        failed_alert_count = len(conn.execute(alert_stmt).all())
        audit_fail_count = len(conn.execute(audit_fail_stmt).all())
        tracker_open_count = len(conn.execute(tracker_stmt).all())

    funnel = _build_w04_funnel_snapshot(site=site, days=window_days, allowed_sites=allowed_sites)
    ttv = funnel.get("metrics", {}).get("median_ttv_minutes")
    inspection_conv = float(funnel.get("metrics", {}).get("inspection_conversion_rate_percent") or 0.0)
    completion_conv = float(funnel.get("metrics", {}).get("work_order_completion_rate_percent") or 0.0)

    candidates: list[dict[str, Any]] = []
    if overdue_count > 0:
        candidates.append(
            {
                "blocker_key": "overdue_open_work_orders",
                "title": "Overdue open work orders",
                "count": overdue_count,
                "source": "work_orders",
                "recommendation": "우선순위 높은 overdue 건부터 담당자 재할당 및 ETA 재설정",
            }
        )
    if failed_alert_count > 0:
        candidates.append(
            {
                "blocker_key": "failed_alert_deliveries",
                "title": "Failed alert deliveries",
                "count": failed_alert_count,
                "source": "alert_deliveries",
                "recommendation": "실패 타겟 재시도 배치 실행 후 channel guard 상태 점검",
            }
        )
    if audit_fail_count > 0:
        candidates.append(
            {
                "blocker_key": "audit_operation_failures",
                "title": "Audit-recorded failed operations",
                "count": audit_fail_count,
                "source": "admin_audit_logs",
                "recommendation": "실패 action별 재현 절차와 빠른 해결 가이드 갱신",
            }
        )
    if tracker_open_count > 0:
        candidates.append(
            {
                "blocker_key": "w04_tracker_open_items",
                "title": "Open W04 coaching items",
                "count": tracker_open_count,
                "source": "adoption_w04_tracker",
                "recommendation": "pending/in_progress 항목 담당자 지정 후 24시간 내 상태 갱신",
            }
        )
    if isinstance(ttv, (int, float)) and float(ttv) > 15.0:
        candidates.append(
            {
                "blocker_key": "median_ttv_over_target",
                "title": "Median TTV over target",
                "count": int(round(float(ttv))),
                "source": "w04_funnel",
                "recommendation": "첫 로그인 15분 내 점검 생성 미션을 강제하고 현장 코칭 실시",
            }
        )
    if inspection_conv < 70.0:
        candidates.append(
            {
                "blocker_key": "low_inspection_conversion",
                "title": "Low inspection conversion",
                "count": int(round(70.0 - inspection_conv)),
                "source": "w04_funnel",
                "recommendation": "초기 화면에서 점검 생성 버튼/가이드 우선 노출",
            }
        )
    if completion_conv < 50.0:
        candidates.append(
            {
                "blocker_key": "low_completion_conversion",
                "title": "Low work-order completion conversion",
                "count": int(round(50.0 - completion_conv)),
                "source": "w04_funnel",
                "recommendation": "ACK/완료 템플릿 표준화 및 관리자 1:1 코칭 적용",
            }
        )

    top = sorted(candidates, key=lambda x: (int(x.get("count", 0)), str(x.get("blocker_key", ""))), reverse=True)[:limit_items]
    counts = {str(item["blocker_key"]): int(item["count"]) for item in candidates}
    return {
        "generated_at": now.isoformat(),
        "site": site,
        "window_days": window_days,
        "top": top,
        "counts": counts,
    }


def _build_w04_common_mistakes_payload(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> dict[str, Any]:
    blockers = _build_w04_blocker_snapshot(site=site, days=days, allowed_sites=allowed_sites, max_items=10)
    blocker_counts = blockers.get("counts", {})
    mistake_items: list[dict[str, Any]] = []
    mapping = {
        "missing_assignee": {"w04_tracker_open_items"},
        "missing_evidence": {"w04_tracker_open_items"},
        "slow_first_action": {"median_ttv_over_target", "low_inspection_conversion"},
        "wo_completion_delay": {"overdue_open_work_orders", "low_completion_conversion"},
        "alert_delivery_failures": {"failed_alert_deliveries"},
    }

    for item in W04_COMMON_MISTAKE_FIX_CATALOG:
        key = str(item.get("mistake_key") or "")
        related_blockers = mapping.get(key, set())
        observed_count = sum(int(blocker_counts.get(name, 0)) for name in related_blockers)
        mistake_items.append(
            {
                "mistake_key": key,
                "mistake": item.get("mistake", ""),
                "symptom": item.get("symptom", ""),
                "quick_fix": item.get("quick_fix", ""),
                "where_to_check": item.get("where_to_check", ""),
                "observed_count": observed_count,
            }
        )
    sorted_items = sorted(mistake_items, key=lambda x: int(x.get("observed_count", 0)), reverse=True)
    now = datetime.now(timezone.utc)
    return {
        "title": "W04 자주 하는 실수와 빠른 해결 가이드",
        "public": True,
        "generated_at": now.isoformat(),
        "site": site,
        "window_days": max(1, min(int(days), 90)),
        "items": sorted_items,
        "top_blockers": blockers.get("top", []),
    }


def _build_w04_common_mistakes_html(payload: dict[str, Any]) -> str:
    return _web_build_w04_common_mistakes_html(payload)


def _build_w05_usage_consistency_snapshot(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_days = max(14, min(int(days), 90))
    start = now - timedelta(days=window_days)
    midpoint = start + timedelta(days=max(1, window_days // 2))

    event_stmt = (
        select(work_order_events.c.actor_username, work_orders.c.site, work_order_events.c.created_at)
        .select_from(work_order_events.join(work_orders, work_order_events.c.work_order_id == work_orders.c.id))
        .where(work_order_events.c.created_at >= start)
    )
    inspection_stmt = (
        select(inspections.c.inspector, inspections.c.site, inspections.c.created_at)
        .where(inspections.c.created_at >= start)
    )
    open_work_orders_stmt = select(work_orders.c.site, work_orders.c.status, work_orders.c.due_at).where(
        work_orders.c.status.in_(["open", "acked"])
    )

    if site is not None:
        event_stmt = event_stmt.where(work_orders.c.site == site)
        inspection_stmt = inspection_stmt.where(inspections.c.site == site)
        open_work_orders_stmt = open_work_orders_stmt.where(work_orders.c.site == site)
    elif allowed_sites is not None:
        if not allowed_sites:
            return {
                "generated_at": now.isoformat(),
                "site": site,
                "window_days": window_days,
                "target_retention_percent": 65.0,
                "metrics": {
                    "active_users": 0,
                    "early_period_users": 0,
                    "retained_users": 0,
                    "two_week_retention_percent": 0.0,
                    "target_met": False,
                    "inspection_activity_users": 0,
                    "open_work_orders": 0,
                    "overdue_open_work_orders": 0,
                    "overdue_ratio_percent": 0.0,
                },
                "top_sites_by_overdue": [],
                "mission_recommendations": [],
            }
        event_stmt = event_stmt.where(work_orders.c.site.in_(allowed_sites))
        inspection_stmt = inspection_stmt.where(inspections.c.site.in_(allowed_sites))
        open_work_orders_stmt = open_work_orders_stmt.where(work_orders.c.site.in_(allowed_sites))

    with get_conn() as conn:
        event_rows = conn.execute(event_stmt).mappings().all()
        inspection_rows = conn.execute(inspection_stmt).mappings().all()
        open_work_order_rows = conn.execute(open_work_orders_stmt).mappings().all()

    early_users: set[str] = set()
    late_users: set[str] = set()
    active_users: set[str] = set()
    for row in event_rows:
        actor = str(row.get("actor_username") or "").strip()
        if not actor or actor == "system":
            continue
        created_at = _as_optional_datetime(row.get("created_at"))
        if created_at is None:
            continue
        active_users.add(actor)
        if created_at < midpoint:
            early_users.add(actor)
        else:
            late_users.add(actor)

    inspection_users: set[str] = set()
    for row in inspection_rows:
        actor = str(row.get("inspector") or "").strip()
        if actor:
            inspection_users.add(actor)

    retained_users = early_users.intersection(late_users)
    early_count = len(early_users)
    retained_count = len(retained_users)
    retention_percent = round((retained_count / early_count) * 100, 2) if early_count > 0 else 0.0
    target_retention_percent = 65.0

    open_total = 0
    overdue_total = 0
    site_open: dict[str, int] = {}
    site_overdue: dict[str, int] = {}
    for row in open_work_order_rows:
        row_site = str(row.get("site") or "").strip()
        if not row_site:
            continue
        open_total += 1
        site_open[row_site] = int(site_open.get(row_site, 0)) + 1
        due_at = _as_optional_datetime(row.get("due_at"))
        if due_at is not None and due_at < now:
            overdue_total += 1
            site_overdue[row_site] = int(site_overdue.get(row_site, 0)) + 1

    overdue_ratio_percent = round((overdue_total / open_total) * 100, 2) if open_total > 0 else 0.0

    top_sites_by_overdue: list[dict[str, Any]] = []
    if site is None:
        for site_name, total in site_open.items():
            overdue = int(site_overdue.get(site_name, 0))
            ratio = round((overdue / total) * 100, 2) if total > 0 else 0.0
            top_sites_by_overdue.append(
                {
                    "site": site_name,
                    "open_work_orders": total,
                    "overdue_open_work_orders": overdue,
                    "overdue_ratio_percent": ratio,
                }
            )
        top_sites_by_overdue = sorted(
            top_sites_by_overdue,
            key=lambda item: (float(item.get("overdue_ratio_percent") or 0.0), int(item.get("overdue_open_work_orders") or 0)),
            reverse=True,
        )[:5]
    else:
        top_sites_by_overdue = [
            {
                "site": site,
                "open_work_orders": open_total,
                "overdue_open_work_orders": overdue_total,
                "overdue_ratio_percent": overdue_ratio_percent,
            }
        ]

    mission_recommendations: list[str] = []
    if retention_percent < target_retention_percent:
        mission_recommendations.append("역할별 주간 미션을 재지정하고 Site Champion 1:1 코칭을 배정하세요.")
    if overdue_ratio_percent >= 25.0:
        mission_recommendations.append("overdue 비율이 높습니다. 담당자 재할당과 ETA 재설정을 우선 수행하세요.")
    if len(inspection_users) < max(3, len(active_users) // 2):
        mission_recommendations.append("점검 생성 참여가 낮습니다. 첫 점검 미션과 빠른 가이드를 강화하세요.")
    if not mission_recommendations:
        mission_recommendations.append("사용 일관성 지표가 목표 범위입니다. 현재 미션 운영 방식을 유지하세요.")

    return {
        "generated_at": now.isoformat(),
        "site": site,
        "window_days": window_days,
        "target_retention_percent": target_retention_percent,
        "metrics": {
            "active_users": len(active_users),
            "early_period_users": early_count,
            "retained_users": retained_count,
            "two_week_retention_percent": retention_percent,
            "target_met": retention_percent >= target_retention_percent,
            "inspection_activity_users": len(inspection_users),
            "open_work_orders": open_total,
            "overdue_open_work_orders": overdue_total,
            "overdue_ratio_percent": overdue_ratio_percent,
        },
        "top_sites_by_overdue": top_sites_by_overdue,
        "mission_recommendations": mission_recommendations,
    }


def _build_w06_operational_rhythm_snapshot(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_days = max(7, min(int(days), 90))
    start = now - timedelta(days=window_days)

    def _scope_matches(scope_values: list[str], *, site_name: str | None, allowed: list[str] | None) -> bool:
        normalized = _site_scope_text_to_list(scope_values, default_all=True)
        if SITE_SCOPE_ALL in normalized:
            if site_name is not None:
                return True
            return not (allowed is not None and len(allowed) == 0)
        if site_name is not None:
            return site_name in normalized
        if allowed is not None:
            return any(item in allowed for item in normalized)
        return True

    event_stmt = (
        select(work_order_events.c.actor_username, work_orders.c.site, work_order_events.c.created_at)
        .select_from(work_order_events.join(work_orders, work_order_events.c.work_order_id == work_orders.c.id))
        .where(work_order_events.c.created_at >= start)
    )
    inspection_stmt = select(inspections.c.inspector, inspections.c.site, inspections.c.created_at).where(
        inspections.c.created_at >= start
    )
    handover_stmt = (
        select(admin_audit_logs.c.actor_username, admin_audit_logs.c.resource_id, admin_audit_logs.c.created_at)
        .where(admin_audit_logs.c.action == "ops_handover_brief_view")
        .where(admin_audit_logs.c.created_at >= start)
    )
    overdue_stmt = select(work_orders.c.id).where(work_orders.c.status.in_(["open", "acked"])).where(
        work_orders.c.due_at.is_not(None)
    ).where(work_orders.c.due_at < now)

    if site is not None:
        event_stmt = event_stmt.where(work_orders.c.site == site)
        inspection_stmt = inspection_stmt.where(inspections.c.site == site)
        overdue_stmt = overdue_stmt.where(work_orders.c.site == site)
    elif allowed_sites is not None:
        if not allowed_sites:
            return {
                "generated_at": now.isoformat(),
                "site": site,
                "window_days": window_days,
                "target_weekly_active_rate_percent": 75.0,
                "metrics": {
                    "eligible_users": 0,
                    "active_users": 0,
                    "weekly_active_rate_percent": 0.0,
                    "target_met": False,
                    "handover_brief_views": 0,
                    "handover_days_covered": 0,
                    "cadence_adherence_percent": 0.0,
                    "overdue_open_work_orders": 0,
                    "active_tokens": 0,
                    "tokens_expiring_7d": 0,
                    "tokens_stale_14d": 0,
                    "users_without_active_token": 0,
                },
                "role_coverage": [],
                "site_activity": [],
                "recommendations": [],
            }
        event_stmt = event_stmt.where(work_orders.c.site.in_(allowed_sites))
        inspection_stmt = inspection_stmt.where(inspections.c.site.in_(allowed_sites))
        overdue_stmt = overdue_stmt.where(work_orders.c.site.in_(allowed_sites))

    with get_conn() as conn:
        event_rows = conn.execute(event_stmt).mappings().all()
        inspection_rows = conn.execute(inspection_stmt).mappings().all()
        handover_rows = conn.execute(handover_stmt).mappings().all()
        overdue_rows = conn.execute(overdue_stmt).all()
        user_rows = conn.execute(
            select(
                admin_users.c.id,
                admin_users.c.username,
                admin_users.c.role,
                admin_users.c.site_scope,
            ).where(admin_users.c.is_active.is_(True))
        ).mappings().all()
        token_rows = conn.execute(
            select(
                admin_tokens.c.user_id,
                admin_tokens.c.expires_at,
                admin_tokens.c.last_used_at,
                admin_tokens.c.site_scope,
            ).where(admin_tokens.c.is_active.is_(True))
        ).mappings().all()

    eligible_roles = {"owner", "manager", "operator"}
    eligible_by_id: dict[int, dict[str, Any]] = {}
    for row in user_rows:
        role = str(row.get("role") or "").strip().lower()
        if role not in eligible_roles:
            continue
        scope_values = _site_scope_text_to_list(row.get("site_scope"), default_all=True)
        if not _scope_matches(scope_values, site_name=site, allowed=allowed_sites):
            continue
        user_id = int(row.get("id") or 0)
        if user_id <= 0:
            continue
        eligible_by_id[user_id] = {
            "username": str(row.get("username") or "").strip(),
            "role": role,
            "scope": scope_values,
        }

    eligible_users = {
        str(info.get("username") or "").strip()
        for info in eligible_by_id.values()
        if str(info.get("username") or "").strip()
    }

    active_users: set[str] = set()
    site_activity_counter: dict[str, int] = {}
    for row in event_rows:
        actor = str(row.get("actor_username") or "").strip()
        row_site = str(row.get("site") or "").strip()
        if not actor or actor == "system":
            continue
        active_users.add(actor)
        if row_site:
            site_activity_counter[row_site] = int(site_activity_counter.get(row_site, 0)) + 1
    for row in inspection_rows:
        actor = str(row.get("inspector") or "").strip()
        row_site = str(row.get("site") or "").strip()
        if not actor:
            continue
        active_users.add(actor)
        if row_site:
            site_activity_counter[row_site] = int(site_activity_counter.get(row_site, 0)) + 1

    active_eligible_users = active_users.intersection(eligible_users)
    eligible_count = len(eligible_users)
    active_count = len(active_eligible_users)
    weekly_active_rate_percent = round((active_count / eligible_count) * 100, 2) if eligible_count > 0 else 0.0
    target_weekly_active_rate_percent = 75.0

    handover_view_count = 0
    handover_days: set[str] = set()
    for row in handover_rows:
        resource_id = str(row.get("resource_id") or "").strip()
        if site is not None:
            if resource_id not in {site, "all"}:
                continue
        elif allowed_sites is not None:
            if resource_id != "all" and resource_id not in allowed_sites:
                continue
        created_at = _as_optional_datetime(row.get("created_at"))
        if created_at is None:
            continue
        handover_view_count += 1
        handover_days.add(created_at.date().isoformat())

    expected_handover_days = max(1, min(window_days, 5))
    cadence_adherence_percent = round((len(handover_days) / expected_handover_days) * 100, 2)
    if cadence_adherence_percent > 100.0:
        cadence_adherence_percent = 100.0

    now_plus_7d = now + timedelta(days=7)
    stale_cutoff = now - timedelta(days=14)
    active_token_count = 0
    tokens_expiring_7d = 0
    tokens_stale_14d = 0
    users_with_active_token: set[int] = set()
    for row in token_rows:
        user_id = int(row.get("user_id") or 0)
        if user_id not in eligible_by_id:
            continue
        user_scope = eligible_by_id[user_id]["scope"]
        token_scope_raw = row.get("site_scope")
        token_scope = _site_scope_text_to_list(token_scope_raw, default_all=True) if token_scope_raw is not None else None
        effective_scope = _resolve_effective_site_scope(user_scope=user_scope, token_scope=token_scope)
        if not _scope_matches(effective_scope, site_name=site, allowed=allowed_sites):
            continue
        active_token_count += 1
        users_with_active_token.add(user_id)
        expires_at = _as_optional_datetime(row.get("expires_at"))
        if expires_at is not None and expires_at <= now_plus_7d:
            tokens_expiring_7d += 1
        last_used_at = _as_optional_datetime(row.get("last_used_at"))
        if last_used_at is None or last_used_at < stale_cutoff:
            tokens_stale_14d += 1

    users_without_active_token = max(0, len(eligible_by_id) - len(users_with_active_token))
    overdue_open_work_orders = len(overdue_rows)

    role_to_users: dict[str, set[str]] = {"owner": set(), "manager": set(), "operator": set()}
    for info in eligible_by_id.values():
        role = str(info.get("role") or "").strip().lower()
        username = str(info.get("username") or "").strip()
        if role in role_to_users and username:
            role_to_users[role].add(username)

    role_coverage = [
        {
            "role": role,
            "user_count": len(users),
            "active_user_count": len(users.intersection(active_eligible_users)),
        }
        for role, users in role_to_users.items()
    ]

    site_activity: list[dict[str, Any]] = []
    if site is None:
        for site_name, count in site_activity_counter.items():
            site_activity.append({"site": site_name, "activity_events": int(count)})
        site_activity = sorted(site_activity, key=lambda item: int(item.get("activity_events", 0)), reverse=True)[:8]
    else:
        site_activity = [{"site": site, "activity_events": int(site_activity_counter.get(site, 0))}]

    recommendations: list[str] = []
    if weekly_active_rate_percent < target_weekly_active_rate_percent:
        recommendations.append("주간 활성률이 낮습니다. 월요일 계획보드에서 역할별 최소 미션을 재지정하세요.")
    if cadence_adherence_percent < 80.0:
        recommendations.append("handover 회의 리듬이 약합니다. 매일 브리프 조회와 action 기록을 고정하세요.")
    if users_without_active_token > 0:
        recommendations.append("활성 토큰이 없는 운영 인원이 있습니다. RBAC/토큰 발급 상태를 점검하세요.")
    if tokens_expiring_7d > 0 or tokens_stale_14d > 0:
        recommendations.append("만료 임박/장기 미사용 토큰 정리를 수행해 보안/운영 리듬을 맞추세요.")
    if overdue_open_work_orders > 0:
        recommendations.append("overdue 작업이 남아 있습니다. 주중 재할당/ETA 업데이트를 우선 수행하세요.")
    if not recommendations:
        recommendations.append("운영 리듬 지표가 목표 범위입니다. 현재 cadence를 유지하세요.")

    return {
        "generated_at": now.isoformat(),
        "site": site,
        "window_days": window_days,
        "target_weekly_active_rate_percent": target_weekly_active_rate_percent,
        "metrics": {
            "eligible_users": eligible_count,
            "active_users": active_count,
            "weekly_active_rate_percent": weekly_active_rate_percent,
            "target_met": weekly_active_rate_percent >= target_weekly_active_rate_percent,
            "handover_brief_views": handover_view_count,
            "handover_days_covered": len(handover_days),
            "cadence_adherence_percent": cadence_adherence_percent,
            "overdue_open_work_orders": overdue_open_work_orders,
            "active_tokens": active_token_count,
            "tokens_expiring_7d": tokens_expiring_7d,
            "tokens_stale_14d": tokens_stale_14d,
            "users_without_active_token": users_without_active_token,
        },
        "role_coverage": role_coverage,
        "site_activity": site_activity,
        "recommendations": recommendations,
    }


def _build_w07_sla_quality_snapshot(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_days = max(7, min(int(days), 90))
    baseline_days = window_days
    start = now - timedelta(days=window_days)
    baseline_start = start - timedelta(days=baseline_days)

    def _empty_snapshot() -> dict[str, Any]:
        return {
            "generated_at": now.isoformat(),
            "site": site,
            "window_days": window_days,
            "baseline_days": baseline_days,
            "target_response_improvement_percent": 10.0,
            "thresholds": {
                "escalation_rate_percent": round(max(0.0, W07_QUALITY_ALERT_ESCALATION_RATE_THRESHOLD), 2),
                "alert_success_rate_percent": round(max(0.0, min(100.0, W07_QUALITY_ALERT_SUCCESS_RATE_THRESHOLD)), 2),
                "data_quality_issue_rate_percent": 5.0,
            },
            "metrics": {
                "created_work_orders": 0,
                "acked_work_orders": 0,
                "completed_work_orders": 0,
                "median_ack_minutes": None,
                "p90_ack_minutes": None,
                "baseline_median_ack_minutes": None,
                "response_time_improvement_percent": None,
                "target_met": False,
                "median_mttr_minutes": None,
                "priority_mttr_minutes": {},
                "sla_violation_count": 0,
                "sla_violation_rate_percent": 0.0,
                "open_work_orders": 0,
                "overdue_open_work_orders": 0,
                "escalated_open_work_orders": 0,
                "escalated_work_orders": 0,
                "escalation_rate_percent": 0.0,
                "alert_total": 0,
                "alert_success_count": 0,
                "alert_success_rate_percent": 0.0,
                "sla_run_count": 0,
                "data_quality_gate_pass": True,
                "data_quality_issue_count": 0,
                "data_quality_critical_issue_count": 0,
                "data_quality_issue_rate_percent": 0.0,
            },
            "data_quality": {
                "gate_pass": True,
                "issue_count": 0,
                "critical_issue_count": 0,
                "issue_rate_percent": 0.0,
                "checks": {
                    "missing_due_at_count": 0,
                    "missing_priority_count": 0,
                    "invalid_status_count": 0,
                    "completed_without_completed_at_count": 0,
                    "ack_before_created_count": 0,
                    "completion_before_created_count": 0,
                    "due_before_created_count": 0,
                },
            },
            "top_risk_sites": [],
            "recommendations": [],
        }

    current_stmt = select(
        work_orders.c.site,
        work_orders.c.status,
        work_orders.c.priority,
        work_orders.c.created_at,
        work_orders.c.acknowledged_at,
        work_orders.c.completed_at,
        work_orders.c.due_at,
        work_orders.c.is_escalated,
    ).where(work_orders.c.created_at >= start)
    baseline_stmt = (
        select(
            work_orders.c.site,
            work_orders.c.created_at,
            work_orders.c.acknowledged_at,
        )
        .where(work_orders.c.created_at >= baseline_start)
        .where(work_orders.c.created_at < start)
    )
    open_stmt = select(
        work_orders.c.site,
        work_orders.c.status,
        work_orders.c.priority,
        work_orders.c.due_at,
        work_orders.c.is_escalated,
    ).where(work_orders.c.status.in_(["open", "acked"]))
    alert_stmt = select(
        alert_deliveries.c.status,
        alert_deliveries.c.payload_json,
        alert_deliveries.c.created_at,
    ).where(alert_deliveries.c.created_at >= start)
    sla_run_stmt = (
        select(job_runs.c.detail_json)
        .where(job_runs.c.job_name == "sla_escalation")
        .where(job_runs.c.finished_at >= start)
    )

    if site is not None:
        current_stmt = current_stmt.where(work_orders.c.site == site)
        baseline_stmt = baseline_stmt.where(work_orders.c.site == site)
        open_stmt = open_stmt.where(work_orders.c.site == site)
    elif allowed_sites is not None:
        if not allowed_sites:
            return _empty_snapshot()
        current_stmt = current_stmt.where(work_orders.c.site.in_(allowed_sites))
        baseline_stmt = baseline_stmt.where(work_orders.c.site.in_(allowed_sites))
        open_stmt = open_stmt.where(work_orders.c.site.in_(allowed_sites))

    with get_conn() as conn:
        current_rows = conn.execute(current_stmt).mappings().all()
        baseline_rows = conn.execute(baseline_stmt).mappings().all()
        open_rows = conn.execute(open_stmt).mappings().all()
        alert_rows = conn.execute(alert_stmt).mappings().all()
        sla_run_rows = conn.execute(sla_run_stmt).mappings().all()

    def _ack_minutes(rows: list[dict[str, Any]]) -> list[float]:
        values: list[float] = []
        for row in rows:
            created_at = _as_optional_datetime(row.get("created_at"))
            acknowledged_at = _as_optional_datetime(row.get("acknowledged_at"))
            if created_at is None or acknowledged_at is None or acknowledged_at < created_at:
                continue
            values.append((acknowledged_at - created_at).total_seconds() / 60.0)
        return values

    def _normalize_priority(raw: Any) -> str:
        value = str(raw or "").strip().lower()
        if value in {"low", "medium", "high", "critical"}:
            return value
        return "unknown"

    def _safe_rate(numerator: int, denominator: int) -> float:
        if denominator <= 0:
            return 0.0
        return round((float(numerator) / float(denominator)) * 100.0, 2)

    current_ack_minutes = _ack_minutes(current_rows)
    baseline_ack_minutes = _ack_minutes(baseline_rows)
    median_ack_minutes = _median_minutes(current_ack_minutes)
    p90_ack_minutes = _percentile_minutes(current_ack_minutes, 90.0)
    baseline_median_ack_minutes = _median_minutes(baseline_ack_minutes)
    response_time_improvement_percent: float | None = None
    if baseline_median_ack_minutes is not None and median_ack_minutes is not None:
        if baseline_median_ack_minutes > 0:
            response_time_improvement_percent = round(
                ((baseline_median_ack_minutes - median_ack_minutes) / baseline_median_ack_minutes) * 100.0,
                2,
            )
        else:
            response_time_improvement_percent = 0.0

    created_work_orders = len(current_rows)
    acked_work_orders = sum(1 for row in current_rows if _as_optional_datetime(row.get("acknowledged_at")) is not None)
    completed_work_orders = sum(1 for row in current_rows if _as_optional_datetime(row.get("completed_at")) is not None)
    escalated_work_orders = sum(1 for row in current_rows if bool(row.get("is_escalated", False)))
    escalation_rate_percent = _safe_rate(escalated_work_orders, created_work_orders)

    priority_mttr_values: dict[str, list[float]] = {}
    overall_mttr_values: list[float] = []
    site_created: dict[str, int] = {}
    site_escalated_work_orders: dict[str, int] = {}
    site_violation_count: dict[str, int] = {}
    site_ack_values: dict[str, list[float]] = {}

    missing_due_at_count = 0
    missing_priority_count = 0
    invalid_status_count = 0
    completed_without_completed_at_count = 0
    ack_before_created_count = 0
    completion_before_created_count = 0
    due_before_created_count = 0
    sla_violation_count = 0

    valid_statuses = {"open", "acked", "completed", "canceled"}
    for row in current_rows:
        row_site = str(row.get("site") or "").strip()
        if row_site:
            site_created[row_site] = int(site_created.get(row_site, 0)) + 1
            if bool(row.get("is_escalated", False)):
                site_escalated_work_orders[row_site] = int(site_escalated_work_orders.get(row_site, 0)) + 1

        status_value = str(row.get("status") or "").strip().lower()
        if status_value not in valid_statuses:
            invalid_status_count += 1

        priority_value = _normalize_priority(row.get("priority"))
        if priority_value == "unknown":
            missing_priority_count += 1

        created_at = _as_optional_datetime(row.get("created_at"))
        acknowledged_at = _as_optional_datetime(row.get("acknowledged_at"))
        completed_at = _as_optional_datetime(row.get("completed_at"))
        due_at = _as_optional_datetime(row.get("due_at"))

        if due_at is None:
            missing_due_at_count += 1
        elif created_at is not None and due_at < created_at:
            due_before_created_count += 1

        if status_value == "completed" and completed_at is None:
            completed_without_completed_at_count += 1

        if created_at is not None and acknowledged_at is not None:
            if acknowledged_at < created_at:
                ack_before_created_count += 1
            elif row_site:
                site_ack_values.setdefault(row_site, []).append(
                    (acknowledged_at - created_at).total_seconds() / 60.0
                )

        if created_at is not None and completed_at is not None:
            if completed_at < created_at:
                completion_before_created_count += 1
            else:
                mttr_minutes = (completed_at - created_at).total_seconds() / 60.0
                overall_mttr_values.append(mttr_minutes)
                priority_mttr_values.setdefault(priority_value, []).append(mttr_minutes)

        violated = False
        if due_at is not None:
            if completed_at is not None:
                violated = completed_at > due_at
            else:
                violated = now > due_at
        if violated:
            sla_violation_count += 1
            if row_site:
                site_violation_count[row_site] = int(site_violation_count.get(row_site, 0)) + 1

    priority_mttr_minutes = {
        priority: _median_minutes(values)
        for priority, values in sorted(priority_mttr_values.items(), key=lambda item: item[0])
        if values
    }
    median_mttr_minutes = _median_minutes(overall_mttr_values)
    sla_violation_rate_percent = _safe_rate(sla_violation_count, created_work_orders)

    open_work_orders = 0
    overdue_open_work_orders = 0
    escalated_open_work_orders = 0
    site_open: dict[str, int] = {}
    site_overdue: dict[str, int] = {}
    site_escalated_open: dict[str, int] = {}
    for row in open_rows:
        row_site = str(row.get("site") or "").strip()
        if not row_site:
            continue
        open_work_orders += 1
        site_open[row_site] = int(site_open.get(row_site, 0)) + 1
        due_at = _as_optional_datetime(row.get("due_at"))
        if due_at is not None and due_at < now:
            overdue_open_work_orders += 1
            site_overdue[row_site] = int(site_overdue.get(row_site, 0)) + 1
        if bool(row.get("is_escalated", False)):
            escalated_open_work_orders += 1
            site_escalated_open[row_site] = int(site_escalated_open.get(row_site, 0)) + 1

    alert_total = 0
    alert_success_count = 0
    for row in alert_rows:
        payload_raw = str(row.get("payload_json") or "{}")
        payload: dict[str, Any] = {}
        try:
            loaded = json.loads(payload_raw)
            if isinstance(loaded, dict):
                payload = loaded
        except json.JSONDecodeError:
            payload = {}

        payload_site_raw = payload.get("site")
        payload_site = _normalize_site_name(str(payload_site_raw)) if payload_site_raw is not None else None
        if site is not None:
            if payload_site != site:
                continue
        elif allowed_sites is not None:
            if payload_site is None or payload_site == "ALL" or payload_site not in allowed_sites:
                continue

        alert_total += 1
        if str(row.get("status") or "").strip().lower() == "success":
            alert_success_count += 1
    alert_success_rate_percent = _safe_rate(alert_success_count, alert_total)

    sla_run_count = 0
    for row in sla_run_rows:
        run_site: str | None = None
        detail_raw = str(row.get("detail_json") or "{}")
        try:
            loaded = json.loads(detail_raw)
            if isinstance(loaded, dict):
                site_raw = loaded.get("site")
                if site_raw is not None:
                    run_site = _normalize_site_name(str(site_raw))
        except json.JSONDecodeError:
            run_site = None

        if site is not None:
            if run_site not in {None, site}:
                continue
        elif allowed_sites is not None:
            if run_site is not None and run_site not in allowed_sites:
                continue
        sla_run_count += 1

    top_risk_sites: list[dict[str, Any]] = []
    if site is None:
        all_sites = set(site_open) | set(site_created)
        for site_name in sorted(all_sites):
            created_count = int(site_created.get(site_name, 0))
            violation_count = int(site_violation_count.get(site_name, 0))
            ack_values = site_ack_values.get(site_name, [])
            top_risk_sites.append(
                {
                    "site": site_name,
                    "open_work_orders": int(site_open.get(site_name, 0)),
                    "overdue_open_work_orders": int(site_overdue.get(site_name, 0)),
                    "escalated_open_work_orders": int(site_escalated_open.get(site_name, 0)),
                    "escalation_rate_percent": _safe_rate(
                        int(site_escalated_work_orders.get(site_name, 0)),
                        created_count,
                    ),
                    "sla_violation_rate_percent": _safe_rate(violation_count, created_count),
                    "median_ack_minutes": _median_minutes(ack_values),
                    "p90_ack_minutes": _percentile_minutes(ack_values, 90.0),
                }
            )
        top_risk_sites = sorted(
            top_risk_sites,
            key=lambda item: (
                float(item.get("sla_violation_rate_percent") or 0.0),
                float(item.get("escalation_rate_percent") or 0.0),
                int(item.get("overdue_open_work_orders") or 0),
                int(item.get("open_work_orders") or 0),
            ),
            reverse=True,
        )[:5]
    elif site is not None:
        ack_values = site_ack_values.get(site, [])
        created_count = int(site_created.get(site, 0))
        top_risk_sites = [
            {
                "site": site,
                "open_work_orders": open_work_orders,
                "overdue_open_work_orders": overdue_open_work_orders,
                "escalated_open_work_orders": escalated_open_work_orders,
                "escalation_rate_percent": _safe_rate(int(site_escalated_work_orders.get(site, 0)), created_count),
                "sla_violation_rate_percent": _safe_rate(int(site_violation_count.get(site, 0)), created_count),
                "median_ack_minutes": _median_minutes(ack_values),
                "p90_ack_minutes": _percentile_minutes(ack_values, 90.0),
            }
        ]

    target_response_improvement_percent = 10.0
    data_quality_issue_count = (
        missing_due_at_count
        + missing_priority_count
        + invalid_status_count
        + completed_without_completed_at_count
        + ack_before_created_count
        + completion_before_created_count
        + due_before_created_count
    )
    data_quality_critical_issue_count = (
        completed_without_completed_at_count
        + ack_before_created_count
        + completion_before_created_count
        + due_before_created_count
    )
    data_quality_issue_rate_percent = _safe_rate(data_quality_issue_count, created_work_orders)
    data_quality_gate_pass = data_quality_critical_issue_count == 0 and data_quality_issue_rate_percent <= 5.0

    recommendations: list[str] = []
    if response_time_improvement_percent is None:
        recommendations.append("ACK 반응시간 비교 데이터가 부족합니다. ack 이벤트를 누락 없이 기록하세요.")
    elif response_time_improvement_percent < target_response_improvement_percent:
        recommendations.append("SLA response 개선폭이 목표 미만입니다. 지연 site를 우선 코칭하세요.")
    if p90_ack_minutes is not None and p90_ack_minutes > 120.0:
        recommendations.append("ACK p90이 120분을 초과했습니다. 피크 시간대 큐 분산/즉시 ACK 룰을 적용하세요.")
    if sla_violation_rate_percent > 20.0:
        recommendations.append("SLA violation rate가 높습니다. due_at/우선순위 기준 triage를 즉시 강화하세요.")
    if overdue_open_work_orders > 0:
        recommendations.append("overdue open 작업지시가 남아 있습니다. 담당자 재할당과 ETA 재설정을 수행하세요.")
    if escalation_rate_percent >= max(0.0, W07_QUALITY_ALERT_ESCALATION_RATE_THRESHOLD):
        recommendations.append("escalation rate가 높습니다. 고위험 작업 분리 보드를 운영하세요.")
    if alert_total > 0 and alert_success_rate_percent < max(0.0, min(100.0, W07_QUALITY_ALERT_SUCCESS_RATE_THRESHOLD)):
        recommendations.append("alert 성공률이 낮습니다. 재시도 런과 채널 상태 점검을 실행하세요.")
    expected_runs = max(1, window_days // 7)
    if sla_run_count < expected_runs:
        recommendations.append("SLA 에스컬레이션 런 빈도가 낮습니다. Cron/수동 백업 런을 점검하세요.")
    if not data_quality_gate_pass:
        recommendations.append("데이터 품질 게이트 실패입니다. due_at/상태/타임스탬프 무결성을 먼저 복구하세요.")
    if not recommendations:
        recommendations.append("SLA 품질 지표가 목표 범위입니다. 현재 운영 리듬을 유지하세요.")

    return {
        "generated_at": now.isoformat(),
        "site": site,
        "window_days": window_days,
        "baseline_days": baseline_days,
        "target_response_improvement_percent": target_response_improvement_percent,
        "thresholds": {
            "escalation_rate_percent": round(max(0.0, W07_QUALITY_ALERT_ESCALATION_RATE_THRESHOLD), 2),
            "alert_success_rate_percent": round(max(0.0, min(100.0, W07_QUALITY_ALERT_SUCCESS_RATE_THRESHOLD)), 2),
            "data_quality_issue_rate_percent": 5.0,
        },
        "metrics": {
            "created_work_orders": created_work_orders,
            "acked_work_orders": acked_work_orders,
            "completed_work_orders": completed_work_orders,
            "median_ack_minutes": median_ack_minutes,
            "p90_ack_minutes": p90_ack_minutes,
            "baseline_median_ack_minutes": baseline_median_ack_minutes,
            "response_time_improvement_percent": response_time_improvement_percent,
            "target_met": (
                response_time_improvement_percent is not None
                and response_time_improvement_percent >= target_response_improvement_percent
            ),
            "median_mttr_minutes": median_mttr_minutes,
            "priority_mttr_minutes": priority_mttr_minutes,
            "sla_violation_count": sla_violation_count,
            "sla_violation_rate_percent": sla_violation_rate_percent,
            "open_work_orders": open_work_orders,
            "overdue_open_work_orders": overdue_open_work_orders,
            "escalated_open_work_orders": escalated_open_work_orders,
            "escalated_work_orders": escalated_work_orders,
            "escalation_rate_percent": escalation_rate_percent,
            "alert_total": alert_total,
            "alert_success_count": alert_success_count,
            "alert_success_rate_percent": alert_success_rate_percent,
            "sla_run_count": sla_run_count,
            "data_quality_gate_pass": data_quality_gate_pass,
            "data_quality_issue_count": data_quality_issue_count,
            "data_quality_critical_issue_count": data_quality_critical_issue_count,
            "data_quality_issue_rate_percent": data_quality_issue_rate_percent,
        },
        "data_quality": {
            "gate_pass": data_quality_gate_pass,
            "issue_count": data_quality_issue_count,
            "critical_issue_count": data_quality_critical_issue_count,
            "issue_rate_percent": data_quality_issue_rate_percent,
            "checks": {
                "missing_due_at_count": missing_due_at_count,
                "missing_priority_count": missing_priority_count,
                "invalid_status_count": invalid_status_count,
                "completed_without_completed_at_count": completed_without_completed_at_count,
                "ack_before_created_count": ack_before_created_count,
                "completion_before_created_count": completion_before_created_count,
                "due_before_created_count": due_before_created_count,
            },
        },
        "top_risk_sites": top_risk_sites,
        "recommendations": recommendations,
    }


def _build_w08_report_discipline_snapshot(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_days = max(14, min(int(days), 120))
    start = now - timedelta(days=window_days)

    def _safe_rate(numerator: int, denominator: int) -> float:
        if denominator <= 0:
            return 0.0
        return round((float(numerator) / float(denominator)) * 100.0, 2)

    def _priority_valid(value: Any) -> bool:
        return str(value or "").strip().lower() in {"low", "medium", "high", "critical"}

    wo_stmt = select(
        work_orders.c.site,
        work_orders.c.status,
        work_orders.c.priority,
        work_orders.c.due_at,
        work_orders.c.completed_at,
        work_orders.c.created_at,
    ).where(work_orders.c.created_at >= start)
    insp_stmt = select(
        inspections.c.site,
        inspections.c.risk_level,
        inspections.c.created_at,
    ).where(inspections.c.created_at >= start)
    export_stmt = (
        select(
            admin_audit_logs.c.action,
            admin_audit_logs.c.detail_json,
            admin_audit_logs.c.created_at,
        )
        .where(admin_audit_logs.c.created_at >= start)
        .where(admin_audit_logs.c.action.in_(["report_monthly_export_csv", "report_monthly_export_pdf"]))
    )

    if site is not None:
        wo_stmt = wo_stmt.where(work_orders.c.site == site)
        insp_stmt = insp_stmt.where(inspections.c.site == site)
    elif allowed_sites is not None:
        if not allowed_sites:
            return {
                "generated_at": now.isoformat(),
                "site": site,
                "window_days": window_days,
                "target_discipline_score": 85.0,
                "thresholds": {
                    "missing_due_rate_percent": 2.0,
                    "data_quality_issue_rate_percent": 5.0,
                    "report_export_coverage_percent": 95.0,
                },
                "metrics": {
                    "site_count": 0,
                    "work_orders_created": 0,
                    "work_orders_completed": 0,
                    "work_orders_missing_due_at": 0,
                    "missing_due_rate_percent": 0.0,
                    "invalid_priority_count": 0,
                    "completed_without_completed_at_count": 0,
                    "open_overdue_count": 0,
                    "overdue_rate_percent": 0.0,
                    "sla_violation_count": 0,
                    "sla_violation_rate_percent": 0.0,
                    "data_quality_issue_count": 0,
                    "data_quality_issue_rate_percent": 0.0,
                    "inspections_created": 0,
                    "inspections_high_risk": 0,
                    "report_export_count": 0,
                    "report_export_csv_count": 0,
                    "report_export_pdf_count": 0,
                    "report_export_coverage_percent": 0.0,
                    "report_export_last_at": None,
                    "discipline_score": 0.0,
                    "target_met": False,
                },
                "top_risk_sites": [],
                "site_benchmark": [],
                "recommendations": ["접근 가능한 site scope에 데이터가 없습니다."],
            }
        wo_stmt = wo_stmt.where(work_orders.c.site.in_(allowed_sites))
        insp_stmt = insp_stmt.where(inspections.c.site.in_(allowed_sites))

    with get_conn() as conn:
        wo_rows = conn.execute(wo_stmt).mappings().all()
        insp_rows = conn.execute(insp_stmt).mappings().all()
        export_rows = conn.execute(export_stmt).mappings().all()

    site_stats: dict[str, dict[str, Any]] = {}

    def _site_bucket(site_name: str) -> dict[str, Any]:
        if site_name not in site_stats:
            site_stats[site_name] = {
                "site": site_name,
                "work_orders_created": 0,
                "work_orders_completed": 0,
                "work_orders_missing_due_at": 0,
                "invalid_priority_count": 0,
                "completed_without_completed_at_count": 0,
                "open_overdue_count": 0,
                "sla_violation_count": 0,
                "data_quality_issue_count": 0,
                "inspections_created": 0,
                "inspections_high_risk": 0,
                "report_export_count": 0,
                "report_export_csv_count": 0,
                "report_export_pdf_count": 0,
                "report_export_last_at": None,
            }
        return site_stats[site_name]

    for row in wo_rows:
        site_name = _normalize_site_name(str(row.get("site") or ""))
        if site_name is None:
            continue
        bucket = _site_bucket(site_name)
        bucket["work_orders_created"] = int(bucket["work_orders_created"]) + 1

        status = str(row.get("status") or "").strip().lower()
        due_at = _as_optional_datetime(row.get("due_at"))
        completed_at = _as_optional_datetime(row.get("completed_at"))

        if status == "completed":
            bucket["work_orders_completed"] = int(bucket["work_orders_completed"]) + 1
            if completed_at is None:
                bucket["completed_without_completed_at_count"] = int(bucket["completed_without_completed_at_count"]) + 1

        if due_at is None:
            bucket["work_orders_missing_due_at"] = int(bucket["work_orders_missing_due_at"]) + 1

        if not _priority_valid(row.get("priority")):
            bucket["invalid_priority_count"] = int(bucket["invalid_priority_count"]) + 1

        is_open = status in {"open", "acked"}
        if is_open and due_at is not None and due_at < now:
            bucket["open_overdue_count"] = int(bucket["open_overdue_count"]) + 1

        violated = False
        if due_at is not None:
            if completed_at is not None:
                violated = completed_at > due_at
            elif is_open:
                violated = now > due_at
        if violated:
            bucket["sla_violation_count"] = int(bucket["sla_violation_count"]) + 1

    for row in insp_rows:
        site_name = _normalize_site_name(str(row.get("site") or ""))
        if site_name is None:
            continue
        bucket = _site_bucket(site_name)
        bucket["inspections_created"] = int(bucket["inspections_created"]) + 1
        risk = str(row.get("risk_level") or "").strip().lower()
        if risk in {"high", "critical"}:
            bucket["inspections_high_risk"] = int(bucket["inspections_high_risk"]) + 1

    for row in export_rows:
        action = str(row.get("action") or "").strip().lower()
        detail = _parse_job_detail_json(row.get("detail_json"))
        detail_site_raw = detail.get("site")
        detail_site = _normalize_site_name(str(detail_site_raw)) if detail_site_raw is not None else None

        if site is not None:
            if detail_site not in {None, "ALL", site}:
                continue
            target_site = site
        elif allowed_sites is not None:
            if detail_site is None or detail_site == "ALL" or detail_site not in allowed_sites:
                continue
            target_site = detail_site
        else:
            if detail_site in {None, "ALL"}:
                continue
            target_site = detail_site

        if target_site is None:
            continue
        bucket = _site_bucket(target_site)
        bucket["report_export_count"] = int(bucket["report_export_count"]) + 1
        if action == "report_monthly_export_csv":
            bucket["report_export_csv_count"] = int(bucket["report_export_csv_count"]) + 1
        if action == "report_monthly_export_pdf":
            bucket["report_export_pdf_count"] = int(bucket["report_export_pdf_count"]) + 1
        created_at = _as_optional_datetime(row.get("created_at"))
        current_last = _as_optional_datetime(bucket.get("report_export_last_at"))
        if created_at is not None and (current_last is None or created_at > current_last):
            bucket["report_export_last_at"] = created_at

    benchmark_rows: list[dict[str, Any]] = []
    for site_name in sorted(site_stats.keys()):
        bucket = site_stats[site_name]
        created_count = int(bucket["work_orders_created"])
        missing_due = int(bucket["work_orders_missing_due_at"])
        invalid_priority = int(bucket["invalid_priority_count"])
        completed_missing = int(bucket["completed_without_completed_at_count"])
        overdue_open = int(bucket["open_overdue_count"])
        violations = int(bucket["sla_violation_count"])
        data_quality_issue_count = missing_due + invalid_priority + completed_missing
        bucket["data_quality_issue_count"] = data_quality_issue_count

        missing_due_rate = _safe_rate(missing_due, created_count)
        overdue_rate = _safe_rate(overdue_open, created_count)
        violation_rate = _safe_rate(violations, created_count)
        data_quality_issue_rate = _safe_rate(data_quality_issue_count, created_count)

        expected_exports = max(1, int(math.ceil(float(window_days) / 30.0)) * 2)
        export_coverage = _safe_rate(int(bucket["report_export_count"]), expected_exports)
        risk_score = round((data_quality_issue_rate * 0.4) + (overdue_rate * 0.3) + (violation_rate * 0.3), 2)
        discipline_score = round(
            max(0.0, min(100.0, 100.0 - risk_score + min(15.0, export_coverage * 0.15))),
            2,
        )

        benchmark_rows.append(
            {
                "site": site_name,
                "work_orders_created": created_count,
                "work_orders_completed": int(bucket["work_orders_completed"]),
                "missing_due_rate_percent": missing_due_rate,
                "overdue_rate_percent": overdue_rate,
                "sla_violation_rate_percent": violation_rate,
                "data_quality_issue_rate_percent": data_quality_issue_rate,
                "report_export_count": int(bucket["report_export_count"]),
                "report_export_coverage_percent": export_coverage,
                "inspections_high_risk": int(bucket["inspections_high_risk"]),
                "risk_score": risk_score,
                "discipline_score": discipline_score,
                "report_export_last_at": (
                    _as_optional_datetime(bucket.get("report_export_last_at")).isoformat()
                    if _as_optional_datetime(bucket.get("report_export_last_at")) is not None
                    else None
                ),
            }
        )

    total_created = sum(int(row.get("work_orders_created") or 0) for row in benchmark_rows)
    total_completed = sum(int(row.get("work_orders_completed") or 0) for row in benchmark_rows)
    total_missing_due = sum(int(site_stats[row["site"]]["work_orders_missing_due_at"]) for row in benchmark_rows)
    total_invalid_priority = sum(int(site_stats[row["site"]]["invalid_priority_count"]) for row in benchmark_rows)
    total_completed_missing = sum(int(site_stats[row["site"]]["completed_without_completed_at_count"]) for row in benchmark_rows)
    total_overdue_open = sum(int(site_stats[row["site"]]["open_overdue_count"]) for row in benchmark_rows)
    total_violations = sum(int(site_stats[row["site"]]["sla_violation_count"]) for row in benchmark_rows)
    total_issue_count = sum(int(site_stats[row["site"]]["data_quality_issue_count"]) for row in benchmark_rows)
    total_inspections = sum(int(site_stats[row["site"]]["inspections_created"]) for row in benchmark_rows)
    total_high_risk = sum(int(site_stats[row["site"]]["inspections_high_risk"]) for row in benchmark_rows)
    total_exports = sum(int(site_stats[row["site"]]["report_export_count"]) for row in benchmark_rows)
    total_exports_csv = sum(int(site_stats[row["site"]]["report_export_csv_count"]) for row in benchmark_rows)
    total_exports_pdf = sum(int(site_stats[row["site"]]["report_export_pdf_count"]) for row in benchmark_rows)

    expected_total_exports = max(1, int(math.ceil(float(window_days) / 30.0)) * 2 * max(1, len(benchmark_rows)))
    export_coverage_percent = _safe_rate(total_exports, expected_total_exports)
    missing_due_rate_percent = _safe_rate(total_missing_due, total_created)
    overdue_rate_percent = _safe_rate(total_overdue_open, total_created)
    violation_rate_percent = _safe_rate(total_violations, total_created)
    issue_rate_percent = _safe_rate(total_issue_count, total_created)
    global_risk_score = round((issue_rate_percent * 0.4) + (overdue_rate_percent * 0.3) + (violation_rate_percent * 0.3), 2)
    discipline_score = round(
        max(0.0, min(100.0, 100.0 - global_risk_score + min(15.0, export_coverage_percent * 0.15))),
        2,
    )

    top_risk_sites = sorted(
        benchmark_rows,
        key=lambda row: (
            float(row.get("risk_score") or 0.0),
            float(row.get("overdue_rate_percent") or 0.0),
            int(row.get("work_orders_created") or 0),
        ),
        reverse=True,
    )[:5]
    site_benchmark = sorted(
        benchmark_rows,
        key=lambda row: (
            float(row.get("discipline_score") or 0.0),
            float(row.get("report_export_coverage_percent") or 0.0),
            -float(row.get("risk_score") or 0.0),
        ),
        reverse=True,
    )

    report_export_last_at: str | None = None
    for row in benchmark_rows:
        candidate = _as_optional_datetime(row.get("report_export_last_at"))
        if candidate is None:
            continue
        current = _as_optional_datetime(report_export_last_at)
        if current is None or candidate > current:
            report_export_last_at = candidate.isoformat()

    recommendations: list[str] = []
    if missing_due_rate_percent > 2.0:
        recommendations.append("due_at 누락 비율이 높습니다. 생성 단계 필수값 검증을 강화하세요.")
    if issue_rate_percent > 5.0:
        recommendations.append("데이터 품질 이슈율이 기준을 초과했습니다. 일일 triage를 고정하세요.")
    if overdue_rate_percent > 10.0:
        recommendations.append("overdue open 비율이 높습니다. 담당자 재할당과 ETA 재설정을 수행하세요.")
    if violation_rate_percent > 10.0:
        recommendations.append("SLA 위반률이 높습니다. 우선순위 기준과 마감 정책을 재점검하세요.")
    if export_coverage_percent < 95.0:
        recommendations.append("월간 리포트 export 커버리지가 낮습니다. CSV/PDF 리허설을 주간 루틴에 추가하세요.")
    if total_high_risk > 0 and total_inspections > 0:
        recommendations.append("고위험 점검 항목이 존재합니다. W07 고위험 대응 플레이와 연동하세요.")
    if not recommendations:
        recommendations.append("W08 리포트 규율 지표가 안정적입니다. 현재 운영 리듬을 유지하세요.")

    return {
        "generated_at": now.isoformat(),
        "site": site,
        "window_days": window_days,
        "target_discipline_score": 85.0,
        "thresholds": {
            "missing_due_rate_percent": 2.0,
            "data_quality_issue_rate_percent": 5.0,
            "report_export_coverage_percent": 95.0,
        },
        "metrics": {
            "site_count": len(benchmark_rows),
            "work_orders_created": total_created,
            "work_orders_completed": total_completed,
            "work_orders_missing_due_at": total_missing_due,
            "missing_due_rate_percent": missing_due_rate_percent,
            "invalid_priority_count": total_invalid_priority,
            "completed_without_completed_at_count": total_completed_missing,
            "open_overdue_count": total_overdue_open,
            "overdue_rate_percent": overdue_rate_percent,
            "sla_violation_count": total_violations,
            "sla_violation_rate_percent": violation_rate_percent,
            "data_quality_issue_count": total_issue_count,
            "data_quality_issue_rate_percent": issue_rate_percent,
            "inspections_created": total_inspections,
            "inspections_high_risk": total_high_risk,
            "report_export_count": total_exports,
            "report_export_csv_count": total_exports_csv,
            "report_export_pdf_count": total_exports_pdf,
            "report_export_coverage_percent": export_coverage_percent,
            "report_export_last_at": report_export_last_at,
            "discipline_score": discipline_score,
            "target_met": discipline_score >= 85.0,
        },
        "top_risk_sites": top_risk_sites,
        "site_benchmark": site_benchmark,
        "recommendations": recommendations,
    }


def _build_w09_kpi_operation_snapshot(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_days = max(14, min(int(days), 120))
    policy, policy_updated_at, policy_key, policy_site = _ensure_w09_kpi_policy(site)

    effective_site = policy_site if policy_site is not None else _normalize_site_name(site)
    effective_allowed_sites = allowed_sites if effective_site is None else None

    w05 = _build_w05_usage_consistency_snapshot(
        site=effective_site,
        days=window_days,
        allowed_sites=effective_allowed_sites,
    )
    w06 = _build_w06_operational_rhythm_snapshot(
        site=effective_site,
        days=window_days,
        allowed_sites=effective_allowed_sites,
    )
    w07 = _build_w07_sla_quality_snapshot(
        site=effective_site,
        days=max(7, min(window_days, 90)),
        allowed_sites=effective_allowed_sites,
    )
    w08 = _build_w08_report_discipline_snapshot(
        site=effective_site,
        days=window_days,
        allowed_sites=effective_allowed_sites,
    )

    w05_metrics = w05.get("metrics", {}) if isinstance(w05.get("metrics"), dict) else {}
    w06_metrics = w06.get("metrics", {}) if isinstance(w06.get("metrics"), dict) else {}
    w07_metrics = w07.get("metrics", {}) if isinstance(w07.get("metrics"), dict) else {}
    w08_metrics = w08.get("metrics", {}) if isinstance(w08.get("metrics"), dict) else {}

    metric_values: dict[str, float | None] = {
        "two_week_retention_percent": (
            float(w05_metrics.get("two_week_retention_percent"))
            if w05_metrics.get("two_week_retention_percent") is not None
            else None
        ),
        "weekly_active_rate_percent": (
            float(w06_metrics.get("weekly_active_rate_percent"))
            if w06_metrics.get("weekly_active_rate_percent") is not None
            else None
        ),
        "escalation_rate_percent": (
            float(w07_metrics.get("escalation_rate_percent"))
            if w07_metrics.get("escalation_rate_percent") is not None
            else None
        ),
        "report_discipline_score": (
            float(w08_metrics.get("discipline_score"))
            if w08_metrics.get("discipline_score") is not None
            else None
        ),
        "data_quality_issue_rate_percent": (
            float(w08_metrics.get("data_quality_issue_rate_percent"))
            if w08_metrics.get("data_quality_issue_rate_percent") is not None
            else None
        ),
    }

    kpis = policy.get("kpis", []) if isinstance(policy.get("kpis"), list) else []
    rows: list[dict[str, Any]] = []
    status_counts = {W09_KPI_STATUS_GREEN: 0, W09_KPI_STATUS_YELLOW: 0, W09_KPI_STATUS_RED: 0}
    owner_assigned_count = 0

    escalation_map = policy.get("escalation_map", []) if isinstance(policy.get("escalation_map"), list) else []
    escalation_by_kpi: dict[str, list[dict[str, Any]]] = {}
    for item in escalation_map:
        if not isinstance(item, dict):
            continue
        kpi_key = str(item.get("kpi_key") or "")
        escalation_by_kpi.setdefault(kpi_key, []).append(item)

    for item in kpis:
        if not isinstance(item, dict):
            continue
        kpi_key = str(item.get("kpi_key") or "").strip()
        if not kpi_key:
            continue
        kpi_name = str(item.get("kpi_name") or kpi_key)
        direction = str(item.get("direction") or "higher_better").strip().lower()
        owner_role = str(item.get("owner_role") or "").strip()
        if owner_role:
            owner_assigned_count += 1
        try:
            green_threshold = float(item.get("green_threshold") or 0.0)
        except (TypeError, ValueError):
            green_threshold = 0.0
        try:
            yellow_threshold = float(item.get("yellow_threshold") or 0.0)
        except (TypeError, ValueError):
            yellow_threshold = 0.0

        actual_value = metric_values.get(kpi_key)
        status = _evaluate_w09_kpi_status(
            actual=actual_value,
            direction=direction,
            green_threshold=green_threshold,
            yellow_threshold=yellow_threshold,
        )
        status_counts[status] = int(status_counts.get(status, 0)) + 1
        rows.append(
            {
                "kpi_key": kpi_key,
                "kpi_name": kpi_name,
                "owner_role": owner_role,
                "direction": direction,
                "target": str(item.get("target") or ""),
                "actual_value": actual_value,
                "green_threshold": round(green_threshold, 2),
                "yellow_threshold": round(yellow_threshold, 2),
                "status": status,
                "source_api": str(item.get("source_api") or ""),
                "escalation_rules": escalation_by_kpi.get(kpi_key, []),
            }
        )

    total_kpis = len(rows)
    owner_coverage_percent = round((owner_assigned_count / total_kpis) * 100.0, 2) if total_kpis > 0 else 0.0
    red_count = int(status_counts.get(W09_KPI_STATUS_RED, 0))
    yellow_count = int(status_counts.get(W09_KPI_STATUS_YELLOW, 0))
    green_count = int(status_counts.get(W09_KPI_STATUS_GREEN, 0))

    overall_status = W09_KPI_STATUS_GREEN
    if red_count > 0:
        overall_status = W09_KPI_STATUS_RED
    elif yellow_count > 0:
        overall_status = W09_KPI_STATUS_YELLOW
    if owner_coverage_percent < 100.0 and overall_status == W09_KPI_STATUS_GREEN:
        overall_status = W09_KPI_STATUS_YELLOW

    escalation_candidates: list[dict[str, Any]] = []
    for row in rows:
        if str(row.get("status")) != W09_KPI_STATUS_RED:
            continue
        for rule in row.get("escalation_rules", []):
            if not isinstance(rule, dict):
                continue
            escalation_candidates.append(
                {
                    "kpi_key": row.get("kpi_key"),
                    "kpi_name": row.get("kpi_name"),
                    "actual_value": row.get("actual_value"),
                    "condition": str(rule.get("condition") or ""),
                    "escalate_to": str(rule.get("escalate_to") or ""),
                    "sla_hours": int(rule.get("sla_hours") or 24),
                    "action": str(rule.get("action") or ""),
                }
            )

    top_red_kpis = [
        {
            "kpi_key": row.get("kpi_key"),
            "kpi_name": row.get("kpi_name"),
            "actual_value": row.get("actual_value"),
            "target": row.get("target"),
            "owner_role": row.get("owner_role"),
        }
        for row in rows
        if str(row.get("status")) == W09_KPI_STATUS_RED
    ][:3]

    recommendations: list[str] = []
    if owner_coverage_percent < 100.0:
        recommendations.append("KPI owner 미지정 항목이 있습니다. Owner assignment를 100%로 맞추세요.")
    if red_count > 0:
        recommendations.append("Red KPI가 있습니다. 에스컬레이션 맵 기준으로 즉시 담당/기한을 지정하세요.")
    if red_count == 0 and yellow_count > 0:
        recommendations.append("Yellow KPI가 남아 있습니다. 임계값 경계 KPI를 주중 재점검하세요.")
    if red_count == 0 and yellow_count == 0 and owner_coverage_percent >= 100.0:
        recommendations.append("W09 KPI 운영 상태가 안정적입니다. 현재 리듬을 유지하세요.")

    return {
        "generated_at": now.isoformat(),
        "site": effective_site,
        "window_days": window_days,
        "policy": {
            "policy_key": policy_key,
            "updated_at": policy_updated_at.isoformat(),
            "enabled": bool(policy.get("enabled", True)),
            "kpi_count": total_kpis,
            "escalation_rule_count": len(escalation_map),
        },
        "metrics": {
            "kpi_count": total_kpis,
            "owner_assigned_count": owner_assigned_count,
            "owner_coverage_percent": owner_coverage_percent,
            "green_count": green_count,
            "yellow_count": yellow_count,
            "red_count": red_count,
            "overall_status": overall_status,
        },
        "kpis": rows,
        "top_red_kpis": top_red_kpis,
        "escalation_candidates": escalation_candidates[:10],
        "source_metrics": {
            "w05_two_week_retention_percent": metric_values.get("two_week_retention_percent"),
            "w06_weekly_active_rate_percent": metric_values.get("weekly_active_rate_percent"),
            "w07_escalation_rate_percent": metric_values.get("escalation_rate_percent"),
            "w08_report_discipline_score": metric_values.get("report_discipline_score"),
            "w08_data_quality_issue_rate_percent": metric_values.get("data_quality_issue_rate_percent"),
        },
        "recommendations": recommendations,
    }


def _parse_job_detail_json(raw: Any) -> dict[str, Any]:
    try:
        loaded = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        loaded = {}
    if isinstance(loaded, dict):
        return loaded
    return {}


def _build_w07_degradation_signals(snapshot: dict[str, Any]) -> dict[str, Any]:
    metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
    escalation_rate = float(metrics.get("escalation_rate_percent") or 0.0)
    alert_success_rate = float(metrics.get("alert_success_rate_percent") or 0.0)
    violation_rate = float(metrics.get("sla_violation_rate_percent") or 0.0)
    data_quality_gate_pass = bool(metrics.get("data_quality_gate_pass", True))
    response_improvement = metrics.get("response_time_improvement_percent")

    escalation_threshold = max(0.0, W07_QUALITY_ALERT_ESCALATION_RATE_THRESHOLD)
    success_threshold = max(0.0, min(100.0, W07_QUALITY_ALERT_SUCCESS_RATE_THRESHOLD))
    violation_threshold = max(10.0, escalation_threshold)

    reasons: list[str] = []
    if escalation_rate >= escalation_threshold:
        reasons.append(f"escalation_rate={escalation_rate}% >= {round(escalation_threshold, 2)}%")
    if alert_success_rate < success_threshold:
        reasons.append(f"alert_success_rate={alert_success_rate}% < {round(success_threshold, 2)}%")
    if violation_rate >= violation_threshold:
        reasons.append(f"sla_violation_rate={violation_rate}% >= {round(violation_threshold, 2)}%")
    if not data_quality_gate_pass:
        reasons.append("data_quality_gate=FAIL")
    if isinstance(response_improvement, (int, float)) and float(response_improvement) < 0:
        reasons.append(f"ack_improvement={round(float(response_improvement), 2)}% < 0%")

    return {
        "degraded": len(reasons) > 0,
        "reasons": reasons,
        "signals": {
            "escalation_rate_percent": round(escalation_rate, 2),
            "alert_success_rate_percent": round(alert_success_rate, 2),
            "sla_violation_rate_percent": round(violation_rate, 2),
            "data_quality_gate_pass": data_quality_gate_pass,
            "response_time_improvement_percent": response_improvement,
        },
        "thresholds": {
            "escalation_rate_percent": round(escalation_threshold, 2),
            "alert_success_rate_percent": round(success_threshold, 2),
            "sla_violation_rate_percent": round(violation_threshold, 2),
        },
    }


def _w07_alert_cooldown_state(*, now: datetime, site: str | None, max_rows: int = 200) -> tuple[bool, int, str | None]:
    cooldown_minutes = max(0, W07_QUALITY_ALERT_COOLDOWN_MINUTES)
    if cooldown_minutes <= 0:
        return False, 0, None

    with get_conn() as conn:
        rows = conn.execute(
            select(
                alert_deliveries.c.payload_json,
                alert_deliveries.c.last_attempt_at,
                alert_deliveries.c.created_at,
            )
            .where(alert_deliveries.c.event_type == W07_DEGRADATION_ALERT_EVENT_TYPE)
            .order_by(alert_deliveries.c.last_attempt_at.desc(), alert_deliveries.c.id.desc())
            .limit(max(1, min(max_rows, 500)))
        ).mappings().all()

    target_site = _normalize_site_name(site)
    for row in rows:
        payload = _parse_job_detail_json(row.get("payload_json"))
        payload_site = _normalize_site_name(str(payload.get("site") or "")) if payload.get("site") is not None else None
        if target_site is None:
            if payload_site not in {None, "ALL"}:
                continue
        elif payload_site != target_site:
            continue

        attempted_at = _as_optional_datetime(row.get("last_attempt_at")) or _as_optional_datetime(row.get("created_at"))
        if attempted_at is None:
            continue
        next_allowed_at = attempted_at + timedelta(minutes=cooldown_minutes)
        if now < next_allowed_at:
            remaining = max(1, int(math.ceil((next_allowed_at - now).total_seconds() / 60.0)))
            return True, remaining, attempted_at.isoformat()
        return False, 0, attempted_at.isoformat()
    return False, 0, None


def run_w07_sla_quality_weekly_job(
    *,
    site: str | None = None,
    days: int = 14,
    trigger: str = "api",
    force_notify: bool = False,
    allowed_sites: list[str] | None = None,
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    run_site = _normalize_site_name(site)
    window_days = max(max(7, W07_QUALITY_ALERT_MIN_WINDOW_DAYS), min(int(days), 90))
    snapshot = _build_w07_sla_quality_snapshot(
        site=run_site,
        days=window_days,
        allowed_sites=allowed_sites if run_site is None else None,
    )
    degradation = _build_w07_degradation_signals(snapshot)
    now = datetime.now(timezone.utc)

    alert_attempted = False
    alert_dispatched = False
    alert_error: str | None = None
    alert_channels: list[SlaAlertChannelResult] = []
    cooldown_active = False
    cooldown_remaining_minutes = 0
    last_alert_at: str | None = None

    if bool(degradation.get("degraded")) and W07_QUALITY_ALERT_ENABLED:
        cooldown_active, cooldown_remaining_minutes, last_alert_at = _w07_alert_cooldown_state(
            now=now,
            site=run_site,
        )
        if force_notify or not cooldown_active:
            alert_attempted = True
            payload = {
                "event": W07_DEGRADATION_ALERT_EVENT_TYPE,
                "site": run_site or "ALL",
                "checked_at": now.isoformat(),
                "window_days": int(snapshot.get("window_days") or window_days),
                "signals": degradation.get("signals", {}),
                "thresholds": degradation.get("thresholds", {}),
                "reasons": degradation.get("reasons", []),
                "metrics": snapshot.get("metrics", {}),
            }
            alert_dispatched, alert_error, alert_channels = _dispatch_alert_event(
                event_type=W07_DEGRADATION_ALERT_EVENT_TYPE,
                payload=payload,
            )

    status = "success"
    if bool(degradation.get("degraded")):
        status = "warning"
        if alert_attempted and not alert_dispatched:
            status = "critical"

    finished_at = datetime.now(timezone.utc)
    detail = {
        "site": run_site,
        "window_days": window_days,
        "degradation": degradation,
        "alert_enabled": W07_QUALITY_ALERT_ENABLED,
        "force_notify": force_notify,
        "cooldown_active": cooldown_active,
        "cooldown_remaining_minutes": cooldown_remaining_minutes,
        "last_alert_at": last_alert_at,
        "alert_attempted": alert_attempted,
        "alert_dispatched": alert_dispatched,
        "alert_error": alert_error,
        "alert_channels": [item.model_dump(mode="json") for item in alert_channels],
        "snapshot": snapshot,
    }
    run_id = _write_job_run(
        job_name=W07_WEEKLY_JOB_NAME,
        trigger=trigger,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        detail=detail,
    )
    return {
        "run_id": run_id,
        "job_name": W07_WEEKLY_JOB_NAME,
        "trigger": trigger,
        "status": status,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "site": run_site,
        "window_days": window_days,
        "degradation": degradation,
        "cooldown_active": cooldown_active,
        "cooldown_remaining_minutes": cooldown_remaining_minutes,
        "last_alert_at": last_alert_at,
        "alert_enabled": W07_QUALITY_ALERT_ENABLED,
        "alert_attempted": alert_attempted,
        "alert_dispatched": alert_dispatched,
        "alert_error": alert_error,
        "alert_channels": [item.model_dump(mode="json") for item in alert_channels],
        "snapshot": snapshot,
    }


def _is_w07_run_visible(
    *,
    detail_site: str | None,
    requested_site: str | None,
    allowed_sites: list[str] | None,
) -> bool:
    if requested_site is not None:
        return detail_site == requested_site
    if allowed_sites is None:
        return True
    if not allowed_sites:
        return False
    if detail_site is None:
        return False
    return detail_site in allowed_sites


def _read_w07_weekly_job_runs(
    *,
    site: str | None,
    allowed_sites: list[str] | None,
    limit: int,
) -> list[tuple[JobRunRead, dict[str, Any]]]:
    with get_conn() as conn:
        rows = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == W07_WEEKLY_JOB_NAME)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(max(1, min(limit * 10, 1000)))
        ).mappings().all()

    collected: list[tuple[JobRunRead, dict[str, Any]]] = []
    for row in rows:
        model = _row_to_job_run_model(row)
        detail = model.detail if isinstance(model.detail, dict) else {}
        detail_site = _normalize_site_name(detail.get("site"))
        if not _is_w07_run_visible(detail_site=detail_site, requested_site=site, allowed_sites=allowed_sites):
            continue
        collected.append((model, detail))
        if len(collected) >= limit:
            break
    return collected


def _build_w07_weekly_trends_payload(
    *,
    site: str | None,
    allowed_sites: list[str] | None,
    limit: int = 26,
) -> dict[str, Any]:
    runs = _read_w07_weekly_job_runs(site=site, allowed_sites=allowed_sites, limit=max(1, min(limit, 104)))
    points: list[dict[str, Any]] = []
    for model, detail in reversed(runs):
        snapshot = detail.get("snapshot", {}) if isinstance(detail.get("snapshot"), dict) else {}
        metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
        degradation = detail.get("degradation", {}) if isinstance(detail.get("degradation"), dict) else {}
        signals = degradation.get("signals", {}) if isinstance(degradation.get("signals"), dict) else {}
        points.append(
            {
                "run_id": model.id,
                "finished_at": model.finished_at.isoformat(),
                "site": detail.get("site"),
                "status": model.status,
                "window_days": detail.get("window_days"),
                "degraded": bool(degradation.get("degraded", False)),
                "escalation_rate_percent": signals.get("escalation_rate_percent", metrics.get("escalation_rate_percent")),
                "alert_success_rate_percent": signals.get("alert_success_rate_percent", metrics.get("alert_success_rate_percent")),
                "sla_violation_rate_percent": signals.get("sla_violation_rate_percent", metrics.get("sla_violation_rate_percent")),
                "median_ack_minutes": metrics.get("median_ack_minutes"),
                "p90_ack_minutes": metrics.get("p90_ack_minutes"),
                "median_mttr_minutes": metrics.get("median_mttr_minutes"),
                "data_quality_gate_pass": bool(signals.get("data_quality_gate_pass", metrics.get("data_quality_gate_pass", True))),
            }
        )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "job_name": W07_WEEKLY_JOB_NAME,
        "site": site,
        "point_count": len(points),
        "points": points,
    }


def _build_w07_weekly_archive_csv(points: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "run_id",
            "finished_at",
            "site",
            "status",
            "window_days",
            "degraded",
            "escalation_rate_percent",
            "alert_success_rate_percent",
            "sla_violation_rate_percent",
            "median_ack_minutes",
            "p90_ack_minutes",
            "median_mttr_minutes",
            "data_quality_gate_pass",
        ]
    )
    for row in points:
        writer.writerow(
            [
                row.get("run_id"),
                row.get("finished_at"),
                row.get("site"),
                row.get("status"),
                row.get("window_days"),
                bool(row.get("degraded", False)),
                row.get("escalation_rate_percent"),
                row.get("alert_success_rate_percent"),
                row.get("sla_violation_rate_percent"),
                row.get("median_ack_minutes"),
                row.get("p90_ack_minutes"),
                row.get("median_mttr_minutes"),
                bool(row.get("data_quality_gate_pass", True)),
            ]
        )
    return buffer.getvalue()


def _build_w07_tracker_items_csv(rows: list[W07TrackerItemRead]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "id",
            "site",
            "item_type",
            "item_key",
            "item_name",
            "assignee",
            "status",
            "completion_checked",
            "completion_note",
            "due_at",
            "completed_at",
            "evidence_count",
            "updated_at",
        ]
    )
    for row in rows:
        writer.writerow(
            [
                row.id,
                row.site,
                row.item_type,
                row.item_key,
                row.item_name,
                row.assignee or "",
                row.status,
                bool(row.completion_checked),
                row.completion_note or "",
                row.due_at.isoformat() if row.due_at is not None else "",
                row.completed_at.isoformat() if row.completed_at is not None else "",
                int(row.evidence_count),
                row.updated_at.isoformat(),
            ]
        )
    return buffer.getvalue()


def _build_w07_evidence_index_csv(rows: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "evidence_id",
            "tracker_item_id",
            "item_key",
            "item_type",
            "file_name",
            "content_type",
            "file_size",
            "sha256",
            "uploaded_by",
            "uploaded_at",
            "archive_path",
            "blob_included",
            "include_reason",
        ]
    )
    for row in rows:
        writer.writerow(
            [
                row.get("evidence_id"),
                row.get("tracker_item_id"),
                row.get("item_key"),
                row.get("item_type"),
                row.get("file_name"),
                row.get("content_type"),
                row.get("file_size"),
                row.get("sha256"),
                row.get("uploaded_by"),
                row.get("uploaded_at"),
                row.get("archive_path"),
                bool(row.get("blob_included", False)),
                row.get("include_reason"),
            ]
        )
    return buffer.getvalue()


def _build_w07_completion_package_zip(
    *,
    site: str,
    completion: W07TrackerCompletionRead,
    rows: list[W07TrackerItemRead],
    include_evidence: bool,
    include_weekly: bool,
    weekly_limit: int,
    principal: dict[str, Any] | None,
) -> tuple[bytes, dict[str, Any]]:
    generated_at = datetime.now(timezone.utc)
    actor = str((principal or {}).get("username") or "system")
    tracker_csv = _build_w07_tracker_items_csv(rows)
    tracker_json = [row.model_dump(mode="json") for row in rows]

    item_by_id: dict[int, W07TrackerItemRead] = {int(row.id): row for row in rows}
    evidence_index_rows: list[dict[str, Any]] = []
    evidence_file_count = 0
    evidence_bytes_included = 0
    evidence_missing_blob_count = 0
    evidence_truncated = False
    weekly_payload: dict[str, Any] | None = None
    weekly_latest_payload: dict[str, Any] | None = None
    weekly_csv: str | None = None

    if include_weekly:
        weekly_payload = _build_w07_weekly_trends_payload(
            site=site,
            allowed_sites=None,
            limit=max(1, min(int(weekly_limit), 104)),
        )
        weekly_csv = _build_w07_weekly_archive_csv(weekly_payload.get("points", []))
        latest_runs = _read_w07_weekly_job_runs(site=site, allowed_sites=None, limit=1)
        if latest_runs:
            latest_model, latest_detail = latest_runs[0]
            weekly_latest_payload = {
                "run_id": latest_model.id,
                "job_name": latest_model.job_name,
                "status": latest_model.status,
                "trigger": latest_model.trigger,
                "started_at": latest_model.started_at.isoformat(),
                "finished_at": latest_model.finished_at.isoformat(),
                "detail": latest_detail,
            }
        else:
            weekly_latest_payload = {
                "run_id": None,
                "job_name": W07_WEEKLY_JOB_NAME,
                "status": "not_found",
                "detail": {},
            }

    with get_conn() as conn:
        evidence_rows = conn.execute(
            select(adoption_w07_evidence_files)
            .where(adoption_w07_evidence_files.c.site == site)
            .order_by(adoption_w07_evidence_files.c.uploaded_at.asc(), adoption_w07_evidence_files.c.id.asc())
        ).mappings().all()

    package_buffer = io.BytesIO()
    with zipfile.ZipFile(package_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "README.txt",
            "\n".join(
                [
                    "KA Facility OS - W07 Completion Package",
                    f"site={site}",
                    f"generated_at={generated_at.isoformat()}",
                    f"generated_by={actor}",
                    "",
                    "Contents:",
                    "- manifest.json",
                    "- completion/completion.json",
                    "- completion/readiness.json",
                    "- tracker/items.json",
                    "- tracker/items.csv",
                    "- evidence/index.csv (optional)",
                    "- evidence/files/* (optional)",
                    "- weekly/latest.json (optional)",
                    "- weekly/trends.json (optional)",
                    "- weekly/trends.csv (optional)",
                ]
            ),
        )
        zf.writestr(
            "completion/completion.json",
            json.dumps(completion.model_dump(mode="json"), ensure_ascii=False, indent=2, default=str),
        )
        zf.writestr(
            "completion/readiness.json",
            json.dumps(completion.readiness.model_dump(mode="json"), ensure_ascii=False, indent=2, default=str),
        )
        zf.writestr("tracker/items.csv", tracker_csv)
        zf.writestr("tracker/items.json", json.dumps(tracker_json, ensure_ascii=False, indent=2, default=str))
        blockers = completion.readiness.blockers if isinstance(completion.readiness.blockers, list) else []
        zf.writestr("completion/blockers.txt", "\n".join([str(x) for x in blockers]) + ("\n" if blockers else ""))

        if include_weekly and weekly_payload is not None and weekly_csv is not None:
            zf.writestr("weekly/trends.csv", weekly_csv)
            zf.writestr(
                "weekly/trends.json",
                json.dumps(weekly_payload, ensure_ascii=False, indent=2, default=str),
            )
            if weekly_latest_payload is not None:
                zf.writestr(
                    "weekly/latest.json",
                    json.dumps(weekly_latest_payload, ensure_ascii=False, indent=2, default=str),
                )

        if include_evidence:
            for evidence in evidence_rows:
                evidence_id = int(evidence.get("id") or 0)
                tracker_item_id = int(evidence.get("tracker_item_id") or 0)
                model = item_by_id.get(tracker_item_id)
                safe_item_key = _safe_download_filename(
                    str(model.item_key) if model is not None else f"item-{tracker_item_id}",
                    fallback=f"item-{tracker_item_id}",
                    max_length=80,
                )
                safe_file_name = _safe_download_filename(
                    str(evidence.get("file_name") or ""),
                    fallback=f"evidence-{evidence_id}.bin",
                    max_length=120,
                )
                archive_path = f"evidence/files/{safe_item_key}/{evidence_id}-{safe_file_name}"
                blob = _read_evidence_blob(row=evidence)
                blob_included = False
                include_reason = "missing_blob"
                blob_size = len(blob) if blob is not None else 0
                if blob is None:
                    evidence_missing_blob_count += 1
                elif evidence_file_count >= W07_COMPLETION_PACKAGE_MAX_EVIDENCE_FILES:
                    include_reason = "skipped_max_files"
                    evidence_truncated = True
                elif (evidence_bytes_included + blob_size) > W07_COMPLETION_PACKAGE_MAX_EVIDENCE_BYTES:
                    include_reason = "skipped_max_bytes"
                    evidence_truncated = True
                else:
                    zf.writestr(archive_path, blob)
                    evidence_file_count += 1
                    evidence_bytes_included += blob_size
                    blob_included = True
                    include_reason = "included"

                evidence_index_rows.append(
                    {
                        "evidence_id": evidence_id,
                        "tracker_item_id": tracker_item_id,
                        "item_key": model.item_key if model is not None else "",
                        "item_type": model.item_type if model is not None else "",
                        "file_name": str(evidence.get("file_name") or ""),
                        "content_type": str(evidence.get("content_type") or ""),
                        "file_size": int(evidence.get("file_size") or 0),
                        "sha256": str(evidence.get("sha256") or ""),
                        "uploaded_by": str(evidence.get("uploaded_by") or ""),
                        "uploaded_at": (
                            _as_optional_datetime(evidence.get("uploaded_at")).isoformat()
                            if _as_optional_datetime(evidence.get("uploaded_at")) is not None
                            else ""
                        ),
                        "archive_path": archive_path,
                        "blob_included": blob_included,
                        "include_reason": include_reason,
                    }
                )
            zf.writestr("evidence/index.csv", _build_w07_evidence_index_csv(evidence_index_rows))
            zf.writestr(
                "evidence/index.json",
                json.dumps(evidence_index_rows, ensure_ascii=False, indent=2, default=str),
            )

        manifest = {
            "title": "W07 Completion Package",
            "generated_at": generated_at.isoformat(),
            "generated_by": actor,
            "site": site,
            "completion_status": completion.status,
            "readiness_ready": bool(completion.readiness.ready),
            "completion_rate_percent": int(completion.readiness.completion_rate_percent),
            "summary": {
                "tracker_items": len(rows),
                "blockers": len(blockers),
                "include_evidence": bool(include_evidence),
                "include_weekly": bool(include_weekly),
                "evidence_rows": len(evidence_index_rows),
                "evidence_files_included": evidence_file_count,
                "evidence_bytes_included": evidence_bytes_included,
                "evidence_missing_blob": evidence_missing_blob_count,
                "evidence_truncated": evidence_truncated,
                "evidence_limit_files": W07_COMPLETION_PACKAGE_MAX_EVIDENCE_FILES,
                "evidence_limit_bytes": W07_COMPLETION_PACKAGE_MAX_EVIDENCE_BYTES,
                "weekly_points": int((weekly_payload or {}).get("point_count") or 0),
            },
            "files": {
                "tracker_csv": "tracker/items.csv",
                "completion_json": "completion/completion.json",
                "readiness_json": "completion/readiness.json",
                "blockers_txt": "completion/blockers.txt",
                "evidence_index_csv": "evidence/index.csv" if include_evidence else None,
                "weekly_trends_csv": "weekly/trends.csv" if include_weekly else None,
            },
        }
        zf.writestr(
            "manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2, default=str),
        )

    package_bytes = package_buffer.getvalue()
    package_sha256 = hashlib.sha256(package_bytes).hexdigest()
    manifest_with_hash = {
        **manifest,
        "sha256": package_sha256,
        "bytes": len(package_bytes),
    }
    return package_bytes, manifest_with_hash


def _build_w07_automation_readiness_snapshot(
    *,
    site: str | None,
    allowed_sites: list[str] | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    generated_at = now or datetime.now(timezone.utc)
    runs = _read_w07_weekly_job_runs(site=site, allowed_sites=allowed_sites, limit=1)
    latest_run_model: JobRunRead | None = None
    latest_run_detail: dict[str, Any] = {}
    if runs:
        latest_run_model, latest_run_detail = runs[0]

    latest_run_at = latest_run_model.finished_at if latest_run_model is not None else None
    latest_run_recent = (
        latest_run_at is not None
        and latest_run_at >= (generated_at - timedelta(days=8))
    )
    latest_degraded = bool((latest_run_detail.get("degradation") or {}).get("degraded", False))
    alert_targets = _configured_alert_targets()
    webhook_configured = len(alert_targets) > 0
    alert_enabled = W07_QUALITY_ALERT_ENABLED
    weekly_window_days = int(latest_run_detail.get("window_days") or max(7, W07_QUALITY_ALERT_MIN_WINDOW_DAYS))

    checks: list[dict[str, Any]] = [
        {
            "id": "w07_weekly_cron_recent",
            "status": "ok" if latest_run_recent else "warning",
            "message": (
                "W07 weekly job observed within 8 days."
                if latest_run_recent
                else "No W07 weekly job run observed within 8 days."
            ),
        },
        {
            "id": "w07_alert_channel_config",
            "status": (
                "ok"
                if webhook_configured or not alert_enabled
                else "warning"
            ),
            "message": (
                "Alert channel targets configured."
                if webhook_configured
                else (
                    "W07 quality alert is enabled but no ALERT_WEBHOOK_URL/ALERT_WEBHOOK_URLS configured."
                    if alert_enabled
                    else "W07 quality alert is disabled."
                )
            ),
            "webhook_target_count": len(alert_targets),
            "alert_enabled": alert_enabled,
        },
        {
            "id": "w07_latest_quality_state",
            "status": "warning" if latest_degraded else "ok",
            "message": (
                "Latest W07 weekly run indicates degradation."
                if latest_degraded
                else "Latest W07 weekly run is within threshold."
            ),
            "degraded": latest_degraded,
        },
        {
            "id": "w07_archive_write_mode",
            "status": "ok" if W07_WEEKLY_ARCHIVE_ENABLED else "warning",
            "message": (
                "Weekly archive file writing is enabled."
                if W07_WEEKLY_ARCHIVE_ENABLED
                else "Weekly archive file writing is disabled."
            ),
            "archive_enabled": W07_WEEKLY_ARCHIVE_ENABLED,
            "archive_path": W07_WEEKLY_ARCHIVE_PATH,
        },
    ]

    overall = "ok"
    if any(item.get("status") == "critical" for item in checks):
        overall = "critical"
    elif any(item.get("status") == "warning" for item in checks):
        overall = "warning"

    return {
        "generated_at": generated_at.isoformat(),
        "site": site,
        "overall_status": overall,
        "checks": checks,
        "runtime": {
            "latest_run_id": latest_run_model.id if latest_run_model is not None else None,
            "latest_run_status": latest_run_model.status if latest_run_model is not None else None,
            "latest_run_at": latest_run_at.isoformat() if latest_run_at is not None else None,
            "latest_run_recent": latest_run_recent,
            "latest_run_degraded": latest_degraded,
            "latest_run_window_days": weekly_window_days,
        },
        "policy": {
            "alert_enabled": alert_enabled,
            "cooldown_minutes": max(0, W07_QUALITY_ALERT_COOLDOWN_MINUTES),
            "min_window_days": max(7, W07_QUALITY_ALERT_MIN_WINDOW_DAYS),
            "escalation_rate_threshold_percent": round(max(0.0, W07_QUALITY_ALERT_ESCALATION_RATE_THRESHOLD), 2),
            "alert_success_rate_threshold_percent": round(max(0.0, min(100.0, W07_QUALITY_ALERT_SUCCESS_RATE_THRESHOLD)), 2),
            "archive_enabled": W07_WEEKLY_ARCHIVE_ENABLED,
            "archive_path": W07_WEEKLY_ARCHIVE_PATH,
        },
        "integration": {
            "webhook_target_count": len(alert_targets),
            "webhook_configured": webhook_configured,
            "webhook_targets": alert_targets,
            "recommended_cron_schedule_utc": "30 23 * * 5",
            "cron_job_name": W07_WEEKLY_JOB_NAME,
            "cron_command": "python -m app.jobs.adoption_w07_weekly --days 14",
        },
    }


def run_sla_escalation_job(
    *,
    site: str | None = None,
    dry_run: bool = False,
    limit: int = 200,
    allowed_sites: list[str] | None = None,
    trigger: str = "manual",
) -> SlaEscalationRunResponse:
    started_at = datetime.now(timezone.utc)
    now = started_at
    stmt = (
        select(work_orders)
        .where(work_orders.c.due_at.is_not(None))
        .where(work_orders.c.due_at < now)
        .where(work_orders.c.status.in_(["open", "acked"]))
        .where(work_orders.c.is_escalated.is_(False))
        .order_by(work_orders.c.due_at.asc())
        .limit(limit * 5)
    )
    if site is not None:
        stmt = stmt.where(work_orders.c.site == site)
    elif allowed_sites is not None:
        if not allowed_sites:
            finished_at = datetime.now(timezone.utc)
            _write_job_run(
                job_name="sla_escalation",
                trigger=trigger,
                status="success",
                started_at=started_at,
                finished_at=finished_at,
                detail={
                    "site": site,
                    "dry_run": dry_run,
                    "limit": limit,
                    "allowed_sites": allowed_sites,
                    "candidate_count": 0,
                    "escalated_count": 0,
                    "grace_minutes_by_site": {},
                    "alert_dispatched": False,
                    "alert_error": None,
                    "alert_channels": [],
                },
            )
            return SlaEscalationRunResponse(
                checked_at=finished_at,
                dry_run=dry_run,
                site=site,
                candidate_count=0,
                escalated_count=0,
                work_order_ids=[],
                alert_dispatched=False,
                alert_error=None,
                alert_channels=[],
            )
        stmt = stmt.where(work_orders.c.site.in_(allowed_sites))

    grace_minutes_by_site: dict[str, int] = {}

    def _resolve_grace(site_name: str) -> int:
        key = site_name.strip()
        if key in grace_minutes_by_site:
            return grace_minutes_by_site[key]
        policy, _, _, _, _ = _load_sla_policy(site=key if key else None)
        grace_value = int(policy["escalation_grace_minutes"])
        grace_minutes_by_site[key] = grace_value
        return grace_value

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()
        ids: list[int] = []
        for row in rows:
            due_at = _as_optional_datetime(row["due_at"])
            if due_at is None:
                continue
            row_site = str(row["site"] or "")
            row_grace = _resolve_grace(row_site)
            due_cutoff = now - timedelta(minutes=row_grace)
            if due_at < due_cutoff:
                ids.append(int(row["id"]))
            if len(ids) >= limit:
                break

        escalated_count = 0
        escalated_ids: list[int] = []
        if ids and not dry_run:
            for work_order_id in ids:
                update_result = conn.execute(
                    update(work_orders)
                    .where(work_orders.c.id == work_order_id)
                    .where(work_orders.c.status.in_(["open", "acked"]))
                    .where(work_orders.c.is_escalated.is_(False))
                    .values(is_escalated=True, updated_at=now)
                )
                if update_result.rowcount and update_result.rowcount > 0:
                    escalated_ids.append(work_order_id)
            escalated_count = len(escalated_ids)

    work_order_ids = ids if dry_run else escalated_ids

    alert_dispatched = False
    alert_error: str | None = None
    alert_channels: list[SlaAlertChannelResult] = []
    if not dry_run and escalated_count > 0:
        alert_dispatched, alert_error, alert_channels = _dispatch_sla_alert(
            site=site,
            checked_at=now,
            escalated_count=escalated_count,
            work_order_ids=work_order_ids,
        )
        _write_audit_log(
            principal=None,
            action="sla_escalation_batch",
            resource_type="work_order",
            resource_id="batch",
            status="success" if alert_error is None else "warning",
            detail={
                "site": site,
                "dry_run": dry_run,
                "allowed_sites": allowed_sites,
                "candidate_count": len(ids),
                "escalated_count": escalated_count,
                "grace_minutes_by_site": grace_minutes_by_site,
                "alert_dispatched": alert_dispatched,
                "alert_error": alert_error,
                "alert_channels": [channel.model_dump() for channel in alert_channels],
                "work_order_ids": work_order_ids,
            },
        )

    finished_at = datetime.now(timezone.utc)
    _write_job_run(
        job_name="sla_escalation",
        trigger=trigger,
        status="success" if alert_error is None else "warning",
        started_at=started_at,
        finished_at=finished_at,
        detail={
            "site": site,
            "dry_run": dry_run,
            "limit": limit,
            "allowed_sites": allowed_sites,
            "candidate_count": len(ids),
            "escalated_count": escalated_count,
            "grace_minutes_by_site": grace_minutes_by_site,
            "alert_dispatched": alert_dispatched,
            "alert_error": alert_error,
            "alert_channels": [channel.model_dump() for channel in alert_channels],
        },
    )

    return SlaEscalationRunResponse(
        checked_at=finished_at,
        dry_run=dry_run,
        site=site,
        candidate_count=len(ids),
        escalated_count=escalated_count,
        work_order_ids=work_order_ids,
        alert_dispatched=alert_dispatched,
        alert_error=alert_error,
        alert_channels=alert_channels,
    )


def run_alert_retry_job(
    *,
    event_type: str | None = None,
    only_status: list[str] | None = None,
    limit: int = 200,
    max_attempt_count: int = 10,
    min_last_attempt_age_sec: int = 30,
    trigger: str = "manual",
) -> AlertRetryRunResponse:
    started_at = datetime.now(timezone.utc)
    now = started_at
    statuses = [s.strip().lower() for s in (only_status or ["failed", "warning"]) if s.strip()]
    if not statuses:
        statuses = ["failed", "warning"]
    statuses = sorted(set(statuses))
    normalized_limit = max(1, min(limit, 5000))
    normalized_max_attempt_count = max(1, min(max_attempt_count, 1000))
    cooldown_cutoff = now - timedelta(seconds=max(0, min(min_last_attempt_age_sec, 86400)))

    stmt = (
        select(alert_deliveries)
        .where(alert_deliveries.c.status.in_(statuses))
        .where(alert_deliveries.c.attempt_count < normalized_max_attempt_count)
        .where(alert_deliveries.c.last_attempt_at <= cooldown_cutoff)
        .order_by(alert_deliveries.c.last_attempt_at.asc(), alert_deliveries.c.id.asc())
        .limit(normalized_limit)
    )
    if event_type is not None:
        stmt = stmt.where(alert_deliveries.c.event_type == event_type)

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()

    processed_count = 0
    success_count = 0
    warning_count = 0
    failed_count = 0
    delivery_ids: list[int] = []

    with get_conn() as conn:
        for row in rows:
            delivery_id = int(row["id"])
            current_status = str(row["status"] or "failed")
            current_attempt_count = int(row["attempt_count"])
            claim_result = conn.execute(
                update(alert_deliveries)
                .where(alert_deliveries.c.id == delivery_id)
                .where(alert_deliveries.c.status == current_status)
                .where(alert_deliveries.c.attempt_count == current_attempt_count)
                .values(
                    attempt_count=current_attempt_count + 1,
                    last_attempt_at=now,
                    updated_at=now,
                )
            )
            if not claim_result.rowcount or claim_result.rowcount <= 0:
                continue

            payload_raw = str(row["payload_json"] or "{}")
            try:
                payload = json.loads(payload_raw)
            except json.JSONDecodeError:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}

            ok, err = _post_json_with_retries(
                url=str(row["target"]),
                payload=payload,
                retries=1,
                timeout_sec=ALERT_WEBHOOK_TIMEOUT_SEC,
            )
            next_status = "success" if ok and err is None else ("warning" if ok else "failed")
            conn.execute(
                update(alert_deliveries)
                .where(alert_deliveries.c.id == delivery_id)
                .where(alert_deliveries.c.attempt_count == (current_attempt_count + 1))
                .values(
                    status=next_status,
                    error=err,
                    updated_at=now,
                )
            )

            processed_count += 1
            delivery_ids.append(delivery_id)
            if next_status == "success":
                success_count += 1
            elif next_status == "warning":
                warning_count += 1
            else:
                failed_count += 1

    finished_at = datetime.now(timezone.utc)
    _write_job_run(
        job_name="alert_retry",
        trigger=trigger,
        status="warning" if failed_count > 0 else "success",
        started_at=started_at,
        finished_at=finished_at,
        detail={
            "event_type": event_type,
            "statuses": statuses,
            "limit": normalized_limit,
            "max_attempt_count": normalized_max_attempt_count,
            "min_last_attempt_age_sec": min_last_attempt_age_sec,
            "processed_count": processed_count,
            "success_count": success_count,
            "warning_count": warning_count,
            "failed_count": failed_count,
            "delivery_ids": delivery_ids,
        },
    )
    return AlertRetryRunResponse(
        checked_at=finished_at,
        event_type=event_type,
        limit=normalized_limit,
        processed_count=processed_count,
        success_count=success_count,
        warning_count=warning_count,
        failed_count=failed_count,
        delivery_ids=delivery_ids,
    )


def _normalized_ops_daily_check_rows(checks: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in checks:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "id": str(item.get("id") or ""),
                "status": str(item.get("status") or "unknown"),
                "message": str(item.get("message") or ""),
            }
        )
    return rows


def _build_ops_daily_check_summary(
    *,
    run_id: int | None,
    checked_at: datetime,
    trigger: str,
    status: str,
    overall_status: str,
    check_count: int,
    warning_count: int,
    critical_count: int,
    checks: list[dict[str, Any]],
    alert_level: str,
    alert_attempted: bool,
    alert_dispatched: bool,
    alert_error: str | None,
    mttr_slo_check: dict[str, Any],
) -> dict[str, Any]:
    return {
        "version": "v1",
        "job_name": "ops_daily_check",
        "run_id": run_id,
        "checked_at": checked_at.isoformat(),
        "trigger": trigger,
        "status": status,
        "overall_status": overall_status,
        "check_count": check_count,
        "warning_count": warning_count,
        "critical_count": critical_count,
        "alert": {
            "level": alert_level,
            "attempted": alert_attempted,
            "dispatched": alert_dispatched,
            "error": alert_error,
        },
        "mttr_slo_check": mttr_slo_check,
        "checks": _normalized_ops_daily_check_rows(checks),
    }


def _build_ops_daily_check_summary_csv(summary: dict[str, Any]) -> str:
    checks = summary.get("checks")
    if not isinstance(checks, list):
        checks = []

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "run_id",
            "checked_at",
            "trigger",
            "status",
            "overall_status",
            "check_count",
            "warning_count",
            "critical_count",
            "alert_level",
            "alert_attempted",
            "alert_dispatched",
            "alert_error",
        ]
    )
    alert = summary.get("alert", {}) if isinstance(summary.get("alert"), dict) else {}
    writer.writerow(
        [
            summary.get("run_id"),
            summary.get("checked_at"),
            summary.get("trigger"),
            summary.get("status"),
            summary.get("overall_status"),
            summary.get("check_count"),
            summary.get("warning_count"),
            summary.get("critical_count"),
            alert.get("level"),
            bool(alert.get("attempted", False)),
            bool(alert.get("dispatched", False)),
            alert.get("error"),
        ]
    )
    writer.writerow([])
    writer.writerow(["check_id", "check_status", "check_message"])
    for item in checks:
        if not isinstance(item, dict):
            continue
        writer.writerow(
            [
                item.get("id"),
                item.get("status"),
                item.get("message"),
            ]
        )
    return buffer.getvalue()


def _prune_ops_daily_check_archive_files(*, archive_dir: Path, now: datetime) -> int:
    cutoff = now - timedelta(days=max(1, OPS_DAILY_CHECK_ARCHIVE_RETENTION_DAYS))
    deleted_count = 0
    for pattern in ("ops-daily-check-*.json", "ops-daily-check-*.csv"):
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


def _publish_ops_daily_check_summary_artifacts(
    *,
    summary: dict[str, Any],
    finished_at: datetime,
) -> dict[str, Any]:
    archive = {
        "enabled": OPS_DAILY_CHECK_ARCHIVE_ENABLED,
        "path": OPS_DAILY_CHECK_ARCHIVE_PATH,
        "retention_days": max(1, OPS_DAILY_CHECK_ARCHIVE_RETENTION_DAYS),
        "json_file": None,
        "csv_file": None,
        "pruned_files": 0,
        "error": None,
    }
    if not OPS_DAILY_CHECK_ARCHIVE_ENABLED:
        return archive
    try:
        archive_dir = Path(OPS_DAILY_CHECK_ARCHIVE_PATH)
        archive_dir.mkdir(parents=True, exist_ok=True)
        stamp = finished_at.strftime("%Y%m%dT%H%M%SZ")
        run_id = summary.get("run_id")
        run_label = f"run-{run_id}" if run_id is not None else "run-na"
        base_name = f"ops-daily-check-{stamp}-{run_label}"
        json_file = archive_dir / f"{base_name}.json"
        csv_file = archive_dir / f"{base_name}.csv"
        json_payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
        }
        json_file.write_text(
            json.dumps(json_payload, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        csv_file.write_text(_build_ops_daily_check_summary_csv(summary), encoding="utf-8")
        archive["json_file"] = str(json_file)
        archive["csv_file"] = str(csv_file)
        archive["pruned_files"] = _prune_ops_daily_check_archive_files(archive_dir=archive_dir, now=finished_at)
    except Exception as exc:  # pragma: no cover - defensive filesystem path
        archive["error"] = str(exc)
    return archive


def _build_ops_daily_check_summary_from_job_run(model: JobRunRead, detail: dict[str, Any]) -> dict[str, Any]:
    checks = detail.get("checks")
    if not isinstance(checks, list):
        checks = []
    return _build_ops_daily_check_summary(
        run_id=model.id,
        checked_at=model.finished_at,
        trigger=model.trigger,
        status=model.status,
        overall_status=str(detail.get("overall_status") or model.status),
        check_count=int(detail.get("check_count") or len(checks)),
        warning_count=int(detail.get("warning_count") or 0),
        critical_count=int(detail.get("critical_count") or 0),
        checks=[item for item in checks if isinstance(item, dict)],
        alert_level=str(detail.get("alert_level") or "critical"),
        alert_attempted=bool(detail.get("alert_attempted", False)),
        alert_dispatched=bool(detail.get("alert_dispatched", False)),
        alert_error=(str(detail.get("alert_error")) if detail.get("alert_error") is not None else None),
        mttr_slo_check=detail.get("mttr_slo_check", {}) if isinstance(detail.get("mttr_slo_check"), dict) else {},
    )


def _build_ops_daily_check_archive_rows(*, limit: int) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == "ops_daily_check")
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(max(1, min(limit, 365)))
        ).mappings().all()

    payload_rows: list[dict[str, Any]] = []
    for row in rows:
        model = _row_to_job_run_model(row)
        detail = model.detail if isinstance(model.detail, dict) else {}
        summary = detail.get("summary") if isinstance(detail.get("summary"), dict) else None
        if summary is None:
            summary = _build_ops_daily_check_summary_from_job_run(model, detail)
        archive = detail.get("archive") if isinstance(detail.get("archive"), dict) else {}
        payload_rows.append(
            {
                "run_id": model.id,
                "finished_at": model.finished_at.isoformat(),
                "trigger": model.trigger,
                "status": model.status,
                "overall_status": summary.get("overall_status"),
                "check_count": summary.get("check_count"),
                "warning_count": summary.get("warning_count"),
                "critical_count": summary.get("critical_count"),
                "alert_level": (summary.get("alert") or {}).get("level") if isinstance(summary.get("alert"), dict) else None,
                "alert_attempted": bool((summary.get("alert") or {}).get("attempted", False))
                if isinstance(summary.get("alert"), dict)
                else False,
                "alert_dispatched": bool((summary.get("alert") or {}).get("dispatched", False))
                if isinstance(summary.get("alert"), dict)
                else False,
                "archive_json_file": archive.get("json_file"),
                "archive_csv_file": archive.get("csv_file"),
                "archive_error": archive.get("error"),
            }
        )
    return payload_rows


def _build_ops_daily_check_archive_csv(rows: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "run_id",
            "finished_at",
            "trigger",
            "status",
            "overall_status",
            "check_count",
            "warning_count",
            "critical_count",
            "alert_level",
            "alert_attempted",
            "alert_dispatched",
            "archive_json_file",
            "archive_csv_file",
            "archive_error",
        ]
    )
    for row in rows:
        writer.writerow(
            [
                row.get("run_id"),
                row.get("finished_at"),
                row.get("trigger"),
                row.get("status"),
                row.get("overall_status"),
                row.get("check_count"),
                row.get("warning_count"),
                row.get("critical_count"),
                row.get("alert_level"),
                bool(row.get("alert_attempted", False)),
                bool(row.get("alert_dispatched", False)),
                row.get("archive_json_file"),
                row.get("archive_csv_file"),
                row.get("archive_error"),
            ]
        )
    return buffer.getvalue()


def run_ops_daily_check_job(
    *,
    trigger: str = "manual",
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    mttr_slo_result = run_alert_mttr_slo_check_job(
        trigger=f"{trigger}:ops_daily_check",
    )
    checks_snapshot = _build_ops_runbook_checks_snapshot(now=started_at)
    posture_snapshot = _build_ops_security_posture_snapshot(now=started_at)
    mttr_slo_summary = {
        "run_id": mttr_slo_result.get("run_id"),
        "status": mttr_slo_result.get("status"),
        "breach": bool(mttr_slo_result.get("breach", False)),
        "window": mttr_slo_result.get("window", {}),
        "actions": {
            "auto_recover_attempted": bool(
                (mttr_slo_result.get("actions") or {}).get("auto_recover_attempted", False)
            ),
            "notify_attempted": bool((mttr_slo_result.get("actions") or {}).get("notify_attempted", False)),
            "notify_dispatched": bool((mttr_slo_result.get("actions") or {}).get("notify_dispatched", False)),
            "notify_error": (mttr_slo_result.get("actions") or {}).get("notify_error"),
            "cooldown_active": bool((mttr_slo_result.get("actions") or {}).get("cooldown_active", False)),
        },
    }

    checks = checks_snapshot.get("checks", [])
    warning_count = sum(1 for item in checks if str(item.get("status")) == "warning")
    critical_count = sum(1 for item in checks if str(item.get("status")) == "critical")
    overall_status = str(checks_snapshot.get("overall_status") or "ok")

    alert_level = _normalize_ops_daily_check_alert_level(OPS_DAILY_CHECK_ALERT_LEVEL)
    alert_attempted = False
    alert_dispatched = False
    alert_error: str | None = None
    alert_channels: list[SlaAlertChannelResult] = []
    should_alert = (
        alert_level == "always"
        or (alert_level == "warning" and overall_status in {"warning", "critical"})
        or (alert_level == "critical" and overall_status == "critical")
    )
    if should_alert:
        payload = {
            "event": "ops_daily_check",
            "checked_at": started_at.isoformat(),
            "overall_status": overall_status,
            "check_count": len(checks),
            "warning_count": warning_count,
            "critical_count": critical_count,
            "checks": checks,
            "security_posture": {
                "rate_limit": posture_snapshot.get("rate_limit"),
                "audit_archive_signing": posture_snapshot.get("audit_archive_signing"),
                "evidence_storage_backend": posture_snapshot.get("evidence_storage_backend"),
                "token_policy": posture_snapshot.get("token_policy"),
            },
        }
        alert_attempted = True
        alert_dispatched, alert_error, alert_channels = _dispatch_alert_event(
            event_type="ops_daily_check",
            payload=payload,
        )

    if overall_status == "critical":
        status = "critical"
    elif overall_status == "warning":
        status = "warning"
    else:
        status = "success"
    if alert_attempted and alert_error is not None and status == "success":
        status = "warning"

    finished_at = datetime.now(timezone.utc)
    detail: dict[str, Any] = {
        "overall_status": overall_status,
        "check_count": len(checks),
        "warning_count": warning_count,
        "critical_count": critical_count,
        "checks": checks,
        "alert_level": alert_level,
        "alert_attempted": alert_attempted,
        "alert_dispatched": alert_dispatched,
        "alert_error": alert_error,
        "alert_channels": [channel.model_dump() for channel in alert_channels],
        "security_posture": {
            "rate_limit": posture_snapshot.get("rate_limit"),
            "audit_archive_signing": posture_snapshot.get("audit_archive_signing"),
            "evidence_storage_backend": posture_snapshot.get("evidence_storage_backend"),
            "token_policy": posture_snapshot.get("token_policy"),
        },
        "mttr_slo_check": mttr_slo_summary,
    }
    run_id = _write_job_run(
        job_name="ops_daily_check",
        trigger=trigger,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        detail=detail,
    )

    summary = _build_ops_daily_check_summary(
        run_id=run_id,
        checked_at=finished_at,
        trigger=trigger,
        status=status,
        overall_status=overall_status,
        check_count=len(checks),
        warning_count=warning_count,
        critical_count=critical_count,
        checks=checks,
        alert_level=alert_level,
        alert_attempted=alert_attempted,
        alert_dispatched=alert_dispatched,
        alert_error=alert_error,
        mttr_slo_check=mttr_slo_summary,
    )
    archive = _publish_ops_daily_check_summary_artifacts(
        summary=summary,
        finished_at=finished_at,
    )
    detail["summary"] = summary
    detail["archive"] = archive
    if run_id is not None:
        try:
            with get_conn() as conn:
                conn.execute(
                    update(job_runs)
                    .where(job_runs.c.id == run_id)
                    .values(detail_json=_to_json_text(detail))
                )
        except SQLAlchemyError:
            pass

    return {
        "run_id": run_id,
        "checked_at": finished_at.isoformat(),
        "trigger": trigger,
        "status": status,
        "overall_status": overall_status,
        "check_count": len(checks),
        "warning_count": warning_count,
        "critical_count": critical_count,
        "checks": checks,
        "alert_level": alert_level,
        "alert_attempted": alert_attempted,
        "alert_dispatched": alert_dispatched,
        "alert_error": alert_error,
        "alert_channels": [channel.model_dump() for channel in alert_channels],
        "security_posture": {
            "rate_limit": posture_snapshot.get("rate_limit"),
            "audit_archive_signing": posture_snapshot.get("audit_archive_signing"),
            "evidence_storage_backend": posture_snapshot.get("evidence_storage_backend"),
            "token_policy": posture_snapshot.get("token_policy"),
        },
        "mttr_slo_check": mttr_slo_summary,
        "summary": summary,
        "archive": archive,
    }


def simulate_sla_policy_change(
    *,
    policy: SlaPolicyUpdate,
    site: str | None = None,
    limit: int = 3000,
    include_work_order_ids: bool = True,
    sample_size: int = 200,
    recompute_due_from_policy: bool = False,
    allowed_sites: list[str] | None = None,
) -> SlaWhatIfResponse:
    now = datetime.now(timezone.utc)
    normalized_site = _normalize_site_name(site)
    normalized_limit = max(1, min(limit, 20000))
    normalized_sample_size = max(0, min(sample_size, 1000))
    simulated_policy = _normalize_sla_policy(policy.model_dump())

    stmt = (
        select(work_orders)
        .where(work_orders.c.status.in_(["open", "acked"]))
        .where(work_orders.c.is_escalated.is_(False))
        .order_by(work_orders.c.due_at.asc(), work_orders.c.id.asc())
        .limit(normalized_limit)
    )
    if normalized_site is not None:
        stmt = stmt.where(work_orders.c.site == normalized_site)
    elif allowed_sites is not None:
        if not allowed_sites:
            return SlaWhatIfResponse(
                checked_at=now,
                site=normalized_site,
                limit=normalized_limit,
                total_candidates=0,
                baseline_escalate_count=0,
                simulated_escalate_count=0,
                delta_escalate_count=0,
                baseline_by_site={},
                simulated_by_site={},
                newly_escalated_ids=[],
                no_longer_escalated_ids=[],
                notes=["No accessible sites in current principal scope."],
            )
        stmt = stmt.where(work_orders.c.site.in_(allowed_sites))

    with get_conn() as conn:
        rows = conn.execute(stmt).mappings().all()

    current_policy_cache: dict[str, dict[str, Any]] = {}

    def _current_policy_for_site(site_name: str) -> dict[str, Any]:
        key = site_name.strip()
        if key in current_policy_cache:
            return current_policy_cache[key]
        loaded, _, _, _, _ = _load_sla_policy(site=key if key else None)
        current_policy_cache[key] = loaded
        return loaded

    baseline_count = 0
    simulated_count = 0
    baseline_by_site: dict[str, int] = {}
    simulated_by_site: dict[str, int] = {}
    newly_escalated_ids: list[int] = []
    no_longer_escalated_ids: list[int] = []

    for row in rows:
        row_id = int(row["id"])
        row_site = str(row["site"] or "")
        row_priority = str(row["priority"] or "medium")

        due_at_baseline = _as_optional_datetime(row["due_at"])
        created_at = _as_optional_datetime(row["created_at"])
        if due_at_baseline is None and not recompute_due_from_policy:
            continue
        if created_at is None:
            continue

        current_policy = _current_policy_for_site(row_site)
        current_grace = int(current_policy["escalation_grace_minutes"])
        baseline_cutoff = now - timedelta(minutes=current_grace)

        simulated_applies = normalized_site is None or row_site == normalized_site
        simulated_grace = (
            int(simulated_policy["escalation_grace_minutes"])
            if simulated_applies
            else int(current_policy["escalation_grace_minutes"])
        )
        simulated_cutoff = now - timedelta(minutes=simulated_grace)

        due_at_for_baseline = due_at_baseline
        due_at_for_simulated = due_at_baseline
        if recompute_due_from_policy and simulated_applies:
            simulated_hours = int(
                simulated_policy["default_due_hours"].get(
                    row_priority, SLA_DEFAULT_DUE_HOURS.get(row_priority, SLA_DEFAULT_DUE_HOURS["medium"])
                )
            )
            due_at_for_simulated = created_at + timedelta(hours=simulated_hours)
        if due_at_for_baseline is None:
            baseline_hours = int(
                current_policy["default_due_hours"].get(
                    row_priority, SLA_DEFAULT_DUE_HOURS.get(row_priority, SLA_DEFAULT_DUE_HOURS["medium"])
                )
            )
            due_at_for_baseline = created_at + timedelta(hours=baseline_hours)
        if due_at_for_simulated is None:
            due_at_for_simulated = due_at_for_baseline

        baseline_escalates = due_at_for_baseline < baseline_cutoff
        simulated_escalates = due_at_for_simulated < simulated_cutoff

        if baseline_escalates:
            baseline_count += 1
            baseline_by_site[row_site] = baseline_by_site.get(row_site, 0) + 1
        if simulated_escalates:
            simulated_count += 1
            simulated_by_site[row_site] = simulated_by_site.get(row_site, 0) + 1

        if include_work_order_ids and normalized_sample_size > 0:
            if simulated_escalates and not baseline_escalates and len(newly_escalated_ids) < normalized_sample_size:
                newly_escalated_ids.append(row_id)
            if baseline_escalates and not simulated_escalates and len(no_longer_escalated_ids) < normalized_sample_size:
                no_longer_escalated_ids.append(row_id)

    notes = [
        "Simulation is read-only and does not mutate work-order state.",
        "Due-hours policy mainly affects future created work orders unless recompute_due_from_policy=true.",
    ]
    return SlaWhatIfResponse(
        checked_at=now,
        site=normalized_site,
        limit=normalized_limit,
        total_candidates=len(rows),
        baseline_escalate_count=baseline_count,
        simulated_escalate_count=simulated_count,
        delta_escalate_count=simulated_count - baseline_count,
        baseline_by_site=baseline_by_site,
        simulated_by_site=simulated_by_site,
        newly_escalated_ids=newly_escalated_ids,
        no_longer_escalated_ids=no_longer_escalated_ids,
        notes=notes,
    )


def build_monthly_report(
    month: str | None,
    site: str | None,
    allowed_sites: list[str] | None = None,
) -> MonthlyReportRead:
    start, end, month_label = _month_window(month)
    now = datetime.now(timezone.utc)

    inspections_stmt = (
        select(inspections)
        .where(inspections.c.inspected_at >= start)
        .where(inspections.c.inspected_at < end)
    )
    work_orders_stmt = (
        select(work_orders)
        .where(work_orders.c.created_at >= start)
        .where(work_orders.c.created_at < end)
    )
    if site is not None:
        inspections_stmt = inspections_stmt.where(inspections.c.site == site)
        work_orders_stmt = work_orders_stmt.where(work_orders.c.site == site)
    elif allowed_sites is not None:
        if not allowed_sites:
            return MonthlyReportRead(
                month=month_label,
                site=site,
                generated_at=now,
                inspections={"total": 0, "risk_counts": {"normal": 0, "warning": 0, "danger": 0}, "top_risk_flags": {}},
                work_orders={
                    "total": 0,
                    "status_counts": {"open": 0, "acked": 0, "completed": 0, "canceled": 0},
                    "escalated_count": 0,
                    "overdue_open_count": 0,
                    "completion_rate_percent": 0.0,
                    "avg_resolution_hours": None,
                },
            )
        inspections_stmt = inspections_stmt.where(inspections.c.site.in_(allowed_sites))
        work_orders_stmt = work_orders_stmt.where(work_orders.c.site.in_(allowed_sites))

    with get_conn() as conn:
        inspection_rows = conn.execute(inspections_stmt).mappings().all()
        work_order_rows = conn.execute(work_orders_stmt).mappings().all()

    risk_counts = {"normal": 0, "warning": 0, "danger": 0}
    flag_counts: dict[str, int] = {}
    for row in inspection_rows:
        risk_level = row["risk_level"] or "normal"
        risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        flags = (row["risk_flags"] or "").split(",")
        for flag in flags:
            if not flag:
                continue
            flag_counts[flag] = flag_counts.get(flag, 0) + 1

    status_counts = {"open": 0, "acked": 0, "completed": 0, "canceled": 0}
    escalated_count = 0
    overdue_open_count = 0
    resolution_hours: list[float] = []
    for row in work_order_rows:
        status = row["status"] or "open"
        status_counts[status] = status_counts.get(status, 0) + 1
        if row["is_escalated"]:
            escalated_count += 1

        due_at = _as_optional_datetime(row["due_at"])
        if due_at is not None and status not in {"completed", "canceled"} and due_at < now:
            overdue_open_count += 1

        created_at = _as_optional_datetime(row["created_at"])
        completed_at = _as_optional_datetime(row["completed_at"])
        if created_at is not None and completed_at is not None:
            hours = (completed_at - created_at).total_seconds() / 3600
            if hours >= 0:
                resolution_hours.append(hours)

    total_work_orders = len(work_order_rows)
    completed_count = status_counts.get("completed", 0)
    completion_rate = round((completed_count / total_work_orders * 100), 2) if total_work_orders else 0.0
    avg_resolution_hours = round(sum(resolution_hours) / len(resolution_hours), 2) if resolution_hours else None

    return MonthlyReportRead(
        month=month_label,
        site=site,
        generated_at=now,
        inspections={
            "total": len(inspection_rows),
            "risk_counts": risk_counts,
            "top_risk_flags": dict(sorted(flag_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
        },
        work_orders={
            "total": total_work_orders,
            "status_counts": status_counts,
            "escalated_count": escalated_count,
            "overdue_open_count": overdue_open_count,
            "completion_rate_percent": completion_rate,
            "avg_resolution_hours": avg_resolution_hours,
        },
    )


def build_dashboard_summary(
    *,
    site: str | None,
    days: int,
    recent_job_limit: int,
    allowed_sites: list[str] | None = None,
) -> DashboardSummaryRead:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)

    inspections_stmt = select(inspections).where(inspections.c.inspected_at >= start)
    work_orders_window_stmt = select(work_orders).where(work_orders.c.created_at >= start)
    work_orders_open_stmt = select(work_orders).where(work_orders.c.status.in_(["open", "acked"]))
    job_runs_stmt = (
        select(job_runs)
        .where(job_runs.c.finished_at >= start)
        .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
        .limit(recent_job_limit)
    )
    report_exports_stmt = (
        select(admin_audit_logs.c.action)
        .where(admin_audit_logs.c.created_at >= start)
        .where(admin_audit_logs.c.action.in_(["report_monthly_export_csv", "report_monthly_export_pdf"]))
    )

    if site is not None:
        inspections_stmt = inspections_stmt.where(inspections.c.site == site)
        work_orders_window_stmt = work_orders_window_stmt.where(work_orders.c.site == site)
        work_orders_open_stmt = work_orders_open_stmt.where(work_orders.c.site == site)
    elif allowed_sites is not None:
        if not allowed_sites:
            return DashboardSummaryRead(
                generated_at=now,
                site=site,
                window_days=days,
                inspections_total=0,
                inspection_risk_counts={"normal": 0, "warning": 0, "danger": 0},
                work_orders_total=0,
                work_order_status_counts={"open": 0, "acked": 0, "completed": 0, "canceled": 0},
                overdue_open_count=0,
                escalated_open_count=0,
                report_export_count=0,
                sla_recent_runs=0,
                sla_warning_runs=0,
                sla_last_run_at=None,
                recent_job_runs=[],
            )
        inspections_stmt = inspections_stmt.where(inspections.c.site.in_(allowed_sites))
        work_orders_window_stmt = work_orders_window_stmt.where(work_orders.c.site.in_(allowed_sites))
        work_orders_open_stmt = work_orders_open_stmt.where(work_orders.c.site.in_(allowed_sites))

    with get_conn() as conn:
        inspection_rows = conn.execute(inspections_stmt).mappings().all()
        work_order_window_rows = conn.execute(work_orders_window_stmt).mappings().all()
        work_order_open_rows = conn.execute(work_orders_open_stmt).mappings().all()
        job_rows = conn.execute(job_runs_stmt).mappings().all()
        export_rows = conn.execute(report_exports_stmt).all()

    inspection_risk_counts = {"normal": 0, "warning": 0, "danger": 0}
    for row in inspection_rows:
        risk_level = str(row["risk_level"] or "normal")
        inspection_risk_counts[risk_level] = inspection_risk_counts.get(risk_level, 0) + 1

    work_order_status_counts = {"open": 0, "acked": 0, "completed": 0, "canceled": 0}
    for row in work_order_window_rows:
        status = str(row["status"] or "open")
        work_order_status_counts[status] = work_order_status_counts.get(status, 0) + 1

    overdue_open_count = 0
    escalated_open_count = 0
    for row in work_order_open_rows:
        if row["is_escalated"]:
            escalated_open_count += 1
        due_at = _as_optional_datetime(row["due_at"])
        if due_at is not None and due_at < now:
            overdue_open_count += 1

    recent_jobs = [_row_to_job_run_model(row) for row in job_rows]
    sla_recent_runs = [job for job in recent_jobs if job.job_name == "sla_escalation"]
    sla_last_run_at = sla_recent_runs[0].finished_at if sla_recent_runs else None
    sla_warning_runs = sum(1 for job in sla_recent_runs if job.status != "success")

    return DashboardSummaryRead(
        generated_at=now,
        site=site,
        window_days=days,
        inspections_total=len(inspection_rows),
        inspection_risk_counts=inspection_risk_counts,
        work_orders_total=len(work_order_window_rows),
        work_order_status_counts=work_order_status_counts,
        overdue_open_count=overdue_open_count,
        escalated_open_count=escalated_open_count,
        report_export_count=len(export_rows),
        sla_recent_runs=len(sla_recent_runs),
        sla_warning_runs=sla_warning_runs,
        sla_last_run_at=sla_last_run_at,
        recent_job_runs=recent_jobs,
    )


def build_dashboard_trends(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> DashboardTrendsRead:
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)

    inspections_stmt = select(inspections.c.inspected_at, inspections.c.site).where(inspections.c.inspected_at >= start)
    work_orders_stmt = select(
        work_orders.c.created_at,
        work_orders.c.completed_at,
        work_orders.c.site,
    ).where((work_orders.c.created_at >= start) | (work_orders.c.completed_at >= start))
    escalations_stmt = (
        select(job_runs.c.finished_at, job_runs.c.detail_json)
        .where(job_runs.c.job_name == "sla_escalation")
        .where(job_runs.c.finished_at >= start)
    )

    if site is not None:
        inspections_stmt = inspections_stmt.where(inspections.c.site == site)
        work_orders_stmt = work_orders_stmt.where(work_orders.c.site == site)
    elif allowed_sites is not None:
        if not allowed_sites:
            return DashboardTrendsRead(generated_at=now, site=site, window_days=days, points=[])
        inspections_stmt = inspections_stmt.where(inspections.c.site.in_(allowed_sites))
        work_orders_stmt = work_orders_stmt.where(work_orders.c.site.in_(allowed_sites))

    with get_conn() as conn:
        inspection_rows = conn.execute(inspections_stmt).mappings().all()
        work_order_rows = conn.execute(work_orders_stmt).mappings().all()
        escalation_rows = conn.execute(escalations_stmt).mappings().all()

    buckets: dict[str, dict[str, int]] = {}
    for i in range(days):
        bucket_day = (start + timedelta(days=i)).date().isoformat()
        buckets[bucket_day] = {
            "inspections_count": 0,
            "work_orders_created_count": 0,
            "work_orders_completed_count": 0,
            "work_orders_escalated_count": 0,
        }

    for row in inspection_rows:
        inspected_at = _as_optional_datetime(row["inspected_at"])
        if inspected_at is None:
            continue
        key = inspected_at.date().isoformat()
        if key in buckets:
            buckets[key]["inspections_count"] += 1

    for row in work_order_rows:
        created_at = _as_optional_datetime(row["created_at"])
        completed_at = _as_optional_datetime(row["completed_at"])
        if created_at is not None:
            key = created_at.date().isoformat()
            if key in buckets:
                buckets[key]["work_orders_created_count"] += 1
        if completed_at is not None:
            key = completed_at.date().isoformat()
            if key in buckets:
                buckets[key]["work_orders_completed_count"] += 1

    for row in escalation_rows:
        finished_at = _as_optional_datetime(row["finished_at"])
        if finished_at is None:
            continue
        key = finished_at.date().isoformat()
        if key not in buckets:
            continue

        detail = {}
        raw = str(row["detail_json"] or "{}")
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                detail = parsed
        except json.JSONDecodeError:
            detail = {}

        detail_site = detail.get("site")
        if site is not None and detail_site not in {site, None}:
            continue
        escalated_count = int(detail.get("escalated_count", 0) or 0)
        buckets[key]["work_orders_escalated_count"] += max(0, escalated_count)

    points = [
        DashboardTrendPoint(
            date=date_key,
            inspections_count=data["inspections_count"],
            work_orders_created_count=data["work_orders_created_count"],
            work_orders_completed_count=data["work_orders_completed_count"],
            work_orders_escalated_count=data["work_orders_escalated_count"],
        )
        for date_key, data in buckets.items()
    ]
    return DashboardTrendsRead(
        generated_at=now,
        site=site,
        window_days=days,
        points=points,
    )


def build_ops_handover_brief(
    *,
    site: str | None,
    window_hours: int,
    due_soon_hours: int,
    max_items: int,
    allowed_sites: list[str] | None = None,
) -> OpsHandoverBriefRead:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=window_hours)
    due_soon_cutoff = now + timedelta(hours=due_soon_hours)
    alert_window_start = now - timedelta(hours=24)

    if site is None and allowed_sites is not None and not allowed_sites:
        return OpsHandoverBriefRead(
            generated_at=now,
            site=site,
            window_hours=window_hours,
            due_soon_hours=due_soon_hours,
            open_work_orders=0,
            overdue_open_work_orders=0,
            due_soon_work_orders=0,
            escalated_open_work_orders=0,
            unassigned_high_priority_open_work_orders=0,
            new_work_orders_in_window=0,
            high_risk_inspections_in_window=0,
            failed_alert_deliveries_24h=0,
            top_work_orders=[],
            recent_high_risk_inspections=[],
            recommended_actions=["No accessible sites in current principal scope."],
        )

    open_work_orders_stmt = select(work_orders).where(work_orders.c.status.in_(["open", "acked"]))
    new_work_orders_stmt = (
        select(work_orders.c.id, work_orders.c.site)
        .where(work_orders.c.status.in_(["open", "acked"]))
        .where(work_orders.c.created_at >= window_start)
    )
    high_risk_inspections_stmt = (
        select(inspections)
        .where(inspections.c.inspected_at >= window_start)
        .where(inspections.c.risk_level.in_(["warning", "danger"]))
    )
    alert_deliveries_stmt = (
        select(alert_deliveries.c.status, alert_deliveries.c.payload_json)
        .where(alert_deliveries.c.last_attempt_at >= alert_window_start)
        .where(alert_deliveries.c.status.in_(["failed", "warning"]))
    )

    if site is not None:
        open_work_orders_stmt = open_work_orders_stmt.where(work_orders.c.site == site)
        new_work_orders_stmt = new_work_orders_stmt.where(work_orders.c.site == site)
        high_risk_inspections_stmt = high_risk_inspections_stmt.where(inspections.c.site == site)
    elif allowed_sites is not None:
        open_work_orders_stmt = open_work_orders_stmt.where(work_orders.c.site.in_(allowed_sites))
        new_work_orders_stmt = new_work_orders_stmt.where(work_orders.c.site.in_(allowed_sites))
        high_risk_inspections_stmt = high_risk_inspections_stmt.where(inspections.c.site.in_(allowed_sites))

    with get_conn() as conn:
        open_work_order_rows = conn.execute(open_work_orders_stmt).mappings().all()
        new_work_order_rows = conn.execute(new_work_orders_stmt).all()
        high_risk_inspection_rows = conn.execute(high_risk_inspections_stmt).mappings().all()
        alert_delivery_rows = conn.execute(alert_deliveries_stmt).mappings().all()

    priority_weights = {"low": 1, "medium": 2, "high": 4, "critical": 6}
    top_work_orders: list[OpsHandoverWorkOrderRead] = []
    overdue_open_work_orders = 0
    due_soon_work_orders = 0
    escalated_open_work_orders = 0
    unassigned_high_priority_open_work_orders = 0

    for row in open_work_order_rows:
        due_at = _as_optional_datetime(row["due_at"])
        created_at = _as_optional_datetime(row["created_at"]) or now
        priority = str(row["priority"] or "medium")
        is_escalated = bool(row["is_escalated"])
        is_overdue = due_at is not None and due_at < now
        is_due_soon = due_at is not None and now <= due_at <= due_soon_cutoff
        is_unassigned_high_priority = priority in {"high", "critical"} and not row["assignee"]

        if is_overdue:
            overdue_open_work_orders += 1
        if is_due_soon:
            due_soon_work_orders += 1
        if is_escalated:
            escalated_open_work_orders += 1
        if is_unassigned_high_priority:
            unassigned_high_priority_open_work_orders += 1

        urgency_score = priority_weights.get(priority, 2)
        reasons: list[str] = [f"{priority} priority"]
        if is_overdue:
            urgency_score += 6
            reasons.append("overdue")
        elif is_due_soon:
            urgency_score += 3
            reasons.append("due soon")
        if is_escalated:
            urgency_score += 4
            reasons.append("escalated")
        if is_unassigned_high_priority:
            urgency_score += 2
            reasons.append("unassigned high priority")

        age_hours = (now - created_at).total_seconds() / 3600
        if age_hours >= 72:
            urgency_score += 2
            reasons.append("open >72h")
        elif age_hours >= 24:
            urgency_score += 1
            reasons.append("open >24h")

        due_in_minutes = None
        if due_at is not None:
            due_in_minutes = int((due_at - now).total_seconds() // 60)

        top_work_orders.append(
            OpsHandoverWorkOrderRead(
                id=int(row["id"]),
                site=str(row["site"]),
                location=str(row["location"]),
                title=str(row["title"]),
                priority=priority,  # type: ignore[arg-type]
                status=str(row["status"]),  # type: ignore[arg-type]
                assignee=row["assignee"],
                due_at=due_at,
                created_at=created_at,
                is_escalated=is_escalated,
                is_overdue=is_overdue,
                due_in_minutes=due_in_minutes,
                urgency_score=urgency_score,
                reasons=reasons,
            )
        )

    far_future = now + timedelta(days=36500)
    top_work_orders.sort(
        key=lambda item: (
            -item.urgency_score,
            item.due_at or far_future,
            item.created_at,
            item.id,
        )
    )
    top_work_orders = top_work_orders[:max_items]

    risk_weights = {"danger": 2, "warning": 1}
    recent_high_risk_inspections: list[OpsHandoverInspectionRead] = []
    for row in high_risk_inspection_rows:
        risk_flags = [flag for flag in str(row["risk_flags"] or "").split(",") if flag]
        recent_high_risk_inspections.append(
            OpsHandoverInspectionRead(
                id=int(row["id"]),
                site=str(row["site"]),
                location=str(row["location"]),
                inspector=str(row["inspector"]),
                risk_level=str(row["risk_level"] or "warning"),
                inspected_at=_as_datetime(row["inspected_at"]),
                risk_flags=risk_flags,
            )
        )
    recent_high_risk_inspections.sort(
        key=lambda item: (
            risk_weights.get(item.risk_level, 0),
            item.inspected_at,
            item.id,
        ),
        reverse=True,
    )
    high_risk_inspections_in_window = len(recent_high_risk_inspections)
    recent_high_risk_inspections = recent_high_risk_inspections[:max_items]

    failed_alert_deliveries_24h = 0
    for row in alert_delivery_rows:
        payload_raw = str(row["payload_json"] or "{}")
        payload: dict[str, Any] = {}
        try:
            parsed_payload = json.loads(payload_raw)
            if isinstance(parsed_payload, dict):
                payload = parsed_payload
        except json.JSONDecodeError:
            payload = {}

        payload_site = _normalize_site_name(str(payload.get("site"))) if payload.get("site") is not None else None
        if site is not None:
            if payload_site != site:
                continue
        elif allowed_sites is not None and payload_site not in allowed_sites:
            continue
        failed_alert_deliveries_24h += 1

    recommended_actions: list[str] = []
    if overdue_open_work_orders > 0:
        recommended_actions.append(f"Resolve or reassign {overdue_open_work_orders} overdue open work orders.")
    if unassigned_high_priority_open_work_orders > 0:
        recommended_actions.append(
            f"Assign owners for {unassigned_high_priority_open_work_orders} unassigned high/critical work orders."
        )
    if high_risk_inspections_in_window > 0:
        recommended_actions.append(
            f"Review {high_risk_inspections_in_window} warning/danger inspections from last {window_hours} hours."
        )
    if due_soon_work_orders > 0:
        recommended_actions.append(f"Preempt {due_soon_work_orders} work orders due within next {due_soon_hours} hours.")
    if failed_alert_deliveries_24h > 0:
        recommended_actions.append(
            f"Investigate {failed_alert_deliveries_24h} failed/warning alert deliveries from last 24 hours."
        )
    if not recommended_actions:
        recommended_actions.append("No urgent blockers detected for this handover window.")

    return OpsHandoverBriefRead(
        generated_at=now,
        site=site,
        window_hours=window_hours,
        due_soon_hours=due_soon_hours,
        open_work_orders=len(open_work_order_rows),
        overdue_open_work_orders=overdue_open_work_orders,
        due_soon_work_orders=due_soon_work_orders,
        escalated_open_work_orders=escalated_open_work_orders,
        unassigned_high_priority_open_work_orders=unassigned_high_priority_open_work_orders,
        new_work_orders_in_window=len(new_work_order_rows),
        high_risk_inspections_in_window=high_risk_inspections_in_window,
        failed_alert_deliveries_24h=failed_alert_deliveries_24h,
        top_work_orders=top_work_orders,
        recent_high_risk_inspections=recent_high_risk_inspections,
        recommended_actions=recommended_actions[:5],
    )


def _json_or_scalar(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    if value is None:
        return ""
    return str(value)


def _build_monthly_report_csv(report: MonthlyReportRead) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["section", "key", "value"])
    writer.writerow(["meta", "month", report.month])
    writer.writerow(["meta", "site", report.site or "ALL"])
    writer.writerow(["meta", "generated_at", report.generated_at.isoformat()])
    writer.writerow(["inspections", "total", report.inspections.get("total", 0)])

    risk_counts = report.inspections.get("risk_counts", {})
    for key, value in risk_counts.items():
        writer.writerow(["inspections.risk_counts", key, value])

    top_flags = report.inspections.get("top_risk_flags", {})
    for key, value in top_flags.items():
        writer.writerow(["inspections.top_risk_flags", key, value])

    writer.writerow(["work_orders", "total", report.work_orders.get("total", 0)])
    for key, value in report.work_orders.items():
        if key == "status_counts":
            continue
        writer.writerow(["work_orders", key, _json_or_scalar(value)])

    status_counts = report.work_orders.get("status_counts", {})
    for key, value in status_counts.items():
        writer.writerow(["work_orders.status_counts", key, value])
    return out.getvalue()


def _build_monthly_report_pdf(report: MonthlyReportRead) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise HTTPException(status_code=500, detail="PDF generator dependency not installed") from exc

    lines = [
        f"Monthly Audit Report ({report.month})",
        "",
        f"Site: {report.site or 'ALL'}",
        f"Generated At: {report.generated_at.isoformat()}",
        "",
        "[Inspection Summary]",
        f"Total: {report.inspections.get('total', 0)}",
        f"Risk Counts: {_json_or_scalar(report.inspections.get('risk_counts', {}))}",
        f"Top Risk Flags: {_json_or_scalar(report.inspections.get('top_risk_flags', {}))}",
        "",
        "[Work Order Summary]",
        f"Total: {report.work_orders.get('total', 0)}",
        f"Status Counts: {_json_or_scalar(report.work_orders.get('status_counts', {}))}",
        f"Escalated Count: {report.work_orders.get('escalated_count', 0)}",
        f"Overdue Open Count: {report.work_orders.get('overdue_open_count', 0)}",
        f"Completion Rate (%): {report.work_orders.get('completion_rate_percent', 0)}",
        f"Avg Resolution Hours: {report.work_orders.get('avg_resolution_hours') or '-'}",
    ]

    buf = io.BytesIO()
    pdf = canvas.Canvas(buf, pagesize=A4)
    _, height = A4
    margin_left = 36
    y = height - 40
    pdf.setFont("Helvetica", 10)
    for line in lines:
        if y < 40:
            pdf.showPage()
            pdf.setFont("Helvetica", 10)
            y = height - 40
        pdf.drawString(margin_left, y, line[:180])
        y -= 14
    pdf.save()
    return buf.getvalue()


def _build_handover_brief_csv(report: OpsHandoverBriefRead) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["section", "key", "value"])
    writer.writerow(["meta", "site", report.site or "ALL"])
    writer.writerow(["meta", "generated_at", report.generated_at.isoformat()])
    writer.writerow(["meta", "window_hours", report.window_hours])
    writer.writerow(["meta", "due_soon_hours", report.due_soon_hours])

    writer.writerow(["summary", "open_work_orders", report.open_work_orders])
    writer.writerow(["summary", "overdue_open_work_orders", report.overdue_open_work_orders])
    writer.writerow(["summary", "due_soon_work_orders", report.due_soon_work_orders])
    writer.writerow(["summary", "escalated_open_work_orders", report.escalated_open_work_orders])
    writer.writerow(
        [
            "summary",
            "unassigned_high_priority_open_work_orders",
            report.unassigned_high_priority_open_work_orders,
        ]
    )
    writer.writerow(["summary", "new_work_orders_in_window", report.new_work_orders_in_window])
    writer.writerow(["summary", "high_risk_inspections_in_window", report.high_risk_inspections_in_window])
    writer.writerow(["summary", "failed_alert_deliveries_24h", report.failed_alert_deliveries_24h])

    writer.writerow([])
    writer.writerow(
        [
            "top_work_orders",
            "id",
            "site",
            "location",
            "title",
            "priority",
            "status",
            "assignee",
            "due_at",
            "due_in_minutes",
            "is_overdue",
            "is_escalated",
            "urgency_score",
            "reasons",
        ]
    )
    for item in report.top_work_orders:
        writer.writerow(
            [
                "top_work_orders",
                item.id,
                item.site,
                item.location,
                item.title,
                item.priority,
                item.status,
                item.assignee or "",
                item.due_at.isoformat() if item.due_at is not None else "",
                item.due_in_minutes if item.due_in_minutes is not None else "",
                item.is_overdue,
                item.is_escalated,
                item.urgency_score,
                ", ".join(item.reasons),
            ]
        )

    writer.writerow([])
    writer.writerow(
        [
            "recent_high_risk_inspections",
            "id",
            "site",
            "location",
            "inspector",
            "risk_level",
            "inspected_at",
            "risk_flags",
        ]
    )
    for item in report.recent_high_risk_inspections:
        writer.writerow(
            [
                "recent_high_risk_inspections",
                item.id,
                item.site,
                item.location,
                item.inspector,
                item.risk_level,
                item.inspected_at.isoformat(),
                ", ".join(item.risk_flags),
            ]
        )

    writer.writerow([])
    writer.writerow(["recommended_actions", "index", "action"])
    for idx, action in enumerate(report.recommended_actions, start=1):
        writer.writerow(["recommended_actions", idx, action])

    return out.getvalue()


def _build_handover_brief_pdf(report: OpsHandoverBriefRead) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise HTTPException(status_code=500, detail="PDF generator dependency not installed") from exc

    lines = [
        "Ops Handover Brief",
        "",
        f"Site: {report.site or 'ALL'}",
        f"Generated At: {report.generated_at.isoformat()}",
        f"Window Hours: {report.window_hours}",
        f"Due Soon Hours: {report.due_soon_hours}",
        "",
        "[Summary]",
        f"Open Work Orders: {report.open_work_orders}",
        f"Overdue Open Work Orders: {report.overdue_open_work_orders}",
        f"Due Soon Work Orders: {report.due_soon_work_orders}",
        f"Escalated Open Work Orders: {report.escalated_open_work_orders}",
        f"Unassigned High Priority Open Work Orders: {report.unassigned_high_priority_open_work_orders}",
        f"New Work Orders In Window: {report.new_work_orders_in_window}",
        f"High Risk Inspections In Window: {report.high_risk_inspections_in_window}",
        f"Failed Alert Deliveries 24h: {report.failed_alert_deliveries_24h}",
        "",
        "[Top Work Orders]",
    ]
    for item in report.top_work_orders:
        due_text = item.due_at.isoformat() if item.due_at is not None else "-"
        lines.append(
            f"#{item.id} {item.priority}/{item.status} score={item.urgency_score} site={item.site} due={due_text}"
        )
        lines.append(f"  {item.title[:120]}")

    lines.append("")
    lines.append("[Recent High Risk Inspections]")
    for item in report.recent_high_risk_inspections:
        lines.append(f"#{item.id} {item.risk_level} site={item.site} inspected_at={item.inspected_at.isoformat()}")
        if item.risk_flags:
            lines.append(f"  flags={', '.join(item.risk_flags)[:140]}")

    lines.append("")
    lines.append("[Recommended Actions]")
    for idx, action in enumerate(report.recommended_actions, start=1):
        lines.append(f"{idx}. {action}")

    buf = io.BytesIO()
    pdf = canvas.Canvas(buf, pagesize=A4)
    _, height = A4
    margin_left = 36
    y = height - 40
    pdf.setFont("Helvetica", 10)
    for line in lines:
        if y < 40:
            pdf.showPage()
            pdf.setFont("Helvetica", 10)
            y = height - 40
        pdf.drawString(margin_left, y, line[:180])
        y -= 14
    pdf.save()
    return buf.getvalue()


def _service_info_payload() -> dict[str, str]:
    return {
        "service": "ka-facility-os",
        "status": "running",
        "main_html": "/",
        "docs": "/docs",
        "inspection_api": "/api/inspections",
        "inspection_evidence_upload_api": "/api/inspections/{inspection_id}/evidence",
        "inspection_evidence_list_api": "/api/inspections/{inspection_id}/evidence",
        "inspection_evidence_download_api": "/api/inspections/evidence/{evidence_id}/download",
        "ops_inspection_checklists_import_validation_api": "/api/ops/inspections/checklists/import-validation",
        "ops_inspection_checklists_import_validation_csv_api": "/api/ops/inspections/checklists/import-validation.csv",
        "ops_inspection_checklists_qr_placeholders_api": "/api/ops/inspections/checklists/qr-assets/placeholders",
        "ops_inspection_checklists_qr_bulk_update_api": "/api/ops/inspections/checklists/qr-assets/bulk-update",
        "work_order_api": "/api/work-orders",
        "work_order_sla_rules_api": "/api/work-orders/sla/rules",
        "work_order_events_api": "/api/work-orders/{id}/events",
        "escalation_api": "/api/work-orders/escalations/run",
        "monthly_report_api": "/api/reports/monthly",
        "monthly_report_csv_api": "/api/reports/monthly/csv",
        "monthly_report_pdf_api": "/api/reports/monthly/pdf",
        "auth_login_api": "/api/auth/login",
        "auth_logout_api": "/api/auth/logout",
        "auth_me_api": "/api/auth/me",
        "auth_me_profile_api": "/api/auth/me/profile",
        "auth_me_deactivate_api": "/api/auth/me",
        "admin_users_api": "/api/admin/users",
        "admin_user_update_api": "/api/admin/users/{user_id}",
        "admin_user_delete_api": "/api/admin/users/{user_id}",
        "admin_user_password_api": "/api/admin/users/{user_id}/password",
        "admin_user_token_issue_api": "/api/admin/users/{user_id}/tokens",
        "admin_tokens_api": "/api/admin/tokens",
        "admin_token_rotate_api": "/api/admin/tokens/{token_id}/rotate",
        "admin_token_revoke_api": "/api/admin/tokens/{token_id}/revoke",
        "admin_token_policy_api": "/api/admin/token-policy",
        "admin_audit_api": "/api/admin/audit-logs",
        "admin_audit_integrity_api": "/api/admin/audit-integrity",
        "admin_audit_rebaseline_api": "/api/admin/audit-chain/rebaseline",
        "admin_audit_archive_monthly_api": "/api/admin/audit-archive/monthly",
        "admin_audit_archive_csv_api": "/api/admin/audit-archive/monthly/csv",
        "job_runs_api": "/api/ops/job-runs",
        "dashboard_summary_api": "/api/ops/dashboard/summary",
        "dashboard_trends_api": "/api/ops/dashboard/trends",
        "ops_api_latency_api": "/api/ops/performance/api-latency",
        "ops_evidence_archive_integrity_api": "/api/ops/integrity/evidence-archive",
        "ops_deploy_checklist_api": "/api/ops/deploy/checklist",
        "ops_deploy_smoke_record_api": "/api/ops/deploy/smoke/record",
        "ops_runbook_checks_api": "/api/ops/runbook/checks",
        "ops_runbook_checks_run_api": "/api/ops/runbook/checks/run",
        "ops_runbook_checks_latest_api": "/api/ops/runbook/checks/latest",
        "ops_runbook_checks_latest_summary_json_api": "/api/ops/runbook/checks/latest/summary.json",
        "ops_runbook_checks_latest_summary_csv_api": "/api/ops/runbook/checks/latest/summary.csv",
        "ops_runbook_checks_archive_json_api": "/api/ops/runbook/checks/archive.json",
        "ops_runbook_checks_archive_csv_api": "/api/ops/runbook/checks/archive.csv",
        "ops_runbook_review_run_api": "/api/ops/runbook/review/run",
        "ops_runbook_review_latest_api": "/api/ops/runbook/review/latest",
        "ops_preflight_api": "/api/ops/preflight",
        "ops_alert_noise_policy_api": "/api/ops/alerts/noise-policy",
        "ops_admin_security_dashboard_api": "/api/ops/admin/security-dashboard",
        "ops_quality_weekly_report_api": "/api/ops/reports/quality/weekly",
        "ops_quality_weekly_report_csv_api": "/api/ops/reports/quality/weekly/csv",
        "ops_quality_monthly_report_api": "/api/ops/reports/quality/monthly",
        "ops_quality_monthly_report_csv_api": "/api/ops/reports/quality/monthly/csv",
        "ops_quality_report_run_api": "/api/ops/reports/quality/run",
        "ops_quality_weekly_streak_api": "/api/ops/reports/quality/weekly/streak",
        "ops_dr_rehearsal_run_api": "/api/ops/dr/rehearsal/run",
        "ops_dr_rehearsal_latest_api": "/api/ops/dr/rehearsal/latest",
        "ops_dr_rehearsal_history_api": "/api/ops/dr/rehearsal/history",
        "ops_governance_gate_api": "/api/ops/governance/gate",
        "ops_governance_gate_run_api": "/api/ops/governance/gate/run",
        "ops_governance_gate_latest_api": "/api/ops/governance/gate/latest",
        "ops_governance_gate_history_api": "/api/ops/governance/gate/history",
        "ops_governance_gate_remediation_api": "/api/ops/governance/gate/remediation",
        "ops_governance_gate_remediation_csv_api": "/api/ops/governance/gate/remediation/csv",
        "ops_governance_remediation_tracker_sync_api": "/api/ops/governance/gate/remediation/tracker/sync",
        "ops_governance_remediation_tracker_items_api": "/api/ops/governance/gate/remediation/tracker/items",
        "ops_governance_remediation_tracker_overview_api": "/api/ops/governance/gate/remediation/tracker/overview",
        "ops_governance_remediation_tracker_readiness_api": "/api/ops/governance/gate/remediation/tracker/readiness",
        "ops_governance_remediation_tracker_completion_api": "/api/ops/governance/gate/remediation/tracker/completion",
        "ops_governance_remediation_tracker_complete_api": "/api/ops/governance/gate/remediation/tracker/complete",
        "ops_governance_remediation_tracker_sla_api": "/api/ops/governance/gate/remediation/tracker/sla",
        "ops_governance_remediation_tracker_escalate_run_api": "/api/ops/governance/gate/remediation/tracker/escalate/run",
        "ops_governance_remediation_tracker_escalate_latest_api": "/api/ops/governance/gate/remediation/tracker/escalate/latest",
        "ops_governance_remediation_tracker_workload_api": "/api/ops/governance/gate/remediation/tracker/workload",
        "ops_governance_remediation_tracker_auto_assign_run_api": "/api/ops/governance/gate/remediation/tracker/auto-assign/run",
        "ops_governance_remediation_tracker_auto_assign_latest_api": "/api/ops/governance/gate/remediation/tracker/auto-assign/latest",
        "ops_governance_remediation_tracker_kpi_api": "/api/ops/governance/gate/remediation/tracker/kpi",
        "ops_governance_remediation_tracker_kpi_run_api": "/api/ops/governance/gate/remediation/tracker/kpi/run",
        "ops_governance_remediation_tracker_kpi_latest_api": "/api/ops/governance/gate/remediation/tracker/kpi/latest",
        "ops_governance_remediation_tracker_autopilot_policy_api": "/api/ops/governance/gate/remediation/tracker/autopilot/policy",
        "ops_governance_remediation_tracker_autopilot_preview_api": "/api/ops/governance/gate/remediation/tracker/autopilot/preview",
        "ops_governance_remediation_tracker_autopilot_guard_api": "/api/ops/governance/gate/remediation/tracker/autopilot/guard",
        "ops_governance_remediation_tracker_autopilot_history_api": "/api/ops/governance/gate/remediation/tracker/autopilot/history",
        "ops_governance_remediation_tracker_autopilot_history_csv_api": "/api/ops/governance/gate/remediation/tracker/autopilot/history.csv",
        "ops_governance_remediation_tracker_autopilot_summary_api": "/api/ops/governance/gate/remediation/tracker/autopilot/summary",
        "ops_governance_remediation_tracker_autopilot_summary_csv_api": "/api/ops/governance/gate/remediation/tracker/autopilot/summary.csv",
        "ops_governance_remediation_tracker_autopilot_anomalies_api": "/api/ops/governance/gate/remediation/tracker/autopilot/anomalies",
        "ops_governance_remediation_tracker_autopilot_anomalies_csv_api": "/api/ops/governance/gate/remediation/tracker/autopilot/anomalies.csv",
        "ops_governance_remediation_tracker_autopilot_run_api": "/api/ops/governance/gate/remediation/tracker/autopilot/run",
        "ops_governance_remediation_tracker_autopilot_latest_api": "/api/ops/governance/gate/remediation/tracker/autopilot/latest",
        "ops_security_posture_api": "/api/ops/security/posture",
        "handover_brief_api": "/api/ops/handover/brief",
        "handover_brief_csv_api": "/api/ops/handover/brief/csv",
        "handover_brief_pdf_api": "/api/ops/handover/brief/pdf",
        "ops_tutorial_simulator_session_start_api": "/api/ops/tutorial-simulator/sessions/start",
        "ops_tutorial_simulator_sessions_api": "/api/ops/tutorial-simulator/sessions",
        "ops_tutorial_simulator_session_api": "/api/ops/tutorial-simulator/sessions/{session_id}",
        "ops_tutorial_simulator_session_check_api": "/api/ops/tutorial-simulator/sessions/{session_id}/check",
        "ops_tutorial_simulator_session_action_api": "/api/ops/tutorial-simulator/sessions/{session_id}/actions/{action}",
        "public_adoption_plan_api": "/api/public/adoption-plan",
        "public_adoption_schedule_csv_api": "/api/public/adoption-plan/schedule.csv",
        "public_adoption_schedule_ics_api": "/api/public/adoption-plan/schedule.ics",
        "public_adoption_campaign_api": "/api/public/adoption-plan/campaign",
        "public_adoption_w02_api": "/api/public/adoption-plan/w02",
        "public_adoption_w02_checklist_csv_api": "/api/public/adoption-plan/w02/checklist.csv",
        "public_adoption_w02_schedule_ics_api": "/api/public/adoption-plan/w02/schedule.ics",
        "public_adoption_w02_sample_files_api": "/api/public/adoption-plan/w02/sample-files",
        "public_adoption_w03_api": "/api/public/adoption-plan/w03",
        "public_adoption_w03_checklist_csv_api": "/api/public/adoption-plan/w03/checklist.csv",
        "public_adoption_w03_schedule_ics_api": "/api/public/adoption-plan/w03/schedule.ics",
        "public_adoption_w04_api": "/api/public/adoption-plan/w04",
        "public_adoption_w04_checklist_csv_api": "/api/public/adoption-plan/w04/checklist.csv",
        "public_adoption_w04_schedule_ics_api": "/api/public/adoption-plan/w04/schedule.ics",
        "public_adoption_w04_common_mistakes_api": "/api/public/adoption-plan/w04/common-mistakes",
        "public_adoption_w04_common_mistakes_html": "/web/adoption/w04/common-mistakes",
        "public_adoption_w05_api": "/api/public/adoption-plan/w05",
        "public_adoption_w05_missions_csv_api": "/api/public/adoption-plan/w05/missions.csv",
        "public_adoption_w05_schedule_ics_api": "/api/public/adoption-plan/w05/schedule.ics",
        "public_adoption_w05_help_docs_api": "/api/public/adoption-plan/w05/help-docs",
        "public_adoption_w06_api": "/api/public/adoption-plan/w06",
        "public_adoption_w06_checklist_csv_api": "/api/public/adoption-plan/w06/checklist.csv",
        "public_adoption_w06_schedule_ics_api": "/api/public/adoption-plan/w06/schedule.ics",
        "public_adoption_w06_rbac_audit_template_api": "/api/public/adoption-plan/w06/rbac-audit-template",
        "public_adoption_w07_api": "/api/public/adoption-plan/w07",
        "public_adoption_w07_checklist_csv_api": "/api/public/adoption-plan/w07/checklist.csv",
        "public_adoption_w07_schedule_ics_api": "/api/public/adoption-plan/w07/schedule.ics",
        "public_adoption_w07_coaching_playbook_api": "/api/public/adoption-plan/w07/coaching-playbook",
        "public_adoption_w08_api": "/api/public/adoption-plan/w08",
        "public_adoption_w08_checklist_csv_api": "/api/public/adoption-plan/w08/checklist.csv",
        "public_adoption_w08_schedule_ics_api": "/api/public/adoption-plan/w08/schedule.ics",
        "public_adoption_w08_reporting_sop_api": "/api/public/adoption-plan/w08/reporting-sop",
        "public_adoption_w09_api": "/api/public/adoption-plan/w09",
        "public_adoption_w09_checklist_csv_api": "/api/public/adoption-plan/w09/checklist.csv",
        "public_adoption_w09_schedule_ics_api": "/api/public/adoption-plan/w09/schedule.ics",
        "public_adoption_w10_api": "/api/public/adoption-plan/w10",
        "public_adoption_w10_checklist_csv_api": "/api/public/adoption-plan/w10/checklist.csv",
        "public_adoption_w10_schedule_ics_api": "/api/public/adoption-plan/w10/schedule.ics",
        "public_adoption_w11_api": "/api/public/adoption-plan/w11",
        "public_adoption_w11_checklist_csv_api": "/api/public/adoption-plan/w11/checklist.csv",
        "public_adoption_w11_schedule_ics_api": "/api/public/adoption-plan/w11/schedule.ics",
        "public_adoption_w12_api": "/api/public/adoption-plan/w12",
        "public_adoption_w12_checklist_csv_api": "/api/public/adoption-plan/w12/checklist.csv",
        "public_adoption_w12_schedule_ics_api": "/api/public/adoption-plan/w12/schedule.ics",
        "public_adoption_w13_api": "/api/public/adoption-plan/w13",
        "public_adoption_w13_checklist_csv_api": "/api/public/adoption-plan/w13/checklist.csv",
        "public_adoption_w13_schedule_ics_api": "/api/public/adoption-plan/w13/schedule.ics",
        "public_adoption_w14_api": "/api/public/adoption-plan/w14",
        "public_adoption_w14_checklist_csv_api": "/api/public/adoption-plan/w14/checklist.csv",
        "public_adoption_w14_schedule_ics_api": "/api/public/adoption-plan/w14/schedule.ics",
        "public_adoption_w15_api": "/api/public/adoption-plan/w15",
        "public_adoption_w15_checklist_csv_api": "/api/public/adoption-plan/w15/checklist.csv",
        "public_adoption_w15_schedule_ics_api": "/api/public/adoption-plan/w15/schedule.ics",
        "adoption_w02_tracker_items_api": "/api/adoption/w02/tracker/items",
        "adoption_w02_tracker_overview_api": "/api/adoption/w02/tracker/overview",
        "adoption_w02_tracker_bootstrap_api": "/api/adoption/w02/tracker/bootstrap",
        "adoption_w02_tracker_readiness_api": "/api/adoption/w02/tracker/readiness",
        "adoption_w02_tracker_completion_api": "/api/adoption/w02/tracker/completion",
        "adoption_w02_tracker_complete_api": "/api/adoption/w02/tracker/complete",
        "adoption_w03_tracker_items_api": "/api/adoption/w03/tracker/items",
        "adoption_w03_tracker_overview_api": "/api/adoption/w03/tracker/overview",
        "adoption_w03_tracker_bootstrap_api": "/api/adoption/w03/tracker/bootstrap",
        "adoption_w03_tracker_readiness_api": "/api/adoption/w03/tracker/readiness",
        "adoption_w03_tracker_completion_api": "/api/adoption/w03/tracker/completion",
        "adoption_w03_tracker_complete_api": "/api/adoption/w03/tracker/complete",
        "adoption_w04_funnel_api": "/api/ops/adoption/w04/funnel",
        "adoption_w04_blockers_api": "/api/ops/adoption/w04/blockers",
        "adoption_w04_tracker_items_api": "/api/adoption/w04/tracker/items",
        "adoption_w04_tracker_overview_api": "/api/adoption/w04/tracker/overview",
        "adoption_w04_tracker_bootstrap_api": "/api/adoption/w04/tracker/bootstrap",
        "adoption_w04_tracker_readiness_api": "/api/adoption/w04/tracker/readiness",
        "adoption_w04_tracker_completion_api": "/api/adoption/w04/tracker/completion",
        "adoption_w04_tracker_complete_api": "/api/adoption/w04/tracker/complete",
        "adoption_w07_tracker_items_api": "/api/adoption/w07/tracker/items",
        "adoption_w07_tracker_overview_api": "/api/adoption/w07/tracker/overview",
        "adoption_w07_tracker_bootstrap_api": "/api/adoption/w07/tracker/bootstrap",
        "adoption_w07_tracker_readiness_api": "/api/adoption/w07/tracker/readiness",
        "adoption_w07_tracker_completion_api": "/api/adoption/w07/tracker/completion",
        "adoption_w07_tracker_completion_package_api": "/api/adoption/w07/tracker/completion-package",
        "adoption_w07_tracker_complete_api": "/api/adoption/w07/tracker/complete",
        "adoption_w09_tracker_items_api": "/api/adoption/w09/tracker/items",
        "adoption_w09_tracker_overview_api": "/api/adoption/w09/tracker/overview",
        "adoption_w09_tracker_bootstrap_api": "/api/adoption/w09/tracker/bootstrap",
        "adoption_w09_tracker_readiness_api": "/api/adoption/w09/tracker/readiness",
        "adoption_w09_tracker_completion_api": "/api/adoption/w09/tracker/completion",
        "adoption_w09_tracker_complete_api": "/api/adoption/w09/tracker/complete",
        "adoption_w10_tracker_items_api": "/api/adoption/w10/tracker/items",
        "adoption_w10_tracker_overview_api": "/api/adoption/w10/tracker/overview",
        "adoption_w10_tracker_bootstrap_api": "/api/adoption/w10/tracker/bootstrap",
        "adoption_w10_tracker_readiness_api": "/api/adoption/w10/tracker/readiness",
        "adoption_w10_tracker_completion_api": "/api/adoption/w10/tracker/completion",
        "adoption_w10_tracker_complete_api": "/api/adoption/w10/tracker/complete",
        "adoption_w11_tracker_items_api": "/api/adoption/w11/tracker/items",
        "adoption_w11_tracker_overview_api": "/api/adoption/w11/tracker/overview",
        "adoption_w11_tracker_bootstrap_api": "/api/adoption/w11/tracker/bootstrap",
        "adoption_w11_tracker_readiness_api": "/api/adoption/w11/tracker/readiness",
        "adoption_w11_tracker_completion_api": "/api/adoption/w11/tracker/completion",
        "adoption_w11_tracker_complete_api": "/api/adoption/w11/tracker/complete",
        "adoption_w12_tracker_items_api": "/api/adoption/w12/tracker/items",
        "adoption_w12_tracker_overview_api": "/api/adoption/w12/tracker/overview",
        "adoption_w12_tracker_bootstrap_api": "/api/adoption/w12/tracker/bootstrap",
        "adoption_w12_tracker_readiness_api": "/api/adoption/w12/tracker/readiness",
        "adoption_w12_tracker_completion_api": "/api/adoption/w12/tracker/completion",
        "adoption_w12_tracker_complete_api": "/api/adoption/w12/tracker/complete",
        "adoption_w13_tracker_items_api": "/api/adoption/w13/tracker/items",
        "adoption_w13_tracker_overview_api": "/api/adoption/w13/tracker/overview",
        "adoption_w13_tracker_bootstrap_api": "/api/adoption/w13/tracker/bootstrap",
        "adoption_w13_tracker_readiness_api": "/api/adoption/w13/tracker/readiness",
        "adoption_w13_tracker_completion_api": "/api/adoption/w13/tracker/completion",
        "adoption_w13_tracker_complete_api": "/api/adoption/w13/tracker/complete",
        "adoption_w14_tracker_items_api": "/api/adoption/w14/tracker/items",
        "adoption_w14_tracker_overview_api": "/api/adoption/w14/tracker/overview",
        "adoption_w14_tracker_bootstrap_api": "/api/adoption/w14/tracker/bootstrap",
        "adoption_w14_tracker_readiness_api": "/api/adoption/w14/tracker/readiness",
        "adoption_w14_tracker_completion_api": "/api/adoption/w14/tracker/completion",
        "adoption_w14_tracker_complete_api": "/api/adoption/w14/tracker/complete",
        "adoption_w15_tracker_items_api": "/api/adoption/w15/tracker/items",
        "adoption_w15_tracker_overview_api": "/api/adoption/w15/tracker/overview",
        "adoption_w15_tracker_bootstrap_api": "/api/adoption/w15/tracker/bootstrap",
        "adoption_w15_tracker_readiness_api": "/api/adoption/w15/tracker/readiness",
        "adoption_w15_tracker_completion_api": "/api/adoption/w15/tracker/completion",
        "adoption_w15_tracker_complete_api": "/api/adoption/w15/tracker/complete",
        "adoption_w05_consistency_api": "/api/ops/adoption/w05/consistency",
        "adoption_w06_rhythm_api": "/api/ops/adoption/w06/rhythm",
        "adoption_w07_sla_quality_api": "/api/ops/adoption/w07/sla-quality",
        "adoption_w07_automation_readiness_api": "/api/ops/adoption/w07/automation-readiness",
        "adoption_w07_sla_quality_weekly_run_api": "/api/ops/adoption/w07/sla-quality/run-weekly",
        "adoption_w07_sla_quality_weekly_latest_api": "/api/ops/adoption/w07/sla-quality/latest-weekly",
        "adoption_w07_sla_quality_weekly_trends_api": "/api/ops/adoption/w07/sla-quality/trends",
        "adoption_w07_sla_quality_weekly_archive_csv_api": "/api/ops/adoption/w07/sla-quality/archive.csv",
        "adoption_w08_report_discipline_api": "/api/ops/adoption/w08/report-discipline",
        "adoption_w08_site_benchmark_api": "/api/ops/adoption/w08/site-benchmark",
        "adoption_w09_kpi_operation_api": "/api/ops/adoption/w09/kpi-operation",
        "adoption_w09_kpi_policy_api": "/api/ops/adoption/w09/kpi-policy",
        "adoption_w10_self_serve_api": "/api/ops/adoption/w10/self-serve",
        "adoption_w10_support_policy_api": "/api/ops/adoption/w10/support-policy",
        "adoption_w11_scale_readiness_api": "/api/ops/adoption/w11/scale-readiness",
        "adoption_w11_readiness_policy_api": "/api/ops/adoption/w11/readiness-policy",
        "adoption_w12_closure_handoff_api": "/api/ops/adoption/w12/closure-handoff",
        "adoption_w12_handoff_policy_api": "/api/ops/adoption/w12/handoff-policy",
        "adoption_w13_closure_handoff_api": "/api/ops/adoption/w13/closure-handoff",
        "adoption_w13_handoff_policy_api": "/api/ops/adoption/w13/handoff-policy",
        "adoption_w14_stability_sprint_api": "/api/ops/adoption/w14/stability-sprint",
        "adoption_w14_stability_policy_api": "/api/ops/adoption/w14/stability-policy",
        "adoption_w15_ops_efficiency_api": "/api/ops/adoption/w15/ops-efficiency",
        "adoption_w15_efficiency_policy_api": "/api/ops/adoption/w15/efficiency-policy",
        "public_post_mvp_plan_api": "/api/public/post-mvp",
        "public_post_mvp_backlog_csv_api": "/api/public/post-mvp/backlog.csv",
        "public_post_mvp_release_ics_api": "/api/public/post-mvp/releases.ics",
        "public_post_mvp_kpi_api": "/api/public/post-mvp/kpi-dashboard",
        "public_post_mvp_risks_api": "/api/public/post-mvp/risks",
        "public_modules_api": "/api/public/modules",
        "public_tutorial_simulator_api": "/api/public/tutorial-simulator",
        "public_tutorial_simulator_sample_files_api": "/api/public/tutorial-simulator/sample-files",
        "public_onboarding_day1_api": "/api/public/onboarding/day1",
        "public_glossary_api": "/api/public/glossary",
        "tutorial_simulator_html": "/web/tutorial-simulator",
        "tutorial_guide_html": "/web/tutorial-guide",
        "adoption_portal_html": "/web/adoption",
        "facility_console_html": "/web/console",
        "facility_console_guide_html": "/web/console/guide",
        "iam_guide_html": "/web/iam-guide",
        "alert_deliveries_api": "/api/ops/alerts/deliveries",
        "alert_internal_webhook_api": "/api/ops/alerts/webhook/internal",
        "alert_channel_kpi_api": "/api/ops/alerts/kpi/channels",
        "alert_channel_mttr_kpi_api": "/api/ops/alerts/kpi/mttr",
        "alert_mttr_slo_policy_api": "/api/ops/alerts/mttr-slo/policy",
        "alert_mttr_slo_run_api": "/api/ops/alerts/mttr-slo/check/run",
        "alert_mttr_slo_latest_api": "/api/ops/alerts/mttr-slo/check/latest",
        "alert_channel_guard_api": "/api/ops/alerts/channels/guard",
        "alert_channel_guard_recover_api": "/api/ops/alerts/channels/guard/recover",
        "alert_channel_guard_recover_batch_api": "/api/ops/alerts/channels/guard/recover-batch",
        "alert_channel_guard_recover_latest_api": "/api/ops/alerts/channels/guard/recover/latest",
        "alert_retry_api": "/api/ops/alerts/retries/run",
        "alert_retention_policy_api": "/api/ops/alerts/retention/policy",
        "alert_retention_latest_api": "/api/ops/alerts/retention/latest",
        "alert_retention_run_api": "/api/ops/alerts/retention/run",
        "sla_simulator_api": "/api/ops/sla/simulate",
        "sla_policy_api": "/api/admin/policies/sla",
        "sla_policy_proposals_api": "/api/admin/policies/sla/proposals",
        "sla_policy_revisions_api": "/api/admin/policies/sla/revisions",
        "workflow_locks_api": "/api/workflow-locks",
    }


def _adoption_plan_payload() -> dict[str, Any]:
    today = datetime.now(timezone.utc).date()
    next_review_date = ADOPTION_PLAN_END.isoformat()
    for item in ADOPTION_WEEKLY_EXECUTION:
        week_end = date.fromisoformat(str(item["end_date"]))
        if week_end >= today:
            next_review_date = week_end.isoformat()
            break

    return {
        "title": "KA Facility OS 사용자 정착 계획 (User Adoption Plan)",
        "published_on": "2026-02-27",
        "public": True,
        "timeline": {
            "start_date": ADOPTION_PLAN_START.isoformat(),
            "end_date": ADOPTION_PLAN_END.isoformat(),
            "duration_weeks": len(ADOPTION_WEEKLY_EXECUTION),
        },
        "weekly_execution": ADOPTION_WEEKLY_EXECUTION,
        "workflow_lock_matrix": ADOPTION_WORKFLOW_LOCK_MATRIX,
        "w02_sop_sandbox": _adoption_w02_payload(),
        "w03_go_live_onboarding": _adoption_w03_payload(),
        "w04_first_success_acceleration": _adoption_w04_payload(),
        "w05_usage_consistency": _adoption_w05_payload(),
        "w06_operational_rhythm": _adoption_w06_payload(),
        "w07_sla_quality": _adoption_w07_payload(),
        "w08_report_discipline": _adoption_w08_payload(),
        "w09_kpi_operation": _adoption_w09_payload(),
        "w10_self_serve_support": _adoption_w10_payload(),
        "w11_scale_readiness": _adoption_w11_payload(),
        "w12_closure_handoff": _adoption_w12_payload(),
        "w13_continuous_improvement": _adoption_w13_payload(),
        "w14_stability_sprint": _adoption_w14_payload(),
        "w15_operations_efficiency": _adoption_w15_payload(),
        "training_outline": ADOPTION_TRAINING_OUTLINE,
        "kpi_dashboard_items": ADOPTION_KPI_DASHBOARD_ITEMS,
        "campaign_kit": {
            "promotion": ADOPTION_PROMOTION_PACK,
            "education": ADOPTION_EDUCATION_PACK,
            "fun": ADOPTION_FUN_PACK,
        },
        "schedule_management": {
            "cadence": [
                "Monday 09:00: Weekly kickoff and role mission assignment",
                "Wednesday 16:00: Mid-week checkpoint and blocker removal",
                "Friday 17:00: KPI review and next-week plan confirmation",
            ],
            "downloads": {
                "schedule_csv": "/api/public/adoption-plan/schedule.csv",
                "schedule_ics": "/api/public/adoption-plan/schedule.ics",
                "w02_json": "/api/public/adoption-plan/w02",
                "w02_checklist_csv": "/api/public/adoption-plan/w02/checklist.csv",
                "w02_schedule_ics": "/api/public/adoption-plan/w02/schedule.ics",
                "w02_sample_files": "/api/public/adoption-plan/w02/sample-files",
                "w03_json": "/api/public/adoption-plan/w03",
                "w03_checklist_csv": "/api/public/adoption-plan/w03/checklist.csv",
                "w03_schedule_ics": "/api/public/adoption-plan/w03/schedule.ics",
                "w04_json": "/api/public/adoption-plan/w04",
                "w04_checklist_csv": "/api/public/adoption-plan/w04/checklist.csv",
                "w04_schedule_ics": "/api/public/adoption-plan/w04/schedule.ics",
                "w04_common_mistakes": "/api/public/adoption-plan/w04/common-mistakes",
                "w05_json": "/api/public/adoption-plan/w05",
                "w05_missions_csv": "/api/public/adoption-plan/w05/missions.csv",
                "w05_schedule_ics": "/api/public/adoption-plan/w05/schedule.ics",
                "w05_help_docs": "/api/public/adoption-plan/w05/help-docs",
                "w06_json": "/api/public/adoption-plan/w06",
                "w06_checklist_csv": "/api/public/adoption-plan/w06/checklist.csv",
                "w06_schedule_ics": "/api/public/adoption-plan/w06/schedule.ics",
                "w06_rbac_audit_template": "/api/public/adoption-plan/w06/rbac-audit-template",
                "w07_json": "/api/public/adoption-plan/w07",
                "w07_checklist_csv": "/api/public/adoption-plan/w07/checklist.csv",
                "w07_schedule_ics": "/api/public/adoption-plan/w07/schedule.ics",
                "w07_coaching_playbook": "/api/public/adoption-plan/w07/coaching-playbook",
                "w08_json": "/api/public/adoption-plan/w08",
                "w08_checklist_csv": "/api/public/adoption-plan/w08/checklist.csv",
                "w08_schedule_ics": "/api/public/adoption-plan/w08/schedule.ics",
                "w08_reporting_sop": "/api/public/adoption-plan/w08/reporting-sop",
                "w09_json": "/api/public/adoption-plan/w09",
                "w09_checklist_csv": "/api/public/adoption-plan/w09/checklist.csv",
                "w09_schedule_ics": "/api/public/adoption-plan/w09/schedule.ics",
                "w10_json": "/api/public/adoption-plan/w10",
                "w10_checklist_csv": "/api/public/adoption-plan/w10/checklist.csv",
                "w10_schedule_ics": "/api/public/adoption-plan/w10/schedule.ics",
                "w11_json": "/api/public/adoption-plan/w11",
                "w11_checklist_csv": "/api/public/adoption-plan/w11/checklist.csv",
                "w11_schedule_ics": "/api/public/adoption-plan/w11/schedule.ics",
                "w12_json": "/api/public/adoption-plan/w12",
                "w12_checklist_csv": "/api/public/adoption-plan/w12/checklist.csv",
                "w12_schedule_ics": "/api/public/adoption-plan/w12/schedule.ics",
                "w13_json": "/api/public/adoption-plan/w13",
                "w13_checklist_csv": "/api/public/adoption-plan/w13/checklist.csv",
                "w13_schedule_ics": "/api/public/adoption-plan/w13/schedule.ics",
                "w14_json": "/api/public/adoption-plan/w14",
                "w14_checklist_csv": "/api/public/adoption-plan/w14/checklist.csv",
                "w14_schedule_ics": "/api/public/adoption-plan/w14/schedule.ics",
                "w15_json": "/api/public/adoption-plan/w15",
                "w15_checklist_csv": "/api/public/adoption-plan/w15/checklist.csv",
                "w15_schedule_ics": "/api/public/adoption-plan/w15/schedule.ics",
            },
            "next_review_date": next_review_date,
        },
    }


def _adoption_w02_payload() -> dict[str, Any]:
    week_item = next(
        (item for item in ADOPTION_WEEKLY_EXECUTION if int(item.get("week", 0)) == 2),
        None,
    )
    if week_item is None:
        timeline = {"week": 2, "start_date": "", "end_date": "", "phase": "Preparation", "focus": "SOP and sandbox"}
    else:
        timeline = {
            "week": int(week_item.get("week", 2)),
            "start_date": str(week_item.get("start_date", "")),
            "end_date": str(week_item.get("end_date", "")),
            "phase": str(week_item.get("phase", "")),
            "focus": str(week_item.get("focus", "")),
            "owner": str(week_item.get("owner", "")),
            "success_metric": str(week_item.get("success_metric", "")),
        }

    return {
        "title": "W02 Scheduled SOP and Sandbox Pack",
        "public": True,
        "timeline": timeline,
        "sop_runbooks": ADOPTION_W02_SOP_RUNBOOKS,
        "sandbox_scenarios": ADOPTION_W02_SANDBOX_SCENARIOS,
        "scheduled_events": ADOPTION_W02_SCHEDULED_EVENTS,
        "downloads": {
            "json": "/api/public/adoption-plan/w02",
            "checklist_csv": "/api/public/adoption-plan/w02/checklist.csv",
            "schedule_ics": "/api/public/adoption-plan/w02/schedule.ics",
            "sample_files": "/api/public/adoption-plan/w02/sample-files",
        },
    }


def _adoption_w03_payload() -> dict[str, Any]:
    week_item = next(
        (item for item in ADOPTION_WEEKLY_EXECUTION if int(item.get("week", 0)) == 3),
        None,
    )
    if week_item is None:
        timeline = {"week": 3, "start_date": "", "end_date": "", "phase": "Launch", "focus": "Go-live onboarding"}
    else:
        timeline = {
            "week": int(week_item.get("week", 3)),
            "start_date": str(week_item.get("start_date", "")),
            "end_date": str(week_item.get("end_date", "")),
            "phase": str(week_item.get("phase", "")),
            "focus": str(week_item.get("focus", "")),
            "owner": str(week_item.get("owner", "")),
            "success_metric": str(week_item.get("success_metric", "")),
        }

    return {
        "title": "W03 Go-live Onboarding Pack",
        "public": True,
        "timeline": timeline,
        "kickoff_agenda": ADOPTION_W03_KICKOFF_AGENDA,
        "role_workshops": ADOPTION_W03_ROLE_WORKSHOPS,
        "office_hours": ADOPTION_W03_OFFICE_HOURS,
        "scheduled_events": ADOPTION_W03_SCHEDULED_EVENTS,
        "downloads": {
            "json": "/api/public/adoption-plan/w03",
            "checklist_csv": "/api/public/adoption-plan/w03/checklist.csv",
            "schedule_ics": "/api/public/adoption-plan/w03/schedule.ics",
        },
    }


def _adoption_w04_payload() -> dict[str, Any]:
    week_item = next(
        (item for item in ADOPTION_WEEKLY_EXECUTION if int(item.get("week", 0)) == 4),
        None,
    )
    if week_item is None:
        timeline = {
            "week": 4,
            "start_date": "",
            "end_date": "",
            "phase": "Adaptation",
            "focus": "First success acceleration",
        }
    else:
        timeline = {
            "week": int(week_item.get("week", 4)),
            "start_date": str(week_item.get("start_date", "")),
            "end_date": str(week_item.get("end_date", "")),
            "phase": str(week_item.get("phase", "")),
            "focus": str(week_item.get("focus", "")),
            "owner": str(week_item.get("owner", "")),
            "success_metric": str(week_item.get("success_metric", "")),
        }

    return {
        "title": "W04 First Success Acceleration Pack",
        "public": True,
        "timeline": timeline,
        "coaching_actions": ADOPTION_W04_COACHING_ACTIONS,
        "scheduled_events": ADOPTION_W04_SCHEDULED_EVENTS,
        "common_mistakes_reference": "/api/public/adoption-plan/w04/common-mistakes",
        "downloads": {
            "json": "/api/public/adoption-plan/w04",
            "checklist_csv": "/api/public/adoption-plan/w04/checklist.csv",
            "schedule_ics": "/api/public/adoption-plan/w04/schedule.ics",
            "common_mistakes": "/api/public/adoption-plan/w04/common-mistakes",
        },
    }


def _build_adoption_w04_checklist_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "section",
            "id",
            "champion_role",
            "action",
            "owner",
            "due_hint",
            "objective",
            "evidence_required",
            "quick_fix",
        ]
    )
    for item in payload.get("coaching_actions", []):
        writer.writerow(
            [
                "coaching_action",
                item.get("id", ""),
                item.get("champion_role", ""),
                item.get("action", ""),
                item.get("owner", ""),
                item.get("due_hint", ""),
                item.get("objective", ""),
                item.get("evidence_required", False),
                item.get("quick_fix", ""),
            ]
        )
    for item in payload.get("scheduled_events", []):
        writer.writerow(
            [
                "scheduled_event",
                item.get("id", ""),
                "",
                item.get("title", ""),
                item.get("owner", ""),
                f"{item.get('date', '')} {item.get('start_time', '')}-{item.get('end_time', '')}",
                "",
                "",
                item.get("output", ""),
            ]
        )
    return out.getvalue()


def _build_adoption_w04_schedule_ics(payload: dict[str, Any]) -> str:
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    events: list[str] = []
    for item in payload.get("scheduled_events", []):
        date_raw = str(item.get("date", ""))
        start_raw = str(item.get("start_time", "09:00"))
        end_raw = str(item.get("end_time", "10:00"))
        try:
            start_dt = datetime.strptime(f"{date_raw} {start_raw}", "%Y-%m-%d %H:%M")
            end_dt = datetime.strptime(f"{date_raw} {end_raw}", "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        uid = f"ka-facility-os-w04-{str(item.get('id', '')).lower()}@public"
        summary = f"[W04] {str(item.get('title', 'First Success Session'))}"
        description = "\n".join(
            [
                f"Owner: {str(item.get('owner', ''))}",
                f"Output: {str(item.get('output', ''))}",
            ]
        )
        events.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{dtstamp}",
                f"DTSTART:{start_dt.strftime('%Y%m%dT%H%M%S')}",
                f"DTEND:{end_dt.strftime('%Y%m%dT%H%M%S')}",
                f"SUMMARY:{_ics_escape(summary)}",
                f"DESCRIPTION:{_ics_escape(description)}",
                "END:VEVENT",
            ]
        )

    calendar_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KA Facility OS//W04 First Success Acceleration//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    calendar_lines.extend(events)
    calendar_lines.append("END:VCALENDAR")
    return "\r\n".join(calendar_lines) + "\r\n"


def _build_adoption_w03_checklist_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "section",
            "id",
            "name_or_role",
            "owner_or_trainer",
            "schedule",
            "objective_or_focus",
            "checklist_or_channel",
            "duration_min",
            "expected_output_or_success",
        ]
    )
    for item in payload.get("kickoff_agenda", []):
        writer.writerow(
            [
                "kickoff_agenda",
                item.get("id", ""),
                item.get("topic", ""),
                item.get("owner", ""),
                "",
                item.get("objective", ""),
                "",
                item.get("duration_min", ""),
                item.get("expected_output", ""),
            ]
        )
    for item in payload.get("role_workshops", []):
        writer.writerow(
            [
                "role_workshop",
                item.get("id", ""),
                item.get("role", ""),
                item.get("trainer", ""),
                "",
                item.get("objective", ""),
                " | ".join(str(x) for x in item.get("checklist", [])),
                item.get("duration_min", ""),
                item.get("success_criteria", ""),
            ]
        )
    for item in payload.get("office_hours", []):
        writer.writerow(
            [
                "office_hour",
                item.get("id", ""),
                "Daily office hour",
                item.get("host", ""),
                f"{item.get('date', '')} {item.get('start_time', '')}-{item.get('end_time', '')}",
                item.get("focus", ""),
                item.get("channel", ""),
                "",
                "",
            ]
        )
    for item in payload.get("scheduled_events", []):
        writer.writerow(
            [
                "scheduled_event",
                item.get("id", ""),
                item.get("title", ""),
                item.get("owner", ""),
                f"{item.get('date', '')} {item.get('start_time', '')}-{item.get('end_time', '')}",
                "",
                "",
                "",
                item.get("output", ""),
            ]
        )
    return out.getvalue()


def _build_adoption_w03_schedule_ics(payload: dict[str, Any]) -> str:
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    events: list[str] = []
    for item in payload.get("scheduled_events", []):
        date_raw = str(item.get("date", ""))
        start_raw = str(item.get("start_time", "09:00"))
        end_raw = str(item.get("end_time", "10:00"))
        try:
            start_dt = datetime.strptime(f"{date_raw} {start_raw}", "%Y-%m-%d %H:%M")
            end_dt = datetime.strptime(f"{date_raw} {end_raw}", "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        uid = f"ka-facility-os-w03-{str(item.get('id', '')).lower()}@public"
        summary = f"[W03] {str(item.get('title', 'Go-live Session'))}"
        description = "\n".join(
            [
                f"Owner: {str(item.get('owner', ''))}",
                f"Output: {str(item.get('output', ''))}",
            ]
        )
        events.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{dtstamp}",
                f"DTSTART:{start_dt.strftime('%Y%m%dT%H%M%S')}",
                f"DTEND:{end_dt.strftime('%Y%m%dT%H%M%S')}",
                f"SUMMARY:{_ics_escape(summary)}",
                f"DESCRIPTION:{_ics_escape(description)}",
                "END:VEVENT",
            ]
        )

    calendar_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KA Facility OS//W03 Go-live Onboarding//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    calendar_lines.extend(events)
    calendar_lines.append("END:VCALENDAR")
    return "\r\n".join(calendar_lines) + "\r\n"


def _adoption_w05_payload() -> dict[str, Any]:
    week_item = next(
        (item for item in ADOPTION_WEEKLY_EXECUTION if int(item.get("week", 0)) == 5),
        None,
    )
    if week_item is None:
        timeline = {
            "week": 5,
            "start_date": "",
            "end_date": "",
            "phase": "Adaptation",
            "focus": "Usage consistency",
        }
    else:
        timeline = {
            "week": int(week_item.get("week", 5)),
            "start_date": str(week_item.get("start_date", "")),
            "end_date": str(week_item.get("end_date", "")),
            "phase": str(week_item.get("phase", "")),
            "focus": str(week_item.get("focus", "")),
            "owner": str(week_item.get("owner", "")),
            "success_metric": str(week_item.get("success_metric", "")),
        }

    return {
        "title": "W05 Usage Consistency Pack",
        "public": True,
        "timeline": timeline,
        "role_missions": ADOPTION_W05_ROLE_MISSIONS,
        "scheduled_events": ADOPTION_W05_SCHEDULED_EVENTS,
        "help_docs": ADOPTION_W05_HELP_DOCS,
        "usage_consistency_api": "/api/ops/adoption/w05/consistency",
        "downloads": {
            "json": "/api/public/adoption-plan/w05",
            "missions_csv": "/api/public/adoption-plan/w05/missions.csv",
            "schedule_ics": "/api/public/adoption-plan/w05/schedule.ics",
            "help_docs": "/api/public/adoption-plan/w05/help-docs",
        },
    }


def _build_adoption_w05_missions_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "section",
            "id",
            "role",
            "mission",
            "weekly_target",
            "owner",
            "evidence_required",
            "evidence_hint",
        ]
    )
    for item in payload.get("role_missions", []):
        writer.writerow(
            [
                "role_mission",
                item.get("id", ""),
                item.get("role", ""),
                item.get("mission", ""),
                item.get("weekly_target", ""),
                item.get("owner", ""),
                item.get("evidence_required", False),
                item.get("evidence_hint", ""),
            ]
        )
    for item in payload.get("scheduled_events", []):
        writer.writerow(
            [
                "scheduled_event",
                item.get("id", ""),
                "",
                item.get("title", ""),
                f"{item.get('date', '')} {item.get('start_time', '')}-{item.get('end_time', '')}",
                item.get("owner", ""),
                "",
                item.get("output", ""),
            ]
        )
    return out.getvalue()


def _build_adoption_w05_schedule_ics(payload: dict[str, Any]) -> str:
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    events: list[str] = []
    for item in payload.get("scheduled_events", []):
        date_raw = str(item.get("date", ""))
        start_raw = str(item.get("start_time", "09:00"))
        end_raw = str(item.get("end_time", "10:00"))
        try:
            start_dt = datetime.strptime(f"{date_raw} {start_raw}", "%Y-%m-%d %H:%M")
            end_dt = datetime.strptime(f"{date_raw} {end_raw}", "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        uid = f"ka-facility-os-w05-{str(item.get('id', '')).lower()}@public"
        summary = f"[W05] {str(item.get('title', 'Usage Consistency Session'))}"
        description = "\n".join(
            [
                f"Owner: {str(item.get('owner', ''))}",
                f"Output: {str(item.get('output', ''))}",
            ]
        )
        events.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{dtstamp}",
                f"DTSTART:{start_dt.strftime('%Y%m%dT%H%M%S')}",
                f"DTEND:{end_dt.strftime('%Y%m%dT%H%M%S')}",
                f"SUMMARY:{_ics_escape(summary)}",
                f"DESCRIPTION:{_ics_escape(description)}",
                "END:VEVENT",
            ]
        )

    calendar_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KA Facility OS//W05 Usage Consistency//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    calendar_lines.extend(events)
    calendar_lines.append("END:VCALENDAR")
    return "\r\n".join(calendar_lines) + "\r\n"


def _adoption_w06_payload() -> dict[str, Any]:
    week_item = next(
        (item for item in ADOPTION_WEEKLY_EXECUTION if int(item.get("week", 0)) == 6),
        None,
    )
    if week_item is None:
        timeline = {
            "week": 6,
            "start_date": "",
            "end_date": "",
            "phase": "Habit",
            "focus": "Operational rhythm",
        }
    else:
        timeline = {
            "week": int(week_item.get("week", 6)),
            "start_date": str(week_item.get("start_date", "")),
            "end_date": str(week_item.get("end_date", "")),
            "phase": str(week_item.get("phase", "")),
            "focus": str(week_item.get("focus", "")),
            "owner": str(week_item.get("owner", "")),
            "success_metric": str(week_item.get("success_metric", "")),
        }

    return {
        "title": "W06 Operational Rhythm Pack",
        "public": True,
        "timeline": timeline,
        "rhythm_checklist": ADOPTION_W06_RHYTHM_CHECKLIST,
        "scheduled_events": ADOPTION_W06_SCHEDULED_EVENTS,
        "rbac_audit_checklist": ADOPTION_W06_RBAC_AUDIT_CHECKLIST,
        "rhythm_api": "/api/ops/adoption/w06/rhythm",
        "downloads": {
            "json": "/api/public/adoption-plan/w06",
            "checklist_csv": "/api/public/adoption-plan/w06/checklist.csv",
            "schedule_ics": "/api/public/adoption-plan/w06/schedule.ics",
            "rbac_audit_template": "/api/public/adoption-plan/w06/rbac-audit-template",
        },
    }


def _build_adoption_w06_checklist_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "section",
            "id",
            "day_or_control",
            "routine_or_objective",
            "owner_or_api_ref",
            "definition_of_done_or_pass_criteria",
            "evidence_hint",
        ]
    )
    for item in payload.get("rhythm_checklist", []):
        writer.writerow(
            [
                "rhythm_checklist",
                item.get("id", ""),
                item.get("day", ""),
                item.get("routine", ""),
                item.get("owner_role", ""),
                item.get("definition_of_done", ""),
                item.get("evidence_hint", ""),
            ]
        )
    for item in payload.get("rbac_audit_checklist", []):
        writer.writerow(
            [
                "rbac_audit",
                item.get("id", ""),
                item.get("control", ""),
                item.get("objective", ""),
                item.get("api_ref", ""),
                item.get("pass_criteria", ""),
                "",
            ]
        )
    for item in payload.get("scheduled_events", []):
        writer.writerow(
            [
                "scheduled_event",
                item.get("id", ""),
                item.get("date", ""),
                item.get("title", ""),
                item.get("owner", ""),
                item.get("output", ""),
                f"{item.get('start_time', '')}-{item.get('end_time', '')}",
            ]
        )
    return out.getvalue()


def _build_adoption_w06_schedule_ics(payload: dict[str, Any]) -> str:
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    events: list[str] = []
    for item in payload.get("scheduled_events", []):
        date_raw = str(item.get("date", ""))
        start_raw = str(item.get("start_time", "09:00"))
        end_raw = str(item.get("end_time", "10:00"))
        try:
            start_dt = datetime.strptime(f"{date_raw} {start_raw}", "%Y-%m-%d %H:%M")
            end_dt = datetime.strptime(f"{date_raw} {end_raw}", "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        uid = f"ka-facility-os-w06-{str(item.get('id', '')).lower()}@public"
        summary = f"[W06] {str(item.get('title', 'Operational Rhythm Session'))}"
        description = "\n".join(
            [
                f"Owner: {str(item.get('owner', ''))}",
                f"Output: {str(item.get('output', ''))}",
            ]
        )
        events.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{dtstamp}",
                f"DTSTART:{start_dt.strftime('%Y%m%dT%H%M%S')}",
                f"DTEND:{end_dt.strftime('%Y%m%dT%H%M%S')}",
                f"SUMMARY:{_ics_escape(summary)}",
                f"DESCRIPTION:{_ics_escape(description)}",
                "END:VEVENT",
            ]
        )

    calendar_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KA Facility OS//W06 Operational Rhythm//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    calendar_lines.extend(events)
    calendar_lines.append("END:VCALENDAR")
    return "\r\n".join(calendar_lines) + "\r\n"


def _adoption_w07_payload() -> dict[str, Any]:
    week_item = next(
        (item for item in ADOPTION_WEEKLY_EXECUTION if int(item.get("week", 0)) == 7),
        None,
    )
    if week_item is None:
        timeline = {
            "week": 7,
            "start_date": "",
            "end_date": "",
            "phase": "Habit",
            "focus": "SLA quality",
        }
    else:
        timeline = {
            "week": int(week_item.get("week", 7)),
            "start_date": str(week_item.get("start_date", "")),
            "end_date": str(week_item.get("end_date", "")),
            "phase": str(week_item.get("phase", "")),
            "focus": str(week_item.get("focus", "")),
            "owner": str(week_item.get("owner", "")),
            "success_metric": str(week_item.get("success_metric", "")),
        }

    return {
        "title": "W07 SLA Quality Pack",
        "public": True,
        "timeline": timeline,
        "sla_checklist": ADOPTION_W07_SLA_CHECKLIST,
        "coaching_plays": ADOPTION_W07_COACHING_PLAYS,
        "scheduled_events": ADOPTION_W07_SCHEDULED_EVENTS,
        "sla_quality_api": "/api/ops/adoption/w07/sla-quality",
        "downloads": {
            "json": "/api/public/adoption-plan/w07",
            "checklist_csv": "/api/public/adoption-plan/w07/checklist.csv",
            "schedule_ics": "/api/public/adoption-plan/w07/schedule.ics",
            "coaching_playbook": "/api/public/adoption-plan/w07/coaching-playbook",
        },
    }


def _build_adoption_w07_checklist_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "section",
            "id",
            "cadence_or_trigger",
            "control_or_play",
            "owner",
            "target_or_expected_impact",
            "definition_of_done_or_evidence",
            "api_ref",
        ]
    )
    for item in payload.get("sla_checklist", []):
        writer.writerow(
            [
                "sla_checklist",
                item.get("id", ""),
                item.get("cadence", ""),
                item.get("control", ""),
                item.get("owner_role", ""),
                item.get("target", ""),
                item.get("definition_of_done", ""),
                "",
            ]
        )
    for item in payload.get("coaching_plays", []):
        writer.writerow(
            [
                "coaching_play",
                item.get("id", ""),
                item.get("trigger", ""),
                item.get("play", ""),
                item.get("owner", ""),
                item.get("expected_impact", ""),
                item.get("evidence_hint", ""),
                item.get("api_ref", ""),
            ]
        )
    for item in payload.get("scheduled_events", []):
        writer.writerow(
            [
                "scheduled_event",
                item.get("id", ""),
                item.get("date", ""),
                item.get("title", ""),
                item.get("owner", ""),
                item.get("output", ""),
                f"{item.get('start_time', '')}-{item.get('end_time', '')}",
                "",
            ]
        )
    return out.getvalue()


def _build_adoption_w07_schedule_ics(payload: dict[str, Any]) -> str:
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    events: list[str] = []
    for item in payload.get("scheduled_events", []):
        date_raw = str(item.get("date", ""))
        start_raw = str(item.get("start_time", "09:00"))
        end_raw = str(item.get("end_time", "10:00"))
        try:
            start_dt = datetime.strptime(f"{date_raw} {start_raw}", "%Y-%m-%d %H:%M")
            end_dt = datetime.strptime(f"{date_raw} {end_raw}", "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        uid = f"ka-facility-os-w07-{str(item.get('id', '')).lower()}@public"
        summary = f"[W07] {str(item.get('title', 'SLA Quality Session'))}"
        description = "\n".join(
            [
                f"Owner: {str(item.get('owner', ''))}",
                f"Output: {str(item.get('output', ''))}",
            ]
        )
        events.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{dtstamp}",
                f"DTSTART:{start_dt.strftime('%Y%m%dT%H%M%S')}",
                f"DTEND:{end_dt.strftime('%Y%m%dT%H%M%S')}",
                f"SUMMARY:{_ics_escape(summary)}",
                f"DESCRIPTION:{_ics_escape(description)}",
                "END:VEVENT",
            ]
        )

    calendar_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KA Facility OS//W07 SLA Quality//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    calendar_lines.extend(events)
    calendar_lines.append("END:VCALENDAR")
    return "\r\n".join(calendar_lines) + "\r\n"


def _adoption_w08_payload() -> dict[str, Any]:
    week_item = next(
        (item for item in ADOPTION_WEEKLY_EXECUTION if int(item.get("week", 0)) == 8),
        None,
    )
    if week_item is None:
        timeline = {
            "week": 8,
            "start_date": "",
            "end_date": "",
            "phase": "Habit",
            "focus": "Report discipline",
        }
    else:
        timeline = {
            "week": int(week_item.get("week", 8)),
            "start_date": str(week_item.get("start_date", "")),
            "end_date": str(week_item.get("end_date", "")),
            "phase": str(week_item.get("phase", "")),
            "focus": str(week_item.get("focus", "")),
            "owner": str(week_item.get("owner", "")),
            "success_metric": str(week_item.get("success_metric", "")),
        }

    return {
        "title": "W08 Report Discipline Pack",
        "public": True,
        "timeline": timeline,
        "report_discipline_checklist": ADOPTION_W08_REPORT_DISCIPLINE_CHECKLIST,
        "data_quality_controls": ADOPTION_W08_DATA_QUALITY_CONTROLS,
        "scheduled_events": ADOPTION_W08_SCHEDULED_EVENTS,
        "reporting_sop": ADOPTION_W08_REPORTING_SOP,
        "report_discipline_api": "/api/ops/adoption/w08/report-discipline",
        "site_benchmark_api": "/api/ops/adoption/w08/site-benchmark",
        "downloads": {
            "json": "/api/public/adoption-plan/w08",
            "checklist_csv": "/api/public/adoption-plan/w08/checklist.csv",
            "schedule_ics": "/api/public/adoption-plan/w08/schedule.ics",
            "reporting_sop": "/api/public/adoption-plan/w08/reporting-sop",
        },
    }


def _build_adoption_w08_checklist_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "section",
            "id",
            "cadence_or_control",
            "discipline_or_objective",
            "owner_or_api_ref",
            "target_or_pass_criteria",
            "definition_of_done_or_evidence",
            "api_ref",
        ]
    )
    for item in payload.get("report_discipline_checklist", []):
        writer.writerow(
            [
                "report_discipline",
                item.get("id", ""),
                item.get("cadence", ""),
                item.get("discipline", ""),
                item.get("owner_role", ""),
                item.get("target", ""),
                item.get("definition_of_done", ""),
                item.get("api_ref", ""),
            ]
        )
    for item in payload.get("data_quality_controls", []):
        writer.writerow(
            [
                "data_quality_control",
                item.get("id", ""),
                item.get("control", ""),
                item.get("objective", ""),
                item.get("api_ref", ""),
                item.get("pass_criteria", ""),
                "",
                item.get("api_ref", ""),
            ]
        )
    for item in payload.get("scheduled_events", []):
        writer.writerow(
            [
                "scheduled_event",
                item.get("id", ""),
                item.get("date", ""),
                item.get("title", ""),
                item.get("owner", ""),
                item.get("output", ""),
                f"{item.get('start_time', '')}-{item.get('end_time', '')}",
                "",
            ]
        )
    return out.getvalue()


def _build_adoption_w08_schedule_ics(payload: dict[str, Any]) -> str:
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    events: list[str] = []
    for item in payload.get("scheduled_events", []):
        date_raw = str(item.get("date", ""))
        start_raw = str(item.get("start_time", "09:00"))
        end_raw = str(item.get("end_time", "10:00"))
        try:
            start_dt = datetime.strptime(f"{date_raw} {start_raw}", "%Y-%m-%d %H:%M")
            end_dt = datetime.strptime(f"{date_raw} {end_raw}", "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        uid = f"ka-facility-os-w08-{str(item.get('id', '')).lower()}@public"
        summary = f"[W08] {str(item.get('title', 'Report Discipline Session'))}"
        description = "\n".join(
            [
                f"Owner: {str(item.get('owner', ''))}",
                f"Output: {str(item.get('output', ''))}",
            ]
        )
        events.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{dtstamp}",
                f"DTSTART:{start_dt.strftime('%Y%m%dT%H%M%S')}",
                f"DTEND:{end_dt.strftime('%Y%m%dT%H%M%S')}",
                f"SUMMARY:{_ics_escape(summary)}",
                f"DESCRIPTION:{_ics_escape(description)}",
                "END:VEVENT",
            ]
        )

    calendar_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KA Facility OS//W08 Report Discipline//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    calendar_lines.extend(events)
    calendar_lines.append("END:VCALENDAR")
    return "\r\n".join(calendar_lines) + "\r\n"


def _adoption_w09_payload() -> dict[str, Any]:
    week_item = next(
        (item for item in ADOPTION_WEEKLY_EXECUTION if int(item.get("week", 0)) == 9),
        None,
    )
    if week_item is None:
        timeline = {
            "week": 9,
            "start_date": "",
            "end_date": "",
            "phase": "Autonomy",
            "focus": "Shift to KPI operation",
        }
    else:
        timeline = {
            "week": int(week_item.get("week", 9)),
            "start_date": str(week_item.get("start_date", "")),
            "end_date": str(week_item.get("end_date", "")),
            "phase": str(week_item.get("phase", "")),
            "focus": str(week_item.get("focus", "")),
            "owner": str(week_item.get("owner", "")),
            "success_metric": str(week_item.get("success_metric", "")),
        }
    return {
        "title": "W09 KPI Operation Pack",
        "public": True,
        "timeline": timeline,
        "kpi_threshold_matrix": ADOPTION_W09_KPI_THRESHOLD_MATRIX,
        "escalation_map": ADOPTION_W09_ESCALATION_MAP,
        "scheduled_events": ADOPTION_W09_SCHEDULED_EVENTS,
        "kpi_operation_api": "/api/ops/adoption/w09/kpi-operation",
        "kpi_policy_api": "/api/ops/adoption/w09/kpi-policy",
        "tracker_items_api": "/api/adoption/w09/tracker/items",
        "tracker_overview_api": "/api/adoption/w09/tracker/overview",
        "downloads": {
            "json": "/api/public/adoption-plan/w09",
            "checklist_csv": "/api/public/adoption-plan/w09/checklist.csv",
            "schedule_ics": "/api/public/adoption-plan/w09/schedule.ics",
        },
    }


def _build_adoption_w09_checklist_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "section",
            "id",
            "kpi_or_event_key",
            "name_or_title",
            "owner_or_escalate_to",
            "direction_or_condition",
            "green_or_sla_hours",
            "yellow_or_action",
            "target_or_output",
            "source_or_time",
        ]
    )
    for item in payload.get("kpi_threshold_matrix", []):
        writer.writerow(
            [
                "kpi_threshold",
                item.get("id", ""),
                item.get("kpi_key", ""),
                item.get("kpi_name", ""),
                item.get("owner_role", ""),
                item.get("direction", ""),
                item.get("green_threshold", ""),
                item.get("yellow_threshold", ""),
                item.get("target", ""),
                item.get("source_api", ""),
            ]
        )
    for item in payload.get("escalation_map", []):
        writer.writerow(
            [
                "escalation_map",
                item.get("id", ""),
                item.get("kpi_key", ""),
                "",
                item.get("escalate_to", ""),
                item.get("condition", ""),
                item.get("sla_hours", ""),
                item.get("action", ""),
                "",
                "",
            ]
        )
    for item in payload.get("scheduled_events", []):
        writer.writerow(
            [
                "scheduled_event",
                item.get("id", ""),
                "",
                item.get("title", ""),
                item.get("owner", ""),
                "",
                "",
                "",
                item.get("output", ""),
                f"{item.get('date', '')} {item.get('start_time', '')}-{item.get('end_time', '')}",
            ]
        )
    return out.getvalue()


def _build_adoption_w09_schedule_ics(payload: dict[str, Any]) -> str:
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    events: list[str] = []
    for item in payload.get("scheduled_events", []):
        date_raw = str(item.get("date", ""))
        start_raw = str(item.get("start_time", "09:00"))
        end_raw = str(item.get("end_time", "10:00"))
        try:
            start_dt = datetime.strptime(f"{date_raw} {start_raw}", "%Y-%m-%d %H:%M")
            end_dt = datetime.strptime(f"{date_raw} {end_raw}", "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        uid = f"ka-facility-os-w09-{str(item.get('id', '')).lower()}@public"
        summary = f"[W09] {str(item.get('title', 'KPI Operation Session'))}"
        description = "\n".join(
            [
                f"Owner: {str(item.get('owner', ''))}",
                f"Output: {str(item.get('output', ''))}",
            ]
        )
        events.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{dtstamp}",
                f"DTSTART:{start_dt.strftime('%Y%m%dT%H%M%S')}",
                f"DTEND:{end_dt.strftime('%Y%m%dT%H%M%S')}",
                f"SUMMARY:{_ics_escape(summary)}",
                f"DESCRIPTION:{_ics_escape(description)}",
                "END:VEVENT",
            ]
        )

    calendar_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KA Facility OS//W09 KPI Operation//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    calendar_lines.extend(events)
    calendar_lines.append("END:VCALENDAR")
    return "\r\n".join(calendar_lines) + "\r\n"


def _adoption_w10_payload() -> dict[str, Any]:
    week_item = next(
        (item for item in ADOPTION_WEEKLY_EXECUTION if int(item.get("week", 0)) == 10),
        None,
    )
    if week_item is None:
        timeline = {
            "week": 10,
            "start_date": "",
            "end_date": "",
            "phase": "Autonomy",
            "focus": "Self-serve support",
        }
    else:
        timeline = {
            "week": int(week_item.get("week", 10)),
            "start_date": str(week_item.get("start_date", "")),
            "end_date": str(week_item.get("end_date", "")),
            "phase": str(week_item.get("phase", "")),
            "focus": str(week_item.get("focus", "")),
            "owner": str(week_item.get("owner", "")),
            "success_metric": str(week_item.get("success_metric", "")),
        }

    return {
        "title": "W10 Self-serve Support Pack",
        "public": True,
        "timeline": timeline,
        "self_serve_guides": ADOPTION_W10_SELF_SERVE_GUIDES,
        "troubleshooting_runbook": ADOPTION_W10_TROUBLESHOOTING_RUNBOOK,
        "scheduled_events": ADOPTION_W10_SCHEDULED_EVENTS,
        "self_serve_api": "/api/ops/adoption/w10/self-serve",
        "support_policy_api": "/api/ops/adoption/w10/support-policy",
        "tracker_items_api": "/api/adoption/w10/tracker/items",
        "tracker_overview_api": "/api/adoption/w10/tracker/overview",
        "downloads": {
            "json": "/api/public/adoption-plan/w10",
            "checklist_csv": "/api/public/adoption-plan/w10/checklist.csv",
            "schedule_ics": "/api/public/adoption-plan/w10/schedule.ics",
        },
    }


def _build_adoption_w10_checklist_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "section",
            "id",
            "key_or_module",
            "name_or_symptom",
            "owner_role",
            "objective_or_target",
            "definition_or_output",
            "api_or_time",
        ]
    )
    for item in payload.get("self_serve_guides", []):
        writer.writerow(
            [
                "self_serve_guide",
                item.get("id", ""),
                item.get("problem_cluster", ""),
                item.get("title", ""),
                item.get("owner_role", ""),
                item.get("target", ""),
                "",
                item.get("source_api", ""),
            ]
        )
    for item in payload.get("troubleshooting_runbook", []):
        writer.writerow(
            [
                "troubleshooting_runbook",
                item.get("id", ""),
                item.get("module", ""),
                item.get("symptom", ""),
                item.get("owner_role", ""),
                "",
                item.get("definition_of_done", ""),
                item.get("api_ref", ""),
            ]
        )
    for item in payload.get("scheduled_events", []):
        writer.writerow(
            [
                "scheduled_event",
                item.get("id", ""),
                "",
                item.get("title", ""),
                item.get("owner", ""),
                "",
                item.get("output", ""),
                f"{item.get('date', '')} {item.get('start_time', '')}-{item.get('end_time', '')}",
            ]
        )
    return out.getvalue()


def _build_adoption_w10_schedule_ics(payload: dict[str, Any]) -> str:
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    events: list[str] = []
    for item in payload.get("scheduled_events", []):
        date_raw = str(item.get("date", ""))
        start_raw = str(item.get("start_time", "09:00"))
        end_raw = str(item.get("end_time", "10:00"))
        try:
            start_dt = datetime.strptime(f"{date_raw} {start_raw}", "%Y-%m-%d %H:%M")
            end_dt = datetime.strptime(f"{date_raw} {end_raw}", "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        uid = f"ka-facility-os-w10-{str(item.get('id', '')).lower()}@public"
        summary = f"[W10] {str(item.get('title', 'Self-serve Support Session'))}"
        description = "\n".join(
            [
                f"Owner: {str(item.get('owner', ''))}",
                f"Output: {str(item.get('output', ''))}",
            ]
        )
        events.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{dtstamp}",
                f"DTSTART:{start_dt.strftime('%Y%m%dT%H%M%S')}",
                f"DTEND:{end_dt.strftime('%Y%m%dT%H%M%S')}",
                f"SUMMARY:{_ics_escape(summary)}",
                f"DESCRIPTION:{_ics_escape(description)}",
                "END:VEVENT",
            ]
        )

    calendar_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KA Facility OS//W10 Self-serve Support//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    calendar_lines.extend(events)
    calendar_lines.append("END:VCALENDAR")
    return "\r\n".join(calendar_lines) + "\r\n"



def _adoption_w11_payload() -> dict[str, Any]:
    week_item = next(
        (item for item in ADOPTION_WEEKLY_EXECUTION if int(item.get("week", 0)) == 11),
        None,
    )
    if week_item is None:
        timeline = {
            "week": 11,
            "start_date": "",
            "end_date": "",
            "phase": "Autonomy",
            "focus": "Scale readiness",
        }
    else:
        timeline = {
            "week": int(week_item.get("week", 11)),
            "start_date": str(week_item.get("start_date", "")),
            "end_date": str(week_item.get("end_date", "")),
            "phase": str(week_item.get("phase", "")),
            "focus": str(week_item.get("focus", "")),
            "owner": str(week_item.get("owner", "")),
            "success_metric": str(week_item.get("success_metric", "")),
        }

    return {
        "title": "W11 Scale Readiness Pack",
        "public": True,
        "timeline": timeline,
        "self_serve_guides": ADOPTION_W11_SELF_SERVE_GUIDES,
        "troubleshooting_runbook": ADOPTION_W11_TROUBLESHOOTING_RUNBOOK,
        "scheduled_events": ADOPTION_W11_SCHEDULED_EVENTS,
        "scale_readiness_api": "/api/ops/adoption/w11/scale-readiness",
        "readiness_policy_api": "/api/ops/adoption/w11/readiness-policy",
        "tracker_items_api": "/api/adoption/w11/tracker/items",
        "tracker_overview_api": "/api/adoption/w11/tracker/overview",
        "downloads": {
            "json": "/api/public/adoption-plan/w11",
            "checklist_csv": "/api/public/adoption-plan/w11/checklist.csv",
            "schedule_ics": "/api/public/adoption-plan/w11/schedule.ics",
        },
    }


def _build_adoption_w11_checklist_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "section",
            "id",
            "key_or_module",
            "name_or_symptom",
            "owner_role",
            "objective_or_target",
            "definition_or_output",
            "api_or_time",
        ]
    )
    for item in payload.get("self_serve_guides", []):
        writer.writerow(
            [
                "self_serve_guide",
                item.get("id", ""),
                item.get("problem_cluster", ""),
                item.get("title", ""),
                item.get("owner_role", ""),
                item.get("target", ""),
                "",
                item.get("source_api", ""),
            ]
        )
    for item in payload.get("troubleshooting_runbook", []):
        writer.writerow(
            [
                "troubleshooting_runbook",
                item.get("id", ""),
                item.get("module", ""),
                item.get("symptom", ""),
                item.get("owner_role", ""),
                "",
                item.get("definition_of_done", ""),
                item.get("api_ref", ""),
            ]
        )
    for item in payload.get("scheduled_events", []):
        writer.writerow(
            [
                "scheduled_event",
                item.get("id", ""),
                "",
                item.get("title", ""),
                item.get("owner", ""),
                "",
                item.get("output", ""),
                f"{item.get('date', '')} {item.get('start_time', '')}-{item.get('end_time', '')}",
            ]
        )
    return out.getvalue()


def _build_adoption_w11_schedule_ics(payload: dict[str, Any]) -> str:
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    events: list[str] = []
    for item in payload.get("scheduled_events", []):
        date_raw = str(item.get("date", ""))
        start_raw = str(item.get("start_time", "09:00"))
        end_raw = str(item.get("end_time", "10:00"))
        try:
            start_dt = datetime.strptime(f"{date_raw} {start_raw}", "%Y-%m-%d %H:%M")
            end_dt = datetime.strptime(f"{date_raw} {end_raw}", "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        uid = f"ka-facility-os-w11-{str(item.get('id', '')).lower()}@public"
        summary = f"[W11] {str(item.get('title', 'Scale Readiness Session'))}"
        description = "\n".join(
            [
                f"Owner: {str(item.get('owner', ''))}",
                f"Output: {str(item.get('output', ''))}",
            ]
        )
        events.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{dtstamp}",
                f"DTSTART:{start_dt.strftime('%Y%m%dT%H%M%S')}",
                f"DTEND:{end_dt.strftime('%Y%m%dT%H%M%S')}",
                f"SUMMARY:{_ics_escape(summary)}",
                f"DESCRIPTION:{_ics_escape(description)}",
                "END:VEVENT",
            ]
        )

    calendar_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KA Facility OS//W11 Scale Readiness//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    calendar_lines.extend(events)
    calendar_lines.append("END:VCALENDAR")
    return "\r\n".join(calendar_lines) + "\r\n"


def _adoption_w12_payload() -> dict[str, Any]:
    week_item = next(
        (item for item in ADOPTION_WEEKLY_EXECUTION if int(item.get("week", 0)) == 12),
        None,
    )
    if week_item is None:
        timeline = {
            "week": 12,
            "start_date": "",
            "end_date": "",
            "phase": "Autonomy",
            "focus": "Closure and handoff",
        }
    else:
        timeline = {
            "week": int(week_item.get("week", 12)),
            "start_date": str(week_item.get("start_date", "")),
            "end_date": str(week_item.get("end_date", "")),
            "phase": str(week_item.get("phase", "")),
            "focus": str(week_item.get("focus", "")),
            "owner": str(week_item.get("owner", "")),
            "success_metric": str(week_item.get("success_metric", "")),
        }

    return {
        "title": "W12 Closure and Handoff Pack",
        "public": True,
        "timeline": timeline,
        "self_serve_guides": ADOPTION_W12_SELF_SERVE_GUIDES,
        "troubleshooting_runbook": ADOPTION_W12_TROUBLESHOOTING_RUNBOOK,
        "scheduled_events": ADOPTION_W12_SCHEDULED_EVENTS,
        "closure_handoff_api": "/api/ops/adoption/w12/closure-handoff",
        "handoff_policy_api": "/api/ops/adoption/w12/handoff-policy",
        "tracker_items_api": "/api/adoption/w12/tracker/items",
        "tracker_overview_api": "/api/adoption/w12/tracker/overview",
        "downloads": {
            "json": "/api/public/adoption-plan/w12",
            "checklist_csv": "/api/public/adoption-plan/w12/checklist.csv",
            "schedule_ics": "/api/public/adoption-plan/w12/schedule.ics",
        },
    }


def _build_adoption_w12_checklist_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "section",
            "id",
            "key_or_module",
            "name_or_symptom",
            "owner_role",
            "objective_or_target",
            "definition_or_output",
            "api_or_time",
        ]
    )
    for item in payload.get("self_serve_guides", []):
        writer.writerow(
            [
                "self_serve_guide",
                item.get("id", ""),
                item.get("problem_cluster", ""),
                item.get("title", ""),
                item.get("owner_role", ""),
                item.get("target", ""),
                "",
                item.get("source_api", ""),
            ]
        )
    for item in payload.get("troubleshooting_runbook", []):
        writer.writerow(
            [
                "troubleshooting_runbook",
                item.get("id", ""),
                item.get("module", ""),
                item.get("symptom", ""),
                item.get("owner_role", ""),
                "",
                item.get("definition_of_done", ""),
                item.get("api_ref", ""),
            ]
        )
    for item in payload.get("scheduled_events", []):
        writer.writerow(
            [
                "scheduled_event",
                item.get("id", ""),
                "",
                item.get("title", ""),
                item.get("owner", ""),
                "",
                item.get("output", ""),
                f"{item.get('date', '')} {item.get('start_time', '')}-{item.get('end_time', '')}",
            ]
        )
    return out.getvalue()


def _build_adoption_w12_schedule_ics(payload: dict[str, Any]) -> str:
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    events: list[str] = []
    for item in payload.get("scheduled_events", []):
        date_raw = str(item.get("date", ""))
        start_raw = str(item.get("start_time", "09:00"))
        end_raw = str(item.get("end_time", "10:00"))
        try:
            start_dt = datetime.strptime(f"{date_raw} {start_raw}", "%Y-%m-%d %H:%M")
            end_dt = datetime.strptime(f"{date_raw} {end_raw}", "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        uid = f"ka-facility-os-w12-{str(item.get('id', '')).lower()}@public"
        summary = f"[W12] {str(item.get('title', 'Closure and Handoff Session'))}"
        description = "\n".join(
            [
                f"Owner: {str(item.get('owner', ''))}",
                f"Output: {str(item.get('output', ''))}",
            ]
        )
        events.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{dtstamp}",
                f"DTSTART:{start_dt.strftime('%Y%m%dT%H%M%S')}",
                f"DTEND:{end_dt.strftime('%Y%m%dT%H%M%S')}",
                f"SUMMARY:{_ics_escape(summary)}",
                f"DESCRIPTION:{_ics_escape(description)}",
                "END:VEVENT",
            ]
        )

    calendar_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KA Facility OS//W12 Closure and Handoff//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    calendar_lines.extend(events)
    calendar_lines.append("END:VCALENDAR")
    return "\r\n".join(calendar_lines) + "\r\n"



def _adoption_w13_payload() -> dict[str, Any]:
    week_item = next(
        (item for item in ADOPTION_WEEKLY_EXECUTION if int(item.get("week", 0)) == 13),
        None,
    )
    if week_item is None:
        timeline = {
            "week": 13,
            "start_date": "",
            "end_date": "",
            "phase": "Autonomy",
            "focus": "Continuous improvement",
        }
    else:
        timeline = {
            "week": int(week_item.get("week", 13)),
            "start_date": str(week_item.get("start_date", "")),
            "end_date": str(week_item.get("end_date", "")),
            "phase": str(week_item.get("phase", "")),
            "focus": str(week_item.get("focus", "")),
            "owner": str(week_item.get("owner", "")),
            "success_metric": str(week_item.get("success_metric", "")),
        }

    return {
        "title": "W13 Continuous Improvement Pack",
        "public": True,
        "timeline": timeline,
        "self_serve_guides": ADOPTION_W13_SELF_SERVE_GUIDES,
        "troubleshooting_runbook": ADOPTION_W13_TROUBLESHOOTING_RUNBOOK,
        "scheduled_events": ADOPTION_W13_SCHEDULED_EVENTS,
        "closure_handoff_api": "/api/ops/adoption/w13/closure-handoff",
        "handoff_policy_api": "/api/ops/adoption/w13/handoff-policy",
        "tracker_items_api": "/api/adoption/w13/tracker/items",
        "tracker_overview_api": "/api/adoption/w13/tracker/overview",
        "downloads": {
            "json": "/api/public/adoption-plan/w13",
            "checklist_csv": "/api/public/adoption-plan/w13/checklist.csv",
            "schedule_ics": "/api/public/adoption-plan/w13/schedule.ics",
        },
    }


def _build_adoption_w13_checklist_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "section",
            "id",
            "key_or_module",
            "name_or_symptom",
            "owner_role",
            "objective_or_target",
            "definition_or_output",
            "api_or_time",
        ]
    )
    for item in payload.get("self_serve_guides", []):
        writer.writerow(
            [
                "self_serve_guide",
                item.get("id", ""),
                item.get("problem_cluster", ""),
                item.get("title", ""),
                item.get("owner_role", ""),
                item.get("target", ""),
                "",
                item.get("source_api", ""),
            ]
        )
    for item in payload.get("troubleshooting_runbook", []):
        writer.writerow(
            [
                "troubleshooting_runbook",
                item.get("id", ""),
                item.get("module", ""),
                item.get("symptom", ""),
                item.get("owner_role", ""),
                "",
                item.get("definition_of_done", ""),
                item.get("api_ref", ""),
            ]
        )
    for item in payload.get("scheduled_events", []):
        writer.writerow(
            [
                "scheduled_event",
                item.get("id", ""),
                "",
                item.get("title", ""),
                item.get("owner", ""),
                "",
                item.get("output", ""),
                f"{item.get('date', '')} {item.get('start_time', '')}-{item.get('end_time', '')}",
            ]
        )
    return out.getvalue()


def _build_adoption_w13_schedule_ics(payload: dict[str, Any]) -> str:
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    events: list[str] = []
    for item in payload.get("scheduled_events", []):
        date_raw = str(item.get("date", ""))
        start_raw = str(item.get("start_time", "09:00"))
        end_raw = str(item.get("end_time", "10:00"))
        try:
            start_dt = datetime.strptime(f"{date_raw} {start_raw}", "%Y-%m-%d %H:%M")
            end_dt = datetime.strptime(f"{date_raw} {end_raw}", "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        uid = f"ka-facility-os-w13-{str(item.get('id', '')).lower()}@public"
        summary = f"[W13] {str(item.get('title', 'Continuous Improvement Session'))}"
        description = "\n".join(
            [
                f"Owner: {str(item.get('owner', ''))}",
                f"Output: {str(item.get('output', ''))}",
            ]
        )
        events.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{dtstamp}",
                f"DTSTART:{start_dt.strftime('%Y%m%dT%H%M%S')}",
                f"DTEND:{end_dt.strftime('%Y%m%dT%H%M%S')}",
                f"SUMMARY:{_ics_escape(summary)}",
                f"DESCRIPTION:{_ics_escape(description)}",
                "END:VEVENT",
            ]
        )

    calendar_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KA Facility OS//W13 Continuous Improvement//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    calendar_lines.extend(events)
    calendar_lines.append("END:VCALENDAR")
    return "\r\n".join(calendar_lines) + "\r\n"


def _adoption_w14_payload() -> dict[str, Any]:
    week_item = next(
        (item for item in ADOPTION_WEEKLY_EXECUTION if int(item.get("week", 0)) == 14),
        None,
    )
    if week_item is None:
        timeline = {
            "week": 14,
            "start_date": "",
            "end_date": "",
            "phase": "Stabilize",
            "focus": "Stability sprint",
        }
    else:
        timeline = {
            "week": int(week_item.get("week", 14)),
            "start_date": str(week_item.get("start_date", "")),
            "end_date": str(week_item.get("end_date", "")),
            "phase": str(week_item.get("phase", "")),
            "focus": str(week_item.get("focus", "")),
            "owner": str(week_item.get("owner", "")),
            "success_metric": str(week_item.get("success_metric", "")),
        }

    return {
        "title": "W14 Stability Sprint Pack",
        "public": True,
        "timeline": timeline,
        "self_serve_guides": ADOPTION_W14_SELF_SERVE_GUIDES,
        "troubleshooting_runbook": ADOPTION_W14_TROUBLESHOOTING_RUNBOOK,
        "scheduled_events": ADOPTION_W14_SCHEDULED_EVENTS,
        "stability_sprint_api": "/api/ops/adoption/w14/stability-sprint",
        "stability_policy_api": "/api/ops/adoption/w14/stability-policy",
        "tracker_items_api": "/api/adoption/w14/tracker/items",
        "tracker_overview_api": "/api/adoption/w14/tracker/overview",
        "downloads": {
            "json": "/api/public/adoption-plan/w14",
            "checklist_csv": "/api/public/adoption-plan/w14/checklist.csv",
            "schedule_ics": "/api/public/adoption-plan/w14/schedule.ics",
        },
    }


def _build_adoption_w14_checklist_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "section",
            "id",
            "key_or_module",
            "name_or_symptom",
            "owner_role",
            "objective_or_target",
            "definition_or_output",
            "api_or_time",
        ]
    )
    for item in payload.get("self_serve_guides", []):
        writer.writerow(
            [
                "self_serve_guide",
                item.get("id", ""),
                item.get("problem_cluster", ""),
                item.get("title", ""),
                item.get("owner_role", ""),
                item.get("target", ""),
                "",
                item.get("source_api", ""),
            ]
        )
    for item in payload.get("troubleshooting_runbook", []):
        writer.writerow(
            [
                "troubleshooting_runbook",
                item.get("id", ""),
                item.get("module", ""),
                item.get("symptom", ""),
                item.get("owner_role", ""),
                "",
                item.get("definition_of_done", ""),
                item.get("api_ref", ""),
            ]
        )
    for item in payload.get("scheduled_events", []):
        writer.writerow(
            [
                "scheduled_event",
                item.get("id", ""),
                "",
                item.get("title", ""),
                item.get("owner", ""),
                "",
                item.get("output", ""),
                f"{item.get('date', '')} {item.get('start_time', '')}-{item.get('end_time', '')}",
            ]
        )
    return out.getvalue()


def _build_adoption_w14_schedule_ics(payload: dict[str, Any]) -> str:
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    events: list[str] = []
    for item in payload.get("scheduled_events", []):
        date_raw = str(item.get("date", ""))
        start_raw = str(item.get("start_time", "09:00"))
        end_raw = str(item.get("end_time", "10:00"))
        try:
            start_dt = datetime.strptime(f"{date_raw} {start_raw}", "%Y-%m-%d %H:%M")
            end_dt = datetime.strptime(f"{date_raw} {end_raw}", "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        uid = f"ka-facility-os-w14-{str(item.get('id', '')).lower()}@public"
        summary = f"[W14] {str(item.get('title', 'Stability Sprint Session'))}"
        description = "\n".join(
            [
                f"Owner: {str(item.get('owner', ''))}",
                f"Output: {str(item.get('output', ''))}",
            ]
        )
        events.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{dtstamp}",
                f"DTSTART:{start_dt.strftime('%Y%m%dT%H%M%S')}",
                f"DTEND:{end_dt.strftime('%Y%m%dT%H%M%S')}",
                f"SUMMARY:{_ics_escape(summary)}",
                f"DESCRIPTION:{_ics_escape(description)}",
                "END:VEVENT",
            ]
        )

    calendar_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KA Facility OS//W14 Stability Sprint//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    calendar_lines.extend(events)
    calendar_lines.append("END:VCALENDAR")
    return "\r\n".join(calendar_lines) + "\r\n"




def _adoption_w15_payload() -> dict[str, Any]:
    week_item = next(
        (item for item in ADOPTION_WEEKLY_EXECUTION if int(item.get("week", 0)) == 15),
        None,
    )
    if week_item is None:
        timeline = {
            "week": 15,
            "start_date": "",
            "end_date": "",
            "phase": "Optimize",
            "focus": "Operations efficiency",
        }
    else:
        timeline = {
            "week": int(week_item.get("week", 15)),
            "start_date": str(week_item.get("start_date", "")),
            "end_date": str(week_item.get("end_date", "")),
            "phase": str(week_item.get("phase", "")),
            "focus": str(week_item.get("focus", "")),
            "owner": str(week_item.get("owner", "")),
            "success_metric": str(week_item.get("success_metric", "")),
        }

    return {
        "title": "W15 Operations Efficiency Pack",
        "public": True,
        "timeline": timeline,
        "self_serve_guides": ADOPTION_W15_SELF_SERVE_GUIDES,
        "troubleshooting_runbook": ADOPTION_W15_TROUBLESHOOTING_RUNBOOK,
        "scheduled_events": ADOPTION_W15_SCHEDULED_EVENTS,
        "ops_efficiency_api": "/api/ops/adoption/w15/ops-efficiency",
        "efficiency_policy_api": "/api/ops/adoption/w15/efficiency-policy",
        "tracker_items_api": "/api/adoption/w15/tracker/items",
        "tracker_overview_api": "/api/adoption/w15/tracker/overview",
        "downloads": {
            "json": "/api/public/adoption-plan/w15",
            "checklist_csv": "/api/public/adoption-plan/w15/checklist.csv",
            "schedule_ics": "/api/public/adoption-plan/w15/schedule.ics",
        },
    }


def _build_adoption_w15_checklist_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "section",
            "id",
            "key_or_module",
            "name_or_symptom",
            "owner_role",
            "objective_or_target",
            "definition_or_output",
            "api_or_time",
        ]
    )
    for item in payload.get("self_serve_guides", []):
        writer.writerow(
            [
                "self_serve_guide",
                item.get("id", ""),
                item.get("problem_cluster", ""),
                item.get("title", ""),
                item.get("owner_role", ""),
                item.get("target", ""),
                "",
                item.get("source_api", ""),
            ]
        )
    for item in payload.get("troubleshooting_runbook", []):
        writer.writerow(
            [
                "troubleshooting_runbook",
                item.get("id", ""),
                item.get("module", ""),
                item.get("symptom", ""),
                item.get("owner_role", ""),
                "",
                item.get("definition_of_done", ""),
                item.get("api_ref", ""),
            ]
        )
    for item in payload.get("scheduled_events", []):
        writer.writerow(
            [
                "scheduled_event",
                item.get("id", ""),
                "",
                item.get("title", ""),
                item.get("owner", ""),
                "",
                item.get("output", ""),
                f"{item.get('date', '')} {item.get('start_time', '')}-{item.get('end_time', '')}",
            ]
        )
    return out.getvalue()


def _build_adoption_w15_schedule_ics(payload: dict[str, Any]) -> str:
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    events: list[str] = []
    for item in payload.get("scheduled_events", []):
        date_raw = str(item.get("date", ""))
        start_raw = str(item.get("start_time", "09:00"))
        end_raw = str(item.get("end_time", "10:00"))
        try:
            start_dt = datetime.strptime(f"{date_raw} {start_raw}", "%Y-%m-%d %H:%M")
            end_dt = datetime.strptime(f"{date_raw} {end_raw}", "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        uid = f"ka-facility-os-w15-{str(item.get('id', '')).lower()}@public"
        summary = f"[W15] {str(item.get('title', 'Operations Efficiency Session'))}"
        description = "\n".join(
            [
                f"Owner: {str(item.get('owner', ''))}",
                f"Output: {str(item.get('output', ''))}",
            ]
        )
        events.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{dtstamp}",
                f"DTSTART:{start_dt.strftime('%Y%m%dT%H%M%S')}",
                f"DTEND:{end_dt.strftime('%Y%m%dT%H%M%S')}",
                f"SUMMARY:{_ics_escape(summary)}",
                f"DESCRIPTION:{_ics_escape(description)}",
                "END:VEVENT",
            ]
        )

    calendar_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KA Facility OS//W15 Operations Efficiency//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    calendar_lines.extend(events)
    calendar_lines.append("END:VCALENDAR")
    return "\r\n".join(calendar_lines) + "\r\n"






def _w02_sample_files_payload() -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for row in W02_SAMPLE_EVIDENCE_ARTIFACTS:
        sample_id = str(row.get("sample_id") or "").strip().lower()
        if not sample_id:
            continue
        items.append(
            {
                "sample_id": sample_id,
                "title": str(row.get("title") or ""),
                "description": str(row.get("description") or ""),
                "file_name": str(row.get("file_name") or f"{sample_id}.txt"),
                "content_type": str(row.get("content_type") or "text/plain"),
                "tracker_item_type": str(row.get("tracker_item_type") or ""),
                "tracker_item_key": str(row.get("tracker_item_key") or ""),
                "download_url": f"/api/public/adoption-plan/w02/sample-files/{sample_id}",
            }
        )

    return {
        "title": "W02 Sample Evidence Files",
        "public": True,
        "count": len(items),
        "items": items,
    }


def _find_w02_sample_file(sample_id: str) -> dict[str, Any] | None:
    normalized = sample_id.strip().lower()
    if not normalized:
        return None
    for row in W02_SAMPLE_EVIDENCE_ARTIFACTS:
        if str(row.get("sample_id") or "").strip().lower() == normalized:
            return row
    return None


def _build_adoption_w02_checklist_csv(payload: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "section",
            "id",
            "name",
            "owner",
            "target_or_module",
            "trigger_or_objective",
            "checkpoints_or_pass_criteria",
            "duration_min",
            "definition_of_done_or_output",
        ]
    )
    for item in payload.get("sop_runbooks", []):
        writer.writerow(
            [
                "sop_runbook",
                item.get("id", ""),
                item.get("name", ""),
                item.get("owner", ""),
                ", ".join(str(x) for x in item.get("target_roles", [])),
                item.get("trigger", ""),
                " | ".join(str(x) for x in item.get("checkpoints", [])),
                "",
                item.get("definition_of_done", ""),
            ]
        )
    for item in payload.get("sandbox_scenarios", []):
        writer.writerow(
            [
                "sandbox_scenario",
                item.get("id", ""),
                item.get("module", ""),
                "",
                item.get("module", ""),
                item.get("objective", ""),
                " | ".join(str(x) for x in item.get("pass_criteria", [])),
                item.get("duration_min", ""),
                " | ".join(str(x) for x in item.get("api_flow", [])),
            ]
        )
    for item in payload.get("scheduled_events", []):
        writer.writerow(
            [
                "scheduled_event",
                item.get("id", ""),
                item.get("title", ""),
                item.get("owner", ""),
                item.get("date", ""),
                f"{item.get('start_time', '')}-{item.get('end_time', '')}",
                "",
                "",
                item.get("output", ""),
            ]
        )
    return out.getvalue()


def _build_adoption_w02_schedule_ics(payload: dict[str, Any]) -> str:
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    events: list[str] = []
    for item in payload.get("scheduled_events", []):
        date_raw = str(item.get("date", ""))
        start_raw = str(item.get("start_time", "09:00"))
        end_raw = str(item.get("end_time", "10:00"))
        try:
            start_dt = datetime.strptime(f"{date_raw} {start_raw}", "%Y-%m-%d %H:%M")
            end_dt = datetime.strptime(f"{date_raw} {end_raw}", "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        uid = f"ka-facility-os-w02-{str(item.get('id', '')).lower()}@public"
        summary = f"[W02] {str(item.get('title', 'SOP/Sandbox Session'))}"
        description = "\n".join(
            [
                f"Owner: {str(item.get('owner', ''))}",
                f"Output: {str(item.get('output', ''))}",
            ]
        )
        events.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{dtstamp}",
                f"DTSTART:{start_dt.strftime('%Y%m%dT%H%M%S')}",
                f"DTEND:{end_dt.strftime('%Y%m%dT%H%M%S')}",
                f"SUMMARY:{_ics_escape(summary)}",
                f"DESCRIPTION:{_ics_escape(description)}",
                "END:VEVENT",
            ]
        )

    calendar_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KA Facility OS//W02 SOP Sandbox//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    calendar_lines.extend(events)
    calendar_lines.append("END:VCALENDAR")
    return "\r\n".join(calendar_lines) + "\r\n"


def _build_adoption_plan_schedule_csv(plan: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "week",
            "start_date",
            "end_date",
            "phase",
            "focus",
            "owner",
            "actions",
            "deliverables",
            "success_metric",
        ]
    )
    for item in plan.get("weekly_execution", []):
        actions = " | ".join(item.get("actions", []))
        deliverables = " | ".join(item.get("deliverables", []))
        writer.writerow(
            [
                item.get("week", ""),
                item.get("start_date", ""),
                item.get("end_date", ""),
                item.get("phase", ""),
                item.get("focus", ""),
                item.get("owner", ""),
                actions,
                deliverables,
                item.get("success_metric", ""),
            ]
        )
    return out.getvalue()


def _ics_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")


def _build_adoption_plan_schedule_ics(plan: dict[str, Any]) -> str:
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    events: list[str] = []

    for item in plan.get("weekly_execution", []):
        week_num = int(item.get("week", 0))
        week_start = date.fromisoformat(str(item.get("start_date")))
        focus = str(item.get("focus", ""))
        owner = str(item.get("owner", ""))
        success_metric = str(item.get("success_metric", ""))
        actions = [str(x) for x in item.get("actions", [])]

        checkpoints = [
            (0, "Kickoff"),
            (2, "Checkpoint"),
            (4, "Review"),
        ]
        for day_offset, checkpoint_label in checkpoints:
            event_date = week_start + timedelta(days=day_offset)
            event_end = event_date + timedelta(days=1)
            summary = f"[W{week_num:02d}] {checkpoint_label} - {focus}"
            description_lines = [
                f"Phase: {item.get('phase', '')}",
                f"Owner: {owner}",
                f"Success metric: {success_metric}",
            ]
            for action in actions[:3]:
                description_lines.append(f"- {action}")
            description = "\n".join(description_lines)

            uid = f"ka-facility-os-adoption-w{week_num:02d}-{checkpoint_label.lower()}@public"
            events.extend(
                [
                    "BEGIN:VEVENT",
                    f"UID:{uid}",
                    f"DTSTAMP:{dtstamp}",
                    f"DTSTART;VALUE=DATE:{event_date.strftime('%Y%m%d')}",
                    f"DTEND;VALUE=DATE:{event_end.strftime('%Y%m%d')}",
                    f"SUMMARY:{_ics_escape(summary)}",
                    f"DESCRIPTION:{_ics_escape(description)}",
                    "END:VEVENT",
                ]
            )

    calendar_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KA Facility OS//User Adoption Plan//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    calendar_lines.extend(events)
    calendar_lines.append("END:VCALENDAR")
    return "\r\n".join(calendar_lines) + "\r\n"


def _post_mvp_payload() -> dict[str, Any]:
    duration_weeks = sum(int(item.get("duration_weeks", 0)) for item in POST_MVP_ROADMAP_PHASES)
    return {
        "title": "KA Facility OS Post-MVP Execution Plan",
        "published_on": "2026-02-27",
        "public": True,
        "timeline": {
            "start_date": POST_MVP_PLAN_START.isoformat(),
            "end_date": POST_MVP_PLAN_END.isoformat(),
            "duration_weeks": duration_weeks,
        },
        "roadmap": POST_MVP_ROADMAP_PHASES,
        "execution_backlog": POST_MVP_EXECUTION_BACKLOG,
        "release_calendar": {
            "milestones": POST_MVP_RELEASE_MILESTONES,
            "downloads": {
                "backlog_csv": "/api/public/post-mvp/backlog.csv",
                "release_ics": "/api/public/post-mvp/releases.ics",
            },
        },
        "kpi_dashboard_spec": POST_MVP_KPI_DASHBOARD_SPEC,
        "risk_register": POST_MVP_RISK_REGISTER,
        "governance": {
            "weekly": "Monday execution sync + Friday KPI review",
            "bi_weekly": "Risk and dependency review board",
            "monthly": "Release readiness and budget steering committee",
            "quarterly": "Executive roadmap reprioritization",
        },
    }


def _facility_modules_payload() -> dict[str, Any]:
    return {
        "title": "KA Facility OS 시설 웹 모듈",
        "published_on": "2026-02-27",
        "public": True,
        "main_page": "/",
        "console_html": "/web/console",
        "modules": FACILITY_WEB_MODULES,
    }


def _get_tutorial_simulator_scenario(scenario_id: str) -> dict[str, Any] | None:
    lookup = scenario_id.strip().lower()
    for scenario in TUTORIAL_SIMULATOR_SCENARIOS:
        if str(scenario.get("id") or "").strip().lower() == lookup:
            return scenario
    return None


def _tutorial_simulator_sample_files_payload() -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for row in TUTORIAL_SIMULATOR_SAMPLE_FILES:
        sample_id = str(row.get("sample_id") or "").strip().lower()
        if not sample_id:
            continue
        items.append(
            {
                "sample_id": sample_id,
                "scenario_id": str(row.get("scenario_id") or ""),
                "title": str(row.get("title") or ""),
                "description": str(row.get("description") or ""),
                "file_name": str(row.get("file_name") or f"{sample_id}.txt"),
                "content_type": str(row.get("content_type") or "text/plain"),
                "download_url": f"/api/public/tutorial-simulator/sample-files/{sample_id}",
            }
        )

    return {
        "title": "Tutorial Simulator Verified 샘플 파일",
        "public": True,
        "validated_on": "2026-03-02",
        "verified_by": "ka-facility-os tutorial qa suite",
        "count": len(items),
        "items": items,
    }


def _find_tutorial_simulator_sample_file(sample_id: str) -> dict[str, Any] | None:
    normalized = sample_id.strip().lower()
    if not normalized:
        return None
    for row in TUTORIAL_SIMULATOR_SAMPLE_FILES:
        if str(row.get("sample_id") or "").strip().lower() == normalized:
            return row
    return None


def _build_tutorial_simulator_payload() -> dict[str, Any]:
    sample_files_pack = _tutorial_simulator_sample_files_payload()
    return {
        "title": "KA Facility OS Tutorial Simulator",
        "published_on": "2026-03-02",
        "public": True,
        "validated_on": "2026-03-02",
        "default_site": TUTORIAL_SIMULATOR_DEFAULT_SITE,
        "simulator_html": "/web/tutorial-simulator",
        "session_start_api": "/api/ops/tutorial-simulator/sessions/start",
        "session_list_api": "/api/ops/tutorial-simulator/sessions",
        "session_lookup_api": "/api/ops/tutorial-simulator/sessions/{session_id}",
        "session_action_api": "/api/ops/tutorial-simulator/sessions/{session_id}/actions/{action}",
        "session_check_api": "/api/ops/tutorial-simulator/sessions/{session_id}/check",
        "sample_files_api": "/api/public/tutorial-simulator/sample-files",
        "day1_onboarding_api": "/api/public/onboarding/day1",
        "glossary_api": "/api/public/glossary",
        "sample_files": sample_files_pack.get("items", []),
        "scenarios": TUTORIAL_SIMULATOR_SCENARIOS,
        "quickstart": {
            "title": "First Practice in 15 Minutes",
            "steps": [
                "1) owner/admin 토큰 입력 후 연결 확인",
                "2) 시나리오(ts-core-01) + site 입력 후 세션 시작",
                "3) ACK 실행 -> COMPLETE 실행",
                "4) 완료 판정(check)에서 completion_percent=100 확인",
                "5) 최근 세션 목록에서 결과 재조회",
            ],
            "definition_of_done": "progress.status=completed and completion_percent=100",
        },
        "usage": {
            "steps": [
                "1) Start session with scenario_id and site.",
                "2) Execute practice actions (ACK -> complete) with existing Work-Order APIs or simulator action API.",
                "3) Run session check and confirm completion_percent=100.",
            ],
            "verification": "All steps are validated against seeded IDs and current DB state.",
        },
    }


def _build_public_day1_onboarding_payload() -> dict[str, Any]:
    total_estimated_minutes = sum(
        max(0, int(step.get("estimated_minutes") or 0)) for step in PUBLIC_DAY1_ONBOARDING_STEPS
    )
    return {
        "title": "KA Facility OS 처음 1일 운영 체크리스트",
        "published_on": "2026-03-07",
        "public": True,
        "console_html": "/",
        "tutorial_simulator_html": "/web/tutorial-simulator",
        "tutorial_simulator_api": "/api/public/tutorial-simulator",
        "glossary_api": "/api/public/glossary",
        "checklist_count": len(PUBLIC_DAY1_ONBOARDING_STEPS),
        "role_guide_count": len(PUBLIC_ROLE_START_GUIDES),
        "total_estimated_minutes": total_estimated_minutes,
        "day1_checklist": PUBLIC_DAY1_ONBOARDING_STEPS,
        "role_guides": PUBLIC_ROLE_START_GUIDES,
    }


def _build_public_glossary_payload() -> dict[str, Any]:
    categories: list[dict[str, str]] = []
    seen_categories: set[str] = set()
    for item in PUBLIC_GLOSSARY_TERMS:
        category = str(item.get("category") or "").strip().lower()
        if not category or category in seen_categories:
            continue
        seen_categories.add(category)
        categories.append(
            {
                "id": category,
                "label": str(item.get("category_ko") or category),
            }
        )
    return {
        "title": "KA Facility OS 운영 용어집",
        "published_on": "2026-03-07",
        "public": True,
        "count": len(PUBLIC_GLOSSARY_TERMS),
        "categories": categories,
        "items": PUBLIC_GLOSSARY_TERMS,
    }


def _build_tutorial_simulator_html(payload: dict[str, Any]) -> str:
    return _web_build_tutorial_simulator_html(payload)


def _load_tutorial_simulator_session_row(session_id: int) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            select(job_runs)
            .where(job_runs.c.id == session_id)
            .where(job_runs.c.job_name == OPS_TUTORIAL_SIMULATOR_SESSION_JOB_NAME)
            .limit(1)
        ).mappings().first()
    return dict(row) if row is not None else None


def _list_tutorial_simulator_sessions(*, limit: int = 20) -> list[dict[str, Any]]:
    normalized_limit = max(1, min(int(limit), 100))
    with get_conn() as conn:
        rows = conn.execute(
            select(job_runs)
            .where(job_runs.c.job_name == OPS_TUTORIAL_SIMULATOR_SESSION_JOB_NAME)
            .order_by(job_runs.c.finished_at.desc(), job_runs.c.id.desc())
            .limit(normalized_limit)
        ).mappings().all()
    sessions: list[dict[str, Any]] = []
    for row in rows:
        model = _row_to_job_run_model(row)
        detail = model.detail if isinstance(model.detail, dict) else {}
        seed = detail.get("seed", {}) if isinstance(detail.get("seed"), dict) else {}
        sessions.append(
            {
                "session_id": model.id,
                "scenario_id": str(detail.get("scenario_id") or ""),
                "scenario_name": str(detail.get("scenario_name") or ""),
                "scenario_name_ko": str(detail.get("scenario_name_ko") or ""),
                "site": str(detail.get("site") or TUTORIAL_SIMULATOR_DEFAULT_SITE),
                "work_order_id": int(seed.get("work_order_id") or 0),
                "inspection_id": int(seed.get("inspection_id") or 0),
                "created_at": model.started_at.isoformat(),
            }
        )
    return sessions


def _evaluate_tutorial_simulator_session(*, session_id: int) -> dict[str, Any]:
    row = _load_tutorial_simulator_session_row(session_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Tutorial simulator session not found")
    model = _row_to_job_run_model(row)
    detail = model.detail if isinstance(model.detail, dict) else {}
    scenario_id = str(detail.get("scenario_id") or "")
    scenario = _get_tutorial_simulator_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Tutorial scenario not found")

    site = str(detail.get("site") or TUTORIAL_SIMULATOR_DEFAULT_SITE)
    seed = detail.get("seed", {}) if isinstance(detail.get("seed"), dict) else {}
    inspection_id = int(seed.get("inspection_id") or 0)
    work_order_id = int(seed.get("work_order_id") or 0)

    period_anchor = model.started_at
    period_start = datetime(period_anchor.year, period_anchor.month, 1, tzinfo=timezone.utc)
    if period_anchor.month == 12:
        period_end = datetime(period_anchor.year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        period_end = datetime(period_anchor.year, period_anchor.month + 1, 1, tzinfo=timezone.utc)

    with get_conn() as conn:
        inspection_row = None
        if inspection_id > 0:
            inspection_row = conn.execute(
                select(inspections).where(inspections.c.id == inspection_id).limit(1)
            ).mappings().first()
        work_order_row = None
        if work_order_id > 0:
            work_order_row = conn.execute(
                select(work_orders).where(work_orders.c.id == work_order_id).limit(1)
            ).mappings().first()
        inspection_count = int(
            conn.execute(
                select(func.count())
                .select_from(inspections)
                .where(inspections.c.site == site)
                .where(inspections.c.inspected_at >= period_start)
                .where(inspections.c.inspected_at < period_end)
            ).scalar_one()
        )
        work_order_count = int(
            conn.execute(
                select(func.count())
                .select_from(work_orders)
                .where(work_orders.c.site == site)
                .where(work_orders.c.created_at >= period_start)
                .where(work_orders.c.created_at < period_end)
            ).scalar_one()
        )

    risk_level = str(inspection_row["risk_level"]) if inspection_row is not None else ""
    step_states: list[dict[str, Any]] = []
    step_states.append(
        {
            "id": "seed_inspection_verified",
            "name": "Seed inspection verified",
            "name_ko": "샘플 점검 확인",
            "completed": bool(inspection_row is not None and risk_level in {"warning", "danger"}),
            "observed": {"inspection_id": inspection_id, "risk_level": risk_level},
        }
    )
    step_states.append(
        {
            "id": "seed_work_order_open",
            "name": "Seed work-order open",
            "name_ko": "샘플 작업지시 OPEN 확인",
            "completed": bool(work_order_row is not None),
            "observed": {
                "work_order_id": work_order_id,
                "status": str(work_order_row["status"]) if work_order_row is not None else None,
            },
        }
    )
    ack_completed = bool(
        work_order_row is not None
        and work_order_row.get("acknowledged_at") is not None
        and str(work_order_row.get("status") or "") in {"acked", "completed"}
    )
    step_states.append(
        {
            "id": "ack_work_order",
            "name": "Acknowledge work-order",
            "name_ko": "작업지시 ACK 처리",
            "completed": ack_completed,
            "observed": {
                "status": str(work_order_row["status"]) if work_order_row is not None else None,
                "acknowledged_at": _as_optional_datetime(work_order_row["acknowledged_at"]).isoformat()
                if work_order_row is not None and work_order_row.get("acknowledged_at") is not None
                else None,
            },
        }
    )
    complete_completed = bool(
        work_order_row is not None
        and str(work_order_row.get("status") or "") == "completed"
        and work_order_row.get("completed_at") is not None
    )
    step_states.append(
        {
            "id": "complete_work_order",
            "name": "Complete work-order",
            "name_ko": "작업지시 완료 처리",
            "completed": complete_completed,
            "observed": {
                "status": str(work_order_row["status"]) if work_order_row is not None else None,
                "completed_at": _as_optional_datetime(work_order_row["completed_at"]).isoformat()
                if work_order_row is not None and work_order_row.get("completed_at") is not None
                else None,
            },
        }
    )
    report_ready = bool(inspection_count >= 1 and work_order_count >= 1 and complete_completed)
    step_states.append(
        {
            "id": "report_data_ready",
            "name": "Report data ready",
            "name_ko": "리포트 데이터 준비 완료",
            "completed": report_ready,
            "observed": {
                "month": f"{period_start.year:04d}-{period_start.month:02d}",
                "inspection_count": inspection_count,
                "work_order_count": work_order_count,
            },
        }
    )

    completed_count = sum(1 for step in step_states if bool(step.get("completed", False)))
    total_steps = len(step_states)
    completion_percent = int(round((completed_count / total_steps) * 100)) if total_steps > 0 else 0
    work_order_status = str(work_order_row["status"]) if work_order_row is not None else None
    month_label = f"{period_start.year:04d}-{period_start.month:02d}"

    return {
        "session_id": model.id,
        "job_name": model.job_name,
        "created_at": model.started_at.isoformat(),
        "site": site,
        "scenario": {
            "id": str(scenario.get("id") or ""),
            "name": str(scenario.get("name") or ""),
            "name_ko": str(scenario.get("name_ko") or ""),
            "estimated_minutes": int(scenario.get("estimated_minutes") or 0),
        },
        "seed": {
            "inspection_id": inspection_id,
            "work_order_id": work_order_id,
            "work_order_status": work_order_status,
        },
        "progress": {
            "status": "completed" if completion_percent >= 100 else "active",
            "completed_steps": completed_count,
            "total_steps": total_steps,
            "completion_percent": completion_percent,
        },
        "steps": step_states,
        "practice_commands": {
            "ack_work_order": {
                "method": "PATCH",
                "url": f"/api/work-orders/{work_order_id}/ack",
                "body": {"assignee": "Ops Trainee"},
            },
            "complete_work_order": {
                "method": "PATCH",
                "url": f"/api/work-orders/{work_order_id}/complete",
                "body": {"resolution_notes": "Tutorial completion"},
            },
            "monthly_report": {
                "method": "GET",
                "url": f"/api/reports/monthly?month={month_label}&site={site}",
            },
            "session_check": {
                "method": "POST",
                "url": f"/api/ops/tutorial-simulator/sessions/{model.id}/check",
            },
            "session_action_ack": {
                "method": "POST",
                "url": f"/api/ops/tutorial-simulator/sessions/{model.id}/actions/ack_work_order",
            },
            "session_action_complete": {
                "method": "POST",
                "url": f"/api/ops/tutorial-simulator/sessions/{model.id}/actions/complete_work_order",
            },
        },
    }


def _start_tutorial_simulator_session(
    *,
    scenario_id: str,
    site: str,
    actor_username: str,
) -> dict[str, Any]:
    scenario = _get_tutorial_simulator_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Tutorial scenario not found")

    normalized_site = site.strip() or TUTORIAL_SIMULATOR_DEFAULT_SITE
    sample_data = scenario.get("verified_sample_data", {}) if isinstance(scenario.get("verified_sample_data"), dict) else {}
    inspection_data = sample_data.get("inspection", {}) if isinstance(sample_data.get("inspection"), dict) else {}
    work_order_data = sample_data.get("work_order", {}) if isinstance(sample_data.get("work_order"), dict) else {}

    now = datetime.now(timezone.utc)
    inspected_at = now - timedelta(minutes=10)
    inspection_payload = InspectionCreate(
        site=normalized_site,
        location=str(inspection_data.get("location") or "MCC-A1"),
        cycle=str(inspection_data.get("cycle") or "daily"),
        inspector=str(inspection_data.get("inspector") or "Tutorial Bot"),
        inspected_at=inspected_at,
        transformer_kva=float(inspection_data.get("transformer_kva") or 1250.0),
        winding_temp_c=float(inspection_data.get("winding_temp_c") or 132.0),
        grounding_ohm=float(inspection_data.get("grounding_ohm") or 11.2),
        insulation_mohm=float(inspection_data.get("insulation_mohm") or 0.6),
        notes=str(inspection_data.get("notes") or "Tutorial simulator seeded sample."),
    )
    risk_level, risk_flags = _calculate_risk(inspection_payload)

    with get_conn() as conn:
        inspection_insert = conn.execute(
            insert(inspections).values(
                site=inspection_payload.site,
                location=inspection_payload.location,
                cycle=inspection_payload.cycle,
                inspector=inspection_payload.inspector,
                inspected_at=_to_utc(inspection_payload.inspected_at),
                transformer_kva=inspection_payload.transformer_kva,
                voltage_r=inspection_payload.voltage_r,
                voltage_s=inspection_payload.voltage_s,
                voltage_t=inspection_payload.voltage_t,
                current_r=inspection_payload.current_r,
                current_s=inspection_payload.current_s,
                current_t=inspection_payload.current_t,
                winding_temp_c=inspection_payload.winding_temp_c,
                grounding_ohm=inspection_payload.grounding_ohm,
                insulation_mohm=inspection_payload.insulation_mohm,
                notes=inspection_payload.notes,
                risk_level=risk_level,
                risk_flags=",".join(risk_flags),
                created_at=now,
            )
        )
        inspection_id = int(inspection_insert.inserted_primary_key[0])

        due_at = now + timedelta(hours=8)
        work_order_insert = conn.execute(
            insert(work_orders).values(
                title=str(work_order_data.get("title") or "Tutorial - transformer hotspot response"),
                description=str(work_order_data.get("description") or "Acknowledge and complete this tutorial work order."),
                site=normalized_site,
                location=inspection_payload.location,
                priority=str(work_order_data.get("priority") or "high"),
                status="open",
                assignee=str(work_order_data.get("assignee") or "Ops Trainee"),
                reporter="Tutorial Bot",
                inspection_id=inspection_id,
                due_at=due_at,
                acknowledged_at=None,
                completed_at=None,
                resolution_notes="",
                is_escalated=False,
                created_at=now,
                updated_at=now,
            )
        )
        work_order_id = int(work_order_insert.inserted_primary_key[0])
        _append_work_order_event(
            conn,
            work_order_id=work_order_id,
            event_type="created",
            actor_username=actor_username,
            from_status=None,
            to_status="open",
            note="Tutorial simulator seeded work-order",
            detail={
                "scenario_id": scenario_id,
                "seeded": True,
                "inspection_id": inspection_id,
            },
        )

    detail = {
        "scenario_id": str(scenario.get("id") or scenario_id),
        "scenario_name": str(scenario.get("name") or ""),
        "scenario_name_ko": str(scenario.get("name_ko") or ""),
        "site": normalized_site,
        "seed": {
            "inspection_id": inspection_id,
            "work_order_id": work_order_id,
            "risk_level": risk_level,
            "risk_flags": risk_flags,
        },
        "actor_username": actor_username,
    }
    run_id = _write_job_run(
        job_name=OPS_TUTORIAL_SIMULATOR_SESSION_JOB_NAME,
        trigger="tutorial_start",
        status="success",
        started_at=now,
        finished_at=now,
        detail=detail,
    )
    if run_id is None:
        raise HTTPException(status_code=500, detail="Failed to create tutorial simulator session")
    return _evaluate_tutorial_simulator_session(session_id=run_id)


def _run_tutorial_simulator_action(
    *,
    session_id: int,
    action: str,
    actor_username: str,
    assignee: str | None = None,
    resolution_notes: str | None = None,
) -> dict[str, Any]:
    row = _load_tutorial_simulator_session_row(session_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Tutorial simulator session not found")
    model = _row_to_job_run_model(row)
    detail = model.detail if isinstance(model.detail, dict) else {}
    seed = detail.get("seed", {}) if isinstance(detail.get("seed"), dict) else {}
    work_order_id = int(seed.get("work_order_id") or 0)
    if work_order_id <= 0:
        raise HTTPException(status_code=409, detail="Tutorial session seed is invalid")

    normalized_action = action.strip().lower()
    now = datetime.now(timezone.utc)
    status_after: str | None = None
    action_result = "noop"
    with get_conn() as conn:
        work_order_row = conn.execute(
            select(work_orders).where(work_orders.c.id == work_order_id).limit(1)
        ).mappings().first()
        if work_order_row is None:
            raise HTTPException(status_code=404, detail="Seeded work-order not found")
        current_status = str(work_order_row.get("status") or "open")
        if normalized_action == "ack_work_order":
            if current_status == "open":
                next_assignee = assignee if assignee is not None else str(work_order_row.get("assignee") or "Ops Trainee")
                conn.execute(
                    update(work_orders)
                    .where(work_orders.c.id == work_order_id)
                    .values(
                        status="acked",
                        assignee=next_assignee,
                        acknowledged_at=now,
                        updated_at=now,
                    )
                )
                _append_work_order_event(
                    conn,
                    work_order_id=work_order_id,
                    event_type="status_changed",
                    actor_username=actor_username,
                    from_status="open",
                    to_status="acked",
                    note="Tutorial simulator action: ACK work-order",
                    detail={"scenario_session_id": session_id},
                )
                action_result = "updated"
                status_after = "acked"
            elif current_status in {"acked", "completed"}:
                action_result = "already_applied"
                status_after = current_status
            else:
                raise HTTPException(status_code=409, detail="Work-order cannot be ACKed from current status")
        elif normalized_action == "complete_work_order":
            if current_status == "open":
                raise HTTPException(status_code=409, detail="ACK the work-order before completion")
            if current_status == "acked":
                note = resolution_notes if resolution_notes is not None else "Tutorial simulator completion"
                conn.execute(
                    update(work_orders)
                    .where(work_orders.c.id == work_order_id)
                    .values(
                        status="completed",
                        completed_at=now,
                        resolution_notes=note,
                        updated_at=now,
                    )
                )
                _append_work_order_event(
                    conn,
                    work_order_id=work_order_id,
                    event_type="status_changed",
                    actor_username=actor_username,
                    from_status="acked",
                    to_status="completed",
                    note="Tutorial simulator action: complete work-order",
                    detail={"scenario_session_id": session_id},
                )
                action_result = "updated"
                status_after = "completed"
            elif current_status == "completed":
                action_result = "already_applied"
                status_after = current_status
            else:
                raise HTTPException(status_code=409, detail="Work-order cannot be completed from current status")
        elif normalized_action == "reset_work_order":
            conn.execute(
                update(work_orders)
                .where(work_orders.c.id == work_order_id)
                .values(
                    status="open",
                    acknowledged_at=None,
                    completed_at=None,
                    resolution_notes="",
                    updated_at=now,
                )
            )
            _append_work_order_event(
                conn,
                work_order_id=work_order_id,
                event_type="status_changed",
                actor_username=actor_username,
                from_status=current_status,
                to_status="open",
                note="Tutorial simulator action: reset work-order",
                detail={"scenario_session_id": session_id},
            )
            action_result = "updated"
            status_after = "open"
        else:
            raise HTTPException(status_code=422, detail="Unsupported tutorial action")

    session = _evaluate_tutorial_simulator_session(session_id=session_id)
    return {
        "session_id": session_id,
        "action": normalized_action,
        "result": action_result,
        "work_order_status": status_after,
        "session": session,
    }


def _build_post_mvp_backlog_csv(plan: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "id",
            "epic",
            "item",
            "priority",
            "owner",
            "estimate_points",
            "target_release",
            "status",
            "success_kpi",
        ]
    )
    for item in plan.get("execution_backlog", []):
        writer.writerow(
            [
                item.get("id", ""),
                item.get("epic", ""),
                item.get("item", ""),
                item.get("priority", ""),
                item.get("owner", ""),
                item.get("estimate_points", ""),
                item.get("target_release", ""),
                item.get("status", ""),
                item.get("success_kpi", ""),
            ]
        )
    return out.getvalue()


def _build_post_mvp_release_ics(plan: dict[str, Any]) -> str:
    dtstamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    events: list[str] = []
    milestones = plan.get("release_calendar", {}).get("milestones", [])

    for milestone in milestones:
        release = str(milestone.get("release", ""))
        name = str(milestone.get("name", ""))
        date_raw = str(milestone.get("date", ""))
        try:
            release_date = date.fromisoformat(date_raw)
        except ValueError:
            continue

        release_end = release_date + timedelta(days=1)
        summary = f"[Post-MVP] {release} - {name}"
        description = "\n".join(
            [
                f"Owner: {milestone.get('owner', '')}",
                f"Goal: {milestone.get('goal', '')}",
            ]
        )
        uid = f"ka-facility-os-post-mvp-{release.lower().replace('.', '-')}-release@public"
        events.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{dtstamp}",
                f"DTSTART;VALUE=DATE:{release_date.strftime('%Y%m%d')}",
                f"DTEND;VALUE=DATE:{release_end.strftime('%Y%m%d')}",
                f"SUMMARY:{_ics_escape(summary)}",
                f"DESCRIPTION:{_ics_escape(description)}",
                "END:VEVENT",
            ]
        )

    calendar_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KA Facility OS//Post-MVP Releases//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    calendar_lines.extend(events)
    calendar_lines.append("END:VCALENDAR")
    return "\r\n".join(calendar_lines) + "\r\n"


def _build_public_main_page_html(service_info: dict[str, str], plan: dict[str, Any]) -> str:
    return _web_build_public_main_page_html(service_info, plan)


def _build_facility_console_html(service_info: dict[str, str], modules_payload: dict[str, Any]) -> str:
    return _web_build_facility_console_html(service_info, modules_payload)


def _build_facility_console_guide_html(service_info: dict[str, str]) -> str:
    return _web_build_facility_console_guide_html(service_info)


def _build_iam_guide_html(service_info: dict[str, str]) -> str:
    return _web_build_iam_guide_html(service_info)


def _build_public_modules_html(modules_payload: dict[str, Any]) -> str:
    return _web_build_public_modules_html(modules_payload)


def _build_shared_tracker_execution_box_html(phase_code: str, phase_label: str) -> str:
    return _web_build_shared_tracker_execution_box_html(phase_code, phase_label)


OPS_CHECKLIST_RESPONSE_SCHEMA = "ops_checklist_catalog_response"
OPS_CHECKLIST_RESPONSE_VERSION = "v1"


def _build_ops_checklist_response_meta(
    payload: dict[str, Any],
    *,
    endpoint: str,
) -> dict[str, Any]:
    checklist_version = str(payload.get("checklist_version") or payload.get("version") or "unknown")
    source = str(payload.get("source") or "unknown")
    applied_at = _as_optional_datetime(payload.get("applied_at"))
    applied_at_iso = applied_at.isoformat() if applied_at is not None else None
    return {
        "checklist_version": checklist_version,
        "source": source,
        "applied_at": applied_at_iso,
        "meta": {
            "schema": OPS_CHECKLIST_RESPONSE_SCHEMA,
            "schema_version": OPS_CHECKLIST_RESPONSE_VERSION,
            "endpoint": endpoint,
            "checklist_version": checklist_version,
            "source": source,
            "applied_at": applied_at_iso,
        },
    }


def _default_ops_special_checklists_payload() -> dict[str, Any]:
    return {
        "source_file": "fallback",
        "source": "fallback",
        "version": "fallback",
        "checklist_version": "fallback",
        "applied_at": None,
        "checklist_sets": [
            {
                "set_id": "electrical_60",
                "label": "전기직무고시60항목",
                "task_type": "전기점검",
                "items": [
                    {"seq": 1, "item": "수변전실 출입통제 상태 확인"},
                    {"seq": 2, "item": "변압기 외관 점검"},
                    {"seq": 3, "item": "수전반 차단기 동작 상태"},
                    {"seq": 4, "item": "분전반 누전차단기 상태"},
                    {"seq": 5, "item": "접지설비 연결 상태"},
                ],
            },
            {
                "set_id": "fire_legal",
                "label": "소방법정점검",
                "task_type": "소방점검",
                "items": [
                    {"seq": 1, "item": "소화기 압력 확인"},
                    {"seq": 2, "item": "옥내소화전 방수 시험"},
                    {"seq": 3, "item": "스프링클러 헤드 막힘 여부"},
                ],
            },
            {
                "set_id": "mechanical_ops",
                "label": "기계설비점검",
                "task_type": "기계점검",
                "items": [
                    {"seq": 1, "item": "급수펌프 외관 상태 확인"},
                    {"seq": 2, "item": "배수펌프 자동운전 상태 확인"},
                    {"seq": 3, "item": "저수조 수위 및 누수 확인"},
                ],
            },
            {
                "set_id": "building_ops",
                "label": "건축시설점검",
                "task_type": "건축점검",
                "items": [
                    {"seq": 1, "item": "외벽 균열 및 박락 여부 확인"},
                    {"seq": 2, "item": "옥상 방수층 손상 여부 확인"},
                    {"seq": 3, "item": "방화문 개폐 상태 확인"},
                ],
            },
            {
                "set_id": "safety_ops",
                "label": "안전시설점검",
                "task_type": "안전점검",
                "items": [
                    {"seq": 1, "item": "CCTV 전원 및 녹화 상태 확인"},
                    {"seq": 2, "item": "주차장 조명 점등 상태 확인"},
                    {"seq": 3, "item": "비상벨 작동 상태 확인"},
                ],
            },
        ],
        "ops_codes": [
            {"code": "E01", "category": "전기", "description": "수변전설비 점검"},
            {"code": "F01", "category": "소방", "description": "소화기 점검"},
            {"code": "M01", "category": "기계", "description": "급수펌프 점검"},
            {"code": "B01", "category": "건축", "description": "외벽 점검"},
            {"code": "S01", "category": "안전", "description": "CCTV 점검"},
        ],
        "qr_assets": [],
    }


def _resolve_ops_special_checklists_data_path() -> Path:
    raw_path = getenv(
        "OPS_SPECIAL_CHECKLISTS_DATA_PATH",
        "data/apartment_facility_special_checklists.json",
    ).strip() or "data/apartment_facility_special_checklists.json"
    target = Path(raw_path)
    if not target.is_absolute():
        target = Path(__file__).resolve().parent.parent / target
    return target


def _persist_ops_special_checklists_payload(payload: dict[str, Any]) -> Path:
    target = _resolve_ops_special_checklists_data_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, ensure_ascii=False, indent=2)
    target.write_text(serialized + "\n", encoding="utf-8")
    return target


def _load_ops_special_checklists_payload() -> dict[str, Any]:
    default_payload = _default_ops_special_checklists_payload()
    target = _resolve_ops_special_checklists_data_path()
    if not target.exists():
        return default_payload
    try:
        loaded = json.loads(target.read_text(encoding="utf-8"))
    except Exception:
        return default_payload
    if not isinstance(loaded, dict):
        return default_payload

    checklist_sets_raw = loaded.get("checklist_sets")
    ops_codes_raw = loaded.get("ops_codes")
    qr_assets_raw = loaded.get("qr_assets")
    checklist_sets: list[dict[str, Any]] = []
    if isinstance(checklist_sets_raw, list):
        for item in checklist_sets_raw:
            if not isinstance(item, dict):
                continue
            set_id = str(item.get("set_id") or "").strip()
            label = str(item.get("label") or "").strip()
            if not set_id or not label:
                continue
            task_type = str(item.get("task_type") or "점검").strip() or "점검"
            items_raw = item.get("items")
            items: list[dict[str, Any]] = []
            if isinstance(items_raw, list):
                for idx, entry in enumerate(items_raw, start=1):
                    if not isinstance(entry, dict):
                        continue
                    text = str(entry.get("item") or "").strip()
                    if not text:
                        continue
                    seq_raw = entry.get("seq")
                    try:
                        seq = int(seq_raw)
                    except Exception:
                        seq = idx
                    items.append({"seq": max(1, seq), "item": text})
            if items:
                checklist_sets.append(
                    {
                        "set_id": set_id,
                        "label": label,
                        "task_type": task_type,
                        "items": items,
                    }
                )
    if not checklist_sets:
        checklist_sets = list(default_payload["checklist_sets"])

    ops_codes: list[dict[str, str]] = []
    if isinstance(ops_codes_raw, list):
        for row in ops_codes_raw:
            if not isinstance(row, dict):
                continue
            code = str(row.get("code") or "").strip()
            category = str(row.get("category") or "").strip()
            description = str(row.get("description") or "").strip()
            if not code:
                continue
            ops_codes.append({"code": code, "category": category, "description": description})

    qr_assets: list[dict[str, str]] = []
    if isinstance(qr_assets_raw, list):
        for row in qr_assets_raw:
            if not isinstance(row, dict):
                continue
            qr_id = str(row.get("qr_id") or "").strip()
            if not qr_id:
                continue
            qr_assets.append(
                {
                    "qr_id": qr_id,
                    "equipment": str(row.get("equipment") or "").strip(),
                    "location": str(row.get("location") or "").strip(),
                    "default_item": str(row.get("default_item") or "").strip(),
                }
            )

    return {
        "source_file": str(loaded.get("source_file") or target.as_posix()),
        "source": str(loaded.get("source") or "file"),
        "version": str(loaded.get("version") or "unknown"),
        "checklist_version": str(loaded.get("checklist_version") or loaded.get("version") or "unknown"),
        "applied_at": (
            loaded.get("applied_at")
            or datetime.fromtimestamp(target.stat().st_mtime, tz=timezone.utc).isoformat()
        ),
        "checklist_sets": checklist_sets,
        "ops_codes": ops_codes,
        "qr_assets": qr_assets,
    }


def _append_ops_import_validation_issue(
    buckets: dict[tuple[str, str, str, str], dict[str, Any]],
    *,
    severity: str,
    category: str,
    code: str,
    message: str,
    reference: str = "",
) -> None:
    normalized_severity = str(severity or "warning").strip().lower() or "warning"
    normalized_category = str(category or "general").strip() or "general"
    normalized_code = str(code or "issue").strip() or "issue"
    normalized_message = str(message or "").strip() or "issue detected"
    normalized_reference = str(reference or "").strip()
    key = (normalized_severity, normalized_category, normalized_code, normalized_message)
    bucket = buckets.get(key)
    if bucket is None:
        bucket = {
            "severity": normalized_severity,
            "category": normalized_category,
            "code": normalized_code,
            "message": normalized_message,
            "count": 0,
            "references": [],
        }
        buckets[key] = bucket
    bucket["count"] = int(bucket["count"]) + 1
    references = bucket.get("references")
    if normalized_reference and isinstance(references, list) and len(references) < 5:
        references.append(normalized_reference)


def _build_ops_checklists_import_validation_report() -> dict[str, Any]:
    payload = _load_ops_special_checklists_payload()
    generated_at = datetime.now(timezone.utc)
    checklist_sets = payload.get("checklist_sets") if isinstance(payload.get("checklist_sets"), list) else []
    ops_codes = payload.get("ops_codes") if isinstance(payload.get("ops_codes"), list) else []
    qr_assets = payload.get("qr_assets") if isinstance(payload.get("qr_assets"), list) else []
    source_file = str(payload.get("source_file") or "")
    source_exists = False
    if source_file:
        source_path = Path(source_file)
        source_exists = source_path.exists()

    issue_buckets: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    task_types: set[str] = set()
    global_item_to_set: dict[str, str] = {}
    checklist_item_total = 0

    seen_set_ids: set[str] = set()
    for set_idx, set_row in enumerate(checklist_sets, start=1):
        if not isinstance(set_row, dict):
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="checklist_sets",
                code="invalid_set",
                message="checklist set row must be an object",
                reference=f"checklist_sets[{set_idx}]",
            )
            continue
        set_id = str(set_row.get("set_id") or "").strip()
        label = str(set_row.get("label") or "").strip()
        task_type = str(set_row.get("task_type") or "").strip()
        if not set_id:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="checklist_sets",
                code="missing_set_id",
                message="checklist set id is missing",
                reference=f"checklist_sets[{set_idx}]",
            )
        elif set_id in seen_set_ids:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="checklist_sets",
                code="duplicate_set_id",
                message=f"duplicate checklist set id: {set_id}",
                reference=f"checklist_sets[{set_idx}]",
            )
        else:
            seen_set_ids.add(set_id)
        if not label:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="warning",
                category="checklist_sets",
                code="missing_label",
                message="checklist set label is missing",
                reference=f"checklist_sets[{set_idx}]",
            )
        if not task_type:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="warning",
                category="checklist_sets",
                code="missing_task_type",
                message="checklist set task_type is missing",
                reference=f"checklist_sets[{set_idx}]",
            )
        else:
            task_types.add(task_type)

        items = set_row.get("items")
        if not isinstance(items, list) or len(items) == 0:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="checklist_items",
                code="empty_items",
                message="checklist set has no items",
                reference=f"checklist_sets[{set_idx}]",
            )
            continue

        if set_id == "electrical_60" and len(items) != 60:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="warning",
                category="checklist_items",
                code="electrical_60_count_mismatch",
                message=f"electrical_60 expected 60 items, found {len(items)}",
                reference=f"checklist_sets[{set_idx}]",
            )
        if set_id == "fire_legal" and len(items) != 18:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="warning",
                category="checklist_items",
                code="fire_legal_count_mismatch",
                message=f"fire_legal expected 18 items, found {len(items)}",
                reference=f"checklist_sets[{set_idx}]",
            )

        seen_seq: set[int] = set()
        seen_item_text: set[str] = set()
        for item_idx, item_row in enumerate(items, start=1):
            if not isinstance(item_row, dict):
                _append_ops_import_validation_issue(
                    issue_buckets,
                    severity="error",
                    category="checklist_items",
                    code="invalid_item_row",
                    message="checklist item row must be an object",
                    reference=f"{set_id}.items[{item_idx}]",
                )
                continue
            checklist_item_total += 1
            item_text = str(item_row.get("item") or "").strip()
            seq_raw = item_row.get("seq")
            try:
                seq = int(seq_raw)
            except (TypeError, ValueError):
                seq = -1
            if seq <= 0:
                _append_ops_import_validation_issue(
                    issue_buckets,
                    severity="warning",
                    category="checklist_items",
                    code="invalid_seq",
                    message="item seq should be a positive integer",
                    reference=f"{set_id}.items[{item_idx}]",
                )
            elif seq in seen_seq:
                _append_ops_import_validation_issue(
                    issue_buckets,
                    severity="warning",
                    category="checklist_items",
                    code="duplicate_seq",
                    message=f"duplicate seq in set {set_id}: {seq}",
                    reference=f"{set_id}.items[{item_idx}]",
                )
            else:
                seen_seq.add(seq)

            if not item_text:
                _append_ops_import_validation_issue(
                    issue_buckets,
                    severity="error",
                    category="checklist_items",
                    code="missing_item_text",
                    message="item text is missing",
                    reference=f"{set_id}.items[{item_idx}]",
                )
                continue
            if item_text in seen_item_text:
                _append_ops_import_validation_issue(
                    issue_buckets,
                    severity="warning",
                    category="checklist_items",
                    code="duplicate_item_text",
                    message=f"duplicate item text in set {set_id}: {item_text}",
                    reference=f"{set_id}.items[{item_idx}]",
                )
            else:
                seen_item_text.add(item_text)
            global_item_to_set.setdefault(item_text, set_id)

    category_to_set: dict[str, str] = {}
    for set_row in checklist_sets:
        if not isinstance(set_row, dict):
            continue
        set_id = str(set_row.get("set_id") or "").strip()
        task_type = str(set_row.get("task_type") or "").strip()
        if set_id and task_type:
            if "전기" in task_type and "전기" not in category_to_set:
                category_to_set["전기"] = set_id
            if "소방" in task_type and "소방" not in category_to_set:
                category_to_set["소방"] = set_id
            if "기계" in task_type and "기계" not in category_to_set:
                category_to_set["기계"] = set_id
            if "건축" in task_type and "건축" not in category_to_set:
                category_to_set["건축"] = set_id
            if "안전" in task_type and "안전" not in category_to_set:
                category_to_set["안전"] = set_id

    seen_ops_codes: set[str] = set()
    for idx, row in enumerate(ops_codes, start=1):
        if not isinstance(row, dict):
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="ops_codes",
                code="invalid_code_row",
                message="ops code row must be an object",
                reference=f"ops_codes[{idx}]",
            )
            continue
        code = str(row.get("code") or "").strip()
        category = str(row.get("category") or "").strip()
        description = str(row.get("description") or "").strip()
        if not code:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="ops_codes",
                code="missing_code",
                message="ops code is missing",
                reference=f"ops_codes[{idx}]",
            )
            continue
        if code in seen_ops_codes:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="ops_codes",
                code="duplicate_code",
                message=f"duplicate ops code: {code}",
                reference=f"ops_codes[{idx}]",
            )
        else:
            seen_ops_codes.add(code)
        if not category:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="warning",
                category="ops_codes",
                code="missing_category",
                message=f"ops code category is missing: {code}",
                reference=f"ops_codes[{idx}]",
            )
            continue
        normalized = f"{category} {description}".lower()
        mapped = False
        if "전기" in normalized and category_to_set.get("전기"):
            mapped = True
        if "소방" in normalized and category_to_set.get("소방"):
            mapped = True
        if "기계" in normalized and category_to_set.get("기계"):
            mapped = True
        if "건축" in normalized and category_to_set.get("건축"):
            mapped = True
        if "안전" in normalized and category_to_set.get("안전"):
            mapped = True
        if not mapped:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="warning",
                category="ops_codes",
                code="unmapped_category",
                message=f"ops code category is not mapped to checklist set: {code}",
                reference=f"ops_codes[{idx}]",
            )

    seen_qr_ids: set[str] = set()
    for idx, row in enumerate(qr_assets, start=1):
        if not isinstance(row, dict):
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="qr_assets",
                code="invalid_qr_row",
                message="qr asset row must be an object",
                reference=f"qr_assets[{idx}]",
            )
            continue
        qr_id = str(row.get("qr_id") or "").strip()
        equipment = str(row.get("equipment") or "").strip()
        location = str(row.get("location") or "").strip()
        default_item = str(row.get("default_item") or "").strip()
        if not qr_id:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="qr_assets",
                code="missing_qr_id",
                message="qr_id is missing",
                reference=f"qr_assets[{idx}]",
            )
            continue
        if qr_id in seen_qr_ids:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="error",
                category="qr_assets",
                code="duplicate_qr_id",
                message=f"duplicate qr_id: {qr_id}",
                reference=f"qr_assets[{idx}]",
            )
        else:
            seen_qr_ids.add(qr_id)

        placeholder_flags = _qr_asset_placeholder_flags(
            {
                "equipment": equipment,
                "location": location,
                "default_item": default_item,
            }
        )
        for flag in placeholder_flags:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="warning",
                category="qr_assets",
                code=flag,
                message=f"{flag.replace('_', ' ')} for {qr_id}",
                reference=f"qr_assets[{idx}]",
            )
        if default_item and default_item not in global_item_to_set:
            _append_ops_import_validation_issue(
                issue_buckets,
                severity="warning",
                category="qr_assets",
                code="unknown_default_item",
                message=f"default_item is not registered in checklist sets for {qr_id}",
                reference=f"qr_assets[{idx}]",
            )

    if source_file and not source_exists:
        _append_ops_import_validation_issue(
            issue_buckets,
            severity="warning",
            category="source",
            code="source_file_not_found",
            message=f"source file path does not exist: {source_file}",
            reference="source_file",
        )

    severity_order = {"error": 0, "warning": 1, "info": 2}
    issues = sorted(
        issue_buckets.values(),
        key=lambda row: (
            severity_order.get(str(row.get("severity") or "warning"), 9),
            str(row.get("category") or ""),
            str(row.get("code") or ""),
            str(row.get("message") or ""),
        ),
    )

    error_count = sum(int(row.get("count") or 0) for row in issues if str(row.get("severity")) == "error")
    warning_count = sum(int(row.get("count") or 0) for row in issues if str(row.get("severity")) == "warning")
    status = "ok"
    if error_count > 0:
        status = "error"
    elif warning_count > 0:
        status = "warning"

    suggestions: list[str] = []
    issue_codes = {str(row.get("code") or "") for row in issues}
    if "placeholder_equipment" in issue_codes or "placeholder_location" in issue_codes or "placeholder_default_item" in issue_codes:
        suggestions.append("QR설비관리 시트의 placeholder 값(설비/위치/점검항목)을 실제 설비 데이터로 치환하세요.")
    if "unknown_default_item" in issue_codes:
        suggestions.append("QR default_item을 checklist set 항목명과 1:1로 맞추고 오탈자를 제거하세요.")
    if "unmapped_category" in issue_codes:
        suggestions.append("OPS코드 분류(기계/건축/안전 등)별 checklist_set을 추가하거나 category 매핑 규칙을 확정하세요.")
    if "duplicate_set_id" in issue_codes or "duplicate_code" in issue_codes or "duplicate_qr_id" in issue_codes:
        suggestions.append("중복 key(set_id/code/qr_id)를 제거하고 마스터키 유일성을 보장하세요.")
    if not suggestions:
        suggestions.append("치명적 정합성 이슈가 없으며 현재 데이터로 운영을 진행할 수 있습니다.")

    return {
        "generated_at": generated_at.isoformat(),
        "source_file": source_file,
        "source_file_exists": source_exists,
        "version": str(payload.get("version") or ""),
        **_build_ops_checklist_response_meta(payload, endpoint="/api/ops/inspections/checklists/import-validation"),
        "status": status,
        "summary": {
            "checklist_set_count": len(checklist_sets),
            "checklist_item_count": checklist_item_total,
            "ops_code_count": len(ops_codes),
            "qr_asset_count": len(qr_assets),
            "task_type_count": len(task_types),
            "error_count": error_count,
            "warning_count": warning_count,
            "issue_bucket_count": len(issues),
        },
        "task_types": sorted(task_types),
        "issues": issues,
        "suggestions": suggestions,
    }


def _build_ops_checklists_import_validation_csv(report: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["generated_at", str(report.get("generated_at") or "")])
    writer.writerow(["status", str(report.get("status") or "")])
    writer.writerow(["source_file", str(report.get("source_file") or "")])
    writer.writerow(["version", str(report.get("version") or "")])
    writer.writerow(["checklist_version", str(report.get("checklist_version") or "")])
    writer.writerow(["source", str(report.get("source") or "")])
    writer.writerow(["applied_at", str(report.get("applied_at") or "")])

    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    writer.writerow([])
    writer.writerow(["summary_key", "value"])
    for key in (
        "checklist_set_count",
        "checklist_item_count",
        "ops_code_count",
        "qr_asset_count",
        "task_type_count",
        "error_count",
        "warning_count",
        "issue_bucket_count",
    ):
        writer.writerow([key, summary.get(key, "")])

    writer.writerow([])
    writer.writerow(["severity", "category", "code", "count", "message", "references"])
    issues = report.get("issues") if isinstance(report.get("issues"), list) else []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        references = issue.get("references")
        if isinstance(references, list):
            references_text = " | ".join(str(item) for item in references if str(item).strip())
        else:
            references_text = str(references or "")
        writer.writerow(
            [
                issue.get("severity", ""),
                issue.get("category", ""),
                issue.get("code", ""),
                issue.get("count", ""),
                issue.get("message", ""),
                references_text,
            ]
        )

    suggestions = report.get("suggestions") if isinstance(report.get("suggestions"), list) else []
    writer.writerow([])
    writer.writerow(["suggestions"])
    for suggestion in suggestions:
        writer.writerow([str(suggestion or "")])
    return out.getvalue()


def _build_ops_checklist_item_set(payload: dict[str, Any]) -> set[str]:
    checklist_sets = payload.get("checklist_sets") if isinstance(payload.get("checklist_sets"), list) else []
    item_set: set[str] = set()
    for set_row in checklist_sets:
        if not isinstance(set_row, dict):
            continue
        items = set_row.get("items")
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            text = str(item.get("item") or "").strip()
            if text:
                item_set.add(text)
    return item_set


def _build_ops_qr_placeholder_snapshot(payload: dict[str, Any]) -> list[dict[str, Any]]:
    qr_assets = payload.get("qr_assets") if isinstance(payload.get("qr_assets"), list) else []
    rows: list[dict[str, Any]] = []
    for row in qr_assets:
        if not isinstance(row, dict):
            continue
        qr_id = str(row.get("qr_id") or "").strip()
        if not qr_id:
            continue
        flags = _qr_asset_placeholder_flags(row)
        if not flags:
            continue
        rows.append(
            {
                "qr_id": qr_id,
                "equipment": str(row.get("equipment") or "").strip(),
                "location": str(row.get("location") or "").strip(),
                "default_item": str(row.get("default_item") or "").strip(),
                "flags": flags,
            }
        )
    rows.sort(key=lambda item: str(item.get("qr_id") or ""))
    return rows


def _coerce_request_bool(value: Any, *, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "y", "yes", "on"}:
        return True
    if normalized in {"0", "false", "n", "no", "off"}:
        return False
    return default


def _build_ops_qr_placeholder_report(payload: dict[str, Any]) -> dict[str, Any]:
    rows = _build_ops_qr_placeholder_snapshot(payload)
    flag_counts: dict[str, int] = {}
    for row in rows:
        flags = row.get("flags")
        if not isinstance(flags, list):
            continue
        for flag in flags:
            key = str(flag or "").strip()
            if not key:
                continue
            flag_counts[key] = flag_counts.get(key, 0) + 1
    qr_assets = payload.get("qr_assets") if isinstance(payload.get("qr_assets"), list) else []
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": str(payload.get("source_file") or ""),
        "version": str(payload.get("version") or ""),
        **_build_ops_checklist_response_meta(payload, endpoint="/api/ops/inspections/checklists/qr-assets/placeholders"),
        "status": "warning" if rows else "ok",
        "summary": {
            "qr_asset_count": len(qr_assets),
            "placeholder_row_count": len(rows),
            "placeholder_flag_counts": flag_counts,
        },
        "rows": rows,
        "suggestions": (
            ["placeholder 행이 남아 있습니다. bulk-update API로 실제 설비값으로 치환하세요."]
            if rows
            else ["placeholder 행이 없습니다. 현재 QR 자산 데이터는 운영 가능한 상태입니다."]
        ),
    }


def _apply_ops_qr_asset_bulk_update_request(request_payload: dict[str, Any]) -> dict[str, Any]:
    body = request_payload if isinstance(request_payload, dict) else {}
    updates_raw = body.get("updates")
    if not isinstance(updates_raw, list) or not updates_raw:
        raise HTTPException(status_code=422, detail="updates must be a non-empty array")

    dry_run = _coerce_request_bool(body.get("dry_run"), default=True)
    create_missing = _coerce_request_bool(body.get("create_missing"), default=False)
    allow_placeholder_values = _coerce_request_bool(body.get("allow_placeholder_values"), default=False)

    payload = _load_ops_special_checklists_payload()
    qr_assets_raw = payload.get("qr_assets") if isinstance(payload.get("qr_assets"), list) else []
    qr_assets: list[dict[str, str]] = []
    for row in qr_assets_raw:
        if not isinstance(row, dict):
            continue
        qr_id = str(row.get("qr_id") or "").strip()
        if not qr_id:
            continue
        qr_assets.append(
            {
                "qr_id": qr_id,
                "equipment": str(row.get("equipment") or "").strip(),
                "location": str(row.get("location") or "").strip(),
                "default_item": str(row.get("default_item") or "").strip(),
            }
        )

    before_payload = {**payload, "qr_assets": [dict(row) for row in qr_assets]}
    before_placeholder_rows = _build_ops_qr_placeholder_snapshot(before_payload)
    checklist_item_set = _build_ops_checklist_item_set(payload)
    unknown_default_before = sum(
        1
        for row in qr_assets
        if str(row.get("default_item") or "").strip()
        and str(row.get("default_item") or "").strip() not in checklist_item_set
    )

    index_by_qr_id: dict[str, int] = {str(row.get("qr_id") or ""): idx for idx, row in enumerate(qr_assets)}
    seen_request_qr_ids: set[str] = set()
    changed_rows: list[dict[str, Any]] = []
    skipped_rows: list[dict[str, Any]] = []
    invalid_rows: list[dict[str, Any]] = []
    updated_count = 0
    created_count = 0

    for idx, raw in enumerate(updates_raw, start=1):
        if not isinstance(raw, dict):
            invalid_rows.append({"index": idx, "reason": "invalid_row_type", "message": "row must be an object"})
            continue

        qr_id = str(raw.get("qr_id") or "").strip()
        if not qr_id:
            invalid_rows.append({"index": idx, "reason": "missing_qr_id", "message": "qr_id is required"})
            continue
        if qr_id in seen_request_qr_ids:
            skipped_rows.append(
                {
                    "index": idx,
                    "qr_id": qr_id,
                    "reason": "duplicate_qr_id_in_request",
                    "message": "duplicate qr_id in updates array",
                }
            )
            continue
        seen_request_qr_ids.add(qr_id)

        requested_fields = [field for field in OPS_QR_MUTABLE_FIELDS if field in raw]
        update_fields: dict[str, str] = {}
        blocked_placeholder_fields: list[str] = []
        for field in requested_fields:
            value = str(raw.get(field) or "").strip()
            if not value:
                continue
            if (not allow_placeholder_values) and value in OPS_QR_PLACEHOLDER_VALUES:
                blocked_placeholder_fields.append(field)
                continue
            update_fields[field] = value
        if not update_fields:
            reason = "no_effective_fields"
            message = "no updatable non-empty fields"
            if blocked_placeholder_fields:
                reason = "blocked_placeholder_values"
                message = "placeholder values are blocked for fields: " + ", ".join(blocked_placeholder_fields)
            skipped_rows.append(
                {
                    "index": idx,
                    "qr_id": qr_id,
                    "reason": reason,
                    "message": message,
                }
            )
            continue

        existing_index = index_by_qr_id.get(qr_id)
        if existing_index is None and not create_missing:
            skipped_rows.append(
                {
                    "index": idx,
                    "qr_id": qr_id,
                    "reason": "qr_id_not_found",
                    "message": "qr_id does not exist (create_missing=false)",
                }
            )
            continue
        if existing_index is None and create_missing:
            missing_for_create = [field for field in OPS_QR_MUTABLE_FIELDS if field not in update_fields]
            if missing_for_create:
                skipped_rows.append(
                    {
                        "index": idx,
                        "qr_id": qr_id,
                        "reason": "missing_required_fields_for_create",
                        "message": "create_missing=true requires all fields: " + ", ".join(missing_for_create),
                    }
                )
                continue

        action = "updated" if existing_index is not None else "created"
        before_row = (
            dict(qr_assets[existing_index])
            if existing_index is not None
            else {"qr_id": qr_id, "equipment": "", "location": "", "default_item": ""}
        )
        after_row = dict(before_row)
        changed_fields: list[str] = []
        for field, value in update_fields.items():
            if str(after_row.get(field) or "").strip() == value:
                continue
            after_row[field] = value
            changed_fields.append(field)
        if not changed_fields:
            skipped_rows.append(
                {
                    "index": idx,
                    "qr_id": qr_id,
                    "reason": "unchanged",
                    "message": "all provided values already match current row",
                }
            )
            continue

        if existing_index is not None:
            qr_assets[existing_index] = after_row
            updated_count += 1
        else:
            index_by_qr_id[qr_id] = len(qr_assets)
            qr_assets.append(after_row)
            created_count += 1

        quality_flags = _qr_asset_placeholder_flags(after_row)
        default_item = str(after_row.get("default_item") or "").strip()
        if default_item and default_item not in checklist_item_set:
            quality_flags.append("unknown_default_item")
        changed_rows.append(
            {
                "index": idx,
                "qr_id": qr_id,
                "action": action,
                "changed_fields": changed_fields,
                "before": before_row,
                "after": after_row,
                "quality_flags": quality_flags,
            }
        )

    after_payload = {**payload, "qr_assets": qr_assets}
    after_placeholder_rows = _build_ops_qr_placeholder_snapshot(after_payload)
    unknown_default_after = sum(
        1
        for row in qr_assets
        if str(row.get("default_item") or "").strip()
        and str(row.get("default_item") or "").strip() not in checklist_item_set
    )
    applied_count = updated_count + created_count

    saved = False
    saved_path = ""
    metadata_payload = after_payload
    if (not dry_run) and applied_count > 0:
        saved_at = datetime.now(timezone.utc)
        next_payload = {**after_payload}
        next_payload["version"] = saved_at.strftime("%Y-%m-%d")
        next_payload["checklist_version"] = next_payload["version"]
        next_payload["source"] = "qr_bulk_update_api"
        next_payload["applied_at"] = saved_at.isoformat()
        persisted = _persist_ops_special_checklists_payload(next_payload)
        metadata_payload = next_payload
        saved = True
        saved_path = persisted.as_posix()

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "create_missing": create_missing,
        "allow_placeholder_values": allow_placeholder_values,
        "saved": saved,
        "saved_path": saved_path,
        **_build_ops_checklist_response_meta(
            metadata_payload,
            endpoint="/api/ops/inspections/checklists/qr-assets/bulk-update",
        ),
        "summary": {
            "requested_count": len(updates_raw),
            "applied_count": applied_count,
            "updated_count": updated_count,
            "created_count": created_count,
            "skipped_count": len(skipped_rows),
            "invalid_count": len(invalid_rows),
            "placeholder_row_count_before": len(before_placeholder_rows),
            "placeholder_row_count_after": len(after_placeholder_rows),
            "placeholder_row_resolved": max(0, len(before_placeholder_rows) - len(after_placeholder_rows)),
            "unknown_default_item_count_before": unknown_default_before,
            "unknown_default_item_count_after": unknown_default_after,
        },
        "changes": changed_rows,
        "skipped": skipped_rows,
        "invalid_rows": invalid_rows,
        "remaining_placeholder_rows": after_placeholder_rows[:20],
    }


def _build_system_main_tabs_html(service_info: dict[str, str], *, initial_tab: str) -> str:
    return _web_build_system_main_tabs_html(service_info, initial_tab=initial_tab)


def _principal_to_auth_me_model(
    principal: dict[str, Any],
    endpoint: str = "/api/auth/me",
) -> AuthMeRead:
    from app.domains.iam.service import _principal_to_auth_me_model as _impl

    return _impl(principal, endpoint=endpoint)


def _attach_auth_me_meta(profile: AuthMeRead, *, endpoint: str = "/api/auth/me") -> AuthMeRead:
    from app.domains.iam.service import _attach_auth_me_meta as _impl

    return _impl(profile, endpoint=endpoint)


def _enforce_active_token_quota(
    *,
    conn: Any,
    user_id: int,
    now: datetime,
    keep_token_ids: set[int] | None = None,
) -> list[int]:
    from app.domains.iam.service import _enforce_active_token_quota as _impl

    return _impl(conn=conn, user_id=user_id, now=now, keep_token_ids=keep_token_ids)



def _build_ops_runbook_checks_snapshot(
    *,
    now: datetime | None = None,
    horizon_minutes: int = 90,
) -> dict[str, Any]:
    from app.domains.ops.router_governance import _build_ops_runbook_checks_snapshot as _impl

    return _impl(now=now, horizon_minutes=horizon_minutes)


def _build_ops_security_posture_snapshot(*, now: datetime | None = None) -> dict[str, Any]:
    from app.domains.ops.router_governance import _build_ops_security_posture_snapshot as _impl

    return _impl(now=now)




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


from app.domains.iam.router_auth import router as iam_auth_router
from app.domains.iam.router_admin import router as iam_admin_router
from app.domains.adoption.router_ops import build_router as build_adoption_ops_router
from app.domains.adoption.router_tracker import build_router as build_adoption_tracker_router
from app.domains.ops.router_core import router as ops_core_router
from app.domains.ops.router_governance import router as ops_governance_router
from app.domains.ops.router_alerts import admin_router as ops_sla_admin_router, router as ops_alerts_router
from app.domains.ops.router_reporting import build_router as build_ops_reporting_router
from app.domains.ops.router_tutorial import build_router as build_ops_tutorial_router
from app.domains.public.router import PublicRouteDeps, build_router as build_public_router

public_router = build_public_router(
    PublicRouteDeps(
        service_info_payload=_service_info_payload,
        facility_modules_payload=_facility_modules_payload,
        build_public_modules_html=_build_public_modules_html,
        build_tutorial_simulator_payload=_build_tutorial_simulator_payload,
        build_tutorial_simulator_html=_build_tutorial_simulator_html,
        build_tutorial_guide_html=_web_build_tutorial_guide_html,
        build_public_day1_onboarding_payload=_build_public_day1_onboarding_payload,
        build_public_glossary_payload=_build_public_glossary_payload,
        tutorial_simulator_sample_files_payload=_tutorial_simulator_sample_files_payload,
        find_tutorial_simulator_sample_file=_find_tutorial_simulator_sample_file,
        tutorial_simulator_sample_allowed_content_types=TUTORIAL_SIMULATOR_SAMPLE_ALLOWED_CONTENT_TYPES,
        build_system_main_tabs_html=lambda service_info, initial_tab: _build_system_main_tabs_html(
            service_info,
            initial_tab=initial_tab,
        ),
        build_facility_console_html=_build_facility_console_html,
        build_facility_console_guide_html=_build_facility_console_guide_html,
        build_iam_guide_html=_build_iam_guide_html,
        build_public_main_page_html=_build_public_main_page_html,
        adoption_plan_payload=_adoption_plan_payload,
        adoption_plan_start=ADOPTION_PLAN_START,
        adoption_plan_end=ADOPTION_PLAN_END,
        build_adoption_plan_schedule_csv=_build_adoption_plan_schedule_csv,
        build_adoption_plan_schedule_ics=_build_adoption_plan_schedule_ics,
        week_payload_builders={
            'w02': _adoption_w02_payload,
            'w03': _adoption_w03_payload,
            'w04': _adoption_w04_payload,
            'w05': _adoption_w05_payload,
            'w06': _adoption_w06_payload,
            'w07': _adoption_w07_payload,
            'w08': _adoption_w08_payload,
            'w09': _adoption_w09_payload,
            'w10': _adoption_w10_payload,
            'w11': _adoption_w11_payload,
            'w12': _adoption_w12_payload,
            'w13': _adoption_w13_payload,
            'w14': _adoption_w14_payload,
            'w15': _adoption_w15_payload,
        },
        week_checklist_csv_builders={
            'w02': _build_adoption_w02_checklist_csv,
            'w03': _build_adoption_w03_checklist_csv,
            'w04': _build_adoption_w04_checklist_csv,
            'w06': _build_adoption_w06_checklist_csv,
            'w07': _build_adoption_w07_checklist_csv,
            'w08': _build_adoption_w08_checklist_csv,
            'w09': _build_adoption_w09_checklist_csv,
            'w10': _build_adoption_w10_checklist_csv,
            'w11': _build_adoption_w11_checklist_csv,
            'w12': _build_adoption_w12_checklist_csv,
            'w13': _build_adoption_w13_checklist_csv,
            'w14': _build_adoption_w14_checklist_csv,
            'w15': _build_adoption_w15_checklist_csv,
        },
        week_schedule_ics_builders={
            'w02': _build_adoption_w02_schedule_ics,
            'w03': _build_adoption_w03_schedule_ics,
            'w04': _build_adoption_w04_schedule_ics,
            'w05': _build_adoption_w05_schedule_ics,
            'w06': _build_adoption_w06_schedule_ics,
            'w07': _build_adoption_w07_schedule_ics,
            'w08': _build_adoption_w08_schedule_ics,
            'w09': _build_adoption_w09_schedule_ics,
            'w10': _build_adoption_w10_schedule_ics,
            'w11': _build_adoption_w11_schedule_ics,
            'w12': _build_adoption_w12_schedule_ics,
            'w13': _build_adoption_w13_schedule_ics,
            'w14': _build_adoption_w14_schedule_ics,
            'w15': _build_adoption_w15_schedule_ics,
        },
        build_w04_common_mistakes_payload=_build_w04_common_mistakes_payload,
        build_w04_common_mistakes_html=_build_w04_common_mistakes_html,
        build_adoption_w05_missions_csv=_build_adoption_w05_missions_csv,
        w02_sample_files_payload=_w02_sample_files_payload,
        find_w02_sample_file=_find_w02_sample_file,
        evidence_allowed_content_types=EVIDENCE_ALLOWED_CONTENT_TYPES,
        safe_download_filename=_safe_download_filename,
        post_mvp_payload=_post_mvp_payload,
        post_mvp_plan_start=POST_MVP_PLAN_START,
        post_mvp_plan_end=POST_MVP_PLAN_END,
        build_post_mvp_backlog_csv=_build_post_mvp_backlog_csv,
        build_post_mvp_release_ics=_build_post_mvp_release_ics,
    )
)

app.include_router(iam_auth_router)
app.include_router(ops_core_router)
app.include_router(ops_governance_router)
app.include_router(ops_alerts_router)
ops_reporting_router = build_ops_reporting_router(globals())
ops_tutorial_router = build_ops_tutorial_router(globals())
adoption_router = build_adoption_tracker_router(globals())
adoption_ops_router = build_adoption_ops_router(globals())
app.include_router(ops_reporting_router)
app.include_router(ops_tutorial_router)
app.include_router(iam_admin_router)
app.include_router(ops_sla_admin_router)
app.include_router(adoption_router)
app.include_router(adoption_ops_router)
app.include_router(public_router)



