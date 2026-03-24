import asyncio
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
    ops_checklist_set_items,
    ops_checklist_set_revisions,
    ops_checklist_sets,
    ops_equipment_assets,
    ops_qr_assets,
    ops_qr_asset_revisions,
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
    facility_console_script_text as _web_facility_console_script_text,
    facility_console_script_version as _web_facility_console_script_version,
)
from app.web.iam_guide import build_iam_guide_html as _web_build_iam_guide_html
from app.web.main_tabs import (
    build_shared_tracker_execution_box_html as _web_build_shared_tracker_execution_box_html,
    build_system_main_tabs_html as _web_build_system_main_tabs_html,
    main_tabs_script_text as _web_main_tabs_script_text,
    main_tabs_script_version as _web_main_tabs_script_version,
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
OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_ENABLED = _env_bool(
    "OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_ENABLED",
    ENV_NAME in {"prod", "production"},
)
OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_INTERVAL_MINUTES = _env_int(
    "OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_INTERVAL_MINUTES",
    30,
    min_value=1,
)
OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_LIMIT = _env_int(
    "OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_LIMIT",
    100,
    min_value=1,
)
OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_SITE = getenv("OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_SITE", "").strip() or None
OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_INITIAL_DELAY_SEC = _env_int(
    "OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_INITIAL_DELAY_SEC",
    60,
    min_value=0,
)
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
DEPLOY_SMOKE_ARCHIVE_ENABLED = _env_bool("DEPLOY_SMOKE_ARCHIVE_ENABLED", True)
DEPLOY_SMOKE_ARCHIVE_PATH = getenv("DEPLOY_SMOKE_ARCHIVE_PATH", "data/deploy-smoke-archives").strip() or "data/deploy-smoke-archives"
DEPLOY_SMOKE_ARCHIVE_RETENTION_DAYS = _env_int("DEPLOY_SMOKE_ARCHIVE_RETENTION_DAYS", 30, min_value=1)
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
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Origin-Agent-Cluster": "?1",
    "X-Permitted-Cross-Domain-Policies": "none",
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
        "official_docs:read",
        "official_docs:write",
        "official_docs:close",
        "reports:read",
        "reports:export",
        "billing:read",
        "billing:write",
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
        "official_docs:read",
        "official_docs:write",
        "official_docs:close",
        "billing:read",
        "billing:write",
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
        "official_docs:read",
        "reports:read",
        "reports:export",
        "billing:read",
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
OPS_MASTER_LIFECYCLE_ACTIVE = "active"
OPS_MASTER_LIFECYCLE_RETIRED = "retired"
OPS_MASTER_LIFECYCLE_REPLACED = "replaced"
OPS_MASTER_LIFECYCLE_SET = {
    OPS_MASTER_LIFECYCLE_ACTIVE,
    OPS_MASTER_LIFECYCLE_RETIRED,
    OPS_MASTER_LIFECYCLE_REPLACED,
}
OPS_CHECKLIST_REVISION_STATUS_DRAFT = "draft"
OPS_CHECKLIST_REVISION_STATUS_PENDING = "pending"
OPS_CHECKLIST_REVISION_STATUS_APPROVED = "approved"
OPS_CHECKLIST_REVISION_STATUS_REJECTED = "rejected"
OPS_CHECKLIST_REVISION_STATUS_SET = {
    OPS_CHECKLIST_REVISION_STATUS_DRAFT,
    OPS_CHECKLIST_REVISION_STATUS_PENDING,
    OPS_CHECKLIST_REVISION_STATUS_APPROVED,
    OPS_CHECKLIST_REVISION_STATUS_REJECTED,
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

from app.domains.adoption.content import *  # noqa: F403

def _latest_job_run_for_name(job_name: str) -> JobRunRead | None:
    return _ops_remediation_service_module()._latest_job_run_for_name(
        job_name,
    )

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

def _effective_permissions(role: str, custom: list[str]) -> list[str]:
    from app.domains.iam.security import _effective_permissions as _impl
    return _impl(role, custom)

def _principal_role(principal: dict[str, Any]) -> str:
    from app.domains.iam.security import _principal_role as _impl
    return _impl(principal)

def _require_user_management_access(principal: dict[str, Any]) -> None:
    from app.domains.iam.security import _require_user_management_access as _impl
    return _impl(principal)

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

def _normalize_admin_username(value: str) -> str:
    from app.domains.iam.security import _normalize_admin_username as _impl
    return _impl(value)

def _validate_admin_password_value(password: str) -> str:
    from app.domains.iam.security import _validate_admin_password_value as _impl
    return _impl(password)

def _hash_password(password: str) -> str:
    from app.domains.iam.security import _hash_password as _impl
    return _impl(password)

def _verify_password(password: str, encoded_hash: str) -> bool:
    from app.domains.iam.security import _verify_password as _impl
    return _impl(password, encoded_hash)

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

def _normalize_evidence_storage_backend(value: str) -> str:
    return _ops_inspection_service_module()._normalize_evidence_storage_backend(
        value,
    )

def _extract_ops_snapshot_values(parsed_ops_notes: dict[str, Any] | None) -> dict[str, str | int | None]:
    return _ops_inspection_service_module()._extract_ops_snapshot_values(
        parsed_ops_notes,
    )

def _ops_snapshot_values_from_inspection_row(row: dict[str, Any] | None) -> dict[str, str | int | None]:
    return _ops_inspection_service_module()._ops_snapshot_values_from_inspection_row(
        row,
    )

def _resolve_ops_master_asset_ids(
    *,
    payload: InspectionCreate,
    parsed_ops_notes: dict[str, Any] | None,
    ops_snapshot: dict[str, str | int | None],
) -> dict[str, int | None]:
    meta = parsed_ops_notes.get("meta") if isinstance(parsed_ops_notes, dict) else {}
    snapshot_qr_id = str(ops_snapshot.get("qr_id") or "").strip()
    snapshot_equipment = str(ops_snapshot.get("equipment_snapshot") or "").strip()
    snapshot_location = str(ops_snapshot.get("equipment_location_snapshot") or "").strip()
    snapshot_checklist_set_id = str(ops_snapshot.get("checklist_set_id") or "").strip()

    requested_qr_asset_id = int(payload.qr_asset_id) if payload.qr_asset_id is not None else None
    requested_equipment_id = int(payload.equipment_id) if payload.equipment_id is not None else None

    resolved_qr_asset_id: int | None = None
    resolved_equipment_id: int | None = None

    with get_conn() as conn:
        qr_row = None
        if requested_qr_asset_id is not None:
            qr_row = conn.execute(
                select(ops_qr_assets).where(ops_qr_assets.c.id == requested_qr_asset_id).limit(1)
            ).mappings().first()
            if qr_row is None:
                raise HTTPException(status_code=422, detail="qr_asset_id is unknown")
            if str(qr_row.get("lifecycle_state") or OPS_MASTER_LIFECYCLE_ACTIVE) != OPS_MASTER_LIFECYCLE_ACTIVE:
                raise HTTPException(status_code=422, detail="qr_asset_id is not active")
        elif snapshot_qr_id:
            qr_row = conn.execute(
                select(ops_qr_assets).where(ops_qr_assets.c.qr_id == snapshot_qr_id).limit(1)
            ).mappings().first()
            if qr_row is not None and str(qr_row.get("lifecycle_state") or OPS_MASTER_LIFECYCLE_ACTIVE) != OPS_MASTER_LIFECYCLE_ACTIVE:
                raise HTTPException(status_code=422, detail="meta.qr_id is not active")

        if qr_row is not None:
            resolved_qr_asset_id = int(qr_row["id"])
            qr_qr_id = str(qr_row.get("qr_id") or "").strip()
            qr_equipment_id = int(qr_row.get("equipment_id") or 0) or None
            qr_equipment_snapshot = str(qr_row.get("equipment_snapshot") or "").strip()
            qr_location_snapshot = str(qr_row.get("equipment_location_snapshot") or "").strip()
            qr_checklist_set_id = str(qr_row.get("checklist_set_id") or "").strip()

            if snapshot_qr_id and qr_qr_id != snapshot_qr_id:
                raise HTTPException(status_code=422, detail="qr_asset_id does not match meta.qr_id")
            if requested_equipment_id is not None and qr_equipment_id is not None and qr_equipment_id != requested_equipment_id:
                raise HTTPException(status_code=422, detail="equipment_id does not match qr_asset_id")
            if snapshot_equipment and qr_equipment_snapshot and qr_equipment_snapshot != snapshot_equipment:
                raise HTTPException(status_code=422, detail="qr_asset_id does not match meta.equipment")
            if snapshot_location and qr_location_snapshot and qr_location_snapshot != snapshot_location:
                raise HTTPException(status_code=422, detail="qr_asset_id does not match meta.equipment_location")
            if snapshot_checklist_set_id and qr_checklist_set_id and qr_checklist_set_id != snapshot_checklist_set_id:
                raise HTTPException(status_code=422, detail="qr_asset_id does not match meta.checklist_set_id")
            if requested_equipment_id is None and qr_equipment_id is not None:
                requested_equipment_id = qr_equipment_id

        equipment_row = None
        if requested_equipment_id is not None:
            equipment_row = conn.execute(
                select(ops_equipment_assets).where(ops_equipment_assets.c.id == requested_equipment_id).limit(1)
            ).mappings().first()
            if equipment_row is None:
                raise HTTPException(status_code=422, detail="equipment_id is unknown")
            if str(equipment_row.get("lifecycle_state") or OPS_MASTER_LIFECYCLE_ACTIVE) != OPS_MASTER_LIFECYCLE_ACTIVE:
                raise HTTPException(status_code=422, detail="equipment_id is not active")
        elif snapshot_equipment:
            equipment_key = _normalize_ops_equipment_key(snapshot_equipment, snapshot_location or payload.location)
            equipment_row = conn.execute(
                select(ops_equipment_assets).where(ops_equipment_assets.c.equipment_key == equipment_key).limit(1)
            ).mappings().first()
            if equipment_row is not None and str(equipment_row.get("lifecycle_state") or OPS_MASTER_LIFECYCLE_ACTIVE) != OPS_MASTER_LIFECYCLE_ACTIVE:
                raise HTTPException(status_code=422, detail="meta.equipment is not active")

        if equipment_row is not None:
            resolved_equipment_id = int(equipment_row["id"])
            equipment_name = str(equipment_row.get("equipment_name") or "").strip()
            location_name = str(equipment_row.get("location_name") or "").strip()
            if snapshot_equipment and equipment_name and equipment_name != snapshot_equipment:
                raise HTTPException(status_code=422, detail="equipment_id does not match meta.equipment")
            if snapshot_location and location_name and location_name != snapshot_location:
                raise HTTPException(status_code=422, detail="equipment_id does not match meta.equipment_location")

        if snapshot_checklist_set_id:
            checklist_row = conn.execute(
                select(ops_checklist_sets).where(ops_checklist_sets.c.set_id == snapshot_checklist_set_id).limit(1)
            ).mappings().first()
            if checklist_row is None:
                raise HTTPException(status_code=422, detail="checklist_set_id is unknown")
            if str(checklist_row.get("lifecycle_state") or OPS_MASTER_LIFECYCLE_ACTIVE) != OPS_MASTER_LIFECYCLE_ACTIVE:
                raise HTTPException(status_code=422, detail="checklist_set_id is not active")

    return {
        "equipment_id": resolved_equipment_id,
        "qr_asset_id": resolved_qr_asset_id,
    }

def _row_to_read_model(row: dict[str, Any]) -> InspectionRead:
    return _ops_inspection_service_module()._row_to_read_model(
        row,
    )

def _row_to_inspection_evidence_model(row: dict[str, Any]) -> InspectionEvidenceRead:
    return _ops_inspection_service_module()._row_to_inspection_evidence_model(
        row,
    )

def _load_principal_by_token(token: str) -> dict[str, Any] | None:
    from app.domains.iam.security import _load_principal_by_token as _impl
    return _impl(token)

def get_current_admin(
    x_admin_token: Annotated[str | None, Header(alias="X-Admin-Token")] = None,
) -> dict[str, Any]:
    from app.domains.iam.security import get_current_admin as _impl
    return _impl(x_admin_token)

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

def _row_to_admin_audit_log_model(row: dict[str, Any]) -> AdminAuditLogRead:
    from app.domains.iam.service import _row_to_admin_audit_log_model as _impl
    return _impl(row)

def rebaseline_admin_audit_chain(
    *,
    from_month: str | None = None,
    max_rows: int = 50000,
    dry_run: bool = False,
) -> dict[str, Any]:
    from app.domains.iam.service import rebaseline_admin_audit_chain as _impl
    return _impl(from_month=from_month, max_rows=max_rows, dry_run=dry_run)

def _row_to_alert_delivery_model(row: dict[str, Any]) -> AlertDeliveryRead:
    return _ops_record_service_module()._row_to_alert_delivery_model(row)


def _row_to_sla_policy_proposal_model(row: dict[str, Any]) -> SlaPolicyProposalRead:
    return _ops_record_service_module()._row_to_sla_policy_proposal_model(row)


def _write_sla_policy_revision(
    *,
    site: str | None,
    policy: dict[str, Any],
    source_action: str,
    actor_username: str,
    note: str = "",
) -> None:
    return _ops_record_service_module()._write_sla_policy_revision(
        site=site,
        policy=policy,
        source_action=source_action,
        actor_username=actor_username,
        note=note,
    )


def _row_to_sla_policy_revision_model(row: dict[str, Any]) -> SlaPolicyRevisionRead:
    return _ops_record_service_module()._row_to_sla_policy_revision_model(row)


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

def _post_json_with_retries(
    *,
    url: str,
    payload: dict[str, Any],
    retries: int,
    timeout_sec: float,
) -> tuple[bool, str | None]:
    return _ops_alert_service_module()._post_json_with_retries(
        url=url,
        payload=payload,
        retries=retries,
        timeout_sec=timeout_sec,
    )

def _dispatch_sla_alert(
    *,
    site: str | None,
    checked_at: datetime,
    escalated_count: int,
    work_order_ids: list[int],
) -> tuple[bool, str | None, list[SlaAlertChannelResult]]:
    return _ops_alert_service_module()._dispatch_sla_alert(
        site=site,
        checked_at=checked_at,
        escalated_count=escalated_count,
        work_order_ids=work_order_ids,
    )

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

def _row_to_work_order_event_model(row: dict[str, Any]) -> WorkOrderEventRead:
    return _ops_workflow_service_module()._row_to_work_order_event_model(row)

def _row_to_workflow_lock_model(row: dict[str, Any]) -> WorkflowLockRead:
    return _ops_workflow_service_module()._row_to_workflow_lock_model(row)

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
    overdue_scheduler_task: asyncio.Task[None] | None = None
    if OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_ENABLED:
        overdue_scheduler_task = asyncio.create_task(
            _official_document_overdue_scheduler_loop(),
            name="official-document-overdue-scheduler",
        )
    try:
        yield
    finally:
        if overdue_scheduler_task is not None:
            overdue_scheduler_task.cancel()
            try:
                await overdue_scheduler_task
            except asyncio.CancelledError:
                pass

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

def _ops_record_service_module() -> Any:
    from app.domains.ops import record_service as _record_service

    _record_service.bind(globals())
    return _record_service

def _ops_alert_service_module() -> Any:
    from app.domains.ops import alert_service as _alert_service

    _alert_service.bind(globals())
    return _alert_service

def _adoption_tracker_service_module() -> Any:
    from app.domains.adoption import tracker_service as _tracker_service

    _tracker_service.bind(globals())
    return _tracker_service

def _ops_checklist_runtime_module() -> Any:
    from app.domains.ops import checklist_runtime as _checklist_runtime

    _checklist_runtime.bind(globals())
    return _checklist_runtime

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

def _month_window_bounds(*, now: datetime | None = None, month_label: str | None = None) -> tuple[str, datetime, datetime]:
    return _ops_service_module()._month_window_bounds(now=now, month_label=month_label)

def _build_deploy_checklist_payload() -> dict[str, Any]:
    return _ops_service_module()._build_deploy_checklist_payload()

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

def _build_ops_quality_report_payload(*, window: str, start: datetime, end: datetime, label: str) -> dict[str, Any]:
    return _ops_service_module()._build_ops_quality_report_payload(window=window, start=start, end=end, label=label)

def _build_ops_quality_report_csv(payload: dict[str, Any]) -> str:
    return _ops_service_module()._build_ops_quality_report_csv(payload)

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

def _build_ops_governance_gate_snapshot(*, now: datetime | None = None) -> dict[str, Any]:
    return _ops_service_module()._build_ops_governance_gate_snapshot(now=now)

def run_ops_governance_gate_job(*, trigger: str = "manual") -> dict[str, Any]:
    return _ops_service_module().run_ops_governance_gate_job(trigger=trigger)

def _latest_ops_governance_gate_payload() -> dict[str, Any] | None:
    return _ops_service_module()._latest_ops_governance_gate_payload()

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

def _hash_token(token: str) -> str:
    from app.domains.iam.security import _hash_token as _impl
    return _impl(token)

def ensure_legacy_admin_token_seed() -> None:
    from app.domains.iam.security import ensure_legacy_admin_token_seed as _impl
    return _impl()

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

def _ensure_evidence_storage_ready() -> None:
    return _ops_inspection_service_module()._ensure_evidence_storage_ready()

def _resolve_evidence_storage_abs_path(storage_key: str) -> Path | None:
    return _ops_inspection_service_module()._resolve_evidence_storage_abs_path(
        storage_key,
    )

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

def _read_evidence_blob(*, row: dict[str, Any]) -> bytes | None:
    return _ops_inspection_service_module()._read_evidence_blob(
        row=row,
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

def _has_permission(principal: dict[str, Any], permission: str) -> bool:
    from app.domains.iam.security import _has_permission as _impl
    return _impl(principal, permission)

def require_permission(permission: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
    from app.domains.iam.security import require_permission as _impl
    return _impl(permission)

def _has_explicit_permission(principal: dict[str, Any], permission: str) -> bool:
    from app.domains.iam.security import _has_explicit_permission as _impl
    return _impl(principal, permission)

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
    return _impl(
        prev_hash=prev_hash,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        status=status,
        detail_json=detail_json,
        created_at=created_at,
    )

def _verify_audit_chain(rows: list[dict[str, Any]], *, initial_prev_hash: str = "") -> dict[str, Any]:
    from app.domains.iam.service import _verify_audit_chain as _impl

    return _impl(rows, initial_prev_hash=initial_prev_hash)

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

def build_monthly_audit_archive(
    *,
    month: str | None,
    max_entries: int = 10000,
    include_entries: bool = True,
) -> dict[str, Any]:
    from app.domains.iam.service import build_monthly_audit_archive as _impl
    return _impl(month=month, max_entries=max_entries, include_entries=include_entries)

def _write_job_run(
    *,
    job_name: str,
    trigger: str,
    status: str,
    started_at: datetime,
    finished_at: datetime,
    detail: dict[str, Any] | None = None,
) -> int | None:
    return _ops_record_service_module()._write_job_run(
        job_name=job_name,
        trigger=trigger,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        detail=detail,
    )

def _row_to_job_run_model(row: dict[str, Any]) -> JobRunRead:
    return _ops_record_service_module()._row_to_job_run_model(row)

def _normalize_site_name(site: str | None) -> str | None:
    if site is None:
        return None
    value = site.strip()
    return value or None

def _normalize_mttr_slo_policy(value: Any) -> dict[str, Any]:
    return _ops_alert_service_module()._normalize_mttr_slo_policy(value)

def _ensure_mttr_slo_policy() -> tuple[dict[str, Any], datetime, str]:
    return _ops_alert_service_module()._ensure_mttr_slo_policy()

def _configured_alert_targets() -> list[str]:
    return _ops_alert_service_module()._configured_alert_targets()

def _normalize_ops_daily_check_alert_level(value: str | None) -> str:
    return _ops_alert_service_module()._normalize_ops_daily_check_alert_level(value)

def _build_alert_channel_guard_snapshot(
    *,
    event_type: str | None = None,
    lookback_days: int = 30,
    max_targets: int = 100,
    now: datetime | None = None,
) -> dict[str, Any]:
    return _ops_alert_service_module()._build_alert_channel_guard_snapshot(
        event_type=event_type,
        lookback_days=lookback_days,
        max_targets=max_targets,
        now=now,
    )

def run_alert_mttr_slo_check_job(
    *,
    event_type: str | None = None,
    force_notify: bool = False,
    trigger: str = 'manual',
) -> dict[str, Any]:
    return _ops_alert_service_module().run_alert_mttr_slo_check_job(
        event_type=event_type,
        force_notify=force_notify,
        trigger=trigger,
    )

def _dispatch_alert_event(
    *,
    event_type: str,
    payload: dict[str, Any],
) -> tuple[bool, str | None, list[SlaAlertChannelResult]]:
    return _ops_alert_service_module()._dispatch_alert_event(event_type=event_type, payload=payload)

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

def _parse_job_detail_json(raw: Any) -> dict[str, Any]:
    try:
        loaded = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        loaded = {}
    if isinstance(loaded, dict):
        return loaded
    return {}

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
        "ops_inspection_checklists_catalog_api": "/api/ops/inspections/checklists/catalog",
        "ops_inspection_checklists_import_validation_api": "/api/ops/inspections/checklists/import-validation",
        "ops_inspection_checklists_import_validation_csv_api": "/api/ops/inspections/checklists/import-validation.csv",
        "ops_inspection_checklists_equipment_assets_api": "/api/ops/inspections/checklists/equipment-assets",
        "ops_inspection_checklists_sets_api": "/api/ops/inspections/checklists/sets",
        "ops_inspection_checklists_qr_assets_api": "/api/ops/inspections/checklists/qr-assets",
        "ops_inspection_checklists_qr_revisions_api": "/api/ops/inspections/checklists/qr-assets/revisions",
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
        "official_documents_api": "/api/official-documents",
        "official_document_detail_api": "/api/official-documents/{document_id}",
        "official_document_close_api": "/api/official-documents/{document_id}/close",
        "official_document_attachments_api": "/api/official-documents/{document_id}/attachments",
        "official_document_attachment_download_api": "/api/official-documents/attachments/{attachment_id}/download",
        "official_document_attachment_zip_api": "/api/official-documents/attachments/zip",
        "official_document_registry_csv_api": "/api/official-documents/registry/csv",
        "official_document_overdue_run_api": "/api/official-documents/overdue/run",
        "official_document_overdue_status_api": "/api/official-documents/overdue/status",
        "official_document_overdue_latest_api": "/api/official-documents/overdue/latest",
        "official_document_overdue_cron_job": "python -m app.jobs.official_document_overdue",
        "official_document_overdue_scheduler_mode": (
            "background" if OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_ENABLED else "disabled"
        ),
        "official_document_monthly_report_api": "/api/reports/official-documents/monthly",
        "official_document_monthly_report_csv_api": "/api/reports/official-documents/monthly/csv",
        "official_document_monthly_report_print_html": "/reports/official-documents/monthly/print",
        "official_document_annual_report_api": "/api/reports/official-documents/annual",
        "official_document_annual_report_csv_api": "/api/reports/official-documents/annual/csv",
        "official_document_annual_report_print_html": "/reports/official-documents/annual/print",
        "integrated_monthly_report_api": "/api/reports/monthly/integrated",
        "integrated_monthly_report_csv_api": "/api/reports/monthly/integrated/csv",
        "integrated_monthly_report_pdf_api": "/api/reports/monthly/integrated/pdf",
        "integrated_monthly_report_print_html": "/reports/monthly/integrated/print",
        "integrated_annual_report_api": "/api/reports/annual/integrated",
        "integrated_annual_report_csv_api": "/api/reports/annual/integrated/csv",
        "integrated_annual_report_pdf_api": "/api/reports/annual/integrated/pdf",
        "integrated_annual_report_print_html": "/reports/annual/integrated/print",
        "billing_units_api": "/api/billing/units",
        "billing_rate_policies_api": "/api/billing/rate-policies",
        "billing_meter_readings_api": "/api/billing/meter-readings",
        "billing_common_charges_api": "/api/billing/common-charges",
        "billing_generate_run_api": "/api/billing/runs/generate",
        "billing_statements_api": "/api/billing/statements",
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
    return _ops_checklist_runtime_module()._build_ops_checklist_response_meta(payload, endpoint=endpoint)


def _default_ops_special_checklists_payload() -> dict[str, Any]:
    return _ops_checklist_runtime_module()._default_ops_special_checklists_payload()


def _resolve_ops_special_checklists_data_path() -> Path:
    return _ops_checklist_runtime_module()._resolve_ops_special_checklists_data_path()


def _persist_ops_special_checklists_payload(payload: dict[str, Any]) -> Path:
    return _ops_checklist_runtime_module()._persist_ops_special_checklists_payload(payload)


def _normalize_ops_equipment_key(equipment: Any, location: Any) -> str | None:
    return _ops_checklist_runtime_module()._normalize_ops_equipment_key(equipment, location)


def _normalize_ops_master_lifecycle_state(value: Any, *, default: str = OPS_MASTER_LIFECYCLE_ACTIVE) -> str:
    return _ops_checklist_runtime_module()._normalize_ops_master_lifecycle_state(value, default=default)


def _normalize_ops_checklist_sets(
    checklist_sets_raw: Any,
    *,
    fallback_sets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return _ops_checklist_runtime_module()._normalize_ops_checklist_sets(
        checklist_sets_raw,
        fallback_sets=fallback_sets,
    )


def _normalize_ops_special_ops_codes(ops_codes_raw: Any) -> list[dict[str, str]]:
    return _ops_checklist_runtime_module()._normalize_ops_special_ops_codes(ops_codes_raw)


def _normalize_ops_special_qr_assets(qr_assets_raw: Any) -> list[dict[str, str]]:
    return _ops_checklist_runtime_module()._normalize_ops_special_qr_assets(qr_assets_raw)


def _read_ops_special_checklists_source_payload() -> dict[str, Any]:
    return _ops_checklist_runtime_module()._read_ops_special_checklists_source_payload()


def _build_ops_checklist_item_to_set_map(payload: dict[str, Any]) -> dict[str, str]:
    return _ops_checklist_runtime_module()._build_ops_checklist_item_to_set_map(payload)


def _sync_ops_checklist_masters(payload: dict[str, Any]) -> bool:
    return _ops_checklist_runtime_module()._sync_ops_checklist_masters(payload)


def _load_ops_master_catalog_snapshot_from_db() -> dict[str, Any] | None:
    return _ops_checklist_runtime_module()._load_ops_master_catalog_snapshot_from_db()


def _sync_ops_asset_masters(payload: dict[str, Any]) -> dict[str, Any] | None:
    return _ops_checklist_runtime_module()._sync_ops_asset_masters(payload)


def _attach_ops_asset_master_ids(payload: dict[str, Any]) -> dict[str, Any]:
    return _ops_checklist_runtime_module()._attach_ops_asset_master_ids(payload)


def _build_ops_special_checklists_payload_from_masters(base_payload: dict[str, Any]) -> dict[str, Any]:
    return _ops_checklist_runtime_module()._build_ops_special_checklists_payload_from_masters(base_payload)


def _load_ops_special_checklists_payload() -> dict[str, Any]:
    return _ops_checklist_runtime_module()._load_ops_special_checklists_payload()


def _export_ops_special_checklists_payload_from_masters(*, source: str) -> Path:
    return _ops_checklist_runtime_module()._export_ops_special_checklists_payload_from_masters(source=source)


def _append_ops_import_validation_issue(
    buckets: dict[tuple[str, str, str, str], dict[str, Any]],
    *,
    severity: str,
    category: str,
    code: str,
    message: str,
    reference: str = "",
) -> None:
    return _ops_checklist_runtime_module()._append_ops_import_validation_issue(
        buckets,
        severity=severity,
        category=category,
        code=code,
        message=message,
        reference=reference,
    )


def _build_ops_checklists_import_validation_report() -> dict[str, Any]:
    return _ops_checklist_runtime_module()._build_ops_checklists_import_validation_report()


def _build_ops_checklists_import_validation_csv(report: dict[str, Any]) -> str:
    return _ops_checklist_runtime_module()._build_ops_checklists_import_validation_csv(report)


def _build_ops_checklist_item_set(payload: dict[str, Any]) -> set[str]:
    return _ops_checklist_runtime_module()._build_ops_checklist_item_set(payload)


def _build_ops_qr_placeholder_snapshot(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return _ops_checklist_runtime_module()._build_ops_qr_placeholder_snapshot(payload)


def _coerce_request_bool(value: Any, *, default: bool = False) -> bool:
    return _ops_checklist_runtime_module()._coerce_request_bool(value, default=default)


def _build_ops_qr_placeholder_report(payload: dict[str, Any]) -> dict[str, Any]:
    return _ops_checklist_runtime_module()._build_ops_qr_placeholder_report(payload)


def _record_ops_qr_asset_revisions(revisions: list[dict[str, Any]]) -> int:
    return _ops_checklist_runtime_module()._record_ops_qr_asset_revisions(revisions)


def _apply_ops_qr_asset_bulk_update_request(request_payload: dict[str, Any]) -> dict[str, Any]:
    return _ops_checklist_runtime_module()._apply_ops_qr_asset_bulk_update_request(request_payload)

def _qr_asset_placeholder_flags(row: dict[str, Any]) -> list[str]:
    return _ops_checklist_runtime_module()._qr_asset_placeholder_flags(row)
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


def run_official_document_overdue_sync_job(
    *,
    site: str | None = None,
    dry_run: bool = False,
    limit: int = 100,
    trigger: str = "manual",
    principal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from app.domains.ops.router_official_documents import run_official_document_overdue_sync_job as _impl

    return _impl(
        site=site,
        dry_run=dry_run,
        limit=limit,
        trigger=trigger,
        principal=principal,
    )


async def _official_document_overdue_scheduler_loop() -> None:
    initial_delay = max(0, OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_INITIAL_DELAY_SEC)
    interval_seconds = max(60, OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_INTERVAL_MINUTES * 60)
    if initial_delay > 0:
        await asyncio.sleep(initial_delay)
    while True:
        try:
            run_official_document_overdue_sync_job(
                site=OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_SITE,
                dry_run=False,
                limit=OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_LIMIT,
                trigger="scheduler",
            )
        except Exception:
            # Job failures are recorded in job_runs by the job wrapper itself.
            pass
        await asyncio.sleep(interval_seconds)




def _build_alert_channel_kpi_snapshot(
    *,
    event_type: str | None = None,
    windows: list[int] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    return _ops_alert_service_module()._build_alert_channel_kpi_snapshot(
        event_type=event_type,
        windows=windows,
        now=now,
    )


def _compute_recovery_minutes_stats(recovery_minutes: list[float]) -> dict[str, float | None]:
    return _ops_alert_service_module()._compute_recovery_minutes_stats(recovery_minutes)


def _build_alert_channel_mttr_snapshot(
    *,
    event_type: str | None = None,
    windows: list[int] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    return _ops_alert_service_module()._build_alert_channel_mttr_snapshot(
        event_type=event_type,
        windows=windows,
        now=now,
    )


def build_dashboard_trends(
    *,
    site: str | None,
    days: int,
    allowed_sites: list[str] | None = None,
) -> DashboardTrendsRead:
    from app.domains.ops.reporting_service import build_dashboard_trends as _impl

    return _impl(site=site, days=days, allowed_sites=allowed_sites)


def build_ops_handover_brief(
    *,
    site: str | None,
    window_hours: int,
    due_soon_hours: int,
    max_items: int,
    allowed_sites: list[str] | None = None,
) -> OpsHandoverBriefRead:
    from app.domains.ops.reporting_service import build_ops_handover_brief as _impl

    return _impl(
        site=site,
        window_hours=window_hours,
        due_soon_hours=due_soon_hours,
        max_items=max_items,
        allowed_sites=allowed_sites,
    )


def _build_handover_brief_csv(report: OpsHandoverBriefRead) -> str:
    from app.domains.ops.reporting_service import _build_handover_brief_csv as _impl

    return _impl(report)


def _build_handover_brief_pdf(report: OpsHandoverBriefRead) -> bytes:
    from app.domains.ops.reporting_service import _build_handover_brief_pdf as _impl

    return _impl(report)


from app.domains.iam.router_auth import router as iam_auth_router
from app.domains.iam.router_admin import router as iam_admin_router
from app.domains.adoption.router_ops import build_router as build_adoption_ops_router
from app.domains.adoption.router_tracker import build_router as build_adoption_tracker_router
from app.domains.complaints.router import router as complaints_router
from app.domains.ops.router_billing import router as ops_billing_router
from app.domains.ops.router_core import router as ops_core_router
from app.domains.ops.router_governance import router as ops_governance_router
from app.domains.ops.router_official_documents import router as ops_official_documents_router
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
        main_tabs_script_text=_web_main_tabs_script_text,
        main_tabs_script_version=_web_main_tabs_script_version,
        build_facility_console_html=_build_facility_console_html,
        facility_console_script_text=_web_facility_console_script_text,
        facility_console_script_version=_web_facility_console_script_version,
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
app.include_router(complaints_router)
app.include_router(ops_billing_router)
app.include_router(ops_core_router)
app.include_router(ops_governance_router)
app.include_router(ops_official_documents_router)
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


