"""Adoption content, payload, and public export builders."""

from __future__ import annotations

import csv
import io
import json
from datetime import date, datetime, timedelta, timezone
from typing import Any

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
        "id": "household-complaints",
        "name": "Household Complaints",
        "name_ko": "세대 민원처리",
        "description": "세대 민원 접수, 상태 변경, 사진 첨부, 문자 발송, 비용 입력을 현장용 화면과 API로 운영합니다.",
        "kpi_hint": "Resident complaint close rate",
        "links": [
            {"label": "Field Console", "href": "/web/complaints"},
            {"label": "Complaint API", "href": "/api/complaints"},
            {
                "label": "Household History",
                "href": "/api/complaints/households/history?site=%EC%97%B0%EC%82%B0%EB%8D%94%EC%83%B5&building=101%EB%8F%99&unit_number=503%ED%98%B8",
            },
        ],
    },
    {
        "id": "facility-team-ops",
        "name": "Facility Team Ops",
        "name_ko": "시설팀 운영",
        "description": "현장기록, 시설위치, 공구/자재 관리를 한 화면에서 운영하고, 기존 작업지시·점검·민원과 읽기 전용으로 연결합니다.",
        "kpi_hint": "Field record completion rate",
        "links": [
            {"label": "Team Ops Console", "href": "/web/team-ops"},
            {"label": "Team Ops Dashboard API", "href": "/api/team-ops/dashboard?site=%EC%97%B0%EC%82%B0%EB%8D%94%EC%83%B5&range_key=week"},
            {"label": "Team Ops Logs API", "href": "/api/team-ops/logs?site=%EC%97%B0%EC%82%B0%EB%8D%94%EC%83%B5"},
        ],
    },
    {
        "id": "utility-billing",
        "name": "Utility Billing",
        "name_ko": "전기/수도 요금부과",
        "description": "세대 등록, 검침 입력, 공용요금 면적배부, 월 부과 생성까지 전기/수도 요금 업무를 운영합니다.",
        "kpi_hint": "Monthly billing close rate",
        "links": [
            {"label": "Billing Units", "href": "/api/billing/units"},
            {"label": "Rate Policies", "href": "/api/billing/rate-policies"},
            {"label": "Meter Readings", "href": "/api/billing/meter-readings"},
            {"label": "Common Charges", "href": "/api/billing/common-charges"},
            {"label": "Billing Statements", "href": "/api/billing/statements"},
        ],
    },
    {
        "id": "official-documents",
        "name": "Official Documents",
        "name_ko": "기관별 공문관리",
        "description": "기관별 공문 접수, 점검/작업지시 연동, 종결보고서 관리와 월/연차 출력까지 운영합니다.",
        "kpi_hint": "Official document close rate",
        "links": [
            {"label": "Official Documents", "href": "/api/official-documents"},
            {"label": "Overdue Sync", "href": "/api/official-documents/overdue/run"},
            {"label": "Monthly Closure Report", "href": "/api/reports/official-documents/monthly"},
            {"label": "Annual Closure Report", "href": "/api/reports/official-documents/annual"},
            {"label": "Integrated Monthly Report", "href": "/api/reports/monthly/integrated"},
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

__all__ = [
    'ADOPTION_PLAN_START',
    'ADOPTION_PLAN_END',
    'ADOPTION_WEEKLY_EXECUTION',
    'ADOPTION_TRAINING_OUTLINE',
    'ADOPTION_KPI_DASHBOARD_ITEMS',
    'ADOPTION_PROMOTION_PACK',
    'ADOPTION_EDUCATION_PACK',
    'ADOPTION_FUN_PACK',
    'ADOPTION_WORKFLOW_LOCK_MATRIX',
    'W02_EVIDENCE_MAX_BYTES',
    'W02_EVIDENCE_REQUIRED_ITEM_TYPES',
    'W02_SITE_COMPLETION_STATUS_ACTIVE',
    'W02_SITE_COMPLETION_STATUS_COMPLETED',
    'W02_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS',
    'W02_SITE_COMPLETION_STATUS_SET',
    'W02_TRACKER_STATUS_BLOCKED',
    'W02_TRACKER_STATUS_DONE',
    'W02_TRACKER_STATUS_IN_PROGRESS',
    'W02_TRACKER_STATUS_PENDING',
    'W02_TRACKER_STATUS_SET',
    'W03_EVIDENCE_MAX_BYTES',
    'W03_EVIDENCE_REQUIRED_ITEM_TYPES',
    'W03_SITE_COMPLETION_STATUS_ACTIVE',
    'W03_SITE_COMPLETION_STATUS_COMPLETED',
    'W03_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS',
    'W03_SITE_COMPLETION_STATUS_SET',
    'W03_TRACKER_STATUS_BLOCKED',
    'W03_TRACKER_STATUS_DONE',
    'W03_TRACKER_STATUS_IN_PROGRESS',
    'W03_TRACKER_STATUS_PENDING',
    'W03_TRACKER_STATUS_SET',
    'W04_EVIDENCE_MAX_BYTES',
    'W04_EVIDENCE_REQUIRED_ITEM_TYPES',
    'W04_SITE_COMPLETION_STATUS_ACTIVE',
    'W04_SITE_COMPLETION_STATUS_COMPLETED',
    'W04_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS',
    'W04_SITE_COMPLETION_STATUS_SET',
    'W04_TRACKER_STATUS_BLOCKED',
    'W04_TRACKER_STATUS_DONE',
    'W04_TRACKER_STATUS_IN_PROGRESS',
    'W04_TRACKER_STATUS_PENDING',
    'W04_TRACKER_STATUS_SET',
    'W07_EVIDENCE_MAX_BYTES',
    'W07_EVIDENCE_REQUIRED_ITEM_TYPES',
    'W07_SITE_COMPLETION_STATUS_ACTIVE',
    'W07_SITE_COMPLETION_STATUS_COMPLETED',
    'W07_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS',
    'W07_SITE_COMPLETION_STATUS_SET',
    'W07_TRACKER_STATUS_BLOCKED',
    'W07_TRACKER_STATUS_DONE',
    'W07_TRACKER_STATUS_IN_PROGRESS',
    'W07_TRACKER_STATUS_PENDING',
    'W07_TRACKER_STATUS_SET',
    'W09_EVIDENCE_MAX_BYTES',
    'W09_EVIDENCE_REQUIRED_ITEM_TYPES',
    'W09_SITE_COMPLETION_STATUS_ACTIVE',
    'W09_SITE_COMPLETION_STATUS_COMPLETED',
    'W09_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS',
    'W09_SITE_COMPLETION_STATUS_SET',
    'W09_TRACKER_STATUS_BLOCKED',
    'W09_TRACKER_STATUS_DONE',
    'W09_TRACKER_STATUS_IN_PROGRESS',
    'W09_TRACKER_STATUS_PENDING',
    'W09_TRACKER_STATUS_SET',
    'W10_EVIDENCE_MAX_BYTES',
    'W10_EVIDENCE_REQUIRED_ITEM_TYPES',
    'W10_SITE_COMPLETION_STATUS_ACTIVE',
    'W10_SITE_COMPLETION_STATUS_COMPLETED',
    'W10_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS',
    'W10_SITE_COMPLETION_STATUS_SET',
    'W10_TRACKER_STATUS_BLOCKED',
    'W10_TRACKER_STATUS_DONE',
    'W10_TRACKER_STATUS_IN_PROGRESS',
    'W10_TRACKER_STATUS_PENDING',
    'W10_TRACKER_STATUS_SET',
    'W11_EVIDENCE_MAX_BYTES',
    'W11_EVIDENCE_REQUIRED_ITEM_TYPES',
    'W11_SITE_COMPLETION_STATUS_ACTIVE',
    'W11_SITE_COMPLETION_STATUS_COMPLETED',
    'W11_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS',
    'W11_SITE_COMPLETION_STATUS_SET',
    'W11_TRACKER_STATUS_BLOCKED',
    'W11_TRACKER_STATUS_DONE',
    'W11_TRACKER_STATUS_IN_PROGRESS',
    'W11_TRACKER_STATUS_PENDING',
    'W11_TRACKER_STATUS_SET',
    'W12_EVIDENCE_MAX_BYTES',
    'W12_EVIDENCE_REQUIRED_ITEM_TYPES',
    'W12_SITE_COMPLETION_STATUS_ACTIVE',
    'W12_SITE_COMPLETION_STATUS_COMPLETED',
    'W12_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS',
    'W12_SITE_COMPLETION_STATUS_SET',
    'W12_TRACKER_STATUS_BLOCKED',
    'W12_TRACKER_STATUS_DONE',
    'W12_TRACKER_STATUS_IN_PROGRESS',
    'W12_TRACKER_STATUS_PENDING',
    'W12_TRACKER_STATUS_SET',
    'W13_EVIDENCE_MAX_BYTES',
    'W13_EVIDENCE_REQUIRED_ITEM_TYPES',
    'W13_SITE_COMPLETION_STATUS_ACTIVE',
    'W13_SITE_COMPLETION_STATUS_COMPLETED',
    'W13_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS',
    'W13_SITE_COMPLETION_STATUS_SET',
    'W13_TRACKER_STATUS_BLOCKED',
    'W13_TRACKER_STATUS_DONE',
    'W13_TRACKER_STATUS_IN_PROGRESS',
    'W13_TRACKER_STATUS_PENDING',
    'W13_TRACKER_STATUS_SET',
    'W14_EVIDENCE_MAX_BYTES',
    'W14_EVIDENCE_REQUIRED_ITEM_TYPES',
    'W14_SITE_COMPLETION_STATUS_ACTIVE',
    'W14_SITE_COMPLETION_STATUS_COMPLETED',
    'W14_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS',
    'W14_SITE_COMPLETION_STATUS_SET',
    'W14_TRACKER_STATUS_BLOCKED',
    'W14_TRACKER_STATUS_DONE',
    'W14_TRACKER_STATUS_IN_PROGRESS',
    'W14_TRACKER_STATUS_PENDING',
    'W14_TRACKER_STATUS_SET',
    'W15_EVIDENCE_MAX_BYTES',
    'W09_KPI_POLICY_KEY_DEFAULT',
    'W09_KPI_POLICY_KEY_SITE_PREFIX',
    'W09_KPI_STATUS_GREEN',
    'W09_KPI_STATUS_YELLOW',
    'W09_KPI_STATUS_RED',
    'W10_SUPPORT_POLICY_KEY_DEFAULT',
    'W10_SUPPORT_POLICY_KEY_SITE_PREFIX',
    'W10_SUPPORT_STATUS_GREEN',
    'W10_SUPPORT_STATUS_YELLOW',
    'W10_SUPPORT_STATUS_RED',
    'W11_READINESS_POLICY_KEY_DEFAULT',
    'W11_READINESS_POLICY_KEY_SITE_PREFIX',
    'W11_READINESS_STATUS_GREEN',
    'W11_READINESS_STATUS_YELLOW',
    'W11_READINESS_STATUS_RED',
    'W12_HANDOFF_POLICY_KEY_DEFAULT',
    'W12_HANDOFF_POLICY_KEY_SITE_PREFIX',
    'W12_HANDOFF_STATUS_GREEN',
    'W12_HANDOFF_STATUS_YELLOW',
    'W12_HANDOFF_STATUS_RED',
    'W13_HANDOFF_POLICY_KEY_DEFAULT',
    'W13_HANDOFF_POLICY_KEY_SITE_PREFIX',
    'W13_HANDOFF_STATUS_GREEN',
    'W13_HANDOFF_STATUS_YELLOW',
    'W13_HANDOFF_STATUS_RED',
    'W14_STABILITY_POLICY_KEY_DEFAULT',
    'W14_STABILITY_POLICY_KEY_SITE_PREFIX',
    'W14_STABILITY_STATUS_GREEN',
    'W14_STABILITY_STATUS_YELLOW',
    'W14_STABILITY_STATUS_RED',
    'W15_EFFICIENCY_POLICY_KEY_DEFAULT',
    'W15_EFFICIENCY_POLICY_KEY_SITE_PREFIX',
    'W15_EFFICIENCY_STATUS_GREEN',
    'W15_EFFICIENCY_STATUS_YELLOW',
    'W15_EFFICIENCY_STATUS_RED',
    'W15_EVIDENCE_REQUIRED_ITEM_TYPES',
    'W15_SITE_COMPLETION_STATUS_ACTIVE',
    'W15_SITE_COMPLETION_STATUS_COMPLETED',
    'W15_SITE_COMPLETION_STATUS_COMPLETED_WITH_EXCEPTIONS',
    'W15_SITE_COMPLETION_STATUS_SET',
    'W15_TRACKER_STATUS_BLOCKED',
    'W15_TRACKER_STATUS_DONE',
    'W15_TRACKER_STATUS_IN_PROGRESS',
    'W15_TRACKER_STATUS_PENDING',
    'W15_TRACKER_STATUS_SET',
    'ADOPTION_W02_SOP_RUNBOOKS',
    'ADOPTION_W02_SANDBOX_SCENARIOS',
    'ADOPTION_W02_SCHEDULED_EVENTS',
    'W02_SAMPLE_EVIDENCE_ARTIFACTS',
    'ADOPTION_W03_KICKOFF_AGENDA',
    'ADOPTION_W03_ROLE_WORKSHOPS',
    'ADOPTION_W03_OFFICE_HOURS',
    'ADOPTION_W03_SCHEDULED_EVENTS',
    'ADOPTION_W04_COACHING_ACTIONS',
    'ADOPTION_W04_SCHEDULED_EVENTS',
    'W04_COMMON_MISTAKE_FIX_CATALOG',
    'ADOPTION_W05_ROLE_MISSIONS',
    'ADOPTION_W05_SCHEDULED_EVENTS',
    'ADOPTION_W05_HELP_DOCS',
    'ADOPTION_W06_RHYTHM_CHECKLIST',
    'ADOPTION_W06_SCHEDULED_EVENTS',
    'ADOPTION_W06_RBAC_AUDIT_CHECKLIST',
    'ADOPTION_W07_SLA_CHECKLIST',
    'ADOPTION_W07_COACHING_PLAYS',
    'ADOPTION_W07_SCHEDULED_EVENTS',
    'ADOPTION_W08_REPORT_DISCIPLINE_CHECKLIST',
    'ADOPTION_W08_DATA_QUALITY_CONTROLS',
    'ADOPTION_W08_SCHEDULED_EVENTS',
    'ADOPTION_W08_REPORTING_SOP',
    'ADOPTION_W09_KPI_THRESHOLD_MATRIX',
    'ADOPTION_W09_ESCALATION_MAP',
    'ADOPTION_W09_SCHEDULED_EVENTS',
    'ADOPTION_W10_SELF_SERVE_GUIDES',
    'ADOPTION_W10_TROUBLESHOOTING_RUNBOOK',
    'ADOPTION_W10_SCHEDULED_EVENTS',
    'ADOPTION_W11_SELF_SERVE_GUIDES',
    'ADOPTION_W11_TROUBLESHOOTING_RUNBOOK',
    'ADOPTION_W11_SCHEDULED_EVENTS',
    'ADOPTION_W12_SELF_SERVE_GUIDES',
    'ADOPTION_W12_TROUBLESHOOTING_RUNBOOK',
    'ADOPTION_W12_SCHEDULED_EVENTS',
    'ADOPTION_W13_SELF_SERVE_GUIDES',
    'ADOPTION_W13_TROUBLESHOOTING_RUNBOOK',
    'ADOPTION_W13_SCHEDULED_EVENTS',
    'ADOPTION_W14_SELF_SERVE_GUIDES',
    'ADOPTION_W14_TROUBLESHOOTING_RUNBOOK',
    'ADOPTION_W14_SCHEDULED_EVENTS',
    'ADOPTION_W15_SELF_SERVE_GUIDES',
    'ADOPTION_W15_TROUBLESHOOTING_RUNBOOK',
    'ADOPTION_W15_SCHEDULED_EVENTS',
    'FACILITY_WEB_MODULES',
    'TUTORIAL_SIMULATOR_SCENARIOS',
    'TUTORIAL_SIMULATOR_SAMPLE_FILES',
    'PUBLIC_DAY1_ONBOARDING_STEPS',
    'PUBLIC_ROLE_START_GUIDES',
    'PUBLIC_GLOSSARY_TERMS',
    'POST_MVP_PLAN_START',
    'POST_MVP_PLAN_END',
    'POST_MVP_ROADMAP_PHASES',
    'POST_MVP_EXECUTION_BACKLOG',
    'POST_MVP_RELEASE_MILESTONES',
    'POST_MVP_KPI_DASHBOARD_SPEC',
    'POST_MVP_RISK_REGISTER',
    '_adoption_plan_payload',
    '_adoption_w02_payload',
    '_adoption_w03_payload',
    '_adoption_w04_payload',
    '_build_adoption_w04_checklist_csv',
    '_build_adoption_w04_schedule_ics',
    '_build_adoption_w03_checklist_csv',
    '_build_adoption_w03_schedule_ics',
    '_adoption_w05_payload',
    '_build_adoption_w05_missions_csv',
    '_build_adoption_w05_schedule_ics',
    '_adoption_w06_payload',
    '_build_adoption_w06_checklist_csv',
    '_build_adoption_w06_schedule_ics',
    '_adoption_w07_payload',
    '_build_adoption_w07_checklist_csv',
    '_build_adoption_w07_schedule_ics',
    '_adoption_w08_payload',
    '_build_adoption_w08_checklist_csv',
    '_build_adoption_w08_schedule_ics',
    '_adoption_w09_payload',
    '_build_adoption_w09_checklist_csv',
    '_build_adoption_w09_schedule_ics',
    '_adoption_w10_payload',
    '_build_adoption_w10_checklist_csv',
    '_build_adoption_w10_schedule_ics',
    '_adoption_w11_payload',
    '_build_adoption_w11_checklist_csv',
    '_build_adoption_w11_schedule_ics',
    '_adoption_w12_payload',
    '_build_adoption_w12_checklist_csv',
    '_build_adoption_w12_schedule_ics',
    '_adoption_w13_payload',
    '_build_adoption_w13_checklist_csv',
    '_build_adoption_w13_schedule_ics',
    '_adoption_w14_payload',
    '_build_adoption_w14_checklist_csv',
    '_build_adoption_w14_schedule_ics',
    '_adoption_w15_payload',
    '_build_adoption_w15_checklist_csv',
    '_build_adoption_w15_schedule_ics',
    '_w02_sample_files_payload',
    '_find_w02_sample_file',
    '_build_adoption_w02_checklist_csv',
    '_build_adoption_w02_schedule_ics',
    '_build_adoption_plan_schedule_csv',
    '_ics_escape',
    '_build_adoption_plan_schedule_ics',
]
