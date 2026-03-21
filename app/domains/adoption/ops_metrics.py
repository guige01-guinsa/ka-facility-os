"""Adoption ops analytics helpers extracted from app.main."""

from __future__ import annotations

import json
import math
import statistics
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import insert, select, update

from app.domains.adoption.content import *  # noqa: F403
from app.runtime_bridge import export_main_symbols_with_prefixes

_REQUIRED_MAIN_NAMES = (
    "SITE_SCOPE_ALL",
    "_as_datetime",
    "_as_optional_datetime",
    "_build_w07_sla_quality_snapshot",
    "_normalize_site_name",
    "_parse_job_detail_json",
    "_resolve_effective_site_scope",
    "_site_scope_text_to_list",
    "_to_json_text",
    "admin_audit_logs",
    "admin_tokens",
    "admin_users",
    "adoption_w10_tracker_items",
    "adoption_w11_tracker_items",
    "adoption_w12_tracker_items",
    "adoption_w13_tracker_items",
    "adoption_w14_tracker_items",
    "adoption_w15_tracker_items",
    "alert_deliveries",
    "get_conn",
    "inspections",
    "job_runs",
    "sla_policies",
    "work_order_events",
    "work_orders",
)
_REQUIRED_MAIN_PREFIXES = (
    "W07_",
    "W09_",
    "W10_",
    "W11_",
    "W12_",
    "W13_",
    "W14_",
    "W15_",
)

export_main_symbols_with_prefixes(
    globals(),
    names=_REQUIRED_MAIN_NAMES,
    prefixes=_REQUIRED_MAIN_PREFIXES,
)

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
    return _ops_alert_service_module()._latest_mttr_slo_breach_finished_at(max_rows=max_rows)


def _detect_alert_target_kind(url: str) -> str:
    return _ops_alert_service_module()._detect_alert_target_kind(url)


def _parse_alert_target_spec(raw_value: str) -> dict[str, str] | None:
    return _ops_alert_service_module()._parse_alert_target_spec(raw_value)


def _configured_alert_target_configs() -> list[dict[str, str]]:
    return _ops_alert_service_module()._configured_alert_target_configs()




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




