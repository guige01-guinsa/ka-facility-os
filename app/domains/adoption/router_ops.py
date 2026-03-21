"""Adoption KPI and policy routes extracted from app.main."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app.domains.adoption.ops_metrics import (
    _build_w05_usage_consistency_snapshot,
    _build_w06_operational_rhythm_snapshot,
    _build_w08_report_discipline_snapshot,
    _build_w09_kpi_operation_snapshot,
    _build_w10_self_serve_snapshot,
    _build_w11_scale_readiness_snapshot,
    _build_w13_closure_handoff_snapshot,
    _build_w14_stability_sprint_snapshot,
    _build_w15_ops_efficiency_snapshot,
    _ensure_w09_kpi_policy,
    _ensure_w10_support_policy,
    _ensure_w11_readiness_policy,
    _ensure_w12_handoff_policy,
    _ensure_w13_handoff_policy,
    _ensure_w14_stability_policy,
    _ensure_w15_efficiency_policy,
    _upsert_w09_kpi_policy,
    _upsert_w10_support_policy,
    _upsert_w11_readiness_policy,
    _upsert_w12_handoff_policy,
    _upsert_w13_handoff_policy,
    _upsert_w14_stability_policy,
    _upsert_w15_efficiency_policy,
)
from app.domains.iam.core import _principal_site_scope
from app.domains.iam.security import _has_permission, _require_site_access, require_permission
from app.domains.iam.service import _write_audit_log
from app.runtime_bridge import export_main_symbols_with_prefixes


def _allowed_sites_for_principal(principal: dict[str, Any]) -> list[str] | None:
    scope = _principal_site_scope(principal)
    if "*" in scope:
        return None
    return scope


_REQUIRED_MAIN_NAMES = (
    "_build_policy_response_payload",
    "_build_w04_blocker_snapshot",
    "_build_w04_funnel_snapshot",
    "_build_w07_automation_readiness_snapshot",
    "_build_w07_sla_quality_snapshot",
    "_build_w07_weekly_archive_csv",
    "_build_w07_weekly_trends_payload",
    "_normalize_site_name",
    "_read_w07_weekly_job_runs",
    "_require_global_site_scope",
    "run_w07_sla_quality_weekly_job",
)
_REQUIRED_MAIN_PREFIXES = ("W07_",)
export_main_symbols_with_prefixes(
    globals(),
    names=_REQUIRED_MAIN_NAMES,
    prefixes=_REQUIRED_MAIN_PREFIXES,
)


def build_router(namespace: dict[str, object] | None = None) -> APIRouter:
    """Compatibility extraction layer with explicit imports and a minimal bridge."""
    router = APIRouter(prefix="/api/ops", tags=["ops"])

    @router.get("/adoption/w05/consistency")
    def get_ops_adoption_w05_consistency(
        site: Annotated[str | None, Query()] = None,
        days: Annotated[int, Query(ge=14, le=90)] = 28,
        principal: dict[str, Any] = Depends(require_permission("adoption_w05:read")),
    ) -> dict[str, Any]:
        _require_site_access(principal, site)
        allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
        snapshot = _build_w05_usage_consistency_snapshot(site=site, days=days, allowed_sites=allowed_sites)
        _write_audit_log(
            principal=principal,
            action="w05_usage_consistency_view",
            resource_type="adoption_w05_consistency",
            resource_id=site or "all",
            detail={
                "site": site,
                "window_days": int(snapshot.get("window_days") or days),
                "two_week_retention_percent": snapshot.get("metrics", {}).get("two_week_retention_percent"),
                "overdue_ratio_percent": snapshot.get("metrics", {}).get("overdue_ratio_percent"),
            },
        )
        return snapshot
    
    
    @router.get("/adoption/w06/rhythm")
    def get_ops_adoption_w06_rhythm(
        site: Annotated[str | None, Query()] = None,
        days: Annotated[int, Query(ge=7, le=90)] = 14,
        principal: dict[str, Any] = Depends(require_permission("adoption_w06:read")),
    ) -> dict[str, Any]:
        _require_site_access(principal, site)
        allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
        snapshot = _build_w06_operational_rhythm_snapshot(site=site, days=days, allowed_sites=allowed_sites)
        _write_audit_log(
            principal=principal,
            action="w06_operational_rhythm_view",
            resource_type="adoption_w06_rhythm",
            resource_id=site or "all",
            detail={
                "site": site,
                "window_days": int(snapshot.get("window_days") or days),
                "weekly_active_rate_percent": snapshot.get("metrics", {}).get("weekly_active_rate_percent"),
                "cadence_adherence_percent": snapshot.get("metrics", {}).get("cadence_adherence_percent"),
                "users_without_active_token": snapshot.get("metrics", {}).get("users_without_active_token"),
            },
        )
        return snapshot
    
    
    @router.get("/adoption/w07/sla-quality")
    def get_ops_adoption_w07_sla_quality(
        site: Annotated[str | None, Query()] = None,
        days: Annotated[int, Query(ge=7, le=90)] = 14,
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:read")),
    ) -> dict[str, Any]:
        _require_site_access(principal, site)
        allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
        snapshot = _build_w07_sla_quality_snapshot(site=site, days=days, allowed_sites=allowed_sites)
        _write_audit_log(
            principal=principal,
            action="w07_sla_quality_view",
            resource_type="adoption_w07_sla_quality",
            resource_id=site or "all",
            detail={
                "site": site,
                "window_days": int(snapshot.get("window_days") or days),
                "median_ack_minutes": snapshot.get("metrics", {}).get("median_ack_minutes"),
                "response_time_improvement_percent": snapshot.get("metrics", {}).get("response_time_improvement_percent"),
                "escalation_rate_percent": snapshot.get("metrics", {}).get("escalation_rate_percent"),
                "alert_success_rate_percent": snapshot.get("metrics", {}).get("alert_success_rate_percent"),
            },
        )
        return snapshot
    
    
    @router.get("/adoption/w08/report-discipline")
    def get_ops_adoption_w08_report_discipline(
        site: Annotated[str | None, Query()] = None,
        days: Annotated[int, Query(ge=14, le=120)] = 30,
        principal: dict[str, Any] = Depends(require_permission("adoption_w08:read")),
    ) -> dict[str, Any]:
        _require_site_access(principal, site)
        allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
        snapshot = _build_w08_report_discipline_snapshot(site=site, days=days, allowed_sites=allowed_sites)
        metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
        _write_audit_log(
            principal=principal,
            action="w08_report_discipline_view",
            resource_type="adoption_w08_report_discipline",
            resource_id=site or "all",
            detail={
                "site": site,
                "window_days": int(snapshot.get("window_days") or days),
                "discipline_score": metrics.get("discipline_score"),
                "report_export_coverage_percent": metrics.get("report_export_coverage_percent"),
                "data_quality_issue_rate_percent": metrics.get("data_quality_issue_rate_percent"),
            },
        )
        return snapshot
    
    
    @router.get("/adoption/w08/site-benchmark")
    def get_ops_adoption_w08_site_benchmark(
        site: Annotated[str | None, Query()] = None,
        days: Annotated[int, Query(ge=14, le=120)] = 30,
        limit: Annotated[int, Query(ge=1, le=30)] = 10,
        principal: dict[str, Any] = Depends(require_permission("adoption_w08:read")),
    ) -> dict[str, Any]:
        _require_site_access(principal, site)
        allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
        snapshot = _build_w08_report_discipline_snapshot(site=site, days=days, allowed_sites=allowed_sites)
        items = snapshot.get("site_benchmark", []) if isinstance(snapshot.get("site_benchmark"), list) else []
        filtered: list[dict[str, Any]] = []
        for row in items:
            row_site = _normalize_site_name(str(row.get("site") or ""))
            if site is not None and row_site != site:
                continue
            filtered.append(row)
        limited = filtered[: max(1, min(limit, 30))]
        _write_audit_log(
            principal=principal,
            action="w08_site_benchmark_view",
            resource_type="adoption_w08_benchmark",
            resource_id=site or "all",
            detail={
                "site": site,
                "window_days": int(snapshot.get("window_days") or days),
                "limit": limit,
                "count": len(limited),
            },
        )
        return {
            "generated_at": snapshot.get("generated_at"),
            "site": site,
            "window_days": snapshot.get("window_days"),
            "count": len(limited),
            "items": limited,
            "thresholds": snapshot.get("thresholds", {}),
        }
    
    
    @router.get("/adoption/w09/kpi-operation")
    def get_ops_adoption_w09_kpi_operation(
        site: Annotated[str | None, Query()] = None,
        days: Annotated[int, Query(ge=14, le=120)] = 30,
        principal: dict[str, Any] = Depends(require_permission("adoption_w09:read")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        allowed_sites = _allowed_sites_for_principal(principal) if normalized_site is None else None
        snapshot = _build_w09_kpi_operation_snapshot(site=normalized_site, days=days, allowed_sites=allowed_sites)
        metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
        _write_audit_log(
            principal=principal,
            action="w09_kpi_operation_view",
            resource_type="adoption_w09_kpi_operation",
            resource_id=normalized_site or "all",
            detail={
                "site": normalized_site,
                "window_days": int(snapshot.get("window_days") or days),
                "overall_status": metrics.get("overall_status"),
                "kpi_count": metrics.get("kpi_count"),
                "owner_coverage_percent": metrics.get("owner_coverage_percent"),
                "red_count": metrics.get("red_count"),
            },
        )
        return snapshot
    
    
    ADOPTION_POLICY_RESPONSE_SCHEMA = "adoption_policy_response"
    ADOPTION_POLICY_RESPONSE_VERSION = "v1"
    
    
    def _build_adoption_policy_response(
        *,
        phase: str,
        policy_kind: str,
        endpoint: str,
        policy: dict[str, Any],
        updated_at: datetime,
        policy_key: str,
        policy_site: str | None,
    ) -> dict[str, Any]:
        scope_type = "site" if policy_site else "global"
        applies_to = policy_site or "global"
        base_payload = _build_policy_response_payload(
            policy_key=policy_key,
            updated_at=updated_at,
            policy=policy,
            scope=scope_type,
            applies_to=applies_to,
            version=ADOPTION_POLICY_RESPONSE_VERSION,
        )
        meta = dict(base_payload.get("meta", {}))
        meta.update(
            {
                "schema": ADOPTION_POLICY_RESPONSE_SCHEMA,
                "schema_version": ADOPTION_POLICY_RESPONSE_VERSION,
                "phase": phase,
                "policy_kind": policy_kind,
                "endpoint": endpoint,
                "scope_type": scope_type,
            }
        )
        return {
            **base_payload,
            "site": policy_site,
            "version": ADOPTION_POLICY_RESPONSE_VERSION,
            "applies_to": applies_to,
            "scope": {
                "type": scope_type,
                "site": policy_site,
                "policy_key": policy_key,
            },
            "meta": meta,
        }
    
    
    @router.get("/adoption/w09/kpi-policy")
    def get_ops_adoption_w09_kpi_policy(
        site: Annotated[str | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w09:read")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        if normalized_site is None:
            _require_global_site_scope(principal)
        policy, updated_at, policy_key, policy_site = _ensure_w09_kpi_policy(normalized_site)
        _write_audit_log(
            principal=principal,
            action="w09_kpi_policy_view",
            resource_type="adoption_w09_policy",
            resource_id=policy_key,
            detail={
                "site": policy_site,
                "policy_key": policy_key,
                "enabled": bool(policy.get("enabled", True)),
                "kpi_count": len(policy.get("kpis", []) if isinstance(policy.get("kpis"), list) else []),
                "escalation_rule_count": len(
                    policy.get("escalation_map", []) if isinstance(policy.get("escalation_map"), list) else []
                ),
            },
        )
        return _build_adoption_policy_response(
            phase="w09",
            policy_kind="kpi-policy",
            endpoint="/api/ops/adoption/w09/kpi-policy",
            policy=policy,
            updated_at=updated_at,
            policy_key=policy_key,
            policy_site=policy_site,
        )
    
    
    @router.put("/adoption/w09/kpi-policy")
    def set_ops_adoption_w09_kpi_policy(
        payload: dict[str, Any],
        site: Annotated[str | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w09:write")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        if normalized_site is None:
            _require_global_site_scope(principal)
            if not _has_permission(principal, "admins:manage"):
                raise HTTPException(status_code=403, detail="Global W09 policy update requires admins:manage")
        policy, updated_at, policy_key, policy_site = _upsert_w09_kpi_policy(normalized_site, payload)
        _write_audit_log(
            principal=principal,
            action="w09_kpi_policy_update",
            resource_type="adoption_w09_policy",
            resource_id=policy_key,
            detail={
                "site": policy_site,
                "policy_key": policy_key,
                "enabled": bool(policy.get("enabled", True)),
                "kpi_count": len(policy.get("kpis", []) if isinstance(policy.get("kpis"), list) else []),
                "escalation_rule_count": len(
                    policy.get("escalation_map", []) if isinstance(policy.get("escalation_map"), list) else []
                ),
            },
        )
        return _build_adoption_policy_response(
            phase="w09",
            policy_kind="kpi-policy",
            endpoint="/api/ops/adoption/w09/kpi-policy",
            policy=policy,
            updated_at=updated_at,
            policy_key=policy_key,
            policy_site=policy_site,
        )
    
    
    @router.get("/adoption/w10/self-serve")
    def get_ops_adoption_w10_self_serve(
        site: Annotated[str | None, Query()] = None,
        days: Annotated[int, Query(ge=14, le=120)] = 30,
        principal: dict[str, Any] = Depends(require_permission("adoption_w10:read")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        allowed_sites = _allowed_sites_for_principal(principal) if normalized_site is None else None
        snapshot = _build_w10_self_serve_snapshot(site=normalized_site, days=days, allowed_sites=allowed_sites)
        metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
        _write_audit_log(
            principal=principal,
            action="w10_self_serve_view",
            resource_type="adoption_w10_self_serve",
            resource_id=normalized_site or "all",
            detail={
                "site": normalized_site,
                "window_days": int(snapshot.get("window_days") or days),
                "overall_status": metrics.get("overall_status"),
                "repeat_rate_percent": metrics.get("repeat_rate_percent"),
                "readiness_score": metrics.get("self_serve_readiness_score"),
                "target_met": metrics.get("target_met"),
            },
        )
        return snapshot
    
    
    @router.get("/adoption/w10/support-policy")
    def get_ops_adoption_w10_support_policy(
        site: Annotated[str | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w10:read")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        if normalized_site is None:
            _require_global_site_scope(principal)
        policy, updated_at, policy_key, policy_site = _ensure_w10_support_policy(normalized_site)
        _write_audit_log(
            principal=principal,
            action="w10_support_policy_view",
            resource_type="adoption_w10_support_policy",
            resource_id=policy_key,
            detail={
                "site": policy_site,
                "policy_key": policy_key,
                "enabled": bool(policy.get("enabled", True)),
            },
        )
        return _build_adoption_policy_response(
            phase="w10",
            policy_kind="support-policy",
            endpoint="/api/ops/adoption/w10/support-policy",
            policy=policy,
            updated_at=updated_at,
            policy_key=policy_key,
            policy_site=policy_site,
        )
    
    
    @router.put("/adoption/w10/support-policy")
    def set_ops_adoption_w10_support_policy(
        payload: dict[str, Any],
        site: Annotated[str | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w10:write")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        if normalized_site is None:
            _require_global_site_scope(principal)
            if not _has_permission(principal, "admins:manage"):
                raise HTTPException(status_code=403, detail="Global W10 policy update requires admins:manage")
        policy, updated_at, policy_key, policy_site = _upsert_w10_support_policy(normalized_site, payload)
        _write_audit_log(
            principal=principal,
            action="w10_support_policy_update",
            resource_type="adoption_w10_support_policy",
            resource_id=policy_key,
            detail={
                "site": policy_site,
                "policy_key": policy_key,
                "enabled": bool(policy.get("enabled", True)),
            },
        )
        return _build_adoption_policy_response(
            phase="w10",
            policy_kind="support-policy",
            endpoint="/api/ops/adoption/w10/support-policy",
            policy=policy,
            updated_at=updated_at,
            policy_key=policy_key,
            policy_site=policy_site,
        )
    
    
    @router.get("/adoption/w11/scale-readiness")
    def get_ops_adoption_w11_scale_readiness(
        site: Annotated[str | None, Query()] = None,
        days: Annotated[int, Query(ge=14, le=120)] = 30,
        principal: dict[str, Any] = Depends(require_permission("adoption_w11:read")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        allowed_sites = _allowed_sites_for_principal(principal) if normalized_site is None else None
        snapshot = _build_w11_scale_readiness_snapshot(site=normalized_site, days=days, allowed_sites=allowed_sites)
        metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
        _write_audit_log(
            principal=principal,
            action="w11_scale_readiness_view",
            resource_type="adoption_w11_scale_readiness",
            resource_id=normalized_site or "all",
            detail={
                "site": normalized_site,
                "window_days": int(snapshot.get("window_days") or days),
                "overall_status": metrics.get("overall_status"),
                "repeat_rate_percent": metrics.get("repeat_rate_percent"),
                "readiness_score": metrics.get("scale_readiness_readiness_score"),
                "target_met": metrics.get("target_met"),
            },
        )
        return snapshot
    
    
    @router.get("/adoption/w11/readiness-policy")
    def get_ops_adoption_w11_readiness_policy(
        site: Annotated[str | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w11:read")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        if normalized_site is None:
            _require_global_site_scope(principal)
        policy, updated_at, policy_key, policy_site = _ensure_w11_readiness_policy(normalized_site)
        _write_audit_log(
            principal=principal,
            action="w11_readiness_policy_view",
            resource_type="adoption_w11_readiness_policy",
            resource_id=policy_key,
            detail={
                "site": policy_site,
                "policy_key": policy_key,
                "enabled": bool(policy.get("enabled", True)),
            },
        )
        return _build_adoption_policy_response(
            phase="w11",
            policy_kind="readiness-policy",
            endpoint="/api/ops/adoption/w11/readiness-policy",
            policy=policy,
            updated_at=updated_at,
            policy_key=policy_key,
            policy_site=policy_site,
        )
    
    
    @router.put("/adoption/w11/readiness-policy")
    def set_ops_adoption_w11_readiness_policy(
        payload: dict[str, Any],
        site: Annotated[str | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w11:write")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        if normalized_site is None:
            _require_global_site_scope(principal)
            if not _has_permission(principal, "admins:manage"):
                raise HTTPException(status_code=403, detail="Global W11 policy update requires admins:manage")
        policy, updated_at, policy_key, policy_site = _upsert_w11_readiness_policy(normalized_site, payload)
        _write_audit_log(
            principal=principal,
            action="w11_readiness_policy_update",
            resource_type="adoption_w11_readiness_policy",
            resource_id=policy_key,
            detail={
                "site": policy_site,
                "policy_key": policy_key,
                "enabled": bool(policy.get("enabled", True)),
            },
        )
        return _build_adoption_policy_response(
            phase="w11",
            policy_kind="readiness-policy",
            endpoint="/api/ops/adoption/w11/readiness-policy",
            policy=policy,
            updated_at=updated_at,
            policy_key=policy_key,
            policy_site=policy_site,
        )
    
    
    @router.get("/adoption/w12/closure-handoff")
    def get_ops_adoption_w12_closure_handoff(
        site: Annotated[str | None, Query()] = None,
        days: Annotated[int, Query(ge=14, le=120)] = 30,
        principal: dict[str, Any] = Depends(require_permission("adoption_w12:read")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        allowed_sites = _allowed_sites_for_principal(principal) if normalized_site is None else None
        snapshot = _build_w12_closure_handoff_snapshot(site=normalized_site, days=days, allowed_sites=allowed_sites)
        metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
        _write_audit_log(
            principal=principal,
            action="w12_closure_handoff_view",
            resource_type="adoption_w12_closure_handoff",
            resource_id=normalized_site or "all",
            detail={
                "site": normalized_site,
                "window_days": int(snapshot.get("window_days") or days),
                "overall_status": metrics.get("overall_status"),
                "repeat_rate_percent": metrics.get("repeat_rate_percent"),
                "readiness_score": metrics.get("closure_handoff_readiness_score"),
                "target_met": metrics.get("target_met"),
            },
        )
        return snapshot
    
    
    @router.get("/adoption/w12/handoff-policy")
    def get_ops_adoption_w12_handoff_policy(
        site: Annotated[str | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w12:read")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        if normalized_site is None:
            _require_global_site_scope(principal)
        policy, updated_at, policy_key, policy_site = _ensure_w12_handoff_policy(normalized_site)
        _write_audit_log(
            principal=principal,
            action="w12_handoff_policy_view",
            resource_type="adoption_w12_handoff_policy",
            resource_id=policy_key,
            detail={
                "site": policy_site,
                "policy_key": policy_key,
                "enabled": bool(policy.get("enabled", True)),
            },
        )
        return _build_adoption_policy_response(
            phase="w12",
            policy_kind="handoff-policy",
            endpoint="/api/ops/adoption/w12/handoff-policy",
            policy=policy,
            updated_at=updated_at,
            policy_key=policy_key,
            policy_site=policy_site,
        )
    
    
    @router.put("/adoption/w12/handoff-policy")
    def set_ops_adoption_w12_handoff_policy(
        payload: dict[str, Any],
        site: Annotated[str | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w12:write")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        if normalized_site is None:
            _require_global_site_scope(principal)
            if not _has_permission(principal, "admins:manage"):
                raise HTTPException(status_code=403, detail="Global W12 policy update requires admins:manage")
        policy, updated_at, policy_key, policy_site = _upsert_w12_handoff_policy(normalized_site, payload)
        _write_audit_log(
            principal=principal,
            action="w12_handoff_policy_update",
            resource_type="adoption_w12_handoff_policy",
            resource_id=policy_key,
            detail={
                "site": policy_site,
                "policy_key": policy_key,
                "enabled": bool(policy.get("enabled", True)),
            },
        )
        return _build_adoption_policy_response(
            phase="w12",
            policy_kind="handoff-policy",
            endpoint="/api/ops/adoption/w12/handoff-policy",
            policy=policy,
            updated_at=updated_at,
            policy_key=policy_key,
            policy_site=policy_site,
        )
    
    
    @router.get("/adoption/w13/closure-handoff")
    def get_ops_adoption_w13_closure_handoff(
        site: Annotated[str | None, Query()] = None,
        days: Annotated[int, Query(ge=14, le=120)] = 30,
        principal: dict[str, Any] = Depends(require_permission("adoption_w13:read")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        allowed_sites = _allowed_sites_for_principal(principal) if normalized_site is None else None
        snapshot = _build_w13_closure_handoff_snapshot(site=normalized_site, days=days, allowed_sites=allowed_sites)
        metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
        _write_audit_log(
            principal=principal,
            action="w13_closure_handoff_view",
            resource_type="adoption_w13_closure_handoff",
            resource_id=normalized_site or "all",
            detail={
                "site": normalized_site,
                "window_days": int(snapshot.get("window_days") or days),
                "overall_status": metrics.get("overall_status"),
                "repeat_rate_percent": metrics.get("repeat_rate_percent"),
                "readiness_score": metrics.get("closure_handoff_readiness_score"),
                "target_met": metrics.get("target_met"),
            },
        )
        return snapshot
    
    
    @router.get("/adoption/w13/handoff-policy")
    def get_ops_adoption_w13_handoff_policy(
        site: Annotated[str | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w13:read")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        if normalized_site is None:
            _require_global_site_scope(principal)
        policy, updated_at, policy_key, policy_site = _ensure_w13_handoff_policy(normalized_site)
        _write_audit_log(
            principal=principal,
            action="w13_handoff_policy_view",
            resource_type="adoption_w13_handoff_policy",
            resource_id=policy_key,
            detail={
                "site": policy_site,
                "policy_key": policy_key,
                "enabled": bool(policy.get("enabled", True)),
            },
        )
        return _build_adoption_policy_response(
            phase="w13",
            policy_kind="handoff-policy",
            endpoint="/api/ops/adoption/w13/handoff-policy",
            policy=policy,
            updated_at=updated_at,
            policy_key=policy_key,
            policy_site=policy_site,
        )
    
    
    @router.put("/adoption/w13/handoff-policy")
    def set_ops_adoption_w13_handoff_policy(
        payload: dict[str, Any],
        site: Annotated[str | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w13:write")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        if normalized_site is None:
            _require_global_site_scope(principal)
            if not _has_permission(principal, "admins:manage"):
                raise HTTPException(status_code=403, detail="Global W13 policy update requires admins:manage")
        policy, updated_at, policy_key, policy_site = _upsert_w13_handoff_policy(normalized_site, payload)
        _write_audit_log(
            principal=principal,
            action="w13_handoff_policy_update",
            resource_type="adoption_w13_handoff_policy",
            resource_id=policy_key,
            detail={
                "site": policy_site,
                "policy_key": policy_key,
                "enabled": bool(policy.get("enabled", True)),
            },
        )
        return _build_adoption_policy_response(
            phase="w13",
            policy_kind="handoff-policy",
            endpoint="/api/ops/adoption/w13/handoff-policy",
            policy=policy,
            updated_at=updated_at,
            policy_key=policy_key,
            policy_site=policy_site,
        )
    
    @router.get("/adoption/w14/stability-sprint")
    def get_ops_adoption_w14_stability_sprint(
        site: Annotated[str | None, Query()] = None,
        days: Annotated[int, Query(ge=14, le=120)] = 30,
        principal: dict[str, Any] = Depends(require_permission("adoption_w14:read")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        allowed_sites = _allowed_sites_for_principal(principal) if normalized_site is None else None
        snapshot = _build_w14_stability_sprint_snapshot(site=normalized_site, days=days, allowed_sites=allowed_sites)
        metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
        _write_audit_log(
            principal=principal,
            action="w14_stability_sprint_view",
            resource_type="adoption_w14_stability_sprint",
            resource_id=normalized_site or "all",
            detail={
                "site": normalized_site,
                "window_days": int(snapshot.get("window_days") or days),
                "overall_status": metrics.get("overall_status"),
                "incident_repeat_rate_percent": metrics.get("incident_repeat_rate_percent"),
                "readiness_score": metrics.get("stability_sprint_readiness_score"),
                "target_met": metrics.get("target_met"),
            },
        )
        return snapshot
    
    
    @router.get("/adoption/w14/stability-policy")
    def get_ops_adoption_w14_stability_policy(
        site: Annotated[str | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w14:read")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        if normalized_site is None:
            _require_global_site_scope(principal)
        policy, updated_at, policy_key, policy_site = _ensure_w14_stability_policy(normalized_site)
        _write_audit_log(
            principal=principal,
            action="w14_stability_policy_view",
            resource_type="adoption_w14_stability_policy",
            resource_id=policy_key,
            detail={
                "site": policy_site,
                "policy_key": policy_key,
                "enabled": bool(policy.get("enabled", True)),
            },
        )
        return _build_adoption_policy_response(
            phase="w14",
            policy_kind="stability-policy",
            endpoint="/api/ops/adoption/w14/stability-policy",
            policy=policy,
            updated_at=updated_at,
            policy_key=policy_key,
            policy_site=policy_site,
        )
    
    
    @router.put("/adoption/w14/stability-policy")
    def set_ops_adoption_w14_stability_policy(
        payload: dict[str, Any],
        site: Annotated[str | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w14:write")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        if normalized_site is None:
            _require_global_site_scope(principal)
            if not _has_permission(principal, "admins:manage"):
                raise HTTPException(status_code=403, detail="Global W14 policy update requires admins:manage")
        policy, updated_at, policy_key, policy_site = _upsert_w14_stability_policy(normalized_site, payload)
        _write_audit_log(
            principal=principal,
            action="w14_stability_policy_update",
            resource_type="adoption_w14_stability_policy",
            resource_id=policy_key,
            detail={
                "site": policy_site,
                "policy_key": policy_key,
                "enabled": bool(policy.get("enabled", True)),
            },
        )
        return _build_adoption_policy_response(
            phase="w14",
            policy_kind="stability-policy",
            endpoint="/api/ops/adoption/w14/stability-policy",
            policy=policy,
            updated_at=updated_at,
            policy_key=policy_key,
            policy_site=policy_site,
        )
    
    
    @router.get("/adoption/w15/ops-efficiency")
    def get_ops_adoption_w15_ops_efficiency(
        site: Annotated[str | None, Query()] = None,
        days: Annotated[int, Query(ge=14, le=120)] = 30,
        principal: dict[str, Any] = Depends(require_permission("adoption_w15:read")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        allowed_sites = _allowed_sites_for_principal(principal) if normalized_site is None else None
        snapshot = _build_w15_ops_efficiency_snapshot(site=normalized_site, days=days, allowed_sites=allowed_sites)
        metrics = snapshot.get("metrics", {}) if isinstance(snapshot.get("metrics"), dict) else {}
        _write_audit_log(
            principal=principal,
            action="w15_ops_efficiency_view",
            resource_type="adoption_w15_ops_efficiency",
            resource_id=normalized_site or "all",
            detail={
                "site": normalized_site,
                "window_days": int(snapshot.get("window_days") or days),
                "overall_status": metrics.get("overall_status"),
                "incident_repeat_rate_percent": metrics.get("incident_repeat_rate_percent"),
                "readiness_score": metrics.get("ops_efficiency_readiness_score"),
                "target_met": metrics.get("target_met"),
            },
        )
        return snapshot
    
    
    @router.get("/adoption/w15/efficiency-policy")
    def get_ops_adoption_w15_efficiency_policy(
        site: Annotated[str | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w15:read")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        if normalized_site is None:
            _require_global_site_scope(principal)
        policy, updated_at, policy_key, policy_site = _ensure_w15_efficiency_policy(normalized_site)
        _write_audit_log(
            principal=principal,
            action="w15_efficiency_policy_view",
            resource_type="adoption_w15_efficiency_policy",
            resource_id=policy_key,
            detail={
                "site": policy_site,
                "policy_key": policy_key,
                "enabled": bool(policy.get("enabled", True)),
            },
        )
        return _build_adoption_policy_response(
            phase="w15",
            policy_kind="efficiency-policy",
            endpoint="/api/ops/adoption/w15/efficiency-policy",
            policy=policy,
            updated_at=updated_at,
            policy_key=policy_key,
            policy_site=policy_site,
        )
    
    
    @router.put("/adoption/w15/efficiency-policy")
    def set_ops_adoption_w15_efficiency_policy(
        payload: dict[str, Any],
        site: Annotated[str | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w15:write")),
    ) -> dict[str, Any]:
        normalized_site = _normalize_site_name(site)
        _require_site_access(principal, normalized_site)
        if normalized_site is None:
            _require_global_site_scope(principal)
            if not _has_permission(principal, "admins:manage"):
                raise HTTPException(status_code=403, detail="Global W15 policy update requires admins:manage")
        policy, updated_at, policy_key, policy_site = _upsert_w15_efficiency_policy(normalized_site, payload)
        _write_audit_log(
            principal=principal,
            action="w15_efficiency_policy_update",
            resource_type="adoption_w15_efficiency_policy",
            resource_id=policy_key,
            detail={
                "site": policy_site,
                "policy_key": policy_key,
                "enabled": bool(policy.get("enabled", True)),
            },
        )
        return _build_adoption_policy_response(
            phase="w15",
            policy_kind="efficiency-policy",
            endpoint="/api/ops/adoption/w15/efficiency-policy",
            policy=policy,
            updated_at=updated_at,
            policy_key=policy_key,
            policy_site=policy_site,
        )
    
    
    
    @router.get("/adoption/w07/automation-readiness")
    def get_ops_adoption_w07_automation_readiness(
        site: Annotated[str | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:read")),
    ) -> dict[str, Any]:
        _require_site_access(principal, site)
        normalized_site = _normalize_site_name(site)
        allowed_sites = _allowed_sites_for_principal(principal) if normalized_site is None else None
        snapshot = _build_w07_automation_readiness_snapshot(site=normalized_site, allowed_sites=allowed_sites)
        _write_audit_log(
            principal=principal,
            action="w07_automation_readiness_view",
            resource_type="adoption_w07_automation",
            resource_id=normalized_site or "all",
            detail={
                "site": normalized_site,
                "overall_status": snapshot.get("overall_status"),
                "webhook_target_count": snapshot.get("integration", {}).get("webhook_target_count"),
                "latest_run_status": snapshot.get("runtime", {}).get("latest_run_status"),
                "latest_run_recent": snapshot.get("runtime", {}).get("latest_run_recent"),
            },
        )
        return snapshot
    
    
    @router.post("/adoption/w07/sla-quality/run-weekly")
    def run_ops_adoption_w07_sla_quality_weekly(
        site: Annotated[str | None, Query()] = None,
        days: Annotated[int, Query(ge=7, le=90)] = 14,
        force_notify: Annotated[bool, Query()] = False,
        write_archive: Annotated[bool | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:write")),
    ) -> dict[str, Any]:
        _require_site_access(principal, site)
        normalized_site = _normalize_site_name(site)
        allowed_sites = _allowed_sites_for_principal(principal) if normalized_site is None else None
    
        result = run_w07_sla_quality_weekly_job(
            site=normalized_site,
            days=days,
            trigger="api",
            force_notify=force_notify,
            allowed_sites=allowed_sites,
        )
    
        archive_file: str | None = None
        archive_error: str | None = None
        archive_enabled = W07_WEEKLY_ARCHIVE_ENABLED if write_archive is None else bool(write_archive)
        if archive_enabled:
            try:
                trends = _build_w07_weekly_trends_payload(
                    site=normalized_site,
                    allowed_sites=allowed_sites,
                    limit=104,
                )
                csv_text = _build_w07_weekly_archive_csv(trends.get("points", []))
                archive_dir = Path(W07_WEEKLY_ARCHIVE_PATH)
                archive_dir.mkdir(parents=True, exist_ok=True)
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                site_label = (normalized_site or "all").replace(" ", "_").replace("/", "_")
                file_path = archive_dir / f"w07-sla-quality-weekly-{site_label}-{stamp}.csv"
                file_path.write_text(csv_text, encoding="utf-8")
                archive_file = str(file_path)
            except Exception as exc:  # pragma: no cover - defensive filesystem path
                archive_error = str(exc)
    
        response = {
            **result,
            "write_archive": archive_enabled,
            "archive_file": archive_file,
            "archive_error": archive_error,
        }
        _write_audit_log(
            principal=principal,
            action="w07_sla_quality_weekly_run",
            resource_type="adoption_w07_sla_quality",
            resource_id=str(response.get("run_id") or "pending"),
            status=str(response.get("status") or "success"),
            detail={
                "site": normalized_site,
                "window_days": int(response.get("window_days") or days),
                "degraded": bool((response.get("degradation") or {}).get("degraded", False)),
                "reasons": (response.get("degradation") or {}).get("reasons", []),
                "cooldown_active": bool(response.get("cooldown_active", False)),
                "alert_attempted": bool(response.get("alert_attempted", False)),
                "alert_dispatched": bool(response.get("alert_dispatched", False)),
                "alert_error": response.get("alert_error"),
                "write_archive": archive_enabled,
                "archive_file": archive_file,
                "archive_error": archive_error,
            },
        )
        return response
    
    
    @router.get("/adoption/w07/sla-quality/latest-weekly")
    def get_ops_adoption_w07_sla_quality_latest_weekly(
        site: Annotated[str | None, Query()] = None,
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:read")),
    ) -> dict[str, Any]:
        _require_site_access(principal, site)
        normalized_site = _normalize_site_name(site)
        allowed_sites = _allowed_sites_for_principal(principal) if normalized_site is None else None
        runs = _read_w07_weekly_job_runs(site=normalized_site, allowed_sites=allowed_sites, limit=1)
        if not runs:
            raise HTTPException(status_code=404, detail="No W07 weekly run found")
        model, detail = runs[0]
        response = {
            "run_id": model.id,
            "job_name": model.job_name,
            "trigger": model.trigger,
            "status": model.status,
            "started_at": model.started_at.isoformat(),
            "finished_at": model.finished_at.isoformat(),
            "site": detail.get("site"),
            "window_days": detail.get("window_days"),
            "degradation": detail.get("degradation", {}),
            "alert_enabled": bool(detail.get("alert_enabled", W07_QUALITY_ALERT_ENABLED)),
            "cooldown_active": bool(detail.get("cooldown_active", False)),
            "cooldown_remaining_minutes": int(detail.get("cooldown_remaining_minutes") or 0),
            "last_alert_at": detail.get("last_alert_at"),
            "alert_attempted": bool(detail.get("alert_attempted", False)),
            "alert_dispatched": bool(detail.get("alert_dispatched", False)),
            "alert_error": detail.get("alert_error"),
            "alert_channels": detail.get("alert_channels", []),
            "snapshot": detail.get("snapshot", {}),
        }
        _write_audit_log(
            principal=principal,
            action="w07_sla_quality_weekly_latest_view",
            resource_type="adoption_w07_sla_quality",
            resource_id=str(model.id),
            detail={
                "site": normalized_site,
                "status": model.status,
                "degraded": bool((response.get("degradation") or {}).get("degraded", False)),
            },
        )
        return response
    
    
    @router.get("/adoption/w07/sla-quality/trends")
    def get_ops_adoption_w07_sla_quality_trends(
        site: Annotated[str | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=104)] = 26,
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:read")),
    ) -> dict[str, Any]:
        _require_site_access(principal, site)
        normalized_site = _normalize_site_name(site)
        allowed_sites = _allowed_sites_for_principal(principal) if normalized_site is None else None
        payload = _build_w07_weekly_trends_payload(site=normalized_site, allowed_sites=allowed_sites, limit=limit)
        _write_audit_log(
            principal=principal,
            action="w07_sla_quality_trends_view",
            resource_type="adoption_w07_sla_quality",
            resource_id=normalized_site or "all",
            detail={
                "site": normalized_site,
                "point_count": int(payload.get("point_count") or 0),
            },
        )
        return payload
    
    
    @router.get("/adoption/w07/sla-quality/archive.csv")
    def get_ops_adoption_w07_sla_quality_archive_csv(
        site: Annotated[str | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=104)] = 52,
        principal: dict[str, Any] = Depends(require_permission("adoption_w07:read")),
    ) -> Response:
        _require_site_access(principal, site)
        normalized_site = _normalize_site_name(site)
        allowed_sites = _allowed_sites_for_principal(principal) if normalized_site is None else None
        payload = _build_w07_weekly_trends_payload(site=normalized_site, allowed_sites=allowed_sites, limit=limit)
        csv_text = _build_w07_weekly_archive_csv(payload.get("points", []))
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        site_label = (normalized_site or "all").replace(" ", "_")
        file_name = f"adoption-w07-sla-quality-weekly-{site_label}-{stamp}.csv"
        _write_audit_log(
            principal=principal,
            action="w07_sla_quality_archive_csv_export",
            resource_type="adoption_w07_sla_quality",
            resource_id=file_name,
            detail={
                "site": normalized_site,
                "point_count": int(payload.get("point_count") or 0),
            },
        )
        return Response(
            content=csv_text,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
        )
    
    
    @router.get("/adoption/w04/funnel")
    def get_ops_adoption_w04_funnel(
        site: Annotated[str | None, Query()] = None,
        days: Annotated[int, Query(ge=1, le=90)] = 30,
        principal: dict[str, Any] = Depends(require_permission("adoption_w04:read")),
    ) -> dict[str, Any]:
        _require_site_access(principal, site)
        allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
        snapshot = _build_w04_funnel_snapshot(site=site, days=days, allowed_sites=allowed_sites)
        _write_audit_log(
            principal=principal,
            action="w04_funnel_view",
            resource_type="adoption_w04_funnel",
            resource_id=site or "all",
            detail={
                "site": site,
                "window_days": int(snapshot.get("window_days") or days),
                "total_users": int(snapshot.get("metrics", {}).get("total_users") or 0),
                "median_ttv_minutes": snapshot.get("metrics", {}).get("median_ttv_minutes"),
                "target_met": bool(snapshot.get("metrics", {}).get("target_met", False)),
            },
        )
        return snapshot
    
    
    @router.get("/adoption/w04/blockers")
    def get_ops_adoption_w04_blockers(
        site: Annotated[str | None, Query()] = None,
        days: Annotated[int, Query(ge=1, le=90)] = 30,
        max_items: Annotated[int, Query(ge=1, le=10)] = 3,
        principal: dict[str, Any] = Depends(require_permission("adoption_w04:read")),
    ) -> dict[str, Any]:
        _require_site_access(principal, site)
        allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
        snapshot = _build_w04_blocker_snapshot(
            site=site,
            days=days,
            allowed_sites=allowed_sites,
            max_items=max_items,
        )
        _write_audit_log(
            principal=principal,
            action="w04_blockers_view",
            resource_type="adoption_w04_blockers",
            resource_id=site or "all",
            detail={
                "site": site,
                "window_days": int(snapshot.get("window_days") or days),
                "max_items": max_items,
                "top_keys": [
                    str(item.get("blocker_key") or "")
                    for item in snapshot.get("top", [])
                    if isinstance(item, dict)
                ],
            },
        )
        return snapshot

    return router
