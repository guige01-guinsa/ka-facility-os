"""OPS dashboard and handover routes extracted from app.main."""

from fastapi import APIRouter


def build_router(namespace: dict[str, object]) -> APIRouter:
    """Compatibility extraction layer until domain services are fully split."""
    exported = {key: value for key, value in namespace.items() if key != "router"}
    globals().update(exported)
    router = APIRouter(prefix="/api/ops", tags=["ops"])

    @router.get("/dashboard/trends", response_model=DashboardTrendsRead)
    def get_dashboard_trends(
        site: Annotated[str | None, Query()] = None,
        days: Annotated[int, Query(ge=1, le=90)] = 30,
        principal: dict[str, Any] = Depends(require_permission("admins:manage")),
    ) -> DashboardTrendsRead:
        _require_site_access(principal, site)
        allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
        return build_dashboard_trends(site=site, days=days, allowed_sites=allowed_sites)

    @router.get("/handover/brief", response_model=OpsHandoverBriefRead)
    def get_ops_handover_brief(
        site: Annotated[str | None, Query()] = None,
        window_hours: Annotated[int, Query(ge=1, le=168)] = 12,
        due_soon_hours: Annotated[int, Query(ge=1, le=72)] = 6,
        max_items: Annotated[int, Query(ge=1, le=50)] = 10,
        principal: dict[str, Any] = Depends(require_permission("admins:manage")),
    ) -> OpsHandoverBriefRead:
        _require_site_access(principal, site)
        allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
        report = build_ops_handover_brief(
            site=site,
            window_hours=window_hours,
            due_soon_hours=due_soon_hours,
            max_items=max_items,
            allowed_sites=allowed_sites,
        )
        _write_audit_log(
            principal=principal,
            action="ops_handover_brief_view",
            resource_type="report",
            resource_id=site or "all",
            detail={
                "site": site,
                "window_hours": window_hours,
                "due_soon_hours": due_soon_hours,
                "max_items": max_items,
                "open_work_orders": report.open_work_orders,
                "overdue_open_work_orders": report.overdue_open_work_orders,
                "due_soon_work_orders": report.due_soon_work_orders,
            },
        )
        return report
    
    
    @router.get("/handover/brief/csv")
    def get_ops_handover_brief_csv(
        site: Annotated[str | None, Query()] = None,
        window_hours: Annotated[int, Query(ge=1, le=168)] = 12,
        due_soon_hours: Annotated[int, Query(ge=1, le=72)] = 6,
        max_items: Annotated[int, Query(ge=1, le=50)] = 10,
        principal: dict[str, Any] = Depends(require_permission("admins:manage")),
    ) -> Response:
        _require_site_access(principal, site)
        allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
        report = build_ops_handover_brief(
            site=site,
            window_hours=window_hours,
            due_soon_hours=due_soon_hours,
            max_items=max_items,
            allowed_sites=allowed_sites,
        )
        csv_text = _build_handover_brief_csv(report)
        site_label = (report.site or "all").replace(" ", "_")
        ts = report.generated_at.strftime("%Y%m%dT%H%M%SZ")
        file_name = f"handover-brief-{site_label}-{ts}.csv"
        response = Response(
            content=csv_text,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
        )
        _write_audit_log(
            principal=principal,
            action="report_handover_export_csv",
            resource_type="report",
            resource_id=f"{report.site or 'ALL'}:{ts}",
            detail={
                "site": site,
                "window_hours": window_hours,
                "due_soon_hours": due_soon_hours,
                "max_items": max_items,
            },
        )
        return response
    
    
    @router.get("/handover/brief/pdf")
    def get_ops_handover_brief_pdf(
        site: Annotated[str | None, Query()] = None,
        window_hours: Annotated[int, Query(ge=1, le=168)] = 12,
        due_soon_hours: Annotated[int, Query(ge=1, le=72)] = 6,
        max_items: Annotated[int, Query(ge=1, le=50)] = 10,
        principal: dict[str, Any] = Depends(require_permission("admins:manage")),
    ) -> Response:
        _require_site_access(principal, site)
        allowed_sites = _allowed_sites_for_principal(principal) if site is None else None
        report = build_ops_handover_brief(
            site=site,
            window_hours=window_hours,
            due_soon_hours=due_soon_hours,
            max_items=max_items,
            allowed_sites=allowed_sites,
        )
        pdf_bytes = _build_handover_brief_pdf(report)
        site_label = (report.site or "all").replace(" ", "_")
        ts = report.generated_at.strftime("%Y%m%dT%H%M%SZ")
        file_name = f"handover-brief-{site_label}-{ts}.pdf"
        response = Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
        )
        _write_audit_log(
            principal=principal,
            action="report_handover_export_pdf",
            resource_type="report",
            resource_id=f"{report.site or 'ALL'}:{ts}",
            detail={
                "site": site,
                "window_hours": window_hours,
                "due_soon_hours": due_soon_hours,
                "max_items": max_items,
            },
        )
        return response

    return router