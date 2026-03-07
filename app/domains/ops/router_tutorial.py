"""OPS tutorial simulator routes extracted from app.main."""

from fastapi import APIRouter


def build_router(namespace: dict[str, object]) -> APIRouter:
    """Compatibility extraction layer until domain services are fully split."""
    exported = {key: value for key, value in namespace.items() if key != "router"}
    globals().update(exported)
    router = APIRouter(prefix="/api/ops", tags=["ops"])

    @router.post("/tutorial-simulator/sessions/start")
    def start_ops_tutorial_simulator_session(
        payload: dict[str, Any] | None = None,
        principal: dict[str, Any] = Depends(require_permission("admins:manage")),
    ) -> dict[str, Any]:
        body = payload if isinstance(payload, dict) else {}
        scenario_id = str(body.get("scenario_id") or "ts-core-01").strip()
        site = str(body.get("site") or TUTORIAL_SIMULATOR_DEFAULT_SITE).strip() or TUTORIAL_SIMULATOR_DEFAULT_SITE
        _require_site_access(principal, site)
        actor_username = str(principal.get("username") or "system")
        session = _start_tutorial_simulator_session(
            scenario_id=scenario_id,
            site=site,
            actor_username=actor_username,
        )
        progress = session.get("progress", {}) if isinstance(session.get("progress"), dict) else {}
        _write_audit_log(
            principal=principal,
            action="ops_tutorial_simulator_session_start",
            resource_type="ops_tutorial_simulator_session",
            resource_id=str(session.get("session_id") or "unknown"),
            status="success",
            detail={
                "scenario_id": session.get("scenario", {}).get("id") if isinstance(session.get("scenario"), dict) else scenario_id,
                "site": session.get("site"),
                "completion_percent": int(progress.get("completion_percent") or 0),
            },
        )
        return session
    
    
    @router.get("/tutorial-simulator/sessions")
    def list_ops_tutorial_simulator_sessions(
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
        principal: dict[str, Any] = Depends(require_permission("admins:manage")),
    ) -> dict[str, Any]:
        items = _list_tutorial_simulator_sessions(limit=limit)
        allowed_sites = _allowed_sites_for_principal(principal)
        if allowed_sites is not None:
            allowed_set = {str(site).strip() for site in allowed_sites}
            items = [item for item in items if str(item.get("site") or "").strip() in allowed_set]
        _write_audit_log(
            principal=principal,
            action="ops_tutorial_simulator_sessions_view",
            resource_type="ops_tutorial_simulator_session",
            resource_id="list",
            status="success",
            detail={"limit": limit, "count": len(items)},
        )
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "limit": int(limit),
            "count": len(items),
            "items": items,
        }
    
    
    @router.get("/tutorial-simulator/sessions/{session_id}")
    def get_ops_tutorial_simulator_session(
        session_id: int,
        principal: dict[str, Any] = Depends(require_permission("admins:manage")),
    ) -> dict[str, Any]:
        session = _evaluate_tutorial_simulator_session(session_id=session_id)
        _require_site_access(principal, str(session.get("site") or ""))
        progress = session.get("progress", {}) if isinstance(session.get("progress"), dict) else {}
        _write_audit_log(
            principal=principal,
            action="ops_tutorial_simulator_session_view",
            resource_type="ops_tutorial_simulator_session",
            resource_id=str(session_id),
            status="success",
            detail={
                "site": session.get("site"),
                "completion_percent": int(progress.get("completion_percent") or 0),
                "status": progress.get("status"),
            },
        )
        return session
    
    
    @router.post("/tutorial-simulator/sessions/{session_id}/check")
    def check_ops_tutorial_simulator_session(
        session_id: int,
        principal: dict[str, Any] = Depends(require_permission("admins:manage")),
    ) -> dict[str, Any]:
        session = _evaluate_tutorial_simulator_session(session_id=session_id)
        _require_site_access(principal, str(session.get("site") or ""))
        progress = session.get("progress", {}) if isinstance(session.get("progress"), dict) else {}
        response = {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            **session,
        }
        _write_audit_log(
            principal=principal,
            action="ops_tutorial_simulator_session_check",
            resource_type="ops_tutorial_simulator_session",
            resource_id=str(session_id),
            status="success",
            detail={
                "site": session.get("site"),
                "completion_percent": int(progress.get("completion_percent") or 0),
                "status": progress.get("status"),
            },
        )
        return response
    
    
    @router.post("/tutorial-simulator/sessions/{session_id}/actions/{action}")
    def run_ops_tutorial_simulator_session_action(
        session_id: int,
        action: str,
        payload: dict[str, Any] | None = None,
        principal: dict[str, Any] = Depends(require_permission("admins:manage")),
    ) -> dict[str, Any]:
        current_session = _evaluate_tutorial_simulator_session(session_id=session_id)
        _require_site_access(principal, str(current_session.get("site") or ""))
        body = payload if isinstance(payload, dict) else {}
        result = _run_tutorial_simulator_action(
            session_id=session_id,
            action=action,
            actor_username=str(principal.get("username") or "system"),
            assignee=str(body.get("assignee")) if body.get("assignee") is not None else None,
            resolution_notes=str(body.get("resolution_notes")) if body.get("resolution_notes") is not None else None,
        )
        session = result.get("session", {}) if isinstance(result.get("session"), dict) else {}
        progress = session.get("progress", {}) if isinstance(session.get("progress"), dict) else {}
        _write_audit_log(
            principal=principal,
            action="ops_tutorial_simulator_session_action",
            resource_type="ops_tutorial_simulator_session",
            resource_id=str(session_id),
            status="success",
            detail={
                "action": str(result.get("action") or action),
                "result": result.get("result"),
                "work_order_status": result.get("work_order_status"),
                "site": session.get("site"),
                "completion_percent": int(progress.get("completion_percent") or 0),
                "progress_status": progress.get("status"),
            },
        )
        return result
    

    return router