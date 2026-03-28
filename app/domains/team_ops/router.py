"""Team operations routes."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import HTMLResponse

from app.domains.iam.core import _principal_site_scope
from app.domains.iam.security import _require_site_access, require_permission
from app.domains.team_ops import service
from app.domains.team_ops.schemas import (
    TeamOpsDashboardRead,
    TeamOpsFacilityCreate,
    TeamOpsFacilityRead,
    TeamOpsFacilityUpdate,
    TeamOpsInventoryCreate,
    TeamOpsInventoryRead,
    TeamOpsInventoryUpdate,
    TeamOpsLogCreate,
    TeamOpsLogRead,
    TeamOpsLogUpdate,
)
from app.web.team_ops import build_team_ops_html, team_ops_script_text, team_ops_script_version


router = APIRouter(tags=["team_ops"])


def _allowed_sites_for_principal(principal: dict[str, Any]) -> list[str] | None:
    scope = _principal_site_scope(principal)
    if "*" in scope:
        return None
    return scope


def _secure_html_response(content: str) -> HTMLResponse:
    return HTMLResponse(
        content,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "X-Robots-Tag": "noindex, nofollow",
        },
    )


@router.get("/web/team-ops", response_model=None)
def team_ops_page() -> HTMLResponse:
    return _secure_html_response(build_team_ops_html())


@router.get("/web/team-ops/app.js", response_model=None)
def team_ops_script() -> Response:
    return Response(
        content=team_ops_script_text(),
        media_type="application/javascript",
        headers={
            "Cache-Control": "public, max-age=31536000, immutable",
            "ETag": team_ops_script_version(),
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/api/team-ops/dashboard", response_model=TeamOpsDashboardRead)
def get_team_ops_dashboard(
    site: str,
    range_key: Annotated[str, Query()] = "week",
    principal: dict[str, Any] = Depends(require_permission("team_ops:read")),
) -> TeamOpsDashboardRead:
    _require_site_access(principal, site)
    return service.get_dashboard(
        site=site,
        range_key=range_key,
        allowed_sites=_allowed_sites_for_principal(principal),
    )


@router.get("/api/team-ops/logs", response_model=list[TeamOpsLogRead])
def list_team_ops_logs(
    site: str,
    q: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    principal: dict[str, Any] = Depends(require_permission("team_ops:read")),
) -> list[TeamOpsLogRead]:
    _require_site_access(principal, site)
    return service.list_logs(site=site, q=q, limit=limit, allowed_sites=_allowed_sites_for_principal(principal))


@router.post("/api/team-ops/logs", response_model=TeamOpsLogRead, status_code=201)
def create_team_ops_log(
    payload: TeamOpsLogCreate,
    principal: dict[str, Any] = Depends(require_permission("team_ops:write")),
) -> TeamOpsLogRead:
    _require_site_access(principal, payload.site)
    return service.create_log(
        payload=payload,
        principal=principal,
        allowed_sites=_allowed_sites_for_principal(principal),
    )


@router.patch("/api/team-ops/logs/{log_id}", response_model=TeamOpsLogRead)
def update_team_ops_log(
    log_id: int,
    payload: TeamOpsLogUpdate,
    principal: dict[str, Any] = Depends(require_permission("team_ops:write")),
) -> TeamOpsLogRead:
    return service.update_log(
        log_id=log_id,
        payload=payload,
        principal=principal,
        allowed_sites=_allowed_sites_for_principal(principal),
    )


@router.delete("/api/team-ops/logs/{log_id}")
def delete_team_ops_log(
    log_id: int,
    principal: dict[str, Any] = Depends(require_permission("team_ops:write")),
) -> dict[str, Any]:
    return service.delete_log(
        log_id=log_id,
        principal=principal,
        allowed_sites=_allowed_sites_for_principal(principal),
    )


@router.get("/api/team-ops/facilities", response_model=list[TeamOpsFacilityRead])
def list_team_ops_facilities(
    site: str,
    q: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    principal: dict[str, Any] = Depends(require_permission("team_ops:read")),
) -> list[TeamOpsFacilityRead]:
    _require_site_access(principal, site)
    return service.list_facilities(site=site, q=q, limit=limit, allowed_sites=_allowed_sites_for_principal(principal))


@router.post("/api/team-ops/facilities", response_model=TeamOpsFacilityRead, status_code=201)
def create_team_ops_facility(
    payload: TeamOpsFacilityCreate,
    principal: dict[str, Any] = Depends(require_permission("team_ops:write")),
) -> TeamOpsFacilityRead:
    _require_site_access(principal, payload.site)
    return service.create_facility(
        payload=payload,
        principal=principal,
        allowed_sites=_allowed_sites_for_principal(principal),
    )


@router.patch("/api/team-ops/facilities/{facility_id}", response_model=TeamOpsFacilityRead)
def update_team_ops_facility(
    facility_id: int,
    payload: TeamOpsFacilityUpdate,
    principal: dict[str, Any] = Depends(require_permission("team_ops:write")),
) -> TeamOpsFacilityRead:
    return service.update_facility(
        facility_id=facility_id,
        payload=payload,
        principal=principal,
        allowed_sites=_allowed_sites_for_principal(principal),
    )


@router.delete("/api/team-ops/facilities/{facility_id}")
def delete_team_ops_facility(
    facility_id: int,
    principal: dict[str, Any] = Depends(require_permission("team_ops:write")),
) -> dict[str, Any]:
    return service.delete_facility(
        facility_id=facility_id,
        principal=principal,
        allowed_sites=_allowed_sites_for_principal(principal),
    )


@router.get("/api/team-ops/inventory", response_model=list[TeamOpsInventoryRead])
def list_team_ops_inventory(
    site: str,
    q: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    principal: dict[str, Any] = Depends(require_permission("team_ops:read")),
) -> list[TeamOpsInventoryRead]:
    _require_site_access(principal, site)
    return service.list_inventory(site=site, q=q, limit=limit, allowed_sites=_allowed_sites_for_principal(principal))


@router.post("/api/team-ops/inventory", response_model=TeamOpsInventoryRead, status_code=201)
def create_team_ops_inventory(
    payload: TeamOpsInventoryCreate,
    principal: dict[str, Any] = Depends(require_permission("team_ops:write")),
) -> TeamOpsInventoryRead:
    _require_site_access(principal, payload.site)
    return service.create_inventory_item(
        payload=payload,
        principal=principal,
        allowed_sites=_allowed_sites_for_principal(principal),
    )


@router.patch("/api/team-ops/inventory/{item_id}", response_model=TeamOpsInventoryRead)
def update_team_ops_inventory(
    item_id: int,
    payload: TeamOpsInventoryUpdate,
    principal: dict[str, Any] = Depends(require_permission("team_ops:write")),
) -> TeamOpsInventoryRead:
    return service.update_inventory_item(
        item_id=item_id,
        payload=payload,
        principal=principal,
        allowed_sites=_allowed_sites_for_principal(principal),
    )


@router.delete("/api/team-ops/inventory/{item_id}")
def delete_team_ops_inventory(
    item_id: int,
    principal: dict[str, Any] = Depends(require_permission("team_ops:write")),
) -> dict[str, Any]:
    return service.delete_inventory_item(
        item_id=item_id,
        principal=principal,
        allowed_sites=_allowed_sites_for_principal(principal),
    )
