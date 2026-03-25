"""Split deployment app factories for facility-core and platform-admin."""

from __future__ import annotations

import asyncio
import copy
from collections.abc import AsyncIterator, Callable, Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import HTMLResponse
from starlette.middleware.gzip import GZipMiddleware

from app import main as main_module
from app.web.facility_console import build_public_modules_html
from app.web.split_shell import build_split_home_html


FACILITY_CORE_MODULE_IDS = frozenset(
    {
        "inspection-ops",
        "work-order-ops",
        "household-complaints",
        "utility-billing",
        "official-documents",
        "reporting-audit",
    }
)

SHELL_PUBLIC_ROUTE_EXCLUDES = frozenset(
    {
        "/",
        "/api/service-info",
        "/web/console",
        "/web/console/app.js",
        "/web/main-shell/app.js",
        "/web/console/guide",
        "/web/iam-guide",
        "/api/public/modules",
    }
)


@dataclass(frozen=True)
class SplitSurface:
    service_name: str
    badge: str
    title: str
    description: str
    quick_links: tuple[dict[str, str], ...]
    notes: str = ""


FACILITY_CORE_SURFACE = SplitSurface(
    service_name="ka-facility-core",
    badge="Facility Core",
    title="시설 운영 코어",
    description="점검, 작업지시, 세대 민원, 요금부과, 공문관리처럼 현장 실무에 직접 쓰는 기능만 묶은 경량 엔트리포인트입니다.",
    quick_links=(
        {"label": "세대 민원처리", "href": "/web/complaints"},
        {"label": "Swagger Docs", "href": "/docs"},
        {"label": "모듈 JSON", "href": "/api/public/modules"},
        {"label": "권한 확인", "href": "/api/auth/me"},
    ),
    notes="백그라운드 자동화와 거버넌스 배치는 기존 메인 서비스에서 계속 실행되도록 두고, 이 앱은 현장/업무 라우트 분리에 집중합니다.",
)

PLATFORM_ADMIN_SURFACE = SplitSurface(
    service_name="ka-platform-admin",
    badge="Platform Admin",
    title="플랫폼 관리 허브",
    description="거버넌스, SLA/알림, 정착 계획, 튜토리얼, 운영 전환 지표처럼 관리자와 PM이 쓰는 관리성 기능만 모은 엔트리포인트입니다.",
    quick_links=(
        {"label": "정착 계획", "href": "/web/adoption"},
        {"label": "튜토리얼", "href": "/web/tutorial-simulator"},
        {"label": "거버넌스 게이트", "href": "/api/ops/governance/gate"},
        {"label": "Swagger Docs", "href": "/docs"},
        {"label": "모듈 JSON", "href": "/api/public/modules"},
    ),
    notes="split-admin 앱은 정착/거버넌스 전용입니다. 현장 민원/점검/작업지시는 facility-core 또는 기존 메인 서비스에서 계속 사용하면 됩니다.",
)


def _secure_shell_html_response(content: str) -> HTMLResponse:
    return HTMLResponse(
        content,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "X-Robots-Tag": "noindex, nofollow",
        },
    )


def _accepts_html(request: Request) -> bool:
    return "text/html" in request.headers.get("accept", "").lower()


def _split_service_info_payload(surface: SplitSurface, *, modules_payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "service": surface.service_name,
        "status": "running",
        "main_html": "/",
        "console_html": "/web/console",
        "docs": "/docs",
        "modules_api": "/api/public/modules",
        "split_surface": surface.badge.lower().replace(" ", "-"),
        "module_count": len(modules_payload.get("modules", [])),
    }


def _filtered_modules_payload(*, include_ids: set[str] | frozenset[str] | None = None, exclude_ids: set[str] | frozenset[str] | None = None) -> dict[str, Any]:
    payload = copy.deepcopy(main_module._facility_modules_payload())
    modules = list(payload.get("modules", []))
    if include_ids is not None:
        modules = [item for item in modules if str(item.get("id") or "") in include_ids]
    if exclude_ids is not None:
        modules = [item for item in modules if str(item.get("id") or "") not in exclude_ids]
    payload["modules"] = modules
    payload["main_page"] = "/"
    payload["console_html"] = "/web/console"
    return payload


def _build_split_shell_router(surface: SplitSurface, modules_payload: dict[str, Any]) -> APIRouter:
    service_info = _split_service_info_payload(surface, modules_payload=modules_payload)
    router = APIRouter(tags=["public"])

    def _render_shell() -> str:
        return build_split_home_html(
            service_info,
            modules_payload,
            badge=surface.badge,
            title=surface.title,
            description=surface.description,
            quick_links=list(surface.quick_links),
            note=surface.notes,
        )

    @router.get("/api/service-info")
    def service_info_payload() -> dict[str, Any]:
        return service_info

    @router.get("/api/public/modules", response_model=None)
    def public_modules(request: Request) -> Any:
        if _accepts_html(request):
            return HTMLResponse(build_public_modules_html(modules_payload))
        return modules_payload

    @router.get("/web/console", response_model=None)
    def split_console() -> HTMLResponse:
        return _secure_shell_html_response(_render_shell())

    @router.get("/", response_model=None)
    def split_root(request: Request) -> Any:
        if _accepts_html(request):
            return _secure_shell_html_response(_render_shell())
        return service_info

    return router


def _build_split_meta_router(surface: SplitSurface, modules_payload: dict[str, Any]) -> APIRouter:
    router = APIRouter(tags=["platform"])
    service_info = _split_service_info_payload(surface, modules_payload=modules_payload)

    @router.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @router.get("/meta")
    def meta() -> dict[str, str]:
        db_backend = "postgresql" if main_module.DATABASE_URL.startswith("postgresql+") else "sqlite"
        return {
            "env": main_module.getenv("ENV", "local"),
            "db": db_backend,
            "service": str(service_info.get("service") or ""),
        }

    return router


def _copy_router_with_excluded_paths(source: APIRouter, *, excluded_paths: Iterable[str]) -> APIRouter:
    excluded = set(excluded_paths)
    router = APIRouter(tags=["public"])
    for route in source.routes:
        if getattr(route, "path", "") in excluded:
            continue
        router.routes.append(route)
    return router


def _attach_common_middlewares(app: FastAPI) -> None:
    app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)
    app.middleware("http")(main_module.browser_json_to_html_middleware)
    app.middleware("http")(main_module.api_rate_limit_middleware)
    app.middleware("http")(main_module.api_latency_monitor_middleware)
    app.middleware("http")(main_module.security_headers_middleware)


def _build_lifespan(*, run_background_automation: bool) -> Callable[[FastAPI], AsyncIterator[None]]:
    @asynccontextmanager
    async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
        main_module.ensure_database()
        main_module._ensure_evidence_storage_ready()
        main_module.ensure_legacy_admin_token_seed()
        main_module._init_rate_limit_backend()
        preflight = main_module._refresh_startup_preflight_snapshot()
        if bool(preflight.get("has_error")) and main_module.PREFLIGHT_FAIL_ON_ERROR:
            blocking_checks = [
                str(item.get("id") or "unknown")
                for item in preflight.get("checks", [])
                if item.get("status") == "error"
            ]
            detail = ", ".join(blocking_checks) if blocking_checks else "unknown"
            raise RuntimeError(f"Startup preflight failed with blocking errors: {detail}")

        overdue_scheduler_task: asyncio.Task[None] | None = None
        if run_background_automation and main_module.OFFICIAL_DOCUMENT_OVERDUE_AUTOMATION_ENABLED:
            overdue_scheduler_task = asyncio.create_task(
                main_module._official_document_overdue_scheduler_loop(),
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

    return _lifespan


def create_facility_core_app(*, run_background_automation: bool = False) -> FastAPI:
    modules_payload = _filtered_modules_payload(include_ids=FACILITY_CORE_MODULE_IDS)
    app = FastAPI(
        title="KA Facility Core",
        description="Facility core split deployment for field operations",
        version=main_module.app.version,
        lifespan=_build_lifespan(run_background_automation=run_background_automation),
    )
    _attach_common_middlewares(app)

    app.include_router(_build_split_meta_router(FACILITY_CORE_SURFACE, modules_payload))
    app.include_router(_build_split_shell_router(FACILITY_CORE_SURFACE, modules_payload))
    app.include_router(main_module.iam_auth_router)
    app.include_router(main_module.complaints_router)
    app.include_router(main_module.ops_billing_router)
    app.include_router(main_module.ops_core_router)
    app.include_router(main_module.ops_official_documents_router)
    return app


def create_platform_admin_app(*, run_background_automation: bool = False) -> FastAPI:
    modules_payload = _filtered_modules_payload(exclude_ids=FACILITY_CORE_MODULE_IDS)
    app = FastAPI(
        title="KA Platform Admin",
        description="Platform admin split deployment for governance and adoption operations",
        version=main_module.app.version,
        lifespan=_build_lifespan(run_background_automation=run_background_automation),
    )
    _attach_common_middlewares(app)

    app.include_router(_build_split_meta_router(PLATFORM_ADMIN_SURFACE, modules_payload))
    app.include_router(_build_split_shell_router(PLATFORM_ADMIN_SURFACE, modules_payload))
    app.include_router(main_module.iam_auth_router)
    app.include_router(_copy_router_with_excluded_paths(main_module.public_router, excluded_paths=SHELL_PUBLIC_ROUTE_EXCLUDES))
    app.include_router(main_module.ops_governance_router)
    app.include_router(main_module.ops_alerts_router)
    app.include_router(main_module.ops_reporting_router)
    app.include_router(main_module.ops_tutorial_router)
    app.include_router(main_module.iam_admin_router)
    app.include_router(main_module.ops_sla_admin_router)
    app.include_router(main_module.adoption_router)
    app.include_router(main_module.adoption_ops_router)
    return app
