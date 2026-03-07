"""Public JSON/HTML route extraction for main shell and onboarding surfaces."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Callable, Mapping, Sequence

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response


JsonPayloadBuilder = Callable[[], dict[str, Any]]
JsonTextBuilder = Callable[[dict[str, Any]], str]


@dataclass(frozen=True)
class PublicRouteDeps:
    service_info_payload: Callable[[], dict[str, str]]
    facility_modules_payload: JsonPayloadBuilder
    build_public_modules_html: JsonTextBuilder
    build_tutorial_simulator_payload: JsonPayloadBuilder
    build_tutorial_simulator_html: JsonTextBuilder
    build_tutorial_guide_html: JsonTextBuilder
    build_public_day1_onboarding_payload: JsonPayloadBuilder
    build_public_glossary_payload: JsonPayloadBuilder
    tutorial_simulator_sample_files_payload: JsonPayloadBuilder
    find_tutorial_simulator_sample_file: Callable[[str], dict[str, Any] | None]
    tutorial_simulator_sample_allowed_content_types: Sequence[str]
    build_system_main_tabs_html: Callable[[dict[str, str], str], str]
    build_facility_console_html: Callable[[dict[str, str], dict[str, Any]], str]
    build_facility_console_guide_html: Callable[[dict[str, str]], str]
    build_iam_guide_html: Callable[[dict[str, str]], str]
    build_public_main_page_html: Callable[[dict[str, str], dict[str, Any]], str]
    adoption_plan_payload: JsonPayloadBuilder
    adoption_plan_start: date
    adoption_plan_end: date
    build_adoption_plan_schedule_csv: JsonTextBuilder
    build_adoption_plan_schedule_ics: JsonTextBuilder
    week_payload_builders: Mapping[str, JsonPayloadBuilder]
    week_checklist_csv_builders: Mapping[str, JsonTextBuilder]
    week_schedule_ics_builders: Mapping[str, JsonTextBuilder]
    build_w04_common_mistakes_payload: Callable[..., dict[str, Any]]
    build_w04_common_mistakes_html: JsonTextBuilder
    build_adoption_w05_missions_csv: JsonTextBuilder
    w02_sample_files_payload: JsonPayloadBuilder
    find_w02_sample_file: Callable[[str], dict[str, Any] | None]
    evidence_allowed_content_types: Sequence[str]
    safe_download_filename: Callable[..., str]
    post_mvp_payload: JsonPayloadBuilder
    post_mvp_plan_start: date
    post_mvp_plan_end: date
    build_post_mvp_backlog_csv: JsonTextBuilder
    build_post_mvp_release_ics: JsonTextBuilder


def _accepts_html(request: Request) -> bool:
    return "text/html" in request.headers.get("accept", "").lower()


def _text_download_response(*, content: bytes, file_name: str, media_type: str) -> Response:
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


def _utf8_text_download_response(*, content_text: str, file_name: str, media_type: str) -> Response:
    return _text_download_response(
        content=content_text.encode("utf-8"),
        file_name=file_name,
        media_type=media_type,
    )


def build_router(deps: PublicRouteDeps) -> APIRouter:
    router = APIRouter(tags=["public"])
    tutorial_sample_types = {str(item).strip().lower() for item in deps.tutorial_simulator_sample_allowed_content_types}
    evidence_sample_types = {str(item).strip().lower() for item in deps.evidence_allowed_content_types}

    def week_payload(week: str) -> dict[str, Any]:
        return deps.week_payload_builders[week]()

    @router.get("/api/service-info")
    def service_info() -> dict[str, str]:
        return deps.service_info_payload()

    @router.get("/web/console", response_model=None)
    def facility_console() -> HTMLResponse:
        return HTMLResponse(
            deps.build_facility_console_html(
                deps.service_info_payload(),
                deps.facility_modules_payload(),
            )
        )

    @router.get("/web/console/guide", response_model=None)
    def facility_console_guide() -> HTMLResponse:
        return HTMLResponse(deps.build_facility_console_guide_html(deps.service_info_payload()))

    @router.get("/web/iam-guide", response_model=None)
    def iam_guide() -> HTMLResponse:
        return HTMLResponse(deps.build_iam_guide_html(deps.service_info_payload()))

    @router.get("/web/tutorial-guide", response_model=None)
    def tutorial_guide() -> HTMLResponse:
        return HTMLResponse(deps.build_tutorial_guide_html(deps.build_tutorial_simulator_payload()))

    @router.get("/web/adoption", response_model=None)
    def adoption_portal() -> HTMLResponse:
        return HTMLResponse(
            deps.build_public_main_page_html(
                deps.service_info_payload(),
                deps.adoption_plan_payload(),
            )
        )

    @router.get("/web/tutorial-simulator", response_model=None)
    def tutorial_simulator_portal() -> HTMLResponse:
        return HTMLResponse(deps.build_tutorial_simulator_html(deps.build_tutorial_simulator_payload()))

    @router.get("/", response_model=None)
    def root(request: Request) -> Any:
        if _accepts_html(request):
            selected_tab = request.query_params.get("tab", "").strip().lower()
            return HTMLResponse(deps.build_system_main_tabs_html(deps.service_info_payload(), selected_tab))
        return deps.service_info_payload()

    @router.get("/api/public/adoption-plan")
    def get_public_adoption_plan() -> dict[str, Any]:
        return deps.adoption_plan_payload()

    @router.get("/api/public/adoption-plan/campaign")
    def get_public_adoption_campaign() -> dict[str, Any]:
        plan = deps.adoption_plan_payload()
        return {
            "title": plan.get("title"),
            "public": plan.get("public", True),
            "campaign_kit": plan.get("campaign_kit", {}),
        }

    @router.get("/api/public/adoption-plan/w02")
    def get_public_adoption_w02() -> dict[str, Any]:
        return week_payload("w02")

    @router.get("/api/public/adoption-plan/w03")
    def get_public_adoption_w03() -> dict[str, Any]:
        return week_payload("w03")

    @router.get("/api/public/adoption-plan/w04")
    def get_public_adoption_w04() -> dict[str, Any]:
        return week_payload("w04")

    @router.get("/api/public/adoption-plan/w05")
    def get_public_adoption_w05() -> dict[str, Any]:
        return week_payload("w05")

    @router.get("/api/public/adoption-plan/w06")
    def get_public_adoption_w06() -> dict[str, Any]:
        return week_payload("w06")

    @router.get("/api/public/adoption-plan/w07")
    def get_public_adoption_w07() -> dict[str, Any]:
        return week_payload("w07")

    @router.get("/api/public/adoption-plan/w08")
    def get_public_adoption_w08() -> dict[str, Any]:
        return week_payload("w08")

    @router.get("/api/public/adoption-plan/w09")
    def get_public_adoption_w09() -> dict[str, Any]:
        return week_payload("w09")

    @router.get("/api/public/adoption-plan/w10")
    def get_public_adoption_w10() -> dict[str, Any]:
        return week_payload("w10")

    @router.get("/api/public/adoption-plan/w11")
    def get_public_adoption_w11() -> dict[str, Any]:
        return week_payload("w11")

    @router.get("/api/public/adoption-plan/w12")
    def get_public_adoption_w12() -> dict[str, Any]:
        return week_payload("w12")

    @router.get("/api/public/adoption-plan/w13")
    def get_public_adoption_w13() -> dict[str, Any]:
        return week_payload("w13")

    @router.get("/api/public/adoption-plan/w14")
    def get_public_adoption_w14() -> dict[str, Any]:
        return week_payload("w14")

    @router.get("/api/public/adoption-plan/w15")
    def get_public_adoption_w15() -> dict[str, Any]:
        return week_payload("w15")

    @router.get("/api/public/modules", response_model=None)
    def get_public_modules(request: Request) -> Any:
        payload = deps.facility_modules_payload()
        if _accepts_html(request):
            return HTMLResponse(deps.build_public_modules_html(payload))
        return payload

    @router.get("/api/public/tutorial-simulator", response_model=None)
    def get_public_tutorial_simulator(request: Request) -> Any:
        payload = deps.build_tutorial_simulator_payload()
        if _accepts_html(request):
            return HTMLResponse(deps.build_tutorial_simulator_html(payload))
        return payload

    @router.get("/api/public/onboarding/day1")
    def get_public_onboarding_day1() -> dict[str, Any]:
        return deps.build_public_day1_onboarding_payload()

    @router.get("/api/public/glossary")
    def get_public_glossary() -> dict[str, Any]:
        return deps.build_public_glossary_payload()

    @router.get("/api/public/tutorial-simulator/sample-files")
    def get_public_tutorial_simulator_sample_files() -> dict[str, Any]:
        return deps.tutorial_simulator_sample_files_payload()

    @router.get("/api/public/tutorial-simulator/sample-files/{sample_id}", response_model=None)
    def download_public_tutorial_simulator_sample_file(sample_id: str) -> Response:
        artifact = deps.find_tutorial_simulator_sample_file(sample_id)
        if artifact is None:
            raise HTTPException(status_code=404, detail="Tutorial simulator sample file not found")
        file_name = deps.safe_download_filename(
            str(artifact.get("file_name") or f"{sample_id}.txt"),
            fallback="tutorial-sample.txt",
            max_length=120,
        )
        content_type = str(artifact.get("content_type") or "text/plain").strip().lower() or "text/plain"
        if content_type not in tutorial_sample_types:
            content_type = "text/plain"
        media_type = f"{content_type}; charset=utf-8" if content_type.startswith("text/") else content_type
        return _text_download_response(
            content=str(artifact.get("content") or "").encode("utf-8"),
            file_name=file_name,
            media_type=media_type,
        )

    @router.get("/api/public/adoption-plan/schedule.csv")
    def get_public_adoption_plan_schedule_csv() -> Response:
        csv_text = deps.build_adoption_plan_schedule_csv(deps.adoption_plan_payload())
        file_name = (
            f"ka-facility-os-adoption-plan-"
            f"{deps.adoption_plan_start.isoformat()}-{deps.adoption_plan_end.isoformat()}.csv"
        )
        return _utf8_text_download_response(content_text=csv_text, file_name=file_name, media_type="text/csv; charset=utf-8")

    @router.get("/api/public/adoption-plan/schedule.ics")
    def get_public_adoption_plan_schedule_ics() -> Response:
        ics_text = deps.build_adoption_plan_schedule_ics(deps.adoption_plan_payload())
        file_name = (
            f"ka-facility-os-adoption-plan-"
            f"{deps.adoption_plan_start.isoformat()}-{deps.adoption_plan_end.isoformat()}.ics"
        )
        return _utf8_text_download_response(
            content_text=ics_text,
            file_name=file_name,
            media_type="text/calendar; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w02/checklist.csv")
    def get_public_adoption_w02_checklist_csv() -> Response:
        csv_text = deps.week_checklist_csv_builders["w02"](week_payload("w02"))
        return _utf8_text_download_response(
            content_text=csv_text,
            file_name="ka-facility-os-adoption-w02-sop-sandbox-checklist.csv",
            media_type="text/csv; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w02/schedule.ics")
    def get_public_adoption_w02_schedule_ics() -> Response:
        ics_text = deps.week_schedule_ics_builders["w02"](week_payload("w02"))
        return _utf8_text_download_response(
            content_text=ics_text,
            file_name="ka-facility-os-adoption-w02-sop-sandbox.ics",
            media_type="text/calendar; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w03/checklist.csv")
    def get_public_adoption_w03_checklist_csv() -> Response:
        csv_text = deps.week_checklist_csv_builders["w03"](week_payload("w03"))
        return _utf8_text_download_response(
            content_text=csv_text,
            file_name="ka-facility-os-adoption-w03-go-live-onboarding-checklist.csv",
            media_type="text/csv; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w03/schedule.ics")
    def get_public_adoption_w03_schedule_ics() -> Response:
        ics_text = deps.week_schedule_ics_builders["w03"](week_payload("w03"))
        return _utf8_text_download_response(
            content_text=ics_text,
            file_name="ka-facility-os-adoption-w03-go-live-onboarding.ics",
            media_type="text/calendar; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w04/checklist.csv")
    def get_public_adoption_w04_checklist_csv() -> Response:
        csv_text = deps.week_checklist_csv_builders["w04"](week_payload("w04"))
        return _utf8_text_download_response(
            content_text=csv_text,
            file_name="ka-facility-os-adoption-w04-first-success-acceleration-checklist.csv",
            media_type="text/csv; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w04/schedule.ics")
    def get_public_adoption_w04_schedule_ics() -> Response:
        ics_text = deps.week_schedule_ics_builders["w04"](week_payload("w04"))
        return _utf8_text_download_response(
            content_text=ics_text,
            file_name="ka-facility-os-adoption-w04-first-success-acceleration.ics",
            media_type="text/calendar; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w04/common-mistakes")
    def get_public_adoption_w04_common_mistakes(
        site: str | None = Query(default=None),
        days: int = Query(default=30, ge=1, le=90),
    ) -> dict[str, Any]:
        return deps.build_w04_common_mistakes_payload(site=site, days=days, allowed_sites=None)

    @router.get("/web/adoption/w04/common-mistakes", response_model=None)
    def get_public_adoption_w04_common_mistakes_html(
        site: str | None = Query(default=None),
        days: int = Query(default=30, ge=1, le=90),
    ) -> HTMLResponse:
        payload = deps.build_w04_common_mistakes_payload(site=site, days=days, allowed_sites=None)
        return HTMLResponse(deps.build_w04_common_mistakes_html(payload))

    @router.get("/api/public/adoption-plan/w05/missions.csv")
    def get_public_adoption_w05_missions_csv() -> Response:
        csv_text = deps.build_adoption_w05_missions_csv(week_payload("w05"))
        return _utf8_text_download_response(
            content_text=csv_text,
            file_name="ka-facility-os-adoption-w05-usage-consistency-missions.csv",
            media_type="text/csv; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w05/schedule.ics")
    def get_public_adoption_w05_schedule_ics() -> Response:
        ics_text = deps.week_schedule_ics_builders["w05"](week_payload("w05"))
        return _utf8_text_download_response(
            content_text=ics_text,
            file_name="ka-facility-os-adoption-w05-usage-consistency.ics",
            media_type="text/calendar; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w05/help-docs")
    def get_public_adoption_w05_help_docs() -> dict[str, Any]:
        payload = week_payload("w05")
        return {
            "title": "W05 Help Docs v2",
            "public": True,
            "timeline": payload.get("timeline", {}),
            "items": payload.get("help_docs", []),
        }

    @router.get("/api/public/adoption-plan/w06/checklist.csv")
    def get_public_adoption_w06_checklist_csv() -> Response:
        csv_text = deps.week_checklist_csv_builders["w06"](week_payload("w06"))
        return _utf8_text_download_response(
            content_text=csv_text,
            file_name="ka-facility-os-adoption-w06-operational-rhythm-checklist.csv",
            media_type="text/csv; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w06/schedule.ics")
    def get_public_adoption_w06_schedule_ics() -> Response:
        ics_text = deps.week_schedule_ics_builders["w06"](week_payload("w06"))
        return _utf8_text_download_response(
            content_text=ics_text,
            file_name="ka-facility-os-adoption-w06-operational-rhythm.ics",
            media_type="text/calendar; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w06/rbac-audit-template")
    def get_public_adoption_w06_rbac_audit_template() -> dict[str, Any]:
        payload = week_payload("w06")
        return {
            "title": "W06 RBAC Audit Template",
            "public": True,
            "timeline": payload.get("timeline", {}),
            "items": payload.get("rbac_audit_checklist", []),
        }

    @router.get("/api/public/adoption-plan/w07/checklist.csv")
    def get_public_adoption_w07_checklist_csv() -> Response:
        csv_text = deps.week_checklist_csv_builders["w07"](week_payload("w07"))
        return _utf8_text_download_response(
            content_text=csv_text,
            file_name="ka-facility-os-adoption-w07-sla-quality-checklist.csv",
            media_type="text/csv; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w07/schedule.ics")
    def get_public_adoption_w07_schedule_ics() -> Response:
        ics_text = deps.week_schedule_ics_builders["w07"](week_payload("w07"))
        return _utf8_text_download_response(
            content_text=ics_text,
            file_name="ka-facility-os-adoption-w07-sla-quality.ics",
            media_type="text/calendar; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w07/coaching-playbook")
    def get_public_adoption_w07_coaching_playbook() -> dict[str, Any]:
        payload = week_payload("w07")
        return {
            "title": "W07 Coaching Playbook",
            "public": True,
            "timeline": payload.get("timeline", {}),
            "items": payload.get("coaching_plays", []),
        }

    @router.get("/api/public/adoption-plan/w08/checklist.csv")
    def get_public_adoption_w08_checklist_csv() -> Response:
        csv_text = deps.week_checklist_csv_builders["w08"](week_payload("w08"))
        return _utf8_text_download_response(
            content_text=csv_text,
            file_name="ka-facility-os-adoption-w08-report-discipline-checklist.csv",
            media_type="text/csv; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w08/schedule.ics")
    def get_public_adoption_w08_schedule_ics() -> Response:
        ics_text = deps.week_schedule_ics_builders["w08"](week_payload("w08"))
        return _utf8_text_download_response(
            content_text=ics_text,
            file_name="ka-facility-os-adoption-w08-report-discipline.ics",
            media_type="text/calendar; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w09/checklist.csv")
    def get_public_adoption_w09_checklist_csv() -> Response:
        csv_text = deps.week_checklist_csv_builders["w09"](week_payload("w09"))
        return _utf8_text_download_response(
            content_text=csv_text,
            file_name="ka-facility-os-adoption-w09-kpi-operation-checklist.csv",
            media_type="text/csv; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w09/schedule.ics")
    def get_public_adoption_w09_schedule_ics() -> Response:
        ics_text = deps.week_schedule_ics_builders["w09"](week_payload("w09"))
        return _utf8_text_download_response(
            content_text=ics_text,
            file_name="ka-facility-os-adoption-w09-kpi-operation.ics",
            media_type="text/calendar; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w10/checklist.csv")
    def get_public_adoption_w10_checklist_csv() -> Response:
        csv_text = deps.week_checklist_csv_builders["w10"](week_payload("w10"))
        return _utf8_text_download_response(
            content_text=csv_text,
            file_name="ka-facility-os-adoption-w10-self-serve-support-checklist.csv",
            media_type="text/csv; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w10/schedule.ics")
    def get_public_adoption_w10_schedule_ics() -> Response:
        ics_text = deps.week_schedule_ics_builders["w10"](week_payload("w10"))
        return _utf8_text_download_response(
            content_text=ics_text,
            file_name="ka-facility-os-adoption-w10-self-serve-support.ics",
            media_type="text/calendar; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w11/checklist.csv")
    def get_public_adoption_w11_checklist_csv() -> Response:
        csv_text = deps.week_checklist_csv_builders["w11"](week_payload("w11"))
        return _utf8_text_download_response(
            content_text=csv_text,
            file_name="ka-facility-os-adoption-w11-scale-readiness-checklist.csv",
            media_type="text/csv; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w11/schedule.ics")
    def get_public_adoption_w11_schedule_ics() -> Response:
        ics_text = deps.week_schedule_ics_builders["w11"](week_payload("w11"))
        return _utf8_text_download_response(
            content_text=ics_text,
            file_name="ka-facility-os-adoption-w11-scale-readiness.ics",
            media_type="text/calendar; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w12/checklist.csv")
    def get_public_adoption_w12_checklist_csv() -> Response:
        csv_text = deps.week_checklist_csv_builders["w12"](week_payload("w12"))
        return _utf8_text_download_response(
            content_text=csv_text,
            file_name="ka-facility-os-adoption-w12-closure-handoff-checklist.csv",
            media_type="text/csv; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w12/schedule.ics")
    def get_public_adoption_w12_schedule_ics() -> Response:
        ics_text = deps.week_schedule_ics_builders["w12"](week_payload("w12"))
        return _utf8_text_download_response(
            content_text=ics_text,
            file_name="ka-facility-os-adoption-w12-closure-handoff.ics",
            media_type="text/calendar; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w13/checklist.csv")
    def get_public_adoption_w13_checklist_csv() -> Response:
        csv_text = deps.week_checklist_csv_builders["w13"](week_payload("w13"))
        return _utf8_text_download_response(
            content_text=csv_text,
            file_name="ka-facility-os-adoption-w13-continuous-improvement-checklist.csv",
            media_type="text/csv; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w13/schedule.ics")
    def get_public_adoption_w13_schedule_ics() -> Response:
        ics_text = deps.week_schedule_ics_builders["w13"](week_payload("w13"))
        return _utf8_text_download_response(
            content_text=ics_text,
            file_name="ka-facility-os-adoption-w13-continuous-improvement.ics",
            media_type="text/calendar; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w14/checklist.csv")
    def get_public_adoption_w14_checklist_csv() -> Response:
        csv_text = deps.week_checklist_csv_builders["w14"](week_payload("w14"))
        return _utf8_text_download_response(
            content_text=csv_text,
            file_name="ka-facility-os-adoption-w14-stability-sprint-checklist.csv",
            media_type="text/csv; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w14/schedule.ics")
    def get_public_adoption_w14_schedule_ics() -> Response:
        ics_text = deps.week_schedule_ics_builders["w14"](week_payload("w14"))
        return _utf8_text_download_response(
            content_text=ics_text,
            file_name="ka-facility-os-adoption-w14-stability-sprint.ics",
            media_type="text/calendar; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w15/checklist.csv")
    def get_public_adoption_w15_checklist_csv() -> Response:
        csv_text = deps.week_checklist_csv_builders["w15"](week_payload("w15"))
        return _utf8_text_download_response(
            content_text=csv_text,
            file_name="ka-facility-os-adoption-w15-operations-efficiency-checklist.csv",
            media_type="text/csv; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w15/schedule.ics")
    def get_public_adoption_w15_schedule_ics() -> Response:
        ics_text = deps.week_schedule_ics_builders["w15"](week_payload("w15"))
        return _utf8_text_download_response(
            content_text=ics_text,
            file_name="ka-facility-os-adoption-w15-operations-efficiency.ics",
            media_type="text/calendar; charset=utf-8",
        )

    @router.get("/api/public/adoption-plan/w08/reporting-sop")
    def get_public_adoption_w08_reporting_sop() -> dict[str, Any]:
        payload = week_payload("w08")
        return {
            "title": "W08 Reporting SOP",
            "public": True,
            "count": len(payload.get("reporting_sop", [])),
            "items": payload.get("reporting_sop", []),
        }

    @router.get("/api/public/adoption-plan/w02/sample-files")
    def get_public_adoption_w02_sample_files() -> dict[str, Any]:
        return deps.w02_sample_files_payload()

    @router.get("/api/public/adoption-plan/w02/sample-files/{sample_id}", response_model=None)
    def download_public_adoption_w02_sample_file(sample_id: str) -> Response:
        artifact = deps.find_w02_sample_file(sample_id)
        if artifact is None:
            raise HTTPException(status_code=404, detail="W02 sample file not found")
        file_name = deps.safe_download_filename(
            str(artifact.get("file_name") or f"{sample_id}.txt"),
            fallback="w02-sample.txt",
            max_length=120,
        )
        content_type = str(artifact.get("content_type") or "text/plain").strip().lower() or "text/plain"
        if content_type not in evidence_sample_types:
            content_type = "text/plain"
        return _utf8_text_download_response(
            content_text=str(artifact.get("content") or ""),
            file_name=file_name,
            media_type=f"{content_type}; charset=utf-8",
        )

    @router.get("/api/public/post-mvp")
    def get_public_post_mvp_plan() -> dict[str, Any]:
        return deps.post_mvp_payload()

    @router.get("/api/public/post-mvp/backlog.csv")
    def get_public_post_mvp_backlog_csv() -> Response:
        csv_text = deps.build_post_mvp_backlog_csv(deps.post_mvp_payload())
        file_name = (
            f"ka-facility-os-post-mvp-backlog-"
            f"{deps.post_mvp_plan_start.isoformat()}-{deps.post_mvp_plan_end.isoformat()}.csv"
        )
        return _utf8_text_download_response(content_text=csv_text, file_name=file_name, media_type="text/csv; charset=utf-8")

    @router.get("/api/public/post-mvp/releases.ics")
    def get_public_post_mvp_releases_ics() -> Response:
        ics_text = deps.build_post_mvp_release_ics(deps.post_mvp_payload())
        file_name = (
            f"ka-facility-os-post-mvp-releases-"
            f"{deps.post_mvp_plan_start.isoformat()}-{deps.post_mvp_plan_end.isoformat()}.ics"
        )
        return _utf8_text_download_response(
            content_text=ics_text,
            file_name=file_name,
            media_type="text/calendar; charset=utf-8",
        )

    @router.get("/api/public/post-mvp/kpi-dashboard")
    def get_public_post_mvp_kpi_dashboard() -> dict[str, Any]:
        plan = deps.post_mvp_payload()
        return {
            "title": plan.get("title"),
            "public": plan.get("public", True),
            "timeline": plan.get("timeline", {}),
            "kpi_dashboard_spec": plan.get("kpi_dashboard_spec", []),
        }

    @router.get("/api/public/post-mvp/risks")
    def get_public_post_mvp_risks() -> dict[str, Any]:
        plan = deps.post_mvp_payload()
        return {
            "title": plan.get("title"),
            "public": plan.get("public", True),
            "timeline": plan.get("timeline", {}),
            "risk_register": plan.get("risk_register", []),
        }

    return router
