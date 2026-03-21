"""Public-facing HTML renderers extracted from app.main."""

from __future__ import annotations

import html
from datetime import date, datetime, timezone
from typing import Any


def _facility_modules_payload() -> dict[str, Any]:
    from app.main import _facility_modules_payload as payload_builder

    return payload_builder()


def _post_mvp_payload() -> dict[str, Any]:
    from app.main import _post_mvp_payload as payload_builder

    return payload_builder()


def build_w04_common_mistakes_html(payload: dict[str, Any]) -> str:
    rows: list[str] = []
    for item in payload.get("items", []):
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('mistake', '')))}</td>"
            f"<td>{html.escape(str(item.get('symptom', '')))}</td>"
            f"<td>{html.escape(str(item.get('quick_fix', '')))}</td>"
            f"<td>{html.escape(str(item.get('where_to_check', '')))}</td>"
            f"<td>{html.escape(str(item.get('observed_count', 0)))}</td>"
            "</tr>"
        )
    if not rows:
        rows.append("<tr><td colspan='5'>No data</td></tr>")

    return f"""
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>W04 자주 하는 실수</title>
  <style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #f2f6fb; color: #112; }}
    .wrap {{ max-width: 980px; margin: 0 auto; padding: 18px; }}
    .box {{ background: #fff; border: 1px solid #d8e2ef; border-radius: 12px; padding: 14px; }}
    h1 {{ margin: 0 0 8px; font-size: 24px; }}
    p {{ margin: 0 0 10px; color: #355; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border: 1px solid #d8e2ef; padding: 8px; font-size: 13px; text-align: left; vertical-align: top; }}
    th {{ background: #eef4fb; }}
    .links a {{ margin-right: 8px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="box">
      <h1>{html.escape(str(payload.get("title", "W04 자주 하는 실수")))}</h1>
      <p>생성 시각: {html.escape(str(payload.get("generated_at", "")))}</p>
      <p>사이트: {html.escape(str(payload.get("site", "ALL")))} | 기간: {html.escape(str(payload.get("window_days", "")))}일</p>
      <div class="links">
        <a href="/api/public/adoption-plan/w04/common-mistakes">JSON 보기</a>
        <a href="/api/public/adoption-plan/w04">W04 패키지</a>
        <a href="/">메인</a>
      </div>
      <table>
        <thead>
          <tr><th>실수</th><th>증상</th><th>빠른 해결</th><th>확인 위치</th><th>발생 수</th></tr>
        </thead>
        <tbody>
          {"".join(rows)}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""

def build_public_main_page_html(service_info: dict[str, str], plan: dict[str, Any]) -> str:
    training = plan.get("training_outline", [])
    kpis = plan.get("kpi_dashboard_items", [])
    w02_pack = plan.get("w02_sop_sandbox", {})
    w03_pack = plan.get("w03_go_live_onboarding", {})
    w04_pack = plan.get("w04_first_success_acceleration", {})
    w05_pack = plan.get("w05_usage_consistency", {})
    w06_pack = plan.get("w06_operational_rhythm", {})
    w07_pack = plan.get("w07_sla_quality", {})
    w08_pack = plan.get("w08_report_discipline", {})
    w09_pack = plan.get("w09_kpi_operation", {})
    w10_pack = plan.get("w10_self_serve_support", {})
    w11_pack = plan.get("w11_scale_readiness", {})
    w12_pack = plan.get("w12_closure_handoff", {})
    w13_pack = plan.get("w13_continuous_improvement", {})
    w14_pack = plan.get("w14_stability_sprint", {})
    w15_pack = plan.get("w15_operations_efficiency", {})
    post_mvp = _post_mvp_payload()
    module_hub = _facility_modules_payload()
    facility_modules = module_hub.get("modules", [])

    weekly_rows: list[str] = []
    for item in plan.get("weekly_execution", []):
        actions_html = "<br>".join(f"&middot; {html.escape(str(x))}" for x in item.get("actions", []))
        deliverables_html = "<br>".join(f"&middot; {html.escape(str(x))}" for x in item.get("deliverables", []))
        weekly_rows.append(
            f"""
            <tr>
              <td>W{int(item.get('week', 0)):02d}</td>
              <td>{html.escape(str(item.get("start_date", "")))} ~ {html.escape(str(item.get("end_date", "")))}</td>
              <td>{html.escape(str(item.get("phase", "")))}</td>
              <td>{html.escape(str(item.get("focus", "")))}</td>
              <td>{actions_html}</td>
              <td>{deliverables_html}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("success_metric", "")))}</td>
            </tr>
            """
        )

    training_rows: list[str] = []
    for module in training:
        contents_html = "<br>".join(f"&middot; {html.escape(str(x))}" for x in module.get("contents", []))
        training_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(module.get("module", "")))}</td>
              <td>{html.escape(str(module.get("audience", "")))}</td>
              <td>{html.escape(str(module.get("duration_min", "")))} min</td>
              <td>{contents_html}</td>
              <td>{html.escape(str(module.get("format", "")))}</td>
            </tr>
            """
        )

    kpi_rows: list[str] = []
    for item in kpis:
        kpi_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("name", "")))}</td>
              <td>{html.escape(str(item.get("formula", "")))}</td>
              <td>{html.escape(str(item.get("target", "")))}</td>
              <td>{html.escape(str(item.get("data_source", "")))}</td>
              <td>{html.escape(str(item.get("frequency", "")))}</td>
            </tr>
            """
        )

    workflow_matrix_rows: list[str] = []
    for item in plan.get("workflow_lock_matrix", {}).get("rows", []):
        perms = item.get("permissions", {})
        workflow_matrix_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("role", "")))}</td>
              <td>{html.escape(str(perms.get("DRAFT", "")))}</td>
              <td>{html.escape(str(perms.get("REVIEW", "")))}</td>
              <td>{html.escape(str(perms.get("APPROVED", "")))}</td>
              <td>{html.escape(str(perms.get("LOCKED", "")))}</td>
            </tr>
            """
        )

    w02_sop_rows: list[str] = []
    for item in w02_pack.get("sop_runbooks", []):
        targets = ", ".join(str(x) for x in item.get("target_roles", []))
        checkpoints = "<br>".join(f"&middot; {html.escape(str(x))}" for x in item.get("checkpoints", []))
        w02_sop_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("name", "")))}</td>
              <td>{html.escape(targets)}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("trigger", "")))}</td>
              <td>{checkpoints}</td>
              <td>{html.escape(str(item.get("definition_of_done", "")))}</td>
            </tr>
            """
        )

    w02_sandbox_rows: list[str] = []
    for item in w02_pack.get("sandbox_scenarios", []):
        api_flow = "<br>".join(f"&middot; {html.escape(str(x))}" for x in item.get("api_flow", []))
        pass_criteria = "<br>".join(f"&middot; {html.escape(str(x))}" for x in item.get("pass_criteria", []))
        w02_sandbox_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("module", "")))}</td>
              <td>{html.escape(str(item.get("objective", "")))}</td>
              <td>{api_flow}</td>
              <td>{pass_criteria}</td>
              <td>{html.escape(str(item.get("duration_min", "")))}</td>
            </tr>
            """
        )

    w02_schedule_rows: list[str] = []
    for item in w02_pack.get("scheduled_events", []):
        w02_schedule_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("date", "")))}</td>
              <td>{html.escape(str(item.get("start_time", "")))} - {html.escape(str(item.get("end_time", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("output", "")))}</td>
            </tr>
            """
        )

    w03_kickoff_rows: list[str] = []
    for item in w03_pack.get("kickoff_agenda", []):
        w03_kickoff_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("topic", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("duration_min", "")))}</td>
              <td>{html.escape(str(item.get("objective", "")))}</td>
              <td>{html.escape(str(item.get("expected_output", "")))}</td>
            </tr>
            """
        )

    w03_workshop_rows: list[str] = []
    for item in w03_pack.get("role_workshops", []):
        checklist_html = "<br>".join(f"&middot; {html.escape(str(x))}" for x in item.get("checklist", []))
        w03_workshop_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("role", "")))}</td>
              <td>{html.escape(str(item.get("trainer", "")))}</td>
              <td>{html.escape(str(item.get("duration_min", "")))}</td>
              <td>{html.escape(str(item.get("objective", "")))}</td>
              <td>{checklist_html}</td>
              <td>{html.escape(str(item.get("success_criteria", "")))}</td>
            </tr>
            """
        )

    w03_office_rows: list[str] = []
    for item in w03_pack.get("office_hours", []):
        w03_office_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("date", "")))}</td>
              <td>{html.escape(str(item.get("start_time", "")))} - {html.escape(str(item.get("end_time", "")))}</td>
              <td>{html.escape(str(item.get("host", "")))}</td>
              <td>{html.escape(str(item.get("focus", "")))}</td>
              <td>{html.escape(str(item.get("channel", "")))}</td>
            </tr>
            """
        )

    w03_schedule_rows: list[str] = []
    for item in w03_pack.get("scheduled_events", []):
        w03_schedule_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("date", "")))}</td>
              <td>{html.escape(str(item.get("start_time", "")))} - {html.escape(str(item.get("end_time", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("output", "")))}</td>
            </tr>
            """
        )

    w04_action_rows: list[str] = []
    for item in w04_pack.get("coaching_actions", []):
        w04_action_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("champion_role", "")))}</td>
              <td>{html.escape(str(item.get("action", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("due_hint", "")))}</td>
              <td>{html.escape(str(item.get("objective", "")))}</td>
              <td>{html.escape(str(item.get("evidence_required", "")))}</td>
            </tr>
            """
        )

    w04_schedule_rows: list[str] = []
    for item in w04_pack.get("scheduled_events", []):
        w04_schedule_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("date", "")))}</td>
              <td>{html.escape(str(item.get("start_time", "")))} - {html.escape(str(item.get("end_time", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("output", "")))}</td>
            </tr>
            """
        )

    w05_mission_rows: list[str] = []
    for item in w05_pack.get("role_missions", []):
        w05_mission_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("role", "")))}</td>
              <td>{html.escape(str(item.get("mission", "")))}</td>
              <td>{html.escape(str(item.get("weekly_target", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("evidence_required", "")))}</td>
              <td>{html.escape(str(item.get("evidence_hint", "")))}</td>
            </tr>
            """
        )

    w05_schedule_rows: list[str] = []
    for item in w05_pack.get("scheduled_events", []):
        w05_schedule_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("date", "")))}</td>
              <td>{html.escape(str(item.get("start_time", "")))} - {html.escape(str(item.get("end_time", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("output", "")))}</td>
            </tr>
            """
        )

    w05_help_rows: list[str] = []
    for item in w05_pack.get("help_docs", []):
        quick_steps = "<br>".join(f"&middot; {html.escape(str(x))}" for x in item.get("quick_steps", []))
        api_refs = "<br>".join(f"&middot; {html.escape(str(x))}" for x in item.get("api_refs", []))
        w05_help_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("doc_id", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("audience", "")))}</td>
              <td>{html.escape(str(item.get("problem", "")))}</td>
              <td>{quick_steps}</td>
              <td>{api_refs}</td>
            </tr>
            """
        )

    w06_rhythm_rows: list[str] = []
    for item in w06_pack.get("rhythm_checklist", []):
        w06_rhythm_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("day", "")))}</td>
              <td>{html.escape(str(item.get("routine", "")))}</td>
              <td>{html.escape(str(item.get("owner_role", "")))}</td>
              <td>{html.escape(str(item.get("definition_of_done", "")))}</td>
              <td>{html.escape(str(item.get("evidence_hint", "")))}</td>
            </tr>
            """
        )

    w06_schedule_rows: list[str] = []
    for item in w06_pack.get("scheduled_events", []):
        w06_schedule_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("date", "")))}</td>
              <td>{html.escape(str(item.get("start_time", "")))} - {html.escape(str(item.get("end_time", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("output", "")))}</td>
            </tr>
            """
        )

    w06_rbac_rows: list[str] = []
    for item in w06_pack.get("rbac_audit_checklist", []):
        w06_rbac_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("control", "")))}</td>
              <td>{html.escape(str(item.get("objective", "")))}</td>
              <td>{html.escape(str(item.get("api_ref", "")))}</td>
              <td>{html.escape(str(item.get("pass_criteria", "")))}</td>
            </tr>
            """
        )

    w07_checklist_rows: list[str] = []
    for item in w07_pack.get("sla_checklist", []):
        w07_checklist_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("cadence", "")))}</td>
              <td>{html.escape(str(item.get("control", "")))}</td>
              <td>{html.escape(str(item.get("owner_role", "")))}</td>
              <td>{html.escape(str(item.get("target", "")))}</td>
              <td>{html.escape(str(item.get("definition_of_done", "")))}</td>
              <td>{html.escape(str(item.get("evidence_hint", "")))}</td>
            </tr>
            """
        )

    w07_coaching_rows: list[str] = []
    for item in w07_pack.get("coaching_plays", []):
        w07_coaching_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("trigger", "")))}</td>
              <td>{html.escape(str(item.get("play", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("expected_impact", "")))}</td>
              <td>{html.escape(str(item.get("evidence_hint", "")))}</td>
              <td>{html.escape(str(item.get("api_ref", "")))}</td>
            </tr>
            """
        )

    w07_schedule_rows: list[str] = []
    for item in w07_pack.get("scheduled_events", []):
        w07_schedule_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("date", "")))}</td>
              <td>{html.escape(str(item.get("start_time", "")))} - {html.escape(str(item.get("end_time", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("output", "")))}</td>
            </tr>
            """
        )

    w08_checklist_rows: list[str] = []
    for item in w08_pack.get("report_discipline_checklist", []):
        w08_checklist_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("cadence", "")))}</td>
              <td>{html.escape(str(item.get("discipline", "")))}</td>
              <td>{html.escape(str(item.get("owner_role", "")))}</td>
              <td>{html.escape(str(item.get("target", "")))}</td>
              <td>{html.escape(str(item.get("definition_of_done", "")))}</td>
              <td>{html.escape(str(item.get("evidence_hint", "")))}</td>
              <td>{html.escape(str(item.get("api_ref", "")))}</td>
            </tr>
            """
        )

    w08_quality_rows: list[str] = []
    for item in w08_pack.get("data_quality_controls", []):
        w08_quality_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("control", "")))}</td>
              <td>{html.escape(str(item.get("objective", "")))}</td>
              <td>{html.escape(str(item.get("api_ref", "")))}</td>
              <td>{html.escape(str(item.get("pass_criteria", "")))}</td>
            </tr>
            """
        )

    w08_schedule_rows: list[str] = []
    for item in w08_pack.get("scheduled_events", []):
        w08_schedule_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("date", "")))}</td>
              <td>{html.escape(str(item.get("start_time", "")))} - {html.escape(str(item.get("end_time", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("output", "")))}</td>
            </tr>
            """
        )

    w09_threshold_rows: list[str] = []
    for item in w09_pack.get("kpi_threshold_matrix", []):
        w09_threshold_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("kpi_name", "")))}</td>
              <td>{html.escape(str(item.get("kpi_key", "")))}</td>
              <td>{html.escape(str(item.get("owner_role", "")))}</td>
              <td>{html.escape(str(item.get("direction", "")))}</td>
              <td>{html.escape(str(item.get("green_threshold", "")))}</td>
              <td>{html.escape(str(item.get("yellow_threshold", "")))}</td>
              <td>{html.escape(str(item.get("target", "")))}</td>
              <td>{html.escape(str(item.get("source_api", "")))}</td>
            </tr>
            """
        )

    w09_escalation_rows: list[str] = []
    for item in w09_pack.get("escalation_map", []):
        w09_escalation_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("kpi_key", "")))}</td>
              <td>{html.escape(str(item.get("condition", "")))}</td>
              <td>{html.escape(str(item.get("escalate_to", "")))}</td>
              <td>{html.escape(str(item.get("sla_hours", "")))}</td>
              <td>{html.escape(str(item.get("action", "")))}</td>
            </tr>
            """
        )

    w09_schedule_rows: list[str] = []
    for item in w09_pack.get("scheduled_events", []):
        w09_schedule_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("date", "")))}</td>
              <td>{html.escape(str(item.get("start_time", "")))} - {html.escape(str(item.get("end_time", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("output", "")))}</td>
            </tr>
            """
        )

    w10_guide_rows: list[str] = []
    for item in w10_pack.get("self_serve_guides", []):
        w10_guide_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("problem_cluster", "")))}</td>
              <td>{html.escape(str(item.get("owner_role", "")))}</td>
              <td>{html.escape(str(item.get("target", "")))}</td>
              <td>{html.escape(str(item.get("source_api", "")))}</td>
            </tr>
            """
        )

    w10_runbook_rows: list[str] = []
    for item in w10_pack.get("troubleshooting_runbook", []):
        w10_runbook_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("module", "")))}</td>
              <td>{html.escape(str(item.get("symptom", "")))}</td>
              <td>{html.escape(str(item.get("owner_role", "")))}</td>
              <td>{html.escape(str(item.get("definition_of_done", "")))}</td>
              <td>{html.escape(str(item.get("api_ref", "")))}</td>
            </tr>
            """
        )

    w10_schedule_rows: list[str] = []
    for item in w10_pack.get("scheduled_events", []):
        w10_schedule_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("date", "")))}</td>
              <td>{html.escape(str(item.get("start_time", "")))} - {html.escape(str(item.get("end_time", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("output", "")))}</td>
            </tr>
            """
        )

    w11_guide_rows: list[str] = []
    for item in w11_pack.get("self_serve_guides", []):
        w11_guide_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("problem_cluster", "")))}</td>
              <td>{html.escape(str(item.get("owner_role", "")))}</td>
              <td>{html.escape(str(item.get("target", "")))}</td>
              <td>{html.escape(str(item.get("source_api", "")))}</td>
            </tr>
            """
        )

    w11_runbook_rows: list[str] = []
    for item in w11_pack.get("troubleshooting_runbook", []):
        w11_runbook_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("module", "")))}</td>
              <td>{html.escape(str(item.get("symptom", "")))}</td>
              <td>{html.escape(str(item.get("owner_role", "")))}</td>
              <td>{html.escape(str(item.get("definition_of_done", "")))}</td>
              <td>{html.escape(str(item.get("api_ref", "")))}</td>
            </tr>
            """
        )

    w11_schedule_rows: list[str] = []
    for item in w11_pack.get("scheduled_events", []):
        w11_schedule_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("date", "")))}</td>
              <td>{html.escape(str(item.get("start_time", "")))} - {html.escape(str(item.get("end_time", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("output", "")))}</td>
            </tr>
            """
        )

    w12_guide_rows: list[str] = []
    for item in w12_pack.get("self_serve_guides", []):
        w12_guide_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("problem_cluster", "")))}</td>
              <td>{html.escape(str(item.get("owner_role", "")))}</td>
              <td>{html.escape(str(item.get("target", "")))}</td>
              <td>{html.escape(str(item.get("source_api", "")))}</td>
            </tr>
            """
        )

    w12_runbook_rows: list[str] = []
    for item in w12_pack.get("troubleshooting_runbook", []):
        w12_runbook_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("module", "")))}</td>
              <td>{html.escape(str(item.get("symptom", "")))}</td>
              <td>{html.escape(str(item.get("owner_role", "")))}</td>
              <td>{html.escape(str(item.get("definition_of_done", "")))}</td>
              <td>{html.escape(str(item.get("api_ref", "")))}</td>
            </tr>
            """
        )

    w12_schedule_rows: list[str] = []
    for item in w12_pack.get("scheduled_events", []):
        w12_schedule_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("date", "")))}</td>
              <td>{html.escape(str(item.get("start_time", "")))} - {html.escape(str(item.get("end_time", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("output", "")))}</td>
            </tr>
            """
        )

    w13_guide_rows: list[str] = []
    for item in w13_pack.get("self_serve_guides", []):
        w13_guide_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("problem_cluster", "")))}</td>
              <td>{html.escape(str(item.get("owner_role", "")))}</td>
              <td>{html.escape(str(item.get("target", "")))}</td>
              <td>{html.escape(str(item.get("source_api", "")))}</td>
            </tr>
            """
        )

    w13_runbook_rows: list[str] = []
    for item in w13_pack.get("troubleshooting_runbook", []):
        w13_runbook_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("module", "")))}</td>
              <td>{html.escape(str(item.get("symptom", "")))}</td>
              <td>{html.escape(str(item.get("owner_role", "")))}</td>
              <td>{html.escape(str(item.get("definition_of_done", "")))}</td>
              <td>{html.escape(str(item.get("api_ref", "")))}</td>
            </tr>
            """
        )

    w13_schedule_rows: list[str] = []
    for item in w13_pack.get("scheduled_events", []):
        w13_schedule_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("date", "")))}</td>
              <td>{html.escape(str(item.get("start_time", "")))} - {html.escape(str(item.get("end_time", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("output", "")))}</td>
            </tr>
            """
        )

    w14_guide_rows: list[str] = []
    for item in w14_pack.get("self_serve_guides", []):
        w14_guide_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("problem_cluster", "")))}</td>
              <td>{html.escape(str(item.get("owner_role", "")))}</td>
              <td>{html.escape(str(item.get("target", "")))}</td>
              <td>{html.escape(str(item.get("source_api", "")))}</td>
            </tr>
            """
        )

    w14_runbook_rows: list[str] = []
    for item in w14_pack.get("troubleshooting_runbook", []):
        w14_runbook_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("module", "")))}</td>
              <td>{html.escape(str(item.get("symptom", "")))}</td>
              <td>{html.escape(str(item.get("owner_role", "")))}</td>
              <td>{html.escape(str(item.get("definition_of_done", "")))}</td>
              <td>{html.escape(str(item.get("api_ref", "")))}</td>
            </tr>
            """
        )

    w14_schedule_rows: list[str] = []
    for item in w14_pack.get("scheduled_events", []):
        w14_schedule_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("date", "")))}</td>
              <td>{html.escape(str(item.get("start_time", "")))} - {html.escape(str(item.get("end_time", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("output", "")))}</td>
            </tr>
            """
        )

    w15_guide_rows: list[str] = []
    for item in w15_pack.get("self_serve_guides", []):
        w15_guide_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("problem_cluster", "")))}</td>
              <td>{html.escape(str(item.get("owner_role", "")))}</td>
              <td>{html.escape(str(item.get("target", "")))}</td>
              <td>{html.escape(str(item.get("source_api", "")))}</td>
            </tr>
            """
        )

    w15_runbook_rows: list[str] = []
    for item in w15_pack.get("troubleshooting_runbook", []):
        w15_runbook_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("module", "")))}</td>
              <td>{html.escape(str(item.get("symptom", "")))}</td>
              <td>{html.escape(str(item.get("owner_role", "")))}</td>
              <td>{html.escape(str(item.get("definition_of_done", "")))}</td>
              <td>{html.escape(str(item.get("api_ref", "")))}</td>
            </tr>
            """
        )

    w15_schedule_rows: list[str] = []
    for item in w15_pack.get("scheduled_events", []):
        w15_schedule_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("date", "")))}</td>
              <td>{html.escape(str(item.get("start_time", "")))} - {html.escape(str(item.get("end_time", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("output", "")))}</td>
            </tr>
            """
        )

    post_timeline = post_mvp.get("timeline", {})
    post_roadmap_rows: list[str] = []
    for item in post_mvp.get("roadmap", []):
        outcomes_html = "<br>".join(f"&middot; {html.escape(str(x))}" for x in item.get("outcomes", []))
        post_roadmap_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("phase", "")))}</td>
              <td>{html.escape(str(item.get("start_date", "")))} ~ {html.escape(str(item.get("end_date", "")))}</td>
              <td>{html.escape(str(item.get("duration_weeks", "")))} weeks</td>
              <td>{html.escape(str(item.get("objective", "")))}</td>
              <td>{outcomes_html}</td>
              <td>{html.escape(str(item.get("release_gate", "")))}</td>
            </tr>
            """
        )

    post_backlog_rows: list[str] = []
    for item in post_mvp.get("execution_backlog", []):
        post_backlog_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("epic", "")))}</td>
              <td>{html.escape(str(item.get("item", "")))}</td>
              <td>{html.escape(str(item.get("priority", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("estimate_points", "")))}</td>
              <td>{html.escape(str(item.get("target_release", "")))}</td>
              <td>{html.escape(str(item.get("status", "")))}</td>
              <td>{html.escape(str(item.get("success_kpi", "")))}</td>
            </tr>
            """
        )

    post_release_rows: list[str] = []
    for item in post_mvp.get("release_calendar", {}).get("milestones", []):
        post_release_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("release", "")))}</td>
              <td>{html.escape(str(item.get("name", "")))}</td>
              <td>{html.escape(str(item.get("date", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("goal", "")))}</td>
            </tr>
            """
        )

    post_kpi_rows: list[str] = []
    for item in post_mvp.get("kpi_dashboard_spec", []):
        post_kpi_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("name", "")))}</td>
              <td>{html.escape(str(item.get("formula", "")))}</td>
              <td>{html.escape(str(item.get("target", "")))}</td>
              <td>{html.escape(str(item.get("cadence", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("alert_rule", "")))}</td>
            </tr>
            """
        )

    post_risk_rows: list[str] = []
    for item in post_mvp.get("risk_register", []):
        post_risk_rows.append(
            f"""
            <tr>
              <td>{html.escape(str(item.get("id", "")))}</td>
              <td>{html.escape(str(item.get("title", "")))}</td>
              <td>{html.escape(str(item.get("probability", "")))}</td>
              <td>{html.escape(str(item.get("impact", "")))}</td>
              <td>{html.escape(str(item.get("signal", "")))}</td>
              <td>{html.escape(str(item.get("mitigation", "")))}</td>
              <td>{html.escape(str(item.get("owner", "")))}</td>
              <td>{html.escape(str(item.get("status", "")))}</td>
              <td>{html.escape(str(item.get("review_cycle", "")))}</td>
            </tr>
            """
        )

    post_governance = post_mvp.get("governance", {})
    post_governance_items_html = "".join(
        f"<li><strong>{html.escape(str(key).replace('_', ' ').title())}:</strong> {html.escape(str(value))}</li>"
        for key, value in post_governance.items()
    )

    module_cards: list[str] = []
    for item in facility_modules:
        links_html = "".join(
            f'<a href="{html.escape(str(link.get("href", "#")))}">{html.escape(str(link.get("label", "Open")))}'
            "</a>"
            for link in item.get("links", [])
        )
        module_cards.append(
            f"""
            <div class="card module-card">
              <h3>{html.escape(str(item.get("name_ko", "")))} <span class="module-en">{html.escape(str(item.get("name", "")))}</span></h3>
              <p>{html.escape(str(item.get("description", "")))}</p>
              <p><strong>KPI Hint:</strong> {html.escape(str(item.get("kpi_hint", "")))}</p>
              <div class="module-links">{links_html}</div>
            </div>
            """
        )

    campaign_kit = plan.get("campaign_kit", {})
    promotion_cards: list[str] = []
    for item in campaign_kit.get("promotion", []):
        channels = "<br>".join(f"&middot; {html.escape(str(x))}" for x in item.get("channels", []))
        assets = "<br>".join(f"&middot; {html.escape(str(x))}" for x in item.get("assets", []))
        promotion_cards.append(
            f"""
            <div class="card">
              <h3>{html.escape(str(item.get("campaign", "")))}</h3>
              <p><strong>Goal:</strong> {html.escape(str(item.get("goal", "")))}</p>
              <p><strong>Channels:</strong><br>{channels}</p>
              <p><strong>Assets:</strong><br>{assets}</p>
              <p><strong>Cadence:</strong> {html.escape(str(item.get("cadence", "")))}</p>
            </div>
            """
        )

    education_cards: list[str] = []
    for item in campaign_kit.get("education", []):
        components = "<br>".join(f"&middot; {html.escape(str(x))}" for x in item.get("components", []))
        targets = ", ".join(html.escape(str(x)) for x in item.get("target_roles", []))
        education_cards.append(
            f"""
            <div class="card">
              <h3>{html.escape(str(item.get("track", "")))}</h3>
              <p><strong>Target:</strong> {targets}</p>
              <p><strong>Components:</strong><br>{components}</p>
              <p><strong>Completion:</strong> {html.escape(str(item.get("completion_rule", "")))}</p>
              <p><strong>Duration:</strong> {html.escape(str(item.get("duration_weeks", "")))} weeks</p>
            </div>
            """
        )

    fun_cards: list[str] = []
    for item in campaign_kit.get("fun", []):
        rewards = "<br>".join(f"&middot; {html.escape(str(x))}" for x in item.get("rewards", []))
        fun_cards.append(
            f"""
            <div class="card">
              <h3>{html.escape(str(item.get("program", "")))}</h3>
              <p><strong>How it works:</strong> {html.escape(str(item.get("how_it_works", "")))}</p>
              <p><strong>Rewards:</strong><br>{rewards}</p>
              <p><strong>Anti-abuse:</strong> {html.escape(str(item.get("anti_abuse_rule", "")))}</p>
            </div>
            """
        )

    cadence_list = "".join(
        f"<li>{html.escape(str(item))}</li>" for item in plan.get("schedule_management", {}).get("cadence", [])
    )
    timeline = plan.get("timeline", {})
    timeline_start = str(timeline.get("start_date", ""))
    timeline_end = str(timeline.get("end_date", ""))
    total_weeks = int(timeline.get("duration_weeks", len(plan.get("weekly_execution", [])) or 1))

    today = datetime.now(timezone.utc).date()
    weekly_items = plan.get("weekly_execution", [])
    completed_weeks = 0
    active_week_item: dict[str, Any] | None = None
    phase_keys: list[str] = []
    for item in weekly_items:
        phase = str(item.get("phase", ""))
        phase_key = "".join(ch.lower() if ch.isalnum() else "-" for ch in phase).strip("-")
        if phase_key and phase_key not in phase_keys:
            phase_keys.append(phase_key)

        start_raw = str(item.get("start_date", ""))
        end_raw = str(item.get("end_date", ""))
        try:
            start_date = date.fromisoformat(start_raw)
            end_date = date.fromisoformat(end_raw)
        except ValueError:
            continue

        if end_date < today:
            completed_weeks += 1
        elif start_date <= today <= end_date:
            active_week_item = item

    progress_percent = int(round((completed_weeks / total_weeks) * 100))
    campaign_total = (
        len(campaign_kit.get("promotion", []))
        + len(campaign_kit.get("education", []))
        + len(campaign_kit.get("fun", []))
    )

    phase_filter_buttons = ['<button class="filter-btn active" type="button" data-phase="all">All</button>']
    for key in phase_keys:
        phase_filter_buttons.append(
            f'<button class="filter-btn" type="button" data-phase="{html.escape(key)}">{html.escape(key.replace("-", " ").title())}</button>'
        )

    week_cards: list[str] = []
    for item in weekly_items:
        week = int(item.get("week", 0))
        phase = str(item.get("phase", ""))
        phase_key = "".join(ch.lower() if ch.isalnum() else "-" for ch in phase).strip("-")
        focus = str(item.get("focus", ""))
        owner = str(item.get("owner", ""))
        metric = str(item.get("success_metric", ""))
        start_raw = str(item.get("start_date", ""))
        end_raw = str(item.get("end_date", ""))
        status_label = "Scheduled"
        status_class = "scheduled"
        try:
            start_date = date.fromisoformat(start_raw)
            end_date = date.fromisoformat(end_raw)
            if end_date < today:
                status_label = "Done"
                status_class = "done"
            elif start_date <= today <= end_date:
                status_label = "Active"
                status_class = "active"
        except ValueError:
            pass

        keywords = f"{phase} {focus} {owner} {metric}".lower()
        week_cards.append(
            f"""
            <article class="week-card {status_class}" data-phase="{html.escape(phase_key)}" data-keywords="{html.escape(keywords)}">
              <div class="week-top">
                <span class="week-num">W{week:02d}</span>
                <span class="week-status">{html.escape(status_label)}</span>
              </div>
              <h4>{html.escape(focus)}</h4>
              <p>{html.escape(start_raw)} ~ {html.escape(end_raw)}</p>
              <p>Owner: {html.escape(owner)}</p>
              <p class="week-metric">{html.escape(metric)}</p>
            </article>
            """
        )

    if active_week_item is not None:
        active_focus = html.escape(str(active_week_item.get("focus", "")))
        active_week = int(active_week_item.get("week", 0))
        active_owner = html.escape(str(active_week_item.get("owner", "")))
        active_actions = "".join(
            f"<li>{html.escape(str(x))}</li>" for x in active_week_item.get("actions", [])
        )
        active_week_guide = f"""
        <div class="active-week-box">
          <h3>이번 주 실행 가이드: W{active_week:02d} - {active_focus}</h3>
          <p>Owner: {active_owner}</p>
          <ul>{active_actions}</ul>
        </div>
        """
    else:
        active_week_guide = """
        <div class="active-week-box">
          <h3>이번 주 실행 가이드</h3>
          <p>현재 진행중인 주차가 없습니다. 아래 Timeline Board에서 다음 주차를 확인하세요.</p>
        </div>
        """

    if active_week_item is not None:
        active_line = (
            f"W{int(active_week_item.get('week', 0)):02d} 진행중: "
            f"{str(active_week_item.get('focus', ''))} "
            f"(Owner: {str(active_week_item.get('owner', ''))})"
        )
    else:
        active_line = "현재 진행중인 주차 없음: 다음 주차 계획을 우선 확인하세요."

    summary_lines = [
        f"기간 {timeline_start}~{timeline_end}, 진행률 {progress_percent}% ({completed_weeks}/{total_weeks}주 완료).",
        active_line,
        f"시설관리 웹 모듈 {len(facility_modules)}개를 메인 허브에서 즉시 연결.",
        f"교육 모듈 {len(training)}개: 역할별 표준 학습경로와 실습 중심 운영.",
        f"KPI {len(kpis)}개 주간 추적, 다음 리뷰일 {plan.get('schedule_management', {}).get('next_review_date', '')}.",
        f"W02 SOP {len(w02_pack.get('sop_runbooks', []))}개 + Sandbox {len(w02_pack.get('sandbox_scenarios', []))}개 + 일정 {len(w02_pack.get('scheduled_events', []))}건 공개.",
        f"W03 Kickoff {len(w03_pack.get('kickoff_agenda', []))}개 + Workshop {len(w03_pack.get('role_workshops', []))}개 + Office hour {len(w03_pack.get('office_hours', []))}개 구성.",
        "일정 파일(CSV/ICS) + 캠페인 킷 + Post-MVP 실행팩으로 즉시 실행 가능.",
    ]
    summary_lines_html = "".join(f"<li>{html.escape(line)}</li>" for line in summary_lines)

    return f"""
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>KA Facility OS - 공개 메인</title>
  <style>
    :root {{
      --ink: #0d1f3a;
      --muted: #3f5576;
      --line: #d1dced;
      --brand: #0e6f5d;
      --accent: #d55222;
      --card: #ffffff;
      --bg: #f4f8fd;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      font-family: "SUIT", "Pretendard", "IBM Plex Sans KR", "Noto Sans KR", sans-serif;
      background:
        radial-gradient(1200px 500px at 10% -20%, #d8f6ff 0%, transparent 60%),
        radial-gradient(900px 400px at 100% -10%, #ffe7ca 0%, transparent 60%),
        var(--bg);
    }}
    .wrap {{ max-width: 1200px; margin: 0 auto; padding: 24px 16px 64px; }}
    .hero {{
      position: relative;
      overflow: hidden;
      border: 1px solid var(--line);
      background: linear-gradient(135deg, #ffffff 0%, #eff8f6 56%, #fff3e6 100%);
      border-radius: 16px;
      padding: 20px;
      box-shadow: 0 10px 30px rgba(16, 42, 67, 0.08);
      animation: fadeup 520ms ease-out both;
    }}
    .hero::after {{
      content: "";
      position: absolute;
      width: 220px;
      height: 220px;
      border-radius: 999px;
      right: -80px;
      top: -90px;
      background: radial-gradient(circle at center, rgba(14, 111, 93, 0.22) 0%, rgba(14, 111, 93, 0) 70%);
      pointer-events: none;
    }}
    .hero h1 {{ margin: 0 0 8px; font-size: 28px; }}
    .hero p {{ margin: 0; color: var(--muted); }}
    .summary-toggle {{
      margin-top: 10px;
      border: 1px solid #8ecfbf;
      background: #eaf9f4;
      color: #0b5c4d;
      border-radius: 10px;
      padding: 7px 10px;
      font-size: 12px;
      font-weight: 800;
      cursor: pointer;
    }}
    .summary-toggle:hover {{ background: #ddf5ec; }}
    .pill {{
      display: inline-block;
      margin-top: 12px;
      padding: 6px 10px;
      border-radius: 999px;
      background: #dcfce7;
      border: 1px solid #86efac;
      font-size: 12px;
      font-weight: 700;
    }}
    .grid {{
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      margin-top: 16px;
    }}
    .card {{
      border: 1px solid var(--line);
      border-radius: 12px;
      background: var(--card);
      padding: 14px;
    }}
    .card h3 {{ margin: 0 0 8px; font-size: 14px; color: var(--brand); }}
    .card p {{ margin: 0; font-size: 13px; color: var(--muted); }}
    .module-card .module-en {{
      color: #4c6b97;
      font-size: 12px;
      font-weight: 700;
      margin-left: 4px;
    }}
    .module-links {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 10px;
    }}
    .module-links a {{
      display: inline-block;
      padding: 6px 9px;
      border-radius: 8px;
      border: 1px solid #bfd5ef;
      text-decoration: none;
      color: #1f4f82;
      background: #f3f8ff;
      font-size: 12px;
      font-weight: 700;
    }}
    .module-links a:hover {{ border-color: #88add8; background: #e8f2ff; }}
    .section {{ margin-top: 24px; }}
    .section h2 {{
      margin: 0 0 10px;
      font-size: 20px;
      border-left: 4px solid var(--accent);
      padding-left: 10px;
    }}
    .section .desc {{ margin: 0 0 12px; color: var(--muted); }}
    .table-wrap {{
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #fff;
    }}
    table {{
      border-collapse: collapse;
      width: 100%;
      min-width: 900px;
      font-size: 13px;
    }}
    th, td {{
      border-bottom: 1px solid #edf2f7;
      padding: 10px;
      vertical-align: top;
      text-align: left;
    }}
    th {{
      background: #f8fafc;
      color: #1f2937;
      position: sticky;
      top: 0;
      z-index: 1;
    }}
    .links a {{
      display: inline-block;
      margin-right: 8px;
      margin-bottom: 8px;
      padding: 8px 12px;
      border-radius: 10px;
      border: 1px solid var(--line);
      text-decoration: none;
      color: var(--ink);
      background: #fff;
      font-size: 13px;
      font-weight: 600;
    }}
    .links a:hover {{ border-color: var(--brand); color: var(--brand); }}
    .chip-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }}
    .chip {{
      padding: 6px 10px;
      border-radius: 999px;
      border: 1px solid #addbcf;
      background: #edfaf5;
      color: #0d5b4d;
      font-size: 12px;
      font-weight: 700;
    }}
    .hero-stats {{
      margin-top: 14px;
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(4, minmax(0, 1fr));
    }}
    .stat {{
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #fff;
      padding: 10px;
    }}
    .stat .k {{ color: var(--muted); font-size: 12px; }}
    .stat .v {{ font-size: 22px; font-weight: 800; margin-top: 2px; }}
    .section .sub {{
      margin: 0 0 12px;
      color: var(--muted);
      font-size: 14px;
    }}
    .filter-row {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
      margin-bottom: 10px;
    }}
    .filter-btn {{
      border: 1px solid var(--line);
      background: #fff;
      color: var(--ink);
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      padding: 6px 11px;
      cursor: pointer;
    }}
    .filter-btn.active {{
      border-color: #8ecfbf;
      background: #e8f9f3;
      color: #0b5c4d;
    }}
    .search-input {{
      margin-left: auto;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 8px 10px;
      min-width: 220px;
      font-size: 13px;
    }}
    .timeline-board {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }}
    .week-card {{
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #fff;
      padding: 11px;
      transition: transform 180ms ease, box-shadow 180ms ease;
      animation: fadeup 600ms ease-out both;
    }}
    .week-card:hover {{
      transform: translateY(-2px);
      box-shadow: 0 8px 22px rgba(16, 42, 67, 0.10);
    }}
    .week-card .week-top {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
    }}
    .week-card .week-num {{ font-size: 12px; font-weight: 800; color: var(--muted); letter-spacing: 0.04em; }}
    .week-card .week-status {{
      font-size: 11px;
      font-weight: 700;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 3px 8px;
    }}
    .week-card.done {{ background: linear-gradient(160deg, #f2fff7 0%, #ffffff 60%); }}
    .week-card.done .week-status {{ border-color: #9ad8bf; color: #0b6e5a; background: #ebfff4; }}
    .week-card.active {{ background: linear-gradient(160deg, #eef7ff 0%, #ffffff 60%); border-color: #a9c8e8; }}
    .week-card.active .week-status {{ border-color: #a0bee2; color: #1f5f9f; background: #f0f7ff; }}
    .week-card.scheduled {{ background: linear-gradient(160deg, #fff9f0 0%, #ffffff 60%); }}
    .week-card.scheduled .week-status {{ border-color: #f2c58d; color: #ab6100; background: #fff5e8; }}
    .week-card h4 {{ margin: 0 0 6px; font-size: 15px; }}
    .week-card p {{ margin: 0 0 4px; color: var(--muted); font-size: 12px; }}
    .week-card .week-metric {{
      margin-top: 6px;
      background: #f7fbff;
      border: 1px solid #d8e4f4;
      border-radius: 8px;
      padding: 6px;
      color: #2b3b52;
    }}
    .active-week-box {{
      margin-top: 12px;
      border: 1px solid #abc8e8;
      border-radius: 12px;
      background: #f2f9ff;
      padding: 12px;
    }}
    .active-week-box h3 {{ margin: 0 0 8px; font-size: 16px; }}
    .active-week-box p {{ margin: 0 0 8px; color: var(--muted); }}
    .active-week-box ul {{ margin: 0 0 0 18px; }}
    .active-week-box li {{ margin: 4px 0; }}
    .summary-panel {{
      display: none;
      margin-top: 12px;
      border: 1px solid #9dc4ea;
      border-radius: 12px;
      background: #eef7ff;
      padding: 12px;
    }}
    .summary-panel h3 {{ margin: 0 0 8px; font-size: 16px; }}
    .summary-panel ul {{ margin: 0 0 0 18px; }}
    .summary-panel li {{ margin: 4px 0; color: #26415f; }}
    body.summary-mode .section {{ display: none; }}
    body.summary-mode .hero .grid,
    body.summary-mode .hero .hero-stats,
    body.summary-mode .hero .chip-row,
    body.summary-mode .hero .pill {{ display: none; }}
    body.summary-mode .summary-panel {{ display: block; }}
    body.summary-mode .hero p {{ margin-top: 6px; }}
    @keyframes fadeup {{
      from {{ opacity: 0; transform: translateY(10px); }}
      to {{ opacity: 1; transform: translateY(0); }}
    }}
    ul {{ margin: 8px 0 0 18px; }}
    @media (max-width: 900px) {{
      .grid {{ grid-template-columns: 1fr; }}
      .hero-stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .timeline-board {{ grid-template-columns: 1fr; }}
      .search-input {{ margin-left: 0; width: 100%; min-width: 0; }}
      .hero h1 {{ font-size: 22px; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>KA Facility OS</h1>
      <p>브라우저에서 바로 이해할 수 있는 공개 운영 포털입니다. 계획, 교육, KPI, 일정, 캠페인을 한 페이지에서 읽고 실행할 수 있습니다.</p>
      <button id="summaryModeToggle" class="summary-toggle" type="button" aria-pressed="false">요약 모드 (핵심 5줄): OFF</button>
      <span class="pill">Public Plan Enabled</span>
      <div class="chip-row">
        <span class="chip">User Adoption Plan</span>
        <span class="chip">Schedule Management</span>
        <span class="chip">Promotion + Education + Fun Kit</span>
      </div>
      <div id="summaryPanel" class="summary-panel">
        <h3>핵심 5줄 요약</h3>
        <ul>{summary_lines_html}</ul>
      </div>
      <div class="hero-stats">
        <div class="stat"><div class="k">Weeks</div><div class="v">{total_weeks}</div></div>
        <div class="stat"><div class="k">Completed</div><div class="v">{completed_weeks}</div></div>
        <div class="stat"><div class="k">Progress</div><div class="v">{progress_percent}%</div></div>
        <div class="stat"><div class="k">Campaign Items</div><div class="v">{campaign_total}</div></div>
      </div>
      <div class="grid">
        <div class="card">
          <h3>Service</h3>
          <p>{html.escape(service_info.get("service", ""))}</p>
        </div>
        <div class="card">
          <h3>Status</h3>
          <p>{html.escape(service_info.get("status", ""))}</p>
        </div>
        <div class="card">
          <h3>Docs</h3>
          <p><a href="{html.escape(service_info.get("docs", "/docs"))}">{html.escape(service_info.get("docs", "/docs"))}</a></p>
        </div>
      </div>
    </section>

    <section class="section">
      <h2>{html.escape(str(plan.get("title", "")))}</h2>
      <p class="sub">
        Timeline: {html.escape(timeline_start)} ~ {html.escape(timeline_end)} |
        Duration: {total_weeks} weeks
      </p>
      <div class="links">
        <a href="/api/public/adoption-plan">JSON API</a>
        <a href="/api/public/adoption-plan/campaign">Campaign API</a>
        <a href="/api/public/adoption-plan/schedule.csv">Schedule CSV</a>
        <a href="/api/public/adoption-plan/schedule.ics">Calendar ICS</a>
        <a href="/api/public/adoption-plan/w02">W02 JSON</a>
        <a href="/api/public/adoption-plan/w02/checklist.csv">W02 체크리스트 CSV</a>
        <a href="/api/public/adoption-plan/w02/schedule.ics">W02 일정 ICS</a>
        <a href="/api/public/adoption-plan/w02/sample-files">W02 샘플 파일</a>
        <a href="/api/public/adoption-plan/w03">W03 JSON</a>
        <a href="/api/public/adoption-plan/w03/checklist.csv">W03 체크리스트 CSV</a>
        <a href="/api/public/adoption-plan/w03/schedule.ics">W03 일정 ICS</a>
        <a href="/api/public/adoption-plan/w04">W04 JSON</a>
        <a href="/api/public/adoption-plan/w04/checklist.csv">W04 체크리스트 CSV</a>
        <a href="/api/public/adoption-plan/w04/schedule.ics">W04 일정 ICS</a>
        <a href="/api/public/adoption-plan/w04/common-mistakes">W04 자주 하는 실수 JSON</a>
        <a href="/api/public/adoption-plan/w05">W05 JSON</a>
        <a href="/api/public/adoption-plan/w05/missions.csv">W05 Missions CSV</a>
        <a href="/api/public/adoption-plan/w05/schedule.ics">W05 Schedule ICS</a>
        <a href="/api/public/adoption-plan/w05/help-docs">W05 Help Docs</a>
        <a href="/api/public/adoption-plan/w06">W06 JSON</a>
        <a href="/api/public/adoption-plan/w06/checklist.csv">W06 Checklist CSV</a>
        <a href="/api/public/adoption-plan/w06/schedule.ics">W06 Schedule ICS</a>
        <a href="/api/public/adoption-plan/w06/rbac-audit-template">W06 RBAC Audit Template</a>
        <a href="/api/public/adoption-plan/w07">W07 JSON</a>
        <a href="/api/public/adoption-plan/w07/checklist.csv">W07 Checklist CSV</a>
        <a href="/api/public/adoption-plan/w07/schedule.ics">W07 Schedule ICS</a>
        <a href="/api/public/adoption-plan/w07/coaching-playbook">W07 Coaching Playbook</a>
        <a href="/api/public/adoption-plan/w08">W08 JSON</a>
        <a href="/api/public/adoption-plan/w08/checklist.csv">W08 Checklist CSV</a>
        <a href="/api/public/adoption-plan/w08/schedule.ics">W08 Schedule ICS</a>
        <a href="/api/public/adoption-plan/w08/reporting-sop">W08 Reporting SOP</a>
        <a href="/api/public/adoption-plan/w09">W09 JSON</a>
        <a href="/api/public/adoption-plan/w09/checklist.csv">W09 Checklist CSV</a>
        <a href="/api/public/adoption-plan/w09/schedule.ics">W09 Schedule ICS</a>
        <a href="/web/adoption/w04/common-mistakes">W04 자주 하는 실수 HTML</a>
        <a href="/web/console">시설 콘솔 HTML</a>
        <a href="/api/service-info">서비스 정보</a>
      </div>
    </section>

    <section class="section">
      <h2>시설 웹 모듈</h2>
      <p class="sub">메인 페이지를 시설관리 허브로 사용하고, 핵심 모듈을 카드형으로 바로 연결합니다.</p>
      <div class="links">
        <a href="/api/public/modules">모듈 API</a>
        <a href="/web/console">운영 콘솔 HTML</a>
        <a href="/web/complaints">세대 민원처리</a>
      </div>
      <div class="grid">
        {"".join(module_cards)}
      </div>
    </section>

    <section class="section">
      <h2>W01 Role Workflow Lock Matrix</h2>
      <p class="sub">DRAFT/REVIEW/APPROVED/LOCKED 단계별 역할 권한 매트릭스를 운영 규칙으로 고정합니다.</p>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Role</th>
              <th>DRAFT</th>
              <th>REVIEW</th>
              <th>APPROVED</th>
              <th>LOCKED</th>
            </tr>
          </thead>
          <tbody>
            {"".join(workflow_matrix_rows)}
          </tbody>
        </table>
      </div>
      <div class="links" style="margin-top: 10px;">
        <a href="/api/workflow-locks">Workflow Lock API</a>
      </div>
    </section>

    <section class="section">
      <h2>W02 Scheduled SOP and Sandbox</h2>
      <p class="sub">SOP 표준화와 샌드박스 실습을 주간 일정으로 고정해 즉시 실행 가능 상태로 만듭니다.</p>
      <div class="links">
        <a href="/api/public/adoption-plan/w02">W02 JSON</a>
        <a href="/api/public/adoption-plan/w02/checklist.csv">W02 체크리스트 CSV</a>
        <a href="/api/public/adoption-plan/w02/schedule.ics">W02 일정 ICS</a>
        <a href="/api/public/adoption-plan/w02/sample-files">W02 샘플 파일</a>
        <a href="/api/adoption/w02/tracker/items">W02 Tracker Items API (Token)</a>
        <a href="/api/adoption/w02/tracker/overview?site=HQ">W02 Tracker Overview API (Token)</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>SOP ID</th>
              <th>Name</th>
              <th>Target Roles</th>
              <th>Owner</th>
              <th>Trigger</th>
              <th>Checkpoints</th>
              <th>Definition of Done</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w02_sop_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Scenario ID</th>
              <th>Module</th>
              <th>Objective</th>
              <th>API Flow</th>
              <th>Pass Criteria</th>
              <th>Duration(min)</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w02_sandbox_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Time</th>
              <th>Session</th>
              <th>Owner</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w02_schedule_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>W03 Go-live Onboarding</h2>
      <p class="sub">런치 주차 온보딩(킥오프 + 역할 워크숍 + 일일 오피스아워) 실행 패키지입니다.</p>
      <div class="links">
        <a href="/api/public/adoption-plan/w03">W03 JSON</a>
        <a href="/api/public/adoption-plan/w03/checklist.csv">W03 체크리스트 CSV</a>
        <a href="/api/public/adoption-plan/w03/schedule.ics">W03 일정 ICS</a>
        <a href="/api/adoption/w03/tracker/items">W03 Tracker Items API (Token)</a>
        <a href="/api/adoption/w03/tracker/overview?site=HQ">W03 Tracker Overview API (Token)</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Kickoff ID</th>
              <th>Topic</th>
              <th>Owner</th>
              <th>Duration(min)</th>
              <th>Objective</th>
              <th>Expected Output</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w03_kickoff_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Workshop ID</th>
              <th>Role</th>
              <th>Trainer</th>
              <th>Duration(min)</th>
              <th>Objective</th>
              <th>Checklist</th>
              <th>Success Criteria</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w03_workshop_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Time</th>
              <th>Host</th>
              <th>Focus</th>
              <th>Channel</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w03_office_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Time</th>
              <th>Session</th>
              <th>Owner</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w03_schedule_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>W04 First Success Acceleration</h2>
      <p class="sub">첫 성공 시간(TTV) 단축과 Top blocker 제거를 위한 코칭 실행 패키지입니다.</p>
      <div class="links">
        <a href="/api/public/adoption-plan/w04">W04 JSON</a>
        <a href="/api/public/adoption-plan/w04/checklist.csv">W04 체크리스트 CSV</a>
        <a href="/api/public/adoption-plan/w04/schedule.ics">W04 일정 ICS</a>
        <a href="/api/public/adoption-plan/w04/common-mistakes">W04 자주 하는 실수 JSON</a>
        <a href="/web/adoption/w04/common-mistakes">W04 자주 하는 실수 HTML</a>
        <a href="/api/ops/adoption/w04/funnel">W04 Funnel API (Token)</a>
        <a href="/api/ops/adoption/w04/blockers">W04 Blockers API (Token)</a>
        <a href="/api/adoption/w04/tracker/items">W04 Tracker Items API (Token)</a>
        <a href="/api/adoption/w04/tracker/overview?site=HQ">W04 Tracker Overview API (Token)</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Action ID</th>
              <th>Champion Role</th>
              <th>Action</th>
              <th>Owner</th>
              <th>Due Hint</th>
              <th>Objective</th>
              <th>Evidence Required</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w04_action_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Time</th>
              <th>Session</th>
              <th>Owner</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w04_schedule_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>W05 Usage Consistency</h2>
      <p class="sub">역할별 주간 미션과 overdue 행동 교정을 통해 2주 유지율을 높이는 실행 패키지입니다.</p>
      <div class="links">
        <a href="/api/public/adoption-plan/w05">W05 JSON</a>
        <a href="/api/public/adoption-plan/w05/missions.csv">W05 Missions CSV</a>
        <a href="/api/public/adoption-plan/w05/schedule.ics">W05 Schedule ICS</a>
        <a href="/api/public/adoption-plan/w05/help-docs">W05 Help Docs</a>
        <a href="/api/ops/adoption/w05/consistency">W05 Consistency API (Token)</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Mission ID</th>
              <th>Role</th>
              <th>Mission</th>
              <th>Weekly Target</th>
              <th>Owner</th>
              <th>Evidence Required</th>
              <th>Evidence Hint</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w05_mission_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Time</th>
              <th>Session</th>
              <th>Owner</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w05_schedule_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Doc ID</th>
              <th>Title</th>
              <th>Audience</th>
              <th>Problem</th>
              <th>Quick Steps</th>
              <th>API Refs</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w05_help_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>W06 Operational Rhythm</h2>
      <p class="sub">주간 운영 리듬(월요일 계획, 일일 handover, 금요일 리뷰)과 RBAC 점검을 정례화하는 실행 패키지입니다.</p>
      <div class="links">
        <a href="/api/public/adoption-plan/w06">W06 JSON</a>
        <a href="/api/public/adoption-plan/w06/checklist.csv">W06 Checklist CSV</a>
        <a href="/api/public/adoption-plan/w06/schedule.ics">W06 Schedule ICS</a>
        <a href="/api/public/adoption-plan/w06/rbac-audit-template">W06 RBAC Audit Template</a>
        <a href="/api/ops/adoption/w06/rhythm">W06 Rhythm API (Token)</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Checklist ID</th>
              <th>Day</th>
              <th>Routine</th>
              <th>Owner Role</th>
              <th>Definition of Done</th>
              <th>Evidence Hint</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w06_rhythm_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Time</th>
              <th>Session</th>
              <th>Owner</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w06_schedule_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Control ID</th>
              <th>Control</th>
              <th>Objective</th>
              <th>API Ref</th>
              <th>Pass Criteria</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w06_rbac_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>W07 SLA Quality</h2>
      <p class="sub">SLA 반응시간 개선, escalation 억제, alert 품질 회복을 주간 운영 루틴으로 고정하는 실행 패키지입니다.</p>
      <div class="links">
        <a href="/api/public/adoption-plan/w07">W07 JSON</a>
        <a href="/api/public/adoption-plan/w07/checklist.csv">W07 Checklist CSV</a>
        <a href="/api/public/adoption-plan/w07/schedule.ics">W07 Schedule ICS</a>
        <a href="/api/public/adoption-plan/w07/coaching-playbook">W07 Coaching Playbook</a>
        <a href="/api/ops/adoption/w07/sla-quality">W07 SLA Quality API (Token)</a>
        <a href="/api/ops/adoption/w07/automation-readiness">W07 Automation Readiness API (Token)</a>
        <a href="/api/adoption/w07/tracker/items">W07 Tracker Items API (Token)</a>
        <a href="/api/adoption/w07/tracker/overview?site=HQ">W07 Tracker Overview API (Token)</a>
        <a href="/api/adoption/w07/tracker/completion-package?site=HQ">W07 Completion Package ZIP (Token)</a>
        <a href="/api/ops/adoption/w07/sla-quality/run-weekly">W07 Weekly Run API (Token)</a>
        <a href="/api/ops/adoption/w07/sla-quality/latest-weekly">W07 Weekly Latest API (Token)</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Checklist ID</th>
              <th>Cadence</th>
              <th>Control</th>
              <th>Owner Role</th>
              <th>Target</th>
              <th>Definition of Done</th>
              <th>Evidence Hint</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w07_checklist_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Play ID</th>
              <th>Trigger</th>
              <th>Play</th>
              <th>Owner</th>
              <th>Expected Impact</th>
              <th>Evidence Hint</th>
              <th>API Ref</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w07_coaching_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Time</th>
              <th>Session</th>
              <th>Owner</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w07_schedule_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>W08 Report Discipline</h2>
      <p class="sub">월간 리포트 출력 규율과 데이터 품질을 운영 KPI로 관리하고, site 벤치마크로 개선 우선순위를 확정합니다.</p>
      <div class="links">
        <a href="/api/public/adoption-plan/w08">W08 JSON</a>
        <a href="/api/public/adoption-plan/w08/checklist.csv">W08 Checklist CSV</a>
        <a href="/api/public/adoption-plan/w08/schedule.ics">W08 Schedule ICS</a>
        <a href="/api/public/adoption-plan/w08/reporting-sop">W08 Reporting SOP</a>
        <a href="/api/ops/adoption/w08/report-discipline">W08 Discipline API (Token)</a>
        <a href="/api/ops/adoption/w08/site-benchmark">W08 Site Benchmark API (Token)</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Checklist ID</th>
              <th>Cadence</th>
              <th>Discipline</th>
              <th>Owner Role</th>
              <th>Target</th>
              <th>Definition of Done</th>
              <th>Evidence Hint</th>
              <th>API Ref</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w08_checklist_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Control ID</th>
              <th>Control</th>
              <th>Objective</th>
              <th>API Ref</th>
              <th>Pass Criteria</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w08_quality_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Time</th>
              <th>Session</th>
              <th>Owner</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w08_schedule_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>W09 KPI Operation</h2>
      <p class="sub">KPI 임계값/오너/에스컬레이션 정책을 기준으로 운영 상태를 주간 점검하고 실행 추적으로 닫습니다.</p>
      <div class="links">
        <a href="/api/public/adoption-plan/w09">W09 JSON</a>
        <a href="/api/public/adoption-plan/w09/checklist.csv">W09 Checklist CSV</a>
        <a href="/api/public/adoption-plan/w09/schedule.ics">W09 Schedule ICS</a>
        <a href="/api/ops/adoption/w09/kpi-operation">W09 KPI Operation API (Token)</a>
        <a href="/api/ops/adoption/w09/kpi-policy">W09 KPI Policy API (Token)</a>
        <a href="/api/adoption/w09/tracker/items">W09 Tracker Items API (Token)</a>
        <a href="/api/adoption/w09/tracker/overview?site=HQ">W09 Tracker Overview API (Token)</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>KPI ID</th>
              <th>KPI Name</th>
              <th>KPI Key</th>
              <th>Owner Role</th>
              <th>Direction</th>
              <th>Green Threshold</th>
              <th>Yellow Threshold</th>
              <th>Target</th>
              <th>Source API</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w09_threshold_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Escalation ID</th>
              <th>KPI Key</th>
              <th>Condition</th>
              <th>Escalate To</th>
              <th>SLA Hours</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w09_escalation_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Time</th>
              <th>Session</th>
              <th>Owner</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w09_schedule_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>W10 Self-serve Support</h2>
      <p class="sub">반복 지원 이슈를 가이드/런북으로 전환하여 현장 자율 해결 비율을 높이고 지원 의존도를 줄입니다.</p>
      <div class="links">
        <a href="/api/public/adoption-plan/w10">W10 JSON</a>
        <a href="/api/public/adoption-plan/w10/checklist.csv">W10 Checklist CSV</a>
        <a href="/api/public/adoption-plan/w10/schedule.ics">W10 Schedule ICS</a>
        <a href="/api/ops/adoption/w10/self-serve">W10 Self-serve API (Token)</a>
        <a href="/api/ops/adoption/w10/support-policy">W10 Support Policy API (Token)</a>
        <a href="/api/adoption/w10/tracker/items">W10 Tracker Items API (Token)</a>
        <a href="/api/adoption/w10/tracker/overview?site=HQ">W10 Tracker Overview API (Token)</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Guide ID</th>
              <th>Title</th>
              <th>Problem Cluster</th>
              <th>Owner Role</th>
              <th>Target</th>
              <th>Source API</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w10_guide_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Runbook ID</th>
              <th>Module</th>
              <th>Symptom</th>
              <th>Owner Role</th>
              <th>Definition of Done</th>
              <th>API Ref</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w10_runbook_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Time</th>
              <th>Session</th>
              <th>Owner</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w10_schedule_rows)}
          </tbody>
        </table>
      </div>
    <section class="section">
      <h2>W11 Scale Readiness</h2>
      <p class="sub">확장 사이트 적용을 위한 체크리스트/시뮬레이션/비상대응 체계를 정착시켜 신규 사이트 전개 리스크를 줄입니다.</p>
      <div class="links">
        <a href="/api/public/adoption-plan/w11">W11 JSON</a>
        <a href="/api/public/adoption-plan/w11/checklist.csv">W11 Checklist CSV</a>
        <a href="/api/public/adoption-plan/w11/schedule.ics">W11 Schedule ICS</a>
        <a href="/api/ops/adoption/w11/scale-readiness">W11 Scale Readiness API (Token)</a>
        <a href="/api/ops/adoption/w11/readiness-policy">W11 Readiness Policy API (Token)</a>
        <a href="/api/adoption/w11/tracker/items">W11 Tracker Items API (Token)</a>
        <a href="/api/adoption/w11/tracker/overview?site=HQ">W11 Tracker Overview API (Token)</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Checklist ID</th>
              <th>Title</th>
              <th>Readiness Cluster</th>
              <th>Owner Role</th>
              <th>Target</th>
              <th>Source API</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w11_guide_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Simulation ID</th>
              <th>Module</th>
              <th>Scenario</th>
              <th>Owner Role</th>
              <th>Definition of Done</th>
              <th>API Ref</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w11_runbook_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Time</th>
              <th>Session</th>
              <th>Owner</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w11_schedule_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>W12 Closure and Handoff</h2>
      <p class="sub">프로그램 종료 기준을 검증하고 운영/문서/리스크를 다음 분기 체계로 인수인계하는 마감 패키지입니다.</p>
      <div class="links">
        <a href="/api/public/adoption-plan/w12">W12 JSON</a>
        <a href="/api/public/adoption-plan/w12/checklist.csv">W12 Checklist CSV</a>
        <a href="/api/public/adoption-plan/w12/schedule.ics">W12 Schedule ICS</a>
        <a href="/api/ops/adoption/w12/closure-handoff">W12 Closure Handoff API (Token)</a>
        <a href="/api/ops/adoption/w12/handoff-policy">W12 Handoff Policy API (Token)</a>
        <a href="/api/adoption/w12/tracker/items">W12 Tracker Items API (Token)</a>
        <a href="/api/adoption/w12/tracker/overview?site=HQ">W12 Tracker Overview API (Token)</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Checklist ID</th>
              <th>Title</th>
              <th>Handoff Cluster</th>
              <th>Owner Role</th>
              <th>Target</th>
              <th>Source API</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w12_guide_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Runbook ID</th>
              <th>Module</th>
              <th>Symptom</th>
              <th>Owner Role</th>
              <th>Definition of Done</th>
              <th>API Ref</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w12_runbook_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Time</th>
              <th>Session</th>
              <th>Owner</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w12_schedule_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>W13 Continuous Improvement</h2>
      <p class="sub">W12 종료 결과를 개선 백로그로 전환하고 분기 거버넌스로 정착시키는 지속 개선 패키지입니다.</p>
      <div class="links">
        <a href="/api/public/adoption-plan/w13">W13 JSON</a>
        <a href="/api/public/adoption-plan/w13/checklist.csv">W13 Checklist CSV</a>
        <a href="/api/public/adoption-plan/w13/schedule.ics">W13 Schedule ICS</a>
        <a href="/api/ops/adoption/w13/closure-handoff">W13 Closure Handoff API (Token)</a>
        <a href="/api/ops/adoption/w13/handoff-policy">W13 Handoff Policy API (Token)</a>
        <a href="/api/adoption/w13/tracker/items">W13 Tracker Items API (Token)</a>
        <a href="/api/adoption/w13/tracker/overview?site=HQ">W13 Tracker Overview API (Token)</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Checklist ID</th>
              <th>Title</th>
              <th>Handoff Cluster</th>
              <th>Owner Role</th>
              <th>Target</th>
              <th>Source API</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w13_guide_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Runbook ID</th>
              <th>Module</th>
              <th>Symptom</th>
              <th>Owner Role</th>
              <th>Definition of Done</th>
              <th>API Ref</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w13_runbook_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Time</th>
              <th>Session</th>
              <th>Owner</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w13_schedule_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>W14 Stability Sprint</h2>
      <p class="sub">W13 이후 안정화 스프린트로 전환하여 API 성능 기준, 배포 신뢰성, 아카이브 무결성 운영을 표준화합니다.</p>
      <div class="links">
        <a href="/api/public/adoption-plan/w14">W14 JSON</a>
        <a href="/api/public/adoption-plan/w14/checklist.csv">W14 Checklist CSV</a>
        <a href="/api/public/adoption-plan/w14/schedule.ics">W14 Schedule ICS</a>
        <a href="/api/ops/adoption/w14/stability-sprint">W14 Stability Sprint API (Token)</a>
        <a href="/api/ops/adoption/w14/stability-policy">W14 Stability Policy API (Token)</a>
        <a href="/api/adoption/w14/tracker/items">W14 Tracker Items API (Token)</a>
        <a href="/api/adoption/w14/tracker/overview?site=HQ">W14 Tracker Overview API (Token)</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Checklist ID</th>
              <th>Title</th>
              <th>Stability Cluster</th>
              <th>Owner Role</th>
              <th>Target</th>
              <th>Source API</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w14_guide_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Runbook ID</th>
              <th>Module</th>
              <th>Symptom</th>
              <th>Owner Role</th>
              <th>Definition of Done</th>
              <th>API Ref</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w14_runbook_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Time</th>
              <th>Session</th>
              <th>Owner</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w14_schedule_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>W15 Operations Efficiency</h2>
      <p class="sub">운영 효율화 주차로 전환하여 실행추적 UI 공통화, 정책 응답 표준화, 주간 운영 리포트 자동화를 정착합니다.</p>
      <div class="links">
        <a href="/api/public/adoption-plan/w15">W15 JSON</a>
        <a href="/api/public/adoption-plan/w15/checklist.csv">W15 Checklist CSV</a>
        <a href="/api/public/adoption-plan/w15/schedule.ics">W15 Schedule ICS</a>
        <a href="/api/ops/adoption/w15/ops-efficiency">W15 Ops Efficiency API (Token)</a>
        <a href="/api/ops/adoption/w15/efficiency-policy">W15 Efficiency Policy API (Token)</a>
        <a href="/api/adoption/w15/tracker/items">W15 Tracker Items API (Token)</a>
        <a href="/api/adoption/w15/tracker/overview?site=HQ">W15 Tracker Overview API (Token)</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Checklist ID</th>
              <th>Title</th>
              <th>Efficiency Cluster</th>
              <th>Owner Role</th>
              <th>Target</th>
              <th>Source API</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w15_guide_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Runbook ID</th>
              <th>Module</th>
              <th>Symptom</th>
              <th>Owner Role</th>
              <th>Definition of Done</th>
              <th>API Ref</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w15_runbook_rows)}
          </tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top: 12px;">
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Time</th>
              <th>Session</th>
              <th>Owner</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>
            {"".join(w15_schedule_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>Weekly Execution Table</h2>
      <p class="sub">상단 카드에서 주차별 상태를 먼저 확인하고, 아래 표에서 상세 액션을 참고하세요.</p>
      <div class="filter-row">
        {"".join(phase_filter_buttons)}
        <input id="weekSearch" class="search-input" type="text" placeholder="phase/focus/owner 검색" />
      </div>
      <div id="timelineBoard" class="timeline-board">
        {"".join(week_cards)}
      </div>
      {active_week_guide}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Week</th>
              <th>Date</th>
              <th>Phase</th>
              <th>Focus</th>
              <th>Actions</th>
              <th>Deliverables</th>
              <th>Owner</th>
              <th>Success Metric</th>
            </tr>
          </thead>
          <tbody>
            {"".join(weekly_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>Training Materials Outline</h2>
      <p class="sub">역할별 학습 경로를 표준화하여 신입도 빠르게 실무에 진입하도록 설계했습니다.</p>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Module</th>
              <th>Audience</th>
              <th>Duration</th>
              <th>Contents</th>
              <th>Format</th>
            </tr>
          </thead>
          <tbody>
            {"".join(training_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>KPI Dashboard Items</h2>
      <p class="sub">운영 전환 이후에는 교육보다 KPI 기반 리뷰 비중을 높이는 것을 권장합니다.</p>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Formula</th>
              <th>Target</th>
              <th>Data Source</th>
              <th>Frequency</th>
            </tr>
          </thead>
          <tbody>
            {"".join(kpi_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>Promotion + Education + Fun Kit</h2>
      <p class="sub">홍보 + 교육 + 재미를 동시에 설계해 사용자 적응속도와 참여 지속성을 함께 확보합니다.</p>
      <h3>Promotion</h3>
      <div class="grid">
        {"".join(promotion_cards)}
      </div>
      <h3>Education</h3>
      <div class="grid">
        {"".join(education_cards)}
      </div>
      <h3>Fun</h3>
      <div class="grid">
        {"".join(fun_cards)}
      </div>
      <div class="links" style="margin-top: 12px;">
        <a href="/api/public/adoption-plan/campaign">Campaign API</a>
      </div>
    </section>

    <section class="section">
      <h2>Schedule Management</h2>
      <p class="sub">Next review date: {html.escape(str(plan.get("schedule_management", {}).get("next_review_date", "")))}</p>
      <div class="card">
        <h3>Operating Cadence</h3>
        <ul>{cadence_list}</ul>
      </div>
    </section>

    <section class="section">
      <h2>Post-MVP Execution Pack</h2>
      <p class="sub">
        Timeline: {html.escape(str(post_timeline.get("start_date", "")))} ~
        {html.escape(str(post_timeline.get("end_date", "")))} |
        Duration: {html.escape(str(post_timeline.get("duration_weeks", "")))} weeks
      </p>
      <div class="links">
        <a href="/api/public/post-mvp">Post-MVP JSON API</a>
        <a href="/api/public/post-mvp/backlog.csv">Backlog CSV</a>
        <a href="/api/public/post-mvp/releases.ics">Release ICS</a>
        <a href="/api/public/post-mvp/kpi-dashboard">KPI Spec API</a>
        <a href="/api/public/post-mvp/risks">Risk Register API</a>
      </div>
      <div class="card">
        <h3>Governance Cadence</h3>
        <ul>{post_governance_items_html}</ul>
      </div>
      <h3>Roadmap Phases</h3>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Phase</th>
              <th>Period</th>
              <th>Duration</th>
              <th>Objective</th>
              <th>Outcomes</th>
              <th>Release Gate</th>
            </tr>
          </thead>
          <tbody>
            {"".join(post_roadmap_rows)}
          </tbody>
        </table>
      </div>
      <h3>Execution Backlog</h3>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Epic</th>
              <th>Item</th>
              <th>Priority</th>
              <th>Owner</th>
              <th>Points</th>
              <th>Target Release</th>
              <th>Status</th>
              <th>Success KPI</th>
            </tr>
          </thead>
          <tbody>
            {"".join(post_backlog_rows)}
          </tbody>
        </table>
      </div>
      <h3>Release Calendar</h3>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Release</th>
              <th>Name</th>
              <th>Date</th>
              <th>Owner</th>
              <th>Goal</th>
            </tr>
          </thead>
          <tbody>
            {"".join(post_release_rows)}
          </tbody>
        </table>
      </div>
      <h3>Post-MVP KPI Dashboard Spec</h3>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Formula</th>
              <th>Target</th>
              <th>Cadence</th>
              <th>Owner</th>
              <th>Alert Rule</th>
            </tr>
          </thead>
          <tbody>
            {"".join(post_kpi_rows)}
          </tbody>
        </table>
      </div>
      <h3>Risk Register</h3>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Risk</th>
              <th>Probability</th>
              <th>Impact</th>
              <th>Signal</th>
              <th>Mitigation</th>
              <th>Owner</th>
              <th>Status</th>
              <th>Review</th>
            </tr>
          </thead>
          <tbody>
            {"".join(post_risk_rows)}
          </tbody>
        </table>
      </div>
    </section>
  </div>
  <script>
    (function() {{
      const buttons = Array.from(document.querySelectorAll(".filter-btn"));
      const cards = Array.from(document.querySelectorAll(".week-card"));
      const searchInput = document.getElementById("weekSearch");
      let selectedPhase = "all";

      function applyFilters() {{
        const query = ((searchInput && searchInput.value) || "").toLowerCase().trim();
        cards.forEach((card) => {{
          const phase = (card.dataset.phase || "").toLowerCase();
          const keywords = (card.dataset.keywords || "").toLowerCase();
          const phaseMatched = selectedPhase === "all" || phase === selectedPhase;
          const queryMatched = query === "" || keywords.includes(query);
          card.style.display = phaseMatched && queryMatched ? "" : "none";
        }});
      }}

      buttons.forEach((btn) => {{
        btn.addEventListener("click", () => {{
          selectedPhase = (btn.dataset.phase || "all").toLowerCase();
          buttons.forEach((b) => b.classList.remove("active"));
          btn.classList.add("active");
          applyFilters();
        }});
      }});

      if (searchInput) {{
        searchInput.addEventListener("input", applyFilters);
      }}
      applyFilters();

      const summaryToggle = document.getElementById("summaryModeToggle");
      if (summaryToggle) {{
        summaryToggle.addEventListener("click", () => {{
          const enabled = document.body.classList.toggle("summary-mode");
          summaryToggle.setAttribute("aria-pressed", enabled ? "true" : "false");
          summaryToggle.textContent = enabled
            ? "요약 모드 (핵심 5줄): ON"
            : "요약 모드 (핵심 5줄): OFF";
          if (enabled) {{
            window.scrollTo({{ top: 0, behavior: "smooth" }});
          }}
        }});
      }}
    }})();
  </script>
</body>
</html>
"""
