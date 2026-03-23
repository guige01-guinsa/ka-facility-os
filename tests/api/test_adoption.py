import importlib
import io
import json
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from tests.helpers.common import _assert_adoption_policy_response_shape, _owner_headers


@pytest.mark.smoke
def test_public_main_and_adoption_plan_endpoints(app_client: TestClient) -> None:
    root_json = app_client.get("/")
    assert root_json.status_code == 200
    assert root_json.json()["service"] == "ka-facility-os"
    assert "public_adoption_plan_api" in root_json.json()
    assert "public_adoption_campaign_api" in root_json.json()
    assert "public_adoption_w02_api" in root_json.json()
    assert "public_adoption_w05_api" in root_json.json()
    assert "public_adoption_w06_api" in root_json.json()
    assert "public_adoption_w07_api" in root_json.json()
    assert "public_adoption_w08_api" in root_json.json()
    assert "public_adoption_w09_api" in root_json.json()
    assert "public_adoption_w10_api" in root_json.json()
    assert "public_adoption_w11_api" in root_json.json()
    assert "public_adoption_w12_api" in root_json.json()
    assert "public_adoption_w13_api" in root_json.json()
    assert "public_adoption_w14_api" in root_json.json()
    assert "public_adoption_w15_api" in root_json.json()
    assert "adoption_w02_tracker_items_api" in root_json.json()
    assert "adoption_w03_tracker_items_api" in root_json.json()
    assert "adoption_w04_tracker_items_api" in root_json.json()
    assert "adoption_w05_consistency_api" in root_json.json()
    assert "adoption_w06_rhythm_api" in root_json.json()
    assert "adoption_w07_sla_quality_api" in root_json.json()
    assert "adoption_w08_report_discipline_api" in root_json.json()
    assert "adoption_w09_kpi_operation_api" in root_json.json()
    assert "adoption_w09_kpi_policy_api" in root_json.json()
    assert "adoption_w09_tracker_items_api" in root_json.json()
    assert "adoption_w10_self_serve_api" in root_json.json()
    assert "adoption_w10_support_policy_api" in root_json.json()
    assert "adoption_w10_tracker_items_api" in root_json.json()
    assert "adoption_w11_scale_readiness_api" in root_json.json()
    assert "adoption_w11_readiness_policy_api" in root_json.json()
    assert "adoption_w11_tracker_items_api" in root_json.json()
    assert "adoption_w12_closure_handoff_api" in root_json.json()
    assert "adoption_w12_handoff_policy_api" in root_json.json()
    assert "adoption_w12_tracker_items_api" in root_json.json()
    assert "adoption_w13_closure_handoff_api" in root_json.json()
    assert "adoption_w13_handoff_policy_api" in root_json.json()
    assert "adoption_w13_tracker_items_api" in root_json.json()
    assert "adoption_w14_stability_sprint_api" in root_json.json()
    assert "adoption_w14_stability_policy_api" in root_json.json()
    assert "adoption_w14_tracker_items_api" in root_json.json()
    assert "adoption_w15_ops_efficiency_api" in root_json.json()
    assert "adoption_w15_efficiency_policy_api" in root_json.json()
    assert "adoption_w15_tracker_items_api" in root_json.json()
    assert "adoption_w07_tracker_items_api" in root_json.json()
    assert "adoption_w07_sla_quality_weekly_run_api" in root_json.json()
    assert "public_modules_api" in root_json.json()
    assert "public_tutorial_simulator_api" in root_json.json()
    assert "public_onboarding_day1_api" in root_json.json()
    assert "public_glossary_api" in root_json.json()
    assert "tutorial_simulator_html" in root_json.json()
    assert root_json.json()["adoption_portal_html"] == "/web/adoption"
    assert root_json.json()["facility_console_html"] == "/web/console"
    assert "public_post_mvp_plan_api" in root_json.json()
    assert "public_post_mvp_backlog_csv_api" in root_json.json()

    root_html = app_client.get("/", headers={"Accept": "text/html"})
    assert root_html.status_code == 200
    assert root_html.headers["content-type"].startswith("text/html")
    assert root_html.headers.get("cache-control") == "no-store"
    assert root_html.headers.get("pragma") == "no-cache"
    assert root_html.headers.get("x-robots-tag") == "noindex, nofollow"
    assert root_html.headers.get("x-content-type-options") == "nosniff"
    assert root_html.headers.get("x-frame-options") == "DENY"
    assert "default-src 'self'" in root_html.headers.get("content-security-policy", "")
    assert "시설관리시스템 메인" in root_html.text
    assert "세대 민원처리" in root_html.text
    assert "운영요약" in root_html.text
    assert ".split(/\\r?\\n/)" in root_html.text
    assert "작업지시" in root_html.text
    assert "점검" in root_html.text
    assert "월간리포트" in root_html.text
    assert "사용자 정착 계획" in root_html.text
    assert "W01 Role Workflow Lock Matrix" in root_html.text
    assert "W02 Scheduled SOP and Sandbox" in root_html.text
    assert "W03 Go-live Onboarding" in root_html.text
    assert "W04 First Success Acceleration" in root_html.text
    assert "W05 Usage Consistency" in root_html.text
    assert "W06 Operational Rhythm" in root_html.text
    assert "W07 SLA Quality" in root_html.text
    assert "W08 Report Discipline" in root_html.text
    assert "W09 KPI Operation" in root_html.text
    assert "W10 Self-serve Support" in root_html.text
    assert "W11 Scale Readiness" in root_html.text
    assert "W15 Operations Efficiency" in root_html.text
    assert "W09 KPI Operation Dashboard (Token)" in root_html.text
    assert "W10 Self-serve Dashboard (Token)" in root_html.text
    assert "W11 Scale Readiness Dashboard (Token)" in root_html.text
    assert "W15 Operations Efficiency Dashboard (Token)" in root_html.text
    assert "W03 실행 추적" in root_html.text
    assert "W04 실행 추적" in root_html.text
    assert "W07 실행 추적" in root_html.text
    assert "W10 실행 추적" in root_html.text
    assert "W11 실행 추적" in root_html.text
    assert "W15 실행 추적" in root_html.text
    assert "처음 1일 운영 체크리스트" in root_html.text
    assert "역할별 시작 가이드" in root_html.text
    assert "운영 용어집" in root_html.text
    assert "권한 확인: 현재 토큰으로 /api/auth/me를 호출해 사용자와 역할을 확인합니다." in root_html.text
    assert "요약 새로고침: 운영요약 데이터와 핵심 지표를 다시 조회합니다." in root_html.text
    assert "점검 저장: 법정점검 1건을 저장하고 필요 시 작업지시/증빙 업로드를 이어서 처리합니다." in root_html.text
    assert "사용자 생성: 새 사용자 계정과 기본 권한을 등록합니다." in root_html.text
    assert "용어집 새로고침: 운영 용어집을 다시 불러와 검색 기준에 맞게 보여줍니다." in root_html.text
    assert "W07 주간 자동화/트렌드" in root_html.text
    assert "W05 지표 새로고침" in root_html.text
    assert "W06 리듬 새로고침" in root_html.text
    assert "W07 품질 새로고침" in root_html.text
    assert "W08 리포트 새로고침" in root_html.text
    assert "완료 판정" in root_html.text
    assert "W02 완료 확정" in root_html.text
    assert "W04 완료 확정" in root_html.text
    assert "알림 채널 KPI" in root_html.text
    assert "알림 채널 MTTR" in root_html.text
    assert "X-Admin-Token 입력" in root_html.text
    assert "kaFacility.auth.token" in root_html.text
    assert "kaFacility.auth.profile" in root_html.text
    assert "ID/PW 로그인" in root_html.text
    assert "사용자 신규가입" in root_html.text
    assert "권한관리" in root_html.text
    assert "로그아웃" in root_html.text
    assert "토큰 발급 / 회전 / 폐기" in root_html.text
    assert "감사 로그 조회" in root_html.text
    assert "사용 설명서 열기" in root_html.text
    assert "/web/iam-guide" in root_html.text
    assert "/web/tutorial-guide" in root_html.text
    assert "Overview(운영요약)" in root_html.text
    assert "IAM(권한관리)" in root_html.text
    assert "요약 새로고침" in root_html.text

    root_html_adoption_tab = app_client.get("/?tab=adoption", headers={"Accept": "text/html"})
    assert root_html_adoption_tab.status_code == 200
    assert "사용자 정착 계획" in root_html_adoption_tab.text

    service_info = app_client.get("/api/service-info")
    assert service_info.status_code == 200
    assert service_info.json()["service"] == "ka-facility-os"
    assert service_info.json()["inspection_evidence_upload_api"] == "/api/inspections/{inspection_id}/evidence"
    assert service_info.json()["inspection_evidence_list_api"] == "/api/inspections/{inspection_id}/evidence"
    assert service_info.json()["inspection_evidence_download_api"] == "/api/inspections/evidence/{evidence_id}/download"
    assert service_info.json()["ops_inspection_checklists_catalog_api"] == "/api/ops/inspections/checklists/catalog"
    assert (
        service_info.json()["ops_inspection_checklists_import_validation_api"]
        == "/api/ops/inspections/checklists/import-validation"
    )
    assert (
        service_info.json()["ops_inspection_checklists_import_validation_csv_api"]
        == "/api/ops/inspections/checklists/import-validation.csv"
    )
    assert (
        service_info.json()["ops_inspection_checklists_qr_placeholders_api"]
        == "/api/ops/inspections/checklists/qr-assets/placeholders"
    )
    assert (
        service_info.json()["ops_inspection_checklists_qr_bulk_update_api"]
        == "/api/ops/inspections/checklists/qr-assets/bulk-update"
    )
    assert service_info.json()["work_order_sla_rules_api"] == "/api/work-orders/sla/rules"
    assert service_info.json()["auth_login_api"] == "/api/auth/login"
    assert service_info.json()["auth_logout_api"] == "/api/auth/logout"
    assert service_info.json()["admin_user_password_api"] == "/api/admin/users/{user_id}/password"
    assert "public_modules_api" in service_info.json()
    assert service_info.json()["adoption_portal_html"] == "/web/adoption"
    assert service_info.json()["facility_console_html"] == "/web/console"
    assert "public_post_mvp_release_ics_api" in service_info.json()
    assert service_info.json()["public_adoption_w02_api"] == "/api/public/adoption-plan/w02"
    assert service_info.json()["public_adoption_w02_checklist_csv_api"] == "/api/public/adoption-plan/w02/checklist.csv"
    assert service_info.json()["public_adoption_w02_schedule_ics_api"] == "/api/public/adoption-plan/w02/schedule.ics"
    assert service_info.json()["public_adoption_w02_sample_files_api"] == "/api/public/adoption-plan/w02/sample-files"
    assert service_info.json()["public_adoption_w03_api"] == "/api/public/adoption-plan/w03"
    assert service_info.json()["public_adoption_w03_checklist_csv_api"] == "/api/public/adoption-plan/w03/checklist.csv"
    assert service_info.json()["public_adoption_w03_schedule_ics_api"] == "/api/public/adoption-plan/w03/schedule.ics"
    assert service_info.json()["public_adoption_w04_api"] == "/api/public/adoption-plan/w04"
    assert service_info.json()["public_adoption_w04_checklist_csv_api"] == "/api/public/adoption-plan/w04/checklist.csv"
    assert service_info.json()["public_adoption_w04_schedule_ics_api"] == "/api/public/adoption-plan/w04/schedule.ics"
    assert service_info.json()["public_adoption_w04_common_mistakes_api"] == "/api/public/adoption-plan/w04/common-mistakes"
    assert service_info.json()["public_adoption_w04_common_mistakes_html"] == "/web/adoption/w04/common-mistakes"
    assert service_info.json()["public_adoption_w05_api"] == "/api/public/adoption-plan/w05"
    assert service_info.json()["public_adoption_w05_missions_csv_api"] == "/api/public/adoption-plan/w05/missions.csv"
    assert service_info.json()["public_adoption_w05_schedule_ics_api"] == "/api/public/adoption-plan/w05/schedule.ics"
    assert service_info.json()["public_adoption_w05_help_docs_api"] == "/api/public/adoption-plan/w05/help-docs"
    assert service_info.json()["public_adoption_w06_api"] == "/api/public/adoption-plan/w06"
    assert service_info.json()["public_adoption_w06_checklist_csv_api"] == "/api/public/adoption-plan/w06/checklist.csv"
    assert service_info.json()["public_adoption_w06_schedule_ics_api"] == "/api/public/adoption-plan/w06/schedule.ics"
    assert service_info.json()["public_adoption_w06_rbac_audit_template_api"] == "/api/public/adoption-plan/w06/rbac-audit-template"
    assert service_info.json()["public_adoption_w07_api"] == "/api/public/adoption-plan/w07"
    assert service_info.json()["public_adoption_w07_checklist_csv_api"] == "/api/public/adoption-plan/w07/checklist.csv"
    assert service_info.json()["public_adoption_w07_schedule_ics_api"] == "/api/public/adoption-plan/w07/schedule.ics"
    assert (
        service_info.json()["public_adoption_w07_coaching_playbook_api"]
        == "/api/public/adoption-plan/w07/coaching-playbook"
    )
    assert service_info.json()["public_adoption_w08_api"] == "/api/public/adoption-plan/w08"
    assert (
        service_info.json()["public_adoption_w08_checklist_csv_api"]
        == "/api/public/adoption-plan/w08/checklist.csv"
    )
    assert (
        service_info.json()["public_adoption_w08_schedule_ics_api"]
        == "/api/public/adoption-plan/w08/schedule.ics"
    )
    assert (
        service_info.json()["public_adoption_w08_reporting_sop_api"]
        == "/api/public/adoption-plan/w08/reporting-sop"
    )
    assert service_info.json()["public_adoption_w09_api"] == "/api/public/adoption-plan/w09"
    assert (
        service_info.json()["public_adoption_w09_checklist_csv_api"]
        == "/api/public/adoption-plan/w09/checklist.csv"
    )
    assert (
        service_info.json()["public_adoption_w09_schedule_ics_api"]
        == "/api/public/adoption-plan/w09/schedule.ics"
    )
    assert service_info.json()["public_adoption_w10_api"] == "/api/public/adoption-plan/w10"
    assert (
        service_info.json()["public_adoption_w10_checklist_csv_api"]
        == "/api/public/adoption-plan/w10/checklist.csv"
    )
    assert (
        service_info.json()["public_adoption_w10_schedule_ics_api"]
        == "/api/public/adoption-plan/w10/schedule.ics"
    )
    assert service_info.json()["public_adoption_w11_api"] == "/api/public/adoption-plan/w11"
    assert (
        service_info.json()["public_adoption_w11_checklist_csv_api"]
        == "/api/public/adoption-plan/w11/checklist.csv"
    )
    assert (
        service_info.json()["public_adoption_w11_schedule_ics_api"]
        == "/api/public/adoption-plan/w11/schedule.ics"
    )
    assert service_info.json()["public_adoption_w12_api"] == "/api/public/adoption-plan/w12"
    assert service_info.json()["public_adoption_w13_api"] == "/api/public/adoption-plan/w13"
    assert service_info.json()["public_adoption_w14_api"] == "/api/public/adoption-plan/w14"
    assert service_info.json()["public_adoption_w14_checklist_csv_api"] == "/api/public/adoption-plan/w14/checklist.csv"
    assert service_info.json()["public_adoption_w14_schedule_ics_api"] == "/api/public/adoption-plan/w14/schedule.ics"
    assert service_info.json()["public_adoption_w15_api"] == "/api/public/adoption-plan/w15"
    assert service_info.json()["public_adoption_w15_checklist_csv_api"] == "/api/public/adoption-plan/w15/checklist.csv"
    assert service_info.json()["public_adoption_w15_schedule_ics_api"] == "/api/public/adoption-plan/w15/schedule.ics"
    assert service_info.json()["adoption_w13_tracker_items_api"] == "/api/adoption/w13/tracker/items"
    assert service_info.json()["adoption_w13_closure_handoff_api"] == "/api/ops/adoption/w13/closure-handoff"
    assert service_info.json()["adoption_w13_handoff_policy_api"] == "/api/ops/adoption/w13/handoff-policy"
    assert service_info.json()["adoption_w14_tracker_items_api"] == "/api/adoption/w14/tracker/items"
    assert service_info.json()["adoption_w14_stability_sprint_api"] == "/api/ops/adoption/w14/stability-sprint"
    assert service_info.json()["adoption_w14_stability_policy_api"] == "/api/ops/adoption/w14/stability-policy"
    assert service_info.json()["adoption_w15_tracker_items_api"] == "/api/adoption/w15/tracker/items"
    assert service_info.json()["adoption_w15_ops_efficiency_api"] == "/api/ops/adoption/w15/ops-efficiency"
    assert service_info.json()["adoption_w15_efficiency_policy_api"] == "/api/ops/adoption/w15/efficiency-policy"
    assert service_info.json()["adoption_w02_tracker_items_api"] == "/api/adoption/w02/tracker/items"
    assert service_info.json()["adoption_w02_tracker_overview_api"] == "/api/adoption/w02/tracker/overview"
    assert service_info.json()["adoption_w02_tracker_readiness_api"] == "/api/adoption/w02/tracker/readiness"
    assert service_info.json()["adoption_w02_tracker_completion_api"] == "/api/adoption/w02/tracker/completion"
    assert service_info.json()["adoption_w02_tracker_complete_api"] == "/api/adoption/w02/tracker/complete"
    assert service_info.json()["adoption_w03_tracker_items_api"] == "/api/adoption/w03/tracker/items"
    assert service_info.json()["adoption_w03_tracker_overview_api"] == "/api/adoption/w03/tracker/overview"
    assert service_info.json()["adoption_w03_tracker_readiness_api"] == "/api/adoption/w03/tracker/readiness"
    assert service_info.json()["adoption_w03_tracker_completion_api"] == "/api/adoption/w03/tracker/completion"
    assert service_info.json()["adoption_w03_tracker_complete_api"] == "/api/adoption/w03/tracker/complete"
    assert service_info.json()["adoption_w04_funnel_api"] == "/api/ops/adoption/w04/funnel"
    assert service_info.json()["adoption_w04_blockers_api"] == "/api/ops/adoption/w04/blockers"
    assert service_info.json()["adoption_w04_tracker_items_api"] == "/api/adoption/w04/tracker/items"
    assert service_info.json()["adoption_w04_tracker_overview_api"] == "/api/adoption/w04/tracker/overview"
    assert service_info.json()["adoption_w04_tracker_readiness_api"] == "/api/adoption/w04/tracker/readiness"
    assert service_info.json()["adoption_w04_tracker_completion_api"] == "/api/adoption/w04/tracker/completion"
    assert service_info.json()["adoption_w04_tracker_complete_api"] == "/api/adoption/w04/tracker/complete"
    assert service_info.json()["adoption_w07_tracker_items_api"] == "/api/adoption/w07/tracker/items"
    assert service_info.json()["adoption_w07_tracker_overview_api"] == "/api/adoption/w07/tracker/overview"
    assert service_info.json()["adoption_w07_tracker_readiness_api"] == "/api/adoption/w07/tracker/readiness"
    assert service_info.json()["adoption_w07_tracker_completion_api"] == "/api/adoption/w07/tracker/completion"
    assert (
        service_info.json()["adoption_w07_tracker_completion_package_api"]
        == "/api/adoption/w07/tracker/completion-package"
    )
    assert service_info.json()["adoption_w07_tracker_complete_api"] == "/api/adoption/w07/tracker/complete"
    assert service_info.json()["adoption_w05_consistency_api"] == "/api/ops/adoption/w05/consistency"
    assert service_info.json()["adoption_w06_rhythm_api"] == "/api/ops/adoption/w06/rhythm"
    assert service_info.json()["adoption_w07_sla_quality_api"] == "/api/ops/adoption/w07/sla-quality"
    assert service_info.json()["adoption_w08_report_discipline_api"] == "/api/ops/adoption/w08/report-discipline"
    assert service_info.json()["adoption_w08_site_benchmark_api"] == "/api/ops/adoption/w08/site-benchmark"
    assert service_info.json()["adoption_w09_tracker_items_api"] == "/api/adoption/w09/tracker/items"
    assert service_info.json()["adoption_w09_tracker_overview_api"] == "/api/adoption/w09/tracker/overview"
    assert service_info.json()["adoption_w09_tracker_bootstrap_api"] == "/api/adoption/w09/tracker/bootstrap"
    assert service_info.json()["adoption_w09_tracker_readiness_api"] == "/api/adoption/w09/tracker/readiness"
    assert service_info.json()["adoption_w09_tracker_completion_api"] == "/api/adoption/w09/tracker/completion"
    assert service_info.json()["adoption_w09_tracker_complete_api"] == "/api/adoption/w09/tracker/complete"
    assert service_info.json()["adoption_w09_kpi_operation_api"] == "/api/ops/adoption/w09/kpi-operation"
    assert service_info.json()["adoption_w09_kpi_policy_api"] == "/api/ops/adoption/w09/kpi-policy"
    assert service_info.json()["adoption_w10_tracker_items_api"] == "/api/adoption/w10/tracker/items"
    assert service_info.json()["adoption_w10_tracker_overview_api"] == "/api/adoption/w10/tracker/overview"
    assert service_info.json()["adoption_w10_tracker_bootstrap_api"] == "/api/adoption/w10/tracker/bootstrap"
    assert service_info.json()["adoption_w10_tracker_readiness_api"] == "/api/adoption/w10/tracker/readiness"
    assert service_info.json()["adoption_w10_tracker_completion_api"] == "/api/adoption/w10/tracker/completion"
    assert service_info.json()["adoption_w10_tracker_complete_api"] == "/api/adoption/w10/tracker/complete"
    assert service_info.json()["adoption_w11_tracker_items_api"] == "/api/adoption/w11/tracker/items"
    assert service_info.json()["adoption_w11_tracker_overview_api"] == "/api/adoption/w11/tracker/overview"
    assert service_info.json()["adoption_w11_tracker_bootstrap_api"] == "/api/adoption/w11/tracker/bootstrap"
    assert service_info.json()["adoption_w11_tracker_readiness_api"] == "/api/adoption/w11/tracker/readiness"
    assert service_info.json()["adoption_w11_tracker_completion_api"] == "/api/adoption/w11/tracker/completion"
    assert service_info.json()["adoption_w11_tracker_complete_api"] == "/api/adoption/w11/tracker/complete"
    assert service_info.json()["adoption_w10_self_serve_api"] == "/api/ops/adoption/w10/self-serve"
    assert service_info.json()["adoption_w10_support_policy_api"] == "/api/ops/adoption/w10/support-policy"
    assert service_info.json()["adoption_w11_scale_readiness_api"] == "/api/ops/adoption/w11/scale-readiness"
    assert service_info.json()["adoption_w11_readiness_policy_api"] == "/api/ops/adoption/w11/readiness-policy"
    assert (
        service_info.json()["adoption_w07_automation_readiness_api"]
        == "/api/ops/adoption/w07/automation-readiness"
    )
    assert (
        service_info.json()["adoption_w07_sla_quality_weekly_run_api"]
        == "/api/ops/adoption/w07/sla-quality/run-weekly"
    )
    assert (
        service_info.json()["adoption_w07_sla_quality_weekly_latest_api"]
        == "/api/ops/adoption/w07/sla-quality/latest-weekly"
    )
    assert (
        service_info.json()["adoption_w07_sla_quality_weekly_trends_api"]
        == "/api/ops/adoption/w07/sla-quality/trends"
    )
    assert (
        service_info.json()["adoption_w07_sla_quality_weekly_archive_csv_api"]
        == "/api/ops/adoption/w07/sla-quality/archive.csv"
    )
    assert service_info.json()["admin_audit_integrity_api"] == "/api/admin/audit-integrity"
    assert service_info.json()["admin_audit_rebaseline_api"] == "/api/admin/audit-chain/rebaseline"
    assert service_info.json()["admin_user_token_issue_api"] == "/api/admin/users/{user_id}/tokens"
    assert service_info.json()["admin_token_rotate_api"] == "/api/admin/tokens/{token_id}/rotate"
    assert service_info.json()["admin_token_revoke_api"] == "/api/admin/tokens/{token_id}/revoke"
    assert service_info.json()["ops_runbook_checks_api"] == "/api/ops/runbook/checks"
    assert service_info.json()["ops_runbook_checks_run_api"] == "/api/ops/runbook/checks/run"
    assert service_info.json()["ops_runbook_checks_latest_api"] == "/api/ops/runbook/checks/latest"
    assert (
        service_info.json()["ops_runbook_checks_latest_summary_json_api"]
        == "/api/ops/runbook/checks/latest/summary.json"
    )
    assert (
        service_info.json()["ops_runbook_checks_latest_summary_csv_api"]
        == "/api/ops/runbook/checks/latest/summary.csv"
    )
    assert service_info.json()["ops_runbook_checks_archive_json_api"] == "/api/ops/runbook/checks/archive.json"
    assert service_info.json()["ops_runbook_checks_archive_csv_api"] == "/api/ops/runbook/checks/archive.csv"
    assert service_info.json()["ops_runbook_review_run_api"] == "/api/ops/runbook/review/run"
    assert service_info.json()["ops_runbook_review_latest_api"] == "/api/ops/runbook/review/latest"
    assert service_info.json()["ops_preflight_api"] == "/api/ops/preflight"
    assert service_info.json()["ops_alert_noise_policy_api"] == "/api/ops/alerts/noise-policy"
    assert service_info.json()["ops_admin_security_dashboard_api"] == "/api/ops/admin/security-dashboard"
    assert service_info.json()["ops_quality_weekly_report_api"] == "/api/ops/reports/quality/weekly"
    assert service_info.json()["ops_quality_weekly_report_csv_api"] == "/api/ops/reports/quality/weekly/csv"
    assert service_info.json()["ops_quality_monthly_report_api"] == "/api/ops/reports/quality/monthly"
    assert service_info.json()["ops_quality_monthly_report_csv_api"] == "/api/ops/reports/quality/monthly/csv"
    assert service_info.json()["ops_quality_report_run_api"] == "/api/ops/reports/quality/run"
    assert service_info.json()["ops_quality_weekly_streak_api"] == "/api/ops/reports/quality/weekly/streak"
    assert service_info.json()["ops_dr_rehearsal_run_api"] == "/api/ops/dr/rehearsal/run"
    assert service_info.json()["ops_dr_rehearsal_latest_api"] == "/api/ops/dr/rehearsal/latest"
    assert service_info.json()["ops_dr_rehearsal_history_api"] == "/api/ops/dr/rehearsal/history"
    assert service_info.json()["ops_governance_gate_api"] == "/api/ops/governance/gate"
    assert service_info.json()["ops_governance_gate_run_api"] == "/api/ops/governance/gate/run"
    assert service_info.json()["ops_governance_gate_latest_api"] == "/api/ops/governance/gate/latest"
    assert service_info.json()["ops_governance_gate_history_api"] == "/api/ops/governance/gate/history"
    assert service_info.json()["ops_governance_gate_remediation_api"] == "/api/ops/governance/gate/remediation"
    assert (
        service_info.json()["ops_governance_gate_remediation_csv_api"]
        == "/api/ops/governance/gate/remediation/csv"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_sync_api"]
        == "/api/ops/governance/gate/remediation/tracker/sync"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_items_api"]
        == "/api/ops/governance/gate/remediation/tracker/items"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_overview_api"]
        == "/api/ops/governance/gate/remediation/tracker/overview"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_readiness_api"]
        == "/api/ops/governance/gate/remediation/tracker/readiness"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_completion_api"]
        == "/api/ops/governance/gate/remediation/tracker/completion"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_complete_api"]
        == "/api/ops/governance/gate/remediation/tracker/complete"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_sla_api"]
        == "/api/ops/governance/gate/remediation/tracker/sla"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_escalate_run_api"]
        == "/api/ops/governance/gate/remediation/tracker/escalate/run"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_escalate_latest_api"]
        == "/api/ops/governance/gate/remediation/tracker/escalate/latest"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_workload_api"]
        == "/api/ops/governance/gate/remediation/tracker/workload"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_auto_assign_run_api"]
        == "/api/ops/governance/gate/remediation/tracker/auto-assign/run"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_auto_assign_latest_api"]
        == "/api/ops/governance/gate/remediation/tracker/auto-assign/latest"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_kpi_api"]
        == "/api/ops/governance/gate/remediation/tracker/kpi"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_kpi_run_api"]
        == "/api/ops/governance/gate/remediation/tracker/kpi/run"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_kpi_latest_api"]
        == "/api/ops/governance/gate/remediation/tracker/kpi/latest"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_autopilot_run_api"]
        == "/api/ops/governance/gate/remediation/tracker/autopilot/run"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_autopilot_policy_api"]
        == "/api/ops/governance/gate/remediation/tracker/autopilot/policy"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_autopilot_preview_api"]
        == "/api/ops/governance/gate/remediation/tracker/autopilot/preview"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_autopilot_guard_api"]
        == "/api/ops/governance/gate/remediation/tracker/autopilot/guard"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_autopilot_history_api"]
        == "/api/ops/governance/gate/remediation/tracker/autopilot/history"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_autopilot_history_csv_api"]
        == "/api/ops/governance/gate/remediation/tracker/autopilot/history.csv"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_autopilot_summary_api"]
        == "/api/ops/governance/gate/remediation/tracker/autopilot/summary"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_autopilot_summary_csv_api"]
        == "/api/ops/governance/gate/remediation/tracker/autopilot/summary.csv"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_autopilot_anomalies_api"]
        == "/api/ops/governance/gate/remediation/tracker/autopilot/anomalies"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_autopilot_anomalies_csv_api"]
        == "/api/ops/governance/gate/remediation/tracker/autopilot/anomalies.csv"
    )
    assert (
        service_info.json()["ops_governance_remediation_tracker_autopilot_latest_api"]
        == "/api/ops/governance/gate/remediation/tracker/autopilot/latest"
    )
    assert (
        service_info.json()["ops_tutorial_simulator_session_start_api"]
        == "/api/ops/tutorial-simulator/sessions/start"
    )
    assert (
        service_info.json()["ops_tutorial_simulator_sessions_api"]
        == "/api/ops/tutorial-simulator/sessions"
    )
    assert (
        service_info.json()["ops_tutorial_simulator_session_api"]
        == "/api/ops/tutorial-simulator/sessions/{session_id}"
    )
    assert (
        service_info.json()["ops_tutorial_simulator_session_check_api"]
        == "/api/ops/tutorial-simulator/sessions/{session_id}/check"
    )
    assert (
        service_info.json()["ops_tutorial_simulator_session_action_api"]
        == "/api/ops/tutorial-simulator/sessions/{session_id}/actions/{action}"
    )
    assert service_info.json()["ops_security_posture_api"] == "/api/ops/security/posture"
    assert service_info.json()["ops_api_latency_api"] == "/api/ops/performance/api-latency"
    assert service_info.json()["ops_evidence_archive_integrity_api"] == "/api/ops/integrity/evidence-archive"
    assert service_info.json()["ops_deploy_checklist_api"] == "/api/ops/deploy/checklist"
    assert service_info.json()["ops_deploy_smoke_record_api"] == "/api/ops/deploy/smoke/record"
    assert service_info.json()["alert_channel_kpi_api"] == "/api/ops/alerts/kpi/channels"
    assert service_info.json()["alert_internal_webhook_api"] == "/api/ops/alerts/webhook/internal"
    assert service_info.json()["alert_channel_mttr_kpi_api"] == "/api/ops/alerts/kpi/mttr"
    assert service_info.json()["alert_mttr_slo_policy_api"] == "/api/ops/alerts/mttr-slo/policy"
    assert service_info.json()["alert_mttr_slo_run_api"] == "/api/ops/alerts/mttr-slo/check/run"
    assert service_info.json()["alert_mttr_slo_latest_api"] == "/api/ops/alerts/mttr-slo/check/latest"
    assert service_info.json()["alert_channel_guard_api"] == "/api/ops/alerts/channels/guard"
    assert service_info.json()["alert_channel_guard_recover_api"] == "/api/ops/alerts/channels/guard/recover"
    assert service_info.json()["alert_channel_guard_recover_batch_api"] == "/api/ops/alerts/channels/guard/recover-batch"
    assert service_info.json()["alert_channel_guard_recover_latest_api"] == "/api/ops/alerts/channels/guard/recover/latest"
    assert service_info.json()["alert_retention_policy_api"] == "/api/ops/alerts/retention/policy"
    assert service_info.json()["alert_retention_latest_api"] == "/api/ops/alerts/retention/latest"
    assert service_info.json()["alert_retention_run_api"] == "/api/ops/alerts/retention/run"
    assert service_info.json()["public_tutorial_simulator_api"] == "/api/public/tutorial-simulator"
    assert (
        service_info.json()["public_tutorial_simulator_sample_files_api"]
        == "/api/public/tutorial-simulator/sample-files"
    )
    assert service_info.json()["public_onboarding_day1_api"] == "/api/public/onboarding/day1"
    assert service_info.json()["public_glossary_api"] == "/api/public/glossary"
    assert service_info.json()["tutorial_simulator_html"] == "/web/tutorial-simulator"
    assert service_info.json()["tutorial_guide_html"] == "/web/tutorial-guide"
    assert service_info.json()["facility_console_guide_html"] == "/web/console/guide"
    assert service_info.json()["iam_guide_html"] == "/web/iam-guide"

    console_html = app_client.get("/web/console")
    assert console_html.status_code == 200
    assert console_html.headers["content-type"].startswith("text/html")
    assert console_html.headers.get("cache-control") == "no-store"
    assert console_html.headers.get("pragma") == "no-cache"
    assert console_html.headers.get("x-robots-tag") == "noindex, nofollow"
    assert "KA Facility OS 시설관리 운영 콘솔" in console_html.text
    assert "X-Admin-Token" in console_html.text
    assert "결과 보기" in console_html.text
    assert "알림 채널 KPI (7/30일)" in console_html.text
    assert "알림 데이터 보관정책" in console_html.text
    assert "토큰 저장: 현재 입력한 X-Admin-Token을 이 브라우저 세션에 저장합니다." in console_html.text
    assert "kaFacility.auth.token" in console_html.text
    assert "kaFacility.auth.profile" in console_html.text
    assert "조회 실행: 서비스 정보 API를 HTML 표 형태로 조회합니다." in console_html.text
    assert "조회 실행: 점검 목록을 조건별로 조회합니다." in console_html.text
    assert "JSON 조회: 월간리포트 원본 JSON을 조회합니다." in console_html.text
    assert "사용 설명서 열기" in console_html.text
    assert "세대 민원처리" in console_html.text
    assert "/web/complaints" in console_html.text

    console_guide_html = app_client.get("/web/console/guide")
    assert console_guide_html.status_code == 200
    assert console_guide_html.headers["content-type"].startswith("text/html")
    assert console_guide_html.headers.get("cache-control") == "no-store"
    assert console_guide_html.headers.get("pragma") == "no-cache"
    assert "운영 콘솔 1페이지 시작 가이드" in console_guide_html.text
    assert "연결 테스트 (/api/auth/me)" in console_guide_html.text
    assert "점검 목록" in console_guide_html.text
    assert "월간 감사 리포트" in console_guide_html.text
    assert "자주 보는 오류와 조치" in console_guide_html.text

    iam_guide_html = app_client.get("/web/iam-guide")
    assert iam_guide_html.status_code == 200
    assert iam_guide_html.headers["content-type"].startswith("text/html")
    assert "IAM 탭 사용자 매뉴얼" in iam_guide_html.text
    assert "내 권한 조회" in iam_guide_html.text
    assert "토큰 발급" in iam_guide_html.text
    assert "감사 로그 조회" in iam_guide_html.text

    tutorial_guide_html = app_client.get("/web/tutorial-guide")
    assert tutorial_guide_html.status_code == 200
    assert tutorial_guide_html.headers["content-type"].startswith("text/html")
    assert "튜토리얼 사용 설명서" in tutorial_guide_html.text
    assert "세션 시작" in tutorial_guide_html.text
    assert "ACK 실행" in tutorial_guide_html.text
    assert "완료 판정" in tutorial_guide_html.text

    adoption_html = app_client.get("/web/adoption")
    assert adoption_html.status_code == 200
    assert adoption_html.headers["content-type"].startswith("text/html")
    assert "KA Facility OS" in adoption_html.text
    assert "User Adoption Plan" in adoption_html.text
    assert "Promotion + Education + Fun Kit" in adoption_html.text
    assert "W02 Scheduled SOP and Sandbox" in adoption_html.text
    assert "W03 Go-live Onboarding" in adoption_html.text
    assert "W04 First Success Acceleration" in adoption_html.text
    assert "W05 Usage Consistency" in adoption_html.text
    assert "W06 Operational Rhythm" in adoption_html.text
    assert "W07 SLA Quality" in adoption_html.text
    assert "W08 Report Discipline" in adoption_html.text
    assert "W09 KPI Operation" in adoption_html.text
    assert "W10 Self-serve Support" in adoption_html.text
    assert "W11 Scale Readiness" in adoption_html.text
    assert "W14 Stability Sprint" in adoption_html.text
    assert "W15 Operations Efficiency" in adoption_html.text
    assert "W02 샘플 파일" in adoption_html.text
    assert "시설 웹 모듈" in adoption_html.text
    assert "Tutorial Simulator" in adoption_html.text
    assert "운영 콘솔 HTML" in adoption_html.text
    assert "요약 모드 (핵심 5줄): OFF" in adoption_html.text
    assert "핵심 5줄 요약" in adoption_html.text
    assert "Post-MVP Execution Pack" in adoption_html.text
    assert "세대 민원처리" in adoption_html.text

    modules = app_client.get("/api/public/modules")
    assert modules.status_code == 200
    modules_body = modules.json()
    assert modules_body["public"] is True
    assert modules_body["main_page"] == "/"
    assert modules_body["console_html"] == "/web/console"
    assert len(modules_body["modules"]) >= 7
    assert any(item.get("id") == "tutorial-simulator" for item in modules_body["modules"])
    assert any(item.get("id") == "household-complaints" for item in modules_body["modules"])

    modules_html = app_client.get("/api/public/modules", headers={"Accept": "text/html"})
    assert modules_html.status_code == 200
    assert modules_html.headers["content-type"].startswith("text/html")
    assert "시설 웹 모듈" in modules_html.text
    assert "운영 콘솔" in modules_html.text
    assert "Tutorial Simulator" in modules_html.text
    assert "세대 민원처리" in modules_html.text

    public_plan = app_client.get("/api/public/adoption-plan")
    assert public_plan.status_code == 200
    body = public_plan.json()
    assert body["public"] is True
    assert body["timeline"]["start_date"] == "2026-03-02"
    assert body["timeline"]["end_date"] == "2026-06-12"
    assert len(body["weekly_execution"]) == 15
    assert body["workflow_lock_matrix"]["states"] == ["DRAFT", "REVIEW", "APPROVED", "LOCKED"]
    assert len(body["workflow_lock_matrix"]["rows"]) == 4
    assert body["w02_sop_sandbox"]["timeline"]["week"] == 2
    assert len(body["w02_sop_sandbox"]["sop_runbooks"]) >= 5
    assert len(body["w02_sop_sandbox"]["sandbox_scenarios"]) >= 3
    assert len(body["w02_sop_sandbox"]["scheduled_events"]) >= 5
    assert body["w03_go_live_onboarding"]["timeline"]["week"] == 3
    assert len(body["w03_go_live_onboarding"]["kickoff_agenda"]) >= 5
    assert len(body["w03_go_live_onboarding"]["role_workshops"]) >= 4
    assert len(body["w03_go_live_onboarding"]["office_hours"]) >= 5
    assert len(body["w03_go_live_onboarding"]["scheduled_events"]) >= 8
    assert body["w04_first_success_acceleration"]["timeline"]["week"] == 4
    assert len(body["w04_first_success_acceleration"]["coaching_actions"]) >= 6
    assert len(body["w04_first_success_acceleration"]["scheduled_events"]) >= 6
    assert body["w04_first_success_acceleration"]["common_mistakes_reference"] == "/api/public/adoption-plan/w04/common-mistakes"
    assert body["w05_usage_consistency"]["timeline"]["week"] == 5
    assert len(body["w05_usage_consistency"]["role_missions"]) >= 5
    assert len(body["w05_usage_consistency"]["scheduled_events"]) >= 5
    assert len(body["w05_usage_consistency"]["help_docs"]) >= 3
    assert body["w06_operational_rhythm"]["timeline"]["week"] == 6
    assert len(body["w06_operational_rhythm"]["rhythm_checklist"]) >= 4
    assert len(body["w06_operational_rhythm"]["scheduled_events"]) >= 5
    assert len(body["w06_operational_rhythm"]["rbac_audit_checklist"]) >= 4
    assert body["w07_sla_quality"]["timeline"]["week"] == 7
    assert len(body["w07_sla_quality"]["sla_checklist"]) >= 4
    assert len(body["w07_sla_quality"]["coaching_plays"]) >= 4
    assert len(body["w07_sla_quality"]["scheduled_events"]) >= 5
    assert body["w08_report_discipline"]["timeline"]["week"] == 8
    assert len(body["w08_report_discipline"]["report_discipline_checklist"]) >= 4
    assert len(body["w08_report_discipline"]["data_quality_controls"]) >= 4
    assert len(body["w08_report_discipline"]["scheduled_events"]) >= 5
    assert len(body["w08_report_discipline"]["reporting_sop"]) >= 4
    assert body["w09_kpi_operation"]["timeline"]["week"] == 9
    assert len(body["w09_kpi_operation"]["kpi_threshold_matrix"]) >= 5
    assert len(body["w09_kpi_operation"]["escalation_map"]) >= 4
    assert len(body["w09_kpi_operation"]["scheduled_events"]) >= 5
    assert body["w10_self_serve_support"]["timeline"]["week"] == 10
    assert len(body["w10_self_serve_support"]["self_serve_guides"]) >= 5
    assert len(body["w10_self_serve_support"]["troubleshooting_runbook"]) >= 4
    assert len(body["w10_self_serve_support"]["scheduled_events"]) >= 5
    assert body["w11_scale_readiness"]["timeline"]["week"] == 11
    assert len(body["w11_scale_readiness"]["self_serve_guides"]) >= 5
    assert len(body["w11_scale_readiness"]["troubleshooting_runbook"]) >= 4
    assert len(body["w11_scale_readiness"]["scheduled_events"]) >= 5
    assert body["w14_stability_sprint"]["timeline"]["week"] == 14
    assert len(body["w14_stability_sprint"]["self_serve_guides"]) >= 5
    assert len(body["w14_stability_sprint"]["troubleshooting_runbook"]) >= 4
    assert len(body["w14_stability_sprint"]["scheduled_events"]) >= 5
    assert body["w15_operations_efficiency"]["timeline"]["week"] == 15
    assert len(body["w15_operations_efficiency"]["self_serve_guides"]) >= 5
    assert len(body["w15_operations_efficiency"]["troubleshooting_runbook"]) >= 4
    assert len(body["w15_operations_efficiency"]["scheduled_events"]) >= 5
    assert len(body["training_outline"]) >= 8
    assert len(body["kpi_dashboard_items"]) >= 8
    assert "campaign_kit" in body
    assert len(body["campaign_kit"]["promotion"]) >= 3
    assert len(body["campaign_kit"]["education"]) >= 3
    assert len(body["campaign_kit"]["fun"]) >= 3

    campaign_api = app_client.get("/api/public/adoption-plan/campaign")
    assert campaign_api.status_code == 200
    campaign_body = campaign_api.json()
    assert campaign_body["public"] is True
    assert len(campaign_body["campaign_kit"]["promotion"]) >= 3

    schedule_csv = app_client.get("/api/public/adoption-plan/schedule.csv")
    assert schedule_csv.status_code == 200
    assert schedule_csv.headers["content-type"].startswith("text/csv")
    assert "week,start_date,end_date,phase,focus,owner" in schedule_csv.text

    schedule_ics = app_client.get("/api/public/adoption-plan/schedule.ics")
    assert schedule_ics.status_code == 200
    assert schedule_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in schedule_ics.text
    assert "SUMMARY:[W01] Kickoff - Role workflow lock" in schedule_ics.text

    w02 = app_client.get("/api/public/adoption-plan/w02")
    assert w02.status_code == 200
    w02_body = w02.json()
    assert w02_body["public"] is True
    assert w02_body["timeline"]["focus"] == "SOP and sandbox"
    assert len(w02_body["sop_runbooks"]) >= 5
    assert len(w02_body["sandbox_scenarios"]) >= 3
    assert len(w02_body["scheduled_events"]) >= 5

    w02_csv = app_client.get("/api/public/adoption-plan/w02/checklist.csv")
    assert w02_csv.status_code == 200
    assert w02_csv.headers["content-type"].startswith("text/csv")
    assert "section,id,name,owner,target_or_module,trigger_or_objective,checkpoints_or_pass_criteria,duration_min,definition_of_done_or_output" in w02_csv.text
    assert "sop_runbook,SOP-INS-01" in w02_csv.text

    w02_ics = app_client.get("/api/public/adoption-plan/w02/schedule.ics")
    assert w02_ics.status_code == 200
    assert w02_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in w02_ics.text
    assert "SUMMARY:[W02] Kickoff - SOP owner assignment" in w02_ics.text

    w03 = app_client.get("/api/public/adoption-plan/w03")
    assert w03.status_code == 200
    w03_body = w03.json()
    assert w03_body["public"] is True
    assert w03_body["timeline"]["focus"] == "Go-live onboarding"
    assert len(w03_body["kickoff_agenda"]) >= 5
    assert len(w03_body["role_workshops"]) >= 4
    assert len(w03_body["office_hours"]) >= 5
    assert len(w03_body["scheduled_events"]) >= 8

    w03_csv = app_client.get("/api/public/adoption-plan/w03/checklist.csv")
    assert w03_csv.status_code == 200
    assert w03_csv.headers["content-type"].startswith("text/csv")
    assert "section,id,name_or_role,owner_or_trainer,schedule,objective_or_focus,checklist_or_channel,duration_min,expected_output_or_success" in w03_csv.text
    assert "kickoff_agenda,KICKOFF-01" in w03_csv.text

    w03_ics = app_client.get("/api/public/adoption-plan/w03/schedule.ics")
    assert w03_ics.status_code == 200
    assert w03_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in w03_ics.text
    assert "SUMMARY:[W03] Kickoff session (60m)" in w03_ics.text

    w04 = app_client.get("/api/public/adoption-plan/w04")
    assert w04.status_code == 200
    w04_body = w04.json()
    assert w04_body["public"] is True
    assert w04_body["timeline"]["focus"] == "First success acceleration"
    assert len(w04_body["coaching_actions"]) >= 6
    assert len(w04_body["scheduled_events"]) >= 6

    w04_csv = app_client.get("/api/public/adoption-plan/w04/checklist.csv")
    assert w04_csv.status_code == 200
    assert w04_csv.headers["content-type"].startswith("text/csv")
    assert "section,id,champion_role,action,owner,due_hint,objective,evidence_required,quick_fix" in w04_csv.text
    assert "coaching_action,W04-CA-01" in w04_csv.text

    w04_ics = app_client.get("/api/public/adoption-plan/w04/schedule.ics")
    assert w04_ics.status_code == 200
    assert w04_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in w04_ics.text
    assert "SUMMARY:[W04] W04 kickoff - first-success funnel review" in w04_ics.text

    w04_mistakes_json = app_client.get("/api/public/adoption-plan/w04/common-mistakes")
    assert w04_mistakes_json.status_code == 200
    mistakes_body = w04_mistakes_json.json()
    assert mistakes_body["public"] is True
    assert mistakes_body["title"] == "W04 자주 하는 실수와 빠른 해결 가이드"
    assert isinstance(mistakes_body["items"], list)
    assert len(mistakes_body["items"]) >= 5

    w04_mistakes_html = app_client.get("/web/adoption/w04/common-mistakes")
    assert w04_mistakes_html.status_code == 200
    assert w04_mistakes_html.headers["content-type"].startswith("text/html")
    assert "W04 자주 하는 실수와 빠른 해결 가이드" in w04_mistakes_html.text

    w05 = app_client.get("/api/public/adoption-plan/w05")
    assert w05.status_code == 200
    w05_body = w05.json()
    assert w05_body["public"] is True
    assert w05_body["timeline"]["focus"] == "Usage consistency"
    assert len(w05_body["role_missions"]) >= 5
    assert len(w05_body["scheduled_events"]) >= 5
    assert len(w05_body["help_docs"]) >= 3
    assert w05_body["usage_consistency_api"] == "/api/ops/adoption/w05/consistency"

    w05_csv = app_client.get("/api/public/adoption-plan/w05/missions.csv")
    assert w05_csv.status_code == 200
    assert w05_csv.headers["content-type"].startswith("text/csv")
    assert "section,id,role,mission,weekly_target,owner,evidence_required,evidence_hint" in w05_csv.text
    assert "role_mission,W05-M-01" in w05_csv.text

    w05_ics = app_client.get("/api/public/adoption-plan/w05/schedule.ics")
    assert w05_ics.status_code == 200
    assert w05_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in w05_ics.text
    assert "SUMMARY:[W05] W05 kickoff - weekly mission board launch" in w05_ics.text

    w05_help_docs = app_client.get("/api/public/adoption-plan/w05/help-docs")
    assert w05_help_docs.status_code == 200
    assert w05_help_docs.json()["public"] is True
    assert len(w05_help_docs.json()["items"]) >= 3

    w06 = app_client.get("/api/public/adoption-plan/w06")
    assert w06.status_code == 200
    w06_body = w06.json()
    assert w06_body["public"] is True
    assert w06_body["timeline"]["focus"] == "Operational rhythm"
    assert len(w06_body["rhythm_checklist"]) >= 4
    assert len(w06_body["scheduled_events"]) >= 5
    assert len(w06_body["rbac_audit_checklist"]) >= 4
    assert w06_body["rhythm_api"] == "/api/ops/adoption/w06/rhythm"

    w06_csv = app_client.get("/api/public/adoption-plan/w06/checklist.csv")
    assert w06_csv.status_code == 200
    assert w06_csv.headers["content-type"].startswith("text/csv")
    assert "section,id,day_or_control,routine_or_objective,owner_or_api_ref,definition_of_done_or_pass_criteria,evidence_hint" in w06_csv.text
    assert "rhythm_checklist,W06-RC-01" in w06_csv.text

    w06_ics = app_client.get("/api/public/adoption-plan/w06/schedule.ics")
    assert w06_ics.status_code == 200
    assert w06_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in w06_ics.text
    assert "SUMMARY:[W06] W06 kickoff - operational rhythm launch" in w06_ics.text

    w06_rbac = app_client.get("/api/public/adoption-plan/w06/rbac-audit-template")
    assert w06_rbac.status_code == 200
    assert w06_rbac.json()["public"] is True
    assert len(w06_rbac.json()["items"]) >= 4

    w07 = app_client.get("/api/public/adoption-plan/w07")
    assert w07.status_code == 200
    w07_body = w07.json()
    assert w07_body["public"] is True
    assert w07_body["timeline"]["focus"] == "SLA quality"
    assert len(w07_body["sla_checklist"]) >= 4
    assert len(w07_body["coaching_plays"]) >= 4
    assert len(w07_body["scheduled_events"]) >= 5
    assert w07_body["sla_quality_api"] == "/api/ops/adoption/w07/sla-quality"

    w07_csv = app_client.get("/api/public/adoption-plan/w07/checklist.csv")
    assert w07_csv.status_code == 200
    assert w07_csv.headers["content-type"].startswith("text/csv")
    assert (
        "section,id,cadence_or_trigger,control_or_play,owner,target_or_expected_impact,definition_of_done_or_evidence,api_ref"
        in w07_csv.text
    )
    assert "sla_checklist,W07-SLA-01" in w07_csv.text

    w07_ics = app_client.get("/api/public/adoption-plan/w07/schedule.ics")
    assert w07_ics.status_code == 200
    assert w07_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in w07_ics.text
    assert "SUMMARY:[W07] W07 kickoff - SLA quality baseline" in w07_ics.text

    w07_playbook = app_client.get("/api/public/adoption-plan/w07/coaching-playbook")
    assert w07_playbook.status_code == 200
    assert w07_playbook.json()["public"] is True
    assert len(w07_playbook.json()["items"]) >= 4

    w08 = app_client.get("/api/public/adoption-plan/w08")
    assert w08.status_code == 200
    w08_body = w08.json()
    assert w08_body["public"] is True
    assert w08_body["timeline"]["focus"] == "Report discipline"
    assert len(w08_body["report_discipline_checklist"]) >= 4
    assert len(w08_body["data_quality_controls"]) >= 4
    assert len(w08_body["scheduled_events"]) >= 5
    assert len(w08_body["reporting_sop"]) >= 4
    assert w08_body["report_discipline_api"] == "/api/ops/adoption/w08/report-discipline"
    assert w08_body["site_benchmark_api"] == "/api/ops/adoption/w08/site-benchmark"

    w08_csv = app_client.get("/api/public/adoption-plan/w08/checklist.csv")
    assert w08_csv.status_code == 200
    assert w08_csv.headers["content-type"].startswith("text/csv")
    assert (
        "section,id,cadence_or_control,discipline_or_objective,owner_or_api_ref,target_or_pass_criteria,definition_of_done_or_evidence,api_ref"
        in w08_csv.text
    )
    assert "report_discipline,W08-RD-01" in w08_csv.text

    w08_ics = app_client.get("/api/public/adoption-plan/w08/schedule.ics")
    assert w08_ics.status_code == 200
    assert w08_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in w08_ics.text
    assert "SUMMARY:[W08] W08 kickoff - report discipline baseline" in w08_ics.text

    w08_sop = app_client.get("/api/public/adoption-plan/w08/reporting-sop")
    assert w08_sop.status_code == 200
    assert w08_sop.json()["public"] is True
    assert len(w08_sop.json()["items"]) >= 4

    w09 = app_client.get("/api/public/adoption-plan/w09")
    assert w09.status_code == 200
    w09_body = w09.json()
    assert w09_body["public"] is True
    assert w09_body["timeline"]["week"] == 9
    assert "kpi operation" in w09_body["timeline"]["focus"].lower()
    assert len(w09_body["kpi_threshold_matrix"]) >= 5
    assert len(w09_body["escalation_map"]) >= 4
    assert len(w09_body["scheduled_events"]) >= 5
    assert w09_body["kpi_operation_api"] == "/api/ops/adoption/w09/kpi-operation"
    assert w09_body["kpi_policy_api"] == "/api/ops/adoption/w09/kpi-policy"
    assert w09_body["tracker_items_api"] == "/api/adoption/w09/tracker/items"

    w09_csv = app_client.get("/api/public/adoption-plan/w09/checklist.csv")
    assert w09_csv.status_code == 200
    assert w09_csv.headers["content-type"].startswith("text/csv")
    assert (
        "section,id,kpi_or_event_key,name_or_title,owner_or_escalate_to,direction_or_condition,green_or_sla_hours,yellow_or_action,target_or_output,source_or_time"
        in w09_csv.text
    )
    assert "kpi_threshold,W09-KPI-01" in w09_csv.text

    w09_ics = app_client.get("/api/public/adoption-plan/w09/schedule.ics")
    assert w09_ics.status_code == 200
    assert w09_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in w09_ics.text
    assert "SUMMARY:[W09] W09 kickoff - KPI ownership lock" in w09_ics.text

    w10 = app_client.get("/api/public/adoption-plan/w10")
    assert w10.status_code == 200
    w10_body = w10.json()
    assert w10_body["public"] is True
    assert w10_body["timeline"]["week"] == 10
    assert "self-serve support" in w10_body["timeline"]["focus"].lower()
    assert len(w10_body["self_serve_guides"]) >= 5
    assert len(w10_body["troubleshooting_runbook"]) >= 4
    assert len(w10_body["scheduled_events"]) >= 5
    assert w10_body["self_serve_api"] == "/api/ops/adoption/w10/self-serve"
    assert w10_body["support_policy_api"] == "/api/ops/adoption/w10/support-policy"
    assert w10_body["tracker_items_api"] == "/api/adoption/w10/tracker/items"

    w10_csv = app_client.get("/api/public/adoption-plan/w10/checklist.csv")
    assert w10_csv.status_code == 200
    assert w10_csv.headers["content-type"].startswith("text/csv")
    assert (
        "section,id,key_or_module,name_or_symptom,owner_role,objective_or_target,definition_or_output,api_or_time"
        in w10_csv.text
    )
    assert "self_serve_guide,W10-SS-01" in w10_csv.text

    w10_ics = app_client.get("/api/public/adoption-plan/w10/schedule.ics")
    assert w10_ics.status_code == 200
    assert w10_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in w10_ics.text
    assert "SUMMARY:[W10] W10 kickoff - self-serve baseline" in w10_ics.text

    w11 = app_client.get("/api/public/adoption-plan/w11")
    assert w11.status_code == 200
    w11_body = w11.json()
    assert w11_body["public"] is True
    assert w11_body["timeline"]["week"] == 11
    assert "scale readiness" in w11_body["timeline"]["focus"].lower()
    assert len(w11_body["self_serve_guides"]) >= 5
    assert len(w11_body["troubleshooting_runbook"]) >= 4
    assert len(w11_body["scheduled_events"]) >= 5
    assert w11_body["scale_readiness_api"] == "/api/ops/adoption/w11/scale-readiness"
    assert w11_body["readiness_policy_api"] == "/api/ops/adoption/w11/readiness-policy"
    assert w11_body["tracker_items_api"] == "/api/adoption/w11/tracker/items"

    w11_csv = app_client.get("/api/public/adoption-plan/w11/checklist.csv")
    assert w11_csv.status_code == 200
    assert w11_csv.headers["content-type"].startswith("text/csv")
    assert (
        "section,id,key_or_module,name_or_symptom,owner_role,objective_or_target,definition_or_output,api_or_time"
        in w11_csv.text
    )
    assert "self_serve_guide,W11-SR-01" in w11_csv.text

    w11_ics = app_client.get("/api/public/adoption-plan/w11/schedule.ics")
    assert w11_ics.status_code == 200
    assert w11_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in w11_ics.text
    assert "SUMMARY:[W11] W11 kickoff - scale readiness baseline" in w11_ics.text

    w02_sample_files = app_client.get("/api/public/adoption-plan/w02/sample-files")
    assert w02_sample_files.status_code == 200
    w02_sample_body = w02_sample_files.json()
    assert w02_sample_body["public"] is True
    assert w02_sample_body["count"] >= 3
    assert len(w02_sample_body["items"]) >= 3
    first_sample = w02_sample_body["items"][0]
    assert first_sample["download_url"].startswith("/api/public/adoption-plan/w02/sample-files/")

    sample_download = app_client.get(first_sample["download_url"])
    assert sample_download.status_code == 200
    assert sample_download.headers["content-type"].startswith("text/plain")
    assert "W02 Sample Evidence" in sample_download.text

    post_mvp = app_client.get("/api/public/post-mvp")
    assert post_mvp.status_code == 200
    post_body = post_mvp.json()
    assert post_body["public"] is True
    assert post_body["timeline"]["start_date"] == "2026-06-01"
    assert post_body["timeline"]["end_date"] == "2026-11-27"
    assert len(post_body["roadmap"]) >= 4
    assert len(post_body["execution_backlog"]) >= 10

    post_backlog_csv = app_client.get("/api/public/post-mvp/backlog.csv")
    assert post_backlog_csv.status_code == 200
    assert post_backlog_csv.headers["content-type"].startswith("text/csv")
    assert "id,epic,item,priority,owner,estimate_points,target_release,status,success_kpi" in post_backlog_csv.text
    assert "PMVP-01" in post_backlog_csv.text

    post_release_ics = app_client.get("/api/public/post-mvp/releases.ics")
    assert post_release_ics.status_code == 200
    assert post_release_ics.headers["content-type"].startswith("text/calendar")
    assert "BEGIN:VCALENDAR" in post_release_ics.text
    assert "SUMMARY:[Post-MVP] R1 - Operations Stability" in post_release_ics.text

    post_kpis = app_client.get("/api/public/post-mvp/kpi-dashboard")
    assert post_kpis.status_code == 200
    assert len(post_kpis.json()["kpi_dashboard_spec"]) >= 8

    post_risks = app_client.get("/api/public/post-mvp/risks")
    assert post_risks.status_code == 200
    assert len(post_risks.json()["risk_register"]) >= 8

    post_mvp_html = app_client.get("/api/public/post-mvp", headers={"Accept": "text/html"})
    assert post_mvp_html.status_code == 200
    assert post_mvp_html.headers["content-type"].startswith("text/html")
    assert "API 브라우저 보기" in post_mvp_html.text
    assert "원본 JSON" in post_mvp_html.text

    post_mvp_raw = app_client.get("/api/public/post-mvp?raw=1", headers={"Accept": "text/html"})
    assert post_mvp_raw.status_code == 200
    assert post_mvp_raw.headers["content-type"].startswith("application/json")
    assert post_mvp_raw.json()["public"] is True

def test_w13_public_and_tracker_flow(app_client: TestClient) -> None:
    headers = _owner_headers()

    public_pack = app_client.get("/api/public/adoption-plan/w13")
    assert public_pack.status_code == 200
    assert public_pack.json()["title"] == "W13 Continuous Improvement Pack"

    checklist = app_client.get("/api/public/adoption-plan/w13/checklist.csv")
    assert checklist.status_code == 200
    assert checklist.headers.get("content-type", "").startswith("text/csv")

    schedule = app_client.get("/api/public/adoption-plan/w13/schedule.ics")
    assert schedule.status_code == 200
    assert schedule.headers.get("content-type", "").startswith("text/calendar")

    bootstrap = app_client.post("/api/adoption/w13/tracker/bootstrap", json={"site": "HQ"}, headers=headers)
    assert bootstrap.status_code == 200
    assert bootstrap.json()["site"] == "HQ"
    assert bootstrap.json()["total_count"] >= 1

    overview = app_client.get("/api/adoption/w13/tracker/overview", params={"site": "HQ"}, headers=headers)
    assert overview.status_code == 200
    assert overview.json()["site"] == "HQ"
    assert overview.json()["total_items"] >= 1

    snapshot = app_client.get("/api/ops/adoption/w13/closure-handoff", params={"site": "HQ"}, headers=headers)
    assert snapshot.status_code == 200
    assert snapshot.json()["site"] == "HQ"
    assert "metrics" in snapshot.json()

def test_w14_public_and_tracker_flow(app_client: TestClient) -> None:
    headers = _owner_headers()

    public_pack = app_client.get("/api/public/adoption-plan/w14")
    assert public_pack.status_code == 200
    assert public_pack.json()["title"] == "W14 Stability Sprint Pack"

    checklist = app_client.get("/api/public/adoption-plan/w14/checklist.csv")
    assert checklist.status_code == 200
    assert checklist.headers.get("content-type", "").startswith("text/csv")

    schedule = app_client.get("/api/public/adoption-plan/w14/schedule.ics")
    assert schedule.status_code == 200
    assert schedule.headers.get("content-type", "").startswith("text/calendar")

    bootstrap = app_client.post("/api/adoption/w14/tracker/bootstrap", json={"site": "HQ"}, headers=headers)
    assert bootstrap.status_code == 200
    assert bootstrap.json()["site"] == "HQ"
    assert bootstrap.json()["total_count"] >= 1

    overview = app_client.get("/api/adoption/w14/tracker/overview", params={"site": "HQ"}, headers=headers)
    assert overview.status_code == 200
    assert overview.json()["site"] == "HQ"
    assert overview.json()["total_items"] >= 1

    snapshot = app_client.get("/api/ops/adoption/w14/stability-sprint", params={"site": "HQ"}, headers=headers)
    assert snapshot.status_code == 200
    assert snapshot.json()["site"] == "HQ"
    assert "metrics" in snapshot.json()

def test_w15_public_and_tracker_flow(app_client: TestClient) -> None:
    headers = _owner_headers()

    public_pack = app_client.get("/api/public/adoption-plan/w15")
    assert public_pack.status_code == 200
    assert public_pack.json()["title"] == "W15 Operations Efficiency Pack"

    checklist = app_client.get("/api/public/adoption-plan/w15/checklist.csv")
    assert checklist.status_code == 200
    assert checklist.headers.get("content-type", "").startswith("text/csv")

    schedule = app_client.get("/api/public/adoption-plan/w15/schedule.ics")
    assert schedule.status_code == 200
    assert schedule.headers.get("content-type", "").startswith("text/calendar")

    bootstrap = app_client.post("/api/adoption/w15/tracker/bootstrap", json={"site": "HQ"}, headers=headers)
    assert bootstrap.status_code == 200
    assert bootstrap.json()["site"] == "HQ"
    assert bootstrap.json()["total_count"] >= 1

    overview = app_client.get("/api/adoption/w15/tracker/overview", params={"site": "HQ"}, headers=headers)
    assert overview.status_code == 200
    assert overview.json()["site"] == "HQ"
    assert overview.json()["total_items"] >= 1

    snapshot = app_client.get("/api/ops/adoption/w15/ops-efficiency", params={"site": "HQ"}, headers=headers)
    assert snapshot.status_code == 200
    assert snapshot.json()["site"] == "HQ"
    assert "metrics" in snapshot.json()

    policy = app_client.get("/api/ops/adoption/w15/efficiency-policy", params={"site": "HQ"}, headers=headers)
    assert policy.status_code == 200
    assert policy.json()["site"] == "HQ"
    assert policy.json()["policy_key"].startswith("adoption_w15_efficiency_policy:site:")

def test_w09_to_w15_policy_response_schema_standardized(app_client: TestClient) -> None:
    headers = _owner_headers()
    site = "HQ"
    cases = [
        ("w09", "kpi-policy", "/api/ops/adoption/w09/kpi-policy", "adoption_w09_kpi_policy:site:"),
        ("w10", "support-policy", "/api/ops/adoption/w10/support-policy", "adoption_w10_support_policy:site:"),
        ("w11", "readiness-policy", "/api/ops/adoption/w11/readiness-policy", "adoption_w11_readiness_policy:site:"),
        ("w12", "handoff-policy", "/api/ops/adoption/w12/handoff-policy", "adoption_w12_handoff_policy:site:"),
        ("w13", "handoff-policy", "/api/ops/adoption/w13/handoff-policy", "adoption_w13_handoff_policy:site:"),
        ("w14", "stability-policy", "/api/ops/adoption/w14/stability-policy", "adoption_w14_stability_policy:site:"),
        ("w15", "efficiency-policy", "/api/ops/adoption/w15/efficiency-policy", "adoption_w15_efficiency_policy:site:"),
    ]
    for phase, policy_kind, path, key_prefix in cases:
        read_resp = app_client.get(path, params={"site": site}, headers=headers)
        assert read_resp.status_code == 200
        read_body = read_resp.json()
        _assert_adoption_policy_response_shape(
            read_body,
            phase=phase,
            policy_kind=policy_kind,
            endpoint=path,
            site=site,
            policy_key_prefix=key_prefix,
        )

        write_resp = app_client.put(path, params={"site": site}, headers=headers, json={"enabled": True})
        assert write_resp.status_code == 200
        write_body = write_resp.json()
        _assert_adoption_policy_response_shape(
            write_body,
            phase=phase,
            policy_kind=policy_kind,
            endpoint=path,
            site=site,
            policy_key_prefix=key_prefix,
        )
        assert write_body["policy"] == read_body["policy"] or isinstance(write_body["policy"], dict)

def test_w02_tracker_execution_flow(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w02_manager_ci",
            "display_name": "W02 Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W02 Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w02-manager-token"},
    )
    assert issued.status_code == 201
    manager_headers = {"X-Admin-Token": issued.json()["token"]}

    bootstrap = app_client.post(
        "/api/adoption/w02/tracker/bootstrap",
        headers=manager_headers,
        json={"site": "W02 Site"},
    )
    assert bootstrap.status_code == 200
    bootstrap_body = bootstrap.json()
    assert bootstrap_body["site"] == "W02 Site"
    assert bootstrap_body["total_count"] >= 10

    overview = app_client.get(
        "/api/adoption/w02/tracker/overview?site=W02+Site",
        headers=manager_headers,
    )
    assert overview.status_code == 200
    overview_body = overview.json()
    assert overview_body["site"] == "W02 Site"
    assert overview_body["total_items"] >= 10
    assert overview_body["done_count"] == 0

    listed = app_client.get(
        "/api/adoption/w02/tracker/items?site=W02+Site&limit=500",
        headers=manager_headers,
    )
    assert listed.status_code == 200
    items = listed.json()
    assert len(items) >= 10
    tracker_item_id = items[0]["id"]

    updated = app_client.patch(
        f"/api/adoption/w02/tracker/items/{tracker_item_id}",
        headers=manager_headers,
        json={
            "assignee": "Ops QA",
            "status": "done",
            "completion_checked": True,
            "completion_note": "W02 checklist done",
        },
    )
    assert updated.status_code == 200
    updated_body = updated.json()
    assert updated_body["assignee"] == "Ops QA"
    assert updated_body["status"] == "done"
    assert updated_body["completion_checked"] is True
    assert updated_body["completed_at"] is not None

    blocked_upload = app_client.post(
        f"/api/adoption/w02/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
        data={"note": "blocked content type"},
        files={"file": ("poc.html", b"<script>alert(1)</script>", "text/html")},
    )
    assert blocked_upload.status_code == 415

    uploaded = app_client.post(
        f"/api/adoption/w02/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
        data={"note": "proof text"},
        files={"file": ("proof.txt", b"w02 evidence", "text/plain")},
    )
    assert uploaded.status_code == 201
    evidence = uploaded.json()
    evidence_id = evidence["id"]
    assert evidence["tracker_item_id"] == tracker_item_id
    assert evidence["file_name"] == "proof.txt"
    assert evidence["file_size"] == 12
    assert evidence["storage_backend"] in {"fs", "db"}
    assert len(evidence["sha256"]) == 64
    assert evidence["malware_scan_status"] in {"clean", "skipped", "suspicious"}

    evidence_list = app_client.get(
        f"/api/adoption/w02/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
    )
    assert evidence_list.status_code == 200
    assert len(evidence_list.json()) >= 1

    downloaded = app_client.get(
        f"/api/adoption/w02/tracker/evidence/{evidence_id}/download",
        headers=manager_headers,
    )
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"].startswith("text/plain")
    assert downloaded.content == b"w02 evidence"
    assert len(downloaded.headers["x-evidence-sha256"]) == 64

    import app.main as main_module

    sample_uploaded = app_client.post(
        f"/api/adoption/w02/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
        data={"note": "sample proof"},
        files={
            "file": (
                "w02-sample-sx-ins-01-proof.txt",
                main_module.W02_SAMPLE_EVIDENCE_ARTIFACTS[0]["content"].encode("utf-8"),
                "text/plain",
            )
        },
    )
    assert sample_uploaded.status_code == 201
    sample_evidence_id = sample_uploaded.json()["id"]

    with main_module.get_conn() as conn:
        row = conn.execute(
            select(main_module.adoption_w02_evidence_files).where(
                main_module.adoption_w02_evidence_files.c.id == sample_evidence_id
            )
        ).mappings().first()
    assert row is not None
    assert str(row.get("storage_backend")) == "fs"
    storage_path = main_module._resolve_evidence_storage_abs_path(str(row.get("storage_key") or ""))
    assert storage_path is not None and storage_path.exists()
    storage_path.unlink()
    assert storage_path.exists() is False

    recovered_download = app_client.get(
        f"/api/adoption/w02/tracker/evidence/{sample_evidence_id}/download",
        headers=manager_headers,
    )
    assert recovered_download.status_code == 200
    assert recovered_download.content == main_module.W02_SAMPLE_EVIDENCE_ARTIFACTS[0]["content"].encode("utf-8")
    assert storage_path.exists() is True

    eicar_signature = (
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
        b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    blocked_malware = app_client.post(
        f"/api/adoption/w02/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
        data={"note": "eicar"},
        files={"file": ("eicar.txt", eicar_signature, "text/plain")},
    )
    assert blocked_malware.status_code == 422

    readiness_before = app_client.get(
        "/api/adoption/w02/tracker/readiness?site=W02+Site",
        headers=manager_headers,
    )
    assert readiness_before.status_code == 200
    assert readiness_before.json()["ready"] is False
    assert readiness_before.json()["pending_count"] >= 1

    completion_before = app_client.get(
        "/api/adoption/w02/tracker/completion?site=W02+Site",
        headers=manager_headers,
    )
    assert completion_before.status_code == 200
    assert completion_before.json()["status"] == "active"
    assert completion_before.json()["readiness"]["ready"] is False

    complete_gate_fail = app_client.post(
        "/api/adoption/w02/tracker/complete",
        headers=manager_headers,
        json={"site": "W02 Site", "completion_note": "attempt normal close"},
    )
    assert complete_gate_fail.status_code == 409

    complete_force_denied = app_client.post(
        "/api/adoption/w02/tracker/complete",
        headers=manager_headers,
        json={"site": "W02 Site", "completion_note": "attempt force close", "force": True},
    )
    assert complete_force_denied.status_code == 403

    complete_force_owner = app_client.post(
        "/api/adoption/w02/tracker/complete",
        headers=_owner_headers(),
        json={"site": "W02 Site", "completion_note": "owner force close", "force": True},
    )
    assert complete_force_owner.status_code == 200
    assert complete_force_owner.json()["status"] == "completed_with_exceptions"
    assert complete_force_owner.json()["force_used"] is True

    completion_after_force = app_client.get(
        "/api/adoption/w02/tracker/completion?site=W02+Site",
        headers=manager_headers,
    )
    assert completion_after_force.status_code == 200
    assert completion_after_force.json()["status"] == "completed_with_exceptions"

    reopen_after_update = app_client.patch(
        f"/api/adoption/w02/tracker/items/{tracker_item_id}",
        headers=manager_headers,
        json={"status": "in_progress", "completion_checked": False, "completion_note": "re-opened"},
    )
    assert reopen_after_update.status_code == 200
    completion_after_reopen = app_client.get(
        "/api/adoption/w02/tracker/completion?site=W02+Site",
        headers=manager_headers,
    )
    assert completion_after_reopen.status_code == 200
    assert completion_after_reopen.json()["status"] == "active"

    listed_all = app_client.get(
        "/api/adoption/w02/tracker/items?site=W02+Site&limit=500",
        headers=manager_headers,
    )
    assert listed_all.status_code == 200
    all_items = listed_all.json()
    sandbox_item_ids: list[int] = []
    for item in all_items:
        item_id = int(item["id"])
        if item["item_type"] == "sandbox_scenario":
            sandbox_item_ids.append(item_id)
        done_update = app_client.patch(
            f"/api/adoption/w02/tracker/items/{item_id}",
            headers=manager_headers,
            json={
                "assignee": item.get("assignee") or "Ops QA",
                "status": "done",
                "completion_checked": True,
                "completion_note": "W02 finalized",
            },
        )
        assert done_update.status_code == 200

    for sandbox_item_id in sandbox_item_ids:
        sandbox_evidence_list = app_client.get(
            f"/api/adoption/w02/tracker/items/{sandbox_item_id}/evidence",
            headers=manager_headers,
        )
        assert sandbox_evidence_list.status_code == 200
        if len(sandbox_evidence_list.json()) == 0:
            sandbox_upload = app_client.post(
                f"/api/adoption/w02/tracker/items/{sandbox_item_id}/evidence",
                headers=manager_headers,
                data={"note": "sandbox proof"},
                files={
                    "file": (
                        f"sandbox-{sandbox_item_id}.txt",
                        f"sandbox evidence {sandbox_item_id}".encode("utf-8"),
                        "text/plain",
                    )
                },
            )
            assert sandbox_upload.status_code == 201

    readiness_after = app_client.get(
        "/api/adoption/w02/tracker/readiness?site=W02+Site",
        headers=manager_headers,
    )
    assert readiness_after.status_code == 200
    readiness_after_body = readiness_after.json()
    assert readiness_after_body["ready"] is True
    assert readiness_after_body["pending_count"] == 0
    assert readiness_after_body["in_progress_count"] == 0
    assert readiness_after_body["blocked_count"] == 0
    assert readiness_after_body["missing_assignee_count"] == 0
    assert readiness_after_body["missing_completion_checked_count"] == 0
    assert readiness_after_body["missing_required_evidence_count"] == 0
    assert readiness_after_body["readiness_score_percent"] == 100

    completed = app_client.post(
        "/api/adoption/w02/tracker/complete",
        headers=manager_headers,
        json={"site": "W02 Site", "completion_note": "W02 complete and signed"},
    )
    assert completed.status_code == 200
    completed_body = completed.json()
    assert completed_body["status"] == "completed"
    assert completed_body["force_used"] is False
    assert completed_body["readiness"]["ready"] is True
    assert completed_body["completed_at"] is not None

    completion_after = app_client.get(
        "/api/adoption/w02/tracker/completion?site=W02+Site",
        headers=manager_headers,
    )
    assert completion_after.status_code == 200
    assert completion_after.json()["status"] == "completed"
    assert completion_after.json()["readiness"]["ready"] is True

    owner_seed_other_site = app_client.post(
        "/api/adoption/w02/tracker/bootstrap",
        headers=_owner_headers(),
        json={"site": "Outside Site"},
    )
    assert owner_seed_other_site.status_code == 200

    forbidden_other_site = app_client.get(
        "/api/adoption/w02/tracker/overview?site=Outside+Site",
        headers=manager_headers,
    )
    assert forbidden_other_site.status_code == 403

def test_w03_tracker_execution_flow(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w03_manager_ci",
            "display_name": "W03 Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W03 Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w03-manager-token"},
    )
    assert issued.status_code == 201
    manager_headers = {"X-Admin-Token": issued.json()["token"]}

    bootstrap = app_client.post(
        "/api/adoption/w03/tracker/bootstrap",
        headers=manager_headers,
        json={"site": "W03 Site"},
    )
    assert bootstrap.status_code == 200
    bootstrap_body = bootstrap.json()
    assert bootstrap_body["site"] == "W03 Site"
    assert bootstrap_body["total_count"] >= 15

    overview = app_client.get(
        "/api/adoption/w03/tracker/overview?site=W03+Site",
        headers=manager_headers,
    )
    assert overview.status_code == 200
    overview_body = overview.json()
    assert overview_body["site"] == "W03 Site"
    assert overview_body["total_items"] >= 15
    assert overview_body["done_count"] == 0

    listed = app_client.get(
        "/api/adoption/w03/tracker/items?site=W03+Site&limit=500",
        headers=manager_headers,
    )
    assert listed.status_code == 200
    items = listed.json()
    assert len(items) >= 15
    tracker_item_id = items[0]["id"]

    updated = app_client.patch(
        f"/api/adoption/w03/tracker/items/{tracker_item_id}",
        headers=manager_headers,
        json={
            "assignee": "Ops Trainer",
            "status": "done",
            "completion_checked": True,
            "completion_note": "W03 kickoff done",
        },
    )
    assert updated.status_code == 200
    updated_body = updated.json()
    assert updated_body["assignee"] == "Ops Trainer"
    assert updated_body["status"] == "done"
    assert updated_body["completion_checked"] is True
    assert updated_body["completed_at"] is not None

    blocked_upload = app_client.post(
        f"/api/adoption/w03/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
        data={"note": "blocked content type"},
        files={"file": ("poc.html", b"<script>alert(1)</script>", "text/html")},
    )
    assert blocked_upload.status_code == 415

    uploaded = app_client.post(
        f"/api/adoption/w03/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
        data={"note": "proof text"},
        files={"file": ("proof-w03.txt", b"w03 evidence", "text/plain")},
    )
    assert uploaded.status_code == 201
    evidence = uploaded.json()
    evidence_id = evidence["id"]
    assert evidence["tracker_item_id"] == tracker_item_id
    assert evidence["file_name"] == "proof-w03.txt"
    assert evidence["storage_backend"] in {"fs", "db"}
    assert len(evidence["sha256"]) == 64
    assert evidence["malware_scan_status"] in {"clean", "skipped", "suspicious"}

    downloaded = app_client.get(
        f"/api/adoption/w03/tracker/evidence/{evidence_id}/download",
        headers=manager_headers,
    )
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"].startswith("text/plain")
    assert downloaded.content == b"w03 evidence"
    assert len(downloaded.headers["x-evidence-sha256"]) == 64

    readiness_before = app_client.get(
        "/api/adoption/w03/tracker/readiness?site=W03+Site",
        headers=manager_headers,
    )
    assert readiness_before.status_code == 200
    assert readiness_before.json()["ready"] is False
    assert readiness_before.json()["pending_count"] >= 1

    completion_before = app_client.get(
        "/api/adoption/w03/tracker/completion?site=W03+Site",
        headers=manager_headers,
    )
    assert completion_before.status_code == 200
    assert completion_before.json()["status"] == "active"
    assert completion_before.json()["readiness"]["ready"] is False

    complete_gate_fail = app_client.post(
        "/api/adoption/w03/tracker/complete",
        headers=manager_headers,
        json={"site": "W03 Site", "completion_note": "attempt normal close"},
    )
    assert complete_gate_fail.status_code == 409

    complete_force_denied = app_client.post(
        "/api/adoption/w03/tracker/complete",
        headers=manager_headers,
        json={"site": "W03 Site", "completion_note": "attempt force close", "force": True},
    )
    assert complete_force_denied.status_code == 403

    complete_force_owner = app_client.post(
        "/api/adoption/w03/tracker/complete",
        headers=_owner_headers(),
        json={"site": "W03 Site", "completion_note": "owner force close", "force": True},
    )
    assert complete_force_owner.status_code == 200
    assert complete_force_owner.json()["status"] == "completed_with_exceptions"
    assert complete_force_owner.json()["force_used"] is True

    completion_after_force = app_client.get(
        "/api/adoption/w03/tracker/completion?site=W03+Site",
        headers=manager_headers,
    )
    assert completion_after_force.status_code == 200
    assert completion_after_force.json()["status"] == "completed_with_exceptions"

    reopen_after_update = app_client.patch(
        f"/api/adoption/w03/tracker/items/{tracker_item_id}",
        headers=manager_headers,
        json={"status": "in_progress", "completion_checked": False, "completion_note": "re-opened"},
    )
    assert reopen_after_update.status_code == 200
    completion_after_reopen = app_client.get(
        "/api/adoption/w03/tracker/completion?site=W03+Site",
        headers=manager_headers,
    )
    assert completion_after_reopen.status_code == 200
    assert completion_after_reopen.json()["status"] == "active"

    listed_all = app_client.get(
        "/api/adoption/w03/tracker/items?site=W03+Site&limit=500",
        headers=manager_headers,
    )
    assert listed_all.status_code == 200
    all_items = listed_all.json()
    workshop_item_ids: list[int] = []
    for item in all_items:
        item_id = int(item["id"])
        if item["item_type"] == "role_workshop":
            workshop_item_ids.append(item_id)
        done_update = app_client.patch(
            f"/api/adoption/w03/tracker/items/{item_id}",
            headers=manager_headers,
            json={
                "assignee": item.get("assignee") or "Ops Trainer",
                "status": "done",
                "completion_checked": True,
                "completion_note": "W03 finalized",
            },
        )
        assert done_update.status_code == 200

    for workshop_item_id in workshop_item_ids:
        workshop_evidence_list = app_client.get(
            f"/api/adoption/w03/tracker/items/{workshop_item_id}/evidence",
            headers=manager_headers,
        )
        assert workshop_evidence_list.status_code == 200
        if len(workshop_evidence_list.json()) == 0:
            workshop_upload = app_client.post(
                f"/api/adoption/w03/tracker/items/{workshop_item_id}/evidence",
                headers=manager_headers,
                data={"note": "workshop proof"},
                files={
                    "file": (
                        f"workshop-{workshop_item_id}.txt",
                        f"workshop evidence {workshop_item_id}".encode("utf-8"),
                        "text/plain",
                    )
                },
            )
            assert workshop_upload.status_code == 201

    readiness_after = app_client.get(
        "/api/adoption/w03/tracker/readiness?site=W03+Site",
        headers=manager_headers,
    )
    assert readiness_after.status_code == 200
    readiness_after_body = readiness_after.json()
    assert readiness_after_body["ready"] is True
    assert readiness_after_body["pending_count"] == 0
    assert readiness_after_body["in_progress_count"] == 0
    assert readiness_after_body["blocked_count"] == 0
    assert readiness_after_body["missing_assignee_count"] == 0
    assert readiness_after_body["missing_completion_checked_count"] == 0
    assert readiness_after_body["missing_required_evidence_count"] == 0
    assert readiness_after_body["readiness_score_percent"] == 100

    completed = app_client.post(
        "/api/adoption/w03/tracker/complete",
        headers=manager_headers,
        json={"site": "W03 Site", "completion_note": "W03 complete and signed"},
    )
    assert completed.status_code == 200
    completed_body = completed.json()
    assert completed_body["status"] == "completed"
    assert completed_body["force_used"] is False
    assert completed_body["readiness"]["ready"] is True
    assert completed_body["completed_at"] is not None

    completion_after = app_client.get(
        "/api/adoption/w03/tracker/completion?site=W03+Site",
        headers=manager_headers,
    )
    assert completion_after.status_code == 200
    assert completion_after.json()["status"] == "completed"
    assert completion_after.json()["readiness"]["ready"] is True

    owner_seed_other_site = app_client.post(
        "/api/adoption/w03/tracker/bootstrap",
        headers=_owner_headers(),
        json={"site": "Outside W03 Site"},
    )
    assert owner_seed_other_site.status_code == 200

    forbidden_other_site = app_client.get(
        "/api/adoption/w03/tracker/overview?site=Outside+W03+Site",
        headers=manager_headers,
    )
    assert forbidden_other_site.status_code == 403

def test_w04_tracker_funnel_and_blockers_flow(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w04_manager_ci",
            "display_name": "W04 Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W04 Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w04-manager-token"},
    )
    assert issued.status_code == 201
    manager_headers = {"X-Admin-Token": issued.json()["token"]}

    bootstrap = app_client.post(
        "/api/adoption/w04/tracker/bootstrap",
        headers=manager_headers,
        json={"site": "W04 Site"},
    )
    assert bootstrap.status_code == 200
    bootstrap_body = bootstrap.json()
    assert bootstrap_body["site"] == "W04 Site"
    assert bootstrap_body["total_count"] >= 12

    overview = app_client.get(
        "/api/adoption/w04/tracker/overview?site=W04+Site",
        headers=manager_headers,
    )
    assert overview.status_code == 200
    overview_body = overview.json()
    assert overview_body["site"] == "W04 Site"
    assert overview_body["total_items"] >= 12
    assert overview_body["done_count"] == 0

    listed = app_client.get(
        "/api/adoption/w04/tracker/items?site=W04+Site&limit=500",
        headers=manager_headers,
    )
    assert listed.status_code == 200
    items = listed.json()
    assert len(items) >= 12
    tracker_item_id = items[0]["id"]

    updated = app_client.patch(
        f"/api/adoption/w04/tracker/items/{tracker_item_id}",
        headers=manager_headers,
        json={
            "assignee": "Site Champion",
            "status": "done",
            "completion_checked": True,
            "completion_note": "W04 first action done",
        },
    )
    assert updated.status_code == 200
    updated_body = updated.json()
    assert updated_body["assignee"] == "Site Champion"
    assert updated_body["status"] == "done"
    assert updated_body["completion_checked"] is True
    assert updated_body["completed_at"] is not None

    blocked_upload = app_client.post(
        f"/api/adoption/w04/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
        data={"note": "blocked content type"},
        files={"file": ("poc.html", b"<script>alert(1)</script>", "text/html")},
    )
    assert blocked_upload.status_code == 415

    uploaded = app_client.post(
        f"/api/adoption/w04/tracker/items/{tracker_item_id}/evidence",
        headers=manager_headers,
        data={"note": "proof text"},
        files={"file": ("proof-w04.txt", b"w04 evidence", "text/plain")},
    )
    assert uploaded.status_code == 201
    evidence = uploaded.json()
    evidence_id = evidence["id"]
    assert evidence["tracker_item_id"] == tracker_item_id
    assert evidence["file_name"] == "proof-w04.txt"
    assert evidence["storage_backend"] in {"fs", "db"}
    assert len(evidence["sha256"]) == 64
    assert evidence["malware_scan_status"] in {"clean", "skipped", "suspicious"}

    downloaded = app_client.get(
        f"/api/adoption/w04/tracker/evidence/{evidence_id}/download",
        headers=manager_headers,
    )
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"].startswith("text/plain")
    assert downloaded.content == b"w04 evidence"
    assert len(downloaded.headers["x-evidence-sha256"]) == 64

    readiness_before = app_client.get(
        "/api/adoption/w04/tracker/readiness?site=W04+Site",
        headers=manager_headers,
    )
    assert readiness_before.status_code == 200
    assert readiness_before.json()["ready"] is False
    assert readiness_before.json()["pending_count"] >= 1

    completion_before = app_client.get(
        "/api/adoption/w04/tracker/completion?site=W04+Site",
        headers=manager_headers,
    )
    assert completion_before.status_code == 200
    assert completion_before.json()["status"] == "active"
    assert completion_before.json()["readiness"]["ready"] is False

    complete_gate_fail = app_client.post(
        "/api/adoption/w04/tracker/complete",
        headers=manager_headers,
        json={"site": "W04 Site", "completion_note": "attempt normal close"},
    )
    assert complete_gate_fail.status_code == 409

    complete_force_denied = app_client.post(
        "/api/adoption/w04/tracker/complete",
        headers=manager_headers,
        json={"site": "W04 Site", "completion_note": "attempt force close", "force": True},
    )
    assert complete_force_denied.status_code == 403

    complete_force_owner = app_client.post(
        "/api/adoption/w04/tracker/complete",
        headers=_owner_headers(),
        json={"site": "W04 Site", "completion_note": "owner force close", "force": True},
    )
    assert complete_force_owner.status_code == 200
    assert complete_force_owner.json()["status"] == "completed_with_exceptions"
    assert complete_force_owner.json()["force_used"] is True

    completion_after_force = app_client.get(
        "/api/adoption/w04/tracker/completion?site=W04+Site",
        headers=manager_headers,
    )
    assert completion_after_force.status_code == 200
    assert completion_after_force.json()["status"] == "completed_with_exceptions"

    reopen_after_update = app_client.patch(
        f"/api/adoption/w04/tracker/items/{tracker_item_id}",
        headers=manager_headers,
        json={"status": "in_progress", "completion_checked": False, "completion_note": "re-opened"},
    )
    assert reopen_after_update.status_code == 200
    completion_after_reopen = app_client.get(
        "/api/adoption/w04/tracker/completion?site=W04+Site",
        headers=manager_headers,
    )
    assert completion_after_reopen.status_code == 200
    assert completion_after_reopen.json()["status"] == "active"

    listed_all = app_client.get(
        "/api/adoption/w04/tracker/items?site=W04+Site&limit=500",
        headers=manager_headers,
    )
    assert listed_all.status_code == 200
    all_items = listed_all.json()
    coaching_item_ids: list[int] = []
    for item in all_items:
        item_id = int(item["id"])
        if item["item_type"] == "coaching_action":
            coaching_item_ids.append(item_id)
        done_update = app_client.patch(
            f"/api/adoption/w04/tracker/items/{item_id}",
            headers=manager_headers,
            json={
                "assignee": item.get("assignee") or "Site Champion",
                "status": "done",
                "completion_checked": True,
                "completion_note": "W04 finalized",
            },
        )
        assert done_update.status_code == 200

    for coaching_item_id in coaching_item_ids:
        coaching_evidence_list = app_client.get(
            f"/api/adoption/w04/tracker/items/{coaching_item_id}/evidence",
            headers=manager_headers,
        )
        assert coaching_evidence_list.status_code == 200
        if len(coaching_evidence_list.json()) == 0:
            coaching_upload = app_client.post(
                f"/api/adoption/w04/tracker/items/{coaching_item_id}/evidence",
                headers=manager_headers,
                data={"note": "coaching proof"},
                files={
                    "file": (
                        f"coaching-{coaching_item_id}.txt",
                        f"coaching evidence {coaching_item_id}".encode("utf-8"),
                        "text/plain",
                    )
                },
            )
            assert coaching_upload.status_code == 201

    readiness_after = app_client.get(
        "/api/adoption/w04/tracker/readiness?site=W04+Site",
        headers=manager_headers,
    )
    assert readiness_after.status_code == 200
    readiness_after_body = readiness_after.json()
    assert readiness_after_body["ready"] is True
    assert readiness_after_body["pending_count"] == 0
    assert readiness_after_body["in_progress_count"] == 0
    assert readiness_after_body["blocked_count"] == 0
    assert readiness_after_body["missing_assignee_count"] == 0
    assert readiness_after_body["missing_completion_checked_count"] == 0
    assert readiness_after_body["missing_required_evidence_count"] == 0
    assert readiness_after_body["readiness_score_percent"] == 100

    completed = app_client.post(
        "/api/adoption/w04/tracker/complete",
        headers=manager_headers,
        json={"site": "W04 Site", "completion_note": "W04 complete and signed"},
    )
    assert completed.status_code == 200
    completed_body = completed.json()
    assert completed_body["status"] == "completed"
    assert completed_body["force_used"] is False
    assert completed_body["readiness"]["ready"] is True
    assert completed_body["completed_at"] is not None

    completion_after = app_client.get(
        "/api/adoption/w04/tracker/completion?site=W04+Site",
        headers=manager_headers,
    )
    assert completion_after.status_code == 200
    assert completion_after.json()["status"] == "completed"
    assert completion_after.json()["readiness"]["ready"] is True

    inspection = app_client.post(
        "/api/inspections",
        headers=manager_headers,
        json={
            "site": "W04 Site",
            "location": "B4",
            "cycle": "daily",
            "inspector": "w04_manager_ci",
            "inspected_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    assert inspection.status_code == 201

    work_order = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "W04 funnel work order",
            "description": "for funnel metrics",
            "site": "W04 Site",
            "location": "B4",
            "priority": "high",
        },
    )
    assert work_order.status_code == 201
    work_order_id = work_order.json()["id"]

    work_order_done = app_client.patch(
        f"/api/work-orders/{work_order_id}/complete",
        headers=manager_headers,
        json={"resolution_notes": "W04 complete path"},
    )
    assert work_order_done.status_code == 200

    funnel = app_client.get(
        "/api/ops/adoption/w04/funnel?site=W04+Site&days=30",
        headers=manager_headers,
    )
    assert funnel.status_code == 200
    funnel_body = funnel.json()
    assert funnel_body["site"] == "W04 Site"
    assert funnel_body["window_days"] == 30
    assert "metrics" in funnel_body
    assert "stages" in funnel_body
    assert "stage_timings_minutes" in funnel_body

    blockers = app_client.get(
        "/api/ops/adoption/w04/blockers?site=W04+Site&days=30&max_items=3",
        headers=manager_headers,
    )
    assert blockers.status_code == 200
    blockers_body = blockers.json()
    assert blockers_body["site"] == "W04 Site"
    assert blockers_body["window_days"] == 30
    assert isinstance(blockers_body["top"], list)
    assert isinstance(blockers_body["counts"], dict)

    owner_seed_other_site = app_client.post(
        "/api/adoption/w04/tracker/bootstrap",
        headers=_owner_headers(),
        json={"site": "Outside W04 Site"},
    )
    assert owner_seed_other_site.status_code == 200

    forbidden_other_site_tracker = app_client.get(
        "/api/adoption/w04/tracker/overview?site=Outside+W04+Site",
        headers=manager_headers,
    )
    assert forbidden_other_site_tracker.status_code == 403

    forbidden_other_site_funnel = app_client.get(
        "/api/ops/adoption/w04/funnel?site=Outside+W04+Site&days=30",
        headers=manager_headers,
    )
    assert forbidden_other_site_funnel.status_code == 403

def test_w05_usage_consistency_snapshot_flow(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w05_manager_ci",
            "display_name": "W05 Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W05 Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w05-manager-token"},
    )
    assert issued.status_code == 201
    manager_headers = {"X-Admin-Token": issued.json()["token"]}

    overdue_due_at = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    created_overdue = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "W05 overdue work",
            "description": "for consistency snapshot",
            "site": "W05 Site",
            "location": "C1",
            "priority": "high",
            "due_at": overdue_due_at,
        },
    )
    assert created_overdue.status_code == 201

    inspection = app_client.post(
        "/api/inspections",
        headers=manager_headers,
        json={
            "site": "W05 Site",
            "location": "C1",
            "cycle": "daily",
            "inspector": "w05_manager_ci",
            "inspected_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    assert inspection.status_code == 201

    scoped = app_client.get(
        "/api/ops/adoption/w05/consistency?site=W05+Site&days=28",
        headers=manager_headers,
    )
    assert scoped.status_code == 200
    scoped_body = scoped.json()
    assert scoped_body["site"] == "W05 Site"
    assert scoped_body["window_days"] == 28
    assert scoped_body["target_retention_percent"] == 65.0
    assert "metrics" in scoped_body
    assert scoped_body["metrics"]["open_work_orders"] >= 1
    assert scoped_body["metrics"]["overdue_open_work_orders"] >= 1
    assert isinstance(scoped_body["mission_recommendations"], list)
    assert len(scoped_body["mission_recommendations"]) >= 1

    all_visible = app_client.get(
        "/api/ops/adoption/w05/consistency?days=28",
        headers=manager_headers,
    )
    assert all_visible.status_code == 200
    all_body = all_visible.json()
    assert all_body["site"] is None
    assert isinstance(all_body["top_sites_by_overdue"], list)
    assert any(row["site"] == "W05 Site" for row in all_body["top_sites_by_overdue"])

    owner_outside = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Outside W05 scope",
            "description": "outside",
            "site": "Outside W05 Site",
            "location": "X1",
            "priority": "high",
            "due_at": overdue_due_at,
        },
    )
    assert owner_outside.status_code == 201

    forbidden = app_client.get(
        "/api/ops/adoption/w05/consistency?site=Outside+W05+Site&days=28",
        headers=manager_headers,
    )
    assert forbidden.status_code == 403

def test_w06_operational_rhythm_snapshot_flow(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w06_manager_ci",
            "display_name": "W06 Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W06 Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w06-manager-token"},
    )
    assert issued.status_code == 201
    manager_token = issued.json()["token"]
    manager_headers = {"X-Admin-Token": manager_token}

    work_order = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "W06 cadence work",
            "description": "for rhythm snapshot",
            "site": "W06 Site",
            "location": "D1",
            "priority": "high",
            "due_at": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat(),
        },
    )
    assert work_order.status_code == 201

    inspection = app_client.post(
        "/api/inspections",
        headers=manager_headers,
        json={
            "site": "W06 Site",
            "location": "D1",
            "cycle": "daily",
            "inspector": "w06_manager_ci",
            "inspected_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    assert inspection.status_code == 201

    handover = app_client.get(
        "/api/ops/handover/brief?site=W06+Site&window_hours=12&due_soon_hours=6&max_items=10",
        headers=_owner_headers(),
    )
    assert handover.status_code == 200

    scoped = app_client.get(
        "/api/ops/adoption/w06/rhythm?site=W06+Site&days=14",
        headers=manager_headers,
    )
    assert scoped.status_code == 200
    scoped_body = scoped.json()
    assert scoped_body["site"] == "W06 Site"
    assert scoped_body["window_days"] == 14
    assert scoped_body["target_weekly_active_rate_percent"] == 75.0
    assert scoped_body["metrics"]["eligible_users"] >= 1
    assert scoped_body["metrics"]["active_users"] >= 1
    assert scoped_body["metrics"]["active_tokens"] >= 1
    assert scoped_body["metrics"]["overdue_open_work_orders"] >= 1
    assert isinstance(scoped_body["role_coverage"], list)
    assert isinstance(scoped_body["site_activity"], list)
    assert isinstance(scoped_body["recommendations"], list)
    assert len(scoped_body["recommendations"]) >= 1

    all_visible = app_client.get(
        "/api/ops/adoption/w06/rhythm?days=14",
        headers=manager_headers,
    )
    assert all_visible.status_code == 200
    assert all_visible.json()["site"] is None

    owner_outside = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Outside W06 scope",
            "description": "outside",
            "site": "Outside W06 Site",
            "location": "D9",
            "priority": "high",
            "due_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        },
    )
    assert owner_outside.status_code == 201

    forbidden = app_client.get(
        "/api/ops/adoption/w06/rhythm?site=Outside+W06+Site&days=14",
        headers=manager_headers,
    )
    assert forbidden.status_code == 403

def test_w07_tracker_execution_flow(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w07_tracker_manager_ci",
            "display_name": "W07 Tracker Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W07 Tracker Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w07-tracker-manager-token"},
    )
    assert issued.status_code == 201
    manager_headers = {"X-Admin-Token": issued.json()["token"]}

    bootstrap = app_client.post(
        "/api/adoption/w07/tracker/bootstrap",
        headers=manager_headers,
        json={"site": "W07 Tracker Site"},
    )
    assert bootstrap.status_code == 200
    bootstrap_body = bootstrap.json()
    assert bootstrap_body["site"] == "W07 Tracker Site"
    assert bootstrap_body["total_count"] >= 13

    listed = app_client.get(
        "/api/adoption/w07/tracker/items?site=W07+Tracker+Site&limit=500",
        headers=manager_headers,
    )
    assert listed.status_code == 200
    items = listed.json()
    assert len(items) >= 13

    for row in items:
        item_id = int(row["id"])
        updated = app_client.patch(
            f"/api/adoption/w07/tracker/items/{item_id}",
            headers=manager_headers,
            json={
                "assignee": "Ops QA",
                "status": "done",
                "completion_checked": True,
                "completion_note": "W07 completed in CI",
            },
        )
        assert updated.status_code == 200
        assert updated.json()["status"] == "done"
        assert updated.json()["completion_checked"] is True

        if row["item_type"] in {"sla_checklist", "coaching_play"}:
            uploaded = app_client.post(
                f"/api/adoption/w07/tracker/items/{item_id}/evidence",
                headers=manager_headers,
                data={"note": "w07 proof"},
                files={"file": (f"w07-{item_id}.txt", f"proof {item_id}".encode("utf-8"), "text/plain")},
            )
            assert uploaded.status_code == 201
            evidence_id = uploaded.json()["id"]
            downloaded = app_client.get(
                f"/api/adoption/w07/tracker/evidence/{evidence_id}/download",
                headers=manager_headers,
            )
            assert downloaded.status_code == 200
            assert len(downloaded.headers["x-evidence-sha256"]) == 64

    readiness = app_client.get(
        "/api/adoption/w07/tracker/readiness?site=W07+Tracker+Site",
        headers=manager_headers,
    )
    assert readiness.status_code == 200
    readiness_body = readiness.json()
    assert readiness_body["ready"] is True
    assert readiness_body["pending_count"] == 0
    assert readiness_body["in_progress_count"] == 0
    assert readiness_body["blocked_count"] == 0
    assert readiness_body["missing_assignee_count"] == 0
    assert readiness_body["missing_completion_checked_count"] == 0
    assert readiness_body["missing_required_evidence_count"] == 0

    completed = app_client.post(
        "/api/adoption/w07/tracker/complete",
        headers=manager_headers,
        json={"site": "W07 Tracker Site", "completion_note": "W07 tracker complete"},
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"
    assert completed.json()["readiness"]["ready"] is True

    completion = app_client.get(
        "/api/adoption/w07/tracker/completion?site=W07+Tracker+Site",
        headers=manager_headers,
    )
    assert completion.status_code == 200
    assert completion.json()["status"] == "completed"

    completion_package = app_client.get(
        "/api/adoption/w07/tracker/completion-package?site=W07+Tracker+Site&include_evidence=true&include_weekly=true&weekly_limit=10",
        headers=manager_headers,
    )
    assert completion_package.status_code == 200
    assert completion_package.headers["content-type"].startswith("application/zip")
    assert completion_package.headers.get("x-package-site") == "W07 Tracker Site"
    assert len(completion_package.headers.get("x-archive-sha256", "")) == 64
    with zipfile.ZipFile(io.BytesIO(completion_package.content), mode="r") as zf:
        names = set(zf.namelist())
        assert "manifest.json" in names
        assert "completion/completion.json" in names
        assert "completion/readiness.json" in names
        assert "tracker/items.csv" in names
        assert "evidence/index.csv" in names
        assert "weekly/trends.csv" in names
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert manifest["site"] == "W07 Tracker Site"
        assert manifest["completion_status"] == "completed"
        assert manifest["summary"]["tracker_items"] >= 13
        assert manifest["summary"]["include_evidence"] is True

def test_w07_sla_quality_snapshot_flow(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w07_manager_ci",
            "display_name": "W07 Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W07 Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w07-manager-token"},
    )
    assert issued.status_code == 201
    manager_token = issued.json()["token"]
    manager_headers = {"X-Admin-Token": manager_token}

    fast_work_order = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "W07 fast response",
            "description": "ack and complete quickly",
            "site": "W07 Site",
            "location": "E1",
            "priority": "high",
            "due_at": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
        },
    )
    assert fast_work_order.status_code == 201
    fast_work_order_id = fast_work_order.json()["id"]

    acked = app_client.patch(
        f"/api/work-orders/{fast_work_order_id}/ack",
        headers=manager_headers,
        json={"assignee": "w07_manager_ci"},
    )
    assert acked.status_code == 200
    assert acked.json()["status"] == "acked"

    completed = app_client.patch(
        f"/api/work-orders/{fast_work_order_id}/complete",
        headers=manager_headers,
        json={"resolution_notes": "done"},
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"

    overdue_work_order = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "W07 overdue escalation",
            "description": "should escalate",
            "site": "W07 Site",
            "location": "E2",
            "priority": "critical",
            "due_at": (datetime.now(timezone.utc) - timedelta(hours=4)).isoformat(),
        },
    )
    assert overdue_work_order.status_code == 201

    escalation_run = app_client.post(
        "/api/work-orders/escalations/run",
        headers=manager_headers,
        json={"site": "W07 Site", "dry_run": False, "limit": 100},
    )
    assert escalation_run.status_code == 200
    assert escalation_run.json()["candidate_count"] >= 1

    scoped = app_client.get(
        "/api/ops/adoption/w07/sla-quality?site=W07+Site&days=14",
        headers=manager_headers,
    )
    assert scoped.status_code == 200
    scoped_body = scoped.json()
    assert scoped_body["site"] == "W07 Site"
    assert scoped_body["window_days"] == 14
    assert scoped_body["target_response_improvement_percent"] == 10.0
    assert scoped_body["metrics"]["created_work_orders"] >= 2
    assert scoped_body["metrics"]["acked_work_orders"] >= 1
    assert scoped_body["metrics"]["completed_work_orders"] >= 1
    assert "p90_ack_minutes" in scoped_body["metrics"]
    assert "median_mttr_minutes" in scoped_body["metrics"]
    assert isinstance(scoped_body["metrics"]["priority_mttr_minutes"], dict)
    assert "sla_violation_rate_percent" in scoped_body["metrics"]
    assert "data_quality_gate_pass" in scoped_body["metrics"]
    assert scoped_body["metrics"]["escalated_work_orders"] >= 1
    assert scoped_body["metrics"]["overdue_open_work_orders"] >= 1
    assert scoped_body["metrics"]["sla_run_count"] >= 1
    assert "thresholds" in scoped_body
    assert "data_quality" in scoped_body
    assert isinstance(scoped_body["top_risk_sites"], list)
    assert isinstance(scoped_body["recommendations"], list)
    assert len(scoped_body["recommendations"]) >= 1

    all_visible = app_client.get(
        "/api/ops/adoption/w07/sla-quality?days=14",
        headers=manager_headers,
    )
    assert all_visible.status_code == 200
    assert all_visible.json()["site"] is None

    weekly_run = app_client.post(
        "/api/ops/adoption/w07/sla-quality/run-weekly?site=W07+Site&days=14",
        headers=manager_headers,
    )
    assert weekly_run.status_code == 200
    weekly_run_body = weekly_run.json()
    assert weekly_run_body["job_name"] == "adoption_w07_sla_quality_weekly"
    assert weekly_run_body["site"] == "W07 Site"
    assert "degradation" in weekly_run_body
    assert "cooldown_active" in weekly_run_body
    assert "snapshot" in weekly_run_body

    weekly_latest = app_client.get(
        "/api/ops/adoption/w07/sla-quality/latest-weekly?site=W07+Site",
        headers=manager_headers,
    )
    assert weekly_latest.status_code == 200
    assert weekly_latest.json()["job_name"] == "adoption_w07_sla_quality_weekly"
    assert weekly_latest.json()["site"] == "W07 Site"

    weekly_trends = app_client.get(
        "/api/ops/adoption/w07/sla-quality/trends?site=W07+Site&limit=10",
        headers=manager_headers,
    )
    assert weekly_trends.status_code == 200
    assert weekly_trends.json()["job_name"] == "adoption_w07_sla_quality_weekly"
    assert weekly_trends.json()["site"] == "W07 Site"
    assert weekly_trends.json()["point_count"] >= 1
    assert isinstance(weekly_trends.json()["points"], list)

    weekly_archive = app_client.get(
        "/api/ops/adoption/w07/sla-quality/archive.csv?site=W07+Site&limit=10",
        headers=manager_headers,
    )
    assert weekly_archive.status_code == 200
    assert weekly_archive.headers["content-type"].startswith("text/csv")
    assert "run_id,finished_at,site,status" in weekly_archive.text

    owner_outside = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Outside W07 scope",
            "description": "outside",
            "site": "Outside W07 Site",
            "location": "E9",
            "priority": "high",
            "due_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        },
    )
    assert owner_outside.status_code == 201

    forbidden = app_client.get(
        "/api/ops/adoption/w07/sla-quality?site=Outside+W07+Site&days=14",
        headers=manager_headers,
    )
    assert forbidden.status_code == 403

def test_w07_automation_readiness_endpoint(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w07_readiness_manager_ci",
            "display_name": "W07 Readiness Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W07 Ready Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w07-readiness-manager-token"},
    )
    assert issued.status_code == 201
    manager_headers = {"X-Admin-Token": issued.json()["token"]}

    before = app_client.get(
        "/api/ops/adoption/w07/automation-readiness?site=W07+Ready+Site",
        headers=manager_headers,
    )
    assert before.status_code == 200
    before_body = before.json()
    assert before_body["site"] == "W07 Ready Site"
    assert before_body["integration"]["cron_job_name"] == "adoption_w07_sla_quality_weekly"
    assert before_body["integration"]["recommended_cron_schedule_utc"] == "30 23 * * 5"
    assert isinstance(before_body["checks"], list)
    assert len(before_body["checks"]) >= 4

    work_order = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "W07 readiness overdue",
            "description": "seed weekly run",
            "site": "W07 Ready Site",
            "location": "R1",
            "priority": "critical",
            "due_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        },
    )
    assert work_order.status_code == 201

    weekly_run = app_client.post(
        "/api/ops/adoption/w07/sla-quality/run-weekly?site=W07+Ready+Site&days=14",
        headers=manager_headers,
    )
    assert weekly_run.status_code == 200

    after = app_client.get(
        "/api/ops/adoption/w07/automation-readiness?site=W07+Ready+Site",
        headers=manager_headers,
    )
    assert after.status_code == 200
    after_body = after.json()
    assert after_body["runtime"]["latest_run_id"] is not None
    assert after_body["runtime"]["latest_run_recent"] is True
    assert after_body["runtime"]["latest_run_status"] in {"success", "warning", "critical"}
    assert isinstance(after_body["integration"]["webhook_targets"], list)
    assert isinstance(after_body["policy"]["archive_enabled"], bool)

    forbidden = app_client.get(
        "/api/ops/adoption/w07/automation-readiness?site=Outside+W07+Ready+Site",
        headers=manager_headers,
    )
    assert forbidden.status_code == 403

def test_w08_report_discipline_snapshot_flow(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w08_manager_ci",
            "display_name": "W08 Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W08 Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w08-manager-token"},
    )
    assert issued.status_code == 201
    manager_headers = {"X-Admin-Token": issued.json()["token"]}

    created_missing_due = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "W08 missing due",
            "description": "data quality check",
            "site": "W08 Site",
            "location": "F1",
            "priority": "high",
        },
    )
    assert created_missing_due.status_code == 201

    created_overdue = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "W08 overdue open",
            "description": "overdue check",
            "site": "W08 Site",
            "location": "F2",
            "priority": "critical",
            "due_at": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat(),
        },
    )
    assert created_overdue.status_code == 201

    created_complete = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "W08 complete path",
            "description": "completion timestamp check",
            "site": "W08 Site",
            "location": "F3",
            "priority": "medium",
            "due_at": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
        },
    )
    assert created_complete.status_code == 201
    created_complete_id = created_complete.json()["id"]
    completed = app_client.patch(
        f"/api/work-orders/{created_complete_id}/complete",
        headers=manager_headers,
        json={"resolution_notes": "W08 completed"},
    )
    assert completed.status_code == 200

    inspection = app_client.post(
        "/api/inspections",
        headers=manager_headers,
        json={
            "site": "W08 Site",
            "location": "F1",
            "cycle": "daily",
            "inspector": "w08_manager_ci",
            "inspected_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    assert inspection.status_code == 201

    month = datetime.now(timezone.utc).strftime("%Y-%m")
    report_export = app_client.get(
        f"/api/reports/monthly/csv?month={month}&site=W08+Site",
        headers=manager_headers,
    )
    assert report_export.status_code == 200

    scoped = app_client.get(
        "/api/ops/adoption/w08/report-discipline?site=W08+Site&days=30",
        headers=manager_headers,
    )
    assert scoped.status_code == 200
    scoped_body = scoped.json()
    assert scoped_body["site"] == "W08 Site"
    assert scoped_body["window_days"] == 30
    assert isinstance(scoped_body["metrics"], dict)
    assert scoped_body["metrics"]["work_orders_created"] >= 3
    assert "discipline_score" in scoped_body["metrics"]
    assert "report_export_coverage_percent" in scoped_body["metrics"]
    assert "data_quality_issue_rate_percent" in scoped_body["metrics"]
    assert isinstance(scoped_body["top_risk_sites"], list)
    assert isinstance(scoped_body["site_benchmark"], list)
    assert isinstance(scoped_body["recommendations"], list)
    assert len(scoped_body["recommendations"]) >= 1

    benchmark = app_client.get(
        "/api/ops/adoption/w08/site-benchmark?site=W08+Site&days=30&limit=5",
        headers=manager_headers,
    )
    assert benchmark.status_code == 200
    benchmark_body = benchmark.json()
    assert benchmark_body["site"] == "W08 Site"
    assert benchmark_body["window_days"] == 30
    assert benchmark_body["count"] >= 1
    assert isinstance(benchmark_body["items"], list)
    assert all(row["site"] == "W08 Site" for row in benchmark_body["items"])

    all_visible = app_client.get(
        "/api/ops/adoption/w08/report-discipline?days=30",
        headers=manager_headers,
    )
    assert all_visible.status_code == 200
    all_visible_body = all_visible.json()
    assert all_visible_body["site"] is None
    assert isinstance(all_visible_body["top_risk_sites"], list)
    assert any(row["site"] == "W08 Site" for row in all_visible_body["top_risk_sites"])

    owner_outside = app_client.post(
        "/api/work-orders",
        headers=_owner_headers(),
        json={
            "title": "Outside W08 scope",
            "description": "outside",
            "site": "Outside W08 Site",
            "location": "F9",
            "priority": "high",
            "due_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        },
    )
    assert owner_outside.status_code == 201

    forbidden = app_client.get(
        "/api/ops/adoption/w08/report-discipline?site=Outside+W08+Site&days=30",
        headers=manager_headers,
    )
    assert forbidden.status_code == 403

def test_w09_kpi_operation_and_tracker_flow(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w09_manager_ci",
            "display_name": "W09 Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W09 Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w09-manager-token"},
    )
    assert issued.status_code == 201
    manager_headers = {"X-Admin-Token": issued.json()["token"]}

    inspection = app_client.post(
        "/api/inspections",
        headers=manager_headers,
        json={
            "site": "W09 Site",
            "location": "K1",
            "cycle": "daily",
            "inspector": "w09_manager_ci",
            "inspected_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    assert inspection.status_code == 201

    work_order = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "W09 overdue signal",
            "description": "seed KPI operation metrics",
            "site": "W09 Site",
            "location": "K2",
            "priority": "critical",
            "due_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        },
    )
    assert work_order.status_code == 201

    snapshot = app_client.get(
        "/api/ops/adoption/w09/kpi-operation?site=W09+Site&days=30",
        headers=manager_headers,
    )
    assert snapshot.status_code == 200
    snapshot_body = snapshot.json()
    assert snapshot_body["site"] == "W09 Site"
    assert snapshot_body["window_days"] == 30
    assert snapshot_body["policy"]["kpi_count"] >= 5
    assert snapshot_body["policy"]["escalation_rule_count"] >= 4
    assert isinstance(snapshot_body["kpis"], list)
    assert len(snapshot_body["kpis"]) >= 5
    assert isinstance(snapshot_body["metrics"], dict)
    assert snapshot_body["metrics"]["kpi_count"] >= 5
    assert snapshot_body["metrics"]["overall_status"] in {"green", "yellow", "red"}
    assert isinstance(snapshot_body["recommendations"], list)
    assert len(snapshot_body["recommendations"]) >= 1

    policy = app_client.get(
        "/api/ops/adoption/w09/kpi-policy?site=W09+Site",
        headers=manager_headers,
    )
    assert policy.status_code == 200
    policy_body = policy.json()
    assert policy_body["site"] == "W09 Site"
    assert policy_body["policy_key"].startswith("adoption_w09_kpi_policy:site:")
    assert isinstance(policy_body["policy"]["kpis"], list)
    assert len(policy_body["policy"]["kpis"]) >= 5

    updated = app_client.put(
        "/api/ops/adoption/w09/kpi-policy?site=W09+Site",
        headers=manager_headers,
        json={
            "enabled": True,
            "kpis": [
                {
                    "kpi_key": "two_week_retention_percent",
                    "owner_role": "Ops Lead",
                    "direction": "higher_better",
                    "green_threshold": 80,
                    "yellow_threshold": 65,
                }
            ],
        },
    )
    assert updated.status_code == 200
    updated_policy = updated.json()["policy"]
    kpi_map = {row["kpi_key"]: row for row in updated_policy["kpis"]}
    assert kpi_map["two_week_retention_percent"]["owner_role"] == "Ops Lead"
    assert kpi_map["two_week_retention_percent"]["green_threshold"] == 80.0
    assert kpi_map["two_week_retention_percent"]["yellow_threshold"] == 65.0

    global_policy_forbidden = app_client.get(
        "/api/ops/adoption/w09/kpi-policy",
        headers=manager_headers,
    )
    assert global_policy_forbidden.status_code == 403

    global_update_forbidden = app_client.put(
        "/api/ops/adoption/w09/kpi-policy",
        headers=manager_headers,
        json={"enabled": False},
    )
    assert global_update_forbidden.status_code == 403

    bootstrap = app_client.post(
        "/api/adoption/w09/tracker/bootstrap",
        headers=manager_headers,
        json={"site": "W09 Site"},
    )
    assert bootstrap.status_code == 200
    bootstrap_body = bootstrap.json()
    assert bootstrap_body["site"] == "W09 Site"
    assert bootstrap_body["total_count"] >= 14

    listed = app_client.get(
        "/api/adoption/w09/tracker/items?site=W09+Site&limit=500",
        headers=manager_headers,
    )
    assert listed.status_code == 200
    items = listed.json()
    assert len(items) >= 14

    required_item_id: int | None = None
    for row in items:
        item_id = int(row["id"])
        patched = app_client.patch(
            f"/api/adoption/w09/tracker/items/{item_id}",
            headers=manager_headers,
            json={
                "assignee": "Ops QA",
                "status": "done",
                "completion_checked": True,
                "completion_note": "W09 completed in CI",
            },
        )
        assert patched.status_code == 200
        assert patched.json()["status"] == "done"
        assert patched.json()["completion_checked"] is True

        if row["item_type"] in {"kpi_threshold", "kpi_escalation"}:
            if required_item_id is None:
                required_item_id = item_id
            uploaded = app_client.post(
                f"/api/adoption/w09/tracker/items/{item_id}/evidence",
                headers=manager_headers,
                data={"note": "w09 proof"},
                files={"file": (f"w09-{item_id}.txt", f"proof {item_id}".encode("utf-8"), "text/plain")},
            )
            assert uploaded.status_code == 201
            evidence_id = uploaded.json()["id"]
            downloaded = app_client.get(
                f"/api/adoption/w09/tracker/evidence/{evidence_id}/download",
                headers=manager_headers,
            )
            assert downloaded.status_code == 200
            assert len(downloaded.headers["x-evidence-sha256"]) == 64

    assert required_item_id is not None

    evidence_list = app_client.get(
        f"/api/adoption/w09/tracker/items/{required_item_id}/evidence",
        headers=manager_headers,
    )
    assert evidence_list.status_code == 200
    assert len(evidence_list.json()) >= 1

    readiness = app_client.get(
        "/api/adoption/w09/tracker/readiness?site=W09+Site",
        headers=manager_headers,
    )
    assert readiness.status_code == 200
    readiness_body = readiness.json()
    assert readiness_body["ready"] is True
    assert readiness_body["pending_count"] == 0
    assert readiness_body["in_progress_count"] == 0
    assert readiness_body["blocked_count"] == 0
    assert readiness_body["missing_assignee_count"] == 0
    assert readiness_body["missing_completion_checked_count"] == 0
    assert readiness_body["missing_required_evidence_count"] == 0

    completed = app_client.post(
        "/api/adoption/w09/tracker/complete",
        headers=manager_headers,
        json={"site": "W09 Site", "completion_note": "W09 tracker complete"},
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"
    assert completed.json()["readiness"]["ready"] is True

    completion = app_client.get(
        "/api/adoption/w09/tracker/completion?site=W09+Site",
        headers=manager_headers,
    )
    assert completion.status_code == 200
    assert completion.json()["status"] == "completed"

    bootstrap_outside = app_client.post(
        "/api/adoption/w09/tracker/bootstrap",
        headers=_owner_headers(),
        json={"site": "Outside W09 Site"},
    )
    assert bootstrap_outside.status_code == 200

    forbidden_kpi = app_client.get(
        "/api/ops/adoption/w09/kpi-operation?site=Outside+W09+Site&days=30",
        headers=manager_headers,
    )
    assert forbidden_kpi.status_code == 403

    forbidden_tracker = app_client.get(
        "/api/adoption/w09/tracker/overview?site=Outside+W09+Site",
        headers=manager_headers,
    )
    assert forbidden_tracker.status_code == 403

def test_w10_self_serve_and_tracker_flow(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w10_manager_ci",
            "display_name": "W10 Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W10 Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w10-manager-token"},
    )
    assert issued.status_code == 201
    manager_headers = {"X-Admin-Token": issued.json()["token"]}

    inspection = app_client.post(
        "/api/inspections",
        headers=manager_headers,
        json={
            "site": "W10 Site",
            "location": "S1",
            "cycle": "weekly",
            "inspector": "w10_manager_ci",
            "inspected_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    assert inspection.status_code == 201

    work_order_a = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "HVAC recurring alarm",
            "description": "repeat issue seed A",
            "site": "W10 Site",
            "location": "S2",
            "priority": "high",
            "due_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        },
    )
    assert work_order_a.status_code == 201

    work_order_b = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "HVAC recurring alarm",
            "description": "repeat issue seed B",
            "site": "W10 Site",
            "location": "S3",
            "priority": "high",
            "due_at": (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat(),
        },
    )
    assert work_order_b.status_code == 201

    snapshot = app_client.get(
        "/api/ops/adoption/w10/self-serve?site=W10+Site&days=30",
        headers=manager_headers,
    )
    assert snapshot.status_code == 200
    snapshot_body = snapshot.json()
    assert snapshot_body["site"] == "W10 Site"
    assert snapshot_body["window_days"] == 30
    assert isinstance(snapshot_body["policy"], dict)
    assert snapshot_body["policy"]["enabled"] is True
    assert isinstance(snapshot_body["kpis"], list)
    assert len(snapshot_body["kpis"]) >= 4
    assert isinstance(snapshot_body["metrics"], dict)
    assert snapshot_body["metrics"]["guide_total_count"] >= 5
    assert snapshot_body["metrics"]["runbook_total_count"] >= 4
    assert snapshot_body["metrics"]["overall_status"] in {"green", "yellow", "red"}
    assert isinstance(snapshot_body["recommendations"], list)
    assert len(snapshot_body["recommendations"]) >= 1
    assert isinstance(snapshot_body["top_repeat_titles"], list)
    assert any(row["title"] == "HVAC recurring alarm" for row in snapshot_body["top_repeat_titles"])

    policy = app_client.get(
        "/api/ops/adoption/w10/support-policy?site=W10+Site",
        headers=manager_headers,
    )
    assert policy.status_code == 200
    policy_body = policy.json()
    assert policy_body["site"] == "W10 Site"
    assert policy_body["policy_key"].startswith("adoption_w10_support_policy:site:")
    assert isinstance(policy_body["policy"], dict)
    assert "repeat_rate_green_threshold" in policy_body["policy"]
    assert "repeat_rate_yellow_threshold" in policy_body["policy"]
    assert "guide_publish_green_threshold" in policy_body["policy"]
    assert "runbook_completion_green_threshold" in policy_body["policy"]
    assert "readiness_target" in policy_body["policy"]

    updated = app_client.put(
        "/api/ops/adoption/w10/support-policy?site=W10+Site",
        headers=manager_headers,
        json={
            "enabled": True,
            "repeat_rate_green_threshold": 18,
            "repeat_rate_yellow_threshold": 27,
            "guide_publish_green_threshold": 85,
            "guide_publish_yellow_threshold": 70,
            "runbook_completion_green_threshold": 88,
            "runbook_completion_yellow_threshold": 72,
            "readiness_target": 82,
        },
    )
    assert updated.status_code == 200
    updated_policy = updated.json()["policy"]
    assert updated_policy["repeat_rate_green_threshold"] == 18.0
    assert updated_policy["repeat_rate_yellow_threshold"] == 27.0
    assert updated_policy["guide_publish_green_threshold"] == 85.0
    assert updated_policy["guide_publish_yellow_threshold"] == 70.0
    assert updated_policy["runbook_completion_green_threshold"] == 88.0
    assert updated_policy["runbook_completion_yellow_threshold"] == 72.0
    assert updated_policy["readiness_target"] == 82.0

    global_policy_forbidden = app_client.get(
        "/api/ops/adoption/w10/support-policy",
        headers=manager_headers,
    )
    assert global_policy_forbidden.status_code == 403

    global_update_forbidden = app_client.put(
        "/api/ops/adoption/w10/support-policy",
        headers=manager_headers,
        json={"enabled": False},
    )
    assert global_update_forbidden.status_code == 403

    bootstrap = app_client.post(
        "/api/adoption/w10/tracker/bootstrap",
        headers=manager_headers,
        json={"site": "W10 Site"},
    )
    assert bootstrap.status_code == 200
    bootstrap_body = bootstrap.json()
    assert bootstrap_body["site"] == "W10 Site"
    assert bootstrap_body["total_count"] >= 14

    listed = app_client.get(
        "/api/adoption/w10/tracker/items?site=W10+Site&limit=500",
        headers=manager_headers,
    )
    assert listed.status_code == 200
    items = listed.json()
    assert len(items) >= 14

    required_item_id: int | None = None
    for row in items:
        item_id = int(row["id"])
        patched = app_client.patch(
            f"/api/adoption/w10/tracker/items/{item_id}",
            headers=manager_headers,
            json={
                "assignee": "Support QA",
                "status": "done",
                "completion_checked": True,
                "completion_note": "W10 completed in CI",
            },
        )
        assert patched.status_code == 200
        assert patched.json()["status"] == "done"
        assert patched.json()["completion_checked"] is True

        if row["item_type"] in {"self_serve_guide", "troubleshooting_runbook"}:
            if required_item_id is None:
                required_item_id = item_id
            uploaded = app_client.post(
                f"/api/adoption/w10/tracker/items/{item_id}/evidence",
                headers=manager_headers,
                data={"note": "w10 proof"},
                files={"file": (f"w10-{item_id}.txt", f"proof {item_id}".encode("utf-8"), "text/plain")},
            )
            assert uploaded.status_code == 201
            evidence_id = uploaded.json()["id"]
            downloaded = app_client.get(
                f"/api/adoption/w10/tracker/evidence/{evidence_id}/download",
                headers=manager_headers,
            )
            assert downloaded.status_code == 200
            assert len(downloaded.headers["x-evidence-sha256"]) == 64

    assert required_item_id is not None

    evidence_list = app_client.get(
        f"/api/adoption/w10/tracker/items/{required_item_id}/evidence",
        headers=manager_headers,
    )
    assert evidence_list.status_code == 200
    assert len(evidence_list.json()) >= 1

    readiness = app_client.get(
        "/api/adoption/w10/tracker/readiness?site=W10+Site",
        headers=manager_headers,
    )
    assert readiness.status_code == 200
    readiness_body = readiness.json()
    assert readiness_body["ready"] is True
    assert readiness_body["pending_count"] == 0
    assert readiness_body["in_progress_count"] == 0
    assert readiness_body["blocked_count"] == 0
    assert readiness_body["missing_assignee_count"] == 0
    assert readiness_body["missing_completion_checked_count"] == 0
    assert readiness_body["missing_required_evidence_count"] == 0

    completed = app_client.post(
        "/api/adoption/w10/tracker/complete",
        headers=manager_headers,
        json={"site": "W10 Site", "completion_note": "W10 tracker complete"},
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"
    assert completed.json()["readiness"]["ready"] is True

    completion = app_client.get(
        "/api/adoption/w10/tracker/completion?site=W10+Site",
        headers=manager_headers,
    )
    assert completion.status_code == 200
    assert completion.json()["status"] == "completed"

    bootstrap_outside = app_client.post(
        "/api/adoption/w10/tracker/bootstrap",
        headers=_owner_headers(),
        json={"site": "Outside W10 Site"},
    )
    assert bootstrap_outside.status_code == 200

    forbidden_snapshot = app_client.get(
        "/api/ops/adoption/w10/self-serve?site=Outside+W10+Site&days=30",
        headers=manager_headers,
    )
    assert forbidden_snapshot.status_code == 403

    forbidden_tracker = app_client.get(
        "/api/adoption/w10/tracker/overview?site=Outside+W10+Site",
        headers=manager_headers,
    )
    assert forbidden_tracker.status_code == 403

def test_w11_scale_readiness_and_tracker_flow(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w11_manager_ci",
            "display_name": "W11 Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W11 Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w11-manager-token"},
    )
    assert issued.status_code == 201
    manager_headers = {"X-Admin-Token": issued.json()["token"]}

    inspection = app_client.post(
        "/api/inspections",
        headers=manager_headers,
        json={
            "site": "W11 Site",
            "location": "R1",
            "cycle": "weekly",
            "inspector": "w11_manager_ci",
            "inspected_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    assert inspection.status_code == 201

    work_order_a = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "Panel recurring alarm",
            "description": "repeat issue seed A",
            "site": "W11 Site",
            "location": "R2",
            "priority": "high",
            "due_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        },
    )
    assert work_order_a.status_code == 201

    work_order_b = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "Panel recurring alarm",
            "description": "repeat issue seed B",
            "site": "W11 Site",
            "location": "R3",
            "priority": "high",
            "due_at": (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat(),
        },
    )
    assert work_order_b.status_code == 201

    snapshot = app_client.get(
        "/api/ops/adoption/w11/scale-readiness?site=W11+Site&days=30",
        headers=manager_headers,
    )
    assert snapshot.status_code == 200
    snapshot_body = snapshot.json()
    assert snapshot_body["site"] == "W11 Site"
    assert snapshot_body["window_days"] == 30
    assert isinstance(snapshot_body["policy"], dict)
    assert snapshot_body["policy"]["enabled"] is True
    assert isinstance(snapshot_body["kpis"], list)
    assert len(snapshot_body["kpis"]) >= 4
    assert isinstance(snapshot_body["metrics"], dict)
    assert snapshot_body["metrics"]["guide_total_count"] >= 5
    assert snapshot_body["metrics"]["runbook_total_count"] >= 4
    assert snapshot_body["metrics"]["overall_status"] in {"green", "yellow", "red"}
    assert isinstance(snapshot_body["recommendations"], list)
    assert len(snapshot_body["recommendations"]) >= 1
    assert isinstance(snapshot_body["top_repeat_titles"], list)
    assert any(row["title"] == "Panel recurring alarm" for row in snapshot_body["top_repeat_titles"])

    policy = app_client.get(
        "/api/ops/adoption/w11/readiness-policy?site=W11+Site",
        headers=manager_headers,
    )
    assert policy.status_code == 200
    policy_body = policy.json()
    assert policy_body["site"] == "W11 Site"
    assert policy_body["policy_key"].startswith("adoption_w11_readiness_policy:site:")
    assert isinstance(policy_body["policy"], dict)
    assert "risk_rate_green_threshold" in policy_body["policy"]
    assert "risk_rate_yellow_threshold" in policy_body["policy"]
    assert "checklist_completion_green_threshold" in policy_body["policy"]
    assert "simulation_success_green_threshold" in policy_body["policy"]
    assert "readiness_target" in policy_body["policy"]

    updated = app_client.put(
        "/api/ops/adoption/w11/readiness-policy?site=W11+Site",
        headers=manager_headers,
        json={
            "enabled": True,
            "risk_rate_green_threshold": 18,
            "risk_rate_yellow_threshold": 27,
            "checklist_completion_green_threshold": 85,
            "checklist_completion_yellow_threshold": 70,
            "simulation_success_green_threshold": 88,
            "simulation_success_yellow_threshold": 72,
            "readiness_target": 82,
        },
    )
    assert updated.status_code == 200
    updated_policy = updated.json()["policy"]
    assert updated_policy["risk_rate_green_threshold"] == 18.0
    assert updated_policy["risk_rate_yellow_threshold"] == 27.0
    assert updated_policy["checklist_completion_green_threshold"] == 85.0
    assert updated_policy["checklist_completion_yellow_threshold"] == 70.0
    assert updated_policy["simulation_success_green_threshold"] == 88.0
    assert updated_policy["simulation_success_yellow_threshold"] == 72.0
    assert updated_policy["readiness_target"] == 82.0

    global_policy_forbidden = app_client.get(
        "/api/ops/adoption/w11/readiness-policy",
        headers=manager_headers,
    )
    assert global_policy_forbidden.status_code == 403

    global_update_forbidden = app_client.put(
        "/api/ops/adoption/w11/readiness-policy",
        headers=manager_headers,
        json={"enabled": False},
    )
    assert global_update_forbidden.status_code == 403

    bootstrap = app_client.post(
        "/api/adoption/w11/tracker/bootstrap",
        headers=manager_headers,
        json={"site": "W11 Site"},
    )
    assert bootstrap.status_code == 200
    bootstrap_body = bootstrap.json()
    assert bootstrap_body["site"] == "W11 Site"
    assert bootstrap_body["total_count"] >= 14

    listed = app_client.get(
        "/api/adoption/w11/tracker/items?site=W11+Site&limit=500",
        headers=manager_headers,
    )
    assert listed.status_code == 200
    items = listed.json()
    assert len(items) >= 14

    required_item_id: int | None = None
    for row in items:
        item_id = int(row["id"])
        patched = app_client.patch(
            f"/api/adoption/w11/tracker/items/{item_id}",
            headers=manager_headers,
            json={
                "assignee": "Scale QA",
                "status": "done",
                "completion_checked": True,
                "completion_note": "W11 completed in CI",
            },
        )
        assert patched.status_code == 200
        assert patched.json()["status"] == "done"
        assert patched.json()["completion_checked"] is True

        if row["item_type"] in {"self_serve_guide", "troubleshooting_runbook"}:
            if required_item_id is None:
                required_item_id = item_id
            uploaded = app_client.post(
                f"/api/adoption/w11/tracker/items/{item_id}/evidence",
                headers=manager_headers,
                data={"note": "w11 proof"},
                files={"file": (f"w11-{item_id}.txt", f"proof {item_id}".encode("utf-8"), "text/plain")},
            )
            assert uploaded.status_code == 201
            evidence_id = uploaded.json()["id"]
            downloaded = app_client.get(
                f"/api/adoption/w11/tracker/evidence/{evidence_id}/download",
                headers=manager_headers,
            )
            assert downloaded.status_code == 200
            assert len(downloaded.headers["x-evidence-sha256"]) == 64

    assert required_item_id is not None

    evidence_list = app_client.get(
        f"/api/adoption/w11/tracker/items/{required_item_id}/evidence",
        headers=manager_headers,
    )
    assert evidence_list.status_code == 200
    assert len(evidence_list.json()) >= 1

    readiness = app_client.get(
        "/api/adoption/w11/tracker/readiness?site=W11+Site",
        headers=manager_headers,
    )
    assert readiness.status_code == 200
    readiness_body = readiness.json()
    assert readiness_body["ready"] is True
    assert readiness_body["pending_count"] == 0
    assert readiness_body["in_progress_count"] == 0
    assert readiness_body["blocked_count"] == 0
    assert readiness_body["missing_assignee_count"] == 0
    assert readiness_body["missing_completion_checked_count"] == 0
    assert readiness_body["missing_required_evidence_count"] == 0

    completed = app_client.post(
        "/api/adoption/w11/tracker/complete",
        headers=manager_headers,
        json={"site": "W11 Site", "completion_note": "W11 tracker complete"},
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"
    assert completed.json()["readiness"]["ready"] is True

    completion = app_client.get(
        "/api/adoption/w11/tracker/completion?site=W11+Site",
        headers=manager_headers,
    )
    assert completion.status_code == 200
    assert completion.json()["status"] == "completed"

    bootstrap_outside = app_client.post(
        "/api/adoption/w11/tracker/bootstrap",
        headers=_owner_headers(),
        json={"site": "Outside W11 Site"},
    )
    assert bootstrap_outside.status_code == 200

    forbidden_snapshot = app_client.get(
        "/api/ops/adoption/w11/scale-readiness?site=Outside+W11+Site&days=30",
        headers=manager_headers,
    )
    assert forbidden_snapshot.status_code == 403

    forbidden_tracker = app_client.get(
        "/api/adoption/w11/tracker/overview?site=Outside+W11+Site",
        headers=manager_headers,
    )
    assert forbidden_tracker.status_code == 403

def test_w15_ops_efficiency_and_tracker_flow(app_client: TestClient) -> None:
    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w15_manager_ci",
            "display_name": "W15 Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W15 Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w15-manager-token"},
    )
    assert issued.status_code == 201
    manager_headers = {"X-Admin-Token": issued.json()["token"]}

    inspection = app_client.post(
        "/api/inspections",
        headers=manager_headers,
        json={
            "site": "W15 Site",
            "location": "E1",
            "cycle": "weekly",
            "inspector": "w15_manager_ci",
            "inspected_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    assert inspection.status_code == 201

    work_order_a = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "W15 recurring incident",
            "description": "repeat issue seed A",
            "site": "W15 Site",
            "location": "E2",
            "priority": "high",
            "due_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        },
    )
    assert work_order_a.status_code == 201

    work_order_b = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "W15 recurring incident",
            "description": "repeat issue seed B",
            "site": "W15 Site",
            "location": "E3",
            "priority": "high",
            "due_at": (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat(),
        },
    )
    assert work_order_b.status_code == 201

    snapshot = app_client.get(
        "/api/ops/adoption/w15/ops-efficiency?site=W15+Site&days=30",
        headers=manager_headers,
    )
    assert snapshot.status_code == 200
    snapshot_body = snapshot.json()
    assert snapshot_body["site"] == "W15 Site"
    assert snapshot_body["window_days"] == 30
    assert isinstance(snapshot_body["policy"], dict)
    assert snapshot_body["policy"]["enabled"] is True
    assert isinstance(snapshot_body["kpis"], list)
    assert len(snapshot_body["kpis"]) >= 4
    assert isinstance(snapshot_body["metrics"], dict)
    assert snapshot_body["metrics"]["incidents_count"] >= 2
    assert snapshot_body["metrics"]["guide_total_count"] >= 5
    assert snapshot_body["metrics"]["runbook_total_count"] >= 4
    assert snapshot_body["metrics"]["overall_status"] in {"green", "yellow", "red"}
    assert isinstance(snapshot_body["recommendations"], list)
    assert len(snapshot_body["recommendations"]) >= 1
    assert isinstance(snapshot_body["top_repeat_incidents"], list)
    assert any(row["title"] == "W15 recurring incident" for row in snapshot_body["top_repeat_incidents"])

    policy = app_client.get(
        "/api/ops/adoption/w15/efficiency-policy?site=W15+Site",
        headers=manager_headers,
    )
    assert policy.status_code == 200
    policy_body = policy.json()
    assert policy_body["site"] == "W15 Site"
    assert policy_body["policy_key"].startswith("adoption_w15_efficiency_policy:site:")
    assert isinstance(policy_body["policy"], dict)
    assert "risk_rate_green_threshold" in policy_body["policy"]
    assert "risk_rate_yellow_threshold" in policy_body["policy"]
    assert "checklist_completion_green_threshold" in policy_body["policy"]
    assert "simulation_success_green_threshold" in policy_body["policy"]
    assert "readiness_target" in policy_body["policy"]

    updated = app_client.put(
        "/api/ops/adoption/w15/efficiency-policy?site=W15+Site",
        headers=manager_headers,
        json={
            "enabled": True,
            "risk_rate_green_threshold": 18,
            "risk_rate_yellow_threshold": 27,
            "checklist_completion_green_threshold": 85,
            "checklist_completion_yellow_threshold": 70,
            "simulation_success_green_threshold": 88,
            "simulation_success_yellow_threshold": 72,
            "readiness_target": 82,
        },
    )
    assert updated.status_code == 200
    updated_policy = updated.json()["policy"]
    assert updated_policy["risk_rate_green_threshold"] == 18.0
    assert updated_policy["risk_rate_yellow_threshold"] == 27.0
    assert updated_policy["checklist_completion_green_threshold"] == 85.0
    assert updated_policy["checklist_completion_yellow_threshold"] == 70.0
    assert updated_policy["simulation_success_green_threshold"] == 88.0
    assert updated_policy["simulation_success_yellow_threshold"] == 72.0
    assert updated_policy["readiness_target"] == 82.0

    global_policy_forbidden = app_client.get(
        "/api/ops/adoption/w15/efficiency-policy",
        headers=manager_headers,
    )
    assert global_policy_forbidden.status_code == 403

    global_update_forbidden = app_client.put(
        "/api/ops/adoption/w15/efficiency-policy",
        headers=manager_headers,
        json={"enabled": False},
    )
    assert global_update_forbidden.status_code == 403

    bootstrap = app_client.post(
        "/api/adoption/w15/tracker/bootstrap",
        headers=manager_headers,
        json={"site": "W15 Site"},
    )
    assert bootstrap.status_code == 200
    bootstrap_body = bootstrap.json()
    assert bootstrap_body["site"] == "W15 Site"
    assert bootstrap_body["total_count"] >= 14

    complete_gate_fail = app_client.post(
        "/api/adoption/w15/tracker/complete",
        headers=manager_headers,
        json={"site": "W15 Site", "completion_note": "attempt normal close"},
    )
    assert complete_gate_fail.status_code == 409

    listed = app_client.get(
        "/api/adoption/w15/tracker/items?site=W15+Site&limit=500",
        headers=manager_headers,
    )
    assert listed.status_code == 200
    items = listed.json()
    assert len(items) >= 14

    required_item_id: int | None = None
    downloaded_evidence_id: int | None = None
    for row in items:
        item_id = int(row["id"])
        patched = app_client.patch(
            f"/api/adoption/w15/tracker/items/{item_id}",
            headers=manager_headers,
            json={
                "assignee": "Ops Efficiency QA",
                "status": "done",
                "completion_checked": True,
                "completion_note": "W15 completed in CI",
            },
        )
        assert patched.status_code == 200
        assert patched.json()["status"] == "done"
        assert patched.json()["completion_checked"] is True

        if row["item_type"] in {"self_serve_guide", "troubleshooting_runbook"}:
            if required_item_id is None:
                required_item_id = item_id
            uploaded = app_client.post(
                f"/api/adoption/w15/tracker/items/{item_id}/evidence",
                headers=manager_headers,
                data={"note": "w15 proof"},
                files={"file": (f"w15-{item_id}.txt", f"proof {item_id}".encode("utf-8"), "text/plain")},
            )
            assert uploaded.status_code == 201
            if downloaded_evidence_id is None:
                downloaded_evidence_id = uploaded.json()["id"]

    assert required_item_id is not None
    assert downloaded_evidence_id is not None

    evidence_list = app_client.get(
        f"/api/adoption/w15/tracker/items/{required_item_id}/evidence",
        headers=manager_headers,
    )
    assert evidence_list.status_code == 200
    assert len(evidence_list.json()) >= 1

    downloaded = app_client.get(
        f"/api/adoption/w15/tracker/evidence/{downloaded_evidence_id}/download",
        headers=manager_headers,
    )
    assert downloaded.status_code == 200
    assert len(downloaded.headers["x-evidence-sha256"]) == 64

    readiness = app_client.get(
        "/api/adoption/w15/tracker/readiness?site=W15+Site",
        headers=manager_headers,
    )
    assert readiness.status_code == 200
    readiness_body = readiness.json()
    assert readiness_body["ready"] is True
    assert readiness_body["pending_count"] == 0
    assert readiness_body["in_progress_count"] == 0
    assert readiness_body["blocked_count"] == 0
    assert readiness_body["missing_assignee_count"] == 0
    assert readiness_body["missing_completion_checked_count"] == 0
    assert readiness_body["missing_required_evidence_count"] == 0

    completed = app_client.post(
        "/api/adoption/w15/tracker/complete",
        headers=manager_headers,
        json={"site": "W15 Site", "completion_note": "W15 tracker complete"},
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"
    assert completed.json()["readiness"]["ready"] is True

    completion = app_client.get(
        "/api/adoption/w15/tracker/completion?site=W15+Site",
        headers=manager_headers,
    )
    assert completion.status_code == 200
    assert completion.json()["status"] == "completed"

    bootstrap_outside = app_client.post(
        "/api/adoption/w15/tracker/bootstrap",
        headers=_owner_headers(),
        json={"site": "Outside W15 Site"},
    )
    assert bootstrap_outside.status_code == 200

    forbidden_snapshot = app_client.get(
        "/api/ops/adoption/w15/ops-efficiency?site=Outside+W15+Site&days=30",
        headers=manager_headers,
    )
    assert forbidden_snapshot.status_code == 403

    forbidden_tracker = app_client.get(
        "/api/adoption/w15/tracker/overview?site=Outside+W15+Site",
        headers=manager_headers,
    )
    assert forbidden_tracker.status_code == 403

def test_w07_weekly_run_respects_cooldown(app_client: TestClient) -> None:
    import app.database as db_module
    from sqlalchemy import insert

    created = app_client.post(
        "/api/admin/users",
        headers=_owner_headers(),
        json={
            "username": "w07_cooldown_manager_ci",
            "display_name": "W07 Cooldown Manager CI",
            "role": "manager",
            "permissions": [],
            "site_scope": ["W07 Cooldown Site"],
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    issued = app_client.post(
        f"/api/admin/users/{user_id}/tokens",
        headers=_owner_headers(),
        json={"label": "w07-cooldown-manager-token"},
    )
    assert issued.status_code == 201
    manager_headers = {"X-Admin-Token": issued.json()["token"]}

    work_order = app_client.post(
        "/api/work-orders",
        headers=manager_headers,
        json={
            "title": "W07 cooldown overdue",
            "description": "degradation input",
            "site": "W07 Cooldown Site",
            "location": "C7",
            "priority": "critical",
            "due_at": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat(),
        },
    )
    assert work_order.status_code == 201

    now = datetime.now(timezone.utc)
    with db_module.get_conn() as conn:
        conn.execute(
            insert(db_module.alert_deliveries).values(
                event_type="adoption_w07_quality_degradation",
                target="http://example.invalid/hook",
                status="warning",
                error="seed cooldown",
                payload_json='{"site":"W07 Cooldown Site","seed":true}',
                attempt_count=1,
                last_attempt_at=now,
                created_at=now,
                updated_at=now,
            )
        )

    run = app_client.post(
        "/api/ops/adoption/w07/sla-quality/run-weekly?site=W07+Cooldown+Site&days=14",
        headers=manager_headers,
    )
    assert run.status_code == 200
    body = run.json()
    assert body["site"] == "W07 Cooldown Site"
    assert body["degradation"]["degraded"] is True
    assert body["cooldown_active"] is True
    assert body["alert_attempted"] is False
    assert body["cooldown_remaining_minutes"] >= 1

def test_tutorial_simulator_session_flow(app_client: TestClient) -> None:
    public_payload = app_client.get("/api/public/tutorial-simulator")
    assert public_payload.status_code == 200
    body = public_payload.json()
    assert body["public"] is True
    assert body["simulator_html"] == "/web/tutorial-simulator"
    assert body["sample_files_api"] == "/api/public/tutorial-simulator/sample-files"
    assert body["day1_onboarding_api"] == "/api/public/onboarding/day1"
    assert body["glossary_api"] == "/api/public/glossary"
    assert body["session_list_api"] == "/api/ops/tutorial-simulator/sessions"
    assert body["default_site"] == "Tutorial-HQ"
    assert body["quickstart"]["definition_of_done"] == "progress.status=completed and completion_percent=100"
    assert len(body["sample_files"]) >= 4
    assert any(item["id"] == "ts-core-01" for item in body["scenarios"])

    onboarding_payload = app_client.get("/api/public/onboarding/day1")
    assert onboarding_payload.status_code == 200
    onboarding_body = onboarding_payload.json()
    assert onboarding_body["public"] is True
    assert onboarding_body["tutorial_simulator_html"] == "/web/tutorial-simulator"
    assert onboarding_body["glossary_api"] == "/api/public/glossary"
    assert onboarding_body["checklist_count"] >= 5
    assert onboarding_body["role_guide_count"] >= 4
    assert any(item["id"] == "create-inspection" for item in onboarding_body["day1_checklist"])
    assert any(item["role"] == "owner" for item in onboarding_body["role_guides"])

    glossary_payload = app_client.get("/api/public/glossary")
    assert glossary_payload.status_code == 200
    glossary_body = glossary_payload.json()
    assert glossary_body["public"] is True
    assert glossary_body["count"] >= 8
    assert any(item["term"] == "SLA" for item in glossary_body["items"])
    assert any(item["term_ko"] == "작업지시" for item in glossary_body["items"])
    assert any(item["id"] == "compliance" for item in glossary_body["categories"])

    sample_files = app_client.get("/api/public/tutorial-simulator/sample-files")
    assert sample_files.status_code == 200
    sample_files_body = sample_files.json()
    assert sample_files_body["public"] is True
    assert sample_files_body["count"] >= 4
    assert len(sample_files_body["items"]) >= 4
    sample_lookup = {str(item["sample_id"]): item for item in sample_files_body["items"]}
    assert "ts-core-01-session-start" in sample_lookup
    assert "ts-core-01-practice-checklist" in sample_lookup

    start_sample_download = app_client.get(sample_lookup["ts-core-01-session-start"]["download_url"])
    assert start_sample_download.status_code == 200
    assert start_sample_download.headers["content-type"].startswith("application/json")
    assert '"scenario_id": "ts-core-01"' in start_sample_download.text

    checklist_sample_download = app_client.get(sample_lookup["ts-core-01-practice-checklist"]["download_url"])
    assert checklist_sample_download.status_code == 200
    assert checklist_sample_download.headers["content-type"].startswith("text/markdown")
    assert "Tutorial Simulator Checklist" in checklist_sample_download.text

    public_html = app_client.get("/api/public/tutorial-simulator", headers={"Accept": "text/html"})
    assert public_html.status_code == 200
    assert public_html.headers.get("content-type", "").startswith("text/html")
    assert "Tutorial Simulator" in public_html.text
    assert "샘플 파일 API" in public_html.text
    assert "세션 실습 실행" in public_html.text

    simulator_html = app_client.get("/web/tutorial-simulator")
    assert simulator_html.status_code == 200
    assert simulator_html.headers.get("content-type", "").startswith("text/html")
    assert "Tutorial Simulator" in simulator_html.text
    assert "사용 설명서 열기" in simulator_html.text
    assert "/web/tutorial-guide" in simulator_html.text
    assert "세션 시작: 선택한 시나리오와 site로 신규 실습 세션을 시작합니다." in simulator_html.text
    assert "ACK 실행: 현재 세션의 작업지시를 ACK 처리합니다." in simulator_html.text
    assert "완료 판정: 현재 세션의 완료율과 단계 충족 여부를 점검합니다." in simulator_html.text

    start = app_client.post(
        "/api/ops/tutorial-simulator/sessions/start",
        headers=_owner_headers(),
        json={"scenario_id": "ts-core-01", "site": "Tutorial Site"},
    )
    assert start.status_code == 200
    start_body = start.json()
    session_id = int(start_body["session_id"])
    work_order_id = int(start_body["seed"]["work_order_id"])
    assert start_body["site"] == "Tutorial Site"
    assert start_body["scenario"]["id"] == "ts-core-01"
    assert int(start_body["progress"]["completion_percent"]) >= 40
    assert start_body["practice_commands"]["ack_work_order"]["url"].endswith(f"/api/work-orders/{work_order_id}/ack")

    session_view = app_client.get(
        f"/api/ops/tutorial-simulator/sessions/{session_id}",
        headers=_owner_headers(),
    )
    assert session_view.status_code == 200
    assert int(session_view.json()["session_id"]) == session_id

    check_before = app_client.post(
        f"/api/ops/tutorial-simulator/sessions/{session_id}/check",
        headers=_owner_headers(),
    )
    assert check_before.status_code == 200
    assert "checked_at" in check_before.json()

    ack_result = app_client.post(
        f"/api/ops/tutorial-simulator/sessions/{session_id}/actions/ack_work_order",
        headers=_owner_headers(),
        json={"assignee": "Ops QA"},
    )
    assert ack_result.status_code == 200
    assert ack_result.json()["work_order_status"] in {"acked", "completed"}

    complete_result = app_client.post(
        f"/api/ops/tutorial-simulator/sessions/{session_id}/actions/complete_work_order",
        headers=_owner_headers(),
        json={"resolution_notes": "tutorial finished"},
    )
    assert complete_result.status_code == 200
    assert complete_result.json()["work_order_status"] == "completed"

    check_after = app_client.post(
        f"/api/ops/tutorial-simulator/sessions/{session_id}/check",
        headers=_owner_headers(),
    )
    assert check_after.status_code == 200
    check_after_body = check_after.json()
    assert check_after_body["progress"]["status"] == "completed"
    assert int(check_after_body["progress"]["completion_percent"]) == 100

    list_resp = app_client.get(
        "/api/ops/tutorial-simulator/sessions?limit=5",
        headers=_owner_headers(),
    )
    assert list_resp.status_code == 200
    list_body = list_resp.json()
    assert int(list_body["count"]) >= 1
    assert any(int(item["session_id"]) == session_id for item in list_body["items"])
