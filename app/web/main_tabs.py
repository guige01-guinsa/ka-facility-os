"""Main tabs HTML renderers extracted from app.main."""

from __future__ import annotations

import html
import json
from typing import Any


def _load_ops_special_checklists_payload() -> dict[str, Any]:
    from app.domains.ops.checklist_runtime import _load_ops_special_checklists_payload as payload_builder

    return payload_builder()


def build_shared_tracker_execution_box_html(phase_code: str, phase_label: str) -> str:
    code = phase_code.lower()
    label = phase_label.upper()
    return f"""
          <div class="box">
            <h3>{label} 실행 추적 (완료 체크 / 담당자 / 증빙 업로드)</h3>
            <div class="filter-row">
              <input id="{code}TrackSite" placeholder="site (필수, 예: HQ)" />
              <input id="{code}TrackItemId" placeholder="tracker_item_id(숫자)" />
              <input id="{code}TrackAssignee" placeholder="담당자" />
              <select id="{code}TrackStatus">
                <option value="">status(선택)</option>
                <option value="pending">pending</option>
                <option value="in_progress">in_progress</option>
                <option value="done">done</option>
                <option value="blocked">blocked</option>
              </select>
              <button id="{code}TrackBootstrapBtn" class="btn run" type="button">{label} 항목 생성</button>
            </div>
            <div class="filter-row">
              <label style="display:flex; align-items:center; gap:6px; font-size:12px;">
                <input id="{code}TrackCompleted" type="checkbox" />
                완료 체크
              </label>
              <input id="{code}TrackNote" placeholder="완료 메모(선택)" />
              <input id="{code}EvidenceNote" placeholder="증빙 메모(선택)" />
              <input id="{code}EvidenceFile" type="file" />
              <button id="{code}TrackUpdateBtn" class="btn" type="button">상태 저장</button>
            </div>
            <div class="filter-row">
              <input id="{code}EvidenceListItemId" placeholder="evidence 조회용 tracker_item_id(숫자)" />
              <input id="{code}Reserved1" value="쓰기 작업에는 토큰 필요" disabled />
              <input id="{code}Reserved2" value="site 범위 권한 적용" disabled />
              <input id="{code}Reserved3" value="파일 최대 5MB" disabled />
              <button id="{code}TrackRefreshBtn" class="btn run" type="button">추적현황 새로고침</button>
            </div>
            <div class="filter-row">
              <input id="{code}CompletionNote" placeholder="완료 메모(선택)" />
              <label style="display:flex; align-items:center; gap:6px; font-size:12px;">
                <input id="{code}CompletionForce" type="checkbox" />
                강제 완료(owner/admin)
              </label>
              <input id="{code}Reserved4" value="준비도 게이트 필요" disabled />
              <button id="{code}ReadinessBtn" class="btn run" type="button">완료 판정</button>
              <button id="{code}CompleteBtn" class="btn" type="button">{label} 완료 확정</button>
            </div>
            <div id="{code}TrackerMeta" class="meta">조회 전</div>
            <div id="{code}TrackerSummary" class="cards"></div>
            <div id="{code}TrackerTable" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">{label} 완료 판정 결과</h4>
            <div id="{code}ReadinessMeta" class="meta">조회 전</div>
            <div id="{code}ReadinessCards" class="cards"></div>
            <div id="{code}ReadinessBlockers" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">증빙 파일 목록</h4>
            <div id="{code}EvidenceTable" class="empty">데이터 없음</div>
          </div>
"""

_build_shared_tracker_execution_box_html = build_shared_tracker_execution_box_html

def build_system_main_tabs_html(service_info: dict[str, str], *, initial_tab: str) -> str:
    allowed_tabs = {"overview", "workorders", "inspections", "billing", "documents", "reports", "iam", "adoption", "tutorial"}
    selected_tab = initial_tab if initial_tab in allowed_tabs else "overview"
    w02_tracker_box_html = _build_shared_tracker_execution_box_html("w02", "W02")
    w03_tracker_box_html = _build_shared_tracker_execution_box_html("w03", "W03")
    w04_tracker_box_html = _build_shared_tracker_execution_box_html("w04", "W04")
    w09_tracker_box_html = _build_shared_tracker_execution_box_html("w09", "W09")
    w10_tracker_box_html = _build_shared_tracker_execution_box_html("w10", "W10")
    w11_tracker_box_html = _build_shared_tracker_execution_box_html("w11", "W11")
    w15_tracker_box_html = _build_shared_tracker_execution_box_html("w15", "W15")
    ops_special_checklists_payload = _load_ops_special_checklists_payload()
    ops_special_checklists_json = json.dumps(ops_special_checklists_payload, ensure_ascii=False)
    return f"""
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>KA Facility OS - Main</title>
  <style>
    :root {{
      --ink: #0d203b;
      --muted: #496081;
      --line: #d6e1ef;
      --bg: #f4f8ff;
      --card: #fff;
      --brand: #0e6f5d;
      --accent: #d25c2e;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      font-family: "SUIT", "Pretendard", "IBM Plex Sans KR", "Noto Sans KR", sans-serif;
      background:
        radial-gradient(860px 320px at 10% -20%, #ddf6ff 0%, transparent 58%),
        radial-gradient(760px 320px at 95% -20%, #ffedd7 0%, transparent 58%),
        var(--bg);
    }}
    .wrap {{ max-width: 1300px; margin: 0 auto; padding: 18px 14px 44px; }}
    .hero {{
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 16px;
      background: linear-gradient(140deg, #fff 0%, #eef8f5 54%, #fff4e8 100%);
      box-shadow: 0 10px 26px rgba(12, 34, 64, 0.08);
    }}
    .hero h1 {{ margin: 0; font-size: 26px; }}
    .hero p {{ margin: 8px 0 0; color: var(--muted); }}
    .links {{
      margin-top: 10px;
      display: flex;
      flex-wrap: wrap;
      gap: 7px;
    }}
    .links a {{
      text-decoration: none;
      border: 1px solid #b9cfe8;
      border-radius: 999px;
      padding: 6px 10px;
      font-size: 12px;
      font-weight: 700;
      color: #1f4f7e;
      background: #f3f8ff;
    }}
    .tabs {{
      margin-top: 14px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: var(--card);
      overflow: hidden;
    }}
    .tab-head {{
      display: flex;
      flex-wrap: wrap;
      gap: 0;
      border-bottom: 1px solid #e4edf8;
      background: #f8fbff;
    }}
    .tab-btn {{
      appearance: none;
      border: 0;
      border-right: 1px solid #e4edf8;
      background: transparent;
      color: #35587f;
      font-size: 14px;
      font-weight: 800;
      padding: 12px 14px;
      cursor: pointer;
    }}
    .tab-btn.active {{
      color: #0b5f4e;
      background: #ebfaf5;
      box-shadow: inset 0 -2px 0 #77c7b4;
    }}
    [data-tip] {{
      position: relative;
    }}
    [data-tip]::after {{
      content: attr(data-tip);
      position: absolute;
      left: 50%;
      top: calc(100% + 8px);
      transform: translateX(-50%) translateY(-3px);
      opacity: 0;
      pointer-events: none;
      z-index: 40;
      width: max-content;
      max-width: 280px;
      border: 1px solid #b8cde6;
      border-radius: 10px;
      background: #ffffff;
      color: #1f456d;
      box-shadow: 0 10px 20px rgba(13, 40, 70, 0.12);
      font-size: 12px;
      font-weight: 700;
      line-height: 1.35;
      padding: 7px 9px;
      white-space: normal;
      text-align: left;
      transition: opacity 130ms ease, transform 130ms ease;
    }}
    [data-tip]::before {{
      content: "";
      position: absolute;
      left: 50%;
      top: calc(100% + 2px);
      transform: translateX(-50%);
      border-left: 6px solid transparent;
      border-right: 6px solid transparent;
      border-bottom: 6px solid #b8cde6;
      opacity: 0;
      pointer-events: none;
      transition: opacity 130ms ease;
      z-index: 41;
    }}
    [data-tip]:hover::after,
    [data-tip]:focus-visible::after {{
      opacity: 1;
      transform: translateX(-50%) translateY(0);
    }}
    [data-tip]:hover::before,
    [data-tip]:focus-visible::before {{
      opacity: 1;
    }}
    .shell {{
      padding: 12px;
    }}
    .auth-row {{
      display: grid;
      grid-template-columns: 1fr auto auto auto;
      gap: 8px;
      margin-bottom: 9px;
    }}
    .auth-actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 9px;
    }}
    .auth-row input, .filter-row input {{
      width: 100%;
      border: 1px solid #c8d8ec;
      border-radius: 10px;
      padding: 8px 10px;
      font-size: 13px;
      color: var(--ink);
      background: #fff;
    }}
    .filter-row select {{
      width: 100%;
      border: 1px solid #c8d8ec;
      border-radius: 10px;
      padding: 8px 10px;
      font-size: 13px;
      color: var(--ink);
      background: #fff;
    }}
    .auth-dialog-grid input, .auth-dialog-grid select {{
      width: 100%;
      border: 1px solid #c8d8ec;
      border-radius: 10px;
      padding: 8px 10px;
      font-size: 13px;
      color: var(--ink);
      background: #fff;
    }}
    .auth-backdrop {{
      position: fixed;
      inset: 0;
      background: rgba(9, 21, 37, 0.45);
      z-index: 10000;
    }}
    .auth-dialog {{
      position: fixed;
      inset: 0;
      z-index: 10001;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px;
    }}
    .auth-backdrop[hidden], .auth-dialog[hidden] {{
      display: none;
    }}
    .auth-dialog-card {{
      width: min(760px, 100%);
      border: 1px solid #c5d8ed;
      border-radius: 12px;
      background: #fff;
      box-shadow: 0 20px 36px rgba(10, 33, 59, 0.24);
      padding: 14px;
    }}
    .auth-dialog-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 10px;
    }}
    .auth-dialog-head h3 {{
      margin: 0;
      font-size: 16px;
      color: #0c614f;
    }}
    .auth-dialog-grid {{
      display: grid;
      gap: 8px;
    }}
    .auth-dialog-grid.login {{
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) minmax(0, 180px) auto;
    }}
    .auth-dialog-grid.signup {{
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) minmax(0, 1fr) minmax(0, 140px) minmax(0, 160px) auto;
    }}
    .btn {{
      border: 1px solid #97badf;
      border-radius: 10px;
      padding: 8px 10px;
      background: #f2f8ff;
      color: #1f4e7c;
      font-size: 12px;
      font-weight: 800;
      cursor: pointer;
      white-space: nowrap;
    }}
    .btn:hover {{ background: #e7f2ff; }}
    .btn.run {{
      border-color: #84cab6;
      color: #0c614f;
      background: #e9f8f2;
    }}
    .btn.run:hover {{ background: #e0f5ed; }}
    .btn.soft {{
      border-color: #c3d6ea;
      color: #2f567c;
      background: #f7fbff;
    }}
    .btn.soft:hover {{ background: #eef6ff; }}
    .auth-state {{
      margin-bottom: 12px;
      border: 1px solid #c7d8ee;
      border-radius: 10px;
      background: #f2f8ff;
      color: #264b70;
      font-size: 12px;
      padding: 7px 8px;
    }}
    .tab-panel {{
      display: none;
      animation: fadeup 200ms ease-out both;
    }}
    .tab-panel.active {{ display: block; }}
    .tab-caption {{
      margin: 0 0 10px;
      color: var(--muted);
      font-size: 13px;
    }}
    .filter-row {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr)) auto;
      gap: 8px;
      margin-bottom: 10px;
    }}
    .ops-form-grid {{
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 8px;
      margin-bottom: 10px;
    }}
    .ops-form-grid input, .ops-form-grid select, .ops-form-grid textarea {{
      width: 100%;
      border: 1px solid #c8d8ec;
      border-radius: 10px;
      padding: 8px 10px;
      font-size: 13px;
      color: var(--ink);
      background: #fff;
    }}
    .ops-form-grid textarea {{
      min-height: 74px;
      resize: vertical;
    }}
    .ops-form-grid .span-2 {{
      grid-column: span 2;
    }}
    .ops-form-grid .span-3 {{
      grid-column: span 3;
    }}
    .ops-form-grid .span-5 {{
      grid-column: span 5;
    }}
    .ops-inline-label {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
      color: #2b4f77;
      border: 1px solid #c8d8ec;
      border-radius: 10px;
      background: #f8fbff;
      padding: 8px 10px;
      min-height: 36px;
      white-space: nowrap;
    }}
    .ops-inline-label input[type="checkbox"] {{
      margin: 0;
    }}
    .ops-checklist-actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 8px;
    }}
    .ops-checklist-summary {{
      margin-bottom: 8px;
      font-size: 12px;
      color: #32567b;
    }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 8px;
      margin-bottom: 10px;
    }}
    .card {{
      border: 1px solid #d8e4f4;
      border-radius: 10px;
      background: #fff;
      padding: 10px;
    }}
    .card .k {{ color: var(--muted); font-size: 12px; }}
    .card .v {{ margin-top: 4px; font-size: 22px; font-weight: 800; }}
    .card .sub {{ margin-top: 6px; font-size: 12px; color: #35587f; }}
    .card.status-ok {{ border-color: #9ed9c3; background: #effaf4; }}
    .card.status-warning {{ border-color: #f3d59e; background: #fff7ea; }}
    .card.status-critical {{ border-color: #e8a8aa; background: #fff1f2; }}
    .card.status-info {{ border-color: #d0ddf0; background: #f5f9ff; }}
    .status-chip {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 800;
      border: 1px solid #bdd3eb;
      color: #2a5680;
      background: #f3f8ff;
    }}
    .status-chip.ok {{ border-color: #8ecfb4; color: #0d654f; background: #e8f8f1; }}
    .status-chip.warning {{ border-color: #e9c786; color: #926016; background: #fff6e6; }}
    .status-chip.critical {{ border-color: #e09ca0; color: #9a2e36; background: #fff0f1; }}
    .status-chip.info {{ border-color: #bdd3eb; color: #2a5680; background: #f3f8ff; }}
    .w07-readiness-card {{
      cursor: pointer;
      transition: transform 140ms ease, box-shadow 140ms ease, border-color 140ms ease;
    }}
    .w07-readiness-card:hover {{
      transform: translateY(-1px);
      box-shadow: 0 8px 16px rgba(28, 62, 102, 0.09);
    }}
    .w07-readiness-card.active {{
      border-color: #5f9dd8;
      box-shadow: 0 0 0 2px rgba(95, 157, 216, 0.2);
    }}
    .w07-track-row {{
      cursor: pointer;
    }}
    .w07-track-row.active {{
      background: #eaf5ff;
    }}
    .w07-track-row td:first-child {{
      width: 36px;
    }}
    .w07-filter-hint {{
      margin-bottom: 8px;
      border: 1px solid #c7d8ee;
      border-radius: 8px;
      background: #f2f8ff;
      color: #264b70;
      font-size: 12px;
      padding: 6px 8px;
    }}
    .dropzone {{
      border: 1px dashed #8ab5de;
      border-radius: 10px;
      padding: 10px;
      font-size: 12px;
      color: #35587f;
      background: #f7fbff;
      text-align: center;
      cursor: pointer;
      user-select: none;
    }}
    .dropzone.dragover {{
      border-color: #0f6a57;
      background: #e8f7f1;
      color: #0f6a57;
    }}
    .modal {{
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 16px;
      z-index: 9999;
      background: rgba(9, 21, 37, 0.45);
    }}
    .modal.open {{
      display: flex;
    }}
    .modal-card {{
      width: min(640px, 100%);
      border: 1px solid #c5d8ed;
      border-radius: 12px;
      background: #fff;
      box-shadow: 0 20px 36px rgba(10, 33, 59, 0.24);
      padding: 14px;
    }}
    .modal-card h4 {{
      margin: 0 0 8px;
      font-size: 16px;
      color: #0c614f;
    }}
    .modal-actions {{
      margin-top: 10px;
      display: flex;
      justify-content: flex-end;
      gap: 8px;
    }}
    .box {{
      border: 1px solid #d8e4f4;
      border-radius: 10px;
      background: #fff;
      padding: 10px;
      margin-bottom: 10px;
    }}
    .box h3 {{ margin: 0 0 8px; font-size: 15px; color: #0b6150; }}
    .table-wrap {{
      overflow: auto;
      border: 1px solid #dbe6f5;
      border-radius: 10px;
      background: #fff;
    }}
    table {{
      border-collapse: collapse;
      width: 100%;
      min-width: 720px;
      font-size: 12px;
    }}
    th, td {{
      border-bottom: 1px solid #edf3fb;
      text-align: left;
      padding: 8px;
      vertical-align: top;
      word-break: break-word;
    }}
    th {{ background: #f7fbff; color: #274c75; }}
    .empty {{
      border: 1px dashed #c5d8ee;
      border-radius: 10px;
      padding: 14px;
      text-align: center;
      color: var(--muted);
      background: #f8fbff;
      font-size: 13px;
    }}
    .meta {{
      margin-bottom: 10px;
      border: 1px solid #c7d8ee;
      border-radius: 10px;
      background: #f2f8ff;
      color: #264b70;
      font-size: 12px;
      padding: 7px 8px;
    }}
    .mini-links {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 8px;
    }}
    .mini-links a {{
      text-decoration: none;
      border: 1px solid #bdd3eb;
      border-radius: 8px;
      padding: 5px 8px;
      font-size: 11px;
      font-weight: 700;
      color: #235281;
      background: #f3f8ff;
    }}
    .adopt-grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
    }}
    .mono {{
      margin: 8px 0 0;
      max-height: 280px;
      overflow: auto;
      border: 1px solid #dbe6f5;
      border-radius: 10px;
      background: #f7fbff;
      padding: 10px;
      font-family: "Consolas", "D2Coding", "IBM Plex Mono", monospace;
      font-size: 12px;
      white-space: pre-wrap;
      word-break: break-word;
      color: #224a72;
    }}
    @keyframes fadeup {{
      from {{ opacity: 0; transform: translateY(8px); }}
      to {{ opacity: 1; transform: translateY(0); }}
    }}
    @media (max-width: 900px) {{
      .hero h1 {{ font-size: 21px; }}
      .tab-btn {{ font-size: 13px; padding: 10px; }}
      .auth-row {{ grid-template-columns: 1fr; }}
      .filter-row {{ grid-template-columns: 1fr; }}
      .ops-form-grid {{ grid-template-columns: 1fr; }}
      .ops-form-grid .span-2, .ops-form-grid .span-3, .ops-form-grid .span-5 {{ grid-column: auto; }}
      .cards {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .adopt-grid {{ grid-template-columns: 1fr; }}
      .auth-dialog-grid.login {{ grid-template-columns: 1fr; }}
      .auth-dialog-grid.signup {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <header class="hero">
      <h1>시설관리시스템 메인</h1>
      <p>단일 셸 기반 운영 화면입니다. 탭 전환 시 같은 페이지에서 데이터를 즉시 조회하며, 링크 공유를 위해 탭 URL 상태도 유지합니다.</p>
      <div class="links">
        <a href="{html.escape(service_info.get("docs", "/docs"))}">스웨거 문서</a>
        <a href="/api/service-info">서비스 정보</a>
        <a href="/web/complaints">세대 민원처리</a>
        <a href="/web/console">레거시 콘솔</a>
        <a href="/web/adoption">레거시 정착 계획</a>
        <a href="/web/tutorial-simulator">튜토리얼</a>
      </div>
    </header>

    <section class="tabs">
      <div class="tab-head" role="tablist" aria-label="메인 탭">
        <button class="tab-btn" type="button" role="tab" data-tab="overview" data-tip="Overview(운영요약): SLA·알림·작업현황 핵심지표를 한눈에 봅니다." title="Overview(운영요약): SLA·알림·작업현황 핵심지표를 한눈에 봅니다.">운영요약</button>
        <button class="tab-btn" type="button" role="tab" data-tab="workorders" data-tip="Work Orders(작업지시): 작업 생성·진행·완료 상태를 관리합니다." title="Work Orders(작업지시): 작업 생성·진행·완료 상태를 관리합니다.">작업지시</button>
        <button class="tab-btn" type="button" role="tab" data-tab="inspections" data-tip="Inspections(점검): 전기·소방 점검 입력과 이력을 관리합니다." title="Inspections(점검): 전기·소방 점검 입력과 이력을 관리합니다.">점검</button>
        <button class="tab-btn" type="button" role="tab" data-tab="billing" data-tip="Billing(요금부과): 전기·수도 검침, 공용요금 면적배부, 월 부과를 관리합니다." title="Billing(요금부과): 전기·수도 검침, 공용요금 면적배부, 월 부과를 관리합니다.">요금부과</button>
        <button class="tab-btn" type="button" role="tab" data-tab="documents" data-tip="Official Documents(공문관리): 기관별 공문 접수, 작업 연동, 종결보고서를 관리합니다." title="Official Documents(공문관리): 기관별 공문 접수, 작업 연동, 종결보고서를 관리합니다.">공문관리</button>
        <button class="tab-btn" type="button" role="tab" data-tab="reports" data-tip="Reports(월간리포트): 월간 집계와 출력(PDF/CSV)을 실행합니다." title="Reports(월간리포트): 월간 집계와 출력(PDF/CSV)을 실행합니다.">월간리포트</button>
        <button class="tab-btn" type="button" role="tab" data-tab="iam" data-tip="IAM(권한관리): 로그인·사용자·토큰·감사로그를 관리합니다." title="IAM(권한관리): 로그인·사용자·토큰·감사로그를 관리합니다.">권한관리</button>
        <button class="tab-btn" type="button" role="tab" data-tab="adoption" data-tip="Adoption(정착계획): 주차별 실행표와 교육자료를 확인합니다." title="Adoption(정착계획): 주차별 실행표와 교육자료를 확인합니다.">사용자 정착 계획</button>
        <button class="tab-btn" type="button" role="tab" data-tab="tutorial" data-tip="Tutorial(튜토리얼): 신규 사용자 실습 시나리오를 실행합니다." title="Tutorial(튜토리얼): 신규 사용자 실습 시나리오를 실행합니다.">튜토리얼</button>
      </div>
      <div class="shell">
        <div class="auth-row">
          <input id="adminTokenInput" type="password" placeholder="X-Admin-Token 입력" autocomplete="off" autocapitalize="off" spellcheck="false" />
          <button id="saveTokenBtn" class="btn" type="button">토큰 저장</button>
          <button id="testTokenBtn" class="btn run" type="button">권한 확인</button>
          <button id="clearTokenBtn" class="btn" type="button">토큰 지우기</button>
        </div>
        <div class="auth-actions">
          <button id="openLoginModalBtn" class="btn run" type="button">ID/PW 로그인</button>
          <button id="openSignupModalBtn" class="btn run" type="button">사용자 신규가입</button>
          <button id="logoutBtn" class="btn" type="button">로그아웃</button>
        </div>
        <div id="authState" class="auth-state">토큰 상태: 없음</div>
        <div id="authModalBackdrop" class="auth-backdrop" hidden></div>
        <section id="authLoginModal" class="auth-dialog" role="dialog" aria-modal="true" aria-labelledby="authLoginModalTitle" hidden>
          <div class="auth-dialog-card">
            <div class="auth-dialog-head">
              <h3 id="authLoginModalTitle">ID/PW 로그인</h3>
              <button id="closeLoginModalBtn" class="btn" type="button">닫기</button>
            </div>
            <div class="auth-dialog-grid login">
              <input id="loginUsernameInput" placeholder="username" autocomplete="username" />
              <input id="loginPasswordInput" type="password" placeholder="password" autocomplete="current-password" />
              <input id="loginTokenLabelInput" value="web-login" placeholder="token label" />
              <button id="loginBtn" class="btn run" type="button">로그인 실행</button>
            </div>
          </div>
        </section>
        <section id="authSignupModal" class="auth-dialog" role="dialog" aria-modal="true" aria-labelledby="authSignupModalTitle" hidden>
          <div class="auth-dialog-card">
            <div class="auth-dialog-head">
              <h3 id="authSignupModalTitle">사용자 신규가입</h3>
              <button id="closeSignupModalBtn" class="btn" type="button">닫기</button>
            </div>
            <div class="auth-dialog-grid signup">
              <input id="signupUsernameInput" placeholder="new username" autocomplete="username" />
              <input id="signupPasswordInput" type="password" placeholder="new password" autocomplete="new-password" />
              <input id="signupDisplayNameInput" placeholder="display name (optional)" />
              <select id="signupRoleInput">
                <option value="operator">operator</option>
                <option value="auditor">auditor</option>
                <option value="manager">manager</option>
                <option value="owner">owner</option>
              </select>
              <input id="signupSiteScopeInput" value="*" placeholder="site scope (comma, e.g. HQ,B1)" />
              <button id="signupBtn" class="btn run" type="button">가입 실행</button>
            </div>
          </div>
        </section>

        <div id="panelOverview" class="tab-panel" role="tabpanel">
          <p class="tab-caption">SLA/점검/알림 상태를 한 화면에서 확인합니다.</p>
          <div class="filter-row">
            <input id="ovSite" placeholder="site (optional)" />
            <input id="ovDays" value="30" placeholder="days (default 30)" />
            <input id="ovJobLimit" value="10" placeholder="job_limit (default 10)" />
            <input id="ovReserved" value="overview" disabled />
            <button id="runOverviewBtn" class="btn run" type="button">요약 새로고침</button>
          </div>
          <div id="overviewMeta" class="meta">요약 데이터를 불러오세요.</div>
          <div id="overviewCards" class="cards"></div>
          <div class="box">
            <h3>공문 기한초과 자동화</h3>
            <div id="overviewOfficialAutomationCards" class="cards"></div>
            <div id="overviewOfficialAutomationMeta" class="meta">조회 전</div>
            <div id="overviewOfficialAutomationLatest" class="empty">데이터 없음</div>
            <div class="mini-links">
              <a id="overviewOfficialOverdueStatusLink" href="/api/official-documents/overdue/status" target="_blank" rel="noopener">Overdue Status API</a>
              <a id="overviewOfficialOverdueLatestLink" href="/api/official-documents/overdue/latest" target="_blank" rel="noopener">Overdue Latest API</a>
            </div>
          </div>
          <div class="box">
            <h3>긴급 작업 상위 목록</h3>
            <div id="overviewTopWorkOrders" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>알림 채널 KPI (최근 7/30일)</h3>
            <div id="overviewAlertKpiSummary" class="cards"></div>
            <div id="overviewAlertKpiChannels" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>알림 채널 MTTR (복구시간, 최근 7/30일)</h3>
            <div id="overviewAlertMttrSummary" class="cards"></div>
            <div id="overviewAlertMttrChannels" class="empty">데이터 없음</div>
            <div class="mini-links">
              <a href="/api/ops/alerts/kpi/mttr">MTTR KPI API</a>
            </div>
          </div>
          <div class="box">
            <h3>알림 채널 보호/보관 상태</h3>
            <div id="overviewAlertGuardMeta" class="meta">조회 전</div>
            <div id="overviewAlertGuardTable" class="empty">데이터 없음</div>
            <div class="filter-row">
              <select id="overviewGuardRecoverState">
                <option value="quarantined">state=quarantined</option>
                <option value="warning">state=warning</option>
                <option value="all">state=all</option>
              </select>
              <input id="overviewGuardRecoverMaxTargets" value="20" placeholder="max_targets" />
              <button id="runOverviewGuardRecoverDryBtn" class="btn" type="button">배치복구 점검</button>
              <button id="runOverviewGuardRecoverRunBtn" class="btn run" type="button">배치복구 실행</button>
              <button id="runOverviewGuardRecoverLatestBtn" class="btn" type="button">최근 결과</button>
            </div>
            <div id="overviewGuardRecoverMeta" class="meta">복구 실행 전</div>
            <div id="overviewGuardRecoverTable" class="empty">데이터 없음</div>
            <div class="mini-links">
              <a href="/api/ops/alerts/channels/guard">Guard API</a>
              <a href="/api/ops/alerts/channels/guard/recover-batch">Guard Recover Batch API</a>
              <a href="/api/ops/alerts/channels/guard/recover/latest">Guard Recover Latest API</a>
              <a href="/api/ops/alerts/mttr-slo/policy">MTTR SLO Policy API</a>
              <a href="/api/ops/alerts/mttr-slo/check/run">MTTR SLO Run API</a>
              <a href="/api/ops/alerts/mttr-slo/check/latest">MTTR SLO Latest API</a>
              <a href="/api/ops/alerts/retention/policy">Retention Policy API</a>
              <a href="/api/ops/alerts/retention/latest">Retention Latest API</a>
            </div>
          </div>
        </div>

        <div id="panelWorkorders" class="tab-panel" role="tabpanel">
          <p class="tab-caption">작업지시 조회/상태 추적을 수행합니다.</p>
          <div class="filter-row">
            <input id="woStatus" placeholder="status (open/acked/completed/...)" />
            <input id="woSite" placeholder="site (optional)" />
            <input id="woLimit" value="20" placeholder="limit" />
            <input id="woOffset" value="0" placeholder="offset" />
            <button id="runWorkordersBtn" class="btn run" type="button">작업지시 조회</button>
          </div>
          <div id="workordersMeta" class="meta">조회 전</div>
          <div id="workordersTable" class="empty">데이터 없음</div>
        </div>

        <div id="panelInspections" class="tab-panel" role="tabpanel">
          <p class="tab-caption">OPS 법정점검(전기/소방) 입력 화면과 점검 이력 조회를 한 곳에서 운영합니다.</p>
          <div class="box">
            <h3>OPS 법정점검 입력 (체크리스트/OPS코드/QR 연동)</h3>
            <div class="ops-form-grid">
              <input id="inCreateInspectedAt" type="datetime-local" />
              <select id="inCreateTaskType">
                <option value="전기점검">업무구분: 전기점검</option>
                <option value="소방점검">업무구분: 소방점검</option>
                <option value="전기안전점검">업무구분: 전기안전점검</option>
                <option value="법정점검">업무구분: 법정점검</option>
              </select>
              <select id="inCreateCycle">
                <option value="daily">주기: 일일점검</option>
                <option value="monthly">주기: 월간점검</option>
              </select>
              <input id="inCreateSite" placeholder="site (예: HQ)" />
              <input id="inCreateInspector" placeholder="점검자 (예: kim.ops)" />
            </div>
            <div class="ops-form-grid">
              <select id="inChecklistSet">
                <option value="electrical_60">체크리스트 세트: 전기직무고시60항목</option>
              </select>
              <select id="inCreateEquipmentGroup">
                <option value="all">설비군: 전체</option>
              </select>
              <select id="inTemplateGroup">
                <option value="all">체크리스트: 전체</option>
              </select>
              <select id="inCreateOpsCode">
                <option value="">OPS코드: 선택(선택)</option>
              </select>
              <select id="inCreateQrId">
                <option value="">QR설비: 선택(선택)</option>
              </select>
              <select id="inCreateEquipmentMaster">
                <option value="">설비마스터: 선택(선택)</option>
              </select>
            </div>
            <div class="ops-form-grid">
              <input id="inCreateEquipment" placeholder="설비명 (예: 변압기 #1)" />
              <input id="inCreateEquipmentCode" placeholder="설비코드 (예: TR-001)" />
              <input id="inCreateLocation" placeholder="설비위치 (예: B1 수변전실)" />
              <input id="inCreateQrLocation" placeholder="QR설비위치 자동참조(읽기용)" disabled />
              <input id="inCreateDefaultItem" placeholder="QR기본점검항목 자동참조(읽기용)" disabled />
            </div>
            <div class="ops-form-grid">
              <input id="inCreateWindingTemp" placeholder="권선온도 C (선택)" />
              <input id="inCreateGroundingOhm" placeholder="접지저항 ohm (선택)" />
              <input id="inCreateInsulationMohm" placeholder="절연저항 Mohm (선택)" />
              <input id="inCreatePhotoFiles" type="file" multiple />
              <input id="inCreateWorkOrderAssignee" placeholder="이상조치 담당자(선택)" />
            </div>
            <div class="ops-form-grid">
              <input id="inCreatePhotoNote" class="span-5" placeholder="사진 메모(선택): 예) 단자부 열화상 / 변압기 외관 / 절연매트 상태" />
            </div>
            <div class="ops-form-grid">
              <textarea id="inCreateAbnormalAction" class="span-3" placeholder="이상조치 등록(예: 단자 재체결 후 열화상 재점검 예정)"></textarea>
              <label class="ops-inline-label">
                <input id="inCreateAutoWorkOrder" type="checkbox" />
                이상 시 작업지시 자동 등록
              </label>
              <select id="inCreateWorkOrderPriority">
                <option value="high">WO 우선순위: high</option>
                <option value="critical">WO 우선순위: critical</option>
                <option value="medium">WO 우선순위: medium</option>
                <option value="low">WO 우선순위: low</option>
              </select>
            </div>
            <div class="ops-form-grid">
              <textarea id="inCreateMemo" class="span-5" placeholder="추가 메모(선택): 환기상태/소화기 상태/작업지시 요청사항 등을 기록"></textarea>
            </div>
            <div class="ops-checklist-actions">
              <button id="inChecklistAllNormalBtn" class="btn" type="button">전체 정상</button>
              <button id="inChecklistAllNaBtn" class="btn" type="button">전체 N/A</button>
              <button id="inChecklistResetBtn" class="btn" type="button">체크리스트 재구성</button>
              <button id="inCreateInspectionBtn" class="btn run" type="button">점검 저장</button>
            </div>
            <div id="inspectionChecklistSummary" class="ops-checklist-summary">체크리스트 준비 중...</div>
            <div id="inspectionChecklistTable" class="empty">체크리스트 준비 중...</div>
            <div id="inspectionCreateMeta" class="meta">입력 대기</div>
          </div>
          <div class="box">
            <h3>점검 이력 조회</h3>
            <div class="filter-row">
              <input id="inSite" placeholder="site (optional)" />
              <input id="inLimit" value="20" placeholder="limit" />
              <input id="inOffset" value="0" placeholder="offset" />
              <input id="inReserved" value="inspections" disabled />
              <button id="runInspectionsBtn" class="btn run" type="button">점검 조회</button>
            </div>
          </div>
          <div id="inspectionsMeta" class="meta">조회 전</div>
          <div id="inspectionsTable" class="empty">데이터 없음</div>
          <div class="box">
            <h3>점검 사진/증빙 파일</h3>
            <div class="filter-row">
              <input id="inEvidenceInspectionId" placeholder="inspection_id (숫자)" />
              <input id="inEvidenceReserved1" value="POST /api/inspections/{id}/evidence" disabled />
              <input id="inEvidenceReserved2" value="GET /api/inspections/{id}/evidence" disabled />
              <input id="inEvidenceReserved3" value="download headers: X-Evidence-SHA256" disabled />
              <button id="runInspectionEvidenceBtn" class="btn run" type="button">증빙 목록 조회</button>
            </div>
            <div id="inspectionEvidenceMeta" class="meta">조회 전</div>
            <div id="inspectionEvidenceTable" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>엑셀 Import 검증 리포트</h3>
            <div class="filter-row">
              <input id="inImportValidationReserved1" value="GET /api/ops/inspections/checklists/import-validation" disabled />
              <input id="inImportValidationReserved2" value="GET /api/ops/inspections/checklists/import-validation.csv" disabled />
              <button id="runInspectionImportValidationBtn" class="btn run" type="button">검증 리포트 조회</button>
              <a id="inspectionImportValidationCsvLink" href="/api/ops/inspections/checklists/import-validation.csv" target="_blank" rel="noopener">CSV 다운로드</a>
            </div>
            <div id="inspectionImportValidationMeta" class="meta">조회 전</div>
            <div id="inspectionImportValidationSummary" class="cards"></div>
            <div id="inspectionImportValidationTable" class="empty">데이터 없음</div>
            <div id="inspectionImportValidationSuggestions" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>OPS 마스터 관리</h3>
            <div class="filter-row">
              <input id="opsMasterCatalogReserved" value="GET /api/ops/inspections/checklists/catalog" disabled />
              <input id="opsMasterEquipmentReserved" value="POST/PATCH/DELETE equipment-assets" disabled />
              <input id="opsMasterChecklistReserved" value="POST/PATCH/DELETE sets" disabled />
              <input id="opsMasterChecklistRevisionReserved" value="POST/GET revisions + submit/approve/reject" disabled />
              <input id="opsMasterQrReserved" value="POST/PATCH/DELETE qr-assets" disabled />
              <button id="runOpsMasterCatalogBtn" class="btn run" type="button">마스터 새로고침</button>
            </div>
            <div class="filter-row">
              <input id="opsMasterSearch" placeholder="검색어 (설비/세트/QR/revision)" />
              <select id="opsMasterLifecycleFilter">
                <option value="all">표시상태: all</option>
                <option value="active">표시상태: active</option>
                <option value="retired">표시상태: retired</option>
                <option value="replaced">표시상태: replaced</option>
              </select>
              <select id="opsMasterRevisionStatusFilter">
                <option value="all">개정안상태: all</option>
                <option value="draft">개정안상태: draft</option>
                <option value="pending">개정안상태: pending</option>
                <option value="approved">개정안상태: approved</option>
                <option value="rejected">개정안상태: rejected</option>
              </select>
            </div>
            <div class="ops-form-grid">
              <input id="opsMasterEquipmentId" placeholder="equipment_id (수정/삭제 시 입력)" />
              <input id="opsMasterEquipmentName" placeholder="설비명" />
              <input id="opsMasterEquipmentLocation" placeholder="설비위치" />
              <select id="opsMasterEquipmentLifecycle">
                <option value="active">설비상태: active</option>
                <option value="retired">설비상태: retired</option>
                <option value="replaced">설비상태: replaced</option>
              </select>
              <button id="runOpsMasterEquipmentCreateBtn" class="btn run" type="button">설비 생성</button>
              <button id="runOpsMasterEquipmentUpdateBtn" class="btn" type="button">설비 수정</button>
            </div>
            <div class="ops-checklist-actions">
              <button id="runOpsMasterEquipmentDeleteBtn" class="btn" type="button">설비 삭제</button>
            </div>
            <div class="ops-form-grid">
              <input id="opsMasterChecklistSetId" placeholder="set_id" />
              <input id="opsMasterChecklistLabel" placeholder="체크리스트 라벨" />
              <input id="opsMasterChecklistTaskType" placeholder="task_type (예: 전기점검)" />
              <input id="opsMasterChecklistVersion" placeholder="version_no / proposed_version_no" />
              <select id="opsMasterChecklistLifecycle">
                <option value="active">세트상태: active</option>
                <option value="retired">세트상태: retired</option>
                <option value="replaced">세트상태: replaced</option>
              </select>
              <button id="runOpsMasterChecklistCreateBtn" class="btn run" type="button">세트 생성</button>
              <button id="runOpsMasterChecklistUpdateBtn" class="btn" type="button">세트 수정</button>
            </div>
            <div class="ops-form-grid">
              <textarea id="opsMasterChecklistItems" class="span-5" placeholder="체크리스트 항목을 줄바꿈으로 입력하세요"></textarea>
            </div>
            <div class="ops-checklist-actions">
              <button id="runOpsMasterChecklistDeleteBtn" class="btn" type="button">세트 삭제</button>
            </div>
            <div class="ops-form-grid">
              <input id="opsMasterChecklistRevisionId" placeholder="revision_id (제출/승인/반려 시 입력)" />
              <button id="runOpsMasterChecklistRevisionCreateBtn" class="btn run" type="button">개정안 작성</button>
              <button id="runOpsMasterChecklistRevisionListBtn" class="btn" type="button">개정안 조회</button>
              <button id="runOpsMasterChecklistRevisionDiffBtn" class="btn" type="button">개정안 비교</button>
            </div>
            <div class="ops-form-grid">
              <textarea id="opsMasterChecklistRevisionNote" class="span-5" placeholder="Summary: what changed&#10;Impact: operator/user effect&#10;Rollback: how to revert safely"></textarea>
            </div>
            <div class="ops-checklist-actions">
              <button id="runOpsMasterChecklistRevisionSubmitBtn" class="btn" type="button">개정안 제출</button>
              <button id="runOpsMasterChecklistRevisionApproveBtn" class="btn" type="button">개정안 승인</button>
              <button id="runOpsMasterChecklistRevisionRejectBtn" class="btn" type="button">개정안 반려</button>
            </div>
            <div class="ops-form-grid">
              <input id="opsMasterQrAssetId" placeholder="qr_asset_id (수정/삭제 시 입력)" />
              <input id="opsMasterQrId" placeholder="qr_id" />
              <input id="opsMasterQrEquipmentId" placeholder="equipment_id" />
              <input id="opsMasterQrChecklistSetId" placeholder="checklist_set_id" />
              <input id="opsMasterQrDefaultItem" placeholder="default_item" />
              <select id="opsMasterQrLifecycle">
                <option value="active">QR상태: active</option>
                <option value="retired">QR상태: retired</option>
                <option value="replaced">QR상태: replaced</option>
              </select>
            </div>
            <div class="ops-checklist-actions">
              <button id="runOpsMasterQrCreateBtn" class="btn run" type="button">QR 생성</button>
              <button id="runOpsMasterQrUpdateBtn" class="btn" type="button">QR 수정</button>
              <button id="runOpsMasterQrDeleteBtn" class="btn" type="button">QR 삭제</button>
            </div>
            <div id="opsMasterMeta" class="meta">조회 전</div>
            <div id="opsMasterEquipmentTable" class="empty">설비 마스터 데이터 없음</div>
            <div id="opsMasterChecklistTable" class="empty">체크리스트 마스터 데이터 없음</div>
            <div id="opsMasterChecklistRevisionTable" class="empty">체크리스트 개정안 데이터 없음</div>
            <div id="opsMasterChecklistRevisionDiffMeta" class="meta">개정안 비교 전</div>
            <div id="opsMasterChecklistRevisionDiffSummary" class="empty">개정안 diff 데이터 없음</div>
            <div id="opsMasterChecklistRevisionDiffTable" class="empty">개정안 diff 항목 없음</div>
            <div id="opsMasterQrTable" class="empty">QR 마스터 데이터 없음</div>
          </div>
        </div>

        <div id="panelBilling" class="tab-panel" role="tabpanel">
          <p class="tab-caption">아파트 전기/수도 세대요금과 공용요금을 함께 관리합니다. 공용전기·공용수도는 월별 금액을 입력하고 면적비로 세대에 배부합니다.</p>
          <div class="box">
            <h3>세대 마스터 등록</h3>
            <div class="ops-form-grid">
              <input id="billingUnitSite" placeholder="site (예: HQ)" />
              <input id="billingUnitBuilding" placeholder="동 (예: 101동)" />
              <input id="billingUnitNumber" placeholder="호 (예: 1001호)" />
              <input id="billingUnitOccupant" placeholder="세대명/입주자명(선택)" />
              <input id="billingUnitArea" placeholder="전용면적 sqm (예: 84.95)" />
            </div>
            <div class="ops-checklist-actions">
              <button id="runBillingCreateUnitBtn" class="btn run" type="button">세대 등록</button>
              <button id="runBillingUnitsBtn" class="btn" type="button">세대 조회</button>
            </div>
            <div id="billingUnitsMeta" class="meta">조회 전</div>
            <div id="billingUnitsTable" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>요율 정책 등록</h3>
            <div class="ops-form-grid">
              <input id="billingPolicySite" placeholder="site (예: HQ)" />
              <select id="billingPolicyType">
                <option value="electricity">전기</option>
                <option value="water">수도</option>
              </select>
              <input id="billingPolicyMonth" placeholder="적용월 YYYY-MM" />
              <input id="billingPolicyBasicFee" placeholder="기본요금" />
              <input id="billingPolicyUnitRate" placeholder="사용량 단가" />
            </div>
            <div class="ops-form-grid">
              <input id="billingPolicySewageRate" placeholder="하수도 단가(수도용)" />
              <input id="billingPolicyServiceFee" placeholder="부가요금/관리수수료" />
              <input id="billingPolicyVatRate" placeholder="부가세율 (예: 0.1)" />
              <input id="billingPolicyNotes" class="span-2" placeholder="비고(선택)" />
            </div>
            <div class="ops-form-grid">
              <textarea id="billingPolicyTiersJson" class="span-5" placeholder='누진단계 JSON(선택): [{{"up_to":200,"rate":120.5}},{{"up_to":400,"rate":214.6}},{{"up_to":null,"rate":307.3}}]'></textarea>
            </div>
            <div class="ops-checklist-actions">
              <button id="runBillingCreatePolicyBtn" class="btn run" type="button">요율 저장</button>
              <button id="runBillingPoliciesBtn" class="btn" type="button">요율 조회</button>
            </div>
            <div id="billingPoliciesMeta" class="meta">조회 전</div>
            <div id="billingPoliciesTable" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>공용요금 입력 (면적비 배부)</h3>
            <div class="ops-form-grid">
              <input id="billingCommonSite" placeholder="site (예: HQ)" />
              <input id="billingCommonMonth" placeholder="부과월 YYYY-MM" />
              <select id="billingCommonType">
                <option value="electricity">공용전기</option>
                <option value="water">공용수도</option>
              </select>
              <input id="billingCommonCategory" placeholder="항목 (예: 산업용, 가로등, 승강기, 공용수도)" />
              <input id="billingCommonAmount" placeholder="금액" />
            </div>
            <div class="ops-form-grid">
              <input id="billingCommonNotes" class="span-5" placeholder="비고(선택): 검침서/고지서 기준 메모" />
            </div>
            <div class="ops-checklist-actions">
              <button id="runBillingCreateCommonBtn" class="btn run" type="button">공용요금 저장</button>
              <button id="runBillingCommonBtn" class="btn" type="button">공용요금 조회</button>
            </div>
            <div id="billingCommonMeta" class="meta">조회 전</div>
            <div id="billingCommonTable" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>검침 입력</h3>
            <div class="ops-form-grid">
              <input id="billingReadingSite" placeholder="site (예: HQ)" />
              <input id="billingReadingBuilding" placeholder="동 (예: 101동)" />
              <input id="billingReadingUnitNumber" placeholder="호 (예: 1001호)" />
              <select id="billingReadingType">
                <option value="electricity">전기</option>
                <option value="water">수도</option>
              </select>
              <input id="billingReadingMonth" placeholder="검침월 YYYY-MM" />
            </div>
            <div class="ops-form-grid">
              <input id="billingReadingPrevious" placeholder="전월 검침값" />
              <input id="billingReadingCurrent" placeholder="당월 검침값" />
              <input id="billingReadingReader" placeholder="검침자" />
              <input id="billingReadingNotes" class="span-2" placeholder="검침 메모(선택)" />
            </div>
            <div class="ops-checklist-actions">
              <button id="runBillingCreateReadingBtn" class="btn run" type="button">검침 저장</button>
              <button id="runBillingReadingsBtn" class="btn" type="button">검침 조회</button>
            </div>
            <div id="billingReadingsMeta" class="meta">조회 전</div>
            <div id="billingReadingsTable" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>월 요금 부과 생성</h3>
            <div class="filter-row">
              <input id="billingRunSite" placeholder="site (예: HQ)" />
              <input id="billingRunMonth" placeholder="부과월 YYYY-MM" />
              <select id="billingRunType">
                <option value="electricity">전기</option>
                <option value="water">수도</option>
              </select>
              <label class="ops-inline-label">
                <input id="billingReplaceExisting" type="checkbox" checked />
                기존 부과내역 덮어쓰기
              </label>
              <button id="runBillingGenerateBtn" class="btn run" type="button">월 부과 생성</button>
            </div>
            <div class="filter-row">
              <input id="billingStatementsSite" placeholder="site (예: HQ)" />
              <input id="billingStatementsMonth" placeholder="부과월 YYYY-MM" />
              <select id="billingStatementsType">
                <option value="">전체 유틸리티</option>
                <option value="electricity">전기</option>
                <option value="water">수도</option>
              </select>
              <input id="billingStatementsBuilding" placeholder="동(선택)" />
              <button id="runBillingStatementsBtn" class="btn" type="button">부과내역 조회</button>
            </div>
            <div id="billingRunMeta" class="meta">생성 전</div>
            <div id="billingRunSummary" class="cards"></div>
            <div id="billingStatementsTable" class="empty">데이터 없음</div>
          </div>
        </div>

        <div id="panelDocuments" class="tab-panel" role="tabpanel">
          <p class="tab-caption">기관별 공문 접수부터 점검/작업지시 연동, 종결보고서와 월/연차 출력까지 한 화면에서 관리합니다.</p>
          <div class="box">
            <h3>공문 등록 / 수정 / 종결</h3>
            <div class="ops-form-grid">
              <input id="officialDocId" placeholder="공문 ID (수정/종결 시 입력)" />
              <input id="officialDocSite" placeholder="site (예: HQ)" />
              <input id="officialDocOrganization" placeholder="기관명 (예: 한전, 수도사업소, 소방서)" />
              <input id="officialDocOrganizationCode" placeholder="기관코드(선택, 예: KEPCO)" />
              <input id="officialDocRegistryNumber" placeholder="접수대장번호(자동생성)" disabled />
            </div>
            <div class="ops-form-grid">
              <input id="officialDocNumber" placeholder="공문번호 (선택)" />
              <input id="officialDocTitle" placeholder="공문 제목" />
            </div>
            <div class="ops-form-grid">
              <input id="officialDocType" placeholder="공문유형 (예: 전기, 수도, 소방, 일반)" />
              <select id="officialDocPriority">
                <option value="medium">priority: medium</option>
                <option value="high">priority: high</option>
                <option value="critical">priority: critical</option>
                <option value="low">priority: low</option>
              </select>
              <input id="officialDocReceivedAt" type="datetime-local" />
              <input id="officialDocDueAt" type="datetime-local" />
              <select id="officialDocStatus">
                <option value="received">status: received</option>
                <option value="in_progress">status: in_progress</option>
                <option value="closed">status: closed</option>
                <option value="canceled">status: canceled</option>
              </select>
            </div>
            <div class="ops-form-grid">
              <input id="officialDocInspectionId" placeholder="linked inspection_id (선택)" />
              <input id="officialDocWorkOrderId" placeholder="linked work_order_id (선택)" />
              <input id="officialDocCloseTitle" class="span-3" placeholder="종결보고서 제목(종결 시)" />
            </div>
            <div class="ops-form-grid">
              <textarea id="officialDocRequiredAction" class="span-5" placeholder="요구조치 / 이행지시 내용을 입력"></textarea>
            </div>
            <div class="ops-form-grid">
              <textarea id="officialDocSummary" class="span-5" placeholder="접수 요약 / 진행 메모"></textarea>
            </div>
            <div class="ops-form-grid">
              <textarea id="officialDocClosureSummary" class="span-3" placeholder="종결 요약(종결 시)"></textarea>
              <textarea id="officialDocClosureResult" class="span-2" placeholder="종결 결과 / 기관 회신 내용"></textarea>
            </div>
            <div class="ops-checklist-actions">
              <button id="runOfficialDocCreateBtn" class="btn run" type="button">공문 등록</button>
              <button id="runOfficialDocLoadBtn" class="btn" type="button">공문 1건 조회</button>
              <button id="runOfficialDocUpdateBtn" class="btn" type="button">공문 수정</button>
              <button id="runOfficialDocCloseBtn" class="btn run" type="button">공문 종결</button>
            </div>
            <div id="officialDocEditMeta" class="meta">입력 대기</div>
          </div>
          <div class="box">
            <h3>공문 원본 PDF / 사진 첨부</h3>
            <div class="filter-row">
              <input id="officialAttachmentDocId" placeholder="공문 ID" />
              <input id="officialAttachmentNote" placeholder="첨부 메모(선택)" />
              <input id="officialAttachmentFile" type="file" accept=".pdf,image/png,image/jpeg" />
              <button id="runOfficialAttachmentUploadBtn" class="btn run" type="button">첨부 업로드</button>
              <button id="runOfficialAttachmentListBtn" class="btn" type="button">첨부 목록 조회</button>
            </div>
            <div id="officialAttachmentMeta" class="meta">조회 전</div>
            <div id="officialAttachmentTable" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>기관별 접수대장 / 첨부 일괄 출력</h3>
            <div class="filter-row">
              <input id="officialExportSite" placeholder="site (예: HQ)" />
              <input id="officialExportOrganization" placeholder="기관명(선택)" />
              <select id="officialExportStatus">
                <option value="">status: all</option>
                <option value="received">received</option>
                <option value="in_progress">in_progress</option>
                <option value="closed">closed</option>
                <option value="canceled">canceled</option>
              </select>
              <input id="officialExportMonth" placeholder="month YYYY-MM" />
              <input id="officialExportYear" placeholder="year YYYY (month 비우면 사용)" />
            </div>
            <div class="mini-links">
              <a id="officialAttachmentZipLink" href="/api/official-documents/attachments/zip" target="_blank" rel="noopener">첨부 ZIP 일괄 다운로드</a>
              <a id="officialRegistryCsvLink" href="/api/official-documents/registry/csv" target="_blank" rel="noopener">접수대장 CSV</a>
            </div>
            <div class="meta">기관별 접수대장과 첨부 원본을 month 또는 year 기준으로 한 번에 출력합니다.</div>
          </div>
          <div class="box">
            <h3>공문 목록 조회</h3>
            <div class="filter-row">
              <input id="officialDocsSite" placeholder="site (예: HQ)" />
              <input id="officialDocsOrganization" placeholder="기관명 필터(선택)" />
              <select id="officialDocsStatus">
                <option value="">status: all</option>
                <option value="received">received</option>
                <option value="in_progress">in_progress</option>
                <option value="closed">closed</option>
                <option value="canceled">canceled</option>
              </select>
              <input id="officialDocsLimit" value="20" placeholder="limit" />
              <input id="officialDocsOffset" value="0" placeholder="offset" />
              <button id="runOfficialDocsBtn" class="btn run" type="button">공문 목록 조회</button>
            </div>
            <div id="officialDocsMeta" class="meta">조회 전</div>
            <div id="officialDocsTable" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>기한초과 자동 작업지시 / SLA 알림</h3>
            <div class="filter-row">
              <input id="officialOverdueSite" placeholder="site (예: HQ)" />
              <input id="officialOverdueLimit" value="50" placeholder="limit" />
              <select id="officialOverdueDryRun">
                <option value="false">실행</option>
                <option value="true">dry-run</option>
              </select>
              <button id="runOfficialOverdueSyncBtn" class="btn run" type="button">기한초과 자동화 실행</button>
            </div>
            <div id="officialOverdueMeta" class="meta">실행 전</div>
            <div id="officialOverdueSummary" class="cards"></div>
          </div>
          <div class="box">
            <h3>종결보고서 출력</h3>
            <div class="filter-row">
              <input id="officialReportSite" placeholder="site (예: HQ)" />
              <input id="officialReportMonth" placeholder="month YYYY-MM" />
              <input id="officialReportYear" placeholder="year YYYY" />
              <button id="runOfficialDocMonthlyReportBtn" class="btn run" type="button">월 보고서 조회</button>
              <button id="runOfficialDocAnnualReportBtn" class="btn" type="button">연차 보고서 조회</button>
              <button id="runOfficialIntegratedMonthlyReportBtn" class="btn" type="button">통합 월간보고서 조회</button>
              <button id="runOfficialIntegratedAnnualReportBtn" class="btn" type="button">통합 연차보고서 조회</button>
            </div>
            <div class="mini-links">
              <a id="officialReportMonthlyPrintLink" href="/reports/official-documents/monthly/print" target="_blank" rel="noopener">월 보고서 인쇄</a>
              <a id="officialReportMonthlyCsvLink" href="/api/reports/official-documents/monthly/csv" target="_blank" rel="noopener">월 CSV</a>
              <a id="officialReportAnnualPrintLink" href="/reports/official-documents/annual/print" target="_blank" rel="noopener">연차 보고서 인쇄</a>
              <a id="officialReportAnnualCsvLink" href="/api/reports/official-documents/annual/csv" target="_blank" rel="noopener">연차 CSV</a>
              <a id="officialReportIntegratedPrintLink" href="/reports/monthly/integrated/print" target="_blank" rel="noopener">통합 월간 인쇄</a>
              <a id="officialReportIntegratedCsvLink" href="/api/reports/monthly/integrated/csv" target="_blank" rel="noopener">통합 월간 CSV</a>
              <a id="officialReportIntegratedPdfLink" href="/api/reports/monthly/integrated/pdf" target="_blank" rel="noopener">통합 월간 PDF</a>
              <a id="officialReportIntegratedAnnualPrintLink" href="/reports/annual/integrated/print" target="_blank" rel="noopener">통합 연차 인쇄</a>
              <a id="officialReportIntegratedAnnualCsvLink" href="/api/reports/annual/integrated/csv" target="_blank" rel="noopener">통합 연차 CSV</a>
              <a id="officialReportIntegratedAnnualPdfLink" href="/api/reports/annual/integrated/pdf" target="_blank" rel="noopener">통합 연차 PDF</a>
            </div>
            <div id="officialReportMeta" class="meta">조회 전</div>
            <div id="officialReportSummary" class="cards"></div>
            <div id="officialReportEntries" class="empty">데이터 없음</div>
            <div id="officialIntegratedReportSummary" class="cards"></div>
            <pre id="officialIntegratedReportRaw" class="mono">{{}}</pre>
          </div>
        </div>

        <div id="panelReports" class="tab-panel" role="tabpanel">
          <p class="tab-caption">월간 리포트 집계와 출력 링크를 제공합니다.</p>
          <div class="filter-row">
            <input id="rpMonth" placeholder="month (YYYY-MM)" />
            <input id="rpYear" placeholder="year (YYYY)" />
            <input id="rpSite" placeholder="site (optional)" />
            <input id="rpReserved1" value="reports" disabled />
            <input id="rpReserved2" value="summary" disabled />
            <button id="runReportsBtn" class="btn run" type="button">리포트 조회</button>
          </div>
          <div id="reportsMeta" class="meta">조회 전</div>
          <div id="reportsSummary" class="cards"></div>
          <div class="box">
            <h3>리포트 다운로드/출력</h3>
            <div class="mini-links">
              <a id="reportPrintLink" href="/reports/monthly/print" target="_blank" rel="noopener">HTML 인쇄</a>
              <a id="reportCsvLink" href="/api/reports/monthly/csv" target="_blank" rel="noopener">CSV</a>
              <a id="reportPdfLink" href="/api/reports/monthly/pdf" target="_blank" rel="noopener">PDF</a>
              <a id="reportIntegratedPrintLink" href="/reports/monthly/integrated/print" target="_blank" rel="noopener">통합 월간 인쇄</a>
              <a id="reportIntegratedCsvLink" href="/api/reports/monthly/integrated/csv" target="_blank" rel="noopener">통합 월간 CSV</a>
              <a id="reportIntegratedPdfLink" href="/api/reports/monthly/integrated/pdf" target="_blank" rel="noopener">통합 월간 PDF</a>
              <a id="reportIntegratedAnnualPrintLink" href="/reports/annual/integrated/print" target="_blank" rel="noopener">통합 연차 인쇄</a>
              <a id="reportIntegratedAnnualCsvLink" href="/api/reports/annual/integrated/csv" target="_blank" rel="noopener">통합 연차 CSV</a>
              <a id="reportIntegratedAnnualPdfLink" href="/api/reports/annual/integrated/pdf" target="_blank" rel="noopener">통합 연차 PDF</a>
            </div>
            <pre id="reportsRaw" class="mono">{{}}</pre>
          </div>
        </div>

        <div id="panelIam" class="tab-panel" role="tabpanel">
          <p class="tab-caption">owner/manager가 로그인 세션, 사용자 권한, 계정 상태를 한 화면에서 관리합니다.</p>
          <div class="mini-links">
            <a id="iamGuideLink" href="/web/iam-guide" target="_blank" rel="noopener">사용 설명서 열기</a>
          </div>
          <div class="box">
            <h3>내 세션 / 권한 / 로그아웃</h3>
            <div class="filter-row">
              <input id="iamReserved1" value="GET /api/auth/me" disabled />
              <input id="iamReserved2" value="POST /api/auth/logout" disabled />
              <input id="iamReserved3" value="GET /api/admin/token-policy" disabled />
              <input id="iamReserved4" value="legacy env token은 서버 revoke 불가" disabled />
              <button id="runIamMeBtn" class="btn run" type="button">내 권한 조회</button>
            </div>
            <div class="ops-checklist-actions">
              <button id="runIamLogoutBtn" class="btn" type="button">로그아웃</button>
              <button id="runIamTokenPolicyBtn" class="btn soft" type="button">토큰 정책 조회</button>
            </div>
            <div id="iamMeMeta" class="meta">조회 전</div>
            <div id="iamMeTable" class="empty">데이터 없음</div>
            <div id="iamTokenPolicyTable" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>사용자 목록</h3>
            <div class="filter-row">
              <input id="iamFilterRole" placeholder="role filter (optional)" />
              <select id="iamFilterActive">
                <option value="all">active: all</option>
                <option value="true">active: true</option>
                <option value="false">active: false</option>
              </select>
              <input id="iamFilterSearch" placeholder="username/display search" />
              <input id="iamUsersReserved1" value="목록에서 선택 클릭 후 아래 수정폼 연동" disabled />
              <button id="runIamUsersBtn" class="btn run" type="button">사용자 조회</button>
            </div>
            <div id="iamUsersMeta" class="meta">조회 전</div>
            <div id="iamUsersTable" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>사용자 생성</h3>
            <div class="ops-form-grid">
              <input id="iamCreateUsername" placeholder="username" />
              <input id="iamCreatePassword" type="password" placeholder="password (8+)" />
              <input id="iamCreateDisplayName" placeholder="display_name (optional)" />
              <select id="iamCreateRole">
                <option value="operator">operator</option>
                <option value="auditor">auditor</option>
                <option value="manager">manager</option>
                <option value="owner">owner</option>
              </select>
              <input id="iamCreateSiteScope" value="*" placeholder="site_scope comma (e.g. HQ,TRAINING-HQ)" />
            </div>
            <div class="ops-form-grid">
              <input id="iamCreatePermissions" class="span-2" placeholder="custom permissions comma (optional)" />
              <label class="ops-inline-label">
                <input id="iamCreateIsActive" type="checkbox" checked />
                is_active=true
              </label>
              <input id="iamCreateReserved1" value="permissions 공백이면 []" disabled />
              <button id="runIamCreateUserBtn" class="btn run" type="button">사용자 생성</button>
            </div>
            <div id="iamCreateMeta" class="meta">생성 전</div>
          </div>
          <div class="box">
            <h3>사용자 수정 / 비활성화 / 삭제</h3>
            <div class="filter-row">
              <input id="iamEditUserId" placeholder="user_id (숫자)" />
              <input id="iamEditUsername" placeholder="username (읽기용)" disabled />
              <input id="iamEditReserved1" value="PATCH /api/admin/users/<id>" disabled />
              <input id="iamEditReserved2" value="POST /api/admin/users/<id>/password" disabled />
              <button id="runIamPickUserBtn" class="btn soft" type="button">사용자 선택</button>
            </div>
            <div class="ops-form-grid">
              <input id="iamEditDisplayName" placeholder="display_name" />
              <select id="iamEditRole">
                <option value="operator">operator</option>
                <option value="auditor">auditor</option>
                <option value="manager">manager</option>
                <option value="owner">owner</option>
              </select>
              <input id="iamEditSiteScope" placeholder="site_scope comma" />
              <input id="iamEditPermissions" placeholder="permissions comma" />
              <select id="iamEditIsActive">
                <option value="true">is_active=true</option>
                <option value="false">is_active=false</option>
              </select>
            </div>
            <div class="ops-form-grid">
              <input id="iamEditPassword" type="password" class="span-2" placeholder="새 password (변경 시 입력)" />
              <input id="iamEditReserved3" value="PATCH /api/admin/users/<id>/active" disabled />
              <input id="iamEditReserved4" value="DELETE /api/admin/users/<id>" disabled />
              <input id="iamEditReserved5" value="owner 최소 1명 유지 정책 적용" disabled />
            </div>
            <div class="ops-checklist-actions">
              <button id="runIamUpdateUserBtn" class="btn run" type="button">사용자 수정</button>
              <button id="runIamSetPasswordBtn" class="btn soft" type="button">비밀번호 변경</button>
              <button id="runIamDeactivateUserBtn" class="btn" type="button">비활성화</button>
              <button id="runIamDeleteUserBtn" class="btn" type="button">사용자 삭제</button>
            </div>
            <div id="iamEditMeta" class="meta">수정 전</div>
          </div>
          <div class="box">
            <h3>토큰 발급 / 회전 / 폐기</h3>
            <div class="filter-row">
              <input id="iamTokensFilterUserId" placeholder="user_id filter (optional)" />
              <select id="iamTokensFilterActive">
                <option value="all">active: all</option>
                <option value="true">active: true</option>
                <option value="false">active: false</option>
              </select>
              <input id="iamTokensReserved1" value="GET /api/admin/tokens" disabled />
              <input id="iamTokensReserved2" value="POST /api/admin/users/<id>/tokens" disabled />
              <button id="runIamTokensBtn" class="btn run" type="button">토큰 조회</button>
            </div>
            <div id="iamTokensMeta" class="meta">조회 전</div>
            <div id="iamTokensTable" class="empty">데이터 없음</div>
            <div class="ops-form-grid">
              <input id="iamIssueTokenUserId" placeholder="issue user_id (기본: 선택 사용자)" />
              <input id="iamIssueTokenLabel" value="console-issued" placeholder="token label" />
              <input id="iamIssueTokenExpiresAt" placeholder="expires_at (ISO-8601, optional)" />
              <input id="iamIssueTokenSiteScope" placeholder="token site_scope comma (optional)" />
              <button id="runIamIssueTokenBtn" class="btn run" type="button">토큰 발급</button>
            </div>
            <div class="ops-form-grid">
              <input id="iamSelectedTokenId" placeholder="token_id" />
              <input id="iamSelectedTokenUser" placeholder="username (읽기용)" disabled />
              <input id="iamSelectedTokenLabel" placeholder="token label (읽기용)" disabled />
              <input id="iamTokensReserved3" value="POST /api/admin/tokens/<id>/rotate|revoke" disabled />
              <button id="runIamPickTokenBtn" class="btn soft" type="button">토큰 선택</button>
            </div>
            <div class="ops-checklist-actions">
              <button id="runIamRotateTokenBtn" class="btn soft" type="button">토큰 회전</button>
              <button id="runIamRevokeTokenBtn" class="btn" type="button">토큰 폐기</button>
            </div>
            <div id="iamTokenActionMeta" class="meta">실행 전</div>
            <pre id="iamTokenPlain" class="mono">신규 토큰 값은 발급/회전 직후 1회만 표시됩니다.</pre>
          </div>
          <div class="box">
            <h3>감사 로그 조회</h3>
            <div class="filter-row">
              <input id="iamAuditAction" placeholder="action filter (optional)" />
              <input id="iamAuditActor" placeholder="actor_username filter (optional)" />
              <input id="iamAuditLimit" value="50" placeholder="limit (1-200)" />
              <input id="iamAuditOffset" value="0" placeholder="offset (0+)" />
              <button id="runIamAuditBtn" class="btn run" type="button">감사 로그 조회</button>
            </div>
            <div id="iamAuditMeta" class="meta">조회 전</div>
            <div id="iamAuditTable" class="empty">데이터 없음</div>
            <pre id="iamAuditDetail" class="mono">로그를 선택하면 detail JSON이 표시됩니다.</pre>
          </div>
        </div>

        <div id="panelAdoption" class="tab-panel" role="tabpanel">
          <p class="tab-caption">주차별 실행표 + 교육자료 + KPI + 일정관리 정보를 즉시 실행 가능한 형태로 확인합니다.</p>
          <div class="filter-row">
            <input id="adoptReserved1" value="public adoption plan" disabled />
            <input id="adoptReserved2" value="training + kpi + schedule" disabled />
            <input id="adoptReserved3" value="campaign ready" disabled />
            <input id="adoptReserved4" value="weekly execution" disabled />
            <button id="runAdoptionBtn" class="btn run" type="button">정착 계획 새로고침</button>
          </div>
          <div id="adoptionMeta" class="meta">조회 전</div>
          <div id="adoptionTop" class="adopt-grid"></div>
          <div class="box">
            <h3>W01 Role Workflow Lock Matrix</h3>
            <div id="adoptionWorkflowMatrix" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>W02 Scheduled SOP and Sandbox</h3>
            <div id="adoptionW02Top" class="cards"></div>
            <div id="adoptionW02Sop" class="empty">데이터 없음</div>
            <div id="adoptionW02Sandbox" class="empty">데이터 없음</div>
            <div id="adoptionW02Schedule" class="empty">데이터 없음</div>
            <div class="mini-links">
              <a id="adoptW02Json" href="/api/public/adoption-plan/w02">W02 JSON</a>
              <a id="adoptW02ChecklistCsv" href="/api/public/adoption-plan/w02/checklist.csv">W02 체크리스트 CSV</a>
              <a id="adoptW02ScheduleIcs" href="/api/public/adoption-plan/w02/schedule.ics">W02 일정 ICS</a>
              <a id="adoptW02SampleFiles" href="/api/public/adoption-plan/w02/sample-files">W02 샘플 파일</a>
            </div>
          </div>
          <div class="box">
            <h3>W03 Go-live Onboarding</h3>
            <div id="adoptionW03Top" class="cards"></div>
            <div id="adoptionW03Kickoff" class="empty">데이터 없음</div>
            <div id="adoptionW03Workshops" class="empty">데이터 없음</div>
            <div id="adoptionW03OfficeHours" class="empty">데이터 없음</div>
            <div id="adoptionW03Schedule" class="empty">데이터 없음</div>
            <div class="mini-links">
              <a id="adoptW03Json" href="/api/public/adoption-plan/w03">W03 JSON</a>
              <a id="adoptW03ChecklistCsv" href="/api/public/adoption-plan/w03/checklist.csv">W03 체크리스트 CSV</a>
              <a id="adoptW03ScheduleIcs" href="/api/public/adoption-plan/w03/schedule.ics">W03 일정 ICS</a>
            </div>
          </div>
          <div class="box">
            <h3>W04 First Success Acceleration</h3>
            <div id="adoptionW04Top" class="cards"></div>
            <div id="adoptionW04Actions" class="empty">데이터 없음</div>
            <div id="adoptionW04Schedule" class="empty">데이터 없음</div>
            <div id="adoptionW04Mistakes" class="empty">데이터 없음</div>
            <div class="mini-links">
              <a id="adoptW04Json" href="/api/public/adoption-plan/w04">W04 JSON</a>
              <a id="adoptW04ChecklistCsv" href="/api/public/adoption-plan/w04/checklist.csv">W04 체크리스트 CSV</a>
              <a id="adoptW04ScheduleIcs" href="/api/public/adoption-plan/w04/schedule.ics">W04 일정 ICS</a>
              <a id="adoptW04MistakesJson" href="/api/public/adoption-plan/w04/common-mistakes">W04 자주 하는 실수 JSON</a>
              <a id="adoptW04MistakesHtml" href="/web/adoption/w04/common-mistakes">W04 자주 하는 실수 HTML</a>
            </div>
          </div>
          {w02_tracker_box_html}
          {w03_tracker_box_html}
          <div class="box">
            <h3>W04 First-Success Funnel + Top Blockers</h3>
            <div class="filter-row">
              <input id="w04FunnelSite" placeholder="site (필수, 예: HQ)" />
              <input id="w04FunnelDays" value="30" placeholder="window days (1-90)" />
              <input id="w04FunnelMaxBlockers" value="3" placeholder="max blockers (1-10)" />
              <input id="w04FunnelReserved" value="token required" disabled />
              <button id="w04FunnelRefreshBtn" class="btn run" type="button">W04 퍼널 새로고침</button>
            </div>
            <div id="w04FunnelMeta" class="meta">조회 전</div>
            <div id="w04FunnelSummary" class="cards"></div>
            <h4 style="margin:10px 0 6px;">퍼널 단계</h4>
            <div id="w04FunnelStages" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Top Blockers</h4>
            <div id="w04BlockerTable" class="empty">데이터 없음</div>
          </div>
          {w04_tracker_box_html}
          <div class="box">
            <h3>W05 Usage Consistency</h3>
            <div id="adoptionW05Top" class="cards"></div>
            <div id="adoptionW05Missions" class="empty">데이터 없음</div>
            <div id="adoptionW05Schedule" class="empty">데이터 없음</div>
            <div id="adoptionW05HelpDocs" class="empty">데이터 없음</div>
            <div class="mini-links">
              <a id="adoptW05Json" href="/api/public/adoption-plan/w05">W05 JSON</a>
              <a id="adoptW05MissionsCsv" href="/api/public/adoption-plan/w05/missions.csv">W05 Missions CSV</a>
              <a id="adoptW05ScheduleIcs" href="/api/public/adoption-plan/w05/schedule.ics">W05 Schedule ICS</a>
              <a id="adoptW05HelpDocs" href="/api/public/adoption-plan/w05/help-docs">W05 Help Docs</a>
              <a id="adoptW05ConsistencyApi" href="/api/ops/adoption/w05/consistency">W05 Consistency API (Token)</a>
            </div>
          </div>
          <div class="box">
            <h3>W05 Usage Consistency Dashboard (Token)</h3>
            <div class="filter-row">
              <input id="w05ConsistencySite" placeholder="site (optional, 빈 값이면 전체)" />
              <input id="w05ConsistencyDays" value="28" placeholder="window days (14-90)" />
              <input id="w05ConsistencyReserved1" value="token required" disabled />
              <input id="w05ConsistencyReserved2" value="site 범위 권한 적용" disabled />
              <button id="w05ConsistencyRefreshBtn" class="btn run" type="button">W05 지표 새로고침</button>
            </div>
            <div id="w05ConsistencyMeta" class="meta">조회 전</div>
            <div id="w05ConsistencySummary" class="cards"></div>
            <h4 style="margin:10px 0 6px;">Site Overdue Top</h4>
            <div id="w05ConsistencyTopSites" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Mission Recommendations</h4>
            <div id="w05ConsistencyRecommendations" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>W06 Operational Rhythm</h3>
            <div id="adoptionW06Top" class="cards"></div>
            <div id="adoptionW06Checklist" class="empty">데이터 없음</div>
            <div id="adoptionW06Schedule" class="empty">데이터 없음</div>
            <div id="adoptionW06RbacAudit" class="empty">데이터 없음</div>
            <div class="mini-links">
              <a id="adoptW06Json" href="/api/public/adoption-plan/w06">W06 JSON</a>
              <a id="adoptW06ChecklistCsv" href="/api/public/adoption-plan/w06/checklist.csv">W06 Checklist CSV</a>
              <a id="adoptW06ScheduleIcs" href="/api/public/adoption-plan/w06/schedule.ics">W06 Schedule ICS</a>
              <a id="adoptW06RbacAuditTemplate" href="/api/public/adoption-plan/w06/rbac-audit-template">W06 RBAC Audit Template</a>
              <a id="adoptW06RhythmApi" href="/api/ops/adoption/w06/rhythm">W06 Rhythm API (Token)</a>
            </div>
          </div>
          <div class="box">
            <h3>W06 Operational Rhythm Dashboard (Token)</h3>
            <div class="filter-row">
              <input id="w06RhythmSite" placeholder="site (optional, 빈 값이면 전체)" />
              <input id="w06RhythmDays" value="14" placeholder="window days (7-90)" />
              <input id="w06RhythmReserved1" value="token required" disabled />
              <input id="w06RhythmReserved2" value="site 범위 권한 적용" disabled />
              <button id="w06RhythmRefreshBtn" class="btn run" type="button">W06 리듬 새로고침</button>
            </div>
            <div id="w06RhythmMeta" class="meta">조회 전</div>
            <div id="w06RhythmSummary" class="cards"></div>
            <h4 style="margin:10px 0 6px;">Role Coverage</h4>
            <div id="w06RhythmRoleCoverage" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Site Activity</h4>
            <div id="w06RhythmSiteActivity" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Recommendations</h4>
            <div id="w06RhythmRecommendations" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>W07 SLA Quality</h3>
            <div id="adoptionW07Top" class="cards"></div>
            <div id="adoptionW07Checklist" class="empty">데이터 없음</div>
            <div id="adoptionW07Coaching" class="empty">데이터 없음</div>
            <div id="adoptionW07Schedule" class="empty">데이터 없음</div>
            <div class="mini-links">
              <a id="adoptW07Json" href="/api/public/adoption-plan/w07">W07 JSON</a>
              <a id="adoptW07ChecklistCsv" href="/api/public/adoption-plan/w07/checklist.csv">W07 Checklist CSV</a>
              <a id="adoptW07ScheduleIcs" href="/api/public/adoption-plan/w07/schedule.ics">W07 Schedule ICS</a>
              <a id="adoptW07CoachingPlaybook" href="/api/public/adoption-plan/w07/coaching-playbook">W07 Coaching Playbook</a>
              <a id="adoptW07QualityApi" href="/api/ops/adoption/w07/sla-quality">W07 SLA Quality API (Token)</a>
              <a id="adoptW07AutomationReadinessApi" href="/api/ops/adoption/w07/automation-readiness">W07 Automation Readiness API (Token)</a>
              <a id="adoptW07TrackerItemsApi" href="/api/adoption/w07/tracker/items">W07 Tracker Items API (Token)</a>
              <a id="adoptW07TrackerOverviewApi" href="/api/adoption/w07/tracker/overview?site=HQ">W07 Tracker Overview API (Token)</a>
              <a id="adoptW07CompletionPackageApi" href="/api/adoption/w07/tracker/completion-package?site=HQ">W07 Completion Package ZIP (Token)</a>
              <a id="adoptW07WeeklyRunApi" href="/api/ops/adoption/w07/sla-quality/run-weekly">W07 Weekly Run API (Token)</a>
              <a id="adoptW07WeeklyLatestApi" href="/api/ops/adoption/w07/sla-quality/latest-weekly">W07 Weekly Latest API (Token)</a>
              <a id="adoptW07WeeklyTrendsApi" href="/api/ops/adoption/w07/sla-quality/trends">W07 Weekly Trends API (Token)</a>
              <a id="adoptW07WeeklyArchiveApi" href="/api/ops/adoption/w07/sla-quality/archive.csv">W07 Weekly Archive CSV (Token)</a>
            </div>
          </div>
          <div class="box">
            <h3>W07 SLA Quality Dashboard (Token)</h3>
            <div class="filter-row">
              <input id="w07QualitySite" placeholder="site (optional, 빈 값이면 전체)" />
              <input id="w07QualityDays" value="14" placeholder="window days (7-90)" />
              <input id="w07QualityReserved1" value="token required" disabled />
              <input id="w07QualityReserved2" value="site 범위 권한 적용" disabled />
              <button id="w07QualityRefreshBtn" class="btn run" type="button">W07 품질 새로고침</button>
            </div>
            <div id="w07QualityMeta" class="meta">조회 전</div>
            <div id="w07QualitySummary" class="cards"></div>
            <h4 style="margin:10px 0 6px;">Automation Readiness</h4>
            <div id="w07AutomationReadiness" class="cards"></div>
            <h4 style="margin:10px 0 6px;">Top Risk Sites</h4>
            <div id="w07QualityTopSites" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Recommendations</h4>
            <div id="w07QualityRecommendations" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>W08 Report Discipline</h3>
            <div id="adoptionW08Top" class="cards"></div>
            <div id="adoptionW08Checklist" class="empty">데이터 없음</div>
            <div id="adoptionW08Quality" class="empty">데이터 없음</div>
            <div id="adoptionW08Schedule" class="empty">데이터 없음</div>
            <div class="mini-links">
              <a id="adoptW08Json" href="/api/public/adoption-plan/w08">W08 JSON</a>
              <a id="adoptW08ChecklistCsv" href="/api/public/adoption-plan/w08/checklist.csv">W08 Checklist CSV</a>
              <a id="adoptW08ScheduleIcs" href="/api/public/adoption-plan/w08/schedule.ics">W08 Schedule ICS</a>
              <a id="adoptW08ReportingSop" href="/api/public/adoption-plan/w08/reporting-sop">W08 Reporting SOP</a>
              <a id="adoptW08DisciplineApi" href="/api/ops/adoption/w08/report-discipline">W08 Discipline API (Token)</a>
              <a id="adoptW08BenchmarkApi" href="/api/ops/adoption/w08/site-benchmark">W08 Site Benchmark API (Token)</a>
            </div>
          </div>
          <div class="box">
            <h3>W08 Report Discipline Dashboard (Token)</h3>
            <div class="filter-row">
              <input id="w08DisciplineSite" placeholder="site (optional, 빈 값이면 전체)" />
              <input id="w08DisciplineDays" value="30" placeholder="window days (14-120)" />
              <input id="w08DisciplineReserved1" value="token required" disabled />
              <input id="w08DisciplineReserved2" value="site 범위 권한 적용" disabled />
              <button id="w08DisciplineRefreshBtn" class="btn run" type="button">W08 리포트 새로고침</button>
            </div>
            <div id="w08DisciplineMeta" class="meta">조회 전</div>
            <div id="w08DisciplineSummary" class="cards"></div>
            <h4 style="margin:10px 0 6px;">Top Risk Sites</h4>
            <div id="w08DisciplineTopSites" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Site Benchmark</h4>
            <div id="w08DisciplineBenchmark" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Recommendations</h4>
            <div id="w08DisciplineRecommendations" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>W09 KPI Operation</h3>
            <div id="adoptionW09Top" class="cards"></div>
            <div id="adoptionW09Thresholds" class="empty">데이터 없음</div>
            <div id="adoptionW09Escalation" class="empty">데이터 없음</div>
            <div id="adoptionW09Schedule" class="empty">데이터 없음</div>
            <div class="mini-links">
              <a id="adoptW09Json" href="/api/public/adoption-plan/w09">W09 JSON</a>
              <a id="adoptW09ChecklistCsv" href="/api/public/adoption-plan/w09/checklist.csv">W09 Checklist CSV</a>
              <a id="adoptW09ScheduleIcs" href="/api/public/adoption-plan/w09/schedule.ics">W09 Schedule ICS</a>
              <a id="adoptW09KpiOperationApi" href="/api/ops/adoption/w09/kpi-operation">W09 KPI Operation API (Token)</a>
              <a id="adoptW09KpiPolicyApi" href="/api/ops/adoption/w09/kpi-policy">W09 KPI Policy API (Token)</a>
              <a id="adoptW09TrackerItemsApi" href="/api/adoption/w09/tracker/items">W09 Tracker Items API (Token)</a>
              <a id="adoptW09TrackerOverviewApi" href="/api/adoption/w09/tracker/overview?site=HQ">W09 Tracker Overview API (Token)</a>
            </div>
          </div>
          <div class="box">
            <h3>W09 KPI Operation Dashboard (Token)</h3>
            <div class="filter-row">
              <input id="w09KpiSite" placeholder="site (optional, 비우면 전체)" />
              <input id="w09KpiDays" value="30" placeholder="window days (14-120)" />
              <input id="w09KpiReserved1" value="token required" disabled />
              <input id="w09KpiReserved2" value="site 범위 권한 적용" disabled />
              <button id="w09KpiRefreshBtn" class="btn run" type="button">W09 KPI 새로고침</button>
            </div>
            <div id="w09KpiMeta" class="meta">조회 전</div>
            <div id="w09KpiSummary" class="cards"></div>
            <h4 style="margin:10px 0 6px;">KPI Status</h4>
            <div id="w09KpiTable" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Escalation Candidates</h4>
            <div id="w09EscalationTable" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Recommendations</h4>
            <div id="w09KpiRecommendations" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Policy Snapshot</h4>
            <div id="w09PolicyMeta" class="meta">조회 전</div>
            <div id="w09PolicyTable" class="empty">데이터 없음</div>
          </div>
          {w09_tracker_box_html}
          <div class="box">
            <h3>W10 Self-serve Support</h3>
            <div id="adoptionW10Top" class="cards"></div>
            <div id="adoptionW10Guides" class="empty">데이터 없음</div>
            <div id="adoptionW10Runbook" class="empty">데이터 없음</div>
            <div id="adoptionW10Schedule" class="empty">데이터 없음</div>
            <div class="mini-links">
              <a id="adoptW10Json" href="/api/public/adoption-plan/w10">W10 JSON</a>
              <a id="adoptW10ChecklistCsv" href="/api/public/adoption-plan/w10/checklist.csv">W10 Checklist CSV</a>
              <a id="adoptW10ScheduleIcs" href="/api/public/adoption-plan/w10/schedule.ics">W10 Schedule ICS</a>
              <a id="adoptW10SelfServeApi" href="/api/ops/adoption/w10/self-serve">W10 Self-serve API (Token)</a>
              <a id="adoptW10SupportPolicyApi" href="/api/ops/adoption/w10/support-policy">W10 Support Policy API (Token)</a>
              <a id="adoptW10TrackerItemsApi" href="/api/adoption/w10/tracker/items">W10 Tracker Items API (Token)</a>
              <a id="adoptW10TrackerOverviewApi" href="/api/adoption/w10/tracker/overview?site=HQ">W10 Tracker Overview API (Token)</a>
            </div>
          </div>
          <div class="box">
            <h3>W10 Self-serve Dashboard (Token)</h3>
            <div class="filter-row">
              <input id="w10KpiSite" placeholder="site (optional, 비우면 전체)" />
              <input id="w10KpiDays" value="30" placeholder="window days (14-120)" />
              <input id="w10KpiReserved1" value="token required" disabled />
              <input id="w10KpiReserved2" value="site 범위 권한 적용" disabled />
              <button id="w10KpiRefreshBtn" class="btn run" type="button">W10 지표 새로고침</button>
            </div>
            <div id="w10KpiMeta" class="meta">조회 전</div>
            <div id="w10KpiSummary" class="cards"></div>
            <h4 style="margin:10px 0 6px;">Support KPI Status</h4>
            <div id="w10KpiTable" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Top Repeat Titles</h4>
            <div id="w10EscalationTable" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Recommendations</h4>
            <div id="w10KpiRecommendations" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Policy Snapshot</h4>
            <div id="w10PolicyMeta" class="meta">조회 전</div>
            <div id="w10PolicyTable" class="empty">데이터 없음</div>
          </div>
          {w10_tracker_box_html}
          <div class="box">
            <h3>W11 Scale Readiness</h3>
            <div id="adoptionW11Top" class="cards"></div>
            <div id="adoptionW11Guides" class="empty">데이터 없음</div>
            <div id="adoptionW11Runbook" class="empty">데이터 없음</div>
            <div id="adoptionW11Schedule" class="empty">데이터 없음</div>
            <div class="mini-links">
              <a id="adoptW11Json" href="/api/public/adoption-plan/w11">W11 JSON</a>
              <a id="adoptW11ChecklistCsv" href="/api/public/adoption-plan/w11/checklist.csv">W11 Checklist CSV</a>
              <a id="adoptW11ScheduleIcs" href="/api/public/adoption-plan/w11/schedule.ics">W11 Schedule ICS</a>
              <a id="adoptW11SelfServeApi" href="/api/ops/adoption/w11/scale-readiness">W11 Scale Readiness API (Token)</a>
              <a id="adoptW11SupportPolicyApi" href="/api/ops/adoption/w11/readiness-policy">W11 Readiness Policy API (Token)</a>
              <a id="adoptW11TrackerItemsApi" href="/api/adoption/w11/tracker/items">W11 Tracker Items API (Token)</a>
              <a id="adoptW11TrackerOverviewApi" href="/api/adoption/w11/tracker/overview?site=HQ">W11 Tracker Overview API (Token)</a>
            </div>
          </div>
          <div class="box">
            <h3>W11 Scale Readiness Dashboard (Token)</h3>
            <div class="filter-row">
              <input id="w11KpiSite" placeholder="site (optional, 비우면 전체)" />
              <input id="w11KpiDays" value="30" placeholder="window days (14-120)" />
              <input id="w11KpiReserved1" value="token required" disabled />
              <input id="w11KpiReserved2" value="site 범위 권한 적용" disabled />
              <button id="w11KpiRefreshBtn" class="btn run" type="button">W11 지표 새로고침</button>
            </div>
            <div id="w11KpiMeta" class="meta">조회 전</div>
            <div id="w11KpiSummary" class="cards"></div>
            <h4 style="margin:10px 0 6px;">Scale KPI Status</h4>
            <div id="w11KpiTable" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Top Expansion Risks</h4>
            <div id="w11EscalationTable" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Recommendations</h4>
            <div id="w11KpiRecommendations" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Policy Snapshot</h4>
            <div id="w11PolicyMeta" class="meta">조회 전</div>
            <div id="w11PolicyTable" class="empty">데이터 없음</div>
          </div>
          {w11_tracker_box_html}
          <div class="box">
            <h3>W15 Operations Efficiency</h3>
            <div id="adoptionW15Top" class="cards"></div>
            <div id="adoptionW15Guides" class="empty">데이터 없음</div>
            <div id="adoptionW15Runbook" class="empty">데이터 없음</div>
            <div id="adoptionW15Schedule" class="empty">데이터 없음</div>
            <div class="mini-links">
              <a id="adoptW15Json" href="/api/public/adoption-plan/w15">W15 JSON</a>
              <a id="adoptW15ChecklistCsv" href="/api/public/adoption-plan/w15/checklist.csv">W15 Checklist CSV</a>
              <a id="adoptW15ScheduleIcs" href="/api/public/adoption-plan/w15/schedule.ics">W15 Schedule ICS</a>
              <a id="adoptW15OpsEfficiencyApi" href="/api/ops/adoption/w15/ops-efficiency">W15 Ops Efficiency API (Token)</a>
              <a id="adoptW15EfficiencyPolicyApi" href="/api/ops/adoption/w15/efficiency-policy">W15 Efficiency Policy API (Token)</a>
              <a id="adoptW15TrackerItemsApi" href="/api/adoption/w15/tracker/items">W15 Tracker Items API (Token)</a>
              <a id="adoptW15TrackerOverviewApi" href="/api/adoption/w15/tracker/overview?site=HQ">W15 Tracker Overview API (Token)</a>
            </div>
          </div>
          <div class="box">
            <h3>W15 Operations Efficiency Dashboard (Token)</h3>
            <div class="filter-row">
              <input id="w15KpiSite" placeholder="site (optional, 비우면 전체)" />
              <input id="w15KpiDays" value="30" placeholder="window days (14-120)" />
              <input id="w15KpiReserved1" value="token required" disabled />
              <input id="w15KpiReserved2" value="site 범위 권한 적용" disabled />
              <button id="w15KpiRefreshBtn" class="btn run" type="button">W15 지표 새로고침</button>
            </div>
            <div id="w15KpiMeta" class="meta">조회 전</div>
            <div id="w15KpiSummary" class="cards"></div>
            <h4 style="margin:10px 0 6px;">Efficiency KPI Status</h4>
            <div id="w15KpiTable" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Top Repeat Incidents</h4>
            <div id="w15EscalationTable" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Recommendations</h4>
            <div id="w15KpiRecommendations" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">Policy Snapshot</h4>
            <div id="w15PolicyMeta" class="meta">조회 전</div>
            <div id="w15PolicyTable" class="empty">데이터 없음</div>
          </div>
          {w15_tracker_box_html}
          <div class="box">
            <h3>W07 실행 추적 (완료 체크 / 담당자 / 증빙 업로드)</h3>
            <div class="filter-row">
              <input id="w07TrackSite" placeholder="site (필수, 예: HQ)" />
              <input id="w07TrackItemId" placeholder="tracker_item_id (표에서 자동 선택)" readonly />
              <input id="w07TrackAssignee" placeholder="담당자" />
              <select id="w07TrackStatus">
                <option value="">status(선택)</option>
                <option value="pending">pending</option>
                <option value="in_progress">in_progress</option>
                <option value="done">done</option>
                <option value="blocked">blocked</option>
              </select>
              <button id="w07TrackBootstrapBtn" class="btn run" type="button">W07 항목 생성</button>
            </div>
            <div class="filter-row">
              <button id="w07TrackNextBtn" class="btn soft" type="button">다음 미완료</button>
              <label style="display:flex; align-items:center; gap:6px; font-size:12px;">
                <input id="w07TrackCompleted" type="checkbox" />
                완료 체크
              </label>
              <input id="w07TrackNote" placeholder="완료 메모(선택)" />
              <input id="w07EvidenceNote" placeholder="증빙 메모(선택)" />
              <input id="w07EvidenceFile" type="file" />
              <button id="w07TrackUpdateBtn" class="btn" type="button">상태 저장</button>
            </div>
            <div class="filter-row">
              <input id="w07EvidenceListItemId" placeholder="evidence 조회용 tracker_item_id (자동 입력)" />
              <div id="w07EvidenceDropzone" class="dropzone" title="클릭 또는 파일 드래그">파일 드래그/클릭 업로드 준비</div>
              <input id="w07Reserved1" value="쓰기 작업에는 토큰 필요" disabled />
              <input id="w07Reserved2" value="site 범위 권한 적용" disabled />
              <input id="w07Reserved3" value="파일 최대 5MB" disabled />
              <button id="w07TrackRefreshBtn" class="btn run" type="button">추적현황 새로고침</button>
            </div>
            <div class="filter-row">
              <button id="w07SelectVisibleBtn" class="btn soft" type="button">현재 목록 전체 선택</button>
              <button id="w07ClearSelectionBtn" class="btn soft" type="button">선택 해제</button>
              <input id="w07BulkAssignee" placeholder="일괄 assignee (optional)" />
              <select id="w07BulkStatus">
                <option value="">일괄 status(선택)</option>
                <option value="pending">pending</option>
                <option value="in_progress">in_progress</option>
                <option value="done">done</option>
                <option value="blocked">blocked</option>
              </select>
              <button id="w07BulkApplyBtn" class="btn run" type="button">선택 항목 일괄 저장</button>
            </div>
            <div class="filter-row">
              <label style="display:flex; align-items:center; gap:6px; font-size:12px;">
                <input id="w07BulkChecked" type="checkbox" checked />
                일괄 완료 체크 적용
              </label>
              <input id="w07BulkReserved1" value="multi-select enabled" disabled />
              <input id="w07BulkReserved2" value="row click fills form" disabled />
              <input id="w07BulkReserved3" value="blocker card filter supported" disabled />
              <input id="w07BulkReserved4" value="force complete needs note" disabled />
            </div>
            <div class="filter-row">
              <input id="w07CompletionNote" placeholder="completion note (force 시 필수)" />
              <label style="display:flex; align-items:center; gap:6px; font-size:12px;">
                <input id="w07CompletionForce" type="checkbox" />
                강제 완료(owner/admin)
              </label>
              <input id="w07Reserved4" value="준비도 게이트 필요" disabled />
              <button id="w07ReadinessBtn" class="btn run" type="button">완료 판정</button>
              <button id="w07CompleteBtn" class="btn" type="button">W07 완료 확정</button>
            </div>
            <div class="filter-row">
              <input id="w07CompleteReserved1" value="원클릭: 완료확정 후 주간실행" disabled />
              <input id="w07CompleteReserved2" value="주간실행은 아래 W07 주간 자동화/트렌드 설정값 사용" disabled />
              <input id="w07CompleteReserved3" value="site는 실행추적 site를 자동 동기화" disabled />
              <input id="w07CompleteReserved4" value="완료 실패 시 주간실행 미수행" disabled />
              <button id="w07CompleteAndWeeklyBtn" class="btn run" type="button">W07 완료+주간실행</button>
            </div>
            <div class="filter-row">
              <label style="display:flex; align-items:center; gap:6px; font-size:12px;">
                <input id="w07PackageIncludeEvidence" type="checkbox" checked />
                evidence 포함
              </label>
              <label style="display:flex; align-items:center; gap:6px; font-size:12px;">
                <input id="w07PackageIncludeWeekly" type="checkbox" checked />
                weekly 포함
              </label>
              <input id="w07PackageWeeklyLimit" value="26" placeholder="weekly limit (1-104)" />
              <input id="w07PackageReserved1" value="ZIP: completion + readiness + tracker + optional evidence/weekly" disabled />
              <button id="w07DownloadPackageBtn" class="btn run" type="button">W07 완료 패키지 다운로드</button>
            </div>
            <div id="w07TrackerMeta" class="meta">조회 전</div>
            <div id="w07SelectionMeta" class="w07-filter-hint">필터: ALL | 표시: 0/0 | 선택: 0</div>
            <div id="w07TrackerSummary" class="cards"></div>
            <div id="w07TrackerTable" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">W07 완료 판정 결과</h4>
            <div id="w07ReadinessMeta" class="meta">조회 전</div>
            <div id="w07ReadinessCards" class="cards"></div>
            <div id="w07ReadinessBlockers" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">증빙 파일 목록</h4>
            <div id="w07EvidenceTable" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">작업 결과 로그</h4>
            <div id="w07ActionResults" class="empty">최근 작업 결과 없음</div>
          </div>
          <div id="w07CompleteModal" class="modal" aria-hidden="true" role="dialog" aria-modal="true" aria-labelledby="w07CompleteModalTitle">
            <div class="modal-card">
              <h4 id="w07CompleteModalTitle">W07 완료 확정 전 체크</h4>
              <div id="w07CompleteModalSummary" class="mono">준비 중...</div>
              <div class="modal-actions">
                <button id="w07CompleteModalCancel" class="btn soft" type="button">취소</button>
                <button id="w07CompleteModalConfirm" class="btn run" type="button">확정 실행</button>
              </div>
            </div>
          </div>
          <div class="box">
            <h3>W07 주간 자동화/트렌드</h3>
            <div class="filter-row">
              <input id="w07WeeklySite" placeholder="site (optional, 빈 값이면 전체)" />
              <input id="w07WeeklyDays" value="14" placeholder="window days (7-90)" />
              <input id="w07WeeklyLimit" value="26" placeholder="trend points (1-104)" />
              <label style="display:flex; align-items:center; gap:6px; font-size:12px;">
                <input id="w07WeeklyForceNotify" type="checkbox" />
                force notify
              </label>
              <button id="w07WeeklyRunBtn" class="btn run" type="button">W07 주간 실행</button>
            </div>
            <div class="filter-row">
              <input id="w07WeeklyReserved1" value="token required" disabled />
              <input id="w07WeeklyReserved2" value="site 범위 권한 적용" disabled />
              <input id="w07WeeklyReserved3" value="cooldown protected alerting" disabled />
              <button id="w07WeeklyLatestBtn" class="btn run" type="button">최근 실행 조회</button>
              <button id="w07WeeklyTrendsBtn" class="btn run" type="button">트렌드 조회</button>
            </div>
            <div id="w07WeeklyMeta" class="meta">조회 전</div>
            <div id="w07WeeklySummary" class="cards"></div>
            <h4 style="margin:10px 0 6px;">최근 실행</h4>
            <div id="w07WeeklyLatest" class="empty">데이터 없음</div>
            <h4 style="margin:10px 0 6px;">트렌드</h4>
            <div id="w07WeeklyTrends" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>주차별 실행표</h3>
            <div id="adoptionWeekly" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>교육자료 목차</h3>
            <div id="adoptionTraining" class="empty">데이터 없음</div>
          </div>
          <div class="box">
            <h3>KPI 대시보드 항목</h3>
            <div id="adoptionKpi" class="empty">데이터 없음</div>
            <div class="mini-links">
              <a id="adoptScheduleCsv" href="/api/public/adoption-plan/schedule.csv">Schedule CSV</a>
              <a id="adoptScheduleIcs" href="/api/public/adoption-plan/schedule.ics">Schedule ICS</a>
              <a href="/api/public/adoption-plan/campaign">Campaign Kit</a>
            </div>
          </div>
        </div>

        <div id="panelTutorial" class="tab-panel" role="tabpanel">
          <p class="tab-caption">신규 사용자용 검증 샘플데이터 실습 모듈입니다.</p>
          <div class="box">
            <h3>튜토리얼 시뮬레이터</h3>
            <div class="meta">검증된 시나리오 기준: 점검 생성 → 작업지시 ACK → 작업지시 완료 → 리포트 데이터 준비</div>
            <div class="mini-links">
              <a id="tutorialGuideLink" href="/web/tutorial-guide" target="_blank" rel="noopener">사용 설명서 열기</a>
              <a href="/web/tutorial-simulator" target="_blank" rel="noopener">튜토리얼 화면 열기</a>
              <a href="/api/public/tutorial-simulator" target="_blank" rel="noopener">튜토리얼 JSON API</a>
              <a href="/api/public/onboarding/day1" target="_blank" rel="noopener">처음 1일 체크리스트 API</a>
              <a href="/api/public/glossary" target="_blank" rel="noopener">운영 용어집 API</a>
              <a href="/api/public/tutorial-simulator/sample-files" target="_blank" rel="noopener">튜토리얼 샘플 파일</a>
              <a href="/api/ops/tutorial-simulator/sessions/start" target="_blank" rel="noopener">세션 시작 API</a>
              <a href="/api/ops/tutorial-simulator/sessions" target="_blank" rel="noopener">세션 목록 API</a>
            </div>
          </div>
          <div class="box">
            <h3>빠른 실습 순서</h3>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>Step</th><th>Action</th><th>API</th></tr>
                </thead>
                <tbody>
                  <tr><td>1</td><td>세션 시작</td><td>POST `/api/ops/tutorial-simulator/sessions/start`</td></tr>
                  <tr><td>2</td><td>ACK 실습</td><td>POST `/api/ops/tutorial-simulator/sessions/{{session_id}}/actions/ack_work_order`</td></tr>
                  <tr><td>3</td><td>완료 실습</td><td>POST `/api/ops/tutorial-simulator/sessions/{{session_id}}/actions/complete_work_order`</td></tr>
                  <tr><td>4</td><td>완료 판정</td><td>POST `/api/ops/tutorial-simulator/sessions/{{session_id}}/check`</td></tr>
                </tbody>
              </table>
            </div>
          </div>
          <div class="box">
            <h3>처음 1일 운영 체크리스트</h3>
            <div id="tutorialDay1Meta" class="meta">조회 전</div>
            <div id="tutorialDay1Cards" class="adopt-grid">데이터 없음</div>
          </div>
          <div class="box">
            <h3>역할별 시작 가이드</h3>
            <div id="tutorialRoleGuides" class="adopt-grid">데이터 없음</div>
          </div>
          <div class="box">
            <h3>운영 용어집</h3>
            <div class="filter-row">
              <input id="tutorialGlossarySearch" placeholder="검색: ACK, SLA, 점검, 증빙" />
              <select id="tutorialGlossaryCategory">
                <option value="all">category: all</option>
              </select>
              <input id="tutorialGlossaryReserved1" value="GET /api/public/glossary" disabled />
              <input id="tutorialGlossaryReserved2" value="영문/한글/업무 의미 검색" disabled />
              <button id="runTutorialGlossaryBtn" class="btn run" type="button">용어집 새로고침</button>
            </div>
            <div id="tutorialGlossaryMeta" class="meta">조회 전</div>
            <div id="tutorialGlossaryTable" class="empty">데이터 없음</div>
          </div>
        </div>
      </div>
    </section>
  </div>
  <script>
    (function() {{
      const TOKEN_KEY = "kaFacility.auth.token";
      const TOKEN_KEY_ALIASES = ["kaFacility.auth.token", "kaFacilityAdminToken", "kaFacilityMainToken", "kaFacility.complaints.token"];
      const PROFILE_KEY = "kaFacility.auth.profile";
      const buttons = Array.from(document.querySelectorAll(".tab-btn"));
      const panels = {{
        overview: document.getElementById("panelOverview"),
        workorders: document.getElementById("panelWorkorders"),
        inspections: document.getElementById("panelInspections"),
        billing: document.getElementById("panelBilling"),
        documents: document.getElementById("panelDocuments"),
        reports: document.getElementById("panelReports"),
        iam: document.getElementById("panelIam"),
        adoption: document.getElementById("panelAdoption"),
        tutorial: document.getElementById("panelTutorial")
      }};
      const url = new URL(window.location.href);
      const authState = document.getElementById("authState");
      const tokenInput = document.getElementById("adminTokenInput");
      const loginUsernameInput = document.getElementById("loginUsernameInput");
      const loginPasswordInput = document.getElementById("loginPasswordInput");
      const loginTokenLabelInput = document.getElementById("loginTokenLabelInput");
      const signupUsernameInput = document.getElementById("signupUsernameInput");
      const signupPasswordInput = document.getElementById("signupPasswordInput");
      const signupDisplayNameInput = document.getElementById("signupDisplayNameInput");
      const signupRoleInput = document.getElementById("signupRoleInput");
      const signupSiteScopeInput = document.getElementById("signupSiteScopeInput");
      const openLoginModalBtn = document.getElementById("openLoginModalBtn");
      const openSignupModalBtn = document.getElementById("openSignupModalBtn");
      const logoutBtn = document.getElementById("logoutBtn");
      const closeLoginModalBtn = document.getElementById("closeLoginModalBtn");
      const closeSignupModalBtn = document.getElementById("closeSignupModalBtn");
      const authModalBackdrop = document.getElementById("authModalBackdrop");
      const authLoginModal = document.getElementById("authLoginModal");
      const authSignupModal = document.getElementById("authSignupModal");
      let activeAuthModal = null;
      let authProfile = null;
      let iamUsersCache = [];
      let iamFilteredUsersCache = [];
      let iamTokensCache = [];
      let iamFilteredTokensCache = [];
      let iamSelectedUserId = null;
      let iamSelectedTokenId = null;
      let iamAuditLogsCache = [];
      let iamSelectedAuditLogId = null;
      let w07TrackerItemsCache = [];
      let w07TrackerFilter = "all";
      let w07SelectedItemIds = new Set();
      let w07ActiveItemId = null;
      let w07LastReadiness = null;
      let w07LastCompletion = null;
      let w07ActionResults = [];
      let w07CompleteModalResolver = null;
      let tutorialOnboardingPayload = null;
      let tutorialGlossaryPayload = null;
      const UI_TOOLTIP_TEXT_BY_ID = {{
        saveTokenBtn: "토큰 저장: 현재 입력한 X-Admin-Token을 이 브라우저 세션에 저장합니다.",
        testTokenBtn: "권한 확인: 현재 토큰으로 /api/auth/me를 호출해 사용자와 역할을 확인합니다.",
        clearTokenBtn: "토큰 지우기: 저장된 관리자 토큰을 브라우저에서 삭제합니다.",
        openLoginModalBtn: "ID/PW 로그인: 사용자 이름과 비밀번호로 새 관리자 토큰을 발급받습니다.",
        openSignupModalBtn: "사용자 신규가입: owner 또는 manager가 새 사용자를 생성할 때 사용합니다.",
        logoutBtn: "로그아웃: 현재 토큰을 종료하고 브라우저 저장값을 정리합니다.",
        closeLoginModalBtn: "닫기: 로그인 창을 닫습니다.",
        loginBtn: "로그인 실행: 입력한 ID/PW로 토큰 발급을 시도합니다.",
        closeSignupModalBtn: "닫기: 신규가입 창을 닫습니다.",
        signupBtn: "가입 실행: 입력한 사용자 정보를 기준으로 계정을 생성합니다.",
        runOverviewBtn: "요약 새로고침: 운영요약 데이터와 핵심 지표를 다시 조회합니다.",
        runOverviewGuardRecoverDryBtn: "배치복구 점검: Alert Guard(알림 보호) 복구를 점검 모드로 미리 실행합니다.",
        runOverviewGuardRecoverRunBtn: "배치복구 실행: 격리 또는 경고 상태 채널 복구를 실제 실행합니다.",
        runOverviewGuardRecoverLatestBtn: "최근 결과: 가장 최근 알림 채널 복구 결과를 조회합니다.",
        overviewOfficialOverdueStatusLink: "Overdue Status API(공문 자동화 상태): 스케줄러 활성 여부와 최근 실행 상태를 조회합니다.",
        overviewOfficialOverdueLatestLink: "Overdue Latest API(공문 최근 실행): 마지막 공문 기한초과 자동화 실행 상세를 조회합니다.",
        runWorkordersBtn: "작업지시 조회: 조건에 맞는 작업지시 목록을 조회합니다.",
        inChecklistAllNormalBtn: "전체 정상: 현재 체크리스트 모든 항목을 정상으로 일괄 설정합니다.",
        inChecklistAllNaBtn: "전체 N/A: 현재 체크리스트 모든 항목을 N/A로 일괄 설정합니다.",
        inChecklistResetBtn: "체크리스트 재구성: 설비군과 템플릿 기준으로 점검 항목을 다시 만듭니다.",
        inCreateInspectionBtn: "점검 저장: 법정점검 1건을 저장하고 필요 시 작업지시/증빙 업로드를 이어서 처리합니다.",
        runInspectionsBtn: "점검 조회: 등록된 점검 이력을 조건별로 조회합니다.",
        runInspectionEvidenceBtn: "증빙 목록 조회: 선택한 inspection_id의 사진·증빙 파일 목록을 가져옵니다.",
        runInspectionImportValidationBtn: "검증 리포트 조회: 엑셀 Import 검증 결과를 최신 상태로 조회합니다.",
        inspectionImportValidationCsvLink: "CSV 다운로드: 엑셀 Import 검증 리포트를 CSV 파일로 내려받습니다.",
        runBillingCreateUnitBtn: "세대 등록: 동·호·전용면적 기준으로 요금부과 대상을 등록합니다.",
        runBillingUnitsBtn: "세대 조회: 등록된 세대 마스터를 site 기준으로 조회합니다.",
        runBillingCreatePolicyBtn: "요율 저장: 전기 또는 수도 단가/기본요금 정책을 적용월 기준으로 등록합니다.",
        runBillingPoliciesBtn: "요율 조회: 등록된 요율 정책을 유틸리티별로 조회합니다.",
        runBillingCreateCommonBtn: "공용요금 저장: 공용전기·공용수도 금액을 입력하고 면적비 배부 대상에 포함합니다.",
        runBillingCommonBtn: "공용요금 조회: 월별 공용 전기/수도 금액 입력 내역을 조회합니다.",
        runBillingCreateReadingBtn: "검침 저장: 세대별 전월/당월 검침값을 저장해 사용량을 확정합니다.",
        runBillingReadingsBtn: "검침 조회: 월별 검침 이력을 조회합니다.",
        runBillingGenerateBtn: "월 부과 생성: 세대요금과 공용요금을 합쳐 면적비 기준 월 부과를 생성합니다.",
        runBillingStatementsBtn: "부과내역 조회: 생성된 전기/수도 부과 명세를 조회합니다.",
        runOfficialDocCreateBtn: "공문 등록: 기관별 공문을 접수하고 점검/작업지시 연동 정보를 함께 저장합니다.",
        runOfficialDocLoadBtn: "공문 1건 조회: 공문 ID로 상세 내용을 불러와 수정/종결 폼에 채웁니다.",
        runOfficialDocUpdateBtn: "공문 수정: 접수요약, 기한, 상태, 연동 대상을 갱신합니다.",
        runOfficialDocCloseBtn: "공문 종결: 종결보고서 제목과 결과를 저장하고 상태를 closed로 변경합니다.",
        runOfficialAttachmentUploadBtn: "첨부 업로드: 공문 원본 PDF 또는 현장 사진을 공문 ID에 연결해 저장합니다.",
        runOfficialAttachmentListBtn: "첨부 목록 조회: 선택한 공문 ID의 PDF/사진 첨부 목록을 가져옵니다.",
        officialAttachmentZipLink: "첨부 ZIP 일괄 다운로드: site·기관·기간 조건에 맞는 공문 첨부를 ZIP과 manifest로 묶어 내려받습니다.",
        officialRegistryCsvLink: "접수대장 CSV: 기관별 공문 접수대장과 상태, 접수번호, 연동 정보를 CSV로 출력합니다.",
        runOfficialDocsBtn: "공문 목록 조회: 기관, 상태, site 기준으로 공문 목록을 조회합니다.",
        runOfficialOverdueSyncBtn: "기한초과 자동화 실행: 기한 지난 공문을 찾아 작업지시를 자동 생성하고 SLA 알림을 연동합니다.",
        runOfficialDocMonthlyReportBtn: "월 보고서 조회: 공문 종결/잔여 현황을 월 단위로 집계합니다.",
        runOfficialDocAnnualReportBtn: "연차 보고서 조회: 공문 종결/잔여 현황을 연 단위로 집계합니다.",
        runOfficialIntegratedMonthlyReportBtn: "통합 월간보고서 조회: 관리비·법정점검·공문 종결 현황을 한 번에 집계합니다.",
        runOfficialIntegratedAnnualReportBtn: "통합 연차보고서 조회: 연간 관리비·법정점검·공문 종결 현황을 한 번에 집계합니다.",
        officialReportMonthlyPrintLink: "월 보고서 인쇄: 월 종결보고서를 인쇄용 HTML로 엽니다.",
        officialReportMonthlyCsvLink: "월 CSV: 월 종결보고서를 CSV 파일로 내려받습니다.",
        officialReportAnnualPrintLink: "연차 보고서 인쇄: 연차 종결보고서를 인쇄용 HTML로 엽니다.",
        officialReportAnnualCsvLink: "연차 CSV: 연차 종결보고서를 CSV 파일로 내려받습니다.",
        officialReportIntegratedPrintLink: "통합 월간 인쇄: 관리비·법정점검·공문 종결을 묶은 인쇄용 보고서를 엽니다.",
        officialReportIntegratedCsvLink: "통합 월간 CSV: 관리비·법정점검·공문 종결 집계를 CSV 파일로 내려받습니다.",
        officialReportIntegratedPdfLink: "통합 월간 PDF: 관리비·법정점검·공문 종결을 병합한 PDF를 내려받습니다.",
        officialReportIntegratedAnnualPrintLink: "통합 연차 인쇄: 연간 통합 운영보고서를 인쇄용 HTML로 엽니다.",
        officialReportIntegratedAnnualCsvLink: "통합 연차 CSV: 연간 통합 운영보고서를 CSV로 내려받습니다.",
        officialReportIntegratedAnnualPdfLink: "통합 연차 PDF: 연간 통합 운영보고서를 병합 PDF로 내려받습니다.",
        runReportsBtn: "리포트 조회: 월간 집계 결과와 출력 링크를 조회합니다.",
        reportPrintLink: "HTML 인쇄: 현재 월간리포트를 인쇄 화면으로 엽니다.",
        reportCsvLink: "CSV 다운로드: 현재 월간리포트를 CSV 파일로 내려받습니다.",
        reportPdfLink: "PDF 다운로드: 현재 월간리포트를 PDF 파일로 내려받습니다.",
        reportIntegratedPrintLink: "통합 월간 인쇄: 기존 월간리포트와 공문/관리비 통합본을 인쇄 화면으로 엽니다.",
        reportIntegratedCsvLink: "통합 월간 CSV: 기존 월간리포트와 공문/관리비 통합본을 CSV로 내려받습니다.",
        reportIntegratedPdfLink: "통합 월간 PDF: 기존 월간리포트와 공문/관리비 통합본을 PDF로 내려받습니다.",
        reportIntegratedAnnualPrintLink: "통합 연차 인쇄: 연간 통합 운영보고서를 인쇄 화면으로 엽니다.",
        reportIntegratedAnnualCsvLink: "통합 연차 CSV: 연간 통합 운영보고서를 CSV로 내려받습니다.",
        reportIntegratedAnnualPdfLink: "통합 연차 PDF: 연간 통합 운영보고서를 PDF로 내려받습니다.",
        runIamMeBtn: "내 권한 조회: 현재 로그인한 사용자 정보와 권한 범위를 확인합니다.",
        runIamLogoutBtn: "로그아웃: 현재 토큰을 서버 기준으로 종료합니다.",
        runIamTokenPolicyBtn: "토큰 정책 조회: 만료, 회전, idle 제한 정책을 확인합니다.",
        iamGuideLink: "사용 설명서 열기: IAM 권한, 사용자, 토큰, 감사 로그 사용 절차를 새 창으로 엽니다.",
        tutorialGuideLink: "사용 설명서 열기: 튜토리얼 실습 절차와 완료 기준을 새 창으로 엽니다.",
        runIamUsersBtn: "사용자 조회: 역할·활성 상태·검색어 기준으로 사용자 목록을 조회합니다.",
        runIamCreateUserBtn: "사용자 생성: 새 사용자 계정과 기본 권한을 등록합니다.",
        runIamPickUserBtn: "사용자 선택: 입력한 user_id의 정보를 아래 수정 폼에 불러옵니다.",
        runIamUpdateUserBtn: "사용자 수정: 표시명, 역할, 권한, 사이트 범위를 수정합니다.",
        runIamSetPasswordBtn: "비밀번호 변경: 선택한 사용자의 새 비밀번호를 적용합니다.",
        runIamDeactivateUserBtn: "비활성화: 선택한 사용자 계정을 로그인 불가 상태로 전환합니다.",
        runIamDeleteUserBtn: "사용자 삭제: 선택한 사용자를 운영 목록에서 제거하고 비활성 상태로 정리합니다.",
        runIamTokensBtn: "토큰 조회: 사용자별 관리자 토큰 목록과 상태를 조회합니다.",
        runIamIssueTokenBtn: "토큰 발급: 선택한 사용자의 새 토큰을 1회 발급합니다.",
        runIamPickTokenBtn: "토큰 선택: 입력한 token_id를 회전 또는 폐기 대상으로 선택합니다.",
        runIamRotateTokenBtn: "토큰 회전: 기존 토큰을 비활성화하고 새 토큰을 발급합니다.",
        runIamRevokeTokenBtn: "토큰 폐기: 선택한 토큰을 즉시 비활성화합니다.",
        runIamAuditBtn: "감사 로그 조회: action, actor, limit 조건으로 감사 로그를 검색합니다.",
        runAdoptionBtn: "정착 계획 새로고침: 교육자료, 실행표, KPI 패키지를 다시 조회합니다.",
        adoptScheduleCsv: "Schedule CSV: 정착 계획 일정을 CSV 파일로 내려받습니다.",
        adoptScheduleIcs: "Schedule ICS: 정착 계획 일정을 캘린더용 ICS 파일로 내려받습니다.",
        w04FunnelRefreshBtn: "W04 퍼널 새로고침: 첫 성공 퍼널과 상위 블로커 현황을 다시 조회합니다.",
        w05ConsistencyRefreshBtn: "W05 지표 새로고침: Usage Consistency(사용 정착도) 지표를 갱신합니다.",
        w06RhythmRefreshBtn: "W06 리듬 새로고침: Operational Rhythm(운영 리듬) 지표를 갱신합니다.",
        w07QualityRefreshBtn: "W07 품질 새로고침: SLA Quality(품질) 대시보드를 다시 조회합니다.",
        w08DisciplineRefreshBtn: "W08 리포트 새로고침: Report Discipline(보고 규율) 지표를 조회합니다.",
        w09KpiRefreshBtn: "W09 KPI 새로고침: KPI Operation(지표 운영) 현황을 갱신합니다.",
        w10KpiRefreshBtn: "W10 지표 새로고침: Self-serve Support(셀프 지원) 지표를 갱신합니다.",
        w11KpiRefreshBtn: "W11 지표 새로고침: Scale Readiness(확장 준비도) 지표를 갱신합니다.",
        w15KpiRefreshBtn: "W15 지표 새로고침: Operations Efficiency(운영 효율) 지표를 갱신합니다.",
        w07TrackBootstrapBtn: "W07 항목 생성: W07 실행 추적 항목을 site 기준으로 초기 생성합니다.",
        w07TrackNextBtn: "다음 미완료: 현재 목록에서 아직 끝나지 않은 다음 항목으로 이동합니다.",
        w07TrackUpdateBtn: "상태 저장: 선택 항목의 상태, 메모, 증빙을 저장합니다.",
        w07TrackRefreshBtn: "추적현황 새로고침: W07 실행 추적 목록을 다시 조회합니다.",
        w07SelectVisibleBtn: "현재 목록 전체 선택: 지금 화면에 보이는 항목을 한 번에 선택합니다.",
        w07ClearSelectionBtn: "선택 해제: 현재 선택된 W07 항목을 모두 해제합니다.",
        w07BulkApplyBtn: "선택 항목 일괄 저장: 선택된 W07 항목에 같은 상태를 일괄 적용합니다.",
        w07ReadinessBtn: "완료 판정: W07 완료 가능 여부와 blocker를 점검합니다.",
        w07CompleteBtn: "W07 완료 확정: 완료 판정 통과 후 W07을 완료 처리합니다.",
        w07CompleteAndWeeklyBtn: "W07 완료+주간실행: 완료 처리 후 주간 자동화까지 이어서 실행합니다.",
        w07DownloadPackageBtn: "W07 완료 패키지 다운로드: 증빙 포함 완료 패키지를 ZIP으로 내려받습니다.",
        w07CompleteModalCancel: "취소: 완료 확정 창을 닫고 작업을 취소합니다.",
        w07CompleteModalConfirm: "확정 실행: W07 완료 확정을 실제 실행합니다.",
        w07WeeklyRunBtn: "W07 주간 실행: SLA 품질 주간 점검을 즉시 실행합니다.",
        w07WeeklyLatestBtn: "최근 실행 조회: 마지막 주간 실행 결과를 조회합니다.",
        w07WeeklyTrendsBtn: "트렌드 조회: 주간 품질 추이를 시계열로 조회합니다.",
        runTutorialGlossaryBtn: "용어집 새로고침: 운영 용어집을 다시 불러와 검색 기준에 맞게 보여줍니다.",
      }};
      const SHARED_TRACKER_PHASE_LABELS = {{
        w02: "W02",
        w03: "W03",
        w04: "W04",
        w09: "W09",
        w10: "W10",
        w11: "W11",
        w15: "W15",
      }};
      let OPS_SPECIAL_CHECKLISTS = {ops_special_checklists_json};
      let OPS_SPECIAL_CHECKLIST_REVISIONS = [];
      const OPS_RESULT_OPTIONS = [
        {{ value: "normal", label: "정상" }},
        {{ value: "abnormal", label: "이상" }},
        {{ value: "na", label: "N/A" }},
      ];
      let opsElectricalChecklistRows = [];

      function persistToken(token) {{
        const normalized = String(token || "").trim();
        if (!normalized) return;
        const keys = Array.from(new Set([TOKEN_KEY].concat(TOKEN_KEY_ALIASES)));
        window.sessionStorage.setItem(TOKEN_KEY, normalized);
        keys.forEach((key) => {{
          if (key !== TOKEN_KEY) {{
            window.sessionStorage.removeItem(key);
          }}
          window.localStorage.removeItem(key);
        }});
      }}

      function getToken() {{
        const keys = Array.from(new Set([TOKEN_KEY].concat(TOKEN_KEY_ALIASES)));
        for (const key of keys) {{
          const sessionToken = window.sessionStorage.getItem(key) || "";
          if (!sessionToken) continue;
          if (key !== TOKEN_KEY) {{
            window.sessionStorage.setItem(TOKEN_KEY, sessionToken);
            window.sessionStorage.removeItem(key);
          }}
          return sessionToken;
        }}
        for (const key of keys) {{
          const localToken = window.localStorage.getItem(key) || "";
          if (!localToken) continue;
          window.sessionStorage.setItem(TOKEN_KEY, localToken);
          keys.forEach((aliasKey) => window.localStorage.removeItem(aliasKey));
          keys.forEach((aliasKey) => {{
            if (aliasKey !== TOKEN_KEY) {{
              window.sessionStorage.removeItem(aliasKey);
            }}
          }});
          return localToken;
        }}
        return "";
      }}

      function getStoredAuthProfile() {{
        const raw = window.sessionStorage.getItem(PROFILE_KEY) || window.localStorage.getItem(PROFILE_KEY) || "";
        if (!raw) return null;
        try {{
          const parsed = JSON.parse(raw);
          if (parsed && typeof parsed === "object") {{
            window.sessionStorage.setItem(PROFILE_KEY, JSON.stringify(parsed));
            window.localStorage.removeItem(PROFILE_KEY);
            return parsed;
          }}
        }} catch (err) {{
          window.sessionStorage.removeItem(PROFILE_KEY);
          window.localStorage.removeItem(PROFILE_KEY);
        }}
        return null;
      }}

      function persistAuthProfile(profile) {{
        if (!profile) {{
          window.sessionStorage.removeItem(PROFILE_KEY);
          window.localStorage.removeItem(PROFILE_KEY);
          return;
        }}
        window.sessionStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
        window.localStorage.removeItem(PROFILE_KEY);
      }}

      function clearStoredAuthArtifacts(options = {{}}) {{
        const keys = Array.from(new Set([TOKEN_KEY].concat(TOKEN_KEY_ALIASES)));
        keys.forEach((key) => {{
          window.sessionStorage.removeItem(key);
          window.localStorage.removeItem(key);
        }});
        persistAuthProfile(null);
        authProfile = null;
        if (!options.preserveInput && tokenInput) {{
          tokenInput.value = "";
        }}
      }}

      function setAuthState(text) {{
        authState.textContent = text;
      }}

      function setElementTooltip(element, text) {{
        if (!element || !text) {{
          return;
        }}
        element.setAttribute("data-tip", text);
        element.setAttribute("title", text);
      }}

      function applyStaticUiTooltips() {{
        Object.entries(UI_TOOLTIP_TEXT_BY_ID).forEach(([id, text]) => {{
          setElementTooltip(document.getElementById(id), text);
        }});
        Object.entries(SHARED_TRACKER_PHASE_LABELS).forEach(([phaseCode, phaseLabel]) => {{
          setElementTooltip(
            document.getElementById(phaseCode + "TrackBootstrapBtn"),
            phaseLabel + " 항목 생성: site 기준 실행 추적 항목을 초기 생성합니다."
          );
          setElementTooltip(
            document.getElementById(phaseCode + "TrackUpdateBtn"),
            phaseLabel + " 상태 저장: 담당자, 상태, 완료 체크와 증빙 메모를 저장합니다."
          );
          setElementTooltip(
            document.getElementById(phaseCode + "TrackRefreshBtn"),
            phaseLabel + " 추적현황 새로고침: 현재 실행 추적 항목을 다시 조회합니다."
          );
          setElementTooltip(
            document.getElementById(phaseCode + "ReadinessBtn"),
            phaseLabel + " 완료 판정: blocker와 준비도 조건을 점검합니다."
          );
          setElementTooltip(
            document.getElementById(phaseCode + "CompleteBtn"),
            phaseLabel + " 완료 확정: 완료 판정 후 phase를 실제 완료 상태로 전환합니다."
          );
        }});
      }}

      function updateAuthStateFromToken() {{
        const token = getToken();
        if (!token) {{
          authProfile = null;
          persistAuthProfile(null);
          setAuthState("토큰 상태: 없음");
          return;
        }}
        if (!authProfile) {{
          authProfile = getStoredAuthProfile();
        }}
        if (authProfile) {{
          const role = authProfile.role || "unknown";
          const username = authProfile.username || "unknown";
          const siteScope = Array.isArray(authProfile.site_scope) && authProfile.site_scope.length
            ? authProfile.site_scope.join(", ")
            : "*";
          setAuthState("토큰 상태: 저장됨 | 사용자: " + username + " | 역할: " + role + " | 범위: " + siteScope);
          return;
        }}
        setAuthState("토큰 상태: 저장됨 (연결 테스트 전)");
      }}

      function closeAuthModal() {{
        if (authLoginModal) {{
          authLoginModal.hidden = true;
        }}
        if (authSignupModal) {{
          authSignupModal.hidden = true;
        }}
        if (authModalBackdrop) {{
          authModalBackdrop.hidden = true;
        }}
        activeAuthModal = null;
      }}

      function openAuthModal(mode) {{
        closeAuthModal();
        if (mode === "signup" && authSignupModal) {{
          authSignupModal.hidden = false;
          activeAuthModal = "signup";
          if (signupUsernameInput) {{
            signupUsernameInput.focus();
          }}
        }} else if (authLoginModal) {{
          authLoginModal.hidden = false;
          activeAuthModal = "login";
          if (loginUsernameInput) {{
            loginUsernameInput.focus();
          }}
        }}
        if (authModalBackdrop) {{
          authModalBackdrop.hidden = false;
        }}
      }}

      function escapeHtml(value) {{
        return String(value)
          .replaceAll("&", "&amp;")
          .replaceAll("<", "&lt;")
          .replaceAll(">", "&gt;")
          .replaceAll('"', "&quot;")
          .replaceAll("'", "&#39;");
      }}

      function renderEmpty(text) {{
        return '<div class="empty">' + escapeHtml(text) + "</div>";
      }}

      function normalizeUiStatus(value) {{
        const normalized = String(value || "").trim().toLowerCase();
        if (normalized === "ok" || normalized === "success" || normalized === "ready") {{
          return "ok";
        }}
        if (normalized === "warning" || normalized === "warn") {{
          return "warning";
        }}
        if (normalized === "critical" || normalized === "error" || normalized === "fail") {{
          return "critical";
        }}
        return "info";
      }}

      function uiStatusLabel(status) {{
        const tone = normalizeUiStatus(status);
        if (tone === "ok") return "OK";
        if (tone === "warning") return "WARNING";
        if (tone === "critical") return "CRITICAL";
        return "INFO";
      }}

      function renderUiStatusChip(status) {{
        const tone = normalizeUiStatus(status);
        return '<span class="status-chip ' + tone + '">' + escapeHtml(uiStatusLabel(tone)) + "</span>";
      }}

      function formatDateLocal(value) {{
        if (!value) return "-";
        const parsed = new Date(value);
        if (Number.isNaN(parsed.getTime())) {{
          return String(value);
        }}
        return parsed.toLocaleString("ko-KR", {{
          year: "numeric",
          month: "2-digit",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false,
        }});
      }}

      function renderUiStatusCard(title, status, value, subtext) {{
        const tone = normalizeUiStatus(status);
        return (
          '<div class="card status-' + tone + '">'
          + '<div class="k">' + escapeHtml(title) + "</div>"
          + '<div class="v">' + escapeHtml(value) + "</div>"
          + '<div class="sub">' + renderUiStatusChip(tone) + " " + escapeHtml(subtext || "") + "</div>"
          + "</div>"
        );
      }}

      function asInt(value, fallback = 0) {{
        const parsed = Number(value);
        if (!Number.isFinite(parsed)) return fallback;
        return Math.trunc(parsed);
      }}

      function isW07EvidenceRequired(row) {{
        const itemType = String((row && row.item_type) || "").trim().toLowerCase();
        return itemType === "sla_checklist" || itemType === "coaching_play";
      }}

      function isW07MissingAssignee(row) {{
        return !String((row && row.assignee) || "").trim();
      }}

      function isW07MissingChecked(row) {{
        return !Boolean(row && row.completion_checked);
      }}

      function isW07MissingEvidence(row) {{
        return isW07EvidenceRequired(row) && asInt(row && row.evidence_count, 0) <= 0;
      }}

      function isW07IncompleteRow(row) {{
        const status = String((row && row.status) || "").trim().toLowerCase();
        return (
          status !== "done"
          || isW07MissingAssignee(row)
          || isW07MissingChecked(row)
          || isW07MissingEvidence(row)
        );
      }}

      function getW07FilterLabel(filterKey) {{
        const labels = {{
          all: "ALL",
          pending: "PENDING",
          in_progress: "IN PROGRESS",
          blocked: "BLOCKED",
          not_done: "NOT DONE",
          missing_assignee: "MISSING ASSIGNEE",
          missing_checked: "MISSING CHECKED",
          missing_evidence: "MISSING EVIDENCE",
        }};
        return labels[String(filterKey || "all")] || "ALL";
      }}

      function getW07FilteredItems(rows) {{
        const source = Array.isArray(rows) ? rows : w07TrackerItemsCache;
        const key = String(w07TrackerFilter || "all");
        return source.filter((row) => {{
          if (key === "pending") return String(row.status || "") === "pending";
          if (key === "in_progress") return String(row.status || "") === "in_progress";
          if (key === "blocked") return String(row.status || "") === "blocked";
          if (key === "not_done") return String(row.status || "") !== "done";
          if (key === "missing_assignee") return isW07MissingAssignee(row);
          if (key === "missing_checked") return isW07MissingChecked(row);
          if (key === "missing_evidence") return isW07MissingEvidence(row);
          return true;
        }});
      }}

      function getW07ItemById(itemId) {{
        const targetId = asInt(itemId, -1);
        if (targetId <= 0) return null;
        const found = w07TrackerItemsCache.find((row) => asInt(row.id, -1) === targetId);
        return found || null;
      }}

      function fillW07FormFromItem(item, options = {{}}) {{
        if (!item) return;
        const keepCurrentNote = Boolean(options.keepCurrentNote);
        const trackerItemId = asInt(item.id, 0);
        if (trackerItemId <= 0) return;
        w07ActiveItemId = trackerItemId;
        document.getElementById("w07TrackItemId").value = String(trackerItemId);
        document.getElementById("w07TrackAssignee").value = String(item.assignee || "");
        document.getElementById("w07TrackStatus").value = String(item.status || "");
        document.getElementById("w07TrackCompleted").checked = Boolean(item.completion_checked);
        document.getElementById("w07EvidenceListItemId").value = String(trackerItemId);
        if (!keepCurrentNote) {{
          document.getElementById("w07TrackNote").value = String(item.completion_note || "");
        }}
      }}

      function renderW07SelectionMeta() {{
        const meta = document.getElementById("w07SelectionMeta");
        if (!meta) return;
        const filteredCount = getW07FilteredItems().length;
        const totalCount = Array.isArray(w07TrackerItemsCache) ? w07TrackerItemsCache.length : 0;
        meta.textContent =
          "필터: " + getW07FilterLabel(w07TrackerFilter)
          + " | 표시: " + String(filteredCount) + "/" + String(totalCount)
          + " | 선택: " + String(w07SelectedItemIds.size);
      }}

      function pushW07ActionResult(entry) {{
        const base = {{
          at: new Date().toISOString(),
          action: "action",
          tracker_item_id: "-",
          result: "ok",
          detail: "",
        }};
        const row = Object.assign(base, entry || {{}});
        w07ActionResults = [row].concat(w07ActionResults).slice(0, 80);
      }}

      function renderW07ActionResultsPanel() {{
        const panel = document.getElementById("w07ActionResults");
        if (!panel) return;
        if (!Array.isArray(w07ActionResults) || w07ActionResults.length === 0) {{
          panel.innerHTML = renderEmpty("최근 작업 결과 없음");
          return;
        }}
        const rows = w07ActionResults.map((row, idx) => ({{
          no: idx + 1,
          at: formatDateLocal(row.at),
          action: row.action || "-",
          tracker_item_id: row.tracker_item_id || "-",
          result: String(row.result || "-").toUpperCase(),
          detail: row.detail || "",
        }}));
        panel.innerHTML = renderTable(
          rows,
          [
            {{ key: "no", label: "#" }},
            {{ key: "at", label: "At" }},
            {{ key: "action", label: "Action" }},
            {{ key: "tracker_item_id", label: "Tracker ID" }},
            {{ key: "result", label: "Result" }},
            {{ key: "detail", label: "Detail" }},
          ]
        );
      }}

      function renderW07ReadinessCards(readiness, completion) {{
        const cards = [
          {{
            label: "Readiness Ready",
            value: readiness && readiness.ready ? "YES" : "NO",
            status: readiness && readiness.ready ? "ok" : "warning",
            sub: "클릭하면 전체 보기",
            filter: "all",
          }},
          {{
            label: "Readiness %",
            value: String((readiness && readiness.readiness_score_percent) ?? 0),
            status: (readiness && readiness.ready) ? "ok" : "info",
            sub: "완료 점수",
            filter: "all",
          }},
          {{
            label: "Missing Assignee",
            value: String((readiness && readiness.missing_assignee_count) ?? 0),
            status: ((readiness && readiness.missing_assignee_count) ?? 0) > 0 ? "warning" : "ok",
            sub: "클릭하면 미지정 항목만",
            filter: "missing_assignee",
          }},
          {{
            label: "Missing Checked",
            value: String((readiness && readiness.missing_completion_checked_count) ?? 0),
            status: ((readiness && readiness.missing_completion_checked_count) ?? 0) > 0 ? "warning" : "ok",
            sub: "클릭하면 체크 누락만",
            filter: "missing_checked",
          }},
          {{
            label: "Missing Evidence",
            value: String((readiness && readiness.missing_required_evidence_count) ?? 0),
            status: ((readiness && readiness.missing_required_evidence_count) ?? 0) > 0 ? "critical" : "ok",
            sub: "클릭하면 증빙 누락만",
            filter: "missing_evidence",
          }},
          {{
            label: "Pending",
            value: String((readiness && readiness.pending_count) ?? 0),
            status: ((readiness && readiness.pending_count) ?? 0) > 0 ? "warning" : "ok",
            sub: "클릭하면 pending만",
            filter: "pending",
          }},
          {{
            label: "In Progress",
            value: String((readiness && readiness.in_progress_count) ?? 0),
            status: ((readiness && readiness.in_progress_count) ?? 0) > 0 ? "warning" : "ok",
            sub: "클릭하면 in_progress만",
            filter: "in_progress",
          }},
          {{
            label: "Blocked",
            value: String((readiness && readiness.blocked_count) ?? 0),
            status: ((readiness && readiness.blocked_count) ?? 0) > 0 ? "critical" : "ok",
            sub: "클릭하면 blocked만",
            filter: "blocked",
          }},
          {{
            label: "Completion Status",
            value: String((completion && completion.status) || "active"),
            status: ((completion && completion.status) || "active").startsWith("completed") ? "ok" : "info",
            sub: "completed_at=" + String((completion && completion.completed_at) || "-"),
            filter: "all",
          }},
        ];
        return cards.map((card) => {{
          const tone = normalizeUiStatus(card.status);
          const active = String(card.filter || "all") === String(w07TrackerFilter || "all");
          return (
            '<div class="card w07-readiness-card status-' + tone + (active ? " active" : "") + '" data-filter="' + escapeHtml(card.filter || "all") + '" tabindex="0" role="button">'
            + '<div class="k">' + escapeHtml(card.label) + "</div>"
            + '<div class="v">' + escapeHtml(card.value) + "</div>"
            + '<div class="sub">' + renderUiStatusChip(tone) + " " + escapeHtml(card.sub || "") + "</div>"
            + "</div>"
          );
        }}).join("");
      }}

      function renderW07TrackerTableMarkup(rows) {{
        if (!Array.isArray(rows) || rows.length === 0) {{
          return renderEmpty("데이터가 없습니다.");
        }}
        const head =
          "<th></th><th>ID</th><th>Type</th><th>Key</th><th>Name</th><th>Assignee</th><th>Status</th><th>Checked</th><th>Evidence</th><th>Updated At</th>";
        const body = rows.map((row) => {{
          const trackerId = asInt(row.id, 0);
          const selected = w07SelectedItemIds.has(trackerId);
          const requiredEvidence = isW07EvidenceRequired(row);
          const evidenceCount = asInt(row.evidence_count, 0);
          const evidenceChip = requiredEvidence
            ? (evidenceCount > 0 ? renderUiStatusChip("ok") : renderUiStatusChip("critical"))
            : renderUiStatusChip("info");
          const statusValue = String(row.status || "");
          const statusTone = statusValue === "done"
            ? "ok"
            : (statusValue === "blocked" ? "critical" : (statusValue === "in_progress" ? "warning" : "info"));
          const checkedTone = Boolean(row.completion_checked) ? "ok" : "warning";
          const rowClass = "w07-track-row" + (trackerId === w07ActiveItemId ? " active" : "");
          const typeLabel = String(row.item_type || "");
          const requiredBadge = requiredEvidence
            ? (' <span class="status-chip ' + (evidenceCount > 0 ? "ok" : "critical") + '">' + (evidenceCount > 0 ? "REQ OK" : "REQ MISS") + "</span>")
            : "";
          return (
            '<tr class="' + rowClass + '" data-item-id="' + escapeHtml(trackerId) + '">'
              + '<td><input class="w07-select-item" type="checkbox" data-item-id="' + escapeHtml(trackerId) + '"' + (selected ? " checked" : "") + " /></td>"
              + '<td><button type="button" class="btn soft w07-pick-item" data-item-id="' + escapeHtml(trackerId) + '">' + escapeHtml(trackerId) + "</button></td>"
              + "<td>" + escapeHtml(typeLabel) + requiredBadge + "</td>"
              + "<td>" + escapeHtml(row.item_key ?? "") + "</td>"
              + "<td>" + escapeHtml(row.item_name ?? "") + "</td>"
              + "<td>" + escapeHtml(row.assignee ?? "") + "</td>"
              + "<td>" + renderUiStatusChip(statusTone) + " " + escapeHtml(statusValue) + "</td>"
              + "<td>" + renderUiStatusChip(checkedTone) + " " + escapeHtml(Boolean(row.completion_checked)) + "</td>"
              + "<td>" + evidenceChip + " " + escapeHtml(evidenceCount) + "</td>"
              + "<td>" + escapeHtml(row.updated_at ?? "") + "</td>"
            + "</tr>"
          );
        }}).join("");
        return '<div class="table-wrap"><table><thead><tr>' + head + "</tr></thead><tbody>" + body + "</tbody></table></div>";
      }}

      function renderW07TrackerTablePanel() {{
        const table = document.getElementById("w07TrackerTable");
        const validIds = new Set((Array.isArray(w07TrackerItemsCache) ? w07TrackerItemsCache : []).map((row) => asInt(row.id, -1)));
        w07SelectedItemIds = new Set(Array.from(w07SelectedItemIds).filter((itemId) => validIds.has(asInt(itemId, -1))));
        if (w07ActiveItemId !== null && !validIds.has(asInt(w07ActiveItemId, -1))) {{
          w07ActiveItemId = null;
        }}
        const rows = getW07FilteredItems();
        table.innerHTML = renderW07TrackerTableMarkup(rows);
        renderW07SelectionMeta();
      }}

      function setW07TrackerFilter(filterKey, options = {{}}) {{
        const requested = String(filterKey || "all");
        const allowed = new Set(["all", "pending", "in_progress", "blocked", "not_done", "missing_assignee", "missing_checked", "missing_evidence"]);
        w07TrackerFilter = allowed.has(requested) ? requested : "all";
        renderW07TrackerTablePanel();
        if (w07LastReadiness && w07LastCompletion) {{
          const readinessCards = document.getElementById("w07ReadinessCards");
          readinessCards.innerHTML = renderW07ReadinessCards(w07LastReadiness, w07LastCompletion);
        }}
        const autoPick = Boolean(options.autoPick);
        if (autoPick) {{
          const rows = getW07FilteredItems();
          if (rows.length > 0) {{
            fillW07FormFromItem(rows[0], {{ keepCurrentNote: true }});
            renderW07TrackerTablePanel();
          }}
        }}
      }}

      function pickW07NextIncompleteItem() {{
        const source = getW07FilteredItems();
        const target = source.find((row) => isW07IncompleteRow(row));
        if (!target) return null;
        fillW07FormFromItem(target, {{ keepCurrentNote: true }});
        renderW07TrackerTablePanel();
        return target;
      }}

      function openW07CompleteModal(summaryText) {{
        const modal = document.getElementById("w07CompleteModal");
        const summary = document.getElementById("w07CompleteModalSummary");
        summary.textContent = summaryText;
        modal.classList.add("open");
        modal.setAttribute("aria-hidden", "false");
        return new Promise((resolve) => {{
          w07CompleteModalResolver = resolve;
        }});
      }}

      function closeW07CompleteModal(confirmed) {{
        const modal = document.getElementById("w07CompleteModal");
        modal.classList.remove("open");
        modal.setAttribute("aria-hidden", "true");
        const resolver = w07CompleteModalResolver;
        w07CompleteModalResolver = null;
        if (resolver) {{
          resolver(Boolean(confirmed));
        }}
      }}

      function assignW07EvidenceFile(file) {{
        const input = document.getElementById("w07EvidenceFile");
        if (!file) return;
        try {{
          const transfer = new DataTransfer();
          transfer.items.add(file);
          input.files = transfer.files;
        }} catch (err) {{
          // Some browsers restrict programmatic assignment; fallback to manual selection.
        }}
        document.getElementById("w07TrackerMeta").textContent =
          "증빙 파일 선택: " + String(file.name || "unknown") + " (" + String(asInt(file.size, 0)) + " bytes)";
      }}

      function renderTable(rows, columns) {{
        if (!Array.isArray(rows) || rows.length === 0) {{
          return renderEmpty("데이터가 없습니다.");
        }}
        const head = columns.map((c) => "<th>" + escapeHtml(c.label) + "</th>").join("");
        const body = rows.map((row) => {{
          const tds = columns.map((c) => {{
            const value = c.render ? c.render(row[c.key], row) : row[c.key];
            if (value === null || value === undefined) return "<td></td>";
            return "<td>" + escapeHtml(value) + "</td>";
          }}).join("");
          return "<tr>" + tds + "</tr>";
        }}).join("");
        return '<div class="table-wrap"><table><thead><tr>' + head + '</tr></thead><tbody>' + body + "</tbody></table></div>";
      }}

      function renderMiniLinks(links) {{
        if (!Array.isArray(links) || links.length === 0) {{
          return "";
        }}
        const items = links
          .filter((row) => row && row.href)
          .map((row) => {{
            const href = escapeHtml(row.href || "#");
            const label = escapeHtml(row.label || row.href || "link");
            return '<a href="' + href + '" target="_blank" rel="noopener">' + label + "</a>";
          }})
          .join("");
        if (!items) {{
          return "";
        }}
        return '<div class="mini-links">' + items + "</div>";
      }}

      function renderTutorialDay1Cards(steps) {{
        if (!Array.isArray(steps) || steps.length === 0) {{
          return renderEmpty("체크리스트가 없습니다.");
        }}
        return steps.map((step) => {{
          const stepNo = escapeHtml(step.step_no ?? "");
          const role = escapeHtml(step.recommended_role || "all");
          const title = escapeHtml(step.title || "-");
          const minutes = escapeHtml(step.estimated_minutes ?? 0);
          const goal = escapeHtml(step.goal || "-");
          const successCheck = escapeHtml(step.success_check || "-");
          return (
            '<div class="card">' +
              '<div class="k">Step ' + stepNo + ' · 추천 역할: ' + role + "</div>" +
              '<div style="margin-top:6px; font-size:16px; font-weight:800;">' + title + "</div>" +
              '<div class="sub">예상 소요 ' + minutes + "분</div>" +
              '<div style="margin-top:8px; font-size:12px; color:#35587f;">목표: ' + goal + "</div>" +
              '<div style="margin-top:6px; font-size:12px; color:#35587f;">완료 확인: ' + successCheck + "</div>" +
              renderMiniLinks(step.links) +
            "</div>"
          );
        }}).join("");
      }}

      function renderTutorialRoleGuides(guides) {{
        if (!Array.isArray(guides) || guides.length === 0) {{
          return renderEmpty("역할별 가이드가 없습니다.");
        }}
        return guides.map((guide) => {{
          const role = escapeHtml(guide.role || "-");
          const roleKo = escapeHtml(guide.role_ko || "-");
          const focus = escapeHtml(guide.first_focus || "-");
          const actions = Array.isArray(guide.first_actions) ? guide.first_actions : [];
          const actionHtml = actions.length === 0
            ? '<div style="margin-top:6px; font-size:12px; color:#35587f;">시작 액션이 없습니다.</div>'
            : actions
              .map((item, index) => '<div style="margin-top:6px; font-size:12px; color:#35587f;">' + escapeHtml(String(index + 1) + ". " + item) + "</div>")
              .join("");
          return (
            '<div class="card">' +
              '<div class="k">' + role.toUpperCase() + " · " + roleKo + "</div>" +
              '<div style="margin-top:6px; font-size:15px; font-weight:800;">' + focus + "</div>" +
              actionHtml +
              renderMiniLinks(guide.recommended_links) +
            "</div>"
          );
        }}).join("");
      }}

      function populateTutorialGlossaryCategories(categories) {{
        const selectNode = document.getElementById("tutorialGlossaryCategory");
        if (!selectNode) {{
          return;
        }}
        const currentValue = String(selectNode.value || "all");
        const options = ['<option value="all">category: all</option>'];
        if (Array.isArray(categories)) {{
          categories.forEach((category) => {{
            if (!category || !category.id) {{
              return;
            }}
            options.push(
              '<option value="'
              + escapeHtml(category.id)
              + '">'
              + escapeHtml(category.label || category.id)
              + "</option>"
            );
          }});
        }}
        selectNode.innerHTML = options.join("");
        selectNode.value = Array.from(selectNode.options).some((option) => option.value === currentValue)
          ? currentValue
          : "all";
      }}

      function applyTutorialGlossaryFilters() {{
        const metaNode = document.getElementById("tutorialGlossaryMeta");
        const tableNode = document.getElementById("tutorialGlossaryTable");
        const searchNode = document.getElementById("tutorialGlossarySearch");
        const categoryNode = document.getElementById("tutorialGlossaryCategory");
        if (!metaNode || !tableNode) {{
          return;
        }}
        const payload = tutorialGlossaryPayload || {{}};
        const items = Array.isArray(payload.items) ? payload.items : [];
        const search = String(searchNode && searchNode.value ? searchNode.value : "").trim().toLowerCase();
        const category = String(categoryNode && categoryNode.value ? categoryNode.value : "all").trim().toLowerCase() || "all";
        const filtered = items.filter((item) => {{
          const itemCategory = String(item.category || "").trim().toLowerCase();
          if (category !== "all" && itemCategory !== category) {{
            return false;
          }}
          if (!search) {{
            return true;
          }}
          const haystack = [
            item.term,
            item.term_ko,
            item.category_ko,
            item.business_meaning,
            item.first_use,
          ]
            .map((value) => String(value || "").toLowerCase())
            .join(" ");
          return haystack.includes(search);
        }});
        metaNode.textContent =
          "용어 "
          + String(filtered.length)
          + "/"
          + String(items.length)
          + " | published="
          + String(payload.published_on || "-")
          + " | category="
          + String(category);
        const rows = filtered.map((item) => {{
          return {{
            term: String(item.term || "-"),
            term_ko: String(item.term_ko || "-"),
            category: String(item.category_ko || item.category || "-"),
            business_meaning: String(item.business_meaning || "-"),
            first_use: String(item.first_use || "-"),
          }};
        }});
        tableNode.innerHTML = renderTable(rows, [
          {{ key: "term", label: "영문" }},
          {{ key: "term_ko", label: "한글" }},
          {{ key: "category", label: "분류" }},
          {{ key: "business_meaning", label: "업무 의미" }},
          {{ key: "first_use", label: "처음 어디서 쓰는가" }},
        ]);
      }}

      async function runTutorialOnboarding() {{
        const metaNode = document.getElementById("tutorialDay1Meta");
        const cardsNode = document.getElementById("tutorialDay1Cards");
        const guidesNode = document.getElementById("tutorialRoleGuides");
        if (!metaNode || !cardsNode || !guidesNode) {{
          return;
        }}
        metaNode.textContent = "온보딩 체크리스트 조회 중...";
        try {{
          tutorialOnboardingPayload = await fetchJson("/api/public/onboarding/day1", false);
          const steps = Array.isArray(tutorialOnboardingPayload.day1_checklist)
            ? tutorialOnboardingPayload.day1_checklist
            : [];
          const guides = Array.isArray(tutorialOnboardingPayload.role_guides)
            ? tutorialOnboardingPayload.role_guides
            : [];
          cardsNode.innerHTML = renderTutorialDay1Cards(steps);
          guidesNode.innerHTML = renderTutorialRoleGuides(guides);
          metaNode.textContent =
            "체크리스트 "
            + String(steps.length)
            + "개 | 역할 가이드 "
            + String(guides.length)
            + "개 | 예상 "
            + String(tutorialOnboardingPayload.total_estimated_minutes || 0)
            + "분";
        }} catch (err) {{
          cardsNode.innerHTML = renderEmpty("온보딩 체크리스트를 불러오지 못했습니다.");
          guidesNode.innerHTML = renderEmpty("역할별 가이드를 불러오지 못했습니다.");
          metaNode.textContent = "조회 실패: " + err.message;
        }}
      }}

      async function runTutorialGlossary(forceRefresh) {{
        const metaNode = document.getElementById("tutorialGlossaryMeta");
        const tableNode = document.getElementById("tutorialGlossaryTable");
        if (!metaNode || !tableNode) {{
          return;
        }}
        metaNode.textContent = "용어집 조회 중...";
        try {{
          if (!tutorialGlossaryPayload || forceRefresh) {{
            tutorialGlossaryPayload = await fetchJson("/api/public/glossary", false);
          }}
          populateTutorialGlossaryCategories(tutorialGlossaryPayload.categories);
          applyTutorialGlossaryFilters();
        }} catch (err) {{
          tableNode.innerHTML = renderEmpty("운영 용어집을 불러오지 못했습니다.");
          metaNode.textContent = "조회 실패: " + err.message;
        }}
      }}

      function renderEvidenceTable(rows, trackerPhase) {{
        if (!Array.isArray(rows) || rows.length === 0) {{
          return renderEmpty("증빙 파일이 없습니다.");
        }}
        const phase = trackerPhase === "w10"
          ? "w10"
          : (trackerPhase === "w09"
          ? "w09"
          : (trackerPhase === "w07"
            ? "w07"
            : (trackerPhase === "w04" ? "w04" : (trackerPhase === "w03" ? "w03" : "w02"))));
        const body = rows.map((row) => {{
          const downloadHref = "/api/adoption/" + phase + "/tracker/evidence/" + encodeURIComponent(String(row.id || "")) + "/download";
          return (
            "<tr>" +
              "<td>" + escapeHtml(row.id ?? "") + "</td>" +
              "<td>" + escapeHtml(row.file_name ?? "") + "</td>" +
              "<td>" + escapeHtml(row.file_size ?? "") + "</td>" +
              "<td>" + escapeHtml(row.uploaded_by ?? "") + "</td>" +
              "<td>" + escapeHtml(row.uploaded_at ?? "") + "</td>" +
              "<td>" + escapeHtml(row.note ?? "") + "</td>" +
              '<td><a href="' + downloadHref + '" target="_blank" rel="noopener">download</a></td>' +
            "</tr>"
          );
        }}).join("");
        return (
          '<div class="table-wrap"><table><thead><tr>' +
          "<th>ID</th><th>File</th><th>Size</th><th>Uploaded By</th><th>Uploaded At</th><th>Note</th><th>Download</th>" +
          "</tr></thead><tbody>" + body + "</tbody></table></div>"
        );
      }}

      function buildQuery(pairs) {{
        const params = new URLSearchParams();
        pairs.forEach((pair) => {{
          const node = document.getElementById(pair.id);
          if (!node) return;
          const value = (node.value || "").trim();
          if (value !== "") {{
            params.set(pair.key, value);
          }}
        }});
        return params.toString();
      }}

      async function fetchJson(path, requiresAuth, options = {{}}) {{
        const headers = {{ "Accept": "application/json" }};
        const optionHeaders = options.headers || {{}};
        Object.keys(optionHeaders).forEach((key) => {{
          headers[key] = optionHeaders[key];
        }});
        if (requiresAuth) {{
          const token = getToken();
          if (!token) {{
            throw new Error("인증 토큰이 없습니다.");
          }}
          headers["X-Admin-Token"] = token;
        }}
        const requestOptions = {{
          method: options.method || "GET",
          headers,
        }};
        if (Object.prototype.hasOwnProperty.call(options, "body")) {{
          requestOptions.body = options.body;
        }}
        const response = await fetch(path, requestOptions);
        const text = await response.text();
        let data = null;
        try {{
          data = text ? JSON.parse(text) : null;
        }} catch (err) {{
          data = text;
        }}
        if (!response.ok) {{
          if (requiresAuth && response.status === 401) {{
            clearStoredAuthArtifacts({{ preserveInput: true }});
            updateAuthStateFromToken();
          }}
          throw new Error("HTTP " + response.status + " | " + (typeof data === "string" ? data : JSON.stringify(data)));
        }}
        return data;
      }}

      function parseContentDispositionFilename(value) {{
        const raw = String(value || "");
        if (!raw) return "";
        const utfMatch = raw.match(/filename\\*=UTF-8''([^;]+)/i);
        if (utfMatch && utfMatch[1]) {{
          try {{
            return decodeURIComponent(utfMatch[1]);
          }} catch (err) {{
            return utfMatch[1];
          }}
        }}
        const basicMatch = raw.match(/filename=\"?([^\";]+)\"?/i);
        if (basicMatch && basicMatch[1]) {{
          return basicMatch[1];
        }}
        return "";
      }}

      async function downloadAuthFile(path, defaultFilename) {{
        const token = getToken();
        if (!token) {{
          throw new Error("인증 토큰이 없습니다.");
        }}
        const response = await fetch(path, {{
          method: "GET",
          headers: {{
            "X-Admin-Token": token,
            "Accept": "application/octet-stream",
          }},
        }});
        if (!response.ok) {{
          const text = await response.text();
          throw new Error("HTTP " + response.status + " | " + text);
        }}
        const blob = await response.blob();
        const headerName = parseContentDispositionFilename(response.headers.get("Content-Disposition"));
        const fileName = headerName || defaultFilename || "download.bin";
        const objectUrl = window.URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = objectUrl;
        anchor.download = fileName;
        anchor.rel = "noopener";
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        window.setTimeout(() => window.URL.revokeObjectURL(objectUrl), 1000);
        return {{
          fileName,
          size: blob.size,
          sha256: response.headers.get("X-Archive-SHA256") || "",
        }};
      }}

      function activate(tab, updateUrl) {{
        const selected = panels[tab] ? tab : "overview";
        buttons.forEach((btn) => {{
          const active = btn.dataset.tab === selected;
          btn.classList.toggle("active", active);
          btn.setAttribute("aria-selected", active ? "true" : "false");
        }});
        Object.entries(panels).forEach(([key, panel]) => {{
          const active = key === selected;
          panel.classList.toggle("active", active);
          panel.setAttribute("aria-hidden", active ? "false" : "true");
        }});
        if (updateUrl) {{
          url.searchParams.set("tab", selected);
          window.history.replaceState(null, "", url.pathname + (url.search || ""));
        }}
      }}

      async function runAuthMe() {{
        try {{
          authProfile = await fetchJson("/api/auth/me", true);
          persistAuthProfile(authProfile);
          const inspectorNode = document.getElementById("inCreateInspector");
          if (inspectorNode && !(inspectorNode.value || "").trim()) {{
            inspectorNode.value = String(authProfile && authProfile.username ? authProfile.username : "");
          }}
          const billingReaderNode = document.getElementById("billingReadingReader");
          if (billingReaderNode && !(billingReaderNode.value || "").trim()) {{
            billingReaderNode.value = String(authProfile && authProfile.username ? authProfile.username : "");
          }}
          updateAuthStateFromToken();
          return authProfile;
        }} catch (err) {{
          authProfile = null;
          persistAuthProfile(null);
          updateAuthStateFromToken();
          throw err;
        }}
      }}

      async function runAuthLogin() {{
        const username = (loginUsernameInput && loginUsernameInput.value ? loginUsernameInput.value : "").trim();
        const password = (loginPasswordInput && loginPasswordInput.value ? loginPasswordInput.value : "").trim();
        const tokenLabelInputValue = (loginTokenLabelInput && loginTokenLabelInput.value ? loginTokenLabelInput.value : "").trim();
        const tokenLabel = tokenLabelInputValue || "web-login";
        if (!username) {{
          setAuthState("로그인 실패: username을 입력하세요.");
          return;
        }}
        if (!password) {{
          setAuthState("로그인 실패: password를 입력하세요.");
          return;
        }}
        setAuthState("로그인 중...");
        try {{
          const result = await fetchJson("/api/auth/login", false, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify({{
              username,
              password,
              token_label: tokenLabel,
            }}),
          }});
          if (!result || !result.token) {{
            throw new Error("로그인 응답에 token이 없습니다.");
          }}
          persistToken(String(result.token));
          tokenInput.value = String(result.token);
          if (loginPasswordInput) {{
            loginPasswordInput.value = "";
          }}
          authProfile = result.profile || null;
          persistAuthProfile(authProfile);
          updateAuthStateFromToken();
          if (authProfile) {{
            setAuthState("로그인 성공 | 사용자: " + authProfile.username + " | 역할: " + authProfile.role);
            closeAuthModal();
            activate(roleDefaultTab(authProfile), true);
          }} else {{
            setAuthState("로그인 성공 | 토큰 발급 완료");
            closeAuthModal();
          }}
        }} catch (err) {{
          authProfile = null;
          persistAuthProfile(null);
          updateAuthStateFromToken();
          setAuthState("로그인 실패 | " + err.message);
        }}
      }}

      async function runAuthLogout() {{
        const token = getToken();
        if (!token) {{
          setAuthState("로그아웃 안내: 현재 저장된 토큰이 없습니다.");
          return;
        }}
        setAuthState("로그아웃 처리 중...");
        try {{
          const result = await fetchJson("/api/auth/logout", true, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify({{}}),
          }});
          clearStoredAuthArtifacts();
          iamUsersCache = [];
          iamFilteredUsersCache = [];
          iamTokensCache = [];
          iamFilteredTokensCache = [];
          iamSelectedUserId = null;
          iamSelectedTokenId = null;
          iamAuditLogsCache = [];
          iamSelectedAuditLogId = null;
          updateAuthStateFromToken();
          const detail = []
          detail.push("token_revoked=" + String(Boolean(result && result.token_revoked)));
          detail.push("is_legacy=" + String(Boolean(result && result.is_legacy)));
          setAuthState("로그아웃 완료 | " + detail.join(" | "));
          const iamMeMeta = document.getElementById("iamMeMeta");
          const iamMeTable = document.getElementById("iamMeTable");
          const iamUsersMeta = document.getElementById("iamUsersMeta");
          const iamUsersTable = document.getElementById("iamUsersTable");
          const iamTokensMeta = document.getElementById("iamTokensMeta");
          const iamTokensTable = document.getElementById("iamTokensTable");
          const iamTokenActionMeta = document.getElementById("iamTokenActionMeta");
          const iamTokenPlain = document.getElementById("iamTokenPlain");
          const iamAuditMeta = document.getElementById("iamAuditMeta");
          const iamAuditTable = document.getElementById("iamAuditTable");
          const iamAuditDetail = document.getElementById("iamAuditDetail");
          if (iamMeMeta) {{
            iamMeMeta.textContent = "로그아웃 완료";
          }}
          if (iamMeTable) {{
            iamMeTable.innerHTML = renderEmpty("로그아웃 상태입니다.");
          }}
          if (iamUsersMeta) {{
            iamUsersMeta.textContent = "로그아웃 상태";
          }}
          if (iamUsersTable) {{
            iamUsersTable.innerHTML = renderEmpty("로그아웃 상태입니다.");
          }}
          if (iamTokensMeta) {{
            iamTokensMeta.textContent = "로그아웃 상태";
          }}
          if (iamTokensTable) {{
            iamTokensTable.innerHTML = renderEmpty("로그아웃 상태입니다.");
          }}
          if (iamTokenActionMeta) {{
            iamTokenActionMeta.textContent = "로그아웃 상태";
          }}
          if (iamTokenPlain) {{
            iamTokenPlain.textContent = "신규 토큰 값은 발급/회전 직후 1회만 표시됩니다.";
          }}
          if (iamAuditMeta) {{
            iamAuditMeta.textContent = "로그아웃 상태";
          }}
          if (iamAuditTable) {{
            iamAuditTable.innerHTML = renderEmpty("로그아웃 상태입니다.");
          }}
          if (iamAuditDetail) {{
            iamAuditDetail.textContent = "로그를 선택하면 detail JSON이 표시됩니다.";
          }}
          document.getElementById("iamSelectedTokenId").value = "";
          document.getElementById("iamSelectedTokenUser").value = "";
          document.getElementById("iamSelectedTokenLabel").value = "";
        }} catch (err) {{
          setAuthState("로그아웃 실패 | " + err.message);
        }}
      }}

      function parseSiteScopeInput(raw) {{
        const parts = String(raw || "")
          .split(",")
          .map((item) => item.trim())
          .filter((item) => item !== "");
        if (!parts.length) {{
          return ["*"];
        }}
        if (parts.includes("*")) {{
          return ["*"];
        }}
        return Array.from(new Set(parts));
      }}

      function parsePermissionsInput(raw) {{
        const parts = String(raw || "")
          .split(",")
          .map((item) => item.trim())
          .filter((item) => item !== "");
        return Array.from(new Set(parts));
      }}

      async function runAuthSignup() {{
        const username = (signupUsernameInput && signupUsernameInput.value ? signupUsernameInput.value : "").trim();
        const password = (signupPasswordInput && signupPasswordInput.value ? signupPasswordInput.value : "").trim();
        const displayName = (signupDisplayNameInput && signupDisplayNameInput.value ? signupDisplayNameInput.value : "").trim();
        const roleValue = (signupRoleInput && signupRoleInput.value ? signupRoleInput.value : "").trim().toLowerCase();
        const role = roleValue || "operator";
        const siteScopeRaw = (signupSiteScopeInput && signupSiteScopeInput.value ? signupSiteScopeInput.value : "").trim();

        if (!username) {{
          setAuthState("가입 실패: username을 입력하세요.");
          return;
        }}
        if (!password) {{
          setAuthState("가입 실패: password를 입력하세요.");
          return;
        }}
        setAuthState("가입 처리 중...");
        try {{
          const payload = {{
            username,
            password,
            role,
            permissions: [],
            site_scope: parseSiteScopeInput(siteScopeRaw),
          }};
          if (displayName) {{
            payload.display_name = displayName;
          }}
          const created = await fetchJson("/api/admin/users", true, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify(payload),
          }});
          if (signupPasswordInput) {{
            signupPasswordInput.value = "";
          }}
          if (loginUsernameInput) {{
            loginUsernameInput.value = String(created.username || username);
          }}
          if (loginPasswordInput) {{
            loginPasswordInput.value = password;
          }}
          setAuthState(
            "가입 성공 | 사용자: " + String(created.username || username)
            + " | 역할: " + String(created.role || role)
            + " | 이제 ID/PW 로그인 버튼으로 확인하세요."
          );
          openAuthModal("login");
        }} catch (err) {{
          setAuthState("가입 실패 | " + err.message);
        }}
      }}

      function getIamUserFromCache(userId) {{
        const targetId = asInt(userId, -1);
        if (targetId <= 0) return null;
        const found = iamUsersCache.find((row) => asInt(row.id, -1) === targetId);
        return found || null;
      }}

      function applyIamUserToForm(user) {{
        if (!user) return;
        const userId = asInt(user.id, 0);
        if (userId <= 0) return;
        iamSelectedUserId = userId;
        document.getElementById("iamEditUserId").value = String(userId);
        document.getElementById("iamEditUsername").value = String(user.username || "");
        document.getElementById("iamEditDisplayName").value = String(user.display_name || "");
        document.getElementById("iamEditRole").value = String(user.role || "operator");
        const siteScope = Array.isArray(user.site_scope) ? user.site_scope : [];
        document.getElementById("iamEditSiteScope").value = siteScope.join(",");
        const permissions = Array.isArray(user.permissions) ? user.permissions : [];
        document.getElementById("iamEditPermissions").value = permissions.join(",");
        document.getElementById("iamEditIsActive").value = user.is_active ? "true" : "false";
        const issueUserInput = document.getElementById("iamIssueTokenUserId");
        if (issueUserInput) {{
          issueUserInput.value = String(userId);
        }}
        const tokenFilterInput = document.getElementById("iamTokensFilterUserId");
        if (tokenFilterInput && !String(tokenFilterInput.value || "").trim()) {{
          tokenFilterInput.value = String(userId);
        }}
      }}

      function renderIamUsersTable(rows) {{
        if (!Array.isArray(rows) || rows.length === 0) {{
          return renderEmpty("사용자 데이터가 없습니다.");
        }}
        const body = rows.map((row) => {{
          const userId = asInt(row.id, 0);
          const selectedCls = iamSelectedUserId === userId ? ' class="w07-track-row active"' : "";
          const scopeText = Array.isArray(row.site_scope) ? row.site_scope.join(", ") : "";
          const permsText = Array.isArray(row.permissions) ? row.permissions.join(", ") : "";
          return (
            "<tr" + selectedCls + ">" +
              "<td>" + escapeHtml(userId) + "</td>" +
              "<td>" + escapeHtml(row.username || "") + "</td>" +
              "<td>" + escapeHtml(row.display_name || "") + "</td>" +
              "<td>" + escapeHtml(row.role || "") + "</td>" +
              "<td>" + escapeHtml(row.is_active ? "true" : "false") + "</td>" +
              "<td>" + escapeHtml(scopeText) + "</td>" +
              "<td>" + escapeHtml(permsText) + "</td>" +
              '<td><button class="btn soft iam-select-user" type="button" data-user-id="' + escapeHtml(userId) + '" data-tip="선택: 이 사용자를 아래 수정 및 권한 폼으로 불러옵니다." title="선택: 이 사용자를 아래 수정 및 권한 폼으로 불러옵니다.">선택</button></td>' +
            "</tr>"
          );
        }}).join("");
        return (
          '<div class="table-wrap"><table><thead><tr>'
          + "<th>ID</th><th>Username</th><th>Display</th><th>Role</th><th>Active</th><th>Site Scope</th><th>Permissions</th><th>Action</th>"
          + "</tr></thead><tbody>" + body + "</tbody></table></div>"
        );
      }}

      function getFilteredIamUsers(rows) {{
        const roleFilter = String(document.getElementById("iamFilterRole").value || "").trim().toLowerCase();
        const activeFilter = String(document.getElementById("iamFilterActive").value || "all").trim().toLowerCase();
        const searchFilter = String(document.getElementById("iamFilterSearch").value || "").trim().toLowerCase();
        let filtered = Array.isArray(rows) ? rows.slice() : [];
        if (roleFilter) {{
          filtered = filtered.filter((row) => String(row.role || "").toLowerCase() === roleFilter);
        }}
        if (activeFilter === "true" || activeFilter === "false") {{
          const expected = activeFilter === "true";
          filtered = filtered.filter((row) => Boolean(row.is_active) === expected);
        }}
        if (searchFilter) {{
          filtered = filtered.filter((row) => {{
            const candidate = (String(row.username || "") + " " + String(row.display_name || "")).toLowerCase();
            return candidate.includes(searchFilter);
          }});
        }}
        return filtered;
      }}

      async function runIamMe() {{
        const meta = document.getElementById("iamMeMeta");
        const table = document.getElementById("iamMeTable");
        const tokenPolicyTable = document.getElementById("iamTokenPolicyTable");
        try {{
          meta.textContent = "조회 중... /api/auth/me";
          const profile = await runAuthMe();
          const role = String(profile.role || "").toLowerCase();
          const ownerHint = role === "owner" ? "owner 권한 확인됨" : ("현재 role=" + role);
          meta.textContent = "성공: /api/auth/me | " + ownerHint;
          const rows = [{{
            username: profile.username || "",
            display_name: profile.display_name || "",
            role: profile.role || "",
            site_scope: Array.isArray(profile.site_scope) ? profile.site_scope.join(", ") : "",
            permissions: Array.isArray(profile.permissions) ? profile.permissions.join(", ") : "",
            token_label: profile.token_label || "",
            token_expires_at: profile.token_expires_at || "",
            token_rotate_due_at: profile.token_rotate_due_at || "",
            token_idle_due_at: profile.token_idle_due_at || "",
            token_must_rotate: Boolean(profile.token_must_rotate),
            is_legacy: Boolean(profile.is_legacy),
          }}];
          table.innerHTML = renderTable(rows, [
            {{ key: "username", label: "Username" }},
            {{ key: "display_name", label: "Display" }},
            {{ key: "role", label: "Role" }},
            {{ key: "site_scope", label: "Site Scope" }},
            {{ key: "permissions", label: "Permissions" }},
            {{ key: "token_label", label: "Token Label" }},
            {{ key: "token_expires_at", label: "Token Expires At" }},
            {{ key: "token_rotate_due_at", label: "Rotate Due At" }},
            {{ key: "token_idle_due_at", label: "Idle Due At" }},
            {{ key: "token_must_rotate", label: "Must Rotate" }},
            {{ key: "is_legacy", label: "Is Legacy" }},
          ]);
          tokenPolicyTable.innerHTML = renderEmpty("토큰 정책은 '토큰 정책 조회' 버튼으로 확인하세요.");
          return profile;
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          table.innerHTML = renderEmpty(err.message);
          tokenPolicyTable.innerHTML = renderEmpty(err.message);
          throw err;
        }}
      }}

      async function runIamTokenPolicy() {{
        const table = document.getElementById("iamTokenPolicyTable");
        try {{
          table.innerHTML = renderEmpty("조회 중...");
          const policy = await fetchJson("/api/admin/token-policy", true);
          table.innerHTML = renderTable([policy], [
            {{ key: "require_expiry", label: "Require Expiry" }},
            {{ key: "max_ttl_days", label: "Max TTL Days" }},
            {{ key: "rotate_after_days", label: "Rotate After Days" }},
            {{ key: "rotate_warning_days", label: "Rotate Warning Days" }},
            {{ key: "max_idle_days", label: "Max Idle Days" }},
            {{ key: "max_active_per_user", label: "Max Active Per User" }},
          ]);
        }} catch (err) {{
          table.innerHTML = renderEmpty(err.message);
        }}
      }}

      async function runIamUsers() {{
        const meta = document.getElementById("iamUsersMeta");
        const table = document.getElementById("iamUsersTable");
        try {{
          meta.textContent = "조회 중... /api/admin/users";
          const users = await fetchJson("/api/admin/users", true);
          iamUsersCache = Array.isArray(users) ? users : [];
          const rows = getFilteredIamUsers(iamUsersCache);
          iamFilteredUsersCache = rows.slice();
          meta.textContent = "성공: /api/admin/users | total=" + String(iamUsersCache.length) + " | filtered=" + String(rows.length);
          table.innerHTML = renderIamUsersTable(rows);
          return rows;
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          table.innerHTML = renderEmpty(err.message);
          iamFilteredUsersCache = [];
          return [];
        }}
      }}

      async function runIamPickUser() {{
        const editMeta = document.getElementById("iamEditMeta");
        const userId = asInt(document.getElementById("iamEditUserId").value, -1);
        if (userId <= 0) {{
          editMeta.textContent = "실패: user_id를 입력하세요.";
          return;
        }}
        if (!iamUsersCache.length) {{
          await runIamUsers();
        }}
        const user = getIamUserFromCache(userId);
        if (!user) {{
          editMeta.textContent = "실패: user_id=" + String(userId) + " 를 목록에서 찾을 수 없습니다.";
          return;
        }}
        applyIamUserToForm(user);
        editMeta.textContent = "선택 완료: user_id=" + String(userId) + " (" + String(user.username || "") + ")";
        const visibleRows = iamFilteredUsersCache.length ? iamFilteredUsersCache : getFilteredIamUsers(iamUsersCache);
        document.getElementById("iamUsersTable").innerHTML = renderIamUsersTable(visibleRows);
      }}

      async function runIamCreateUser() {{
        const meta = document.getElementById("iamCreateMeta");
        const username = String(document.getElementById("iamCreateUsername").value || "").trim();
        const password = String(document.getElementById("iamCreatePassword").value || "").trim();
        const displayName = String(document.getElementById("iamCreateDisplayName").value || "").trim();
        const role = String(document.getElementById("iamCreateRole").value || "operator").trim().toLowerCase();
        const siteScopeRaw = String(document.getElementById("iamCreateSiteScope").value || "").trim();
        const permissionsRaw = String(document.getElementById("iamCreatePermissions").value || "").trim();
        const isActive = Boolean(document.getElementById("iamCreateIsActive").checked);
        if (!username) {{
          meta.textContent = "실패: username을 입력하세요.";
          return;
        }}
        if (!password) {{
          meta.textContent = "실패: password를 입력하세요.";
          return;
        }}
        try {{
          const payload = {{
            username,
            password,
            role,
            permissions: parsePermissionsInput(permissionsRaw),
            site_scope: parseSiteScopeInput(siteScopeRaw),
            is_active: isActive,
          }};
          if (displayName) {{
            payload.display_name = displayName;
          }}
          const created = await fetchJson("/api/admin/users", true, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify(payload),
          }});
          meta.textContent = "생성 성공: user_id=" + String(created.id) + " | username=" + String(created.username || "");
          document.getElementById("iamCreatePassword").value = "";
          await runIamUsers();
          applyIamUserToForm(created);
          document.getElementById("iamEditMeta").textContent = "선택 완료: 방금 생성한 사용자";
        }} catch (err) {{
          meta.textContent = "생성 실패: " + err.message;
        }}
      }}

      async function runIamUpdateUser() {{
        const meta = document.getElementById("iamEditMeta");
        const userId = asInt(document.getElementById("iamEditUserId").value, -1);
        if (userId <= 0) {{
          meta.textContent = "실패: user_id를 입력하세요.";
          return;
        }}
        try {{
          const payload = {{
            display_name: String(document.getElementById("iamEditDisplayName").value || "").trim(),
            role: String(document.getElementById("iamEditRole").value || "operator").trim().toLowerCase(),
            permissions: parsePermissionsInput(document.getElementById("iamEditPermissions").value || ""),
            site_scope: parseSiteScopeInput(document.getElementById("iamEditSiteScope").value || ""),
            is_active: String(document.getElementById("iamEditIsActive").value || "true").trim().toLowerCase() !== "false",
          }};
          const updated = await fetchJson("/api/admin/users/" + encodeURIComponent(String(userId)), true, {{
            method: "PATCH",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify(payload),
          }});
          meta.textContent = "수정 성공: user_id=" + String(updated.id) + " | role=" + String(updated.role || "");
          await runIamUsers();
          applyIamUserToForm(updated);
        }} catch (err) {{
          meta.textContent = "수정 실패: " + err.message;
        }}
      }}

      async function runIamSetPassword() {{
        const meta = document.getElementById("iamEditMeta");
        const userId = asInt(document.getElementById("iamEditUserId").value, -1);
        const nextPassword = String(document.getElementById("iamEditPassword").value || "").trim();
        if (userId <= 0) {{
          meta.textContent = "실패: user_id를 입력하세요.";
          return;
        }}
        if (!nextPassword) {{
          meta.textContent = "실패: 새 password를 입력하세요.";
          return;
        }}
        try {{
          await fetchJson("/api/admin/users/" + encodeURIComponent(String(userId)) + "/password", true, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify({{ password: nextPassword }}),
          }});
          document.getElementById("iamEditPassword").value = "";
          meta.textContent = "비밀번호 변경 성공: user_id=" + String(userId);
        }} catch (err) {{
          meta.textContent = "비밀번호 변경 실패: " + err.message;
        }}
      }}

      async function runIamDeactivateUser() {{
        const meta = document.getElementById("iamEditMeta");
        const userId = asInt(document.getElementById("iamEditUserId").value, -1);
        if (userId <= 0) {{
          meta.textContent = "실패: user_id를 입력하세요.";
          return;
        }}
        if (!window.confirm("user_id=" + String(userId) + " 계정을 비활성화하시겠습니까?")) {{
          return;
        }}
        try {{
          const updated = await fetchJson("/api/admin/users/" + encodeURIComponent(String(userId)) + "/active", true, {{
            method: "PATCH",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify({{ is_active: false }}),
          }});
          meta.textContent = "비활성화 성공: user_id=" + String(updated.id);
          await runIamUsers();
          applyIamUserToForm(updated);
        }} catch (err) {{
          meta.textContent = "비활성화 실패: " + err.message;
        }}
      }}

      async function runIamDeleteUser() {{
        const meta = document.getElementById("iamEditMeta");
        const userId = asInt(document.getElementById("iamEditUserId").value, -1);
        if (userId <= 0) {{
          meta.textContent = "실패: user_id를 입력하세요.";
          return;
        }}
        if (!window.confirm("user_id=" + String(userId) + " 계정을 삭제(비활성화)하시겠습니까?")) {{
          return;
        }}
        try {{
          await fetchJson("/api/admin/users/" + encodeURIComponent(String(userId)), true, {{
            method: "DELETE",
          }});
          meta.textContent = "삭제(비활성화) 성공: user_id=" + String(userId);
          iamSelectedUserId = null;
          document.getElementById("iamEditUserId").value = "";
          document.getElementById("iamEditUsername").value = "";
          document.getElementById("iamEditDisplayName").value = "";
          document.getElementById("iamEditPermissions").value = "";
          document.getElementById("iamEditPassword").value = "";
          await runIamUsers();
        }} catch (err) {{
          meta.textContent = "삭제 실패: " + err.message;
        }}
      }}

      function getIamTokenFromCache(tokenId) {{
        const targetId = asInt(tokenId, -1);
        if (targetId <= 0) return null;
        const found = iamTokensCache.find((row) => asInt(row.token_id, -1) === targetId);
        return found || null;
      }}

      function applyIamTokenToForm(token) {{
        if (!token) return;
        const tokenId = asInt(token.token_id, 0);
        if (tokenId <= 0) return;
        iamSelectedTokenId = tokenId;
        document.getElementById("iamSelectedTokenId").value = String(tokenId);
        document.getElementById("iamSelectedTokenUser").value = String(token.username || "");
        document.getElementById("iamSelectedTokenLabel").value = String(token.label || "");
      }}

      function renderIamTokensTable(rows) {{
        if (!Array.isArray(rows) || rows.length === 0) {{
          return renderEmpty("토큰 데이터가 없습니다.");
        }}
        const body = rows.map((row) => {{
          const tokenId = asInt(row.token_id, 0);
          const selectedCls = iamSelectedTokenId === tokenId ? ' class="w07-track-row active"' : "";
          const scopeText = Array.isArray(row.site_scope) ? row.site_scope.join(", ") : "";
          return (
            "<tr" + selectedCls + ">" +
              "<td>" + escapeHtml(tokenId) + "</td>" +
              "<td>" + escapeHtml(row.user_id || "") + "</td>" +
              "<td>" + escapeHtml(row.username || "") + "</td>" +
              "<td>" + escapeHtml(row.label || "") + "</td>" +
              "<td>" + escapeHtml(row.is_active ? "true" : "false") + "</td>" +
              "<td>" + escapeHtml(scopeText) + "</td>" +
              "<td>" + escapeHtml(row.expires_at || "") + "</td>" +
              "<td>" + escapeHtml(row.rotate_due_at || "") + "</td>" +
              "<td>" + escapeHtml(row.idle_due_at || "") + "</td>" +
              "<td>" + escapeHtml(row.last_used_at || "") + "</td>" +
              "<td>" + escapeHtml(row.created_at || "") + "</td>" +
              "<td>" + escapeHtml(Boolean(row.must_rotate) ? "true" : "false") + "</td>" +
              '<td><button class="btn soft iam-select-token" type="button" data-token-id="' + escapeHtml(tokenId) + '" data-tip="선택: 이 토큰을 회전 또는 폐기 대상으로 지정합니다." title="선택: 이 토큰을 회전 또는 폐기 대상으로 지정합니다.">선택</button></td>' +
            "</tr>"
          );
        }}).join("");
        return (
          '<div class="table-wrap"><table><thead><tr>'
          + "<th>Token ID</th><th>User ID</th><th>Username</th><th>Label</th><th>Active</th><th>Site Scope</th><th>Expires</th><th>Rotate Due</th><th>Idle Due</th><th>Last Used</th><th>Created</th><th>Must Rotate</th><th>Action</th>"
          + "</tr></thead><tbody>" + body + "</tbody></table></div>"
        );
      }}

      async function runIamTokens() {{
        const meta = document.getElementById("iamTokensMeta");
        const table = document.getElementById("iamTokensTable");
        try {{
          const userId = asInt(document.getElementById("iamTokensFilterUserId").value, -1);
          const activeFilter = String(document.getElementById("iamTokensFilterActive").value || "all").trim().toLowerCase();
          const params = new URLSearchParams();
          if (userId > 0) {{
            params.set("user_id", String(userId));
          }}
          if (activeFilter === "true") {{
            params.set("active_only", "true");
          }}
          const query = params.toString();
          const path = "/api/admin/tokens" + (query ? "?" + query : "");
          meta.textContent = "조회 중... " + path;
          const rows = await fetchJson(path, true);
          iamTokensCache = Array.isArray(rows) ? rows : [];
          let filtered = iamTokensCache.slice();
          if (activeFilter === "false") {{
            filtered = filtered.filter((row) => !Boolean(row.is_active));
          }}
          iamFilteredTokensCache = filtered;
          if (iamSelectedTokenId != null && !getIamTokenFromCache(iamSelectedTokenId)) {{
            iamSelectedTokenId = null;
            document.getElementById("iamSelectedTokenId").value = "";
            document.getElementById("iamSelectedTokenUser").value = "";
            document.getElementById("iamSelectedTokenLabel").value = "";
          }}
          meta.textContent = "성공: " + path + " | total=" + String(iamTokensCache.length) + " | filtered=" + String(filtered.length);
          table.innerHTML = renderIamTokensTable(filtered);
          return filtered;
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          table.innerHTML = renderEmpty(err.message);
          iamTokensCache = [];
          iamFilteredTokensCache = [];
          return [];
        }}
      }}

      async function runIamPickToken() {{
        const meta = document.getElementById("iamTokenActionMeta");
        const tokenId = asInt(document.getElementById("iamSelectedTokenId").value, -1);
        if (tokenId <= 0) {{
          meta.textContent = "실패: token_id를 입력하세요.";
          return;
        }}
        if (!iamTokensCache.length) {{
          await runIamTokens();
        }}
        const token = getIamTokenFromCache(tokenId);
        if (!token) {{
          meta.textContent = "실패: token_id=" + String(tokenId) + " 를 목록에서 찾을 수 없습니다.";
          return;
        }}
        applyIamTokenToForm(token);
        const visibleRows = iamFilteredTokensCache.length ? iamFilteredTokensCache : iamTokensCache;
        document.getElementById("iamTokensTable").innerHTML = renderIamTokensTable(visibleRows);
        meta.textContent = "선택 완료: token_id=" + String(tokenId) + " | user=" + String(token.username || "");
      }}

      async function runIamIssueToken() {{
        const meta = document.getElementById("iamTokenActionMeta");
        const plainNode = document.getElementById("iamTokenPlain");
        const issueUserIdRaw = String(document.getElementById("iamIssueTokenUserId").value || "").trim();
        const fallbackUserId = asInt(document.getElementById("iamEditUserId").value, iamSelectedUserId || -1);
        const userId = issueUserIdRaw ? asInt(issueUserIdRaw, -1) : fallbackUserId;
        const label = String(document.getElementById("iamIssueTokenLabel").value || "").trim() || "console-issued";
        const expiresAtRaw = String(document.getElementById("iamIssueTokenExpiresAt").value || "").trim();
        const tokenSiteScopeRaw = String(document.getElementById("iamIssueTokenSiteScope").value || "").trim();
        if (userId <= 0) {{
          meta.textContent = "실패: issue 대상 user_id를 입력하세요.";
          return;
        }}
        try {{
          const payload = {{ label }};
          if (expiresAtRaw) {{
            payload.expires_at = expiresAtRaw;
          }}
          if (tokenSiteScopeRaw) {{
            payload.site_scope = parseSiteScopeInput(tokenSiteScopeRaw);
          }}
          const issued = await fetchJson("/api/admin/users/" + encodeURIComponent(String(userId)) + "/tokens", true, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify(payload),
          }});
          document.getElementById("iamTokensFilterUserId").value = String(userId);
          document.getElementById("iamTokensFilterActive").value = "all";
          await runIamTokens();
          const issuedToken = getIamTokenFromCache(issued.token_id);
          if (issuedToken) {{
            applyIamTokenToForm(issuedToken);
          }} else {{
            iamSelectedTokenId = asInt(issued.token_id, null);
            document.getElementById("iamSelectedTokenId").value = String(issued.token_id || "");
            document.getElementById("iamSelectedTokenLabel").value = String(issued.label || "");
            document.getElementById("iamSelectedTokenUser").value = "";
          }}
          plainNode.textContent = String(issued.token || "");
          meta.textContent =
            "발급 성공: token_id=" + String(issued.token_id)
            + " | user_id=" + String(issued.user_id)
            + " | expires_at=" + String(issued.expires_at || "-");
        }} catch (err) {{
          meta.textContent = "발급 실패: " + err.message;
        }}
      }}

      async function runIamRotateToken() {{
        const meta = document.getElementById("iamTokenActionMeta");
        const plainNode = document.getElementById("iamTokenPlain");
        const tokenId = asInt(document.getElementById("iamSelectedTokenId").value, iamSelectedTokenId || -1);
        if (tokenId <= 0) {{
          meta.textContent = "실패: token_id를 입력하세요.";
          return;
        }}
        if (!window.confirm("token_id=" + String(tokenId) + " 를 회전하시겠습니까? 기존 토큰은 즉시 비활성화됩니다.")) {{
          return;
        }}
        try {{
          const rotated = await fetchJson("/api/admin/tokens/" + encodeURIComponent(String(tokenId)) + "/rotate", true, {{
            method: "POST",
          }});
          iamSelectedTokenId = asInt(rotated.token_id, null);
          document.getElementById("iamSelectedTokenId").value = String(rotated.token_id || "");
          document.getElementById("iamSelectedTokenLabel").value = String(rotated.label || "");
          plainNode.textContent = String(rotated.token || "");
          await runIamTokens();
          const newToken = getIamTokenFromCache(rotated.token_id);
          if (newToken) {{
            applyIamTokenToForm(newToken);
          }}
          meta.textContent =
            "회전 성공: old_token_id=" + String(tokenId)
            + " -> new_token_id=" + String(rotated.token_id)
            + " | user_id=" + String(rotated.user_id);
        }} catch (err) {{
          meta.textContent = "회전 실패: " + err.message;
        }}
      }}

      async function runIamRevokeToken() {{
        const meta = document.getElementById("iamTokenActionMeta");
        const plainNode = document.getElementById("iamTokenPlain");
        const tokenId = asInt(document.getElementById("iamSelectedTokenId").value, iamSelectedTokenId || -1);
        if (tokenId <= 0) {{
          meta.textContent = "실패: token_id를 입력하세요.";
          return;
        }}
        if (!window.confirm("token_id=" + String(tokenId) + " 를 폐기(비활성화)하시겠습니까?")) {{
          return;
        }}
        try {{
          const revoked = await fetchJson("/api/admin/tokens/" + encodeURIComponent(String(tokenId)) + "/revoke", true, {{
            method: "POST",
          }});
          iamSelectedTokenId = asInt(revoked.token_id, null);
          document.getElementById("iamSelectedTokenId").value = String(revoked.token_id || "");
          document.getElementById("iamSelectedTokenLabel").value = String(revoked.label || "");
          document.getElementById("iamSelectedTokenUser").value = String(revoked.username || "");
          plainNode.textContent = "토큰 폐기 완료 (token plain text는 표시되지 않습니다).";
          await runIamTokens();
          meta.textContent =
            "폐기 성공: token_id=" + String(revoked.token_id)
            + " | is_active=" + String(Boolean(revoked.is_active));
        }} catch (err) {{
          meta.textContent = "폐기 실패: " + err.message;
        }}
      }}

      function getIamAuditLogFromCache(logId) {{
        const targetId = asInt(logId, -1);
        if (targetId <= 0) return null;
        const found = iamAuditLogsCache.find((row) => asInt(row.id, -1) === targetId);
        return found || null;
      }}

      function showIamAuditDetail(logRow) {{
        const detailNode = document.getElementById("iamAuditDetail");
        if (!detailNode) return;
        if (!logRow) {{
          detailNode.textContent = "로그를 선택하면 detail JSON이 표시됩니다.";
          return;
        }}
        iamSelectedAuditLogId = asInt(logRow.id, null);
        let detailText = "";
        try {{
          detailText = JSON.stringify(logRow.detail || {{}}, null, 2);
        }} catch (err) {{
          detailText = String(logRow.detail || "");
        }}
        detailNode.textContent =
          "id=" + String(logRow.id)
          + " | action=" + String(logRow.action || "")
          + " | actor=" + String(logRow.actor_username || "")
          + "\\n"
          + detailText;
      }}

      function renderIamAuditTable(rows) {{
        if (!Array.isArray(rows) || rows.length === 0) {{
          return renderEmpty("감사 로그가 없습니다.");
        }}
        const body = rows.map((row) => {{
          const logId = asInt(row.id, 0);
          const selectedCls = iamSelectedAuditLogId === logId ? ' class="w07-track-row active"' : "";
          return (
            "<tr" + selectedCls + ">" +
              "<td>" + escapeHtml(logId) + "</td>" +
              "<td>" + escapeHtml(row.created_at || "") + "</td>" +
              "<td>" + escapeHtml(row.actor_username || "") + "</td>" +
              "<td>" + escapeHtml(row.action || "") + "</td>" +
              "<td>" + escapeHtml(row.resource_type || "") + "</td>" +
              "<td>" + escapeHtml(row.resource_id || "") + "</td>" +
              "<td>" + escapeHtml(row.status || "") + "</td>" +
              '<td><button class="btn soft iam-select-audit" type="button" data-audit-id="' + escapeHtml(logId) + '" data-tip="상세: 이 감사 로그의 detail JSON을 아래 패널에 표시합니다." title="상세: 이 감사 로그의 detail JSON을 아래 패널에 표시합니다.">상세</button></td>' +
            "</tr>"
          );
        }}).join("");
        return (
          '<div class="table-wrap"><table><thead><tr>'
          + "<th>ID</th><th>Created</th><th>Actor</th><th>Action</th><th>Resource Type</th><th>Resource ID</th><th>Status</th><th>Action</th>"
          + "</tr></thead><tbody>" + body + "</tbody></table></div>"
        );
      }}

      async function runIamAuditLogs() {{
        const meta = document.getElementById("iamAuditMeta");
        const table = document.getElementById("iamAuditTable");
        try {{
          const action = String(document.getElementById("iamAuditAction").value || "").trim();
          const actor = String(document.getElementById("iamAuditActor").value || "").trim();
          const limit = Math.max(1, Math.min(200, asInt(document.getElementById("iamAuditLimit").value, 50)));
          const offset = Math.max(0, asInt(document.getElementById("iamAuditOffset").value, 0));
          document.getElementById("iamAuditLimit").value = String(limit);
          document.getElementById("iamAuditOffset").value = String(offset);
          const params = new URLSearchParams();
          if (action) {{
            params.set("action", action);
          }}
          if (actor) {{
            params.set("actor_username", actor);
          }}
          params.set("limit", String(limit));
          params.set("offset", String(offset));
          const path = "/api/admin/audit-logs?" + params.toString();
          meta.textContent = "조회 중... " + path;
          const rows = await fetchJson(path, true);
          iamAuditLogsCache = Array.isArray(rows) ? rows : [];
          const selected =
            getIamAuditLogFromCache(iamSelectedAuditLogId)
            || (iamAuditLogsCache.length ? iamAuditLogsCache[0] : null);
          if (selected) {{
            iamSelectedAuditLogId = asInt(selected.id, null);
          }} else {{
            iamSelectedAuditLogId = null;
          }}
          meta.textContent = "성공: " + path + " | count=" + String(iamAuditLogsCache.length);
          table.innerHTML = renderIamAuditTable(iamAuditLogsCache);
          showIamAuditDetail(selected);
          return iamAuditLogsCache;
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          table.innerHTML = renderEmpty(err.message);
          iamAuditLogsCache = [];
          iamSelectedAuditLogId = null;
          showIamAuditDetail(null);
          return [];
        }}
      }}

      async function runOverview() {{
        const query = buildQuery([
          {{ key: "site", id: "ovSite" }},
          {{ key: "days", id: "ovDays" }},
          {{ key: "job_limit", id: "ovJobLimit" }}
        ]);
        const path = "/api/ops/dashboard/summary" + (query ? "?" + query : "");
        const siteValue = (document.getElementById("ovSite").value || "").trim();
        const siteSuffix = siteValue ? ("?site=" + encodeURIComponent(siteValue)) : "";
        const handoverParams = new URLSearchParams();
        if (siteValue) {{
          handoverParams.set("site", siteValue);
        }}
        handoverParams.set("window_hours", "12");
        handoverParams.set("due_soon_hours", "6");
        handoverParams.set("max_items", "10");
        const handoverPath = "/api/ops/handover/brief?" + handoverParams.toString();
        const meta = document.getElementById("overviewMeta");
        const cards = document.getElementById("overviewCards");
        const topTable = document.getElementById("overviewTopWorkOrders");
        const officialAutomationCards = document.getElementById("overviewOfficialAutomationCards");
        const officialAutomationMeta = document.getElementById("overviewOfficialAutomationMeta");
        const officialAutomationLatest = document.getElementById("overviewOfficialAutomationLatest");
        const alertKpiSummary = document.getElementById("overviewAlertKpiSummary");
        const alertKpiChannels = document.getElementById("overviewAlertKpiChannels");
        const alertMttrSummary = document.getElementById("overviewAlertMttrSummary");
        const alertMttrChannels = document.getElementById("overviewAlertMttrChannels");
        const alertGuardMeta = document.getElementById("overviewAlertGuardMeta");
        const alertGuardTable = document.getElementById("overviewAlertGuardTable");
        const alertGuardRecoverMeta = document.getElementById("overviewGuardRecoverMeta");
        const alertGuardRecoverTable = document.getElementById("overviewGuardRecoverTable");
        try {{
          meta.textContent = "조회 중... " + path;
          document.getElementById("overviewOfficialOverdueStatusLink").setAttribute("href", "/api/official-documents/overdue/status" + siteSuffix);
          document.getElementById("overviewOfficialOverdueLatestLink").setAttribute("href", "/api/official-documents/overdue/latest" + siteSuffix);
          const [data, handover, officialOverdueStatus, officialOverdueLatest, kpi, mttr, guard, guardRecoverLatest, retentionPolicy, retentionLatest] = await Promise.all([
            fetchJson(path, true),
            fetchJson(handoverPath, true).catch(() => null),
            fetchJson("/api/official-documents/overdue/status" + siteSuffix, true).catch(() => null),
            fetchJson("/api/official-documents/overdue/latest" + siteSuffix, true).catch(() => null),
            fetchJson("/api/ops/alerts/kpi/channels", true).catch(() => null),
            fetchJson("/api/ops/alerts/kpi/mttr", true).catch(() => null),
            fetchJson("/api/ops/alerts/channels/guard", true).catch(() => null),
            fetchJson("/api/ops/alerts/channels/guard/recover/latest", true).catch(() => null),
            fetchJson("/api/ops/alerts/retention/policy", true).catch(() => null),
            fetchJson("/api/ops/alerts/retention/latest", true).catch(() => null),
          ]);
          meta.textContent = "성공: " + path;
          const stats = [
            ["Inspections", data.inspections_total ?? 0],
            ["Work Orders", data.work_orders_total ?? 0],
            ["Overdue Open", data.overdue_open_count ?? 0],
            ["Escalated Open", data.escalated_open_count ?? 0],
            ["Report Exports", data.report_export_count ?? 0],
            ["SLA Runs", data.sla_recent_runs ?? 0],
            ["SLA Warning Runs", data.sla_warning_runs ?? 0],
            ["Last SLA Run", data.sla_last_run_at || "-"],
          ];
          cards.innerHTML = stats.map((s) => (
            '<div class="card"><div class="k">' + escapeHtml(s[0]) + '</div><div class="v">' + escapeHtml(s[1] || 0) + "</div></div>"
          )).join("");

          if (officialOverdueStatus) {{
            const automationCards = [
              ["Mode", officialOverdueStatus.scheduler_mode || "-"],
              ["Enabled", officialOverdueStatus.automation_enabled ? "YES" : "NO"],
              ["Interval(min)", officialOverdueStatus.interval_minutes || 0],
              ["Latest Status", officialOverdueStatus.latest_run_status || "idle"],
              ["Candidates", officialOverdueStatus.latest_candidate_count || 0],
              ["Created", officialOverdueStatus.latest_work_order_created_count || 0],
              ["Existing Linked", officialOverdueStatus.latest_linked_existing_count || 0],
            ];
            officialAutomationCards.innerHTML = automationCards.map((item) => (
              '<div class="card"><div class="k">' + escapeHtml(item[0]) + '</div><div class="v">' + escapeHtml(item[1]) + '</div></div>'
            )).join("");
            officialAutomationMeta.textContent =
              "공문 자동화 상태="
              + String(officialOverdueStatus.overall_status || "idle")
              + " | site_scope=" + String(officialOverdueStatus.site_scope || "ALL")
              + " | latest_finished_at=" + String(officialOverdueStatus.latest_finished_at || "-");
          }} else {{
            officialAutomationCards.innerHTML = "";
            officialAutomationMeta.textContent = "공문 자동화 상태 조회 실패 또는 데이터 없음";
          }}

          if (officialOverdueLatest && officialOverdueLatest.exists && officialOverdueLatest.latest_run) {{
            const latestRun = officialOverdueLatest.latest_run || {{}};
            const latestDetail = officialOverdueLatest.detail || {{}};
            officialAutomationLatest.innerHTML = renderTable(
              [{{
                job_name: latestRun.job_name || "",
                trigger: latestRun.trigger || "",
                status: latestRun.status || "",
                finished_at: latestRun.finished_at || "",
                candidate_count: latestDetail.candidate_count || 0,
                work_order_created_count: latestDetail.work_order_created_count || 0,
                linked_existing_work_order_count: latestDetail.linked_existing_work_order_count || 0,
              }}],
              [
                {{ key: "job_name", label: "Job" }},
                {{ key: "trigger", label: "Trigger" }},
                {{ key: "status", label: "Status" }},
                {{ key: "finished_at", label: "Finished At" }},
                {{ key: "candidate_count", label: "Candidates" }},
                {{ key: "work_order_created_count", label: "Created" }},
                {{ key: "linked_existing_work_order_count", label: "Existing Linked" }},
              ]
            );
          }} else {{
            officialAutomationLatest.innerHTML = renderEmpty("공문 자동화 실행 이력이 없습니다.");
          }}

          if (handover && Array.isArray(handover.top_work_orders)) {{
            topTable.innerHTML = renderTable(
              handover.top_work_orders || [],
              [
                {{ key: "id", label: "ID" }},
                {{ key: "site", label: "Site" }},
                {{ key: "title", label: "Title" }},
                {{ key: "priority", label: "Priority" }},
                {{ key: "status", label: "Status" }},
                {{ key: "urgency_score", label: "Score" }}
              ]
            );
          }} else {{
            topTable.innerHTML = renderTable(
              data.recent_job_runs || [],
              [
                {{ key: "job_name", label: "Job" }},
                {{ key: "status", label: "Status" }},
                {{ key: "finished_at", label: "Finished At" }},
                {{ key: "trigger", label: "Trigger" }},
              ]
            );
          }}

          const windows = (kpi && Array.isArray(kpi.windows)) ? kpi.windows : [];
          const sortedWindows = windows.slice().sort((a, b) => Number(a.days || 0) - Number(b.days || 0));
          if (sortedWindows.length > 0) {{
            const kpiCards = [];
            sortedWindows.forEach((win) => {{
              kpiCards.push(["" + String(win.days || 0) + "d Success %", (win.success_rate_percent ?? 0) + "%"]);
              kpiCards.push(["" + String(win.days || 0) + "d Deliveries", win.total_deliveries ?? 0]);
            }});
            alertKpiSummary.innerHTML = kpiCards.map((x) => (
              '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
            )).join("");

            const window30 = sortedWindows.find((item) => Number(item.days || 0) === 30) || sortedWindows[sortedWindows.length - 1];
            const channels = Array.isArray(window30.channels) ? window30.channels : [];
            alertKpiChannels.innerHTML = renderTable(
              channels.slice(0, 20),
              [
                {{ key: "target", label: "Target" }},
                {{ key: "total_deliveries", label: "Total" }},
                {{ key: "success_count", label: "Success" }},
                {{ key: "warning_count", label: "Warning" }},
                {{ key: "failed_count", label: "Failed" }},
                {{ key: "success_rate_percent", label: "Success %" }},
                {{ key: "last_attempt_at", label: "Last Attempt" }},
              ]
            );
          }} else {{
            alertKpiSummary.innerHTML = "";
            alertKpiChannels.innerHTML = renderEmpty("알림 KPI 데이터가 없습니다.");
          }}

          const mttrWindows = (mttr && Array.isArray(mttr.windows)) ? mttr.windows : [];
          const sortedMttrWindows = mttrWindows.slice().sort((a, b) => Number(a.days || 0) - Number(b.days || 0));
          if (sortedMttrWindows.length > 0) {{
            const mttrCards = [];
            sortedMttrWindows.forEach((win) => {{
              mttrCards.push(["" + String(win.days || 0) + "d MTTR(min)", win.mttr_minutes ?? "-"]);
              mttrCards.push(["" + String(win.days || 0) + "d Recovered", win.recovered_incidents ?? 0]);
              mttrCards.push(["" + String(win.days || 0) + "d Unresolved", win.unresolved_incidents ?? 0]);
            }});
            alertMttrSummary.innerHTML = mttrCards.map((x) => (
              '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
            )).join("");

            const window30Mttr = sortedMttrWindows.find((item) => Number(item.days || 0) === 30) || sortedMttrWindows[sortedMttrWindows.length - 1];
            const mttrChannels = Array.isArray(window30Mttr.channels) ? window30Mttr.channels : [];
            alertMttrChannels.innerHTML = renderTable(
              mttrChannels.slice(0, 20),
              [
                {{ key: "target", label: "Target" }},
                {{ key: "incident_count", label: "Incidents" }},
                {{ key: "recovered_incidents", label: "Recovered" }},
                {{ key: "unresolved_incidents", label: "Unresolved" }},
                {{ key: "mttr_minutes", label: "MTTR(min)" }},
                {{ key: "median_recovery_minutes", label: "Median(min)" }},
                {{ key: "longest_recovery_minutes", label: "Longest(min)" }},
                {{ key: "last_recovery_at", label: "Last Recovery" }},
              ]
            );
          }} else {{
            alertMttrSummary.innerHTML = "";
            alertMttrChannels.innerHTML = renderEmpty("알림 MTTR 데이터가 없습니다.");
          }}

          if (guard && guard.summary) {{
            const summary = guard.summary || {{}};
            const latestRetention = retentionLatest && retentionLatest.run_id
              ? ("최근 정리: run#" + String(retentionLatest.run_id) + " deleted=" + String(retentionLatest.deleted_count || 0))
              : "최근 정리: 없음";
            const latestRecover = guardRecoverLatest && guardRecoverLatest.run_id
              ? (" | 최근 복구: run#" + String(guardRecoverLatest.run_id) + " processed=" + String(guardRecoverLatest.processed_count || 0) + " failed=" + String(guardRecoverLatest.failed_count || 0))
              : " | 최근 복구: 없음";
            const policyText = retentionPolicy
              ? (" | retention=" + String(retentionPolicy.retention_days || "-") + "d archive=" + String(retentionPolicy.archive_enabled))
              : "";
            alertGuardMeta.textContent =
              "Guard=" + String(summary.status || "-")
              + " | quarantined=" + String(summary.quarantined_count || 0)
              + " | warning=" + String(summary.warning_count || 0)
              + " | targets=" + String(summary.target_count || 0)
              + " | " + latestRetention
              + latestRecover
              + policyText;
            alertGuardTable.innerHTML = renderTable(
              (guard.channels || []).slice(0, 20),
              [
                {{ key: "target", label: "Target" }},
                {{ key: "state", label: "State" }},
                {{ key: "consecutive_failures", label: "Consecutive Failures" }},
                {{ key: "quarantined_until", label: "Quarantined Until" }},
                {{ key: "last_status", label: "Last Status" }},
                {{ key: "last_attempt_at", label: "Last Attempt" }},
              ]
            );
          }} else {{
            alertGuardMeta.textContent = "보호 상태 조회 실패 또는 데이터 없음";
            alertGuardTable.innerHTML = renderEmpty("알림 채널 보호 상태 데이터가 없습니다.");
          }}

          if (guardRecoverLatest && guardRecoverLatest.run_id) {{
            alertGuardRecoverMeta.textContent =
              "최근 배치복구 run#" + String(guardRecoverLatest.run_id)
              + " | status=" + String(guardRecoverLatest.status || "-")
              + " | processed=" + String(guardRecoverLatest.processed_count || 0)
              + " | success=" + String(guardRecoverLatest.success_count || 0)
              + " | failed=" + String(guardRecoverLatest.failed_count || 0)
              + " | skipped=" + String(guardRecoverLatest.skipped_count || 0);
            alertGuardRecoverTable.innerHTML = renderTable(
              (guardRecoverLatest.results || []).slice(0, 20),
              [
                {{ key: "target", label: "Target" }},
                {{ key: "status", label: "Probe" }},
                {{ key: "before_state", label: "Before" }},
                {{ key: "after_state", label: "After" }},
                {{ key: "delivery_id", label: "Delivery ID" }},
                {{ key: "error", label: "Error" }},
              ]
            );
          }} else {{
            alertGuardRecoverMeta.textContent = "최근 배치복구 이력 없음";
            alertGuardRecoverTable.innerHTML = renderEmpty("배치복구 실행 이력이 없습니다.");
          }}
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          cards.innerHTML = "";
          officialAutomationCards.innerHTML = "";
          officialAutomationMeta.textContent = "실패: " + err.message;
          officialAutomationLatest.innerHTML = renderEmpty(err.message);
          topTable.innerHTML = renderEmpty(err.message);
          alertKpiSummary.innerHTML = "";
          alertKpiChannels.innerHTML = renderEmpty(err.message);
          alertMttrSummary.innerHTML = "";
          alertMttrChannels.innerHTML = renderEmpty(err.message);
          alertGuardMeta.textContent = "실패: " + err.message;
          alertGuardTable.innerHTML = renderEmpty(err.message);
          alertGuardRecoverMeta.textContent = "실패: " + err.message;
          alertGuardRecoverTable.innerHTML = renderEmpty(err.message);
        }}
      }}

      async function runOverviewGuardRecover(dryRun) {{
        const meta = document.getElementById("overviewGuardRecoverMeta");
        const table = document.getElementById("overviewGuardRecoverTable");
        const state = (document.getElementById("overviewGuardRecoverState").value || "quarantined").trim() || "quarantined";
        const maxTargetsRaw = (document.getElementById("overviewGuardRecoverMaxTargets").value || "").trim();
        const params = new URLSearchParams();
        params.set("state", state);
        if (maxTargetsRaw !== "") {{
          params.set("max_targets", maxTargetsRaw);
        }}
        params.set("dry_run", dryRun ? "true" : "false");
        const path = "/api/ops/alerts/channels/guard/recover-batch?" + params.toString();
        try {{
          meta.textContent = "실행 중... " + path;
          const data = await fetchJson(
            path,
            true,
            {{
              method: "POST",
            }}
          );
          meta.textContent =
            "성공: run#" + String(data.run_id || "-")
            + " | status=" + String(data.status || "-")
            + " | processed=" + String(data.processed_count || 0)
            + " | success=" + String(data.success_count || 0)
            + " | failed=" + String(data.failed_count || 0)
            + " | skipped=" + String(data.skipped_count || 0);
          table.innerHTML = renderTable(
            (data.results || []).slice(0, 30),
            [
              {{ key: "target", label: "Target" }},
              {{ key: "status", label: "Probe" }},
              {{ key: "before_state", label: "Before" }},
              {{ key: "after_state", label: "After" }},
              {{ key: "delivery_id", label: "Delivery ID" }},
              {{ key: "error", label: "Error" }},
            ]
          );
          await runOverview();
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          table.innerHTML = renderEmpty(err.message);
        }}
      }}

      async function runOverviewGuardRecoverLatest() {{
        const meta = document.getElementById("overviewGuardRecoverMeta");
        const table = document.getElementById("overviewGuardRecoverTable");
        try {{
          meta.textContent = "조회 중... /api/ops/alerts/channels/guard/recover/latest";
          const data = await fetchJson("/api/ops/alerts/channels/guard/recover/latest", true);
          meta.textContent =
            "최근 run#" + String(data.run_id || "-")
            + " | status=" + String(data.status || "-")
            + " | processed=" + String(data.processed_count || 0)
            + " | success=" + String(data.success_count || 0)
            + " | failed=" + String(data.failed_count || 0)
            + " | skipped=" + String(data.skipped_count || 0);
          table.innerHTML = renderTable(
            (data.results || []).slice(0, 30),
            [
              {{ key: "target", label: "Target" }},
              {{ key: "status", label: "Probe" }},
              {{ key: "before_state", label: "Before" }},
              {{ key: "after_state", label: "After" }},
              {{ key: "delivery_id", label: "Delivery ID" }},
              {{ key: "error", label: "Error" }},
            ]
          );
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          table.innerHTML = renderEmpty(err.message);
        }}
      }}

      function currentLocalDatetimeInputValue() {{
        const now = new Date();
        const offsetMs = now.getTimezoneOffset() * 60000;
        return new Date(now.getTime() - offsetMs).toISOString().slice(0, 16);
      }}

      function parseOptionalNumberInput(id, label) {{
        const node = document.getElementById(id);
        if (!node) return null;
        const raw = String(node.value || "").trim();
        if (!raw) return null;
        const value = Number(raw);
        if (!Number.isFinite(value)) {{
          throw new Error(label + " 값이 숫자가 아닙니다: " + raw);
        }}
        return value;
      }}

      function normalizeOpsLifecycleState(value) {{
        const normalized = String(value || "active").trim().toLowerCase() || "active";
        return ["active", "retired", "replaced"].includes(normalized) ? normalized : "active";
      }}

      function getAllOpsChecklistSets() {{
        const sets = OPS_SPECIAL_CHECKLISTS && Array.isArray(OPS_SPECIAL_CHECKLISTS.checklist_sets)
          ? OPS_SPECIAL_CHECKLISTS.checklist_sets
          : [];
        return sets.filter((row) => row && row.set_id && row.label && Array.isArray(row.items) && row.items.length > 0);
      }}

      function getOpsChecklistSets() {{
        return getAllOpsChecklistSets().filter((row) => normalizeOpsLifecycleState(row.lifecycle_state) === "active");
      }}

      function getSelectedOpsChecklistSetId() {{
        const node = document.getElementById("inChecklistSet");
        const sets = getOpsChecklistSets();
        const fallback = sets.length > 0 ? String(sets[0].set_id) : "electrical_60";
        if (!node) {{
          return fallback;
        }}
        const selected = String(node.value || "").trim();
        if (!selected) {{
          return fallback;
        }}
        return selected;
      }}

      function getOpsChecklistSetById(setId) {{
        const target = String(setId || "").trim();
        const sets = getOpsChecklistSets();
        if (sets.length === 0) {{
          return null;
        }}
        const found = sets.find((row) => String(row.set_id) === target);
        if (found) {{
          return found;
        }}
        return sets[0];
      }}

      function deriveOpsChecklistGroupLabel(setId, itemText) {{
        const setKey = String(setId || "").trim().toLowerCase();
        const text = String(itemText || "").trim();
        if (!text) {{
          return "기타";
        }}
        const upper = text.toUpperCase();
        const token = text.split(/\\s+/)[0] || text;

        if (setKey.includes("electrical")) {{
          if (text.startsWith("수변전실")) return "수변전실";
          if (text.startsWith("변압기")) return "변압기";
          if (text.startsWith("수전반") || text.startsWith("고압반")) return "수전반 / 고압반";
          if (text.startsWith("배전반") || text.startsWith("분전반")) return "배전반 / 분전반";
          if (text.startsWith("접지")) return "접지 설비";
          if (text.startsWith("발전기") || text.startsWith("비상발전기")) return "비상발전기";
          if (upper.startsWith("UPS")) return "UPS";
        }}
        if (setKey.includes("fire")) {{
          if (text.startsWith("소화기")) return "소화기";
          if (text.startsWith("옥내소화전")) return "옥내소화전";
          if (text.startsWith("스프링클러")) return "스프링클러";
          if (text.startsWith("감지기")) return "감지기";
          if (text.startsWith("수신기") || text.startsWith("화재수신반")) return "수신설비";
          if (text.startsWith("유도등") || text.startsWith("비상조명")) return "유도/비상조명";
          if (text.startsWith("비상방송")) return "비상방송";
        }}
        return token;
      }}

      function buildOpsChecklistGroups(setObj) {{
        if (!setObj || !Array.isArray(setObj.items)) {{
          return [];
        }}
        const byGroup = new Map();
        const setId = String(setObj.set_id || "");
        setObj.items.forEach((entry, idx) => {{
          if (!entry || typeof entry !== "object") {{
            return;
          }}
          const itemText = String(entry.item || "").trim();
          if (!itemText) {{
            return;
          }}
          const group = deriveOpsChecklistGroupLabel(setId, itemText);
          const bucket = byGroup.get(group) || [];
          bucket.push(itemText);
          byGroup.set(group, bucket);
        }});
        const groups = [];
        byGroup.forEach((items, group) => {{
          groups.push({{ group, items }});
        }});
        return groups;
      }}

      function populateOpsChecklistSetSelector() {{
        const node = document.getElementById("inChecklistSet");
        if (!node) {{
          return;
        }}
        const previous = String(node.value || "").trim();
        const sets = getOpsChecklistSets();
        if (sets.length === 0) {{
          node.innerHTML = '<option value="electrical_60">체크리스트 세트: 기본</option>';
          return;
        }}
        const defaultSet = sets.find((item) => String(item.set_id || "") === "electrical_60") || sets[0];
        node.innerHTML = sets.map((item) => (
          '<option value="' + escapeHtml(item.set_id) + '">체크리스트 세트: '
          + escapeHtml(item.label)
          + " (v"
          + escapeHtml(String(item.version_no || 1))
          + ")</option>"
        )).join("");
        if (previous && sets.some((item) => String(item.set_id || "") === previous)) {{
          node.value = previous;
        }} else {{
          node.value = String(defaultSet.set_id || "electrical_60");
        }}
      }}

      function selectNodeHasOptionValue(node, value) {{
        if (!node) {{
          return false;
        }}
        const target = String(value || "").trim();
        if (!target) {{
          return false;
        }}
        return Array.from(node.options || []).some((opt) => String(opt.value || "") === target);
      }}

      function setSelectValueIfAvailable(node, value, fallbackValue = "") {{
        if (!node) {{
          return;
        }}
        const target = String(value || "").trim();
        if (target && selectNodeHasOptionValue(node, target)) {{
          node.value = target;
          return;
        }}
        const fallback = String(fallbackValue || "").trim();
        if (fallback && selectNodeHasOptionValue(node, fallback)) {{
          node.value = fallback;
          return;
        }}
        if (node.options && node.options.length > 0) {{
          node.value = String(node.options[0].value || "");
        }}
      }}

      function setOpsTaskTypeFromChecklistSet(setObj) {{
        const node = document.getElementById("inCreateTaskType");
        if (!node || !setObj) {{
          return;
        }}
        const taskType = String(setObj.task_type || "").trim();
        if (!taskType) {{
          return;
        }}
        if (!selectNodeHasOptionValue(node, taskType)) {{
          const option = document.createElement("option");
          option.value = taskType;
          option.textContent = "업무구분: " + taskType;
          node.appendChild(option);
        }}
        node.value = taskType;
      }}

      function findChecklistSetIdByTaskType(taskType) {{
        const target = String(taskType || "").trim();
        if (!target) {{
          return "";
        }}
        const sets = getOpsChecklistSets();
        const found = sets.find((item) => String(item.task_type || "").trim() === target);
        return found ? String(found.set_id || "") : "";
      }}

      function findChecklistSetIdByCategory(categoryText, descriptionText = "") {{
        const category = String(categoryText || "").trim();
        const description = String(descriptionText || "").trim();
        const normalized = (category + " " + description).toLowerCase();
        if (normalized.includes("전기")) {{
          return (
            findChecklistSetIdByTaskType("전기점검")
            || String((getOpsChecklistSets().find((item) => String(item.set_id || "").toLowerCase().includes("electrical")) || {{}}).set_id || "")
          );
        }}
        if (normalized.includes("소방")) {{
          return (
            findChecklistSetIdByTaskType("소방점검")
            || String((getOpsChecklistSets().find((item) => String(item.set_id || "").toLowerCase().includes("fire")) || {{}}).set_id || "")
          );
        }}
        return "";
      }}

      function findChecklistSetIdByItemText(itemText) {{
        const target = String(itemText || "").trim();
        if (!target) {{
          return "";
        }}
        const sets = getOpsChecklistSets();
        for (const setObj of sets) {{
          const items = Array.isArray(setObj.items) ? setObj.items : [];
          const matched = items.some((entry) => String((entry && entry.item) || "").trim() === target);
          if (matched) {{
            return String(setObj.set_id || "");
          }}
        }}
        return "";
      }}

      function populateOpsChecklistGroupSelectors() {{
        const setObj = getOpsChecklistSetById(getSelectedOpsChecklistSetId());
        const previousEquipmentGroup = String((document.getElementById("inCreateEquipmentGroup") || {{ value: "all" }}).value || "all");
        const previousTemplateGroup = String((document.getElementById("inTemplateGroup") || {{ value: "all" }}).value || "all");
        const groups = buildOpsChecklistGroups(setObj);
        const options = ['<option value="all">전체</option>'].concat(
          groups.map((group) => (
            '<option value="' + escapeHtml(group.group) + '">' + escapeHtml(group.group) + "</option>"
          ))
        ).join("");
        const equipmentGroupNode = document.getElementById("inCreateEquipmentGroup");
        const templateGroupNode = document.getElementById("inTemplateGroup");
        if (equipmentGroupNode) {{
          equipmentGroupNode.innerHTML = options;
          setSelectValueIfAvailable(equipmentGroupNode, previousEquipmentGroup, "all");
        }}
        if (templateGroupNode) {{
          templateGroupNode.innerHTML = options;
          setSelectValueIfAvailable(templateGroupNode, previousTemplateGroup || previousEquipmentGroup, "all");
        }}
      }}

      function populateOpsCodeSelector() {{
        const node = document.getElementById("inCreateOpsCode");
        if (!node) {{
          return;
        }}
        const rows = OPS_SPECIAL_CHECKLISTS && Array.isArray(OPS_SPECIAL_CHECKLISTS.ops_codes)
          ? OPS_SPECIAL_CHECKLISTS.ops_codes
          : [];
        const options = ['<option value="">OPS코드: 선택(선택)</option>'].concat(
          rows
            .filter((row) => row && row.code)
            .map((row) => (
              '<option value="' + escapeHtml(row.code) + '">'
              + escapeHtml(String(row.code || ""))
              + " | "
              + escapeHtml(String(row.category || ""))
              + " | "
              + escapeHtml(String(row.description || ""))
              + "</option>"
            ))
        );
        node.innerHTML = options.join("");
      }}

      function populateOpsEquipmentSelector() {{
        const node = document.getElementById("inCreateEquipmentMaster");
        if (!node) {{
          return;
        }}
        const rows = getOpsEquipmentAssets();
        const options = ['<option value="">설비마스터: 선택(선택)</option>'].concat(
          rows
            .filter((row) => row && row.equipment_id)
            .map((row) => (
              '<option value="' + escapeHtml(String(row.equipment_id || "")) + '">'
              + escapeHtml(String(row.equipment_id || ""))
              + " | "
              + escapeHtml(String(row.equipment || "-"))
              + " | "
              + escapeHtml(String(row.location || "-"))
              + " | "
              + escapeHtml(String(row.lifecycle_state || "active"))
              + "</option>"
            ))
        );
        node.innerHTML = options.join("");
      }}

      function populateOpsQrSelector() {{
        const node = document.getElementById("inCreateQrId");
        if (!node) {{
          return;
        }}
        const rows = getOpsQrAssets();
        const options = ['<option value="">QR설비: 선택(선택)</option>'].concat(
          rows
            .filter((row) => row && row.qr_id)
            .map((row) => (
              '<option value="' + escapeHtml(row.qr_id) + '">'
              + escapeHtml(String(row.qr_id || ""))
              + " | "
              + escapeHtml(String(row.equipment || "-"))
              + " | "
              + escapeHtml(String(row.location || "-"))
              + " | "
              + escapeHtml(String(row.lifecycle_state || "active"))
              + "</option>"
            ))
        );
        node.innerHTML = options.join("");
      }}

      function getSelectedOpsCodeRecord() {{
        const node = document.getElementById("inCreateOpsCode");
        const code = String(node && node.value ? node.value : "").trim();
        const rows = OPS_SPECIAL_CHECKLISTS && Array.isArray(OPS_SPECIAL_CHECKLISTS.ops_codes)
          ? OPS_SPECIAL_CHECKLISTS.ops_codes
          : [];
        if (!code) {{
          return null;
        }}
        return rows.find((row) => String((row && row.code) || "") === code) || null;
      }}

      function getSelectedOpsEquipmentRecord() {{
        const node = document.getElementById("inCreateEquipmentMaster");
        const equipmentId = Number(node && node.value ? node.value : 0);
        const rows = getOpsEquipmentAssets();
        if (!Number.isInteger(equipmentId) || equipmentId <= 0) {{
          return null;
        }}
        return rows.find((row) => Number(row && row.equipment_id) === equipmentId) || null;
      }}

      function getSelectedQrAssetRecord() {{
        const node = document.getElementById("inCreateQrId");
        const qrId = String(node && node.value ? node.value : "").trim();
        const rows = getOpsQrAssets();
        if (!qrId) {{
          return null;
        }}
        return rows.find((row) => String((row && row.qr_id) || "") === qrId) || null;
      }}

      function applySelectedOpsEquipmentToForm(options = {{}}) {{
        const overwriteFields = Boolean(options.overwriteFields);
        const equipmentRecord = getSelectedOpsEquipmentRecord();
        if (!equipmentRecord) {{
          return;
        }}
        const equipmentNode = document.getElementById("inCreateEquipment");
        const locationNode = document.getElementById("inCreateLocation");
        if (equipmentNode && equipmentRecord.equipment && (overwriteFields || !(equipmentNode.value || "").trim())) {{
          equipmentNode.value = String(equipmentRecord.equipment || "").trim();
        }}
        if (locationNode && equipmentRecord.location && (overwriteFields || !(locationNode.value || "").trim())) {{
          locationNode.value = String(equipmentRecord.location || "").trim();
        }}
      }}

      function applyChecklistSetSelection(options = {{}}) {{
        const setObj = getOpsChecklistSetById(getSelectedOpsChecklistSetId());
        if (setObj) {{
          setOpsTaskTypeFromChecklistSet(setObj);
        }}
        populateOpsChecklistGroupSelectors();
        if (options.syncTemplateFromEquipment !== false) {{
          syncOpsTemplateGroupFromEquipmentGroup();
        }}
        if (options.resetChecklist !== false) {{
          resetOpsElectricalChecklistRows({{ preserve: Boolean(options.preserveChecklist) }});
        }}
      }}

      function applySelectedOpsCodeToForm() {{
        const codeRecord = getSelectedOpsCodeRecord();
        if (!codeRecord) {{
          return;
        }}
        const setNode = document.getElementById("inChecklistSet");
        const targetSetId = findChecklistSetIdByCategory(codeRecord.category, codeRecord.description);
        if (setNode && targetSetId && String(setNode.value || "") !== targetSetId) {{
          setNode.value = targetSetId;
          applyChecklistSetSelection({{ preserveChecklist: false }});
        }} else {{
          const selectedSet = getOpsChecklistSetById(getSelectedOpsChecklistSetId());
          if (selectedSet) {{
            setOpsTaskTypeFromChecklistSet(selectedSet);
          }}
        }}
        const equipmentCodeNode = document.getElementById("inCreateEquipmentCode");
        if (equipmentCodeNode && !(equipmentCodeNode.value || "").trim()) {{
          equipmentCodeNode.value = String(codeRecord.code || "").trim();
        }}
        const equipmentNode = document.getElementById("inCreateEquipment");
        const equipmentHint = String(codeRecord.description || "").trim().replace(/\\s*점검\\s*$/, "");
        if (equipmentNode && equipmentHint && !(equipmentNode.value || "").trim()) {{
          equipmentNode.value = equipmentHint;
        }}
      }}

      function applySelectedQrAssetToForm(options = {{}}) {{
        const overwriteFields = Boolean(options.overwriteFields);
        const qrRecord = getSelectedQrAssetRecord();
        const qrLocationNode = document.getElementById("inCreateQrLocation");
        const defaultItemNode = document.getElementById("inCreateDefaultItem");
        if (!qrRecord) {{
          if (qrLocationNode) qrLocationNode.value = "";
          if (defaultItemNode) defaultItemNode.value = "";
          return;
        }}
        const qrId = String(qrRecord.qr_id || "").trim();
        const qrEquipment = String(qrRecord.equipment || "").trim();
        const qrLocation = String(qrRecord.location || "").trim();
        const defaultItem = String(qrRecord.default_item || "").trim();
        if (qrLocationNode) {{
          qrLocationNode.value = qrLocation;
        }}
        if (defaultItemNode) {{
          defaultItemNode.value = defaultItem;
        }}
        const equipmentNode = document.getElementById("inCreateEquipment");
        if (equipmentNode && qrEquipment && (overwriteFields || !(equipmentNode.value || "").trim())) {{
          equipmentNode.value = qrEquipment;
        }}
        const locationNode = document.getElementById("inCreateLocation");
        if (locationNode && qrLocation && (overwriteFields || !(locationNode.value || "").trim())) {{
          locationNode.value = qrLocation;
        }}
        const equipmentCodeNode = document.getElementById("inCreateEquipmentCode");
        if (equipmentCodeNode && qrId && !(equipmentCodeNode.value || "").trim()) {{
          equipmentCodeNode.value = qrId;
        }}
        if (!defaultItem) {{
          return;
        }}
        const setNode = document.getElementById("inChecklistSet");
        const targetSetId = findChecklistSetIdByItemText(defaultItem);
        if (setNode && targetSetId && String(setNode.value || "") !== targetSetId) {{
          setNode.value = targetSetId;
          applyChecklistSetSelection({{ preserveChecklist: true }});
        }}
        const equipmentGroupNode = document.getElementById("inCreateEquipmentGroup");
        const targetGroup = deriveOpsChecklistGroupLabel(getSelectedOpsChecklistSetId(), defaultItem);
        if (equipmentGroupNode && selectNodeHasOptionValue(equipmentGroupNode, targetGroup)) {{
          equipmentGroupNode.value = targetGroup;
          syncOpsTemplateGroupFromEquipmentGroup();
          resetOpsElectricalChecklistRows({{ preserve: true }});
        }}
      }}

      function getAllOpsEquipmentAssets() {{
        return OPS_SPECIAL_CHECKLISTS && Array.isArray(OPS_SPECIAL_CHECKLISTS.equipment_assets)
          ? OPS_SPECIAL_CHECKLISTS.equipment_assets
          : [];
      }}

      function getOpsEquipmentAssets() {{
        return getAllOpsEquipmentAssets().filter((row) => normalizeOpsLifecycleState(row && row.lifecycle_state) === "active");
      }}

      function getAllOpsQrAssets() {{
        return OPS_SPECIAL_CHECKLISTS && Array.isArray(OPS_SPECIAL_CHECKLISTS.qr_assets)
          ? OPS_SPECIAL_CHECKLISTS.qr_assets
          : [];
      }}

      function getOpsQrAssets() {{
        return getAllOpsQrAssets().filter((row) => normalizeOpsLifecycleState(row && row.lifecycle_state) === "active");
      }}

      function parseOpsMasterChecklistItemsInput() {{
        const raw = String((document.getElementById("opsMasterChecklistItems") || {{ value: "" }}).value || "");
        return raw
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter((line) => line !== "");
      }}

      function getOpsMasterTableFilters() {{
        const search = String((document.getElementById("opsMasterSearch") || {{ value: "" }}).value || "").trim().toLowerCase();
        const lifecycleRaw = String((document.getElementById("opsMasterLifecycleFilter") || {{ value: "all" }}).value || "all").trim().toLowerCase() || "all";
        const lifecycleState = ["active", "retired", "replaced"].includes(lifecycleRaw) ? lifecycleRaw : "all";
        const revisionStatus = String((document.getElementById("opsMasterRevisionStatusFilter") || {{ value: "all" }}).value || "all").trim().toLowerCase() || "all";
        return {{
          search,
          lifecycleState: lifecycleState || "all",
          revisionStatus,
        }};
      }}

      function rowMatchesOpsMasterSearch(row, fields, query) {{
        if (!query) {{
          return true;
        }}
        const haystack = (Array.isArray(fields) ? fields : [])
          .map((field) => String(((row || {{}})[field]) || "").trim().toLowerCase())
          .filter(Boolean)
          .join(" ");
        return haystack.includes(query);
      }}

      function rowMatchesOpsMasterLifecycle(row, lifecycleState) {{
        if (!lifecycleState || lifecycleState === "all") {{
          return true;
        }}
        return normalizeOpsLifecycleState((row || {{}}).lifecycle_state || "active") === lifecycleState;
      }}

      function rowMatchesOpsMasterRevisionStatus(row, revisionStatus) {{
        if (!revisionStatus || revisionStatus === "all") {{
          return true;
        }}
        return String(((row || {{}}).status) || "").trim().toLowerCase() === revisionStatus;
      }}

      function buildOpsRevisionDiffSummary(row) {{
        const diff = row && row.diff && typeof row.diff === "object" ? row.diff : {{}};
        const parts = [];
        if (diff.label_changed) {{
          parts.push("label");
        }}
        if (diff.task_type_changed) {{
          parts.push("task_type");
        }}
        if (diff.lifecycle_changed) {{
          parts.push("state");
        }}
        parts.push("+" + String(diff.added_count || 0));
        parts.push("-" + String(diff.removed_count || 0));
        return parts.join(" / ");
      }}

      function resetOpsMasterChecklistRevisionDiff() {{
        const meta = document.getElementById("opsMasterChecklistRevisionDiffMeta");
        const summary = document.getElementById("opsMasterChecklistRevisionDiffSummary");
        const table = document.getElementById("opsMasterChecklistRevisionDiffTable");
        if (meta) {{
          meta.textContent = "개정안 비교 전";
        }}
        if (summary) {{
          summary.innerHTML = renderEmpty("개정안 diff 데이터 없음");
        }}
        if (table) {{
          table.innerHTML = renderEmpty("개정안 diff 항목 없음");
        }}
      }}

      function renderOpsMasterChecklistRevisionDiff(data) {{
        const meta = document.getElementById("opsMasterChecklistRevisionDiffMeta");
        const summary = document.getElementById("opsMasterChecklistRevisionDiffSummary");
        const table = document.getElementById("opsMasterChecklistRevisionDiffTable");
        if (!meta || !summary || !table) {{
          return;
        }}
        const row = data && data.row && typeof data.row === "object" ? data.row : null;
        if (!row) {{
          resetOpsMasterChecklistRevisionDiff();
          return;
        }}
        const diff = row.diff && typeof row.diff === "object" ? row.diff : {{}};
        const missingSections = Array.isArray(row.release_note_missing_sections) ? row.release_note_missing_sections : [];
        const summaryItems = [
          ["Revision ID", row.id || "-"],
          ["Set ID", row.set_id || "-"],
          ["Status", row.status || "-"],
          ["Live Version", row.live_version_no || "-"],
          ["Proposed Version", row.proposed_version_no || "-"],
          ["Release Note", row.release_note_valid ? "valid" : ("invalid: " + (missingSections.join(", ") || "missing"))],
          ["Added", diff.added_count || 0],
          ["Removed", diff.removed_count || 0],
          ["Has Changes", diff.has_changes ? "YES" : "NO"],
        ];
        summary.innerHTML = summaryItems.map((item) => (
          '<div class="card"><div class="k">' + escapeHtml(item[0]) + '</div><div class="v">' + escapeHtml(item[1]) + "</div></div>"
        )).join("");

        const diffRows = [];
        if (diff.label_changed) {{
          diffRows.push({{ change_type: "meta", item: "label changed" }});
        }}
        if (diff.task_type_changed) {{
          diffRows.push({{ change_type: "meta", item: "task_type changed" }});
        }}
        if (diff.lifecycle_changed) {{
          diffRows.push({{ change_type: "meta", item: "lifecycle_state changed" }});
        }}
        (Array.isArray(diff.added_items) ? diff.added_items : []).forEach((item) => {{
          diffRows.push({{ change_type: "added", item: item }});
        }});
        (Array.isArray(diff.removed_items) ? diff.removed_items : []).forEach((item) => {{
          diffRows.push({{ change_type: "removed", item: item }});
        }});
        (Array.isArray(diff.unchanged_items) ? diff.unchanged_items : []).slice(0, 5).forEach((item) => {{
          diffRows.push({{ change_type: "unchanged", item: item }});
        }});
        table.innerHTML = diffRows.length > 0
          ? renderTable(
              diffRows,
              [
                {{ key: "change_type", label: "Diff" }},
                {{ key: "item", label: "Item / Detail" }},
              ]
            )
          : renderEmpty("개정안 diff 항목 없음");
        meta.textContent = "비교 완료: revision_id=" + String(row.id || "-");
      }}

      function renderOpsMasterTables() {{
        const equipmentTable = document.getElementById("opsMasterEquipmentTable");
        const checklistTable = document.getElementById("opsMasterChecklistTable");
        const checklistRevisionTable = document.getElementById("opsMasterChecklistRevisionTable");
        const qrTable = document.getElementById("opsMasterQrTable");
        if (!equipmentTable || !checklistTable || !checklistRevisionTable || !qrTable) {{
          return;
        }}
        const filters = getOpsMasterTableFilters();

        const equipmentRows = getAllOpsEquipmentAssets().filter((row) => (
          rowMatchesOpsMasterLifecycle(row, filters.lifecycleState)
          && rowMatchesOpsMasterSearch(row, ["equipment_id", "equipment", "location", "source"], filters.search)
        ));
        equipmentTable.innerHTML = equipmentRows.length > 0
          ? renderTable(
              equipmentRows,
              [
                {{ key: "equipment_id", label: "Equipment ID" }},
                {{ key: "equipment", label: "Equipment" }},
                {{ key: "location", label: "Location" }},
                {{ key: "lifecycle_state", label: "State" }},
                {{ key: "source", label: "Source" }},
                {{ key: "updated_at", label: "Updated At" }},
              ]
            )
          : renderEmpty("설비 마스터 데이터가 없습니다.");

        const checklistRows = getAllOpsChecklistSets().map((row) => {{
          const items = Array.isArray(row.items) ? row.items : [];
          return {{
            checklist_master_id: row.checklist_master_id || "-",
            set_id: row.set_id || "-",
            label: row.label || "-",
            task_type: row.task_type || "-",
            version_no: row.version_no || 1,
            lifecycle_state: row.lifecycle_state || "active",
            item_count: row.item_count || items.length || 0,
            items_preview: items.slice(0, 3).map((item) => String((item && item.item) || "").trim()).filter(Boolean).join(" / "),
            source: row.source || "-",
            updated_at: row.updated_at || "-",
          }};
        }}).filter((row) => (
          rowMatchesOpsMasterLifecycle(row, filters.lifecycleState)
          && rowMatchesOpsMasterSearch(row, ["checklist_master_id", "set_id", "label", "task_type", "items_preview", "source"], filters.search)
        ));
        checklistTable.innerHTML = checklistRows.length > 0
          ? renderTable(
              checklistRows,
              [
                {{ key: "checklist_master_id", label: "Master ID" }},
                {{ key: "set_id", label: "Set ID" }},
                {{ key: "label", label: "Label" }},
                {{ key: "task_type", label: "Task Type" }},
                {{ key: "version_no", label: "Version" }},
                {{ key: "lifecycle_state", label: "State" }},
                {{ key: "item_count", label: "Items" }},
                {{ key: "items_preview", label: "Preview" }},
                {{ key: "updated_at", label: "Updated At" }},
              ]
            )
          : renderEmpty("체크리스트 마스터 데이터가 없습니다.");

        const revisionRows = Array.isArray(OPS_SPECIAL_CHECKLIST_REVISIONS)
          ? OPS_SPECIAL_CHECKLIST_REVISIONS.map((row) => {{
              const items = Array.isArray(row && row.items) ? row.items : [];
              const diff = row && row.diff && typeof row.diff === "object" ? row.diff : {{}};
              return {{
                id: row.id || "-",
                set_id: row.set_id || "-",
                label: row.label || "-",
                task_type: row.task_type || "-",
                proposed_version_no: row.proposed_version_no || 1,
                status: row.status || "-",
                lifecycle_state: row.lifecycle_state || "active",
                release_note: row.release_note_valid ? "valid" : ("invalid: " + ((row.release_note_missing_sections || []).join(", "))),
                diff_summary: buildOpsRevisionDiffSummary(row),
                created_by: row.created_by || "-",
                submitted_by: row.submitted_by || "-",
                decided_by: row.decided_by || "-",
                item_count: row.item_count || items.length || 0,
                updated_at: row.updated_at || "-",
              }};
            }})
            .filter((row) => (
              rowMatchesOpsMasterLifecycle(row, filters.lifecycleState)
              && rowMatchesOpsMasterRevisionStatus(row, filters.revisionStatus)
              && rowMatchesOpsMasterSearch(row, ["id", "set_id", "label", "task_type", "status", "release_note", "created_by", "submitted_by", "decided_by", "diff_summary"], filters.search)
            ))
          : [];
        checklistRevisionTable.innerHTML = revisionRows.length > 0
          ? renderTable(
              revisionRows,
              [
                {{ key: "id", label: "Revision ID" }},
                {{ key: "set_id", label: "Set ID" }},
                {{ key: "label", label: "Label" }},
                {{ key: "proposed_version_no", label: "Proposed Version" }},
                {{ key: "status", label: "Status" }},
                {{ key: "lifecycle_state", label: "State" }},
                {{ key: "release_note", label: "Release Note" }},
                {{ key: "diff_summary", label: "Diff" }},
                {{ key: "created_by", label: "Created By" }},
                {{ key: "submitted_by", label: "Submitted By" }},
                {{ key: "decided_by", label: "Decided By" }},
                {{ key: "item_count", label: "Items" }},
                {{ key: "updated_at", label: "Updated At" }},
              ]
            )
          : renderEmpty("체크리스트 개정안 데이터가 없습니다.");

        const qrRows = getAllOpsQrAssets().filter((row) => (
          rowMatchesOpsMasterLifecycle(row, filters.lifecycleState)
          && rowMatchesOpsMasterSearch(row, ["qr_asset_id", "qr_id", "equipment_id", "equipment", "location", "checklist_set_id", "default_item"], filters.search)
        ));
        qrTable.innerHTML = qrRows.length > 0
          ? renderTable(
              qrRows,
              [
                {{ key: "qr_asset_id", label: "QR Asset ID" }},
                {{ key: "qr_id", label: "QR ID" }},
                {{ key: "equipment_id", label: "Equipment ID" }},
                {{ key: "equipment", label: "Equipment" }},
                {{ key: "location", label: "Location" }},
                {{ key: "checklist_set_id", label: "Checklist Set" }},
                {{ key: "default_item", label: "Default Item" }},
                {{ key: "lifecycle_state", label: "State" }},
                {{ key: "updated_at", label: "Updated At" }},
              ]
            )
          : renderEmpty("QR 마스터 데이터가 없습니다.");
      }}

      function applyOpsMasterCatalogData(payload) {{
        if (!payload || typeof payload !== "object") {{
          return;
        }}
        OPS_SPECIAL_CHECKLISTS = payload;
        populateOpsChecklistSetSelector();
        populateOpsCodeSelector();
        populateOpsEquipmentSelector();
        populateOpsQrSelector();
        applyChecklistSetSelection({{ preserveChecklist: true, resetChecklist: false }});
        applySelectedOpsEquipmentToForm({{ overwriteFields: false }});
        applySelectedQrAssetToForm({{ overwriteFields: false }});
        renderOpsMasterTables();
      }}

      async function fetchAndApplyOpsMasterChecklistRevisions() {{
        const data = await fetchJson("/api/ops/inspections/checklists/revisions?limit=200", true);
        OPS_SPECIAL_CHECKLIST_REVISIONS = Array.isArray(data && data.rows) ? data.rows : [];
        renderOpsMasterTables();
        return data;
      }}

      async function fetchAndApplyOpsMasterCatalog() {{
        const data = await fetchJson("/api/ops/inspections/checklists/catalog", true);
        applyOpsMasterCatalogData(data);
        return data;
      }}

      async function runOpsMasterCatalogRefresh() {{
        const meta = document.getElementById("opsMasterMeta");
        try {{
          meta.textContent = "조회 중... /api/ops/inspections/checklists/catalog";
          const data = await fetchAndApplyOpsMasterCatalog();
          await fetchAndApplyOpsMasterChecklistRevisions().catch(() => null);
          const summary = data.summary || {{}};
          meta.textContent =
            "성공: checklist_set=" + String(summary.checklist_set_count || 0)
            + " | equipment=" + String(summary.equipment_asset_count || 0)
            + " | qr=" + String(summary.qr_asset_count || 0);
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          renderOpsMasterTables();
        }}
      }}

      function requirePositiveIntInput(id, label) {{
        const raw = String((document.getElementById(id) || {{ value: "" }}).value || "").trim();
        const value = Number(raw);
        if (!Number.isInteger(value) || value <= 0) {{
          throw new Error(label + " 값이 올바른 정수가 아닙니다.");
        }}
        return value;
      }}

      async function runOpsMasterEquipmentCreate() {{
        const meta = document.getElementById("opsMasterMeta");
        const equipment = String((document.getElementById("opsMasterEquipmentName") || {{ value: "" }}).value || "").trim();
        const location = String((document.getElementById("opsMasterEquipmentLocation") || {{ value: "" }}).value || "").trim();
        const lifecycleState = normalizeOpsLifecycleState((document.getElementById("opsMasterEquipmentLifecycle") || {{ value: "active" }}).value || "active");
        if (!equipment) {{
          meta.textContent = "실패: 설비명을 입력하세요.";
          return;
        }}
        try {{
          meta.textContent = "설비 생성 중...";
          const created = await fetchJson(
            "/api/ops/inspections/checklists/equipment-assets",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{ equipment, location, lifecycle_state: lifecycleState }}),
            }}
          );
          await fetchAndApplyOpsMasterCatalog();
          document.getElementById("opsMasterEquipmentId").value = String((((created || {{}}).row || {{}}).equipment_id) || "");
          meta.textContent = "성공: equipment_id=" + String((((created || {{}}).row || {{}}).equipment_id) || "-");
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runOpsMasterEquipmentUpdate() {{
        const meta = document.getElementById("opsMasterMeta");
        try {{
          const equipmentId = requirePositiveIntInput("opsMasterEquipmentId", "equipment_id");
          const equipment = String((document.getElementById("opsMasterEquipmentName") || {{ value: "" }}).value || "").trim();
          const location = String((document.getElementById("opsMasterEquipmentLocation") || {{ value: "" }}).value || "").trim();
          const lifecycleState = normalizeOpsLifecycleState((document.getElementById("opsMasterEquipmentLifecycle") || {{ value: "active" }}).value || "active");
          if (!equipment) {{
            meta.textContent = "실패: 설비명을 입력하세요.";
            return;
          }}
          meta.textContent = "설비 수정 중...";
          await fetchJson(
            "/api/ops/inspections/checklists/equipment-assets/" + encodeURIComponent(String(equipmentId)),
            true,
            {{
              method: "PATCH",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{ equipment, location, lifecycle_state: lifecycleState }}),
            }}
          );
          await fetchAndApplyOpsMasterCatalog();
          meta.textContent = "성공: equipment_id=" + String(equipmentId);
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runOpsMasterEquipmentDelete() {{
        const meta = document.getElementById("opsMasterMeta");
        try {{
          const equipmentId = requirePositiveIntInput("opsMasterEquipmentId", "equipment_id");
          meta.textContent = "설비 삭제 중...";
          await fetchJson(
            "/api/ops/inspections/checklists/equipment-assets/" + encodeURIComponent(String(equipmentId)),
            true,
            {{ method: "DELETE" }}
          );
          await fetchAndApplyOpsMasterCatalog();
          meta.textContent = "성공: equipment_id=" + String(equipmentId) + " 삭제";
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runOpsMasterChecklistCreate() {{
        const meta = document.getElementById("opsMasterMeta");
        const setId = String((document.getElementById("opsMasterChecklistSetId") || {{ value: "" }}).value || "").trim();
        const label = String((document.getElementById("opsMasterChecklistLabel") || {{ value: "" }}).value || "").trim();
        const taskType = String((document.getElementById("opsMasterChecklistTaskType") || {{ value: "" }}).value || "").trim();
        const versionNoRaw = String((document.getElementById("opsMasterChecklistVersion") || {{ value: "" }}).value || "").trim();
        const lifecycleState = normalizeOpsLifecycleState((document.getElementById("opsMasterChecklistLifecycle") || {{ value: "active" }}).value || "active");
        const items = parseOpsMasterChecklistItemsInput();
        if (!setId || !label || !taskType || items.length === 0) {{
          meta.textContent = "실패: set_id, label, task_type, items를 모두 입력하세요.";
          return;
        }}
        try {{
          meta.textContent = "체크리스트 세트 생성 중...";
          await fetchJson(
            "/api/ops/inspections/checklists/sets",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{
                set_id: setId,
                label: label,
                task_type: taskType,
                version_no: versionNoRaw || undefined,
                lifecycle_state: lifecycleState,
                items: items,
              }}),
            }}
          );
          await fetchAndApplyOpsMasterCatalog();
          meta.textContent = "성공: set_id=" + setId;
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runOpsMasterChecklistUpdate() {{
        const meta = document.getElementById("opsMasterMeta");
        const setId = String((document.getElementById("opsMasterChecklistSetId") || {{ value: "" }}).value || "").trim();
        const label = String((document.getElementById("opsMasterChecklistLabel") || {{ value: "" }}).value || "").trim();
        const taskType = String((document.getElementById("opsMasterChecklistTaskType") || {{ value: "" }}).value || "").trim();
        const versionNoRaw = String((document.getElementById("opsMasterChecklistVersion") || {{ value: "" }}).value || "").trim();
        const lifecycleState = normalizeOpsLifecycleState((document.getElementById("opsMasterChecklistLifecycle") || {{ value: "active" }}).value || "active");
        const items = parseOpsMasterChecklistItemsInput();
        if (!setId || !label || !taskType || items.length === 0) {{
          meta.textContent = "실패: set_id, label, task_type, items를 모두 입력하세요.";
          return;
        }}
        try {{
          meta.textContent = "체크리스트 세트 수정 중...";
          await fetchJson(
            "/api/ops/inspections/checklists/sets/" + encodeURIComponent(setId),
            true,
            {{
              method: "PATCH",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{
                label: label,
                task_type: taskType,
                version_no: versionNoRaw || undefined,
                lifecycle_state: lifecycleState,
                items: items,
              }}),
            }}
          );
          await fetchAndApplyOpsMasterCatalog();
          meta.textContent = "성공: set_id=" + setId;
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runOpsMasterChecklistDelete() {{
        const meta = document.getElementById("opsMasterMeta");
        const setId = String((document.getElementById("opsMasterChecklistSetId") || {{ value: "" }}).value || "").trim();
        if (!setId) {{
          meta.textContent = "실패: set_id를 입력하세요.";
          return;
        }}
        try {{
          meta.textContent = "체크리스트 세트 삭제 중...";
          await fetchJson(
            "/api/ops/inspections/checklists/sets/" + encodeURIComponent(setId),
            true,
            {{ method: "DELETE" }}
          );
          await fetchAndApplyOpsMasterCatalog();
          meta.textContent = "성공: set_id=" + setId + " 삭제";
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runOpsMasterChecklistRevisionCreate() {{
        const meta = document.getElementById("opsMasterMeta");
        const setId = String((document.getElementById("opsMasterChecklistSetId") || {{ value: "" }}).value || "").trim();
        const label = String((document.getElementById("opsMasterChecklistLabel") || {{ value: "" }}).value || "").trim();
        const taskType = String((document.getElementById("opsMasterChecklistTaskType") || {{ value: "" }}).value || "").trim();
        const proposedVersionNo = String((document.getElementById("opsMasterChecklistVersion") || {{ value: "" }}).value || "").trim();
        const lifecycleState = normalizeOpsLifecycleState((document.getElementById("opsMasterChecklistLifecycle") || {{ value: "active" }}).value || "active");
        const note = String((document.getElementById("opsMasterChecklistRevisionNote") || {{ value: "" }}).value || "").trim();
        const items = parseOpsMasterChecklistItemsInput();
        if (!setId || !label || !taskType || items.length === 0) {{
          meta.textContent = "실패: set_id, label, task_type, items를 모두 입력하세요.";
          return;
        }}
        try {{
          meta.textContent = "체크리스트 개정안 작성 중...";
          const created = await fetchJson(
            "/api/ops/inspections/checklists/revisions",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{
                set_id: setId,
                label: label,
                task_type: taskType,
                proposed_version_no: proposedVersionNo || undefined,
                lifecycle_state: lifecycleState,
                note: note,
                items: items,
              }}),
            }}
          );
          document.getElementById("opsMasterChecklistRevisionId").value = String((((created || {{}}).row || {{}}).id) || "");
          await fetchAndApplyOpsMasterChecklistRevisions();
          meta.textContent = "성공: revision_id=" + String((((created || {{}}).row || {{}}).id) || "-");
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runOpsMasterChecklistRevisionList() {{
        const meta = document.getElementById("opsMasterMeta");
        try {{
          meta.textContent = "체크리스트 개정안 조회 중...";
          const data = await fetchAndApplyOpsMasterChecklistRevisions();
          const summary = data.summary || {{}};
          meta.textContent =
            "성공: revision=" + String(summary.revision_count || 0)
            + " | pending=" + String(summary.pending_count || 0);
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runOpsMasterChecklistRevisionDiff() {{
        const meta = document.getElementById("opsMasterMeta");
        try {{
          const revisionId = requirePositiveIntInput("opsMasterChecklistRevisionId", "revision_id");
          meta.textContent = "체크리스트 개정안 비교 중...";
          const data = await fetchJson(
            "/api/ops/inspections/checklists/revisions/" + encodeURIComponent(String(revisionId)),
            true
          );
          renderOpsMasterChecklistRevisionDiff(data);
          meta.textContent = "성공: revision_id=" + String(revisionId) + " 비교";
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          resetOpsMasterChecklistRevisionDiff();
        }}
      }}

      async function runOpsMasterChecklistRevisionSubmit() {{
        const meta = document.getElementById("opsMasterMeta");
        const note = String((document.getElementById("opsMasterChecklistRevisionNote") || {{ value: "" }}).value || "").trim();
        try {{
          const revisionId = requirePositiveIntInput("opsMasterChecklistRevisionId", "revision_id");
          meta.textContent = "체크리스트 개정안 제출 중...";
          await fetchJson(
            "/api/ops/inspections/checklists/revisions/" + encodeURIComponent(String(revisionId)) + "/submit",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{ note }}),
            }}
          );
          await fetchAndApplyOpsMasterChecklistRevisions();
          meta.textContent = "성공: revision_id=" + String(revisionId) + " 제출";
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runOpsMasterChecklistRevisionApprove() {{
        const meta = document.getElementById("opsMasterMeta");
        const note = String((document.getElementById("opsMasterChecklistRevisionNote") || {{ value: "" }}).value || "").trim();
        try {{
          const revisionId = requirePositiveIntInput("opsMasterChecklistRevisionId", "revision_id");
          meta.textContent = "체크리스트 개정안 승인 중...";
          await fetchJson(
            "/api/ops/inspections/checklists/revisions/" + encodeURIComponent(String(revisionId)) + "/approve",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{ note }}),
            }}
          );
          await fetchAndApplyOpsMasterCatalog();
          await fetchAndApplyOpsMasterChecklistRevisions();
          meta.textContent = "성공: revision_id=" + String(revisionId) + " 승인";
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runOpsMasterChecklistRevisionReject() {{
        const meta = document.getElementById("opsMasterMeta");
        const note = String((document.getElementById("opsMasterChecklistRevisionNote") || {{ value: "" }}).value || "").trim();
        try {{
          const revisionId = requirePositiveIntInput("opsMasterChecklistRevisionId", "revision_id");
          meta.textContent = "체크리스트 개정안 반려 중...";
          await fetchJson(
            "/api/ops/inspections/checklists/revisions/" + encodeURIComponent(String(revisionId)) + "/reject",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{ note }}),
            }}
          );
          await fetchAndApplyOpsMasterChecklistRevisions();
          meta.textContent = "성공: revision_id=" + String(revisionId) + " 반려";
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runOpsMasterQrCreate() {{
        const meta = document.getElementById("opsMasterMeta");
        const qrId = String((document.getElementById("opsMasterQrId") || {{ value: "" }}).value || "").trim();
        const checklistSetId = String((document.getElementById("opsMasterQrChecklistSetId") || {{ value: "" }}).value || "").trim();
        const defaultItem = String((document.getElementById("opsMasterQrDefaultItem") || {{ value: "" }}).value || "").trim();
        const lifecycleState = normalizeOpsLifecycleState((document.getElementById("opsMasterQrLifecycle") || {{ value: "active" }}).value || "active");
        if (!qrId || !checklistSetId) {{
          meta.textContent = "실패: qr_id와 checklist_set_id를 입력하세요.";
          return;
        }}
        try {{
          const equipmentId = requirePositiveIntInput("opsMasterQrEquipmentId", "equipment_id");
          meta.textContent = "QR 자산 생성 중...";
          const created = await fetchJson(
            "/api/ops/inspections/checklists/qr-assets",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{
                qr_id: qrId,
                equipment_id: equipmentId,
                checklist_set_id: checklistSetId,
                default_item: defaultItem,
                lifecycle_state: lifecycleState,
              }}),
            }}
          );
          await fetchAndApplyOpsMasterCatalog();
          document.getElementById("opsMasterQrAssetId").value = String((((created || {{}}).row || {{}}).qr_asset_id) || "");
          meta.textContent = "성공: qr_asset_id=" + String((((created || {{}}).row || {{}}).qr_asset_id) || "-");
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runOpsMasterQrUpdate() {{
        const meta = document.getElementById("opsMasterMeta");
        const qrId = String((document.getElementById("opsMasterQrId") || {{ value: "" }}).value || "").trim();
        const checklistSetId = String((document.getElementById("opsMasterQrChecklistSetId") || {{ value: "" }}).value || "").trim();
        const defaultItem = String((document.getElementById("opsMasterQrDefaultItem") || {{ value: "" }}).value || "").trim();
        const lifecycleState = normalizeOpsLifecycleState((document.getElementById("opsMasterQrLifecycle") || {{ value: "active" }}).value || "active");
        if (!qrId || !checklistSetId) {{
          meta.textContent = "실패: qr_id와 checklist_set_id를 입력하세요.";
          return;
        }}
        try {{
          const qrAssetId = requirePositiveIntInput("opsMasterQrAssetId", "qr_asset_id");
          const equipmentId = requirePositiveIntInput("opsMasterQrEquipmentId", "equipment_id");
          meta.textContent = "QR 자산 수정 중...";
          await fetchJson(
            "/api/ops/inspections/checklists/qr-assets/" + encodeURIComponent(String(qrAssetId)),
            true,
            {{
              method: "PATCH",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{
                qr_id: qrId,
                equipment_id: equipmentId,
                checklist_set_id: checklistSetId,
                default_item: defaultItem,
                lifecycle_state: lifecycleState,
              }}),
            }}
          );
          await fetchAndApplyOpsMasterCatalog();
          meta.textContent = "성공: qr_asset_id=" + String(qrAssetId);
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runOpsMasterQrDelete() {{
        const meta = document.getElementById("opsMasterMeta");
        try {{
          const qrAssetId = requirePositiveIntInput("opsMasterQrAssetId", "qr_asset_id");
          meta.textContent = "QR 자산 삭제 중...";
          await fetchJson(
            "/api/ops/inspections/checklists/qr-assets/" + encodeURIComponent(String(qrAssetId)),
            true,
            {{ method: "DELETE" }}
          );
          await fetchAndApplyOpsMasterCatalog();
          meta.textContent = "성공: qr_asset_id=" + String(qrAssetId) + " 삭제";
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      function getOpsElectricalChecklistGroups(selectedGroup) {{
        const group = String(selectedGroup || "all");
        const setObj = getOpsChecklistSetById(getSelectedOpsChecklistSetId());
        const groups = buildOpsChecklistGroups(setObj);
        if (!group || group === "all") {{
          return groups;
        }}
        return groups.filter((item) => item.group === group);
      }}

      function summarizeOpsElectricalChecklistRows(rows) {{
        const source = Array.isArray(rows) ? rows : [];
        const summary = {{
          total: source.length,
          normal: 0,
          abnormal: 0,
          na: 0,
        }};
        source.forEach((row) => {{
          const result = String((row && row.result) || "normal");
          if (result === "abnormal") {{
            summary.abnormal += 1;
            return;
          }}
          if (result === "na") {{
            summary.na += 1;
            return;
          }}
          summary.normal += 1;
        }});
        return summary;
      }}

      function renderOpsElectricalChecklist() {{
        const table = document.getElementById("inspectionChecklistTable");
        const summaryNode = document.getElementById("inspectionChecklistSummary");
        if (!table || !summaryNode) {{
          return;
        }}
        if (!Array.isArray(opsElectricalChecklistRows) || opsElectricalChecklistRows.length === 0) {{
          summaryNode.textContent = "표시할 점검 항목이 없습니다.";
          table.innerHTML = renderEmpty("체크리스트가 비어 있습니다.");
          return;
        }}
        const summary = summarizeOpsElectricalChecklistRows(opsElectricalChecklistRows);
        summaryNode.textContent =
          "항목 " + String(summary.total)
          + "건 | 정상 " + String(summary.normal)
          + " | 이상 " + String(summary.abnormal)
          + " | N/A " + String(summary.na);
        const head = "<th>#</th><th>구분</th><th>점검내용</th><th>결과</th><th>조치</th>";
        const body = opsElectricalChecklistRows.map((row, index) => {{
          const options = OPS_RESULT_OPTIONS.map((opt) => {{
            const selected = opt.value === row.result ? " selected" : "";
            return '<option value="' + escapeHtml(opt.value) + '"' + selected + ">" + escapeHtml(opt.label) + "</option>";
          }}).join("");
          return (
            "<tr>"
            + "<td>" + escapeHtml(row.seq) + "</td>"
            + "<td>" + escapeHtml(row.group) + "</td>"
            + "<td>" + escapeHtml(row.item) + "</td>"
            + '<td><select class="ops-check-result" data-row-index="' + escapeHtml(index) + '">' + options + "</select></td>"
            + '<td><input class="ops-check-action" data-row-index="' + escapeHtml(index) + '" placeholder="조치 내용(선택)" value="' + escapeHtml(row.action || "") + '" /></td>'
            + "</tr>"
          );
        }}).join("");
        table.innerHTML = '<div class="table-wrap"><table><thead><tr>' + head + "</tr></thead><tbody>" + body + "</tbody></table></div>";
      }}

      function bindOpsElectricalChecklistHandlers() {{
        const table = document.getElementById("inspectionChecklistTable");
        if (!table) {{
          return;
        }}
        table.addEventListener("change", (event) => {{
          const target = event.target;
          if (!(target instanceof Element)) {{
            return;
          }}
          const selectNode = target.closest(".ops-check-result");
          if (!selectNode) {{
            return;
          }}
          const rowIndex = asInt(selectNode.getAttribute("data-row-index"), -1);
          if (rowIndex < 0 || rowIndex >= opsElectricalChecklistRows.length) {{
            return;
          }}
          const value = String(selectNode.value || "normal");
          opsElectricalChecklistRows[rowIndex].result = value;
          renderOpsElectricalChecklist();
        }});
        table.addEventListener("input", (event) => {{
          const target = event.target;
          if (!(target instanceof Element)) {{
            return;
          }}
          const inputNode = target.closest(".ops-check-action");
          if (!inputNode) {{
            return;
          }}
          const rowIndex = asInt(inputNode.getAttribute("data-row-index"), -1);
          if (rowIndex < 0 || rowIndex >= opsElectricalChecklistRows.length) {{
            return;
          }}
          opsElectricalChecklistRows[rowIndex].action = String(inputNode.value || "");
        }});
      }}

      function resetOpsElectricalChecklistRows(options = {{}}) {{
        const templateNode = document.getElementById("inTemplateGroup");
        const selectedGroup = String(options.selectedGroup || (templateNode ? templateNode.value : "all") || "all");
        const preserve = Boolean(options.preserve);
        const previous = new Map();
        if (preserve) {{
          (opsElectricalChecklistRows || []).forEach((row) => {{
            const key = String(row.group || "") + "|" + String(row.item || "");
            previous.set(key, {{
              result: String(row.result || "normal"),
              action: String(row.action || ""),
            }});
          }});
        }}
        const nextRows = [];
        let seq = 1;
        getOpsElectricalChecklistGroups(selectedGroup).forEach((groupItem) => {{
          (groupItem.items || []).forEach((item) => {{
            const key = String(groupItem.group || "") + "|" + String(item || "");
            const prev = previous.get(key) || null;
            nextRows.push({{
              seq: seq,
              group: String(groupItem.group || ""),
              item: String(item || ""),
              result: prev ? prev.result : "normal",
              action: prev ? prev.action : "",
            }});
            seq += 1;
          }});
        }});
        opsElectricalChecklistRows = nextRows;
        renderOpsElectricalChecklist();
      }}

      function setOpsChecklistAllResult(resultValue) {{
        const target = String(resultValue || "normal");
        if (!Array.isArray(opsElectricalChecklistRows) || opsElectricalChecklistRows.length === 0) {{
          return;
        }}
        opsElectricalChecklistRows = opsElectricalChecklistRows.map((row) => {{
          return {{
            seq: row.seq,
            group: row.group,
            item: row.item,
            result: target,
            action: target === "abnormal" ? String(row.action || "") : (target === "na" ? "" : String(row.action || "")),
          }};
        }});
        renderOpsElectricalChecklist();
      }}

      function syncOpsTemplateGroupFromEquipmentGroup() {{
        const equipmentGroupNode = document.getElementById("inCreateEquipmentGroup");
        const templateGroupNode = document.getElementById("inTemplateGroup");
        if (!equipmentGroupNode || !templateGroupNode) {{
          return;
        }}
        const value = String(equipmentGroupNode.value || "all");
        setSelectValueIfAvailable(templateGroupNode, value || "all", "all");
      }}

      function collectOpsPhotoFiles() {{
        const fileInput = document.getElementById("inCreatePhotoFiles");
        if (!fileInput || !fileInput.files) {{
          return [];
        }}
        return Array.from(fileInput.files);
      }}

      function collectOpsPhotoFileNames() {{
        return collectOpsPhotoFiles()
          .map((file) => String((file && file.name) || "").trim())
          .filter((name) => name !== "");
      }}

      function buildOpsInspectionNotes(meta, checklistRows, memoText) {{
        const compactRows = (Array.isArray(checklistRows) ? checklistRows : []).map((row) => {{
          return {{
            group: String(row.group || ""),
            item: String(row.item || ""),
            result: String(row.result || "normal"),
            action: String(row.action || "").trim(),
          }};
        }});
        const lines = [
          "[OPS_CHECKLIST_V1]",
          "meta=" + JSON.stringify(meta || {{}}),
          "checklist=" + JSON.stringify(compactRows),
        ];
        const memo = String(memoText || "").trim();
        if (memo) {{
          lines.push("memo=" + memo.replace(/\\r?\\n/g, " / "));
        }}
        return lines.join("\\n");
      }}

      function parseOpsInspectionNotes(noteText) {{
        const text = String(noteText || "");
        if (!text.includes("[OPS_CHECKLIST_V1]") && !text.includes("[OPS_ELECTRICAL_V1]")) {{
          return null;
        }}
        const lines = text.split(/\\r?\\n/);
        let meta = null;
        let checklist = null;
        let memo = "";
        lines.forEach((line) => {{
          if (line.startsWith("meta=")) {{
            try {{
              const parsed = JSON.parse(line.slice(5));
              if (parsed && typeof parsed === "object") {{
                meta = parsed;
              }}
            }} catch (err) {{
              meta = null;
            }}
            return;
          }}
          if (line.startsWith("checklist=")) {{
            try {{
              const parsed = JSON.parse(line.slice(10));
              if (Array.isArray(parsed)) {{
                checklist = parsed;
              }}
            }} catch (err) {{
              checklist = null;
            }}
            return;
          }}
          if (line.startsWith("memo=")) {{
            memo = line.slice(5);
          }}
        }});
        return {{
          meta: meta && typeof meta === "object" ? meta : {{}},
          checklist: Array.isArray(checklist) ? checklist : [],
          memo: memo,
        }};
      }}

      function buildOpsInspectionDisplayRow(row) {{
        const parsed = parseOpsInspectionNotes(row.notes);
        const hasOps = !!parsed;
        const meta = parsed ? (parsed.meta || {{}}) : {{}};
        const summary = meta && typeof meta.summary === "object" && meta.summary ? meta.summary : {{}};
        const normalCount = asInt(summary.normal, 0);
        const abnormalCount = asInt(summary.abnormal, 0);
        const naCount = asInt(summary.na, 0);
        const photoFiles = Array.isArray(meta.photo_files) ? meta.photo_files : [];
        const actionText = String(meta.abnormal_action || "").trim();
        const inspectedAtLabel = formatDateLocal(row.inspected_at);
        return {{
          id: row.id,
          site: row.site,
          task_type: hasOps ? (meta.task_type || row.cycle || "-") : (row.cycle || "-"),
          equipment: hasOps ? (meta.equipment || "-") : "-",
          equipment_code: hasOps ? (meta.equipment_code || "-") : "-",
          equipment_location: hasOps ? (meta.equipment_location || row.location || "-") : (row.location || "-"),
          inspector: row.inspector || "-",
          result_summary: hasOps ? ("정상 " + String(normalCount) + " / 이상 " + String(abnormalCount) + " / N/A " + String(naCount)) : "-",
          action: hasOps ? (actionText || "-") : "-",
          photos: hasOps ? (photoFiles.length > 0 ? String(photoFiles.length) + " files" : "-") : "-",
          risk_level: row.risk_level || "-",
          inspected_at: inspectedAtLabel,
          _ops_record: hasOps ? "yes" : "no",
        }};
      }}

      async function runCreateOpsInspection() {{
        const meta = document.getElementById("inspectionCreateMeta");
        const site = (document.getElementById("inCreateSite").value || "").trim();
        const location = (document.getElementById("inCreateLocation").value || "").trim();
        const inspectorInput = (document.getElementById("inCreateInspector").value || "").trim();
        const inspector = inspectorInput || String((authProfile && authProfile.username) || "").trim();
        const inspectedAtRaw = (document.getElementById("inCreateInspectedAt").value || "").trim() || currentLocalDatetimeInputValue();
        const inspectedAt = new Date(inspectedAtRaw);
        if (!site) {{
          meta.textContent = "실패: site 값을 입력하세요.";
          return;
        }}
        if (!location) {{
          meta.textContent = "실패: 설비위치를 입력하세요.";
          return;
        }}
        if (!inspector) {{
          meta.textContent = "실패: 점검자 값을 입력하세요.";
          return;
        }}
        if (Number.isNaN(inspectedAt.getTime())) {{
          meta.textContent = "실패: 점검일시 형식이 올바르지 않습니다.";
          return;
        }}
        if (!Array.isArray(opsElectricalChecklistRows) || opsElectricalChecklistRows.length === 0) {{
          meta.textContent = "실패: 체크리스트 항목이 없습니다.";
          return;
        }}

        const checklistSetObj = getOpsChecklistSetById(getSelectedOpsChecklistSetId());
        const checklistSetId = String((checklistSetObj && checklistSetObj.set_id) || "").trim();
        const checklistSetLabel = String((checklistSetObj && checklistSetObj.label) || "").trim();
        const checklistTaskType = String((checklistSetObj && checklistSetObj.task_type) || "").trim();
        const selectedOpsCode = getSelectedOpsCodeRecord();
        const selectedEquipmentRecord = getSelectedOpsEquipmentRecord();
        const selectedQrAsset = getSelectedQrAssetRecord();
        const taskType = (document.getElementById("inCreateTaskType").value || "").trim() || checklistTaskType || "전기점검";
        const cycle = (document.getElementById("inCreateCycle").value || "").trim() || "daily";
        const equipmentGroup = (document.getElementById("inCreateEquipmentGroup").value || "").trim() || "all";
        const equipmentRaw = (document.getElementById("inCreateEquipment").value || "").trim();
        if (!checklistSetId) {{
          meta.textContent = "실패: checklist_set_id가 비어 있습니다. 체크리스트 세트를 선택하세요.";
          return;
        }}
        if (!taskType) {{
          meta.textContent = "실패: 업무구분(task_type)을 선택하세요.";
          return;
        }}
        const qrEquipment = String((selectedQrAsset && selectedQrAsset.equipment) || "").trim();
        const selectedEquipmentName = String((selectedEquipmentRecord && selectedEquipmentRecord.equipment) || "").trim();
        const defaultEquipment = taskType.includes("소방") ? "소방설비" : "전기설비";
        const equipment = equipmentRaw || qrEquipment || selectedEquipmentName || (equipmentGroup === "all" ? defaultEquipment : equipmentGroup);
        const equipmentCodeRaw = (document.getElementById("inCreateEquipmentCode").value || "").trim();
        const selectedOpsCodeValue = String((selectedOpsCode && selectedOpsCode.code) || "").trim();
        const selectedQrId = String((selectedQrAsset && selectedQrAsset.qr_id) || "").trim();
        const selectedEquipmentId = Number((selectedEquipmentRecord && selectedEquipmentRecord.equipment_id) || (selectedQrAsset && selectedQrAsset.equipment_id) || 0);
        const selectedQrAssetId = Number((selectedQrAsset && selectedQrAsset.qr_asset_id) || 0);
        const equipmentCode = equipmentCodeRaw || selectedOpsCodeValue || selectedQrId;
        const abnormalAction = (document.getElementById("inCreateAbnormalAction").value || "").trim();
        const memo = (document.getElementById("inCreateMemo").value || "").trim();
        const templateGroup = (document.getElementById("inTemplateGroup").value || "").trim() || "all";
        const photoFiles = collectOpsPhotoFiles();
        const photoFileNames = photoFiles
          .map((file) => String((file && file.name) || "").trim())
          .filter((name) => name !== "");
        const photoNote = (document.getElementById("inCreatePhotoNote").value || "").trim();
        const checklistDataVersion = String(((checklistSetObj && checklistSetObj.version_no) || (OPS_SPECIAL_CHECKLISTS && OPS_SPECIAL_CHECKLISTS.version) || "")).trim();
        const checklistSourceFile = String((OPS_SPECIAL_CHECKLISTS && OPS_SPECIAL_CHECKLISTS.source_file) || "").trim();
        const checklistRows = opsElectricalChecklistRows.map((row) => {{
          return {{
            seq: row.seq,
            group: row.group,
            item: row.item,
            result: String(row.result || "normal"),
            action: String(row.action || "").trim(),
          }};
        }});
        const summary = summarizeOpsElectricalChecklistRows(checklistRows);
        const abnormalRows = checklistRows.filter((row) => String(row.result || "") === "abnormal");
        const abnormalRowsWithoutAction = abnormalRows.filter((row) => !String(row.action || "").trim());
        if (abnormalRowsWithoutAction.length > 0 && !abnormalAction) {{
          meta.textContent =
            "실패: 이상 항목의 조치내용이 누락되었습니다. "
            + String(abnormalRowsWithoutAction.length)
            + "건의 이상 항목에 대해 행 조치 또는 이상조치 등록을 입력하세요.";
          return;
        }}
        const notes = buildOpsInspectionNotes(
          {{
            task_type: taskType,
            equipment_group: equipmentGroup,
            equipment: equipment,
            equipment_id: Number.isInteger(selectedEquipmentId) && selectedEquipmentId > 0 ? selectedEquipmentId : undefined,
            equipment_code: equipmentCode,
            equipment_location: location,
            template_group: templateGroup,
            checklist_set_id: checklistSetId,
            checklist_set_label: checklistSetLabel,
            checklist_task_type: checklistTaskType,
            checklist_data_version: checklistDataVersion,
            checklist_source_file: checklistSourceFile,
            ops_code: selectedOpsCodeValue,
            ops_code_category: String((selectedOpsCode && selectedOpsCode.category) || "").trim(),
            ops_code_description: String((selectedOpsCode && selectedOpsCode.description) || "").trim(),
            qr_id: selectedQrId,
            qr_asset_id: Number.isInteger(selectedQrAssetId) && selectedQrAssetId > 0 ? selectedQrAssetId : undefined,
            qr_equipment: qrEquipment,
            qr_location: String((selectedQrAsset && selectedQrAsset.location) || "").trim(),
            qr_default_item: String((selectedQrAsset && selectedQrAsset.default_item) || "").trim(),
            summary: summary,
            abnormal_action: abnormalAction,
            photo_files: photoFileNames,
            photo_note: photoNote,
            auto_work_order_requested: !!document.getElementById("inCreateAutoWorkOrder").checked,
          }},
          checklistRows,
          memo,
        );

        const payload = {{
          site: site,
          location: location,
          cycle: cycle,
          inspector: inspector,
          inspected_at: inspectedAt.toISOString(),
          notes: notes,
        }};
        if (Number.isInteger(selectedEquipmentId) && selectedEquipmentId > 0) {{
          payload.equipment_id = selectedEquipmentId;
        }}
        if (Number.isInteger(selectedQrAssetId) && selectedQrAssetId > 0) {{
          payload.qr_asset_id = selectedQrAssetId;
        }}
        try {{
          const windingTempC = parseOptionalNumberInput("inCreateWindingTemp", "권선온도");
          const groundingOhm = parseOptionalNumberInput("inCreateGroundingOhm", "접지저항");
          const insulationMohm = parseOptionalNumberInput("inCreateInsulationMohm", "절연저항");
          if (windingTempC !== null) payload.winding_temp_c = windingTempC;
          if (groundingOhm !== null) payload.grounding_ohm = groundingOhm;
          if (insulationMohm !== null) payload.insulation_mohm = insulationMohm;
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          return;
        }}

        try {{
          meta.textContent = "점검 저장 중...";
          const created = await fetchJson(
            "/api/inspections",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify(payload),
            }}
          );
          let createdWorkOrder = null;
          const autoWorkOrder = !!document.getElementById("inCreateAutoWorkOrder").checked;
          if (autoWorkOrder && summary.abnormal > 0) {{
            const workOrderPriority = (document.getElementById("inCreateWorkOrderPriority").value || "high").trim() || "high";
            const workOrderAssignee = (document.getElementById("inCreateWorkOrderAssignee").value || "").trim();
            const descriptionLines = [
              "자동 생성: OPS " + taskType + " 이상 항목 조치",
              "업무구분: " + taskType,
              "설비: " + equipment,
              "설비코드: " + (equipmentCode || "-"),
              "체크리스트세트: " + (checklistSetLabel || checklistSetId || "-"),
              "OPS코드: " + (selectedOpsCodeValue || "-"),
              "QR설비ID: " + (selectedQrId || "-"),
              "이상 항목 수: " + String(summary.abnormal),
              "점검ID: " + String(created.id),
            ];
            abnormalRows.slice(0, 10).forEach((row, idx) => {{
              const actionLabel = row.action ? (" / 조치: " + row.action) : "";
              descriptionLines.push(String(idx + 1) + ". " + row.item + actionLabel);
            }});
            if (abnormalAction) {{
              descriptionLines.push("이상조치 등록: " + abnormalAction);
            }}
            const workOrderPayload = {{
              title: "[" + taskType + "] 이상조치 필요 - " + equipment,
              description: descriptionLines.join("\\n"),
              site: site,
              location: location,
              priority: workOrderPriority,
              inspection_id: created.id,
              reporter: inspector,
            }};
            if (workOrderAssignee) {{
              workOrderPayload.assignee = workOrderAssignee;
            }}
            createdWorkOrder = await fetchJson(
              "/api/work-orders",
              true,
              {{
                method: "POST",
                headers: {{ "Content-Type": "application/json" }},
                body: JSON.stringify(workOrderPayload),
              }}
            );
          }}
          let uploadedEvidenceCount = 0;
          const evidenceUploadErrors = [];
          if (photoFiles.length > 0) {{
            for (const photoFile of photoFiles) {{
              const formData = new FormData();
              formData.append("file", photoFile);
              formData.append("note", photoNote);
              try {{
                const uploadedEvidence = await fetchJson(
                  "/api/inspections/" + encodeURIComponent(String(created.id)) + "/evidence",
                  true,
                  {{
                    method: "POST",
                    body: formData,
                  }}
                );
                if (uploadedEvidence && uploadedEvidence.id) {{
                  uploadedEvidenceCount += 1;
                }}
              }} catch (err) {{
                const fileName = String((photoFile && photoFile.name) || "unknown-file");
                evidenceUploadErrors.push(fileName + ": " + err.message);
              }}
            }}
            const photoFilesNode = document.getElementById("inCreatePhotoFiles");
            if (photoFilesNode) {{
              photoFilesNode.value = "";
            }}
          }}
          const inSiteNode = document.getElementById("inSite");
          if (inSiteNode && !(inSiteNode.value || "").trim()) {{
            inSiteNode.value = site;
          }}
          const inEvidenceInspectionIdNode = document.getElementById("inEvidenceInspectionId");
          if (inEvidenceInspectionIdNode) {{
            inEvidenceInspectionIdNode.value = String(created.id);
          }}
          const workOrderText = createdWorkOrder ? (" | WO #" + String(createdWorkOrder.id) + " 자동 생성") : "";
          const evidenceText = photoFiles.length > 0
            ? (" | 사진증빙 " + String(uploadedEvidenceCount) + "/" + String(photoFiles.length) + "건 업로드")
            : "";
          const evidenceErrorText = evidenceUploadErrors.length > 0
            ? (" | 업로드실패 " + String(evidenceUploadErrors.length) + "건")
            : "";
          meta.textContent = "성공: 점검 #" + String(created.id) + " 저장" + workOrderText + evidenceText + evidenceErrorText;
          await runInspections();
          if (inEvidenceInspectionIdNode) {{
            await runInspectionEvidenceList().catch(() => null);
          }}
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      function renderInspectionEvidenceTable(rows) {{
        if (!Array.isArray(rows) || rows.length === 0) {{
          return renderEmpty("증빙 파일이 없습니다.");
        }}
        const body = rows.map((row) => {{
          const evidenceId = row.id ?? "";
          const downloadHref = "/api/inspections/evidence/" + encodeURIComponent(String(evidenceId)) + "/download";
          return (
            "<tr>"
              + "<td>" + escapeHtml(evidenceId) + "</td>"
              + "<td>" + escapeHtml(row.file_name ?? "") + "</td>"
              + "<td>" + escapeHtml(row.file_size ?? "") + "</td>"
              + "<td>" + escapeHtml(row.content_type ?? "") + "</td>"
              + "<td>" + escapeHtml(row.uploaded_by ?? "") + "</td>"
              + "<td>" + escapeHtml(row.uploaded_at ?? "") + "</td>"
              + "<td>" + escapeHtml(row.note ?? "") + "</td>"
              + "<td>" + escapeHtml(row.sha256 ?? "") + "</td>"
              + '<td><a href="' + downloadHref + '" target="_blank" rel="noopener">download</a></td>'
            + "</tr>"
          );
        }}).join("");
        return (
          '<div class="table-wrap"><table><thead><tr>'
          + "<th>ID</th><th>File</th><th>Size</th><th>Type</th><th>Uploaded By</th><th>Uploaded At</th><th>Note</th><th>SHA256</th><th>Download</th>"
          + "</tr></thead><tbody>" + body + "</tbody></table></div>"
        );
      }}

      async function runInspectionEvidenceList() {{
        const meta = document.getElementById("inspectionEvidenceMeta");
        const table = document.getElementById("inspectionEvidenceTable");
        const inspectionIdRaw = (document.getElementById("inEvidenceInspectionId").value || "").trim();
        const inspectionId = Number(inspectionIdRaw);
        if (!inspectionIdRaw || !Number.isFinite(inspectionId) || inspectionId <= 0) {{
          meta.textContent = "inspection_id를 입력하세요.";
          table.innerHTML = renderEmpty("유효한 inspection_id가 필요합니다.");
          return;
        }}
        const path = "/api/inspections/" + encodeURIComponent(String(Math.trunc(inspectionId))) + "/evidence";
        try {{
          meta.textContent = "조회 중... " + path;
          const rows = await fetchJson(path, true);
          const items = Array.isArray(rows) ? rows : [];
          meta.textContent = "성공: " + path + " | count=" + String(items.length);
          table.innerHTML = renderInspectionEvidenceTable(items);
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          table.innerHTML = renderEmpty(err.message);
        }}
      }}

      async function runInspectionImportValidation() {{
        const path = "/api/ops/inspections/checklists/import-validation";
        const meta = document.getElementById("inspectionImportValidationMeta");
        const summaryNode = document.getElementById("inspectionImportValidationSummary");
        const table = document.getElementById("inspectionImportValidationTable");
        const suggestionsNode = document.getElementById("inspectionImportValidationSuggestions");
        try {{
          meta.textContent = "조회 중... " + path;
          const data = await fetchJson(path, true);
          const summary = data && typeof data.summary === "object" && data.summary ? data.summary : {{}};
          const issues = Array.isArray(data.issues) ? data.issues : [];
          const suggestions = Array.isArray(data.suggestions) ? data.suggestions : [];
          meta.textContent =
            "성공: " + path
            + " | status=" + String(data.status || "-")
            + " | errors=" + String(summary.error_count || 0)
            + " | warnings=" + String(summary.warning_count || 0)
            + " | issue_buckets=" + String(summary.issue_bucket_count || 0);
          const summaryItems = [
            ["Status", String(data.status || "-")],
            ["Checklist Sets", String(summary.checklist_set_count || 0)],
            ["Checklist Items", String(summary.checklist_item_count || 0)],
            ["OPS Codes", String(summary.ops_code_count || 0)],
            ["QR Assets", String(summary.qr_asset_count || 0)],
            ["Error Count", String(summary.error_count || 0)],
            ["Warning Count", String(summary.warning_count || 0)],
            ["Source Exists", String(Boolean(data.source_file_exists)).toUpperCase()],
          ];
          summaryNode.innerHTML = summaryItems.map((item) => (
            '<div class="card"><div class="k">' + escapeHtml(item[0]) + '</div><div class="v">' + escapeHtml(item[1]) + "</div></div>"
          )).join("");
          const rows = issues.map((item) => {{
            const refs = Array.isArray(item.references) ? item.references.join(" | ") : String(item.references || "");
            return {{
              severity: item.severity || "-",
              category: item.category || "-",
              code: item.code || "-",
              count: item.count ?? 0,
              message: item.message || "-",
              references: refs || "-",
            }};
          }});
          table.innerHTML = rows.length > 0
            ? renderTable(rows, [
              {{ key: "severity", label: "Severity" }},
              {{ key: "category", label: "Category" }},
              {{ key: "code", label: "Code" }},
              {{ key: "count", label: "Count" }},
              {{ key: "message", label: "Message" }},
              {{ key: "references", label: "References" }},
            ])
            : renderEmpty("이슈 없음");
          if (suggestions.length > 0) {{
            suggestionsNode.innerHTML = (
              '<div class="table-wrap"><table><thead><tr><th>#</th><th>Suggestion</th></tr></thead><tbody>'
              + suggestions.map((item, idx) => (
                "<tr><td>" + escapeHtml(idx + 1) + "</td><td>" + escapeHtml(item) + "</td></tr>"
              )).join("")
              + "</tbody></table></div>"
            );
          }} else {{
            suggestionsNode.innerHTML = renderEmpty("권고사항 없음");
          }}
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          summaryNode.innerHTML = "";
          table.innerHTML = renderEmpty(err.message);
          suggestionsNode.innerHTML = renderEmpty(err.message);
        }}
      }}

      async function runWorkorders() {{
        const query = buildQuery([
          {{ key: "status", id: "woStatus" }},
          {{ key: "site", id: "woSite" }},
          {{ key: "limit", id: "woLimit" }},
          {{ key: "offset", id: "woOffset" }}
        ]);
        const path = "/api/work-orders" + (query ? "?" + query : "");
        const meta = document.getElementById("workordersMeta");
        const table = document.getElementById("workordersTable");
        try {{
          meta.textContent = "조회 중... " + path;
          const data = await fetchJson(path, true);
          meta.textContent = "성공: " + path + " | count=" + data.length;
          table.innerHTML = renderTable(
            data,
            [
              {{ key: "id", label: "ID" }},
              {{ key: "site", label: "Site" }},
              {{ key: "title", label: "Title" }},
              {{ key: "priority", label: "Priority" }},
              {{ key: "status", label: "Status" }},
              {{ key: "assignee", label: "Assignee" }},
              {{ key: "due_at", label: "Due At" }},
              {{ key: "is_escalated", label: "Escalated" }}
            ]
          );
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          table.innerHTML = renderEmpty(err.message);
        }}
      }}

      async function runInspections() {{
        const query = buildQuery([
          {{ key: "site", id: "inSite" }},
          {{ key: "limit", id: "inLimit" }},
          {{ key: "offset", id: "inOffset" }}
        ]);
        const path = "/api/inspections" + (query ? "?" + query : "");
        const meta = document.getElementById("inspectionsMeta");
        const table = document.getElementById("inspectionsTable");
        try {{
          meta.textContent = "조회 중... " + path;
          const data = await fetchJson(path, true);
          const rows = (Array.isArray(data) ? data : []).map((row) => buildOpsInspectionDisplayRow(row));
          const opsRows = rows.filter((row) => row._ops_record === "yes");
          meta.textContent = "성공: " + path + " | count=" + rows.length + " | ops_format=" + opsRows.length;
          const evidenceInspectionIdNode = document.getElementById("inEvidenceInspectionId");
          if (evidenceInspectionIdNode && rows.length > 0 && !(evidenceInspectionIdNode.value || "").trim()) {{
            evidenceInspectionIdNode.value = String(rows[0].id);
          }}
          table.innerHTML = renderTable(
            rows,
            [
              {{ key: "id", label: "ID" }},
              {{ key: "site", label: "Site" }},
              {{ key: "task_type", label: "업무구분" }},
              {{ key: "equipment", label: "설비" }},
              {{ key: "equipment_code", label: "설비코드" }},
              {{ key: "equipment_location", label: "설비위치" }},
              {{ key: "inspector", label: "Inspector" }},
              {{ key: "result_summary", label: "결과요약" }},
              {{ key: "action", label: "조치" }},
              {{ key: "photos", label: "사진" }},
              {{ key: "risk_level", label: "Risk" }},
              {{ key: "inspected_at", label: "Inspected At" }}
            ]
          );
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          table.innerHTML = renderEmpty(err.message);
        }}
      }}

      function currentMonthLabel() {{
        const now = new Date();
        return String(now.getFullYear()) + "-" + String(now.getMonth() + 1).padStart(2, "0");
      }}

      function parseOptionalNumber(value, fallback) {{
        const raw = String(value || "").trim();
        if (!raw) return fallback;
        const parsed = Number(raw);
        if (!Number.isFinite(parsed)) {{
          throw new Error("숫자 형식이 올바르지 않습니다: " + raw);
        }}
        return parsed;
      }}

      function renderBillingSummaryCards(summary) {{
        if (!summary || typeof summary !== "object") {{
          return "";
        }}
        return [
          ["부과 세대수", summary.statement_count ?? 0],
          ["총 사용량", summary.total_usage ?? 0],
          ["공용요금 합계", summary.common_charge_total ?? 0],
          ["총 부과금액", summary.total_amount ?? 0],
        ].map((item) => (
          '<div class="card status-info"><div class="k">' + escapeHtml(item[0]) + '</div><div class="v">' + escapeHtml(item[1]) + "</div></div>"
        )).join("");
      }}

      async function runBillingUnits() {{
        const meta = document.getElementById("billingUnitsMeta");
        const table = document.getElementById("billingUnitsTable");
        meta.textContent = "세대 조회 중...";
        try {{
          const query = buildQuery([
            {{ key: "site", id: "billingUnitSite" }},
            {{ key: "building", id: "billingUnitBuilding" }},
          ]);
          const rows = await fetchJson("/api/billing/units" + (query ? "?" + query : ""), true);
          meta.textContent = "세대 " + String(rows.length) + "건";
          table.innerHTML = renderTable(rows, [
            {{ key: "site", label: "site" }},
            {{ key: "building", label: "동" }},
            {{ key: "unit_number", label: "호" }},
            {{ key: "occupant_name", label: "세대명" }},
            {{ key: "area_sqm", label: "전용면적" }},
            {{ key: "is_active", label: "활성" }},
          ]);
        }} catch (err) {{
          table.innerHTML = renderEmpty("세대 조회 실패");
          meta.textContent = "조회 실패: " + err.message;
        }}
      }}

      async function runBillingCreateUnit() {{
        const meta = document.getElementById("billingUnitsMeta");
        meta.textContent = "세대 등록 중...";
        try {{
          const payload = {{
            site: (document.getElementById("billingUnitSite").value || "").trim(),
            building: (document.getElementById("billingUnitBuilding").value || "").trim(),
            unit_number: (document.getElementById("billingUnitNumber").value || "").trim(),
            occupant_name: (document.getElementById("billingUnitOccupant").value || "").trim() || null,
            area_sqm: parseOptionalNumber(document.getElementById("billingUnitArea").value, null),
            is_active: true,
          }};
          const created = await fetchJson("/api/billing/units", true, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify(payload),
          }});
          meta.textContent = "세대 등록 완료: " + String(created.building || "") + " " + String(created.unit_number || "");
          await runBillingUnits();
        }} catch (err) {{
          meta.textContent = "등록 실패: " + err.message;
        }}
      }}

      async function runBillingPolicies() {{
        const meta = document.getElementById("billingPoliciesMeta");
        const table = document.getElementById("billingPoliciesTable");
        meta.textContent = "요율 조회 중...";
        try {{
          const query = buildQuery([
            {{ key: "site", id: "billingPolicySite" }},
            {{ key: "utility_type", id: "billingPolicyType" }},
          ]);
          const rows = await fetchJson("/api/billing/rate-policies" + (query ? "?" + query : ""), true);
          meta.textContent = "요율 정책 " + String(rows.length) + "건";
          table.innerHTML = renderTable(rows, [
            {{ key: "site", label: "site" }},
            {{ key: "utility_type", label: "유틸리티" }},
            {{ key: "effective_month", label: "적용월" }},
            {{ key: "basic_fee", label: "기본요금" }},
            {{ key: "unit_rate", label: "사용량 단가" }},
            {{ key: "sewage_rate_per_unit", label: "하수도 단가" }},
            {{ key: "vat_rate", label: "부가세율" }},
          ]);
        }} catch (err) {{
          table.innerHTML = renderEmpty("요율 조회 실패");
          meta.textContent = "조회 실패: " + err.message;
        }}
      }}

      async function runBillingCreatePolicy() {{
        const meta = document.getElementById("billingPoliciesMeta");
        meta.textContent = "요율 저장 중...";
        try {{
          const tiersText = (document.getElementById("billingPolicyTiersJson").value || "").trim();
          let tiers = [];
          if (tiersText) {{
            tiers = JSON.parse(tiersText);
            if (!Array.isArray(tiers)) {{
              throw new Error("누진단계 JSON은 배열이어야 합니다.");
            }}
          }}
          const payload = {{
            site: (document.getElementById("billingPolicySite").value || "").trim(),
            utility_type: (document.getElementById("billingPolicyType").value || "").trim(),
            effective_month: (document.getElementById("billingPolicyMonth").value || "").trim(),
            basic_fee: parseOptionalNumber(document.getElementById("billingPolicyBasicFee").value, 0),
            unit_rate: parseOptionalNumber(document.getElementById("billingPolicyUnitRate").value, 0),
            sewage_rate_per_unit: parseOptionalNumber(document.getElementById("billingPolicySewageRate").value, 0),
            service_fee: parseOptionalNumber(document.getElementById("billingPolicyServiceFee").value, 0),
            vat_rate: parseOptionalNumber(document.getElementById("billingPolicyVatRate").value, 0.1),
            tiers,
            notes: (document.getElementById("billingPolicyNotes").value || "").trim(),
          }};
          const created = await fetchJson("/api/billing/rate-policies", true, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify(payload),
          }});
          meta.textContent = "요율 저장 완료: " + String(created.utility_type || "") + " / " + String(created.effective_month || "");
          await runBillingPolicies();
        }} catch (err) {{
          meta.textContent = "저장 실패: " + err.message;
        }}
      }}

      async function runBillingCommonCharges() {{
        const meta = document.getElementById("billingCommonMeta");
        const table = document.getElementById("billingCommonTable");
        meta.textContent = "공용요금 조회 중...";
        try {{
          const query = buildQuery([
            {{ key: "site", id: "billingCommonSite" }},
            {{ key: "billing_month", id: "billingCommonMonth" }},
            {{ key: "utility_type", id: "billingCommonType" }},
          ]);
          const rows = await fetchJson("/api/billing/common-charges" + (query ? "?" + query : ""), true);
          const total = rows.reduce((sum, row) => sum + Number(row.amount || 0), 0);
          meta.textContent = "공용요금 " + String(rows.length) + "건 | 합계 " + String(total.toFixed(2));
          table.innerHTML = renderTable(rows, [
            {{ key: "site", label: "site" }},
            {{ key: "billing_month", label: "부과월" }},
            {{ key: "utility_type", label: "유틸리티" }},
            {{ key: "charge_category", label: "항목" }},
            {{ key: "amount", label: "금액" }},
            {{ key: "notes", label: "비고" }},
          ]);
        }} catch (err) {{
          table.innerHTML = renderEmpty("공용요금 조회 실패");
          meta.textContent = "조회 실패: " + err.message;
        }}
      }}

      async function runBillingCreateCommonCharge() {{
        const meta = document.getElementById("billingCommonMeta");
        meta.textContent = "공용요금 저장 중...";
        try {{
          const payload = {{
            site: (document.getElementById("billingCommonSite").value || "").trim(),
            billing_month: (document.getElementById("billingCommonMonth").value || "").trim(),
            utility_type: (document.getElementById("billingCommonType").value || "").trim(),
            charge_category: (document.getElementById("billingCommonCategory").value || "").trim(),
            amount: parseOptionalNumber(document.getElementById("billingCommonAmount").value, 0),
            notes: (document.getElementById("billingCommonNotes").value || "").trim(),
          }};
          const created = await fetchJson("/api/billing/common-charges", true, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify(payload),
          }});
          meta.textContent = "공용요금 저장 완료: " + String(created.charge_category || "") + " / " + String(created.amount || 0);
          await runBillingCommonCharges();
        }} catch (err) {{
          meta.textContent = "저장 실패: " + err.message;
        }}
      }}

      async function runBillingReadings() {{
        const meta = document.getElementById("billingReadingsMeta");
        const table = document.getElementById("billingReadingsTable");
        meta.textContent = "검침 조회 중...";
        try {{
          const query = buildQuery([
            {{ key: "site", id: "billingReadingSite" }},
            {{ key: "building", id: "billingReadingBuilding" }},
            {{ key: "utility_type", id: "billingReadingType" }},
            {{ key: "reading_month", id: "billingReadingMonth" }},
          ]);
          const rows = await fetchJson("/api/billing/meter-readings" + (query ? "?" + query : ""), true);
          meta.textContent = "검침 " + String(rows.length) + "건";
          table.innerHTML = renderTable(rows, [
            {{ key: "site", label: "site" }},
            {{ key: "building", label: "동" }},
            {{ key: "unit_number", label: "호" }},
            {{ key: "utility_type", label: "유틸리티" }},
            {{ key: "reading_month", label: "검침월" }},
            {{ key: "usage", label: "사용량" }},
            {{ key: "reader_name", label: "검침자" }},
          ]);
        }} catch (err) {{
          table.innerHTML = renderEmpty("검침 조회 실패");
          meta.textContent = "조회 실패: " + err.message;
        }}
      }}

      async function runBillingCreateReading() {{
        const meta = document.getElementById("billingReadingsMeta");
        meta.textContent = "검침 저장 중...";
        try {{
          const payload = {{
            site: (document.getElementById("billingReadingSite").value || "").trim(),
            building: (document.getElementById("billingReadingBuilding").value || "").trim(),
            unit_number: (document.getElementById("billingReadingUnitNumber").value || "").trim(),
            utility_type: (document.getElementById("billingReadingType").value || "").trim(),
            reading_month: (document.getElementById("billingReadingMonth").value || "").trim(),
            previous_reading: parseOptionalNumber(document.getElementById("billingReadingPrevious").value, 0),
            current_reading: parseOptionalNumber(document.getElementById("billingReadingCurrent").value, 0),
            reader_name: (document.getElementById("billingReadingReader").value || "").trim(),
            notes: (document.getElementById("billingReadingNotes").value || "").trim(),
          }};
          const created = await fetchJson("/api/billing/meter-readings", true, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify(payload),
          }});
          meta.textContent = "검침 저장 완료: " + String(created.building || "") + " " + String(created.unit_number || "") + " / 사용량 " + String(created.usage || 0);
          await runBillingReadings();
        }} catch (err) {{
          meta.textContent = "저장 실패: " + err.message;
        }}
      }}

      async function runBillingGenerate() {{
        const meta = document.getElementById("billingRunMeta");
        const summaryNode = document.getElementById("billingRunSummary");
        const table = document.getElementById("billingStatementsTable");
        meta.textContent = "월 부과 생성 중...";
        summaryNode.innerHTML = "";
        try {{
          const payload = {{
            site: (document.getElementById("billingRunSite").value || "").trim(),
            billing_month: (document.getElementById("billingRunMonth").value || "").trim(),
            utility_type: (document.getElementById("billingRunType").value || "").trim(),
            replace_existing: Boolean(document.getElementById("billingReplaceExisting").checked),
          }};
          const result = await fetchJson("/api/billing/runs/generate", true, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify(payload),
          }});
          meta.textContent =
            "월 부과 생성 완료 | run_id="
            + String(result.run && result.run.id ? result.run.id : "-")
            + " | 세대 "
            + String(result.summary && result.summary.statement_count ? result.summary.statement_count : 0)
            + "건";
          summaryNode.innerHTML = renderBillingSummaryCards(result.summary || {{}});
          table.innerHTML = renderTable(result.statements || [], [
            {{ key: "building", label: "동" }},
            {{ key: "unit_number", label: "호" }},
            {{ key: "utility_type", label: "유틸리티" }},
            {{ key: "usage", label: "사용량" }},
            {{ key: "basic_fee", label: "기본요금" }},
            {{ key: "usage_fee", label: "사용요금" }},
            {{ key: "common_fee", label: "공용요금 배부" }},
            {{ key: "sewage_fee", label: "하수도" }},
            {{ key: "vat_amount", label: "부가세" }},
            {{ key: "total_amount", label: "합계" }},
          ]);
        }} catch (err) {{
          table.innerHTML = renderEmpty("월 부과 생성 실패");
          meta.textContent = "생성 실패: " + err.message;
        }}
      }}

      async function runBillingStatements() {{
        const meta = document.getElementById("billingRunMeta");
        const table = document.getElementById("billingStatementsTable");
        meta.textContent = "부과내역 조회 중...";
        try {{
          const query = buildQuery([
            {{ key: "site", id: "billingStatementsSite" }},
            {{ key: "billing_month", id: "billingStatementsMonth" }},
            {{ key: "utility_type", id: "billingStatementsType" }},
            {{ key: "building", id: "billingStatementsBuilding" }},
          ]);
          const rows = await fetchJson("/api/billing/statements" + (query ? "?" + query : ""), true);
          meta.textContent = "부과내역 " + String(rows.length) + "건";
          table.innerHTML = renderTable(rows, [
            {{ key: "site", label: "site" }},
            {{ key: "building", label: "동" }},
            {{ key: "unit_number", label: "호" }},
            {{ key: "utility_type", label: "유틸리티" }},
            {{ key: "billing_month", label: "부과월" }},
            {{ key: "usage", label: "사용량" }},
            {{ key: "usage_fee", label: "사용요금" }},
            {{ key: "common_fee", label: "공용요금 배부" }},
            {{ key: "total_amount", label: "합계" }},
          ]);
        }} catch (err) {{
          table.innerHTML = renderEmpty("부과내역 조회 실패");
          meta.textContent = "조회 실패: " + err.message;
        }}
      }}

      function fillOfficialDocumentForm(doc) {{
        document.getElementById("officialDocId").value = doc.id || "";
        document.getElementById("officialDocSite").value = doc.site || "";
        document.getElementById("officialDocOrganization").value = doc.organization || "";
        document.getElementById("officialDocOrganizationCode").value = doc.organization_code || "";
        document.getElementById("officialDocRegistryNumber").value = doc.registry_number || "";
        document.getElementById("officialDocNumber").value = doc.document_number || "";
        document.getElementById("officialDocTitle").value = doc.title || "";
        document.getElementById("officialDocType").value = doc.document_type || "general";
        document.getElementById("officialDocPriority").value = doc.priority || "medium";
        document.getElementById("officialDocStatus").value = doc.status || "received";
        document.getElementById("officialDocReceivedAt").value = formatDateTimeLocal(doc.received_at);
        document.getElementById("officialDocDueAt").value = formatDateTimeLocal(doc.due_at);
        document.getElementById("officialDocInspectionId").value = doc.linked_inspection_id || "";
        document.getElementById("officialDocWorkOrderId").value = doc.linked_work_order_id || "";
        document.getElementById("officialDocRequiredAction").value = doc.required_action || "";
        document.getElementById("officialDocSummary").value = doc.summary || "";
        document.getElementById("officialDocCloseTitle").value = doc.closed_report_title || "";
        document.getElementById("officialDocClosureSummary").value = doc.closure_summary || "";
        document.getElementById("officialDocClosureResult").value = doc.closure_result || "";
        document.getElementById("officialAttachmentDocId").value = doc.id || "";
      }}

      function updateOfficialReportLinks() {{
        const monthlyQuery = buildQuery([
          {{ key: "site", id: "officialReportSite" }},
          {{ key: "month", id: "officialReportMonth" }},
        ]);
        const annualQuery = buildQuery([
          {{ key: "site", id: "officialReportSite" }},
          {{ key: "year", id: "officialReportYear" }},
        ]);
        document.getElementById("officialReportMonthlyPrintLink").setAttribute("href", "/reports/official-documents/monthly/print" + (monthlyQuery ? "?" + monthlyQuery : ""));
        document.getElementById("officialReportMonthlyCsvLink").setAttribute("href", "/api/reports/official-documents/monthly/csv" + (monthlyQuery ? "?" + monthlyQuery : ""));
        document.getElementById("officialReportAnnualPrintLink").setAttribute("href", "/reports/official-documents/annual/print" + (annualQuery ? "?" + annualQuery : ""));
        document.getElementById("officialReportAnnualCsvLink").setAttribute("href", "/api/reports/official-documents/annual/csv" + (annualQuery ? "?" + annualQuery : ""));
        document.getElementById("officialReportIntegratedPrintLink").setAttribute("href", "/reports/monthly/integrated/print" + (monthlyQuery ? "?" + monthlyQuery : ""));
        document.getElementById("officialReportIntegratedCsvLink").setAttribute("href", "/api/reports/monthly/integrated/csv" + (monthlyQuery ? "?" + monthlyQuery : ""));
        document.getElementById("officialReportIntegratedPdfLink").setAttribute("href", "/api/reports/monthly/integrated/pdf" + (monthlyQuery ? "?" + monthlyQuery : ""));
        document.getElementById("officialReportIntegratedAnnualPrintLink").setAttribute("href", "/reports/annual/integrated/print" + (annualQuery ? "?" + annualQuery : ""));
        document.getElementById("officialReportIntegratedAnnualCsvLink").setAttribute("href", "/api/reports/annual/integrated/csv" + (annualQuery ? "?" + annualQuery : ""));
        document.getElementById("officialReportIntegratedAnnualPdfLink").setAttribute("href", "/api/reports/annual/integrated/pdf" + (annualQuery ? "?" + annualQuery : ""));
      }}

      function updateOfficialBulkExportLinks() {{
        const query = buildQuery([
          {{ key: "site", id: "officialExportSite" }},
          {{ key: "organization", id: "officialExportOrganization" }},
          {{ key: "status", id: "officialExportStatus" }},
          {{ key: "month", id: "officialExportMonth" }},
          {{ key: "year", id: "officialExportYear" }},
        ]);
        const suffix = query ? "?" + query : "";
        document.getElementById("officialAttachmentZipLink").setAttribute("href", "/api/official-documents/attachments/zip" + suffix);
        document.getElementById("officialRegistryCsvLink").setAttribute("href", "/api/official-documents/registry/csv" + suffix);
      }}

      function renderOfficialReport(report) {{
        const summary = document.getElementById("officialReportSummary");
        const entries = document.getElementById("officialReportEntries");
        const summaryItems = [
          ["Period", report.period_label],
          ["Site", report.site || "ALL"],
          ["Total Documents", report.total_documents || 0],
          ["Closed In Period", report.closed_in_period || 0],
          ["Open Documents", report.open_documents || 0],
          ["Overdue Open", report.overdue_open_documents || 0],
          ["Linked Inspections", report.linked_inspection_documents || 0],
          ["Linked Work Orders", report.linked_work_order_documents || 0],
        ];
        summary.innerHTML = summaryItems.map((item) => (
          '<div class="card"><div class="k">' + escapeHtml(item[0]) + '</div><div class="v">' + escapeHtml(item[1]) + "</div></div>"
        )).join("");
        entries.innerHTML = renderTable(report.entries || [], [
          {{ key: "id", label: "ID" }},
          {{ key: "organization", label: "기관" }},
          {{ key: "registry_number", label: "접수대장" }},
          {{ key: "document_number", label: "공문번호" }},
          {{ key: "title", label: "제목" }},
          {{ key: "status", label: "상태" }},
          {{ key: "priority", label: "우선순위" }},
          {{ key: "linked_inspection_id", label: "점검" }},
          {{ key: "linked_work_order_id", label: "작업지시" }},
          {{ key: "closed_report_title", label: "종결제목" }},
          {{ key: "attachment_count", label: "첨부" }},
          {{ key: "closed_at", label: "종결일시" }},
        ]);
      }}

      function renderOfficialAttachmentTable(rows) {{
        if (!Array.isArray(rows) || rows.length === 0) {{
          return renderEmpty("첨부 데이터 없음");
        }}
        return '<div class="table-wrap"><table><thead><tr>'
          + '<th>ID</th><th>파일명</th><th>유형</th><th>크기</th><th>업로드</th><th>메모</th><th>다운로드</th>'
          + '</tr></thead><tbody>'
          + rows.map((row) => (
            '<tr>'
            + '<td>' + escapeHtml(row.id ?? "") + '</td>'
            + '<td>' + escapeHtml(row.file_name ?? "") + '</td>'
            + '<td>' + escapeHtml(row.content_type ?? "") + '</td>'
            + '<td>' + escapeHtml(row.file_size ?? "") + '</td>'
            + '<td>' + escapeHtml(row.uploaded_at ?? "") + '</td>'
            + '<td>' + escapeHtml(row.note ?? "") + '</td>'
            + '<td><a href="/api/official-documents/attachments/' + encodeURIComponent(String(row.id || "")) + '/download" target="_blank" rel="noopener">다운로드</a></td>'
            + '</tr>'
          )).join("")
          + '</tbody></table></div>';
      }}

      function renderOfficialOverdueSummary(data) {{
        const summary = document.getElementById("officialOverdueSummary");
        const items = [
          ["Checked At", data.checked_at || ""],
          ["Candidates", data.candidate_count || 0],
          ["Created Work Orders", data.work_order_created_count || 0],
          ["Existing Linked", data.linked_existing_work_order_count || 0],
          ["Alert Escalated", (data.alert_run && data.alert_run.escalated_count) || 0],
        ];
        summary.innerHTML = items.map((item) => (
          '<div class="card"><div class="k">' + escapeHtml(item[0]) + '</div><div class="v">' + escapeHtml(item[1]) + '</div></div>'
        )).join("");
      }}

      function renderIntegratedReport(report) {{
        const summary = document.getElementById("officialIntegratedReportSummary");
        const raw = document.getElementById("officialIntegratedReportRaw");
        const cards = [
          ["Period", report.period_label || report.month || report.year || ""],
          ["Period Type", report.period_type || "monthly"],
          ["Site", report.site || "ALL"],
          ["Inspections", (report.inspections && report.inspections.total) || 0],
          ["Work Orders", (report.work_orders && report.work_orders.total) || 0],
          ["Official Docs Closed", (report.official_documents && report.official_documents.closed_in_period) || 0],
          ["Billing Total", (report.billing && report.billing.total_amount) || 0],
          ["Merged Sections", ((report.merged_sections || []).length ? report.merged_sections.join(", ") : "-")],
        ];
        summary.innerHTML = cards.map((item) => (
          '<div class="card"><div class="k">' + escapeHtml(item[0]) + '</div><div class="v">' + escapeHtml(item[1]) + '</div></div>'
        )).join("");
        raw.textContent = JSON.stringify(report, null, 2);
      }}

      async function runOfficialDocuments() {{
        const meta = document.getElementById("officialDocsMeta");
        const table = document.getElementById("officialDocsTable");
        meta.textContent = "공문 목록 조회 중...";
        try {{
          const query = buildQuery([
            {{ key: "site", id: "officialDocsSite" }},
            {{ key: "organization", id: "officialDocsOrganization" }},
            {{ key: "status", id: "officialDocsStatus" }},
            {{ key: "limit", id: "officialDocsLimit" }},
            {{ key: "offset", id: "officialDocsOffset" }},
          ]);
          const rows = await fetchJson("/api/official-documents" + (query ? "?" + query : ""), true);
          meta.textContent = "공문 " + String(rows.length) + "건";
          table.innerHTML = renderTable(rows, [
            {{ key: "id", label: "ID" }},
            {{ key: "site", label: "site" }},
            {{ key: "organization", label: "기관" }},
            {{ key: "registry_number", label: "접수대장" }},
            {{ key: "document_number", label: "공문번호" }},
            {{ key: "title", label: "제목" }},
            {{ key: "status", label: "상태" }},
            {{ key: "priority", label: "우선순위" }},
            {{ key: "due_at", label: "기한" }},
            {{ key: "linked_inspection_id", label: "점검" }},
            {{ key: "linked_work_order_id", label: "작업지시" }},
            {{ key: "attachment_count", label: "첨부" }},
          ]);
        }} catch (err) {{
          meta.textContent = "조회 실패: " + err.message;
          table.innerHTML = renderEmpty("공문 목록 조회 실패");
        }}
      }}

      async function runOfficialDocumentCreate() {{
        const meta = document.getElementById("officialDocEditMeta");
        try {{
          const payload = {{
            site: (document.getElementById("officialDocSite").value || "").trim(),
            organization: (document.getElementById("officialDocOrganization").value || "").trim(),
            organization_code: (document.getElementById("officialDocOrganizationCode").value || "").trim() || null,
            registry_number: (document.getElementById("officialDocRegistryNumber").value || "").trim() || null,
            document_number: (document.getElementById("officialDocNumber").value || "").trim() || null,
            title: (document.getElementById("officialDocTitle").value || "").trim(),
            document_type: (document.getElementById("officialDocType").value || "").trim() || "general",
            priority: (document.getElementById("officialDocPriority").value || "medium").trim(),
            received_at: new Date(document.getElementById("officialDocReceivedAt").value || "").toISOString(),
            due_at: (document.getElementById("officialDocDueAt").value || "").trim()
              ? new Date(document.getElementById("officialDocDueAt").value).toISOString()
              : null,
            required_action: (document.getElementById("officialDocRequiredAction").value || "").trim(),
            summary: (document.getElementById("officialDocSummary").value || "").trim(),
            linked_inspection_id: parseOptionalNumber(document.getElementById("officialDocInspectionId").value, null),
            linked_work_order_id: parseOptionalNumber(document.getElementById("officialDocWorkOrderId").value, null),
          }};
          meta.textContent = "등록 중...";
          const created = await fetchJson("/api/official-documents", true, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify(payload),
          }});
          fillOfficialDocumentForm(created);
          meta.textContent = "등록 성공: 공문 ID " + String(created.id);
          await runOfficialDocuments();
        }} catch (err) {{
          meta.textContent = "등록 실패: " + err.message;
        }}
      }}

      async function runOfficialDocumentLoad() {{
        const meta = document.getElementById("officialDocEditMeta");
        try {{
          const idValue = Number(document.getElementById("officialDocId").value || "");
          if (!Number.isFinite(idValue) || idValue <= 0) {{
            throw new Error("공문 ID가 필요합니다.");
          }}
          meta.textContent = "조회 중...";
          const doc = await fetchJson("/api/official-documents/" + encodeURIComponent(String(Math.trunc(idValue))), true);
          fillOfficialDocumentForm(doc);
          meta.textContent = "조회 성공: 공문 ID " + String(doc.id);
        }} catch (err) {{
          meta.textContent = "조회 실패: " + err.message;
        }}
      }}

      async function runOfficialDocumentUpdate() {{
        const meta = document.getElementById("officialDocEditMeta");
        try {{
          const idValue = Number(document.getElementById("officialDocId").value || "");
          if (!Number.isFinite(idValue) || idValue <= 0) {{
            throw new Error("공문 ID가 필요합니다.");
          }}
          const payload = {{
            organization: (document.getElementById("officialDocOrganization").value || "").trim(),
            organization_code: (document.getElementById("officialDocOrganizationCode").value || "").trim() || null,
            registry_number: (document.getElementById("officialDocRegistryNumber").value || "").trim() || null,
            document_number: (document.getElementById("officialDocNumber").value || "").trim() || null,
            title: (document.getElementById("officialDocTitle").value || "").trim(),
            document_type: (document.getElementById("officialDocType").value || "").trim() || "general",
            status: (document.getElementById("officialDocStatus").value || "received").trim(),
            priority: (document.getElementById("officialDocPriority").value || "medium").trim(),
            received_at: new Date(document.getElementById("officialDocReceivedAt").value || "").toISOString(),
            due_at: (document.getElementById("officialDocDueAt").value || "").trim()
              ? new Date(document.getElementById("officialDocDueAt").value).toISOString()
              : null,
            required_action: (document.getElementById("officialDocRequiredAction").value || "").trim(),
            summary: (document.getElementById("officialDocSummary").value || "").trim(),
            linked_inspection_id: parseOptionalNumber(document.getElementById("officialDocInspectionId").value, null),
            linked_work_order_id: parseOptionalNumber(document.getElementById("officialDocWorkOrderId").value, null),
          }};
          meta.textContent = "수정 중...";
          const doc = await fetchJson("/api/official-documents/" + encodeURIComponent(String(Math.trunc(idValue))), true, {{
            method: "PATCH",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify(payload),
          }});
          fillOfficialDocumentForm(doc);
          meta.textContent = "수정 성공: 공문 ID " + String(doc.id);
          await runOfficialDocuments();
        }} catch (err) {{
          meta.textContent = "수정 실패: " + err.message;
        }}
      }}

      async function runOfficialDocumentClose() {{
        const meta = document.getElementById("officialDocEditMeta");
        try {{
          const idValue = Number(document.getElementById("officialDocId").value || "");
          if (!Number.isFinite(idValue) || idValue <= 0) {{
            throw new Error("공문 ID가 필요합니다.");
          }}
          const payload = {{
            closed_report_title: (document.getElementById("officialDocCloseTitle").value || "").trim(),
            closure_summary: (document.getElementById("officialDocClosureSummary").value || "").trim(),
            closure_result: (document.getElementById("officialDocClosureResult").value || "").trim(),
          }};
          meta.textContent = "종결 중...";
          const doc = await fetchJson("/api/official-documents/" + encodeURIComponent(String(Math.trunc(idValue))) + "/close", true, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify(payload),
          }});
          fillOfficialDocumentForm(doc);
          meta.textContent = "종결 성공: 공문 ID " + String(doc.id);
          await runOfficialDocuments();
        }} catch (err) {{
          meta.textContent = "종결 실패: " + err.message;
        }}
      }}

      async function runOfficialAttachmentList() {{
        const meta = document.getElementById("officialAttachmentMeta");
        const table = document.getElementById("officialAttachmentTable");
        try {{
          const idValue = Number(document.getElementById("officialAttachmentDocId").value || "");
          if (!Number.isFinite(idValue) || idValue <= 0) {{
            throw new Error("공문 ID가 필요합니다.");
          }}
          meta.textContent = "첨부 목록 조회 중...";
          const rows = await fetchJson("/api/official-documents/" + encodeURIComponent(String(Math.trunc(idValue))) + "/attachments", true);
          meta.textContent = "첨부 " + String(rows.length) + "건";
          table.innerHTML = renderOfficialAttachmentTable(rows);
        }} catch (err) {{
          meta.textContent = "첨부 목록 조회 실패: " + err.message;
          table.innerHTML = renderEmpty("첨부 목록 조회 실패");
        }}
      }}

      async function runOfficialAttachmentUpload() {{
        const meta = document.getElementById("officialAttachmentMeta");
        try {{
          const idValue = Number(document.getElementById("officialAttachmentDocId").value || "");
          if (!Number.isFinite(idValue) || idValue <= 0) {{
            throw new Error("공문 ID가 필요합니다.");
          }}
          const fileInput = document.getElementById("officialAttachmentFile");
          if (!fileInput.files || !fileInput.files.length) {{
            throw new Error("첨부 파일을 선택하세요.");
          }}
          const formData = new FormData();
          formData.append("file", fileInput.files[0]);
          formData.append("note", (document.getElementById("officialAttachmentNote").value || "").trim());
          meta.textContent = "첨부 업로드 중...";
          await fetchJson("/api/official-documents/" + encodeURIComponent(String(Math.trunc(idValue))) + "/attachments", true, {{
            method: "POST",
            body: formData,
          }});
          meta.textContent = "첨부 업로드 성공";
          fileInput.value = "";
          await Promise.all([runOfficialAttachmentList(), runOfficialDocuments()]);
        }} catch (err) {{
          meta.textContent = "첨부 업로드 실패: " + err.message;
        }}
      }}

      async function runOfficialOverdueSync() {{
        const meta = document.getElementById("officialOverdueMeta");
        try {{
          const query = buildQuery([
            {{ key: "site", id: "officialOverdueSite" }},
            {{ key: "limit", id: "officialOverdueLimit" }},
            {{ key: "dry_run", id: "officialOverdueDryRun" }},
          ]);
          meta.textContent = "기한초과 자동화 실행 중...";
          const result = await fetchJson("/api/official-documents/overdue/run" + (query ? "?" + query : ""), true, {{
            method: "POST",
          }});
          meta.textContent = "자동화 성공: 후보 " + String(result.candidate_count || 0) + "건";
          renderOfficialOverdueSummary(result);
          await runOfficialDocuments();
        }} catch (err) {{
          meta.textContent = "자동화 실패: " + err.message;
          document.getElementById("officialOverdueSummary").innerHTML = "";
        }}
      }}

      async function runOfficialDocumentMonthlyReport() {{
        const meta = document.getElementById("officialReportMeta");
        updateOfficialReportLinks();
        try {{
          const query = buildQuery([
            {{ key: "site", id: "officialReportSite" }},
            {{ key: "month", id: "officialReportMonth" }},
          ]);
          const report = await fetchJson("/api/reports/official-documents/monthly" + (query ? "?" + query : ""), true);
          meta.textContent = "월 보고서 성공: " + String(report.period_label);
          renderOfficialReport(report);
        }} catch (err) {{
          meta.textContent = "월 보고서 실패: " + err.message;
          document.getElementById("officialReportSummary").innerHTML = "";
          document.getElementById("officialReportEntries").innerHTML = renderEmpty("월 보고서 조회 실패");
        }}
      }}

      async function runOfficialDocumentAnnualReport() {{
        const meta = document.getElementById("officialReportMeta");
        updateOfficialReportLinks();
        try {{
          const query = buildQuery([
            {{ key: "site", id: "officialReportSite" }},
            {{ key: "year", id: "officialReportYear" }},
          ]);
          const report = await fetchJson("/api/reports/official-documents/annual" + (query ? "?" + query : ""), true);
          meta.textContent = "연차 보고서 성공: " + String(report.period_label);
          renderOfficialReport(report);
        }} catch (err) {{
          meta.textContent = "연차 보고서 실패: " + err.message;
          document.getElementById("officialReportSummary").innerHTML = "";
          document.getElementById("officialReportEntries").innerHTML = renderEmpty("연차 보고서 조회 실패");
        }}
      }}

      async function runOfficialIntegratedMonthlyReport() {{
        const meta = document.getElementById("officialReportMeta");
        updateOfficialReportLinks();
        try {{
          const query = buildQuery([
            {{ key: "site", id: "officialReportSite" }},
            {{ key: "month", id: "officialReportMonth" }},
          ]);
          const report = await fetchJson("/api/reports/monthly/integrated" + (query ? "?" + query : ""), true);
          meta.textContent = "통합 월간보고서 성공: " + String(report.month || "");
          renderIntegratedReport(report);
        }} catch (err) {{
          meta.textContent = "통합 월간보고서 실패: " + err.message;
          document.getElementById("officialIntegratedReportSummary").innerHTML = "";
          document.getElementById("officialIntegratedReportRaw").textContent = err.message;
        }}
      }}

      async function runOfficialIntegratedAnnualReport() {{
        const meta = document.getElementById("officialReportMeta");
        updateOfficialReportLinks();
        try {{
          const query = buildQuery([
            {{ key: "site", id: "officialReportSite" }},
            {{ key: "year", id: "officialReportYear" }},
          ]);
          const report = await fetchJson("/api/reports/annual/integrated" + (query ? "?" + query : ""), true);
          meta.textContent = "통합 연차보고서 성공: " + String(report.period_label || report.year || "");
          renderIntegratedReport(report);
        }} catch (err) {{
          meta.textContent = "통합 연차보고서 실패: " + err.message;
          document.getElementById("officialIntegratedReportSummary").innerHTML = "";
          document.getElementById("officialIntegratedReportRaw").textContent = err.message;
        }}
      }}

      function updateReportLinks() {{
        const query = buildQuery([
          {{ key: "month", id: "rpMonth" }},
          {{ key: "site", id: "rpSite" }}
        ]);
        const annualQuery = buildQuery([
          {{ key: "year", id: "rpYear" }},
          {{ key: "site", id: "rpSite" }}
        ]);
        const suffix = query ? "?" + query : "";
        const annualSuffix = annualQuery ? "?" + annualQuery : "";
        document.getElementById("reportPrintLink").setAttribute("href", "/reports/monthly/print" + suffix);
        document.getElementById("reportCsvLink").setAttribute("href", "/api/reports/monthly/csv" + suffix);
        document.getElementById("reportPdfLink").setAttribute("href", "/api/reports/monthly/pdf" + suffix);
        document.getElementById("reportIntegratedPrintLink").setAttribute("href", "/reports/monthly/integrated/print" + suffix);
        document.getElementById("reportIntegratedCsvLink").setAttribute("href", "/api/reports/monthly/integrated/csv" + suffix);
        document.getElementById("reportIntegratedPdfLink").setAttribute("href", "/api/reports/monthly/integrated/pdf" + suffix);
        document.getElementById("reportIntegratedAnnualPrintLink").setAttribute("href", "/reports/annual/integrated/print" + annualSuffix);
        document.getElementById("reportIntegratedAnnualCsvLink").setAttribute("href", "/api/reports/annual/integrated/csv" + annualSuffix);
        document.getElementById("reportIntegratedAnnualPdfLink").setAttribute("href", "/api/reports/annual/integrated/pdf" + annualSuffix);
      }}

      async function runReports() {{
        const query = buildQuery([
          {{ key: "month", id: "rpMonth" }},
          {{ key: "site", id: "rpSite" }}
        ]);
        const path = "/api/reports/monthly" + (query ? "?" + query : "");
        const meta = document.getElementById("reportsMeta");
        const summary = document.getElementById("reportsSummary");
        const raw = document.getElementById("reportsRaw");
        updateReportLinks();
        try {{
          meta.textContent = "조회 중... " + path;
          const data = await fetchJson(path, true);
          meta.textContent = "성공: " + path;
          const summaryItems = [
            ["Month", data.month],
            ["Site", data.site || "ALL"],
            ["Total Inspections", data.total_inspections],
            ["High Risk Inspections", data.high_risk_inspections],
            ["Total Work Orders", data.total_work_orders],
            ["Escalated Work Orders", data.escalated_work_orders],
            ["Completed Work Orders", data.completed_work_orders],
            ["Overdue Open Work Orders", data.overdue_open_work_orders]
          ];
          summary.innerHTML = summaryItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1] ?? "") + "</div></div>"
          )).join("");
          raw.textContent = JSON.stringify(data, null, 2);
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          summary.innerHTML = "";
          raw.textContent = err.message;
        }}
      }}

      async function runW02Tracker() {{
        const meta = document.getElementById("w02TrackerMeta");
        const summary = document.getElementById("w02TrackerSummary");
        const table = document.getElementById("w02TrackerTable");
        const readinessMeta = document.getElementById("w02ReadinessMeta");
        const readinessCards = document.getElementById("w02ReadinessCards");
        const readinessBlockers = document.getElementById("w02ReadinessBlockers");
        const evidenceTable = document.getElementById("w02EvidenceTable");
        const site = (document.getElementById("w02TrackSite").value || "").trim();
        if (!site) {{
          meta.textContent = "site 값을 입력하세요.";
          summary.innerHTML = "";
          table.innerHTML = renderEmpty("site 입력이 필요합니다.");
          readinessMeta.textContent = "site 값을 입력하세요.";
          readinessCards.innerHTML = "";
          readinessBlockers.innerHTML = renderEmpty("site 입력이 필요합니다.");
          evidenceTable.innerHTML = renderEmpty("site 입력이 필요합니다.");
          return;
        }}
        try {{
          meta.textContent = "조회 중... W02 tracker";
          readinessMeta.textContent = "조회 중... W02 readiness";
          const [trackerOverview, trackerItems, readiness, completion] = await Promise.all([
            fetchJson("/api/adoption/w02/tracker/overview?site=" + encodeURIComponent(site), true),
            fetchJson("/api/adoption/w02/tracker/items?site=" + encodeURIComponent(site) + "&limit=500", true),
            fetchJson("/api/adoption/w02/tracker/readiness?site=" + encodeURIComponent(site), true),
            fetchJson("/api/adoption/w02/tracker/completion?site=" + encodeURIComponent(site), true),
          ]);
          meta.textContent = "성공: W02 tracker (" + site + ")";
          readinessMeta.textContent =
            "상태: " + String(completion.status || "active")
            + " | ready=" + (readiness.ready ? "YES" : "NO")
            + " | 마지막 판정=" + String(readiness.checked_at || "-");
          const summaryItems = [
            ["Total", trackerOverview.total_items || 0],
            ["Pending", trackerOverview.pending_count || 0],
            ["In Progress", trackerOverview.in_progress_count || 0],
            ["Done", trackerOverview.done_count || 0],
            ["Blocked", trackerOverview.blocked_count || 0],
            ["Completion %", trackerOverview.completion_rate_percent || 0],
            ["Evidence", trackerOverview.evidence_total_count || 0],
          ];
          summary.innerHTML = summaryItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");
          const readinessItems = [
            ["Readiness Ready", readiness.ready ? "YES" : "NO"],
            ["Readiness %", readiness.readiness_score_percent || 0],
            ["Missing Assignee", readiness.missing_assignee_count || 0],
            ["Missing Checked", readiness.missing_completion_checked_count || 0],
            ["Missing Evidence", readiness.missing_required_evidence_count || 0],
            ["Completion Status", completion.status || "active"],
            ["Completed At", completion.completed_at || "-"],
            ["Completed By", completion.completed_by || "-"],
          ];
          readinessCards.innerHTML = readinessItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");
          const blockers = Array.isArray(readiness.blockers) ? readiness.blockers : [];
          if (blockers.length > 0) {{
            readinessBlockers.innerHTML = (
              '<div class="table-wrap"><table><thead><tr><th>#</th><th>Blocker</th></tr></thead><tbody>'
              + blockers.map((item, idx) => (
                "<tr><td>" + escapeHtml(idx + 1) + "</td><td>" + escapeHtml(item) + "</td></tr>"
              )).join("")
              + "</tbody></table></div>"
            );
          }} else {{
            readinessBlockers.innerHTML = renderEmpty("차단 항목 없음");
          }}
          table.innerHTML = renderTable(
            trackerItems || [],
            [
              {{ key: "id", label: "ID" }},
              {{ key: "item_type", label: "Type" }},
              {{ key: "item_key", label: "Key" }},
              {{ key: "item_name", label: "Name" }},
              {{ key: "assignee", label: "Assignee" }},
              {{ key: "status", label: "Status" }},
              {{ key: "completion_checked", label: "Checked" }},
              {{ key: "evidence_count", label: "Evidence" }},
              {{ key: "updated_at", label: "Updated At" }},
            ]
          );

          let evidenceItemId = (document.getElementById("w02EvidenceListItemId").value || "").trim();
          if (!evidenceItemId) {{
            evidenceItemId = (document.getElementById("w02TrackItemId").value || "").trim();
          }}
          if (evidenceItemId) {{
            const evidences = await fetchJson(
              "/api/adoption/w02/tracker/items/" + encodeURIComponent(evidenceItemId) + "/evidence",
              true
            );
            evidenceTable.innerHTML = renderEvidenceTable(evidences || [], "w02");
          }} else {{
            evidenceTable.innerHTML = renderEmpty("tracker_item_id 입력 시 증빙 파일 목록을 표시합니다.");
          }}
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          summary.innerHTML = "";
          table.innerHTML = renderEmpty(err.message);
          readinessMeta.textContent = "실패: " + err.message;
          readinessCards.innerHTML = "";
          readinessBlockers.innerHTML = renderEmpty(err.message);
          evidenceTable.innerHTML = renderEmpty(err.message);
        }}
      }}

      async function runW02Readiness() {{
        await runW02Tracker();
      }}

      async function runW02TrackerBootstrap() {{
        const meta = document.getElementById("w02TrackerMeta");
        const site = (document.getElementById("w02TrackSite").value || "").trim();
        if (!site) {{
          meta.textContent = "site 값을 입력하세요.";
          return;
        }}
        try {{
          meta.textContent = "생성 중... W02 tracker bootstrap";
          const data = await fetchJson(
            "/api/adoption/w02/tracker/bootstrap",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{ site }}),
            }}
          );
          meta.textContent = "성공: 생성 " + String(data.created_count || 0) + "건";
          await runW02Tracker();
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runW02Complete() {{
        const meta = document.getElementById("w02ReadinessMeta");
        const site = (document.getElementById("w02TrackSite").value || "").trim();
        if (!site) {{
          meta.textContent = "site 값을 입력하세요.";
          return;
        }}
        const completionNote = (document.getElementById("w02CompletionNote").value || "").trim();
        const force = !!document.getElementById("w02CompletionForce").checked;
        const payload = {{
          site: site,
          force: force,
        }};
        if (completionNote) {{
          payload.completion_note = completionNote;
        }}
        try {{
          meta.textContent = "실행 중... W02 완료 확정";
          const result = await fetchJson(
            "/api/adoption/w02/tracker/complete",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify(payload),
            }}
          );
          meta.textContent =
            "성공: status=" + String(result.status || "-")
            + " | ready=" + String(result.readiness && result.readiness.ready ? "YES" : "NO")
            + " | completed_at=" + String(result.completed_at || "-");
          await runW02Tracker();
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          await runW02Tracker().catch(() => null);
        }}
      }}

      async function runW02TrackerUpdateAndUpload() {{
        const meta = document.getElementById("w02TrackerMeta");
        const trackerItemIdRaw = (document.getElementById("w02TrackItemId").value || "").trim();
        const trackerItemId = Number(trackerItemIdRaw);
        if (!trackerItemIdRaw || !Number.isFinite(trackerItemId) || trackerItemId <= 0) {{
          meta.textContent = "유효한 tracker_item_id를 입력하세요.";
          return;
        }}

        const assignee = (document.getElementById("w02TrackAssignee").value || "").trim();
        const status = (document.getElementById("w02TrackStatus").value || "").trim();
        const completionChecked = !!document.getElementById("w02TrackCompleted").checked;
        const note = (document.getElementById("w02TrackNote").value || "").trim();
        const payload = {{}};
        if (assignee) payload.assignee = assignee;
        if (status) payload.status = status;
        if (completionChecked) {{
          payload.completion_checked = true;
        }} else if (status && status !== "done") {{
          payload.completion_checked = false;
        }}
        if (note) payload.completion_note = note;
        const fileInput = document.getElementById("w02EvidenceFile");
        const file = fileInput && fileInput.files ? fileInput.files[0] : null;
        const hasTrackerUpdate = Object.keys(payload).length > 0;
        if (!hasTrackerUpdate && !file) {{
          meta.textContent = "저장할 변경 또는 업로드 파일이 없습니다.";
          return;
        }}

        try {{
          meta.textContent = "저장 중... tracker update";
          if (hasTrackerUpdate) {{
            await fetchJson(
              "/api/adoption/w02/tracker/items/" + encodeURIComponent(trackerItemIdRaw),
              true,
              {{
                method: "PATCH",
                headers: {{ "Content-Type": "application/json" }},
                body: JSON.stringify(payload),
              }}
            );
          }}

          if (file) {{
            const formData = new FormData();
            formData.append("file", file);
            const evidenceNote = (document.getElementById("w02EvidenceNote").value || "").trim();
            formData.append("note", evidenceNote);
            const token = getToken();
            if (!token) {{
              throw new Error("인증 토큰이 없습니다.");
            }}
            const uploadResp = await fetch(
              "/api/adoption/w02/tracker/items/" + encodeURIComponent(trackerItemIdRaw) + "/evidence",
              {{
                method: "POST",
                headers: {{
                  "X-Admin-Token": token,
                  "Accept": "application/json",
                }},
                body: formData,
              }}
            );
            const uploadText = await uploadResp.text();
            if (!uploadResp.ok) {{
              throw new Error("Evidence upload failed: HTTP " + uploadResp.status + " | " + uploadText);
            }}
            document.getElementById("w02EvidenceFile").value = "";
          }}

          meta.textContent = "성공: tracker 저장 완료";
          await runW02Tracker();
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runW03Tracker() {{
        const meta = document.getElementById("w03TrackerMeta");
        const summary = document.getElementById("w03TrackerSummary");
        const table = document.getElementById("w03TrackerTable");
        const readinessMeta = document.getElementById("w03ReadinessMeta");
        const readinessCards = document.getElementById("w03ReadinessCards");
        const readinessBlockers = document.getElementById("w03ReadinessBlockers");
        const evidenceTable = document.getElementById("w03EvidenceTable");
        const site = (document.getElementById("w03TrackSite").value || "").trim();
        if (!site) {{
          meta.textContent = "site 값을 입력하세요.";
          summary.innerHTML = "";
          table.innerHTML = renderEmpty("site 입력이 필요합니다.");
          readinessMeta.textContent = "site 값을 입력하세요.";
          readinessCards.innerHTML = "";
          readinessBlockers.innerHTML = renderEmpty("site 입력이 필요합니다.");
          evidenceTable.innerHTML = renderEmpty("site 입력이 필요합니다.");
          return;
        }}
        try {{
          meta.textContent = "조회 중... W03 tracker";
          readinessMeta.textContent = "조회 중... W03 readiness";
          const [trackerOverview, trackerItems, readiness, completion] = await Promise.all([
            fetchJson("/api/adoption/w03/tracker/overview?site=" + encodeURIComponent(site), true),
            fetchJson("/api/adoption/w03/tracker/items?site=" + encodeURIComponent(site) + "&limit=500", true),
            fetchJson("/api/adoption/w03/tracker/readiness?site=" + encodeURIComponent(site), true),
            fetchJson("/api/adoption/w03/tracker/completion?site=" + encodeURIComponent(site), true),
          ]);
          meta.textContent = "성공: W03 tracker (" + site + ")";
          readinessMeta.textContent =
            "상태: " + String(completion.status || "active")
            + " | ready=" + (readiness.ready ? "YES" : "NO")
            + " | 마지막 판정=" + String(readiness.checked_at || "-");
          const summaryItems = [
            ["Total", trackerOverview.total_items || 0],
            ["Pending", trackerOverview.pending_count || 0],
            ["In Progress", trackerOverview.in_progress_count || 0],
            ["Done", trackerOverview.done_count || 0],
            ["Blocked", trackerOverview.blocked_count || 0],
            ["Completion %", trackerOverview.completion_rate_percent || 0],
            ["Evidence", trackerOverview.evidence_total_count || 0],
          ];
          summary.innerHTML = summaryItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");
          const readinessItems = [
            ["Readiness Ready", readiness.ready ? "YES" : "NO"],
            ["Readiness %", readiness.readiness_score_percent || 0],
            ["Missing Assignee", readiness.missing_assignee_count || 0],
            ["Missing Checked", readiness.missing_completion_checked_count || 0],
            ["Missing Evidence", readiness.missing_required_evidence_count || 0],
            ["Completion Status", completion.status || "active"],
            ["Completed At", completion.completed_at || "-"],
            ["Completed By", completion.completed_by || "-"],
          ];
          readinessCards.innerHTML = readinessItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");
          const blockers = Array.isArray(readiness.blockers) ? readiness.blockers : [];
          if (blockers.length > 0) {{
            readinessBlockers.innerHTML = (
              '<div class="table-wrap"><table><thead><tr><th>#</th><th>Blocker</th></tr></thead><tbody>'
              + blockers.map((item, idx) => (
                "<tr><td>" + escapeHtml(idx + 1) + "</td><td>" + escapeHtml(item) + "</td></tr>"
              )).join("")
              + "</tbody></table></div>"
            );
          }} else {{
            readinessBlockers.innerHTML = renderEmpty("차단 항목 없음");
          }}
          table.innerHTML = renderTable(
            trackerItems || [],
            [
              {{ key: "id", label: "ID" }},
              {{ key: "item_type", label: "Type" }},
              {{ key: "item_key", label: "Key" }},
              {{ key: "item_name", label: "Name" }},
              {{ key: "assignee", label: "Assignee" }},
              {{ key: "status", label: "Status" }},
              {{ key: "completion_checked", label: "Checked" }},
              {{ key: "evidence_count", label: "Evidence" }},
              {{ key: "updated_at", label: "Updated At" }},
            ]
          );

          let evidenceItemId = (document.getElementById("w03EvidenceListItemId").value || "").trim();
          if (!evidenceItemId) {{
            evidenceItemId = (document.getElementById("w03TrackItemId").value || "").trim();
          }}
          if (evidenceItemId) {{
            const evidences = await fetchJson(
              "/api/adoption/w03/tracker/items/" + encodeURIComponent(evidenceItemId) + "/evidence",
              true
            );
            evidenceTable.innerHTML = renderEvidenceTable(evidences || [], "w03");
          }} else {{
            evidenceTable.innerHTML = renderEmpty("tracker_item_id 입력 시 증빙 파일 목록을 표시합니다.");
          }}
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          summary.innerHTML = "";
          table.innerHTML = renderEmpty(err.message);
          readinessMeta.textContent = "실패: " + err.message;
          readinessCards.innerHTML = "";
          readinessBlockers.innerHTML = renderEmpty(err.message);
          evidenceTable.innerHTML = renderEmpty(err.message);
        }}
      }}

      async function runW03Readiness() {{
        await runW03Tracker();
      }}

      async function runW03TrackerBootstrap() {{
        const meta = document.getElementById("w03TrackerMeta");
        const site = (document.getElementById("w03TrackSite").value || "").trim();
        if (!site) {{
          meta.textContent = "site 값을 입력하세요.";
          return;
        }}
        try {{
          meta.textContent = "생성 중... W03 tracker bootstrap";
          const data = await fetchJson(
            "/api/adoption/w03/tracker/bootstrap",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{ site }}),
            }}
          );
          meta.textContent = "성공: 생성 " + String(data.created_count || 0) + "건";
          await runW03Tracker();
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runW03Complete() {{
        const meta = document.getElementById("w03ReadinessMeta");
        const site = (document.getElementById("w03TrackSite").value || "").trim();
        if (!site) {{
          meta.textContent = "site 값을 입력하세요.";
          return;
        }}
        const completionNote = (document.getElementById("w03CompletionNote").value || "").trim();
        const force = !!document.getElementById("w03CompletionForce").checked;
        const payload = {{
          site: site,
          force: force,
        }};
        if (completionNote) {{
          payload.completion_note = completionNote;
        }}
        try {{
          meta.textContent = "실행 중... W03 완료 확정";
          const result = await fetchJson(
            "/api/adoption/w03/tracker/complete",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify(payload),
            }}
          );
          meta.textContent =
            "성공: status=" + String(result.status || "-")
            + " | ready=" + String(result.readiness && result.readiness.ready ? "YES" : "NO")
            + " | completed_at=" + String(result.completed_at || "-");
          await runW03Tracker();
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          await runW03Tracker().catch(() => null);
        }}
      }}

      async function runW03TrackerUpdateAndUpload() {{
        const meta = document.getElementById("w03TrackerMeta");
        const trackerItemIdRaw = (document.getElementById("w03TrackItemId").value || "").trim();
        const trackerItemId = Number(trackerItemIdRaw);
        if (!trackerItemIdRaw || !Number.isFinite(trackerItemId) || trackerItemId <= 0) {{
          meta.textContent = "유효한 tracker_item_id를 입력하세요.";
          return;
        }}

        const assignee = (document.getElementById("w03TrackAssignee").value || "").trim();
        const status = (document.getElementById("w03TrackStatus").value || "").trim();
        const completionChecked = !!document.getElementById("w03TrackCompleted").checked;
        const note = (document.getElementById("w03TrackNote").value || "").trim();
        const payload = {{}};
        if (assignee) payload.assignee = assignee;
        if (status) payload.status = status;
        if (completionChecked) {{
          payload.completion_checked = true;
        }} else if (status && status !== "done") {{
          payload.completion_checked = false;
        }}
        if (note) payload.completion_note = note;
        const fileInput = document.getElementById("w03EvidenceFile");
        const file = fileInput && fileInput.files ? fileInput.files[0] : null;
        const hasTrackerUpdate = Object.keys(payload).length > 0;
        if (!hasTrackerUpdate && !file) {{
          meta.textContent = "저장할 변경 또는 업로드 파일이 없습니다.";
          return;
        }}

        try {{
          meta.textContent = "저장 중... tracker update";
          if (hasTrackerUpdate) {{
            await fetchJson(
              "/api/adoption/w03/tracker/items/" + encodeURIComponent(trackerItemIdRaw),
              true,
              {{
                method: "PATCH",
                headers: {{ "Content-Type": "application/json" }},
                body: JSON.stringify(payload),
              }}
            );
          }}

          if (file) {{
            const formData = new FormData();
            formData.append("file", file);
            const evidenceNote = (document.getElementById("w03EvidenceNote").value || "").trim();
            formData.append("note", evidenceNote);
            const token = getToken();
            if (!token) {{
              throw new Error("인증 토큰이 없습니다.");
            }}
            const uploadResp = await fetch(
              "/api/adoption/w03/tracker/items/" + encodeURIComponent(trackerItemIdRaw) + "/evidence",
              {{
                method: "POST",
                headers: {{
                  "X-Admin-Token": token,
                  "Accept": "application/json",
                }},
                body: formData,
              }}
            );
            const uploadText = await uploadResp.text();
            if (!uploadResp.ok) {{
              throw new Error("Evidence upload failed: HTTP " + uploadResp.status + " | " + uploadText);
            }}
            document.getElementById("w03EvidenceFile").value = "";
          }}

          meta.textContent = "성공: tracker 저장 완료";
          await runW03Tracker();
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runW04FunnelBlockers() {{
        const meta = document.getElementById("w04FunnelMeta");
        const summary = document.getElementById("w04FunnelSummary");
        const stages = document.getElementById("w04FunnelStages");
        const blockers = document.getElementById("w04BlockerTable");
        const site = (document.getElementById("w04FunnelSite").value || "").trim();
        if (!site) {{
          meta.textContent = "site 값을 입력하세요.";
          summary.innerHTML = "";
          stages.innerHTML = renderEmpty("site 입력이 필요합니다.");
          blockers.innerHTML = renderEmpty("site 입력이 필요합니다.");
          return;
        }}
        const daysRaw = (document.getElementById("w04FunnelDays").value || "").trim();
        const maxItemsRaw = (document.getElementById("w04FunnelMaxBlockers").value || "").trim();
        const params = new URLSearchParams();
        params.set("site", site);
        if (daysRaw) {{
          params.set("days", daysRaw);
        }}
        if (maxItemsRaw) {{
          params.set("max_items", maxItemsRaw);
        }}
        try {{
          meta.textContent = "조회 중... W04 funnel + blockers";
          const [funnel, topBlockers] = await Promise.all([
            fetchJson("/api/ops/adoption/w04/funnel?" + params.toString(), true),
            fetchJson("/api/ops/adoption/w04/blockers?" + params.toString(), true),
          ]);
          const metrics = funnel.metrics || {{}};
          const timings = funnel.stage_timings_minutes || {{}};
          meta.textContent =
            "성공: W04 funnel (" + site + ")"
            + " | median_ttv=" + String(metrics.median_ttv_minutes ?? "-")
            + " | target_met=" + String(metrics.target_met ? "YES" : "NO");
          const summaryItems = [
            ["Target TTV(min)", funnel.target_ttv_minutes ?? 15],
            ["Median TTV(min)", metrics.median_ttv_minutes ?? "-"],
            ["Target Met", metrics.target_met ? "YES" : "NO"],
            ["Total Users", metrics.total_users ?? 0],
            ["Inspection Conv %", metrics.inspection_conversion_rate_percent ?? 0],
            ["WO Complete Conv %", metrics.work_order_completion_rate_percent ?? 0],
            ["Auth->Inspection(min)", timings.auth_to_first_inspection ?? "-"],
            ["Inspection->Complete(min)", timings.inspection_to_first_work_order_complete ?? "-"],
          ];
          summary.innerHTML = summaryItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");

          stages.innerHTML = renderTable(
            funnel.stages || [],
            [
              {{ key: "stage_id", label: "Stage ID" }},
              {{ key: "label", label: "Label" }},
              {{ key: "user_count", label: "Users" }},
              {{ key: "conversion_rate_percent", label: "Conv %" }},
            ]
          );
          blockers.innerHTML = renderTable(
            topBlockers.top || [],
            [
              {{ key: "blocker_key", label: "Blocker Key" }},
              {{ key: "title", label: "Title" }},
              {{ key: "count", label: "Count" }},
              {{ key: "source", label: "Source" }},
              {{ key: "recommendation", label: "Recommendation" }},
            ]
          );
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          summary.innerHTML = "";
          stages.innerHTML = renderEmpty(err.message);
          blockers.innerHTML = renderEmpty(err.message);
        }}
      }}

      async function runW04Tracker() {{
        const meta = document.getElementById("w04TrackerMeta");
        const summary = document.getElementById("w04TrackerSummary");
        const table = document.getElementById("w04TrackerTable");
        const readinessMeta = document.getElementById("w04ReadinessMeta");
        const readinessCards = document.getElementById("w04ReadinessCards");
        const readinessBlockers = document.getElementById("w04ReadinessBlockers");
        const evidenceTable = document.getElementById("w04EvidenceTable");
        const site = (document.getElementById("w04TrackSite").value || "").trim();
        if (!site) {{
          meta.textContent = "site 값을 입력하세요.";
          summary.innerHTML = "";
          table.innerHTML = renderEmpty("site 입력이 필요합니다.");
          readinessMeta.textContent = "site 값을 입력하세요.";
          readinessCards.innerHTML = "";
          readinessBlockers.innerHTML = renderEmpty("site 입력이 필요합니다.");
          evidenceTable.innerHTML = renderEmpty("site 입력이 필요합니다.");
          return;
        }}
        try {{
          meta.textContent = "조회 중... W04 tracker";
          readinessMeta.textContent = "조회 중... W04 readiness";
          const [trackerOverview, trackerItems, readiness, completion] = await Promise.all([
            fetchJson("/api/adoption/w04/tracker/overview?site=" + encodeURIComponent(site), true),
            fetchJson("/api/adoption/w04/tracker/items?site=" + encodeURIComponent(site) + "&limit=500", true),
            fetchJson("/api/adoption/w04/tracker/readiness?site=" + encodeURIComponent(site), true),
            fetchJson("/api/adoption/w04/tracker/completion?site=" + encodeURIComponent(site), true),
          ]);
          meta.textContent = "성공: W04 tracker (" + site + ")";
          readinessMeta.textContent =
            "상태: " + String(completion.status || "active")
            + " | ready=" + (readiness.ready ? "YES" : "NO")
            + " | 마지막 판정=" + String(readiness.checked_at || "-");
          const summaryItems = [
            ["Total", trackerOverview.total_items || 0],
            ["Pending", trackerOverview.pending_count || 0],
            ["In Progress", trackerOverview.in_progress_count || 0],
            ["Done", trackerOverview.done_count || 0],
            ["Blocked", trackerOverview.blocked_count || 0],
            ["Completion %", trackerOverview.completion_rate_percent || 0],
            ["Evidence", trackerOverview.evidence_total_count || 0],
          ];
          summary.innerHTML = summaryItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");
          const readinessItems = [
            ["Readiness Ready", readiness.ready ? "YES" : "NO"],
            ["Readiness %", readiness.readiness_score_percent || 0],
            ["Missing Assignee", readiness.missing_assignee_count || 0],
            ["Missing Checked", readiness.missing_completion_checked_count || 0],
            ["Missing Evidence", readiness.missing_required_evidence_count || 0],
            ["Completion Status", completion.status || "active"],
            ["Completed At", completion.completed_at || "-"],
            ["Completed By", completion.completed_by || "-"],
          ];
          readinessCards.innerHTML = readinessItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");
          const blockers = Array.isArray(readiness.blockers) ? readiness.blockers : [];
          if (blockers.length > 0) {{
            readinessBlockers.innerHTML = (
              '<div class="table-wrap"><table><thead><tr><th>#</th><th>Blocker</th></tr></thead><tbody>'
              + blockers.map((item, idx) => (
                "<tr><td>" + escapeHtml(idx + 1) + "</td><td>" + escapeHtml(item) + "</td></tr>"
              )).join("")
              + "</tbody></table></div>"
            );
          }} else {{
            readinessBlockers.innerHTML = renderEmpty("차단 항목 없음");
          }}
          table.innerHTML = renderTable(
            trackerItems || [],
            [
              {{ key: "id", label: "ID" }},
              {{ key: "item_type", label: "Type" }},
              {{ key: "item_key", label: "Key" }},
              {{ key: "item_name", label: "Name" }},
              {{ key: "assignee", label: "Assignee" }},
              {{ key: "status", label: "Status" }},
              {{ key: "completion_checked", label: "Checked" }},
              {{ key: "evidence_count", label: "Evidence" }},
              {{ key: "updated_at", label: "Updated At" }},
            ]
          );

          let evidenceItemId = (document.getElementById("w04EvidenceListItemId").value || "").trim();
          if (!evidenceItemId) {{
            evidenceItemId = (document.getElementById("w04TrackItemId").value || "").trim();
          }}
          if (evidenceItemId) {{
            const evidences = await fetchJson(
              "/api/adoption/w04/tracker/items/" + encodeURIComponent(evidenceItemId) + "/evidence",
              true
            );
            evidenceTable.innerHTML = renderEvidenceTable(evidences || [], "w04");
          }} else {{
            evidenceTable.innerHTML = renderEmpty("tracker_item_id 입력 시 증빙 파일 목록을 표시합니다.");
          }}
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          summary.innerHTML = "";
          table.innerHTML = renderEmpty(err.message);
          readinessMeta.textContent = "실패: " + err.message;
          readinessCards.innerHTML = "";
          readinessBlockers.innerHTML = renderEmpty(err.message);
          evidenceTable.innerHTML = renderEmpty(err.message);
        }}
      }}

      async function runW04Readiness() {{
        await runW04Tracker();
      }}

      async function runW04TrackerBootstrap() {{
        const meta = document.getElementById("w04TrackerMeta");
        const site = (document.getElementById("w04TrackSite").value || "").trim();
        if (!site) {{
          meta.textContent = "site 값을 입력하세요.";
          return;
        }}
        try {{
          meta.textContent = "생성 중... W04 tracker bootstrap";
          const data = await fetchJson(
            "/api/adoption/w04/tracker/bootstrap",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{ site }}),
            }}
          );
          meta.textContent = "성공: 생성 " + String(data.created_count || 0) + "건";
          await runW04Tracker();
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runW04Complete() {{
        const meta = document.getElementById("w04ReadinessMeta");
        const site = (document.getElementById("w04TrackSite").value || "").trim();
        if (!site) {{
          meta.textContent = "site 값을 입력하세요.";
          return;
        }}
        const completionNote = (document.getElementById("w04CompletionNote").value || "").trim();
        const force = !!document.getElementById("w04CompletionForce").checked;
        const payload = {{
          site: site,
          force: force,
        }};
        if (completionNote) {{
          payload.completion_note = completionNote;
        }}
        try {{
          meta.textContent = "실행 중... W04 완료 확정";
          const result = await fetchJson(
            "/api/adoption/w04/tracker/complete",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify(payload),
            }}
          );
          meta.textContent =
            "성공: status=" + String(result.status || "-")
            + " | ready=" + String(result.readiness && result.readiness.ready ? "YES" : "NO")
            + " | completed_at=" + String(result.completed_at || "-");
          await runW04Tracker();
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          await runW04Tracker().catch(() => null);
        }}
      }}

      async function runW04TrackerUpdateAndUpload() {{
        const meta = document.getElementById("w04TrackerMeta");
        const trackerItemIdRaw = (document.getElementById("w04TrackItemId").value || "").trim();
        const trackerItemId = Number(trackerItemIdRaw);
        if (!trackerItemIdRaw || !Number.isFinite(trackerItemId) || trackerItemId <= 0) {{
          meta.textContent = "유효한 tracker_item_id를 입력하세요.";
          return;
        }}

        const assignee = (document.getElementById("w04TrackAssignee").value || "").trim();
        const status = (document.getElementById("w04TrackStatus").value || "").trim();
        const completionChecked = !!document.getElementById("w04TrackCompleted").checked;
        const note = (document.getElementById("w04TrackNote").value || "").trim();
        const payload = {{}};
        if (assignee) payload.assignee = assignee;
        if (status) payload.status = status;
        if (completionChecked) {{
          payload.completion_checked = true;
        }} else if (status && status !== "done") {{
          payload.completion_checked = false;
        }}
        if (note) payload.completion_note = note;
        const fileInput = document.getElementById("w04EvidenceFile");
        const file = fileInput && fileInput.files ? fileInput.files[0] : null;
        const hasTrackerUpdate = Object.keys(payload).length > 0;
        if (!hasTrackerUpdate && !file) {{
          meta.textContent = "저장할 변경 또는 업로드 파일이 없습니다.";
          return;
        }}

        try {{
          meta.textContent = "저장 중... tracker update";
          if (hasTrackerUpdate) {{
            await fetchJson(
              "/api/adoption/w04/tracker/items/" + encodeURIComponent(trackerItemIdRaw),
              true,
              {{
                method: "PATCH",
                headers: {{ "Content-Type": "application/json" }},
                body: JSON.stringify(payload),
              }}
            );
          }}

          if (file) {{
            const formData = new FormData();
            formData.append("file", file);
            const evidenceNote = (document.getElementById("w04EvidenceNote").value || "").trim();
            formData.append("note", evidenceNote);
            const token = getToken();
            if (!token) {{
              throw new Error("인증 토큰이 없습니다.");
            }}
            const uploadResp = await fetch(
              "/api/adoption/w04/tracker/items/" + encodeURIComponent(trackerItemIdRaw) + "/evidence",
              {{
                method: "POST",
                headers: {{
                  "X-Admin-Token": token,
                  "Accept": "application/json",
                }},
                body: formData,
              }}
            );
            const uploadText = await uploadResp.text();
            if (!uploadResp.ok) {{
              throw new Error("Evidence upload failed: HTTP " + uploadResp.status + " | " + uploadText);
            }}
            document.getElementById("w04EvidenceFile").value = "";
          }}

          meta.textContent = "성공: tracker 저장 완료";
          await runW04Tracker();
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runW05Consistency() {{
        const meta = document.getElementById("w05ConsistencyMeta");
        const summary = document.getElementById("w05ConsistencySummary");
        const topSites = document.getElementById("w05ConsistencyTopSites");
        const recommendations = document.getElementById("w05ConsistencyRecommendations");
        const site = (document.getElementById("w05ConsistencySite").value || "").trim();
        const daysRaw = (document.getElementById("w05ConsistencyDays").value || "").trim();
        const params = new URLSearchParams();
        if (site) {{
          params.set("site", site);
        }}
        if (daysRaw) {{
          params.set("days", daysRaw);
        }}
        const path = "/api/ops/adoption/w05/consistency" + (params.toString() ? ("?" + params.toString()) : "");
        try {{
          meta.textContent = "조회 중... " + path;
          const data = await fetchJson(path, true);
          const metrics = data.metrics || {{}};
          meta.textContent =
            "성공: site=" + String(data.site || "ALL")
            + " | window_days=" + String(data.window_days || "-")
            + " | retention=" + String(metrics.two_week_retention_percent ?? 0) + "%"
            + " | target=" + String(data.target_retention_percent ?? 65) + "%";
          const summaryItems = [
            ["Active Users", metrics.active_users ?? 0],
            ["Early Period Users", metrics.early_period_users ?? 0],
            ["Retained Users", metrics.retained_users ?? 0],
            ["2-week Retention %", metrics.two_week_retention_percent ?? 0],
            ["Target Met", metrics.target_met ? "YES" : "NO"],
            ["Inspection Activity Users", metrics.inspection_activity_users ?? 0],
            ["Open Work Orders", metrics.open_work_orders ?? 0],
            ["Overdue Open", metrics.overdue_open_work_orders ?? 0],
            ["Overdue Ratio %", metrics.overdue_ratio_percent ?? 0],
          ];
          summary.innerHTML = summaryItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");
          topSites.innerHTML = renderTable(
            data.top_sites_by_overdue || [],
            [
              {{ key: "site", label: "Site" }},
              {{ key: "open_work_orders", label: "Open Work Orders" }},
              {{ key: "overdue_open_work_orders", label: "Overdue Open" }},
              {{ key: "overdue_ratio_percent", label: "Overdue Ratio %" }},
            ]
          );
          const recRows = Array.isArray(data.mission_recommendations)
            ? data.mission_recommendations.map((item, idx) => ({{
                no: idx + 1,
                recommendation: item,
              }}))
            : [];
          recommendations.innerHTML = renderTable(
            recRows,
            [
              {{ key: "no", label: "#" }},
              {{ key: "recommendation", label: "Recommendation" }},
            ]
          );
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          summary.innerHTML = "";
          topSites.innerHTML = renderEmpty(err.message);
          recommendations.innerHTML = renderEmpty(err.message);
        }}
      }}

      async function runW06Rhythm() {{
        const meta = document.getElementById("w06RhythmMeta");
        const summary = document.getElementById("w06RhythmSummary");
        const roleCoverage = document.getElementById("w06RhythmRoleCoverage");
        const siteActivity = document.getElementById("w06RhythmSiteActivity");
        const recommendations = document.getElementById("w06RhythmRecommendations");
        const site = (document.getElementById("w06RhythmSite").value || "").trim();
        const daysRaw = (document.getElementById("w06RhythmDays").value || "").trim();
        const params = new URLSearchParams();
        if (site) {{
          params.set("site", site);
        }}
        if (daysRaw) {{
          params.set("days", daysRaw);
        }}
        const path = "/api/ops/adoption/w06/rhythm" + (params.toString() ? ("?" + params.toString()) : "");
        try {{
          meta.textContent = "조회 중... " + path;
          const data = await fetchJson(path, true);
          const metrics = data.metrics || {{}};
          meta.textContent =
            "성공: site=" + String(data.site || "ALL")
            + " | window_days=" + String(data.window_days || "-")
            + " | weekly_active_rate=" + String(metrics.weekly_active_rate_percent ?? 0) + "%"
            + " | target=" + String(data.target_weekly_active_rate_percent ?? 75) + "%";
          const summaryItems = [
            ["Eligible Users", metrics.eligible_users ?? 0],
            ["Active Users", metrics.active_users ?? 0],
            ["Weekly Active Rate %", metrics.weekly_active_rate_percent ?? 0],
            ["Target Met", metrics.target_met ? "YES" : "NO"],
            ["Handover Views", metrics.handover_brief_views ?? 0],
            ["Handover Days", metrics.handover_days_covered ?? 0],
            ["Cadence Adherence %", metrics.cadence_adherence_percent ?? 0],
            ["Overdue Open WOs", metrics.overdue_open_work_orders ?? 0],
            ["Active Tokens", metrics.active_tokens ?? 0],
            ["Expiring Tokens(7d)", metrics.tokens_expiring_7d ?? 0],
            ["Stale Tokens(14d)", metrics.tokens_stale_14d ?? 0],
            ["Users Without Token", metrics.users_without_active_token ?? 0],
          ];
          summary.innerHTML = summaryItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");
          roleCoverage.innerHTML = renderTable(
            data.role_coverage || [],
            [
              {{ key: "role", label: "Role" }},
              {{ key: "user_count", label: "Users" }},
              {{ key: "active_user_count", label: "Active Users" }},
            ]
          );
          siteActivity.innerHTML = renderTable(
            data.site_activity || [],
            [
              {{ key: "site", label: "Site" }},
              {{ key: "activity_events", label: "Activity Events" }},
            ]
          );
          const recRows = Array.isArray(data.recommendations)
            ? data.recommendations.map((item, idx) => ({{
                no: idx + 1,
                recommendation: item,
              }}))
            : [];
          recommendations.innerHTML = renderTable(
            recRows,
            [
              {{ key: "no", label: "#" }},
              {{ key: "recommendation", label: "Recommendation" }},
            ]
          );
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          summary.innerHTML = "";
          roleCoverage.innerHTML = renderEmpty(err.message);
          siteActivity.innerHTML = renderEmpty(err.message);
          recommendations.innerHTML = renderEmpty(err.message);
        }}
      }}

      async function runW07SlaQuality() {{
        const meta = document.getElementById("w07QualityMeta");
        const summary = document.getElementById("w07QualitySummary");
        const readinessCards = document.getElementById("w07AutomationReadiness");
        const topSites = document.getElementById("w07QualityTopSites");
        const recommendations = document.getElementById("w07QualityRecommendations");
        const site = (document.getElementById("w07QualitySite").value || "").trim();
        const daysRaw = (document.getElementById("w07QualityDays").value || "").trim();
        const params = new URLSearchParams();
        if (site) {{
          params.set("site", site);
        }}
        if (daysRaw) {{
          params.set("days", daysRaw);
        }}
        const path = "/api/ops/adoption/w07/sla-quality" + (params.toString() ? ("?" + params.toString()) : "");
        const readinessParams = new URLSearchParams();
        if (site) {{
          readinessParams.set("site", site);
        }}
        const readinessPath = "/api/ops/adoption/w07/automation-readiness"
          + (readinessParams.toString() ? ("?" + readinessParams.toString()) : "");
        try {{
          meta.textContent = "조회 중... " + path;
          const [data, readiness] = await Promise.all([
            fetchJson(path, true),
            fetchJson(readinessPath, true).catch((err) => ({{ __error: err.message }})),
          ]);
          const metrics = data.metrics || {{}};
          meta.textContent =
            "성공: site=" + String(data.site || "ALL")
            + " | window_days=" + String(data.window_days || "-")
            + " | ack_improvement=" + String(metrics.response_time_improvement_percent ?? "-") + "%";
          const summaryItems = [
            ["Created WOs", metrics.created_work_orders ?? 0],
            ["Acked WOs", metrics.acked_work_orders ?? 0],
            ["Completed WOs", metrics.completed_work_orders ?? 0],
            ["Median ACK(min)", metrics.median_ack_minutes ?? "-"],
            ["p90 ACK(min)", metrics.p90_ack_minutes ?? "-"],
            ["Baseline ACK(min)", metrics.baseline_median_ack_minutes ?? "-"],
            ["ACK Improvement %", metrics.response_time_improvement_percent ?? "-"],
            ["Target Met", metrics.target_met ? "YES" : "NO"],
            ["Median MTTR(min)", metrics.median_mttr_minutes ?? "-"],
            ["SLA Violation %", metrics.sla_violation_rate_percent ?? 0],
            ["Open WOs", metrics.open_work_orders ?? 0],
            ["Overdue Open", metrics.overdue_open_work_orders ?? 0],
            ["Escalated Open", metrics.escalated_open_work_orders ?? 0],
            ["Escalation Rate %", metrics.escalation_rate_percent ?? 0],
            ["Alert Success %", metrics.alert_success_rate_percent ?? 0],
            ["DQ Gate", metrics.data_quality_gate_pass ? "PASS" : "FAIL"],
            ["DQ Issue %", metrics.data_quality_issue_rate_percent ?? 0],
            ["SLA Runs", metrics.sla_run_count ?? 0],
          ];
          summary.innerHTML = summaryItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");
          if (readiness && !readiness.__error) {{
            const runtime = readiness.runtime || {{}};
            const integration = readiness.integration || {{}};
            const overallStatus = normalizeUiStatus(readiness.overall_status || "info");
            const latestRunStatus = normalizeUiStatus(
              runtime.latest_run_recent
                ? "ok"
                : (runtime.latest_run_at ? "warning" : "critical")
            );
            const webhookStatus = normalizeUiStatus(
              integration.webhook_configured ? "ok" : "warning"
            );
            const checkCount = Array.isArray(readiness.checks) ? readiness.checks.length : 0;
            readinessCards.innerHTML = [
              renderUiStatusCard(
                "Overall Status",
                overallStatus,
                uiStatusLabel(overallStatus),
                "자동화 체크 " + String(checkCount) + "개"
              ),
              renderUiStatusCard(
                "최근 실행 시간",
                latestRunStatus,
                formatDateLocal(runtime.latest_run_at),
                runtime.latest_run_recent ? "8일 이내 실행됨" : "8일 초과 또는 실행 이력 없음"
              ),
              renderUiStatusCard(
                "웹훅 구성 상태",
                webhookStatus,
                integration.webhook_configured ? "구성됨" : "미구성",
                "대상 " + String(integration.webhook_target_count || 0) + "개"
              ),
            ].join("");
          }} else {{
            readinessCards.innerHTML = renderEmpty(
              "Automation Readiness 조회 실패: " + String(readiness && readiness.__error ? readiness.__error : "unknown")
            );
          }}
          topSites.innerHTML = renderTable(
            data.top_risk_sites || [],
            [
              {{ key: "site", label: "Site" }},
              {{ key: "open_work_orders", label: "Open WOs" }},
              {{ key: "overdue_open_work_orders", label: "Overdue Open" }},
              {{ key: "escalated_open_work_orders", label: "Escalated Open" }},
              {{ key: "escalation_rate_percent", label: "Escalation %" }},
              {{ key: "sla_violation_rate_percent", label: "Violation %" }},
              {{ key: "median_ack_minutes", label: "Median ACK(min)" }},
              {{ key: "p90_ack_minutes", label: "p90 ACK(min)" }},
            ]
          );
          const recRows = Array.isArray(data.recommendations)
            ? data.recommendations.map((item, idx) => ({{
                no: idx + 1,
                recommendation: item,
              }}))
            : [];
          recommendations.innerHTML = renderTable(
            recRows,
            [
              {{ key: "no", label: "#" }},
              {{ key: "recommendation", label: "Recommendation" }},
            ]
          );
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          summary.innerHTML = "";
          readinessCards.innerHTML = renderEmpty(err.message);
          topSites.innerHTML = renderEmpty(err.message);
          recommendations.innerHTML = renderEmpty(err.message);
        }}
      }}

      async function runW08ReportDiscipline() {{
        const meta = document.getElementById("w08DisciplineMeta");
        const summary = document.getElementById("w08DisciplineSummary");
        const topSites = document.getElementById("w08DisciplineTopSites");
        const benchmark = document.getElementById("w08DisciplineBenchmark");
        const recommendations = document.getElementById("w08DisciplineRecommendations");
        const site = (document.getElementById("w08DisciplineSite").value || "").trim();
        const daysRaw = (document.getElementById("w08DisciplineDays").value || "").trim();
        const params = new URLSearchParams();
        if (site) {{
          params.set("site", site);
        }}
        if (daysRaw) {{
          params.set("days", daysRaw);
        }}
        const path = "/api/ops/adoption/w08/report-discipline" + (params.toString() ? ("?" + params.toString()) : "");
        const benchmarkParams = new URLSearchParams();
        if (site) {{
          benchmarkParams.set("site", site);
        }}
        if (daysRaw) {{
          benchmarkParams.set("days", daysRaw);
        }}
        benchmarkParams.set("limit", "10");
        const benchmarkPath = "/api/ops/adoption/w08/site-benchmark?" + benchmarkParams.toString();
        try {{
          meta.textContent = "조회 중... " + path;
          const [data, benchmarkData] = await Promise.all([
            fetchJson(path, true),
            fetchJson(benchmarkPath, true).catch((err) => ({{ __error: err.message }})),
          ]);
          const metrics = data.metrics || {{}};
          meta.textContent =
            "성공: site=" + String(data.site || "ALL")
            + " | window_days=" + String(data.window_days || "-")
            + " | discipline_score=" + String(metrics.discipline_score ?? 0)
            + " | coverage=" + String(metrics.report_export_coverage_percent ?? 0) + "%";
          const summaryItems = [
            ["Site Count", metrics.site_count ?? 0],
            ["Created WOs", metrics.work_orders_created ?? 0],
            ["Completed WOs", metrics.work_orders_completed ?? 0],
            ["Missing due_at", metrics.work_orders_missing_due_at ?? 0],
            ["Missing due_at %", metrics.missing_due_rate_percent ?? 0],
            ["Invalid Priority", metrics.invalid_priority_count ?? 0],
            ["Completed w/o TS", metrics.completed_without_completed_at_count ?? 0],
            ["Overdue Open", metrics.open_overdue_count ?? 0],
            ["Overdue Rate %", metrics.overdue_rate_percent ?? 0],
            ["SLA Violation %", metrics.sla_violation_rate_percent ?? 0],
            ["DQ Issue %", metrics.data_quality_issue_rate_percent ?? 0],
            ["Inspections", metrics.inspections_created ?? 0],
            ["High Risk Inspections", metrics.inspections_high_risk ?? 0],
            ["Report Exports", metrics.report_export_count ?? 0],
            ["Report Coverage %", metrics.report_export_coverage_percent ?? 0],
            ["Discipline Score", metrics.discipline_score ?? 0],
            ["Target Met", metrics.target_met ? "YES" : "NO"],
          ];
          summary.innerHTML = summaryItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");
          topSites.innerHTML = renderTable(
            data.top_risk_sites || [],
            [
              {{ key: "site", label: "Site" }},
              {{ key: "risk_score", label: "Risk Score" }},
              {{ key: "discipline_score", label: "Discipline Score" }},
              {{ key: "missing_due_rate_percent", label: "Missing due %" }},
              {{ key: "overdue_rate_percent", label: "Overdue %" }},
              {{ key: "sla_violation_rate_percent", label: "Violation %" }},
              {{ key: "report_export_coverage_percent", label: "Coverage %" }},
            ]
          );
          const benchmarkItems = benchmarkData && !benchmarkData.__error
            ? (benchmarkData.items || [])
            : (data.site_benchmark || []);
          benchmark.innerHTML = renderTable(
            benchmarkItems,
            [
              {{ key: "site", label: "Site" }},
              {{ key: "discipline_score", label: "Discipline Score" }},
              {{ key: "risk_score", label: "Risk Score" }},
              {{ key: "work_orders_created", label: "Created WOs" }},
              {{ key: "data_quality_issue_rate_percent", label: "DQ Issue %" }},
              {{ key: "report_export_count", label: "Export Count" }},
              {{ key: "report_export_last_at", label: "Last Export At" }},
            ]
          );
          const recRows = Array.isArray(data.recommendations)
            ? data.recommendations.map((item, idx) => ({{
                no: idx + 1,
                recommendation: item,
              }}))
            : [];
          recommendations.innerHTML = renderTable(
            recRows,
            [
              {{ key: "no", label: "#" }},
              {{ key: "recommendation", label: "Recommendation" }},
            ]
          );
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          summary.innerHTML = "";
          topSites.innerHTML = renderEmpty(err.message);
          benchmark.innerHTML = renderEmpty(err.message);
          recommendations.innerHTML = renderEmpty(err.message);
        }}
      }}

      async function runW09KpiOperation() {{
        const meta = document.getElementById("w09KpiMeta");
        const summary = document.getElementById("w09KpiSummary");
        const kpiTable = document.getElementById("w09KpiTable");
        const escalationTable = document.getElementById("w09EscalationTable");
        const recommendations = document.getElementById("w09KpiRecommendations");
        const policyMeta = document.getElementById("w09PolicyMeta");
        const policyTable = document.getElementById("w09PolicyTable");
        const site = (document.getElementById("w09KpiSite").value || "").trim();
        const daysRaw = (document.getElementById("w09KpiDays").value || "").trim();
        const params = new URLSearchParams();
        if (site) {{
          params.set("site", site);
        }}
        if (daysRaw) {{
          params.set("days", daysRaw);
        }}
        const path = "/api/ops/adoption/w09/kpi-operation" + (params.toString() ? ("?" + params.toString()) : "");
        const policyPath = site
          ? "/api/ops/adoption/w09/kpi-policy?site=" + encodeURIComponent(site)
          : "";
        try {{
          meta.textContent = "조회 중.. " + path;
          if (policyPath) {{
            policyMeta.textContent = "조회 중.. " + policyPath;
          }} else {{
            policyMeta.textContent = "site 입력 시 정책 조회 가능";
            policyTable.innerHTML = renderEmpty("site를 입력하면 정책 세부를 조회합니다.");
          }}
          const [data, policyPayload] = await Promise.all([
            fetchJson(path, true),
            policyPath
              ? fetchJson(policyPath, true).catch((err) => ({{ __error: err.message }}))
              : Promise.resolve({{ __skipped: true }}),
          ]);
          const metrics = data.metrics || {{}};
          meta.textContent =
            "성공: site=" + String(data.site || "ALL")
            + " | window_days=" + String(data.window_days || "-")
            + " | overall=" + String(metrics.overall_status || "-")
            + " | red=" + String(metrics.red_count || 0)
            + " | yellow=" + String(metrics.yellow_count || 0)
            + " | green=" + String(metrics.green_count || 0);
          const summaryItems = [
            ["KPI Count", metrics.kpi_count ?? 0],
            ["Owner Assigned", metrics.owner_assigned_count ?? 0],
            ["Owner Coverage %", metrics.owner_coverage_percent ?? 0],
            ["Overall Status", metrics.overall_status || "-"],
            ["Green", metrics.green_count ?? 0],
            ["Yellow", metrics.yellow_count ?? 0],
            ["Red", metrics.red_count ?? 0],
          ];
          summary.innerHTML = summaryItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");
          kpiTable.innerHTML = renderTable(
            data.kpis || [],
            [
              {{ key: "kpi_key", label: "KPI Key" }},
              {{ key: "kpi_name", label: "KPI Name" }},
              {{ key: "owner_role", label: "Owner Role" }},
              {{ key: "actual_value", label: "Actual" }},
              {{ key: "target", label: "Target" }},
              {{ key: "green_threshold", label: "Green" }},
              {{ key: "yellow_threshold", label: "Yellow" }},
              {{ key: "status", label: "Status" }},
              {{ key: "source_api", label: "Source API" }},
            ]
          );
          escalationTable.innerHTML = renderTable(
            data.escalation_candidates || [],
            [
              {{ key: "kpi_key", label: "KPI Key" }},
              {{ key: "kpi_name", label: "KPI Name" }},
              {{ key: "actual_value", label: "Actual" }},
              {{ key: "condition", label: "Condition" }},
              {{ key: "escalate_to", label: "Escalate To" }},
              {{ key: "sla_hours", label: "SLA Hours" }},
              {{ key: "action", label: "Action" }},
            ]
          );
          const recRows = Array.isArray(data.recommendations)
            ? data.recommendations.map((item, idx) => ({{
                no: idx + 1,
                recommendation: item,
              }}))
            : [];
          recommendations.innerHTML = renderTable(
            recRows,
            [
              {{ key: "no", label: "#" }},
              {{ key: "recommendation", label: "Recommendation" }},
            ]
          );
          if (policyPayload && !policyPayload.__error && !policyPayload.__skipped) {{
            const policy = policyPayload.policy || {{}};
            policyMeta.textContent =
              "성공: key=" + String(policyPayload.policy_key || "-")
              + " | site=" + String(policyPayload.site || "default")
              + " | updated_at=" + String(policyPayload.updated_at || "-");
            policyTable.innerHTML = renderTable(
              policy.kpis || [],
              [
                {{ key: "kpi_key", label: "KPI Key" }},
                {{ key: "kpi_name", label: "KPI Name" }},
                {{ key: "owner_role", label: "Owner Role" }},
                {{ key: "direction", label: "Direction" }},
                {{ key: "green_threshold", label: "Green" }},
                {{ key: "yellow_threshold", label: "Yellow" }},
                {{ key: "target", label: "Target" }},
              ]
            );
          }} else if (policyPayload && policyPayload.__error) {{
            policyMeta.textContent = "정책 조회 실패: " + String(policyPayload.__error);
            policyTable.innerHTML = renderEmpty(String(policyPayload.__error));
          }}
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          summary.innerHTML = "";
          kpiTable.innerHTML = renderEmpty(err.message);
          escalationTable.innerHTML = renderEmpty(err.message);
          recommendations.innerHTML = renderEmpty(err.message);
          if (!site) {{
            policyMeta.textContent = "site 입력 시 정책 조회 가능";
            policyTable.innerHTML = renderEmpty("site를 입력하면 정책 세부를 조회합니다.");
          }} else {{
            policyMeta.textContent = "실패: " + err.message;
            policyTable.innerHTML = renderEmpty(err.message);
          }}
        }}
      }}

      function buildSharedTrackerConfig(phaseCode, phaseLabel) {{
        return {{
          phaseCode: phaseCode,
          phaseLabel: phaseLabel,
          apiBase: "/api/adoption/" + phaseCode + "/tracker",
          evidenceNamespace: phaseCode,
          ids: {{
            site: phaseCode + "TrackSite",
            trackerItemId: phaseCode + "TrackItemId",
            assignee: phaseCode + "TrackAssignee",
            status: phaseCode + "TrackStatus",
            completionChecked: phaseCode + "TrackCompleted",
            trackerNote: phaseCode + "TrackNote",
            evidenceFile: phaseCode + "EvidenceFile",
            evidenceNote: phaseCode + "EvidenceNote",
            evidenceListItemId: phaseCode + "EvidenceListItemId",
            completionNote: phaseCode + "CompletionNote",
            completionForce: phaseCode + "CompletionForce",
            trackerMeta: phaseCode + "TrackerMeta",
            trackerSummary: phaseCode + "TrackerSummary",
            trackerTable: phaseCode + "TrackerTable",
            readinessMeta: phaseCode + "ReadinessMeta",
            readinessCards: phaseCode + "ReadinessCards",
            readinessBlockers: phaseCode + "ReadinessBlockers",
            evidenceTable: phaseCode + "EvidenceTable",
          }},
        }};
      }}

      const SHARED_TRACKER_CONFIGS = {{
        w09: buildSharedTrackerConfig("w09", "W09"),
        w10: buildSharedTrackerConfig("w10", "W10"),
        w11: buildSharedTrackerConfig("w11", "W11"),
        w15: buildSharedTrackerConfig("w15", "W15"),
      }};

      const SHARED_TRACKER_ITEM_COLUMNS = [
        {{ key: "id", label: "ID" }},
        {{ key: "item_type", label: "Type" }},
        {{ key: "item_key", label: "Key" }},
        {{ key: "item_name", label: "Name" }},
        {{ key: "assignee", label: "Assignee" }},
        {{ key: "status", label: "Status" }},
        {{ key: "completion_checked", label: "Checked" }},
        {{ key: "evidence_count", label: "Evidence" }},
        {{ key: "updated_at", label: "Updated At" }},
      ];

      function getSharedTrackerConfig(phaseCode) {{
        const config = SHARED_TRACKER_CONFIGS[phaseCode];
        if (!config) {{
          throw new Error("Unknown shared tracker phase: " + String(phaseCode));
        }}
        return config;
      }}

      function getSharedTrackerElements(config) {{
        return {{
          meta: document.getElementById(config.ids.trackerMeta),
          summary: document.getElementById(config.ids.trackerSummary),
          table: document.getElementById(config.ids.trackerTable),
          readinessMeta: document.getElementById(config.ids.readinessMeta),
          readinessCards: document.getElementById(config.ids.readinessCards),
          readinessBlockers: document.getElementById(config.ids.readinessBlockers),
          evidenceTable: document.getElementById(config.ids.evidenceTable),
        }};
      }}

      function setSharedTrackerAuthRequired(config) {{
        const el = getSharedTrackerElements(config);
        el.meta.textContent = "토큰 저장 후 " + config.phaseLabel + " tracker API를 사용할 수 있습니다.";
        el.summary.innerHTML = "";
        el.table.innerHTML = renderEmpty("인증 토큰 필요");
        el.readinessMeta.textContent = "토큰 저장 후 완료 판정 API를 사용할 수 있습니다.";
        el.readinessCards.innerHTML = "";
        el.readinessBlockers.innerHTML = renderEmpty("인증 토큰 필요");
        el.evidenceTable.innerHTML = renderEmpty("인증 토큰 필요");
      }}

      function setSharedTrackerError(config, message) {{
        const el = getSharedTrackerElements(config);
        el.meta.textContent = "실패: " + message;
        el.summary.innerHTML = "";
        el.table.innerHTML = renderEmpty(message);
        el.readinessMeta.textContent = "실패: " + message;
        el.readinessCards.innerHTML = "";
        el.readinessBlockers.innerHTML = renderEmpty(message);
        el.evidenceTable.innerHTML = renderEmpty(message);
      }}

      function setSharedTrackerSiteDefault(config, siteValue = "HQ") {{
        const node = document.getElementById(config.ids.site);
        if (node && !node.value) {{
          node.value = siteValue;
        }}
      }}

      async function runSharedTracker(config) {{
        const el = getSharedTrackerElements(config);
        const site = (document.getElementById(config.ids.site).value || "").trim();
        if (!site) {{
          el.meta.textContent = "site 값을 입력하세요";
          el.summary.innerHTML = "";
          el.table.innerHTML = renderEmpty("site 입력이 필요합니다.");
          el.readinessMeta.textContent = "site 값을 입력하세요";
          el.readinessCards.innerHTML = "";
          el.readinessBlockers.innerHTML = renderEmpty("site 입력이 필요합니다.");
          el.evidenceTable.innerHTML = renderEmpty("site 입력이 필요합니다.");
          return;
        }}
        try {{
          el.meta.textContent = "조회 중.. " + config.phaseLabel + " tracker";
          el.readinessMeta.textContent = "조회 중.. " + config.phaseLabel + " readiness";
          const [trackerOverview, trackerItems, readiness, completion] = await Promise.all([
            fetchJson(config.apiBase + "/overview?site=" + encodeURIComponent(site), true),
            fetchJson(config.apiBase + "/items?site=" + encodeURIComponent(site) + "&limit=500", true),
            fetchJson(config.apiBase + "/readiness?site=" + encodeURIComponent(site), true),
            fetchJson(config.apiBase + "/completion?site=" + encodeURIComponent(site), true),
          ]);
          el.meta.textContent = "성공: " + config.phaseLabel + " tracker (" + site + ")";
          el.readinessMeta.textContent =
            "상태: " + String(completion.status || "active")
            + " | ready=" + (readiness.ready ? "YES" : "NO")
            + " | 마지막 판정=" + String(readiness.checked_at || "-");
          const summaryItems = [
            ["Total", trackerOverview.total_items || 0],
            ["Pending", trackerOverview.pending_count || 0],
            ["In Progress", trackerOverview.in_progress_count || 0],
            ["Done", trackerOverview.done_count || 0],
            ["Blocked", trackerOverview.blocked_count || 0],
            ["Completion %", trackerOverview.completion_rate_percent || 0],
            ["Evidence", trackerOverview.evidence_total_count || 0],
          ];
          el.summary.innerHTML = summaryItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");
          const readinessItems = [
            ["Readiness Ready", readiness.ready ? "YES" : "NO"],
            ["Readiness %", readiness.readiness_score_percent || 0],
            ["Missing Assignee", readiness.missing_assignee_count || 0],
            ["Missing Checked", readiness.missing_completion_checked_count || 0],
            ["Missing Evidence", readiness.missing_required_evidence_count || 0],
            ["Completion Status", completion.status || "active"],
            ["Completed At", completion.completed_at || "-"],
            ["Completed By", completion.completed_by || "-"],
          ];
          el.readinessCards.innerHTML = readinessItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");
          const blockers = Array.isArray(readiness.blockers) ? readiness.blockers : [];
          if (blockers.length > 0) {{
            el.readinessBlockers.innerHTML = (
              '<div class="table-wrap"><table><thead><tr><th>#</th><th>Blocker</th></tr></thead><tbody>'
              + blockers.map((item, idx) => (
                "<tr><td>" + escapeHtml(idx + 1) + "</td><td>" + escapeHtml(item) + "</td></tr>"
              )).join("")
              + "</tbody></table></div>"
            );
          }} else {{
            el.readinessBlockers.innerHTML = renderEmpty("차단 항목 없음");
          }}
          el.table.innerHTML = renderTable(trackerItems || [], SHARED_TRACKER_ITEM_COLUMNS);

          let evidenceItemId = (document.getElementById(config.ids.evidenceListItemId).value || "").trim();
          if (!evidenceItemId) {{
            evidenceItemId = (document.getElementById(config.ids.trackerItemId).value || "").trim();
          }}
          if (evidenceItemId) {{
            const evidences = await fetchJson(
              config.apiBase + "/items/" + encodeURIComponent(evidenceItemId) + "/evidence",
              true
            );
            el.evidenceTable.innerHTML = renderEvidenceTable(evidences || [], config.evidenceNamespace);
          }} else {{
            el.evidenceTable.innerHTML = renderEmpty("tracker_item_id 입력 시 증빙 파일 목록을 표시합니다.");
          }}
        }} catch (err) {{
          setSharedTrackerError(config, err.message);
        }}
      }}

      async function runSharedTrackerBootstrap(config) {{
        const meta = document.getElementById(config.ids.trackerMeta);
        const site = (document.getElementById(config.ids.site).value || "").trim();
        if (!site) {{
          meta.textContent = "site 값을 입력하세요";
          return;
        }}
        try {{
          meta.textContent = "생성 중.. " + config.phaseLabel + " tracker bootstrap";
          const data = await fetchJson(
            config.apiBase + "/bootstrap",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{ site }}),
            }}
          );
          meta.textContent = "성공: 생성 " + String(data.created_count || 0) + "건";
          await runSharedTracker(config);
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runSharedTrackerComplete(config) {{
        const meta = document.getElementById(config.ids.readinessMeta);
        const site = (document.getElementById(config.ids.site).value || "").trim();
        if (!site) {{
          meta.textContent = "site 값을 입력하세요";
          return;
        }}
        const completionNote = (document.getElementById(config.ids.completionNote).value || "").trim();
        const force = !!document.getElementById(config.ids.completionForce).checked;
        const payload = {{
          site: site,
          force: force,
        }};
        if (completionNote) {{
          payload.completion_note = completionNote;
        }}
        try {{
          meta.textContent = "실행 중.. " + config.phaseLabel + " 완료 확정";
          const result = await fetchJson(
            config.apiBase + "/complete",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify(payload),
            }}
          );
          meta.textContent =
            "성공: status=" + String(result.status || "-")
            + " | ready=" + String(result.readiness && result.readiness.ready ? "YES" : "NO")
            + " | completed_at=" + String(result.completed_at || "-");
          await runSharedTracker(config);
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          await runSharedTracker(config).catch(() => null);
        }}
      }}

      async function runSharedTrackerUpdateAndUpload(config) {{
        const meta = document.getElementById(config.ids.trackerMeta);
        const trackerItemIdRaw = (document.getElementById(config.ids.trackerItemId).value || "").trim();
        const trackerItemId = Number(trackerItemIdRaw);
        if (!trackerItemIdRaw || !Number.isFinite(trackerItemId) || trackerItemId <= 0) {{
          meta.textContent = "유효한 tracker_item_id를 입력하세요.";
          return;
        }}

        const assignee = (document.getElementById(config.ids.assignee).value || "").trim();
        const status = (document.getElementById(config.ids.status).value || "").trim();
        const completionChecked = !!document.getElementById(config.ids.completionChecked).checked;
        const note = (document.getElementById(config.ids.trackerNote).value || "").trim();
        const payload = {{}};
        if (assignee) payload.assignee = assignee;
        if (status) payload.status = status;
        if (completionChecked) {{
          payload.completion_checked = true;
        }} else if (status && status !== "done") {{
          payload.completion_checked = false;
        }}
        if (note) payload.completion_note = note;
        const fileInput = document.getElementById(config.ids.evidenceFile);
        const file = fileInput && fileInput.files ? fileInput.files[0] : null;
        const hasTrackerUpdate = Object.keys(payload).length > 0;
        if (!hasTrackerUpdate && !file) {{
          meta.textContent = "저장할 변경 또는 업로드 파일이 없습니다.";
          return;
        }}

        try {{
          meta.textContent = "저장 중.. tracker update";
          if (hasTrackerUpdate) {{
            await fetchJson(
              config.apiBase + "/items/" + encodeURIComponent(trackerItemIdRaw),
              true,
              {{
                method: "PATCH",
                headers: {{ "Content-Type": "application/json" }},
                body: JSON.stringify(payload),
              }}
            );
          }}

          if (file) {{
            const formData = new FormData();
            formData.append("file", file);
            const evidenceNote = (document.getElementById(config.ids.evidenceNote).value || "").trim();
            formData.append("note", evidenceNote);
            const token = getToken();
            if (!token) {{
              throw new Error("인증 토큰이 없습니다.");
            }}
            const uploadResp = await fetch(
              config.apiBase + "/items/" + encodeURIComponent(trackerItemIdRaw) + "/evidence",
              {{
                method: "POST",
                headers: {{
                  "X-Admin-Token": token,
                  "Accept": "application/json",
                }},
                body: formData,
              }}
            );
            const uploadText = await uploadResp.text();
            if (!uploadResp.ok) {{
              throw new Error("Evidence upload failed: HTTP " + uploadResp.status + " | " + uploadText);
            }}
            fileInput.value = "";
          }}

          meta.textContent = "성공: tracker 저장 완료";
          await runSharedTracker(config);
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
        }}
      }}

      async function runW09Tracker() {{
        await runSharedTracker(getSharedTrackerConfig("w09"));
      }}

      async function runW09Readiness() {{
        await runW09Tracker();
      }}

      async function runW09TrackerBootstrap() {{
        await runSharedTrackerBootstrap(getSharedTrackerConfig("w09"));
      }}

      async function runW09Complete() {{
        await runSharedTrackerComplete(getSharedTrackerConfig("w09"));
      }}

      async function runW09TrackerUpdateAndUpload() {{
        await runSharedTrackerUpdateAndUpload(getSharedTrackerConfig("w09"));
      }}

      const SHARED_ADOPTION_KPI_COLUMNS = [
        {{ key: "kpi_key", label: "KPI Key" }},
        {{ key: "kpi_name", label: "KPI Name" }},
        {{ key: "actual_value", label: "Actual" }},
        {{ key: "target", label: "Target" }},
        {{ key: "green_threshold", label: "Green" }},
        {{ key: "yellow_threshold", label: "Yellow" }},
        {{ key: "status", label: "Status" }},
      ];

      const SHARED_ADOPTION_REPEAT_COLUMNS = [
        {{ key: "title", label: "Title" }},
        {{ key: "count", label: "Count" }},
        {{ key: "share_percent", label: "Share %" }},
      ];

      const SHARED_ADOPTION_RECOMMENDATION_COLUMNS = [
        {{ key: "no", label: "#" }},
        {{ key: "recommendation", label: "Recommendation" }},
      ];

      const SHARED_ADOPTION_POLICY_COLUMNS_SUPPORT = [
        {{ key: "repeat_rate_green_threshold", label: "Repeat Green <= %" }},
        {{ key: "repeat_rate_yellow_threshold", label: "Repeat Yellow <= %" }},
        {{ key: "guide_publish_green_threshold", label: "Guide Green >= %" }},
        {{ key: "guide_publish_yellow_threshold", label: "Guide Yellow >= %" }},
        {{ key: "runbook_completion_green_threshold", label: "Runbook Green >= %" }},
        {{ key: "runbook_completion_yellow_threshold", label: "Runbook Yellow >= %" }},
        {{ key: "readiness_target", label: "Readiness Target" }},
        {{ key: "enabled", label: "Enabled" }},
      ];

      const SHARED_ADOPTION_POLICY_COLUMNS_EFFICIENCY = [
        {{ key: "risk_rate_green_threshold", label: "Risk Green <= %" }},
        {{ key: "risk_rate_yellow_threshold", label: "Risk Yellow <= %" }},
        {{ key: "checklist_completion_green_threshold", label: "Checklist Green >= %" }},
        {{ key: "checklist_completion_yellow_threshold", label: "Checklist Yellow >= %" }},
        {{ key: "simulation_success_green_threshold", label: "Simulation Green >= %" }},
        {{ key: "simulation_success_yellow_threshold", label: "Simulation Yellow >= %" }},
        {{ key: "readiness_target", label: "Readiness Target" }},
        {{ key: "enabled", label: "Enabled" }},
      ];

      const SHARED_ADOPTION_KPI_CONFIGS = {{
        w10: {{
          apiPath: "/api/ops/adoption/w10/self-serve",
          policyPathBase: "/api/ops/adoption/w10/support-policy",
          repeatMetricKey: "repeat_rate_percent",
          readinessMetricKey: "self_serve_readiness_score",
          repeatItemsKey: "top_repeat_titles",
          policyColumns: SHARED_ADOPTION_POLICY_COLUMNS_SUPPORT,
          summaryRows: [
            ["WO Count", "work_orders_count"],
            ["Unique Titles", "unique_titles"],
            ["Repeat WOs", "repeated_work_orders_count"],
            ["Repeat Rate %", "repeat_rate_percent"],
            ["Guide Publish %", "guide_publish_rate_percent"],
            ["Runbook Completion %", "runbook_completion_rate_percent"],
            ["Readiness Score", "self_serve_readiness_score"],
            ["Overall Status", "overall_status", "text"],
            ["Target Met", "target_met", "bool"],
          ],
        }},
        w11: {{
          apiPath: "/api/ops/adoption/w11/scale-readiness",
          policyPathBase: "/api/ops/adoption/w11/readiness-policy",
          repeatMetricKey: "repeat_rate_percent",
          readinessMetricKey: "self_serve_readiness_score",
          repeatItemsKey: "top_repeat_titles",
          policyColumns: SHARED_ADOPTION_POLICY_COLUMNS_SUPPORT,
          summaryRows: [
            ["WO Count", "work_orders_count"],
            ["Unique Titles", "unique_titles"],
            ["Repeat WOs", "repeated_work_orders_count"],
            ["Repeat Rate %", "repeat_rate_percent"],
            ["Guide Publish %", "guide_publish_rate_percent"],
            ["Runbook Completion %", "runbook_completion_rate_percent"],
            ["Readiness Score", "self_serve_readiness_score"],
            ["Overall Status", "overall_status", "text"],
            ["Target Met", "target_met", "bool"],
          ],
        }},
        w15: {{
          apiPath: "/api/ops/adoption/w15/ops-efficiency",
          policyPathBase: "/api/ops/adoption/w15/efficiency-policy",
          repeatMetricKey: "incident_repeat_rate_percent",
          readinessMetricKey: "ops_efficiency_readiness_score",
          repeatItemsKey: "top_repeat_incidents",
          policyColumns: SHARED_ADOPTION_POLICY_COLUMNS_EFFICIENCY,
          summaryRows: [
            ["Incidents", "incidents_count"],
            ["Unique Titles", "unique_titles"],
            ["Repeated Incidents", "repeated_incidents_count"],
            ["Repeat Rate %", "incident_repeat_rate_percent"],
            ["Checklist %", "checklist_completion_rate_percent"],
            ["Runbook %", "simulation_success_rate_percent"],
            ["Readiness Score", "ops_efficiency_readiness_score"],
            ["Overall Status", "overall_status", "text"],
            ["Target Met", "target_met", "bool"],
          ],
        }},
      }};

      function getSharedAdoptionKpiConfig(phaseCode) {{
        const config = SHARED_ADOPTION_KPI_CONFIGS[phaseCode];
        if (!config) {{
          throw new Error("Unknown adoption KPI phase: " + String(phaseCode));
        }}
        return config;
      }}

      function getSharedAdoptionKpiElements(phaseCode) {{
        return {{
          meta: document.getElementById(phaseCode + "KpiMeta"),
          summary: document.getElementById(phaseCode + "KpiSummary"),
          kpiTable: document.getElementById(phaseCode + "KpiTable"),
          escalationTable: document.getElementById(phaseCode + "EscalationTable"),
          recommendations: document.getElementById(phaseCode + "KpiRecommendations"),
          policyMeta: document.getElementById(phaseCode + "PolicyMeta"),
          policyTable: document.getElementById(phaseCode + "PolicyTable"),
        }};
      }}

      function buildSharedAdoptionSummaryItems(metrics, summaryRows) {{
        return summaryRows.map((row) => {{
          const label = row[0];
          const key = row[1];
          const kind = row[2] || "number";
          const rawValue = metrics[key];
          if (kind === "bool") {{
            return [label, rawValue ? "YES" : "NO"];
          }}
          if (kind === "text") {{
            return [label, rawValue || "-"];
          }}
          return [label, rawValue ?? 0];
        }});
      }}

      async function runSharedAdoptionKpiOperation(phaseCode) {{
        const config = getSharedAdoptionKpiConfig(phaseCode);
        const el = getSharedAdoptionKpiElements(phaseCode);
        const site = (document.getElementById(phaseCode + "KpiSite").value || "").trim();
        const daysRaw = (document.getElementById(phaseCode + "KpiDays").value || "").trim();
        const params = new URLSearchParams();
        if (site) {{
          params.set("site", site);
        }}
        if (daysRaw) {{
          params.set("days", daysRaw);
        }}
        const path = config.apiPath + (params.toString() ? ("?" + params.toString()) : "");
        const policyPath = site
          ? config.policyPathBase + "?site=" + encodeURIComponent(site)
          : "";

        try {{
          el.meta.textContent = "조회 중.. " + path;
          if (policyPath) {{
            el.policyMeta.textContent = "조회 중.. " + policyPath;
          }} else {{
            el.policyMeta.textContent = "site 입력 시 정책 조회 가능";
            el.policyTable.innerHTML = renderEmpty("site를 입력하면 정책 세부를 조회합니다.");
          }}
          const [data, policyPayload] = await Promise.all([
            fetchJson(path, true),
            policyPath
              ? fetchJson(policyPath, true).catch((err) => ({{ __error: err.message }}))
              : Promise.resolve({{ __skipped: true }}),
          ]);
          const metrics = data.metrics || {{}};
          el.meta.textContent =
            "성공: site=" + String(data.site || "ALL")
            + " | window_days=" + String(data.window_days || "-")
            + " | overall=" + String(metrics.overall_status || "-")
            + " | repeat_rate=" + String(metrics[config.repeatMetricKey] ?? 0) + "%"
            + " | readiness=" + String(metrics[config.readinessMetricKey] ?? 0);
          const summaryItems = buildSharedAdoptionSummaryItems(metrics, config.summaryRows);
          el.summary.innerHTML = summaryItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");
          el.kpiTable.innerHTML = renderTable(data.kpis || [], SHARED_ADOPTION_KPI_COLUMNS);
          el.escalationTable.innerHTML = renderTable(data[config.repeatItemsKey] || [], SHARED_ADOPTION_REPEAT_COLUMNS);
          const recRows = Array.isArray(data.recommendations)
            ? data.recommendations.map((item, idx) => ({{
                no: idx + 1,
                recommendation: item,
              }}))
            : [];
          el.recommendations.innerHTML = renderTable(recRows, SHARED_ADOPTION_RECOMMENDATION_COLUMNS);
          if (policyPayload && !policyPayload.__error && !policyPayload.__skipped) {{
            const policy = policyPayload.policy || {{}};
            const policySite = String(
              policyPayload.site
              || ((policyPayload.meta && policyPayload.meta.applies_to) || "default")
            );
            const policyUpdatedAt = String(
              policyPayload.updated_at
              || ((policyPayload.meta && policyPayload.meta.updated_at) || "-")
            );
            el.policyMeta.textContent =
              "성공: key=" + String(policyPayload.policy_key || "-")
              + " | site=" + policySite
              + " | updated_at=" + policyUpdatedAt;
            el.policyTable.innerHTML = renderTable([policy], config.policyColumns);
          }} else if (policyPayload && policyPayload.__error) {{
            el.policyMeta.textContent = "정책 조회 실패: " + String(policyPayload.__error);
            el.policyTable.innerHTML = renderEmpty(String(policyPayload.__error));
          }}
        }} catch (err) {{
          el.meta.textContent = "실패: " + err.message;
          el.summary.innerHTML = "";
          el.kpiTable.innerHTML = renderEmpty(err.message);
          el.escalationTable.innerHTML = renderEmpty(err.message);
          el.recommendations.innerHTML = renderEmpty(err.message);
          if (!site) {{
            el.policyMeta.textContent = "site 입력 시 정책 조회 가능";
            el.policyTable.innerHTML = renderEmpty("site를 입력하면 정책 세부를 조회합니다.");
          }} else {{
            el.policyMeta.textContent = "실패: " + err.message;
            el.policyTable.innerHTML = renderEmpty(err.message);
          }}
        }}
      }}

      async function runW10KpiOperation() {{
        await runSharedAdoptionKpiOperation("w10");
      }}

      async function runW10Tracker() {{
        await runSharedTracker(getSharedTrackerConfig("w10"));
      }}

      async function runW10Readiness() {{
        await runW10Tracker();
      }}

      async function runW10TrackerBootstrap() {{
        await runSharedTrackerBootstrap(getSharedTrackerConfig("w10"));
      }}

      async function runW10Complete() {{
        await runSharedTrackerComplete(getSharedTrackerConfig("w10"));
      }}

      async function runW10TrackerUpdateAndUpload() {{
        await runSharedTrackerUpdateAndUpload(getSharedTrackerConfig("w10"));
      }}

      async function runW11KpiOperation() {{
        await runSharedAdoptionKpiOperation("w11");
      }}

      async function runW11Tracker() {{
        await runSharedTracker(getSharedTrackerConfig("w11"));
      }}

      async function runW11Readiness() {{
        await runW11Tracker();
      }}

      async function runW11TrackerBootstrap() {{
        await runSharedTrackerBootstrap(getSharedTrackerConfig("w11"));
      }}

      async function runW11Complete() {{
        await runSharedTrackerComplete(getSharedTrackerConfig("w11"));
      }}

      async function runW11TrackerUpdateAndUpload() {{
        await runSharedTrackerUpdateAndUpload(getSharedTrackerConfig("w11"));
      }}

      async function runW15KpiOperation() {{
        await runSharedAdoptionKpiOperation("w15");
      }}

      async function runW15Tracker() {{
        await runSharedTracker(getSharedTrackerConfig("w15"));
      }}

      async function runW15Readiness() {{
        await runW15Tracker();
      }}

      async function runW15TrackerBootstrap() {{
        await runSharedTrackerBootstrap(getSharedTrackerConfig("w15"));
      }}

      async function runW15Complete() {{
        await runSharedTrackerComplete(getSharedTrackerConfig("w15"));
      }}

      async function runW15TrackerUpdateAndUpload() {{
        await runSharedTrackerUpdateAndUpload(getSharedTrackerConfig("w15"));
      }}

      async function runW07Tracker() {{
        const meta = document.getElementById("w07TrackerMeta");
        const summary = document.getElementById("w07TrackerSummary");
        const table = document.getElementById("w07TrackerTable");
        const readinessMeta = document.getElementById("w07ReadinessMeta");
        const readinessCards = document.getElementById("w07ReadinessCards");
        const readinessBlockers = document.getElementById("w07ReadinessBlockers");
        const evidenceTable = document.getElementById("w07EvidenceTable");
        const site = (document.getElementById("w07TrackSite").value || "").trim();
        if (!site) {{
          w07TrackerItemsCache = [];
          w07SelectedItemIds = new Set();
          w07ActiveItemId = null;
          w07LastReadiness = null;
          w07LastCompletion = null;
          meta.textContent = "site 값을 입력하세요.";
          summary.innerHTML = "";
          table.innerHTML = renderEmpty("site 입력이 필요합니다.");
          readinessMeta.textContent = "site 값을 입력하세요.";
          readinessCards.innerHTML = "";
          readinessBlockers.innerHTML = renderEmpty("site 입력이 필요합니다.");
          evidenceTable.innerHTML = renderEmpty("site 입력이 필요합니다.");
          renderW07SelectionMeta();
          renderW07ActionResultsPanel();
          return;
        }}
        try {{
          meta.textContent = "조회 중... W07 tracker";
          readinessMeta.textContent = "조회 중... W07 readiness";
          const [trackerOverview, trackerItems, readiness, completion] = await Promise.all([
            fetchJson("/api/adoption/w07/tracker/overview?site=" + encodeURIComponent(site), true),
            fetchJson("/api/adoption/w07/tracker/items?site=" + encodeURIComponent(site) + "&limit=500", true),
            fetchJson("/api/adoption/w07/tracker/readiness?site=" + encodeURIComponent(site), true),
            fetchJson("/api/adoption/w07/tracker/completion?site=" + encodeURIComponent(site), true),
          ]);
          w07TrackerItemsCache = Array.isArray(trackerItems) ? trackerItems : [];
          w07LastReadiness = readiness;
          w07LastCompletion = completion;
          meta.textContent = "성공: W07 tracker (" + site + ")";
          readinessMeta.textContent =
            "상태: " + String(completion.status || "active")
            + " | ready=" + (readiness.ready ? "YES" : "NO")
            + " | 마지막 판정=" + String(readiness.checked_at || "-")
            + " | filter=" + getW07FilterLabel(w07TrackerFilter);
          const summaryItems = [
            ["Total", trackerOverview.total_items || 0],
            ["Pending", trackerOverview.pending_count || 0],
            ["In Progress", trackerOverview.in_progress_count || 0],
            ["Done", trackerOverview.done_count || 0],
            ["Blocked", trackerOverview.blocked_count || 0],
            ["Completion %", trackerOverview.completion_rate_percent || 0],
            ["Evidence", trackerOverview.evidence_total_count || 0],
          ];
          summary.innerHTML = summaryItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");
          readinessCards.innerHTML = renderW07ReadinessCards(readiness, completion);
          const blockers = Array.isArray(readiness.blockers) ? readiness.blockers : [];
          if (blockers.length > 0) {{
            readinessBlockers.innerHTML = (
              '<div class="table-wrap"><table><thead><tr><th>#</th><th>Blocker</th></tr></thead><tbody>'
              + blockers.map((item, idx) => (
                "<tr><td>" + escapeHtml(idx + 1) + "</td><td>" + escapeHtml(item) + "</td></tr>"
              )).join("")
              + "</tbody></table></div>"
            );
          }} else {{
            readinessBlockers.innerHTML = renderEmpty("차단 항목 없음");
          }}
          if (w07ActiveItemId === null) {{
            const firstIncomplete = w07TrackerItemsCache.find((row) => isW07IncompleteRow(row));
            if (firstIncomplete) {{
              fillW07FormFromItem(firstIncomplete, {{ keepCurrentNote: true }});
            }}
          }} else {{
            const activeItem = getW07ItemById(w07ActiveItemId);
            if (activeItem) {{
              fillW07FormFromItem(activeItem, {{ keepCurrentNote: true }});
            }} else {{
              w07ActiveItemId = null;
            }}
          }}
          renderW07TrackerTablePanel();

          let evidenceItemId = (document.getElementById("w07EvidenceListItemId").value || "").trim();
          if (!evidenceItemId) {{
            evidenceItemId = (document.getElementById("w07TrackItemId").value || "").trim();
          }}
          if (evidenceItemId) {{
            const evidences = await fetchJson(
              "/api/adoption/w07/tracker/items/" + encodeURIComponent(evidenceItemId) + "/evidence",
              true
            );
            evidenceTable.innerHTML = renderEvidenceTable(evidences || [], "w07");
          }} else {{
            evidenceTable.innerHTML = renderEmpty("행 선택 또는 다음 미완료 버튼으로 tracker_item_id를 자동 선택하세요.");
          }}
          renderW07ActionResultsPanel();
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          summary.innerHTML = "";
          table.innerHTML = renderEmpty(err.message);
          readinessMeta.textContent = "실패: " + err.message;
          readinessCards.innerHTML = "";
          readinessBlockers.innerHTML = renderEmpty(err.message);
          evidenceTable.innerHTML = renderEmpty(err.message);
          renderW07SelectionMeta();
          renderW07ActionResultsPanel();
        }}
      }}

      async function runW07Readiness() {{
        await runW07Tracker();
      }}

      async function runW07TrackerBootstrap() {{
        const meta = document.getElementById("w07TrackerMeta");
        const site = (document.getElementById("w07TrackSite").value || "").trim();
        if (!site) {{
          meta.textContent = "site 값을 입력하세요.";
          return;
        }}
        try {{
          meta.textContent = "생성 중... W07 tracker bootstrap";
          const data = await fetchJson(
            "/api/adoption/w07/tracker/bootstrap",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{ site }}),
            }}
          );
          meta.textContent = "성공: 생성 " + String(data.created_count || 0) + "건";
          pushW07ActionResult({{
            action: "bootstrap",
            tracker_item_id: "-",
            result: "ok",
            detail: "created=" + String(data.created_count || 0),
          }});
          renderW07ActionResultsPanel();
          await runW07Tracker();
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          pushW07ActionResult({{
            action: "bootstrap",
            tracker_item_id: "-",
            result: "failed",
            detail: err.message,
          }});
          renderW07ActionResultsPanel();
        }}
      }}

      function runW07SelectVisible() {{
        const rows = getW07FilteredItems();
        rows.forEach((row) => {{
          const itemId = asInt(row.id, -1);
          if (itemId > 0) {{
            w07SelectedItemIds.add(itemId);
          }}
        }});
        renderW07TrackerTablePanel();
        document.getElementById("w07TrackerMeta").textContent =
          "성공: 현재 목록 " + String(rows.length) + "건 선택";
      }}

      function runW07ClearSelection() {{
        w07SelectedItemIds = new Set();
        renderW07TrackerTablePanel();
        document.getElementById("w07TrackerMeta").textContent = "선택 항목을 모두 해제했습니다.";
      }}

      function runW07NextIncomplete() {{
        const meta = document.getElementById("w07TrackerMeta");
        const picked = pickW07NextIncompleteItem();
        if (!picked) {{
          meta.textContent = "현재 필터에서 미완료 항목이 없습니다.";
          return;
        }}
        meta.textContent =
          "선택됨: tracker_item_id=" + String(picked.id || "-")
          + " | status=" + String(picked.status || "-")
          + " | assignee=" + String(picked.assignee || "-");
      }}

      async function runW07BulkApply() {{
        const meta = document.getElementById("w07TrackerMeta");
        const selectedIds = Array.from(w07SelectedItemIds);
        if (selectedIds.length === 0) {{
          meta.textContent = "일괄 저장할 항목을 먼저 선택하세요.";
          return;
        }}
        const assignee = (document.getElementById("w07BulkAssignee").value || "").trim();
        const status = (document.getElementById("w07BulkStatus").value || "").trim();
        const bulkChecked = !!document.getElementById("w07BulkChecked").checked;
        const payload = {{}};
        if (assignee) payload.assignee = assignee;
        if (status) payload.status = status;
        if (bulkChecked) {{
          payload.completion_checked = true;
        }} else if (status && status !== "done") {{
          payload.completion_checked = false;
        }}
        if (Object.keys(payload).length === 0) {{
          meta.textContent = "일괄 저장할 값이 없습니다. assignee/status/완료체크를 지정하세요.";
          return;
        }}
        let successCount = 0;
        let failedCount = 0;
        meta.textContent = "일괄 저장 중... " + String(selectedIds.length) + "건";
        for (const itemId of selectedIds) {{
          try {{
            await fetchJson(
              "/api/adoption/w07/tracker/items/" + encodeURIComponent(String(itemId)),
              true,
              {{
                method: "PATCH",
                headers: {{ "Content-Type": "application/json" }},
                body: JSON.stringify(payload),
              }}
            );
            successCount += 1;
            pushW07ActionResult({{
              action: "bulk_patch",
              tracker_item_id: String(itemId),
              result: "ok",
              detail: "saved",
            }});
          }} catch (err) {{
            failedCount += 1;
            pushW07ActionResult({{
              action: "bulk_patch",
              tracker_item_id: String(itemId),
              result: "failed",
              detail: err.message,
            }});
          }}
        }}
        renderW07ActionResultsPanel();
        meta.textContent =
          "일괄 저장 완료: success=" + String(successCount) + " | failed=" + String(failedCount);
        await runW07Tracker();
      }}

      async function runW07Complete(options = {{}}) {{
        const meta = document.getElementById("w07ReadinessMeta");
        const settings = Object.assign({{ triggerWeeklyAfterComplete: false }}, options || {{}});
        const site = (document.getElementById("w07TrackSite").value || "").trim();
        if (!site) {{
          meta.textContent = "site 값을 입력하세요.";
          return;
        }}
        const completionNote = (document.getElementById("w07CompletionNote").value || "").trim();
        const force = !!document.getElementById("w07CompletionForce").checked;
        if (force && !completionNote) {{
          meta.textContent = "강제 완료(force) 시 completion note를 반드시 입력하세요.";
          return;
        }}
        if (!w07LastReadiness || String(w07LastReadiness.site || "") !== site) {{
          await runW07Tracker();
        }}
        const readiness = w07LastReadiness || {{}};
        const completion = w07LastCompletion || {{}};
        const summaryLines = [
          "Site: " + site,
          "현재 상태: " + String(completion.status || "active"),
          "Ready: " + String(readiness.ready ? "YES" : "NO"),
          "Pending/InProgress/Blocked: "
            + String(readiness.pending_count || 0) + "/"
            + String(readiness.in_progress_count || 0) + "/"
            + String(readiness.blocked_count || 0),
          "Missing Assignee/Checked/Evidence: "
            + String(readiness.missing_assignee_count || 0) + "/"
            + String(readiness.missing_completion_checked_count || 0) + "/"
            + String(readiness.missing_required_evidence_count || 0),
          "Completion Note: " + (completionNote || "-"),
          "Force: " + String(force),
        ];
        const confirmed = await openW07CompleteModal(summaryLines.join("\\n"));
        if (!confirmed) {{
          meta.textContent = "취소됨: W07 완료 확정을 중단했습니다.";
          return;
        }}
        const payload = {{
          site: site,
          force: force,
        }};
        if (completionNote) {{
          payload.completion_note = completionNote;
        }}
        try {{
          meta.textContent = "실행 중... W07 완료 확정";
          const result = await fetchJson(
            "/api/adoption/w07/tracker/complete",
            true,
            {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify(payload),
            }}
          );
          meta.textContent =
            "성공: status=" + String(result.status || "-")
            + " | ready=" + String(result.readiness && result.readiness.ready ? "YES" : "NO")
            + " | completed_at=" + String(result.completed_at || "-");
          pushW07ActionResult({{
            action: "complete_site",
            tracker_item_id: "-",
            result: "ok",
            detail: "status=" + String(result.status || "-"),
          }});
          if (settings.triggerWeeklyAfterComplete) {{
            const statusValue = String(result.status || "");
            if (!statusValue.startsWith("completed")) {{
              pushW07ActionResult({{
                action: "complete_then_weekly",
                tracker_item_id: "-",
                result: "skipped",
                detail: "status=" + statusValue + " (weekly skipped)",
              }});
              meta.textContent += " | 주간실행: 완료 상태가 아니어서 건너뜀";
            }} else {{
              const weeklySiteInput = document.getElementById("w07WeeklySite");
              if (weeklySiteInput) {{
                weeklySiteInput.value = site;
              }}
              try {{
                const weeklyRunResult = await runW07WeeklyJob();
                if (!weeklyRunResult || weeklyRunResult.ok !== true) {{
                  throw new Error((weeklyRunResult && weeklyRunResult.error) || "weekly run failed");
                }}
                pushW07ActionResult({{
                  action: "complete_then_weekly",
                  tracker_item_id: "-",
                  result: "ok",
                  detail: "weekly run triggered",
                }});
                meta.textContent += " | 주간실행: 성공";
              }} catch (weeklyErr) {{
                pushW07ActionResult({{
                  action: "complete_then_weekly",
                  tracker_item_id: "-",
                  result: "failed",
                  detail: weeklyErr.message || String(weeklyErr),
                }});
                meta.textContent += " | 주간실행: 실패";
              }}
            }}
          }}
          renderW07ActionResultsPanel();
          await runW07Tracker();
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          pushW07ActionResult({{
            action: "complete_site",
            tracker_item_id: "-",
            result: "failed",
            detail: err.message,
          }});
          renderW07ActionResultsPanel();
          await runW07Tracker().catch(() => null);
        }}
      }}

      async function runW07CompleteAndWeekly() {{
        await runW07Complete({{ triggerWeeklyAfterComplete: true }});
      }}

      async function runW07DownloadCompletionPackage() {{
        const meta = document.getElementById("w07TrackerMeta");
        const site = (document.getElementById("w07TrackSite").value || "").trim();
        if (!site) {{
          meta.textContent = "site 값을 입력하세요.";
          return;
        }}
        const includeEvidence = !!document.getElementById("w07PackageIncludeEvidence").checked;
        const includeWeekly = !!document.getElementById("w07PackageIncludeWeekly").checked;
        const weeklyLimitRaw = (document.getElementById("w07PackageWeeklyLimit").value || "").trim();
        const weeklyLimit = Math.max(1, Math.min(104, asInt(weeklyLimitRaw || "26", 26)));
        const params = new URLSearchParams();
        params.set("site", site);
        params.set("include_evidence", includeEvidence ? "true" : "false");
        params.set("include_weekly", includeWeekly ? "true" : "false");
        params.set("weekly_limit", String(weeklyLimit));
        const path = "/api/adoption/w07/tracker/completion-package?" + params.toString();
        try {{
          meta.textContent = "다운로드 준비 중... " + path;
          const result = await downloadAuthFile(
            path,
            "ka-facility-os-w07-completion-package-" + site.replaceAll(" ", "_") + ".zip"
          );
          meta.textContent =
            "성공: 패키지 다운로드 완료 | file=" + String(result.fileName || "-")
            + " | bytes=" + String(result.size || 0)
            + " | sha256=" + String(result.sha256 || "-");
          pushW07ActionResult({{
            action: "completion_package_download",
            tracker_item_id: "-",
            result: "ok",
            detail: String(result.fileName || "downloaded"),
          }});
          renderW07ActionResultsPanel();
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          pushW07ActionResult({{
            action: "completion_package_download",
            tracker_item_id: "-",
            result: "failed",
            detail: err.message,
          }});
          renderW07ActionResultsPanel();
        }}
      }}

      async function runW07TrackerUpdateAndUpload() {{
        const meta = document.getElementById("w07TrackerMeta");
        const trackerItemIdRaw = (document.getElementById("w07TrackItemId").value || "").trim();
        const trackerItemId = Number(trackerItemIdRaw);
        if (!trackerItemIdRaw || !Number.isFinite(trackerItemId) || trackerItemId <= 0) {{
          meta.textContent = "표에서 tracker 항목을 선택하세요. (ID 자동 입력)";
          return;
        }}

        const assignee = (document.getElementById("w07TrackAssignee").value || "").trim();
        const status = (document.getElementById("w07TrackStatus").value || "").trim();
        const completionChecked = !!document.getElementById("w07TrackCompleted").checked;
        const note = (document.getElementById("w07TrackNote").value || "").trim();
        const payload = {{}};
        if (assignee) payload.assignee = assignee;
        if (status) payload.status = status;
        if (completionChecked) {{
          payload.completion_checked = true;
        }} else if (status && status !== "done") {{
          payload.completion_checked = false;
        }}
        if (note) payload.completion_note = note;
        const fileInput = document.getElementById("w07EvidenceFile");
        const file = fileInput && fileInput.files ? fileInput.files[0] : null;
        const hasTrackerUpdate = Object.keys(payload).length > 0;
        if (!hasTrackerUpdate && !file) {{
          meta.textContent = "저장할 변경 또는 업로드 파일이 없습니다.";
          return;
        }}

        let successCount = 0;
        let failedCount = 0;
        meta.textContent = "저장 중... tracker update";

        if (hasTrackerUpdate) {{
          try {{
            await fetchJson(
              "/api/adoption/w07/tracker/items/" + encodeURIComponent(trackerItemIdRaw),
              true,
              {{
                method: "PATCH",
                headers: {{ "Content-Type": "application/json" }},
                body: JSON.stringify(payload),
              }}
            );
            successCount += 1;
            pushW07ActionResult({{
              action: "single_patch",
              tracker_item_id: trackerItemIdRaw,
              result: "ok",
              detail: "saved",
            }});
          }} catch (err) {{
            failedCount += 1;
            pushW07ActionResult({{
              action: "single_patch",
              tracker_item_id: trackerItemIdRaw,
              result: "failed",
              detail: err.message,
            }});
          }}
        }}

        if (file) {{
          try {{
            const formData = new FormData();
            formData.append("file", file);
            const evidenceNote = (document.getElementById("w07EvidenceNote").value || "").trim();
            formData.append("note", evidenceNote);
            const token = getToken();
            if (!token) {{
              throw new Error("인증 토큰이 없습니다.");
            }}
            const uploadResp = await fetch(
              "/api/adoption/w07/tracker/items/" + encodeURIComponent(trackerItemIdRaw) + "/evidence",
              {{
                method: "POST",
                headers: {{
                  "X-Admin-Token": token,
                  "Accept": "application/json",
                }},
                body: formData,
              }}
            );
            const uploadText = await uploadResp.text();
            if (!uploadResp.ok) {{
              throw new Error("Evidence upload failed: HTTP " + uploadResp.status + " | " + uploadText);
            }}
            document.getElementById("w07EvidenceFile").value = "";
            successCount += 1;
            pushW07ActionResult({{
              action: "evidence_upload",
              tracker_item_id: trackerItemIdRaw,
              result: "ok",
              detail: String(file.name || "uploaded"),
            }});
          }} catch (err) {{
            failedCount += 1;
            pushW07ActionResult({{
              action: "evidence_upload",
              tracker_item_id: trackerItemIdRaw,
              result: "failed",
              detail: err.message,
            }});
          }}
        }}

        renderW07ActionResultsPanel();
        meta.textContent =
          "저장 완료: success=" + String(successCount) + " | failed=" + String(failedCount);
        await runW07Tracker();
      }}

      async function runW07WeeklyJob() {{
        const meta = document.getElementById("w07WeeklyMeta");
        const summary = document.getElementById("w07WeeklySummary");
        const latestTable = document.getElementById("w07WeeklyLatest");
        const site = (document.getElementById("w07WeeklySite").value || "").trim();
        const daysRaw = (document.getElementById("w07WeeklyDays").value || "").trim();
        const forceNotify = !!document.getElementById("w07WeeklyForceNotify").checked;
        const params = new URLSearchParams();
        if (site) params.set("site", site);
        if (daysRaw) params.set("days", daysRaw);
        if (forceNotify) params.set("force_notify", "true");
        try {{
          meta.textContent = "실행 중... W07 weekly run";
          const data = await fetchJson(
            "/api/ops/adoption/w07/sla-quality/run-weekly" + (params.toString() ? ("?" + params.toString()) : ""),
            true,
            {{
              method: "POST",
            }}
          );
          const signals = (data.degradation && data.degradation.signals) || {{}};
          meta.textContent =
            "성공: run#" + String(data.run_id || "-")
            + " | status=" + String(data.status || "-")
            + " | degraded=" + String(data.degradation && data.degradation.degraded ? "YES" : "NO")
            + " | cooldown=" + String(data.cooldown_active ? ("ON(" + String(data.cooldown_remaining_minutes || 0) + "m)") : "OFF");
          const summaryItems = [
            ["Run ID", data.run_id || "-"],
            ["Site", data.site || "ALL"],
            ["Window Days", data.window_days || "-"],
            ["Degraded", data.degradation && data.degradation.degraded ? "YES" : "NO"],
            ["Escalation Rate %", signals.escalation_rate_percent ?? "-"],
            ["Alert Success %", signals.alert_success_rate_percent ?? "-"],
            ["SLA Violation %", signals.sla_violation_rate_percent ?? "-"],
            ["DQ Gate", signals.data_quality_gate_pass ? "PASS" : "FAIL"],
            ["Alert Attempted", data.alert_attempted ? "YES" : "NO"],
            ["Alert Dispatched", data.alert_dispatched ? "YES" : "NO"],
            ["Archive File", data.archive_file || "-"],
          ];
          summary.innerHTML = summaryItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");
          latestTable.innerHTML = renderTable(
            [{{ run_id: data.run_id, status: data.status, finished_at: data.finished_at, site: data.site || "ALL", degraded: !!(data.degradation && data.degradation.degraded), reasons: Array.isArray(data.degradation && data.degradation.reasons) ? data.degradation.reasons.join(" | ") : "" }}],
            [
              {{ key: "run_id", label: "Run ID" }},
              {{ key: "status", label: "Status" }},
              {{ key: "finished_at", label: "Finished At" }},
              {{ key: "site", label: "Site" }},
              {{ key: "degraded", label: "Degraded" }},
              {{ key: "reasons", label: "Reasons" }},
            ]
          );
          await runW07WeeklyLatest();
          await runW07WeeklyTrends();
          return {{ ok: true, data }};
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          summary.innerHTML = "";
          latestTable.innerHTML = renderEmpty(err.message);
          return {{ ok: false, error: err.message }};
        }}
      }}

      async function runW07WeeklyLatest() {{
        const meta = document.getElementById("w07WeeklyMeta");
        const latestTable = document.getElementById("w07WeeklyLatest");
        const site = (document.getElementById("w07WeeklySite").value || "").trim();
        const params = new URLSearchParams();
        if (site) params.set("site", site);
        const path = "/api/ops/adoption/w07/sla-quality/latest-weekly" + (params.toString() ? ("?" + params.toString()) : "");
        try {{
          const data = await fetchJson(path, true);
          meta.textContent =
            "성공: latest run#" + String(data.run_id || "-")
            + " | status=" + String(data.status || "-")
            + " | degraded=" + String(data.degradation && data.degradation.degraded ? "YES" : "NO");
          latestTable.innerHTML = renderTable(
            [{{ run_id: data.run_id, status: data.status, finished_at: data.finished_at, site: data.site || "ALL", degraded: !!(data.degradation && data.degradation.degraded), reasons: Array.isArray(data.degradation && data.degradation.reasons) ? data.degradation.reasons.join(" | ") : "" }}],
            [
              {{ key: "run_id", label: "Run ID" }},
              {{ key: "status", label: "Status" }},
              {{ key: "finished_at", label: "Finished At" }},
              {{ key: "site", label: "Site" }},
              {{ key: "degraded", label: "Degraded" }},
              {{ key: "reasons", label: "Reasons" }},
            ]
          );
        }} catch (err) {{
          latestTable.innerHTML = renderEmpty(err.message);
        }}
      }}

      async function runW07WeeklyTrends() {{
        const trendsTable = document.getElementById("w07WeeklyTrends");
        const site = (document.getElementById("w07WeeklySite").value || "").trim();
        const limitRaw = (document.getElementById("w07WeeklyLimit").value || "").trim();
        const params = new URLSearchParams();
        if (site) params.set("site", site);
        if (limitRaw) params.set("limit", limitRaw);
        const path = "/api/ops/adoption/w07/sla-quality/trends" + (params.toString() ? ("?" + params.toString()) : "");
        try {{
          const data = await fetchJson(path, true);
          trendsTable.innerHTML = renderTable(
            data.points || [],
            [
              {{ key: "run_id", label: "Run ID" }},
              {{ key: "finished_at", label: "Finished At" }},
              {{ key: "site", label: "Site" }},
              {{ key: "status", label: "Status" }},
              {{ key: "degraded", label: "Degraded" }},
              {{ key: "escalation_rate_percent", label: "Escalation %" }},
              {{ key: "alert_success_rate_percent", label: "Alert Success %" }},
              {{ key: "sla_violation_rate_percent", label: "Violation %" }},
              {{ key: "median_ack_minutes", label: "Median ACK(min)" }},
              {{ key: "p90_ack_minutes", label: "p90 ACK(min)" }},
              {{ key: "median_mttr_minutes", label: "Median MTTR(min)" }},
              {{ key: "data_quality_gate_pass", label: "DQ Gate" }},
            ]
          );
        }} catch (err) {{
          trendsTable.innerHTML = renderEmpty(err.message);
        }}
      }}

      async function runAdoption() {{
        const meta = document.getElementById("adoptionMeta");
        const top = document.getElementById("adoptionTop");
        const matrix = document.getElementById("adoptionWorkflowMatrix");
        const w02Top = document.getElementById("adoptionW02Top");
        const w02Sop = document.getElementById("adoptionW02Sop");
        const w02Sandbox = document.getElementById("adoptionW02Sandbox");
        const w02Schedule = document.getElementById("adoptionW02Schedule");
        const w03Top = document.getElementById("adoptionW03Top");
        const w03Kickoff = document.getElementById("adoptionW03Kickoff");
        const w03Workshops = document.getElementById("adoptionW03Workshops");
        const w03OfficeHours = document.getElementById("adoptionW03OfficeHours");
        const w03Schedule = document.getElementById("adoptionW03Schedule");
        const w04Top = document.getElementById("adoptionW04Top");
        const w04Actions = document.getElementById("adoptionW04Actions");
        const w04Schedule = document.getElementById("adoptionW04Schedule");
        const w04Mistakes = document.getElementById("adoptionW04Mistakes");
        const w05Top = document.getElementById("adoptionW05Top");
        const w05Missions = document.getElementById("adoptionW05Missions");
        const w05Schedule = document.getElementById("adoptionW05Schedule");
        const w05HelpDocs = document.getElementById("adoptionW05HelpDocs");
        const w06Top = document.getElementById("adoptionW06Top");
        const w06Checklist = document.getElementById("adoptionW06Checklist");
        const w06Schedule = document.getElementById("adoptionW06Schedule");
        const w06RbacAudit = document.getElementById("adoptionW06RbacAudit");
        const w07Top = document.getElementById("adoptionW07Top");
        const w07Checklist = document.getElementById("adoptionW07Checklist");
        const w07Coaching = document.getElementById("adoptionW07Coaching");
        const w07Schedule = document.getElementById("adoptionW07Schedule");
        const w08Top = document.getElementById("adoptionW08Top");
        const w08Checklist = document.getElementById("adoptionW08Checklist");
        const w08Quality = document.getElementById("adoptionW08Quality");
        const w08Schedule = document.getElementById("adoptionW08Schedule");
        const w09Top = document.getElementById("adoptionW09Top");
        const w09Thresholds = document.getElementById("adoptionW09Thresholds");
        const w09Escalation = document.getElementById("adoptionW09Escalation");
        const w09Schedule = document.getElementById("adoptionW09Schedule");
        const w10Top = document.getElementById("adoptionW10Top");
        const w10Guides = document.getElementById("adoptionW10Guides");
        const w10Runbook = document.getElementById("adoptionW10Runbook");
        const w10Schedule = document.getElementById("adoptionW10Schedule");
        const w11Top = document.getElementById("adoptionW11Top");
        const w11Guides = document.getElementById("adoptionW11Guides");
        const w11Runbook = document.getElementById("adoptionW11Runbook");
        const w11Schedule = document.getElementById("adoptionW11Schedule");
        const w15Top = document.getElementById("adoptionW15Top");
        const w15Guides = document.getElementById("adoptionW15Guides");
        const w15Runbook = document.getElementById("adoptionW15Runbook");
        const w15Schedule = document.getElementById("adoptionW15Schedule");
        const weekly = document.getElementById("adoptionWeekly");
        const training = document.getElementById("adoptionTraining");
        const kpi = document.getElementById("adoptionKpi");
        try {{
          meta.textContent = "조회 중... /api/public/adoption-plan";
          const data = await fetchJson("/api/public/adoption-plan", false);
          meta.textContent = "성공: /api/public/adoption-plan";
          const topItems = [
            ["Start", data.timeline?.start_date || ""],
            ["End", data.timeline?.end_date || ""],
            ["Weeks", data.timeline?.duration_weeks || 0],
            ["Training Modules", (data.training_outline || []).length],
            ["KPI Items", (data.kpi_dashboard_items || []).length],
            ["Next Review", data.schedule_management?.next_review_date || ""]
          ];
          top.innerHTML = topItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");

          const workflowRows = (data.workflow_lock_matrix && data.workflow_lock_matrix.rows) || [];
          matrix.innerHTML = renderTable(
            workflowRows.map((row) => {{
              const perms = row.permissions || {{}};
              return {{
                role: row.role || "",
                draft: perms.DRAFT || "",
                review: perms.REVIEW || "",
                approved: perms.APPROVED || "",
                locked: perms.LOCKED || "",
              }};
            }}),
            [
              {{ key: "role", label: "Role" }},
              {{ key: "draft", label: "DRAFT" }},
              {{ key: "review", label: "REVIEW" }},
              {{ key: "approved", label: "APPROVED" }},
              {{ key: "locked", label: "LOCKED" }},
            ]
          );

          const w02 = data.w02_sop_sandbox || {{}};
          const w02TopItems = [
            ["Week", "W" + String(w02.timeline?.week || 2).padStart(2, "0")],
            ["Focus", w02.timeline?.focus || "SOP and sandbox"],
            ["SOP Count", (w02.sop_runbooks || []).length],
            ["Sandbox Count", (w02.sandbox_scenarios || []).length],
            ["Sessions", (w02.scheduled_events || []).length],
            ["Metric", w02.timeline?.success_metric || ""]
          ];
          w02Top.innerHTML = w02TopItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");

          w02Sop.innerHTML = renderTable(
            w02.sop_runbooks || [],
            [
              {{ key: "id", label: "SOP ID" }},
              {{ key: "name", label: "Name" }},
              {{ key: "target_roles", label: "Target Roles", render: (v) => Array.isArray(v) ? v.join(", ") : "" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "definition_of_done", label: "Definition of Done" }}
            ]
          );
          w02Sandbox.innerHTML = renderTable(
            (w02.sandbox_scenarios || []).map((row) => ({{
              id: row.id || "",
              module: row.module || "",
              objective: row.objective || "",
              duration_min: row.duration_min ?? "",
              pass_criteria: Array.isArray(row.pass_criteria) ? row.pass_criteria.join(" | ") : "",
            }})),
            [
              {{ key: "id", label: "Scenario ID" }},
              {{ key: "module", label: "Module" }},
              {{ key: "objective", label: "Objective" }},
              {{ key: "duration_min", label: "Duration(min)" }},
              {{ key: "pass_criteria", label: "Pass Criteria" }}
            ]
          );
          w02Schedule.innerHTML = renderTable(
            (w02.scheduled_events || []).map((row) => ({{
              date: row.date || "",
              time: (row.start_time || "") + " - " + (row.end_time || ""),
              title: row.title || "",
              owner: row.owner || "",
              output: row.output || "",
            }})),
            [
              {{ key: "date", label: "Date" }},
              {{ key: "time", label: "Time" }},
              {{ key: "title", label: "Session" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "output", label: "Output" }}
            ]
          );

          const w03 = data.w03_go_live_onboarding || {{}};
          const w03TopItems = [
            ["Week", "W" + String(w03.timeline?.week || 3).padStart(2, "0")],
            ["Focus", w03.timeline?.focus || "Go-live onboarding"],
            ["Kickoff Agenda", (w03.kickoff_agenda || []).length],
            ["Role Workshops", (w03.role_workshops || []).length],
            ["Office Hours", (w03.office_hours || []).length],
            ["Sessions", (w03.scheduled_events || []).length],
          ];
          w03Top.innerHTML = w03TopItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");

          w03Kickoff.innerHTML = renderTable(
            (w03.kickoff_agenda || []).map((row) => ({{
              id: row.id || "",
              topic: row.topic || "",
              owner: row.owner || "",
              duration_min: row.duration_min ?? "",
              objective: row.objective || "",
              expected_output: row.expected_output || "",
            }})),
            [
              {{ key: "id", label: "Kickoff ID" }},
              {{ key: "topic", label: "Topic" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "duration_min", label: "Duration(min)" }},
              {{ key: "objective", label: "Objective" }},
              {{ key: "expected_output", label: "Expected Output" }},
            ]
          );

          w03Workshops.innerHTML = renderTable(
            (w03.role_workshops || []).map((row) => ({{
              id: row.id || "",
              role: row.role || "",
              trainer: row.trainer || "",
              duration_min: row.duration_min ?? "",
              objective: row.objective || "",
              checklist: Array.isArray(row.checklist) ? row.checklist.join(" | ") : "",
              success_criteria: row.success_criteria || "",
            }})),
            [
              {{ key: "id", label: "Workshop ID" }},
              {{ key: "role", label: "Role" }},
              {{ key: "trainer", label: "Trainer" }},
              {{ key: "duration_min", label: "Duration(min)" }},
              {{ key: "objective", label: "Objective" }},
              {{ key: "checklist", label: "Checklist" }},
              {{ key: "success_criteria", label: "Success Criteria" }},
            ]
          );

          w03OfficeHours.innerHTML = renderTable(
            (w03.office_hours || []).map((row) => ({{
              date: row.date || "",
              time: (row.start_time || "") + " - " + (row.end_time || ""),
              host: row.host || "",
              focus: row.focus || "",
              channel: row.channel || "",
            }})),
            [
              {{ key: "date", label: "Date" }},
              {{ key: "time", label: "Time" }},
              {{ key: "host", label: "Host" }},
              {{ key: "focus", label: "Focus" }},
              {{ key: "channel", label: "Channel" }},
            ]
          );

          w03Schedule.innerHTML = renderTable(
            (w03.scheduled_events || []).map((row) => ({{
              date: row.date || "",
              time: (row.start_time || "") + " - " + (row.end_time || ""),
              title: row.title || "",
              owner: row.owner || "",
              output: row.output || "",
            }})),
            [
              {{ key: "date", label: "Date" }},
              {{ key: "time", label: "Time" }},
              {{ key: "title", label: "Session" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "output", label: "Output" }},
            ]
          );

          const w04 = data.w04_first_success_acceleration || {{}};
          const w04TopItems = [
            ["Week", "W" + String(w04.timeline?.week || 4).padStart(2, "0")],
            ["Focus", w04.timeline?.focus || "First success acceleration"],
            ["Coaching Actions", (w04.coaching_actions || []).length],
            ["Sessions", (w04.scheduled_events || []).length],
            ["Metric", w04.timeline?.success_metric || "Median TTV <= 15m"],
            ["Common Mistakes", "Published"],
          ];
          w04Top.innerHTML = w04TopItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");

          w04Actions.innerHTML = renderTable(
            (w04.coaching_actions || []).map((row) => ({{
              id: row.id || "",
              champion_role: row.champion_role || "",
              action: row.action || "",
              owner: row.owner || "",
              due_hint: row.due_hint || "",
              objective: row.objective || "",
              evidence_required: String(Boolean(row.evidence_required)),
            }})),
            [
              {{ key: "id", label: "Action ID" }},
              {{ key: "champion_role", label: "Champion Role" }},
              {{ key: "action", label: "Action" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "due_hint", label: "Due Hint" }},
              {{ key: "objective", label: "Objective" }},
              {{ key: "evidence_required", label: "Evidence Required" }},
            ]
          );
          w04Schedule.innerHTML = renderTable(
            (w04.scheduled_events || []).map((row) => ({{
              date: row.date || "",
              time: (row.start_time || "") + " - " + (row.end_time || ""),
              title: row.title || "",
              owner: row.owner || "",
              output: row.output || "",
            }})),
            [
              {{ key: "date", label: "Date" }},
              {{ key: "time", label: "Time" }},
              {{ key: "title", label: "Session" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "output", label: "Output" }},
            ]
          );

          const commonMistakesPath = String(w04.common_mistakes_reference || "/api/public/adoption-plan/w04/common-mistakes");
          const mistakesPayload = await fetchJson(commonMistakesPath, false).catch(() => null);
          const mistakeRows = mistakesPayload && Array.isArray(mistakesPayload.items) ? mistakesPayload.items : [];
          w04Mistakes.innerHTML = renderTable(
            mistakeRows.slice(0, 6).map((row) => ({{
              mistake: row.mistake || "",
              symptom: row.symptom || "",
              quick_fix: row.quick_fix || "",
              observed_count: row.observed_count ?? 0,
            }})),
            [
              {{ key: "mistake", label: "Mistake" }},
              {{ key: "symptom", label: "Symptom" }},
              {{ key: "quick_fix", label: "Quick Fix" }},
              {{ key: "observed_count", label: "Observed" }},
            ]
          );

          const w05 = data.w05_usage_consistency || {{}};
          const w05TopItems = [
            ["Week", "W" + String(w05.timeline?.week || 5).padStart(2, "0")],
            ["Focus", w05.timeline?.focus || "Usage consistency"],
            ["Role Missions", (w05.role_missions || []).length],
            ["Sessions", (w05.scheduled_events || []).length],
            ["Help Docs", (w05.help_docs || []).length],
            ["Metric", w05.timeline?.success_metric || "2-week retention >= 65%"],
          ];
          w05Top.innerHTML = w05TopItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");

          w05Missions.innerHTML = renderTable(
            (w05.role_missions || []).map((row) => ({{
              id: row.id || "",
              role: row.role || "",
              mission: row.mission || "",
              weekly_target: row.weekly_target || "",
              owner: row.owner || "",
              evidence_required: String(Boolean(row.evidence_required)),
              evidence_hint: row.evidence_hint || "",
            }})),
            [
              {{ key: "id", label: "Mission ID" }},
              {{ key: "role", label: "Role" }},
              {{ key: "mission", label: "Mission" }},
              {{ key: "weekly_target", label: "Weekly Target" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "evidence_required", label: "Evidence Required" }},
              {{ key: "evidence_hint", label: "Evidence Hint" }},
            ]
          );

          w05Schedule.innerHTML = renderTable(
            (w05.scheduled_events || []).map((row) => ({{
              date: row.date || "",
              time: (row.start_time || "") + " - " + (row.end_time || ""),
              title: row.title || "",
              owner: row.owner || "",
              output: row.output || "",
            }})),
            [
              {{ key: "date", label: "Date" }},
              {{ key: "time", label: "Time" }},
              {{ key: "title", label: "Session" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "output", label: "Output" }},
            ]
          );

          w05HelpDocs.innerHTML = renderTable(
            (w05.help_docs || []).map((row) => ({{
              doc_id: row.doc_id || "",
              title: row.title || "",
              audience: row.audience || "",
              problem: row.problem || "",
              quick_steps: Array.isArray(row.quick_steps) ? row.quick_steps.join(" | ") : "",
              api_refs: Array.isArray(row.api_refs) ? row.api_refs.join(", ") : "",
            }})),
            [
              {{ key: "doc_id", label: "Doc ID" }},
              {{ key: "title", label: "Title" }},
              {{ key: "audience", label: "Audience" }},
              {{ key: "problem", label: "Problem" }},
              {{ key: "quick_steps", label: "Quick Steps" }},
              {{ key: "api_refs", label: "API Refs" }},
            ]
          );

          const w06 = data.w06_operational_rhythm || {{}};
          const w06TopItems = [
            ["Week", "W" + String(w06.timeline?.week || 6).padStart(2, "0")],
            ["Focus", w06.timeline?.focus || "Operational rhythm"],
            ["Rhythm Checklist", (w06.rhythm_checklist || []).length],
            ["Sessions", (w06.scheduled_events || []).length],
            ["RBAC Audit Controls", (w06.rbac_audit_checklist || []).length],
            ["Metric", w06.timeline?.success_metric || "Weekly active rate >= 75%"],
          ];
          w06Top.innerHTML = w06TopItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");

          w06Checklist.innerHTML = renderTable(
            (w06.rhythm_checklist || []).map((row) => ({{
              id: row.id || "",
              day: row.day || "",
              routine: row.routine || "",
              owner_role: row.owner_role || "",
              definition_of_done: row.definition_of_done || "",
              evidence_hint: row.evidence_hint || "",
            }})),
            [
              {{ key: "id", label: "Checklist ID" }},
              {{ key: "day", label: "Day" }},
              {{ key: "routine", label: "Routine" }},
              {{ key: "owner_role", label: "Owner Role" }},
              {{ key: "definition_of_done", label: "Definition of Done" }},
              {{ key: "evidence_hint", label: "Evidence Hint" }},
            ]
          );

          w06Schedule.innerHTML = renderTable(
            (w06.scheduled_events || []).map((row) => ({{
              date: row.date || "",
              time: (row.start_time || "") + " - " + (row.end_time || ""),
              title: row.title || "",
              owner: row.owner || "",
              output: row.output || "",
            }})),
            [
              {{ key: "date", label: "Date" }},
              {{ key: "time", label: "Time" }},
              {{ key: "title", label: "Session" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "output", label: "Output" }},
            ]
          );

          w06RbacAudit.innerHTML = renderTable(
            (w06.rbac_audit_checklist || []).map((row) => ({{
              id: row.id || "",
              control: row.control || "",
              objective: row.objective || "",
              api_ref: row.api_ref || "",
              pass_criteria: row.pass_criteria || "",
            }})),
            [
              {{ key: "id", label: "Control ID" }},
              {{ key: "control", label: "Control" }},
              {{ key: "objective", label: "Objective" }},
              {{ key: "api_ref", label: "API Ref" }},
              {{ key: "pass_criteria", label: "Pass Criteria" }},
            ]
          );

          const w07 = data.w07_sla_quality || {{}};
          const w07TopItems = [
            ["Week", "W" + String(w07.timeline?.week || 7).padStart(2, "0")],
            ["Focus", w07.timeline?.focus || "SLA quality"],
            ["SLA Checklist", (w07.sla_checklist || []).length],
            ["Coaching Plays", (w07.coaching_plays || []).length],
            ["Sessions", (w07.scheduled_events || []).length],
            ["Metric", w07.timeline?.success_metric || "SLA response time improves >= 10%"],
          ];
          w07Top.innerHTML = w07TopItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");

          w07Checklist.innerHTML = renderTable(
            (w07.sla_checklist || []).map((row) => ({{
              id: row.id || "",
              cadence: row.cadence || "",
              control: row.control || "",
              owner_role: row.owner_role || "",
              target: row.target || "",
              definition_of_done: row.definition_of_done || "",
              evidence_hint: row.evidence_hint || "",
            }})),
            [
              {{ key: "id", label: "Checklist ID" }},
              {{ key: "cadence", label: "Cadence" }},
              {{ key: "control", label: "Control" }},
              {{ key: "owner_role", label: "Owner Role" }},
              {{ key: "target", label: "Target" }},
              {{ key: "definition_of_done", label: "Definition of Done" }},
              {{ key: "evidence_hint", label: "Evidence Hint" }},
            ]
          );

          w07Coaching.innerHTML = renderTable(
            (w07.coaching_plays || []).map((row) => ({{
              id: row.id || "",
              trigger: row.trigger || "",
              play: row.play || "",
              owner: row.owner || "",
              expected_impact: row.expected_impact || "",
              evidence_hint: row.evidence_hint || "",
              api_ref: row.api_ref || "",
            }})),
            [
              {{ key: "id", label: "Play ID" }},
              {{ key: "trigger", label: "Trigger" }},
              {{ key: "play", label: "Play" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "expected_impact", label: "Expected Impact" }},
              {{ key: "evidence_hint", label: "Evidence Hint" }},
              {{ key: "api_ref", label: "API Ref" }},
            ]
          );

          w07Schedule.innerHTML = renderTable(
            (w07.scheduled_events || []).map((row) => ({{
              date: row.date || "",
              time: (row.start_time || "") + " - " + (row.end_time || ""),
              title: row.title || "",
              owner: row.owner || "",
              output: row.output || "",
            }})),
            [
              {{ key: "date", label: "Date" }},
              {{ key: "time", label: "Time" }},
              {{ key: "title", label: "Session" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "output", label: "Output" }},
            ]
          );

          const w08 = data.w08_report_discipline || {{}};
          const w08TopItems = [
            ["Week", "W" + String(w08.timeline?.week || 8).padStart(2, "0")],
            ["Focus", w08.timeline?.focus || "Report discipline"],
            ["Checklist", (w08.report_discipline_checklist || []).length],
            ["DQ Controls", (w08.data_quality_controls || []).length],
            ["Sessions", (w08.scheduled_events || []).length],
            ["Metric", w08.timeline?.success_metric || "Monthly report on-time rate >= 95%"],
          ];
          w08Top.innerHTML = w08TopItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");

          w08Checklist.innerHTML = renderTable(
            (w08.report_discipline_checklist || []).map((row) => ({{
              id: row.id || "",
              cadence: row.cadence || "",
              discipline: row.discipline || "",
              owner_role: row.owner_role || "",
              target: row.target || "",
              definition_of_done: row.definition_of_done || "",
              api_ref: row.api_ref || "",
            }})),
            [
              {{ key: "id", label: "Checklist ID" }},
              {{ key: "cadence", label: "Cadence" }},
              {{ key: "discipline", label: "Discipline" }},
              {{ key: "owner_role", label: "Owner Role" }},
              {{ key: "target", label: "Target" }},
              {{ key: "definition_of_done", label: "Definition of Done" }},
              {{ key: "api_ref", label: "API Ref" }},
            ]
          );

          w08Quality.innerHTML = renderTable(
            (w08.data_quality_controls || []).map((row) => ({{
              id: row.id || "",
              control: row.control || "",
              objective: row.objective || "",
              api_ref: row.api_ref || "",
              pass_criteria: row.pass_criteria || "",
            }})),
            [
              {{ key: "id", label: "Control ID" }},
              {{ key: "control", label: "Control" }},
              {{ key: "objective", label: "Objective" }},
              {{ key: "api_ref", label: "API Ref" }},
              {{ key: "pass_criteria", label: "Pass Criteria" }},
            ]
          );

          w08Schedule.innerHTML = renderTable(
            (w08.scheduled_events || []).map((row) => ({{
              date: row.date || "",
              time: (row.start_time || "") + " - " + (row.end_time || ""),
              title: row.title || "",
              owner: row.owner || "",
              output: row.output || "",
            }})),
            [
              {{ key: "date", label: "Date" }},
              {{ key: "time", label: "Time" }},
              {{ key: "title", label: "Session" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "output", label: "Output" }},
            ]
          );

          const w09 = data.w09_kpi_operation || {{}};
          const w09TopItems = [
            ["Week", "W" + String(w09.timeline?.week || 9).padStart(2, "0")],
            ["Focus", w09.timeline?.focus || "KPI operation"],
            ["Threshold KPIs", (w09.kpi_threshold_matrix || []).length],
            ["Escalation Rules", (w09.escalation_map || []).length],
            ["Sessions", (w09.scheduled_events || []).length],
            ["Metric", w09.timeline?.success_metric || "Green ratio >= 80%"],
          ];
          w09Top.innerHTML = w09TopItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");

          w09Thresholds.innerHTML = renderTable(
            (w09.kpi_threshold_matrix || []).map((row) => ({{
              id: row.id || "",
              kpi_name: row.kpi_name || "",
              kpi_key: row.kpi_key || "",
              owner_role: row.owner_role || "",
              direction: row.direction || "",
              green_threshold: row.green_threshold ?? "",
              yellow_threshold: row.yellow_threshold ?? "",
              target: row.target || "",
              source_api: row.source_api || "",
            }})),
            [
              {{ key: "id", label: "KPI ID" }},
              {{ key: "kpi_name", label: "KPI Name" }},
              {{ key: "kpi_key", label: "KPI Key" }},
              {{ key: "owner_role", label: "Owner Role" }},
              {{ key: "direction", label: "Direction" }},
              {{ key: "green_threshold", label: "Green" }},
              {{ key: "yellow_threshold", label: "Yellow" }},
              {{ key: "target", label: "Target" }},
              {{ key: "source_api", label: "Source API" }},
            ]
          );

          w09Escalation.innerHTML = renderTable(
            (w09.escalation_map || []).map((row) => ({{
              id: row.id || "",
              kpi_key: row.kpi_key || "",
              condition: row.condition || "",
              escalate_to: row.escalate_to || "",
              sla_hours: row.sla_hours ?? "",
              action: row.action || "",
            }})),
            [
              {{ key: "id", label: "Rule ID" }},
              {{ key: "kpi_key", label: "KPI Key" }},
              {{ key: "condition", label: "Condition" }},
              {{ key: "escalate_to", label: "Escalate To" }},
              {{ key: "sla_hours", label: "SLA Hours" }},
              {{ key: "action", label: "Action" }},
            ]
          );

          w09Schedule.innerHTML = renderTable(
            (w09.scheduled_events || []).map((row) => ({{
              date: row.date || "",
              time: (row.start_time || "") + " - " + (row.end_time || ""),
              title: row.title || "",
              owner: row.owner || "",
              output: row.output || "",
            }})),
            [
              {{ key: "date", label: "Date" }},
              {{ key: "time", label: "Time" }},
              {{ key: "title", label: "Session" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "output", label: "Output" }},
            ]
          );

          const w10 = data.w10_self_serve_support || {{}};
          const w10TopItems = [
            ["Week", "W" + String(w10.timeline?.week || 10).padStart(2, "0")],
            ["Focus", w10.timeline?.focus || "Self-serve support"],
            ["Guides", (w10.self_serve_guides || []).length],
            ["Runbook", (w10.troubleshooting_runbook || []).length],
            ["Sessions", (w10.scheduled_events || []).length],
            ["Metric", w10.timeline?.success_metric || "Support repeat rate down >= 20%"],
          ];
          w10Top.innerHTML = w10TopItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");

          w10Guides.innerHTML = renderTable(
            (w10.self_serve_guides || []).map((row) => ({{
              id: row.id || "",
              title: row.title || "",
              problem_cluster: row.problem_cluster || "",
              owner_role: row.owner_role || "",
              target: row.target || "",
              source_api: row.source_api || "",
            }})),
            [
              {{ key: "id", label: "Guide ID" }},
              {{ key: "title", label: "Title" }},
              {{ key: "problem_cluster", label: "Problem Cluster" }},
              {{ key: "owner_role", label: "Owner Role" }},
              {{ key: "target", label: "Target" }},
              {{ key: "source_api", label: "Source API" }},
            ]
          );

          w10Runbook.innerHTML = renderTable(
            (w10.troubleshooting_runbook || []).map((row) => ({{
              id: row.id || "",
              module: row.module || "",
              symptom: row.symptom || "",
              owner_role: row.owner_role || "",
              definition_of_done: row.definition_of_done || "",
              api_ref: row.api_ref || "",
            }})),
            [
              {{ key: "id", label: "Runbook ID" }},
              {{ key: "module", label: "Module" }},
              {{ key: "symptom", label: "Symptom" }},
              {{ key: "owner_role", label: "Owner Role" }},
              {{ key: "definition_of_done", label: "Definition of Done" }},
              {{ key: "api_ref", label: "API Ref" }},
            ]
          );

          w10Schedule.innerHTML = renderTable(
            (w10.scheduled_events || []).map((row) => ({{
              date: row.date || "",
              time: (row.start_time || "") + " - " + (row.end_time || ""),
              title: row.title || "",
              owner: row.owner || "",
              output: row.output || "",
            }})),
            [
              {{ key: "date", label: "Date" }},
              {{ key: "time", label: "Time" }},
              {{ key: "title", label: "Session" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "output", label: "Output" }},
            ]
          );

          const w11 = data.w11_scale_readiness || {{}};
          const w11TopItems = [
            ["Week", "W" + String(w11.timeline?.week || 11).padStart(2, "0")],
            ["Focus", w11.timeline?.focus || "Scale readiness"],
            ["Guides", (w11.self_serve_guides || []).length],
            ["Runbook", (w11.troubleshooting_runbook || []).length],
            ["Sessions", (w11.scheduled_events || []).length],
            ["Metric", w11.timeline?.success_metric || "New-site simulation success >= 90%"],
          ];
          w11Top.innerHTML = w11TopItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");

          w11Guides.innerHTML = renderTable(
            (w11.self_serve_guides || []).map((row) => ({{
              id: row.id || "",
              title: row.title || "",
              problem_cluster: row.problem_cluster || "",
              owner_role: row.owner_role || "",
              target: row.target || "",
              source_api: row.source_api || "",
            }})),
            [
              {{ key: "id", label: "Checklist ID" }},
              {{ key: "title", label: "Title" }},
              {{ key: "problem_cluster", label: "Readiness Cluster" }},
              {{ key: "owner_role", label: "Owner Role" }},
              {{ key: "target", label: "Target" }},
              {{ key: "source_api", label: "Source API" }},
            ]
          );

          w11Runbook.innerHTML = renderTable(
            (w11.troubleshooting_runbook || []).map((row) => ({{
              id: row.id || "",
              module: row.module || "",
              symptom: row.symptom || "",
              owner_role: row.owner_role || "",
              definition_of_done: row.definition_of_done || "",
              api_ref: row.api_ref || "",
            }})),
            [
              {{ key: "id", label: "Simulation ID" }},
              {{ key: "module", label: "Module" }},
              {{ key: "symptom", label: "Scenario" }},
              {{ key: "owner_role", label: "Owner Role" }},
              {{ key: "definition_of_done", label: "Definition of Done" }},
              {{ key: "api_ref", label: "API Ref" }},
            ]
          );

          w11Schedule.innerHTML = renderTable(
            (w11.scheduled_events || []).map((row) => ({{
              date: row.date || "",
              time: (row.start_time || "") + " - " + (row.end_time || ""),
              title: row.title || "",
              owner: row.owner || "",
              output: row.output || "",
            }})),
            [
              {{ key: "date", label: "Date" }},
              {{ key: "time", label: "Time" }},
              {{ key: "title", label: "Session" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "output", label: "Output" }},
            ]
          );

          const w15 = data.w15_operations_efficiency || {{}};
          const w15TopItems = [
            ["Week", "W" + String(w15.timeline?.week || 15).padStart(2, "0")],
            ["Focus", w15.timeline?.focus || "Operations efficiency"],
            ["Guides", (w15.self_serve_guides || []).length],
            ["Runbook", (w15.troubleshooting_runbook || []).length],
            ["Sessions", (w15.scheduled_events || []).length],
            ["Metric", w15.timeline?.success_metric || "Operations efficiency readiness >= 75"],
          ];
          w15Top.innerHTML = w15TopItems.map((x) => (
            '<div class="card"><div class="k">' + escapeHtml(x[0]) + '</div><div class="v">' + escapeHtml(x[1]) + "</div></div>"
          )).join("");

          w15Guides.innerHTML = renderTable(
            (w15.self_serve_guides || []).map((row) => ({{
              id: row.id || "",
              title: row.title || "",
              problem_cluster: row.problem_cluster || "",
              owner_role: row.owner_role || "",
              target: row.target || "",
              source_api: row.source_api || "",
            }})),
            [
              {{ key: "id", label: "Guide ID" }},
              {{ key: "title", label: "Title" }},
              {{ key: "problem_cluster", label: "Problem Cluster" }},
              {{ key: "owner_role", label: "Owner Role" }},
              {{ key: "target", label: "Target" }},
              {{ key: "source_api", label: "Source API" }},
            ]
          );

          w15Runbook.innerHTML = renderTable(
            (w15.troubleshooting_runbook || []).map((row) => ({{
              id: row.id || "",
              module: row.module || "",
              symptom: row.symptom || "",
              owner_role: row.owner_role || "",
              definition_of_done: row.definition_of_done || "",
              api_ref: row.api_ref || "",
            }})),
            [
              {{ key: "id", label: "Runbook ID" }},
              {{ key: "module", label: "Module" }},
              {{ key: "symptom", label: "Scenario" }},
              {{ key: "owner_role", label: "Owner Role" }},
              {{ key: "definition_of_done", label: "Definition of Done" }},
              {{ key: "api_ref", label: "API Ref" }},
            ]
          );

          w15Schedule.innerHTML = renderTable(
            (w15.scheduled_events || []).map((row) => ({{
              date: row.date || "",
              time: (row.start_time || "") + " - " + (row.end_time || ""),
              title: row.title || "",
              owner: row.owner || "",
              output: row.output || "",
            }})),
            [
              {{ key: "date", label: "Date" }},
              {{ key: "time", label: "Time" }},
              {{ key: "title", label: "Session" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "output", label: "Output" }},
            ]
          );

          weekly.innerHTML = renderTable(
            data.weekly_execution || [],
            [
              {{ key: "week", label: "Week", render: (v) => "W" + String(v).padStart(2, "0") }},
              {{ key: "phase", label: "Phase" }},
              {{ key: "focus", label: "Focus" }},
              {{ key: "owner", label: "Owner" }},
              {{ key: "success_metric", label: "Success Metric" }}
            ]
          );
          training.innerHTML = renderTable(
            data.training_outline || [],
            [
              {{ key: "module", label: "Module" }},
              {{ key: "audience", label: "Audience" }},
              {{ key: "duration_min", label: "Duration(min)" }},
              {{ key: "format", label: "Format" }}
            ]
          );
          kpi.innerHTML = renderTable(
            data.kpi_dashboard_items || [],
            [
              {{ key: "id", label: "ID" }},
              {{ key: "name", label: "Name" }},
              {{ key: "target", label: "Target" }},
              {{ key: "frequency", label: "Frequency" }}
            ]
          );
          if (getToken()) {{
            runW02Tracker().catch(() => null);
            runW03Tracker().catch(() => null);
            runW04Tracker().catch(() => null);
            runW04FunnelBlockers().catch(() => null);
            runW05Consistency().catch(() => null);
            runW06Rhythm().catch(() => null);
            runW07SlaQuality().catch(() => null);
            runW08ReportDiscipline().catch(() => null);
            runW09KpiOperation().catch(() => null);
            runW09Tracker().catch(() => null);
            runW10KpiOperation().catch(() => null);
            runW10Tracker().catch(() => null);
            runW11KpiOperation().catch(() => null);
            runW11Tracker().catch(() => null);
            runW15KpiOperation().catch(() => null);
            runW15Tracker().catch(() => null);
          }} else {{
            const w02TrackerMeta = document.getElementById("w02TrackerMeta");
            const w02TrackerSummary = document.getElementById("w02TrackerSummary");
            const w02TrackerTable = document.getElementById("w02TrackerTable");
            const w02ReadinessMeta = document.getElementById("w02ReadinessMeta");
            const w02ReadinessCards = document.getElementById("w02ReadinessCards");
            const w02ReadinessBlockers = document.getElementById("w02ReadinessBlockers");
            const w02EvidenceTable = document.getElementById("w02EvidenceTable");
            w02TrackerMeta.textContent = "토큰 저장 후 실행 추적 API를 사용할 수 있습니다.";
            w02TrackerSummary.innerHTML = "";
            w02TrackerTable.innerHTML = renderEmpty("인증 토큰 필요");
            w02ReadinessMeta.textContent = "토큰 저장 후 완료 판정 API를 사용할 수 있습니다.";
            w02ReadinessCards.innerHTML = "";
            w02ReadinessBlockers.innerHTML = renderEmpty("인증 토큰 필요");
            w02EvidenceTable.innerHTML = renderEmpty("인증 토큰 필요");

            const w03TrackerMeta = document.getElementById("w03TrackerMeta");
            const w03TrackerSummary = document.getElementById("w03TrackerSummary");
            const w03TrackerTable = document.getElementById("w03TrackerTable");
            const w03ReadinessMeta = document.getElementById("w03ReadinessMeta");
            const w03ReadinessCards = document.getElementById("w03ReadinessCards");
            const w03ReadinessBlockers = document.getElementById("w03ReadinessBlockers");
            const w03EvidenceTable = document.getElementById("w03EvidenceTable");
            w03TrackerMeta.textContent = "토큰 저장 후 실행 추적 API를 사용할 수 있습니다.";
            w03TrackerSummary.innerHTML = "";
            w03TrackerTable.innerHTML = renderEmpty("인증 토큰 필요");
            w03ReadinessMeta.textContent = "토큰 저장 후 완료 판정 API를 사용할 수 있습니다.";
            w03ReadinessCards.innerHTML = "";
            w03ReadinessBlockers.innerHTML = renderEmpty("인증 토큰 필요");
            w03EvidenceTable.innerHTML = renderEmpty("인증 토큰 필요");

            const w04FunnelMeta = document.getElementById("w04FunnelMeta");
            const w04FunnelSummary = document.getElementById("w04FunnelSummary");
            const w04FunnelStages = document.getElementById("w04FunnelStages");
            const w04BlockerTable = document.getElementById("w04BlockerTable");
            w04FunnelMeta.textContent = "토큰 저장 후 W04 funnel API를 사용할 수 있습니다.";
            w04FunnelSummary.innerHTML = "";
            w04FunnelStages.innerHTML = renderEmpty("인증 토큰 필요");
            w04BlockerTable.innerHTML = renderEmpty("인증 토큰 필요");

            const w04TrackerMeta = document.getElementById("w04TrackerMeta");
            const w04TrackerSummary = document.getElementById("w04TrackerSummary");
            const w04TrackerTable = document.getElementById("w04TrackerTable");
            const w04ReadinessMeta = document.getElementById("w04ReadinessMeta");
            const w04ReadinessCards = document.getElementById("w04ReadinessCards");
            const w04ReadinessBlockers = document.getElementById("w04ReadinessBlockers");
            const w04EvidenceTable = document.getElementById("w04EvidenceTable");
            w04TrackerMeta.textContent = "토큰 저장 후 실행 추적 API를 사용할 수 있습니다.";
            w04TrackerSummary.innerHTML = "";
            w04TrackerTable.innerHTML = renderEmpty("인증 토큰 필요");
            w04ReadinessMeta.textContent = "토큰 저장 후 완료 판정 API를 사용할 수 있습니다.";
            w04ReadinessCards.innerHTML = "";
            w04ReadinessBlockers.innerHTML = renderEmpty("인증 토큰 필요");
            w04EvidenceTable.innerHTML = renderEmpty("인증 토큰 필요");

            const w05ConsistencyMeta = document.getElementById("w05ConsistencyMeta");
            const w05ConsistencySummary = document.getElementById("w05ConsistencySummary");
            const w05ConsistencyTopSites = document.getElementById("w05ConsistencyTopSites");
            const w05ConsistencyRecommendations = document.getElementById("w05ConsistencyRecommendations");
            w05ConsistencyMeta.textContent = "토큰 저장 후 W05 consistency API를 사용할 수 있습니다.";
            w05ConsistencySummary.innerHTML = "";
            w05ConsistencyTopSites.innerHTML = renderEmpty("인증 토큰 필요");
            w05ConsistencyRecommendations.innerHTML = renderEmpty("인증 토큰 필요");

            const w06RhythmMeta = document.getElementById("w06RhythmMeta");
            const w06RhythmSummary = document.getElementById("w06RhythmSummary");
            const w06RhythmRoleCoverage = document.getElementById("w06RhythmRoleCoverage");
            const w06RhythmSiteActivity = document.getElementById("w06RhythmSiteActivity");
            const w06RhythmRecommendations = document.getElementById("w06RhythmRecommendations");
            w06RhythmMeta.textContent = "토큰 저장 후 W06 rhythm API를 사용할 수 있습니다.";
            w06RhythmSummary.innerHTML = "";
            w06RhythmRoleCoverage.innerHTML = renderEmpty("인증 토큰 필요");
            w06RhythmSiteActivity.innerHTML = renderEmpty("인증 토큰 필요");
            w06RhythmRecommendations.innerHTML = renderEmpty("인증 토큰 필요");

            const w07QualityMeta = document.getElementById("w07QualityMeta");
            const w07QualitySummary = document.getElementById("w07QualitySummary");
            const w07AutomationReadiness = document.getElementById("w07AutomationReadiness");
            const w07QualityTopSites = document.getElementById("w07QualityTopSites");
            const w07QualityRecommendations = document.getElementById("w07QualityRecommendations");
            w07QualityMeta.textContent = "토큰 저장 후 W07 SLA quality API를 사용할 수 있습니다.";
            w07QualitySummary.innerHTML = "";
            w07AutomationReadiness.innerHTML = renderEmpty("인증 토큰 필요");
            w07QualityTopSites.innerHTML = renderEmpty("인증 토큰 필요");
            w07QualityRecommendations.innerHTML = renderEmpty("인증 토큰 필요");

            const w08DisciplineMeta = document.getElementById("w08DisciplineMeta");
            const w08DisciplineSummary = document.getElementById("w08DisciplineSummary");
            const w08DisciplineTopSites = document.getElementById("w08DisciplineTopSites");
            const w08DisciplineBenchmark = document.getElementById("w08DisciplineBenchmark");
            const w08DisciplineRecommendations = document.getElementById("w08DisciplineRecommendations");
            w08DisciplineMeta.textContent = "토큰 저장 후 W08 report discipline API를 사용할 수 있습니다.";
            w08DisciplineSummary.innerHTML = "";
            w08DisciplineTopSites.innerHTML = renderEmpty("인증 토큰 필요");
            w08DisciplineBenchmark.innerHTML = renderEmpty("인증 토큰 필요");
            w08DisciplineRecommendations.innerHTML = renderEmpty("인증 토큰 필요");

            const sharedKpiAuthConfigs = [
              {{ phaseCode: "w09", kpiApiLabel: "W09 KPI operation", policyApiLabel: "W09 policy" }},
              {{ phaseCode: "w10", kpiApiLabel: "W10 self-serve", policyApiLabel: "W10 support policy" }},
              {{ phaseCode: "w11", kpiApiLabel: "W11 scale-readiness", policyApiLabel: "W11 readiness policy" }},
              {{ phaseCode: "w15", kpiApiLabel: "W15 ops-efficiency", policyApiLabel: "W15 efficiency policy" }},
            ];
            sharedKpiAuthConfigs.forEach((item) => {{
              document.getElementById(item.phaseCode + "KpiMeta").textContent =
                "토큰 저장 후 " + item.kpiApiLabel + " API를 사용할 수 있습니다.";
              document.getElementById(item.phaseCode + "KpiSummary").innerHTML = "";
              document.getElementById(item.phaseCode + "KpiTable").innerHTML = renderEmpty("인증 토큰 필요");
              document.getElementById(item.phaseCode + "EscalationTable").innerHTML = renderEmpty("인증 토큰 필요");
              document.getElementById(item.phaseCode + "KpiRecommendations").innerHTML = renderEmpty("인증 토큰 필요");
              document.getElementById(item.phaseCode + "PolicyMeta").textContent =
                "토큰 저장 후 " + item.policyApiLabel + " API를 사용할 수 있습니다.";
              document.getElementById(item.phaseCode + "PolicyTable").innerHTML = renderEmpty("인증 토큰 필요");
            }});
            ["w09", "w10", "w11", "w15"].forEach((phaseCode) => {{
              setSharedTrackerAuthRequired(getSharedTrackerConfig(phaseCode));
            }});

            w07TrackerItemsCache = [];
            w07SelectedItemIds = new Set();
            w07ActiveItemId = null;
            w07LastReadiness = null;
            w07LastCompletion = null;
            document.getElementById("w07TrackerMeta").textContent = "토큰 저장 후 W07 tracker API를 사용할 수 있습니다.";
            document.getElementById("w07SelectionMeta").textContent = "필터: ALL | 표시: 0/0 | 선택: 0";
            document.getElementById("w07TrackerSummary").innerHTML = "";
            document.getElementById("w07TrackerTable").innerHTML = renderEmpty("인증 토큰 필요");
            document.getElementById("w07ReadinessMeta").textContent = "토큰 저장 후 완료 판정 API를 사용할 수 있습니다.";
            document.getElementById("w07ReadinessCards").innerHTML = "";
            document.getElementById("w07ReadinessBlockers").innerHTML = renderEmpty("인증 토큰 필요");
            document.getElementById("w07EvidenceTable").innerHTML = renderEmpty("인증 토큰 필요");
            renderW07ActionResultsPanel();
          }}
        }} catch (err) {{
          meta.textContent = "실패: " + err.message;
          top.innerHTML = "";
          matrix.innerHTML = renderEmpty(err.message);
          w02Top.innerHTML = "";
          w02Sop.innerHTML = renderEmpty(err.message);
          w02Sandbox.innerHTML = renderEmpty(err.message);
          w02Schedule.innerHTML = renderEmpty(err.message);
          w03Top.innerHTML = "";
          w03Kickoff.innerHTML = renderEmpty(err.message);
          w03Workshops.innerHTML = renderEmpty(err.message);
          w03OfficeHours.innerHTML = renderEmpty(err.message);
          w03Schedule.innerHTML = renderEmpty(err.message);
          w04Top.innerHTML = "";
          w04Actions.innerHTML = renderEmpty(err.message);
          w04Schedule.innerHTML = renderEmpty(err.message);
          w04Mistakes.innerHTML = renderEmpty(err.message);
          w05Top.innerHTML = "";
          w05Missions.innerHTML = renderEmpty(err.message);
          w05Schedule.innerHTML = renderEmpty(err.message);
          w05HelpDocs.innerHTML = renderEmpty(err.message);
          w06Top.innerHTML = "";
          w06Checklist.innerHTML = renderEmpty(err.message);
          w06Schedule.innerHTML = renderEmpty(err.message);
          w06RbacAudit.innerHTML = renderEmpty(err.message);
          w07Top.innerHTML = "";
          w07Checklist.innerHTML = renderEmpty(err.message);
          w07Coaching.innerHTML = renderEmpty(err.message);
          w07Schedule.innerHTML = renderEmpty(err.message);
          w08Top.innerHTML = "";
          w08Checklist.innerHTML = renderEmpty(err.message);
          w08Quality.innerHTML = renderEmpty(err.message);
          w08Schedule.innerHTML = renderEmpty(err.message);
          w10Top.innerHTML = "";
          w10Guides.innerHTML = renderEmpty(err.message);
          w10Runbook.innerHTML = renderEmpty(err.message);
          w10Schedule.innerHTML = renderEmpty(err.message);
          w11Top.innerHTML = "";
          w11Guides.innerHTML = renderEmpty(err.message);
          w11Runbook.innerHTML = renderEmpty(err.message);
          w11Schedule.innerHTML = renderEmpty(err.message);
          w15Top.innerHTML = "";
          w15Guides.innerHTML = renderEmpty(err.message);
          w15Runbook.innerHTML = renderEmpty(err.message);
          w15Schedule.innerHTML = renderEmpty(err.message);
          document.getElementById("w05ConsistencyMeta").textContent = "실패: " + err.message;
          document.getElementById("w05ConsistencySummary").innerHTML = "";
          document.getElementById("w05ConsistencyTopSites").innerHTML = renderEmpty(err.message);
          document.getElementById("w05ConsistencyRecommendations").innerHTML = renderEmpty(err.message);
          document.getElementById("w06RhythmMeta").textContent = "실패: " + err.message;
          document.getElementById("w06RhythmSummary").innerHTML = "";
          document.getElementById("w06RhythmRoleCoverage").innerHTML = renderEmpty(err.message);
          document.getElementById("w06RhythmSiteActivity").innerHTML = renderEmpty(err.message);
          document.getElementById("w06RhythmRecommendations").innerHTML = renderEmpty(err.message);
          document.getElementById("w07QualityMeta").textContent = "실패: " + err.message;
          document.getElementById("w07QualitySummary").innerHTML = "";
          document.getElementById("w07AutomationReadiness").innerHTML = renderEmpty(err.message);
          document.getElementById("w07QualityTopSites").innerHTML = renderEmpty(err.message);
          document.getElementById("w07QualityRecommendations").innerHTML = renderEmpty(err.message);
          document.getElementById("w08DisciplineMeta").textContent = "실패: " + err.message;
          document.getElementById("w08DisciplineSummary").innerHTML = "";
          document.getElementById("w08DisciplineTopSites").innerHTML = renderEmpty(err.message);
          document.getElementById("w08DisciplineBenchmark").innerHTML = renderEmpty(err.message);
          document.getElementById("w08DisciplineRecommendations").innerHTML = renderEmpty(err.message);
          w09Top.innerHTML = "";
          w09Thresholds.innerHTML = renderEmpty(err.message);
          w09Escalation.innerHTML = renderEmpty(err.message);
          w09Schedule.innerHTML = renderEmpty(err.message);
          document.getElementById("w09KpiMeta").textContent = "실패: " + err.message;
          document.getElementById("w09KpiSummary").innerHTML = "";
          document.getElementById("w09KpiTable").innerHTML = renderEmpty(err.message);
          document.getElementById("w09EscalationTable").innerHTML = renderEmpty(err.message);
          document.getElementById("w09KpiRecommendations").innerHTML = renderEmpty(err.message);
          document.getElementById("w09PolicyMeta").textContent = "실패: " + err.message;
          document.getElementById("w09PolicyTable").innerHTML = renderEmpty(err.message);
          document.getElementById("w10KpiMeta").textContent = "실패: " + err.message;
          document.getElementById("w10KpiSummary").innerHTML = "";
          document.getElementById("w10KpiTable").innerHTML = renderEmpty(err.message);
          document.getElementById("w10EscalationTable").innerHTML = renderEmpty(err.message);
          document.getElementById("w10KpiRecommendations").innerHTML = renderEmpty(err.message);
          document.getElementById("w10PolicyMeta").textContent = "실패: " + err.message;
          document.getElementById("w10PolicyTable").innerHTML = renderEmpty(err.message);
          document.getElementById("w11KpiMeta").textContent = "실패: " + err.message;
          document.getElementById("w11KpiSummary").innerHTML = "";
          document.getElementById("w11KpiTable").innerHTML = renderEmpty(err.message);
          document.getElementById("w11EscalationTable").innerHTML = renderEmpty(err.message);
          document.getElementById("w11KpiRecommendations").innerHTML = renderEmpty(err.message);
          document.getElementById("w11PolicyMeta").textContent = "실패: " + err.message;
          document.getElementById("w11PolicyTable").innerHTML = renderEmpty(err.message);
          document.getElementById("w15KpiMeta").textContent = "실패: " + err.message;
          document.getElementById("w15KpiSummary").innerHTML = "";
          document.getElementById("w15KpiTable").innerHTML = renderEmpty(err.message);
          document.getElementById("w15EscalationTable").innerHTML = renderEmpty(err.message);
          document.getElementById("w15KpiRecommendations").innerHTML = renderEmpty(err.message);
          document.getElementById("w15PolicyMeta").textContent = "실패: " + err.message;
          document.getElementById("w15PolicyTable").innerHTML = renderEmpty(err.message);
          ["w09", "w10", "w11", "w15"].forEach((phaseCode) => {{
            setSharedTrackerError(getSharedTrackerConfig(phaseCode), err.message);
          }});
          document.getElementById("w07TrackerMeta").textContent = "실패: " + err.message;
          document.getElementById("w07TrackerSummary").innerHTML = "";
          document.getElementById("w07TrackerTable").innerHTML = renderEmpty(err.message);
          document.getElementById("w07ReadinessMeta").textContent = "실패: " + err.message;
          document.getElementById("w07ReadinessCards").innerHTML = "";
          document.getElementById("w07ReadinessBlockers").innerHTML = renderEmpty(err.message);
          document.getElementById("w07EvidenceTable").innerHTML = renderEmpty(err.message);
          document.getElementById("w07SelectionMeta").textContent = "필터: ALL | 표시: 0/0 | 선택: 0";
          renderW07ActionResultsPanel();
          weekly.innerHTML = renderEmpty(err.message);
          training.innerHTML = renderEmpty(err.message);
          kpi.innerHTML = renderEmpty(err.message);
        }}
      }}

      function roleDefaultTab(profile) {{
        const role = (profile && profile.role) || "";
        if (role === "operator") return "workorders";
        if (role === "auditor") return "reports";
        return "overview";
      }}

      buttons.forEach((btn) => {{
        btn.addEventListener("click", () => activate(btn.dataset.tab, true));
      }});

      document.getElementById("saveTokenBtn").addEventListener("click", async () => {{
        const token = (tokenInput.value || "").trim();
        if (!token) {{
          setAuthState("토큰 상태: 빈 값은 저장할 수 없습니다.");
          return;
        }}
        persistToken(token);
        authProfile = null;
        persistAuthProfile(null);
        updateAuthStateFromToken();
        try {{
          const profile = await runAuthMe();
          setAuthState("토큰 저장 성공 | 사용자: " + profile.username + " | 역할: " + profile.role);
        }} catch (err) {{
          clearStoredAuthArtifacts({{ preserveInput: true }});
          setAuthState("토큰 저장 실패 | " + err.message);
        }}
      }});
      document.getElementById("clearTokenBtn").addEventListener("click", () => {{
        clearStoredAuthArtifacts();
        updateAuthStateFromToken();
      }});
      document.getElementById("testTokenBtn").addEventListener("click", async () => {{
        try {{
          const profile = await runAuthMe();
          setAuthState("토큰 상태: 연결 성공 | 사용자: " + profile.username + " | 역할: " + profile.role);
          if (!url.searchParams.get("tab")) {{
            activate(roleDefaultTab(profile), true);
          }}
        }} catch (err) {{
          setAuthState("토큰 상태: 연결 실패 | " + err.message);
        }}
      }});
      if (openLoginModalBtn) {{
        openLoginModalBtn.addEventListener("click", () => openAuthModal("login"));
      }}
      if (openSignupModalBtn) {{
        openSignupModalBtn.addEventListener("click", () => openAuthModal("signup"));
      }}
      if (logoutBtn) {{
        logoutBtn.addEventListener("click", runAuthLogout);
      }}
      if (closeLoginModalBtn) {{
        closeLoginModalBtn.addEventListener("click", closeAuthModal);
      }}
      if (closeSignupModalBtn) {{
        closeSignupModalBtn.addEventListener("click", closeAuthModal);
      }}
      if (authModalBackdrop) {{
        authModalBackdrop.addEventListener("click", closeAuthModal);
      }}
      document.addEventListener("keydown", (event) => {{
        if (event.key === "Escape" && activeAuthModal) {{
          closeAuthModal();
        }}
      }});
      document.getElementById("loginBtn").addEventListener("click", runAuthLogin);
      if (loginPasswordInput) {{
        loginPasswordInput.addEventListener("keydown", (event) => {{
          if (event.key === "Enter") {{
            event.preventDefault();
            runAuthLogin();
          }}
        }});
      }}
      document.getElementById("signupBtn").addEventListener("click", runAuthSignup);
      if (signupPasswordInput) {{
        signupPasswordInput.addEventListener("keydown", (event) => {{
          if (event.key === "Enter") {{
            event.preventDefault();
            runAuthSignup();
          }}
        }});
      }}
      document.getElementById("runIamMeBtn").addEventListener("click", runIamMe);
      document.getElementById("runIamLogoutBtn").addEventListener("click", runAuthLogout);
      document.getElementById("runIamTokenPolicyBtn").addEventListener("click", runIamTokenPolicy);
      document.getElementById("runIamUsersBtn").addEventListener("click", runIamUsers);
      document.getElementById("runIamPickUserBtn").addEventListener("click", runIamPickUser);
      document.getElementById("runIamCreateUserBtn").addEventListener("click", runIamCreateUser);
      document.getElementById("runIamUpdateUserBtn").addEventListener("click", runIamUpdateUser);
      document.getElementById("runIamSetPasswordBtn").addEventListener("click", runIamSetPassword);
      document.getElementById("runIamDeactivateUserBtn").addEventListener("click", runIamDeactivateUser);
      document.getElementById("runIamDeleteUserBtn").addEventListener("click", runIamDeleteUser);
      document.getElementById("runIamTokensBtn").addEventListener("click", runIamTokens);
      document.getElementById("runIamIssueTokenBtn").addEventListener("click", runIamIssueToken);
      document.getElementById("runIamPickTokenBtn").addEventListener("click", runIamPickToken);
      document.getElementById("runIamRotateTokenBtn").addEventListener("click", runIamRotateToken);
      document.getElementById("runIamRevokeTokenBtn").addEventListener("click", runIamRevokeToken);
      document.getElementById("runIamAuditBtn").addEventListener("click", runIamAuditLogs);
      const iamUsersTableContainer = document.getElementById("iamUsersTable");
      if (iamUsersTableContainer) {{
        iamUsersTableContainer.addEventListener("click", (event) => {{
          const pickBtn = event.target.closest(".iam-select-user");
          if (!pickBtn) return;
          const userId = asInt(pickBtn.getAttribute("data-user-id"), -1);
          if (userId <= 0) return;
          const user = getIamUserFromCache(userId);
          if (!user) return;
          applyIamUserToForm(user);
          runIamUsers();
          document.getElementById("iamEditMeta").textContent =
            "선택 완료: user_id=" + String(userId) + " (" + String(user.username || "") + ")";
        }});
      }}
      const iamTokensTableContainer = document.getElementById("iamTokensTable");
      if (iamTokensTableContainer) {{
        iamTokensTableContainer.addEventListener("click", (event) => {{
          const pickBtn = event.target.closest(".iam-select-token");
          if (!pickBtn) return;
          const tokenId = asInt(pickBtn.getAttribute("data-token-id"), -1);
          if (tokenId <= 0) return;
          const token = getIamTokenFromCache(tokenId);
          if (!token) return;
          applyIamTokenToForm(token);
          const visibleRows = iamFilteredTokensCache.length ? iamFilteredTokensCache : iamTokensCache;
          iamTokensTableContainer.innerHTML = renderIamTokensTable(visibleRows);
          document.getElementById("iamTokenActionMeta").textContent =
            "선택 완료: token_id=" + String(tokenId) + " | user=" + String(token.username || "");
        }});
      }}
      const iamAuditTableContainer = document.getElementById("iamAuditTable");
      if (iamAuditTableContainer) {{
        iamAuditTableContainer.addEventListener("click", (event) => {{
          const detailBtn = event.target.closest(".iam-select-audit");
          if (!detailBtn) return;
          const logId = asInt(detailBtn.getAttribute("data-audit-id"), -1);
          if (logId <= 0) return;
          const logRow = getIamAuditLogFromCache(logId);
          if (!logRow) return;
          showIamAuditDetail(logRow);
          iamAuditTableContainer.innerHTML = renderIamAuditTable(iamAuditLogsCache);
        }});
      }}

      const w07TrackerTableContainer = document.getElementById("w07TrackerTable");
      if (w07TrackerTableContainer) {{
        w07TrackerTableContainer.addEventListener("click", (event) => {{
          const pickBtn = event.target.closest(".w07-pick-item");
          if (pickBtn) {{
            const item = getW07ItemById(pickBtn.getAttribute("data-item-id"));
            if (item) {{
              fillW07FormFromItem(item, {{ keepCurrentNote: true }});
              renderW07TrackerTablePanel();
            }}
            return;
          }}
          if (event.target.closest("input,button,a,label")) {{
            return;
          }}
          const rowEl = event.target.closest("tr.w07-track-row");
          if (!rowEl) return;
          const item = getW07ItemById(rowEl.getAttribute("data-item-id"));
          if (!item) return;
          fillW07FormFromItem(item, {{ keepCurrentNote: true }});
          renderW07TrackerTablePanel();
        }});
        w07TrackerTableContainer.addEventListener("change", (event) => {{
          const checkbox = event.target.closest(".w07-select-item");
          if (!checkbox) return;
          const itemId = asInt(checkbox.getAttribute("data-item-id"), -1);
          if (itemId <= 0) return;
          if (checkbox.checked) {{
            w07SelectedItemIds.add(itemId);
          }} else {{
            w07SelectedItemIds.delete(itemId);
          }}
          renderW07SelectionMeta();
        }});
      }}

      const w07ReadinessCardsPanel = document.getElementById("w07ReadinessCards");
      if (w07ReadinessCardsPanel) {{
        w07ReadinessCardsPanel.addEventListener("click", (event) => {{
          const card = event.target.closest(".w07-readiness-card");
          if (!card) return;
          const filterKey = card.getAttribute("data-filter") || "all";
          setW07TrackerFilter(filterKey, {{ autoPick: true }});
          const readinessMeta = document.getElementById("w07ReadinessMeta");
          readinessMeta.textContent =
            "상태: " + String((w07LastCompletion && w07LastCompletion.status) || "active")
            + " | ready=" + String(w07LastReadiness && w07LastReadiness.ready ? "YES" : "NO")
            + " | filter=" + getW07FilterLabel(filterKey);
        }});
        w07ReadinessCardsPanel.addEventListener("keydown", (event) => {{
          if (!(event.key === "Enter" || event.key === " ")) return;
          const card = event.target.closest(".w07-readiness-card");
          if (!card) return;
          event.preventDefault();
          const filterKey = card.getAttribute("data-filter") || "all";
          setW07TrackerFilter(filterKey, {{ autoPick: true }});
        }});
      }}

      const w07EvidenceFileInput = document.getElementById("w07EvidenceFile");
      const w07EvidenceDropzone = document.getElementById("w07EvidenceDropzone");
      if (w07EvidenceDropzone && w07EvidenceFileInput) {{
        w07EvidenceDropzone.addEventListener("click", () => w07EvidenceFileInput.click());
        w07EvidenceFileInput.addEventListener("change", () => {{
          const file = (w07EvidenceFileInput.files && w07EvidenceFileInput.files[0]) || null;
          if (file) {{
            assignW07EvidenceFile(file);
          }}
        }});
        w07EvidenceDropzone.addEventListener("dragover", (event) => {{
          event.preventDefault();
          w07EvidenceDropzone.classList.add("dragover");
        }});
        w07EvidenceDropzone.addEventListener("dragleave", () => {{
          w07EvidenceDropzone.classList.remove("dragover");
        }});
        w07EvidenceDropzone.addEventListener("drop", (event) => {{
          event.preventDefault();
          w07EvidenceDropzone.classList.remove("dragover");
          const files = event.dataTransfer && event.dataTransfer.files ? event.dataTransfer.files : null;
          const file = files && files.length > 0 ? files[0] : null;
          if (!file) return;
          assignW07EvidenceFile(file);
        }});
      }}

      const w07CompleteModal = document.getElementById("w07CompleteModal");
      document.getElementById("w07CompleteModalCancel").addEventListener("click", () => closeW07CompleteModal(false));
      document.getElementById("w07CompleteModalConfirm").addEventListener("click", () => closeW07CompleteModal(true));
      if (w07CompleteModal) {{
        w07CompleteModal.addEventListener("click", (event) => {{
          if (event.target === w07CompleteModal) {{
            closeW07CompleteModal(false);
          }}
        }});
      }}
      window.addEventListener("keydown", (event) => {{
        if (event.key === "Escape" && w07CompleteModal && w07CompleteModal.classList.contains("open")) {{
          closeW07CompleteModal(false);
        }}
      }});

      document.getElementById("runOverviewBtn").addEventListener("click", runOverview);
      document.getElementById("runOverviewGuardRecoverDryBtn").addEventListener("click", () => runOverviewGuardRecover(true));
      document.getElementById("runOverviewGuardRecoverRunBtn").addEventListener("click", () => runOverviewGuardRecover(false));
      document.getElementById("runOverviewGuardRecoverLatestBtn").addEventListener("click", runOverviewGuardRecoverLatest);
      document.getElementById("runWorkordersBtn").addEventListener("click", runWorkorders);
      document.getElementById("runInspectionsBtn").addEventListener("click", runInspections);
      document.getElementById("runInspectionEvidenceBtn").addEventListener("click", runInspectionEvidenceList);
      document.getElementById("runInspectionImportValidationBtn").addEventListener("click", runInspectionImportValidation);
      document.getElementById("runOpsMasterCatalogBtn").addEventListener("click", runOpsMasterCatalogRefresh);
      document.getElementById("runOpsMasterEquipmentCreateBtn").addEventListener("click", runOpsMasterEquipmentCreate);
      document.getElementById("runOpsMasterEquipmentUpdateBtn").addEventListener("click", runOpsMasterEquipmentUpdate);
      document.getElementById("runOpsMasterEquipmentDeleteBtn").addEventListener("click", runOpsMasterEquipmentDelete);
      document.getElementById("runOpsMasterChecklistCreateBtn").addEventListener("click", runOpsMasterChecklistCreate);
      document.getElementById("runOpsMasterChecklistUpdateBtn").addEventListener("click", runOpsMasterChecklistUpdate);
      document.getElementById("runOpsMasterChecklistDeleteBtn").addEventListener("click", runOpsMasterChecklistDelete);
      document.getElementById("runOpsMasterChecklistRevisionCreateBtn").addEventListener("click", runOpsMasterChecklistRevisionCreate);
      document.getElementById("runOpsMasterChecklistRevisionListBtn").addEventListener("click", runOpsMasterChecklistRevisionList);
      document.getElementById("runOpsMasterChecklistRevisionDiffBtn").addEventListener("click", runOpsMasterChecklistRevisionDiff);
      document.getElementById("runOpsMasterChecklistRevisionSubmitBtn").addEventListener("click", runOpsMasterChecklistRevisionSubmit);
      document.getElementById("runOpsMasterChecklistRevisionApproveBtn").addEventListener("click", runOpsMasterChecklistRevisionApprove);
      document.getElementById("runOpsMasterChecklistRevisionRejectBtn").addEventListener("click", runOpsMasterChecklistRevisionReject);
      document.getElementById("runOpsMasterQrCreateBtn").addEventListener("click", runOpsMasterQrCreate);
      document.getElementById("runOpsMasterQrUpdateBtn").addEventListener("click", runOpsMasterQrUpdate);
      document.getElementById("runOpsMasterQrDeleteBtn").addEventListener("click", runOpsMasterQrDelete);
      document.getElementById("opsMasterSearch").addEventListener("input", renderOpsMasterTables);
      document.getElementById("opsMasterLifecycleFilter").addEventListener("change", renderOpsMasterTables);
      document.getElementById("opsMasterRevisionStatusFilter").addEventListener("change", renderOpsMasterTables);
      document.getElementById("inCreateInspectionBtn").addEventListener("click", runCreateOpsInspection);
      document.getElementById("inChecklistAllNormalBtn").addEventListener("click", () => setOpsChecklistAllResult("normal"));
      document.getElementById("inChecklistAllNaBtn").addEventListener("click", () => setOpsChecklistAllResult("na"));
      document.getElementById("inChecklistResetBtn").addEventListener("click", () => resetOpsElectricalChecklistRows({{ preserve: false }}));
      document.getElementById("inChecklistSet").addEventListener("change", () => applyChecklistSetSelection({{ preserveChecklist: false }}));
      document.getElementById("inTemplateGroup").addEventListener("change", () => resetOpsElectricalChecklistRows({{ preserve: true }}));
      document.getElementById("inCreateEquipmentGroup").addEventListener("change", () => {{
        syncOpsTemplateGroupFromEquipmentGroup();
        resetOpsElectricalChecklistRows({{ preserve: true }});
        const equipmentNode = document.getElementById("inCreateEquipment");
        if (equipmentNode && !(equipmentNode.value || "").trim()) {{
          const selectedGroup = document.getElementById("inCreateEquipmentGroup").value || "";
          if (selectedGroup && selectedGroup !== "all") {{
            equipmentNode.value = selectedGroup;
          }}
        }}
      }});
      document.getElementById("inCreateOpsCode").addEventListener("change", applySelectedOpsCodeToForm);
      document.getElementById("inCreateEquipmentMaster").addEventListener("change", () => applySelectedOpsEquipmentToForm({{ overwriteFields: true }}));
      document.getElementById("inCreateQrId").addEventListener("change", () => applySelectedQrAssetToForm({{ overwriteFields: true }}));
      document.getElementById("runBillingCreateUnitBtn").addEventListener("click", runBillingCreateUnit);
      document.getElementById("runBillingUnitsBtn").addEventListener("click", runBillingUnits);
      document.getElementById("runBillingCreatePolicyBtn").addEventListener("click", runBillingCreatePolicy);
      document.getElementById("runBillingPoliciesBtn").addEventListener("click", runBillingPolicies);
      document.getElementById("runBillingCreateCommonBtn").addEventListener("click", runBillingCreateCommonCharge);
      document.getElementById("runBillingCommonBtn").addEventListener("click", runBillingCommonCharges);
      document.getElementById("runBillingCreateReadingBtn").addEventListener("click", runBillingCreateReading);
      document.getElementById("runBillingReadingsBtn").addEventListener("click", runBillingReadings);
      document.getElementById("runBillingGenerateBtn").addEventListener("click", runBillingGenerate);
      document.getElementById("runBillingStatementsBtn").addEventListener("click", runBillingStatements);
      document.getElementById("runOfficialDocCreateBtn").addEventListener("click", runOfficialDocumentCreate);
      document.getElementById("runOfficialDocLoadBtn").addEventListener("click", runOfficialDocumentLoad);
      document.getElementById("runOfficialDocUpdateBtn").addEventListener("click", runOfficialDocumentUpdate);
      document.getElementById("runOfficialDocCloseBtn").addEventListener("click", runOfficialDocumentClose);
      document.getElementById("runOfficialAttachmentUploadBtn").addEventListener("click", runOfficialAttachmentUpload);
      document.getElementById("runOfficialAttachmentListBtn").addEventListener("click", runOfficialAttachmentList);
      document.getElementById("runOfficialDocsBtn").addEventListener("click", runOfficialDocuments);
      document.getElementById("runOfficialOverdueSyncBtn").addEventListener("click", runOfficialOverdueSync);
      document.getElementById("runOfficialDocMonthlyReportBtn").addEventListener("click", runOfficialDocumentMonthlyReport);
      document.getElementById("runOfficialDocAnnualReportBtn").addEventListener("click", runOfficialDocumentAnnualReport);
      document.getElementById("runOfficialIntegratedMonthlyReportBtn").addEventListener("click", runOfficialIntegratedMonthlyReport);
      document.getElementById("runOfficialIntegratedAnnualReportBtn").addEventListener("click", runOfficialIntegratedAnnualReport);
      document.getElementById("runReportsBtn").addEventListener("click", runReports);
      document.getElementById("runAdoptionBtn").addEventListener("click", runAdoption);
      document.getElementById("runTutorialGlossaryBtn").addEventListener("click", () => runTutorialGlossary(true));
      document.getElementById("tutorialGlossarySearch").addEventListener("input", applyTutorialGlossaryFilters);
      document.getElementById("tutorialGlossaryCategory").addEventListener("change", applyTutorialGlossaryFilters);
      document.getElementById("w02TrackBootstrapBtn").addEventListener("click", runW02TrackerBootstrap);
      document.getElementById("w02TrackRefreshBtn").addEventListener("click", runW02Tracker);
      document.getElementById("w02ReadinessBtn").addEventListener("click", runW02Readiness);
      document.getElementById("w02CompleteBtn").addEventListener("click", runW02Complete);
      document.getElementById("w02TrackUpdateBtn").addEventListener("click", runW02TrackerUpdateAndUpload);
      document.getElementById("w03TrackBootstrapBtn").addEventListener("click", runW03TrackerBootstrap);
      document.getElementById("w03TrackRefreshBtn").addEventListener("click", runW03Tracker);
      document.getElementById("w03ReadinessBtn").addEventListener("click", runW03Readiness);
      document.getElementById("w03CompleteBtn").addEventListener("click", runW03Complete);
      document.getElementById("w03TrackUpdateBtn").addEventListener("click", runW03TrackerUpdateAndUpload);
      document.getElementById("w04FunnelRefreshBtn").addEventListener("click", runW04FunnelBlockers);
      document.getElementById("w04TrackBootstrapBtn").addEventListener("click", runW04TrackerBootstrap);
      document.getElementById("w04TrackRefreshBtn").addEventListener("click", runW04Tracker);
      document.getElementById("w04ReadinessBtn").addEventListener("click", runW04Readiness);
      document.getElementById("w04CompleteBtn").addEventListener("click", runW04Complete);
      document.getElementById("w04TrackUpdateBtn").addEventListener("click", runW04TrackerUpdateAndUpload);
      document.getElementById("w05ConsistencyRefreshBtn").addEventListener("click", runW05Consistency);
      document.getElementById("w06RhythmRefreshBtn").addEventListener("click", runW06Rhythm);
      document.getElementById("w07QualityRefreshBtn").addEventListener("click", runW07SlaQuality);
      document.getElementById("w07TrackBootstrapBtn").addEventListener("click", runW07TrackerBootstrap);
      document.getElementById("w07TrackNextBtn").addEventListener("click", runW07NextIncomplete);
      document.getElementById("w07SelectVisibleBtn").addEventListener("click", runW07SelectVisible);
      document.getElementById("w07ClearSelectionBtn").addEventListener("click", runW07ClearSelection);
      document.getElementById("w07BulkApplyBtn").addEventListener("click", runW07BulkApply);
      document.getElementById("w07TrackRefreshBtn").addEventListener("click", runW07Tracker);
      document.getElementById("w07ReadinessBtn").addEventListener("click", runW07Readiness);
      document.getElementById("w07CompleteBtn").addEventListener("click", () => runW07Complete());
      document.getElementById("w07CompleteAndWeeklyBtn").addEventListener("click", runW07CompleteAndWeekly);
      document.getElementById("w07DownloadPackageBtn").addEventListener("click", runW07DownloadCompletionPackage);
      document.getElementById("w07TrackUpdateBtn").addEventListener("click", runW07TrackerUpdateAndUpload);
      document.getElementById("w07WeeklyRunBtn").addEventListener("click", runW07WeeklyJob);
      document.getElementById("w07WeeklyLatestBtn").addEventListener("click", runW07WeeklyLatest);
      document.getElementById("w07WeeklyTrendsBtn").addEventListener("click", runW07WeeklyTrends);
      document.getElementById("w08DisciplineRefreshBtn").addEventListener("click", runW08ReportDiscipline);
      const sharedKpiRefreshHandlers = {{
        w09: runW09KpiOperation,
        w10: runW10KpiOperation,
        w11: runW11KpiOperation,
        w15: runW15KpiOperation,
      }};
      Object.keys(sharedKpiRefreshHandlers).forEach((phaseCode) => {{
        document.getElementById(phaseCode + "KpiRefreshBtn")
          .addEventListener("click", sharedKpiRefreshHandlers[phaseCode]);
      }});
      const sharedTrackerHandlers = {{
        w09: {{
          bootstrap: runW09TrackerBootstrap,
          refresh: runW09Tracker,
          readiness: runW09Readiness,
          complete: runW09Complete,
          update: runW09TrackerUpdateAndUpload,
        }},
        w10: {{
          bootstrap: runW10TrackerBootstrap,
          refresh: runW10Tracker,
          readiness: runW10Readiness,
          complete: runW10Complete,
          update: runW10TrackerUpdateAndUpload,
        }},
        w11: {{
          bootstrap: runW11TrackerBootstrap,
          refresh: runW11Tracker,
          readiness: runW11Readiness,
          complete: runW11Complete,
          update: runW11TrackerUpdateAndUpload,
        }},
        w15: {{
          bootstrap: runW15TrackerBootstrap,
          refresh: runW15Tracker,
          readiness: runW15Readiness,
          complete: runW15Complete,
          update: runW15TrackerUpdateAndUpload,
        }},
      }};
      Object.keys(sharedTrackerHandlers).forEach((phaseCode) => {{
        const handlers = sharedTrackerHandlers[phaseCode];
        document.getElementById(phaseCode + "TrackBootstrapBtn").addEventListener("click", handlers.bootstrap);
        document.getElementById(phaseCode + "TrackRefreshBtn").addEventListener("click", handlers.refresh);
        document.getElementById(phaseCode + "ReadinessBtn").addEventListener("click", handlers.readiness);
        document.getElementById(phaseCode + "CompleteBtn").addEventListener("click", handlers.complete);
        document.getElementById(phaseCode + "TrackUpdateBtn").addEventListener("click", handlers.update);
      }});
      ["rpMonth", "rpYear", "rpSite"].forEach((id) => {{
        const node = document.getElementById(id);
        if (node) {{
          node.addEventListener("input", updateReportLinks);
          node.addEventListener("change", updateReportLinks);
        }}
      }});
      ["officialReportSite", "officialReportMonth", "officialReportYear"].forEach((id) => {{
        const node = document.getElementById(id);
        if (node) {{
          node.addEventListener("input", updateOfficialReportLinks);
          node.addEventListener("change", updateOfficialReportLinks);
        }}
      }});
      ["officialExportSite", "officialExportOrganization", "officialExportStatus", "officialExportMonth", "officialExportYear"].forEach((id) => {{
        const node = document.getElementById(id);
        if (node) {{
          node.addEventListener("input", updateOfficialBulkExportLinks);
          node.addEventListener("change", updateOfficialBulkExportLinks);
        }}
      }});

      authProfile = getStoredAuthProfile();
      const savedToken = getToken();
      if (savedToken) {{
        tokenInput.value = savedToken;
      }}
      updateAuthStateFromToken();
      if (savedToken && !authProfile) {{
        runAuthMe().catch((err) => {{
          setAuthState("토큰 상태: 자동 확인 실패 | " + err.message);
        }});
      }}
      applyStaticUiTooltips();
      updateReportLinks();
      updateOfficialReportLinks();
      updateOfficialBulkExportLinks();
      bindOpsElectricalChecklistHandlers();
      populateOpsChecklistSetSelector();
      populateOpsCodeSelector();
      populateOpsEquipmentSelector();
      populateOpsQrSelector();
      applyChecklistSetSelection({{ preserveChecklist: false }});
      applySelectedOpsEquipmentToForm();
      applySelectedQrAssetToForm();
      renderOpsMasterTables();
      const inCreateInspectedAtNode = document.getElementById("inCreateInspectedAt");
      if (inCreateInspectedAtNode && !(inCreateInspectedAtNode.value || "").trim()) {{
        inCreateInspectedAtNode.value = currentLocalDatetimeInputValue();
      }}
      if (!document.getElementById("inCreateSite").value) {{
        document.getElementById("inCreateSite").value = "HQ";
      }}
      [
        "billingUnitSite",
        "billingPolicySite",
        "billingCommonSite",
        "billingReadingSite",
        "billingRunSite",
        "billingStatementsSite",
        "officialDocSite",
        "officialDocsSite",
        "officialExportSite",
        "officialOverdueSite",
        "officialReportSite",
        "rpSite",
      ].forEach((id) => {{
        const node = document.getElementById(id);
        if (node && !node.value) {{
          node.value = "HQ";
        }}
      }});
      [
        "billingPolicyMonth",
        "billingCommonMonth",
        "billingReadingMonth",
        "billingRunMonth",
        "billingStatementsMonth",
        "officialReportMonth",
      ].forEach((id) => {{
        const node = document.getElementById(id);
        if (node && !node.value) {{
          node.value = currentMonthLabel();
        }}
      }});
      const officialDocReceivedAtNode = document.getElementById("officialDocReceivedAt");
      if (officialDocReceivedAtNode && !(officialDocReceivedAtNode.value || "").trim()) {{
        officialDocReceivedAtNode.value = currentLocalDatetimeInputValue();
      }}
      const officialReportYearNode = document.getElementById("officialReportYear");
      if (officialReportYearNode && !(officialReportYearNode.value || "").trim()) {{
        officialReportYearNode.value = String(new Date().getFullYear());
      }}
      if (!document.getElementById("billingReadingReader").value && authProfile && authProfile.username) {{
        document.getElementById("billingReadingReader").value = String(authProfile.username);
      }}
      if (!document.getElementById("inCreateLocation").value) {{
        document.getElementById("inCreateLocation").value = "B1 수변전실";
      }}
      if (!document.getElementById("inCreateEquipment").value) {{
        document.getElementById("inCreateEquipment").value = "변압기";
      }}
      if (!document.getElementById("inCreateInspector").value && authProfile && authProfile.username) {{
        document.getElementById("inCreateInspector").value = String(authProfile.username);
      }}
      if ((document.getElementById("inCreateOpsCode").value || "").trim()) {{
        applySelectedOpsCodeToForm();
      }}
      if ((document.getElementById("inCreateQrId").value || "").trim()) {{
        applySelectedQrAssetToForm({{ overwriteFields: false }});
      }}
      if (!document.getElementById("w02TrackSite").value) {{
        document.getElementById("w02TrackSite").value = "HQ";
      }}
      if (!document.getElementById("w03TrackSite").value) {{
        document.getElementById("w03TrackSite").value = "HQ";
      }}
      if (!document.getElementById("w04TrackSite").value) {{
        document.getElementById("w04TrackSite").value = "HQ";
      }}
      if (!document.getElementById("w04FunnelSite").value) {{
        document.getElementById("w04FunnelSite").value = "HQ";
      }}
      if (!document.getElementById("w05ConsistencySite").value) {{
        document.getElementById("w05ConsistencySite").value = "HQ";
      }}
      if (!document.getElementById("w06RhythmSite").value) {{
        document.getElementById("w06RhythmSite").value = "HQ";
      }}
      if (!document.getElementById("w07QualitySite").value) {{
        document.getElementById("w07QualitySite").value = "HQ";
      }}
      if (!document.getElementById("w07TrackSite").value) {{
        document.getElementById("w07TrackSite").value = "HQ";
      }}
      if (!document.getElementById("w07WeeklySite").value) {{
        document.getElementById("w07WeeklySite").value = "HQ";
      }}
      if (!document.getElementById("w08DisciplineSite").value) {{
        document.getElementById("w08DisciplineSite").value = "HQ";
      }}
      ["w09KpiSite", "w10KpiSite", "w11KpiSite", "w15KpiSite"].forEach((id) => {{
        const node = document.getElementById(id);
        if (node && !node.value) {{
          node.value = "HQ";
        }}
      }});
      ["w09", "w10", "w11", "w15"].forEach((phaseCode) => {{
        setSharedTrackerSiteDefault(getSharedTrackerConfig(phaseCode), "HQ");
      }});
      renderW07SelectionMeta();
      renderW07ActionResultsPanel();
      activate("{selected_tab}", false);

      runAdoption();
      runTutorialOnboarding();
      runTutorialGlossary(false);
      if (savedToken) {{
        runAuthMe().then(() => runOverview()).catch(() => {{
          setAuthState("토큰 상태: 저장되어 있으나 인증 실패. 토큰을 다시 확인하세요.");
        }});
      }}
    }})();
  </script>
</body>
</html>
"""
