"""Main tabs HTML renderers extracted from app.main."""

from __future__ import annotations

import hashlib
import html
import json
from functools import lru_cache
from pathlib import Path
from typing import Any


_MAIN_TABS_ASSET_DIR = Path(__file__).resolve().parent / "assets"
_MAIN_TABS_APP_JS_PATH = _MAIN_TABS_ASSET_DIR / "main_tabs_app.js"


@lru_cache(maxsize=1)
def _main_tabs_script_text() -> str:
    return _MAIN_TABS_APP_JS_PATH.read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def main_tabs_script_version() -> str:
    payload = _main_tabs_script_text().encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:12]


def main_tabs_script_text() -> str:
    return _main_tabs_script_text()


def main_tabs_script_url() -> str:
    return f"/web/main-shell/app.js?v={main_tabs_script_version()}"


def _build_main_tabs_bootstrap_json(*, initial_tab: str, ops_special_checklists_payload: dict[str, Any]) -> str:
    payload = {"initialTab": initial_tab, "opsSpecialChecklists": ops_special_checklists_payload}
    return json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c")




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
    bootstrap_json = _build_main_tabs_bootstrap_json(
        initial_tab=selected_tab,
        ops_special_checklists_payload=ops_special_checklists_payload,
    )
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
  <script id="kaMainBootstrap" type="application/json">{bootstrap_json}</script>
  <script defer src="{main_tabs_script_url()}"></script>
</body>
</html>
"""
