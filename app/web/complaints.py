"""Complaint mobile web field console."""

from __future__ import annotations

import hashlib
import html
from functools import lru_cache
from pathlib import Path


_COMPLAINTS_ASSET_DIR = Path(__file__).resolve().parent / "assets"
_COMPLAINTS_APP_JS_PATH = _COMPLAINTS_ASSET_DIR / "complaints_app.js"


@lru_cache(maxsize=1)
def _complaints_script_text() -> str:
    return _COMPLAINTS_APP_JS_PATH.read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def complaints_script_version() -> str:
    payload = _complaints_script_text().encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:12]


def complaints_script_text() -> str:
    return _complaints_script_text()


def complaints_script_url() -> str:
    return f"/web/complaints/app.js?v={complaints_script_version()}"


def build_complaints_mobile_html(*, title: str = "세대 민원관리") -> str:
    page_title = html.escape(title)
    template = """<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>KA Facility OS - __PAGE_TITLE__</title>
  <style>
    :root {
      --ink: #10213c;
      --muted: #5b6f8b;
      --line: #d7e2f0;
      --card: rgba(255, 255, 255, 0.92);
      --bg: #edf5ff;
      --brand: #0c6d58;
      --accent: #ca5f2d;
      --warning: #c68a0d;
      --danger: #b53b2f;
      --ok: #197347;
      --shadow: 0 16px 34px rgba(15, 39, 74, 0.10);
      --radius: 18px;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      color: var(--ink);
      font-family: "SUIT", "Pretendard", "IBM Plex Sans KR", "Noto Sans KR", sans-serif;
      background:
        radial-gradient(920px 360px at 0% -10%, rgba(185, 237, 255, 0.85) 0%, transparent 60%),
        radial-gradient(720px 340px at 100% -12%, rgba(255, 226, 198, 0.92) 0%, transparent 58%),
        linear-gradient(180deg, #f8fbff 0%, var(--bg) 100%);
      min-height: 100vh;
    }
    a { color: inherit; }
    .wrap { max-width: 1440px; margin: 0 auto; padding: 18px 14px 42px; }
    .mast {
      border: 1px solid rgba(176, 198, 223, 0.75);
      border-radius: 26px;
      background:
        linear-gradient(145deg, rgba(255,255,255,0.95) 0%, rgba(235,247,242,0.95) 48%, rgba(255,243,231,0.94) 100%);
      box-shadow: var(--shadow);
      padding: 18px;
      display: grid;
      grid-template-columns: minmax(0, 1.2fr) minmax(340px, 0.8fr);
      gap: 16px;
      align-items: stretch;
    }
    .eyebrow {
      margin: 0 0 8px;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border-radius: 999px;
      padding: 6px 10px;
      background: rgba(9, 108, 88, 0.10);
      color: var(--brand);
      font-size: 12px;
      font-weight: 900;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }
    .title-block h1 {
      margin: 0;
      font-size: clamp(28px, 4vw, 42px);
      line-height: 1.05;
      letter-spacing: -0.03em;
    }
    .title-block p {
      margin: 10px 0 0;
      max-width: 68ch;
      color: var(--muted);
      line-height: 1.55;
      font-size: 14px;
    }
    .hero-links { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
    .hero-links a {
      text-decoration: none;
      border: 1px solid rgba(148, 179, 212, 0.95);
      border-radius: 999px;
      padding: 8px 11px;
      font-size: 12px;
      font-weight: 800;
      background: rgba(248, 252, 255, 0.86);
      color: #214f7c;
    }
    .snapshot-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
    .stat-card {
      position: relative;
      overflow: hidden;
      border: 1px solid rgba(190, 207, 226, 0.88);
      border-radius: 18px;
      padding: 14px;
      background: rgba(255, 255, 255, 0.88);
      min-height: 118px;
    }
    .stat-card::after {
      content: "";
      position: absolute;
      inset: auto -30px -32px auto;
      width: 98px;
      height: 98px;
      border-radius: 999px;
      opacity: 0.18;
      background: currentColor;
    }
    .stat-card span {
      display: block;
      font-size: 12px;
      font-weight: 900;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .stat-card strong {
      display: block;
      margin-top: 8px;
      font-size: 34px;
      line-height: 1;
      letter-spacing: -0.04em;
    }
    .stat-card small {
      display: block;
      margin-top: 12px;
      max-width: 16ch;
      color: #526984;
      font-size: 12px;
      line-height: 1.35;
    }
    .stat-card.total { color: #2d567f; }
    .stat-card.received { color: var(--accent); }
    .stat-card.active { color: var(--warning); }
    .stat-card.done { color: var(--ok); }
    .notice-bar {
      margin-top: 14px;
      border: 1px solid rgba(177, 197, 222, 0.85);
      border-radius: 16px;
      background: rgba(255,255,255,0.86);
      padding: 11px 12px;
      font-size: 13px;
      color: #355474;
    }
    .notice-bar.error {
      border-color: rgba(204, 107, 98, 0.7);
      color: #8f2d24;
      background: rgba(255, 239, 236, 0.95);
    }
    .notice-bar.success {
      border-color: rgba(107, 178, 136, 0.75);
      color: #155f38;
      background: rgba(236, 250, 242, 0.96);
    }
    .dock { margin-top: 14px; display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
    .surface {
      border: 1px solid rgba(195, 209, 228, 0.82);
      border-radius: var(--radius);
      background: var(--card);
      backdrop-filter: blur(10px);
      box-shadow: 0 12px 26px rgba(17, 45, 78, 0.07);
    }
    .surface-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 14px 14px 0;
    }
    .surface-head h2, .surface-head h3 {
      margin: 0;
      font-size: 18px;
      color: var(--brand);
      letter-spacing: -0.02em;
    }
    .surface-head .meta { color: var(--muted); font-size: 12px; font-weight: 700; }
    .surface-body { padding: 14px; }
    .grid-2, .grid-3, .grid-4 { display: grid; gap: 8px; }
    .grid-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .grid-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .grid-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    label.caption {
      display: block;
      margin: 0 0 6px;
      color: #506885;
      font-size: 12px;
      font-weight: 800;
    }
    input, textarea, select {
      width: 100%;
      border: 1px solid #c6d7ec;
      border-radius: 12px;
      background: rgba(255,255,255,0.96);
      color: var(--ink);
      padding: 11px 12px;
      font-size: 14px;
      font-family: inherit;
      transition: border-color 140ms ease, box-shadow 140ms ease, transform 140ms ease;
    }
    input:focus, textarea:focus, select:focus {
      outline: none;
      border-color: #6aa9cf;
      box-shadow: 0 0 0 4px rgba(107, 182, 221, 0.16);
      transform: translateY(-1px);
    }
    textarea { min-height: 100px; resize: vertical; line-height: 1.5; }
    .field-stack + .field-stack { margin-top: 8px; }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
    button, .button-link {
      appearance: none;
      border: 1px solid rgba(137, 183, 216, 0.96);
      border-radius: 12px;
      padding: 10px 12px;
      background: rgba(239, 247, 255, 0.98);
      color: #1a4f7e;
      font-size: 13px;
      font-weight: 900;
      letter-spacing: -0.01em;
      cursor: pointer;
      text-decoration: none;
    }
    button.run, .button-link.run {
      border-color: rgba(111, 197, 171, 0.98);
      background: rgba(233, 248, 242, 0.98);
      color: #0c5d4d;
    }
    button.ghost {
      background: rgba(255,255,255,0.72);
      border-color: rgba(190, 206, 226, 0.95);
      color: #3d5f84;
    }
    .tab-strip { margin-top: 14px; display: flex; flex-wrap: wrap; gap: 8px; }
    .tab-btn.active {
      border-color: rgba(111, 197, 171, 0.98);
      background: rgba(233, 248, 242, 0.98);
      color: #0c5d4d;
      box-shadow: 0 10px 18px rgba(15, 63, 47, 0.08);
    }
    .workspace { margin-top: 14px; display: grid; grid-template-columns: 390px minmax(0, 1fr); gap: 12px; align-items: start; }
    .workspace.hidden, .surface.hidden { display: none; }
    .queue-list { padding: 0 14px 14px; display: grid; gap: 8px; max-height: calc(100vh - 250px); overflow: auto; }
    .queue-item { border: 1px solid rgba(211, 224, 239, 0.95); border-radius: 16px; padding: 12px; background: rgba(251, 253, 255, 0.92); cursor: pointer; }
    .queue-item.active { border-color: rgba(92, 145, 197, 0.98); background: linear-gradient(140deg, rgba(246, 251, 255, 0.98) 0%, rgba(235, 248, 244, 0.96) 100%); }
    .queue-top strong { display: block; font-size: 15px; line-height: 1.2; letter-spacing: -0.02em; }
    .queue-copy { margin-top: 8px; color: #3d5878; font-size: 13px; line-height: 1.45; }
    .queue-meta, .badge-row, .chip-row { display: flex; flex-wrap: wrap; gap: 6px; }
    .queue-meta { margin-top: 8px; color: var(--muted); font-size: 12px; }
    .badge, .chip { display: inline-flex; align-items: center; justify-content: center; gap: 6px; border-radius: 999px; padding: 6px 10px; font-size: 12px; font-weight: 900; border: 1px solid rgba(191, 208, 228, 0.94); background: rgba(247, 250, 255, 0.92); color: #315778; }
    .chip { cursor: pointer; }
    .chip.active { box-shadow: inset 0 0 0 1px rgba(17, 64, 107, 0.22), 0 8px 16px rgba(16, 51, 89, 0.08); transform: translateY(-1px); }
    button:disabled { opacity: 0.55; cursor: not-allowed; }
    .badge.status-received, .chip.status-received { color: #8a4b00; background: rgba(255, 243, 221, 0.96); border-color: rgba(223, 190, 112, 0.96); }
    .badge.status-assigned, .chip.status-assigned, .badge.status-visit-scheduled, .chip.status-visit-scheduled, .badge.status-in-progress, .chip.status-in-progress { color: #8c6500; background: rgba(255, 247, 226, 0.96); border-color: rgba(221, 196, 120, 0.96); }
    .badge.status-resolved, .chip.status-resolved, .badge.status-resident-confirmed, .chip.status-resident-confirmed, .badge.status-closed, .chip.status-closed { color: #115f39; background: rgba(233, 249, 239, 0.98); border-color: rgba(126, 202, 153, 0.95); }
    .badge.status-reopened, .chip.status-reopened { color: #8e2f25; background: rgba(255, 238, 235, 0.98); border-color: rgba(220, 131, 120, 0.92); }
    .badge.type { color: #24577d; background: rgba(239, 246, 255, 0.96); }
    .badge.priority-high, .badge.priority-urgent { color: #8b2f26; background: rgba(255, 238, 235, 0.98); border-color: rgba(220, 130, 117, 0.92); }
    .badge.priority-low { color: #295a84; background: rgba(241, 247, 255, 0.96); }
    .detail-stack { display: grid; gap: 12px; }
    .card { border: 1px solid rgba(215, 226, 240, 0.92); border-radius: 18px; background: rgba(252, 254, 255, 0.92); padding: 14px; }
    .card h3 { margin: 0; font-size: 16px; color: var(--brand); }
    .card-copy { margin: 8px 0 0; color: #49627f; line-height: 1.55; font-size: 14px; }
    .detail-grid { display: grid; gap: 12px; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .summary-grid { margin-top: 12px; display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
    .key-box { border: 1px solid rgba(221, 231, 243, 0.95); border-radius: 14px; background: rgba(247, 250, 255, 0.90); padding: 10px; }
    .key-box span { display: block; color: #657c98; font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.03em; }
    .key-box strong, .key-box a { display: block; margin-top: 6px; color: var(--ink); font-size: 14px; font-weight: 800; word-break: break-word; }
    .timeline-list, .mini-list { display: grid; gap: 8px; margin-top: 12px; }
    .timeline-item, .mini-item { border: 1px solid rgba(219, 229, 241, 0.95); border-radius: 14px; background: rgba(249, 252, 255, 0.92); padding: 10px 11px; }
    .timeline-item strong, .mini-item strong { display: block; font-size: 13px; line-height: 1.35; }
    .timeline-item .meta, .mini-item .meta { margin-top: 5px; color: var(--muted); font-size: 12px; line-height: 1.4; }
    .empty { border: 1px dashed rgba(184, 205, 228, 0.96); border-radius: 14px; background: rgba(249, 252, 255, 0.92); padding: 16px; text-align: center; color: var(--muted); font-size: 13px; }
    .debug-box { margin-top: 14px; border: 1px solid rgba(204, 218, 234, 0.95); border-radius: 16px; background: rgba(248, 251, 255, 0.94); padding: 12px; overflow: auto; font-size: 12px; line-height: 1.45; color: #2f4d6d; min-height: 100px; white-space: pre-wrap; }
    .table-wrap { margin-top: 12px; overflow: auto; border: 1px solid rgba(209, 223, 241, 0.96); border-radius: 16px; background: rgba(252, 254, 255, 0.96); }
    table.data-table { width: 100%; border-collapse: collapse; min-width: 1080px; }
    table.data-table th, table.data-table td { border-bottom: 1px solid rgba(221, 231, 243, 0.92); padding: 8px; vertical-align: top; text-align: left; font-size: 12px; }
    table.data-table th { position: sticky; top: 0; z-index: 1; background: rgba(241, 248, 255, 0.98); color: #325578; font-weight: 900; }
    table.data-table tr.row-dirty { background: rgba(255, 249, 227, 0.7); }
    .table-input, .table-select, .table-textarea { width: 100%; min-width: 120px; padding: 8px 9px; border-radius: 10px; font-size: 12px; }
    .table-textarea { min-height: 72px; resize: vertical; }
    .table-checkbox { width: 16px; height: 16px; }
    .table-readonly { white-space: pre-wrap; color: #294968; line-height: 1.45; }
    .db-column-panel { margin-top: 12px; border: 1px solid rgba(209, 223, 241, 0.96); border-radius: 16px; background: rgba(248, 251, 255, 0.94); padding: 12px; }
    .db-column-toolbar { display: flex; flex-wrap: wrap; align-items: flex-start; justify-content: space-between; gap: 10px; }
    .db-column-title { margin: 0; font-size: 14px; color: #274f77; }
    .db-column-toggle-wrap { margin-top: 10px; }
    .db-column-chip.inactive { background: rgba(255,255,255,0.72); color: #5d7591; border-color: rgba(190, 206, 226, 0.95); }
    details.surface summary { list-style: none; cursor: pointer; padding: 14px; font-size: 17px; font-weight: 900; color: var(--brand); }
    details.surface summary::-webkit-details-marker { display: none; }
    details.surface .surface-body { padding-top: 0; }
    .hint-line { margin-top: 10px; color: #5c738f; font-size: 12px; line-height: 1.45; }
    @media (max-width: 1180px) { .mast { grid-template-columns: 1fr; } .workspace { grid-template-columns: 1fr; } .queue-list { max-height: none; } }
    @media (max-width: 900px) { .dock, .detail-grid, .grid-4 { grid-template-columns: 1fr; } .grid-3 { grid-template-columns: repeat(2, minmax(0, 1fr)); } .summary-grid { grid-template-columns: 1fr 1fr; } table.data-table { min-width: 900px; } }
    @media (max-width: 640px) { .wrap { padding-inline: 10px; } .grid-2, .grid-3, .summary-grid { grid-template-columns: 1fr; } .mast { border-radius: 22px; padding: 14px; } .surface-head { padding-inline: 12px; } .surface-body, .queue-list { padding-inline: 12px; } .snapshot-grid { grid-template-columns: 1fr 1fr; } .stat-card strong { font-size: 28px; } }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="mast">
      <div class="title-block">
        <div class="eyebrow">Field Workflow Console</div>
        <h1>__PAGE_TITLE__</h1>
        <p>현장 담당자가 휴대폰에서 민원 큐를 훑고, 세대 상세를 열어 상태 변경, 사진 업로드, 문자 발송, 비용 입력까지 한 번에 처리할 수 있도록 정리한 실무형 화면입니다. 접수 누락보다 처리 속도와 이력 정합성에 맞춰 설계했습니다.</p>
        <div class="hero-links">
          <a href="/web/console">운영 콘솔</a>
          <a href="/api/complaints">민원 API</a>
          <a href="/api/public/modules">모듈 목록</a>
        </div>
      </div>
      <div class="snapshot-grid">
        <article class="stat-card total"><span>전체 건수</span><strong id="statTotal">0</strong><small>현재 site 필터 기준 전체 민원</small></article>
        <article class="stat-card received"><span>접수 대기</span><strong id="statReceived">0</strong><small>접수 후 아직 움직이지 않은 민원</small></article>
        <article class="stat-card active"><span>처리 진행</span><strong id="statActive">0</strong><small>배정, 방문예정, 처리중, 재민원</small></article>
        <article class="stat-card done"><span>처리 완료</span><strong id="statDone">0</strong><small>처리완료, 세대확인완료, 종결</small></article>
      </div>
    </section>
    <div id="noticeBar" class="notice-bar">토큰과 site를 입력한 뒤 큐를 새로고침하면 현장 민원 작업면이 활성화됩니다.</div>
    <section class="dock">
      <section class="surface">
        <div class="surface-head"><h2>작업 세션</h2><div class="meta">토큰과 현장 site를 유지합니다.</div></div>
        <div class="surface-body">
          <div class="grid-2">
            <div class="field-stack"><label class="caption" for="token">X-Admin-Token</label><input id="token" type="password" placeholder="관리자 토큰" autocomplete="off" autocapitalize="off" spellcheck="false" /></div>
            <div class="field-stack"><label class="caption" for="siteFilter">site</label><input id="siteFilter" placeholder="예: 연산더샵" /></div>
          </div>
          <div class="actions">
            <button class="run" id="refreshQueueBtn" type="button">현장 큐 새로고침</button>
            <button class="ghost" id="savePrefsBtn" type="button">토큰 저장</button>
            <button class="ghost" id="checkConnectionBtn" type="button">연결 확인</button>
            <button class="ghost" id="toggleTokenVisibilityBtn" type="button">토큰 보기</button>
            <button class="ghost" id="clearPrefsBtn" type="button">저장값 지우기</button>
          </div>
          <div class="hint-line" id="sessionStatus">토큰은 브라우저 저장소에 유지되며 기본 숨김 상태입니다. 연결 확인 후 같은 현장으로 바로 복귀할 수 있습니다.</div>
        </div>
      </section>
      <section class="surface">
        <div class="surface-head"><h2>큐 필터</h2><div class="meta" id="queueMeta">site 미설정</div></div>
        <div class="surface-body">
          <div class="grid-2">
            <div class="field-stack">
              <label class="caption" for="statusFilter">상태</label>
              <select id="statusFilter">
                <option value="">전체 상태</option>
                <option value="received">접수</option>
                <option value="assigned">배정완료</option>
                <option value="visit_scheduled">방문예정</option>
                <option value="in_progress">처리중</option>
                <option value="resolved">처리완료</option>
                <option value="resident_confirmed">세대확인완료</option>
                <option value="reopened">재민원</option>
                <option value="closed">종결</option>
              </select>
            </div>
            <div class="field-stack"><label class="caption" for="searchFilter">검색</label><input id="searchFilter" placeholder="동/호, 연락처, 민원내용" /></div>
          </div>
          <div class="actions">
            <button class="ghost" id="recurrenceToggle" type="button">재민원만 보기: OFF</button>
            <button class="ghost" id="clearFiltersBtn" type="button">필터 초기화</button>
          </div>
        </div>
      </section>
      <section class="surface">
        <div class="surface-head"><h2>빠른 가이드</h2><div class="meta">현장 기준 추천 흐름</div></div>
        <div class="surface-body">
          <div class="mini-list">
            <div class="mini-item"><strong>1. 큐에서 세대를 선택</strong><div class="meta">검색창으로 동/호 또는 연락처를 바로 찾습니다.</div></div>
            <div class="mini-item"><strong>2. 상태와 방문일정 저장</strong><div class="meta">배정완료, 방문예정, 처리중 순으로 바꾸면서 이력을 남깁니다.</div></div>
            <div class="mini-item"><strong>3. 사진·문자·비용 입력</strong><div class="meta">증빙과 안내, 정산 자료를 같은 케이스 안에 누적합니다.</div></div>
          </div>
        </div>
      </section>
      <section class="surface">
        <div class="surface-head"><h2>출력</h2><div class="meta">엑셀 · PDF</div></div>
        <div class="surface-body">
          <div class="grid-3">
            <div class="field-stack">
              <label class="caption" for="reportType">출력 구분</label>
              <select id="reportType">
                <option value="all">전체</option>
                <option value="building">동별</option>
                <option value="complaint">민원</option>
                <option value="category">분류별</option>
                <option value="unresolved">미처리</option>
                <option value="closed">종결</option>
              </select>
            </div>
            <div class="field-stack"><label class="caption" for="reportBuilding">동 필터</label><input id="reportBuilding" placeholder="예: 101동, 비우면 전체" /></div>
            <div class="field-stack">
              <label class="caption" for="reportSortBy">정렬 기준</label>
              <select id="reportSortBy">
                <option value="reported_at">접수일시 순</option>
                <option value="building_unit">동/호 순</option>
              </select>
            </div>
          </div>
          <div class="field-stack" style="margin-top:12px;">
            <label class="caption">출력 표지 설정</label>
            <div class="grid-2">
              <div class="field-stack">
                <label class="caption" for="reportCompanyPreset">회사명 선택</label>
                <select id="reportCompanyPreset">
                  <option value="default">운영 기본값</option>
                  <option value="ka">KA Facility OS</option>
                  <option value="facility">시설관리 운영팀</option>
                  <option value="custom">직접 입력 유지</option>
                </select>
              </div>
              <div class="field-stack"><label class="caption" for="reportCompanyName">회사명 입력</label><input id="reportCompanyName" placeholder="예: KA Facility OS" /></div>
            </div>
            <div class="grid-2">
              <div class="field-stack">
                <label class="caption" for="reportContractorPreset">공사업체 선택</label>
                <select id="reportContractorPreset">
                  <option value="default">운영 기본값</option>
                  <option value="paint_vendor">외벽 재도장 협력업체</option>
                  <option value="custom">직접 입력 유지</option>
                </select>
              </div>
              <div class="field-stack"><label class="caption" for="reportContractorName">공사업체 입력</label><input id="reportContractorName" placeholder="예: 외벽 재도장 협력업체" /></div>
            </div>
            <div class="grid-2">
              <div class="field-stack">
                <label class="caption" for="reportPhrasePreset">제출 문구 선택</label>
                <select id="reportPhrasePreset">
                  <option value="default">운영 기본값</option>
                  <option value="submission">상기 현황을 아래와 같이 보고드립니다.</option>
                  <option value="review">귀 관리사무소 검토를 위해 아래와 같이 제출합니다.</option>
                  <option value="share">공사 협의 및 확인용으로 아래와 같이 공유드립니다.</option>
                  <option value="custom">직접 입력 유지</option>
                </select>
              </div>
              <div class="field-stack"><label class="caption" for="reportLogoFile">로고 이미지 불러오기</label><input id="reportLogoFile" type="file" accept="image/png,image/jpeg" /></div>
            </div>
            <div class="field-stack"><label class="caption" for="reportSubmissionPhrase">제출 문구 입력</label><textarea id="reportSubmissionPhrase" placeholder="예: 상기 현황을 아래와 같이 보고드립니다."></textarea></div>
            <div class="grid-2">
              <div class="field-stack"><label class="caption" for="reportLogoStatus">로고 상태</label><input id="reportLogoStatus" placeholder="불러온 로고 없음" readonly /></div>
              <div class="field-stack"><label class="caption" for="reportSettingsStatus">설정 상태</label><input id="reportSettingsStatus" placeholder="표지 설정 기본값 사용" readonly /></div>
            </div>
            <div class="actions">
              <button class="ghost" id="applyReportDefaultsBtn" type="button">기본값 채우기</button>
              <button class="ghost" id="clearReportLogoBtn" type="button">로고 지우기</button>
              <button class="ghost" id="saveReportPrefsBtn" type="button">표지 설정 저장</button>
            </div>
          </div>
          <div class="field-stack" style="margin-top:12px;">
            <label class="caption">표지 프리셋</label>
            <div class="grid-2">
              <div class="field-stack"><label class="caption" for="reportPresetName">프리셋 이름</label><input id="reportPresetName" placeholder="예: 관리사무소 제출 기본안" /></div>
              <div class="field-stack"><label class="caption" for="reportPresetSelect">저장된 프리셋</label><select id="reportPresetSelect"><option value="">저장된 프리셋 없음</option></select></div>
            </div>
            <div class="actions">
              <button class="ghost" id="saveReportPresetBtn" type="button">프리셋 저장</button>
              <button class="ghost" id="loadReportPresetBtn" type="button">프리셋 불러오기</button>
              <button class="ghost" id="deleteReportPresetBtn" type="button">프리셋 삭제</button>
            </div>
          </div>
          <div class="field-stack" style="margin-top:12px;">
            <label class="caption">관리자 공통 기본값</label>
            <div class="grid-2">
              <div class="field-stack">
                <label class="caption" for="reportAdminScope">기본값 범위</label>
                <select id="reportAdminScope">
                  <option value="site">현재 site 기본값</option>
                  <option value="global">공통 기본값</option>
                </select>
              </div>
              <div class="field-stack"><label class="caption" for="reportAdminStatus">관리자 기본값 상태</label><input id="reportAdminStatus" placeholder="관리자 기본값 미확인" readonly /></div>
            </div>
            <div class="actions">
              <button class="ghost" id="loadAdminReportDefaultBtn" type="button">관리자 기본값 불러오기</button>
              <button class="ghost" id="saveAdminReportDefaultBtn" type="button">현재 값 관리자 기본값 저장</button>
              <button class="ghost" id="deleteAdminReportDefaultBtn" type="button">관리자 기본값 삭제</button>
            </div>
          </div>
          <div class="field-stack" style="margin-top:12px;">
            <label class="caption">표지 미리보기</label>
            <div class="card" id="reportPreviewCard"><div class="empty">표지 설정을 입력하면 여기에 미리보기가 나타납니다.</div></div>
          </div>
          <div class="actions">
            <button class="run" id="downloadXlsxBtn" type="button">엑셀 출력</button>
            <button class="ghost" id="downloadPdfBtn" type="button">PDF 출력</button>
          </div>
          <div class="hint-line">현재 site를 기준으로 `전체 / 동별 / 민원 / 분류별 / 미처리 / 종결` 보고서를 내려받습니다. PDF는 위 표지 설정과 불러온 로고 이미지를 함께 반영합니다.</div>
        </div>
      </section>
    </section>
    <div class="tab-strip">
      <button class="tab-btn active" id="fieldTabBtn" type="button">현장 처리</button>
      <button class="tab-btn" id="dbTabBtn" type="button">DB 레코드 관리</button>
    </div>
    <section class="workspace" id="fieldWorkspace">
      <section class="surface queue-panel">
        <div class="surface-head"><h2>현장 큐</h2><div class="meta" id="queueCountLabel">0건</div></div>
        <div class="queue-list" id="queueList"><div class="empty">큐를 불러오면 여기에 민원 카드가 나타납니다.</div></div>
      </section>
      <section class="detail-panel">
        <details class="surface" open>
          <summary>민원 신규 등록</summary>
          <div class="surface-body">
            <div class="grid-3">
              <div class="field-stack"><label class="caption" for="createSite">site</label><input id="createSite" placeholder="연산더샵" /></div>
              <div class="field-stack"><label class="caption" for="createBuilding">동</label><input id="createBuilding" placeholder="101동" /></div>
              <div class="field-stack"><label class="caption" for="createUnitNumber">호수</label><input id="createUnitNumber" placeholder="503호" /></div>
            </div>
            <div class="grid-3">
              <div class="field-stack"><label class="caption" for="createResidentName">입주민명</label><input id="createResidentName" placeholder="선택 입력" /></div>
              <div class="field-stack"><label class="caption" for="createPhone">연락처</label><input id="createPhone" placeholder="010-0000-0000" /></div>
              <div class="field-stack"><label class="caption" for="createPriority">우선순위</label><select id="createPriority"><option value="medium">보통</option><option value="low">낮음</option><option value="high">높음</option><option value="urgent">긴급</option></select></div>
            </div>
            <div class="grid-2">
              <div class="field-stack">
                <label class="caption" for="createComplaintType">민원유형</label>
                <select id="createComplaintType">
                  <option value="">자동 분류</option><option value="screen_contamination">방충망 오염</option><option value="screen_damage">방충망 파손</option><option value="glass_contamination">유리/창문 오염</option><option value="glass_damage">유리/창문 파손</option><option value="railing_contamination">난간 오염</option><option value="louver_issue">루버창 불량</option><option value="silicone_issue">실리콘/퍼티 불량</option><option value="wall_floor_contamination">벽면/바닥 오염</option><option value="other_finish_issue">기타 마감불량</option><option value="composite">복합 민원</option>
                </select>
              </div>
              <div class="field-stack"><label class="caption" for="createRecurrence">재민원 여부</label><select id="createRecurrence"><option value="false">신규 접수</option><option value="true">재민원</option></select></div>
            </div>
            <div class="field-stack"><label class="caption" for="createDescription">민원내용</label><textarea id="createDescription" placeholder="예: 거실 방충망 오염, 안방 난간 페인트 오염"></textarea></div>
            <div class="actions">
              <button class="run" id="createComplaintBtn" type="button">민원 등록</button>
              <button class="ghost" id="seedCreateSiteBtn" type="button">현재 site 채우기</button>
            </div>
          </div>
        </details>
        <section class="surface" id="detailSurface" style="margin-top: 12px;">
          <div class="surface-head"><h2>상세 처리</h2><div class="meta" id="detailMeta">민원을 선택하세요.</div></div>
          <div class="surface-body" id="detailBody"><div class="empty">현장 큐에서 세대를 선택하면 처리 화면이 열립니다.</div></div>
        </section>
      </section>
    </section>
    <section class="surface hidden" id="dbWorkspace" style="margin-top: 14px;">
      <div class="surface-head"><h2>DB 레코드 전용 관리</h2><div class="meta" id="dbMeta">site 미설정</div></div>
      <div class="surface-body">
        <div class="grid-4">
          <div class="field-stack">
            <label class="caption" for="dbRecordType">레코드 종류</label>
            <select id="dbRecordType">
              <option value="cases">민원 본체</option>
              <option value="events">처리 이력</option>
              <option value="attachments">첨부</option>
              <option value="messages">문자 이력</option>
              <option value="cost_items">비용 항목</option>
            </select>
          </div>
          <div class="field-stack"><label class="caption" for="dbLimit">행 수</label><input id="dbLimit" type="number" min="1" max="1000" value="200" /></div>
          <div class="field-stack"><label class="caption" for="dbSearch">검색</label><input id="dbSearch" placeholder="동/호, 제목, 메모, 파일명 등" /></div>
          <div class="field-stack"><label class="caption" for="dbSiteMirror">site</label><input id="dbSiteMirror" placeholder="현재 site 사용" readonly /></div>
        </div>
        <div class="actions">
          <button class="run" id="loadDbRecordsBtn" type="button">DB 레코드 불러오기</button>
          <button class="ghost" id="applyDbChangesBtn" type="button">변경 일괄 적용</button>
          <button class="ghost" id="deleteDbRowsBtn" type="button">선택 행 삭제</button>
          <button class="ghost" id="clearDbSelectionBtn" type="button">선택/변경 초기화</button>
        </div>
        <div class="hint-line" id="dbSummary">site를 기준으로 DB 레코드 원본을 표로 불러오고, 수정된 셀만 일괄 반영합니다.</div>
        <div class="db-column-panel">
          <div class="db-column-toolbar">
            <div>
              <h3 class="db-column-title">칼럼 숨김/표시</h3>
              <div class="hint-line" id="dbColumnSummary">레코드를 불러오면 표시할 칼럼을 선택할 수 있습니다.</div>
            </div>
            <div class="actions" style="margin-top:0;">
              <button class="ghost" id="showAllDbColumnsBtn" type="button">전체 표시</button>
              <button class="ghost" id="resetDbColumnsBtn" type="button">기본값 복원</button>
            </div>
          </div>
          <div class="chip-row db-column-toggle-wrap" id="dbColumnToggleWrap"><div class="empty">레코드를 불러오면 칼럼 토글이 나타납니다.</div></div>
        </div>
        <div class="table-wrap" id="dbTableWrap"><div class="empty">DB 레코드 관리 탭에서 레코드를 불러오면 표가 나타납니다.</div></div>
      </div>
    </section>
    <pre id="debugBox" class="debug-box">ready</pre>
  </div>
  <script defer src="__SCRIPT_URL__"></script>
</body>
</html>
"""
    return (
        template.replace("__PAGE_TITLE__", page_title)
        .replace("__SCRIPT_URL__", complaints_script_url())
    )
