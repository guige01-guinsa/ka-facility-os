"""Complaint mobile web field console."""

from __future__ import annotations

import html


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
          <div class="grid-2">
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
  <script>
__SCRIPT__
  </script>
</body>
</html>
"""
    script = """
const STORAGE_KEYS = {
  token: 'kaFacility.auth.token',
  site: 'kaFacility.complaints.site',
  dbColumnPrefs: 'kaFacility.complaints.dbColumnPrefs',
  reportCoverPrefs: 'kaFacility.complaints.reportCoverPrefs',
  reportCoverPresets: 'kaFacility.complaints.reportCoverPresets',
};
const TOKEN_STORAGE_KEYS = ['kaFacility.auth.token', 'kaFacilityAdminToken', 'kaFacilityMainToken', 'kaFacility.complaints.token'];
const AUTH_PROFILE_KEY = 'kaFacility.auth.profile';
const STATUS_LABELS = { received: '접수', assigned: '배정완료', visit_scheduled: '방문예정', in_progress: '처리중', resolved: '처리완료', resident_confirmed: '세대확인완료', reopened: '재민원', closed: '종결' };
const TYPE_LABELS = { screen_contamination: '방충망 오염', screen_damage: '방충망 파손', glass_contamination: '유리/창문 오염', glass_damage: '유리/창문 파손', railing_contamination: '난간 오염', louver_issue: '루버창 불량', silicone_issue: '실리콘/퍼티 불량', wall_floor_contamination: '벽면/바닥 오염', other_finish_issue: '기타 마감불량', composite: '복합 민원' };
const PRIORITY_LABELS = { low: '낮음', medium: '보통', high: '높음', urgent: '긴급' };
const ATTACHMENT_KIND_LABELS = { intake: '접수 사진', before: '작업 전 사진', after: '작업 후 사진', other: '기타' };
const REPORT_COMPANY_PRESETS = {
  default: 'KA Facility OS',
  ka: 'KA Facility OS',
  facility: '시설관리 운영팀',
  custom: '',
};
const REPORT_CONTRACTOR_PRESETS = {
  default: '외벽 재도장 협력업체',
  paint_vendor: '외벽 재도장 협력업체',
  custom: '',
};
const REPORT_SUBMISSION_PRESETS = {
  default: '상기 현황을 아래와 같이 보고드립니다.',
  submission: '상기 현황을 아래와 같이 보고드립니다.',
  review: '귀 관리사무소 검토를 위해 아래와 같이 제출합니다.',
  share: '공사 협의 및 확인용으로 아래와 같이 공유드립니다.',
  custom: '',
};
const REPORT_TYPE_LABELS = { all: '전체', building: '동별', complaint: '민원', category: '분류별', unresolved: '미처리', closed: '종결' };
const PRIORITY_ORDER = { urgent: 0, high: 1, medium: 2, low: 3 };
const ACTIVE_STATUSES = new Set(['assigned', 'visit_scheduled', 'in_progress', 'reopened']);
const DONE_STATUSES = new Set(['resolved', 'resident_confirmed', 'closed']);
const STATUS_SEQUENCE = ['received', 'assigned', 'visit_scheduled', 'in_progress', 'resolved', 'resident_confirmed', 'reopened', 'closed'];
const MESSAGE_TEMPLATE_BUILDERS = {
  '': () => '',
  intake_ack: () => '안녕하세요. 외부도색 관련 민원이 접수되었습니다. 확인 후 방문 일정을 안내드리겠습니다.',
  visit_notice: (caseData) => '안녕하세요. 접수하신 민원 관련하여 ' + (formatPlainDateTime(caseData.scheduled_visit_at) || '방문 일정') + ' 방문 예정입니다. 협조 부탁드립니다.',
  resolved_notice: () => '안녕하세요. 접수하신 민원에 대한 조치가 완료되었습니다. 확인 후 추가 문의가 있으시면 연락 부탁드립니다.',
  revisit_notice: (caseData) => '안녕하세요. 추가 조치가 필요하여 ' + (formatPlainDateTime(caseData.scheduled_visit_at) || '재방문 일정') + ' 재방문 예정입니다.',
};

const state = {
  queue: [],
  filteredQueue: [],
  selectedId: null,
  detail: null,
  householdHistory: null,
  recurrenceOnly: false,
  activeTab: 'field',
  dbEditor: { recordType: 'cases', columns: [], rows: [], totalCount: 0, dirtyRows: {}, selectedIds: {}, originalRows: {}, hiddenColumnsByType: {} },
  reportCover: { companyName: 'KA Facility OS', contractorName: '외벽 재도장 협력업체', submissionPhrase: '상기 현황을 아래와 같이 보고드립니다.', logoDataUrl: '', logoFileName: '', logoPersisted: false },
  reportPresets: {},
  reportCoverPrefsLoaded: false,
  reportAdminDefault: null,
};
let tokenHideTimer = null;
const elements = {
  noticeBar: document.getElementById('noticeBar'),
  token: document.getElementById('token'),
  siteFilter: document.getElementById('siteFilter'),
  refreshQueueBtn: document.getElementById('refreshQueueBtn'),
  savePrefsBtn: document.getElementById('savePrefsBtn'),
  checkConnectionBtn: document.getElementById('checkConnectionBtn'),
  toggleTokenVisibilityBtn: document.getElementById('toggleTokenVisibilityBtn'),
  clearPrefsBtn: document.getElementById('clearPrefsBtn'),
  sessionStatus: document.getElementById('sessionStatus'),
  statusFilter: document.getElementById('statusFilter'),
  searchFilter: document.getElementById('searchFilter'),
  recurrenceToggle: document.getElementById('recurrenceToggle'),
  clearFiltersBtn: document.getElementById('clearFiltersBtn'),
  reportType: document.getElementById('reportType'),
  reportBuilding: document.getElementById('reportBuilding'),
  reportCompanyPreset: document.getElementById('reportCompanyPreset'),
  reportCompanyName: document.getElementById('reportCompanyName'),
  reportContractorPreset: document.getElementById('reportContractorPreset'),
  reportContractorName: document.getElementById('reportContractorName'),
  reportPhrasePreset: document.getElementById('reportPhrasePreset'),
  reportSubmissionPhrase: document.getElementById('reportSubmissionPhrase'),
  reportLogoFile: document.getElementById('reportLogoFile'),
  reportLogoStatus: document.getElementById('reportLogoStatus'),
  reportSettingsStatus: document.getElementById('reportSettingsStatus'),
  applyReportDefaultsBtn: document.getElementById('applyReportDefaultsBtn'),
  clearReportLogoBtn: document.getElementById('clearReportLogoBtn'),
  saveReportPrefsBtn: document.getElementById('saveReportPrefsBtn'),
  reportPresetName: document.getElementById('reportPresetName'),
  reportPresetSelect: document.getElementById('reportPresetSelect'),
  saveReportPresetBtn: document.getElementById('saveReportPresetBtn'),
  loadReportPresetBtn: document.getElementById('loadReportPresetBtn'),
  deleteReportPresetBtn: document.getElementById('deleteReportPresetBtn'),
  reportAdminScope: document.getElementById('reportAdminScope'),
  reportAdminStatus: document.getElementById('reportAdminStatus'),
  loadAdminReportDefaultBtn: document.getElementById('loadAdminReportDefaultBtn'),
  saveAdminReportDefaultBtn: document.getElementById('saveAdminReportDefaultBtn'),
  deleteAdminReportDefaultBtn: document.getElementById('deleteAdminReportDefaultBtn'),
  reportPreviewCard: document.getElementById('reportPreviewCard'),
  downloadXlsxBtn: document.getElementById('downloadXlsxBtn'),
  downloadPdfBtn: document.getElementById('downloadPdfBtn'),
  fieldTabBtn: document.getElementById('fieldTabBtn'),
  dbTabBtn: document.getElementById('dbTabBtn'),
  fieldWorkspace: document.getElementById('fieldWorkspace'),
  dbWorkspace: document.getElementById('dbWorkspace'),
  dbRecordType: document.getElementById('dbRecordType'),
  dbLimit: document.getElementById('dbLimit'),
  dbSearch: document.getElementById('dbSearch'),
  dbSiteMirror: document.getElementById('dbSiteMirror'),
  loadDbRecordsBtn: document.getElementById('loadDbRecordsBtn'),
  applyDbChangesBtn: document.getElementById('applyDbChangesBtn'),
  deleteDbRowsBtn: document.getElementById('deleteDbRowsBtn'),
  clearDbSelectionBtn: document.getElementById('clearDbSelectionBtn'),
  dbSummary: document.getElementById('dbSummary'),
  dbColumnSummary: document.getElementById('dbColumnSummary'),
  dbColumnToggleWrap: document.getElementById('dbColumnToggleWrap'),
  showAllDbColumnsBtn: document.getElementById('showAllDbColumnsBtn'),
  resetDbColumnsBtn: document.getElementById('resetDbColumnsBtn'),
  dbTableWrap: document.getElementById('dbTableWrap'),
  dbMeta: document.getElementById('dbMeta'),
  queueMeta: document.getElementById('queueMeta'),
  queueCountLabel: document.getElementById('queueCountLabel'),
  queueList: document.getElementById('queueList'),
  detailMeta: document.getElementById('detailMeta'),
  detailBody: document.getElementById('detailBody'),
  debugBox: document.getElementById('debugBox'),
  statTotal: document.getElementById('statTotal'),
  statReceived: document.getElementById('statReceived'),
  statActive: document.getElementById('statActive'),
  statDone: document.getElementById('statDone'),
  createSite: document.getElementById('createSite'),
  createBuilding: document.getElementById('createBuilding'),
  createUnitNumber: document.getElementById('createUnitNumber'),
  createResidentName: document.getElementById('createResidentName'),
  createPhone: document.getElementById('createPhone'),
  createPriority: document.getElementById('createPriority'),
  createComplaintType: document.getElementById('createComplaintType'),
  createRecurrence: document.getElementById('createRecurrence'),
  createDescription: document.getElementById('createDescription'),
  createComplaintBtn: document.getElementById('createComplaintBtn'),
  seedCreateSiteBtn: document.getElementById('seedCreateSiteBtn'),
};

function escapeHtml(value) {
  return String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function statusCssClass(value) {
  return escapeHtml(String(value ?? '').replace(/_/g, '-'));
}

function formatApiError(payload) {
  if (!payload) return '요청이 실패했습니다.';
  if (Array.isArray(payload.detail)) {
    return payload.detail.map((item) => item && item.msg ? item.msg : JSON.stringify(item)).join('; ');
  }
  if (typeof payload.detail === 'string') return payload.detail;
  return JSON.stringify(payload.detail || payload);
}

function writeDebug(label, payload) {
  const stamp = new Date().toLocaleString('ko-KR');
  let body = '';
  if (payload instanceof Error) body = payload.stack || payload.message;
  else if (typeof payload === 'string') body = payload;
  else {
    try { body = JSON.stringify(payload, null, 2); } catch (error) { body = String(payload); }
  }
  elements.debugBox.textContent = '[' + stamp + '] ' + label + '\\n' + body;
}

function setNotice(message, kind) {
  elements.noticeBar.textContent = message;
  elements.noticeBar.className = 'notice-bar';
  if (kind === 'error') elements.noticeBar.classList.add('error');
  if (kind === 'success') elements.noticeBar.classList.add('success');
}

function nullIfBlank(value) {
  const normalized = String(value ?? '').trim();
  return normalized ? normalized : null;
}

function maskToken(value) {
  const token = String(value ?? '').trim();
  if (!token) return '미저장';
  if (token.length <= 8) return token[0] + '***' + token[token.length - 1];
  return token.slice(0, 4) + '...' + token.slice(-4);
}

function updateSessionStatus(message) {
  if (!elements.sessionStatus) return;
  elements.sessionStatus.textContent = message;
}

function numberValue(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : 0;
}

function formatDateTime(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat('ko-KR', { dateStyle: 'short', timeStyle: 'short' }).format(date);
}

function formatPlainDateTime(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  return year + '-' + month + '-' + day + ' ' + hours + ':' + minutes;
}

function formatCurrency(value) {
  return new Intl.NumberFormat('ko-KR', { style: 'currency', currency: 'KRW', maximumFractionDigits: 0 }).format(numberValue(value));
}

function toLocalDateTimeInput(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  return year + '-' + month + '-' + day + 'T' + hours + ':' + minutes;
}

function fromLocalDateTimeInput(value) {
  const normalized = String(value ?? '').trim();
  if (!normalized) return null;
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function buildOptions(map, currentValue, blankLabel) {
  const rows = [];
  if (blankLabel !== undefined) rows.push('<option value="">' + escapeHtml(blankLabel) + '</option>');
  Object.entries(map).forEach(([value, label]) => {
    rows.push('<option value="' + escapeHtml(value) + '"' + (value === currentValue ? ' selected' : '') + '>' + escapeHtml(label) + '</option>');
  });
  return rows.join('');
}

function parseContentDispositionFilename(headerValue) {
  const header = String(headerValue || '');
  const utf8Match = header.match(/filename\\*=UTF-8''([^;]+)/i);
  if (utf8Match && utf8Match[1]) {
    try { return decodeURIComponent(utf8Match[1]); } catch (error) {}
  }
  const quotedMatch = header.match(/filename=\"([^\"]+)\"/i);
  if (quotedMatch && quotedMatch[1]) return quotedMatch[1];
  const rawMatch = header.match(/filename=([^;]+)/i);
  if (rawMatch && rawMatch[1]) return rawMatch[1].trim();
  return '';
}

function summarizeSearch(item) {
  return [item.site, item.building, item.unit_number, item.resident_name, item.contact_phone, item.complaint_type_label, item.title, item.description, item.assignee].filter(Boolean).join(' ').toLowerCase();
}

function getStoredToken() {
  const keys = Array.from(new Set([STORAGE_KEYS.token].concat(TOKEN_STORAGE_KEYS)));
  for (const key of keys) {
    const sessionToken = window.sessionStorage.getItem(key) || '';
    if (!sessionToken) continue;
    if (key !== STORAGE_KEYS.token) {
      window.sessionStorage.setItem(STORAGE_KEYS.token, sessionToken);
      window.sessionStorage.removeItem(key);
    }
    return sessionToken;
  }
  for (const key of keys) {
    const localToken = window.localStorage.getItem(key) || '';
    if (!localToken) continue;
    window.sessionStorage.setItem(STORAGE_KEYS.token, localToken);
    keys.forEach((aliasKey) => {
      if (aliasKey !== STORAGE_KEYS.token) {
        window.sessionStorage.removeItem(aliasKey);
      }
      window.localStorage.removeItem(aliasKey);
    });
    return localToken;
  }
  return '';
}

function persistStoredToken(token) {
  const normalized = String(token || '').trim();
  if (!normalized) return;
  const keys = Array.from(new Set([STORAGE_KEYS.token].concat(TOKEN_STORAGE_KEYS)));
  window.sessionStorage.setItem(STORAGE_KEYS.token, normalized);
  keys.forEach((key) => {
    if (key !== STORAGE_KEYS.token) {
      window.sessionStorage.removeItem(key);
    }
    window.localStorage.removeItem(key);
  });
}

function clearStoredToken() {
  const keys = Array.from(new Set([STORAGE_KEYS.token].concat(TOKEN_STORAGE_KEYS)));
  keys.forEach((key) => {
    window.sessionStorage.removeItem(key);
    window.localStorage.removeItem(key);
  });
}

function getStoredAuthProfile() {
  const raw = window.sessionStorage.getItem(AUTH_PROFILE_KEY) || window.localStorage.getItem(AUTH_PROFILE_KEY) || '';
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') {
      window.sessionStorage.setItem(AUTH_PROFILE_KEY, JSON.stringify(parsed));
      window.localStorage.removeItem(AUTH_PROFILE_KEY);
      return parsed;
    }
  } catch (error) {
    window.sessionStorage.removeItem(AUTH_PROFILE_KEY);
    window.localStorage.removeItem(AUTH_PROFILE_KEY);
  }
  return null;
}

function persistAuthProfile(profile) {
  if (!profile) {
    window.sessionStorage.removeItem(AUTH_PROFILE_KEY);
    window.localStorage.removeItem(AUTH_PROFILE_KEY);
    return;
  }
  window.sessionStorage.setItem(AUTH_PROFILE_KEY, JSON.stringify(profile));
  window.localStorage.removeItem(AUTH_PROFILE_KEY);
}

function clearStoredAuthArtifacts(options) {
  clearStoredToken();
  persistAuthProfile(null);
  if (!(options && options.preserveInput)) {
    elements.token.value = '';
  }
}

function savePrefs() {
  try {
    persistStoredToken(elements.token.value.trim());
    localStorage.setItem(STORAGE_KEYS.site, elements.siteFilter.value.trim());
    updateSessionStatus('저장된 토큰: ' + maskToken(elements.token.value) + ' · site: ' + (elements.siteFilter.value.trim() || '미설정'));
  } catch (error) {
    writeDebug('localStorage-save-error', error);
  }
}

function loadPrefs() {
  try {
    const token = getStoredToken();
    const site = localStorage.getItem(STORAGE_KEYS.site) || '';
    const authProfile = getStoredAuthProfile();
    const dbColumnPrefsRaw = localStorage.getItem(STORAGE_KEYS.dbColumnPrefs) || '{}';
    const reportCoverPrefsRaw = localStorage.getItem(STORAGE_KEYS.reportCoverPrefs) || '{}';
    const reportCoverPresetsRaw = localStorage.getItem(STORAGE_KEYS.reportCoverPresets) || '{}';
    let dbColumnPrefs = {};
    let reportCoverPrefs = {};
    let reportCoverPresets = {};
    try {
      dbColumnPrefs = JSON.parse(dbColumnPrefsRaw) || {};
    } catch (error) {
      dbColumnPrefs = {};
    }
    try {
      reportCoverPrefs = JSON.parse(reportCoverPrefsRaw) || {};
    } catch (error) {
      reportCoverPrefs = {};
    }
    try {
      reportCoverPresets = JSON.parse(reportCoverPresetsRaw) || {};
    } catch (error) {
      reportCoverPresets = {};
    }
    if (token) elements.token.value = token;
    if (site) {
      elements.siteFilter.value = site;
      if (!elements.createSite.value.trim()) elements.createSite.value = site;
    }
    state.dbEditor.hiddenColumnsByType = dbColumnPrefs && typeof dbColumnPrefs === 'object' ? dbColumnPrefs : {};
    if (reportCoverPrefs && typeof reportCoverPrefs === 'object') {
      state.reportCoverPrefsLoaded = Object.keys(reportCoverPrefs).length > 0;
      state.reportCover = {
        companyName: String(reportCoverPrefs.companyName || state.reportCover.companyName || ''),
        contractorName: String(reportCoverPrefs.contractorName || state.reportCover.contractorName || ''),
        submissionPhrase: String(reportCoverPrefs.submissionPhrase || state.reportCover.submissionPhrase || ''),
        logoDataUrl: String(reportCoverPrefs.logoDataUrl || ''),
        logoFileName: String(reportCoverPrefs.logoFileName || ''),
        logoPersisted: Boolean(reportCoverPrefs.logoDataUrl),
      };
    }
    state.reportPresets = reportCoverPresets && typeof reportCoverPresets === 'object' ? reportCoverPresets : {};
    if (authProfile && typeof authProfile === 'object') {
      updateSessionStatus('저장된 토큰: ' + maskToken(token) + ' · ' + String(authProfile.username || '-') + ' / ' + String(authProfile.role || '-') + ' · site: ' + (site || '미설정'));
    } else {
      updateSessionStatus('저장된 토큰: ' + maskToken(token) + ' · site: ' + (site || '미설정'));
    }
  } catch (error) {
    writeDebug('localStorage-load-error', error);
  }
}

function saveDbColumnPrefs() {
  try {
    localStorage.setItem(STORAGE_KEYS.dbColumnPrefs, JSON.stringify(state.dbEditor.hiddenColumnsByType || {}));
  } catch (error) {
    writeDebug('localStorage-db-column-save-error', error);
  }
}

function syncReportCoverStatus() {
  if (elements.reportLogoStatus) {
    elements.reportLogoStatus.value = state.reportCover.logoFileName ? (state.reportCover.logoFileName + (state.reportCover.logoPersisted ? ' · 저장됨' : ' · 현재 세션')) : '불러온 로고 없음';
  }
  if (elements.reportSettingsStatus) {
    elements.reportSettingsStatus.value = '회사명 ' + (state.reportCover.companyName || '미입력') + ' · 공사업체 ' + (state.reportCover.contractorName || '미입력');
  }
  if (elements.reportAdminStatus && !elements.reportAdminStatus.value) {
    elements.reportAdminStatus.value = '관리자 기본값 미확인';
  }
}

function fillReportCoverInputs() {
  if (elements.reportCompanyName) elements.reportCompanyName.value = state.reportCover.companyName || '';
  if (elements.reportContractorName) elements.reportContractorName.value = state.reportCover.contractorName || '';
  if (elements.reportSubmissionPhrase) elements.reportSubmissionPhrase.value = state.reportCover.submissionPhrase || '';
  if (elements.reportCompanyPreset) {
    elements.reportCompanyPreset.value = Object.entries(REPORT_COMPANY_PRESETS).find(([, value]) => value && value === state.reportCover.companyName)?.[0] || 'custom';
  }
  if (elements.reportContractorPreset) {
    elements.reportContractorPreset.value = Object.entries(REPORT_CONTRACTOR_PRESETS).find(([, value]) => value && value === state.reportCover.contractorName)?.[0] || 'custom';
  }
  if (elements.reportPhrasePreset) {
    elements.reportPhrasePreset.value = Object.entries(REPORT_SUBMISSION_PRESETS).find(([, value]) => value && value === state.reportCover.submissionPhrase)?.[0] || 'custom';
  }
  syncReportCoverStatus();
  renderReportPreview();
}

function readReportCoverInputs() {
  state.reportCover.companyName = String(elements.reportCompanyName?.value || '').trim();
  state.reportCover.contractorName = String(elements.reportContractorName?.value || '').trim();
  state.reportCover.submissionPhrase = String(elements.reportSubmissionPhrase?.value || '').trim();
  syncReportCoverStatus();
}

function buildPersistableReportCoverSnapshot() {
  readReportCoverInputs();
  const persistableLogo = state.reportCover.logoDataUrl && state.reportCover.logoDataUrl.length <= 350000 ? state.reportCover.logoDataUrl : '';
  return {
    companyName: state.reportCover.companyName,
    contractorName: state.reportCover.contractorName,
    submissionPhrase: state.reportCover.submissionPhrase,
    logoDataUrl: persistableLogo,
    logoFileName: persistableLogo ? state.reportCover.logoFileName : '',
  };
}

function applyReportCoverSnapshot(snapshot, options) {
  const payload = snapshot && typeof snapshot === 'object' ? snapshot : {};
  state.reportCover.companyName = String(payload.companyName ?? payload.company_name ?? '');
  state.reportCover.contractorName = String(payload.contractorName ?? payload.contractor_name ?? '');
  state.reportCover.submissionPhrase = String(payload.submissionPhrase ?? payload.submission_phrase ?? '');
  state.reportCover.logoDataUrl = String(payload.logoDataUrl ?? payload.logo_data_url ?? '');
  state.reportCover.logoFileName = String(payload.logoFileName ?? payload.logo_file_name ?? '');
  state.reportCover.logoPersisted = Boolean(state.reportCover.logoDataUrl && state.reportCover.logoDataUrl.length <= 350000);
  fillReportCoverInputs();
  if (!(options && options.persist === false)) saveReportCoverPrefs();
}

function saveReportPresets() {
  try {
    localStorage.setItem(STORAGE_KEYS.reportCoverPresets, JSON.stringify(state.reportPresets || {}));
  } catch (error) {
    writeDebug('localStorage-report-presets-save-error', error);
  }
}

function renderReportPresetOptions(selectedName) {
  if (!elements.reportPresetSelect) return;
  const presets = state.reportPresets && typeof state.reportPresets === 'object' ? state.reportPresets : {};
  const names = Object.keys(presets).sort((left, right) => left.localeCompare(right, 'ko'));
  const selected = names.includes(String(selectedName || '').trim()) ? String(selectedName || '').trim() : (elements.reportPresetSelect.value || '');
  if (!names.length) {
    elements.reportPresetSelect.innerHTML = '<option value="">저장된 프리셋 없음</option>';
    return;
  }
  elements.reportPresetSelect.innerHTML = '<option value="">프리셋 선택</option>' + names.map((name) => '<option value="' + escapeHtml(name) + '"' + (name === selected ? ' selected' : '') + '>' + escapeHtml(name) + '</option>').join('');
  if (selected && elements.reportPresetName) elements.reportPresetName.value = selected;
}

function saveReportCoverPrefs() {
  const payload = buildPersistableReportCoverSnapshot();
  state.reportCover.logoPersisted = Boolean(payload.logoDataUrl);
  state.reportCoverPrefsLoaded = true;
  try {
    localStorage.setItem(STORAGE_KEYS.reportCoverPrefs, JSON.stringify(payload));
  } catch (error) {
    state.reportCover.logoPersisted = false;
    writeDebug('localStorage-report-cover-save-error', error);
  }
  syncReportCoverStatus();
  renderReportPreview();
}

function saveCurrentReportPreset() {
  const presetName = String(elements.reportPresetName?.value || '').trim();
  if (!presetName) {
    setNotice('프리셋 이름을 입력하세요.', 'error');
    return;
  }
  saveReportCoverPrefs();
  const alreadyExists = Boolean(state.reportPresets[presetName]);
  if (alreadyExists && !window.confirm('같은 이름의 프리셋을 덮어쓸까요?')) return;
  const snapshot = buildPersistableReportCoverSnapshot();
  const droppedLogo = Boolean(state.reportCover.logoDataUrl && !snapshot.logoDataUrl);
  state.reportPresets[presetName] = Object.assign({}, snapshot, { savedAt: new Date().toISOString() });
  saveReportPresets();
  renderReportPresetOptions(presetName);
  setNotice('표지 프리셋을 저장했습니다.' + (droppedLogo ? ' 큰 로고 파일은 프리셋에 포함되지 않았습니다.' : ''), 'success');
}

function loadSelectedReportPreset() {
  const presetName = String(elements.reportPresetSelect?.value || elements.reportPresetName?.value || '').trim();
  if (!presetName) {
    setNotice('불러올 프리셋을 선택하세요.', 'error');
    return;
  }
  const snapshot = state.reportPresets[presetName];
  if (!snapshot) {
    setNotice('선택한 프리셋을 찾지 못했습니다.', 'error');
    return;
  }
  if (elements.reportPresetName) elements.reportPresetName.value = presetName;
  if (elements.reportPresetSelect) elements.reportPresetSelect.value = presetName;
  applyReportCoverSnapshot(snapshot);
  setNotice('표지 프리셋을 불러왔습니다.', 'success');
}

function deleteSelectedReportPreset() {
  const presetName = String(elements.reportPresetSelect?.value || elements.reportPresetName?.value || '').trim();
  if (!presetName || !state.reportPresets[presetName]) {
    setNotice('삭제할 프리셋을 선택하세요.', 'error');
    return;
  }
  if (!window.confirm('프리셋 "' + presetName + '"을 삭제할까요?')) return;
  delete state.reportPresets[presetName];
  saveReportPresets();
  renderReportPresetOptions('');
  if (elements.reportPresetName && elements.reportPresetName.value.trim() === presetName) elements.reportPresetName.value = '';
  setNotice('표지 프리셋을 삭제했습니다.', 'success');
}

function renderReportPreview() {
  if (!elements.reportPreviewCard) return;
  readReportCoverInputs();
  const site = elements.siteFilter?.value.trim() || 'site 미설정';
  const building = elements.reportBuilding?.value.trim() || '전체 동';
  const reportType = REPORT_TYPE_LABELS[elements.reportType?.value || 'all'] || '전체';
  const companyName = state.reportCover.companyName || '회사명 미입력';
  const contractorName = state.reportCover.contractorName || '공사업체 미입력';
  const submissionPhrase = state.reportCover.submissionPhrase || '제출 문구 미입력';
  const adminSource = state.reportAdminDefault?.source_scope || 'none';
  const adminSourceLabel = adminSource === 'site' ? 'site 기본값' : (adminSource === 'global' ? 'global 기본값' : '미확인');
  const logoHtml = state.reportCover.logoDataUrl
    ? '<img src="' + escapeHtml(state.reportCover.logoDataUrl) + '" alt="표지 로고 미리보기" style="max-width:120px;max-height:52px;object-fit:contain;border-radius:8px;background:#fff;padding:6px;border:1px solid rgba(15,23,42,0.08);" />'
    : '<div style="min-width:120px;min-height:52px;display:flex;align-items:center;justify-content:center;border-radius:8px;background:#f3f6fb;border:1px dashed rgba(15,23,42,0.12);font-weight:700;color:#1f4e78;">LOGO</div>';
  elements.reportPreviewCard.innerHTML = '' +
    '<div style="display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap;">' +
      '<div style="flex:1 1 320px;">' +
        '<div class="meta" style="font-weight:700;color:#1f4e78;">관리사무소 제출용 표지 미리보기</div>' +
        '<h3 style="margin:8px 0 6px;">' + escapeHtml(site) + ' 세대 민원 처리 현황 보고</h3>' +
        '<div class="meta">단지명 ' + escapeHtml(site) + ' · 공사명 ' + escapeHtml(contractorName) + ' · 보고일 ' + escapeHtml(new Date().toLocaleDateString('ko-KR')) + '</div>' +
        '<div class="meta">출력 구분 ' + escapeHtml(reportType) + ' · 범위 ' + escapeHtml(building) + ' · 관리자 기본값 ' + escapeHtml(adminSourceLabel) + '</div>' +
      '</div>' +
      '<div style="flex:0 0 140px;display:flex;justify-content:flex-end;">' + logoHtml + '</div>' +
    '</div>' +
    '<div style="margin-top:14px;padding:14px;border:1px solid rgba(15,23,42,0.08);border-radius:14px;background:#f8fbff;">' +
      '<div style="font-size:18px;font-weight:800;color:#0f172a;">' + escapeHtml(companyName) + '</div>' +
      '<div class="meta" style="margin-top:6px;">공사업체 ' + escapeHtml(contractorName) + '</div>' +
      '<div style="margin-top:10px;line-height:1.6;color:#334155;">' + escapeHtml(submissionPhrase) + '</div>' +
    '</div>';
}

function selectedReportAdminScope() {
  return elements.reportAdminScope?.value === 'global' ? 'global' : 'site';
}

function describeReportAdminDefault(model, requestedScope) {
  if (!elements.reportAdminStatus) return;
  if (!model || model.source_scope === 'none') {
    elements.reportAdminStatus.value = requestedScope === 'global' ? 'global 기본값 없음' : 'site 기본값 없음';
    return;
  }
  const updatedAt = model.updated_at ? formatDateTime(model.updated_at) : '시간 미기록';
  const scopeLabel = model.source_scope === 'site' ? ((model.site || 'site') + ' 기본값') : 'global 기본값';
  const requestedLabel = requestedScope === 'global' ? 'global 조회' : 'site 조회';
  const logoLabel = model.logo_present ? '로고 포함' : '로고 없음';
  elements.reportAdminStatus.value = requestedLabel + ' · ' + scopeLabel + ' · ' + logoLabel + ' · ' + updatedAt;
}

async function loadAdminReportDefault(options) {
  const opts = options || {};
  const scope = opts.scope || selectedReportAdminScope();
  if (scope === 'site' && !nullIfBlank(elements.siteFilter?.value)) {
    state.reportAdminDefault = null;
    if (elements.reportAdminStatus) elements.reportAdminStatus.value = 'site 입력 후 관리자 기본값을 확인하세요';
    renderReportPreview();
    return null;
  }
  try {
    const session = ensureSession(scope !== 'global');
    const params = new URLSearchParams();
    if (scope === 'site' && session.site) params.set('site', session.site);
    const model = await request('/api/complaints/report-cover/default' + (params.toString() ? '?' + params.toString() : ''));
    state.reportAdminDefault = model;
    describeReportAdminDefault(model, scope);
    renderReportPreview();
    if (opts.applyToForm && model && model.source_scope !== 'none') applyReportCoverSnapshot(model);
    if (!opts.silent) {
      setNotice(model && model.source_scope !== 'none' ? '관리자 공통 기본값을 불러왔습니다.' : '저장된 관리자 기본값이 없습니다.', model && model.source_scope !== 'none' ? 'success' : undefined);
    }
    return model;
  } catch (error) {
    state.reportAdminDefault = null;
    describeReportAdminDefault(null, scope);
    renderReportPreview();
    if (!opts.silent) {
      setNotice(error.message || '관리자 기본값을 불러오지 못했습니다.', 'error');
      writeDebug('load-admin-report-default-error', error);
    }
    return null;
  }
}

async function saveAdminReportDefault() {
  try {
    const scope = selectedReportAdminScope();
    const session = ensureSession(scope !== 'global');
    const cover = buildReportCoverPayload();
    const result = await request('/api/complaints/report-cover/default', {
      method: 'PUT',
      json: {
        scope_type: scope,
        site: scope === 'site' ? session.site : null,
        company_name: cover.company_name,
        contractor_name: cover.contractor_name,
        submission_phrase: cover.submission_phrase,
        logo_data_url: cover.logo_data_url,
        logo_file_name: cover.logo_file_name,
        clear_logo: !cover.logo_data_url,
      },
    });
    state.reportAdminDefault = result;
    describeReportAdminDefault(result, scope);
    renderReportPreview();
    setNotice(scope === 'global' ? 'global 기본값을 저장했습니다.' : 'site 기본값을 저장했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '관리자 기본값 저장에 실패했습니다.', 'error');
    writeDebug('save-admin-report-default-error', error);
  }
}

async function deleteAdminReportDefault() {
  const scope = selectedReportAdminScope();
  const scopeLabel = scope === 'global' ? 'global' : 'site';
  if (!window.confirm(scopeLabel + ' 기본값을 삭제할까요?')) return;
  try {
    const session = ensureSession(scope !== 'global');
    const params = new URLSearchParams({ scope_type: scope });
    if (scope === 'site' && session.site) params.set('site', session.site);
    await request('/api/complaints/report-cover/default?' + params.toString(), { method: 'DELETE' });
    await loadAdminReportDefault({ scope: scope, applyToForm: false, silent: true });
    setNotice(scopeLabel + ' 기본값을 삭제했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '관리자 기본값 삭제에 실패했습니다.', 'error');
    writeDebug('delete-admin-report-default-error', error);
  }
}

function applyReportPreset(kind, presetKey) {
  const normalizedKind = String(kind || '');
  const normalizedPresetKey = String(presetKey || '');
  if (normalizedKind === 'company') {
    const value = REPORT_COMPANY_PRESETS[normalizedPresetKey];
    if (value !== undefined && elements.reportCompanyName) elements.reportCompanyName.value = value;
  }
  if (normalizedKind === 'contractor') {
    const value = REPORT_CONTRACTOR_PRESETS[normalizedPresetKey];
    if (value !== undefined && elements.reportContractorName) elements.reportContractorName.value = value;
  }
  if (normalizedKind === 'phrase') {
    const value = REPORT_SUBMISSION_PRESETS[normalizedPresetKey];
    if (value !== undefined && elements.reportSubmissionPhrase) elements.reportSubmissionPhrase.value = value;
  }
  saveReportCoverPrefs();
}

function applyDefaultReportCover() {
  if (elements.reportCompanyPreset) elements.reportCompanyPreset.value = 'default';
  if (elements.reportContractorPreset) elements.reportContractorPreset.value = 'default';
  if (elements.reportPhrasePreset) elements.reportPhrasePreset.value = 'default';
  if (elements.reportCompanyName) elements.reportCompanyName.value = REPORT_COMPANY_PRESETS.default;
  if (elements.reportContractorName) elements.reportContractorName.value = REPORT_CONTRACTOR_PRESETS.default;
  if (elements.reportSubmissionPhrase) elements.reportSubmissionPhrase.value = REPORT_SUBMISSION_PRESETS.default;
  saveReportCoverPrefs();
  setNotice('출력 표지 기본값을 채웠습니다.', 'success');
}

function clearReportLogo() {
  state.reportCover.logoDataUrl = '';
  state.reportCover.logoFileName = '';
  state.reportCover.logoPersisted = false;
  if (elements.reportLogoFile) elements.reportLogoFile.value = '';
  saveReportCoverPrefs();
  setNotice('표지 로고 이미지를 지웠습니다.', 'success');
}

async function loadReportLogoFile(file) {
  if (!(file instanceof File)) return;
  if (!/^image\\/(png|jpeg)$/.test(String(file.type || ''))) {
    setNotice('로고 이미지는 PNG 또는 JPEG만 불러올 수 있습니다.', 'error');
    if (elements.reportLogoFile) elements.reportLogoFile.value = '';
    return;
  }
  const dataUrl = await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ''));
    reader.onerror = () => reject(reader.error || new Error('파일 읽기 실패'));
    reader.readAsDataURL(file);
  });
  state.reportCover.logoDataUrl = dataUrl;
  state.reportCover.logoFileName = file.name || 'logo-image';
  state.reportCover.logoPersisted = dataUrl.length <= 350000;
  saveReportCoverPrefs();
  setNotice('표지 로고 이미지를 불러왔습니다.', 'success');
}

function buildReportCoverPayload() {
  readReportCoverInputs();
  return {
    company_name: state.reportCover.companyName || null,
    contractor_name: state.reportCover.contractorName || null,
    submission_phrase: state.reportCover.submissionPhrase || null,
    logo_data_url: state.reportCover.logoDataUrl || null,
    logo_file_name: state.reportCover.logoFileName || null,
  };
}

function updateReportCoverDraft() {
  readReportCoverInputs();
  renderReportPreview();
}

function setTokenVisibility(visible) {
  elements.token.type = visible ? 'text' : 'password';
  if (elements.toggleTokenVisibilityBtn) {
    elements.toggleTokenVisibilityBtn.textContent = visible ? '토큰 숨기기' : '토큰 보기';
  }
  if (tokenHideTimer) {
    clearTimeout(tokenHideTimer);
    tokenHideTimer = null;
  }
  if (visible) {
    tokenHideTimer = setTimeout(() => setTokenVisibility(false), 8000);
  }
}

function clearPrefs() {
  try {
    clearStoredAuthArtifacts();
    localStorage.removeItem(STORAGE_KEYS.site);
  } catch (error) {
    writeDebug('localStorage-clear-error', error);
  }
  elements.siteFilter.value = '';
  elements.createSite.value = '';
  setTokenVisibility(false);
  updateSessionStatus('저장된 토큰과 site를 지웠습니다.');
  state.queue = [];
  state.filteredQueue = [];
  state.selectedId = null;
  state.detail = null;
  state.householdHistory = null;
  state.reportAdminDefault = null;
  if (elements.reportAdminStatus) elements.reportAdminStatus.value = '관리자 기본값 미확인';
  state.dbEditor = { recordType: elements.dbRecordType.value || 'cases', columns: [], rows: [], totalCount: 0, dirtyRows: {}, selectedIds: {}, originalRows: {}, hiddenColumnsByType: state.dbEditor.hiddenColumnsByType || {} };
  renderStats();
  renderQueue();
  syncDbSiteMirror();
  renderDbEditorTable();
  renderReportPreview();
  clearDetail('토큰과 site 저장값을 지웠습니다. 다시 입력하면 현장 큐를 불러올 수 있습니다.');
  setNotice('저장된 세션 정보를 초기화했습니다.', 'success');
}

function ensureSession(requireSite) {
  const token = elements.token.value.trim();
  const site = elements.siteFilter.value.trim();
  if (!token) throw new Error('X-Admin-Token을 입력하세요.');
  if (requireSite !== false && !site) throw new Error('site를 입력하세요.');
  return { token, site };
}

async function probeAuthProfile(options) {
  const silent = Boolean(options && options.silent);
  try {
    ensureSession(false);
    const me = await request('/api/auth/me');
    persistAuthProfile(me);
    savePrefs();
    updateSessionStatus('연결 확인됨 · ' + maskToken(elements.token.value) + ' · ' + String(me.username || me.display_name || 'admin') + ' / ' + String(me.role || '-') + ' · site: ' + (elements.siteFilter.value.trim() || '미설정'));
    if (!silent) setNotice('토큰 연결을 확인했습니다.', 'success');
    return me;
  } catch (error) {
    persistAuthProfile(null);
    if (!silent) {
      setNotice(error.message || '토큰 연결 확인에 실패했습니다.', 'error');
    } else {
      updateSessionStatus('저장된 토큰: ' + maskToken(elements.token.value) + ' · 권한 확인 필요');
    }
    writeDebug('auth-profile-probe-error', error);
    throw error;
  } finally {
    setTokenVisibility(false);
  }
}

async function checkConnection() {
  setNotice('토큰 연결을 확인하는 중입니다.');
  try {
    await probeAuthProfile();
  } catch (error) {
    writeDebug('check-connection-error', error);
  }
}

async function request(path, options) {
  const init = Object.assign({ method: 'GET' }, options || {});
  const headers = new Headers(init.headers || {});
  const token = elements.token.value.trim();
  if (token) headers.set('X-Admin-Token', token);
  headers.set('Accept', init.accept || 'application/json');
  if (init.json !== undefined) {
    headers.set('Content-Type', 'application/json');
    init.body = JSON.stringify(init.json);
  }
  delete init.json;
  delete init.accept;
  init.headers = headers;
  const response = await fetch(path, init);
  if (!response.ok) {
    const contentType = response.headers.get('content-type') || '';
    let detail = response.status + ' error';
    if (contentType.includes('application/json')) detail = formatApiError(await response.json());
    else detail = (await response.text()).trim() || detail;
    if (response.status === 401) {
      clearStoredAuthArtifacts({ preserveInput: true });
      updateSessionStatus('저장된 토큰: ' + maskToken(elements.token.value) + ' · 인증 만료 또는 무효 토큰');
      setTokenVisibility(false);
    } else if (response.status === 403) {
      updateSessionStatus('저장된 토큰: ' + maskToken(elements.token.value) + ' · 권한 또는 site 범위 확인 필요');
    }
    throw new Error(response.status + ' ' + detail);
  }
  if (init.responseType === 'blob') return response.blob();
  if (response.status === 204) return null;
  const contentType = response.headers.get('content-type') || '';
  return contentType.includes('application/json') ? response.json() : response.text();
}

async function downloadComplaintReport(format) {
  try {
    const session = ensureSession(true);
    savePrefs();
    const params = new URLSearchParams({ site: session.site, report_type: elements.reportType.value || 'all' });
    const building = nullIfBlank(elements.reportBuilding.value);
    if (building) params.set('building', building);
    setNotice((format === 'xlsx' ? '엑셀' : 'PDF') + ' 출력 파일을 준비하는 중입니다.');
    let response;
    if (format === 'pdf') {
      saveReportCoverPrefs();
      response = await fetch('/api/complaints/reports/pdf', {
        method: 'POST',
        headers: {
          'X-Admin-Token': elements.token.value.trim(),
          'Accept': 'application/pdf',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          site: session.site,
          report_type: elements.reportType.value || 'all',
          building: building,
          cover: buildReportCoverPayload(),
        }),
      });
    } else {
      response = await fetch('/api/complaints/reports/' + format + '?' + params.toString(), {
        headers: { 'X-Admin-Token': elements.token.value.trim(), 'Accept': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
      });
    }
    if (!response.ok) {
      const contentType = response.headers.get('content-type') || '';
      const detail = contentType.includes('application/json') ? formatApiError(await response.json()) : ((await response.text()).trim() || (response.status + ' error'));
      throw new Error(detail);
    }
    const blob = await response.blob();
    const fileName = parseContentDispositionFilename(response.headers.get('Content-Disposition')) || ('complaints-report.' + format);
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setNotice((format === 'xlsx' ? '엑셀' : 'PDF') + ' 파일을 내려받았습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '출력 파일 다운로드에 실패했습니다.', 'error');
    writeDebug('download-report-error', error);
  } finally {
    setTokenVisibility(false);
  }
}

function syncDbSiteMirror() {
  if (!elements.dbSiteMirror) return;
  elements.dbSiteMirror.value = elements.siteFilter.value.trim();
}

function getHiddenDbColumnMap(recordType) {
  const prefs = state.dbEditor.hiddenColumnsByType || {};
  const hiddenMap = prefs[recordType || state.dbEditor.recordType || 'cases'];
  return hiddenMap && typeof hiddenMap === 'object' ? hiddenMap : {};
}

function getVisibleDbColumns() {
  const hiddenMap = getHiddenDbColumnMap(state.dbEditor.recordType);
  return (state.dbEditor.columns || []).filter((column) => !hiddenMap[column.key]);
}

function renderDbColumnToggles() {
  if (!elements.dbColumnToggleWrap || !elements.dbColumnSummary) return;
  const columns = state.dbEditor.columns || [];
  if (!columns.length) {
    elements.dbColumnSummary.textContent = '레코드를 불러오면 표시할 칼럼을 선택할 수 있습니다.';
    elements.dbColumnToggleWrap.innerHTML = '<div class="empty">레코드를 불러오면 칼럼 토글이 나타납니다.</div>';
    return;
  }
  const hiddenMap = getHiddenDbColumnMap(state.dbEditor.recordType);
  const visibleCount = columns.filter((column) => !hiddenMap[column.key]).length;
  elements.dbColumnSummary.textContent = '표시 ' + visibleCount + ' / ' + columns.length + ' · 칩을 눌러 칼럼을 숨기거나 다시 표시합니다.';
  elements.dbColumnToggleWrap.innerHTML = columns.map((column) => {
    const visible = !hiddenMap[column.key];
    return '<button class="chip db-column-chip' + (visible ? ' active' : ' inactive') + '" type="button" data-db-column-key="' + escapeHtml(column.key) + '">' + escapeHtml(column.label) + ' · ' + (visible ? '표시' : '숨김') + '</button>';
  }).join('');
  elements.dbColumnToggleWrap.querySelectorAll('[data-db-column-key]').forEach((node) => {
    node.addEventListener('click', () => toggleDbColumnVisibility(node.getAttribute('data-db-column-key') || ''));
  });
}

function toggleDbColumnVisibility(columnKey) {
  const normalizedKey = String(columnKey || '').trim();
  if (!normalizedKey) return;
  const columns = state.dbEditor.columns || [];
  const hiddenMap = getHiddenDbColumnMap(state.dbEditor.recordType);
  const isVisible = !hiddenMap[normalizedKey];
  const visibleCount = columns.filter((column) => !hiddenMap[column.key]).length;
  if (isVisible && visibleCount <= 1) {
    setNotice('최소 1개 칼럼은 표시 상태여야 합니다.', 'error');
    return;
  }
  if (!state.dbEditor.hiddenColumnsByType[state.dbEditor.recordType]) state.dbEditor.hiddenColumnsByType[state.dbEditor.recordType] = {};
  if (isVisible) state.dbEditor.hiddenColumnsByType[state.dbEditor.recordType][normalizedKey] = true;
  else delete state.dbEditor.hiddenColumnsByType[state.dbEditor.recordType][normalizedKey];
  if (!Object.keys(state.dbEditor.hiddenColumnsByType[state.dbEditor.recordType]).length) delete state.dbEditor.hiddenColumnsByType[state.dbEditor.recordType];
  saveDbColumnPrefs();
  renderDbColumnToggles();
  renderDbEditorTable();
}

function showAllDbColumns() {
  if (state.dbEditor.hiddenColumnsByType[state.dbEditor.recordType]) delete state.dbEditor.hiddenColumnsByType[state.dbEditor.recordType];
  saveDbColumnPrefs();
  renderDbColumnToggles();
  renderDbEditorTable();
  setNotice('현재 레코드 종류의 모든 칼럼을 다시 표시했습니다.', 'success');
}

function resetDbColumnVisibility() {
  if (state.dbEditor.hiddenColumnsByType[state.dbEditor.recordType]) delete state.dbEditor.hiddenColumnsByType[state.dbEditor.recordType];
  saveDbColumnPrefs();
  renderDbColumnToggles();
  renderDbEditorTable();
  setNotice('현재 레코드 종류의 칼럼 표시를 기본값으로 되돌렸습니다.', 'success');
}

function updateDbSummary(message) {
  if (!elements.dbSummary) return;
  if (message) {
    elements.dbSummary.textContent = message;
    return;
  }
  const dirtyCount = Object.keys(state.dbEditor.dirtyRows || {}).length;
  const selectedCount = Object.keys(state.dbEditor.selectedIds || {}).length;
  const visibleCount = getVisibleDbColumns().length;
  const totalColumns = (state.dbEditor.columns || []).length;
  elements.dbSummary.textContent = '총 ' + state.dbEditor.totalCount + '행 · 변경 ' + dirtyCount + '행 · 선택 ' + selectedCount + '행 · 칼럼 ' + visibleCount + '/' + totalColumns + ' 표시';
}

function switchTab(nextTab) {
  state.activeTab = nextTab === 'db' ? 'db' : 'field';
  elements.fieldWorkspace.classList.toggle('hidden', state.activeTab !== 'field');
  elements.dbWorkspace.classList.toggle('hidden', state.activeTab !== 'db');
  elements.fieldTabBtn.classList.toggle('active', state.activeTab === 'field');
  elements.dbTabBtn.classList.toggle('active', state.activeTab === 'db');
  syncDbSiteMirror();
  if (state.activeTab === 'db' && !state.dbEditor.rows.length && elements.siteFilter.value.trim()) {
    loadDbRecords();
  }
}

function dbColumnByKey(key) {
  return (state.dbEditor.columns || []).find((column) => column.key === key) || null;
}

function buildDbCellValue(column, value) {
  if (column.input_type === 'checkbox') {
    return '<input class="table-checkbox db-cell-input" type="checkbox" data-record-id="' + column.__recordId + '" data-field="' + escapeHtml(column.key) + '"' + (value ? ' checked' : '') + ' />';
  }
  if (column.input_type === 'select') {
    const options = Array.isArray(column.options) ? column.options : [];
    return '<select class="table-select db-cell-input" data-record-id="' + column.__recordId + '" data-field="' + escapeHtml(column.key) + '">' +
      options.map((option) => '<option value="' + escapeHtml(option.value) + '"' + (String(option.value ?? '') === String(value ?? '') ? ' selected' : '') + '>' + escapeHtml(option.label) + '</option>').join('') +
      '<option value=""' + (value == null || value === '' ? ' selected' : '') + '>비움</option>' +
    '</select>';
  }
  if (column.input_type === 'textarea') {
    return '<textarea class="table-textarea db-cell-input" data-record-id="' + column.__recordId + '" data-field="' + escapeHtml(column.key) + '">' + escapeHtml(value ?? '') + '</textarea>';
  }
  const inputType = column.input_type === 'number' ? 'number' : 'text';
  const step = column.input_type === 'number' ? ' step="0.1"' : '';
  return '<input class="table-input db-cell-input" type="' + inputType + '"' + step + ' data-record-id="' + column.__recordId + '" data-field="' + escapeHtml(column.key) + '" value="' + escapeHtml(value ?? '') + '" />';
}

function renderDbEditorTable() {
  renderDbColumnToggles();
  if (!state.dbEditor.rows.length) {
    elements.dbTableWrap.innerHTML = '<div class="empty">조건에 맞는 DB 레코드가 없습니다.</div>';
    updateDbSummary();
    return;
  }
  const columns = getVisibleDbColumns();
  if (!columns.length) {
    elements.dbTableWrap.innerHTML = '<div class="empty">표시 중인 칼럼이 없습니다. 위의 칼럼 숨김/표시에서 다시 선택하세요.</div>';
    updateDbSummary();
    return;
  }
  const headerHtml = '<tr><th style="width:44px;"><input id="dbSelectAllRows" class="table-checkbox" type="checkbox" /></th>' + columns.map((column) => '<th>' + escapeHtml(column.label) + '</th>').join('') + '</tr>';
  const bodyHtml = state.dbEditor.rows.map((row) => {
    const recordId = Number(row.id);
    const isDirty = Boolean(state.dbEditor.dirtyRows[recordId]);
    const isSelected = Boolean(state.dbEditor.selectedIds[recordId]);
    const cellHtml = columns.map((column) => {
      const value = row[column.key];
      if (!column.editable) return '<td><div class="table-readonly">' + escapeHtml(value ?? '') + '</div></td>';
      const inputColumn = Object.assign({}, column, { __recordId: recordId });
      return '<td>' + buildDbCellValue(inputColumn, value) + '</td>';
    }).join('');
    return '<tr class="' + (isDirty ? 'row-dirty' : '') + '" data-record-id="' + recordId + '"><td><input class="table-checkbox db-select-row" type="checkbox" data-record-id="' + recordId + '"' + (isSelected ? ' checked' : '') + ' /></td>' + cellHtml + '</tr>';
  }).join('');
  elements.dbTableWrap.innerHTML = '<table class="data-table"><thead>' + headerHtml + '</thead><tbody>' + bodyHtml + '</tbody></table>';
  document.getElementById('dbSelectAllRows')?.addEventListener('change', (event) => {
    const checked = Boolean(event.target.checked);
    state.dbEditor.selectedIds = {};
    state.dbEditor.rows.forEach((row) => {
      if (checked) state.dbEditor.selectedIds[Number(row.id)] = true;
    });
    renderDbEditorTable();
  });
  elements.dbTableWrap.querySelectorAll('.db-select-row').forEach((node) => {
    node.addEventListener('change', () => {
      const recordId = Number(node.getAttribute('data-record-id'));
      if (!Number.isFinite(recordId)) return;
      if (node.checked) state.dbEditor.selectedIds[recordId] = true;
      else delete state.dbEditor.selectedIds[recordId];
      updateDbSummary();
    });
  });
  elements.dbTableWrap.querySelectorAll('.db-cell-input').forEach((node) => {
    const eventName = node.tagName === 'SELECT' || node.type === 'checkbox' ? 'change' : 'input';
    node.addEventListener(eventName, () => {
      const recordId = Number(node.getAttribute('data-record-id'));
      const field = node.getAttribute('data-field') || '';
      const column = dbColumnByKey(field);
      if (!Number.isFinite(recordId) || !column) return;
      const originalRow = state.dbEditor.originalRows[recordId] || {};
      const nextValue = column.input_type === 'checkbox' ? Boolean(node.checked) : node.value;
      const originalComparable = column.input_type === 'checkbox' ? Boolean(originalRow[field]) : String(originalRow[field] ?? '');
      const nextComparable = column.input_type === 'checkbox' ? Boolean(nextValue) : String(nextValue ?? '');
      if (originalComparable === nextComparable) {
        if (state.dbEditor.dirtyRows[recordId]) {
          delete state.dbEditor.dirtyRows[recordId][field];
          if (!Object.keys(state.dbEditor.dirtyRows[recordId]).length) delete state.dbEditor.dirtyRows[recordId];
        }
      } else {
        if (!state.dbEditor.dirtyRows[recordId]) state.dbEditor.dirtyRows[recordId] = {};
        state.dbEditor.dirtyRows[recordId][field] = nextValue;
      }
      node.closest('tr')?.classList.toggle('row-dirty', Boolean(state.dbEditor.dirtyRows[recordId]));
      updateDbSummary();
    });
  });
  updateDbSummary();
}

async function loadDbRecords() {
  try {
    const session = ensureSession(true);
    syncDbSiteMirror();
    const params = new URLSearchParams({
      site: session.site,
      record_type: elements.dbRecordType.value || 'cases',
      limit: String(numberValue(elements.dbLimit.value) || 200),
    });
    const search = nullIfBlank(elements.dbSearch.value);
    if (search) params.set('q', search);
    setNotice('DB 레코드를 불러오는 중입니다.');
    const payload = await request('/api/complaints/admin/records?' + params.toString());
    state.dbEditor.recordType = payload.record_type;
    state.dbEditor.columns = Array.isArray(payload.columns) ? payload.columns : [];
    state.dbEditor.rows = Array.isArray(payload.rows) ? payload.rows : [];
    state.dbEditor.totalCount = Number(payload.total_count || state.dbEditor.rows.length);
    state.dbEditor.dirtyRows = {};
    state.dbEditor.selectedIds = {};
    state.dbEditor.originalRows = {};
    state.dbEditor.rows.forEach((row) => { state.dbEditor.originalRows[Number(row.id)] = Object.assign({}, row); });
    elements.dbMeta.textContent = session.site + ' · ' + (payload.record_label || payload.record_type) + ' · ' + state.dbEditor.totalCount + '행';
    renderDbColumnToggles();
    renderDbEditorTable();
    setNotice('DB 레코드를 불러왔습니다.', 'success');
  } catch (error) {
    state.dbEditor.columns = [];
    state.dbEditor.rows = [];
    state.dbEditor.totalCount = 0;
    state.dbEditor.dirtyRows = {};
    state.dbEditor.selectedIds = {};
    state.dbEditor.originalRows = {};
    renderDbColumnToggles();
    renderDbEditorTable();
    setNotice(error.message || 'DB 레코드 불러오기에 실패했습니다.', 'error');
    writeDebug('load-db-records-error', error);
  }
}

async function applyDbChanges() {
  const dirtyRows = Object.entries(state.dbEditor.dirtyRows || {}).map(([recordId, changes]) => ({ record_id: Number(recordId), changes: changes }));
  if (!dirtyRows.length) {
    setNotice('적용할 변경 행이 없습니다.', 'error');
    return;
  }
  try {
    const session = ensureSession(true);
    setNotice('DB 변경을 일괄 적용하는 중입니다.');
    const result = await request('/api/complaints/admin/records/bulk-update', {
      method: 'POST',
      json: { site: session.site, record_type: state.dbEditor.recordType, rows: dirtyRows },
    });
    writeDebug('db-bulk-update', result);
    await loadDbRecords();
    setNotice('변경 ' + (result.updated_count || 0) + '행을 적용했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || 'DB 변경 적용에 실패했습니다.', 'error');
    writeDebug('apply-db-changes-error', error);
  }
}

async function deleteSelectedDbRows() {
  const recordIds = Object.keys(state.dbEditor.selectedIds || {}).map((value) => Number(value)).filter((value) => Number.isFinite(value));
  if (!recordIds.length) {
    setNotice('삭제할 행을 먼저 선택하세요.', 'error');
    return;
  }
  if (!window.confirm('선택한 ' + recordIds.length + '개 레코드를 삭제할까요?')) return;
  try {
    const session = ensureSession(true);
    setNotice('선택 레코드를 삭제하는 중입니다.');
    const result = await request('/api/complaints/admin/records/bulk-delete', {
      method: 'POST',
      json: { site: session.site, record_type: state.dbEditor.recordType, record_ids: recordIds },
    });
    writeDebug('db-bulk-delete', result);
    await loadDbRecords();
    setNotice('선택한 레코드 ' + (result.deleted_count || 0) + '행을 삭제했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '선택 레코드 삭제에 실패했습니다.', 'error');
    writeDebug('delete-db-rows-error', error);
  }
}

function clearDbSelectionAndChanges() {
  state.dbEditor.dirtyRows = {};
  state.dbEditor.selectedIds = {};
  state.dbEditor.rows = Object.values(state.dbEditor.originalRows || {}).map((row) => Object.assign({}, row));
  renderDbEditorTable();
  setNotice('DB 관리 탭의 선택과 미적용 변경을 지웠습니다.', 'success');
}

function sortQueue(rows) {
  return rows.slice().sort((left, right) => {
    if (Boolean(left.recurrence_flag) !== Boolean(right.recurrence_flag)) return left.recurrence_flag ? -1 : 1;
    const leftPriority = PRIORITY_ORDER[left.priority] ?? 9;
    const rightPriority = PRIORITY_ORDER[right.priority] ?? 9;
    if (leftPriority !== rightPriority) return leftPriority - rightPriority;
    const leftReported = new Date(left.reported_at || 0).getTime();
    const rightReported = new Date(right.reported_at || 0).getTime();
    if (leftReported !== rightReported) return rightReported - leftReported;
    return right.id - left.id;
  });
}

function applyQueueFilters(rows) {
  const search = elements.searchFilter.value.trim().toLowerCase();
  const status = elements.statusFilter.value.trim();
  return rows.filter((item) => {
    if (status && item.status !== status) return false;
    if (state.recurrenceOnly && !item.recurrence_flag) return false;
    if (search && !summarizeSearch(item).includes(search)) return false;
    return true;
  });
}

function renderStats() {
  elements.statTotal.textContent = String(state.queue.length);
  elements.statReceived.textContent = String(state.queue.filter((item) => item.status === 'received').length);
  elements.statActive.textContent = String(state.queue.filter((item) => ACTIVE_STATUSES.has(item.status)).length);
  elements.statDone.textContent = String(state.queue.filter((item) => DONE_STATUSES.has(item.status)).length);
}

function renderQueue() {
  state.filteredQueue = applyQueueFilters(state.queue);
  const site = elements.siteFilter.value.trim();
  const filters = [];
  if (elements.statusFilter.value) filters.push(STATUS_LABELS[elements.statusFilter.value] || elements.statusFilter.value);
  if (state.recurrenceOnly) filters.push('재민원만');
  if (elements.searchFilter.value.trim()) filters.push('검색 적용');
  elements.queueMeta.textContent = site ? site + ' · ' + (filters.join(' · ') || '전체 큐') : 'site 미설정';
  elements.queueCountLabel.textContent = state.filteredQueue.length + '건';
  elements.recurrenceToggle.textContent = '재민원만 보기: ' + (state.recurrenceOnly ? 'ON' : 'OFF');
  if (!state.filteredQueue.length) {
    elements.queueList.innerHTML = '<div class="empty">조건에 맞는 민원이 없습니다.</div>';
    return;
  }
  elements.queueList.innerHTML = state.filteredQueue.map((item) => {
    return '' +
      '<article class="queue-item' + (item.id === state.selectedId ? ' active' : '') + '" data-complaint-id="' + item.id + '">' +
        '<div class="queue-top"><strong>' + escapeHtml(item.building) + ' ' + escapeHtml(item.unit_number) + '</strong></div>' +
        '<div class="badge-row">' +
          '<span class="badge status-' + statusCssClass(item.status) + '">' + escapeHtml(item.status_label) + '</span>' +
          '<span class="badge type">' + escapeHtml(item.complaint_type_label) + '</span>' +
          '<span class="badge priority-' + escapeHtml(item.priority) + '">' + escapeHtml(item.priority_label) + '</span>' +
          (item.recurrence_flag ? '<span class="badge status-reopened">재민원</span>' : '') +
        '</div>' +
        '<div class="queue-copy">' + escapeHtml(item.description) + '</div>' +
        '<div class="queue-meta"><span>' + escapeHtml(item.assignee || '미배정') + '</span><span>' + escapeHtml(formatDateTime(item.reported_at)) + '</span></div>' +
      '</article>';
  }).join('');
  elements.queueList.querySelectorAll('[data-complaint-id]').forEach((node) => {
    node.addEventListener('click', () => {
      const complaintId = Number(node.getAttribute('data-complaint-id'));
      if (Number.isFinite(complaintId)) loadDetail(complaintId);
    });
  });
}

function renderHistoryHtml() {
  if (state.detail === null) return '<div class="empty">세대 이력을 보려면 민원을 선택하세요.</div>';
  if (state.householdHistory === null) return '<div class="empty">세대 이력을 불러오는 중입니다.</div>';
  if (!state.householdHistory.complaints.length) return '<div class="empty">세대 이력이 없습니다.</div>';
  return '<div class="timeline-list">' + state.householdHistory.complaints.map((item) => {
    return '' +
      '<div class="timeline-item">' +
        '<strong>' + escapeHtml(item.building) + ' ' + escapeHtml(item.unit_number) + ' · ' + escapeHtml(item.complaint_type_label) + '</strong>' +
        '<div class="badge-row" style="margin-top:6px;">' +
          '<span class="badge status-' + statusCssClass(item.status) + '">' + escapeHtml(item.status_label) + '</span>' +
          (state.detail && item.id === state.detail.case.id ? '<span class="badge type">현재 건</span>' : '') +
        '</div>' +
        '<div class="meta">' + escapeHtml(formatDateTime(item.reported_at)) + ' · ' + escapeHtml(item.description) + '</div>' +
      '</div>';
  }).join('') + '</div>';
}

function renderEventTimeline(events) {
  if (!events.length) return '<div class="empty">기록된 처리 이력이 없습니다.</div>';
  return '<div class="timeline-list">' + events.map((item) => {
    const statusTrail = item.to_status ? ' · 상태 ' + (STATUS_LABELS[item.to_status] || item.to_status) : '';
    return '' +
      '<div class="timeline-item">' +
        '<strong>' + escapeHtml(item.event_type) + '</strong>' +
        '<div class="meta">' + escapeHtml(formatDateTime(item.created_at)) + ' · ' + escapeHtml(item.actor_username) + statusTrail + '</div>' +
        '<div class="meta">' + escapeHtml(item.note || '메모 없음') + '</div>' +
        '<div class="actions"><button class="ghost edit-event-btn" type="button" data-event-id="' + item.id + '">수정</button><button class="ghost delete-event-btn" type="button" data-event-id="' + item.id + '">삭제</button></div>' +
      '</div>';
  }).join('') + '</div>';
}

function renderAttachmentTimeline(attachments) {
  if (!attachments.length) return '<div class="empty">업로드된 사진이나 첨부가 없습니다.</div>';
  return '<div class="timeline-list">' + attachments.map((item) => {
    return '' +
      '<div class="timeline-item">' +
        '<strong>' + escapeHtml(item.attachment_kind_label) + ' · ' + escapeHtml(item.file_name) + '</strong>' +
        '<div class="meta">' + escapeHtml(formatDateTime(item.uploaded_at)) + ' · ' + escapeHtml(item.uploaded_by) + ' · ' + escapeHtml(String(item.file_size)) + ' bytes</div>' +
        '<div class="meta">' + escapeHtml(item.note || '메모 없음') + '</div>' +
        '<div class="actions"><button class="ghost download-attachment-btn" type="button" data-attachment-id="' + item.id + '" data-file-name="' + escapeHtml(item.file_name) + '">파일 받기</button><button class="ghost edit-attachment-btn" type="button" data-attachment-id="' + item.id + '">수정</button><button class="ghost delete-attachment-btn" type="button" data-attachment-id="' + item.id + '">삭제</button></div>' +
      '</div>';
  }).join('') + '</div>';
}

function renderMessageTimeline(messages) {
  if (!messages.length) return '<div class="empty">발송된 문자가 없습니다.</div>';
  return '<div class="timeline-list">' + messages.map((item) => {
    const suffix = (item.template_key ? ' · 템플릿 ' + item.template_key : '') + (item.error ? ' · 실패 ' + item.error : '');
    return '' +
      '<div class="timeline-item">' +
        '<strong>' + escapeHtml(item.recipient) + ' · ' + escapeHtml(item.delivery_status) + '</strong>' +
        '<div class="meta">' + escapeHtml(formatDateTime(item.created_at)) + ' · ' + escapeHtml(item.provider_name) + suffix + '</div>' +
        '<div class="meta">' + escapeHtml(item.body) + '</div>' +
        '<div class="actions"><button class="ghost edit-message-btn" type="button" data-message-id="' + item.id + '">수정</button><button class="ghost delete-message-btn" type="button" data-message-id="' + item.id + '">삭제</button></div>' +
      '</div>';
  }).join('') + '</div>';
}

function renderCostTimeline(costItems) {
  if (!costItems.length) return '<div class="empty">입력된 비용 항목이 없습니다.</div>';
  return '<div class="timeline-list">' + costItems.map((item) => {
    return '' +
      '<div class="timeline-item">' +
        '<strong>' + escapeHtml(item.item_name) + ' · ' + escapeHtml(formatCurrency(item.total_cost)) + '</strong>' +
        '<div class="meta">' + escapeHtml(item.cost_category) + ' · 수량 ' + escapeHtml(String(item.quantity)) + ' · 단가 ' + escapeHtml(formatCurrency(item.unit_price)) + '</div>' +
        '<div class="meta">' + escapeHtml(item.note || '메모 없음') + '</div>' +
        '<div class="actions"><button class="ghost edit-cost-btn" type="button" data-cost-id="' + item.id + '">수정</button><button class="ghost delete-cost-btn" type="button" data-cost-id="' + item.id + '">삭제</button></div>' +
      '</div>';
  }).join('') + '</div>';
}

function renderStatusChips(caseData) {
  return STATUS_SEQUENCE.map((status) => '<button type="button" class="chip status-' + statusCssClass(status) + (caseData.status === status ? ' active' : '') + '" data-quick-status="' + escapeHtml(status) + '">' + escapeHtml(STATUS_LABELS[status] || status) + '</button>').join('');
}

function clearDetail(message) {
  elements.detailMeta.textContent = '민원을 선택하세요.';
  elements.detailBody.innerHTML = '<div class="empty">' + escapeHtml(message || '현장 큐에서 세대를 선택하면 처리 화면이 열립니다.') + '</div>';
}

function renderDetail() {
  if (!state.detail) {
    clearDetail();
    return;
  }
  const detail = state.detail;
  const caseData = detail.case;
  elements.detailMeta.textContent = caseData.site + ' · ' + caseData.building + ' ' + caseData.unit_number + ' · #' + caseData.id;
  elements.detailBody.innerHTML = '' +
    '<div class="detail-stack">' +
      '<article class="card">' +
        '<div class="badge-row">' +
          '<span class="badge status-' + statusCssClass(caseData.status) + '">' + escapeHtml(caseData.status_label) + '</span>' +
          '<span class="badge type">' + escapeHtml(caseData.complaint_type_label) + '</span>' +
          '<span class="badge priority-' + escapeHtml(caseData.priority) + '">' + escapeHtml(caseData.priority_label) + '</span>' +
          (caseData.recurrence_flag ? '<span class="badge status-reopened">재민원</span>' : '') +
        '</div>' +
        '<h3 style="margin-top:10px;">' + escapeHtml(caseData.title) + '</h3>' +
        '<p class="card-copy">' + escapeHtml(caseData.description) + '</p>' +
        '<div class="chip-row" style="margin-top:12px;">' + renderStatusChips(caseData) + '</div>' +
        '<div class="summary-grid">' +
          '<div class="key-box"><span>세대</span><strong>' + escapeHtml(caseData.building + ' ' + caseData.unit_number) + '</strong></div>' +
          '<div class="key-box"><span>입주민</span><strong>' + escapeHtml(caseData.resident_name || '-') + '</strong></div>' +
          '<div class="key-box"><span>연락처</span><strong>' + escapeHtml(caseData.contact_phone || '-') + '</strong></div>' +
          '<div class="key-box"><span>담당자</span><strong>' + escapeHtml(caseData.assignee || '미배정') + '</strong></div>' +
          '<div class="key-box"><span>방문예정</span><strong>' + escapeHtml(formatDateTime(caseData.scheduled_visit_at)) + '</strong></div>' +
          '<div class="key-box"><span>누적 비용</span><strong>' + escapeHtml(formatCurrency(detail.total_cost)) + '</strong></div>' +
        '</div>' +
      '</article>' +
      '<div class="detail-grid">' +
        '<article class="card">' +
          '<h3>담당/상태 관리</h3>' +
          '<div class="field-stack" style="margin-top:12px;"><label class="caption" for="detailTitle">제목</label><input id="detailTitle" value="' + escapeHtml(caseData.title || '') + '" /></div>' +
          '<div class="field-stack"><label class="caption" for="detailDescription">민원내용</label><textarea id="detailDescription">' + escapeHtml(caseData.description || '') + '</textarea></div>' +
          '<div class="grid-3" style="margin-top:12px;">' +
            '<div class="field-stack"><label class="caption" for="detailAssignee">담당자</label><input id="detailAssignee" value="' + escapeHtml(caseData.assignee || '') + '" placeholder="현장반장" /></div>' +
            '<div class="field-stack"><label class="caption" for="detailStatus">상태</label><select id="detailStatus">' + buildOptions(STATUS_LABELS, caseData.status) + '</select></div>' +
            '<div class="field-stack"><label class="caption" for="detailPriority">우선순위</label><select id="detailPriority">' + buildOptions(PRIORITY_LABELS, caseData.priority) + '</select></div>' +
          '</div>' +
          '<div class="grid-3">' +
            '<div class="field-stack"><label class="caption" for="detailVisitAt">방문예정일시</label><input id="detailVisitAt" type="datetime-local" value="' + escapeHtml(toLocalDateTimeInput(caseData.scheduled_visit_at)) + '" /></div>' +
            '<div class="field-stack"><label class="caption" for="detailComplaintType">민원유형</label><select id="detailComplaintType">' + buildOptions(TYPE_LABELS, caseData.complaint_type, '자동 분류') + '</select></div>' +
            '<div class="field-stack"><label class="caption" for="detailRecurrence">재민원 여부</label><select id="detailRecurrence"><option value="false"' + (caseData.recurrence_flag ? '' : ' selected') + '>신규</option><option value="true"' + (caseData.recurrence_flag ? ' selected' : '') + '>재민원</option></select></div>' +
          '</div>' +
          '<div class="grid-2">' +
            '<div class="field-stack"><label class="caption" for="detailResidentName">입주민명</label><input id="detailResidentName" value="' + escapeHtml(caseData.resident_name || '') + '" /></div>' +
            '<div class="field-stack"><label class="caption" for="detailPhone">연락처</label><input id="detailPhone" value="' + escapeHtml(caseData.contact_phone || '') + '" /></div>' +
          '</div>' +
          '<div class="actions"><button class="run" id="saveCaseBtn" type="button">기본정보 저장</button><button class="ghost" id="deleteCaseBtn" type="button">민원 삭제</button></div>' +
          '<div class="hint-line">상태만 빨리 바꿀 때는 위의 상태 칩을 눌러도 됩니다.</div>' +
        '</article>' +
        '<article class="card">' +
          '<h3>처리 이력 추가</h3>' +
          '<div class="grid-2" style="margin-top:12px;">' +
            '<div class="field-stack"><label class="caption" for="eventType">이력 유형</label><select id="eventType"><option value="note">note</option><option value="field_visit">field_visit</option><option value="call_back">call_back</option><option value="resident_contact">resident_contact</option><option value="rework">rework</option></select></div>' +
            '<div class="field-stack"><label class="caption" for="eventToStatus">이후 상태</label><select id="eventToStatus"><option value="">상태 유지</option>' + buildOptions(STATUS_LABELS, '') + '</select></div>' +
          '</div>' +
          '<div class="field-stack"><label class="caption" for="eventNote">메모</label><textarea id="eventNote" placeholder="예: 방문 후 방충망 세척 완료, 난간 오염 일부 잔존"></textarea></div>' +
          '<div class="actions"><button class="run" id="addEventBtn" type="button">처리 이력 저장</button></div>' +
        '</article>' +
        '<article class="card">' +
          '<h3>문자 발송</h3>' +
          '<div class="grid-2" style="margin-top:12px;">' +
            '<div class="field-stack"><label class="caption" for="messageTemplate">템플릿</label><select id="messageTemplate"><option value="">직접 입력</option><option value="intake_ack">접수 확인</option><option value="visit_notice">방문 예정</option><option value="resolved_notice">처리 완료</option><option value="revisit_notice">재방문 안내</option></select></div>' +
            '<div class="field-stack"><label class="caption" for="messageRecipient">수신번호</label><input id="messageRecipient" value="' + escapeHtml(caseData.contact_phone || '') + '" placeholder="010-0000-0000" /></div>' +
          '</div>' +
          '<div class="field-stack"><label class="caption" for="messageBody">문자 내용</label><textarea id="messageBody" placeholder="문자 내용을 입력하거나 템플릿을 선택하세요."></textarea></div>' +
          '<div class="actions"><button class="ghost" id="fillTemplateBtn" type="button">템플릿 채우기</button><button class="run" id="sendMessageBtn" type="button">문자 발송</button></div>' +
        '</article>' +
        '<article class="card">' +
          '<h3>사진/첨부 업로드</h3>' +
          '<div class="grid-2" style="margin-top:12px;">' +
            '<div class="field-stack"><label class="caption" for="attachmentKind">첨부 구분</label><select id="attachmentKind">' + buildOptions(ATTACHMENT_KIND_LABELS, 'intake') + '</select></div>' +
            '<div class="field-stack"><label class="caption" for="attachmentFile">파일</label><input id="attachmentFile" type="file" accept=".jpg,.jpeg,.png,.webp,.pdf,.txt,.csv,.xls,.xlsx,.doc,.docx,image/*" /></div>' +
          '</div>' +
          '<div class="field-stack"><label class="caption" for="attachmentNote">메모</label><input id="attachmentNote" placeholder="예: 작업 후 사진 3면" /></div>' +
          '<div class="actions"><button class="run" id="uploadAttachmentBtn" type="button">첨부 업로드</button></div>' +
        '</article>' +
        '<article class="card">' +
          '<h3>비용 입력</h3>' +
          '<div class="grid-3" style="margin-top:12px;">' +
            '<div class="field-stack"><label class="caption" for="costCategory">비용 구분</label><select id="costCategory"><option value="cleaning">cleaning</option><option value="repair">repair</option><option value="replacement">replacement</option><option value="revisit">revisit</option><option value="vendor">vendor</option><option value="other">other</option></select></div>' +
            '<div class="field-stack"><label class="caption" for="costItemName">항목명</label><input id="costItemName" placeholder="예: 방충망 세척" /></div>' +
            '<div class="field-stack"><label class="caption" for="costQuantity">수량</label><input id="costQuantity" type="number" min="0" step="0.1" value="1" /></div>' +
          '</div>' +
          '<div class="grid-4">' +
            '<div class="field-stack"><label class="caption" for="costUnitPrice">단가</label><input id="costUnitPrice" type="number" min="0" step="100" value="0" /></div>' +
            '<div class="field-stack"><label class="caption" for="costMaterial">자재비</label><input id="costMaterial" type="number" min="0" step="100" value="0" /></div>' +
            '<div class="field-stack"><label class="caption" for="costLabor">인건비</label><input id="costLabor" type="number" min="0" step="100" value="0" /></div>' +
            '<div class="field-stack"><label class="caption" for="costVendor">외주비</label><input id="costVendor" type="number" min="0" step="100" value="0" /></div>' +
          '</div>' +
          '<div class="field-stack"><label class="caption" for="costNote">메모</label><input id="costNote" placeholder="예: 2차 방문 포함" /></div>' +
          '<div class="hint-line">예상 합계: <strong id="costTotalPreview">' + escapeHtml(formatCurrency(0)) + '</strong></div>' +
          '<div class="actions"><button class="run" id="addCostBtn" type="button">비용 저장</button></div>' +
        '</article>' +
        '<article class="card"><h3>세대 이력</h3>' + renderHistoryHtml() + '</article>' +
      '</div>' +
      '<div class="detail-grid">' +
        '<article class="card"><h3>처리 이력</h3>' + renderEventTimeline(detail.events) + '</article>' +
        '<article class="card"><h3>사진/첨부</h3>' + renderAttachmentTimeline(detail.attachments) + '</article>' +
        '<article class="card"><h3>문자 발송 이력</h3>' + renderMessageTimeline(detail.messages) + '</article>' +
        '<article class="card"><h3>비용 입력 이력</h3>' + renderCostTimeline(detail.cost_items) + '</article>' +
      '</div>' +
    '</div>';
  bindDetailActions();
  updateCostPreview();
}

function updateCostPreview() {
  const preview = document.getElementById('costTotalPreview');
  if (!preview) return;
  const total = numberValue(document.getElementById('costQuantity')?.value) * numberValue(document.getElementById('costUnitPrice')?.value) + numberValue(document.getElementById('costMaterial')?.value) + numberValue(document.getElementById('costLabor')?.value) + numberValue(document.getElementById('costVendor')?.value);
  preview.textContent = formatCurrency(total);
}

function applyMessageTemplate(force) {
  if (!state.detail) return;
  const templateKey = document.getElementById('messageTemplate')?.value || '';
  const builder = MESSAGE_TEMPLATE_BUILDERS[templateKey];
  const target = document.getElementById('messageBody');
  if (!builder || !target) return;
  if (!force && target.value.trim()) return;
  target.value = builder(state.detail.case);
}

function findDetailRecord(collectionName, recordId) {
  const rows = state.detail && Array.isArray(state.detail[collectionName]) ? state.detail[collectionName] : [];
  return rows.find((item) => Number(item.id) === Number(recordId)) || null;
}

function bindDetailActions() {
  elements.detailBody.querySelectorAll('[data-quick-status]').forEach((node) => {
    node.addEventListener('click', () => quickSetStatus(node.getAttribute('data-quick-status')));
  });
  elements.detailBody.querySelectorAll('.download-attachment-btn').forEach((node) => {
    node.addEventListener('click', () => {
      const attachmentId = Number(node.getAttribute('data-attachment-id'));
      const fileName = node.getAttribute('data-file-name') || ('complaint-' + attachmentId);
      if (Number.isFinite(attachmentId)) downloadAttachment(attachmentId, fileName);
    });
  });
  elements.detailBody.querySelectorAll('.edit-event-btn').forEach((node) => {
    node.addEventListener('click', () => {
      const eventId = Number(node.getAttribute('data-event-id'));
      if (Number.isFinite(eventId)) editEventRecord(eventId);
    });
  });
  elements.detailBody.querySelectorAll('.delete-event-btn').forEach((node) => {
    node.addEventListener('click', () => {
      const eventId = Number(node.getAttribute('data-event-id'));
      if (Number.isFinite(eventId)) deleteEventRecord(eventId);
    });
  });
  elements.detailBody.querySelectorAll('.edit-attachment-btn').forEach((node) => {
    node.addEventListener('click', () => {
      const attachmentId = Number(node.getAttribute('data-attachment-id'));
      if (Number.isFinite(attachmentId)) editAttachmentRecord(attachmentId);
    });
  });
  elements.detailBody.querySelectorAll('.delete-attachment-btn').forEach((node) => {
    node.addEventListener('click', () => {
      const attachmentId = Number(node.getAttribute('data-attachment-id'));
      if (Number.isFinite(attachmentId)) deleteAttachmentRecord(attachmentId);
    });
  });
  elements.detailBody.querySelectorAll('.edit-message-btn').forEach((node) => {
    node.addEventListener('click', () => {
      const messageId = Number(node.getAttribute('data-message-id'));
      if (Number.isFinite(messageId)) editMessageRecord(messageId);
    });
  });
  elements.detailBody.querySelectorAll('.delete-message-btn').forEach((node) => {
    node.addEventListener('click', () => {
      const messageId = Number(node.getAttribute('data-message-id'));
      if (Number.isFinite(messageId)) deleteMessageRecord(messageId);
    });
  });
  elements.detailBody.querySelectorAll('.edit-cost-btn').forEach((node) => {
    node.addEventListener('click', () => {
      const costId = Number(node.getAttribute('data-cost-id'));
      if (Number.isFinite(costId)) editCostRecord(costId);
    });
  });
  elements.detailBody.querySelectorAll('.delete-cost-btn').forEach((node) => {
    node.addEventListener('click', () => {
      const costId = Number(node.getAttribute('data-cost-id'));
      if (Number.isFinite(costId)) deleteCostRecord(costId);
    });
  });
  document.getElementById('saveCaseBtn')?.addEventListener('click', saveCaseChanges);
  document.getElementById('deleteCaseBtn')?.addEventListener('click', deleteComplaintCase);
  document.getElementById('addEventBtn')?.addEventListener('click', addCaseEvent);
  document.getElementById('fillTemplateBtn')?.addEventListener('click', () => applyMessageTemplate(true));
  document.getElementById('messageTemplate')?.addEventListener('change', () => applyMessageTemplate(true));
  document.getElementById('sendMessageBtn')?.addEventListener('click', sendCaseMessage);
  document.getElementById('uploadAttachmentBtn')?.addEventListener('click', uploadAttachment);
  document.getElementById('addCostBtn')?.addEventListener('click', addCostItem);
  ['costQuantity', 'costUnitPrice', 'costMaterial', 'costLabor', 'costVendor'].forEach((id) => {
    document.getElementById(id)?.addEventListener('input', updateCostPreview);
  });
}

async function quickSetStatus(status) {
  if (!state.selectedId || !status) return;
  try {
    ensureSession(true);
    setNotice('상태를 변경하는 중입니다.');
    await request('/api/complaints/' + state.selectedId, { method: 'PATCH', json: { status: status } });
    await loadQueue({ selectId: state.selectedId });
    setNotice('상태를 ' + (STATUS_LABELS[status] || status) + '로 저장했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '상태 저장에 실패했습니다.', 'error');
    writeDebug('quick-status-error', error);
  }
}

async function saveCaseChanges() {
  if (!state.selectedId) return;
  try {
    ensureSession(true);
    const payload = {
      title: nullIfBlank(document.getElementById('detailTitle')?.value),
      description: document.getElementById('detailDescription')?.value || '',
      assignee: nullIfBlank(document.getElementById('detailAssignee')?.value),
      status: document.getElementById('detailStatus')?.value || null,
      priority: document.getElementById('detailPriority')?.value || null,
      complaint_type: nullIfBlank(document.getElementById('detailComplaintType')?.value),
      scheduled_visit_at: fromLocalDateTimeInput(document.getElementById('detailVisitAt')?.value),
      recurrence_flag: document.getElementById('detailRecurrence')?.value === 'true',
      resident_name: nullIfBlank(document.getElementById('detailResidentName')?.value),
      contact_phone: nullIfBlank(document.getElementById('detailPhone')?.value),
    };
    setNotice('민원 기본정보를 저장하는 중입니다.');
    await request('/api/complaints/' + state.selectedId, { method: 'PATCH', json: payload });
    await loadQueue({ selectId: state.selectedId });
    setNotice('민원 기본정보를 저장했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '민원 기본정보 저장에 실패했습니다.', 'error');
    writeDebug('save-case-error', error);
  }
}

async function deleteComplaintCase() {
  if (!state.selectedId || !state.detail) return;
  if (!window.confirm(state.detail.case.building + ' ' + state.detail.case.unit_number + ' 민원과 하위 레코드를 모두 삭제할까요?')) return;
  try {
    ensureSession(true);
    const complaintId = state.selectedId;
    setNotice('민원 레코드를 삭제하는 중입니다.');
    await request('/api/complaints/' + complaintId, { method: 'DELETE' });
    state.selectedId = null;
    state.detail = null;
    state.householdHistory = null;
    await loadQueue({ selectId: null });
    setNotice('민원 레코드를 삭제했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '민원 삭제에 실패했습니다.', 'error');
    writeDebug('delete-case-error', error);
  }
}

async function addCaseEvent() {
  if (!state.selectedId) return;
  try {
    ensureSession(true);
    const payload = { event_type: document.getElementById('eventType')?.value || 'note', to_status: nullIfBlank(document.getElementById('eventToStatus')?.value), note: document.getElementById('eventNote')?.value || '', detail: {} };
    setNotice('처리 이력을 저장하는 중입니다.');
    await request('/api/complaints/' + state.selectedId + '/events', { method: 'POST', json: payload });
    await loadQueue({ selectId: state.selectedId });
    setNotice('처리 이력을 저장했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '처리 이력 저장에 실패했습니다.', 'error');
    writeDebug('add-event-error', error);
  }
}

async function editEventRecord(eventId) {
  const item = findDetailRecord('events', eventId);
  if (!item) return;
  const eventType = window.prompt('이력 유형을 입력하세요.', item.event_type || 'note');
  if (eventType === null) return;
  const note = window.prompt('이력 메모를 입력하세요.', item.note || '');
  if (note === null) return;
  const detailText = window.prompt('detail JSON을 입력하세요.', JSON.stringify(item.detail || {}));
  if (detailText === null) return;
  try {
    let detailPayload = {};
    try {
      detailPayload = detailText.trim() ? JSON.parse(detailText) : {};
    } catch (error) {
      throw new Error('detail JSON 형식이 올바르지 않습니다.');
    }
    ensureSession(true);
    setNotice('처리 이력 레코드를 수정하는 중입니다.');
    await request('/api/complaints/events/' + eventId, { method: 'PATCH', json: { event_type: eventType, note: note, detail: detailPayload } });
    await refreshSelectedDetail();
    setNotice('처리 이력 레코드를 수정했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '처리 이력 수정에 실패했습니다.', 'error');
    writeDebug('edit-event-error', error);
  }
}

async function deleteEventRecord(eventId) {
  if (!window.confirm('이 처리 이력 레코드를 삭제할까요?')) return;
  try {
    ensureSession(true);
    setNotice('처리 이력 레코드를 삭제하는 중입니다.');
    await request('/api/complaints/events/' + eventId, { method: 'DELETE' });
    await refreshSelectedDetail();
    setNotice('처리 이력 레코드를 삭제했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '처리 이력 삭제에 실패했습니다.', 'error');
    writeDebug('delete-event-error', error);
  }
}

async function sendCaseMessage() {
  if (!state.selectedId) return;
  try {
    ensureSession(true);
    const payload = { template_key: nullIfBlank(document.getElementById('messageTemplate')?.value), recipient: nullIfBlank(document.getElementById('messageRecipient')?.value), body: document.getElementById('messageBody')?.value || '' };
    if (!payload.body.trim()) throw new Error('문자 내용을 입력하세요.');
    setNotice('문자를 발송하는 중입니다.');
    await request('/api/complaints/' + state.selectedId + '/messages', { method: 'POST', json: payload });
    await refreshSelectedDetail();
    setNotice('문자를 발송했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '문자 발송에 실패했습니다.', 'error');
    writeDebug('send-message-error', error);
  }
}

async function uploadAttachment() {
  if (!state.selectedId) return;
  try {
    ensureSession(true);
    const fileInput = document.getElementById('attachmentFile');
    const file = fileInput?.files?.[0];
    if (!file) throw new Error('업로드할 파일을 선택하세요.');
    const formData = new FormData();
    formData.append('attachment_kind', document.getElementById('attachmentKind')?.value || 'intake');
    formData.append('note', document.getElementById('attachmentNote')?.value || '');
    formData.append('file', file);
    setNotice('첨부를 업로드하는 중입니다.');
    await request('/api/complaints/' + state.selectedId + '/attachments', { method: 'POST', body: formData });
    await refreshSelectedDetail();
    if (fileInput) fileInput.value = '';
    const noteInput = document.getElementById('attachmentNote');
    if (noteInput) noteInput.value = '';
    setNotice('첨부를 업로드했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '첨부 업로드에 실패했습니다.', 'error');
    writeDebug('upload-attachment-error', error);
  }
}

async function editAttachmentRecord(attachmentId) {
  const item = findDetailRecord('attachments', attachmentId);
  if (!item) return;
  const attachmentKind = window.prompt('첨부 구분을 입력하세요. intake / before / after / other', item.attachment_kind || 'intake');
  if (attachmentKind === null) return;
  const note = window.prompt('첨부 메모를 입력하세요.', item.note || '');
  if (note === null) return;
  try {
    ensureSession(true);
    setNotice('첨부 레코드를 수정하는 중입니다.');
    await request('/api/complaints/attachments/' + attachmentId, { method: 'PATCH', json: { attachment_kind: attachmentKind, note: note } });
    await refreshSelectedDetail();
    setNotice('첨부 레코드를 수정했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '첨부 수정에 실패했습니다.', 'error');
    writeDebug('edit-attachment-error', error);
  }
}

async function deleteAttachmentRecord(attachmentId) {
  if (!window.confirm('이 첨부 레코드를 삭제할까요?')) return;
  try {
    ensureSession(true);
    setNotice('첨부 레코드를 삭제하는 중입니다.');
    await request('/api/complaints/attachments/' + attachmentId, { method: 'DELETE' });
    await refreshSelectedDetail();
    setNotice('첨부 레코드를 삭제했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '첨부 삭제에 실패했습니다.', 'error');
    writeDebug('delete-attachment-error', error);
  }
}

async function addCostItem() {
  if (!state.selectedId) return;
  try {
    ensureSession(true);
    const payload = {
      cost_category: document.getElementById('costCategory')?.value || 'other',
      item_name: document.getElementById('costItemName')?.value || '',
      quantity: numberValue(document.getElementById('costQuantity')?.value),
      unit_price: numberValue(document.getElementById('costUnitPrice')?.value),
      material_cost: numberValue(document.getElementById('costMaterial')?.value),
      labor_cost: numberValue(document.getElementById('costLabor')?.value),
      vendor_cost: numberValue(document.getElementById('costVendor')?.value),
      note: document.getElementById('costNote')?.value || '',
    };
    if (!payload.item_name.trim()) throw new Error('비용 항목명을 입력하세요.');
    setNotice('비용 항목을 저장하는 중입니다.');
    await request('/api/complaints/' + state.selectedId + '/cost-items', { method: 'POST', json: payload });
    await refreshSelectedDetail();
    ['costItemName', 'costNote'].forEach((id) => { const input = document.getElementById(id); if (input) input.value = ''; });
    ['costQuantity', 'costUnitPrice', 'costMaterial', 'costLabor', 'costVendor'].forEach((id, index) => { const input = document.getElementById(id); if (input) input.value = index === 0 ? '1' : '0'; });
    updateCostPreview();
    setNotice('비용 항목을 저장했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '비용 항목 저장에 실패했습니다.', 'error');
    writeDebug('add-cost-error', error);
  }
}

async function editMessageRecord(messageId) {
  const item = findDetailRecord('messages', messageId);
  if (!item) return;
  const recipient = window.prompt('수신번호를 입력하세요.', item.recipient || '');
  if (recipient === null) return;
  const templateKey = window.prompt('템플릿 키를 입력하세요. 비우면 직접입력입니다.', item.template_key || '');
  if (templateKey === null) return;
  const deliveryStatus = window.prompt('발송 상태를 입력하세요.', item.delivery_status || 'sent');
  if (deliveryStatus === null) return;
  const body = window.prompt('문자 내용을 입력하세요.', item.body || '');
  if (body === null) return;
  const errorText = window.prompt('오류 메시지를 입력하세요. 없으면 비워두세요.', item.error || '');
  if (errorText === null) return;
  try {
    ensureSession(true);
    setNotice('문자 레코드를 수정하는 중입니다.');
    await request('/api/complaints/messages/' + messageId, {
      method: 'PATCH',
      json: { recipient: recipient, template_key: nullIfBlank(templateKey), delivery_status: deliveryStatus, body: body, error: nullIfBlank(errorText) },
    });
    await refreshSelectedDetail();
    setNotice('문자 레코드를 수정했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '문자 레코드 수정에 실패했습니다.', 'error');
    writeDebug('edit-message-error', error);
  }
}

async function deleteMessageRecord(messageId) {
  if (!window.confirm('이 문자 레코드를 삭제할까요?')) return;
  try {
    ensureSession(true);
    setNotice('문자 레코드를 삭제하는 중입니다.');
    await request('/api/complaints/messages/' + messageId, { method: 'DELETE' });
    await refreshSelectedDetail();
    setNotice('문자 레코드를 삭제했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '문자 레코드 삭제에 실패했습니다.', 'error');
    writeDebug('delete-message-error', error);
  }
}

async function editCostRecord(costId) {
  const item = findDetailRecord('cost_items', costId);
  if (!item) return;
  const costCategory = window.prompt('비용 구분을 입력하세요.', item.cost_category || 'other');
  if (costCategory === null) return;
  const itemName = window.prompt('항목명을 입력하세요.', item.item_name || '');
  if (itemName === null) return;
  const quantity = window.prompt('수량을 입력하세요.', String(item.quantity ?? 0));
  if (quantity === null) return;
  const unitPrice = window.prompt('단가를 입력하세요.', String(item.unit_price ?? 0));
  if (unitPrice === null) return;
  const materialCost = window.prompt('자재비를 입력하세요.', String(item.material_cost ?? 0));
  if (materialCost === null) return;
  const laborCost = window.prompt('인건비를 입력하세요.', String(item.labor_cost ?? 0));
  if (laborCost === null) return;
  const vendorCost = window.prompt('외주비를 입력하세요.', String(item.vendor_cost ?? 0));
  if (vendorCost === null) return;
  const note = window.prompt('메모를 입력하세요.', item.note || '');
  if (note === null) return;
  try {
    ensureSession(true);
    setNotice('비용 레코드를 수정하는 중입니다.');
    await request('/api/complaints/cost-items/' + costId, {
      method: 'PATCH',
      json: {
        cost_category: costCategory,
        item_name: itemName,
        quantity: numberValue(quantity),
        unit_price: numberValue(unitPrice),
        material_cost: numberValue(materialCost),
        labor_cost: numberValue(laborCost),
        vendor_cost: numberValue(vendorCost),
        note: note,
      },
    });
    await refreshSelectedDetail();
    setNotice('비용 레코드를 수정했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '비용 레코드 수정에 실패했습니다.', 'error');
    writeDebug('edit-cost-error', error);
  }
}

async function deleteCostRecord(costId) {
  if (!window.confirm('이 비용 레코드를 삭제할까요?')) return;
  try {
    ensureSession(true);
    setNotice('비용 레코드를 삭제하는 중입니다.');
    await request('/api/complaints/cost-items/' + costId, { method: 'DELETE' });
    await refreshSelectedDetail();
    setNotice('비용 레코드를 삭제했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '비용 레코드 삭제에 실패했습니다.', 'error');
    writeDebug('delete-cost-error', error);
  }
}

async function downloadAttachment(attachmentId, fileName) {
  try {
    ensureSession(true);
    const response = await fetch('/api/complaints/attachments/' + attachmentId + '/download', { headers: { 'X-Admin-Token': elements.token.value.trim() } });
    if (!response.ok) {
      const contentType = response.headers.get('content-type') || '';
      const detail = contentType.includes('application/json') ? formatApiError(await response.json()) : ((await response.text()).trim() || (response.status + ' error'));
      throw new Error(detail);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = fileName || ('complaint-' + attachmentId);
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setNotice('첨부를 내려받았습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '첨부 다운로드에 실패했습니다.', 'error');
    writeDebug('download-attachment-error', error);
  }
}

async function loadQueue(options) {
  try {
    const session = ensureSession(true);
    savePrefs();
    setNotice('현장 큐를 불러오는 중입니다.');
    const rows = await request('/api/complaints?' + new URLSearchParams({ site: session.site }).toString());
    state.queue = sortQueue(Array.isArray(rows) ? rows : []);
    renderStats();
    renderQueue();
    writeDebug('queue-loaded', { site: session.site, count: state.queue.length, sample: state.queue[0] || null });
    const preferredId = options && Object.prototype.hasOwnProperty.call(options, 'selectId') ? options.selectId : state.selectedId;
    if (preferredId && state.queue.some((item) => item.id === preferredId)) {
      await loadDetail(preferredId, { suppressNotice: true });
    } else if (!state.selectedId && state.filteredQueue.length) {
      await loadDetail(state.filteredQueue[0].id, { suppressNotice: true });
    } else if (!state.queue.length) {
      state.selectedId = null;
      state.detail = null;
      state.householdHistory = null;
      clearDetail('현재 site에 등록된 민원이 없습니다.');
    }
    setNotice('민원 ' + state.queue.length + '건을 불러왔습니다.', 'success');
  } catch (error) {
    state.queue = [];
    state.filteredQueue = [];
    renderStats();
    renderQueue();
    clearDetail('토큰 또는 site를 확인한 뒤 다시 불러와 주세요.');
    setNotice(error.message || '현장 큐를 불러오지 못했습니다.', 'error');
    writeDebug('queue-error', error);
  }
}

async function loadDetail(complaintId, options) {
  try {
    ensureSession(true);
    state.selectedId = complaintId;
    state.householdHistory = null;
    renderQueue();
    elements.detailMeta.textContent = '민원 #' + complaintId + ' 불러오는 중';
    elements.detailBody.innerHTML = '<div class="empty">상세 정보를 불러오는 중입니다.</div>';
    const detail = await request('/api/complaints/' + complaintId);
    if (state.selectedId !== complaintId) return;
    state.detail = detail;
    renderDetail();
    const history = await request('/api/complaints/households/history?' + new URLSearchParams({ site: detail.case.site, building: detail.case.building, unit_number: detail.case.unit_number }).toString());
    if (state.selectedId !== complaintId) return;
    state.householdHistory = history;
    renderDetail();
    if (!(options && options.suppressNotice)) setNotice(detail.case.building + ' ' + detail.case.unit_number + ' 상세를 불러왔습니다.', 'success');
    writeDebug('detail-loaded', detail);
  } catch (error) {
    setNotice(error.message || '상세를 불러오지 못했습니다.', 'error');
    writeDebug('detail-error', error);
  }
}

async function refreshSelectedDetail() {
  if (!state.selectedId) return loadQueue();
  return loadDetail(state.selectedId, { suppressNotice: true });
}

async function createComplaint() {
  try {
    ensureSession(true);
    const payload = {
      site: nullIfBlank(elements.createSite.value) || nullIfBlank(elements.siteFilter.value),
      building: elements.createBuilding.value,
      unit_number: elements.createUnitNumber.value,
      resident_name: nullIfBlank(elements.createResidentName.value),
      contact_phone: nullIfBlank(elements.createPhone.value),
      complaint_type: nullIfBlank(elements.createComplaintType.value),
      description: elements.createDescription.value,
      priority: elements.createPriority.value || 'medium',
      recurrence_flag: elements.createRecurrence.value === 'true',
      source_channel: 'manual',
    };
    if (!payload.site) throw new Error('site를 입력하세요.');
    if (!String(payload.building || '').trim()) throw new Error('동 정보를 입력하세요.');
    if (!String(payload.unit_number || '').trim()) throw new Error('호수 정보를 입력하세요.');
    if (!String(payload.description || '').trim()) throw new Error('민원내용을 입력하세요.');
    setNotice('민원을 등록하는 중입니다.');
    const created = await request('/api/complaints', { method: 'POST', json: payload });
    elements.siteFilter.value = created.site;
    elements.createSite.value = created.site;
    elements.createBuilding.value = '';
    elements.createUnitNumber.value = '';
    elements.createResidentName.value = '';
    elements.createPhone.value = '';
    elements.createComplaintType.value = '';
    elements.createDescription.value = '';
    elements.createPriority.value = 'medium';
    elements.createRecurrence.value = 'false';
    savePrefs();
    await loadQueue({ selectId: created.id });
    setNotice('민원을 등록했습니다.', 'success');
  } catch (error) {
    setNotice(error.message || '민원 등록에 실패했습니다.', 'error');
    writeDebug('create-complaint-error', error);
  }
}

function resetFilters() {
  elements.statusFilter.value = '';
  elements.searchFilter.value = '';
  state.recurrenceOnly = false;
  renderQueue();
}

function bindStaticEvents() {
  elements.fieldTabBtn.addEventListener('click', () => switchTab('field'));
  elements.dbTabBtn.addEventListener('click', () => switchTab('db'));
  elements.refreshQueueBtn.addEventListener('click', () => loadQueue({ selectId: state.selectedId }));
  elements.savePrefsBtn.addEventListener('click', () => {
    savePrefs();
    setTokenVisibility(false);
    setNotice('토큰과 site를 저장했습니다.', 'success');
  });
  elements.checkConnectionBtn.addEventListener('click', checkConnection);
  elements.toggleTokenVisibilityBtn.addEventListener('click', () => setTokenVisibility(elements.token.type === 'password'));
  elements.clearPrefsBtn.addEventListener('click', clearPrefs);
  elements.statusFilter.addEventListener('change', renderQueue);
  elements.searchFilter.addEventListener('input', renderQueue);
  elements.recurrenceToggle.addEventListener('click', () => {
    state.recurrenceOnly = !state.recurrenceOnly;
    renderQueue();
  });
  elements.clearFiltersBtn.addEventListener('click', resetFilters);
  elements.token.addEventListener('change', savePrefs);
  elements.siteFilter.addEventListener('change', () => {
    if (!elements.createSite.value.trim()) elements.createSite.value = elements.siteFilter.value.trim();
    syncDbSiteMirror();
    savePrefs();
    renderReportPreview();
    if (elements.token.value.trim()) loadAdminReportDefault({ applyToForm: false, silent: true });
  });
  elements.seedCreateSiteBtn.addEventListener('click', () => {
    elements.createSite.value = elements.siteFilter.value.trim();
  });
  elements.reportCompanyPreset.addEventListener('change', () => applyReportPreset('company', elements.reportCompanyPreset.value));
  elements.reportContractorPreset.addEventListener('change', () => applyReportPreset('contractor', elements.reportContractorPreset.value));
  elements.reportPhrasePreset.addEventListener('change', () => applyReportPreset('phrase', elements.reportPhrasePreset.value));
  elements.reportCompanyName.addEventListener('input', updateReportCoverDraft);
  elements.reportContractorName.addEventListener('input', updateReportCoverDraft);
  elements.reportSubmissionPhrase.addEventListener('input', updateReportCoverDraft);
  elements.reportCompanyName.addEventListener('change', saveReportCoverPrefs);
  elements.reportContractorName.addEventListener('change', saveReportCoverPrefs);
  elements.reportSubmissionPhrase.addEventListener('change', saveReportCoverPrefs);
  elements.applyReportDefaultsBtn.addEventListener('click', applyDefaultReportCover);
  elements.clearReportLogoBtn.addEventListener('click', clearReportLogo);
  elements.saveReportPrefsBtn.addEventListener('click', () => {
    saveReportCoverPrefs();
    setNotice('출력 표지 설정을 저장했습니다.', 'success');
  });
  elements.reportLogoFile.addEventListener('change', async () => {
    const file = elements.reportLogoFile.files && elements.reportLogoFile.files[0];
    if (!file) return;
    try {
      await loadReportLogoFile(file);
    } catch (error) {
      setNotice(error.message || '로고 파일을 불러오지 못했습니다.', 'error');
      writeDebug('report-logo-load-error', error);
    }
  });
  elements.reportType.addEventListener('change', renderReportPreview);
  elements.reportBuilding.addEventListener('input', renderReportPreview);
  elements.reportPresetSelect.addEventListener('change', () => {
    if (elements.reportPresetName) elements.reportPresetName.value = elements.reportPresetSelect.value || '';
  });
  elements.saveReportPresetBtn.addEventListener('click', saveCurrentReportPreset);
  elements.loadReportPresetBtn.addEventListener('click', loadSelectedReportPreset);
  elements.deleteReportPresetBtn.addEventListener('click', deleteSelectedReportPreset);
  elements.reportAdminScope.addEventListener('change', () => {
    if (elements.token.value.trim()) loadAdminReportDefault({ applyToForm: false, silent: true });
  });
  elements.loadAdminReportDefaultBtn.addEventListener('click', () => loadAdminReportDefault({ applyToForm: true }));
  elements.saveAdminReportDefaultBtn.addEventListener('click', saveAdminReportDefault);
  elements.deleteAdminReportDefaultBtn.addEventListener('click', deleteAdminReportDefault);
  elements.downloadXlsxBtn.addEventListener('click', () => downloadComplaintReport('xlsx'));
  elements.downloadPdfBtn.addEventListener('click', () => downloadComplaintReport('pdf'));
  elements.createComplaintBtn.addEventListener('click', createComplaint);
  elements.loadDbRecordsBtn.addEventListener('click', loadDbRecords);
  elements.applyDbChangesBtn.addEventListener('click', applyDbChanges);
  elements.deleteDbRowsBtn.addEventListener('click', deleteSelectedDbRows);
  elements.clearDbSelectionBtn.addEventListener('click', clearDbSelectionAndChanges);
  elements.showAllDbColumnsBtn.addEventListener('click', showAllDbColumns);
  elements.resetDbColumnsBtn.addEventListener('click', resetDbColumnVisibility);
  elements.dbRecordType.addEventListener('change', () => {
    state.dbEditor.recordType = elements.dbRecordType.value || 'cases';
    state.dbEditor.columns = [];
    state.dbEditor.rows = [];
    state.dbEditor.totalCount = 0;
    state.dbEditor.dirtyRows = {};
    state.dbEditor.selectedIds = {};
    state.dbEditor.originalRows = {};
    elements.dbMeta.textContent = (elements.siteFilter.value.trim() || 'site 미설정') + ' · 레코드 종류를 바꿨습니다. 다시 불러오세요.';
    renderDbColumnToggles();
    renderDbEditorTable();
  });
  elements.dbSearch.addEventListener('keydown', (event) => { if (event.key === 'Enter') loadDbRecords(); });
  elements.token.addEventListener('blur', () => setTokenVisibility(false));
}

function init() {
  loadPrefs();
  setTokenVisibility(false);
  syncDbSiteMirror();
  fillReportCoverInputs();
  renderReportPresetOptions('');
  bindStaticEvents();
  renderStats();
  renderQueue();
  renderDbEditorTable();
  clearDetail();
  switchTab('field');
  writeDebug('ready', '토큰과 site를 입력하면 현장 큐를 불러올 수 있습니다.');
  if (elements.token.value.trim()) {
    loadAdminReportDefault({ applyToForm: !state.reportCoverPrefsLoaded, silent: true });
    if (!getStoredAuthProfile()) {
      probeAuthProfile({ silent: true }).catch(() => {});
    }
  }
  if (elements.token.value.trim() && elements.siteFilter.value.trim()) loadQueue();
}

init();
"""
    return template.replace("__PAGE_TITLE__", page_title).replace("__SCRIPT__", script.strip())
