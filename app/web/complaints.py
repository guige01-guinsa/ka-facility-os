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
    .workspace { margin-top: 14px; display: grid; grid-template-columns: 390px minmax(0, 1fr); gap: 12px; align-items: start; }
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
    details.surface summary { list-style: none; cursor: pointer; padding: 14px; font-size: 17px; font-weight: 900; color: var(--brand); }
    details.surface summary::-webkit-details-marker { display: none; }
    details.surface .surface-body { padding-top: 0; }
    .hint-line { margin-top: 10px; color: #5c738f; font-size: 12px; line-height: 1.45; }
    @media (max-width: 1180px) { .mast { grid-template-columns: 1fr; } .workspace { grid-template-columns: 1fr; } .queue-list { max-height: none; } }
    @media (max-width: 900px) { .dock, .detail-grid, .grid-4 { grid-template-columns: 1fr; } .grid-3 { grid-template-columns: repeat(2, minmax(0, 1fr)); } .summary-grid { grid-template-columns: 1fr 1fr; } }
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
            <div class="field-stack"><label class="caption" for="token">X-Admin-Token</label><input id="token" placeholder="관리자 토큰" /></div>
            <div class="field-stack"><label class="caption" for="siteFilter">site</label><input id="siteFilter" placeholder="예: 연산더샵" /></div>
          </div>
          <div class="actions">
            <button class="run" id="refreshQueueBtn" type="button">현장 큐 새로고침</button>
            <button class="ghost" id="clearPrefsBtn" type="button">저장값 지우기</button>
          </div>
          <div class="hint-line">토큰과 site는 브라우저 저장소에 유지됩니다. `/web/complaints`를 다시 열어도 같은 현장으로 복귀할 수 있습니다.</div>
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
    </section>
    <section class="workspace">
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
    <pre id="debugBox" class="debug-box">ready</pre>
  </div>
  <script>
__SCRIPT__
  </script>
</body>
</html>
"""
    script = """
const STORAGE_KEYS = { token: 'kaFacility.complaints.token', site: 'kaFacility.complaints.site' };
const STATUS_LABELS = { received: '접수', assigned: '배정완료', visit_scheduled: '방문예정', in_progress: '처리중', resolved: '처리완료', resident_confirmed: '세대확인완료', reopened: '재민원', closed: '종결' };
const TYPE_LABELS = { screen_contamination: '방충망 오염', screen_damage: '방충망 파손', glass_contamination: '유리/창문 오염', glass_damage: '유리/창문 파손', railing_contamination: '난간 오염', louver_issue: '루버창 불량', silicone_issue: '실리콘/퍼티 불량', wall_floor_contamination: '벽면/바닥 오염', other_finish_issue: '기타 마감불량', composite: '복합 민원' };
const PRIORITY_LABELS = { low: '낮음', medium: '보통', high: '높음', urgent: '긴급' };
const ATTACHMENT_KIND_LABELS = { intake: '접수 사진', before: '작업 전 사진', after: '작업 후 사진', other: '기타' };
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

const state = { queue: [], filteredQueue: [], selectedId: null, detail: null, householdHistory: null, recurrenceOnly: false };
const elements = {
  noticeBar: document.getElementById('noticeBar'),
  token: document.getElementById('token'),
  siteFilter: document.getElementById('siteFilter'),
  refreshQueueBtn: document.getElementById('refreshQueueBtn'),
  clearPrefsBtn: document.getElementById('clearPrefsBtn'),
  statusFilter: document.getElementById('statusFilter'),
  searchFilter: document.getElementById('searchFilter'),
  recurrenceToggle: document.getElementById('recurrenceToggle'),
  clearFiltersBtn: document.getElementById('clearFiltersBtn'),
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

function summarizeSearch(item) {
  return [item.site, item.building, item.unit_number, item.resident_name, item.contact_phone, item.complaint_type_label, item.title, item.description, item.assignee].filter(Boolean).join(' ').toLowerCase();
}

function savePrefs() {
  try {
    localStorage.setItem(STORAGE_KEYS.token, elements.token.value.trim());
    localStorage.setItem(STORAGE_KEYS.site, elements.siteFilter.value.trim());
  } catch (error) {
    writeDebug('localStorage-save-error', error);
  }
}

function loadPrefs() {
  try {
    const token = localStorage.getItem(STORAGE_KEYS.token) || '';
    const site = localStorage.getItem(STORAGE_KEYS.site) || '';
    if (token) elements.token.value = token;
    if (site) {
      elements.siteFilter.value = site;
      if (!elements.createSite.value.trim()) elements.createSite.value = site;
    }
  } catch (error) {
    writeDebug('localStorage-load-error', error);
  }
}

function clearPrefs() {
  try {
    localStorage.removeItem(STORAGE_KEYS.token);
    localStorage.removeItem(STORAGE_KEYS.site);
  } catch (error) {
    writeDebug('localStorage-clear-error', error);
  }
  elements.token.value = '';
  elements.siteFilter.value = '';
  elements.createSite.value = '';
  state.queue = [];
  state.filteredQueue = [];
  state.selectedId = null;
  state.detail = null;
  state.householdHistory = null;
  renderStats();
  renderQueue();
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
    throw new Error(response.status + ' ' + detail);
  }
  if (init.responseType === 'blob') return response.blob();
  if (response.status === 204) return null;
  const contentType = response.headers.get('content-type') || '';
  return contentType.includes('application/json') ? response.json() : response.text();
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
    return '<div class="timeline-item"><strong>' + escapeHtml(item.event_type) + '</strong><div class="meta">' + escapeHtml(formatDateTime(item.created_at)) + ' · ' + escapeHtml(item.actor_username) + statusTrail + '</div><div class="meta">' + escapeHtml(item.note || '메모 없음') + '</div></div>';
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
        '<div class="actions"><button class="ghost download-attachment-btn" type="button" data-attachment-id="' + item.id + '" data-file-name="' + escapeHtml(item.file_name) + '">파일 받기</button></div>' +
      '</div>';
  }).join('') + '</div>';
}

function renderMessageTimeline(messages) {
  if (!messages.length) return '<div class="empty">발송된 문자가 없습니다.</div>';
  return '<div class="timeline-list">' + messages.map((item) => {
    const suffix = (item.template_key ? ' · 템플릿 ' + item.template_key : '') + (item.error ? ' · 실패 ' + item.error : '');
    return '<div class="timeline-item"><strong>' + escapeHtml(item.recipient) + ' · ' + escapeHtml(item.delivery_status) + '</strong><div class="meta">' + escapeHtml(formatDateTime(item.created_at)) + ' · ' + escapeHtml(item.provider_name) + suffix + '</div><div class="meta">' + escapeHtml(item.body) + '</div></div>';
  }).join('') + '</div>';
}

function renderCostTimeline(costItems) {
  if (!costItems.length) return '<div class="empty">입력된 비용 항목이 없습니다.</div>';
  return '<div class="timeline-list">' + costItems.map((item) => {
    return '<div class="timeline-item"><strong>' + escapeHtml(item.item_name) + ' · ' + escapeHtml(formatCurrency(item.total_cost)) + '</strong><div class="meta">' + escapeHtml(item.cost_category) + ' · 수량 ' + escapeHtml(String(item.quantity)) + ' · 단가 ' + escapeHtml(formatCurrency(item.unit_price)) + '</div><div class="meta">' + escapeHtml(item.note || '메모 없음') + '</div></div>';
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
          '<div class="actions"><button class="run" id="saveCaseBtn" type="button">기본정보 저장</button></div>' +
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
  document.getElementById('saveCaseBtn')?.addEventListener('click', saveCaseChanges);
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
  elements.refreshQueueBtn.addEventListener('click', () => loadQueue({ selectId: state.selectedId }));
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
    savePrefs();
  });
  elements.seedCreateSiteBtn.addEventListener('click', () => {
    elements.createSite.value = elements.siteFilter.value.trim();
  });
  elements.createComplaintBtn.addEventListener('click', createComplaint);
}

function init() {
  loadPrefs();
  bindStaticEvents();
  renderStats();
  renderQueue();
  clearDetail();
  writeDebug('ready', '토큰과 site를 입력하면 현장 큐를 불러올 수 있습니다.');
  if (elements.token.value.trim() && elements.siteFilter.value.trim()) loadQueue();
}

init();
"""
    return template.replace("__PAGE_TITLE__", page_title).replace("__SCRIPT__", script.strip())
