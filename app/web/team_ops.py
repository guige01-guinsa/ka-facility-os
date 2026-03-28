"""Team operations web shell."""

from __future__ import annotations

import hashlib
import html
from functools import lru_cache
from pathlib import Path


_TEAM_OPS_ASSET_DIR = Path(__file__).resolve().parent / "assets"
_TEAM_OPS_APP_JS_PATH = _TEAM_OPS_ASSET_DIR / "team_ops_app.js"


@lru_cache(maxsize=1)
def _team_ops_script_text() -> str:
    return _TEAM_OPS_APP_JS_PATH.read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def team_ops_script_version() -> str:
    payload = _team_ops_script_text().encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:12]


def team_ops_script_text() -> str:
    return _team_ops_script_text()


def team_ops_script_url() -> str:
    return f"/web/team-ops/app.js?v={team_ops_script_version()}"


def build_team_ops_html(*, title: str = "시설팀 운영") -> str:
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
      --card: rgba(255, 255, 255, 0.93);
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
    .wrap { max-width: 1460px; margin: 0 auto; padding: 18px 14px 42px; }
    .mast {
      border: 1px solid rgba(176, 198, 223, 0.75);
      border-radius: 28px;
      background:
        linear-gradient(145deg, rgba(255,255,255,0.96) 0%, rgba(236,248,243,0.95) 48%, rgba(255,243,231,0.95) 100%);
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
      font-size: clamp(28px, 4vw, 44px);
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
      opacity: 0.16;
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
    .stat-card.active { color: var(--accent); }
    .stat-card.attention { color: var(--warning); }
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
    textarea { min-height: 92px; resize: vertical; line-height: 1.5; }
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
    button.warn {
      border-color: rgba(214, 116, 103, 0.96);
      background: rgba(255, 239, 236, 0.98);
      color: #8f2d24;
    }
    button.ghost {
      background: rgba(255,255,255,0.72);
    }
    .session-grid { display: grid; gap: 10px; grid-template-columns: minmax(0, 1.3fr) minmax(180px, 0.7fr); align-items: end; }
    .toolbar { margin-top: 16px; display: grid; gap: 14px; grid-template-columns: minmax(0, 1.1fr) minmax(0, 0.9fr); }
    .toolbar-row { display: flex; flex-wrap: wrap; gap: 8px; }
    .tab-strip { display: flex; flex-wrap: wrap; gap: 8px; }
    .tab-strip button[aria-pressed="true"] {
      background: rgba(233, 248, 242, 0.98);
      border-color: rgba(111, 197, 171, 0.98);
      color: #0c5d4d;
    }
    .workspace-grid { margin-top: 14px; display: grid; gap: 14px; grid-template-columns: minmax(0, 1.15fr) minmax(360px, 0.85fr); }
    .table-wrap, .list-wrap {
      border: 1px solid rgba(200, 213, 229, 0.86);
      border-radius: 16px;
      background: rgba(255,255,255,0.9);
      overflow: auto;
    }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td {
      padding: 11px 10px;
      border-bottom: 1px solid rgba(219, 229, 242, 0.92);
      text-align: left;
      vertical-align: top;
    }
    th { font-size: 12px; color: #4f6685; font-weight: 900; background: rgba(245, 249, 255, 0.96); position: sticky; top: 0; }
    tr.selected { background: rgba(233, 248, 242, 0.82); }
    tr:hover td { background: rgba(248, 252, 255, 0.76); }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border-radius: 999px;
      padding: 5px 8px;
      font-size: 11px;
      font-weight: 900;
      background: rgba(239, 247, 255, 0.96);
      color: #27527e;
    }
    .pill.ok { background: rgba(236, 250, 242, 0.96); color: #165c39; }
    .pill.warn { background: rgba(255, 245, 225, 0.96); color: #8a6110; }
    .pill.danger { background: rgba(255, 239, 236, 0.96); color: #8f2d24; }
    .meta-list, .quick-links, .category-list {
      list-style: none;
      margin: 0;
      padding: 0;
      display: grid;
      gap: 8px;
    }
    .meta-list li, .quick-links li, .category-list li {
      border: 1px solid rgba(204, 216, 231, 0.9);
      border-radius: 14px;
      background: rgba(255,255,255,0.88);
      padding: 10px 12px;
    }
    .quick-links a {
      text-decoration: none;
      color: #154e7a;
      font-weight: 800;
    }
    .muted { color: var(--muted); font-size: 12px; }
    .empty {
      padding: 22px;
      text-align: center;
      color: var(--muted);
      font-size: 13px;
    }
    .hidden { display: none !important; }
    @media (max-width: 1080px) {
      .mast, .toolbar, .workspace-grid { grid-template-columns: 1fr; }
      .snapshot-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 720px) {
      .wrap { padding: 14px 10px 32px; }
      .session-grid, .grid-4, .grid-3, .grid-2, .snapshot-grid { grid-template-columns: 1fr; }
      th, td { white-space: nowrap; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="mast">
      <div class="title-block">
        <p class="eyebrow">Facility Team Ops Module</p>
        <h1>시설팀 운영</h1>
        <p>다운로드한 JSX 시안의 정보구조를 기존 시스템 안정형 구조로 다시 얹은 모듈입니다. 현장기록, 시설위치, 공구/자재, 기존 코어 업무 링크를 한 화면에서 다루되, 새 데이터는 팀 운영 전용 테이블에만 저장해 기존 민원·작업지시 흐름을 건드리지 않습니다.</p>
        <div class="hero-links">
          <a href="/web/console">운영 콘솔</a>
          <a href="/web/complaints">세대 민원</a>
          <a href="/api/work-orders">작업지시 API</a>
          <a href="/api/inspections">점검 API</a>
        </div>
      </div>
      <div class="snapshot-grid">
        <article class="stat-card total">
          <span>팀 작업일지</span>
          <strong id="heroLogTotal">-</strong>
          <small>현장기록 누적 건수</small>
        </article>
        <article class="stat-card active">
          <span>미완료 현안</span>
          <strong id="heroLogActive">-</strong>
          <small>후속조치 필요 항목</small>
        </article>
        <article class="stat-card attention">
          <span>주의 재고</span>
          <strong id="heroInventoryAttention">-</strong>
          <small>부족 또는 점검 필요 품목</small>
        </article>
        <article class="stat-card done">
          <span>완료 기록</span>
          <strong id="heroLogCompleted">-</strong>
          <small>완결된 작업 내역</small>
        </article>
      </div>
    </section>

    <div id="noticeBar" class="notice-bar">토큰과 site를 입력한 뒤 연결 확인을 하면 팀 운영 화면이 활성화됩니다.</div>

    <section class="surface" style="margin-top:14px;">
      <div class="surface-head">
        <h2>작업 세션</h2>
        <div class="meta">공통 인증 토큰을 공유합니다.</div>
      </div>
      <div class="surface-body">
        <div class="session-grid">
          <div class="field-stack">
            <label class="caption" for="token">X-Admin-Token</label>
            <input id="token" type="password" autocomplete="off" />
          </div>
          <div class="field-stack">
            <label class="caption" for="siteFilter">site</label>
            <input id="siteFilter" type="text" placeholder="예: 연산더샵" />
          </div>
        </div>
        <div class="actions">
          <button id="refreshAllBtn" class="run" type="button">현장 데이터 새로고침</button>
          <button id="savePrefsBtn" type="button">토큰 저장</button>
          <button id="checkConnectionBtn" type="button">연결 확인</button>
          <button id="toggleTokenVisibilityBtn" type="button">토큰 보기</button>
          <button id="clearPrefsBtn" class="ghost" type="button">저장값 지우기</button>
        </div>
        <div id="sessionStatus" class="notice-bar" style="margin-top:12px;">토큰 상태: 없음</div>
      </div>
    </section>

    <section class="toolbar">
      <div class="surface">
        <div class="surface-head">
          <h2>대시보드</h2>
          <div class="meta" id="dashboardMeta">site 미설정</div>
        </div>
        <div class="surface-body">
          <div class="grid-4">
            <div>
              <label class="caption" for="rangeKey">집계 범위</label>
              <select id="rangeKey">
                <option value="day">일간</option>
                <option value="week" selected>주간</option>
                <option value="month">월간</option>
                <option value="all">전체</option>
              </select>
            </div>
            <div>
              <label class="caption">작업지시 열림</label>
              <input id="statWorkOrders" type="text" readonly />
            </div>
            <div>
              <label class="caption">세대 민원 진행</label>
              <input id="statComplaints" type="text" readonly />
            </div>
            <div>
              <label class="caption">공문 진행</label>
              <input id="statDocs" type="text" readonly />
            </div>
          </div>
          <div class="actions">
            <button id="refreshDashboardBtn" class="run" type="button">대시보드 새로고침</button>
          </div>
          <div class="grid-2" style="margin-top:12px;">
            <div>
              <label class="caption">카테고리 분포</label>
              <ul id="categoryList" class="category-list"><li class="empty">데이터를 불러오면 표시됩니다.</li></ul>
            </div>
            <div>
              <label class="caption">코어 업무 바로가기</label>
              <ul id="quickLinks" class="quick-links"><li class="empty">데이터를 불러오면 표시됩니다.</li></ul>
            </div>
          </div>
        </div>
      </div>

      <div class="surface">
        <div class="surface-head">
          <h2>모듈 작업 구역</h2>
          <div class="meta" id="workspaceMeta">기존 코어 데이터는 읽기 전용으로 재사용합니다.</div>
        </div>
        <div class="surface-body">
          <div class="tab-strip">
            <button id="logsTabBtn" type="button" aria-pressed="true">현장기록</button>
            <button id="facilitiesTabBtn" type="button" aria-pressed="false">시설위치</button>
            <button id="inventoryTabBtn" type="button" aria-pressed="false">공구/자재</button>
            <button id="reportsTabBtn" type="button" aria-pressed="false">보고</button>
          </div>
          <p class="muted" style="margin:12px 0 0;">현장기록은 팀 운영 전용 테이블에 저장됩니다. 민원이나 작업지시 자체를 직접 복제하지 않고 필요한 연결 ID만 기록합니다.</p>
        </div>
      </div>
    </section>

    <section id="logsWorkspace" class="workspace-grid">
      <article class="surface">
        <div class="surface-head">
          <h3>현장기록 목록</h3>
          <div class="meta" id="logsMeta">최근 기록</div>
        </div>
        <div class="surface-body">
          <div class="grid-3">
            <div>
              <label class="caption" for="logsSearch">검색</label>
              <input id="logsSearch" type="text" placeholder="담당자, 위치, 문제 내용" />
            </div>
            <div>
              <label class="caption" for="logsLimit">조회 건수</label>
              <select id="logsLimit">
                <option value="20">20</option>
                <option value="50" selected>50</option>
                <option value="100">100</option>
              </select>
            </div>
            <div>
              <label class="caption">실행</label>
              <div class="toolbar-row">
                <button id="loadLogsBtn" class="run" type="button">새로고침</button>
                <button id="clearLogsFormBtn" class="ghost" type="button">입력 초기화</button>
              </div>
            </div>
          </div>
          <div class="table-wrap" style="margin-top:12px;">
            <table>
              <thead>
                <tr>
                  <th>일시</th>
                  <th>담당자</th>
                  <th>분류</th>
                  <th>위치</th>
                  <th>상태</th>
                  <th>우선도</th>
                  <th>사진</th>
                </tr>
              </thead>
              <tbody id="logsTableBody">
                <tr><td class="empty" colspan="7">데이터를 불러오면 표시됩니다.</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </article>
      <article class="surface">
        <div class="surface-head">
          <h3>현장기록 입력</h3>
          <div class="meta" id="logsFormMeta">새 기록</div>
        </div>
        <div class="surface-body">
          <div class="grid-2">
            <div><label class="caption" for="logRecordedAt">기록일시</label><input id="logRecordedAt" type="datetime-local" /></div>
            <div><label class="caption" for="logReporter">담당자</label><input id="logReporter" type="text" /></div>
            <div><label class="caption" for="logCategory">분류</label><select id="logCategory"></select></div>
            <div><label class="caption" for="logLocation">위치</label><input id="logLocation" type="text" /></div>
            <div><label class="caption" for="logStatus">상태</label><select id="logStatus"></select></div>
            <div><label class="caption" for="logPriority">우선도</label><select id="logPriority"></select></div>
            <div><label class="caption" for="logPhotoCount">사진 수</label><input id="logPhotoCount" type="number" min="0" step="1" /></div>
            <div><label class="caption" for="logWorkOrderId">연결 작업지시 ID</label><input id="logWorkOrderId" type="number" min="1" step="1" /></div>
            <div><label class="caption" for="logComplaintId">연결 민원 ID</label><input id="logComplaintId" type="number" min="1" step="1" /></div>
          </div>
          <div class="field-stack" style="margin-top:8px;">
            <label class="caption" for="logIssue">문제 내용</label>
            <textarea id="logIssue"></textarea>
          </div>
          <div class="field-stack">
            <label class="caption" for="logActionTaken">조치 내용</label>
            <textarea id="logActionTaken"></textarea>
          </div>
          <div class="actions">
            <button id="saveLogBtn" class="run" type="button">기록 저장</button>
            <button id="deleteLogBtn" class="warn" type="button">선택 기록 삭제</button>
          </div>
        </div>
      </article>
    </section>

    <section id="facilitiesWorkspace" class="workspace-grid hidden">
      <article class="surface">
        <div class="surface-head">
          <h3>시설위치 목록</h3>
          <div class="meta" id="facilitiesMeta">활성 설비 위치</div>
        </div>
        <div class="surface-body">
          <div class="grid-3">
            <div>
              <label class="caption" for="facilitiesSearch">검색</label>
              <input id="facilitiesSearch" type="text" placeholder="설비종류, 위치, 메모" />
            </div>
            <div>
              <label class="caption" for="facilitiesLimit">조회 건수</label>
              <select id="facilitiesLimit">
                <option value="20">20</option>
                <option value="50" selected>50</option>
                <option value="100">100</option>
              </select>
            </div>
            <div>
              <label class="caption">실행</label>
              <div class="toolbar-row">
                <button id="loadFacilitiesBtn" class="run" type="button">새로고침</button>
                <button id="clearFacilitiesFormBtn" class="ghost" type="button">입력 초기화</button>
              </div>
            </div>
          </div>
          <div class="table-wrap" style="margin-top:12px;">
            <table>
              <thead>
                <tr>
                  <th>설비종류</th>
                  <th>위치</th>
                  <th>세부</th>
                  <th>상태</th>
                  <th>최근점검</th>
                </tr>
              </thead>
              <tbody id="facilitiesTableBody">
                <tr><td class="empty" colspan="5">데이터를 불러오면 표시됩니다.</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </article>
      <article class="surface">
        <div class="surface-head">
          <h3>시설위치 입력</h3>
          <div class="meta" id="facilitiesFormMeta">새 위치</div>
        </div>
        <div class="surface-body">
          <div class="grid-2">
            <div><label class="caption" for="facilityType">설비종류</label><input id="facilityType" type="text" /></div>
            <div><label class="caption" for="facilityLocation">위치</label><input id="facilityLocation" type="text" /></div>
            <div><label class="caption" for="facilityActive">활성 여부</label><select id="facilityActive"><option value="true">활성</option><option value="false">비활성</option></select></div>
            <div><label class="caption" for="facilityLastCheckedAt">최근 점검일시</label><input id="facilityLastCheckedAt" type="datetime-local" /></div>
          </div>
          <div class="field-stack" style="margin-top:8px;">
            <label class="caption" for="facilityDetail">세부 정보</label>
            <textarea id="facilityDetail"></textarea>
          </div>
          <div class="field-stack">
            <label class="caption" for="facilityNote">운영 메모</label>
            <textarea id="facilityNote"></textarea>
          </div>
          <div class="actions">
            <button id="saveFacilityBtn" class="run" type="button">시설위치 저장</button>
            <button id="deleteFacilityBtn" class="warn" type="button">선택 위치 삭제</button>
          </div>
        </div>
      </article>
    </section>

    <section id="inventoryWorkspace" class="workspace-grid hidden">
      <article class="surface">
        <div class="surface-head">
          <h3>공구/자재 목록</h3>
          <div class="meta" id="inventoryMeta">주의 품목 포함</div>
        </div>
        <div class="surface-body">
          <div class="grid-3">
            <div>
              <label class="caption" for="inventorySearch">검색</label>
              <input id="inventorySearch" type="text" placeholder="품목명, 종류, 위치" />
            </div>
            <div>
              <label class="caption" for="inventoryLimit">조회 건수</label>
              <select id="inventoryLimit">
                <option value="20">20</option>
                <option value="50" selected>50</option>
                <option value="100">100</option>
              </select>
            </div>
            <div>
              <label class="caption">실행</label>
              <div class="toolbar-row">
                <button id="loadInventoryBtn" class="run" type="button">새로고침</button>
                <button id="clearInventoryFormBtn" class="ghost" type="button">입력 초기화</button>
              </div>
            </div>
          </div>
          <div class="table-wrap" style="margin-top:12px;">
            <table>
              <thead>
                <tr>
                  <th>종류</th>
                  <th>품목명</th>
                  <th>수량</th>
                  <th>보관장소</th>
                  <th>상태</th>
                </tr>
              </thead>
              <tbody id="inventoryTableBody">
                <tr><td class="empty" colspan="5">데이터를 불러오면 표시됩니다.</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </article>
      <article class="surface">
        <div class="surface-head">
          <h3>공구/자재 입력</h3>
          <div class="meta" id="inventoryFormMeta">새 품목</div>
        </div>
        <div class="surface-body">
          <div class="grid-2">
            <div><label class="caption" for="inventoryKind">종류</label><select id="inventoryKind"></select></div>
            <div><label class="caption" for="inventoryName">품목명</label><input id="inventoryName" type="text" /></div>
            <div><label class="caption" for="inventoryQuantity">수량</label><input id="inventoryQuantity" type="number" step="0.01" /></div>
            <div><label class="caption" for="inventoryUnit">단위</label><input id="inventoryUnit" type="text" /></div>
            <div><label class="caption" for="inventoryPlace">보관장소</label><input id="inventoryPlace" type="text" /></div>
            <div><label class="caption" for="inventoryStatus">상태</label><select id="inventoryStatus"></select></div>
          </div>
          <div class="field-stack" style="margin-top:8px;">
            <label class="caption" for="inventoryNote">메모</label>
            <textarea id="inventoryNote"></textarea>
          </div>
          <div class="actions">
            <button id="saveInventoryBtn" class="run" type="button">재고 저장</button>
            <button id="deleteInventoryBtn" class="warn" type="button">선택 품목 삭제</button>
          </div>
        </div>
      </article>
    </section>

    <section id="reportsWorkspace" class="workspace-grid hidden">
      <article class="surface">
        <div class="surface-head">
          <h3>보고용 요약</h3>
          <div class="meta" id="reportsMeta">JSX 시안의 보고 탭을 안정형으로 재구성</div>
        </div>
        <div class="surface-body">
          <ul id="reportSummaryList" class="meta-list">
            <li class="empty">대시보드를 먼저 불러오면 요약이 표시됩니다.</li>
          </ul>
        </div>
      </article>
      <article class="surface">
        <div class="surface-head">
          <h3>코어 연동 링크</h3>
          <div class="meta">중복 저장 없이 기존 시스템을 그대로 재사용</div>
        </div>
        <div class="surface-body">
          <ul id="reportQuickLinks" class="quick-links">
            <li class="empty">대시보드를 먼저 불러오면 표시됩니다.</li>
          </ul>
        </div>
      </article>
    </section>
  </div>
  <script src="__SCRIPT_URL__"></script>
</body>
</html>
"""
    return template.replace("__PAGE_TITLE__", page_title).replace("__SCRIPT_URL__", html.escape(team_ops_script_url(), quote=True))
