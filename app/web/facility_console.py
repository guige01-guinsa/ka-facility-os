"""Facility console HTML renderers extracted from app.main."""

from __future__ import annotations

import html
from typing import Any


def build_facility_console_html(service_info: dict[str, str], modules_payload: dict[str, Any]) -> str:
    modules = modules_payload.get("modules", [])
    module_cards: list[str] = []
    for item in modules:
        links = "".join(
            f'<a href="{html.escape(str(link.get("href", "#")))}">{html.escape(str(link.get("label", "Open")))}'
            "</a>"
            for link in item.get("links", [])
        )
        module_cards.append(
            f"""
            <article class="module-card">
              <h3>{html.escape(str(item.get("name_ko", "")))}</h3>
              <p class="en">{html.escape(str(item.get("name", "")))}</p>
              <p>{html.escape(str(item.get("description", "")))}</p>
              <p class="hint"><strong>KPI Hint:</strong> {html.escape(str(item.get("kpi_hint", "")))}</p>
              <div class="module-links">{links}</div>
            </article>
            """
        )

    module_cards_html = "".join(module_cards) or '<p class="empty">모듈 정보가 없습니다.</p>'

    template = """<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>KA Facility OS - 시설 콘솔</title>
  <style>
    :root {
      --ink: #0f1e36;
      --muted: #4a607f;
      --line: #d4dfef;
      --card: #ffffff;
      --bg: #f2f7ff;
      --brand: #0a6d58;
      --accent: #cb4f20;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--ink);
      font-family: "SUIT", "Pretendard", "IBM Plex Sans KR", "Noto Sans KR", sans-serif;
      background:
        radial-gradient(900px 380px at 0% -20%, #dcf6ff 0%, transparent 60%),
        radial-gradient(700px 320px at 100% -20%, #ffefd9 0%, transparent 60%),
        var(--bg);
    }
    .wrap { max-width: 1280px; margin: 0 auto; padding: 18px 14px 56px; }
    .hero {
      border: 1px solid var(--line);
      border-radius: 16px;
      background: linear-gradient(145deg, #ffffff 0%, #eff8f5 54%, #fff5ea 100%);
      box-shadow: 0 10px 28px rgba(13, 38, 76, 0.09);
      padding: 16px;
    }
    .hero h1 { margin: 0; font-size: 24px; }
    .hero p { margin: 7px 0 0; color: var(--muted); }
    .hero-links { margin-top: 11px; display: flex; flex-wrap: wrap; gap: 8px; }
    .hero-links a {
      text-decoration: none;
      font-size: 12px;
      font-weight: 700;
      border: 1px solid #b8cfea;
      border-radius: 999px;
      padding: 6px 10px;
      color: #1f4f82;
      background: #f4f8ff;
    }
    .hero-links a:hover { border-color: #87addb; background: #e8f2ff; }
    [data-tip] { position: relative; }
    [data-tip]::after {
      content: attr(data-tip);
      position: absolute;
      left: 50%;
      top: calc(100% + 8px);
      transform: translateX(-50%) translateY(-3px);
      opacity: 0;
      pointer-events: none;
      z-index: 60;
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
    }
    [data-tip]::before {
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
      z-index: 61;
    }
    [data-tip]:hover::after,
    [data-tip]:focus-visible::after {
      opacity: 1;
      transform: translateX(-50%) translateY(0);
    }
    [data-tip]:hover::before,
    [data-tip]:focus-visible::before {
      opacity: 1;
    }
    .section {
      border: 1px solid var(--line);
      border-radius: 14px;
      background: var(--card);
      margin-top: 14px;
      padding: 14px;
    }
    .section h2 {
      margin: 0 0 8px;
      font-size: 18px;
      border-left: 4px solid var(--accent);
      padding-left: 8px;
    }
    .sub { margin: 0; color: var(--muted); font-size: 13px; }
    .auth-row {
      margin-top: 10px;
      display: grid;
      grid-template-columns: 1fr auto auto auto;
      gap: 8px;
    }
    .auth-row input, .query-card input {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 8px 10px;
      font-size: 13px;
      background: #fff;
      color: var(--ink);
    }
    .btn {
      border: 1px solid #86b7d8;
      background: #eff7ff;
      color: #1a4d7d;
      border-radius: 10px;
      padding: 8px 10px;
      font-size: 12px;
      font-weight: 800;
      cursor: pointer;
      white-space: nowrap;
    }
    .btn:hover { background: #e3f0ff; }
    .btn.run {
      border-color: #85cab7;
      background: #e9f8f3;
      color: #0d5f4f;
    }
    .btn.run:hover { background: #def5ed; }
    .token-state {
      margin-top: 8px;
      font-size: 12px;
      color: #234565;
      background: #eef5ff;
      border: 1px solid #c7d8ef;
      border-radius: 8px;
      padding: 6px 8px;
    }
    .module-grid {
      margin-top: 12px;
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 9px;
    }
    .module-card {
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #fff;
      padding: 10px;
    }
    .module-card h3 { margin: 0; font-size: 14px; color: var(--brand); }
    .module-card .en { margin: 4px 0 7px; font-size: 12px; color: #3d5b82; font-weight: 700; }
    .module-card p { margin: 4px 0; font-size: 12px; color: var(--muted); }
    .module-card .hint { margin-top: 6px; color: #254a73; }
    .module-links {
      margin-top: 8px;
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }
    .module-links a {
      text-decoration: none;
      border: 1px solid #bdd3ec;
      border-radius: 8px;
      padding: 5px 8px;
      font-size: 11px;
      font-weight: 700;
      color: #225385;
      background: #f4f9ff;
    }
    .module-links a:hover { border-color: #8bb0da; background: #eaf2ff; }
    .workspace {
      margin-top: 12px;
      display: grid;
      grid-template-columns: 420px minmax(0, 1fr);
      gap: 12px;
      align-items: start;
    }
    .query-grid {
      display: grid;
      gap: 8px;
    }
    .query-card {
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #fff;
      padding: 10px;
    }
    .query-card h3 { margin: 0 0 7px; font-size: 14px; color: #0e5f50; }
    .query-card p { margin: 0 0 8px; color: var(--muted); font-size: 12px; }
    .query-fields { display: grid; gap: 6px; margin-bottom: 7px; }
    .query-inline { display: grid; gap: 6px; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .result-panel {
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #fff;
      padding: 12px;
      min-height: 740px;
    }
    .result-meta {
      font-size: 12px;
      color: #26496d;
      background: #eef5ff;
      border: 1px solid #c8d8ee;
      border-radius: 8px;
      padding: 7px 8px;
      margin-bottom: 10px;
    }
    .empty {
      border: 1px dashed #bcd0e8;
      border-radius: 10px;
      color: var(--muted);
      background: #f8fbff;
      padding: 16px;
      text-align: center;
      font-size: 13px;
    }
    .kv-table, .arr-table {
      width: 100%;
      border-collapse: collapse;
      border: 1px solid #dbe5f2;
      border-radius: 8px;
      overflow: hidden;
      font-size: 12px;
    }
    .kv-table th, .kv-table td, .arr-table th, .arr-table td {
      border-bottom: 1px solid #eaf0f8;
      padding: 7px 8px;
      vertical-align: top;
      text-align: left;
      word-break: break-word;
    }
    .kv-table th, .arr-table th {
      background: #f6f9ff;
      color: #27486f;
    }
    .mono {
      font-family: "Consolas", "D2Coding", "IBM Plex Mono", monospace;
      font-size: 12px;
      color: #183858;
      white-space: pre-wrap;
      margin: 0;
      background: #f4f8ff;
      border: 1px solid #d8e4f4;
      border-radius: 8px;
      padding: 9px;
      max-height: 280px;
      overflow: auto;
    }
    details { margin-top: 10px; }
    details summary { cursor: pointer; color: #2c4d76; font-weight: 700; font-size: 12px; }
    .download-links {
      margin-top: 6px;
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }
    .download-links a {
      text-decoration: none;
      border: 1px solid #b6cce5;
      border-radius: 8px;
      padding: 5px 8px;
      font-size: 11px;
      font-weight: 700;
      color: #25517d;
      background: #f4f9ff;
    }
    @media (max-width: 1000px) {
      .module-grid { grid-template-columns: 1fr; }
      .workspace { grid-template-columns: 1fr; }
      .result-panel { min-height: 500px; }
      .auth-row { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <header class="hero">
      <h1>KA Facility OS 시설관리 운영 콘솔</h1>
      <p>서비스: __SERVICE_NAME__ | API 결과를 브라우저에서 표/카드로 즉시 확인하는 HTML 콘솔입니다. JSON API는 그대로 유지되며, 이 화면은 사람 중심 운영 뷰입니다.</p>
      <div class="hero-links">
        <a href="/" data-tip="공개 메인: 메인 운영 셸로 이동합니다." title="공개 메인: 메인 운영 셸로 이동합니다.">공개 메인</a>
        <a href="/docs" data-tip="스웨거 문서: 전체 API를 Swagger UI에서 확인합니다." title="스웨거 문서: 전체 API를 Swagger UI에서 확인합니다.">스웨거 문서</a>
        <a href="/web/console/guide" data-tip="콘솔 사용 가이드: 신규 사용자를 위한 1페이지 운영 흐름을 엽니다." title="콘솔 사용 가이드: 신규 사용자를 위한 1페이지 운영 흐름을 엽니다.">콘솔 사용 가이드</a>
        <a href="/api/service-info" data-tip="서비스 정보 API: 엔드포인트 맵과 주요 경로를 JSON으로 확인합니다." title="서비스 정보 API: 엔드포인트 맵과 주요 경로를 JSON으로 확인합니다.">서비스 정보 API</a>
        <a href="/api/public/modules" data-tip="모듈 API: 공개 모듈 레지스트리를 JSON으로 확인합니다." title="모듈 API: 공개 모듈 레지스트리를 JSON으로 확인합니다.">모듈 API</a>
      </div>
    </header>

    <section class="section">
      <h2>1) 인증 연결</h2>
      <p class="sub">권한이 필요한 모듈(점검/작업지시/SLA/리포트)은 관리자 토큰(X-Admin-Token)으로 조회합니다.</p>
      <div class="auth-row">
        <input id="adminTokenInput" type="password" placeholder="X-Admin-Token 입력" autocomplete="off" />
        <button id="saveTokenBtn" class="btn" type="button">토큰 저장</button>
        <button id="testTokenBtn" class="btn run" type="button">연결 테스트 (/api/auth/me)</button>
        <button id="clearTokenBtn" class="btn" type="button">토큰 지우기</button>
      </div>
      <div id="tokenState" class="token-state">토큰 상태: 없음</div>
    </section>

    <section class="section">
      <h2>2) 시설관리 모듈 허브</h2>
      <p class="sub">현재 등록된 모듈(__MODULE_COUNT__개)과 핵심 API 바로가기를 확인합니다.</p>
      <div class="module-grid">__MODULE_CARDS__</div>
    </section>

    <section class="section">
      <h2>3) 운영 데이터 HTML 조회</h2>
      <p class="sub">왼쪽에서 조회 대상을 선택하면, 오른쪽에 사람이 읽기 쉬운 표 형태로 결과가 표시됩니다.</p>
      <div class="workspace">
        <div class="query-grid">
          <article class="query-card">
            <h3>공개: 서비스 정보</h3>
            <p>인증 없이 서비스 엔드포인트 맵을 확인합니다.</p>
            <button class="btn run run-btn" data-panel="serviceInfo" type="button">조회 실행</button>
          </article>

          <article class="query-card">
            <h3>공개: 모듈 레지스트리</h3>
            <p>메인 허브 모듈 구성을 JSON 대신 HTML로 확인합니다.</p>
            <button class="btn run run-btn" data-panel="publicModules" type="button">조회 실행</button>
          </article>

          <article class="query-card">
            <h3>인증: 내 권한 확인</h3>
            <p>현재 토큰의 사용자/권한/site scope를 확인합니다.</p>
            <button class="btn run run-btn" data-panel="authMe" type="button">조회 실행</button>
          </article>

          <article class="query-card">
            <h3>점검 목록</h3>
            <div class="query-fields">
              <input id="q-inspection-site" placeholder="site (optional)" />
              <div class="query-inline">
                <input id="q-inspection-limit" placeholder="limit (default 20)" value="20" />
                <input id="q-inspection-offset" placeholder="offset (default 0)" value="0" />
              </div>
            </div>
            <button class="btn run run-btn" data-panel="inspections" type="button">조회 실행</button>
          </article>

          <article class="query-card">
            <h3>작업지시 목록</h3>
            <div class="query-fields">
              <div class="query-inline">
                <input id="q-work-status" placeholder="status (open/acked/...)" />
                <input id="q-work-site" placeholder="site (optional)" />
              </div>
              <div class="query-inline">
                <input id="q-work-limit" placeholder="limit (default 20)" value="20" />
                <input id="q-work-offset" placeholder="offset (default 0)" value="0" />
              </div>
            </div>
            <button class="btn run run-btn" data-panel="workOrders" type="button">조회 실행</button>
          </article>

          <article class="query-card">
            <h3>운영 대시보드 요약</h3>
            <div class="query-fields">
              <input id="q-dash-site" placeholder="site (optional)" />
              <div class="query-inline">
                <input id="q-dash-days" placeholder="days (default 30)" value="30" />
                <input id="q-dash-jobs" placeholder="job_limit (default 10)" value="10" />
              </div>
            </div>
            <button class="btn run run-btn" data-panel="dashboardSummary" type="button">조회 실행</button>
          </article>

          <article class="query-card">
            <h3>알림 채널 KPI (7/30일)</h3>
            <div class="query-fields">
              <input id="q-alert-event-type" placeholder="event_type (optional)" />
            </div>
            <button class="btn run run-btn" data-panel="alertChannelKpi" type="button">조회 실행</button>
          </article>

          <article class="query-card">
            <h3>알림 채널 보호상태</h3>
            <div class="query-fields">
              <div class="query-inline">
                <input id="q-alert-guard-lookback" placeholder="lookback_days (default 30)" value="30" />
                <input id="q-alert-guard-max-targets" placeholder="max_targets (default 100)" value="100" />
              </div>
            </div>
            <button class="btn run run-btn" data-panel="alertChannelGuard" type="button">조회 실행</button>
          </article>

          <article class="query-card">
            <h3>알림 데이터 보관정책</h3>
            <p>보관일/아카이브 설정과 최근 정리 작업 결과를 조회합니다.</p>
            <div class="query-inline">
              <button class="btn run run-btn" data-panel="alertRetentionPolicy" type="button">정책 조회</button>
              <button class="btn run run-btn" data-panel="alertRetentionLatest" type="button">최근 실행 조회</button>
            </div>
          </article>

          <article class="query-card">
            <h3>핸드오버 브리프</h3>
            <div class="query-fields">
              <input id="q-handover-site" placeholder="site (optional)" />
              <div class="query-inline">
                <input id="q-handover-window" placeholder="window_hours (default 12)" value="12" />
                <input id="q-handover-due-soon" placeholder="due_soon_hours (default 6)" value="6" />
              </div>
              <input id="q-handover-max-items" placeholder="max_items (default 10)" value="10" />
            </div>
            <button class="btn run run-btn" data-panel="handoverBrief" type="button">조회 실행</button>
          </article>

          <article class="query-card">
            <h3>월간 감사 리포트</h3>
            <div class="query-fields">
              <div class="query-inline">
                <input id="q-report-month" placeholder="month (YYYY-MM)" />
                <input id="q-report-site" placeholder="site (optional)" />
              </div>
            </div>
            <button class="btn run run-btn" data-panel="monthlyReport" type="button">JSON 조회</button>
            <div class="download-links">
              <a id="reportPrintLink" href="/reports/monthly/print" target="_blank" rel="noopener">HTML 인쇄</a>
              <a id="reportCsvLink" href="/api/reports/monthly/csv" target="_blank" rel="noopener">CSV 다운로드</a>
              <a id="reportPdfLink" href="/api/reports/monthly/pdf" target="_blank" rel="noopener">PDF 다운로드</a>
            </div>
          </article>

          <article class="query-card">
            <h3>SLA 정책 조회</h3>
            <div class="query-fields">
              <input id="q-sla-site" placeholder="site (optional)" />
            </div>
            <button class="btn run run-btn" data-panel="slaPolicy" type="button">조회 실행</button>
          </article>
        </div>

        <div class="result-panel">
          <h3>결과 보기</h3>
          <p id="resultMeta" class="result-meta">조회 대상을 선택하세요.</p>
          <div id="resultView" class="empty">아직 조회 결과가 없습니다.</div>
          <details>
            <summary>원본 JSON 보기</summary>
            <pre id="resultRaw" class="mono">{}</pre>
          </details>
        </div>
      </div>
    </section>
  </div>

  <script>
    (function() {
      const TOKEN_KEY = 'kaFacilityAdminToken';
      const TOKEN_KEY_ALIASES = ['kaFacilityAdminToken', 'kaFacilityMainToken'];
      const tokenInput = document.getElementById('adminTokenInput');
      const tokenState = document.getElementById('tokenState');
      const resultMeta = document.getElementById('resultMeta');
      const resultView = document.getElementById('resultView');
      const resultRaw = document.getElementById('resultRaw');
      const STATIC_TOOLTIP_TEXT_BY_ID = {
        saveTokenBtn: '토큰 저장: 현재 입력한 X-Admin-Token을 이 브라우저 세션에 저장합니다.',
        testTokenBtn: '연결 테스트: 현재 토큰으로 /api/auth/me를 호출해 권한과 역할을 확인합니다.',
        clearTokenBtn: '토큰 지우기: 저장된 관리자 토큰을 브라우저에서 제거합니다.',
        reportPrintLink: 'HTML 인쇄: 현재 월간리포트를 인쇄 화면으로 엽니다.',
        reportCsvLink: 'CSV 다운로드: 현재 월간리포트를 CSV 파일로 내려받습니다.',
        reportPdfLink: 'PDF 다운로드: 현재 월간리포트를 PDF 파일로 내려받습니다.',
      };
      const PANEL_TOOLTIP_TEXT = {
        serviceInfo: '조회 실행: 서비스 정보 API를 HTML 표 형태로 조회합니다.',
        publicModules: '조회 실행: 공개 모듈 레지스트리를 사람이 읽기 쉬운 표로 조회합니다.',
        authMe: '조회 실행: 현재 토큰의 사용자, 역할, site scope를 확인합니다.',
        inspections: '조회 실행: 점검 목록을 조건별로 조회합니다.',
        workOrders: '조회 실행: 작업지시 목록을 상태와 site 기준으로 조회합니다.',
        dashboardSummary: '조회 실행: 운영 대시보드 요약과 핵심 지표를 조회합니다.',
        alertChannelKpi: '조회 실행: 알림 채널 KPI를 최근 기간 기준으로 조회합니다.',
        alertChannelGuard: '조회 실행: 알림 채널 보호 상태와 guard 현황을 조회합니다.',
        alertRetentionPolicy: '정책 조회: 알림 데이터 보관정책을 조회합니다.',
        alertRetentionLatest: '최근 실행 조회: 최근 알림 보관 정리 작업 결과를 조회합니다.',
        handoverBrief: '조회 실행: 인수인계 브리프를 site 기준으로 조회합니다.',
        monthlyReport: 'JSON 조회: 월간리포트 원본 JSON을 조회합니다.',
        slaPolicy: '조회 실행: SLA 정책을 site 기준으로 조회합니다.',
      };

      const panelDefs = {
        serviceInfo: { path: '/api/service-info', auth: false, params: [] },
        publicModules: { path: '/api/public/modules', auth: false, params: [] },
        authMe: { path: '/api/auth/me', auth: true, params: [] },
        inspections: {
          path: '/api/inspections',
          auth: true,
          params: [
            { key: 'site', id: 'q-inspection-site' },
            { key: 'limit', id: 'q-inspection-limit' },
            { key: 'offset', id: 'q-inspection-offset' }
          ]
        },
        workOrders: {
          path: '/api/work-orders',
          auth: true,
          params: [
            { key: 'status', id: 'q-work-status' },
            { key: 'site', id: 'q-work-site' },
            { key: 'limit', id: 'q-work-limit' },
            { key: 'offset', id: 'q-work-offset' }
          ]
        },
        dashboardSummary: {
          path: '/api/ops/dashboard/summary',
          auth: true,
          params: [
            { key: 'site', id: 'q-dash-site' },
            { key: 'days', id: 'q-dash-days' },
            { key: 'job_limit', id: 'q-dash-jobs' }
          ]
        },
        alertChannelKpi: {
          path: '/api/ops/alerts/kpi/channels',
          auth: true,
          params: [{ key: 'event_type', id: 'q-alert-event-type' }]
        },
        alertChannelGuard: {
          path: '/api/ops/alerts/channels/guard',
          auth: true,
          params: [
            { key: 'event_type', id: 'q-alert-event-type' },
            { key: 'lookback_days', id: 'q-alert-guard-lookback' },
            { key: 'max_targets', id: 'q-alert-guard-max-targets' }
          ]
        },
        alertRetentionPolicy: {
          path: '/api/ops/alerts/retention/policy',
          auth: true,
          params: []
        },
        alertRetentionLatest: {
          path: '/api/ops/alerts/retention/latest',
          auth: true,
          params: []
        },
        handoverBrief: {
          path: '/api/ops/handover/brief',
          auth: true,
          params: [
            { key: 'site', id: 'q-handover-site' },
            { key: 'window_hours', id: 'q-handover-window' },
            { key: 'due_soon_hours', id: 'q-handover-due-soon' },
            { key: 'max_items', id: 'q-handover-max-items' }
          ]
        },
        monthlyReport: {
          path: '/api/reports/monthly',
          auth: true,
          params: [
            { key: 'month', id: 'q-report-month' },
            { key: 'site', id: 'q-report-site' }
          ]
        },
        slaPolicy: {
          path: '/api/admin/policies/sla',
          auth: true,
          params: [{ key: 'site', id: 'q-sla-site' }]
        }
      };

      function escapeHtml(value) {
        return String(value)
          .replaceAll('&', '&amp;')
          .replaceAll('<', '&lt;')
          .replaceAll('>', '&gt;')
          .replaceAll('"', '&quot;')
          .replaceAll("'", '&#39;');
      }

      function setTooltip(element, text) {
        if (!element || !text) return;
        element.setAttribute('data-tip', text);
        element.setAttribute('title', text);
      }

      function applyTooltips() {
        Object.entries(STATIC_TOOLTIP_TEXT_BY_ID).forEach(([id, text]) => {
          setTooltip(document.getElementById(id), text);
        });
        document.querySelectorAll('.run-btn[data-panel]').forEach((btn) => {
          setTooltip(btn, PANEL_TOOLTIP_TEXT[btn.dataset.panel] || '조회 실행: 선택한 패널의 데이터를 조회합니다.');
        });
      }

      function getToken() {
        const keys = Array.from(new Set([TOKEN_KEY].concat(TOKEN_KEY_ALIASES)));
        for (const key of keys) {
          const sessionToken = window.sessionStorage.getItem(key) || '';
          if (!sessionToken) continue;
          if (key !== TOKEN_KEY) {
            window.sessionStorage.setItem(TOKEN_KEY, sessionToken);
            window.sessionStorage.removeItem(key);
          }
          return sessionToken;
        }
        for (const key of keys) {
          const localToken = window.localStorage.getItem(key) || '';
          if (!localToken) continue;
          window.sessionStorage.setItem(TOKEN_KEY, localToken);
          keys.forEach((aliasKey) => window.localStorage.removeItem(aliasKey));
          keys.forEach((aliasKey) => {
            if (aliasKey !== TOKEN_KEY) {
              window.sessionStorage.removeItem(aliasKey);
            }
          });
          return localToken;
        }
        return '';
      }

      function updateTokenState() {
        const token = getToken();
        tokenState.textContent = token
          ? '토큰 상태: 저장됨 (길이 ' + token.length + ')'
          : '토큰 상태: 없음';
      }

      function readInput(id) {
        const node = document.getElementById(id);
        if (!node) return '';
        return (node.value || '').trim();
      }

      function buildPath(def) {
        const params = new URLSearchParams();
        (def.params || []).forEach((item) => {
          const value = readInput(item.id);
          if (value !== '') {
            params.set(item.key, value);
          }
        });
        const query = params.toString();
        return query ? def.path + '?' + query : def.path;
      }

      function renderArray(arr) {
        if (!arr.length) {
          return '<div class="empty">결과 배열이 비어 있습니다.</div>';
        }
        const allObjects = arr.every((item) => item !== null && typeof item === 'object' && !Array.isArray(item));
        if (!allObjects) {
          const list = arr.map((item) => '<li>' + escapeHtml(typeof item === 'object' ? JSON.stringify(item, null, 2) : item) + '</li>').join('');
          return '<ul>' + list + '</ul>';
        }

        const keys = [];
        arr.forEach((row) => {
          Object.keys(row).forEach((key) => {
            if (!keys.includes(key)) keys.push(key);
          });
        });
        const head = keys.map((key) => '<th>' + escapeHtml(key) + '</th>').join('');
        const body = arr.map((row) => {
          const cells = keys.map((key) => {
            const value = row[key];
            if (value === null || value === undefined) return '<td></td>';
            if (typeof value === 'object') return '<td>' + escapeHtml(JSON.stringify(value)) + '</td>';
            return '<td>' + escapeHtml(value) + '</td>';
          }).join('');
          return '<tr>' + cells + '</tr>';
        }).join('');
        return '<table class="arr-table"><thead><tr>' + head + '</tr></thead><tbody>' + body + '</tbody></table>';
      }

      function renderObject(obj) {
        const rows = Object.keys(obj).map((key) => {
          const value = obj[key];
          let valueHtml = '';
          if (Array.isArray(value)) {
            valueHtml = renderArray(value);
          } else if (value !== null && typeof value === 'object') {
            valueHtml = '<pre class="mono">' + escapeHtml(JSON.stringify(value, null, 2)) + '</pre>';
          } else if (value === null || value === undefined) {
            valueHtml = '';
          } else {
            valueHtml = escapeHtml(value);
          }
          return '<tr><th>' + escapeHtml(key) + '</th><td>' + valueHtml + '</td></tr>';
        }).join('');
        return '<table class="kv-table"><tbody>' + rows + '</tbody></table>';
      }

      function renderData(data) {
        if (Array.isArray(data)) return renderArray(data);
        if (data !== null && typeof data === 'object') return renderObject(data);
        if (data === null || data === undefined) return '<div class="empty">결과가 없습니다.</div>';
        return '<pre class="mono">' + escapeHtml(String(data)) + '</pre>';
      }

      async function runPanel(panelId) {
        const def = panelDefs[panelId];
        if (!def) return;
        const path = buildPath(def);
        const headers = { 'Accept': 'application/json' };
        if (def.auth) {
          const token = getToken();
          if (!token) {
            resultMeta.textContent = '인증 필요: 먼저 관리자 토큰을 저장하세요.';
            resultView.innerHTML = '<div class="empty">토큰이 없어 조회를 실행할 수 없습니다.</div>';
            return;
          }
          headers['X-Admin-Token'] = token;
        }

        resultMeta.textContent = '조회 중... ' + path;
        try {
          const res = await fetch(path, { headers });
          const rawText = await res.text();
          let data = rawText;
          try {
            data = JSON.parse(rawText);
          } catch (err) {
            data = rawText;
          }
          resultRaw.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);

          if (!res.ok) {
            resultMeta.textContent = '실패: HTTP ' + res.status + ' | ' + path;
            resultView.innerHTML = renderData(data);
            return;
          }

          resultMeta.textContent = '성공: HTTP ' + res.status + ' | ' + path;
          resultView.innerHTML = renderData(data);
        } catch (err) {
          resultMeta.textContent = '요청 오류: ' + (err && err.message ? err.message : 'unknown error');
          resultView.innerHTML = '<div class="empty">네트워크 또는 런타임 오류가 발생했습니다.</div>';
        }
      }

      function updateReportLinks() {
        const month = readInput('q-report-month');
        const site = readInput('q-report-site');
        const params = new URLSearchParams();
        if (month) params.set('month', month);
        if (site) params.set('site', site);
        const suffix = params.toString() ? '?' + params.toString() : '';
        document.getElementById('reportPrintLink').setAttribute('href', '/reports/monthly/print' + suffix);
        document.getElementById('reportCsvLink').setAttribute('href', '/api/reports/monthly/csv' + suffix);
        document.getElementById('reportPdfLink').setAttribute('href', '/api/reports/monthly/pdf' + suffix);
      }

      document.querySelectorAll('.run-btn').forEach((btn) => {
        btn.addEventListener('click', () => runPanel(btn.dataset.panel));
      });

      document.getElementById('saveTokenBtn').addEventListener('click', () => {
        const token = (tokenInput.value || '').trim();
        if (!token) {
          tokenState.textContent = '토큰 상태: 빈 값은 저장할 수 없습니다.';
          return;
        }
        window.sessionStorage.setItem(TOKEN_KEY, token);
        TOKEN_KEY_ALIASES.forEach((key) => {
          if (key !== TOKEN_KEY) {
            window.sessionStorage.removeItem(key);
          }
          window.localStorage.removeItem(key);
        });
        updateTokenState();
      });

      document.getElementById('clearTokenBtn').addEventListener('click', () => {
        TOKEN_KEY_ALIASES.forEach((key) => {
          window.sessionStorage.removeItem(key);
          window.localStorage.removeItem(key);
        });
        tokenInput.value = '';
        updateTokenState();
      });

      document.getElementById('testTokenBtn').addEventListener('click', () => runPanel('authMe'));
      ['q-report-month', 'q-report-site'].forEach((id) => {
        const node = document.getElementById(id);
        if (node) node.addEventListener('input', updateReportLinks);
      });

      const storedToken = getToken();
      if (storedToken) tokenInput.value = storedToken;
      updateTokenState();
      applyTooltips();
      updateReportLinks();
      runPanel('serviceInfo');
    })();
  </script>
</body>
</html>
"""

    rendered = template
    rendered = rendered.replace("__MODULE_CARDS__", module_cards_html)
    rendered = rendered.replace("__MODULE_COUNT__", str(len(modules)))
    rendered = rendered.replace("__SERVICE_NAME__", html.escape(service_info.get("service", "ka-facility-os")))
    return rendered


def build_facility_console_guide_html(service_info: dict[str, str]) -> str:
    quick_steps = [
        (
            "1) 인증 연결",
            "X-Admin-Token을 입력하고 `토큰 저장`을 누른 뒤 `연결 테스트 (/api/auth/me)`로 현재 역할과 권한이 맞는지 먼저 확인합니다.",
        ),
        (
            "2) 공개 정보로 화면 익히기",
            "`공개: 서비스 정보`와 `공개: 모듈 레지스트리`를 먼저 눌러 화면 구조와 주요 API 경로를 익힙니다.",
        ),
        (
            "3) 점검과 작업지시 확인",
            "`점검 목록`에서 최근 점검을 보고, 이어서 `작업지시 목록`으로 open/acked 상태를 확인합니다. site를 넣으면 현장별로 좁혀 볼 수 있습니다.",
        ),
        (
            "4) 운영 상태 요약 보기",
            "`운영 대시보드 요약`과 `핸드오버 브리프`를 조회해 오늘 처리해야 할 일과 인수인계 이슈를 확인합니다.",
        ),
        (
            "5) 보고서/정책 확인",
            "`월간 감사 리포트`에서 month=`YYYY-MM`을 넣고 JSON 조회 또는 HTML/CSV/PDF 다운로드를 실행합니다. SLA 기준은 `SLA 정책 조회`에서 확인합니다.",
        ),
    ]
    parameter_rows = [
        ("site", "선택값", "아파트/현장 코드. 비워두면 전체 범위를 조회합니다."),
        ("limit", "기본 20", "한 번에 가져올 건수입니다. 신규 사용자는 20으로 유지하는 편이 안전합니다."),
        ("offset", "기본 0", "다음 페이지를 볼 때만 사용합니다."),
        ("status", "선택값", "작업지시 상태. 예: `open`, `acked`."),
        ("days", "기본 30", "대시보드 집계 기간입니다."),
        ("month", "YYYY-MM", "월간 리포트 조회 시 사용합니다."),
    ]
    daily_flow = [
        "1. `연결 테스트 (/api/auth/me)`로 오늘 사용할 토큰 상태를 확인한다.",
        "2. `점검 목록`에서 오늘 점검 데이터가 정상 등록되는지 확인한다.",
        "3. `작업지시 목록`에서 미처리(open) 건과 ACK 대기 건을 확인한다.",
        "4. `운영 대시보드 요약`으로 누락, 지연, 최근 작업 현황을 본다.",
        "5. 교대 직전에는 `핸드오버 브리프`를 열어 인수인계 메모를 정리한다.",
        "6. 월말/월초에는 `월간 감사 리포트`를 조회하고 필요하면 CSV/PDF를 내려받는다.",
    ]
    failure_rows = [
        ("토큰이 없어 조회를 실행할 수 없습니다.", "아직 `토큰 저장`을 하지 않았습니다. 관리자 토큰을 저장한 뒤 다시 실행합니다."),
        ("HTTP 401 또는 403", "토큰이 만료됐거나 권한/site scope가 맞지 않습니다. `/api/auth/me` 결과를 먼저 확인합니다."),
        ("결과 배열이 비어 있습니다.", "조건은 맞지만 현재 데이터가 없습니다. site, status, month, offset 값을 다시 확인합니다."),
        ("월간 리포트가 비어 보입니다.", "month 형식이 `YYYY-MM`인지 확인하고, 해당 월 데이터가 실제로 있는지 점검합니다."),
    ]

    step_cards = "".join(
        f"""
        <article class="card step-card">
          <h3>{html.escape(title)}</h3>
          <p>{html.escape(body)}</p>
        </article>
        """
        for title, body in quick_steps
    )
    parameter_html = "".join(
        f"""
        <tr>
          <th>{html.escape(name)}</th>
          <td>{html.escape(default_value)}</td>
          <td>{html.escape(description)}</td>
        </tr>
        """
        for name, default_value, description in parameter_rows
    )
    daily_html = "".join(f"<li>{html.escape(item)}</li>" for item in daily_flow)
    failure_html = "".join(
        f"""
        <tr>
          <th>{html.escape(message)}</th>
          <td>{html.escape(action)}</td>
        </tr>
        """
        for message, action in failure_rows
    )

    return f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>KA Facility OS - 운영 콘솔 1페이지 시작 가이드</title>
  <style>
    :root {{
      --ink: #10213a;
      --muted: #4d6381;
      --line: #d8e3f0;
      --card: #ffffff;
      --bg: #f3f7ff;
      --brand: #0c6a55;
      --accent: #c9551b;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      font-family: "SUIT", "Pretendard", "IBM Plex Sans KR", "Noto Sans KR", sans-serif;
      background:
        radial-gradient(860px 360px at 0% -20%, #dff5ff 0%, transparent 58%),
        radial-gradient(760px 340px at 100% -20%, #ffeddc 0%, transparent 58%),
        var(--bg);
    }}
    .wrap {{ max-width: 1120px; margin: 0 auto; padding: 18px 14px 48px; }}
    .hero {{
      border: 1px solid var(--line);
      border-radius: 16px;
      background: linear-gradient(145deg, #ffffff 0%, #eef8f5 52%, #fff6eb 100%);
      box-shadow: 0 12px 28px rgba(14, 38, 70, 0.08);
      padding: 16px;
    }}
    .hero h1 {{ margin: 0; font-size: 26px; }}
    .hero p {{ margin: 8px 0 0; color: var(--muted); font-size: 14px; line-height: 1.6; }}
    .hero-links {{
      margin-top: 12px;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .hero-links a {{
      text-decoration: none;
      border: 1px solid #b7cde7;
      border-radius: 999px;
      padding: 6px 10px;
      font-size: 12px;
      font-weight: 800;
      color: #1f4e7d;
      background: #f3f8ff;
    }}
    .grid {{
      margin-top: 14px;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
      align-items: start;
    }}
    .card {{
      border: 1px solid var(--line);
      border-radius: 14px;
      background: var(--card);
      padding: 14px;
    }}
    .card h2 {{
      margin: 0 0 10px;
      font-size: 18px;
      border-left: 4px solid var(--accent);
      padding-left: 8px;
    }}
    .card h3 {{
      margin: 0 0 8px;
      font-size: 15px;
      color: var(--brand);
    }}
    .card p, .card li {{
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
    }}
    .step-grid {{
      display: grid;
      grid-template-columns: 1fr;
      gap: 10px;
    }}
    .step-card {{
      background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
    }}
    .table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }}
    .table th, .table td {{
      border-bottom: 1px solid #e8eff8;
      text-align: left;
      padding: 8px;
      vertical-align: top;
      word-break: break-word;
    }}
    .table th {{
      background: #f6f9ff;
      color: #24486d;
    }}
    .callout {{
      margin-top: 10px;
      border: 1px solid #cce0cf;
      border-radius: 12px;
      background: #eefaf4;
      padding: 10px 12px;
      color: #245345;
      font-size: 13px;
      line-height: 1.6;
    }}
    code {{
      font-family: "Consolas", "D2Coding", "IBM Plex Mono", monospace;
      font-size: 12px;
      background: #f3f7ff;
      border: 1px solid #d7e3f1;
      border-radius: 6px;
      padding: 1px 5px;
      color: #1e446e;
    }}
    ul, ol {{ margin: 0; padding-left: 20px; }}
    @media (max-width: 900px) {{
      .grid {{ grid-template-columns: 1fr; }}
      .hero h1 {{ font-size: 22px; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <header class="hero">
      <h1>운영 콘솔 1페이지 시작 가이드</h1>
      <p>서비스: {html.escape(service_info.get("service", "ka-facility-os"))} | 신규 사용자가 <code>/web/console</code>에서 로그인 확인, 점검 조회, 작업지시 확인, 월간 리포트 조회까지 5분 안에 따라 할 수 있도록 정리한 운영용 안내입니다.</p>
      <div class="hero-links">
        <a href="/web/console">운영 콘솔 열기</a>
        <a href="/">메인 운영 셸</a>
        <a href="/web/tutorial-simulator">튜토리얼 화면</a>
        <a href="/api/service-info">서비스 정보 API</a>
      </div>
    </header>

    <section class="grid">
      <article class="card">
        <h2>5분 시작 순서</h2>
        <div class="step-grid">
          {step_cards}
        </div>
        <div class="callout">
          처음 접속했을 때는 결과 패널이 자동으로 <code>공개: 서비스 정보</code>를 보여줍니다. 이 단계에서 화면이 정상 열리는지만 먼저 확인하면 됩니다.
        </div>
      </article>

      <article class="card">
        <h2>입력값 읽는 법</h2>
        <table class="table">
          <thead>
            <tr><th>필드</th><th>기본값</th><th>사용 기준</th></tr>
          </thead>
          <tbody>
            {parameter_html}
          </tbody>
        </table>
        <div class="callout">
          신규 사용자는 먼저 <code>site</code>를 비워 전체 조회를 해보고, 결과가 많을 때만 site를 넣어 좁히는 방식이 안전합니다.
        </div>
      </article>

      <article class="card">
        <h2>일일 운영 권장 순서</h2>
        <ol>
          {daily_html}
        </ol>
      </article>

      <article class="card">
        <h2>자주 보는 오류와 조치</h2>
        <table class="table">
          <thead>
            <tr><th>화면 메시지</th><th>바로 할 일</th></tr>
          </thead>
          <tbody>
            {failure_html}
          </tbody>
        </table>
      </article>
    </section>
  </div>
</body>
</html>
"""

def build_public_modules_html(modules_payload: dict[str, Any]) -> str:
    modules = modules_payload.get("modules", [])
    cards: list[str] = []
    for item in modules:
        links_html = "".join(
            f'<a href="{html.escape(str(link.get("href", "#")))}">{html.escape(str(link.get("label", "Open")))}'
            "</a>"
            for link in item.get("links", [])
        )
        cards.append(
            f"""
            <article class="module-card">
              <h3>{html.escape(str(item.get("name_ko", "")))}</h3>
              <p class="en">{html.escape(str(item.get("name", "")))}</p>
              <p class="desc">{html.escape(str(item.get("description", "")))}</p>
              <p class="hint"><strong>KPI Hint:</strong> {html.escape(str(item.get("kpi_hint", "")))}</p>
              <div class="links">{links_html}</div>
            </article>
            """
        )

    cards_html = "".join(cards) or "<p>등록된 모듈이 없습니다.</p>"
    return f"""
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>KA Facility OS - 공개 모듈</title>
  <style>
    :root {{
      --ink: #0f1f37;
      --muted: #49617f;
      --line: #d5e0ef;
      --bg: #f4f8ff;
      --card: #fff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      font-family: "SUIT", "Pretendard", "IBM Plex Sans KR", "Noto Sans KR", sans-serif;
      background:
        radial-gradient(820px 320px at 10% -20%, #dff6ff 0%, transparent 58%),
        radial-gradient(740px 320px at 95% -20%, #ffecd8 0%, transparent 58%),
        var(--bg);
    }}
    .wrap {{ max-width: 1200px; margin: 0 auto; padding: 18px 14px 48px; }}
    .hero {{
      border: 1px solid var(--line);
      border-radius: 14px;
      background: linear-gradient(145deg, #fff 0%, #eef8f5 52%, #fff4e8 100%);
      padding: 14px;
      box-shadow: 0 10px 24px rgba(15, 35, 63, 0.08);
    }}
    .hero h1 {{ margin: 0; font-size: 24px; }}
    .hero p {{ margin: 7px 0 0; color: var(--muted); font-size: 14px; }}
    .hero-links {{ margin-top: 10px; display: flex; flex-wrap: wrap; gap: 7px; }}
    .hero-links a {{
      text-decoration: none;
      font-size: 12px;
      border: 1px solid #b7cde7;
      border-radius: 999px;
      padding: 6px 10px;
      color: #1f4d7c;
      background: #f3f8ff;
      font-weight: 700;
    }}
    .grid {{
      margin-top: 14px;
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }}
    .module-card {{
      border: 1px solid var(--line);
      border-radius: 12px;
      background: var(--card);
      padding: 12px;
    }}
    .module-card h3 {{ margin: 0; font-size: 15px; color: #0c654f; }}
    .module-card .en {{ margin: 4px 0 8px; font-size: 12px; color: #3e5f84; font-weight: 700; }}
    .module-card .desc {{ margin: 0; color: var(--muted); font-size: 12px; }}
    .module-card .hint {{ margin: 8px 0 0; color: #264d77; font-size: 12px; }}
    .module-card .links {{
      margin-top: 8px;
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }}
    .module-card .links a {{
      text-decoration: none;
      border: 1px solid #bdd2eb;
      border-radius: 8px;
      padding: 5px 8px;
      font-size: 11px;
      font-weight: 700;
      color: #245281;
      background: #f3f8ff;
    }}
    @media (max-width: 900px) {{
      .grid {{ grid-template-columns: 1fr; }}
      .hero h1 {{ font-size: 20px; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <header class="hero">
      <h1>시설 웹 모듈</h1>
      <p>브라우저에서 API JSON 대신 사람이 읽기 쉬운 모듈 카드 화면입니다.</p>
      <div class="hero-links">
        <a href="/">공개 메인</a>
        <a href="/web/console">운영 콘솔</a>
        <a href="/api/public/modules">동일 URL (JSON/HTML)</a>
      </div>
    </header>
    <section class="grid">
      {cards_html}
    </section>
  </div>
</body>
</html>
"""
