"""Tutorial simulator HTML renderer extracted from app.main."""

from __future__ import annotations

import json
from typing import Any


def build_tutorial_simulator_html(payload: dict[str, Any]) -> str:
    payload_json = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    html_doc = """
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>KA Facility OS Tutorial Simulator</title>
  <style>
    :root { --bg:#edf4ff; --panel:#fff; --line:#c7d8ed; --ink:#112741; --muted:#456583; --ok:#0f6754; --warn:#9a6019; --err:#9b2d2d; }
    * { box-sizing: border-box; }
    body { margin:0; background: radial-gradient(900px 360px at 0% -20%, #dff2ff 0%, transparent 60%), radial-gradient(780px 320px at 100% -18%, #fbeed8 0%, transparent 60%), var(--bg); color:var(--ink); font-family:"SUIT","Pretendard","Noto Sans KR",sans-serif; }
    .wrap { max-width:1220px; margin:0 auto; padding:18px 14px 56px; display:grid; gap:12px; }
    .card { background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:14px; box-shadow:0 10px 24px rgba(11,34,59,.08); }
    .hero { background:linear-gradient(145deg,#fff 0%,#edf6ff 58%,#eef9f4 100%); }
    h1 { margin:0; font-size:25px; } h2 { margin:0 0 8px; font-size:18px; }
    .caption { margin:6px 0 0; color:var(--muted); font-size:13px; }
    .links { margin-top:10px; display:flex; flex-wrap:wrap; gap:8px; }
    .links a { text-decoration:none; border:1px solid #b9cde9; background:#eef5ff; color:#215080; border-radius:999px; padding:6px 10px; font-size:12px; font-weight:800; }
    .row { display:grid; grid-template-columns:1fr 1fr 1fr auto; gap:8px; margin-top:8px; }
    .grid2 { display:grid; grid-template-columns:1.08fr 1fr; gap:12px; }
    .grid3 { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:8px; }
    input, select { width:100%; border:1px solid var(--line); border-radius:10px; padding:8px 10px; font-size:13px; color:var(--ink); background:#fff; }
    .btn { border:1px solid #95bbdf; border-radius:10px; background:#edf6ff; color:#214f7d; padding:8px 10px; font-size:12px; font-weight:800; cursor:pointer; white-space:nowrap; }
    .btn.run { border-color:#86cab7; background:#e8f8f2; color:#0d604f; }
    .btn.warn { border-color:#d8b98d; background:#fff5e8; color:#8e5a15; }
    .status { margin-top:8px; border:1px solid #c8d9ef; border-radius:10px; padding:8px 10px; font-size:12px; color:#264c76; background:#eef5ff; }
    .status[data-kind="ok"] { border-color:#9fd2c1; background:#ebfaf3; color:var(--ok); }
    .status[data-kind="warning"] { border-color:#dbbe92; background:#fff5e8; color:var(--warn); }
    .status[data-kind="error"] { border-color:#e3b0b0; background:#fff1f1; color:var(--err); }
    .chips { margin-top:8px; display:flex; flex-wrap:wrap; gap:8px; }
    .chips span { border:1px solid #b9cde9; border-radius:999px; background:#eef5ff; color:#275079; padding:4px 8px; font-size:12px; font-weight:700; }
    .box { margin-top:8px; border:1px dashed #c7d8ed; border-radius:10px; padding:8px; background:#fbfdff; overflow:auto; }
    .empty { border:1px dashed #c7d8ed; border-radius:10px; padding:16px 10px; text-align:center; color:var(--muted); font-size:13px; background:#fbfdff; margin-top:8px; }
    table { width:100%; border-collapse:collapse; font-size:12px; }
    th, td { border:1px solid var(--line); padding:7px 8px; text-align:left; vertical-align:top; }
    th { background:#edf5ff; }
    ol { margin:8px 0 0; padding-left:18px; color:#27507a; font-size:13px; } li+li { margin-top:4px; }
    .mono { margin-top:8px; border:1px solid #d5e2f3; border-radius:10px; background:#f6fbff; padding:10px; max-height:320px; overflow:auto; white-space:pre-wrap; font-family:"Consolas","D2Coding","IBM Plex Mono",monospace; font-size:12px; color:#1f4c77; }
    @media (max-width: 980px) { .grid2 { grid-template-columns:1fr; } .grid3 { grid-template-columns:1fr 1fr; } .row { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <main class="wrap">
    <section class="card hero">
      <h1>KA Facility OS Tutorial Simulator</h1>
      <p class="caption">검증 샘플데이터/파일 기반으로 신규 사용자가 실습 실행부터 완료판정까지 한 화면에서 진행할 수 있습니다.</p>
      <div class="links">
        <a href="/api/public/tutorial-simulator">튜토리얼 JSON API</a>
        <a href="/api/public/tutorial-simulator/sample-files">샘플 파일 API</a>
        <a href="/api/public/modules">시설 모듈</a>
        <a href="/web/console">운영 콘솔</a>
      </div>
      <div class="chips">
        <span id="chipValidatedOn">validated_on: -</span>
        <span id="chipDefaultSite">default_site: -</span>
        <span id="chipDod">DoD: -</span>
      </div>
    </section>

    <section class="card">
      <h2>1) 토큰 연결</h2>
      <div class="row">
        <input id="tokenInput" type="password" placeholder="X-Admin-Token" autocomplete="off" />
        <button id="saveTokenBtn" class="btn" type="button">토큰 저장</button>
        <button id="testTokenBtn" class="btn run" type="button">권한 확인</button>
        <button id="clearTokenBtn" class="btn" type="button">토큰 지우기</button>
      </div>
      <div id="statusBox" class="status">토큰 상태: 없음</div>
    </section>

    <section class="grid2">
      <article class="card">
        <h2>2) 검증 샘플 파일</h2>
        <p class="caption">실습 요청 바디(JSON)와 체크리스트 파일을 내려받아 동일 조건으로 훈련할 수 있습니다.</p>
        <div id="sampleFiles" class="box"></div>
      </article>
      <article class="card">
        <h2>3) 세션 실습 실행</h2>
        <div class="row">
          <select id="scenarioSelect"></select>
          <input id="siteInput" placeholder="site" />
          <button id="startSessionBtn" class="btn run" type="button">세션 시작</button>
          <button id="reloadSessionBtn" class="btn" type="button">세션 조회</button>
        </div>
        <div class="row">
          <input id="sessionIdInput" placeholder="session_id (자동채움)" />
          <input id="assigneeInput" value="Ops Trainee" placeholder="담당자" />
          <input id="resolutionInput" value="Tutorial completion" placeholder="resolution_notes" />
          <button id="listSessionsBtn" class="btn" type="button">최근 세션</button>
        </div>
        <div class="row">
          <button id="ackBtn" class="btn run" type="button">ACK 실행</button>
          <button id="completeBtn" class="btn run" type="button">COMPLETE 실행</button>
          <button id="checkBtn" class="btn" type="button">완료 판정</button>
          <button id="resetBtn" class="btn warn" type="button">RESET</button>
        </div>
        <div id="sessionMeta" class="status">세션 정보: 없음</div>
      </article>
    </section>

    <section class="card">
      <h2>4) 신규 사용자 빠른 순서</h2>
      <ol id="quickstart"></ol>
    </section>

    <section class="card">
      <h2>5) 현재 세션 진행률</h2>
      <div class="grid3">
        <div id="summarySession" class="status">Session: -</div>
        <div id="summaryProgress" class="status">Progress: -</div>
        <div id="summarySeed" class="status">Seed IDs: -</div>
      </div>
      <div id="stepsTable" class="box"></div>
    </section>

    <section class="card">
      <h2>6) 최근 세션 목록</h2>
      <div id="sessionsTable" class="box"></div>
    </section>

    <section class="card">
      <h2>결과 JSON</h2>
      <pre id="resultJson" class="mono">{}</pre>
    </section>
  </main>

  <script>
    (function () {
      const payload = __TUTORIAL_PAYLOAD_JSON__;
      const TOKEN_KEY = "kaTutorialSimulatorToken";
      const tokenInput = document.getElementById("tokenInput");
      const statusBox = document.getElementById("statusBox");
      const scenarioSelect = document.getElementById("scenarioSelect");
      const siteInput = document.getElementById("siteInput");
      const sessionIdInput = document.getElementById("sessionIdInput");
      const assigneeInput = document.getElementById("assigneeInput");
      const resolutionInput = document.getElementById("resolutionInput");
      const sampleFiles = document.getElementById("sampleFiles");
      const sessionsTable = document.getElementById("sessionsTable");
      const stepsTable = document.getElementById("stepsTable");
      const sessionMeta = document.getElementById("sessionMeta");
      const resultJson = document.getElementById("resultJson");

      function esc(v) { return String(v == null ? "" : v).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;"); }
      function token() { return String(window.sessionStorage.getItem(TOKEN_KEY) || ""); }
      function setToken(v) { if (v) window.sessionStorage.setItem(TOKEN_KEY, v); else window.sessionStorage.removeItem(TOKEN_KEY); }
      function setStatus(kind, msg) { statusBox.dataset.kind = kind || "info"; statusBox.textContent = msg; }
      function setResult(data) { try { resultJson.textContent = JSON.stringify(data, null, 2); } catch { resultJson.textContent = String(data); } }
      function headers() { const h = { Accept: "application/json" }; const t = token(); if (t) h["X-Admin-Token"] = t; return h; }
      function errText(d) { if (d == null) return ""; if (typeof d === "string") return d; if (Array.isArray(d)) return d.map((x) => typeof x === "string" ? x : JSON.stringify(x)).join(" | "); if (typeof d === "object" && d.detail != null) return errText(d.detail); try { return JSON.stringify(d); } catch { return String(d); } }
      async function req(method, url, body) {
        const h = headers();
        const init = { method, headers: h };
        if (body !== undefined) { h["Content-Type"] = "application/json"; init.body = JSON.stringify(body); }
        const r = await fetch(url, init);
        const txt = await r.text();
        let data = null;
        if (txt) { try { data = JSON.parse(txt); } catch { data = txt; } }
        if (!r.ok) throw new Error(`HTTP ${r.status} | ${errText(data) || r.statusText}`);
        return data;
      }
      function sid() { const v = Number((sessionIdInput.value || "").trim()); if (!Number.isFinite(v) || v <= 0) throw new Error("session_id를 먼저 설정하세요."); return Math.trunc(v); }
      function urlSession(id) { return String(payload.session_lookup_api || "").replace("{session_id}", String(id)); }
      function urlCheck(id) { return String(payload.session_check_api || "").replace("{session_id}", String(id)); }
      function urlAction(id, a) { return String(payload.session_action_api || "").replace("{session_id}", String(id)).replace("{action}", String(a)); }

      function renderBasics() {
        document.getElementById("chipValidatedOn").textContent = "validated_on: " + String(payload.validated_on || "-");
        document.getElementById("chipDefaultSite").textContent = "default_site: " + String(payload.default_site || "-");
        document.getElementById("chipDod").textContent = "DoD: " + String((payload.quickstart || {}).definition_of_done || "-");
        const qs = Array.isArray((payload.quickstart || {}).steps) ? payload.quickstart.steps : [];
        document.getElementById("quickstart").innerHTML = qs.length ? qs.map((x) => `<li>${esc(x)}</li>`).join("") : "<li>가이드 없음</li>";
        const scenarios = Array.isArray(payload.scenarios) ? payload.scenarios : [];
        scenarioSelect.innerHTML = scenarios.length ? scenarios.map((s) => `<option value="${esc(s.id || "")}">${esc(s.name_ko || s.name || s.id || "")} (${Number(s.estimated_minutes || 0)}m)</option>`).join("") : '<option value="">(no scenarios)</option>';
        siteInput.value = String(payload.default_site || "Tutorial-HQ");
      }

      function renderSampleFiles() {
        const items = Array.isArray(payload.sample_files) ? payload.sample_files : [];
        if (!items.length) { sampleFiles.innerHTML = '<div class="empty">샘플 파일 없음</div>'; return; }
        const rows = items.map((i) => "<tr>"
          + `<td>${esc(i.sample_id || "")}</td>`
          + `<td>${esc(i.title || "")}</td>`
          + `<td>${esc(i.scenario_id || "")}</td>`
          + `<td>${esc(i.file_name || "")}</td>`
          + `<td><a href="${esc(i.download_url || "#")}" target="_blank" rel="noopener">다운로드</a></td>`
          + "</tr>").join("");
        sampleFiles.innerHTML = '<table><thead><tr><th>sample_id</th><th>title</th><th>scenario</th><th>file</th><th>download</th></tr></thead><tbody>' + rows + "</tbody></table>";
      }

      function renderSession(session) {
        if (!session || typeof session !== "object") {
          sessionMeta.textContent = "세션 정보: 없음";
          document.getElementById("summarySession").textContent = "Session: -";
          document.getElementById("summaryProgress").textContent = "Progress: -";
          document.getElementById("summarySeed").textContent = "Seed IDs: -";
          stepsTable.innerHTML = '<div class="empty">세션 단계 데이터 없음</div>';
          return;
        }
        const p = session.progress || {};
        const seed = session.seed || {};
        const sidValue = Number(session.session_id || 0);
        sessionIdInput.value = sidValue > 0 ? String(sidValue) : "";
        sessionMeta.textContent = "세션 정보: scenario=" + String((session.scenario || {}).id || "-") + " | site=" + String(session.site || "-") + " | " + String(p.status || "-") + " | " + String(p.completion_percent || 0) + "%";
        document.getElementById("summarySession").textContent = "Session: " + (sidValue > 0 ? String(sidValue) : "-");
        document.getElementById("summaryProgress").textContent = "Progress: " + String(p.status || "-") + " (" + String(p.completion_percent || 0) + "%)";
        document.getElementById("summarySeed").textContent = "Seed IDs: inspection=" + String(seed.inspection_id || "-") + ", work_order=" + String(seed.work_order_id || "-");
        const steps = Array.isArray(session.steps) ? session.steps : [];
        if (!steps.length) { stepsTable.innerHTML = '<div class="empty">세션 단계 데이터 없음</div>'; setResult(session); return; }
        const rows = steps.map((s) => {
          const obs = s && typeof s.observed === "object" ? s.observed : {};
          const obsTxt = Object.entries(obs).map(([k, v]) => `${k}=${v}`).join(", ");
          return "<tr>"
            + `<td>${esc(s.id || "")}</td>`
            + `<td>${esc(s.name_ko || s.name || "")}</td>`
            + `<td>${s.completed ? "완료" : "진행중"}</td>`
            + `<td>${esc(obsTxt || "-")}</td>`
            + "</tr>";
        }).join("");
        stepsTable.innerHTML = '<table><thead><tr><th>step_id</th><th>단계</th><th>상태</th><th>관측값</th></tr></thead><tbody>' + rows + "</tbody></table>";
        setResult(session);
      }

      async function startSession() {
        const scenarioId = String(scenarioSelect.value || "ts-core-01");
        const site = String((siteInput.value || payload.default_site || "Tutorial-HQ")).trim() || "Tutorial-HQ";
        const data = await req("POST", String(payload.session_start_api || "/api/ops/tutorial-simulator/sessions/start"), { scenario_id: scenarioId, site });
        renderSession(data);
        setStatus("ok", "세션 시작 성공");
        await listSessions();
      }
      async function loadSession() { const data = await req("GET", urlSession(sid())); renderSession(data); setStatus("ok", "세션 조회 성공"); }
      async function checkSession() { const data = await req("POST", urlCheck(sid())); renderSession(data); setStatus("ok", "완료 판정 성공"); }
      async function runAction(action) {
        const body = action === "ack_work_order" ? { assignee: String(assigneeInput.value || "Ops Trainee").trim() || "Ops Trainee" } :
          action === "complete_work_order" ? { resolution_notes: String(resolutionInput.value || "Tutorial completion").trim() || "Tutorial completion" } : {};
        const data = await req("POST", urlAction(sid(), action), body);
        if (data && typeof data.session === "object") renderSession(data.session); else setResult(data);
        setStatus("ok", "액션 실행 성공 | " + action);
        await listSessions();
      }
      async function listSessions() {
        const data = await req("GET", String(payload.session_list_api || "/api/ops/tutorial-simulator/sessions") + "?limit=10");
        const items = Array.isArray(data.items) ? data.items : [];
        if (!items.length) { sessionsTable.innerHTML = '<div class="empty">최근 세션 없음</div>'; setResult(data); return; }
        const rows = items.map((x) => "<tr>"
          + `<td><button class="btn pick-session" data-session-id="${Number(x.session_id || 0)}" type="button">${Number(x.session_id || 0)}</button></td>`
          + `<td>${esc(x.scenario_id || "")}</td>`
          + `<td>${esc(x.site || "")}</td>`
          + `<td>${esc(x.work_order_id || "")}</td>`
          + `<td>${esc(x.created_at || "")}</td>`
          + "</tr>").join("");
        sessionsTable.innerHTML = '<table><thead><tr><th>session_id</th><th>scenario</th><th>site</th><th>work_order_id</th><th>created_at</th></tr></thead><tbody>' + rows + "</tbody></table>";
        setResult(data);
      }

      function bind() {
        document.getElementById("saveTokenBtn").addEventListener("click", () => {
          const v = String(tokenInput.value || "").trim();
          if (!v) { setStatus("warning", "빈 토큰은 저장할 수 없습니다."); return; }
          setToken(v);
          setStatus("ok", "토큰 저장 완료 (sessionStorage)");
        });
        document.getElementById("clearTokenBtn").addEventListener("click", () => {
          setToken("");
          tokenInput.value = "";
          setStatus("info", "토큰 제거 완료");
        });
        document.getElementById("testTokenBtn").addEventListener("click", async () => {
          try {
            const me = await req("GET", "/api/auth/me");
            setStatus("ok", "권한 확인 성공 | 사용자: " + String(me.username || "-") + " | 역할: " + String(me.role || "-"));
            setResult(me);
          } catch (err) {
            setStatus("error", "권한 확인 실패 | " + String(err && err.message ? err.message : err));
          }
        });
        document.getElementById("startSessionBtn").addEventListener("click", async () => { try { await startSession(); } catch (err) { setStatus("error", "세션 시작 실패 | " + String(err.message || err)); } });
        document.getElementById("reloadSessionBtn").addEventListener("click", async () => { try { await loadSession(); } catch (err) { setStatus("error", "세션 조회 실패 | " + String(err.message || err)); } });
        document.getElementById("listSessionsBtn").addEventListener("click", async () => { try { await listSessions(); } catch (err) { setStatus("error", "최근 세션 조회 실패 | " + String(err.message || err)); } });
        document.getElementById("checkBtn").addEventListener("click", async () => { try { await checkSession(); } catch (err) { setStatus("error", "완료 판정 실패 | " + String(err.message || err)); } });
        document.getElementById("ackBtn").addEventListener("click", async () => { try { await runAction("ack_work_order"); } catch (err) { setStatus("error", "ACK 실패 | " + String(err.message || err)); } });
        document.getElementById("completeBtn").addEventListener("click", async () => { try { await runAction("complete_work_order"); } catch (err) { setStatus("error", "COMPLETE 실패 | " + String(err.message || err)); } });
        document.getElementById("resetBtn").addEventListener("click", async () => { try { await runAction("reset_work_order"); } catch (err) { setStatus("error", "RESET 실패 | " + String(err.message || err)); } });
        sessionsTable.addEventListener("click", (event) => {
          const btn = event.target.closest(".pick-session");
          if (!btn) return;
          const sidValue = String(btn.getAttribute("data-session-id") || "").trim();
          if (!sidValue) return;
          sessionIdInput.value = sidValue;
          loadSession().catch((err) => setStatus("error", "세션 조회 실패 | " + String(err.message || err)));
        });
      }

      renderBasics();
      renderSampleFiles();
      renderSession(null);
      bind();
      const t = token();
      if (t) {
        tokenInput.value = t;
        setStatus("info", "토큰 상태: 저장됨 (권한 확인 전)");
      } else {
        setStatus("info", "토큰 상태: 없음");
      }
    })();
  </script>
</body>
</html>
"""
    return html_doc.replace("__TUTORIAL_PAYLOAD_JSON__", payload_json)
