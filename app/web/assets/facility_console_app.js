    (function() {
      const TOKEN_KEY = 'kaFacility.auth.token';
      const TOKEN_KEY_ALIASES = ['kaFacility.auth.token', 'kaFacilityAdminToken', 'kaFacilityMainToken', 'kaFacility.complaints.token'];
      const PROFILE_KEY = 'kaFacility.auth.profile';
      const tokenInput = document.getElementById('adminTokenInput');
      const tokenState = document.getElementById('tokenState');
      const resultMeta = document.getElementById('resultMeta');
      const resultView = document.getElementById('resultView');
      const resultRaw = document.getElementById('resultRaw');
      let authProfile = null;
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

      function persistToken(token) {
        const normalized = String(token || '').trim();
        if (!normalized) return;
        const keys = Array.from(new Set([TOKEN_KEY].concat(TOKEN_KEY_ALIASES)));
        window.sessionStorage.setItem(TOKEN_KEY, normalized);
        keys.forEach((key) => {
          if (key !== TOKEN_KEY) {
            window.sessionStorage.removeItem(key);
          }
          window.localStorage.removeItem(key);
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

      function getStoredAuthProfile() {
        const raw = window.sessionStorage.getItem(PROFILE_KEY) || window.localStorage.getItem(PROFILE_KEY) || '';
        if (!raw) return null;
        try {
          const parsed = JSON.parse(raw);
          if (parsed && typeof parsed === 'object') {
            window.sessionStorage.setItem(PROFILE_KEY, JSON.stringify(parsed));
            window.localStorage.removeItem(PROFILE_KEY);
            return parsed;
          }
        } catch (err) {
          window.sessionStorage.removeItem(PROFILE_KEY);
          window.localStorage.removeItem(PROFILE_KEY);
        }
        return null;
      }

      function persistAuthProfile(profile) {
        if (!profile) {
          window.sessionStorage.removeItem(PROFILE_KEY);
          window.localStorage.removeItem(PROFILE_KEY);
          return;
        }
        window.sessionStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
        window.localStorage.removeItem(PROFILE_KEY);
      }

      function clearStoredAuth(options = {}) {
        const keys = Array.from(new Set([TOKEN_KEY].concat(TOKEN_KEY_ALIASES)));
        keys.forEach((key) => {
          window.sessionStorage.removeItem(key);
          window.localStorage.removeItem(key);
        });
        persistAuthProfile(null);
        authProfile = null;
        if (!options.preserveInput) {
          tokenInput.value = '';
        }
      }

      function updateTokenState() {
        const token = getToken();
        if (!token) {
          authProfile = null;
          persistAuthProfile(null);
          tokenState.textContent = '토큰 상태: 없음';
          return;
        }
        if (!authProfile) {
          authProfile = getStoredAuthProfile();
        }
        if (authProfile) {
          const siteScope = Array.isArray(authProfile.site_scope) && authProfile.site_scope.length
            ? authProfile.site_scope.join(', ')
            : '*';
          tokenState.textContent = '토큰 상태: 확인됨 | 사용자 ' + String(authProfile.username || '-') + ' | 역할 ' + String(authProfile.role || '-') + ' | 범위 ' + siteScope;
          return;
        }
        tokenState.textContent = '토큰 상태: 저장됨 (권한 확인 전)';
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
            if (def.auth && res.status === 401) {
              clearStoredAuth({ preserveInput: true });
              updateTokenState();
            }
            resultMeta.textContent = '실패: HTTP ' + res.status + ' | ' + path;
            resultView.innerHTML = renderData(data);
            return;
          }

          if (panelId === 'authMe' && data && typeof data === 'object') {
            authProfile = data;
            persistAuthProfile(authProfile);
            updateTokenState();
          }
          resultMeta.textContent = '성공: HTTP ' + res.status + ' | ' + path;
          resultView.innerHTML = renderData(data);
        } catch (err) {
          if (panelId === 'authMe') {
            authProfile = null;
            persistAuthProfile(null);
            updateTokenState();
          }
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

      document.getElementById('saveTokenBtn').addEventListener('click', async () => {
        const token = (tokenInput.value || '').trim();
        if (!token) {
          tokenState.textContent = '토큰 상태: 빈 값은 저장할 수 없습니다.';
          return;
        }
        persistToken(token);
        authProfile = null;
        persistAuthProfile(null);
        updateTokenState();
        await runPanel('authMe');
      });

      document.getElementById('clearTokenBtn').addEventListener('click', () => {
        clearStoredAuth();
        updateTokenState();
      });

      document.getElementById('testTokenBtn').addEventListener('click', () => runPanel('authMe'));
      ['q-report-month', 'q-report-site'].forEach((id) => {
        const node = document.getElementById(id);
        if (node) node.addEventListener('input', updateReportLinks);
      });

      authProfile = getStoredAuthProfile();
      const storedToken = getToken();
      if (storedToken) tokenInput.value = storedToken;
      updateTokenState();
      if (storedToken && !authProfile) {
        runPanel('authMe');
      }
      applyTooltips();
      updateReportLinks();
      runPanel('serviceInfo');
    })();
