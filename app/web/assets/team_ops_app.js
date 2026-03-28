const STORAGE_KEYS = {
  token: 'kaFacility.auth.token',
  site: 'kaFacility.teamOps.site',
};
const TOKEN_STORAGE_KEYS = ['kaFacility.auth.token', 'kaFacilityAdminToken', 'kaFacilityMainToken', 'kaFacility.complaints.token', 'kaFacility.teamOps.token'];
const AUTH_PROFILE_KEY = 'kaFacility.auth.profile';
const LOG_CATEGORY_LABELS = { electrical: '전기', mechanical: '기계', fire: '소방', plumbing: '설비', civil: '건축', general: '기타' };
const LOG_STATUS_LABELS = { planned: '점검예정', in_progress: '진행중', completed: '완료', blocked: '보류' };
const LOG_PRIORITY_LABELS = { low: '낮음', medium: '보통', high: '높음', critical: '긴급' };
const INVENTORY_KIND_LABELS = { tool: '공구', material: '자재', spare: '예비품', consumable: '소모품' };
const INVENTORY_STATUS_LABELS = { normal: '정상', needs_check: '점검필요', low_stock: '부족', out_of_stock: '품절' };

const state = {
  dashboard: null,
  logs: [],
  facilities: [],
  inventory: [],
  activeTab: 'logs',
  selectedLogId: null,
  selectedFacilityId: null,
  selectedInventoryId: null,
};

let tokenHideTimer = null;

const elements = {
  noticeBar: document.getElementById('noticeBar'),
  token: document.getElementById('token'),
  siteFilter: document.getElementById('siteFilter'),
  refreshAllBtn: document.getElementById('refreshAllBtn'),
  savePrefsBtn: document.getElementById('savePrefsBtn'),
  checkConnectionBtn: document.getElementById('checkConnectionBtn'),
  toggleTokenVisibilityBtn: document.getElementById('toggleTokenVisibilityBtn'),
  clearPrefsBtn: document.getElementById('clearPrefsBtn'),
  sessionStatus: document.getElementById('sessionStatus'),
  rangeKey: document.getElementById('rangeKey'),
  refreshDashboardBtn: document.getElementById('refreshDashboardBtn'),
  dashboardMeta: document.getElementById('dashboardMeta'),
  statWorkOrders: document.getElementById('statWorkOrders'),
  statComplaints: document.getElementById('statComplaints'),
  statDocs: document.getElementById('statDocs'),
  categoryList: document.getElementById('categoryList'),
  quickLinks: document.getElementById('quickLinks'),
  heroLogTotal: document.getElementById('heroLogTotal'),
  heroLogActive: document.getElementById('heroLogActive'),
  heroInventoryAttention: document.getElementById('heroInventoryAttention'),
  heroLogCompleted: document.getElementById('heroLogCompleted'),
  workspaceMeta: document.getElementById('workspaceMeta'),
  logsTabBtn: document.getElementById('logsTabBtn'),
  facilitiesTabBtn: document.getElementById('facilitiesTabBtn'),
  inventoryTabBtn: document.getElementById('inventoryTabBtn'),
  reportsTabBtn: document.getElementById('reportsTabBtn'),
  logsWorkspace: document.getElementById('logsWorkspace'),
  facilitiesWorkspace: document.getElementById('facilitiesWorkspace'),
  inventoryWorkspace: document.getElementById('inventoryWorkspace'),
  reportsWorkspace: document.getElementById('reportsWorkspace'),
  reportsMeta: document.getElementById('reportsMeta'),
  reportSummaryList: document.getElementById('reportSummaryList'),
  reportQuickLinks: document.getElementById('reportQuickLinks'),
  logsMeta: document.getElementById('logsMeta'),
  logsSearch: document.getElementById('logsSearch'),
  logsLimit: document.getElementById('logsLimit'),
  loadLogsBtn: document.getElementById('loadLogsBtn'),
  logsTableBody: document.getElementById('logsTableBody'),
  logsFormMeta: document.getElementById('logsFormMeta'),
  logRecordedAt: document.getElementById('logRecordedAt'),
  logReporter: document.getElementById('logReporter'),
  logCategory: document.getElementById('logCategory'),
  logLocation: document.getElementById('logLocation'),
  logStatus: document.getElementById('logStatus'),
  logPriority: document.getElementById('logPriority'),
  logPhotoCount: document.getElementById('logPhotoCount'),
  logWorkOrderId: document.getElementById('logWorkOrderId'),
  logComplaintId: document.getElementById('logComplaintId'),
  logIssue: document.getElementById('logIssue'),
  logActionTaken: document.getElementById('logActionTaken'),
  saveLogBtn: document.getElementById('saveLogBtn'),
  deleteLogBtn: document.getElementById('deleteLogBtn'),
  clearLogsFormBtn: document.getElementById('clearLogsFormBtn'),
  facilitiesMeta: document.getElementById('facilitiesMeta'),
  facilitiesSearch: document.getElementById('facilitiesSearch'),
  facilitiesLimit: document.getElementById('facilitiesLimit'),
  loadFacilitiesBtn: document.getElementById('loadFacilitiesBtn'),
  facilitiesTableBody: document.getElementById('facilitiesTableBody'),
  facilitiesFormMeta: document.getElementById('facilitiesFormMeta'),
  facilityType: document.getElementById('facilityType'),
  facilityLocation: document.getElementById('facilityLocation'),
  facilityActive: document.getElementById('facilityActive'),
  facilityLastCheckedAt: document.getElementById('facilityLastCheckedAt'),
  facilityDetail: document.getElementById('facilityDetail'),
  facilityNote: document.getElementById('facilityNote'),
  saveFacilityBtn: document.getElementById('saveFacilityBtn'),
  deleteFacilityBtn: document.getElementById('deleteFacilityBtn'),
  clearFacilitiesFormBtn: document.getElementById('clearFacilitiesFormBtn'),
  inventoryMeta: document.getElementById('inventoryMeta'),
  inventorySearch: document.getElementById('inventorySearch'),
  inventoryLimit: document.getElementById('inventoryLimit'),
  loadInventoryBtn: document.getElementById('loadInventoryBtn'),
  inventoryTableBody: document.getElementById('inventoryTableBody'),
  inventoryFormMeta: document.getElementById('inventoryFormMeta'),
  inventoryKind: document.getElementById('inventoryKind'),
  inventoryName: document.getElementById('inventoryName'),
  inventoryQuantity: document.getElementById('inventoryQuantity'),
  inventoryUnit: document.getElementById('inventoryUnit'),
  inventoryPlace: document.getElementById('inventoryPlace'),
  inventoryStatus: document.getElementById('inventoryStatus'),
  inventoryNote: document.getElementById('inventoryNote'),
  saveInventoryBtn: document.getElementById('saveInventoryBtn'),
  deleteInventoryBtn: document.getElementById('deleteInventoryBtn'),
  clearInventoryFormBtn: document.getElementById('clearInventoryFormBtn'),
};

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatApiError(payload) {
  if (!payload) return '요청이 실패했습니다.';
  if (Array.isArray(payload.detail)) return payload.detail.map((item) => item && item.msg ? item.msg : JSON.stringify(item)).join('; ');
  if (typeof payload.detail === 'string') return payload.detail;
  return JSON.stringify(payload.detail || payload);
}

function setNotice(message, kind) {
  elements.noticeBar.textContent = message;
  elements.noticeBar.className = 'notice-bar';
  if (kind === 'error') elements.noticeBar.classList.add('error');
  if (kind === 'success') elements.noticeBar.classList.add('success');
}

function updateSessionStatus(message) {
  elements.sessionStatus.textContent = message;
}

function maskToken(value) {
  const token = String(value ?? '').trim();
  if (!token) return '미저장';
  if (token.length <= 8) return token[0] + '***' + token[token.length - 1];
  return token.slice(0, 4) + '...' + token.slice(-4);
}

function numberValue(value, fallback) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
}

function integerOrNull(value) {
  const trimmed = String(value ?? '').trim();
  if (!trimmed) return null;
  const numeric = Number.parseInt(trimmed, 10);
  return Number.isFinite(numeric) && numeric > 0 ? numeric : null;
}

function floatOrZero(value) {
  const numeric = Number.parseFloat(String(value ?? '').trim());
  return Number.isFinite(numeric) ? numeric : 0;
}

function nullIfBlank(value) {
  const normalized = String(value ?? '').trim();
  return normalized ? normalized : null;
}

function formatDateTime(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat('ko-KR', { dateStyle: 'short', timeStyle: 'short' }).format(date);
}

function toLocalInputValue(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  const offsetMinutes = date.getTimezoneOffset();
  const localDate = new Date(date.getTime() - (offsetMinutes * 60000));
  return localDate.toISOString().slice(0, 16);
}

function fromLocalInputValue(value) {
  const trimmed = String(value ?? '').trim();
  if (!trimmed) return null;
  const date = new Date(trimmed);
  if (Number.isNaN(date.getTime())) throw new Error('날짜 형식을 확인하세요.');
  return date.toISOString();
}

function toBooleanText(value) {
  return value ? '활성' : '비활성';
}

function pillClassForLog(log) {
  if (log.priority === 'critical' || log.priority === 'high') return 'pill danger';
  if (log.status === 'completed') return 'pill ok';
  if (log.status === 'blocked') return 'pill warn';
  return 'pill';
}

function pillClassForInventory(item) {
  if (item.status === 'out_of_stock') return 'pill danger';
  if (item.status === 'needs_check' || item.status === 'low_stock') return 'pill warn';
  return 'pill ok';
}

function populateSelect(selectElement, labelMap) {
  const options = Object.entries(labelMap).map(([value, label]) => '<option value="' + escapeHtml(value) + '">' + escapeHtml(label) + '</option>');
  selectElement.innerHTML = options.join('');
}

function getToken() {
  return String(elements.token.value ?? '').trim();
}

function getSite() {
  return String(elements.siteFilter.value ?? '').trim();
}

function requireSession(requireSite) {
  const token = getToken();
  const site = getSite();
  if (!token) throw new Error('X-Admin-Token을 입력하세요.');
  if (requireSite !== false && !site) throw new Error('site를 입력하세요.');
  return { token, site };
}

async function request(path, options) {
  const settings = options || {};
  const headers = new Headers(settings.headers || {});
  const token = getToken();
  if (token && !headers.has('X-Admin-Token')) headers.set('X-Admin-Token', token);
  if (settings.json !== undefined) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, {
    method: settings.method || 'GET',
    headers,
    body: settings.json !== undefined ? JSON.stringify(settings.json) : settings.body,
  });
  if (!response.ok) {
    let payload = null;
    try {
      payload = await response.json();
    } catch (error) {
      payload = null;
    }
    throw new Error(formatApiError(payload) || ('HTTP ' + response.status));
  }
  if (response.status === 204) return null;
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) return response.json();
  return response.text();
}

function saveSession() {
  const token = getToken();
  const site = getSite();
  if (!token) {
    setNotice('저장할 토큰이 없습니다.', 'error');
    return;
  }
  localStorage.setItem(STORAGE_KEYS.token, token);
  TOKEN_STORAGE_KEYS.forEach((key) => localStorage.setItem(key, token));
  if (site) localStorage.setItem(STORAGE_KEYS.site, site);
  else localStorage.removeItem(STORAGE_KEYS.site);
  updateSessionStatus('저장된 토큰: ' + maskToken(token) + ' · site: ' + (site || '미설정'));
  setNotice('토큰과 site를 저장했습니다.', 'success');
}

function clearSession() {
  TOKEN_STORAGE_KEYS.forEach((key) => localStorage.removeItem(key));
  localStorage.removeItem(STORAGE_KEYS.site);
  localStorage.removeItem(AUTH_PROFILE_KEY);
  elements.token.value = '';
  elements.siteFilter.value = '';
  state.dashboard = null;
  state.logs = [];
  state.facilities = [];
  state.inventory = [];
  state.selectedLogId = null;
  state.selectedFacilityId = null;
  state.selectedInventoryId = null;
  renderDashboard();
  renderLogs();
  renderFacilities();
  renderInventory();
  updateSessionStatus('토큰 상태: 없음');
  setNotice('저장된 토큰과 site를 지웠습니다.', 'success');
}

function hideToken() {
  elements.token.type = 'password';
  elements.toggleTokenVisibilityBtn.textContent = '토큰 보기';
  if (tokenHideTimer) {
    window.clearTimeout(tokenHideTimer);
    tokenHideTimer = null;
  }
}

function toggleTokenVisibility() {
  if (elements.token.type === 'password') {
    elements.token.type = 'text';
    elements.toggleTokenVisibilityBtn.textContent = '토큰 숨기기';
    if (tokenHideTimer) window.clearTimeout(tokenHideTimer);
    tokenHideTimer = window.setTimeout(() => hideToken(), 8000);
  } else {
    hideToken();
  }
}

async function checkConnection() {
  const session = requireSession(false);
  const me = await request('/api/auth/me', { headers: { 'X-Admin-Token': session.token } });
  localStorage.setItem(AUTH_PROFILE_KEY, JSON.stringify(me));
  updateSessionStatus('연결 확인됨 · ' + maskToken(session.token) + ' · ' + String(me.username || me.display_name || 'admin') + ' / ' + String(me.role || '-') + ' · site: ' + (getSite() || '미설정'));
  setNotice('권한 확인이 완료되었습니다.', 'success');
  return me;
}

function applySavedSession() {
  const storedToken = TOKEN_STORAGE_KEYS.map((key) => localStorage.getItem(key)).find((item) => item && item.trim()) || '';
  const site = localStorage.getItem(STORAGE_KEYS.site) || '';
  if (storedToken) elements.token.value = storedToken;
  if (site) elements.siteFilter.value = site;
  if (storedToken) updateSessionStatus('저장된 토큰: ' + maskToken(storedToken) + ' · site: ' + (site || '미설정'));
}

function fillDashboardFallback() {
  elements.heroLogTotal.textContent = '-';
  elements.heroLogActive.textContent = '-';
  elements.heroInventoryAttention.textContent = '-';
  elements.heroLogCompleted.textContent = '-';
  elements.statWorkOrders.value = '-';
  elements.statComplaints.value = '-';
  elements.statDocs.value = '-';
}

function renderDashboard() {
  const model = state.dashboard;
  if (!model) {
    fillDashboardFallback();
    elements.dashboardMeta.textContent = getSite() || 'site 미설정';
    elements.categoryList.innerHTML = '<li class="empty">대시보드를 불러오면 표시됩니다.</li>';
    elements.quickLinks.innerHTML = '<li class="empty">대시보드를 불러오면 표시됩니다.</li>';
    elements.reportSummaryList.innerHTML = '<li class="empty">대시보드를 먼저 불러오면 요약이 표시됩니다.</li>';
    elements.reportQuickLinks.innerHTML = '<li class="empty">대시보드를 먼저 불러오면 표시됩니다.</li>';
    return;
  }
  elements.dashboardMeta.textContent = model.site + ' · ' + model.range_label;
  elements.heroLogTotal.textContent = String(model.log_total);
  elements.heroLogActive.textContent = String(model.log_active);
  elements.heroInventoryAttention.textContent = String(model.inventory_attention);
  elements.heroLogCompleted.textContent = String(model.log_completed);
  elements.statWorkOrders.value = String(model.work_orders_open);
  elements.statComplaints.value = String(model.complaints_active);
  elements.statDocs.value = String(model.official_documents_open);

  if (Array.isArray(model.category_counts) && model.category_counts.length) {
    elements.categoryList.innerHTML = model.category_counts.map((item) => (
      '<li><strong>' + escapeHtml(item.category_label) + '</strong><div class="muted">' + escapeHtml(item.category) + ' · ' + escapeHtml(String(item.count)) + '건</div></li>'
    )).join('');
  } else {
    elements.categoryList.innerHTML = '<li class="empty">현재 범위에 기록이 없습니다.</li>';
  }

  const quickLinksMarkup = Array.isArray(model.quick_links) && model.quick_links.length
    ? model.quick_links.map((item) => '<li><a href="' + escapeHtml(item.href) + '">' + escapeHtml(item.label) + '</a></li>').join('')
    : '<li class="empty">바로가기가 없습니다.</li>';
  elements.quickLinks.innerHTML = quickLinksMarkup;
  elements.reportQuickLinks.innerHTML = quickLinksMarkup;

  elements.reportSummaryList.innerHTML = [
    '<li><strong>현장기록</strong><div class="muted">총 ' + escapeHtml(String(model.log_total)) + '건 · 완료 ' + escapeHtml(String(model.log_completed)) + '건 · 진행/보류 ' + escapeHtml(String(model.log_active)) + '건</div></li>',
    '<li><strong>긴급/높음 우선도</strong><div class="muted">' + escapeHtml(String(model.log_high_priority)) + '건</div></li>',
    '<li><strong>시설위치 활성</strong><div class="muted">' + escapeHtml(String(model.facility_active)) + '건 · 재고 주의 ' + escapeHtml(String(model.inventory_attention)) + '건</div></li>',
    '<li><strong>코어 업무 현황</strong><div class="muted">작업지시 ' + escapeHtml(String(model.work_orders_open)) + ' · 민원 ' + escapeHtml(String(model.complaints_active)) + ' · 최근 점검 ' + escapeHtml(String(model.inspections_recent)) + ' · 공문 ' + escapeHtml(String(model.official_documents_open)) + '</div></li>',
  ].join('');
}

function renderLogs() {
  const rows = state.logs;
  elements.logsMeta.textContent = (getSite() || 'site 미설정') + ' · ' + rows.length + '건';
  if (!rows.length) {
    elements.logsTableBody.innerHTML = '<tr><td class="empty" colspan="7">조회된 기록이 없습니다.</td></tr>';
    return;
  }
  elements.logsTableBody.innerHTML = rows.map((item) => (
    '<tr data-log-id="' + escapeHtml(String(item.id)) + '"' + (state.selectedLogId === item.id ? ' class="selected"' : '') + '>' +
      '<td>' + escapeHtml(formatDateTime(item.recorded_at)) + '</td>' +
      '<td>' + escapeHtml(item.reporter) + '</td>' +
      '<td><span class="pill">' + escapeHtml(item.category_label) + '</span></td>' +
      '<td>' + escapeHtml(item.location) + '<div class="muted">' + escapeHtml(item.issue || '') + '</div></td>' +
      '<td><span class="' + pillClassForLog(item) + '">' + escapeHtml(item.status_label) + '</span></td>' +
      '<td>' + escapeHtml(item.priority_label) + '</td>' +
      '<td>' + escapeHtml(String(item.photo_count || 0)) + '장</td>' +
    '</tr>'
  )).join('');
  elements.logsTableBody.querySelectorAll('tr[data-log-id]').forEach((row) => {
    row.addEventListener('click', () => selectLog(Number.parseInt(row.dataset.logId || '0', 10)));
  });
}

function renderFacilities() {
  const rows = state.facilities;
  elements.facilitiesMeta.textContent = (getSite() || 'site 미설정') + ' · ' + rows.length + '건';
  if (!rows.length) {
    elements.facilitiesTableBody.innerHTML = '<tr><td class="empty" colspan="5">조회된 시설위치가 없습니다.</td></tr>';
    return;
  }
  elements.facilitiesTableBody.innerHTML = rows.map((item) => (
    '<tr data-facility-id="' + escapeHtml(String(item.id)) + '"' + (state.selectedFacilityId === item.id ? ' class="selected"' : '') + '>' +
      '<td>' + escapeHtml(item.facility_type) + '</td>' +
      '<td>' + escapeHtml(item.location) + '</td>' +
      '<td>' + escapeHtml(item.detail || '') + '</td>' +
      '<td><span class="' + (item.is_active ? 'pill ok' : 'pill') + '">' + escapeHtml(toBooleanText(item.is_active)) + '</span></td>' +
      '<td>' + escapeHtml(formatDateTime(item.last_checked_at)) + '</td>' +
    '</tr>'
  )).join('');
  elements.facilitiesTableBody.querySelectorAll('tr[data-facility-id]').forEach((row) => {
    row.addEventListener('click', () => selectFacility(Number.parseInt(row.dataset.facilityId || '0', 10)));
  });
}

function renderInventory() {
  const rows = state.inventory;
  elements.inventoryMeta.textContent = (getSite() || 'site 미설정') + ' · ' + rows.length + '건';
  if (!rows.length) {
    elements.inventoryTableBody.innerHTML = '<tr><td class="empty" colspan="5">조회된 재고가 없습니다.</td></tr>';
    return;
  }
  elements.inventoryTableBody.innerHTML = rows.map((item) => (
    '<tr data-inventory-id="' + escapeHtml(String(item.id)) + '"' + (state.selectedInventoryId === item.id ? ' class="selected"' : '') + '>' +
      '<td>' + escapeHtml(item.item_kind_label) + '</td>' +
      '<td>' + escapeHtml(item.item_name) + '</td>' +
      '<td>' + escapeHtml(String(item.stock_quantity)) + ' ' + escapeHtml(item.unit) + '</td>' +
      '<td>' + escapeHtml(item.storage_place || '') + '</td>' +
      '<td><span class="' + pillClassForInventory(item) + '">' + escapeHtml(item.status_label) + '</span></td>' +
    '</tr>'
  )).join('');
  elements.inventoryTableBody.querySelectorAll('tr[data-inventory-id]').forEach((row) => {
    row.addEventListener('click', () => selectInventory(Number.parseInt(row.dataset.inventoryId || '0', 10)));
  });
}

function clearLogForm() {
  state.selectedLogId = null;
  elements.logsFormMeta.textContent = '새 기록';
  elements.logRecordedAt.value = toLocalInputValue(new Date().toISOString());
  elements.logReporter.value = '';
  elements.logCategory.value = 'general';
  elements.logLocation.value = '';
  elements.logStatus.value = 'in_progress';
  elements.logPriority.value = 'medium';
  elements.logPhotoCount.value = '0';
  elements.logWorkOrderId.value = '';
  elements.logComplaintId.value = '';
  elements.logIssue.value = '';
  elements.logActionTaken.value = '';
  renderLogs();
}

function clearFacilityForm() {
  state.selectedFacilityId = null;
  elements.facilitiesFormMeta.textContent = '새 위치';
  elements.facilityType.value = '';
  elements.facilityLocation.value = '';
  elements.facilityActive.value = 'true';
  elements.facilityLastCheckedAt.value = '';
  elements.facilityDetail.value = '';
  elements.facilityNote.value = '';
  renderFacilities();
}

function clearInventoryForm() {
  state.selectedInventoryId = null;
  elements.inventoryFormMeta.textContent = '새 품목';
  elements.inventoryKind.value = 'material';
  elements.inventoryName.value = '';
  elements.inventoryQuantity.value = '0';
  elements.inventoryUnit.value = '개';
  elements.inventoryPlace.value = '';
  elements.inventoryStatus.value = 'normal';
  elements.inventoryNote.value = '';
  renderInventory();
}

function selectLog(logId) {
  const item = state.logs.find((row) => row.id === logId);
  if (!item) return;
  state.selectedLogId = logId;
  elements.logsFormMeta.textContent = '#' + item.id + ' 수정';
  elements.logRecordedAt.value = toLocalInputValue(item.recorded_at);
  elements.logReporter.value = item.reporter || '';
  elements.logCategory.value = item.category || 'general';
  elements.logLocation.value = item.location || '';
  elements.logStatus.value = item.status || 'in_progress';
  elements.logPriority.value = item.priority || 'medium';
  elements.logPhotoCount.value = String(item.photo_count || 0);
  elements.logWorkOrderId.value = item.linked_work_order_id || '';
  elements.logComplaintId.value = item.linked_complaint_id || '';
  elements.logIssue.value = item.issue || '';
  elements.logActionTaken.value = item.action_taken || '';
  renderLogs();
}

function selectFacility(facilityId) {
  const item = state.facilities.find((row) => row.id === facilityId);
  if (!item) return;
  state.selectedFacilityId = facilityId;
  elements.facilitiesFormMeta.textContent = '#' + item.id + ' 수정';
  elements.facilityType.value = item.facility_type || '';
  elements.facilityLocation.value = item.location || '';
  elements.facilityActive.value = item.is_active ? 'true' : 'false';
  elements.facilityLastCheckedAt.value = toLocalInputValue(item.last_checked_at);
  elements.facilityDetail.value = item.detail || '';
  elements.facilityNote.value = item.note || '';
  renderFacilities();
}

function selectInventory(itemId) {
  const item = state.inventory.find((row) => row.id === itemId);
  if (!item) return;
  state.selectedInventoryId = itemId;
  elements.inventoryFormMeta.textContent = '#' + item.id + ' 수정';
  elements.inventoryKind.value = item.item_kind || 'material';
  elements.inventoryName.value = item.item_name || '';
  elements.inventoryQuantity.value = String(item.stock_quantity ?? 0);
  elements.inventoryUnit.value = item.unit || '개';
  elements.inventoryPlace.value = item.storage_place || '';
  elements.inventoryStatus.value = item.status || 'normal';
  elements.inventoryNote.value = item.note || '';
  renderInventory();
}

async function loadDashboard() {
  const session = requireSession(true);
  const params = new URLSearchParams({ site: session.site, range_key: elements.rangeKey.value || 'week' });
  state.dashboard = await request('/api/team-ops/dashboard?' + params.toString());
  renderDashboard();
}

async function loadLogs() {
  const session = requireSession(true);
  const params = new URLSearchParams({
    site: session.site,
    limit: String(numberValue(elements.logsLimit.value, 50)),
  });
  const q = nullIfBlank(elements.logsSearch.value);
  if (q) params.set('q', q);
  state.logs = await request('/api/team-ops/logs?' + params.toString());
  if (!state.logs.some((item) => item.id === state.selectedLogId)) clearLogForm();
  renderLogs();
}

async function loadFacilities() {
  const session = requireSession(true);
  const params = new URLSearchParams({
    site: session.site,
    limit: String(numberValue(elements.facilitiesLimit.value, 50)),
  });
  const q = nullIfBlank(elements.facilitiesSearch.value);
  if (q) params.set('q', q);
  state.facilities = await request('/api/team-ops/facilities?' + params.toString());
  if (!state.facilities.some((item) => item.id === state.selectedFacilityId)) clearFacilityForm();
  renderFacilities();
}

async function loadInventory() {
  const session = requireSession(true);
  const params = new URLSearchParams({
    site: session.site,
    limit: String(numberValue(elements.inventoryLimit.value, 50)),
  });
  const q = nullIfBlank(elements.inventorySearch.value);
  if (q) params.set('q', q);
  state.inventory = await request('/api/team-ops/inventory?' + params.toString());
  if (!state.inventory.some((item) => item.id === state.selectedInventoryId)) clearInventoryForm();
  renderInventory();
}

async function refreshAll() {
  const session = requireSession(true);
  await Promise.all([loadDashboard(), loadLogs(), loadFacilities(), loadInventory()]);
  elements.workspaceMeta.textContent = session.site + ' · 현장기록 ' + state.logs.length + '건 · 시설위치 ' + state.facilities.length + '건 · 재고 ' + state.inventory.length + '건';
  setNotice('팀 운영 데이터를 새로 불러왔습니다.', 'success');
}

async function saveLog() {
  const session = requireSession(true);
  const payload = {
    site: session.site,
    recorded_at: fromLocalInputValue(elements.logRecordedAt.value),
    reporter: nullIfBlank(elements.logReporter.value),
    category: elements.logCategory.value || 'general',
    location: nullIfBlank(elements.logLocation.value),
    issue: nullIfBlank(elements.logIssue.value),
    action_taken: elements.logActionTaken.value || '',
    status: elements.logStatus.value || 'in_progress',
    priority: elements.logPriority.value || 'medium',
    photo_count: Math.max(0, numberValue(elements.logPhotoCount.value, 0)),
    linked_work_order_id: integerOrNull(elements.logWorkOrderId.value),
    linked_complaint_id: integerOrNull(elements.logComplaintId.value),
  };
  if (!payload.recorded_at || !payload.reporter || !payload.location || !payload.issue) throw new Error('필수 항목을 입력하세요.');
  if (state.selectedLogId) {
    await request('/api/team-ops/logs/' + state.selectedLogId, { method: 'PATCH', json: payload });
    setNotice('현장기록을 수정했습니다.', 'success');
  } else {
    await request('/api/team-ops/logs', { method: 'POST', json: payload });
    setNotice('현장기록을 등록했습니다.', 'success');
  }
  await loadDashboard();
  await loadLogs();
  clearLogForm();
}

async function deleteLog() {
  requireSession(true);
  if (!state.selectedLogId) throw new Error('삭제할 현장기록을 먼저 선택하세요.');
  await request('/api/team-ops/logs/' + state.selectedLogId, { method: 'DELETE' });
  setNotice('현장기록을 삭제했습니다.', 'success');
  await loadDashboard();
  await loadLogs();
  clearLogForm();
}

async function saveFacility() {
  const session = requireSession(true);
  const payload = {
    site: session.site,
    facility_type: nullIfBlank(elements.facilityType.value),
    location: nullIfBlank(elements.facilityLocation.value),
    detail: elements.facilityDetail.value || '',
    note: elements.facilityNote.value || '',
    is_active: elements.facilityActive.value === 'true',
    last_checked_at: nullIfBlank(elements.facilityLastCheckedAt.value) ? fromLocalInputValue(elements.facilityLastCheckedAt.value) : null,
  };
  if (!payload.facility_type || !payload.location) throw new Error('설비종류와 위치를 입력하세요.');
  if (state.selectedFacilityId) {
    await request('/api/team-ops/facilities/' + state.selectedFacilityId, { method: 'PATCH', json: payload });
    setNotice('시설위치를 수정했습니다.', 'success');
  } else {
    await request('/api/team-ops/facilities', { method: 'POST', json: payload });
    setNotice('시설위치를 등록했습니다.', 'success');
  }
  await loadDashboard();
  await loadFacilities();
  clearFacilityForm();
}

async function deleteFacility() {
  requireSession(true);
  if (!state.selectedFacilityId) throw new Error('삭제할 시설위치를 먼저 선택하세요.');
  await request('/api/team-ops/facilities/' + state.selectedFacilityId, { method: 'DELETE' });
  setNotice('시설위치를 삭제했습니다.', 'success');
  await loadDashboard();
  await loadFacilities();
  clearFacilityForm();
}

async function saveInventory() {
  const session = requireSession(true);
  const payload = {
    site: session.site,
    item_kind: elements.inventoryKind.value || 'material',
    item_name: nullIfBlank(elements.inventoryName.value),
    stock_quantity: floatOrZero(elements.inventoryQuantity.value),
    unit: nullIfBlank(elements.inventoryUnit.value),
    storage_place: elements.inventoryPlace.value || '',
    status: elements.inventoryStatus.value || 'normal',
    note: elements.inventoryNote.value || '',
  };
  if (!payload.item_name || !payload.unit) throw new Error('품목명과 단위를 입력하세요.');
  if (state.selectedInventoryId) {
    await request('/api/team-ops/inventory/' + state.selectedInventoryId, { method: 'PATCH', json: payload });
    setNotice('재고 정보를 수정했습니다.', 'success');
  } else {
    await request('/api/team-ops/inventory', { method: 'POST', json: payload });
    setNotice('재고 정보를 등록했습니다.', 'success');
  }
  await loadDashboard();
  await loadInventory();
  clearInventoryForm();
}

async function deleteInventory() {
  requireSession(true);
  if (!state.selectedInventoryId) throw new Error('삭제할 품목을 먼저 선택하세요.');
  await request('/api/team-ops/inventory/' + state.selectedInventoryId, { method: 'DELETE' });
  setNotice('재고 정보를 삭제했습니다.', 'success');
  await loadDashboard();
  await loadInventory();
  clearInventoryForm();
}

function setActiveTab(tabName) {
  state.activeTab = tabName;
  const tabMap = {
    logs: [elements.logsTabBtn, elements.logsWorkspace],
    facilities: [elements.facilitiesTabBtn, elements.facilitiesWorkspace],
    inventory: [elements.inventoryTabBtn, elements.inventoryWorkspace],
    reports: [elements.reportsTabBtn, elements.reportsWorkspace],
  };
  Object.entries(tabMap).forEach(([name, pair]) => {
    const button = pair[0];
    const panel = pair[1];
    const active = name === tabName;
    button.setAttribute('aria-pressed', active ? 'true' : 'false');
    panel.classList.toggle('hidden', !active);
  });
  const labels = { logs: '현장기록', facilities: '시설위치', inventory: '공구/자재', reports: '보고' };
  elements.reportsMeta.textContent = (getSite() || 'site 미설정') + ' · ' + labels[tabName];
}

function bindButton(element, handler) {
  element.addEventListener('click', async () => {
    try {
      await handler();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error), 'error');
    }
  });
}

function initialize() {
  populateSelect(elements.logCategory, LOG_CATEGORY_LABELS);
  populateSelect(elements.logStatus, LOG_STATUS_LABELS);
  populateSelect(elements.logPriority, LOG_PRIORITY_LABELS);
  populateSelect(elements.inventoryKind, INVENTORY_KIND_LABELS);
  populateSelect(elements.inventoryStatus, INVENTORY_STATUS_LABELS);
  applySavedSession();
  clearLogForm();
  clearFacilityForm();
  clearInventoryForm();
  setActiveTab('logs');
  renderDashboard();

  bindButton(elements.refreshAllBtn, refreshAll);
  bindButton(elements.savePrefsBtn, async () => saveSession());
  bindButton(elements.checkConnectionBtn, checkConnection);
  bindButton(elements.clearPrefsBtn, async () => clearSession());
  elements.toggleTokenVisibilityBtn.addEventListener('click', toggleTokenVisibility);
  elements.token.addEventListener('blur', hideToken);

  bindButton(elements.refreshDashboardBtn, loadDashboard);
  bindButton(elements.loadLogsBtn, loadLogs);
  bindButton(elements.loadFacilitiesBtn, loadFacilities);
  bindButton(elements.loadInventoryBtn, loadInventory);

  bindButton(elements.saveLogBtn, saveLog);
  bindButton(elements.deleteLogBtn, deleteLog);
  bindButton(elements.saveFacilityBtn, saveFacility);
  bindButton(elements.deleteFacilityBtn, deleteFacility);
  bindButton(elements.saveInventoryBtn, saveInventory);
  bindButton(elements.deleteInventoryBtn, deleteInventory);

  elements.clearLogsFormBtn.addEventListener('click', clearLogForm);
  elements.clearFacilitiesFormBtn.addEventListener('click', clearFacilityForm);
  elements.clearInventoryFormBtn.addEventListener('click', clearInventoryForm);

  elements.logsTabBtn.addEventListener('click', () => setActiveTab('logs'));
  elements.facilitiesTabBtn.addEventListener('click', () => setActiveTab('facilities'));
  elements.inventoryTabBtn.addEventListener('click', () => setActiveTab('inventory'));
  elements.reportsTabBtn.addEventListener('click', () => setActiveTab('reports'));

  elements.rangeKey.addEventListener('change', async () => {
    if (getToken() && getSite()) {
      try {
        await loadDashboard();
      } catch (error) {
        setNotice(error instanceof Error ? error.message : String(error), 'error');
      }
    }
  });

  if (getToken() && getSite()) {
    refreshAll().catch((error) => {
      setNotice(error instanceof Error ? error.message : String(error), 'error');
    });
  }
}

initialize();
