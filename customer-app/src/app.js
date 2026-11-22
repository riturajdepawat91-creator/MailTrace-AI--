import { icon } from './icons.js';
import { SCAN_LIMITS, SCAN_RANGES, normalizeScanConfig, summarizeScanConfig, canRunCustomerScan } from './ui-state.js';

const nav = [
  ['overview', 'Overview', 'overview'],
  ['mailbox-connections', 'Mailbox Connections', 'mailbox'],
  ['continuous-protection', 'Continuous Protection', 'security'],
  ['manual-scan', 'Manual Scan', 'scan'],
  ['scan-activity', 'Scan Activity', 'refresh'],
  ['threat-center', 'Threat Center', 'threat'],
  ['quarantine', 'Quarantine', 'quarantine'],
  ['reports', 'Reports', 'reports'],
  ['performance', 'Performance', 'performance'],
  ['privacy-center', 'Privacy Center', 'privacy'],
  ['device-agent-status', 'Device & Agent Status', 'device'],
  ['mailbox-security', 'Mailbox Security', 'security'],
  ['settings', 'Settings', 'settings'],
];

const quick = [
  { id: 'manual-scan', title: 'Manual Scan', body: 'Configure a scan request', button: 'Configure', icon: 'scan', accent: '#168bff' },
  { id: 'mailbox-connections', title: 'Connect Mailbox', body: 'Provider status and setup', button: 'Connections', icon: 'mailPlus', accent: '#00d2d5' },
  { id: 'threat-center', title: 'Threat Center', body: 'Authorized findings only', button: 'Open center', icon: 'threat', accent: '#ffad25' },
  { id: 'quarantine', title: 'Quarantine', body: 'Evidence access status', button: 'Vault status', icon: 'quarantine', accent: '#bd75ff' },
  { id: 'reports', title: 'Reports', body: 'Customer report availability', button: 'Open reports', icon: 'reports', accent: '#44db90' },
];

const $ = (selector, root = document) => root.querySelector(selector);
const navElement = $('#mainNav');
const overview = $('#view-overview');
const page = $('#view-page');
let activePage = 'overview';
let toastTimer;
let serviceStatusMessage = 'Not checked';
let serviceStatusOk = false;
let scanConfig = normalizeScanConfig({ days: 7, mailbox: 'none', folder: 'Inbox', mode: 'standard', maxEmails: 500, maxSizeMb: 50 });
const requestMap = new Map();

const pageTitles = {
  'mailbox-connections': ['Mailbox Connections', 'mailbox', 'Supported providers'],
  'continuous-protection': ['Continuous Protection', 'security', 'Local protection controls'],
  'manual-scan': ['Manual Scan', 'scan', 'Create a scan request'],
  'scan-activity': ['Scan Activity', 'refresh', 'Run history'],
  'threat-center': ['Threat Center', 'threat', 'Investigation classifications'],
  quarantine: ['Quarantine', 'quarantine', 'Evidence handling'],
  reports: ['Reports', 'reports', 'Customer reports'],
  settings: ['Settings', 'settings', 'Local application settings'],
  performance: ['Performance', 'performance', 'Device telemetry'],
  'privacy-center': ['Privacy Center', 'privacy', 'Privacy controls'],
  'device-agent-status': ['Device & Agent Status', 'device', 'Agent connectivity'],
  'mailbox-security': ['Mailbox Security', 'security', 'Mailbox protection'],
};

function showToast(message) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.classList.add('visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('visible'), 3200);
}

function renderNav() {
  navElement.innerHTML = nav.map(([id, label, glyph]) => `<button class="nav-item${id === activePage ? ' active' : ''}" type="button" data-nav="${id}" aria-current="${id === activePage ? 'page' : 'false'}" title="${label}">${icon(glyph, 21)}<span>${label}</span></button>`).join('');
}

function renderQuickActions() {
  $('#quickActions').innerHTML = quick.map(item => `<article class="quick-card" style="--accent:${item.accent}"><span class="quick-icon">${icon(item.icon, 32)}</span><h3>${item.title}</h3><p>${item.body}</p><button type="button" data-nav="${item.id}" aria-label="${item.button}: ${item.title}">${item.button}</button></article>`).join('');
}

function pageHeader(id) {
  const [title, glyph, subtitle] = pageTitles[id] || pageTitles.settings;
  return `<div class="screen-heading"><div class="screen-icon">${icon(glyph, 25)}</div><div><span class="eyebrow">CUSTOMER WORKSPACE</span><h1>${title}</h1><p>${subtitle}</p></div></div>`;
}

function unavailablePill(label = 'NOT CONNECTED', id = '') { return `<span class="health-pill unavailable"${id ? ` id="${id}"` : ''}>${label}</span>`; }
function capability(title, body, glyph = 'help') { return `<article class="info-card panel"><div class="info-card-icon">${icon(glyph, 21)}</div><h3>${title}</h3><p>${body}</p></article>`; }

function mailboxScreen() {
  return `<div class="notice panel"><span>${icon('cpu', 18)}</span><p id="customerApiState">Checking the local Customer API…</p></div><div class="provider-grid"><article class="provider-card panel" id="gmailProviderCard"><div class="provider-heading"><span class="provider-icon">${icon('gmail', 24)}</span><div><h2>Gmail</h2><p>Readonly mailbox connection</p></div><span class="health-pill unavailable" id="gmailConnectionPill">NOT CONNECTED</span></div><p class="provider-copy" id="gmailConnectionMessage">Sign-in unavailable until customer OIDC is configured.</p><div class="state-line"><span>Customer authorization</span><strong id="customerAuthState">Signed out</strong></div><div class="state-line"><span>Mailbox</span><strong id="gmailMailboxIdentity">Not connected</strong></div><div class="state-line"><span>Synchronization</span><strong id="gmailSyncState">Not reported</strong></div><div class="provider-actions"><button class="primary-button" id="customerLoginButton" data-customer-operation="login" type="button" disabled>Sign in</button><button class="secondary-button" id="gmailConnectButton" data-customer-operation="connect-gmail" type="button" disabled>Connect Gmail</button><button class="secondary-button" id="gmailDisconnectButton" data-customer-operation="disconnect-gmail" type="button" hidden>Disconnect Gmail</button><button class="secondary-button" id="customerLogoutButton" data-customer-operation="logout" type="button" hidden>Sign out</button></div></article><article class="provider-card panel"><div class="provider-heading"><span class="provider-icon">${icon('mailbox', 24)}</span><div><h2>Outlook / Microsoft 365</h2><p>Mailbox provider</p></div>${unavailablePill('NOT CONNECTED')}</div><p class="provider-copy">Microsoft Graph is not configured for this customer app.</p><div class="state-line"><span>Authorization</span><strong>Not configured</strong></div><div class="state-line"><span>Synchronization</span><strong>Unavailable</strong></div><button class="secondary-button" type="button" disabled>Connect unavailable</button></article><article class="provider-card panel"><div class="provider-heading"><span class="provider-icon">${icon('mailbox', 24)}</span><div><h2>Exchange</h2><p>Mailbox provider</p></div>${unavailablePill('NOT CONNECTED')}</div><p class="provider-copy">No customer Exchange connector is exposed by the current architecture.</p><div class="state-line"><span>Authorization</span><strong>Not configured</strong></div><div class="state-line"><span>Synchronization</span><strong>Unavailable</strong></div><button class="secondary-button" type="button" disabled>Connect unavailable</button></article></div><div class="notice panel"><span>${icon('help', 18)}</span><p>MailTrace customer sign-in uses OIDC. Gmail authorization is a separate readonly OAuth grant. Tokens are held by the native host and never placed in WebView storage.</p></div>`;
}

function scanScreen() {
  const days = SCAN_RANGES.map(value => `<option value="${value}"${scanConfig.days === value ? ' selected' : ''}>${value} ${value === 1 ? 'day' : 'days'}</option>`).join('');
  return `<div class="scan-layout"><section class="panel form-panel"><div class="panel-heading"><div><span class="eyebrow">REQUEST CONFIGURATION</span><h2>Choose scan scope</h2></div>${unavailablePill('SERVICE UNAVAILABLE')}</div><div class="form-grid"><label>Date range<select data-scan="days">${days}</select></label><label>Mailbox<select data-scan="mailbox"><option value="none">No connected mailbox</option><option disabled>Gmail — not connected</option><option disabled>Outlook — not connected</option><option disabled>Exchange — not connected</option></select></label><label>Folder<select data-scan="folder"><option>Inbox</option><option>Sent Items</option><option>All folders</option></select></label><label>Scan mode<select data-scan="mode"><option value="standard"${scanConfig.mode === 'standard' ? ' selected' : ''}>Standard scan</option><option value="deep"${scanConfig.mode === 'deep' ? ' selected' : ''}>Deep scan</option></select></label><label>Email limit<input data-scan="maxEmails" type="number" min="1" max="${SCAN_LIMITS.maxEmails}" value="${scanConfig.maxEmails}"><small>Maximum ${SCAN_LIMITS.maxEmails.toLocaleString()} emails per request</small></label><label>Data limit (MB)<input data-scan="maxSizeMb" type="number" min="1" max="${SCAN_LIMITS.maxSizeMb}" value="${scanConfig.maxSizeMb}"><small>Maximum ${SCAN_LIMITS.maxSizeMb} MB per request</small></label></div><div class="scan-summary"><span class="eyebrow">CONFIGURATION SUMMARY</span><strong id="scanSummaryText">${summarizeScanConfig(scanConfig)}</strong></div><div class="scan-controls"><button class="primary-button" data-scan-action="start">Start scan</button><button class="secondary-button" data-scan-action="pause" disabled>Pause</button><button class="secondary-button" data-scan-action="resume" disabled>Resume</button><button class="secondary-button danger-button" data-scan-action="cancel" disabled>Cancel</button></div><p class="inline-status" id="scanRequestStatus" role="status">No scan started. Scan requests are unavailable until a customer scan service is connected.</p></section><aside class="panel scan-side"><span class="eyebrow">SCAN PROGRESS</span><h2>Ready when service is connected</h2><div class="progress-track"><span></span></div><div class="state-line"><span>Progress</span><strong>Unavailable</strong></div><div class="state-line"><span>Completion state</span><strong>No completed run</strong></div><div class="state-line"><span>Failed items</span><strong>—</strong></div><button class="secondary-button" data-scan-action="retry" disabled>Retry failed items</button><div class="privacy-note">${icon('privacy', 16)} No operation starts from this screen without a real backend.</div></aside></div>`;
}

function activityScreen() {
  return `<section class="panel table-panel"><div class="panel-heading"><div><span class="eyebrow">CUSTOMER ACTIVITY</span><h2>Scan activity</h2></div><div class="filter-row"><select aria-label="Activity status"><option>All statuses</option><option>Completed</option><option>Failed</option><option>Running</option></select><select aria-label="Activity date range"><option>Last 7 days</option><option>Last 30 days</option></select></div></div><div class="empty-state">${icon('refresh', 30)}<h3>No scan runs available</h3><p>A customer scan-history endpoint is not available. No activity or results are being simulated.</p></div><div class="table-footer">Failed-item retry is unavailable until a real scan job is returned by the service.</div></section>`;
}

function threatScreen() {
  const groups = [
    ['SAFE', 'success', 'No customer records are available. SAFE individual email records are never shown here.', 'Aggregate only'],
    ['MODERATE', 'warning', 'No MODERATE finding feed is connected.', 'No evidence loaded'],
    ['HIGH', 'warning', 'No HIGH investigation records are connected.', 'Encrypted evidence not verified'],
    ['CRITICAL', 'threat', 'No CRITICAL investigation records are connected.', 'SOC synchronization not available'],
    ['Unavailable / Incomplete', 'help', 'Unavailable checks must remain distinct from a clean result.', 'Analysis status not connected'],
  ];
  return `<div class="threat-grid">${groups.map(([name, glyph, body, privacy]) => `<article class="threat-state panel"><div class="threat-state-heading"><span>${icon(glyph, 21)}</span><h2>${name}</h2>${unavailablePill('NO FEED')}</div><p>${body}</p><div class="privacy-tag">${icon('lock', 14)}${privacy}</div><button class="text-button" disabled>View investigation</button></article>`).join('')}</div><div class="notice panel"><span>${icon('help', 18)}</span><p>Findings and evidence will appear only when an authorized customer-scoped result API supplies them. Internal SOC cases are not exposed in this app.</p></div>`;
}

function quarantineScreen() {
  return `<section class="panel vault-panel"><div class="vault-emblem">${icon('quarantine', 32)}</div>${unavailablePill('VAULT NOT CONNECTED')}<h2>Quarantine is unavailable</h2><p>No customer quarantine service or evidence vault is connected. There are no records to display.</p><div class="vault-facts"><div><span>Stored items</span><strong>—</strong></div><div><span>Encryption status</span><strong>Not verified</strong></div><div><span>Retention policy</span><strong>Not reported</strong></div><div><span>Authorized access</span><strong>Not configured</strong></div></div><div class="scan-controls"><button class="secondary-button" disabled>View evidence</button><button class="secondary-button danger-button" disabled>Release / delete</button></div><div class="notice inline-notice"><span>${icon('privacy', 17)}</span><p>No quarantine, release, deletion, or email modification action is implemented.</p></div></section>`;
}

function reportsScreen() {
  return `<section class="panel table-panel"><div class="panel-heading"><div><span class="eyebrow">AUTHORIZED CUSTOMER REPORTS</span><h2>Reports</h2></div><div class="filter-row"><select aria-label="Report period"><option>All time</option><option>Last 7 days</option><option>Last 30 days</option></select><select aria-label="Report type"><option>All report types</option><option>Scan summary</option><option>Investigation</option></select><button class="secondary-button" disabled>Export unavailable</button></div></div><div class="empty-state">${icon('reports', 30)}<h3>No customer reports available</h3><p>Report listing and export APIs are not available. The internal SOC report store is not queried.</p></div><div class="table-footer">Filters are view-only until report data is connected.</div></section>`;
}

function settingsScreen(id) {
  if (id === 'settings') return `<div class="settings-grid"><section class="panel setting-panel"><div class="panel-heading"><div><span class="eyebrow">LOCAL INTEGRATION</span><h2>MailTrace service</h2></div>${unavailablePill('NOT CHECKED', 'serviceHealthPill')}</div><p class="setting-help">A read-only health and readiness check is available. Mailbox and customer scan operations are not connected.</p><label for="apiBase">Loopback API address</label><div class="api-field"><input id="apiBase" type="url" spellcheck="false" autocomplete="url"><button class="primary-button" id="checkConnection">Check service</button></div><div class="setting-status" id="connectionMessage" role="status">Not checked</div><div class="state-line"><span>Agent connection</span><strong>Not available</strong></div><div class="state-line"><span>Health endpoint</span><strong>/api/health</strong></div><div class="state-line"><span>Readiness endpoint</span><strong>/api/ready</strong></div></section><section class="panel setting-panel"><div class="panel-heading"><div><span class="eyebrow">PRIVACY &amp; OPERATIONS</span><h2>Local policy status</h2></div>${unavailablePill('SERVICE NOT CONNECTED')}</div>${readonlyPreference('SAFE email content', 'Not persisted by policy', true)}${readonlyPreference('Evidence encryption', 'Not verified')}${readonlyPreference('SOC evidence sharing', 'Policy status unavailable')}${readonlyPreference('Retention', 'Policy not reported')}<div class="notice inline-notice"><span>${icon('help', 17)}</span><p>Privacy controls are presented for reference. This UI cannot change backend policy.</p></div></section><section class="panel setting-panel"><div class="panel-heading"><div><span class="eyebrow">RESOURCE LIMITS</span><h2>Local processing</h2></div>${unavailablePill('NOT CONFIGURABLE')}</div>${readonlyPreference('CPU limit', 'Not reported')}${readonlyPreference('Memory limit', 'Not reported')}${readonlyPreference('Local processing mode', 'Agent not connected')}</section><section class="panel setting-panel"><div class="panel-heading"><div><span class="eyebrow">SCHEDULE &amp; NOTIFICATIONS</span><h2>Reconciliation</h2></div>${unavailablePill('NOT CONFIGURABLE')}</div>${readonlyPreference('Reconciliation schedule', 'Not reported')}${readonlyPreference('Desktop notifications', 'Not configured')}${readonlyPreference('Failed scan notifications', 'Not configured')}</section></div>`;
  if (id === 'continuous-protection') return `<div class="settings-grid"><section class="panel setting-panel"><div class="panel-heading"><div><span class="eyebrow">PROTECTION MODE</span><h2>Continuous Protection</h2></div>${unavailablePill()}</div><p class="setting-help">No customer Agent or mailbox sync connection is active. These controls are displayed but cannot start or change a protection service.</p>${readonlyPreference('Continuous scanning', 'Unavailable')}${readonlyPreference('Mailbox sync', 'Not connected')}${readonlyPreference('24-hour reconciliation', 'Not scheduled')}${readonlyPreference('Windows startup', 'Not configured')}${readonlyPreference('Last successful scan', 'Not available')}</section><section class="panel setting-panel"><div class="panel-heading"><div><span class="eyebrow">LOCAL AGENT</span><h2>Protection status</h2></div>${unavailablePill('AGENT NOT CONNECTED')}</div><div class="empty-state compact-empty">${icon('device', 28)}<h3>No Agent heartbeat</h3><p>Agent status and command APIs are not exposed to this customer app.</p></div></section></div>`;
  if (id === 'device-agent-status') return `<div class="settings-grid">${capability('Local API', 'Health/readiness can be checked from Settings.', 'cpu')}${capability('Customer Agent', 'Not connected; no heartbeat or installation status is available.', 'device')}${capability('Automatic startup', 'No service installation or startup configuration is implemented.', 'refresh')}${capability('Mailbox sync', 'No customer mailbox synchronization state is exposed.', 'mailbox')}</div>`;
  if (id === 'performance') return `<div class="settings-grid">${capability('CPU', 'Live device telemetry is available in the WinUI host only; browser preview reports unavailable.', 'cpu')}${capability('Memory', 'Live device telemetry is available in the WinUI host only; browser preview reports unavailable.', 'device')}${capability('Disk', 'Telemetry does not include an analysis-engine resource cap.', 'vault')}${capability('Network', 'No mailbox or external intelligence traffic is initiated by this UI.', 'performance')}</div>`;
  if (id === 'privacy-center') return `<section class="panel setting-panel policy-panel"><div class="panel-heading"><div><span class="eyebrow">LOCAL-FIRST</span><h2>Privacy Controls</h2></div>${unavailablePill('POLICY REFERENCE')}</div>${readonlyPreference('Email body in dashboard records', 'Never displayed as a record', true)}${readonlyPreference('SAFE email content', 'Not persisted by policy', true)}${readonlyPreference('Email content transfer to SOC', 'Not performed by this app', true)}${readonlyPreference('Encryption for evidence', 'Not verified')}${readonlyPreference('Retention schedule', 'Not connected')}<p class="setting-help">These are current application boundaries; they are not a live audit of backend processing or storage.</p></section>`;
  return `<section class="panel setting-panel policy-panel"><div class="panel-heading"><div><span class="eyebrow">MAILBOX CONFIGURATION</span><h2>Mailbox Security</h2></div>${unavailablePill('NOT CONNECTED')}</div>${readonlyPreference('Mailbox policies', 'Not exposed by customer API')}${readonlyPreference('Authentication status', 'Not checked')}${readonlyPreference('Mailbox sync health', 'Unavailable')}${readonlyPreference('Security score', 'Not calculated')}<div class="notice inline-notice"><span>${icon('help', 17)}</span><p>No mailbox configuration is fetched or changed by this screen.</p></div></section>`;
}

function readonlyPreference(label, value, safe = false) {
  return `<div class="preference-row"><span>${label}</span><span class="preference-value ${safe ? 'safe' : ''}">${value}</span><button class="toggle-placeholder" type="button" disabled aria-label="${label}: unavailable"><i></i></button></div>`;
}

function renderPage(id) {
  let body;
  if (id === 'mailbox-connections') body = mailboxScreen();
  else if (id === 'manual-scan') body = scanScreen();
  else if (id === 'scan-activity') body = activityScreen();
  else if (id === 'threat-center') body = threatScreen();
  else if (id === 'quarantine') body = quarantineScreen();
  else if (id === 'reports') body = reportsScreen();
  else body = settingsScreen(id);
  page.innerHTML = `${pageHeader(id)}<div class="page-content">${body}</div>`;
  wirePageInteractions(id);
}

function navigate(id) {
  activePage = id;
  overview.classList.toggle('hidden', id !== 'overview');
  page.classList.toggle('hidden', id === 'overview');
  if (id !== 'overview') renderPage(id);
  renderNav();
  $('#workspace').scrollTop = 0;
  $('#workspace').focus({ preventScroll: true });
}

function safeBase(value) {
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || !['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname)) return null;
    return url.origin;
  } catch { return null; }
}
function readSavedApiBase() { try { return localStorage.getItem('mailtrace.customer.apiBase'); } catch { return null; } }
function saveApiBase(value) { try { localStorage.setItem('mailtrace.customer.apiBase', value); } catch { /* storage may be disabled */ } }

function updateHealth(health, ready) {
  const online = health?.status === 'ok' && health?.service === 'MailTrace AI Backend';
  const databaseReady = ready?.status === 'ok' && ready?.dependencies?.database === 'ok';
  $('#localEngineHealth').textContent = online ? 'API reachable' : 'Not connected';
  $('#localEngineHealth').className = `health-value ${online ? 'good' : 'muted'}`;
  $('#mailboxHealth').textContent = 'Unavailable';
  $('#privacyHealth').textContent = 'Not verified';
  $('#stabilityHealth').textContent = ready?.status === 'ok' ? 'Ready' : ready?.status === 'degraded' ? 'Degraded' : 'Unknown';
  $('#stabilityHealth').className = `health-value ${databaseReady ? 'good' : ready?.status === 'degraded' ? 'bad' : 'muted'}`;
  $('#healthValue').textContent = online ? (databaseReady ? 'OK' : 'API') : '—';
  $('#healthValue').style.fontSize = online ? '28px' : '';
  $('#healthRing').setAttribute('aria-label', online ? (databaseReady ? 'API and database ready' : 'API reachable, readiness degraded') : 'Service status unavailable');
  $('#healthFoot').textContent = online ? 'API state confirmed. Agent and mailbox status are not exposed.' : 'Connect to a local MailTrace service to check readiness.';
  $('#protectionSummary').textContent = online ? 'API connected; protection status unavailable' : 'Protection is not connected';
  $('.hero-status .status-dot').className = `status-dot ${online ? 'online' : 'offline'}`;
  $('#engineVersion').textContent = online ? 'Version not reported' : 'NOT DETECTED';
  $('#footerEngine').textContent = online ? 'Version not reported' : 'Unknown';
  $('#footerProtection').textContent = online ? 'API CONNECTED' : 'NOT CONNECTED';
  $('#footerProtection').className = online ? 'good' : 'muted';
  const servicePill = $('#serviceHealthPill');
  if (servicePill) { servicePill.textContent = online ? 'API REACHABLE' : 'NOT CONNECTED'; servicePill.className = `health-pill ${online ? 'available' : 'unavailable'}`; }
  $('#sidebarConnection').textContent = online ? 'MailTrace API reachable' : 'Local services not connected';
  $('#settingsConnectionState')?.replaceChildren(document.createTextNode(online ? 'API CONNECTED' : 'NOT CONNECTED'));
  $('#mailboxSummaryStatus').textContent = 'NOT CONNECTED';
  $('#mailboxSummaryText').textContent = 'Mailbox connector unavailable';
  $('#mailboxCount').textContent = '—';
  $('#scannedToday').textContent = '—';
}

function renderCheckResult(ok, data) {
  const health = data?.health;
  const ready = data?.ready;
  serviceStatusOk = Boolean(ok && health?.status === 'ok' && health?.service === 'MailTrace AI Backend');
  updateHealth(health, ready);
  serviceStatusMessage = serviceStatusOk ? ready?.status === 'ok' ? 'Connected. API and database readiness confirmed.' : 'API reachable. Readiness is degraded or unavailable.' : data?.error || 'The local endpoint did not identify as the MailTrace backend.';
  const message = $('#connectionMessage');
  if (message) {
    message.textContent = serviceStatusMessage;
    message.className = `setting-status ${serviceStatusOk ? 'good-text' : 'muted'}`;
  }
}

async function checkConnection() {
  const base = safeBase($('#apiBase')?.value.trim() || readSavedApiBase() || '') || 'http://127.0.0.1:8002';
  const baseInput = $('#apiBase');
  if (baseInput) baseInput.value = base;
  if (baseInput?.value.trim()) saveApiBase(base);
  const message = $('#connectionMessage');
  const checkButton = $('#checkConnection');
  if (message) message.textContent = 'Checking health and readiness…';
  if (checkButton) checkButton.disabled = true;
  try {
    let data;
    if (window.chrome?.webview) {
      const requestId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
      data = await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => { requestMap.delete(requestId); reject(new Error('timeout')); }, 30000);
        requestMap.set(requestId, payload => { clearTimeout(timeout); resolve(payload); });
        window.chrome.webview.postMessage({ type: 'health-check', requestId, baseUrl: base });
      });
    } else {
      const response = await fetch(`/integration/health?base=${encodeURIComponent(base)}`, { signal: AbortSignal.timeout(3500), cache: 'no-store' });
      data = await response.json();
      data.httpOk = response.ok;
    }
    renderCheckResult(data.httpOk !== false && data.health?.status === 'ok', data);
  } catch { renderCheckResult(false, { error: 'Could not reach the local MailTrace health/readiness endpoints.' }); }
  finally { if (checkButton) checkButton.disabled = false; }
}

function applyTelemetry(value) {
  if (!value || typeof value !== 'object') return;
  for (const [key, metric, color] of [['cpu', value.cpuPercent, '#00c8ff'], ['ram', value.memoryPercent, '#00d2d5'], ['disk', value.diskPercent, '#bd75ff'], ['network', value.networkMbps, '#44db90']]) {
    const valid = Number.isFinite(metric) && metric >= 0;
    $(`#${key}Value`).textContent = valid ? (key === 'network' ? `${metric.toFixed(1)} Mb/s` : `${Math.round(metric)}%`) : '—';
    $(`#${key}Bar`).style.width = valid ? `${Math.min(100, Math.max(3, metric))}%` : '0';
    $(`#${key}Bar`).style.background = color;
  }
  $('#telemetryState').textContent = 'LIVE DEVICE DATA';
}

function updateScanSummary() {
  const values = Object.fromEntries([...page.querySelectorAll('[data-scan]')].map(input => [input.dataset.scan, input.value]));
  scanConfig = normalizeScanConfig({ ...scanConfig, ...values });
  $('#scanSummaryText').textContent = summarizeScanConfig(scanConfig);
}

function wirePageInteractions(id) {
  if (id === 'mailbox-connections' && window.chrome?.webview) {
    requestCustomerApiStatus();
  }
  if (id === 'manual-scan') {
    page.querySelectorAll('[data-scan]').forEach(input => input.addEventListener('change', updateScanSummary));
    page.querySelectorAll('[data-scan]').forEach(input => input.addEventListener('input', updateScanSummary));
  }
  if (id === 'settings') {
    $('#apiBase').value = safeBase(readSavedApiBase() || '') || 'http://127.0.0.1:8002';
    $('#connectionMessage').textContent = serviceStatusMessage;
    $('#connectionMessage').className = `setting-status ${serviceStatusOk ? 'good-text' : 'muted'}`;
    $('#checkConnection').addEventListener('click', checkConnection);
    $('#apiBase').addEventListener('keydown', event => { if (event.key === 'Enter') checkConnection(); });
  }
}

function requestCustomerApiStatus() {
  if (!window.chrome?.webview) return;
  const requestId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  requestMap.set(requestId, updateCustomerMailboxStatus);
  window.chrome.webview.postMessage({ type: 'customer-api-status', requestId });
}

function updateCustomerMailboxStatus(payload) {
  const state = $('#customerApiState');
  if (!state) return;
  const configured = Boolean(payload.online && payload.auth?.login_supported);
  const signedIn = Boolean(payload.session?.authenticated);
  state.textContent = !payload.online ? 'Customer API is not reachable. Mailbox actions remain unavailable.'
    : !configured ? 'Customer API is running; customer OIDC configuration is missing. Mailbox actions are locked.'
      : signedIn ? 'Customer API connected. Customer identity verified.' : 'Customer API ready. Sign in to continue.';
  $('#customerLoginButton').disabled = !configured || signedIn;
  $('#gmailConnectButton').disabled = !signedIn;
  $('#customerLogoutButton').hidden = !signedIn;
  $('#customerAuthState').textContent = signedIn ? 'Authenticated customer_user' : payload.session?.reauth_required ? 'Reauthentication required' : configured ? 'Signed out' : 'Sign-in unavailable';
  const mailbox = payload.session?.mailboxes?.items?.find(item => item.provider === 'gmail');
  $('#gmailDisconnectButton').hidden = !signedIn || mailbox?.status !== 'CONNECTED';
  if (mailbox) {
    $('#gmailConnectionPill').textContent = mailbox.status === 'CONNECTED' ? 'CONNECTED' : mailbox.status.replaceAll('_', ' ');
    $('#gmailConnectionPill').className = `health-pill ${mailbox.status === 'CONNECTED' ? 'available' : 'unavailable'}`;
    $('#gmailMailboxIdentity').textContent = mailbox.identity || 'Not connected';
    $('#gmailConnectionMessage').textContent = mailbox.status === 'CONNECTED' ? 'Gmail readonly authorization is active.' : signedIn ? 'Connect the Gmail mailbox to authorize readonly access.' : 'Sign-in is required before connecting Gmail.';
  }
  const sync = payload.session?.sync;
  const syncedAt = Number(sync?.last_successful_sync_ms);
  $('#gmailSyncState').textContent = !signedIn ? 'Sign in required'
    : !sync ? 'Unavailable'
      : Number.isFinite(syncedAt) && syncedAt > 0 ? `Last sync ${new Date(syncedAt).toLocaleString()}`
        : sync.health_status || 'Not synchronized';
}

function startCustomerOperation(operation) {
  if (!window.chrome?.webview) { showToast('Customer operations require the installed Windows app.'); return; }
  const requestId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  requestMap.set(requestId, result => {
    const outcome = result?.result || {};
    if (result?.operation === 'login') showToast(outcome.ok ? 'MailTrace sign-in completed.' : `Sign-in unavailable (${outcome.state || 'FAILED'}).`);
    else if (result?.operation === 'logout') showToast(outcome.ok ? 'MailTrace signed out.' : `Sign-out status: ${outcome.state || 'UNKNOWN'}.`);
    else showToast(outcome.status || outcome.state || 'Customer operation completed.');
    requestCustomerApiStatus();
  });
  window.chrome.webview.postMessage({ type: 'customer-api-operation', requestId, operation });
}

function initializeIcons() {
  const mapping = { enterpriseIcon: 'bank', agentChipIcon: 'security', engineChipIcon: 'refresh', lastScanIcon: 'clock', localEngineHealthIcon: 'cpu', mailboxHealthIcon: 'mailbox', privacyHealthIcon: 'privacy', stabilityHealthIcon: 'performance', activityEmptyIcon: 'refresh', cpuIcon: 'cpu', ramIcon: 'device', diskIcon: 'vault', networkIcon: 'performance', footerShield: 'security', footerRefresh: 'refresh', footerVault: 'vault', footerFeedback: 'help', footerHelp: 'help' };
  for (const [id, glyph] of Object.entries(mapping)) $(`#${id}`).innerHTML = icon(glyph, 22);
  document.querySelectorAll('[data-brand-image]').forEach(image => {
    const useFallback = () => {
      if (!image.isConnected) return;
      const fallback = document.createElement('span');
      fallback.className = 'brand-fallback';
      fallback.innerHTML = icon('security', 25);
      image.replaceWith(fallback);
    };
    image.addEventListener('error', useFallback, { once: true });
    if (image.complete && image.naturalWidth === 0) useFallback();
  });
}

function wireEvents() {
  document.addEventListener('click', event => {
    const target = event.target.closest('[data-nav]');
    if (target) { navigate(target.dataset.nav); return; }
    const scanAction = event.target.closest('[data-scan-action]');
    if (scanAction) {
      if (scanAction.dataset.scanAction === 'start' && !canRunCustomerScan()) showToast('No scan started. Customer scan service is unavailable.');
      else showToast('No active scan job is available.');
      return;
    }
    const action = event.target.closest('[data-action]');
    if (action?.dataset.action === 'health-details') navigate('settings');
    if (action?.dataset.action === 'feature-request') showToast('Feedback channel is not configured in this customer build.');
    if (action?.dataset.action === 'help') showToast('Help content is not connected yet.');
    const customerOperation = event.target.closest('[data-customer-operation]');
    if (customerOperation && !customerOperation.disabled) { startCustomerOperation(customerOperation.dataset.customerOperation); return; }
    const caption = event.target.closest('[data-window]');
    if (caption && window.chrome?.webview) window.chrome.webview.postMessage({ type: 'window-command', command: caption.dataset.window });
  });
  window.addEventListener('message', event => acceptHostMessage(event.data));
  if (window.chrome?.webview) window.chrome.webview.addEventListener('message', event => acceptHostMessage(event.data));
}

function acceptHostMessage(data) {
  if (!data || typeof data !== 'object') return;
  if (data.type === 'telemetry') applyTelemetry(data.value);
  if (data.type === 'health-result') {
    const resolve = requestMap.get(data.requestId);
    if (resolve) { requestMap.delete(data.requestId); resolve(data); }
  }
  if (data.type === 'customer-api-result') {
    const resolve = requestMap.get(data.requestId);
    if (resolve) { requestMap.delete(data.requestId); resolve(data); }
  }
  if (data.type === 'customer-api-operation-result') {
    const resolve = requestMap.get(data.requestId);
    if (resolve) { requestMap.delete(data.requestId); resolve(data); }
  }
}

function initialize() {
  initializeIcons();
  renderNav();
  renderQuickActions();
  updateHealth(null, null);
  wireEvents();
  void checkConnection();
  window.setInterval(() => {
    if (document.visibilityState === 'visible') void checkConnection();
  }, 20000);
  window.addEventListener('focus', () => void checkConnection());
}
initialize();
