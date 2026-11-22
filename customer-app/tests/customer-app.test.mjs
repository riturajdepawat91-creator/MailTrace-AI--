import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canRunCustomerScan, normalizeScanConfig, SCAN_LIMITS, SCAN_RANGES, summarizeScanConfig } from '../src/ui-state.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('customer navigation includes each requested screen and remains app-local', () => {
  const app = read('src/app.js');
  for (const label of ['Overview', 'Mailbox Connections', 'Continuous Protection', 'Manual Scan', 'Scan Activity', 'Threat Center', 'Quarantine', 'Reports', 'Settings']) assert.ok(app.includes(`'${label}'`) || app.includes(`"${label}"`), `missing ${label}`);
  assert.match(app, /function navigate\(id\)/);
  assert.match(app, /renderPage\(id\)/);
});

test('overview quick actions render five available customer destinations', () => {
  const app = read('src/app.js');
  const quick = app.slice(app.indexOf('const quick = ['), app.indexOf('const $ ='));
  assert.equal((quick.match(/\{ id:/g) || []).length, 5);
  for (const id of ['manual-scan', 'mailbox-connections', 'threat-center', 'quarantine', 'reports']) assert.ok(quick.includes(`'${id}'`));
  assert.match(app, /function renderQuickActions\(\)/);
});

test('manual scan ranges, limits, normalization and honest operation gate work', () => {
  assert.deepEqual(SCAN_RANGES, [1, 3, 7, 14, 30]);
  assert.equal(SCAN_LIMITS.maxEmails, 5000);
  assert.equal(SCAN_LIMITS.maxSizeMb, 250);
  const config = normalizeScanConfig({ days: 14, mailbox: 'none', folder: 'Inbox', mode: 'deep', maxEmails: 9000, maxSizeMb: -4 });
  assert.equal(config.days, 14);
  assert.equal(config.mode, 'deep');
  assert.equal(config.maxEmails, 5000);
  assert.equal(config.maxSizeMb, 1);
  assert.match(summarizeScanConfig(config), /14-day range.*Deep scan.*5000 messages/);
  assert.equal(canRunCustomerScan(), false);
  assert.equal(canRunCustomerScan({ serviceAvailable: false }), false);
  assert.equal(canRunCustomerScan({ serviceAvailable: true }), true);
});

test('scan controls are present but cannot falsely start a customer job', () => {
  const app = read('src/app.js');
  const scan = app.slice(app.indexOf('function scanScreen()'), app.indexOf('function activityScreen()'));
  for (const action of ['start', 'pause', 'resume', 'cancel', 'retry']) assert.ok(scan.includes(`data-scan-action="${action}"`));
  assert.match(scan, /No scan started/);
  assert.match(app, /No scan started\. Customer scan service is unavailable/);
  assert.match(scan, /data-scan="days"/);
  assert.match(scan, /data-scan="mailbox"/);
  assert.match(scan, /data-scan="folder"/);
  assert.match(scan, /data-scan="mode"/);
});

test('mailbox, threat, quarantine, reports and settings show unavailable states only', () => {
  const app = read('src/app.js');
  for (const snippet of ['Sign-in unavailable', 'Not reported', 'No customer records are available', 'No customer quarantine service', 'No customer reports available', 'No customer Agent']) assert.ok(app.includes(snippet), `missing honest state: ${snippet}`);
  assert.match(app, /Connect unavailable/);
  assert.match(app, /Export unavailable/);
  assert.match(app, /No quarantine, release, deletion, or email modification action is implemented/);
});

test('customer app does not submit mailbox or invoke analysis and reputation APIs', () => {
  const app = read('src/app.js');
  const server = read('server.mjs');
  assert.doesNotMatch(app, /\/api\/(?:analyze-email|synthetic-analysis|messages|gmail)/i);
  assert.doesNotMatch(server, /\/api\/(?:analyze-email|synthetic-analysis|messages|gmail)/i);
  assert.match(server, /\/api\/health/);
  assert.match(server, /\/api\/ready/);
  assert.match(server, /Only a loopback MailTrace API address is allowed/);
});

test('customer app automatically checks only local health and readiness endpoints', () => {
  const app = read('src/app.js');
  const server = read('server.mjs');
  assert.match(app, /void checkConnection\(\)/);
  assert.match(app, /setInterval\(\(\) => \{[\s\S]*?void checkConnection\(\)/);
  assert.match(app, /\/integration\/health\?base=/);
  assert.match(server, /fetch\(healthUrl/);
  assert.match(server, /fetch\(readyUrl/);
  assert.doesNotMatch(server, /\/api\/(?:alerts|cases|employee\/reports|evidence|investigations|synthetic-analysis)/i);
});

test('desktop host starts the SOC backend and isolated Customer API separately', () => {
  const host = read('windows/MainWindow.xaml.cs');
  const installer = read('installer/build-installer.ps1');
  assert.match(host, /EnsureBackendAvailableAsync\(baseUrl!\)/);
  assert.match(host, /--port[\s\S]*?8002/);
  assert.doesNotMatch(host, /MAILTRACE_DISABLE_BACKGROUND_WORKERS/);
  assert.match(host, /MAILTRACE_BACKEND_DIR/);
  assert.match(host, /backend-path\.txt/);
  assert.match(host, /Local\\\\MailTraceCustomerBackendStart/);
  assert.match(host, /EnsureCustomerApiAvailableAsync/);
  assert.match(host, /Local\\\\MailTraceCustomerApiStart/);
  assert.match(host, /--port[\s\S]*?8100/);
  assert.match(installer, /customer_api/);
  assert.match(installer, /backend-path\.txt/);
  assert.doesNotMatch(host, /--port[\s\S]*?8000/);
});

test('native customer sign-in uses system-browser PKCE and keeps tokens out of WebView storage', () => {
  const oidc = read('windows/OidcSessionManager.cs');
  const host = read('windows/MainWindow.xaml.cs');
  const app = read('src/app.js');
  assert.match(oidc, /code_challenge_method"\] = "S256"/);
  assert.match(oidc, /code_verifier/);
  assert.match(oidc, /Process\.Start\(new ProcessStartInfo\(authUri\) \{ UseShellExecute = true \}\)/);
  assert.match(oidc, /CryptProtectData/);
  assert.match(oidc, /CryptUnprotectData/);
  assert.match(oidc, /\/v1\/auth\/logout/);
  assert.match(host, /source\.Host\.Equals\("mailtrace\.invalid"/);
  assert.match(host, /"login" => await OidcSessionManager\.Instance\.LoginAsync\(\)/);
  assert.doesNotMatch(app, /localStorage\.(?:setItem|getItem)\([^)]*(?:token|auth)/i);
  assert.doesNotMatch(oidc, /PostWebMessageAsJson\([^)]*token/i);
});

test('all brand/icon references are local and have a local fallback', () => {
  const html = read('src/index.html');
  const app = read('src/app.js');
  const icons = read('src/icons.js');
  const css = read('src/styles.css');
  assert.match(html, /rel="icon"[^>]+\.\/assets\/mailtrace-mark\.svg/);
  assert.equal((html.match(/data-brand-image/g) || []).length, 3);
  assert.match(app, /brand-fallback/);
  assert.match(icons, /export function icon/);
  assert.match(css, /\.brand-fallback/);
  assert.doesNotMatch(html, /<(?:img|script|link)[^>]+(?:src|href)=["']https?:\/\//i);
  assert.doesNotMatch(css, /url\(["']?https?:\/\//i);
});

test('bundled MailTrace logo matches the SOC shield, envelope, trace paths and colors', () => {
  const logo = read('assets/mailtrace-mark.svg');
  for (const fragment of [
    'M24 5 L37 10 V21 C37 30 32 37 24 42 C16 37 11 30 11 21 V10 Z',
    'M15.5 17.5 H32.5 V29 H15.5 Z',
    'M16 18 L24 24 L32 18',
    'M18 33 H21.5 L24 30 L27 33 H30',
    'stroke: #00c8ff',
    'stroke: #8bdcf3',
  ]) assert.ok(logo.includes(fragment), `SOC brand fragment missing: ${fragment}`);
});

test('HTML asset paths resolve inside customer-app for browser and WebView2 layouts', () => {
  const html = read('src/index.html');
  const refs = [...html.matchAll(/(?:src|href)=["'](\.[^"']+)["']/g)].map(match => match[1]);
  assert.ok(refs.length >= 5);
  for (const ref of refs) {
    const relative = ref.startsWith('./assets/') ? path.join('assets', ref.slice('./assets/'.length)) : path.join('src', ref.slice(2));
    assert.ok(fs.statSync(path.join(root, relative)).isFile(), `${ref} did not resolve to ${relative}`);
  }
  assert.match(read('windows/MailTraceCustomer.csproj'), /Assets\\Web\\assets/);
});

test('settings include resource, reconciliation, notifications and Agent state', () => {
  const app = read('src/app.js');
  for (const item of ['CPU limit', 'Memory limit', 'Reconciliation schedule', 'Desktop notifications', 'Agent connection']) assert.ok(app.includes(item), `missing ${item}`);
  assert.match(app, /NOT CONFIGURABLE/);
  assert.match(app, /serviceHealthPill/);
});

test('responsive layout includes scroll handling and focus-visible keyboard states', () => {
  const css = read('src/styles.css');
  assert.match(css, /\.workspace \{[^}]*overflow: auto/s);
  assert.match(css, /\.sidebar \{[^}]*overflow-y: auto/s);
  assert.match(css, /:focus-visible/);
  assert.match(css, /max-width: 1440px/);
  assert.match(css, /max-width: 900px/);
  assert.match(css, /max-width: 640px/);
});

test('required isolated application files exist', () => {
  for (const file of ['package.json', 'README.md', 'server.mjs', 'src/index.html', 'src/styles.css', 'src/app.js', 'src/ui-state.js', 'src/icons.js', 'assets/mailtrace-mark.svg', 'windows/MailTraceCustomer.csproj']) assert.ok(fs.statSync(path.join(root, file)).isFile(), `${file} missing`);
});
