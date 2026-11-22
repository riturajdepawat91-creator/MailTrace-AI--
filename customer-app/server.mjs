import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.join(root, 'src');
const port = Number(process.env.MAILTRACE_CUSTOMER_PREVIEW_PORT || 4173);
const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json; charset=utf-8' };

function localBase(value) {
  try {
    const url = new URL(value || 'http://127.0.0.1:8002');
    if (!['http:', 'https:'].includes(url.protocol) || !['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname)) return null;
    return url.origin;
  } catch { return null; }
}

const server = http.createServer(async (request, response) => {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'");
  const url = new URL(request.url || '/', `http://${request.headers.host || '127.0.0.1'}`);
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' }); response.end('Method not allowed'); return;
  }
  if (url.pathname === '/integration/health' || url.pathname === '/integration/ready') {
    const base = localBase(url.searchParams.get('base'));
    if (!base) { response.writeHead(400, { 'Content-Type': types['.json'] }); response.end(JSON.stringify({ error: 'Only a loopback MailTrace API address is allowed.' })); return; }
    const healthUrl = `${base}/api/health`;
    const readyUrl = `${base}/api/ready`;
    try {
      const [healthResponse, readyResponse] = await Promise.all([
        fetch(healthUrl, { signal: AbortSignal.timeout(2200), redirect: 'error' }),
        fetch(readyUrl, { signal: AbortSignal.timeout(2200), redirect: 'error' }),
      ]);
      const health = await healthResponse.json();
      const ready = await readyResponse.json();
      response.writeHead(healthResponse.ok ? 200 : 502, { 'Content-Type': types['.json'], 'Cache-Control': 'no-store' });
      response.end(JSON.stringify({ health, ready }));
    } catch {
      response.writeHead(503, { 'Content-Type': types['.json'], 'Cache-Control': 'no-store' });
      response.end(JSON.stringify({ error: 'Local MailTrace health/readiness endpoints are unavailable.' }));
    }
    return;
  }
  let requested = url.pathname === '/' ? '/index.html' : decodeURIComponent(url.pathname);
  const assetRequest = requested.startsWith('/assets/');
  const staticRoot = assetRequest ? path.join(root, 'assets') : webRoot;
  if (assetRequest) requested = requested.slice('/assets'.length);
  let file = path.resolve(staticRoot, `.${requested}`);
  if (!file.startsWith(`${path.resolve(staticRoot)}${path.sep}`) && file !== path.join(staticRoot, 'index.html')) {
    response.writeHead(403); response.end('Forbidden'); return;
  }
  try {
    const stat = await fs.promises.stat(file);
    if (!stat.isFile()) throw new Error('not a file');
    response.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
    if (request.method === 'HEAD') response.end(); else fs.createReadStream(file).pipe(response);
  } catch {
    response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); response.end('Not found');
  }
});

server.on('error', error => { process.stderr.write(`Preview server could not start (${error.code || 'error'}).\n`); process.exitCode = 1; });
server.listen(port, '127.0.0.1', () => process.stdout.write(`MailTrace Customer preview: http://127.0.0.1:${port}\n`));
