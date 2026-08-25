import http from 'node:http';
import { createReadStream, statSync } from 'node:fs';
import { extname, join, normalize, resolve, sep } from 'node:path';

const root = resolve(process.env.KASPA_PORTAL_E2E_SITE || '');
const port = Number(process.env.KASPA_PORTAL_E2E_BROWSER_PORT || '4173');
if (!root) throw new Error('KASPA_PORTAL_E2E_SITE is required');

const types = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.mjs', 'text/javascript; charset=utf-8'],
  ['.wasm', 'application/wasm'],
  ['.json', 'application/json; charset=utf-8'],
]);

function pathFor(url) {
  const pathname = new URL(url, 'http://127.0.0.1').pathname;
  const rel = normalize(decodeURIComponent(pathname)).replace(/^([/\\])+/, '') || 'index.html';
  const candidate = resolve(join(root, rel));
  if (candidate !== root && !candidate.startsWith(root + sep)) return null;
  return candidate;
}

const server = http.createServer((req, res) => {
  const file = pathFor(req.url || '/');
  if (!file) {
    res.writeHead(403).end('forbidden');
    return;
  }
  try {
    if (!statSync(file).isFile()) throw new Error('not file');
    res.setHeader('Content-Type', types.get(extname(file)) || 'application/octet-stream');
    res.setHeader('Cache-Control', 'no-store');
    createReadStream(file).pipe(res);
  } catch {
    res.writeHead(404).end('not found');
  }
});
server.listen(port, '127.0.0.1');
