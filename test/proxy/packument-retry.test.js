// Since 0.1.8: a packument request whose upstream sends no response headers in time is sent once more before the proxy answers
// 504 (recon's 11-01 replay: 9 of 1,004 packument GETs got the proxy's own 504 at the 10 s header timeout, and all 9 were served
// on a re-run minutes later). Only the header (or connect) timeout is retried, and only once; a tarball, an upstream error status
// and an unreachable upstream are as in 0.1.7. Written before the code.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fetchPackument, fetchTarball, UpstreamTimeoutError, UpstreamError } from '../../proxy/registry.js';

const close = (s) => new Promise((resolve) => { s.closeAllConnections?.(); s.close(() => resolve()); });

/** A loopback server; `route(req, n)` (n = 1 for the first request) returns { status, body } or 'hang' (never answers). */
async function server(route) {
  const log = [];
  const s = http.createServer((req, res) => {
    log.push(req.url);
    const r = route(req, log.length);
    if (r === 'hang') return;
    res.writeHead(r.status, { 'content-type': 'application/json' });
    res.end(r.body ?? '');
  });
  await new Promise((resolve) => s.listen(0, '127.0.0.1', resolve));
  return { s, log, base: `http://127.0.0.1:${s.address().port}` };
}

const config = (upstream) => ({ upstream, headersTimeoutMs: 150, bodyTimeoutMs: 5_000 });
const DOC = JSON.stringify({ name: 'p', versions: {} });

test('PR1 a packument whose first request gets no headers in time is sent again, and the second answer is served', async () => {
  const up = await server((req, n) => (n === 1 ? 'hang' : { status: 200, body: DOC }));
  try {
    const res = await fetchPackument('p', { config: config(up.base) });
    assert.equal(res.statusCode, 200);
    assert.equal(await res.body.text(), DOC);
    assert.deepEqual(up.log, ['/p', '/p']);
  } finally { await close(up.s); }
});

test('PR2 a packument that times out twice is a timeout after exactly two requests', async () => {
  const up = await server(() => 'hang');
  try {
    await assert.rejects(fetchPackument('p', { config: config(up.base) }), (err) => err instanceof UpstreamTimeoutError);
    assert.deepEqual(up.log, ['/p', '/p']);
  } finally { await close(up.s); }
});

test('PR3 a tarball is not retried: one request, then the timeout, as in 0.1.7', async () => {
  const up = await server(() => 'hang');
  try {
    await assert.rejects(fetchTarball('p', 'p-1.0.0.tgz', { config: config(up.base) }), (err) => err instanceof UpstreamTimeoutError);
    assert.deepEqual(up.log, ['/p/-/p-1.0.0.tgz']);
  } finally { await close(up.s); }
});

test('PR4 an upstream error status is returned as it is, not retried (npm retries a 5xx itself)', async () => {
  const up = await server(() => ({ status: 503, body: '{}' }));
  try {
    const res = await fetchPackument('p', { config: config(up.base) });
    await res.body.dump();
    assert.equal(res.statusCode, 503);
    assert.deepEqual(up.log, ['/p']);
  } finally { await close(up.s); }
});

test('PR5 an unreachable upstream is an upstream error at once, not retried', async () => {
  const up = await server(() => ({ status: 200, body: DOC }));
  const base = up.base; await close(up.s);
  const t0 = Date.now();
  await assert.rejects(fetchPackument('p', { config: config(base) }), (err) => err instanceof UpstreamError && !(err instanceof UpstreamTimeoutError));
  assert.ok(Date.now() - t0 < 2_000);
});
