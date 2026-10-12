// 0.1.4 group 3, unit 3b — N1h judged at tarball time (D-N3), the dependency cache (D-N4) and the record's carry-forward
// (D-N5). Expected results: decision tables ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G3-TIER1-20261012.md §3, written
// before this file. Fixture packages are synthetic; nothing is installed or run.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createProxyServer } from '../../proxy/server.js';
import { resetDependencyCache } from '../../gates/dependency-cache.js';
import { renderReport } from '../../cli/report-render.js';

const H = 3_600_000;
const T0 = Date.parse('2026-03-01T00:00:00Z');
const at = (h) => new Date(T0 + h * H).toISOString();
const DOCS = {
  carrier: { name: 'carrier', 'dist-tags': { latest: '1.1.0' },
    versions: { '1.0.0': { name: 'carrier', version: '1.0.0', dependencies: { a: '^1.0.0' } },
      '1.1.0': { name: 'carrier', version: '1.1.0', dependencies: { a: '^1.0.0', evil: '^2.0.0' } } },
    time: { '1.0.0': at(0), '1.1.0': at(48) } },
  evil: { name: 'evil', 'dist-tags': { latest: '2.0.1' }, versions: { '2.0.1': { name: 'evil', version: '2.0.1', scripts: { postinstall: 'node drop.js' } } },
    time: { '2.0.1': at(40) } },
  slowcarrier: { name: 'slowcarrier', 'dist-tags': { latest: '1.1.0' },
    versions: { '1.0.0': { name: 'slowcarrier', version: '1.0.0' }, '1.1.0': { name: 'slowcarrier', version: '1.1.0', dependencies: { stall: '^1' } } },
    time: { '1.0.0': at(0), '1.1.0': at(48) } },
};

async function withProxy(fn) {
  resetDependencyCache();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g3b-'));
  const hits = {};
  const held = [];
  const upstream = http.createServer((req, res) => {
    const name = decodeURIComponent(req.url.split('?')[0]).slice(1);
    hits[name] = (hits[name] ?? 0) + 1;
    if (name.includes('/-/')) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end('tarball-bytes'); return; }
    if (name === 'stall') { held.push(res); return; }                                // never answers
    const d = DOCS[name];
    if (!d) { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); return; }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(d));
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const dbPath = path.join(dir, 'witness.db');
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`, witnessDbPath: dbPath,
    headersTimeoutMs: 20_000, bodyTimeoutMs: 20_000 }, { dependencyBudgetMs: 600 });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  const realErr = console.error; console.error = () => {};
  try {
    return await fn({ base, hits, proxy, dbPath });
  } finally {
    console.error = realErr;
    for (const r of held) r.destroy();
    await new Promise((r) => proxy.close(r)); upstream.closeAllConnections?.(); await new Promise((r) => upstream.close(r));
    fs.rmSync(dir, { recursive: true, force: true }); resetDependencyCache();
  }
}
const get = (u, headers = {}) => new Promise((resolve, reject) => http.get(u, { agent: false, headers }, (res) => {
  let b = ''; res.on('data', (x) => { b += x; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
}).on('error', reject));

test('G3b-7 (D-N3, D-N4) a release adding a hooked dependency: N1h WARN on that tarball response, in the record and the report; fetched once', async () => {
  await withProxy(async ({ base, hits, proxy }) => {
    await get(`${base}/carrier`, { 'npm-session': 'g3b7' });
    const t = await get(`${base}/carrier/-/carrier-1.1.0.tgz`, { 'npm-session': 'g3b7' });
    assert.equal(t.status, 200);
    assert.equal(t.headers['npm-notice'], 'chaingate: WARNING carrier@1.1.0: it adds a dependency that runs install scripts. Details: chaingate why carrier@1.1.0');
    await get(`${base}/carrier/-/carrier-1.1.0.tgz`, { 'npm-session': 'g3b7' });
    assert.equal(hits.evil, 1, 'the dependency packument is cached');
    const rep = JSON.parse((await get(`${base}/_chaingate/report`)).body);
    const e = rep.installs[0].events.find((x) => x.kind === 'served' && x.version === '1.1.0');
    assert.deepEqual(e.named, ['dependency-hooks']);
    assert.match(e.reason, /^dependency-hooks: .*evil@2\.0\.1 \(postinstall\)/);
    const text = renderReport(rep, { source: 'proxy' }).text;
    assert.ok(text.includes('carrier@1.1.0  NAMED WARNING: it adds a dependency that runs install scripts'), text);
    assert.ok(text.includes('  baseline: packument'));
    assert.equal((await get(`${base}/carrier/-/carrier-1.0.0.tgz`)).headers['npm-notice'], undefined, '1.0.0 adds nothing');
  });
});

test('G3b-8 (D-N3) the budget: a dependency whose registry never answers -> not evaluable within the budget; the tarball is served', async () => {
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/slowcarrier`);
    const t0 = Date.now();
    const t = await get(`${base}/slowcarrier/-/slowcarrier-1.1.0.tgz`);
    assert.equal(t.status, 200);
    assert.ok(Date.now() - t0 < 5_000, `${Date.now() - t0} ms`);
    assert.equal(t.headers['npm-notice'], undefined);
    const rep = JSON.parse((await get(`${base}/_chaingate/report?all=1`)).body);
    const e = rep.installs.flatMap((i) => i.events).find((x) => x.kind === 'served' && x.package === 'slowcarrier');
    assert.notEqual(e.class, 'named');
    // G3 dated note 3.7: the record says WHY -- not evaluable within the budget, never clean
    const row = proxy.witnessDb.getLatestDecision('slowcarrier', '1.1.0').gates_fired.find((g) => g.gate === 'dependency-hooks');
    assert.equal(row.result, 'SKIP');
    assert.match(row.detail, /not evaluable: stall \(no answer within/);
  });
});

test('G3b-9 (D-N5) the record keeps the judgement: a later observation with a cold cache writes no new row and keeps the WARN', async () => {
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/carrier`);
    await get(`${base}/carrier/-/carrier-1.1.0.tgz`);
    await new Promise((r) => setTimeout(r, 200));            // 3c: the MC outcome is written after the response ends
    const db = proxy.witnessDb;
    const rows = () => db.getDecisionHistory('carrier', '1.1.0').length;
    const n = rows();
    resetDependencyCache();
    await get(`${base}/carrier`);
    assert.equal(rows(), n, 'no new row because a cache expired');
    const latest = db.getLatestDecision('carrier', '1.1.0');
    assert.equal(latest.gates_fired.find((g) => g.gate === 'dependency-hooks').result, 'WARN');
    assert.equal(latest.disposition, 'WARN');
  });
});
