// 0.1.4 release-readiness audit (G4 tables dated note 4): R1 carry-forward from the version's history, R3 MC's registry
// manifest refreshed when the hook map lost it, R4 N1h's fetches bounded and fed from parsed packuments, R7 /_chaingate/self
// names its witness database. Expected results are in the note, written before this file. Fixture packages are synthetic;
// nothing is installed or run.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createProxyServer } from '../../proxy/server.js';
import { resetDependencyCache, getDependency } from '../../gates/dependency-cache.js';
import { forgetManifestHooks, rememberManifestHooks, MAX_PACKAGES } from '../../proxy/manifest-check.js';
import { fetchPending, MAX_IN_FLIGHT } from '../../proxy/dependency-judge.js';

const H = 3_600_000;
const T0 = Date.parse('2026-03-01T00:00:00Z');
const at = (h) => new Date(T0 + h * H).toISOString();
function tgz(pj) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g4a-'));
  try {
    fs.mkdirSync(path.join(dir, 'package'));
    fs.writeFileSync(path.join(dir, 'package', 'package.json'), JSON.stringify(pj));
    execFileSync('tar', ['-czf', path.join(dir, 'o.tgz'), '-C', dir, 'package']);
    return fs.readFileSync(path.join(dir, 'o.tgz'));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
const TARBALLS = {
  '/m/-/m-1.0.0.tgz': tgz({ name: 'm', version: '1.0.0' }),
  '/m/-/m-1.1.0.tgz': tgz({ name: 'm', version: '1.1.0', scripts: { postinstall: 'node s.js' } }),
};
const DOCS = {
  m: { name: 'm', 'dist-tags': { latest: '1.1.0' },
    versions: { '1.0.0': { name: 'm', version: '1.0.0' }, '1.1.0': { name: 'm', version: '1.1.0' } }, time: { '1.0.0': at(0), '1.1.0': at(48) } },
  carrier: { name: 'carrier', 'dist-tags': { latest: '1.1.0' },
    versions: { '1.0.0': { name: 'carrier', version: '1.0.0', dependencies: { a: '^1.0.0' } },
      '1.1.0': { name: 'carrier', version: '1.1.0', dependencies: { a: '^1.0.0', evil: '^2.0.0' } } },
    time: { '1.0.0': at(0), '1.1.0': at(48) } },
  evil: { name: 'evil', 'dist-tags': { latest: '2.0.1' }, versions: { '2.0.1': { name: 'evil', version: '2.0.1', scripts: { postinstall: 'node drop.js' } } },
    time: { '2.0.1': at(40) } },
};

async function withProxy(fn, { failDoc = () => false } = {}) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g4p-'));
  const hits = {};
  const upstream = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    hits[u.slice(1)] = (hits[u.slice(1)] ?? 0) + 1;
    if (TARBALLS[u]) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(TARBALLS[u]); return; }
    if (u.includes('/-/')) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end('tarball-bytes'); return; }
    const d = DOCS[u.slice(1)];
    if (!d || failDoc(u.slice(1))) { res.writeHead(d ? 500 : 404, { 'content-type': 'application/json' }); res.end('{}'); return; }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(d));
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const dbPath = path.join(dir, 'witness.db');
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`,
    witnessDbPath: dbPath, headersTimeoutMs: 10_000, bodyTimeoutMs: 10_000 }, { dependencyBudgetMs: 2_000 });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  const realErr = console.error; console.error = () => {};
  try { return await fn({ base, proxy, hits, dbPath }); } finally {
    console.error = realErr;
    await new Promise((r) => proxy.close(r)); upstream.closeAllConnections?.(); await new Promise((r) => upstream.close(r));
    fs.rmSync(dir, { recursive: true, force: true }); resetDependencyCache(); forgetManifestHooks();
  }
}
const get = (u, headers = {}) => new Promise((resolve, reject) => http.get(u, { agent: false, headers }, (res) => {
  const chunks = []; res.on('data', (x) => chunks.push(x)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
}).on('error', reject));
const settle = () => new Promise((r) => setTimeout(r, 150));
const gateOf = (proxy, pkg, v, gate) => proxy.witnessDb.getLatestDecision(pkg, v).gates_fired.find((g) => g.gate === gate);

test('G4-7a (R1) a row written without MC (a 0.1.3 rollback) does not erase the recorded MC WARN', async () => {
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/m`);
    await get(`${base}/m/-/m-1.1.0.tgz`);
    await settle();
    assert.equal(gateOf(proxy, 'm', '1.1.0', 'install-manifest-mismatch')?.result, 'WARN');
    // what 0.1.3 writes when it re-evaluates the version: its own gates, no MC, no N1h
    proxy.witnessDb.insertGateDecision('m', '1.1.0', 'ALLOW', [{ gate: 'content-hash', result: 'ALLOW', detail: 'cft-policy-1.1 x' }]);
    await get(`${base}/m`);
    const latest = proxy.witnessDb.getLatestDecision('m', '1.1.0');
    assert.equal(latest.disposition, 'WARN', JSON.stringify(latest));
    assert.equal(gateOf(proxy, 'm', '1.1.0', 'install-manifest-mismatch')?.result, 'WARN');
  });
});

test('G4-7b (R1) allow, then overrides revoke: the MC WARN and the judged N1h row come back', async () => {
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/m`); await get(`${base}/m/-/m-1.1.0.tgz`); await settle();
    await get(`${base}/carrier`); await get(`${base}/carrier/-/carrier-1.1.0.tgz`);
    assert.equal(gateOf(proxy, 'carrier', '1.1.0', 'dependency-hooks')?.result, 'WARN');
    for (const [pkg, v] of [['m', '1.1.0'], ['carrier', '1.1.0']]) proxy.witnessDb.insertOverride(pkg, v, 'test');
    await get(`${base}/m`); await get(`${base}/carrier`);
    assert.ok(proxy.witnessDb.getLatestDecision('m', '1.1.0').gates_fired.some((g) => g.gate === 'override'), 'the override row is newest');
    for (const [pkg, v] of [['m', '1.1.0'], ['carrier', '1.1.0']]) proxy.witnessDb.deleteOverride(pkg, v);
    resetDependencyCache();                                        // a cold cache: the judgement must come from the record
    await get(`${base}/m`); await get(`${base}/carrier`);
    // the decision that APPLIES once the override is gone (what the tarball gate, the notice and the report read)
    const app = (pkg, v) => proxy.witnessDb.getApplicableDecision(pkg, v, { overrideLive: false }).latest;
    assert.equal(app('m', '1.1.0').gates_fired.find((g) => g.gate === 'install-manifest-mismatch')?.result, 'WARN');
    const n1h = app('carrier', '1.1.0').gates_fired.find((g) => g.gate === 'dependency-hooks');
    assert.equal(n1h?.result, 'WARN', JSON.stringify(n1h));
    assert.equal(app('carrier', '1.1.0').disposition, 'WARN');
    assert.equal(app('m', '1.1.0').disposition, 'WARN');
    // and the next download carries the notice again
    assert.match((await get(`${base}/m/-/m-1.1.0.tgz`)).headers['npm-notice'] ?? '', /install scripts differ/);
  });
});

test('G4-8a (R3) the hook map evicted the package but the version counts as evaluated: MC is still checked at the first download', async () => {
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/m`);
    for (let i = 0; i <= MAX_PACKAGES; i += 1) rememberManifestHooks(`filler-${i}`, { '1.0.0': {} });
    const t = await get(`${base}/m/-/m-1.1.0.tgz`);
    assert.equal(t.status, 200);
    assert.ok(t.body.equals(TARBALLS['/m/-/m-1.1.0.tgz']));
    await settle();
    assert.equal(gateOf(proxy, 'm', '1.1.0', 'install-manifest-mismatch')?.result, 'WARN');
  });
});

test('G4-8b (R3) the refresh fails: the tarball is served as decided before, and MC records not checked', async () => {
  let fail = false;
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/m`);
    forgetManifestHooks();
    fail = true;
    const t = await get(`${base}/m/-/m-1.1.0.tgz`);
    assert.equal(t.status, 200, 'the stored evaluation still serves it');
    await settle();
    const row = gateOf(proxy, 'm', '1.1.0', 'install-manifest-mismatch');
    assert.equal(row?.result, 'SKIP');
    assert.match(row.detail, /not checked: no registry manifest at hand/);
  }, { failDoc: (n) => fail && n === 'm' });
});

test('G4-9a (R4) a dependency packument npm already fetched through the proxy is not fetched again at tarball time', async () => {
  await withProxy(async ({ base, proxy, hits }) => {
    await get(`${base}/carrier`);
    await get(`${base}/evil`);                                      // npm resolves the new dependency through the proxy
    assert.ok(getDependency('evil')?.summary, 'the served document filled the dependency cache');
    const t = await get(`${base}/carrier/-/carrier-1.1.0.tgz`);
    assert.match(t.headers['npm-notice'] ?? '', /adds a dependency that runs install scripts/);
    assert.equal(hits.evil, 1, 'one upstream fetch of evil');
    assert.equal(gateOf(proxy, 'carrier', '1.1.0', 'dependency-hooks')?.result, 'WARN');
  });
});

test('G4-9b (R4) at most MAX_IN_FLIGHT dependency fetches run at once; queued ones past every budget are never started', async () => {
  resetDependencyCache();
  assert.equal(MAX_IN_FLIGHT, 8);
  let active = 0; let peak = 0; let started = 0;
  const release = [];
  const fetchPackument = (name) => {
    started += 1; active += 1; peak = Math.max(peak, active);
    return new Promise((resolve) => {
      release.push(() => { active -= 1; resolve({ statusCode: 404, body: { dump: async () => {} } }); });
    });
  };
  const pending = Array.from({ length: 20 }, (_, i) => ({ name: `d${i}`, target: `d${i}` }));
  const r = await fetchPending(pending, { fetchPackument, budgetMs: 100 });
  assert.equal(r.timedOut.length, 20, 'nothing answered within the budget');
  assert.equal(peak, MAX_IN_FLIGHT);
  assert.equal(started, MAX_IN_FLIGHT);
  for (const f of release.splice(0)) f();                          // the running ones finish: the expired queue is dropped
  await new Promise((r2) => setTimeout(r2, 50));
  assert.equal(started, MAX_IN_FLIGHT, 'queued fetches whose budget passed were not started');
  for (const f of release.splice(0)) f();
  // a later request with its own budget gets fetched
  const again = await fetchPending([{ name: 'late', target: 'late' }], { fetchPackument: async () => ({ statusCode: 404, body: { dump: async () => {} } }), budgetMs: 500 });
  assert.deepEqual(again.timedOut, []);
  resetDependencyCache();
});

test('G4-10 (R7) /_chaingate/self names the witness database the proxy reads (its real path)', async () => {
  await withProxy(async ({ base, dbPath }) => {
    const self = JSON.parse((await get(`${base}/_chaingate/self`)).body.toString());
    assert.equal(self.witness_db, fs.realpathSync(dbPath));
  });
});

test('G4-24 (W4) a version that will be refused is not refreshed for MC (no upstream metadata fetch first)', async () => {
  await withProxy(async ({ base, proxy, hits }) => {
    await get(`${base}/m`);
    proxy.witnessDb.insertGateDecision('m', '1.1.0', 'BLOCK', [{ gate: 'content-hash', result: 'BLOCK', detail: 'content differs from the recorded baseline' }]);
    forgetManifestHooks();
    const before = hits.m;
    const t = await get(`${base}/m/-/m-1.1.0.tgz`);
    assert.equal(t.status, 403);
    assert.equal(hits.m, before, 'no refresh fetch for a refused version');
  });
});
