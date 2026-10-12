// 0.1.4 group 3, unit 3b — review fixes (G3 dated note 3; G3b-12..G3b-20). Expected results: decision tables
// ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G3-TIER1-20261012.md, dated note 3, written before this file and the fixes.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createProxyServer } from '../../proxy/server.js';
import * as N from '../../gates/dependency-hooks.js';
import { setDependencyDoc, getDependency, resetDependencyCache, MAX_ENTRIES } from '../../gates/dependency-cache.js';
import { judgeAtTarball } from '../../proxy/dependency-judge.js';
import { createGateRunner, DEFAULT_GATE_MODULES } from '../../gates/index.js';
import { classify } from '../../witness/row-class.js';
import { lastVersionWithoutSignal } from '../../witness/last-without-signal.js';
import { openWitnessDB } from '../../witness/db.js';

const H = 3_600_000;
const T0 = Date.parse('2026-03-01T00:00:00Z');
const at = (h) => new Date(T0 + h * H).toISOString();
const carrier = (name, deps) => ({ name, 'dist-tags': { latest: '1.1.0' },
  versions: { '1.0.0': { name, version: '1.0.0' }, '1.1.0': { name, version: '1.1.0', dependencies: deps } },
  time: { '1.0.0': at(0), '1.1.0': at(48) } });
const hooked = (name, v = '1.0.0') => ({ name, 'dist-tags': { latest: v }, versions: { [v]: { name, version: v, scripts: { postinstall: 'x' } } }, time: { [v]: at(10) } });
const clean = (name, v = '1.0.0') => ({ name, 'dist-tags': { latest: v }, versions: { [v]: { name, version: v } }, time: { [v]: at(10) } });

async function withProxy(docs, fn, { status = {} } = {}) {
  resetDependencyCache();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g3br-'));
  const hits = {}; const auth = {};
  const upstream = http.createServer((req, res) => {
    const name = decodeURIComponent(req.url.split('?')[0]).slice(1);
    hits[name] = (hits[name] ?? 0) + 1;
    auth[name] = req.headers.authorization;
    if (name.includes('/-/')) { res.writeHead(200); res.end('x'); return; }
    const st = typeof status[name] === 'function' ? status[name]() : status[name];
    if (st && st !== 200) { res.writeHead(st, { 'content-type': 'application/json' }); res.end('{}'); return; }
    const d = docs[name];
    if (!d) { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); return; }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(d));
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`,
    witnessDbPath: path.join(dir, 'witness.db'), headersTimeoutMs: 20_000, bodyTimeoutMs: 20_000 }, { dependencyBudgetMs: 800 });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  const realErr = console.error; console.error = () => {};
  try { return await fn({ base, hits, auth, proxy }); } finally {
    console.error = realErr;
    await new Promise((r) => proxy.close(r)); upstream.closeAllConnections?.(); await new Promise((r) => upstream.close(r));
    fs.rmSync(dir, { recursive: true, force: true }); resetDependencyCache();
  }
}
const get = (u, headers = {}) => new Promise((resolve, reject) => http.get(u, { agent: false, headers }, (res) => {
  let b = ''; res.on('data', (x) => { b += x; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
}).on('error', reject));
const n1h = (proxy, pkg, v) => proxy.witnessDb.getLatestDecision(pkg, v).gates_fired.find((g) => g.gate === 'dependency-hooks');

test('G3b-12 (note 3.1) cost: 10,000 versions x 30 dependencies evaluated in under 3 s', () => {
  resetDependencyCache();
  const versions = {}; const time = {};
  for (let i = 0; i < 10_000; i += 1) {
    const deps = {}; for (let d = 0; d < 30; d += 1) deps[`dep${(i + d) % 400}`] = '^1.0.0';
    const v = `1.${Math.floor(i / 100)}.${i % 100}`;
    versions[v] = { version: v, dependencies: deps }; time[v] = at(i);
  }
  const t = Date.now();
  for (const v of Object.keys(versions)) N.default.evaluate({ version: v, rawVersions: versions, rawTimes: time });
  assert.ok(Date.now() - t < 3000, `${Date.now() - t} ms`);
});

test('G3b-13 (note 3.2) an over-long spec or name is not evaluable, the lists stay valid, and the other dependencies are judged', () => {
  resetDependencyCache();
  setDependencyDoc('bad', hooked('bad'));
  const long = `>=1.0.0${' '.repeat(300)}<2`;
  const doc = carrier('c', { bad: '^1.0.0', sneaky: long });
  const runGates = createGateRunner({ modules: DEFAULT_GATE_MODULES });
  const row = (d) => runGates({ ecosystem: 'npm', packageName: 'c', version: '1.1.0', incoming: { version: '1.1.0' }, rawVersions: d.versions,
    rawTimes: d.time, history: [], baseline: null }).results.find((g) => g.gate === 'dependency-hooks');
  assert.equal(row(doc).result, 'WARN', 'a firing dependency still wins');
  const alone = row(carrier('c', { sneaky: long }));
  assert.equal(alone.result, 'SKIP');
  assert.match(alone.detail, /not evaluable: sneaky \(spec too long to judge\)/);
  assert.ok(Array.isArray(row(doc).added), 'the structured list survives normalisation');
  resetDependencyCache();
});

test('G3b-14 (note 3.3) tarball time fetches every added target missing from the cache, not only the stored pending ones', async () => {
  await withProxy({ c: carrier('c', { a1: '^1', a2: '^1' }), a1: clean('a1'), a2: hooked('a2') }, async ({ base, hits, proxy }) => {
    setDependencyDoc('a1', clean('a1'));                    // a1 judged clean at observation from the cache; a2 pending
    await get(`${base}/c`);
    assert.deepEqual(n1h(proxy, 'c', '1.1.0').pending.map((d) => d.name), ['a2']);
    resetDependencyCache();                                 // a1's entry expires before the download
    const t = await get(`${base}/c/-/c-1.1.0.tgz`);
    assert.equal(hits.a1, 1, 'the expired added target is fetched too');
    assert.equal(hits.a2, 1);
    assert.match(t.headers['npm-notice'] ?? '', /it adds a dependency that runs install scripts/);
    assert.equal(n1h(proxy, 'c', '1.1.0').result, 'WARN');
  });
});

test('G3b-15 (note 3.4) a not-evaluable judgement is retried: failures are cached 1 minute, and the next download re-judges', async () => {
  let fail = true;
  let now = Date.now();
  await withProxy({ c: carrier('c', { flaky: '^1' }), flaky: hooked('flaky') }, async ({ base, proxy }) => {
    resetDependencyCache({ now: () => now });
    await get(`${base}/c`);
    await get(`${base}/c/-/c-1.1.0.tgz`);
    // the download's MC row is written just after its response ends; let it land before the next judgement reads the record
    // (otherwise that judgement can lose the race, as on macOS CI run 38277629363, and is retried only at a later download)
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(n1h(proxy, 'c', '1.1.0').result, 'SKIP');
    assert.match(n1h(proxy, 'c', '1.1.0').detail, /flaky \(upstream 500\)/);
    fail = false;
    now += 61_000;
    await get(`${base}/c`);                                  // a re-observation: the not-evaluable row is not carried
    const t = await get(`${base}/c/-/c-1.1.0.tgz`);
    assert.equal(n1h(proxy, 'c', '1.1.0').result, 'WARN');
    assert.match(t.headers['npm-notice'] ?? '', /runs install scripts/);
  }, { status: { flaky: () => (fail ? 500 : 200) } });
});

test('G3b-16 (note 3.5) after an override is revoked, N1h is still judged at download', async () => {
  await withProxy({ c: carrier('c', { evil: '^1' }), evil: hooked('evil') }, async ({ base, proxy }) => {
    await get(`${base}/c`);
    proxy.witnessDb.insertOverride('c', '1.1.0', 'g3b-16');
    await get(`${base}/c`);                                  // the runner writes an override row
    proxy.witnessDb.deleteOverride('c', '1.1.0');
    const t = await get(`${base}/c/-/c-1.1.0.tgz`);
    assert.match(t.headers['npm-notice'] ?? '', /runs install scripts/, JSON.stringify(proxy.witnessDb.getDecisionHistory('c', '1.1.0').map((r) => r.gates_fired.map((g) => g.gate))));
  });
});

test('G3b-17 (note 3.6) judgeAtTarball reports a lost race, so the caller re-reads the record', async () => {
  resetDependencyCache();
  setDependencyDoc('evil', hooked('evil'));
  const latest = { id: 1, disposition: 'ALLOW', gates_fired: [{ gate: 'dependency-hooks', result: 'SKIP', detail: 'p',
    added: [{ name: 'evil', target: 'evil', spec: '^1' }], pending: [{ name: 'evil', target: 'evil', spec: '^1' }] }] };
  const db = { getLatestNonOverrideDecision: () => ({ id: 2 }), insertGateDecision: () => { throw new Error('must not write'); } };
  const r = await judgeAtTarball({ db, pkg: 'c', version: '1.1.0', latest, fetchPackument: async () => { throw new Error('no fetch'); }, config: {} });
  assert.equal(r, 'raced');
  resetDependencyCache();
});

test('G3b-18/19 (note 3.7) the cache: two carriers adding one dependency fetch it once; TTL and LRU bound', async () => {
  await withProxy({ c1: carrier('c1', { shared: '^1' }), c2: carrier('c2', { shared: '^1' }), shared: hooked('shared') }, async ({ base, hits }) => {
    await get(`${base}/c1`); await get(`${base}/c2`);
    await get(`${base}/c1/-/c1-1.1.0.tgz`); await get(`${base}/c2/-/c2-1.1.0.tgz`);
    assert.equal(hits.shared, 1);
  });
  let now = 0;
  resetDependencyCache({ now: () => now });
  setDependencyDoc('x', clean('x'));
  now = 10 * 60_000 - 1; assert.ok(getDependency('x'));
  now = 10 * 60_000 + 1; assert.equal(getDependency('x'), undefined, 'expired after 10 minutes');
  setDependencyDoc('gone', null, 'upstream 503');
  now += 60_001; assert.equal(getDependency('gone'), undefined, 'a failure expires after 1 minute');
  for (let i = 0; i <= MAX_ENTRIES; i += 1) setDependencyDoc(`n${i}`, clean(`n${i}`));
  assert.equal(getDependency('n0'), undefined, 'the least recently used entry is dropped at the bound');
  resetDependencyCache();
});

test('G3b-20 (note 3.7) authorization relayed; a 404 named in the detail; /self dependency_cache; an N1h WARN is named for K and accept', async () => {
  await withProxy({ c: carrier('c', { evil: '^1', missing: '^1' }), evil: hooked('evil') }, async ({ base, auth, proxy }) => {
    await get(`${base}/c`);
    await get(`${base}/c/-/c-1.1.0.tgz`, { authorization: 'Bearer g3b20' });
    assert.equal(auth.evil, 'Bearer g3b20');
    assert.match(n1h(proxy, 'c', '1.1.0').detail, /evil@1\.0\.0 \(postinstall\)/);
    const self = JSON.parse((await get(`${base}/_chaingate/self`)).body);
    assert.equal(typeof self.dependency_cache.entries, 'number');
  });
  await withProxy({ c: carrier('c', { missing: '^1' }) }, async ({ base, proxy }) => {
    await get(`${base}/c`); await get(`${base}/c/-/c-1.1.0.tgz`);
    assert.match(n1h(proxy, 'c', '1.1.0').detail, /not evaluable: missing \(upstream 404\)/);
  });
  const row = { gate: 'dependency-hooks', result: 'WARN', detail: 'adds evil@1.0.0 (postinstall)' };
  assert.deepEqual(classify([row]).named, ['dependency-hooks']);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g3b20-'));
  try {
    const db = openWitnessDB(path.join(dir, 'w.db')).applySchema();
    try {
      db.recordBaseline('c', '1.0.0', { published_at: at(0) });
      db.insertGateDecision('c', '1.0.0', 'WARN', [{ gate: 'install-introduced', result: 'ALLOW', detail: 'x' }, row]);
      db.recordBaseline('c', '1.1.0', { published_at: at(100) });
      db.insertGateDecision('c', '1.1.0', 'WARN', [{ gate: 'install-introduced', result: 'WARN', detail: 'y' }]);
      assert.equal(lastVersionWithoutSignal(db, 'c', '1.1.0'), null, 'a version with an N1h WARN is never K');
    } finally { db.close(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
