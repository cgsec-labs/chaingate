// 0.1.4 group 3, unit 3a — review fixes (G3 dated note 2; G3a-12..G3a-17). Expected results: decision tables
// ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G3-TIER1-20261012.md, dated note 2, written before this file and the fixes.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import installIntroduced from '../../gates/install-introduced.js';
import sizeJump from '../../gates/size-jump.js';
import publishToolChange from '../../gates/publish-tool-change.js';
import { classSignature } from '../../witness/row-class.js';
import { renderReport } from '../../cli/report-render.js';
import { createProxyServer } from '../../proxy/server.js';
import { openWitnessDB } from '../../witness/db.js';
import { buildSeed, docFor, manifestFor, after, LIVE } from '../seed-v3/u05-fixtures.mjs';

const H = 3_600_000;
const T0 = Date.parse('2026-01-01T00:00:00Z');
const at = (h) => new Date(T0 + h * H).toISOString();

test('G3a-12 (note 2.1) size-jump and publish-tool-change: 30,000 versions each in under 3 s; the walk is bounded at 64', () => {
  const versions = {}; const time = {};
  for (let i = 0; i < 30_000; i += 1) {
    const v = `${1 + Math.floor(i / 10_000)}.${Math.floor((i % 10_000) / 100)}.${i % 100}`;
    versions[v] = { version: v, _npmVersion: `10.${i % 7}.0`, dist: { unpackedSize: 1000 + (i % 13) } };
    time[v] = at(i);
  }
  for (const gate of [sizeJump, publishToolChange]) {
    const t = Date.now();
    for (const v of Object.keys(versions)) gate.evaluate({ version: v, rawVersions: versions, rawTimes: time });
    assert.ok(Date.now() - t < 3000, `${gate.name}: ${Date.now() - t} ms`);
  }
  // bounded walk: 70 lower releases without a size, then one with
  const b = { '1.0.0': { dist: { unpackedSize: 100 } } }; const bt = { '1.0.0': at(0) };
  for (let i = 1; i <= 70; i += 1) { b[`1.0.${i}`] = {}; bt[`1.0.${i}`] = at(i); }
  b['1.1.0'] = { dist: { unpackedSize: 900 } }; bt['1.1.0'] = at(100);
  const r = sizeJump.evaluate({ version: '1.1.0', rawVersions: b, rawTimes: bt });
  assert.equal(r.result, 'SKIP');
  assert.match(r.detail, /no predecessor within the last 64 lower releases/);
});

test('G3a-13 (note 2.2) install-introduced with no time map SKIPs at once (no per-version index rebuild)', () => {
  const versions = {};
  for (let i = 0; i < 20_000; i += 1) versions[`1.0.${i}`] = {};
  const t = Date.now();
  for (const v of Object.keys(versions)) assert.equal(installIntroduced.evaluate({ version: v, rawVersions: versions }).result, 'SKIP');
  assert.ok(Date.now() - t < 1000, `${Date.now() - t} ms`);
});

test('G3a-14 (note 2.3, D-N7 amended) a determinate named runner row is part of the class signature; an upgraded record is refreshed', async () => {
  const old = [{ gate: 'content-hash', result: 'ALLOW', detail: 'x' }, { gate: 'release-age', result: 'ALLOW', detail: 'y' }];
  assert.notEqual(classSignature('ALLOW', old), classSignature('ALLOW', [...old, { gate: 'install-introduced', result: 'ALLOW', detail: 'z' }]));
  assert.equal(classSignature('ALLOW', [...old, { gate: 'install-introduced', result: 'SKIP', detail: 'z' }]), classSignature('ALLOW', old),
    'a SKIP is not a determinate named rule');
  // through the proxy (no seed: the default today): a 0.1.3-shaped stored row is replaced by a current one
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g3a14-'));
  const doc = { name: 'u', 'dist-tags': { latest: '1.2.0' }, versions: {}, time: {} };
  for (const [v, h, extra] of [['1.0.0', 0, {}], ['1.1.0', 48, {}], ['1.2.0', 96, { scripts: { postinstall: 'x' } }]]) {
    doc.versions[v] = { name: 'u', version: v, ...extra }; doc.time[v] = at(h);
  }
  const dbPath = path.join(dir, 'witness.db');
  const db = openWitnessDB(dbPath).applySchema();
  for (const v of ['1.0.0', '1.1.0']) { db.recordBaseline('u', v, { published_at: doc.time[v] }); db.insertGateDecision('u', v, 'ALLOW', old); }
  db.close();
  const upstream = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(doc)); });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`, witnessDbPath: dbPath,
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000 });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const realErr = console.error; console.error = () => {};
  try {
    await new Promise((resolve, reject) => http.get(`http://127.0.0.1:${proxy.address().port}/u`, (res) => { res.resume(); res.on('end', resolve); }).on('error', reject));
    const ro = openWitnessDB(dbPath, { readonly: true });
    try {
      const latest = ro.getLatestDecision('u', '1.1.0');
      assert.ok(latest.gates_fired.some((g) => g.gate === 'install-introduced'), 'the upgraded record carries T1.1');
    } finally { ro.close(); }
  } finally {
    console.error = realErr;
    await new Promise((r) => proxy.close(r)); await new Promise((r) => upstream.close(r)); fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('G3a-15 (note 2.4) the T1.1 detail names the set used and its size', () => {
  const versions = { '1.0.0': {}, '1.1.0': {}, '1.2.0': { scripts: { postinstall: 'x' } } };
  const time = { '1.0.0': at(0), '1.1.0': at(48), '1.2.0': at(96) };
  assert.match(installIntroduced.evaluate({ version: '1.2.0', rawVersions: versions, rawTimes: time }).detail, /\(settled 24 h: 2 versions\)/);
  const cold = { '1.0.0': {}, '1.0.1': { scripts: { postinstall: 'x' } } };
  assert.match(installIntroduced.evaluate({ version: '1.0.1', rawVersions: cold, rawTimes: { '1.0.0': at(0), '1.0.1': at(1) } }).detail,
    /\(cold start: plain: 1 version\)/);
});

test('G3a-16 (note 2.5) a named warning with both a seed row and T1.1 names both baselines', () => {
  const START = '2026-10-12T09:00:00.000Z';
  const text = renderReport({ service: 'chaingate-proxy', version: '0.1.4', started_at: START, policy: 'cft-policy-1.2', view: 'latest',
    seed: { sha256: 'ab'.repeat(32), history_cutoff: '2026-12-31T00:00:00Z' }, stats: {},
    installs: [{ key: 'npm-session:a', grouping: 'npm-session', started_at: START, last_at: START, dropped: 0, dropped_important: 0,
      events: [{ at: START, kind: 'served', package: 'q', version: '1.5.0', class: 'named', coverage: 'checked',
        named: ['install-introduced', 'seed-v3:dac-trajectory:surface'], contributing: [], reason: 'r', policy: 'cft-policy-1.2', notice: true, k: null }] }] },
  { source: 'proxy' }).text;
  assert.ok(text.includes('  baseline: seed (history to 2026-12-31T00:00:00Z) + packument'), text);
  assert.ok(text.includes('NAMED WARNING: an install script appears that earlier releases did not have; release-history break vs the seed (2+ package-wide signals)'), text);
});

test('G3a-17 (note 2.7) through the proxy: the seed strict tier and T1.1 on one version -- both labels, both baselines', async () => {
  const s = buildSeed({ layout: '1.1' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g3a17-'));
  const strict = manifestFor('q', '1.5.0', { scripts: { postinstall: 'node x.js' }, dist: { unpackedSize: 10_000, attestations: { url: 'https://x' } } });
  const q = docFor('q', [['1.5.0', after(2), strict]]);           // q@1.0.0..1.2.0 have no hook: T1.1 fires on 1.5.0
  const upstream = http.createServer((req, res) => {
    if (req.url.includes('/-/')) { res.writeHead(200); res.end('x'); return; }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(q));
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`, witnessDbPath: path.join(dir, 'witness.db'),
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedV3Path: s.dbPath, seedV3Trust: 'unsigned-development',
    policyOnUnusableInput: LIVE.on_unusable_input, policyOnNoEvidence: LIVE.on_no_evidence });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  const get = (u) => new Promise((resolve, reject) => http.get(u, { agent: false }, (res) => {
    let b = ''; res.on('data', (x) => { b += x; }); res.on('end', () => resolve({ headers: res.headers, body: b }));
  }).on('error', reject));
  const realErr = console.error; console.error = () => {};
  try {
    await get(`${base}/q`);
    const t = await get(`${base}/q/-/q-1.5.0.tgz`);
    assert.equal(t.headers['npm-notice'], 'chaingate: WARNING q@1.5.0: an install script appears that earlier releases did not have; '
      + 'release-history break vs the seed (2+ package-wide signals). Details: chaingate why q@1.5.0');
    const rep = JSON.parse((await get(`${base}/_chaingate/report`)).body);
    const text = renderReport(rep, { source: 'proxy' }).text;
    assert.ok(text.includes('  baseline: seed (history to 2026-12-31T00:00:00Z) + packument'), text);
  } finally {
    console.error = realErr;
    await new Promise((r) => proxy.close(r)); await new Promise((r) => upstream.close(r)); s.cleanup(); fs.rmSync(dir, { recursive: true, force: true });
  }
});
