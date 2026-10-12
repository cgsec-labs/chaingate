// 0.1.4 group 2, unit 2c — the review fixes (G2c-11..G2c-23). Expected results: decision tables
// ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G2-TIER0-20261011.md, dated note 7, written before this file and before the
// fixes. CLI review cases are in test/cli/cft014-g2c-review-cli.test.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createProxyServer, enforceTarballGate } from '../../proxy/server.js';
import { createInstallSummary } from '../../proxy/install-summary.js';
import { openWitnessDB } from '../../witness/db.js';
import { renderReport } from '../../cli/report-render.js';
import { buildSeed, docFor, manifestFor, after, iso, TIP_S, STEP_S, LIVE, WARNCFG } from '../seed-v3/u05-fixtures.mjs';

const listen = (srv) => new Promise((resolve) => { srv.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${srv.address().port}`)); });
const close = (srv) => new Promise((resolve) => { srv.close(() => resolve()); });
const get = (url, { session, headers = {} } = {}) => new Promise((resolve, reject) => {
  http.get(url, { agent: false, headers: { ...(session ? { 'npm-session': session } : {}), ...headers } }, (res) => {
    let b = ''; res.setEncoding('utf8'); res.on('data', (x) => { b += x; });
    res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* not JSON */ } resolve({ status: res.statusCode, headers: res.headers, json, body: b }); });
  }).on('error', reject);
});
const tgz = (name, v) => `/${name}/-/${name}-${v}.tgz`;

const strict = () => manifestFor('q', '1.5.0', { scripts: { postinstall: 'node x.js' },
  dist: { unpackedSize: 10_000, attestations: { url: 'https://x' } } });
const DOCS = () => {
  const p = docFor('p', [['1.3.0', after(1)]]);
  p['dist-tags'] = { latest: '1.3.0' };
  const q = docFor('q', [['1.4.0', after(1), manifestFor('q', '1.4.0', { scripts: { postinstall: 'node x.js' } })],
    ['1.4.5', iso(TIP_S + 2 * STEP_S - 3600)], ['1.5.0', after(2), strict()]]);
  q['dist-tags'] = { latest: '1.5.0' };
  q.versions['1.0.0'].scripts = { postinstall: 'node legacy.js' };   // G3 dated note 1.2: T1.1 stays quiet; the seed rows are the subject
  return { p, q };
};

/** A proxy over `dir/witness.db`; `docs` and `packumentStatus` may be changed between requests. */
async function withProxy({ dir, cfg = LIVE, seed = true, docs = DOCS(), world = {} } = {}, fn) {
  const s = seed ? buildSeed({ layout: '1.1' }) : null;
  const own = !dir;
  const base = dir ?? fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2cr-'));
  const w = { docs, packumentStatus: 200, ...world };
  const upstream = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url);
    if (url.includes('/-/')) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end('tarball-bytes'); return; }
    if (w.packumentStatus !== 200) { res.writeHead(w.packumentStatus, { 'content-type': 'application/json' }); res.end('{}'); return; }
    const d = w.docs[url.slice(1)];
    if (!d) { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); return; }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(d));
  });
  const upstreamUrl = await listen(upstream);
  const dbPath = path.join(base, 'witness.db');
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: dbPath,
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000,
    ...(s ? { seedV3Path: s.dbPath, seedV3Trust: 'unsigned-development', policyOnUnusableInput: cfg.on_unusable_input,
      policyOnNoEvidence: cfg.on_no_evidence } : {}) });
  const proxyUrl = await listen(proxy);
  const realErr = console.error; console.error = () => {};
  try {
    return await fn({ proxyUrl, dbPath, w });
  } finally {
    console.error = realErr;
    await close(proxy); await close(upstream);
    s?.cleanup(); if (own) fs.rmSync(base, { recursive: true, force: true });
  }
}
const report = async (proxyUrl, all = false) => (await get(`${proxyUrl}/_chaingate/report${all ? '?all=1' : ''}`)).json;

const served = (pkg, version, over = {}) => ({ kind: 'served', package: pkg, version, class: 'clean', coverage: 'checked',
  named: [], contributing: [], reason: 'seed-v3: cft-policy-1.2: ok', policy: 'cft-policy-1.2', notice: false, k: null, ...over });
const refused = (pkg, version, facts, over = {}) => ({ kind: 'refused', package: pkg, version, facts, status: 403,
  reason: 'seed-v3: cft-policy-1.2: seed-v3:known-malicious-pin: recorded advisory ADV-P-130', policy: 'cft-policy-1.2', ...over });
const START = '2026-10-12T09:00:00.000Z';
const wrap = (installs, over = {}) => ({ service: 'chaingate-proxy', version: '0.1.4', started_at: START, policy: 'cft-policy-1.2',
  seed: { sha256: 'ab'.repeat(32), history_cutoff: '2026-12-31T00:00:00Z' }, view: 'latest', installs, stats: { installs_evicted: 0 }, ...over });

test('G2c-11 (note 7.1) a transient non-fact refusal never hides the later fact refusal of the same version', () => {
  const s = createInstallSummary({ now: () => 0 });
  const who = { session: 'r1sess' };
  s.record(who, refused('p', '1.3.0', [], { status: 503, reason: 'p@1.3.0 could not be evaluated now (busy); a resource refusal' }));
  const b = s.record(who, refused('p', '1.3.0', ['seed-v3:pin']));
  assert.equal(s.claimDisk(b.key, 'fact-refused|p@1.3.0'), true, 'the fact refusal still reaches disk');
  const r = renderReport(wrap(s.snapshot({ all: true }).installs), { source: 'proxy' });
  assert.ok(r.text.includes('p@1.3.0  BLOCKED (download refused): a recorded advisory names this version — npm could not install it'), r.text);
  assert.ok(!r.text.includes('p@1.3.0  REFUSED'), 'one line per version; the fact wins');
  assert.equal(r.exit, 3);

  const t = createInstallSummary({ now: () => 0 });
  t.record({ session: 'r1b' }, refused('x', '1.0.0', [], { status: 503, reason: 'x@1.0.0 was not evaluated: boom' }));
  t.record({ session: 'r1b' }, served('x', '1.0.0'));
  const r2 = renderReport(wrap(t.snapshot({ all: true }).installs), { source: 'proxy' });
  assert.ok(r2.text.includes('x@1.0.0  REFUSED once (not a recorded fact — x@1.0.0 was not evaluated: boom); a later request for it was served'), r2.text);
  assert.ok(!r2.text.includes('npm could not install it'));
  assert.equal(r2.exit, 0, 'npm got it on the retry: not a refusal for the exit code');
});

test('G2c-12 (note 7.2) a tarball served after a failed C1 evaluation is not-checked / failed, never the older stored row', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2c12-'));
  try {
    await withProxy({ dir, cfg: WARNCFG }, async ({ proxyUrl }) => {
      assert.equal((await get(`${proxyUrl}/q`)).status, 200);                     // stores q's rows
    });
    await withProxy({ dir, cfg: WARNCFG, world: { packumentStatus: 500 } }, async ({ proxyUrl }) => {
      const t = await get(`${proxyUrl}${tgz('q', '1.4.0')}`, { session: 'r2sess' });
      assert.equal(t.status, 200, 'on_unusable_input WARN serves without an evaluation');
      const [inst] = (await report(proxyUrl)).installs;
      const e = inst.events.find((x) => x.kind === 'served');
      assert.deepEqual([e.class, e.coverage, e.policy], ['not-checked', 'failed', null], JSON.stringify(e));
      assert.ok(e.reason.startsWith('served without an evaluation ('), e.reason);
    });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('G2c-13 (note 7.3) many dist-tags: at most 20 tag events per response, latest first; one disk row per withheld version', async () => {
  const docs = DOCS();
  const tags = { latest: '1.3.0' };
  for (let i = 0; i < 50; i += 1) tags[`t${i}`] = '1.3.0';
  docs.p['dist-tags'] = tags;
  await withProxy({ docs }, async ({ proxyUrl, dbPath }) => {
    assert.equal((await get(`${proxyUrl}/p`, { session: 'r3sess' })).status, 200);
    await get(`${proxyUrl}/p`, { session: 'r3sess' });
    const [inst] = (await report(proxyUrl, true)).installs;
    const moved = inst.events.filter((e) => e.kind === 'tag-moved');
    assert.equal(moved.length, 40, 'two responses, 20 each');
    assert.equal(moved[0].tag, 'latest');
    assert.equal(moved[19].more, 31, 'the rest of the 51 tags are counted on the last event');
    const db = openWitnessDB(dbPath, { readonly: true });
    try {
      const rows = db.listNamedFactEvents().filter((x) => x.kind === 'fact-tag-moved');
      assert.equal(rows.length, 1, 'one row per (install, package, withheld version)');
      assert.equal(rows[0].classes.tags.length, 20);
      assert.equal(rows[0].classes.more, 31);
      assert.deepEqual(rows[0].classes.tags[0], { tag: 'latest', to: '1.2.0' });
    } finally { db.close(); }
    const text = renderReport((await report(proxyUrl, true)), { source: 'proxy' }).text;
    assert.ok(text.includes('p: dist-tag latest moved from 1.3.0 to 1.2.0: a recorded advisory names this version'), text);
    assert.ok(text.includes('p: 31 more dist-tag(s) moved off 1.3.0 (not listed)'), text);
  });
});

test('G2c-13b (note 7.3) at most 500 disk rows per install; the rest are counted, never written', () => {
  const s = createInstallSummary({ now: () => 0 });
  const { key } = s.record({ session: 'r3b' }, served('a', '1.0.0'));
  let yes = 0;
  for (let i = 0; i < 600; i += 1) if (s.claimDisk(key, `named-served|n${i}@1.0.0`)) yes += 1;
  assert.equal(yes, 500);
  const [inst] = s.snapshot({ all: true }).installs;
  assert.equal(inst.disk_suppressed, 100);
});

test('G2c-14 (note 7.4, E22) report and self answer a loopback Host only, never a browser request (DNS rebinding)', async () => {
  await withProxy({}, async ({ proxyUrl }) => {
    const port = new URL(proxyUrl).port;
    for (const p of ['/_chaingate/report', '/_chaingate/self']) {
      assert.equal((await get(`${proxyUrl}${p}`)).status, 200, `${p} plain`);
      assert.equal((await get(`${proxyUrl}${p}`, { headers: { host: `localhost:${port}` } })).status, 200, `${p} localhost`);
      assert.equal((await get(`${proxyUrl}${p}`, { headers: { host: `[::1]:${port}` } })).status, 200, `${p} [::1]`);
      assert.equal((await get(`${proxyUrl}${p}`, { headers: { host: `attacker.example:${port}` } })).status, 404, `${p} rebinding Host`);
      assert.equal((await get(`${proxyUrl}${p}`, { headers: { host: `127.0.0.1.attacker.example:${port}` } })).status, 404, `${p} lookalike`);
      assert.equal((await get(`${proxyUrl}${p}`, { headers: { origin: 'http://attacker.example' } })).status, 404, `${p} Origin`);
      assert.equal((await get(`${proxyUrl}${p}`, { headers: { 'sec-fetch-site': 'cross-site' } })).status, 404, `${p} cross-site`);
      assert.equal((await get(`${proxyUrl}${p}`, { headers: { 'sec-fetch-site': 'none' } })).status, 200, `${p} typed in`);
    }
  });
});

test('G2c-15 (note 7.5) whole-install eviction is stated: a re-created install is incomplete, and an empty view with evictions exits 4', () => {
  let t = 0;
  const s = createInstallSummary({ now: () => t });
  s.record({ session: 'victim' }, served('a', '1.0.0'));
  for (let i = 0; i < 20; i += 1) { t += 1; s.record({ session: `o${i}` }, served(`o${i}`, '1.0.0')); }
  t += 1; s.record({ session: 'victim' }, served('b', '1.0.0'));
  const v = s.snapshot({ all: true }).installs.find((i) => i.key === 'npm-session:victim');
  assert.equal(v.evicted_earlier, true);
  const r = renderReport(wrap([v]), { source: 'proxy' });
  assert.ok(r.text.includes('Earlier events of this install were evicted (more than 20 installs were active); this report is incomplete.'), r.text);
  assert.equal(r.exit, 4);
  const empty = renderReport(wrap([], { stats: { installs_evicted: 3 } }), { source: 'proxy' });
  assert.ok(empty.text.includes('3 earlier install(s) were evicted (at most 20 are held).'), empty.text);
  assert.equal(empty.exit, 4);
  const all = renderReport(wrap([v], { view: 'all', stats: { installs_evicted: 2 } }), { source: 'proxy' });
  assert.ok(all.text.includes('2 earlier install(s) were evicted (at most 20 are held).'));
});

test('G2c-17 (note 7.7) the disk read keeps the NEWEST rows of the window; a truncated disk view is incomplete', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2c17-'));
  try {
    const db = openWitnessDB(path.join(dir, 'witness.db')).applySchema();
    try {
      for (let i = 1; i <= 5; i += 1) {
        db.insertNamedFactEvent({ at: new Date(Date.now() - (10 - i) * 60_000).toISOString(), kind: 'fact-refused', package_name: `n${i}`,
          version: '1.0.0', classes: { facts: ['seed-v3:pin'] }, reason: 'r', policy_version: 'cft-policy-1.2', seed_sha256: null,
          install_key: 'k', k_version: null });
      }
      assert.deepEqual(db.listNamedFactEvents({ limit: 3 }).map((x) => x.package_name), ['n3', 'n4', 'n5']);
    } finally { db.close(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  const r = renderReport({ host: '127.0.0.1', port: 1, why: 'nothing is listening', since: '24h', events: [], truncated: true }, { source: 'disk' });
  assert.ok(r.text.includes('Only the newest 10000 rows of the window are shown; this view is incomplete.'), r.text);
  assert.equal(r.exit, 4);
  const inc = renderReport({ host: '127.0.0.1', port: 1, why: 'x', since: '24h', events: [], incomplete: true }, { source: 'disk' });
  assert.equal(inc.exit, 4, 'a proxy that gave no summary makes the disk view incomplete');
});

test('G2c-18 (note 7.9) a tarball whose version cannot be derived is recorded: not-checked / failed', async () => {
  await withProxy({ seed: false }, async ({ proxyUrl }) => {
    assert.equal((await get(`${proxyUrl}/p/-/evil.tgz`, { session: 'r9sess' })).status, 200, 'pilot-only setups serve it, as before');
    const [inst] = (await report(proxyUrl)).installs;
    const e = inst.events.find((x) => x.kind === 'served');
    assert.ok(e, JSON.stringify(inst.events));
    assert.deepEqual([e.package, e.version, e.class, e.coverage], ['p', null, 'not-checked', 'failed']);
    const text = renderReport(await report(proxyUrl), { source: 'proxy' }).text;
    assert.ok(text.includes('1 evaluation failed'), text);
  });
});

test('G2c-19 (note 7.10, E23) a remembered fact BLOCK refused while the unstored record is FULL keeps its facts', () => {
  const state = {};
  const known = { gates: [{ gate: 'seed-v3', result: 'BLOCK', detail: 'x' }], remembered_at: '2026-10-12T00:00:00Z', detail: 'pin', reasons: 2 };
  const r = enforceTarballGate({}, 'p', 'p-1.3.0.tgz', null, { unstored: { full: true, get: () => known }, overriddenLive: () => false }, state);
  assert.equal(r.version, '1.3.0');
  assert.deepEqual(state.blockFacts, ['seed-v3:pin']);
});

test('G2c-20 (note 7.11) "every package was checked" names the override exception; a named version is never "not checked"', () => {
  const s = (events) => renderReport(wrap([{ key: 'npm-session:a', grouping: 'npm-session', started_at: START, last_at: START,
    dropped: 0, dropped_important: 0, events: events.map((e) => ({ at: START, ...e })) }]), { source: 'proxy' }).text;
  const withOverride = s([served('a', '1.0.0'), served('o', '1.0.0', { class: 'override', coverage: null })]);
  assert.ok(withOverride.includes('Every package served in this install, other than those served under your overrides, was checked by a named rule.'), withOverride);
  assert.ok(withOverride.includes('1 version(s) were served under your exact-version overrides (chaingate allow): o@1.0.0'));
  const namedIndeterminate = s([served('a', '1.0.0'), served('q', '1.5.0', { class: 'named', coverage: 'indeterminate',
    named: ['seed-v3:dac-trajectory:surface'] })]);
  assert.ok(namedIndeterminate.includes('Every package served in this install was checked by a named rule.'), namedIndeterminate);
  assert.ok(!namedIndeterminate.includes('not checked by any named rule'));
});

test('G2c-22 (note 7.14) bidi and C1 controls are stripped from text; the summary caps strings at every depth', () => {
  const r = renderReport(wrap([{ key: 'npm-session:a', grouping: 'npm-session', started_at: START, last_at: START, dropped: 0,
    dropped_important: 0, events: [{ at: START, ...refused('x', '1.0.0', [], { status: 503, reason: 'a\u202eb\u009bc\u200fd\ufeffe' }) }] }]), { source: 'proxy' });
  assert.ok(!/[\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/.test(r.text), JSON.stringify(r.text));
  assert.ok(r.text.includes('abcde'));
  const s = createInstallSummary({ now: () => 0 });
  s.record({ session: 'cap' }, { kind: 'withheld', package: 'p', versions: [{ version: 'v'.repeat(5000), facts: ['seed-v3:pin'] }], more: 0 });
  const [inst] = s.snapshot({ all: true }).installs;
  assert.ok(inst.events[0].versions[0].version.length <= 1001, 'nested strings are capped too');
});

test('G2c-23 (note 7.15) a tarball served under an exact-version override is class `override`', async () => {
  await withProxy({}, async ({ proxyUrl, dbPath }) => {
    await get(`${proxyUrl}/q`, { session: 'r16sess' });
    const rw = openWitnessDB(dbPath).applySchema();
    try { rw.insertOverride('q', '1.5.0', 'g2c-23'); } finally { rw.close(); }
    assert.equal((await get(`${proxyUrl}${tgz('q', '1.5.0')}`, { session: 'r16sess' })).status, 200);
    const [inst] = (await report(proxyUrl)).installs;
    const e = inst.events.find((x) => x.kind === 'served' && x.package === 'q');
    assert.deepEqual([e.class, e.coverage, e.k], ['override', null, null], JSON.stringify(e));
    const text = renderReport(await report(proxyUrl), { source: 'proxy' }).text;
    assert.ok(text.includes('1 version(s) were served under your exact-version overrides (chaingate allow): q@1.5.0'), text);
    assert.ok(!text.includes('NAMED WARNING'), 'an overridden version is not reported as a named warning');
  });
});
