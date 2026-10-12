// 0.1.4 group 2, unit 2d — user actions in the proxy: what a pin does (D-U5, D-U6), what an acceptance does (D-U3),
// validators and conditional headers (E25), and how the report shows them (D-U9). Expected results: decision tables
// ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G2-TIER0-20261011.md §8, written before this file. CLI cases:
// test/cli/cft014-g2d-actions-cli.test.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createProxyServer } from '../../proxy/server.js';
import { openWitnessDB } from '../../witness/db.js';
import { caretClass, withheldBy, createPinSet } from '../../witness/pins.js';
import { rewritePackument } from '../../gates/rewriter.js';
import { renderReport } from '../../cli/report-render.js';
import { buildSeed, docFor, manifestFor, after, iso, TIP_S, STEP_S, LIVE } from '../seed-v3/u05-fixtures.mjs';

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
  const q = docFor('q', [['1.4.0', after(1)], ['1.4.5', iso(TIP_S + 2 * STEP_S - 3600)], ['1.5.0', after(2), strict()],
    ['1.6.0-beta.1', after(3)], ['2.0.0', after(4)]]);
  q['dist-tags'] = { latest: '1.5.0', next: '1.6.0-beta.1', v2: '2.0.0' };
  q.versions['1.0.0'].scripts = { postinstall: 'node legacy.js' };   // G3 dated note 1.2: T1.1 stays quiet; the seed rows are the subject
  return { p, q };
};
const VALIDATORS = { etag: '"upstream-etag"', 'last-modified': 'Mon, 12 Oct 2026 00:00:00 GMT', 'cache-control': 'public, max-age=300' };

async function withProxy(fn, { docs = DOCS() } = {}) {
  const s = buildSeed({ layout: '1.1' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2d-'));
  const seenHeaders = [];
  const upstream = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url);
    seenHeaders.push({ url, headers: { ...req.headers } });
    if (url.includes('/-/')) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end('tarball-bytes'); return; }
    const d = docs[url.slice(1)];
    if (!d) { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); return; }
    res.writeHead(200, { 'content-type': 'application/json', ...VALIDATORS }); res.end(JSON.stringify(d));
  });
  const upstreamUrl = await listen(upstream);
  const dbPath = path.join(dir, 'witness.db');
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: dbPath,
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedV3Path: s.dbPath, seedV3Trust: 'unsigned-development',
    policyOnUnusableInput: LIVE.on_unusable_input, policyOnNoEvidence: LIVE.on_no_evidence });
  const proxyUrl = await listen(proxy);
  const logs = []; const realErr = console.error;
  console.error = (m) => { logs.push(String(m)); };
  const cli = (f) => { const db = openWitnessDB(dbPath).applySchema(); try { return f(db); } finally { db.close(); } };
  try {
    return await fn({ proxyUrl, dbPath, logs, seenHeaders, cli });
  } finally {
    console.error = realErr;
    await close(proxy); await close(upstream);
    s.cleanup(); fs.rmSync(dir, { recursive: true, force: true });
  }
}
const report = async (proxyUrl) => (await get(`${proxyUrl}/_chaingate/report?all=1`)).json;

test('G2d-4a (D-U4, D-U5) caret classes and the withheld rule (prereleases above K included)', () => {
  assert.deepEqual(['1.4.0', '1.6.0-beta.1', '0.3.2', '0.0.4', '0.0.1-security', 'nope'].map(caretClass), ['1', '1', '0.3', null, null, null]);
  const pins = [{ package_name: 'q', class_key: '1', k_version: '1.4.0' }];
  const w = (v) => withheldBy(pins, 'q', v)?.k_version ?? null;
  assert.deepEqual(['1.4.0', '1.4.1-rc.1', '1.4.5', '1.6.0-beta.1', '1.4.0-rc.1', '1.0.0', '2.0.0'].map(w),
    [null, '1.4.0', '1.4.0', '1.4.0', null, null, null]);
  assert.equal(withheldBy(pins, 'other', '1.9.0'), null);
});

test('G2d-4b (D-U5) the rewriter withholds pinned versions; tags move within K\'s class only; BLOCK walk unchanged', () => {
  const doc = DOCS().q;
  const pins = [{ package_name: 'q', class_key: '1', k_version: '1.4.0' }];
  const decisions = new Map(Object.keys(doc.versions).map((v) => [v, { disposition: 'ALLOW', results: [] }]));
  const { packument, changed, summary } = rewritePackument(doc, decisions, { pinned: (v) => withheldBy(pins, 'q', v) });
  assert.equal(changed, true);
  assert.deepEqual(Object.keys(packument.versions).sort(), ['1.0.0', '1.1.0', '1.2.0', '1.4.0', '2.0.0']);
  assert.deepEqual(packument['dist-tags'], { latest: '1.4.0', next: '1.4.0', v2: '2.0.0' });
  assert.deepEqual(summary.pinned.map((x) => x.version).sort(), ['1.4.5', '1.5.0', '1.6.0-beta.1']);
  assert.ok(summary.dist_tag_downgrades.every((d) => d.pin && d.pin.k_version === '1.4.0'), JSON.stringify(summary.dist_tag_downgrades));
  assert.equal(summary.blocked.length, 0, 'a pin is not a BLOCK');
  // a BLOCKed target keeps the existing walk (across majors), with pinned versions no longer available to it
  const d2 = new Map(decisions); d2.set('2.0.0', { disposition: 'BLOCK', results: [] });
  const r2 = rewritePackument(doc, d2, { pinned: (v) => withheldBy(pins, 'q', v) });
  assert.equal(r2.packument['dist-tags'].v2, '1.4.0');
});

test('G2d-4c/G2d-8 (D-U5) through the proxy: packument withheld, tarball 403 withheld_by_pin with notice; a BLOCK keeps its reason', async () => {
  await withProxy(async ({ proxyUrl, cli }) => {
    cli((db) => { db.upsertPin({ package_name: 'q', class_key: '1', k_version: '1.4.0' }); db.upsertPin({ package_name: 'p', class_key: '1', k_version: '1.2.0' }); });
    const q = await get(`${proxyUrl}/q`, { session: 'g2d4' });
    assert.equal(q.status, 200);
    assert.deepEqual(Object.keys(q.json.versions).sort(), ['1.0.0', '1.1.0', '1.2.0', '1.4.0', '2.0.0']);
    assert.deepEqual(q.json['dist-tags'], { latest: '1.4.0', next: '1.4.0', v2: '2.0.0' });
    const t = await get(`${proxyUrl}${tgz('q', '1.5.0')}`, { session: 'g2d4' });
    assert.equal(t.status, 403);
    assert.equal(t.json.error, 'withheld_by_pin');
    assert.equal(t.headers['npm-notice'], 'chaingate: WITHHELD q@1.5.0: pinned by you to 1.4.0. Undo: chaingate unpin q');
    assert.equal((await get(`${proxyUrl}${tgz('q', '1.4.0')}`, { session: 'g2d4' })).status, 200);
    assert.equal((await get(`${proxyUrl}${tgz('q', '2.0.0')}`, { session: 'g2d4' })).status, 200, 'another major still resolves');
    // G2d-8: p@1.3.0 is BLOCKed (advisory) AND above the pin: the BLOCK's reason, not the pin's
    const p = await get(`${proxyUrl}/p`, { session: 'g2d4' });
    assert.ok(!('1.3.0' in p.json.versions));
    // dated note 8.5: the packument half -- the tag move off 1.3.0 is the BLOCK's (its fact), and no pin event lists 1.3.0
    const evs = (await report(proxyUrl)).installs.flatMap((i) => i.events);
    assert.deepEqual(evs.filter((e) => e.kind === 'tag-moved' && e.package === 'p').map((e) => [e.from, e.to, e.facts]),
      [['1.3.0', '1.2.0', ['seed-v3:pin']]]);
    assert.ok(!evs.some((e) => e.kind === 'pin-withheld' && e.package === 'p' && e.versions.includes('1.3.0')), JSON.stringify(evs));
    const b = await get(`${proxyUrl}${tgz('p', '1.3.0')}`, { session: 'g2d4' });
    assert.equal(b.status, 403);
    assert.equal(b.json.error, 'blocked_by_chaingate');
    assert.match(b.headers['npm-notice'], /^chaingate: BLOCKED p@1\.3\.0: a recorded advisory names this version/);
    // D-U9: the report
    const text = renderReport(await report(proxyUrl), { source: 'proxy' }).text;
    assert.ok(text.includes('q@1.5.0  WITHHELD BY YOUR PIN (download refused): pinned to 1.4.0 — undo: chaingate unpin q'), text);
    assert.ok(text.includes('your pin on q (1.4.0) withheld 3 version(s); dist-tag latest → 1.4.0; dist-tag next → 1.4.0'), text);
  });
});

test('G2d-6 (D-U6) pins apply live (no restart), unpin restores; a failed pins read keeps the last good set', async () => {
  await withProxy(async ({ proxyUrl, cli }) => {
    assert.ok('1.5.0' in (await get(`${proxyUrl}/q`)).json.versions);
    cli((db) => db.upsertPin({ package_name: 'q', class_key: '1', k_version: '1.4.0' }));
    assert.ok(!('1.5.0' in (await get(`${proxyUrl}/q`)).json.versions), 'applied on the next request');
    const self = (await get(`${proxyUrl}/_chaingate/self`)).json;
    assert.equal(self.pins.enforced, true);
    assert.equal(self.pins.count, 1);
    cli((db) => db.deletePins('q'));
    assert.ok('1.5.0' in (await get(`${proxyUrl}/q`)).json.versions, 'unpin restores');
  });
  let version = 1; let fail = false;
  const fake = { dataVersion: () => version, listPins: () => { if (fail) throw new Error('disk I/O error'); return [{ package_name: 'q', class_key: '1', k_version: '1.4.0' }]; } };
  const warned = [];
  const set = createPinSet(fake, { log: { warn: (m) => warned.push(m) } });
  assert.equal(set.forPackage('q').length, 1);
  fail = true; version = 2;
  assert.equal(set.forPackage('q').length, 1, 'the last good set is kept');
  assert.equal(set.forPackage('q').length, 1);
  assert.equal(warned.length, 1, 'logged once per failure transition');
  assert.match(set.stats().last_error, /disk I\/O error/);
  fail = false; version = 3;
  assert.equal(set.forPackage('q').length, 1);
  assert.equal(set.stats().last_error, null);
});

test('G2d-7 (E25) pinned packages are fetched without conditional headers; rewritten packuments carry no validators', async () => {
  await withProxy(async ({ proxyUrl, cli, seenHeaders }) => {
    cli((db) => db.upsertPin({ package_name: 'q', class_key: '1', k_version: '1.4.0' }));
    const cond = { 'if-none-match': '"old"', 'if-modified-since': 'Sun, 11 Oct 2026 00:00:00 GMT' };
    const q = await get(`${proxyUrl}/q`, { headers: cond });
    const up = seenHeaders.filter((h) => h.url === '/q').at(-1).headers;
    assert.equal(up['if-none-match'], undefined);
    assert.equal(up['if-modified-since'], undefined);
    assert.equal(q.headers.etag, undefined);
    assert.equal(q.headers['last-modified'], undefined);
    const p = await get(`${proxyUrl}/p`, { headers: cond });                     // BLOCK-rewritten, not pinned
    assert.equal(seenHeaders.filter((h) => h.url === '/p').at(-1).headers['if-none-match'], '"old"', 'unpinned: relayed as before');
    assert.equal(p.headers.etag, undefined);
    assert.equal(p.headers['last-modified'], undefined, 'E25: every rewritten packument drops last-modified');
  });
});

test('G2d-9 (D-U7) an exact override on a pin-withheld version: the pin wins in serving; nothing is deleted', async () => {
  await withProxy(async ({ proxyUrl, cli }) => {
    cli((db) => { db.upsertPin({ package_name: 'q', class_key: '1', k_version: '1.4.0' }); db.insertOverride('q', '1.5.0', 'g2d-9'); });
    await get(`${proxyUrl}/q`);
    const t = await get(`${proxyUrl}${tgz('q', '1.5.0')}`);
    assert.equal(t.status, 403);
    assert.equal(t.json.error, 'withheld_by_pin');
    cli((db) => { assert.ok(db.getOverride('q', '1.5.0')); assert.equal(db.listPins().length, 1); });
  });
});

test('G2d-2/G2d-3 (D-U3) an accepted named WARN sends no notice and is cacheable; another named row warns again; a BLOCK still blocks', async () => {
  await withProxy(async ({ proxyUrl, cli, logs, dbPath }) => {
    await get(`${proxyUrl}/q`, { session: 'g2d2' });
    cli((db) => db.upsertAcceptance({ package_name: 'q', version: '1.5.0', named: ['seed-v3:dac-trajectory:surface'],
      decision_id: null, policy_version: 'cft-policy-1.2' }));
    const t = await get(`${proxyUrl}${tgz('q', '1.5.0')}`, { session: 'g2d2' });
    assert.equal(t.status, 200);
    assert.equal(t.headers['npm-notice'], undefined);
    assert.notEqual(t.headers['cache-control'], 'no-store');
    assert.ok(logs.some((l) => l.startsWith('[gate] q@1.5.0: WARN named seed-v3:dac-trajectory:surface') && l.endsWith(' (accepted)')), JSON.stringify(logs));
    const [inst] = (await report(proxyUrl)).installs;
    assert.equal(inst.events.find((e) => e.kind === 'served' && e.version === '1.5.0').accepted, true);
    const db = openWitnessDB(dbPath, { readonly: true });
    try { assert.equal(db.listNamedFactEvents().find((r) => r.kind === 'named-served').classes.accepted, true); } finally { db.close(); }
    const text = renderReport(await report(proxyUrl), { source: 'proxy' });
    assert.ok(text.text.includes('q@1.5.0  NAMED WARNING (accepted by you): release-history break vs the seed (2+ package-wide signals)'), text.text);
    assert.equal(text.exit, 0, 'an accepted warning does not count toward exit 2');
    // dated note 8.5: a LATER named signal on the same version is not covered by the acceptance (D-U3)
    cli((db) => db.insertGateDecision('q', '1.5.0', 'WARN', [{ gate: 'seed-v3', result: 'WARN', detail: 'cft-policy-1.2: later signal',
      rows: [{ gate: 'seed-v3:known-malicious-pin', result: 'ALLOW' }, { gate: 'seed-v3:channel-a:critical', result: 'WARN' },
        { gate: 'seed-v3:dac-trajectory:surface', result: 'WARN' }] }]));
    const later = await get(`${proxyUrl}${tgz('q', '1.5.0')}`);
    assert.match(later.headers['npm-notice'] ?? '', /^chaingate: WARNING q@1\.5\.0: release-history break vs the seed \(3\+ of 5 groups\)/, JSON.stringify(later.headers));
    assert.equal(later.headers['cache-control'], 'no-store');
    // G2d-3: an acceptance never overrides a BLOCK
    await get(`${proxyUrl}/p`);
    cli((db) => db.upsertAcceptance({ package_name: 'p', version: '1.3.0', named: ['seed-v3:dac-trajectory:surface'], decision_id: null, policy_version: 'cft-policy-1.2' }));
    const b = await get(`${proxyUrl}${tgz('p', '1.3.0')}`);
    assert.equal(b.status, 403);
    assert.match(b.headers['npm-notice'], /^chaingate: BLOCKED p@1\.3\.0/);
  });
});

test('G2d-13 (D-U9) report lines for accepted, pin-refused and pin-withheld events, and their exit codes', () => {
  const START = '2026-10-12T09:00:00.000Z';
  const wrap = (events) => ({ service: 'chaingate-proxy', version: '0.1.4', started_at: START, policy: 'cft-policy-1.2', view: 'latest',
    seed: { sha256: 'ab'.repeat(32), history_cutoff: '2026-12-31T00:00:00Z' }, stats: { installs_evicted: 0 },
    installs: [{ key: 'npm-session:a', grouping: 'npm-session', started_at: START, last_at: START, dropped: 0, dropped_important: 0,
      events: events.map((e) => ({ at: START, ...e })) }] });
  const acc = { kind: 'served', package: 'q', version: '1.5.0', class: 'named', coverage: 'checked', named: ['seed-v3:dac-trajectory:surface'],
    contributing: [], reason: 'r', policy: 'cft-policy-1.2', notice: false, k: '1.4.0', accepted: true };
  const a = renderReport(wrap([acc]), { source: 'proxy' });
  assert.ok(a.text.includes('q@1.5.0  NAMED WARNING (accepted by you): release-history break vs the seed (2+ package-wide signals)'));
  assert.ok(!a.text.includes('chaingate pin q@1.4.0'), 'no action block for an accepted warning');
  assert.equal(a.exit, 0);
  const pinRef = { kind: 'refused', package: 'q', version: '1.5.0', facts: [], status: 403, reason: 'pinned', policy: null, pinned: { k: '1.4.0' } };
  const b = renderReport(wrap([pinRef]), { source: 'proxy' });
  assert.ok(b.text.includes('q@1.5.0  WITHHELD BY YOUR PIN (download refused): pinned to 1.4.0 — undo: chaingate unpin q'), b.text);
  assert.equal(b.exit, 3);
  const ctx = { kind: 'pin-withheld', package: 'q', k: '1.4.0', versions: ['1.4.5', '1.5.0'], more: 0, tags: [{ tag: 'latest', from: '1.5.0', to: '1.4.0' }] };
  const c = renderReport(wrap([ctx, { kind: 'served', package: 'q', version: '1.4.0', class: 'clean', coverage: 'checked', named: [], contributing: [], reason: 'r', policy: 'cft-policy-1.2', notice: false, k: null }]), { source: 'proxy' });
  assert.ok(c.text.includes('your pin on q (1.4.0) withheld 2 version(s); dist-tag latest → 1.4.0'), c.text);
  assert.equal(c.exit, 0, 'pin context changes no exit code');
});
