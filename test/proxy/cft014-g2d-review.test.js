// 0.1.4 group 2, unit 2d — review fixes and added guards (dated note 8; G2d-14..G2d-18). Expected results: decision tables
// ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G2-TIER0-20261011.md, dated note 8, written before this file and the fixes.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createProxyServer } from '../../proxy/server.js';
import { openWitnessDB } from '../../witness/db.js';
import { withheldBy } from '../../witness/pins.js';
import { rewritePackument } from '../../gates/rewriter.js';
import { renderReport } from '../../cli/report-render.js';
import { buildSeed, docFor, after, LIVE } from '../seed-v3/u05-fixtures.mjs';

const listen = (srv) => new Promise((resolve) => { srv.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${srv.address().port}`)); });
const close = (srv) => new Promise((resolve) => { srv.close(() => resolve()); });
const get = (url) => new Promise((resolve, reject) => {
  http.get(url, { agent: false }, (res) => {
    let b = ''; res.setEncoding('utf8'); res.on('data', (x) => { b += x; });
    res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* not JSON */ } resolve({ status: res.statusCode, headers: res.headers, json }); });
  }).on('error', reject);
});

test('G2d-14 (note 8.1) a tag on a version both BLOCKed and pin-withheld stays in the pin\'s class; it is still a BLOCK move', () => {
  const doc = docFor('q', [['1.4.0', after(1)], ['1.4.5', after(2)], ['1.5.0', after(3)], ['2.0.0', after(4)]]);
  doc['dist-tags'] = { latest: '1.5.0' };
  const pins = [{ package_name: 'q', class_key: '1', k_version: '1.4.0' }];
  const decisions = new Map(Object.keys(doc.versions).map((v) => [v, { disposition: 'ALLOW', results: [] }]));
  decisions.set('1.5.0', { disposition: 'BLOCK', results: [{ gate: 'seed-v3', result: 'BLOCK', detail: 'advisory' }] });
  const { packument, summary } = rewritePackument(doc, decisions, { pinned: (v) => withheldBy(pins, 'q', v) });
  assert.equal(packument['dist-tags'].latest, '1.4.0', 'never 2.0.0 against a 1.x pin');
  const move = summary.dist_tag_downgrades.find((d) => d.tag === 'latest');
  assert.deepEqual([move.from, move.to, move.pin], ['1.5.0', '1.4.0', undefined], 'a BLOCK move (its fact, its reason), not a pin move');
  assert.deepEqual(summary.blocked.map((b) => b.version), ['1.5.0']);
  // without a pin the BLOCK walk is unchanged (across majors)
  const plain = rewritePackument(doc, decisions);
  assert.equal(plain.packument['dist-tags'].latest, '2.0.0');
});

test('G2d-15 (note 8.2) disk mode: an accepted warning is listed with its binding, and the empty sentence is not printed', () => {
  const row = { at: '2026-10-12T10:00:00.000Z', kind: 'named-served', package_name: 'q', version: '1.5.0',
    classes: { named: ['seed-v3:dac-trajectory:surface'], accepted: true }, reason: 'r', policy_version: 'cft-policy-1.2',
    seed_sha256: 'cd'.repeat(32), install_key: 'k', k_version: '1.4.0' };
  const r = renderReport({ host: '127.0.0.1', port: 1, why: 'nothing is listening', since: '24h', events: [row] }, { source: 'disk' });
  assert.ok(r.text.includes('q@1.5.0  NAMED WARNING (accepted by you): release-history break vs the seed (2+ package-wide signals)'), r.text);
  assert.ok(r.text.includes('recorded: policy cft-policy-1.2, seed cdcdcdcdcdcdcdcd'), 'bound to its policy and seed');
  assert.ok(!r.text.includes('No named warning, refusal or tag move was recorded'), r.text);
  assert.equal(r.exit, 0, 'accepted: no exit 2');
});

test('G2d-16 (D-U1, note 8.5) the adjudication log is append-only: UPDATE and DELETE are refused', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2d16-'));
  try {
    const db = openWitnessDB(path.join(dir, 'witness.db')).applySchema();
    try {
      db.appendAdjudication({ action: 'pin', package_name: 'q', version: '1.4.0', k_version: '1.4.0', classes: {}, interactive: false, ci: false });
      assert.throws(() => db.db.prepare("UPDATE adjudications SET action = 'unpin'").run(), /append-only/);
      assert.throws(() => db.db.prepare('DELETE FROM adjudications').run(), /append-only/);
      assert.throws(() => db.appendAdjudication({ action: 'erase', package_name: 'q', classes: {}, interactive: false, ci: false }), /CHECK/);
      assert.equal(db.listAdjudications().length, 1);
    } finally { db.close(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('G2d-17 (D-U6, note 8.5) the REAL proxy: a pins read failure keeps the last good set, and /self shows last_error', async () => {
  const s = buildSeed({ layout: '1.1' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2d17-'));
  const doc = docFor('q', [['1.4.0', after(1)], ['1.5.0', after(2)]]);
  const upstream = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(doc)); });
  const up = await listen(upstream);
  const dbPath = path.join(dir, 'witness.db');
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: up, witnessDbPath: dbPath, headersTimeoutMs: 5_000,
    bodyTimeoutMs: 15_000, seedV3Path: s.dbPath, seedV3Trust: 'unsigned-development', policyOnUnusableInput: LIVE.on_unusable_input,
    policyOnNoEvidence: LIVE.on_no_evidence });
  const url = await listen(proxy);
  const realErr = console.error; const logs = []; console.error = (m) => logs.push(String(m));
  try {
    const rw = openWitnessDB(dbPath).applySchema();
    try { rw.upsertPin({ package_name: 'q', class_key: '1', k_version: '1.4.0' }); } finally { rw.close(); }
    assert.ok(!('1.5.0' in (await get(`${url}/q`)).json.versions));
    const raw = openWitnessDB(dbPath);
    try { raw.db.exec('DROP TABLE pins'); } finally { raw.close(); }
    assert.ok(!('1.5.0' in (await get(`${url}/q`)).json.versions), 'the last good set still holds the pin');
    const self = (await get(`${url}/_chaingate/self`)).json;
    assert.match(String(self.pins.last_error), /pins/);
    assert.equal(self.pins.count, 1);
    assert.equal(logs.filter((l) => l.startsWith('[pins] could not read the pins')).length, 1, 'logged once');
  } finally {
    console.error = realErr;
    await close(proxy); await close(upstream); s.cleanup(); fs.rmSync(dir, { recursive: true, force: true });
  }
});
