// 0.1.4 group 3, unit 3a — T1.1 install-introduced (L1 + L1i) from the served packument, named; T1.2 size-jump and T1.3
// publish-tool-change, contributing; named runner rows in classify, V6 and K. Expected results: decision tables
// ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G3-TIER1-20261012.md §2, written before this file. The counted rule is
// validate_a1.py `eval_rule` (A1, ecb06386…) over validate.py `hooks` (PROTOCOL 78878f55…); its port below is written
// from that Python, independently of the gate.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import installIntroduced from '../../gates/install-introduced.js';
import sizeJump from '../../gates/size-jump.js';
import publishToolChange from '../../gates/publish-tool-change.js';
import { CONTRIBUTING_GATES, withRole } from '../../gates/row-class.js';
import POL from '../../seed/v3/policy.js';
import { classify, servedClass } from '../../witness/row-class.js';
import { buildNotice } from '../../proxy/notice.js';
import { renderReport } from '../../cli/report-render.js';
import { openWitnessDB } from '../../witness/db.js';
import { lastVersionWithoutSignal } from '../../witness/last-without-signal.js';

const H = 3_600_000;
const T0 = Date.parse('2026-06-01T00:00:00Z');
const at = (h) => new Date(T0 + h * H).toISOString();
/** A packument from [[version, hoursAfterT0 | null, manifestExtra]] */
function pk(rows) {
  const versions = {}; const time = { created: at(0), modified: at(9999) };
  for (const [v, h, extra = {}] of rows) { versions[v] = { name: 'x', version: v, ...extra }; if (h !== null) time[v] = at(h); }
  return { versions, time };
}
const run = (doc, version) => installIntroduced.evaluate({ version, rawVersions: doc.versions, rawTimes: doc.time });
const HOOK = { scripts: { postinstall: 'node s.js' } };

// ---- the counted rule, ported from validate_a1.py / validate.py (Python truthiness: bool(v) and v not in ("",0,False,[],{})) ----
const pyTruthy = (v) => !(v === undefined || v === null || v === false || v === '' || v === 0
  || (Array.isArray(v) && v.length === 0) || (v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === 0));
const HOOKS = ['preinstall', 'install', 'postinstall'];
const hooksOf = (man) => { const s = man && typeof man === 'object' ? man.scripts : null; const o = {};
  if (s && typeof s === 'object' && !Array.isArray(s)) for (const k of HOOKS) if (pyTruthy(s[k])) o[k] = s[k]; return o; };
function evalRule(doc, ver, windowMs) {
  const t = doc.time; const vs = doc.versions;
  if (!(ver in vs) || !(ver in t)) return null;
  const c = Date.parse(t[ver]);
  const prior = Object.keys(vs).filter((v) => v in t && v !== ver && !Number.isNaN(Date.parse(t[v]))
    && Date.parse(t[v]) <= c - windowMs && (windowMs > 0 || Date.parse(t[v]) < c));
  if (!prior.length) return null;
  const cur = hooksOf(vs[ver]); const ever = prior.some((v) => Object.keys(hooksOf(vs[v])).length > 0);
  const gyp = Boolean(vs[ver].gypfile) && !('install' in cur || 'preinstall' in cur);
  return { L1: Object.keys(cur).length > 0 && !ever, L1i: gyp && !ever };
}
/** 1.2's rule (§18.10): the settled window; on cold start the plain rule. */
const counted = (doc, ver) => evalRule(doc, ver, 24 * H) ?? evalRule(doc, ver, 0);

test('G3a-1 (D-T1) L1: first hook vs a hookless settled set; settled hooked history; staging ignored; cold start plain; not evaluable', () => {
  const doc = pk([['1.0.0', 0], ['1.1.0', 48], ['1.2.0', 96, HOOK], ['1.3.0', 144, HOOK]]);
  const r12 = run(doc, '1.2.0');
  assert.equal(r12.gate, 'install-introduced');
  assert.equal(r12.result, 'WARN');
  assert.match(r12.detail, /postinstall/);
  assert.match(r12.detail, /settled 24 h/);
  assert.equal(run(doc, '1.3.0').result, 'ALLOW', 'an earlier settled version had a hook');
  const staging = pk([['1.0.0', 0], ['1.0.1', 50], ['1.1.0', 199, HOOK], ['1.2.0', 200, HOOK]]);
  assert.equal(run(staging, '1.2.0').result, 'WARN', 'a hooked staging release < 24 h earlier does not suppress it');
  const cold = pk([['1.0.0', 0], ['1.0.1', 1, HOOK]]);
  const rc = run(cold, '1.0.1');
  assert.equal(rc.result, 'WARN');
  assert.match(rc.detail, /cold start: plain/);
  const coldQuiet = pk([['1.0.0', 0, HOOK], ['1.0.1', 1, HOOK]]);
  assert.equal(run(coldQuiet, '1.0.1').result, 'ALLOW');
  assert.equal(run(doc, '1.0.0').result, 'SKIP', 'no earlier version');
  const noTime = pk([['1.0.0', 0], ['1.1.0', null, HOOK]]);
  assert.equal(run(noTime, '1.1.0').result, 'SKIP', 'no publication time');
});

test('G3a-2 (D-T1) L1i: gypfile without install/preinstall and no earlier hooks; a postinstall makes it L1', () => {
  const gyp = pk([['1.0.0', 0], ['1.1.0', 48, { gypfile: true }]]);
  const r = run(gyp, '1.1.0');
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /gypfile/);
  const gypPost = pk([['1.0.0', 0], ['1.1.0', 48, { gypfile: true, scripts: { postinstall: 'x' } }]]);
  assert.match(run(gypPost, '1.1.0').detail, /postinstall/);
  const gypInstall = pk([['1.0.0', 0], ['1.1.0', 48, { gypfile: true, scripts: { install: 'node-gyp rebuild' } }]]);
  assert.match(run(gypInstall, '1.1.0').detail, /install/);
});

test('G3a-3 (D-T1) parity with the counted rule on generated packuments, falsy hooks and odd times included', () => {
  let seed = 7;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  const FALSY = ['', 0, [], {}, false, null];
  let compared = 0;
  for (let n = 0; n < 300; n += 1) {
    const rows = [];
    const count = 1 + Math.floor(rnd() * 8);
    for (let i = 0; i < count; i += 1) {
      const r = rnd();
      const extra = r < 0.2 ? HOOK : r < 0.3 ? { scripts: { install: FALSY[Math.floor(rnd() * FALSY.length)] } }
        : r < 0.38 ? { gypfile: true } : r < 0.42 ? { gypfile: true, scripts: { preinstall: 'p' } } : {};
      const h = rnd() < 0.05 ? null : Math.floor(rnd() * 120);
      rows.push([`1.0.${i}`, h, extra]);
    }
    const doc = pk(rows);
    if (rnd() < 0.05) doc.time['1.0.0'] = 'not a time';
    for (const [v] of rows) {
      const want = counted(doc, v);
      const got = run(doc, v);
      if (want === null) assert.equal(got.result, 'SKIP', `${JSON.stringify(doc)} ${v}`);
      else assert.equal(got.result, want.L1 || want.L1i ? 'WARN' : 'ALLOW', `${JSON.stringify(doc)} ${v}`);
      compared += 1;
    }
  }
  assert.ok(compared > 500);
});

test('G3a-4 (D-T1) cost: 5,000 versions evaluated in under 2 s (memoised per packument)', () => {
  const rows = [];
  for (let i = 0; i < 5000; i += 1) rows.push([`1.${Math.floor(i / 100)}.${i % 100}`, i, i === 4000 ? HOOK : {}]);
  const doc = pk(rows);
  const t = Date.now();
  let warns = 0;
  for (const [v] of rows) if (run(doc, v).result === 'WARN') warns += 1;
  assert.ok(Date.now() - t < 2000, `${Date.now() - t} ms`);
  assert.equal(warns, 1);
});

test('G3a-5 (D-T2) an install-introduced WARN is a named row: classify, notice label, report block with a packument baseline', () => {
  const row = { gate: 'install-introduced', result: 'WARN', detail: 'postinstall present; no earlier version (settled 24 h, 2) had an install hook' };
  assert.deepEqual(POL.NAMED_RUNNER_GATES, ['install-introduced']);
  assert.deepEqual(classify([row]).named, ['install-introduced']);
  assert.equal(servedClass([row]).class, 'named');
  assert.equal(buildNotice({ kind: 'WARNING', pkg: 'h', version: '1.2.0', labels: ['install-introduced'] }),
    'chaingate: WARNING h@1.2.0: an install script appears that earlier releases did not have. Details: chaingate why h@1.2.0');
  const START = '2026-10-12T09:00:00.000Z';
  const text = renderReport({ service: 'chaingate-proxy', version: '0.1.4', started_at: START, policy: 'cft-policy-1.2', view: 'latest',
    seed: null, stats: {}, installs: [{ key: 'npm-session:a', grouping: 'npm-session', started_at: START, last_at: START, dropped: 0,
      dropped_important: 0, events: [{ at: START, kind: 'served', package: 'h', version: '1.2.0', class: 'named', coverage: 'no-seed',
        named: ['install-introduced'], contributing: [], reason: `install-introduced: ${row.detail}`, policy: null, notice: true, k: null }] }] },
  { source: 'proxy' }).text;
  assert.ok(text.includes('h@1.2.0  NAMED WARNING: an install script appears that earlier releases did not have'), text);
  assert.ok(text.includes('  baseline: packument'), text);
});

test('G3a-6 (D-T4) size-jump: >= 2x vs the same-major, non-prerelease, earlier, lower predecessor; contributing', () => {
  const doc = pk([['1.0.0', 0, { dist: { unpackedSize: 1000 } }], ['1.1.0-slim', 10, { dist: { unpackedSize: 50 } }],
    ['1.1.0', 20, { dist: { unpackedSize: 2500 } }], ['1.2.0', 30, { dist: { unpackedSize: 4700 } }], ['2.0.0', 40, { dist: { unpackedSize: 99999 } }],
    ['1.3.0', 50, {}]]);
  const s = (v) => sizeJump.evaluate({ version: v, rawVersions: doc.versions, rawTimes: doc.time });
  assert.equal(s('1.1.0').result, 'WARN', '2.5x of 1.0.0 (the -slim sibling is never a predecessor)');
  assert.match(s('1.1.0').detail, /2\.5×/);
  assert.equal(s('1.2.0').result, 'ALLOW', '1.88x');
  assert.equal(s('2.0.0').result, 'SKIP', 'no predecessor in major 2');
  assert.equal(s('1.3.0').result, 'SKIP', 'size missing');
  assert.equal(withRole(s('1.1.0')).result, 'NOTE', 'contributing in 1.2');
});

test('G3a-7 (D-T5) publish-tool-change: a downgrade of _npmVersion vs the predecessor; upgrades are not signals', () => {
  const doc = pk([['1.0.0', 0, { _npmVersion: '11.2.0' }], ['1.1.0', 20, { _npmVersion: '9.8.1' }], ['1.2.0', 30, { _npmVersion: '10.0.0' }],
    ['1.3.0', 40, {}]]);
  const t = (v) => publishToolChange.evaluate({ version: v, rawVersions: doc.versions, rawTimes: doc.time });
  assert.equal(t('1.1.0').result, 'WARN');
  assert.match(t('1.1.0').detail, /11\.2\.0 → 9\.8\.1/);
  assert.equal(t('1.2.0').result, 'ALLOW');
  assert.equal(t('1.3.0').result, 'SKIP');
  assert.equal(withRole(t('1.1.0')).result, 'NOTE');
});

test('G3a-8 (D-T3) V6 and K: a release checked only by the install-hook rule is not "not checked"; K may be such a version', () => {
  const uncovered = { gate: 'seed-v3', result: 'WARN', detail: 'cft-policy-1.2: …', rows: [{ gate: 'seed-v3:known-malicious-pin', result: 'ALLOW' },
    { gate: 'seed-v3:channel-a', result: 'SKIP' }, { gate: 'seed-v3:dac-trajectory:surface', result: 'SKIP' }, { gate: 'seed-v3:coverage', result: 'WARN' }] };
  const t11 = { gate: 'install-introduced', result: 'ALLOW', detail: 'no install hook' };
  const c = servedClass([uncovered, t11]);
  assert.deepEqual([c.class, c.coverage], ['clean', 'not-covered']);
  assert.equal(servedClass([uncovered]).class, 'not-checked');
  const START = '2026-10-12T09:00:00.000Z';
  const ev = (pkg, over) => ({ at: START, kind: 'served', package: pkg, version: '1.0.0', named: [], contributing: [], reason: 'r', policy: 'cft-policy-1.2', notice: false, k: null, ...over });
  const text = renderReport({ service: 'chaingate-proxy', version: '0.1.4', started_at: START, policy: 'cft-policy-1.2', view: 'latest', seed: null, stats: {},
    installs: [{ key: 'npm-session:a', grouping: 'npm-session', started_at: START, last_at: START, dropped: 0, dropped_important: 0,
      events: [ev('a', { class: 'clean', coverage: 'not-covered' }), ev('b', { class: 'not-checked', coverage: 'not-covered' })] }] }, { source: 'proxy' }).text;
  assert.ok(text.includes('1 package(s) were not checked by any named rule: 1 not covered by the seed or not placeable in its history'), text);
  assert.ok(text.includes('1 package(s) were checked only by the install-hook rule (the seed had no usable history for them).'), text);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g3a8-'));
  try {
    const db = openWitnessDB(path.join(dir, 'witness.db')).applySchema();
    try {
      const T = Date.parse('2026-06-01T00:00:00Z');
      db.recordBaseline('u', '1.2.0', { published_at: new Date(T).toISOString() });
      db.insertGateDecision('u', '1.2.0', 'WARN', [uncovered, { gate: 'install-introduced', result: 'WARN', detail: 'x' }]);
      db.recordBaseline('u', '1.1.0', { published_at: new Date(T - 48 * H).toISOString() });
      db.insertGateDecision('u', '1.1.0', 'WARN', [uncovered, t11]);
      assert.equal(lastVersionWithoutSignal(db, 'u', '1.2.0'), '1.1.0', 'evaluated by a named rule (T1.1)');
    } finally { db.close(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('G3a-9 (D-T6) the 1.2 role tables', () => {
  assert.deepEqual([...CONTRIBUTING_GATES].sort(), ['dep-structure', 'provenance-continuity', 'publish-tool-change', 'publisher-identity',
    'release-age', 'scope-boundary', 'size-jump']);
  assert.deepEqual(POL.NAMED_RUNNER_GATES, ['install-introduced']);
});
