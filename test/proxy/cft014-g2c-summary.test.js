// 0.1.4 group 2, unit 2c — the conclusion, pure parts: the install summary (D-R1), coverage classes (D-R7), the last
// version without the signal (D-R5) and the report text and exit codes (D-R3, D-R4, D-R6, D-R8). Expected results: decision
// tables ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G2-TIER0-20261011.md §7 and dated note 6, written before this file.
// Proxy and CLI cases are in cft014-g2c-report.test.js and test/cli/cft014-g2c-report-cli.test.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createInstallSummary, isLoopbackPeer } from '../../proxy/install-summary.js';
import { coverageClass, servedClass } from '../../witness/row-class.js';
import { lastVersionWithoutSignal } from '../../witness/last-without-signal.js';
import { openWitnessDB } from '../../witness/db.js';
import { renderReport } from '../../cli/report-render.js';

const served = (pkg, version, over = {}) => ({ kind: 'served', package: pkg, version, class: 'clean', coverage: 'checked',
  named: [], contributing: [], reason: 'seed-v3: cft-policy-1.2: ok', policy: 'cft-policy-1.2', notice: false, k: null, ...over });
const named = (pkg, version, over = {}) => served(pkg, version, { class: 'named', named: ['seed-v3:dac-trajectory:surface'],
  contributing: ['seed-v3:dac-trajectory:any'], reason: 'seed-v3: cft-policy-1.2: seed-v3:dac-trajectory:surface: 2/2 witnesses broke',
  notice: true, ...over });
const refused = (pkg, version, facts, over = {}) => ({ kind: 'refused', package: pkg, version, facts, status: 403,
  reason: 'seed-v3: cft-policy-1.2: seed-v3:known-malicious-pin: recorded advisory ADV-P-130', policy: 'cft-policy-1.2', ...over });

test('G2c-1a (D-R1) one npm-session value is one install; without it a 60 s client idle gap splits installs', () => {
  let t = 0;
  const s = createInstallSummary({ now: () => t });
  s.record({ session: 'aaaa1111', client: '127.0.0.1' }, served('a', '1.0.0'));
  s.record({ session: 'bbbb2222', client: '127.0.0.1' }, served('b', '1.0.0'));
  t = 5_000; s.record({ session: 'aaaa1111', client: '127.0.0.1' }, served('c', '1.0.0'));
  t = 10_000; s.record({ client: '127.0.0.1' }, served('d', '1.0.0'));
  t = 40_000; s.record({ client: '127.0.0.1' }, served('e', '1.0.0'));               // 30 s idle: same install
  t = 101_001; s.record({ client: '127.0.0.1' }, served('f', '1.0.0'));              // 61 s idle: a new install
  t = 102_000; s.record({ session: 'bad value!', client: '127.0.0.1' }, served('g', '1.0.0')); // invalid header: idle grouping
  const { installs } = s.snapshot({ all: true });
  const by = (pkgs) => installs.find((i) => i.events.map((e) => e.package).join() === pkgs);
  assert.equal(installs.length, 4, JSON.stringify(installs.map((i) => i.events.map((e) => e.package))));
  assert.equal(by('a,c').grouping, 'npm-session');
  assert.equal(by('b').grouping, 'npm-session');
  assert.equal(by('d,e').grouping, 'client-idle');
  assert.equal(by('f,g').grouping, 'client-idle');
  assert.equal(by('a,c').events[1].at, new Date(5_000).toISOString(), 'each event carries its time');
});

test('G2c-1b (D-R1) at 2,000 events ordinary ones drop first, named and fact events never before them, drops counted', () => {
  const s = createInstallSummary({ now: () => 0 });
  const who = { session: 'cccc3333' };
  for (let i = 0; i < 2000; i += 1) s.record(who, served(`o${i}`, '1.0.0'));
  s.record(who, named('n', '1.0.0'));                                     // full: an ordinary event makes room
  s.record(who, served('late', '1.0.0'));                                 // full: an incoming ordinary event is dropped
  let [inst] = s.snapshot({ all: true }).installs;
  assert.equal(inst.events.length, 2000);
  assert.ok(inst.events.some((e) => e.package === 'n'), 'the named event is kept');
  assert.ok(!inst.events.some((e) => e.package === 'late'));
  assert.equal(inst.dropped, 2);
  assert.equal(inst.dropped_important, 0);
  for (let i = 0; i < 1999; i += 1) s.record(who, refused(`r${i}`, '1.0.0', ['seed-v3:pin']));
  [inst] = s.snapshot({ all: true }).installs;
  assert.equal(inst.events.filter((e) => e.kind === 'served' && e.class !== 'named').length, 0, 'every ordinary event gave way');
  s.record(who, { kind: 'tag-moved', package: 'z', tag: 'latest', from: '2.0.0', to: '1.0.0', facts: ['seed-v3:pin'], reason: 'x' });
  [inst] = s.snapshot({ all: true }).installs;
  assert.equal(inst.events.length, 2000);
  assert.equal(inst.dropped_important, 1, 'only when nothing ordinary is left does an important event drop, counted');
  assert.equal(inst.dropped, 2002, '`dropped` is every event not recorded, important ones included');
});

test('G2c-1c (D-R1) at most 20 installs (least recently active evicted); `fresh` is per install; default = latest with a tarball', () => {
  let t = 0;
  const s = createInstallSummary({ now: () => t });
  for (let i = 0; i < 21; i += 1) { t = i * 1000; s.record({ session: `s${i}` }, served(`p${i}`, '1.0.0')); }
  const all = s.snapshot({ all: true });
  assert.equal(all.installs.length, 20);
  assert.ok(!all.installs.some((i) => i.events[0].package === 'p0'), 'the oldest install was evicted');
  assert.equal(all.stats.installs_evicted, 1);
  const first = s.record({ session: 'fx' }, named('q', '1.5.0'));
  const again = s.record({ session: 'fx' }, named('q', '1.5.0'));
  const other = s.record({ session: 'fy' }, named('q', '1.5.0'));
  assert.deepEqual([first.fresh, again.fresh, other.fresh], [true, false, true]);
  t = 99_000;
  s.record({ session: 'pk' }, { kind: 'tag-moved', package: 'p', tag: 'latest', from: '1.3.0', to: '1.2.0', facts: ['seed-v3:pin'], reason: 'x' });
  const latest = s.snapshot();
  assert.equal(latest.installs.length, 1);
  assert.equal(latest.installs[0].key, 'npm-session:fy', 'a packument-only install is not the default report');
  const empty = createInstallSummary({ now: () => 0 }).snapshot();
  assert.deepEqual(empty.installs, []);
});

test('G2c-1d (dated note 6.9) the report endpoint answers loopback peers only', () => {
  for (const a of ['127.0.0.1', '127.8.9.10', '::1', '::ffff:127.0.0.1']) assert.equal(isLoopbackPeer(a), true, a);
  for (const a of ['10.0.0.5', '192.168.1.2', '::ffff:10.0.0.1', 'fe80::1', '', undefined, null]) assert.equal(isLoopbackPeer(a), false, String(a));
});

// --- D-R7 coverage classes (structural; dated note 6.4) ---
const seedRow = (result, rows, prefix = 'cft-policy-1.2') => ({ gate: 'seed-v3', result, detail: `${prefix}: …`, rows });
const R = (gate, result) => ({ gate: `seed-v3:${gate}`, result });
const PIN_OK = R('known-malicious-pin', 'ALLOW');

test('G2c-6a (D-R7) coverageClass: no-seed, earlier-policy, failed, not-covered, indeterminate, checked', () => {
  const cases = [
    ['no seed-v3 result', [{ gate: 'content-hash', result: 'ALLOW', detail: 'x' }], 'no-seed'],
    ['a 1.1 row (rowless)', [{ gate: 'seed-v3', result: 'ALLOW', detail: 'cft-policy-1.1: seed-v3:channel-a:critical: …' }], 'earlier-policy'],
    ['a rowless 1.2 failure', [{ gate: 'seed-v3', result: 'WARN', detail: 'cft-policy-1.2: the seed-v3 path could not run (boom)' }], 'failed'],
    ['input WARN', [seedRow('WARN', [R('known-malicious-pin', 'SKIP'), R('input', 'WARN'), R('channel-a:critical', 'ALLOW'), R('dac-trajectory:surface', 'ALLOW')])], 'failed'],
    ['input SKIP (REFUSE_TO_DECIDE)', [seedRow(null, [R('known-malicious-pin', 'SKIP'), R('input', 'SKIP')])], 'failed'],
    ['uncovered package', [seedRow('WARN', [PIN_OK, R('channel-a', 'SKIP'), R('dac-trajectory:surface', 'SKIP'), R('dac-trajectory:any', 'SKIP'), R('coverage', 'SKIP'), R('coverage', 'WARN')])], 'not-covered'],
    ['uncovered, no coverage WARN (on_no_evidence ALLOW)', [seedRow('ALLOW', [PIN_OK, R('channel-a', 'SKIP'), R('dac-trajectory:surface', 'SKIP'), R('coverage', 'SKIP')])], 'not-covered'],
    ['not placed but surface evaluated', [seedRow('ALLOW', [PIN_OK, R('channel-a', 'SKIP'), R('dac-trajectory:surface', 'ALLOW'), R('dac-trajectory:any', 'ALLOW')])], 'checked'],
    ['first release of a recorded lineage', [seedRow('WARN', [PIN_OK, R('channel-a:critical', 'SKIP'), R('dac-trajectory:surface', 'SKIP'), R('coverage', 'WARN')])], 'indeterminate'],
    ['the same under on_no_evidence ALLOW', [seedRow('ALLOW', [PIN_OK, R('channel-a:critical', 'SKIP'), R('dac-trajectory:surface', 'SKIP')])], 'indeterminate'],
    ['surface SKIP beside critical ALLOW and any NOTE (2a review)', [seedRow('ALLOW', [PIN_OK, R('channel-a:critical', 'ALLOW'), R('dac-trajectory:surface', 'SKIP'), R('dac-trajectory:any', 'NOTE')])], 'indeterminate'],
    ['both named determinate', [seedRow('ALLOW', [PIN_OK, R('channel-a:critical', 'ALLOW'), R('dac-trajectory:surface', 'ALLOW'), R('dac-trajectory:any', 'NOTE')])], 'checked'],
    ['named WARN', [seedRow('WARN', [PIN_OK, R('channel-a:critical', 'ALLOW'), R('dac-trajectory:surface', 'WARN')])], 'checked'],
  ];
  for (const [what, results, want] of cases) assert.equal(coverageClass(results), want, what);
});

test('G2c-6b (D-R1, dated note 6.5) servedClass: named > not-checked > contributing > clean', () => {
  const checkedRows = [PIN_OK, R('channel-a:critical', 'ALLOW'), R('dac-trajectory:surface', 'ALLOW')];
  assert.equal(servedClass([seedRow('WARN', [PIN_OK, R('channel-a:critical', 'ALLOW'), R('dac-trajectory:surface', 'WARN')])]).class, 'named');
  assert.equal(servedClass([seedRow('ALLOW', [...checkedRows, R('dac-trajectory:any', 'NOTE')])]).class, 'contributing');
  assert.equal(servedClass([seedRow('ALLOW', checkedRows)]).class, 'clean');
  const pilotNote = servedClass([seedRow('ALLOW', checkedRows), { gate: 'publisher-identity', result: 'NOTE', detail: 'x' }]);
  assert.deepEqual([pilotNote.class, pilotNote.contributing], ['contributing', ['publisher-identity']]);
  const unc = servedClass([seedRow('WARN', [PIN_OK, R('channel-a', 'SKIP'), R('dac-trajectory:surface', 'SKIP'), R('coverage', 'WARN')]),
    { gate: 'publisher-identity', result: 'NOTE', detail: 'x' }]);
  assert.deepEqual([unc.class, unc.coverage], ['not-checked', 'not-covered']);
});

// --- D-R5 the last version without the signal (dated note 6.1-6.3) ---
const H = 3_600_000;
function kDb() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2c-k-'));
  const db = openWitnessDB(path.join(dir, 'witness.db')).applySchema();
  return { db, cleanup: () => { db.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}
const CHECKED = [PIN_OK, R('channel-a:critical', 'ALLOW'), R('dac-trajectory:surface', 'ALLOW')];
function put(db, pkg, version, publishedMs, { disposition = 'ALLOW', rows = CHECKED, extra = [] } = {}) {
  db.recordBaseline(pkg, version, { published_at: publishedMs == null ? null : new Date(publishedMs).toISOString() });
  db.insertGateDecision(pkg, version, disposition, [seedRow(disposition, rows), ...extra]);
}

test('G2c-5a (D-R5) K: settled >= 24 h, same major, lower, release, unnamed, no fact, not BLOCK, evaluated, not overridden', () => {
  const { db, cleanup } = kDb();
  try {
    const T = Date.parse('2026-06-01T00:00:00Z');
    put(db, 'k', '1.5.0', T, { disposition: 'WARN', rows: [PIN_OK, R('channel-a:critical', 'ALLOW'), R('dac-trajectory:surface', 'WARN')] });
    put(db, 'k', '1.4.9', T - 1 * H);                                                          // decoy: not settled
    put(db, 'k', '1.4.5-beta.1', T - 30 * H);                                                  // prerelease
    put(db, 'k', '1.4.4', T - 25 * H, { extra: [{ gate: 'override', result: 'ALLOW', detail: 'x' }] });   // override-based
    put(db, 'k', '1.4.3', T - 26 * H, { rows: [PIN_OK, R('channel-a:critical', 'ALLOW'), R('dac-trajectory:surface', 'SKIP')] }); // not evaluated
    put(db, 'k', '1.4.2', T - 30 * H, { disposition: 'WARN', rows: [PIN_OK, R('channel-a:critical', 'WARN'), R('dac-trajectory:surface', 'ALLOW')] }); // named
    put(db, 'k', '1.4.1', T - 40 * H, { disposition: 'BLOCK', rows: [R('known-malicious-pin', 'BLOCK'), R('channel-a:critical', 'ALLOW'), R('dac-trajectory:surface', 'ALLOW')] }); // fact
    put(db, 'k', '1.4.0', T - 48 * H, { rows: [...CHECKED, R('dac-trajectory:any', 'NOTE')] }); // contributing is allowed: K
    put(db, 'k', '1.3.0', T - 72 * H);
    put(db, 'k', '2.0.0', T - 100 * H);                                                        // another major, and higher
    assert.equal(lastVersionWithoutSignal(db, 'k', '1.5.0'), '1.4.0');
    // seen (6.1): a version absent from the latest packument this proxy observed is not offered
    db.db.prepare("UPDATE versions SET last_seen_at = datetime('now', '-1 day') WHERE version = '1.4.0'").run();
    assert.equal(lastVersionWithoutSignal(db, 'k', '1.5.0'), '1.3.0');
    db.db.prepare("UPDATE versions SET last_seen_at = datetime('now', '-1 day') WHERE version = '1.3.0'").run();
    assert.equal(lastVersionWithoutSignal(db, 'k', '1.5.0'), null, 'none qualifies: no K');
  } finally { cleanup(); }
});

test('G2c-5b (D-R5, 6.3) K: caret boundary for 0.x; no publication time for the warned version: no K', () => {
  const { db, cleanup } = kDb();
  try {
    const T = Date.parse('2026-06-01T00:00:00Z');
    put(db, 'z', '0.3.1', T, { disposition: 'WARN', rows: [PIN_OK, R('channel-a:critical', 'ALLOW'), R('dac-trajectory:surface', 'WARN')] });
    put(db, 'z', '0.3.0', T - 48 * H);
    put(db, 'z', '0.2.9', T - 72 * H);
    assert.equal(lastVersionWithoutSignal(db, 'z', '0.3.1'), '0.3.0');
    put(db, 'y', '0.3.1', T, { disposition: 'WARN', rows: [PIN_OK, R('channel-a:critical', 'ALLOW'), R('dac-trajectory:surface', 'WARN')] });
    put(db, 'y', '0.2.9', T - 72 * H);
    assert.equal(lastVersionWithoutSignal(db, 'y', '0.3.1'), null, '0.2.x is outside ^0.3');
    put(db, 'x', '0.0.5', T, { disposition: 'WARN', rows: [PIN_OK, R('channel-a:critical', 'ALLOW'), R('dac-trajectory:surface', 'WARN')] });
    put(db, 'x', '0.0.4', T - 72 * H);
    assert.equal(lastVersionWithoutSignal(db, 'x', '0.0.5'), null, '0.0.z: no K');
    put(db, 'w', '1.1.0', null, { disposition: 'WARN', rows: [PIN_OK, R('channel-a:critical', 'ALLOW'), R('dac-trajectory:surface', 'WARN')] });
    put(db, 'w', '1.0.0', T - 72 * H);
    assert.equal(lastVersionWithoutSignal(db, 'w', '1.1.0'), null, 'the warned version has no publication time');
  } finally { cleanup(); }
});

// --- D-R3/D-R4/D-R6/D-R8 the report text and exit codes ---
const START = '2026-10-12T09:00:00.000Z';
const payload = (events, over = {}) => ({ service: 'chaingate-proxy', version: '0.1.4', started_at: START, policy: 'cft-policy-1.2',
  seed: { sha256: 'ab'.repeat(32), history_cutoff: '2026-12-31T00:00:00Z' },
  installs: events === null ? [] : [{ key: 'npm-session:abcd1234', grouping: 'npm-session', started_at: '2026-10-12T10:00:00.000Z',
    last_at: '2026-10-12T10:00:05.000Z', dropped: 0, dropped_important: 0,
    events: events.map((e, i) => ({ at: `2026-10-12T10:00:0${Math.min(i, 9)}.000Z`, ...e })), ...over }] });
const FORBIDDEN = [/you will be told/i, /will be blocked/i, /will be held/i, /re-checked later/i, /\b0 warnings\b/i];

test('G2c-4 (D-R4) the named warning lines, exactly; no forbidden promise anywhere', () => {
  const r = renderReport(payload([named('q', '1.5.0', { k: '1.4.0' })]), { source: 'proxy' });
  const want = [
    'q@1.5.0  NAMED WARNING: release-history break vs the seed (2+ package-wide signals)',
    '  what moved: seed-v3: cft-policy-1.2: seed-v3:dac-trajectory:surface: 2/2 witnesses broke',
    '  baseline: seed (history to 2026-12-31T00:00:00Z)',
    '  already happened: ChainGate served it to npm at 2026-10-12T10:00:00.000Z; if it declares install scripts, npm ran them unless scripts were disabled',
    "  last version without the signal: q@1.4.0 (based on this proxy's records)",
    '  to stay on 1.4.0: chaingate pin q@1.4.0',
    '  to accept this version: chaingate accept q@1.5.0',
    '  if you do nothing: ChainGate checks only the requests that reach it; it does not re-check what is installed and will not tell you about this version later.',
  ];
  const lines = r.text.split('\n');
  const at = lines.indexOf(want[0]);
  assert.ok(at >= 0, r.text);
  assert.deepEqual(lines.slice(at, at + want.length), want);
  assert.ok(lines.includes('Packages npm installed from its own cache never reach ChainGate and are not listed here.'));
  assert.ok(r.text.includes('cft-policy-1.2') && r.text.includes('abababababababab'), 'the verdict is bound: policy and seed shown');
  assert.equal(r.exit, 2);

  const noK = renderReport(payload([named('q', '1.5.0', { k: null })]), { source: 'proxy' }).text;
  assert.ok(noK.includes('  last version without the signal: no earlier version qualifies (no pin offered)'));
  assert.ok(!noK.includes('chaingate pin'));

  const bad = renderReport(payload([named('Bad Name\u001b[31m', '1.5.0', { reason: 'evil\u001b]0;title\u0007\r\nfake line' })]), { source: 'proxy' }).text;
  assert.ok(!/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/.test(bad), 'no control characters reach the terminal');
  assert.ok(!bad.includes('chaingate accept'), 'no copyable command for an invalid identity');
  assert.ok(!bad.split('\n').some((l) => l.startsWith('fake line')), 'a reason cannot start a line of its own');

  const twice = renderReport(payload([named('q', '1.5.0'), named('q', '1.5.0')]), { source: 'proxy' }).text;
  assert.equal(twice.split('\n').filter((l) => l.startsWith('q@1.5.0  NAMED WARNING')).length, 1, 'one block per version');
  for (const t of [r.text, noK, bad, twice]) for (const re of FORBIDDEN) assert.ok(!re.test(t), `${re} in:\n${t}`);
});

test('G2c-8 (D-R3, 6.6) exit codes 0 / 2 / 3 / 4; the empty and partial wording', () => {
  const exit = (events, over) => renderReport(payload(events, over), { source: 'proxy' });
  assert.equal(exit([served('a', '1.0.0')]).exit, 0);
  assert.equal(exit([named('q', '1.5.0')]).exit, 2);
  assert.equal(exit([named('q', '1.5.0'), refused('p', '1.3.0', ['seed-v3:pin'])]).exit, 3);
  assert.equal(exit([refused('x', '1.0.0', [], { status: 503, reason: 'seed-v3: cft-policy-1.2: seed-v3:input: boom' })]).exit, 3, 'a non-fact refusal');
  assert.equal(exit([{ kind: 'tag-moved', package: 'p', tag: 'latest', from: '1.3.0', to: '1.2.0', facts: ['seed-v3:pin'], reason: 'x' }]).exit, 3);
  const ctx = exit([{ kind: 'withheld', package: 'p', versions: [{ version: '1.5.0', facts: ['seed-v3:pin'] }], more: 0 }, served('p', '1.2.0')]);
  assert.equal(ctx.exit, 0, 'a withheld version no tag points at changes no exit code');
  const partial = exit([served('a', '1.0.0')], { dropped: 3 });
  assert.equal(partial.exit, 4);
  assert.ok(partial.text.includes('3 events were not recorded (bounds); this report is incomplete.'));
  assert.equal(exit([named('q', '1.5.0')], { dropped: 3 }).exit, 2, 'something to report outranks an incomplete record');
  const empty = renderReport(payload(null), { source: 'proxy' });
  assert.equal(empty.exit, 0);
  assert.ok(empty.text.includes(`No install recorded by the running proxy since ${START}.`), empty.text);
  assert.ok(empty.text.includes('Packages npm installed from its own cache never reach ChainGate and are not listed here.'));
  assert.equal(renderReport({ error: 'no witness database' }, { source: 'disk' }).exit, 4);
  for (const t of [ctx.text, partial.text, empty.text]) for (const re of FORBIDDEN) assert.ok(!re.test(t), `${re} in:\n${t}`);
});

test('G2c-6c (D-R7) the V6 line: counts split by class, per distinct version', () => {
  const r = renderReport(payload([
    served('u1', '1.0.0', { class: 'not-checked', coverage: 'not-covered' }),
    served('u2', '1.0.0', { class: 'not-checked', coverage: 'not-covered' }),
    served('u2', '1.0.0', { class: 'not-checked', coverage: 'not-covered' }),
    served('i', '1.0.0', { class: 'not-checked', coverage: 'indeterminate' }),
    served('f', '1.0.0', { class: 'not-checked', coverage: 'failed' }),
    served('n', '1.0.0', { class: 'not-checked', coverage: 'no-seed' }),
    served('l', '1.0.0', { class: 'not-checked', coverage: 'earlier-policy' }),
    served('ok', '1.0.0'),
  ]), { source: 'proxy' });
  assert.ok(r.text.includes('6 package(s) were not checked by any named rule: 2 not covered by the seed or not placeable in its history, '
    + '1 history indeterminate, 1 evaluation failed, 1 no seed loaded, 1 decided under an earlier policy. For them only the advisory '
    + 'lookup (when a seed is loaded) and the content check (where this machine had a baseline) applied, plus detail-only checks where '
    + 'local history allowed.'), r.text);
  const base = renderReport(payload([served('u1', '1.0.0', { class: 'not-checked', coverage: 'not-covered' })]), { source: 'proxy' });
  assert.ok(base.text.includes('1 package(s) were not checked by any named rule: 1 not covered by the seed or not placeable in its history, '
    + '0 history indeterminate, 0 evaluation failed.'), base.text);
  assert.equal(r.exit, 0, 'not checked is coverage, not a warning');
});

test('G2c-7a (D-R6) fact lines: refused, and a tag moved (with "npm installed" only when that tarball was served)', () => {
  const tag = { kind: 'tag-moved', package: 'p', tag: 'latest', from: '1.3.0', to: '1.2.0', facts: ['seed-v3:pin'], reason: 'x' };
  const withServe = renderReport(payload([tag, served('p', '1.2.0'), refused('p', '1.3.0', ['seed-v3:pin'])]), { source: 'proxy' }).text;
  assert.ok(withServe.includes('p: dist-tag latest moved from 1.3.0 to 1.2.0: a recorded advisory names this version — npm installed 1.2.0'), withServe);
  assert.ok(withServe.includes('p@1.3.0  BLOCKED (download refused): a recorded advisory names this version — npm could not install it'));
  const noServe = renderReport(payload([tag, served('a', '1.0.0')]), { source: 'proxy' }).text;
  assert.ok(noServe.includes('p: dist-tag latest moved from 1.3.0 to 1.2.0: a recorded advisory names this version'));
  assert.ok(!noServe.includes('— npm installed'), 'the D-R6 suffix (the cache footer also says "npm installed")');
  const dropped = renderReport(payload([{ ...tag, to: null }, served('a', '1.0.0')]), { source: 'proxy' }).text;
  assert.ok(dropped.includes('p: dist-tag latest dropped (was 1.3.0): a recorded advisory names this version'), dropped);
  const nonFact = renderReport(payload([refused('x', '1.0.0', [], { status: 503, reason: 'seed-v3: cft-policy-1.2: seed-v3:input: boom' })]), { source: 'proxy' }).text;
  assert.ok(nonFact.includes('x@1.0.0  REFUSED (download refused): not a recorded fact — seed-v3: cft-policy-1.2: seed-v3:input: boom — npm could not install it'), nonFact);
});
