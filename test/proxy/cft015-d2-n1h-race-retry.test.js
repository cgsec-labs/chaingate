// 0.1.5 follow-up #2 (operator ruling 2026-10-15: IN, build test-first): a raced N1h judgement is retried once at the same
// download. Before: when another writer (the late MC/static rows of an earlier download of the same version, or a packument
// re-evaluation) inserted a decision between this download's read and its write, judgeAtTarball returned 'raced' and the fresh
// judgement was dropped until a later download (G4 tables dated note 7, CI run 38277629363). Now: on 'raced' the newest
// non-override decision is read once more and the same judgement (the cached packuments, no new fetch) is written on top of it,
// keeping every row of the other writer; a second race keeps the old behaviour. The retry is stated in the [n1h] log line only.
// Against the real witness store and the real late writer (recordLate).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setDependencyDoc, resetDependencyCache } from '../../gates/dependency-cache.js';
import { judgeAtTarball } from '../../proxy/dependency-judge.js';
import { recordLate } from '../../proxy/manifest-check.js';
import { openWitnessDB } from '../../witness/db.js';

const DEP = { name: 'evil', target: 'evil', spec: '^1' };
const hooked = { name: 'evil', 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': { name: 'evil', version: '1.0.0', scripts: { postinstall: 'x' } } },
  time: { '1.0.0': '2026-03-01T10:00:00.000Z' } };
const PENDING = { gate: 'dependency-hooks', result: 'SKIP', detail: 'pending', added: [DEP], pending: [DEP] };
const BASE = [{ gate: 'install-introduced', result: 'ALLOW', detail: 'no install hooks' }, PENDING];
const MC = { gate: 'install-manifest-mismatch', result: 'ALLOW', detail: 'tarball package.json install hooks match the registry entry' };
const S2 = { gate: 'static:S2-obfuscation', result: 'NOTE', detail: 'other writer' };

function store(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-d2-'));
  const db = openWitnessDB(path.join(dir, 'w.db')).applySchema();
  t.after(() => { db.close?.(); fs.rmSync(dir, { recursive: true, force: true }); resetDependencyCache(); });
  resetDependencyCache();
  setDependencyDoc('evil', hooked);
  db.insertGateDecision('c', '1.1.0', 'ALLOW', BASE);
  return db;
}
// the store, with `races` other writes landing just before each of the judge's own reads
function racing(db, writes) {
  let n = 0;
  return new Proxy(db, { get(target, prop) {
    if (prop === 'getLatestNonOverrideDecision') {
      return (pkg, v) => {
        const w = writes[n++];
        if (w) assert.equal(recordLate({ db: target, pkg, version: v, latest: target.getLatestNonOverrideDecision(pkg, v), rows: w }), 'wrote');
        return target.getLatestNonOverrideDecision(pkg, v);
      };
    }
    const val = target[prop];
    return typeof val === 'function' ? val.bind(target) : val;
  } });
}
const noFetch = { n: 0 };
const fetchPackument = async () => { noFetch.n += 1; throw new Error('no fetch: the packument is cached'); };
const logger = () => { const lines = []; return { lines, info: (l) => lines.push(l) }; };
const gates = (r) => r.gates_fired.map((g) => `${g.gate}:${g.result}`);

test('D2-1 one race: the judgement is written once on top of the other writer\'s decision, nothing of theirs lost, no new fetch', async (t) => {
  const db = store(t);
  const latest = db.getLatestNonOverrideDecision('c', '1.1.0');
  const log = logger();
  noFetch.n = 0;
  const r = await judgeAtTarball({ db: racing(db, [[MC, S2]]), pkg: 'c', version: '1.1.0', latest, fetchPackument, config: {}, log });
  assert.equal(r, 'wrote');
  assert.equal(noFetch.n, 0);
  const hist = db.getDecisionHistory('c', '1.1.0');
  assert.equal(hist.length, 3, 'base, the other writer, the retried judgement');
  const last = hist[2];
  assert.equal(last.disposition, 'WARN');
  assert.deepEqual(gates(last), ['install-introduced:ALLOW', 'dependency-hooks:WARN', 'install-manifest-mismatch:ALLOW', 'static:S2-obfuscation:NOTE']);
  assert.deepEqual(last.gates_fired.slice(2), [MC, S2], 'the other writer\'s rows are kept as written');
  assert.ok(!/retr|race|concurrent/i.test(last.gates_fired[1].detail), 'the row detail does not mention the retry');
  assert.equal(log.lines.length, 1);
  assert.match(log.lines[0], /^\[n1h\] c@1\.1\.0: WARN \(.*\) \(retried after a concurrent write\)$/);
});

test('D2-2 a second race keeps today\'s behaviour: raced, nothing written by the judgement, no log line', async (t) => {
  const db = store(t);
  const latest = db.getLatestNonOverrideDecision('c', '1.1.0');
  const log = logger();
  const r = await judgeAtTarball({ db: racing(db, [[MC], [S2]]), pkg: 'c', version: '1.1.0', latest, fetchPackument, config: {}, log });
  assert.equal(r, 'raced');
  const hist = db.getDecisionHistory('c', '1.1.0');
  assert.equal(hist.length, 3, 'base and the two other writes only');
  assert.equal(hist[2].gates_fired.find((g) => g.gate === 'dependency-hooks').result, 'SKIP');
  assert.deepEqual(log.lines, []);
});

test('D2-3 no retry onto a decision that no longer awaits the judgement: already judged by another download, or a BLOCK', async (t) => {
  const db = store(t);
  const latest = db.getLatestNonOverrideDecision('c', '1.1.0');
  const judged = { gate: 'dependency-hooks', result: 'ALLOW', detail: 'judged elsewhere', added: [DEP] };
  const r1 = await judgeAtTarball({ db: racing(db, [[judged]]), pkg: 'c', version: '1.1.0', latest, fetchPackument, config: {} });
  assert.equal(r1, 'raced');
  assert.equal(db.getDecisionHistory('c', '1.1.0').length, 2, 'a determinate judgement of another download stands');

  const db2 = store(t);
  const latest2 = db2.getLatestNonOverrideDecision('c', '1.1.0');
  const blocking = new Proxy(db2, { get(target, prop) {
    if (prop === 'getLatestNonOverrideDecision') {
      return (pkg, v) => { target.insertGateDecision(pkg, v, 'BLOCK', [{ gate: 'content-hash', result: 'BLOCK', detail: 'x' }, PENDING]); return target.getLatestNonOverrideDecision(pkg, v); };
    }
    const val = target[prop];
    return typeof val === 'function' ? val.bind(target) : val;
  } });
  const r2 = await judgeAtTarball({ db: blocking, pkg: 'c', version: '1.1.0', latest: latest2, fetchPackument, config: {} });
  assert.equal(r2, 'raced');
  assert.equal(db2.getDecisionHistory('c', '1.1.0').at(-1).disposition, 'BLOCK', 'never written over a BLOCK');
});

test('D2-4 no race: one write, the [n1h] line without the retry note (unchanged)', async (t) => {
  const db = store(t);
  const latest = db.getLatestNonOverrideDecision('c', '1.1.0');
  const log = logger();
  const r = await judgeAtTarball({ db, pkg: 'c', version: '1.1.0', latest, fetchPackument, config: {}, log });
  assert.equal(r, 'wrote');
  assert.equal(db.getDecisionHistory('c', '1.1.0').length, 2);
  assert.equal(log.lines.length, 1);
  assert.match(log.lines[0], /^\[n1h\] c@1\.1\.0: WARN \(.*\)$/);
  assert.ok(!log.lines[0].includes('retried'), log.lines[0]);
});
