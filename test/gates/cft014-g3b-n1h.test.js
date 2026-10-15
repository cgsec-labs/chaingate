// 0.1.4 group 3, unit 3b — N1h (dependency-hooks): the counted P6 plain rule ported exactly (judged fields, eligibility,
// added, spec classes, resolution, hook test, A1 outcome) and the runner gate on first sight. Expected results: decision
// tables ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G3-TIER1-20261012.md §3 (D-N1, D-N2), written before this file; the
// counted code is artifacts/cft-0.1.4-design-20261008/p5/{run_p5.py, run_p5_r1.py, resolve.mjs} under P6 46072722….
import test from 'node:test';
import assert from 'node:assert/strict';
import * as N from '../../gates/dependency-hooks.js';
import { setDependencyDoc, resetDependencyCache } from '../../gates/dependency-cache.js';
import { createGateRunner, DEFAULT_GATE_MODULES } from '../../gates/index.js';
import POL from '../../seed/v3/policy.js';

const H = 3_600_000;
const T0 = Date.parse('2026-03-01T00:00:00Z');
const at = (h) => new Date(T0 + h * H).toISOString();

test('G3b-1 (D-N1) judged fields: deps, optional, non-optional peers; first field wins; specs trimmed', () => {
  const m = { dependencies: { a: ' ^1.0.0 ', b: '2' }, optionalDependencies: { b: '3', c: '~1' },
    peerDependencies: { d: '*', e: '^5' }, peerDependenciesMeta: { e: { optional: true } } };
  assert.deepEqual(N.judgedFields(m), { a: { spec: '^1.0.0', field: 'dependencies' }, b: { spec: '2', field: 'dependencies' },
    c: { spec: '~1', field: 'optionalDependencies' }, d: { spec: '*', field: 'peerDependencies' } });
  assert.deepEqual(N.judgedFields({ dependencies: [] }), {});
});

test('G3b-2 (D-N1) added: absent from every ELIGIBLE earlier version (stubs and npm-published placeholders ignored)', () => {
  const versions = {
    '1.0.0': { dependencies: { a: '1' } },
    '0.0.1-security': { dependencies: { x: '1' } },                                       // a stub: not eligible
    '1.0.2': { dependencies: { y: '1' }, _npmUser: { name: 'npm', email: 'npm@npmjs.com' } }, // npm placeholder
    '1.1.0': { dependencies: { a: '1', x: '1', y: '1', z: 'github:o/r' } },
  };
  const time = { '1.0.0': at(0), '0.0.1-security': at(1), '1.0.2': at(2), '1.1.0': at(3) };
  assert.deepEqual(N.addedDeps(versions, time, '1.1.0').map((d) => d.name).sort(), ['x', 'y', 'z']);
  assert.deepEqual(N.addedDeps(versions, time, '1.0.0'), null, 'no eligible earlier version: not judged');
});

test('G3b-3 (D-N1) spec classes: npm: alias judges its target; git/URL/file/link/owner-repo are D2 (not judged)', () => {
  assert.deepEqual(N.specTarget('lodash', 'npm:evil-lodash@^2.0.0'), { kind: 'registry', target: 'evil-lodash', spec: '^2.0.0' });
  assert.deepEqual(N.specTarget('x', 'npm:@s/p@1.2.3'), { kind: 'registry', target: '@s/p', spec: '1.2.3' });
  assert.deepEqual(N.specTarget('x', 'npm:plain'), { kind: 'registry', target: 'plain', spec: 'latest' });
  for (const s of ['git+https://x/y.git', 'git://x', 'github:o/r', 'https://x/t.tgz', 'file:../x', 'link:../y', 'owner/repo', 'owner/repo#v1']) {
    assert.equal(N.specTarget('x', s).kind, 'd2', s);
  }
  assert.deepEqual(N.specTarget('x', ''), { kind: 'registry', target: 'x', spec: 'latest' });
  assert.deepEqual(N.specTarget('x', 'next'), { kind: 'registry', target: 'x', spec: 'next' });
});

test('G3b-4 (D-N1) resolution: ranges by maxSatisfying (no prerelease, loose); tags by the served dist-tags', () => {
  const doc = { versions: { '1.0.0': {}, '1.2.0': {}, '1.3.0-beta.1': {}, '2.0.0': {} }, 'dist-tags': { latest: '1.2.0', next: '1.3.0-beta.1' } };
  assert.deepEqual(N.resolveSpec(doc, '^1.0.0'), { resolved: '1.2.0' });
  assert.deepEqual(N.resolveSpec(doc, '>=1.0.0'), { resolved: '2.0.0' }, 'maxSatisfying, as counted (not latest-preferring)');
  assert.deepEqual(N.resolveSpec(doc, 'next'), { resolved: '1.3.0-beta.1' });
  assert.equal(N.resolveSpec(doc, 'nope').resolved, undefined);
  assert.equal(N.resolveSpec(doc, '^9').resolved, undefined);
});

test('G3b-5 (D-N1) the hook test on the resolved manifest', () => {
  assert.deepEqual(N.fires({ scripts: { postinstall: 'node x' } }), true);
  assert.deepEqual(N.fires({ scripts: { install: '' } }), false);
  assert.deepEqual(N.fires({ gypfile: true }), true);
  assert.deepEqual(N.fires({ gypfile: 'true' }), false, 'gypfile is True, strictly, as counted');
  assert.deepEqual(N.fires({ scripts: { prepare: 'x' } }), false);
});

test('G3b-6 (D-N1 A1, D-N2) outcome: a fire wins over not-evaluable; none fire + one not evaluable = SKIP; > 10 added = SKIP', () => {
  resetDependencyCache();
  setDependencyDoc('hooked', { versions: { '1.0.0': { scripts: { postinstall: 'x' } } }, 'dist-tags': { latest: '1.0.0' } });
  setDependencyDoc('clean', { versions: { '1.0.0': {} }, 'dist-tags': { latest: '1.0.0' } });
  setDependencyDoc('gone', null, 'upstream 404');
  const mk = (deps) => ({ versions: { '1.0.0': {}, '1.1.0': { dependencies: deps } }, time: { '1.0.0': at(0), '1.1.0': at(48) } });
  const ev = (doc) => N.default.evaluate({ version: '1.1.0', rawVersions: doc.versions, rawTimes: doc.time });
  let r = ev(mk({ hooked: '^1', gone: '^1' }));
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /hooked@1\.0\.0 \(postinstall\)/);
  r = ev(mk({ clean: '^1', gone: '^1' }));
  assert.equal(r.result, 'SKIP');
  assert.match(r.detail, /not evaluable: gone \(upstream 404\)/);
  assert.equal(ev(mk({ clean: '^1' })).result, 'ALLOW');
  r = ev(mk({ unseen: '^1' }));
  assert.equal(r.result, 'SKIP');
  assert.deepEqual(r.pending, [{ name: 'unseen', target: 'unseen', spec: '^1' }]);
  assert.match(r.detail, /1 added dependency not yet fetched/);
  const many = {}; for (let i = 0; i < 11; i += 1) many[`d${i}`] = '^1';
  r = ev(mk(many));
  assert.equal(r.result, 'SKIP');
  assert.match(r.detail, /more than 10 added dependencies; not judged/);
  assert.equal(ev(mk({ z: 'github:o/r' })).result, 'ALLOW', 'only a D2 dependency added: nothing to judge');
  resetDependencyCache();
});

test('G3b-11 (D-N2) the runner evaluates dependency-hooks on first sight (no depth guard); it is a named runner gate', () => {
  resetDependencyCache();
  const runGates = createGateRunner({ modules: DEFAULT_GATE_MODULES });
  const versions = { '1.0.0': {}, '1.1.0': { dependencies: { fresh: '^1' } } };
  const out = runGates({ ecosystem: 'npm', packageName: 'x', version: '1.1.0', incoming: { version: '1.1.0' }, rawVersions: versions,
    rawTimes: { '1.0.0': at(0), '1.1.0': at(48) }, history: [], baseline: null });
  const row = out.results.find((g) => g.gate === 'dependency-hooks');
  assert.equal(row.result, 'SKIP');
  assert.match(row.detail, /not yet fetched/);
  assert.deepEqual(POL.NAMED_RUNNER_GATES, ['install-introduced', 'dependency-hooks', 'install-manifest-mismatch', 'size-jump-provenance', 'static:S0-shell-fetch-in-hook', 'static:S5-oversized-hook-target']);   // 0.1.5 T1.4; 0.1.5 S0+S5 named (deliberate)
});
