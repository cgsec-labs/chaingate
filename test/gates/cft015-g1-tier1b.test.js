// 0.1.5 group 1 — T1.4 size-jump-provenance and T1.5 identity-break, from the served packument, against the runtime
// predecessor (gates/predecessor.js); both CONTRIBUTING under cft-policy-1.2 until the lineage re-measure (chaingate-ops
// handover §7.2) confirms T1.4 as named. Expected results are stated from the measured definitions in
// chaingate-ops tools/corpus/base_rates.py (A:size5x_prov@rt, B:identity@rt), written before the gates.
import test from 'node:test';
import assert from 'node:assert/strict';
import sizeJumpProvenance, { provenanceBreaks, repoOf } from '../../gates/size-jump-provenance.js';
import identityBreak, { publisherNew, identityBreaks, maintainersOf } from '../../gates/identity-break.js';
import { CONTRIBUTING_GATES, withRole } from '../../gates/row-class.js';
import { DEFAULT_GATE_MODULES, createGateRunner } from '../../gates/index.js';

const H = 3_600_000;
const T0 = Date.parse('2026-06-01T00:00:00Z');
const at = (h) => new Date(T0 + h * H).toISOString();
/** A packument from [[version, hoursAfterT0 | null, manifestExtra]] */
function pk(rows) {
  const versions = {}; const time = { created: at(0), modified: at(9999) };
  for (const [v, h, extra = {}] of rows) { versions[v] = { name: 'x', version: v, ...extra }; if (h !== null) time[v] = at(h); }
  return { versions, time };
}
const man = ({ size, git = 'abc', repo = 'https://github.com/o/r', email = 'a@x.io', npm = '10.9.0', maint = ['a@x.io'] }) => ({
  dist: { unpackedSize: size }, gitHead: git, repository: repo === null ? undefined : { type: 'git', url: repo },
  _npmUser: email ? { name: email.split('@')[0], email } : undefined, _npmVersion: npm,
  maintainers: maint ? maint.map((e) => ({ name: e.split('@')[0], email: e })) : undefined,
});
const A = (doc, v) => sizeJumpProvenance.evaluate({ version: v, rawVersions: doc.versions, rawTimes: doc.time });
const B = (doc, v) => identityBreak.evaluate({ version: v, rawVersions: doc.versions, rawTimes: doc.time });

// ------------------------------------------------------------------------------------------------- T1.4 size-jump-provenance
test('G1-1 T1.4 fires on >= 5x with gitHead lost, or with a repository change; not on size alone, not below 5x', () => {
  const doc = pk([
    ['1.0.0', 0, man({ size: 1000 })],
    ['1.1.0', 100, man({ size: 6000, git: null })],                                 // 6x and gitHead lost -> WARN
    ['1.2.0', 200, man({ size: 31000, repo: 'https://github.com/evil/r' })],        // 5.2x and repository moved -> WARN
    ['1.3.0', 300, man({ size: 160000, repo: 'https://github.com/evil/r' })],        // 5.2x, provenance as in 1.2.0 -> ALLOW
    ['1.4.0', 400, man({ size: 170000, git: null, repo: 'https://github.com/evil2/r' })],   // 1.1x, both broke -> ALLOW (size)
  ]);
  const r11 = A(doc, '1.1.0');
  assert.equal(r11.result, 'WARN');
  assert.match(r11.detail, /unpackedSize 6000 vs 1000 of 1\.0\.0 \(6\.0×\), at or above 5×, and gitHead absent/);
  const r12 = A(doc, '1.2.0');
  assert.equal(r12.result, 'WARN');
  assert.match(r12.detail, /repository https:\/\/github\.com\/o\/r → https:\/\/github\.com\/evil\/r vs 1\.1\.0/);
  assert.equal(A(doc, '1.3.0').result, 'ALLOW');
  assert.match(A(doc, '1.3.0').detail, /at or above 5×; gitHead and repository as in 1\.2\.0/);
  assert.equal(A(doc, '1.4.0').result, 'ALLOW');
  assert.match(A(doc, '1.4.0').detail, /below 5×/);
});

test('G1-2 T1.4 compares within the major: a 1.x patch after 2.0.0 is judged against 1.x; a prerelease is never a predecessor', () => {
  const doc = pk([
    ['1.0.0', 0, man({ size: 1000 })],
    ['2.0.0-beta.1', 50, man({ size: 90000 })],
    ['2.0.0', 100, man({ size: 50000, git: 'def' })],
    ['1.0.1', 200, man({ size: 1200, git: null })],            // vs 1.0.0: 1.2x -> ALLOW (publish order would have said collapse)
    ['2.0.1', 300, man({ size: 260000, git: null })],          // vs 2.0.0 (not the beta): 5.2x, gitHead lost -> WARN
    ['3.0.0', 400, man({ size: 999999, git: null })],          // no earlier release of major 3 -> SKIP
  ]);
  assert.equal(A(doc, '1.0.1').result, 'ALLOW');
  assert.match(A(doc, '1.0.1').detail, /vs 1000 of 1\.0\.0/);
  const r = A(doc, '2.0.1');
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /vs 50000 of 2\.0\.0 \(5\.2×\)/);
  assert.equal(A(doc, '3.0.0').result, 'SKIP');
  assert.match(A(doc, '3.0.0').detail, /no earlier release of this major/);
});

test('G1-3 T1.4 not evaluable without a size; repository normalisation ignores git+ / .git / trailing slash', () => {
  const doc = pk([['1.0.0', 0, man({ size: 1000 })], ['1.1.0', 10, { ...man({ size: 9000, git: null }), dist: {} }]]);
  assert.equal(A(doc, '1.1.0').result, 'SKIP');
  assert.equal(repoOf({ repository: 'git+https://github.com/o/r.git/' }), 'https://github.com/o/r');
  assert.equal(repoOf({ repository: { url: 'https://github.com/o/r' } }), 'https://github.com/o/r');
  assert.equal(repoOf({ repository: 7 }), null);
  assert.deepEqual(provenanceBreaks(man({ size: 1, repo: 'git+https://github.com/o/r.git' }), man({ size: 1 })), []);
  assert.deepEqual(provenanceBreaks(man({ size: 1, git: null }), man({ size: 1, git: null })), []);       // never had one: no loss
});

// ------------------------------------------------------------------------------------------------- T1.5 identity-break
test('G1-4 T1.5 fires when the publisher is new to the package and >= 2 identity facts break; one fact is not enough', () => {
  const doc = pk([
    ['1.0.0', 0, man({ size: 1000, npm: '11.0.0' })],
    ['1.1.0', 100, man({ size: 1000, npm: '11.0.0' })],
    ['1.2.0', 200, man({ size: 1000, email: 'new@p.me', npm: '9.0.0', maint: ['z@p.me'] })],       // new + tool + maintainers
    ['1.3.0', 300, man({ size: 1000, email: 'other@p.me', npm: '9.0.0', maint: ['z@p.me'] })],     // new + nothing broke
    ['1.4.0', 400, man({ size: 1000, email: 'a@x.io', npm: '8.0.0', maint: ['q@p.me'], git: null })],   // seen before, 3 broke
  ]);
  const r = B(doc, '1.2.0');
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /publisher new@p\.me is new to this package, and maintainers changed; npm 11\.0\.0 → 9\.0\.0 \(a downgrade\) vs 1\.1\.0/);
  assert.equal(B(doc, '1.3.0').result, 'ALLOW');
  assert.match(B(doc, '1.3.0').detail, /only 0 identity fact\(s\) differ from 1\.2\.0/);
  assert.equal(B(doc, '1.4.0').result, 'ALLOW');
  assert.match(B(doc, '1.4.0').detail, /published earlier versions; 3 identity fact\(s\) differ/);
});

test('G1-5 T1.5 "new" means unseen in versions published BEFORE the candidate; evaluability', () => {
  const doc = pk([
    ['1.0.0', 0, man({ size: 1, email: 'a@x.io' })],
    ['1.1.0', 100, man({ size: 1, email: 'b@y.io', git: null, repo: 'https://github.com/b/r' })],   // b is new, 2 broke -> WARN
    ['1.0.1', 50, man({ size: 1, email: 'b@y.io' })],                                               // published BEFORE 1.1.0
    ['1.2.0', 200, man({ size: 1, email: null })],
    ['2.0.0', 300, man({ size: 1, email: 'c@z.io', git: null, repo: 'https://github.com/c/r' })],   // no release of major 2 before
  ]);
  assert.equal(publisherNew(doc.versions, doc.time, '1.1.0'), false, '1.0.1 (earlier) already carries b@y.io');
  assert.equal(B(doc, '1.1.0').result, 'ALLOW');
  assert.equal(B(doc, '1.2.0').result, 'SKIP');
  assert.equal(B(doc, '2.0.0').result, 'SKIP');
  assert.match(B(doc, '2.0.0').detail, /no earlier release of this major/);
  assert.deepEqual([...maintainersOf({ maintainers: [{ name: 'A', email: 'A@X.io' }, 'b@y.io', { name: 'noemail' }] })].sort(), ['a@x.io', 'b@y.io', 'noemail']);
  assert.equal(maintainersOf({ maintainers: 'x' }), null);
  assert.deepEqual(identityBreaks(man({ size: 1 }), man({ size: 1 })), []);
});

// ------------------------------------------------------------------------------------------------- roles and wiring
test('G1-6 both gates are CONTRIBUTING under cft-policy-1.2 (WARN -> NOTE), wired into the default runner, history-independent', () => {
  assert.ok(CONTRIBUTING_GATES.has('size-jump-provenance') && CONTRIBUTING_GATES.has('identity-break'));
  assert.equal(withRole({ gate: 'size-jump-provenance', result: 'WARN', detail: 'd' }).result, 'NOTE');
  assert.equal(withRole({ gate: 'identity-break', result: 'WARN', detail: 'd' }).result, 'NOTE');
  assert.deepEqual(DEFAULT_GATE_MODULES.map((m) => m.name).filter((n) => /size-jump-provenance|identity-break/.test(n)),
    ['size-jump-provenance', 'identity-break']);
  // a package seen for the first time (no local history) still evaluates both: they read only the served packument
  const doc = pk([['1.0.0', 0, man({ size: 1000, npm: '11.0.0' })],
    ['1.1.0', 100, man({ size: 6000, git: null, email: 'new@p.me', npm: '9.0.0', maint: ['z@p.me'] })]]);
  const run = createGateRunner({ modules: DEFAULT_GATE_MODULES.filter((m) => /size-jump-provenance|identity-break/.test(m.name)),
    getOverride: () => null, logger: { info() {}, warn() {}, error() {} } });
  const d = run({ ecosystem: 'npm', packageName: 'x', version: '1.1.0', incoming: {}, baseline: null, history: [],
    rawVersions: doc.versions, rawTimes: doc.time, config: {} });
  const rows = Object.fromEntries(d.results.map((r) => [r.gate, r.result]));
  assert.equal(rows['size-jump-provenance'], 'NOTE');
  assert.equal(rows['identity-break'], 'NOTE');
  assert.equal(d.disposition, 'ALLOW', 'contributing rows never make a warning on their own');
});
