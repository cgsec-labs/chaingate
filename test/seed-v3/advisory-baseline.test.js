// Since 0.1.8 (retier-1.1): a version a recorded advisory names (a pin, from the seed or the pins feed) is never the release another
// one is compared with. The re-tier (0.1.6) and the live recount (0.1.8) both read a release against the latest earlier release
// of its line in the registry document; when the release before is the attacker's own first release, the next malicious release
// shows no break against it (the event-stream shape), so the re-tier called it "not new" and the recount found nothing new
// (local arch's consult view 2026-11-12, Q4; operator: "Yes added"). Such a version is skipped as a sibling build is: never the
// baseline, never on the walk back. A pin lookup that fails skips the version too. Written before the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import RT from '../../seed/v3/retier.js';
import G from '../../seed/v3/gate.js';
import { inputFromPackument } from '../../cli/check-record.js';
import { buildSeed, openFixtureSeed, docFor, manifestFor, after, WARNCFG } from './u05-fixtures.mjs';

const DAY = 86_400_000;
const T = (d) => new Date(Date.parse('2026-01-01T00:00:00Z') + d * DAY).toISOString();
const BOB = { _npmUser: { name: 'bob', email: 'bob@example.net' }, maintainers: [{ name: 'bob', email: 'bob@example.net' }] };
function doc(rows) {
  const versions = {}; const time = {};
  for (const [v, d, over = {}] of rows) {
    versions[v] = { name: 'x', version: v, _npmUser: { name: 'alice', email: 'alice@example.com' }, _npmVersion: '10.2.3',
      maintainers: [{ name: 'alice', email: 'alice@example.com' }], gitHead: `g${v.replace(/\W/g, '')}`, dist: { unpackedSize: 1000 }, ...over };
    time[v] = T(d);
  }
  return { name: 'x', versions, time };
}
const APPEND = Object.freeze({ kind: 'append', channel_a_usable: true });
const pinned = (...vs) => (v) => vs.includes(v);

test('AB1 chooseBaseline skips a version an advisory names, as it skips a sibling build: never the baseline, never on the walk back', () => {
  const d = doc([['1.0.0', 0], ['1.1.0', 10, BOB], ['1.2.0', 20, BOB]]);
  assert.equal(RT.chooseBaseline(d.versions, d.time, '1.2.0').baseline, '1.1.0', 'without the check: the release before');
  const c = RT.chooseBaseline(d.versions, d.time, '1.2.0', { exclude: pinned('1.1.0') });
  assert.equal(c.baseline, '1.0.0'); assert.equal(c.basis, 'same flavor'); assert.deepEqual(c.problems, []);
  assert.equal(c.skipped_advisory, 1);
  assert.deepEqual([...c.walkBack()].map(([, v]) => v), ['1.0.0']);
  // only advisory-named versions before it: no baseline
  const only = RT.chooseBaseline(d.versions, d.time, '1.1.0', { exclude: pinned('1.0.0') });
  assert.equal(only.baseline, null); assert.match(only.problems.join(), /named by an advisory/);
  // a predicate that throws skips the version (a failed lookup is not "no advisory")
  assert.equal(RT.chooseBaseline(d.versions, d.time, '1.2.0', { exclude: (v) => { if (v === '1.1.0') throw new Error('x'); return false; } }).baseline, '1.0.0');
});

test('AB2 the re-tier: a publisher change the attacker\'s first release already had is no longer "not new" when that release is pinned', () => {
  const d = doc([['1.0.0', 0], ['1.1.0', 10, BOB], ['1.2.0', 20, BOB]]);
  const f = { channel_a: { groups: { publisher: { value: true } } }, dac_trajectory: { predicates: {} } };
  const args = { packageName: 'x', version: '1.2.0', finding: f, placement: APPEND, notEvaluated: [], rawVersions: d.versions, rawTimes: d.time };
  assert.equal(RT.retierOf(args).placement, 'recorded', 'without the check: the same publisher as the release before');
  const r = RT.retierOf({ ...args, excludeBaseline: pinned('1.1.0') });
  assert.equal(r.version, 'retier-1.1');
  assert.equal(r.baseline, '1.0.0'); assert.equal(r.placement, 'raised');
  assert.match(r.words, /1 version\(s\) named by an advisory skipped/);
  assert.equal(RT.compact(r).version, 'retier-1.1');
  // a stored 0.1.6/0.1.7 block (retier-1.0) is still read
  assert.equal(RT.validCompact({ ...RT.compact(r), version: 'retier-1.0' }).version, 'retier-1.0');
  assert.equal(RT.validCompact({ ...RT.compact(r), version: 'retier-0.9' }), null);
});

test('AB3 the live recount: the attacker\'s first release after the seed tip is not the release the next one is compared with', () => {
  const st = { checked: true, k: 3, tip: '1.0.0', versions: [] };
  const big = { dist: { unpackedSize: 3000 } };
  const d = doc([['1.0.0', 0], ['1.1.0', 10, big], ['1.2.0', 20, { ...BOB, gitHead: undefined }], ['1.3.0', 30, { ...BOB, gitHead: undefined }]]);
  const f = { channel_a: { groups: { publisher: { value: true }, git: { value: true } } }, dac_trajectory: { predicates: {} } };
  const args = { packageName: 'x', version: '1.3.0', finding: f, placement: APPEND, staleSeed: st, rawVersions: d.versions, rawTimes: d.time };
  assert.equal(RT.liveRecountOf(args).fires, false, 'without the check: nothing is new against the attacker\'s 1.2.0');
  const r = RT.liveRecountOf({ ...args, excludeBaseline: pinned('1.2.0') });
  assert.equal(r.baseline, '1.1.0'); assert.deepEqual(r.live_new, ['size']); assert.equal(r.fires, true); assert.equal(r.skipped_advisory, 1);
});

test('AB4 through the gate: the seed\'s pin on p@1.3.0 keeps it from being 1.4.0\'s baseline, and the live recount warns', () => {
  const s = buildSeed({ layout: '1.1' });
  const seed = openFixtureSeed(s.dbPath);
  try {
    // the seed tip 1.2.0: alice, provenance, gitHead, 1000 B. 1.2.5 (clean) grew to 3000 B; 1.3.0 (pinned by ADV-P-130) and 1.4.0
    // are bob's, without gitHead, 1000 B: against the tip publisher and git broke (2 of 5); against 1.2.5 the size too (3 of 5)
    const m = (v, over) => { const x = manifestFor('p', v, over); if (over.gitHead === undefined && 'gitHead' in over) delete x.gitHead; return x; };
    const d = docFor('p', [['1.2.5', after(1), manifestFor('p', '1.2.5', { dist: { unpackedSize: 3000, attestations: { url: 'https://x' } } })],
      ['1.3.0', after(2), m('1.3.0', { ...BOB, gitHead: undefined })], ['1.4.0', after(3), m('1.4.0', { ...BOB, gitHead: undefined })]]);
    const e = G.evaluateCandidate(seed, { config: WARNCFG, domainVersionCount: 3 }, inputFromPackument(d, 'p', '1.4.0'));
    const row = e.decision.results.find((x) => x.gate === 'seed-v3:channel-a:live');
    assert.ok(row, JSON.stringify(e.decision.results.map((x) => [x.gate, x.result])));
    assert.equal(row.result, 'WARN');
    assert.match(row.detail, /against 1\.2\.5, the latest registry release this one follows/);
    assert.match(row.detail, /1 version\(s\) named by an advisory skipped/);
  } finally { seed.close(); s.cleanup(); }
});
