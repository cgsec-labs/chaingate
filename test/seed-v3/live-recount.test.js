// Since 0.1.8 (cft-policy-1.4): Channel-A recounted against the latest registry release when the seed is behind. Channel-A
// compares an appended release with the seed tip, however many releases npm has published since; a break that only shows
// against the release this one actually follows was silent (ops' reading of 0.1.7, operator's requirement 2026-11-07). When
// releases were published after the seed tip, each Channel-A group is also read against the re-tier's baseline (the latest
// earlier release of the same line and flavor, from the registry document in hand). A group counts when it broke against that
// baseline (R-A4-5, settled by the measurement 2026-11-12; the union with the tip was measured and not chosen), and the new named
// row seed-v3:channel-a:live WARNs when that count reaches the Channel-A threshold (3 of 5) while the tip count alone did not
// (operator 2026-11-12: "Same 3-of-5 rule"). The re-tier still handles a tip warning. A side that cannot be read never counts.
// Written before the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import RT from '../../seed/v3/retier.js';
import POL from '../../seed/v3/policy.js';
import G from '../../seed/v3/gate.js';
import { buildCheckRecord, inputFromPackument, SUPPORTED_RECORDS, CHECK_SCHEMA_ID } from '../../cli/check-record.js';
import { validateRecord } from '../../examples/ci/chaingate-ci.mjs';
import { classify } from '../../witness/row-class.js';
import { buildNotice } from '../../proxy/notice.js';
import { buildSeed, openFixtureSeed, docFor, manifestFor, after, WARNCFG } from './u05-fixtures.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const V3 = path.join(HERE, '..', '..', 'seed', 'v3');
const LIVE_ROW = 'seed-v3:channel-a:live';
const DAY = 86_400_000;
const T = (d) => new Date(Date.parse('2026-01-01T00:00:00Z') + d * DAY).toISOString();
const APPEND = Object.freeze({ kind: 'append', channel_a_usable: true });
const finding = (ch = []) => ({ channel_a: { groups: Object.fromEntries(['publisher', 'provenance', 'install', 'size', 'git']
  .map((k) => [k, { value: ch.includes(k) }])) }, dac_trajectory: { predicates: {} } });
const stale = (k = 2, tip = '1.0.0') => ({ checked: true, k, tip, versions: [] });

/** A small document of package `x`: [version, day, manifest overrides] rows. */
function doc(rows) {
  const versions = {}; const time = {};
  for (const [v, d, over = {}] of rows) {
    versions[v] = { name: 'x', version: v, _npmUser: { name: 'alice', email: 'alice@example.com' }, _npmVersion: '10.2.3',
      maintainers: [{ name: 'alice', email: 'alice@example.com' }], gitHead: `g${v.replace(/\W/g, '')}`, dist: { unpackedSize: 1000 }, ...over };
    time[v] = T(d);
  }
  return { name: 'x', versions, time };
}
const PROV = { dist: { unpackedSize: 1000, attestations: { url: 'https://x', provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } } };
const BOB = { _npmUser: { name: 'bob', email: 'bob@example.net' }, maintainers: [{ name: 'bob', email: 'bob@example.net' }] };
// the candidate of the recount cases: another publisher, 3000 B against the 1000 B releases before it (breaks publisher and size)
const TAKE = { ...BOB, dist: { unpackedSize: 3000 } };
const recount = (d, version, f, st = stale(), placement = APPEND) => RT.liveRecountOf({ packageName: d.name, version, finding: f,
  placement, staleSeed: st, rawVersions: d.versions, rawTimes: d.time });

// ------------------------------------------------------------------------------------------------ the recount
test('LR1 ops\' case, provenance: the tip had none, the gap releases had it, this one has none: new against the live baseline', () => {
  const d = doc([['1.0.0', 0], ['1.1.0', 10, PROV], ['1.2.0', 20, PROV], ['1.3.0', 30, TAKE]]);
  const r = recount(d, '1.3.0', finding(['publisher', 'size']));
  assert.equal(r.baseline, '1.2.0'); assert.equal(r.basis, 'same flavor');
  assert.deepEqual(r.live_new, ['provenance']); assert.deepEqual(r.broke, ['publisher', 'provenance', 'size']);
  assert.equal(r.n, 3); assert.equal(r.threshold, 3); assert.equal(r.fires, true);
  assert.equal(r.tip, '1.0.0'); assert.equal(r.k, 2);
});

test('LR2 the gitHead variant: gitHead on the gap releases, none now', () => {
  const d = doc([['1.0.0', 0, { gitHead: undefined }], ['1.1.0', 10], ['1.2.0', 20], ['1.3.0', 30, { ...TAKE, gitHead: undefined }]]);
  const r = recount(d, '1.3.0', finding(['publisher', 'size']));
  assert.deepEqual(r.live_new, ['git']); assert.equal(r.fires, true);
});

test('LR3 control: the gap releases lack provenance too, so nothing is new against them and the recount stays below the threshold', () => {
  const d = doc([['1.0.0', 0], ['1.1.0', 10], ['1.2.0', 20], ['1.3.0', 30, TAKE]]);
  const r = recount(d, '1.3.0', finding(['publisher', 'size']));
  assert.deepEqual(r.live_new, []); assert.equal(r.n, 2); assert.equal(r.fires, false);
  // one new group alone is not enough: the threshold is the seed's 3 of 5
  const one = recount(doc([['1.0.0', 0], ['1.1.0', 10, PROV], ['1.2.0', 20, PROV], ['1.3.0', 30, BOB]]), '1.3.0', finding(['publisher']));
  assert.deepEqual(one.live_new, ['provenance']); assert.equal(one.n, 2); assert.equal(one.fires, false);
});

test('LR3b (R-A4-5) a group that broke against the seed tip only is not counted: the latest release already had that state', () => {
  // the tip broke publisher and size (bob and 3000 B since the gap releases), but against 1.2.0 only provenance broke
  const d = doc([['1.0.0', 0], ['1.1.0', 10, { ...TAKE, ...PROV, dist: { ...PROV.dist, unpackedSize: 3000 } }],
    ['1.2.0', 20, { ...TAKE, ...PROV, dist: { ...PROV.dist, unpackedSize: 3000 } }], ['1.3.0', 30, TAKE]]);
  const r = recount(d, '1.3.0', finding(['publisher', 'size']));
  assert.deepEqual(r.baseline_broke, ['provenance']); assert.deepEqual(r.broke, ['provenance']); assert.equal(r.n, 1);
  assert.equal(r.fires, false, 'the union would have counted 3 of 5 here (measured, not chosen)');
});

test('LR4 no recount without a stale seed, when the tip count already reaches the threshold, or when Channel-A is not usable', () => {
  const d = doc([['1.0.0', 0], ['1.1.0', 10, PROV], ['1.2.0', 20, PROV], ['1.3.0', 30]]);
  const f = finding(['publisher', 'size']);
  assert.equal(recount(d, '1.3.0', f, null), null);
  assert.equal(recount(d, '1.3.0', f, { checked: true, k: 0, tip: '1.0.0', versions: [] }), null);
  assert.equal(recount(d, '1.3.0', f, { checked: false, tip: '1.0.0' }), null);
  assert.equal(recount(d, '1.3.0', finding(['publisher', 'size', 'git'])), null, 'the tip threshold and the re-tier decide');
  assert.equal(recount(d, '1.3.0', f, stale(), { kind: 'cold-start', channel_a_usable: false }), null);
});

test('LR5 no recount without a clean baseline after the tip: a tie, a removed version between, a baseline at or before the tip', () => {
  const f = finding(['publisher', 'size']);
  const tie = doc([['1.0.0', 0], ['1.1.0', 10, PROV], ['1.2.0', 20, PROV], ['1.2.1', 20, PROV], ['1.3.0', 30]]);
  assert.equal(recount(tie, '1.3.0', f), null);
  const removed = doc([['1.0.0', 0], ['1.1.0', 10, PROV], ['1.2.0', 20, PROV], ['1.3.0', 30]]); removed.time['1.2.5'] = T(25);
  assert.equal(recount(removed, '1.3.0', f), null);
  // the seed tip is the latest release before this one: the tip comparison is the live one
  const fresh = doc([['1.0.0', 0, PROV], ['1.3.0', 30]]);
  assert.equal(recount(fresh, '1.3.0', f, stale(1, '1.0.0')), null);
  assert.equal(recount(doc([['1.0.0', 0], ['1.1.0', 10], ['1.3.0', 30]]), '1.3.0', f, stale(1, '1.1.0')), null);
});

test('LR6 a side that cannot be read never counts: size unknown on the baseline, publisher identity unknown', () => {
  const d = doc([['1.0.0', 0], ['1.1.0', 10, { dist: {} }], ['1.2.0', 20, { dist: {} }], ['1.3.0', 30]]);
  const r = recount(d, '1.3.0', finding(['publisher', 'git']));
  assert.ok(!r.live_new.includes('size')); assert.equal(r.fires, false);
  const u = doc([['1.0.0', 0], ['1.1.0', 10, { _npmUser: undefined }], ['1.2.0', 20, { _npmUser: undefined }], ['1.3.0', 30]]);
  assert.ok(!recount(u, '1.3.0', finding(['git', 'size'])).live_new.includes('publisher'));
});

test('LR7 each group is the checker\'s: install = an install hook where the baseline had none; size = a 50 % move either way', () => {
  const hook = { scripts: { postinstall: 'node x.js' } };
  let r = recount(doc([['1.0.0', 0], ['1.1.0', 10], ['1.2.0', 20], ['1.3.0', 30, hook]]), '1.3.0', finding(['publisher']));
  assert.deepEqual(r.live_new, ['install']);
  r = recount(doc([['1.0.0', 0], ['1.1.0', 10, hook], ['1.2.0', 20, hook], ['1.3.0', 30, hook]]), '1.3.0', finding(['publisher']));
  assert.deepEqual(r.live_new, [], 'a hook the baseline already had is not new');
  r = recount(doc([['1.0.0', 0], ['1.1.0', 10, { dist: { unpackedSize: 3000 } }], ['1.2.0', 20, { dist: { unpackedSize: 3000 } }], ['1.3.0', 30]]), '1.3.0', finding(['publisher']));
  assert.deepEqual(r.live_new, ['size'], '1000 B against 3000 B is a 67 % shrink');
  r = recount(doc([['1.0.0', 0], ['1.1.0', 10, { dist: { unpackedSize: 1400 } }], ['1.2.0', 20, { dist: { unpackedSize: 1400 } }], ['1.3.0', 30]]), '1.3.0', finding(['publisher']));
  assert.deepEqual(r.live_new, []);
  r = recount(doc([['1.0.0', 0], ['1.1.0', 10, BOB], ['1.2.0', 20, BOB], ['1.3.0', 30]]), '1.3.0', finding(['git']));
  assert.deepEqual(r.live_new, ['publisher'], 'back to alice after bob published the gap releases');
});

// ------------------------------------------------------------------------------------------------ the policy row
const live = (over = {}) => ({ version: 'live-1.0', baseline: '1.4.0', basis: 'same flavor', tip: '1.2.0', k: 2,
  broke: ['publisher', 'size', 'git'], live_new: ['size'], n: 3, threshold: 3, fires: true, ...over });

test('LP1 policy: a firing recount is one named WARN row, after the stale-seed row; a recount that does not fire adds nothing', () => {
  assert.equal(POL.POLICY_CONTRACT_VERSION, 'cft-policy-1.4');
  assert.ok(POL.NAMED_ROWS.includes(LIVE_ROW)); assert.ok(POL.POLICY_ROW_GATES.includes(LIVE_ROW));
  assert.deepEqual(POL.RETIER_ROWS, ['seed-v3:channel-a:critical', 'seed-v3:dac-trajectory:surface'], 'the re-tier never moves the live row');
});

// ------------------------------------------------------------------------------------------------ through the gate
function withSeed(fn) {
  const s = buildSeed({ layout: '1.1' });
  const seed = openFixtureSeed(s.dbPath);
  try { return fn(seed); } finally { seed.close(); s.cleanup(); }
}
const SIZE = (n) => ({ dist: { unpackedSize: n, attestations: { url: 'https://x' } } });
const BOBM = { _npmUser: { name: 'bob', email: 'bob@example.net' }, maintainers: [{ name: 'bob', email: 'bob@example.net' }] };
const candidate = () => { const m = manifestFor('q', '1.5.0', { ...BOBM }); delete m.gitHead; return m; };
// the seed tip 1.2.0: alice, provenance, gitHead, 1000 B. 1.5.0: bob, provenance, no gitHead, 1000 B -> publisher and git broke
// against the tip (2 of 5). The gap releases 1.3.0 and 1.4.0 are 3000 B: against 1.4.0 the size broke as well (3 of 5).
const GAP = (n) => docFor('q', [['1.3.0', after(1), manifestFor('q', '1.3.0', SIZE(n))], ['1.4.0', after(2), manifestFor('q', '1.4.0', SIZE(n))],
  ['1.5.0', after(3), candidate()]]);
const evaluate = (seed, d) => G.evaluateCandidate(seed, { config: WARNCFG, domainVersionCount: 3 }, inputFromPackument(d, 'q', '1.5.0'));

test('LI1 through the gate: 2 of 5 against the stale tip, 3 of 5 against the latest release: the live row warns and decides', () => {
  withSeed((seed) => {
    const e = evaluate(seed, GAP(3000));
    assert.equal(e.placement.kind, 'append'); assert.equal(e.finding.channel_a.predecessor_version, '1.2.0');
    const rows = e.decision.results;
    const crit = rows.find((x) => x.gate === 'seed-v3:channel-a:critical');
    assert.notEqual(crit.result, 'WARN', 'the tip count alone does not reach the threshold');
    const row = rows.find((x) => x.gate === LIVE_ROW);
    assert.equal(row.result, 'WARN');
    assert.equal(row.detail, '3/5 witness groups broke against 1.4.0, the latest registry release this one follows (same flavor), '
      + 'threshold 3: publisher, size, git (new against 1.4.0: size); the seed tip 1.2.0 is 2 release(s) behind (warns, never blocks)');
    assert.ok(rows.indexOf(row) === rows.findIndex((x) => x.gate === 'seed-v3:coverage' && x.detail.startsWith('stale_seed')) + 1,
      'right after the stale-seed row');
    assert.equal(e.decision.disposition, 'WARN'); assert.equal(e.decision.policy_version, 'cft-policy-1.4');
    assert.deepEqual(classify([{ gate: 'seed-v3', result: 'WARN', detail: 'cft-policy-1.4: x', rows: rows.map((x) => ({ gate: x.gate, result: x.result })) }]).named, [LIVE_ROW]);
  });
});

test('LI2 control: the same release with gap releases of the tip\'s size stays below the threshold; no live row, as in 0.1.7', () => {
  withSeed((seed) => {
    const e = evaluate(seed, GAP(1000));
    assert.equal(e.decision.results.some((x) => x.gate === LIVE_ROW), false);
    assert.notEqual(e.decision.disposition, 'WARN');
  });
});

test('LI3 the check record is chaingate.check/6 under cft-policy-1.4; /6 is /5 with the schema const, retier-1.1 and the optional live and live_not_run members only, and validates', () => {
  assert.equal(CHECK_SCHEMA_ID, 'chaingate.check/6');
  assert.equal(SUPPORTED_RECORDS['chaingate.check/6'].policy_version, 'cft-policy-1.4');
  assert.equal(SUPPORTED_RECORDS['chaingate.check/5'].policy_version, 'cft-policy-1.3', '/5 records are still read');
  const read = (f) => JSON.parse(fs.readFileSync(path.join(V3, f), 'utf8'));
  const want = read('chaingate-check-5.schema.json'); const got = read('chaingate-check-6.schema.json');
  want.$id = 'https://chaingate.dev/schemas/chaingate-check-6.json';
  for (const shape of want.oneOf) shape.properties.schema.const = 'chaingate.check/6';
  want.$defs.decision.properties.retier.properties.version.const = 'retier-1.1';   // the advisory-named baseline is skipped
  want.$defs.decision.properties.live = got.$defs.decision.properties.live;               // R-A4-1: the optional recount member
  want.$defs.decision.properties.live_not_run = got.$defs.decision.properties.live_not_run;   // why it did not run (measurement)
  assert.ok(!want.$defs.decision.required.includes('live') && !want.$defs.decision.required.includes('live_not_run'), 'optional');
  want.title = got.title; want.description = got.description;
  assert.deepEqual(got, want);
  assert.ok(/^[\x20-\x7e\n]*$/.test(fs.readFileSync(path.join(V3, 'chaingate-check-6.schema.json'), 'utf8')), 'ASCII only');
  withSeed((seed) => {
    const rec = buildCheckRecord({ seed, policy: WARNCFG, domainVersionCount: 3, input: inputFromPackument(GAP(3000), 'q', '1.5.0'),
      request: { package: 'q', version: '1.5.0' }, tool: { name: 'chaingate', version: 'test' } });
    assert.equal(rec.schema, 'chaingate.check/6'); assert.equal(rec.decision.disposition, 'WARN');
    assert.deepEqual(validateRecord(rec), []);
    let Ajv2020 = null; try { Ajv2020 = createRequire(import.meta.url)('ajv/dist/2020.js'); } catch { /* not installed */ }
    if (Ajv2020) {
      const Ctor = Ajv2020.default || Ajv2020; const ajv = new Ctor({ strict: true, strictRequired: false, allErrors: true });
      ajv.addSchema(JSON.parse(fs.readFileSync(path.join(HERE, '..', 'fixtures', 'cft03', 'finding.schema.json'), 'utf8')));
      const v6 = ajv.compile(read('chaingate-check-6.schema.json'));
      assert.ok(v6(rec), JSON.stringify(v6.errors));
    }
  });
});

test('LI4 the download notice names the live row in plain words', () => {
  const n = buildNotice({ kind: 'WARNING', pkg: 'q', version: '1.5.0', labels: [LIVE_ROW] });
  assert.match(n, /release-history break vs the latest release \(3\+ of 5 groups; the seed is behind\)/);
  assert.ok(/^[\x20-\x7e]*$/.test(n));
});

// ------------------------------------------------------------------------------------------------ the record member (R-A4-1)
// local arch's ruling R-A4-1, accepted by the operator 2026-11-12: the decision carries an OPTIONAL `live` member, present only when
// the recount ran (fired or not), so `why` re-explains it and the measurement reads it; closed vocabularies, never null-filled.
const LIVE_KEYS = ['baseline', 'baseline_broke', 'basis', 'broke', 'fires', 'k', 'live_new', 'n', 'skipped_advisory', 'threshold', 'tip', 'version'];

test('LM1 compactLive / validLive: the closed shape; anything outside it is refused', () => {
  const lv = recount(doc([['1.0.0', 0], ['1.1.0', 10, PROV], ['1.2.0', 20, PROV], ['1.3.0', 30, TAKE]]), '1.3.0', finding(['publisher', 'size']));
  const c = RT.compactLive(lv);
  assert.deepEqual(Object.keys(c).sort(), LIVE_KEYS);
  assert.equal(c.version, 'live-1.0'); assert.equal(c.fires, true); assert.deepEqual(c.live_new, ['provenance']);
  assert.deepEqual(RT.validLive(c), c);
  for (const [k, v] of [['version', 'live-0.9'], ['baseline', 'x\u001b'], ['basis', 'nearby'], ['broke', ['publisher', 'evil']], ['live_new', 'size'],
    ['n', 4], ['threshold', 2], ['fires', 'yes'], ['k', 0], ['skipped_advisory', -1], ['tip', null]]) {
    assert.equal(RT.validLive({ ...c, [k]: v }), null, k);
  }
  assert.equal(RT.validLive({ ...c, extra: 1 }), null, 'no other member');
  assert.equal(RT.compactLive(null), null);
});

test('LM2 the decision and the check record carry `live` when the recount ran, fired or not; not when it did not run', () => {
  withSeed((seed) => {
    const fired = evaluate(seed, GAP(3000)).decision; const quiet = evaluate(seed, GAP(1000)).decision;
    assert.equal(fired.live.fires, true); assert.equal(quiet.live.fires, false); assert.deepEqual(quiet.live.live_new, []);
    const none = G.evaluateCandidate(seed, { config: WARNCFG, domainVersionCount: 3 },
      inputFromPackument(docFor('q', [['1.5.0', after(3), candidate()]]), 'q', '1.5.0')).decision;
    assert.equal('live' in none, false, 'no release after the seed tip: no recount, no member');
    const rec = buildCheckRecord({ seed, policy: WARNCFG, domainVersionCount: 3, input: inputFromPackument(GAP(1000), 'q', '1.5.0'),
      request: { package: 'q', version: '1.5.0' }, tool: { name: 'chaingate', version: 'test' } });
    assert.deepEqual(Object.keys(rec.decision.live).sort(), LIVE_KEYS);
    assert.deepEqual(rec.decision.live, RT.compactLive(quiet.live));
    assert.deepEqual(validateRecord(rec), []);
    let Ajv2020 = null; try { Ajv2020 = createRequire(import.meta.url)('ajv/dist/2020.js'); } catch { /* not installed */ }
    if (Ajv2020) {
      const Ctor = Ajv2020.default || Ajv2020; const ajv = new Ctor({ strict: true, strictRequired: false, allErrors: true });
      ajv.addSchema(JSON.parse(fs.readFileSync(path.join(HERE, '..', 'fixtures', 'cft03', 'finding.schema.json'), 'utf8')));
      const v6 = ajv.compile(JSON.parse(fs.readFileSync(path.join(V3, 'chaingate-check-6.schema.json'), 'utf8')));
      assert.ok(v6(rec), JSON.stringify(v6.errors));
      const bad = structuredClone(rec); bad.decision.live.basis = 'nearby';
      assert.equal(v6(bad), false, 'a basis outside the vocabulary is refused');
      const bad2 = structuredClone(rec); bad2.decision.live.extra = 1;
      assert.equal(v6(bad2), false, 'no other member');
    }
    const bad3 = structuredClone(rec); bad3.decision.live.version = 'live-0.9';
    assert.notDeepEqual(validateRecord(bad3), [], 'the CI consumer refuses another version');
  });
});

// ------------------------------------------------------------------------------------------------ measurement fields (operator 11-12)
// For the measurement (ops' M1, rules r3 e/f; operator: "Add both"): `baseline_broke` = every group that broke against the baseline,
// tip-broken or not (the latest-release-only count of R-A4-5), and, when the seed is behind but no recount ran, a reason code in the
// decision's `live_not_run`. Neither changes a decision.
test('LM3 baseline_broke counts every group that broke against the baseline; live_new only those that held against the tip', () => {
  // the tip broke publisher and size; against 1.2.0 publisher broke too (bob both), size did not, provenance is new
  const d = doc([['1.0.0', 0], ['1.1.0', 10, PROV], ['1.2.0', 20, PROV], ['1.3.0', 30, BOB]]);
  const r = recount(d, '1.3.0', finding(['publisher', 'size']));
  assert.deepEqual(r.baseline_broke, ['publisher', 'provenance']); assert.deepEqual(r.live_new, ['provenance']);
  assert.deepEqual(r.broke, r.baseline_broke, 'R-A4-5: the groups counted are those against the baseline');
  assert.deepEqual(RT.compactLive(r).baseline_broke, ['publisher', 'provenance']);
  assert.equal(RT.validLive({ ...RT.compactLive(r), baseline_broke: ['evil'] }), null);
});

test('LM4 when the seed is behind but no recount ran, the reason is a code; with no release after the tip there is none', () => {
  const d = doc([['1.0.0', 0], ['1.1.0', 10, PROV], ['1.2.0', 20, PROV], ['1.3.0', 30, TAKE]]);
  const run = (over = {}) => RT.liveRecountRun({ packageName: 'x', version: '1.3.0', finding: finding(['publisher', 'size']), placement: APPEND,
    staleSeed: stale(), rawVersions: d.versions, rawTimes: d.time, ...over });
  assert.deepEqual(RT.LIVE_NOT_RUN, ['channel_a_unusable', 'no_groups', 'tip_at_threshold', 'no_registry_doc', 'no_clean_baseline',
    'baseline_not_after_tip', 'side_unreadable']);
  assert.equal(run().live.fires, true); assert.equal(run().not_run, null);
  assert.deepEqual(run({ staleSeed: null }), { live: null, not_run: null }, 'the seed is not behind: nothing to say');
  assert.deepEqual(run({ staleSeed: { checked: true, k: 0, tip: '1.0.0', versions: [] } }), { live: null, not_run: null });
  const why = (over) => { const x = run(over); assert.equal(x.live, null); return x.not_run; };
  assert.equal(why({ placement: { kind: 'cold-start', channel_a_usable: false } }), 'channel_a_unusable');
  assert.equal(why({ finding: { channel_a: {}, dac_trajectory: {} } }), 'no_groups');
  assert.equal(why({ finding: finding(['publisher', 'size', 'git']) }), 'tip_at_threshold');
  assert.equal(why({ rawVersions: null }), 'no_registry_doc');
  const tie = doc([['1.0.0', 0], ['1.1.0', 10, PROV], ['1.2.0', 20, PROV], ['1.2.1', 20, PROV], ['1.3.0', 30]]);
  assert.equal(why({ rawVersions: tie.versions, rawTimes: tie.time }), 'no_clean_baseline');
  assert.equal(why({ staleSeed: stale(1, '1.2.0') }), 'baseline_not_after_tip');
  const bad = structuredClone(d); bad.versions['1.2.0'] = 'not an object';
  assert.equal(why({ rawVersions: bad.versions }), 'side_unreadable', 'the baseline\'s registry entry is not a manifest');
});

test('LM5 the decision and the check record carry live_not_run when the seed is behind and no recount ran', () => {
  withSeed((seed) => {
    // the tip count is already 3 of 5 (bob, no gitHead, 3000 B against the 1000 B tip): the strict row and the re-tier decide
    const m = candidate(); m.dist = { unpackedSize: 3000, attestations: { url: 'https://x' } };
    const d = docFor('q', [['1.3.0', after(1)], ['1.4.0', after(2)], ['1.5.0', after(3), m]]);
    const e = evaluate(seed, d).decision;
    assert.equal('live' in e, false); assert.equal(e.live_not_run, 'tip_at_threshold');
    const rec = buildCheckRecord({ seed, policy: WARNCFG, domainVersionCount: 3, input: inputFromPackument(d, 'q', '1.5.0'),
      request: { package: 'q', version: '1.5.0' }, tool: { name: 'chaingate', version: 'test' } });
    assert.equal(rec.decision.live_not_run, 'tip_at_threshold'); assert.deepEqual(validateRecord(rec), []);
    assert.equal('live_not_run' in evaluate(seed, GAP(3000)).decision, false, 'not when it ran');
  });
});
