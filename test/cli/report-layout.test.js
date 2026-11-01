// Since 0.1.6.1: the human `chaingate report` is a short table per install, then what needs a look listed by name (named warnings,
// refusals, tag moves, packages the seed did not check, packages no named rule checked); recorded facts are one count line unless
// --verbose lists them grouped by kind. ASCII only, and no internal record versions. --json and the exit code are unchanged.
// Written before the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import { renderReport } from '../../cli/report-render.js';

const START = '2026-11-01T07:33:06.894Z';
const LAST = '2026-11-01T07:33:41.264Z';
const ev = (pkg, over = {}) => ({ at: START, kind: 'served', package: pkg, version: '1.0.0', class: 'clean', coverage: 'checked',
  named: [], contributing: [], reason: 'r', policy: 'cft-policy-1.3', notice: false, k: null, ...over });
const facts = (pkg, version, f, extra = {}) => ({ at: START, kind: 'facts', package: pkg, version,
  facts: { version: 'shadow-facts-1.0', ...f }, ...extra });
const cold = { transition: { state: 'not-applicable' }, size: { state: 'not-applicable' } };
const owner = (publisher, known = true) => ({ state: 'known', publisher, known_owner: known, listed_maintainer: known, earlier_publisher: known,
  by_publisher: known ? 3 : 0, earlier_versions: 18 });
const EVENTS = [
  ev('lodash', { version: '4.17.21' }),
  ev('left-pad', { version: '1.3.0', class: 'named', coverage: 'checked', named: ['install-introduced'], reason: 'an install script appears',
    notice: true, k: '1.2.0' }),
  { at: START, kind: 'refused', package: 'evil-pkg', version: '6.6.6', facts: ['seed-v3:pin'], reason: 'pin', status: 403 },
  ev('fresh-pkg', { version: '0.1.0', coverage: 'not-covered', seed_unheld: true, notice: true }),
  ev('odd-pkg', { version: '2.0.0', class: 'not-checked', coverage: 'indeterminate' }),
  ev('hooky', { version: '3.0.0', coverage: 'not-covered' }),
  facts('p-try', '2.2.0', { dist_tag: { state: 'known', not_latest: true, latest: '3.0.0', tags: [] }, known_owner: owner('sindresorhus'), ...cold }),
  facts('@pkgr/core', '0.3.6', { dist_tag: { state: 'known', not_latest: false, tags: ['latest'] }, known_owner: owner('GitHub Actions', false), ...cold }),
  facts('lodash', '4.17.21', { dist_tag: { state: 'known', not_latest: false, tags: ['latest'] }, known_owner: owner('jdalton'), ...cold }),
];
const payload = (events = EVENTS, seed = { sha256: null, history_cutoff: '2026-10-30T02:14:59Z', trust: 'authenticated',
  cache: { root_cut_at: '2026-11-01T02:44:49Z', root_digest: 'f'.repeat(64), seed_version: 'seed-v3.3-full' } }) => ({
  service: 'chaingate-proxy', version: '0.1.6.1', started_at: START, policy: 'cft-policy-1.3', view: 'all', seed, stats: {},
  installs: [{ key: 'client:127.0.0.1#1', grouping: 'client', started_at: START, last_at: LAST, dropped: 0, dropped_important: 0, events }],
});
const render = (opts) => renderReport(payload(), { source: 'proxy', ...opts });

test('RL1 the header names proxy, policy and seed on their own lines; each install opens with its time span and a table of counts', () => {
  const { text } = render();
  const lines = text.split('\n');
  assert.equal(lines[0], 'ChainGate report   proxy 0.1.6.1   policy cft-policy-1.3');
  assert.equal(lines[1], 'Seed               seed cache (seed seed-v3.3-full, root of 2026-11-01T02:44:49Z, history to 2026-10-30T02:14:59Z)');
  assert.ok(text.includes('Install 1   2026-11-01 07:33:06Z to 07:33:41Z (34 s)   from 127.0.0.1 (requests grouped by a 60 s idle gap)'), text);
  for (const row of [
    '  Packages served                   5',
    '  Named warnings                    1',
    '  Blocked or refused                1',
    '  Not checked by the seed           1',
    '  Checked only by install rule      1',
    '  Not checked by any named rule     1   (1 history indeterminate)',
  ]) assert.ok(lines.includes(row), `${row}\n---\n${text}`);
});

test('RL2 what needs a look is listed by name after the table: named warnings, refusals, packages the seed did not check, packages no named rule checked', () => {
  const { text, exit } = render();
  assert.equal(exit, 3, 'the exit code is unchanged: a refusal');
  assert.ok(text.includes('left-pad@1.3.0  NAMED WARNING: an install script appears that earlier releases did not have'), text);
  assert.ok(text.includes('evil-pkg@6.6.6  BLOCKED (download refused): a recorded advisory names this version - npm could not install it'), text);
  assert.ok(text.includes('  Not checked by the seed (its seed data could not be downloaded in time):\n    fresh-pkg@0.1.0'), text);
  assert.ok(text.includes('  Not checked by any named rule:\n    odd-pkg@2.0.0 (history indeterminate)'), text);
  assert.ok(!text.includes('hooky@3.0.0'), 'a package checked only by the install rule is counted, not listed');
});

test('RL3 recorded facts are one count line by default; --verbose lists the notable ones grouped by kind', () => {
  const { text } = render();
  assert.ok(text.includes('  Recorded facts: 2 version(s) with a notable fact (recorded only; no verdict depends on them). '
    + 'Show them: chaingate report --verbose'), text);
  assert.ok(!text.includes('p-try@2.2.0'), text);
  const v = render({ verbose: true }).text;
  assert.ok(v.includes('  Recorded facts (recorded only; no verdict depends on them):'), v);
  assert.ok(v.includes('    Not the latest tag (1):\n      p-try@2.2.0 (latest is 3.0.0)'), v);
  assert.ok(v.includes('    Publisher not a known owner (1):\n      @pkgr/core@0.3.6 (GitHub Actions; published 0 of 18 earlier versions)'), v);
  assert.ok(!v.includes('not applicable'), 'a fact that does not apply is not printed');
  assert.ok(!v.includes('lodash@4.17.21 ('), 'a version with nothing notable is not listed');
});

test('RL4 the human report is ASCII only and never prints internal record versions; --json is what the proxy sent', () => {
  for (const verbose of [false, true]) {
    const { text } = render({ verbose });
    assert.ok(/^[\x0a\x20-\x7e]*$/.test(text), [...text].filter((c) => c > '\x7e').join(''));
    assert.doesNotMatch(text, /shadow-facts-|static-checks-\d/);
  }
  const p = payload();
  const before = JSON.stringify(p);
  renderReport(p, { source: 'proxy', verbose: true });
  assert.equal(JSON.stringify(p), before, 'rendering never changes the payload --json prints');
});

test('RL5 a full seed and no seed keep their header line; zero-only rows that rarely matter are left out', () => {
  const full = renderReport(payload([ev('a')], { sha256: '1408e015a7026ea2'.padEnd(64, '0'), history_cutoff: '2026-10-30T02:14:59Z' }),
    { source: 'proxy' }).text;
  assert.ok(full.split('\n')[1] === 'Seed               seed 1408e015a7026ea2 (history to 2026-10-30T02:14:59Z)', full);
  assert.ok(!full.includes('Dist-tags moved') && !full.includes('Served under your overrides'), full);
  const none = renderReport(payload([ev('a')], null), { source: 'proxy' }).text;
  assert.equal(none.split('\n')[1], 'Seed               no seed loaded');
});
