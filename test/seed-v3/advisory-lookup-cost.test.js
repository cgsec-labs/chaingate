// Since 0.1.9 (the 0.1.8 fix release): the advisory check behind "a version named by an advisory is never the comparison" (0.1.8,
// retier-1.1) asks once per version per registry document. 0.1.8 asked again on every walk back, for every version the proxy
// evaluates in the document, so a package with thousands of releases cost millions of seed lookups per request (a 4,652-version
// document took 200 s instead of 14 s, and every other download waited behind it). The decisions do not change: only how often
// the same question is asked. Written before the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import G from '../../seed/v3/gate.js';
import { inputFromPackument } from '../../cli/check-record.js';
import { buildSeed, openFixtureSeed, docFor, manifestFor, after, WARNCFG } from './u05-fixtures.mjs';

const BOB = { _npmUser: { name: 'bob', email: 'bob@example.net' }, maintainers: [{ name: 'bob', email: 'bob@example.net' }] };
const N = 120;
// N releases after the seed tip, every other one bob's and without gitHead: Channel-A breaks, so the re-tier and the live recount
// both look for a baseline, and their walk back passes every earlier release of the line
function bigDoc() {
  const extra = [];
  for (let i = 0; i < N; i += 1) {
    const v = `1.2.${i + 1}`;
    const m = manifestFor('p', v, i % 2 ? { ...BOB } : {});
    if (i % 2) delete m.gitHead;
    extra.push([v, after(1 + i / 1000), m]);
  }
  return docFor('p', extra);
}
const evalAll = (seed, doc, pinOverlay) => Object.keys(doc.versions).map((v) => G.evaluateCandidate(seed,
  { config: WARNCFG, domainVersionCount: 'from-packument', pinOverlay }, inputFromPackument(doc, 'p', v)).decision);

function withSeed(fn) {
  const s = buildSeed({ layout: '1.1' });
  const seed = openFixtureSeed(s.dbPath);
  try { return fn(seed); } finally { seed.close(); s.cleanup(); }
}

test('AC1 evaluating every version of one document asks the advisory question about each version at most once more', () => withSeed((seed) => {
  const doc = bigDoc(); const n = Object.keys(doc.versions).length;
  let calls = 0; const overlay = () => { calls += 1; return null; };
  const ds = evalAll(seed, doc, overlay);
  assert.ok(ds.some((d) => d.retier || d.live), 'the fixture reaches the baseline search');
  // one lookup per evaluated version (its own pin) plus at most one per version as a candidate baseline
  assert.ok(calls <= 2 * n, `${calls} pins-feed lookups for ${n} versions (0.1.8: quadratic)`);
}));

test('AC2 the seed\'s pin query runs once per lookup, so it is bounded by the versions too (each lookup still prepares it, as in 0.1.8)', () => withSeed((seed) => {
  const doc = bigDoc(); const n = Object.keys(doc.versions).length;
  const prep = seed.db.prepare.bind(seed.db); let pinPrepares = 0;
  seed.db.prepare = (sql) => { if (/known_malicious_pins/.test(sql)) pinPrepares += 1; return prep(sql); };
  try { evalAll(seed, doc, () => null); } finally { delete seed.db.prepare; }
  assert.ok(pinPrepares <= 2 * n, `${pinPrepares} pin queries for ${n} versions`);
}));

test('AC3 the decisions are the ones a fresh document gives each version (nothing carried that should not be)', () => withSeed((seed) => {
  const overlay = (p, v) => (v === '1.2.7' ? { record_id: 'R-1', advisory_id: 'ADV-X', source: 'feed' } : null);
  const shared = bigDoc();
  const once = evalAll(seed, shared, overlay);
  const fresh = Object.keys(shared.versions).map((v) => { const d = bigDoc(); return G.evaluateCandidate(seed,
    { config: WARNCFG, domainVersionCount: 'from-packument', pinOverlay: overlay }, inputFromPackument(d, 'p', v)).decision; });
  const strip = (d) => JSON.parse(JSON.stringify(d));
  assert.deepEqual(once.map(strip), fresh.map(strip));
  assert.ok(once.some((d) => d.live?.skipped_advisory > 0 || /named by an advisory skipped/.test(JSON.stringify(d))),
    'the feed pin on 1.2.7 is skipped somewhere');
}));

test('AC4 an answer is kept for one document and one pins source only: a new document or a new overlay asks again', () => withSeed((seed) => {
  const v = '1.2.9';
  const ask = (doc, overlay) => G.evaluateCandidate(seed, { config: WARNCFG, domainVersionCount: 'from-packument', pinOverlay: overlay },
    inputFromPackument(doc, 'p', v)).decision;
  const doc = bigDoc();
  const none = () => null; const pin8 = (p, x) => (x === '1.2.8' ? { record_id: 'R-8', advisory_id: 'ADV-8', source: 'feed' } : null);
  const a = JSON.stringify(ask(doc, none));
  const b = JSON.stringify(ask(doc, pin8));         // same document, the feed now names 1.2.8
  const c = JSON.stringify(ask(bigDoc(), pin8));    // a new document
  assert.equal(b, c, 'a new overlay is not answered from the old one\'s memo');
  assert.notEqual(a, b, 'the feed pin changes what 1.2.9 is compared with');
}));

test('AC5 the same document, the same overlay function and the same seed: an answer that changes between two passes is read anew', async () => {
  const s = buildSeed({ layout: '1.1' }); const seed = openFixtureSeed(s.dbPath);
  try {
    const doc = bigDoc(); let named = null;   // closure state, as a new pins feed cut changes what the one overlay returns
    const overlay = (p, x) => (x === named ? { record_id: 'R', advisory_id: 'ADV-CUT', source: 'feed' } : null);
    const one = () => G.evaluateCandidate(seed, { config: WARNCFG, domainVersionCount: 'from-packument', pinOverlay: overlay },
      inputFromPackument(doc, 'p', '1.2.9')).decision;
    const before = JSON.stringify(one());
    await new Promise((r) => setImmediate(r));
    named = '1.2.8';
    const after1 = JSON.stringify(one());
    const fresh = JSON.stringify(G.evaluateCandidate(seed, { config: WARNCFG, domainVersionCount: 'from-packument', pinOverlay: overlay },
      inputFromPackument(bigDoc(), 'p', '1.2.9')).decision);
    assert.equal(after1, fresh, 'the second pass answers as a fresh document does');
    assert.notEqual(before, after1, 'the new cut changes what 1.2.9 is compared with');
  } finally { seed.close(); s.cleanup(); }
});

test('AC6 an overlay that throws for one version: the shared document decides as fresh documents do', () => withSeed((seed) => {
  const overlay = (p, v) => { if (v === '1.2.7') throw new Error('feed read failed'); return null; };
  const shared = bigDoc();
  const once = evalAll(seed, shared, overlay);
  const fresh = Object.keys(shared.versions).map((v) => G.evaluateCandidate(seed,
    { config: WARNCFG, domainVersionCount: 'from-packument', pinOverlay: overlay }, inputFromPackument(bigDoc(), 'p', v)).decision);
  const strip = (d) => JSON.parse(JSON.stringify(d));
  assert.deepEqual(once.map(strip), fresh.map(strip));
}));
