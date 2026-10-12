// cft-policy-1.2 (0.1.4 group 2a, D-N6): ONE classification of a decision's gate results, for visibility, the report and
// the store's change rule. Structural: named, contributing and coverage come from the seed-v3 GateResult's `rows` member
// and the row values, never from free text. Facts come from C2's own classifier (decision-rule.js blockReasons), so
// enforcement and reporting cannot disagree.
//
//   fact          a BLOCK whose C2 reason is content-hash or seed-v3:pin
//   named         a seed-v3 `rows` entry in policy.NAMED_ROWS with result WARN (Tier 1 adds its gates by name)
//   contributing  any NOTE (a top-level runner row, or a seed-v3 `rows` entry)
//   coverage      seed-v3 `rows` entries seed-v3:coverage WARN, or seed-v3:input WARN/BLOCK (operator choices)
//   legacy        a seed-v3 result without `rows` whose detail carries an older policy prefix (1.0 / 1.1): never
//                 relabelled as named; the store writes a current row on the next evaluation (D-N7)
import POL from '../seed/v3/policy.js';
import { REASON, blockReasons } from './decision-rule.js';

const NAMED = new Set(POL.NAMED_ROWS);
const NAMED_RUNNER = new Set(POL.NAMED_RUNNER_GATES);
const LEGACY_PREFIXES = Object.freeze(['cft-policy-1.0: ', 'cft-policy-1.1: ']);
const FACT_REASONS = new Set([REASON.CONTENT_HASH, REASON.PIN]);

/** The seed-v3 policy prefix of a result list ('cft-policy-1.2', …), or null when there is no seed-v3 result. */
export function policyPrefix(results) {
  const s = (Array.isArray(results) ? results : []).find((x) => x && x.gate === 'seed-v3');
  if (!s || typeof s.detail !== 'string') return null;
  const m = /^(cft-policy-\d+\.\d+): /.exec(s.detail);
  return m ? m[1] : null;
}

/** Classes of one decision's gate results. Unknown shapes are never named and never clean. */
export function classify(results) {
  const list = Array.isArray(results) ? results : [];
  const out = { facts: [], named: [], contributing: [], coverage: [], legacy: false };
  out.facts = factsOf(list);
  for (const x of list) {
    if (!x || typeof x !== 'object') continue;
    if (x.result === POL.NOTE) out.contributing.push(x.gate);
    if (x.result === 'WARN' && NAMED_RUNNER.has(x.gate)) out.named.push(x.gate);     // 0.1.4 group 3a (D-T2)
    if (x.gate !== 'seed-v3') continue;
    if (!Array.isArray(x.rows)) {
      if (typeof x.detail === 'string' && LEGACY_PREFIXES.some((p) => x.detail.startsWith(p))) out.legacy = true;
      continue;
    }
    for (const row of x.rows) {
      if (!row || typeof row !== 'object') continue;
      if (row.result === 'WARN' && NAMED.has(row.gate)) out.named.push(row.gate);
      else if (row.result === POL.NOTE) out.contributing.push(row.gate);
      else if ((row.gate === 'seed-v3:coverage' && row.result === 'WARN')
        || (row.gate === 'seed-v3:input' && (row.result === 'WARN' || row.result === 'BLOCK'))) out.coverage.push(row.gate);
    }
  }
  out.named = [...new Set(out.named)].sort();
  out.contributing = [...new Set(out.contributing)].sort();
  out.coverage = [...new Set(out.coverage)].sort();
  return out;
}

/**
 * Facts, STRUCTURALLY where the record allows (2b review, dated note 5.2): content-hash BLOCK -> content-hash; a seed-v3
 * BLOCK that carries `rows` is a pin fact only if a `seed-v3:known-malicious-pin` BLOCK row says so (detail text, which
 * can echo manifest fields, is never trusted for a 1.2 row); a rowless seed-v3 row (written by an older runtime) falls back
 * to C2's text classifier.
 */
function factsOf(list) {
  const out = new Set();
  for (const x of list) {
    if (!x || typeof x !== 'object' || x.result !== 'BLOCK') continue;
    if (x.gate === 'content-hash') out.add(REASON.CONTENT_HASH);
    else if (x.gate === 'seed-v3') {
      if (Array.isArray(x.rows)) {
        if (x.rows.some((r) => r && r.gate === POL.PIN_GATE && r.result === 'BLOCK')) out.add(REASON.PIN);
      } else if (blockReasons([x]).includes(REASON.PIN)) out.add(REASON.PIN);
    }
  }
  return [...out].sort();
}

/** The facts held in an unstored-BLOCK reason bit set (decision-rule.js BITS: content-hash 1, pin 2; input 4 is no fact). */
export function factsFromBits(bits) {
  const out = [];
  if (Number.isInteger(bits) && (bits & 1)) out.push(REASON.CONTENT_HASH);
  if (Number.isInteger(bits) && (bits & 2)) out.push(REASON.PIN);
  return out;
}

/**
 * The fact reasons among C2's `pending` that a stored row structurally confirms (dated note 5.3): a pending reason C2
 * derived from text alone is not claimed as a fact unless some stored row's structural facts include it.
 */
export function pendingFacts(rows, pending) {
  const want = (Array.isArray(pending) ? pending : [...(pending ?? [])]).filter((r) => FACT_REASONS.has(r));
  if (!want.length) return [];
  const seen = new Set();
  for (const row of Array.isArray(rows) ? rows : []) for (const f of factsOf(Array.isArray(row?.gates_fired) ? row.gates_fired : [])) seen.add(f);
  return want.filter((r) => seen.has(r)).sort();
}

/**
 * D-N7 (amended before the 2a commit): what a stored row must still say for the record to be current -- the disposition,
 * the named rows, the CONTRIBUTING rows, the fact reasons and the policy identity. Contributing rows are included because
 * under 1.2 they no longer move the disposition: without them a release whose only signals are contributing (axios-style:
 * four pilot gates) would never reach the record, and `why` could not show them.
 */
export function classSignature(disposition, results) {
  const c = classify(results);
  return JSON.stringify([disposition ?? null, c.named, c.contributing, c.facts, policyPrefix(results)]);
}

/**
 * 0.1.4 group 2c (D-R7, dated note 6.4): whether any named rule checked a decision, from the seed-v3 GateResult's `rows`
 * member (gate and result only; no free text, no placement kind). The first rule that matches decides:
 *   no-seed         no seed-v3 result
 *   earlier-policy  a rowless seed-v3 result with a 1.0 / 1.1 prefix (written before re-evaluation)
 *   failed          any other rowless seed-v3 result (the runner's plain-value fallback), or any `seed-v3:input` row
 *   not-covered     Channel-A could not place the release (an unsuffixed `seed-v3:channel-a` row) and no named row is
 *                   determinate
 *   indeterminate   a named row SKIP, or no named row at all
 *   checked         every named row present is determinate (ALLOW or WARN)
 * The `seed-v3:coverage` "nothing evaluated" row is not read: it exists only under on_no_evidence WARN.
 */
export function coverageClass(results) {
  const s = (Array.isArray(results) ? results : []).find((x) => x && x.gate === 'seed-v3');
  if (!s) return 'no-seed';
  if (!Array.isArray(s.rows)) {
    return typeof s.detail === 'string' && LEGACY_PREFIXES.some((p) => s.detail.startsWith(p)) ? 'earlier-policy' : 'failed';
  }
  const rows = s.rows.filter((r) => r && typeof r === 'object');
  if (rows.some((r) => r.gate === 'seed-v3:input')) return 'failed';
  const namedRows = rows.filter((r) => NAMED.has(r.gate));
  const determinate = (r) => r.result === 'ALLOW' || r.result === 'WARN';
  if (rows.some((r) => r.gate === 'seed-v3:channel-a') && !namedRows.some(determinate)) return 'not-covered';
  if (!namedRows.length || !namedRows.every(determinate)) return 'indeterminate';
  return 'checked';
}

/**
 * 0.1.4 group 2c (D-R1, dated note 6.5): the class of a SERVED tarball's decision -- named > not-checked > contributing >
 * clean -- with its coverage class and the named and contributing rows.
 */
export function servedClass(results) {
  const c = classify(results);
  const coverage = coverageClass(results);
  const cls = c.named.length ? 'named' : (!namedRuleChecked(results) ? 'not-checked' : (c.contributing.length ? 'contributing' : 'clean'));
  return { class: cls, coverage, named: c.named, contributing: c.contributing };
}

/**
 * 0.1.4 group 3a (D-T3): whether SOME named rule was determinate (ALLOW or WARN) -- the seed's strict tier (coverage class
 * `checked`) or a named runner gate. "Not checked by any named rule" (V6) and K's "evaluated" (D-R5) both read this.
 */
export function namedRuleChecked(results) {
  if (coverageClass(results) === 'checked') return true;
  return (Array.isArray(results) ? results : []).some((x) => x && NAMED_RUNNER.has(x.gate) && (x.result === 'ALLOW' || x.result === 'WARN'));
}

export default { classify, classSignature, policyPrefix, decidingReason, factsFromBits, pendingFacts, coverageClass, servedClass,
  namedRuleChecked };

/** Rank of one row for the deciding reason (D-V1): fact 0, named 1, coverage 2, other 3, synthetic chaingate 4. */
function rank(x) {
  if (!x || typeof x !== 'object') return 9;
  if (x.gate === 'chaingate') return 4;
  const c = classify([x]);
  if (c.facts.length) return 0;
  if (c.named.length) return 1;
  if (c.coverage.length) return 2;
  return 3;
}

/**
 * 0.1.4 group 2b (D-V1, A1): the reason a decision says what it says -- the rows whose result equals the disposition (all
 * rows when none does), ranked fact > named > coverage > other > synthetic, stable within a rank, `<gate>: <detail>`.
 */
export function decidingReason(results, disposition) {
  const list = (Array.isArray(results) ? results : []).filter((x) => x && typeof x === 'object');
  const bearing = list.filter((x) => x.result === disposition);
  const rows = (bearing.length ? bearing : list).map((x, i) => ({ x, i, r: rank(x) }));
  rows.sort((a, b) => (a.r - b.r) || (a.i - b.i));
  return rows.map(({ x }) => `${x.gate}: ${typeof x.detail === 'string' ? x.detail : ''}`).join(' | ');
}
