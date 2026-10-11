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
  out.facts = blockReasons(list).filter((r) => FACT_REASONS.has(r)).sort();
  for (const x of list) {
    if (!x || typeof x !== 'object') continue;
    if (x.result === POL.NOTE) out.contributing.push(x.gate);
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
 * D-N7 (amended before the 2a commit): what a stored row must still say for the record to be current -- the disposition,
 * the named rows, the CONTRIBUTING rows, the fact reasons and the policy identity. Contributing rows are included because
 * under 1.2 they no longer move the disposition: without them a release whose only signals are contributing (axios-style:
 * four pilot gates) would never reach the record, and `why` could not show them.
 */
export function classSignature(disposition, results) {
  const c = classify(results);
  return JSON.stringify([disposition ?? null, c.named, c.contributing, c.facts, policyPrefix(results)]);
}

export default { classify, classSignature, policyPrefix };
