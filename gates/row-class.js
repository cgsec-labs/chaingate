// cft-policy-1.2 (0.1.4 group 2a, D-N3/D-N4): the D1 runner's ONE role table, and the validation of the seed-v3 gate's
// structured `rows` member.
//
// Contributing gates (r3 §18.7, §18.15): their signal is shown beside a named row and as detail, never as a warning on its
// own. The runner records a WARN from one of them as NOTE (detail verbatim); the gate modules themselves are not edited.
// A WARN from any module NOT listed here (the seed-v3 gate, Tier 1's named modules, an unlisted module) aggregates as it
// always did. A new policy identity changes this table deliberately; the guard test pins it
// (test/seed-v3/cft014-g2a-contributing.test.js, G2a-9).
import POL from '../seed/v3/policy.js';

export const ROLE_POLICY = 'cft-policy-1.2';

export const CONTRIBUTING_GATES = Object.freeze(new Set([
  'publisher-identity', 'dep-structure', 'provenance-continuity', 'release-age', 'scope-boundary',
]));

/** A runner row with the 1.2 role applied: a contributing gate's WARN becomes NOTE. Everything else unchanged. */
export function withRole(row) {
  if (row && row.result === 'WARN' && CONTRIBUTING_GATES.has(row.gate)) return { ...row, result: POL.NOTE };
  return row;
}

const ROW_GATES = new Set(POL.POLICY_ROW_GATES);
const ROW_RESULTS = new Set(POL.ROW_RESULTS);
export const MAX_ROWS = 32;

/** A validated copy of a GateResult's `rows`, or null when absent or malformed (never throws). */
export function validRows(rows) {
  if (!Array.isArray(rows) || rows.length === 0 || rows.length > MAX_ROWS) return null;
  const out = [];
  for (const x of rows) {
    if (!x || typeof x !== 'object' || !ROW_GATES.has(x.gate) || !ROW_RESULTS.has(x.result)) return null;
    out.push({ gate: x.gate, result: x.result });
  }
  return out;
}

export default { ROLE_POLICY, CONTRIBUTING_GATES, withRole, validRows, MAX_ROWS };
