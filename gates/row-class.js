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
  // 0.1.4 group 3a (D-T4, D-T5): T1.2 at >= 2x and T1.3, contributing in 1.2 (r3 §18.6, §18.7)
  'size-jump', 'publish-tool-change',
  // 0.1.5 group 1: T1.5 identity-break, contributing by operator ruling 2026-10-13 (ops handover §7.3). T1.4
  // size-jump-provenance is a NAMED runner gate (policy.NAMED_RUNNER_GATES), the lineage re-measure having held.
  'identity-break',
  // 0.1.5 T1.6 entry-path-change (operator 2026-10-15, orchestrator verdict 20:25Z): contributing; every component over the bar but one
  'entry-path-change',
  // 0.1.5 static checks step 3 (design note §5): the five tarball static checks start CONTRIBUTING; a check becomes named only by an
  // operator ruling after the §6 measurement, one at a time (then: OUT of this list, into policy.NAMED_RUNNER_GATES and proxy/notice.js;
  // a gate left here has its WARN turned into NOTE by withRole, so it can never be named)
  // static-checks-1.2 (operator ruling 2026-10-15, path (a)): S5 oversized-hook-target joined as a sixth static check, CONTRIBUTING first.
  // Naming (operator ruling 2026-10-15, ops handover 11.1/11.4): S0 and S5 are NAMED runner gates and left this list; S1-S4 stay.
  'static:S1-loader-in-hook-target', 'static:S2-obfuscated-entry', 'static:S3-secret-harvest-with-sink', 'static:S4-wallet-swap-hook',
  // operator rulings R2 and R3 2026-10-21: S6 network-only-beacon and S7 entry-capability-delta, CONTRIBUTING first
  'static:S6-network-only-beacon', 'static:S7-entry-capability-delta',
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

/**
 * 0.1.4 group 3b (D-N2): a validated copy of N1h's `added` / `pending` list -- at most 10 { name, target, spec } with string
 * members of bounded length -- or null when absent or malformed (never throws).
 */
export function validDeps(list) {
  if (!Array.isArray(list) || list.length > 10) return null;
  const ok = (s, n) => typeof s === 'string' && s.length > 0 && s.length <= n;
  const out = [];
  for (const d of list) {
    if (!d || typeof d !== 'object' || !ok(d.name, 214) || !ok(d.target, 214) || !ok(d.spec, 256)) return null;
    out.push({ name: d.name, target: d.target, spec: d.spec });
  }
  return out;
}

/** 0.1.4 group 3b (G3 dated note 3.2): N1h's `unjudgeable` notes -- at most 10 strings of at most 120 characters, or null. */
export function validNotes(list) {
  if (!Array.isArray(list) || list.length === 0 || list.length > 10) return null;
  return list.every((x) => typeof x === 'string' && x.length > 0 && x.length <= 120) ? [...list] : null;
}

export default { ROLE_POLICY, CONTRIBUTING_GATES, withRole, validRows, validDeps, validNotes, MAX_ROWS };
