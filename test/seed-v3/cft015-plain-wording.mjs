// 0.1.5: four reason texts no longer carry internal rule codes (seed/v3/gate.js placement reasons, seed/v3/policy.js threshold
// detail). The frozen goldens keep the wording they were captured with; a comparison maps a COPY of a golden to the current
// wording with exactly these replacements, applied after the policy transforms, and nothing else.
export const PLAIN_WORDING = Object.freeze([
  ['(threshold over history: warns, never blocks — D1)', '(threshold over history: warns, never blocks)'],
  ['takedown stub (FU-2 E4): it is excluded', 'takedown stub: it is excluded'],
  ['no publication time (FU-2 E5):', 'no publication time:'],
  ['depends on the FU-2 E1 CalVer collapse', 'depends on the CalVer collapse rule'],
]);

/** A deep copy of `x` with every string mapped through PLAIN_WORDING. */
export function plainWording(x) {
  if (typeof x === 'string') return PLAIN_WORDING.reduce((s, [a, b]) => s.replaceAll(a, b), x);
  if (Array.isArray(x)) return x.map(plainWording);
  if (x && typeof x === 'object') return Object.fromEntries(Object.entries(x).map(([k, v]) => [k, plainWording(v)]));
  return x;
}
