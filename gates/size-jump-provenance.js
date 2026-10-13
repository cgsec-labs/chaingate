// 0.1.5 group 1 (T1.4) size-jump-provenance -- "a payload bundled into the tarball, published from outside the repository's
// CI": the candidate's dist.unpackedSize at or above 5x its predecessor's (gates/predecessor.js: the highest lower release
// of the same major, published before) AND the candidate's provenance to the repository broke against that predecessor:
// its gitHead is absent where the predecessor had one, or its repository URL differs.
//
// Measured before it was written (chaingate-ops, docs/operator-runbooks/pin-admission-1.1-handover-20261013.md §7.1,
// tools/corpus/base_rates.py over 24,152,465 corpus versions, 2026-10-13, publish-order baseline): fires on 0.028 % of
// versions (1 per 3,810 established versions), and on the first malicious version of 8 established packages that no named
// rule of 0.1.4 reaches (57.4 % -> 64.8 % of 108 established labelled packages; +14 of 174 overall). Operator ruling
// 2026-10-13: NAMED in 0.1.5 once the same figure holds against the runtime predecessor (§7.2, base-rates-1.2 `@rt`);
// CONTRIBUTING until then, so its row is recorded as NOTE and shown beside a named row and in `chaingate why`.
//
// Reads only the served packument (`rawVersions`, `rawTimes`): history-independent, like the other Tier 1 gates.
// Deterministic. Nothing here is a judgement of the code; a release that bundles its build output and moves its repository
// in one version fires it, and `chaingate why` says exactly which two facts did.
import { predecessorOf, MAX_WALK } from './predecessor.js';

export const RATIO = 5;
const GATE = 'size-jump-provenance';
const result = (r, detail) => ({ gate: GATE, result: r, detail });

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
export const sizeOf = (m) => (isObj(m) && isObj(m.dist) && typeof m.dist.unpackedSize === 'number'
  && Number.isFinite(m.dist.unpackedSize) && m.dist.unpackedSize > 0 ? m.dist.unpackedSize : null);
export const gitHeadOf = (m) => (isObj(m) && typeof m.gitHead === 'string' && m.gitHead.trim() ? m.gitHead.trim() : null);
/** The repository URL as npm records it (a string, or { url }), normalised: no `git+`, no `.git`, no trailing `/`. */
export function repoOf(m) {
  if (!isObj(m)) return null;
  let u = typeof m.repository === 'string' ? m.repository : (isObj(m.repository) && typeof m.repository.url === 'string' ? m.repository.url : null);
  if (!u) return null;
  u = u.trim().replace(/^git\+/, '').replace(/\/+$/, '').replace(/\.git$/, '').replace(/\/+$/, '');
  return u || null;
}

/** The two provenance facts of the candidate against its predecessor; [] when neither broke. */
export function provenanceBreaks(cand, pred) {
  const out = [];
  if (gitHeadOf(pred) && !gitHeadOf(cand)) out.push('gitHead absent (the predecessor had one)');
  const a = repoOf(cand); const b = repoOf(pred);
  if (a && b && a !== b) out.push(`repository ${b} → ${a}`);
  return out;
}

export default {
  name: GATE,
  evaluate(input) {
    const versions = input?.rawVersions;
    const cand = versions?.[input?.version];
    const size = sizeOf(cand);
    if (size === null) return result('SKIP', 'not evaluable: no dist.unpackedSize for this version');
    const pred = predecessorOf(versions, input?.rawTimes, input?.version, (m) => sizeOf(m) !== null);
    if (pred?.beyond) return result('SKIP', `not evaluable: no predecessor within the last ${MAX_WALK} lower releases`);
    if (!pred) return result('SKIP', 'not evaluable: no earlier release of this major with a size');
    const psize = sizeOf(pred.manifest);
    const ratio = size / psize;
    const sizeText = `unpackedSize ${size} vs ${psize} of ${pred.version} (${ratio.toFixed(1)}×)`;
    if (ratio < RATIO) return result('ALLOW', `${sizeText}, below ${RATIO}×`);
    const breaks = provenanceBreaks(cand, pred.manifest);
    if (!breaks.length) return result('ALLOW', `${sizeText}, at or above ${RATIO}×; gitHead and repository as in ${pred.version}`);
    return result('WARN', `${sizeText}, at or above ${RATIO}×, and ${breaks.join('; ')} vs ${pred.version}`);
  },
};
