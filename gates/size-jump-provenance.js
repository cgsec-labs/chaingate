// 0.1.5 size-jump-provenance -- a NAMED gate in cft-policy-1.2: "a payload bundled into the tarball, published
// from outside the repository's CI". The candidate's dist.unpackedSize at or above 5x its LINEAGE predecessor's
// (gates/lineage-predecessor.js: the previous version in publish order within its release line, and
// for a prerelease the previous version of its own tag there) AND the
// candidate's provenance to the repository broke against that predecessor: its gitHead is absent where the predecessor had
// one, or its repository URL differs.
//
// Measured before it was written (over 24,154,424 corpus versions, against the lineage predecessor): fires on 0.020 % of
// versions (1 per 6,083 established versions) and on the first malicious version of 8 established labelled packages that no
// named rule of 0.1.4 reaches (leo-*, creditcard.js, mbt, node-env-resolver; 57.4 % -> 64.8 % of 108 established labelled
// packages), all plain releases. Against gates/predecessor.js the same rule fires 5x more often with no recall gain
// (canary/nightly prereleases compared with an old stable), which is why this gate uses the lineage predecessor.
// The gate is NAMED on the strength of this lineage re-measure.
//
// Reads only the served packument (`rawVersions`, `rawTimes`): history-independent, like the other Tier 1 gates.
// Deterministic. Nothing here is a judgement of the code; a release that bundles its build output and moves its repository
// in one version fires it, and `chaingate why` says exactly which two facts did.
import { lineagePredecessorOf, noPredecessorReason } from './lineage-predecessor.js';

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
    const pred = lineagePredecessorOf(versions, input?.rawTimes, input?.version);
    if (!pred) return result('SKIP', `not evaluable: ${noPredecessorReason(input.version)}`);
    const psize = sizeOf(pred.manifest);
    if (psize === null) return result('SKIP', `not evaluable: the previous version of this release line (${pred.version}) has no size`);
    const ratio = size / psize;
    const sizeText = `unpackedSize ${size} vs ${psize} of ${pred.version} (${ratio.toFixed(1)}×)`;
    if (ratio < RATIO) return result('ALLOW', `${sizeText}, below ${RATIO}×`);
    const breaks = provenanceBreaks(cand, pred.manifest);
    if (!breaks.length) return result('ALLOW', `${sizeText}, at or above ${RATIO}×; gitHead and repository as in ${pred.version}`);
    return result('WARN', `${sizeText}, at or above ${RATIO}×, and ${breaks.join('; ')} vs ${pred.version}`);
  },
};
