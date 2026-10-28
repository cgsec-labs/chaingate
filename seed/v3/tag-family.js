// The prerelease tag family (collector/drift_cooccurrence.py tag_family, pinned by lineage-tag-family-cases-0.2): one
// definition for the seed's rl2 placement (seed/v3/gate.js) and the install-time lineage predecessor
// (gates/lineage-predecessor.js).
export const RELEASE_FAMILY = 'release';
// the npm holding text the forward stub predicate excludes (collector/stub_recognition.py HOLDING_DESCRIPTION; name-hold
// texts are NOT excluded, as there)
export const HOLDING_DESCRIPTION = 'security holding package';
// Python's `$` also matches before a final newline, hence `\n?`
const HEX_ID_RE = /^[0-9a-f]{7,40}\n?$/;
const FAMILY_RE = /^[A-Za-z]+/;

/** The prerelease tag family: build metadata dropped; no "-" is release; a commit-hash or numeric-first tag is num. */
export function tagFamily(version) {
  const v = String(version ?? '').split('+')[0];
  const dash = v.indexOf('-');
  if (dash < 0) return RELEASE_FAMILY;
  const pre = v.slice(dash + 1);
  const first = pre.split('.')[0];
  if (HEX_ID_RE.test(first) && /[0-9]/.test(first)) return 'num';
  const m = FAMILY_RE.exec(pre);
  return m ? m[0].toLowerCase() : 'num';
}
