// Packument rewriter — pure, side-effect-free.
//
// Given the original packument and a Map<version, decision>, produce a
// modified packument with BLOCK versions stripped from `versions{}` and
// `time{}`, and dist-tags downgraded to the highest remaining
// non-blocked candidate.
//
// Contract:
//
//   rewritePackument(packument, decisions) → {
//     packument,                 // new object, input is NOT mutated
//     changed,                   // boolean — true iff any BLOCK stripped
//     summary: {
//       kept:                number,
//       blocked:             Array<{version, reason}>,
//       warned:              Array<{version, reason}>,
//       dist_tag_downgrades: Array<{tag, from, to|null}>,
//     },
//   }
//
// Rules:
//   1. A version V is removed iff decisions.get(V).disposition === 'BLOCK'.
//   2. WARN and ALLOW versions are kept. Versions with no decision entry
//      are kept (fail-open: treat unknowns as ALLOW).
//   3. For each dist-tag pointing at a blocked version:
//        - walk remaining versions in semver.rcompare order
//        - pick the highest candidate:
//            'latest' → highest non-prerelease (npm convention)
//            other    → highest overall (prereleases allowed)
//        - no candidate → delete the tag
//   4. Input packument is not mutated. We build a new top-level object
//      and replace `versions`, `time`, and `dist-tags` with fresh objects.
//      Everything else is shared by reference (cheap on ~700KB packuments).
//   5. Versions whose version string is not valid semver are filtered out
//      of dist-tag candidates but left untouched in the output — real
//      npm packuments contain historical oddities we should not drop.

import semver from 'semver';
// Since 0.1.4: the deciding reason replaces the first non-empty detail.
import { decidingReason } from '../witness/row-class.js';
import { caretClass } from '../witness/pins.js';

const BLOCK = 'BLOCK';
const WARN = 'WARN';

function pickHighestCandidate(versionStrings, { nonPrereleaseOnly, classKey = null }) {
  let best = null;
  for (const v of versionStrings) {
    if (!semver.valid(v)) continue;
    if (nonPrereleaseOnly && semver.prerelease(v) != null) continue;
    if (classKey != null && caretClass(v) !== classKey) continue;
    if (best == null || semver.gt(v, best)) best = v;
  }
  return best;
}

/**
 * `pinned(version)` (since 0.1.4): the user pin that withholds a version, or null. A pin-withheld version is removed
 * like a BLOCKed one, but it is no BLOCK (summary.pinned, never summary.blocked); a version that is also BLOCKed is
 * removed as BLOCKed and keeps its reason. A dist-tag on a pin-withheld version moves within the pin's caret class only.
 */
export function rewritePackument(packument, decisions, { pinned = null } = {}) {
  const summary = {
    kept: 0,
    blocked: [],
    warned: [],
    pinned: [],
    dist_tag_downgrades: [],
  };

  if (packument == null || typeof packument !== 'object') {
    return { packument, changed: false, summary };
  }

  const originalVersions =
    packument.versions && typeof packument.versions === 'object' ? packument.versions : {};
  const originalTime =
    packument.time && typeof packument.time === 'object' ? packument.time : {};
  const originalTags =
    packument['dist-tags'] && typeof packument['dist-tags'] === 'object'
      ? packument['dist-tags']
      : null;

  const decisionMap = decisions instanceof Map ? decisions : new Map();

  const newVersions = {};
  const blockedSet = new Set();
  const pinnedSet = new Map();                 // version -> the pin withholding it
  let anyBlock = false;

  for (const [v, entry] of Object.entries(originalVersions)) {
    const dec = decisionMap.get(v);
    const disposition = typeof dec === 'string' ? dec : dec?.disposition;
    if (disposition === BLOCK) {
      anyBlock = true;
      blockedSet.add(v);
      summary.blocked.push({
        version: v,
        reason: typeof dec === 'object' ? decidingReason(dec?.results, BLOCK) : '',
      });
      continue;
    }
    if (disposition === WARN) {
      summary.warned.push({
        version: v,
        reason: typeof dec === 'object' ? decidingReason(dec?.results, WARN) : '',
      });
    }
    const pin = typeof pinned === 'function' ? pinned(v) : null;
    if (pin) {
      anyBlock = true;
      pinnedSet.set(v, pin);
      summary.pinned.push({ version: v, k_version: pin.k_version, class_key: pin.class_key });
      continue;
    }
    newVersions[v] = entry;
    summary.kept += 1;
  }

  if (!anyBlock) {
    return { packument, changed: false, summary };
  }

  // Build new time{} preserving non-version keys (created, modified, ...).
  const newTime = {};
  for (const [k, v] of Object.entries(originalTime)) {
    if (blockedSet.has(k) || pinnedSet.has(k)) continue;
    newTime[k] = v;
  }

  // Dist-tag walk.
  let newTags = null;
  if (originalTags) {
    newTags = {};
    const remaining = Object.keys(newVersions);
    for (const [tag, target] of Object.entries(originalTags)) {
      if (typeof target !== 'string') {
        newTags[tag] = target;
        continue;
      }
      const pin = pinnedSet.get(target);
      if (pin) {
        // Within the pin's class only, never across majors; K itself remains unless it is BLOCKed
        const inClass = pickHighestCandidate(remaining, { nonPrereleaseOnly: tag === 'latest', classKey: pin.class_key });
        if (inClass != null) newTags[tag] = inClass;
        summary.dist_tag_downgrades.push({ tag, from: target, to: inClass, pin: { k_version: pin.k_version, class_key: pin.class_key } });
        continue;
      }
      if (!blockedSet.has(target)) {
        newTags[tag] = target;
        continue;
      }
      // A BLOCKed target a user pin would also withhold moves within the pin's class;
      // it stays a BLOCK move (its fact, its reason).
      const pinOfTarget = typeof pinned === 'function' ? pinned(target) : null;
      const candidate = pickHighestCandidate(remaining, {
        nonPrereleaseOnly: tag === 'latest',
        classKey: pinOfTarget?.class_key ?? null,
      });
      if (candidate != null) {
        newTags[tag] = candidate;
        summary.dist_tag_downgrades.push({ tag, from: target, to: candidate });
      } else {
        summary.dist_tag_downgrades.push({ tag, from: target, to: null });
        // tag dropped — don't set it on newTags
      }
    }
  }

  const rewritten = { ...packument, versions: newVersions, time: newTime };
  if (newTags !== null) rewritten['dist-tags'] = newTags;

  return { packument: rewritten, changed: true, summary };
}
