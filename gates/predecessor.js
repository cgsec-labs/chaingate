// The release a Tier 1 detail row compares against -- the highest version of the same major
// with no prerelease and lower SemVer precedence, published before the candidate, for which `has(manifest)` holds.
// Siblings (prerelease builds such as -slim or platform variants) are never predecessors.
//
// Cost: an index per packument -- eligible versions parsed once, grouped by major and sorted -- memoised
// per (versions, time) object. A candidate is a binary search plus a walk down at most MAX_WALK lower releases; past that
// there is no predecessor (stated), so a packument costs O(n log n) however many versions it lists.
import semver from 'semver';

export const MAX_WALK = 64;
const indexes = new WeakMap();           // versions -> WeakMap(times -> index) | index (no time map)

function build(versions, times) {
  const byMajor = new Map();
  for (const [v, m] of Object.entries(versions)) {
    const p = semver.parse(v);
    if (!p || p.prerelease.length) continue;
    const t = times && typeof times[v] === 'string' ? Date.parse(times[v]) : NaN;
    if (!byMajor.has(p.major)) byMajor.set(p.major, []);
    byMajor.get(p.major).push({ version: v, parsed: p, t, manifest: m });
  }
  for (const list of byMajor.values()) list.sort((a, b) => semver.compare(a.parsed, b.parsed));
  return byMajor;
}

function indexFor(versions, times) {
  const timed = times && typeof times === 'object';
  let entry = indexes.get(versions);
  if (timed) {
    if (!(entry instanceof WeakMap)) { entry = new WeakMap(); indexes.set(versions, entry); }
    if (!entry.has(times)) entry.set(times, build(versions, times));
    return entry.get(times);
  }
  if (!entry || entry instanceof WeakMap) { entry = build(versions, null); indexes.set(versions, entry); }
  return entry;
}

/** { version, manifest } of the predecessor, `{ beyond: true }` when the walk ran out, or null. */
export function predecessorOf(versions, times, version, has = () => true) {
  const cand = typeof version === 'string' ? semver.parse(version) : null;
  if (!cand || !versions || typeof versions !== 'object') return null;
  const list = indexFor(versions, times).get(cand.major);
  if (!list || !list.length) return null;
  const c = times && typeof times[version] === 'string' ? Date.parse(times[version]) : NaN;
  let lo = 0; let hi = list.length;                       // first index whose version is >= the candidate
  while (lo < hi) { const mid = (lo + hi) >> 1; if (semver.compare(list[mid].parsed, cand) < 0) lo = mid + 1; else hi = mid; }
  for (let i = lo - 1, steps = 0; i >= 0; i -= 1, steps += 1) {
    if (steps >= MAX_WALK) return { beyond: true };
    const e = list[i];
    if (!Number.isNaN(c) && !(e.t < c)) continue;
    if (!has(e.manifest)) continue;
    return { version: e.version, manifest: e.manifest };
  }
  return null;
}

export default { predecessorOf, MAX_WALK };
