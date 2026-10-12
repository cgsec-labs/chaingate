// 0.1.4 group 3a (D-T4, D-T5): the release a Tier 1 detail row compares against -- the highest version of the same major
// with no prerelease and lower SemVer precedence, published before the candidate, for which `has(manifest)` holds.
// Siblings (prerelease builds such as -slim or platform variants) are never predecessors (r3 T1.2: recon cmp-rule-3).
// Linear in the number of versions; the rows using it are contributing (detail), evaluated once per version.
import semver from 'semver';

export function predecessorOf(versions, times, version, has = () => true) {
  const cand = typeof version === 'string' ? semver.parse(version) : null;
  if (!cand || !versions || typeof versions !== 'object') return null;
  const c = times && typeof times[version] === 'string' ? Date.parse(times[version]) : NaN;
  let best = null;
  for (const [v, m] of Object.entries(versions)) {
    const p = semver.parse(v);
    if (!p || p.prerelease.length || p.major !== cand.major || semver.compare(p, cand) >= 0) continue;
    const t = times && typeof times[v] === 'string' ? Date.parse(times[v]) : NaN;
    if (!Number.isNaN(c) && !(t < c)) continue;
    if (!has(m)) continue;
    if (!best || semver.compare(p, best.parsed) > 0) best = { version: v, parsed: p, manifest: m };
  }
  return best;
}

export default { predecessorOf };
