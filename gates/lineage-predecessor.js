// 0.1.5 group 1 (T1.4): the LINEAGE predecessor -- a port of the seed's FU-2 FINAL lineage rule
// (chaingate-ops collector/drift_cooccurrence.py `resolve_lineage_predecessors`, parity PASS vs the E1 census 2026-09-17),
// over the served packument instead of the corpus:
//
//   E5  a version whose `time` entry is missing or does not parse is in no lineage and holds no predecessor;
//   E4  a `0.0.x-security` takedown stub likewise;
//   sort the rest by (publication time, version string), stable -- the order the corpus and the seed use;
//   E2  lineage key = the leading integer of the version (all 0.x share '0'; a non-digit prefix -> '0');
//   E1  contiguous-CalVer tail: when the >= 2 most recently introduced DISTINCT majors are strictly decreasing CalVer years
//       (2000..2027), they collapse into one lineage key, so a prerelease of the next year is judged against the right base;
//   predecessor = the previous version in publish order within the same lineage key (prereleases are members).
//
// Why this and not gates/predecessor.js (the highest lower RELEASE of the same SemVer major): chaingate-ops handover §7.3.
// Measured on 24,154,424 versions (base-rates-1.2, 2026-10-13), the size-jump-provenance rule fires on 0.020 % of versions
// against this predecessor (1 per 6,083 established versions) and on 0.106 % against gates/predecessor.js, with the same
// recall: a canary or nightly prerelease compared with an old stable release is noise, and this rule compares it with the
// build before it instead. The two predecessors answer different questions; the other Tier 1 gates keep theirs.
//
// Cost: an index per packument (memoised per (versions, times) object), O(n log n); a lookup is O(1).
export const STUB_RE = /0\.0\.\d+-security$/;          // E4, exactly the corpus's pattern
const MAJOR_RE = /^(\d+)/;
const CALVER_RE = /^20\d\d$/;
const CALVER_MIN = 2000; const CALVER_MAX = 2027;
export const CALVER_KEY = '__CALVER__';

export const majorOf = (version) => { const m = MAJOR_RE.exec(String(version ?? '')); return m ? m[1] : '0'; };
const isCalverYear = (major) => CALVER_RE.test(major) && Number(major) >= CALVER_MIN && Number(major) <= CALVER_MAX;

/** version -> predecessor version | null, for every version of the packument (FU-2 FINAL, scoped to one package). */
export function lineagePredecessors(versions, times) {
  const out = new Map();
  if (!versions || typeof versions !== 'object') return out;
  const valid = [];
  for (const v of Object.keys(versions)) {
    out.set(v, null);
    if (STUB_RE.test(v)) continue;
    const t = times && typeof times[v] === 'string' ? Date.parse(times[v]) : NaN;
    if (Number.isNaN(t)) continue;
    valid.push({ v, t });
  }
  valid.sort((a, b) => (a.t - b.t) || (a.v < b.v ? -1 : (a.v > b.v ? 1 : 0)));
  // E1: distinct majors in order of first appearance; the CalVer tail collapses only when it has >= 2 members
  const distinct = [];
  const seen = new Set();
  for (const { v } of valid) { const m = majorOf(v); if (!seen.has(m)) { seen.add(m); distinct.push(m); } }
  const tail = [];
  for (let i = distinct.length - 1; i >= 0; i -= 1) {
    const m = distinct[i];
    if (isCalverYear(m) && (!tail.length || Number(m) < Number(tail[tail.length - 1]))) tail.push(m); else break;
  }
  const calver = new Set(tail.length >= 2 ? tail : []);
  const key = (v) => { const m = majorOf(v); return calver.has(m) ? CALVER_KEY : m; };
  const last = new Map();
  for (const { v } of valid) {
    const k = key(v);
    out.set(v, last.has(k) ? last.get(k) : null);
    last.set(k, v);
  }
  return out;
}

const indexes = new WeakMap();           // versions -> WeakMap(times -> Map) | Map
function indexFor(versions, times) {
  const timed = times && typeof times === 'object';
  let entry = indexes.get(versions);
  if (timed) {
    if (!(entry instanceof WeakMap)) { entry = new WeakMap(); indexes.set(versions, entry); }
    if (!entry.has(times)) entry.set(times, lineagePredecessors(versions, times));
    return entry.get(times);
  }
  if (!entry || entry instanceof WeakMap) { entry = lineagePredecessors(versions, null); indexes.set(versions, entry); }
  return entry;
}

/** { version, manifest } of the lineage predecessor, or null (first of its line, a stub, or undated). */
export function lineagePredecessorOf(versions, times, version) {
  if (typeof version !== 'string' || !versions || typeof versions !== 'object') return null;
  const p = indexFor(versions, times).get(version);
  return p ? { version: p, manifest: versions[p] } : null;
}

export default { lineagePredecessorOf, lineagePredecessors, majorOf, STUB_RE, CALVER_KEY };
