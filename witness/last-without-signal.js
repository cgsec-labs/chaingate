// Since 0.1.4: the last version without the signal ("K") for a named warning -- the version
// `chaingate report` offers to stay on. Computed by the proxy when the named tarball is served, from this proxy's own
// records, and stored with the event: never recomputed later.
//
// K is the highest version of the same package that meets all of these:
//   - a release (no prerelease), lower than the warned version, inside npm's caret boundary of it (major >= 1: the same
//     major; 0.y.z with y >= 1: the same 0.y; 0.0.z: none);
//   - published at least 24 h before the warned version (the settled window, SETTLED_MS); the warned version needs a time too;
//   - seen in the latest packument this proxy observed for the package (its `last_seen_at` within 60 s of the newest);
//   - its applicable stored decision is not a BLOCK, leaves nothing pending, is not override-based, carries no named row
//     and no fact, and a named rule checked it (coverage class `checked`).
// At most `maxCandidates` decisions are read; none qualifying -> null (no pin is offered).
import semver from 'semver';
import { isOverrideRow } from './db.js';
import { classify, namedRuleChecked } from './row-class.js';

export const SETTLED_MS = 24 * 3_600_000;
const SEEN_SLACK_MS = 60_000;

const timeOf = (iso) => (typeof iso === 'string' && iso ? Date.parse(iso) : NaN);
// SQLite datetime('now') text: 'YYYY-MM-DD HH:MM:SS', UTC.
const seenAt = (s) => (typeof s === 'string' && s ? Date.parse(`${s.replace(' ', 'T')}Z`) : NaN);

function caretMates(warned) {
  const w = semver.parse(warned);
  if (!w) return () => false;
  if (w.major > 0) return (v) => v.major === w.major;
  if (w.minor > 0) return (v) => v.major === 0 && v.minor === w.minor;
  return () => false;
}

/** Whether `version` was in the latest packument this proxy observed; shared with `chaingate pin`. */
export function seenInLatest(history, version) {
  const newest = history.reduce((m, h) => { const t = seenAt(h.last_seen_at); return Number.isNaN(t) ? m : Math.max(m, t); }, -Infinity);
  const h = history.find((x) => x.version === version);
  return Boolean(h) && seenAt(h.last_seen_at) >= newest - SEEN_SLACK_MS;
}

export function lastVersionWithoutSignal(db, packageName, version, { settledMs = SETTLED_MS, maxCandidates = 25 } = {}) {
  const history = db.getHistory(packageName);
  const warned = history.find((h) => h.version === version);
  const warnedAt = timeOf(warned?.published_at);
  if (!warned || Number.isNaN(warnedAt) || !semver.valid(version)) return null;
  // reduce, not Math.max(...spread): a package can list tens of thousands of versions
  const newestSeen = history.reduce((m, h) => { const t = seenAt(h.last_seen_at); return Number.isNaN(t) ? m : Math.max(m, t); }, -Infinity);
  const mate = caretMates(version);
  const candidates = history
    .map((h) => ({ h, v: semver.parse(h.version) }))
    .filter(({ h, v }) => v && v.prerelease.length === 0 && mate(v) && semver.lt(v, version)
      && timeOf(h.published_at) <= warnedAt - settledMs
      && seenAt(h.last_seen_at) >= newestSeen - SEEN_SLACK_MS)
    .sort((a, b) => semver.rcompare(a.v, b.v))
    .slice(0, maxCandidates);
  for (const { h } of candidates) {
    const a = db.getApplicableDecision(packageName, h.version, { overrideLive: false });
    const latest = a.latest;
    if (!latest || a.block || (a.pending && (a.pending.length ?? a.pending.size)) || latest.disposition === 'BLOCK') continue;
    const rows = latest.gates_fired;
    if (isOverrideRow(rows)) continue;
    const c = classify(rows);
    if (c.named.length || c.facts.length || !namedRuleChecked(rows)) continue;          // any named rule determinate
    return h.version;
  }
  return null;
}

export default { lastVersionWithoutSignal, seenInLatest, SETTLED_MS };
