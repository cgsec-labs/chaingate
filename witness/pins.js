// 0.1.4 group 2d (O1, D-U4..D-U6): a user's pins. `chaingate pin <pkg>@<K>` withholds every version of <pkg> in K's caret
// class whose SemVer precedence is above K (prereleases included) until `chaingate unpin`. A pin is a serving overlay read
// live from the `pins` table; it is never a stored decision (a stored user-pin BLOCK could never be cleared by C2).
import semver from 'semver';

/** K's caret class: "<major>" for major >= 1, "0.<minor>" for 0.y (y >= 1); null for 0.0.z and invalid versions. */
export function caretClass(version) {
  const v = typeof version === 'string' ? semver.parse(version) : null;
  if (!v) return null;
  if (v.major > 0) return String(v.major);
  if (v.minor > 0) return `0.${v.minor}`;
  return null;
}

/** How a class is shown: "1.x", "0.3.x". */
export const classLabel = (classKey) => `${classKey}.x`;

/** The pin that withholds `version` of `pkg`, or null. */
export function withheldBy(pins, pkg, version) {
  const cls = caretClass(version);
  if (!cls || !Array.isArray(pins)) return null;
  for (const p of pins) {
    if (p && p.package_name === pkg && p.class_key === cls && semver.valid(p.k_version) && semver.gt(version, p.k_version)) return p;
  }
  return null;
}

/**
 * The proxy's pin set (D-U6): read from the database and re-read when PRAGMA data_version changes (a commit by another
 * connection, i.e. the CLI). A failed read keeps the last good set and is logged once per failure transition: a pin-read
 * failure never refuses an install and never drops a pin silently.
 */
export function createPinSet(db, { log } = {}) {
  let byPackage = new Map();
  let count = 0;
  let seenVersion = null;
  let generation = 0;
  let lastError = null;
  const fail = (err) => {
    if (lastError === null) log?.warn?.(`[pins] could not read the pins (${err.message}); keeping the last good set (${count})`);
    lastError = err.message;
  };
  function refresh() {
    let v;
    try { v = db.dataVersion(); } catch (err) { fail(err); return; }
    if (v === seenVersion && lastError === null) return;
    try {
      const rows = db.listPins();
      const next = new Map();
      for (const r of rows) next.set(r.package_name, [...(next.get(r.package_name) ?? []), r]);
      byPackage = next;
      count = rows.length;
      seenVersion = v;
      generation += 1;
      if (lastError !== null) log?.warn?.(`[pins] reading the pins works again (${count})`);
      lastError = null;
    } catch (err) { fail(err); }
  }
  return {
    forPackage(name) { refresh(); return byPackage.get(name) ?? []; },
    stats() { return { enforced: true, count, generation, last_error: lastError }; },
  };
}

export default { caretClass, classLabel, withheldBy, createPinSet };
