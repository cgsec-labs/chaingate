// 0.1.4 group 3c (D-M1, D-M3, D-M4): MC -- the tarball's package.json hooks against the registry manifest's, as counted
// (validate.py tar_checks: `MC = hooks(tarball package.json) != hooks(manifest)`, the hook DICTS with their values; a tarball
// with no root package.json reads as {}). The registry manifest's hooks come from an in-memory map that every observation
// fills; the outcome is written as an `install-manifest-mismatch` row when the download's stream has ended.
import { pyTruthy } from '../seed/v3/packument.js';

export const GATE = 'install-manifest-mismatch';
export const MAX_PACKAGES = 2000;
const HOOKS = ['preinstall', 'install', 'postinstall'];
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);

/** validate.py `hooks`: { hook: value } for the truthy install hooks of a manifest (or package.json). */
export function hookDict(man) {
  const s = isObj(man) ? man.scripts : null;
  const out = {};
  if (!isObj(s)) return out;
  for (const k of HOOKS) if (pyTruthy(s[k])) out[k] = s[k];
  return out;
}

export const MAX_DEPTH = 64;
class TooDeep extends Error {}
const canonical = (x, d = 0) => {
  if (d > MAX_DEPTH) throw new TooDeep('a hook value nested too deeply');
  return Array.isArray(x) ? `[${x.map((y) => canonical(y, d + 1)).join(',')}]`
    : isObj(x) ? `{${Object.keys(x).sort().map((k) => `${JSON.stringify(k)}:${canonical(x[k], d + 1)}`).join(',')}}` : JSON.stringify(x);
};
export const manifestMismatch = (th, mh) => canonical(th) !== canonical(mh);

// ---- the registry manifests' hooks, per package, as last observed by this process (D-M3) ----
const observed = new Map();               // package -> { versions: Set, hooked: Map(version -> dict) }; LRU order
export function rememberManifestHooks(pkg, versions) {
  if (!isObj(versions)) return;
  const hooked = new Map();
  for (const [v, m] of Object.entries(versions)) { const d = hookDict(m); if (Object.keys(d).length) hooked.set(v, d); }
  observed.delete(pkg);
  observed.set(pkg, { versions: new Set(Object.keys(versions)), hooked });
  while (observed.size > MAX_PACKAGES) observed.delete(observed.keys().next().value);
}
/** The registry manifest's hook dict for pkg@version, or undefined when not at hand. */
export function manifestHooksFor(pkg, version) {
  const e = observed.get(pkg);
  if (!e || !e.versions.has(version)) return undefined;
  observed.delete(pkg); observed.set(pkg, e);
  return e.hooked.get(version) ?? {};
}
export function forgetManifestHooks() { observed.clear(); }

// The entry name is publisher text: control and bidi characters stripped, capped at 80 characters (as G4 D-C1).
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g;
const shownName = (n) => { const x = String(n ?? '').replace(UNSAFE, ''); return x.length > 80 ? `${x.slice(0, 80)}…` : x; };
const keys = (d) => Object.keys(d).sort().join(', ') || 'no install hook';

/** One view's hook dict: { th } | { skip } | { unread } (a package.json that does not parse: npm cannot install from it). */
function viewHooks(buf) {
  let pj = {};
  if (buf) {
    // a UTF-8 BOM is dropped first, as Python's json.loads(bytes) and npm both do (G3 dated note 5.2)
    const text = buf.toString('utf8').replace(/^\uFEFF/, '');
    try { pj = JSON.parse(text); } catch { return { unread: true }; }
  }
  return { th: hookDict(pj) };
}

/**
 * The MC row for a finished walk (D-M1, D-M4). The POSIX view (the counted read) decides first, with its detail unchanged;
 * then each other file-system view that installs a different entry (release audit R2): a mismatch there is a WARN naming
 * the platforms and the entry.
 */
export function mcRow(walk, mh) {
  if (mh === undefined) return { gate: GATE, result: 'SKIP', detail: 'not checked: no registry manifest at hand' };
  if (!walk.ok) return { gate: GATE, result: 'SKIP', detail: `not checked: ${walk.reason}` };
  const groups = Array.isArray(walk.views) && walk.views.length ? walk.views
    : [{ platforms: ['Linux', 'macOS', 'Windows'], packageJson: walk.packageJson ?? null, name: null }];
  const primary = groups.find((g) => g.platforms.includes('Linux')) ?? groups[0];
  for (const g of [primary, ...groups.filter((x) => x !== primary)]) {
    const v = viewHooks(g.packageJson);
    const where = g === primary ? '' : ` as installed on ${g.platforms.join(' and ')} (entry ${shownName(g.name)})`;
    if (v.unread) {
      if (g === primary) return { gate: GATE, result: 'SKIP', detail: 'not checked: the tarball package.json does not parse' };
      continue;                                      // npm on that platform cannot read it, so it runs none of its hooks
    }
    let differ;
    try { differ = manifestMismatch(v.th, mh); } catch (err) {
      if (err instanceof TooDeep) return { gate: GATE, result: 'SKIP', detail: `not checked: ${err.message}${where}` };
      throw err;
    }
    if (!differ) continue;
    const same = keys(v.th) === keys(mh);
    return { gate: GATE, result: 'WARN',
      detail: same ? `tarball package.json${where} declares ${keys(v.th)} with different commands than the registry entry`
        : `tarball package.json${where} declares ${keys(v.th)}; the registry entry declares ${keys(mh)}` };
  }
  return { gate: GATE, result: 'ALLOW', detail: 'tarball package.json install hooks match the registry entry' };
}

const aggregate = (results) => (results.some((r) => r?.result === 'BLOCK') ? 'BLOCK'
  : (results.some((r) => r?.result === 'WARN') ? 'WARN' : 'ALLOW'));

/** Write the MC row into one new decision row when the outcome changed. 'wrote' | 'raced' | false. */
export function recordMc({ db, pkg, version, latest, row }) {
  const rows = Array.isArray(latest?.gates_fired) ? latest.gates_fired : [];
  const prev = rows.find((g) => g && g.gate === GATE);
  if (prev && prev.result === row.result && prev.detail === row.detail) return false;
  const results = [...rows.filter((g) => !(g && g.gate === GATE)), row];
  const fresh = db.getLatestNonOverrideDecision(pkg, version);
  if (fresh && fresh.id !== latest.id) return 'raced';
  db.insertGateDecision(pkg, version, aggregate(results), results);
  return 'wrote';
}

/** Whether the stored row already holds a determinate MC outcome (tarballs are immutable per version: no second walk). */
export const mcDeterminate = (latest) => (Array.isArray(latest?.gates_fired) ? latest.gates_fired : [])
  .some((g) => g && g.gate === GATE && (g.result === 'WARN' || g.result === 'ALLOW'));

export default { hookDict, manifestMismatch, rememberManifestHooks, manifestHooksFor, forgetManifestHooks, mcRow, recordMc, mcDeterminate, GATE };
