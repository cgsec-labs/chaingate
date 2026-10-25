// N1h -- dependency-hooks, a NAMED gate in cft-policy-1.2. The measured plain rule, ported exactly from the measurement
// scripts (judged fields, added dependencies, target, eligibility, STUB, NONREG; resolution with node-semver):
//
//   R fires iff an ADDED dependency D -- in R's judged fields (dependencies, optionalDependencies, peerDependencies not
//   marked optional) and absent from the judged fields of every ELIGIBLE earlier version (published before R; not a
//   takedown stub; not npm-published) -- with a REGISTRY spec (an npm: alias judges its target; git/URL/file/link/owner-repo
//   are not judged) RESOLVES (a range: maxSatisfying, no prerelease, loose; a dist-tag: the SERVED dist-tags) to a
//   version declaring a truthy preinstall/install/postinstall, or gypfile === true.
//   Outcome: WARN if any added dependency fires; else SKIP (not evaluable) if any is not evaluable; else ALLOW.
//
// The dependency's packument is not in the parent's; the runner judges from the process cache (gates/dependency-cache.js)
// and records the dependencies it could not judge yet as `pending`. The proxy fetches those at TARBALL time, bounded, and
// writes the judged row; the store keeps the last judgement over a later pending row.
import semver from 'semver';
import { getDependency, manifestFacts } from './dependency-cache.js';

export const MAX_ADDED = 10;
const GATE = 'dependency-hooks';
const STUB = /^0\.0\.\d+-security(\.\d+)?$/;
const NONREG = /^(git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:|[\w.-]+\/[\w.-]+(#.*)?$)/;
const TAG = /^[A-Za-z][\w.-]*$/;
const FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies'];
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);

/** name -> { spec, field } over the judged fields (first field wins; peers marked optional excluded; specs trimmed). */
export function judgedFields(man) {
  const out = {};
  if (!isObj(man)) return out;
  const meta = isObj(man.peerDependenciesMeta) ? man.peerDependenciesMeta : {};
  for (const field of FIELDS) {
    const d = man[field];
    if (!isObj(d)) continue;
    for (const [n, s] of Object.entries(d)) {
      if (field === 'peerDependencies' && isObj(meta[n]) && meta[n].optional === true) continue;
      if (!Object.hasOwn(out, n)) out[n] = { spec: String(s).trim(), field };
    }
  }
  return out;
}

/** Eligible as an EARLIER version: not a takedown stub, not published by npm itself. */
export function isEligible(man, version) {
  if (STUB.test(version || '')) return false;
  const u = isObj(man) && isObj(man._npmUser) ? man._npmUser : {};
  return !(String(u.email || '').toLowerCase() === 'npm@npmjs.com' || u.name === 'npm');
}

// One index per packument (memoised per versions/time object) -- each version's time and judged fields,
// the earliest time each name appears among ELIGIBLE versions, and the two earliest eligible times -- so a version costs
// O(its own dependencies), not O(every version).
const indexes = new WeakMap();
function indexFor(versions, times) {
  let byTimes = indexes.get(versions);
  if (byTimes?.has(times)) return byTimes.get(times);
  const time = new Map(); const fields = new Map(); const firstSeen = new Map(); const eligible = [];
  for (const [v, m] of Object.entries(versions)) {
    const f = judgedFields(m);
    fields.set(v, f);
    const t = typeof times[v] === 'string' ? Date.parse(times[v]) : NaN;
    if (Number.isNaN(t)) continue;
    time.set(v, t);
    if (!isEligible(m, v)) continue;
    eligible.push([t, v]);
    for (const n of Object.keys(f)) if (!firstSeen.has(n) || t < firstSeen.get(n)) firstSeen.set(n, t);
  }
  let a = null; let b = null;                              // the two earliest eligible [time, version]
  for (const e of eligible) { if (!a || e[0] < a[0]) { b = a; a = e; } else if (!b || e[0] < b[0]) b = e; }
  const idx = { time, fields, firstSeen, earliest: [a, b] };
  if (!byTimes) { byTimes = new WeakMap(); indexes.set(versions, byTimes); }
  byTimes.set(times, idx);
  return idx;
}

/** The added dependencies of `version` ([{ name, spec, field }]), or null when it has no time or no eligible earlier version. */
export function addedDeps(versions, times, version) {
  if (!isObj(versions) || !Object.hasOwn(versions, version) || !isObj(times)) return null;
  const idx = indexFor(versions, times);
  const tR = idx.time.get(version);
  if (tR === undefined) return null;
  const [a, b] = idx.earliest;
  const firstOther = a && a[1] !== version ? a[0] : (b ? b[0] : Infinity);
  if (!(firstOther < tR)) return null;                     // no eligible earlier version
  // added iff no eligible version declared the name before t_R (the counted strict <; R's own entry is at t_R)
  return Object.entries(idx.fields.get(version)).filter(([n]) => !(idx.firstSeen.get(n) < tR))
    .map(([name, { spec, field }]) => ({ name, spec, field }));
}

/** { kind: 'registry', target, spec } | { kind: 'd2' }. */
export function specTarget(name, spec) {
  if (spec.startsWith('npm:')) {
    const rest = spec.slice(4);
    const at = rest.lastIndexOf('@');
    return at > 0 ? { kind: 'registry', target: rest.slice(0, at), spec: rest.slice(at + 1) || 'latest' }
      : { kind: 'registry', target: rest, spec: 'latest' };
  }
  if (NONREG.test(spec)) return { kind: 'd2' };
  return { kind: 'registry', target: name, spec: spec || 'latest' };
}

/** { resolved } | { why }, over a served document (raw or cache summary). */
export function resolveSpec(doc, spec) {
  const versions = isObj(doc?.versions) ? Object.keys(doc.versions) : [];
  const valid = versions.filter((v) => semver.valid(v));
  if (semver.validRange(spec, { loose: true })) {
    const r = semver.maxSatisfying(valid, spec, { includePrerelease: false, loose: true });
    return r ? { resolved: r } : { why: 'no version satisfies the range' };
  }
  if (TAG.test(spec)) {
    const v = isObj(doc?.['dist-tags']) ? doc['dist-tags'][spec] : undefined;
    return typeof v === 'string' && versions.includes(v) ? { resolved: v } : { why: `dist-tag ${spec} not served` };
  }
  return { why: 'spec not parsed' };
}

/** Whether a resolved manifest (or its cached facts) runs install scripts. */
export function fires(manOrFacts) {
  const f = manOrFacts && Array.isArray(manOrFacts.hooks) && typeof manOrFacts.gypfile === 'boolean' ? manOrFacts : manifestFacts(manOrFacts);
  return f.hooks.length > 0 || f.gypfile;
}

const label = (f) => [...f.hooks, ...(f.gypfile ? ['gypfile'] : [])].join(', ');

/**
 * Judge a list of registry added dependencies ({ name, target, spec }) from the cache (`lookup`). Returns the row.
 * `at`: the judgement's clock, named in the detail (a binding, not a claim about now).
 */
export function judge(added, { lookup = getDependency, at = new Date().toISOString(), unjudgeable = [] } = {}) {
  const fired = []; const ne = [...unjudgeable]; const pending = []; const clean = [];
  for (const d of added) {
    const c = lookup(d.target);
    if (c === undefined) { pending.push(d); continue; }
    if (!c.summary) { ne.push(`${d.name} (${c.why})`); continue; }
    const r = resolveSpec(c.summary, d.spec);
    if (!r.resolved) { ne.push(`${d.name} (${r.why})`); continue; }
    const f = c.summary.versions[r.resolved];
    if (fires(f)) fired.push(`${d.target}@${r.resolved} (${label(f)})`);
    else clean.push(`${d.target}@${r.resolved}`);
  }
  const base = { gate: GATE, added, ...(unjudgeable.length ? { unjudgeable } : {}) };
  if (fired.length) return { ...base, result: 'WARN', detail: `adds ${fired.join('; ')}: an added dependency runs install scripts (judged ${at})` };
  if (pending.length) {
    return { ...base, result: 'SKIP', pending,
      detail: `${pending.length} added dependenc${pending.length === 1 ? 'y' : 'ies'} not yet fetched (judged at download)` };
  }
  if (ne.length) return { ...base, result: 'SKIP', detail: `not evaluable: ${ne.join('; ')} (judged ${at})` };
  return { ...base, result: 'ALLOW', detail: clean.length ? `added dependencies run no install scripts: ${clean.join(', ')} (judged ${at})`
    : 'adds no registry dependency' };
}

export default {
  name: GATE,
  evaluate(input) {
    const added = addedDeps(input?.rawVersions, input?.rawTimes, input?.version);
    if (added === null) return { gate: GATE, result: 'SKIP', detail: 'not evaluable: no publication time, or no eligible earlier version' };
    const registry = []; const unjudgeable = [];
    for (const d of added) {
      const t = specTarget(d.name, d.spec);
      if (t.kind !== 'registry') continue;
      // a name/spec too long to carry is NOT EVALUABLE (never dropped, never clean)
      const tooLong = d.name.length > 214 || t.target.length > 214 ? 'name' : (t.spec.length > 256 ? 'spec' : null);
      if (tooLong) {
        const shown = d.name.replace(/[\u0000-\u001f\u007f-\u009f]/g, '').slice(0, 60);
        unjudgeable.push(`${shown}${d.name.length > 60 ? '…' : ''} (${tooLong} too long to judge)`);
      }
      else registry.push({ name: d.name, target: t.target, spec: t.spec });
    }
    registry.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    if (registry.length > MAX_ADDED) {
      return { gate: GATE, result: 'SKIP', detail: `more than ${MAX_ADDED} added dependencies; not judged (${registry.length})` };
    }
    return judge(registry, { unjudgeable: unjudgeable.slice(0, MAX_ADDED) });
  },
};
