// 0.1.4 group 3b (D-N4): the process's cache of DEPENDENCY packuments that N1h judges -- filled at tarball time by the proxy
// (bounded fetch, §18.20 item 2), read by the `dependency-hooks` runner gate. Per target name: a summary of the served
// document (each version's manifest facts N1h needs, and the dist-tags) or the reason it could not be read. 10 minutes per
// entry; at most 500 entries (least recently used dropped).
import { pyTruthy } from '../seed/v3/packument.js';

export const TTL_MS = 10 * 60_000;
export const MAX_ENTRIES = 500;
const HOOKS = ['preinstall', 'install', 'postinstall'];

const cache = new Map();                 // name -> { at, summary | null, why | null }
const stats = { hits: 0, misses: 0, stored: 0, evicted: 0 };
let clock = Date.now;

/** The facts of one manifest N1h reads (validate.py-style truthiness for hooks; gypfile strictly true, as counted). */
export function manifestFacts(m) {
  const s = m && typeof m === 'object' && m.scripts && typeof m.scripts === 'object' && !Array.isArray(m.scripts) ? m.scripts : {};
  return { hooks: HOOKS.filter((k) => pyTruthy(s[k])), gypfile: Boolean(m && typeof m === 'object' && m.gypfile === true) };
}

function summarize(doc) {
  const versions = {};
  const vs = doc && typeof doc === 'object' && doc.versions && typeof doc.versions === 'object' ? doc.versions : {};
  for (const [v, m] of Object.entries(vs)) versions[v] = manifestFacts(m);
  const tags = doc && typeof doc['dist-tags'] === 'object' && doc['dist-tags'] ? { ...doc['dist-tags'] } : {};
  return { versions, 'dist-tags': tags };
}

/** Store a served document (or null with the reason it could not be read). */
export function setDependencyDoc(name, doc, why = null) {
  cache.delete(name);
  cache.set(name, { at: clock(), summary: doc ? summarize(doc) : null, why: doc ? null : (why ?? 'not readable') });
  stats.stored += 1;
  while (cache.size > MAX_ENTRIES) { cache.delete(cache.keys().next().value); stats.evicted += 1; }
}

/** { summary } | { why } | undefined (never fetched, or expired). */
export function getDependency(name) {
  const e = cache.get(name);
  if (!e || clock() - e.at > TTL_MS) { if (e) cache.delete(name); stats.misses += 1; return undefined; }
  cache.delete(name); cache.set(name, e);                     // least recently used last
  stats.hits += 1;
  return e.summary ? { summary: e.summary } : { why: e.why };
}

export function resetDependencyCache({ now = Date.now } = {}) {
  cache.clear(); clock = now;
  for (const k of Object.keys(stats)) stats[k] = 0;
}

export function dependencyCacheStats() {
  return { entries: cache.size, ttl_ms: TTL_MS, max_entries: MAX_ENTRIES, ...stats };
}

export default { setDependencyDoc, getDependency, resetDependencyCache, dependencyCacheStats, manifestFacts, TTL_MS, MAX_ENTRIES };
