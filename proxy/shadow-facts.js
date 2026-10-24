// 0.1.5 shadow facts (operator ruling R11 2026-10-24, "Shadow first"): the triage noise-reduction rules the runtime computes
// (chaingate-ops af922e7, docs/design/triage-noise-rules-20261023.md, section B), recorded once per served version beside its entry
// facts and shown in `why` and `report`. RECORD ONLY: nothing here is a runner row, so no verdict, tier or notice depends on it; a
// re-tier on any of them is a later ruling, after the first weeks live and the section D replay. Kept outside proxy/static-checks.js,
// which mirrors recon byte for byte.
//   rule 3   the served version is not the `latest` dist-tag, and which tags point at it (the registry's own tags, before any rewrite);
//   rule 5   transition half: each named sign on this version, and whether it was already on the version this proxy served before;
//   rule 8   packument half: the publisher is a known owner (a listed maintainer, an earlier publisher, the majority publisher). The
//            token-delta half is S7's gain set, already on S7's row;
//   8b       the size change against the version served before, by file class: docs, source maps, declarations, a second module
//            format (only when this version ships both a CommonJS and an ES module form), other files. The root package.json is
//            not counted (its version field always changes).
// Rule 8's fourth form ("maintains other packages already in scope") needs state across packages and is not computed here.

export const SHADOW_FACTS_VERSION = 'shadow-facts-1.0';
export const SHADOW_NOTE = 'recorded only: no verdict, tier or notice depends on it (operator ruling R11)';
const BASIS = 'the version this proxy served before';
const NOT_AT_HAND = 'the package metadata is not at hand';

// ---- the package metadata a fact reads: the registry's dist-tags, maintainers and each version's publisher and time, remembered
// where the metadata is observed (as manifest-check remembers the hook map); least recently used dropped past MAX_PACKAGES
export const MAX_PACKAGES = 500;
const memo = new Map();
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
// publisher text: control and bidi characters stripped, capped at 80 characters (as manifest-check's entry names)
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g;
const shown = (n) => { const x = String(n ?? '').replace(UNSAFE, ''); return x.length > 80 ? `${x.slice(0, 80)}...` : x; };
const emailKey = (e) => (typeof e === 'string' && e.trim() ? e.trim().toLowerCase() : null);
const nameKey = (n) => (typeof n === 'string' && n.trim() ? `name:${n.trim()}` : null);

export function rememberPackumentFacts(pkg, doc) {
  if (!isObj(doc)) return;
  const tags = {};
  if (isObj(doc['dist-tags'])) for (const [t, v] of Object.entries(doc['dist-tags'])) if (typeof v === 'string') tags[t] = v;
  const maint = new Set();
  for (const m of Array.isArray(doc.maintainers) ? doc.maintainers : []) {
    if (!isObj(m)) continue;
    const e = emailKey(m.email); const n = nameKey(m.name);
    if (e) maint.add(e);
    if (n) maint.add(n);
  }
  const time = isObj(doc.time) ? doc.time : {};
  const pubs = new Map();
  for (const [v, man] of Object.entries(isObj(doc.versions) ? doc.versions : {})) {
    const u = isObj(man) && isObj(man._npmUser) ? man._npmUser : null;
    const e = u ? emailKey(u.email) : null; const n = u ? nameKey(u.name) : null;
    pubs.set(v, { k: e ?? n, e, n, name: u && typeof u.name === 'string' ? shown(u.name) : null,
      t: typeof time[v] === 'string' ? Date.parse(time[v]) : NaN });
  }
  memo.delete(pkg);
  memo.set(pkg, { tags, maint, pubs });
  while (memo.size > MAX_PACKAGES) memo.delete(memo.keys().next().value);
}
/** The remembered metadata of pkg, or undefined. */
export function packumentFactsFor(pkg) {
  const m = memo.get(pkg);
  if (!m) return undefined;
  memo.delete(pkg); memo.set(pkg, m);
  return m;
}
export function forgetPackumentFacts() { memo.clear(); }

// ---- rule 3
export function distTagFact(m, version) {
  if (!m) return { state: 'not-known', why: NOT_AT_HAND };
  const latest = typeof m.tags.latest === 'string' ? m.tags.latest : null;
  const tags = Object.keys(m.tags).filter((t) => m.tags[t] === version).sort();
  return { state: 'known', latest, tags, not_latest: latest !== version };
}

// ---- rule 8, packument half
export function knownOwnerFact(m, version) {
  if (!m) return { state: 'not-known', why: NOT_AT_HAND };
  const p = m.pubs.get(version);
  if (!p) return { state: 'not-known', why: 'the version is not in the package metadata' };
  if (!p.k) return { state: 'not-known', why: 'no publisher recorded for this version' };
  const earlier = Number.isFinite(p.t) ? [...m.pubs.values()].filter((x) => Number.isFinite(x.t) && x.t < p.t) : [];
  const byPublisher = earlier.filter((x) => x.k === p.k).length;
  const listed = Boolean((p.e && m.maint.has(p.e)) || (p.n && m.maint.has(p.n)));
  const earlierPublisher = byPublisher > 0;
  const majority = earlier.length > 0 && byPublisher * 2 > earlier.length;
  return { state: 'known', publisher: p.name ?? 'unnamed', known_owner: listed || earlierPublisher || majority, listed_maintainer: listed,
    earlier_publisher: earlierPublisher, majority_publisher: majority, earlier_versions: earlier.length, by_publisher: byPublisher };
}

// ---- 8b: file classes and the per-version size tally (fed by the tar walker's onFile, constant memory)
const DOC_NAME = /^(readme|changelog|changes|history|license|licence|authors|contributors|contributing|notice|copying)(\.(md|markdown|txt|rst|html))?$/;
const DOC_EXT = /\.(md|markdown|mdx|rst|txt)$/;
export function fileClass(p) {
  const x = String(p).toLowerCase();
  if (x === 'package.json') return 'manifest';
  if (x.endsWith('.map')) return 'maps';
  if (/\.d\.(ts|mts|cts)$/.test(x)) return 'types';
  const segs = x.split('/'); const base = segs[segs.length - 1]; const dirs = segs.slice(0, -1);
  if (dirs[0] === 'docs' || dirs[0] === 'doc' || DOC_EXT.test(base) || DOC_NAME.test(base)) return 'docs';
  if (base.endsWith('.cjs') || dirs.some((d) => d === 'cjs' || d === 'commonjs')) return 'cjs';
  if (base.endsWith('.mjs') || dirs.some((d) => d === 'esm' || d === 'es' || d === 'mjs')) return 'esm';
  return 'other';
}
const CLASSES = ['manifest', 'docs', 'maps', 'types', 'cjs', 'esm', 'other'];
export function createShapeTally() {
  const by = Object.fromEntries(CLASSES.map((c) => [c, 0])); let files = 0;
  return {
    onFile(p, n) {
      if (typeof p !== 'string' || !Number.isFinite(n) || n < 0) return;
      by[fileClass(p)] += n; files += 1;
    },
    result: () => ({ files, by: { ...by } }),
  };
}
const validShape = (s) => isObj(s) && isObj(s.by) && CLASSES.every((c) => Number.isFinite(s.by[c]));

export function sizeAttributionFact(cur, pred) {
  if (!pred) return { state: 'not-applicable' };
  if (!validShape(cur)) return { state: 'not-checked', why: 'this archive was not read' };
  if (!validShape(pred.shape)) return { state: 'not-checked', vs: pred.version, why: `no file sizes stored for ${pred.version}` };
  const d = Object.fromEntries(CLASSES.map((c) => [c, cur.by[c] - pred.shape.by[c]]));
  const dual = cur.by.cjs > 0 && cur.by.esm > 0;
  const by = { docs: d.docs, maps: d.maps, types: d.types, second_format: dual ? d.cjs + d.esm : 0, other: d.other + (dual ? 0 : d.cjs + d.esm) };
  const attributable = by.docs !== 0 || by.maps !== 0 || by.types !== 0 || by.second_format !== 0;
  return { state: 'known', vs: pred.version, delta_bytes: by.docs + by.maps + by.types + by.second_format + by.other, by,
    all_attributed: by.other === 0 && attributable };
}

// ---- rule 5, transition half: pred = { version, named } (named null when the predecessor has no stored decision), or null
export function transitionFact(curNamed, pred) {
  if (!pred) return { state: 'not-applicable' };
  if (!Array.isArray(pred.named)) return { state: 'not-known', vs: pred.version, why: `no stored decision for ${pred.version}` };
  const signs = (Array.isArray(curNamed) ? curNamed : []).map((g) => ({ gate: g, new: !pred.named.includes(g) }));
  return { state: 'known', vs: pred.version, signs, all_not_new: signs.length > 0 && signs.every((s) => !s.new) };
}

/** All four facts of one served version. predecessor: { version, shape, named } of the version served before, or null. */
export function shadowFactsOf({ memo: m, version, shape, predecessor, named }) {
  return { version: SHADOW_FACTS_VERSION, dist_tag: distTagFact(m, version), known_owner: knownOwnerFact(m, version),
    transition: transitionFact(named, predecessor ? { version: predecessor.version, named: predecessor.named } : null),
    size: sizeAttributionFact(shape, predecessor ? { version: predecessor.version, shape: predecessor.shape } : null) };
}

// ---- what `why` and `report` print
const signed = (n) => (n > 0 ? `+${n}` : String(n));
const COLD = 'no earlier version served by this proxy';
export function shadowLines(f) {
  const out = [];
  const t = f?.dist_tag;
  if (t?.state === 'known') {
    out.push(!t.not_latest ? 'dist-tag: the latest tag'
      : (t.tags.length ? `dist-tag: not the latest tag (latest is ${t.latest ?? 'not set'}); tagged ${t.tags.join(', ')}`
        : `dist-tag: no tag points at it (latest is ${t.latest ?? 'not set'})`));
  } else out.push(`dist-tag: not known (${t?.why ?? 'not recorded'})`);
  const o = f?.known_owner;
  if (o?.state === 'known') {
    const share = `published ${o.by_publisher} of ${o.earlier_versions} earlier versions`;
    out.push(o.known_owner
      ? `publisher ${o.publisher}: a known owner (${[o.listed_maintainer && 'a listed maintainer', o.earlier_publisher && 'an earlier publisher', share].filter(Boolean).join('; ')})`
      : `publisher ${o.publisher}: not a known owner (not a listed maintainer, not an earlier publisher; ${share})`);
  } else out.push(`publisher: not known (${o?.why ?? 'not recorded'})`);
  const r = f?.transition;
  if (r?.state === 'known') {
    out.push(`named signs vs ${r.vs} (${BASIS}): ${r.signs.length
      ? r.signs.map((s) => (s.new ? `${s.gate} new` : `${s.gate} not new since ${r.vs}`)).join('; ') : 'none on this version'}`);
  } else out.push(r?.state === 'not-applicable' ? `named signs: not applicable (${COLD})` : `named signs: not known (${r?.why ?? 'not recorded'})`);
  const s = f?.size;
  if (s?.state === 'known') {
    const parts = [['other files', s.by.other], ['docs', s.by.docs], ['source maps', s.by.maps], ['declarations', s.by.types],
      ['second module format', s.by.second_format]].filter(([, n]) => n !== 0).map(([w, n]) => `${w} ${signed(n)}`);
    out.push(parts.length
      ? `size change vs ${s.vs} (${BASIS}): ${signed(s.delta_bytes)} bytes, ${s.all_attributed ? 'all' : 'not all'} in docs, source maps, `
        + `declarations or a second module format (${parts.join(', ')})`
      : `size change vs ${s.vs} (${BASIS}): none`);
  } else out.push(s?.state === 'not-applicable' ? `size change: not applicable (${COLD})` : `size change: not checked (${s?.why ?? 'not recorded'})`);
  return out;
}

/** Whether a fact would have spoken on a triage card: not the latest tag, not a known owner, a sign not new, a size change all docs. */
export function notable(f) {
  return Boolean((f?.dist_tag?.state === 'known' && f.dist_tag.not_latest)
    || (f?.known_owner?.state === 'known' && !f.known_owner.known_owner)
    || (f?.transition?.state === 'known' && f.transition.signs.some((s) => !s.new))
    || (f?.size?.state === 'known' && f.size.all_attributed));
}

export default { SHADOW_FACTS_VERSION, SHADOW_NOTE, MAX_PACKAGES, rememberPackumentFacts, packumentFactsFor, forgetPackumentFacts,
  distTagFact, knownOwnerFact, fileClass, createShapeTally, sizeAttributionFact, transitionFact, shadowFactsOf, shadowLines, notable };
