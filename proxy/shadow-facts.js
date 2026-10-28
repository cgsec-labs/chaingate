// 0.1.5 shadow facts: the noise-reduction rules the runtime computes, recorded once per served version beside its entry
// facts and shown in `why` and `report`. RECORD ONLY: nothing here is a runner row, so no verdict, tier or notice depends on it;
// any re-tier on them is a later decision, after the first weeks live. Kept outside proxy/static-checks.js, which mirrors the
// offline scanner byte for byte.
//   rule 3   the served version is not the `latest` dist-tag, and which tags point at it (the registry's own tags, before any rewrite);
//   rule 5   transition half: each named sign on this version, and whether it was already on the version this proxy served before;
//   rule 8   packument half: the publisher is a known owner (a listed maintainer, an earlier publisher, the majority publisher). The
//            token-delta half is S7's gain set, already on S7's row;
//   8b       the size change against the version served before, by file class: docs, source maps, declarations, a second module
//            format (only when this version ships both a CommonJS and an ES module form), other files. The root package.json is
//            not counted (its version field always changes).
// Rule 8's fourth form ("maintains other packages already in scope") needs state across packages and is not computed here.
// The repository claim (repoClaimFact) is recorded for an ARMED version only: the build workflow repository its registry attestation
// bundle names, against its `repository` field in the package metadata. The bundle's signature is not verified.

export const SHADOW_FACTS_VERSION = 'shadow-facts-1.0';
export const SHADOW_NOTE = 'recorded only: no verdict, tier or notice depends on it';
/** The plain notes the proxy stores and shows in place of the two notes the offline scanner's facts block carries (that block stays byte for byte). */
const STATIC_FACTS_NOTE = 'recorded only: no outcome, tier or notice depends on these facts; a fact is read against the file, never a verdict';
const EXCLUDED_PATHS_NOTE = 'lines with a hit, over each file\'s read window: p2 = dynamic code (eval, Function, vm), p9 = a URL with a bare IP address';
/** A copy of a staticFactsOf result ({ facts, s5 }) with those two notes in plain words; nothing else changes. Null stays null. */
export function publicStaticFacts(x) {
  if (!x || typeof x !== 'object' || !x.facts || typeof x.facts !== 'object') return x ?? null;
  const facts = { ...x.facts, note: STATIC_FACTS_NOTE };
  if (facts.excluded_paths && typeof facts.excluded_paths === 'object') facts.excluded_paths = { ...facts.excluded_paths, note: EXCLUDED_PATHS_NOTE };
  return { ...x, facts };
}
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
  const pubs = new Map(); const repos = new Map();
  for (const [v, man] of Object.entries(isObj(doc.versions) ? doc.versions : {})) {
    const u = isObj(man) && isObj(man._npmUser) ? man._npmUser : null;
    const e = u ? emailKey(u.email) : null; const n = u ? nameKey(u.name) : null;
    pubs.set(v, { k: e ?? n, e, n, name: u && typeof u.name === 'string' ? shown(u.name) : null,
      t: typeof time[v] === 'string' ? Date.parse(time[v]) : NaN, att: isObj(man) && isObj(man.dist) && isObj(man.dist.attestations),
      repo: isObj(man) ? repoKeyOf(man.repository, repos) : null });
  }
  memo.delete(pkg);
  memo.set(pkg, { name: pkg, tags, maint, pubs });
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

// ---- the repository claim: the attestation bundle's build workflow repository vs this version's `repository` field
export const REPO_CLAIM_VERSION = 'repo-claim-1.0';
/** The bounds of the one attestation fetch per armed version: time, bytes, fetches in flight. */
export const REPO_CLAIM_LIMITS = Object.freeze({ timeoutMs: 5000, maxBytes: 1 << 20, maxInFlight: 4 });
const SHORT_HOST = { github: 'github.com', gitlab: 'gitlab.com', bitbucket: 'bitbucket.org' };
/** One key per repository: host/owner/repo, lower case, for every npm `repository` spelling (a string or { url }): git+, .git, ssh,
 *  scp-like, `github:o/r` and the bare `o/r` shorthand. GitHub keeps owner/repo (a /tree/... tail dropped); other hosts keep the path
 *  up to `/-/`. null when it is not a repository URL this proxy reads. The offline scanner reads them the same way. */
export function normRepoUrl(x) {
  let u = isObj(x) ? x.url : x; if (typeof u !== 'string') return null; u = u.trim(); if (!u || u.length > 500) return null;
  let m = /^(github|gitlab|bitbucket):([A-Za-z0-9][\w.-]*)\/([\w.-]+?)(?:\.git)?$/i.exec(u);
  if (m) return `${SHORT_HOST[m[1].toLowerCase()]}/${m[2]}/${m[3]}`.toLowerCase();
  m = /^([A-Za-z0-9][\w.-]*)\/([\w.-]+?)(?:\.git)?$/.exec(u); if (m) return `github.com/${m[1]}/${m[2]}`.toLowerCase();   // npm's bare shorthand is GitHub
  u = u.replace(/^git\+/i, ''); let host; let path;
  m = /^(?:(?:ssh|git):\/\/)?[\w.+-]+@([\w.-]+)[:/](.+)$/.exec(u);
  if (m) { host = m[1]; path = m[2].replace(/[?#].*$/, ''); } else {
    let url; try { url = new URL(u); } catch { return null; }
    if (!['https:', 'http:', 'git:', 'ssh:'].includes(url.protocol)) return null; host = url.hostname; path = url.pathname; }
  host = String(host).toLowerCase().replace(/^www\./, ''); const segs = path.split('/').filter(Boolean); if (segs.length < 2 || !/^[a-z0-9.-]+$/.test(host)) return null;
  const cut = host === 'github.com' ? 2 : (segs.indexOf('-') > 1 ? segs.indexOf('-') : segs.length);
  const parts = segs.slice(0, cut); parts[parts.length - 1] = parts[parts.length - 1].replace(/\.git$/i, '');
  if (parts.some((p) => p === '.' || p === '..' || !p)) return null;
  return `${host}/${parts.join('/')}`.toLowerCase();
}
// a version's repository as remembered: its key, '' when the field is there but not read, null when there is none; one string per
// distinct key within a package (most versions share one)
function repoKeyOf(x, repos) {
  if (x == null) return null;
  const k = normRepoUrl(x) ?? '';
  if (!repos.has(k)) repos.set(k, k);
  return repos.get(k);
}

const SLSA_V1 = 'https://slsa.dev/provenance/v1';
const SLSA_V02 = 'https://slsa.dev/provenance/v0.2';
const clip = (x, n) => (x.length > n ? x.slice(0, n) : x);
/** The repository the first SLSA provenance statement of an attestation bundle names (v1: the build workflow's repository; v0.2: the
 *  source address without its ref), clipped to 200 characters, or the reason there is none. The payload is decoded, never verified. */
export function attestationRepository(bytes) {
  let doc; try { doc = JSON.parse(Buffer.from(bytes).toString('utf8')); } catch { return { repository: null, reason: 'the bundle is not JSON' }; }
  const list = isObj(doc) && Array.isArray(doc.attestations) ? doc.attestations : [];
  if (!list.length) return { repository: null, reason: 'no attestations in the bundle' };
  for (const a of list) {
    const pt = isObj(a) && typeof a.predicateType === 'string' ? a.predicateType : null;
    if (pt !== SLSA_V1 && pt !== SLSA_V02) continue;
    let st = null;
    try { st = JSON.parse(Buffer.from(String(a.bundle?.dsseEnvelope?.payload), 'base64').toString('utf8')); } catch { st = null; }
    if (!isObj(st)) continue;
    const pred = isObj(st.predicate) ? st.predicate : {};
    let repo = null;
    if (pt === SLSA_V1) {
      const w = pred.buildDefinition?.externalParameters?.workflow;
      repo = isObj(w) && typeof w.repository === 'string' && w.repository ? w.repository : null;
    } else {
      const uri = pred.invocation?.configSource?.uri;
      const m = /^git\+(.+?)(?:@(.+))?$/.exec(typeof uri === 'string' ? uri : '');
      repo = m ? m[1] : null;
    }
    return repo ? { repository: clip(repo, 200), reason: null } : { repository: null, reason: 'the provenance names no repository' };
  }
  return { repository: null, reason: 'no SLSA provenance in the bundle (a publish attestation only, or not decodable)' };
}

/** The repository claim of one armed version. predecessor: the version this proxy served before, or null. fetchBundle(name, version)
 *  resolves { ok: true, bytes } or { ok: false, reason }; it is called only when this version has an attestation. Never throws. */
export async function repoClaimFact({ memo: m, name, version, predecessor = null, fetchBundle }) {
  const vs = predecessor ?? null;
  const out = (outcome, extra = {}) => ({ version: REPO_CLAIM_VERSION, outcome, attestation_repository: null, packument_repository: null, vs, ...extra });
  const nf = (reason, extra = {}) => out('NOT_FETCHED', { reason: clip(String(reason), 200), ...extra });
  if (!m) return nf(NOT_AT_HAND);
  const p = m.pubs.get(version);
  if (!p) return nf('the version is not in the package metadata');
  const pRepo = p.repo || null;
  if (!p.att) return out(vs && m.pubs.get(vs)?.att ? 'ABSENT' : 'NONE', { packument_repository: pRepo });
  let r;
  try { r = await fetchBundle(name ?? m.name, version); } catch (err) { return nf(`the bundle was not read: ${err?.message ?? err}`, { packument_repository: pRepo }); }
  if (!r?.ok) return nf(r?.reason ?? 'the bundle was not read', { packument_repository: pRepo });
  const a = attestationRepository(r.bytes);
  if (!a.repository) return nf(a.reason, { packument_repository: pRepo });
  const aRepo = normRepoUrl(a.repository);
  if (!aRepo) return nf('the provenance repository is not a URL this proxy reads', { packument_repository: pRepo });
  if (p.repo === null) return nf('the package metadata has no repository field', { attestation_repository: aRepo });
  if (!pRepo) return nf('the package metadata repository field is not a URL this proxy reads', { attestation_repository: aRepo });
  return out(aRepo === pRepo ? 'MATCH' : 'MISMATCH', { attestation_repository: aRepo, packument_repository: pRepo });
}

/** The repository claim as `why` and `report` print it. */
export function repoClaimLine(rc) {
  const a = shown(rc?.attestation_repository); const pr = shown(rc?.packument_repository); const vs = shown(rc?.vs);
  switch (rc?.outcome) {
    case 'MATCH': return `repository claim matches, unverified: ${a} (the provenance and the package metadata; the signature is not checked)`;
    case 'MISMATCH': return `repository claim differs: the provenance names ${a}, the package metadata ${pr} (the signature is not checked)`;
    case 'ABSENT': return `provenance dropped: ${vs} (${BASIS}) had provenance, this version has none`;
    case 'NONE': return rc.vs ? `no provenance on this release or the one before (${vs}, ${BASIS})` : `no provenance on this release (${COLD})`;
    case 'NOT_FETCHED': return `repository claim not read (${shown(rc.reason) || 'no reason recorded'})`;
    default: return 'repository claim: not recorded';
  }
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

/** The static-checks-1.6 facts of an armed version ({ facts, s5 }, proxy/static-checks.js staticFactsOf), as `why` and `report` print them. */
export function staticFactsLines(x) {
  const f = x?.facts; const out = [];
  if (!f || f.status !== 'CHECKED') out.push(`not checked (${f?.reason ?? 'not recorded'})`);
  else {
    const er = f.encoded_runs ?? {}; const mg = Object.entries(er.by_magic ?? {}).filter(([, n]) => n > 0).map(([k, n]) => `${k === 'none' ? 'no known magic' : k} ${n}`);
    out.push(er.runs ? `encoded runs ${er.runs} (${mg.join(', ')}); ${er.under_diversity_ref} with fewer than ${er.diversity_ref} distinct characters` : 'encoded runs 0');
    const xp = f.excluded_paths ?? {}; const U = 'under test, fixture, vendor or node_modules paths';
    out.push(`dynamic-code lines ${xp.p2?.rest ?? 0}, and ${xp.p2?.excluded ?? 0} ${U}; bare-IP URL lines ${xp.p9?.rest ?? 0}, and ${xp.p9?.excluded ?? 0} ${U}`);
    const aw = f.agent_config_writes ?? { count: 0, listed: [] };
    out.push(`agent config writes ${aw.count}${aw.count ? `: ${(aw.listed ?? []).map((w) => `${w.source === 'file' ? shown(w.path) : `${shown(w.hook)} hook`} ${w.dirs.join(', ')} (${w.writes.join(', ')})`).join('; ')}` : ''}`);
    const io = f.io_surface ?? {};
    out.push(io.status !== 'CHECKED' ? `I/O surface not checked (${io.reason ?? 'not recorded'})` : io.no_io_surface ? `I/O surface NONE (${io.text_read} members read as text)`
      : `I/O surface present (${[...Object.entries(io.classes ?? {}).filter(([, n]) => n > 0).map(([c, n]) => `${c} ${n}`), ...(io.install_hooks ? [`install hooks ${io.install_hooks}`] : [])].join(', ')})`);
  }
  for (const e of Array.isArray(x?.s5) ? x.s5 : []) {
    out.push(`S5 ${shown(e.path)} (${e.size} B): ${e.base64_share === null ? `base64 share not checked (${e.base64_note})` : `base64 share ${e.base64_share}, magic ${e.base64_magic ?? 'none'}`}`);
  }
  return out;
}

/** Whether a fact would have spoken on a reviewer's card: not the latest tag, not a known owner, a sign not new, a size change all docs. */
export function notable(f) {
  return Boolean((f?.dist_tag?.state === 'known' && f.dist_tag.not_latest)
    || (f?.known_owner?.state === 'known' && !f.known_owner.known_owner)
    || (f?.transition?.state === 'known' && f.transition.signs.some((s) => !s.new))
    || (f?.size?.state === 'known' && f.size.all_attributed));
}

export default { SHADOW_FACTS_VERSION, SHADOW_NOTE, publicStaticFacts, MAX_PACKAGES, rememberPackumentFacts, packumentFactsFor, forgetPackumentFacts,
  distTagFact, knownOwnerFact, fileClass, createShapeTally, sizeAttributionFact, transitionFact, shadowFactsOf, shadowLines, staticFactsLines, notable,
  REPO_CLAIM_VERSION, REPO_CLAIM_LIMITS, normRepoUrl, attestationRepository, repoClaimFact, repoClaimLine };
