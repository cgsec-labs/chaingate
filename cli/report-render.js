// The text and exit code of `chaingate report`, a pure function of what the proxy's install
// summary (or the disk record) holds. Every verdict shown is what the proxy decided when it served the request, bound to
// that policy and seed; nothing here re-evaluates a stored row.
//
// Exit: 4 tool error > 3 any refusal or tag moved off a withheld version > 2 named warnings > 4 an incomplete record with
// nothing else to report > 0. Every string from a record is stripped of control characters (C0, DEL, C1)
// and bidi/format controls, and capped; copyable commands are printed only for identities notice.js validates.
import { identity, labelFor } from '../proxy/notice.js';
import { staticFactsLines, repoClaimLine } from '../proxy/shadow-facts.js';

// C0, DEL, C1, and the bidi/format controls (U+061C, U+200B-U+200F, U+202A-U+202E, U+2060-U+2069, U+FEFF)
export const UNSAFE_CHARS = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g;
export const DISK_READ_LIMIT = 10_000;
const TAG_RE = /^[A-Za-z0-9._-]{1,64}$/;
const clean = (v, max = 300) => {
  const s = String(v ?? '').replace(UNSAFE_CHARS, '');
  return s.length > max ? `${s.slice(0, max)}...` : s;
};
const shownId = (pkg, version) => identity(pkg, version)
  ?? (version == null ? `${clean(pkg, 214)} (version not derivable from the request)` : `${clean(pkg, 214)}@${clean(version, 64)}`);
const labels = (keys, fallback) => [...new Set((Array.isArray(keys) ? keys : []).map(labelFor).filter(Boolean))].join('; ') || fallback;

export const CACHE_LINE = 'Packages npm installed from its own cache never reach ChainGate and are not listed here.';
const DO_NOTHING = '  if you do nothing: ChainGate checks only the requests that reach it; it does not re-check what is installed and '
  + 'will not tell you about this version later.';
const COVERAGE = [
  ['not-covered', 'not covered by the seed or not placeable in its history', true],
  ['indeterminate', 'history indeterminate', true],
  ['failed', 'evaluation failed', true],
  ['no-seed', 'no seed loaded', false],
  ['earlier-policy', 'decided under an earlier policy', false],
];
const MAX_INSTALLS_HELD = 20;

/** The lines for one named warning. `cutoff`: the seed's history_cutoff; `bound`: an extra binding line (disk). */
function namedBlock(e, { cutoff, bound = null }) {
  const id = identity(e.package, e.version);
  const namedRows = Array.isArray(e.named) ? e.named : [];
  // a seed row and a packument (Tier 1 runner) row on one version name both baselines
  const seedRow = namedRows.some((g) => String(g).startsWith('seed-v3:'));
  const packumentRow = namedRows.some((g) => !String(g).startsWith('seed-v3:'));
  const seedText = `seed (history to ${cutoff ? clean(cutoff, 40) : 'an unrecorded cutoff'})`;
  const baseline = seedRow && packumentRow ? `${seedText} + packument` : (seedRow ? seedText : (packumentRow ? 'packument' : 'none'));
  const out = [
    `${shownId(e.package, e.version)}  NAMED WARNING: ${labels(namedRows, 'see chaingate why')}`,
    `  what moved: ${clean(e.reason)}`,
    `  baseline: ${baseline}`,
    `  already happened: ChainGate served it to npm at ${clean(e.at, 40)}; if it declares install scripts, npm ran them unless `
      + 'scripts were disabled',
  ];
  const kId = id && typeof e.k === 'string' ? identity(e.package, e.k) : null;
  if (!id) out.push('  last version without the signal: not offered (the package name or version is not valid in a command)');
  else if (kId) {
    out.push(`  last version without the signal: ${kId} (based on this proxy's records)`);
    out.push(`  to stay on ${e.k}: chaingate pin ${kId}`);
  } else out.push('  last version without the signal: no earlier version qualifies (no pin offered)');
  if (id) out.push(`  to accept this version: chaingate accept ${id}`);
  out.push(DO_NOTHING);
  if (bound) out.push(bound);
  return out;
}

/** An accepted named warning, one line. */
const acceptedLine = (e) => `${shownId(e.package, e.version)}  NAMED WARNING (accepted by you): ${labels(e.named, 'see chaingate why')}`;

/** A tarball refused because the user's own pin withholds it. */
function pinRefusedLine(e, k) {
  const undo = identity(e.package, k) ? `chaingate unpin ${e.package}` : 'chaingate unpin <package>';
  return `${shownId(e.package, e.version)}  WITHHELD BY YOUR PIN (download refused): pinned to ${clean(k, 64)} - undo: ${undo}`;
}

/** A refusal. `retried`: a non-fact refusal whose version was served later in the same install. */
function refusedLine(e, { retried = false } = {}) {
  const facts = Array.isArray(e.facts) ? e.facts : [];
  if (facts.length) return `${shownId(e.package, e.version)}  BLOCKED (download refused): ${labels(facts, 'a recorded fact')} - npm could not install it`;
  if (retried) return `${shownId(e.package, e.version)}  REFUSED once (not a recorded fact: ${clean(e.reason, 200)}); a later request for it was served`;
  return `${shownId(e.package, e.version)}  REFUSED (download refused): not a recorded fact: ${clean(e.reason, 200)} - npm could not install it`;
}

/** A dist-tag moved off a withheld version; `installed` when this install's summary shows that tarball served. */
function tagLine(e, installed) {
  const pkg = clean(e.package, 214);
  const tag = TAG_RE.test(String(e.tag)) ? e.tag : 'a dist-tag';
  const what = labels(e.facts, "withheld by ChainGate's policy (not a recorded fact)");
  if (e.to == null) return `${pkg}: dist-tag ${tag} dropped (was ${clean(e.from, 64)}): ${what}`;
  return `${pkg}: dist-tag ${tag} moved from ${clean(e.from, 64)} to ${clean(e.to, 64)}: ${what}`
    + (installed ? ` - npm installed ${clean(e.to, 64)}` : '');
}
const moreTagsLine = (pkg, from, n) => `${clean(pkg, 214)}: ${Number(n)} more dist-tag(s) moved off ${clean(from, 64)} (not listed)`;

function exitFor({ error = false, refusals = 0, tags = 0, named = 0, dropped = 0 }) {
  if (error) return 4;
  if (refusals || tags) return 3;
  if (named) return 2;
  if (dropped) return 4;
  return 0;
}


/** Since 0.1.6.1: a time as "YYYY-MM-DD HH:MM:SSZ"; `sameDayAs` drops the date when it is that day's. Unreadable: as recorded. */
function shownTime(iso, sameDayAs = null) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return clean(iso, 40);
  const s = new Date(t).toISOString();
  const day = s.slice(0, 10); const time = `${s.slice(11, 19)}Z`;
  return sameDayAs && day === new Date(Date.parse(sameDayAs)).toISOString().slice(0, 10) ? time : `${day} ${time}`;
}
function spanOf(a, b) {
  const ms = Date.parse(b) - Date.parse(a);
  if (!Number.isFinite(ms) || ms < 0) return '';
  return ms < 120e3 ? ` (${Math.floor(ms / 1000)} s)` : ` (${Math.round(ms / 60e3)} min)`;
}
function describeInstall(inst, n) {
  const who = inst.grouping === 'npm-session'
    ? `npm session ${clean(String(inst.key).replace(/^npm-session:/, ''), 64)}`
    : `${clean(String(inst.key).replace(/^client:/, '').replace(/#\d+$/, ''), 64)} (requests grouped by a 60 s idle gap)`;
  return `Install ${n}   ${shownTime(inst.started_at)} to ${shownTime(inst.last_at, inst.started_at)}${spanOf(inst.started_at, inst.last_at)}   from ${who}`;
}
const row = (label, n, note = '') => `  ${label.padEnd(30)}${String(n).padStart(5)}${note ? `   (${note})` : ''}`;
const capped = (items, max = 20) => [...items.slice(0, max).map((x) => `    ${x}`),
  ...(items.length > max ? [`    ... and ${items.length - max} more (chaingate report --json)`] : [])];
const FACTS_NOTE = 'recorded only; no verdict depends on them';

/** The notable recorded facts, grouped by kind (each list: one entry per version). */
function factGroups(factsBy) {
  const g = { tag: [], owner: [], signs: [], size: [], files: [], repo: [] };
  const ids = new Set();
  for (const e of factsBy.values()) {
    try {
      const f = e.facts; const id = shownId(e.package, e.version);
      const before = Object.values(g).reduce((a, l) => a + l.length, 0);
      if (f?.dist_tag?.state === 'known' && f.dist_tag.not_latest) g.tag.push(`${id} (latest is ${clean(f.dist_tag.latest ?? 'not set', 64)})`);
      const o = f?.known_owner;
      if (o?.state === 'known' && !o.known_owner) {
        g.owner.push(`${id} (${clean(o.publisher, 64)}; published ${Number(o.by_publisher)} of ${Number(o.earlier_versions)} earlier versions)`);
      }
      const r = f?.transition;
      if (r?.state === 'known' && r.signs.some((x) => !x.new)) {
        g.signs.push(`${id} (${r.signs.filter((x) => !x.new).map((x) => clean(x.gate, 64)).join(', ')}, not new since ${clean(r.vs, 64)})`);
      }
      const z = f?.size;
      if (z?.state === 'known' && z.all_attributed) g.size.push(`${id} (${z.delta_bytes > 0 ? '+' : ''}${Number(z.delta_bytes)} bytes vs ${clean(z.vs, 64)})`);
      if (e.static_facts && typeof e.static_facts === 'object') g.files.push(`${id}: ${staticFactsLines(e.static_facts).map((l) => clean(l, 400)).join('; ')}`);
      if (e.repo_claim && typeof e.repo_claim === 'object') g.repo.push(`${id}: ${clean(repoClaimLine(e.repo_claim), 400)}`);
      if (Object.values(g).reduce((a, l) => a + l.length, 0) > before) ids.add(id);
    } catch { /* malformed: not shown */ }
  }
  return { groups: g, versions: ids.size };
}
const FACT_KINDS = [['tag', 'Not the latest tag'], ['owner', 'Publisher not a known owner'], ['signs', 'Named sign not new'],
  ['size', 'Size change all in docs, source maps, declarations or a second module format'], ['files', 'File checks (versions a row armed)'],
  ['repo', 'Repository claim (versions a row armed)']];

/** The lines and counts of one install from the summary. */
function renderInstall(inst, cutoff, n = 1, { verbose = false } = {}) {
  const events = Array.isArray(inst.events) ? inst.events : [];
  const idOf = (e) => `${e.package}@${e.version ?? ''}`;
  const counts = { named: 0, refusals: 0, tags: 0, dropped: (Number(inst.dropped) || 0) + (inst.evicted_earlier ? 1 : 0) };
  const detail = [];

  // named warnings, one block per version: every named event of the version merged (a late MC event is
  // never shadowed by an earlier one); the earliest serve's time and K; an accepted one is one line
  const namedByVersion = new Map();
  for (const e of events) {
    if (e.kind !== 'served' || e.class !== 'named') continue;
    const m = namedByVersion.get(idOf(e));
    if (!m) { namedByVersion.set(idOf(e), { ...e, named: [...(e.named ?? [])] }); continue; }
    m.named = [...new Set([...m.named, ...(e.named ?? [])])].sort();
    if (m.k == null && e.k != null) m.k = e.k;
    if (e.late && !m.late) m.reason = `${m.reason} | ${e.reason}`;
    m.accepted = Boolean(m.accepted && e.accepted);
  }
  let acceptedCount = 0;
  for (const e of namedByVersion.values()) {
    if (e.accepted) { detail.push(acceptedLine(e)); acceptedCount += 1; continue; }
    detail.push(...namedBlock(e, { cutoff }), '');
    counts.named += 1;
  }
  // refusals, merged per version: any fact makes it BLOCKED; a non-fact refusal served later is a retry
  const refusals = new Map();
  events.forEach((e, i) => {
    if (e.kind !== 'refused') return;
    const r = refusals.get(idOf(e)) ?? { first: e, facts: new Set(), lastIndex: i };
    for (const f of Array.isArray(e.facts) ? e.facts : []) r.facts.add(f);
    if (e.pinned && typeof e.pinned.k === 'string') r.pinned = e.pinned.k;
    r.lastIndex = i;
    refusals.set(idOf(e), r);
  });
  for (const [id, r] of refusals) {
    if (r.pinned) { detail.push(pinRefusedLine(r.first, r.pinned)); counts.refusals += 1; continue; }
    const facts = [...r.facts].sort();
    const servedAfter = events.some((e, i) => i > r.lastIndex && e.kind === 'served' && idOf(e) === id);
    const retried = !facts.length && servedAfter;
    detail.push(refusedLine({ ...r.first, facts }, { retried }));
    if (!retried) counts.refusals += 1;
  }
  // tag moves, one line per (package, withheld version, tag); counted remainders per withheld version
  const servedIds = new Set(events.filter((e) => e.kind === 'served').map(idOf));
  const tagSeen = new Set();
  const more = new Map();
  for (const e of events) {
    if (e.kind !== 'tag-moved') continue;
    if (Number(e.more) > 0) more.set(`${e.package}\u0000${e.from}`, Math.max(more.get(`${e.package}\u0000${e.from}`) ?? 0, Number(e.more)));
    const k = `${e.package}\u0000${e.from}\u0000${e.tag}`;
    if (tagSeen.has(k)) continue;
    tagSeen.add(k);
    detail.push(tagLine(e, e.to != null && servedIds.has(`${e.package}@${e.to}`)));
    counts.tags += 1;
  }
  for (const [k, m] of more) { const [pkg, from] = k.split('\u0000'); detail.push(moreTagsLine(pkg, from, m)); }
  // what the user's pins withheld, as context (no exit code)
  const pinSeen = new Map();
  for (const e of events) {
    if (e.kind !== 'pin-withheld') continue;
    const key = `${e.package}\u0000${e.k}`;
    const prev = pinSeen.get(key);
    const m = (Array.isArray(e.versions) ? e.versions.length : 0) + (Number(e.more) || 0);
    const tags = Array.isArray(e.tags) ? e.tags : [];
    pinSeen.set(key, { e, n: Math.max(prev?.n ?? 0, m), tags: prev?.tags?.length ? prev.tags : tags });
  }
  for (const { e, n: m, tags } of pinSeen.values()) {
    const tagText = tags.slice(0, 20).map((t) => `; dist-tag ${TAG_RE.test(String(t.tag)) ? t.tag : 'a dist-tag'} -> ${t.to == null ? 'dropped' : clean(t.to, 64)}`).join('');
    detail.push(`your pin on ${clean(e.package, 214)} (${clean(e.k, 64)}) withheld ${m} version(s)${tagText}`);
  }
  const withheldSeen = new Set();
  for (const e of events) {
    if (e.kind !== 'withheld' || withheldSeen.has(e.package)) continue;
    withheldSeen.add(e.package);
    const list = (Array.isArray(e.versions) ? e.versions : []).slice(0, 10)
      .map((w) => `${clean(w.version, 64)} (${labels(w.facts, 'not a recorded fact')})`).join(', ');
    const extra = Number(e.more) > 0 ? `, ... +${Number(e.more)} more` : '';
    detail.push(`context: ${clean(e.package, 214)}: withheld from the metadata npm saw, with no dist-tag pointing at them: ${list}${extra}`);
  }

  // not-checked coverage, per distinct version; a named version is never "not checked" (its named rule fired)
  const byCoverage = new Map();
  const notCheckedIds = [];
  const overrides = [];
  const servedSeen = new Set();
  for (const e of events) {
    if (e.kind !== 'served' || servedSeen.has(idOf(e))) continue;
    servedSeen.add(idOf(e));
    if (namedByVersion.has(idOf(e))) continue;                // a named version is never "not checked"
    if (e.class === 'override') overrides.push(shownId(e.package, e.version));
    else if (e.class === 'not-checked') {
      byCoverage.set(e.coverage, (byCoverage.get(e.coverage) ?? 0) + 1);
      notCheckedIds.push(`${shownId(e.package, e.version)} (${COVERAGE.find(([c]) => c === e.coverage)?.[1] ?? 'unclassified'})`);
    }
  }
  const notChecked = [...byCoverage.values()].reduce((a, b) => a + b, 0);
  const coverageNote = notChecked ? [...COVERAGE.filter(([k]) => byCoverage.get(k)).map(([k, words]) => `${byCoverage.get(k)} ${words}`),
    ...(() => { const o = [...byCoverage.entries()].filter(([k]) => !COVERAGE.some(([c]) => c === k)).reduce((a, [, x]) => a + x, 0); return o ? [`${o} unclassified`] : []; })()]
    .join(', ') : '';
  // since 0.1.6.1: versions decided while their seed cache bucket was not held: the seed checked neither history nor advisories
  const unheldIds = new Set();
  const unheld = [];
  for (const e of events) {
    if (e.kind !== 'served' || e.seed_unheld !== true || namedByVersion.has(idOf(e)) || unheldIds.has(idOf(e))) continue;
    unheldIds.add(idOf(e)); unheld.push(shownId(e.package, e.version));
  }
  // checked by a named rule, but not by the seed's
  const hookOnly = [...new Set(events.filter((e) => e.kind === 'served' && (e.class === 'clean' || e.class === 'contributing')
    && e.coverage !== 'checked' && !unheldIds.has(idOf(e))).map(idOf))].length;

  const out = [describeInstall(inst, n)];
  out.push(row('Packages served', servedSeen.size));
  out.push(row('Named warnings', counts.named));
  if (acceptedCount) out.push(row('Named warnings accepted by you', acceptedCount));
  out.push(row('Blocked or refused', counts.refusals));
  if (counts.tags) out.push(row('Dist-tags moved', counts.tags));
  out.push(row('Not checked by the seed', unheld.length));
  out.push(row('Checked only by install rule', hookOnly));
  out.push(row('Not checked by any named rule', notChecked, coverageNote));
  if (overrides.length) out.push(row('Served under your overrides', overrides.length));

  if (detail.length) out.push('', ...detail.map((l) => (l ? `  ${l}` : l)));
  if (unheld.length) {
    out.push('', '  Not checked by the seed (its seed data could not be downloaded in time):',
      ...capped(unheld));
  }
  if (notCheckedIds.length) {
    out.push('', '  Not checked by any named rule:', ...capped(notCheckedIds),
      '    For them only the advisory lookup (when a seed is loaded) and the content check (where this machine had a baseline) '
        + 'applied, plus detail-only checks where local history allowed.');
  }
  if (overrides.length) out.push('', '  Served under your exact-version overrides (chaingate allow):', ...capped(overrides));

  // 0.1.5 shadow facts: record only, never counted and never in the exit code; the newest facts event per version
  const factsBy = new Map();
  for (const e of events) if (e.kind === 'facts' && e.facts && typeof e.facts === 'object') factsBy.set(idOf(e), e);
  const { groups, versions: notableCount } = factGroups(factsBy);
  if (notableCount) {
    if (!verbose) {
      out.push('', `  Recorded facts: ${notableCount} version(s) with a notable fact (${FACTS_NOTE}). Show them: chaingate report --verbose`);
    } else {
      out.push('', `  Recorded facts (${FACTS_NOTE}):`);
      for (const [k, title] of FACT_KINDS) {
        if (!groups[k].length) continue;
        out.push(`    ${title} (${groups[k].length}):`, ...capped(groups[k]).map((l) => `  ${l}`));
      }
    }
  }
  if (inst.evicted_earlier) {
    out.push('', `  Earlier events of this install were evicted (more than ${MAX_INSTALLS_HELD} installs were active); this report is incomplete.`);
  }
  if (Number(inst.dropped) > 0) out.push('', `  ${Number(inst.dropped)} events were not recorded (bounds); this report is incomplete.`);
  return { lines: out, counts };
}

const evictedLine = (n) => `${Number(n)} earlier install(s) were evicted (at most ${MAX_INSTALLS_HELD} are held).`;

function renderProxy(p, { verbose = false } = {}) {
  const installs = Array.isArray(p.installs) ? p.installs : [];
  const evictedCount = Number(p.stats?.installs_evicted) || 0;
  const cutoff = p.seed?.history_cutoff ?? null;
  const history = `history to ${cutoff ? clean(cutoff, 40) : 'an unrecorded cutoff'}`;
  const tag = typeof p.seed?.cache?.seed_version === 'string' && /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/.test(p.seed.cache.seed_version)
    ? `seed ${p.seed.cache.seed_version}, ` : '';
  const seed = p.seed?.sha256 ? `seed ${clean(p.seed.sha256, 64).slice(0, 16)} (${history})`
    // since 0.1.6.1: a seed cache has no file digest; its root names what the proxy reads
    : (p.seed?.cache ? `seed cache (${tag}root of ${clean(p.seed.cache.root_cut_at, 40)}, ${history})` : 'no seed loaded');
  const out = [`ChainGate report   proxy ${clean(p.version, 40)}   policy ${clean(p.policy ?? 'unknown', 40)}`,
    `Seed               ${seed}`,
    'Verdicts below are what this proxy decided when it served each request, under that policy and seed; nothing here is a new evaluation.',
    ''];
  if (!installs.length) {
    out.push(`No install recorded by the running proxy since ${clean(p.started_at, 40)}.`);
    if (evictedCount) out.push(evictedLine(evictedCount));
    out.push(CACHE_LINE);
    return { text: out.join('\n'), exit: exitFor({ dropped: evictedCount }) };
  }
  const total = { named: 0, refusals: 0, tags: 0, dropped: 0 };
  installs.forEach((inst, i) => {
    const r = renderInstall(inst, cutoff, i + 1, { verbose });
    out.push(...r.lines, '');
    for (const k of Object.keys(total)) total[k] += r.counts[k];
  });
  if (p.view === 'all' && evictedCount) out.push(evictedLine(evictedCount));
  out.push(CACHE_LINE);
  return { text: out.join('\n'), exit: exitFor(total) };
}

function renderDisk(p) {
  const rows = Array.isArray(p.events) ? p.events : [];
  const where = `${clean(p.host ?? '127.0.0.1', 64)}:${clean(p.port, 8)}`;
  const first = p.proxy
    ? `A ChainGate proxy (version ${clean(p.proxy.version ?? 'unknown', 40)}) is running on ${where} but gave no install summary `
      + `(${clean(p.why ?? 'no answer', 120)}). To get one, restart it with this version: chaingate stop, then chaingate init.`
    : `No ChainGate proxy answered on ${where} (${clean(p.why ?? 'no answer', 120)}).`;
  const out = [first,
    `From the disk record (the last ${clean(p.since ?? '24h', 16)}): named warnings served, and refusals and tag moves resting on a `
      + 'fact; the per-install summary (every package served, and what was not checked) is held only by a running proxy.', ''];
  const seen = new Set();
  const total = { named: 0, refusals: 0, tags: 0, dropped: (p.truncated ? 1 : 0) + (p.incomplete || p.proxy ? 1 : 0) };
  let accepted = 0;
  const boundOf = (r) => `  recorded: policy ${clean(r.policy_version ?? 'unknown', 40)}, seed ${r.seed_sha256 ? clean(r.seed_sha256, 64).slice(0, 16) : 'none'}`;
  // a version's named rows are merged as the proxy view merges them --
  // the union of the named rows, accepted only if every row was, a late row's reason appended, the first K and cutoff
  const namedOf = new Map();
  for (const r of rows) {
    if (r.kind !== 'named-served') continue;
    const c = r.classes && typeof r.classes === 'object' ? r.classes : {};
    const id = `${r.package_name}@${r.version}`;
    const m = namedOf.get(id);
    const named = Array.isArray(c.named) ? c.named : [];
    if (!m) {
      namedOf.set(id, { row: r, named: [...named], accepted: Boolean(c.accepted), reason: r.reason, k: r.k_version ?? null,
        cutoff: c.history_cutoff ?? null, late: Boolean(c.late) });
      continue;
    }
    m.named = [...new Set([...m.named, ...named])].sort();
    m.accepted = m.accepted && Boolean(c.accepted);
    if (c.late && !m.late) m.reason = `${m.reason ?? ''} | ${r.reason ?? ''}`;
    if (m.k == null && r.k_version != null) m.k = r.k_version;
    if (m.cutoff == null && c.history_cutoff != null) m.cutoff = c.history_cutoff;
  }
  for (const r of rows) {
    const c = r.classes && typeof r.classes === 'object' ? r.classes : {};
    const k = `${r.kind}|${r.package_name}@${r.version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    const m = r.kind === 'named-served' ? namedOf.get(`${r.package_name}@${r.version}`) : null;
    if (m && m.accepted) {
      // listed with its binding; counted for the empty sentence, never for the exit code
      out.push(`${acceptedLine({ package: r.package_name, version: r.version, named: m.named })} (at ${clean(r.at, 40)})`, boundOf(r));
      accepted += 1;
    } else if (m) {
      out.push(...namedBlock({ package: r.package_name, version: r.version, named: m.named, reason: m.reason, at: r.at, k: m.k },
        { cutoff: m.cutoff, bound: boundOf(r) }), '');
      total.named += 1;
    } else if (r.kind === 'fact-refused') {
      out.push(`${refusedLine({ package: r.package_name, version: r.version, facts: c.facts, reason: r.reason })} (at ${clean(r.at, 40)})`);
      total.refusals += 1;
    } else if (r.kind === 'fact-tag-moved') {
      const tags = Array.isArray(c.tags) ? c.tags : [{ tag: c.tag, to: c.to ?? null }];
      for (const t of tags.slice(0, 20)) {
        out.push(`${tagLine({ package: r.package_name, tag: t?.tag, from: r.version, to: t?.to ?? null, facts: c.facts }, false)} (at ${clean(r.at, 40)})`);
      }
      if (Number(c.more) > 0) out.push(moreTagsLine(r.package_name, r.version, c.more));
      total.tags += 1;
    }
  }
  if (!total.named && !total.refusals && !total.tags && !accepted) {
    out.push(`No named warning, refusal or tag move was recorded on disk in the last ${clean(p.since ?? '24h', 16)}.`);
  }
  if (p.truncated) out.push(`Only the newest ${DISK_READ_LIMIT} rows of the window are shown; this view is incomplete.`);
  if (p.proxy || p.incomplete) out.push('The running proxy kept no summary for this window; this view is incomplete.');
  out.push('', CACHE_LINE);
  return { text: out.join('\n'), exit: exitFor(total) };
}

/**
 * payload: the proxy's `/_chaingate/report` answer, or `{ events, since, host, port, why, truncated?, incomplete?, proxy? }`
 * from disk (`proxy`: a ChainGate proxy that answered without a summary), or `{ error }`.
 */
export function renderReport(payload, { source = 'proxy', verbose = false } = {}) {
  if (!payload || typeof payload !== 'object' || payload.error) {
    return { text: `chaingate report: ${clean(payload?.error ?? 'no report', 300)}`, exit: exitFor({ error: true }) };
  }
  return source === 'disk' ? renderDisk(payload) : renderProxy(payload, { verbose });
}

// What JSON.stringify leaves raw inside strings: DEL, C1 and the bidi/format controls (it escapes C0 itself, and the
// newlines of its own indentation must stay).
const JSON_UNSAFE = /[\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g;

/** JSON for the terminal: DEL, C1 and bidi/format controls escaped as \uXXXX (lossless). */
export function safeJson(value) {
  return JSON.stringify(value, null, 2).replace(JSON_UNSAFE, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

export default { renderReport, safeJson, CACHE_LINE, UNSAFE_CHARS, DISK_READ_LIMIT };
