// 0.1.4 group 2c (D-R3..D-R8): the text and exit code of `chaingate report`, a pure function of what the proxy's install
// summary (or the disk record) holds. Every verdict shown is what the proxy decided when it served the request, bound to
// that policy and seed; nothing here re-evaluates a stored row (CFT-04 R4).
//
// Exit: 4 tool error > 3 any refusal or tag moved off a withheld version > 2 named warnings > 4 an incomplete record with
// nothing else to report > 0 (dated note 6.6). Every string from a record is stripped of control characters and capped;
// copyable commands are printed only for identities notice.js validates (dated note 6.10).
import { identity, labelFor } from '../proxy/notice.js';

const CONTROL = /[\u0000-\u001f\u007f-\u009f]/g;
const TAG_RE = /^[A-Za-z0-9._-]{1,64}$/;
const clean = (v, max = 300) => {
  const s = String(v ?? '').replace(CONTROL, '');
  return s.length > max ? `${s.slice(0, max)}…` : s;
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

/** D-R4: the lines for one named warning. `cutoff`: the seed's history_cutoff; `bound`: an extra binding line (disk). */
function namedBlock(e, { cutoff, bound = null }) {
  const id = identity(e.package, e.version);
  const namedRows = Array.isArray(e.named) ? e.named : [];
  const baseline = namedRows.some((g) => String(g).startsWith('seed-v3:'))
    ? `seed (history to ${cutoff ? clean(cutoff, 40) : 'an unrecorded cutoff'})` : (namedRows.length ? 'packument' : 'none');
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

/** D-R6: a refusal. */
function refusedLine(e) {
  const facts = Array.isArray(e.facts) ? e.facts : [];
  return facts.length
    ? `${shownId(e.package, e.version)}  BLOCKED (download refused): ${labels(facts, 'a recorded fact')} — npm could not install it`
    : `${shownId(e.package, e.version)}  REFUSED (download refused): not a recorded fact — ${clean(e.reason, 200)} — npm could not install it`;
}

/** D-R6: a dist-tag moved off a withheld version; `installed` when this install's summary shows that tarball served. */
function tagLine(e, installed) {
  const pkg = clean(e.package, 214);
  const tag = TAG_RE.test(String(e.tag)) ? e.tag : 'a dist-tag';
  const what = labels(e.facts, "withheld by ChainGate's policy (not a recorded fact)");
  if (e.to == null) return `${pkg}: dist-tag ${tag} dropped (was ${clean(e.from, 64)}): ${what}`;
  return `${pkg}: dist-tag ${tag} moved from ${clean(e.from, 64)} to ${clean(e.to, 64)}: ${what}`
    + (installed ? ` — npm installed ${clean(e.to, 64)}` : '');
}

function exitFor({ error = false, refusals = 0, tags = 0, named = 0, dropped = 0 }) {
  if (error) return 4;
  if (refusals || tags) return 3;
  if (named) return 2;
  if (dropped) return 4;
  return 0;
}

function describeInstall(inst) {
  const who = inst.grouping === 'npm-session'
    ? `npm session ${clean(String(inst.key).replace(/^npm-session:/, ''), 64)}`
    : `requests from ${clean(String(inst.key).replace(/^client:/, '').replace(/#\d+$/, ''), 64)} (grouped by a 60 s idle gap)`;
  return `${who}, ${clean(inst.started_at, 40)} to ${clean(inst.last_at, 40)}`;
}

/** The lines and counts of one install from the summary. */
function renderInstall(inst, cutoff) {
  const events = Array.isArray(inst.events) ? inst.events : [];
  const out = [`Install: ${describeInstall(inst)}`, ''];
  const seen = new Set();
  const once = (e) => { const k = `${e.kind}|${e.package}@${e.version ?? ''}|${e.tag ?? ''}`; if (seen.has(k)) return false; seen.add(k); return true; };
  const servedIds = new Set(events.filter((e) => e.kind === 'served').map((e) => `${e.package}@${e.version}`));
  const counts = { named: 0, refusals: 0, tags: 0, dropped: Number(inst.dropped) || 0 };

  for (const e of events) {
    if (e.kind === 'served' && e.class === 'named' && once(e)) { out.push(...namedBlock(e, { cutoff }), ''); counts.named += 1; }
  }
  for (const e of events) {
    if (e.kind === 'refused' && once(e)) { out.push(refusedLine(e)); counts.refusals += 1; }
  }
  for (const e of events) {
    if (e.kind === 'tag-moved' && once(e)) { out.push(tagLine(e, e.to != null && servedIds.has(`${e.package}@${e.to}`))); counts.tags += 1; }
  }
  for (const e of events) {
    if (e.kind !== 'withheld' || !once({ ...e, version: '' })) continue;
    const list = (Array.isArray(e.versions) ? e.versions : []).slice(0, 10)
      .map((w) => `${clean(w.version, 64)} (${labels(w.facts, 'not a recorded fact')})`).join(', ');
    const more = Number(e.more) > 0 ? `, … +${Number(e.more)} more` : '';
    out.push(`context: ${clean(e.package, 214)}: withheld from the metadata npm saw, with no dist-tag pointing at them: ${list}${more}`);
  }
  if (counts.refusals || counts.tags || events.some((e) => e.kind === 'withheld')) out.push('');

  // V6 (D-R7), per distinct version
  const byCoverage = new Map();
  const overrides = [];
  const servedSeen = new Set();
  for (const e of events) {
    if (e.kind !== 'served') continue;
    const id = `${e.package}@${e.version}`;
    if (servedSeen.has(id)) continue;
    servedSeen.add(id);
    if (e.class === 'override') overrides.push(shownId(e.package, e.version));
    else if (e.class === 'not-checked') byCoverage.set(e.coverage, (byCoverage.get(e.coverage) ?? 0) + 1);
  }
  const notChecked = [...byCoverage.values()].reduce((a, b) => a + b, 0);
  if (notChecked) {
    const parts = COVERAGE.filter(([k, , always]) => always || byCoverage.get(k)).map(([k, words]) => `${byCoverage.get(k) ?? 0} ${words}`);
    const other = [...byCoverage.entries()].filter(([k]) => !COVERAGE.some(([c]) => c === k)).reduce((a, [, n]) => a + n, 0);
    if (other) parts.push(`${other} unclassified`);
    out.push(`${notChecked} package(s) were not checked by any named rule: ${parts.join(', ')}. For them only the advisory lookup `
      + '(when a seed is loaded) and the content check (where this machine had a baseline) applied, plus detail-only checks where '
      + 'local history allowed.');
  } else if (servedSeen.size > overrides.length) {
    out.push('Every package served in this install was checked by the named rules.');
  }
  if (overrides.length) {
    out.push(`${overrides.length} version(s) were served under your exact-version overrides (chaingate allow): `
      + `${overrides.slice(0, 20).join(', ')}${overrides.length > 20 ? ', …' : ''}`);
  }
  if (counts.dropped) out.push(`${counts.dropped} events were not recorded (bounds); this report is incomplete.`);
  return { lines: out, counts };
}

function renderProxy(p) {
  const installs = Array.isArray(p.installs) ? p.installs : [];
  const cutoff = p.seed?.history_cutoff ?? null;
  const seed = p.seed?.sha256 ? `seed ${clean(p.seed.sha256, 64).slice(0, 16)} (history to ${cutoff ? clean(cutoff, 40) : 'an unrecorded cutoff'})`
    : 'no seed loaded';
  const out = [`ChainGate report: proxy ${clean(p.version, 40)}, policy ${clean(p.policy ?? 'unknown', 40)}, ${seed}`,
    'Each verdict below is what this proxy decided when it served the request, under that policy and seed; it is not a new '
      + 'evaluation.', ''];
  if (!installs.length) {
    out.push(`No install recorded by the running proxy since ${clean(p.started_at, 40)}.`, CACHE_LINE);
    return { text: out.join('\n'), exit: 0 };
  }
  const total = { named: 0, refusals: 0, tags: 0, dropped: 0 };
  for (const inst of installs) {
    const r = renderInstall(inst, cutoff);
    out.push(...r.lines, '');
    for (const k of Object.keys(total)) total[k] += r.counts[k];
  }
  out.push(CACHE_LINE);
  return { text: out.join('\n'), exit: exitFor(total) };
}

function renderDisk(p) {
  const rows = Array.isArray(p.events) ? p.events : [];
  const out = [`No ChainGate proxy answered on ${clean(p.host ?? '127.0.0.1', 64)}:${clean(p.port, 8)} (${clean(p.why ?? 'no answer', 120)}).`,
    `From the disk record (the last ${clean(p.since ?? '24h', 16)}): named warnings served, and refusals and tag moves resting on a `
      + 'fact; the per-install summary (every package served, and what was not checked) is held only by a running proxy.', ''];
  const seen = new Set();
  const total = { named: 0, refusals: 0, tags: 0 };
  const boundOf = (r) => `  recorded: policy ${clean(r.policy_version ?? 'unknown', 40)}, seed ${r.seed_sha256 ? clean(r.seed_sha256, 64).slice(0, 16) : 'none'}`;
  for (const r of rows) {
    const c = r.classes && typeof r.classes === 'object' ? r.classes : {};
    const k = `${r.kind}|${r.package_name}@${r.version}|${c.tag ?? ''}`;
    if (seen.has(k)) continue;
    seen.add(k);
    if (r.kind === 'named-served') {
      out.push(...namedBlock({ package: r.package_name, version: r.version, named: c.named, reason: r.reason, at: r.at, k: r.k_version },
        { cutoff: c.history_cutoff ?? null, bound: boundOf(r) }), '');
      total.named += 1;
    } else if (r.kind === 'fact-refused') {
      out.push(`${refusedLine({ package: r.package_name, version: r.version, facts: c.facts, reason: r.reason })} (at ${clean(r.at, 40)})`);
      total.refusals += 1;
    } else if (r.kind === 'fact-tag-moved') {
      out.push(`${tagLine({ package: r.package_name, tag: c.tag, from: r.version, to: c.to ?? null, facts: c.facts }, false)} (at ${clean(r.at, 40)})`);
      total.tags += 1;
    }
  }
  if (!total.named && !total.refusals && !total.tags) {
    out.push(`No named warning, refusal or tag move was recorded on disk in the last ${clean(p.since ?? '24h', 16)}.`);
  }
  out.push('', CACHE_LINE);
  return { text: out.join('\n'), exit: exitFor(total) };
}

/** payload: the proxy's `/_chaingate/report` answer, or `{ events, since, host, port, why }` from disk, or `{ error }`. */
export function renderReport(payload, { source = 'proxy' } = {}) {
  if (!payload || typeof payload !== 'object' || payload.error) {
    return { text: `chaingate report: ${clean(payload?.error ?? 'no report', 300)}`, exit: exitFor({ error: true }) };
  }
  return source === 'disk' ? renderDisk(payload) : renderProxy(payload);
}

export default { renderReport, CACHE_LINE };
