// identity-break (0.1.5) -- "a publisher this package has never had, publishing from a different toolchain,
// account set or repository": the candidate's `_npmUser.email` appears in no version of the served packument published
// before it, AND at least two of these broke against the predecessor (gates/predecessor.js: the highest lower release of
// the same major, published before): the maintainers' e-mail set differs; `_npmVersion` is lower (a tool downgrade, as
// publish-tool-change counts it); the repository URL differs; gitHead is absent where the predecessor had one.
//
// Measured before it was written (24,152,465 corpus versions, publish-order baseline): 0.057 % of versions (1 per 1,890
// established versions); the first malicious version of 37 more labelled packages than 0.1.4's named rules, 36 of them the
// 2017 crossenv typosquats (a placeholder version, then the attacker's) and one established package. CONTRIBUTING in 0.1.5
// -- a detail row beside a named warning and in `chaingate why`, never a warning on its own -- pending a lineage
// re-measure.
//
// Reads only the served packument: history-independent. The identity parts are the ones the seed's Channel-A publisher
// group counts as ONE group; this row counts them individually, which is why it fires where Channel-A's 3-of-5 does not.
import semver from 'semver';
import { predecessorOf, MAX_WALK } from './predecessor.js';
import { gitHeadOf, repoOf } from './size-jump-provenance.js';

const GATE = 'identity-break';
export const MIN_BREAKS = 2;
const result = (r, detail) => ({ gate: GATE, result: r, detail });
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);

export const emailOf = (m) => (isObj(m) && isObj(m._npmUser) && typeof m._npmUser.email === 'string' && m._npmUser.email.trim()
  ? m._npmUser.email.trim().toLowerCase() : null);
export const toolOf = (m) => (isObj(m) && typeof m._npmVersion === 'string' && semver.valid(m._npmVersion) ? m._npmVersion : null);
/** The maintainers' e-mails (lower-cased; a name when an entry has no e-mail), or null when the field is absent/malformed. */
export function maintainersOf(m) {
  if (!isObj(m) || !Array.isArray(m.maintainers)) return null;
  const out = new Set();
  for (const x of m.maintainers) {
    if (isObj(x)) { const k = (x.email || x.name || '').toString().trim().toLowerCase(); if (k) out.add(k); }
    else if (typeof x === 'string' && x.trim()) out.add(x.trim().toLowerCase());
  }
  return out;
}
const sameSet = (a, b) => a.size === b.size && [...a].every((x) => b.has(x));

/** True when no version published before the candidate carries the candidate's publisher e-mail. */
export function publisherNew(versions, times, version) {
  const email = emailOf(versions?.[version]);
  if (!email) return null;
  const c = times && typeof times[version] === 'string' ? Date.parse(times[version]) : NaN;
  if (Number.isNaN(c)) return null;
  for (const [v, m] of Object.entries(versions)) {
    if (v === version) continue;
    const t = typeof times[v] === 'string' ? Date.parse(times[v]) : NaN;
    if (Number.isNaN(t) || !(t < c)) continue;
    if (emailOf(m) === email) return false;
  }
  return true;
}

/** The identity facts of the candidate that broke against its predecessor. */
export function identityBreaks(cand, pred) {
  const out = [];
  const mc = maintainersOf(cand); const mp = maintainersOf(pred);
  if (mc && mp && !sameSet(mc, mp)) out.push('maintainers changed');
  const tc = toolOf(cand); const tp = toolOf(pred);
  if (tc && tp && semver.lt(tc, tp)) out.push(`npm ${tp} → ${tc} (a downgrade)`);
  const rc = repoOf(cand); const rp = repoOf(pred);
  if (rc && rp && rc !== rp) out.push(`repository ${rp} → ${rc}`);
  if (gitHeadOf(pred) && !gitHeadOf(cand)) out.push('gitHead absent (the predecessor had one)');
  return out;
}

export default {
  name: GATE,
  evaluate(input) {
    const versions = input?.rawVersions; const times = input?.rawTimes; const version = input?.version;
    const cand = versions?.[version];
    if (!isObj(cand)) return result('SKIP', 'the version is not in the served metadata');
    const fresh = publisherNew(versions, times, version);
    if (fresh === null) return result('SKIP', 'not evaluable: no publisher e-mail or publication time for this version');
    const pred = predecessorOf(versions, times, version, (m) => isObj(m));
    if (pred?.beyond) return result('SKIP', `not evaluable: no predecessor within the last ${MAX_WALK} lower releases`);
    if (!pred) return result('SKIP', 'not evaluable: no earlier release of this major');
    const breaks = identityBreaks(cand, pred.manifest);
    const who = `publisher ${emailOf(cand)}`;
    if (!fresh) return result('ALLOW', `${who} published earlier versions; ${breaks.length} identity fact(s) differ from ${pred.version}`);
    if (breaks.length < MIN_BREAKS) {
      return result('ALLOW', `${who} is new to this package, but only ${breaks.length} identity fact(s) differ from ${pred.version}`
        + (breaks.length ? ` (${breaks.join('; ')})` : ''));
    }
    return result('WARN', `${who} is new to this package, and ${breaks.join('; ')} vs ${pred.version}`);
  },
};
