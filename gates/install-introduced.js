// T1.1 install-introduced (L1 + L1i) -- a NAMED gate in cft-policy-1.2 (r3 §18.7 item 2, §18.8 item 4, §18.10; group 3
// tables D-T1). The counted rule, reproduced exactly: validate_a1.py `eval_rule` over validate.py `hooks`
// (PROTOCOL 78878f55…, amendment A1 ecb06386…: 0 / 2,982 benign under the 24 h window).
//
// For the candidate published at c, over the served packument (`versions` and `time`):
//   settled set = other versions published at or before c - 24 h; on a COLD START (empty) the plain set = other versions
//                 published before c (§18.10 clarification); neither -> not evaluable (SKIP)
//   hooks       = preinstall / install / postinstall with Python truthiness; ever = a version in the set had one
//   L1          = the candidate has a hook, and not ever
//   L1i         = the candidate's gypfile is truthy, it has no install/preinstall hook, and not ever (the counted form:
//                 ever counts hooks only)
// A version whose time does not parse orders nothing (it is in no set), as in the counted code.
import { pyTruthy } from '../seed/v3/packument.js';

export const SETTLED_MS = 24 * 3_600_000;
const HOOKS = ['preinstall', 'install', 'postinstall'];
const GATE = 'install-introduced';
const result = (r, detail) => ({ gate: GATE, result: r, detail });

function hooksOf(manifest) {
  const s = manifest && typeof manifest === 'object' ? manifest.scripts : null;
  if (!s || typeof s !== 'object' || Array.isArray(s)) return [];
  return HOOKS.filter((k) => pyTruthy(s[k]));
}

/** The two earliest [time, version] of a list (enough to exclude the candidate itself in O(1)). */
function twoEarliest(entries) {
  let a = null; let b = null;
  for (const e of entries) {
    if (!a || e[0] < a[0]) { b = a; a = e; } else if (!b || e[0] < b[0]) b = e;
  }
  return [a, b];
}
const earliestOther = ([a, b], version) => (a && a[1] !== version ? a[0] : (b ? b[0] : Infinity));

const indexes = new WeakMap();
/** Per packument (memoised per versions object): times, hooks, and the two earliest overall and hooked. */
function indexFor(versions, times) {
  let byTimes = indexes.get(versions);
  if (byTimes && byTimes.has(times)) return byTimes.get(times);
  const time = new Map();
  const hooks = new Map();
  const all = []; const hooked = [];
  for (const [v, m] of Object.entries(versions)) {
    const h = hooksOf(m);
    hooks.set(v, h);
    const t = times && typeof times[v] === 'string' ? Date.parse(times[v]) : NaN;
    if (Number.isNaN(t)) continue;
    time.set(v, t);
    all.push([t, v]);
    if (h.length) hooked.push([t, v]);
  }
  const idx = { time, hooks, all: twoEarliest(all), hooked: twoEarliest(hooked) };
  if (!byTimes) { byTimes = new WeakMap(); indexes.set(versions, byTimes); }
  if (times && typeof times === 'object') byTimes.set(times, idx);
  return idx;
}

export function evaluateL1(versions, times, version) {
  if (!versions || typeof versions !== 'object' || !Object.hasOwn(versions, version)) return { skip: 'the version is not in the served metadata' };
  const idx = indexFor(versions, times);
  const c = idx.time.get(version);
  if (c === undefined) return { skip: 'no publication time for this version' };
  const firstOther = earliestOther(idx.all, version);
  const firstHooked = earliestOther(idx.hooked, version);
  let used; let ever;
  if (firstOther <= c - SETTLED_MS) { used = 'settled 24 h'; ever = firstHooked <= c - SETTLED_MS; } else if (firstOther < c) {
    used = 'cold start: plain'; ever = firstHooked < c;
  } else return { skip: 'no earlier version' };
  const cur = idx.hooks.get(version);
  const m = versions[version];
  const gyp = Boolean(m && typeof m === 'object' && pyTruthy(m.gypfile)) && !cur.includes('install') && !cur.includes('preinstall');
  return { L1: cur.length > 0 && !ever, L1i: gyp && !ever, hooks: cur, used };
}

export default {
  name: GATE,
  evaluate(input) {
    const r = evaluateL1(input?.rawVersions, input?.rawTimes, input?.version);
    if (r.skip) return result('SKIP', `not evaluable: ${r.skip}`);
    if (r.L1) return result('WARN', `${r.hooks.join(', ')} present; no earlier version (${r.used}) had an install hook`);
    if (r.L1i) return result('WARN', `gypfile present (an implicit node-gyp install) with no install/preinstall hook; no earlier version (${r.used}) had an install hook`);
    return result('ALLOW', `no install hook introduced (${r.used})`);
  },
};
