// 0.1.5 T1.6 entry-path-change -- a CONTRIBUTING gate in cft-policy-1.2: what npm runs or links for a version changed against its
// LINEAGE predecessor (gates/lineage-predecessor.js: the previous version in publish order within its release line, FU-2 FINAL).
// Five components, the measurement's own definitions (chaingate-ops collector/npm_capture.py _lifecycle, _bin, _main; shared
// fixture t16-predicates-1.2, tools/corpus/fixtures/t16-predicate-cases-1.2.json; ops collector/install_scripts.py since 8f0b0536):
//   lifecycle_added    a non-install lifecycle script (LIFECYCLE_HOOKS; preinstall/install/postinstall are T1.1) absent before
//   lifecycle_changed  the same lifecycle script, its text differs
//   bin_added          a bin command absent before (the string form is named after the package, as npm links it)
//   bin_changed        the same bin command, a different path
//   main               the entry point differs (absent or empty main = index.js; a relative main loses its leading "./" and any "/"
//                      after it; a main starting with "/" is kept, absolute to Node; a final segment without a "." gets ".js", so
//                      "./x" = "x" = "x.js" but "/x" != "x"; a directory move or .cjs / .mjs stays a change)
// Measured (ops handover 11.4, base-rates-1.3, 23,456,355 versions @lin): per 10k lifecycle_added 20.47, lifecycle_changed 15.13,
// bin_added 6.84, bin_changed 2.75, main 69.54. Contributing only (operator, 2026-10-15); naming a component is a later ruling. The
// predicate follows ops' version string (T16_PREDICATES_VERSION), never leads it.
//
// Reads only the served packument (`rawVersions`, `rawTimes`); the proxy always fetches the full document (npm 10/11/12 grounding
// 2026-10-15). The detail is closed vocabulary: lifecycle names from the fixed list, bin commands as counts, never a path or text.
import { lineagePredecessorOf } from './lineage-predecessor.js';

export const T16_PREDICATES_VERSION = 't16-predicates-1.2';
export const LIFECYCLE_HOOKS = Object.freeze(['prepare', 'preprepare', 'postprepare', 'prepack', 'postpack', 'prepublish', 'prepublishOnly',
  'publish', 'postpublish', 'preuninstall', 'uninstall', 'postuninstall', 'dependencies']);
export const COMPONENTS = Object.freeze(['lifecycle_added', 'lifecycle_changed', 'bin_added', 'bin_changed', 'main']);
const GATE = 'entry-path-change';
const result = (r, detail, extra = {}) => ({ gate: GATE, result: r, detail, ...extra });

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const pathOf = (p) => (typeof p === 'string' && p.startsWith('./') ? p.slice(2) : p);
const same = (a, b) => (typeof a === 'string' || typeof b === 'string' ? a === b : JSON.stringify(a) === JSON.stringify(b));

/** The lifecycle scripts as { name: text }: strings that are not blank, from the fixed list. */
export function lifecycleOf(m) {
  const s = isObj(m) && isObj(m.scripts) ? m.scripts : {};
  const out = {};
  for (const k of LIFECYCLE_HOOKS) if (Object.hasOwn(s, k) && typeof s[k] === 'string' && s[k].trim()) out[k] = s[k];
  return out;
}
/** `bin` as { command: path }; the string form is named after the package (the part after the scope). */
export function binOf(m) {
  if (!isObj(m)) return {};
  const b = m.bin;
  if (typeof b === 'string' && b.trim()) {
    const name = typeof m.name === 'string' ? m.name : '';
    return { [name.split('/').at(-1)]: pathOf(b) };
  }
  if (!isObj(b)) return {};
  const out = {};
  for (const [k, v] of Object.entries(b)) if (typeof v === 'string') out[k] = pathOf(v);
  return out;
}
// t16-predicates-1.2: artefact-only normalisation, looser than Node's resolver in one place that can only remove a main change (an
// extensionless main also resolves X, X.json, X.node, X/index.js). A leading "/" is kept (1.1 stripped it and lost a labelled pair).
// Non-strings stay as they are.
const entryPath = (p) => {
  if (typeof p !== 'string') return p;
  if (!p.startsWith('/')) while (p.startsWith('./') || p.startsWith('/')) p = p.startsWith('./') ? p.slice(2) : p.slice(1);
  const last = p.split('/').at(-1);
  return last && !last.includes('.') ? `${p}.js` : p;
};
/** npm's entry point: absent or empty main is index.js. */
export const mainOf = (m) => { const v = isObj(m) ? m.main : undefined; return v === undefined || v === null || v === '' ? 'index.js' : entryPath(v); };

const diff = (cur, prev) => {
  const added = []; const changed = [];
  for (const [k, v] of Object.entries(cur)) {
    if (!Object.hasOwn(prev, k)) added.push(k); else if (!same(prev[k], v)) changed.push(k);
  }
  return { added, changed };
};

/** The components that fire for `cand` against `pred`, in COMPONENTS order. */
export function components(cand, pred) {
  const l = diff(lifecycleOf(cand), lifecycleOf(pred));
  const b = diff(binOf(cand), binOf(pred));
  const hit = { lifecycle_added: l.added.length > 0, lifecycle_changed: l.changed.length > 0, bin_added: b.added.length > 0,
    bin_changed: b.changed.length > 0, main: !same(mainOf(cand), mainOf(pred)) };
  return COMPONENTS.filter((c) => hit[c]);
}

const commands = (n, what) => `${n} bin command${n === 1 ? '' : 's'} ${what}`;

export default {
  name: GATE,
  evaluate(input) {
    const versions = input?.rawVersions;
    const cand = versions?.[input?.version];
    if (!isObj(cand)) return result('SKIP', 'not evaluable: no manifest for this version');
    const pred = lineagePredecessorOf(versions, input?.rawTimes, input?.version);
    if (!pred) return result('SKIP', 'not evaluable: no earlier version in this release line');
    const fired = components(cand, pred.manifest);
    if (!fired.length) return result('ALLOW', `lifecycle scripts, bin and main as in ${pred.version}`);
    const l = diff(lifecycleOf(cand), lifecycleOf(pred.manifest));
    const b = diff(binOf(cand), binOf(pred.manifest));
    const parts = [];
    if (l.added.length) parts.push(`lifecycle script added (${l.added.join(', ')})`);
    if (l.changed.length) parts.push(`lifecycle script changed (${l.changed.join(', ')})`);
    if (b.added.length) parts.push(commands(b.added.length, 'added'));
    if (b.changed.length) parts.push(commands(b.changed.length, 'changed'));
    if (fired.includes('main')) parts.push('main changed');
    return result('WARN', `vs ${pred.version}: ${parts.join('; ')}`, { components: fired });
  },
};
