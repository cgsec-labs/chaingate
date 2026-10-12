// 0.1.4 group 2b (D-V4, D-V4b, D-V5): the `npm-notice` header ChainGate sends, and the hygiene applied to one relayed from
// upstream. npm prints a response's npm-notice (`npm notice <text>`) only when the response is not stored in or served from
// its cache: a `cache-control: no-store` response or an error status (measured on npm 10.9.7 and 11.19.0, A10). So a 200
// that carries a ChainGate notice is also sent `no-store` (NOTICE_CACHE_CONTROL).
//
// Our text is built ONLY from a validated identity and a closed vocabulary: no registry-controlled string ever reaches it.
// An upstream notice is relayed as `registry: <printable ASCII, capped>`, so a registry can never print a line that looks
// like ChainGate's.
import { SEMVER_RE } from '../seed/v3/gate.js';

export const NOTICE_CACHE_CONTROL = 'no-store';
export const NOTICE_MAX_BYTES = 400;
const UPSTREAM_MAX = 300;
// npm's package-name characters (validate-npm-package-name): URL-safe, optional @scope/, <= 214. Uppercase is allowed
// because legacy names keep it (e.g. JSONStream; dated note 5.7).
const NAME_RE = /^(?:@[a-zA-Z0-9-*~][a-zA-Z0-9-*._~]*\/)?[a-zA-Z0-9-~][a-zA-Z0-9-._~]*$/;

const LABELS = Object.freeze({
  'seed-v3:channel-a:critical': 'release-history break vs the seed (3+ of 5 groups)',
  'seed-v3:dac-trajectory:surface': 'release-history break vs the seed (2+ package-wide signals)',
  'seed-v3:pin': 'a recorded advisory names this version',
  'content-hash': 'its content differs from the recorded baseline',
  'install-introduced': 'an install script appears that earlier releases did not have',          // 0.1.4 group 3a (E30)
});

const printable = (s) => String(s).replace(/[^\x20-\x7e]/g, '');
const validId = (pkg, version) => typeof pkg === 'string' && pkg.length <= 214 && NAME_RE.test(pkg)
  && typeof version === 'string' && version.length <= 256 && SEMVER_RE.test(version);

/** The closed-vocabulary label of one classification key, or null (shared with `chaingate report`, 2c D-R4/D-R6). */
export function labelFor(key) {
  return Object.hasOwn(LABELS, key) ? LABELS[key] : null;
}

/** A validated `pkg@version`, or null. */
export function identity(pkg, version) {
  return validId(pkg, version) ? `${pkg}@${version}` : null;
}

/**
 * kind: 'WARNING' | 'BLOCKED'; labels: classification keys (named row gates, 'seed-v3:pin', 'content-hash'); tail: an
 * optional closed-vocabulary clause built by the caller from validated values (e.g. the dist-tag move).
 */
export function buildNotice({ kind, pkg, version, labels = [], tail = '' }) {
  const id = identity(pkg, version);
  const what = [...new Set(labels.map((k) => LABELS[k]).filter(Boolean))].join('; ') || 'see details';
  const text = `chaingate: ${kind} ${id ?? 'this version'}: ${what}${tail ? ` ${tail}` : ''}.`
    + (id ? ` Details: chaingate why ${id}` : ' Details: chaingate why <package>@<version>');
  let out = printable(text);
  while (Buffer.byteLength(out) > NOTICE_MAX_BYTES) out = out.slice(0, -1);
  return out;
}

/** 0.1.4 group 2d (D-U5): the notice of a tarball withheld by the user's own pin; null unless every part validates. */
export function pinNotice(pkg, version, k) {
  const id = identity(pkg, version);
  if (!id || !identity(pkg, k)) return null;
  const out = printable(`chaingate: WITHHELD ${id}: pinned by you to ${k}. Undo: chaingate unpin ${pkg}`);
  return Buffer.byteLength(out) <= NOTICE_MAX_BYTES ? out : null;
}

/** An upstream npm-notice, relabelled and stripped to printable ASCII. */
export function sanitizeUpstreamNotice(value) {
  const v = Array.isArray(value) ? value.join(' ') : String(value ?? '');
  return `registry: ${printable(v).slice(0, UPSTREAM_MAX)}`;
}

export default { buildNotice, pinNotice, sanitizeUpstreamNotice, identity, labelFor, NOTICE_CACHE_CONTROL, NOTICE_MAX_BYTES };
