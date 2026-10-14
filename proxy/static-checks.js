// 0.1.5 tarball static checks S0–S4 (design note §4, §5). Pure functions over the registry manifest, the tarball package.json and the
// walker's kept bodies (tar-walk.js `keep`, step 1). Each check is a CONJUNCTION of two facts about ONE file (or one hook command),
// stated so a reviewer can confirm it by opening the tarball. A row is { gate, result: ALLOW | SKIP | WARN, detail }, the shape every
// gate writes; its detail is built from a closed vocabulary -- the marker NAMES that matched (never file content, never a host, never
// a command), the file's path sanitised and capped as MC's shownName, and the kept size. "Not checked" (SKIP) is stated per file and
// never read as absence; a WARN wins over not checked, which wins over ALLOW (as MC). No static row is ever a BLOCK.
// The marker constants are the ops recon tool's (chaingate-ops tools/recon/v6.5/static-checks.mjs) under the SAME version string, so a
// runtime row and a recon row read against each other; a change to any marker bumps STATIC_CHECKS_VERSION on both sides.
//   S0 shell-fetch-in-hook        a preinstall/install/postinstall command carries a FETCH (curl, wget, Invoke-WebRequest, certutil
//                                 -urlcache, bitsadmin) AND an EXECUTE/DECODE (| sh, powershell -enc, base64 -d, eval, iex)
//   S1 loader-in-hook-target      a kept hook target under 8 KiB with a NETWORK sink AND an EXECUTION sink
//   S2 obfuscated-entry           a kept main/bin target with >= 20 distinct `_0x[0-9a-f]{4,6}` identifiers AND a decode marker
//                                 (eval, Function, atob, a String.fromCharCode run of >= 50 codes, hex-escape density > 15 %)
//   S3 secret-harvest-with-sink   a kept main/bin/hook target with a CREDENTIAL source AND an OUTBOUND sink to a non-registry host
//   S4 wallet-swap-hook           a kept main/bin target that OVERRIDES XMLHttpRequest.prototype.send / window.fetch /
//                                 window.ethereum.request AND carries >= 2 crypto-address regex families
// The keep list (keepListFor) comes from the REGISTRY manifest, known before the first byte: install-hook targets (a small hook
// grammar, node-resolution variants), main (default index.js), up to 4 bin targets; what is dropped is stated. The roles of a kept
// body (hook, main, bin) decide which checks read it; a body the tarball package.json alone names gets its role from that file.
import { posix } from 'node:path';
import { pyTruthy } from '../seed/v3/packument.js';
import { DEFAULTS as WALK } from './tar-walk.js';
import { classify } from '../witness/row-class.js';

export const STATIC_CHECKS_VERSION = 'static-checks-1.0';
export const LIMITS = Object.freeze({ maxKeep: WALK.maxKeep, maxKeepBytes: WALK.maxKeepBytes, maxBin: 4, maxHookTargets: 3, s1MaxBytes: 8192,
  s2MinIdents: 20, s2MinCharCodes: 50, s2HexDensity: 0.15, s4MinAddressFamilies: 2, headBytes: 8000, detailChars: 400 });
export const CHECKS = Object.freeze([
  { id: 'S0', gate: 'static:S0-shell-fetch-in-hook', roles: null, notice: 'an install script fetches and runs remote code' },
  { id: 'S1', gate: 'static:S1-loader-in-hook-target', roles: ['hook'], notice: 'an install script runs a small loader that fetches and executes' },
  { id: 'S2', gate: 'static:S2-obfuscated-entry', roles: ['main', 'bin'], notice: 'its entry file is obfuscated code' },
  { id: 'S3', gate: 'static:S3-secret-harvest-with-sink', roles: ['main', 'bin', 'hook'], notice: 'its code reads credentials and sends them to an outside host' },
  { id: 'S4', gate: 'static:S4-wallet-swap-hook', roles: ['main', 'bin'], notice: 'its code rewrites wallet addresses in web traffic' },
]);
export const STATIC_GATES = Object.freeze(CHECKS.map((c) => c.gate));
/** Armed keep-list walks at once (design note §3 budget: ≤ 6 MiB each); beyond it a download gets the MC-only walk, stated and retried. */
export const MAX_ARMED_WALKS = 4;
const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall'];
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const names = (list, s) => list.filter(([, re]) => re.test(s)).map(([n]) => n);
// publisher text: control and bidi characters stripped, capped at 80 characters (as MC's shownName, G4 D-C1)
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g;
export const shownName = (n) => { const x = String(n ?? '').replace(UNSAFE, ''); return x.length > 80 ? `${x.slice(0, 80)}…` : x; };
const clipDetail = (s) => (s.length > LIMITS.detailChars ? `${s.slice(0, LIMITS.detailChars - 1)}…` : s);

// ---- marker constants (closed vocabulary; names are what reaches a row) -- the recon v6.5 lists, verbatim ----
export const FETCH_MARKERS = [
  ['curl', /\bcurl(?:\.exe)?\b/i], ['wget', /\bwget(?:\.exe)?\b/i],
  ['Invoke-WebRequest', /Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b/i],
  ['certutil-urlcache', /\bcertutil(?:\.exe)?\b[^|&;]{0,200}-urlcache/i],
  ['bitsadmin', /\bbitsadmin(?:\.exe)?\b|Start-BitsTransfer/i],
];
export const EXEC_MARKERS = [
  ['powershell-encoded', /\b(?:powershell|pwsh)(?:\.exe)?\b[^|&;]{0,200}\s-(?:e|ec|enc|encodedcommand)\b/i],
  ['Invoke-Expression', /Invoke-Expression|\biex\b/i],
  ['base64-decode', /\bbase64\b\s+(?:-\w+\s+)*(?:-d|-D|--decode)\b|\bcertutil(?:\.exe)?\b[^|&;]{0,200}-decode/i],
  ['pipe-to-shell', /(?<!\|)\|(?!\|)\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k|c|tc|fi)?sh\b(?!-)/],                      // a pipe, never the || operator
  ['pipe-to-interpreter', /(?<!\|)\|(?!\|)\s*(?:sudo\s+(?:-\S+\s+)*)?(?:node|bun|deno|python[23]?|perl|ruby)\b(?![-.])/],   // `|| node-gyp rebuild` is neither
  ['eval', /\beval\b/],
];
export const NET_SINKS = [
  ['http-request', /\b(?:https?|http2)\.(?:request|get)\s*\(/], ['fetch', /\bfetch\s*\(/],
  ['net-connect', /\bnet\.(?:connect|createConnection)\s*\(|\btls\.connect\s*\(|\bdgram\.createSocket\s*\(/],
  ['websocket', /\bnew\s+WebSocket\s*\(/], ['xhr', /\bnew\s+XMLHttpRequest\s*\(/], ['axios', /\baxios(?:\.\w+)?\s*\(/],
  ['url-literal', /https?:\/\/[^\s'"`]{3,}/],
];
export const EXEC_SINKS = [
  ['child_process', /child_process|\b(?:execSync|spawnSync|execFileSync|execFile|spawn|fork)\s*\(/],
  ['eval', /\beval\s*\(/], ['Function', /(?:^|[^\w$.])(?:new\s+)?Function\s*\(/], ['vm', /\bvm\.(?:runIn(?:New|This)?Context|Script)\s*\(/],
];
export const DECODE_MARKERS = [['eval', /\beval\s*\(/], ['Function', /(?:^|[^\w$.])(?:new\s+)?Function\s*\(/], ['atob', /\batob\s*\(/]];
export const OBF_IDENT = /_0x[0-9a-f]{4,6}\b/g;
const HEX_ESCAPE = /\\x[0-9a-fA-F]{2}/g;
const CHARCODE_RUN = new RegExp(`String\\.fromCharCode\\s*\\(\\s*(?:\\d{1,3}\\s*,\\s*){${LIMITS.s2MinCharCodes - 1},}\\d{1,3}`);
export const CRED_SOURCES = [
  ['npmrc', /\.npmrc\b/], ['ssh-key', /\.ssh\/|\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b/],
  ['aws-credentials', /\.aws\/credentials|\bAWS_SECRET_ACCESS_KEY\b|\bAWS_ACCESS_KEY_ID\b/], ['git-credentials', /\.git-credentials\b/],
  ['token-env', /\b(?:NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|NODE_AUTH_TOKEN|NPM_AUTH_TOKEN|GITLAB_TOKEN|CI_JOB_TOKEN)\b/],
  ['env-dump', /JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:keys|entries|values)\(\s*process\.env\s*\)|\.\.\.process\.env\b/],
  ['wallet-file', /wallet\.dat|Local Storage\/leveldb|\.config\/gcloud|\.kube\/config/],
];
export const EXFIL_HOSTS = /discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org|hooks\.slack\.com|webhook\.site|\.pipedream\.net|\.ngrok(?:-free)?\.(?:io|app|dev)|\binteract\.sh\b|\boast\.(?:pro|live|site|fun|me)\b|burpcollaborator\.net|requestbin|pastebin\.com|transfer\.sh|\.requestcatcher\.com|\.free\.beeceptor\.com|\.hookbin\.com|\.pipedream\.com/i;
export const RAW_IP_URL = /\bhttps?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/;
export const REGISTRY_HOSTS = Object.freeze(['registry.npmjs.org', 'registry.yarnpkg.com', 'registry.npmmirror.com', 'npmjs.com', 'www.npmjs.com', 'localhost', '127.0.0.1']);
const URL_HOST = /https?:\/\/([^\s'"`/:?#\\]+)/g;
const POST_MARKER = /method\s*[:=]\s*['"]POST['"]|\.post\s*\(|['"]POST['"]\s*,/i;
export const OVERRIDES = [
  ['xhr-send', /XMLHttpRequest\.prototype\.send\s*=/], ['window-fetch', /\b(?:window|globalThis|self)\.fetch\s*=/], ['ethereum-request', /\bethereum\.request\s*=/],
];
export const ADDRESS_FAMILIES = [
  ['evm', /0x\[(?:a-fA-F0-9|0-9a-fA-F|a-f0-9|0-9a-f|A-F0-9|0-9A-F|a-zA-Z0-9)\]\{40\}/],
  ['btc', /bc1\[[^\]]{1,60}\]\{|\[13\]\[[^\]]{1,60}\]\{2\d,3\d\}/],
  ['trx', /\bT\[[^\]]{1,40}\]\{33\}/],
  ['sol', /\[1-9A-HJ-NP-Za-km-z\]\{32,44\}|\[1-9A-HJ-NP-Za-km-z\]\{43,44\}/],
  ['ltc', /\[LM3\]\[[^\]]{1,40}\]\{26,33\}|ltc1\[[^\]]{1,60}\]\{/],
  ['xmr', /4\[0-9AB\]\[1-9A-HJ-NP-Za-km-z\]\{93\}/],
];

// ---- S0 over a hook command string ----
/** { fetch, exec, fires } for one hook command; a non-string never throws and never fires. */
export function hookFetchExec(cmd) {
  const s = typeof cmd === 'string' ? cmd : '';
  const fetch = names(FETCH_MARKERS, s); const exec = names(EXEC_MARKERS, s);
  return { fetch, exec, fires: fetch.length > 0 && exec.length > 0 };
}

// ---- the keep list: what the registry manifest points npm at ----
const META = /[`$(){}<>*?![\]'"&#~\\]/;
const BUILTIN = new Set(['cd', 'echo', 'exit', 'true', 'false', 'test', ':', 'export', 'set']);
const NODEISH = new Set(['node', 'bun', 'deno']);
const INTERP = new Set(['node', 'bun', 'deno', 'sh', 'bash', 'zsh', 'python', 'python2', 'python3', 'tsx', 'ts-node', 'zx', 'perl', 'ruby', 'pwsh', 'powershell']);
const SUBCMD = { bun: new Set(['run', 'x']), deno: new Set(['run']) };
const PRELOAD = /^(?:-r|--require|--import|--loader|--experimental-loader)$/; const PRELOAD_EQ = /^(?:--require|--import|--loader|--experimental-loader)=(.+)$/;
const VALUE_FLAGS = new Set(['--stack-size', '--max-old-space-size', '--inspect-port', '--title', '-c', '--config', '--cwd']);
const MAX_SEGMENTS = 50;
/** Local code a hook command loads (the recon hook grammar's targets): [{ path, node }] and the reasons for what was not parsed. */
export function hookTargets(cmd) {
  const out = []; const dropped = [];
  const parts = String(cmd).split(/&&|\|\||;|\||&|\r?\n|\r/).map((s) => s.trim()).filter(Boolean);
  let cwd = '.'; let cwdUnknown = false;
  for (const s of parts.slice(0, MAX_SEGMENTS)) {
    if (META.test(s)) { dropped.push('unsupported hook syntax: quotes or shell syntax not parsed'); continue; }
    const tok = s.split(/\s+/); while (tok.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tok[0])) tok.shift();
    const t0 = tok[0] ?? ''; const targets = [];
    if (t0 === 'cd') { const d = tok[1]; if (!d || d.startsWith('/') || d.startsWith('~')) cwdUnknown = true; else cwd = posix.join(cwd, d); continue; }
    if (BUILTIN.has(t0)) continue;
    if (INTERP.has(t0)) {
      const args = tok.slice(1); let script = null;
      for (let i = 0; i < args.length; i += 1) {
        const a = args[i];
        if (PRELOAD.test(a) && args[i + 1]) { targets.push(args[i + 1]); i += 1; continue; }
        const q = PRELOAD_EQ.exec(a); if (q) { targets.push(q[1]); continue; }
        if (a === '-m' && /^python/.test(t0)) { script = null; break; }
        if (/^-(e|p|-eval|-print|c)$/.test(a)) { script = null; break; }
        if (VALUE_FLAGS.has(a)) { i += 1; continue; } if (a.startsWith('-')) continue;
        if (SUBCMD[t0]?.has(a) && script === null) continue;
        script = a; break;
      }
      if (script) targets.unshift(script);
      for (const t of targets) out.push({ path: cwdUnknown ? null : posix.join(cwd, t), raw: t, node: NODEISH.has(t0), cwdUnknown });
      continue;
    }
    if (t0.includes('/')) out.push({ path: cwdUnknown ? null : posix.join(cwd, t0), raw: t0, node: false, cwdUnknown });
  }
  if (parts.length > MAX_SEGMENTS) dropped.push(`${parts.length - MAX_SEGMENTS} hook segment(s) beyond the grammar limit not parsed`);
  return { targets: out, dropped };
}
const norm = (p) => { const n = posix.normalize(String(p)).replace(/^\.\//, '').replace(/\/+$/, ''); return n === '.' ? '' : n; };
const outside = (n) => n === '' || n === '..' || n.startsWith('../') || n.startsWith('/') || n.includes('\0');
const variants = (n, node) => (node ? [n, `${n}.js`, `${n}.cjs`, `${n}.mjs`, `${n}/index.js`] : [n]);
/**
 * Candidate paths from a manifest (registry, or the tarball package.json): install-hook targets (node-resolution variants), then main
 * (default index.js), then up to 4 bin targets. { source, paths (priority order), roles: { path: [roles] }, hooks, dropped }. Bounded
 * (<= 3 hook targets x 5 variants + 5 main variants + 4 bin); never throws on a hostile manifest.
 */
export function keepListFor(man, source = 'registry manifest') {
  const roles = {}; const paths = []; const dropped = []; const hooks = []; const targets = [];
  const add = (p, role) => { if (!roles[p]) { roles[p] = []; paths.push(p); } if (!roles[p].includes(role)) roles[p].push(role); };
  const addTarget = (p, node, role) => { const vs = variants(p, node); for (const v of vs) add(v, role); targets.push({ path: p, variants: vs, role }); };
  const scripts = isObj(man) && isObj(man.scripts) ? man.scripts : {};
  let n = 0;
  for (const hook of INSTALL_HOOKS) {
    const cmd = scripts[hook]; if (typeof cmd !== 'string' || !pyTruthy(cmd)) continue;
    const g = hookTargets(cmd); const hookPaths = [];
    for (const r of g.dropped) dropped.push({ hook, reason: r });
    for (const t of g.targets) {
      if (t.cwdUnknown || t.path === null) { dropped.push({ hook, path: shownName(t.raw), reason: 'working directory unknown after an earlier segment' }); continue; }
      const p = norm(t.path); if (outside(p)) { dropped.push({ hook, path: shownName(t.raw), reason: 'target outside the package' }); continue; }
      if (n >= LIMITS.maxHookTargets) { dropped.push({ hook, path: shownName(p), reason: `hook targets beyond ${LIMITS.maxHookTargets}` }); continue; }
      n += 1; hookPaths.push(p); addTarget(p, t.node, 'hook');
    }
    hooks.push({ hook, cmd, targets: hookPaths });
  }
  const main = isObj(man) && typeof man.main === 'string' && !outside(norm(man.main)) ? norm(man.main) : 'index.js';
  addTarget(main, true, 'main');
  const bin = isObj(man) ? man.bin : undefined;
  const bins = typeof bin === 'string' ? [bin] : isObj(bin) ? Object.values(bin).filter((v) => typeof v === 'string') : [];
  let nb = 0;
  for (const b of bins) {
    const p = norm(b); if (outside(p)) { dropped.push({ path: shownName(b), reason: 'bin target outside the package' }); continue; }
    if (nb >= LIMITS.maxBin) { dropped.push({ path: shownName(p), reason: `bin targets beyond ${LIMITS.maxBin}` }); continue; }
    nb += 1; addTarget(p, false, 'bin');
  }
  return { source, version: STATIC_CHECKS_VERSION, paths, roles, hooks, targets, dropped };
}

// ---- per-file facts: counts and marker names only ----
/** Facts about one kept body { path, buf }. `binary` (a NUL in the first 8000 bytes) carries no text facts. Never throws. */
export function fileFacts(file) {
  const buf = Buffer.isBuffer(file?.buf) ? file.buf : Buffer.alloc(0);
  const base = { path: file?.path ?? '', size: buf.length };
  if (buf.subarray(0, LIMITS.headBytes).includes(0)) return { ...base, binary: true };
  const s = buf.toString('utf8');
  const idents = new Set(); for (const m of s.matchAll(OBF_IDENT)) idents.add(m[0]);
  let hex = 0; for (const m of s.matchAll(HEX_ESCAPE)) hex += m ? 1 : 0;
  const hexDensity = s.length ? (hex * 4) / s.length : 0;
  const decode = names(DECODE_MARKERS, s); if (CHARCODE_RUN.test(s)) decode.push('fromCharCode-run'); if (hexDensity > LIMITS.s2HexDensity) decode.push('hex-density');
  const sinks = []; if (EXFIL_HOSTS.test(s)) sinks.push('exfil-host'); if (RAW_IP_URL.test(s)) sinks.push('raw-ip');
  const hosts = new Set(); for (const m of s.matchAll(URL_HOST)) hosts.add(m[1].toLowerCase());
  const foreign = [...hosts].filter((h) => !REGISTRY_HOSTS.includes(h) && !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(h));
  if (foreign.length && POST_MARKER.test(s)) sinks.push('post-to-literal-host');
  return { ...base, binary: false, net_sinks: names(NET_SINKS, s), exec_sinks: names(EXEC_SINKS, s), obf_idents: idents.size, decode_markers: decode,
    hex_density: Number(hexDensity.toFixed(3)), cred_sources: names(CRED_SOURCES, s), sinks, overrides: names(OVERRIDES, s), address_families: names(ADDRESS_FAMILIES, s) };
}

// ---- the rows ----
const hookDictOf = (man) => { const out = {}; const s = isObj(man) ? man.scripts : null; if (!isObj(s)) return out; for (const k of INSTALL_HOOKS) if (pyTruthy(s[k])) out[k] = s[k]; return out; };
const platSuffix = (plats) => (plats.length ? `; not checked for ${plats.join(', ')} (another entry installs there)` : '');
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
const ALLOW_TEXT = { S1: (n) => `hook targets carry no loader (${plural(n, 'file')} read)`, S2: (n) => `entry files carry no obfuscation marker pair (${plural(n, 'file')} read)`,
  S3: (n) => `files carry no credential source with a sink (${plural(n, 'file')} read)`, S4: (n) => `entry files carry no override with address regexes (${plural(n, 'file')} read)` };
const NONE_TEXT = { S1: 'no hook target to read', S2: 'no entry file to read', S3: 'no file to read', S4: 'no entry file to read' };
const list = (xs) => xs.join(', ');

/**
 * The five rows for a finished walk. `manifest`: the registry version manifest (what npm acts on; the keep list's source);
 * `packageJson`: the tarball's root package.json, parsed (Linux view), or null; `walk`: the walker result (step 1: `files`, `notKept`).
 * Every row is { gate, result, detail }; the detail never carries publisher text beyond a sanitised path and fixed hook names.
 */
export function staticRows({ manifest, packageJson = null, walk, armed = null }) {
  const suffix = typeof armed === 'string' && armed ? `; armed by ${armed}` : '';
  const row = (c, result, detail) => ({ gate: c.gate, result, detail: clipDetail(`${detail}${suffix}`) });
  if (!walk || !walk.ok) return CHECKS.map((c) => row(c, 'SKIP', `not checked: ${walk?.reason ?? 'the tarball was not walked'}`));
  if (!Array.isArray(walk.files)) return CHECKS.map((c) => row(c, 'SKIP', 'not checked: the tarball was not examined (keep list not armed)'));
  const klReg = keepListFor(manifest); const klTar = keepListFor(packageJson, 'tarball package.json');
  const roles = { ...klTar.roles };
  for (const [p, r] of Object.entries(klReg.roles)) roles[p] = [...new Set([...(roles[p] ?? []), ...r])];
  const primaryOf = {}; for (const t of [...klReg.targets, ...klTar.targets]) for (const v of t.variants) primaryOf[v] ??= t.path;
  const keptPaths = new Set(walk.files.map((f) => f.path));
  const keptPrimary = new Set([...keptPaths].map((p) => primaryOf[p] ?? p));
  const rows = [];
  // S0: the hook commands -- the registry manifest's, and those only the tarball package.json declares (MC says they differ)
  const reg = hookDictOf(manifest); const tar = hookDictOf(packageJson);
  const hooks = Object.entries(reg).map(([hook, cmd]) => ({ src: '', hook, cmd }));
  for (const [hook, cmd] of Object.entries(tar)) if (reg[hook] !== cmd) hooks.push({ src: 'tarball package.json ', hook, cmd });
  const fired = hooks.map((h) => ({ ...h, r: hookFetchExec(h.cmd) })).filter((h) => h.r.fires);
  if (fired.length) rows.push(row(CHECKS[0], 'WARN', `${fired[0].src}${fired[0].hook} command contains a fetch (${list(fired[0].r.fetch)}) and an execute (${list(fired[0].r.exec)})${fired.length > 1 ? `; and ${fired.length - 1} more hook(s)` : ''}`));
  else rows.push(row(CHECKS[0], 'ALLOW', hooks.length ? 'install hooks carry no fetch-and-execute' : 'no install hook'));
  // S1-S4: the kept bodies by role
  const facts = walk.files.map((f) => ({ f, facts: fileFacts(f), roles: roles[f.path] ?? [], shown: shownName(f.path), plats: Array.isArray(f.platformsNotChecked) ? f.platformsNotChecked : [] }));
  // what the walker did not keep, ONE statement per target (its node-resolution variants are the same target; a kept variant settles it);
  // a target only the tarball package.json names was never on the keep list: stated as such, never guessed
  const notKept = []; const stated = new Set();
  for (const x of Array.isArray(walk.notKept) ? walk.notKept : []) {
    if (!x || typeof x.path !== 'string' || !roles[x.path]) continue;
    const prim = primaryOf[x.path] ?? x.path;
    if (keptPrimary.has(prim) || stated.has(prim)) continue;
    if (/^not in the archive/.test(String(x.reason)) && x.path !== prim) continue;        // an absent variant is not news; the primary says it
    stated.add(prim); notKept.push({ path: prim, reason: x.reason });
  }
  for (const t of klTar.targets) if (!klReg.roles[t.path] && !keptPrimary.has(t.path) && !stated.has(t.path)) { stated.add(t.path); notKept.push({ path: t.path, reason: 'named by the tarball package.json only (not kept)' }); }
  for (const c of CHECKS.slice(1)) {
    const mine = facts.filter((x) => c.roles.some((r) => x.roles.includes(r)));
    const skipped = notKept.filter((x) => c.roles.some((r) => (roles[x.path] ?? []).includes(r))).map((x) => `${shownName(x.path)} ${x.reason}`);
    const hits = []; const platsRead = new Set(); let read = 0;
    for (const x of mine) {
      const F = x.facts;
      if (F.binary) { skipped.push(`${x.shown} is binary (a NUL in the first ${LIMITS.headBytes} bytes)`); continue; }
      if (c.id === 'S1' && F.size > LIMITS.s1MaxBytes) { skipped.push(`${x.shown} over 8 KiB (a loader stub is small)`); continue; }
      read += 1; for (const p of x.plats) platsRead.add(p);
      let detail = null;
      if (c.id === 'S1' && F.net_sinks.length && F.exec_sinks.length) detail = `hook target ${x.shown} (${F.size} B) has a network sink (${list(F.net_sinks)}) and an execution sink (${list(F.exec_sinks)})`;
      else if (c.id === 'S2' && F.obf_idents >= LIMITS.s2MinIdents && F.decode_markers.length) detail = `entry file ${x.shown} (${F.size} B) has ${F.obf_idents} _0x identifiers and a decode marker (${list(F.decode_markers)})`;
      else if (c.id === 'S3' && F.cred_sources.length && F.sinks.length) detail = `${x.shown} (${F.size} B) has a credential source (${list(F.cred_sources)}) and an outbound sink (${list(F.sinks)})`;
      else if (c.id === 'S4' && F.overrides.length && F.address_families.length >= LIMITS.s4MinAddressFamilies) detail = `entry file ${x.shown} (${F.size} B) has an override (${list(F.overrides)}) and ${F.address_families.length} address-regex families (${list(F.address_families)})`;
      if (detail) hits.push({ detail, plats: x.plats });
    }
    if (hits.length) rows.push(row(c, 'WARN', `${hits[0].detail}${hits.length > 1 ? `; and ${hits.length - 1} more file(s)` : ''}${platSuffix(hits[0].plats)}`));
    else if (skipped.length) rows.push(row(c, 'SKIP', `not checked: ${skipped[0]}${skipped.length > 1 ? `; and ${skipped.length - 1} more` : ''}`));
    else rows.push(row(c, 'ALLOW', `${read ? ALLOW_TEXT[c.id](read) : NONE_TEXT[c.id]}${platSuffix([...platsRead])}`));
  }
  return rows;
}

// ---- the trigger (operator ruling 2026-10-13, design note §3) and the retry rule ----
/**
 * Why a download's keep-list walk is armed, from the version's recorded rows: a NAMED WARN row (the runner's named gates, or a seed-v3
 * named row), the identity-break NOTE, or the seed's coverage WARN (nothing in the finding was evaluated: the brand-new-package case).
 * Any other contributing row, or nothing, returns null. Pure; never throws on a malformed list.
 */
export function armedBy(results) {
  let cls; try { cls = classify(results); } catch { return null; }
  if (cls.named.length) return `named row${cls.named.length > 1 ? 's' : ''} ${cls.named.join(', ')}`;
  if (cls.contributing.includes('identity-break')) return 'identity-break';
  if (cls.coverage.includes('seed-v3:coverage')) return 'seed coverage WARN (nothing in the finding was evaluated)';
  return null;
}
const RETRY_PREFIXES = ['not checked: not armed', 'not checked: no registry manifest at hand'];
/** The five rows of a walk that was not armed (or could not be: the concurrency ceiling), with the reason; retried when a later download is armed. */
export const unarmedRows = (why) => CHECKS.map((c) => ({ gate: c.gate, result: 'SKIP', detail: clipDetail(`not checked: not armed (${why})`) }));
/** The five rows of an armed walk whose registry manifest was not at hand (no keep list); retried, as MC's own "not checked" is. */
export const noManifestRows = (armed) => CHECKS.map((c) => ({ gate: c.gate, result: 'SKIP', detail: clipDetail(`not checked: no registry manifest at hand; armed by ${armed}`) }));
/** Whether the record's static rows are FINAL: all five present and none a retryable "not checked". A walked outcome, WARN, ALLOW or a
 *  SKIP for the tarball's own shape, is final: tarballs are immutable per version. */
export function staticSettled(latest) {
  const rows = Array.isArray(latest?.gates_fired) ? latest.gates_fired : [];
  const mine = STATIC_GATES.map((g) => rows.find((r) => r && r.gate === g));
  if (mine.some((r) => !r)) return false;
  return mine.every((r) => typeof r.detail === 'string' && !RETRY_PREFIXES.some((p) => r.detail.startsWith(p)));
}

export default { STATIC_CHECKS_VERSION, LIMITS, CHECKS, STATIC_GATES, MAX_ARMED_WALKS, hookFetchExec, hookTargets, keepListFor, fileFacts, staticRows, shownName, armedBy, unarmedRows, noManifestRows, staticSettled };
