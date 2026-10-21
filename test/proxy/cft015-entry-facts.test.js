// 0.1.5 per-version entry facts store (operator ruling R4 2026-10-21, option (a); design FOLLOWUPS #24). On every download, armed
// or not, the proxy keeps the bodies of the main and bin targets, computes the fileFacts summary of each and stores it once per
// served version in witness.db: role, path, size, sha256, the closed-vocabulary facts, and whether the file was read. S7 (R3)
// compares a version's entry files with those of the last version this proxy served before it; with none stored it is a cold start.
// Retention: the newest 3 served versions per package, and at most 200,000 served versions in all. Failing first: written before
// the code. Tarballs are synthetic; nothing is run.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import Database from 'better-sqlite3';
import { createProxyServer } from '../../proxy/server.js';
import { resetDependencyCache } from '../../gates/dependency-cache.js';
import { forgetManifestHooks } from '../../proxy/manifest-check.js';
import { openWitnessDB } from '../../witness/db.js';
import { walkerStats } from '../../proxy/tar-walk.js';

const SC = () => import('../../proxy/static-checks.js');

const H = 3_600_000; const T0 = Date.parse('2026-03-01T00:00:00Z'); const at = (h) => new Date(T0 + h * H).toISOString();
function hdr(name, size) {
  const h = Buffer.alloc(512, 0); Buffer.from(name, 'utf8').copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116); h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  h.write('00000000000\0', 136); h.write('        ', 148); h.write('0', 156, 'latin1'); h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1');
  let sum = 0; for (let i = 0; i < 512; i += 1) sum += h[i]; h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1'); return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]);
const tgz = (files) => zlib.gzipSync(Buffer.concat([...Object.entries(files).flatMap(([p, c]) => [hdr(`package/${p}`, Buffer.byteLength(c)), pad(Buffer.from(c))]), Buffer.alloc(1024, 0)]));
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const BENIGN = 'module.exports = 1;\n';
const NETTY = 'const https = require("https");\nhttps.request({ host: "h" }).end(require("os").hostname());\n';
const FACT_KEYS = ['binary', 'net_sinks', 'exec_sinks', 'obf_idents', 'decode_markers', 'hex_density', 'numeric_hex', 'cred_sources', 'sinks', 'overrides',
  'address_families', 'identity_sources'];

// g: two plain versions, nothing named or contributing -> NOT armed; main index.js, one bin
const G = { name: 'g', 'dist-tags': { latest: '1.1.0' }, time: { '1.0.0': at(0), '1.1.0': at(48) },
  versions: { '1.0.0': { name: 'g', version: '1.0.0', main: 'index.js', bin: { g: 'cli.js' } }, '1.1.0': { name: 'g', version: '1.1.0', main: 'index.js', bin: { g: 'cli.js' } } } };
// k: one plain version served slowly, for the timing of the facts pass
const K = { name: 'k', 'dist-tags': { latest: '1.0.0' }, time: { '1.0.0': at(0) }, versions: { '1.0.0': { name: 'k', version: '1.0.0', main: 'index.js' } } };
const DOCS = { '/g': G, '/k': K };
const SLOW = { '/k/-/k-1.0.0.tgz': tgz({ 'package.json': JSON.stringify(K.versions['1.0.0']), 'index.js': BENIGN, 'pad.txt': crypto.randomBytes(64 * 1024).toString('hex') }) };
const TARBALLS = {
  '/g/-/g-1.0.0.tgz': tgz({ 'package.json': JSON.stringify(G.versions['1.0.0']), 'index.js': BENIGN, 'cli.js': BENIGN }),
  '/g/-/g-1.1.0.tgz': tgz({ 'package.json': JSON.stringify(G.versions['1.1.0']), 'index.js': NETTY, 'cli.js': BENIGN }),
};
async function withProxy(fn) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-ef-'));
  const upstream = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    if (SLOW[u]) {                                            // half now, the rest 300 ms later: the client sees the download in flight
      const b = SLOW[u]; const h = Math.floor(b.length / 2);
      res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.write(b.subarray(0, h)); setTimeout(() => res.end(b.subarray(h)), 300); return;
    }
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
function withDb(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-efdb-'));
  const db = openWitnessDB(path.join(dir, 'witness.db')); db.applySchema();
  try { return fn(db, dir); } finally { db.close(); fs.rmSync(dir, { recursive: true, force: true }); }
}
const rec = (version, files = [{ role: 'main', path: 'index.js', state: 'read', size_bytes: 20, sha256: sha(BENIGN), facts: { net_sinks: [] } }], extra = {}) =>
  ({ package_name: 'a', version, walk: 'read', reason: null, static_checks_version: 'static-checks-1.3', files, ...extra });

// ------------------------------------------------------------------ the store (witness/db.js)
test('EF-U1 recordEntryFacts writes once per version; hasEntryFacts and the predecessor read it back', () => withDb((db) => {
  assert.equal(db.hasEntryFacts('a', '1.0.0'), false);
  assert.equal(db.recordEntryFacts(rec('1.0.0')), 'wrote');
  assert.equal(db.hasEntryFacts('a', '1.0.0'), true);
  assert.equal(db.recordEntryFacts(rec('1.0.0', [])), 'exists', 'tarballs are immutable per version: a second write changes nothing');
  assert.equal(db.predecessorEntryFacts('a', '1.0.0'), null, 'cold start: no other version served');
  assert.equal(db.recordEntryFacts(rec('1.1.0')), 'wrote');
  const p = db.predecessorEntryFacts('a', '1.1.0');
  assert.equal(p.version, '1.0.0'); assert.equal(p.walk, 'read'); assert.equal(p.static_checks_version, 'static-checks-1.3');
  assert.equal(p.files.length, 1);
  assert.deepEqual({ ...p.files[0], facts: p.files[0].facts }, { role: 'main', path: 'index.js', state: 'read', size_bytes: 20, sha256: sha(BENIGN), facts: { net_sinks: [] }, reason: null });
  assert.equal(db.predecessorEntryFacts('b', '1.0.0'), null, 'another package is never a predecessor');
}));

test('EF-U2 the predecessor is the last version SERVED before, by serving order, not by version number', () => withDb((db) => {
  db.recordEntryFacts(rec('2.0.0')); db.recordEntryFacts(rec('1.5.0'));
  assert.equal(db.predecessorEntryFacts('a', '3.0.0').version, '1.5.0');
  assert.equal(db.predecessorEntryFacts('a', '1.5.0').version, '2.0.0', 'the current version itself is never its own predecessor');
}));

test('EF-U3 a refused archive is stored as such, with no files, so S7 can say NOT_CHECKED rather than a clean delta', () => withDb((db) => {
  db.recordEntryFacts(rec('1.0.0', [], { walk: 'refused', reason: 'tar: truncated archive' }));
  const p = db.predecessorEntryFacts('a', '1.1.0');
  assert.equal(p.walk, 'refused'); assert.equal(p.reason, 'tar: truncated archive'); assert.deepEqual(p.files, []);
}));

test('EF-U4 retention: the newest 3 served versions per package are kept; a global cap prunes the oldest served first', () => withDb((db) => {
  for (const v of ['1.0.0', '1.1.0', '1.2.0', '1.3.0', '1.4.0']) db.recordEntryFacts(rec(v));
  assert.deepEqual(['1.0.0', '1.1.0', '1.2.0', '1.3.0', '1.4.0'].map((v) => db.hasEntryFacts('a', v)), [false, false, true, true, true]);
  for (const v of ['1.0.0', '1.1.0']) db.recordEntryFacts({ ...rec(v), package_name: 'b' }, { maxVersions: 4 });
  assert.equal(db.hasEntryFacts('a', '1.2.0'), false, 'over the global cap: the oldest served version goes first');
  assert.equal(db.hasEntryFacts('b', '1.1.0'), true);
  assert.equal(db.hasEntryFacts('a', '1.4.0'), true);
}));

test('EF-U5 a witness.db written by an older runtime (no entry facts tables) reads as empty and never throws', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-efold-'));
  try {
    const p = path.join(dir, 'w.db'); new Database(p).close();
    const db = openWitnessDB(p, { readonly: true });
    try { assert.equal(db.hasEntryFacts('a', '1.0.0'), false); assert.equal(db.predecessorEntryFacts('a', '1.0.0'), null); } finally { db.close(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------ the facts of one walk (proxy/static-checks.js)
test('EF-U6 entryFactsOf: one entry per main and bin target, read with sha256 and closed-vocabulary facts, or not read with its reason', async () => {
  const S = await SC();
  const manifest = { name: 'g', main: 'index.js', bin: { g: 'cli.js', h: 'big.js' } };
  const walk = { ok: true, files: [{ path: 'index.js', buf: Buffer.from(NETTY) }],
    notKept: [{ path: 'big.js', reason: 'over the kept-file cap (1048576 bytes)', size: 2_000_000 }, { path: 'cli.js', reason: 'not in the archive' }] };
  const out = S.entryFactsOf({ manifest, walk });
  assert.equal(out.walk, 'read');
  const main = out.files.find((f) => f.role === 'main');
  assert.equal(main.path, 'index.js'); assert.equal(main.state, 'read'); assert.equal(main.size_bytes, Buffer.byteLength(NETTY)); assert.equal(main.sha256, sha(NETTY));
  assert.deepEqual(Object.keys(main.facts).sort(), [...FACT_KEYS].sort(), 'facts only: never the path, the size or text from the body');
  assert.ok(main.facts.net_sinks.length > 0, JSON.stringify(main.facts));
  const big = out.files.find((f) => f.path === 'big.js');
  assert.equal(big.role, 'bin'); assert.equal(big.state, 'not-read'); assert.equal(big.size_bytes, 2_000_000); assert.equal(big.sha256, null); assert.equal(big.facts, null);
  assert.match(big.reason, /kept-file cap/);
  const cli = out.files.find((f) => f.path === 'cli.js');
  assert.equal(cli.state, 'absent');
  assert.deepEqual(S.entryFactsOf({ manifest, walk: { ok: false, reason: 'tar: truncated archive' } }), { walk: 'refused', reason: 'tar: truncated archive', files: [] });
});

test('EF-U7 entryKeepFor lists only main and bin targets (with node-resolution variants for main), never hook targets', async () => {
  const S = await SC();
  const keep = S.entryKeepFor({ name: 'g', main: './lib/x', bin: 'cli.js', scripts: { postinstall: 'node install.js' } });
  assert.ok(keep.includes('lib/x') && keep.includes('lib/x.js') && keep.includes('cli.js'), JSON.stringify(keep));
  assert.ok(!keep.includes('install.js'));
  assert.ok(S.entryKeepFor(null).includes('index.js'), 'no manifest at all: main defaults to index.js');
});

// ------------------------------------------------------------------ the proxy (every download, armed or not)
test('EF-E1 an UNARMED download stores its entry facts once; the next version finds it as predecessor; a repeat writes nothing', async () => {
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/g`);
    const t = await get(`${base}/g/-/g-1.0.0.tgz`); assert.equal(t.status, 200); assert.ok(t.body.equals(TARBALLS['/g/-/g-1.0.0.tgz']));
    await settle();
    assert.equal(proxy.witnessDb.hasEntryFacts('g', '1.0.0'), true);
    assert.match(proxy.witnessDb.getLatestDecision('g', '1.0.0').gates_fired.find((r) => r.gate === 'static:S1-loader-in-hook-target')?.detail ?? 'not checked: not armed', /^not checked: not armed/, 'storing facts arms nothing');
    await get(`${base}/g/-/g-1.1.0.tgz`); await settle();
    const p = proxy.witnessDb.predecessorEntryFacts('g', '1.1.0');
    assert.equal(p?.version, '1.0.0');
    const main = p.files.find((f) => f.role === 'main'); assert.equal(main.state, 'read'); assert.equal(main.sha256, sha(BENIGN));
    assert.equal(p.files.find((f) => f.role === 'bin')?.path, 'cli.js');
    const n = new Database(proxy.witnessDb.db.name, { readonly: true });
    try {
      const before = n.prepare('SELECT COUNT(*) AS c FROM entry_facts').get().c;
      await get(`${base}/g/-/g-1.0.0.tgz`); await settle();
      assert.equal(n.prepare('SELECT COUNT(*) AS c FROM entry_facts').get().c, before, 'a version is written once');
    } finally { n.close(); }
  });
});

// The first download of a version walks in-stream for MC (0.1.4, unchanged) and its facts ride that walk. A walk for the facts ALONE
// (MC already settled, no facts stored: a witness.db from before R4) runs after the response (review verdict 2026-10-21, M6).
test('EF-E2 a facts-only walk runs AFTER the response: no walker while the bytes are in flight; the facts are stored after', async () => {
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/k`); await get(`${base}/k/-/k-1.0.0.tgz`); await settle();
    assert.equal(proxy.witnessDb.hasEntryFacts('k', '1.0.0'), true, 'the first download stores them from the MC walk');
    proxy.witnessDb.db.prepare('DELETE FROM entry_fact_versions').run();       // as on a witness.db written before R4
    const before = walkerStats().created; let during = null;
    const body = await new Promise((resolve, reject) => http.get(`${base}/k/-/k-1.0.0.tgz`, { agent: false }, (res) => {
      const chunks = []; res.on('data', (x) => { if (during === null) during = walkerStats().created; chunks.push(x); });
      res.on('end', () => resolve(Buffer.concat(chunks)));
    }).on('error', reject));
    assert.ok(body.equals(SLOW['/k/-/k-1.0.0.tgz']), 'served as is');
    assert.equal(during, before, 'no walk started while the download was in flight');
    await settle();
    assert.equal(proxy.witnessDb.hasEntryFacts('k', '1.0.0'), true, 'the facts are stored once the response has finished');
    assert.equal(proxy.witnessDb.predecessorEntryFacts('k', '9.9.9').files.find((f) => f.role === 'main').state, 'read');
  });
});
