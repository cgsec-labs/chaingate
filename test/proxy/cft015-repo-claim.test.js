// 0.1.5 recorded fact: the repository claim. On an ARMED first download, after the response, the proxy reads the registry's
// attestation bundle for the version (/-/npm/v1/attestations/<pkg>@<ver>), decodes the SLSA provenance statement and compares the
// build workflow's repository with the version's `repository` field in the package metadata, both in one normal form
// (host/owner/repo, lower case). Outcomes: MATCH, MISMATCH, ABSENT (the version this proxy served before had provenance, this one has
// none), NONE (neither has), NOT_FETCHED with the reason. No signature is verified. Recorded only: no verdict, tier or notice depends
// on it, the fetch is bounded (time, bytes, in flight) and never delays or fails a download. Stored beside the version's entry facts
// with its time, shown by `why` and `report`. Failing first: written before the code. Tarballs are synthetic; nothing is run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { createProxyServer } from '../../proxy/server.js';
import { openWitnessDB } from '../../witness/db.js';
import { resetDependencyCache } from '../../gates/dependency-cache.js';
import { forgetManifestHooks } from '../../proxy/manifest-check.js';

const SF = () => import('../../proxy/shadow-facts.js');
const CLI = fileURLToPath(new URL('../../cli/index.js', import.meta.url));
const INTERNAL = /operator|ruling|recon|\bR1[0-9]\b|rule 4a/i;
const ascii = (s) => s.split('').every((ch) => ch.charCodeAt(0) < 0x80);

// ------------------------------------------------------------------ bundles
const SLSA_V1 = 'https://slsa.dev/provenance/v1';
const SLSA_V02 = 'https://slsa.dev/provenance/v0.2';
const PUBLISH = 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1';
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64');
const v1 = (repository) => ({ predicateType: SLSA_V1, bundle: { dsseEnvelope: { payload: b64({ _type: 'https://in-toto.io/Statement/v1', predicateType: SLSA_V1,
  predicate: { buildDefinition: { externalParameters: { workflow: { repository, path: '.github/workflows/release.yml', ref: 'refs/heads/main' } } } } }) } } });
const v02 = (uri) => ({ predicateType: SLSA_V02, bundle: { dsseEnvelope: { payload: b64({ predicateType: SLSA_V02, predicate: { invocation: { configSource: { uri, entryPoint: 'release.yml' } } } }) } } });
const publish = () => ({ predicateType: PUBLISH, bundle: { dsseEnvelope: { payload: b64({ predicateType: PUBLISH, predicate: { name: 'z', version: '1.1.0' } }) } } });
const bundle = (...a) => Buffer.from(JSON.stringify({ attestations: a }));

test('A1 normRepoUrl: one normal form, host/owner/repo in lower case, for every npm repository spelling; null for what it does not read', async () => {
  const { normRepoUrl } = await SF();
  const cases = [
    ['git+https://github.com/O/R.git', 'github.com/o/r'], [{ type: 'git', url: 'https://github.com/o/r/tree/main/packages/x' }, 'github.com/o/r'],
    ['git://github.com/o/r.git', 'github.com/o/r'], ['ssh://git@github.com/o/r.git', 'github.com/o/r'], ['git@github.com:o/r.git', 'github.com/o/r'],
    ['github:o/r', 'github.com/o/r'], ['gitlab:g/p', 'gitlab.com/g/p'], ['bitbucket:t/r', 'bitbucket.org/t/r'], ['o/r', 'github.com/o/r'],
    ['https://gitlab.com/g/sub/p/-/tree/main', 'gitlab.com/g/sub/p'], ['https://github.com/o/r#readme', 'github.com/o/r'],
    ['https://github.com/o/r?x=1', 'github.com/o/r'], ['https://www.github.com/o/r', 'github.com/o/r'], ['https://GitHub.com/O/R', 'github.com/o/r'],
    ['git+ssh://git@gitlab.com/g/p.git', 'gitlab.com/g/p'],
    [null, null], [42, null], ['', null], ['not a url', null], ['https://github.com/o', null], ['ftp://example.com/o/r', null], [{ url: 5 }, null],
    ['https://github.com/o/../r', null], [`https://github.com/o/${'r'.repeat(600)}`, null],
  ];
  for (const [x, want] of cases) assert.equal(normRepoUrl(x), want, JSON.stringify(x));
});

test('A2 attestationRepository: the SLSA v1 workflow repository, the v0.2 source address without its ref; the reason when there is none', async () => {
  const { attestationRepository } = await SF();
  assert.deepEqual(attestationRepository(bundle(publish(), v1('https://github.com/o/r'))), { repository: 'https://github.com/o/r', reason: null });
  assert.deepEqual(attestationRepository(bundle(v02('git+https://github.com/o/r@refs/heads/main'))), { repository: 'https://github.com/o/r', reason: null });
  assert.deepEqual(attestationRepository(bundle(v1('https://github.com/a/b'), v1('https://github.com/c/d'))), { repository: 'https://github.com/a/b', reason: null }, 'the first');
  const r = (b) => attestationRepository(b).reason;
  assert.match(r(bundle(publish())), /no SLSA provenance in the bundle/);
  assert.match(r(bundle({ predicateType: SLSA_V1, bundle: { dsseEnvelope: { payload: '!!not base64 json' } } })), /no SLSA provenance in the bundle/);
  assert.match(r(bundle()), /no attestations in the bundle/);
  assert.match(r(Buffer.from('<html>')), /the bundle is not JSON/);
  assert.match(r(bundle(v1(''))), /the provenance names no repository/);
  assert.match(r(bundle({ predicateType: SLSA_V1, bundle: { dsseEnvelope: { payload: b64({ predicate: {} }) } } })), /the provenance names no repository/);
  assert.equal(attestationRepository(bundle(v1(`https://github.com/o/${'x'.repeat(400)}`))).repository.length, 200, 'clipped');
});

// ------------------------------------------------------------------ the fact, over remembered package metadata
const H = 3_600_000; const T0 = Date.parse('2026-03-01T00:00:00Z'); const at = (h) => new Date(T0 + h * H).toISOString();
const ATT = (name, v) => ({ url: `https://registry.npmjs.org/-/npm/v1/attestations/${name}@${v}`, provenance: { predicateType: SLSA_V1 } });
// versions: { '1.0.0': { att, repo }, ... }; att true = dist.attestations present
function meta(name, versions) {
  const vs = Object.keys(versions);
  return { name, 'dist-tags': { latest: vs[vs.length - 1] }, time: Object.fromEntries(vs.map((v, i) => [v, at(i * 48)])),
    versions: Object.fromEntries(vs.map((v) => [v, { name, version: v, main: 'index.js', ...(versions[v].repo !== undefined ? { repository: versions[v].repo } : {}),
      ...(versions[v].scripts ? { scripts: versions[v].scripts } : {}), dist: { tarball: `x/${name}-${v}.tgz`, ...(versions[v].att ? { attestations: ATT(name, v) } : {}) } }])) };
}
async function claim(doc, version, predecessor, reply) {
  const S = await SF(); S.forgetPackumentFacts(); S.rememberPackumentFacts(doc.name, doc);
  const calls = [];
  const f = await S.repoClaimFact({ memo: S.packumentFactsFor(doc.name), version, predecessor,
    fetchBundle: async (name, v) => { calls.push(`${name}@${v}`); return reply; } });
  return { f, calls };
}
const R = 'git+https://github.com/o/r.git';

test('A3 repoClaimFact: MATCH and MISMATCH read the bundle; ABSENT and NONE never fetch; NOT_FETCHED carries the reason', async () => {
  const ok = (repo) => ({ ok: true, bytes: bundle(v1(repo)) });
  let x = await claim(meta('z', { '1.0.0': { att: true, repo: R }, '1.1.0': { att: true, repo: R } }), '1.1.0', '1.0.0', ok('https://github.com/O/R'));
  assert.equal(x.f.outcome, 'MATCH'); assert.deepEqual(x.calls, ['z@1.1.0']);
  assert.equal(x.f.attestation_repository, 'github.com/o/r'); assert.equal(x.f.packument_repository, 'github.com/o/r'); assert.equal(x.f.version, 'repo-claim-1.0');
  x = await claim(meta('z', { '1.1.0': { att: true, repo: { type: 'git', url: R } } }), '1.1.0', null, ok('https://github.com/evil/r'));
  assert.equal(x.f.outcome, 'MISMATCH'); assert.equal(x.f.attestation_repository, 'github.com/evil/r'); assert.equal(x.f.vs, null);
  x = await claim(meta('z', { '1.0.0': { att: true, repo: R }, '1.1.0': { att: false, repo: R } }), '1.1.0', '1.0.0', ok('x'));
  assert.equal(x.f.outcome, 'ABSENT'); assert.equal(x.f.vs, '1.0.0'); assert.deepEqual(x.calls, [], 'no attestation on this version: nothing fetched');
  x = await claim(meta('z', { '1.0.0': { att: false, repo: R }, '1.1.0': { att: false, repo: R } }), '1.1.0', '1.0.0', ok('x'));
  assert.equal(x.f.outcome, 'NONE'); assert.deepEqual(x.calls, []);
  x = await claim(meta('z', { '1.0.0': { att: true, repo: R }, '1.1.0': { att: false, repo: R } }), '1.1.0', null, ok('x'));
  assert.equal(x.f.outcome, 'NONE', 'no version served before: nothing was dropped');
  const nf = async (doc, reply, re, version = '1.1.0') => {
    const y = await claim(doc, version, null, reply);
    assert.equal(y.f.outcome, 'NOT_FETCHED', JSON.stringify(y.f)); assert.match(y.f.reason, re);
  };
  const D = meta('z', { '1.1.0': { att: true, repo: R } });
  await nf(D, { ok: false, reason: 'HTTP 404' }, /^HTTP 404$/);
  await nf(D, { ok: false, reason: 'timeout after 5000 ms' }, /timeout/);
  await nf(D, { ok: true, bytes: Buffer.from('nope') }, /the bundle is not JSON/);
  await nf(D, { ok: true, bytes: bundle(publish()) }, /no SLSA provenance/);
  await nf(D, { ok: true, bytes: bundle(v1('not a url')) }, /the provenance repository is not a URL this proxy reads/);
  await nf(meta('z', { '1.1.0': { att: true } }), ok('https://github.com/o/r'), /the package metadata has no repository field/);
  await nf(meta('z', { '1.1.0': { att: true, repo: 'not a url' } }), ok('https://github.com/o/r'), /the package metadata repository field is not a URL this proxy reads/);
  await nf(D, ok('https://github.com/o/r'), /the version is not in the package metadata/, '9.9.9');
  const S = await SF(); S.forgetPackumentFacts();
  const none = await S.repoClaimFact({ memo: undefined, version: '1.1.0', predecessor: null, fetchBundle: async () => { throw new Error('not called'); } });
  assert.equal(none.outcome, 'NOT_FETCHED'); assert.match(none.reason, /the package metadata is not at hand/);
  const thrown = await S.repoClaimFact({ memo: (S.rememberPackumentFacts('z', D), S.packumentFactsFor('z')), version: '1.1.0', predecessor: null,
    fetchBundle: async () => { throw new Error('boom'); } });
  assert.equal(thrown.outcome, 'NOT_FETCHED', 'a throwing fetch is a reason, never an error'); assert.match(thrown.reason, /boom/);
});

test('A4 repoClaimLine: the outcome in plain words ("repository claim matches, unverified", "repository claim differs", "provenance dropped"); plain ASCII', async () => {
  const { repoClaimLine } = await SF();
  const base = { version: 'repo-claim-1.0', attestation_repository: 'github.com/o/r', packument_repository: 'github.com/o/r', vs: '1.0.0' };
  const lines = {
    MATCH: repoClaimLine({ ...base, outcome: 'MATCH' }),
    MISMATCH: repoClaimLine({ ...base, outcome: 'MISMATCH', attestation_repository: 'github.com/evil/r' }),
    ABSENT: repoClaimLine({ ...base, outcome: 'ABSENT', attestation_repository: null }),
    NONE: repoClaimLine({ ...base, outcome: 'NONE', attestation_repository: null }),
    NOT_FETCHED: repoClaimLine({ ...base, outcome: 'NOT_FETCHED', attestation_repository: null, reason: 'HTTP 404' }),
  };
  assert.match(lines.MATCH, /^repository claim matches, unverified: github\.com\/o\/r/);
  assert.match(lines.MISMATCH, /^repository claim differs: the provenance names github\.com\/evil\/r, the package metadata github\.com\/o\/r/);
  assert.match(lines.ABSENT, /^provenance dropped: 1\.0\.0 \(the version this proxy served before\) had provenance, this version has none/);
  assert.match(lines.NONE, /^no provenance on this release or the one before/);
  assert.match(lines.NOT_FETCHED, /^repository claim not read \(HTTP 404\)/);
  for (const l of Object.values(lines)) { assert.ok(ascii(l), l); assert.doesNotMatch(l, INTERNAL, l); }
  assert.match(repoClaimLine(null), /not recorded/);
  assert.ok(!repoClaimLine({ ...base, outcome: 'MISMATCH', attestation_repository: 'github.com/a/b\u202e' }).includes('\u202e'), 'control and bidi characters dropped');
});

// ------------------------------------------------------------------ the store
function withDb(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-rc-'));
  const db = openWitnessDB(path.join(dir, 'witness.db')); db.applySchema();
  try { return fn(db); } finally { db.close(); fs.rmSync(dir, { recursive: true, force: true }); }
}
const rec = (v) => ({ package_name: 'a', version: v, walk: 'read', static_checks_version: 'static-checks-1.6', files: [] });

test('A5 the store: recordRepoClaim(p, v, x, ms) once beside the entry facts, with its time; an old table gains the columns; a read-only old one reads null', () => {
  withDb((db) => {
    db.recordEntryFacts(rec('1.0.0'));
    assert.equal(db.repoClaimFor('a', '1.0.0'), null);
    const x = { version: 'repo-claim-1.0', outcome: 'MATCH', attestation_repository: 'github.com/o/r', packument_repository: 'github.com/o/r', vs: null };
    assert.equal(db.recordRepoClaim('a', '1.0.0', x, 41.5), 1);
    assert.equal(db.recordRepoClaim('a', '1.0.0', { ...x, outcome: 'NONE' }, 1), 0, 'once per version');
    assert.deepEqual(db.repoClaimFor('a', '1.0.0'), x);
    assert.equal(db.db.prepare("SELECT repo_claim_ms FROM entry_fact_versions WHERE version = '1.0.0'").get().repo_claim_ms, 41.5);
    assert.equal(db.recordRepoClaim('a', '9.9.9', x, 1), 0, 'no entry facts row: nothing written');
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-rcm-'));
  try {
    const p = path.join(dir, 'w.db'); const raw = new Database(p);
    raw.exec(`CREATE TABLE entry_fact_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, package_name TEXT NOT NULL, version TEXT NOT NULL,
      served_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), walk TEXT NOT NULL CHECK (walk IN ('read','refused')), reason TEXT,
      static_checks_version TEXT NOT NULL, facts_ms REAL, shape TEXT, shadow TEXT, static_facts TEXT, static_facts_ms REAL, UNIQUE (package_name, version));
      INSERT INTO entry_fact_versions (package_name, version, walk, static_checks_version) VALUES ('a', '0.9.0', 'read', 'static-checks-1.6');`);
    raw.close();
    const ro = openWitnessDB(p, { readonly: true });
    try { assert.equal(ro.repoClaimFor('a', '0.9.0'), null, 'no column: null, no throw'); } finally { ro.close(); }
    const db = openWitnessDB(p); db.applySchema();
    try { assert.equal(db.recordRepoClaim('a', '0.9.0', { outcome: 'NONE' }, 0.5), 1); } finally { db.close(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------ end to end
function hdr(name, size) {
  const h = Buffer.alloc(512, 0); Buffer.from(name, 'utf8').copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116); h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  h.write('00000000000\0', 136); h.write('        ', 148); h.write('0', 156, 'latin1'); h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1');
  let sum = 0; for (let i = 0; i < 512; i += 1) sum += h[i]; h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1'); return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]);
const tgz = (files) => zlib.gzipSync(Buffer.concat([...Object.entries(files).flatMap(([p, c]) => { const b = Buffer.from(c); return [hdr(`package/${p}`, b.length), pad(b)]; }), Buffer.alloc(1024, 0)]));
// 1.1.0 adds an install hook 48 h after a hookless 1.0.0: install-introduced WARN (named), so its walk is armed
const HOOK = { postinstall: 'node install.js' };
const armedDoc = (name, att10, att11, repo11 = R) => meta(name, { '1.0.0': { att: att10, repo: R }, '1.1.0': { att: att11, repo: repo11, scripts: HOOK } });
const DOCS = {
  z: armedDoc('z', false, true), w: armedDoc('w', false, true), y: armedDoc('y', true, false), n: armedDoc('n', false, false),
  t: armedDoc('t', false, true), e: armedDoc('e', false, true), b: armedDoc('b', false, true), k: armedDoc('k', false, true), j: armedDoc('j', false, true), c: armedDoc('c', false, true),
  q: meta('q', { '1.0.0': { att: false, repo: R }, '1.1.0': { att: true, repo: R } }),                      // no hook: never armed
};
const tarOf = (name, v) => { const man = DOCS[name].versions[v]; return tgz({ 'package.json': JSON.stringify(man), 'index.js': 'module.exports = 1;\n', ...(man.scripts ? { 'install.js': 'console.log(1);\n' } : {}) }); };
const TARBALLS = Object.fromEntries(Object.keys(DOCS).flatMap((n) => ['1.0.0', '1.1.0'].map((v) => [`/${n}/-/${n}-${v}.tgz`, tarOf(n, v)])));
// what the fake registry's attestation endpoint answers, per package
const ATTEST = {
  z: (res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(bundle(publish(), v1('https://github.com/o/r'))); },
  w: (res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(bundle(v1('https://github.com/evil/r'))); },
  t: () => { /* never answers */ },
  e: (res) => { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); },
  b: (res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(bundle(v1(`https://github.com/o/${'r'.repeat(5000)}`))); },
  k: (res) => { res.writeHead(200, { 'content-type': 'application/json' }); for (let i = 0; i < 10; i += 1) res.write(' '.repeat(500)); res.end('{}'); },   // no length
  j: (res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('<html>'); },
  c: (res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(bundle(v1('https://github.com/o/r'))); },
  q: (res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(bundle(v1('https://github.com/o/r'))); },
};
async function withProxy(config, fn) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-rce-'));
  const seen = []; const hanging = [];
  const upstream = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    const m = /^\/-\/npm\/v1\/attestations\/(.+)@([^@]+)$/.exec(u);
    if (m) {
      seen.push({ id: `${m[1]}@${m[2]}`, at: Date.now(), auth: req.headers.authorization ?? null });
      if (ATTEST[m[1]]) { if (m[1] === 't') hanging.push(res); ATTEST[m[1]](res); return; }
    }
    if (TARBALLS[u]) { res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(TARBALLS[u].length) }); res.end(TARBALLS[u]); return; }
    const d = DOCS[u.slice(1)];
    if (d) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(d)); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const dbPath = path.join(dir, 'witness.db');
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`,
    witnessDbPath: dbPath, headersTimeoutMs: 10_000, bodyTimeoutMs: 20_000, ...config });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  try { return await fn({ base, proxy, dir, dbPath, seen }); } finally {
    for (const r of hanging) r.destroy();
    await new Promise((r) => proxy.close(r)); upstream.closeAllConnections?.(); await new Promise((r) => upstream.close(r));
    fs.rmSync(dir, { recursive: true, force: true }); resetDependencyCache(); forgetManifestHooks();
  }
}
const get = (u, headers = {}) => new Promise((resolve, reject) => http.get(u, { agent: false, headers }, (res) => {
  const chunks = []; res.on('data', (x) => chunks.push(x)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks), at: Date.now() }));
}).on('error', reject));
const settle = () => new Promise((r) => setTimeout(r, 300));
async function eventually(fn, ms = 5000) { const until = Date.now() + ms; let v = fn(); while (!v && Date.now() < until) { await new Promise((r) => setTimeout(r, 50)); v = fn(); } return v; }
const runCli = (args, env) => new Promise((resolve) => {
  const c = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, NO_COLOR: '1', CI: '', ...env } });
  let out = ''; c.stdout.on('data', (d) => { out += d; }); c.stderr.on('data', (d) => { out += d; }); c.on('close', (code) => resolve({ code, out }));
});
const install = async (base, name, v = '1.1.0', headers = {}) => { await get(`${base}/${name}`, headers); return get(`${base}/${name}/-/${name}-${v}.tgz`, headers); };
const msOf = (dbPath, name) => { const r = new Database(dbPath, { readonly: true }); try { return r.prepare('SELECT repo_claim_ms FROM entry_fact_versions WHERE package_name = ? AND version = ?').get(name, '1.1.0')?.repo_claim_ms; } finally { r.close(); } };

test('E1 an armed first download: MATCH stored once after the response, with its time; no credentials sent; `why`, the report event and the report text show it', async () => {
  await withProxy({}, async ({ base, proxy, dbPath, dir, seen }) => {
    const t = await install(base, 'z', '1.1.0', { authorization: 'Bearer secret-token' });
    assert.equal(t.status, 200); assert.ok(t.body.equals(TARBALLS['/z/-/z-1.1.0.tgz']), 'served unchanged');
    const rc = await eventually(() => proxy.witnessDb.repoClaimFor('z', '1.1.0'));
    assert.equal(rc?.outcome, 'MATCH', JSON.stringify(rc)); assert.equal(rc.attestation_repository, 'github.com/o/r');
    assert.deepEqual(seen.map((s) => s.id), ['z@1.1.0']); assert.equal(seen[0].auth, null, 'the user\'s token is not sent to the attestation endpoint');
    assert.ok(Number.isFinite(msOf(dbPath, 'z')), 'the fetch time beside it');
    await install(base, 'z'); await settle();
    assert.equal(seen.length, 1, 'once per version'); assert.deepEqual(proxy.witnessDb.repoClaimFor('z', '1.1.0'), rc);
    const w = await runCli(['why', 'z@1.1.0'], { CHAINGATE_WITNESS_DB: dbPath, HOME: dir });
    assert.match(w.out, /repository claim matches, unverified: github\.com\/o\/r/, w.out);
    const j = await runCli(['why', 'z@1.1.0', '--json'], { CHAINGATE_WITNESS_DB: dbPath, HOME: dir });
    assert.equal(JSON.parse(j.out.slice(j.out.indexOf('{'))).repo_claim?.outcome, 'MATCH');
    const rep = JSON.parse((await get(`${base}/_chaingate/report`)).body.toString('utf8'));
    const ev = rep.installs.flatMap((i) => i.events).find((e) => e.kind === 'facts' && e.package === 'z' && e.version === '1.1.0');
    assert.equal(ev?.repo_claim?.outcome, 'MATCH', JSON.stringify(ev));
    const { renderReport } = await import('../../cli/report-render.js');
    const text = renderReport(rep, { source: 'proxy' }).text;
    assert.match(text, /z@1\.1\.0: .*repository claim matches, unverified/);
    assert.doesNotMatch(w.out + j.out + text, INTERNAL);
    const bare = { ...rep, installs: rep.installs.map((i) => ({ ...i, events: i.events.map(({ repo_claim, ...e }) => e) })) };   // eslint-disable-line no-unused-vars
    assert.equal(renderReport(rep, { source: 'proxy' }).exit, renderReport(bare, { source: 'proxy' }).exit, 'no exit code depends on it');
  });
});

test('E2 MISMATCH changes no row and no notice: the rows and the npm-notice of a mismatching version are those of a matching one', async () => {
  await withProxy({}, async ({ base, proxy, dir, dbPath }) => {
    const a = await install(base, 'z'); const b = await install(base, 'w');
    const rc = await eventually(() => proxy.witnessDb.repoClaimFor('w', '1.1.0'));
    assert.equal(rc?.outcome, 'MISMATCH'); assert.equal(rc.attestation_repository, 'github.com/evil/r'); assert.equal(rc.packument_repository, 'github.com/o/r');
    await eventually(() => proxy.witnessDb.repoClaimFor('z', '1.1.0'));
    const shape = (p) => proxy.witnessDb.getLatestDecision(p, '1.1.0').gates_fired.map((g) => [g.gate, g.result]);
    assert.deepEqual(shape('w'), shape('z'));
    assert.equal(String(b.headers['npm-notice'] ?? '').replaceAll('w@', 'z@'), String(a.headers['npm-notice'] ?? ''));
    assert.ok(!proxy.witnessDb.getLatestDecision('w', '1.1.0').gates_fired.some((g) => /repository claim|evil/i.test(`${g.gate} ${g.detail}`)), 'no row reads the claim');
    const w = await runCli(['why', 'w@1.1.0'], { CHAINGATE_WITNESS_DB: dbPath, HOME: dir });
    assert.match(w.out, /repository claim differs: the provenance names github\.com\/evil\/r, the package metadata github\.com\/o\/r/, w.out);
  });
});

test('E3 ABSENT and NONE need no fetch; an unarmed version is not fetched and records no claim', async () => {
  await withProxy({}, async ({ base, proxy, dir, dbPath, seen }) => {
    await install(base, 'y', '1.0.0'); await settle();                         // attested, unarmed: served before
    await install(base, 'y');
    const rc = await eventually(() => proxy.witnessDb.repoClaimFor('y', '1.1.0'));
    assert.equal(rc?.outcome, 'ABSENT', JSON.stringify(rc)); assert.equal(rc.vs, '1.0.0');
    const w = await runCli(['why', 'y@1.1.0'], { CHAINGATE_WITNESS_DB: dbPath, HOME: dir });
    assert.match(w.out, /provenance dropped: 1\.0\.0 \(the version this proxy served before\) had provenance, this version has none/, w.out);
    await install(base, 'n');
    assert.equal((await eventually(() => proxy.witnessDb.repoClaimFor('n', '1.1.0')))?.outcome, 'NONE');
    await install(base, 'q'); await settle(); await settle();
    assert.equal(proxy.witnessDb.repoClaimFor('q', '1.1.0'), null, 'not armed: no claim');
    assert.deepEqual(seen, [], 'nothing fetched');
  });
});

test('E4 a fetch that hangs never delays the download: served at once, NOT_FETCHED on the timeout', async () => {
  await withProxy({ attestationTimeoutMs: 2500 }, async ({ base, proxy, seen }) => {
    await get(`${base}/t`); const t0 = Date.now(); const t = await get(`${base}/t/-/t-1.1.0.tgz`);
    assert.equal(t.status, 200); assert.ok(t.body.equals(TARBALLS['/t/-/t-1.1.0.tgz']));
    assert.ok(t.at - t0 < 2000, `served in ${t.at - t0} ms, before the 2500 ms fetch bound`);
    const rc = await eventually(() => proxy.witnessDb.repoClaimFor('t', '1.1.0'), 8000);
    assert.equal(rc?.outcome, 'NOT_FETCHED', JSON.stringify(rc)); assert.match(rc.reason, /timeout after 2500 ms/);
    assert.equal(seen.length, 1);
  });
});

test('E5 NOT_FETCHED with the reason: a 404, a bundle over the byte cap (declared or streamed), a bundle that is not JSON, no fetch slot free', async () => {
  await withProxy({ attestationMaxBytes: 2000 }, async ({ base, proxy }) => {
    for (const n of ['e', 'b', 'k', 'j']) await install(base, n);
    const of = async (n) => (await eventually(() => proxy.witnessDb.repoClaimFor(n, '1.1.0')));
    assert.match((await of('e'))?.reason ?? '', /^HTTP 404$/);
    assert.match((await of('b'))?.reason ?? '', /the bundle exceeds 2000 bytes/);
    assert.match((await of('k'))?.reason ?? '', /the bundle exceeds 2000 bytes/);
    assert.match((await of('j'))?.reason ?? '', /the bundle is not JSON/);
  });
  await withProxy({ attestationMaxInFlight: 0 }, async ({ base, proxy, seen }) => {
    await install(base, 'c');
    const rc = await eventually(() => proxy.witnessDb.repoClaimFor('c', '1.1.0'));
    assert.equal(rc?.outcome, 'NOT_FETCHED'); assert.match(rc.reason, /too many provenance fetches in flight/); assert.deepEqual(seen, []);
  });
});
