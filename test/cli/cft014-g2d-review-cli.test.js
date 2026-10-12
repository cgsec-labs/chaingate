// 0.1.4 group 2, unit 2d — review fixes and added guards on the CLI (dated note 8; G2d-18..G2d-22). Expected results:
// decision tables ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G2-TIER0-20261011.md, dated note 8, written before this file.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createProxyServer } from '../../proxy/server.js';
import { openWitnessDB } from '../../witness/db.js';
import { buildSeed, docFor, manifestFor, after, iso, TIP_S, STEP_S, LIVE } from '../seed-v3/u05-fixtures.mjs';

const CLI = fileURLToPath(new URL('../../cli/index.js', import.meta.url));
const listen = (srv) => new Promise((resolve) => { srv.listen(0, '127.0.0.1', () => resolve(srv.address().port)); });
const close = (srv) => new Promise((resolve) => { srv.close(() => resolve()); });
const get = (url) => new Promise((resolve, reject) => {
  http.get(url, { agent: false }, (res) => { let b = ''; res.on('data', (x) => { b += x; }); res.on('end', () => resolve({ status: res.statusCode, body: b })); }).on('error', reject);
});
function cli(args, env) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const c = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, NO_COLOR: '1', CI: '', ...env } });
    let out = ''; let err = '';
    c.stdout.on('data', (b) => { out += b; }); c.stderr.on('data', (b) => { err += b; });
    const timer = setTimeout(() => c.kill('SIGKILL'), 60_000);
    c.on('close', (code) => { clearTimeout(timer); resolve({ code, out, err, all: out + err, ms: Date.now() - t0 }); });
  });
}
const strict = () => manifestFor('q', '1.5.0', { scripts: { postinstall: 'node x.js' },
  dist: { unpackedSize: 10_000, attestations: { url: 'https://x' } } });
const DOCS = () => {
  const q = docFor('q', [['1.4.0', after(1)], ['1.4.5', iso(TIP_S + 2 * STEP_S - 3600)], ['1.5.0', after(2), strict()]]);
  q['dist-tags'] = { latest: '1.5.0' };
  q.versions['1.0.0'].scripts = { postinstall: 'node legacy.js' };   // G3 dated note 1.2: T1.1 stays quiet; the seed rows are the subject
  return { q };
};

async function withObservedHome(fn) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2dr-cli-'));
  const s = buildSeed({ layout: '1.1' });
  const docs = DOCS();
  const upstream = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url);
    if (url.includes('/-/')) { res.writeHead(200); res.end('x'); return; }
    const d = docs[url.slice(1)];
    if (!d) { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); return; }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(d));
  });
  const up = await listen(upstream);
  const dbPath = path.join(home, 'witness.db');
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${up}`, witnessDbPath: dbPath,
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedV3Path: s.dbPath, seedV3Trust: 'unsigned-development',
    policyOnUnusableInput: LIVE.on_unusable_input, policyOnNoEvidence: LIVE.on_no_evidence });
  const port = await listen(proxy);
  const realErr = console.error; console.error = () => {};
  try {
    assert.equal((await get(`http://127.0.0.1:${port}/q`)).status, 200);
    return await fn({ home, dbPath, port, env: { CHAINGATE_HOME: home, CHAINGATE_PORT: String(port) } });
  } finally {
    console.error = realErr;
    await close(proxy); await close(upstream); s.cleanup(); fs.rmSync(home, { recursive: true, force: true });
  }
}
const ro = (dbPath, f) => { const h = openWitnessDB(dbPath, { readonly: true }); try { return f(h); } finally { h.close(); } };

test('G2d-18 (O2, trap 2, note 8.5) `chaingate accept`, then an advisory for that version: the tarball is still refused', async () => {
  await withObservedHome(async ({ dbPath, port, env }) => {
    assert.equal((await cli(['accept', 'q@1.5.0'], env)).code, 0);
    const rw = openWitnessDB(dbPath);
    try {
      rw.insertGateDecision('q', '1.5.0', 'BLOCK', [{ gate: 'seed-v3', result: 'BLOCK',
        detail: 'cft-policy-1.2: seed-v3:known-malicious-pin: recorded advisory ADV-Q-150 pins q@1.5.0 (source fixture)',
        rows: [{ gate: 'seed-v3:known-malicious-pin', result: 'BLOCK' }] }]);
    } finally { rw.close(); }
    const t = await get(`http://127.0.0.1:${port}/q/-/q-1.5.0.tgz`);
    assert.equal(t.status, 403);
    assert.equal(JSON.parse(t.body).error, 'blocked_by_chaingate');
  });
});

test('G2d-19 (note 8.5) the integrity gate refuses accept, pin and unpin; nothing is written', async () => {
  await withObservedHome(async ({ home, dbPath, env }) => {
    fs.writeFileSync(path.join(home, 'witness.db.install-pending.json'), 'not json');
    for (const args of [['accept', 'q@1.5.0'], ['pin', 'q@1.4.0'], ['unpin', 'q']]) {
      const r = await cli(args, env);
      assert.equal(r.code, 6, `${args.join(' ')}: ${r.all}`);
    }
    ro(dbPath, (h) => { assert.deepEqual([h.listAcceptances().length, h.listPins().length, h.listAdjudications().length], [0, 0, 0]); });
  });
});

test('G2d-20 (note 8.3) an action and its log are one transaction: a log failure leaves nothing changed, and says so', async () => {
  await withObservedHome(async ({ dbPath, env }) => {
    const rw = openWitnessDB(dbPath).applySchema();
    try { rw.db.exec("CREATE TRIGGER g2d20 BEFORE INSERT ON adjudications BEGIN SELECT RAISE(ABORT, 'log broken'); END;"); } finally { rw.close(); }
    for (const args of [['accept', 'q@1.5.0'], ['pin', 'q@1.4.0']]) {
      const r = await cli(args, env);
      assert.equal(r.code, 1, `${args.join(' ')}: ${r.all}`);
      assert.match(r.all, /log broken/);
      assert.match(r.all, /nothing was changed/);
    }
    ro(dbPath, (h) => { assert.equal(h.listAcceptances().length, 0); assert.equal(h.listPins().length, 0); });
  });
});

test('G2d-21 (D-U8, note 8.5) `why` returns promptly while another connection holds the write lock; its output is unchanged', async () => {
  await withObservedHome(async ({ dbPath, env }) => {
    const before = await cli(['why', 'q@1.5.0', '--cached'], env);
    const lock = openWitnessDB(dbPath);
    try {
      lock.db.exec('BEGIN IMMEDIATE');
      const r = await cli(['why', 'q@1.5.0', '--cached'], env);
      assert.ok(r.ms < 3_000, `why took ${r.ms} ms`);
      assert.equal(r.code, before.code);
      assert.equal(r.out, before.out);
    } finally { try { lock.db.exec('ROLLBACK'); } catch { /* none */ } lock.close(); }
  });
});

test('G2d-22 (note 8.4) `pin` says the pin is not in force while the running proxy cannot read its pins', async () => {
  await withObservedHome(async ({ env }) => {
    const fake = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ service: 'chaingate-proxy', version: '0.1.4', pins: { enforced: true, count: 0, generation: 3, last_error: 'disk I/O error' } }));
    });
    const port = await listen(fake);
    try {
      const r = await cli(['pin', 'q@1.4.0'], { ...env, CHAINGATE_PORT: String(port) });
      assert.equal(r.code, 0, r.all);
      assert.match(r.out, /recorded; the running proxy cannot read its pins right now \(disk I\/O error\), so it is not in force yet/);
      assert.doesNotMatch(r.out, /in force for new metadata requests/);
    } finally { await close(fake); }
  });
});
