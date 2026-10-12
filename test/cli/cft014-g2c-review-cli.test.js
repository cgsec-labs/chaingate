// 0.1.4 group 2, unit 2c — review fixes on the CLI side (dated note 7: items 6, 7, 12, 13, 14). Expected results: decision
// tables ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G2-TIER0-20261011.md, dated note 7, written before this file.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { openWitnessDB } from '../../witness/db.js';

const CLI = fileURLToPath(new URL('../../cli/index.js', import.meta.url));
const listen = (srv) => new Promise((resolve) => { srv.listen(0, '127.0.0.1', () => resolve(srv.address().port)); });
const close = (srv) => new Promise((resolve) => { srv.close(() => resolve()); });
const freePort = async () => { const s = net.createServer(); const p = await listen(s); await close(s); return p; };
function cli(args, env) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, NO_COLOR: '1', ...env } });
    let out = ''; let err = '';
    c.stdout.on('data', (b) => { out += b; }); c.stderr.on('data', (b) => { err += b; });
    const timer = setTimeout(() => c.kill('SIGKILL'), 120_000);
    c.on('close', (code) => { clearTimeout(timer); resolve({ code, out, err }); });
  });
}
async function withHome(fn) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2cr-cli-'));
  try { return await fn(home); } finally { fs.rmSync(home, { recursive: true, force: true }); }
}
const row = (over) => ({ at: new Date().toISOString(), kind: 'fact-refused', package_name: 'p', version: '1.3.0',
  classes: { facts: ['seed-v3:pin'] }, reason: 'r', policy_version: 'cft-policy-1.2', seed_sha256: null, install_key: 'k', k_version: null, ...over });

test('G2c-16 (note 7.6) an older ChainGate proxy on the port: said so, the disk view is incomplete, exit 4', async () => {
  await withHome(async (home) => {
    openWitnessDB(path.join(home, 'witness.db')).applySchema().close();
    const old = http.createServer((req, res) => {
      if (req.url === '/_chaingate/self') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ service: 'chaingate-proxy', version: '0.1.3', pid: 4242 })); return; }
      res.writeHead(404, { 'content-type': 'application/json' }); res.end('{"error":"not_found"}');
    });
    const port = await listen(old);
    try {
      const r = await cli(['report'], { CHAINGATE_HOME: home, CHAINGATE_PORT: String(port) });
      assert.equal(r.code, 4, r.out + r.err);
      assert.ok(r.out.includes(`A ChainGate proxy (version 0.1.3) is running on 127.0.0.1:${port} but gave no install summary`), r.out);
      assert.ok(!r.out.includes('No ChainGate proxy answered'));
      assert.ok(r.out.includes('this view is incomplete'), r.out);
    } finally { await close(old); }
  });
});

test('G2c-21 (note 7.13) an unreadable witness DB in disk mode is a tool error: exit 4', async () => {
  await withHome(async (home) => {
    fs.writeFileSync(path.join(home, 'witness.db'), 'this is not a sqlite database, only some bytes'.repeat(100));
    const r = await cli(['report'], { CHAINGATE_HOME: home, CHAINGATE_PORT: String(await freePort()) });
    assert.equal(r.code, 4, r.out + r.err);
    assert.match(r.out + r.err, /witness database/);
  });
});

test('G2c-22b (note 7.14) --json escapes DEL, C1 and bidi controls losslessly', async () => {
  await withHome(async (home) => {
    const db = openWitnessDB(path.join(home, 'witness.db')).applySchema();
    try { db.insertNamedFactEvent(row({ reason: 'a‮b\u009bc\u007fd' })); } finally { db.close(); }
    const r = await cli(['report', '--json'], { CHAINGATE_HOME: home, CHAINGATE_PORT: String(await freePort()) });
    assert.ok(!/[\u007f-\u009f‮]/.test(r.out), 'no raw control character on stdout');
    const j = JSON.parse(r.out);
    assert.equal(j.events[0].reason, 'a‮b\u009bc\u007fd', 'the data is unchanged');
    assert.equal(j.exit, 3);
  });
});

test('G2c-17b (note 7.7) more rows than the read limit: the newest are shown, and the view says it is incomplete', async () => {
  await withHome(async (home) => {
    const db = openWitnessDB(path.join(home, 'witness.db')).applySchema();
    try {
      const t0 = Date.now() - 3_600_000;
      db.db.transaction(() => {
        for (let i = 0; i <= 10_000; i += 1) db.insertNamedFactEvent(row({ at: new Date(t0 + i * 100).toISOString(), package_name: `n${i}` }));
      })();
    } finally { db.close(); }
    const r = await cli(['report'], { CHAINGATE_HOME: home, CHAINGATE_PORT: String(await freePort()) });
    assert.equal(r.code, 3);
    assert.ok(r.out.includes('Only the newest 10000 rows of the window are shown; this view is incomplete.'));
    assert.ok(r.out.includes('n10000@1.0.0') || r.out.includes('n10000@1.3.0'), 'the newest row is shown');
    assert.ok(!r.out.includes('n0@1.3.0  BLOCKED'), 'the oldest row is the one left out');
  });
});
