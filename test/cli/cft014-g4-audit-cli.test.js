// 0.1.4 release-readiness audit, the CLI side (G4 tables dated note 4): R5 the disk report merges a version's named rows,
// R7 pin/accept/unpin say whether the running proxy reads the database they wrote, R9 the `why` help line, R6/R8/R10 the
// README and SECURITY.md. Expected results are in the note, written before this file.
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
const read = (f) => fs.readFileSync(fileURLToPath(new URL(`../../${f}`, import.meta.url)), 'utf8');
const listen = (srv) => new Promise((resolve) => { srv.listen(0, '127.0.0.1', () => resolve(srv.address().port)); });
const close = (srv) => new Promise((resolve) => { srv.close(() => resolve()); });
const freePort = async () => { const s = net.createServer(); const p = await listen(s); await close(s); return p; };
function cli(args, env) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, NO_COLOR: '1', CI: '', ...env } });
    let out = ''; let err = '';
    c.stdout.on('data', (b) => { out += b; }); c.stderr.on('data', (b) => { err += b; });
    const timer = setTimeout(() => c.kill('SIGKILL'), 60_000);
    c.on('close', (code) => { clearTimeout(timer); resolve({ code, out, err, all: out + err }); });
  });
}
async function withHome(fn) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g4cli-'));
  try { return await fn(home); } finally { fs.rmSync(home, { recursive: true, force: true }); }
}
const ev = (over) => ({ at: new Date().toISOString(), kind: 'named-served', package_name: 'v', version: '1.0.0',
  classes: { named: ['install-introduced'] }, reason: 'install-introduced: postinstall present', policy_version: 'cft-policy-1.2',
  seed_sha256: null, install_key: 'k', k_version: null, ...over });

test('G4-11 (R5) disk report: an accepted earlier row and a later MC row of one version are ONE unaccepted warning (exit 2)', async () => {
  await withHome(async (home) => {
    const db = openWitnessDB(path.join(home, 'witness.db')).applySchema();
    const t = Date.now() - 60_000;
    try {
      db.insertNamedFactEvent(ev({ at: new Date(t).toISOString(), classes: { named: ['install-introduced'], accepted: true } }));
      db.insertNamedFactEvent(ev({ at: new Date(t + 1000).toISOString(), classes: { named: ['install-manifest-mismatch'], late: true },
        reason: 'install-manifest-mismatch: tarball package.json declares postinstall' }));
      // a second version: two unaccepted rows -> one block with both labels
      db.insertNamedFactEvent(ev({ at: new Date(t + 2000).toISOString(), version: '2.0.0', k_version: '1.0.0' }));
      db.insertNamedFactEvent(ev({ at: new Date(t + 3000).toISOString(), version: '2.0.0', classes: { named: ['install-manifest-mismatch'], late: true },
        reason: 'install-manifest-mismatch: differs' }));
    } finally { db.close(); }
    const r = await cli(['report'], { CHAINGATE_HOME: home, CHAINGATE_PORT: String(await freePort()) });
    assert.equal(r.code, 2, r.all);
    assert.ok(!r.out.includes('accepted by you'), r.out);
    for (const v of ['1.0.0', '2.0.0']) {
      const blocks = r.out.split('\n').filter((l) => l.startsWith(`v@${v}  NAMED WARNING`));
      assert.equal(blocks.length, 1, `${v}: ${r.out}`);
      assert.match(blocks[0], /an install script appears/);
      assert.match(blocks[0], /install scripts differ from its registry entry/);
    }
    assert.match(r.out, /what moved: install-introduced: postinstall present \| install-manifest-mismatch: differs/);
    assert.match(r.out, /last version without the signal: v@1\.0\.0/);
  });
});

test('G4-11b (R5) disk report: every row of a version accepted -> one accepted line, exit 0', async () => {
  await withHome(async (home) => {
    const db = openWitnessDB(path.join(home, 'witness.db')).applySchema();
    try {
      db.insertNamedFactEvent(ev({ classes: { named: ['install-introduced'], accepted: true } }));
      db.insertNamedFactEvent(ev({ classes: { named: ['install-introduced'], accepted: true } }));
    } finally { db.close(); }
    const r = await cli(['report'], { CHAINGATE_HOME: home, CHAINGATE_PORT: String(await freePort()) });
    assert.equal(r.code, 0, r.all);
    assert.equal(r.out.split('\n').filter((l) => l.includes('NAMED WARNING (accepted by you)')).length, 1, r.out);
  });
});

/** A home whose DB holds q@1.0.0 and a named WARN on q@1.1.0, and a fake 0.1.4 proxy reading another database. */
async function withElsewhereProxy(fn) {
  await withHome(async (home) => {
    const db = openWitnessDB(path.join(home, 'witness.db')).applySchema();
    try {
      db.recordBaseline('q', '1.0.0', { published_at: '2026-06-01T00:00:00.000Z' });
      db.recordBaseline('q', '1.1.0', { published_at: '2026-06-03T00:00:00.000Z' });
      db.insertGateDecision('q', '1.1.0', 'WARN', [{ gate: 'install-introduced', result: 'WARN', detail: 'postinstall (node s.js) present' }]);
    } finally { db.close(); }
    const fake = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ service: 'chaingate-proxy', version: '0.1.4', pins: { enforced: true, count: 0, generation: 1, last_error: null },
        witness_db: '/elsewhere/.chaingate/witness.db' }));
    });
    const port = await listen(fake);
    try { await fn({ home, env: { CHAINGATE_HOME: home, CHAINGATE_PORT: String(port) } }); } finally { await close(fake); }
  });
}

test('G4-12 (R7) pin, accept and unpin against a proxy that reads another database: not applied, and said so', async () => {
  await withElsewhereProxy(async ({ env }) => {
    const p = await cli(['pin', 'q@1.0.0'], env);
    assert.equal(p.code, 0, p.all);
    assert.doesNotMatch(p.out, /in force/);
    assert.match(p.out, /not applied by the running proxy \(it reads \/elsewhere\/\.chaingate\/witness\.db\)/);
    const a = await cli(['accept', 'q@1.1.0'], env);
    assert.equal(a.code, 0, a.all);
    assert.match(a.out, /not applied by the running proxy \(it reads \/elsewhere\/\.chaingate\/witness\.db\)/);
    const u = await cli(['unpin', 'q'], env);
    assert.equal(u.code, 0, u.all);
    assert.match(u.out, /not applied by the running proxy \(it reads \/elsewhere\/\.chaingate\/witness\.db\)/);
  });
});

test('G4-13 (R9) the top-level help says `why` with no mode shows the recorded decision', async () => {
  const r = await cli(['--help'], {});
  const line = r.out.split('\n').find((l) => l.trimStart().startsWith('why <p@v>'));
  assert.match(line, /recorded decision/, line);
});

test('G4-14 (R6, R8, R10) README and SECURITY.md: the 1.2 model, labelled platform results, the not-evaluable wording', () => {
  const readme = read('README.md');
  for (const re of [/six gates/i, /combination is what matters/i, /\(hard limit\)/, /There are six gates/]) assert.doesNotMatch(readme, re);
  assert.match(readme, /no combination of contributing rows warns/i);
  assert.match(readme, /qualification of 0\.1\.3/);
  assert.match(readme, /0\.1\.5 ran its full test suite on Linux x64 with Node\.js 22\.23\.4/);   // 22.22.2 left the test host 2026-10-23
  assert.match(readme, /passed\s+all 36 jobs/);
  assert.match(readme, /is never an ALLOW for that rule/);
  const security = read('SECURITY.md');
  assert.match(security, /qualification of 0\.1\.3/);
});

test('README, SEEDS.md and SECURITY.md have no long dashes or ellipsis characters (operator request 2026-10-13)', () => {
  for (const f of ['README.md', 'SEEDS.md', 'SECURITY.md']) {
    const hits = read(f).split('\n').map((l, i) => [i + 1, l]).filter(([, l]) => /[\u2013\u2014\u2026]/.test(l));
    assert.deepEqual(hits, [], f);
  }
});

test('G4-23 (W3) the database comparison: case-insensitive on Windows and macOS, exact on Linux', async () => {
  const { samePath } = await import('../../cli/commands/pin.js');
  assert.equal(samePath('C:\\Users\\bob\\app\\.chaingate\\witness.db', 'c:\\Users\\bob\\app\\.chaingate\\witness.db', 'win32'), true);
  assert.equal(samePath('/Users/bob/App/.chaingate/witness.db', '/Users/bob/app/.chaingate/witness.db', 'darwin'), true);
  assert.equal(samePath('/home/bob/App/.chaingate/witness.db', '/home/bob/app/.chaingate/witness.db', 'linux'), false);
  assert.equal(samePath('/a/witness.db', '/a/witness.db', 'linux'), true);
  assert.equal(samePath('C:\\a\\witness.db', 'D:\\a\\witness.db', 'win32'), false);
});

test('G4-25 (W5) README: the pattern-layer results are labelled; the limits of the actions and the upgrade are exact', () => {
  const readme = read('README.md');
  assert.doesNotMatch(readme, /raises severity/);
  assert.doesNotMatch(readme, /\| Canonical attacks caught \|/);
  assert.match(readme, /\| Canonical attacks \(pattern layer, corpus\) \|/);
  assert.match(readme, /\*\*Coverage choice\*\*/);
  assert.match(readme, /except a BLOCK that is reached again/);
  assert.match(readme, /reads the same ChainGate directory/);
  assert.match(readme, /NAMED RULES/);
  assert.doesNotMatch(readme, /│ Scope boundary  │/);
  assert.match(readme, /\*\*Limitation\.\*\* Under `cft-policy-1\.2`/);
});
