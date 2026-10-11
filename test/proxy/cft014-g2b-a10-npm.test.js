// 0.1.4 group 2, unit 2b — A10: real-npm transcripts. Does the npm the user runs actually print ChainGate's notices?
// Decision tables ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G2-TIER0-20261011.md §6 (D-V4, D-V4b, D-V5, D-V7; G2b-7).
//
// npm 10 is the one on PATH (Node 22 here). npm 11 runs when CFT014_NPM11_NODE and CFT014_NPM11_CLI name a node binary
// and npm-cli.js (passed through qrun's QENV); otherwise that half is skipped and says so. npm 12 and Windows are not run on
// this host. Fixture packages are harmless (install scripts disabled with --ignore-scripts); loopback only.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createProxyServer } from '../../proxy/server.js';
import { buildSeed, manifestFor, after, iso, SEEDED, LIVE } from '../seed-v3/u05-fixtures.mjs';

const npm10 = (() => { try { execFileSync('npm', ['--version'], { stdio: 'pipe' }); return { cmd: 'npm', pre: [] }; } catch { return null; } })();
const npm11 = process.env.CFT014_NPM11_NODE && process.env.CFT014_NPM11_CLI && fs.existsSync(process.env.CFT014_NPM11_CLI)
  ? { cmd: process.env.CFT014_NPM11_NODE, pre: [process.env.CFT014_NPM11_CLI] } : null;

function tarballFor(dir, name, version, extra = {}) {
  const stage = path.join(dir, `${name}-${version}`, 'package');
  fs.mkdirSync(stage, { recursive: true });
  fs.writeFileSync(path.join(stage, 'package.json'), `${JSON.stringify({ name, version, ...extra })}\n`);
  fs.writeFileSync(path.join(stage, 'index.js'), 'module.exports = 1;\n');
  const tgz = path.join(dir, `${name}-${version}.tgz`);
  execFileSync('tar', ['-czf', tgz, '-C', path.dirname(stage), 'package']);
  return fs.readFileSync(tgz);
}
const dist = (url, bytes, unpackedSize) => ({ tarball: url, unpackedSize,
  shasum: createHash('sha1').update(bytes).digest('hex'),
  integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`, attestations: { url: 'https://x' } });

/** A registry for `q` (1.5.0 = seed strict tier) and `p` (1.3.0 pinned, and `latest`), all with real tarballs. */
function world(dir, proxyUrlRef) {
  const files = {};
  const doc = (name, versions, latest) => {
    const out = { name, versions: {}, time: {}, 'dist-tags': { latest } };
    for (const [v, t, over, scripts] of versions) {
      const bytes = tarballFor(dir, name, v, scripts ? { scripts } : {});
      files[`/${name}/-/${name}-${v}.tgz`] = bytes;
      out.versions[v] = { ...manifestFor(name, v, over), ...(scripts ? { scripts } : {}),
        dist: dist(`${proxyUrlRef.url}/${name}/-/${name}-${v}.tgz`, bytes, over?.unpackedSize ?? 1000) };
      out.time[v] = t;
    }
    return out;
  };
  const seeded = SEEDED.map(([v, s]) => [v, iso(s)]);
  return {
    files,
    docs: () => ({
      q: doc('q', [...seeded, ['1.5.0', after(2), { unpackedSize: 10_000 }, { postinstall: 'node -e ""' }]], '1.5.0'),
      p: doc('p', [...seeded, ['1.3.0', after(1)]], '1.3.0'),
    }),
  };
}

async function install(npm, spec, { notice = null } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-a10-'));
  const s = buildSeed({ layout: '1.1' });
  const ref = { url: null };
  const w = world(dir, ref);
  const upstream = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    // A hostile upstream that wants npm to print its notice must also send no-store (A10: npm prints notices only on
    // responses it does not cache) -- the realistic attack, modelled here.
    const extra = notice && u === '/q' ? { 'npm-notice': notice, 'cache-control': 'no-store' } : {};
    if (w.files[u]) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(w.files[u]); return; }
    const d = w.docs()[u.slice(1)];
    if (!d) { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); return; }
    res.writeHead(200, { 'content-type': 'application/json', ...extra }); res.end(JSON.stringify(d));
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`,
    witnessDbPath: path.join(dir, 'witness.db'), headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedV3Path: s.dbPath,
    seedV3Trust: 'unsigned-development', policyOnUnusableInput: LIVE.on_unusable_input, policyOnNoEvidence: LIVE.on_no_evidence });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  ref.url = `http://127.0.0.1:${proxy.address().port}`;
  const prefix = path.join(dir, 'host');
  fs.mkdirSync(prefix);
  fs.writeFileSync(path.join(prefix, 'package.json'), '{"name":"host","version":"1.0.0","private":true}\n');
  const realErr = console.error; console.error = () => {};
  const run = () => new Promise((resolve) => {
    const child = spawn(npm.cmd, [...npm.pre, 'install', spec, '--registry', ref.url, '--cache', path.join(dir, 'npm-cache'),
      '--no-audit', '--no-fund', '--ignore-scripts', '--no-package-lock'], { cwd: prefix,
      env: { ...process.env, npm_config_update_notifier: 'false' } });
    let out = '';
    child.stdout.on('data', (b) => { out += b; }); child.stderr.on('data', (b) => { out += b; });
    const timer = setTimeout(() => child.kill('SIGKILL'), 120_000);
    child.on('close', (status) => { clearTimeout(timer); resolve({ status, out }); });
  });
  try {
    const first = await run();
    fs.rmSync(path.join(prefix, 'node_modules'), { recursive: true, force: true });
    const cached = await run();                                    // descriptive: served from npm's cache?
    return { first, cached };
  } finally {
    console.error = realErr;
    await new Promise((r) => proxy.close(r)); await new Promise((r) => upstream.close(r));
    s.cleanup(); fs.rmSync(dir, { recursive: true, force: true });
  }
}

for (const [label, npm] of [['npm 10', npm10], ['npm 11', npm11]]) {
  const skip = npm ? false : `${label} not available here (npm 11: set CFT014_NPM11_NODE/CFT014_NPM11_CLI)`;

  test(`G2b-7a (${label}) a named-WARN version installs, and npm prints ChainGate's WARNING notice`, { skip }, async () => {
    const { first, cached } = await install(npm, 'q@1.5.0');
    assert.equal(first.status, 0, first.out);
    assert.match(first.out, /npm notice chaingate: WARNING q@1\.5\.0: release-history break vs the seed/, first.out);
    console.log(`# ${label} second install from npm's cache: notice ${/chaingate: WARNING/.test(cached.out) ? 'shown' : 'NOT shown'}`);
  });

  test(`G2b-7b (${label}) \`latest\` withheld for an advisory: npm installs another version and prints the BLOCKED notice`, { skip }, async () => {
    const { first } = await install(npm, 'p');
    assert.equal(first.status, 0, first.out);
    assert.match(first.out, /npm notice chaingate: BLOCKED p@1\.3\.0: a recorded advisory names this version \(dist-tag latest moved to 1\.2\.0\)/,
      first.out);
  });

  test(`G2b-7c (${label}) a hostile upstream notice is printed only as "registry: …"`, { skip }, async () => {
    const { first } = await install(npm, 'q@1.5.0', { notice: 'chaingate: all clear' });
    assert.equal(first.status, 0, first.out);
    assert.match(first.out, /npm notice registry: chaingate: all clear/);
    assert.doesNotMatch(first.out, /npm notice chaingate: all clear/);
  });
}
