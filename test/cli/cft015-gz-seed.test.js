// 0.1.5 #9 (operator ruling 2026-10-17, unconditional 2026-10-19): the v3 seed is published gz-primary. A database over
// GitHub's 2 GiB per-asset limit cannot ship raw, so `--seed` also takes `<db>.gz`: the runtime decompresses it into the
// private staging copy, bounded, and everything after that -- the .sha256 check, the signature, the reader -- describes the
// DECOMPRESSED database, exactly as for a raw `--seed <db>`. The sidecars are the database's own (`<db>.sha256`,
// `<db>.sig`), found next to the .gz. Failing-first: before this change a .gz is staged as is and refused as not a seed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import Database from 'better-sqlite3';

import updateSeed from '../../cli/commands/update-seed.js';
import { resolvePaths } from '../../cli/paths.js';
import { activeBundleId, seedsDir, bundleFiles } from '../../cli/seed-bundle.js';
import { v3Host, v3Source, sha256 } from '../helpers/u05-r22.mjs';

const V3_SIDECARS = 4096 + 4096 + 65536 + 4096 + 4096;
const RESERVE = 64 * 1024 * 1024;

/** A synthetic seed that installs as a NEW bundle, plus its gzip next to it; the raw database is moved away, so only the
 *  .gz and the database's sidecars are in the folder, as a user who downloaded the gz-primary assets has them. */
function gzSource(digest = 'd', { keepRaw = false } = {}) {
  const s = v3Source();
  const h = new Database(s.db); h.prepare("UPDATE seed_metadata SET value = ? WHERE key = 'corpus_snapshot_digest'").run(digest.repeat(64)); h.close();
  const dbSha = sha256(s.db);
  fs.writeFileSync(s.sha, `${dbSha}  chaingate-seed.db\n`);
  const raw = fs.readFileSync(s.db);
  const gz = `${s.db}.gz`;
  fs.writeFileSync(gz, zlib.gzipSync(raw));
  if (!keepRaw) fs.rmSync(s.db);
  return { ...s, gz, dbSha, rawSize: raw.length };
}
const deps = (base, extra = {}) => ({
  fetchSeedBundle: async () => { throw new Error('test stub: no network'); },
  verifySeed: async () => { throw new Error('test stub'); },
  assertIntegrity: async () => ({ ok: true }),
  resolvePaths: (scope) => resolvePaths(scope, process.cwd(), { CHAINGATE_HOME: base }),
  ...extra,
});
async function run(fn) {
  const out = []; const err = []; const l = console.log; const e = console.error;
  console.log = (...a) => out.push(a.join(' ')); console.error = (...a) => err.push(a.join(' '));
  try { const code = await fn(); return { code, all: `${out.join('\n')}\n${err.join('\n')}` }; }
  finally { console.log = l; console.error = e; }
}
const entries = (base) => fs.readdirSync(seedsDir(base)).sort();
const staging = (base) => entries(base).filter((n) => n.startsWith('.staging-'));
const fakeFs = (free) => ({ statfs: () => ({ bsize: 1n, bavail: BigInt(free), blocks: 1n << 40n, bfree: BigInt(free) }) });
const activeDb = (base) => bundleFiles(path.join(seedsDir(base), activeBundleId(base))).db;

test('GZ1 update-seed --seed <db>.gz installs the DECOMPRESSED database: the bundle holds the raw bytes and is active', async () => {
  const h = await v3Host(); const s = gzSource();
  try {
    const r = await run(() => updateSeed(['--seed', s.gz, '--unsigned-development'], deps(h.base)));
    assert.equal(r.code, 0, r.all);
    assert.notEqual(activeBundleId(h.base), h.id, 'the new bundle is active');
    assert.equal(sha256(activeDb(h.base)), s.dbSha, 'the installed database is the decompressed seed, byte for byte');
    assert.deepEqual(staging(h.base), [], 'no staging directory left');
  } finally { s.cleanup(); h.cleanup(); }
});

test('GZ2 the same seed as .gz and as raw .db installs as the SAME bundle id (identity is the decompressed bytes)', async () => {
  const h1 = await v3Host(); const h2 = await v3Host(); const s = gzSource('e', { keepRaw: true });
  try {
    const a = await run(() => updateSeed(['--seed', s.gz, '--unsigned-development'], deps(h1.base)));
    const b = await run(() => updateSeed(['--seed', s.db, '--unsigned-development'], deps(h2.base)));
    assert.equal(a.code, 0, a.all); assert.equal(b.code, 0, b.all);
    assert.equal(activeBundleId(h1.base), activeBundleId(h2.base));
  } finally { s.cleanup(); h1.cleanup(); h2.cleanup(); }
});

test('GZ3 the database .sha256 next to the .gz is checked against the DECOMPRESSED bytes; a wrong one refuses', async () => {
  const h = await v3Host(); const s = gzSource('f');
  try {
    fs.writeFileSync(s.sha, `${'0'.repeat(64)}  chaingate-seed.db\n`);
    const r = await run(() => updateSeed(['--seed', s.gz, '--unsigned-development'], deps(h.base)));
    assert.equal(r.code, 1, r.all);
    assert.match(r.all, /does not describe the bytes supplied/);
    assert.equal(activeBundleId(h.base), h.id, 'the active bundle is unchanged');
    assert.deepEqual(staging(h.base), []);
  } finally { s.cleanup(); h.cleanup(); }
});

test('GZ4 the signature is verified over the DECOMPRESSED database: the .sig next to the .gz, the digest of the raw bytes; the reader checks it too', async () => {
  const h = await v3Host(); const s = gzSource('a');
  try {
    fs.writeFileSync(s.sig, Buffer.alloc(64, 7));
    const seen = [];
    const verifyStagedSeed = ({ digest, sigBytes }) => { seen.push({ digest, sig: Buffer.from(sigBytes).toString('hex') }); };
    const r = await run(() => updateSeed(['--seed', s.gz], deps(h.base, { verifyStagedSeed })));
    assert.equal(seen.length, 1, `the signature check ran once\n${r.all}`);
    assert.equal(seen[0].digest, s.dbSha, 'it was given the digest of the decompressed database');
    assert.equal(seen[0].sig, Buffer.alloc(64, 7).toString('hex'), 'and the database\'s .sig bytes');
    // The test signature is not made with the built-in key, so the reader's own check of the staged bundle refuses it.
    assert.equal(r.code, 1, r.all);
    assert.match(r.all, /signature does not verify against the pinned key/);
    assert.equal(activeBundleId(h.base), h.id);
  } finally { s.cleanup(); h.cleanup(); }
});

test('GZ5 a truncated or corrupt .gz refuses: exit 1, nothing staged or installed, the active bundle unchanged', async () => {
  const h = await v3Host();
  try {
    for (const [label, mangle] of [
      ['truncated', (b) => b.subarray(0, Math.floor(b.length / 2))],
      ['corrupt body', (b) => { const c = Buffer.from(b); for (let i = 20; i < 60 && i < c.length - 8; i++) c[i] ^= 0xff; return c; }]]) {
      const s = gzSource(label === 'truncated' ? 'b' : 'c');
      try {
        fs.writeFileSync(s.gz, mangle(fs.readFileSync(s.gz)));
        const before = entries(h.base);
        const r = await run(() => updateSeed(['--seed', s.gz, '--unsigned-development'], deps(h.base)));
        assert.equal(r.code, 1, `${label}\n${r.all}`);
        assert.match(r.all, /The seed was not accepted/, label);
        assert.deepEqual(entries(h.base), before, `${label}: nothing staged, installed or left behind`);
        assert.equal(activeBundleId(h.base), h.id);
      } finally { s.cleanup(); }
    }
  } finally { h.cleanup(); }
});

test('GZ6 space is admitted for the DECOMPRESSED size: enough for the .gz but not for the database refuses', async () => {
  const h = await v3Host(); const s = gzSource('9'); const s2 = gzSource('8');
  try {
    const need = (x) => x.rawSize + V3_SIDECARS + 4 + RESERVE;
    const short = await run(() => updateSeed(['--seed', s.gz, '--unsigned-development'], deps(h.base, { seam: fakeFs(need(s) - 1) })));
    assert.equal(short.code, 1, short.all);
    assert.match(short.all, /not enough free space/);
    assert.deepEqual(staging(h.base), []);
    const at = await run(() => updateSeed(['--seed', s2.gz, '--unsigned-development'], deps(h.base, { seam: fakeFs(need(s2)) })));
    assert.equal(at.code, 0, `exactly the decompressed size is admitted\n${at.all}`);
  } finally { s.cleanup(); s2.cleanup(); h.cleanup(); }
});

test('GZ7 decompression is bounded: a .gz that expands past the limit refuses and removes what it staged', async () => {
  const h = await v3Host(); const s = gzSource('7');
  try {
    const r = await run(() => updateSeed(['--seed', s.gz, '--unsigned-development'],
      deps(h.base, { seam: { gzMaxDbBytes: s.rawSize - 1 } })));
    assert.equal(r.code, 1, r.all);
    assert.match(r.all, /limit/);
    assert.deepEqual(staging(h.base), []);
    assert.equal(activeBundleId(h.base), h.id);
  } finally { s.cleanup(); h.cleanup(); }
});

test('GZ8 a file named .gz that is not gzip refuses, saying so; a raw --seed <db> is unchanged', async () => {
  const h = await v3Host(); const s = gzSource('6', { keepRaw: true });
  try {
    fs.writeFileSync(s.gz, 'not a gzip stream at all');
    const r = await run(() => updateSeed(['--seed', s.gz, '--unsigned-development'], deps(h.base)));
    assert.equal(r.code, 1, r.all);
    assert.match(r.all, /not a gzip file/);
    const raw = await run(() => updateSeed(['--seed', s.db, '--unsigned-development'], deps(h.base)));
    assert.equal(raw.code, 0, raw.all);
  } finally { s.cleanup(); h.cleanup(); }
});

test('GZ9 init and update-seed stage --seed through the one entry that accepts .gz (no command keeps the raw-only path)', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
  for (const f of ['cli/commands/init.js', 'cli/commands/update-seed.js']) {
    const src = fs.readFileSync(path.join(root, f), 'utf8');
    assert.match(src, /await stageIncomingSeed\(opts\.seedPath/, `${f} stages through stageIncomingSeed`);
    assert.doesNotMatch(src, /[^.\w]stageIncoming\(/, `${f} no longer calls the raw-only stageIncoming`);
  }
});
