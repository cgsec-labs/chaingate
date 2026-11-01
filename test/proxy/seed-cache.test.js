// Since 0.1.6: the seed cache in the proxy. With `seed_cache_url` set (on unless `"seed_cache": false`), the proxy reads the seed
// cache instead of a full seed. Before deciding a package whose bucket the cache does not hold, it fetches that bucket, waiting
// at most 5 seconds; past that the package is uncovered (the no-evidence choice decides) and the bucket keeps downloading for the
// next request. The root is refreshed at start and hourly; buckets a new root changes are fetched again. The bucket host here is
// a local server serving the seed lane's fixture unchanged. Written before the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateConfig, ConfigUnreadable, writeConfig, DEFAULT_POLICY, DEFAULT_SEED_CACHE_URL } from '../../config-store.js';
import { loadConfig } from '../../proxy/config.js';
import { createProxyServer } from '../../proxy/server.js';
import { createSeedCache } from '../../proxy/seed-cache.js';
import { shardSource } from '../../cli/seed-shards.js';
import Database from 'better-sqlite3';
import R from '../../seed/v3/reader.js';
import { renderReport } from '../../cli/report-render.js';
import * as SH from '../../seed/v3/shards.js';
import { docFor, LIVE } from '../seed-v3/u05-fixtures.mjs';
import { fixtureRel, caPathOf } from '../helpers/shards-host.mjs';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'shards-1.0');
const EXPECTED = JSON.parse(fs.readFileSync(path.join(FIX, 'good', 'expected.json'), 'utf8'));
const SEED_KEY = crypto.createPublicKey(fs.readFileSync(path.join(FIX, 'good', 'fixture-seed-pub.pem')));
const NOW = Date.parse(EXPECTED.now);
const good = (rel) => fs.readFileSync(path.join(FIX, 'good', rel));
const ROOT = SH.verifyRoot({ rootBytes: good('root.json'), sig: good('root.json.sig'), keysBytes: good('keys.json'),
  keysSig: good('keys.json.sig'), seedKey: SEED_KEY, now: NOW, bits: 3 });

const listen = (srv) => new Promise((r) => srv.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${srv.address().port}`)));
const close = (srv) => new Promise((r) => srv.close(() => r()));
const get = (url) => new Promise((resolve, reject) => {
  http.get(url, { agent: false }, (res) => {
    let b = ''; res.setEncoding('utf8'); res.on('data', (x) => { b += x; });
    res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* not JSON */ } resolve({ status: res.statusCode, json }); });
  }).on('error', reject);
});

// ------------------------------------------------------------------------------------------------ configuration
test('SC1 seed_cache_url is an https base URL (the published host when unset); seed_cache is true or false', () => {
  assert.equal(DEFAULT_SEED_CACHE_URL, 'https://shards.cgsec.dev/');
  assert.deepEqual(validateConfig({}).seedCache, { url: DEFAULT_SEED_CACHE_URL, enabled: true });
  assert.deepEqual(validateConfig({ seed_cache_url: 'https://seed.example/shards/' }).seedCache, { url: 'https://seed.example/shards/', enabled: true });
  assert.deepEqual(validateConfig({ seed_cache_url: 'https://seed.example/shards/', seed_cache: false }).seedCache,
    { url: 'https://seed.example/shards/', enabled: false });
  for (const bad of [{ seed_cache_url: 'http://seed.example/' }, { seed_cache_url: 7 }, { seed_cache: 'yes' }]) {
    assert.throws(() => validateConfig(bad), ConfigUnreadable, JSON.stringify(bad));
  }
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'cg016-sc-'));
  try {
    writeConfig(path.join(home, 'config.json'), { policy: DEFAULT_POLICY, advisory_feed: false, seed_cache_url: 'https://seed.example/shards/' });
    const c = loadConfig({ CHAINGATE_HOME: home });
    assert.equal(c.seedCacheUrl, 'https://seed.example/shards/');
    assert.equal(c.seedCachePath, path.join(home, 'seed-cache', 'chaingate-seed.db'));
    assert.equal(c.seedV3Path, null, 'no cache yet and no bundle: nothing to read');
    writeConfig(path.join(home, 'config.json'), { policy: DEFAULT_POLICY, advisory_feed: false, seed_cache_url: 'https://seed.example/shards/', seed_cache: false });
    assert.equal(loadConfig({ CHAINGATE_HOME: home }).seedCacheUrl, null);
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
});

test('SC2 a cache holding a bucket replaces the full seed: the proxy reads it, authenticated', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'cg016-sc-'));
  try {
    writeConfig(path.join(home, 'config.json'), { policy: DEFAULT_POLICY, advisory_feed: false, seed_cache_url: 'https://seed.example/shards/' });
    const cache = path.join(home, 'seed-cache', 'chaingate-seed.db');
    fs.mkdirSync(path.dirname(cache));
    SH.importBucket(cache, ROOT, 2, SH.verifyBucketBytes(ROOT, 2, good('buckets/00002.db.gz')));
    const c = loadConfig({ CHAINGATE_HOME: home });
    assert.equal(c.seedV3Path, cache); assert.equal(c.seedV3Trust, 'authenticated'); assert.equal(c.seedV3BundleId, null);
    assert.equal(c.policyOnUnusableInput, DEFAULT_POLICY.on_unusable_input);
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------------------------------------ the proxy
/** The bucket host (the fixture, or `down`: every request refused) and a registry with pkg-b's document. */
async function withProxy({ held = [0], down = false, slowMs = 0, waitMs = 5_000, missing = [], extraDocs = {} } = {}, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg016-scp-'));
  const cache = path.join(dir, 'chaingate-seed.db');
  for (const i of held) SH.importBucket(cache, ROOT, i, SH.verifyBucketBytes(ROOT, i, good(`buckets/${String(i).padStart(5, '0')}.db.gz`)));
  const seen = [];
  const host = http.createServer((req, res) => {
    const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname.slice(1));
    seen.push(rel);
    if (down || missing.some((i) => rel === caPathOf(ROOT, i))) { res.writeHead(down ? 503 : 404); return res.end(); }
    let body; try { body = good(fixtureRel(rel)); } catch { res.writeHead(404); return res.end(); }
    setTimeout(() => { res.writeHead(200, { etag: `"${crypto.createHash('sha256').update(body).digest('hex').slice(0, 16)}"` }); res.end(body); },
      rel.startsWith('buckets/') ? slowMs : 0);
  });
  const docs = { 'pkg-b': docFor('pkg-b'), 'pkg-e': docFor('pkg-e'), ...extraDocs };
  const upstream = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url).slice(1);
    if (url.includes('/-/')) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); return res.end('tarball-bytes'); }
    if (docs[url]) { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify(docs[url])); }
    res.writeHead(404, { 'content-type': 'application/json' }); return res.end('{}');
  });
  const hostUrl = `${await listen(host)}/`; const upstreamUrl = await listen(upstream);
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: path.join(dir, 'witness.db'),
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedV3Path: cache, seedV3Trust: 'authenticated',
    policyOnUnusableInput: LIVE.on_unusable_input, policyOnNoEvidence: LIVE.on_no_evidence,
    seedCacheUrl: hostUrl, seedCachePath: cache, seedCacheKey: SEED_KEY, seedCacheBits: 3, seedCacheNow: () => NOW, seedCacheWaitMs: waitMs });
  const base = await listen(proxy);
  const realErr = console.error; console.error = () => {};
  try { return await fn({ base, proxy, seen, cache }); } finally {
    console.error = realErr; await close(proxy); await close(upstream); await close(host); fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('SC7 a proxy whose seed cache directory does not exist yet (started after `init --seed`): its first root refresh creates the cache', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg016-scp7-'));
  const cache = path.join(dir, 'seed-cache', 'chaingate-seed.db');
  const host = http.createServer((req, res) => {
    const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname.slice(1));
    let body; try { body = good(fixtureRel(rel)); } catch { res.writeHead(404); return res.end(); }
    res.writeHead(200); res.end(body);
  });
  const upstream = http.createServer((req, res) => { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); });
  const hostUrl = `${await listen(host)}/`; const upstreamUrl = await listen(upstream);
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: path.join(dir, 'witness.db'),
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedCacheUrl: hostUrl, seedCachePath: cache, seedCacheKey: SEED_KEY,
    seedCacheBits: 3, seedCacheNow: () => NOW });
  const realErr = console.error; const logged = []; console.error = (...a) => { logged.push(a.join(' ')); };
  try {
    await listen(proxy);
    const r = await proxy.refreshSeedCache();
    assert.equal(r?.outcome, 'accepted', JSON.stringify({ r, logged }));
    assert.equal(fs.existsSync(cache), true);
    assert.ok(!logged.some((l) => /directory does not exist/.test(l)), logged.join('\n'));
  } finally {
    console.error = realErr; await close(proxy); await close(upstream); await close(host); fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('SC3 a package whose bucket the cache does not hold: the proxy fetches it before deciding, and the seed\'s pin BLOCKs', async () => {
  await withProxy({ held: [0] }, async ({ base, proxy, seen }) => {
    const pk = await get(`${base}/pkg-b`);
    assert.equal(pk.status, 200);
    assert.ok(!('1.1.0' in pk.json.versions), 'the version the seed pins is removed from the metadata npm sees');
    assert.ok(seen.includes(caPathOf(ROOT, 2)));
    assert.equal(proxy.seedCacheState().buckets_held, 2);
    const t = await get(`${base}/pkg-b/-/pkg-b-1.1.0.tgz`);
    assert.equal(t.status, 403);
  });
});

test('SC4 a bucket host that is down or slow: the decision waits at most the bound, the package is uncovered (WARN, served), and the bucket arrives for the next request', async () => {
  await withProxy({ held: [0], down: true, waitMs: 300 }, async ({ base, proxy }) => {
    const t0 = Date.now();
    const pk = await get(`${base}/pkg-b`);
    assert.ok(Date.now() - t0 < 4_000, 'no longer than the wait and the request itself');
    assert.equal(pk.status, 200); assert.ok('1.1.0' in pk.json.versions, 'uncovered warns; it does not block');
    assert.equal(proxy.seedCacheState().buckets_held, 1);
  });
  await withProxy({ held: [0], slowMs: 1_000, waitMs: 200 }, async ({ base, proxy }) => {
    const first = await get(`${base}/pkg-b`);
    assert.ok('1.1.0' in first.json.versions, 'decided before the slow bucket arrived');
    await proxy.seedCacheIdle();
    assert.equal(proxy.seedCacheState().buckets_held, 2, 'the bucket kept downloading');
    const again = await get(`${base}/pkg-b`);
    assert.ok(!('1.1.0' in again.json.versions), 'the next decision has the bucket and the pin');
  });
});

test('SC6 a bucket the host does not have (404): the proxy refreshes the root and asks once more; still missing, the package is uncovered (WARN, served)', async () => {
  await withProxy({ held: [0], missing: [2] }, async ({ base, proxy, seen }) => {
    await proxy.seedCacheIdle();
    const roots = seen.filter((r) => r === 'root.json.gz').length;
    const pk = await get(`${base}/pkg-b`);
    assert.equal(pk.status, 200); assert.ok('1.1.0' in pk.json.versions, 'uncovered warns; it does not block');
    await proxy.seedCacheIdle();
    assert.equal(seen.filter((r) => r === caPathOf(ROOT, 2)).length, 2, 'asked twice');
    assert.equal(seen.filter((r) => r === 'root.json.gz').length, roots + 1, 'the root refreshed once in between');
    assert.equal(proxy.seedCacheState().buckets_held, 1);
  });
});

test('SC5 the root refresh: a 304 changes nothing; the state names the root, its age and the last fetch', async () => {
  await withProxy({ held: [2] }, async ({ proxy, seen }) => {
    const r = await proxy.refreshSeedCache();
    assert.ok(['same', 'accepted'].includes(r.outcome), JSON.stringify(r));
    const r2 = await proxy.refreshSeedCache();
    assert.equal(r2.outcome, 'same');
    assert.equal(seen.filter((x) => x === 'root.json.gz').length, 2);
    const st = proxy.seedCacheState();
    assert.equal(st.root_cut_at, ROOT.cut_at); assert.equal(st.buckets_held, 1); assert.equal(st.last_fetch.outcome, 'same');
  });
});

// ------------------------------------------------------------------------------------------------ the refresh never waits on itself
// Since 0.1.6.1. A refresh fetches buckets (with no cache in use, bucket 0; after a new root, the buckets it dropped). A 404 on one of
// them used to ask for a root refresh, which returned the refresh in progress: each waited on the other, the refresh never ended,
// and every later refresh returned it for the life of the process. Now the 404 waits only for the root the refresh already holds.
const STUCK = Symbol('stuck');
const settles = (p, ms = 3_000) => { let t; return Promise.race([p, new Promise((r) => { t = setTimeout(() => r(STUCK), ms); })]).finally(() => clearTimeout(t)); };
async function withHost(missing, fn) {
  const seen = [];
  const host = http.createServer((req, res) => {
    const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname.slice(1));
    seen.push(rel);
    if (missing.some((i) => rel === caPathOf(ROOT, i))) { res.writeHead(404); return res.end(); }
    let body; try { body = good(fixtureRel(rel)); } catch { res.writeHead(404); return res.end(); }
    res.writeHead(200); res.end(body);
  });
  const url = `${await listen(host)}/`;
  try { return await fn({ url, seen }); } finally { await close(host); }
}
const heldIn = (cache) => { const db = new Database(cache, { readonly: true }); try { return SH.cacheBuckets(db).map((b) => b.i); } finally { db.close(); } };

test('SC8 a bucket missing while a refresh brings the first bucket: the refresh ends, and a later refresh fetches it when the host has it again', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg0161-sc8-'));
  const cache = path.join(dir, 'chaingate-seed.db');
  const missing = [0];
  try {
    await withHost(missing, async ({ url, seen }) => {
      const sc = createSeedCache({ get: shardSource(url), cachePath: cache, seedKey: SEED_KEY, bits: 3, now: () => NOW });
      const first = await settles(sc.refresh());
      assert.notEqual(first, STUCK, 'the refresh ended');
      assert.equal(first.outcome, 'accepted');
      assert.equal(seen.filter((r) => r === caPathOf(ROOT, 0)).length, 2, 'asked once more after the 404');
      assert.deepEqual(heldIn(cache), []);
      missing.length = 0;                                               // the host recovers
      const second = await settles(sc.refresh());
      assert.notEqual(second, STUCK, 'a later refresh is a new refresh, not the one before');
      assert.deepEqual(heldIn(cache), [0], 'the first bucket arrived');
      assert.notEqual(await settles(sc.idle()), STUCK);
    });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('SC9 a bucket a new root dropped and the host does not have: the refresh ends, the bucket is uncovered, and the next refresh runs', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg0161-sc9-'));
  const cache = path.join(dir, 'chaingate-seed.db');
  try {
    for (const i of [2, 3]) SH.importBucket(cache, ROOT, i, SH.verifyBucketBytes(ROOT, i, good(`buckets/0000${i}.db.gz`)));
    const seed = R.openSeed(cache, { trust: R.TRUST_AUTHENTICATED, pubkey: SEED_KEY, shardBits: 3, now: () => NOW });
    try {
      // the cache's root becomes an older one under which bucket 3 had other rows: the fixture's root is then a new root dropping it
      const db = new Database(cache);
      try {
        db.prepare("UPDATE shard_root SET digest = ?, cut_at = '2000-01-01T00:00:00Z' WHERE id = 1").run('0'.repeat(64));
        db.prepare('UPDATE shard_buckets SET logical = ? WHERE i = 3').run('1'.repeat(64));
      } finally { db.close(); }
      await withHost([3], async ({ url, seen }) => {
        const sc = createSeedCache({ get: shardSource(url), cachePath: cache, seedKey: SEED_KEY, bits: 3, now: () => NOW });
        sc.attach(seed);
        const r = await settles(sc.refresh());
        assert.notEqual(r, STUCK, 'the refresh ended');
        assert.equal(r.outcome, 'accepted'); assert.deepEqual(r.dropped, [3]);
        assert.equal(seen.filter((x) => x === caPathOf(ROOT, 3)).length, 2, 'asked once more after the 404');
        assert.deepEqual(heldIn(cache), [2], 'bucket 3 stays uncovered');
        const next = await settles(sc.refresh());
        assert.notEqual(next, STUCK, 'the next hourly refresh runs');
        assert.equal(next.outcome, 'same');
        assert.notEqual(await settles(sc.idle()), STUCK);
      });
    } finally { seed.close(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------------------------------------ the seed could not answer
// Since 0.1.6.1. A version decided while its bucket was not held was checked neither against its history nor against the seed's
// recorded advisories (the pins feed still was). The download carries a notice saying so, and the install record marks it, so the
// report counts it apart from a package the seed has no history for. A package the seed does not have (in a held bucket) stays
// quiet on the download, as before.
const getH = (url) => new Promise((resolve, reject) => {
  http.get(url, { agent: false }, (res) => { res.resume(); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers })); })
    .on('error', reject);
});
const servedOf = (r, name) => (r.json?.installs ?? []).flatMap((i) => i.events ?? []).filter((e) => e.kind === 'served' && e.package === name);

test('SC10 a version decided while its seed bucket could not be fetched: the download says it was not checked by the seed, and the install record marks it', async () => {
  await withProxy({ held: [0], down: true, waitMs: 300 }, async ({ base }) => {
    const pk = await get(`${base}/pkg-b`);
    assert.equal(pk.status, 200);
    const v = Object.keys(pk.json.versions).find((x) => x !== '1.1.0');
    const t = await getH(`${base}/pkg-b/-/pkg-b-${v}.tgz`);
    assert.equal(t.status, 200);
    assert.equal(t.headers['npm-notice'], `chaingate: NOT CHECKED pkg-b@${v}: its seed data could not be downloaded in time, so the `
      + `seed history and advisory checks did not run. Details: chaingate why pkg-b@${v}`);
    assert.equal(t.headers['cache-control'], 'no-store', 'npm prints a notice only on a response it does not cache');
    const rep = await get(`${base}/_chaingate/report`);
    const served = servedOf(rep, 'pkg-b');
    assert.equal(served.length, 1); assert.equal(served[0].seed_unheld, true); assert.equal(served[0].notice, true);
  });
});

test('SC11 a package the seed does not have, in a bucket the cache holds: no notice on the download, and no mark in the install record', async () => {
  let name = null;
  for (let n = 0; name === null; n += 1) if (SH.bucketOf(`zz-new-${n}`, 3) === 0) name = `zz-new-${n}`;
  await withProxy({ held: [0], extraDocs: { [name]: docFor(name) } }, async ({ base }) => {
    const pk = await get(`${base}/${name}`);
    assert.equal(pk.status, 200);
    const v = Object.keys(pk.json.versions)[0];
    const t = await getH(`${base}/${name}/-/${name}-${v}.tgz`);
    assert.equal(t.status, 200);
    assert.equal(t.headers['npm-notice'], undefined);
    const served = servedOf(await get(`${base}/_chaingate/report`), name);
    assert.equal(served.length, 1); assert.equal(served[0].seed_unheld, undefined);
  });
});

test('SC12 the report counts versions the seed could not check (bucket not fetched) apart from those it has no history for, and never says every package was checked', () => {
  const START = '2026-10-29T12:00:00.000Z';
  const ev = (pkg, over) => ({ at: START, kind: 'served', package: pkg, version: '1.0.0', class: 'clean', coverage: 'not-covered',
    named: [], contributing: [], reason: 'r', policy: 'cft-policy-1.3', notice: false, k: null, ...over });
  const text = (events) => renderReport({ service: 'chaingate-proxy', version: '0.1.6.1', started_at: START, policy: 'cft-policy-1.3',
    view: 'latest', seed: null, stats: {}, installs: [{ key: 'npm-session:a', grouping: 'npm-session', started_at: START, last_at: START,
      dropped: 0, dropped_important: 0, events }] }, { source: 'proxy' }).text;
  const both = text([ev('a', { seed_unheld: true, notice: true }), ev('b')]);
  const rows = both.split('\n');
  assert.ok(rows.includes('  Not checked by the seed           1'), both);
  assert.ok(both.includes('  Not checked by the seed (its seed data could not be downloaded in time):\n    a@1.0.0'), both);
  assert.ok(rows.includes('  Checked only by install rule      1'), both);
  assert.ok(!both.includes('Every package served'), both);
  const hookOnly = text([ev('b')]);
  assert.ok(hookOnly.split('\n').includes('  Not checked by the seed           0'), hookOnly);
  assert.ok(!hookOnly.includes('Not checked by the seed ('), hookOnly);
  assert.ok(hookOnly.split('\n').includes('  Checked only by install rule      1'), hookOnly);
});

test('SC13 the report on a seed cache names the cache root, not "no seed loaded"', async () => {
  await withProxy({ held: [0] }, async ({ base }) => {
    const r = await get(`${base}/_chaingate/report`);
    assert.equal(r.json.seed.cache.root_cut_at, ROOT.cut_at); assert.equal(r.json.seed.cache.seed_version, EXPECTED.seed_version);
    const seedLine = renderReport(r.json, { source: 'proxy' }).text.split('\n')[1];   // since 0.1.6.1 the seed has its own header line
    assert.match(seedLine, /^Seed {15}seed cache \(seed seed-v0\.0-fixture, root of 2026-10-29T12:00:00Z, history to [^)]+\)$/, seedLine);
    assert.doesNotMatch(seedLine, /no seed loaded/);
  });
});
