// 0.1.4 Tier 0, A7 (failing-first spec `0.1.4-DESIGN-failing-first-test-specs-20261008T075255Z.md`, Part A; seed-base
// decision table F6): `/_chaingate/self` reports the loaded seed's `history_cutoff`. The seed binds it
// (`SEED_BINDING_KEYS` in checker.js) but the endpoint did not show it, so `init`, `doctor` and a reader of the self
// report could not tell how old the history behind every seed comparison is.
//
// Expected results come from the spec and the decision table, written before this file. Display only: no decision,
// disposition or record changes.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createProxyServer } from '../../proxy/server.js';
import { buildSeed, LIVE } from './u05-fixtures.mjs';

const listen = (srv) => new Promise((resolve) => { srv.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${srv.address().port}`)); });
const close = (srv) => new Promise((resolve) => { srv.close(() => resolve()); });
const getJson = (url) => new Promise((resolve, reject) => {
  http.get(url, { agent: false }, (res) => {
    let b = ''; res.setEncoding('utf8'); res.on('data', (x) => { b += x; });
    res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(b) }));
  }).on('error', reject);
});

async function withProxy(seedPath, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-a7-'));
  const conf = { port: 0, host: '127.0.0.1', upstream: 'http://127.0.0.1:1', witnessDbPath: path.join(dir, 'witness.db'),
    headersTimeoutMs: 2_000, bodyTimeoutMs: 2_000 };
  if (seedPath) Object.assign(conf, { seedV3Path: seedPath, seedV3Trust: 'unsigned-development',
    policyOnUnusableInput: LIVE.on_unusable_input, policyOnNoEvidence: LIVE.on_no_evidence });
  const proxy = createProxyServer(conf);
  const url = await listen(proxy);
  try {
    return await fn(url);
  } finally {
    await close(proxy);
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('A7: /_chaingate/self reports the loaded seed history_cutoff, read from the seed metadata', async () => {
  const seed = buildSeed({ layout: '1.1' });
  try {
    await withProxy(seed.dbPath, async (url) => {
      const r = await getJson(`${url}/_chaingate/self`);
      assert.equal(r.status, 200);
      assert.ok(r.json.seed_v3, 'a v3 seed is loaded');
      assert.ok(Object.hasOwn(r.json.seed_v3, 'history_cutoff'), 'seed_v3 carries history_cutoff');
      assert.equal(r.json.seed_v3.history_cutoff, '2026-12-31T00:00:00Z', 'the value is the seed metadata value');
      // the members that were already there are unchanged
      assert.equal(r.json.seed_v3.corpus_snapshot_digest, 'f'.repeat(64));
      assert.equal(r.json.seed_v3.schema_version, '3');
    });
  } finally {
    seed.cleanup();
  }
});

test('A7: with no seed loaded the self report is unchanged (seed_v3 is null)', async () => {
  await withProxy(null, async (url) => {
    const r = await getJson(`${url}/_chaingate/self`);
    assert.equal(r.status, 200);
    assert.equal(r.json.seed_v3, null);
  });
});
