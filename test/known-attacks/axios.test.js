// Axios attack validation (flagship test)
//
// Simulates the Axios 1.14.1 supply chain attack (2026-03-31): a phantom
// dependency (plain-crypto-js), publisher email change, OIDC provenance
// dropped, and install scripts added. ChainGate fires 4 gates simultaneously:
// dep-structure WARN, publisher-identity WARN, provenance-continuity WARN,
// scope-boundary WARN (V2-demoted from BLOCK). Overall disposition: WARN.
//
// 0.1.4 group 3 (G3 dated note 2 item 6): the REAL axios@1.14.1 declared no install script -- the postinstall was in the
// injected dependency plain-crypto-js@4.2.1, which is N1h's shape (unit 3b). The hook in this fixture's 1.14.1 is a modelling
// device (it feeds scope-boundary's signal); the test using it is named as a variant, and the real shape has its own test.
//
// 0.1.4 (cft-policy-1.2, group 2a E8; r3 §18.7/§18.15): these four pilot gates are CONTRIBUTING rows. Each still fires
// and is recorded, as NOTE, and none of them is a warning on its own, so the disposition is ALLOW. The signals stay in the
// record (detail, `why`); a named row (seed strict tier, install-introduced, N1h) is what makes a 1.2 WARN.
//
// V2 foundation note (Section 7 item 1 of docs/V2_DESIGN.md): during the
// V2 dev window only content-hash can BLOCK. The four advisory signals
// are all observed and persisted to gate_decisions, but the packument is
// NOT rewritten and the tarball is NOT refused. V2 pattern-aware gates
// will restore BLOCK on this fixture once they can distinguish attack-
// shape from legitimate-evolution-shape without cry-wolfing.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as undiciRequest } from 'undici';

import { createProxyServer } from '../../proxy/server.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tmpDbPath() {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-axios-'));
  return { path: join(dir, 'witness.db'), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function startFakeUpstream(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, url: `http://127.0.0.1:${server.address().port}` });
    });
  });
}

async function startProxy(upstreamUrl, witnessDbPath, configOverrides = {}) {
  const server = createProxyServer({
    port: 0,
    host: '127.0.0.1',
    upstream: upstreamUrl,
    witnessDbPath,
    headersTimeoutMs: 5_000,
    bodyTimeoutMs: 5_000,
    ...configOverrides,
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

function close(s) {
  return new Promise((resolve) => s.close(resolve));
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

const FIXED_NOW = Date.parse('2026-04-15T12:00:00.000Z');
function hoursAgo(h) {
  return new Date(FIXED_NOW - h * 3_600_000).toISOString();
}

// ---------------------------------------------------------------------------
// Fixture: axios packument with 8 clean versions + 1 attack version
// ---------------------------------------------------------------------------

const CLEAN_DEPS = {
  'follow-redirects': '^1.15.6',
  'form-data': '^4.0.0',
  'proxy-from-env': '1.1.0',
};

const LEGIT_USER = { name: 'jasonsaayman', email: 'jasonsaayman@gmail.com' };
const ATTACK_USER = { name: 'ifstap', email: 'ifstap@protonmail.me' };

const CLEAN_VERSIONS = [
  '1.7.0', '1.8.0', '1.9.0', '1.10.0',
  '1.11.0', '1.12.0', '1.13.0', '1.14.0',
];

function buildPackument({ hook = true } = {}) {
  const versions = {};
  const time = {
    created: '2019-10-01T00:00:00.000Z',
    modified: '2026-03-31T00:00:00.000Z',
  };

  // 8 clean versions: consistent publisher, deps, provenance, no install scripts
  for (let i = 0; i < CLEAN_VERSIONS.length; i++) {
    const v = CLEAN_VERSIONS[i];
    versions[v] = {
      name: 'axios',
      version: v,
      dependencies: { ...CLEAN_DEPS },
      _npmUser: { ...LEGIT_USER },
      _npmVersion: '10.5.0',
      dist: {
        shasum: `aaaa${i}000aaaa${i}000aaaa${i}000aaaa${i}000`.slice(0, 40),
        integrity: `sha512-CleanAxios${v.replace(/\./g, '')}CleanAxios==`,
        tarball: `https://registry.npmjs.org/axios/-/axios-${v}.tgz`,
        unpackedSize: 430000 + i * 1000,
        // OIDC provenance present on all clean versions
        attestations: {
          url: `https://registry.npmjs.org/-/npm/v1/attestations/axios@${v}`,
          provenance: { predicateType: 'https://slsa.dev/provenance/v1' },
        },
      },
    };
    // Stagger clean versions: 300 to 100 days ago (all well past 72h threshold)
    time[v] = hoursAgo(7200 - i * 600);
  }

  // Attack version: phantom dep, changed publisher, no provenance, install scripts
  versions['1.14.1'] = {
    name: 'axios',
    version: '1.14.1',
    dependencies: {
      ...CLEAN_DEPS,
      'plain-crypto-js': '^4.2.1', // phantom dependency (the real spec)
    },
    ...(hook ? { scripts: { install: 'node install.js' } } : {}),   // the variant's hook (triggers has_install_scripts)
    _npmUser: { ...ATTACK_USER }, // publisher change
    _npmVersion: '10.5.0',
    dist: {
      shasum: 'ffff9999ffff9999ffff9999ffff9999ffff9999',
      integrity: 'sha512-AttackAxios1141AttackAxios1141Attack==',
      tarball: 'https://registry.npmjs.org/axios/-/axios-1.14.1.tgz',
      unpackedSize: 445000,
      // NO attestations → provenance_present: false
    },
  };
  // Published 96h ago (> 72h threshold → release-age ALLOW)
  time['1.14.1'] = hoursAgo(96);

  return JSON.stringify({
    name: 'axios',
    'dist-tags': { latest: '1.14.1' },
    versions,
    time,
  });
}

const packumentBody = buildPackument();

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('axios-shaped VARIANT with an install hook in 1.14.1 (a fixture device; the real release had none): T1.1 WARN, the 4 pilot signals NOTE', async (t) => {
  const { path: dbPath, cleanup } = tmpDbPath();

  const upstream = await startFakeUpstream((req, res) => {
    if (req.url === '/axios') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(packumentBody);
    } else if (req.url.endsWith('.tgz')) {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(Buffer.from([0x1f, 0x8b, 0x08]));
    } else {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end('{"error":"not found"}');
    }
  });

  const proxy = await startProxy(upstream.url, dbPath, { _nowMs: FIXED_NOW });

  try {
    // Pre-populate dep cache: plain-crypto-js published 6h ago (< 24h → scope-boundary BLOCK)
    proxy.server.depCache.recordOk('plain-crypto-js', hoursAgo(6));

    // -- Observation 1: establish baselines (history empty → all ALLOW) --
    await t.test('first observation: baselines recorded, all ALLOW', async () => {
      const resp = await undiciRequest(`${proxy.url}/axios`);
      assert.equal(resp.statusCode, 200);
      await resp.body.text(); // drain

      // 0.1.4 group 3a (T1.1, D-T7): install-introduced reads the served packument, not local history, so the hook 1.14.1
      // introduces is a named WARN on the package's FIRST sight. The pattern gates still wait for local history.
      const decision = proxy.server.witnessDb.getLatestDecision('axios', '1.14.1');
      assert.ok(decision, 'decision should exist for 1.14.1');
      assert.equal(decision.disposition, 'WARN', 'first-seen: install-introduced (named) WARNs');
      const t11 = decision.gates_fired.find((g) => g.gate === 'install-introduced');
      assert.equal(t11?.result, 'WARN', JSON.stringify(decision.gates_fired));
    });

    // Re-populate dep cache in case the background dep-fetcher overwrote it
    proxy.server.depCache.recordOk('plain-crypto-js', hoursAgo(6));

    // -- Observation 2: full history available → gates fire on 1.14.1 --
    await t.test('second observation: 1.14.1 observed as WARN, NOT stripped', async () => {
      const resp = await undiciRequest(`${proxy.url}/axios`);
      assert.equal(resp.statusCode, 200);
      const parsed = JSON.parse(await resp.body.text());

      // V1 post-demotion: WARN does not strip versions from the packument.
      // 1.14.1 stays visible to npm — advisory only.
      assert.ok('1.14.1' in parsed.versions, '1.14.1 stays in packument (WARN, not BLOCK)');

      // Clean versions still present
      for (const v of CLEAN_VERSIONS) {
        assert.ok(v in parsed.versions, `${v} should remain in packument`);
      }

      // dist-tags.latest NOT downgraded (nothing blocked)
      assert.equal(parsed['dist-tags'].latest, '1.14.1');
    });

    await t.test('gate_decisions for 1.14.1: the 4 pilot signals are recorded as NOTE (cft-policy-1.2 E8)', async () => {
      const decision = proxy.server.witnessDb.getLatestDecision('axios', '1.14.1');
      // cft-policy-1.2: the four pilot signals are contributing (NOTE, group 2a E8); the WARN is T1.1's named row (group 3a)
      assert.equal(decision.disposition, 'WARN',
        'install-introduced is the named WARN; the four contributing signals are kept as NOTE beside it');

      const gateMap = {};
      for (const g of decision.gates_fired) {
        gateMap[g.gate] = g;
      }

      // content-hash: ALLOW (same hash as recorded baseline from obs 1)
      assert.ok(gateMap['content-hash'], 'content-hash gate should be present');
      assert.equal(gateMap['content-hash'].result, 'ALLOW',
        'content-hash should ALLOW (same hash as recorded baseline)');

      // dep-structure: WARN (plain-crypto-js not in prior 8 versions)
      assert.ok(gateMap['dep-structure'], 'dep-structure gate should be present');
      assert.equal(gateMap['dep-structure'].result, 'NOTE');
      assert.match(gateMap['dep-structure'].detail, /plain-crypto-js/);

      // publisher-identity: WARN (email changed)
      assert.ok(gateMap['publisher-identity'], 'publisher-identity gate should be present');
      assert.equal(gateMap['publisher-identity'].result, 'NOTE');
      assert.match(gateMap['publisher-identity'].detail, /publisher changed/i);

      // provenance-continuity: WARN (prior had OIDC, this doesn't)
      assert.ok(gateMap['provenance-continuity'], 'provenance-continuity gate should be present');
      assert.equal(gateMap['provenance-continuity'].result, 'NOTE');

      // release-age: ALLOW (96h > 72h threshold)
      assert.ok(gateMap['release-age'], 'release-age gate should be present');
      assert.equal(gateMap['release-age'].result, 'ALLOW');

      // install-introduced (T1.1, named): the hook 1.14.1 adds, absent from every settled earlier version
      assert.equal(gateMap['install-introduced']?.result, 'WARN');
      assert.match(gateMap['install-introduced'].detail, /no earlier version \(settled 24 h/);

      // scope-boundary: WARN (V2-demoted from BLOCK; detail still names the fresh dep)
      assert.ok(gateMap['scope-boundary'], 'scope-boundary gate should be present');
      assert.equal(gateMap['scope-boundary'].result, 'NOTE',
        'V2 foundation demoted scope-boundary to WARN; cft-policy-1.2 records it as NOTE (contributing)');
      assert.match(gateMap['scope-boundary'].detail, /plain-crypto-js/);
    });

    await t.test('clean version 1.14.0: not BLOCK (still in packument)', async () => {
      const decision = proxy.server.witnessDb.getLatestDecision('axios', '1.14.0');
      assert.ok(decision, 'decision should exist for 1.14.0');
      // On re-observation, 1.14.0's "latest prior" by publish_at is 1.14.1
      // (the attack version), so publisher-identity fires WARN.
      assert.notEqual(decision.disposition, 'BLOCK',
        '1.14.0 should not be BLOCK (it has no attack signals of its own)');
    });

    await t.test('tarball for 1.14.1 → 200 (V1 post-demotion: WARN does not refuse)', async () => {
      const resp = await undiciRequest(`${proxy.url}/axios/-/axios-1.14.1.tgz`);
      assert.equal(resp.statusCode, 200,
        'WARN dispositions do not trigger tarball gate; only BLOCK does');
      await resp.body.text(); // drain
    });

    await t.test('tarball for clean 1.14.0 → 200', async () => {
      const resp = await undiciRequest(`${proxy.url}/axios/-/axios-1.14.0.tgz`);
      assert.equal(resp.statusCode, 200);
      await resp.body.text(); // drain
    });
  } finally {
    await close(proxy.server);
    await close(upstream.server);
    cleanup();
  }
});

test('axios REAL shape (no hook in 1.14.1; the hook is in the injected dependency): ALLOW at observation, N1h WARN at the tarball (3b)', async () => {
  const { path: dbPath, cleanup } = tmpDbPath();
  const body = buildPackument({ hook: false });
  // the injected dependency as the public reporting describes it: 4.2.1 declares the postinstall dropper (fixture text only)
  const plain = JSON.stringify({ name: 'plain-crypto-js', 'dist-tags': { latest: '4.2.1' },
    versions: { '4.2.0': { name: 'plain-crypto-js', version: '4.2.0' }, '4.2.1': { name: 'plain-crypto-js', version: '4.2.1', scripts: { postinstall: 'node setup.js' } } },
    time: { '4.2.0': hoursAgo(200), '4.2.1': hoursAgo(100) } });
  const upstream = await startFakeUpstream((req, res) => {
    if (req.url === '/axios') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(body); return; }
    if (req.url === '/plain-crypto-js') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(plain); return; }
    if (req.url.endsWith('.tgz')) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(Buffer.from([0x1f, 0x8b, 0x08])); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  const proxy = await startProxy(upstream.url, dbPath, { _nowMs: FIXED_NOW });
  try {
    for (let i = 0; i < 2; i += 1) { const r = await undiciRequest(`${proxy.url}/axios`); await r.body.text(); }
    const d = proxy.server.witnessDb.getLatestDecision('axios', '1.14.1');
    const g = Object.fromEntries(d.gates_fired.map((x) => [x.gate, x]));
    assert.equal(d.disposition, 'ALLOW', 'the gap group 2a stated: pilot-only signals do not warn in 1.2');
    assert.equal(g['install-introduced'].result, 'ALLOW', 'no hook in the release itself: T1.1 is quiet (correctly)');
    for (const n of ['dep-structure', 'publisher-identity', 'provenance-continuity']) assert.equal(g[n].result, 'NOTE', n);
    // 3b (D-N7): at the tarball, the added dependency is judged on its own release -> N1h, a named WARN
    const t = await undiciRequest(`${proxy.url}/axios/-/axios-1.14.1.tgz`);
    await t.body.text();
    assert.equal(t.statusCode, 200);
    assert.equal(t.headers['npm-notice'], 'chaingate: WARNING axios@1.14.1: it adds a dependency that runs install scripts. Details: chaingate why axios@1.14.1');
    const after = proxy.server.witnessDb.getLatestDecision('axios', '1.14.1');
    assert.equal(after.disposition, 'WARN');
    assert.match(after.gates_fired.find((x) => x.gate === 'dependency-hooks').detail, /plain-crypto-js@4\.2\.1 \(postinstall\)/);
  } finally {
    await close(proxy.server); await close(upstream.server); cleanup();
  }
});
