// 0.1.4 I1 review finding (group-1 review, 2026-10-11; confirmed by 4 of 5 lenses): the C2 applicable-BLOCK rule
// (witness/decision-rule.js) recognised only the cft-policy-1.0/1.1 detail prefixes, so after the identity moved to
// cft-policy-1.2 no seed-v3 result could clear a stored INPUT or PIN BLOCK. The C2 tests missed it because their clearance
// rows were hand-written 1.1 strings. These cases run the LIVE gate end to end (the real producer of the detail text),
// plus a guard tied to the current policy identity so the next identity move fails here first.
//
// Expected results: U-05 owner decision 10 C2 table (a definitive later evaluation clears; nothing else does), unchanged
// in substance; 1.2 keeps 1.1's D4 pin semantics, so a 1.2 "no recorded advisory pins this version" clears a pin.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { POLICY_CONTRACT_VERSION } from '../../seed/v3/policy.js';
import { REASON, clears } from '../../witness/decision-rule.js';
import { seed, registry, proxy, tarball, packument, tmp, stopAll, safely } from '../helpers/u05-d10.mjs';

const silence = () => { const e = console.error; const w = console.warn; console.error = () => {}; console.warn = () => {}; return () => { console.error = e; console.warn = w; }; };

async function world(t, seedOpts = {}) {
  const dir = tmp('cft014-clr'); const reg = await registry(); const s = seed(seedOpts);
  const restore = silence();
  t.after(async () => { await stopAll(); restore(); await safely(() => reg.close()); await safely(() => s.cleanup());
    await safely(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })); });
  return { dir, reg, s, witness: path.join(dir, 'witness.db') };
}

test('I1-C1 (BLOCK, live) an input-rule BLOCK from an unreadable seed is cleared by the next clean 1.2 evaluation', async (t) => {
  const w = await world(t); const sw = { on: true };
  const px = await proxy({ upstream: w.reg.url, witness: w.witness, policy: 'BLOCK', seedDb: w.s.dbPath, seedFault: sw });
  t.after(() => px.stop());
  assert.ok(!(await packument(px, 'p')).versions.includes('1.4.0'), 'while the seed cannot be read, 1.4.0 is withheld');
  assert.equal((await tarball(px, 'p', '1.4.0')).status, 403);
  sw.on = false;
  assert.ok((await packument(px, 'p')).versions.includes('1.4.0'), 'the seed recovered: a clean evaluation clears the input BLOCK');
  assert.equal((await tarball(px, 'p', '1.4.0')).status, 200);
});

test('I1-C2 (live) a pin BLOCK is cleared by a 1.2 evaluation under a seed that no longer pins the version', async (t) => {
  const w = await world(t);
  let px = await proxy({ upstream: w.reg.url, witness: w.witness, policy: 'BLOCK', seedDb: w.s.dbPath });
  assert.ok(!(await packument(px, 'p')).versions.includes('1.3.0'), 'pinned: withheld');
  await px.stop();
  const unpinned = seed({ withoutPin: '1.3.0' });
  t.after(() => safely(() => unpinned.cleanup()));
  px = await proxy({ upstream: w.reg.url, witness: w.witness, policy: 'BLOCK', seedDb: unpinned.dbPath });
  t.after(() => px.stop());
  assert.ok((await packument(px, 'p')).versions.includes('1.3.0'), 'the advisory is gone: the pin BLOCK is cleared');
  assert.equal((await tarball(px, 'p', '1.3.0')).status, 200);
});

test('I1-C3 (guard) the CURRENT policy identity is a clearance prefix for both the input and the pin reason', () => {
  const p = `${POLICY_CONTRACT_VERSION}: `;
  assert.ok(clears(REASON.INPUT, [{ gate: 'seed-v3', result: 'ALLOW',
    detail: `${p}seed-v3:known-malicious-pin: no recorded advisory pins this version | seed-v3:channel-a:critical: below threshold` }]),
  `${POLICY_CONTRACT_VERSION} clears an input BLOCK`);
  assert.ok(clears(REASON.PIN, [{ gate: 'seed-v3', result: 'ALLOW',
    detail: `${p}seed-v3:known-malicious-pin: no recorded advisory pins this version` }]),
  `${POLICY_CONTRACT_VERSION} clears a pin BLOCK`);
  // and the rule is otherwise unchanged: an input-rule result under the current identity still never clears
  assert.equal(clears(REASON.INPUT, [{ gate: 'seed-v3', result: 'WARN', detail: `${p}seed-v3:input: Error: boom` }]), false);
  assert.equal(clears(REASON.PIN, [{ gate: 'seed-v3', result: 'ALLOW', detail: `${p}seed-v3:known-malicious-pin: advisory pin lookup FAILED` }]), false);
});
