// 0.1.4 group 5 — release docs (G5-1): the README describes what 0.1.4 does and promises nothing it does not. Expected
// results: ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G4-CLOSEOUT-20261012.md §4 (D-D1, D-D2), written before the edits.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const read = (f) => fs.readFileSync(fileURLToPath(new URL(`../../${f}`, import.meta.url)), 'utf8');

test('G5-1 (D-D1, D-D2) the README and SECURITY.md describe 0.1.4: commands, record, policy, check scope; no forbidden promise', () => {
  const readme = read('README.md');
  for (const c of ['init', 'status', 'check', 'why', 'history', 'allow', 'overrides', 'update-seed', 'doctor', 'stop', 'report', 'accept', 'pin', 'unpin']) {
    assert.ok(readme.includes(`\`${c}\``), c);
  }
  assert.match(readme, /Fourteen commands/);
  assert.match(readme, /chaingate\.check\/3/);
  assert.match(readme, /cft-policy-1\.2/);
  assert.match(readme, /`chaingate check` \(the CI command\) evaluates the seed only in 0\.1\.4/);
  for (const k of ['install-introduced', 'N1h', 'MC', 'chaingate report', 'chaingate accept', 'chaingate pin', 'chaingate unpin', 'no-store']) {
    assert.ok(readme.includes(k), k);
  }
  for (const re of [/you will be told/i, /will be blocked/i, /will be held/i, /re-checked later/i, /\b0 warnings\b/i]) assert.doesNotMatch(readme, re);
  const security = read('SECURITY.md');
  assert.match(security, /`chaingate accept`, `chaingate pin` and\s+`chaingate unpin` -- pass the same integrity gate/);
});
