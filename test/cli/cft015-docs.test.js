// 0.1.5 release docs: the README describes the rules 0.1.5 adds, as built (gates/size-jump-provenance.js, identity-break.js,
// entry-path-change.js, gates/row-class.js, config-store.js static_withhold), and its contributing list is current
// (S0 and S5 were named in 0.1.5, so "the five tarball static checks" is no longer the contributing set).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const read = (f) => fs.readFileSync(fileURLToPath(new URL(`../../${f}`, import.meta.url)), 'utf8');
const words = (f) => read(f).replace(/\s+/g, ' ');

test('D1 the README names size-jump-provenance as a named rule, with both of its facts and the predecessor it compares', () => {
  const r = words('README.md');
  assert.match(r, /\*\*size-jump-provenance\*\*/);
  assert.match(r, /at least 5 times/);
  assert.match(r, /gitHead/);
  assert.match(r, /previous version of its own tag/);
  assert.match(r, /its tarball grew fivefold and its link to the repository broke/, 'the npm notice text, as proxy/notice.js has it');
});

test('D2 the README lists identity-break and entry-path-change as contributing, and S1 to S4 (not five) as the contributing static checks', () => {
  const r = words('README.md');
  assert.match(r, /\*\*identity-break\*\*/);
  assert.match(r, /\*\*entry-path-change\*\*/);
  assert.doesNotMatch(r, /the five tarball static checks/);
  assert.match(r, /tarball static checks S1 to S4/);
});

test('D3 the README describes the static_withhold switch: off by default, 8 MiB, a 403, the decision stays WARN', () => {
  const r = words('README.md');
  assert.match(r, /`static_withhold`/);
  assert.match(r, /off by default/);
  assert.match(r, /8 MiB/);
  assert.match(r, /403/);
  assert.match(r, /stays WARN/);
});

test('D4 README and SEEDS.md say --seed takes the compressed database', () => {
  assert.match(words('README.md'), /`--seed` also takes the compressed database, `chaingate-seed-v3\.db\.gz`/);
  assert.match(words('SEEDS.md'), /chaingate-seed-v3\.db\.gz/);
});

test('D5 the package is 0.1.5: package.json and both version fields of package-lock.json', () => {
  assert.equal(JSON.parse(read('package.json')).version, '0.1.5');
  const lock = JSON.parse(read('package-lock.json'));
  assert.equal(lock.version, '0.1.5');
  assert.equal(lock.packages[''].version, '0.1.5');
});
