// 0.1.4 group 4 — closeout (G4-1..G4-4): T1.1 names the hook command (B1/B18), doctor counts failed checks only (A11), the
// README names both npm approval commands (A12), review-counterexamples leaves no temp folder (A13). Expected results:
// decision tables ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G4-CLOSEOUT-20261012.md, written before this file.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import installIntroduced from '../../gates/install-introduced.js';
import { failedCount } from '../../cli/commands/doctor.js';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const at = (h) => new Date(Date.parse('2026-01-01T00:00:00Z') + h * 3_600_000).toISOString();
const run = (scripts) => installIntroduced.evaluate({ version: '1.1.0', rawVersions: { '1.0.0': {}, '1.1.0': { scripts } },
  rawTimes: { '1.0.0': at(0), '1.1.0': at(48) } });

test('G4-1 (D-C1) the T1.1 detail names each hook and its command, sanitised and capped', () => {
  assert.match(run({ postinstall: 'node lib/setup.mjs' }).detail, /^postinstall \(node lib\/setup\.mjs\) present; no earlier version \(settled 24 h: 1 version\) had an install hook$/);
  assert.match(run({ preinstall: ['a', 'b'] }).detail, /^preinstall \(\[list\]\) present/);
  const long = run({ install: `node ${'x'.repeat(300)}` }).detail;
  assert.ok(long.includes(`install (node ${'x'.repeat(75)}…)`), long);
  const evil = run({ postinstall: 'node a.js\u001b[2J‮\r\nfake' }).detail;
  assert.ok(!/[\u0000-\u001f\u007f-\u009f‮]/.test(evil), JSON.stringify(evil));
  assert.ok(evil.includes('postinstall (node a.jsfake)'), evil);
});

test('G4-2 (D-C2) doctor counts failed checks only; skipped checks are never failures', () => {
  const checks = [{ pass: false }, { pass: false, severity: 'unverifiable' },
    { pass: false, severity: 'skipped' }, { pass: true, severity: 'skipped' }, { pass: false, severity: 'skipped' }];
  assert.equal(failedCount(checks), 2);
});

test('G4-3 (D-C3) the README names both npm approval commands with the version they were checked on', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  assert.ok(readme.includes('npm approve-scripts better-sqlite3'));
  assert.ok(readme.includes('npm install-scripts approve better-sqlite3'));
  assert.match(readme, /npm 11\.19\.0/);
});

test('G4-4 (D-C4) review-counterexamples leaves no cft04-cx- folder behind', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g4-'));
  try {
    const r = spawnSync(process.execPath, ['--test', path.join(ROOT, 'test/seed-v3/review-counterexamples.test.js')],
      { env: { ...process.env, TMPDIR: tmp }, encoding: 'utf8', timeout: 120_000 });
    assert.match(r.stdout, /# pass [1-9]/, r.stdout + r.stderr);
    assert.deepEqual(fs.readdirSync(tmp).filter((n) => n.startsWith('cft04-cx-')), []);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});
