// 0.1.5 follow-up #8 (operator ruling 2026-10-14: IN): every flag a command parses appears in its `--help`. `update-seed --help`
// listed only --force and --scope while the command also takes --seed <path>, --rollback and --unsigned-development (the seed
// release notes tell users to run `update-seed --seed <folder>/chaingate-seed-v3.db`). The per-command help lives in one exported
// table so this test reads exactly what `chaingate <cmd> --help` prints.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const COMMANDS = path.join(ROOT, 'cli', 'commands');

test('H1 update-seed --help names --seed <path>, --rollback and --unsigned-development beside --force and --scope', async () => {
  const { COMMAND_HELP } = await import('../../cli/help.js');
  const h = COMMAND_HELP['update-seed'];
  for (const f of ['--force', '--scope', '--seed <path>', '--rollback', '--unsigned-development']) assert.ok(h.includes(f), `${f} in: ${h}`);
});

test('H2 every flag a command source parses appears in that command\'s --help', async () => {
  const { COMMAND_HELP } = await import('../../cli/help.js');
  const files = fs.readdirSync(COMMANDS).filter((f) => f.endsWith('.js'));
  assert.ok(files.length >= 10, 'the command sources were found');
  const missing = [];
  for (const f of files) {
    const cmd = f.slice(0, -3);
    const src = fs.readFileSync(path.join(COMMANDS, f), 'utf8');
    const flags = [...new Set([...src.matchAll(/['"](--[a-z][a-z0-9-]*)['"]/g)].map((m) => m[1]))].filter((x) => x !== '--help');
    const help = COMMAND_HELP[cmd];
    assert.equal(typeof help, 'string', `${cmd} has a --help entry`);
    for (const flag of flags) if (!help.includes(flag)) missing.push(`${cmd} ${flag}`);
  }
  assert.deepEqual(missing, []);
});
