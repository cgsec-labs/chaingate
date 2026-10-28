// 0.1.5 follow-up #4 (operator ruling 2026-10-14: IN): `chaingate doctor` probes the proxy at CHAINGATE_PORT when it is set, the
// variable the proxy itself reads, as `chaingate report` and `chaingate pin` already do; unset or invalid, the default port.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import doctor from '../../cli/commands/doctor.js';
import { proxyPort } from '../../cli/commands/pin.js';
import { DEFAULT_PORT } from '../../cli/constants.js';

async function doctorChecks(env) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-d4-'));
  const prevCwd = process.cwd(); const prevLog = console.log; const saved = process.env.CHAINGATE_PORT;
  const out = [];
  console.log = (line) => out.push(line);
  if (env.CHAINGATE_PORT === undefined) delete process.env.CHAINGATE_PORT; else process.env.CHAINGATE_PORT = env.CHAINGATE_PORT;
  process.chdir(root);
  try {
    await doctor(['--scope', 'project', '--json']);
  } finally {
    console.log = prevLog; process.chdir(prevCwd);
    if (saved === undefined) delete process.env.CHAINGATE_PORT; else process.env.CHAINGATE_PORT = saved;
    fs.rmSync(root, { recursive: true, force: true });
  }
  return JSON.parse(out.join('\n'));
}

test('D4-1 doctor probes CHAINGATE_PORT when it is set: a proxy listening there is found, and the detail names that port', async () => {
  const server = http.createServer((req, res) => { res.writeHead(404); res.end(); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  try {
    const checks = await doctorChecks({ CHAINGATE_PORT: String(port) });
    const c = checks.find((x) => x.name === 'proxy-port');
    assert.ok(c, 'the proxy-port check is reported');
    assert.equal(c.pass, true, c.detail);
    assert.match(c.detail, new RegExp(`:${port} accepting connections`));
  } finally { await new Promise((r) => server.close(r)); }
});

test('D4-2 unset or invalid CHAINGATE_PORT: doctor names the default port, as report and pin do', async () => {
  for (const v of [undefined, 'not-a-port', '0', '70000']) {
    const checks = await doctorChecks({ CHAINGATE_PORT: v });
    const c = checks.find((x) => x.name === 'proxy-port');
    assert.match(c.detail, new RegExp(`:${DEFAULT_PORT} `), `CHAINGATE_PORT=${v}`);
    assert.equal(proxyPort(v === undefined ? {} : { CHAINGATE_PORT: v }), DEFAULT_PORT);
  }
});
