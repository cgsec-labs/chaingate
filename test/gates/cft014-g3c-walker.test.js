// 0.1.4 group 3, unit 3c — the constant-memory tar walk (D-M2) and MC parity with validate.py tar_checks (D-M1).
// Expected results: decision tables ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G3-TIER1-20261012.md §4, written before this
// file. Tarballs are built here with tar(1) from synthetic files; nothing is extracted to disk or run.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { createTarWalker } from '../../proxy/tar-walk.js';
import { manifestMismatch, hookDict } from '../../proxy/manifest-check.js';

function tgz(files, { format = 'gnu', order = null } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g3c-'));
  try {
    for (const [p, content] of Object.entries(files)) {
      fs.mkdirSync(path.join(dir, path.dirname(p)), { recursive: true });
      fs.writeFileSync(path.join(dir, p), content);
    }
    const out = path.join(dir, 'out.tgz');
    execFileSync('tar', ['-czf', out, `--format=${format}`, '-C', dir, ...(order ?? Object.keys(files))]);
    return fs.readFileSync(out);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
async function walk(buf, opts = {}, chunk = 777) {
  const w = createTarWalker(opts);
  for (let i = 0; i < buf.length; i += chunk) w.write(buf.subarray(i, i + chunk));
  return w.end();
}
const LONG = `package/${'d'.repeat(120)}/${'f'.repeat(60)}.js`;

test('G3c-1a (D-M2) the root package.json is found after long-named entries, in gnu, ustar and pax formats', async () => {
  for (const format of ['gnu', 'ustar', 'pax']) {
    const files = { [format === 'ustar' ? `package/${'d'.repeat(90)}/${'f'.repeat(60)}.js` : LONG]: 'x', 'package/package.json': '{"name":"p","scripts":{"postinstall":"node s.js"}}' };
    const r = await walk(tgz(files, { format }));
    assert.equal(r.ok, true, `${format}: ${r.reason}`);
    assert.deepEqual(JSON.parse(r.packageJson.toString('utf8')).scripts, { postinstall: 'node s.js' }, format);
  }
});

test('G3c-1b (D-M2) a package.json below the root is not the root one; the last root package.json wins (as read_tar keeps the last)', async () => {
  const r = await walk(tgz({ 'package/lib/package.json': '{"scripts":{"install":"evil"}}', 'package/package.json': '{"name":"p"}' }));
  assert.deepEqual(JSON.parse(r.packageJson), { name: 'p' });
  const none = await walk(tgz({ 'package/index.js': '1' }));
  assert.equal(none.ok, true);
  assert.equal(none.packageJson, null);
});

test('G3c-1c (D-M2) caps and errors are "not checked" with the reason; content bytes are skipped, never buffered', async () => {
  const big = Buffer.alloc(3 * 1024 * 1024, 0);
  const r = await walk(tgz({ 'package/big.bin': big, 'package/package.json': '{}' }), { maxUncompressed: 1024 * 1024 });
  assert.equal(r.ok, false);
  assert.match(r.reason, /uncompressed cap/);
  const c = await walk(tgz({ 'package/package.json': '{}' }), { maxCompressed: 10 });
  assert.match(c.reason, /compressed cap/);
  const bad = await walk(Buffer.from('this is not gzip at all, only bytes'.repeat(20)));
  assert.equal(bad.ok, false);
  assert.match(bad.reason, /gunzip|tar/);
  const hugePj = await walk(tgz({ 'package/package.json': `{"x":"${'a'.repeat(2 * 1024 * 1024)}"}` }));
  assert.equal(hugePj.ok, false);
  assert.match(hugePj.reason, /package\.json over/);
});

/** A minimal ustar header (for the constant-memory check, the content is streamed separately). */
function tarHeader(name, size) {
  const h = Buffer.alloc(512, 0);
  h.write(name, 0, 100, 'utf8');
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(`${size.toString(8).padStart(11, '0')}\0`, 124); h.write('00000000000\0', 136);
  h.write('        ', 148); h.write('0', 156); h.write('ustar\0', 257); h.write('00', 263);
  let sum = 0; for (const b of h) sum += b;
  h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
  return h;
}

test('G3c-1d (D-M2) constant memory: a 256 MiB-entry stream is walked chunk by chunk without holding the entry', async () => {
  const w = createTarWalker({ maxUncompressed: 512 * 1024 * 1024 });
  const gz = zlib.createGzip();
  gz.on('data', (c) => w.write(c));
  const before = process.memoryUsage().rss;
  gz.write(tarHeader('package/z.bin', 256 * 1024 * 1024));
  const zero = Buffer.alloc(1024 * 1024, 0);
  for (let i = 0; i < 256; i += 1) { gz.write(zero); await new Promise((r) => setImmediate(r)); }
  gz.write(tarHeader('package/package.json', 2)); gz.write(Buffer.concat([Buffer.from('{}'), Buffer.alloc(510, 0)]));
  gz.write(Buffer.alloc(1024, 0));
  await new Promise((r) => gz.end(r));
  const r = await w.end();
  assert.equal(r.ok, true, r.reason);
  assert.deepEqual(JSON.parse(r.packageJson), {});
  assert.ok(process.memoryUsage().rss - before < 128 * 1024 * 1024, 'the entry was never buffered');
});

test('G3c-2 (D-M1) MC parity with tar_checks: dicts with values compared; a missing package.json reads as {}', () => {
  const man = (scripts) => ({ name: 'p', ...(scripts ? { scripts } : {}) });
  assert.equal(manifestMismatch(hookDict({ scripts: { postinstall: 'node s.js' } }), hookDict(man(null))), true, 'hook only in the tarball');
  assert.equal(manifestMismatch(hookDict({ scripts: { postinstall: 'node s.js' } }), hookDict(man({ postinstall: 'node s.js' }))), false);
  assert.equal(manifestMismatch(hookDict({}), hookDict(man({ install: 'x' }))), true, 'hook only in the manifest');
  assert.equal(manifestMismatch(hookDict({ scripts: { install: 'a' } }), hookDict(man({ install: 'b' }))), true, 'a different command');
  assert.equal(manifestMismatch(hookDict(null), hookDict(man({ install: 'x' }))), true, 'no package.json in the tarball');
  assert.equal(manifestMismatch(hookDict({ scripts: { install: '', test: 'x' } }), hookDict(man({ test: 'y' }))), false, 'falsy hooks and non-hooks ignored');
  assert.deepEqual(hookDict({ scripts: { postinstall: ['a'], preinstall: 0, install: {} } }), { postinstall: ['a'] });
});
