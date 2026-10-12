// 0.1.4 release-readiness audit, R2 (G4 tables dated note 4): MC finds the root package.json the way npm's extractor does --
// pacote (links filtered, `strip: 1`) over node-tar (a leading root stripped by win32 rules on every platform, `..` refused;
// on Windows `\` is a separator), on case-sensitive (Linux), case-insensitive (macOS) and Windows file systems. Each view's
// last entry wins; MC WARNs when any view's package.json differs from the registry entry. Tarballs are crafted header by
// header; nothing is installed or run.
import test from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { createTarWalker } from '../../proxy/tar-walk.js';
import { mcRow } from '../../proxy/manifest-check.js';

function hdr(name, size, type = '0') {
  const h = Buffer.alloc(512, 0);
  Buffer.from(name, 'utf8').copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  h.write('00000000000\0', 136); h.write('        ', 148); h.write(type, 156, 'latin1');
  h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1');
  let sum = 0; for (let i = 0; i < 512; i += 1) sum += h[i];
  h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
  return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]);
const entry = (name, content, type = '0') => [hdr(name, Buffer.byteLength(content), type), pad(Buffer.from(content))];
const EOF = Buffer.alloc(1024, 0);
const HOOKED = '{"name":"p","scripts":{"postinstall":"node evil.js"}}';
const BENIGN = '{"name":"p"}';
async function walk(parts) {
  const w = createTarWalker();
  const gz = zlib.gzipSync(Buffer.concat(parts.flat()));
  for (let i = 0; i < gz.length; i += 333) w.write(gz.subarray(i, i + 333));
  return w.end();
}

test('G4-6a (R2) a root package.json written on EVERY platform under another entry name is the one MC reads', async () => {
  // each resolves to <dir>/package.json through node-tar: `./`, an empty segment, a leading `\` root, a drive root
  for (const alias of ['package/./package.json', 'package//package.json', 'package/\\package.json', 'package/c:package.json',
    'package/C:/package.json', 'package/.//./package.json']) {
    const r = await walk([entry('package/package.json', BENIGN), entry(alias, HOOKED), EOF]);
    assert.equal(r.ok, true, `${alias}: ${r.reason}`);
    const row = mcRow(r, {});
    assert.equal(row.result, 'WARN', `${alias}: ${row.detail}`);
    assert.match(row.detail, /declares postinstall/, alias);
  }
});

test('G4-6b (R2) a case alias is installed on macOS and Windows: WARN, the detail names those platforms and the entry', async () => {
  const r = await walk([entry('package/package.json', BENIGN), entry('package/PACKAGE.JSON', HOOKED), EOF]);
  assert.equal(r.ok, true, r.reason);
  const row = mcRow(r, {});
  assert.equal(row.result, 'WARN', row.detail);
  assert.match(row.detail, /as installed on macOS and Windows \(entry package\/PACKAGE\.JSON\)/);
  assert.match(row.detail, /declares postinstall; the registry entry declares no install hook/);
  // Unicode case folding: U+017F (long s) folds to s on a case-insensitive file system
  const r2 = await walk([entry('package/package.json', BENIGN), entry('package/package.j\u017fon', HOOKED), EOF]);
  assert.equal(mcRow(r2, {}).result, 'WARN');
});

test('G4-6c (R2) Windows only: a backslash separator, the 8.3 short name, trailing dots and spaces', async () => {
  for (const alias of ['package\\package.json', 'package/PACKAG~1.JSO', 'package/package.json.', 'package/package.json ']) {
    const r = await walk([entry('package/package.json', BENIGN), entry(alias, HOOKED), EOF]);
    const row = mcRow(r, {});
    assert.equal(row.result, 'WARN', `${alias}: ${row.detail}`);
    assert.match(row.detail, /installed on Windows \(entry /, alias);                // exact or approximate (dated note 5)
  }
});

test('G4-6d (R2) entries npm does not install as the root file are not read', async () => {
  for (const name of ['package/x/../package.json', 'package/sub/package.json', 'package.json', 'package/../package.json']) {
    const r = await walk([entry('package/package.json', BENIGN), entry(name, HOOKED), EOF]);
    assert.equal(r.ok, true, `${name}: ${r.reason}`);
    assert.equal(mcRow(r, {}).result, 'ALLOW', name);
  }
  // a hard or symbolic link named package.json is filtered by pacote: the regular entry is what npm installs
  for (const type of ['1', '2']) {
    const r = await walk([entry('package/package.json', BENIGN), entry('package/package.json', '', type), EOF]);
    assert.equal(mcRow(r, {}).result, 'ALLOW', `type ${type}`);
  }
});

test('G4-6e (R2) an ordinary npm-pack tarball is unchanged: one view, the same detail text as before', async () => {
  const r = await walk([entry('package/index.js', '1'), entry('package/package.json', HOOKED), EOF]);
  assert.equal(r.packageJson.toString(), HOOKED);
  assert.deepEqual(mcRow(r, {}), { gate: 'install-manifest-mismatch', result: 'WARN',
    detail: 'tarball package.json declares postinstall; the registry entry declares no install hook' });
  assert.equal(mcRow(r, { postinstall: 'node evil.js' }).result, 'ALLOW');
  // a case alias that agrees with the registry adds nothing
  const same = await walk([entry('package/package.json', HOOKED), entry('package/Package.json', HOOKED), EOF]);
  assert.equal(mcRow(same, { postinstall: 'node evil.js' }).result, 'ALLOW');
});

test('G4-6f (R2) the entry name in the detail is sanitised and capped (the first segment is publisher text too)', async () => {
  const name = `package\u001b[31m${'A'.repeat(70)}/PACKAGE.JSON`;
  const r = await walk([entry('package/package.json', BENIGN), entry(name, HOOKED), EOF]);
  const row = mcRow(r, {});
  assert.equal(row.result, 'WARN', row.detail);
  assert.ok(!/[\u0000-\u001f\u007f]/.test(row.detail), row.detail);
  const shown = row.detail.match(/\(entry (.*)\)/)[1];
  assert.ok(shown.length <= 81 && shown.endsWith('\u2026'), shown);                // 80 characters and an ellipsis (as D-C1)
});
