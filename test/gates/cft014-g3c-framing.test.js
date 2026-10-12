// 0.1.4 group 3, unit 3c — review fixes to the tar walk's framing (G3 dated note 5; G3c-7..G3c-13). Tarballs are crafted here
// header by header so that each rule DECIDES the outcome (the root package.json is reachable only through it). Expected
// results: decision tables ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G3-TIER1-20261012.md, dated note 5.
import test from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { createTarWalker } from '../../proxy/tar-walk.js';
import { mcRow, hookDict } from '../../proxy/manifest-check.js';

/** One 512-byte header. `sizeField` overrides the octal size text; `signed` writes the signed checksum. */
function hdr(name, size, type = '0', { prefix = '', sizeField = null, signed = false, linkname = '' } = {}) {
  const h = Buffer.alloc(512, 0);
  Buffer.from(name, 'utf8').copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  if (Buffer.isBuffer(sizeField)) sizeField.copy(h, 124); else h.write(sizeField ?? `${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  h.write('00000000000\0', 136); h.write('        ', 148); h.write(type, 156, 'latin1');
  Buffer.from(linkname, 'utf8').copy(h, 157, 0, 100);
  h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1');
  Buffer.from(prefix, 'utf8').copy(h, 345, 0, 155);
  let sum = 0;
  for (let i = 0; i < 512; i += 1) sum += signed ? (h[i] > 127 ? h[i] - 256 : h[i]) : h[i];
  h.write(`${(sum >>> 0 & 0o777777).toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
  return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]);
const entry = (name, content, type = '0', opts = {}) => [hdr(name, Buffer.byteLength(content), type, opts), pad(Buffer.from(content))];
/** pax records with byte-exact lengths */
function paxBody(records) {
  return Buffer.concat(records.map(([k, v]) => {
    const tail = Buffer.from(` ${k}=${v}\n`, 'utf8');
    let n = tail.length + 1;
    while (String(n).length + tail.length !== n) n += 1;
    return Buffer.concat([Buffer.from(String(n)), tail]);
  }));
}
const paxEntry = (records, type = 'x') => { const b = paxBody(records); return [hdr('PaxHeader', b.length, type), pad(b)]; };
const EOF = Buffer.alloc(1024, 0);
const HOOKED = '{"name":"p","scripts":{"postinstall":"node evil.js"}}';
const BENIGN = '{"name":"p"}';
async function walk(parts) {
  const w = createTarWalker();
  const gz = zlib.gzipSync(Buffer.concat(parts.flat()));
  for (let i = 0; i < gz.length; i += 333) w.write(gz.subarray(i, i + 333));
  return w.end();
}
const pj = (r) => (r.ok && r.packageJson ? JSON.parse(r.packageJson.toString('utf8').replace(/^﻿/, '')) : null);

test('G3c-7 (note 5.1) a pax size= override frames the archive (no decoy inside another entry\'s data)', async () => {
  // a.bin's ustar size is 0 but pax says 1536: its data holds a fake header that would swallow the real package.json
  const decoyHeader = hdr('package/b.bin', 2048);
  const aData = Buffer.concat([decoyHeader, Buffer.alloc(1024, 0x41)]);           // 1536 bytes
  const r = await walk([paxEntry([['size', '1536']]), hdr('package/a.bin', 0), aData, entry('package/package.json', HOOKED), EOF]);
  assert.equal(r.ok, true, r.reason);
  assert.deepEqual(pj(r)?.scripts, { postinstall: 'node evil.js' });
});

test('G3c-8 (note 5.1) pax records are parsed as bytes: a non-ASCII record before path, and a non-ASCII root', async () => {
  const r = await walk([paxEntry([['comment', 'josé ünïcödé'], ['path', 'package/package.json']]), entry('package/readme.md', HOOKED), EOF]);
  assert.deepEqual(pj(r)?.scripts, { postinstall: 'node evil.js' }, r.reason);
  const r2 = await walk([paxEntry([['path', 'é/package.json']]), entry('package/readme.md', HOOKED), EOF]);
  assert.deepEqual(pj(r2)?.scripts, { postinstall: 'node evil.js' }, r2.reason);
});

test('G3c-9 (note 5.1) Solaris X is pax; GNU K does not use up an L name; a global g path applies onward', async () => {
  const x = await walk([paxEntry([['path', 'package/package.json']], 'X'), entry('package/readme.md', HOOKED), EOF]);
  assert.deepEqual(pj(x)?.scripts, { postinstall: 'node evil.js' }, x.reason);
  const lname = Buffer.from('package/package.json\0');
  const k = await walk([[hdr('././@LongLink', lname.length, 'L'), pad(lname)], [hdr('././@LongLink', 8, 'K'), pad(Buffer.from('target\0\0'))],
    entry('package/x', HOOKED), EOF]);
  assert.deepEqual(pj(k)?.scripts, { postinstall: 'node evil.js' }, k.reason);
  const g = await walk([paxEntry([['path', 'package/package.json']], 'g'), entry('package/a', BENIGN), entry('package/b', HOOKED), EOF]);
  assert.deepEqual(pj(g)?.scripts, { postinstall: 'node evil.js' }, 'every following entry takes the global path; the last wins');
});

test('G3c-10 (note 5.1) a negative or invalid size is not checked, at once (no endless loop)', async () => {
  const t = Date.now();
  const neg = await walk([[hdr('package/a', 0, '0', { sizeField: '-0000001\0' })], entry('package/package.json', BENIGN), EOF]);
  assert.equal(neg.ok, false);
  assert.match(neg.reason, /invalid size/);
  const b256 = Buffer.alloc(12, 0xff);                                         // base-256 with the sign bit: negative
  const neg2 = await walk([[hdr('package/a', 0, '0', { sizeField: b256 })], EOF]);
  assert.equal(neg2.ok, false);
  assert.match(neg2.reason, /invalid size/);
  assert.ok(Date.now() - t < 2000);
});

test('G3c-11 (note 5.1) ustar prefix decides the name; two root package.json entries: the last wins; signed checksums are read', async () => {
  const pre = await walk([entry('package.json', HOOKED, '0', { prefix: 'package' }), EOF]);
  assert.deepEqual(pj(pre)?.scripts, { postinstall: 'node evil.js' }, pre.reason);
  const two = await walk([entry('package/package.json', HOOKED), entry('package/package.json', BENIGN), EOF]);
  assert.deepEqual(pj(two), { name: 'p' });
  const signed = await walk([entry('package/ünï.js', '1', '0', { signed: true }), entry('package/package.json', HOOKED), EOF]);
  assert.equal(signed.ok, true, signed.reason);
});

test('G3c-12 (note 5.1, 5.3) end of archive: npm\'s two zero blocks; trailing bytes after them are harmless', async () => {
  const single = await walk([entry('package/package.json', BENIGN), Buffer.alloc(512, 0), entry('package/package.json', HOOKED), EOF]);
  assert.deepEqual(pj(single)?.scripts, { postinstall: 'node evil.js' }, 'npm reads past one zero block, so the walk does too');
  const trailing = await walk([entry('package/package.json', HOOKED), EOF, Buffer.alloc(4096, 0x5a)]);
  assert.equal(trailing.ok, true, trailing.reason);
});

test('G3c-13 (note 5.2, 5.3) a BOM is stripped before parsing; a too-deep hook value is not checked (never a throw)', () => {
  const bom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(HOOKED)]);
  assert.equal(mcRow({ ok: true, packageJson: bom }, {}).result, 'WARN');
  let deep = 'x'; for (let i = 0; i < 200; i += 1) deep = [deep];
  const r = mcRow({ ok: true, packageJson: Buffer.from(JSON.stringify({ scripts: { postinstall: deep } })) }, {});
  assert.equal(r.result, 'SKIP');
  assert.match(r.detail, /not checked: a hook value nested too deeply/);
  assert.deepEqual(hookDict({ scripts: { install: 'a' } }), { install: 'a' });
});
