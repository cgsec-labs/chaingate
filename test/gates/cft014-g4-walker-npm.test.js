// 0.1.4 release audit, review of 83e6cf2 (G4 tables dated note 5, W1/W2): the MC walk reads the archive as npm's extractor
// does (pacote over node-tar 7.5.11 / 7.5.19). Each tarball below hides a hooked package.json behind a construct that a
// different framing or naming would miss, and must WARN; where npm 10's and npm 11's readers differ, the walk is "not
// checked". Tarballs are crafted header by header; nothing is installed or run.
import test from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { createTarWalker } from '../../proxy/tar-walk.js';
import { mcRow } from '../../proxy/manifest-check.js';

/** One 512-byte header. */
function hdr(name, size, type = '0', o = {}) {
  const h = Buffer.alloc(512, 0);
  (Buffer.isBuffer(name) ? name : Buffer.from(name, 'utf8')).copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(o.sizeField ?? `${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  h.write('00000000000\0', 136); h.write('        ', 148); h.write(type, 156, 'latin1');
  Buffer.from(o.linkname ?? '', 'utf8').copy(h, 157, 0, 100);
  if (o.gnuMagic) h.write('ustar  \0', 257, 'latin1');
  else { h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1'); }
  Buffer.from(o.prefix ?? '', 'utf8').copy(h, 345, 0, 155);
  let sum = 0;
  for (let i = 0; i < 512; i += 1) sum += o.signed ? (h[i] > 127 ? h[i] - 256 : h[i]) : h[i];
  h.write(`${(sum >>> 0 & 0o777777).toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
  return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]);
const entry = (name, content, type = '0', o = {}) => [hdr(name, Buffer.byteLength(content), type, o), pad(Buffer.from(content))];
function paxBody(records) {
  return Buffer.concat(records.map(([k, v]) => {
    const tail = Buffer.from(` ${k}=${v}\n`, 'utf8');
    let n = tail.length + 1;
    while (String(n).length + tail.length !== n) n += 1;
    return Buffer.concat([Buffer.from(String(n)), tail]);
  }));
}
const meta = (type, body) => [hdr('././@LongLink', body.length, type), pad(body)];
const pax = (records, type = 'x') => meta(type, paxBody(records));
const EOF = Buffer.alloc(1024, 0);
const HOOKED = '{"name":"p","scripts":{"postinstall":"node evil.js"}}';
const BENIGN = '{"name":"p"}';
async function walk(parts) {
  const w = createTarWalker();
  const gz = zlib.gzipSync(Buffer.concat(parts.flat()));
  for (let i = 0; i < gz.length; i += 333) w.write(gz.subarray(i, i + 333));
  return w.end();
}
const mc = async (parts) => { const r = await walk(parts); return { r, row: mcRow(r, {}) }; };
/** A body of `bytes` bytes holding a hidden, hooked root package.json entry. */
const hidden = () => Buffer.concat(entry('package/package.json', HOOKED).flat());

test('G4-15 (W1, review #1) entries npm never writes as package.json do not replace the real one', async () => {
  // a `0` entry ending in `/` is a directory to node-tar (size 0; its "body" is read as headers)
  let { r, row } = await mc([entry('package/package.json', HOOKED), entry('package/package.json/', BENIGN), EOF]);
  assert.equal(row.result, 'WARN', `${r.reason ?? ''} ${row.detail}`);
  // a path of more than 1,024 parts is refused by node-tar
  for (const deep of [`package/${'./'.repeat(1025)}package.json`, `package${'/'.repeat(1026)}package.json`]) {
    ({ r, row } = await mc([entry('package/package.json', HOOKED), pax([['path', deep]]), entry('package/z', BENIGN), EOF]));
    assert.equal(row.result, 'WARN', `${deep.length}: ${r.reason ?? ''} ${row.detail}`);
  }
});

test('G4-16 (W1, review #6) an approximate 8.3 name after a Windows alias does not hide it', async () => {
  const { row } = await mc([entry('package/package.json', BENIGN), entry('package\\package.json', HOOKED), entry('package/PACKAG~7.JSO', BENIGN), EOF]);
  assert.equal(row.result, 'WARN', row.detail);
  assert.match(row.detail, /installed on Windows \(entry package\\package\.json\)/);
});

test('G4-17 (W1, review #7) an unreadable Linux package.json does not hide a mismatching macOS/Windows one', async () => {
  const { row } = await mc([entry('package/package.json', '{'), entry('package/PACKAGE.JSON', HOOKED), EOF]);
  assert.equal(row.result, 'WARN', row.detail);
  assert.match(row.detail, /as installed on macOS and Windows/);
});

test('G4-18 (W2, review #2) names as node-tar computes them: L/N, g, merged x, x vs L, malformed pax lines, GNU magic', async () => {
  const cases = {
    // L: node-tar cuts at the NUL only to the end of the line: "package\n/package.json" -> strip 1 -> package.json
    L_nul_newline: [entry('package/package.json', BENIGN), meta('L', Buffer.from('package\0\n/package.json')), entry('package/x', HOOKED)],
    // g never sets a path: the later benign entry is package/z, not package/package.json
    g_path: [entry('package/package.json', HOOKED), pax([['path', 'package/package.json']], 'g'), entry('package/z', BENIGN)],
    // two x headers merge: the path survives the second
    x_merge: [entry('package/package.json', BENIGN), pax([['path', 'package/package.json']]), pax([['mtime', '1']]), entry('package/z', HOOKED)],
    // x path, then L name: the last one wins
    x_then_L: [entry('package/package.json', BENIGN), pax([['path', 'package/z']]), meta('L', Buffer.from('package/package.json\0')), entry('package/q', HOOKED)],
    // N (old GNU long path) is an L
    N: [entry('package/package.json', BENIGN), meta('N', Buffer.from('package/package.json\0')), entry('package/q', HOOKED)],
    // a malformed pax line is skipped and the next one applies
    pax_bad_line: [entry('package/package.json', BENIGN),
      meta('x', Buffer.concat([Buffer.from('5 a=b\n'), paxBody([['path', 'package/package.json']])])), entry('package/q', HOOKED)],
    // GNU magic: bytes 345.. are not a prefix
    gnu_magic: [entry('package/package.json', BENIGN), entry('package/package.json', HOOKED, '0', { gnuMagic: true, prefix: 'x' })],
  };
  for (const [k, parts] of Object.entries(cases)) {
    const { r, row } = await mc([...parts, EOF]);
    assert.equal(row.result, 'WARN', `${k}: ${r.reason ?? ''} ${row.detail}`);
  }
});

test('G4-19 (W2, review #3) framing as node-tar: a directory body, and headers npm skips, are read as headers', async () => {
  const body = hidden();                                                     // 1024 bytes: a hooked root entry
  const cases = {
    dir_with_size: [entry('package/package.json', BENIGN), [hdr('package/lib/', body.length, '5'), body]],
    signed_checksum: [entry('package/package.json', BENIGN), [hdr(Buffer.from('package/\xe9.bin', 'latin1'), body.length, '0', { signed: true }), body]],
    file_with_linkname: [entry('package/package.json', BENIGN), [hdr('package/a.bin', body.length, '0', { linkname: 'x' }), body]],
    link_without_linkname: [entry('package/package.json', BENIGN), [hdr('package/l', body.length, '2'), body]],
    empty_path: [entry('package/package.json', BENIGN), [hdr('', body.length, '0'), body]],
  };
  for (const [k, parts] of Object.entries(cases)) {
    const { r, row } = await mc([...parts, EOF]);
    assert.equal(row.result, 'WARN', `${k}: ${r.reason ?? ''} ${row.detail}`);
  }
});

test('G4-20 (W2) where npm 10 and npm 11 read differently, the walk is not checked (never a final result)', async () => {
  const cases = {
    pending_size_on_meta: [pax([['size', '512']]), meta('L', Buffer.from('package/package.json\0')), entry('package/q', HOOKED)],
    global_size_on_meta: [pax([['size', '512']], 'g'), meta('L', Buffer.from('package/x\0')), entry('package/q', HOOKED)],
    size_not_digits: [pax([['size', '1e3']]), entry('package/q', HOOKED)],
    path_digits: [pax([['path', '123']]), entry('package/q', HOOKED)],
    path_nul: [pax([['path', 'package/package.json\0x']]), entry('package/q', HOOKED)],
    type_key: [pax([['type', '0']]), entry('package/q', HOOKED)],
    unknown_key: [pax([['nullBlock', '1']]), entry('package/q', HOOKED)],
  };
  for (const [k, parts] of Object.entries(cases)) {
    const r = await walk([...parts, EOF]);
    assert.equal(r.ok, false, `${k}: expected not checked`);
    assert.match(r.reason, /npm 10 and npm 11 read it differently|not a pax key npm reads the same way/, k);
    assert.equal(mcRow(r, {}).result, 'SKIP', k);
  }
  // vendor keys, comment and mtime are read alike: still checked
  const ok = await walk([pax([['comment', 'x'], ['mtime', '1.5'], ['SCHILY.xattr.a', 'b']]), entry('package/package.json', HOOKED), EOF]);
  assert.equal(ok.ok, true, ok.reason);
  assert.equal(mcRow(ok, {}).result, 'WARN');
});
