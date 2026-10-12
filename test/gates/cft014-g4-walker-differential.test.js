// 0.1.4 release audit (G4 tables dated note 5, W1/W2): the walk against the REAL reader. Every crafted tarball is extracted by
// npm's own node-tar -- 7.5.11 (npm 10.9.7) and 7.5.19 (npm 11.19.0), with pacote's options (`strip: 1`, links filtered,
// regular files only) -- and the package.json it writes must be exactly the walk's Linux view. Extraction only: nothing is
// installed or run. Skipped, with the reason, where those npm installations are not present (this checks Linux only; the
// macOS and Windows views are emulated, not observed).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { pathToFileURL } from 'node:url';
import workerThreads from 'node:worker_threads';
import { createTarWalker } from '../../proxy/tar-walk.js';

const NPMS = {
  'npm 10.9.7 (tar 7.5.11)': path.join(path.dirname(process.execPath), '..', 'lib', 'node_modules', 'npm'),
  'npm 11.19.0 (tar 7.5.19)': process.env.CFT014_NPM11_CLI ? path.resolve(path.dirname(process.env.CFT014_NPM11_CLI), '..') : null,
};
const tars = {};
for (const [label, dir] of Object.entries(NPMS)) {
  const t = dir && path.join(dir, 'node_modules', 'tar', 'dist', 'esm', 'index.js');
  if (t && fs.existsSync(t)) tars[label] = { file: t, version: JSON.parse(fs.readFileSync(path.join(dir, 'node_modules', 'tar', 'package.json'), 'utf8')).version };
}

function hdr(name, size, type = '0', o = {}) {
  const h = Buffer.alloc(512, 0);
  (Buffer.isBuffer(name) ? name : Buffer.from(name, 'utf8')).copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
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
const A = '{"name":"p","v":"A"}';
const B = '{"name":"p","v":"B"}';
const hiddenB = () => Buffer.concat(entry('package/package.json', B).flat());

const CASES = {
  literal: [entry('package/index.js', '1'), entry('package/package.json', A)],
  two_literals_last_wins: [entry('package/package.json', A), entry('package/package.json', B)],
  alias_dot: [entry('package/package.json', A), entry('package/./package.json', B)],
  alias_double_slash: [entry('package/package.json', A), entry('package//package.json', B)],
  alias_backslash_root: [entry('package/package.json', A), entry('package/\\package.json', B)],
  alias_drive: [entry('package/package.json', A), entry('package/c:package.json', B)],
  alias_drive_root: [entry('package/package.json', A), entry('package/C:/package.json', B)],
  not_root_dotdot: [entry('package/package.json', A), entry('package/x/../package.json', B)],
  not_root_sub: [entry('package/package.json', A), entry('package/sub/package.json', B)],
  not_root_top: [entry('package/package.json', A), entry('package.json', B)],
  case_alias_linux: [entry('package/package.json', A), entry('package/PACKAGE.JSON', B)],
  phantom_trailing_slash: [entry('package/package.json', A), entry('package/package.json/', B)],
  phantom_deep_dots: [entry('package/package.json', A), pax([['path', `package/${'./'.repeat(1025)}package.json`]]), entry('package/z', B)],
  phantom_deep_empty: [entry('package/package.json', A), pax([['path', `package${'/'.repeat(1026)}package.json`]]), entry('package/z', B)],
  L_nul_newline: [entry('package/package.json', A), meta('L', Buffer.from('package\0\n/package.json')), entry('package/x', B)],
  g_path_ignored: [entry('package/package.json', A), pax([['path', 'package/package.json']], 'g'), entry('package/z', B)],
  x_merge: [entry('package/package.json', A), pax([['path', 'package/package.json']]), pax([['mtime', '1']]), entry('package/z', B)],
  x_then_L: [entry('package/package.json', A), pax([['path', 'package/z']]), meta('L', Buffer.from('package/package.json\0')), entry('package/q', B)],
  L_then_x: [entry('package/package.json', A), meta('L', Buffer.from('package/package.json\0')), pax([['path', 'package/z']]), entry('package/q', B)],
  N_long_path: [entry('package/package.json', A), meta('N', Buffer.from('package/package.json\0')), entry('package/q', B)],
  K_then_L: [entry('package/package.json', A), meta('K', Buffer.from('target\0')), meta('L', Buffer.from('package/package.json\0')), entry('package/q', B)],
  X_is_pax: [entry('package/package.json', A), pax([['path', 'package/package.json']], 'X'), entry('package/q', B)],
  pax_bad_line: [entry('package/package.json', A), meta('x', Buffer.concat([Buffer.from('5 a=b\n'), paxBody([['path', 'package/package.json']])])), entry('package/q', B)],
  pax_size_frames: [pax([['size', '1536']]), hdr('package/a.bin', 0), Buffer.concat([hdr('package/b.bin', 2048), Buffer.alloc(1024, 0x41)]), entry('package/package.json', B)],
  ustar_prefix: [entry('package/package.json', A), entry('package.json', B, '0', { prefix: 'package' })],
  gnu_magic_no_prefix: [entry('package/package.json', A), entry('package/package.json', B, '0', { gnuMagic: true, prefix: 'x' })],
  dir_with_size: [entry('package/package.json', A), [hdr('package/lib/', 1024, '5'), hiddenB()]],
  signed_checksum_skipped: [entry('package/package.json', A), [hdr(Buffer.from('package/\xe9.bin', 'latin1'), 1024, '0', { signed: true }), hiddenB()]],
  file_with_linkname: [entry('package/package.json', A), [hdr('package/a.bin', 1024, '0', { linkname: 'x' }), hiddenB()]],
  link_without_linkname: [entry('package/package.json', A), [hdr('package/l', 1024, '2'), hiddenB()]],
  empty_path: [entry('package/package.json', A), [hdr('', 1024, '0'), hiddenB()]],
  after_one_zero_block: [entry('package/package.json', A), Buffer.alloc(512, 0), entry('package/package.json', B)],
  link_named_package_json: [entry('package/package.json', A), entry('package/package.json', '', '2', { linkname: 'other.json' })],
  // found by the differential fuzz (dated note 6): a pending L or pax path replaces the name, prefix included
  L_path_drops_prefix: [entry('package/package.json', A), meta('L', Buffer.from('package/package.json\0')), entry('package/x', B, '0', { prefix: 'package' })],
  pax_path_drops_prefix: [entry('package/package.json', A), pax([['path', 'package/package.json']]), entry('package/x', B, '0', { prefix: 'package/sub' })],
  prefix_without_pending_path: [entry('package/package.json', A), entry('x', B, '0', { prefix: 'package/sub' })],
  contiguous_trailing_slash_is_written: [entry('package/package.json', A), entry('package/package.json/', B, '7')],
};

async function extracted(tarFile, tgz, track = []) {
  const tar = await import(pathToFileURL(tarFile).href);
  const dest = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g4diff-'));
  const file = path.join(dest, '..', `${path.basename(dest)}.tgz`);
  track.push(dest, file);                                    // removed by the caller even when node-tar never settles
  try {
    fs.writeFileSync(file, tgz);
    await tar.x({ file, cwd: dest, strip: 1, noChmod: true, noMtime: true, onwarn: () => {},
      filter: (name, e) => { if (/Link$/.test(e.type)) return false; if (/File$/.test(e.type)) return true; return undefined; } });
    const pj = path.join(dest, 'package.json');
    return fs.existsSync(pj) && fs.statSync(pj).isFile() ? fs.readFileSync(pj, 'utf8') : null;
  } finally { fs.rmSync(dest, { recursive: true, force: true }); fs.rmSync(file, { force: true }); }
}
async function walked(tgz) {
  const w = createTarWalker();
  for (let i = 0; i < tgz.length; i += 333) w.write(tgz.subarray(i, i + 333));
  return w.end();
}

const skip = Object.keys(tars).length === 2 ? {} : { skip: `npm's node-tar not found for both npm 10.9.7 and 11.19.0 (found: ${Object.keys(tars).join(', ') || 'none'})` };
test('G4-21 (W1/W2) the walk\'s Linux view is exactly the package.json npm 10 and npm 11 extract, for every crafted tarball', skip, async () => {
  const rows = [];
  for (const [name, parts] of Object.entries(CASES)) {
    const tgz = zlib.gzipSync(Buffer.concat([...parts.flat(), EOF]));
    const w = await walked(tgz);
    assert.equal(w.ok, true, `${name}: the walk is not checked (${w.reason})`);
    const mine = w.packageJson ? w.packageJson.toString('utf8') : null;
    for (const [label, t] of Object.entries(tars)) {
      const theirs = await extracted(t.file, tgz);
      rows.push(`${name} | ${label} | npm: ${theirs ?? '(none)'} | walk: ${mine ?? '(none)'}`);
      assert.equal(mine, theirs, `${name} under ${label} (tar ${t.version}): npm wrote ${theirs}, the walk read ${mine}`);
    }
  }
  assert.ok(rows.length >= Object.keys(CASES).length * 2);
});

test('G4-22 (W2) a construct the walk calls "not checked" for npm 10 vs 11 is one the two readers really disagree on', skip, async () => {
  // a pending pax size meeting an L header: 7.5.11 applies it to the L header (and reads the next header as the name),
  // 7.5.19 does not -- npm 10 writes no package.json, npm 11 writes one (observed 2026-10-12)
  const tgz = zlib.gzipSync(Buffer.concat([...[pax([['size', '1024']]), meta('L', Buffer.from('package/package.json\0')),
    entry('package/q', B)].flat(), EOF]));
  const w = await walked(tgz);
  assert.equal(w.ok, false);
  const got = [];
  for (const t of Object.values(tars)) got.push(await extracted(t.file, tgz));
  assert.notEqual(got[0], got[1], `both readers wrote ${got[0]}`);
});

test('G4-26 (dated note 6) 300 seeded random archives: whenever the walk gives a result, it is the package.json npm 10 and npm 11 write', skip, async () => {
  const { generate } = await import('./fixtures/cft014-tar-fuzz.mjs');
  const pools = Object.values(tars).map((t) => isolated(t.file));
  const tally = { ok: 0, agree: 0, not_checked: 0, npm_error: 0 };
  try {
    for (const [n, tgz] of generate(20261012, 300).entries()) {
      const w = await walked(tgz);
      const [a, b] = [await pools[0].extract(tgz), await pools[1].extract(tgz)];
      if (!w.ok) { tally.not_checked += 1; continue; }
      tally.ok += 1;
      if (a.error && b.error) { tally.npm_error += 1; continue; }
      const theirs = (x) => x.error ?? x.pj;
      assert.equal(theirs(a), theirs(b), `archive ${n}: the walk gave a result, but npm 10 and npm 11 write different files`);
      const mine = w.packageJson ? w.packageJson.toString('utf8') : null;
      assert.equal(mine, a.pj, `archive ${n}: npm wrote ${a.pj}, the walk read ${mine}`);
      tally.agree += 1;
    }
  } finally { for (const p of pools) await p.close(); }
  assert.ok(tally.agree > 150, JSON.stringify(tally));
});

/** One node-tar in a worker thread, restarted after a crash (an error thrown from a callback: npm's install fails there). */
function isolated(tarFile) {
  const { Worker } = workerThreads;
  const workerUrl = new URL('./fixtures/cft014-tar-extract-worker.mjs', import.meta.url);
  let worker = null; let pending = null; let seq = 0;
  const start = () => {
    worker = new Worker(workerUrl, { workerData: { tarUrl: pathToFileURL(tarFile).href } });
    worker.on('message', (m) => { if (pending && m.id === pending.id) { const p = pending; pending = null; p.resolve(m); } });
    worker.on('error', (err) => { if (pending) { const p = pending; pending = null; p.resolve({ error: `CRASH ${String(err.code ?? err.message).slice(0, 50)}` }); } worker = null; });
  };
  return {
    async extract(tgz) {
      if (!worker) start();
      const dest = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g4fz-'));
      const file = `${dest}.tgz`;
      fs.writeFileSync(file, tgz);
      try {
        return await new Promise((resolve) => {
          pending = { id: (seq += 1), resolve };
          const timer = setTimeout(() => { if (pending) { pending = null; worker?.terminate(); worker = null; resolve({ error: 'TIMEOUT' }); } }, 10_000);
          worker.postMessage({ id: seq, file, dest });
          const done = pending.resolve; pending.resolve = (m) => { clearTimeout(timer); done(m); };
        });
      } finally { fs.rmSync(dest, { recursive: true, force: true }); fs.rmSync(file, { force: true }); }
    },
    async close() { if (worker) await worker.terminate(); worker = null; },
  };
}
