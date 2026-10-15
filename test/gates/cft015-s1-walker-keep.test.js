// 0.1.5 tarball static checks, step 1 (design note §9): the KEEP LIST in the walker. `createTarWalker({ keep })` keeps the bodies of
// at most 6 named files (1 MiB each) while the archive streams, on the Linux view, the same way it keeps the root package.json; every
// other byte is still skipped. `keep` is either a list of package-relative paths decided before the first byte (the registry manifest's
// main, bin and hook targets) or a function of the parsed root package.json (applied when that entry completes; earlier entries are
// stated as not kept). Without `keep` the walk result is today's, key for key. Written failing-first against the 0.1.4 walker.
import test from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { createTarWalker, DEFAULTS } from '../../proxy/tar-walk.js';
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
const entry = (name, content, type = '0') => [hdr(name, Buffer.byteLength(content), type), pad(Buffer.isBuffer(content) ? content : Buffer.from(content))];
const EOF = Buffer.alloc(1024, 0);
const PJ = '{"name":"p","version":"1.0.0","main":"lib/index.js","scripts":{"postinstall":"node install.js"}}';
async function walk(parts, opts) {
  const w = createTarWalker(opts);
  const gz = zlib.gzipSync(Buffer.concat(parts.flat()));
  for (let i = 0; i < gz.length; i += 333) w.write(gz.subarray(i, i + 333));
  return w.end();
}
const paths = (r) => r.files.map((f) => f.path);
const text = (r, p) => r.files.find((f) => f.path === p)?.buf.toString('utf8');

test('K1 without keep the walk result is today\'s, key for key, and MC reads it as before', async () => {
  const r = await walk([entry('package/package.json', PJ), entry('package/install.js', 'x'), EOF]);
  assert.equal(r.ok, true, r.reason);
  assert.deepEqual(Object.keys(r), ['ok', 'packageJson', 'views', 'approx']);
  assert.equal(mcRow(r, {}).result, 'WARN');
  assert.equal(DEFAULTS.maxKeep, 6); assert.equal(DEFAULTS.maxKeepBytes, 1024 * 1024);
});

test('K2 a keep LIST (decided before the first byte) keeps the named bodies whatever the archive order; a target absent from the archive is stated', async () => {
  const r = await walk([entry('package/install.js', 'require("https")'), entry('package/package.json', PJ), entry('package/lib/index.js', 'module.exports = 1'),
    entry('package/README.md', 'docs'), EOF], { keep: ['install.js', 'lib/index.js', 'bin/cli.js'] });
  assert.equal(r.ok, true, r.reason);
  assert.deepEqual(paths(r).sort(), ['install.js', 'lib/index.js']);
  assert.equal(text(r, 'install.js'), 'require("https")'); assert.equal(text(r, 'lib/index.js'), 'module.exports = 1');
  assert.deepEqual(r.files.map((f) => f.name).sort(), ['package/install.js', 'package/lib/index.js']);
  assert.deepEqual(r.notKept, [{ path: 'bin/cli.js', reason: 'not in the archive' }]);
  // the package.json views are exactly today's
  assert.equal(r.packageJson.toString('utf8'), PJ); assert.equal(mcRow(r, {}).result, 'WARN');
  for (const f of r.files) assert.deepEqual(f.platformsNotChecked, []);
});

test('K3 a keep FUNCTION of the parsed root package.json: applied when that entry completes; an entry that preceded it is stated, not kept', async () => {
  let seen = null;
  const keep = (pj) => { seen = pj; return pj ? [pj.main, 'install.js'] : []; };
  const r = await walk([entry('package/install.js', 'early'), entry('package/package.json', PJ), entry('package/lib/index.js', 'late'), EOF], { keep });
  assert.equal(r.ok, true, r.reason);
  assert.equal(seen?.scripts?.postinstall, 'node install.js', 'the function sees the parsed Linux-view package.json');
  assert.deepEqual(paths(r), ['lib/index.js']); assert.equal(text(r, 'lib/index.js'), 'late');
  assert.deepEqual(r.notKept, [{ path: 'install.js', reason: 'preceded package.json' }]);
  // an unparseable package.json: the function is given null and decides; nothing kept, nothing thrown
  const r2 = await walk([entry('package/package.json', '{nope'), entry('package/a.js', 'x'), EOF], { keep: (pj) => (pj ? ['a.js'] : []) });
  assert.equal(r2.ok, true); assert.deepEqual(r2.files, []); assert.deepEqual(r2.notKept, []);
  // a function that throws never breaks the walk: MC still has its views, the keep list is stated as not computed
  const r3 = await walk([entry('package/package.json', PJ), entry('package/a.js', 'x'), EOF], { keep: () => { throw new Error('boom'); } });
  assert.equal(r3.ok, true); assert.equal(mcRow(r3, {}).result, 'WARN'); assert.deepEqual(r3.files, []);
  assert.deepEqual(r3.notKept, [{ path: null, reason: 'keep list not computed: boom' }]);
});

test('K4 caps: at most 6 kept files and 1 MiB per body; what is over a cap is stated and the walk goes on', async () => {
  const names = ['a', 'b', 'c', 'd', 'e', 'f', 'g'].map((x) => `${x}.js`);
  const r = await walk([entry('package/package.json', PJ), ...names.map((n) => entry(`package/${n}`, n)), EOF], { keep: names });
  assert.equal(r.ok, true, r.reason);
  assert.deepEqual(paths(r), names.slice(0, 6));
  assert.deepEqual(r.notKept, [{ path: 'g.js', reason: 'beyond 6 kept files' }]);
  const big = Buffer.alloc(1024 * 1024 + 1, 0x61);
  const r2 = await walk([entry('package/package.json', PJ), entry('package/big.js', big), entry('package/small.js', 'ok'), EOF], { keep: ['big.js', 'small.js'], maxKeepBytes: 1024 * 1024 });
  assert.equal(r2.ok, true, r2.reason);
  assert.deepEqual(paths(r2), ['small.js']);
  assert.deepEqual(r2.notKept, [{ path: 'big.js', reason: 'over the kept-file cap (1048576 bytes)', size: 1024 * 1024 + 1 }]);   // declared, static-checks-1.1: the header size (cft015-s7 W1)
  // a smaller cap is an option, as every other cap
  const r3 = await walk([entry('package/package.json', PJ), entry('package/a.js', 'twelve bytes'), EOF], { keep: ['a.js'], maxKeepBytes: 4 });
  assert.deepEqual(r3.notKept, [{ path: 'a.js', reason: 'over the kept-file cap (4 bytes)', size: 12 }]);
});

test('K5 platform views, as for package.json: the Linux view decides the kept entry; where macOS or Windows would install another entry at that path, it is stated', async () => {
  // a case alias: on Linux `index.js` is the exact entry; on macOS and Windows `Index.js` lands on the same file
  const r = await walk([entry('package/package.json', PJ), entry('package/index.js', 'exact'), entry('package/Index.js', 'alias'), EOF], { keep: ['index.js'] });
  assert.equal(r.ok, true, r.reason);
  assert.equal(text(r, 'index.js'), 'exact'); assert.deepEqual(r.files[0].platformsNotChecked, ['macOS', 'Windows']);
  // a backslash separator is a separator on Windows only
  const r2 = await walk([entry('package/package.json', PJ), entry('package/lib/a.js', 'exact'), entry('package/lib\\a.js', 'alias'), EOF], { keep: ['lib/a.js'] });
  assert.equal(text(r2, 'lib/a.js'), 'exact'); assert.deepEqual(r2.files[0].platformsNotChecked, ['Windows']);
  // the alias alone, no exact entry: on Linux the path is absent (stated), on the other platforms it exists -- never read as the file
  const r3 = await walk([entry('package/package.json', PJ), entry('package/Index.js', 'alias'), EOF], { keep: ['index.js'] });
  assert.deepEqual(r3.files, []); assert.deepEqual(r3.notKept, [{ path: 'index.js', reason: 'not in the archive (an entry installs there on macOS, Windows)' }]);
  // two exact entries: the last one wins, as node-tar overwrites
  const r4 = await walk([entry('package/package.json', PJ), entry('package/index.js', 'first'), entry('package/index.js', 'second'), EOF], { keep: ['index.js'] });
  assert.equal(text(r4, 'index.js'), 'second'); assert.equal(r4.files.length, 1);
});

test('K6 path rules: `./` is normalised, a path outside the package is refused, aliases through node-tar\'s root stripping are the same file, links are not files', async () => {
  const r = await walk([entry('package/package.json', PJ), entry('package/./lib/index.js', 'via dot'), EOF], { keep: ['./lib/index.js'] });
  assert.equal(r.ok, true, r.reason); assert.deepEqual(paths(r), ['lib/index.js']); assert.equal(text(r, 'lib/index.js'), 'via dot');
  const r2 = await walk([entry('package/package.json', PJ), entry('package/a.js', 'x'), EOF], { keep: ['../a.js', '/a.js', '', 'a.js'] });
  assert.deepEqual(paths(r2), ['a.js']);
  assert.deepEqual(r2.notKept, [{ path: '../a.js', reason: 'outside the package' }, { path: '/a.js', reason: 'outside the package' }, { path: '', reason: 'outside the package' }]);
  // a hard or symbolic link named like a target is filtered by pacote: not a file, not kept
  for (const type of ['1', '2']) {
    const r3 = await walk([entry('package/package.json', PJ), entry('package/a.js', '', type), EOF], { keep: ['a.js'] });
    assert.deepEqual(r3.files, [], `type ${type}`); assert.deepEqual(r3.notKept, [{ path: 'a.js', reason: 'not in the archive' }]);
  }
  // a kept body is never the root package.json itself (MC owns that entry)
  const r4 = await walk([entry('package/package.json', PJ), EOF], { keep: ['package.json'] });
  assert.deepEqual(r4.files, []); assert.deepEqual(r4.notKept, [{ path: 'package.json', reason: 'the root package.json is read by the manifest check, not kept' }]);
});

test('K7 the walk\'s failure modes are unchanged with a keep list: a gunzip error or a cap is "not checked" for everything', async () => {
  const w = createTarWalker({ keep: ['a.js'] }); w.write(Buffer.from('not gzip at all'));
  const r = await w.end(); assert.equal(r.ok, false); assert.match(r.reason, /gunzip/);
  const r2 = await walk([entry('package/package.json', PJ), entry('package/a.js', 'x'), EOF], { keep: ['a.js'], maxUncompressed: 600 });
  assert.equal(r2.ok, false); assert.match(r2.reason, /uncompressed cap/);
});
