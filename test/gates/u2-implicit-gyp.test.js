// Since 0.1.8: the install-manifest-mismatch check reads the tarball as npm installs it. npm runs `node-gyp rebuild` as the install
// step of a package whose folder holds a binding.gyp file when its package.json declares no install or preinstall script and does
// not set gypfile to false (@npmcli/arborist rebuild, @npmcli/run-script, @npmcli/node-gyp isNodeGypPackage). The registry entry
// of such a package carries that install step (npm adds it at publish), so 0.1.7 warned on every one (recon's s3 lead
// @theia/ffmpeg 1.77.0-next.95). Any other difference still warns. Tarballs are crafted header by header; nothing is installed or
// run. Written before the code.
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
  let sum = 0;
  for (let i = 0; i < 512; i += 1) sum += h[i];
  h.write(`${(sum & 0o777777).toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
  return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]);
const entry = (name, content, type = '0') => [hdr(name, Buffer.byteLength(content), type), pad(Buffer.from(content))];
const EOF = Buffer.alloc(1024, 0);
async function walk(parts) {
  const w = createTarWalker();
  const gz = zlib.gzipSync(Buffer.concat(parts.flat()));
  for (let i = 0; i < gz.length; i += 333) w.write(gz.subarray(i, i + 333));
  return w.end();
}
const GYP = '{ "targets": [ { "target_name": "addon", "sources": [ "addon.cc" ] } ] }';
const pj = (o) => entry('package/package.json', JSON.stringify({ name: 'p', version: '1.0.0', ...o }));
const row = async (parts, mh) => { const r = await walk([...parts, EOF]); assert.equal(r.ok, true, r.reason); return mcRow(r, mh); };
const REBUILD = { install: 'node-gyp rebuild' };

test('U2-1 a root binding.gyp with no install or preinstall declared matches a registry entry that carries install node-gyp rebuild', async () => {
  const r = await row([pj({}), entry('package/binding.gyp', GYP)], REBUILD);
  assert.equal(r.result, 'ALLOW', r.detail);
  // the binding.gyp may come before the package.json in the archive
  assert.equal((await row([entry('package/binding.gyp', GYP), pj({})], REBUILD)).result, 'ALLOW');
});

test('U2-2 with a declared postinstall (node-sword-interface): install node-gyp rebuild plus the same postinstall matches', async () => {
  const r = await row([pj({ scripts: { postinstall: 'node post.js' } }), entry('package/binding.gyp', GYP)], { ...REBUILD, postinstall: 'node post.js' });
  assert.equal(r.result, 'ALLOW', r.detail);
});

test('U2-3 without a root binding.gyp the registry install step still warns, as in 0.1.7 (one in a sub-folder does not count)', async () => {
  assert.equal((await row([pj({})], REBUILD)).result, 'WARN');
  assert.equal((await row([pj({}), entry('package/src/binding.gyp', GYP)], REBUILD)).result, 'WARN');
  assert.equal((await row([pj({}), entry('package/other.gyp', GYP)], REBUILD)).result, 'WARN');
  assert.equal((await row([pj({}), entry('package/binding.gyp/', '', '5')], REBUILD)).result, 'WARN', 'a directory is not a file');
});

test('U2-4 npm adds no install step when the package.json declares preinstall or install, or sets gypfile to false', async () => {
  const gyp = entry('package/binding.gyp', GYP);
  assert.equal((await row([pj({ scripts: { preinstall: 'node pre.js' } }), gyp], { ...REBUILD, preinstall: 'node pre.js' })).result, 'WARN');
  assert.equal((await row([pj({ gypfile: false }), gyp], REBUILD)).result, 'WARN');
  // a declared install of its own is compared as it is
  assert.equal((await row([pj({ scripts: { install: 'node i.js' } }), gyp], { install: 'node i.js' })).result, 'ALLOW');
});

test('U2-5 a registry install step other than node-gyp rebuild still warns with a root binding.gyp', async () => {
  const r = await row([pj({}), entry('package/binding.gyp', GYP)], { install: 'node evil.js' });
  assert.equal(r.result, 'WARN');
  assert.match(r.detail, /different commands/);
});

test('U2-6 the implicit step only clears a mismatch; no hook on either side stays a match, as in 0.1.7', async () => {
  // a registry entry without the step while the tarball has a root binding.gyp: 0.1.7 matched it and 0.1.8 still does (a new
  // warning here would be a new detection, unmeasured; not this change)
  const r = await row([pj({}), entry('package/binding.gyp', GYP)], {});
  assert.equal(r.result, 'ALLOW', r.detail);
});
