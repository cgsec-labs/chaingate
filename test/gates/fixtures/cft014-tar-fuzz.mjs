// 0.1.4 release audit (G4 tables dated note 6): seeded random tar archives over the constructs where a reader can disagree
// with npm's extractor (aliased and odd names, pax x/g/X with unknown or malformed records, L/N/K, bad checksums, directories
// and links with bodies, prefixes under both magics, stray zero blocks, wrong declared sizes, headers hidden in bodies).
// Generation only; the differential test extracts them with npm's own node-tar. Copied from
// ~/artifacts/cft014-walker-fuzz-20261012/fuzz.mjs (seeds 2-7 there: 12,000 archives, 0 disagreements after note 6's fixes).
import zlib from 'node:zlib';

/** `count` gzipped archives from `seed` (deterministic). */
export function generate(seed, count) {
  let s = seed >>> 0;
  const rnd = () => { s = (s + 0x6D2B79F5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const pick = (a) => a[Math.floor(rnd() * a.length)];
  const chance = (p) => rnd() < p;

  function hdr(name, size, type, o = {}) {
    const h = Buffer.alloc(512, 0);
    (Buffer.isBuffer(name) ? name : Buffer.from(name, 'utf8')).copy(h, 0, 0, 100);
    h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
    if (o.sizeRaw) o.sizeRaw.copy(h, 124); else h.write(`${Math.max(0, size).toString(8).padStart(11, '0')}\0`, 124, 'latin1');
    h.write('00000000000\0', 136); h.write('        ', 148); h.write(type, 156, 'latin1');
    Buffer.from(o.linkname ?? '', 'utf8').copy(h, 157, 0, 100);
    if (o.magic === 'gnu') h.write('ustar  \0', 257, 'latin1');
    else if (o.magic === 'none') { /* v7 */ } else { h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1'); }
    Buffer.from(o.prefix ?? '', 'utf8').copy(h, 345, 0, 155);
    if (o.b475) h[475] = 0x41;
    let sum = 0;
    for (let i = 0; i < 512; i += 1) sum += o.signed ? (h[i] > 127 ? h[i] - 256 : h[i]) : h[i];
    if (o.badSum) sum += 1;
    h.write(`${(sum >>> 0 & 0o777777).toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
    return h;
  }
  const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]);
  function paxBody(records, malformed) {
    const parts = records.map(([k, v]) => {
      const tail = Buffer.from(` ${k}=${v}\n`, 'utf8');
      let n = tail.length + 1;
      while (String(n).length + tail.length !== n) n += 1;
      return Buffer.concat([Buffer.from(String(n)), tail]);
    });
    if (malformed) parts.splice(Math.floor(rnd() * (parts.length + 1)), 0, Buffer.from(pick(['5 a=b\n', 'x path=q\n', '99 path=package/package.json\n'])));
    return Buffer.concat(parts);
  }
  const NAMES = ['package/package.json', 'package/./package.json', 'package//package.json', 'package/\\package.json', 'package/c:package.json',
    'package/C:/package.json', 'package/PACKAGE.JSON', 'package/x/../package.json', 'package/package.json/', 'package.json', 'package/sub/package.json',
    'package/z', 'x/package.json', '', 'package\0\n/package.json', 'package/package.json\0junk', 'a/b/c', 'package/.//package.json', '/package/package.json',
    `package/${'d'.repeat(120)}/package.json`];
  const PAXKEYS = ['path', 'size', 'mtime', 'comment', 'linkpath', 'charset', 'SCHILY.xattr.a', 'nullBlock', 'type', 'uid'];
  let serial = 0;
  const content = () => Buffer.from(`{"i":${serial += 1}}`);
  function hiddenEntry() { const c = content(); return Buffer.concat([hdr('package/package.json', c.length, '0'), pad(c)]); }

  function item() {
    const k = pick(['file', 'file', 'file', 'file', 'pax', 'gpax', 'L', 'N', 'K', 'dir', 'link', 'zero', 'other', 'hidden']);
    const o = { magic: chance(0.1) ? pick(['gnu', 'none']) : 'ustar', prefix: chance(0.15) ? pick(['package', 'x', 'package/sub', '']) : '',
      b475: chance(0.05), signed: chance(0.05), badSum: chance(0.04), linkname: chance(0.06) ? 'other' : '' };
    if (k === 'zero') return [Buffer.alloc(512, 0)];
    if (k === 'hidden') { const body = hiddenEntry(); return [hdr(pick(NAMES) || 'package/h', body.length, pick(['0', '5', '0'])), body]; }
    if (k === 'pax' || k === 'gpax') {
      const recs = [];
      for (let i = 0, n = 1 + Math.floor(rnd() * 3); i < n; i += 1) {
        const key = pick(PAXKEYS);
        const v = key === 'path' ? pick(NAMES.filter(Boolean)) : key === 'size' ? pick(['0', '512', '1024', '13', '1e3', '-1', ' 12'])
          : key === 'mtime' ? pick(['1', '1.5']) : key === 'type' ? pick(['0', '5']) : 'v';
        recs.push([key, v]);
      }
      const body = paxBody(recs, chance(0.2));
      return [hdr('././@PaxHeader', body.length, k === 'gpax' ? 'g' : pick(['x', 'x', 'X']), o), pad(body)];
    }
    if (k === 'L' || k === 'N' || k === 'K') {
      const nm = pick(NAMES.filter(Boolean));
      const body = chance(0.1) ? Buffer.alloc(0) : Buffer.from(chance(0.7) ? `${nm}\0` : nm);
      return [hdr('././@LongLink', body.length, k, o), pad(body)];
    }
    if (k === 'dir') { const sz = chance(0.4) ? 512 : 0; return [hdr(pick(['package/lib/', 'package/package.json/', 'package/d']), sz, '5', o), Buffer.alloc(sz, 0x20)]; }
    if (k === 'link') return [hdr(pick(NAMES) || 'package/l', chance(0.3) ? 512 : 0, pick(['1', '2']), { ...o, linkname: chance(0.8) ? 'target' : '' }), chance(0.3) ? Buffer.alloc(512, 0x30) : Buffer.alloc(0)];
    if (k === 'other') { const c = content(); return [hdr(pick(NAMES) || 'package/o', c.length, pick(['3', '6', 'S', 'Z', 'D', 'M']), o), pad(c)]; }
    const c = content();
    const declared = chance(0.85) ? c.length : pick([0, c.length + 512, 1024, 1]);
    return [hdr(pick(NAMES), declared, pick(['0', '0', '0', '\0', '7']), o), pad(c)];
  }
  const out = [];
  for (let n = 0; n < count; n += 1) {
    const items = [];
    for (let i = 0, m = 1 + Math.floor(rnd() * 7); i < m; i += 1) items.push(...item());
    const tail = pick([Buffer.alloc(1024, 0), Buffer.alloc(1024, 0), Buffer.alloc(512, 0), Buffer.concat([Buffer.alloc(1024, 0), Buffer.from('trailing')])]);
    out.push(zlib.gzipSync(Buffer.concat([...items, tail])));
  }
  return out;
}
