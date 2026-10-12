// 0.1.4 group 3c (D-M2): a constant-memory walk of a .tgz as it streams -- gunzip, then tar headers only. It keeps the ROOT
// package.json (`<first path segment>/package.json`, the last one wins, as validate.py read_tar keeps the last) and skips
// every other content byte. It understands ustar prefix+name, GNU 'L' long names and pax 'path=' records, verifies header
// checksums, and gives up -- "not checked", with the reason -- past a cap or on any gunzip/tar error. It never touches the
// bytes npm receives: the caller feeds it a copy of each chunk.
import zlib from 'node:zlib';

export const DEFAULTS = Object.freeze({ maxCompressed: 64 * 1024 * 1024, maxUncompressed: 256 * 1024 * 1024,
  maxPackageJson: 1024 * 1024, maxMeta: 64 * 1024, maxBehind: 16 * 1024 * 1024 });
const REGULAR = new Set(['0', '\0', '7']);

const cstr = (b) => { const i = b.indexOf(0); return b.subarray(0, i < 0 ? b.length : i).toString('utf8'); };
function sizeOf(h) {
  const f = h.subarray(124, 136);
  if (f[0] & 0x80) {                                       // base-256 (GNU, large entries)
    let n = 0; for (let i = 1; i < f.length; i += 1) n = n * 256 + f[i];
    return n;
  }
  const s = cstr(f).trim();
  return s ? parseInt(s, 8) : 0;
}
function checksumOk(h) {
  const want = parseInt(cstr(h.subarray(148, 156)).trim(), 8);
  let sum = 0;
  for (let i = 0; i < 512; i += 1) sum += (i >= 148 && i < 156) ? 32 : h[i];
  return sum === want;
}
function paxPath(buf) {
  let off = 0; let path = null;
  const s = buf.toString('utf8');
  while (off < s.length) {
    const sp = s.indexOf(' ', off);
    if (sp < 0) break;
    const len = parseInt(s.slice(off, sp), 10);
    if (!Number.isFinite(len) || len <= 0) break;
    const rec = s.slice(sp + 1, off + len - 1);           // "key=value" without the trailing newline
    const eq = rec.indexOf('=');
    if (eq > 0 && rec.slice(0, eq) === 'path') path = rec.slice(eq + 1);
    off += len;
  }
  return path;
}

export function createTarWalker(opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  let compressed = 0; let uncompressed = 0; let failed = null; let ended = false;
  let pending = Buffer.alloc(0);
  let state = 'header'; let remaining = 0; let pad = 0;
  let collect = null;                                      // { kind: 'pj' | 'L' | 'x', chunks, size }
  let nextName = null; let packageJson = null; let zeroBlocks = 0;
  const gunzip = zlib.createGunzip();
  const fail = (reason) => { if (!failed) { failed = reason; gunzip.removeListener('data', onData); } };
  const settled = new Promise((resolve) => { gunzip.once('end', resolve); gunzip.on('error', (e) => { fail(`gunzip: ${e.message}`); resolve(); }); });

  function complete() {
    if (!collect) return;
    const body = Buffer.concat(collect.chunks);
    if (collect.kind === 'pj') packageJson = body;
    else if (collect.kind === 'L') nextName = cstr(body);
    else if (collect.kind === 'x') { const p = paxPath(body); if (p !== null) nextName = p; }
    collect = null;
  }

  function onData(chunk) {
    if (failed || ended) return;
    uncompressed += chunk.length;
    if (uncompressed > o.maxUncompressed) { fail(`over the uncompressed cap (${o.maxUncompressed} bytes)`); return; }
    const buf = pending.length ? Buffer.concat([pending, chunk]) : chunk;
    pending = Buffer.alloc(0);
    let off = 0;
    while (off < buf.length && !failed && !ended) {
      if (state === 'header') {
        if (buf.length - off < 512) { pending = Buffer.from(buf.subarray(off)); return; }
        const h = buf.subarray(off, off + 512); off += 512;
        let zero = true; for (let i = 0; i < 512; i += 1) if (h[i] !== 0) { zero = false; break; }
        if (zero) { zeroBlocks += 1; if (zeroBlocks >= 2) ended = true; continue; }
        zeroBlocks = 0;
        if (!checksumOk(h)) { fail('tar: bad header checksum'); return; }
        const type = String.fromCharCode(h[156]);
        const size = sizeOf(h);
        const ustar = h.subarray(257, 262).toString('latin1') === 'ustar';
        const prefix = ustar ? cstr(h.subarray(345, 500)) : '';
        const own = cstr(h.subarray(0, 100));
        remaining = size; pad = (512 - (size % 512)) % 512;
        if (type === 'L' || type === 'x') {
          if (size > o.maxMeta) { fail(`tar: a ${type === 'L' ? 'long-name' : 'pax'} header over ${o.maxMeta} bytes`); return; }
          collect = { kind: type, chunks: [] };
        } else if (type === 'g') {
          collect = null;
        } else {
          const name = nextName ?? (prefix ? `${prefix}/${own}` : own);
          nextName = null;
          const slash = name.indexOf('/');
          if (REGULAR.has(type) && slash >= 0 && name.slice(slash + 1) === 'package.json') {
            if (size > o.maxPackageJson) { fail(`package.json over ${o.maxPackageJson} bytes`); return; }
            collect = { kind: 'pj', chunks: [] };
          } else collect = null;
        }
        state = 'content';
        if (remaining === 0) { complete(); state = pad ? 'pad' : 'header'; }
        continue;
      }
      if (state === 'content') {
        const take = Math.min(remaining, buf.length - off);
        if (collect) collect.chunks.push(Buffer.from(buf.subarray(off, off + take)));
        off += take; remaining -= take;
        if (remaining === 0) { complete(); state = pad ? 'pad' : 'header'; }
        continue;
      }
      // state === 'pad'
      const take = Math.min(pad, buf.length - off);
      off += take; pad -= take;
      if (pad === 0) state = 'header';
    }
  }
  gunzip.on('data', onData);

  return {
    write(chunk) {
      if (failed || ended) return;
      compressed += chunk.length;
      if (compressed > o.maxCompressed) { fail(`over the compressed cap (${o.maxCompressed} bytes)`); return; }
      if (gunzip.writableLength > o.maxBehind) { fail('the walk fell behind the download'); return; }
      gunzip.write(chunk);
    },
    /** Finish: { ok: true, packageJson: Buffer | null } or { ok: false, reason }. */
    async end() {
      if (!failed) gunzip.end();
      if (!failed) await settled;
      if (failed) { gunzip.destroy(); return { ok: false, reason: failed }; }
      if (!ended && (state !== 'header' || pending.length)) return { ok: false, reason: 'tar: truncated archive' };
      return { ok: true, packageJson };
    },
  };
}

export default { createTarWalker, DEFAULTS };
