// 0.1.4 group 3c (D-M2; G3 dated note 5): a constant-memory walk of a .tgz as it streams -- gunzip, then tar headers only.
// It keeps the ROOT package.json (`<first path segment>/package.json`; the last one wins, as validate.py read_tar keeps the
// last) and skips every other content byte. It never touches the bytes npm receives: the caller feeds it a copy of each chunk.
//
// Framing follows the readers it must agree with -- tarfile (the counted code) and node-tar (what npm installs):
//   pax `x` (and the old Solaris `X`) apply to the next entry, `g` to every following one; both `path` and `size` apply;
//   records are parsed as BYTES (a record's length counts bytes) and only values are decoded as UTF-8;
//   GNU `L` names the next entry; GNU `K` (a long link name) is metadata and never uses up an `L` name;
//   the ustar prefix joins the name; the signed header checksum is accepted as well as the unsigned one;
//   a size that is negative, not a finite integer, or past the caps is "not checked" (never an endless loop);
//   the archive ends at TWO zero blocks, as node-tar reads it (tarfile stops at one: a package.json after a single zero
//   block is installed by npm, so the walk reads it -- stated in dated note 5, a deviation that can only add detections).
// Past a cap or on any gunzip/tar error the outcome is "not checked", with the reason.
import zlib from 'node:zlib';

export const DEFAULTS = Object.freeze({ maxCompressed: 64 * 1024 * 1024, maxUncompressed: 256 * 1024 * 1024,
  maxPackageJson: 1024 * 1024, maxMeta: 64 * 1024, maxBehind: 16 * 1024 * 1024 });
const REGULAR = new Set(['0', '\0', '7']);
const stats = { created: 0 };
export const walkerStats = () => ({ ...stats });

const cstr = (b) => { const i = b.indexOf(0); return b.subarray(0, i < 0 ? b.length : i).toString('utf8'); };

/** The header's size field: octal text, or base-256 (the high bit set; the sign bit 0x40 on the first byte = negative). */
function sizeOf(h) {
  const f = h.subarray(124, 136);
  if (f[0] & 0x80) {
    if (f[0] & 0x40) return -1;                            // negative base-256
    let n = f[0] & 0x3f;
    for (let i = 1; i < f.length; i += 1) n = n * 256 + f[i];
    return n;
  }
  const s = cstr(f).trim();
  if (!s) return 0;
  return /^[0-7]+$/.test(s) ? parseInt(s, 8) : NaN;
}
function checksumOk(h) {
  const text = cstr(h.subarray(148, 156)).trim();
  if (!/^[0-7]+$/.test(text)) return false;
  const want = parseInt(text, 8);
  let unsigned = 0; let signed = 0;
  for (let i = 0; i < 512; i += 1) {
    const b = (i >= 148 && i < 156) ? 32 : h[i];
    unsigned += b; signed += b > 127 ? b - 256 : b;
  }
  return want === unsigned || want === (signed & 0o777777);
}
/** pax records, parsed as bytes: Map(key -> value string). Malformed framing ends the parse. */
function paxRecords(buf) {
  const out = new Map();
  let off = 0;
  while (off < buf.length) {
    const sp = buf.indexOf(0x20, off);
    if (sp < 0) break;
    const len = Number(buf.subarray(off, sp).toString('latin1'));
    if (!Number.isInteger(len) || len <= 0 || off + len > buf.length || buf[off + len - 1] !== 0x0a) break;
    const rec = buf.subarray(sp + 1, off + len - 1);
    const eq = rec.indexOf(0x3d);
    if (eq > 0) out.set(rec.subarray(0, eq).toString('utf8'), rec.subarray(eq + 1).toString('utf8'));
    off += len;
  }
  return out;
}

export function createTarWalker(opts = {}) {
  stats.created += 1;
  const o = { ...DEFAULTS, ...opts };
  let compressed = 0; let uncompressed = 0; let failed = null; let ended = false;
  let pending = Buffer.alloc(0);
  let state = 'header'; let remaining = 0; let pad = 0;
  let collect = null;                                      // { kind: 'pj' | 'L' | 'K' | 'x' | 'g', chunks }
  let nextName = null; let paxNext = new Map(); const paxGlobal = new Map();
  let packageJson = null; let zeroBlocks = 0;
  const gunzip = zlib.createGunzip();
  let resolveSettled;
  const settled = new Promise((r) => { resolveSettled = r; });
  const fail = (reason) => {
    if (failed) return;
    failed = reason;
    gunzip.removeListener('data', onData);
    try { gunzip.destroy(); } catch { /* already gone */ }
    resolveSettled();
  };
  gunzip.once('end', () => resolveSettled());
  gunzip.on('error', (e) => fail(`gunzip: ${e.message}`));

  function complete() {
    if (!collect) return;
    const body = Buffer.concat(collect.chunks);
    if (collect.kind === 'pj') packageJson = body;
    else if (collect.kind === 'L') nextName = cstr(body);
    else if (collect.kind === 'x') paxNext = paxRecords(body);
    else if (collect.kind === 'g') for (const [k, v] of paxRecords(body)) paxGlobal.set(k, v);
    collect = null;                                        // 'K' (long link name): read, ignored
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
        const meta = type === 'L' || type === 'K' || type === 'x' || type === 'X' || type === 'g';
        let size = sizeOf(h);
        if (!meta) {
          const pax = new Map([...paxGlobal, ...paxNext]);
          if (pax.has('size')) size = /^\d+$/.test(pax.get('size')) ? Number(pax.get('size')) : NaN;
          const ustar = h.subarray(257, 262).toString('latin1') === 'ustar';
          const prefix = ustar ? cstr(h.subarray(345, 500)) : '';
          const own = cstr(h.subarray(0, 100));
          const name = pax.get('path') ?? nextName ?? (prefix ? `${prefix}/${own}` : own);
          nextName = null; paxNext = new Map();
          if (!Number.isSafeInteger(size) || size < 0) { fail('tar: invalid size'); return; }
          if (size > o.maxUncompressed) { fail(`an entry over the uncompressed cap (${o.maxUncompressed} bytes)`); return; }
          const slash = name.indexOf('/');
          if (REGULAR.has(type) && slash >= 0 && name.slice(slash + 1) === 'package.json') {
            if (size > o.maxPackageJson) { fail(`package.json over ${o.maxPackageJson} bytes`); return; }
            collect = { kind: 'pj', chunks: [] };
          } else collect = null;
        } else {
          if (!Number.isSafeInteger(size) || size < 0) { fail('tar: invalid size'); return; }
          if (size > o.maxMeta) { fail(`tar: a metadata header over ${o.maxMeta} bytes`); return; }
          collect = { kind: type === 'X' ? 'x' : type, chunks: [] };
        }
        remaining = size; pad = (512 - (size % 512)) % 512;
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
      const take = Math.min(pad, buf.length - off);       // state === 'pad'
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
      if (!failed && !ended) { gunzip.end(); await settled; }
      if (failed) return { ok: false, reason: failed };
      if (ended) { try { gunzip.destroy(); } catch { /* gone */ } return { ok: true, packageJson }; }   // the end is final
      if (state !== 'header' || pending.length) return { ok: false, reason: 'tar: truncated archive' };
      return { ok: true, packageJson };
    },
  };
}

export default { createTarWalker, walkerStats, DEFAULTS };
