// 0.1.4 group 3c (D-M2): a constant-memory walk of a .tgz as it streams -- gunzip, then tar headers. It keeps the root
// package.json entries and skips every other content byte. It never touches the bytes npm receives: the caller feeds it a
// copy of each chunk.
//
// It reads the archive the way npm's extractor does (G4 tables dated notes 4 and 5): pacote over node-tar 7.5.11 (npm 10.9.7)
// and 7.5.19 (npm 11.19.0).
//   Framing and names as node-tar: a header is valid only with the unsigned checksum; a header node-tar rejects (bad checksum,
//   empty path, a link without a link name or a non-link with one, an invalid base-256 number) is skipped by ONE block and
//   the next block is read as a header; a directory (also a `0` entry ending in `/`) has size 0; names as node-tar's
//   decString; the ustar prefix only for the magic `ustar\0` + `00` (155 or 130 bytes by byte 475) -- and a pending pax or
//   L/N path replaces the whole name, prefix included, as read-entry.js does; pax records parsed line by line; x/X, L/N and K fill ONE pending set (the last wins); g never sets a path; a
//   size-0 meta header does nothing; a meta header over 1 MiB is ignored; the archive ends at two null blocks.
//   Where npm 10's and npm 11's readers differ, the walk is "not checked" (never a final result): a pending pax or global
//   size or path meeting a header that is not a normal file-system type; a pax size that is not all digits; a pax path that
//   is all digits or holds a NUL; a pax key outside the ones both read alike; a negative size.
//   Which entry is installed as <pkg>/package.json: pacote's filter (regular files only), `strip: 1`, node-tar's depth
//   limit, root stripping and `..` refusal -- emulated EXACTLY per view: Linux; macOS (ASCII case-insensitive); Windows
//   (`\` is a separator too; ASCII case-insensitive). Each view keeps its last such entry. Names a case-insensitive or
//   Windows file system MAY also map there (Unicode case folds, the 8.3 name, trailing dots or spaces) are separate
//   candidates that never replace a view's entry: MC compares each of them on its own, so they can only add a detection.
// Past a cap, on a gunzip error or a truncated archive, the outcome is "not checked", with the reason.
// 0.1.5 static checks step 1: an optional KEEP LIST. `createTarWalker({ keep })` also keeps the bodies of at most `maxKeep` named
// files (`maxKeepBytes` each) on the Linux view -- the files the manifest points npm at (main, bin, install-hook targets) -- exactly
// as it keeps the root package.json; every other byte is still skipped. `keep` is a list of package-relative paths known before
// the first byte (the registry manifest), or a function of the parsed root package.json applied when that entry completes (entries
// that preceded it are stated as not kept). The result then carries `files` [{ path, buf, name, platformsNotChecked }] and `notKept`
// [{ path, reason, size? }] (size: an over-cap target's header size); without `keep` the result is unchanged, key for key. Where macOS or Windows would install ANOTHER entry at a
// kept path (a case alias, a backslash separator), that platform is listed in platformsNotChecked: the body read is the Linux one.
import zlib from 'node:zlib';
import { posix, win32 } from 'node:path';

export const DEFAULTS = Object.freeze({ maxCompressed: 64 * 1024 * 1024, maxUncompressed: 256 * 1024 * 1024,
  maxPackageJson: 1024 * 1024, maxMeta: 64 * 1024, maxBehind: 16 * 1024 * 1024, maxApprox: 8, maxApproxBytes: 2 * 1024 * 1024,
  maxKeep: 6, maxKeepBytes: 1024 * 1024 });
const MAX_SEEN_BEFORE = 4096;                               // entry paths remembered until a keep FUNCTION resolves
const stats = { created: 0 };
export const walkerStats = () => ({ ...stats });

// ---- node-tar's field decoding (header.js, large-numbers.js) ----
const CODES = new Set(['0', '', '1', '2', '3', '4', '5', '6', '7', 'g', 'x', 'A', 'D', 'I', 'K', 'L', 'M', 'N', 'S', 'V', 'X']);
const NORMAL_FS = new Set(['0', '', '1', '2', '3', '4', '5', '6', '7', 'D']);       // 7.5.19 types.normalFsTypes
const META = new Set(['L', 'K', 'N', 'x', 'X', 'g']);
const DIVERGE = 'npm 10 and npm 11 read it differently';
class BadHeader extends Error {}
const decString = (b, off, size) => b.subarray(off, off + size).toString('utf8').replace(/\0.*/, '');
function decNumber(b, off, size) {
  const f = b.subarray(off, off + size);
  if (f[0] & 0x80) {
    let v = null;
    if (f[0] === 0x80) { v = 0; for (let i = 1; i < f.length; i += 1) v = v * 256 + f[i]; } else if (f[0] === 0xff) v = -1;
    if (v === null || !Number.isSafeInteger(v)) throw new BadHeader('invalid base-256 number');
    return v;
  }
  const n = parseInt(f.toString('utf8').replace(/\0.*$/, '').trim(), 8);
  return Number.isNaN(n) ? undefined : n;
}
// pax.js parseKV, with the values both versions read alike (anything else: not checked)
const PAX_KEYS = new Set(['path', 'size', 'mtime', 'atime', 'ctime', 'charset', 'comment', 'gname', 'uname', 'uid', 'gid',
  'mode', 'linkpath', 'dev', 'ino', 'nlink']);
function paxRecords(buf) {
  const out = {};
  for (const line of buf.toString('utf8').replace(/\n$/, '').split('\n')) {
    const n = parseInt(line, 10);
    if (n !== Buffer.byteLength(line) + 1) continue;
    const kv = line.slice(`${n} `.length).split('=');
    const r = kv.shift();
    if (!r) continue;
    const k = r.replace(/^SCHILY\.(dev|ino|nlink)/, '$1');
    const v = kv.join('=');
    if (!PAX_KEYS.has(k) && !k.includes('.')) throw new BadHeader(`not checked: pax key "${k.slice(0, 40)}" is not a pax key npm reads the same way`);
    if (k === 'size' && !/^[0-9]+$/.test(v)) throw new BadHeader(`not checked: a pax size ${DIVERGE}`);
    if (k === 'path' && (v.includes('\0') || /^[0-9]+$/.test(v))) throw new BadHeader(`not checked: a pax path ${DIVERGE}`);
    out[k] = k === 'size' ? Number(v) : v;
  }
  return out;
}

// ---- where npm writes an entry (pacote `strip: 1`, node-tar [CHECKPATH] / [STRIPABSOLUTEPATH]) ----
function stripAbsolute(p) {                                // strip-absolute-path.js: every leading root, by win32 rules
  let parsed = win32.parse(p);
  while (win32.isAbsolute(p) || parsed.root) {
    const root = p.charAt(0) === '/' && p.slice(0, 4) !== '//?/' ? '/' : parsed.root;
    p = p.slice(root.length);
    parsed = win32.parse(p);
  }
  return p;
}
/** The path, relative to the package folder, that npm writes a file entry to (one view), or null when it writes none. */
function writtenRel(name, windows) {
  const p = windows ? name.replace(/\\/g, '/') : name;
  const parts = p.split('/');
  parts.splice(0, 1);
  if (parts.length > 1024) return null;                    // node-tar: path excessively deep
  const stripped = stripAbsolute(parts.join('/'));
  if (!stripped) return null;                              // the package folder itself: refused for a file
  const segs = stripped.replace(/\\/g, '/').split('/');
  if (segs.includes('..') || (windows && /^[a-z]:\.\.$/i.test(segs[0] ?? ''))) return null;
  const base = windows ? 'C:\\pkg' : '/pkg';
  const abs = (windows ? win32 : posix).resolve(base, stripped);
  const prefix = `${base}${windows ? '\\' : '/'}`;
  if (!(windows ? abs.toLowerCase().startsWith(prefix.toLowerCase()) : abs.startsWith(prefix))) return null;
  return abs.slice(prefix.length);
}
const ASCII = /^[\x20-\x7e]*$/;
const fold = (x) => x.toUpperCase().toLowerCase();         // Unicode case folding, approximately (U+017F -> s)
/** For a regular-file entry name: the exact views it is installed as package.json in, and the approximate platforms. */
export function installTargets(name) {
  const exact = []; const approx = new Set();
  const lx = writtenRel(name, false);
  if (lx != null && !lx.includes('/')) {
    if (lx === 'package.json') exact.push('linux');
    if (ASCII.test(lx) && lx.toLowerCase() === 'package.json') exact.push('macos');
    else if (fold(lx) === 'package.json') approx.add('macOS');
  }
  const wx = writtenRel(name, true);
  if (wx != null && !/[\\/]/.test(wx)) {
    if (ASCII.test(wx) && wx.toLowerCase() === 'package.json') exact.push('windows');
    else {
      const t = wx.replace(/[. ]+$/, '');
      if (fold(t) === 'package.json' || /^packag~\d+\.jso$/i.test(t)) approx.add('Windows');
    }
  }
  return { exact, approx: [...approx] };
}

export function createTarWalker(opts = {}) {
  stats.created += 1;
  const o = { ...DEFAULTS, ...opts };
  let compressed = 0; let uncompressed = 0; let failed = null; let ended = false;
  let pending = Buffer.alloc(0);
  let state = 'header'; let remaining = 0; let pad = 0;
  let collect = null;                                      // { kind: 'pj' | meta type | null, chunks }
  let ex = null; let gex = {}; let sawNull = false;
  const views = { linux: null, macos: null, windows: null };   // view -> { buf, name }: the last entry npm installs there
  const approx = []; let approxBytes = 0;
  // 0.1.5 keep list: targets (normalised Linux-view paths), kept bodies (last entry wins, as node-tar overwrites), what was not kept
  const keepOpt = o.keep; const keepGiven = keepOpt !== undefined;
  let keepTargets = Array.isArray(keepOpt) ? null : (typeof keepOpt === 'function' ? null : new Set());
  const keepOrder = []; const kept = new Map(); const notKept = []; const aliases = new Map();
  const seenBefore = new Set(); let seenOverflow = false;
  const normKeep = (p) => {
    if (typeof p !== 'string' || p.includes('\0')) return null;
    const n = posix.normalize(p).replace(/^\.\//, '');
    return n === '' || n === '.' || n === '..' || n.startsWith('../') || n.startsWith('/') ? null : n;
  };
  const pushNotKept = (path, reason, size) => { if (!notKept.some((x) => x.path === path)) notKept.push(size === undefined ? { path, reason } : { path, reason, size }); };
  function setKeep(list) {
    keepTargets = new Set();
    for (const p of Array.isArray(list) ? list : []) {
      const n = normKeep(p);
      if (n === null) { pushNotKept(typeof p === 'string' ? p : String(p), 'outside the package'); continue; }
      if (n === 'package.json') { pushNotKept(n, 'the root package.json is read by the manifest check, not kept'); continue; }
      if (!keepTargets.has(n)) { keepTargets.add(n); keepOrder.push(n); }
    }
  }
  if (Array.isArray(keepOpt)) setKeep(keepOpt);
  else if (keepGiven && typeof keepOpt !== 'function') pushNotKept(null, 'keep list not computed: `keep` is neither a list of paths nor a function');
  /** The keep FUNCTION, once the FIRST Linux-view package.json is complete: it decides on the parsed object (null when unparseable).
   *  A later root package.json (MC reads the last) does not re-decide: the bodies between could not be kept anyway. */
  function resolveKeep(body) {
    let pj = null; try { pj = JSON.parse(body.toString('utf8')); } catch { pj = null; }
    if (pj === null || typeof pj !== 'object' || Array.isArray(pj)) pj = null;
    let list;
    try { list = keepOpt(pj); } catch (err) { setKeep([]); pushNotKept(null, `keep list not computed: ${err?.message ?? err}`); return; }
    setKeep(list);
    for (const t of keepOrder) if (seenBefore.has(t)) pushNotKept(t, 'preceded package.json');
    if (seenOverflow) pushNotKept(null, `entries before package.json beyond ${MAX_SEEN_BEFORE} not tracked`);
    seenBefore.clear();
  }
  /** Another entry that a case-insensitive or Windows file system installs at a kept path (the Linux body is the one read). */
  function noteAliases(entryPath, lx) {
    if (!keepTargets || !keepTargets.size) return;
    const wx = writtenRel(entryPath, true); const wxn = wx != null ? wx.replace(/\\/g, '/') : null;
    for (const t of keepTargets) {
      if (lx === t) continue;
      const tl = t.toLowerCase(); const hit = aliases.get(t) ?? new Set();
      if (lx != null && (lx.toLowerCase() === tl || fold(lx) === fold(t))) hit.add('macOS');
      if (wxn != null && (wxn.toLowerCase() === tl || fold(wxn.replace(/[. ]+$/, '')) === fold(t))) hit.add('Windows');
      if (hit.size) aliases.set(t, hit);
    }
  }
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
    const c = collect; collect = null;
    if (c.kind === 'keep') { kept.set(c.path, { buf: body, name: c.name }); return; }
    if (c.kind === 'pj') {
      for (const v of c.exact) views[v] = { buf: body, name: c.name };
      if (typeof keepOpt === 'function' && keepTargets === null && c.exact.includes('linux')) resolveKeep(body);
      if (c.approx.length) {
        approxBytes += body.length;
        if (approx.length >= o.maxApprox || approxBytes > o.maxApproxBytes) { fail('too many possible package.json entries'); return; }
        approx.push({ buf: body, name: c.name, platforms: c.approx });
      }
    } else if (c.kind === 'x' || c.kind === 'X') ex = { ...(ex ?? {}), ...paxRecords(body) };
    else if (c.kind === 'g') gex = { ...gex, ...paxRecords(body) };
    else if (c.kind === 'L' || c.kind === 'N') ex = { ...(ex ?? {}), path: body.toString('utf8').replace(/\0.*/, '') };
    else if (c.kind === 'K') ex = { ...(ex ?? {}), linkpath: body.toString('utf8').replace(/\0.*/, '') };
  }

  /** One header block, as node-tar's Header + Parse read it. Returns the body length to consume, or -1 to skip the block. */
  function header(h) {
    let sum = 256;
    for (let i = 0; i < 148; i += 1) sum += h[i];
    for (let i = 156; i < 512; i += 1) sum += h[i];
    const t = decString(h, 156, 1);
    const normal = NORMAL_FS.has(t);
    const pend = normal ? null : ex;                         // pending fields 7.5.11 applies and 7.5.19 does not
    const fieldPath = decString(h, 0, 100);
    let fieldSize; let cksum;
    try {
      for (const [off, size] of [[100, 8], [108, 8], [116, 8], [136, 12]]) decNumber(h, off, size);
      fieldSize = decNumber(h, 124, 12);
      cksum = decNumber(h, 148, 12);
    } catch (err) {
      if (err instanceof BadHeader && (ex || Object.keys(gex).length)) throw new BadHeader(`not checked: a header field ${DIVERGE}`);
      return -1;                                             // node-tar: the header is invalid; the next block is read
    }
    if (cksum === undefined && sum === 256) {                // a null block
      if (sawNull) ended = true; else sawNull = true;
      return 0;
    }
    sawNull = false;
    if (!normal) {
      const pendSize = pend?.size ?? gex.size;
      if (pendSize !== undefined && pendSize !== fieldSize) throw new BadHeader(`not checked: a pending pax size ${DIVERGE}`);
      if (!fieldPath && pend?.path !== undefined) throw new BadHeader(`not checked: a pending pax path ${DIVERGE}`);
    }
    let path = (normal ? ex?.path : undefined) ?? fieldPath;
    let size = (normal ? (ex?.size ?? gex.size) : undefined) ?? fieldSize;
    let type = CODES.has(t) ? (t || '0') : 'Unsupported';
    if (type === '0' && path.slice(-1) === '/') type = '5';
    if (type === '5') size = 0;
    const linkpath = decString(h, 157, 100);
    if (h.subarray(257, 265).toString() === 'ustar\u000000') {
      try { for (const [off, sz] of [[329, 8], [337, 8]]) decNumber(h, off, sz); if (h[475] === 0) { decNumber(h, 476, 12); decNumber(h, 488, 12); } } catch {
        if (ex || Object.keys(gex).length) throw new BadHeader(`not checked: a header field ${DIVERGE}`);
        return -1;
      }
      const prefix = h[475] !== 0 ? decString(h, 345, 155) : decString(h, 345, 130);
      if (h[475] !== 0 || prefix) path = `${prefix}/${path}`;
    }
    if (sum !== cksum) return -1;                            // checksum failure: skipped
    if (!path) return -1;                                    // path is required
    const link = type === '1' || type === '2';
    if (link && !linkpath) return -1;                        // linkpath required
    if (!link && type !== 'x' && type !== 'g' && linkpath) return -1;   // linkpath forbidden
    if (size !== undefined && size < 0) throw new BadHeader(`not checked: an invalid size (negative): ${DIVERGE}`);
    size = size ?? 0;
    if (size > o.maxUncompressed) throw new BadHeader(`an entry over the uncompressed cap (${o.maxUncompressed} bytes)`);
    // read-entry.js: the entry's path is the pending extended path when there is one (the prefix joined above only makes the
    // header valid), else the header's own (prefixed) path
    const entryPath = ex?.path !== undefined ? ex.path : path;
    if (META.has(type)) {
      if (size > 1024 * 1024) { collect = null; return size; }                 // node-tar ignores it
      if (size > o.maxMeta) throw new BadHeader(`tar: a metadata header over ${o.maxMeta} bytes`);
      collect = size > 0 ? { kind: type, chunks: [] } : null;
      return size;
    }
    ex = null;                                               // a pending extended header applies to this entry only
    collect = null;
    if (type === '0' || type === '7') {                      // pacote installs File / OldFile / ContiguousFile
      const tg = installTargets(entryPath);
      if (tg.exact.length || tg.approx.length) {
        if (size > o.maxPackageJson) throw new BadHeader(`package.json over ${o.maxPackageJson} bytes`);
        collect = { kind: 'pj', chunks: [], exact: tg.exact, approx: tg.approx, name: entryPath };
      } else if (keepGiven) {                                 // 0.1.5: a keep-list target, on the Linux view (writtenRel, as package.json)
        const lx = writtenRel(entryPath, false);
        if (keepTargets === null) { if (lx != null) { if (seenBefore.size < MAX_SEEN_BEFORE) seenBefore.add(lx); else seenOverflow = true; } }
        else {
          if (lx != null && keepTargets.has(lx)) {
            if (size > o.maxKeepBytes) pushNotKept(lx, `over the kept-file cap (${o.maxKeepBytes} bytes)`, size);   // static-checks-1.1: the header size (S1 oversized)
            else if (!kept.has(lx) && kept.size >= o.maxKeep) pushNotKept(lx, `beyond ${o.maxKeep} kept files`);
            else collect = { kind: 'keep', chunks: [], path: lx, name: entryPath };
          }
          noteAliases(entryPath, lx);
        }
      }
    }
    return size;
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
        let size;
        try { size = header(h); } catch (err) {
          if (!(err instanceof BadHeader)) throw err;
          fail(err.message.startsWith('not checked: ') ? err.message.slice('not checked: '.length) : err.message); return;
        }
        if (size <= 0) { if (size === 0) complete(); continue; }
        remaining = size; pad = (512 - (size % 512)) % 512;
        state = 'content';
        continue;
      }
      if (state === 'content') {
        const take = Math.min(remaining, buf.length - off);
        if (collect) collect.chunks.push(Buffer.from(buf.subarray(off, off + take)));
        off += take; remaining -= take;
        if (remaining === 0) {
          try { complete(); } catch (err) {
            if (!(err instanceof BadHeader)) throw err;
            fail(err.message.startsWith('not checked: ') ? err.message.slice('not checked: '.length) : err.message); return;
          }
          state = pad ? 'pad' : 'header';
        }
        continue;
      }
      const take = Math.min(pad, buf.length - off);       // state === 'pad'
      off += take; pad -= take;
      if (pad === 0) state = 'header';
    }
  }
  gunzip.on('data', onData);
  /** 0.1.5: `files` in keep order (kept bodies, Linux view) and `notKept` with one reason each; a target never seen is stated. */
  function keepResult() {
    if (typeof keepOpt === 'function' && keepTargets === null) { setKeep([]); pushNotKept(null, 'keep list not computed: no root package.json in the archive'); }
    const plat = (t) => ['macOS', 'Windows'].filter((x) => aliases.get(t)?.has(x));
    for (const t of keepOrder) if (!kept.has(t) && !notKept.some((x) => x.path === t)) {
      const a = plat(t); pushNotKept(t, a.length ? `not in the archive (an entry installs there on ${a.join(', ')})` : 'not in the archive');
    }
    return { files: keepOrder.filter((t) => kept.has(t)).map((t) => ({ path: t, buf: kept.get(t).buf, name: kept.get(t).name, platformsNotChecked: plat(t) })), notKept };
  }
  function grouped() {
    const out = [];
    for (const [v, label] of [['linux', 'Linux'], ['macos', 'macOS'], ['windows', 'Windows']]) {
      const e = views[v];
      const g = out.find((x) => x.packageJson === (e?.buf ?? null));
      if (g) g.platforms.push(label);
      else out.push({ platforms: [label], packageJson: e?.buf ?? null, name: e?.name ?? null });
    }
    return out;
  }

  return {
    write(chunk) {
      if (failed || ended) return;
      compressed += chunk.length;
      if (compressed > o.maxCompressed) { fail(`over the compressed cap (${o.maxCompressed} bytes)`); return; }
      if (gunzip.writableLength > o.maxBehind) { fail('the walk fell behind the download'); return; }
      gunzip.write(chunk);
    },
    /**
     * Finish: { ok: true, packageJson: Buffer | null (the Linux view), views, approx } or { ok: false, reason }. `views` groups
     * the exact views by the entry each installs: [{ platforms: ['Linux', 'macOS', 'Windows'], packageJson, name }];
     * `approx`: [{ platforms, packageJson, name }], each compared on its own.
     */
    async end() {
      if (!failed && !ended) { gunzip.end(); await settled; }
      if (failed) return { ok: false, reason: failed };
      const done = () => ({ ok: true, packageJson: views.linux?.buf ?? null, views: grouped(),
        approx: approx.map((a) => ({ platforms: a.platforms, packageJson: a.buf, name: a.name })), ...(keepGiven ? keepResult() : {}) });
      if (ended) { try { gunzip.destroy(); } catch { /* gone */ } return done(); }   // the end is final
      if (state !== 'header' || pending.length) return { ok: false, reason: 'tar: truncated archive' };
      return done();
    },
  };
}

export default { createTarWalker, walkerStats, installTargets, DEFAULTS };
