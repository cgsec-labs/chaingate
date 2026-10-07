// G10 runtime performance (dispatch 2026-10-07 §2): loadPackage must load a package with a CONSTANT number of
// statements, however many lineages it has (it used three per lineage: 6,566 for google-closure-compiler), and the
// change must be semantics-preserving. The reference below is the published 0.1.3 loader and LineageView, copied
// verbatim (source b66edfdd, seed/v3/checker.js:20-86), so parity is checked against the shipped behaviour.
import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import C from '../../seed/v3/checker.js';

// ------------------------------------------------------------------ reference: published 0.1.3, verbatim
const EVENT_ONLY_KEYS = new Set(['tool_version', 'added', 'removed']);
function stripEventOnly(after) {
  const out = {};
  for (const [k, v] of Object.entries(after)) if (!EVENT_ONLY_KEYS.has(k)) out[k] = v;
  return out;
}
class RefLineageView {
  constructor(row) { Object.assign(this, row); }
  stateAt(grp, ord) {
    let st = { ...this.initial[grp] };
    for (const e of this.events) if (e.grp === grp && e.ord <= ord) st = stripEventOnly(e.after);
    return st;
  }
  segmentStarts(grp) {
    const out = [[0, this.first_published_s, { ...this.initial[grp] }]];
    const evs = this.events.filter((e) => e.grp === grp).sort((a, b) => a.ord - b.ord);
    for (const e of evs) out.push([e.ord, e.published_s, stripEventOnly(e.after)]);
    return out;
  }
  get minSpineOrd() {
    const ords = [...this.spine.keys()];
    return ords.length ? Math.min(...ords) : null;
  }
}
function refLoadPackage(db, packageName, seedMeta) {
  const row = db.prepare('SELECT id, package_name FROM packages WHERE package_name = ?').get(packageName);
  if (!row) return null;
  const pv = { package_id: row.id, package_name: row.package_name, lineages: new Map(), seed_meta: seedMeta };
  const lrows = db.prepare(
    'SELECT id, lineage_key, n_versions, first_published_s, last_published_s FROM lineages WHERE package_id = ? ORDER BY ord',
  ).all(pv.package_id);
  const qState = db.prepare('SELECT grp, initial_state FROM lineage_state WHERE lineage_id = ?');
  const qEvents = db.prepare(
    'SELECT grp, ord, version, published_s, after_state FROM events WHERE lineage_id = ? ORDER BY ord, grp');
  const qSpine = db.prepare(
    'SELECT ord, version, published_s, size_bytes, tool_key, shasum, capture_class FROM spine WHERE lineage_id = ? ORDER BY ord');
  for (const l of lrows) {
    const initial = {};
    for (const s of qState.all(l.id)) initial[s.grp] = JSON.parse(s.initial_state);
    const events = qEvents.all(l.id).map((e) => ({
      grp: e.grp, ord: e.ord, version: e.version, published_s: e.published_s, after: JSON.parse(e.after_state),
    }));
    const spine = new Map();
    for (const s of qSpine.all(l.id)) {
      spine.set(s.ord, {
        version: s.version, published_s: s.published_s, size_bytes: s.size_bytes, tool_key: s.tool_key,
        shasum: Buffer.isBuffer(s.shasum) ? s.shasum.toString('hex') : s.shasum, capture_class: s.capture_class,
      });
    }
    pv.lineages.set(l.id, new RefLineageView({
      lineage_id: l.id, lineage_key: l.lineage_key, n_versions: l.n_versions,
      first_published_s: l.first_published_s, last_published_s: l.last_published_s, initial, events, spine,
    }));
  }
  return pv;
}

// ------------------------------------------------------------------ fixture seed (the real seed schema)
const SCHEMA = `
CREATE TABLE packages (id INTEGER PRIMARY KEY, package_name TEXT NOT NULL UNIQUE, latest_version TEXT,
  lineage_count INTEGER NOT NULL, major_order TEXT NOT NULL);
CREATE TABLE lineages (id INTEGER PRIMARY KEY, package_id INTEGER NOT NULL, ord INTEGER NOT NULL,
  lineage_key TEXT NOT NULL, first_version TEXT NOT NULL, last_version TEXT NOT NULL,
  n_versions INTEGER NOT NULL, first_published_s INTEGER NOT NULL, last_published_s INTEGER NOT NULL,
  UNIQUE (package_id, ord));
CREATE INDEX idx_lineages_pkg ON lineages(package_id);
CREATE TABLE lineage_state (lineage_id INTEGER NOT NULL, grp TEXT NOT NULL, initial_state TEXT NOT NULL,
  PRIMARY KEY (lineage_id, grp)) WITHOUT ROWID;
CREATE TABLE spine (lineage_id INTEGER NOT NULL, ord INTEGER NOT NULL, version TEXT NOT NULL,
  published_s INTEGER NOT NULL, prerelease INTEGER NOT NULL, size_bytes INTEGER, tool_key REAL,
  shasum BLOB, capture_class TEXT NOT NULL, row_digest BLOB NOT NULL,
  PRIMARY KEY (lineage_id, ord)) WITHOUT ROWID;
CREATE TABLE events (lineage_id INTEGER NOT NULL, grp TEXT NOT NULL, ord INTEGER NOT NULL,
  version TEXT NOT NULL, published_s INTEGER NOT NULL, after_state TEXT NOT NULL,
  witness_row_digest BLOB NOT NULL, PRIMARY KEY (lineage_id, grp, ord)) WITHOUT ROWID;
CREATE TABLE seed_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
`;
const GROUPS = ['publisher', 'provenance', 'install', 'git', 'deps'];
const hexOf = (i, n) => (i.toString(16).padStart(2, '0')).repeat(n / 2).slice(0, n);

/**
 * One package 'big' with `n` lineages whose ids are NON-CONTIGUOUS and NOT in `ord` order, events with TIED publication
 * times (across lineages and across groups at one ord), a BLOB and a text shasum, a lineage with no events and no spine,
 * plus a neighbour package whose rows must never leak into 'big'.
 */
function buildSeed(n) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'g10-load-'));
  const dbPath = path.join(dir, 'seed.db');
  const db = new Database(dbPath);
  db.exec(SCHEMA);
  const insP = db.prepare('INSERT INTO packages VALUES (?,?,?,?,?)');
  const insL = db.prepare('INSERT INTO lineages VALUES (?,?,?,?,?,?,?,?,?)');
  const insS = db.prepare('INSERT INTO lineage_state VALUES (?,?,?)');
  const insE = db.prepare('INSERT INTO events VALUES (?,?,?,?,?,?,?)');
  const insSp = db.prepare('INSERT INTO spine VALUES (?,?,?,?,?,?,?,?,?,?)');
  insP.run(7, 'big', null, n, ''); insP.run(3, 'other', null, 1, '');
  db.transaction(() => {
    for (let k = 0; k < n; k += 1) {
      const id = 1000 - 37 * k + (k % 3) * 5000;           // non-contiguous, not monotone in ord
      const ord = (k * 7) % n;                              // ords are a permutation of 0..n-1
      const t0 = 1000 + 100 * (ord % 4);                    // tied first-publication times across lineages
      const nv = 6;
      insL.run(id, 7, ord, `L${ord}`, 'v0', 'vN', nv, t0, t0 + 500);
      for (const g of GROUPS) {
        insS.run(id, g, JSON.stringify({ g, k, present: k % 2 === 0, has_scripts: k % 5 === 0, tuple_digest: hexOf(k, 64),
          identity_digest: hexOf(k + 1, 64), tool_name: 'npm', head_present: true }));
      }
      if (k % 9 !== 4) {                                    // k % 9 === 4: no events, no spine
        for (const [g, o] of [['publisher', 2], ['install', 2], ['provenance', 3], ['git', 5], ['deps', 1], ['publisher', 4]]) {
          insE.run(id, g, o, `v${o}`, t0 + 100 * Math.floor(o / 2), JSON.stringify({ o, g, k, present: o % 2 === 1,
            has_scripts: o === 2, tuple_digest: hexOf(o + k, 64), added: ['x'], removed: [], tool_version: '1' }),
          Buffer.alloc(32));
        }
        for (let o = 2; o < nv; o += 1) {
          insSp.run(id, o, `v${o}`, t0 + 100 * Math.floor(o / 2), 0, o === 3 ? null : 1000 * (o + 1), o === 4 ? null : 10 + o,
            o === 2 ? Buffer.from(hexOf(o, 40), 'hex') : (o === 5 ? 'not-hex' : null), 'LIVE', Buffer.alloc(32));
        }
      }
    }
    insL.run(5, 3, 0, 'O0', 'v0', 'v1', 1, 1000, 1000);
    for (const g of GROUPS) insS.run(5, g, JSON.stringify({ other: true }));
    insE.run(5, 'publisher', 0, 'v0', 1000, '{"other":true}', Buffer.alloc(32));
    insSp.run(5, 0, 'v0', 1000, 0, 5, 1, null, 'LIVE', Buffer.alloc(32));
  })();
  db.close();
  return dbPath;
}

/** A database wrapper that counts every statement execution (get/all/iterate/run). */
function counting(db) {
  const stats = { prepared: 0, executed: 0 };
  return { stats, db: {
    prepare(sql) {
      stats.prepared += 1;
      const st = db.prepare(sql);
      const wrap = (fn) => (...a) => { stats.executed += 1; return st[fn](...a); };
      return { get: wrap('get'), all: wrap('all'), iterate: wrap('iterate'), run: wrap('run') };
    },
  } };
}

/** Canonical, order-preserving view of a loaded package (Map order included). */
function canon(pv) {
  if (pv === null) return null;
  return {
    package_id: pv.package_id, package_name: pv.package_name, seed_meta: pv.seed_meta,
    lineages: [...pv.lineages].map(([id, lv]) => [id, {
      lineage_id: lv.lineage_id, lineage_key: lv.lineage_key, n_versions: lv.n_versions,
      first_published_s: lv.first_published_s, last_published_s: lv.last_published_s,
      initial: lv.initial, initialKeys: Object.keys(lv.initial), events: lv.events, spine: [...lv.spine],
      minSpineOrd: lv.minSpineOrd,
    }]),
  };
}

test('loadPackage runs a constant number of statements, independent of the lineage count (query amplification)', () => {
  const counts = [];
  for (const n of [1, 12, 60]) {
    const db = new Database(buildSeed(n), { readonly: true });
    try {
      const c = counting(db);
      const pv = C.loadPackage(c.db, 'big', {});
      assert.strictEqual(pv.lineages.size, n);
      counts.push(c.stats.executed);
    } finally { db.close(); }
  }
  assert.ok(counts.every((x) => x === counts[0]), `statement executions must not grow with lineages: ${counts.join(', ')}`);
  assert.ok(counts[0] <= 5, `at most 5 statement executions per package load, got ${counts[0]}`);
});

test('set-based loadPackage is identical to the published loader (order, ids, ties, shasum forms, empty lineages, neighbours)', () => {
  const db = new Database(buildSeed(60), { readonly: true });
  try {
    for (const name of ['big', 'other', 'absent']) {
      const meta = { history_cutoff: 'x' };
      assert.deepStrictEqual(canon(C.loadPackage(db, name, meta)), canon(refLoadPackage(db, name, meta)), name);
    }
  } finally { db.close(); }
});

test('LineageView lookups and segment derivation match the published LineageView for every group and ord', () => {
  const db = new Database(buildSeed(60), { readonly: true });
  try {
    const got = C.loadPackage(db, 'big', {}); const ref = refLoadPackage(db, 'big', {});
    for (const [id, lv] of got.lineages) {
      const rv = ref.lineages.get(id);
      for (const g of [...GROUPS, 'size', 'absent']) {
        assert.deepStrictEqual(lv.segmentStarts(g), rv.segmentStarts(g), `segmentStarts ${id} ${g}`);
        assert.deepStrictEqual(lv.segmentStarts(g), rv.segmentStarts(g), `segmentStarts repeat ${id} ${g}`);
        for (let o = -1; o <= lv.n_versions + 1; o += 1) assert.deepStrictEqual(lv.stateAt(g, o), rv.stateAt(g, o), `stateAt ${id} ${g} ${o}`);
      }
      // returned states are fresh objects: a caller mutating one cannot alter the view
      const s = lv.segmentStarts('publisher'); s[0][2].mutated = true; s.push('junk');
      assert.deepStrictEqual(lv.segmentStarts('publisher'), rv.segmentStarts('publisher'));
      const st = lv.stateAt('install', 3); st.mutated = true;
      assert.deepStrictEqual(lv.stateAt('install', 3), rv.stateAt('install', 3));
    }
  } finally { db.close(); }
});

test('a LineageView built from UNSORTED events keeps the published semantics (last event in array order wins in stateAt)', () => {
  const ev = (grp, ord, x) => ({ grp, ord, version: `v${ord}`, published_s: 100 + ord, after: { x, added: ['a'] } });
  const row = { lineage_id: 9, lineage_key: 'k', n_versions: 8, first_published_s: 100, last_published_s: 200,
    initial: { publisher: { x: 0 } }, events: [ev('publisher', 5, 'c'), ev('publisher', 2, 'a'), ev('install', 1, 'i'),
      ev('publisher', 3, 'b'), ev('publisher', 1, 'z')], spine: new Map([[4, {}], [2, {}]]) };
  const lv = new C.LineageView({ ...row, events: row.events.slice() });
  const rv = new RefLineageView({ ...row, events: row.events.slice() });
  for (const g of ['publisher', 'install', 'git']) {
    assert.deepStrictEqual(lv.segmentStarts(g), rv.segmentStarts(g));
    for (let o = 0; o <= 8; o += 1) assert.deepStrictEqual(lv.stateAt(g, o), rv.stateAt(g, o), `${g} ${o}`);
  }
  assert.strictEqual(lv.minSpineOrd, rv.minSpineOrd);
});

test('findings over every lineage of the package are byte-identical to findings from the published loader', () => {
  const db = new Database(buildSeed(60), { readonly: true });
  try {
    const got = C.loadPackage(db, 'big', { m: 1 }); const ref = refLoadPackage(db, 'big', { m: 1 });
    const base = { package_name: 'big', version: 'x', tool_name: 'npm', tool_key: 12, maint_digest: 'm', body_digest: 'b',
      publish_method: '', provider_class: 'unknown', provenance_present: false, has_scripts: true, head_present: false,
      identity_digest: hexOf(99, 64), tuple_digest: hexOf(98, 64), repo_digest: null, size_bytes: 9000 };
    for (const [id, lv] of got.lineages) {
      for (const [ord, published_s] of [[null, 9999], [0, 1000], [3, 1100], [lv.n_versions - 1, 1200], [2, null], [1, 1300]]) {
        const c = { ...base, lineage_id: id, ord, published_s };
        assert.strictEqual(JSON.stringify(C.check(got, c)), JSON.stringify(C.check(ref, c)), `lineage ${id} ord ${ord}`);
      }
    }
  } finally { db.close(); }
});

test('a malformed stored state fails exactly as the published loader fails (same row, same error)', () => {
  const dbPath = buildSeed(12);
  const w = new Database(dbPath);
  // corrupt one event of the lineage at ord 3 and one state of the lineage at ord 8: the published loader meets ord 3 first
  const at = (o) => w.prepare('SELECT id FROM lineages WHERE package_id = 7 AND ord = ?').pluck().get(o);
  w.prepare("UPDATE events SET after_state = '{bad' WHERE lineage_id = ? AND grp = 'git'").run(at(3));
  w.prepare("UPDATE lineage_state SET initial_state = '[oops' WHERE lineage_id = ? AND grp = 'deps'").run(at(8));
  w.close();
  const db = new Database(dbPath, { readonly: true });
  try {
    let refErr; let gotErr;
    try { refLoadPackage(db, 'big', {}); } catch (e) { refErr = e; }
    try { C.loadPackage(db, 'big', {}); } catch (e) { gotErr = e; }
    assert.ok(refErr && gotErr);
    assert.strictEqual(gotErr.name, refErr.name); assert.strictEqual(gotErr.message, refErr.message);
  } finally { db.close(); }
});
