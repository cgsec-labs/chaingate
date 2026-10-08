// G10 EXPERIMENTAL read layout g10-rl1 (dispatch 2026-10-08 §3). A seed that declares the derived initial-state table is
// loaded from it for the selected packages (one row instead of one row per lineage and group), the loaded view is
// identical to the canonical one, a declared but missing/unknown/partial/corrupt/inconsistent layout is refused, and a
// seed without the declaration is read exactly as before.
import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import C from '../../seed/v3/checker.js';
import R from '../../seed/v3/reader.js';
import RL from '../../seed/v3/read-layout.js';

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
const N = RL.RL1_MIN_LINEAGES + 7;
const stateOf = (g, k) => (g === 'deps' && k % 11 === 3
  ? JSON.stringify({ count: 2, names: ['a', 'b'], nested: { k: k % 2 } })          // a NON-flat state (array/object values)
  : JSON.stringify({ g, v: k % 4, present: k % 2 === 0, tool_name: 'npm', d: null }));

/** 'big' (N lineages, non-contiguous ids, ord a permutation), 'mid' (5 lineages, below the rule), 'odd' (N lineages but
 *  one lacks a group: outside the rule). Returns the path. */
function buildSeed({ malformed = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'g10-rl1-'));
  const dbPath = path.join(dir, 'seed.db');
  const db = new Database(dbPath);
  db.exec(SCHEMA);
  const insP = db.prepare('INSERT INTO packages VALUES (?,?,?,?,?)');
  const insL = db.prepare('INSERT INTO lineages VALUES (?,?,?,?,?,?,?,?,?)');
  const insS = db.prepare('INSERT INTO lineage_state VALUES (?,?,?)');
  const insE = db.prepare('INSERT INTO events VALUES (?,?,?,?,?,?,?)');
  const insSp = db.prepare('INSERT INTO spine VALUES (?,?,?,?,?,?,?,?,?,?)');
  db.transaction(() => {
    let id = 10;
    for (const [pid, name, n] of [[7, 'big', N], [3, 'mid', 5], [9, 'odd', N]]) {
      insP.run(pid, name, null, n, '');
      for (let k = 0; k < n; k += 1) {
        id += (k % 3) + 1; const ord = (k * 7) % n; const t0 = 1000 + ord;
        insL.run(id, pid, ord, `L${ord}`, 'v0', 'vN', 4, t0, t0 + 50);
        for (const g of RL.RL1_GROUPS) if (!(name === 'odd' && k === 5 && g === 'git')) insS.run(id, g, stateOf(g, k));
        if (k % 4 === 1) {
          insE.run(id, 'publisher', 2, 'v2', t0 + 20, JSON.stringify({ g: 'publisher', v: 9, added: ['x'] }), Buffer.alloc(32));
          insSp.run(id, 2, 'v2', t0 + 20, 0, 100, 1.5, Buffer.from('ab'.repeat(20), 'hex'), 'LIVE', Buffer.alloc(32));
        }
      }
    }
    for (const [k, v] of [['schema_version', '3'], ['contract_version', 'cft-seed-v3-contract-1.1']]) db.prepare('INSERT INTO seed_metadata VALUES (?,?)').run(k, v);
    if (malformed) {     // the published loader meets lineage ord 3's bad event before lineage ord 8's bad state
      const at = (o) => db.prepare('SELECT id FROM lineages WHERE package_id = 7 AND ord = ?').pluck().get(o);
      db.prepare("INSERT OR REPLACE INTO events VALUES (?, 'git', 1, 'v1', 0, '{bad', zeroblob(32))").run(at(3));
      db.prepare("UPDATE lineage_state SET initial_state = '[oops' WHERE lineage_id = ? AND grp = 'deps'").run(at(8));
    }
  })();
  db.close();
  return dbPath;
}

/** Adds the g10-rl1 table and declaration, derived from the canonical rows (mirrors tools/seedgen/read_layout.py). */
function addRl1(dbPath) {
  const db = new Database(dbPath);
  db.exec(`CREATE TABLE ${RL.RL1_TABLE} (package_id INTEGER PRIMARY KEY, n_lineages INTEGER NOT NULL, groups TEXT NOT NULL, dict TEXT NOT NULL, idx TEXT NOT NULL)`);
  const rows = [];
  for (const pid of [7]) {                                     // 'big' only: 'mid' is below the rule, 'odd' lacks a group
    const texts = []; const at = new Map(); const idx = [];
    for (const lid of db.prepare('SELECT id FROM lineages WHERE package_id = ? ORDER BY ord').pluck().all(pid)) {
      const st = Object.fromEntries(db.prepare('SELECT grp, initial_state FROM lineage_state WHERE lineage_id = ?').raw(true).all(lid));
      const x = [lid];
      for (const g of RL.RL1_GROUPS) { if (!at.has(st[g])) { at.set(st[g], texts.length); texts.push(st[g]); } x.push(at.get(st[g])); }
      idx.push(x);
    }
    rows.push({ package_id: pid, n_lineages: idx.length, groups: JSON.stringify(RL.RL1_GROUPS), dict: JSON.stringify(texts), idx: JSON.stringify(idx) });
  }
  const ins = db.prepare(`INSERT INTO ${RL.RL1_TABLE} VALUES (@package_id, @n_lineages, @groups, @dict, @idx)`);
  for (const r of rows) ins.run(r);
  const m = db.prepare('INSERT INTO seed_metadata VALUES (?,?)');
  m.run('read_layout', RL.RL1); m.run('read_layout_digest', RL.contentDigest(rows)); m.run('read_layout_recipe', RL.RL1_RECIPE);
  db.close();
  return dbPath;
}
const copyOf = (p) => { const q = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'g10-rl1c-')), 'seed.db'); fs.copyFileSync(p, q); return q; };
const mutate = (p, sql, ...a) => { const db = new Database(p); try { db.prepare(sql).run(...a); } finally { db.close(); } return p; };
const redigest = (p) => { const db = new Database(p); try {
  const rows = db.prepare(`SELECT ${RL.RL1_COLUMNS.join(', ')} FROM ${RL.RL1_TABLE}`).all();
  db.prepare("UPDATE seed_metadata SET value = ? WHERE key = 'read_layout_digest'").run(RL.contentDigest(rows)); } finally { db.close(); } return p; };

/** Counts statement executions and every row materialised (get = 1, all = its length), per SQL text. */
function counting(db) {
  const stats = { executed: 0, rows: 0, bySql: new Map() };
  return { stats, db: {
    prepare(sql) {
      const st = db.prepare(sql);
      const w = { raw(on = true) { st.raw(on); return w; }, pluck(on = true) { st.pluck(on); return w; } };
      for (const fn of ['get', 'all', 'iterate', 'run']) {
        w[fn] = (...a) => { const r = st[fn](...a); stats.executed += 1; const n = fn === 'all' ? r.length : (r === undefined ? 0 : 1);
          stats.rows += n; stats.bySql.set(sql, (stats.bySql.get(sql) ?? 0) + n); return r; };
      }
      return w;
    },
  } };
}
const canon = (pv) => (pv === null ? null : { id: pv.package_id, name: pv.package_name, meta: pv.seed_meta,
  lineages: [...pv.lineages].map(([id, lv]) => [id, lv.lineage_key, lv.n_versions, lv.first_published_s, lv.last_published_s,
    lv.initial, Object.keys(lv.initial), Object.keys(lv.initial).map((g) => Object.keys(lv.initial[g])), lv.events, [...lv.spine]]) });
const loadWith = (p, name) => { const db = new Database(p, { readonly: true }); try { return C.loadPackage(db, name, { m: 1 }); } finally { db.close(); } };

test('g10-rl1: a selected package is loaded from ONE derived row, not one row per lineage and group (row materialisation)', () => {
  const legacy = buildSeed(); const rl1 = addRl1(copyOf(legacy));
  const rowsOf = (p) => { const db = new Database(p, { readonly: true }); try { const c = counting(db); const pv = C.loadPackage(c.db, 'big', {});
    return { pv, ...c.stats, stateRows: [...c.stats.bySql].filter(([s]) => /lineage_state/.test(s)).reduce((a, [, n]) => a + n, 0),
      layoutRows: [...c.stats.bySql].filter(([s]) => s.includes(RL.RL1_TABLE)).reduce((a, [, n]) => a + n, 0) }; } finally { db.close(); } };
  const a = rowsOf(legacy); const b = rowsOf(rl1);
  assert.strictEqual(a.stateRows, N * 5); assert.strictEqual(a.layoutRows, 0);
  assert.strictEqual(b.stateRows, 0, 'no lineage_state row is materialised for a selected package');
  assert.strictEqual(b.layoutRows, 1);
  assert.strictEqual(a.rows - b.rows, N * 5 - 1, `rows materialised ${a.rows} -> ${b.rows}`);
  assert.ok(b.executed <= 5, `at most 5 statement executions, got ${b.executed}`);
  assert.deepStrictEqual(canon(b.pv), canon(a.pv));
});

test('g10-rl1: the loaded package is identical to the canonical load for every package (selected, below the rule, outside it, absent)', () => {
  const legacy = buildSeed(); const rl1 = addRl1(copyOf(legacy));
  for (const name of ['big', 'mid', 'odd', 'absent']) assert.deepStrictEqual(canon(loadWith(rl1, name)), canon(loadWith(legacy, name)), name);
  const db = new Database(rl1, { readonly: true });      // segment derivation over the loaded views
  try {
    const got = C.loadPackage(db, 'big', {}); const ref = loadWith(legacy, 'big');
    for (const [id, lv] of got.lineages) for (const g of [...RL.RL1_GROUPS, 'absent']) assert.deepStrictEqual(lv.segmentStarts(g), ref.lineages.get(id).segmentStarts(g));
  } finally { db.close(); }
});

test('g10-rl1: every lineage gets its own state objects (no sharing through the dictionary), flat or nested', () => {
  const pv = loadWith(addRl1(buildSeed()), 'big');
  const lvs = [...pv.lineages.values()];
  const seen = new Set();
  for (const lv of lvs) for (const g of RL.RL1_GROUPS) { assert.ok(!seen.has(lv.initial[g]), 'state object shared between lineages'); seen.add(lv.initial[g]); }
  const nested = lvs.filter((lv) => Array.isArray(lv.initial.deps.names));
  assert.ok(nested.length >= 2);
  assert.notStrictEqual(nested[0].initial.deps.names, nested[1].initial.deps.names);
  const before = JSON.stringify(lvs[1].initial); lvs[0].initial.publisher.v = 'mutated'; nested[0].initial.deps.names.push('z');
  assert.strictEqual(JSON.stringify(lvs[1].initial), before);
  assert.deepStrictEqual(nested[1].initial.deps.names, ['a', 'b']);
});

test('g10-rl1: a seed without the declaration is read exactly as before (no derived-table read), even if the table exists', () => {
  const legacy = buildSeed();
  const undeclared = mutate(addRl1(copyOf(legacy)), "DELETE FROM seed_metadata WHERE key LIKE 'read_layout%'");
  for (const p of [legacy, undeclared]) {
    const db = new Database(p, { readonly: true });
    try { const c = counting(db); C.loadPackage(c.db, 'big', {});
      assert.ok(![...c.stats.bySql.keys()].some((s) => s.includes(RL.RL1_TABLE))); assert.ok(c.stats.executed <= 5); } finally { db.close(); }
    assert.deepStrictEqual(canon(loadWith(p, 'big')), canon(loadWith(legacy, 'big')));
  }
  const rep = R.verify(undeclared, { trust: R.TRUST_UNSIGNED_DEV, verifyDigest: false });
  assert.ok(!('read_layout' in rep.checks), 'no read-layout check for an undeclared seed');
  assert.ok(!('read_layout' in R.verify(legacy, { trust: R.TRUST_UNSIGNED_DEV, verifyDigest: false }).checks));
});

test('g10-rl1: verify() accepts the declared layout only when it re-derives exactly from the canonical rows', () => {
  const v = (p) => R.verify(p, { trust: R.TRUST_UNSIGNED_DEV, verifyDigest: false }).checks.read_layout;
  const good = addRl1(buildSeed());
  assert.strictEqual(v(good), true);
  const cases = {
    'table missing': mutate(copyOf(good), `DROP TABLE ${RL.RL1_TABLE}`),
    'unknown layout id': mutate(copyOf(good), "UPDATE seed_metadata SET value = 'g10-rl9' WHERE key = 'read_layout'"),
    'partial declaration': mutate(copyOf(good), "DELETE FROM seed_metadata WHERE key = 'read_layout_digest'"),
    'recipe changed': mutate(copyOf(good), "UPDATE seed_metadata SET value = '{}' WHERE key = 'read_layout_recipe'"),
    'corrupt contents (digest)': mutate(copyOf(good), `UPDATE ${RL.RL1_TABLE} SET dict = '[not json' WHERE package_id = 7`),
    'inconsistent with canonical (digest recomputed)': redigest(mutate(copyOf(good), `UPDATE ${RL.RL1_TABLE} SET dict = replace(dict, '\\"v\\":1', '\\"v\\":2') WHERE package_id = 7`)),
    'canonical row changed after derivation': mutate(copyOf(good), "UPDATE lineage_state SET initial_state = '{\"x\":1}' WHERE grp = 'git' AND lineage_id = (SELECT max(id) FROM lineages WHERE package_id = 7)"),
    'selected package missing (digest recomputed)': redigest(mutate(copyOf(good), `DELETE FROM ${RL.RL1_TABLE} WHERE package_id = 7`)),
    'extra row below the rule (digest recomputed)': redigest(mutate(copyOf(good), `INSERT INTO ${RL.RL1_TABLE} SELECT 3, 5, groups, dict, idx FROM ${RL.RL1_TABLE} WHERE package_id = 7`)),
    'lineage count wrong (digest recomputed)': redigest(mutate(copyOf(good), `UPDATE ${RL.RL1_TABLE} SET n_lineages = n_lineages + 1 WHERE package_id = 7`)),
  };
  for (const [what, p] of Object.entries(cases)) {
    const got = v(p);
    assert.ok(typeof got === 'string' && got.length > 0, `${what}: ${got}`);
    assert.throws(() => R.openSeed(p, { trust: R.TRUST_UNSIGNED_DEV, verifyDigest: false }), /read_layout/, what);
  }
});

test('g10-rl1: loadPackage refuses a corrupt or inconsistent derived row instead of serving it', () => {
  const good = addRl1(buildSeed());
  const bad = {
    dict: mutate(copyOf(good), `UPDATE ${RL.RL1_TABLE} SET dict = '[not json' WHERE package_id = 7`),
    idx: mutate(copyOf(good), `UPDATE ${RL.RL1_TABLE} SET idx = replace(idx, '[[', '[[1,') WHERE package_id = 7`),
    count: mutate(copyOf(good), `UPDATE ${RL.RL1_TABLE} SET n_lineages = 3 WHERE package_id = 7`),
    groups: mutate(copyOf(good), `UPDATE ${RL.RL1_TABLE} SET groups = '["deps"]' WHERE package_id = 7`),
    range: mutate(copyOf(good), `UPDATE ${RL.RL1_TABLE} SET dict = '[]' WHERE package_id = 7`),
    'table missing': mutate(copyOf(good), `DROP TABLE ${RL.RL1_TABLE}`),
    'unknown layout id': mutate(copyOf(good), "UPDATE seed_metadata SET value = 'g10-rl9' WHERE key = 'read_layout'"),
  };
  for (const [what, p] of Object.entries(bad)) assert.throws(() => loadWith(p, 'big'), /read layout g10-rl1/, what);
});

test('g10-rl1: a malformed stored state fails exactly as the canonical loader fails (same row, same error)', () => {
  const legacy = buildSeed({ malformed: true }); const rl1 = addRl1(copyOf(legacy));
  let refErr; let gotErr;
  try { loadWith(legacy, 'big'); } catch (e) { refErr = e; }
  try { loadWith(rl1, 'big'); } catch (e) { gotErr = e; }
  assert.ok(refErr && gotErr);
  assert.strictEqual(gotErr.name, refErr.name); assert.strictEqual(gotErr.message, refErr.message);
});
