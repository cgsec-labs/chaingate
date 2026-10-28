// Portable v3 evaluator — an INDEPENDENT native JavaScript implementation of detection contract v1.
// It computes findings itself from the shipped seed representation; it never calls Python and never
// reads an expected answer. Mirrors tools/seedgen/checker.py.
import K from './contract.js';
import RL from './read-layout.js';

const SEED_BINDING_KEYS = ['corpus_snapshot_digest', 'contract_version', 'schema_version', 'history_cutoff'];

/** Python's dict.get(): a key that is absent and a key that is null are the same thing here. */
function g(obj, key) {
  const v = obj === null || obj === undefined ? undefined : obj[key];
  return v === undefined ? null : v;
}
const EVENT_ONLY_KEYS = new Set(['tool_version', 'added', 'removed']);
function stripEventOnly(after) {
  const out = {};
  for (const [k, v] of Object.entries(after)) if (!EVENT_ONLY_KEYS.has(k)) out[k] = v;
  return out;
}

class LineageView {
  constructor(row) { Object.assign(this, row); }

  /** Group state in force at `ord` — initial state REPLACED by each event of that group at ord <= ord. */
  stateAt(grp, ord) {
    let st = { ...this.initial[grp] };
    for (const e of this.events) if (e.grp === grp && e.ord <= ord) st = stripEventOnly(e.after);
    return st;
  }

  /** [[start_ord, start_published_s, state]] for every segment of `grp`, in order. */
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

function loadSeedMeta(db) {
  const meta = {};
  for (const r of db.prepare('SELECT key, value FROM seed_metadata').all()) meta[r.key] = r.value;
  const out = {};
  for (const k of SEED_BINDING_KEYS) if (k in meta) out[k] = meta[k];
  if ('rule_versions' in meta) {
    try { out.rule_versions = JSON.parse(meta.rule_versions); } catch { out.rule_versions = meta.rule_versions; }
  }
  return out;
}

// Package loading is set-based, for performance: ONE statement per table for the whole package, never one
// per lineage (the per-lineage form ran 3 statements per lineage: 6,566 for google-closure-compiler). Loading stays
// eager and complete. Each per-lineage row order is the one the per-lineage statements produced (lineage_state in its
// primary-key order (grp); events ORDER BY ord, grp; spine ORDER BY ord), and rows are parsed and assembled lineage by
// lineage in `ORDER BY ord`, so the loaded package -- and the first malformed row a load meets -- are unchanged.
// Statements are prepared lazily, in the order the per-lineage loader prepared them, and reused per connection;
// they hold no data between calls. The four bulk statements return rows as ARRAYS (raw mode): the same
// values in the same order, without materialising one object per row; columns are read by position (LOAD_COLS).
// EXPERIMENTAL read layout g10-rl1 (seed/v3/read-layout.js): the package lookup also returns the seed's
// declared read layout (one scalar subquery, no extra statement); a database without seed_metadata keeps the original
// lookup (`packageLegacy`), so a legacy seed is read exactly as before. For a package with >= RL1_MIN_LINEAGES lineages
// in a seed that declares g10-rl1, its initial states come from the ONE derived row (`rl1`) instead of one row per lineage
// and group; the dictionary texts are parsed in the same traversal order the canonical rows were (lineages by ord, groups
// by grp), each lineage gets its own state objects, and a corrupt or inconsistent row is refused (ReadLayoutError).
const LOAD_SQL = {
  package: "SELECT id, package_name, (SELECT value FROM seed_metadata WHERE key = 'read_layout') AS read_layout FROM packages WHERE package_name = ?",
  packageLegacy: 'SELECT id, package_name FROM packages WHERE package_name = ?',
  rl1: `SELECT package_id, n_lineages, groups, dict, idx FROM ${RL.RL1_TABLE} WHERE package_id = ?`,
  lineages: 'SELECT id, lineage_key, n_versions, first_published_s, last_published_s FROM lineages WHERE package_id = ? ORDER BY ord',
  // seed contract 1.2 (rl2): the chain's tag family, and the cross-links of the package's chains
  lineagesRl2: 'SELECT id, lineage_key, n_versions, first_published_s, last_published_s, tag_family FROM lineages '
    + 'WHERE package_id = ? ORDER BY ord',
  links: 'SELECT x.lineage_id, x.ord, x.pred_lineage_id, x.pred_ord, x.pred_version, x.pred_size_bytes, x.pred_tool_key '
    + 'FROM lineages l JOIN cross_links x ON x.lineage_id = l.id WHERE l.package_id = ? ORDER BY x.lineage_id, x.ord',
  states: 'SELECT s.lineage_id, s.grp, s.initial_state FROM lineages l JOIN lineage_state s ON s.lineage_id = l.id '
    + 'WHERE l.package_id = ? ORDER BY s.lineage_id, s.grp',
  events: 'SELECT e.lineage_id, e.grp, e.ord, e.version, e.published_s, e.after_state FROM lineages l '
    + 'JOIN events e ON e.lineage_id = l.id WHERE l.package_id = ? ORDER BY e.lineage_id, e.ord, e.grp',
  spine: 'SELECT s.lineage_id, s.ord, s.version, s.published_s, s.size_bytes, s.tool_key, s.shasum, s.capture_class '
    + 'FROM lineages l JOIN spine s ON s.lineage_id = l.id WHERE l.package_id = ? ORDER BY s.lineage_id, s.ord',
};
const LOAD_RAW = new Set(['lineages', 'lineagesRl2', 'links', 'states', 'events', 'spine']);
// column positions of the raw rows, in LOAD_SQL's SELECT order
const LOAD_COLS = {
  lineages: { id: 0, lineage_key: 1, n_versions: 2, first_published_s: 3, last_published_s: 4, tag_family: 5 },
  links: { lineage_id: 0, ord: 1, pred_lineage_id: 2, pred_ord: 3, pred_version: 4, pred_size_bytes: 5, pred_tool_key: 6 },
  states: { lineage_id: 0, grp: 1, initial_state: 2 },
  events: { lineage_id: 0, grp: 1, ord: 2, version: 3, published_s: 4, after_state: 5 },
  spine: { lineage_id: 0, ord: 1, version: 2, published_s: 3, size_bytes: 4, tool_key: 5, shasum: 6, capture_class: 7 },
};
const LOAD_STATEMENTS = new WeakMap();
function loadStatement(db, key) {
  let m = LOAD_STATEMENTS.get(db);
  if (!m) { m = new Map(); LOAD_STATEMENTS.set(db, m); }
  let st = m.get(key);
  if (!st) {
    if (key === 'package') {
      try { st = db.prepare(LOAD_SQL.package); } catch { st = loadStatement(db, 'packageLegacy'); }   // no seed_metadata
    } else if (key === 'rl1') {
      try { st = db.prepare(LOAD_SQL.rl1); } catch (e) { throw new RL.ReadLayoutError(`declared, but ${RL.RL1_TABLE} is unreadable (${e.message})`); }
    } else { st = db.prepare(LOAD_SQL[key]); if (LOAD_RAW.has(key)) st.raw(true); }
    m.set(key, st);
  }
  return st;
}
/**
 * Whether this seed has the rl2 layout (contract 1.2: `lineages.tag_family`), decided once per handle by COMPILING the rl2
 * lineage statement (no execution, so a package load still runs a constant number of statements; a legacy seed adds none).
 */
const RL2_LAYOUT = new WeakMap();
function hasRl2(db) {
  let v = RL2_LAYOUT.get(db);
  if (v === undefined) {
    try { db.prepare(LOAD_SQL.lineagesRl2); v = true; } catch { v = false; }
    RL2_LAYOUT.set(db, v);
  }
  return v;
}
const isFlat = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
  && Object.values(v).every((x) => x === null || typeof x !== 'object');
/** Initial states of a g10-rl1 package, one function call per lineage in `ord` order (see LOAD_SQL). */
function rl1States(d, lineageIds) {
  const { groups, texts, idx } = RL.decodeRow(d, lineageIds);
  const tpl = new Array(texts.length); const flat = new Array(texts.length);
  let i = 0;
  return () => {
    const x = idx[i]; i += 1;
    const initial = {};
    for (let k = 0; k < groups.length; k += 1) {
      const j = x[k + 1];
      if (tpl[j] === undefined) {          // first use: parsed here, as the canonical row would have been
        const v = JSON.parse(texts[j]); tpl[j] = v; flat[j] = isFlat(v); initial[groups[k]] = v;
      } else initial[groups[k]] = flat[j] ? { ...tpl[j] } : JSON.parse(texts[j]);
    }
    return initial;
  };
}
function byLineage(rows) {
  const out = new Map();
  for (const r of rows) {
    let a = out.get(r[0]);                 // column 0 of every bulk statement is the lineage id
    if (!a) { a = []; out.set(r[0], a); }
    a.push(r);
  }
  return out;
}
const NONE = Object.freeze([]);

function loadPackage(db, packageName, seedMeta) {
  const row = loadStatement(db, 'package').get(packageName);
  if (!row) return null;
  const pv = { package_id: row.id, package_name: row.package_name, lineages: new Map(), seed_meta: seedMeta };
  const rl2 = hasRl2(db);
  const lrows = loadStatement(db, rl2 ? 'lineagesRl2' : 'lineages').all(pv.package_id);
  const L = LOAD_COLS.lineages; const S = LOAD_COLS.states; const E = LOAD_COLS.events; const P = LOAD_COLS.spine;
  const X = LOAD_COLS.links;
  const linkRows = rl2 ? byLineage(loadStatement(db, 'links').all(pv.package_id)) : null;
  const layout = row.read_layout ?? null;
  if (layout !== null && layout !== RL.RL1) throw new RL.ReadLayoutError(`unknown read layout ${JSON.stringify(layout)}`);
  const d = layout !== null && lrows.length >= RL.RL1_MIN_LINEAGES ? loadStatement(db, 'rl1').get(pv.package_id) : undefined;
  const derived = d === undefined ? null : rl1States(d, lrows.map((l) => l[L.id]));
  const states = derived === null ? byLineage(loadStatement(db, 'states').all(pv.package_id)) : null;
  const evRows = byLineage(loadStatement(db, 'events').all(pv.package_id));
  const spRows = byLineage(loadStatement(db, 'spine').all(pv.package_id));
  for (const l of lrows) {
    const id = l[L.id];
    let initial;
    if (derived !== null) initial = derived();
    else { initial = {}; for (const s of states.get(id) || NONE) initial[s[S.grp]] = JSON.parse(s[S.initial_state]); }
    const events = (evRows.get(id) || NONE).map((e) => ({
      grp: e[E.grp], ord: e[E.ord], version: e[E.version], published_s: e[E.published_s], after: JSON.parse(e[E.after_state]),
    }));
    const spine = new Map();
    for (const s of spRows.get(id) || NONE) {
      const sh = s[P.shasum];
      spine.set(s[P.ord], {
        version: s[P.version], published_s: s[P.published_s], size_bytes: s[P.size_bytes], tool_key: s[P.tool_key],
        shasum: Buffer.isBuffer(sh) ? sh.toString('hex') : sh, capture_class: s[P.capture_class],
      });
    }
    // rl2: a cross-link per ord whose predecessor is not this chain's previous row; it carries the predecessor's spine
    // fields because later rows of that row's own chain can push it out of the K tail. A 1.1 seed: one family, no links.
    const crossLinks = new Map();
    for (const x of (linkRows && linkRows.get(id)) || NONE) {
      crossLinks.set(x[X.ord], { pred_lineage_id: x[X.pred_lineage_id], pred_ord: x[X.pred_ord], version: x[X.pred_version],
        size_bytes: x[X.pred_size_bytes], tool_key: x[X.pred_tool_key] });
    }
    pv.lineages.set(id, new LineageView({
      lineage_id: id, lineage_key: l[L.lineage_key], n_versions: l[L.n_versions],
      first_published_s: l[L.first_published_s], last_published_s: l[L.last_published_s], initial, events, spine,
      tag_family: rl2 ? l[L.tag_family] : 'release', cross_links: crossLinks,
    }));
  }
  return pv;
}

/**
 * [predecessor's lineage, its ord, its spine fields or null beyond the tail], or null for a cold start. The seed side's
 * checker.py `_predecessor`: a live candidate (ord null) extends the tip of its lineage (placement puts it on the chain
 * whose tip IS its predecessor); a recorded row takes its cross-link when it has one, else the previous row of its chain.
 */
function predecessorOf(pv, lv, c) {
  if (c.ord === null || c.ord === undefined) {
    const po = lv.n_versions - 1;
    return po >= 0 ? [lv, po, lv.spine.get(po) || null] : null;
  }
  const link = lv.cross_links ? lv.cross_links.get(c.ord) : undefined;
  if (link !== undefined) {
    const plv = pv.lineages.get(link.pred_lineage_id);
    const srow = plv.spine.get(link.pred_ord) || { version: link.version, size_bytes: link.size_bytes, tool_key: link.tool_key };
    return [plv, link.pred_ord, srow];
  }
  if (c.ord - 1 < 0) return null;
  return [lv, c.ord - 1, lv.spine.get(c.ord - 1) || null];
}

// ---------------------------------------------------------------------------
// Channel-A (lineage predecessor)
// ---------------------------------------------------------------------------
function channelA(pv, c) {
  const lv = pv.lineages.get(c.lineage_id) || null;
  const groups = {}; const constituents = {};
  let predVersion = null;

  if (lv === null) {
    for (const gname of K.CHANNEL_A_GROUPS) groups[gname] = K.unknown(K.UNCOVERED_PACKAGE);
    for (const cn of K.PUBLISHER_CONSTITUENTS) constituents[cn] = K.unknown(K.UNCOVERED_PACKAGE);
  } else {
    const located = predecessorOf(pv, lv, c);
    if (located === null) {
      for (const gname of K.CHANNEL_A_GROUPS) groups[gname] = K.unknown(K.COLD_START);
      for (const cn of K.PUBLISHER_CONSTITUENTS) constituents[cn] = K.unknown(K.COLD_START);
    } else {
      // the predecessor's state comes from ITS lineage's own walk (a cross-link may name another chain)
      const [plv, predOrd, srow] = located;
      const pub = plv.stateAt('publisher', predOrd);
      const prov = plv.stateAt('provenance', predOrd);
      const ins = plv.stateAt('install', predOrd);
      const git = plv.stateAt('git', predOrd);
      predVersion = srow ? srow.version : null;

      const pId = g(pub, 'identity_digest'); const cId = c.identity_digest;
      constituents.identity = (pId === null || cId === null)
        ? K.unknown(K.UNSUPPORTED_FIELD, { predecessor_identity_present: pId !== null, candidate_identity_present: cId !== null })
        : K.known(pId !== cId, { predecessor: pId.slice(0, 16), candidate: cId.slice(0, 16) });

      const pM = g(pub, 'maint_digest') || ''; const cM = c.maint_digest || '';
      constituents.maintainers = !pM
        ? K.unknown(K.UNSUPPORTED_FIELD, { predecessor_maint_digest_empty: true })
        : K.known(pM !== cM, { predecessor: pM.slice(0, 16), candidate: cM ? cM.slice(0, 16) : '', candidate_empty: !cM });

      const pName = g(pub, 'tool_name') || '';
      if (!pName || !c.tool_name) {
        constituents.tool_downgrade = K.known(false, { reason_note: 'tool name absent on one side: no break, no clear' });
      } else if (pName !== c.tool_name) {
        constituents.tool_downgrade = K.known(false, { predecessor_tool: pName, candidate_tool: c.tool_name });
      } else if (srow === null || srow.tool_key === null || srow.tool_key === undefined) {
        constituents.tool_downgrade = K.unknown(K.BEYOND_SPINE, { predecessor_ord: predOrd });
      } else {
        constituents.tool_downgrade = K.known(c.tool_key < srow.tool_key,
          { predecessor_tool_key: srow.tool_key, candidate_tool_key: c.tool_key });
      }
      groups.publisher = K.publisherGroup(constituents);

      groups.provenance = K.known(Boolean(g(prov, 'present')) && !c.provenance_present,
        { predecessor_present: Boolean(g(prov, 'present')), candidate_present: c.provenance_present });
      groups.install = K.known(!Boolean(g(ins, 'has_scripts')) && c.has_scripts,
        { predecessor_has_scripts: Boolean(g(ins, 'has_scripts')), candidate_has_scripts: c.has_scripts });
      groups.git = K.known(Boolean(g(git, 'head_present')) && !c.head_present, {
        predecessor_head_present: Boolean(g(git, 'head_present')), candidate_head_present: c.head_present,
        repo_digest_changed: g(git, 'repo_digest') !== c.repo_digest,
      });

      const psize = srow === null ? null : srow.size_bytes;
      if (srow === null || psize === null || psize === undefined || psize <= 0) {
        groups.size = K.unknown(srow === null ? K.BEYOND_SPINE : K.UNSUPPORTED_FIELD, { predecessor_ord: predOrd });
      } else if (c.size_bytes === null) {
        groups.size = K.unknown(K.UNSUPPORTED_FIELD, { candidate_size_missing: true });
      } else {
        groups.size = K.known(
          c.size_bytes >= psize * (1 + K.SIZE_BREAK_FRACTION) || c.size_bytes <= psize * (1 - K.SIZE_BREAK_FRACTION),
          { predecessor_size: psize, candidate_size: c.size_bytes },
        );
      }
    }
  }

  const agg = K.aggregate(groups, [['critical', K.CHANNEL_A_T]], K.CHANNEL_A_GROUPS.length);
  // install_body: RECORDED evidence, never a group, never in N.
  let bodyRecorded = null;
  const located2 = lv === null ? null : predecessorOf(pv, lv, c);
  if (located2 !== null) {
    const prevBody = g(located2[0].stateAt('install', located2[1]), 'body_digest') || '';
    bodyRecorded = {
      predecessor_body_digest: prevBody.slice(0, 16),
      candidate_body_digest: (c.body_digest || '').slice(0, 16),
      changed: Boolean(prevBody) && Boolean(c.body_digest) && prevBody !== c.body_digest,
      counts_toward_n: false,
    };
  }
  const groupsOut = {}; for (const [k, v] of Object.entries(groups)) groupsOut[k] = v.asDict();
  const consOut = {}; for (const [k, v] of Object.entries(constituents)) consOut[k] = v.asDict();
  return { predecessor_version: predVersion, groups: groupsOut, publisher_constituents: consOut,
    install_body: bodyRecorded, ...agg };
}

// ---------------------------------------------------------------------------
// DAC trajectory (package-wide, strictly prior)
// ---------------------------------------------------------------------------
function priorStates(pv, c, grp) {
  const prior = []; const ambiguous = [];
  for (const [lid, lv] of pv.lineages) {
    for (const [startOrd, startS, st] of lv.segmentStarts(grp)) {
      if (lid === c.lineage_id) {
        const candOrd = c.ord === null ? lv.n_versions : c.ord;
        if (startOrd < candOrd) prior.push(st);
      } else if (c.published_s === null || startS === null) {
        ambiguous.push(st);
      } else if (startS < c.published_s) {
        prior.push(st);
      } else if (startS === c.published_s) {
        ambiguous.push(st);
      }
    }
  }
  return [prior, ambiguous];
}

function hasPriorVersion(pv, c) {
  let certain = false; let ambiguous = false;
  for (const [lid, lv] of pv.lineages) {
    if (lid === c.lineage_id) {
      const candOrd = c.ord === null ? lv.n_versions : c.ord;
      if (candOrd > 0) certain = true;
    } else if (c.published_s === null) {
      ambiguous = true;
    } else if (lv.first_published_s < c.published_s) {
      certain = true;
    } else if (lv.first_published_s === c.published_s) {
      ambiguous = true;
    }
  }
  return [certain, ambiguous];
}

function everTrue(pv, c, grp, key) {
  const [prior, ambiguous] = priorStates(pv, c, grp);
  if (prior.some((st) => Boolean(g(st, key)))) return K.known(true);
  if (ambiguous.some((st) => Boolean(g(st, key)))) {
    return K.unknown(K.AMBIGUOUS_ORDER, { note: `a tie in stored publication time could add a prior ${grp}.${key}` });
  }
  return K.known(false);
}

function sizeReferenceCandidates(pv, c) {
  const visible = [];      // [published_s, lineage_id, ord, size]
  const equalTime = [];
  const bounds = [];
  for (const [lid, lv] of pv.lineages) {
    const own = lid === c.lineage_id;
    const candOrd = own ? (c.ord === null ? lv.n_versions : c.ord) : null;
    for (const [o, r] of lv.spine) {
      const size = r.size_bytes || 0;
      if (own) {
        if (o < candOrd && size > 0) visible.push([r.published_s, lid, o, size]);
        continue;
      }
      if (c.published_s === null || r.published_s === null) {
        if (size > 0) equalTime.push(size);
        continue;
      }
      if (r.published_s < c.published_s && size > 0) visible.push([r.published_s, lid, o, size]);
      else if (r.published_s === c.published_s && size > 0) equalTime.push(size);
    }
    const mso = lv.minSpineOrd;
    if (mso !== null && mso > 0) {
      let hidesPrior;
      if (own) hidesPrior = candOrd > 0;
      else if (c.published_s === null || lv.first_published_s === null) hidesPrior = true;
      else if (lv.first_published_s < c.published_s) hidesPrior = true;
      else hidesPrior = false;       // every version of this lineage is at or after the candidate
      if (hidesPrior) bounds.push(lv.spine.get(mso).published_s);
    }
  }
  if (!visible.length && !equalTime.length) {
    const [hasPrior] = hasPriorVersion(pv, c);
    if (!hasPrior) return [[], K.ZERO_HISTORY];
    return [[], bounds.length ? K.BEYOND_SPINE : K.UNSUPPORTED_FIELD];
  }
  const maxS = visible.length ? Math.max(...visible.map((r) => r[0])) : null;
  if (visible.length && bounds.length && maxS <= Math.max(...bounds)) return [[], K.BEYOND_SPINE];
  const sizes = [];
  if (visible.length) {
    const tied = visible.filter((r) => r[0] === maxS);
    if (new Set(tied.map((r) => r[1])).size > 1) {
      for (const r of tied) sizes.push(r[3]);               // different lineages, same stored second
    } else {
      sizes.push(tied.reduce((a, b) => (b[2] > a[2] ? b : a))[3]);   // same lineage: ord is authoritative
    }
  }
  sizes.push(...equalTime);
  return [[...new Set(sizes)].sort((a, b) => a - b), null];
}

function dac(pv, c) {
  const preds = {};
  let historyNote;
  if (c.published_s === null) {
    for (const p of K.DAC_PREDICATES) preds[p] = K.unknown(K.MISSING_PUBLICATION_TIME);
    historyNote = { prior_versions: null };
  } else {
    const [hasPrior, priorAmbiguous] = hasPriorVersion(pv, c);
    if (!hasPrior) {
      const reason = priorAmbiguous ? K.AMBIGUOUS_ORDER : K.ZERO_HISTORY;
      for (const p of K.DAC_PREDICATES) preds[p] = K.unknown(reason);
      historyNote = { prior_versions: 0, ambiguous: priorAmbiguous };
    } else {
      const everScripts = everTrue(pv, c, 'install', 'has_scripts');
      preds.install_introduced = everScripts.evaluable
        ? K.known(c.has_scripts && !everScripts.value) : K.unknown(everScripts.reason);
      const everProv = everTrue(pv, c, 'provenance', 'present');
      preds.prov_dropped = everProv.evaluable
        ? K.known(!c.provenance_present && Boolean(everProv.value)) : K.unknown(everProv.reason);

      const [priorSt, ambSt] = priorStates(pv, c, 'publisher');
      const priorTuples = new Set(priorSt.map((st) => g(st, 'tuple_digest')));
      const ambTuples = new Set(ambSt.map((st) => g(st, 'tuple_digest')));
      if (c.tuple_digest === null) {
        preds.first_pkg_appearance_new_publisher = K.unknown(K.UNSUPPORTED_FIELD, { candidate_tuple_missing: true });
      } else if (priorTuples.has(null)) {
        preds.first_pkg_appearance_new_publisher = K.unknown(K.UNSUPPORTED_FIELD, { prior_tuple_missing: true });
      } else if (priorTuples.has(c.tuple_digest)) {
        preds.first_pkg_appearance_new_publisher = K.known(false, { prior_tuple_count: priorTuples.size });
      } else if (ambTuples.has(c.tuple_digest)) {
        preds.first_pkg_appearance_new_publisher = K.unknown(K.AMBIGUOUS_ORDER);
      } else {
        preds.first_pkg_appearance_new_publisher = K.known(true, { prior_tuple_count: priorTuples.size });
      }

      const [sizes, why] = sizeReferenceCandidates(pv, c);
      if (why !== null) {
        preds.size_jump_5x = K.unknown(why);
      } else if (c.size_bytes === null) {
        preds.size_jump_5x = K.unknown(K.UNSUPPORTED_FIELD, { candidate_size_missing: true });
      } else {
        const outcomes = new Set(sizes.map((b) => c.size_bytes / b >= K.DAC_SIZE_JUMP_FACTOR));
        preds.size_jump_5x = outcomes.size === 1
          ? K.known([...outcomes][0], { reference_sizes: sizes, candidate_size: c.size_bytes })
          : K.unknown(K.AMBIGUOUS_ORDER, { reference_sizes: sizes, candidate_size: c.size_bytes });
      }
      historyNote = { prior_versions: '>=1', ambiguous: priorAmbiguous };
    }
  }
  const agg = K.aggregate(preds, [['surface', K.DAC_SURFACE_T], ['any', K.DAC_ANY_T]], K.DAC_PREDICATES.length);
  const out = {}; for (const [k, v] of Object.entries(preds)) out[k] = v.asDict();
  return { predicates: out, history: historyNote, ...agg };
}

/** The portable finding. No ALLOW/WARN/BLOCK: findings, evidence, counts and coverage only. */
function check(pv, c, seedMeta = null) {
  let ca; let dacOut;
  if (pv === null) {
    const na = {}; const nd = {}; const cons = {};
    for (const gname of K.CHANNEL_A_GROUPS) na[gname] = K.unknown(K.UNCOVERED_PACKAGE);
    for (const p of K.DAC_PREDICATES) nd[p] = K.unknown(K.UNCOVERED_PACKAGE);
    for (const cn of K.PUBLISHER_CONSTITUENTS) cons[cn] = K.unknown(K.UNCOVERED_PACKAGE).asDict();
    const ga = {}; for (const [k, v] of Object.entries(na)) ga[k] = v.asDict();
    const pa = {}; for (const [k, v] of Object.entries(nd)) pa[k] = v.asDict();
    ca = { predecessor_version: null, groups: ga, publisher_constituents: cons, install_body: null,
      ...K.aggregate(na, [['critical', K.CHANNEL_A_T]], K.CHANNEL_A_GROUPS.length) };
    dacOut = { predicates: pa, history: { prior_versions: null },
      ...K.aggregate(nd, [['surface', K.DAC_SURFACE_T], ['any', K.DAC_ANY_T]], K.DAC_PREDICATES.length) };
  } else {
    ca = channelA(pv, c); dacOut = dac(pv, c);
  }
  const binding = seedMeta !== null ? seedMeta : (pv !== null ? pv.seed_meta : {});
  return {
    contract_version: K.CONTRACT_VERSION,
    timestamp_precision: K.TIMESTAMP_PRECISION,
    candidate: { package: c.package_name, version: c.version, published_s: c.published_s,
      lineage_id: c.lineage_id, ord: c.ord, candidate_digest: c.identity_digest, provider_class: c.provider_class },
    corpus_context: 'unavailable',
    channel_a: ca,
    dac_trajectory: dacOut,
    seed: { ...binding },
  };
}

export { loadSeedMeta, loadPackage, check, channelA, dac, LineageView, predecessorOf,
  priorStates, hasPriorVersion, everTrue, sizeReferenceCandidates, SEED_BINDING_KEYS };


// A default export as well: the consumer is used both as `import R from` and
// `import { verify } from`, and the runtime package is ESM.
export default { loadSeedMeta, loadPackage, check, channelA, dac, LineageView, predecessorOf, priorStates,
  hasPriorVersion, everTrue, sizeReferenceCandidates, SEED_BINDING_KEYS
};