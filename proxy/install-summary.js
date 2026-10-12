// 0.1.4 group 2c (D-R1, O3, E19): what this proxy served and refused, per install, held in memory only. `chaingate
// report` reads it through `GET /_chaingate/report`; the log is never its source, so an exhausted log budget or a
// deduplicated line changes nothing here (G2c-9).
//
// One install = one `npm-session` header value (npm sends a fresh one per invocation), else a client's requests until it
// is idle for 60 s. Bounded: at most 20 installs (the least recently active is evicted) and 2,000 events per install.
// When an install is full, ordinary events give way first: an incoming ordinary event is dropped, an incoming important
// one (a named served, any refusal, a tag moved) evicts the oldest ordinary event, and only when none is left is an
// important event dropped. Every drop is counted, so the report can say it is incomplete. An install evicted and then
// heard from again is marked `evicted_earlier` (dated note 7.5).
//
// Disk writes are CLAIMED per install and disk event (`claimDisk`, dated note 7.1/7.3): never keyed by the install event,
// so a non-fact event can never use up the claim of a fact one. At most 500 disk rows per install; the rest are counted.

const SESSION_RE = /^[A-Za-z0-9._-]{1,64}$/;
const MAX_TEXT = 1000;
const MAX_DISK_PER_INSTALL = 500;
const MAX_EVICTED_KEYS = 1000;

export const DEFAULTS = Object.freeze({ maxInstalls: 20, maxEvents: 2000, idleMs: 60_000 });

/** Whether a peer address is loopback (dated note 6.9): 127.0.0.0/8, ::1, or IPv4-mapped 127.0.0.0/8. */
export function isLoopbackPeer(addr) {
  if (typeof addr !== 'string' || !addr) return false;
  if (addr === '::1') return true;
  const v4 = addr.startsWith('::ffff:') ? addr.slice(7) : addr;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v4);
}

/** Whether an event must survive ordinary ones when an install is full. */
export function isImportant(e) {
  return e.kind === 'refused' || e.kind === 'tag-moved' || (e.kind === 'served' && e.class === 'named');
}

const isTarballEvent = (e) => e.kind === 'served' || e.kind === 'refused';
/** Strings capped at every depth (dated note 7.14); arrays and objects copied. */
function capped(v, depth = 0) {
  if (typeof v === 'string') return v.length > MAX_TEXT ? `${v.slice(0, MAX_TEXT)}…` : v;
  if (depth > 4 || v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map((x) => capped(x, depth + 1));
  const out = {};
  for (const [k, x] of Object.entries(v)) out[k] = capped(x, depth + 1);
  return out;
}

export function createInstallSummary({ now = Date.now, maxInstalls = DEFAULTS.maxInstalls, maxEvents = DEFAULTS.maxEvents,
  idleMs = DEFAULTS.idleMs } = {}) {
  const installs = new Map();          // key -> install; Map order = least to most recently active
  const lastByClient = new Map();      // client -> key of its current idle-grouped install (held or recently evicted)
  const evicted = new Map();           // recently evicted key -> { lastMs, client }; bounded, insertion order = age
  const stats = { installs_evicted: 0 };
  let clientSeq = 0;

  function keyFor({ session, client } = {}, t) {
    if (typeof session === 'string' && SESSION_RE.test(session)) return { key: `npm-session:${session}`, grouping: 'npm-session' };
    const who = typeof client === 'string' && client ? client : 'unknown';
    const current = lastByClient.get(who);
    const lastMs = current && (installs.get(current)?.lastMs ?? evicted.get(current)?.lastMs);
    if (lastMs != null && t - lastMs <= idleMs) return { key: current, grouping: 'client-idle', client: who };
    clientSeq += 1;
    const key = `client:${who}#${clientSeq}`;
    lastByClient.set(who, key);
    return { key, grouping: 'client-idle', client: who };
  }

  function evictOldest() {
    const [oldest, old] = installs.entries().next().value;
    installs.delete(oldest);
    evicted.set(oldest, { lastMs: old.lastMs, client: old.client });
    while (evicted.size > MAX_EVICTED_KEYS) {
      const [k, v] = evicted.entries().next().value;
      evicted.delete(k);
      if (v.client && lastByClient.get(v.client) === k) lastByClient.delete(v.client);
    }
    stats.installs_evicted += 1;
  }

  function installFor(who, t) {
    const { key, grouping, client } = keyFor(who, t);
    let inst = installs.get(key);
    if (inst) installs.delete(key);
    else {
      const wasEvicted = evicted.delete(key);
      inst = { key, grouping, client, startedMs: t, lastMs: t, events: [], dropped: 0, dropped_important: 0,
        evicted_earlier: wasEvicted, disk: new Set(), disk_suppressed: 0 };
      while (installs.size >= maxInstalls) evictOldest();
    }
    installs.set(key, inst);
    inst.lastMs = t;
    return inst;
  }

  /** Record one event for the install `who` belongs to. Returns { key, at }: the install's key and the event's time. */
  function record(who, event) {
    const t = now();
    const inst = installFor(who, t);
    const e = { at: new Date(t).toISOString(), ...capped(event) };
    if (inst.events.length >= maxEvents) {
      if (!isImportant(e)) { inst.dropped += 1; return { key: inst.key, at: e.at }; }
      const i = inst.events.findIndex((x) => !isImportant(x));
      if (i < 0) { inst.dropped += 1; inst.dropped_important += 1; return { key: inst.key, at: e.at }; }
      inst.events.splice(i, 1);
      inst.dropped += 1;
    }
    inst.events.push(e);
    return { key: inst.key, at: e.at };
  }

  /** The install `who` belongs to, touched without an event (a disk-only write). Returns { key, at }. */
  function touch(who) {
    const t = now();
    return { key: installFor(who, t).key, at: new Date(t).toISOString() };
  }

  /**
   * Claim the one disk write of `diskKey` (kind|package@version) for install `key`: true the first time, while the install
   * holds fewer than 500 claims; otherwise false (beyond the cap, counted). An install no longer held claims nothing.
   */
  function claimDisk(key, diskKey) {
    const inst = installs.get(key);
    if (!inst || inst.disk.has(diskKey)) return false;
    if (inst.disk.size >= MAX_DISK_PER_INSTALL) { inst.disk_suppressed += 1; return false; }
    inst.disk.add(diskKey);
    return true;
  }

  const view = (inst) => ({ key: inst.key, grouping: inst.grouping, started_at: new Date(inst.startedMs).toISOString(),
    last_at: new Date(inst.lastMs).toISOString(), dropped: inst.dropped, dropped_important: inst.dropped_important,
    evicted_earlier: inst.evicted_earlier, disk_suppressed: inst.disk_suppressed, events: inst.events.map((e) => ({ ...e })) });

  /** all: every install, least recently active first; otherwise the most recently active install with a tarball event. */
  function snapshot({ all = false } = {}) {
    const list = [...installs.values()];
    if (all) return { installs: list.map(view), stats: { ...stats } };
    const latest = list.reverse().find((i) => i.events.some(isTarballEvent));
    return { installs: latest ? [view(latest)] : [], stats: { ...stats } };
  }

  return { record, touch, claimDisk, snapshot };
}

export default { createInstallSummary, isLoopbackPeer, isImportant, DEFAULTS };
