// 0.1.4 group 2c (D-R1, O3, E19): what this proxy served and refused, per install, held in memory only. `chaingate
// report` reads it through `GET /_chaingate/report`; the log is never its source, so an exhausted log budget or a
// deduplicated line changes nothing here (G2c-9).
//
// One install = one `npm-session` header value (npm sends a fresh one per invocation), else a client's requests until it
// is idle for 60 s. Bounded: at most 20 installs (the least recently active is evicted) and 2,000 events per install.
// When an install is full, ordinary events give way first: an incoming ordinary event is dropped, an incoming important
// one (a named served, any refusal, a tag moved) evicts the oldest ordinary event, and only when none is left is an
// important event dropped. Every drop is counted, so the report can say it is incomplete.

const SESSION_RE = /^[A-Za-z0-9._-]{1,64}$/;
const MAX_TEXT = 1000;

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
const cap = (v) => (typeof v === 'string' && v.length > MAX_TEXT ? `${v.slice(0, MAX_TEXT)}…` : v);
const dedupKey = (e) => `${e.kind}|${e.package}@${e.version ?? ''}|${e.tag ?? ''}`;

export function createInstallSummary({ now = Date.now, maxInstalls = DEFAULTS.maxInstalls, maxEvents = DEFAULTS.maxEvents,
  idleMs = DEFAULTS.idleMs } = {}) {
  const installs = new Map();          // key -> install; Map order = least to most recently active
  const lastByClient = new Map();      // client -> key of its current idle-grouped install
  const stats = { installs_evicted: 0 };
  let clientSeq = 0;

  function keyFor({ session, client } = {}, t) {
    if (typeof session === 'string' && SESSION_RE.test(session)) return { key: `npm-session:${session}`, grouping: 'npm-session' };
    const who = typeof client === 'string' && client ? client : 'unknown';
    const current = lastByClient.get(who);
    const inst = current && installs.get(current);
    if (inst && t - inst.lastMs <= idleMs) return { key: current, grouping: 'client-idle', client: who };
    clientSeq += 1;
    const key = `client:${who}#${clientSeq}`;
    lastByClient.set(who, key);
    return { key, grouping: 'client-idle', client: who };
  }

  /**
   * Record one event for the install `who` belongs to. Returns { key, fresh, at }: fresh = the first such event (kind,
   * package@version, tag) in that install; at = the event's time.
   */
  function record(who, event) {
    const t = now();
    const { key, grouping, client } = keyFor(who, t);
    let inst = installs.get(key);
    if (inst) installs.delete(key);
    else {
      inst = { key, grouping, client, startedMs: t, lastMs: t, events: [], dropped: 0, dropped_important: 0, seen: new Set() };
      while (installs.size >= maxInstalls) {
        const [oldest, old] = installs.entries().next().value;
        installs.delete(oldest);
        if (old.client && lastByClient.get(old.client) === oldest) lastByClient.delete(old.client);
        stats.installs_evicted += 1;
      }
    }
    installs.set(key, inst);
    inst.lastMs = t;
    const e = { at: new Date(t).toISOString() };
    for (const [k, v] of Object.entries(event)) e[k] = cap(v);
    // `fresh` keys the disk record's once-per-install write (dated note 6.8). Bounded: past the cap every event counts as
    // fresh, so a flood can only duplicate a disk row, never lose one.
    const dk = dedupKey(e);
    const fresh = !inst.seen.has(dk);
    if (inst.seen.size < 4 * maxEvents) inst.seen.add(dk);
    if (inst.events.length >= maxEvents) {
      if (!isImportant(e)) { inst.dropped += 1; return { key, fresh, at: e.at }; }
      const i = inst.events.findIndex((x) => !isImportant(x));
      if (i < 0) { inst.dropped += 1; inst.dropped_important += 1; return { key, fresh, at: e.at }; }
      inst.events.splice(i, 1);
      inst.dropped += 1;
    }
    inst.events.push(e);
    return { key, fresh, at: e.at };
  }

  const view = (inst) => ({ key: inst.key, grouping: inst.grouping, started_at: new Date(inst.startedMs).toISOString(),
    last_at: new Date(inst.lastMs).toISOString(), dropped: inst.dropped, dropped_important: inst.dropped_important,
    events: inst.events.map((e) => ({ ...e })) });

  /** all: every install, least recently active first; otherwise the most recently active install with a tarball event. */
  function snapshot({ all = false } = {}) {
    const list = [...installs.values()];
    if (all) return { installs: list.map(view), stats: { ...stats } };
    const latest = list.reverse().find((i) => i.events.some(isTarballEvent));
    return { installs: latest ? [view(latest)] : [], stats: { ...stats } };
  }

  return { record, snapshot };
}

export default { createInstallSummary, isLoopbackPeer, isImportant, DEFAULTS };
