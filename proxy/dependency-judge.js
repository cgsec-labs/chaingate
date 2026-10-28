// N1h at TARBALL time (since 0.1.4). For the exact version npm downloads, the dependencies its
// stored `dependency-hooks` row left pending are fetched -- in parallel, all within one budget (5 s), the request's
// authorization relayed -- into the dependency cache, judged, and, when the judgement differs from the stored row, ONE new
// decision row is written: the applicable row's results with that row replaced, the disposition recomputed (any WARN ->
// WARN, else ALLOW; never over a BLOCK, which was refused before this point). A dependency that does not answer in time is
// not evaluable, with the reason; the tarball is served either way.
import { judge } from '../gates/dependency-hooks.js';
import { getDependency, setDependencyDoc } from '../gates/dependency-cache.js';

export const BUDGET_MS = 5_000;
// At most MAX_IN_FLIGHT dependency fetches run in the process; the rest wait in
// line. A queued fetch whose every waiter's budget has passed is dropped unstarted. A running fetch is not aborted: the
// upstream timeouts bound it, and its answer still fills the cache.
export const MAX_IN_FLIGHT = 8;
const inflight = new Map();             // target -> { promise, deadline } (one fetch per target at a time)
const queue = [];
let active = 0;
function pump() {
  while (active < MAX_IN_FLIGHT && queue.length) {
    const job = queue.shift();
    if (Date.now() > job.entry.deadline) { job.done(); continue; }
    active += 1;
    fetchOne(job.target, job.fetchPackument, job.opts).finally(() => { active -= 1; job.done(); pump(); });
  }
}
function schedule(target, fetchPackument, opts, deadline) {
  const cur = inflight.get(target);
  if (cur) { cur.deadline = Math.max(cur.deadline, deadline); return cur.promise; }
  const entry = { deadline };
  entry.promise = new Promise((done) => { queue.push({ target, fetchPackument, opts, entry, done }); })
    .finally(() => { if (inflight.get(target) === entry) inflight.delete(target); });
  inflight.set(target, entry);
  pump();
  return entry.promise;
}

async function fetchOne(target, fetchPackument, opts) {
  try {
    const up = await fetchPackument(target, opts);
    if (up.statusCode !== 200) {
      try { await up.body.dump(); } catch { /* nothing to drain */ }
      setDependencyDoc(target, null, `upstream ${up.statusCode}`);
      return;
    }
    const doc = JSON.parse(Buffer.from(await up.body.arrayBuffer()).toString('utf8'));
    setDependencyDoc(target, doc && typeof doc === 'object' ? doc : null, 'not a JSON document');
  } catch (err) {
    setDependencyDoc(target, null, `fetch failed (${err.code ?? err.name ?? 'error'})`);
  }
}

/** Fetch the pending targets into the cache, all within `budgetMs`; a target still unanswered is marked timed out. */
export async function fetchPending(pending, { fetchPackument, config, authorization, budgetMs = BUDGET_MS }) {
  const targets = [...new Set(pending.map((d) => d.target))].filter((t) => getDependency(t) === undefined);
  const opts = { config, requestHeaders: authorization ? { authorization } : {} };
  const deadline = Date.now() + budgetMs;
  const work = targets.map((t) => schedule(t, fetchPackument, opts, deadline));
  let timer;
  await Promise.race([Promise.all(work), new Promise((r) => { timer = setTimeout(r, budgetMs); })]);
  clearTimeout(timer);
  // A late answer still fills the cache when it arrives; for THIS judgement it is not evaluable.
  return { timedOut: targets.filter((t) => getDependency(t) === undefined) };
}

const aggregate = (results) => (results.some((r) => r?.result === 'BLOCK') ? 'BLOCK'
  : (results.some((r) => r?.result === 'WARN') ? 'WARN' : 'ALLOW'));

const awaitsJudgement = (g) => g && g.gate === 'dependency-hooks' && Array.isArray(g.added) && (Array.isArray(g.pending) || g.result === 'SKIP');
const sameJudgement = (a, b) => a.result === b.result
  && String(a.detail).replace(/ \(judged [^)]*\)$/, '') === String(b.detail).replace(/ \(judged [^)]*\)$/, '');

/**
 * Judge the served version's pending or not-evaluable N1h row at tarball time. Returns 'wrote' (a new decision row),
 * 'raced' (a concurrent writer wrote first, twice, or its decision no longer awaits this judgement; re-read the record), or
 * false (nothing to judge, or the same judgement).
 * `latest`: the applicable stored row (the newest non-override row; not a BLOCK).
 */
export async function judgeAtTarball({ db, pkg, version, latest, fetchPackument, config, authorization, budgetMs, log }) {
  const rows = Array.isArray(latest?.gates_fired) ? latest.gates_fired : [];
  const i = rows.findIndex((g) => g && g.gate === 'dependency-hooks');
  // judged now: a pending row, or a not-evaluable SKIP (retried); a determinate judgement stands
  if (i < 0 || !awaitsJudgement(rows[i])) return false;
  // EVERY added target missing from the cache is fetched, not only the stored pending ones
  const { timedOut } = await fetchPending(rows[i].added, { fetchPackument, config, authorization, budgetMs });
  const lookup = (t) => (timedOut.includes(t) ? { why: `no answer within ${Math.round((budgetMs ?? BUDGET_MS) / 1000)} s` } : getDependency(t));
  const row = judge(rows[i].added, { lookup, unjudgeable: Array.isArray(rows[i].unjudgeable) ? rows[i].unjudgeable : [] });
  if (Array.isArray(row.pending)) return false;               // nothing could be judged (cache evicted mid-way): keep the stored row
  if (sameJudgement(row, rows[i])) return false;               // the same judgement: no new row
  // the guard compares like with like: `latest` is the newest NON-override row
  let base = latest;
  let retried = false;
  for (;;) {
    const fresh = db.getLatestNonOverrideDecision(pkg, version);
    if (!fresh || fresh.id === base.id) break;
    // Since 0.1.5: a concurrent writer got there first. Once per download, the same judgement goes on top of its
    // decision (every row of theirs kept), when that decision still awaits it for the same added dependencies and is not a
    // BLOCK; a second race, or anything else, leaves it to the caller's re-read and a later download, as before.
    if (retried || fresh.disposition === 'BLOCK') return 'raced';
    const have = Array.isArray(fresh.gates_fired) ? fresh.gates_fired : [];
    const k = have.findIndex((g) => g && g.gate === 'dependency-hooks');
    if (k < 0 || !awaitsJudgement(have[k]) || JSON.stringify(have[k].added) !== JSON.stringify(rows[i].added)) return 'raced';
    if (sameJudgement(row, have[k])) return 'raced';
    base = fresh;
    retried = true;
  }
  const have = Array.isArray(base.gates_fired) ? base.gates_fired : [];
  const at = have.findIndex((g) => g && g.gate === 'dependency-hooks');
  const results = have.map((g, k) => (k === at ? row : g));
  db.insertGateDecision(pkg, version, aggregate(results), results);
  log?.info?.(`[n1h] ${pkg}@${version}: ${row.result} (${row.detail})${retried ? ' (retried after a concurrent write)' : ''}`);
  return 'wrote';
}

export default { judgeAtTarball, fetchPending, BUDGET_MS, MAX_IN_FLIGHT };
