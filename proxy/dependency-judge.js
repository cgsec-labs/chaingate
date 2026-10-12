// 0.1.4 group 3b (D-N3, §18.20 item 2): N1h at TARBALL time. For the exact version npm downloads, the dependencies its
// stored `dependency-hooks` row left pending are fetched -- in parallel, all within one budget (5 s), the request's
// authorization relayed -- into the dependency cache, judged, and, when the judgement differs from the stored row, ONE new
// decision row is written: the applicable row's results with that row replaced, the disposition recomputed (any WARN ->
// WARN, else ALLOW; never over a BLOCK, which was refused before this point). A dependency that does not answer in time is
// not evaluable, with the reason; the tarball is served either way.
import { judge } from '../gates/dependency-hooks.js';
import { getDependency, setDependencyDoc } from '../gates/dependency-cache.js';

export const BUDGET_MS = 5_000;
const inflight = new Map();             // target -> promise (one fetch per target at a time)

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
  const work = targets.map((t) => {
    if (!inflight.has(t)) inflight.set(t, fetchOne(t, fetchPackument, opts).finally(() => inflight.delete(t)));
    return inflight.get(t);
  });
  let timer;
  await Promise.race([Promise.all(work), new Promise((r) => { timer = setTimeout(r, budgetMs); })]);
  clearTimeout(timer);
  // A late answer still fills the cache when it arrives; for THIS judgement it is not evaluable.
  return { timedOut: targets.filter((t) => getDependency(t) === undefined) };
}

const aggregate = (results) => (results.some((r) => r?.result === 'BLOCK') ? 'BLOCK'
  : (results.some((r) => r?.result === 'WARN') ? 'WARN' : 'ALLOW'));

/**
 * Judge the served version's pending N1h row at tarball time. Returns true when a new decision row was written.
 * `latest`: the applicable stored row (not a BLOCK).
 */
export async function judgeAtTarball({ db, pkg, version, latest, fetchPackument, config, authorization, budgetMs, log }) {
  const rows = Array.isArray(latest?.gates_fired) ? latest.gates_fired : [];
  const i = rows.findIndex((g) => g && g.gate === 'dependency-hooks');
  if (i < 0 || !Array.isArray(rows[i].pending) || !Array.isArray(rows[i].added)) return false;
  const { timedOut } = await fetchPending(rows[i].pending, { fetchPackument, config, authorization, budgetMs });
  const lookup = (t) => (timedOut.includes(t) ? { why: `no answer within ${Math.round((budgetMs ?? BUDGET_MS) / 1000)} s` } : getDependency(t));
  const row = judge(rows[i].added, { lookup });
  if (Array.isArray(row.pending)) return false;               // nothing could be judged (cache evicted mid-way): keep the stored row
  const results = rows.map((g, k) => (k === i ? row : g));
  const fresh = db.getLatestDecision(pkg, version);
  if (fresh && fresh.id !== latest.id) return false;           // a concurrent writer got there first
  db.insertGateDecision(pkg, version, aggregate(results), results);
  log?.info?.(`[n1h] ${pkg}@${version}: ${row.result} (${row.detail})`);
  return true;
}

export default { judgeAtTarball, fetchPending, BUDGET_MS };
