// 0.1.4 group 2a — the enumerated differences E6, E7, E10, E11 (decision tables
// ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G2-TIER0-20261011.md §2) applied to a COPY of a frozen golden. Derived from
// the golden's own frozen decision rows, never from runtime output:
//   E6  a `seed-v3:dac-trajectory:any` WARN row is NOTE, its parenthetical replaced by the contributing text;
//   E7  where E6 changed a row, the disposition is the D1 aggregate of the rows again (the row was WARN, so the old
//       disposition was the aggregate: the finding was evaluated);
//   E10 the gate detail's bearing list follows the new disposition, and NOTE rows follow it as `| also (contributing): …`;
//   E11 the GateResult carries `rows: [{gate, result}]` (every golden, changed or not).
export const ANY = 'seed-v3:dac-trajectory:any';
export const OLD_TEXT = '(threshold over history: warns, never blocks — D1)';
export const CONTRIB_TEXT = '(contributing in cft-policy-1.2: shown beside a named row, never a warning on its own)';

const aggregate = (rows) => (rows.some((x) => x.result === 'BLOCK') ? 'BLOCK'
  : rows.some((x) => x.result === 'WARN') ? 'WARN' : 'ALLOW');
const whyOf = (disposition, rows) => {
  const bearing = rows.filter((x) => x.result === disposition);
  return { bearing, why: (bearing.length ? bearing : rows).map((x) => `${x.gate}: ${x.detail}`).join(' | ') };
};

/** E6/E7 on a decision. Returns { decision, changed }. */
export function decisionG2a(decision) {
  const d = structuredClone(decision);
  let changed = false;
  for (const x of d.results || []) {
    if (x.gate === ANY && x.result === 'WARN') {
      if (!x.detail.includes(OLD_TEXT)) throw new Error(`golden any-row text unexpected: ${x.detail}`);
      x.result = 'NOTE'; x.detail = x.detail.replace(OLD_TEXT, CONTRIB_TEXT); changed = true;
    }
  }
  if (changed) d.disposition = aggregate(d.results);
  return { decision: d, changed };
}

/** E6/E7/E10/E11 on a golden record whose decision and gate_result are already at the current policy prefix. */
export function recordG2a(g, policyPrefix) {
  const out = structuredClone(g);
  if (!out.decision) return { record: out, changed: false };
  const before = out.decision;
  const { decision, changed } = decisionG2a(before);
  out.decision = decision;
  if (out.gate_result) {
    const gr = out.gate_result;
    if (changed) {
      const head = `${policyPrefix}: `;
      const old = whyOf(before.disposition, before.results);
      if (!gr.detail.startsWith(head + old.why)) throw new Error(`golden gate detail does not start with its bearing rows: ${g.id}`);
      const suffix = gr.detail.slice((head + old.why).length);
      const now = whyOf(decision.disposition, decision.results);
      const also = now.bearing.length ? decision.results.filter((x) => x.result === 'NOTE')
        .map((x) => ` | also (contributing): ${x.gate}: ${x.detail}`).join('') : '';
      gr.result = decision.disposition;
      gr.detail = `${head}${now.why}${also}${suffix}`;
    }
    // E11, every record with a decision: the rows member, in the decision's order (inserted after `result`, as built)
    out.gate_result = { gate: gr.gate, result: gr.result, rows: decision.results.map((x) => ({ gate: x.gate, result: x.result })),
      detail: gr.detail };
  }
  return { record: out, changed };
}

/**
 * E6/E7 as they reach an explain-2 EVALUATED explanation (the renderer is unchanged; its input rows changed): the header
 * action, the disposition line, the "decided by" block (rows whose result equals the new disposition), the `any` line
 * under "all results", and structured disposition / effective / decided_by / results. Nothing else.
 */
export function explanationG2a(ex) {
  const s = ex.structured;
  if (s.result !== 'evaluated') return { explanation: ex, changed: false };
  const { decision: nd, changed } = decisionG2a({ disposition: s.disposition, results: s.results });
  if (!changed) return { explanation: ex, changed: false };
  const out = structuredClone(ex);
  const os = out.structured;
  const oldAny = s.results.find((x) => x.gate === ANY);
  const newAny = nd.results.find((x) => x.gate === ANY);
  const bearing = nd.results.filter((x) => x.result === nd.disposition);
  os.results = nd.results;
  os.disposition = nd.disposition;
  if (os.effective.basis === 'evaluation') os.effective.action = nd.disposition;
  os.decided_by = bearing.map((x) => ({ gate: x.gate, detail: x.detail }));
  const t = out.text;
  if (os.effective.basis === 'evaluation') t[0] = t[0].replace(new RegExp(`: ${s.disposition}$`), `: ${nd.disposition}`);
  const di = t.findIndex((l) => l.startsWith('  evaluated disposition: '));
  t[di] = t[di].replace(`evaluated disposition: ${s.disposition} `, `evaluated disposition: ${nd.disposition} `);
  const from = t.indexOf('  decided by:');
  const to = t.indexOf('  all results:');
  t.splice(from + 1, to - from - 1, ...bearing.map((x) => `    ${x.gate}: ${x.detail}`));
  const ai = t.indexOf(`    [WARN] ${ANY}: ${oldAny.detail}`);
  if (ai < 0) throw new Error('explanation lacks the any line');
  t[ai] = `    [NOTE] ${ANY}: ${newAny.detail}`;
  return { explanation: out, changed: true };
}
