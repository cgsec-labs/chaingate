// 0.1.4 group 2d (D-U8, V2): one adjudication row per user action, with the version's applicable decision at that moment
// COPIED into it (classes, decision id, policy identity) -- never recomputed later.
import { classify, policyPrefix } from '../witness/row-class.js';

/** The applicable decision of (pkg, version) as the record holds it now (override not applied), and its classes. */
export function decisionSnapshot(db, pkg, version) {
  let app = null;
  try { app = version ? db.getApplicableDecision(pkg, version, { overrideLive: false }) : null; } catch { app = null; }
  const d = app?.block ?? app?.latest ?? null;
  if (!d) return { app, decision: null, decision_id: null, policy: null, classes: {} };
  const c = classify(d.gates_fired);
  return { app, decision: d, decision_id: d.id ?? null, policy: policyPrefix(d.gates_fired),
    classes: { disposition: app.disposition ?? d.disposition ?? null, named: c.named, contributing: c.contributing, facts: c.facts } };
}

const ciFlag = (env) => Boolean(env.CI) && !['0', 'false'].includes(String(env.CI).toLowerCase());

/** Append one adjudication. `snapshot` from decisionSnapshot (taken BEFORE the action changes anything). */
export function adjudicate(db, { action, pkg, version = null, k = null, snapshot }, env = process.env) {
  return db.appendAdjudication({ action, package_name: pkg, version, k_version: k, classes: snapshot?.classes ?? {},
    decision_id: snapshot?.decision_id ?? null, policy_version: snapshot?.policy ?? null,
    interactive: Boolean(process.stdin.isTTY && process.stdout.isTTY), ci: ciFlag(env) });
}

/** `<pkg>@<version>` split at the last '@' (scoped names keep their leading '@'), or null. */
export function parseTarget(target) {
  if (typeof target !== 'string' || !target) return null;
  const at = target.lastIndexOf('@');
  if (at <= 0) return null;
  return { name: target.slice(0, at), version: target.slice(at + 1) };
}

export default { decisionSnapshot, adjudicate, parseTarget };
