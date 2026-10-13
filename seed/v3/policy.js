// CFT-05 — the POLICY contract. Versioned SEPARATELY from the detection contract, and deliberately
// so: detection says what was observed, policy says what to do about it, and the two move at
// different speeds. A finding carries evidence and coverage and NO disposition (CFT-03 D, LOCKED).
// This module is the only place where evidence becomes an action, it never writes back into a
// finding, and nothing in the detection path imports it.
//
// WHAT IS ALREADY LOCKED, and therefore is not re-decided here
// ------------------------------------------------------------
// The shipped pilot (`gates/index.js`, D1) fixes the shape and the arithmetic:
//
//   * four per-gate result values: ALLOW / SKIP / WARN / BLOCK, and three dispositions:
//     ALLOW / WARN / BLOCK;
//   * aggregation: any BLOCK -> BLOCK, else any WARN -> WARN, else ALLOW. SKIP does not count and
//     never escalates;
//   * N-warnings-escalate-to-BLOCK was REMOVED to prevent cry-wolf, so a pattern-derived signal
//     warns and does not block;
//   * "any BLOCK in results is a true-positive-by-construction signal" — a BLOCK must rest on a
//     recorded fact about this exact artifact, not on an inference from history;
//   * an override short-circuits to ALLOW without running anything;
//   * insufficient history is SKIP (first-seen poisoning protection), not a pass and not a block.
//
// Channel-A and the DAC trajectory are both threshold-over-history rules — inference, not recorded
// fact — so under the locked criterion they WARN. A `known_malicious_pins` row is the other kind:
// it names this package at this exact version in a recorded advisory, which is what
// true-positive-by-construction means, so it blocks on the same criterion that lets content-hash
// block. Neither of those is an open choice; both follow from rules already in force.
//
// WHAT IS GENUINELY OPEN, and therefore is NOT decided here
// ---------------------------------------------------------
// Two questions the pilot never had to answer, because it had no notion of an evidence artifact
// that could be untrustworthy or silent:
//
//   on_unusable_input   the seed was refused, or the candidate was rejected. There is NO finding.
//   on_no_evidence      a finding exists but nothing in it was evaluated (an uncovered package, a
//                       cold start, a stale seed).
//
// D1's fail-open covers ONE broken gate among several that still produced evidence. Extending it to
// "the whole evidence source is unusable" would be a new policy, and inventing it here is exactly
// the move that turns missing evidence into a clean result. So this module REFUSES TO DECIDE until
// an operator sets them, and says which ones are unset. A refusal to decide is not an ALLOW.

//
// CFT-POLICY-1.1 (U-05, D4). One change of substance, and it follows from the criterion above rather than adding a
// new one: a recorded advisory naming this exact version is a fact about the ARTIFACT, not about the input, so it
// stands on the unusable-input paths too. Under 1.0 every refusal and contract mismatch decided from
// `on_unusable_input` alone and never consulted the pin -- under WARN a known-malicious version was only warned about,
// and under BLOCK the decision named the input instead of the advisory. Under 1.1 the pin row comes first and the
// input row stays beside it. A pin lookup that FAILS is recorded (`not_evaluated` policy/pin_lookup) and the input
// rule decides; it is never read as "no advisory". Everything else in the decision table is unchanged.
//
// CFT-POLICY-1.2 (0.1.4; identity allocated by the operator, release doc r3 §18.5 item 3). I1 moves the identity
// before any 0.1.4 change to the decision record, with nothing else changed (decision tables
// 0.1.4-IMPL-DECISION-TABLES-I1-A8-20261011.md, T-2' E1/E2). Each later 0.1.4 change is enumerated there.
import K from './contract.js';

const POLICY_CONTRACT_VERSION = 'cft-policy-1.2';
const PIN_GATE = 'seed-v3:known-malicious-pin';
// The seed contract whose pins are keyed by package name (reader.js SEED_CONTRACT_1_1). A literal here, not an import:
// policy.js imports nothing from the detection path.
const PIN_BY_NAME_SEED_CONTRACT = 'cft-seed-v3-contract-1.1';
const IMPLEMENTED_DETECTION_CONTRACT = K.CONTRACT_VERSION;

const ALLOW = 'ALLOW';
const WARN = 'WARN';
const BLOCK = 'BLOCK';
const SKIP = 'SKIP';
// cft-policy-1.2 (0.1.4 group 2a, D-N1): a ROW value, "a contributing signal fired". Never a disposition: aggregate()
// counts only BLOCK and WARN, so a NOTE row can never make a WARN on its own (r3 §18.7, §18.15).
const NOTE = 'NOTE';
const DISPOSITIONS = Object.freeze([ALLOW, WARN, BLOCK]);
// The 1.2 role of the threshold rows (r3 §18.18: the seed strict tier is named; the loose `any` rule contributes).
// A new identity changes these deliberately; test/seed-v3/cft014-g2a-contributing.test.js guards them.
const NAMED_ROWS = Object.freeze(['seed-v3:channel-a:critical', 'seed-v3:dac-trajectory:surface']);
const CONTRIBUTING_ROWS = Object.freeze(['seed-v3:dac-trajectory:any']);
// 0.1.4 group 3a (D-T2): the D1 runner's NAMED gates -- a top-level runner row of one of these with result WARN is a named
// warning, exactly like a NAMED_ROWS entry (r3 §18.7 item 2, §18.11). 3b and 3c add their gates here.
// 0.1.5 group 1 (operator ruling 2026-10-13, chaingate-ops handover §7.3): T1.4 size-jump-provenance is named -- measured at
// 0.020 % of 24.15M corpus versions against its lineage predecessor, +8 established labelled packages beyond 0.1.4's named set.
const NAMED_RUNNER_GATES = Object.freeze(['install-introduced', 'dependency-hooks', 'install-manifest-mismatch', 'size-jump-provenance']);
// Every row name this policy emits (the closed vocabulary of the seed-v3 GateResult's `rows` member, D-N4).
const POLICY_ROW_GATES = Object.freeze(['override', 'seed-v3:known-malicious-pin', 'seed-v3:input', 'seed-v3:channel-a',
  'seed-v3:channel-a:critical', 'seed-v3:dac-trajectory:surface', 'seed-v3:dac-trajectory:any', 'seed-v3:coverage']);
const ROW_RESULTS = Object.freeze([ALLOW, WARN, BLOCK, SKIP, NOTE]);

/** The two genuinely unlocked choices, with the values an operator may pick and what each means. */
const OPEN_CHOICES = Object.freeze({
  on_unusable_input: {
    question: 'The seed was refused or the candidate rejected, so no finding exists. What then?',
    values: {
      BLOCK: 'fail closed: treat an unusable evidence source as a reason to refuse the release',
      WARN: 'proceed, but never silently: the decision records that nothing was checked',
      REFUSE_TO_DECIDE: 'return no disposition at all and let the caller decide; the default',
    },
    why_open: 'D1 fails open for ONE broken gate among several that still produced evidence. It '
      + 'never ruled on the whole evidence source being unusable.',
  },
  on_no_evidence: {
    question: 'A finding exists but nothing in it was evaluated (uncovered package, cold start, '
      + 'stale seed). What then?',
    values: {
      WARN: 'surface it: a release nobody could check is not a release that checked out',
      ALLOW: 'treat absence of evidence as absence of a problem, as D1 does for a skipped gate',
      REFUSE_TO_DECIDE: 'return no disposition at all; the default',
    },
    why_open: 'D1 SKIPs a gate it cannot run and lets the rest decide. Here there is no rest.',
  },
});
const OPEN_CHOICE_KEYS = Object.freeze(Object.keys(OPEN_CHOICES));

class PolicyConfigInvalid extends Error {
  constructor(msg) { super(msg); this.name = 'PolicyConfigInvalid'; }
}

/**
 * Validate an operator's policy configuration. Unset is allowed and means "refuse to decide"; an
 * unrecognised key or value is not, because a typo must never read as a chosen policy.
 */
function normaliseConfig(config = {}) {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    throw new PolicyConfigInvalid('policy config must be an object');
  }
  const unknown = Object.keys(config).filter((k) => !(k in OPEN_CHOICES));
  if (unknown.length) {
    throw new PolicyConfigInvalid(`unknown policy choices [${unknown.sort().join(', ')}]; this `
      + `policy version has exactly [${OPEN_CHOICE_KEYS.join(', ')}]`);
  }
  const out = {};
  for (const k of OPEN_CHOICE_KEYS) {
    const v = config[k] === undefined ? 'REFUSE_TO_DECIDE' : config[k];
    if (!(v in OPEN_CHOICES[k].values)) {
      throw new PolicyConfigInvalid(`${k}=${JSON.stringify(v)} is not one of `
        + `[${Object.keys(OPEN_CHOICES[k].values).join(', ')}]`);
    }
    out[k] = v;
  }
  return out;
}

const r = (gate, result, detail) => ({ gate, result, detail });

const reasonOf = (err) => (err instanceof Error ? `${err.name}: ${err.message}` : String(err));
const pinBlockRow = (pin, pkg, version) => r(PIN_GATE, BLOCK,
  `recorded advisory ${pin.advisory_id} pins ${pkg}@${version}${pin.source ? ` (source ${pin.source})` : ''}`);
const pinFailedRow = (err) => r(PIN_GATE, SKIP,
  `advisory pin lookup FAILED (${reasonOf(err)}): whether an advisory names this version is NOT known`);
const pinLookupMissing = (err) => ({ where: 'policy', name: 'pin_lookup', reason: reasonOf(err) });
const inputResult = (choice) => (choice === 'BLOCK' ? BLOCK : (choice === 'WARN' ? WARN : SKIP));

/** D1's aggregation, unchanged: any BLOCK -> BLOCK, else any WARN -> WARN, else ALLOW. */
function aggregate(results) {
  if (results.some((x) => x.result === BLOCK)) return BLOCK;
  if (results.some((x) => x.result === WARN)) return WARN;
  return ALLOW;
}

/**
 * Every group and predicate a finding could not evaluate, with the reason it gives.
 *
 * When the caller states that Channel-A could not be PLACED, its reason replaces the checker's.
 * The checker reports `uncovered_package` whenever it cannot find the lineage, which is a false
 * statement about a package the seed covers; the caller knows which of the FU-2 outcomes actually
 * applies and says so. The finding itself is never rewritten -- this is policy's record, not the
 * detection contract's.
 */
function notEvaluated(finding, placement = null) {
  const out = [];
  const unplaced = placement && placement.channel_a_usable === false;
  const scan = (where, obj, override) => {
    for (const [name, tri] of Object.entries(obj || {})) {
      if (override) out.push({ where, name, reason: override, stated_by: 'placement' });
      else if (tri && tri.coverage !== K.EVALUATED) out.push({ where, name, reason: tri.reason ?? null });
    }
  };
  const channelAReason = unplaced ? (placement.reason || placement.kind) : null;
  scan('channel_a.group', finding.channel_a.groups, channelAReason);
  scan('channel_a.publisher_constituent', finding.channel_a.publisher_constituents, channelAReason);
  scan('dac_trajectory.predicate', finding.dac_trajectory.predicates, null);
  return out;
}

/** Turn one aggregate's thresholds into gate results. Determinacy is not decoration: an
 *  indeterminate threshold is a "could not tell", which SKIPs and marks the evidence incomplete. */
function thresholdResults(prefix, agg) {
  const out = [];
  for (const t of agg.thresholds) {
    const [lo, hi] = t.interval;
    const name = `${prefix}:${t.name}`;
    if (t.threshold_determinacy === 'determinate' && t.threshold_result === true
      && CONTRIBUTING_ROWS.includes(name)) {
      out.push(r(name, NOTE, `${agg.n_broke}/${agg.M} witnesses broke, threshold ${t.threshold} `
        + '(contributing in cft-policy-1.2: shown beside a named row, never a warning on its own)'));
    } else if (t.threshold_determinacy === 'determinate' && t.threshold_result === true) {
      out.push(r(name, WARN, `${agg.n_broke}/${agg.M} witnesses broke, threshold ${t.threshold} `
        + '(threshold over history: warns, never blocks — D1)'));
    } else if (t.threshold_determinacy === 'determinate') {
      out.push(r(name, ALLOW, `${agg.n_broke}/${agg.M} broke, threshold ${t.threshold} cannot be `
        + `reached (retained interval [${lo}, ${hi}])`));
    } else {
      out.push(r(name, SKIP, `indeterminate: ${agg.n_unevaluable} of ${agg.M} unevaluable, retained `
        + `interval [${lo}, ${hi}] spans threshold ${t.threshold} — NOT a clean result`));
    }
  }
  return out;
}

const STALE_LISTED = 10;
/** The A8 coverage row for a gate-supplied gap count, or null (no append placement, or k = 0). */
function staleSeedRow(st) {
  if (!st || typeof st !== 'object') return null;
  if (st.checked === false) {
    return r('seed-v3:coverage', SKIP, 'stale_seed not checked: no packument publication times were supplied; '
      + `Channel-A compared against the seed tip ${st.tip}`);
  }
  if (!Number.isInteger(st.k) || st.k < 1) return null;
  const shown = st.versions.slice(0, STALE_LISTED).join(', ');
  const more = st.k > STALE_LISTED ? `, … +${st.k - STALE_LISTED} more` : '';
  return r('seed-v3:coverage', SKIP, `stale_seed k=${st.k}: ${st.k} release(s) published after the seed tip ${st.tip} `
    + `are not in the seed (${shown}${more}); Channel-A compared against ${st.tip}`);
}

/**
 * Map one finding (plus any recorded pin for the same package and version) to a disposition.
 *
 * @param {object|null} finding   a CFT-03 finding, or null when there is none
 * @param {object} ctx
 *   ctx.pin        a known_malicious_pins row for THIS package and version, or null
 *   ctx.pinLookupError  the error a pin lookup threw, or null (1.1): recorded, and the input rule decides
 *   ctx.refusal    the SeedRefused / CandidateRejected that prevented evaluation, or null
 *   ctx.config     the operator's answers to OPEN_CHOICES
 *   ctx.override   an override row (D1 short-circuit), or null
 *   ctx.staleSeed  (cft-policy-1.2, A8) the gate's gap count for an `append` placement, or null:
 *                  {checked: true, k, tip, versions} or {checked: false, tip}. A coverage fact, never an alert.
 * @returns {object} a decision. `disposition` is null when policy declines to decide; it is never
 *   ALLOW merely because something could not be established.
 */
function decide(finding, ctx = {}) {
  const { pin = null, refusal = null, override = null } = ctx;
  const pinLookupError = pin ? null : (ctx.pinLookupError ?? null);
  const config = normaliseConfig(ctx.config || {});
  const base = {
    placement: null,
    channel_a_usable: null,
    policy_version: POLICY_CONTRACT_VERSION,
    detection_contract_version: finding ? finding.contract_version : null,
    package: finding ? finding.candidate.package : (ctx.packageName ?? null),
    version: finding ? finding.candidate.version : (ctx.version ?? null),
    // Read from the FINDING, so a decision record shows which provider class the evidence carried.
    // It is derived from a domain version count the consumer supplies or computes, and a recorded
    // decision that omits it cannot be re-read later to see which classification applied.
    provider_class: finding ? (finding.candidate.provider_class ?? null) : null,
    seed: finding ? finding.seed : null,
    override: null,
    undecided: [],
  };

  // D1: an override short-circuits to ALLOW and nothing else runs. Kept verbatim, including that it
  // outranks a pin — an operator who has pinned an exception has made a decision policy must honour
  // and record, not quietly reverse.
  if (override) {
    const reason = override.reason ?? '(no reason)';
    return {
      ...base,
      disposition: ALLOW,
      results: [r('override', ALLOW, `override: ${reason}`)],
      evidence_complete: false,
      not_evaluated: [{ where: 'policy', name: 'override', reason: 'gates did not run' }],
      override: { reason, created_at: override.created_at ?? null },
    };
  }

  // An UNUSABLE INPUT: there is no finding to read (1), or one written under another detection contract (2).
  // `on_unusable_input` decides the input row. A recorded advisory for this exact version is not about the input:
  // under 1.1 it comes first and BLOCKs whatever that choice says (D4), and a failed lookup is recorded beside it.
  const unusable = (detail, name) => {
    const choice = config.on_unusable_input;
    const results = [];
    if (pin) results.push(pinBlockRow(pin, base.package, base.version));
    else if (pinLookupError) results.push(pinFailedRow(pinLookupError));
    results.push(r('seed-v3:input', inputResult(choice), detail));
    const notEvaluated = [{ where: 'policy', name, reason: detail }];
    if (pinLookupError) notEvaluated.push(pinLookupMissing(pinLookupError));
    return {
      ...base,
      // A pin is a recorded fact and stands on its own, as it does when nothing was evaluated (row 8).
      disposition: pin ? BLOCK : (choice === 'REFUSE_TO_DECIDE' ? null : aggregate(results)),
      results,
      evidence_complete: false,
      not_evaluated: notEvaluated,
      undecided: choice === 'REFUSE_TO_DECIDE' ? ['on_unusable_input'] : [],
    };
  };

  // 1. UNSUPPORTED INPUT or TRUST FAILURE. There is no finding, so there is nothing to be clean.
  if (refusal || !finding) {
    return unusable(refusal
      ? `${refusal.name || 'refused'}: ${(refusal.reasons || [refusal.message]).join('; ')}`
      : 'no finding was produced', 'input');
  }

  // A finding produced under a detection contract this policy version was not written against is an
  // unsupported input too: the field meanings are exactly what policy is reading.
  if (finding.contract_version !== IMPLEMENTED_DETECTION_CONTRACT) {
    return unusable(`finding declares detection contract ${finding.contract_version}; this policy `
      + `implements ${IMPLEMENTED_DETECTION_CONTRACT}`, 'detection_contract_version');
  }

  // PLACEMENT. Channel-A compares a release against its predecessor in a lineage; the DAC
  // trajectory reads prior versions across the whole package by publication time and never needs a
  // lineage; an advisory pin names an exact version and needs neither. So an unresolved placement
  // costs Channel-A and NOTHING ELSE -- discarding the finding wholesale would throw away results
  // that remain independently evaluable.
  const placement = ctx.placement || null;
  const channelAUsable = !placement || placement.channel_a_usable !== false;
  const missing = notEvaluated(finding, placement);
  const results = [];

  // 2. KNOWN-MALWARE PIN — a recorded advisory naming this exact version. Locked criterion, not a
  //    choice: this is the same true-positive-by-construction standard that lets content-hash block.
  //    A lookup that FAILED is not "no advisory": it is recorded and the input rule decides it (1.1).
  const policyMissing = [];
  if (pin) {
    results.push(pinBlockRow(pin, base.package, base.version));
  } else if (pinLookupError) {
    results.push(pinFailedRow(pinLookupError));
    results.push(r('seed-v3:input', inputResult(config.on_unusable_input),
      `advisory pin lookup FAILED (${reasonOf(pinLookupError)}); on_unusable_input decides it`));
    policyMissing.push(pinLookupMissing(pinLookupError));
  } else {
    results.push(r(PIN_GATE, ALLOW, 'no recorded advisory pins this version'));
  }

  // 3. TRAJECTORY AND CHANNEL-A THRESHOLDS — inference over history, so WARN at most.
  if (channelAUsable) {
    results.push(...thresholdResults('seed-v3:channel-a', finding.channel_a));
  } else {
    // NOT a clean result, and not a threshold result either: the comparison did not happen.
    results.push(r('seed-v3:channel-a', SKIP,
      `not evaluated — ${placement.reason || placement.kind}. Channel-A compares this release `
      + 'against its lineage predecessor, and this release could not be placed; the thresholds in '
      + 'the finding are over an empty comparison and are NOT used.'));
  }
  results.push(...thresholdResults('seed-v3:dac-trajectory', finding.dac_trajectory));

  // 3b. STALE SEED (cft-policy-1.2, 0.1.4 A8; seed-base table R1/R7/P3, Q1). Channel-A compared an `append` release
  //     against the seed tip; registry releases between that tip and this release are not in the seed. The count is
  //     a COVERAGE fact: a SKIP row (D1 aggregation ignores it), never in not_evaluated, never an alert. With no
  //     publication times to count from it says "not checked" rather than implying k = 0.
  const stale = staleSeedRow(ctx.staleSeed);
  if (stale) results.push(stale);

  // 4. INCOMPLETE EVIDENCE. Never folded into the disposition silently: it is a SKIP with the
  //    reasons named, it sets evidence_complete=false, and when NOTHING was evaluated the
  //    disposition itself is an open question rather than an ALLOW by default.
  // What counts as "something was evaluated" must ignore a Channel-A aggregate the placement just
  // invalidated, or an unplaced release would look evidenced when only the discarded half was.
  const evaluatedAnything = (channelAUsable && finding.channel_a.n_evaluable > 0)
    || finding.dac_trajectory.n_evaluable > 0;
  if (missing.length) {
    const reasons = [...new Set(missing.map((m) => m.reason))].sort();
    results.push(r('seed-v3:coverage', SKIP,
      `${missing.length} of ${finding.channel_a.M + K.PUBLISHER_CONSTITUENTS.length
        + finding.dac_trajectory.M} observations NOT_EVALUATED (${reasons.join(', ')})`));
  }
  const undecided = [];
  let disposition = aggregate(results);
  if (!evaluatedAnything) {
    const choice = config.on_no_evidence;
    if (choice === 'REFUSE_TO_DECIDE') {
      undecided.push('on_no_evidence');
      // A pin is a recorded fact and stands on its own even with no history to evaluate.
      disposition = pin ? BLOCK : null;
    } else if (choice === WARN) {
      results.push(r('seed-v3:coverage', WARN, 'nothing in this finding was evaluated'));
      disposition = aggregate(results);
    }
    // ALLOW: D1's fail-open, chosen explicitly by an operator rather than arrived at by omission.
  }
  if (pinLookupError && config.on_unusable_input === 'REFUSE_TO_DECIDE') {
    // Whether an advisory names this version is unknown, and the operator has not said what that means.
    if (!undecided.includes('on_unusable_input')) undecided.push('on_unusable_input');
    disposition = null;
  }

  return {
    ...base,
    disposition,
    results,
    placement: placement ? placement.kind : null,
    channel_a_usable: channelAUsable,
    evidence_complete: missing.length === 0 && policyMissing.length === 0,
    not_evaluated: [...missing, ...policyMissing],
    undecided,
  };
}

/** Look up a recorded advisory pin for one package and version. Read-only, and its own query so the
 *  detection path never has to know this table exists.
 *
 *  Seed contract 1.1 keys pins by NAME, so a pin is found whether or not the package is represented (D4: the 1.0
 *  join made a pin row without a `packages` row invisible). A 1.0 seed keeps the 1.0 join exactly. */
function pinFor(seed, packageName, version) {
  const byName = seed.meta?.seed_contract_version === PIN_BY_NAME_SEED_CONTRACT;
  const row = seed.db.prepare(byName
    ? 'SELECT advisory_id, source FROM known_malicious_pins WHERE package_name = ? AND version = ? '
      + 'ORDER BY advisory_id LIMIT 1'
    : 'SELECT k.advisory_id AS advisory_id, k.source AS source FROM known_malicious_pins k '
      + 'JOIN packages p ON p.id = k.package_id WHERE p.package_name = ? AND k.version = ? LIMIT 1',
  ).get(packageName, version);
  return row || null;
}

/**
 * `pinFor` for callers that must not lose the result to an exception (the "safePinFor" of the D4 proposal).
 * Looks up only an EXACT identity -- both a non-empty string -- in the seed the caller hands it, which is the seed the
 * caller accepted under its configured trust mode. Never throws: a failure is RETURNED, so it can be recorded.
 * @returns {{pin: object|null, error: Error|null, attempted: boolean}}
 */
function lookupPin(seed, packageName, version) {
  if (typeof packageName !== 'string' || !packageName || typeof version !== 'string' || !version) {
    return { pin: null, error: null, attempted: false };
  }
  try {
    return { pin: pinFor(seed, packageName, version), error: null, attempted: true };
  } catch (e) {
    return { pin: null, error: e instanceof Error ? e : new Error(String(e)), attempted: true };
  }
}

export {
  NAMED_RUNNER_GATES,
  POLICY_CONTRACT_VERSION, IMPLEMENTED_DETECTION_CONTRACT, DISPOSITIONS, OPEN_CHOICES,
  OPEN_CHOICE_KEYS, PolicyConfigInvalid, normaliseConfig, aggregate, notEvaluated,
  thresholdResults, decide, pinFor, lookupPin, PIN_GATE, ALLOW, WARN, BLOCK, SKIP,
  NOTE, NAMED_ROWS, CONTRIBUTING_ROWS, POLICY_ROW_GATES, ROW_RESULTS,
};
export default {
  NAMED_RUNNER_GATES,
  POLICY_CONTRACT_VERSION, IMPLEMENTED_DETECTION_CONTRACT, DISPOSITIONS, OPEN_CHOICES,
  OPEN_CHOICE_KEYS, PolicyConfigInvalid, normaliseConfig, aggregate, notEvaluated,
  thresholdResults, decide, pinFor, lookupPin, PIN_GATE, ALLOW, WARN, BLOCK, SKIP,
  NOTE, NAMED_ROWS, CONTRIBUTING_ROWS, POLICY_ROW_GATES, ROW_RESULTS,
};
