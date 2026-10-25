// `chaingate why` — explain, never re-decide.
//
//   why <package>@<version> --packument <file>   evaluate through `check`, then explain that result
//   why --from <check.json>                      explain a SAVED check output; evaluates nothing
//   why <package>@<version> --cached             show the legacy stored row, labelled UNBOUND, exit 4
//
// The explanation is `explain()`, a pure function of the check result. `--cached` is a
// LEGACY DIAGNOSTIC: a `gate_decisions` row records no seed, rule or policy identity, so it does
// NOT meet the identity requirement of a current result and is never shown as current.
import { existsSync, readFileSync } from 'node:fs';
import { fmt, renderGate } from '../format.js';
import { resolvePaths } from '../paths.js';
import { openWitnessDB } from '../../witness/db.js';
import { explain } from '../../seed/v3/explain.js';
import { CHECK_SCHEMA_IDS, EXIT_TOOL_ERROR, recordCompatibility } from '../check-record.js';
import { runCheck, parseTarget } from './check.js';
import { decisionSnapshot, adjudicate } from '../adjudicate.js';
import { shadowLines, staticFactsLines, SHADOW_NOTE } from '../../proxy/shadow-facts.js';

export const UNBOUND_LABEL = 'CACHED — UNBOUND: produced without recorded seed/rule/policy identities; '
  + 'not a current evaluation';

export const USAGE = 'Usage:\n'
  + '  chaingate why <package>@<version> --packument <file> [--json]   evaluate, then explain\n'
  + '  chaingate why --from <check.json> [--json]                      explain a saved check output\n'
  + '  chaingate why <package>@<version> --cached [--json]             legacy stored row (UNBOUND, exit 4)\n'
  + '  chaingate why <package>@<version>                               the same as --cached (the form npm notices print)';

function parseArgs(args) {
  const opts = { scope: 'user', json: false, target: null, packument: null, from: null, cached: false, errors: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const value = () => (args[i + 1] && !args[i + 1].startsWith('--') ? args[++i] : (opts.errors.push(`${a} needs a value`), null));
    if (a === '--scope') opts.scope = value() ?? opts.scope;
    else if (a === '--json') opts.json = true;
    else if (a === '--packument') opts.packument = value();
    else if (a === '--from') opts.from = value();
    else if (a === '--cached') opts.cached = true;
    else if (a.startsWith('-')) opts.errors.push(`unknown option ${a}`);
    else if (!opts.target) opts.target = a;
    else opts.errors.push(`unexpected argument ${a}`);
  }
  const modes = [opts.packument !== null, opts.from !== null, opts.cached].filter(Boolean).length;
  // 0.1.4: `why <pkg>@<ver>` with no mode -- the form ChainGate's npm notice prints -- shows the recorded
  // decision, exactly as --cached (UNBOUND, exit 4), so the pointer in the notice works.
  if (modes === 0 && opts.target) { opts.cached = true; opts.defaulted = true; } else if (modes !== 1) {
    opts.errors.push('choose exactly one of --packument, --from, --cached');
  }
  if (opts.from === null && !parseTarget(opts.target)) opts.errors.push('a <package>@<version> is required');
  if (opts.from !== null && opts.target) opts.errors.push('--from takes no <package>@<version>');
  return opts;
}

function print(expl, json) {
  if (json) console.log(JSON.stringify(expl, null, 2));
  else for (const line of expl.text) console.log(line);
}

/** Explain a saved record. Evaluates nothing; reads only the file. */
export function explainSaved(file) {
  let rec;
  try { rec = JSON.parse(readFileSync(file, 'utf8')); } catch (e) {
    return { error: `cannot read a check result from ${file}: ${e.code || e.message}` };
  }
  if (!rec || !CHECK_SCHEMA_IDS.includes(rec.schema)) {
    return { error: `${file} is not a ${CHECK_SCHEMA_IDS.join(' or ')} result (schema ${JSON.stringify(rec?.schema ?? null)})` };
  }
  if (rec.result === 'tool_error') {
    return { error: `${file} is a tool error (${rec.error?.code}): nothing was evaluated, so there is nothing to explain` };
  }
  // A supported schema id is not enough: the policy, explanation, detection and seed versions must be the combination
  // that schema carries, and a refused explanation's deciding rows must be the decision's.
  const problems = recordCompatibility(rec);
  if (problems.length) return { error: `${file} is not a record this chaingate reads: ${problems.join('; ')}` };
  try { return { explanation: explain(rec) }; } catch (e) {
    return { error: `${file}: ${e.message}` };
  }
}

function showCached(parsed, opts) {
  const paths = resolvePaths(opts.scope);
  const dbPath = process.env.CHAINGATE_WITNESS_DB || paths.witnessDb;
  if (!existsSync(dbPath)) {
    console.error(fmt.fail(`No witness database at ${dbPath}.`));
    return EXIT_TOOL_ERROR;
  }
  const db = openWitnessDB(dbPath, { readonly: true });
  try {
    const row = db.getLatestDecision(parsed.name, parsed.version);
    // The decision that APPLIES under the one applicable-BLOCK rule, beside the latest row.
    let applicable = null;
    try { applicable = row ? db.getApplicableDecision(parsed.name, parsed.version) : null; } catch { applicable = null; }
    const applies = applicable ? { disposition: applicable.disposition, block_row: applicable.block?.id ?? null,
      pending: applicable.pending, override: applicable.override } : null;
    // 0.1.5 shadow facts: recorded once per served version; record only, no verdict reads them
    const shadow = db.shadowFactsFor(parsed.name, parsed.version);
    const staticFacts = typeof db.staticFactsFor === 'function' ? db.staticFactsFor(parsed.name, parsed.version) : null;   // static-checks-1.6, armed versions
    if (opts.json) {
      console.log(JSON.stringify({ label: 'CACHED-UNBOUND', note: UNBOUND_LABEL,
        package: parsed.name, version: parsed.version, cached: row || null, applicable: applies, shadow_facts: shadow, static_facts: staticFacts }, null, 2));
    } else {
      console.log(fmt.yellow ? fmt.yellow(UNBOUND_LABEL) : UNBOUND_LABEL);
      if (!row) {
        console.log(`  no stored row for ${parsed.name}@${parsed.version}`);
      } else {
        console.log(`  ${parsed.name}@${parsed.version}  stored disposition ${row.disposition}  at ${row.decided_at}`);
        for (const gate of row.gates_fired || []) console.log(renderGate(gate));
        if (applies && applies.disposition !== row.disposition) {
          console.log(`  applies: ${applies.disposition} -- stored BLOCK #${applies.block_row} is not definitively cleared `
            + `(${applies.pending.join(', ')})`);
        }
      }
      if (shadow) {
        let lines = [];
        try { lines = shadowLines(shadow); } catch { lines = ['not readable']; }
        console.log(`  Recorded facts (${shadow.version ?? 'unknown'}; ${SHADOW_NOTE}):`);
        for (const l of lines) console.log(`    ${l}`);
      }
      if (staticFacts) {
        let lines = [];
        try { lines = staticFactsLines(staticFacts); } catch { lines = ['not readable']; }
        console.log(`  Static check facts (${staticFacts.facts?.version ?? 'unknown'}; ${SHADOW_NOTE}):`);
        for (const l of lines) console.log(`    ${l}`);
      }
      console.log(`  For a current evaluation: chaingate check ${parsed.name}@${parsed.version} --packument <file>`);
      // 0.1.4: the conclusion for the proxy's named warnings -- what moved, the baseline, what to do
      console.log('  For what the proxy served and why, with what you can do: chaingate report');
    }
  } finally { db.close(); }
  // Exit 4 whether or not a row exists: a cached row is never a check result.
  return EXIT_TOOL_ERROR;
}

/**
 * Append a `why` adjudication, best-effort -- a read-write open with a 250 ms busy timeout; it never
 * creates a table (a read command is no migration) and never changes `why`'s output or exit code.
 */
function recordWhy(parsed, scope) {
  try {
    const dbPath = process.env.CHAINGATE_WITNESS_DB || resolvePaths(scope).witnessDb;
    if (!parsed?.name || !parsed?.version || !existsSync(dbPath)) return;
    const db = openWitnessDB(dbPath, { timeoutMs: 250 });
    try {
      adjudicate(db, { action: 'why', pkg: parsed.name, version: parsed.version, snapshot: decisionSnapshot(db, parsed.name, parsed.version) });
    } finally { db.close(); }
  } catch { /* best-effort: a read-only, locked or 0.1.3 database records nothing */ }
}

export default async function why(args) {
  const opts = parseArgs(args);
  if (opts.errors.length) {
    for (const e of opts.errors) console.error(`chaingate why: ${e}`);
    console.error(USAGE);
    return EXIT_TOOL_ERROR;
  }
  if (opts.from !== null) {
    const r = explainSaved(opts.from);
    if (r.error) { console.error(fmt.fail(r.error)); return EXIT_TOOL_ERROR; }
    print(r.explanation, opts.json);
    return 0;
  }
  const parsed = parseTarget(opts.target);
  if (opts.cached) {
    const code = showCached(parsed, opts);
    recordWhy(parsed, opts.scope);
    return code;
  }

  const { record } = await runCheck({ name: parsed.name, version: parsed.version, packument: opts.packument,
    scope: opts.scope });
  if (record.result === 'tool_error') {
    console.error(fmt.fail(`${parsed.name}@${parsed.version}: tool error (${record.error.code}): ${record.error.message}`));
    return EXIT_TOOL_ERROR;
  }
  print(record.explanation, opts.json);
  recordWhy(parsed, opts.scope);
  return 0;
}
