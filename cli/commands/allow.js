import { existsSync } from 'node:fs';
import { fmt } from '../format.js';
import { resolvePaths } from '../paths.js';
import { openWitnessDB } from '../../witness/db.js';
import { assertIntegrity } from '../integrity-gate.js';
import { EXIT } from '../constants.js';
import { decisionSnapshot, adjudicate } from '../adjudicate.js';
import { withheldBy } from '../../witness/pins.js';

function parseArgs(args) {
  const opts = { scope: 'user', reason: null, target: null };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) opts.scope = args[++i];
    else if (args[i] === '--reason' && args[i + 1]) opts.reason = args[++i];
    else if (!args[i].startsWith('-') && !opts.target) opts.target = args[i];
  }
  return opts;
}

function parseTarget(target) {
  if (!target) return null;
  const at = target.lastIndexOf('@');
  if (at <= 0) return null;
  return { name: target.slice(0, at), version: target.slice(at + 1) };
}

export default async function allow(args) {
  const opts = parseArgs(args);
  const parsed = parseTarget(opts.target);

  if (!parsed) {
    console.error('Usage: chaingate allow <package>@<version> --reason "..."');
    return EXIT.ERROR;
  }
  if (!opts.reason) {
    console.error('--reason is required. Explain why this override is safe.');
    return EXIT.ERROR;
  }

  const paths = resolvePaths(opts.scope);
  if (!existsSync(paths.witnessDb)) {
    console.error(fmt.fail('No witness database found. Run `chaingate init` first.'));
    return EXIT.ERROR;
  }

  // Refuse to record an override if the installed chaingate fails integrity
  // checks — writing policy exceptions from a compromised install defeats
  // the whole point.
  const gate = await assertIntegrity(paths, { command: 'allow' });
  if (!gate.ok) return gate.exit;

  const db = openWitnessDB(paths.witnessDb);
  try {
    db.applySchema();                                          // the adjudication log exists on every writer
    const snap = decisionSnapshot(db, parsed.name, parsed.version);
    db.insertOverride(parsed.name, parsed.version, opts.reason);
    // Since 0.1.4: the action is logged; a log failure never undoes the override
    try { adjudicate(db, { action: 'allow', pkg: parsed.name, version: parsed.version, snapshot: snap }); } catch (err) {
      console.error(fmt.dim(`  (the action could not be logged: ${err.message})`));
    }
    console.log(fmt.ok(`Override recorded: ${parsed.name}@${parsed.version}`));
    console.log(fmt.dim(`  Reason: ${opts.reason}`));
    console.log(fmt.dim('  Takes effect on next install (no restart needed).'));
    // A pin that withholds this version wins in serving; say so, delete nothing
    const pin = withheldBy(db.listPins(), parsed.name, parsed.version);
    if (pin) {
      console.log(fmt.yellow(`  conflict: your pin on ${parsed.name} (${pin.k_version}) withholds ${parsed.name}@${parsed.version}; `
        + `the pin wins until chaingate unpin ${parsed.name}`));
    }
  } finally {
    db.close();
  }

  return EXIT.OK;
}
