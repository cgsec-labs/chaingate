// `chaingate accept <package>@<version>` | `--revoke <package>@<version>` | `--list` -- since 0.1.4.
//
// Records that you accept a NAMED warning for one exact version: ChainGate stops sending npm a notice for it while the
// version's record shows only the named signals you accepted (a different or later named signal warns again). It never
// overrides a BLOCK -- a later advisory for that version still BLOCKs; for a false-positive BLOCK use `chaingate allow`.
import { existsSync } from 'node:fs';
import { fmt } from '../format.js';
import { resolvePaths } from '../paths.js';
import { openWitnessDB } from '../../witness/db.js';
import { assertIntegrity } from '../integrity-gate.js';
import { identity } from '../../proxy/notice.js';
import { decisionSnapshot, adjudicate, parseTarget } from '../adjudicate.js';
import { EXIT } from '../constants.js';
import { otherDatabaseLine } from './pin.js';

const USAGE = 'Usage: chaingate accept <package>@<version> | --revoke <package>@<version> | --list';

function parseArgs(args) {
  const opts = { scope: 'user', revoke: false, list: false, target: null };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) opts.scope = args[++i];
    else if (args[i] === '--revoke') opts.revoke = true;
    else if (args[i] === '--list') opts.list = true;
    else if (!args[i].startsWith('-') && !opts.target) opts.target = args[i];
  }
  return opts;
}

export default async function accept(args) {
  const opts = parseArgs(args);
  const paths = resolvePaths(opts.scope);
  if (!existsSync(paths.witnessDb)) {
    console.error(fmt.fail('No witness database found. Run `chaingate init` first.'));
    return EXIT.ERROR;
  }

  if (opts.list) {
    const db = openWitnessDB(paths.witnessDb, { readonly: true });
    try {
      const rows = db.listAcceptances();
      if (!rows.length) console.log('No accepted warnings.');
      for (const r of rows) console.log(`${r.package_name}@${r.version}  accepted ${r.created_at}  (${(r.named ?? []).join(', ')})`);
    } finally { db.close(); }
    return EXIT.OK;
  }

  const t = parseTarget(opts.target);
  if (!t || !identity(t.name, t.version)) {
    console.error(t ? `${opts.target} is not a valid package@version.` : USAGE);
    return EXIT.ERROR;
  }
  const id = `${t.name}@${t.version}`;
  const gate = await assertIntegrity(paths, { command: 'accept' });
  if (!gate.ok) return gate.exit;

  const db = openWitnessDB(paths.witnessDb);
  try {
    db.applySchema();
    const snap = decisionSnapshot(db, t.name, t.version);
    if (opts.revoke) {
      if (!db.getAcceptance(t.name, t.version)) { console.log(`No acceptance recorded for ${id}.`); return EXIT.OK; }
      // the action and its log are one transaction
      try {
        db.db.transaction(() => {
          db.deleteAcceptance(t.name, t.version);
          adjudicate(db, { action: 'unaccept', pkg: t.name, version: t.version, snapshot: snap });
        })();
      } catch (err) {
        console.error(`${id}: the revocation could not be recorded and logged (${err.message}); nothing was changed.`);
        return EXIT.ERROR;
      }
      console.log(fmt.ok(`Acceptance revoked: ${id}. ChainGate sends npm its notice again while the warning stands.`));
      const other = await otherDatabaseLine(paths.witnessDb);         // the running proxy may read another database
      if (other) console.log(fmt.yellow(`  ${other}`));
      return EXIT.OK;
    }
    if (!snap.app?.latest) {
      console.error(`ChainGate has no record of this version (${id}): it has not served its metadata.`);
      return EXIT.ERROR;
    }
    if (snap.app.block || snap.app.latest.disposition === 'BLOCK') {
      console.error(`${id} is BLOCKed: accept never overrides a BLOCK; for a false positive use chaingate allow.`);
      return EXIT.ERROR;
    }
    const named = snap.classes.named ?? [];
    if (!named.length) {
      console.error(`nothing to accept: ${id} carries no named warning.`);
      return EXIT.ERROR;
    }
    try {
      db.db.transaction(() => {
        db.upsertAcceptance({ package_name: t.name, version: t.version, named, decision_id: snap.decision_id, policy_version: snap.policy });
        adjudicate(db, { action: 'accept', pkg: t.name, version: t.version, snapshot: snap });
      })();
    } catch (err) {
      console.error(`${id}: the acceptance could not be recorded and logged (${err.message}); nothing was changed.`);
      return EXIT.ERROR;
    }
    console.log(fmt.ok(`Accepted: ${id} (${named.join(', ')}).`));
    console.log(fmt.dim('  ChainGate stops sending npm a notice for this version while its record shows only these signals.'));
    console.log(fmt.dim('  This does not override a BLOCK: a later advisory for this version still blocks it.'));
    console.log(fmt.dim(`  Undo: chaingate accept --revoke ${id}`));
    const other = await otherDatabaseLine(paths.witnessDb);           // the running proxy may read another database
    if (other) console.log(fmt.yellow(`  ${other}`));
  } finally {
    db.close();
  }
  return EXIT.OK;
}
