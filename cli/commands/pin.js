// `chaingate pin <package>@<K>` | `--list` -- 0.1.4 group 2d (O1, D-U4).
//
// Keeps <package> on K within K's caret class: every version of it in that class above K (prereleases included, later
// releases included) is withheld until `chaingate unpin <package>`. Other majors still resolve. The pin is a live serving
// overlay of the running proxy, never a stored decision.
import { existsSync } from 'node:fs';
import { fmt } from '../format.js';
import { resolvePaths } from '../paths.js';
import { fetchSelf } from '../proxy-control.js';
import { openWitnessDB } from '../../witness/db.js';
import { assertIntegrity } from '../integrity-gate.js';
import { identity } from '../../proxy/notice.js';
import { caretClass, classLabel, withheldBy } from '../../witness/pins.js';
import { seenInLatest } from '../../witness/last-without-signal.js';
import { isStub } from '../../seed/v3/gate.js';
import { decisionSnapshot, adjudicate, parseTarget } from '../adjudicate.js';
import { DEFAULT_HOST, DEFAULT_PORT, EXIT } from '../constants.js';
import semver from 'semver';

const USAGE = 'Usage: chaingate pin <package>@<version> | --list';

function parseArgs(args) {
  const opts = { scope: 'user', list: false, target: null };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) opts.scope = args[++i];
    else if (args[i] === '--list') opts.list = true;
    else if (!args[i].startsWith('-') && !opts.target) opts.target = args[i];
  }
  return opts;
}

/** The proxy port `chaingate report` and `pin` ask: CHAINGATE_PORT when set (the variable the proxy reads), else default. */
export function proxyPort(env = process.env) {
  const n = Number(env.CHAINGATE_PORT);
  return Number.isInteger(n) && n > 0 && n < 65536 ? n : DEFAULT_PORT;
}

/** Whether the running proxy enforces pins, in words (D-U4). */
export async function enforcementLine() {
  const self = await fetchSelf(DEFAULT_HOST, proxyPort(), 1500);
  if (self.ok && self.json.service === 'chaingate-proxy' && self.json.pins?.enforced === true) {
    return 'in force for new metadata requests; npm may keep using metadata it cached (up to its max-age, usually 5 minutes); '
      + '`npm install --prefer-online` refreshes it now.';
  }
  return 'recorded, not in force until the proxy runs this version'
    + (self.ok && self.json.service === 'chaingate-proxy' ? ` (the running proxy is ${self.json.version ?? 'an older version'})` : ' (no proxy answered)')
    + '.';
}

export default async function pin(args) {
  const opts = parseArgs(args);
  const paths = resolvePaths(opts.scope);
  if (!existsSync(paths.witnessDb)) {
    console.error(fmt.fail('No witness database found. Run `chaingate init` first.'));
    return EXIT.ERROR;
  }
  if (opts.list) {
    const db = openWitnessDB(paths.witnessDb, { readonly: true });
    try {
      const rows = db.listPins();
      if (!rows.length) console.log('No pins.');
      for (const r of rows) console.log(`${r.package_name}@${r.k_version} (${classLabel(r.class_key)})  pinned ${r.created_at}`);
    } finally { db.close(); }
    return EXIT.OK;
  }

  const t = parseTarget(opts.target);
  if (!t || !identity(t.name, t.version)) {
    console.error(t ? `${opts.target} is not a valid package@version.` : USAGE);
    return EXIT.ERROR;
  }
  const id = `${t.name}@${t.version}`;
  const cls = caretClass(t.version);
  if (!cls || isStub(t.version)) {
    console.error(isStub(t.version) ? `${id} is a takedown stub; a pin cannot hold it.`
      : `${id}: a pin needs a version in a caret range above 0.0.z (a 0.0.z version has no range to hold).`);
    return EXIT.ERROR;
  }
  const gate = await assertIntegrity(paths, { command: 'pin' });
  if (!gate.ok) return gate.exit;

  const db = openWitnessDB(paths.witnessDb);
  try {
    db.applySchema();
    const history = db.getHistory(t.name);
    if (!seenInLatest(history, t.version)) {
      console.error(`ChainGate has not seen ${id} in the latest metadata it served for ${t.name}; a pin needs a version npm can get.`);
      return EXIT.ERROR;
    }
    const snap = decisionSnapshot(db, t.name, t.version);
    if (snap.app?.block) {
      console.error(`${id} is BLOCKed; a pin cannot hold a BLOCKed version.`);
      return EXIT.ERROR;
    }
    const pinRow = { package_name: t.name, class_key: cls, k_version: t.version };
    const withheld = history.map((h) => h.version).filter((v) => withheldBy([pinRow], t.name, v)).sort(semver.compare);
    const conflicts = db.listOverrides().filter((o) => o.package_name === t.name && withheldBy([pinRow], t.name, o.version));
    db.upsertPin(pinRow);
    adjudicate(db, { action: 'pin', pkg: t.name, version: t.version, k: t.version, snapshot: snap });
    console.log(fmt.ok(`Pinned ${t.name} to ${t.version} within ${classLabel(cls)}.`));
    console.log(`  withholds now: ${withheld.length ? withheld.join(', ') : 'nothing yet (later releases in this range will be)'}`);
    for (const o of conflicts) {
      console.log(fmt.yellow(`  conflict: an exact override (chaingate allow) exists for ${o.package_name}@${o.version}; the pin withholds it`));
    }
    console.log(`  ${await enforcementLine()}`);
    console.log(fmt.dim(`  Undo: chaingate unpin ${t.name}`));
  } finally {
    db.close();
  }
  return EXIT.OK;
}
