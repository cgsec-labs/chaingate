// `chaingate unpin <package> [<major> | 0.<minor>]` -- 0.1.4 group 2d (O1, D-U4): removes the package's pins (every
// class, or the one named).
import { existsSync } from 'node:fs';
import { fmt } from '../format.js';
import { resolvePaths } from '../paths.js';
import { openWitnessDB } from '../../witness/db.js';
import { assertIntegrity } from '../integrity-gate.js';
import { identity } from '../../proxy/notice.js';
import { classLabel } from '../../witness/pins.js';
import { decisionSnapshot, adjudicate } from '../adjudicate.js';
import { EXIT } from '../constants.js';

const USAGE = 'Usage: chaingate unpin <package> [<major> | 0.<minor>]';

export default async function unpin(args) {
  let scope = 'user';
  const pos = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) scope = args[++i];
    else if (!args[i].startsWith('-')) pos.push(args[i]);
  }
  const [name, classKey = null] = pos;
  if (!name || !identity(name, '1.0.0') || (classKey != null && !/^(?:[1-9]\d{0,8}|0\.[1-9]\d{0,8})$/.test(classKey))) {
    console.error(USAGE);
    return EXIT.ERROR;
  }
  const paths = resolvePaths(scope);
  if (!existsSync(paths.witnessDb)) {
    console.error(fmt.fail('No witness database found. Run `chaingate init` first.'));
    return EXIT.ERROR;
  }
  const gate = await assertIntegrity(paths, { command: 'unpin' });
  if (!gate.ok) return gate.exit;

  const db = openWitnessDB(paths.witnessDb);
  try {
    db.applySchema();
    const removed = db.listPins().filter((p) => p.package_name === name && (classKey == null || p.class_key === classKey));
    if (!removed.length) { console.log(`No pin for ${name}${classKey ? ` in ${classLabel(classKey)}` : ''}.`); return EXIT.OK; }
    // dated note 8.3: the removal and its log are one transaction
    try {
      db.db.transaction(() => {
        db.deletePins(name, classKey);
        for (const p of removed) {
          adjudicate(db, { action: 'unpin', pkg: name, version: p.k_version, k: p.k_version, snapshot: decisionSnapshot(db, name, p.k_version) });
        }
      })();
    } catch (err) {
      console.error(`${name}: the unpin could not be recorded and logged (${err.message}); nothing was changed.`);
      return EXIT.ERROR;
    }
    console.log(fmt.ok(`Unpinned ${name}: ${removed.map((p) => `${p.k_version} (${classLabel(p.class_key)})`).join(', ')}.`));
    console.log(fmt.dim('  npm may keep using metadata it cached (up to its max-age, usually 5 minutes); '
      + '`npm install --prefer-online` refreshes it now.'));
  } finally {
    db.close();
  }
  return EXIT.OK;
}
