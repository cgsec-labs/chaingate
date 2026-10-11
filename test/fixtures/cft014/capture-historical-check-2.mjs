// 0.1.4 I1 — capture `chaingate.check/2` records from the RELEASED 0.1.3 source, as historical fixtures for the 0.1.4
// readers (`why --from`, the CI consumer). The /1 precedent is test/fixtures/u05/historical-check-1.json (captured with
// the released 0.1.2). Run through qrun with CAPTURE_ROOT = a worktree at b66edfdd (tag cgsec-chaingate-v0.1.3); it only
// IMPORTS from there (read-only) and prints one JSON document to stdout. Not a test file; never run by the suite.
//
//   QENV="CAPTURE_ROOT=<a worktree at b66edfdd>" qrun.sh <label> 5 cmd -- node test/fixtures/cft014/capture-historical-check-2.mjs
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';

const ROOT = process.env.CAPTURE_ROOT;
if (!ROOT) { console.error('CAPTURE_ROOT is required'); process.exit(2); }
const imp = (rel) => import(pathToFileURL(path.join(ROOT, rel)).href);

const head = execFileSync('git', ['-C', ROOT, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
if (head !== 'b66edfdd67ea7dcd72fe967c3db799d7d80f869e') {
  console.error(`CAPTURE_ROOT is at ${head}, not the released 0.1.3 source b66edfdd`); process.exit(2);
}
const { buildCheckRecord, inputFromPackument, CHECK_SCHEMA_ID } = await imp('cli/check-record.js');
const F = await imp('test/seed-v3/u05-fixtures.mjs');
if (CHECK_SCHEMA_ID !== 'chaingate.check/2') { console.error(`unexpected schema ${CHECK_SCHEMA_ID}`); process.exit(2); }

const TOOL = { name: 'chaingate', version: '0.1.3' };
function record(cfg, doc, version) {
  const s = F.buildSeed({ layout: '1.1' });
  const seed = F.openFixtureSeed(s.dbPath);
  try {
    return buildCheckRecord({ seed, policy: cfg, domainVersionCount: 'from-packument',
      input: inputFromPackument(doc, 'p', version), request: { package: 'p', version }, tool: TOOL });
  } finally { seed.close(); s.cleanup(); }
}

const records = [
  { id: 'evaluated-append-live', record: record(F.LIVE, F.docFor('p', [['1.4.0', F.after()]]), '1.4.0') },
  { id: 'refused-pinned-live', record: record(F.LIVE, F.docFor('p', [['1.3.0', F.after(), null]]), '1.3.0') },
  { id: 'refused-pinned-warn', record: record(F.WARNCFG, F.docFor('p', [['1.3.0', F.after(), null]]), '1.3.0') },
];
process.stdout.write(`${JSON.stringify({ captured_with: '@cgsec/chaingate 0.1.3 source b66edfdd (tag cgsec-chaingate-v0.1.3)',
  capture_script: 'test/fixtures/cft014/capture-historical-check-2.mjs', records }, null, 2)}\n`);
