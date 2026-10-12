// `chaingate report [--all | --since <dur>] [--json] [--scope user|project]` -- 0.1.4 group 2c (D-R3, E21).
//
// With a running proxy: its latest install that fetched a tarball (`--all`: every install it holds), from
// `/_chaingate/report`. Without one: the disk record (named warnings served, refusals and tag moves resting on a fact) of
// the last 24 h (`--since` to change), saying that the per-install summary is held only by a running proxy.
// The proxy is reached at CHAINGATE_PORT when set (the variable the proxy itself reads), else the default port.
//
// Exit: 0 nothing named, refused or tag-moved, and the record complete; 2 named warnings; 3 a refusal or a tag moved off a
// withheld version; 4 a tool error, or an incomplete record with nothing else to report.
import { existsSync } from 'node:fs';
import { resolvePaths } from '../paths.js';
import { fetchLocalJson } from '../proxy-control.js';
import { openWitnessDB } from '../../witness/db.js';
import { renderReport } from '../report-render.js';
import { DEFAULT_PORT, DEFAULT_HOST, EXIT } from '../constants.js';

const REPORT_MAX_BYTES = 32 * 1048576;
const UNITS = { m: 60_000, h: 3_600_000, d: 86_400_000 };

function parseArgs(args) {
  const opts = { scope: 'user', json: false, all: false, since: '24h', errors: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--scope' && args[i + 1]) opts.scope = args[++i];
    else if (a === '--json') opts.json = true;
    else if (a === '--all') opts.all = true;
    else if (a === '--since') {
      if (args[i + 1] === undefined) opts.errors.push('--since needs a duration such as 30m, 24h or 7d');
      else opts.since = args[++i];
    } else opts.errors.push(`unknown argument ${JSON.stringify(a)}`);
  }
  const m = /^(\d{1,6})([mhd])$/.exec(opts.since);
  if (!m) opts.errors.push(`--since ${JSON.stringify(opts.since)} is not a duration such as 30m, 24h or 7d`);
  else opts.sinceMs = Number(m[1]) * UNITS[m[2]];
  return opts;
}

function portFromEnv(env) {
  const n = Number(env.CHAINGATE_PORT);
  return Number.isInteger(n) && n > 0 && n < 65536 ? n : DEFAULT_PORT;
}

function emit(opts, source, payload, rendered) {
  if (opts.json) console.log(JSON.stringify({ source, ...payload, exit: rendered.exit }, null, 2));
  else console.log(rendered.text);
  return rendered.exit;
}

export default async function report(args) {
  const opts = parseArgs(args);
  if (opts.errors.length) {
    for (const e of opts.errors) console.error(`chaingate report: ${e}`);
    return EXIT.TOOL_ERROR;
  }
  const host = DEFAULT_HOST;
  const port = portFromEnv(process.env);

  const r = await fetchLocalJson(host, port, `/_chaingate/report${opts.all ? '?all=1' : ''}`,
    { timeoutMs: 5000, maxBytes: REPORT_MAX_BYTES });
  if (r.ok && r.json.service === 'chaingate-proxy') {
    return emit(opts, 'proxy', r.json, renderReport(r.json, { source: 'proxy' }));
  }
  const why = r.ok ? 'something answered, but not a ChainGate proxy'
    : (r.status === 404 ? 'the proxy there keeps no install summary (an older version, or not a ChainGate proxy)' : r.why);

  const paths = resolvePaths(opts.scope);
  const dbPath = process.env.CHAINGATE_WITNESS_DB || paths.witnessDb;
  if (!existsSync(dbPath)) {
    const payload = { error: `no proxy answered on ${host}:${port} (${why}), and no witness database was found at ${dbPath}` };
    return emit(opts, 'none', payload, renderReport(payload));
  }
  let events;
  const db = openWitnessDB(dbPath, { readonly: true });
  try {
    events = db.listNamedFactEvents({ sinceIso: new Date(Date.now() - opts.sinceMs).toISOString() });
  } finally { db.close(); }
  const payload = { host, port, why, since: opts.since, events };
  return emit(opts, 'disk', payload, renderReport(payload, { source: 'disk' }));
}
