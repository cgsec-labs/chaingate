// `chaingate report [--all | --since <dur>] [--json] [--scope user|project]` -- 0.1.4 group 2c (D-R3, E21).
//
// With a running proxy: its latest install that fetched a tarball (`--all`: every install it holds), from
// `/_chaingate/report`. Without one: the disk record (named warnings served, refusals and tag moves resting on a fact) of
// the last 24 h (`--since` to change), saying that the per-install summary is held only by a running proxy. A ChainGate
// proxy that answers without a summary (an older version, a timeout, an oversized answer) is named as such, and the disk
// view is then incomplete (dated note 7.6). The proxy is reached at CHAINGATE_PORT when set (the variable the proxy itself
// reads), else the default port.
//
// Exit: 0 nothing named, refused or tag-moved, and the record complete; 2 named warnings; 3 a refusal or a tag moved off a
// withheld version; 4 a tool error, or an incomplete record with nothing else to report.
import { existsSync } from 'node:fs';
import { resolvePaths } from '../paths.js';
import { fetchLocalJson, fetchSelf } from '../proxy-control.js';
import { openWitnessDB } from '../../witness/db.js';
import { renderReport, safeJson, DISK_READ_LIMIT } from '../report-render.js';
import { DEFAULT_PORT, DEFAULT_HOST, EXIT } from '../constants.js';

const REPORT_MAX_BYTES = 128 * 1048576;
const REPORT_TIMEOUT_MS = 15_000;
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

/** Write and wait until stdout has taken it: on a pipe stdout may be asynchronous, and the CLI exits right after (7.8). */
const write = (text) => new Promise((resolve) => { process.stdout.write(`${text}\n`, () => resolve()); });

async function emit(opts, source, payload, rendered) {
  await write(opts.json ? safeJson({ source, ...payload, exit: rendered.exit }) : rendered.text);
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
    { timeoutMs: REPORT_TIMEOUT_MS, maxBytes: REPORT_MAX_BYTES });
  if (r.ok && r.json.service === 'chaingate-proxy') {
    return emit(opts, 'proxy', r.json, renderReport(r.json, { source: 'proxy' }));
  }
  const why = r.ok ? 'it answered, but not as a ChainGate proxy'
    : (r.status === 404 ? 'it has no install summary endpoint' : r.why);
  // Something answered (or timed out): is it a ChainGate proxy without a summary?
  let proxy = null;
  if (r.ok || r.status !== undefined || !/nothing is listening/.test(r.why ?? '')) {
    const self = await fetchSelf(host, port, 1500);
    if (self.ok && self.json.service === 'chaingate-proxy') proxy = { version: self.json.version ?? null };
  }

  const paths = resolvePaths(opts.scope);
  const dbPath = process.env.CHAINGATE_WITNESS_DB || paths.witnessDb;
  if (!existsSync(dbPath)) {
    const payload = { error: `${proxy ? `the ChainGate proxy on ${host}:${port} gave no install summary` : `no proxy answered on ${host}:${port}`} `
      + `(${why}), and no witness database was found at ${dbPath}` };
    return emit(opts, 'none', payload, renderReport(payload));
  }
  let events;
  try {
    const db = openWitnessDB(dbPath, { readonly: true });
    try {
      events = db.listNamedFactEvents({ sinceIso: new Date(Date.now() - opts.sinceMs).toISOString(), limit: DISK_READ_LIMIT + 1 });
    } finally { db.close(); }
  } catch (err) {
    const payload = { error: `the witness database at ${dbPath} could not be read (${err.message})` };
    return emit(opts, 'none', payload, renderReport(payload));
  }
  const truncated = events.length > DISK_READ_LIMIT;
  if (truncated) events = events.slice(events.length - DISK_READ_LIMIT);     // newest rows, oldest first: drop the oldest
  const payload = { host, port, why, since: opts.since, events, truncated, ...(proxy ? { proxy } : {}) };
  return emit(opts, 'disk', payload, renderReport(payload, { source: 'disk' }));
}
