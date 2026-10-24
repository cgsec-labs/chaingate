# 0.1.5 tarball static checks — handoff for the 0.1.5-owner session (2026-10-14)

Branch `claude/chaingate-cloud-e2e-run-ughfpv`; the parked WIP `claude/chaingate-check-tarball-wip` (5b41fae) belongs to the same
session. Never push to `main`. Failing-first commits (tests, then the implementation). The operator's canonical handover and every
ruling live in the private ops repository (chaingate-ops, branch `g10-c2-pin-admission-1.1`,
`docs/operator-runbooks/pin-admission-1.1-handover-20261013.md` §11; the design note beside it under `docs/design/`).

## What this branch did (steps 1–3 of the design note §9, plus step 5's tests)
- Group 1 (`425faf5`..`65b3b92`, before the static checks; operator ruling 2026-10-13, ops handover §7.2/§7.3): T1.4
  `size-jump-provenance` is NAMED against a lineage predecessor (`gates/lineage-predecessor.js`, a port of the seed's FU-2 FINAL
  rule) and T1.5 `identity-break` is CONTRIBUTING. It edited `seed/v3/policy.js` (NAMED_RUNNER_GATES gains
  `size-jump-provenance`), `proxy/notice.js` (its label) and `gates/row-class.js`; the role pins were updated deliberately.
- Step 1 (`proxy/tar-walk.js`): the walker's keep list — `createTarWalker({ keep })`, bodies up to 1 MiB each, at most 6, `files` and
  `notKept` in the walk result; the MC walk without `keep` is byte-for-byte 0.1.4's.
- Step 2 (`proxy/static-checks.js`): S0–S4 as pure functions over `{ packageJson, files }`, closed-vocabulary rows,
  `STATIC_CHECKS_VERSION = 'static-checks-1.0'` — the same vocabulary as recon v6.5's `static-checks.mjs`; rows join the version's
  decision the way MC's does (the `late` report event; the next-download notice is for named rows only).
- Step 3 (trigger and roles, `fb10b02`): the keep list is armed per the 2026-10-13 ruling (a named WARN row, `identity-break`, or the
  brand-new-package coverage case); `armed by` in the detail; the five `static:*` gates are CONTRIBUTING in `gates/row-class.js`;
  store carry-forward; README "Tarball checks (0.1.5)" section; CONTRIBUTING lists the five gates. `seed/v3/policy.js` and
  `proxy/notice.js` untouched by step 3, by design. (That applies to step 3 only: group 1, below, already edited both.)
- Step 5 failing-first (`28882dd`): `test/cli/cft015-s5-check-tarball.test.js` for `chaingate check --tarball`; its implementation is
  the parked WIP (below).

## State (verified 2026-10-14 on a root host)
- Full suite on this branch: 1,454 tests, 1,399 pass, 12 fail = the 7 step-5 failing-first tests + 5 environment failures expected to
  pass on a non-root host (`doctor --json`, RETAINED bundle re-verify, user- and project-scope restart chains, A9 Python jsonschema).
- Behind `origin/main` by one docs commit (`72db2f3`), which also touches README.
- The WIP (`5b41fae`): step-5 file 8/8; full suite 1,404 pass, 7 fail = the 5 environment failures + two regressions that pass here:
  **A8** (`why --packument` exits 1: `cli/commands/why.js:153` calls the now-async `runCheck` without `await`; `why` is already async)
  and **G5-1** (the README sentence "`chaingate check` (the CI command) evaluates the seed only in 0.1.4" was rewritten; the doc test
  pins it — keep the sentence and add the 0.1.5 paragraph after it, or move the test to 0.1.5 wording, operator's ruling).
  Operator hold on merging it stands.

## Can start now (not gated on the measurement ruling)
1. Merge `origin/main` into this branch (README on both sides); run the full suite on a non-root host and record the baseline.
2. On the WIP branch: the `await` fix, then the step-5 file and the full suite (expect the 5 environment failures only, G5-1 aside).
3. Nothing in `seed/v3/policy.js`, `proxy/notice.js` or the role pins yet.

## Gated on the measurement ruling (ops side; relayed by the operator)
- The per-check naming: which of S0–S4 become NAMED (`seed/v3/policy.js` NAMED_RUNNER_GATES, `proxy/notice.js` text from the design
  note §5 table, role pins updated deliberately). B2 said S0, S2, S4 clear the base-rate bar; S1 and S3 as written do not.
- A `static-checks` bump: recon's module changes first, then `proxy/static-checks.js` mirrors it with the identical version string.
  Never two independent wordings.
- The WIP merge: after the main merge, before the bump, so one commit touches the proxy rows and the `--tarball` rows together.
- The policy identity stays `cft-policy-1.2` (role tables change, not the arithmetic).

## Operator rulings 2026-10-21 (relayed; the ops section 12 follows when ops is reactivated)

R1 Trigger: entry-path-change arms the keep-list walk, beside the named WARN rows, identity-break and the brand-new-package case; "armed by: entry-path-change" in the row detail.

R2 S6 network-only beacon: a hook target with an API network sink (http-request, fetch, net-connect, websocket, xhr, axios), a host-identity source (os.hostname(), os.userInfo(), os.networkInterfaces(), the env-dump marker, or the identity variables USER, USERNAME, LOGNAME, HOSTNAME, COMPUTERNAME) and no execution sink in the same file; url-literal is not a sink, a bare process.env read is not a source. Gate static:S6-network-only-beacon, CONTRIBUTING first.

R3 S7 entry capability delta: main or bin gains an API network sink, an execution sink, an obfuscation or decode marker, or a credential source that the predecessor's same-role file lacked; url-literal excluded. Predecessor at runtime = the last version this proxy served; cold start NOT_APPLICABLE; a refused predecessor or current archive is NOT_CHECKED, never a clean delta; the row names the predecessor version. Gate static:S7-entry-capability-delta, CONTRIBUTING first.

R4 Predecessor facts: option (a): the proxy computes the fileFacts summary for main/bin on every download (not only armed ones) and stores it per served version in the witness store; retention and cold start stated. Its added cost per download is measured by ops; the 50 ms bar applies.

R5 Tree: the proxy mirrors recon's static-checks-1.4 from v6.12 byte for byte when recon hands over the constants; the version string stays held until then.

R6 Release commit: 3973224 is retired; Stage A reruns on the final commit; v3.2 waits and changes nothing.

Build now, tests first: the trigger addition (R1); the per-version facts store (R4); S7's runtime path and S6's plumbing against the held copy of the vocabulary, to be aligned to recon's 1.4 constants when they arrive. Naming edits only after the operator's naming ruling on the re-measure.

## Operator rulings 2026-10-22 (relayed by the review session; operator "Agree with your lean" on review verdict 4; the records are chaingate-ops `tarball-scan-1.3` @db98a29, handover 11.5; ops carries this text into the handover section 12)

R7 Naming on the static-checks-1.4 re-measure. S0 stays NAMED; its 1.4 wording is measured (0 new benign fires on B2 and compromised_lib, 813 newly reached on malicious_intent, 785 by no other check). S6 network-only beacon is NAMED as INDICATOR: B2 0/19,617 benign, malicious_intent 2,931/24,890 (2,804 by no other check), not-checked 5/19,622 on B2; compromised_lib 0/1,031 is recorded beside it as a fact (a beacon check; compromised libraries carry payloads). The three naming edits (`seed/v3/policy.js` NAMED_RUNNER_GATES, `proxy/notice.js`, out of CONTRIBUTING_GATES in `gates/row-class.js`) land once, together with S7's under R9, after the static-checks-1.5 mirror. Policy identity stays cft-policy-1.2.

R8 The 50 ms bar on the re-measure is read on the driver's check time with the facts summary counted once (11.5 "The p99 basis"): B2 33.9 ms, compromised_lib 46.3 / 42.6 ms, malicious_intent 8.0 ms; cleared. The earlier "facts + check 50.1 ms" counted the facts summary twice and is not the bar. Recorded beside it: 1.4 roughly doubles the 1.2 check p99 on B2 (15.4 -> 33.9 ms); the proxy's own per-download time (R4(a), stored per served version) is the confirming measure in the first week of 0.1.5, reported by ops.

R9 S7 entry capability delta is NAMED on subset (d) only; all-gains stays a recorded fact (12.6 per 10k on B2 fails the bar). Named condition: the predecessor's same-role entry facts were read and non-empty (the role READ on both sides), and the gain set in that role either contains a decode or obfuscation class other than decode:Function (R9a), or contains both an API network sink and an execution sink other than exec:Function (R9b). The net+exec arm stays: it costs no benign row on any set and adds one malicious_intent row (npmamzs 1.1.0; 11.5 R9a pass corrects the earlier "adds none"). Every other gain is NONE; the full gain set, the predecessor version and predecessor_nonempty stay on the row as facts. This is a vocabulary change: recon v6.13 = static-checks-1.5, failing-first, recon first, proxy mirror second with the identical version string and constants, then the naming edits for S6 and S7 together. Verification is the stored S7 hit rows only (23 B2 + 54 compromised_lib + 68 malicious_intent): v6.13 fires on exactly the rows the 11.5 R9a pass gives for this condition (B2 2 = @firebase/database 0.2.2-0 and @velcro/runtime 0.7.0, about 1.1 per 10k; compromised_lib 17; malicious_intent 28, the 27 decode/obf rows plus npmamzs 1.1.0) and on no other; no full re-measure. Recorded: the runtime predecessor (R3, the last version this proxy served) is not the measured one (FU-2 lineage predecessor); the 541 and 10,315 absent predecessors are registry removals that do not arise at runtime; 3.8 per 10k on 7 rows has a 95% interval of 1.5 to 7.9 and the first-week runtime count confirms or retracts.

R9a (closed; operator "Yes proceed" 2026-10-22 on the review lean, after the 11.5 R9a pass at chaingate-ops 3f7852a): the decode/obfuscation arm of the named condition is every decode:* or obf:* class except decode:Function (decode:eval, decode:atob, decode:numeric-hex, obf:_0x-idents and any later class stay). Why: taking out decode:Function removes 5 of the 7 benign B2 (d) rows (the Function decode+exec pair a bundler adds) and no malicious row on either set; taking out decode:eval as well would remove 1 more benign row and 24 of malicious_intent's 27 (eval gains). The S7 row keeps the full gain set as a fact, Function included, so the exclusion is visible in `why`.

R9b (operator "Yes proceed with your lean" to ops, 2026-10-22, on ops' check at chaingate-ops 31f501d; written in the handover section 12 at f8688d0): in the net+exec arm of R9's named condition, exec:Function does not count as the execution sink. Why: with decode:Function out of the decode arm, the net+exec arm alone would fire @wiris/mathtype-tinymce6 8.2.2 on B2 (main gained decode:Function, exec:Function, net:websocket), giving B2 3 rows (1.6 per 10k) instead of the 2 R9 states. With exec:Function out of the exec arm as well the counts are the stated 2 / 17 / 28, recomputed from the same stored rows; no compromised_lib or malicious_intent net+exec row rests on exec:Function (npmamzs 1.1.0 rests on exec:child_process). So the Function constructor is excluded on both arms and stays on the row as a fact.

R10 Disk (14 GB free against the 50 GB floor). Order: the DataDog sample zips first, each zip's sha256 and size in the inventory before it goes (re-downloadable and verifiable); the measurement work dirs (work-mi-1.3, work-cl-r3, the B2 stream work) stay until R9's hit-row verification is done, and before they go, work/index.jsonl, work/pred-facts.jsonl, the per-row results of the three runs and the repacked tarballs of the 145 S7 hit rows are copied to a kept directory npm cannot resolve (no package.json above it, no node_modules path), sizes recorded. Inventory first; every deletion on the operator's go, per the 11.5 rule. The merge of tarball-scan-1.3 to main is the operator's act; it carries no live-service change.

Build now, tests first (0.1.5 owner): nothing until recon hands over the static-checks-1.5 constants; then the mirror, then the six naming edits (S6, S7) in one commit, then the full suite on a non-root host and the release checks on the final commit. Recon lane: v6.13 after R9a, hit-row verification with ops' stored rows, swap only after both.

## Built state at 5e2b5bc (2026-10-22; candidate final commit)

5e2b5bc is the candidate final code commit for 0.1.5: no code change is planned after it. Under R6, Stage A and the v3.2
re-qualification run against the final commit. The README and release notes still land after 5e2b5bc, and README.md ships in the
package, so the release commit that carries them is named here, with its tarball sha256, before the release checks start.

- Reverts (`84733e6`, `d7508fc`): the deferred facts-only walk (`a23ae45`, `8a341b7`) is reverted; the tree matched `4d5675b` after
  them. The first download walks in-stream; up to 6 main/bin bodies are kept under the 1 MiB cap; the facts summary and the witness
  write run after the response; a file over 1 MiB or a refused archive makes the next S7 NOT_CHECKED; a facts-only walk that falls
  behind is recorded as not read and retried.
- static-checks-1.4 (`2492ca3` tests, `3c64c30` mirror): recon's v6.12 tree mirrored under R5. Superseded by 1.5 below.
- static-checks-1.5 (`dbafc80` tests, `1b56f36` mirror): recon's v6.13 mirrored under R9, R9a and R9b with the identical version
  string `static-checks-1.5`. The hand-off file is `static-checks-1.5-constants.json`, sha256
  `d78fa156630f220c3f711676944520215c3a07e1f7872a431464a6cb1537de83`. `test/proxy/cft015-static-checks-parity.test.js` pins the
  version string, the constant tables, CHECKS and the 16 S7 vectors against it. S7's named condition is `s7Named`: the role READ and
  non-empty on both sides, and a gain that is a decode:* or obf:* class other than decode:Function, or an API network sink together
  with an execution sink other than exec:Function. The full gain set, the predecessor version and the basis ("the version this proxy
  served before") stay on the row as facts, Function included.
- Naming (`a961274` tests, `0c97c05`): S6 and S7 added to `seed/v3/policy.js` NAMED_RUNNER_GATES, both notice labels added in
  `proxy/notice.js`, both removed from CONTRIBUTING_GATES in `gates/row-class.js`. S6 is named as INDICATOR. The policy identity stays
  `cft-policy-1.2`. `5e2b5bc` updates two remaining test pins that still treated S6 and S7 as contributing.
- R8 facts time (`c906e78` tests, `c016fe5`): the proxy times `entryFactsOf` (the fileFacts summary over the kept entry files, the
  driver's facts basis) and stores it in milliseconds as `facts_ms` on `entry_fact_versions`, one row per served version. An existing
  witness store gains the column on open (a guarded ALTER TABLE); rows written before it read NULL. To read the first-week numbers
  from the proxy's witness store (default `~/.chaingate/witness.db`, or `CHAINGATE_WITNESS_DB`):

      sqlite3 ~/.chaingate/witness.db "SELECT package_name, version, served_at, walk, facts_ms
        FROM entry_fact_versions WHERE facts_ms IS NOT NULL ORDER BY served_at"

  The p99 is read over `facts_ms` from those rows; the 50 ms bar applies (R4, R8).
- Full suite at 5e2b5bc on a non-root host: 1,571 tests, 1,530 pass, 0 fail, 41 skipped; protected paths unchanged. All commits
  signed.

Next, on the operator's word: recon's v6.13 swap, then the README and release notes, then the release checks on the final commit,
then the final commit and its tarball sha256 go once to the v3.2 session, which re-issues against them (R6).

## Operator ruling 2026-10-24 (R11; relayed by the review session: "Yes I want in 0.1.5", form "Shadow first")

The "After 0.1.5" backlog line of c69a252 is superseded by this ruling.

R11 The triage chat's noise-reduction rules (chaingate-ops `g10-c2-pin-admission-1.1` @af922e7, `docs/design/triage-noise-rules-20261023.md`, section B's static-checks list) enter 0.1.5 as SHADOW FACTS: each rule is computed and recorded on the row, visible in `why` and `report`, and changes no verdict, no tier and no notice in 0.1.5. Re-tiering on any of them is a later ruling, after the first weeks live and ops' lead-time replay against the 141 takeover packages (section D), which is the recall gate the document itself names. Consequences: 5e2b5bc is no longer the final code commit; the final code commit is named after this work; the v3.2 re-issue (R6) waits for it; `cft-policy-1.2` is unchanged (no arithmetic change); the section 6 bars do not apply to a fact that changes no outcome, but each fact's benign frequency is read from the witness store in the first weeks, beside the R8 numbers.

Division (each session carries its own task):
- (a) Recon lane: static-checks-1.6, a facts-only bump, S0-S7 outcomes identical by construction. Facts: rule 6 (per base64/hex run: distinct-character count, and the magic of the decoded first bytes: `\0asm`, PNG, gzip, woff); rule 7 (an S5 target: base64 share of the file and the decoded magic); 8a (P2/P9-type hits under `test/`, `__tests__/`, `fixtures/`, `vendor/`, `node_modules/` counted separately from the rest); 8d (a hook or module that writes under `~/.claude`, `~/.cursor`, `~/.codex`, `~/.config/<agent>`: a named capability fact); 8h (a tarball with zero network, filesystem, process, env, exec or encoding tokens: "no I/O surface"). After the v6.13 swap, recon first; outcome identity shown by drift 0 on ops' stored rows and on the frozen 28; the proxy mirror second, byte for byte, identical version string.
- (b) 0.1.5 owner: runtime facts computed outside `proxy/static-checks.js` (the mirror stays byte for byte), tests first. Facts: rule 3 (the served version is not the `latest` dist-tag, and which tag it is); rule 5 transition half (a named sign on this version was already present on the version this proxy served before: "not new since <version>", from the witness store); rule 8 packument half (the publisher is a known owner: a listed maintainer, the same email as a prior publisher, or the majority historical publisher; the token-delta half is S7's gain set, already on the row); 8b (the size change attributed to docs, source maps, declaration files or a second module format). Shown in `why` and `report` as facts; nothing added to NAMED_RUNNER_GATES or CONTRIBUTING_GATES; then the 1.6 mirror when recon hands over the constants; then the new final code commit is named here.
- (c) Ops: the 1.6 drift check against 1.5 on the stored rows (S0-S7 identical, the new fact fields listed); the section D replay unchanged, as the recall gate for any later re-tier; the facts' first-week frequencies read beside R8.
- (d) v3.2: nothing until the new final code commit is named; then the R6 re-issue against it.

Order: recon's v6.13 swap (unchanged, now) -> owner (b) and recon (a) in parallel -> the 1.6 mirror -> the final code commit named -> README and release notes -> release checks -> v3.2 re-issue. No deadline (operator).

## R11 part (b) built (2026-10-25, 0.1.5 owner; operator confirmed R11 and the defaults directly)

- Tests first `219fecc` (one miscounted fixture size corrected in `7210dae`); code `ca67eef`, `f6088ce` (the publisher-text filter
  written with escapes, G4-5); `b3bfb0d` updates G2c-9 deliberately (a facts event follows its first download's walk, so it is
  compared as a set).
- `proxy/shadow-facts.js`, `shadow-facts-1.0`, outside `proxy/static-checks.js`. Per served version, once, after its first
  download's rows are final, stored in `entry_fact_versions.shadow` (and the file sizes by class in `entry_fact_versions.shape`):
  rule 3 (the registry's dist-tags: latest or not, which tags point at it); rule 5 transition half (each named sign on this version,
  new or "not new since" the version this proxy served before; the named list is `classify()` over the stored rows); rule 8
  packument half (known owner = a listed maintainer in the packument `maintainers`, an earlier publisher by e-mail, else by name, or
  more than half of the earlier versions' publisher; the fourth form, other packages in scope, is not computed); 8b (the size change
  vs the version served before by class: docs, source maps, declarations, a second module format only when this version ships both a
  CommonJS and an ES module form, other files; the root package.json not counted; "all attributed" when other files are unchanged).
- Shown: `why <pkg>@<ver>` prints "Recorded facts" under the rows (`--json`: `shadow_facts`); `report --json` carries a `facts` event
  per served version; the report text lists only versions with a notable fact. Not a runner row, nothing added to NAMED_RUNNER_GATES
  or CONTRIBUTING_GATES, no exit code changes; `cft-policy-1.2` unchanged.
- Retention as the entry facts (the newest 3 served versions per package). First-week frequencies from witness.db:

      sqlite3 ~/.chaingate/witness.db "SELECT package_name, version, shadow FROM entry_fact_versions WHERE shadow IS NOT NULL"

- Full suite at `b3bfb0d` on a non-root host, Node 22.23.4: 1,585 tests, 1,544 pass, 0 fail, 41 skipped; protected paths unchanged.
- Next: the static-checks-1.6 mirror when recon hands over the constants; then the final code commit is named here.
