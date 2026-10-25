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

## static-checks-1.6 mirrored (2026-10-25, 0.1.5 owner; R11 (a) handed over by recon, (b) the walk input)

- Hand-off: recon v6.14 (branch `g10-c2-recon-v6.14` @90c2303, tree `tools/recon/v6.14`, `static-checks.mjs` 812cf94b), constants file
  sha256 c4c1e0c0 (65,128 bytes), committed byte for byte as `test/fixtures/cft015/static-checks-1.6-constants.json`. Ops' R11 (c)(1)
  drift check of 1.6 against 1.5 passed on 10-25 (handover 12.4).
- Tests first `95aa226`: the file's constants against the module's exports (regex source and flags), every 1.5 section unchanged, recon's
  41 vectors (10 encoded runs, 4 base64 shares at chunk sizes 1, 7 and 401, 17 member facts, 5 package blocks, 5 agent writes), the
  walker input, the store, `why` and `report`. The 1.5 version pins in six earlier test files move to 1.6 deliberately. Code `1966cd6`
  (it also narrows E2's plain-ASCII check to the facts block: other `why` lines predate it).
- `proxy/static-checks.js`: `STATIC_CHECKS_VERSION` is `static-checks-1.6`; recon's facts code is copied as written (`FACTS_LIMITS`,
  `FACTS_NOTE`, `DECODED_MAGIC`, `encodedRuns`, `makeBase64Share`, `EXCLUDED_PATH`, `DYNAMIC_CODE`, the agent dirs and write markers,
  `IO_CLASSES`, `IO_TOKENS`, `memberFacts`, `staticFacts`). Checked in code: the copy equals recon's block except that paths go through
  recon's clip with the proxy's control and bidi characters removed, and the 8000-byte head is read from `LIMITS`.
- The proxy's half (owner's choices, stated here for review):
  - Facts are read on an ARMED walk only, the walk whose static rows are computed (recon reads them on the flagged archive).
  - `proxy/tar-walk.js` gains `onMember(path, size, window)` (every regular file on the Linux view, its first 2 MiB; the caller keeps the
    last duplicate in the place of the first, as recon's tar reader) and `shareOf()` (a keep-list target over the 1 MiB cap is streamed
    whole through recon's base64 counter, its result on that not-kept entry). Without them the walk result is unchanged key for key.
  - `staticFactsOf` gives `{ facts, s5 }`: recon's block (hooks as S0 reads them, roles from the registry keep list, members only from a
    walk read in full) and, for each hook target over the cap, recon's S5 entry fields (`base64_share`, `base64_magic`, or the nulls and
    `base64_note`). They are stored once in `entry_fact_versions.static_facts` when the walk's rows are recorded. No row carries them: the
    S5 row text is unchanged.
  - At most 20,000 member records per walk (`MAX_FACTS_MEMBERS`; recon refuses an archive over 100,000 files); past it the block is
    NOT_CHECKED "more than 20000 archive members: member facts not kept".
- Shown: `why` prints "Static check facts (static-checks-1.6; recorded only: no verdict, tier or notice depends on it (operator ruling R11)):" under the recorded facts (`--json`: `static_facts`);
  the `report` facts event carries `static_facts`, and the report text lists an armed version with its static facts. No exit code changes.
- The version string changes S7's predecessor rule only for facts stored by a 1.5 build ("stored by static-checks-1.5, not
  static-checks-1.6"): no released build stores entry facts, so no user store is affected.
- Read from witness.db (armed walks only, not all downloads: a frequency read here is per armed walk):

      sqlite3 ~/.chaingate/witness.db "SELECT package_name, version, static_facts FROM entry_fact_versions WHERE static_facts IS NOT NULL"

- Full suite at `1966cd6` on a non-root host, Node 22.23.4: 1,603 tests, 1,562 pass, 0 fail, 41 skipped; protected paths unchanged.
- Candidate final code commit: `1966cd6`. It becomes final when recon's parity check against the 41 vectors passes on it. Then README
  and release notes, release checks, and the v3.2 re-issue (R6) against it.

## Recon parity on 1966cd6 (2026-10-25; named final at df1e9da, retired by R12 in the next section)

- Recon's parity check of the mirror PASSED (recon lane, 2026-10-25, on dc373ef; `proxy/static-checks.js` sha256 df56a279): the
  constants byte-equal to recon's (c4c1e0c0); the facts block equal to recon v6.14's line for line after the three declared
  substitutions; 42 shared non-function exports differ 0; 83 of 83 regex literals equal; the 41 vectors and the 16 S7 vectors pass on
  both sides (shares also at chunk sizes 3 and 64); a seeded random comparison over 3,000 packages (69,574 calls) differs 0. The one
  difference is the declared one: a path with control or bidi characters is shown stripped. The 20,000-member cap is a declared
  deviation (recon has none; its largest frozen case is 1,656 members).
- `1966cd6` was named the final code commit at df1e9da. The review session's verdict, sent before that naming reached it, made the
  armed-walk time a condition first, and the operator ruled it (R12): `1966cd6` is NOT the final code commit (next section).
- Recon v6.14 (static-checks-1.6) went live on 2026-10-25 at 10:38Z after this check and ops' drift check (12.4).

## Final code commit: 44113b7 (2026-10-25; operator ruling R12, the 1.6 cost timer)

- R12: 1966cd6 retired for the 1.6 cost timer, operator 2026-10-25.
- The review session accepted the three choices above (facts on armed walks only; stored in `static_facts`, never a row, the S5 row
  text unchanged; the 20,000-member cap with its NOT_CHECKED reason), with one condition, which the operator ruled (R12): measure
  what 1.6 adds to the armed path, as R8 did for R4. The member work runs inside the walker, synchronous on the event loop every
  other download shares, bounded by the 2 MiB window and `MAX_ARMED_WALKS`; recon measured memberFacts at about 1.5 s CPU on a 482 MB
  decompressed archive (16 percent more unit CPU).
- Tests first `083e6b2` (T1 to T3; W1 and W2 compare the walk result without the one added key). Code `44113b7`, touching
  `proxy/tar-walk.js`, `proxy/server.js` and `witness/db.js` only. `proxy/static-checks.js` is unchanged at sha256 df56a279, so
  recon's parity record on dc373ef stands and was not re-run.
- Timed, in milliseconds to three places: the walker's member windows (each file's first 2 MiB copied out), its `onMember` calls
  (recon's memberFacts) and its share counter's `push` and `end` calls (a hook target over the keep cap), as the walk result's
  `memberMs` (present only when either is given); the proxy adds `staticFactsOf`. The sum is stored once with the facts as
  `entry_fact_versions.static_facts_ms`, beside `facts_ms`; NULL on a version not walked armed (the column is added to an existing
  store on open). The facts block has no timing field; every row is unchanged.
- No bar is set on it in 0.1.5: the facts change no outcome. The first week gives the number and the operator rules on it.
- Sampling: the static facts and `static_facts_ms` are over ARMED walks only, not over all downloads; `facts_ms` (R8) is over every
  walk that read entry facts. The first-week read:

      sqlite3 ~/.chaingate/witness.db "SELECT package_name, version, served_at, facts_ms, static_facts_ms
        FROM entry_fact_versions WHERE static_facts_ms IS NOT NULL ORDER BY served_at"

- Full suite at `44113b7` on a non-root host, Node 22.23.4: 1,606 tests, 1,565 pass, 0 fail, 41 skipped; protected paths unchanged.
- Final code commit: `44113b7`. Every later commit is docs only (`docs/` is not in the npm package). The v3.2 re-issue (R6) is
  against `44113b7`.
- Next, each on the operator's word: README and release notes (the 2026-10-23 review note for README lines 175 and 181, now
  static-checks-1.6, the shadow facts and this time), the release commit and release checks, the package sha256 sent once to the
  v3.2 session.

## README for 0.1.5 (2026-10-25, on the operator's word)

- `fe77f8a`: S6 and S7 named beside S0 and S5 (what each reads, the four npm notice texts, the measurement basis over about
  19,600 ordinary versions and S7's runtime basis); entry-path-change arms the walk; `static-checks-1.6`; withholding on any named
  static check; the recorded facts (record only) and their timing columns; `check --tarball` reports S7 not applicable offline.
  This closes the 2026-10-23 review note for README lines 175 and 181.
- `ce2ca23`: the 0.1.5 test run line (Node.js 22.23.4, 1,606 tests, none failed, 41 skipped).
- `a5d3864`, test only (`test/` is not in the package): G4-14 pins that line; G2c-9 waits for the first install's facts events
  before the second install (it failed once under load in the full suite after `ce2ca23`: the last download's facts follow its
  response). The final code commit stays `44113b7`: nothing under `files` in package.json changed after it except README.md.
- Full suite at `a5d3864` after the push: 1,606 tests, 1,565 pass, 0 fail, 41 skipped; protected paths unchanged.
- The release notes draft is outside the repository. Next, each on the operator's word: the release commit and release checks,
  then the package sha256 once to the v3.2 session.

## Final code commit: ce64220 (2026-10-25; the operator, directly: plain wording in public text and runtime output)

- The operator asked that public text and what the runtime prints carry none of the project's internal naming. 44113b7 is
  retired for this; the final code commit is `ce64220`.
- Runtime (`a6d6e5e` tests, `ce64220`): `SHADOW_NOTE` no longer names a ruling. The proxy stores the static facts through
  `publicStaticFacts` (`proxy/shadow-facts.js`), which replaces the two notes recon's block carries (`facts.note` and
  `facts.excluded_paths.note`) with plain ones and changes nothing else. `proxy/static-checks.js` is unchanged at df56a279
  (`FACTS_NOTE` included), so recon's parity record stands. Stored, `why` (text and `--json`) and the report carry no internal
  wording (T4, T5).
- Docs: README and SECURITY.md in plain language (`4df8b68`; tests `91e4f66`), SEEDS.md without internal identifiers and
  without the unpublished engineering seed's record (`fec9019`; guard `71b1e34`, test D8).
- Full suite at `fec9019` on a non-root host, Node.js 22.23.4: 1,609 tests, 1,568 pass, 0 fail, 41 skipped; protected paths
  unchanged.
- Open with the operator: commit messages since v0.1.4 that name the internal plan (69 of 118) and this file itself, before
  anything reaches main.

## Final code commit: 7e981c8 (2026-10-25; the operator, directly: no internal codes in comments or printed text)

- ce64220 is retired for this. Comments: `1015b36`, 80 shipped files, comments only (checked: with comments stripped, every file's
  code equals the previous commit's; the one exception is witness/db.js, whose SQL `--` comment lines inside the schema text were
  reworded; node --check on every file). `proxy/static-checks.js` untouched (df56a279), so recon's parity record stands.
- Printed text (`c727bc6` tests, `7e981c8`): the placement reasons for a takedown stub, a release with no publication time and a
  CalVer collapse, the strict-tier threshold detail, and the two `on_*` choice explanations no longer name internal rule codes.
  The frozen goldens are unchanged and are compared through an explicit wording map (`test/seed-v3/cft015-plain-wording.mjs`);
  test D9 keeps the codes out of printed strings.
- Full suite at `7e981c8` on a non-root host, Node.js 22.23.4: 1,610 tests, 1,569 pass, 0 fail, 41 skipped; protected paths
  unchanged.
- Main: squash, as the operator chose; this file leaves the tree before the squash commit.

## Operator ruling 2026-10-25 (R13; relayed by the review session: "implement the suggestion", "Yes")

R13 Rule 4a of the triage noise-reduction consult, revision 2026-10-25 (chaingate-ops `g10-c2-pin-admission-1.1` @ac95df5, `docs/design/triage-noise-rules-20261023.md`), enters 0.1.5 as a SHADOW FACT under the R11 discipline: no verdict, tier or notice depends on it. 7e981c8 is no longer the final code commit; the final code commit is named after this work, and the R6 re-issue waits for it.

- (b) 0.1.5 owner, in `proxy/shadow-facts.js` (the mirrored module stays at df56a279), tests first: on an ARMED first download, after the response, fetch the attestation bundle from the registry (`/-/npm/v1/attestations/<pkg>@<ver>`), decode the DSSE payload, read `externalParameters.workflow.repository`, compare with the packument `repository` field, and record one of MATCH, MISMATCH, ABSENT (the version this proxy served before had an attestation and this one has none), NONE (neither has one), or NOT_FETCHED with the reason (non-200, timeout, undecodable). No signature verification and no commit-author lookup (recon-only). Stored with the recorded facts, shown in `why` and `report` as a fact in plain words ("repository claim matches, unverified" / "repository claim differs" / "provenance dropped"), the fetch time stored beside it as the other facts' times are. Then the new final code commit is named here; README's recorded-facts list gains the one line; non-root suite.
- (a) Recon lane, in parallel and outside the 0.1.5 package: the recon-only rules 1, 2, 4 in full, 8c, 8e, 8f, 8g as facts on the card first (no LOOK FIRST change), under the lane's own bump and swap procedure; re-tiering on any of them is a later ruling read against handover 12.3.
- (c) Ops: 4a's MATCH/MISMATCH/ABSENT counts join the facts read from the witness store in the first weeks of 0.1.5; nothing else changes.
- (d) v3.2: unchanged; the re-issue runs against the final code commit when it is named.

Coverage after R13: every rule of the consult is encoded as a fact: 6, 7, 8a, 8d, 8h in static-checks-1.6 (recon live, proxy mirror); 3, 5 (transition half), 8 (known-owner half), 8b and 4a in shadow-facts (proxy); 1, 2, 4, 8c, 8e-8g on recon's card. Nothing re-tiers in 0.1.5 (the recall gate, 12.3, stands). The consult's 10-25 status line ("3, 5, 8, 8b not encoded anywhere") is corrected by this record: they are in the proxy at ca67eef.

## Final code commit: c0b52d3 (2026-10-26; R13 part (b), the repository claim)

- 7e981c8 is retired for this. Tests `999f500` (failing first: 10 of 10), code `c0b52d3`. `proxy/static-checks.js` untouched
  (df56a279), so recon's parity record stands.
- Where: `proxy/shadow-facts.js` (`normRepoUrl`, `attestationRepository`, `repoClaimFact`, `repoClaimLine`, version
  `repo-claim-1.0`); the fetch in `proxy/registry.js` `fetchAttestationBundle`, through the one upstream call site; the store in
  `witness/db.js` (`entry_fact_versions.repo_claim` and `repo_claim_ms`, guarded ALTER for older tables); `why`, `report` and the
  report text show it; README's recorded-facts list has the one line.
- When: an armed version's first download, after its rows and shadow facts are recorded and its response is finished (`settled`);
  once per version. An unarmed version is never fetched.
- Compared as recon v6.15 does (chaingate-ops `g10-c2-recon-v6.15` @7cb4f58, `triage-facts.mjs` normRepoUrl/repoClaim): the same
  normal form (host/owner/repo, lower case), the first SLSA v1 or v0.2 statement, ABSENT/NONE read from `dist.attestations` with no
  fetch. The one planned difference: "previous" is the version this proxy served before, not recon's primary baseline.
- Bounds: 5 s for the whole request, 1 MiB (declared or streamed), 4 fetches in flight process-wide, no redirect, no user header
  relayed (the user's token is not sent). Every failure is NOT_FETCHED with its reason; nothing here can fail or delay a download.
- Full suite at `c0b52d3`'s tree on a non-root host, Node.js 22.23.4: 1,620 tests, 1,579 pass, 0 fail, 41 skipped; protected paths
  unchanged. (A first run failed one guard test, the single upstream call site; fixed before the commit.)
- Next, as before: the R6 re-issue against this commit (v3.2 session), then the release sequence; main is a squash.
