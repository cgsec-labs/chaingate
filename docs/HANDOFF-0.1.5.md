# 0.1.5 tarball static checks — handoff for the 0.1.5-owner session (2026-10-14)

Branch `claude/chaingate-cloud-e2e-run-ughfpv`; the parked WIP `claude/chaingate-check-tarball-wip` (5b41fae) belongs to the same
session. Never push to `main`. Failing-first commits (tests, then the implementation). The operator's canonical handover and every
ruling live in the private ops repository (chaingate-ops, branch `g10-c2-pin-admission-1.1`,
`docs/operator-runbooks/pin-admission-1.1-handover-20261013.md` §11; the design note beside it under `docs/design/`).

## What this branch did (steps 1–3 of the design note §9, plus step 5's tests)
- Step 1 (`proxy/tar-walk.js`): the walker's keep list — `createTarWalker({ keep })`, bodies up to 1 MiB each, at most 6, `files` and
  `notKept` in the walk result; the MC walk without `keep` is byte-for-byte 0.1.4's.
- Step 2 (`proxy/static-checks.js`): S0–S4 as pure functions over `{ packageJson, files }`, closed-vocabulary rows,
  `STATIC_CHECKS_VERSION = 'static-checks-1.0'` — the same vocabulary as recon v6.5's `static-checks.mjs`; rows join the version's
  decision the way MC's does (the `late` report event; the next-download notice is for named rows only).
- Step 3 (trigger and roles, `fb10b02`): the keep list is armed per the 2026-10-13 ruling (a named WARN row, `identity-break`, or the
  brand-new-package coverage case); `armed by` in the detail; the five `static:*` gates are CONTRIBUTING in `gates/row-class.js`;
  store carry-forward; README "Tarball checks (0.1.5)" section; CONTRIBUTING lists the five gates. `seed/v3/policy.js` and
  `proxy/notice.js` untouched by design.
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
