# Consult: corpus label fix, eval-redo Stage 5 rules, Stage 6 plan (review session, 2026-10-31)

Asked by ops on the operator's word ("consult and then handle"). Paper only. Facts F1 to F6 as ops recorded them
(~/artifacts/eval-redo-20261031/DERIVATION.md Stage 5) are taken as read; nothing here changes a served artifact.

## What the facts mean before the answers

Two things are good news and one is a correction to the record.

- The seed and the feed never carried the two mislabelled packages. The ledger removed them under "keyword or CWE heuristic match
  only" (category B), and the served feed has 0 rows for either. The pipeline's second line of defence did its job.
- The CFT-08 in-corpus set mixed 88 PyPI rows into npm figures through a join with no ecosystem filter; the npm-only figures are
  now stated (316 versions / 134 packages at 09-24, 311 / 137 today) and nothing left the corpus.
- The corpus's `attack_labels` carried @babel/traverse (148 version rows) and openclaw (60) as malware since the OSV backfill.
  Those rows were in the labelled set every base-rates run measured (1,133 versions, 879 evaluable, 174 packages). The "87
  percent" and the per-rule recalls in handover 7.1 and 7.3 are therefore over 174 packages of which 2 are not attacks. See Q2.

## Q1 Label code fix

Agreed, with two additions. The rule for a non-MAL id: malware only on CWE-506, 507, 509 or 512, or on a structured summary form
("Malicious code in <pkg>", "<pkg> is malware", "Embedded malware"); a summary containing "vulnerab" never matches on keywords
alone; MAL ids unchanged. Additions:

1. Every `attack_labels` row written by the backfill carries `label_rule_version` (the heuristic's version string), so a later
   change to the rule is a visible re-label and the eval set can state which rule produced each positive.
2. Failing-first from the two real records as the must-NOT-match cases, pandora-doomsday (GHSA-428f-mh7w-6w2x, "is malware",
   CWE-509) as the must-match case, and the canonical incident table of SEED_ARCHITECTURE.md section 4.2 (axios MAL-2026-2307,
   event-stream, ua-parser-js, node-ipc, rc, coa, debug, chalk, eslint-config-prettier) as regression cases that must still label.
   Before the backfill runs, a read-only dry run counts the rows the new rule flips, and that count is in the record.

Build in a worktree; merge on the operator's go.

## Q2 Data fix in PROD

Agreed: no row edits now. The ledger's REMOVE outcomes assume the rows exist, and the seed is unaffected either way. The corrected
backfill updates the two package rows on its next run; the 208 stale version rows go in one reviewed transaction coordinated with
v3.4's label input, as proposed.

One thing BEFORE that deletion, from the saved reports and without a re-run: restate base-rates-1.1 section 7.1 and base-rates-1.2
section 7.3 with the two packages excluded. `labelled_detail` carries each labelled package's fired set, so the per-package recall
numerators and the 174 / 108 denominators can be recomputed from the JSON on disk. Record the restated "any rule" ceiling and the
named-set recalls beside the originals with the set name `base-rates-1.1 labelled-172`. If either package counted as a miss, the
restated recalls rise slightly; if as a hit, they fall; either way the record should say which. Also confirm whether replay-131's T
(141 packages) contained either package; F3 and F4 suggest not, and the record should state it.

Do the restatement while the rows still exist, so the recomputation and the deletion are two separate, reviewable steps.

## Q3 Eval rules

R5a to R5e agreed as written. R5f agreed with one refinement: a ledger REMOVE excludes that VERSION from every positive set, not
the package. The six replay-131 cases split in two kinds, and the eval set should treat them differently:

- `@metamask/sdk`, `-communication-layer`, `-react` 0.16.0: "indirect exposure via debug@4.4.2". The package was not compromised;
  no version of it is a positive. Out.
- duckdb 1.3.3-dev0.0, @teselagen/file-utils 0.3.21-beta.1, range-utils 0.3.14-beta.1: version attribution errors on packages that
  WERE taken over. Under R5d the record's current versions apply, and DataDog names 1.3.3, 0.3.21 and 0.3.22, 0.3.14 and 0.3.15. These
  packages stay in P-HIST at the version a second column names, with the first malicious version re-derived from it; the ledger
  REMOVE of the pre-release label is honoured, the package is not lost.

Also: pandora-doomsday is a positive (CWE-509, "is malware"), so R5b's "2 packages" is right and the Stage 5 GHSA rule's correction
is recorded.

## Q4 Stage 6 plan

Agreed, with three small changes:

1. Campaign key: actor where known (publisher account or e-mail digest, or the attestation repository), else advisory family, plus
   the week. The payload family alone merges unrelated typosquat waves that reuse a public stealer.
2. The fixed random 20 percent of earlier campaigns for the holdout is drawn with a recorded seed, and the draw is in the
   manifest, so the holdout is reproducible and provably untouched.
3. N-POP by downloads is fine for an evaluation set (the seed's privacy stance is about publisher identities, not about download
   counts); state the download source and its date in the manifest. N-SAME before t_star, N-TRIAGE from the triage records, N-B2 by
   digest: as drafted.

Cutoff 2026-09-01 for the holdout is acceptable: the August waves tune, the September and October ones judge, and the next cutoff
moves forward as the archive adds captures. The manifest with every file's sha, the query shas and the snapshot time, approved by the
operator by sha, as drafted. Every number quoted from before the eval set keeps its original set name, as agreed on 10-31.

## Addendum, 2026-10-31 (ops' dry run changed the Q1 rule; no objection)

Ops ran the proposed Q1 rule read-only over all 22,117 stored package-level OSV labels. The structured-summary-only form I
suggested would have flipped 7 rows, 4 of them real malware with no malware CWE: @solana/web3.js GHSA-jcxm-7wvp-g6p5 ("Modified
package published to npm, containing malware ...", CWE-200) and three PyPI records (telnyx PYSEC-2026-3, num2words PYSEC-2025-72,
litellm PYSEC-2026-2, "published containing ... malware", no CWE). My wording was too narrow; it is withdrawn.

The rule as built (branch `ops-osv-label-rule-1` @79c3eae): MAL ids count as malware, unchanged; CWE-506, 507, 509 or 512 always
count; otherwise the original markers (malware, malicious code, typosquat, embedded malicious) count only when the summary does not
contain "vulnerab". Dry run: exactly 3 rows flip true to false (openclaw, @babel/traverse, babel-traverse), 0 flip false to true.
The four records above join pandora-doomsday and the section 4.2 incident table as must-match tests; `label_rule_version` and
`attack_name` are refreshed on re-label; migration `phase_label_rule_2` goes to PROD before the failing-first build. No objection:
the operator's merge go decides. The restatement in Q2 is over 172 packages as before (the two npm packages; babel-traverse is a
third label row, not a third labelled package in the base-rates set unless the saved reports say so, which ops checks).
