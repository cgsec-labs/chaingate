# Consult: chaingate-eval-1.1 rules, draft r1 (review session, 2026-11-01)

Asked by ops on the operator's "proceed with the eval 1.1", confirmed with the operator before this was committed. Verdicts on the r1
section (sha256 dc7b130b..., DERIVATION.md "eval-1.1 - rules r1"), written before anything is built or scored. 1.0's rows, rules and
split stay frozen (set 44db418e, Stage 7 155010fc); 1.1 only adds. Counts are ops' read-only PROD facts. Leans are leans; the operator
approves the 1.1 manifest by sha.

## Per rule

- **T1 N-TRIAGE.** Agreed: triage's benign verdicts, version-level and held, 127 rows with benign-capability (3) as a subclass; the 30
  never-captured and the 6 unpublish-event rows listed, not scored; the seed as of the version's own publish, as Stage 7. Three
  conditions. (a) The verdict ledger and its correction enter the manifest by sha, with the verdict date on every row; these are the
  triage sessions' judgments, not ground truth, and the manifest says so. (b) Labels are re-read at scoring time: a row OSV labels
  malicious after the verdict leaves N-TRIAGE and is listed with the label, never scored as a negative. (c) With 127 rows, "per 10k"
  is one false positive = 79 per 10k. Report every N-TRIAGE figure as a count with a 95 percent interval beside the per-10k form, and
  say in the rules that any set under 1,000 rows is reported that way. N-TRIAGE rows were leads, so a high named rate on them is the
  expected shape of a hard-negative set, and the text says so before the number.
- **T2 P-triage.** Agreed on the rows: 7 held beacons scorable, kind as a column, probes reported and never in a harm claim, the 29
  never-captured listed, the conx3993 package-level rows entering only if held, notsemz scored internally and never published. One
  addition that decides Q1 and Q3 below: **P-triage is selected by the detector.** Every row is there because a ChainGate lead was read
  by triage, so its recall under ChainGate is not an estimate of anything; it is a count of cases the system found. The set's value is
  lead time, not recall: for each row, capture time, first signal and detector version, triage verdict time, and the public advisory
  time or "no public advisory as of <manifest date>". Report those; report recall only as a count, never a percentage or a macro.
- **T3 P-ghsa P-NEW fix.** Agreed: the earliest labelled non-placeholder version held, 34 packages scored, 209 excluded with the stated
  reason. Two conditions: the GHSA record must actually name the chosen version (range or list), recorded on the row; and the class
  follows the lineage rule of record (a benign predecessor in the corpus makes it P-HIST, else P-NEW), since a taken-over package
  later replaced by npm's placeholder is often P-HIST in truth.
- **T4 split.** Agreed as the rule applied honestly; see Q3.
- **T5 not in 1.1.** Agreed. Case-insensitive name matching is its own check with its own measurement; full GuardDog and the tarball
  checks wait for the sandbox host.
- **Scoring and outputs.** Agreed: the Stage 7 harness and rules r2 unchanged, run only on the new and changed rows, 1.0's figures never
  re-run. The 1.1 manifest names the 1.0 set manifest and the Stage 7 manifest by sha, and every 1.1 figure names its set and version.

## Addendum from ops (candidate s61-MANIFEST b433ce7b, snapshot 2026-11-01 17:46Z, nothing scored)

P-triage is EMPTY: of triage's malicious packages, 9 are already in 1.0's P-osv as the October `0.0.0-*` placeholder wave, class
manipulated-history, excluded by 1.0's rule; the other 15 were never captured. N-TRIAGE is 127 as drafted (5 unpublish rows listed, one
unresolved). T3 gives 34 rows a real labelled version, 209 excluded. So Q1 is moot and the T2 text above describes a set with no rows;
the lead-time columns it asks for remain the right design for the day a triage-found row is held.

## The questions

- **Q1.** Moot: no P-triage set in 1.1. If a later version has rows, the T2 rule applies unchanged.
- **Q4 (new).** RULED by the operator, 2026-11-01, on this lean: **yes, add a reported class for the manipulated-history
  dependency-confusion wave**, as its own set (say `P-DC-1.1`), scored on its own and never merged into P-HIST or any 1.0 figure. Why: it is
  a real, current attack class that both triage and OSV saw, and 1.0 excludes it by construction, so today the record says nothing
  about the one shape the install-hook beacon checks were built for. What it measures is different from P-HIST and the text must say
  so: these packages have no benign predecessor and squat internal names with placeholder versions, so every history rule is silent by
  design and a coverage WARN alone is not protection (Stage 7 rule); the only named path is a tarball check on the hook (S0, S6 and the
  DNS arm). The figure is therefore "named static check fired at install" on this class, reported as a count with the kind column
  (beacon or probe) and triage's harm statement (probes: no reach) beside it, never as "attacks prevented". Rows: the held versions of
  the 9 (triage leads were captured, so most should be held), each with the OSV MAL id, capture time, first signal and detector version;
  the never-captured listed. Baselines on the same rows as in Stage 7, so the lead over B1 is visible for a class where OSV labels
  arrive by package. Alternative, if the operator prefers 1.0's silence: keep the exclusion and add one line to the record that the wave
  exists, is excluded, and why.
- **Q2.** Count the 3 benign-capability rows as N-TRIAGE negatives, broken out as the subclass on every figure. They are benign, so a
  warning on them is a false positive; they are also the rows where a warning is most defensible, so the reader sees them apart.
- **Q3.** All-holdout is right by the rule, and the worry is backwards. Nothing in 1.1 tunes anything (rules r2 are frozen), so tuning
  "never seeing" them costs nothing. The real caveat is the one in T2: the set is detector-selected, so its placement cannot make its
  recall meaningful either way. State both.
