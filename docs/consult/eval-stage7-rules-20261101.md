# Consult: chaingate-eval-1.0 Stage 7 recall rules, draft r1 (review session, 2026-11-01)

Asked by ops. Verdicts on the r1 rules as sent (section sha256 05710864..., DERIVATION.md Stage 7), written before any recall
number exists. The frozen set is manifest r2 44db418e, approved by the operator; nothing below touches a row, a rule or the split.
A rule changed after a number is seen is a new rules version with both kept, as ops states. Leans are leans; the operator rules on
O7-1 and O7-2 and on the headline choices.

## Per bullet

1. **Unit.** Agreed. State in the rules how t_star is read (the first malicious version's `published_at` from the Stage 1 export),
   because every baseline and every lag below is measured from it.
2. **Install-time model.** Agreed on the grid d in {1 h, 24 h, 72 h, 7 d}, every figure per d. Headline d = 24 h, see Q2.
3. **B0.** Agreed. Note the direction of its bias: `vanished_at` is when the collector observed the removal, so it is at or after
   the true removal, and B0 is understated by up to one poll interval. Say so beside B1's bias, which runs the other way.
4. **B1.** Agreed, including "earliest possible time favours the baseline, so the margin is a lower bound". Rows whose advisory
   cannot be dated are reported as a count, never silently dropped.
5. **B2.** Agreed. Two things the script asserts rather than finds: B2(d) = B1(max(d, 72 h)) by construction, so for d >= 72 h the
   two are equal; and the friction is every update delayed, with the delay distribution reported.
6. **B3 (O7-1, operator).** Lean (a) now, (b) named as later work, never (c). Condition: the figure is called "GuardDog metadata
   rules (subset)", never "GuardDog", and the rules run are listed by name in the manifest. Full GuardDog waits for the sandbox host.
7. **CG-detect and CG-full.** Agreed on the method (the triage-replay one-package seed from PROD rows before t_star, no pins, no
   labels; the published v3.3 never touches a positive). Five additions:
   - **Protection is a named gate, never the coverage gate.** A WARN produced only by `on_no_evidence` (coverage, insufficient
     history, no bucket) is what every unknown package gets; it is not detection. Count it separately as "no-evidence WARN" on
     positives and as friction on every negative set. A row the Part B re-tier shows as a NOTE is not protected either. Protected =
     a named gate (pin, channel-A critical, DAC surface, install-introduced, a named static check, the dependency rules) fired
     BLOCK or WARN; both reported, BLOCK alone also given, as drafted.
   - **Rules that read other packages.** A one-package seed cannot evaluate any rule that reads another package's rows
     (dependency hooks, the non-registry dependency rule, dep_names). List those rules in the manifest; in CG-detect they are SKIP
     and not protected, and the number of positives where only such a rule would have fired is reported as the bound this costs.
   - **Seed lag.** Add L = 1 d to {0, 7 d}. The v3.4 freshness decision (F1) is between a daily delta and a weekly full seed, so
     the daily figure is the one it needs; L = 0 is the upper bound, L = 7 d the current cadence.
   - **Feed lag in CG-full.** Use advisory public + 2 h, not + 1 h: the cut is hourly and the client's refresh is hourly, so the
     worst case is two hours. Report + 1 h beside it if cheap, labelled "cut lag only".
   - **O7-2 (operator).** Lean: run 0.1.6's own checker.js under node on the one-package seed. It measures the shipped runtime,
     and the Part B re-tier changes decisions that the 0.1.4-equivalence tests do not cover. The Python equivalence stays a cross
     check, not the measurement. CG-detect is not reported until one of the two holds, as drafted.
8. **Holdout headline.** Yes, see Q1: macro recall@campaign (mean over campaigns of per-row recall) is the headline. Beside it,
   replace campaign-any with **campaign-first**: whether the campaign's earliest-t_star row is protected. That is the figure lead
   time means (catching the first release protects everyone after), and campaign-any rewards one lucky late row. Keep campaign-any
   only if it costs nothing. Micro beside both, with the 2026-W21 share named (29 of 51 P-osv P-HIST holdout rows). Tune split:
   micro and macro, as drafted.
9. **False positives.** Agreed, with the mirror of 7: an FP is a NAMED WARN or BLOCK on a benign version, under the same as-of rule;
   the no-evidence WARN rate on each negative set is reported beside it as friction, where it will be highest on N-SAME's early
   versions. N-TRIAGE is stated as not sourced in 1.0. See Q3 for the N-SAME seed.
10. **Lead time.** Agreed: CG-detect 0 by definition, B1 = advisory public minus published_at, the distribution not only the
    median. Add the lead time of CG-full on rows where CG-detect missed (that is the feed's lead time), and the count of rows whose
    advisory could not be dated.
11. **Value statement.** Agreed on the form. Report the margin twice: over the best single free baseline (max of B1, B2, B3m per
    set) and over their per-row union, the stricter "all free tools together" figure. No claim beyond that, as drafted.
12. **Outputs.** Agreed. One requirement on `s7-rows.jsonl`: every row carries the times that explain it (published_at, capture
    time, CG first signal and its detector version, pin time, OSV and GHSA `published`, vanished_at) and which gate or baseline
    protected it. Then the per-incident timeline is a projection of the file, not a second derivation. The rules document's sha
    goes into s7-MANIFEST.json beside the inputs' digests.

## The three questions

- **Q1.** Yes: macro recall@campaign is what addendum 2 meant by "one unit per campaign". Campaign-first beside it, per 8.
- **Q2.** Lean: keep d = 24 h as the headline, because it is the conservative one against ChainGate and the one a reader will
  believe; always print d = 1 h beside it as the lead-time figure, since the whole margin over B1 lives there. The operator may
  prefer 1 h as the headline; both are defensible, so the rules name one and print both.
- **Q3.** As written: the seed as of the negative version's own publish time. A seed as of t_star would hold versions published
  after the benign one, which no user could have had; and own-publish is the same as-of rule the positives use, so the FP and the
  recall figures are comparable. Both as-of-own-publish and as-of-t_star stay ruled out for the published v3.3 seed, for leakage.
