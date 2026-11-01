# Consult: release gates 22, the 0.1.7 qualification and the ledger stand-in (review session, 2026-11-01)

Asked by the seed owner (v3.4 session) on the operator's go ("Yes proceed" for the 0.1.7 qualification; "Yes looks good to me" for the
stand-in plan, with this verdict before the merge). The operator relays.

## Verified from here

- The 0.1.7 candidate is the head of `claude/chaingate-0.1.6.1`, bd66b8f: the eight commits I verified at 4973b67 plus three signed
  docs-and-version commits (README, SEEDS.md, package.json and lock, one docs test), no code change. `npm pack` from bd66b8f
  reproduces tarball sha256 5fd781f5 exactly. It is not on main, not tagged and not published; gates 22 registers a candidate, as
  gates 19 did for 0.1.6 before its publish. If the branch moves again the registered tarball is stale and the gate must refuse it.
- `g10-release-gates-22` is NOT on the ops remote. The design verdict below is on the message; the four commits get "verified" only
  once pushed (signatures, failing-first order, the 11 stand-in tests fail-first, the DB-free suite in a worktree). Push before merge.
- The loss: no copy of PROPOSED-PIN-CHANGE-LEDGER-r1.tsv (96fc9511) exists; the label input a55ba06a, bound in the signed v3.3
  manifest, names that digest and carries 859 ledger_outcomes rows with every field a gate reads. I take both as the seed owner's
  record; the label-input digest itself I have seen bound in the published root and the feed header.

## Q1 Soundness and scope: sound, tightly scoped, four conditions

What the stand-in trusts is exactly what every other gate already trusts: the signed manifest binds the label input by digest, the
label input names the lost ledger by digest and carries the rows the build consumed. The chain reviewer file -> build input is the
one link that cannot be re-walked; everything downstream of the build input still is. Scoped to one digest, by table, with the
ruling in the entry: right.

1. **The table never grows without an operator ruling recorded in the entry**, and an entry applies only to a label input produced
   before the loss. State this beside the table. A stand-in for a future label input is a different decision, never a precedent.
2. **The verdict is never a plain PASS.** G-ADM's result string reads `PASS (ledger stand-in)` and the Stage A summary prints the
   stand-in and its not-rechecked items on the summary line, not only inside `info`. A reader of ten green rows must see it without
   opening the record.
3. **The 0.1.7 release notes say it.** The qualification record's sha goes in the notes as for 0.1.6, with one sentence: qualified
   with a ledger stand-in because the reviewer's ledger file was lost on 2026-11-01; the rows were read from the signed label input.
4. **The loss is an incident with a record and a rule.** The record: what was deleted, at what time, by which cleanup, under what
   inventory and go, and that no copy existed. The rule, for every cleanup by any lane from now on: before deletion, every file's
   sha256 is checked against every digest named in any signed manifest, label input, gate record or qualification record on the box,
   and a match stops the deletion. This is the condition that matters most; the stand-in repairs one file, the rule prevents the next.

## Q2 The not-rechecked items: add one, keep them in info, plus condition 2

(a) file digest equals the label input's ledger digest, (b) every row has an enforced outcome, (c) the applicability record's source is
that file: right. Add **(d) the reviewer's approval of the file cannot be re-verified against its bytes**; "owner-approved r1" now
rests on the recorded approval, not on the file, and the columns the gates do not read (reviewer, evidence, category, notes) are gone.
`info.ledger_standin.not_rechecked` is the right place for the list, never a check row, and condition 2 puts the fact on the summary.

## Q3 par-i-8: acceptable for 0.1.7 on v3.3, not for any new seed, stated as such

par-i-7 was independent: the expectation came from the reviewer's file, the seed from the build. par-i-8 derives the expectation from
the candidate's own label input, the same artifact the seed was built from, so it is a consistency check of build -> seed, not the
independent check. It is acceptable here for one reason only: the seed is unchanged. seed-v3.3-full already passed par-i-7 with the
real file in the 0.1.6 record (593630cf, 135,107 compared, 0 mismatches); par-i-8's job is to show the new runtime reads the same seed
identically, and 135,107 / 0 does that. Write in the 0.1.7 record that the reviewer -> seed link for v3.3 is established by 593630cf
and that par-i-8 is the consistency form. For v3.4 or any new seed, par-i-8 is not evidence; ledger r2 and par-i-7 are.

## Q4 Retained clients under v3.4 (flag, not this merge)

Two classes, because "ignore" is the wrong requirement for a client that can read the seed. **Retained non-readers** (0.1.5 and
earlier on a 1.3 seed): G-ONB as today, the selector ignores the release. **Retained readers** (0.1.6 on a 1.3 v3.4): the older-client
harness must show it reads the seed and, where the policy is the same (cft-policy-1.3 on both), decides identically to the current
client on the fixture set. That is a stronger check than ignoring, and it is the right one: a reader that decided differently would be
a silent fork of the product on one seed. Build the class for v3.4.

## Q5 Conditions on the next cut (ledger r2 and the four review directories)

1. **r2 re-affirms, it does not re-decide.** r2 reproduces r1's 859 outcomes exactly from the stand-in rows; the diff r2 minus stand-in
   on those 859 is empty, and every new row is new. Any changed outcome is listed by name and approved explicitly, never folded in.
2. **The four re-fetched review directories match the digests the label input records for them**, or the record states each
   difference. A re-fetch that differs is a fact about the source, not a reason to edit the digest.
3. **Everything a gate reads by digest lives in a tracked, backed-up place from now on**: the ops repository or the home store with a
   second copy, never only `~/artifacts`. The loss happened because the approved ledger lived in an untracked directory.
4. **The operator keeps a copy of r2** at approval time; r1 was never downloaded.
5. **The cleanup rule of Q1 condition 4 is in force before the next cut's artifacts exist.**
