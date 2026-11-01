# Consult: pin-on-label in the capture lane (review session, 2026-11-01)

Asked by ops on the operator's "proceed" on ops' lean. Context: the forward holdout of bc57897 needs its inputs to outlive the scoring,
but the capture store deletes unpinned tarballs after 14 days and unpinned rows after 30, and the rolling 35 GB store can evict earlier;
OSV labels often land days after capture. F3 is corrected accordingly (recon runs the frozen arm daily, in memory, on every own-bytes
placeholder-shape capture after 18:35Z, before any label; bytes that expire first count as not checked). Proposal: when a malware label
appears for a version whose capture is stored and on disk, set `pinned` on the row so neither retention nor eviction removes it; no new
bytes fetched; built by the watcher lane in a worktree, failing-first, full suite, signed merge. The operator rules.

## Q1 Sound as scoped: yes, with three conditions

The pin changes one thing, a deletion rule. It fetches nothing, publishes nothing, copies nothing, extracts nothing; the live-malware
handling (on host only, never published, copied or extracted; RULEBOOK D7) is untouched because no byte moves. Conditions:

1. **Mechanical and recorded.** The pin is set by the label reader when the label lands, never by a person, and every pin is one
   append-only line: name, version, tarball sha256, label id, label time, pin time. A pin that cannot be explained by a label is a defect.
2. **Row and bytes together.** `pinned` protects the tarball from the 14-day and eviction rules AND the row from the 30-day rule; a row
   without its bytes or bytes without their row is worthless to an auditor.
3. **Count what the pin arrived too late for.** Every label that lands after its capture was already evicted or expired is counted and
   listed ("label after eviction"). That number is the loss the current retention causes and the honest size of the archive question.

## Q2 Unpin: never automatically; only on the operator's word

A labelled tarball is evidence, and the forward holdout is only its first use (re-check, a corrected arm, eval-1.2, an auditor; R1). The
only ground to unpin is a label withdrawn upstream, and even then the unpin waits for the withdrawal to be recorded and the operator to
say so. No N-day rule, no unpin at judging.

## Q3 Scope: every stored capture the label rule marks malicious, not only the placeholder shape

Three reasons. The labelled tier is the permanent tier of the archive the operator parked, by its own design. Restricting the pin to the
shape today's arm targets pre-selects tomorrow's evidence to today's hypothesis and biases every later arm's holdout. The cost
difference is small: tens of versions a month at 5 MiB or less. "Malware label" means what label rule 2 marks malicious (MAL ids and the
GHSA records it accepts), so the pin and the eval set agree on what a positive is.

## Q4 The freeze and the "nothing is built" line

It does not touch the detector: no rule, no vocabulary, no decision, no notice, no change to what is captured or scanned. But it IS a
build in the window: code, tests, a merge in the capture lane. Say so rather than argue it away: record it as the one exception to the
window's "nothing is built", with its reason (preserving the holdout's inputs) and the operator's ruling, so the freeze's record stays
honest. Condition: the change must not alter the capture selector or the scan cohort; a test asserts that the set of versions captured
and scanned is identical with and without the change.

## Q5 Store cap: a ceiling with an alert, never an automatic unpin

- Pinned bytes at most 20 percent of the store (7 GB of 35 GB): at tens of versions a month under 5 MiB each, that is more than a year.
- Past the ceiling: alert to the operator, no unpin, the unpinned working set shrinks. The daily status line prints pinned count and bytes.
- A second alert when the unpinned headroom falls under one day's capture volume, so pins can never starve capture silently.

Not proposed and rightly so: a shadow arm column in the capture scan. It would duplicate recon's run and is the go-live build the arm has
not earned. Recon measures, the capture lane preserves, ops scores on approval.

## Addendum: the watcher's code facts and ops' two questions (same evening)

Verified on the ops main: `retention()` (collector/npm_capture.py 1185) expires and deletes only rows `NOT pinned`, and `evict()` (1288)
selects only `NOT pinned` tarballs. So the change is exactly "set pinned", no delete path changes, no migration. Condition 2 above (row
and bytes together) is therefore already how the store behaves; the test asserts it rather than builds it.

- **Ceiling: 10 percent of the store cap, as the watcher proposes, in place of my 20.** The watcher's risk is the decisive fact: pinned
  bytes count toward the footprint cap and can never be evicted, so pins approaching the cap would pause ALL tarball capture. 10 percent
  (3.5 GB) is about 700 tarballs at the 5 MiB bound, more than a year at tens a month, and leaves the working set its room.
- **A refused pin is an ALERT, not a log line.** A pin refused at the ceiling means evidence is about to be lost to retention while a
  label says it matters; that is a decision for a person (raise the ceiling, or accept the loss), never a line nobody reads. Log it as
  `pin_refused_ceiling` AND alert the operator; the daily status prints pinned count, pinned bytes and refused pins.
- **v1 pins on exact name and version only.** A version-less package-level label would pin every stored version of the package, benign
  earlier ones included, spending the ceiling on non-evidence and mislabelling it. List the version-less rows (package, label, stored
  versions) in the pass's output instead; a later version may pin them once a rule for "which version did the label mean" exists (the
  same question eval-1.1 T3 answered with a range match before the record's publish).
- The join reads what label rule 2 marks malicious (is_malicious), so the pin, the eval set and the seed's label input agree on what a
  positive is. The step runs in the hourly retention pass, before the expiry and eviction steps of the same pass, so a label that lands
  in the hour before expiry still pins.
