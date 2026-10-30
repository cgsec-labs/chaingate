# Consult: W1.5q, scan a same-hook release when the package already fired (review session, 2026-10-30)

Asked by the watcher lane on the operator's "yes please, with the review consult first". Design verdict on the proposal as
described; the branch is not pushed, so nothing is verified against code.

## The gap, confirmed as stated

The capture worker stores a hooked version's tarball only when its hook command string is new for the package. A release that
keeps the command and changes the file it runs is never scanned. Two live cases show it: @pcb-dp/qa-commons 1.0.10 (the
collector address moved, same `node index.js`) and @zmtcdn/ui 9999.0.7, both `same_hook`, both unscanned after an earlier
version fired S6. About 2,700 to 4,200 versions a day are `same_hook`; 125 of them in the window, on 34 packages, belong to
packages that already fired a named check: about 12 a day.

## Verdict

Fit to build as described: the narrow cohort, install-level priority, no cap changes, a trailing `prior_hit` token, one pass-log
count. Four conditions and one measurement.

### Q1 Cohort

Right as a first step: any package with an `ok` scan row that fired a named check, any version, any static-checks version. No
time window; the cohort is 34 packages and a package that fired once stays interesting. Do not widen to contributing rows now.

**The measurement that decides the next step, read-only, in the same pass:** count the `same_hook` versions whose registry
`dist.unpackedSize` or `dist.fileCount` differs from the stored version's. Both fields come with the packument at no download
cost, and a changed hook-target file almost always moves one of them. If that count is a few hundred a day, the hook signature
can become (command, unpackedSize, fileCount) in a later change and close the stated limit "a package whose first hit is itself
same_hook" for most cases, within the tarball budget. Record the count for a week before proposing it.

### Q2 Priority

Install-level, as proposed. The package has fired; the 12 a day must not wait on the day's last gigabyte.

### Q3 Caps

No change to the per-package-version cap of 20 or the scope cap, as proposed. A campaign that publishes past 20 versions of one
package has shown its shape by then.

### Q4 The `prior_hit` token

Safe if every downstream reader of `tarball_reason` matches by token or by prefix, not by equality. Before merge, grep the readers
(recon's set-B `g:` tokens, the drift3 LIKE patterns, the alert and pass-log formatters) for an exact comparison against
`"install"` or `"gyp"`; one exact match is the one thing that would break. Append the token last, so prefix matches hold, and
list it in the capture schema note beside the other reasons.

### Q5 Backfill

No, as you lean: the two campaigns are held by the operator and triage has read the cases; the 125 would cost most of a day's
budget for versions already understood. The fix is forward-looking.

## Two things outside this change, recorded for their owners

- A `same_hook` release that fires on rescan (W1.5p) and a `prior_hit` capture that fires on first scan both reach the same
  alert and recon paths; the dedupe on package + version + sha512 covers both. No change needed; stated so nobody adds a second
  dedupe.
- The 9999.x shape (@zmtcdn/ui): a version far above the package's `latest`, the classic dependency-confusion marker, is a
  packument fact recon can record in a later bump ("version exceeds latest by N majors"). It is not part of this change, and it
  would be measured before it is ever named, like every other fact.

## Exit

Tests first, the branch pushed so the worker change and its tests can be verified, the first week's pass-log counts (prior_hit
stored; same_hook with changed size or file count) in the handover, merge on the operator's go.
