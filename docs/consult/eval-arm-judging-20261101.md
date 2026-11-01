# Consult: judging a candidate static arm when the eval's tune split holds no tarballs (review session, 2026-11-01)

Asked by ops. Context: on the operator's "yes, measure first", recon is measuring a candidate static arm for the P-DC-1.1 miss (a hook
target making a network request to a hard-coded non-registry host), tarballs read in memory only. RULEBOOK E1 says an arm is judged on
the eval of record, but (a) eval-1.0's tune split (313 rows) has no stored tarball, because capture began 10-14 after every tune attack
and most of those versions are unpublished; (b) the class the arm targets, P-DC-1.1, is holdout by rule, and recon read 4 of its 12
held tarballs while designing the arm; (c) the N-B2 index (19,937 benign tarballs) is on disk nowhere and would be re-fetched by sha.
Ops' options: (1) judge on false positives from re-fetched benign tarballs, report P-DC as "seen in design", freeze the arm and let the
forward wave be its holdout; (2) the same plus a forward-only holdout defined now. The operator rules; this is the lean.

## Lean: (2), with N = 20 and the conditions below

(1) is honest but leaves the arm with no recall figure that anyone can trust. (2) costs nothing now and is the only way this arm ever
gets an unbiased recall: the holdout is defined before a single forward row exists, so no later choice can shape it.

1. **The forward holdout, fixed now.** The first N = 20 dependency-confusion beacons captured after the freeze instant, where the class is
   defined today in writing (OSV-labelled malicious, the manipulated-history or placeholder shape as P-DC-1.1 defines it, the tarball
   held), taken strictly in capture order, none skipped. Judged when 20 are reached or on 1 December, whichever is first, reporting the
   count reached. Why 20: 0 of 20 bounds the arm's recall under about 14 percent at 95 percent confidence, which is a verdict; 15 of 20
   is a working arm; fewer rows say little, and more will not arrive in the window (October's whole wave gave 12 held).
2. **The arm is a shadow fact during the window.** It is recorded on captures and rescans by the capture lane, never a notice, never a
   row in s3 or the proxy, never a wording bump. The detector freeze stands; measuring on captures does not touch it. Going live later
   needs the standing rule as written: the four bars (benign at most 4 per 10k on B2, recall above zero on a labelled set, not-checked
   under 5 percent, p99 under 50 ms), the A5 replay (hidden 0 of 71), recon first and the proxy mirroring byte for byte.
3. **The eight P-DC rows not read in design are a small pre-holdout.** Of the 12 held, recon read 4; the other 8 were not. Report
   "fires on X of 8 not read in design" beside "fires on Y of 4 read in design", both labelled. It is weak evidence, but it is real and
   it exists today.
4. **False positives from re-fetched benign tarballs, three conditions.** (i) The re-fetched bytes must hash to the sha256 the index
   records; a mismatch excludes the row and is counted and listed, since npm tarballs are immutable and a mismatch is a fact about the
   index or the registry, never a reason to score the new bytes. (ii) Unpublished versions are listed with their count, not scored, and
   the figure's denominator is what was actually scored. (iii) The figure names its sets (N-POP-1.0 970, the N-B2 sample a140d6ff 5,000)
   and is a count with a 95 percent interval beside the per-10k form; the 4 per 10k bar is read against the interval, not the point.
5. **One line in the eval record.** eval-1.0's tune split holds no tarballs, so no static arm can be tuned on 1.0; every static arm from
   now on is judged forward. The remedy is the forward tarball archive the operator parked; this consult is a reason to reopen that
   decision after 1 December, not now.

Nothing here builds anything or changes a rule in the window. Recon measures, the capture lane records, ops scores on approval.
