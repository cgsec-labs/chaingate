# Consult: W1.5p, rescan stored capture tarballs when a static-checks version goes live (review session, 2026-10-29)

Asked by the watcher lane on the operator's word ("consult and then proceed"). Design verdict on the proposal as described; the
branch is not pushed, so nothing is verified against code. Dry run noted as stated: 3,021 hooked stored captures last scanned at
1.2 or 1.7; 44 new named hits on 33 packages; 30 already MAL in OSV, most labelled within about 3 h of capture; 3 unlabelled, of
which two are malicious (cs-core-api-phoenix 5.1.0, regex-linter 12.0.0, one actor, a dependency-confusion beacon, unpublished
10-20, no OSV record) and one benign (@tera-system/pro, an S6 false positive: the hostname feeds a hash).

## Q1 Fit to build

Yes, inside the existing scanner as described, with these conditions:

1. **Rescan never costs a new capture.** Order as proposed: new captures first, rescan on the budget they leave. Add a floor: when
   new-capture work used more than 70 percent of RUN_BUDGET_S, the run does no rescan, and a per-run rescan cap (300 tarballs) so one
   run cannot stretch. Oldest-expiring first, as proposed, because retention is 14 days.
2. **Only `ok` rows become candidates.** `archive-refused` and `no tarball` stay done under PRIOR_DONE at every version; rescanning them
   buys nothing.
3. **Retry twice, then mark failed at that version** with the reason in the row; the 4 failures of the dry run must not come back every
   run.
4. **The stored bytes, never a re-fetch.** The two malicious finds were unpublished nine days ago; the rescan exists precisely because the
   registry no longer has them.

## Q2 Alert filter

Right as proposed: email only when (a) the earlier version's row did not fire that check and (b) OSV has no MAL record for the package
at scan time; held, never sent unfiltered, when OSV fails; the mail marks the hit as a rescan and names the prior version.

Labelled rescan hits are recorded, never emailed, and no digest: a closed case costs triage time for nothing. One exception in what is
RECORDED, not sent: for every labelled hit, store `lead_time_s` = label time minus capture time. The dry run says most labels arrived
within about 3 h of capture, before the checks existed, so there was no gain on those campaigns; that number, kept per hit, is the
honest measure of what the checks buy over OSV, and it belongs in the handover as a weekly line.

Package-level MAL suppression (any version of the package labelled) is accepted for the rescan path: it is historical and lower
urgency, and serial typosquat accounts would otherwise re-mail on every version. The live capture path keeps its own rule.

## Q3 Flood cap

N = 10 new unlabelled rescan hits per static-checks version, as proposed. Reasoning: a check named at 4 per 10,000 benign should fire
about once on 3,000 benign tarballs; ten unlabelled hits means a campaign or a broken check, and either way a person decides before
more mail goes out. The cap stops emails only: scanning, recording and the recon queue continue, and the capped mail says "N more
recorded, not sent" with the count. A share-of-set cap is not needed at this size.

## Q4 Scope

Hooked captures only, now: every named check the pinned driver runs (S0, S5, S6, S8, S9) reads a hook or a gyp file, and both S9 hits
were in the hooked set. Revisit when the driver gains a check that reads main or bin on captures (S7 needs predecessor facts the
scanner does not hold; keep-list reach is a later bump).

## Q5 Risks not in the proposal

- **Dedupe across versions on the recon queue**: package + version + sha512, as proposed, is right; condition (a) also stops a hit that
  fired at 1.7 from re-mailing at 1.8.
- **Release-day backlog**: about 3,000 tarballs clearing over 3 to 4 runs under the floor above; new captures arriving meanwhile go first
  by construction.
- **The S6 false positive** (@tera-system/pro, hostname used only as hash input) is the first live S6 benign fire against 0 of 19,617 in
  measurement. Record it as such for recon; a narrowing ("identity source consumed only by a hash") is a recon measurement item, not a
  change here.
- **The two malicious finds are the first analyst pins.** They fit pin-admission-1.4 exactly (a capture with its tarball sha256 and
  dist.integrity, the recon report, the operator's approval). The operator holds the OSV filing for them; the pin can precede the
  filing. Route them to the review sheet so ops' feed writer can take them once the operator approves.

## Exit

Tests first, the branch pushed so the migration-free change and its tests can be verified, the first release-day log line
(pending, scanned, new, labelled, emailed, failed) recorded in the handover, merge on the operator's go.
