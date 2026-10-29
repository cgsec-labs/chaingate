# Consult: W1.5o hook-cluster shadow, design verdict (review session, 2026-10-29)

Asked by the watcher lane on the operator's go of 2026-10-29. Branch `w15o-hook-cluster-shadow` @09e6f32 is local to the VPS and
not pushed, so nothing below is verified against code; this is a verdict on the design as described. No verdict on a commit is
final until it is on the remote.

## Verdict

Fit to go live as a SHADOW (no mail, no tarball reads, two derived tables) with the four choices as described, on five conditions.
None changes the rule; each makes the later ruling readable from the data.

## The four choices

1. **Per-publisher key** (publisher e-mail; the source-repository owner under trusted publishing; the scope when no repository
   URL): accepted. Record on every row which of the three forms the key took.
2. **Merged key alongside, one cluster id shared**: accepted; the same key-form field says "merged" on those rows.
3. **Earlier carriers seeded from the pinned 10-12 export** (sha256 2a12a07f..., the same normaliser, refusal on mismatch) and a
   **carrier ledger never pruned**: accepted. Add the normaliser's version to every event and carrier row, so a later normaliser
   change is a visible break, never a silent one.
4. **Recorded, not filtering** (carriers_before and how many are labelled, scope counts and first-seen, publisher domains and
   first-seen, mal_at_write, mal_now; labels re-read for 60 days): accepted. This is the shadow-first discipline the runtime
   facts follow.

## Conditions before the timer is enabled

1. **Time source on every event.** 60 percent of hooked rows have no publish time and take their capture time, so the 72 h gap
   chain measures capture cadence there, not publish cadence: two packages published weeks apart and captured in one run would
   chain. Record `time_source` (publish or capture) per event, and per cluster the share of capture-time events; a cluster made
   only of capture-time events carries a flag. Acceptable for a shadow; not acceptable for any later alerting without that flag.
2. **Both suppression readings.** "Fires when no unlabelled package carried the body before" is the rule that suppressed the
   PR-1639 actor in the 10-15 measurement, because its own earlier unlabelled package counted as a prior carrier. Compute and
   record two readings per cluster: strict (as written) and tolerant (a prior carrier younger than 14 days does not suppress),
   with the age of the youngest suppressing carrier. The later ruling picks one from the numbers; a shadow can afford both.
3. **Size distribution.** Record every chain of 2 or more as a cluster row with its size, and let "at least 5" be the fire
   condition only. The threshold is then a ruling read from the distribution, not a constant baked into what was recorded.
4. **Rewrites.** The 7-day rewrite window replaces rows the job no longer reproduces. The ops repository's invariant is
   append-only on fact tables; these are derived tables, so rebuilding is allowed, but say so in the migration's header, keep
   `mal_at_write` immutable as designed, and give a replaced row a `supersedes` pointer to the row it replaced rather than
   overwriting in place, so the 60-day label re-read has a stable key to update.
5. **Push before merge.** Push the branch to the remote so the review session can verify the commit, the migration and the 23
   tests; the migration is applied and the merge made only on the operator's go, as every other lane.

## Reading of the dry run

Per publisher 21 clusters, 7 fire, 2 MAL (beacon.cjs); merged 49, 6 fire, 1 MAL. About 5 unlabelled fires per key per two weeks
is the cost number a later alerting ruling must weigh; as a shadow it costs nothing. The two beacon.cjs fires are the same campaign
the runtime's S6 names, so the shadow and the static check will be measurable against each other on live captures. Keep the
output where the other recorded facts go: card facts for triage and the handover table, never a new alert path.
