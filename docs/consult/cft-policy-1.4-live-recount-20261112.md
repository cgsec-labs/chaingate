# Consult: cft-policy-1.4, the live recount of Channel-A when the seed is behind (review session, 2026-11-12)

Asked by the runtime owner on the operator's word of 2026-11-12. Code: `claude/chaingate-0.1.8` at e09a935 (base main 08da677); A4 is
5ec9e79 with its tests, a66a678 the expectation fix. Verified here: six signed commits; the twelve live-recount tests pass; the suite at
the head gives 1,810 tests, 1,757 pass, 44 skipped, the 9 failures this container's usual ones (root user, no registry egress, the Python
cross-check), so the owner's 1,810 / 0 / 41 is the record. One convention note for the record: A4's tests and code are one commit, no
failing-first commit exists for it; say so in the release record as for W1.5o. Leans are leans; the operator rules on the policy identity.

## The design, as read

Channel-A compares an appended release with the seed tip. When k releases were published after the tip, each of the five groups is also
read against the re-tier's baseline (same flavor, else same line, else previous; no recount on problems), which must be published after
the tip. A group counts when it broke against the tip OR the baseline. A new named row `seed-v3:channel-a:live` WARNs when the count
reaches 3 and at least one group is new against the baseline; the tip row's own threshold is unchanged; the re-tier moves only the old
strict pair, so a recorded re-tier cannot demote the live row. Doubt on any side adds no warning. The operator chose the same 3-of-5
rule over a lone new flag; agreed, the lone flag would have been a new vocabulary with no measured base rate.

## Q1 Record: carry the recount as a member, as 1.3 carries `retier`

Lean: `chaingate.check/6` = /5 plus an optional `decision.live` member, present whenever a recount was MADE, firing or not:
`{version: "live-1.0", baseline, basis, tip, k, broke, live_new, n, threshold, fires}`, and when no recount was made, `{skipped:
<reason>}` with one of `no_gap`, `tip_count_at_threshold`, `channel_a_unusable`, `no_baseline`, `baseline_not_after_tip`,
`unreadable_side`, `baseline_pinned` (Q4). Three reasons. The project's rule is that a decision is explainable from its record; today the
recount's inputs live only inside the row's prose `detail`, which `why` can print but no harness can count. 1.3 set the precedent with
`retier`, and ops' eval harness reads decisions by field. And the non-firing recounts and the skip reasons are exactly the numbers M1
needs: how often the recount runs, why it does not, and what it finds when it does. A /6 "no member" is already a new schema id; the
optional member costs the same and buys the measurement. Schema additive, absent member omitted, explain-2 unchanged.

## Q2 The baseline after the tip: one real loss, rare, and the record should count it

The rule is right and the tests cover its edge (a tie, a removed version between, a baseline at or before the tip). The case it loses: a
candidate on another release line than the gap releases, whose same-line baseline is before the tip, while the main line gained the
signal in the gap (a 2.x backport published after 3.3 and 3.4 brought provenance; the tip 3.2 had none). The tip comparison is silent
and so is the recount. Rare, and the operator's direction was to add a check, not to chase every shape; but record it as `skipped:
baseline_not_after_tip` (Q1) so M1 can say how rare. The other loss is deliberate: an attacker who unpublishes the gap releases makes
chooseBaseline report a problem and suppresses the live row; the tip row still runs, so 1.3's protection is untouched, which is the
whole point of "add, not replace". Say that in the policy comment.

## Q3 Fail-safe direction: agree, and state it as one principle

The re-tier REMOVES a warning, so doubt must keep it; the recount ADDS a warning, so doubt must not add. Both are the same rule from
the user's side: doubt never reduces protection relative to 1.3. Write that sentence in policy.js above the two comments, so the next
reader does not see two opposite rules.

## Q4 Guards: chooseBaseline's sibling exclusion is enough, plus one

The re-tier's guards (recent state, hooks differ, provenance gone, dependency added, incomplete evidence) exist because it demotes; none of
them belongs on a row that only adds. The platform-sibling exclusion in chooseBaseline is the one that prevents a false fire, and it is
already there. Add one guard: a baseline the seed or the feed pins is not a reference; skip with `baseline_pinned`. Comparing a candidate
with a known-malicious gap release reads the attacker's own state as the norm; the tip row still covers the candidate.

## Q5 The union: accept it, and let M1 split the figure

Count a group that broke only against the tip. The seed never blessed the gap releases, so a state that changed at a gap release and
persists is still a change against the history the seed holds; a takeover spread over several releases (publisher and size at X+1,
provenance at X+3) is exactly the shape the union catches and the stricter count would miss. The union cannot fire on persistence
alone, because `live_new` must be non-empty. The alternative (live-new plus tip-and-live) measures "is the candidate a break against
its predecessor", which is the re-tier's question in reverse, and it would make the live row silent on the spread takeover. The detail
already names which groups are new; the `live` member makes it countable. M1 reports the live row's fire rate split by how many of its
three were tip-only, so the operator can narrow later from a number, never from a guess.

## One correctness question before the merge, owner to confirm

`liveGroup` treats some absent candidate facts as breaks, not as unknown: `provenance` fires when the baseline had provenance and
`c.provenance_present` is falsy, `git` likewise for `head_present`, and `publisher`'s maintainers constituent reads an absent candidate
`maint_digest` as `''`, which differs from any baseline digest and so counts as a break. "An unknown side never counts" holds for size
and identity (LR6) but not for these three. If the facts adapter guarantees these fields are real booleans for any readable registry
entry (absence meaning "none", which is the checker's own 1.3 definition), say so in a comment and a test; if a field can be absent
because the entry could not be read, return null there. Either way the answer goes in the record.

## Before it ships

The row is new vocabulary at the policy level, so the standing bars apply as to a check bump: benign at most 4 per 10k on B2, recall
above zero on a labelled set, p99 cost under the budget, and the A5 replay (hidden 0 of 71). M1 at seed lag 7 days with the L0 control
is the right measurement, because the row runs only when the seed is behind and Stage 7 showed a 7-day-stale seed already doubles
named false positives; the live row's own rate must be read on top of that, by the `live` member. Register the candidate tarball sha
first, as the owner says; no go-live before the numbers, and the detector freeze for the soak window stands until the operator lifts it.
