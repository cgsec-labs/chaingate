# Consult: Amendment H, ownership from E5 and on-demand draws under R-H13 (review session, 2026-11-01)

Asked by the recon lane on the operator's "consult and then proceed". Leans; the ruling exists when the operator writes it into H.

## (A) Ownership of the running s3 soak from E5

Lean: split by what a reader of the record needs to trust, not a single owner.

- **Recon operates the instrument**: the live-s3 tree, the collector and its units, the consumers, the enrich, as for s2. Recon
  built it and continuity a week before the start matters.
- **Ops owns the numbers**: from the counted directory, ops runs score and draw, publishes the daily lead counts under recon's
  published lead definition (its sha in the record), and holds the draw records and the dated items. The counted directory is
  append-only with a daily sha chain that ops reads and records, so recon has no silent write path to a recorded decision after it
  lands.
- Why: the lane that writes the static checks the proxy mirrors, defines a lead and runs the enrich should not also compute the lead
  count and the precision. A CFT reader will ask who measured this.
- Fallback if ops cannot take score and draw before E5: recon runs them and ops reproduces every published number weekly from the
  counted directory, with the discrepancy required to be zero.
- Either form goes into H as one paragraph that names the separation. The 0.1.7 owner owns nothing in the soak and reads S1 from
  the published numbers.

## (B) R-H13: draws on demand, no 28-day frame

The design (draw on the operator's word, frame = every R-H11 lead since the previous draw and not drawn before, append-only draw
records, precision per draw and pooled by tier, adjudicated leads only) is right in shape. Five conditions:

1. **Frame = all R-H11 leads**, not strict only, since the s3 measure is 0.1.6's disposition; but **stratify by tier** (strict /
   disposition-only) with a fixed minimum per stratum each draw, so the pre-registered strict-tier precision keeps a known sampling
   basis and is not starved when disposition leads dominate.
2. **The strict-tier precision stays the measure of record** for CFT-12 continuity. Pool over draws weighted by each draw's frame
   size, never by raw drawn rows; print per-draw beside the pool. The 0.1.6 disposition precision is reported beside it as the s3
   measure and becomes a measure of record only by amendment.
3. **Only settled leads enter a frame**: static_settled true, or past the late-merge window. A lead not yet settled waits for the
   next frame, so a drawn row's disposition cannot change under the adjudicator.
4. **The draw's seed derives from the frame digest**, not chosen, so an on-demand instant cannot select a favourable sample. Record
   instant, bounds, size, digest, n and selection, append-only. State in H that drawing on demand can bias when but not what,
   because the frame is everything since the last draw and the selection is deterministic in the frame.
5. **Report the unadjudicated count per draw** beside the adjudicated precision; a draw with incomplete adjudication prints as such,
   never as a precision.

Frame bounds by the proxy's decision instant (decided_at), not the release's publish time, so a late-captured release cannot fall
between two frames. Built failing-first before signing.
