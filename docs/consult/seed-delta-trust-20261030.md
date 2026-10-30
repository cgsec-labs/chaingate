# Consult: seed deltas on top of shards (v3.4), trust and bounds (review session, 2026-10-30)

Asked by ops on the operator's word: a design ruling before any design work. Not for building now; after 0.1.6 ships and the
shards have run a week. The operator rules on (a); the rest are leans the design should carry.

## The fact that frames the whole question

From a client's point of view, daily shards ALREADY rest on the online shards key. The client verifies the key manifest under
the seed key, then the root under the shards key, then each bucket against the root. It never sees the K1 signature on the full
seed; that signature is checked on the server, by the cut command, as the cut's input. So K1 anchors two things today: the full
`.gz` download path, and the server-side input of every cut. A delta removes the second anchor for the buckets it changes, and
only for those. It does not change what a client trusts; it changes what a compromised server could feed the cut.

The honest consequence: whoever holds the shards key and the server can already serve a forged root. Deltas do not open that
door; they make the K1 base less than the whole of what is served. The bounds below exist to keep the K1 base meaningful and to
make a forged or wrong delta visible fast.

## (a) Trust: acceptable, with four bounds

1. **A delta names its K1 base and the client shows it.** The root carries `base_seed_logical_digest` (the K1-signed seed the
   delta extends), `base_cut_at`, `delta_seq` (monotonic from 0 at the base) and `delta_cutoff`. `seed_logical_digest` is the
   digest of the delta-applied whole, so the client's "all buckets imported" comparison stays one digest. `status` shows
   "seed v3.3 (signed) + delta 7, history to 2026-11-06, 9 days since the signed base".
2. **A maximum age forces the K1 cadence.** A root whose `base_cut_at` is older than 28 days is STALE: the client keeps serving
   it, says so on every coverage row, and `doctor` warns. The monthly K1 release is then a requirement the design enforces, not
   a hope. Lean 28 days; the operator sets it.
3. **No separate "delta" role key.** Both keys would sit on the same host under the same user; a second role buys a ceremony
   and no isolation. The shards key signs delta roots. What isolates is the input discipline in (b) and (c), not a second key.
4. **Pins never travel in a delta.** A delta carries history (lineages, spine, events, dep_names) for changed packages only.
   Pins come from the hourly feed, already signed, already guarded (chain, flood, removal). That takes the highest-consequence
   table out of the lower-review path entirely.

## (b) Gates per delta, automatic, every cut

- `verify_bucket` on every changed bucket (the existing check) and the bucket rule (every package in the bucket its name maps to).
- The identity-leak scan over the changed buckets (publisher digests only, nothing in clear).
- Reference equality for changed packages: the lineage and spine rows are produced by the rule of record (the same resolver the
  live combiner stamps findings with) from the live extract, and the writer's determinism holds: a delta over zero changes
  reproduces the base bucket byte for byte. This is the seed-side design item with v3.3 (id and ordinal stability under a
  per-package rebuild) and it is the precondition for deltas at all.
- Fixture parity: the placement fixtures (rl2, tag family 0.3) re-run against the delta-applied seed.
- A failed gate publishes nothing; the previous root keeps serving. Never a partial delta, never a fallback that drops to the
  base on the client (the client should not need to know a gate failed).
- Weekly, not per cut: the 71-release replay against the delta-applied seed, as the recall gate; and the hidden count must be 0.

## (c) Poisoning: rate limit, independent check, review sample, public log

- **Rate limit on change.** A delta may change at most 3x the trailing 7-day median of changed packages per day (measured from
  the shards' first week); more is refused and alerted. A mass rewrite is the signature of a bad extract or a bad actor, and
  either should stop the cut.
- **Independent cause for every changed bucket.** The delta writer emits a changelist (package, new versions since cutoff); the
  publish job re-derives it from the registry itself (each package's packument `time` map must show a version newer than the
  cutoff) before upload. A bucket that changed with no registry cause is refused. This is the check that makes a forged history
  rewrite visible without a human.
- **Review sample.** Weekly, five changed packages drawn by digest, before-and-after lineage state read by a person, recorded.
- **Public log of roots.** Every published root's digest, `delta_seq`, `base_seed_logical_digest` and `cut_at` is appended daily
  to the pins repository (append-only, as the dated feed copies are). A root served to one client that is not in the log is
  detectable by comparison; a later client can check its root against the log on refresh.

## (d) Client contract

Deltas are shards contract 1.1, declared in the root. A shards 1.0 reader (0.1.6) refuses a 1.1 root and keeps its last good
root, so deltas need the 1.1 reader (0.1.7 at the earliest). A 1.1 reader verifies as today, then: `delta_seq` strictly greater
than the held root's (a lower one is a rollback, refused); `base_seed_logical_digest` equal to the held root's unless the new root
is itself a base (a new K1 release, `delta_seq` 0); age bound as in (a) 2; `seed_logical_digest` compared after import as
today. Display as in (a) 1. Nothing else changes for the client; buckets are the same objects at the same content-addressed paths.

## Why deltas rather than a daily full build without K1

A daily full build skipping K1 has the same trust as a delta and costs the full extract and build every day. Deltas give the same
freshness for the changed packages only. The trust question is identical; deltas are the cheaper form of it.

## Not decided here

The age bound value, the change rate multiplier and the review sample size are the operator's numbers once the first week of
shard churn exists. Build order: after 0.1.6 ships and a week of shards, v3.4, as agreed with the operator.
