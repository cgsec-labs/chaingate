# Consult: the "87 percent" figure named exactly, and chaingate-eval-1.0 (review session, 2026-10-31)

Asked by ops on the operator's word.

## 1. The metadata ceiling, named

The figure is from the ops handover, section 7.1, base-rates-1.1, run 2026-10-13 (2,678 s). It is NOT replay-131 and NOT
T-derive.

- **Set:** the corpus's labelled versions at that snapshot: `attack_labels` rows with `is_malicious` and a `version_id`, 1,133
  versions (879 evaluable) across 174 packages, 108 of them established (an earlier non-malicious version in the corpus).
- **Numerator and denominator, per PACKAGE, on the first malicious version:** any metadata rule in `base_rates.RULES` fired on the
  package's first malicious version: 87.9 percent of 174 (153 packages) and 87.0 percent of 108 established (94 packages). The
  comparison rows in the same table: `install_introduced` alone 26.4 percent; the 0.1.4 named set about 38.5 percent of 174 and
  57.4 percent of 108; the base rate of "any rule" 8.7 percent of all versions.
- **Snapshot:** the corpus at 2026-10-13 (24,152,465 versions, 23,784,512 evaluable, 14,009,175 on established packages).
- **Rule versions:** `base_rates.py` at base-rates-1.1 (the `RULES` table of that commit, publish-order predecessor;
  `channel_a_critical~` and `dac_surface~` marked approximations). The lineage re-measure, base-rates-1.2 on 2026-10-13 (24,154,424
  versions, 879 evaluable labelled), re-ran the pairwise rules against the FU-2 and runtime predecessors; the "any rule" line was
  not re-stated there, so 87.9 / 87.0 is the 1.1 publish-order figure.
- The 13 percent silent cases named in the design note (14 of 108 established: @keyv/* 6.0.0, astro 7.1.0, duckdb 1.3.3-dev0.0,
  @asyncapi/*, @injectivelabs/sdk-ts) are the complement of the 87.0 percent.

Caveat the record already carries: the figures carry campaign correlation (leo-*, @antv/*) and the labelled set is only what the
corpus observed before npm removed it.

**T-derive.jsonl (68a5a0b0, 141 rows):** not in this session's records. What is recorded (handover 12.3): T was "re-derived
read-only from PROD 2026-10-24 per memptec SPEC s2 (sha 2bde077b; defined by the triage session, no saved list)", 141 packages
(140 npm, 1 PyPI), by `tools/corpus/triage_replay.py`'s population step, giving population.jsonl 3d67dcae (131 replayed, 9
placeholder-only, 1 PyPI). If T-derive.jsonl is that step's intermediate, the triage session (which wrote SPEC s2) is the one
that can say; the eval set below closes the gap by making the derivation a committed query.

## 2. chaingate-eval-1.0

Yes to the whole shape, and this is the measurement discipline the project has been doing by hand; freezing it is overdue. The
draft's classes and split are right, with these additions and choices.

### Classes

Positives:
- **P-HIST** (first malicious version after at least one benign version; the replay-131 family), sub-tagged by mechanism from the
  record: publisher change, same account (stolen token or pipeline), workflow or pipeline compromise, maintainer handover. Recall
  is reported per sub-tag as well as overall, because the rules reach these shapes very differently.
- **P-VER** (version-level ground truth; CFT-08's 144 of 330): adopt as-is with its CFT-08 ids.
- **P-NEW** (born malicious in the corpus): for never-seen handling only, never in baseline recall, as the draft says.

Negatives:
- **N-B2**: the B2 benign tarball set, adopt as-is (draw seed 20261014, 19,622 walked, the sha-pinned report), with a note that it is
  stratified by the corpus's selection axes, not by downloads.
- **N-SELF**: benign versions of the positive packages (per-package false positives).
- **N-POP**: a popular-package benign set (top dependents or downloads, latest versions), the set a false alarm costs most on.
- **N-TRIAGE** (add): the releases the triage sessions read and judged benign, from the card ledger. These are the hard negatives:
  benign releases that already tripped a contributing or named row. Every precision claim about a noise rule should be quoted on
  this set.

Exclusions with reasons, as drafted: manipulated history, non-npm, placeholder-only predecessors.

### Split

Time split by LABEL date: tuning before the cutoff, frozen holdout after it, as drafted. Two rules on top: a campaign (same
actor, same body or payload family, same week) is one unit, counted once in a `recall@campaign` figure beside the per-release
figure, and no campaign straddles the split (it goes to the part its first label falls in). The holdout is never used to tune a
rule; a rule tuned on holdout data invalidates that holdout, and the next holdout is drawn from captures after a new cutoff,
which the forward archive supplies when it exists.

### Adopt as-is versus re-derive

Adopt as-is, with their existing digests: B2 (report and draw), replay-131 (population 3d67dcae and the as-of packuments), the
DataDog compromised_lib and malicious_intent sets by zip sha (re-fetchable; the full malicious_intent set left the disk under R10 and
is restored on the home disk when it exists), the triage card verdicts. Re-derive by committed query at the stated snapshot: the
labelled-1147 set, P-HIST from `attack_labels` plus the lineage rule of record, and T itself, which closes the T-derive gap by
construction.

### Rows

Every positive row: name, version, label sources (OSV id, DataDog path, own capture id), label date, publish date, capture date,
tarball held yes or no with its sha256 and dist.integrity, predecessor version under the lineage rule, mechanism tag, campaign id,
split part. Lead time is label date minus publish date, and capture date minus publish date beside it.

### Reporting rule

Every number names set and version: `recall@P-HIST-1.0 (holdout)`, `FP/10k@N-B2-1.0`, `lead_time_h@P-HIST-1.0`. A number without a
set name is not a result. The handover sections that quote earlier figures keep them under their original set names (base-rates-1.1
labelled-174, replay-131), which the eval manifest maps to its classes.

### Ownership

Ops owns the manifest, the derivation queries, the digests and every measurement run. The review session designs the set, rules
on changes and holds the versioning rule: any change to membership or labels is a new version, never an edit. The seed lane
supplies the snapshot identifiers; recon supplies the card verdicts for N-TRIAGE and the mechanism tags where its cards carry them;
the operator approves each version by its manifest sha, as for a seed.
