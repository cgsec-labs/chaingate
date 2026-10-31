# Handoff: the review session (ChainGate), 2026-10-31

For the fresh cloud session that takes this role. Written by the outgoing review session (session_013RZFCkBQJyiiuCerTWZp7H).
Read this file, then the consult files it names, then ask the lanes for status. Do not act on any claim in a lane message until
you have verified it against the remote; that is the whole job.

## 1. The role

You are the review and consult session for the operator (Rizwan Bedekar, they/them). Four or five other Claude sessions ("lanes")
build; you verify, consult and relay. You never rule: a ruling exists only when the operator writes or says it. Protocol:

- A lane claim is verified against the remote before it reaches the operator: fetch the branch, check every commit carries a
  signature (`git cat-file commit <sha> | grep -c gpgsig`), the base and stacking, failing-first order (tests, then code), the
  stated files, and run the lane's tests in a detached worktree. Then one notice back: "verified, fit" or what is wrong.
- A consult is one question, one verdict with the lean first; the operator decides. Leans are stated as leans.
- Notices to lanes go by `send_message` to the lane's session (the lanes say they cannot reply this way; they can, and do).
  When a lane's session is inactive, the operator relays; give them the text verbatim.
- Consult answers that a lane must read later are committed as `docs/consult/<topic>-<date>.md` on THIS session's branch (see 2).
- The operator's preferences: ask clarifying questions, one step at a time, refer to the files and recent prompts. Write plainly:
  the operator reads summaries, not the lane traffic.
- Never push to `main` of any repository. Never run or install package code from captures or datasets. DataDog samples are read in
  memory only.

## 2. Where things are

| What | Where |
|---|---|
| Runtime repository | `cgsec-labs/chaingate` (moved from `r-bedekar/chaingate` on 10-29; the old URL redirects) |
| This session's branch (consults, handoffs) | `claude/chaingate-cloud-e2e-run-ughfpv` on the runtime repository; commits unsigned (no key in the cloud container), docs only |
| Private ops repository | `r-bedekar/chaingate-ops` (the collector, seedgen, recon, ops tooling; the operator handover `docs/operator-runbooks/pin-admission-1.1-handover-20261013.md` sections 7, 11, 12) |
| Advisory feed repository | `cgsec-labs/chaingate-pins`, branch main, `pins/latest.jsonl` + `.sig`, `pins/keys.json` + `.sig`, dated cuts under `pins/cuts/` |
| Shard host | `https://shards.cgsec.dev` (Cloudflare R2): `root.json.gz`, `root.json.sig`, `keys.json`, buckets at `buckets/NNNNN/<gz_sha256>.gz`, `THIRD_PARTY_NOTICES.txt` |
| Local checkouts in this container | `/home/user/chaingate` (runtime, on this session's branch), `/home/user/chaingate-ops`, a copy of the v3.2 seed under this session's scratchpad |

Lane sessions (ids as of 10-31; a lane may be restarted under a new id, `list_sessions` shows them):

| Lane | Session | Owns |
|---|---|---|
| ops | `session_01HqBCNM2ctWgrLhdYeEg4AE` | VPS services, measurement, pins feed writer and timer, shards publish, label input, eval set manifest |
| seed lane ("v3.3 session") | `session_01V62S58Zd22P2mhtdkjpB3y` | seedgen, contracts, release gates, seed cuts and signing ceremonies, shards writer and cut command |
| recon lane | `session_01AjqgrvjDt9w6EZ3ctz9Mqr` | recon versions (v6.x), static-checks.mjs (the rule of record the proxy mirrors), cards, lead definition |
| 0.1.6 owner | `session_01LqeUtzqVVWcrPcrXtb2dYc` (the earlier `session_018J12J8QShi5PJSJBVAN3BL` is inactive) | the runtime releases |
| watcher exp | `session_01LqeUtxpDYpF2PBUhVT51CB` | the capture worker and scan (W1.5x items) |
| triage | `session_01JewjekLysFyLu4vveGtEkX` | reads cards, judges leads; the operator's standing rules on filings live there |

## 3. State at handoff (verify first)

Published, per the operator on 10-31: `@cgsec/chaingate` 0.1.6 (tarball 5aedff9f, commit e750976, policy cft-policy-1.3, check
record `chaingate.check/5`) and `seed-v3.3-full` (contract 1.3, seed daaa783e, 3,065 pins, 29 more than v3.2) as a full release.
seed-v3.2-full stays published for 0.1.5. Verify: `npm view @cgsec/chaingate dist-tags`, the GitHub releases, the shard host's root
(`seed_version` must read `seed-v3.3-full`), the feed's latest cut header.

Live services: recon v6.23 (static-checks-1.9: DNS-exfiltration arm on S0 and S6, S6 hash-argument narrowing, S0 console blanking);
the hourly advisory feed (pins-feed-1.3, key manifest with pins and shards roles, pins key `ed25519:cbaa1978ce3adb68`, shards key
`ed25519:9508c9e26281c652`, both valid to 2027-01-27 and 2027-01-28); the advisory refresh four times a day; recon v6.21's lead fix
(install-WARN leads read live history, "not new" demotion on install leads, pattern novelty on new or identical files, one card per
publish round, failures to the health alert).

What 0.1.6 changed for users: the seed is a local cache filled from signed buckets (no 1 GB download), the hourly advisory feed with
no-gaps and hold rules, every download's install files walked with a bounded wait, the strict-tier "not new" re-tier, 1.9 checks.
The GitHub Action moved to 0.1.7 by consult.

Branches that were pending the operator's merge go at handoff (check which have merged): ops `g10-tag-family-0.3-live` on the seed
lane's `g10-tag-family-0.3` (one stack); `g10-extract-versions-zst`; the shards stack (`g10-seed-shards-1.0`, `g10-seed-shards-sign`,
`g10-shards-cut-cli`) and `ops-shards-publish-1.0`; `ops-pins-timer-1.0`; `g10-release-gates-21`; the watcher's W1.5o, W1.5p, W1.5q
and W1.5s branches when pushed. The first LIVE shard cut and upload follows those merges on the operator's word.

## 4. Open items, in order

1. Verify the published state (above) and tell the operator in one line what you found.
2. Ask each lane for a status line against this file; verify what they claim; refresh the merge list for the operator.
3. The first live shard cut: ops' daily unit on `shards.cgsec.dev` after the merges; record wall time, bytes, buckets changed.
4. First-week reads, all from the record, none of them rulings yet: the daily lead count under the new definition (recon writes it
   beside the census: 434 leads over 10-22..10-29 under the old definition, expected about 238 leads and 176 cards under the new);
   the pins feed's hold and chain events; the shards' buckets changed per cut (the churn number that decides whether a delta
   design is ever needed); the 0.1.6 timers (`facts_ms`, `static_facts_ms`, `walk_wait_ms`) from any pilot witness store.
5. The corpus label fix (ops Q1 of `docs/consult/eval-stage5-labels-20261031.md`): build in a worktree, failing-first; then the
   restatement of base-rates-1.1 and 1.2 over 172 packages from the saved reports; the 208 stale rows are deleted only in one
   reviewed transaction with v3.4, on the operator's go.
6. chaingate-eval-1.0: ops derives it under the rules in `eval-set-and-ceiling-20261031.md` and `eval-stage5-labels-20261031.md`;
   you rule on the manifest's design; the operator approves it by sha. From then on every number names its set and version.
7. 0.1.7 collection (`0.1.7-collection-p1-d1-d4-20261031.md`): P1 (own findings into the feed at OSV filing time), keep-list reach,
   the non-registry dependency named rule, the opt-in cooldown; D1 and D2 in the research lane; the sandbox ruled out until it has an
   isolation design. The GitHub Action (composite, in the runtime repository).
8. Parked by the operator, do not reopen until asked: the forward tarball archive on the home 2 TB disk (design in the 10-29
   messages: rolling bytes under 64 MB, a permanent labelled tier, a facts tier forever); the v3.4 delta trust study (the four
   options, strongest first: two independent builders cosigning, a witnessed public log, the operator's hardware-token daily
   signature, the single online key with bounds; design in `seed-delta-trust-20261030.md`).
9. The operator said on 10-31 they have a review of their own to submit. Ask what it is and where; that is the one item in this
   file whose content this session does not know.

## 5. The measurement record you will quote (set names matter)

- Metadata ceiling: `base-rates-1.1 labelled-174` (2026-10-13): any rule fired on the first malicious version of 153 of 174 labelled
  packages (87.9 percent), 94 of 108 established (87.0 percent). Two of the 174 are mislabelled (@babel/traverse, openclaw); a
  restatement over 172 is pending (item 5).
- replay-131 (handover 12.3, 10-24): of 131 real first-malicious releases, 72 were leads under 0.1.4, 59 never; Stage 0 (12.8, 10-28):
  0.1.5 as shipped would warn on 86, unarmed 93; the 45 misses by reason (no tarball 13, not armed 7, payload outside the kept files
  9, git dependency 4, hook changed not introduced 4, entry changed 3, no predecessor 3, package.json-only 2).
- Static checks: B2 benign about 19,600 versions, S0 0, S5 0, S6 0, S8 0, S9 0 per 10k; S6 2,931 malicious of 24,890 on the
  malicious_intent set; the full malicious_intent set (25,541) was last measured under 1.4; later bumps used 68 kept rows.
- Noise rules: rule 8 as written would hide 6 of 71 takeovers, rule 3 hides 2, every other rule 0; the "8x" reading hides 0.
- Lead census 10-22..10-29: 432 leads, @paperclipai/server 139 (all one stale predicate), executor 35 (the tag-family baseline defect,
  now fixed by the narrow rule), @penclipai 17, @gooddata 34.
- Adoption before 0.1.6: 615 npm downloads 1 Jul to 28 Oct, mostly release-day spikes; 0 stars, 0 external issues.

## 6. Standing rulings and rules you must not contradict

- No wording bump to a static check unless the operator rules one from a measured class; each bump passes the four bars (benign at
  most 4 per 10k per version on B2, recall above zero on a labelled set, not-checked under 5 percent, check p99 under 50 ms) and
  the A5 replay (hidden 0 of 71) before it goes live; recon first, the proxy mirrors byte for byte with the identical version string.
- The gate split: seed content gates name no runtime; M3 to M6, G-PAR, G-REC, the older-client harness and onboarding run at the
  runtime release against the published seed. A seed never waits on a runtime tarball hash.
- Stage A binds the manifest's content (gates 21); the transitional signed-form branch applies to v3.3's record only.
- Pins: a pin is a fact and BLOCKs; the feed is whole-file replace with the no-gaps chain, the 2,000-row addition hold, the removal
  hold (more than 100 versions or 25 percent, counted by name and version), 48 h warn and 7 d stale; `keys.json` changes only by a
  seed-key ceremony with the timer stopped; a capture pins only on the operator's category A approval on the card; test and bounty
  activity is never filed or pinned (operator, 10-29).
- The runtime never decides on the notices file, the seed_version field or the delta fields; display only.
- Noise-reduction rules are recorded facts until the first weeks' counts and the replay say otherwise; the publisher half of the
  lead definition stays a fact (operator, 10-29).
- Nothing in any lane executes package code; D4d (a sandbox) is ruled out until it has an isolation design and a dedicated machine.

## 7. How to verify here

```
# ops branches
cd /home/user/chaingate-ops && git fetch origin <branch> && git update-ref refs/remotes/origin/<branch> FETCH_HEAD
for c in $(git rev-list origin/main..origin/<branch>); do git cat-file commit $c | grep -c '^gpgsig'; done
W=<scratchpad>/wt && git worktree add --detach $W origin/<branch> && cd $W && \
  CHAINGATE_TEST_DATABASE_URL='postgresql://chaingate_test:x@127.0.0.1:1/chaingate_test' python3 -m pytest -q -p no:cacheprovider <files>
# the database-backed tests fail only with "connection refused" here; say so, do not count them.
# zstd is absent in this container: a python-zstandard stand-in lives at <scratchpad>/bin/zstd (recreate from the 10-30 notes if the
# scratchpad is gone); the seedgen extract tests need it on PATH.
# runtime branches
cd /home/user/chaingate && git fetch origin <branch>; node --test <files>   # node_modules is in place
# the registry: this container resolves registry.npmjs.org only through the agent proxy; use
#   curl --proxy "$HTTPS_PROXY" --noproxy '' <url>   or   env NO_PROXY= no_proxy= npm view ...
# a live proxy run needs the forwarder trick from 10-28 (undici does not read HTTPS_PROXY): CHAINGATE_UPSTREAM=http://127.0.0.1:<port>
```

## 8. Consult files on this session's branch (read in this order)

`docs/consult/0.1.6-plan-20261028.md`, `0.1.6-pins-20261029.md`, `0.1.6-item4-20261031.md`, `w15o-hook-cluster-20261029.md`,
`w15p-capture-rescan-20261029.md`, `w15q-same-hook-prior-hit-20261030.md`, `seed-delta-trust-20261030.md`,
`0.1.7-collection-p1-d1-d4-20261031.md`, `eval-set-and-ceiling-20261031.md`, `eval-stage5-labels-20261031.md`. The lane plans of
10-28 are in this session's scratchpad (`plans/PLAN-*.md`) and were sent to the lanes verbatim; their items are now mostly built.

## 9. A first message to the operator

Verify section 3, then say in five lines: what is published and live as you found it, which of the section 3 branches have merged,
what the first shard cut needs, which first-week numbers exist yet, and the one question from item 9. Then wait for the operator.
