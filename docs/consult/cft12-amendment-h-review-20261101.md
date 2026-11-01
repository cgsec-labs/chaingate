# Review: M-04 (CFT-12) Amendment H, gate doc draft r2 (review session, 2026-11-01)

Asked by the recon lane under the operator's ruling R-H2 (the review session reviews before the operator signs). The host file of
record is AMENDMENT-H-GATE-DRAFT-r2-20261101.md, sha256 567fd3da...; this is the review of the copy sent, on the operator's go.

## Checked from here

- 0.1.6 tarball 5aedff9f is npm latest; the qualification record sha 593630cf matches the release notes; every seed-v3.3-full fact
  (publish time 2026-10-30T18:25:26Z, not pre-release, gz dd6bcfa5, db daaa783e, 2,430,681,088 bytes, contract 1.3, K1
  ed25519:09f6c9fdb8f5a2ea) matches the GitHub release.
- `createProxyServer` is proxy/server.js line 745 and the gate composition line 879, as cited. The late static merge is
  `witness/store.js` 268 to 276 and the role logic `gates/row-class.js` 33; the draft omits both directories. "The walk fell behind
  the download" is raised in proxy/tar-walk.js when the gunzip buffer exceeds its bound.
- The dry-run counts, the host state and the traffic figures are recon's claims from the VPS, not verified here.

## Verdict

Fit to sign once the PENDING slots are filled, on five conditions. It is the right change: it moves the measurement instrument to
the frozen, published 0.1.6 and touches no detector, seed or feed rule.

1. **The advisory feed must be stated.** 0.1.6 fetches it by default, so every fresh witness store per batch fetches the current
   hourly cut, and the pins behind a BLOCK change during the window. Lean: keep it on, because R-H4 asks for the real verdict, and
   record with every decision the feed cut digest and whether a BLOCK came from a seed pin or a feed pin. The alternative is the feed
   off, with the reading stated as seed-only.
2. **The configuration of record goes in the doc**: `init --seed` sets `seed_cache` false, so no shards are read; `static_withhold`
   off; `on_no_evidence` WARN; the config file's sha recorded.
3. **The not-checked rate.** 68 of 1,000 walks fell behind in the dry run, 6.8 percent, above the project's 5 percent not-checked bar.
   The cause is the walker starving under Nice 10, idle IO and 4 requests in flight. Measure in the P5 replay at 2 in flight; if it
   stays above 5 percent, state it as a limit of the reading and print the not-checked share beside every rate. Not a blocker.
4. Fix the two paths (witness/store.js, gates/row-class.js) and name the 13 default gate modules in the doc rather than count them.
5. N and the installed-tree digest are filled before signing. N is the seed's selected package count, 367,612 per the shard root.

## Open items

1. **Strict tier:** both, disposition primary. The strict tier is the pre-registered CFT-12 measure; dropping it breaks continuity
   with s1 and s2.
2. **Draw:** keep F.3 (28 days, one draw, n = 20). The draw is the human-read precision sample; the alert lane alone says nothing
   about precision.
3. **Seed updates in the window:** v3.3 fixed for the whole window to 1 December, no update rule now. eval-1.0 Stage 7 run A found
   seed lag of 0, 1 or 7 days does not change recall. A later seed is a new amendment.
4. **s2 late labels:** yes, weekly read-only regeneration of labelled leads until cohort end plus 30 days, as F.5 and RL-16 did for
   s1. Late labels are the lead-time measure.
