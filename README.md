> **Research prototype, not production-ready.**
> A change in a package's metadata is a reason to look, not proof of malicious intent. What exists
> today: a local proxy, a CLI, a witness store, the rules of policy `cft-policy-1.2` (facts that block,
> named rules that warn, contributing signals shown as detail), signed seeds verified against a key
> built into the runtime, and ALLOW / WARN / BLOCK enforcement, with a passing test suite. [What's built today](#whats-built-today) lists what runs;
> [What's next](#whats-next) lists what does not exist yet.

# ChainGate

ChainGate by CGSec. npm package `@cgsec/chaingate`, command `chaingate`.

ChainGate is a local npm proxy that compares each new package version with that package's own
release history and warns or blocks when its metadata changes in ways that often come with a
compromised release.

> **Install the scoped package.** The unscoped `chaingate` package on npm is an
> unrelated project, a cryptocurrency SDK. It is not this tool.

Most supply chain tools check a package against lists of known-bad packages. ChainGate instead
checks whether a release differs from the releases before it. It runs on your machine, needs no
threat feed or account, and is licensed Apache 2.0.

---

## The Problem

When axios@1.14.1 was published with a remote access trojan, its registry metadata already looked
different from earlier releases: a new dependency that had only just been published, a new
publisher email on a privacy-focused domain, no provenance attestation, and a publish from a CLI
token instead of GitHub Actions OIDC.

The new dependency, plain-crypto-js@4.2.1, also declared a `postinstall` script, so installing
axios@1.14.1 ran it. All of that is in the registry metadata that npm downloads anyway. Nothing shows
it to the developer at install time.

ChainGate records what each package looked like before. In 0.1.4 it warns on a short list of named
rules: for axios@1.14.1, that the release adds a dependency that runs install scripts. The other
changes are recorded as detail. ChainGate does not look at the code inside a package, so it
complements code analysis rather than replacing it.

## The Idea

ChainGate keeps a **witness log**, an append-only record of every package version it has seen:
content hash, dependency tree, publisher identity and provenance status. When a new version appears,
policy `cft-policy-1.2` compares it with that history and with the seed. The same input always gives
the same result. Each row of the result has one of these effects:

| Kind | Rows | Effect |
|------|------|--------|
| **Facts** | an advisory in the seed naming this exact version; content that differs from the version's recorded baseline (content hash) | BLOCK |
| **Named rules** | the seed's strict tier; install-introduced; N1h (an added dependency runs install scripts); MC (the tarball's install scripts differ from its registry entry) | WARN |
| **Contributing signals** | publisher change, new dependency, provenance dropped, release age, scope boundary, size jump, npm-version downgrade, the seed's loose rule | detail only |
| **Coverage choice** | the seed cannot use the release's input, or nothing in its finding was evaluated | what you set at `init`: `on_unusable_input` (default BLOCK) and `on_no_evidence` (default WARN) |

One contributing signal is common and usually harmless, and no combination of contributing rows warns:
they are shown beside a named warning and in `chaingate why`. A takeover that adds no install script
and no dependency that runs one warns only when the seed's strict tier marks the release.

## How It Works

```
npm (developer or CI)  ->  ChainGate proxy  ->  upstream registry
                               |
                               v
                   compare with the witness log and the seed
                   apply cft-policy-1.2
                   ALLOW / WARN / BLOCK
```

## What's Built Today

The whole path, from `npm install` to a decision with its reasons, works today.

**Local npm proxy.** Sits between npm and the upstream registry, built on `undici`. It rewrites
package metadata and evaluates every version it resolves. Installs from a lockfile (`npm ci`, and `npm install` with a
complete lockfile) ask only for tarballs, so before it serves a tarball whose exact version the running proxy has not
evaluated, the proxy fetches that package's metadata, evaluates it and applies the version's current decision. This
applies in every configuration that has a witness store. A version stays tracked as evaluated while the proxy runs, up
to 100,000 tracked versions; a version published later, one whose evaluation failed, and one dropped from that bounded
tracking are evaluated again on their next request.

If the requested version cannot be evaluated (the metadata cannot be fetched, the version is missing from it or could
not be evaluated, or the version cannot be derived from the tarball name), the existing policy for a request without a
decision applies, and the tarball is not counted as evaluated:
- with a v3 seed and `on_unusable_input: BLOCK`, it is refused (HTTP 503 `chaingate_evaluation_failed`);
- with `on_unusable_input: WARN`, or without a v3 seed, it is served without an evaluation, and the log says so.

When too many evaluations are already waiting, a request is refused with HTTP 503 `chaingate_evaluation_busy`, a
resource refusal, not a finding. A stored or remembered BLOCK is refused, and an exact override is honoured, whatever
the evaluation's outcome. While the in-memory record is FULL (below), its own rules apply instead.

**Cost of evaluating before serving (measured).** A lockfile install through a newly started proxy fetches and
evaluates each package's metadata before serving its tarball. On the tested Linux host, with a synthetic workload of
200 packages whose metadata each lists 200 versions (medians of 3 runs, local registry on loopback):
- `npm ci` took 10.2 s on a newly started proxy, against 0.9 s for the same install without this evaluation;
- it took 13.5 s after a restart with those packages already in the witness store, where stored histories are read
  too.

That is about 50 ms per package for this workload, not a general figure: the cost depends on each package's size and
history, the upstream and the machine. Repeat installs on the same running proxy took 0.9 s, because their versions
were still tracked as evaluated. A new version, or one dropped from the tracking, is evaluated again. A CI job that
starts a new proxy every run pays the first-install cost every time.

**CLI.** Fourteen commands: `init`, `status`, `check`, `why`, `history`, `allow`, `overrides`, `update-seed`,
`doctor`, `stop`, `report`, `accept`, `pin`, `unpin`.

**Witness store.** Append-only log backed by SQLite: content hashes, dependency
trees, publisher metadata, provenance status.

**What decides a warning (policy `cft-policy-1.2`).** Each release gets a record of every check's result. Only some of
those checks can make a warning:
- **Facts BLOCK.** These are a recorded advisory naming the exact version (from the seed), and content that differs from
  the version's recorded baseline (content-hash).
- **Named rows WARN.** Each one is a specific, counted reason:
  - the seed's strict tier (a release-history break of 3+ of 5 groups, or 2+ package-wide signals);
  - **install-introduced**: the release declares an install script (`preinstall`, `install` or `postinstall`, or a
    node-gyp build) when no version published at least 24 h earlier declared any (on a package's first day: no earlier
    version at all). A package's first version is not judged. A changed or additional install script on a package that
    already had one is not this rule;
  - **N1h**: the release adds a registry dependency (a name no earlier release depended on) whose resolved version runs
    install scripts. Git, URL and file dependencies are not judged. It follows the counted rule: a range resolves to the
    highest matching version (npm may install the `latest` tag instead when it matches), a name in both `dependencies`
    and `optionalDependencies` is judged on its `dependencies` entry, and re-pointing an existing name is not "added";
  - **MC**: the tarball's `package.json` declares install scripts that differ from its registry entry.
- **Contributing rows are detail.** These are publisher change, new dependency, provenance dropped, release age, scope
  boundary, size jump of 2x or more, npm-version downgrade, the seed contract's loose rule, and the five tarball static
  checks (below). They are listed in
  `chaingate why <pkg>@<ver>` (the recorded decision) and in `chaingate report --json`, and they never make a warning on
  their own.

Some named rows are checked when npm downloads the tarball:
- **N1h** judges the added dependencies from metadata npm already fetched through ChainGate, or fetches it before
  answering: within 5 s, at most 8 fetches at once, cached for 10 minutes. A release that adds more than 10 is not
  judged, and a dependency that does not answer in time is "not evaluable".
  Either outcome is never an ALLOW for that rule. An install from a lockfile (`npm ci`) fetches no metadata, so each
  tarball that adds a dependency can wait up to 5 s.
- **MC** reads the tarball while it streams to npm. It reads the archive as npm's extractor (node-tar) does, and
  compares every entry npm writes as the root `package.json`: on Linux checked against npm 10.9.7's and 11.19.0's own
  extractor, on macOS and Windows emulated, with names those systems may also map to that file compared on their own.
  An archive that npm 10 and npm 11 would read differently is "not checked". The download that reveals a mismatch
  carries no notice, and npm caches it. `chaingate report` lists the mismatch at once. A later download that reaches ChainGate carries the notice,
  but npm installs a tarball it already holds from its own cache without asking ChainGate, so this machine may never
  print it.

**Tarball checks (0.1.5).** On a download whose version already carries a named WARN row, the identity-break note, or the
seed's coverage warning (nothing in the finding could be evaluated: a package the seed has never seen), the same walk also
keeps the bodies of the files the registry manifest points npm at -- the install-hook targets, `main`, up to 4 `bin`
targets; at most 6 files of 1 MiB each -- and runs five checks over them, each a conjunction of two facts about one file:
- **S0** an install-hook command carries a fetch (curl, wget, Invoke-WebRequest, certutil -urlcache, bitsadmin) and an
  execute or decode (a pipe into a shell or interpreter, powershell -enc, base64 -d, eval, iex);
- **S1** a hook target under 8 KiB carries a network sink and an execution sink (a loader);
- **S2** an entry file carries 20 or more `_0x` identifiers and a decode marker (eval, Function, atob, a long
  String.fromCharCode run, or hex escapes over 15 % of the file);
- **S3** a file carries a credential source (.npmrc, ssh keys, cloud credentials, token variables, a process.env dump) and
  an outbound sink to a host that is not the registry (a known exfiltration host class, a raw IP, or a POST to a literal host);
- **S4** an entry file overrides `XMLHttpRequest.prototype.send`, `window.fetch` or `window.ethereum.request` and carries
  two or more cryptocurrency-address regexes.
All five are contributing rows (`static:S0-shell-fetch-in-hook` through `static:S4-wallet-swap-hook`): recorded as notes, shown
in `chaingate why` and `chaingate report --json`, never a warning on their own until a measured base rate and an operator
ruling name one. A row names the markers that matched, the file and its size -- never the file's content. The marker
lists are constants under the version `static-checks-1.0`, the same lists the operator's recon tool runs. A download the
rule did not arm records "not armed"; a file that is binary, over the cap, absent, or named only by the tarball's own
`package.json` is "not checked" and says so. A tarball whose download was armed is examined once: the outcome rides every
later record of that version.

A "not evaluable" N1h or "not checked" MC outcome is kept in the record (`chaingate why <pkg>@<ver>`). npm does not print
it. The report counts a release as checked when another named rule (install-introduced or the seed's strict tier) gave
a result, and as not checked only when no named rule did.

`chaingate check` (the CI command) evaluates the seed only in 0.1.4. Install-introduced, N1h and MC are reported by the
proxy, not by `check`.

**What you see.** For a named warning, a refusal that rests on a fact (a recorded advisory or a content change), or a
version your pin withholds, ChainGate sends npm a notice on the tarball response, and npm prints it. Other refusals (an
evaluation that failed or is busy, a full record) carry only the HTTP error. `chaingate why <pkg>@<ver>`, the command the
notice names, shows the proxy's recorded decision for that version (labelled UNBOUND, exit code 4):

```console
npm notice chaingate: WARNING q@1.5.0: release-history break vs the seed (2+ package-wide signals). Details: chaingate why q@1.5.0
npm notice chaingate: BLOCKED p@1.3.0: a recorded advisory names this version. Details: chaingate why p@1.3.0
```

npm prints a notice only on a response it does not cache (measured on npm 10.9.7 and 11.19.0). So a named-WARN tarball is
sent `no-store`. Two consequences follow:
- An offline or `--prefer-offline` install cannot take that tarball from npm's cache.
- `chaingate accept` makes the version cacheable again (below).

A dist-tag that ChainGate moves off a blocked version is not printed by npm, because the metadata stays cacheable. The
report shows it instead.

**The report.** `chaingate report` says what the proxy served and refused in your last install:
- each named warning: what moved, the baseline, what already happened, the last version without the signal, and what
  to do;
- each refusal, and each dist-tag moved off a blocked version;
- how many packages no named rule checked, and why.

`--all` shows every install the running proxy holds; `--json` gives the record. Without a running proxy it reads
ChainGate's disk record of the last 24 h (`--since 7d` to change), which keeps only named warnings and the refusals and
dist-tag moves that rest on a fact (a pin refusal, for example, is not on disk).
- Exit codes: 0 = nothing named, refused or moved; 2 = named warnings; 3 = a refusal or a moved dist-tag; 4 = a tool
  error, or an incomplete record with nothing else to report.
- The report covers only what reached ChainGate: npm's own cache is invisible to it.

**Your actions:**
- `chaingate accept <pkg>@<ver>` accepts a named warning for that exact version.
  - ChainGate stops sending the notice while the version's record shows only the signals you accepted. A later or
    different signal warns again.
  - It never overrides a BLOCK: a later advisory for that version still blocks it.
  - `--revoke` undoes it and `--list` shows them.
- `chaingate pin <pkg>@<K>` keeps `<pkg>` on K within K's major (for 0.x, within 0.y). Every newer version in that range,
  prereleases included, is withheld until `chaingate unpin <pkg>`.
  - A running 0.1.4 proxy that reads the same ChainGate directory (the same `--scope` or `CHAINGATE_HOME`) applies it at
    once, and the command says whether it did. npm may keep using metadata it cached for up to about 5 minutes, and
    `npm install --prefer-online` refreshes it.
  - A withheld version requested from a lockfile is refused with a notice naming your pin.
- `chaingate allow <pkg>@<ver> --reason "..."` keeps its meaning: an exact-version override for a false-positive BLOCK.
  A pin wins over an override on a version it withholds, and both commands say so.

These actions, and each `chaingate why`, are recorded locally with the version's classes at that moment, for a later
reading of which warnings anyone acted on; no 0.1.4 command displays it. Nothing leaves the machine.

**Local endpoints.** `/_chaingate/self` and `/_chaingate/report` answer only local, non-browser requests: a loopback
client and a loopback `Host`, no `Origin` header, and `Sec-Fetch-Site` absent or `none`. This keeps a web page from
reading your installed package names through DNS rebinding.

**ALLOW / WARN / BLOCK enforcement** with a persisted decision log, per-version
overrides, and CI-friendly exit codes from `chaingate check` (0 / 2 / 3; 4 = tool error). `chaingate check --json`
emits a versioned `chaingate.check/3` record (0.1.3 wrote `chaingate.check/2` and 0.1.2 and earlier
`chaingate.check/1`; both are still read); `examples/ci/` has an offline CI consumer for them.

**A failure never turns a BLOCK into permission.** A BLOCK stays in force until the check that issued it
definitively clears it (for example, the content hash matches its first-seen value again, or the seed no longer
records the advisory), or until you add an exact override with `chaingate allow`. A skipped check, an error, missing
evidence, an unreadable seed or an input the seed cannot use never clears it. This also applies to decisions written
by earlier versions; nothing in your history is rewritten.

**Exception, by your choice:** with `on_unusable_input: WARN`, a version whose stored decision cannot be read at all is
served. A BLOCK the running proxy holds in memory is still refused. Without a v3 seed (a legacy seed or
`--no-seed`), a decision that cannot be read is refused; those configurations do not provide v3 detection.

**When a BLOCK cannot be stored.** If a BLOCK decision cannot be stored, the running proxy remembers and
enforces it in memory. Restarting the proxy clears that memory. After a restart, a version is evaluated again before
its tarball is served (with the failure policy above), and a BLOCK that this evaluation reproduces from the seed or the
stored history is refused again. A BLOCK it cannot reproduce is lost at the restart, for example a content-hash BLOCK
whose stored baseline is no longer available.

**What the proxy cannot see.** ChainGate decides only requests that reach it:
- npm reuses its local cache by content hash without contacting any registry, so a version already in the cache is
  installed without a check. Give CI jobs an empty cache, and clear the cache (`npm cache clean --force`) when you
  start using ChainGate on a machine;
- a lockfile `resolved` URL on any host other than `registry.npmjs.org` or the proxy (a private registry, a mirror)
  is fetched from that host directly. With `replace-registry-host=never`, even `registry.npmjs.org` URLs are;
- an upstream other than `registry.npmjs.org` may give tarball URLs on its own host, which npm then fetches directly.

**Protected CI workflow (tested):**
1. Start the proxy with your seed (`chaingate init --seed <folder>/chaingate-seed-v3.db`).
2. Set `registry` to the proxy, and keep npm's default `replace-registry-host`.
3. Keep lockfile `resolved` URLs on `registry.npmjs.org`.
4. Run `npm ci --cache "$(mktemp -d)"`.

A pinned version then fails the install; any other version is evaluated before it is served.

This in-memory record is bounded: by default 50,000 entries and an estimated 64 MiB of retained data. You can change
these with `unstored_block_cap_entries` and `unstored_block_cap_bytes` in the configuration, or
`CHAINGATE_UNSTORED_BLOCK_CAP_ENTRIES` and `CHAINGATE_UNSTORED_BLOCK_CAP_BYTES`. The bound applies to the record, not
to the proxy's total memory, and the default values are not a measured safe limit for every machine. On the tested
Linux configuration, a record at its 64 MiB byte cap (maximum-size names and details) came with about 122 MB of heap
and 336 MB resident memory in the proxy process. Nothing is ever
evicted. When a new BLOCK does not fit, the record becomes **FULL** and stays FULL until the proxy is restarted. While
FULL, the proxy refuses (HTTP 503 `chaingate_storage_degraded`) every tarball that has no stored or remembered BLOCK and
no exact-version override, including tarballs whose stored decision is ALLOW or WARN. This happens under every
`on_unusable_input` setting, and requests whose decision cannot be made are refused too. FULL is a resource-safety
refusal, not a finding that the package is malicious. An exact override (`chaingate allow`) still lets that one version
through, but only when the override can be looked up at request time.

`chaingate status` and `chaingate doctor` show the running proxy's storage state (`witness-storage` in doctor):
- whether decisions are being stored;
- how many BLOCKs are held only in memory, with some of their names to re-request;
- whether the record is FULL.

Any BLOCK held only in memory, and FULL, are reported as degraded; doctor exits 1. The proxy's log is rate-limited, and
lines it suppresses are counted and summarised. It is not a complete record of every decision.

**Seed verification.** Every seed is checked against its `.sha256` file before use. A seed counts as
**authenticated** only when its Ed25519 signature verifies against a key built into the runtime. An
unsigned v3 seed can be used only with `--unsigned-development`, and the tool then reports
`authenticated: false`. A signature that is present but cannot be checked is refused.

**Detection engine.** Two layers of patterns. Publisher identity looks at how long each publisher
has held a package, handovers to a new publisher, and email domains. Provenance tracks attestation
per major version and flags when it stops. Under `cft-policy-1.2` both are contributing signals: they are shown
beside a named warning and never warn on their own. Both work only from a package's recorded history.

**Validation.** A script runs the detection engine on train and test splits of the research corpus
and writes metrics to `validation/results.json`. Snapshot tests fail if those numbers change.

**Tests.** `npm test` runs the full suite; release candidates record their results in the release notes.

**Pilot results on the held-out test split.** These come from a small research corpus of 209
packages. Treat them as a pilot measurement, not an estimate for npm as a whole:

| Metric | Value |
|--------|-------|
| Package recall | 0.67 (4 of 6 labeled attacks detected) |
| Attributable label recall | 1.0 (every attack with a version-pinned label is caught) |
| Provenance-only false-positive rate on clean packages | 0.0 |
| Canonical attacks (pattern layer, corpus) | axios@1.14.1, event-stream@3.3.6, shai-hulud, ua-parser-js (what 0.1.4 warns on: [Attack Coverage](#attack-coverage-from-the-corpus)) |

## Quick Start

You need no account or subscription. You download the detection seed yourself once (below), and
ChainGate verifies it locally.

Install from npm. ChainGate supports Node.js 22 and 24, the two major versions `package.json`
declares. The command is `chaingate` either way:

```bash
npm install -g @cgsec/chaingate        # global
chaingate --help

npm install @cgsec/chaingate           # or inside a project
npx chaingate --help
```

**Upgrading.** After installing a new version, restart the proxy (`chaingate stop`, then `chaingate init`). Until then
the proxy that is running keeps the old version's rules, and `chaingate doctor` reports the version mismatch as
TAMPER. The first install that touches each package afterwards records a current decision for every version of it
that npm's metadata still lists, except a BLOCK that is reached again, which keeps its stored row (rows are only
appended).

**The SQLite module has a native part.** It is installed by `better-sqlite3`'s own install script,
which downloads a prebuilt binary. npm 12 blocks dependency install scripts unless you approve them.
npm 11 runs them, but warns about any that `allowScripts` does not list. With `ignore-scripts=true` in
your npm configuration they never run. If the script did not run, ChainGate installs but cannot open
its database; `chaingate doctor` reports this as `native-sqlite` and prints the fix. Approve only
that one package's script:

```bash
# global install (npm 11 and 12)
npm install -g @cgsec/chaingate --allow-scripts=better-sqlite3

# project install: approve in package.json before installing ...
npm pkg set allowScripts.better-sqlite3=true --json && npm install @cgsec/chaingate
# ... or install first, then approve and build it
npm install @cgsec/chaingate && npm approve-scripts better-sqlite3 && npm rebuild better-sqlite3
# (npm 11.19.0 also names it npm install-scripts approve better-sqlite3; checked on 11.19.0, absent from 10.9.7)

# with ignore-scripts=true in your npm configuration: rebuild just that package
cd "$(npm root -g)/@cgsec/chaingate" && npm rebuild better-sqlite3 --ignore-scripts=false
```

`--allow-scripts` works for global installs only. npm rejects it for project installs, which use
`allowScripts` in your own `package.json` instead. The `allowScripts` entry in ChainGate's own
`package.json` applies only when developing ChainGate itself and grants nothing in your project. Do
not enable every dependency's scripts to fix this.

**Tested platforms.** 0.1.4 ran its full test suite on Linux x64 with Node.js 22.22.2. CI on the release commit passed
all 36 jobs: unit tests and install acceptance on Linux x64 (Ubuntu 24.04), macOS 15 on arm64 and x64, and Windows
Server 2022, each on Node.js 22 and 24 with npm bundled and latest, plus small-filesystem (disk-full) checks and a
reduced measurement on Linux and macOS arm64. The table below is the fuller qualification of 0.1.3; its rows that are
not CI were not repeated in the same form for 0.1.4. Anything not listed is untested and not supported. On each row the
SQLite module installed from its official prebuilt binary, with no Python or compiler.

| OS | Architecture | Node.js | npm | How it was tested |
|----|--------------|---------|-----|-------------------|
| Linux (Ubuntu 24.04) | x64 | 22.22.2 | 10.9.7 | full local qualification (suite, lifecycle, parity, installed package, BLOCK through the proxy with real npm, protected CI workflow, resource and log measurement, offline kit) |
| Linux (Ubuntu 24.04) | x64 | 22.23.3; 24.21.0 | 10.9.9, 12.2.0; 11.19.0, 12.2.0 | CI: test suite and install acceptance; real small-filesystem (disk-full) checks and reduced measurement |
| macOS 15 | arm64 | 22.23.2; 24.20.0 | 10.9.8, 12.2.0; 11.19.0, 12.2.0 | CI: test suite and install acceptance; real small-filesystem (disk-full) checks and reduced measurement |
| macOS 15 | x64 | 22.23.2; 24.19.0 | 10.9.8, 12.2.0; 11.17.0, 12.2.0 | CI: test suite and install acceptance |
| Windows Server 2022 (administrator account) | x64 | 22.23.3; 24.21.0 | 10.9.9, 12.2.0; 11.19.0, 12.2.0 | CI: test suite and install acceptance |
| Windows 10 Pro (standard account) | x64 | 24.21.0 | 11.19.0 | global and project install acceptance, BLOCK through the proxy with real npm, protected CI workflow, installed-package checks, Windows device, pipe, size-limit, junction, lock and free-space checks |

Not tested on Windows:
- **A real full disk.** Free-space handling there was exercised only by a simulated free-space figure and injected
  write errors.
- **An activation file that is a symbolic link.** A standard account cannot create one; a junction was tested.

**On Windows:**

- If PowerShell refuses to run `npm` or `chaingate` ("running scripts is disabled on this system"),
  type `npm.cmd` and `chaingate.cmd` instead. The Command Prompt uses the `.cmd` launchers
  automatically. You do not need to change the execution policy.
- Approve the SQLite script in the install command, so npm does not warn about it or skip it:
  `npm.cmd install -g @cgsec/chaingate --allow-scripts=better-sqlite3`. To approve it once for all
  your global installs: `npm.cmd config set allow-scripts=better-sqlite3 --location=user`.
- Start ChainGate with your v3 seed:
  `chaingate.cmd init --seed C:\path\to\chaingate-seed-v3.db`. On a new install,
  `init` without `--seed` downloads the older legacy witness seed instead (see below).
- [SEEDS.md](SEEDS.md) shows how to check a seed file's SHA-256 in PowerShell.

From source:

```bash
git clone https://github.com/r-bedekar/chaingate.git
cd chaingate && npm install
npm test
```

**You download the v3 detection seed yourself.** It is published as the signed GitHub pre-release
[seed-v3.1-full](https://github.com/r-bedekar/chaingate/releases/tag/seed-v3.1-full). Download its
`chaingate-seed-v3.db`, `.sha256` and `.sig` assets into one folder (the database is about 2 GB) and pass
the database with `--seed`. **ChainGate does not download it for you.** Before it uses the seed, ChainGate
checks it against the `.sha256` file and verifies the signature against the key built into the runtime.
The release page lists the seed's exact identifiers and how to verify the download yourself.
[SECURITY.md](SECURITY.md) describes the trust model. An unsigned seed, such as the v3.0-rc3 test
seed described in [SEEDS.md](SEEDS.md), still needs `--unsigned-development`, and the tool then reports
`authenticated: false`.

Running `chaingate init` without `--seed` does **not** set up v3 detection. On a new install (no v3
seed and no witness database yet) it downloads the older, signed legacy witness seed (about 100 MB)
and tells you so. It never downloads with `--no-seed`, or on a host that uses a v3 seed. For v3
detection, always pass `--seed`.

**1. Initialize.** This installs the v3 seed, starts the proxy and points npm at it:

```console
$ chaingate init --seed ./seed-v3.1/chaingate-seed-v3.db
Verifying v3 seed signature...
✓ v3 seed signature verified
✓ v3 seed bundle <bundle id> active
  sha256 a4c4e364de00653b...  snapshot <snapshot>...  trust authenticated (authenticated)
  policy on_unusable_input=BLOCK on_no_evidence=WARN
✓ .npmrc updated
```

Opening and verifying a full seed takes tens of seconds, and `init` waits for the proxy to start.
`--scope project` keeps everything inside the current directory.

**2. Install through the proxy.** Every `npm install` now goes through ChainGate, which checks each
version as npm resolves it.

**3. Check a release.** `chaingate check` evaluates a release, described by a saved packument file,
against the active seed. It always evaluates afresh and never reports a stored decision:

```console
$ chaingate check express@4.22.3 --packument ./express.json
express@4.22.3: ALLOW
  evaluated disposition: ALLOW under cft-policy-1.2
  placement: recorded
  ...
$ echo $?
0
```

Exit codes: 0 ALLOW, 2 WARN, 3 BLOCK, 4 tool error. `--json` gives the `chaingate.check/3` record. In 0.1.4 `check`
evaluates the seed only: install-introduced, N1h and MC are reported by the proxy (above).

A version named in a recorded advisory is blocked even when the release cannot be evaluated (for example a
manifest the adapter rejects), and the result names the advisory.

**4. Explain.** `chaingate why` explains a result. It never changes one:

- `chaingate why <pkg>@<ver> --packument <file>` evaluates the release, then explains the result.
- `chaingate why --from <check.json>` explains a saved `check --json` result without evaluating again.
- `chaingate why <pkg>@<ver> --cached` shows an old stored decision, labelled cached and unbound
  (`CACHED-UNBOUND` in `--json`) because it records no seed, rule or policy identity, and exits with code 4.
- `chaingate why <pkg>@<ver>` with no mode (the form ChainGate's npm notices print) is the same as `--cached`: the
  proxy's recorded decision, including the install-introduced, N1h and MC rows that `--packument` (seed only, like
  `check`) does not evaluate.

Anything that could not be evaluated is listed with the reason. Missing evidence is never reported
as a clean result. `why` also records, locally, that it was asked about that version (best-effort; it never changes
its output or exit code).

**5. Stop and restore:**

```console
$ chaingate stop
✓ Proxy stopped
✓ .npmrc restored
```

`chaingate stop` signals only the process recorded for this scope, and only after that process answers on
127.0.0.1:6173 as the ChainGate proxy with the same pid. It prints "Proxy stopped" only once the process has exited and
the port is closed, waiting up to about 8 seconds.

The stop does not succeed when:
- the process does not exit in time;
- it is not confirmed to be the proxy;
- the operating system refuses the check.

In those cases nothing is changed, the `.npmrc` block is left in place, the command says what it found, and it exits
with code 1. A pid can be reused by another process in the milliseconds between the last check and the signal; signals
cannot rule that out.

While ChainGate's block is in your `.npmrc`, npm sends every request to the proxy. If the proxy is
not running, for example after a restart, npm cannot install anything until you either run
`chaingate init` again, which restarts the proxy on the active seed, or run `chaingate stop`, which
restores `.npmrc`.

**Updating the seed.** Switch to another v3 seed you have with
`chaingate update-seed --seed <folder>/chaingate-seed-v3.db` (add `--unsigned-development` only for an
unsigned seed), and go back to the
previous one with `chaingate update-seed --rollback`. A running proxy keeps its current seed until
you restart it with `chaingate stop && chaingate init`. On a host that uses a v3 seed,
`chaingate update-seed` without `--seed` **refuses**, because v3 seeds cannot be downloaded
automatically. `update-seed --seed` accepts v3 seeds only; a legacy seed file is refused (see
[Seed bundles](#seed-bundles)).

**One seed command at a time.** `init`, `update-seed` and `update-seed --rollback` take a lock on the
ChainGate directory (the file `.seed-mutation.lock`) before they read or change anything about seeds.
A second seed command started meanwhile waits about 2 seconds, then stops with "another seed command
... is running" and changes nothing; run it again when the first has finished. The proxy, `status`
and `doctor` never wait for it. If a command is killed, the operating system releases the lock.
ChainGate 0.1.2 and earlier do not take this lock, so do not run seed commands from different
versions against the same directory. Seed commands are not supported on network filesystems or FAT.

**If a seed command is interrupted.** On Linux and macOS, the next seed command first finishes or
undoes an interrupted activation (`status` and `doctor` report one that is pending; they never repair
it themselves). If that record is unreadable, seed commands stop and say so: inspect
`chaingate status` and `chaingate doctor --json`, then rename the file to
`.activation-intent.json.held-<UTC timestamp>` yourself; ChainGate never deletes it. Partial copies left
by a killed command are removed by a later seed command, once the process that made them has exited
and they are more than 15 minutes old. Until then, `doctor` lists them under `seed-leftovers`.

**Space.** Installing a seed copies it first, so it needs about the seed's size free **in addition to**
what is already used, plus the small sidecar files and a 64 MiB reserve, on the filesystem that holds
the ChainGate directory. ChainGate refuses up front when there is clearly not enough. That check is
not a guarantee, because other programs can use space at the same time. A copy that fails is removed,
and the active seed stays as it was. Seed metadata files are read with fixed size limits (4 KiB for
`.sha256` and `.sig`, 64 KiB for `bundle.json` and `config.json`), and a FIFO, device or other
non-regular file in their place is refused.

## Seed bundles

There are two kinds of seed.

- **v3 detection seed**, installed by `init --seed` or `update-seed --seed`. It is built from public
  registry metadata on the maintainer's private collection servers and published as signed GitHub
  releases (`seed-v3.*`), starting with `seed-v3.1-full`. **You download it yourself; it is not
  downloaded automatically.** It is opened read-only and checked against its `.sha256` file. It counts
  as authenticated only when its signature verifies against the built-in key (see SECURITY.md).
- **Legacy witness seed**, published as `seed-v2.x` GitHub releases. On a new install, `chaingate init`
  without `--seed` downloads this signed seed for the older witness store. It does **not** set up v3
  detection, and `init` says so.

**The legacy witness seed, in detail:**

- It is never installed on a host that uses a v3 seed, and never without a valid signature.
- `--force` does not replace the witness database, and `--no-seed` never downloads. `--seed` and
  `--no-seed` together are refused.
- To refresh the legacy seed of an existing witness database, run `chaingate update-seed`, or
  `chaingate init --seed <legacy db> --force`. Stop the proxy first. The refresh happens in place, in
  one database transaction, and keeps your local decisions and overrides. Baselines the proxy
  recorded for versions the new seed does not contain are not kept, as before.
- Downloads are limited to 256 MiB for the database and 4 KiB for each signature file, with time
  limits, and the temporary download directory is removed afterwards.

**An interrupted legacy installation.** ChainGate marks a legacy seed installation as pending
(`witness.db.install-pending.json`) before it changes the witness database. While it is pending,
`chaingate doctor` reports the seed signature as unverifiable, and `init`, `allow` and the other
commands that pass ChainGate's integrity check refuse, except the one that completes the
installation. To complete it, run the same command again with the same seed: `chaingate update-seed`,
or `chaingate init --seed <legacy db> --force`.

Completing it needs the **exact** seed that was being installed and its signature files. This applies
to a local legacy bundle as much as to a published release, so **keep the original bundle until the
installation has completed**. If that seed or its signature files are no longer available, the
installation stays pending: ChainGate has no supported way to substitute another seed or to reset it.
Do not delete the witness database or the marker file to get past this, and do not try to bypass
signature verification. Other integrity failures are reported as before; completing an installation
does not skip them.

[SECURITY.md](SECURITY.md) describes the full trust model.

## What's Next

**Detection rules as code.** Export the gate rules and their evidence so that your own tools can
read and audit them, instead of receiving a single score.

**Structured evidence output.** One documented format for a decision and the evidence behind it.

**Integrations.** SIEM, EDR, CI pipelines and agent workflows that read that format.

Also planned: a larger corpus and more calibration, PyPI support, and plugins for Artifactory and
Nexus.

## Attack Coverage (from the corpus)

The middle column is the pattern layer's result in the validation corpus: the validation script reports
`detected=true` with the reasons shown. Under `cft-policy-1.2` those pattern signals are contributing
detail, so they do not warn on their own. The last column is what 0.1.4 does in its own fixture tests.
None of this comes from live registry traffic.

| Attack | Pattern layer, validation corpus | 0.1.4 (`cft-policy-1.2`), fixture tests |
|--------|----------------------------------|------------------------------------------|
| **Axios 1.14.1** | Provenance stopped within the major version, plus three supporting signals: a new email domain (proton.me), a privacy-focused provider, and a switch from automated to manual publishing | ALLOW when the metadata is seen; a named N1h WARN when the tarball is fetched (the release adds plain-crypto-js, which runs a `postinstall` script) |
| **Event-stream 3.3.6** | BLOCK at 3.3.5 for an abrupt handover to a new publisher (right9ctrl), carried to 3.3.6 because the same publisher released it | not tested under 1.2; a publisher change is contributing |
| **Shai-Hulud** | Publisher identity change across 500+ packages (fixture-verified) | the fixture models only the publisher change: ALLOW, recorded as contributing |
| **Ua-parser-js** | New unverified domain after established baseline (fixture-verified) | not tested under 1.2 |
| **Tarball replaced after publication** (trivy-shaped fixture) | n/a | BLOCK (content hash) |

**Limitation.** Under `cft-policy-1.2` a release warns only on a named rule. A takeover that changes the publisher,
the provenance, the dependencies or the code, but adds no install script, no dependency that runs one and no
manifest mismatch, gets no warning unless the seed's strict tier marks the release. A takeover through the same CI/CD
workflow, as the same publisher, that changes only the code looks normal in the metadata. Code analysis is needed for
those cases.

## Architecture

```
┌───────────────────────────────────────────────┐
│                CHAINGATE PROXY                │
│                                               │
│  ┌──────────────┐   ┌──────────────────────┐  │
│  │   WITNESS    │   │  SEED (v3)           │  │
│  │ content hash │   │  advisories, history │  │
│  │ pkg profiles │   │  strict / loose tier │  │
│  │ append-only  │   └──────────┬───────────┘  │
│  └──────┬───────┘              │              │
│         ▼                      ▼              │
│  ┌─────────────────────────────────────────┐  │
│  │      POLICY cft-policy-1.2              │  │
│  │  FACTS (advisory, content hash) → BLOCK │  │
│  │  NAMED RULES (strict tier, install-     │  │
│  │    introduced, N1h, MC)         → WARN  │  │
│  │  CONTRIBUTING (publisher, deps, prove-  │  │
│  │    nance, age, scope, size, npm) → note │  │
│  └─────────────────────────────────────────┘  │
└───────────────────────────────────────────────┘
```

## Ecosystem Support

| Ecosystem | Status |
|-----------|--------|
| npm | Proxy, CLI, gates and witness store built |
| PyPI | Metadata collector built; detection planned |
| Docker Hub | Planned |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Feedback, questions and contributions for other ecosystems
are welcome.

## License

Apache 2.0. See [LICENSE](LICENSE).

## Contact

Built by Rizwan Bedekar.
Email: rbedekar@zeroinsec.com
GitHub: [@r-bedekar](https://github.com/r-bedekar)

