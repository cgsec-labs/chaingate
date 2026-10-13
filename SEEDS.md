# ChainGate v3 detection seeds

This file records the exact identity of each v3 detection seed that is offered for download, and
how to check a download. It lives in the signed git history, so the digests below can be verified
through the maintainer's git signing key, independently of the release page that hosts the files.

A v3 seed is never downloaded automatically: you pass it to `chaingate init --seed`.

## seed-v3.1-full: signed v3 detection seed (current)

**Status:** published as the GitHub pre-release
[seed-v3.1-full](https://github.com/r-bedekar/chaingate/releases/tag/seed-v3.1-full), for
`@cgsec/chaingate` 0.1.4.

- **Signed.** The seed is signed with the ChainGate seed key `ed25519:09f6c9fdb8f5a2ea`, the key built into the
  runtime (`witness/seed_verify.js`). The runtime checks the signature before it imports anything, and the seed
  installs in `authenticated` mode.
- **Git record.** The signed annotated tag `seed-v3.1-full` points at the signed marker commit
  `a283b65a93760c9392a97e6a76182521f86de9b0`, whose `SEED-RELEASE.md` records the seed, key, runtime, record and asset
  digests.

| Field | Value |
|---|---|
| file | `chaingate-seed-v3.db`, 1,960,910,848 bytes |
| file SHA-256 | `a4c4e364de00653bea01c9f0a5ca5655a6ba2e2488e9a96a7da045f75bc89790` |
| data cutoff | 2026-10-12T12:18:13Z |
| content | 367,580 npm packages and 736,659 lineages; 810 pinned package versions |
| contract and read layout | `cft-seed-v3-contract-1.1`, `g10-rl1` |
| signing key | `ed25519:09f6c9fdb8f5a2ea` |

### Verify the download

The seed key, save it as `chaingate-seed-key.pem`:

```
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAP2W40LmbxTrDqDKaOpbfWD/xrbSPW4hz6RqQxZFte5E=
-----END PUBLIC KEY-----
```

The signature is Ed25519 over the database's SHA-256 written as 64 lower-case hex characters, with no newline. With
OpenSSL 3:

```
H=$(sha256sum chaingate-seed-v3.db | cut -d' ' -f1)
[ "$H" = "$(cut -c1-64 chaingate-seed-v3.db.sha256)" ] && echo "digest OK"
printf '%s' "$H" > msg.txt
openssl pkeyutl -verify -pubin -inkey chaingate-seed-key.pem -rawin -in msg.txt -sigfile chaingate-seed-v3.db.sig
```

The expected output is `digest OK`, then `Signature Verified Successfully`.

### Asset digests (sha256)

```
a4c4e364de00653bea01c9f0a5ca5655a6ba2e2488e9a96a7da045f75bc89790  chaingate-seed-v3.db
bcf624c23dd4a5a9f0a86bff83cafef9d530956b742ea2ea301991ceefc527ec  chaingate-seed-v3.db.sha256
c5a06109926cd623cc8cfdc25a6986ce865a33c7ccc5119d98b989bb0d095b6f  chaingate-seed-v3.db.manifest.json
b2cf178c981033e66b0573b8aad57243efe2f395efadea4ba84d7fb613821ac3  chaingate-seed-v3.db.sig
b2715a4041ebc3c4e6ed1d04cc62f8d085c6093cad65a3dc6db2eda6e747e755  chaingate-seed-v3.db.manifest.sig
14e5830c6b1693c5608196fb648adc1b6da93b23f480a5d8e9e2e4c98155c66c  THIRD_PARTY_NOTICES.txt
80e3ce8965b49a27c8689a9e51990941c5003d6bb282236bb07c9df202d3906f  chaingate-seed-v3.db.gz
```

### Use it

Download `chaingate-seed-v3.db`, `chaingate-seed-v3.db.sha256` and `chaingate-seed-v3.db.sig` into one folder, then:

```bash
chaingate update-seed --seed <folder>/chaingate-seed-v3.db     # an existing install
chaingate init --seed <folder>/chaingate-seed-v3.db            # a new install
```

Do not add `--unsigned-development`. This seed is signed and never needs it; that option is only for unsigned
engineering and test seeds.

To request a correction or a removal (for example a withdrawn advisory or a wrong pairing), open an issue at
https://github.com/r-bedekar/chaingate/issues. Corrected seeds are cut with the regular classification refresh, every one
to two weeks.

The seed is licensed CC BY 4.0; third-party data keeps its own terms (see `THIRD_PARTY_NOTICES.txt` on the release).

## seed-v3.0-rc3: unsigned engineering and test seed, never published as a release

**Status:** never published as a seed release. It is the unsigned seed used for engineering and
measurement, not the current seed. Its record is kept below.

- **Not release-qualified.** It passed the bootstrap gate profile only; the release profile has not
  run.
- **Unsigned.** It carries no seed signature. Use it only with `--unsigned-development`; the tool
  reports `authenticated: false`.
- **Git signature, not a seed signature.** The git commit and tag that record these digests are
  signed with the maintainer's git signing key. That authenticates this record, not the seed itself.

| Field | Value |
|---|---|
| file | `chaingate-seed.db`, 1,943,855,104 bytes |
| file SHA-256 | `974c7d7ea2f24ef627074517ea49b2f089d5e8108bc22b60401e6b1b612376dc` |
| `chaingate-seed.db.sha256` (contents: the file SHA-256 and a newline, no filename) | SHA-256 `eef7045b9c23272d7ad41d544ae4ac442ec5bbadce1751238b9e01b3069d4bb2` |
| `chaingate-seed.db.manifest.json` | SHA-256 `e140e806f7b6a71dbb8ba7fc53fc52bfa04294d04bbf3fce585818bbdb7fd957` |
| seed logical digest | `b3f9b1ab0b0ac2d12da011b10fceaa46562548fbd8e4c6dfeaefffb6d54c9521` |
| corpus snapshot digest | `d47e8679d6dd4c5f295f5c9201db08b99b28c391a3a1981e77cce3202875941e` |
| corpus snapshot | 2026-09-19T23:50:26+03:00; 368,879 packages; 23,752,890 versions |
| gate profile | `bootstrap` |

### 1. Verify this record (the git signature)

The maintainer's git signing key:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIADj46VirEcIgq2xi6UiH66C7vx1UPiiZynIoNoIh28l
```

- **Fingerprint:** `SHA256:zbLchuE+udpzKR52Oiv2129cKjL9smHZ8d+Ul2k+LdQ`.
- **Principal:** `rbedekar@zeroinsec.com`.
- **Confirm the key through a second channel:** GitHub lists it as the signing key of
  `@r-bedekar`, at `https://api.github.com/users/r-bedekar/ssh_signing_keys`. Compare the full key.

**Online steps**, done once:

```bash
git clone https://github.com/r-bedekar/chaingate.git
cd chaingate
git fetch --tags
```

**Offline steps:**

```bash
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIADj46VirEcIgq2xi6UiH66C7vx1UPiiZynIoNoIh28l\n' > signer.pub
ssh-keygen -lf signer.pub               # must show SHA256:zbLchuE+udpzKR52Oiv2129cKjL9smHZ8d+Ul2k+LdQ
printf 'rbedekar@zeroinsec.com namespaces="git" %s\n' "$(cat signer.pub)" > allowed_signers
git -c gpg.ssh.allowedSignersFile=allowed_signers verify-tag seed-v3.0-rc3
git -c gpg.ssh.allowedSignersFile=allowed_signers verify-commit seed-v3.0-rc3^{commit}
git cat-file -p seed-v3.0-rc3           # the tag message carries the file SHA-256
```

**Expected output:**
- **Signature check:** both `verify` commands print
  `Good "git" signature for rbedekar@zeroinsec.com with ED25519 key SHA256:zbLchuE+udpzKR52Oiv2129cKjL9smHZ8d+Ul2k+LdQ`
  and exit 0.
- **A different key:** the check fails with `No principal matched`.
- **The record:** read this file at that commit (`git show seed-v3.0-rc3:SEEDS.md`) and use the file
  SHA-256 above as the trusted digest.

On Windows, run the same commands in Git Bash. They need Git 2.34 or later and OpenSSH's `ssh-keygen`.

### 2. If the seed comes as an archive

No archive of this seed is published yet. If one is published, its file name and its **archive SHA-256** are recorded
here, in the same signed history. The archive holds three files: `chaingate-seed.db`, `chaingate-seed.db.sha256` and
`chaingate-seed.db.manifest.json`.

Two different digests apply:
- **Archive SHA-256:** covers the downloaded `.tar.gz` file. It only shows that the download arrived intact.
- **Database SHA-256:** the file SHA-256 in the table above. It covers the database you import, and **it is the
  check that matters.** Verify the extracted database against it (step 3) before you import anything. The `.sha256` file
  inside the archive comes from the same place as the database, so a match with it proves nothing on its own.

**Linux:**

```bash
archive=<archive file name from this record>
archive_expected=<archive SHA-256 from this record>
echo "$archive_expected  $archive" | sha256sum -c -
mkdir seed && tar -xzf "$archive" -C seed && cd seed
```

**macOS:** the same, with `shasum -a 256 -c -` in place of `sha256sum -c -`.

**Windows (PowerShell; `tar` ships with Windows 10 version 1803 and later):**

```powershell
$archive = '<archive file name from this record>'
$archiveExpected = '<archive SHA-256 from this record>'
(Get-FileHash $archive -Algorithm SHA256).Hash.ToLower() -eq $archiveExpected
New-Item -ItemType Directory seed | Out-Null; tar -xzf $archive -C seed; Set-Location seed
```

The archive check must pass (`OK` on Linux and macOS, `True` in PowerShell). Then continue with step 3 inside the `seed`
folder.

### 3. Verify the database file

Compare with the **trusted digest from step 1**, not only with the `.sha256` file from the same
release page.

**Linux:**

```bash
expected=974c7d7ea2f24ef627074517ea49b2f089d5e8108bc22b60401e6b1b612376dc
[ "$(tr -d '[:space:]' < chaingate-seed.db.sha256)" = "$expected" ] && echo ".sha256 file matches"
echo "$expected  chaingate-seed.db" | sha256sum -c -
```

**macOS:** the same, with `shasum -a 256 -c -` in place of `sha256sum -c -`.

**Windows (PowerShell):**

```powershell
$expected = '974c7d7ea2f24ef627074517ea49b2f089d5e8108bc22b60401e6b1b612376dc'
(Get-Content .\chaingate-seed.db.sha256 -Raw).Trim() -eq $expected
(Get-FileHash .\chaingate-seed.db -Algorithm SHA256).Hash.ToLower() -eq $expected
```

Both lines must print `True`. For `cmd`, run `certutil -hashfile chaingate-seed.db SHA256` and
compare the output with the trusted digest, ignoring case.

### 4. Use it

Only after step 3 passed:

```bash
chaingate init --seed ./chaingate-seed.db --unsigned-development
```

### Data sources and attribution

The seed is derived data: package metadata and advisory identifiers. It contains no package code.

- **Package metadata** comes from the public npm registry, replicated through its public APIs.
- **Publisher and maintainer identities** are present only as unkeyed SHA-256 digests.
  - **They are pseudonymous, not anonymous.** Anyone who knows an address can recompute its digest.
- **Advisory identifiers** were obtained from the OSV API (`api.osv.dev`), not from npm's security
  endpoints:
  - **GitHub Advisory Database** (GHSA identifiers): licensed CC BY 4.0,
    https://github.com/github/advisory-database/blob/main/LICENSE.md.
  - **OpenSSF malicious-packages** (MAL identifiers): licensed Apache-2.0,
    https://github.com/ossf/malicious-packages/blob/main/LICENSE.
  - The seed records identifiers, versions and the resulting pins. It does not reproduce the
    advisory text.
- **Seven pins without a source or identifier** (`@immobiliarelabs/backstage-plugin-gitlab`, seven
  versions):
  - they are ChainGate analyst labels added on 2026-06-26 from a public incident report;
  - OSV has since published `MAL-2026-6526` for the same seven versions;
  - the frozen seed is unchanged and still shows them without a source.
