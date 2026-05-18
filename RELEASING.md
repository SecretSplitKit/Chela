# Releasing chela

`.github/workflows/release.yml` runs on tag push (`v[0-9]+.[0-9]+.[0-9]+`), builds
each artifact twice on fresh target dirs, hash-diffs the two passes, signs every
artifact + a `SHA256SUMS` aggregate with minisign, and attaches everything to a
GitHub release with the hashes inlined into the release notes body.

## One-time setup

### 1. Generate a minisign keypair

Do this offline on a machine you trust. Keep the secret key off GitHub.

```sh
minisign -G -p minisign.pub -s minisign.key   # prompts for a passphrase
```

### 2. Install repo secrets

In **Settings → Secrets and variables → Actions**:

| Name                   | Value                                                                       |
|------------------------|-----------------------------------------------------------------------------|
| `MINISIGN_PRIVATE_KEY` | Full contents of `minisign.key`, including the `untrusted comment:` header. |
| `MINISIGN_PASSWORD`    | The passphrase from step 1.                                                 |

minisign reads `MINISIGN_PASSWORD` from the env, so no tty trickery is needed in CI.

### 3. Publish the public key

Paste `minisign.pub` into:

- `README.md` under "Verifying a release"
- `AUDITORS.md` § 6

## Cutting a release

```sh
git tag v1.0.0
git push origin v1.0.0
```

Wall time: ~6–8 min cold cache, ~4 min warm.

## What ships per release

Every release attaches, per target (linux-x86_64, macos-x86_64, macos-aarch64,
windows-x86_64) plus one web bundle:

- `chela-<version>-<target>.tar.gz` (or `.zip` on Windows) — the binaries
- `<file>.sha256` — single-artifact hash
- `<file>.minisig` — minisign signature
- `chela-<version>-web.html` + `.sha256` + `.minisig` — standalone browser bundle
- `SHA256SUMS` — every artifact's hash, sorted, signed (`SHA256SUMS.minisig`)

The release notes body includes the `SHA256SUMS` block inline so verifiers can compare
without downloading the aggregate.

## Reproducibility failures

The workflow fails with `::error::<bin> not reproducible: <h1> != <h2>`. Likely causes
in order of frequency:

- A new dependency embeds a timestamp or PRNG constant — diff strings sections, vendor
  or pin.
- A `build.rs` writes the current time into generated code.
- A new rustc release changed code-gen determinism — pin `rust-toolchain.toml`.
- GitHub upgraded a runner image mid-month.

Don't paper over the failure — investigate first.

## Signing failures

Symptom: `minisign -S` reports "Password incorrect" or "Unable to parse key".

- `MINISIGN_PRIVATE_KEY` must be the **complete** key file including the
  `untrusted comment:` header and trailing newline.
- `MINISIGN_PASSWORD`: no leading or trailing whitespace.
- Reproduce locally: copy the secrets to a scratch dir,
  `MINISIGN_PASSWORD=... minisign -S -m anything -s minisign.key`.

## Bumping pinned GitHub Action SHAs

Third-party actions in `ci.yml`, `fuzz.yml`, and `release.yml` are pinned to commit
SHAs (the version tag is in a trailing comment for humans, not consumed by GitHub).
Dependabot opens a PR for each upstream release; review the diff before merging.

## Rotating the key

If compromised:

1. Generate a new keypair.
2. Update both repo secrets.
3. Update the public key in `README.md` and `AUDITORS.md`.
4. Note the rotation in the next release's notes so verifiers refresh.

minisign has no revocation mechanism. Recipients who haven't updated may still trust
an old signature; in practice the README / AUDITORS update lands before the next
download.
