# Releasing chela

`.github/workflows/release.yml` runs on tag push - a release tag
(`v[0-9]+.[0-9]+.[0-9]+`, e.g. `v1.0.0`) or a pre-release tag with a suffix
(`v[0-9]+.[0-9]+.[0-9]+-*`, e.g. `v1.0.0-beta.1`). It builds every target's binaries
twice on fresh target dirs and hash-diffs the two passes (the reproducibility check),
assembles **one** archive with a subfolder per architecture plus the docs and the web
bundle, signs it and a `SHA256SUMS` aggregate with minisign, and attaches everything
to a GitHub release with the hashes inlined into the notes. A tag whose name contains
a `-` is published as a GitHub **pre-release** and is not marked "Latest".

## One-time setup

### 1. Generate a minisign keypair

Do this offline on a machine you trust. Keep the secret key off GitHub.

```sh
minisign -G -p chela.pub -s minisign.key   # prompts for a passphrase
```

### 2. Install repo secrets

In **Settings → Secrets and variables → Actions**:

| Name                   | Value                                                                       |
|------------------------|-----------------------------------------------------------------------------|
| `MINISIGN_PRIVATE_KEY` | Full contents of `minisign.key`, including the `untrusted comment:` header. |
| `MINISIGN_PASSWORD`    | The passphrase from step 1.                                                 |

The C minisign has no password env var; it reads the passphrase from stdin when
there is no tty. The workflow pipes `MINISIGN_PASSWORD` into `minisign -S` on stdin,
so no tty trickery is needed in CI.

### 3. Publish the public key

Paste `chela.pub` into `README.md` under "Verifying a release".

## Cutting a release

```sh
git tag v1.0.0                 # or a pre-release: git tag v1.0.0-beta.1
git push origin v1.0.0         #                   git push origin v1.0.0-beta.1
```

Keep the tag's version in step with the workspace version in `Cargo.toml`
(`[workspace.package] version`). A pre-release tag (`-beta.N`, `-rc.N`) publishes as
a GitHub pre-release.

Wall time: ~6–8 min cold cache, ~4 min warm.

## What ships per release

One combined archive, plus the web bundle on its own:

- `chela-<version>.zip` - everything in one: a subfolder per architecture
  (linux-x86_64, macos-x86_64, macos-aarch64, windows-x86_64), each with the `chela`
  and `chela-cli` binaries, plus the standalone `chela.html`, a `docs/` folder
  (README, SPEC, RECOVERY, MANUAL_RECOVERY, AUDITORS, licenses), and a README.txt
  (with the macOS Gatekeeper note). A double-clickable zip (Finder/Explorer open it
  natively); `unzip` and Archive Utility keep the Unix `+x` bit.
- `chela-<version>-web.html` - the standalone browser bundle on its own, since the
  recovery guide points heirs straight at it.
- Each file's `.minisig` and `.sha256`, plus `SHA256SUMS` and `SHA256SUMS.minisig`.

## Reproducibility failures

The workflow fails with `::error::<bin> not reproducible: <h1> != <h2>`. Likely causes
in order of frequency:

- A new dependency embeds a timestamp or PRNG constant - diff strings sections, vendor
  or pin.
- A `build.rs` writes the current time into generated code.
- A new rustc release changed code-gen determinism - pin `rust-toolchain.toml`.
- GitHub upgraded a runner image mid-month.

Don't paper over the failure - investigate first.

## Signing failures

Symptom: `minisign -S` reports "Password incorrect" or "Unable to parse key".

- `MINISIGN_PRIVATE_KEY` must be the **complete** key file including the
  `untrusted comment:` header and trailing newline.
- `MINISIGN_PASSWORD`: no leading or trailing whitespace.
- Reproduce locally (no tty needed, mirrors CI):
  `printf '%s\n' "$MINISIGN_PASSWORD" | minisign -S -m anything -s minisign.key`.

## Bumping pinned GitHub Action SHAs

Third-party actions in `ci.yml`, `audit.yml`, `pages.yml`, and `release.yml`
are pinned to commit SHAs (the version tag is in a trailing comment for humans, not
consumed by GitHub).
Dependabot opens a PR for each upstream release; review the diff before merging.

## Rotating the key

If compromised:

1. Generate a new keypair.
2. Update both repo secrets.
3. Update the public key in `README.md`.
4. Note the rotation in the next release's notes so verifiers refresh.

minisign has no revocation mechanism. Recipients who haven't updated may still trust
an old signature; in practice the README update lands before the next download.
