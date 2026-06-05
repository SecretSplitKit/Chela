# AGENTS.md — auditing chela with an AI agent

You have been pointed at the chela repository and asked to verify it is secure
and well packaged. This file tells you what to check and how to check it.

chela splits a BIP-39 wallet seed or short password into N shares; any M of them
recover the original. The cryptographic core is in-tree — no third-party crates
beyond the OS RNG. A human auditor uses `AUDITORS.md` to walk the codebase; this
file is for an agent that can run shell commands.

## Repo orientation

```
chela-primitives/   SHA-256 (BIP-39 checksum only), CRC-11, ct_eq, volatile zeroize, OS RNG
chela-field/        constant-time GF(2^8)
chela-sss/          Shamir split / combine
chela-bip39/        BIP-0039 codec + English wordlist
chela-share/        share text format + paper-backup HTML
chela-engine/       bundle codec + split / recover orchestration
chela-tui/          interactive wizard binary
chela-cli/          scriptable CLI binary
chela-wasm/         C-ABI FFI for the browser bundle
chela-bundle/       builds the standalone chela.html
```

`chela-share/fuzz/` is excluded from the main workspace. It depends on
`libfuzzer-sys` — the only crates.io dep in the repo, test-harness-only.

## Security checks

### No crates.io dependencies in the cryptographic core

```sh
grep '^name = ' Cargo.lock | sort -u
```
Expected: only workspace members. Any third-party crate is a finding.

### unsafe_code is denied workspace-wide

```sh
grep -rn '#!\[forbid(unsafe_code)\]\|#!\[deny(unsafe_code)\]\|allow(unsafe_code)' chela-*/src
```
Expected: every opt-in is module-level `#[allow(unsafe_code)]` in one of:
- `chela-primitives/src/rng.rs` (OS RNG syscall externs)
- `chela-primitives/src/zeroize.rs` (`core::ptr::write_volatile`)
- `chela-sss/src/lib.rs` (one cast to wipe polynomial coefficients)
- `chela-tui/src/term.rs` (termios FFI)
- `chela-wasm/src/lib.rs` (linear-memory slice FFI)

Each `unsafe` block must carry a `// SAFETY:` comment.

### Secret-bearing buffers are wiped via volatile_set

```sh
grep -rn 'volatile_set\|\.zeroize()\|impl Drop' chela-*/src
```
Plain `fill(0)` or `= [0; N]` on a buffer that held secret bytes is a finding —
the optimiser may elide either. `chela-primitives::zeroize::volatile_set` is
the only sanctioned wipe.

### Crypto test vectors come from a primary source

Every `#[test]` involving cryptographic output should either cite its source
(FIPS 180-2, FIPS 197, BIP-39, NIST CAVP) in the test name or a comment, or be
a property test. Spot-check ten tests.

### Pinned third-party GitHub Actions

```sh
grep -rn 'uses:' .github/workflows/
```
Expected: every `uses:` value is a 40-character commit SHA, not `@v4` or
`@stable`. Trailing `# tag` comment is informational.

## Packaging checks

### Release signing

`.github/workflows/release.yml` signs every artifact with minisign and produces
a signed `SHA256SUMS` aggregate. The public key is in `README.md`.

### Reproducible builds

The release workflow builds every binary twice in independent target
directories and fails if they hash-differ. Pre-conditions (deterministic linker
flags, `SOURCE_DATE_EPOCH`) live in `release.yml` and `Cargo.toml`.

### Pre-push hook

`scripts/git-hooks/pre-push` runs the CI matrix locally before push. Mirrors
`.github/workflows/ci.yml` step for step.

### Fuzz harness

`chela-share/fuzz/` fuzzes the share-text parser, the only externally-supplied
input. A smoke run executes on every PR via `.github/workflows/fuzz.yml`.

## What this file is not

- A contributor onboarding guide. See `CONTRIBUTING.md`.
- A code walkthrough. See `AUDITORS.md`.
- The wire-format spec. See `SPEC.md`.
