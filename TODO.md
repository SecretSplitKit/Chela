# chela TODO

## Shipped

- BIP-39 mnemonic split & recover (12 / 15 / 18 / 21 / 24 words + optional passphrase)
- Arbitrary text payload up to 255 bytes
- Wizard TUI (macOS + Linux) with raw-mode termios masked password input and
  `SecretString` zeroize-on-Drop
- Scriptable CLI (`split` / `recover`)
- Print-ready HTML paper backup
- OS RNG on macOS / Linux / Windows / WASM
- WASM webapp via `chela-serve` and the offline single-file `chela.html`
- KATs against FIPS 180-2, FIPS 197, BIP-0039
- Reproducible release builds, signed with minisign, `SHA256SUMS` aggregate
  attached + inlined in the GitHub release notes
- 60-second smoke fuzz on every PR (`.github/workflows/fuzz.yml`)

## Project rules

- **No external deps in the cryptographic core.** Vendor with provenance comments
  (the BIP-39 wordlist is the pattern), or hand-roll.
- **No `unsafe`** outside the five opt-in modules listed in AUDITORS.md § 4.
- **Crypto test vectors must come from a primary source** (RFC / FIPS / spec authoring
  repo).

## Pre-v1.0 release steps (operational, not code)

1. Generate the minisign keypair off-CI.
2. Paste the public key into `README.md` and `AUDITORS.md`.
3. Add `MINISIGN_PRIVATE_KEY` + `MINISIGN_PASSWORD` repo secrets.

## Ongoing — long-duration fuzzing

Two 4-hour runs already completed against `parse_share` / `parse_shares` with no
crashes. More fuzzing is always welcome before tagging a release or after any change
to the share parser:

```sh
cd chela-share/fuzz
cargo +nightly fuzz run parse_shares -- -max_total_time=14400   # 4 hours
```

Any crash → input committed under `chela-share/fuzz/crash-inputs/` plus a regression
test in `parse_share`'s unit suite.
