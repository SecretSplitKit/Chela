# Auditing chela

What's in the cryptographic core, where it came from, and the invariants the code
relies on. For someone reviewing the crypto; paired with [AGENTS.md](./AGENTS.md) for
code conventions.

## Threat model

chela defends against:

- **Loss of fewer than `M` shares.** Information-theoretic: any subset of size `< M`
  reveals nothing about the secret (S1).
- **A single transcription error** in a recovered card (S5).
- **Cross-split share contamination** — shares from two unrelated splits never silently
  combine (S6).

chela does **not** defend against:

- **A tampered build artifact.** Trust the signed release (§ 6) or build from the
  tagged commit.
- **A coalition of ≥ `M` cardholders.** Any `M` shares reconstruct the secret. That's
  the design.
- **A compromised process on the same machine** — argv copies, screen captures, swap
  files, hibernation files, and clipboard sniffers are out of scope.
- **A compromised browser** loading the standalone bundle. The WASM is only as trusted
  as the page it runs in; verify the HTML hash against the release.
- **Forensic recovery of cleared scrollback.** The TUI reveal screen uses the
  alt-screen buffer and falls back to `CSI 3J`, but neither is universally honoured.

## 1. Provenance

Every cryptographic primitive was written from scratch against the cited specification.
The BIP-39 wordlist is the only vendored data.

| Module                            | Spec                                          |
|-----------------------------------|-----------------------------------------------|
| `chela-primitives/src/sha256.rs`  | FIPS 180-4 § 6.2                              |
| `chela-primitives/src/ct.rs`      | Standard constant-time idioms                 |
| `chela-primitives/src/zeroize.rs` | `write_volatile` + `compiler_fence(SeqCst)`   |
| `chela-primitives/src/rng.rs`     | Platform syscalls (see § 3)                   |
| `chela-field/src/gf256.rs`        | FIPS 197 § 4.2 (Rijndael poly `0x11b`)        |
| `chela-sss/src/lib.rs`            | Shamir 1979 — Lagrange at x=0 over GF(2^8)    |
| `chela-bip39/src/lib.rs`          | BIP-0039                                      |

### BIP-39 wordlist verification

`chela-bip39/src/wordlist.rs` contains the 2048 English words verbatim. Canonical
SHA-256: `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`. Re-verify:

```sh
diff \
  <(curl -sL https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt) \
  <(awk -F'"' '/^    "/ {print $2}' chela-bip39/src/wordlist.rs)
```

## 2. Test vectors

All KATs are from primary sources.

| Test                                              | Source                                |
|---------------------------------------------------|---------------------------------------|
| SHA-256: empty, "abc", 56-byte, 112-byte, 1M-'a'  | FIPS 180-2 App B + NIST CAVP          |
| BIP-39 12 / 18 / 24-word vectors                  | Trezor python-mnemonic `vectors.json` |
| BIP-39 15-word and 21-word zero entropy           | Derived from BIP-39 § 4               |
| GF(2^8) `0x57 × 0x83 = 0xc1`                      | FIPS 197 § 4.1                        |
| GF(2^8) exhaustive inverse over non-zero          | Property test                         |
| SSS round-trip over every M-subset, M ≤ N ≤ 6     | Property test                         |

## 3. Entropy

The OS RNG is the only entropy source. `chela-sss::OsRng` wraps
`chela_primitives::rng::fill_bytes`. Tests inject `DeterministicRng` via the
`RandomSource` trait — never used outside `#[cfg(test)]`.

| Target  | Call                                                               |
|---------|--------------------------------------------------------------------|
| macOS   | `getentropy(buf, len)` via libSystem, 256-byte chunks              |
| Linux   | `getrandom(buf, len, 0)` via libc, loops on short reads            |
| Windows | `BCryptGenRandom(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG)` |
| wasm32  | host import `chela.random_bytes(ptr, len) -> i32`                  |
| other   | `RngError::Unsupported` — no fallback                              |

WASM embedders supply `chela.random_bytes`; `chela-serve` wires it to
`crypto.getRandomValues` on the linear-memory view.

Verify no other entropy source exists:

```sh
grep -rn 'thread_rng\|rand::\|OsRng::default' chela-*/src   # must be empty
```

## 4. `unsafe`

`unsafe_code` is denied workspace-wide. Five files opt in with module-level
`#[allow(unsafe_code)]`. Every `unsafe` block carries a `// SAFETY:` comment.

| File                                  | Purpose                                      |
|---------------------------------------|----------------------------------------------|
| `chela-primitives/src/rng.rs`         | OS RNG syscall externs + call sites          |
| `chela-primitives/src/zeroize.rs`     | `core::ptr::write_volatile` loop             |
| `chela-sss/src/lib.rs`                | One cast `&mut [Gf256]` → `&mut [u8]` to wipe polynomial coefficients. Sound because `Gf256` is `#[repr(transparent)]`. |
| `chela-tui/src/term.rs::raw_termios`  | `tcgetattr` / `tcsetattr` / `ioctl(TIOCGWINSZ)` FFI |
| `chela-wasm/src/lib.rs`               | `slice::from_raw_parts` to view JS-allocated linear-memory buffers |

## 5. Load-bearing invariants

### S1 — A single share reveals zero information

`chela-sss::split` samples fresh GF(2^8) coefficients per byte position from the
injected `RandomSource` — the `rng.fill_random(...)` call sits inside the per-byte
loop, so each byte gets independent coefficients.
Test: `sub_threshold_combine_does_not_recover_secret`.

### S2 — Any M of N shares recover the secret

`chela-sss::combine` computes `L_i(0)` once, then evaluates per-byte. Rejects duplicate
x-values and `x = 0` (the secret's coordinate).
Test: `round_trip_for_every_subset_of_every_m_n_up_to_6`.

### S3 — Transient secret-bearing buffers are wiped

Wipe primitive: `chela_primitives::zeroize::volatile_set` (`core::ptr::write_volatile`
per byte + `compiler_fence(SeqCst)`). Plain `fill(0)` is forbidden — the optimiser may
elide it.

| Location                                  | Wiped buffer(s)                                                                          |
|-------------------------------------------|------------------------------------------------------------------------------------------|
| `chela-sss::split`                        | RNG scratch, polynomial coefficients (`wipe_coeffs`)                                     |
| `chela-engine::split_with_rng`            | body (joined secret), per-share `sb` after consumption, BIP-39 `indices`, `entropy` Vec — pre-sized to defeat `extend_from_slice` realloc orphaning |
| `chela-engine::{encode,decode}_share_bip39` | SHA-256 digest scratch, decoded share `buf`                                            |
| `chela-engine::recover_secret`            | body (recovered secret), all share payload `Vec`s                                        |
| `chela-engine::interpret_body`            | re-encoded mnemonic `indices`                                                            |
| `chela-tui::wizard`                       | input mnemonic (via `SecretString`), recovered secret on reveal-decline and post-display |
| `chela-cli`                               | argv-derived mnemonic / passphrase / text, stdin share buffer, recovered secret. argv copies in the OS process listing still leak — CLI-inherent. |
| `chela-wasm`                              | `SplitRequest` / `RawShare` `impl Drop`; `chela_dealloc` volatile-wipes every buffer it frees |

Audit query:

```sh
grep -rn 'volatile_set\|\.zeroize()\|impl Drop' chela-*/src
```

### S4 — SHA-256 internal state is wiped on Drop

`Sha256` `impl Drop` volatile-wipes its 64-byte input buffer and 8-word state. The
256-byte message schedule `w` is wiped inside `compress` after the final state update.
Working variables `a..h` (32 bytes on the stack) are left to be overwritten by the
next compression call — documented limitation.

### S5 — Per-share checksum detects transcription errors

Each share carries `SHA-256(body || identifier || x)[..2]` as a 2-byte tail. Comparison
via `chela_primitives::ct::ct_eq`. Binding to both `identifier` and `x` also catches a
card swapped between two splits (the `x` is wrong relative to its content) or between
positions of one split. False-positive rate ≈ 1/65k per typo; the residual case is
caught by S6.
Test: `corrupted_share_word_detected`.

### S6 — Shares from different splits never silently combine

Two defences:

1. `recover_secret` rejects shares whose `(identifier, scheme, kind, threshold, total)`
   disagree → `MismatchedShares`.
2. If two splits coincidentally share the same identifier (~1/65k), Lagrange combines
   garbage; `parse_bundle` then reports `BundleCorrupt` because no candidate `kind_byte`
   reproduces the printed identifier.

Tests: `shares_of_different_secrets_rejected`,
`shares_from_two_splits_of_the_same_secret_rejected_as_bundle_corrupt`.

### S7 — No crates.io dependencies in the cryptographic core

```sh
grep '^name = ' Cargo.lock | sort -u   # only workspace members
```

`chela-share/fuzz` is its own workspace, excluded from the main one; its sole dep
(`libfuzzer-sys`) is a fuzz-only test harness and never reaches a release artifact.

## 6. Release signing

Published binaries and the bundled `chela.html` are signed with minisign. Public key
duplicated in `README.md`. Operator runbook in `RELEASING.md`.

Verify any release artifact:

```sh
minisign -V -p chela.pub -m <artifact>
sha256sum -c SHA256SUMS                # all artifacts in one shot
minisign -V -p chela.pub -m SHA256SUMS # confirm the aggregate is signed
```

A failed signature, or a `cargo build --locked` of the tagged commit that produces a
different hash than the release, is grounds to refuse the binary and file an issue.
