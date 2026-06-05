# AUDITORS.md — reading chela end-to-end

You're here to convince yourself chela's cryptographic core does what it
claims, and that the claims are sound. The fastest path is to open every file
in `chela-primitives/`, `chela-field/`, `chela-sss/`, `chela-bip39/`, and
`chela-engine/` in the order below and read them with this document in the
other window.

## Threat model

chela defends against:

- **Loss of fewer than `M` shares.** Information-theoretic: any subset of size
  `< M` reveals nothing about the secret.
- **A single transcription error** in a recovered card — per-share checksums
  catch this before Lagrange is invoked.
- **Cross-split share contamination** — shares from two unrelated splits never
  silently combine.

chela does **not** defend against:

- **A tampered build artifact.** Trust the signed release (see Release
  verification below) or build from the tagged commit.
- **A coalition of ≥ `M` cardholders.** Any `M` shares reconstruct the secret.
  That's the design.
- **A compromised process on the same machine** — argv copies, screen captures,
  swap files, hibernation files, and clipboard sniffers are out of scope.
- **A compromised browser** loading the standalone bundle. The WASM is only as
  trusted as the page it runs in; verify the HTML hash against the release.
- **Forensic recovery of cleared scrollback.** The TUI reveal screen uses the
  alt-screen buffer and falls back to `CSI 3J`, but neither is universally
  honoured.

## Reading order

Read the files in this order. Each section tells you what the file does, the
spec it implements, what to verify yourself, and the reasoning behind any
choice that isn't obvious from the spec.

### 1. `chela-primitives/src/sha256.rs` — SHA-256

Implements FIPS 180-4 § 6.2.

- The 8 initial hash values, the 64 round constants, the message schedule, and
  the compression function should all match the FIPS document verbatim.
- The `impl Drop` block wipes the 64-byte input buffer and the 8-word state.
  The 256-byte message schedule `w` is wiped at the end of `compress` (a stack
  variable; relies on `volatile_set`).
- Test vectors: empty string, "abc", 56-byte, 112-byte, 1M-of-'a' — FIPS 180-2
  App B + NIST CAVP. Confirm the literal expected digests against the FIPS
  document; do not trust the file's annotations alone.

Working variables `a..h` (32 bytes on the stack) are not wiped after each
compression call — they're overwritten on the next call but remain in stack
memory between calls. Documented limitation.

### 2. `chela-primitives/src/ct.rs` — constant-time equality

One function (`ct_eq`) — the standard XOR-OR-reduce idiom. Verify it compiles
to a constant-time sequence in release builds (no early return).

### 3. `chela-primitives/src/zeroize.rs` — volatile wipe

`volatile_set` is `core::ptr::write_volatile` per byte plus a
`compiler_fence(SeqCst)`. The fence is the load-bearing part — without it the
compiler can elide the writes since the buffer is "dead" after the call.

Plain `.fill(0)` is forbidden and not present anywhere in `chela-*/src` that
touches a secret-bearing buffer. Audit query:
```sh
grep -rn '\.fill(0)' chela-*/src
```
Any hit must operate on a non-secret buffer.

### 4. `chela-primitives/src/rng.rs` — OS RNG

Per-platform syscalls. macOS: `getentropy` in 256-byte chunks. Linux:
`getrandom` looping on short reads. Windows: `BCryptGenRandom`. wasm32: a JS
host import `chela.random_bytes(ptr, len) -> i32` that the embedder wires to
`crypto.getRandomValues`. No fallback on unsupported targets — `RngError::Unsupported`.

`OsRng` is the only entropy source. Confirm:
```sh
grep -rn 'thread_rng\|rand::\|OsRng::default' chela-*/src
```
Must be empty.

### 5. `chela-field/src/gf256.rs` — constant-time GF(2^8)

Add is XOR. Multiply is 8 unconditional rounds of mask-driven shift + mask-
driven reduction mod `0x11b` (Rijndael polynomial, AES). Inverse via the
fixed-shape squaring chain `x^254` (Fermat in GF(2^8) since `|F*| = 255`).
`inv(0) == 0` is intentional so `inv` is total — callers must ensure `x = 0`
never reaches Lagrange (`chela-sss::combine` rejects it).

No tables. Tables would leak data-dependent timing via the CPU cache.

KAT: `mul(0x57, 0x83) = 0xc1` — FIPS 197 § 4.1.

### 6. `chela-sss/src/lib.rs` — Shamir split / combine

`split` samples fresh coefficients per byte position from the injected
`RandomSource`. The `rng.fill_random` call sits inside the per-byte loop, so
each byte gets independent coefficients.

`combine` rejects duplicate x-coordinates and `x = 0` (the secret's
coordinate). Lagrange interpolation at `x = 0`: compute the coefficients once,
then apply per byte.

Allocation-free — callers pass in `out_x: &mut [u8]` and
`out_shares: &mut [&mut [u8]]`. Allocation lives one level up in `chela-engine`,
which always has a real allocator. Cost: std callers have to build a
`Vec<&mut [u8]>` of slice refs.

### 7. `chela-bip39/src/lib.rs` — BIP-0039 codec

Entropy ↔ 11-bit indices with the BIP-39 checksum byte (top `checksum_bits`
bits of `SHA-256(entropy)`). Implements BIP-39 § 4 verbatim. Vectors come from
the Trezor python-mnemonic `vectors.json` (12/18/24-word) and derived 15/21-word
zero-entropy cases.

### 8. `chela-bip39/src/wordlist.rs` — vendored English wordlist

2048 words, in order, verbatim from BIP-0039. Verify against the canonical
hash `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`:

```sh
diff \
  <(curl -sL https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt) \
  <(awk -F'"' '/^    "/ {print $2}' chela-bip39/src/wordlist.rs)
```

### 9. `chela-engine/src/lib.rs` — bundle codec, identifier, per-share checksum

The orchestration layer. Five things matter here:

1. **What SSS splits is just the body.** No magic byte, no in-bundle version,
   no in-bundle kind tag, no in-bundle checksum. For BIP-39: raw entropy
   followed by optional passphrase bytes. For text: raw UTF-8.
2. **The 16-bit identifier is `SHA-256(body || kind_byte)[..2]`.** `kind_byte`
   is a 1-byte tag (payload type × entropy length × passphrase presence) mixed
   into the hash but never written into the body. At recover time the engine
   enumerates the ≤11 candidate `kind_byte` values that fit the observed body
   length, recomputes the identifier, and picks the match. False-positive rate
   ≈ 11/65 536.
3. **The 16-bit per-share checksum is `SHA-256(share || identifier || x)[..2]`.**
   Without it, a single transcription error propagates through Lagrange into a
   wrong but identifier-validating secret. Binding to `identifier` and `x`
   also catches a card swapped between positions of the same split, or between
   two splits.
4. **Word-count ambiguity.** Several byte counts pack into the same 11-bit
   word count (e.g. 36 and 37 bytes both pack into 27 words). Recovery
   enumerates the candidate byte counts and picks the one whose per-share
   checksum verifies for every share.
5. **Allocation lives here, not in `chela-sss`.** The engine builds the
   `Vec<&mut [u8]>` of slice refs that `chela-sss::split` needs.

### 10. `chela-share/` — share text format + JSON + paper-backup HTML

`parse_share` / `parse_shares` is the only parser that ingests externally-
supplied text. Fuzzed via `chela-share/fuzz`; a smoke run executes on every
PR. The `is_ascii()` guard at the byte slice in `parse_share` is load-bearing —
its absence is what the fuzz harness originally tripped.

`html::render_paper_html` produces a single self-contained HTML document with
embedded CSS. The user prints to PDF from the browser. A PDF library would
have pulled in dependencies; static HTML survives offline indefinitely.

The JSON share schema (`chela.share.v1` / `chela.shares.v1`) is documented in
`SPEC.md` § 5.2.

### 11. `chela-wasm/src/lib.rs` — browser FFI

Exposes a C-ABI an HTML/JS page calls to split secrets, recover them, and
render paper backups. Seven `unsafe` blocks (the only ones in this crate),
each with a `// SAFETY:` comment. `impl Drop` on every
secret-bearing request type; `chela_dealloc` volatile-wipes every buffer it
frees.

## Cross-cutting concerns

### Secret-bearing buffers and where they're wiped

Wipe primitive: `chela_primitives::zeroize::volatile_set` (`core::ptr::write_volatile`
per byte + `compiler_fence(SeqCst)`). Plain `fill(0)` is forbidden — the
optimiser may elide it.

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

### The five `unsafe` opt-ins

`unsafe_code` is denied workspace-wide. Five files opt in with module-level
`#[allow(unsafe_code)]`. Every `unsafe` block carries a `// SAFETY:` comment.

| File                                  | Purpose                                      |
|---------------------------------------|----------------------------------------------|
| `chela-primitives/src/rng.rs`         | OS RNG syscall externs + call sites          |
| `chela-primitives/src/zeroize.rs`     | `core::ptr::write_volatile` loop             |
| `chela-sss/src/lib.rs`                | One cast `&mut [Gf256]` → `&mut [u8]` to wipe polynomial coefficients. Sound because `Gf256` is `#[repr(transparent)]`. |
| `chela-tui/src/term.rs::raw_termios`  | `tcgetattr` / `tcsetattr` / `ioctl(TIOCGWINSZ)` FFI |
| `chela-wasm/src/lib.rs`               | `slice::from_raw_parts` to view JS-allocated linear-memory buffers |

### No crates.io dependencies

```sh
grep '^name = ' Cargo.lock | sort -u
```
Only workspace members. `chela-share/fuzz` is its own workspace, excluded from
the main one; its sole dep (`libfuzzer-sys`) is a fuzz-only test harness and
never reaches a release artifact.

## Release verification

Published binaries and the bundled `chela.html` are signed with minisign. The public
key is in `README.md`; save its block to a file named `chela.pub`. Operator runbook in
`RELEASING.md`.

Verify any release artifact:

```sh
minisign -V -p chela.pub -m <artifact>
sha256sum -c SHA256SUMS                # all artifacts in one shot
minisign -V -p chela.pub -m SHA256SUMS # confirm the aggregate is signed
```

A failed signature, or a `cargo build --locked` of the tagged commit that produces a
different hash than the release, is grounds to refuse the binary and file an issue.
