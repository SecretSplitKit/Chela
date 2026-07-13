# AUDITORS.md - reading chela end-to-end

You're here to convince yourself chela's cryptographic core does what it
claims, and that the claims are sound. The fastest path is to open every file
in `chela-primitives/`, `chela-field/`, `chela-sss/`, `chela-bip39/`, and
`chela-engine/` in the order below and read them with this document in the
other window.

## Threat model

chela defends against:

- **Loss of fewer than `M` shares.** Information-theoretic: any subset of size
  `< M` reveals nothing about the secret.
- **A single transcription error** in a recovered card - per-share checksums
  catch this before Lagrange is invoked.
- **Cross-split share contamination** - shares from two unrelated splits never
  silently combine. Each split carries a random recovery set id (a per-split nonce, § 9); a
  mismatch is `MismatchedShares`. Because the recovery set id is drawn per generation, even
  two splits of the *same* secret carry different recovery set ids and are correctly
  refused (SPEC.md § 3.2).
- **A wrong recombination returning a wrong secret.** A one-byte body integrity tag
  (§ 9) binds the reconstructed secret, so a wrong share subset that slips past the
  recovery set id check (for instance a ~1/2048 recovery set id collision) fails closed as `BundleCorrupt`
  rather than decoding into a plausible wrong secret (SPEC.md § 5).

chela does **not** defend against:

- **A tampered build artifact.** Trust the signed release (see Release
  verification below) or build from the tagged commit.
- **A coalition of ≥ `M` cardholders.** Any `M` shares reconstruct the secret.
  That's the design.
- **A compromised process on the same machine** - argv copies, screen captures,
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

### 1. `chela-primitives/src/sha256.rs` - SHA-256

Implements FIPS 180-4 § 6.2. **Scope:** two callers - `chela-bip39` validates a
mnemonic's built-in checksum (§ 7), and `chela-engine` computes the one-byte body
integrity tag `SHA-256(payload ‖ kind_byte)[0]` (§ 9). There is no SHA identifier and
no SHA per-share checksum (that is CRC-11, § 4a). SPEC.md § 1.3.

- The 8 initial hash values, the 64 round constants, the message schedule, and
  the compression function should all match the FIPS document verbatim.
- The `impl Drop` block wipes the 64-byte input buffer and the 8-word state.
  The 256-byte message schedule `w` is wiped at the end of `compress` (a stack
  variable; relies on `volatile_set`).
- Test vectors: empty string, "abc", 56-byte, 112-byte, 1M-of-'a' - FIPS 180-2
  App B + NIST CAVP. Confirm the literal expected digests against the FIPS
  document; do not trust the file's annotations alone.

Working variables `a..h` (32 bytes on the stack) are not wiped after each
compression call - they're overwritten on the next call but remain in stack
memory between calls. Documented limitation.

### 2. `chela-primitives/src/ct.rs` - constant-time equality

One function (`ct_eq`) - the standard XOR-OR-reduce idiom. Verify it compiles
to a constant-time sequence in release builds (no early return).

### 3. `chela-primitives/src/zeroize.rs` - volatile wipe

`volatile_set` is `core::ptr::write_volatile` per byte plus a
`compiler_fence(SeqCst)`. The fence is the load-bearing part - without it the
compiler can elide the writes since the buffer is "dead" after the call.

Plain `.fill(0)` is forbidden and not present anywhere in `chela-*/src` that
touches a secret-bearing buffer. Audit query:
```sh
grep -rn '\.fill(0)' chela-*/src
```
Any hit must operate on a non-secret buffer.

### 4. `chela-primitives/src/rng.rs` - the CSPRNG sources

Every random byte chela ever uses comes from one function, `fill_bytes`, and it
is a thin shim over the operating system's own CSPRNG. There is no userspace PRNG,
no seed chela controls, and no software fallback: an unsupported target returns
`RngError::Unsupported` and the split aborts rather than emitting low-entropy
shares. The two consumers are `chela-engine` (the per-split recovery set id and the
`N` share `x`-coordinates) and `chela-sss` (the Shamir polynomial coefficients).

The per-platform call, and the security-relevant detail of each, is:

| Target | Call | Source | Notes |
|---|---|---|---|
| macOS | `getentropy(buf, len)` (`<sys/random.h>`, libSystem) | kernel CSPRNG | 256-byte cap per call; chela feeds it via `chunks_mut(256)`. Any non-zero return → `SyscallFailed`. |
| Linux | `getrandom(buf, len, 0)` (libc; glibc ≥ 2.25 / musl ≥ 1.1.20) | kernel `urandom` pool | `flags = 0`: blocks only until the pool is first seeded at boot, then never blocks. Loops on short reads; any negative return (incl. `EINTR`) → `SyscallFailed`. |
| Windows | `BCryptGenRandom(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG)` (bcrypt.dll) | system-preferred RNG | the NULL algorithm handle is valid precisely *because* of the system-preferred flag; chunks at `u32::MAX`. Any status ≠ `STATUS_SUCCESS` → `SyscallFailed`. |
| wasm32 | host import `chela.random_bytes(ptr, len) -> i32` | embedder-supplied | the standalone bundle wires this to `crypto.getRandomValues`; the WASM has no entropy source of its own. Non-zero return → `SyscallFailed`. |
| anything else | - | - | `RngError::Unsupported`; no syscall is attempted. |

All four `unsafe extern` declarations and their call sites live in this one file,
each behind a `// SAFETY:` comment justifying the raw-pointer write. Confirm the OS
is the *only* entropy source - this must come back empty:
```sh
grep -rn 'thread_rng\|rand::\|OsRng::default' chela-*/src
```

### 4a. `chela-primitives/src/crc.rs` - CRC-11/UMTS

The per-share transcription checksum (the last word of every share). Poly
`0x307` (`x¹¹+x⁹+x⁸+x²+x+1`, implicit `x¹¹`), `init 0`, non-reflected
(`refin/refout = false`), `xorout 0` - textbook GF(2) long division, auditable by
hand and reproducible by any standard CRC tool. KAT: `crc11_umts("123456789") ==
0x061` (reveng catalogue check value). An 11-bit register detects every
transcription error that flips a single word (one word = a burst of ≤ 11 bits).
SPEC.md § 1.2 / § 8.2.

### 5. `chela-field/src/gf256.rs` - constant-time GF(2^8)

Add is XOR. Multiply is 8 unconditional rounds of mask-driven shift + mask-
driven reduction mod `0x11b` (Rijndael polynomial, AES). Inverse via the
fixed-shape squaring chain `x^254` (Fermat in GF(2^8) since `|F*| = 255`).
`inv(0) == 0` is intentional so `inv` is total - callers must ensure `x = 0`
never reaches Lagrange (`chela-sss::combine` rejects it).

No tables. Tables would leak data-dependent timing via the CPU cache.

KAT: `mul(0x57, 0x83) = 0xc1` - FIPS 197 § 4.1.

### 6. `chela-sss/src/lib.rs` - Shamir split / combine

`split` samples fresh coefficients per byte position from the injected
`RandomSource`. The `rng.fill_random` call sits inside the per-byte loop, so
each byte gets independent coefficients.

`combine` rejects duplicate x-coordinates and `x = 0` (the secret's
coordinate). Lagrange interpolation at `x = 0`: compute the coefficients once,
then apply per byte.

Allocation-free - callers pass in `out_x: &mut [u8]` and
`out_shares: &mut [&mut [u8]]`. Allocation lives one level up in `chela-engine`,
which always has a real allocator. Cost: std callers have to build a
`Vec<&mut [u8]>` of slice refs.

### 7. `chela-bip39/src/lib.rs` - BIP-0039 codec

Entropy ↔ 11-bit indices with the BIP-39 checksum byte (top `checksum_bits`
bits of `SHA-256(entropy)`). Implements BIP-39 § 4 verbatim. Vectors come from
the Trezor python-mnemonic `vectors.json` (12/18/24-word) and derived 15/21-word
zero-entropy cases.

### 8. `chela-bip39/src/wordlist.rs` - vendored English wordlist

2048 words, in order, verbatim from BIP-0039. Verify against the canonical
hash `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`:

```sh
diff \
  <(curl -sL https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt) \
  <(awk -F'"' '/^    "/ {print $2}' chela-bip39/src/wordlist.rs)
```

### 9. `chela-engine/src/lib.rs` - body codec, integrity tag, generation recovery set id, per-share checksum

The orchestration layer. The only SHA-256 in this file is the one-byte body
integrity tag (point 2); the per-share checksum is CRC-11, and the per-generation
tag is a random recovery set id, not a hash. Six things matter here:

1. **What SSS splits is `body = payload ‖ tag ‖ kind_byte`.** Both the tag and the
   kind byte are *appended to the body and split with it*, so a single share's words
   reveal nothing about the payload type or the tag. No magic byte, no in-bundle
   version. For BIP-39 the payload is raw entropy followed by optional passphrase
   bytes; for text, raw UTF-8.
2. **The integrity tag is `SHA-256(payload ‖ kind_byte)[0]` (one byte).** It binds
   the whole reconstructed secret: combine the wrong shares and the recovered tag
   won't match, so recovery fails (`BundleCorrupt`) instead of returning a plausible
   wrong secret. This is the only place the secret is hashed, and it is the only guard
   that protects a *text* payload - a BIP-39 mnemonic re-derives from its entropy and
   so has no checksum of its own to fall back on.
3. **Recovery trims by the kind terminator, then checks the tag.** After combine
   reconstructs `body`, `kind = body[len-1]`, `tag = body[len-2]`, and `payload =
   body[..len-2]`. Reject (`BundleCorrupt`) unless the kind decodes, the payload length
   fits it, and `ct_eq(tag, SHA-256(payload ‖ kind_byte)[0])`. SPEC.md § 5.
4. **The generation recovery set id is an 11-bit CSPRNG value (a nonce; `sample_recovery_set_id`).** Drawn once
   per split and written identically into every share of that generation (word 1). It
   binds one *generation*, not the secret - re-splitting the same secret draws an
   independent recovery set id, so shares from two runs carry different recovery set ids and recovery
   refuses them (`MismatchedShares`). Binding the *secret* is the integrity tag's job
   (point 2), not the recovery set id's.
5. **The per-share checksum is CRC-11/UMTS (§ 4a), not a hash.** Computed over
   `[x, M] ‖ rsid_be ‖ Y_bytes` (poly `0x307`). It is the last word of the
   share and catches a single transcription error before Lagrange is invoked.
6. **Candidate-length disambiguation is resolved by CRC.** Several body lengths
   pack into the same Y-word count; `decode_share_bip39_v2` tries each candidate
   length from longest to shortest and keeps the one whose CRC-11 matches the
   stored checksum word. SPEC.md § 4.3. (Allocation also lives here, not in
   `chela-sss` - the engine builds the `Vec<&mut [u8]>` of slice refs that
   `chela-sss::split` needs.)

### 9a. `SplitState` - the extendable-split profile (rev-3)

`chela-engine` exposes an optional *extendable* split. `split_extendable` /
`split_extendable_with_rng` behave exactly like `split` but also return a
`SplitState`; `extend` issues further shares on that same polynomial at fresh
CSPRNG-drawn x-coordinates. The shares are ordinary Shamir shares - the
coefficients are drawn from the CSPRNG exactly as in § 6, merely **retained**
instead of wiped - so SPEC.md § 3.1's information-theoretic below-threshold
guarantee is unqualified. A decoder cannot tell an extended share from an
original one, and the wire format (SPEC.md § 4-5) is untouched.

What an auditor must check:

- **`SplitState` is secret-equivalent.** Its `coeffs` field stores each
  polynomial constant-term-first, and those constant terms *are* the body bytes
  (`payload ‖ tag ‖ kind`). State alone reconstructs the secret - no shares
  needed. Treat it as sensitivity-equal to the plaintext secret.
- **Chela never persists or seals it.** `SplitState` is deliberately *not*
  `Serialize`; its `Debug` is redacted; it wipes `coeffs` (and `issued_x`) on
  drop via `volatile_set`. Bytes leave only through the explicit, versioned
  `to_bytes` (a self-zeroizing `Zeroizing<Vec<u8>>`). The **embedder** MUST
  encrypt those bytes with an AEAD (binding `rsid ‖ M` as associated data) under
  a key at least as protected as the secret, before any persistence. Losing the
  sealed state loses only the ability to extend; existing-share recovery and
  full re-split are unaffected.
- **`extend` re-derives and checks the body.** It rebuilds `body` from the
  supplied secret and constant-time-compares it against the retained constant
  terms (`ct_eq`), so a wrong secret/state pairing is a clean `WrongSecret`
  error, never shares incompatible with the originals.
- **Byte-identity is one code path.** Extended shares come from
  `chela-sss::evaluate_shares`, which reuses the same Horner evaluation and the
  same `encode_share_bip39_v2` path as `split`. The SSS math is *not* duplicated:
  `split` and `split_retaining_coeffs` share one `split_inner`.
- **Issuance caps.** `x ∈ 1..=32` hard-caps lifetime issuance at 32
  (`ExtendError::Exhausted`); a soft cap of `3·M − 1` requires an explicit
  `allow_over_cap` override (`ExtendError::OverSoftCap`). Extension never
  re-randomizes - a leaked or lost-then-found card is live forever on this
  polynomial; suspected compromise means a full re-split with a new `rsid`.
- **`from_bytes` is fuzz-robust.** It parses a fixed 7-byte header and validates
  every field (version, threshold, rsid range, issued count, body length,
  distinct in-range x) with no panic on arbitrary input. SPEC.md § 8 amendment
  sketch: "Extendable splits (optional profile)."

### 10. `chela-share/` - share text format + JSON + paper-backup HTML

`parse_share` / `parse_shares` is the only parser that ingests externally-
supplied text. A fuzz harness lives in `chela-share/fuzz` (`cargo +nightly fuzz
run`), run locally and before a release rather than in CI. The `is_ascii()` guard
at the byte slice in `parse_share` is load-bearing - its absence is what the fuzz
harness originally tripped, and that crash is now pinned as a regression test (see
`chela-share/src/lib.rs`, "Fuzz crash 8c3bfb86").

`html::render_paper_html` produces a single self-contained HTML document with
embedded CSS. The user prints to PDF from the browser. A PDF library would
have pulled in dependencies; static HTML survives offline indefinitely.

The JSON share schema (`chela.share` / `chela.shares`) is documented in
`SPEC.md` § 6.2.

### 11. `chela-wasm/src/lib.rs` - browser FFI

Exposes a C-ABI an HTML/JS page calls to split secrets, recover them, and
render paper backups. Seven `unsafe` blocks (the only ones in this crate),
each with a `// SAFETY:` comment. `impl Drop` on every
secret-bearing request type; `chela_dealloc` volatile-wipes every buffer it
frees.

## Cross-cutting concerns

### Secret-bearing buffers and where they're wiped

Wipe primitive: `chela_primitives::zeroize::volatile_set` (`core::ptr::write_volatile`
per byte + `compiler_fence(SeqCst)`). Plain `fill(0)` is forbidden - the
optimiser may elide it.

| Location                                  | Wiped buffer(s)                                                                          |
|-------------------------------------------|------------------------------------------------------------------------------------------|
| `chela-sss::split`                        | RNG scratch, polynomial coefficients (`wipe_coeffs`)                                     |
| `chela-engine::split_with_rng`            | body (joined secret), per-share `sb` after consumption, BIP-39 `indices`, `entropy` Vec - pre-sized to defeat `extend_from_slice` realloc orphaning |
| `chela-engine::{encode_share_bip39_v2, decode_share_bip39_v2}` | CRC input (holds the Y bytes), wrapped in `Zeroizing`; decoded share `body` buffer  |
| `chela-engine::recover_secret`            | body (recovered secret), all share payload `Vec`s                                        |
| `chela-engine::interpret_body`            | re-encoded mnemonic `indices`                                                            |
| `chela-engine::{split_core, extend}`      | retained coefficient matrix (`Zeroizing`, pre-sized), per-share `sb`, `extend`'s body/constant-terms scratch |
| `chela-engine::SplitState` (`impl Drop`)  | `coeffs` (secret-equivalent) and `issued_x`; `to_bytes` returns a self-zeroizing buffer |
| `chela-sss::{split_retaining_coeffs, evaluate_shares}` | RNG scratch and the `row`/`coeffs` field-element scratch (`wipe_coeffs`); the retained matrix is the caller's to wipe (`SplitState` does) |
| `chela-tui::wizard`                       | input mnemonic (via `SecretString`), recovered secret on reveal-decline and post-display |
| `chela-cli`                               | argv-derived mnemonic / passphrase / text, stdin share buffer, recovered secret. argv copies in the OS process listing still leak - CLI-inherent. |
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

## Carrier parsing details

The share *words* are authoritative; the text/JSON/HTML carriers around them are
conveniences, and their parsers are deliberately small and forgiving. Four
behaviours are worth reading in the source because they are easy to get subtly
wrong:

- **The JSON string-escape set is fixed and HTML-safe.** `json_string`
  (`chela-share/src/export.rs:194`) escapes `"`, `\`, the C0 controls (`\n`, `\r`,
  `\t`, and `\u00xx` for the rest), and - critically - `<` to `<`. The `<`
  escape is what lets a share's JSON sit inside an HTML `<script>` block without a
  user-supplied `</script>` in a name or description breaking out of the tag.
- **Malformed JSON numbers are treated as absent, never as zero.** The parser
  stores every number as an `i64` (`Value::Number`); `as_u8` / `as_usize`
  (`chela-share/src/json.rs:47`) are `try_from` conversions that return `None` on
  anything out of range. Each advisory field is read as
  `v.get(..).and_then(Value::as_u8)` (`chela-share/src/import.rs:199`), so an
  out-of-range or wrong-typed number simply makes the advisory check not fire -
  it can never silently coerce to `0` and pass. The recovery set id takes the same
  fail-closed route in `parse_recovery_set_id` (`import.rs:234`): wrong length,
  non-hex, or a value above the 11-bit range is rejected, not masked.
- **HTML extraction is tolerant but bounded.** `find_chela_share_blocks`
  (`chela-share/src/import.rs:105`) finds every
  `<script type="application/json" class="chela-share">` block case-insensitively,
  tolerating attribute order and single-or-double quotes via
  `tag_attribute_contains` (`import.rs:271`). It will not match `<scripting>` (it
  checks the byte after `<script`), and it relies on the `<`-escaping above so a
  literal `</script>` inside share data cannot prematurely close a block.
- **Word acceptance is ASCII case-insensitive.** `word_to_index`
  (`chela-bip39/src/lib.rs:169`) first tries an exact binary search, then falls back
  to a length-matched, byte-wise case-folded scan, so `Abandon` and `ABANDON` map to
  the same index as `abandon`. It early-outs on any word longer than 8 bytes (no
  BIP-39 word exceeds that), bounding the scan.

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
