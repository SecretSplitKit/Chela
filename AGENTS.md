# AGENTS.md

Reference for contributors and AI agents working in this repo. Build / run lives in
[README.md](./README.md); cryptographic provenance and invariants live in
[AUDITORS.md](./AUDITORS.md).

## Crate map

Cargo workspace. Library crates are `#![no_std]` + `alloc` and build for
`wasm32-unknown-unknown`. Binaries (`chela-tui`, `chela-cli`) and `chela-serve` use std.

```
chela-primitives/   SHA-256, ct_eq, volatile zeroize, OS RNG
chela-field/        Field trait + constant-time GF(2^8)
chela-sss/          Shamir split/combine over Gf256 — caller-allocated, no heap
chela-bip39/        BIP-0039 codec + vendored English wordlist
chela-share/        Share text format + print-ready HTML paper backup
chela-engine/       Bundle codec + split/recover orchestration
chela-cli/          Scriptable CLI binary
chela-tui/          Interactive wizard binary
chela-wasm/         no_std FFI for the browser bundle
chela-serve/        Localhost HTTP server + standalone-bundle builder
```

`chela-share/fuzz/` is its own little workspace — `libfuzzer-sys` is the one and only
third-party crate in the repo, and it's a test harness, never shipped.

## Required before every PR

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

After touching any library crate, sanity-check the wasm path:

```sh
cargo build --target wasm32-unknown-unknown -p chela-engine
```

## Hard rules

CI enforces most of these; reviewers enforce the rest.

- **No third-party crates in the cryptographic core.** Add a workspace crate, vendor
  with provenance comments (the BIP-39 wordlist is the pattern), or hand-roll.
- **`unsafe_code` is denied workspace-wide.** Five modules opt in with a module-level
  `#[allow(unsafe_code)]`: `chela-primitives/src/{rng,zeroize}.rs`,
  `chela-sss/src/lib.rs` (one `wipe_coeffs` cast), `chela-tui/src/term.rs::raw_termios`,
  `chela-wasm/src/lib.rs` (FFI). Every `unsafe` block needs a `// SAFETY:` comment
  enumerating the invariants. Don't add a new opt-in without raising it in review.
- **Zeroize secrets via `volatile_set`** (`chela_primitives::zeroize`). Never use
  `fill(0)` or simple assignment on a buffer holding secret bytes — the optimiser is
  allowed to elide both. New secret-bearing buffers belong in AUDITORS.md § 5 (S3).
- **No `thiserror` / `anyhow`.** Each crate has a small `*Error` enum.
- **Crypto test vectors must come from a primary source** (RFC, FIPS, BIP, NIST CAVP).
  Cite the source in the test name or a comment.
- **Pin third-party GitHub Actions to commit SHAs**, not `@v4` / `@stable` mutable refs.
  Dependabot opens PRs to refresh them.

## Load-bearing design decisions

These rest under everything else. Don't change them without updating this section.

### D1 — Bundle is body bytes only; identifier carries the metadata

What SSS splits is **just** the body: raw entropy (+ passphrase, if any) for BIP-39,
raw UTF-8 for text payloads. No magic byte, no version, no in-bundle kind tag, no
in-bundle checksum.

A 16-bit `identifier = SHA-256(body || kind_byte)[..2]` is printed on every card.
`kind_byte` is a 1-byte internal tag (payload type × entropy length × passphrase-present)
mixed into the hash but never written into the body. At recover, the engine enumerates
the ≤11 candidate `kind_byte`s whose length pattern fits the observed body, recomputes
the identifier, and picks the match. False-positive rate ≈ 11/65k; a false match
almost always fails downstream as invalid BIP-39 or invalid UTF-8.

Pay-off: a 24-word seed used to carry 10 bytes of framing and now carries zero — share
length dropped from 34 words to 25.

### D2 — Per-share checksum binds (body, identifier, x)

Each share carries `SHA-256(body || identifier || x)[..2]` as a 2-byte tail. Without
this, a single transcription error propagates through Lagrange into a fully-recovered-
but-wrong bundle whose identifier check fails with no hint which card was wrong.
Binding to `identifier` + `x` also catches a card swapped between two splits or
between positions of the same split.

### D3 — Constant-time GF(2^8), no tables

`Gf256::mul_ct` is 8 unconditional rounds of mask-driven add + mask-driven reduction
mod `0x11b`. `Gf256::inv_ct` is `x^254` via a fixed-shape squaring chain. Tables would
leak data-dependent timing via the CPU cache. `inv(0) == 0` is intentional so `inv` is
total — callers must ensure no `x = 0` reaches Lagrange (`combine` rejects it).

### D4 — `chela-sss` is allocation-free; callers pre-allocate

`split` takes `out_x: &mut [u8]` and `out_shares: &mut [&mut [u8]]`; `combine` takes
`out: &mut [u8]`. Allocation lives in `chela-engine`, which always has a real
allocator. Cost: std callers have to build a `Vec<&mut [u8]>` of slice refs.

### D5 — Word-count ambiguity in share decoding

Several byte counts pack into the same number of 11-bit groups (e.g. 27 words ↔ 36 or
37 bytes). `recover_secret` enumerates the candidate byte counts and picks the one
whose per-share checksum verifies for every share. Free in code; gated by D2.

### D6 — Hybrid TUI: raw-mode menu, line-based wizards

Main menu runs in the xterm alternate-screen buffer with stdin in raw mode
(ECHO / ICANON / ISIG off), navigable with arrows + Enter or a digit shortcut. Once an
item is chosen the screen guard drops and a line-based wizard takes over.
`read_secret` momentarily flips into raw + no-echo to mask password input.

Why split: wizards have to ingest 12–24-word mnemonics that are typically pasted, and
bracketed-paste in raw mode is fiddly. If termios isn't available (stdin not a tty)
the menu falls back to line input so `printf '...' | chela` still works for scripting.

The recovery reveal phase enters its own alt-screen so the displayed secret leaves no
trace in the user's scrollback when they exit.

### D7 — Print-ready HTML paper backup

`chela-share::html::render_paper_html` produces a single self-contained HTML document
with embedded CSS; the user prints to PDF from the browser. A PDF library would fight
D1's no-deps rule. Static HTML survives offline indefinitely.

### D8 — Share text format

```
CHELA-<ID>-<x>-<M>-<N>-<W>
word1 word2 ... wordW
```

`ID` = 4-hex-char identifier, `x` = 1-based share number, `M`/`N` = threshold/total,
`W` = word count on line 2 (redundant but printed for hand-typing — the parser rejects
shares where header `W` and actual count disagree). Multiple shares are
blank-line-separated, so `cat share1 share2 share3 | chela-cli recover` works.

## Adding a payload kind

`kind_byte` values 0x01–0x0B are defined in `chela-engine::kind`. To add another:

1. Pick the next byte value. Add it to `kind::*` and `kind::ALL_VALUES`.
2. Extend `decode_kind_byte` to map it to a `DecodedKind`.
3. Add `SplitInput::<NewKind>` + `RecoveredSecret::<NewKind>` variants and the matching
   arms in `build_bundle` / `interpret_body`.
4. Add a round-trip test in `chela-engine::tests`.

The share text format does not need to change — kind is recovered via D1.

## Where untrusted bytes enter

Only one parser ingests externally-supplied text: `chela_share::parse_share` /
`parse_shares`. It's fuzzed via `chela-share/fuzz`; a smoke run executes on every PR.
`chela-tui::wizard::ParsedHeader::from_str` is a partial-header parser used to prompt
for words one at a time — keep it in sync with `parse_share` (the `is_ascii()` guard
at the byte slice is load-bearing; the lack of it was the fuzz crash that prompted the
guard in the shared parser).

`chela-serve` accepts no user input over HTTP — it only serves `/` (HTML) and
`/chela.wasm`, both static.
