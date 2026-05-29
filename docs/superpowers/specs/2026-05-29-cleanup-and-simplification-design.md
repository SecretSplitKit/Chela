# Cleanup & simplification (chela)

Status: approved design, ready for implementation plan.
Date: 2026-05-29.

## Why

Two problems to fix in one pass:

1. **The repo reads as LLM-generated.** Public criticism of the project points at
   tone and density: marketing-style interjections in technical prose, numbered
   design-decision frameworks (D1..D8) treated as load-bearing vocabulary,
   per-line "see AGENTS.md § X" cross-references, multi-paragraph commentary on
   routine code. Style problem, not correctness problem.
2. **`chela-serve` is extra surface for negligible benefit.** A localhost-only
   HTTP server that serves two static assets, when the same assets ship as a
   standalone HTML file. Removing it shrinks the audit surface and the CI
   matrix.

This pass does NOT touch the cryptographic core, the wire format, the JSON share
schema, the TUI/CLI UX, the zeroize discipline, or the reproducible-build
profile. A follow-up "transparency / explainability" initiative is planned
separately.

## Scope

In scope:

- Remove `chela-serve/` from the workspace.
- Add `chela-bundle/` workspace crate that takes over standalone-HTML
  production.
- Rewrite comments and docstrings across the repo to drop AI-flavored prose.
- Consolidate and slim Markdown docs.
- Drop the SHA-256-by-hand section from `MANUAL_RECOVERY.md` (manual recovery
  will skip checksum verification rather than walk users through computing
  SHA-256 with paper and pencil).

Explicitly out of scope:

- Cryptographic algorithms (Shamir, GF(2^8), SHA-256 in BIP-39, OS RNG).
- Wire format. The per-share checksum stays exactly as it is; the share text
  format, JSON schemas (`chela.share.v1` / `chela.shares.v1`), and bit-packing
  do not change.
- Zeroize discipline.
- The TUI / CLI surface area (menus, prompts, output format).
- Test vectors, fuzz harness, or fuzz corpus.

## Changes

### 1. Crate layout

Drop `chela-serve/` entirely. That removes:

- `chela-serve/src/main.rs` (HTTP server, CSP, security headers, hash printing).
- `chela-serve/src/bin/chela-bundle.rs` (the standalone-HTML builder).
- `chela-serve/build.rs` (compiles `chela-wasm` and computes CSP inline-script
  hashes).
- `chela-serve/assets/chela.html` (the 1,662-line standalone HTML).
- `chela-serve/Cargo.toml`.

Add `chela-bundle/`:

```
chela-bundle/
  Cargo.toml
  build.rs              # compiles chela-wasm; writes OUT_DIR/chela.wasm
  assets/
    chela.html          # moved from chela-serve/assets/chela.html
  src/
    main.rs             # reads the HTML template, embeds the WASM, writes output
```

`chela-bundle/build.rs` is the existing `chela-serve/build.rs` minus the CSP
inline-script-hash computation (no server, no CSP). It compiles `chela-wasm` to
`wasm32-unknown-unknown` into `OUT_DIR/chela.wasm`.

`chela-bundle/src/main.rs` is structurally equivalent to the current
`chela-serve/src/bin/chela-bundle.rs`: takes an output path on argv, reads the
template, base64-encodes the embedded WASM at the marker, writes the result.

Workspace members go from 10 to 9 (`chela-serve` out, `chela-bundle` in).
`chela-wasm` is unchanged.

Affected:

- `Cargo.toml` — workspace `members` list.
- `README.md` — drop the "browser server" run section; keep the standalone
  bundle section.
- `RELEASING.md` — drop server binary from the release artifact list.
- `AGENTS.md` — drop `chela-serve` from the crate map.
- `.github/workflows/*.yml` — drop server build / test steps; replace with a
  bundle build smoke test.

### 2. Manual recovery doc: skip checksum verification

`MANUAL_RECOVERY.md` currently walks the reader through computing SHA-256 by
hand to verify the per-share checksum. Computing SHA-256 by hand is a day's
work per hash and is the dominant source of complexity in the manual procedure.

The wire format does not change. The per-share checksum is still on every share
and the chela tool still verifies it on recovery. The manual procedure simply
skips that step.

New flow in the doc:

1. Convert words to 11-bit chunks (unchanged).
2. Concatenate the bit stream (unchanged).
3. Split off the last 2 bytes as checksum and **discard them** (new — replaces
   the "now verify SHA-256" section).
4. Treat the remaining bytes as the share payload and run Lagrange combine
   (unchanged).
5. Use the 4-hex identifier on the cards to confirm the right cards belong to
   the same set; do not attempt to recompute the SHA-256 identifier by hand.

Concrete edits:

- Remove the entire "Computing SHA-256 by hand" section (~400 lines).
- Replace with a 30-line "skip the checksum" section that explains what the
  last 2 bytes are, why the tool verifies them, and why the manual procedure
  doesn't.
- Update the worked example to drop the SHA-256 step but otherwise produce the
  same recovered secret.

### 3. Prose cleanup

Concrete rules applied across the repo:

- **Module / file docstrings:** one sentence. No headers, no
  multi-paragraph essays.
- **Function comments:** delete all "see AGENTS.md § X" / "see SPEC.md § Y"
  cross-references. Keep WHY-comments only when the reason is non-obvious from
  the code.
- **Inline comments:** delete commentary that restates the code. Keep notes
  about hidden invariants. Keep every `// SAFETY:` block — those are
  load-bearing.
- **No `///` docstring essays on internal items.** A signature is usually
  enough.
- **Section divider comments** (`// ---`, `// === Section ===`) inside source
  files: delete. Use modules and blank lines instead.
- **Marketing-style prose:** delete instances of "Pay-off:", "Why split:",
  "load-bearing", "trade-offs we accept for", "Bias toward action", and
  similar.
- **Numbered design-decision framework (D1..D8 in AGENTS.md):** delete the
  numbering. The content stays where it's useful, restated as plain prose under
  topic headers rather than catalogued items.
- **Test names:** keep. They're descriptive, not flowery.

Docs consolidation:

| File | Action |
|---|---|
| `README.md` | Keep, slim. The current "Where to find the hashes" block lists three ways to find hashes (inlined in release notes, `SHA256SUMS` file, per-artifact `.sha256` files); collapse to just the `SHA256SUMS` + minisign path. Drop the "Run — browser server" section. |
| `SPEC.md` | Keep, slim. Drop justification prose; the tables and rules stay. Target ~60% of current length. |
| `AGENTS.md` | Keep, restructured. Merge `AUDITORS.md` content into a section. Drop the D1..D8 numbering. |
| `AUDITORS.md` | **Delete.** Content merged into `AGENTS.md`. |
| `MANUAL_RECOVERY.md` | Keep, slim (see § 2 above). |
| `RECOVERY.md` | Keep. User-facing wizard walkthrough; minor prose pass only. |
| `RELEASING.md` | Keep, slim. Single-path SHA256SUMS instructions. |
| `TODO.md` | **Delete.** Project state, not documentation. |
| `CONTRIBUTING.md` | Keep. Already short. |
| `CODE_OF_CONDUCT.md` | Keep, unchanged. |
| `AGENTS.md` framing | Reframe as a contributors' reference. The current opening line markets the file as a guide for "contributors and AI agents working in this repo" — drop the AI-agents framing; the file is a developer reference. Consider renaming to `CONTRIBUTING-INTERNAL.md` or folding the crate-map section into `CONTRIBUTING.md`; final naming decided during implementation. |

Scope ceiling for the prose pass:

- Do not rewrite test bodies or test vectors. Only the test-module-level
  comments are in scope.
- Do not touch wizard UI text strings in `chela-tui` — that is user-facing
  copy, a separate conversation.
- Do not change identifier names, function signatures, or types as part of the
  prose pass. If a name reads as AI-generated, flag it but leave it.

## What is explicitly preserved

- Cryptographic core: SHA-256, GF(2^8), Shamir split / combine, OS RNG, BIP-39.
- Wire format v1: share text format, bit-packing, per-share checksum, identifier
  computation, JSON schemas (`chela.share.v1`, `chela.shares.v1`).
- All test vectors and their citations.
- The fuzz harness (`chela-share/fuzz`).
- The reproducible-build release profile.
- The TUI menu / wizard flow and the CLI surface (`split`, `recover`,
  `--mnemonic`, `--passphrase`, `--text`, `--paper`, `--json`, `--json-dir`).

## Risk and verification

The cryptographic risk of this pass is essentially zero: no algorithm change,
no wire-format change, no engine logic change. The verification matrix is
unchanged except for the `chela-serve` removal:

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace`
- `cargo build --target wasm32-unknown-unknown -p chela-engine`
- New: `cargo run -p chela-bundle -- /tmp/chela.html && file /tmp/chela.html`
  (smoke test the bundle binary).
- All existing engine round-trip tests must pass unmodified (they cover the
  wire format that is not changing).

Risk on the prose pass: a sweeping rewrite can accidentally delete a
load-bearing comment. Mitigation: SAFETY blocks, zeroize-justification
comments, and crypto-vector citations are explicitly preserved per the rules
in § 3.

## Out of scope (deferred follow-up)

Transparency / explainability work — addressing the underlying criticism that
the project is hard to verify as a reader — is a separate initiative tracked in
memory (`project-chela-transparency`). That work is content-additive (diagrams,
walking-tour docs, possibly in-bundle visualisations) and shouldn't be
conflated with this pass, which is a structural / prose cleanup.
