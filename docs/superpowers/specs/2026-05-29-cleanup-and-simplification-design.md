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

#### Why not merge `chela-wasm` and `chela-bundle` into one crate

Considered. Rejected because the build invocations are fundamentally different:

- `chela-wasm` is a `cdylib` library that targets `wasm32-unknown-unknown`.
- `chela-bundle` is a native binary that consumes the wasm bytes.

Merging them would require one `Cargo.toml` whose `build.rs` recursively
invokes cargo on its own crate for a different target. That works, but the
recursive wasm build would run on every `cargo build -p chela-wasm` (even when
the caller just wants the rlib for tests) and "build this crate" silently
triggering "also build a wasm of this crate" is surprising. The split between
"the wasm library" and "the thing that bundles the wasm library into HTML" is a
clean separation of concerns; the new layout preserves it.

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
  about hidden invariants. Every `// SAFETY:` block is preserved verbatim.
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
| `AGENTS.md` | Keep, reframe and rewrite (see § 4 below). Drop the D1..D8 numbering. Content: instructions for an AI agent that a user has pointed at the repo to verify that chela is secure and well packaged. |
| `AUDITORS.md` | **Keep, restructure** (see § 5 below). Step-by-step walkthrough of the codebase for a human auditor: zero fluff, no "load-bearing" rhetoric, walks the reader through files in the order they should be read with the rationale for each decision in line. |
| `MANUAL_RECOVERY.md` | Keep, slim (see § 2 above). |
| `RECOVERY.md` | Keep. User-facing wizard walkthrough; minor prose pass only. |
| `RELEASING.md` | Keep, slim. Single-path SHA256SUMS instructions. |
| `TODO.md` | **Delete.** Project state, not documentation. |
| `CONTRIBUTING.md` | Keep. Already short. |
| `CODE_OF_CONDUCT.md` | Keep, unchanged. |

Scope ceiling for the prose pass:

- Do not rewrite test bodies or test vectors. Only the test-module-level
  comments are in scope.
- Do not touch wizard UI text strings in `chela-tui` — that is user-facing
  copy, a separate conversation.
- Do not change identifier names, function signatures, or types as part of the
  prose pass. If a name reads as AI-generated, flag it but leave it.

### 4. `AGENTS.md` — reframe as "for AI agents evaluating the repo"

Current state: `AGENTS.md` is framed as a contributor reference (crate map,
required-before-PR commands, "hard rules", "load-bearing design decisions"
D1..D8, "adding a payload kind", "where untrusted bytes enter"). The opening
line says "Reference for contributors and AI agents working in this repo."

New purpose: `AGENTS.md` is a reference for someone who has pointed an AI
agent at this repo and wants the agent to verify that chela is **secure** and
**well packaged**. The audience is the agent, but the user is the human
deciding whether to trust the project.

Structure of the rewritten file:

1. **What you are looking at** — one paragraph stating what chela does and
   what someone running an agent over the repo should be checking.
2. **Repo orientation** — the crate map (which already exists), kept terse.
3. **What to verify for security** — concrete things an agent should be able
   to check itself:
   - No crates.io dependencies in the cryptographic core. Audit query
     provided.
   - `unsafe_code = "deny"` workspace-wide. The five opt-in files are listed;
     every `unsafe` block carries a `// SAFETY:` comment.
   - Every secret-bearing buffer is wiped via `volatile_set` rather than
     `fill(0)`. Audit query provided.
   - Crypto test vectors come from a primary source; each test cites it.
   - Pinned third-party GitHub Actions (SHA, not `@v4`).
   - Reproducible release builds (link to `RELEASING.md`).
4. **What to verify for packaging** — release signing (minisign), `SHA256SUMS`,
   pre-push hook, CI matrix, fuzz harness.
5. **What this file is not** — a contributor onboarding guide; for that,
   `CONTRIBUTING.md`. The codebase walkthrough lives in `AUDITORS.md`.

Constraints:

- No D1..D8 numbering. No "load-bearing".
- No marketing prose. State the rule, state the audit query, move on.
- Cross-references to other docs are fine, but no per-line `// see AGENTS.md
  § X` in the *source code* (that's covered by § 3).

The "Hard rules" content from the current file mostly belongs in `AUDITORS.md`
(as code-level invariants) or in `CONTRIBUTING.md` (as PR rules); the
`AGENTS.md` rewrite drops it.

### 5. `AUDITORS.md` — restructure as a step-by-step walkthrough

Current state: `AUDITORS.md` is already information-dense — sections for threat
model, provenance, test vectors, entropy, `unsafe`, load-bearing invariants
(S1..S7), release signing. The content is good; the framing is the problem.
Patterns to drop: the S1..S7 numbering used as vocabulary, "load-bearing", per-
section "trade-off" / "documented limitation" headings, the fact that S5 and S6
cross-reference each other by number.

New purpose: an auditor sits down with the repo open and reads `AUDITORS.md`
top to bottom. By the end they have read every cryptographic source file and
know why each decision was made.

Structure of the rewritten file:

1. **Threat model** — what chela defends against, what it does not. (Kept
   roughly as-is; already tight.)
2. **Read these files in this order** — a numbered reading list, e.g.:
   1. `chela-primitives/src/sha256.rs` — SHA-256 by FIPS 180-4; here is what
      to check.
   2. `chela-primitives/src/ct.rs` — constant-time equality.
   3. `chela-primitives/src/zeroize.rs` — volatile wipe primitive.
   4. `chela-primitives/src/rng.rs` — OS RNG, per-platform syscalls.
   5. `chela-field/src/gf256.rs` — constant-time GF(2^8).
   6. `chela-sss/src/lib.rs` — Shamir split / combine.
   7. `chela-bip39/src/lib.rs` — BIP-0039 codec.
   8. `chela-bip39/src/wordlist.rs` — vendored English wordlist (with the
      SHA-256 verification command).
   9. `chela-engine/src/lib.rs` — bundle codec, identifier, per-share checksum.
   10. `chela-share/` — share text and JSON formats.
   11. `chela-wasm/src/lib.rs` — FFI surface to the browser bundle.
3. **For each file in the reading list:**
   - What it does (one sentence).
   - The spec it implements, with the citation.
   - What an auditor should verify here.
   - The rationale for any decision that isn't obvious from the spec — the
     "why this is here" content, restated in plain prose rather than as a
     numbered design decision.
4. **Cross-cutting concerns** — concerns that don't belong to a single file:
   - The set of secret-bearing buffers and where they're wiped (current S3
     table, kept).
   - The five `unsafe` opt-ins (current § 4 table, kept).
   - The "no crates.io deps" property (current S7, with the audit query).
5. **Release verification** — current § 6, kept.

Constraints:

- No S1..S7 numbering as vocabulary. Section titles are descriptive.
- No "load-bearing" or "trade-offs we accept for".
- Every section either tells the auditor what to read, what to check, or what
  to run as a command. No standalone exposition.
- The current content is mostly preserved. This is a reorganisation, not a
  delete.

The "why this is here" parts that previously lived in `AGENTS.md`'s D1..D8
section (e.g. why the identifier doesn't include the kind byte, why GF(2^8)
is constant-time and not table-based, why allocation lives in `chela-engine`
not `chela-sss`) move into the relevant file walkthroughs in `AUDITORS.md`.

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

Risk on the prose pass: a sweeping rewrite can accidentally delete a comment
that documents a non-obvious invariant. Mitigation: SAFETY blocks,
zeroize-justification comments, and crypto-vector citations are explicitly
preserved per the rules in § 3. Anything outside those categories is fair game
for deletion if it restates the code.

## Out of scope (deferred follow-up)

Transparency / explainability work — addressing the underlying criticism that
the project is hard to verify as a reader — is a separate initiative tracked in
memory (`project-chela-transparency`). That work is content-additive (diagrams,
walking-tour docs, possibly in-bundle visualisations) and shouldn't be
conflated with this pass, which is a structural / prose cleanup.
