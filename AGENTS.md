# AGENTS.md - orienting an AI agent in the chela repository

You have been pointed at the chela repository. chela splits a secret - a BIP-39
wallet seed, a password, or any short message up to 255 bytes - into N shares
using Shamir's Secret Sharing; any M of them recover the original, and fewer than
M reveal nothing. The cryptographic core is written in-tree, with no third-party
crates beyond the OS RNG.

This file is a map of the codebase. For the two things an agent most often needs,
go straight to the authoritative documents:

- **The wire format** - how a share is encoded byte by byte, with worked test
  vectors: [`SPEC.md`](SPEC.md). It is precise enough to write a compatible
  implementation in another language.
- **The audit** - the threat model, a file-by-file reading order, and the
  cross-cutting checks (where every secret buffer is wiped, the five `unsafe`
  opt-ins, no crates.io dependencies in the core) plus release verification
  (minisign signatures, reproducible builds): [`AUDITORS.md`](AUDITORS.md). Each
  check lists the exact command and the expected result, so an agent can run it
  directly.

## The workspace

chela is one Cargo workspace of ten crates. The lower half is the cryptographic
core; the upper half is user-facing. Each layer depends only on the layers below
it - nothing in the upper half is imported by the lower half.

```
chela-field      --> chela-sss ---\
chela-primitives --> chela-sss     >--> chela-engine --> chela-share --> chela-tui
chela-primitives --> chela-bip39 --/                                 \-> chela-cli
                                                                      \-> chela-wasm --> chela-bundle
```

### The cryptographic core

- **`chela-primitives/`** - the foundation. SHA-256 (hand-written, used only for
  the BIP-39 checksum), CRC-11, constant-time byte equality (`ct_eq`), a
  `volatile_set` primitive that zeroes secret buffers without the optimizer
  eliding the write, and a thin wrapper over the OS RNG. Every security-sensitive
  operation bottoms out here.
- **`chela-field/`** - constant-time arithmetic over GF(2^8). Addition is XOR;
  multiplication is a branch-free shift-and-XOR loop reduced modulo the Rijndael
  polynomial `0x11b` with bit masks, not branches. No lookup tables - a table
  indexed by secret bytes would leak through the CPU cache - so share values
  cannot be recovered through a timing side-channel. No dependencies.
- **`chela-sss/`** - Shamir's Secret Sharing. `split` samples a random degree
  `M-1` polynomial over GF(2^8) and evaluates it at N distinct x-coordinates;
  `combine` runs Lagrange interpolation at `x = 0`. Each byte of the secret is an
  independent single-byte polynomial.
- **`chela-bip39/`** - the BIP-0039 codec and the 2048-word English wordlist,
  compiled in at build time. Converts between entropy bytes and the mnemonic, and
  encodes share bytes as words for transcription.
- **`chela-engine/`** - orchestration. Draws the per-split nonce and N random
  distinct x-coordinates, appends the kind byte and integrity tag to the body,
  Shamir-splits the whole thing, and encodes each share into the wire format
  ([`SPEC.md`](SPEC.md)): word 0 packs `[x, M]`, word 1 is the nonce, the middle
  words are the Shamir output, the last word is an 11-bit CRC. Recovery is the
  inverse, with the integrity tag rejecting a wrong set of shares.

### The user-facing half

- **`chela-share/`** - presentation. Renders shares as plain text, JSON, and a
  print-ready paper-backup HTML page. Its parser is the one place chela reads
  externally supplied text, so the fuzz harness (`chela-share/fuzz/` - the only
  crates.io-dependent crate, a test-only harness outside the main workspace)
  lives here.
- **`chela-tui/`** - the interactive terminal wizard binary (`chela`).
- **`chela-cli/`** - the scriptable command-line binary (`chela-cli`).
- **`chela-wasm/`** - a hand-rolled C-ABI FFI wrapper for the browser, with no
  `wasm-bindgen` and no third-party crates.
- **`chela-bundle/`** - a build tool that inlines the compiled WASM, the
  JavaScript glue, and the UI into the single self-contained `chela.html`.

## Next

To audit, follow [`AUDITORS.md`](AUDITORS.md). To reimplement the format, read
[`SPEC.md`](SPEC.md). The same crate tour, with diagrams, is on the explainer site
under "Tour of the codebase."
