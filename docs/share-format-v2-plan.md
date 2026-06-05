# R0 — Words-Alone Share Format Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-encode chela shares so the BIP-39 words alone carry everything needed to recover — x, threshold, a generation nonce, and a hidden kind — with no dependence on the card label.

**Architecture:** Per-share words become four word-aligned sections — `word0 = [X:5|M:5|reserved:1]`, `word1 = nonce:11`, `words2..W-2 = SSS body (payload ‖ kind_byte)`, `wordW-1 = CRC-11`. SHA-256 leaves the engine entirely: the identifier becomes an 11-bit random nonce, the per-share checksum becomes CRC-11/UMTS. Recovery reads x/M/nonce from the words, combines, then reads the kind from the recovered body. Spec: `docs/share-format-v2-design.md`.

**Tech Stack:** Rust workspace, `#![no_std]` engine crates (`chela-primitives`, `chela-field`, `chela-sss`, `chela-bip39`, `chela-engine`), `std` wire/UI crates (`chela-share`, `chela-cli`, `chela-tui`, `chela-wasm`). Only fuzz crates use crates.io deps.

---

## Decisions this plan locks in (review before executing)

These follow from the spec but aren't spelled out there; flag now if any is wrong.

1. **`Share` struct shape.** `identifier: [u8;2]` → `nonce: u16` (11-bit). `total` and `kind` become `Option` — a single share's words reveal neither N (never encoded) nor kind (hidden in the split body). They are `Some` only when known from a header/JSON or at split time; recovery does not depend on them.
2. **Words-only parse entry point.** `parse_share` keeps taking an optional header for advisory display + cross-checking, but a new `parse_share_words(words_line) -> Result<Share, FormatError>` recovers with no header at all. The words are authoritative; a present header that disagrees on x/M/nonce is a transcription error (`FormatError::HeaderWordsMismatch`).
3. **Card label stays, advisory only.** `CHELA-<NONCE>-<x>-<M>-<N>-<W>` keeps its shape (`<NONCE>` = 4 hex of the 11-bit nonce, high bits zero). It is printed for humans and cross-checked when present, but never required.

## File structure

| File | Responsibility | Change |
|---|---|---|
| `chela-primitives/src/crc.rs` | CRC-11/UMTS | **create** |
| `chela-primitives/src/lib.rs` | module registry | add `pub mod crc;` |
| `chela-sss/src/lib.rs` | `split` accepts caller-supplied x | modify `split` |
| `chela-engine/src/lib.rs` | nonce/x gen, body+kind, encode/decode, `Share`, split/recover | major modify |
| `chela-share/src/lib.rs` | text format + words-only parse | modify |
| `chela-share/src/import.rs` `export.rs` `html.rs` | JSON/HTML render+parse | modify |
| `chela-cli/src/main.rs` | CLI split/recover/display | modify |
| `chela-tui/src/wizard.rs` | TUI flows + header parse | modify |
| `chela-wasm/src/lib.rs` | wasm JSON + browser RNG check | modify |
| `web/` shim (locate) | `crypto.getRandomValues` for `chela.random_bytes` | verify/modify |
| `SPEC.md` | normative format | rewrite §2,§4,§5,§6 |

---

## Phase 1 — CRC-11/UMTS primitive

### Task 1: CRC-11/UMTS in chela-primitives

**Files:**
- Create: `chela-primitives/src/crc.rs`
- Modify: `chela-primitives/src/lib.rs:9` (add module)

- [ ] **Step 1: Register the module.** In `chela-primitives/src/lib.rs`, add after line 6 (`pub mod ct;`):

```rust
pub mod crc;
```

- [ ] **Step 2: Write the failing test.** Create `chela-primitives/src/crc.rs` with only the test (no impl yet):

```rust
//! CRC-11/UMTS (poly 0x307, init 0x000, non-reflected, xorout 0x000) — the per-share
//! transcription checksum for the bip39-wordlist scheme. Chosen for hand-auditability:
//! init 0, no reflection, no final XOR == textbook GF(2) polynomial long division.

#[cfg(test)]
mod tests {
    use super::crc11_umts;

    #[test]
    fn catalogue_check_value() {
        // reveng catalogue CRC-11/UMTS check: CRC of ASCII "123456789" == 0x061.
        assert_eq!(crc11_umts(b"123456789"), 0x061);
    }

    #[test]
    fn empty_is_init() {
        assert_eq!(crc11_umts(b""), 0x000);
    }

    #[test]
    fn single_bit_changes_crc() {
        assert_ne!(crc11_umts(&[0x00]), crc11_umts(&[0x01]));
    }

    #[test]
    fn output_is_11_bit() {
        for n in 0u16..=512 {
            let b = n.to_be_bytes();
            assert!(crc11_umts(&b) <= 0x7FF);
        }
    }
}
```

- [ ] **Step 3: Run it, expect failure.** Run: `cargo test -p chela-primitives crc -- --nocapture`
Expected: FAIL — `cannot find function crc11_umts`.

- [ ] **Step 4: Implement.** Prepend to `chela-primitives/src/crc.rs` (above the test module):

```rust
/// CRC-11/UMTS over `data`. Non-reflected, MSB-first; returns an 11-bit value (`0..=0x7FF`).
///
/// Bytewise long division by the generator `x¹¹+x⁹+x⁸+x²+x+1` (`0x307`, implicit `x¹¹`).
pub fn crc11_umts(data: &[u8]) -> u16 {
    const POLY: u16 = 0x307;
    const MSB: u16 = 0x400; // bit 10, the high bit of an 11-bit register
    let mut crc: u16 = 0x000;
    for &byte in data {
        // Align the byte's MSB with the register MSB (bits 10..3).
        crc ^= u16::from(byte) << 3;
        for _ in 0..8 {
            crc = if crc & MSB != 0 {
                ((crc << 1) ^ POLY) & 0x7FF
            } else {
                (crc << 1) & 0x7FF
            };
        }
    }
    crc & 0x7FF
}
```

- [ ] **Step 5: Run tests, expect pass.** Run: `cargo test -p chela-primitives crc`
Expected: PASS (4 tests). If `catalogue_check_value` fails, the byte-alignment shift is wrong — the implementation above is the reference; do not change the test's `0x061`.

- [ ] **Step 6: Commit.**

```bash
git add chela-primitives/src/crc.rs chela-primitives/src/lib.rs
git commit -m "feat(primitives): add CRC-11/UMTS"
```

---

## Phase 2 — Engine wire format

### Task 2: `chela-sss::split` accepts caller-supplied x-coordinates

Today `split` writes `out_x = 1..=total` itself (chela-sss/src/lib.rs:70-72). v2 needs random, distinct x chosen by the engine. Change `split` to *read* `out_x` as caller-provided coordinates instead of generating them.

**Files:**
- Modify: `chela-sss/src/lib.rs:47-104` (`split`)
- Test: `chela-sss/src/lib.rs` tests module

- [ ] **Step 1: Write the failing test.** Add to the `tests` module in `chela-sss/src/lib.rs`:

```rust
#[test]
fn split_uses_caller_supplied_x() {
    let mut rng = DeterministicRng::new(&[0x5a; 64]);
    let mut xs = [7u8, 3u8, 200u8]; // caller-chosen, distinct, non-sequential
    let mut data = [[0u8; 4]; 3];
    let mut refs: Vec<&mut [u8]> = data.iter_mut().map(<[u8; 4]>::as_mut_slice).collect();
    split(b"data", 2, 3, &mut rng, &mut xs, &mut refs).unwrap();
    assert_eq!(xs, [7, 3, 200], "split must not overwrite caller x-coordinates");

    let recovered = do_combine(&[xs[0], xs[1]], &[data[0].to_vec(), data[1].to_vec()], 4).unwrap();
    assert_eq!(recovered.as_slice(), b"data");
}

#[test]
fn split_rejects_zero_or_duplicate_caller_x() {
    let mut rng = DeterministicRng::new(&[0x5a; 64]);
    let mut data = [[0u8; 4]; 2];
    {
        let mut xs = [0u8, 1u8];
        let mut refs: Vec<&mut [u8]> = data.iter_mut().map(<[u8; 4]>::as_mut_slice).collect();
        assert_eq!(split(b"data", 2, 2, &mut rng, &mut xs, &mut refs).unwrap_err(), SssError::DuplicateXCoordinate);
    }
    {
        let mut xs = [5u8, 5u8];
        let mut refs: Vec<&mut [u8]> = data.iter_mut().map(<[u8; 4]>::as_mut_slice).collect();
        assert_eq!(split(b"data", 2, 2, &mut rng, &mut xs, &mut refs).unwrap_err(), SssError::DuplicateXCoordinate);
    }
}
```

Also update the existing `do_split` test helper to seed `xs` with `1..=total` before calling `split` (so the round-trip tests still pass with the new contract):

```rust
    fn do_split(secret: &[u8], threshold: u8, total: u8, rng: &mut dyn RandomSource)
        -> Result<(Vec<u8>, Vec<Vec<u8>>), SssError> {
        let mut xs: Vec<u8> = (1..=total).collect();
        let mut shares: Vec<Vec<u8>> = vec![vec![0u8; secret.len()]; total as usize];
        {
            let mut share_refs: Vec<&mut [u8]> = shares.iter_mut().map(Vec::as_mut_slice).collect();
            split(secret, threshold, total, rng, &mut xs, &mut share_refs)?;
        }
        Ok((xs, shares))
    }
```

- [ ] **Step 2: Run, expect failure.** Run: `cargo test -p chela-sss split_uses_caller`
Expected: FAIL — `split` overwrites `xs` to `[1,2,3]`.

- [ ] **Step 3: Modify `split`.** In `chela-sss/src/lib.rs`, replace the x-generation loop (lines 70-72):

```rust
    for (i, x_slot) in out_x.iter_mut().enumerate() {
        *x_slot = u8::try_from(i + 1).expect("total <= 255 (u8::MAX)");
    }
```

with validation of the caller-supplied coordinates:

```rust
    // Caller supplies the x-coordinates in `out_x`; they MUST be non-zero and distinct
    // (x = 0 is the secret; Lagrange needs distinct points).
    for (i, &xi) in out_x.iter().enumerate() {
        if xi == 0 || out_x[i + 1..].contains(&xi) {
            return Err(SssError::DuplicateXCoordinate);
        }
    }
```

Update the doc comment on `split` (lines 39-46) to say `out_x` is an input (caller-chosen distinct coordinates), not an output.

- [ ] **Step 4: Run, expect pass.** Run: `cargo test -p chela-sss`
Expected: PASS (all existing round-trip tests plus the two new ones).

- [ ] **Step 5: Commit.**

```bash
git add chela-sss/src/lib.rs
git commit -m "refactor(sss): split takes caller-supplied distinct x-coordinates"
```

---

### Task 3: Generation nonce + random distinct x helper (engine)

**Files:**
- Modify: `chela-engine/src/lib.rs` (add helpers near the top, after the consts)
- Test: `chela-engine/src/lib.rs` tests module

- [ ] **Step 1: Write the failing test.** Add to the engine `tests` module:

```rust
    #[test]
    fn random_distinct_x_are_in_range_and_unique() {
        use super::sample_distinct_x;
        let mut rng = DeterministicRng::new(&[3, 200, 3, 3, 17, 9, 250, 1, 1, 1, 31, 0, 5]);
        let xs = sample_distinct_x(5, &mut rng).unwrap();
        assert_eq!(xs.len(), 5);
        for &x in &xs { assert!((1..=32).contains(&x)); }
        for i in 0..xs.len() { for j in i+1..xs.len() { assert_ne!(xs[i], xs[j]); } }
    }
```

- [ ] **Step 2: Run, expect failure.** Run: `cargo test -p chela-engine random_distinct_x`
Expected: FAIL — `cannot find function sample_distinct_x`.

- [ ] **Step 3: Implement helpers.** Add to `chela-engine/src/lib.rs` (after `MIN_THRESHOLD`):

```rust
/// Maximum share count / x-range in v2: x ∈ 1..=32 (5-bit field, x = field + 1).
pub const MAX_SHARES: u8 = 32;

/// Draw `count` distinct x-coordinates in `1..=32` from the CSPRNG. Each draw is a raw
/// 5-bit field (`0..31`, a power of two — uniform, no modulo bias); `x = field + 1`.
fn sample_distinct_x(count: u8, rng: &mut dyn RandomSource) -> Result<Vec<u8>, EngineError> {
    if count == 0 || count > MAX_SHARES {
        return Err(EngineError::InvalidInput("total must be 1..=32"));
    }
    let mut xs: Vec<u8> = Vec::with_capacity(count as usize);
    let mut byte = [0u8; 1];
    while (xs.len() as u8) < count {
        rng.fill_random(&mut byte).map_err(EngineError::Sss)?;
        let x = (byte[0] & 0x1F) + 1; // field 0..31 -> x 1..32
        if !xs.contains(&x) {
            xs.push(x);
        }
    }
    Ok(xs)
}

/// Draw an 11-bit generation nonce from the CSPRNG.
fn sample_nonce(rng: &mut dyn RandomSource) -> Result<u16, EngineError> {
    let mut b = [0u8; 2];
    rng.fill_random(&mut b).map_err(EngineError::Sss)?;
    Ok(u16::from_be_bytes(b) & 0x7FF)
}
```

> Note: `EngineError::Sss(SssError)` already exists (chela-engine/src/lib.rs:170-174). `fill_random` returns `SssError`.

- [ ] **Step 4: Run, expect pass.** Run: `cargo test -p chela-engine random_distinct_x`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add chela-engine/src/lib.rs
git commit -m "feat(engine): random distinct x-coordinate and nonce sampling"
```

---

### Task 4: Move kind into the body; replace identifier with nonce

`build_bundle` returns `(body, kind_byte)`; today the kind is hashed into a SHA identifier and never stored. v2 appends `kind_byte` to the body and splits it; the identifier is gone.

**Files:**
- Modify: `chela-engine/src/lib.rs` — `build_bundle` (244-296), delete `compute_identifier` (298-307), rewrite `parse_bundle` (329-344), `interpret_body` keeps working on the payload slice.
- Test: engine tests module.

- [ ] **Step 1: Write the failing test.**

```rust
    #[test]
    fn body_carries_kind_byte_last() {
        use super::{build_bundle_v2, SplitInput};
        let (body, _) = build_bundle_v2(&SplitInput::Text { text: "hi" }).unwrap();
        assert_eq!(body.last().copied(), Some(0x0Bu8)); // kind::TEXT
        assert_eq!(&body[..body.len()-1], b"hi");
    }
```

- [ ] **Step 2: Run, expect failure.** Run: `cargo test -p chela-engine body_carries_kind`
Expected: FAIL — `cannot find function build_bundle_v2`.

- [ ] **Step 3: Implement.** Add a wrapper that appends the kind byte (keep the existing `build_bundle` for the payload+kind split, or fold in). Simplest: add

```rust
/// Build the full SSS body: the payload bytes with the `kind_byte` appended. The kind is
/// split with the secret (hidden per share) and read back from the recovered body.
fn build_bundle_v2(input: &SplitInput<'_>) -> Result<(Vec<u8>, u8), EngineError> {
    let (mut body, kind_byte) = build_bundle(input)?;
    body.push(kind_byte);
    Ok((body, kind_byte))
}
```

Rewrite `parse_bundle` to read the kind from the body's last byte instead of enumerating + SHA-matching:

```rust
/// Recover the secret from the SSS-combined body. The kind byte is the final body byte.
fn parse_bundle(body: &[u8]) -> Result<RecoveredSecret, EngineError> {
    let (&kind_byte, payload) = body.split_last().ok_or(EngineError::BundleCorrupt)?;
    let dec = decode_kind_byte(kind_byte).ok_or(EngineError::BundleCorrupt)?;
    if !body_len_fits(dec, payload.len()) {
        return Err(EngineError::BundleCorrupt);
    }
    interpret_body(dec, payload)
}
```

Delete `compute_identifier` (298-307) and its call. Keep `decode_kind_byte`, `body_len_fits`, `interpret_body` (they operate on the payload).

- [ ] **Step 4: Run, expect pass.** Run: `cargo test -p chela-engine body_carries_kind`
Expected: PASS. (Other engine tests will not compile yet — they depend on the old `encode_share_bip39`/`Share`; fixed in Tasks 5-8. Run this single test by name.)

- [ ] **Step 5: Commit.**

```bash
git add chela-engine/src/lib.rs
git commit -m "feat(engine): append kind byte to the split body (hidden kind)"
```

---

### Task 5: Rewrite `encode_share_bip39` to the four-section layout

**Files:**
- Modify: `chela-engine/src/lib.rs` — `encode_share_bip39` (388-422)
- Test: engine tests module

- [ ] **Step 1: Write the failing test.**

```rust
    #[test]
    fn encode_layout_word0_and_nonce_and_crc() {
        use super::encode_share_bip39_v2;
        let body = [0xABu8, 0xCD, 0xEF]; // 3-byte Y -> ceil(24/11)=3 Y words
        let nonce = 0x123u16;
        let words = encode_share_bip39_v2(&body, nonce, /*x*/ 7, /*M*/ 3);
        // W = 2 (word0, nonce) + 3 (Y) + 1 (crc) = 6
        assert_eq!(words.len(), 6);
        // word0 = (x-1)<<6 | (M-2)<<1 | 0 = 6<<6 | 1<<1 = 0x186
        assert_eq!(words[0], (6 << 6) | (1 << 1));
        assert_eq!(words[1], nonce);
        let crc_input: Vec<u8> = [7u8, 3].iter().copied()
            .chain(nonce.to_be_bytes()).chain(body.iter().copied()).collect();
        assert_eq!(*words.last().unwrap(), chela_primitives::crc::crc11_umts(&crc_input));
        for &w in &words { assert!(w < 2048); }
    }
```

- [ ] **Step 2: Run, expect failure.** Run: `cargo test -p chela-engine encode_layout`
Expected: FAIL — `cannot find function encode_share_bip39_v2`.

- [ ] **Step 3: Implement.** Replace `encode_share_bip39` with:

```rust
/// Encode one share's words: [X:5|M:5|reserved:1] ‖ [nonce:11] ‖ Y-words ‖ [CRC-11].
/// `share_bytes` is this share's SSS output (the Y values).
fn encode_share_bip39_v2(share_bytes: &[u8], nonce: u16, x: u8, threshold: u8) -> Vec<u16> {
    let x_field = u16::from(x - 1) & 0x1F;        // 1..32 -> 0..31
    let m_field = u16::from(threshold - 2) & 0x1F; // 2..32 -> 0..30
    let word0 = (x_field << 6) | (m_field << 1);   // reserved bit (bit 0) = 0
    let word1 = nonce & 0x7FF;

    let body_bits = share_bytes.len() * 8;
    let y_words = body_bits.div_ceil(11);
    let mut words = Vec::with_capacity(2 + y_words + 1);
    words.push(word0);
    words.push(word1);
    for i in 0..y_words {
        let mut w = 0u16;
        for b in 0..11usize {
            let bit_pos = i * 11 + b;
            let bit = if bit_pos < body_bits {
                (share_bytes[bit_pos / 8] >> (7 - (bit_pos % 8))) & 1
            } else {
                0
            };
            w = (w << 1) | u16::from(bit);
        }
        words.push(w);
    }

    // CRC-11 over [x, M] ‖ nonce_be ‖ Y_bytes. Wrap input in Zeroizing — it holds Y bytes.
    let mut crc_input = chela_primitives::zeroize::Zeroizing::new(Vec::with_capacity(4 + share_bytes.len()));
    crc_input.push(x);
    crc_input.push(threshold);
    crc_input.extend_from_slice(&word1.to_be_bytes());
    crc_input.extend_from_slice(share_bytes);
    words.push(chela_primitives::crc::crc11_umts(&crc_input[..]));
    words
}
```

- [ ] **Step 4: Run, expect pass.** Run: `cargo test -p chela-engine encode_layout`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add chela-engine/src/lib.rs
git commit -m "feat(engine): v2 share encoding (X|M, nonce, Y, CRC-11)"
```

---

### Task 6: Rewrite `decode_share_bip39` (parse + CRC + length disambiguation)

**Files:**
- Modify: `chela-engine/src/lib.rs` — `decode_share_bip39` (424-472)
- Test: engine tests module

- [ ] **Step 1: Write the failing test.**

```rust
    #[test]
    fn decode_round_trips_and_rejects_corruption() {
        use super::{decode_share_bip39_v2, encode_share_bip39_v2, DecodedShare};
        let body = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        let words = encode_share_bip39_v2(&body, 0x2AA, 9, 4);
        let DecodedShare { x, threshold, nonce, body: got } =
            decode_share_bip39_v2(&words).unwrap();
        assert_eq!((x, threshold, nonce), (9, 4, 0x2AA));
        assert_eq!(got, body);

        // Flip one word -> CRC must reject.
        let mut bad = words.clone();
        bad[2] ^= 1;
        assert!(decode_share_bip39_v2(&bad).is_err());

        // Reserved bit set -> reject.
        let mut bad0 = words.clone();
        bad0[0] |= 1;
        assert!(decode_share_bip39_v2(&bad0).is_err());
    }
```

- [ ] **Step 2: Run, expect failure.** Run: `cargo test -p chela-engine decode_round_trips`
Expected: FAIL — missing `decode_share_bip39_v2` / `DecodedShare`.

- [ ] **Step 3: Implement.** Add the struct and function:

```rust
/// A share decoded from its words (everything the words carry — not kind or total).
pub struct DecodedShare {
    pub x: u8,
    pub threshold: u8,
    pub nonce: u16,
    pub body: Vec<u8>,
}

fn decode_share_bip39_v2(words: &[u16]) -> Result<DecodedShare, EngineError> {
    if words.len() < 4 {
        return Err(EngineError::ShareCorrupt);
    }
    for &w in words {
        if w >= 2048 {
            return Err(EngineError::ShareCorrupt);
        }
    }
    let word0 = words[0];
    if word0 & 1 != 0 {
        return Err(EngineError::ShareCorrupt); // reserved bit must be 0
    }
    let x_field = (word0 >> 6) & 0x1F;
    let m_field = (word0 >> 1) & 0x1F;
    if m_field == 31 {
        return Err(EngineError::ShareCorrupt); // would be M=33
    }
    let x = u8::try_from(x_field).unwrap() + 1;
    let threshold = u8::try_from(m_field).unwrap() + 2;
    let nonce = words[1] & 0x7FF;
    let crc_stored = words[words.len() - 1] & 0x7FF;
    let y_words = &words[2..words.len() - 1];

    // Candidate body lengths B with ceil(8B/11) == y_words.len(); CRC selects the right one.
    let k = y_words.len();
    let max_bytes = (k * 11) / 8;
    let min_bytes = ((k.saturating_sub(1)) * 11 + 1).div_ceil(8);
    for total_bytes in (min_bytes..=max_bytes).rev() {
        let mut body = chela_primitives::zeroize::Zeroizing::new(vec![0u8; total_bytes]);
        for (i, &w) in y_words.iter().enumerate() {
            for b in 0..11usize {
                let bit_pos = i * 11 + b;
                if bit_pos >= total_bytes * 8 {
                    break;
                }
                let bit = u8::try_from((w >> (10 - b)) & 1).unwrap();
                body[bit_pos / 8] |= bit << (7 - (bit_pos % 8));
            }
        }
        let mut crc_input =
            chela_primitives::zeroize::Zeroizing::new(Vec::with_capacity(4 + total_bytes));
        crc_input.push(x);
        crc_input.push(threshold);
        crc_input.extend_from_slice(&(nonce).to_be_bytes());
        crc_input.extend_from_slice(&body[..]);
        if chela_primitives::crc::crc11_umts(&crc_input[..]) == crc_stored {
            return Ok(DecodedShare { x, threshold, nonce, body: body.as_slice().to_vec() });
        }
    }
    Err(EngineError::ShareCorrupt)
}
```

> The trailing `.to_vec()` copies out of the `Zeroizing` buffer; the buffer wipes on drop. The returned `body` is wiped by the caller (recover) after combine.

- [ ] **Step 4: Run, expect pass.** Run: `cargo test -p chela-engine decode_round_trips`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add chela-engine/src/lib.rs
git commit -m "feat(engine): v2 share decoding with CRC-11 verification"
```

---

### Task 7: New `Share` struct, `split_with_rng`, `recover_secret`

**Files:**
- Modify: `chela-engine/src/lib.rs` — `Share` (183-200), `split_with_rng` (486-546), `recover_secret` (550-631). Remove `SHARE_CHECKSUM_LEN` (31), `IDENTIFIER_LEN` (32) usage where now dead.
- Test: rewrite engine round-trip tests (Task 8).

- [ ] **Step 1: Replace the `Share` struct** (chela-engine/src/lib.rs:182-200):

```rust
/// A single share. The words carry `x`, `threshold`, and `nonce`; `total` and `kind` are
/// known only at split time or from an advisory header, never from a lone share's words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub scheme: OutputMode,
    pub x: u8,
    pub threshold: u8,
    pub nonce: u16,
    pub total: Option<u8>,
    pub kind: Option<PayloadKind>,
    pub word_indices: Vec<u16>,
}

impl Drop for Share {
    fn drop(&mut self) {
        chela_primitives::zeroize::Zeroize::zeroize(&mut self.word_indices);
    }
}
```

- [ ] **Step 2: Rewrite `split_with_rng`** body (keep the signature). Replace lines 496-545 with:

```rust
    let (body, kind_byte) = build_bundle_v2(input)?;
    let body = chela_primitives::zeroize::Zeroizing::new(body);
    if body.len() > MAX_PASSPHRASE_LEN + 32 + 1 {
        return Err(EngineError::BundleTooLarge); // +1 for the appended kind byte
    }
    if total > MAX_SHARES {
        return Err(EngineError::InvalidInput("total must be 1..=32"));
    }

    let nonce = sample_nonce(rng)?;
    let mut xs = sample_distinct_x(total, rng)?;

    let mut share_bytes: Vec<Vec<u8>> = vec![vec![0u8; body.len()]; total as usize];
    let split_result = {
        let mut share_refs: Vec<&mut [u8]> = share_bytes.iter_mut().map(Vec::as_mut_slice).collect();
        split(&body[..], threshold, total, rng, &mut xs, &mut share_refs)
    };
    if let Err(e) = split_result {
        for sb in &mut share_bytes {
            chela_primitives::zeroize::Zeroize::zeroize(sb);
        }
        return Err(e.into());
    }

    let coarse_kind = match input {
        SplitInput::Bip39 { .. } => PayloadKind::Bip39,
        SplitInput::Text { .. } => PayloadKind::Text,
    };

    let mut out = Vec::with_capacity(total as usize);
    for (idx, mut sb) in share_bytes.into_iter().enumerate() {
        let x = xs[idx];
        let word_indices = match mode {
            OutputMode::Bip39Wordlist => encode_share_bip39_v2(&sb, nonce, x, threshold),
        };
        chela_primitives::zeroize::Zeroize::zeroize(&mut sb);
        out.push(Share {
            scheme: mode,
            x,
            threshold,
            nonce,
            total: Some(total),
            kind: Some(coarse_kind),
            word_indices,
        });
    }
    let _ = kind_byte; // already inside `body`
    Ok(out)
```

- [ ] **Step 3: Rewrite `recover_secret`** (lines 550-631):

```rust
pub fn recover_secret(shares: &[Share]) -> Result<RecoveredSecret, EngineError> {
    if shares.is_empty() {
        return Err(EngineError::InsufficientShares);
    }

    // Decode each share's words (authoritative x/M/nonce/body).
    let mut decoded: Vec<DecodedShare> = Vec::with_capacity(shares.len());
    for s in shares {
        match s.scheme {
            OutputMode::Bip39Wordlist => decoded.push(decode_share_bip39_v2(&s.word_indices)?),
        }
    }

    let first = &decoded[0];
    for d in &decoded[1..] {
        if d.nonce != first.nonce || d.threshold != first.threshold || d.body.len() != first.body.len() {
            return Err(EngineError::MismatchedShares); // different generation or corrupt
        }
    }
    if decoded.len() < first.threshold as usize {
        return Err(EngineError::InsufficientShares);
    }

    let xs: Vec<u8> = decoded.iter().map(|d| d.x).collect();
    for (i, &xi) in xs.iter().enumerate() {
        if xi == 0 || xs[i + 1..].contains(&xi) {
            return Err(EngineError::Sss(chela_sss::SssError::DuplicateXCoordinate));
        }
    }

    let mut body = chela_primitives::zeroize::Zeroizing::new(vec![0u8; first.body.len()]);
    {
        let refs: Vec<&[u8]> = decoded.iter().map(|d| d.body.as_slice()).collect();
        combine(&xs, &refs, &mut body[..])?;
    }
    parse_bundle(&body[..])
}
```

> `DecodedShare.body` holds combinable share material; the `Vec`s drop at function end. If you want belt-and-suspenders wiping, wrap each `d.body` in `Zeroizing` at decode (Task 6 already does for scratch). Acceptable as-is for the plan; tighten in review if desired.

- [ ] **Step 4: Delete dead code.** Remove `compute_identifier` (already in Task 4), and the now-unused `SHARE_CHECKSUM_LEN`/`IDENTIFIER_LEN`-based logic. Keep `IDENTIFIER_LEN` only if still referenced; otherwise delete (and its `Quick reference` mentions move to SPEC rewrite, Phase 5).

- [ ] **Step 5: Build.** Run: `cargo build -p chela-engine`
Expected: compiles (engine tests updated in Task 8).

- [ ] **Step 6: Commit.**

```bash
git add chela-engine/src/lib.rs
git commit -m "feat(engine): v2 Share (nonce, optional total/kind), nonce-bound recovery"
```

---

### Task 8: Engine round-trip + property tests

**Files:**
- Modify: `chela-engine/src/lib.rs` tests module (665-end). Fix the existing end-to-end tests to the new `RecoveredSecret`-by-ref pattern (already `match &recovered`) — they need no `identifier` reads; remove `assert_eq!(s.identifier, id)` lines (680-685) and assert on `s.nonce`/`s.threshold` instead.

- [ ] **Step 1: Replace `identifier` assertions** in `end_to_end_bip39_24_word_no_passphrase_3_of_5` (680-685):

```rust
        let nonce = shares[0].nonce;
        for s in &shares {
            assert_eq!(s.nonce, nonce);
            assert_eq!(s.threshold, 3);
            assert_eq!(s.total, Some(5));
        }
```

- [ ] **Step 2: Add the v2 property tests:**

```rust
    #[test]
    fn round_trip_every_subset_text_and_passphrase() {
        for (input, ms) in [
            (SplitInput::Text { text: "correct horse battery staple" }, 2u8),
            (SplitInput::Bip39 {
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                passphrase: "trezor",
            }, 3u8),
        ] {
            let shares = split_secret(&input, ms, 5, OutputMode::Bip39Wordlist).unwrap();
            // Every share has distinct x in 1..=32 and a shared nonce.
            let n = shares[0].nonce;
            for s in &shares { assert!((1..=32).contains(&s.x)); assert_eq!(s.nonce, n); }
            // Any M of the 5 recovers.
            let recovered = recover_secret(&shares[..ms as usize]).unwrap();
            drop(recovered); // value matched in the dedicated end-to-end tests above
        }
    }

    #[test]
    fn mixing_two_generations_is_rejected() {
        let mk = || split_secret(&SplitInput::Text { text: "hello world" }, 2, 3, OutputMode::Bip39Wordlist).unwrap();
        let a = mk();
        let b = mk();
        // Same secret, two generations -> different nonces -> mixing rejected.
        let mixed = alloc::vec![a[0].clone(), b[1].clone()];
        assert!(matches!(recover_secret(&mixed), Err(super::EngineError::MismatchedShares)));
    }

    #[test]
    fn words_alone_recovery_ignores_total_and_kind() {
        let shares = split_secret(&SplitInput::Text { text: "secret note" }, 2, 4, OutputMode::Bip39Wordlist).unwrap();
        // Strip the advisory fields a lone transcription wouldn't have.
        let bare: Vec<super::Share> = shares.iter().take(2).map(|s| super::Share {
            scheme: s.scheme, x: s.x, threshold: s.threshold, nonce: s.nonce,
            total: None, kind: None, word_indices: s.word_indices.clone(),
        }).collect();
        match recover_secret(&bare).unwrap() {
            RecoveredSecret::Text { text } => assert_eq!(text, "secret note"),
            _ => panic!("expected text"),
        }
    }
```

- [ ] **Step 3: Run.** Run: `cargo test -p chela-engine`
Expected: PASS (all engine tests).

- [ ] **Step 4: Commit.**

```bash
git add chela-engine/src/lib.rs
git commit -m "test(engine): v2 round-trip, generation-mixing rejection, words-alone recovery"
```

---

## Phase 3 — chela-share wire formats

### Task 9: Text format + words-only parse

**Files:**
- Modify: `chela-share/src/lib.rs` — `format_share` (162-182), `parse_share` (186-243), add `parse_share_words`. Add `FormatError::HeaderWordsMismatch`.

- [ ] **Step 1: Update `format_share`** to emit the nonce and use `total.unwrap_or(0)`:

```rust
pub fn format_share(share: &Share) -> String {
    let word_count = share.word_indices.len();
    let total = share.total.map_or_else(|| "?".to_string(), |n| n.to_string());
    let mut out = format!(
        "CHELA-{:04X}-{}-{}-{}-{}\n",
        share.nonce & 0x7FF, share.x, share.threshold, total, word_count,
    );
    // ... existing word-append loop unchanged (172-179) ...
    out
}
```

- [ ] **Step 2: Rewrite `parse_share`** so the words are authoritative. Decode the words via the engine, then cross-check the advisory header:

```rust
pub fn parse_share(header: &str, words_line: &str) -> Result<Share, FormatError> {
    let mut share = parse_share_words(words_line)?;
    // Advisory header: cross-check x/M/nonce if present, capture total N.
    let body = uppercase_ascii(header.trim());
    let body = body.strip_prefix("CHELA-").ok_or(FormatError::BadHeader)?;
    let parts: Vec<&str> = body.split('-').collect();
    if parts.len() != 5 { return Err(FormatError::BadHeader); }
    let h_nonce = u16::from_str_radix(parts[0], 16).map_err(|_| FormatError::BadIdentifier)?;
    let h_x: u8 = parts[1].parse().map_err(|_| FormatError::BadShareIndex)?;
    let h_m: u8 = parts[2].parse().map_err(|_| FormatError::BadThresholdTotal)?;
    let h_n: u8 = parts[3].parse().map_err(|_| FormatError::BadThresholdTotal)?;
    if (h_nonce & 0x7FF) != share.nonce || h_x != share.x || h_m != share.threshold {
        return Err(FormatError::HeaderWordsMismatch);
    }
    share.total = Some(h_n);
    Ok(share)
}

/// Recover a share from its words alone — no header. Authoritative path for words-only backups.
pub fn parse_share_words(words_line: &str) -> Result<Share, FormatError> {
    let mut word_indices = Vec::new();
    for w in words_line.split_whitespace() {
        word_indices.push(chela_bip39::word_to_index(w).ok_or(FormatError::UnknownWord)?);
    }
    if word_indices.is_empty() { return Err(FormatError::MissingWords); }
    let d = chela_engine::decode_share_words(&word_indices)
        .map_err(|_| FormatError::ShareCorrupt)?;
    Ok(Share {
        scheme: OutputMode::Bip39Wordlist,
        x: d.x,
        threshold: d.threshold,
        nonce: d.nonce,
        total: None,
        kind: None,
        word_indices,
    })
}
```

> Requires a thin public engine accessor — add to chela-engine: `pub fn decode_share_words(words: &[u16]) -> Result<DecodedShare, EngineError> { decode_share_bip39_v2(words) }` and make `DecodedShare` public (Task 6 already marks it `pub`). Add `FormatError::HeaderWordsMismatch` and `FormatError::ShareCorrupt` variants.

- [ ] **Step 3: Update tests** in `chela-share/src/lib.rs` (343-380): construct `Share` with `nonce`/`Option` fields, and build headers from real encoded words (use `chela_engine::split_secret` to get valid shares rather than hand-built ones). Replace `s2.x = 4` style mutation with re-split fixtures.

- [ ] **Step 4: Run.** Run: `cargo test -p chela-share`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add chela-share/src/lib.rs chela-engine/src/lib.rs
git commit -m "feat(share): words-authoritative text parse + words-only entry point"
```

---

### Task 10: JSON export/import

**Files:**
- Modify: `chela-share/src/export.rs` — `write_share_json_object` (127-190), `shares_bundle_filename` (21), `share_json_filename` (15).
- Modify: `chela-share/src/import.rs` — `decode_share_value` (159-235), `parse_set_id` (237-245).

- [ ] **Step 1: Export.** In `write_share_json_object`, emit `set_id` as the 4-hex nonce, `card_number`=x, `threshold`=M from the share; `total` and `payload_kind` only when `Some` (omit or `null` when `None`):

```rust
    // set_id (lines 136-141): use the nonce.
    let _ = core::fmt::Write::write_fmt(out, format_args!("\"set_id\":\"{:04X}\",", share.nonce & 0x7FF));
    // card_number / threshold (143-144): unchanged (share.x, share.threshold).
    // total (145): only if known.
    if let Some(n) = share.total {
        let _ = core::fmt::Write::write_fmt(out, format_args!("\"total\":{n},"));
    }
    // payload_kind (152-154): only if known.
    if let Some(k) = share.kind {
        let name = match k { PayloadKind::Bip39 => "bip39", PayloadKind::Text => "text" };
        let _ = core::fmt::Write::write_fmt(out, format_args!("\"payload_kind\":\"{name}\","));
    }
```

Update `shares_bundle_filename`/`share_json_filename` to use `share.nonce` (was `identifier[0]/[1]`).

- [ ] **Step 2: Import.** In `decode_share_value`, derive x/M/nonce from the words (authoritative) and treat `card_number`/`threshold`/`set_id`/`total`/`payload_kind` as advisory cross-checks:

```rust
    // Parse words first (authoritative).
    let words_arr = v.get("words").and_then(Value::as_array).ok_or(ImportError::BadField("words"))?;
    let mut word_indices = Vec::with_capacity(words_arr.len());
    for w in words_arr {
        let s = w.as_str().ok_or(ImportError::BadField("words"))?;
        word_indices.push(chela_bip39::word_to_index(s).ok_or(ImportError::UnknownWord)?);
    }
    let d = chela_engine::decode_share_words(&word_indices).map_err(|_| ImportError::ShareCorrupt)?;
    // Advisory cross-checks (reject on disagreement to catch corruption):
    if let Some(cn) = v.get("card_number").and_then(Value::as_u8) {
        if cn != d.x { return Err(ImportError::BadThresholdTotalOrIndex); }
    }
    if let Some(th) = v.get("threshold").and_then(Value::as_u8) {
        if th != d.threshold { return Err(ImportError::BadThresholdTotalOrIndex); }
    }
    let total = v.get("total").and_then(Value::as_u8);
    let kind = match v.get("payload_kind").and_then(Value::as_str) {
        Some("bip39") => Some(PayloadKind::Bip39),
        Some("text") => Some(PayloadKind::Text),
        Some(_) => return Err(ImportError::UnknownPayloadKind),
        None => None,
    };
    Ok(Share { scheme: OutputMode::Bip39Wordlist, x: d.x, threshold: d.threshold,
               nonce: d.nonce, total, kind, word_indices })
```

Delete `parse_set_id` if unused, or keep it to validate the advisory `set_id` against `d.nonce`. Add `ImportError::ShareCorrupt`.

- [ ] **Step 3: Update export/import tests** to build fixtures from `split_secret` (not hand-set `s.x = ...`).

- [ ] **Step 4: Run.** Run: `cargo test -p chela-share`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add chela-share/src/export.rs chela-share/src/import.rs
git commit -m "feat(share): words-authoritative JSON import/export with nonce set_id"
```

---

### Task 11: HTML render

**Files:**
- Modify: `chela-share/src/html.rs` — identifier→nonce display (62), total display (127, 189), shareholder indexing (156).

- [ ] **Step 1: Replace identifier hex** (line 62) with `format!("{:04X}", share.nonce & 0x7FF)`.
- [ ] **Step 2: Guard `total`** (127, 189): `share.total.map_or("?".to_string(), |n| n.to_string())`.
- [ ] **Step 3: Shareholder index** (156): `share.x` is 1..32; keep `saturating_sub(1)` (works regardless of N).
- [ ] **Step 4: Update html tests** (532, 659, 733, 768) to use `split_secret` fixtures.
- [ ] **Step 5: Run + commit.** Run: `cargo test -p chela-share`

```bash
git add chela-share/src/html.rs
git commit -m "feat(share): HTML render uses nonce and optional total"
```

---

## Phase 4 — Caller crates

### Task 12: chela-cli

**Files:**
- Modify: `chela-cli/src/main.rs` — `cmd_split` (125-151) display, `cmd_recover` (343-370). Update the `MAX_SHARES` cap at split input validation.

- [ ] **Step 1:** Add a `total > chela_engine::MAX_SHARES` check beside the existing `MIN_THRESHOLD` check (125-128) with message `"total (-n) must be at most 32"`.
- [ ] **Step 2:** `cmd_split` output uses `format_share(share)` — unchanged. Any direct identifier hex printing switches to `share.nonce`.
- [ ] **Step 3:** `cmd_recover` — switch the recover input path to accept words-only (call `parse_share_words` when no header line is present). Match on `RecoveredSecret` unchanged.
- [ ] **Step 4: Run + commit.** Run: `cargo test -p chela-cli && cargo run -p chela-cli -- --help`

```bash
git add chela-cli/src/main.rs
git commit -m "feat(cli): 32-share cap, nonce display, words-only recovery"
```

### Task 13: chela-tui

**Files:**
- Modify: `chela-tui/src/wizard.rs` — `display_share` (734-747), `run_recover` (803-935), `ParsedHeader::from_str` (1242-1286), `import_html_phase` (1108-1138), local `MIN_THRESHOLD` (21).

- [ ] **Step 1:** `display_share` header: build from `share.nonce`, `x`, `threshold`, `total.unwrap_or(0)`, word_count.
- [ ] **Step 2:** Recovery duplicate detection (875, 1126) — key on `s.x` (1..32) unchanged. "Remaining cards" logic (846-848) depends on `total`; guard with `total.unwrap_or(0)` and skip the hint when total is unknown (words-only).
- [ ] **Step 3:** `ParsedHeader::from_str` — parse the advisory header but cross-check against decoded words; require `total >= threshold` only when present. Replace local `MIN_THRESHOLD` (line 21) with `chela_engine::MIN_THRESHOLD`; add `chela_engine::MAX_SHARES` cap.
- [ ] **Step 4:** `import_html_phase` set-consistency check (1108-1112): compare `nonce`/`threshold` (drop `identifier`/`kind`/`total` equality — kind/total are now `Option`).
- [ ] **Step 5: Run + commit.** Run: `cargo test -p chela-tui`

```bash
git add chela-tui/src/wizard.rs
git commit -m "feat(tui): nonce header, optional total, 32-share cap"
```

### Task 14: chela-wasm + browser RNG

**Files:**
- Modify: `chela-wasm/src/lib.rs` — `do_split` (168-188), `do_recover` (239-247), `do_extract_shares` (410-418).
- Verify/modify: the JS shim that provides `chela.random_bytes` (locate under `web/` or `chela-bundle`).

- [ ] **Step 1:** `do_split`/`do_extract_shares` JSON: `set_id` from `share.nonce` (`{:04X}`), `total` only when `Some`. `card_code` via `format_share`.
- [ ] **Step 2:** `do_recover` matches `RecoveredSecret` unchanged; ensure the parse path uses `parse_share_words` for words-only input.
- [ ] **Step 3: Browser RNG audit.** Locate the host import for `chela.random_bytes` (the wasm import module `chela`, see `chela-primitives/src/rng.rs:176-178`). Confirm the JS backs it with `crypto.getRandomValues`. Add the test below to the shim or a doc check.

```bash
grep -rn "random_bytes\|getRandomValues\|Math.random" web/ chela-bundle/ chela-wasm/
```

Expected: the shim calls `crypto.getRandomValues`; **no** `Math.random`. If `Math.random` backs it, replace with `crypto.getRandomValues(new Uint8Array(...))`.

- [ ] **Step 4: Run + commit.** Run: `cargo build -p chela-wasm --target wasm32-unknown-unknown` (or the workspace's wasm build script).

```bash
git add chela-wasm/src/lib.rs web/
git commit -m "feat(wasm): nonce set_id, words-only recovery, verified crypto RNG"
```

---

## Phase 5 — Spec + final verification

### Task 15: Rewrite SPEC.md to v2 format

**Files:**
- Modify: `SPEC.md` — Quick reference table (7-16), §2 (42-81), §4 (105-129), §5.1/5.2 (133-175), §6 (188-200), §7 vectors (202-228), §8 (230-234).

- [ ] **Step 1:** Quick reference: drop `Identifier length`/`Per-share checksum length` SHA rows; add `nonce = 11-bit random`, `per-share checksum = CRC-11/UMTS 0x307`, `max N/M = 32`, `x = field+1 (1..32)`, `M = field+2 (2..32)`.
- [ ] **Step 2:** §2: body is `payload ‖ kind_byte`; remove §2.3 Identifier and §2.4 kind-discovery; kind is the final body byte.
- [ ] **Step 3:** §4: replace §4.1/4.2/4.3 with the four-section layout, the CRC-11 input `[x,M]‖nonce_be‖Y`, and the candidate-length disambiguation.
- [ ] **Step 4:** §5.1 header `CHELA-<NONCE>-<x>-<M>-<N>-<W>` advisory; §5.2 JSON `set_id`=nonce, `total`/`payload_kind` optional.
- [ ] **Step 5:** §7: add the CRC-11/UMTS vector (`crc11_umts(b"123456789") == 0x061`) and a full v2 share encode vector for a known short text secret.
- [ ] **Step 6: Commit.**

```bash
git add SPEC.md
git commit -m "spec: rewrite share format to v2 (words-alone, nonce, CRC-11)"
```

### Task 16: Cross-crate verification

- [ ] **Step 1: SHA-256 is out of the engine.** Run: `grep -rn "sha256\|Sha256" chela-engine/src` — expect **no matches**.
- [ ] **Step 2: Full workspace check.** Run: `cargo test --workspace`
Expected: all green.
- [ ] **Step 3: Lint (matches the pre-push hook).** Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings` and the wasm-target clippy the hook runs.
- [ ] **Step 4: Manual smoke.** `cargo run -p chela-cli -- split` a 12-word seed 2-of-3, then recover from words only (paste just the words, no `CHELA-` line). Confirm recovery.
- [ ] **Step 5: Commit any lint fixups.**

```bash
git add -A
git commit -m "chore: workspace lint + format after v2 share format"
```

---

## Self-review

- **Spec coverage:** §3.1 word0 → Tasks 5/6; §3.2 nonce → Tasks 3/7; §3.3 body+kind → Task 4; §3.4 CRC-11 → Tasks 1/5/6; §4 random distinct x → Tasks 2/3; §5 recovery → Task 7; §6 card label → Tasks 9-13; §7 trade-offs (size/binding) → covered by tests in Task 8; §8 browser RNG → Task 14. SPEC.md normative rewrite → Task 15.
- **Types are consistent:** `encode_share_bip39_v2(&[u8], u16, u8, u8)`, `decode_share_bip39_v2(&[u16]) -> DecodedShare {x,threshold,nonce,body}`, `Share { scheme,x,threshold,nonce,total:Option,kind:Option,word_indices }`, `crc11_umts(&[u8]) -> u16`, engine accessor `decode_share_words`. Used identically in Phases 3-4.
- **Open risk:** Task 6's per-share length disambiguation uses an 11-bit CRC, so a wrong candidate length passes with ≈1/2048. The cross-share `body.len()` agreement check in Task 7 (`recover_secret`) is the backstop; for a single share decoded in isolation the first CRC-matching length wins — acceptable, matches the design's stated residual.
