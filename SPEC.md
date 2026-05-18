# chela format specification v1

This document is **the minimum sufficient information** to write a new
implementation of chela's share-split and share-recover machinery that is
bit-compatible with the reference Rust implementation. Audience: an engineer
porting chela to another language (Python, Go, C, Java, …) or auditing the
construction.

For prose context — threat model, provenance, design tradeoffs — see
[AUDITORS.md](./AUDITORS.md) and [AGENTS.md](./AGENTS.md). For paper
recovery without any chela tool, see [MANUAL_RECOVERY.md](./MANUAL_RECOVERY.md).

## Scope

A chela "share set" splits a fixed-length byte payload into `N` shares such
that any `M` of them reconstruct the payload. The payload is:

- **BIP-39 mnemonic**: raw 16/20/24/28/32-byte entropy + optional 0..255-byte
  passphrase, concatenated
- **Text**: raw 1..255-byte UTF-8 bytes

A reimplementation must produce shares that the reference implementation can
recover, and recover shares the reference implementation produces. There is
no schema negotiation; everything is version-pinned via the `chela.share.v1`
sentinel.

## Quick reference

| Constant                          | Value                                            |
|-----------------------------------|--------------------------------------------------|
| GF(2^8) reduction polynomial      | `0x11b` (x⁸ + x⁴ + x³ + x + 1, AES / Rijndael)   |
| Identifier length                 | 2 bytes (16 bits)                                |
| Per-share checksum length         | 2 bytes (16 bits)                                |
| Max body length                   | 287 bytes (32 entropy + 255 passphrase)          |
| Max threshold `M` and total `N`   | 255 (`x = 0` reserved for the secret)            |
| BIP-39 wordlist size              | 2048 (11 bits per word, English wordlist)        |
| BIP-39 wordlist SHA-256           | `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` |
| Format version sentinel           | `chela.share.v1` (single), `chela.shares.v1` (bundle) |

## 1. Cryptographic core

### 1.1 SHA-256

FIPS 180-4 § 6.2, unmodified. No keys, no truncation except where explicitly
called out (`[..2]` = first two bytes of the 32-byte digest).

### 1.2 GF(2^8)

Elements are bytes (`u8`). Add is XOR. Multiply is polynomial multiplication
mod the AES reduction polynomial `0x11b` (low byte `0x1b`).

```text
add(a, b)  =  a XOR b
mul(a, b)  =  Σ over i=0..7  ((b >> i) AND 1) ? rot(a, i) : 0   where
             rot(a, 0) = a
             rot(a, i) = let v = rot(a, i-1); (v << 1) XOR (msb(v) ? 0x1b : 0)
inv(0)     =  0   (convention; combine MUST never call inv(0))
inv(x)     =  x^254   when x ≠ 0   (Fermat's little theorem in GF(2^8))
```

A constant-time `inv` via squaring chain is in `chela-field/src/gf256.rs`.
Reimplementations may use a 512-byte log/antilog table if side-channels aren't
a concern; both produce the same output.

KAT: `mul(0x57, 0x83) = 0xc1` (FIPS 197 § 4.1).

### 1.3 BIP-39 wordlist

The English wordlist from BIP-0039 verbatim, 2048 entries indexed 0..2047.
Verify against the canonical hash above. Each entry is the 11-bit value used
to encode that index in chela's share words (see § 4).

## 2. Bundle layout

What SSS splits is **only the body bytes**. There is no framing, no kind tag,
and no checksum **inside** the body. Discriminator metadata lives in the
identifier hash and on the printed card.

### 2.1 Body construction

| Payload kind        | Body bytes                                                |
|---------------------|-----------------------------------------------------------|
| BIP-39 (no pass)    | `entropy_bytes` (16/20/24/28/32)                          |
| BIP-39 (passphrase) | `entropy_bytes ‖ passphrase_utf8` (passphrase 1..255 B)  |
| Text                | `text_utf8` (1..255 B)                                    |

### 2.2 `kind_byte` table

A 1-byte tag that's mixed into the identifier hash but **never written into
the body**. The set is closed at v1 — reimplementations MUST recognise
every byte below.

| `kind_byte` | Kind                                            |
|-------------|-------------------------------------------------|
| `0x01`      | BIP-39, 12 words (16 B entropy), no passphrase  |
| `0x02`      | BIP-39, 15 words (20 B entropy), no passphrase  |
| `0x03`      | BIP-39, 18 words (24 B entropy), no passphrase  |
| `0x04`      | BIP-39, 21 words (28 B entropy), no passphrase  |
| `0x05`      | BIP-39, 24 words (32 B entropy), no passphrase  |
| `0x06`      | BIP-39, 12 words, with passphrase               |
| `0x07`      | BIP-39, 15 words, with passphrase               |
| `0x08`      | BIP-39, 18 words, with passphrase               |
| `0x09`      | BIP-39, 21 words, with passphrase               |
| `0x0A`      | BIP-39, 24 words, with passphrase               |
| `0x0B`      | Text                                            |

### 2.3 Identifier

```
identifier = SHA-256(body ‖ [kind_byte])[0..2]
```

Two bytes, printed as four uppercase hex characters on every card (`A4F7`).

### 2.4 Recovery: kind discovery

The card carries the identifier but not the `kind_byte`. Recovery enumerates
the kind table in order; for each `kind_byte`:

1. Check `body.len()` against the kind's allowed lengths (table § 2.2):
   - No-passphrase BIP-39 kinds: exactly `entropy_bytes`
   - With-passphrase BIP-39 kinds: strictly greater than `entropy_bytes`, ≤ `entropy_bytes + 255`
   - Text: 1..=255
2. If length matches, compute `SHA-256(body ‖ [kind_byte])[0..2]` and compare to
   the printed identifier via constant-time equality.
3. First match wins; decode `body` per that kind.

If no kind matches, recovery fails (`BundleCorrupt`). False-positive rate
≈ 11/65 536; any false match almost always then fails as invalid BIP-39 or
invalid UTF-8.

## 3. Shamir split / combine

### 3.1 Split — per-byte polynomial

For each byte position `i` of the body, and for each share number `x` in
`1..=N`:

```
P_i(x) = body[i] ⊕ r_{i,1}·x ⊕ r_{i,2}·x² ⊕ … ⊕ r_{i,M-1}·x^{M-1}
share_x[i] = P_i(x)
```

All arithmetic in GF(2^8). The non-constant coefficients `r_{i,1}..r_{i,M-1}`
are sampled uniformly at random per byte position from the OS RNG. A
single share reveals zero information about `body[i]` (information-theoretic
secrecy of Shamir).

x-coordinates: `1..=N`; `x = 0` is reserved for the secret and MUST NOT be
issued as a share.

### 3.2 Combine — Lagrange at x=0

Given any subset `S ⊆ {1..=N}` with `|S| ≥ M`:

```
L_i(0) = Π over j in S, j ≠ i  of  ( x_j / (x_i ⊕ x_j) )       (GF(2^8))
body[i] = Σ over i in S  of  ( L_i(0) · share_{x_i}[byte] )
```

`x_i ⊕ x_j` is the GF(2^8) "subtraction" (`a - b == a + b == a ⊕ b` in
characteristic 2). `combine` MUST reject duplicate x-values and `x = 0`.

Compute Lagrange coefficients once per recovery (outside the per-byte loop).

## 4. Share encoding (BIP-39 wordlist scheme)

The scheme identifier is `"bip39-wordlist"`. This is the only encoding v1
defines.

### 4.1 Per-share checksum

```
share_checksum = SHA-256(share_bytes ‖ identifier ‖ [x])[0..2]
```

`share_bytes` is the SSS output for this `x` (length == `body.len()`).
The checksum is a 2-byte tail that follows the share bytes in the bit stream.
It binds to `identifier` and `x` so a card from a different split, or one
swapped between positions of the same split, fails verification immediately.

### 4.2 Bit packing

```
payload_bits = share_bytes ‖ share_checksum     (bit order: MSB-first per byte)
total_bits   = 8 · (body.len() + 2)
word_count   = ceil(total_bits / 11)             (one word = 11 bits)
```

Walk `payload_bits` MSB-first, taking 11 bits at a time. The final group is
zero-padded on the right (i.e. the unused bits become the low bits of the
final 11-bit word).

Each 11-bit value is a BIP-39 wordlist index (0..2047) → look up the word.

### 4.3 Word-count ambiguity (decode side)

Different `body.len()` values may pack into the same `word_count`. Example:
a 36-byte and a 37-byte body both produce 27 words.

Recovery procedure:

1. Compute `total_bits_max = word_count · 11` and `min_bytes`/`max_bytes`
   such that `ceil(B · 8 / 11) == word_count`.
2. For each candidate `total_bytes` in `max_bytes..=min_bytes` (descending):
   - Set `payload_len = total_bytes - 2`
   - For every share, attempt to verify `share_checksum` against the
     `payload_len`-prefixed bytes.
   - First `payload_len` for which **every** share's checksum verifies is the
     correct length.
3. If no candidate verifies for every share, recovery fails (`ShareCorrupt`).

## 5. Wire formats

### 5.1 Share text format

Two lines, separated by a newline:

```
CHELA-<ID>-<x>-<M>-<N>-<W>
word1 word2 word3 … wordW
```

- `<ID>` — 4 uppercase hex characters of the identifier (e.g. `A4F7`).
  Parser is case-insensitive on the prefix and the hex; encoder emits uppercase.
- `<x>` — decimal share number, 1..N
- `<M>` / `<N>` — decimal threshold / total
- `<W>` — decimal word count on line 2 (redundant; parser rejects mismatches)
- words — space-separated, drawn from the BIP-39 English wordlist

Multiple shares concatenate with a blank line between them.

### 5.2 JSON formats

The JSON schema embedded in HTML paper backups and used by chela-cli's
`--json` / `--json-dir` flags.

**Single share** (`chela.share.v1`):

```json
{
  "type": "chela.share.v1",
  "card_code": "CHELA-A4F7-1-3-5-25",
  "set_id": "A4F7",
  "card_number": 1,
  "threshold": 3,
  "total": 5,
  "word_count": 25,
  "scheme": "bip39-wordlist",
  "payload_kind": "bip39",
  "words": ["abandon", "ability", "able", "..."],
  "backup_name": "Alice's Ethereum wallet",
  "description": "Optional free-form note.",
  "shareholder_names": ["Alice", "Bob", "Carol", "Dan", "Eve"]
}
```

Required fields: `type`, `card_code`, `set_id`, `card_number`, `threshold`,
`total`, `word_count`, `scheme`, `payload_kind`, `words`. `words.length` MUST
equal `word_count`. Optional: `backup_name`, `description`,
`shareholder_names` (presentation metadata only; does not affect crypto).

**Bundle** (`chela.shares.v1`):

```json
{
  "type": "chela.shares.v1",
  "shares": [ { /* chela.share.v1 */ }, { /* chela.share.v1 */ }, ... ]
}
```

### 5.3 HTML embedding

```html
<script type="application/json" class="chela-share">
{ /* exact chela.share.v1 JSON object */ }
</script>
```

One block per `<article>` in multi-page documents. Tools extract via
`querySelectorAll('script.chela-share')`. The encoder MUST escape `<` to
`<` inside JSON strings (defeats `</script>` injection from user-supplied
text fields).

## 6. Wire-format normative rules

A conformant implementation MUST:

1. Reject shares whose `(identifier, scheme, payload_kind, threshold, total)`
   tuples disagree across the input set (`MismatchedShares`).
2. Reject `<` `M` shares supplied to combine (`InsufficientShares`).
3. Reject duplicate or zero `x`-coordinates passed to combine.
4. Reject any share whose per-share checksum doesn't verify (`ShareCorrupt`).
5. Validate `card_code` parses identically before and after a JSON round-trip.
6. Treat the `chela.share.v1` `type` sentinel as a hard schema gate — newer
   sentinels MUST cause a decoder targeting v1 to refuse the input.

A conformant implementation MAY:

- Allow extra unknown fields in the JSON (forward compatibility).
- Use either constant-time or table-based GF(2^8) multiplication (the wire
  format is identical; side-channel posture differs).

## 7. Test vectors

### 7.1 GF(2^8)

```
mul(0x57, 0x83) = 0xc1                       (FIPS 197 § 4.1)
inv(0x53) = 0xca                              (AES S-box pre-affine)
mul(x, inv(x)) = 0x01     for every x in 1..=255
```

### 7.2 SHA-256

Per FIPS 180-2 App B + NIST CAVP — the reference vectors in
`chela-primitives/src/sha256.rs` tests.

### 7.3 Identifier

```
body      = 0x68 0x65 0x6c 0x6c 0x6f                  ("hello" as text)
kind_byte = 0x0B
SHA-256(body ‖ [kind_byte])[0..2] = ?
```

Compute the full SHA-256 of `68656c6c6f0b` (six bytes); the first two bytes
of the digest are the identifier. (A reimplementation hits the same value
as the reference because both use the unmodified FIPS 180-4 SHA-256.)

### 7.4 SSS (with a deterministic test RNG)

For exhaustive split → every-M-subset → combine round-trip vectors over M ≤ N
≤ 6, see `chela-sss/src/lib.rs::tests::round_trip_for_every_subset_of_every_m_n_up_to_6`
and `chela-engine/src/lib.rs::tests::round_trip_at_payload_lengths_with_word_count_ambiguity`.

### 7.5 Word-count ambiguity edge cases

The reference test `round_trip_at_payload_lengths_with_word_count_ambiguity`
sweeps every text length from 1 to 60 bytes. Each length MUST round-trip
through the encode-decode pair for a conformant implementation; this also
exercises the candidate-length enumeration in § 4.3.

## 8. Versioning

`v1` is the first published format and the only one defined here. Future
versions will:

- Bump the JSON `type` sentinel (e.g. `chela.share.v2`)
- Possibly add new `kind_byte` values 0x0C onwards (decoders MUST treat
  unknown `kind_byte` as `BundleCorrupt`)
- Possibly add new `scheme` values (decoders MUST treat unknown `scheme` as
  `UnknownScheme`)

Reimplementations targeting v1 MUST NOT silently accept v2-or-later inputs.

## 9. Out of scope for this spec

Threat model, secret-zeroize discipline, constant-time correctness, terminal
display sanitisation, paper-backup HTML rendering, the recovery UI in any
front-end. Those are implementation concerns specific to the reference Rust
build and are covered in [AUDITORS.md](./AUDITORS.md) and the per-crate
source.
