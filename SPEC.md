# chela format specification v1

Minimum sufficient information to write a chela-compatible implementation, version-pinned via `chela.share.v1`.

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

### 1.1 SHA-256 — FIPS 180-4 § 6.2, unmodified; `[..2]` = first 2 bytes of digest

### 1.2 GF(2^8)

Elements are bytes (`u8`); add = XOR; multiply = polynomial mul mod `0x11b` (AES polynomial, low byte `0x1b`).

```text
add(a, b)  =  a XOR b
mul(a, b)  =  Σ over i=0..7  ((b >> i) AND 1) ? rot(a, i) : 0   where
             rot(a, 0) = a
             rot(a, i) = let v = rot(a, i-1); (v << 1) XOR (msb(v) ? 0x1b : 0)
inv(0)     =  0   (convention; combine MUST never call inv(0))
inv(x)     =  x^254   when x ≠ 0   (Fermat's little theorem in GF(2^8))
```

KAT: `mul(0x57, 0x83) = 0xc1` (FIPS 197 § 4.1). A 512-byte log/antilog table produces identical output.

### 1.3 BIP-39 wordlist

BIP-0039 English wordlist verbatim, 2048 entries (0..2047); verify against the
canonical hash (Quick reference); each index is an 11-bit value used in § 4.

## 2. Bundle layout

### 2.1 Body construction

| Payload kind        | Body bytes                                                |
|---------------------|-----------------------------------------------------------|
| BIP-39 (no pass)    | `entropy_bytes` (16/20/24/28/32)                          |
| BIP-39 (passphrase) | `entropy_bytes ‖ passphrase_utf8` (passphrase 1..255 B)  |
| Text                | `text_utf8` (1..255 B)                                    |

### 2.2 `kind_byte` table

Mixed into the identifier hash; **never written into the body**. Set is closed at v1 — MUST recognise all values.

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
identifier = SHA-256(body ‖ [kind_byte])[0..2]   # 2 bytes, 4 uppercase hex chars on card
```

### 2.4 Recovery: kind discovery

Enumerate kind table in order. For each `kind_byte`: check `body.len()` fits the kind
(no-pass BIP-39 = exactly `entropy_bytes`; with-pass = `entropy_bytes+1..+255`; text = 1..=255);
if so, compute `SHA-256(body ‖ [kind_byte])[0..2]` and compare to the printed identifier
(constant-time). First match → decode. No match → `BundleCorrupt`.

## 3. Shamir split / combine

### 3.1 Split — per-byte polynomial

For each body byte `i` and share `x` in `1..=N`; arithmetic GF(2^8);
coefficients OS-RNG random; `x = 0` reserved for the secret and MUST NOT be issued:

```
P_i(x) = body[i] ⊕ r_{i,1}·x ⊕ r_{i,2}·x² ⊕ … ⊕ r_{i,M-1}·x^{M-1}
share_x[i] = P_i(x)
```

### 3.2 Combine — Lagrange at x=0

Given subset `S ⊆ {1..=N}`, `|S| ≥ M`; GF(2^8) arithmetic (`a ⊕ b = a - b`);
`combine` MUST reject duplicate x-values and `x = 0`:

```
L_i(0) = Π over j in S, j ≠ i  of  ( x_j / (x_i ⊕ x_j) )
body[i] = Σ over i in S  of  ( L_i(0) · share_{x_i}[byte] )
```

## 4. Share encoding — scheme `"bip39-wordlist"` (only scheme in v1)

### 4.1 Per-share checksum

```
share_checksum = SHA-256(share_bytes ‖ identifier ‖ [x])[0..2]
# share_bytes: SSS output for this x, length == body.len(); checksum follows in bit stream
```

### 4.2 Bit packing

```
payload_bits = share_bytes ‖ share_checksum     (bit order: MSB-first per byte)
total_bits   = 8 · (body.len() + 2)
word_count   = ceil(total_bits / 11)             (one word = 11 bits)
```

Walk MSB-first, 11 bits at a time; zero-pad the final group. Each 11-bit value indexes the BIP-39 wordlist (0..2047).

### 4.3 Word-count ambiguity (decode side)

Multiple body lengths may encode to the same `word_count`. Find `min_bytes`/`max_bytes`
s.t. `ceil(B·8/11) == word_count`. Iterate `total_bytes` from `max_bytes` down to
`min_bytes`; for each set `payload_len = total_bytes - 2` and verify `share_checksum`
against all shares. First `payload_len` where all verify → correct length; none → `ShareCorrupt`.

## 5. Wire formats

### 5.1 Share text format

```
CHELA-<ID>-<x>-<M>-<N>-<W>     (line 1)
word1 word2 word3 … wordW        (line 2; multiple shares: blank line between)
```

`<ID>` = 4 uppercase hex (case-insensitive parse); `<x>` = decimal 1..N;
`<M>`/`<N>` = threshold/total; `<W>` = word count (parser rejects mismatches);
words = space-separated BIP-39 English words.

### 5.2 JSON formats

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

Required: `type` `card_code` `set_id` `card_number` `threshold` `total` `word_count` `scheme` `payload_kind` `words`; `words.length` MUST equal `word_count`. Optional (presentation): `backup_name` `description` `shareholder_names`.

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

One block per `<article>`; tools extract via `querySelectorAll('script.chela-share')`.
Encoder MUST escape `<` → `&lt;` inside JSON strings.

## 6. Wire-format normative rules

A conformant implementation MUST:

1. Reject shares with mismatched `(identifier, scheme, payload_kind, threshold, total)` (`MismatchedShares`).
2. Reject fewer than `M` shares (`InsufficientShares`).
3. Reject duplicate or zero `x`-coordinates.
4. Reject shares whose per-share checksum fails (`ShareCorrupt`).
5. Validate `card_code` round-trips identically through JSON.
6. Treat `chela.share.v1` as a hard schema gate; reject any other `type` sentinel.

A conformant implementation MAY: allow extra unknown JSON fields; use
constant-time or table-based GF(2^8) multiplication (wire format is identical).

## 7. Test vectors

### 7.1 GF(2^8)

```
mul(0x57, 0x83) = 0xc1                       (FIPS 197 § 4.1)
inv(0x53) = 0xca                              (AES S-box pre-affine)
mul(x, inv(x)) = 0x01     for every x in 1..=255
```

### 7.2 SHA-256 — FIPS 180-2 App B + NIST CAVP (`chela-primitives/src/sha256.rs`)

### 7.3 Identifier

```
body      = 0x68 0x65 0x6c 0x6c 0x6f   ("hello", text)
kind_byte = 0x0B
input_hex = 68656c6c6f0b
SHA-256(input_hex)[0..2] = identifier
```

### 7.4 SSS round-trip

Exhaustive split → every-M-subset → combine for M ≤ N ≤ 6 and text body 1..60 B.
Each body length MUST round-trip (exercises § 4.3). Reference tests:
`chela-sss::tests::round_trip_for_every_subset_of_every_m_n_up_to_6` and
`chela-engine::tests::round_trip_at_payload_lengths_with_word_count_ambiguity`.

## 8. Versioning

Reimplementations targeting v1 MUST NOT silently accept v2-or-later inputs.
Decoders MUST treat unknown `kind_byte` as `BundleCorrupt` and unknown `scheme`
as `UnknownScheme`. Future versions bump the `type` sentinel (e.g. `chela.share.v2`).

## 9. Out of scope

Threat model, secret-zeroize discipline, constant-time correctness, terminal
display sanitisation, paper-backup HTML rendering, the recovery UI.
