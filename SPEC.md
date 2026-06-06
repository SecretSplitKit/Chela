# chela format specification v1

Minimum sufficient information to write a chela-compatible implementation, version-pinned via `chela.share.v1`.

A share recovers from its BIP-39 words alone — `x`, threshold `M`, a generation nonce, and a hidden payload kind all live in the words. The card label and JSON metadata are advisory.

## Quick reference

| Constant                          | Value                                            |
|-----------------------------------|--------------------------------------------------|
| GF(2^8) reduction polynomial      | `0x11b` (x⁸ + x⁴ + x³ + x + 1, AES / Rijndael)   |
| Generation nonce                  | 11-bit random, one per split, in word 1          |
| Per-share checksum                | CRC-11/UMTS, poly `0x307`, in the last word      |
| Max body length                   | 288 bytes (32 entropy + 255 passphrase + 1 kind) |
| Max threshold `M` and total `N`   | 32 each (`x = 0` reserved for the secret)        |
| `x` encoding                      | 5-bit field `0..31`, `x = field + 1` → `1..32`   |
| `M` encoding                      | 5-bit field `0..30`, `M = field + 2` → `2..32`   |
| BIP-39 wordlist size              | 2048 (11 bits per word, English wordlist)        |
| BIP-39 wordlist SHA-256           | `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` |
| Format version sentinel           | `chela.share.v1` (single), `chela.shares.v1` (bundle) |

## 1. Cryptographic core

### 1.1 GF(2^8)

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

### 1.2 CRC-11/UMTS

The per-share transcription checksum. Poly `0x307` (x¹¹+x⁹+x⁸+x²+x+1, implicit x¹¹),
`init 0x000`, `refin/refout = false`, `xorout 0x000`; catalogue check `0x061` over ASCII `"123456789"`.
With init 0, no reflection and no final XOR it is textbook GF(2) long division — auditable by hand,
cross-checkable against standard CRC tools. An 11-bit register detects every transcription error that
flips a single word (one word = a burst of ≤ 11 bits).

```text
crc = 0x000
for each input byte:
    crc ^= byte << 3                 # align byte MSB with bit 10 of the 11-bit register
    repeat 8 times:
        msb = crc & 0x400
        crc = (crc << 1) & 0x7FF
        if msb: crc ^= 0x307
return crc & 0x7FF
```

### 1.3 BIP-39 wordlist

BIP-0039 English wordlist verbatim, 2048 entries (0..2047); verify against the
canonical hash (Quick reference); each index is an 11-bit value used in § 4.

SHA-256 (FIPS 180-4 § 6.2, unmodified) is used inside `chela-bip39` to validate a mnemonic's built-in
checksum on recovery (§ 5), and to compute the body integrity tag (§ 2.1) that binds the whole secret.

## 2. Body layout

SSS splits the **body** = payload bytes, a 1-byte `kind_byte`, and a 2-byte integrity tag. No framing,
no identifier. The kind is split *with* the secret, so a single share's words reveal nothing about the
payload type, and recovery reads the kind from the body — no enumeration. The tag binds the whole
reconstructed secret so a wrong/foreign subset fails closed instead of returning a wrong secret (§ 5).

### 2.1 Body construction

```text
body = payload ‖ [kind_byte] ‖ tag      tag = SHA-256(payload ‖ kind_byte)[..2]
```

| Payload kind        | Payload bytes                                            |
|---------------------|----------------------------------------------------------|
| BIP-39 (no pass)    | `entropy_bytes` (16/20/24/28/32)                         |
| BIP-39 (passphrase) | `entropy_bytes ‖ passphrase_utf8` (passphrase 1..255 B) |
| Text                | `text_utf8` (1..255 B)                                   |

The **tag** is the first 2 bytes of `SHA-256(payload ‖ kind_byte)`, appended last. It is split *with*
the body, never carried out of band. Recovery recomputes it from the reconstructed `payload ‖ kind_byte`
and compares in constant time; a mismatch is `BundleCorrupt`. This is the only whole-secret integrity
binder: the per-share CRC-11 (§ 4) only proves a share is internally consistent, and the nonce (§ 4.2)
only binds a generation. A wrong subset — a same-secret nonce collision, or a corruption that still
satisfies its own CRC — interpolates to a garbage body whose recomputed tag won't match, so recovery
fails closed (residual ≈ 2⁻¹⁶ per wrong subset).

### 2.2 `kind_byte` table

Appended after the payload, before the tag. Set is closed at v1 — MUST recognise all values; any other byte is `BundleCorrupt`.

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

### 2.3 Reading the kind back

After combine reconstructs `body`: split off the trailing 2-byte tag, recompute `SHA-256(rest)[..2]`,
and compare in constant time; mismatch → `BundleCorrupt`. Only then trust the rest: kind = `rest[len-1]`,
payload = `rest[..len-1]`. Decode the kind via the table; reject (`BundleCorrupt`) unless the payload
length fits — no-pass BIP-39 = exactly `entropy_bytes`, with-pass = `entropy_bytes+1 .. entropy_bytes+255`,
text = `1..=255` — then interpret per the kind.

## 3. Shamir split / combine

### 3.1 Split — per-byte polynomial

For each body byte `i` and each of the `N` caller-supplied x-coordinates (§ 4.2); arithmetic GF(2^8);
coefficients OS-RNG random. The x-coordinates are distinct and in `1..=32`; `x = 0` is reserved for the
secret and MUST NOT be issued. `split` MUST reject duplicate or zero x:

```
P_i(x) = body[i] ⊕ r_{i,1}·x ⊕ r_{i,2}·x² ⊕ … ⊕ r_{i,M-1}·x^{M-1}
share_x[i] = P_i(x)
```

### 3.2 Combine — Lagrange at x=0

Given a subset `S` of held shares, `|S| ≥ M`; GF(2^8) arithmetic (`a ⊕ b = a - b`);
`combine` MUST reject duplicate x-values and `x = 0`:

```
L_i(0) = Π over j in S, j ≠ i  of  ( x_j / (x_i ⊕ x_j) )
body[i] = Σ over i in S  of  ( L_i(0) · share_{x_i}[byte] )
```

## 4. Share encoding — scheme `"bip39-wordlist"` (only scheme in v1)

### 4.1 Four-section word layout

A share is `W` BIP-39 word indices, `W ≥ 4`. Each section is bit-packed independently — **no byte
straddles a section boundary** — so the layout stays trivially auditable:

```text
word 0          : [ X:5 | M:5 | reserved:1 ]   metadata (per-share)
word 1          : [ nonce:11 ]                  set id, identical across the generation
words 2 .. W-2  : [ Y values ]                  this share's SSS output, per-share
word W-1        : [ CRC-11 ]                     checksum

W = 2 + ceil(body_len · 8 / 11) + 1             (minimum 4; body_len = payload + kind byte + 2-byte tag)
```

**Word 0 — metadata** (11 bits, MSB-first). Bits 10..6 = `X` field, bits 5..1 = `M` field, bit 0 = reserved:

```text
x_field = x - 1                     # x in 1..32 -> field 0..31; x = 0 is unrepresentable
m_field = M - 2                     # M in 2..32 -> field 0..30; M < 2 unrepresentable (2-of-N floor)
word0   = (x_field << 6) | (m_field << 1)       # reserved bit (bit 0) = 0
```

Decode: `x = (word0 >> 6 & 0x1F) + 1`, `M = (word0 >> 1 & 0x1F) + 2`. Reject if the reserved bit ≠ 0 or
the `M` field == 31 (would be `M = 33`). `M ≤ N` is not encoded — enforced at split, implicit at recovery.

**Word 1 — generation nonce** (11 bits). An 11-bit value from the OS CSPRNG drawn **once per split** and
written identically into every share of that generation. It binds one generation, not the secret: re-splitting
the same secret draws an independent nonce and independent polynomials, so shares from two runs carry different
nonces and are correctly refused as non-combinable.

**Y values** (words 2..W-2). This share's SSS output bytes (length `== body_len`), packed MSB-first per byte,
11 bits at a time, final word zero-padded on the right.

**Checksum word** (word W-1) — CRC-11/UMTS (§ 1.2) over the decoded semantic values:

```text
crc_input = [x, M] ‖ nonce_be ‖ Y_bytes         # x, M one byte each (1..32, 2..32); nonce_be = word1 as 2 BE bytes
word_last = CRC-11/UMTS(crc_input)               # 11-bit remainder fills the word
```

A transcription error in word 0 or word 1 changes `crc_input` and is caught; the reserved bit has its own must-be-zero check.

### 4.2 X-coordinate generation

A split issues `N` **distinct** x-coordinates, each in `1..=32`. Each is a raw 5-bit field from the OS
CSPRNG mapped `x = field + 1`; the range `0..31` is a power of two, so the draw is uniform (no modulo
bias, no rejection). Sample without replacement. x is random rather than sequential `1..N` so it leaks
neither the total `N` nor a share's position; x is public (it is in the words), so its randomness is a
privacy property, not confidentiality — the coefficients (§ 3.1) are what must be perfectly random.

### 4.3 Candidate-length disambiguation (decode side)

Different `body_len` values can pack into the same Y-word count; the CRC selects the right length.
With `k = W - 3` Y words:

```text
max_bytes = (k · 11) / 8                          (integer division)
min_bytes = ceil(((k - 1) · 11 + 1) / 8)
```

For each candidate `body_len` from `max_bytes` down to `min_bytes`: unpack the Y words MSB-first into
`body_len` bytes, compute `CRC-11/UMTS([x, M] ‖ nonce_be ‖ body)`, and compare to the stored CRC word.
First match → that length. None → `ShareCorrupt`. For a share decoded in isolation a wrong length passes
with probability ≈ 1/2048; the cross-share `body_len` agreement check (§ 5) is the backstop.

## 5. Recovery from words alone

A decoder MUST accept a bare list of BIP-39 words — no card label, no JSON.

Per share: read `W` words (`W ≥ 4`); reject any ≥ 2048. Word 0 → `x`, `M` (reject reserved bit ≠ 0 or
`M` field == 31). Word 1 → nonce. Word `W-1` → stored CRC. Unpack words `2..W-2` and select `body_len`
by CRC (§ 4.3); no match → `ShareCorrupt`.

Across shares: all MUST agree on nonce, `M`, and `body_len`, else `MismatchedShares`. Require ≥ `M`
shares with **distinct** `x` (fewer → `InsufficientShares`). Lagrange-interpolate at `x = 0` (§ 3.2) →
`body`. Verify the body tag, split off the trailing kind, and validate (§ 2.3), then interpret. The tag
is the whole-secret backstop for *every* kind — if a `1/2048` nonce collision admits a wrong subset, the
recomputed tag won't match and recovery returns `BundleCorrupt` rather than a wrong secret. No
identifier-driven kind search.

## 6. Wire formats

### 6.1 Share text format

```
CHELA-<NONCE>-<x>-<M>-<N>-<W>     (line 1)
word1 word2 word3 … wordW          (line 2; multiple shares: blank line between)
```

`<NONCE>` = 4 uppercase hex of the 11-bit nonce (high bit always 0; case-insensitive parse); `<x>` =
decimal 1..32; `<M>`/`<N>` = threshold/total; `<W>` = word count (parser rejects mismatches); words =
space-separated BIP-39 English words. The header is **advisory** — the words carry `x`, `M`, and the
nonce; the header only adds `N`, which recovery never needs. When present, a parser MUST cross-check
`<NONCE>`/`<x>`/`<M>` against the words and reject a disagreement (`HeaderWordsMismatch`); `<N>` may be
`?` when the total is unknown.

### 6.2 JSON formats

**Single share** (`chela.share.v1`):

```json
{
  "type": "chela.share.v1",
  "card_code": "CHELA-02C9-5-2-3-6",
  "set_id": "02C9",
  "card_number": 5,
  "threshold": 2,
  "total": 3,
  "word_count": 6,
  "scheme": "bip39-wordlist",
  "payload_kind": "text",
  "words": ["cactus", "float", "half", "embark", "scale", "volcano"],
  "backup_name": "Alice's note",
  "description": "Optional free-form note.",
  "shareholder_names": ["Alice", "Bob", "Carol"]
}
```

Required: `type` `card_code` `set_id` `card_number` `threshold` `word_count` `scheme` `words`;
`words.length` MUST equal `word_count`. `set_id` = 4-hex of the nonce. `card_number`/`threshold` (= `x`/`M`)
are advisory, cross-checked against the words on import and rejected on disagreement. `total` is present
only when `N` is known; `payload_kind` (`"bip39"`/`"text"`) only when the kind is known (omitted for a
words-only share). The `words` array is authoritative — an importer derives `x`/`M`/nonce from it, not from
the JSON fields. Optional presentation metadata: `backup_name` `description` `shareholder_names`.

**Bundle** (`chela.shares.v1`):

```json
{
  "type": "chela.shares.v1",
  "shares": [ { /* chela.share.v1 */ }, { /* chela.share.v1 */ }, ... ]
}
```

### 6.3 HTML embedding

```html
<script type="application/json" class="chela-share">
{ /* exact chela.share.v1 JSON object */ }
</script>
```

One block per `<article>`; tools extract via `querySelectorAll('script.chela-share')`.
Encoder MUST escape `<` → `&lt;` inside JSON strings.

## 7. Wire-format normative rules

A conformant implementation MUST:

1. Recover a share from its BIP-39 words alone — no card label, no JSON.
2. Read `x`/`M`/nonce from the words; cross-check any present header/JSON `x`/`M`/nonce and reject a disagreement (`HeaderWordsMismatch`).
3. Reject a share whose reserved bit is set, whose `M` field is 31, or whose CRC-11 verifies for no candidate length (`ShareCorrupt`).
4. Reject a set whose shares disagree on nonce, threshold, or body length (`MismatchedShares`).
5. Reject fewer than `M` shares (`InsufficientShares`) and duplicate or zero `x`-coordinates.
6. Reject a recovered body whose trailing `kind_byte` is unknown or whose payload length doesn't fit (`BundleCorrupt`).
7. Validate `card_code` round-trips identically through JSON.
8. Treat `chela.share.v1` as a hard schema gate; reject any other `type` sentinel.

A conformant implementation MAY: allow extra unknown JSON fields; use
constant-time or table-based GF(2^8) multiplication (wire format is identical).

## 8. Test vectors

### 8.1 GF(2^8)

```
mul(0x57, 0x83) = 0xc1                       (FIPS 197 § 4.1)
inv(0x53) = 0xca                              (AES S-box pre-affine)
mul(x, inv(x)) = 0x01     for every x in 1..=255
```

### 8.2 CRC-11/UMTS

```
crc11_umts("123456789") = 0x061              (reveng catalogue check value)
crc11_umts("")          = 0x000              (init value)
```

Any standard CRC tool set to `width 11, poly 0x307, init 0x000, refin false, refout false, xorout 0x000` reproduces `0x061`.

### 8.3 Full share-encode vector (short text secret)

Secret = text `"hi"` (`68 69`); appended kind `0x0B` (Text) → body `68 69 0B` (3 B). For a single share with
SSS output `Y = 68 69 0B`, `x = 5`, `M = 2`, nonce `0x2C9`:

```
x_field = 4, m_field = 0
word0   = (4 << 6) | (0 << 1)                = 0x100 = 256
word1   = nonce                              = 0x2C9 = 713

Y bits MSB-first : 0110 1000  0110 1001  0000 1011          (24 bits)
group 0          : 0110 1000 011               = 0x343 = 835
group 1          : 0100 1000 010               = 0x242 = 578
group 2          : 11 + 9 zero pad = 1100000000 0 = 0x600 = 1536

crc_input        = [x, M] ‖ nonce_be ‖ Y     = 05 02 02 C9 68 69 0B
CRC-11/UMTS      = 0x7AD = 1965              (last word)

word indices (W = 6) : 256 713 835 578 1536 1965
words                : cactus float half embark scale volcano
```

Decode: `k = 3` Y words → candidate `body_len ∈ {3, 4}` (`max = 33/8 = 4`, `min = ceil(23/8) = 3`).
Length 4 gives CRC `0x708` (no match); length 3 gives `0x7AD` (match) → `body = 68 69 0B` → `"hi"`, kind Text.

### 8.4 SSS round-trip

Exhaustive split → every-M-subset → combine for M ≤ N ≤ 6, plus engine round-trips over text and
passphrase payloads, generation-mixing rejection, and words-alone recovery. Reference tests:
`chela-sss::tests::round_trip_for_every_subset_of_every_m_n_up_to_6` and the round-trip tests in
`chela-engine::tests`.

## 9. Versioning

`v1` as published here is the words-alone format — nonce-bound generations, in-band `x`/`M`, hidden kind,
CRC-11 per-share checksum. Nothing earlier was deployed, so the `chela.share.v1` sentinel is **not** bumped:
this spec *is* v1. Reimplementations targeting v1 MUST NOT silently accept v2-or-later inputs. Decoders MUST
treat unknown `kind_byte` as `BundleCorrupt` and unknown `scheme` as `UnknownScheme`. Future versions bump
the `type` sentinel (e.g. `chela.share.v2`).

## 10. Out of scope

Threat model, secret-zeroize discipline, constant-time correctness, terminal
display sanitisation, paper-backup HTML rendering, the recovery UI.
