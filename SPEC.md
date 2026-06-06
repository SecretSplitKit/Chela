# chela format specification (v1)

This document defines the chela share format completely enough to write an
independent, compatible implementation — and to *understand* it. Every
construction step is explained three ways:

- **Plain terms** — what it does and why, no math required.
- **The math** — the theory, assuming only a vague memory of high-school
  polynomials.
- **In bits & bytes** — how that theory becomes the actual bits on the card.

The format is version-pinned by the sentinel `chela.share.v1`.

---

## 1. What chela is

chela takes one **secret** — a BIP-39 wallet seed phrase, a passphrase, or any
short text — and splits it into **N shares** such that any **M** of them
reconstruct the secret, while **M − 1 reveal nothing at all** (not "less," not
"weaker" — mathematically nothing). This is *Shamir's Secret Sharing* (SSS).

What makes chela specific:

- **Each share is just a list of ordinary BIP-39 words.** You write the words on
  a card the same way you'd write a seed phrase.
- **A share recovers from its words alone.** Everything recovery needs — the
  share's coordinate, the threshold, a batch identifier, and the payload type —
  is encoded *in the words*. The printed card label and any JSON are convenience,
  never required. (This matters because the intended use is inheritance: the
  person recovering may be a family member or executor who only has the cards.)
- **A single share leaks nothing about the secret, including its *type*.** You
  can't tell from one card whether it's a 24-word seed or a short password.

## 2. Acronyms and terms

| Acronym | Meaning |
|---|---|
| SSS | Shamir's Secret Sharing |
| GF(2⁸) | Galois Field of 256 elements — exact arithmetic on single bytes (§ 4.2) |
| AES | Advanced Encryption Standard — source of the GF(2⁸) polynomial |
| CRC | Cyclic Redundancy Check — an error-detecting checksum |
| CRC-11/UMTS | the specific 11-bit CRC chela uses (catalogued under the UMTS telecom standard) |
| BIP-39 | Bitcoin Improvement Proposal 39 — the standard 2048-word mnemonic list |
| CSPRNG | Cryptographically Secure Pseudo-Random Number Generator |
| RNG | Random Number Generator |
| MSB / LSB | Most / Least Significant Bit; "MSB-first" = highest-value bit first |
| XOR | bitwise exclusive-OR (`^`) |
| UTF-8 | the standard 8-bit Unicode text encoding |
| KAT | Known-Answer Test (a fixed input→output check vector) |
| FIPS | (US) Federal Information Processing Standards |

| Term | Meaning |
|---|---|
| secret | the protected data: a BIP-39 mnemonic, optional passphrase, or text |
| payload | the raw secret bytes (entropy, or `entropy ‖ passphrase`, or text) |
| body | what actually gets split: `payload ‖ kind_byte` (§ 5.3) |
| kind byte | one byte naming the payload type; also the body terminator (§ 5.4) |
| share (card) | one split piece, rendered as a list of BIP-39 words |
| word | one BIP-39 word = an 11-bit number, 0–2047 |
| `M` (threshold) | how many shares are needed to recover (2–32) |
| `N` (total) | how many shares were produced (≤ 32) |
| `x` | a share's coordinate / identifying number (1–32) |
| nonce | an 11-bit random "batch id" shared by every card of one split (§ 5.2) |
| Y values | a share's SSS output bytes — one per body byte (§ 5.3) |

## 3. Constants (quick reference)

| Constant | Value |
|---|---|
| GF(2⁸) reduction polynomial | `0x11b` (x⁸ + x⁴ + x³ + x + 1, the AES/Rijndael polynomial) |
| Threshold `M` range | 2 – 32 |
| Total `N` / coordinate `x` range | 1 – 32 (`x = 0` is reserved for the secret itself) |
| Generation nonce | 11-bit random, one per split, carried in word 1 |
| Per-share checksum | CRC-11/UMTS, polynomial `0x307`, in the last word |
| `x` field encoding | 5-bit field `0..31`, stored as `x − 1` |
| `M` field encoding | 5-bit field `0..30`, stored as `M − 2` |
| Max body length | 288 bytes (32 entropy + 255 passphrase + 1 kind byte) |
| BIP-39 wordlist | English, 2048 entries, 11 bits per word |
| BIP-39 wordlist SHA-256 | `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` |
| Version sentinels | `chela.share.v1` (single), `chela.shares.v1` (bundle) |

---

## 4. Shamir's Secret Sharing, the chela way

### 4.1 The core idea

**Plain terms.** Hide the secret as the starting point of a curve. Each share is
one point *on* that curve. With enough points you can redraw the exact curve and
read off where it started — that starting point is the secret. With too few
points, infinitely many curves fit, so the starting point could be anything: the
shares you hold tell you nothing.

**The math.** Pick a polynomial `P(x)` of degree `M − 1` whose constant term is
the secret, i.e. `P(0) = secret`. The other coefficients are random. A share is a
point `(x, P(x))` for some `x ≠ 0`. A degree-`(M − 1)` polynomial is uniquely
determined by any `M` of its points (Lagrange interpolation), so any `M` shares
recover `P` and hence `P(0)`. With only `M − 1` points, for *every* candidate
secret there is exactly one polynomial of that degree passing through your points
and hitting that secret at `x = 0` — all secrets remain equally possible. That is
the information-theoretic security guarantee.

**In bits & bytes.** A secret is many bytes, so chela runs one independent
polynomial *per byte*. Byte `i` of the body is the constant term `P_i(0)`; the
`M − 1` higher coefficients of `P_i` are fresh random bytes from the CSPRNG. A
share for coordinate `x` is the byte vector `[P_0(x), P_1(x), …]` — the same
length as the body. All arithmetic is in GF(2⁸) (§ 4.2) so every intermediate
value is exactly one byte.

```text
P_i(x) = body[i] ⊕ r_{i,1}·x ⊕ r_{i,2}·x² ⊕ … ⊕ r_{i,M-1}·x^{M-1}      (GF(2⁸))
share_x[i] = P_i(x)
```

### 4.2 The arithmetic: GF(2⁸)

**Plain terms.** Ordinary byte math overflows — `200 + 100` doesn't fit in a
byte. GF(2⁸) is a self-contained way to add and multiply bytes where the answer
is *always* exactly one byte, with no rounding and no overflow, so the
polynomials above behave perfectly. It's the same arithmetic AES uses.

**The math.** Treat each byte as a degree-≤7 polynomial over the field with two
elements (coefficients 0/1). Addition is XOR. Multiplication is polynomial
multiplication reduced modulo the fixed irreducible polynomial
`x⁸ + x⁴ + x³ + x + 1` (`0x11b`). Every non-zero element has a multiplicative
inverse, which is what lets recovery "divide."

**In bits & bytes.**

```text
add(a, b) = a XOR b
mul(a, b) = Σ over i=0..7  ((b >> i) & 1) ? rot(a, i) : 0
            rot(a, 0) = a
            rot(a, i) = let v = rot(a, i-1); (v << 1) XOR (msb(v) ? 0x1b : 0)
inv(0)    = 0      (convention; combine never calls inv(0))
inv(x)    = x^254  for x ≠ 0   (Fermat's little theorem in GF(2⁸))
```

KAT: `mul(0x57, 0x83) = 0xc1` (FIPS 197 § 4.1). A 512-byte log/antilog table gives
identical results; the wire format is unchanged either way.

### 4.3 The threshold `M`

**Plain terms.** `M` is how many cards you need to recover. Hold fewer and you
have nothing.

**The math.** `M` is the polynomial degree plus one — a degree-`(M − 1)` curve
needs `M` points to pin down. chela requires `M ≥ 2`: a "1-of-N" split is just
plain copies and provides no secret-sharing security, so it is rejected. The cap
is `M ≤ 32` (§ 4.4).

**In bits & bytes.** `M` is encoded in word 0 (§ 5.1) and re-derived at recovery;
it is read from the words, never assumed.

### 4.4 Picking each share's coordinate `x`

**Plain terms.** Every card gets its own number, `x`. It's chosen at random from
1–32 (not 1, 2, 3, …). Random numbering means a stray card doesn't reveal how
many cards exist or where it sits in the set.

**The math.** `x` is the point at which this share evaluates the polynomials.
`x = 0` is reserved (that's the secret), so coordinates live in `1..=32`. A split
draws `N` *distinct* coordinates; duplicates or `x = 0` are rejected, because
Lagrange interpolation needs distinct points and `x = 0` would hand out the
secret. `x` is **public** — it is printed in the words — so its randomness is a
*privacy* property, not confidentiality; the *coefficients* (§ 4.1) are what must
be perfectly random.

**In bits & bytes.** Each `x` is `(rngbyte & 0x1F) + 1`: the low 5 bits of a fresh
CSPRNG byte give a uniform field `0..31` (a power-of-two range, so no modulo
bias), mapped to `1..=32`. Draw without replacement (re-draw on collision). Cap:
32 shares.

---

## 5. The share word format

A share is `W` BIP-39 word indices (`W ≥ 4`). Each word is an 11-bit value (0–2047)
— one entry in the 2048-word English BIP-39 list (verify the list against the
SHA-256 in § 3). The words split into four sections, each packed independently so
**no byte ever straddles a section boundary** — which keeps the layout auditable
by hand:

```text
word 0          : [ X:5 | M:5 | reserved:1 ]   metadata for this share
word 1          : [ nonce:11 ]                  generation id (same on every card of the split)
words 2 .. W-2  : [ Y values ]                  this share's SSS output bytes
word W-1        : [ CRC-11 ]                     transcription checksum

W = 2 + ceil(body_len · 8 / 11) + 1            (minimum 4; body_len = payload + 1 kind byte)
```

### 5.1 Word 0 — coordinate and threshold (`x`, `M`)

**Plain terms.** The first word says *which* share this is (its number `x`) and
*how many* are needed to recover (`M`). Both are packed into one word.

**The math.** These are the two values recovery can't run without: `x` (which
point on the curves this card holds) and `M` (how many cards are required). They
are stored as small offsets so the encoding can't represent the illegal values —
`x = 0` and `M < 2` are literally unrepresentable.

**In bits & bytes.** 11 bits, MSB-first: bits 10..6 are the `x` field, bits 5..1
the `M` field, bit 0 reserved.

```text
x_field = x − 1                 # x in 1..32  → field 0..31  (x = 0 cannot be encoded)
m_field = M − 2                 # M in 2..32  → field 0..30  (M < 2 cannot be encoded)
word0   = (x_field << 6) | (m_field << 1)        # reserved bit (bit 0) = 0

decode: x = ((word0 >> 6) & 0x1F) + 1
        M = ((word0 >> 1) & 0x1F) + 2
```

Reject the share if the reserved bit ≠ 0, or if the `M` field == 31 (that would
mean `M = 33`). `M ≤ N` is *not* encoded — it's enforced at split time and is
implicit at recovery (you can't combine more cards than you physically hold).

### 5.2 Word 1 — the generation identifier (nonce)

**Plain terms.** A random "batch number" stamped identically on every card of a
single split. Its only job is grouping: if you try to combine cards that don't
share it, recovery refuses. It is **not** derived from the secret and reveals
nothing about it.

**The math.** It binds *one generation* of shares, not the secret. If you split
the same secret twice, the two runs draw independent random polynomials, so a
card from run A and a card from run B sit on different curves and can't be
combined — and they carry different nonces, so the mismatch is caught up front. A
hash *of the secret* would wrongly mark both runs as combinable (and would leak a
fingerprint of the secret); a fresh random nonce does neither. Two unrelated
splits collide on the same nonce with probability 1/2048; that case is caught
downstream (§ 6) and never yields a wrong secret.

**In bits & bytes.** 11 random bits from the CSPRNG, drawn once per split and
written verbatim into word 1 of every share.

### 5.3 Words 2 … W−2 — the body (the split secret)

**Plain terms.** These words carry this card's share of the actual secret. The
secret bytes are turned into Shamir shares (§ 4.1) and then packed into words.

**The math.** The **body** is `payload ‖ kind_byte` (the kind byte is § 5.4). SSS
(§ 4.1) turns the body into this share's `Y` values: one output byte per body
byte, namely `P_i(x)` for this card's `x`. So the `Y` vector is exactly as long
as the body; it looks random and, on its own, reveals nothing.

| Payload (by kind) | Payload bytes |
|---|---|
| BIP-39, no passphrase | `entropy` (16/20/24/28/32 bytes) |
| BIP-39, with passphrase | `entropy ‖ passphrase_utf8` (passphrase 1–255 bytes) |
| Text | `text_utf8` (1–255 bytes) |

**In bits & bytes.** Pack the `Y` bytes MSB-first, 11 bits at a time, into words.
Byte boundaries (8 bits) and word boundaries (11 bits) don't line up, so the
final word is zero-padded on the right to fill its 11 bits. With `len` = number
of `Y` bytes there are `ceil(len · 8 / 11)` body words.

```text
bit b of the Y stream  →  word (b / 11), position (10 − b mod 11)   # MSB-first
trailing bits of the last word are 0
```

### 5.4 The kind byte — payload type *and* terminator

**Plain terms.** The body's final byte names what the secret is (which size of
seed, with/without passphrase, or text). It pulls double duty as an **end-marker**:
because it is never zero and the packing pads with zeros, recovery can spot where
the real data stops.

**The math.** The byte is a small non-zero sentinel (`0x01`–`0x0B`). Padding is
always `0x00`. So after the secret is reconstructed, the last non-zero byte *is*
the terminator — this is what lets recovery resolve the exact byte length despite
the byte/word misalignment (§ 5.5, § 6).

**In bits & bytes.** One byte, appended to the payload to form the body. Recovery
reads it from `body[len − 1]`. Any value outside the table is `BundleCorrupt`.

| `kind_byte` | Meaning |
|---|---|
| `0x01`–`0x05` | BIP-39 12 / 15 / 18 / 21 / 24 words (16/20/24/28/32 B entropy), no passphrase |
| `0x06`–`0x0A` | BIP-39 12 / 15 / 18 / 21 / 24 words, with passphrase |
| `0x0B` | Text |

### 5.5 The last word — CRC checksum

**Plain terms.** A check value, like a checksum digit, that catches a mistyped or
swapped word so you don't recover garbage silently.

**The math.** CRC-11/UMTS is the remainder of dividing the share's bytes
(as a big binary polynomial) by a fixed 11-bit generator polynomial `0x307`, in
GF(2). An 11-bit CRC is guaranteed to detect any error confined to a single word
(one word changes at most 11 contiguous bits — a burst of length ≤ 11 — and an
11-bit CRC catches every burst ≤ 11 bits).

**In bits & bytes.** The CRC covers the share's *semantic* values — `x`, `M`, the
nonce, and the `Y` bytes — so a mistyped word 0 or word 1 is also caught. Poly
`0x307` (x¹¹+x⁹+x⁸+x²+x+1, implicit x¹¹), `init = 0`, no input/output reflection,
`xorout = 0`; catalogue check `0x061` over ASCII `"123456789"`. With `init 0`, no
reflection and no final XOR it is plain GF(2) long division — verifiable by hand
and against any standard CRC tool.

```text
crc_input = [x, M] ‖ nonce_be ‖ Y_bytes      # x, M one byte each; nonce_be = word 1 as 2 big-endian bytes
word_last = CRC-11/UMTS(crc_input)            # the 11-bit remainder fills the word

crc = 0x000
for each input byte:
    crc ^= byte << 3                 # align the byte's MSB with bit 10 of the 11-bit register
    repeat 8 times:
        msb = crc & 0x400
        crc = (crc << 1) & 0x7FF
        if msb: crc ^= 0x307
```

### 5.6 Word count and the byte↔word ambiguity

**Plain terms.** Because bytes (8 bits) and words (11 bits) don't divide evenly,
two slightly different secret lengths can produce the *same* number of words. The
word count alone doesn't tell you the exact byte length — recovery resolves it
(§ 6) using the kind-byte terminator.

**The math.** The byte and word grids realign only every 88 bits (= 11 bytes = 8
words), so for a given Y-word count `k` the body is one of at most two consecutive
byte lengths.

**In bits & bytes.** With `k = W − 3` body words:

```text
max_bytes = (k · 11) / 8                       (integer division)
min_bytes = ceil(((k − 1) · 11 + 1) / 8)
```

A share *validated in isolation* (no set to combine) is merely checked, not
length-pinned: unpack at each candidate length and accept the first whose
`CRC-11/UMTS([x, M] ‖ nonce_be ‖ body)` matches the stored CRC word; none →
`ShareCorrupt`. The authoritative length comes from the set at recovery (§ 6).

---

## 6. Recovery (from words alone)

**Plain terms.** Gather `M` cards, read off their words, and the tool redraws the
curves and reads back the secret. No card label or JSON is needed — only the
words.

**The math.** Reconstruct each body byte by Lagrange interpolation at `x = 0`:

```text
L_i(0) = Π over j ≠ i  ( x_j / (x_i ⊕ x_j) )        (GF(2⁸); ⊕ is also subtraction)
body[i] = Σ over i in the subset  ( L_i(0) · share_{x_i}[i] )
```

**In bits & bytes.** A decoder MUST accept a bare list of BIP-39 words. Algorithm:

1. **Per share:** read `W` words (`W ≥ 4`); reject any ≥ 2048. Word 0 → `x`, `M`
   (reject reserved bit ≠ 0, or `M` field == 31). Word 1 → nonce. Word `W−1` →
   stored CRC. Words `2..W−2` are the packed `Y` bytes.
2. **Agree:** all shares MUST share the same nonce, `M`, and Y-word count `k`,
   else `MismatchedShares`. Require ≥ `M` shares with **distinct** `x` (fewer →
   `InsufficientShares`; duplicate or `x = 0` → rejected).
3. **Reconstruct at the maximum length:** unpack every share's `Y` to `max_bytes`
   (§ 5.6) and Lagrange-interpolate at `x = 0` → `body` of `max_bytes`.
4. **Find the true length (terminator):** the kind byte is never `0x00`, and any
   over-read byte is zero padding — so if `max_bytes > min_bytes` and
   `body[max_bytes − 1] == 0x00`, the true length is `min_bytes` (drop the padding
   byte); otherwise it is `max_bytes`. This resolves § 5.6 deterministically for
   the whole set.
5. **Verify each share:** recompute `CRC-11/UMTS([x, M] ‖ nonce_be ‖ Y[..len])`
   for every share against its stored CRC; a mismatch (a mistyped word) →
   `ShareCorrupt`.
6. **Interpret:** kind = `body[len − 1]`, payload = `body[..len − 1]`. Decode the
   kind via § 5.4; reject (`BundleCorrupt`) unless the kind is known and the
   payload length fits its kind (no-pass BIP-39 = exactly `entropy_bytes`;
   with-pass = `entropy_bytes + 1 .. entropy_bytes + 255`; text = `1..=255`). For
   BIP-39, re-encode the entropy to a mnemonic (its built-in checksum is a final
   sanity check).

The nonce guards against mixing splits. In the ≈ 1/2048 case where two unrelated
generations collide on the nonce with matching `M` and length, the interpolated
body is garbage and is rejected at step 6 (its trailing byte is almost never a
valid kind) — recovery **never silently returns a wrong secret**.

---

## 7. Wire formats

The words are authoritative. The text/JSON/HTML carriers below are for transport
and human convenience; an importer derives `x`, `M`, and the nonce from the words,
and cross-checks any carrier metadata against them.

### 7.1 Share text format

```text
CHELA-<NONCE>-<x>-<M>-<N>-<W>      (line 1)
word1 word2 word3 … wordW           (line 2; blank line between multiple shares)
```

`<NONCE>` = 4 uppercase hex of the 11-bit nonce (high bit always 0; parsed
case-insensitively); `<x>` = decimal 1–32; `<M>`/`<N>` = threshold/total; `<W>` =
word count. The header is **advisory** — the words carry `x`, `M`, and the nonce;
the header only adds `N`, which recovery never needs. A parser that sees a header
MUST cross-check `<NONCE>`/`<x>`/`<M>` against the words and reject a disagreement
(`HeaderWordsMismatch`); `<N>` may be `?` when the total is unknown.

### 7.2 JSON formats

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

Required: `type`, `card_code`, `set_id`, `card_number`, `threshold`, `word_count`,
`scheme`, `words`; `words.length` MUST equal `word_count`. `set_id` is the 4-hex
nonce; `card_number`/`threshold` (= `x`/`M`) are advisory and cross-checked
against the words on import. `total` appears only when `N` is known;
`payload_kind` (`"bip39"`/`"text"`) only when the kind is known (omitted for a
words-only share). The `words` array is authoritative. Optional presentation
fields: `backup_name`, `description`, `shareholder_names`.

**Bundle** (`chela.shares.v1`):

```json
{ "type": "chela.shares.v1", "shares": [ { /* chela.share.v1 */ }, … ] }
```

### 7.3 HTML embedding

```html
<script type="application/json" class="chela-share">
{ /* exact chela.share.v1 JSON object */ }
</script>
```

One block per `<article>`; tools extract via `querySelectorAll('script.chela-share')`.
The encoder MUST escape `<` → `&lt;` inside JSON strings.

---

## 8. Normative rules

A conformant implementation MUST:

1. Recover a share from its BIP-39 words alone — no card label, no JSON.
2. Read `x`/`M`/nonce from the words; cross-check any present header/JSON
   `x`/`M`/nonce and reject a disagreement (`HeaderWordsMismatch`).
3. Reject a share whose reserved bit is set, whose `M` field is 31, or whose
   CRC-11 matches for no candidate length (`ShareCorrupt`).
4. Reject a set whose shares disagree on nonce, threshold, or body length
   (`MismatchedShares`).
5. Reject fewer than `M` shares (`InsufficientShares`) and duplicate or zero `x`.
6. Reject a recovered body whose trailing kind byte is unknown, or whose payload
   length doesn't fit the kind (`BundleCorrupt`).
7. Treat `chela.share.v1` as a hard schema gate; reject any other `type` sentinel.

A conformant implementation MAY: accept extra unknown JSON fields; use constant-
time or table-based GF(2⁸) multiplication (the wire format is identical).

---

## 9. Test vectors

### 9.1 GF(2⁸)

```text
mul(0x57, 0x83) = 0xc1                       (FIPS 197 § 4.1)
inv(0x53)       = 0xca                        (AES S-box, pre-affine)
mul(x, inv(x))  = 0x01   for every x in 1..=255
```

### 9.2 CRC-11/UMTS

```text
crc11_umts("123456789") = 0x061              (reveng catalogue check value)
crc11_umts("")          = 0x000              (the init value)
```

Any CRC tool set to `width 11, poly 0x307, init 0x000, refin false, refout false,
xorout 0x000` reproduces `0x061`.

### 9.3 Full share-encode vector (short text secret)

Secret = text `"hi"` (`68 69`); kind `0x0B` (Text) → body `68 69 0B` (3 bytes). To
isolate the packing and CRC, take a share whose SSS output happens to be
`Y = 68 69 0B`, with `x = 5`, `M = 2`, nonce `0x2C9`:

```text
x_field = 4, m_field = 0
word0   = (4 << 6) | (0 << 1)                = 0x100 = 256
word1   = nonce                              = 0x2C9 = 713

Y bits (MSB-first) : 0110 1000  0110 1001  0000 1011         (24 bits)
word 2             : 0110 1000 011               = 0x343 = 835
word 3             : 0 1001 0000 10              = 0x242 = 578
word 4             : 11 + nine 0-pad bits        = 0x600 = 1536

crc_input          = [x, M] ‖ nonce_be ‖ Y      = 05 02 02 C9 68 69 0B
CRC-11/UMTS        = 0x7AD = 1965              (the last word)

words (W = 6)      : 256 713 835 578 1536 1965
                   : cactus float half embark scale volcano
```

Decode: `k = 3` body words → candidates `{3, 4}` (`max = 33/8 = 4`,
`min = ceil(23/8) = 3`). Unpacking to 4 bytes yields `68 69 0B 00`; the trailing
`0x00` is padding and `0x0B` is the non-zero terminator, so the true length is 3 →
`body = 68 69 0B` → `"hi"`, kind Text.

### 9.4 SSS round-trip

Exhaustive split → every-`M`-subset → combine for `M ≤ N ≤ 6`, plus engine
round-trips over text and passphrase payloads, generation-mixing rejection, and
words-alone recovery. Reference tests:
`chela-sss::tests::round_trip_for_every_subset_of_every_m_n_up_to_6` and the
round-trip tests in `chela-engine::tests`.

---

## 10. Versioning

`v1` as published here *is* the words-alone format — random nonce per generation,
`x`/`M` in the words, hidden kind byte, CRC-11 per-share checksum. Nothing earlier
was deployed, so the `chela.share.v1` sentinel is **not** bumped. Reimplementations
targeting v1 MUST NOT silently accept v2-or-later inputs. Decoders MUST treat an
unknown `kind_byte` as `BundleCorrupt` and an unknown `scheme` as `UnknownScheme`.
Future versions bump the `type` sentinel (e.g. `chela.share.v2`).

## 11. Out of scope

Threat model, secret-zeroization discipline, constant-time correctness, terminal
display sanitisation, paper-backup HTML rendering, and the recovery UI are
implementation concerns documented elsewhere, not part of the wire format.
