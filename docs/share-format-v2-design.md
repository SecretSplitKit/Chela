# chela share format — R0 redesign

Design doc. Date: 2026-06-05. Status: proposed, pre-implementation.

This is the wire-format change that makes a share **recoverable from its words alone** —
no card label, no out-of-band metadata. It rewrites `SPEC.md` §2, §4, and parts of §5/§6.
Nothing is deployed, so this redefines the **v1** format in place — the `chela.share.v1`
sentinel is kept, not bumped. "Redesign," not "migration."

## 1. The requirement (why this exists)

A chela share MUST be reconstructable from the transcribed BIP-39 words by themselves.
In the old format the x-coordinate, threshold `M`, and kind live only on the printed
`CHELA-<ID>-<x>-<M>-<N>-<W>` label and are merely *inputs to a hash* — lose the label and
the words are unrecoverable. That is an availability/funds-loss risk: people transcribe
BIP-39 words the way they always have (just the words), and a backup whose words silently
depend on a label will lose funds.

The redesign moves everything needed for recovery **into the words**, and keeps the kind
**hidden** (split with the secret) so a single share leaks nothing about the payload type.

## 2. Changes at a glance

| Aspect | old | new |
|---|---|---|
| x-coordinate | label only; hash input | **in the words** (word 0), and **random**, not sequential |
| threshold `M` | label only | **in the words** (word 0) |
| kind | `kind_byte`, hash input only, never in body | **appended to the body and split** — hidden until recovery |
| identifier | hash of the secret, on the card label | **11-bit random nonce per generation**, in the words (word 1) + on the card |
| per-share checksum | `SHA-256(…)[0..2]`, 16 bits | **CRC-11**, 11 bits |
| max `N` / `M` | 255 | **32 / 32** |
| kind discovery on recovery | enumerate 11 kinds, SHA-match identifier | read kind from the recovered body — no search |
| SHA-256 in the engine | identifier + per-share checksum | per-share checksum is **gone** (CRC-11); SHA-256 stays only for the 2-byte whole-secret body tag (§3.3) and in `chela-bip39` (mnemonic checksum) |
| recover from words alone | no | **yes** |

## 3. Per-share layout

Four word-aligned sections. Each is bit-packed independently — no byte straddles a section
boundary, which is the point: it stays trivially auditable.

```
word 0          : [ X:5 | M:5 | reserved:1 ]      metadata (per-share)
word 1          : [ nonce:11 ]                     set id, identical across all shares of a generation
words 2 .. W-2  : [ Y values ]                     SSS-split body (secret ‖ kind), per-share
word W-1        : [ CRC-11:11 ]                    checksum
```

`W = 3 + ceil(body_len · 8 / 11)`, minimum 4 words. `body_len = payload_len + 1` (the appended
kind byte).

### 3.1 Word 0 — metadata (11 bits, MSB-first)

| Bits (10 = MSB) | Field | Decode |
|---|---|---|
| 10..6 | `X` field, 0..31 | `x = field + 1` → **1..32** |
| 5..1  | `M` field, 0..30 | `M = field + 2` → **2..32** |
| 0     | reserved | MUST be 0; decoder rejects nonzero |

```
word0 = (x_field << 6) | (m_field << 1) | 0
x_field = x - 1        # x in 1..32 ; x = 0 is unrepresentable, never collides with the secret
m_field = M - 2        # M in 2..32 ; M < 2 is unrepresentable (the 2-of-N floor IS the encoding)
```

`m_field = 31` (would mean `M = 33`) is invalid — reject. `M ≤ N` is not encoded: enforced at
split (`threshold ≤ total`) and implicit at recovery (you cannot combine more shares than you
hold).

### 3.2 Word 1 — generation nonce (11 bits)

An **11-bit random nonce drawn from the OS CSPRNG, once per split**, written identically into
every share of that generation.

Its job is to bind *one generation of shares* together — not to identify the secret. This
distinction is load-bearing: if you split the same secret twice, the two runs draw independent
random polynomials, so a share from run A and a share from run B **cannot be combined** (their
points don't lie on the same polynomials — recovery yields garbage). A hash-of-the-secret would
hand both runs the *same* id and falsely declare them mixable; a fresh random nonce gives each
generation its own id and correctly refuses the mix. The nonce also leaks nothing about the
secret (a hash in the clear would be an offline verifier for low-entropy text payloads).

At recovery the nonce (a) groups a pile of shares, and (b) rejects a foreign share mixed into
the set (different nonce → `MismatchedShares`). Two unrelated generations collide on the nonce
with probability `1/2048`; the whole-secret body tag (§3.3) is the backstop for every kind when
that happens, so a colliding wrong subset fails closed rather than returning a wrong secret.

### 3.3 Y values — SSS-split body (words 2 .. W-2)

The body is the secret payload with the **kind byte and a 2-byte integrity tag appended**, then
Shamir-split. The Y values are this share's SSS output bytes for its `x`, length `== body_len`,
packed MSB-first per byte, 11 bits at a time, final word zero-padded.

```
body = payload ‖ [kind_byte] ‖ tag      tag = SHA-256(payload ‖ kind_byte)[..2]
```

| kind (payload) | payload bytes |
|---|---|
| BIP-39 no passphrase | `entropy` (16/20/24/28/32 B) |
| BIP-39 + passphrase  | `entropy ‖ passphrase_utf8` (passphrase 1..255 B) |
| text | `text_utf8` (1..255 B) |

`kind_byte` reuses the old format's table verbatim (`0x01`..`0x0B`, 11 values; see `SPEC.md`
§2.2). It is now physically appended to the body and split with it — so a single share's words
reveal **nothing** about the payload type, and the kind is read straight from the recovered
body (no enumerate-and-match search).

The **tag** is the first 2 bytes of `SHA-256(payload ‖ kind_byte)`, appended last and split with
the body. It is the only whole-secret integrity binder: the per-share CRC-11 (§3.4) only proves a
share is internally consistent, and the nonce (§3.2) only binds a generation. A wrong subset — a
same-secret nonce collision, or a corruption that still satisfies its own CRC — interpolates to a
garbage body whose recomputed tag won't match, so recovery fails closed (§5) instead of returning
a wrong-but-valid-looking secret. Verified in constant time; residual ≈ 2⁻¹⁶ per wrong subset.

### 3.4 Checksum word (word W-1) — CRC-11

```
crc_input = [x, M] ‖ nonce_be ‖ Y_bytes   # x (1 B), M (1 B), word 1 as 2 B big-endian, then this share's Y bytes
word_last = CRC-11(crc_input)             # 11-bit remainder, occupies the whole word
```

CRC over the decoded semantic values keeps it byte-aligned and auditable; a transcription error
in word 0 or word 1 changes the input and is caught. The reserved bit is covered by its separate
must-be-zero check.

**CRC-11 guarantees detection of any single mistyped word.** A wrong word changes at most 11
contiguous bits — a burst of length ≤ 11 — and an 11-bit CRC detects every burst ≤ 11 bits.
Two-word bursts are caught with probability `1 − 2⁻¹¹`. This is why kind moved into the body:
the full 11 bits go to error detection.

**Polynomial: CRC-11/UMTS** — `poly 0x307` (x¹¹+x⁹+x⁸+x²+x+1), `init 0x000`, `refin/refout =
false`, `xorout 0x000`; catalogue check value `0x061` over ASCII `"123456789"`. Chosen for
hand-auditability: with `init = 0`, no reflection, and no final XOR, it is exactly textbook GF(2)
polynomial long division (append 11 zero bits, divide by the generator, take the remainder).
It is a named/catalogued model, so implementers can cross-check against standard CRC tools.
(CRC-11/FLEXRAY `0x385` is the more widely deployed CRC-11 but uses `init 0x1A`, which is harder
to verify by hand; equal error-detection strength. See §8.)

Reference (bitwise, MSB-first, no table):

```
crc = 0x000
for each bit b of crc_input, most-significant bit first:
    msb = (crc >> 10) & 1
    crc = ((crc << 1) | b) & 0x7FF
    if msb: crc ^= 0x307
# after the last input bit, feed 11 zero bits the same way (or run 11 extra shifts)
```

## 4. X-coordinate generation

- Draw each 5-bit field directly from the OS CSPRNG (`chela_primitives::rng::fill_bytes`).
  The range `0..31` is a power of two, so a raw 5-bit draw is already uniform — **no rejection
  for bias, no modulo skew**.
- **Distinct MUST:** a split MUST issue `N` distinct x-coordinates. The generator samples
  without replacement (dedup-reject for small `N`, or a partial Fisher-Yates over `0..31` as
  `N` approaches 32) and MUST verify distinctness before emitting any share. Recovery
  independently rejects duplicate or zero x (Lagrange requires distinct points).
- `x = field + 1`, so x is always `1..32` and never 0.

Random rather than sequential `1..N`: a sequential x leaks the total count `N` and a share's
position; random x reveals neither. x is **public** (printed in the words) — its randomness is a
*privacy* property, not a confidentiality one. The randomness that must be perfect is the
polynomial coefficients (unchanged).

## 5. Recovery from words alone

Per share:

1. Read `W` words (`W ≥ 4`). Reject any word ≥ 2048.
2. word 0 → `x = bits10..6 + 1`, `M = bits5..1 + 2`; reject if reserved bit ≠ 0 or `M`-field == 31.
3. word 1 → `nonce = bits10..0`.
4. word `W-1` → `crc = bits10..0`.
5. Unpack words `2..W-2` (MSB-first) to body bytes. Candidate `body_len` satisfies
   `ceil(8·body_len/11) == W-3` (a 1–2 value range); for each candidate high→low compute the
   CRC over `[x,M] ‖ nonce_be ‖ Y` and accept the first matching `crc`. None → `ShareCorrupt`.

Across shares:

6. All shares MUST share the same `nonce` → else `MismatchedShares`. Require ≥ `M` shares with
   **distinct** `x`. (Same nonce ⇒ same generation ⇒ shares are guaranteed mutually compatible.)
7. Lagrange-interpolate at `x = 0` (unchanged) → `body`.
8. Split off the trailing 2-byte tag, recompute `SHA-256(rest)[..2]`, and compare in constant
   time; mismatch → `BundleCorrupt`. Only then trust `rest`: split into `payload ‖ kind_byte`
   (kind is the last byte); validate `kind_byte` is in the table and `payload` length fits the kind.
9. Interpret. For BIP-39, re-encode entropy → mnemonic. The body tag is the whole-secret integrity
   backstop for *every* kind, so a `1/2048` nonce collision that lets a wrong/foreign subset reach
   combine fails closed at step 8 rather than returning a wrong secret — text included.

No identifier-driven kind search. A decoder MUST accept a bare word list; the card label and JSON
metadata are advisory.

## 6. What the card label keeps

The card still prints the nonce (as its BIP-39 word, or 3 hex digits) so humans can group
physical cards, and `N` for context. Neither is required to recover — the words carry the nonce
and `M` themselves. The card is convenience, not a dependency.

## 7. Accepted trade-offs (named, not hidden)

- **Generation binding is 11-bit.** Two unrelated generations collide on the nonce with
  probability `1/2048`. A collision plus a mixed subset passes step 6 and reaches combine, but
  the whole-secret body tag (§3.3) catches it at step 8 for every kind — text included — so the
  result is `BundleCorrupt`, not a wrong secret (residual ≈ 2⁻¹⁶). Widening the nonce would cost
  more words; the 2-byte tag closes the hole more cheaply. Note the upside: because the id is
  per-generation, even re-splitting the *same* secret is correctly refused — which a
  hash-of-secret id would have wrongly accepted.
- **Max 32 shares / threshold 32**, down from 255 — the cost of fitting `x` and `M` into one
  11-bit word. Far beyond any realistic M-of-N seed backup.
- **Size:** +1 word (nonce), plus the appended kind byte and 2-byte tag (3 body bytes ≈ +2 to +3
  words). A 12-word seed share goes 14 → 17 words; a 24-word seed share 26 → 29. Bought for
  words-alone recovery, a hidden kind, in-band generation binding, and a whole-secret integrity
  tag that makes recovery fail closed.

Three earlier worries are now **gone**: kind no longer leaks per share (it's split); CRC-11
catches every single-word error (no "1/256 on text"); and the id is a random nonce, so it leaks
no fingerprint of the secret. The body tag adds whole-secret integrity on top, so no kind relies
on an external checksum to avoid a silent wrong-secret return.

## 8. Implementation notes

- **Browser RNG.** Verify the wasm host shim backs `chela.random_bytes` with
  `crypto.getRandomValues` (not `Math.random`) — in scope for R0, out of scope for the format.

### Resolved decisions

- **Versioning:** no sentinel bump; the `chela.share.v1` format is redefined in place.
- **Checksum:** CRC-11/UMTS (`0x307`, `init 0`, non-reflected) — confirmed.
- **Kind:** appended to the body and split (hidden until recovery).
- **Identifier:** an 11-bit random nonce per generation, in word 1 — binds a generation, not a
  secret. SHA-256 stays in the engine only for the whole-secret body tag (§3.3).
- **Body tag:** 2-byte `SHA-256(payload ‖ kind_byte)[..2]`, split with the body — the
  whole-secret integrity backstop so recovery fails closed instead of returning a wrong secret.
- **Distinct x:** explicit MUST at generation (§4).
