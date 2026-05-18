# Manual recovery — by hand, on paper

This is the guide for recovering a chela secret from the paper cards **with
nothing but pen, paper, and patience**. No computer, no calculator beyond
basic arithmetic, no internet. The point is to give a future you (or your
descendants, or you-in-a-bunker) a recovery path that survives even if
every chela tool, mirror, archive, and copy of the code is gone.

It's a long doc. Set aside a day. The actual cryptographic math is small —
a few hundred bit-flips, additions, and table lookups — but every step is
spelled out from the ground up so a careful reader who's never seen
binary numbers before can still get through it.

This doc teaches everything you need from scratch. You can skip the
"pre-flight" section if you already know binary, hex, and XOR.

---

# What you need

| Item                                                        | Why                                                  |
|-------------------------------------------------------------|------------------------------------------------------|
| At least `M` of your `N` paper cards                         | The input. `M` is the "Required to recover" number printed on each card. |
| A **printed copy of the BIP-39 English wordlist**            | Look up word → number and number → word              |
| The **GF(2⁸) inverse table** in the appendix of this doc     | Division step (Step 5)                               |
| Plain paper, pen, eraser                                    | For all the working-out                              |
| Time                                                        | First-time, a careful walkthrough takes ~4 hours     |

The BIP-39 wordlist is a list of 2048 short English words. It's the same
list every BIP-39 wallet in the world uses. Print or write down a copy
**before** you need it; without the list, you can't decode the words on
the cards. (You can get it from anywhere — the canonical source is
<https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt>.)

---

# Two things this guide deliberately skips

chela's recovery has two optional verification steps that both require
SHA-256 (a hash function). SHA-256 by hand is a day's work per hash,
so this guide skips them:

- **The per-card checksum** (last 2 bytes of each card's bit-string).
  Catches typos. By hand: just re-read every word carefully — if you mis-
  copy a word, the recovered body will be garbage, but the math itself
  still runs.
- **The identifier check** (the 4-hex-character set ID). Lets the tool
  auto-detect what kind of payload the cards hold (mnemonic vs text). By
  hand: **you need to already know** what kind of secret you stored.
  Usually obvious from context.

Neither step is needed for the actual mathematical recovery — they're
sanity checks. Skip both and the procedure still works.

---

# Pre-flight: things you need to know first

Skip these if you already know binary, hex, bytes, and XOR.

## Numbers in three forms

We humans usually write numbers in **decimal** (base 10): each digit is
one of 0–9. Computers use **binary** (base 2): each digit is 0 or 1.
There's a third form, **hexadecimal** (or "hex", base 16): each digit is
one of 0–9 or A, B, C, D, E, F (A means 10, B means 11, …, F means 15).

Hex is convenient because every hex digit equals exactly four binary
digits. So if you know the table for 0–15, you can flip between hex and
binary trivially.

Here's the table you have to memorise. Just the first column ↔ third
column matters; decimal is shown for reference.

| Decimal | Hex  | Binary |
|---------|------|--------|
| 0       | 0    | 0000   |
| 1       | 1    | 0001   |
| 2       | 2    | 0010   |
| 3       | 3    | 0011   |
| 4       | 4    | 0100   |
| 5       | 5    | 0101   |
| 6       | 6    | 0110   |
| 7       | 7    | 0111   |
| 8       | 8    | 1000   |
| 9       | 9    | 1001   |
| 10      | A    | 1010   |
| 11      | B    | 1011   |
| 12      | C    | 1100   |
| 13      | D    | 1101   |
| 14      | E    | 1110   |
| 15      | F    | 1111   |

Throughout this doc, when you see `0x` in front of something it means
"this is a hex number". So `0x68` = the hex number "68" = `6 × 16 + 8`
= 104 in decimal.

### The hex ↔ binary shortcut

To turn **2 hex digits into 8 binary digits**: write the left digit's
4-bit pattern from the table, then the right digit's 4-bit pattern.

> `0x68` → `6` is `0110`, `8` is `1000`, side by side: **`0110 1000`**

To turn **8 binary digits into 2 hex digits**: take 4 bits at a time,
look up each group.

> `0010 1010` → `0010` is **2**, `1010` is **A**, joined: **`0x2A`**

A space between every 4 binary digits makes this easier to do by eye —
get in the habit of writing them like that.

## A byte is 8 bits

A **bit** is one binary digit. A **byte** is 8 bits in a row. A byte can
hold any value from 0 to 255 (or 0x00 to 0xFF in hex). The text character
`h` (the letter "h") is the byte 0x68. The character `i` is 0x69. The
word `"hi"` is two bytes: `0x68 0x69`.

(You don't have to memorise every letter's byte value — there's a table in
the appendix for ASCII text. You only need it at the very end if your
secret was text.)

## XOR — the only "math" you'll do on bytes

**XOR** (written `⊕`, said "ex-or") is the most important operation in
this guide. It takes two bits and produces one bit:

| a | b | a ⊕ b |
|---|---|-------|
| 0 | 0 |   0   |
| 0 | 1 |   1   |
| 1 | 0 |   1   |
| 1 | 1 |   0   |

In words: **"if the two bits are the same, the answer is 0; if they're
different, the answer is 1."**

To XOR two bytes, line them up and XOR each pair of bits in turn.
**Always work bit by bit, top to bottom or left to right — never try to
do it in your head**.

> ```
>    0x68 = 0110 1000
>    0x42 = 0100 0010
>    ────────────────
>    XOR  = 0010 1010 = 0x2A
> ```
>
> Checking column by column:
> - column 1: 0 and 0 are the same → **0**
> - column 2: 1 and 1 are the same → **0**
> - column 3: 1 and 0 are different → **1**
> - column 4: 0 and 0 are the same → **0**
> - column 5: 1 and 0 are different → **1**
> - column 6: 0 and 0 are the same → **0**
> - column 7: 0 and 1 are different → **1**
> - column 8: 0 and 0 are the same → **0**
>
> Joined: `00101010` → `0010 1010` → `0x2A`. ✓

Two properties to remember:

- **XOR is its own undo.** `(a ⊕ b) ⊕ b = a`. This is why chela can hide
  secrets inside seemingly random bytes and pull them back out.
- **In this guide, addition and subtraction of bytes are both XOR.** When
  you see `+` or `−` between bytes, do XOR.

That's all the maths-prerequisite. Take a break here if it's a lot.

---

# What's on a chela card

Pick up one of your cards and look at it. Here are all the parts that
matter for recovery (everything else on the card is human-readable
labelling — feel free to ignore the description, the "share holders"
list, the brand stamp, etc.):

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   ALICE'S ETHEREUM WALLET                               │ ← title (ignore)
│                                                         │
│   Recovery set:      9651                               │ ← (1) set ID
│   Required:          2 of 3                             │ ← (2) M of N
│   Card code:         CHELA-9651-1-2-3-3                 │ ← (3) full code
│                                                         │
│   Your share words:                                     │
│     1.  clean                                           │
│     2.  verify                                          │ ← (4) the words
│     3.  client                                          │
│                                                         │
│   …recovery instructions…                               │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**(1) Set ID** — four hex characters. Every card from the same split has
the same set ID. If the cards you have don't all show the same set ID,
they're not all from the same split and recovery won't work.

**(2) Required / total** — the threshold "M" (the number you need to
recover; the LEFT number in "2 of 3") and total "N" (the right number).
You need at least M cards to recover. Extras don't hurt; missing cards
mean no recovery, ever.

**(3) Card code** — the whole machine-readable header in one line.
`CHELA-9651-1-2-3-3` decomposes as:

- `9651` — set ID (same as item 1, just repeated here so the format
  parses on its own)
- `1` — **this card's number** (called `x` in the math)
- `2` — threshold M (same as the left of item 2)
- `3` — total N (same as the right of item 2)
- `3` — number of words on this card

**(4) The words** — the actual data. Every card has the same number of
words. Each word stands in for an 11-bit number from the BIP-39 wordlist.

---

# The recovery in 6 steps — overview

Here's the whole shape of what we're going to do. Read this through once
before starting Step 1; it's a map.

1. **Read each card** and write down its parts.
2. **Look up each word** in the BIP-39 wordlist to get a number.
3. **Convert each number to 11 bits** of binary and stitch them together.
4. **Cut the bits into bytes** and identify which bytes are "share bytes".
5. **Lagrange-combine the share bytes** from the M cards you have. This
   is the only step with non-trivial maths; the appendix has the lookup
   table that makes it manageable.
6. **Read out the body bytes** — for text, just look up each byte in the
   ASCII table; for BIP-39, see the BIP-39-specific guidance at the end.

We'll do all of it with a complete worked example: a **2-of-3 split of
the text `"hi"`**. The cards from that split are:

```
CHELA-9651-1-2-3-3
clean verify client

CHELA-9651-2-2-3-3
ugly disease hub

CHELA-9651-3-2-3-3
purchase lottery soon
```

We'll recover using cards 1 and 2. (Card 3 is shown so you can practise
on it separately if you want.)

---

# Step 1 — Read each card

For each card you have, write down (on a fresh sheet of paper):

- Set ID (4 hex characters)
- This card's number, `x`
- Threshold, `M`
- Total, `N`
- Word count
- The words, in order

For our worked example, working from cards 1 and 2:

```
CARD 1
  set ID:    9 6 5 1       (in bytes: 0x96 and 0x51)
  x:         1
  M:         2
  N:         3
  words:     3
  → clean, verify, client

CARD 2
  set ID:    9 6 5 1       ← same as card 1; good
  x:         2
  M:         2             ← same as card 1; good
  N:         3             ← same as card 1; good
  words:     3             ← same as card 1; good
  → ugly, disease, hub
```

**If the set IDs differ between cards, stop.** The cards are from
different splits and can't be combined.

**If the M / N / word-count differ between cards, stop and re-check.** All
cards from one split have identical M, N, and word counts.

---

# Step 2 — Look up each word's number

The BIP-39 wordlist is **alphabetical** and **numbered starting at zero**.
The first word in the list (`abandon`) is number 0. The second (`ability`)
is number 1. And so on.

If your wordlist is printed with line numbers starting at 1 (most are),
then **the word's number = its line number minus 1**.

For each word on each card, look it up and write down its number.

**Worked example (cards 1 and 2):**

| Card | Word    | Line # | Word number |
|------|---------|--------|-------------|
| 1    | clean   | 339    | 338         |
| 1    | verify  | 1942   | 1941        |
| 1    | client  | 343    | 342         |
| 2    | ugly    | 1889   | 1888        |
| 2    | disease | 505    | 504         |
| 2    | hub     | 885    | 884         |

> **Smudged or unreadable word?** The BIP-39 wordlist was specifically
> designed so every word has a unique 4-letter prefix. If you can read the
> first 4 letters, look those up — only one word will match.

---

# Step 3 — Convert each number to 11 bits of binary

Every BIP-39 word number fits in **exactly 11 binary digits**. The biggest
number (2047) is `1111 1111 111` — 11 ones. The smallest (0) is
`0000 0000 000` — 11 zeros.

For each number, write it in 11 bits.

## How to convert a number to binary

Procedure (slow but foolproof):

1. Write your number at the top of a column.
2. Divide it by 2, write the new (smaller) number under it, and write the
   **remainder** (0 or 1) on the right.
3. Repeat with the new number until you get to 0.
4. Read the remainders **bottom to top** — that's your binary.
5. Pad with leading zeros on the **left** until you have 11 digits total.

### Worked: converting **338** to 11-bit binary

```
   number     ÷ 2        new number     remainder
   ──────     ─────      ───────────    ─────────
   338        ÷ 2  =     169            r 0   ← first remainder (rightmost bit)
   169        ÷ 2  =     84             r 1
   84         ÷ 2  =     42             r 0
   42         ÷ 2  =     21             r 0
   21         ÷ 2  =     10             r 1
   10         ÷ 2  =     5              r 0
   5          ÷ 2  =     2              r 1
   2          ÷ 2  =     1              r 0
   1          ÷ 2  =     0              r 1   ← last remainder (leftmost bit)
```

Read the remainders bottom-to-top: `1 0 1 0 1 0 0 1 0`. That's 9 digits.
Pad with **2 leading zeros** to make exactly 11: **`00101010010`**.

> Don't panic if this is slow at first. With practice you can do a
> three-digit number in about a minute.
>
> **Shortcut for small numbers:** if the number is below 1024, the leftmost
> bit is 0; if below 512, the two leftmost bits are 00; etc. The biggest
> power of 2 less than your number tells you how many leading zeros you'll
> need.

### Worked: all six numbers from our example

You should be able to verify each of these by repeating the process above.

| Card | Word    | Number | 11-bit binary  |
|------|---------|--------|----------------|
| 1    | clean   | 338    | `00101010010`  |
| 1    | verify  | 1941   | `11110010101`  |
| 1    | client  | 342    | `00101010110`  |
| 2    | ugly    | 1888   | `11101100000`  |
| 2    | disease | 504    | `00111111000`  |
| 2    | hub     | 884    | `01101110100`  |

**Critical: every row is exactly 11 digits.** Count them. Off-by-one here
is the single most common cause of a failed recovery.

---

# Step 4 — Stitch the bits, then cut into bytes

## Stitch

For **each card separately**, write all the words' 11-bit binary side by
side, in the order the words appeared on the card. Don't add any spaces;
the bits run together.

**Card 1 stitched:**

```
clean       verify        client
00101010010 11110010101 00101010110
```

All together (33 bits):

```
001010100101111001010100101010110
```

**Card 2 stitched:**

```
ugly         disease       hub
11101100000 00111111000 01101110100
```

All together (33 bits):

```
111011000000011111100001101110100
```

(`word_count × 11` = `3 × 11` = 33. Sanity-check yourself: count the bits.
There should be exactly 33 in each card's string.)

## Cut into bytes

Group the bit string **into chunks of 8, starting from the LEFT**. A byte
is 8 bits.

**Card 1:**

```
0010 1010 │ 0101 1110 │ 0101 0100 │ 1010 1011 │ 0
 byte 1   │  byte 2   │  byte 3   │  byte 4   │ leftover bit
```

We have **33 bits** = 4 full bytes + 1 leftover bit. The leftover bit at
the end is **padding** chela added to make the total a multiple of 11.
It must be `0` (if it's `1`, you typed a word wrong). Throw it away.

Convert each byte from binary to hex using the **hex shortcut** from the
pre-flight section (4 bits → 1 hex digit):

| Byte # | Binary       | Left hex | Right hex | Hex byte |
|--------|--------------|----------|-----------|----------|
| 1      | `0010 1010`  | 2        | A         | `0x2A`   |
| 2      | `0101 1110`  | 5        | E         | `0x5E`   |
| 3      | `0101 0100`  | 5        | 4         | `0x54`   |
| 4      | `1010 1011`  | A        | B         | `0xAB`   |

**Card 1 bytes:** `0x2A  0x5E  0x54  0xAB`

**Card 2:**

```
1110 1100 │ 0000 0111 │ 1110 0001 │ 1011 1010 │ 0
 byte 1   │  byte 2   │  byte 3   │  byte 4   │ padding (must be 0)
```

| Byte # | Binary       | Left hex | Right hex | Hex byte |
|--------|--------------|----------|-----------|----------|
| 1      | `1110 1100`  | E        | C         | `0xEC`   |
| 2      | `0000 0111`  | 0        | 7         | `0x07`   |
| 3      | `1110 0001`  | E        | 1         | `0xE1`   |
| 4      | `1011 1010`  | B        | A         | `0xBA`   |

**Card 2 bytes:** `0xEC  0x07  0xE1  0xBA`

## Identify share-bytes vs checksum

Chela puts a 2-byte **checksum** at the end of each card's bit string. The
checksum is for typo detection only; we're skipping that check (it
requires SHA-256). The **first part** is the **share bytes** — the actual
data we'll combine in Step 5.

The split is always **(total bytes) − 2** share bytes, then **2 bytes**
of checksum. For our cards: 4 total bytes − 2 = 2 share bytes per card.

| Card | Share bytes      | Checksum (discard) |
|------|------------------|--------------------|
| 1    | `0x2A 0x5E`      | `0x54 0xAB`        |
| 2    | `0xEC 0x07`      | `0xE1 0xBA`        |

> **Why is the body 2 bytes?** Each card has the same number of share
> bytes, and the share-byte count equals the recovered body length. For
> our example, the original `"hi"` was 2 bytes; that's what we'll get
> back at the end of Step 5.

### The word-count-ambiguity caveat (read this once, skip on retry)

For some word counts, **two body lengths** could fit into the same number
of bits. For example, with a 25-word card, the share+checksum could be
either 33 bytes or 34 bytes — both round up to 25 11-bit groups. If you
hit this case, you have two candidate splits:

- candidate A: 31 share bytes + 2 checksum bytes
- candidate B: 32 share bytes + 2 checksum bytes

The chela tool uses SHA-256 to figure out which is right. **By hand, the
clue is: you know what kind of payload you stored.** If you stored a
24-word BIP-39 mnemonic, the body is exactly 32 bytes (so use candidate
B). If you stored a text password, the body length equals the number of
characters you typed.

For our `"hi"` example there's only one possibility (4 total = 2 + 2), so
this doesn't come up.

---

# Step 5 — Combine the shares (the real work)

This is the heart of the procedure. We **mathematically combine** the
share bytes from M cards to recover the original body bytes.

The math is **Lagrange interpolation**, in a special arithmetic where
addition is XOR and multiplication is a special "shift-and-XOR" procedure.
Don't worry about why it works — just follow the procedure.

## 5.1 The intuition (skip if you don't care)

When chela split your secret, it built a tiny **recipe** (a polynomial,
in math jargon) for each byte of your secret. The recipe was designed so
that:

- Plugging in `x = 0` gives the secret byte itself.
- Plugging in `x = 1` gives card 1's value for that byte.
- Plugging in `x = 2` gives card 2's value.
- And so on.

The recipes are degree `M − 1` (a line if `M = 2`, a curve if `M = 3`,
etc.). From any `M` of the (x, value) points, **you can mathematically
rebuild the recipe and read off the value at x = 0**.

That last step is "Lagrange interpolation". The formula looks scary but
it's just multiplications and XORs.

## 5.2 The special byte arithmetic

Two rules. Both happen entirely on **bytes** (8-bit values, 0x00–0xFF).

### Rule 1 — addition is XOR

`a + b` = `a − b` = `a ⊕ b`. There's no "minus" — subtraction is the same
operation as addition. (Yes, this is weird if you're used to normal
arithmetic. It's a feature of this number system.)

### Rule 2 — multiplication is shift-and-XOR-with-0x1B

Multiplying by some powers of 2 is simple:

- `× 1` — value unchanged
- `× 2` — **shift the byte's bits left by one place.** If the leftmost
  bit was a 1, then XOR the result with `0x1B` (`0001 1011`).
- `× 4` = multiply by 2 twice
- `× 8` = multiply by 2 three times
- etc.

Multiplying by something that's **not** a power of 2: break it into a sum
of powers of 2 (i.e. write the multiplier in binary), and XOR all the
shifted copies.

Worked: `0x37 × 6`. The multiplier `6` in binary is `110` (= 4 + 2). So
`0x37 × 6 = (0x37 × 4) ⊕ (0x37 × 2)`.

- `0x37 × 2`: `0x37` = `0011 0111`. Leftmost bit is 0, so just shift:
  `0110 1110` = `0x6E`.
- `0x37 × 4`: do `× 2` twice. From `0x6E` = `0110 1110`. Leftmost bit is
  0, so shift: `1101 1100` = `0xDC`.
- XOR: `0xDC ⊕ 0x6E` = ?
  ```
     0xDC = 1101 1100
     0x6E = 0110 1110
     ────────────────
     XOR  = 1011 0010 = 0xB2
  ```

So `0x37 × 6 = 0xB2`.

> **The reduction step.** When you shift a byte left and the leftmost bit
> was 1, the shifted value would overflow the 8-bit range. The XOR with
> `0x1B` is the way this arithmetic handles overflow. Forget WHY; just do
> it: leftmost bit was 1 → after shifting, XOR with `0x1B`.

**Worked with reduction: `0xF6 × 2`.** `0xF6` = `1111 0110`. Leftmost bit
is **1**. Shift: `1110 1100` = `0xEC`. Now XOR with `0x1B`:
```
   0xEC = 1110 1100
   0x1B = 0001 1011
   ────────────────
   XOR  = 1111 0111 = 0xF7
```

So `0xF6 × 2 = 0xF7`.

### Rule 3 — division means "multiply by the inverse"

To do `a ÷ b`, find `b`'s **inverse** (call it `inv(b)`), then compute
`a × inv(b)`. The inverse of a byte `b` is a special byte that satisfies
`b × inv(b) = 1`.

You don't compute inverses by hand — **look them up in the table in the
appendix**. Print the table or write it out before you start.

A few from the table for reference:

| `b`  | `inv(b)` |
|------|----------|
| 0x01 | 0x01     |
| 0x02 | 0x8D     |
| 0x03 | **0xF6** |
| 0x04 | 0xCB     |
| 0x05 | 0x52     |

## 5.3 Compute the Lagrange coefficients

For each card you're using, you need one **Lagrange coefficient**. Call
them `L_1, L_2, …`. (One coefficient per card, regardless of how many
bytes the body is.)

The formula, for card number `i` whose `x` value is `x_i`, given you have
cards with x-values `{x_1, x_2, …, x_M}`:

```
L_i = (x_1 × inv(x_i ⊕ x_1)) × (x_2 × inv(x_i ⊕ x_2)) × … 
                                                  for every other card
```

(That is: multiply together `(x_j × inv(x_i ⊕ x_j))` for every other card
`j ≠ i`. Skip the case where `j == i`. All multiplications and XORs are in
the special arithmetic.)

For our worked example, M = 2 and we have cards 1 (`x = 1`) and 2 (`x =
2`). Only two terms each:

```
L_1 = x_2 × inv(x_1 ⊕ x_2) = 2 × inv(1 ⊕ 2) = 2 × inv(3)
L_2 = x_1 × inv(x_2 ⊕ x_1) = 1 × inv(2 ⊕ 1) = 1 × inv(3)
```

From the inverse table, `inv(3) = 0xF6`. So:

- `L_1 = 2 × 0xF6`. Apply rule 2 to compute `0xF6 × 2` (we already worked
  this above): **`L_1 = 0xF7`**.
- `L_2 = 1 × 0xF6 = 0xF6` (multiplying by 1 leaves the value alone). So
  **`L_2 = 0xF6`**.

Write these down — you'll use them for every byte.

## 5.4 Combine each byte of the body

For each byte position of the body (0, 1, 2, …):

```
body[byte position] = (L_1 × card_1_share[byte position])
                    ⊕ (L_2 × card_2_share[byte position])
                    ⊕ …
                          for every card you have
```

Our body is 2 bytes (from Step 4: each card has 2 share bytes). So we do
this twice.

### Byte 0 of the body

- `card_1_share[0]` = `0x2A`
- `card_2_share[0]` = `0xEC`

**First term: `L_1 × card_1_share[0]` = `0xF7 × 0x2A`.**

The multiplier is `0x2A` = `0010 1010`. Bits set are at positions 1, 3, 5
(counting from the right starting at 0). So `0x2A = 32 + 8 + 2`. Therefore
`0xF7 × 0x2A = (0xF7 × 32) ⊕ (0xF7 × 8) ⊕ (0xF7 × 2)`.

Compute each:

- `0xF7 × 2`: `0xF7` = `1111 0111`. Leftmost bit 1. Shift = `1110 1110` =
  `0xEE`, then XOR `0x1B`:
  ```
     0xEE = 1110 1110
     0x1B = 0001 1011
     XOR  = 1111 0101 = 0xF5
  ```
- `0xF7 × 4` = `(0xF7 × 2) × 2` = `0xF5 × 2`. `0xF5` = `1111 0101`,
  leftmost 1. Shift = `1110 1010` = `0xEA`, XOR `0x1B`:
  ```
     0xEA = 1110 1010
     0x1B = 0001 1011
     XOR  = 1111 0001 = 0xF1
  ```
- `0xF7 × 8` = `(0xF7 × 4) × 2` = `0xF1 × 2`. `0xF1` = `1111 0001`,
  leftmost 1. Shift = `1110 0010` = `0xE2`, XOR `0x1B`:
  ```
     0xE2 = 1110 0010
     0x1B = 0001 1011
     XOR  = 1111 1001 = 0xF9
  ```
- `0xF7 × 16` = `(0xF7 × 8) × 2` = `0xF9 × 2`. `0xF9` = `1111 1001`,
  leftmost 1. Shift = `1111 0010` = `0xF2`, XOR `0x1B`:
  ```
     0xF2 = 1111 0010
     0x1B = 0001 1011
     XOR  = 1110 1001 = 0xE9
  ```
- `0xF7 × 32` = `(0xF7 × 16) × 2` = `0xE9 × 2`. `0xE9` = `1110 1001`,
  leftmost 1. Shift = `1101 0010` = `0xD2`, XOR `0x1B`:
  ```
     0xD2 = 1101 0010
     0x1B = 0001 1011
     XOR  = 1100 1001 = 0xC9
  ```

Now XOR the three needed pieces (`× 32`, `× 8`, `× 2`):

```
   0xC9  =  1100 1001
   0xF9  =  1111 1001
   0xF5  =  1111 0101
  ───────────────────────
   XOR   =  1100 0101  =  0xC5
```

So **`0xF7 × 0x2A = 0xC5`**.

**Second term: `L_2 × card_2_share[0]` = `0xF6 × 0xEC`.**

Multiplier `0xEC` = `1110 1100` = 128 + 64 + 32 + 8 + 4 (= 236; sanity).
So `0xF6 × 0xEC = (0xF6 × 128) ⊕ (0xF6 × 64) ⊕ (0xF6 × 32) ⊕ (0xF6 × 8) ⊕ (0xF6 × 4)`.

Build up the powers of `0xF6 × 2`:

- `0xF6 × 2` = `0xF7` (computed earlier)
- `0xF6 × 4` = `0xF7 × 2`. `0xF7` = `1111 0111`, leftmost 1, shift =
  `1110 1110` = `0xEE`, XOR `0x1B` = `0xF5`. So `0xF6 × 4 = 0xF5`.
- `0xF6 × 8` = `0xF5 × 2` = `0xF1` (already computed).
- `0xF6 × 16` = `0xF1 × 2` = `0xF9`.
- `0xF6 × 32` = `0xF9 × 2` = `0xE9`.
- `0xF6 × 64` = `0xE9 × 2` = `0xC9`.
- `0xF6 × 128` = `0xC9 × 2`. `0xC9` = `1100 1001`, leftmost 1, shift =
  `1001 0010` = `0x92`, XOR `0x1B`:
  ```
     0x92 = 1001 0010
     0x1B = 0001 1011
     XOR  = 1000 1001 = 0x89
  ```
  So `0xF6 × 128 = 0x89`.

XOR the needed pieces (`× 128`, `× 64`, `× 32`, `× 8`, `× 4`):

```
   0x89  =  1000 1001
   0xC9  =  1100 1001
   0xE9  =  1110 1001
   0xF1  =  1111 0001
   0xF5  =  1111 0101
  ───────────────────────
   XOR   =  1010 1101  =  0xAD
```

(XOR five bytes by going column by column, counting how many 1s there are
— if it's an odd count the result bit is 1, if even it's 0.)

So **`0xF6 × 0xEC = 0xAD`**.

**Finally, XOR the two terms:**

```
   0xC5 = 1100 0101
   0xAD = 1010 1101
   ────────────────
   XOR  = 0110 1000 = 0x68
```

**Body byte 0 = `0x68`.** That's the byte for the letter `h`.

### Byte 1 of the body

- `card_1_share[1]` = `0x5E`
- `card_2_share[1]` = `0x07`

Same procedure.

**First term: `L_1 × card_1_share[1]` = `0xF7 × 0x5E`.**

`0x5E` = `0101 1110` = 64 + 16 + 8 + 4 + 2. So
`0xF7 × 0x5E = (0xF7 × 64) ⊕ (0xF7 × 16) ⊕ (0xF7 × 8) ⊕ (0xF7 × 4) ⊕ (0xF7 × 2)`.

We already have most of these from byte 0:

- `0xF7 × 2 = 0xF5`
- `0xF7 × 4 = 0xF1`
- `0xF7 × 8 = 0xF9`
- `0xF7 × 16 = 0xE9`
- `0xF7 × 32 = 0xC9`
- `0xF7 × 64 = 0xC9 × 2 = 0x89` (computed in the second-term work above
  as `0xF6 × 128`; same number)

XOR the needed pieces (`× 64`, `× 16`, `× 8`, `× 4`, `× 2`):

```
   0x89  =  1000 1001
   0xE9  =  1110 1001
   0xF9  =  1111 1001
   0xF1  =  1111 0001
   0xF5  =  1111 0101
  ───────────────────────
   XOR   =  1001 1101  =  0x9D
```

So **`0xF7 × 0x5E = 0x9D`**.

**Second term: `L_2 × card_2_share[1]` = `0xF6 × 0x07`.**

`0x07` = `0000 0111` = 4 + 2 + 1.

- `0xF6 × 1 = 0xF6`
- `0xF6 × 2 = 0xF7`
- `0xF6 × 4 = 0xF5`

XOR all three:

```
   0xF6 = 1111 0110
   0xF7 = 1111 0111
   0xF5 = 1111 0101
  ─────────────────────
   XOR  = 1111 0100  =  0xF4
```

So **`0xF6 × 0x07 = 0xF4`**.

**Finally, XOR the two terms:**

```
   0x9D = 1001 1101
   0xF4 = 1111 0100
   ────────────────
   XOR  = 0110 1001 = 0x69
```

**Body byte 1 = `0x69`.** That's the byte for the letter `i`.

### Result

**Recovered body bytes: `0x68 0x69`.**

---

# Step 6 — Read out the body

You have the body bytes. The last step is interpreting them. **What you do
here depends on what kind of secret was originally stored.**

## If the secret was text

Look up each byte in the **ASCII table** (appendix). For our example:

- `0x68` → letter `h`
- `0x69` → letter `i`

**Recovered secret: `"hi"`** ✓

(For text with non-English characters — accented letters, emoji — the
bytes use a slightly more involved encoding called UTF-8. ASCII covers
all the unaccented Latin letters, digits, and common punctuation; for
anything else, any UTF-8 lookup chart will translate the bytes.)

## If the secret was a BIP-39 wallet mnemonic

The body bytes are the raw **entropy** that the BIP-39 mnemonic encodes,
**possibly followed by an optional passphrase** as UTF-8 bytes.

The entropy length tells you the word count:

| Body length (if no passphrase) | BIP-39 word count |
|--------------------------------|-------------------|
| 16 bytes                       | 12 words          |
| 20 bytes                       | 15 words          |
| 24 bytes                       | 18 words          |
| 28 bytes                       | 21 words          |
| 32 bytes                       | 24 words          |

If the body is **longer** than one of these exact sizes, the extra bytes
are a passphrase (encoded as UTF-8). For example, body = 18 bytes →
16 bytes of entropy for a 12-word mnemonic + 2 bytes of passphrase.

### Getting the entropy into your wallet

The body bytes you recovered **are** the BIP-39 entropy. Every major wallet
accepts entropy in one of two ways:

- **Import as hex / raw entropy.** Look for "import from hex", "raw seed",
  or an "advanced" import option in your wallet. Type the body bytes as
  hex (two characters per byte). This is the easiest path and works for
  any word count.
- **Import as 12/24 words.** The wallet wants the actual BIP-39 mnemonic.
  Producing it from entropy needs one SHA-256 computation (of the
  entropy) which you'd have to do with a tool — at which point you'd
  presumably just use chela itself instead. If you're stuck, the
  **brute-force shortcut** for a 12-word mnemonic is to try all 16
  possible last-words (the BIP-39 checksum is only 4 bits → 16
  candidates → exactly one will make the wallet accept the phrase).

If there's a passphrase: the bytes **after** the entropy (e.g. bytes 17+
of an 18-byte body) are the passphrase, UTF-8 encoded. The wallet asks
for it separately ("BIP-39 passphrase", "25th word", or "seed extension").

---

# When something goes wrong

| Symptom                                              | Likely cause                                                | Action                                                                                       |
|------------------------------------------------------|-------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| Leftover bits in Step 4 aren't all 0                 | Word mis-typed                                              | Re-check that card's words against the printed wordlist (use 4-letter prefix matching)        |
| Recovered text is garbage (random-looking bytes)     | An undetected word substitution (one valid word swapped for another), OR cards from different splits combined | Re-check every word; confirm all cards share the same set ID; redo Step 5 with a fresh sheet |
| Set IDs differ between cards                         | Cards are from independent splits                           | Recovery impossible from this mix. Find more cards from the same set.                         |
| You have fewer than M cards                          | Not enough cards                                            | Recovery impossible. Find at least M cards.                                                   |
| You're not sure if your payload was text or BIP-39   | Card title / description was vague                          | Check the body length: 16/20/24/28/32 bytes (or those + 1..255) → BIP-39; 1–255 → text. Length alone narrows it. |

---

# Appendix A — GF(2⁸) inverse table (all 256 values)

For Step 5 (Lagrange coefficient computation). Print this. The `inv(0)` =
`0x00` entry is a convention — you never actually divide by zero in a
valid recovery.

```
inv[0x00]=0x00  inv[0x01]=0x01  inv[0x02]=0x8d  inv[0x03]=0xf6
inv[0x04]=0xcb  inv[0x05]=0x52  inv[0x06]=0x7b  inv[0x07]=0xd1
inv[0x08]=0xe8  inv[0x09]=0x4f  inv[0x0a]=0x29  inv[0x0b]=0xc0
inv[0x0c]=0xb0  inv[0x0d]=0xe1  inv[0x0e]=0xe5  inv[0x0f]=0xc7
inv[0x10]=0x74  inv[0x11]=0xb4  inv[0x12]=0xaa  inv[0x13]=0x4b
inv[0x14]=0x99  inv[0x15]=0x2b  inv[0x16]=0x60  inv[0x17]=0x5f
inv[0x18]=0x58  inv[0x19]=0x3f  inv[0x1a]=0xfd  inv[0x1b]=0xcc
inv[0x1c]=0xff  inv[0x1d]=0x40  inv[0x1e]=0xee  inv[0x1f]=0xb2
inv[0x20]=0x3a  inv[0x21]=0x6e  inv[0x22]=0x5a  inv[0x23]=0xf1
inv[0x24]=0x55  inv[0x25]=0x4d  inv[0x26]=0xa8  inv[0x27]=0xc9
inv[0x28]=0xc1  inv[0x29]=0x0a  inv[0x2a]=0x98  inv[0x2b]=0x15
inv[0x2c]=0x30  inv[0x2d]=0x44  inv[0x2e]=0xa2  inv[0x2f]=0xc2
inv[0x30]=0x2c  inv[0x31]=0x45  inv[0x32]=0x92  inv[0x33]=0x6c
inv[0x34]=0xf3  inv[0x35]=0x39  inv[0x36]=0x66  inv[0x37]=0x42
inv[0x38]=0xf2  inv[0x39]=0x35  inv[0x3a]=0x20  inv[0x3b]=0x6f
inv[0x3c]=0x77  inv[0x3d]=0xbb  inv[0x3e]=0x59  inv[0x3f]=0x19
inv[0x40]=0x1d  inv[0x41]=0xfe  inv[0x42]=0x37  inv[0x43]=0x67
inv[0x44]=0x2d  inv[0x45]=0x31  inv[0x46]=0xf5  inv[0x47]=0x69
inv[0x48]=0xa7  inv[0x49]=0x64  inv[0x4a]=0xab  inv[0x4b]=0x13
inv[0x4c]=0x54  inv[0x4d]=0x25  inv[0x4e]=0xe9  inv[0x4f]=0x09
inv[0x50]=0xed  inv[0x51]=0x5c  inv[0x52]=0x05  inv[0x53]=0xca
inv[0x54]=0x4c  inv[0x55]=0x24  inv[0x56]=0x87  inv[0x57]=0xbf
inv[0x58]=0x18  inv[0x59]=0x3e  inv[0x5a]=0x22  inv[0x5b]=0xf0
inv[0x5c]=0x51  inv[0x5d]=0xec  inv[0x5e]=0x61  inv[0x5f]=0x17
inv[0x60]=0x16  inv[0x61]=0x5e  inv[0x62]=0xaf  inv[0x63]=0xd3
inv[0x64]=0x49  inv[0x65]=0xa6  inv[0x66]=0x36  inv[0x67]=0x43
inv[0x68]=0xf4  inv[0x69]=0x47  inv[0x6a]=0x91  inv[0x6b]=0xdf
inv[0x6c]=0x33  inv[0x6d]=0x93  inv[0x6e]=0x21  inv[0x6f]=0x3b
inv[0x70]=0x79  inv[0x71]=0xb7  inv[0x72]=0x97  inv[0x73]=0x85
inv[0x74]=0x10  inv[0x75]=0xb5  inv[0x76]=0xba  inv[0x77]=0x3c
inv[0x78]=0xb6  inv[0x79]=0x70  inv[0x7a]=0xd0  inv[0x7b]=0x06
inv[0x7c]=0xa1  inv[0x7d]=0xfa  inv[0x7e]=0x81  inv[0x7f]=0x82
inv[0x80]=0x83  inv[0x81]=0x7e  inv[0x82]=0x7f  inv[0x83]=0x80
inv[0x84]=0x96  inv[0x85]=0x73  inv[0x86]=0xbe  inv[0x87]=0x56
inv[0x88]=0x9b  inv[0x89]=0x9e  inv[0x8a]=0x95  inv[0x8b]=0xd9
inv[0x8c]=0xf7  inv[0x8d]=0x02  inv[0x8e]=0xb9  inv[0x8f]=0xa4
inv[0x90]=0xde  inv[0x91]=0x6a  inv[0x92]=0x32  inv[0x93]=0x6d
inv[0x94]=0xd8  inv[0x95]=0x8a  inv[0x96]=0x84  inv[0x97]=0x72
inv[0x98]=0x2a  inv[0x99]=0x14  inv[0x9a]=0x9f  inv[0x9b]=0x88
inv[0x9c]=0xf9  inv[0x9d]=0xdc  inv[0x9e]=0x89  inv[0x9f]=0x9a
inv[0xa0]=0xfb  inv[0xa1]=0x7c  inv[0xa2]=0x2e  inv[0xa3]=0xc3
inv[0xa4]=0x8f  inv[0xa5]=0xb8  inv[0xa6]=0x65  inv[0xa7]=0x48
inv[0xa8]=0x26  inv[0xa9]=0xc8  inv[0xaa]=0x12  inv[0xab]=0x4a
inv[0xac]=0xce  inv[0xad]=0xe7  inv[0xae]=0xd2  inv[0xaf]=0x62
inv[0xb0]=0x0c  inv[0xb1]=0xe0  inv[0xb2]=0x1f  inv[0xb3]=0xef
inv[0xb4]=0x11  inv[0xb5]=0x75  inv[0xb6]=0x78  inv[0xb7]=0x71
inv[0xb8]=0xa5  inv[0xb9]=0x8e  inv[0xba]=0x76  inv[0xbb]=0x3d
inv[0xbc]=0xbd  inv[0xbd]=0xbc  inv[0xbe]=0x86  inv[0xbf]=0x57
inv[0xc0]=0x0b  inv[0xc1]=0x28  inv[0xc2]=0x2f  inv[0xc3]=0xa3
inv[0xc4]=0xda  inv[0xc5]=0xd4  inv[0xc6]=0xe4  inv[0xc7]=0x0f
inv[0xc8]=0xa9  inv[0xc9]=0x27  inv[0xca]=0x53  inv[0xcb]=0x04
inv[0xcc]=0x1b  inv[0xcd]=0xfc  inv[0xce]=0xac  inv[0xcf]=0xe6
inv[0xd0]=0x7a  inv[0xd1]=0x07  inv[0xd2]=0xae  inv[0xd3]=0x63
inv[0xd4]=0xc5  inv[0xd5]=0xdb  inv[0xd6]=0xe2  inv[0xd7]=0xea
inv[0xd8]=0x94  inv[0xd9]=0x8b  inv[0xda]=0xc4  inv[0xdb]=0xd5
inv[0xdc]=0x9d  inv[0xdd]=0xf8  inv[0xde]=0x90  inv[0xdf]=0x6b
inv[0xe0]=0xb1  inv[0xe1]=0x0d  inv[0xe2]=0xd6  inv[0xe3]=0xeb
inv[0xe4]=0xc6  inv[0xe5]=0x0e  inv[0xe6]=0xcf  inv[0xe7]=0xad
inv[0xe8]=0x08  inv[0xe9]=0x4e  inv[0xea]=0xd7  inv[0xeb]=0xe3
inv[0xec]=0x5d  inv[0xed]=0x50  inv[0xee]=0x1e  inv[0xef]=0xb3
inv[0xf0]=0x5b  inv[0xf1]=0x23  inv[0xf2]=0x38  inv[0xf3]=0x34
inv[0xf4]=0x68  inv[0xf5]=0x46  inv[0xf6]=0x03  inv[0xf7]=0x8c
inv[0xf8]=0xdd  inv[0xf9]=0x9c  inv[0xfa]=0x7d  inv[0xfb]=0xa0
inv[0xfc]=0xcd  inv[0xfd]=0x1a  inv[0xfe]=0x41  inv[0xff]=0x1c
```

---

# Appendix B — ASCII printable bytes

For the "decode body as text" step. Only the printable subset is shown
(0x20 / space through 0x7E / `~`); anything outside this range in a text
payload usually means accented letters or emoji, encoded via UTF-8.

```
0x20 = (space)   0x30 = 0   0x40 = @   0x50 = P   0x60 = `   0x70 = p
0x21 = !         0x31 = 1   0x41 = A   0x51 = Q   0x61 = a   0x71 = q
0x22 = "         0x32 = 2   0x42 = B   0x52 = R   0x62 = b   0x72 = r
0x23 = #         0x33 = 3   0x43 = C   0x53 = S   0x63 = c   0x73 = s
0x24 = $         0x34 = 4   0x44 = D   0x54 = T   0x64 = d   0x74 = t
0x25 = %         0x35 = 5   0x45 = E   0x55 = U   0x65 = e   0x75 = u
0x26 = &         0x36 = 6   0x46 = F   0x56 = V   0x66 = f   0x76 = v
0x27 = '         0x37 = 7   0x47 = G   0x57 = W   0x67 = g   0x77 = w
0x28 = (         0x38 = 8   0x48 = H   0x58 = X   0x68 = h   0x78 = x
0x29 = )         0x39 = 9   0x49 = I   0x59 = Y   0x69 = i   0x79 = y
0x2a = *         0x3a = :   0x4a = J   0x5a = Z   0x6a = j   0x7a = z
0x2b = +         0x3b = ;   0x4b = K   0x5b = [   0x6b = k   0x7b = {
0x2c = ,         0x3c = <   0x4c = L   0x5c = \   0x6c = l   0x7c = |
0x2d = -         0x3d = =   0x4d = M   0x5d = ]   0x6d = m   0x7d = }
0x2e = .         0x3e = >   0x4e = N   0x5e = ^   0x6e = n   0x7e = ~
0x2f = /         0x3f = ?   0x4f = O   0x5f = _   0x6f = o
```

---

# Glossary

- **bit** — one binary digit (0 or 1).
- **byte** — 8 bits in a row; holds a number 0–255 (or 0x00–0xFF in hex).
- **hex** (hexadecimal) — base 16; digits 0–9, A–F. Each hex digit = 4
  bits.
- **XOR** (⊕) — bit-by-bit operation: 0 if same, 1 if different. On
  bytes, XOR each pair of corresponding bits.
- **BIP-39** — the standard wordlist (2048 English words) used to encode
  bytes as easy-to-write words. Each word represents 11 bits.
- **set ID / identifier** — the 4-hex-character "recovery set" code
  printed on every chela card. Every card from the same split shows the
  same set ID.
- **share** — one card's worth of data. By itself, a single share tells
  you nothing about the secret. Combine M shares to recover.
- **threshold (M)** — the minimum number of cards needed to recover.
- **GF(2⁸)** — short for "the finite field with 2⁸ = 256 elements".
  Mathematician's name for the special byte arithmetic used here:
  addition is XOR, multiplication is the shift-and-XOR procedure in
  Step 5.2.
- **Lagrange interpolation** — the procedure in Step 5 that recombines M
  share bytes to recover a body byte. Named after Joseph-Louis Lagrange
  (1736–1813).
- **Shamir's Secret Sharing** — the method chela uses to split a secret
  into N shares such that any M reconstruct it. Invented by Adi Shamir
  in 1979.

---

# Where to go from here

For an engineer's reference of chela's wire formats (for reimplementing
the tool in another language), see [SPEC.md](./SPEC.md).

For the chela tool's normal usage, see [README.md](./README.md) and the
user-facing recovery walkthrough at [RECOVERY.md](./RECOVERY.md).
