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

**The words are all you need.** Everything recovery depends on — each
card's coordinate `x`, the threshold `M`, the generation tag that groups
cards, and the kind of secret stored — is packed *inside the words
themselves*. The `CHELA-…` code printed on the card is a convenience for
sorting cards by eye; you never read a number off the label to recover.
If all you have is the list of words from each card, you can still finish.

---

# One thing this guide leaves optional

Each card ends with a single **checksum word** that catches transcription
typos. It's a CRC — an 11-bit long division you *can* do by hand (Step 4
and Appendix C describe it), but it only tells you *whether* a card was
copied correctly, not *what* the secret is. The recovery math runs without
it, so the main walkthrough computes the recovery first and treats the
checksum as an end-of-run cross-check.

This guide needs **no SHA-256 and no hashing of any kind.** The whole
procedure is XOR, one byte-multiply rule, table lookups, and (if you want
the checksum) one long division.

The body you recover also carries a one-byte SHA-256 **integrity check**
(the *integrity byte*, Step 6). The chela tool uses it to confirm the right
cards were combined; by hand you simply strip it off and never recompute it,
so the procedure stays hash-free.

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

> `0110 0010` → `0110` is **6**, `0010` is **2**, joined: **`0x62`**

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
│   ALICE'S NOTE                                          │ ← title (ignore)
│                                                         │
│   Group tag:         02C9                               │ ← (1) generation tag
│   Required:          2 of 3                             │ ← (2) M of N
│   Card code:         CHELA-02C9-6-2-3-6                 │ ← (3) full code
│                                                         │
│   Your share words:                                     │
│     1.  chimney                                         │
│     2.  float                                           │
│     3.  vintage                                         │ ← (4) the words
│     4.  before                                          │
│     5.  learn                                           │
│     6.  film                                            │
│                                                         │
│   …recovery instructions…                               │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

Everything below is **printed for convenience** — useful for sorting and
sanity-checking cards, but recovery reads it all back out of the words, so
you don't *have* to trust the label.

**(1) Generation tag** — four hex characters (`02C9` here). This is a
random number chosen once when the cards were made, and printed on every
card from that one making. It's *not* derived from the secret. Its only
job is to group cards: every card from the same making shows the same tag.
If two cards show different tags, they're from different makings and won't
combine. (You'll re-read this same tag out of the words in Step 1, so a
smudged label doesn't matter.)

**(2) Required / total** — the threshold "M" (the number of cards you need;
the LEFT number in "2 of 3") and total "N" (the right number). You need at
least M cards to recover. Extras don't hurt; missing cards below M mean no
recovery, ever. (M also comes back out of the words; N is only ever a
human hint and recovery never needs it.)

**(3) Card code** — the whole header in one line.
`CHELA-02C9-6-2-3-6` decomposes as:

- `02C9` — the generation tag (same as item 1)
- `6` — **this card's coordinate** (called `x` in the math). It is a
  **random** number in the range 1–32, *not* the card's position in the
  set. Card "number one" of a making will usually not show `1` here, and
  that's correct — every card just gets a random `x`.
- `2` — threshold M (same as the left of item 2)
- `3` — total N (same as the right of item 2)
- `6` — number of words on this card

**(4) The words** — the actual data, and the only thing recovery truly
needs. Every card from one making has the same number of words. Each word
stands in for an 11-bit number from the BIP-39 wordlist. The words split
into four parts, which Step 1 pulls apart:

```
word 1          the metadata word  → this card's x, and M
word 2          the generation tag → the same 4-hex number on every card
words 3 … (W−1) the share body     → the numbers we'll combine
word W (last)   the checksum word  → optional typo check (Step 4 / Appendix C)
```

There are always **at least 4 words** on a card (one each for metadata,
tag, body, checksum). A card with fewer than 4 words is not a valid chela
card.

---

# The v2 limits (so the metadata word decodes)

To read the first word you need the ranges the format allows:

- `x` (this card's coordinate) is **1 to 32**. In the words it's stored as
  a 5-bit field `0..31`; the stored field plus 1 is `x`.
- `M` (threshold) is **2 to 32**. Stored as a 5-bit field `0..30`; the
  stored field plus 2 is `M`. (A field of 31 would mean M = 33 — invalid;
  if you ever decode that, you mis-read a word.)
- `N` (total) is at most **32**. It is never needed to recover.

You'll use the "+1 for x, +2 for M" offsets in Step 1.

---

# The recovery in 6 steps — overview

Here's the whole shape of what we're going to do. Read this through once
before starting Step 1; it's a map.

1. **Read each card's words** and pull out its four parts.
2. **Look up each body word** in the BIP-39 wordlist to get a number.
3. **Convert each number to 11 bits** of binary and stitch them together.
4. **Cut the bits into bytes** — these are the "share bytes" for the card.
5. **Lagrange-combine the share bytes** from the M cards you have. This
   is the only step with non-trivial maths; the appendix has the lookup
   table that makes it manageable.
6. **Read out the body bytes**: drop the last byte (it names the *kind* of
   secret) and the byte before it (a one-byte integrity check you can't redo
   by hand), then for text look up each remaining byte in the ASCII table, or
   for a BIP-39 seed follow the guidance at the end.

We'll do all of it with a complete worked example: a **2-of-3 split of
the text `"hi"`**. The three cards from that split are:

```
CHELA-02C9-6-2-3-6
chimney float vintage before learn film

CHELA-02C9-3-2-3-6
avoid float chat ancient orphan produce

CHELA-02C9-20-2-3-6
object float assist elevator also hole
```

We'll recover using the first two cards (the ones with `x = 6` and
`x = 3`). The third card (`x = 20`) is shown so you can practise on it
separately if you want. Notice the coordinates are `6`, `3`, `20` — random,
not `1`, `2`, `3`. That's expected.

---

# Step 1 — Read each card's four parts

For each card you have, write down (on a fresh sheet of paper) the words
in order, then split them into the four parts. We do the metadata and tag
words by hand here; the body and checksum words wait for Step 2.

Take **card 1** (`chimney float vintage before learn film`). Look up the
**first word** and the **second word** in the wordlist:

| Word    | Line # | Number |
|---------|--------|--------|
| chimney | 321    | 320    |
| float   | 714    | 713    |

(The wordlist is numbered from 0, so number = line number − 1. Step 2
explains the lookup in full; for now you only need these two.)

**The metadata word (word 1) → `x` and `M`.** Write the first word's
number, 320, in 11 bits (Step 3 teaches the conversion; the answer is):

```
chimney = 320 = 0 0 1 0 1 │ 0 0 0 0 0 │ 0
                └─ X ──┘   └─ M ──┘   └ reserved
                bits 10..6  bits 5..1  bit 0
```

Read it left to right and split it `5 | 5 | 1`:

- **X field** = `00101` = 5.  `x = field + 1 = 6`.
- **M field** = `00000` = 0.  `M = field + 2 = 2`.
- **reserved bit** = `0`. It **must** be 0. If it's 1, you mis-read the
  word — go back and check it.

So card 1 is coordinate `x = 6`, threshold `M = 2`. (The `6` and `2`
printed in the card code match — that's the cross-check, not the source.)

**The generation tag (word 2).** The second word's number *is* the tag.
`float` = 713 = `0x2C9`. Every card from this making must give the same
713 here. (It matches the `02C9` printed on the label.)

Now do the same for **card 2** (`avoid float chat ancient orphan produce`):

| Word    | Line # | Number |
|---------|--------|--------|
| avoid   | 129    | 128    |
| float   | 714    | 713    |

```
avoid = 128 = 0 0 0 1 0 │ 0 0 0 0 0 │ 0
              └─ X ──┘    └─ M ──┘   └ reserved
```

- **X field** = `00010` = 2.  `x = 3`.
- **M field** = `00000` = 0.  `M = 2`.
- **reserved** = 0. Good.
- **tag** word = `float` = 713 = `0x2C9`. **Same tag as card 1 — good.**

Write the running summary:

```
CARD 1   x = 6   M = 2   tag = 713 (0x2C9)   words = 6
  body words: vintage, before, learn     checksum word: film
CARD 2   x = 3   M = 2   tag = 713 (0x2C9)   words = 6
  body words: chat, ancient, orphan      checksum word: produce
```

The **body words** are everything from word 3 up to but not including the
last word. The **last word** is the checksum (we handle it in Step 4).
With 6 words per card: words 3, 4, 5 are the body; word 6 is the checksum.

**Stop and check before going on:**

- **All cards must show the same tag.** Different tag → the cards are from
  different makings and can't be combined.
- **All cards must show the same M and the same word count.** If they
  don't, you mis-read a metadata word — recheck.
- **You need at least M cards.** Here M = 2 and we have 2. Good.

---

# Step 2 — Look up each body word's number

Now the body words. The BIP-39 wordlist is **alphabetical** and **numbered
starting at zero**. The first word in the list (`abandon`) is number 0.
The second (`ability`) is number 1. And so on.

If your wordlist is printed with line numbers starting at 1 (most are),
then **the word's number = its line number minus 1**.

For each **body word** on each card, look it up and write down its number.
(You already did the metadata and tag words in Step 1.)

**Worked example (body words of cards 1 and 2):**

| Card | Word    | Line # | Word number |
|------|---------|--------|-------------|
| 1    | vintage | 1954   | 1953        |
| 1    | before  | 162    | 161         |
| 1    | learn   | 1015   | 1014        |
| 2    | chat    | 311    | 310         |
| 2    | ancient | 69     | 68          |
| 2    | orphan  | 1255   | 1254        |

> **Smudged or unreadable word?** The BIP-39 wordlist was specifically
> designed so every word has a unique 4-letter prefix. If you can read the
> first 4 letters, look those up — only one word will match.

---

# Step 3 — Convert each number to 11 bits of binary

Every BIP-39 word number fits in **exactly 11 binary digits**. The biggest
number (2047) is `1111 1111 111` — 11 ones. The smallest (0) is
`0000 0000 000` — 11 zeros.

For each body number, write it in 11 bits.

## How to convert a number to binary

Procedure (slow but foolproof):

1. Write your number at the top of a column.
2. Divide it by 2, write the new (smaller) number under it, and write the
   **remainder** (0 or 1) on the right.
3. Repeat with the new number until you get to 0.
4. Read the remainders **bottom to top** — that's your binary.
5. Pad with leading zeros on the **left** until you have 11 digits total.

### Worked: converting **1953** to 11-bit binary

```
   number     ÷ 2        new number     remainder
   ──────     ─────      ───────────    ─────────
   1953       ÷ 2  =     976            r 1   ← first remainder (rightmost bit)
   976        ÷ 2  =     488            r 0
   488        ÷ 2  =     244            r 0
   244        ÷ 2  =     122            r 0
   122        ÷ 2  =     61             r 0
   61         ÷ 2  =     30             r 1
   30         ÷ 2  =     15             r 0
   15         ÷ 2  =     7              r 1
   7          ÷ 2  =     3              r 1
   3          ÷ 2  =     1              r 1
   1          ÷ 2  =     0              r 1   ← last remainder (leftmost bit)
```

Read the remainders bottom-to-top: `1 1 1 1 0 1 0 0 0 0 1`. That's exactly
11 digits, so no padding is needed: **`11110100001`**.

> Don't panic if this is slow at first. With practice you can do a
> three-digit number in about a minute.
>
> **Shortcut for small numbers:** if the number is below 1024, the leftmost
> bit is 0; if below 512, the two leftmost bits are 00; etc. The biggest
> power of 2 less than your number tells you how many leading zeros you'll
> need.

### Worked: the body numbers from our example

You should be able to verify each of these by repeating the process above.

| Card | Word    | Number | 11-bit binary  |
|------|---------|--------|----------------|
| 1    | vintage | 1953   | `11110100001`  |
| 1    | before  | 161    | `00010100001`  |
| 1    | learn   | 1014   | `01111110110`  |
| 2    | chat    | 310    | `00100110110`  |
| 2    | ancient | 68     | `00001000100`  |
| 2    | orphan  | 1254   | `10011100110`  |

**Critical: every row is exactly 11 digits.** Count them. Off-by-one here
is the single most common cause of a failed recovery.

---

# Step 4 — Stitch the body bits, then cut into bytes

## Stitch

For **each card separately**, write the card's three **body** words'
11-bit binary side by side, in order. Don't add any spaces; the bits run
together. (The metadata word, the tag word, and the checksum word are
*not* part of this — only the body words.)

**Card 1 body stitched (`vintage before learn`):**

```
vintage     before      learn
11110100001 00010100001 01111110110
```

All together (33 bits):

```
111101000010001010000101111110110
```

**Card 2 body stitched (`chat ancient orphan`):**

```
chat        ancient     orphan
00100110110 00001000100 10011100110
```

All together (33 bits):

```
001001101100000100010010011100110
```

(`body_word_count × 11` = `3 × 11` = 33. Sanity-check yourself: count the
bits. There should be exactly 33 in each card's body string.)

## Cut into bytes

Group the bit string **into chunks of 8, starting from the LEFT**. A byte
is 8 bits.

**Card 1:**

```
1111 0100 │ 0010 0010 │ 1000 0101 │ 1111 1011 │ 0
 byte 1   │  byte 2   │  byte 3   │  byte 4   │ pad bit
```

We have **33 bits** = 4 full bytes + 1 leftover bit. That leftover bit is
**padding** chela added to fill out the final word; it is `0`. If it is
`1`, you typed a body word wrong. Throw the padding away.

Convert each byte from binary to hex using the **hex shortcut** from the
pre-flight section (4 bits → 1 hex digit):

| Byte # | Binary       | Left hex | Right hex | Hex byte |
|--------|--------------|----------|-----------|----------|
| 1      | `1111 0100`  | F        | 4         | `0xF4`   |
| 2      | `0010 0010`  | 2        | 2         | `0x22`   |
| 3      | `1000 0101`  | 8        | 5         | `0x85`   |
| 4      | `1111 1011`  | F        | B         | `0xFB`   |

**Card 1 share bytes:** `0xF4  0x22  0x85  0xFB`

**Card 2:**

```
0010 0110 │ 1100 0001 │ 0001 0010 │ 0111 0011 │ 0
 byte 1   │  byte 2   │  byte 3   │  byte 4   │ pad bit
```

| Byte # | Binary       | Left hex | Right hex | Hex byte |
|--------|--------------|----------|-----------|----------|
| 1      | `0010 0110`  | 2        | 6         | `0x26`   |
| 2      | `1100 0001`  | C        | 1         | `0xC1`   |
| 3      | `0001 0010`  | 1        | 2         | `0x12`   |
| 4      | `0111 0011`  | 7        | 3         | `0x73`   |

**Card 2 share bytes:** `0x26  0xC1  0x12  0x73`

These are the **share bytes** — four per card here — the numbers we
combine in Step 5. There is no checksum *inside* this bit string: the
checksum is its own separate word (word 6), which we never stitched in.

> **How many share bytes?** The share-byte count is the same on every card
> and equals the length of the recovered body. Here it's 4, and the body
> we recover at the end of Step 5 is 4 bytes. (The original text `"hi"` is
> 2 bytes; the body adds a 1-byte integrity check and a 1-byte kind marker,
> so 4 total — see Step 6.)

### How many body bytes? (read once, skip on retry)

Three body words hold 33 bits = 4 full bytes + 1 padding bit, so the body
*could* in principle be 3 bytes or 4 bytes (3 bytes = 24 bits would leave 9
padding bits; 4 bytes = 32 bits leaves 1). The chela tool decides between
candidate lengths using the kind byte (the last non-zero body byte); by hand
the simpler clue is **what you stored**:

- A text secret of *n* characters gives a body of *n + 2* bytes (a 1-byte
  integrity check, then a 1-byte kind marker — Step 6).
- A BIP-39 seed of 16/20/24/28/32 entropy bytes gives a body of
  18/22/26/30/34 bytes (again +2), plus any passphrase bytes.

For our `"hi"` example the body is 4 bytes (2 characters + 1 integrity byte
+ 1 kind byte), which is the longer of the two candidates here — so we take
all 4 bytes.

### Optional: verify the checksum word

If you want to confirm a card was transcribed correctly *before* spending
an hour on the combine, you can check its checksum word. It's an 11-bit
CRC over the card's decoded numbers; the full by-hand procedure is in
**Appendix C**. It's a long division, not a hash — tedious but elementary.
Most people skip it and just re-read each word carefully against the
wordlist (the unique 4-letter prefixes make substitution errors rare). If
a chela tool is ever available again, typing the words in checks every
card's checksum automatically and names the bad card.

---

# Step 5 — Combine the shares (the real work)

This is the heart of the procedure. We **mathematically combine** the
share bytes from M cards to recover the original body bytes.

The math is **Lagrange interpolation**, in a special arithmetic where
addition is XOR and multiplication is a special "shift-and-XOR" procedure.
Don't worry about why it works — just follow the procedure.

## 5.1 The intuition (skip if you don't care)

When chela split your secret, it built a tiny **recipe** (a polynomial,
in math jargon) for each byte of the body. The recipe was designed so
that:

- Plugging in `x = 0` gives the body byte itself.
- Plugging in each card's `x` gives that card's share byte.

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
| 0x03 | 0xF6     |
| 0x04 | 0xCB     |
| 0x05 | **0x52** |

## 5.3 Compute the Lagrange coefficients

For each card you're using, you need one **Lagrange coefficient**. Call
them `L_a, L_b, …`, one per card, regardless of how many bytes the body is.

The formula, for the card whose coordinate is `x_i`, given you're combining
cards with coordinates `{x_1, x_2, …, x_M}`:

```
L_i = (x_1 × inv(x_i ⊕ x_1)) × (x_2 × inv(x_i ⊕ x_2)) × …
                                                  for every other card
```

(That is: multiply together `(x_j × inv(x_i ⊕ x_j))` for every other card
`j ≠ i`. Skip the case where `j == i`. All multiplications and XORs are in
the special arithmetic.)

For our worked example, M = 2 and we're combining card 1 (`x = 6`) and
card 2 (`x = 3`). Each coefficient has just one term:

```
L_6 = x_3 × inv(x_6 ⊕ x_3) = 3 × inv(6 ⊕ 3) = 3 × inv(5)
L_3 = x_6 × inv(x_3 ⊕ x_6) = 6 × inv(3 ⊕ 6) = 6 × inv(5)
```

(`6 ⊕ 3`: `0110 ⊕ 0011 = 0101 = 5`. Same both ways — XOR doesn't care
about order.) From the inverse table, `inv(5) = 0x52`. So:

- `L_6 = 3 × 0x52`. The multiplier `3` is `11` = 2 + 1, so
  `3 × 0x52 = (0x52 × 2) ⊕ (0x52 × 1)`.
  - `0x52 × 2`: `0x52` = `0101 0010`, leftmost bit 0, shift = `1010 0100`
    = `0xA4`.
  - `0x52 × 1 = 0x52`.
  - XOR: `0xA4 ⊕ 0x52`:
    ```
       0xA4 = 1010 0100
       0x52 = 0101 0010
       ────────────────
       XOR  = 1111 0110 = 0xF6
    ```
  So **`L_6 = 0xF6`**.
- `L_3 = 6 × 0x52`. The multiplier `6` is `110` = 4 + 2, so
  `6 × 0x52 = (0x52 × 4) ⊕ (0x52 × 2)`.
  - `0x52 × 2 = 0xA4` (just computed).
  - `0x52 × 4 = 0xA4 × 2`: `0xA4` = `1010 0100`, leftmost bit 1, shift =
    `0100 1000` = `0x48`, XOR `0x1B`:
    ```
       0x48 = 0100 1000
       0x1B = 0001 1011
       ────────────────
       XOR  = 0101 0011 = 0x53
    ```
  - XOR: `0x53 ⊕ 0xA4`:
    ```
       0x53 = 0101 0011
       0xA4 = 1010 0100
       ────────────────
       XOR  = 1111 0111 = 0xF7
    ```
  So **`L_3 = 0xF7`**.

Write these down — `L_6 = 0xF6`, `L_3 = 0xF7` — you'll use them for every
byte.

## 5.4 Combine each byte of the body

For each byte position of the body (0, 1, 2, 3):

```
body[byte position] = (L_6 × card_1_share[byte position])
                    ⊕ (L_3 × card_2_share[byte position])
                    ⊕ …
                          for every card you have
```

Recall the share bytes from Step 4:

```
card 1 (x = 6):  0xF4  0x22  0x85  0xFB
card 2 (x = 3):  0x26  0xC1  0x12  0x73
```

Our body is 4 bytes, so we do this four times. To save work, first build
the **doubling chains** for both coefficients (each entry is the previous
one `× 2`):

```
L_6 = 0xF6 :  ×1=F6  ×2=F7  ×4=F5  ×8=F1  ×16=F9  ×32=E9  ×64=C9  ×128=89
L_3 = 0xF7 :  ×1=F7  ×2=F5  ×4=F1  ×8=F9  ×16=E9  ×32=C9  ×64=89  ×128=09
```

Spot-check a couple so you trust the chain:

- `0xF6 × 2 = 0xF7` (worked in 5.2).
- `0xF7 × 2`: `1111 0111`, leftmost 1, shift `1110 1110` = `0xEE`, XOR
  `0x1B` = `1111 0101` = `0xF5`. ✓ (this is `L_6 × 4` and `L_3 × 2`).
- `0xC9 × 2` (to get `×128` of `L_6`): `1100 1001`, leftmost 1, shift
  `1001 0010` = `0x92`, XOR `0x1B` = `1000 1001` = `0x89`. ✓

To multiply a coefficient by a share byte, write the share byte in binary,
note which power-of-two columns are 1, and XOR the matching chain entries.

### Byte 0 of the body

- `card_1_share[0]` = `0xF4`, `card_2_share[0]` = `0x26`

**First term: `L_6 × 0xF4`.** `0xF4` = `1111 0100` = 128 + 64 + 32 + 16 + 4.
XOR the `L_6` chain at ×128, ×64, ×32, ×16, ×4 =
`0x89 ⊕ 0xC9 ⊕ 0xE9 ⊕ 0xF9 ⊕ 0xF5`:

```
   0x89 = 1000 1001
   0xC9 = 1100 1001
   0xE9 = 1110 1001
   0xF9 = 1111 1001
   0xF5 = 1111 0101
  ───────────────────
   XOR  = 1010 0101 = 0xA5
```

**Second term: `L_3 × 0x26`.** `0x26` = `0010 0110` = 32 + 4 + 2.
XOR the `L_3` chain at ×32, ×4, ×2 = `0xC9 ⊕ 0xF1 ⊕ 0xF5`:

```
   0xC9 = 1100 1001
   0xF1 = 1111 0001
   0xF5 = 1111 0101
  ───────────────────
   XOR  = 1100 1101 = 0xCD
```

(XOR several bytes by going column by column, counting how many 1s — odd
count → 1, even count → 0.)

**XOR the two terms:**

```
   0xA5 = 1010 0101
   0xCD = 1100 1101
  ───────────────────
   XOR  = 0110 1000 = 0x68
```

**Body byte 0 = `0x68`.** That's the byte for the letter `h`.

### Byte 1 of the body

- `card_1_share[1]` = `0x22`, `card_2_share[1]` = `0xC1`

**First term: `L_6 × 0x22`.** `0x22` = `0010 0010` = 32 + 2.
XOR the `L_6` chain at ×32, ×2 = `0xE9 ⊕ 0xF7`:

```
   0xE9 = 1110 1001
   0xF7 = 1111 0111
  ───────────────────
   XOR  = 0001 1110 = 0x1E
```

**Second term: `L_3 × 0xC1`.** `0xC1` = `1100 0001` = 128 + 64 + 1.
XOR the `L_3` chain at ×128, ×64, ×1 = `0x09 ⊕ 0x89 ⊕ 0xF7`:

```
   0x09 = 0000 1001
   0x89 = 1000 1001
   0xF7 = 1111 0111
  ───────────────────
   XOR  = 0111 0111 = 0x77
```

**XOR the two terms:**

```
   0x1E = 0001 1110
   0x77 = 0111 0111
  ───────────────────
   XOR  = 0110 1001 = 0x69
```

**Body byte 1 = `0x69`.** That's the byte for the letter `i`.

### Byte 2 of the body

- `card_1_share[2]` = `0x85`, `card_2_share[2]` = `0x12`

**First term: `L_6 × 0x85`.** `0x85` = `1000 0101` = 128 + 4 + 1.
XOR the `L_6` chain at ×128, ×4, ×1 = `0x89 ⊕ 0xF5 ⊕ 0xF6`:

```
   0x89 = 1000 1001
   0xF5 = 1111 0101
   0xF6 = 1111 0110
  ───────────────────
   XOR  = 1000 1010 = 0x8A
```

**Second term: `L_3 × 0x12`.** `0x12` = `0001 0010` = 16 + 2.
XOR the `L_3` chain at ×16, ×2 = `0xE9 ⊕ 0xF5`:

```
   0xE9 = 1110 1001
   0xF5 = 1111 0101
  ───────────────────
   XOR  = 0001 1100 = 0x1C
```

**XOR the two terms:**

```
   0x8A = 1000 1010
   0x1C = 0001 1100
  ───────────────────
   XOR  = 1001 0110 = 0x96
```

**Body byte 2 = `0x96`.** This is the **integrity byte** (Step 6 explains it).

### Byte 3 of the body

- `card_1_share[3]` = `0xFB`, `card_2_share[3]` = `0x73`

**First term: `L_6 × 0xFB`.** `0xFB` = `1111 1011` = 128 + 64 + 32 + 16 + 8 + 2 + 1.
XOR the `L_6` chain at ×128, ×64, ×32, ×16, ×8, ×2, ×1 =
`0x89 ⊕ 0xC9 ⊕ 0xE9 ⊕ 0xF9 ⊕ 0xF1 ⊕ 0xF7 ⊕ 0xF6`:

```
   0x89 = 1000 1001
   0xC9 = 1100 1001
   0xE9 = 1110 1001
   0xF9 = 1111 1001
   0xF1 = 1111 0001
   0xF7 = 1111 0111
   0xF6 = 1111 0110
  ───────────────────
   XOR  = 1010 0000 = 0xA0
```

**Second term: `L_3 × 0x73`.** `0x73` = `0111 0011` = 64 + 32 + 16 + 2 + 1.
XOR the `L_3` chain at ×64, ×32, ×16, ×2, ×1 =
`0x89 ⊕ 0xC9 ⊕ 0xE9 ⊕ 0xF5 ⊕ 0xF7`:

```
   0x89 = 1000 1001
   0xC9 = 1100 1001
   0xE9 = 1110 1001
   0xF5 = 1111 0101
   0xF7 = 1111 0111
  ───────────────────
   XOR  = 1010 1011 = 0xAB
```

**XOR the two terms:**

```
   0xA0 = 1010 0000
   0xAB = 1010 1011
  ───────────────────
   XOR  = 0000 1011 = 0x0B
```

**Body byte 3 = `0x0B`.** This is the **kind byte** (Step 6 explains it).

### Result

**Recovered body bytes: `0x68 0x69 0x96 0x0B`.**

---

# Step 6 — Read out the body

You have the body bytes: `0x68 0x69 0x96 0x0B`. Three things happen here.

## First: split off the kind byte

**The last body byte is the *kind byte*** — it names what the rest of the
body is. Strip it off and look it up:

| Kind byte | What the rest of the body is               |
|-----------|--------------------------------------------|
| `0x01`    | BIP-39 seed, 12 words (16 B entropy), no passphrase |
| `0x02`    | BIP-39 seed, 15 words (20 B entropy), no passphrase |
| `0x03`    | BIP-39 seed, 18 words (24 B entropy), no passphrase |
| `0x04`    | BIP-39 seed, 21 words (28 B entropy), no passphrase |
| `0x05`    | BIP-39 seed, 24 words (32 B entropy), no passphrase |
| `0x06`    | BIP-39 seed, 12 words, with passphrase     |
| `0x07`    | BIP-39 seed, 15 words, with passphrase     |
| `0x08`    | BIP-39 seed, 18 words, with passphrase     |
| `0x09`    | BIP-39 seed, 21 words, with passphrase     |
| `0x0A`    | BIP-39 seed, 24 words, with passphrase     |
| `0x0B`    | Text                                       |

For our example the kind byte is `0x0B` → **Text**. (Had the kind byte been
some value not in this table, you'd have mis-read a word or picked the wrong
body length — go back and check.) That leaves `0x68 0x69 0x96`.

The kind byte means **you don't have to remember what you stored** — the
cards tell you. (You can still sanity-check against what you expected.)

## Then: strip the integrity byte

The next byte in from the end — here `0x96` — is the **integrity byte**. It's
a one-byte check the chela tool computes with SHA-256 over the rest of the
body, so that combining the *wrong* set of cards is caught instead of handing
back a plausible-but-wrong secret. By hand you **can't** recompute it (it
needs SHA-256), so just strip it off, the same way you skipped the checksum
word. What remains is the **payload**: `0x68 0x69`.

(The SPEC calls the generation tag the *nonce* and this integrity byte the
*integrity tag*; the names differ but they're the same two fields.)

## If the kind is text (0x0B)

Look up each payload byte in the **ASCII table** (Appendix B). For our
example:

- `0x68` → letter `h`
- `0x69` → letter `i`

**Recovered secret: `"hi"`** ✓

(For text with non-English characters — accented letters, emoji — the
bytes use a slightly more involved encoding called UTF-8. ASCII covers
all the unaccented Latin letters, digits, and common punctuation; for
anything else, any UTF-8 lookup chart will translate the bytes.)

## If the kind is a BIP-39 seed (0x01–0x0A)

The payload (body minus the integrity byte and the kind byte) is the raw
**entropy** the BIP-39 mnemonic encodes, **possibly followed by a
passphrase** as UTF-8 bytes.
The kind byte already told you the word count and whether there's a
passphrase; the entropy length is the cross-check:

| Kind byte         | Entropy bytes | BIP-39 word count |
|-------------------|---------------|-------------------|
| `0x01` / `0x06`   | 16            | 12 words          |
| `0x02` / `0x07`   | 20            | 15 words          |
| `0x03` / `0x08`   | 24            | 18 words          |
| `0x04` / `0x09`   | 28            | 21 words          |
| `0x05` / `0x0A`   | 32            | 24 words          |

For the no-passphrase kinds (`0x01`–`0x05`) the payload is exactly the
entropy. For the with-passphrase kinds (`0x06`–`0x0A`) the first
16/20/24/28/32 bytes are the entropy and **everything after** is the
passphrase, UTF-8 encoded.

(So, counting the integrity and kind bytes, a 24-word seed with no passphrase
recovers as a 34-byte body: 32 entropy + 1 integrity + 1 kind. A 12-word seed
with a 4-character passphrase recovers as 16 + 4 + 1 + 1 = 22 bytes.)

### Getting the entropy into your wallet

The payload bytes you recovered **are** the BIP-39 entropy. Every major
wallet accepts entropy in one of two ways:

- **Import as hex / raw entropy.** Look for "import from hex", "raw seed",
  or an "advanced" import option in your wallet. Type the entropy bytes as
  hex (two characters per byte). This is the easiest path and works for
  any word count.
- **Import as 12/24 words.** The wallet wants the actual BIP-39 mnemonic.
  Turning entropy into the mnemonic needs one SHA-256 computation (BIP-39's
  own checksum) — which you'd do with a tool, at which point you'd
  presumably just use chela. If you're stuck without any tool, the
  **brute-force shortcut** for a 12-word mnemonic is to try all 16
  possible last-words: BIP-39's checksum is only 4 bits → 16 candidates →
  exactly one makes the wallet accept the phrase.

If there's a passphrase (kind `0x06`–`0x0A`): the bytes **after** the
entropy are the passphrase, UTF-8 encoded. The wallet asks for it
separately ("BIP-39 passphrase", "25th word", or "seed extension").

---

# When something goes wrong

| Symptom                                              | Likely cause                                                | Action                                                                                       |
|------------------------------------------------------|-------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| Reserved bit (last bit of word 1) isn't 0            | Metadata word mis-read                                      | Re-check the first word against the wordlist; you have its 11 bits wrong                      |
| Padding bits in Step 4 aren't all 0                  | A body word mis-typed                                       | Re-check that card's body words (use 4-letter prefix matching)                                |
| Recovered last body byte isn't `0x01`–`0x0B`         | A word substitution, or wrong body length picked            | Re-check every word; if two body lengths fit, try the other length; redo Step 5 on a fresh sheet |
| Recovered text/seed is garbage                       | An undetected word substitution (one valid word swapped for another), OR a foreign card mixed in | Re-check every word; confirm all cards show the **same generation tag** (word 2); redo Step 5 |
| Generation tags differ between cards                 | Cards are from independent makings                          | Recovery impossible from this mix. Find more cards with the matching tag.                     |
| You have fewer than M cards                          | Not enough cards                                            | Recovery impossible. Find at least M cards.                                                   |
| You're not sure if your payload was text or a seed   | —                                                           | You don't have to guess — the recovered last body byte is the kind (`0x0B` = text, `0x01`–`0x0A` = seed). |

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

For the "decode payload as text" step. Only the printable subset is shown
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

# Appendix C — Verifying a card's checksum word (optional)

The last word of each card is an **11-bit CRC** — a checksum that catches
a mistyped word. It's a long division in binary, not a hash, so you *can*
do it by hand. It tells you only whether the card was copied correctly; it
plays no part in recovering the secret, so skip it unless you want the
extra confidence.

## What's checked

The CRC is computed over the card's decoded values, in this byte order:

```
[ x ] [ M ] [ tag high byte ] [ tag low byte ] [ share byte 0 ] [ share byte 1 ] …
```

`x` and `M` are one byte each (the decoded coordinate and threshold, not
the raw 5-bit fields). The **tag** is the generation tag as a 2-byte
number, high byte first. Then every share byte from Step 4, in order.

For card 1 of our example (`x = 6`, `M = 2`, tag `0x02C9`, share bytes
`0xF4 0x22 0x85 0xFB`):

```
06  02  02  C9  F4  22  85  FB
```

## The long division

The CRC uses the generator number `0x307` = `011 0000 0111` (11 bits below
an implied leading 1, i.e. the 12-bit pattern `1 0110 0000 111`). The
recipe:

1. Lay out all the input bytes as one long string of bits, MSB-first.
2. Append **11 zero bits** on the right.
3. Run an 11-bit register starting at 0. Feed in the bits one at a time,
   most-significant first. For each bit:
   - Look at the register's top bit (bit 10) **before** shifting.
   - Shift the register left by 1, drop in the next input bit at the
     bottom, and keep only the low 11 bits.
   - If the top bit you noted was 1, XOR the register with `0x307`.
4. After the last appended zero bit, the 11-bit register **is** the CRC.

Equivalently (the byte-at-a-time form chela uses): start the register at
0; for each input byte, XOR `(byte << 3)` into the register, then do 8
rounds of "note top bit, shift left within 11 bits, XOR `0x307` if the top
bit was 1".

Compare the result to the card's last word. **Match** → the card's
`x`, `M`, tag, and share bytes were all transcribed correctly. **No
match** → at least one word on that card is wrong; re-read them.

> **Sanity-check your CRC routine first.** Run it over the ASCII bytes of
> `"123456789"` (that's `31 32 33 34 35 36 37 38 39`). A correct CRC-11
> gives `0x061`. If you get that, your hand-procedure is right; then check
> your real cards.

For reference, the checksum words of the example cards are: card 1
(`film`) = 690 = `0x2B2`; card 2 (`produce`) = 1373 = `0x55D`.

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
- **generation tag** — an 11-bit random number chosen once when a set of
  cards is made, written into word 2 of every card from that making (and
  printed as 4 hex on the label). It groups cards that belong together; it
  is *not* derived from the secret, so two makings of the same secret get
  different tags and won't (and shouldn't) combine. A different tag marks a
  foreign card.
- **kind byte** — the last byte of the recovered body. It names the
  payload type (`0x0B` = text, `0x01`–`0x0A` = the various BIP-39 seed
  variants) and is stripped off before you read the payload.
- **share** — one card's worth of data. By itself, a single card tells you
  nothing about the secret. Combine M cards to recover.
- **threshold (M)** — the minimum number of cards needed to recover.
- **coordinate (x)** — each card's random number in 1–32, stored in its
  metadata word. It is the card's place in the Shamir math, not its
  position in the set.
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
- **CRC** — the 11-bit checksum in each card's last word; catches a
  mistyped word (Appendix C). It is a long division, not a hash.

---

# Where to go from here

For an engineer's reference of chela's wire formats (for reimplementing
the tool in another language), see [SPEC.md](./SPEC.md).

For the chela tool's normal usage, see [README.md](./README.md) and the
user-facing recovery walkthrough at [RECOVERY.md](./RECOVERY.md).
</content>
</invoke>
