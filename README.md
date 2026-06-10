# chela

[![Crates.io](https://img.shields.io/crates/v/chela.svg)](https://crates.io/crates/chela)
[![Docs.rs](https://docs.rs/chela/badge.svg)](https://docs.rs/chela)
[![CI](https://github.com/SecretSplitKit/Chela/workflows/CI/badge.svg)](https://github.com/SecretSplitKit/Chela/actions)

![Chela](./chela.png)

**chela** splits one secret - a crypto wallet's recovery phrase, or any short
password - into a set of paper cards, so that any *M* of the *N* cards rebuild it and
any fewer reveal nothing at all. Make five cards and require three: two can be lost or
destroyed and you can still recover, while anyone who finds one or two learns nothing.

It is built for inheritance and disaster recovery. Hand the cards to family or trusted
friends; the secret comes back only when enough of them bring their cards together.
Each card is a short list of ordinary words, and a card recovers from those words alone
- no account, no server, nothing kept online.

The method is Shamir's Secret Sharing, the standard approach for exactly this problem.
chela implements it - and everything it needs, the field arithmetic, BIP-39, the
checksums - from scratch in this repository, with no outside dependencies, so every
line can be read and checked. **[SPEC.md](./SPEC.md)** explains how it works, in plain
language and in full detail.

## I was handed a card and need to recover a secret

You don't need to be technical, and you don't need to install anything.

> **Take your time.** The paper cards in your hand are the only thing that can recover
> the secret, and they don't expire. If you need to come back tomorrow, they will still
> work tomorrow.

1. **Find any computer with a web browser** - Windows, Mac, or Linux, anything from the
   last decade.
2. **Download the recovery program.** On the
   [latest release](https://github.com/SecretSplitKit/Chela/releases/latest), under
   *Assets*, click the file whose name ends in **`-web.html`**. Save it to your Desktop
   or Downloads.
3. **Open it.** Double-click the file; it opens in your browser as chela's main screen.
4. **Click "Recover from shares"** and follow the wizard. It asks for one card at a
   time, then shows the recovered secret.
5. **You need a minimum number of cards.** The card itself says how many: look for the
   *"M of N"* on the front (for example *"3 of 5"* means any 3 of the 5 cards).

**Step by step, with screenshots: [RECOVERY.md](./RECOVERY.md).** And if every copy of
chela ever vanished, you can still recover by hand with pen and paper:
**[MANUAL_RECOVERY.md](./MANUAL_RECOVERY.md).**

> **Privacy:** chela runs entirely inside your browser. Nothing is sent over the
> internet. To be extra careful, turn off Wi-Fi before you start - it works the same
> offline.

## I want to make a backup

Pick two numbers: how many cards to make (*N*) and how many it should take to recover
(*M*). "5 cards, any 3" is a common choice. Then:

1. Download the **`-web.html`** file from the
   [latest release](https://github.com/SecretSplitKit/Chela/releases/latest) and open
   it in your browser (the same file used for recovery).
2. Choose to **split a secret**, enter your wallet phrase or password, set *M* and *N*,
   and add a name and the cardholders if you want them printed.
3. **Print the cards** (Print → Save as PDF works well), give one to each person, and
   store them somewhere safe. Keep the *whole card*: the words are what recover the
   secret, and the printed label is there to help.

Prefer a terminal? The interactive wizard and the scriptable CLI are under
[Build from source](#build-from-source).

## What is printed on a card

```
CHELA-<NONCE>-<x>-<M>-<N>-<W>
word1 word2 ... wordW
```

The words on the second line are the secret in split form, and **a card recovers from
its words alone.** The top line just restates the same details for people to read, and
it is cross-checked against the words. One card on its own reveals nothing about the
secret - not even what kind of secret it is. The exact format is in
[SPEC.md](./SPEC.md).

## Understanding and checking chela

chela is meant to be a tool you can trust without taking anyone's word for it.

- **[SPEC.md](./SPEC.md)** - what chela does and exactly how a card is built, from
  first principles and precise enough to reimplement in another language.
- **[AUDITORS.md](./AUDITORS.md)** - a guided walk through the cryptographic code, file
  by file.
- **[MANUAL_RECOVERY.md](./MANUAL_RECOVERY.md)** - recover a secret by hand, on paper,
  with no computer at all.
- **[AGENTS.md](./AGENTS.md)** - for pointing an AI assistant at the repository to check
  that it is sound and well packaged.

## Build from source

```sh
git clone https://github.com/SecretSplitKit/Chela.git
cd chela
cargo build --release --workspace
cargo test --workspace
```

| Path | What it is |
|---|---|
| `target/release/chela` | Interactive wizard (terminal) |
| `target/release/chela-cli` | Scriptable command-line tool |
| `target/release/chela-bundle` | Builds the standalone `chela.html` |

**Wizard** - `./target/release/chela` splits a seed or password, recovers, or quits.
The split wizard ends by offering a print-ready HTML backup; the recover wizard stops at
the threshold, asks for confirmation before showing the secret, and clears the screen on
exit.

**CLI:**

```sh
# Split a 24-word seed (+ optional passphrase) into 5 cards, any 3 to recover.
./target/release/chela-cli split --mnemonic "abandon abandon ... art" \
  --passphrase "optional passphrase" -m 3 -n 5 --paper backup.html > shares.txt

# Split arbitrary text.
./target/release/chela-cli split --text "correct horse battery staple" -m 2 -n 4 > shares.txt

# Recover from any threshold of cards.
./target/release/chela-cli recover < shares.txt
```

**Standalone browser file** - `./target/release/chela-bundle chela.html` writes one
self-contained HTML file. Open it in any modern browser; no install, no network.

## Verifying a release

Every release artifact is signed with [minisign](https://jedisct1.github.io/minisign/)
and built reproducibly: rebuilding a given source tag on the same target and toolchain
yields byte-identical binaries, which the release workflow checks with a two-pass build.

`SHA256SUMS` and `SHA256SUMS.minisig` are attached to every release. Save the public key
below as `chela.pub`, then:

```sh
minisign -V -p chela.pub -m SHA256SUMS
sha256sum -c SHA256SUMS
```

### Public key

```text
untrusted comment: minisign public key DDD078AB7F7BE629
RWQp5nt/q3jQ3XBn/Ni5bQNj6MehmwvQTYgdBQ9zxTTgc4+qyJfazk9x
```

### Reproduce a release locally

```sh
git checkout <tag>
SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) \
  RUSTFLAGS="-C link-arg=-Wl,--build-id=none" \
  cargo build --release --locked
sha256sum target/release/chela target/release/chela-cli target/release/chela-bundle
```

Compare against the release's `SHA256SUMS`. The RUSTFLAGS above are for Linux; macOS
uses `-Wl,-no_uuid` and Windows MSVC uses `/Brepro`. The release workflow
(`.github/workflows/release.yml`) is the authoritative recipe.

## License

Dual-licensed at your option:

- Apache 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT ([LICENSE-MIT](LICENSE-MIT))
