# chela

[![Crates.io](https://img.shields.io/crates/v/chela.svg)](https://crates.io/crates/chela)
[![Docs.rs](https://docs.rs/chela/badge.svg)](https://docs.rs/chela)
[![CI](https://github.com/SecretSplitKit/Chela/workflows/CI/badge.svg)](https://github.com/SecretSplitKit/Chela/actions)

![Chela](./chela.png)

**chela** splits a BIP-39 wallet seed (or any short text password) into `N` shares,
any `M` of which can reconstruct the original. Designed for inheritance and disaster
recovery — distribute shares across family members; recover the wallet (or a
password-manager master password) when any threshold of shareholders cooperate.

The cryptographic core has no external dependencies beyond the OS RNG: SHA-256,
constant-time GF(2^8), Shamir's split/combine, and BIP-39 are implemented in this
repository so every line can be audited in-tree. See [AUDITORS.md](./AUDITORS.md)
for provenance and a guided walk-through.

## Recovering shares — for family members

You don't need to be technical. You don't need to install anything.

> **Take your time.** The paper cards in your hand are the only
> thing that can recover the secret, they don't expire. If you need to come back
> tomorrow, the cards will still work tomorrow.

### Quick version — 5 steps

1. **Find a Windows, Mac, or Linux computer with a web browser.** Any modern
   computer from the last 10 years works.
2. **Download the recovery program.** Go to the
   [latest release](https://github.com/SecretSplitKit/Chela/releases/latest),
   scroll to the *Assets* section, and click the file ending in **`-web.html`**
   (for example `chela-v1.0.0-web.html`). Save it somewhere you'll remember — your
   Desktop or Downloads is fine.
3. **Open the file you just downloaded.** Double-click it. Your web browser will
   open with chela's main screen.
4. **Click "Recover from shares"** and follow the wizard. It asks you for one card
   at a time, then shows the recovered secret on the next screen.
5. **You need a minimum number of cards** to recover. The card itself tells you how
   many — look for the "M of N" notation on the front (e.g. *"3 of 5"* means any 3
   of the 5 cards is enough).

**Full walk-through with screenshots and troubleshooting:
[RECOVERY.md](./RECOVERY.md).**

> **Your privacy:** chela runs entirely inside your web browser. Nothing is sent
> over the internet. If you want to be extra cautious, you can disconnect from Wi-Fi
> *before* you start the recovery — it still works the same way.

## Build

```sh
git clone https://github.com/SecretSplitKit/Chela.git
cd chela
cargo build --release --workspace
```

Produces:

| Path                          | Purpose                                      |
|-------------------------------|----------------------------------------------|
| `target/release/chela`        | Interactive wizard TUI                       |
| `target/release/chela-cli`    | Non-interactive CLI for scripting / piping   |
| `target/release/chela-serve`  | Localhost browser UI                         |
| `target/release/chela-bundle` | Builds the standalone `chela.html`           |

```sh
cargo test --workspace
```

## Run — wizard TUI

```sh
./target/release/chela
```

Main menu: split a BIP-39 seed, split a text password, recover, or quit. The split
wizard ends with an offer to save a print-ready HTML paper backup — open in any
browser and **Print → Save as PDF** for a paper inheritance kit. The recover wizard
auto-stops at threshold, requires explicit confirmation before revealing the secret,
and clears the screen on exit.

## Run — scriptable CLI

```sh
# Split a 24-word seed + optional passphrase into 5 shares (threshold 3).
./target/release/chela-cli split \
  --mnemonic "abandon abandon abandon ... art" \
  --passphrase "optional passphrase" \
  -m 3 -n 5 --paper backup.html > shares.txt

# Split arbitrary text.
./target/release/chela-cli split --text "correct horse battery staple" -m 2 -n 4 > shares.txt

# Recover from any threshold subset.
./target/release/chela-cli recover < shares.txt
```

## Run — browser

```sh
./target/release/chela-serve              # localhost server
./target/release/chela-bundle chela.html  # standalone, offline file
```

The standalone bundle is one self-contained HTML file. Open it in any modern browser
— no install, no network.

## Share format

Each share is two lines:

```
CHELA-<ID>-<x>-<M>-<N>-<W>
word1 word2 ... wordW
```

- `<ID>` — 4-hex-char set tag; recovery uses it to detect cards from different splits.
- `<x>` — this share's number (1..N).
- `<M>` / `<N>` — recovery threshold and total share count.
- `<W>` — word count on line 2 (printed for hand-typing).
- words — drawn from the BIP-39 English wordlist; count depends on payload size.

Full wire-format spec for a re-implementation in another language:
[SPEC.md](./SPEC.md). To recover from cards if chela itself is unavailable:
[MANUAL_RECOVERY.md](./MANUAL_RECOVERY.md).

A single share alone reveals nothing about the secret.

## Verifying a release

Every artifact on the [releases page](https://github.com/SecretSplitKit/Chela/releases)
is signed with [minisign](https://jedisct1.github.io/minisign/) and reproducibly built
— the same source tag will produce byte-identical binaries.

### Where to find the hashes

Each release publishes SHA-256 hashes in **three places** so you can verify without
trusting any single channel:

1. **Inlined in the release notes** — every release body on
   [the releases page](https://github.com/SecretSplitKit/Chela/releases) ends with a
   ```` ``` ```` block holding the full `SHA256SUMS` content. Quickest visual check.
2. **`SHA256SUMS` + `SHA256SUMS.minisig`** — attached as files on every release.
   One signed document covering every artifact:

   ```sh
   minisign -V -p chela.pub -m SHA256SUMS
   sha256sum -c SHA256SUMS
   ```

3. **Per-artifact `<name>.sha256`** — attached alongside each archive for tools that
   prefer one file per artifact.

`chela-serve` additionally prints `SHA-256(chela.html)` and `SHA-256(chela.wasm)`
to stderr at startup so you can cross-check the embedded bundle against the
release values without leaving your terminal.

### Public key

(Same value duplicated in `AUDITORS.md`.)

```text
RWQ_REPLACE_ME_WITH_ACTUAL_PUBLIC_KEY_AFTER_GENERATION
```

### Verify

```sh
minisign -V -p chela.pub -m chela-v1.0.0-x86_64-apple-darwin.tar.gz
```

### Reproduce a release locally

```sh
git checkout v1.0.0
SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) \
  RUSTFLAGS="-C link-arg=-Wl,--build-id=none" \
  cargo build --release --locked
sha256sum target/release/chela target/release/chela-cli \
          target/release/chela-serve target/release/chela-bundle
```

Compare against the `SHA256SUMS` file on the release. RUSTFLAGS above are for Linux;
macOS uses `-Wl,-no_uuid` and Windows MSVC uses `/Brepro`. The release workflow
(`.github/workflows/release.yml`) is the authoritative recipe.

## License

Dual-licensed at your option:

- Apache 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT ([LICENSE-MIT](LICENSE-MIT))

See [CONTRIBUTING.md](CONTRIBUTING.md).
