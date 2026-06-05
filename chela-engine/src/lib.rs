//! High-level split/recover API: bundle the secret, SSS-split, encode shares, and the inverse.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use chela_sss::{combine, split, OsRng, RandomSource, SssError};

/// Public-API view of a share's payload kind. The finer-grained internal kind byte
/// (word count, passphrase presence) is appended to the body and split with the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    Bip39,
    Text,
}

/// Output mode: which wordlist the shares are rendered in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// BIP-0039 English wordlist (2048 words).
    Bip39Wordlist,
}

const MAX_PASSPHRASE_LEN: usize = 255;
const MAX_TEXT_LEN: usize = 255;

/// Minimum reconstruction threshold. A threshold of 1 (any single share rebuilds the
/// secret) gives no secret-sharing security, so the engine refuses to produce it.
pub const MIN_THRESHOLD: u8 = 2;

/// Maximum share count / x-range in v2: x ∈ 1..=32 (5-bit field, x = field + 1).
pub const MAX_SHARES: u8 = 32;

/// Draw `count` distinct x-coordinates in `1..=32` from the CSPRNG. Each draw is a raw
/// 5-bit field (`0..31`, a power of two — uniform, no modulo bias); `x = field + 1`.
fn sample_distinct_x(count: u8, rng: &mut dyn RandomSource) -> Result<Vec<u8>, EngineError> {
    if count == 0 || count > MAX_SHARES {
        return Err(EngineError::InvalidInput("total must be 1..=32"));
    }
    let count = usize::from(count);
    let mut xs: Vec<u8> = Vec::with_capacity(count);
    let mut byte = [0u8; 1];
    while xs.len() < count {
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

/// Bundle `kind` byte values (0x01..0x0B).
mod kind {
    pub(super) const BIP39_NO_PASS_12: u8 = 0x01;
    pub(super) const BIP39_NO_PASS_15: u8 = 0x02;
    pub(super) const BIP39_NO_PASS_18: u8 = 0x03;
    pub(super) const BIP39_NO_PASS_21: u8 = 0x04;
    pub(super) const BIP39_NO_PASS_24: u8 = 0x05;
    pub(super) const BIP39_PASS_12: u8 = 0x06;
    pub(super) const BIP39_PASS_15: u8 = 0x07;
    pub(super) const BIP39_PASS_18: u8 = 0x08;
    pub(super) const BIP39_PASS_21: u8 = 0x09;
    pub(super) const BIP39_PASS_24: u8 = 0x0A;
    pub(super) const TEXT: u8 = 0x0B;
}

/// Decoded view of a `kind` byte for `parse_bundle`.
#[derive(Debug, Clone, Copy)]
enum DecodedKind {
    Bip39 {
        entropy_bytes: usize,
        word_count: usize,
        has_passphrase: bool,
    },
    Text,
}

fn decode_kind_byte(b: u8) -> Option<DecodedKind> {
    match b {
        kind::BIP39_NO_PASS_12 => Some(DecodedKind::Bip39 {
            entropy_bytes: 16,
            word_count: 12,
            has_passphrase: false,
        }),
        kind::BIP39_NO_PASS_15 => Some(DecodedKind::Bip39 {
            entropy_bytes: 20,
            word_count: 15,
            has_passphrase: false,
        }),
        kind::BIP39_NO_PASS_18 => Some(DecodedKind::Bip39 {
            entropy_bytes: 24,
            word_count: 18,
            has_passphrase: false,
        }),
        kind::BIP39_NO_PASS_21 => Some(DecodedKind::Bip39 {
            entropy_bytes: 28,
            word_count: 21,
            has_passphrase: false,
        }),
        kind::BIP39_NO_PASS_24 => Some(DecodedKind::Bip39 {
            entropy_bytes: 32,
            word_count: 24,
            has_passphrase: false,
        }),
        kind::BIP39_PASS_12 => Some(DecodedKind::Bip39 {
            entropy_bytes: 16,
            word_count: 12,
            has_passphrase: true,
        }),
        kind::BIP39_PASS_15 => Some(DecodedKind::Bip39 {
            entropy_bytes: 20,
            word_count: 15,
            has_passphrase: true,
        }),
        kind::BIP39_PASS_18 => Some(DecodedKind::Bip39 {
            entropy_bytes: 24,
            word_count: 18,
            has_passphrase: true,
        }),
        kind::BIP39_PASS_21 => Some(DecodedKind::Bip39 {
            entropy_bytes: 28,
            word_count: 21,
            has_passphrase: true,
        }),
        kind::BIP39_PASS_24 => Some(DecodedKind::Bip39 {
            entropy_bytes: 32,
            word_count: 24,
            has_passphrase: true,
        }),
        kind::TEXT => Some(DecodedKind::Text),
        _ => None,
    }
}

/// Pick the kind byte for a BIP-39 split. `None` outside 12/15/18/21/24-word mnemonics.
fn encode_bip39_kind_byte(word_count: usize, has_passphrase: bool) -> Option<u8> {
    let base = match word_count {
        12 => kind::BIP39_NO_PASS_12,
        15 => kind::BIP39_NO_PASS_15,
        18 => kind::BIP39_NO_PASS_18,
        21 => kind::BIP39_NO_PASS_21,
        24 => kind::BIP39_NO_PASS_24,
        _ => return None,
    };
    Some(if has_passphrase { base + 5 } else { base })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    InvalidInput(&'static str),
    Sss(SssError),
    Bip39(chela_bip39::Bip39Error),
    BundleTooLarge,
    /// Combined body's trailing kind byte is invalid or its length doesn't fit — usually
    /// the wrong share subset.
    BundleCorrupt,
    /// Shares disagree on nonce/scheme/threshold/body length — different generation or corrupt.
    MismatchedShares,
    /// Share's CRC-11 doesn't verify, or its words are malformed.
    ShareCorrupt,
    /// Words used in the share aren't valid BIP-39 wordlist entries.
    UnknownWord,
    /// Fewer shares than the threshold.
    InsufficientShares,
    Utf8,
}

impl core::fmt::Display for EngineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidInput(msg) => f.write_str(msg),
            Self::Sss(e) => e.fmt(f),
            Self::Bip39(e) => e.fmt(f),
            Self::BundleTooLarge => f.write_str("the secret is too large to split"),
            Self::BundleCorrupt => f.write_str(
                "the recovered secret is invalid — this is usually the wrong set of shares",
            ),
            Self::MismatchedShares => f.write_str(
                "these shares are not from the same split (different nonce or threshold) — do not mix shares from two separate splits",
            ),
            Self::ShareCorrupt => f.write_str(
                "a share failed its built-in checksum: one of its words was mistyped, or the share has the wrong number of words",
            ),
            Self::UnknownWord => {
                f.write_str("a share contains a word that is not in the BIP-39 word list (check spelling)")
            }
            Self::InsufficientShares => {
                f.write_str("not enough shares to recover: you provided fewer than the threshold this secret needs")
            }
            Self::Utf8 => f.write_str("the recovered secret is not valid UTF-8 text"),
        }
    }
}

impl From<SssError> for EngineError {
    fn from(e: SssError) -> Self {
        Self::Sss(e)
    }
}

impl From<chela_bip39::Bip39Error> for EngineError {
    fn from(e: chela_bip39::Bip39Error) -> Self {
        Self::Bip39(e)
    }
}

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
    /// BIP-39 wordlist indices (each in `0..2048`).
    pub word_indices: Vec<u16>,
}

impl Drop for Share {
    fn drop(&mut self) {
        // `word_indices` is share material: a threshold of shares reconstructs the secret.
        chela_primitives::zeroize::Zeroize::zeroize(&mut self.word_indices);
    }
}

/// What `split` was given as input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitInput<'a> {
    Bip39 {
        mnemonic: &'a str,
        passphrase: &'a str,
    },
    Text {
        text: &'a str,
    },
}

/// What `recover` reconstructs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveredSecret {
    Bip39 {
        mnemonic: String,
        passphrase: String,
    },
    Text {
        text: String,
    },
}

impl Drop for RecoveredSecret {
    fn drop(&mut self) {
        use chela_primitives::zeroize::Zeroize as _;
        match self {
            RecoveredSecret::Bip39 {
                mnemonic,
                passphrase,
            } => {
                mnemonic.zeroize();
                passphrase.zeroize();
            }
            RecoveredSecret::Text { text } => text.zeroize(),
        }
    }
}

/// Build the payload bytes SSS will split, plus the `kind_byte`. The kind byte is appended
/// to the body by [`build_bundle_v2`], never carried out of band.
fn build_bundle(input: &SplitInput<'_>) -> Result<(Vec<u8>, u8), EngineError> {
    match input {
        SplitInput::Bip39 {
            mnemonic,
            passphrase,
        } => {
            // `indices` and `entropy` are secret-derived. Wrap them in `Zeroizing` so they
            // wipe on every exit — including the `?` early returns below, which a mistyped
            // word of a real seed (bad BIP-39 checksum) reaches.
            let indices = chela_primitives::zeroize::Zeroizing::new(
                mnemonic
                    .split_whitespace()
                    .map(|w| chela_bip39::word_to_index(w).ok_or(EngineError::UnknownWord))
                    .collect::<Result<Vec<u16>, _>>()?,
            );
            let entropy_bytes = chela_bip39::entropy_bytes_for_words(indices.len()).ok_or(
                EngineError::InvalidInput("not a 12/15/18/21/24-word mnemonic"),
            )?;
            let word_count = indices.len();
            let mut entropy = chela_primitives::zeroize::Zeroizing::new(vec![0u8; entropy_bytes]);
            chela_bip39::decode_indices_to_entropy(&indices[..], &mut entropy[..])?;

            if passphrase.len() > MAX_PASSPHRASE_LEN {
                return Err(EngineError::InvalidInput("passphrase exceeds 255 bytes"));
            }

            let has_passphrase = !passphrase.is_empty();
            let kind_byte = encode_bip39_kind_byte(word_count, has_passphrase)
                .expect("word_count validated by entropy_bytes_for_words above");

            // Pre-size `body` to its final length so `extend_from_slice` cannot trigger a
            // Vec reallocation that would orphan an un-wiped, entropy-holding buffer.
            let passphrase_bytes = if has_passphrase {
                passphrase.as_bytes()
            } else {
                &[][..]
            };
            let mut body: Vec<u8> = Vec::with_capacity(entropy_bytes + passphrase_bytes.len());
            body.extend_from_slice(&entropy[..]);
            body.extend_from_slice(passphrase_bytes);
            Ok((body, kind_byte))
        }
        SplitInput::Text { text } => {
            if text.is_empty() {
                return Err(EngineError::InvalidInput("text payload cannot be empty"));
            }
            if text.len() > MAX_TEXT_LEN {
                return Err(EngineError::InvalidInput("text exceeds 255 bytes"));
            }
            Ok((text.as_bytes().to_vec(), kind::TEXT))
        }
    }
}

/// Build the full SSS body: the payload bytes with the `kind_byte` appended. The kind is
/// split with the secret (hidden per share) and read back from the recovered body.
fn build_bundle_v2(input: &SplitInput<'_>) -> Result<(Vec<u8>, u8), EngineError> {
    let (mut body, kind_byte) = build_bundle(input)?;
    body.push(kind_byte);
    Ok((body, kind_byte))
}

/// Whether `body_len` is a valid payload length for the given decoded kind.
fn body_len_fits(dec: DecodedKind, body_len: usize) -> bool {
    match dec {
        DecodedKind::Bip39 {
            entropy_bytes,
            has_passphrase,
            ..
        } => {
            if has_passphrase {
                body_len > entropy_bytes && body_len <= entropy_bytes + MAX_PASSPHRASE_LEN
            } else {
                body_len == entropy_bytes
            }
        }
        DecodedKind::Text => (1..=MAX_TEXT_LEN).contains(&body_len),
    }
}

/// Recover the secret from the SSS-combined body. The kind byte is the final body byte.
fn parse_bundle(body: &[u8]) -> Result<RecoveredSecret, EngineError> {
    let (&kind_byte, payload) = body.split_last().ok_or(EngineError::BundleCorrupt)?;
    let dec = decode_kind_byte(kind_byte).ok_or(EngineError::BundleCorrupt)?;
    if !body_len_fits(dec, payload.len()) {
        return Err(EngineError::BundleCorrupt);
    }
    interpret_body(dec, payload)
}

fn interpret_body(dec: DecodedKind, body: &[u8]) -> Result<RecoveredSecret, EngineError> {
    match dec {
        DecodedKind::Bip39 {
            entropy_bytes,
            word_count,
            has_passphrase,
        } => {
            let entropy = &body[..entropy_bytes];
            let passphrase_bytes = &body[entropy_bytes..];

            let mut indices = vec![0u16; word_count];
            let n = chela_bip39::encode_entropy_to_indices(entropy, &mut indices)?;
            let words: Vec<&str> = indices[..n]
                .iter()
                .map(|&i| chela_bip39::index_to_word(i).expect("encode returns valid indices"))
                .collect();
            let mnemonic = words.join(" ");
            chela_primitives::zeroize::Zeroize::zeroize(&mut indices);

            let passphrase = if has_passphrase {
                core::str::from_utf8(passphrase_bytes)
                    .map_err(|_| EngineError::Utf8)?
                    .to_owned()
            } else {
                // body_len_fits guarantees passphrase_bytes is empty in this branch.
                String::new()
            };

            Ok(RecoveredSecret::Bip39 {
                mnemonic,
                passphrase,
            })
        }
        DecodedKind::Text => {
            let text = core::str::from_utf8(body)
                .map_err(|_| EngineError::Utf8)?
                .to_owned();
            Ok(RecoveredSecret::Text { text })
        }
    }
}

/// Encode one share's words: [X:5|M:5|reserved:1] ‖ [nonce:11] ‖ Y-words ‖ [CRC-11].
/// `share_bytes` is this share's SSS output (the Y values).
fn encode_share_bip39_v2(share_bytes: &[u8], nonce: u16, x: u8, threshold: u8) -> Vec<u16> {
    let x_field = u16::from(x - 1) & 0x1F; // 1..32 -> 0..31
    let m_field = u16::from(threshold - 2) & 0x1F; // 2..32 -> 0..30
    let word0 = (x_field << 6) | (m_field << 1); // reserved bit (bit 0) = 0
    let word1 = nonce & 0x7FF;

    let body_bits = share_bytes.len() * 8;
    let y_word_count = body_bits.div_ceil(11);
    let mut out = Vec::with_capacity(2 + y_word_count + 1);
    out.push(word0);
    out.push(word1);
    for i in 0..y_word_count {
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
        out.push(w);
    }

    // CRC-11 over [x, M] ‖ nonce_be ‖ Y_bytes. Wrap input in Zeroizing — it holds Y bytes.
    let mut crc_input =
        chela_primitives::zeroize::Zeroizing::new(Vec::with_capacity(4 + share_bytes.len()));
    crc_input.push(x);
    crc_input.push(threshold);
    crc_input.extend_from_slice(&word1.to_be_bytes());
    crc_input.extend_from_slice(share_bytes);
    out.push(chela_primitives::crc::crc11_umts(&crc_input[..]));
    out
}

/// A share decoded from its words (everything the words carry — not kind or total).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedShare {
    pub x: u8,
    pub threshold: u8,
    pub nonce: u16,
    pub body: Vec<u8>,
}

impl Drop for DecodedShare {
    fn drop(&mut self) {
        // `body` is per-share SSS material; wipe on every path, success or error.
        chela_primitives::zeroize::Zeroize::zeroize(&mut self.body);
    }
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
    let meta = words[0];
    if meta & 1 != 0 {
        return Err(EngineError::ShareCorrupt); // reserved bit must be 0
    }
    let x_field = (meta >> 6) & 0x1F;
    let m_field = (meta >> 1) & 0x1F;
    if m_field == 31 {
        return Err(EngineError::ShareCorrupt); // would be M=33
    }
    let x = u8::try_from(x_field).unwrap() + 1;
    let threshold = u8::try_from(m_field).unwrap() + 2;
    let nonce = words[1] & 0x7FF;
    let crc_stored = words[words.len() - 1] & 0x7FF;
    let y_section = &words[2..words.len() - 1];

    // Candidate body lengths B with ceil(8B/11) == y_section.len(); CRC selects the right one.
    let k = y_section.len();
    let max_bytes = (k * 11) / 8;
    let min_bytes = ((k.saturating_sub(1)) * 11 + 1).div_ceil(8);
    for total_bytes in (min_bytes..=max_bytes).rev() {
        let mut body = chela_primitives::zeroize::Zeroizing::new(vec![0u8; total_bytes]);
        for (i, &w) in y_section.iter().enumerate() {
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
        crc_input.extend_from_slice(&nonce.to_be_bytes());
        crc_input.extend_from_slice(&body[..]);
        if chela_primitives::crc::crc11_umts(&crc_input[..]) == crc_stored {
            return Ok(DecodedShare {
                x,
                threshold,
                nonce,
                body: body.as_slice().to_vec(),
            });
        }
    }
    Err(EngineError::ShareCorrupt)
}

/// Decode a share from its BIP-39 word indices alone — the words-only recovery path.
pub fn decode_share_words(words: &[u16]) -> Result<DecodedShare, EngineError> {
    decode_share_bip39_v2(words)
}

/// Split a secret into `total` shares with reconstruction threshold `threshold`.
/// Uses the OS RNG; for deterministic testing use [`split_with_rng`].
pub fn split_secret(
    input: &SplitInput<'_>,
    threshold: u8,
    total: u8,
    mode: OutputMode,
) -> Result<Vec<Share>, EngineError> {
    split_with_rng(input, threshold, total, mode, &mut OsRng)
}

/// As [`split_secret`] but with an injectable RNG for testing.
pub fn split_with_rng(
    input: &SplitInput<'_>,
    threshold: u8,
    total: u8,
    mode: OutputMode,
    rng: &mut dyn RandomSource,
) -> Result<Vec<Share>, EngineError> {
    if threshold < MIN_THRESHOLD {
        return Err(EngineError::InvalidInput("threshold must be at least 2"));
    }
    let (body, kind_byte) = build_bundle_v2(input)?;
    // `body` is the full plaintext secret plus the appended kind byte; `Zeroizing` wipes it
    // on every exit, including the BundleTooLarge and split-error early returns below.
    let body = chela_primitives::zeroize::Zeroizing::new(body);
    if body.len() > MAX_PASSPHRASE_LEN + 32 + 1 {
        // 32 entropy + 255 passphrase + 1 kind byte is the largest legitimate body.
        return Err(EngineError::BundleTooLarge);
    }
    if total > MAX_SHARES {
        return Err(EngineError::InvalidInput("total must be 1..=32"));
    }

    let nonce = sample_nonce(rng)?;
    let mut xs = sample_distinct_x(total, rng)?;

    let mut share_bytes: Vec<Vec<u8>> = vec![vec![0u8; body.len()]; total as usize];
    let split_result = {
        let mut share_refs: Vec<&mut [u8]> =
            share_bytes.iter_mut().map(Vec::as_mut_slice).collect();
        split(&body[..], threshold, total, rng, &mut xs, &mut share_refs)
    };
    if let Err(e) = split_result {
        // share_bytes holds partial share material after a mid-split RNG failure; wipe it.
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
}

/// Reconstruct a secret from at least `threshold` shares. Every metadatum (x, threshold,
/// nonce, body) is read from the words; a present `total`/`kind` is advisory and ignored.
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
        if d.nonce != first.nonce
            || d.threshold != first.threshold
            || d.body.len() != first.body.len()
        {
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
    // `decoded` holds per-share SSS material; its `Drop` wipes each body here.
    parse_bundle(&body[..])
}

#[cfg(test)]
mod tests {
    use super::{
        recover_secret, split_secret, split_with_rng, OutputMode, RecoveredSecret, SplitInput,
    };
    use alloc::string::String;
    use alloc::vec::Vec;
    use chela_sss::{RandomSource, SssError};

    /// Deterministic test RNG that returns successive bytes from a fixed source array.
    struct DeterministicRng<'a> {
        source: &'a [u8],
        pos: usize,
    }

    impl<'a> DeterministicRng<'a> {
        fn new(source: &'a [u8]) -> Self {
            Self { source, pos: 0 }
        }
    }

    impl RandomSource for DeterministicRng<'_> {
        fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), SssError> {
            if self.pos + buf.len() > self.source.len() {
                return Err(SssError::RngFailed);
            }
            buf.copy_from_slice(&self.source[self.pos..self.pos + buf.len()]);
            self.pos += buf.len();
            Ok(())
        }
    }

    #[test]
    fn random_distinct_x_are_in_range_and_unique() {
        use super::sample_distinct_x;
        let mut rng = DeterministicRng::new(&[3, 200, 3, 3, 17, 9, 250, 1, 1, 1, 31, 0, 5]);
        let xs = sample_distinct_x(5, &mut rng).unwrap();
        assert_eq!(xs.len(), 5);
        for &x in &xs {
            assert!((1..=32).contains(&x));
        }
        for i in 0..xs.len() {
            for j in i + 1..xs.len() {
                assert_ne!(xs[i], xs[j]);
            }
        }
    }

    #[test]
    fn body_carries_kind_byte_last() {
        use super::{build_bundle_v2, SplitInput};
        let (body, _) = build_bundle_v2(&SplitInput::Text { text: "hi" }).unwrap();
        assert_eq!(body.last().copied(), Some(0x0Bu8)); // kind::TEXT
        assert_eq!(&body[..body.len() - 1], b"hi");
    }

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
        let crc_input: Vec<u8> = [7u8, 3]
            .iter()
            .copied()
            .chain(nonce.to_be_bytes())
            .chain(body.iter().copied())
            .collect();
        assert_eq!(
            *words.last().unwrap(),
            chela_primitives::crc::crc11_umts(&crc_input)
        );
        for &w in &words {
            assert!(w < 2048);
        }
    }

    #[test]
    fn decode_round_trips_and_rejects_corruption() {
        use super::{decode_share_bip39_v2, encode_share_bip39_v2, DecodedShare};
        let body = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        let words = encode_share_bip39_v2(&body, 0x2AA, 9, 4);
        let DecodedShare {
            x,
            threshold,
            nonce,
            body: got,
        } = &decode_share_bip39_v2(&words).unwrap();
        assert_eq!((*x, *threshold, *nonce), (9, 4, 0x2AA));
        assert_eq!(got.as_slice(), body);

        // Flip one word -> CRC must reject.
        let mut bad = words.clone();
        bad[2] ^= 1;
        assert!(decode_share_bip39_v2(&bad).is_err());

        // Reserved bit set -> reject.
        let mut bad0 = words.clone();
        bad0[0] |= 1;
        assert!(decode_share_bip39_v2(&bad0).is_err());
    }

    #[test]
    fn round_trip_every_subset_text_and_passphrase() {
        for (input, ms) in [
            (
                SplitInput::Text {
                    text: "correct horse battery staple",
                },
                2u8,
            ),
            (
                SplitInput::Bip39 {
                    mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                    passphrase: "trezor",
                },
                3u8,
            ),
        ] {
            let shares = split_secret(&input, ms, 5, OutputMode::Bip39Wordlist).unwrap();
            // Every share has distinct x in 1..=32 and a shared nonce.
            let n = shares[0].nonce;
            for s in &shares {
                assert!((1..=32).contains(&s.x));
                assert_eq!(s.nonce, n);
            }
            // Any M of the 5 recovers.
            let recovered = recover_secret(&shares[..ms as usize]).unwrap();
            drop(recovered); // value matched in the dedicated end-to-end tests above
        }
    }

    #[test]
    fn mixing_two_generations_is_rejected() {
        let mk = || {
            split_secret(
                &SplitInput::Text {
                    text: "hello world",
                },
                2,
                3,
                OutputMode::Bip39Wordlist,
            )
            .unwrap()
        };
        let a = mk();
        let b = mk();
        // Same secret, two generations -> different nonces -> mixing rejected.
        let mixed = alloc::vec![a[0].clone(), b[1].clone()];
        assert!(matches!(
            recover_secret(&mixed),
            Err(super::EngineError::MismatchedShares)
        ));
    }

    #[test]
    fn words_alone_recovery_ignores_total_and_kind() {
        let shares = split_secret(
            &SplitInput::Text {
                text: "secret note",
            },
            2,
            4,
            OutputMode::Bip39Wordlist,
        )
        .unwrap();
        // Strip the advisory fields a lone transcription wouldn't have.
        let bare: Vec<super::Share> = shares
            .iter()
            .take(2)
            .map(|s| super::Share {
                scheme: s.scheme,
                x: s.x,
                threshold: s.threshold,
                nonce: s.nonce,
                total: None,
                kind: None,
                word_indices: s.word_indices.clone(),
            })
            .collect();
        match &recover_secret(&bare).unwrap() {
            RecoveredSecret::Text { text } => assert_eq!(text, "secret note"),
            RecoveredSecret::Bip39 { .. } => panic!("expected text"),
        }
    }

    #[test]
    fn decode_rejects_m_field_31() {
        // m_field 31 would decode to M=33 (above the 32 cap); decode must reject it before
        // any CRC work. word0 = (x_field=0 << 6) | (m_field=31 << 1) | reserved=0 = 62.
        let words = [62u16, 0, 0, 0];
        assert!(super::decode_share_words(&words).is_err());
    }

    #[test]
    fn share_word_counts_are_pinned() {
        // body = payload ‖ kind_byte, then W = 2 + ceil(8 * body_len / 11) + 1.
        let seed12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let s12 = split_secret(
            &SplitInput::Bip39 {
                mnemonic: seed12,
                passphrase: "",
            },
            2,
            3,
            OutputMode::Bip39Wordlist,
        )
        .unwrap();
        assert_eq!(s12[0].word_indices.len(), 16); // 16 entropy + 1 kind = 17 B

        let seed24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let s24 = split_secret(
            &SplitInput::Bip39 {
                mnemonic: seed24,
                passphrase: "",
            },
            2,
            3,
            OutputMode::Bip39Wordlist,
        )
        .unwrap();
        assert_eq!(s24[0].word_indices.len(), 27); // 32 entropy + 1 kind = 33 B

        let t = split_secret(
            &SplitInput::Text { text: "hi" },
            2,
            3,
            OutputMode::Bip39Wordlist,
        )
        .unwrap();
        assert_eq!(t[0].word_indices.len(), 6); // 2 text + 1 kind = 3 B
    }

    #[test]
    fn end_to_end_bip39_24_word_no_passphrase_3_of_5() {
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let shares = split_secret(
            &SplitInput::Bip39 {
                mnemonic,
                passphrase: "",
            },
            3,
            5,
            OutputMode::Bip39Wordlist,
        )
        .unwrap();
        assert_eq!(shares.len(), 5);

        let nonce = shares[0].nonce;
        for s in &shares {
            assert_eq!(s.nonce, nonce);
            assert_eq!(s.threshold, 3);
            assert_eq!(s.total, Some(5));
        }

        let recovered = recover_secret(&shares[..3]).unwrap();
        match &recovered {
            RecoveredSecret::Bip39 {
                mnemonic: m,
                passphrase,
            } => {
                assert_eq!(m, mnemonic);
                assert_eq!(passphrase, "");
            }
            RecoveredSecret::Text { .. } => panic!("expected Bip39 recovery"),
        }

        // Different subset (0, 2, 4) must also recover.
        let subset = alloc::vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = recover_secret(&subset).unwrap();
        match &recovered {
            RecoveredSecret::Bip39 { mnemonic: m, .. } => assert_eq!(m, mnemonic),
            RecoveredSecret::Text { .. } => panic!("expected Bip39 recovery"),
        }
    }

    #[test]
    fn end_to_end_bip39_with_passphrase_2_of_3() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "this is my passphrase 🦀";
        let shares = split_secret(
            &SplitInput::Bip39 {
                mnemonic,
                passphrase,
            },
            2,
            3,
            OutputMode::Bip39Wordlist,
        )
        .unwrap();
        let recovered = recover_secret(&shares[..2]).unwrap();
        match &recovered {
            RecoveredSecret::Bip39 {
                mnemonic: m,
                passphrase: p,
            } => {
                assert_eq!(m, mnemonic);
                assert_eq!(p, passphrase);
            }
            RecoveredSecret::Text { .. } => panic!("expected Bip39 recovery"),
        }
    }

    #[test]
    fn end_to_end_text_3_of_5() {
        let text = "correct horse battery staple";
        let shares =
            split_secret(&SplitInput::Text { text }, 3, 5, OutputMode::Bip39Wordlist).unwrap();
        let recovered = recover_secret(&shares[..3]).unwrap();
        match &recovered {
            RecoveredSecret::Text { text: t } => assert_eq!(t, text),
            RecoveredSecret::Bip39 { .. } => panic!("expected Text recovery"),
        }
    }

    #[test]
    fn sub_threshold_fails_to_recover() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let shares = split_secret(
            &SplitInput::Bip39 {
                mnemonic,
                passphrase: "",
            },
            3,
            5,
            OutputMode::Bip39Wordlist,
        )
        .unwrap();
        let err = recover_secret(&shares[..2]).unwrap_err();
        assert_eq!(err, super::EngineError::InsufficientShares);
    }

    #[test]
    fn corrupted_share_word_detected() {
        let text = "secret";
        let pool: alloc::vec::Vec<u8> = (0..64).collect();
        let mut rng = DeterministicRng::new(&pool);
        let mut shares = split_with_rng(
            &SplitInput::Text { text },
            2,
            3,
            OutputMode::Bip39Wordlist,
            &mut rng,
        )
        .unwrap();
        shares[0].word_indices[0] ^= 1;
        let err = recover_secret(&shares[..2]).unwrap_err();
        assert_eq!(err, super::EngineError::ShareCorrupt);
    }

    #[test]
    fn split_rejects_threshold_below_two() {
        let err = split_secret(
            &SplitInput::Text { text: "secret" },
            1,
            5,
            OutputMode::Bip39Wordlist,
        )
        .unwrap_err();
        assert!(matches!(err, super::EngineError::InvalidInput(_)));
    }

    #[test]
    fn shares_of_different_secrets_rejected() {
        // Different generations => different nonces => MismatchedShares before SSS runs.
        let mnemonic_a = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic_b =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let shares_a = split_secret(
            &SplitInput::Bip39 {
                mnemonic: mnemonic_a,
                passphrase: "",
            },
            2,
            3,
            OutputMode::Bip39Wordlist,
        )
        .unwrap();
        let shares_b = split_secret(
            &SplitInput::Bip39 {
                mnemonic: mnemonic_b,
                passphrase: "",
            },
            2,
            3,
            OutputMode::Bip39Wordlist,
        )
        .unwrap();
        let mixed = alloc::vec![shares_a[0].clone(), shares_b[1].clone()];
        let err = recover_secret(&mixed).unwrap_err();
        assert_eq!(err, super::EngineError::MismatchedShares);
    }

    #[test]
    fn round_trip_at_payload_lengths_with_word_count_ambiguity() {
        // Exercises both sides of every word-count ambiguity boundary. In v2 the appended
        // kind byte and the per-share CRC pick the right candidate length.
        for text_len in 1usize..=60 {
            let text: String = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                .chars()
                .cycle()
                .take(text_len)
                .collect();
            let shares = split_secret(
                &SplitInput::Text { text: &text },
                2,
                3,
                OutputMode::Bip39Wordlist,
            )
            .unwrap_or_else(|e| panic!("split failed at len {text_len}: {e:?}"));
            let recovered = recover_secret(&shares[..2])
                .unwrap_or_else(|e| panic!("recover failed at len {text_len}: {e:?}"));
            match &recovered {
                RecoveredSecret::Text { text: t } => assert_eq!(t, &text, "len {text_len}"),
                RecoveredSecret::Bip39 { .. } => panic!("expected Text recovery at len {text_len}"),
            }
        }
    }

    #[test]
    fn bad_input_word_rejected() {
        let result = split_secret(
            &SplitInput::Bip39 {
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notarealbip39word",
                passphrase: "",
            },
            2,
            3,
            OutputMode::Bip39Wordlist,
        );
        assert!(result.is_err());
    }
}
