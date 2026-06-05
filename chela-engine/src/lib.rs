//! High-level split/recover API: bundle the secret, SSS-split, encode shares, and the inverse.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use chela_primitives::sha256::Sha256;
use chela_sss::{combine, split, OsRng, RandomSource, SssError};

/// Public-API view of a share's payload kind. The finer-grained internal kind byte
/// (word count, passphrase presence) lives only inside the identifier hash.
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

const SHARE_CHECKSUM_LEN: usize = 2;
const IDENTIFIER_LEN: usize = 2;
const MAX_PASSPHRASE_LEN: usize = 255;
const MAX_TEXT_LEN: usize = 255;

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

    /// All defined kind bytes, enumerated at recovery time.
    pub(super) const ALL_VALUES: [u8; 11] = [
        BIP39_NO_PASS_12,
        BIP39_NO_PASS_15,
        BIP39_NO_PASS_18,
        BIP39_NO_PASS_21,
        BIP39_NO_PASS_24,
        BIP39_PASS_12,
        BIP39_PASS_15,
        BIP39_PASS_18,
        BIP39_PASS_21,
        BIP39_PASS_24,
        TEXT,
    ];
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
    /// Combined body doesn't match any kind's identifier — usually wrong share subset.
    BundleCorrupt,
    /// Shares disagree on identifier/scheme/kind/threshold/total.
    MismatchedShares,
    /// Share's own 2-byte checksum doesn't verify against (payload, identifier, x).
    ShareCorrupt,
    /// Words used in the share aren't valid BIP-39 wordlist entries.
    UnknownWord,
    /// Fewer shares than the threshold.
    InsufficientShares,
    Utf8,
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

/// A single share as produced by the engine — every field on the printed card or in the text form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub identifier: [u8; IDENTIFIER_LEN],
    pub scheme: OutputMode,
    pub kind: PayloadKind,
    pub threshold: u8,
    pub total: u8,
    pub x: u8,
    /// BIP-39 wordlist indices (each in `0..2048`).
    pub word_indices: Vec<u16>,
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

/// Build the body bytes SSS will split, plus the `kind_byte` (folded into the identifier
/// hash, never in the body itself).
fn build_bundle(input: &SplitInput<'_>) -> Result<(Vec<u8>, u8), EngineError> {
    match input {
        SplitInput::Bip39 {
            mnemonic,
            passphrase,
        } => {
            let mut indices: Vec<u16> = mnemonic
                .split_whitespace()
                .map(|w| chela_bip39::word_to_index(w).ok_or(EngineError::UnknownWord))
                .collect::<Result<_, _>>()?;
            let entropy_bytes = chela_bip39::entropy_bytes_for_words(indices.len()).ok_or(
                EngineError::InvalidInput("not a 12/15/18/21/24-word mnemonic"),
            )?;
            let word_count = indices.len();
            let mut entropy = vec![0u8; entropy_bytes];
            chela_bip39::decode_indices_to_entropy(&indices, &mut entropy)?;
            chela_primitives::zeroize::Zeroize::zeroize(&mut indices);

            if passphrase.len() > MAX_PASSPHRASE_LEN {
                chela_primitives::zeroize::volatile_set(&mut entropy);
                return Err(EngineError::InvalidInput("passphrase exceeds 255 bytes"));
            }

            let has_passphrase = !passphrase.is_empty();
            let kind_byte = encode_bip39_kind_byte(word_count, has_passphrase)
                .expect("word_count validated by entropy_bytes_for_words above");

            // Pre-size `body` to its final length so `extend_from_slice` cannot trigger
            // a Vec reallocation. The naïve `body = entropy; body.extend_from_slice(...)`
            // pattern reallocates because `vec![0u8; N]` produces capacity == length,
            // and the orphaned (entropy-holding) heap buffer is freed without being
            // wiped — that's the zeroize gap this branch avoids.
            let passphrase_bytes = if has_passphrase {
                passphrase.as_bytes()
            } else {
                &[][..]
            };
            let mut body: Vec<u8> = Vec::with_capacity(entropy_bytes + passphrase_bytes.len());
            body.extend_from_slice(&entropy);
            body.extend_from_slice(passphrase_bytes);
            chela_primitives::zeroize::volatile_set(&mut entropy);
            drop(entropy);
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

/// `identifier = SHA-256(body || kind_byte)[0..2]`.
fn compute_identifier(body: &[u8], kind_byte: u8) -> [u8; IDENTIFIER_LEN] {
    let mut h = Sha256::new();
    h.update(body);
    h.update(&[kind_byte]);
    let digest = h.finalize();
    let mut id = [0u8; IDENTIFIER_LEN];
    id.copy_from_slice(&digest[..IDENTIFIER_LEN]);
    id
}

/// Whether `body_len` is a valid body length for the given decoded kind.
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

/// Recover the original secret from the SSS-combined body. Tries each kind whose length
/// pattern fits; the one whose identifier matches names the kind.
fn parse_bundle(
    body: &[u8],
    identifier: [u8; IDENTIFIER_LEN],
) -> Result<RecoveredSecret, EngineError> {
    for &kind_byte in &kind::ALL_VALUES {
        let dec = decode_kind_byte(kind_byte).expect("ALL_VALUES are all valid kind bytes");
        if !body_len_fits(dec, body.len()) {
            continue;
        }
        let candidate = compute_identifier(body, kind_byte);
        if chela_primitives::ct::ct_eq(&candidate, &identifier) {
            return interpret_body(dec, body);
        }
    }
    Err(EngineError::BundleCorrupt)
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

fn encode_share_bip39(share_bytes: &[u8], identifier: [u8; IDENTIFIER_LEN], x: u8) -> Vec<u16> {
    // share_checksum = SHA-256(share_bytes || identifier || x)[0..SHARE_CHECKSUM_LEN]
    let mut h = Sha256::new();
    h.update(share_bytes);
    h.update(&identifier);
    h.update(&[x]);
    let mut cs = h.finalize();

    let total_bytes = share_bytes.len() + SHARE_CHECKSUM_LEN;
    let total_bits = total_bytes * 8;
    let word_count = total_bits.div_ceil(11);

    // Bit-stream: payload || checksum, zero-padded into the LOW bits of the last 11-bit word.
    let mut words = vec![0u16; word_count];
    for (i, slot) in words.iter_mut().enumerate() {
        let mut w: u16 = 0;
        for b in 0..11usize {
            let bit_pos = i * 11 + b;
            if bit_pos < total_bits {
                let byte = if bit_pos < share_bytes.len() * 8 {
                    share_bytes[bit_pos / 8]
                } else {
                    cs[(bit_pos - share_bytes.len() * 8) / 8]
                };
                let bit = (byte >> (7 - (bit_pos % 8))) & 1;
                w = (w << 1) | u16::from(bit);
            } else {
                w <<= 1;
            }
        }
        *slot = w;
    }
    chela_primitives::zeroize::Zeroize::zeroize(&mut cs);
    words
}

fn decode_share_bip39(
    words: &[u16],
    expected_payload_len: usize,
    identifier: [u8; IDENTIFIER_LEN],
    x: u8,
) -> Result<Vec<u8>, EngineError> {
    let total_bytes = expected_payload_len + SHARE_CHECKSUM_LEN;
    let total_bits = total_bytes * 8;
    let word_count = total_bits.div_ceil(11);
    if words.len() != word_count {
        return Err(EngineError::ShareCorrupt);
    }
    for &w in words {
        if w >= 2048 {
            return Err(EngineError::ShareCorrupt);
        }
    }

    let mut buf = vec![0u8; total_bytes];
    for (i, &w) in words.iter().enumerate() {
        for b in 0..11usize {
            let bit_pos = i * 11 + b;
            if bit_pos >= total_bits {
                break;
            }
            let bit = u8::try_from((w >> (10 - b)) & 1).unwrap();
            buf[bit_pos / 8] |= bit << (7 - (bit_pos % 8));
        }
    }

    let (payload, cs_stored) = buf.split_at(expected_payload_len);

    let mut h = Sha256::new();
    h.update(payload);
    h.update(&identifier);
    h.update(&[x]);
    let mut cs_expected = h.finalize();

    let cs_ok = chela_primitives::ct::ct_eq(&cs_expected[..SHARE_CHECKSUM_LEN], cs_stored);
    chela_primitives::zeroize::Zeroize::zeroize(&mut cs_expected);
    if !cs_ok {
        chela_primitives::zeroize::Zeroize::zeroize(&mut buf);
        return Err(EngineError::ShareCorrupt);
    }

    let out = payload.to_vec();
    chela_primitives::zeroize::Zeroize::zeroize(&mut buf);
    Ok(out)
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
    let (body, kind_byte) = build_bundle(input)?;
    if body.len() > MAX_PASSPHRASE_LEN + 32 {
        // 32 entropy + 255 passphrase is the largest legitimate body.
        return Err(EngineError::BundleTooLarge);
    }

    let id = compute_identifier(&body, kind_byte);

    let mut xs = vec![0u8; total as usize];
    let mut share_bytes: Vec<Vec<u8>> = vec![vec![0u8; body.len()]; total as usize];
    {
        let mut share_refs: Vec<&mut [u8]> =
            share_bytes.iter_mut().map(Vec::as_mut_slice).collect();
        split(&body, threshold, total, rng, &mut xs, &mut share_refs)?;
    }

    let coarse_kind = match input {
        SplitInput::Bip39 { .. } => PayloadKind::Bip39,
        SplitInput::Text { .. } => PayloadKind::Text,
    };

    let mut out = Vec::with_capacity(total as usize);
    for (idx, mut sb) in share_bytes.into_iter().enumerate() {
        let x = xs[idx];
        let word_indices = match mode {
            OutputMode::Bip39Wordlist => encode_share_bip39(&sb, id, x),
        };
        chela_primitives::zeroize::Zeroize::zeroize(&mut sb);
        out.push(Share {
            identifier: id,
            scheme: mode,
            kind: coarse_kind,
            threshold,
            total,
            x,
            word_indices,
        });
    }

    let mut body_wipe = body;
    chela_primitives::zeroize::volatile_set(&mut body_wipe);

    Ok(out)
}

/// Reconstruct a secret from at least `threshold` shares.
/// The threshold is read off the shares; metadata must be consistent across them.
pub fn recover_secret(shares: &[Share]) -> Result<RecoveredSecret, EngineError> {
    if shares.is_empty() {
        return Err(EngineError::InsufficientShares);
    }
    let first = &shares[0];
    for s in &shares[1..] {
        if s.identifier != first.identifier
            || s.scheme != first.scheme
            || s.kind != first.kind
            || s.threshold != first.threshold
            || s.total != first.total
        {
            return Err(EngineError::MismatchedShares);
        }
    }
    if shares.len() < first.threshold as usize {
        return Err(EngineError::InsufficientShares);
    }

    // Multiple body lengths can encode to the same word count: enumerate candidate lengths
    // and pick the first whose share checksum verifies for all shares.
    let words_n = first.word_indices.len();
    let total_bits = words_n * 11;
    // Valid byte counts B satisfy ceil(B*8 / 11) == words_n.
    let max_bytes = total_bits / 8;
    let min_bits_for_word_count = (words_n.saturating_sub(1)) * 11 + 1;
    let min_bytes = min_bits_for_word_count.div_ceil(8);
    if max_bytes < SHARE_CHECKSUM_LEN || min_bytes > max_bytes {
        return Err(EngineError::ShareCorrupt);
    }

    let mut chosen: Option<(usize, Vec<Vec<u8>>)> = None;
    'outer: for total_bytes in (min_bytes..=max_bytes).rev() {
        if total_bytes < SHARE_CHECKSUM_LEN {
            continue;
        }
        let payload_len = total_bytes - SHARE_CHECKSUM_LEN;
        let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(shares.len());
        for s in shares {
            if s.word_indices.len() != words_n {
                return Err(EngineError::MismatchedShares);
            }
            let payload = match s.scheme {
                OutputMode::Bip39Wordlist => {
                    match decode_share_bip39(&s.word_indices, payload_len, s.identifier, s.x) {
                        Ok(p) => p,
                        Err(_) => continue 'outer,
                    }
                }
            };
            payloads.push(payload);
        }
        chosen = Some((payload_len, payloads));
        break;
    }
    let (payload_len, mut payloads) = chosen.ok_or(EngineError::ShareCorrupt)?;
    let xs: Vec<u8> = shares.iter().map(|s| s.x).collect();

    let mut body = vec![0u8; payload_len];
    {
        let refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
        combine(&xs, &refs, &mut body)?;
    }
    for p in &mut payloads {
        chela_primitives::zeroize::Zeroize::zeroize(p);
    }

    let recovered = parse_bundle(&body, first.identifier);

    let mut body_wipe = body;
    chela_primitives::zeroize::volatile_set(&mut body_wipe);

    recovered
}

#[cfg(test)]
mod tests {
    use super::{
        recover_secret, split_secret, split_with_rng, OutputMode, RecoveredSecret, SplitInput,
    };
    use alloc::string::String;
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

        let id = shares[0].identifier;
        for s in &shares {
            assert_eq!(s.identifier, id);
            assert_eq!(s.threshold, 3);
            assert_eq!(s.total, 5);
        }

        let recovered = recover_secret(&shares[..3]).unwrap();
        match recovered {
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
        match recovered {
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
        match recovered {
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
        match recovered {
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
    fn shares_of_different_secrets_rejected() {
        // Different secrets => different identifiers => MismatchedShares before SSS runs.
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
    fn shares_from_two_splits_of_the_same_secret_rejected_as_bundle_corrupt() {
        // Same secret => same identifier, so the mismatch gate doesn't fire; SSS combine
        // garbage and parse_bundle reports BundleCorrupt.
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let shares_a = split_secret(
            &SplitInput::Bip39 {
                mnemonic,
                passphrase: "",
            },
            2,
            3,
            OutputMode::Bip39Wordlist,
        )
        .unwrap();
        let shares_b = split_secret(
            &SplitInput::Bip39 {
                mnemonic,
                passphrase: "",
            },
            2,
            3,
            OutputMode::Bip39Wordlist,
        )
        .unwrap();
        let mixed = alloc::vec![shares_a[0].clone(), shares_b[1].clone()];
        let err = recover_secret(&mixed).unwrap_err();
        assert_eq!(err, super::EngineError::BundleCorrupt);
    }

    #[test]
    fn round_trip_at_payload_lengths_with_word_count_ambiguity() {
        // Exercises both sides of every word-count ambiguity boundary.
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
            match recovered {
                RecoveredSecret::Text { text: t } => assert_eq!(t, text, "len {text_len}"),
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
