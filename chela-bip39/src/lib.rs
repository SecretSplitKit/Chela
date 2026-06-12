//! BIP-0039 codec: entropy <-> 11-bit wordlist indices with SHA-256 checksum (BIP-39 § 4).

#![no_std]
#![forbid(unsafe_code)]

pub mod wordlist;
pub use wordlist::WORDLIST;

use chela_primitives::sha256::Sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip39Error {
    /// Entropy is not 16/20/24/28/32 bytes.
    InvalidEntropyLength,
    /// Mnemonic is not 12/15/18/21/24 words.
    InvalidMnemonicLength,
    /// A word is not in the BIP-39 wordlist.
    UnknownWord,
    /// The recovered checksum does not match the recomputed checksum.
    InvalidChecksum,
    /// A word index is outside `0..2048`.
    InvalidIndex,
    /// Output buffer is shorter than the required output length.
    BufferTooSmall,
}

impl core::fmt::Display for Bip39Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidEntropyLength => f.write_str("entropy is not 16/20/24/28/32 bytes"),
            Self::InvalidMnemonicLength => f.write_str("not a 12/15/18/21/24-word BIP-39 mnemonic"),
            Self::UnknownWord => {
                f.write_str("a word is not in the BIP-39 word list (check spelling)")
            }
            Self::InvalidChecksum => f.write_str("the mnemonic's built-in checksum does not match"),
            Self::InvalidIndex => f.write_str("a word index is outside the valid range"),
            Self::BufferTooSmall => f.write_str("output buffer is too small"),
        }
    }
}

/// Word count for the given entropy length in bytes.
#[must_use]
pub const fn words_for_entropy_bytes(entropy_bytes: usize) -> Option<usize> {
    match entropy_bytes {
        16 => Some(12),
        20 => Some(15),
        24 => Some(18),
        28 => Some(21),
        32 => Some(24),
        _ => None,
    }
}

/// Entropy length in bytes for the given mnemonic word count.
#[must_use]
pub const fn entropy_bytes_for_words(word_count: usize) -> Option<usize> {
    match word_count {
        12 => Some(16),
        15 => Some(20),
        18 => Some(24),
        21 => Some(28),
        24 => Some(32),
        _ => None,
    }
}

/// Encode `entropy` into BIP-39 wordlist indices (BIP-39 § 4). Returns indices written.
pub fn encode_entropy_to_indices(
    entropy: &[u8],
    out_indices: &mut [u16],
) -> Result<usize, Bip39Error> {
    let word_count =
        words_for_entropy_bytes(entropy.len()).ok_or(Bip39Error::InvalidEntropyLength)?;
    if out_indices.len() < word_count {
        return Err(Bip39Error::BufferTooSmall);
    }

    let entropy_bits = entropy.len() * 8;
    let checksum_bits = entropy_bits / 32;

    // BIP-39 § 4: checksum = top `checksum_bits` bits of SHA-256(entropy); always fits in one byte.
    let hash = Sha256::hash(entropy);
    let checksum_byte = hash[0];

    for (i, idx_slot) in out_indices.iter_mut().enumerate().take(word_count) {
        let mut idx: u16 = 0;
        for b in 0..11usize {
            let bit_pos = i * 11 + b;
            let bit: u16 = if bit_pos < entropy_bits {
                let byte = entropy[bit_pos / 8];
                u16::from((byte >> (7 - (bit_pos % 8))) & 1)
            } else {
                let offset = bit_pos - entropy_bits;
                debug_assert!(offset < checksum_bits);
                u16::from((checksum_byte >> (7 - offset)) & 1)
            };
            idx = (idx << 1) | bit;
        }
        *idx_slot = idx;
    }

    Ok(word_count)
}

/// Decode BIP-39 wordlist indices into entropy. Verifies the BIP-39 checksum in
/// constant time. Returns the number of entropy bytes written.
///
/// # Panics
/// Cannot panic: `(idx >> n) & 1 ∈ {0, 1}`, so the inner `u8::try_from` is total.
pub fn decode_indices_to_entropy(
    indices: &[u16],
    out_entropy: &mut [u8],
) -> Result<usize, Bip39Error> {
    let entropy_bytes =
        entropy_bytes_for_words(indices.len()).ok_or(Bip39Error::InvalidMnemonicLength)?;
    if out_entropy.len() < entropy_bytes {
        return Err(Bip39Error::BufferTooSmall);
    }
    for &idx in indices {
        if idx >= 2048 {
            return Err(Bip39Error::InvalidIndex);
        }
    }

    let entropy_bits = entropy_bytes * 8;
    let checksum_bits = entropy_bits / 32;

    out_entropy[..entropy_bytes].fill(0);
    let mut checksum_byte: u8 = 0;

    for (i, &idx) in indices.iter().enumerate() {
        for b in 0..11usize {
            let bit: u8 = u8::try_from((idx >> (10 - b)) & 1).unwrap();
            let bit_pos = i * 11 + b;
            if bit_pos < entropy_bits {
                out_entropy[bit_pos / 8] |= bit << (7 - (bit_pos % 8));
            } else {
                let offset = bit_pos - entropy_bits;
                checksum_byte |= bit << (7 - offset);
            }
        }
    }

    // Constant-time checksum verify. The mask leaks `checksum_bits`, which is public.
    let hash = Sha256::hash(&out_entropy[..entropy_bytes]);
    let mask: u8 = if checksum_bits >= 8 {
        0xff
    } else {
        (!0u8) << (8 - checksum_bits)
    };
    let expected = hash[0] & mask;
    let stored = checksum_byte & mask;
    if !chela_primitives::ct::ct_eq(&[expected], &[stored]) {
        return Err(Bip39Error::InvalidChecksum);
    }

    Ok(entropy_bytes)
}

/// Look up a BIP-39 wordlist entry by index.
#[must_use]
pub fn index_to_word(idx: u16) -> Option<&'static str> {
    WORDLIST.get(idx as usize).copied()
}

/// Look up the index of a word in the BIP-39 wordlist. ASCII case-insensitive.
#[must_use]
pub fn word_to_index(word: &str) -> Option<u16> {
    if word.is_empty() || word.len() > 8 {
        return None;
    }
    if let Ok(idx) = WORDLIST.binary_search(&word) {
        return u16::try_from(idx).ok();
    }
    let needle = word.as_bytes();
    for (idx, &candidate) in WORDLIST.iter().enumerate() {
        let candidate_bytes = candidate.as_bytes();
        if candidate_bytes.len() != needle.len() {
            continue;
        }
        let mut equal = true;
        for (a, b) in candidate_bytes.iter().zip(needle.iter()) {
            let b_lc = if b.is_ascii_uppercase() { b + 32 } else { *b };
            if *a != b_lc {
                equal = false;
                break;
            }
        }
        if equal {
            return u16::try_from(idx).ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::{
        decode_indices_to_entropy, encode_entropy_to_indices, index_to_word, word_to_index,
        Bip39Error,
    };
    use alloc::vec;
    use alloc::vec::Vec;

    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "hex must be even length");
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(s.len() / 2);
        let mut i = 0;
        while i < bytes.len() {
            let hi = nibble(bytes[i]);
            let lo = nibble(bytes[i + 1]);
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("invalid hex digit: {b}"),
        }
    }

    fn entropy_to_mnemonic_string(entropy: &[u8]) -> alloc::string::String {
        let mut indices = vec![0u16; 24];
        let n = encode_entropy_to_indices(entropy, &mut indices).unwrap();
        let words: Vec<&'static str> = indices[..n]
            .iter()
            .map(|&i| index_to_word(i).unwrap())
            .collect();
        words.join(" ")
    }

    fn mnemonic_to_entropy_bytes(mnemonic: &str) -> Result<Vec<u8>, Bip39Error> {
        let indices: Vec<u16> = mnemonic
            .split_whitespace()
            .map(|w| word_to_index(w).ok_or(Bip39Error::UnknownWord))
            .collect::<Result<_, _>>()?;
        let mut out = vec![0u8; 32];
        let n = decode_indices_to_entropy(&indices, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    // BIP-39 reference test vectors. Source (the BIP-39 authors' own reference
    // implementation): https://github.com/trezor/python-mnemonic/blob/master/vectors.json

    macro_rules! bip39_vector {
        ($name:ident, $entropy_hex:expr, $mnemonic:expr) => {
            #[test]
            fn $name() {
                let entropy = hex_decode($entropy_hex);
                let expected_mnemonic = $mnemonic;

                let got = entropy_to_mnemonic_string(&entropy);
                assert_eq!(
                    got, expected_mnemonic,
                    "encode mismatch for {}",
                    $entropy_hex
                );

                let got_entropy = mnemonic_to_entropy_bytes(expected_mnemonic).unwrap();
                assert_eq!(
                    got_entropy, entropy,
                    "decode mismatch for {}",
                    expected_mnemonic
                );
            }
        };
    }

    bip39_vector!(
        bip39_vector_12_word_zero,
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    );
    bip39_vector!(
        bip39_vector_12_word_7f,
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank yellow"
    );
    bip39_vector!(
        bip39_vector_12_word_80,
        "80808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
    );
    bip39_vector!(
        bip39_vector_12_word_ff,
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
    );
    // 15/21-word zero-entropy vectors derived from BIP-39 § 4 (the reference impl only
    // publishes 12/18/24).
    bip39_vector!(
        bip39_vector_15_word_zero,
        "0000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address"
    );
    bip39_vector!(
        bip39_vector_18_word_zero,
        "000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent"
    );
    bip39_vector!(
        bip39_vector_21_word_zero,
        "00000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit"
    );
    bip39_vector!(
        bip39_vector_24_word_zero,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
    );
    bip39_vector!(
        bip39_vector_24_word_ff,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
    );
    bip39_vector!(
        bip39_vector_12_word_ozone,
        "9e885d952ad362caeb4efe34a8e91bd2",
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
    );
    bip39_vector!(
        bip39_vector_18_word_gravity,
        "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
        "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog"
    );
    bip39_vector!(
        bip39_vector_24_word_hamster,
        "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"
    );

    #[test]
    fn decode_rejects_invalid_word_count() {
        let indices = vec![0u16; 10];
        let mut out = vec![0u8; 32];
        let err = decode_indices_to_entropy(&indices, &mut out).unwrap_err();
        assert_eq!(err, Bip39Error::InvalidMnemonicLength);
    }

    #[test]
    fn decode_rejects_invalid_index() {
        let mut indices = vec![0u16; 12];
        indices[5] = 2048;
        let mut out = vec![0u8; 16];
        let err = decode_indices_to_entropy(&indices, &mut out).unwrap_err();
        assert_eq!(err, Bip39Error::InvalidIndex);
    }

    #[test]
    fn decode_rejects_bad_checksum() {
        let mut indices = vec![0u16; 12];
        let entropy = [0u8; 16];
        encode_entropy_to_indices(&entropy, &mut indices).unwrap();
        indices[11] ^= 1;
        let mut out = vec![0u8; 16];
        let err = decode_indices_to_entropy(&indices, &mut out).unwrap_err();
        assert_eq!(err, Bip39Error::InvalidChecksum);
    }

    #[test]
    fn encode_rejects_invalid_entropy_length() {
        let mut out = vec![0u16; 24];
        let err = encode_entropy_to_indices(&[0u8; 7], &mut out).unwrap_err();
        assert_eq!(err, Bip39Error::InvalidEntropyLength);
    }

    #[test]
    fn encode_rejects_short_output_buffer() {
        let mut out = vec![0u16; 10];
        let err = encode_entropy_to_indices(&[0u8; 16], &mut out).unwrap_err();
        assert_eq!(err, Bip39Error::BufferTooSmall);
    }

    #[test]
    fn word_to_index_exact_and_case_insensitive() {
        assert_eq!(word_to_index("abandon"), Some(0));
        assert_eq!(word_to_index("ability"), Some(1));
        assert_eq!(word_to_index("zoo"), Some(2047));
        assert_eq!(word_to_index("ABANDON"), Some(0));
        assert_eq!(word_to_index("AbAnDoN"), Some(0));
        assert_eq!(word_to_index("notinwordlist"), None);
        assert_eq!(word_to_index(""), None);
    }

    #[test]
    fn index_to_word_bounds() {
        assert_eq!(index_to_word(0), Some("abandon"));
        assert_eq!(index_to_word(2047), Some("zoo"));
        assert_eq!(index_to_word(2048), None);
    }

    #[test]
    fn round_trip_every_length() {
        for &n in &[16usize, 20, 24, 28, 32] {
            let entropy: Vec<u8> = (0..n)
                .map(|i| {
                    u8::try_from(i % 256)
                        .unwrap()
                        .wrapping_mul(13)
                        .wrapping_add(0x17)
                })
                .collect();
            let mut indices = vec![0u16; 24];
            let nw = encode_entropy_to_indices(&entropy, &mut indices).unwrap();
            let mut recovered = vec![0u8; 32];
            let nb = decode_indices_to_entropy(&indices[..nw], &mut recovered).unwrap();
            assert_eq!(nb, n, "entropy_bytes mismatch for n={n}");
            assert_eq!(&recovered[..nb], entropy.as_slice(), "round-trip for n={n}");
        }
    }
}
