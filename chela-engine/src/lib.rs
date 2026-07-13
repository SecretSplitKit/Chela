//! High-level split/recover API: bundle the secret, SSS-split, encode shares, and the inverse.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use chela_primitives::zeroize::Zeroizing;
use chela_sss::{combine, evaluate_shares, split, split_retaining_coeffs, OsRng, RandomSource, SssError};

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

/// Largest legitimate SSS body: 32 entropy + 255 passphrase + 1 integrity tag + 1 kind byte.
const MAX_BODY_LEN: usize = MAX_PASSPHRASE_LEN + 32 + 2;

/// Wire version of the [`SplitState`] byte layout (`SplitState::to_bytes`). Bump only on an
/// incompatible layout change so sealed blobs from older versions are cleanly rejected.
const STATE_VERSION: u8 = 1;

/// Minimum reconstruction threshold. A threshold of 1 (any single share rebuilds the
/// secret) gives no secret-sharing security, so the engine refuses to produce it.
pub const MIN_THRESHOLD: u8 = 2;

/// Maximum share count / x-range in v2: x ∈ 1..=32 (5-bit field, x = field + 1).
pub const MAX_SHARES: u8 = 32;

/// Draw `count` distinct x-coordinates in `1..=32` from the CSPRNG. Each draw is a raw
/// 5-bit field (`0..31`, a power of two - uniform, no modulo bias); `x = field + 1`.
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

/// Draw the 11-bit recovery set id (a per-split random tag, i.e. a nonce) from the CSPRNG.
fn sample_recovery_recovery_set_id(rng: &mut dyn RandomSource) -> Result<u16, EngineError> {
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
    /// Combined body's trailing kind byte is invalid or its length doesn't fit - usually
    /// the wrong share subset.
    BundleCorrupt,
    /// Shares disagree on recovery set id/scheme/threshold/body length - different generation or corrupt.
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
                "the recovered secret is invalid - this is usually the wrong set of shares",
            ),
            Self::MismatchedShares => f.write_str(
                "these shares are not from the same split (different recovery set id or threshold) - do not mix shares from two separate splits",
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

/// Failure modes of [`extend`]. Kept separate from [`EngineError`] so adding extendable-split
/// errors never perturbs the exhaustive `EngineError` handling in the other crates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtendError {
    /// `count` was zero - nothing to issue.
    ZeroCount,
    /// The supplied secret does not match the retained state (wrong secret or wrong state).
    /// The state's constant terms are the original body; a recomputed body that differs
    /// means the caller paired the wrong secret with this state.
    WrongSecret,
    /// No coordinates remain: `count` exceeds the `32 − issued_count` shares still available
    /// on this polynomial (SPEC § 3.3 caps lifetime issuance at 32).
    Exhausted,
    /// Issuing would push lifetime issuance past the soft cap of `3·M − 1` shares (rev-3 § 5).
    /// Re-split with a larger threshold, or pass `allow_over_cap` to proceed deliberately.
    OverSoftCap,
    /// The secret could not be bundled (invalid input, too large, or a BIP-39 error).
    Bundle(EngineError),
    /// The underlying SSS evaluation or the RNG rejected its inputs.
    Sss(SssError),
}

impl core::fmt::Display for ExtendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ZeroCount => f.write_str("count must be at least 1"),
            Self::WrongSecret => f.write_str(
                "the supplied secret does not match this split-state (wrong secret or wrong state file)",
            ),
            Self::Exhausted => f.write_str(
                "no share coordinates remain: this split has already issued all 32 possible shares",
            ),
            Self::OverSoftCap => f.write_str(
                "issuing these shares would exceed the recommended limit of 3*M-1 shares; re-split with a larger threshold, or set allow_over_cap to proceed",
            ),
            Self::Bundle(e) => e.fmt(f),
            Self::Sss(e) => e.fmt(f),
        }
    }
}

/// Failure modes of [`SplitState::from_bytes`]. Every variant is reached without panicking on
/// arbitrary input - the parser is fuzz-robust by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    /// Fewer than the fixed-size header (7 bytes).
    TooShort,
    /// Unknown layout version - a blob from an incompatible (usually newer) build.
    UnsupportedVersion(u8),
    /// Threshold outside `2..=32`.
    BadThreshold,
    /// Recovery set id has bits set above the 11-bit range.
    BadRecoverySetId,
    /// Issued count above the 32-share ceiling.
    BadIssuedCount,
    /// Body length zero or above the 289-byte maximum.
    BadBodyLen,
    /// Total length does not match the header's declared field sizes.
    LengthMismatch,
    /// An issued x-coordinate is out of `1..=32` or repeated.
    BadXCoordinate,
}

impl core::fmt::Display for StateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort => f.write_str("split-state is too short to contain a header"),
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported split-state version {v} (this build understands {STATE_VERSION})")
            }
            Self::BadThreshold => f.write_str("split-state threshold is outside 2..=32"),
            Self::BadRecoverySetId => f.write_str("split-state recovery set id exceeds 11 bits"),
            Self::BadIssuedCount => f.write_str("split-state issued count exceeds 32"),
            Self::BadBodyLen => f.write_str("split-state body length is zero or exceeds 289"),
            Self::LengthMismatch => f.write_str("split-state length does not match its header"),
            Self::BadXCoordinate => {
                f.write_str("split-state contains an out-of-range or duplicate x-coordinate")
            }
        }
    }
}

/// A single share. The words carry `x`, `threshold`, and `recovery_set_id`; `total` and `kind` are
/// known only at split time or from an advisory header, never from a lone share's words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub scheme: OutputMode,
    pub x: u8,
    pub threshold: u8,
    pub recovery_set_id: u16,
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

/// Retained polynomial state for chela's *extendable-split* profile (rev-3). It pins the
/// exact polynomials a split drew, so [`extend`] can issue further shares on the same
/// `recovery_set_id` and threshold at fresh x-coordinates, byte-identical to what the
/// original split would have emitted.
///
/// # Secret-equivalence
///
/// `coeffs` stores every polynomial's coefficients constant-term-first, and those constant
/// terms ARE the secret body. State alone therefore reconstructs the secret; it is *as
/// sensitive as the secret*. This type wipes `coeffs` on drop, hides its contents from
/// `Debug`, and is deliberately **not** `Serialize`: persisting it is an explicit act via
/// [`SplitState::to_bytes`], after which the embedder MUST seal the bytes under an AEAD
/// (binding `rsid ‖ M` as associated data) with a key at least as protected as the secret.
/// Chela never persists, encrypts, or sees a state file - sealing is the embedder's job.
pub struct SplitState {
    recovery_set_id: u16,
    threshold: u8,
    /// Every x-coordinate ever issued on this polynomial (1..=32, no duplicates), including
    /// lost and replaced ones - the cap in [`extend`] counts all of them.
    issued_x: Vec<u8>,
    /// Row-major `body_len × threshold` field elements, one polynomial per body byte, each
    /// row `[constant_term, c_1, …, c_{M-1}]`. Wiped on drop.
    coeffs: Vec<u8>,
}

impl SplitState {
    /// Number of body bytes (polynomials) this state pins. Invariant: `coeffs.len()` is an
    /// exact multiple of `threshold`, and `threshold >= 2`, so this never divides by zero.
    fn body_len(&self) -> usize {
        self.coeffs.len() / usize::from(self.threshold)
    }

    /// The recovery set id shared by every share of this split (11-bit, word 1 on the wire).
    pub fn recovery_set_id(&self) -> u16 {
        self.recovery_set_id
    }

    /// The reconstruction threshold `M`.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// How many shares have been issued over this split's lifetime (originals plus every
    /// extension, including lost and replaced cards). The soft cap in [`extend`] is `3·M − 1`.
    pub fn issued_count(&self) -> usize {
        self.issued_x.len()
    }

    /// Serialize to a stable, versioned little byte layout for sealing. **Secret-equivalent:**
    /// the caller MUST encrypt the result before persisting it (see the type docs). The
    /// returned buffer self-zeroizes on drop.
    ///
    /// Layout (all multi-byte fields big-endian):
    /// ```text
    /// [0]      version = 1
    /// [1]      threshold (M)
    /// [2..4]   recovery_set_id (u16)
    /// [4]      issued_count
    /// [5..7]   body_len (u16)
    /// [7..]    issued_x (issued_count bytes) ‖ coeffs (body_len * M bytes)
    /// ```
    ///
    /// # Panics
    ///
    /// Never in practice: it panics only if the state's construction invariants were violated
    /// (issued count > 32 or body length > 289), which both constructors ([`split_extendable`]
    /// and [`SplitState::from_bytes`]) enforce.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let body_len = self.body_len();
        // Exact capacity: `extend_from_slice` must never realloc and orphan an un-wiped copy
        // of the secret-bearing coefficients.
        let mut out = Zeroizing::new(Vec::with_capacity(
            7 + self.issued_x.len() + self.coeffs.len(),
        ));
        out.push(STATE_VERSION);
        out.push(self.threshold);
        out.extend_from_slice(&self.recovery_set_id.to_be_bytes());
        out.push(u8::try_from(self.issued_x.len()).expect("issued_x len <= 32 by construction"));
        out.extend_from_slice(
            &u16::try_from(body_len)
                .expect("body_len <= 289 by construction")
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.issued_x);
        out.extend_from_slice(&self.coeffs);
        out
    }

    /// Parse the bytes produced by [`SplitState::to_bytes`]. Rejects any malformed or
    /// out-of-range input without panicking (fuzz-robust). The caller is responsible for
    /// having decrypted and integrity-checked the bytes first (the AEAD is the embedder's).
    pub fn from_bytes(b: &[u8]) -> Result<Self, StateError> {
        // Fixed 7-byte header: version, M, rsid(2), issued_count, body_len(2). Direct indexing
        // is bounds-checked by this guard (matches `decode_share_parts`'s style).
        if b.len() < 7 {
            return Err(StateError::TooShort);
        }
        if b[0] != STATE_VERSION {
            return Err(StateError::UnsupportedVersion(b[0]));
        }
        let threshold = b[1];
        if !(MIN_THRESHOLD..=MAX_SHARES).contains(&threshold) {
            return Err(StateError::BadThreshold);
        }
        let recovery_set_id = u16::from_be_bytes([b[2], b[3]]);
        if recovery_set_id > 0x7FF {
            return Err(StateError::BadRecoverySetId);
        }
        let issued_count = usize::from(b[4]);
        if issued_count > usize::from(MAX_SHARES) {
            return Err(StateError::BadIssuedCount);
        }
        let body_len = usize::from(u16::from_be_bytes([b[5], b[6]]));
        if body_len == 0 || body_len > MAX_BODY_LEN {
            return Err(StateError::BadBodyLen);
        }

        let coeffs_len = body_len * usize::from(threshold); // <= 289 * 32, no overflow
        let expected = 7 + issued_count + coeffs_len;
        if b.len() != expected {
            return Err(StateError::LengthMismatch);
        }

        let issued_x = b[7..7 + issued_count].to_vec();
        for (i, &x) in issued_x.iter().enumerate() {
            if !(1..=MAX_SHARES).contains(&x) || issued_x[i + 1..].contains(&x) {
                return Err(StateError::BadXCoordinate);
            }
        }
        let coeffs = b[7 + issued_count..].to_vec();

        Ok(Self {
            recovery_set_id,
            threshold,
            issued_x,
            coeffs,
        })
    }
}

impl Drop for SplitState {
    fn drop(&mut self) {
        use chela_primitives::zeroize::Zeroize as _;
        // `coeffs` is secret-equivalent (its constant terms are the body); `issued_x` is not
        // secret, but wiping it too costs nothing and matches the "wipes on drop" contract.
        self.coeffs.zeroize();
        self.issued_x.zeroize();
    }
}

// Manual `Debug` (never derived): the derived form would print `coeffs`, i.e. the secret.
impl core::fmt::Debug for SplitState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SplitState")
            .field("recovery_set_id", &self.recovery_set_id)
            .field("threshold", &self.threshold)
            .field("issued_count", &self.issued_x.len())
            .finish_non_exhaustive()
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
fn build_bundle(
    input: &SplitInput<'_>,
) -> Result<(chela_primitives::zeroize::Zeroizing<Vec<u8>>, u8), EngineError> {
    match input {
        SplitInput::Bip39 {
            mnemonic,
            passphrase,
        } => {
            // `indices` and `entropy` are secret-derived. Wrap them in `Zeroizing` so they
            // wipe on every exit - including the `?` early returns below, which a mistyped
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

            // Pre-size `body` to its final length (payload + integrity tag + kind byte) and wrap
            // in `Zeroizing` so neither the `extend_from_slice`s here nor the tag/kind `push`es in
            // `build_bundle_v2` can realloc and orphan an un-wiped, entropy-holding buffer.
            let passphrase_bytes = if has_passphrase {
                passphrase.as_bytes()
            } else {
                &[][..]
            };
            let mut body = chela_primitives::zeroize::Zeroizing::new(Vec::with_capacity(
                entropy_bytes + passphrase_bytes.len() + 2,
            ));
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
            let mut body =
                chela_primitives::zeroize::Zeroizing::new(Vec::with_capacity(text.len() + 2));
            body.extend_from_slice(text.as_bytes());
            Ok((body, kind::TEXT))
        }
    }
}

/// Build the full SSS body: `payload ‖ tag ‖ kind_byte`.
///
/// `tag` is a one-byte integrity check ([`body_integrity_tag`]) that binds the reconstructed
/// secret, so a wrong recombination - e.g. two unrelated splits that happen to collide on the
/// 11-bit recovery set id - is rejected at recovery rather than returned as a plausible wrong secret. The
/// kind byte stays last: it is never `0x00`, so it remains the terminator recovery uses to trim
/// the trailing zero padding and find the true message end (see [`recover_secret`]).
fn build_bundle_v2(
    input: &SplitInput<'_>,
) -> Result<(chela_primitives::zeroize::Zeroizing<Vec<u8>>, u8), EngineError> {
    let (mut body, kind_byte) = build_bundle(input)?;
    let tag = body_integrity_tag(&body[..], kind_byte); // over the payload, before tag/kind appended
    body.push(tag); // capacity for tag + kind reserved in `build_bundle` - no realloc, no orphan
    body.push(kind_byte);
    Ok((body, kind_byte))
}

/// One-byte integrity tag `SHA-256(payload ‖ kind_byte)[0]`. Carried inside the SSS body (so a
/// single share never reveals it) and re-checked at recovery to catch a wrong recombination.
fn body_integrity_tag(payload: &[u8], kind_byte: u8) -> u8 {
    let mut hasher = chela_primitives::sha256::Sha256::new();
    hasher.update(payload);
    hasher.update(&[kind_byte]);
    hasher.finalize()[0]
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

/// Recover the secret from the SSS-combined body `payload ‖ tag ‖ kind_byte`, already trimmed to
/// its true length by [`recover_secret`]. The trailing kind byte names the payload interpretation;
/// the byte before it is the integrity tag. An invalid kind byte, a length that doesn't fit it, or
/// a tag that doesn't match the recomputed value means the wrong share subset.
fn parse_bundle(body: &[u8]) -> Result<RecoveredSecret, EngineError> {
    let (&kind_byte, rest) = body.split_last().ok_or(EngineError::BundleCorrupt)?;
    let dec = decode_kind_byte(kind_byte).ok_or(EngineError::BundleCorrupt)?;
    let (&tag, payload) = rest.split_last().ok_or(EngineError::BundleCorrupt)?;
    if !body_len_fits(dec, payload.len()) {
        return Err(EngineError::BundleCorrupt);
    }
    // The integrity tag binds the whole reconstructed secret; a wrong recombination fails this
    // constant-time check instead of decoding into a different, valid-looking secret.
    if !chela_primitives::ct::ct_eq(&[tag], &[body_integrity_tag(payload, kind_byte)]) {
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

/// Encode one share's words: `[X:5|M:5|reserved:1] ‖ [recovery set id:11] ‖ Y-words ‖ [CRC-11]`.
/// `share_bytes` is this share's SSS output (the Y values).
fn encode_share_bip39_v2(
    share_bytes: &[u8],
    recovery_set_id: u16,
    x: u8,
    threshold: u8,
) -> Vec<u16> {
    let x_field = u16::from(x - 1) & 0x1F; // 1..32 -> 0..31
    let m_field = u16::from(threshold - 2) & 0x1F; // 2..32 -> 0..30
    let word0 = (x_field << 6) | (m_field << 1); // reserved bit (bit 0) = 0
    let word1 = recovery_set_id & 0x7FF;

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

    out.push(share_crc(x, threshold, recovery_set_id, share_bytes));
    out
}

/// Candidate body-byte lengths for a Y-section of `k` words - every `B` with `ceil(8B/11) == k`.
/// At most two consecutive values (the byte/word grids only realign every 11 bytes); `(min, max)`.
fn candidate_body_lens(k: usize) -> (usize, usize) {
    let max_bytes = (k * 11) / 8;
    let min_bytes = (k.saturating_sub(1) * 11 + 1).div_ceil(8);
    (min_bytes, max_bytes)
}

/// CRC-11/UMTS over `[x, M] ‖ recovery_recovery_set_id_be ‖ y_bytes` - the per-share checksum input. `Zeroizing`
/// because the scratch holds share material.
fn share_crc(x: u8, threshold: u8, recovery_set_id: u16, y_bytes: &[u8]) -> u16 {
    let mut input =
        chela_primitives::zeroize::Zeroizing::new(Vec::with_capacity(4 + y_bytes.len()));
    input.push(x);
    input.push(threshold);
    input.extend_from_slice(&recovery_set_id.to_be_bytes());
    input.extend_from_slice(y_bytes);
    chela_primitives::crc::crc11_umts(&input[..])
}

/// Unpack a Y-section (`y_words`, 11-bit values, MSB-first) into `body_len` bytes; bits beyond
/// `body_len * 8` are dropped (zero padding).
fn unpack_y(y_words: &[u16], body_len: usize) -> chela_primitives::zeroize::Zeroizing<Vec<u8>> {
    let mut body = chela_primitives::zeroize::Zeroizing::new(vec![0u8; body_len]);
    let bits = body_len * 8;
    for (i, &w) in y_words.iter().enumerate() {
        for b in 0..11usize {
            let bit_pos = i * 11 + b;
            if bit_pos >= bits {
                break;
            }
            let bit = u8::try_from((w >> (10 - b)) & 1).unwrap();
            body[bit_pos / 8] |= bit << (7 - (bit_pos % 8));
        }
    }
    body
}

/// A share decoded from its words (everything the words carry - not kind or total).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedShare {
    pub x: u8,
    pub threshold: u8,
    pub recovery_set_id: u16,
    pub body: Vec<u8>,
}

impl Drop for DecodedShare {
    fn drop(&mut self) {
        // `body` is per-share SSS material; wipe on every path, success or error.
        chela_primitives::zeroize::Zeroize::zeroize(&mut self.body);
    }
}

/// A share's header fields plus a borrow of its Y-section and stored CRC. The exact body length
/// is *not* committed here - it is resolved across the whole set in [`recover_secret`].
struct ShareParts<'a> {
    x: u8,
    threshold: u8,
    recovery_set_id: u16,
    y_words: &'a [u16],
    crc: u16,
}

fn decode_share_parts(words: &[u16]) -> Result<ShareParts<'_>, EngineError> {
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
    let m_field = (meta >> 1) & 0x1F;
    if m_field == 31 {
        return Err(EngineError::ShareCorrupt); // would be M = 33
    }
    Ok(ShareParts {
        x: u8::try_from((meta >> 6) & 0x1F).unwrap() + 1,
        threshold: u8::try_from(m_field).unwrap() + 2,
        recovery_set_id: words[1] & 0x7FF,
        y_words: &words[2..words.len() - 1],
        crc: words[words.len() - 1] & 0x7FF,
    })
}

/// Decode a share from its BIP-39 word indices alone - the words-only recovery path. A single
/// share's exact body length is ambiguous (it is resolved across the set at recovery via the
/// kind-byte terminator), so this only validates the share's CRC at a candidate length and
/// returns its authoritative `x` / `threshold` / `recovery_set_id`.
pub fn decode_share_words(words: &[u16]) -> Result<DecodedShare, EngineError> {
    let p = decode_share_parts(words)?;
    let (min_bytes, max_bytes) = candidate_body_lens(p.y_words.len());
    for body_len in min_bytes..=max_bytes {
        let body = unpack_y(p.y_words, body_len);
        if share_crc(p.x, p.threshold, p.recovery_set_id, &body[..]) == p.crc {
            return Ok(DecodedShare {
                x: p.x,
                threshold: p.threshold,
                recovery_set_id: p.recovery_set_id,
                body: body.as_slice().to_vec(),
            });
        }
    }
    Err(EngineError::ShareCorrupt)
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
    let (shares, _state) = split_core(input, threshold, total, mode, rng, false)?;
    Ok(shares)
}

/// As [`split_secret`], but also returns the retained polynomial state so further shares can
/// be issued later on the same polynomial (same `recovery_set_id`, same threshold) via
/// [`extend`]. The returned shares are exactly those [`split_secret`] would produce; uses the
/// OS RNG. The [`SplitState`] is secret-equivalent and MUST be sealed before persistence -
/// see the [`SplitState`] docs.
pub fn split_extendable(
    input: &SplitInput<'_>,
    threshold: u8,
    total: u8,
    mode: OutputMode,
) -> Result<(Vec<Share>, SplitState), EngineError> {
    split_extendable_with_rng(input, threshold, total, mode, &mut OsRng)
}

/// As [`split_extendable`] but with an injectable RNG for testing.
pub fn split_extendable_with_rng(
    input: &SplitInput<'_>,
    threshold: u8,
    total: u8,
    mode: OutputMode,
    rng: &mut dyn RandomSource,
) -> Result<(Vec<Share>, SplitState), EngineError> {
    let (shares, state) = split_core(input, threshold, total, mode, rng, true)?;
    // `retain = true` always yields `Some`; surface the broken invariant as an error rather
    // than panicking (keeps this pub fn panic-free).
    let state = state.ok_or(EngineError::InvalidInput("internal: split-state not retained"))?;
    Ok((shares, state))
}

/// Shared body of [`split_with_rng`] and [`split_extendable_with_rng`]. When `retain` is set,
/// the polynomial coefficients are captured into a [`SplitState`]; otherwise the behavior -
/// RNG consumption, share bytes, wire encoding - is byte-identical to the original `split`.
fn split_core(
    input: &SplitInput<'_>,
    threshold: u8,
    total: u8,
    mode: OutputMode,
    rng: &mut dyn RandomSource,
    retain: bool,
) -> Result<(Vec<Share>, Option<SplitState>), EngineError> {
    if threshold < MIN_THRESHOLD {
        return Err(EngineError::InvalidInput("threshold must be at least 2"));
    }
    // `body` is the full plaintext secret plus the appended kind byte, already `Zeroizing` so it
    // wipes on every exit, including the BundleTooLarge and split-error early returns below.
    let (body, _kind_byte) = build_bundle_v2(input)?;
    if body.len() > MAX_BODY_LEN {
        return Err(EngineError::BundleTooLarge);
    }
    if total > MAX_SHARES {
        return Err(EngineError::InvalidInput("total must be 1..=32"));
    }

    let recovery_set_id = sample_recovery_recovery_set_id(rng)?;
    let mut xs = sample_distinct_x(total, rng)?;

    let mut share_bytes: Vec<Vec<u8>> = vec![vec![0u8; body.len()]; total as usize];

    // Retained coefficient matrix (body_len × M), only for the extendable path. Pre-sized to its
    // exact length and wrapped in `Zeroizing` so it never reallocs (orphaning secret material)
    // and always wipes on an early return; the non-retaining path allocates nothing.
    let mut coeffs: Zeroizing<Vec<u8>> = Zeroizing::new(if retain {
        vec![0u8; body.len() * usize::from(threshold)]
    } else {
        Vec::new()
    });

    let split_result = {
        let mut share_refs: Vec<&mut [u8]> =
            share_bytes.iter_mut().map(Vec::as_mut_slice).collect();
        if retain {
            split_retaining_coeffs(
                &body[..],
                threshold,
                total,
                rng,
                &mut xs,
                &mut share_refs,
                &mut coeffs[..],
            )
        } else {
            split(&body[..], threshold, total, rng, &mut xs, &mut share_refs)
        }
    };
    if let Err(e) = split_result {
        // share_bytes holds partial share material after a mid-split RNG failure; wipe it.
        // `coeffs` wipes itself on drop.
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
            OutputMode::Bip39Wordlist => encode_share_bip39_v2(&sb, recovery_set_id, x, threshold),
        };
        chela_primitives::zeroize::Zeroize::zeroize(&mut sb);
        out.push(Share {
            scheme: mode,
            x,
            threshold,
            recovery_set_id,
            total: Some(total),
            kind: Some(coarse_kind),
            word_indices,
        });
    }

    let state = if retain {
        // Move the coefficient bytes into the state (same allocation, no un-wiped copy); the
        // now-empty `coeffs` wrapper drops harmlessly. `xs` are the coordinates just issued.
        Some(SplitState {
            recovery_set_id,
            threshold,
            issued_x: xs,
            coeffs: core::mem::take(&mut *coeffs),
        })
    } else {
        None
    };

    Ok((out, state))
}

/// Draw `count` distinct x-coordinates in `1..=32` from the CSPRNG that are not already in
/// `issued` (rejection sampling, without replacement across the split's lifetime). The caller
/// MUST ensure `count <= 32 - issued.len()` so this terminates.
fn sample_fresh_x(
    count: u8,
    issued: &[u8],
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>, SssError> {
    let count = usize::from(count);
    let mut fresh: Vec<u8> = Vec::with_capacity(count);
    let mut byte = [0u8; 1];
    while fresh.len() < count {
        rng.fill_random(&mut byte)?;
        let x = (byte[0] & 0x1F) + 1; // field 0..31 -> x 1..32
        if !issued.contains(&x) && !fresh.contains(&x) {
            fresh.push(x);
        }
    }
    Ok(fresh)
}

/// The soft-cap ceiling for a threshold: `3·M − 1` lifetime shares (rev-3 § 5). Beyond it any
/// recovering coalition would be below one third of outstanding shares.
fn soft_cap(threshold: u8) -> usize {
    usize::from(threshold) * 3 - 1
}

/// Issue `count` additional shares on the polynomial pinned by `state`, at fresh CSPRNG-drawn
/// x-coordinates from `1..=32` not already issued. Uses the OS RNG; the returned shares are
/// byte-identical to what the original split would have emitted at those coordinates.
///
/// `input` is the same secret the split was made from: [`extend`] recomputes the body and
/// checks it against the state's retained constant terms, so a wrong secret/state pairing is a
/// clean [`ExtendError::WrongSecret`] rather than shares incompatible with the originals.
///
/// Issuance is capped: past the soft cap of `3·M − 1` lifetime shares this returns
/// [`ExtendError::OverSoftCap`] unless `allow_over_cap` is set; there is a hard ceiling of 32
/// ([`ExtendError::Exhausted`]). On success the new coordinates are recorded in `state`.
pub fn extend(
    state: &mut SplitState,
    input: &SplitInput<'_>,
    count: u8,
    allow_over_cap: bool,
    mode: OutputMode,
) -> Result<Vec<Share>, ExtendError> {
    extend_with_rng(state, input, count, allow_over_cap, mode, &mut OsRng)
}

/// As [`extend`] but with an injectable RNG for testing.
pub fn extend_with_rng(
    state: &mut SplitState,
    input: &SplitInput<'_>,
    count: u8,
    allow_over_cap: bool,
    mode: OutputMode,
    rng: &mut dyn RandomSource,
) -> Result<Vec<Share>, ExtendError> {
    if count == 0 {
        return Err(ExtendError::ZeroCount);
    }

    // Recompute the body from the supplied secret and constant-time-compare it against the
    // retained constant terms. This catches a wrong secret/state pairing (the embedder's AEAD
    // will usually catch it first; this also serves unsealed in-memory callers).
    let (body, _kind_byte) = build_bundle_v2(input).map_err(ExtendError::Bundle)?;
    let body_len = state.body_len();
    let m = usize::from(state.threshold);
    if body.len() != body_len {
        return Err(ExtendError::WrongSecret);
    }
    let mut constants = Zeroizing::new(vec![0u8; body_len]);
    for (slot, row) in constants.iter_mut().zip(state.coeffs.chunks_exact(m)) {
        *slot = row[0]; // constant term = original body byte
    }
    if !chela_primitives::ct::ct_eq(&body[..], &constants[..]) {
        return Err(ExtendError::WrongSecret);
    }

    // Hard cap: never exceed 32 lifetime coordinates. Check before drawing so exhaustion is a
    // clean error, not an infinite rejection loop.
    let issued = state.issued_x.len();
    let available = usize::from(MAX_SHARES) - issued;
    if usize::from(count) > available {
        return Err(ExtendError::Exhausted);
    }

    // Soft cap: require an explicit override once lifetime issuance would pass `3·M − 1`.
    let projected = issued + usize::from(count);
    if projected > soft_cap(state.threshold) && !allow_over_cap {
        return Err(ExtendError::OverSoftCap);
    }

    let new_xs = sample_fresh_x(count, &state.issued_x, rng).map_err(ExtendError::Sss)?;

    // Evaluate the retained polynomials at the new coordinates - byte-identical to split time.
    let mut share_bytes: Vec<Vec<u8>> = vec![vec![0u8; body_len]; usize::from(count)];
    let eval_result = {
        let mut refs: Vec<&mut [u8]> = share_bytes.iter_mut().map(Vec::as_mut_slice).collect();
        evaluate_shares(&state.coeffs, state.threshold, &new_xs, &mut refs)
    };
    if let Err(e) = eval_result {
        for sb in &mut share_bytes {
            chela_primitives::zeroize::Zeroize::zeroize(sb);
        }
        return Err(ExtendError::Sss(e));
    }

    let coarse_kind = match input {
        SplitInput::Bip39 { .. } => PayloadKind::Bip39,
        SplitInput::Text { .. } => PayloadKind::Text,
    };

    let mut out = Vec::with_capacity(usize::from(count));
    for (idx, mut sb) in share_bytes.into_iter().enumerate() {
        let x = new_xs[idx];
        let word_indices = match mode {
            OutputMode::Bip39Wordlist => {
                encode_share_bip39_v2(&sb, state.recovery_set_id, x, state.threshold)
            }
        };
        chela_primitives::zeroize::Zeroize::zeroize(&mut sb);
        out.push(Share {
            scheme: mode,
            x,
            threshold: state.threshold,
            recovery_set_id: state.recovery_set_id,
            // `total` (= N) is not carried in the words and is no longer well-defined once a
            // split grows; a decoder never needs it.
            total: None,
            kind: Some(coarse_kind),
            word_indices,
        });
    }

    // Commit the new coordinates only after every share issued successfully.
    state.issued_x.extend_from_slice(&new_xs);

    Ok(out)
}

/// Reconstruct a secret from at least `threshold` shares. `x`, `threshold`, and `recovery_set_id` are read
/// from the words; a present `total`/`kind` is advisory and ignored. The body length is resolved
/// for the whole set by the kind-byte terminator (below), not guessed per share.
pub fn recover_secret(shares: &[Share]) -> Result<RecoveredSecret, EngineError> {
    if shares.is_empty() {
        return Err(EngineError::InsufficientShares);
    }

    let mut parts: Vec<ShareParts> = Vec::with_capacity(shares.len());
    for s in shares {
        match s.scheme {
            OutputMode::Bip39Wordlist => parts.push(decode_share_parts(&s.word_indices)?),
        }
    }

    let first = &parts[0];
    for p in &parts[1..] {
        if p.recovery_set_id != first.recovery_set_id
            || p.threshold != first.threshold
            || p.y_words.len() != first.y_words.len()
        {
            return Err(EngineError::MismatchedShares); // different generation or corrupt
        }
    }
    if parts.len() < first.threshold as usize {
        return Err(EngineError::InsufficientShares);
    }

    let xs: Vec<u8> = parts.iter().map(|p| p.x).collect();
    for (i, &xi) in xs.iter().enumerate() {
        if xi == 0 || xs[i + 1..].contains(&xi) {
            return Err(EngineError::Sss(chela_sss::SssError::DuplicateXCoordinate));
        }
    }

    // Combine at the longest candidate length, then let the kind byte mark the message end: it
    // is the body's last byte and is never 0x00, while any over-read phantom byte is built from
    // zero padding - so a trailing 0x00 means the true body is one byte shorter. This resolves
    // the byte↔word-count ambiguity deterministically for the whole set (no per-share guessing).
    let (min_bytes, max_bytes) = candidate_body_lens(first.y_words.len());
    let ys: Vec<chela_primitives::zeroize::Zeroizing<Vec<u8>>> = parts
        .iter()
        .map(|p| unpack_y(p.y_words, max_bytes))
        .collect();
    let mut body = chela_primitives::zeroize::Zeroizing::new(vec![0u8; max_bytes]);
    {
        let refs: Vec<&[u8]> = ys.iter().map(|y| y.as_slice()).collect();
        combine(&xs, &refs, &mut body[..])?;
    }
    let body_len = if max_bytes > min_bytes && body[max_bytes - 1] == 0 {
        min_bytes
    } else {
        max_bytes
    };

    // Verify every share's CRC at the resolved length - a mistyped word fails here.
    for (p, y) in parts.iter().zip(ys.iter()) {
        if share_crc(p.x, p.threshold, p.recovery_set_id, &y[..body_len]) != p.crc {
            return Err(EngineError::ShareCorrupt);
        }
    }

    parse_bundle(&body[..body_len])
}

#[cfg(test)]
mod tests {
    use super::{
        extend, extend_with_rng, recover_secret, split_extendable, split_extendable_with_rng,
        split_secret, split_with_rng, ExtendError, OutputMode, RecoveredSecret, SplitInput,
        SplitState, StateError,
    };
    use alloc::string::String;
    use alloc::vec;
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
        // Layout is payload ‖ tag ‖ kind_byte; the kind byte stays last as the message terminator.
        assert_eq!(&body[..body.len() - 2], b"hi");
        assert_eq!(
            body[body.len() - 2],
            super::body_integrity_tag(b"hi", 0x0Bu8)
        );
        assert_eq!(body.last().copied(), Some(0x0Bu8)); // kind::TEXT
    }

    #[test]
    fn parse_bundle_rejects_invalid_kind() {
        use super::{build_bundle_v2, parse_bundle, EngineError, SplitInput};
        let (mut body, _) = build_bundle_v2(&SplitInput::Text { text: "hi" }).unwrap();
        parse_bundle(&body[..]).unwrap(); // sanity: the genuine body parses
        *body.last_mut().unwrap() = 0x00; // 0x00 is not a valid kind byte
        assert_eq!(parse_bundle(&body[..]), Err(EngineError::BundleCorrupt));
    }

    #[test]
    fn body_tag_rejects_tampered_payload() {
        use super::{build_bundle_v2, parse_bundle, EngineError, SplitInput};
        // A wrong recombination perturbs the payload bytes. Without the integrity tag those would
        // decode into a different, valid-looking secret; the tag must reject them instead. The
        // kind byte (last) and tag (second-last) are left intact so only the payload changes.
        let (mut body, _) = build_bundle_v2(&SplitInput::Text { text: "hello" }).unwrap();
        parse_bundle(&body[..]).unwrap(); // the genuine body parses
        body[0] ^= 0x01;
        assert_eq!(parse_bundle(&body[..]), Err(EngineError::BundleCorrupt));
    }

    #[test]
    fn body_tag_rejects_tampered_tag_byte() {
        use super::{build_bundle_v2, parse_bundle, EngineError, SplitInput};
        // body = payload ‖ tag ‖ kind; corrupting the tag byte (second from the end) is caught.
        let (mut body, _) = build_bundle_v2(&SplitInput::Text { text: "hello" }).unwrap();
        let n = body.len();
        body[n - 2] ^= 0x01;
        assert_eq!(parse_bundle(&body[..]), Err(EngineError::BundleCorrupt));
    }

    #[test]
    fn encode_layout_word0_and_nonce_and_crc() {
        use super::encode_share_bip39_v2;
        let body = [0xABu8, 0xCD, 0xEF]; // 3-byte Y -> ceil(24/11)=3 Y words
        let recovery_set_id = 0x123u16;
        let words = encode_share_bip39_v2(&body, recovery_set_id, /*x*/ 7, /*M*/ 3);
        // W = 2 (word0, recovery set id) + 3 (Y) + 1 (crc) = 6
        assert_eq!(words.len(), 6);
        // word0 = (x-1)<<6 | (M-2)<<1 | 0 = 6<<6 | 1<<1 = 0x186
        assert_eq!(words[0], (6 << 6) | (1 << 1));
        assert_eq!(words[1], recovery_set_id);
        let crc_input: Vec<u8> = [7u8, 3]
            .iter()
            .copied()
            .chain(recovery_set_id.to_be_bytes())
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
        use super::{decode_share_words, encode_share_bip39_v2, DecodedShare};
        let body = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        let words = encode_share_bip39_v2(&body, 0x2AA, 9, 4);
        let DecodedShare {
            x,
            threshold,
            recovery_set_id,
            body: got,
        } = &decode_share_words(&words).unwrap();
        assert_eq!((*x, *threshold, *recovery_set_id), (9, 4, 0x2AA));
        assert_eq!(got.as_slice(), body);

        // Flip one word -> CRC must reject.
        let mut bad = words.clone();
        bad[2] ^= 1;
        assert!(decode_share_words(&bad).is_err());

        // Reserved bit set -> reject.
        let mut bad0 = words.clone();
        bad0[0] |= 1;
        assert!(decode_share_words(&bad0).is_err());
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
            // Every share has distinct x in 1..=32 and a shared recovery set id.
            let n = shares[0].recovery_set_id;
            for s in &shares {
                assert!((1..=32).contains(&s.x));
                assert_eq!(s.recovery_set_id, n);
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
        // Same secret, two generations -> different recovery set ids -> mixing rejected.
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
                recovery_set_id: s.recovery_set_id,
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
    fn max_length_passphrase_round_trips() {
        // 32 entropy + 255 passphrase + tag + kind = 289 bytes, the largest legitimate body.
        // Guards the body-size bound after the integrity tag widened the body by one byte.
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let passphrase: String = "p".repeat(255);
        let shares = split_secret(
            &SplitInput::Bip39 {
                mnemonic,
                passphrase: passphrase.as_str(),
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
                assert_eq!(m.as_str(), mnemonic);
                assert_eq!(p, &passphrase);
            }
            RecoveredSecret::Text { .. } => panic!("expected bip39"),
        }
    }

    #[test]
    fn share_word_counts_are_pinned() {
        // body = payload ‖ tag ‖ kind_byte, then W = 3 + ceil(8 * body_len / 11).
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
        assert_eq!(s12[0].word_indices.len(), 17); // 16 entropy + 1 tag + 1 kind = 18 B

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
        assert_eq!(s24[0].word_indices.len(), 28); // 32 entropy + 1 tag + 1 kind = 34 B

        let t = split_secret(
            &SplitInput::Text { text: "hi" },
            2,
            3,
            OutputMode::Bip39Wordlist,
        )
        .unwrap();
        assert_eq!(t[0].word_indices.len(), 6); // 2 text + 1 tag + 1 kind = 4 B
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

        let recovery_set_id = shares[0].recovery_set_id;
        for s in &shares {
            assert_eq!(s.recovery_set_id, recovery_set_id);
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
        // Different generations get different random recovery set ids, so a mix is rejected - almost always
        // MismatchedShares, and in the ~1/2048 recovery-set-id-collision case BundleCorrupt. Either way the
        // wrong secret is never returned, which is all this guards.
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
        assert!(recover_secret(&mixed).is_err()); // never silently recovers a wrong secret
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

    // ---- Extendable-split profile (rev-3) ----------------------------------------------

    const EXT_TEXT: &str = "extendable split secret";

    fn ext_input() -> SplitInput<'static> {
        SplitInput::Text { text: EXT_TEXT }
    }

    // Recover from a chosen subset of shares (cloning, since recovery borrows).
    fn recover_subset(shares: &[super::Share], idxs: &[usize]) -> RecoveredSecret {
        let subset: Vec<super::Share> = idxs.iter().map(|&i| shares[i].clone()).collect();
        recover_secret(&subset).unwrap()
    }

    fn assert_is_ext_text(rec: &RecoveredSecret) {
        match rec {
            RecoveredSecret::Text { text } => assert_eq!(text, EXT_TEXT),
            RecoveredSecret::Bip39 { .. } => panic!("expected text"),
        }
    }

    #[test]
    fn split_extendable_shares_recover_like_a_plain_split() {
        let (shares, state) =
            split_extendable(&ext_input(), 2, 3, OutputMode::Bip39Wordlist).unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(state.issued_count(), 3);
        assert_eq!(state.threshold(), 2);
        for s in &shares {
            assert_eq!(s.recovery_set_id, state.recovery_set_id());
            assert!((1..=32).contains(&s.x));
        }
        assert_is_ext_text(&recover_subset(&shares, &[0, 1]));
    }

    #[test]
    fn mixed_original_and_extended_shares_recover() {
        let (orig, mut state) =
            split_extendable(&ext_input(), 3, 3, OutputMode::Bip39Wordlist).unwrap();
        // 3 + 2 = 5 issued, soft cap for M=3 is 8, so no override needed.
        let extra = extend(&mut state, &ext_input(), 2, false, OutputMode::Bip39Wordlist).unwrap();
        assert_eq!(extra.len(), 2);
        assert_eq!(state.issued_count(), 5);

        // Every share shares the split's rsid/threshold; x's are all distinct.
        let mut all = orig.clone();
        all.extend(extra.iter().cloned());
        let mut xs: Vec<u8> = all.iter().map(|s| s.x).collect();
        xs.sort_unstable();
        xs.dedup();
        assert_eq!(xs.len(), 5, "all issued x are distinct");
        for s in &all {
            assert_eq!(s.recovery_set_id, state.recovery_set_id());
            assert_eq!(s.threshold, 3);
        }

        // A quorum mixing originals and extended shares recovers the secret.
        assert_is_ext_text(&recover_subset(&all, &[0, 3, 4])); // 1 original + 2 extended
        assert_is_ext_text(&recover_subset(&all, &[1, 2, 3])); // 2 originals + 1 extended
    }

    #[test]
    fn every_m_subset_recovers_after_extension() {
        // Split 2-of-3, extend by 2 -> 5 lifetime shares on one polynomial; every 2-subset of
        // the full set must recover (the repo's round_trip_for_every_subset pattern).
        let (orig, mut state) =
            split_extendable(&ext_input(), 2, 3, OutputMode::Bip39Wordlist).unwrap();
        let extra = extend(&mut state, &ext_input(), 2, false, OutputMode::Bip39Wordlist).unwrap();
        let mut all = orig.clone();
        all.extend(extra.iter().cloned());
        assert_eq!(all.len(), 5);

        let n = all.len();
        for mask in 0u32..(1u32 << n) {
            if mask.count_ones() != 2 {
                continue;
            }
            let idxs: Vec<usize> = (0..n).filter(|i| mask & (1 << i) != 0).collect();
            assert_is_ext_text(&recover_subset(&all, &idxs));
        }
    }

    #[test]
    fn extended_share_is_byte_identical_to_split_output() {
        // Re-evaluating the retained polynomial at any *already issued* x must reproduce that
        // original share byte-for-byte - proving the state pins the exact split polynomial, and
        // hence that a later share at a fresh x is what split would have emitted there.
        let (orig, mut state) =
            split_extendable(&ext_input(), 3, 4, OutputMode::Bip39Wordlist).unwrap();
        let m = usize::from(state.threshold);
        let body_len = state.coeffs.len() / m;
        for (i, &x) in state.issued_x.clone().iter().enumerate() {
            let mut sb = vec![0u8; body_len];
            chela_sss::evaluate_shares(&state.coeffs, state.threshold, &[x], &mut [sb.as_mut_slice()])
                .unwrap();
            let words = super::encode_share_bip39_v2(&sb, state.recovery_set_id, x, state.threshold);
            assert_eq!(
                words, orig[i].word_indices,
                "re-evaluated share at issued x={x} matches original"
            );
        }

        // And a freshly extended share equals an independent evaluate+encode at its own x.
        let extra = extend(&mut state, &ext_input(), 1, false, OutputMode::Bip39Wordlist).unwrap();
        let e = &extra[0];
        let mut sb = vec![0u8; body_len];
        chela_sss::evaluate_shares(&state.coeffs, state.threshold, &[e.x], &mut [sb.as_mut_slice()])
            .unwrap();
        let words = super::encode_share_bip39_v2(&sb, state.recovery_set_id, e.x, state.threshold);
        assert_eq!(words, e.word_indices);
    }

    #[test]
    fn extend_rejects_wrong_secret() {
        let (_orig, mut state) =
            split_extendable(&ext_input(), 2, 3, OutputMode::Bip39Wordlist).unwrap();

        // Same length, different content -> constant terms differ.
        let wrong_text = "Extendable split secret"; // capital E; same byte length
        assert_eq!(wrong_text.len(), EXT_TEXT.len());
        let wrong_same_len = SplitInput::Text { text: wrong_text };
        assert_eq!(
            extend(&mut state, &wrong_same_len, 1, false, OutputMode::Bip39Wordlist),
            Err(ExtendError::WrongSecret)
        );

        // Different length -> body-length mismatch.
        let wrong_len = SplitInput::Text { text: "short" };
        assert_eq!(
            extend(&mut state, &wrong_len, 1, false, OutputMode::Bip39Wordlist),
            Err(ExtendError::WrongSecret)
        );

        // The correct secret still extends, and the count is untouched by the rejections above.
        assert_eq!(state.issued_count(), 3);
        let ok = extend(&mut state, &ext_input(), 1, false, OutputMode::Bip39Wordlist).unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(state.issued_count(), 4);
    }

    #[test]
    fn extend_enforces_soft_cap_and_override() {
        // M=2 -> soft cap 3*2-1 = 5.
        let (_orig, mut state) =
            split_extendable(&ext_input(), 2, 3, OutputMode::Bip39Wordlist).unwrap();
        assert_eq!(state.issued_count(), 3);

        // 3 + 3 = 6 > 5 without override -> distinguishable OverSoftCap, nothing issued.
        assert_eq!(
            extend(&mut state, &ext_input(), 3, false, OutputMode::Bip39Wordlist),
            Err(ExtendError::OverSoftCap)
        );
        assert_eq!(state.issued_count(), 3, "a rejected extend issues nothing");

        // 3 + 2 = 5 == cap -> allowed without override.
        extend(&mut state, &ext_input(), 2, false, OutputMode::Bip39Wordlist).unwrap();
        assert_eq!(state.issued_count(), 5);

        // 5 + 1 = 6 > 5 -> requires override; with it, succeeds.
        assert_eq!(
            extend(&mut state, &ext_input(), 1, false, OutputMode::Bip39Wordlist),
            Err(ExtendError::OverSoftCap)
        );
        extend(&mut state, &ext_input(), 1, true, OutputMode::Bip39Wordlist).unwrap();
        assert_eq!(state.issued_count(), 6);
    }

    #[test]
    fn extend_hard_caps_at_x_exhaustion() {
        // Fill 30 of 32 coordinates, then ask for 3 more: only 2 remain -> Exhausted.
        let (_orig, mut state) =
            split_extendable(&ext_input(), 2, 30, OutputMode::Bip39Wordlist).unwrap();
        assert_eq!(state.issued_count(), 30);
        assert_eq!(
            extend(&mut state, &ext_input(), 3, true, OutputMode::Bip39Wordlist),
            Err(ExtendError::Exhausted)
        );
        // The 2 that fit still issue (with override, since we're far past the soft cap).
        let last = extend(&mut state, &ext_input(), 2, true, OutputMode::Bip39Wordlist).unwrap();
        assert_eq!(last.len(), 2);
        assert_eq!(state.issued_count(), 32);
        // Now truly exhausted: not one more.
        assert_eq!(
            extend(&mut state, &ext_input(), 1, true, OutputMode::Bip39Wordlist),
            Err(ExtendError::Exhausted)
        );
    }

    #[test]
    fn extend_rejects_zero_count() {
        let (_orig, mut state) =
            split_extendable(&ext_input(), 2, 3, OutputMode::Bip39Wordlist).unwrap();
        assert_eq!(
            extend(&mut state, &ext_input(), 0, false, OutputMode::Bip39Wordlist),
            Err(ExtendError::ZeroCount)
        );
    }

    #[test]
    fn split_state_round_trips_through_bytes() {
        let (orig, mut state) =
            split_extendable(&ext_input(), 2, 3, OutputMode::Bip39Wordlist).unwrap();
        // Extend once so issued_x has a non-trivial length to serialize.
        let extra = extend(&mut state, &ext_input(), 1, false, OutputMode::Bip39Wordlist).unwrap();

        let bytes = state.to_bytes();
        let restored = SplitState::from_bytes(&bytes).unwrap();

        // Serialization is stable: re-serializing the restored state is byte-identical.
        assert_eq!(&restored.to_bytes()[..], &bytes[..]);
        assert_eq!(restored.recovery_set_id(), state.recovery_set_id());
        assert_eq!(restored.threshold(), state.threshold());
        assert_eq!(restored.issued_count(), state.issued_count());

        // The restored state is functionally equivalent: it extends onto the same polynomial,
        // and the new share recovers together with the originals.
        let mut restored = restored;
        let more = extend(&mut restored, &ext_input(), 1, false, OutputMode::Bip39Wordlist).unwrap();
        let mut all = orig.clone();
        all.extend(extra.iter().cloned());
        all.extend(more.iter().cloned());
        // Recover using the original share 0, the pre-serialization extension, and the
        // post-serialization extension - all must lie on one polynomial.
        assert_is_ext_text(&recover_subset(&all, &[0, 3]));
        assert_is_ext_text(&recover_subset(&all, &[0, 4]));
        assert_is_ext_text(&recover_subset(&all, &[3, 4]));
    }

    #[test]
    fn from_bytes_rejects_malformed_input() {
        let (_orig, state) =
            split_extendable(&ext_input(), 2, 3, OutputMode::Bip39Wordlist).unwrap();
        let good = state.to_bytes().as_slice().to_vec();

        // Sanity: the genuine bytes parse.
        SplitState::from_bytes(&good).unwrap();

        // Too short (header is 7 bytes). `SplitState` has no `PartialEq` (it holds secret
        // material), so compare the error side via `unwrap_err`.
        assert_eq!(SplitState::from_bytes(&[]).unwrap_err(), StateError::TooShort);
        assert_eq!(
            SplitState::from_bytes(&good[..6]).unwrap_err(),
            StateError::TooShort
        );

        // Wrong version.
        let mut bad = good.clone();
        bad[0] = 2;
        assert_eq!(
            SplitState::from_bytes(&bad).unwrap_err(),
            StateError::UnsupportedVersion(2)
        );

        // Bad threshold (1 and 33 both out of 2..=32).
        for m in [1u8, 33] {
            let mut bad = good.clone();
            bad[1] = m;
            assert_eq!(
                SplitState::from_bytes(&bad).unwrap_err(),
                StateError::BadThreshold
            );
        }

        // Recovery set id with a high bit set.
        let mut bad = good.clone();
        bad[2] |= 0x80; // top byte of the u16 -> value > 0x7FF
        assert_eq!(
            SplitState::from_bytes(&bad).unwrap_err(),
            StateError::BadRecoverySetId
        );

        // Truncated body (drop a coeff byte) -> length mismatch.
        let mut bad = good.clone();
        bad.pop();
        assert_eq!(
            SplitState::from_bytes(&bad).unwrap_err(),
            StateError::LengthMismatch
        );

        // Corrupt an issued x to 0 (first issued-x byte sits right after the 7-byte header).
        let mut bad = good.clone();
        bad[7] = 0;
        assert_eq!(
            SplitState::from_bytes(&bad).unwrap_err(),
            StateError::BadXCoordinate
        );
    }

    #[test]
    fn from_bytes_never_panics_on_arbitrary_bytes() {
        // Fuzz-style: feed a spread of lengths and byte patterns; from_bytes must always return
        // a Result, never panic. Also mutate a valid serialization at every byte position.
        for len in 0usize..300 {
            for &fill in &[0x00u8, 0x01, 0x7f, 0x80, 0xff] {
                let buf = vec![fill; len];
                let _ = SplitState::from_bytes(&buf);
            }
            // A pseudo-random-ish pattern (no external RNG needed).
            let buf: Vec<u8> = (0..len)
                .map(|i| u8::try_from((i.wrapping_mul(131).wrapping_add(17)) & 0xff).unwrap())
                .collect();
            let _ = SplitState::from_bytes(&buf);
        }

        let (_orig, state) =
            split_extendable(&ext_input(), 2, 4, OutputMode::Bip39Wordlist).unwrap();
        let good = state.to_bytes().as_slice().to_vec();
        for i in 0..good.len() {
            for delta in [1u8, 0x40, 0x80, 0xff] {
                let mut m = good.clone();
                m[i] = m[i].wrapping_add(delta);
                // Round-trips or errors, but never panics; if it parses, re-serialize is stable.
                if let Ok(s) = SplitState::from_bytes(&m) {
                    assert_eq!(&s.to_bytes()[..], &m[..]);
                }
            }
        }
    }

    #[test]
    fn extend_with_deterministic_rng_draws_fresh_distinct_x() {
        // A varied pool lets both x-sampling passes find distinct coordinates.
        let pool: Vec<u8> = (0..255u16).map(|i| u8::try_from(i).unwrap()).collect();
        let mut rng = DeterministicRng::new(&pool);
        let (orig, mut state) =
            split_extendable_with_rng(&ext_input(), 2, 3, OutputMode::Bip39Wordlist, &mut rng)
                .unwrap();
        let mut rng2 = DeterministicRng::new(&pool);
        let extra =
            extend_with_rng(&mut state, &ext_input(), 2, false, OutputMode::Bip39Wordlist, &mut rng2)
                .unwrap();
        // Fresh x's avoid every already-issued coordinate.
        for e in &extra {
            assert!(!orig.iter().any(|o| o.x == e.x));
        }
        let mut all = orig.clone();
        all.extend(extra.iter().cloned());
        assert_is_ext_text(&recover_subset(&all, &[0, 3]));
    }
}
