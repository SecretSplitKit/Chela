//! Share serialization: plain-text card format and print-ready HTML paper backup.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod html;
pub use html::render_paper_html;
use html::render_share_card_html;

pub mod export;
pub mod import;
pub mod json;

#[cfg(test)]
mod test_rng;
pub use export::{
    render_combined_folder, render_json_folder, render_share_json, render_shares_json,
    share_json_filename, shares_bundle_filename, CombinedFolder, JsonFolder,
};
pub use import::{extract_shares_from_html, extract_shares_from_json, ImportError};

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use chela_engine::{OutputMode, Share};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    BadHeader,
    BadIdentifier,
    BadThresholdTotal,
    BadShareIndex,
    BadWordCount,
    UnknownWord,
    MissingWords,
    WordCountMismatch,
    /// The words decoded cleanly but the advisory header disagrees on x/M/nonce -
    /// a transcription error on the human-readable label.
    HeaderWordsMismatch,
    /// The words failed to decode (bad CRC, reserved bit set, too few words).
    ShareCorrupt,
}

impl core::fmt::Display for FormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadHeader => f.write_str("a CHELA header line is malformed"),
            Self::BadIdentifier => f.write_str("the CHELA header's set id is not 4 hex characters"),
            Self::BadThresholdTotal => {
                f.write_str("the CHELA header's threshold/total fields are malformed")
            }
            Self::BadShareIndex => f.write_str("the CHELA header's share number is malformed"),
            Self::BadWordCount => f.write_str("the CHELA header's word count is malformed"),
            Self::UnknownWord => {
                f.write_str("a share contains a word that is not in the BIP-39 word list (check spelling)")
            }
            Self::MissingWords => f.write_str("a share has no words"),
            Self::WordCountMismatch => {
                f.write_str("a share's word count doesn't match its CHELA header")
            }
            Self::HeaderWordsMismatch => f.write_str(
                "a share's CHELA header disagrees with its words (a label was mistranscribed)",
            ),
            Self::ShareCorrupt => f.write_str(
                "a share failed its built-in checksum: one of its words was mistyped, or the share has the wrong number of words",
            ),
        }
    }
}

/// A folder-worth of paper-backup files. Pure strings - no filesystem access (this crate
/// is `#![no_std]`); the binaries write each `(filename, contents)` pair to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaperFolder {
    /// Contents of `README.txt`.
    pub readme: String,
    /// `(filename, html_contents)` per share, e.g. `share-1.html`.
    pub shares: Vec<(String, String)>,
}

/// Presentation-layer metadata rendered onto each share card and into the README. None of
/// these values affect the cryptographic payload.
#[derive(Debug, Clone, Copy, Default)]
pub struct BackupMeta<'a> {
    /// Short title shown at the top of each card.
    pub backup_name: Option<&'a str>,
    /// Optional free-form note rendered at the top of each card.
    pub description: Option<&'a str>,
    /// Optional N shareholder names indexed by `x - 1`. When present, each card lists
    /// every holder by name - this expands the social-graph attack surface, but reveals
    /// no share data. Rendering is suppressed if the count doesn't match the share set.
    pub shareholder_names: Option<&'a [String]>,
}

/// Render the paper backup as a folder of files (one HTML page per share + README).
#[must_use]
pub fn render_paper_folder(shares: &[Share], meta: &BackupMeta<'_>) -> PaperFolder {
    let names_valid = meta
        .shareholder_names
        .filter(|names| names.len() == shares.len());

    let share_files: Vec<(String, String)> = shares
        .iter()
        .map(|share| {
            let filename = format!("share-{}.html", share.x);
            let local_meta = BackupMeta {
                shareholder_names: names_valid,
                ..*meta
            };
            let html = render_share_card_html(share, &local_meta);
            (filename, html)
        })
        .collect();

    let readme = render_readme(shares, meta, names_valid);

    PaperFolder {
        readme,
        shares: share_files,
    }
}

fn render_readme(
    shares: &[Share],
    meta: &BackupMeta<'_>,
    shareholder_names: Option<&[String]>,
) -> String {
    let Some(first) = shares.first() else {
        return String::new();
    };
    let id = format!("{:04X}", first.nonce & 0x7FF);
    let threshold = first.threshold;
    let total = first
        .total
        .map_or_else(|| "?".into(), |n: u8| n.to_string());

    let title = match meta.backup_name {
        Some(name) if !name.trim().is_empty() => {
            format!("chela recovery kit - {} (set {id})", name.trim())
        }
        _ => format!("chela recovery kit - set {id}"),
    };
    let mut out = String::with_capacity(1024);
    out.push_str(&title);
    out.push('\n');
    let underline_len = title.chars().count();
    for _ in 0..underline_len {
        out.push('=');
    }
    out.push_str("\n\n");

    if let Some(desc) = meta.description {
        out.push_str(desc);
        out.push_str("\n\n");
    }

    if let Some(names) = shareholder_names {
        out.push_str("Share holders in this set:\n");
        for (idx, name) in names.iter().enumerate() {
            let n = idx + 1;
            writeln!(out, "  {n}. {name}").expect("write");
        }
        out.push('\n');
    }

    out.push_str("Contents of this folder:\n");
    out.push_str("  README.txt    - this file\n");
    for share in shares {
        let filename = format!("share-{}.html", share.x);
        writeln!(out, "  {filename:<13} - share #{} of {total}", share.x).expect("write");
    }
    out.push('\n');

    write!(
        out,
        "Open each share-N.html in a browser and choose File → Print to put it on\n\
         paper. Distribute one printed share to each trusted person. Any {threshold} of\n\
         the {total} shares together can recover the secret; any fewer reveals nothing.\n\n\
         Once the paper copies are distributed, you can safely delete this folder.\n",
    )
    .expect("write");

    out
}

/// Render a [`Share`] as the canonical two-line text format:
///
/// ```text
/// CHELA-<NONCE>-<x>-<M>-<N>-<W>
/// word1 word2 word3 ... wordW
/// ```
///
/// `<NONCE>` is the 11-bit generation nonce in 4 hex digits (high bits zero). The
/// header is advisory: the words alone carry x, M, and the nonce. `<N>` is `?` when
/// the total is unknown (a words-only or single-share context).
///
/// # Panics
/// Panics only on a hand-constructed `Share` with a word index outside `0..2048`.
pub fn format_share(share: &Share) -> String {
    // Scheme and kind are not included on the card.
    let _ = (share.scheme, share.kind);

    let word_count = share.word_indices.len();
    let total = share.total.map_or_else(|| "?".into(), |n| n.to_string());
    let mut out = format!(
        "CHELA-{:04X}-{}-{}-{}-{}\n",
        share.nonce & 0x7FF,
        share.x,
        share.threshold,
        total,
        word_count,
    );
    let mut first = true;
    for &idx in &share.word_indices {
        let word = chela_bip39::index_to_word(idx).expect("share contains valid wordlist index");
        if !first {
            out.push(' ');
        }
        first = false;
        out.push_str(word);
    }
    out.push('\n');
    out
}

/// Parse a single share from a header line and a words line. The words are
/// authoritative - they alone carry x, M, and the nonce. The header is advisory:
/// it is cross-checked against the decoded words (a disagreement is a transcription
/// error, [`FormatError::HeaderWordsMismatch`]) and supplies the total `N`.
///
/// Header is case-insensitive.
pub fn parse_share(header: &str, words_line: &str) -> Result<Share, FormatError> {
    let mut share = parse_share_words(words_line)?;

    let upper = uppercase_ascii(header.trim());
    let body = upper.strip_prefix("CHELA-").ok_or(FormatError::BadHeader)?;
    let parts: Vec<&str> = body.split('-').collect();
    if parts.len() != 5 {
        return Err(FormatError::BadHeader);
    }
    let h_nonce = u16::from_str_radix(parts[0], 16).map_err(|_| FormatError::BadIdentifier)?;
    let h_x: u8 = parts[1].parse().map_err(|_| FormatError::BadShareIndex)?;
    let h_m: u8 = parts[2]
        .parse()
        .map_err(|_| FormatError::BadThresholdTotal)?;
    if (h_nonce & 0x7FF) != share.nonce || h_x != share.x || h_m != share.threshold {
        return Err(FormatError::HeaderWordsMismatch);
    }
    // `N` is `?` for a words-only / single-share label; otherwise it's the total.
    if parts[3] != "?" {
        let h_n: u8 = parts[3]
            .parse()
            .map_err(|_| FormatError::BadThresholdTotal)?;
        share.total = Some(h_n);
    }
    // `W` (word count) is advisory like the other header fields: a disagreement with the actual
    // words is a transcription error, flagged here instead of surfacing later as a CRC failure.
    let h_w: usize = parts[4].parse().map_err(|_| FormatError::BadWordCount)?;
    if h_w != share.word_indices.len() {
        return Err(FormatError::WordCountMismatch);
    }
    Ok(share)
}

/// Recover a share from its BIP-39 words alone - no header. This is the
/// authoritative path for words-only backups: the words carry x, M, and the nonce,
/// verified by the per-share CRC. `total` and `kind` stay `None` (a lone share's
/// words reveal neither).
pub fn parse_share_words(words_line: &str) -> Result<Share, FormatError> {
    let mut word_indices = Vec::new();
    for w in words_line.split_whitespace() {
        word_indices.push(chela_bip39::word_to_index(w).ok_or(FormatError::UnknownWord)?);
    }
    if word_indices.is_empty() {
        return Err(FormatError::MissingWords);
    }
    let d =
        chela_engine::decode_share_words(&word_indices).map_err(|_| FormatError::ShareCorrupt)?;
    Ok(Share {
        scheme: OutputMode::Bip39Wordlist,
        x: d.x,
        threshold: d.threshold,
        nonce: d.nonce,
        total: None,
        kind: None,
        word_indices,
    })
}

fn uppercase_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        out.push(c.to_ascii_uppercase());
    }
    out
}

/// Parse zero or more shares from a multi-line input. Shares are separated by blank lines.
pub fn parse_shares(input: &str) -> Result<Vec<Share>, FormatError> {
    let mut shares = Vec::new();
    let mut lines = input.lines().peekable();
    while lines.peek().is_some() {
        while lines.peek().is_some_and(|l| l.trim().is_empty()) {
            lines.next();
        }
        let Some(header_line) = lines.next() else {
            break;
        };
        let header = header_line.trim();
        if header.is_empty() {
            continue;
        }
        let words_line = lines.next().ok_or(FormatError::MissingWords)?;
        shares.push(parse_share(header, words_line.trim())?);
    }
    Ok(shares)
}

#[cfg(test)]
mod tests {
    use super::{format_share, parse_share, parse_share_words, parse_shares, FormatError};
    use crate::test_rng::SeededRng;
    use alloc::string::String;
    use chela_engine::{split_with_rng, OutputMode, Share, SplitInput};

    /// A real 2-of-3 generation. The words carry x/M/nonce; fixtures are never hand-built.
    /// Deterministic (fixed seed) so data-dependent assertions below cannot flake.
    fn fixture() -> alloc::vec::Vec<Share> {
        let mut rng = SeededRng(0x5EED_1234_ABCD_0001);
        split_with_rng(
            &SplitInput::Text {
                text: "correct horse battery staple",
            },
            2,
            3,
            OutputMode::Bip39Wordlist,
            &mut rng,
        )
        .unwrap()
    }

    /// The words line (no header) for a share.
    fn words_line(s: &Share) -> String {
        let txt = format_share(s);
        txt.lines().nth(1).unwrap().into()
    }

    #[test]
    fn round_trip_format_then_parse() {
        let s = &fixture()[0];
        let txt = format_share(s);
        let mut lines = txt.lines();
        let header = lines.next().unwrap();
        let words = lines.next().unwrap();
        let parsed = parse_share(header, words).unwrap();
        // The advisory header carried the total; otherwise the share is reproduced.
        assert_eq!(parsed.x, s.x);
        assert_eq!(parsed.threshold, s.threshold);
        assert_eq!(parsed.nonce, s.nonce);
        assert_eq!(parsed.total, s.total);
        assert_eq!(parsed.word_indices, s.word_indices);
    }

    #[test]
    fn format_emits_nonce_x_m_n_w_header() {
        let s = &fixture()[0];
        let header: String = format_share(s).lines().next().unwrap().into();
        let expected: String = alloc::format!(
            "CHELA-{:04X}-{}-{}-{}-{}",
            s.nonce & 0x7FF,
            s.x,
            s.threshold,
            s.total.unwrap(),
            s.word_indices.len(),
        );
        assert_eq!(header, expected);
    }

    #[test]
    fn format_uses_question_mark_for_unknown_total() {
        let mut s = fixture().into_iter().next().unwrap();
        s.total = None;
        let header: String = format_share(&s).lines().next().unwrap().into();
        let expected: String = alloc::format!(
            "CHELA-{:04X}-{}-{}-?-{}",
            s.nonce & 0x7FF,
            s.x,
            s.threshold,
            s.word_indices.len(),
        );
        assert_eq!(header, expected);
    }

    #[test]
    fn parse_share_rejects_header_word_count_mismatch() {
        let s = &fixture()[0];
        let txt = format_share(s);
        let mut lines = txt.lines();
        let header = lines.next().unwrap();
        let words = lines.next().unwrap();
        // Bump the trailing W field so it disagrees with the actual word count.
        let wrong = s.word_indices.len() + 1;
        let (head, _) = header.rsplit_once('-').unwrap();
        let bad = alloc::format!("{head}-{wrong}");
        assert_eq!(
            parse_share(&bad, words),
            Err(FormatError::WordCountMismatch)
        );
    }

    #[test]
    fn parse_share_rejects_malformed_header_word_count() {
        let s = &fixture()[0];
        let txt = format_share(s);
        let mut lines = txt.lines();
        let header = lines.next().unwrap();
        let words = lines.next().unwrap();
        let (head, _) = header.rsplit_once('-').unwrap();
        let bad = alloc::format!("{head}-xx");
        assert_eq!(parse_share(&bad, words), Err(FormatError::BadWordCount));
    }

    #[test]
    fn words_alone_recover_share_without_header() {
        let s = &fixture()[0];
        let parsed = parse_share_words(&words_line(s)).unwrap();
        assert_eq!(parsed.x, s.x);
        assert_eq!(parsed.threshold, s.threshold);
        assert_eq!(parsed.nonce, s.nonce);
        assert_eq!(parsed.total, None);
        assert_eq!(parsed.kind, None);
        assert_eq!(parsed.word_indices, s.word_indices);
    }

    #[test]
    fn header_is_advisory_and_cross_checked() {
        let s = &fixture()[0];
        let words = words_line(s);
        // A header that disagrees with the words on x is a transcription error.
        let wrong_x = (s.x % 32) + 1;
        let bad = alloc::format!(
            "CHELA-{:04X}-{}-{}-{}-{}",
            s.nonce & 0x7FF,
            wrong_x,
            s.threshold,
            s.total.unwrap(),
            s.word_indices.len(),
        );
        assert_eq!(
            parse_share(&bad, &words).unwrap_err(),
            FormatError::HeaderWordsMismatch,
        );
    }

    #[test]
    fn header_question_mark_total_leaves_total_unknown() {
        let s = &fixture()[0];
        let words = words_line(s);
        let header = alloc::format!(
            "CHELA-{:04X}-{}-{}-?-{}",
            s.nonce & 0x7FF,
            s.x,
            s.threshold,
            s.word_indices.len(),
        );
        let parsed = parse_share(&header, &words).unwrap();
        assert_eq!(parsed.total, None);
    }

    #[test]
    fn parse_header_is_case_insensitive() {
        let s = &fixture()[0];
        let header = format_share(s).lines().next().unwrap().to_lowercase();
        let words = words_line(s);
        let parsed = parse_share(&header, &words).unwrap();
        assert_eq!(parsed.nonce, s.nonce);
        assert_eq!(parsed.total, s.total);
    }

    #[test]
    fn parse_shares_handles_multiple_blocks() {
        let shares = fixture();
        let combined = format_share(&shares[0]) + "\n" + &format_share(&shares[1]);
        let parsed = parse_shares(&combined).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].x, shares[0].x);
        assert_eq!(parsed[1].x, shares[1].x);
    }

    #[test]
    fn parse_share_rejects_non_ascii_header_without_panicking() {
        // Fuzz crash 8c3bfb86: a 4-byte non-ASCII nonce field must not crash the parser.
        let s = &fixture()[0];
        let words = words_line(s);
        let header = "CHELA-\u{FFFD}W-1-2-3-1";
        assert!(parse_share(header, &words).is_err());
    }

    #[test]
    fn parse_share_rejects_bad_header() {
        let s = &fixture()[0];
        let err = parse_share("not-a-chela-header", &words_line(s)).unwrap_err();
        assert_eq!(err, FormatError::BadHeader);
    }

    #[test]
    fn parse_share_rejects_unknown_word() {
        let err = parse_share_words("abandon notarealwordatall").unwrap_err();
        assert_eq!(err, FormatError::UnknownWord);
    }

    #[test]
    fn parse_share_words_rejects_empty() {
        assert_eq!(
            parse_share_words("   ").unwrap_err(),
            FormatError::MissingWords
        );
    }

    #[test]
    fn parse_share_words_rejects_corrupt_words() {
        // Real words, single transcription flip → CRC rejects. Relies on the deterministic
        // fixture: the 11-bit CRC can miss a flip ~1/2048 of the time at an ambiguous body
        // length, so random data would make this flaky.
        let s = &fixture()[0];
        let mut idx = s.word_indices.clone();
        idx[2] ^= 1;
        let line = idx
            .iter()
            .map(|&i| chela_bip39::index_to_word(i).unwrap())
            .collect::<alloc::vec::Vec<_>>()
            .join(" ");
        assert_eq!(
            parse_share_words(&line).unwrap_err(),
            FormatError::ShareCorrupt
        );
    }
}
