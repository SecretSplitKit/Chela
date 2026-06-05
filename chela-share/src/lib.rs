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
pub use export::{
    render_combined_folder, render_json_folder, render_share_json, render_shares_json,
    share_json_filename, shares_bundle_filename, CombinedFolder, JsonFolder,
};
pub use import::{extract_shares_from_html, extract_shares_from_json, ImportError};

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use chela_engine::{OutputMode, PayloadKind, Share};

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
}

/// A folder-worth of paper-backup files. Pure strings — no filesystem access (this crate
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
    /// every holder by name — this expands the social-graph attack surface, but reveals
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
    let id = format!("{:02X}{:02X}", first.identifier[0], first.identifier[1]);
    let threshold = first.threshold;
    let total = first.total;

    let title = match meta.backup_name {
        Some(name) if !name.trim().is_empty() => {
            format!("chela recovery kit — {} (set {id})", name.trim())
        }
        _ => format!("chela recovery kit — set {id}"),
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
    out.push_str("  README.txt    — this file\n");
    for share in shares {
        let filename = format!("share-{}.html", share.x);
        writeln!(out, "  {filename:<13} — share #{} of {total}", share.x).expect("write");
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
/// CHELA-<ID>-<x>-<M>-<N>-<W>
/// word1 word2 word3 ... wordW
/// ```
///
/// # Panics
/// Panics only on a hand-constructed `Share` with a word index outside `0..2048`.
pub fn format_share(share: &Share) -> String {
    // Scheme and kind are not included on the card.
    let _ = (share.scheme, share.kind);

    let word_count = share.word_indices.len();
    let mut out = format!(
        "CHELA-{:02X}{:02X}-{}-{}-{}-{}\n",
        share.identifier[0], share.identifier[1], share.x, share.threshold, share.total, word_count,
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

/// Parse a single share from a header line and a words line. Header is case-insensitive;
/// the header's word count must match the actual words on the second line.
pub fn parse_share(header: &str, words_line: &str) -> Result<Share, FormatError> {
    let header_trim = header.trim();
    let upper = uppercase_ascii(header_trim);
    let body = upper.strip_prefix("CHELA-").ok_or(FormatError::BadHeader)?;
    let parts: Vec<&str> = body.split('-').collect();
    if parts.len() != 5 {
        return Err(FormatError::BadHeader);
    }
    let id_hex = parts[0];
    // ASCII guard: `&id_hex[..2]` byte-indexes a &str and panics if not on a char
    // boundary. Without is_ascii(), a 4-byte non-ASCII slice (e.g. "\u{FFFD}W")
    // passes the length check and crashes the slicer — the fuzz harness originally
    // tripped on this exact case.
    if id_hex.len() != 4 || !id_hex.is_ascii() {
        return Err(FormatError::BadIdentifier);
    }
    let id_hi = parse_hex_byte(&id_hex[..2]).ok_or(FormatError::BadIdentifier)?;
    let id_lo = parse_hex_byte(&id_hex[2..]).ok_or(FormatError::BadIdentifier)?;
    let x: u8 = parts[1].parse().map_err(|_| FormatError::BadShareIndex)?;
    if x == 0 {
        return Err(FormatError::BadShareIndex);
    }
    let threshold: u8 = parts[2]
        .parse()
        .map_err(|_| FormatError::BadThresholdTotal)?;
    let total: u8 = parts[3]
        .parse()
        .map_err(|_| FormatError::BadThresholdTotal)?;
    if threshold < chela_engine::MIN_THRESHOLD || total < threshold {
        return Err(FormatError::BadThresholdTotal);
    }
    if x > total {
        return Err(FormatError::BadShareIndex);
    }
    let declared_words: usize = parts[4].parse().map_err(|_| FormatError::BadWordCount)?;

    let mut word_indices = Vec::new();
    for w in words_line.split_whitespace() {
        let idx = chela_bip39::word_to_index(w).ok_or(FormatError::UnknownWord)?;
        word_indices.push(idx);
    }
    if word_indices.is_empty() {
        return Err(FormatError::MissingWords);
    }
    if word_indices.len() != declared_words {
        return Err(FormatError::WordCountMismatch);
    }

    Ok(Share {
        identifier: [id_hi, id_lo],
        scheme: OutputMode::Bip39Wordlist,
        kind: PayloadKind::Bip39,
        threshold,
        total,
        x,
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

fn parse_hex_byte(s: &str) -> Option<u8> {
    if s.len() != 2 {
        return None;
    }
    u8::from_str_radix(s, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::{format_share, parse_share, parse_shares, FormatError};
    use chela_engine::{OutputMode, PayloadKind, Share};

    fn sample_share() -> Share {
        Share {
            identifier: [0xa4, 0xf7],
            scheme: OutputMode::Bip39Wordlist,
            kind: PayloadKind::Bip39,
            threshold: 3,
            total: 5,
            x: 2,
            word_indices: alloc::vec![0u16, 1, 2, 3, 4, 2047],
        }
    }

    #[test]
    fn round_trip_format_then_parse() {
        let s = sample_share();
        let txt = format_share(&s);
        let mut lines = txt.lines();
        let header = lines.next().unwrap();
        let words = lines.next().unwrap();
        assert!(lines.next().is_none() || lines.next().unwrap().is_empty());
        let parsed = parse_share(header, words).unwrap();
        assert_eq!(parsed, s);
    }

    #[test]
    fn format_emits_expected_header() {
        let s = sample_share();
        let txt = format_share(&s);
        assert!(txt.starts_with("CHELA-A4F7-2-3-5-6\n"));
        assert!(txt.contains("abandon ability able about above zoo"));
    }

    #[test]
    fn parse_share_rejects_non_ascii_identifier_with_4_byte_len() {
        // Fuzz crash 8c3bfb86: parts[0] = "\u{FFFD}W" has byte len 4 but isn't ASCII.
        // Pre-fix, &id_hex[..2] panicked on the char-boundary check.
        let header = "CHELA-\u{FFFD}W-1-2-3-1";
        assert!(matches!(
            parse_share(header, "abandon"),
            Err(FormatError::BadIdentifier)
        ));
    }

    #[test]
    fn parse_header_is_case_insensitive_on_prefix_and_hex() {
        let s = sample_share();
        let words = "abandon ability able about above zoo";
        let parsed = parse_share("chela-a4f7-2-3-5-6", words).unwrap();
        assert_eq!(parsed, s);
        let parsed = parse_share("Chela-A4f7-2-3-5-6", words).unwrap();
        assert_eq!(parsed, s);
    }

    #[test]
    fn parse_shares_handles_multiple_blocks() {
        let s1 = sample_share();
        let mut s2 = sample_share();
        s2.x = 4;
        let combined = format_share(&s1) + "\n" + &format_share(&s2);
        let parsed = parse_shares(&combined).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].x, 2);
        assert_eq!(parsed[1].x, 4);
    }

    #[test]
    fn parse_share_rejects_bad_header() {
        let err = parse_share("not-a-chela-header", "abandon").unwrap_err();
        assert_eq!(err, FormatError::BadHeader);
    }

    #[test]
    fn parse_share_rejects_unknown_word() {
        let err = parse_share("CHELA-A4F7-2-3-5-2", "abandon notarealwordatall").unwrap_err();
        assert_eq!(err, FormatError::UnknownWord);
    }

    #[test]
    fn parse_share_rejects_word_count_mismatch() {
        let err =
            parse_share("CHELA-A4F7-2-3-5-6", "abandon ability able about above").unwrap_err();
        assert_eq!(err, FormatError::WordCountMismatch);
    }

    #[test]
    fn parse_share_rejects_zero_share_index() {
        let err =
            parse_share("CHELA-A4F7-0-3-5-6", "abandon ability able about above zoo").unwrap_err();
        assert_eq!(err, FormatError::BadShareIndex);
    }

    #[test]
    fn parse_share_rejects_threshold_greater_than_total() {
        let err =
            parse_share("CHELA-A4F7-2-5-3-6", "abandon ability able about above zoo").unwrap_err();
        assert_eq!(err, FormatError::BadThresholdTotal);
    }
}
