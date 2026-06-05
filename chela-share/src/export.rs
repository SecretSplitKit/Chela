//! JSON export of chela shares: per-share `chela.share.v1` files and a combined `chela.shares.v1` bundle.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use chela_engine::{OutputMode, PayloadKind, Share};

use crate::{format_share, BackupMeta, PaperFolder};

/// Per-share `.share.json` filename: `share-<x>.share.json`.
#[must_use]
pub fn share_json_filename(share: &Share) -> String {
    format!("share-{}.share.json", share.x)
}

/// Bundle filename: `chela-<setID>-shares.json`.
#[must_use]
pub fn shares_bundle_filename(shares: &[Share]) -> String {
    let id = shares.first().map_or("0000".to_owned(), |s| {
        format!("{:02X}{:02X}", s.identifier[0], s.identifier[1])
    });
    format!("chela-{id}-shares.json")
}

/// Render a single share as a standalone `chela.share.v1` JSON document (trailing newline included).
#[must_use]
pub fn render_share_json(share: &Share, meta: &BackupMeta<'_>) -> String {
    let mut out = String::with_capacity(1024);
    write_share_json_object(&mut out, share, meta);
    out.push('\n');
    out
}

/// Render every share as a single `chela.shares.v1` bundle document (trailing newline included).
#[must_use]
pub fn render_shares_json(shares: &[Share], meta: &BackupMeta<'_>) -> String {
    let names_valid = meta
        .shareholder_names
        .filter(|names| names.len() == shares.len());
    let local_meta = BackupMeta {
        shareholder_names: names_valid,
        ..*meta
    };

    let mut out = String::with_capacity(2048);
    out.push('{');
    out.push_str("\"type\":\"chela.shares.v1\",");
    out.push_str("\"shares\":[");
    for (i, share) in shares.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_share_json_object(&mut out, share, &local_meta);
    }
    out.push(']');
    out.push_str("}\n");
    out
}

/// A folder-worth of per-share JSON files. Pure strings — no filesystem access
/// (this crate is `#![no_std]`); the binaries write each `(filename, contents)`
/// pair to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonFolder {
    /// `(filename, contents)` per share, e.g. `share-1.share.json`.
    pub shares: Vec<(String, String)>,
    /// Filename + contents of the combined bundle (`chela-<setID>-shares.json`).
    pub bundle: (String, String),
}

/// Render every share as both per-share files AND a combined bundle file.
#[must_use]
pub fn render_json_folder(shares: &[Share], meta: &BackupMeta<'_>) -> JsonFolder {
    let names_valid = meta
        .shareholder_names
        .filter(|names| names.len() == shares.len());

    let share_files: Vec<(String, String)> = shares
        .iter()
        .map(|share| {
            let local_meta = BackupMeta {
                shareholder_names: names_valid,
                ..*meta
            };
            (
                share_json_filename(share),
                render_share_json(share, &local_meta),
            )
        })
        .collect();

    let bundle = (
        shares_bundle_filename(shares),
        render_shares_json(shares, meta),
    );

    JsonFolder {
        shares: share_files,
        bundle,
    }
}

/// Construct a combined HTML + JSON output folder.
#[must_use]
pub fn render_combined_folder(shares: &[Share], meta: &BackupMeta<'_>) -> CombinedFolder {
    CombinedFolder {
        paper: crate::render_paper_folder(shares, meta),
        json: render_json_folder(shares, meta),
    }
}

/// Both paper-backup and JSON formats together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CombinedFolder {
    pub paper: PaperFolder,
    pub json: JsonFolder,
}

/// Write a single `chela.share.v1` JSON object (no surrounding tags / newlines) to `out`.
///
/// String fields escape `<` to `<` so a user-supplied `</script>` in
/// `description` / `backup_name` / `shareholder_names` can't break out of the
/// surrounding `<script>` tag when this JSON is embedded in HTML.
pub(crate) fn write_share_json_object(out: &mut String, share: &Share, meta: &BackupMeta<'_>) {
    out.push('{');
    out.push_str("\"type\":\"chela.share.v1\",");

    out.push_str("\"card_code\":");
    let card_code = format_share(share).lines().next().unwrap_or("").to_owned();
    json_string(out, &card_code);
    out.push(',');

    out.push_str("\"set_id\":");
    json_string(
        out,
        &format!("{:02X}{:02X}", share.identifier[0], share.identifier[1]),
    );
    out.push(',');

    let _ = write!(out, "\"card_number\":{},", share.x);
    let _ = write!(out, "\"threshold\":{},", share.threshold);
    let _ = write!(out, "\"total\":{},", share.total);
    let _ = write!(out, "\"word_count\":{},", share.word_indices.len());

    out.push_str("\"scheme\":");
    json_string(out, scheme_name(share.scheme));
    out.push(',');

    out.push_str("\"payload_kind\":");
    json_string(out, payload_kind_name(share.kind));
    out.push(',');

    out.push_str("\"words\":[");
    let mut first = true;
    for &idx in &share.word_indices {
        if !first {
            out.push(',');
        }
        first = false;
        let word = chela_bip39::index_to_word(idx).expect("share index is in 0..2048");
        json_string(out, word);
    }
    out.push(']');

    if let Some(name) = meta.backup_name.filter(|s| !s.trim().is_empty()) {
        out.push_str(",\"backup_name\":");
        json_string(out, name);
    }
    if let Some(desc) = meta.description.filter(|s| !s.trim().is_empty()) {
        out.push_str(",\"description\":");
        json_string(out, desc);
    }
    if let Some(names) = meta.shareholder_names {
        out.push_str(",\"shareholder_names\":[");
        let mut first = true;
        for name in names {
            if !first {
                out.push(',');
            }
            first = false;
            json_string(out, name);
        }
        out.push(']');
    }

    out.push('}');
}

/// Write a JSON string literal with standard escapes plus `<` → `<` to keep JSON safe inside HTML `<script>` tags.
pub(crate) fn json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '<' => out.push_str("\\u003c"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn scheme_name(s: OutputMode) -> &'static str {
    match s {
        OutputMode::Bip39Wordlist => "bip39-wordlist",
    }
}

fn payload_kind_name(k: PayloadKind) -> &'static str {
    match k {
        PayloadKind::Bip39 => "bip39",
        PayloadKind::Text => "text",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract_shares_from_json;
    use alloc::vec::Vec;
    use chela_engine::{OutputMode, PayloadKind, Share};

    fn sample() -> Share {
        Share {
            identifier: [0xa4, 0xf7],
            scheme: OutputMode::Bip39Wordlist,
            kind: PayloadKind::Bip39,
            threshold: 3,
            total: 5,
            x: 2,
            word_indices: alloc::vec![0u16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        }
    }

    #[test]
    fn share_json_filename_format() {
        let s = sample();
        assert_eq!(share_json_filename(&s), "share-2.share.json");
    }

    #[test]
    fn bundle_filename_includes_set_id() {
        let s = sample();
        assert_eq!(shares_bundle_filename(&[s]), "chela-A4F7-shares.json");
    }

    #[test]
    fn bundle_filename_empty_input_falls_back() {
        // Defensive: don't panic if called with no shares.
        assert_eq!(shares_bundle_filename(&[]), "chela-0000-shares.json");
    }

    #[test]
    fn render_share_json_round_trips_to_share() {
        let original = sample();
        let json = render_share_json(&original, &BackupMeta::default());
        // Must parse, exactly one share.
        let result = extract_shares_from_json(&json).unwrap();
        assert_eq!(result.len(), 1);
        let parsed = result.into_iter().next().unwrap().unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn render_share_json_emits_schema_sentinel() {
        let json = render_share_json(&sample(), &BackupMeta::default());
        assert!(json.contains(r#""type":"chela.share.v1""#));
        assert!(json.contains(r#""card_code":"CHELA-A4F7-2-3-5-12""#));
        assert!(json.ends_with('\n'));
    }

    #[test]
    fn render_shares_json_round_trips_to_shares() {
        let shares: Vec<Share> = (1u8..=5u8)
            .map(|x| {
                let mut s = sample();
                s.x = x;
                s
            })
            .collect();
        let json = render_shares_json(&shares, &BackupMeta::default());
        assert!(json.contains(r#""type":"chela.shares.v1""#));
        let extracted = extract_shares_from_json(&json).unwrap();
        assert_eq!(extracted.len(), 5);
        for (i, r) in extracted.into_iter().enumerate() {
            assert_eq!(r.unwrap(), shares[i]);
        }
    }

    #[test]
    fn render_json_folder_writes_per_share_files_plus_bundle() {
        let shares: Vec<Share> = (1u8..=3u8)
            .map(|x| {
                let mut s = sample();
                s.x = x;
                s
            })
            .collect();
        let folder = render_json_folder(&shares, &BackupMeta::default());

        assert_eq!(folder.shares.len(), 3);
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(folder.shares[i].0, share_json_filename(share));
        }

        assert_eq!(folder.bundle.0, "chela-A4F7-shares.json");
        let extracted = extract_shares_from_json(&folder.bundle.1).unwrap();
        assert_eq!(extracted.len(), 3);

        // Each per-share file is independently parseable.
        for (filename, contents) in &folder.shares {
            let parsed = extract_shares_from_json(contents).unwrap();
            assert_eq!(parsed.len(), 1, "{filename} should hold one share");
        }
    }

    #[test]
    fn render_json_preserves_optional_metadata() {
        let names = alloc::vec!["A".to_owned(), "B".to_owned(), "C".to_owned()];
        let meta = BackupMeta {
            backup_name: Some("Test wallet"),
            description: Some("multi\nline"),
            shareholder_names: Some(&names),
        };
        let shares: Vec<Share> = (1u8..=3u8)
            .map(|x| {
                let mut s = sample();
                s.x = x;
                s
            })
            .collect();
        let json = render_shares_json(&shares, &meta);
        assert!(json.contains(r#""backup_name":"Test wallet""#));
        assert!(json.contains(r#""description":"multi\nline""#));
        assert!(json.contains(r#""shareholder_names":["A","B","C"]"#));
    }

    #[test]
    fn json_escapes_user_supplied_script_close_tag() {
        // Same security property as the HTML embedder: user-supplied text
        // can't break out of a surrounding `<script>` if this JSON is
        // later inlined into HTML. The `<` escape is always emitted.
        let meta = BackupMeta {
            backup_name: Some("oops </script><script>alert(1)</script>"),
            ..BackupMeta::default()
        };
        let json = render_share_json(&sample(), &meta);
        // Raw `</script` substring must NOT appear — every `<` was escaped.
        assert!(!json.contains("</script"));
        // Escaped form (`</script`) IS present — the attack payload made
        // it through the encoder intact, just neutralised for HTML embedding.
        assert!(json.contains("\\u003c/script"));
        // And the resulting JSON still round-trips to the original backup_name.
        let extracted = crate::extract_shares_from_json(&json)
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(extracted, sample());
    }

    #[test]
    fn render_combined_folder_emits_both_formats() {
        let shares: Vec<Share> = (1u8..=3u8)
            .map(|x| {
                let mut s = sample();
                s.x = x;
                s
            })
            .collect();
        let combined = render_combined_folder(&shares, &BackupMeta::default());

        // Per-share files, both formats.
        assert_eq!(combined.paper.shares.len(), 3);
        assert_eq!(combined.json.shares.len(), 3);
        // No filename collisions: paper is `.html`, json is `.share.json`.
        // (Lowercase-only literals here — no need for case-insensitive checks;
        // we own the encoder and always emit lowercase. Allow the lint for
        // this test only.)
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        for ((p_name, _), (j_name, _)) in combined.paper.shares.iter().zip(&combined.json.shares) {
            assert!(p_name.ends_with(".html"));
            assert!(j_name.ends_with(".share.json"));
            assert_ne!(p_name, j_name);
        }
        // Paper folder also has a README.
        assert!(!combined.paper.readme.is_empty());
    }
}
