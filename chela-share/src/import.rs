//! Import shares from chela paper-backup HTML and JSON files.

use alloc::vec::Vec;

use chela_engine::{OutputMode, PayloadKind, Share};

use crate::json::{self, JsonError, Value};

/// Errors raised while extracting a single share from an HTML blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// The HTML contained no `<script class="chela-share">` block.
    NoChelaSharesFound,
    /// The JSON inside a block failed to parse.
    BadJson(JsonError),
    /// JSON parsed but the schema-version sentinel (`"type":"chela.share.v1"`)
    /// is missing or wrong.
    UnknownSchema,
    /// A required field is missing or has the wrong type.
    BadField(&'static str),
    /// `scheme` field doesn't match any wordlist scheme this build supports.
    UnknownScheme,
    /// `payload_kind` field doesn't match any kind this build supports.
    UnknownPayloadKind,
    /// A word string is not in the BIP-39 English wordlist.
    UnknownWord,
    /// `words.len()` didn't equal `word_count`.
    WordCountMismatch,
    /// `set_id` isn't a 4-character ASCII hex string.
    BadSetId,
    /// `x`, `threshold`, or `total` violate the invariants
    /// (`1 ≤ x ≤ total`, `2 ≤ threshold ≤ total ≤ 255`, `total ≥ 1`).
    BadThresholdTotalOrIndex,
}

/// Extract every chela share embedded in `html`. Order in the result matches
/// order of appearance in the document. An empty input or one with no chela
/// blocks returns [`ImportError::NoChelaSharesFound`].
///
/// Per-block parse / validate errors are returned in the result vector — the
/// caller can decide to keep the successes and surface the failures, or stop
/// on any error.
///
/// # Errors
/// Returns [`ImportError::NoChelaSharesFound`] if zero blocks were detected.
pub fn extract_shares_from_html(
    html: &str,
) -> Result<Vec<Result<Share, ImportError>>, ImportError> {
    let blocks = find_chela_share_blocks(html);
    if blocks.is_empty() {
        return Err(ImportError::NoChelaSharesFound);
    }
    Ok(blocks.into_iter().map(decode_share_json).collect())
}

/// Convenience: extract and require every block to succeed. Use this when you
/// want to fail the whole import if any single block is corrupt.
///
/// # Errors
/// Returns the first per-block error encountered, or [`ImportError::NoChelaSharesFound`]
/// if no blocks were detected.
pub fn extract_shares_strict(html: &str) -> Result<Vec<Share>, ImportError> {
    extract_shares_from_html(html)?
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
}

/// Extract shares from a standalone JSON file. Accepts either:
///
/// - **A single share** (`{"type":"chela.share.v1", …}`) — returns a one-element
///   vector
/// - **A bundle** (`{"type":"chela.shares.v1", "shares":[…]}`) — returns each
///   share as a separate result (per-share validation errors preserved)
///
/// The two formats are distinguished by the top-level `"type"` field. Other
/// JSON shapes return [`ImportError::UnknownSchema`].
///
/// # Errors
/// - [`ImportError::BadJson`] if the input isn't valid JSON
/// - [`ImportError::UnknownSchema`] if the top-level `type` field is missing
///   or doesn't match a recognised value
/// - [`ImportError::BadField`] if the bundle's `shares` field isn't an array
pub fn extract_shares_from_json(
    json: &str,
) -> Result<Vec<Result<Share, ImportError>>, ImportError> {
    let v = json::parse(json).map_err(ImportError::BadJson)?;
    let ty = v.get("type").and_then(Value::as_str);
    match ty {
        Some("chela.share.v1") => Ok(alloc::vec![decode_share_value(&v)]),
        Some("chela.shares.v1") => {
            let arr = v
                .get("shares")
                .and_then(Value::as_array)
                .ok_or(ImportError::BadField("shares"))?;
            Ok(arr.iter().map(decode_share_value).collect())
        }
        Some(_) | None => Err(ImportError::UnknownSchema),
    }
}

/// Find every `<script type="application/json" class="chela-share">…</script>` body in `html`.
/// Tolerant of attribute order and single-vs-double quotes.
fn find_chela_share_blocks(html: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = html.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let Some(start_rel) = find_subslice_ci(&bytes[i..], b"<script") else {
            break;
        };
        let tag_start = i + start_rel;
        let Some(tag_end_rel) = bytes[tag_start..].iter().position(|&b| b == b'>') else {
            break;
        };
        let tag_end = tag_start + tag_end_rel;
        let opening_tag = &html[tag_start..=tag_end];
        // Skip if `<script` isn't followed by a recognised attribute char —
        // avoids matching things like `<scripting>`.
        let after_script = tag_start + b"<script".len();
        let next_char = bytes.get(after_script).copied().unwrap_or(b'>');
        let is_script_tag = matches!(next_char, b' ' | b'\t' | b'\n' | b'\r' | b'>' | b'/');
        if !is_script_tag {
            i = tag_end + 1;
            continue;
        }

        let is_chela = tag_attribute_contains(opening_tag, "class", "chela-share")
            && tag_attribute_contains(opening_tag, "type", "application/json");
        if !is_chela {
            i = tag_end + 1;
            continue;
        }

        // Body runs from after `>` to the first `</script>`. JSON strings
        // produced by this crate escape `<` to `<`, so a literal `</script>`
        // inside user data can't prematurely close the block.
        let body_start = tag_end + 1;
        let Some(close_rel) = find_subslice_ci(&bytes[body_start..], b"</script>") else {
            // Unclosed script — abandon.
            break;
        };
        let body_end = body_start + close_rel;
        out.push(&html[body_start..body_end]);
        i = body_end + b"</script>".len();
    }
    out
}

/// Decode a parsed chela.share.v1 JSON document into a [`Share`]. Used by the
/// HTML extractor (wraps `json::parse` + this).
fn decode_share_json(json_text: &str) -> Result<Share, ImportError> {
    let v = json::parse(json_text).map_err(ImportError::BadJson)?;
    decode_share_value(&v)
}

/// Decode a pre-parsed `Value` (a single chela.share.v1 object) into a
/// [`Share`]. Used by `extract_shares_from_json` for the bundle path, where
/// each array element is already a parsed `Value` — avoids re-serializing.
fn decode_share_value(v: &Value) -> Result<Share, ImportError> {
    // Schema version sentinel.
    let ty = v.get("type").and_then(Value::as_str);
    if ty != Some("chela.share.v1") {
        return Err(ImportError::UnknownSchema);
    }

    let set_id = v
        .get("set_id")
        .and_then(Value::as_str)
        .ok_or(ImportError::BadField("set_id"))?;
    let identifier = parse_set_id(set_id)?;

    let x = v
        .get("card_number")
        .and_then(Value::as_u8)
        .ok_or(ImportError::BadField("card_number"))?;
    let threshold = v
        .get("threshold")
        .and_then(Value::as_u8)
        .ok_or(ImportError::BadField("threshold"))?;
    let total = v
        .get("total")
        .and_then(Value::as_u8)
        .ok_or(ImportError::BadField("total"))?;
    let word_count = v
        .get("word_count")
        .and_then(Value::as_usize)
        .ok_or(ImportError::BadField("word_count"))?;

    if x == 0 || x > total || threshold == 0 || threshold > total {
        return Err(ImportError::BadThresholdTotalOrIndex);
    }

    let scheme = v
        .get("scheme")
        .and_then(Value::as_str)
        .ok_or(ImportError::BadField("scheme"))?;
    let scheme = match scheme {
        "bip39-wordlist" => OutputMode::Bip39Wordlist,
        _ => return Err(ImportError::UnknownScheme),
    };

    let payload_kind = v
        .get("payload_kind")
        .and_then(Value::as_str)
        .ok_or(ImportError::BadField("payload_kind"))?;
    let kind = match payload_kind {
        "bip39" => PayloadKind::Bip39,
        "text" => PayloadKind::Text,
        _ => return Err(ImportError::UnknownPayloadKind),
    };

    let words_arr = v
        .get("words")
        .and_then(Value::as_array)
        .ok_or(ImportError::BadField("words"))?;
    if words_arr.len() != word_count {
        return Err(ImportError::WordCountMismatch);
    }
    let mut word_indices = Vec::with_capacity(words_arr.len());
    for w in words_arr {
        let word_str = w.as_str().ok_or(ImportError::BadField("words"))?;
        let idx = chela_bip39::word_to_index(word_str).ok_or(ImportError::UnknownWord)?;
        word_indices.push(idx);
    }

    Ok(Share {
        identifier,
        scheme,
        kind,
        threshold,
        total,
        x,
        word_indices,
    })
}

/// Parse a 4-hex-char `set_id` like `"3058"` into `[u8; 2]`. Case-insensitive.
fn parse_set_id(s: &str) -> Result<[u8; 2], ImportError> {
    if s.len() != 4 || !s.is_ascii() {
        return Err(ImportError::BadSetId);
    }
    let hi = u8::from_str_radix(&s[..2], 16).map_err(|_| ImportError::BadSetId)?;
    let lo = u8::from_str_radix(&s[2..], 16).map_err(|_| ImportError::BadSetId)?;
    Ok([hi, lo])
}

/// Case-insensitive substring search on bytes (lowercases the needle once,
/// expects the haystack to be ASCII for the keyword). Returns the byte offset
/// of the match within `haystack`.
fn find_subslice_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    'outer: for i in 0..=haystack.len() - needle.len() {
        for (j, &n) in needle.iter().enumerate() {
            let h = haystack[i + j];
            if h.eq_ignore_ascii_case(&n) {
                continue;
            }
            continue 'outer;
        }
        return Some(i);
    }
    None
}

/// Returns true if `tag` (e.g. `<script type="application/json" class="chela-share">`)
/// has an attribute `name` whose value contains `needle` (case-insensitive on
/// the attribute name; case-sensitive on the value). Tolerant of single or
/// double quotes around the value.
fn tag_attribute_contains(tag: &str, name: &str, needle: &str) -> bool {
    let lower_name = name.to_ascii_lowercase();
    let bytes = tag.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip whitespace.
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] == b'>' || bytes[i] == b'/' {
            break;
        }
        // Read attribute name.
        let name_start = i;
        while i < bytes.len()
            && !matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r' | b'=' | b'>' | b'/')
        {
            i += 1;
        }
        let attr_name = &tag[name_start..i];
        // Optional `="value"`.
        let mut attr_value = "";
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            let quote = bytes.get(i).copied();
            if matches!(quote, Some(b'"' | b'\'')) {
                let q = quote.unwrap();
                i += 1;
                let val_start = i;
                while i < bytes.len() && bytes[i] != q {
                    i += 1;
                }
                attr_value = &tag[val_start..i];
                if i < bytes.len() {
                    i += 1;
                }
            } else {
                // Unquoted value — read up to whitespace or `>`.
                let val_start = i;
                while i < bytes.len()
                    && !matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r' | b'>' | b'/')
                {
                    i += 1;
                }
                attr_value = &tag[val_start..i];
            }
        }
        if attr_name.eq_ignore_ascii_case(&lower_name) && attr_value.contains(needle) {
            return true;
        }
    }
    false
}

impl core::fmt::Display for ImportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoChelaSharesFound => f.write_str("no chela share data found in the HTML"),
            Self::BadJson(e) => write!(f, "embedded JSON did not parse: {e}"),
            Self::UnknownSchema => f.write_str("embedded data uses an unknown schema version"),
            Self::BadField(name) => write!(f, "embedded JSON missing or wrong-typed field: {name}"),
            Self::UnknownScheme => f.write_str("unknown share scheme"),
            Self::UnknownPayloadKind => f.write_str("unknown payload kind"),
            Self::UnknownWord => f.write_str("share word is not in the BIP-39 wordlist"),
            Self::WordCountMismatch => f.write_str("words array length doesn't match word_count"),
            Self::BadSetId => f.write_str("set_id is not 4 hex characters"),
            Self::BadThresholdTotalOrIndex => {
                f.write_str("card_number / threshold / total violate invariants")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_share_json, extract_shares_from_html, extract_shares_strict,
        find_chela_share_blocks, ImportError,
    };
    use crate::{render_paper_folder, render_paper_html, BackupMeta};
    use alloc::borrow::ToOwned;
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
            // First 12 BIP-39 words.
            word_indices: alloc::vec![0u16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        }
    }

    #[test]
    fn finds_one_block_in_single_card_html() {
        let html = crate::html::render_share_card_html(&sample(), &BackupMeta::default());
        let blocks = find_chela_share_blocks(&html);
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn finds_n_blocks_in_multi_card_html() {
        let shares: Vec<Share> = (1u8..=4u8)
            .map(|x| {
                let mut s = sample();
                s.x = x;
                s
            })
            .collect();
        let html = render_paper_html(&shares, &BackupMeta::default());
        let blocks = find_chela_share_blocks(&html);
        assert_eq!(blocks.len(), 4);
    }

    #[test]
    fn round_trip_single_card_html_back_to_share() {
        let original = sample();
        let html = crate::html::render_share_card_html(&original, &BackupMeta::default());
        let shares = extract_shares_strict(&html).unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0], original);
    }

    #[test]
    fn round_trip_paper_folder_extracts_every_share() {
        let shares: Vec<Share> = (1u8..=5u8)
            .map(|x| {
                let mut s = sample();
                s.x = x;
                s
            })
            .collect();
        let folder = render_paper_folder(&shares, &BackupMeta::default());
        // Each share-N.html in the folder has exactly one block.
        for (i, (_filename, html)) in folder.shares.iter().enumerate() {
            let extracted = extract_shares_strict(html).unwrap();
            assert_eq!(extracted.len(), 1);
            assert_eq!(extracted[0], shares[i]);
        }
    }

    #[test]
    fn round_trip_with_metadata_preserves_words_and_share_fields() {
        // Presentation metadata isn't part of Share, but the JSON should still
        // decode the share correctly when those fields are present.
        let names = alloc::vec![
            "Alice".to_owned(),
            "Bob".to_owned(),
            "Carol".to_owned(),
            "Dan".to_owned(),
            "Eve".to_owned(),
        ];
        let original = sample();
        let html = crate::html::render_share_card_html(
            &original,
            &BackupMeta {
                backup_name: Some("Alice's Ethereum wallet"),
                description: Some("Mixed punctuation: `<>&\"'`"),
                shareholder_names: Some(&names),
            },
        );
        let shares = extract_shares_strict(&html).unwrap();
        assert_eq!(shares[0], original);
    }

    #[test]
    fn empty_html_returns_no_shares_found() {
        let err = extract_shares_from_html("").unwrap_err();
        assert_eq!(err, ImportError::NoChelaSharesFound);
    }

    #[test]
    fn html_without_chela_blocks_returns_no_shares_found() {
        let html = "<!doctype html><html><body><p>not a chela page</p></body></html>";
        let err = extract_shares_from_html(html).unwrap_err();
        assert_eq!(err, ImportError::NoChelaSharesFound);
    }

    #[test]
    fn unrelated_script_tags_are_ignored() {
        // A page with a normal `<script>` tag (no class="chela-share") must not
        // be mistaken for an import source.
        let html = "<!doctype html><html><body><script>alert('hi')</script></body></html>";
        let err = extract_shares_from_html(html).unwrap_err();
        assert_eq!(err, ImportError::NoChelaSharesFound);
    }

    #[test]
    fn attribute_order_tolerated() {
        // `class` before `type` — our encoder uses the opposite order, but the
        // scanner shouldn't care.
        let html = r#"<script class="chela-share" type="application/json">
            {"type":"chela.share.v1","card_code":"CHELA-A4F7-2-3-5-12","set_id":"A4F7","card_number":2,"threshold":3,"total":5,"word_count":12,"scheme":"bip39-wordlist","payload_kind":"bip39","words":["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident"]}
        </script>"#;
        let shares = extract_shares_strict(html).unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].x, 2);
    }

    #[test]
    fn single_quoted_attributes_tolerated() {
        let html = r#"<script class='chela-share' type='application/json'>
            {"type":"chela.share.v1","card_code":"CHELA-A4F7-2-3-5-12","set_id":"A4F7","card_number":2,"threshold":3,"total":5,"word_count":12,"scheme":"bip39-wordlist","payload_kind":"bip39","words":["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident"]}
        </script>"#;
        let shares = extract_shares_strict(html).unwrap();
        assert_eq!(shares.len(), 1);
    }

    #[test]
    fn malformed_json_surfaces_per_block_error() {
        let html =
            r#"<script type="application/json" class="chela-share">{not valid json}</script>"#;
        let result = extract_shares_from_html(html).unwrap();
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], Err(ImportError::BadJson(_))));
    }

    #[test]
    fn wrong_schema_version_rejected() {
        let html = r#"<script type="application/json" class="chela-share">{"type":"chela.share.v9","card_code":"x","set_id":"A4F7","card_number":1,"threshold":3,"total":5,"word_count":12,"scheme":"bip39-wordlist","payload_kind":"bip39","words":["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident"]}</script>"#;
        let result = extract_shares_from_html(html).unwrap();
        assert!(matches!(result[0], Err(ImportError::UnknownSchema)));
    }

    #[test]
    fn missing_required_field_rejected() {
        let html = r#"<script type="application/json" class="chela-share">{"type":"chela.share.v1","set_id":"A4F7","card_number":1,"threshold":3,"total":5,"word_count":12,"scheme":"bip39-wordlist","payload_kind":"bip39"}</script>"#;
        let result = extract_shares_from_html(html).unwrap();
        assert!(matches!(result[0], Err(ImportError::BadField("words"))));
    }

    #[test]
    fn word_count_mismatch_rejected() {
        let html = r#"<script type="application/json" class="chela-share">{"type":"chela.share.v1","card_code":"x","set_id":"A4F7","card_number":1,"threshold":3,"total":5,"word_count":12,"scheme":"bip39-wordlist","payload_kind":"bip39","words":["abandon","ability"]}</script>"#;
        let result = extract_shares_from_html(html).unwrap();
        assert!(matches!(result[0], Err(ImportError::WordCountMismatch)));
    }

    #[test]
    fn unknown_word_rejected() {
        let html = r#"<script type="application/json" class="chela-share">{"type":"chela.share.v1","card_code":"x","set_id":"A4F7","card_number":1,"threshold":3,"total":5,"word_count":12,"scheme":"bip39-wordlist","payload_kind":"bip39","words":["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","notarealbip39word"]}</script>"#;
        let result = extract_shares_from_html(html).unwrap();
        assert!(matches!(result[0], Err(ImportError::UnknownWord)));
    }

    #[test]
    fn unknown_scheme_rejected() {
        let html = r#"<script type="application/json" class="chela-share">{"type":"chela.share.v1","card_code":"x","set_id":"A4F7","card_number":1,"threshold":3,"total":5,"word_count":12,"scheme":"future-wordlist","payload_kind":"bip39","words":["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident"]}</script>"#;
        let result = extract_shares_from_html(html).unwrap();
        assert!(matches!(result[0], Err(ImportError::UnknownScheme)));
    }

    #[test]
    fn out_of_range_card_number_rejected() {
        let html = r#"<script type="application/json" class="chela-share">{"type":"chela.share.v1","card_code":"x","set_id":"A4F7","card_number":7,"threshold":3,"total":5,"word_count":12,"scheme":"bip39-wordlist","payload_kind":"bip39","words":["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident"]}</script>"#;
        let result = extract_shares_from_html(html).unwrap();
        assert!(matches!(
            result[0],
            Err(ImportError::BadThresholdTotalOrIndex)
        ));
    }

    #[test]
    fn zero_card_number_rejected() {
        let html = r#"<script type="application/json" class="chela-share">{"type":"chela.share.v1","card_code":"x","set_id":"A4F7","card_number":0,"threshold":3,"total":5,"word_count":12,"scheme":"bip39-wordlist","payload_kind":"bip39","words":["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident"]}</script>"#;
        let result = extract_shares_from_html(html).unwrap();
        assert!(matches!(
            result[0],
            Err(ImportError::BadThresholdTotalOrIndex)
        ));
    }

    #[test]
    fn bad_set_id_rejected() {
        let html = r#"<script type="application/json" class="chela-share">{"type":"chela.share.v1","card_code":"x","set_id":"ZZZZ","card_number":1,"threshold":3,"total":5,"word_count":12,"scheme":"bip39-wordlist","payload_kind":"bip39","words":["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident"]}</script>"#;
        let result = extract_shares_from_html(html).unwrap();
        assert!(matches!(result[0], Err(ImportError::BadSetId)));
    }

    #[test]
    fn extract_strict_fails_on_first_bad_block() {
        // Mix one good, one bad — strict mode rejects the whole batch.
        let good = crate::html::render_share_card_html(&sample(), &BackupMeta::default());
        let bad_block = r#"<script type="application/json" class="chela-share">{}</script>"#;
        let mixed = alloc::format!("{good}{bad_block}");
        let err = extract_shares_strict(&mixed).unwrap_err();
        // The first block was good, second is bad → strict reports the failure.
        assert!(matches!(err, ImportError::UnknownSchema));
    }

    #[test]
    fn extract_non_strict_returns_both_successes_and_failures() {
        let good = crate::html::render_share_card_html(&sample(), &BackupMeta::default());
        let bad_block = r#"<script type="application/json" class="chela-share">{}</script>"#;
        let mixed = alloc::format!("{good}{bad_block}");
        let result = extract_shares_from_html(&mixed).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result[0].is_ok());
        assert!(matches!(result[1], Err(ImportError::UnknownSchema)));
    }

    #[test]
    fn injected_close_script_in_user_strings_does_not_break_extraction() {
        // The encoder escapes `<` to `<` inside JSON strings, so a
        // backup_name containing `</script>` cannot prematurely close the
        // wrapping tag. Round-trip verifies extraction still works.
        let original = sample();
        let attack = "oops </script><script>alert(1)</script>";
        let html = crate::html::render_share_card_html(
            &original,
            &BackupMeta {
                backup_name: Some(attack),
                ..BackupMeta::default()
            },
        );
        // Only one script open tag in the rendered HTML — the attack didn't escape.
        assert_eq!(html.matches("<script").count(), 1);
        let shares = extract_shares_strict(&html).unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0], original);
    }

    #[test]
    fn handles_html_with_lots_of_unrelated_markup_around_block() {
        let original = sample();
        let block = crate::html::render_share_card_html(&original, &BackupMeta::default());
        let wrapped = alloc::format!(
            "<!doctype html><html><head><title>x</title></head><body><nav>menu</nav><main>{block}<aside>side</aside></main><footer>foot</footer></body></html>"
        );
        let shares = extract_shares_strict(&wrapped).unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0], original);
    }

    #[test]
    fn decode_share_json_directly() {
        let json = r#"{"type":"chela.share.v1","card_code":"CHELA-A4F7-2-3-5-12","set_id":"A4F7","card_number":2,"threshold":3,"total":5,"word_count":12,"scheme":"bip39-wordlist","payload_kind":"bip39","words":["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident"]}"#;
        let share = decode_share_json(json).unwrap();
        assert_eq!(share, sample());
    }

    #[test]
    fn extracted_shares_pass_through_recover_secret_end_to_end() {
        // Highest-confidence test: real split → render to paper HTML → import
        // every card via this module → recover the original secret.
        use chela_engine::{recover_secret, split_secret, OutputMode, SplitInput};

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "test passphrase";
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

        // Render to the multi-page paper-backup HTML.
        let html = render_paper_html(
            &shares,
            &BackupMeta {
                backup_name: Some("E2E import"),
                ..BackupMeta::default()
            },
        );
        // Extract every share back from the HTML.
        let extracted = extract_shares_strict(&html).unwrap();
        assert_eq!(extracted.len(), 3);

        // Recover using any threshold-sized subset of the extracted shares.
        let subset = alloc::vec![extracted[0].clone(), extracted[2].clone()];
        let recovered = recover_secret(&subset).unwrap();
        match &recovered {
            chela_engine::RecoveredSecret::Bip39 {
                mnemonic: m,
                passphrase: p,
            } => {
                assert_eq!(m, mnemonic);
                assert_eq!(p, passphrase);
            }
            chela_engine::RecoveredSecret::Text { .. } => panic!("expected Bip39 recovery"),
        }
    }

    #[test]
    fn random_garbage_does_not_panic() {
        let cases: &[&str] = &[
            "",
            "<",
            "<script",
            "<script>",
            "<script></script>",
            "<script type=\"application/json\" class=\"chela-share\"",
            "<script type=\"application/json\" class=\"chela-share\">",
            "<script type=\"application/json\" class=\"chela-share\">{",
        ];
        for c in cases {
            let _ = extract_shares_from_html(c);
        }
    }
}
