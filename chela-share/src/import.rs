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
    /// JSON parsed but the schema-version sentinel (`"type":"chela.share"`)
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
    /// The advisory `card_number` / `threshold` / `total` / `set_id` disagree with the
    /// values the words carry - a transcription error in the metadata.
    BadThresholdTotalOrIndex,
    /// The `words` array failed to decode (bad CRC, reserved bit set, too few words).
    ShareCorrupt,
}

/// Extract every chela share embedded in `html`. Order in the result matches
/// order of appearance in the document. An empty input or one with no chela
/// blocks returns [`ImportError::NoChelaSharesFound`].
///
/// Per-block parse / validate errors are returned in the result vector - the
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
/// - **A single share** (`{"type":"chela.share", …}`) - returns a one-element
///   vector
/// - **A bundle** (`{"type":"chela.shares", "shares":[…]}`) - returns each
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
        Some("chela.share") => Ok(alloc::vec![decode_share_value(&v)]),
        Some("chela.shares") => {
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
        // Skip if `<script` isn't followed by a recognised attribute char -
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
            // Unclosed script - abandon.
            break;
        };
        let body_end = body_start + close_rel;
        out.push(&html[body_start..body_end]);
        i = body_end + b"</script>".len();
    }
    out
}

/// Decode a parsed chela.share JSON document into a [`Share`]. Used by the
/// HTML extractor (wraps `json::parse` + this).
fn decode_share_json(json_text: &str) -> Result<Share, ImportError> {
    let v = json::parse(json_text).map_err(ImportError::BadJson)?;
    decode_share_value(&v)
}

/// Decode a pre-parsed `Value` (a single chela.share object) into a
/// [`Share`]. Used by `extract_shares_from_json` for the bundle path, where
/// each array element is already a parsed `Value` - avoids re-serializing.
fn decode_share_value(v: &Value) -> Result<Share, ImportError> {
    // Schema version sentinel.
    let ty = v.get("type").and_then(Value::as_str);
    if ty != Some("chela.share") {
        return Err(ImportError::UnknownSchema);
    }

    // Words are authoritative: x, M, and the nonce come from them, verified by the CRC.
    let words_arr = v
        .get("words")
        .and_then(Value::as_array)
        .ok_or(ImportError::BadField("words"))?;
    let mut word_indices = Vec::with_capacity(words_arr.len());
    for w in words_arr {
        let word_str = w.as_str().ok_or(ImportError::BadField("words"))?;
        let idx = chela_bip39::word_to_index(word_str).ok_or(ImportError::UnknownWord)?;
        word_indices.push(idx);
    }
    let d =
        chela_engine::decode_share_words(&word_indices).map_err(|_| ImportError::ShareCorrupt)?;

    let scheme = v
        .get("scheme")
        .and_then(Value::as_str)
        .ok_or(ImportError::BadField("scheme"))?;
    let scheme = match scheme {
        "bip39-wordlist" => OutputMode::Bip39Wordlist,
        _ => return Err(ImportError::UnknownScheme),
    };

    // Everything below is advisory: present to help humans, cross-checked against the
    // words to catch transcription errors, never trusted over them.
    if let Some(set_id) = v.get("set_id").and_then(Value::as_str) {
        let nonce = parse_set_id(set_id)?;
        if nonce != d.nonce {
            return Err(ImportError::BadThresholdTotalOrIndex);
        }
    }
    if let Some(cn) = v.get("card_number").and_then(Value::as_u8) {
        if cn != d.x {
            return Err(ImportError::BadThresholdTotalOrIndex);
        }
    }
    if let Some(th) = v.get("threshold").and_then(Value::as_u8) {
        if th != d.threshold {
            return Err(ImportError::BadThresholdTotalOrIndex);
        }
    }
    if let Some(wc) = v.get("word_count").and_then(Value::as_usize) {
        if wc != word_indices.len() {
            return Err(ImportError::WordCountMismatch);
        }
    }
    let total = v.get("total").and_then(Value::as_u8);
    let kind = match v.get("payload_kind").and_then(Value::as_str) {
        Some("bip39") => Some(PayloadKind::Bip39),
        Some("text") => Some(PayloadKind::Text),
        Some(_) => return Err(ImportError::UnknownPayloadKind),
        None => None,
    };

    Ok(Share {
        scheme,
        x: d.x,
        threshold: d.threshold,
        nonce: d.nonce,
        total,
        kind,
        word_indices,
    })
}

/// Parse a 4-hex-char `set_id` like `"3058"` into the 11-bit nonce. Case-insensitive.
fn parse_set_id(s: &str) -> Result<u16, ImportError> {
    if s.len() != 4 || !s.is_ascii() {
        return Err(ImportError::BadSetId);
    }
    let n = u16::from_str_radix(s, 16).map_err(|_| ImportError::BadSetId)?;
    // The nonce is 11 bits; a well-formed set_id has its top 5 bits clear. Reject rather than
    // silently mask so a corrupted/forged label can't pass as a different valid set.
    if n > 0x7FF {
        return Err(ImportError::BadSetId);
    }
    Ok(n)
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
                // Unquoted value - read up to whitespace or `>`.
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
                f.write_str("advisory set_id / card_number / threshold disagree with the words")
            }
            Self::ShareCorrupt => f.write_str("share words failed to decode (bad checksum)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_share_json, extract_shares_from_html, extract_shares_strict,
        find_chela_share_blocks, ImportError,
    };
    use crate::{render_paper_folder, render_paper_html, render_share_json, BackupMeta};
    use alloc::borrow::ToOwned;
    use alloc::string::String;
    use alloc::vec::Vec;
    use chela_engine::{split_secret, OutputMode, Share, SplitInput};

    /// A real 3-share 2-of-3 generation; words decode and pass the CRC.
    fn fixture() -> Vec<Share> {
        split_secret(
            &SplitInput::Bip39 {
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                passphrase: "test passphrase",
            },
            2,
            3,
            OutputMode::Bip39Wordlist,
        )
        .unwrap()
    }

    fn sample() -> Share {
        fixture().into_iter().next().unwrap()
    }

    /// The bare `chela.share` JSON object for a share (no trailing newline).
    fn share_json(s: &Share) -> String {
        let mut out = String::new();
        crate::export::write_share_json_object(&mut out, s, &BackupMeta::default());
        out
    }

    /// Wrap a JSON object in a chela-share `<script>` block.
    fn wrap_block(json: &str) -> String {
        alloc::format!("<script type=\"application/json\" class=\"chela-share\">{json}</script>")
    }

    #[test]
    fn finds_one_block_in_single_card_html() {
        let html = crate::html::render_share_card_html(&sample(), &BackupMeta::default());
        let blocks = find_chela_share_blocks(&html);
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn finds_n_blocks_in_multi_card_html() {
        let shares = fixture();
        let html = render_paper_html(&shares, &BackupMeta::default());
        let blocks = find_chela_share_blocks(&html);
        assert_eq!(blocks.len(), 3);
    }

    #[test]
    fn json_set_id_above_11_bits_rejected() {
        let s = sample();
        let real = alloc::format!("\"set_id\":\"{:04X}\"", s.nonce & 0x7FF);
        // 0xF800 has bits above the 11-bit nonce range; it must be rejected, not masked.
        let json = share_json(&s).replace(&real, "\"set_id\":\"F800\"");
        assert_eq!(decode_share_json(&json), Err(ImportError::BadSetId));
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
        let shares = fixture();
        let folder = render_paper_folder(&shares, &BackupMeta::default());
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
        let names = alloc::vec!["Alice".to_owned(), "Bob".to_owned(), "Carol".to_owned(),];
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
        let html = "<!doctype html><html><body><script>alert('hi')</script></body></html>";
        let err = extract_shares_from_html(html).unwrap_err();
        assert_eq!(err, ImportError::NoChelaSharesFound);
    }

    #[test]
    fn attribute_order_tolerated() {
        // `class` before `type` - our encoder uses the opposite order, but the
        // scanner shouldn't care.
        let s = sample();
        let json = share_json(&s);
        let html = alloc::format!(
            "<script class=\"chela-share\" type=\"application/json\">{json}</script>"
        );
        let shares = extract_shares_strict(&html).unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0], s);
    }

    #[test]
    fn single_quoted_attributes_tolerated() {
        let s = sample();
        let json = share_json(&s);
        let html =
            alloc::format!("<script class='chela-share' type='application/json'>{json}</script>");
        let shares = extract_shares_strict(&html).unwrap();
        assert_eq!(shares.len(), 1);
    }

    #[test]
    fn malformed_json_surfaces_per_block_error() {
        let html = wrap_block("{not valid json}");
        let result = extract_shares_from_html(&html).unwrap();
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], Err(ImportError::BadJson(_))));
    }

    #[test]
    fn wrong_schema_version_rejected() {
        let json = share_json(&sample()).replace("\"chela.share\"", "\"chela.unknown\"");
        let html = wrap_block(&json);
        let result = extract_shares_from_html(&html).unwrap();
        assert!(matches!(result[0], Err(ImportError::UnknownSchema)));
    }

    #[test]
    fn missing_words_field_rejected() {
        // Drop the whole "words":[...] array; everything else is well-formed.
        let json = share_json(&sample());
        let cut = json.find(",\"words\":[").expect("words field present");
        let trimmed = alloc::format!("{}}}", &json[..cut]);
        let html = wrap_block(&trimmed);
        let result = extract_shares_from_html(&html).unwrap();
        assert!(matches!(result[0], Err(ImportError::BadField("words"))));
    }

    #[test]
    fn word_count_mismatch_rejected() {
        // A word_count that disagrees with the actual words array.
        let s = sample();
        let json = share_json(&s).replace(
            &alloc::format!("\"word_count\":{}", s.word_indices.len()),
            "\"word_count\":99",
        );
        let html = wrap_block(&json);
        let result = extract_shares_from_html(&html).unwrap();
        assert!(matches!(result[0], Err(ImportError::WordCountMismatch)));
    }

    #[test]
    fn unknown_word_rejected() {
        // Replace the first real word with a non-wordlist token.
        let s = sample();
        let first = chela_bip39::index_to_word(s.word_indices[0]).unwrap();
        let json =
            share_json(&s).replacen(&alloc::format!("\"{first}\""), "\"notarealbip39word\"", 1);
        let html = wrap_block(&json);
        let result = extract_shares_from_html(&html).unwrap();
        assert!(matches!(result[0], Err(ImportError::UnknownWord)));
    }

    #[test]
    fn corrupt_words_rejected() {
        // Flip one Y word to a different valid wordlist index → CRC fails.
        let mut s = sample();
        s.word_indices[2] ^= 1;
        let html = wrap_block(&share_json(&s));
        let result = extract_shares_from_html(&html).unwrap();
        assert!(matches!(result[0], Err(ImportError::ShareCorrupt)));
    }

    #[test]
    fn unknown_scheme_rejected() {
        let json = share_json(&sample()).replace("bip39-wordlist", "future-wordlist");
        let html = wrap_block(&json);
        let result = extract_shares_from_html(&html).unwrap();
        assert!(matches!(result[0], Err(ImportError::UnknownScheme)));
    }

    #[test]
    fn advisory_card_number_mismatch_rejected() {
        // card_number that disagrees with the words is a transcription error.
        let s = sample();
        let wrong = (s.x % 32) + 1;
        let json = share_json(&s).replace(
            &alloc::format!("\"card_number\":{}", s.x),
            &alloc::format!("\"card_number\":{wrong}"),
        );
        let html = wrap_block(&json);
        let result = extract_shares_from_html(&html).unwrap();
        assert!(matches!(
            result[0],
            Err(ImportError::BadThresholdTotalOrIndex)
        ));
    }

    #[test]
    fn advisory_set_id_mismatch_rejected() {
        let s = sample();
        let real = alloc::format!("\"set_id\":\"{:04X}\"", s.nonce & 0x7FF);
        let wrong = alloc::format!("\"set_id\":\"{:04X}\"", (s.nonce ^ 1) & 0x7FF);
        let json = share_json(&s).replace(&real, &wrong);
        let html = wrap_block(&json);
        let result = extract_shares_from_html(&html).unwrap();
        assert!(matches!(
            result[0],
            Err(ImportError::BadThresholdTotalOrIndex)
        ));
    }

    #[test]
    fn bad_set_id_rejected() {
        let s = sample();
        let real = alloc::format!("\"set_id\":\"{:04X}\"", s.nonce & 0x7FF);
        let json = share_json(&s).replace(&real, "\"set_id\":\"ZZZZ\"");
        let html = wrap_block(&json);
        let result = extract_shares_from_html(&html).unwrap();
        assert!(matches!(result[0], Err(ImportError::BadSetId)));
    }

    #[test]
    fn extract_strict_fails_on_first_bad_block() {
        let good = crate::html::render_share_card_html(&sample(), &BackupMeta::default());
        let bad_block = wrap_block("{}");
        let mixed = alloc::format!("{good}{bad_block}");
        let err = extract_shares_strict(&mixed).unwrap_err();
        assert!(matches!(err, ImportError::UnknownSchema));
    }

    #[test]
    fn extract_non_strict_returns_both_successes_and_failures() {
        let good = crate::html::render_share_card_html(&sample(), &BackupMeta::default());
        let bad_block = wrap_block("{}");
        let mixed = alloc::format!("{good}{bad_block}");
        let result = extract_shares_from_html(&mixed).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result[0].is_ok());
        assert!(matches!(result[1], Err(ImportError::UnknownSchema)));
    }

    #[test]
    fn injected_close_script_in_user_strings_does_not_break_extraction() {
        let original = sample();
        let attack = "oops </script><script>alert(1)</script>";
        let html = crate::html::render_share_card_html(
            &original,
            &BackupMeta {
                backup_name: Some(attack),
                ..BackupMeta::default()
            },
        );
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
        let s = sample();
        let json = render_share_json(&s, &BackupMeta::default());
        let share = decode_share_json(&json).unwrap();
        assert_eq!(share, s);
    }

    #[test]
    fn import_omits_total_and_kind_when_absent() {
        // A words-only export carries neither total nor payload_kind; import leaves both None.
        let mut s = sample();
        s.total = None;
        s.kind = None;
        let json = render_share_json(&s, &BackupMeta::default());
        assert!(!json.contains("\"total\""));
        assert!(!json.contains("\"payload_kind\""));
        let decoded = decode_share_json(&json).unwrap();
        assert_eq!(decoded.total, None);
        assert_eq!(decoded.kind, None);
        assert_eq!(decoded, s);
    }

    #[test]
    fn extracted_shares_pass_through_recover_secret_end_to_end() {
        // Highest-confidence test: real split → render to paper HTML → import
        // every card via this module → recover the original secret.
        use chela_engine::recover_secret;

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

        let html = render_paper_html(
            &shares,
            &BackupMeta {
                backup_name: Some("E2E import"),
                ..BackupMeta::default()
            },
        );
        let extracted = extract_shares_strict(&html).unwrap();
        assert_eq!(extracted.len(), 3);

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
