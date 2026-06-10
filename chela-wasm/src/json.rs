//! Tiny JSON encoder. Only handles the shapes our WASM exports produce - strings with
//! the standard escape set. No parser; inputs come in via the binary `request` format.

use std::fmt::Write as _;
use std::string::String;

/// Encode `s` as a JSON string literal, including the surrounding quotes. Handles the
/// minimum escape set required by RFC 8259: `"`, `\`, control chars `0x00..=0x1F`.
/// Non-ASCII bytes are passed through verbatim (UTF-8 encoded), which `JSON.parse`
/// accepts on the JS side.
pub(crate) fn str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::str as encode;

    #[test]
    fn empty() {
        assert_eq!(encode(""), "\"\"");
    }

    #[test]
    fn plain_ascii() {
        assert_eq!(encode("hello world"), "\"hello world\"");
    }

    #[test]
    fn escape_quote_and_backslash() {
        assert_eq!(encode("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }

    #[test]
    fn escape_control_chars() {
        assert_eq!(encode("\n\r\t"), "\"\\n\\r\\t\"");
        assert_eq!(encode("\x01"), "\"\\u0001\"");
    }

    #[test]
    fn passes_non_ascii_through() {
        // UTF-8 bytes are valid in a JSON string per RFC 8259; no \u-escape needed.
        assert_eq!(encode("café"), "\"café\"");
        assert_eq!(encode("\u{1F600}"), "\"\u{1F600}\"");
    }
}
