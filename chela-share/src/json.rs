//! Minimal JSON parser used by [`crate::import`] to read the structured share
//! data embedded in chela's paper-backup HTML files.
//!
//! No third-party dependencies; no `unsafe`. Bounds recursion depth so an
//! adversarial input can't blow the stack. Strings are returned as owned
//! `String`s; the input is assumed to be valid UTF-8 (a `&str`).
//!
//! Scope is deliberately tight — we own the JSON we emit, so we never need
//! to round-trip floats or exotic escapes. Numbers are integers (`i64`).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Maximum nesting depth. chela's own schema nests two levels (object with
/// arrays of strings); the limit is generous enough that a future schema bump
/// won't hit it, while still small enough to prevent stack-overflow via
/// adversarial input.
const MAX_DEPTH: usize = 32;

/// A parsed JSON value. Numbers are `i64` (chela's schema is integer-only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(i64),
    String(String),
    Array(Vec<Value>),
    /// Object members preserved in source order (`Vec`, not `HashMap`, for `no_std`).
    Object(Vec<(String, Value)>),
}

impl Value {
    /// Borrow the string payload, if this value is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Read the number as `i64`, if this value is a number.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Read the number as `u8`, if this value is a number in `0..=255`.
    #[must_use]
    pub fn as_u8(&self) -> Option<u8> {
        self.as_i64().and_then(|n| u8::try_from(n).ok())
    }

    /// Read the number as `usize`, if this value is a non-negative number.
    #[must_use]
    pub fn as_usize(&self) -> Option<usize> {
        self.as_i64().and_then(|n| usize::try_from(n).ok())
    }

    /// Borrow the array contents, if this value is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// Borrow the object members, if this value is an object.
    #[must_use]
    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Self::Object(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// Find an object member by key (first match if duplicates exist).
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }
}

/// Error reported by [`parse`]. Position is a byte offset into the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    /// Got an unexpected character at this byte offset.
    UnexpectedChar(usize),
    /// Reached end of input mid-value.
    UnexpectedEof,
    /// Malformed `\…` escape inside a string literal.
    BadEscape,
    /// Number literal couldn't be parsed as `i64`, or contains a `.` / `e` /
    /// `E` (this parser is integer-only by design).
    InvalidNumber,
    /// Nesting depth exceeded [`MAX_DEPTH`].
    DepthLimitExceeded,
    /// Non-whitespace data after the top-level value.
    TrailingGarbage,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedChar(pos) => write!(f, "unexpected character at byte {pos}"),
            Self::UnexpectedEof => f.write_str("unexpected end of input"),
            Self::BadEscape => f.write_str("bad escape sequence in string"),
            Self::InvalidNumber => f.write_str("invalid number"),
            Self::DepthLimitExceeded => f.write_str("nesting depth exceeded"),
            Self::TrailingGarbage => f.write_str("unexpected data after top-level value"),
        }
    }
}

/// Parse one JSON value from `input`. Returns [`JsonError::TrailingGarbage`]
/// if anything non-whitespace follows the value.
pub fn parse(input: &str) -> Result<Value, JsonError> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let v = p.parse_value(0)?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(JsonError::TrailingGarbage);
    }
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn expect(&mut self, want: u8) -> Result<(), JsonError> {
        match self.bump() {
            Some(b) if b == want => Ok(()),
            Some(_) => Err(JsonError::UnexpectedChar(self.pos - 1)),
            None => Err(JsonError::UnexpectedEof),
        }
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::DepthLimitExceeded);
        }
        self.skip_ws();
        let b = self.peek().ok_or(JsonError::UnexpectedEof)?;
        match b {
            b'{' => self.parse_object(depth + 1),
            b'[' => self.parse_array(depth + 1),
            b'"' => self.parse_string().map(Value::String),
            b't' | b'f' => self.parse_bool(),
            b'n' => self.parse_null(),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(JsonError::UnexpectedChar(self.pos)),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::DepthLimitExceeded);
        }
        self.expect(b'{')?;
        let mut members = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let value = self.parse_value(depth)?;
            members.push((key, value));
            self.skip_ws();
            match self.bump() {
                Some(b',') => (),
                Some(b'}') => return Ok(Value::Object(members)),
                Some(_) => return Err(JsonError::UnexpectedChar(self.pos - 1)),
                None => return Err(JsonError::UnexpectedEof),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::DepthLimitExceeded);
        }
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            let value = self.parse_value(depth)?;
            items.push(value);
            self.skip_ws();
            match self.bump() {
                Some(b',') => (),
                Some(b']') => return Ok(Value::Array(items)),
                Some(_) => return Err(JsonError::UnexpectedChar(self.pos - 1)),
                None => return Err(JsonError::UnexpectedEof),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let b = self.bump().ok_or(JsonError::UnexpectedEof)?;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self.bump().ok_or(JsonError::UnexpectedEof)?;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let cp = self.parse_unicode_escape()?;
                            // Reject high/low surrogates — keep parser minimal; chela
                            // only emits codepoints below 0xD800 in `\u` escapes
                            // (control chars and `<`).
                            if (0xD800..=0xDFFF).contains(&cp) {
                                return Err(JsonError::BadEscape);
                            }
                            let c = char::from_u32(cp).ok_or(JsonError::BadEscape)?;
                            out.push(c);
                        }
                        _ => return Err(JsonError::BadEscape),
                    }
                }
                // Per RFC 8259, raw control chars (< 0x20) are not allowed
                // unescaped inside string literals.
                b if b < 0x20 => return Err(JsonError::UnexpectedChar(self.pos - 1)),
                // Otherwise treat the byte as part of the underlying UTF-8 (the
                // input is already &str so it's valid UTF-8). We need to copy
                // the full codepoint, which may be 1–4 bytes.
                b => {
                    let extra = match b {
                        0x00..=0x7f => 0,
                        0xc0..=0xdf => 1,
                        0xe0..=0xef => 2,
                        0xf0..=0xf7 => 3,
                        _ => return Err(JsonError::UnexpectedChar(self.pos - 1)),
                    };
                    let start = self.pos - 1;
                    for _ in 0..extra {
                        self.bump().ok_or(JsonError::UnexpectedEof)?;
                    }
                    // SAFETY: input is &str, so the byte range is valid UTF-8.
                    let s = core::str::from_utf8(&self.bytes[start..self.pos])
                        .map_err(|_| JsonError::BadEscape)?;
                    out.push_str(s);
                }
            }
        }
    }

    /// Read exactly four hex digits, returning their u32 value.
    fn parse_unicode_escape(&mut self) -> Result<u32, JsonError> {
        let mut cp: u32 = 0;
        for _ in 0..4 {
            let b = self.bump().ok_or(JsonError::UnexpectedEof)?;
            let digit = match b {
                b'0'..=b'9' => u32::from(b - b'0'),
                b'a'..=b'f' => u32::from(b - b'a' + 10),
                b'A'..=b'F' => u32::from(b - b'A' + 10),
                _ => return Err(JsonError::BadEscape),
            };
            cp = (cp << 4) | digit;
        }
        Ok(cp)
    }

    fn parse_bool(&mut self) -> Result<Value, JsonError> {
        if self.bytes[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(Value::Bool(true))
        } else if self.bytes[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(Value::Bool(false))
        } else {
            Err(JsonError::UnexpectedChar(self.pos))
        }
    }

    fn parse_null(&mut self) -> Result<Value, JsonError> {
        if self.bytes[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(Value::Null)
        } else {
            Err(JsonError::UnexpectedChar(self.pos))
        }
    }

    fn parse_number(&mut self) -> Result<Value, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        // Reject floats / exponents — out of scope.
        if let Some(b) = self.peek() {
            if matches!(b, b'.' | b'e' | b'E') {
                return Err(JsonError::InvalidNumber);
            }
        }
        if self.pos == start || (self.pos == start + 1 && self.bytes[start] == b'-') {
            return Err(JsonError::InvalidNumber);
        }
        let lexeme = core::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| JsonError::InvalidNumber)?;
        let n = lexeme
            .parse::<i64>()
            .map_err(|_| JsonError::InvalidNumber)?;
        Ok(Value::Number(n))
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, JsonError, Value, MAX_DEPTH};
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;

    #[test]
    fn primitives() {
        assert_eq!(parse("null").unwrap(), Value::Null);
        assert_eq!(parse("true").unwrap(), Value::Bool(true));
        assert_eq!(parse("false").unwrap(), Value::Bool(false));
        assert_eq!(parse("0").unwrap(), Value::Number(0));
        assert_eq!(parse("42").unwrap(), Value::Number(42));
        assert_eq!(parse("-17").unwrap(), Value::Number(-17));
        assert_eq!(
            parse("9223372036854775807").unwrap(),
            Value::Number(i64::MAX)
        );
    }

    #[test]
    fn rejects_floats_and_exponents() {
        assert_eq!(parse("3.14"), Err(JsonError::InvalidNumber));
        assert_eq!(parse("1e10"), Err(JsonError::InvalidNumber));
        assert_eq!(parse("2E5"), Err(JsonError::InvalidNumber));
    }

    #[test]
    fn rejects_bare_minus_or_empty_number() {
        assert_eq!(parse("-"), Err(JsonError::InvalidNumber));
    }

    #[test]
    fn rejects_number_overflow() {
        assert_eq!(parse("99999999999999999999"), Err(JsonError::InvalidNumber));
    }

    #[test]
    fn strings_basic_and_escapes() {
        assert_eq!(parse(r#""""#).unwrap(), Value::String(String::new()));
        assert_eq!(
            parse(r#""hello""#).unwrap(),
            Value::String("hello".to_string())
        );
        assert_eq!(
            parse(r#""line\nbreak\ttab\r\b\f""#).unwrap(),
            Value::String("line\nbreak\ttab\r\u{0008}\u{000C}".to_string())
        );
        assert_eq!(
            parse(r#""quote\"inside""#).unwrap(),
            Value::String("quote\"inside".to_string())
        );
        assert_eq!(
            parse(r#""slash\/forward""#).unwrap(),
            Value::String("slash/forward".to_string())
        );
        assert_eq!(
            parse(r#""back\\slash""#).unwrap(),
            Value::String("back\\slash".to_string())
        );
    }

    #[test]
    fn unicode_escape() {
        assert_eq!(parse(r#""<""#).unwrap(), Value::String("<".to_string()));
        assert_eq!(parse(r#""é""#).unwrap(), Value::String("é".to_string()));
    }

    #[test]
    fn rejects_surrogate_escape() {
        assert_eq!(parse(r#""\uD800""#), Err(JsonError::BadEscape));
    }

    #[test]
    fn passes_through_utf8_in_strings() {
        let s = parse(r#""café 🦀""#).unwrap();
        assert_eq!(s, Value::String("café 🦀".to_string()));
    }

    #[test]
    fn rejects_unescaped_control_char_in_string() {
        // Tab byte 0x09 unescaped is illegal per RFC.
        let bad = "\"line\tbreak\"";
        assert!(matches!(parse(bad), Err(JsonError::UnexpectedChar(_))));
    }

    #[test]
    fn arrays() {
        assert_eq!(parse("[]").unwrap(), Value::Array(Vec::new()));
        assert_eq!(
            parse("[1,2,3]").unwrap(),
            Value::Array(alloc::vec![
                Value::Number(1),
                Value::Number(2),
                Value::Number(3)
            ])
        );
        assert_eq!(
            parse(r#"["a", "b"]"#).unwrap(),
            Value::Array(alloc::vec![
                Value::String("a".to_string()),
                Value::String("b".to_string())
            ])
        );
    }

    #[test]
    fn objects() {
        assert_eq!(parse("{}").unwrap(), Value::Object(Vec::new()));
        let v = parse(r#"{"name":"Alice","age":30}"#).unwrap();
        assert_eq!(v.get("name"), Some(&Value::String("Alice".to_string())));
        assert_eq!(v.get("age"), Some(&Value::Number(30)));
    }

    #[test]
    fn whitespace_tolerated_everywhere() {
        let v = parse("  {  \"k\"  :  [ 1 , 2 ]  }  ").unwrap();
        assert!(v.get("k").is_some());
    }

    #[test]
    fn trailing_garbage_rejected() {
        assert_eq!(parse("42 extra"), Err(JsonError::TrailingGarbage));
        assert_eq!(parse("[1,2,3]}"), Err(JsonError::TrailingGarbage));
    }

    #[test]
    fn trailing_comma_rejected() {
        assert!(matches!(parse("[1,2,]"), Err(JsonError::UnexpectedChar(_))));
        assert!(matches!(
            parse(r#"{"a":1,}"#),
            Err(JsonError::UnexpectedChar(_))
        ));
    }

    #[test]
    fn unterminated_string_rejected() {
        assert_eq!(parse(r#""abc"#), Err(JsonError::UnexpectedEof));
    }

    #[test]
    fn unterminated_array_rejected() {
        assert_eq!(parse("[1, 2"), Err(JsonError::UnexpectedEof));
    }

    #[test]
    fn unterminated_object_rejected() {
        assert_eq!(parse(r#"{"a":1"#), Err(JsonError::UnexpectedEof));
    }

    #[test]
    fn depth_limit_enforced() {
        // 33 levels of nesting should trip the limit (MAX_DEPTH=32).
        let mut deep = String::new();
        for _ in 0..=MAX_DEPTH {
            deep.push('[');
        }
        for _ in 0..=MAX_DEPTH {
            deep.push(']');
        }
        assert_eq!(parse(&deep), Err(JsonError::DepthLimitExceeded));
    }

    #[test]
    fn deep_but_within_limit_parses() {
        let mut deep = String::new();
        for _ in 0..MAX_DEPTH - 1 {
            deep.push('[');
        }
        deep.push('1');
        for _ in 0..MAX_DEPTH - 1 {
            deep.push(']');
        }
        assert!(parse(&deep).is_ok());
    }

    #[test]
    fn as_helpers_return_none_for_wrong_type() {
        let n = Value::Number(5);
        assert_eq!(n.as_str(), None);
        assert_eq!(n.as_array(), None);
        assert_eq!(n.as_object(), None);
        assert_eq!(n.as_u8(), Some(5u8));
        assert_eq!(n.as_usize(), Some(5usize));

        let s = Value::String("hi".to_string());
        assert_eq!(s.as_str(), Some("hi"));
        assert_eq!(s.as_i64(), None);
        assert_eq!(s.as_u8(), None);

        let neg = Value::Number(-1);
        assert_eq!(neg.as_u8(), None);
        assert_eq!(neg.as_usize(), None);
    }

    /// Random byte strings must never panic the parser.
    #[test]
    fn fuzz_smoke_does_not_panic() {
        let cases: &[&str] = &[
            "",
            " ",
            "\0",
            "{",
            "}",
            "[",
            "]",
            r#""\"#,
            r#""\u""#,
            r#""\u00""#,
            r#""\uZZZZ""#,
            "-",
            "01",
            "[[[[[",
            r#"{"a":"#,
            "{:1}",
            r#"{"a":,}"#,
            "tru",
            "fals",
            "nul",
        ];
        for c in cases {
            let _ = parse(c);
        }
    }
}
