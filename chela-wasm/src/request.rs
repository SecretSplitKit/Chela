//! Binary request decoder.
//!
//! Wire format is a single tag byte followed by length-prefixed UTF-8 strings and small
//! integers. Length prefixes are little-endian `u32` - over-provisioned vs. the actual
//! payload sizes, but it keeps the decoder trivial and leaves room for larger text.
//!
//! Per request type:
//!
//! ```text
//! 0x01 SplitBip39:    [u8 threshold][u8 total][lp_str mnemonic][lp_str passphrase]
//! 0x02 SplitText:     [u8 threshold][u8 total][lp_str text]
//! 0x03 Recover:       [u16 n_shares][ n × { lp_str header, lp_str words } ]
//! 0x04 RenderPaper:   [u16 n_shares][ n × { lp_str header, lp_str words } ]
//!                     [u8 has_backup_name][lp_str if has]
//!                     [u8 has_description][lp_str if has]
//!                     [u8 has_shareholders][u16 count + n × lp_str if has]
//! ```
//!
//! Where `lp_str` = `[u32 le len][len bytes utf-8]`.

use chela_primitives::zeroize::Zeroize;
use std::string::{String, ToString};
use std::vec::Vec;

#[derive(Debug)]
pub(crate) enum SplitRequest {
    Bip39 {
        threshold: u8,
        total: u8,
        mnemonic: String,
        passphrase: String,
    },
    Text {
        threshold: u8,
        total: u8,
        text: String,
    },
}

impl Drop for SplitRequest {
    fn drop(&mut self) {
        match self {
            SplitRequest::Bip39 {
                mnemonic,
                passphrase,
                ..
            } => {
                mnemonic.zeroize();
                passphrase.zeroize();
            }
            SplitRequest::Text { text, .. } => text.zeroize(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct RawShare {
    pub(crate) header: String,
    pub(crate) words: String,
}

impl Drop for RawShare {
    fn drop(&mut self) {
        self.header.zeroize();
        self.words.zeroize();
    }
}

#[derive(Debug)]
pub(crate) struct RecoverRequest {
    pub(crate) shares: Vec<RawShare>,
}

#[derive(Debug)]
pub(crate) struct RenderPaperRequest {
    pub(crate) shares: Vec<RawShare>,
    pub(crate) backup_name: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) shareholder_names: Option<Vec<String>>,
}

const TAG_SPLIT_BIP39: u8 = 0x01;
const TAG_SPLIT_TEXT: u8 = 0x02;
const TAG_RECOVER: u8 = 0x03;
const TAG_RENDER_PAPER: u8 = 0x04;

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn need(&self, n: usize) -> Result<(), String> {
        // checked_add: on wasm32 `usize` is 32-bit, and `n` derives from an attacker/JS
        // length prefix, so `self.pos + n` could overflow and wrap past the bounds check.
        if self
            .pos
            .checked_add(n)
            .is_none_or(|end| end > self.buf.len())
        {
            Err(format!(
                "unexpected end of input at byte {} (wanted {} more)",
                self.pos, n
            ))
        } else {
            Ok(())
        }
    }

    fn u8(&mut self) -> Result<u8, String> {
        self.need(1)?;
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn u16_le(&mut self) -> Result<u16, String> {
        self.need(2)?;
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn u32_le(&mut self) -> Result<u32, String> {
        self.need(4)?;
        let v = u32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn lp_str(&mut self) -> Result<String, String> {
        let len = self.u32_le()? as usize;
        self.need(len)?;
        let bytes = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        core::str::from_utf8(bytes)
            .map(ToString::to_string)
            .map_err(|e| format!("invalid UTF-8 at byte {} ({e})", self.pos - len))
    }

    fn finish(&self) -> Result<(), String> {
        if self.pos < self.buf.len() {
            Err(format!(
                "trailing bytes after request: {} unread of {}",
                self.buf.len() - self.pos,
                self.buf.len()
            ))
        } else {
            Ok(())
        }
    }
}

fn read_shares(c: &mut Cursor<'_>) -> Result<Vec<RawShare>, String> {
    let n = c.u16_le()? as usize;
    let mut shares = Vec::with_capacity(n);
    for _ in 0..n {
        let header = c.lp_str()?;
        let words = c.lp_str()?;
        shares.push(RawShare { header, words });
    }
    Ok(shares)
}

impl SplitRequest {
    pub(crate) fn decode(input: &[u8]) -> Result<Self, String> {
        let mut c = Cursor::new(input);
        let tag = c.u8()?;
        let req = match tag {
            TAG_SPLIT_BIP39 => {
                let threshold = c.u8()?;
                let total = c.u8()?;
                let mnemonic = c.lp_str()?;
                let passphrase = c.lp_str()?;
                Self::Bip39 {
                    threshold,
                    total,
                    mnemonic,
                    passphrase,
                }
            }
            TAG_SPLIT_TEXT => {
                let threshold = c.u8()?;
                let total = c.u8()?;
                let text = c.lp_str()?;
                Self::Text {
                    threshold,
                    total,
                    text,
                }
            }
            other => return Err(format!("unknown split tag 0x{other:02x}")),
        };
        c.finish()?;
        Ok(req)
    }
}

impl RecoverRequest {
    pub(crate) fn decode(input: &[u8]) -> Result<Self, String> {
        let mut c = Cursor::new(input);
        let tag = c.u8()?;
        if tag != TAG_RECOVER {
            return Err(format!("expected recover tag 0x03, got 0x{tag:02x}"));
        }
        let shares = read_shares(&mut c)?;
        c.finish()?;
        Ok(Self { shares })
    }
}

impl RenderPaperRequest {
    pub(crate) fn decode(input: &[u8]) -> Result<Self, String> {
        let mut c = Cursor::new(input);
        let tag = c.u8()?;
        if tag != TAG_RENDER_PAPER {
            return Err(format!("expected render-paper tag 0x04, got 0x{tag:02x}"));
        }
        let shares = read_shares(&mut c)?;
        let backup_name = if c.u8()? > 0 { Some(c.lp_str()?) } else { None };
        let description = if c.u8()? > 0 { Some(c.lp_str()?) } else { None };
        let shareholder_names = if c.u8()? > 0 {
            let n = c.u16_le()? as usize;
            let mut names = Vec::with_capacity(n);
            for _ in 0..n {
                names.push(c.lp_str()?);
            }
            Some(names)
        } else {
            None
        };
        c.finish()?;
        Ok(Self {
            shares,
            backup_name,
            description,
            shareholder_names,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Push a length-prefixed string to a manually-built test request.
    fn push_lp(buf: &mut Vec<u8>, s: &str) {
        let len = u32::try_from(s.len()).expect("test string fits in u32");
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(s.as_bytes());
    }

    #[test]
    fn decode_split_bip39() {
        let mut buf = vec![0x01, 3, 5];
        push_lp(&mut buf, "foo");
        push_lp(&mut buf, "bar");
        let req = SplitRequest::decode(&buf).unwrap();
        match &req {
            SplitRequest::Bip39 {
                threshold,
                total,
                mnemonic,
                passphrase,
            } => {
                assert_eq!((*threshold, *total), (3, 5));
                assert_eq!(mnemonic, "foo");
                assert_eq!(passphrase, "bar");
            }
            SplitRequest::Text { .. } => panic!("wrong variant"),
        }
    }

    #[test]
    fn decode_split_text() {
        let mut buf = vec![0x02, 2, 3];
        push_lp(&mut buf, "hello");
        let req = SplitRequest::decode(&buf).unwrap();
        match &req {
            SplitRequest::Text {
                threshold,
                total,
                text,
            } => {
                assert_eq!((*threshold, *total), (2, 3));
                assert_eq!(text, "hello");
            }
            SplitRequest::Bip39 { .. } => panic!("wrong variant"),
        }
    }

    #[test]
    fn decode_recover_two_shares() {
        let mut buf = vec![0x03];
        buf.extend_from_slice(&2u16.to_le_bytes()); // n_shares
        for (h, w) in [("HDR1", "w1 w2"), ("HDR2", "w3 w4")] {
            push_lp(&mut buf, h);
            push_lp(&mut buf, w);
        }
        let req = RecoverRequest::decode(&buf).unwrap();
        assert_eq!(req.shares.len(), 2);
        assert_eq!(req.shares[0].header, "HDR1");
        assert_eq!(req.shares[1].words, "w3 w4");
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut buf = vec![0x02, 2, 3];
        push_lp(&mut buf, "hello");
        buf.push(0xff);
        let err = SplitRequest::decode(&buf).unwrap_err();
        assert!(err.contains("trailing bytes"));
    }

    #[test]
    fn rejects_truncated() {
        let buf = vec![0x01, 3];
        let err = SplitRequest::decode(&buf).unwrap_err();
        assert!(err.contains("end of input"));
    }

    #[test]
    fn rejects_invalid_utf8() {
        let mut buf = vec![0x02, 2, 3];
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&[0xff, 0xfe]);
        let err = SplitRequest::decode(&buf).unwrap_err();
        assert!(err.contains("UTF-8"));
    }
}
