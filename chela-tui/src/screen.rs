//! Alternate-buffer raw-mode screen for the main menu.

#![allow(
    clippy::missing_errors_doc,
    clippy::unused_self,
    clippy::match_same_arms
)]

use std::io::{self, Read, Write};

use crate::term::raw_termios::RawModeGuard;

/// Active full-screen session. Drop it to return to the normal terminal.
pub(crate) struct Screen {
    _termios_guard: RawModeGuard,
}

impl Screen {
    /// Enter the alternate screen buffer in raw mode, or `None` if termios fails.
    pub(crate) fn enter() -> Option<Self> {
        let guard = crate::term::raw_termios::enter_full_raw()?;
        let mut out = io::stdout();
        // CSI ?1049h enter alt screen · CSI ?25l hide cursor · CSI 2J erase screen · CSI H home.
        let _ = out.write_all(b"\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H");
        let _ = out.flush();
        Some(Self {
            _termios_guard: guard,
        })
    }

    /// Clear screen and home the cursor.
    pub(crate) fn clear(&self) {
        let mut out = io::stdout();
        // CSI 2J - erase entire screen; CSI H - move cursor to (1, 1).
        let _ = out.write_all(b"\x1b[2J\x1b[H");
        let _ = out.flush();
    }

    /// Write text at row, col (both 1-indexed).
    pub(crate) fn write_at(&self, row: u16, col: u16, text: &str) {
        let mut out = io::stdout();
        let _ = write!(out, "\x1b[{row};{col}H{text}");
        let _ = out.flush();
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let mut out = io::stdout();
        // CSI 0m reset SGR · CSI ?25h show cursor · CSI ?1049l leave alt screen.
        let _ = out.write_all(b"\x1b[0m\x1b[?25h\x1b[?1049l");
        let _ = out.flush();
    }
}

/// Keys recognised by the screen-based UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Key {
    Char(char),
    Enter,
    Escape,
    Backspace,
    Tab,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    Delete,
    CtrlC,
    Other,
    Eof,
}

/// Read a single keystroke, blocking until a key arrives or stdin closes.
pub(crate) fn read_key() -> io::Result<Key> {
    let mut byte = [0u8; 1];
    let stdin = io::stdin();
    let mut h = stdin.lock();
    let n = h.read(&mut byte)?;
    if n == 0 {
        return Ok(Key::Eof);
    }
    match byte[0] {
        b'\r' | b'\n' => Ok(Key::Enter),
        b'\t' => Ok(Key::Tab),
        0x01 => Ok(Key::Home), // Ctrl-A
        0x03 => Ok(Key::CtrlC),
        0x05 => Ok(Key::End), // Ctrl-E
        0x7f | 0x08 => Ok(Key::Backspace),
        0x1b => {
            // A lone Esc and the start of an escape sequence (arrows, Home/End) both begin
            // with 0x1b. Under the ambient VMIN=1 the follow-up read blocks forever on a
            // bare Esc, so drop to VMIN=0/VTIME=1 (~100ms): the read times out and returns
            // 0, which `read_escape_sequence` reports as `Key::Escape`. Restore the blocking
            // config afterward so the next keystroke's first byte still waits.
            crate::term::raw_termios::set_read_timeout(0, 1);
            let key = read_escape_sequence(&mut h);
            crate::term::raw_termios::set_read_timeout(1, 1);
            key
        }
        b if b < 0x80 => {
            if b.is_ascii_graphic() || b == b' ' {
                Ok(Key::Char(b as char))
            } else {
                Ok(Key::Other)
            }
        }
        b => {
            // UTF-8 leading byte: decode continuation byte count from the high bits.
            let extra = match b {
                0xc0..=0xdf => 1,
                0xe0..=0xef => 2,
                0xf0..=0xf7 => 3,
                _ => return Ok(Key::Other),
            };
            let mut bytes = [0u8; 4];
            bytes[0] = b;
            h.read_exact(&mut bytes[1..=extra])?;
            match core::str::from_utf8(&bytes[..=extra]) {
                Ok(s) => Ok(Key::Char(s.chars().next().unwrap_or('\u{FFFD}'))),
                Err(_) => Ok(Key::Other),
            }
        }
    }
}

/// Decode an escape sequence after `\x1b` is consumed.
/// Handles SS3 (`\x1bO<letter>`) and CSI (`\x1b[<letter>` or `\x1b[<num>~`). A lone
/// Esc (VTIME timeout, no follow-up byte) returns `Key::Escape`.
fn read_escape_sequence(h: &mut dyn Read) -> io::Result<Key> {
    let mut b = [0u8; 1];
    let n = h.read(&mut b)?;
    if n == 0 {
        return Ok(Key::Escape);
    }
    match b[0] {
        b'[' => {
            let n = h.read(&mut b)?;
            if n == 0 {
                return Ok(Key::Other);
            }
            match b[0] {
                b'A' => Ok(Key::Up),
                b'B' => Ok(Key::Down),
                b'C' => Ok(Key::Right),
                b'D' => Ok(Key::Left),
                b'H' => Ok(Key::Home),
                b'F' => Ok(Key::End),
                d @ b'0'..=b'9' => {
                    // CSI <digits> [;<digits>]* <final>: we only need the leading digit
                    // and the final terminator (`~` or letter); modifier subfields ignored.
                    let mut first = d;
                    let mut last;
                    loop {
                        let n = h.read(&mut b)?;
                        if n == 0 {
                            return Ok(Key::Other);
                        }
                        last = b[0];
                        if !last.is_ascii_digit() && last != b';' {
                            break;
                        }
                        if last.is_ascii_digit() && first == 0 {
                            first = last;
                        }
                    }
                    if last == b'~' {
                        match first {
                            b'1' | b'7' => Ok(Key::Home),
                            b'3' => Ok(Key::Delete),
                            b'4' | b'8' => Ok(Key::End),
                            _ => Ok(Key::Other),
                        }
                    } else {
                        Ok(Key::Other)
                    }
                }
                _ => Ok(Key::Other),
            }
        }
        b'O' => {
            let n = h.read(&mut b)?;
            if n == 0 {
                return Ok(Key::Other);
            }
            match b[0] {
                b'A' => Ok(Key::Up),
                b'B' => Ok(Key::Down),
                b'C' => Ok(Key::Right),
                b'D' => Ok(Key::Left),
                b'H' => Ok(Key::Home),
                b'F' => Ok(Key::End),
                _ => Ok(Key::Other),
            }
        }
        _ => Ok(Key::Other),
    }
}

#[cfg(test)]
mod tests {
    use super::{read_escape_sequence, Key};
    use std::io::Cursor;

    fn decode(bytes: &[u8]) -> Key {
        // Caller has consumed the leading 0x1b; pass the remainder.
        read_escape_sequence(&mut Cursor::new(bytes)).unwrap()
    }

    #[test]
    fn lone_esc_returns_escape() {
        assert_eq!(decode(b""), Key::Escape);
    }

    #[test]
    fn csi_arrows() {
        assert_eq!(decode(b"[A"), Key::Up);
        assert_eq!(decode(b"[B"), Key::Down);
        assert_eq!(decode(b"[C"), Key::Right);
        assert_eq!(decode(b"[D"), Key::Left);
    }

    #[test]
    fn csi_home_end() {
        assert_eq!(decode(b"[H"), Key::Home);
        assert_eq!(decode(b"[F"), Key::End);
    }

    #[test]
    fn csi_tilde_keys() {
        assert_eq!(decode(b"[1~"), Key::Home);
        assert_eq!(decode(b"[3~"), Key::Delete);
        assert_eq!(decode(b"[4~"), Key::End);
        assert_eq!(decode(b"[7~"), Key::Home);
        assert_eq!(decode(b"[8~"), Key::End);
    }

    #[test]
    fn csi_with_modifier_subfield() {
        // xterm sends `\x1b[1;5A` for Ctrl+Up; we recognise the prefix as Home (per the
        // `b'1'` arm of the tilde match) only if terminated by `~`, otherwise Other.
        assert_eq!(decode(b"[1;5A"), Key::Other);
    }

    #[test]
    fn ss3_arrows() {
        assert_eq!(decode(b"OA"), Key::Up);
        assert_eq!(decode(b"OB"), Key::Down);
        assert_eq!(decode(b"OH"), Key::Home);
        assert_eq!(decode(b"OF"), Key::End);
    }

    #[test]
    fn unknown_csi_letter_is_other() {
        assert_eq!(decode(b"[Z"), Key::Other);
    }

    #[test]
    fn truncated_csi_is_other() {
        assert_eq!(decode(b"["), Key::Other);
        assert_eq!(decode(b"O"), Key::Other);
    }

    #[test]
    fn unknown_lead_byte_is_other() {
        assert_eq!(decode(b"x"), Key::Other);
    }
}
