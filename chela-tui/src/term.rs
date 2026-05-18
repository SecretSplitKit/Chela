//! Terminal helpers: colors, prompts, masked password input.

#![allow(clippy::missing_errors_doc)]

use std::io::{self, BufRead, Read, Write};

pub(crate) const RESET: &str = "\x1b[0m";
pub(crate) const BOLD: &str = "\x1b[1m";
/// 256-color mid-gray (#949494, index 246) — used instead of SGR faint (`\x1b[2m`)
/// because faint renders ~50% intensity and was illegible on many themes.
pub(crate) const DIM: &str = "\x1b[38;5;246m";
pub(crate) const CYAN: &str = "\x1b[36m";
pub(crate) const BRIGHT_CYAN: &str = "\x1b[96m";
pub(crate) const YELLOW: &str = "\x1b[33m";
pub(crate) const RED: &str = "\x1b[31m";
pub(crate) const GREEN: &str = "\x1b[32m";
/// SGR 7 — reverse video.
pub(crate) const REVERSE: &str = "\x1b[7m";

pub(crate) fn clear() {
    // CSI 2J — erase entire screen; CSI H — cursor to (1, 1).
    print!("\x1b[2J\x1b[H");
    let _ = io::stdout().flush();
}

/// Visible-screen clear plus the xterm scrollback-wipe extension (`CSI 3J`).
/// Used when we have to display a secret in the normal terminal (no alt-screen
/// fallback) — best-effort, not all terminals honour `3J`.
pub(crate) fn clear_with_scrollback() {
    // CSI 2J — visible screen; CSI 3J — scrollback (xterm/most modern terms);
    // CSI H — home; then a soft reset to drop any leftover attributes.
    print!("\x1b[2J\x1b[3J\x1b[H");
    let _ = io::stdout().flush();
}

/// Replace bytes that would be interpreted as control / escape sequences by the
/// terminal with a visible `\xHH` (C0/DEL) or `\u{HHHH}` (C1) escape. Recovered
/// secrets pass through this before being printed so an attacker-controlled
/// payload cannot inject OSC 52 (clipboard write), window-title spoofs, or
/// cursor manipulation when the user displays the reconstruction.
///
/// `\n` and `\t` are preserved — they have no escape-sequence interpretation by
/// themselves and removing them would garble legitimate multi-line input.
pub(crate) fn sanitize_for_terminal(s: &str) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\n' || c == '\t' {
            out.push(c);
        } else if c.is_control() {
            let cp = u32::from(c);
            if cp < 0x80 {
                let _ = write!(out, "\\x{cp:02X}");
            } else {
                let _ = write!(out, "\\u{{{cp:04X}}}");
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub(crate) fn banner(title: &str) {
    clear();
    println!(
        "{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════╗{RESET}"
    );
    println!("{BOLD}{CYAN}║{RESET} {BOLD}{title:<61}{RESET} {BOLD}{CYAN}║{RESET}");
    println!(
        "{BOLD}{CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}"
    );
    println!();
}

pub(crate) fn info(msg: &str) {
    println!("{DIM}{msg}{RESET}");
}

pub(crate) fn warn(msg: &str) {
    println!("{YELLOW}⚠  {msg}{RESET}");
}

pub(crate) fn error(msg: &str) {
    println!("{RED}✗  {msg}{RESET}");
}

pub(crate) fn success(msg: &str) {
    println!("{GREEN}✓  {msg}{RESET}");
}

/// Highlight everything up to and including the `❯` marker; pass through unchanged
/// when there is no marker (so plain "Press Enter" prompts render normally).
fn decorate(p: &str) -> String {
    match p.rfind('❯') {
        Some(idx) => {
            let marker_end = idx + '❯'.len_utf8();
            let (highlighted, rest) = p.split_at(marker_end);
            format!("{BRIGHT_CYAN}{BOLD}{highlighted}{RESET}{rest}")
        }
        None => p.to_owned(),
    }
}

/// Print `prompt` and read a line from stdin; `None` on EOF.
pub(crate) fn prompt(prompt: &str) -> io::Result<Option<String>> {
    print!("{}", decorate(prompt));
    io::stdout().flush()?;
    let stdin = io::stdin();
    let mut line = String::new();
    let n = stdin.lock().read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
    Ok(Some(trimmed))
}

/// Like [`prompt`] but loops until a non-empty line is entered.
pub(crate) fn prompt_nonempty(p: &str) -> io::Result<Option<String>> {
    loop {
        let Some(value) = prompt(p)? else {
            return Ok(None);
        };
        if !value.trim().is_empty() {
            return Ok(Some(value));
        }
        warn("Please enter a value (or Ctrl-D to abort).");
    }
}

/// Prompt for a `u8` in `[min, max]`, looping on parse / range error.
pub(crate) fn prompt_u8_in_range(p: &str, min: u8, max: u8) -> io::Result<Option<u8>> {
    loop {
        let Some(line) = prompt(p)? else {
            return Ok(None);
        };
        match line.trim().parse::<u8>() {
            Ok(n) if (min..=max).contains(&n) => return Ok(Some(n)),
            Ok(_) => warn(&format!("Number must be between {min} and {max}.")),
            Err(_) => warn("Please enter a whole number."),
        }
    }
}

/// Prompt for a line; empty input returns `default`, Esc/Ctrl-C/EOF returns `None`.
/// Falls back to a canonical-mode read (where only EOF can cancel) without raw termios.
pub(crate) fn prompt_line_or_default(p: &str, default: &str) -> io::Result<Option<String>> {
    if let Some(_guard) = raw_termios::enter_full_raw() {
        return raw_line_editor(p, "", default);
    }
    let Some(line) = prompt(p)? else {
        return Ok(None);
    };
    Ok(Some(if line.trim().is_empty() {
        default.to_owned()
    } else {
        line
    }))
}

/// Prompt with `initial` pre-filled in the editor; whatever's in the buffer on Enter
/// is returned (no empty-input default). Newlines in `initial` are collapsed to spaces
/// because the editor is single-line. `None` on Esc/Ctrl-C/EOF. Canonical-mode fallback
/// can't pre-fill the buffer, so `initial` is shown as a hint and only used if the user
/// commits an empty line.
pub(crate) fn prompt_line_prefilled(p: &str, initial: &str) -> io::Result<Option<String>> {
    let collapsed: String = initial.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(_guard) = raw_termios::enter_full_raw() {
        return raw_line_editor(p, &collapsed, "");
    }
    info(&format!("(starting text: {collapsed})"));
    let Some(line) = prompt(p)? else {
        return Ok(None);
    };
    Ok(Some(if line.trim().is_empty() {
        collapsed
    } else {
        line
    }))
}

/// Raw-mode line editor with cursor movement, mid-text insert/delete, and wrap-aware
/// cursor positioning. Returns `empty_default` if the user commits an empty buffer;
/// `None` on Esc / Ctrl-C / EOF.
fn raw_line_editor(p: &str, prefill: &str, empty_default: &str) -> io::Result<Option<String>> {
    use std::io::Write as _;
    let mut stdout = io::stdout();

    // Prompt char count (ANSI escapes don't take a column, our prompts are ASCII + `❯`
    // so each char == one column).
    let prompt_visible = p.chars().count();
    let width = usize::from(raw_termios::terminal_width().unwrap_or(80)).max(1);
    let decorated = decorate(p);

    let mut buf: Vec<u8> = prefill.as_bytes().to_vec();
    // BYTE offset on a UTF-8 char boundary; start at end so Enter commits the prefill.
    let mut cursor: usize = buf.len();

    // DECSC — save cursor; paired with DECRC (`\x1b8`) in the redraw.
    stdout.write_all(b"\x1b7")?;
    stdout.flush()?;

    loop {
        // DECRC restore · CSI J erase to end of screen.
        stdout.write_all(b"\x1b8\x1b[J")?;
        stdout.write_all(decorated.as_bytes())?;
        stdout.write_all(&buf)?;

        let buf_str = std::str::from_utf8(&buf).unwrap_or("");
        let chars_before_cursor = buf_str[..cursor].chars().count();
        let chars_total = chars_before_cursor + buf_str[cursor..].chars().count();
        let cursor_visible = prompt_visible + chars_before_cursor;
        let end_visible = prompt_visible + chars_total;
        let end_row = end_visible / width;
        let cursor_row = cursor_visible / width;
        let cursor_col = cursor_visible % width;
        let rows_up = end_row.saturating_sub(cursor_row);
        if rows_up > 0 {
            // CSI A — cursor up N rows.
            write!(stdout, "\x1b[{rows_up}A")?;
        }
        // CSI G — move to absolute column (1-indexed).
        write!(stdout, "\x1b[{}G", cursor_col + 1)?;
        stdout.flush()?;

        match crate::screen::read_key()? {
            crate::screen::Key::Enter => {
                println!();
                let s = String::from_utf8_lossy(&buf).into_owned();
                return Ok(Some(if s.is_empty() {
                    empty_default.to_owned()
                } else {
                    s
                }));
            }
            crate::screen::Key::Escape | crate::screen::Key::CtrlC | crate::screen::Key::Eof => {
                println!();
                return Ok(None);
            }
            crate::screen::Key::Left => {
                if cursor > 0 {
                    cursor = prev_char_boundary(&buf, cursor);
                }
            }
            crate::screen::Key::Right => {
                if cursor < buf.len() {
                    cursor = next_char_boundary(&buf, cursor);
                }
            }
            crate::screen::Key::Home => {
                cursor = 0;
            }
            crate::screen::Key::End => {
                cursor = buf.len();
            }
            crate::screen::Key::Backspace => {
                if cursor > 0 {
                    let new_cursor = prev_char_boundary(&buf, cursor);
                    buf.drain(new_cursor..cursor);
                    cursor = new_cursor;
                }
            }
            crate::screen::Key::Delete => {
                if cursor < buf.len() {
                    let end = next_char_boundary(&buf, cursor);
                    buf.drain(cursor..end);
                }
            }
            crate::screen::Key::Char(c) => {
                let mut bytes = [0u8; 4];
                let s = c.encode_utf8(&mut bytes);
                let bytes = s.as_bytes();
                buf.splice(cursor..cursor, bytes.iter().copied());
                cursor += bytes.len();
            }
            _ => {}
        }
    }
}

/// Walk back over UTF-8 continuation bytes (`10xxxxxx`) to the previous codepoint start.
fn prev_char_boundary(buf: &[u8], pos: usize) -> usize {
    debug_assert!(pos > 0);
    let mut i = pos - 1;
    while i > 0 && (buf[i] & 0xc0) == 0x80 {
        i -= 1;
    }
    i
}

/// Walk forward past UTF-8 continuation bytes to the next codepoint start.
fn next_char_boundary(buf: &[u8], pos: usize) -> usize {
    debug_assert!(pos < buf.len());
    let mut i = pos + 1;
    while i < buf.len() && (buf[i] & 0xc0) == 0x80 {
        i += 1;
    }
    i
}

/// Arrow-key picker. `initial = None` forces an explicit ↑/↓ before Enter commits,
/// so reflex-Enter can't pick a security-sensitive default. Returns the 0-based index,
/// or `None` on Esc/Ctrl-C/EOF. Falls back to a numbered prompt without raw termios.
pub(crate) fn select(options: &[&str], initial: Option<usize>) -> io::Result<Option<usize>> {
    if options.is_empty() {
        return Ok(None);
    }
    let Some(_guard) = raw_termios::enter_full_raw() else {
        return select_fallback(options, initial);
    };
    select_raw(options, initial)
}

fn select_raw(options: &[&str], initial: Option<usize>) -> io::Result<Option<usize>> {
    use std::io::Write as _;
    let mut stdout = io::stdout();

    let mut cursor: Option<usize> = initial.map(|i| i.min(options.len() - 1));
    let mut prev_lines: Option<usize> = None;
    let mut error: Option<&'static str> = None;

    loop {
        if let Some(n) = prev_lines {
            write!(stdout, "\x1b[{n}A\r\x1b[J")?;
        }
        let frame = render_select_frame(options, cursor, error);
        write!(stdout, "{frame}")?;
        stdout.flush()?;
        prev_lines = Some(frame.matches('\n').count());

        match crate::screen::read_key()? {
            crate::screen::Key::Up => {
                error = None;
                cursor = Some(match cursor {
                    None | Some(0) => options.len() - 1,
                    Some(c) => c - 1,
                });
            }
            crate::screen::Key::Down | crate::screen::Key::Tab => {
                error = None;
                cursor = Some(match cursor {
                    None => 0,
                    Some(c) => (c + 1) % options.len(),
                });
            }
            crate::screen::Key::Char(c) if c.is_ascii_digit() => {
                if let Some(idx) = (c as u8).checked_sub(b'1').map(usize::from) {
                    if idx < options.len() {
                        cursor = Some(idx);
                        error = None;
                    }
                }
            }
            crate::screen::Key::Enter => match cursor {
                Some(idx) => {
                    if let Some(n) = prev_lines {
                        write!(stdout, "\x1b[{n}A\r\x1b[J")?;
                    }
                    writeln!(stdout, "  {BOLD}{}{RESET}", options[idx])?;
                    writeln!(stdout)?;
                    stdout.flush()?;
                    return Ok(Some(idx));
                }
                None => {
                    error = Some("Use ↑/↓ to pick an option, then Enter to confirm.");
                }
            },
            crate::screen::Key::Escape | crate::screen::Key::CtrlC | crate::screen::Key::Eof => {
                if let Some(n) = prev_lines {
                    write!(stdout, "\x1b[{n}A\r\x1b[J")?;
                }
                stdout.flush()?;
                return Ok(None);
            }
            _ => {}
        }
    }
}

fn render_select_frame(
    options: &[&str],
    cursor: Option<usize>,
    error: Option<&'static str>,
) -> String {
    // Distinct from the module-level `std::io::Write`.
    use core::fmt::Write as _;

    let mut out = String::with_capacity(256);
    for (i, opt) in options.iter().enumerate() {
        if Some(i) == cursor {
            let _ = writeln!(
                out,
                "  {BRIGHT_CYAN}{BOLD}▶{RESET} {REVERSE}{BOLD} {opt} {RESET}",
            );
        } else {
            let _ = writeln!(out, "    {opt}");
        }
    }
    out.push('\n');
    let _ = writeln!(
        out,
        "  {DIM}[↑/↓] move   [Enter] confirm   [Esc] cancel{RESET}",
    );
    if let Some(e) = error {
        let _ = writeln!(out, "  {YELLOW}{e}{RESET}");
    }
    out
}

fn select_fallback(options: &[&str], initial: Option<usize>) -> io::Result<Option<usize>> {
    for (i, opt) in options.iter().enumerate() {
        let marker = if Some(i) == initial { ">" } else { " " };
        println!("  {marker} {}) {}", i + 1, opt);
    }
    loop {
        let Some(line) = prompt("choice ❯ ")? else {
            return Ok(None);
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if let Some(i) = initial {
                return Ok(Some(i));
            }
            warn("Please pick one of the numbered options.");
            continue;
        }
        match trimmed.parse::<usize>() {
            Ok(n) if (1..=options.len()).contains(&n) => return Ok(Some(n - 1)),
            _ => warn(&format!(
                "Please enter a number between 1 and {}.",
                options.len()
            )),
        }
    }
}

/// String whose bytes are volatile-zeroed on drop via `chela_primitives::zeroize`.
/// Avoid `.clone()` — copies bypass the zeroize behaviour.
#[derive(Default)]
pub(crate) struct SecretString {
    inner: String,
}

impl SecretString {
    pub(crate) fn new(s: String) -> Self {
        Self { inner: s }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.inner
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        // `String::as_bytes_mut` is unsafe outside std, so take the inner String, convert
        // to Vec<u8>, zero, drop. The inner String is exclusively owned during Drop so
        // there's no aliasing concern.
        let s = core::mem::take(&mut self.inner);
        let mut bytes = s.into_bytes();
        chela_primitives::zeroize::volatile_set(&mut bytes);
        drop(bytes);
    }
}

/// Reason `read_secret` returned no secret.
pub(crate) enum SecretReadCancel {
    /// User pressed Escape, Ctrl-C, or EOF.
    UserCancelled,
    /// Termios setup failed; refusing to fall back to an echoed prompt is intentional —
    /// echoing a secret in cleartext is strictly worse than aborting.
    NoMaskedInput,
}

/// Read a sensitive line with `*` masking. Tab toggles reveal/re-mask. Refuses to fall
/// back to echoed input — `NoMaskedInput` is returned if termios setup fails.
#[allow(clippy::too_many_lines)]
pub(crate) fn read_secret(p: &str) -> io::Result<Result<SecretString, SecretReadCancel>> {
    print!("{}", decorate(p));
    io::stdout().flush()?;

    // Full-raw (not just no-echo) so a lone Esc can be distinguished from a CSI prefix.
    let Some(_guard) = raw_termios::enter_full_raw() else {
        return Ok(Err(SecretReadCancel::NoMaskedInput));
    };

    let stdin = io::stdin();
    let mut handle = stdin.lock();
    let mut buf: Vec<u8> = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    let mut masked = true;
    // Count of non-continuation bytes drawn on screen, for Tab-toggle erase math.
    let mut visible_cells: usize = 0;

    // Zero the buffer on any non-success exit so a partial secret doesn't reach the allocator.
    let cancel = |mut buf: Vec<u8>| -> io::Result<Result<SecretString, SecretReadCancel>> {
        chela_primitives::zeroize::volatile_set(&mut buf);
        drop(buf);
        println!();
        Ok(Err(SecretReadCancel::UserCancelled))
    };

    loop {
        let n = handle.read(&mut byte)?;
        if n == 0 {
            return cancel(buf);
        }
        match byte[0] {
            b'\n' | b'\r' => {
                println!();
                // UTF-8 lossy: a partial trailing sequence is preferable to dropping the
                // whole secret; masked input is usually ASCII anyway.
                let s = match String::from_utf8(buf) {
                    Ok(s) => s,
                    Err(e) => {
                        let mut bad = e.into_bytes();
                        let recovered = String::from_utf8_lossy(&bad).into_owned();
                        chela_primitives::zeroize::volatile_set(&mut bad);
                        drop(bad);
                        recovered
                    }
                };
                return Ok(Ok(SecretString::new(s)));
            }
            0x03 => {
                return cancel(buf);
            }
            0x1b => {
                // VMIN=0/VTIME=1 (~100ms) to disambiguate lone Esc from a CSI prefix.
                raw_termios::set_read_timeout(0, 1);
                let mut next = [0u8; 1];
                let n2 = handle.read(&mut next)?;
                if n2 == 0 {
                    raw_termios::set_read_timeout(1, 1);
                    return cancel(buf);
                }
                if next[0] == b'[' || next[0] == b'O' {
                    // CSI / SS3: drain until ECMA-48 final byte (0x40..=0x7e).
                    loop {
                        let n3 = handle.read(&mut next)?;
                        if n3 == 0 {
                            break;
                        }
                        if (0x40..=0x7e).contains(&next[0]) {
                            break;
                        }
                    }
                }
                raw_termios::set_read_timeout(1, 1);
            }
            b'\t' => {
                let mut stdout = io::stdout();
                // BS-space-BS erases one cell in place.
                for _ in 0..visible_cells {
                    stdout.write_all(b"\x08 \x08")?;
                }
                masked = !masked;
                if masked {
                    for _ in 0..visible_cells {
                        stdout.write_all(b"*")?;
                    }
                } else {
                    stdout.write_all(&buf)?;
                }
                stdout.flush()?;
            }
            0x7f | 0x08 => {
                let mut erased_any_char = false;
                while let Some(&last) = buf.last() {
                    buf.pop();
                    if (last & 0xc0) != 0x80 {
                        erased_any_char = true;
                        break;
                    }
                }
                if erased_any_char {
                    visible_cells = visible_cells.saturating_sub(1);
                    // BS-space-BS to erase one displayed cell.
                    print!("\x08 \x08");
                    io::stdout().flush()?;
                }
            }
            b => {
                buf.push(b);
                let is_leading_byte = (b & 0xc0) != 0x80;
                if is_leading_byte {
                    visible_cells += 1;
                }
                if masked {
                    if is_leading_byte {
                        print!("*");
                        io::stdout().flush()?;
                    }
                } else {
                    io::stdout().write_all(&[b])?;
                    io::stdout().flush()?;
                }
            }
        }
    }
}

// Raw-mode termios shim — the only `unsafe` in chela-tui. Per-OS `platform` module
// holds the FFI; unsupported targets get a no-op stub.
pub(crate) mod raw_termios {
    #![allow(unsafe_code)]

    #[cfg(target_os = "macos")]
    #[allow(unreachable_pub)]
    mod platform {
        use core::ffi::c_int;
        use core::mem::MaybeUninit;

        /// Darwin `struct termios` from `<sys/termios.h>`: `tcflag_t`/`speed_t` are 8-byte
        /// `unsigned long`, `cc_t` is `unsigned char`, `NCCS == 20`.
        #[repr(C)]
        #[derive(Clone, Copy)]
        #[allow(clippy::struct_field_names)]
        struct Termios {
            c_iflag: u64,
            c_oflag: u64,
            c_cflag: u64,
            c_lflag: u64,
            c_cc: [u8; 20],
            c_ispeed: u64,
            c_ospeed: u64,
        }
        // Compile-time ABI lock against silent termios layout drift.
        const _: () = assert!(core::mem::size_of::<Termios>() == 72);

        #[repr(C)]
        #[derive(Debug, Clone, Copy)]
        #[allow(clippy::struct_field_names)]
        struct WinSize {
            ws_row: u16,
            ws_col: u16,
            ws_xpixel: u16,
            ws_ypixel: u16,
        }
        const _: () = assert!(core::mem::size_of::<WinSize>() == 8);

        unsafe extern "C" {
            fn tcgetattr(fd: c_int, t: *mut Termios) -> c_int;
            fn tcsetattr(fd: c_int, action: c_int, t: *const Termios) -> c_int;
            // POSIX variadic; the request encodes buffer size.
            fn ioctl(fd: c_int, request: u64, ...) -> c_int;
        }

        /// Darwin `TIOCGWINSZ` = `_IOR('t', 104, struct winsize)` =
        /// IOR (0x40000000) | size 8 (0x00080000) | group 't' (0x7400) | num 104 (0x68).
        const TIOCGWINSZ: u64 = 0x4008_7468;
        const STDIN_FD: c_int = 0;
        const TCSANOW: c_int = 0;
        const ECHO: u64 = 0x0000_0008;
        const ICANON: u64 = 0x0000_0100;
        const ISIG: u64 = 0x0000_0080;
        const ICRNL: u64 = 0x0000_0100;
        const IXON: u64 = 0x0000_0200;
        const VMIN: usize = 16;
        const VTIME: usize = 17;

        pub struct RawModeGuard {
            original: Termios,
        }

        impl Drop for RawModeGuard {
            fn drop(&mut self) {
                // SAFETY: STDIN_FD is the always-valid stdin descriptor. `original`
                // was populated by a successful `tcgetattr` before this guard existed.
                // The call only reads `original` (it's `*const`); no aliasing.
                unsafe {
                    tcsetattr(STDIN_FD, TCSANOW, &raw const self.original);
                }
            }
        }

        pub fn enter_full_raw() -> Option<RawModeGuard> {
            let mut buf: MaybeUninit<Termios> = MaybeUninit::uninit();
            // SAFETY: STDIN_FD is always valid; tcgetattr fills `*t` on success.
            let rc = unsafe { tcgetattr(STDIN_FD, buf.as_mut_ptr()) };
            if rc != 0 {
                return None;
            }
            // SAFETY: rc == 0 ⇒ Termios is fully initialised.
            let original = unsafe { buf.assume_init() };
            let mut modified = original;
            modified.c_lflag &= !(ECHO | ICANON | ISIG);
            modified.c_iflag &= !(ICRNL | IXON);
            // VMIN=1 / VTIME=1 (×0.1s): block for first byte, 100ms for CSI follow-ons.
            modified.c_cc[VMIN] = 1;
            modified.c_cc[VTIME] = 1;
            // SAFETY: `modified` is fully initialised; tcsetattr reads it.
            let rc = unsafe { tcsetattr(STDIN_FD, TCSANOW, &raw const modified) };
            if rc != 0 {
                return None;
            }
            Some(RawModeGuard { original })
        }

        pub fn set_read_timeout(vmin: u8, vtime: u8) {
            let mut buf: MaybeUninit<Termios> = MaybeUninit::uninit();
            // SAFETY: STDIN_FD valid; tcgetattr fills *t on success.
            let rc = unsafe { tcgetattr(STDIN_FD, buf.as_mut_ptr()) };
            if rc != 0 {
                return;
            }
            // SAFETY: rc == 0 ⇒ Termios is fully initialised.
            let mut current = unsafe { buf.assume_init() };
            current.c_cc[VMIN] = vmin;
            current.c_cc[VTIME] = vtime;
            // SAFETY: `current` is fully initialised; tcsetattr reads it.
            let _ = unsafe { tcsetattr(STDIN_FD, TCSANOW, &raw const current) };
        }

        pub fn terminal_width() -> Option<u16> {
            let mut ws = MaybeUninit::<WinSize>::uninit();
            // SAFETY: STDIN_FD valid. TIOCGWINSZ expects a pointer to a 8-byte
            // `struct winsize`; `WinSize` matches that layout. ioctl writes the full
            // struct on success and leaves it untouched on failure.
            let rc = unsafe { ioctl(STDIN_FD, TIOCGWINSZ, ws.as_mut_ptr()) };
            if rc != 0 {
                return None;
            }
            // SAFETY: rc == 0 ⇒ WinSize is fully initialised.
            let ws = unsafe { ws.assume_init() };
            if ws.ws_col == 0 {
                None
            } else {
                Some(ws.ws_col)
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[allow(unreachable_pub)]
    mod platform {
        use core::ffi::c_int;
        use core::mem::MaybeUninit;

        /// Linux asm-generic `struct termios` (x86_64, aarch64, arm, riscv64):
        /// `tcflag_t` is 4-byte `unsigned int`, `cc_t` is `unsigned char`, `NCCS == 32`,
        /// plus the `c_line` byte that Darwin lacks. MIPS/SPARC/Alpha/PowerPC differ —
        /// the size assertion below will fail there and force an arch-specific port.
        #[repr(C)]
        #[derive(Clone, Copy)]
        #[allow(clippy::struct_field_names)]
        struct Termios {
            c_iflag: u32,
            c_oflag: u32,
            c_cflag: u32,
            c_lflag: u32,
            c_line: u8,
            c_cc: [u8; 32],
            c_ispeed: u32,
            c_ospeed: u32,
        }
        const _: () = assert!(core::mem::size_of::<Termios>() == 60);

        #[repr(C)]
        #[derive(Debug, Clone, Copy)]
        #[allow(clippy::struct_field_names)]
        struct WinSize {
            ws_row: u16,
            ws_col: u16,
            ws_xpixel: u16,
            ws_ypixel: u16,
        }
        const _: () = assert!(core::mem::size_of::<WinSize>() == 8);

        unsafe extern "C" {
            fn tcgetattr(fd: c_int, t: *mut Termios) -> c_int;
            fn tcsetattr(fd: c_int, action: c_int, t: *const Termios) -> c_int;
            // POSIX variadic. `request` is `unsigned long` on Linux; `u64` matches on
            // LP64 (x86_64/aarch64/riscv64) and is harmlessly wider on 32-bit arm/x86
            // (kernel ignores upper bits). Keeps the signature uniform with macOS.
            fn ioctl(fd: c_int, request: u64, ...) -> c_int;
        }

        /// Linux asm-generic `TIOCGWINSZ` = `0x5413`.
        const TIOCGWINSZ: u64 = 0x5413;
        const STDIN_FD: c_int = 0;
        const TCSANOW: c_int = 0;
        const ECHO: u32 = 0x0000_0008;
        const ICANON: u32 = 0x0000_0002;
        const ISIG: u32 = 0x0000_0001;
        const ICRNL: u32 = 0x0000_0100;
        const IXON: u32 = 0x0000_0400;
        const VMIN: usize = 6;
        const VTIME: usize = 5;

        pub struct RawModeGuard {
            original: Termios,
        }

        impl Drop for RawModeGuard {
            fn drop(&mut self) {
                // SAFETY: STDIN_FD always valid; `original` was populated by tcgetattr
                // before this guard existed; tcsetattr only reads through `*const`.
                unsafe {
                    tcsetattr(STDIN_FD, TCSANOW, &raw const self.original);
                }
            }
        }

        pub fn enter_full_raw() -> Option<RawModeGuard> {
            let mut buf: MaybeUninit<Termios> = MaybeUninit::uninit();
            // SAFETY: STDIN_FD valid; tcgetattr fills *t on success.
            let rc = unsafe { tcgetattr(STDIN_FD, buf.as_mut_ptr()) };
            if rc != 0 {
                return None;
            }
            // SAFETY: rc == 0 ⇒ Termios is fully initialised.
            let original = unsafe { buf.assume_init() };
            let mut modified = original;
            modified.c_lflag &= !(ECHO | ICANON | ISIG);
            modified.c_iflag &= !(ICRNL | IXON);
            modified.c_cc[VMIN] = 1;
            modified.c_cc[VTIME] = 1;
            // SAFETY: `modified` is fully initialised; tcsetattr reads it.
            let rc = unsafe { tcsetattr(STDIN_FD, TCSANOW, &raw const modified) };
            if rc != 0 {
                return None;
            }
            Some(RawModeGuard { original })
        }

        pub fn set_read_timeout(vmin: u8, vtime: u8) {
            let mut buf: MaybeUninit<Termios> = MaybeUninit::uninit();
            // SAFETY: STDIN_FD valid; tcgetattr fills *t on success.
            let rc = unsafe { tcgetattr(STDIN_FD, buf.as_mut_ptr()) };
            if rc != 0 {
                return;
            }
            // SAFETY: rc == 0 ⇒ Termios is fully initialised.
            let mut current = unsafe { buf.assume_init() };
            current.c_cc[VMIN] = vmin;
            current.c_cc[VTIME] = vtime;
            // SAFETY: `current` is fully initialised; tcsetattr reads it.
            let _ = unsafe { tcsetattr(STDIN_FD, TCSANOW, &raw const current) };
        }

        pub fn terminal_width() -> Option<u16> {
            let mut ws = MaybeUninit::<WinSize>::uninit();
            // SAFETY: STDIN_FD valid; TIOCGWINSZ writes the 8-byte WinSize on success.
            let rc = unsafe { ioctl(STDIN_FD, TIOCGWINSZ, ws.as_mut_ptr()) };
            if rc != 0 {
                return None;
            }
            // SAFETY: rc == 0 ⇒ WinSize is fully initialised.
            let ws = unsafe { ws.assume_init() };
            if ws.ws_col == 0 {
                None
            } else {
                Some(ws.ws_col)
            }
        }
    }

    /// No-op fallback for unported targets (Windows, BSDs); TUI degrades to canonical input.
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[allow(unreachable_pub)]
    mod platform {
        pub struct RawModeGuard;

        impl Drop for RawModeGuard {
            fn drop(&mut self) {}
        }

        pub fn enter_full_raw() -> Option<RawModeGuard> {
            None
        }
        pub fn set_read_timeout(_vmin: u8, _vtime: u8) {}
        pub fn terminal_width() -> Option<u16> {
            None
        }
    }

    pub(crate) use platform::{enter_full_raw, set_read_timeout, terminal_width, RawModeGuard};
}
