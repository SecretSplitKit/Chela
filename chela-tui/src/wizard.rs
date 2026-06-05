//! Split and recover wizards. Line-based prompts; each major step gets its own screen.

// Sequential UI flow; splitting these up would scatter the conversation across the file.
#![allow(clippy::too_many_lines)]

use std::fmt::Write as _;
use std::io;

use chela_engine::{
    recover_secret, split_secret, OutputMode, RecoveredSecret, Share, SplitInput, MAX_SHARES,
    MIN_THRESHOLD,
};
use chela_share::{
    extract_shares_from_html, extract_shares_from_json, parse_share, parse_shares, FormatError,
};

use crate::term::{
    banner, error, info, prompt, prompt_line_or_default, prompt_line_prefilled, prompt_nonempty,
    prompt_u8_in_range, read_secret, sanitize_for_terminal, select, success, warn,
    SecretReadCancel, SecretString, BOLD, BRIGHT_CYAN, CYAN, DIM, GREEN, RED, RESET, REVERSE,
};

// v2 caps the set at 32 shares (5-bit x field). Min = 2; 1-of-N is just N copies of the secret.
const MAX_THRESHOLD: u8 = MAX_SHARES;

#[derive(Debug, Clone, Copy)]
pub(crate) enum SplitKind {
    Bip39,
    Text,
}

pub(crate) fn run_split(kind: SplitKind) -> io::Result<()> {
    let (title, what) = match kind {
        SplitKind::Bip39 => ("chela — Split a BIP-39 seed", "BIP-39 seed"),
        SplitKind::Text => ("chela — Split a text password", "password"),
    };

    // Setup-screen count, plus N once we know it. BIP-39 has the extra passphrase screen.
    let setup_steps: u32 = match kind {
        SplitKind::Bip39 => 7, // mnemonic, passphrase, M+N form, name, names?, note, confirm
        SplitKind::Text => 6,  // text, M+N form, name, names?, note, confirm
    };

    let mut step: u32 = 1;
    let mnemonic: Option<SecretString>;
    let passphrase: SecretString;
    let text: Option<SecretString>;
    match kind {
        SplitKind::Bip39 => {
            banner(title);
            step_header(step, None, "Enter Your BIP-39 Mnemonic");
            println!();
            println!("Paste the mnemonic on one line (12, 15, 18, 21, or 24 words):");
            let Some(m) = prompt_nonempty("mnemonic ❯ ")? else {
                return Ok(());
            };
            let words: Vec<&str> = m.split_whitespace().collect();
            if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
                error(&format!(
                    "Expected 12/15/18/21/24 words, got {}. Press Enter to retry from the menu.",
                    words.len()
                ));
                let _ = prompt("❯ ")?;
                return Ok(());
            }
            for w in &words {
                if chela_bip39::word_to_index(w).is_none() {
                    error(&format!(
                        "Word {w:?} is not in the BIP-39 wordlist. Press Enter to return."
                    ));
                    let _ = prompt("❯ ")?;
                    return Ok(());
                }
            }
            mnemonic = Some(SecretString::new(m));
            step += 1;

            banner(title);
            step_header(step, None, "Enter the BIP-39 Passphrase");
            println!();
            println!("BIP-39 wallets optionally combine the mnemonic with a passphrase to");
            println!("derive a different seed. If your wallet uses one, enter it now. If");
            println!("not, leave it blank.");
            info(
                "Input will be masked. Press Tab to reveal, Tab again to re-mask; Escape cancels.",
            );
            passphrase = match read_secret("passphrase ❯ ")? {
                Ok(p) => p,
                Err(SecretReadCancel::UserCancelled) => return Ok(()),
                Err(SecretReadCancel::NoMaskedInput) => {
                    return refuse_unmasked_input();
                }
            };
            text = None;
            step += 1;
        }
        SplitKind::Text => {
            banner(title);
            step_header(step, None, "Enter the Text to Split");
            println!();
            println!("Up to 255 characters; UTF-8 is supported.");
            info(
                "Input will be masked. Press Tab to reveal, Tab again to re-mask; Escape cancels.",
            );
            let t = match read_secret("text ❯ ")? {
                Ok(s) => s,
                Err(SecretReadCancel::UserCancelled) => return Ok(()),
                Err(SecretReadCancel::NoMaskedInput) => {
                    return refuse_unmasked_input();
                }
            };
            if t.as_str().is_empty() {
                error("Empty input. Press Enter to return.");
                let _ = prompt("❯ ")?;
                return Ok(());
            }
            if t.as_str().len() > 255 {
                error(
                    "Text is too long to fit on the share cards (limit is 255 characters; non-Latin scripts and emoji take more room). Press Enter to return.",
                );
                let _ = prompt("❯ ")?;
                return Ok(());
            }
            mnemonic = None;
            passphrase = SecretString::default();
            text = Some(t);
            step += 1;
        }
    }

    banner(title);
    step_header(step, None, "Give This Backup a Name");
    println!();
    println!("A short name lets recipients see what this card is for at a glance");
    println!("(e.g. \"Alice's Ethereum wallet\" or \"Family password manager\").");
    info("Press Enter to skip — the cards will still work without a name.");
    let Some(name_raw) = prompt_line_or_default("name ❯ ", "")? else {
        return Ok(());
    };
    let backup_name: Option<String> = {
        let t = name_raw.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_owned())
        }
    };
    step += 1;

    banner(title);
    step_header(step, None, "Choose the Recovery Rule");
    println!();
    println!("Pick how many total shares to generate, and how many of them will be");
    println!("needed to recover the secret. Any smaller number reveals nothing.");
    println!();
    println!("{BOLD}Trade-offs:{RESET}");
    println!("  · {BOLD}More total shares{RESET} = more redundancy if a card is lost or");
    println!("    unreachable — but also more cards an attacker might find.");
    println!("  · {BOLD}Higher required-to-recover{RESET} = harder for an attacker who");
    println!("    finds some cards — but harder for legitimate recipients to coordinate.");
    println!("  · Required must be at least 2; a 1-of-N split just makes N copies.");
    println!();
    println!("{BOLD}Common configurations:{RESET}");
    println!("  2-of-3   — small family, simple coordination");
    println!("  3-of-5   — typical inheritance kit (tolerates 2 lost cards)");
    println!("  4-of-7   — wider distribution, more loss tolerance");
    println!("  5-of-9   — institutional / multi-jurisdiction setups");
    println!();
    let Some((total, threshold)) = pick_total_and_threshold_form()? else {
        return Ok(());
    };
    step += 1;

    banner(title);
    step_header(step, None, "Identify Each Shareholder on Their Card?");
    println!();
    println!("If you say yes, each printed share will list every shareholder by name");
    println!("with this card's recipient marked. That helps the recipients find each");
    println!("other later — without it, they may not know who else holds a card.");
    println!();
    println!("{BOLD}Trade-off:{RESET} a single recovered card now identifies every");
    println!("shareholder by name. The cryptographic payload still reveals nothing,");
    println!("but an attacker who finds one card learns who else to target for the");
    println!("remaining cards (physical, social-engineering, or coercion).");
    println!();
    println!("Mitigation: use first names only, or pseudonyms shared out of band");
    println!("with each recipient. If you say yes here, you'll be asked for each name");
    println!("in turn as you record the shares.");
    println!();
    let Some(name_choice) = select(
        &[
            "Yes — list every shareholder on each card",
            "No — keep cards anonymous",
        ],
        None,
    )?
    else {
        return Ok(());
    };
    let name_each_share = name_choice == 0;
    step += 1;

    banner(title);
    step_header(step, None, "Add a Note to Each Card");
    println!();
    println!("Write a short note that will appear at the top of every printed share.");
    println!("This is context for the recipient, not recovery instructions (the cards");
    println!("already include step-by-step instructions at the bottom).");
    println!();
    println!("{BOLD}Examples:{RESET}");
    println!(
        "  · {DIM}\"This is my Ethereum wallet seed phrase, ask Scott to help you recover it.\"{RESET}"
    );
    println!(
        "  · {DIM}\"Bitwarden master password; vault lives at https://vw.myserver.lol\"{RESET}"
    );
    println!(
        "  · {DIM}\"Backup for the family Bitcoin wallet — call Alice at (555) 123-4567 first.\"{RESET}"
    );
    println!();
    info("Type your note (Enter to commit; press Enter on empty for no note; Escape cancels).");
    let description: Option<String> = match prompt_line_prefilled("note ❯ ", "")? {
        Some(edited) => {
            let trimmed = edited.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(edited)
            }
        }
        None => return Ok(()),
    };
    step += 1;

    banner(title);
    step_header(step, None, "Confirm");
    println!();
    println!("{BRIGHT_CYAN}{BOLD}You are about to split your {what} into {total} shares.{RESET}");
    println!(
        "{BRIGHT_CYAN}{BOLD}Any {threshold} of them, combined later, will reconstruct the secret.{RESET}"
    );
    if let Some(name) = &backup_name {
        println!("{BRIGHT_CYAN}{BOLD}Backup name: {name}{RESET}");
    }
    if name_each_share {
        println!();
        println!(
            "{BRIGHT_CYAN}{BOLD}You'll be asked for each shareholder's name as you record their card.{RESET}"
        );
    }
    println!();
    warn("After splitting, distribute one share to each shareholder.");
    warn("ANY single share alone reveals nothing about the secret.");
    println!();
    let Some(proceed_choice) = select(
        &[
            "Yes — split the secret now",
            "No — go back to the menu without splitting",
        ],
        None,
    )?
    else {
        return Ok(());
    };
    if proceed_choice != 0 {
        return Ok(());
    }
    step += 1;

    let input = match (mnemonic.as_ref(), text.as_ref()) {
        (Some(m), None) => SplitInput::Bip39 {
            mnemonic: m.as_str(),
            passphrase: passphrase.as_str(),
        },
        (None, Some(t)) => SplitInput::Text { text: t.as_str() },
        _ => unreachable!("collected above"),
    };
    let shares = match split_secret(&input, threshold, total, OutputMode::Bip39Wordlist) {
        Ok(s) => s,
        Err(e) => {
            error(&format!("Split failed: {e:?}. Press Enter to return."));
            let _ = prompt("❯ ")?;
            return Ok(());
        }
    };

    let record_total_steps = setup_steps + u32::from(total);
    let mut shareholder_names: Option<Vec<String>> = if name_each_share {
        Some(Vec::with_capacity(shares.len()))
    } else {
        None
    };
    for share in &shares {
        banner(title);
        step_header(
            step,
            Some(record_total_steps),
            &format!("Record Share {} of {}", share.x, shares.len()),
        );
        println!();

        // Ask for the holder before drawing the card so the on-screen label matches the
        // printed page.
        let this_name: Option<String> = if let Some(names) = shareholder_names.as_mut() {
            let prompt_msg = format!("Who gets share #{} of {}? name ❯ ", share.x, shares.len());
            let Some(raw) = prompt(&prompt_msg)? else {
                return Ok(());
            };
            let trimmed = raw.trim();
            let name = if trimmed.is_empty() {
                format!("Share {} holder", share.x)
            } else {
                trimmed.to_owned()
            };
            names.push(name.clone());
            println!();
            Some(name)
        } else {
            None
        };

        display_share(share);
        println!();
        if let Some(name) = &this_name {
            println!("Hand-write or print this share for {BOLD}{name}{RESET}.");
        } else {
            println!(
                "Hand-write or print this share for shareholder #{}.",
                share.x
            );
        }
        println!();
        let prompt_msg = if step < record_total_steps {
            "Press Enter once you've recorded this share to see the next one: "
        } else {
            "Press Enter once you've recorded the last share: "
        };
        let Some(_) = prompt(prompt_msg)? else {
            return Ok(());
        };
        step += 1;
    }

    banner(title);
    success("All shares generated.");
    println!();
    info(
        "Before you destroy the original secret, run the recover flow on a threshold of shares to verify.",
    );
    println!();

    println!();
    println!("{BOLD}What would you like to save to this computer?{RESET}");
    println!();
    println!("Two formats are available — pick whichever suits how you plan to recover:");
    println!();
    println!("  {BOLD}HTML cards{RESET}    — one printable page per share. Open in a browser,");
    println!("                  Print → Save as PDF, then print to paper.");
    println!("  {BOLD}JSON files{RESET}    — one structured `.share.json` per share + a combined");
    println!("                  bundle. For machine-readable backup or programmatic recovery.");
    println!();
    let Some(save_choice) = select(
        &[
            "Both — printable HTML cards AND machine-readable JSON files",
            "HTML cards only (printable)",
            "JSON files only (machine-readable)",
            "Nothing — I've recorded the shares by hand",
        ],
        None,
    )?
    else {
        return Ok(());
    };
    let want_html = matches!(save_choice, 0 | 1);
    let want_json = matches!(save_choice, 0 | 2);
    if want_html || want_json {
        let id_hex = format!("{:04X}", shares[0].nonce & 0x7FF);
        let default_dir = format!("~/chela-backup-{id_hex}");
        println!();
        println!("Where to save the folder?");
        info("Edit the path below (Backspace + typing); Enter to commit, Escape to cancel.");
        let Some(raw_path) = prompt_line_prefilled("folder ❯ ", &default_dir)? else {
            info("Backup save cancelled.");
            println!();
            // Shares are already generated/recorded — still show completion.
            return match wait_for_exit_or_menu()? {
                AfterComplete::Menu => Ok(()),
                AfterComplete::Exit => {
                    drop(shares); // wipe share material (Share's Drop) before exiting
                    std::process::exit(0);
                }
            };
        };
        let trimmed = raw_path.trim();
        if !trimmed.is_empty() {
            let dir = expand_home(trimmed);
            let meta = chela_share::BackupMeta {
                backup_name: backup_name.as_deref(),
                description: description.as_deref(),
                shareholder_names: shareholder_names.as_deref(),
            };

            if want_html {
                let folder = chela_share::render_paper_folder(&shares, &meta);
                match write_paper_folder(&dir, &folder) {
                    Ok(()) => {
                        success(&format!(
                            "Wrote {} HTML file(s) + README to {dir}.",
                            folder.shares.len(),
                        ));
                        info("Open each share-N.html in a browser and choose Print → Save as PDF.");
                    }
                    Err(e) => error(&format!("Couldn't write HTML folder: {e}")),
                }
            }

            if want_json {
                let folder = chela_share::render_json_folder(&shares, &meta);
                match write_json_folder(&dir, &folder) {
                    Ok(()) => {
                        success(&format!(
                            "Wrote {} JSON share file(s) + {} bundle to {dir}.",
                            folder.shares.len(),
                            folder.bundle.0,
                        ));
                        info("Recipients can import these files via `chela-cli recover share-N.share.json` or the web UI's \"Choose HTML files\" picker.");
                    }
                    Err(e) => error(&format!("Couldn't write JSON folder: {e}")),
                }
            }
            println!();
        }
    }

    match wait_for_exit_or_menu()? {
        AfterComplete::Menu => Ok(()),
        AfterComplete::Exit => {
            drop(shares); // wipe share material (Share's Drop) before exiting
            std::process::exit(0);
        }
    }
}

/// Bail out when `read_secret` reports no masked input is available; we never fall
/// back to an echoed prompt for a secret.
fn refuse_unmasked_input() -> io::Result<()> {
    error(
        "Cannot put this terminal into masked-input mode (is this a real interactive terminal?).",
    );
    error("Refusing to read the secret in cleartext. Aborting.");
    let _ = prompt("Press Enter to return to the menu. ")?;
    Ok(())
}

/// What [`wait_for_exit_or_menu`] decided: return to the menu, or exit chela.
enum AfterComplete {
    Menu,
    Exit,
}

/// End-of-flow choice: Enter returns to the menu, Esc/Ctrl-C/EOF exits chela. Returns the
/// choice rather than calling `process::exit` itself, so the caller can wipe secrets and
/// drop terminal guards before the process ends (`process::exit` runs no destructors).
fn wait_for_exit_or_menu() -> io::Result<AfterComplete> {
    println!();
    for line in COMPLETE_BANNER.lines() {
        println!("  {GREEN}{BOLD}{line}{RESET}");
    }
    println!();
    println!("  {DIM}Press Enter to return to the menu, or Escape to exit chela.{RESET}");
    println!();

    // Raw mode lets us distinguish Enter / Esc / Ctrl-C from typed text; fall back to a
    // line-based prompt (Enter-only) when termios is unavailable.
    if let Some(_guard) = crate::term::raw_termios::enter_full_raw() {
        loop {
            match crate::screen::read_key()? {
                crate::screen::Key::Enter => return Ok(AfterComplete::Menu),
                crate::screen::Key::Escape
                | crate::screen::Key::CtrlC
                | crate::screen::Key::Eof => {
                    println!();
                    return Ok(AfterComplete::Exit);
                }
                _ => {}
            }
        }
    } else {
        let _ = prompt("❯ ")?;
        Ok(AfterComplete::Menu)
    }
}

/// Box-drawing "COMPLETE" banner shown at end of split/recover.
const COMPLETE_BANNER: &str = "\
╔═╗╔═╗╔╦╗╔═╗╦  ╔═╗╔╦╗╔═╗
║  ║ ║║║║╠═╝║  ║╣  ║ ║╣
╚═╝╚═╝╩ ╩╩  ╩═╝╚═╝ ╩ ╚═╝";

/// Two-field form for N (total) and M (threshold). Falls back to sequential prompts
/// when termios isn't available, keeping scripted/piped flows working.
fn pick_total_and_threshold_form() -> io::Result<Option<(u8, u8)>> {
    let Some(_guard) = crate::term::raw_termios::enter_full_raw() else {
        return pick_total_and_threshold_fallback();
    };
    raw_form_loop()
}

fn pick_total_and_threshold_fallback() -> io::Result<Option<(u8, u8)>> {
    let Some(total) = prompt_u8_in_range(
        "How many shares should I generate? (2-255) ❯ ",
        MIN_THRESHOLD,
        MAX_THRESHOLD,
    )?
    else {
        return Ok(None);
    };
    let Some(threshold) = prompt_u8_in_range(
        &format!("How many shares are required to recover? (2-{total}) ❯ "),
        MIN_THRESHOLD,
        total,
    )?
    else {
        return Ok(None);
    };
    Ok(Some((total, threshold)))
}

/// Interactive loop for the two-field form. Caller owns the raw-mode guard.
#[allow(clippy::too_many_lines)]
fn raw_form_loop() -> io::Result<Option<(u8, u8)>> {
    use std::io::Write as _;
    let mut stdout = io::stdout();

    let mut total_buf = String::from("5");
    let mut threshold_buf = String::from("3");
    let mut focused: usize = 0; // 0 = total, 1 = threshold
    let mut error_msg: Option<String> = None;

    // None on first iteration; otherwise line count of the previous frame so we can
    // erase only the form region rather than the whole screen.
    let mut prev_lines: Option<usize> = None;

    loop {
        // CSI A move up · CR · CSI J erase to end of screen.
        if let Some(n) = prev_lines {
            write!(stdout, "\x1b[{n}A\r\x1b[J")?;
        }

        let frame = render_form_frame(&total_buf, &threshold_buf, focused, error_msg.as_deref());
        write!(stdout, "{frame}")?;
        stdout.flush()?;
        prev_lines = Some(frame.matches('\n').count());

        match crate::screen::read_key()? {
            crate::screen::Key::Tab => {
                focused = 1 - focused;
                error_msg = None;
            }
            crate::screen::Key::Backspace => {
                let buf = if focused == 0 {
                    &mut total_buf
                } else {
                    &mut threshold_buf
                };
                buf.pop();
                error_msg = None;
            }
            crate::screen::Key::Char(c) if c.is_ascii_digit() => {
                let buf = if focused == 0 {
                    &mut total_buf
                } else {
                    &mut threshold_buf
                };
                // u8 max is 255, so cap at 3 digits.
                if buf.len() < 3 {
                    buf.push(c);
                    error_msg = None;
                }
            }
            crate::screen::Key::Enter => {
                match (total_buf.parse::<u8>(), threshold_buf.parse::<u8>()) {
                    (Ok(t), Ok(m))
                        if (MIN_THRESHOLD..=MAX_THRESHOLD).contains(&t)
                            && (MIN_THRESHOLD..=t).contains(&m) =>
                    {
                        // Drop help/error lines from the final repaint for clean scrollback.
                        if let Some(n) = prev_lines {
                            write!(stdout, "\x1b[{n}A\r\x1b[J")?;
                        }
                        writeln!(stdout, "  Total shares: {BOLD}{t}{RESET}")?;
                        writeln!(stdout, "  Required to recover: {BOLD}{m}{RESET}")?;
                        writeln!(stdout)?;
                        stdout.flush()?;
                        return Ok(Some((t, m)));
                    }
                    _ => {
                        error_msg = Some(format!(
                            "Total must be {MIN_THRESHOLD}-{MAX_THRESHOLD}; required must be {MIN_THRESHOLD}-(total). You entered total={total_buf:?}, required={threshold_buf:?}."
                        ));
                    }
                }
            }
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

fn render_form_frame(total: &str, threshold: &str, focused: usize, error: Option<&str>) -> String {
    let mut out = String::with_capacity(512);

    let thresh_upper_hint = total
        .parse::<u8>()
        .ok()
        .filter(|n| (MIN_THRESHOLD..=MAX_THRESHOLD).contains(n))
        .map_or_else(|| String::from("?"), |n| n.to_string());

    let total_chip = render_field_chip(total, focused == 0);
    let thresh_chip = render_field_chip(threshold, focused == 1);
    let total_caret = if focused == 0 {
        format!("{BRIGHT_CYAN}{BOLD}❯{RESET}")
    } else {
        " ".to_owned()
    };
    let thresh_caret = if focused == 1 {
        format!("{BRIGHT_CYAN}{BOLD}❯{RESET}")
    } else {
        " ".to_owned()
    };

    let _ = writeln!(
        out,
        "  {total_caret} {BOLD}{:<24}{RESET} ({DIM}{}-{}{RESET})  {total_chip}",
        "Total shares", MIN_THRESHOLD, MAX_THRESHOLD,
    );
    let _ = writeln!(
        out,
        "  {thresh_caret} {BOLD}{:<24}{RESET} ({DIM}{}-{}{RESET})  {thresh_chip}",
        "Required to recover", MIN_THRESHOLD, thresh_upper_hint,
    );
    out.push('\n');
    let _ = writeln!(
        out,
        "  {DIM}[Tab] switch field   [Enter] continue   [Esc] cancel{RESET}",
    );
    if let Some(e) = error {
        let _ = writeln!(out, "  {RED}✗  {e}{RESET}");
    }
    out
}

fn render_field_chip(value: &str, focused: bool) -> String {
    if focused {
        format!("{REVERSE}{BOLD} {value}_ {RESET}")
    } else {
        format!(" {value} ")
    }
}

/// Print a `"Step N [of M]: <action>"` header. `total = None` during setup, before N is known.
fn step_header(step: u32, total: Option<u32>, action: &str) {
    let prefix = match total {
        Some(t) => format!("Step {step} of {t}:"),
        None => format!("Step {step}:"),
    };
    println!("{DIM}{prefix}{RESET} {BRIGHT_CYAN}{BOLD}{action}{RESET}");
}

/// Write a `PaperFolder` to `dir`, creating the directory if needed.
fn write_paper_folder(dir: &str, folder: &chela_share::PaperFolder) -> io::Result<()> {
    let path = std::path::Path::new(dir);
    std::fs::create_dir_all(path)?;
    write_private(path.join("README.txt"), &folder.readme)?;
    for (filename, contents) in &folder.shares {
        write_private(path.join(filename), contents)?;
    }
    Ok(())
}

fn write_json_folder(dir: &str, folder: &chela_share::JsonFolder) -> io::Result<()> {
    let path = std::path::Path::new(dir);
    std::fs::create_dir_all(path)?;
    write_private(path.join(&folder.bundle.0), &folder.bundle.1)?;
    for (filename, contents) in &folder.shares {
        write_private(path.join(filename), contents)?;
    }
    Ok(())
}

fn expand_home(p: &str) -> String {
    if let Some(stripped) = p.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            let mut out = home.to_string_lossy().into_owned();
            out.push('/');
            out.push_str(stripped);
            return out;
        }
    }
    p.to_owned()
}

/// Write `contents` to `path` with owner-only (0600) permissions on Unix, so share
/// material doesn't land world-readable at the default umask. Other platforms use the
/// filesystem default.
fn write_private(path: impl AsRef<std::path::Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let path = path.as_ref();
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents.as_ref())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents.as_ref())
    }
}

fn display_share(share: &Share) {
    let word_count = share.word_indices.len();
    let header = format!(
        "CHELA-{:04X}-{}-{}-{}-{}",
        share.nonce & 0x7FF,
        share.x,
        share.threshold,
        share.total.unwrap_or(0),
        word_count,
    );
    // Top rail IS the parseable header: what's shown = what gets typed back at recovery.
    let pad = 67usize.saturating_sub(header.len() + 4);
    println!(
        "{BOLD}{CYAN}┏━ {header} {}{RESET}",
        "━".repeat(pad).as_str(),
    );
    println!();
    let words: Vec<&str> = share
        .word_indices
        .iter()
        .map(|&i| chela_bip39::index_to_word(i).expect("valid index"))
        .collect();
    let columns = 4;
    for (row_start, chunk) in words.chunks(columns).enumerate() {
        let mut line = String::new();
        for (col, w) in chunk.iter().enumerate() {
            let n = row_start * columns + col + 1;
            write!(line, "{DIM}{n:>3}.{RESET} {BOLD}{w:<10}{RESET} ").expect("string write");
        }
        println!("  {line}");
    }
    println!();
    println!(
        "{BOLD}{CYAN}┗━ {word_count} words ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}",
    );
}

pub(crate) fn run_recover() -> io::Result<()> {
    banner("chela — Recover from shares");
    println!("How would you like to enter the shares?");
    println!();
    let Some(input_mode) = select(
        &[
            "Import HTML files saved on this computer",
            "Type each card by hand from the printed paper",
        ],
        None,
    )?
    else {
        return Ok(());
    };

    let mut shares: Vec<Share> = Vec::new();
    // First share establishes set ID / threshold / total / word count; later shares only
    // need the new card's `x`.
    let mut expected: Option<ParsedHeader> = None;

    if input_mode == 0 {
        // Import phase — load shares from HTML files first, then fall through
        // to the manual loop if we still need more cards.
        match import_html_phase()? {
            Some(imported) => {
                if !imported.is_empty() {
                    expected = Some(parsed_header_from_share(&imported[0]));
                    shares = imported;
                }
            }
            None => return Ok(()),
        }
    }

    if input_mode == 1
        || expected
            .as_ref()
            .is_none_or(|e| shares.len() < usize::from(e.threshold))
    {
        banner("chela — Recover from shares");
        info("Enter each card by typing its card code, then its words one at a time.");
        println!();
        println!("The card code is the dashed line near the top of each card (e.g.");
        println!("CHELA-05DA-1-3-5-34) — it identifies the recovery set, which card this is,");
        println!("how many are needed, and how many words to expect. The wizard will then");
        println!("prompt for each word in turn.");
        println!();
        info(
            "While typing words: enter '<' to revise the previous word, or 'abort' to cancel this share.",
        );
        println!();
    }

    loop {
        // If imports alone already met the threshold, skip the prompting and proceed.
        if let Some(first) = expected {
            if shares.len() >= usize::from(first.threshold) {
                break;
            }
        }
        let (header_line, meta) = match expected {
            None => {
                let Some(raw) = prompt_nonempty("Card code from card #1: ")? else {
                    break;
                };
                let header_line = raw.trim().to_owned();
                match ParsedHeader::from_str(&header_line) {
                    Ok(m) => (header_line, m),
                    Err(e) => {
                        error(&format!(
                            "Card code didn't parse: {}. Expected CHELA-05DA-1-3-5-34 — recovery set, card #, required, total, word count.",
                            describe_format_error(&e),
                        ));
                        continue;
                    }
                }
            }
            Some(first) => {
                let need = usize::from(first.threshold);
                let have = shares.len();
                // The remaining-card list only makes sense when the total `N` is known;
                // a words-only set carries no total, so allow any x in 1..=32.
                let x_upper = first.total.unwrap_or(MAX_SHARES);
                if let Some(total) = first.total {
                    let remaining_display = (1..=total)
                        .filter(|n| !shares.iter().any(|s| s.x == *n))
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    info(&format!(
                        "Recovery set {:04X} · {have} of {need} cards entered — card numbers still available: {remaining_display}.",
                        first.nonce & 0x7FF,
                    ));
                } else {
                    info(&format!(
                        "Recovery set {:04X} · {have} of {need} cards entered.",
                        first.nonce & 0x7FF,
                    ));
                }
                let Some(x) = prompt_u8_in_range(
                    &format!("Card # printed on the next card (1-{x_upper}): "),
                    1,
                    x_upper,
                )?
                else {
                    break;
                };
                // parse_share re-validates the (header, words) pair end-to-end. `N` is
                // `?` when the set's total is unknown (words-only).
                let total = first.total.map_or_else(|| "?".into(), |n| n.to_string());
                let header_line = format!(
                    "CHELA-{:04X}-{}-{}-{}-{}",
                    first.nonce & 0x7FF,
                    x,
                    first.threshold,
                    total,
                    first.word_count,
                );
                (header_line, ParsedHeader { x, ..first })
            }
        };

        if shares.iter().any(|s| s.x == meta.x) {
            error(&format!(
                "Card #{} already entered. Pick another number.",
                meta.x,
            ));
            continue;
        }

        println!();
        let of_total = meta.total.map_or_else(String::new, |n| format!(" of {n}"));
        info(&format!(
            "Recovery set {:04X} · card {}{of_total} · {} required to recover · {} words.",
            meta.nonce & 0x7FF,
            meta.x,
            meta.threshold,
            meta.word_count,
        ));
        println!();

        let Some(words) = collect_words_interactive(meta.word_count)? else {
            warn("Cancelled this share.");
            continue;
        };

        let words_line = words.join(" ");
        match parse_share(&header_line, &words_line) {
            Ok(share) => {
                shares.push(share);
                if expected.is_none() {
                    expected = Some(meta);
                }
                let need = usize::from(meta.threshold);
                let have = shares.len();
                println!();
                if have >= need {
                    success(&format!(
                        "Share added. Have {have} of {need} — ready to recover."
                    ));
                } else {
                    success(&format!(
                        "Share added. Have {have} of {need} — need {} more.",
                        need - have,
                    ));
                }
                println!();
                if have >= need {
                    break;
                }
            }
            Err(e) => {
                error(&format!(
                    "Share didn't validate: {}. Try entering this share again.",
                    describe_format_error(&e),
                ));
            }
        }
    }

    if shares.is_empty() {
        warn("No shares entered. Returning to menu.");
        let _ = prompt("Press Enter to continue. ")?;
        return Ok(());
    }

    let mut recovered = match recover_secret(&shares) {
        Ok(r) => r,
        Err(e) => {
            error(&format!("Recovery failed: {e:?}"));
            let _ = prompt("Press Enter to return. ")?;
            return Ok(());
        }
    };

    banner("chela — Secret reconstructed");
    println!("Shares verified. The original secret has been reconstructed in memory.");
    println!();
    warn("Before revealing on screen, confirm nobody can see this terminal.");
    println!();
    let Some(reveal_choice) = select(
        &[
            "Yes — show me the recovered secret on this screen",
            "No — discard the result without showing it",
        ],
        None,
    )?
    else {
        return Ok(());
    };
    if reveal_choice != 0 {
        // User explicitly declined. Wipe the reconstructed secret before dropping.
        wipe_recovered(&mut recovered);
        success("Aborted without revealing. Clearing screen.");
        let _ = prompt("Press Enter to continue. ")?;
        crate::term::clear();
        return Ok(());
    }

    // Move the reveal to the alternate screen buffer so when we leave the buffer the
    // displayed secret is gone — nothing lands in the user's scrollback. Falls back
    // to the normal terminal with a best-effort scrollback wipe (`CSI 3J`) when
    // termios isn't available (Windows non-VT, dumb terminals).
    let alt_screen = crate::screen::Screen::enter();
    let in_alt_screen = alt_screen.is_some();
    if in_alt_screen {
        banner("chela — Recovered secret");
    } else {
        println!();
    }

    match &mut recovered {
        RecoveredSecret::Bip39 {
            mnemonic,
            passphrase,
        } => {
            // Mnemonic words come from the BIP-39 wordlist (ASCII-only by construction),
            // but the passphrase is arbitrary UTF-8 derived from attacker-influenceable
            // share bytes if any cards were forged — sanitize before display.
            let mnemonic_safe =
                chela_primitives::zeroize::Zeroizing::new(sanitize_for_terminal(mnemonic));
            println!("{BOLD}Kind:{RESET} BIP-39 mnemonic");
            println!("{BOLD}Mnemonic:{RESET}");
            println!("  {GREEN}{}{RESET}", *mnemonic_safe);
            println!();
            if passphrase.is_empty() {
                println!("{BOLD}Passphrase:{RESET} (none)");
            } else {
                let passphrase_safe =
                    chela_primitives::zeroize::Zeroizing::new(sanitize_for_terminal(passphrase));
                println!("{BOLD}Passphrase:{RESET}");
                println!("  {GREEN}{}{RESET}", *passphrase_safe);
            }
        }
        RecoveredSecret::Text { text } => {
            let text_safe = chela_primitives::zeroize::Zeroizing::new(sanitize_for_terminal(text));
            println!("{BOLD}Kind:{RESET} text");
            println!("{BOLD}Text:{RESET}");
            println!("  {GREEN}{}{RESET}", *text_safe);
        }
    }
    println!();
    info("Use the values above to recover access to the wallet or account.");
    let choice = wait_for_exit_or_menu()?;
    wipe_recovered(&mut recovered);

    // Drop the alt-screen guard first — that swaps back to the normal terminal
    // buffer with the secret display gone. If we never entered alt-screen, fall
    // back to wiping the visible screen and (best-effort) scrollback.
    drop(alt_screen);
    if !in_alt_screen {
        crate::term::clear_with_scrollback();
    }
    // Exit only after the secret is wiped and the terminal is restored above
    // (process::exit runs no destructors).
    if matches!(choice, AfterComplete::Exit) {
        std::process::exit(0);
    }
    Ok(())
}

/// Build a [`ParsedHeader`] from a fully-parsed [`Share`]. Used after import to
/// pre-populate the wizard's "expected" state so the manual-entry phase only
/// asks for the remaining card numbers.
fn parsed_header_from_share(share: &Share) -> ParsedHeader {
    ParsedHeader {
        nonce: share.nonce,
        x: share.x,
        threshold: share.threshold,
        total: share.total,
        word_count: share.word_indices.len(),
    }
}

/// Interactive sub-flow: prompt for HTML / text file paths one at a time,
/// parse each, accumulate shares.
///
/// Returns:
///   - `Ok(Some(vec))` — shares the user successfully loaded (possibly empty if
///     they finished without typing any paths; the caller still falls through
///     to manual entry in that case).
///   - `Ok(None)` — the user cancelled (Ctrl-D / Esc); the caller returns to
///     the main menu without recovering anything.
fn import_html_phase() -> io::Result<Option<Vec<Share>>> {
    info("Type the path to each chela paper-backup file (HTML or text), one per line.");
    info("Press Enter on an empty line when you're done. Tab-completion isn't available; paste full paths.");
    println!();

    let mut shares: Vec<Share> = Vec::new();
    let mut expected_first_share: Option<Share> = None;

    loop {
        let prompt_msg = if shares.is_empty() {
            "file path ❯ ".to_owned()
        } else {
            format!(
                "file path (or Enter to finish; have {} share(s)) ❯ ",
                shares.len()
            )
        };
        let Some(raw) = prompt(&prompt_msg)? else {
            // EOF / Ctrl-D — treat as cancel only if nothing was imported.
            return if shares.is_empty() {
                Ok(None)
            } else {
                Ok(Some(shares))
            };
        };
        let path = raw.trim();
        if path.is_empty() {
            return Ok(Some(shares));
        }

        let contents = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                error(&format!("Couldn't read {path}: {e}. Try another path."));
                continue;
            }
        };

        let from_file = match decode_file(&contents) {
            Ok(s) => s,
            Err(msg) => {
                error(&format!("{path}: {msg}. Try another file."));
                continue;
            }
        };

        if from_file.is_empty() {
            warn(&format!("{path}: no shares found in this file. Skipped."));
            continue;
        }

        // Sanity: every share in the batch (and across files) must agree on the
        // recovery set and threshold. `kind`/`total` are advisory `Option`s a
        // words-only share may omit, so they aren't part of the set identity.
        for s in &from_file {
            let bad = if let Some(first) = expected_first_share.as_ref() {
                first.nonce != s.nonce || first.scheme != s.scheme || first.threshold != s.threshold
            } else {
                false
            };
            if bad {
                error(&format!(
                    "{path}: share belongs to a different recovery set (set {:04X} vs the {:04X} we're recovering). Skipped this file.",
                    s.nonce & 0x7FF,
                    expected_first_share.as_ref().unwrap().nonce & 0x7FF,
                ));
                // Skip the whole file — don't partially import a mismatched set.
                continue;
            }
            if shares.iter().any(|existing| existing.x == s.x) {
                warn(&format!(
                    "{path}: card #{} already loaded — skipped duplicate.",
                    s.x,
                ));
                continue;
            }
            if expected_first_share.is_none() {
                expected_first_share = Some(s.clone());
            }
            let of_total = s.total.map_or_else(String::new, |n| format!(" of {n}"));
            success(&format!(
                "Imported card #{}{of_total} from set {:04X} ({} required).",
                s.x,
                s.nonce & 0x7FF,
                s.threshold,
            ));
            shares.push(s.clone());
        }

        if let Some(first) = expected_first_share.as_ref() {
            let need = usize::from(first.threshold);
            let have = shares.len();
            if have >= need {
                println!();
                success(&format!(
                    "Have {have} of {need} cards — enough to recover. (Add more files or press Enter to proceed.)"
                ));
            } else {
                println!();
                info(&format!(
                    "Have {have} of {need} cards from set {:04X}. Add another file, or press Enter to switch to typing the rest by hand.",
                    first.nonce & 0x7FF,
                ));
            }
        }
    }
}

/// Auto-detect HTML / JSON / share-text and decode accordingly. Mirrors
/// `chela-cli::read_one_file` — kept duplicated rather than shared because the
/// two binaries have very different error surfaces and the helper is tiny.
fn decode_file(contents: &str) -> Result<Vec<Share>, String> {
    let trimmed = contents.trim_start();
    let looks_html = contents.contains(r#"class="chela-share""#)
        || contents.contains("class='chela-share'")
        || trimmed.starts_with('<');
    if looks_html {
        let results = extract_shares_from_html(contents).map_err(|e| format!("{e}"))?;
        collect_strict(results, "block")
    } else if trimmed.starts_with('{') {
        let results = extract_shares_from_json(contents).map_err(|e| format!("{e}"))?;
        collect_strict(results, "share")
    } else {
        parse_shares(contents).map_err(|e| format!("doesn't look like chela share text: {e:?}"))
    }
}

fn collect_strict(
    results: Vec<Result<Share, chela_share::ImportError>>,
    label: &str,
) -> Result<Vec<Share>, String> {
    let mut out = Vec::with_capacity(results.len());
    for (idx, r) in results.into_iter().enumerate() {
        let share = r.map_err(|e| format!("{label} #{}: {e}", idx + 1))?;
        out.push(share);
    }
    Ok(out)
}

fn wipe_recovered(r: &mut RecoveredSecret) {
    use chela_primitives::zeroize::Zeroize;
    match r {
        RecoveredSecret::Bip39 {
            mnemonic,
            passphrase,
        } => {
            mnemonic.zeroize();
            passphrase.zeroize();
        }
        RecoveredSecret::Text { text } => text.zeroize(),
    }
}

fn describe_format_error(e: &FormatError) -> &'static str {
    match e {
        FormatError::BadHeader => "card code should look like CHELA-05DA-1-3-5-34",
        FormatError::BadIdentifier => "recovery set must be four hex digits (e.g. 05DA)",
        FormatError::BadThresholdTotal => {
            "required and total must be small whole numbers, and required cannot exceed total"
        }
        FormatError::BadShareIndex => "card # must be a whole number >= 1",
        FormatError::BadWordCount => "word count must be a whole number",
        FormatError::UnknownWord => "word not in the BIP-39 wordlist",
        FormatError::MissingWords => "card has no words on the second line",
        FormatError::WordCountMismatch => {
            "number of words doesn't match the word count in the card code"
        }
        FormatError::HeaderWordsMismatch => {
            "the card code doesn't match the words — check for a transcription error"
        }
        FormatError::ShareCorrupt => "the words failed their checksum — re-check each one",
    }
}

/// Parsed `CHELA-...` header without per-word data; lets us probe a card before
/// prompting for its words.
#[derive(Debug, Clone, Copy)]
struct ParsedHeader {
    nonce: u16,
    x: u8,
    threshold: u8,
    total: Option<u8>,
    word_count: usize,
}

impl ParsedHeader {
    fn from_str(s: &str) -> Result<Self, FormatError> {
        let upper = s
            .trim()
            .chars()
            .map(|c| c.to_ascii_uppercase())
            .collect::<String>();
        let body = upper.strip_prefix("CHELA-").ok_or(FormatError::BadHeader)?;
        let parts: Vec<&str> = body.split('-').collect();
        if parts.len() != 5 {
            return Err(FormatError::BadHeader);
        }
        // The nonce is 4 hex digits (11-bit value, high bits zero). `from_str_radix`
        // rejects non-ASCII before any byte-indexing, so no char-boundary panic.
        let nonce = u16::from_str_radix(parts[0], 16).map_err(|_| FormatError::BadIdentifier)?;
        let x: u8 = parts[1].parse().map_err(|_| FormatError::BadShareIndex)?;
        if x == 0 || x > MAX_SHARES {
            return Err(FormatError::BadShareIndex);
        }
        let threshold: u8 = parts[2]
            .parse()
            .map_err(|_| FormatError::BadThresholdTotal)?;
        if !(MIN_THRESHOLD..=MAX_SHARES).contains(&threshold) {
            return Err(FormatError::BadThresholdTotal);
        }
        // `N` is advisory and may be `?` (words-only / single-share). When present it
        // must be a real total: >= threshold and within the 32-share cap.
        let total: Option<u8> = if parts[3] == "?" {
            None
        } else {
            let n: u8 = parts[3]
                .parse()
                .map_err(|_| FormatError::BadThresholdTotal)?;
            if n < threshold || n > MAX_SHARES {
                return Err(FormatError::BadThresholdTotal);
            }
            if x > n {
                return Err(FormatError::BadShareIndex);
            }
            Some(n)
        };
        let word_count: usize = parts[4].parse().map_err(|_| FormatError::BadWordCount)?;
        if word_count == 0 {
            return Err(FormatError::BadWordCount);
        }
        Ok(Self {
            nonce,
            x,
            threshold,
            total,
            word_count,
        })
    }
}

/// Prompt for `n` BIP-39 words. `<` / `back` revises the previous word, `abort` /
/// EOF cancels the share.
fn collect_words_interactive(n: usize) -> io::Result<Option<Vec<String>>> {
    let mut words: Vec<String> = Vec::with_capacity(n);
    while words.len() < n {
        let i = words.len() + 1;
        let prompt_msg = format!("  word {i:>2} of {n}: ");
        let Some(raw) = prompt(&prompt_msg)? else {
            return Ok(None);
        };
        let w = raw.trim();
        match w {
            "abort" => return Ok(None),
            "<" | "back" => {
                if words.pop().is_some() {
                    info("(stepped back; re-enter the previous word)");
                } else {
                    warn("Already at the first word.");
                }
            }
            "" => {
                warn("Please type the word, or '<' to revise the previous word.");
            }
            other => {
                if chela_bip39::word_to_index(other).is_some() {
                    words.push(other.to_owned());
                } else {
                    warn(&format!(
                        "{other:?} isn't in the BIP-39 wordlist. Try again (or '<' to revise).",
                    ));
                }
            }
        }
    }
    Ok(Some(words))
}
