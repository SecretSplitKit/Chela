//! chela TUI entry point. See AGENTS.md D10 for the raw-menu / line-wizard split.

// The only opt-in to `unsafe` is `term::raw_termios` (termios FFI).
#![deny(unsafe_code)]

use std::process::ExitCode;

mod screen;
mod term;
mod wizard;

use screen::{read_key, Key, Screen};
use term::{banner, prompt, BOLD, CYAN, DIM, RESET, REVERSE};
use wizard::{run_recover, run_split, SplitKind};

fn main() -> ExitCode {
    loop {
        match main_menu() {
            Ok(MenuChoice::SplitBip39) => {
                if let Err(e) = run_split(SplitKind::Bip39) {
                    eprintln!("chela: I/O error: {e}");
                    return ExitCode::from(1);
                }
            }
            Ok(MenuChoice::SplitText) => {
                if let Err(e) = run_split(SplitKind::Text) {
                    eprintln!("chela: I/O error: {e}");
                    return ExitCode::from(1);
                }
            }
            Ok(MenuChoice::Recover) => {
                if let Err(e) = run_recover() {
                    eprintln!("chela: I/O error: {e}");
                    return ExitCode::from(1);
                }
            }
            Ok(MenuChoice::Quit) => return ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("chela: I/O error: {e}");
                return ExitCode::from(1);
            }
        }
    }
}

enum MenuChoice {
    SplitBip39,
    SplitText,
    Recover,
    Quit,
}

struct MenuItem {
    key_hint: char,
    label: &'static str,
    color: &'static str,
    choice: MenuChoice,
}

fn menu_items() -> Vec<MenuItem> {
    vec![
        MenuItem {
            key_hint: '1',
            label: "Split a BIP-39 seed (with optional passphrase)",
            color: CYAN,
            choice: MenuChoice::SplitBip39,
        },
        MenuItem {
            key_hint: '2',
            label: "Split a text password",
            color: CYAN,
            choice: MenuChoice::SplitText,
        },
        MenuItem {
            key_hint: '3',
            label: "Recover from a threshold of shares",
            color: CYAN,
            choice: MenuChoice::Recover,
        },
        MenuItem {
            key_hint: 'q',
            label: "Quit",
            color: DIM,
            choice: MenuChoice::Quit,
        },
    ]
}

fn main_menu() -> std::io::Result<MenuChoice> {
    if let Some(screen) = Screen::enter() {
        return main_menu_raw(&screen);
    }
    main_menu_line()
}

fn main_menu_raw(screen: &Screen) -> std::io::Result<MenuChoice> {
    let items = menu_items();
    let mut cursor: usize = 0;
    loop {
        draw_menu(screen, &items, cursor);
        match read_key()? {
            Key::Up => {
                if cursor == 0 {
                    cursor = items.len() - 1;
                } else {
                    cursor -= 1;
                }
            }
            Key::Down => {
                cursor = (cursor + 1) % items.len();
            }
            Key::Enter => {
                return Ok(consume(items, cursor));
            }
            Key::Char(c) => {
                let c = c.to_ascii_lowercase();
                if let Some(idx) = items.iter().position(|it| it.key_hint == c) {
                    return Ok(consume(items, idx));
                }
                if c == 'q' || c == 'x' {
                    return Ok(MenuChoice::Quit);
                }
            }
            Key::Escape | Key::CtrlC | Key::Eof => return Ok(MenuChoice::Quit),
            _ => {}
        }
    }
}

fn consume(mut items: Vec<MenuItem>, idx: usize) -> MenuChoice {
    items.swap_remove(idx).choice
}

fn draw_menu(screen: &Screen, items: &[MenuItem], cursor: usize) {
    screen.clear();
    let title = "chela — Shamir's Secret Sharing for inheritance & recovery";
    screen.write_at(
        2,
        4,
        &format!(
            "{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════╗{RESET}"
        ),
    );
    screen.write_at(
        3,
        4,
        &format!("{BOLD}{CYAN}║{RESET} {BOLD}{title:<61}{RESET} {BOLD}{CYAN}║{RESET}"),
    );
    screen.write_at(
        4,
        4,
        &format!(
            "{BOLD}{CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}"
        ),
    );

    for (i, item) in items.iter().enumerate() {
        let row = u16::try_from(6 + i).unwrap_or(u16::MAX);
        let selected = i == cursor;
        if selected {
            screen.write_at(
                row,
                6,
                &format!(
                    "{BOLD}{}{RESET} {REVERSE}{BOLD} {}) {}  {} {RESET}",
                    "▶", item.key_hint, item.color, item.label,
                ),
            );
        } else {
            screen.write_at(
                row,
                6,
                &format!("  {DIM}{}){RESET}  {}", item.key_hint, item.label,),
            );
        }
    }

    let hint_row = u16::try_from(8 + items.len()).unwrap_or(u16::MAX);
    screen.write_at(
        hint_row,
        4,
        &format!("{DIM}↑/↓ to move · Enter to choose · 1/2/3 or q for direct picks · Esc/Ctrl-C to quit{RESET}"),
    );
}

/// Fallback when raw mode is unavailable.
fn main_menu_line() -> std::io::Result<MenuChoice> {
    loop {
        banner("chela — Shamir's Secret Sharing for inheritance & recovery");
        println!("  {BOLD}1){RESET} Split a {CYAN}BIP-39 seed{RESET} (with optional passphrase) into shares");
        println!("  {BOLD}2){RESET} Split a {CYAN}text password{RESET} into shares");
        println!("  {BOLD}3){RESET} {CYAN}Recover{RESET} from a threshold of shares");
        println!("  {BOLD}q){RESET} Quit");
        println!();
        println!("{DIM}Type your choice and press Enter.{RESET}");
        println!();
        let Some(line) = prompt("Choice: ")? else {
            return Ok(MenuChoice::Quit);
        };
        match line.trim().to_ascii_lowercase().as_str() {
            "1" => return Ok(MenuChoice::SplitBip39),
            "2" => return Ok(MenuChoice::SplitText),
            "3" => return Ok(MenuChoice::Recover),
            "q" | "quit" | "exit" => return Ok(MenuChoice::Quit),
            _ => {}
        }
    }
}
