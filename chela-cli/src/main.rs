//! chela CLI entry point. Hand-rolled arg parsing; see `print_usage` for the full surface.

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use chela_engine::{
    recover_secret, split_secret, EngineError, OutputMode, RecoveredSecret, SplitInput,
};
use chela_share::{
    extract_shares_from_html, extract_shares_from_json, format_share, parse_share_words,
    parse_shares, render_json_folder, render_paper_folder, render_paper_html, render_shares_json,
    BackupMeta, ImportError, JsonFolder, PaperFolder,
};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let result = match cmd.as_str() {
        "split" => cmd_split(args.collect()),
        "recover" => cmd_recover(&args.collect::<Vec<_>>()),
        "-h" | "--help" | "" => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("chela: unknown command {other:?}");
            print_usage();
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("chela: error: {msg}");
            ExitCode::from(1)
        }
    }
}

fn print_usage() {
    let exe = env!("CARGO_BIN_NAME");
    println!("chela — Shamir's Secret Sharing for BIP-39 seeds and short passwords");
    println!();
    println!("USAGE:");
    println!("  {exe} split    --mnemonic \"<12-24 words>\" [--passphrase \"...\"] -m N -n M [paper flags]");
    println!("  {exe} split    --text \"<utf-8 text up to 255 bytes>\" -m N -n M [paper flags]");
    println!("  {exe} recover                                  # reads share text from stdin");
    println!(
        "  {exe} recover  share-1.html share-2.html ...   # imports from chela paper-backup HTML"
    );
    println!();
    println!("OUTPUT FLAGS (any combination; can be used together):");
    println!("  --paper FILE              Write a combined HTML backup (one page per share).");
    println!("  --paper-dir DIR           Write a folder of one HTML file per share plus README.");
    println!("  --json FILE               Write a single chela.shares.v1 JSON bundle.");
    println!(
        "  --json-dir DIR            Write a folder of one chela.share.v1 JSON file per share"
    );
    println!(
        "                            (filename: share-<x>.share.json) plus the combined bundle."
    );
    println!();
    println!("PAPER METADATA (apply to both HTML cards and JSON output):");
    println!("  --name \"TEXT\"             Title rendered at the top of each card.");
    println!("  --description \"TEXT\"      Free-form note rendered at the top of each card.");
    println!("  --shareholders \"A,B,...\"  Comma-separated names (must equal N) listed on every");
    println!("                            card with the recipient marked. Trade-off: one card");
    println!("                            now identifies the whole shareholder set.");
}

fn cmd_split(args: Vec<String>) -> Result<(), String> {
    let mut mnemonic: Option<String> = None;
    let mut passphrase: String = String::new();
    let mut text: Option<String> = None;
    let mut threshold: Option<u8> = None;
    let mut total: Option<u8> = None;
    let mut paper_path: Option<String> = None;
    let mut paper_dir: Option<String> = None;
    let mut json_path: Option<String> = None;
    let mut json_dir: Option<String> = None;
    let mut backup_name: Option<String> = None;
    let mut description_override: Option<String> = None;
    let mut shareholders_csv: Option<String> = None;

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--mnemonic" => mnemonic = Some(needs_value(it.next(), "--mnemonic")?),
            "--passphrase" => passphrase = needs_value(it.next(), "--passphrase")?,
            "--text" => text = Some(needs_value(it.next(), "--text")?),
            "--paper" => paper_path = Some(needs_value(it.next(), "--paper")?),
            "--paper-dir" => paper_dir = Some(needs_value(it.next(), "--paper-dir")?),
            "--json" => json_path = Some(needs_value(it.next(), "--json")?),
            "--json-dir" => json_dir = Some(needs_value(it.next(), "--json-dir")?),
            "--name" => backup_name = Some(needs_value(it.next(), "--name")?),
            "--description" => {
                description_override = Some(needs_value(it.next(), "--description")?);
            }
            "--shareholders" => {
                shareholders_csv = Some(needs_value(it.next(), "--shareholders")?);
            }
            "-m" | "--threshold" => {
                threshold = Some(
                    needs_value(it.next(), arg.as_str())?
                        .parse()
                        .map_err(|_| format!("{arg} must be a small positive integer"))?,
                );
            }
            "-n" | "--total" => {
                total = Some(
                    needs_value(it.next(), arg.as_str())?
                        .parse()
                        .map_err(|_| format!("{arg} must be a small positive integer"))?,
                );
            }
            other => return Err(format!("unknown flag {other:?}")),
        }
    }

    let threshold = threshold.ok_or("missing -m / --threshold")?;
    let total = total.ok_or("missing -n / --total")?;
    if threshold < chela_engine::MIN_THRESHOLD {
        return Err(format!(
            "threshold (-m) must be at least {}",
            chela_engine::MIN_THRESHOLD
        ));
    }
    if total > chela_engine::MAX_SHARES {
        return Err("total (-n) must be at most 32".into());
    }

    let input = match (mnemonic.as_deref(), text.as_deref()) {
        (Some(m), None) => SplitInput::Bip39 {
            mnemonic: m,
            passphrase: passphrase.as_str(),
        },
        (None, Some(t)) => SplitInput::Text { text: t },
        (Some(_), Some(_)) => return Err("specify --mnemonic OR --text, not both".into()),
        (None, None) => return Err("specify --mnemonic or --text".into()),
    };

    let shares = split_secret(&input, threshold, total, OutputMode::Bip39Wordlist)
        .map_err(|e| engine_err(&e))?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    for (i, share) in shares.iter().enumerate() {
        if i > 0 {
            writeln!(out).map_err(|e| e.to_string())?;
        }
        write!(out, "{}", format_share(share)).map_err(|e| e.to_string())?;
    }
    drop(out);

    let _ = threshold;
    let result = write_paper_outputs(
        &shares,
        total,
        PaperFlags {
            paper_path: paper_path.as_deref(),
            paper_dir: paper_dir.as_deref(),
            json_path: json_path.as_deref(),
            json_dir: json_dir.as_deref(),
            backup_name: backup_name.as_deref(),
            description_override,
            shareholders_csv,
        },
    );

    // Wipe input secrets before returning. argv copies still leak via the OS process
    // listing, but the in-process duplicates are gone.
    if let Some(mut m) = mnemonic {
        chela_primitives::zeroize::Zeroize::zeroize(&mut m);
    }
    chela_primitives::zeroize::Zeroize::zeroize(&mut passphrase);
    if let Some(mut t) = text {
        chela_primitives::zeroize::Zeroize::zeroize(&mut t);
    }
    result
}

struct PaperFlags<'a> {
    paper_path: Option<&'a str>,
    paper_dir: Option<&'a str>,
    json_path: Option<&'a str>,
    json_dir: Option<&'a str>,
    backup_name: Option<&'a str>,
    description_override: Option<String>,
    shareholders_csv: Option<String>,
}

/// Build a [`BackupMeta`] and dispatch every requested output flag. Any
/// combination of `--paper` / `--paper-dir` / `--json` / `--json-dir` may be
/// supplied; they're independent.
fn write_paper_outputs(
    shares: &[chela_engine::Share],
    total: u8,
    flags: PaperFlags<'_>,
) -> Result<(), String> {
    let description: Option<String> = flags.description_override;

    let shareholders: Option<Vec<String>> = match flags.shareholders_csv {
        None => None,
        Some(csv) => {
            let names: Vec<String> = csv
                .split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect();
            if names.len() != usize::from(total) {
                return Err(format!(
                    "--shareholders has {} names but -n is {}; counts must match",
                    names.len(),
                    total,
                ));
            }
            Some(names)
        }
    };

    let meta = BackupMeta {
        backup_name: flags.backup_name,
        description: description.as_deref(),
        shareholder_names: shareholders.as_deref(),
    };

    if let Some(path) = flags.paper_path {
        let html = render_paper_html(shares, &meta);
        write_private(path, html).map_err(|e| format!("writing {path}: {e}"))?;
        eprintln!("Wrote paper backup to {path}");
    }

    if let Some(dir) = flags.paper_dir {
        let folder = render_paper_folder(shares, &meta);
        write_paper_folder(Path::new(dir), &folder)?;
        eprintln!("Wrote paper backup folder to {dir}");
    }

    if let Some(path) = flags.json_path {
        let json = render_shares_json(shares, &meta);
        write_private(path, json).map_err(|e| format!("writing {path}: {e}"))?;
        eprintln!("Wrote JSON share bundle to {path}");
    }

    if let Some(dir) = flags.json_dir {
        let folder = render_json_folder(shares, &meta);
        write_json_folder(Path::new(dir), &folder)?;
        eprintln!(
            "Wrote {} JSON share file(s) + {} to {dir}",
            folder.shares.len(),
            folder.bundle.0,
        );
    }

    Ok(())
}

/// Write a [`PaperFolder`] to `dir`, creating the directory if needed.
fn write_paper_folder(dir: &Path, folder: &PaperFolder) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let readme_path = dir.join("README.txt");
    write_private(&readme_path, &folder.readme)
        .map_err(|e| format!("writing {}: {e}", readme_path.display()))?;
    for (filename, contents) in &folder.shares {
        let path = dir.join(filename);
        write_private(&path, contents).map_err(|e| format!("writing {}: {e}", path.display()))?;
    }
    Ok(())
}

/// Write a [`JsonFolder`] to `dir`: one `share-<x>.share.json` per share +
/// the combined `chela-<setID>-shares.json` bundle. Mirrors `write_paper_folder`.
fn write_json_folder(dir: &Path, folder: &JsonFolder) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let bundle_path = dir.join(&folder.bundle.0);
    write_private(&bundle_path, &folder.bundle.1)
        .map_err(|e| format!("writing {}: {e}", bundle_path.display()))?;
    for (filename, contents) in &folder.shares {
        let path = dir.join(filename);
        write_private(&path, contents).map_err(|e| format!("writing {}: {e}", path.display()))?;
    }
    Ok(())
}

/// Write `contents` to `path` with owner-only (0600) permissions on Unix, so share
/// material doesn't land world-readable at the default umask. Other platforms use the
/// filesystem default.
fn write_private(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
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

fn cmd_recover(file_paths: &[String]) -> Result<(), String> {
    let shares = if file_paths.is_empty() {
        // No positional args → read share text from stdin (legacy / piped flow).
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("read stdin: {e}"))?;
        let parsed = parse_share_text(&buf).map_err(|e| format!("parse: {e:?}"))?;
        chela_primitives::zeroize::Zeroize::zeroize(&mut buf);
        if parsed.is_empty() {
            return Err("no shares found on stdin".into());
        }
        parsed
    } else {
        // Positional args → treat each as a path. Auto-detect HTML vs text.
        // HTML files contain the embedded `<script class="chela-share">` block;
        // text files are the two-line CHELA-…/words format `parse_shares` reads.
        let mut accumulated = Vec::new();
        for path in file_paths {
            let contents =
                std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
            let extracted = read_one_file(&contents).map_err(|e| format!("{path}: {e}"))?;
            accumulated.extend(extracted);
        }
        if accumulated.is_empty() {
            return Err("no shares found in any input file".into());
        }
        eprintln!(
            "Imported {} share(s) from {} file(s).",
            accumulated.len(),
            file_paths.len(),
        );
        accumulated
    };

    let mut secret = recover_secret(&shares).map_err(|e| engine_err(&e))?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    let write_result = (|| -> Result<(), String> {
        match &mut secret {
            RecoveredSecret::Bip39 {
                mnemonic,
                passphrase,
            } => {
                // Mnemonic words are ASCII (BIP-39 wordlist) but pass through the same
                // sanitiser for consistency. The passphrase is arbitrary UTF-8 derived
                // from share bytes — attacker-influenceable if any cards were forged —
                // so escape control sequences before display to prevent terminal-escape
                // injection (OSC 52 clipboard write, window-title spoof, etc.).
                let mnemonic_safe =
                    chela_primitives::zeroize::Zeroizing::new(sanitize_for_terminal(mnemonic));
                let passphrase_safe =
                    chela_primitives::zeroize::Zeroizing::new(sanitize_for_terminal(passphrase));
                writeln!(out, "kind: BIP-39 mnemonic").map_err(|e| e.to_string())?;
                writeln!(out, "mnemonic:").map_err(|e| e.to_string())?;
                writeln!(out, "{}", *mnemonic_safe).map_err(|e| e.to_string())?;
                if passphrase.is_empty() {
                    writeln!(out, "passphrase: (none)").map_err(|e| e.to_string())?;
                } else {
                    writeln!(out, "passphrase:").map_err(|e| e.to_string())?;
                    writeln!(out, "{}", *passphrase_safe).map_err(|e| e.to_string())?;
                }
            }
            RecoveredSecret::Text { text } => {
                let text_safe =
                    chela_primitives::zeroize::Zeroizing::new(sanitize_for_terminal(text));
                writeln!(out, "kind: text").map_err(|e| e.to_string())?;
                writeln!(out, "text:").map_err(|e| e.to_string())?;
                writeln!(out, "{}", *text_safe).map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    })();

    match &mut secret {
        RecoveredSecret::Bip39 {
            mnemonic,
            passphrase,
        } => {
            chela_primitives::zeroize::Zeroize::zeroize(mnemonic);
            chela_primitives::zeroize::Zeroize::zeroize(passphrase);
        }
        RecoveredSecret::Text { text } => chela_primitives::zeroize::Zeroize::zeroize(text),
    }
    write_result
}

fn needs_value(v: Option<String>, flag: &str) -> Result<String, String> {
    v.ok_or_else(|| format!("{flag} needs a value"))
}

/// Decode a single file's contents into a list of shares.
///
/// Auto-detects three formats:
///   - **HTML** (chela paper-backup): contains `class="chela-share"`
///   - **JSON** (single `chela.share.v1` or bundle `chela.shares.v1`): first
///     non-whitespace char is `{`
///   - **Share text** (canonical `CHELA-…` two-line cards): everything else
///
/// Strict on import: any single bad block in a multi-share file fails the whole
/// file. The user's job is to fix the corrupted card, not to silently skip it.
fn read_one_file(contents: &str) -> Result<Vec<chela_engine::Share>, String> {
    let trimmed = contents.trim_start();
    let looks_html = contents.contains(r#"class="chela-share""#)
        || contents.contains("class='chela-share'")
        || trimmed.starts_with('<');
    if looks_html {
        let results = extract_shares_from_html(contents).map_err(|e| import_err_to_string(&e))?;
        collect_strict(results, "block")
    } else if trimmed.starts_with('{') {
        let results = extract_shares_from_json(contents).map_err(|e| import_err_to_string(&e))?;
        collect_strict(results, "share")
    } else {
        // Fall through to text-share parser. Accepts both headered `CHELA-…` cards
        // and words-only backups. Empty / unrecognized input surfaces as a parse error.
        parse_share_text(contents).map_err(|e| format!("parse share text: {e:?}"))
    }
}

/// Parse share text that may be either headered `CHELA-…` cards or words-only
/// backups. A `CHELA-` line anywhere selects the headered parser; otherwise each
/// non-blank line is a lone share's words, decoded via [`parse_share_words`].
fn parse_share_text(input: &str) -> Result<Vec<chela_engine::Share>, chela_share::FormatError> {
    let has_header = input
        .lines()
        .any(|l| l.trim_start().to_ascii_uppercase().starts_with("CHELA-"));
    if has_header {
        return parse_shares(input);
    }
    input
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| parse_share_words(l.trim()))
        .collect()
}

/// Reduce a `Vec<Result<Share, ImportError>>` to `Vec<Share>` or the first
/// per-item error, prefixed with `<label> #N:` so the user knows which entry
/// inside the file failed.
fn collect_strict(
    results: Vec<Result<chela_engine::Share, ImportError>>,
    label: &str,
) -> Result<Vec<chela_engine::Share>, String> {
    let mut out = Vec::with_capacity(results.len());
    for (idx, r) in results.into_iter().enumerate() {
        let share = r.map_err(|e| format!("{label} #{}: {}", idx + 1, import_err_to_string(&e)))?;
        out.push(share);
    }
    Ok(out)
}

fn import_err_to_string(e: &ImportError) -> String {
    format!("{e}")
}

/// Replace control bytes (C0 < 0x20 except `\n`/`\t`, DEL, and C1 0x80–0x9F) with a
/// visible `\xHH` / `\u{HHHH}` escape. Run over reconstructed secrets before they
/// reach stdout — an attacker who can supply a threshold of forged shares could
/// otherwise inject ANSI/OSC sequences (OSC 52 clipboard write, window-title
/// spoof, cursor manipulation) when the user prints the recovered text.
fn sanitize_for_terminal(s: &str) -> String {
    use std::fmt::Write as _;
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

fn engine_err(e: &EngineError) -> String {
    format!("{e:?}")
}

#[cfg(test)]
mod tests {
    use super::sanitize_for_terminal;

    #[test]
    fn passthrough_for_printable_ascii_and_utf8() {
        assert_eq!(sanitize_for_terminal("hello world"), "hello world");
        assert_eq!(sanitize_for_terminal("café 🦀"), "café 🦀");
        assert_eq!(
            sanitize_for_terminal("line\nbreak\ttab"),
            "line\nbreak\ttab"
        );
    }

    #[test]
    fn escapes_c0_controls() {
        assert_eq!(
            sanitize_for_terminal("\x1b[31mRED\x1b[0m"),
            "\\x1B[31mRED\\x1B[0m"
        );
        assert_eq!(sanitize_for_terminal("bell\x07"), "bell\\x07");
        assert_eq!(sanitize_for_terminal("\x7f"), "\\x7F");
    }

    #[test]
    fn escapes_c1_controls() {
        // U+0085 NEL (C1) is a known terminal-confused control.
        assert_eq!(sanitize_for_terminal("\u{0085}"), "\\u{0085}");
        assert_eq!(sanitize_for_terminal("\u{009B}"), "\\u{009B}");
    }

    #[test]
    fn osc_52_clipboard_payload_is_neutralised() {
        // Real attack payload — must not survive sanitisation.
        let attack = "\x1b]52;c;dGVzdA==\x07";
        let safe = sanitize_for_terminal(attack);
        assert!(!safe.contains('\x1b'));
        assert!(!safe.contains('\x07'));
    }
}
