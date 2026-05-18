//! End-to-end tests: spawn the `chela-cli` binary and round-trip split/recover via stdio.

use std::io::Write;
use std::process::{Command, Stdio};

const CHELA_CLI: &str = env!("CARGO_BIN_EXE_chela-cli");

fn split_with_args(args: &[&str]) -> String {
    let output = Command::new(CHELA_CLI)
        .args(args)
        .stderr(Stdio::piped())
        .output()
        .expect("failed to spawn chela-cli split");
    assert!(
        output.status.success(),
        "split exited non-zero: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).expect("split stdout is valid UTF-8")
}

/// Run `chela-cli recover` with the given shares on stdin. Returns (status, stdout, stderr).
fn recover_with_input(shares: &str) -> (std::process::ExitStatus, String, String) {
    let mut child = Command::new(CHELA_CLI)
        .arg("recover")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn chela-cli recover");
    {
        let stdin = child.stdin.as_mut().expect("child stdin");
        stdin
            .write_all(shares.as_bytes())
            .expect("write to child stdin");
    }
    let output = child
        .wait_with_output()
        .expect("wait for chela-cli recover");
    (
        output.status,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Pick share blocks by 1-based index out of the share output. Each block is two
/// non-blank lines (header + words), separated from the next by a blank line.
fn pick_shares(all: &str, indices: &[usize]) -> String {
    let mut blocks: Vec<Vec<&str>> = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    for line in all.lines() {
        if line.trim().is_empty() {
            if !current.is_empty() {
                blocks.push(core::mem::take(&mut current));
            }
        } else {
            current.push(line);
        }
    }
    if !current.is_empty() {
        blocks.push(current);
    }
    let mut out = String::new();
    for &i in indices {
        let block = blocks
            .get(i - 1)
            .unwrap_or_else(|| panic!("share index {i} not found (have {})", blocks.len()));
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&block.join("\n"));
        out.push('\n');
    }
    out
}

const ABANDON_24: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon art";

#[test]
fn round_trip_24_word_seed_with_passphrase_3_of_5_non_contiguous_subset() {
    let shares = split_with_args(&[
        "split",
        "--mnemonic",
        ABANDON_24,
        "--passphrase",
        "this is a 🦀 passphrase",
        "-m",
        "3",
        "-n",
        "5",
    ]);
    // Pick shares 1, 3, 5 — non-contiguous, exercises the "shares can be combined in
    // any order" property.
    let subset = pick_shares(&shares, &[1, 3, 5]);
    let (status, stdout, _) = recover_with_input(&subset);
    assert!(status.success(), "recover failed: {stdout}");
    assert!(
        stdout.contains(ABANDON_24),
        "recovered mnemonic missing from output:\n{stdout}",
    );
    assert!(
        stdout.contains("this is a 🦀 passphrase"),
        "recovered passphrase missing from output:\n{stdout}",
    );
}

#[test]
fn round_trip_12_word_seed_no_passphrase_2_of_3() {
    let mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon about";
    let shares = split_with_args(&["split", "--mnemonic", mnemonic, "-m", "2", "-n", "3"]);
    let subset = pick_shares(&shares, &[1, 2]);
    let (status, stdout, _) = recover_with_input(&subset);
    assert!(status.success(), "recover failed: {stdout}");
    assert!(
        stdout.contains(mnemonic),
        "recovered mnemonic missing:\n{stdout}"
    );
    assert!(
        stdout.contains("passphrase: (none)"),
        "expected (none) passphrase marker:\n{stdout}",
    );
}

#[test]
fn round_trip_text_payload_2_of_4() {
    let secret = "correct horse battery staple";
    let shares = split_with_args(&["split", "--text", secret, "-m", "2", "-n", "4"]);
    // Use shares 2 and 4
    let subset = pick_shares(&shares, &[2, 4]);
    let (status, stdout, _) = recover_with_input(&subset);
    assert!(status.success(), "recover failed: {stdout}");
    assert!(stdout.contains("kind: text"));
    assert!(stdout.contains(secret), "recovered text missing:\n{stdout}");
}

#[test]
fn sub_threshold_recovery_fails_cleanly() {
    let shares = split_with_args(&["split", "--mnemonic", ABANDON_24, "-m", "3", "-n", "5"]);
    // Pass only 2 of 5 shares — below the 3-of-5 threshold.
    let subset = pick_shares(&shares, &[1, 2]);
    let (status, stdout, stderr) = recover_with_input(&subset);
    assert!(
        !status.success(),
        "expected non-zero exit; got stdout={stdout} stderr={stderr}"
    );
    let msg = format!("{stdout}{stderr}");
    assert!(
        msg.contains("InsufficientShares"),
        "expected InsufficientShares in error output:\n{msg}",
    );
}

#[test]
fn mixed_shares_from_different_splits_rejected() {
    let split_a = split_with_args(&["split", "--mnemonic", ABANDON_24, "-m", "2", "-n", "3"]);
    let split_b = split_with_args(&["split", "--mnemonic", ABANDON_24, "-m", "2", "-n", "3"]);
    // One share from each split. Same mnemonic → same identifier (it's deterministic
    // from the body), so the early consistency check passes; SSS combine on points from
    // two different polynomials then yields garbage that no kind's identifier matches,
    // surfacing as BundleCorrupt. The important guarantee is that we don't silently
    // produce a recovered secret.
    let from_first_split = pick_shares(&split_a, &[1]);
    let from_second_split = pick_shares(&split_b, &[2]);
    let mixed = format!("{from_first_split}\n{from_second_split}");
    let (status, stdout, stderr) = recover_with_input(&mixed);
    assert!(!status.success(), "expected non-zero exit");
    let msg = format!("{stdout}{stderr}");
    assert!(
        msg.contains("BundleCorrupt") || msg.contains("MismatchedShares") || msg.contains("parse:"),
        "expected BundleCorrupt / MismatchedShares / parse error, got:\n{msg}",
    );
}

#[test]
fn invalid_mnemonic_word_rejected_at_split_time() {
    let bad_mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon notarealbip39word";
    let output = Command::new(CHELA_CLI)
        .args(["split", "--mnemonic", bad_mnemonic, "-m", "2", "-n", "3"])
        .output()
        .expect("spawn chela-cli");
    assert!(
        !output.status.success(),
        "expected non-zero exit on invalid mnemonic"
    );
}
