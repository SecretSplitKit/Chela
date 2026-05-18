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

/// Run `chela-cli recover <file>...` with positional file paths. Returns
/// (status, stdout, stderr).
fn recover_with_files(file_paths: &[&str]) -> (std::process::ExitStatus, String, String) {
    let output = Command::new(CHELA_CLI)
        .arg("recover")
        .args(file_paths)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .expect("failed to spawn chela-cli recover");
    (
        output.status,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn recover_imports_shares_from_paper_html_files() {
    // Split a real secret with --paper-dir so chela-cli writes per-share HTML
    // files. Then recover by passing 3 of the 5 HTML files as positional args.
    let tmpdir = std::env::temp_dir().join(format!("chela-e2e-import-{}", std::process::id(),));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    let _ = split_with_args(&[
        "split",
        "--mnemonic",
        ABANDON_24,
        "--passphrase",
        "html-import test 🦀",
        "-m",
        "3",
        "-n",
        "5",
        "--paper-dir",
        tmpdir.to_str().unwrap(),
    ]);

    let file = |n: u8| {
        tmpdir
            .join(format!("share-{n}.html"))
            .to_str()
            .unwrap()
            .to_owned()
    };
    let f1 = file(1);
    let f3 = file(3);
    let f5 = file(5);
    let (status, stdout, stderr) = recover_with_files(&[&f1, &f3, &f5]);
    assert!(
        status.success(),
        "recover failed:\nstdout: {stdout}\nstderr: {stderr}",
    );
    assert!(stderr.contains("Imported 3 share(s) from 3 file(s)."));
    assert!(
        stdout.contains(ABANDON_24),
        "recovered mnemonic missing:\n{stdout}",
    );
    assert!(
        stdout.contains("html-import test 🦀"),
        "recovered passphrase missing:\n{stdout}",
    );

    std::fs::remove_dir_all(&tmpdir).ok();
}

#[test]
fn recover_imports_from_combined_paper_html_file() {
    // --paper writes a single HTML doc containing every share's <article>.
    // Passing that one file should yield every share in one shot.
    let tmpdir =
        std::env::temp_dir().join(format!("chela-e2e-import-combined-{}", std::process::id(),));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();
    let combined = tmpdir.join("combined.html");

    let _ = split_with_args(&[
        "split",
        "--mnemonic",
        ABANDON_24,
        "-m",
        "3",
        "-n",
        "5",
        "--paper",
        combined.to_str().unwrap(),
    ]);

    let path = combined.to_str().unwrap().to_owned();
    let (status, stdout, stderr) = recover_with_files(&[&path]);
    assert!(
        status.success(),
        "recover failed:\nstdout: {stdout}\nstderr: {stderr}",
    );
    // One file → 5 shares (more than the 3-of-5 threshold needs). The combine
    // ignores the extras correctly.
    assert!(stderr.contains("Imported 5 share(s) from 1 file(s)."));
    assert!(stdout.contains(ABANDON_24));

    std::fs::remove_dir_all(&tmpdir).ok();
}

#[test]
fn recover_mixed_html_and_text_files() {
    // Realistic flow: some shareholders sent in HTML files, others typed in
    // their words on paper and the recovering party saved both as text and HTML.
    let tmpdir =
        std::env::temp_dir().join(format!("chela-e2e-import-mixed-{}", std::process::id(),));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    let all_shares = split_with_args(&[
        "split",
        "--mnemonic",
        ABANDON_24,
        "-m",
        "3",
        "-n",
        "5",
        "--paper-dir",
        tmpdir.to_str().unwrap(),
    ]);

    // Save share 3 as a plain text file (the share-text format that
    // parse_shares accepts).
    let text_share_3 = pick_shares(&all_shares, &[3]);
    let text_path = tmpdir.join("share-3.txt");
    std::fs::write(&text_path, &text_share_3).unwrap();

    // Recover using cards 1 and 5 as HTML + card 3 as text.
    let html_1 = tmpdir.join("share-1.html").to_str().unwrap().to_owned();
    let html_5 = tmpdir.join("share-5.html").to_str().unwrap().to_owned();
    let text_3 = text_path.to_str().unwrap().to_owned();
    let (status, stdout, stderr) = recover_with_files(&[&html_1, &text_3, &html_5]);
    assert!(
        status.success(),
        "recover failed:\nstdout: {stdout}\nstderr: {stderr}",
    );
    assert!(stdout.contains(ABANDON_24));

    std::fs::remove_dir_all(&tmpdir).ok();
}

#[test]
fn recover_html_with_corrupt_block_reports_per_block_error() {
    let tmpdir =
        std::env::temp_dir().join(format!("chela-e2e-import-corrupt-{}", std::process::id(),));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();
    let bad = tmpdir.join("corrupt.html");
    std::fs::write(
        &bad,
        r#"<!doctype html><html><body>
            <script type="application/json" class="chela-share">{not valid json}</script>
            </body></html>"#,
    )
    .unwrap();
    let path = bad.to_str().unwrap().to_owned();
    let (status, stdout, stderr) = recover_with_files(&[&path]);
    assert!(!status.success(), "expected failure on corrupt block");
    let msg = format!("{stdout}{stderr}");
    // Error must mention the file and the per-block index, so the user knows
    // which file to fix.
    assert!(
        msg.contains("corrupt.html") && msg.contains("block #1"),
        "expected file path + block index in error, got:\n{msg}",
    );
}

#[test]
fn recover_html_file_with_no_chela_blocks_errors_clearly() {
    let tmpdir =
        std::env::temp_dir().join(format!("chela-e2e-import-empty-{}", std::process::id(),));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();
    let empty = tmpdir.join("not-a-chela-page.html");
    std::fs::write(
        &empty,
        "<!doctype html><html><body><p>just a page</p></body></html>",
    )
    .unwrap();
    let path = empty.to_str().unwrap().to_owned();
    let (status, _stdout, _stderr) = recover_with_files(&[&path]);
    assert!(
        !status.success(),
        "expected failure when no chela blocks present",
    );
    std::fs::remove_dir_all(&tmpdir).ok();
}

#[test]
fn recover_imports_per_share_json_files() {
    let tmpdir = std::env::temp_dir().join(format!("chela-e2e-json-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    let _ = split_with_args(&[
        "split",
        "--mnemonic",
        ABANDON_24,
        "--passphrase",
        "json-import test 🦀",
        "-m",
        "3",
        "-n",
        "5",
        "--json-dir",
        tmpdir.to_str().unwrap(),
    ]);

    // The folder should now contain share-1..5.share.json + the bundle.
    let entries: Vec<_> = std::fs::read_dir(&tmpdir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(entries.iter().any(|n| n == "share-1.share.json"));
    assert!(entries.iter().any(|n| n == "share-3.share.json"));
    assert!(entries.iter().any(|n| n == "share-5.share.json"));
    assert!(entries
        .iter()
        .any(|n| n.starts_with("chela-") && n.ends_with("-shares.json")));

    let file = |n: u8| {
        tmpdir
            .join(format!("share-{n}.share.json"))
            .to_str()
            .unwrap()
            .to_owned()
    };
    let (status, stdout, stderr) = recover_with_files(&[&file(1), &file(3), &file(5)]);
    assert!(status.success(), "recover failed:\n{stdout}\n{stderr}");
    assert!(stdout.contains(ABANDON_24));
    assert!(stdout.contains("json-import test 🦀"));

    std::fs::remove_dir_all(&tmpdir).ok();
}

#[test]
fn recover_imports_combined_json_bundle_file() {
    let tmpdir = std::env::temp_dir().join(format!("chela-e2e-json-bundle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();
    let bundle = tmpdir.join("all.shares.json");

    let _ = split_with_args(&[
        "split",
        "--mnemonic",
        ABANDON_24,
        "-m",
        "3",
        "-n",
        "5",
        "--json",
        bundle.to_str().unwrap(),
    ]);

    let path = bundle.to_str().unwrap().to_owned();
    let (status, stdout, stderr) = recover_with_files(&[&path]);
    assert!(status.success(), "recover failed:\n{stdout}\n{stderr}");
    // Combined bundle holds all 5; the engine ignores the extras correctly.
    assert!(stderr.contains("Imported 5 share(s) from 1 file(s)."));
    assert!(stdout.contains(ABANDON_24));

    std::fs::remove_dir_all(&tmpdir).ok();
}

#[test]
fn recover_mixed_html_text_and_json_files() {
    let tmpdir =
        std::env::temp_dir().join(format!("chela-e2e-mixed-formats-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    let all = split_with_args(&[
        "split",
        "--mnemonic",
        ABANDON_24,
        "-m",
        "3",
        "-n",
        "5",
        "--paper-dir",
        tmpdir.to_str().unwrap(),
        "--json-dir",
        tmpdir.to_str().unwrap(),
    ]);

    // Save share #3 as plain text alongside the HTML/JSON the split wrote.
    let text_share = pick_shares(&all, &[3]);
    let text_path = tmpdir.join("share-3.txt");
    std::fs::write(&text_path, &text_share).unwrap();

    // Mix one HTML + one JSON + one text — all should compose.
    let html_1 = tmpdir.join("share-1.html").to_str().unwrap().to_owned();
    let json_5 = tmpdir
        .join("share-5.share.json")
        .to_str()
        .unwrap()
        .to_owned();
    let text_3 = text_path.to_str().unwrap().to_owned();
    let (status, stdout, stderr) = recover_with_files(&[&html_1, &json_5, &text_3]);
    assert!(status.success(), "recover failed:\n{stdout}\n{stderr}");
    assert!(stdout.contains(ABANDON_24));

    std::fs::remove_dir_all(&tmpdir).ok();
}

#[test]
fn split_writes_all_four_outputs_when_all_flags_given() {
    // --paper, --paper-dir, --json, --json-dir all at once should each produce
    // their respective outputs without stepping on each other.
    let tmpdir = std::env::temp_dir().join(format!("chela-e2e-all-outputs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();
    let paper_html = tmpdir.join("combined.html");
    let json_bundle = tmpdir.join("bundle.json");
    let paper_dir = tmpdir.join("paper");
    let json_dir = tmpdir.join("json");

    let _ = split_with_args(&[
        "split",
        "--mnemonic",
        ABANDON_24,
        "-m",
        "2",
        "-n",
        "3",
        "--paper",
        paper_html.to_str().unwrap(),
        "--json",
        json_bundle.to_str().unwrap(),
        "--paper-dir",
        paper_dir.to_str().unwrap(),
        "--json-dir",
        json_dir.to_str().unwrap(),
    ]);

    assert!(paper_html.exists(), "--paper file should exist");
    assert!(json_bundle.exists(), "--json file should exist");
    assert!(paper_dir.join("share-1.html").exists());
    assert!(paper_dir.join("README.txt").exists());
    assert!(json_dir.join("share-1.share.json").exists());

    // The combined JSON bundle uses the chela.shares.v1 schema.
    let bundle_text = std::fs::read_to_string(&json_bundle).unwrap();
    assert!(bundle_text.contains(r#""type":"chela.shares.v1""#));

    // Single share files use chela.share.v1.
    let per_share = std::fs::read_to_string(json_dir.join("share-2.share.json")).unwrap();
    assert!(per_share.contains(r#""type":"chela.share.v1""#));
    // And the bundle filename includes the set ID.
    let json_entries: Vec<String> = std::fs::read_dir(&json_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(
        json_entries
            .iter()
            .any(|n| n.starts_with("chela-") && n.ends_with("-shares.json")),
        "json-dir bundle missing from {json_entries:?}",
    );

    std::fs::remove_dir_all(&tmpdir).ok();
}

#[test]
fn recover_rejects_corrupt_json_file_with_per_share_context() {
    let tmpdir =
        std::env::temp_dir().join(format!("chela-e2e-corrupt-json-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();
    let path = tmpdir.join("bad.share.json");
    std::fs::write(&path, r#"{"type":"chela.share.v1","card_code":"x"}"#).unwrap();
    let p = path.to_str().unwrap().to_owned();
    let (status, stdout, stderr) = recover_with_files(&[&p]);
    assert!(!status.success(), "expected failure on corrupt JSON");
    let msg = format!("{stdout}{stderr}");
    assert!(
        msg.contains("bad.share.json") && msg.contains("share #1"),
        "expected file path + share index in error:\n{msg}",
    );
    std::fs::remove_dir_all(&tmpdir).ok();
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
