//! Build-time helper for `chela-serve`: compiles `chela-wasm` to
//! `wasm32-unknown-unknown` and copies the resulting `.wasm` blob into
//! `OUT_DIR/chela.wasm` so `main.rs` can `include_bytes!()` it from a stable path.
//!
//! The inner build uses a dedicated `--target-dir` to avoid two pitfalls:
//!   1. cargo gets confused if the same target dir holds both native and wasm32
//!      artefacts for the same crate graph.
//!   2. Writing wasm artefacts under the outer build's `target/` would re-trigger
//!      this script on every build via `rerun-if-changed`.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Register every source file in the WASM dep graph so editing any of them rebuilds.
    register_rerun_globs(&[
        "../chela-wasm/Cargo.toml",
        "../chela-wasm/src",
        "../chela-engine",
        "../chela-share",
        "../chela-bip39",
        "../chela-sss",
        "../chela-field",
        "../chela-primitives",
    ]);

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR set by cargo"));
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"));
    let workspace_root = manifest_dir
        .parent()
        .expect("chela-serve sits inside the workspace root")
        .to_path_buf();

    let wasm_target_dir = out_dir.join("wasm-target");

    // The outer cargo sets `CARGO` to its own executable; reuse it so the inner build
    // runs on the same toolchain.
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());

    println!("cargo:warning=building chela-wasm for wasm32-unknown-unknown...");
    let status = Command::new(&cargo)
        .arg("build")
        .arg("--release")
        .arg("-p")
        .arg("chela-wasm")
        .arg("--target")
        .arg("wasm32-unknown-unknown")
        .arg("--target-dir")
        .arg(&wasm_target_dir)
        .arg("--manifest-path")
        .arg(workspace_root.join("Cargo.toml"))
        .env_remove("CARGO_BUILD_JOBS")
        .status()
        .expect("failed to spawn inner `cargo build` for chela-wasm");
    assert!(
        status.success(),
        "inner cargo build for chela-wasm failed (exit {status})"
    );

    let wasm_src = wasm_target_dir
        .join("wasm32-unknown-unknown")
        .join("release")
        .join("chela_wasm.wasm");
    assert!(
        wasm_src.exists(),
        "WASM build succeeded but artefact missing at {}",
        wasm_src.display()
    );

    let wasm_dst = out_dir.join("chela.wasm");
    fs::copy(&wasm_src, &wasm_dst).unwrap_or_else(|e| {
        panic!(
            "copying {} → {}: {e}",
            wasm_src.display(),
            wasm_dst.display()
        )
    });

    println!(
        "cargo:warning=embedded {} bytes of WASM from {}",
        fs::metadata(&wasm_dst).map(|m| m.len()).unwrap_or(0),
        wasm_src.display()
    );

    // Compute CSP script-src hashes for every inline <script> block in chela.html.
    // The served CSP whitelists scripts by hash, so we can keep `'unsafe-inline'`
    // out of script-src — only the exact known-good inline scripts are allowed.
    // If chela.html changes, this regenerates and the new hash is shipped.
    let html_path = manifest_dir.join("assets/chela.html");
    println!("cargo:rerun-if-changed={}", html_path.display());
    let html = fs::read_to_string(&html_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", html_path.display()));
    let hashes = inline_script_csp_hashes(&html);
    let hash_file = out_dir.join("csp_script_hashes.txt");
    fs::write(&hash_file, hashes.join(" "))
        .unwrap_or_else(|e| panic!("write {}: {e}", hash_file.display()));
    println!(
        "cargo:warning=pinned {} inline <script> hash(es) for CSP",
        hashes.len()
    );
}

/// Find every `<script>...</script>` block in `html`, hash its inner bytes with
/// SHA-256, and return the CSP token form `'sha256-<base64>'` for each.
///
/// Only handles bare `<script>` tags (no attributes), which is what chela.html
/// uses. Tags with attributes (e.g. `<script type="module">`) would need
/// different handling — the assertion at the end of the function catches that.
fn inline_script_csp_hashes(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find("<script>") {
        let after_open = start + "<script>".len();
        let end_offset_in_rest = rest[after_open..]
            .find("</script>")
            .expect("inline <script> has matching </script>");
        let body = &rest[after_open..after_open + end_offset_in_rest];
        out.push(csp_hash_token(body.as_bytes()));
        rest = &rest[after_open + end_offset_in_rest + "</script>".len()..];
    }
    assert!(
        !html.contains("<script "),
        "build.rs only handles bare <script> tags; chela.html now contains attributed \
         <script ...> which would silently slip past the CSP hash list. Update build.rs."
    );
    out
}

fn csp_hash_token(bytes: &[u8]) -> String {
    let mut h = chela_primitives::sha256::Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    format!("'sha256-{}'", base64_encode(&digest))
}

/// Standard base64 alphabet per RFC 4648 §4 — keeps build.rs dependency-free.
/// Duplicated from chela-bundle's runtime copy; both are tiny and self-contained.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n0 = (b0 >> 2) & 0x3f;
        let n1 = ((b0 << 4) | (b1 >> 4)) & 0x3f;
        let n2 = ((b1 << 2) | (b2 >> 6)) & 0x3f;
        let n3 = b2 & 0x3f;
        out.push(ALPHABET[n0 as usize] as char);
        out.push(ALPHABET[n1 as usize] as char);
        if chunk.len() >= 2 {
            out.push(ALPHABET[n2 as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() >= 3 {
            out.push(ALPHABET[n3 as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Emit `cargo:rerun-if-changed=` for files, or every file under a directory tree.
fn register_rerun_globs(paths: &[&str]) {
    for p in paths {
        let path = Path::new(p);
        if path.is_dir() {
            for entry in walkdir(path) {
                println!("cargo:rerun-if-changed={}", entry.display());
            }
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

fn walkdir(start: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![start.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(entries) = fs::read_dir(&p) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // Skip `target/` and dot-dirs — including them would loop via rerun-if-changed.
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with('.') || name == "target" {
                    continue;
                }
            }
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}
