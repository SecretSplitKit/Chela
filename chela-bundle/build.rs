//! Compiles `chela-wasm` for `wasm32-unknown-unknown` into `OUT_DIR/chela.wasm`.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
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
        .expect("chela-bundle sits inside the workspace root")
        .to_path_buf();

    let wasm_target_dir = out_dir.join("wasm-target");
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
        // Scrub host-target linker flags so they don't reach the wasm link. The release
        // workflow sets host-only RUSTFLAGS (e.g. -C link-arg=-Wl,--build-id=none); rust-lld
        // rejects them, which would abort this inner wasm build.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
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
        fs::metadata(&wasm_dst).map_or(0, |m| m.len()),
        wasm_src.display()
    );
}

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
