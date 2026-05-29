# chela cleanup & simplification — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Drop `chela-serve`, add `chela-bundle` (tiny bundle-builder crate), purge AI-flavored prose across the repo, restructure `AUDITORS.md` and `AGENTS.md`, slim ancillary docs.

**Architecture:** Three independent passes — (A) crate layout, (B) docs, (C) source prose. Crypto, wire format, JSON schemas, TUI/CLI surface, and the reproducible-build profile are explicitly preserved. Spec at `docs/superpowers/specs/2026-05-29-cleanup-and-simplification-design.md`.

**Tech Stack:** Rust workspace (10 crates → 9), `wasm32-unknown-unknown` target via inner cargo build, GitHub Actions, Markdown docs.

**Hard constraints (apply to every task):**

- Do not edit anything inside `chela-share/fuzz/` — it's an excluded sub-workspace.
- Do not change algorithm code, wire-format constants, or test bodies. Only comments / docstrings / surrounding prose.
- Every `// SAFETY:` block stays **verbatim**. Every zeroize-justification comment and crypto-vector citation stays.
- Every task ends with `cargo test --workspace` green. If a prose edit breaks the build (likely a doctest), revert that edit.
- After every commit, run `cargo fmt --all` before pushing if you reformatted.
- Commit small. One task = one commit unless explicitly noted.

---

## File map

Files this plan creates, modifies, or deletes.

**Created:**
- `chela-bundle/Cargo.toml`
- `chela-bundle/build.rs`
- `chela-bundle/src/main.rs`
- `chela-bundle/assets/chela.html` (moved, not authored)

**Deleted:**
- `chela-serve/` (entire directory tree)
- `TODO.md`

**Modified:**
- `Cargo.toml` (workspace members)
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `README.md`, `RELEASING.md`, `MANUAL_RECOVERY.md`, `RECOVERY.md`, `SPEC.md`
- `AGENTS.md` (full rewrite)
- `AUDITORS.md` (restructure)
- Every `chela-*/src/**.rs` (prose pass)
- Every `chela-*/Cargo.toml` (drop AI-flavored comments)

---

## Phase A — Crate layout (chela-serve → chela-bundle)

### Task A1: Snapshot baseline

**Files:** none modified.

- [ ] **Step 1: Confirm clean working tree**

Run:
```sh
git status
```
Expected: `nothing to commit, working tree clean`.

- [ ] **Step 2: Confirm full suite passes**

Run:
```sh
cargo test --workspace
```
Expected: `test result: ok` for every crate.

- [ ] **Step 3: Build the current standalone HTML, save as reference**

Run:
```sh
cargo build --release --bin chela-bundle
./target/release/chela-bundle /tmp/chela-baseline.html
sha256sum /tmp/chela-baseline.html | tee /tmp/chela-baseline.sha256
```
Save the sha somewhere durable (e.g. paste it into this task's checkmark message). Used in Task A6 to confirm the new crate produces an identical bundle.

---

### Task A2: Create `chela-bundle/Cargo.toml`

**Files:**
- Create: `chela-bundle/Cargo.toml`

- [ ] **Step 1: Create the directory**

Run:
```sh
mkdir -p chela-bundle/src chela-bundle/assets
```

- [ ] **Step 2: Write Cargo.toml**

`chela-bundle/Cargo.toml`:
```toml
[package]
name = "chela-bundle"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
description = "Builds the standalone chela.html bundle with the chela WebAssembly UI embedded."
build = "build.rs"

[[bin]]
name = "chela-bundle"
path = "src/main.rs"

[lints]
workspace = true
```

No runtime or build dependencies. The bundler reads its own HTML asset and the WASM bytes produced by `build.rs`; no SHA-256 needed (the CSP hash logic stays in `chela-serve` until it goes away in Task A8).

---

### Task A3: Move `chela.html` and write `build.rs`

**Files:**
- Move: `chela-serve/assets/chela.html` → `chela-bundle/assets/chela.html`
- Create: `chela-bundle/build.rs`

- [ ] **Step 1: Copy the HTML template**

Run:
```sh
cp chela-serve/assets/chela.html chela-bundle/assets/chela.html
```
(Leaving the original for now — `chela-serve` still needs to build until Task A8.)

- [ ] **Step 2: Write build.rs**

`chela-bundle/build.rs` — this is the existing `chela-serve/build.rs` minus the CSP inline-script hashing. Replace the file with exactly:

```rust
//! Compiles chela-wasm for wasm32-unknown-unknown into OUT_DIR/chela.wasm.

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
```

Notes:
- This is literally the `chela-serve/build.rs` content minus the CSP-hash block (everything from `// Compute CSP script-src hashes for every inline <script> block` to end of `main` that wrote `csp_script_hashes.txt`), the `inline_script_csp_hashes` function, the `csp_hash_token` function, and the duplicate `base64_encode`.
- Module docstring is one line.

---

### Task A4: Write `chela-bundle/src/main.rs`

**Files:**
- Create: `chela-bundle/src/main.rs`

- [ ] **Step 1: Write main.rs**

`chela-bundle/src/main.rs` — this is the existing `chela-serve/src/bin/chela-bundle.rs` with the asset path adjusted (`../../assets/chela.html` becomes `../assets/chela.html`) and the module docstring shortened:

```rust
//! Produces the standalone single-file chela.html with the WebAssembly UI inlined.

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

const INDEX_HTML: &str = include_str!("../assets/chela.html");
const WASM_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/chela.wasm"));

const WASM_PLACEHOLDER: &str = "const WASM_BASE64 = null;";

fn main() -> ExitCode {
    let out_path = env::args()
        .nth(1)
        .map_or_else(|| PathBuf::from("chela.html"), PathBuf::from);

    if !INDEX_HTML.contains(WASM_PLACEHOLDER) {
        eprintln!(
            "chela-bundle: source HTML doesn't contain the expected `{WASM_PLACEHOLDER}` line. \
             Aborting so we don't ship a broken bundle."
        );
        return ExitCode::from(1);
    }

    let b64 = base64_encode(WASM_BYTES);
    let replacement = format!("const WASM_BASE64 = \"{b64}\";");
    let bundled = INDEX_HTML.replacen(WASM_PLACEHOLDER, &replacement, 1);

    match fs::File::create(&out_path).and_then(|mut f| f.write_all(bundled.as_bytes())) {
        Ok(()) => {
            eprintln!(
                "chela-bundle: wrote {} bytes to {} (WASM was {} bytes → {} base64)",
                bundled.len(),
                out_path.display(),
                WASM_BYTES.len(),
                b64.len(),
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("chela-bundle: failed to write {}: {e}", out_path.display());
            ExitCode::from(1)
        }
    }
}

/// Standard base64 alphabet per RFC 4648 §4. Hand-rolled to keep the workspace dependency-free.
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

#[cfg(test)]
mod tests {
    use super::{base64_encode, INDEX_HTML, WASM_PLACEHOLDER};

    #[test]
    fn empty() {
        assert_eq!(base64_encode(b""), "");
    }

    /// RFC 4648 §10 test vectors.
    #[test]
    fn rfc4648_vectors() {
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn always_padded_to_quartet() {
        for len in 0..32 {
            let bytes = vec![0xa5u8; len];
            let out = base64_encode(&bytes);
            assert_eq!(out.len() % 4, 0, "len {len} encodes to non-quartet `{out}`");
        }
    }

    #[test]
    fn source_html_contains_placeholder() {
        assert!(
            INDEX_HTML.contains(WASM_PLACEHOLDER),
            "chela.html must contain `{WASM_PLACEHOLDER}` exactly once for the bundler to rewrite it"
        );
        assert_eq!(
            INDEX_HTML.matches(WASM_PLACEHOLDER).count(),
            1,
            "placeholder should appear exactly once",
        );
    }

    #[test]
    fn rewrite_replaces_placeholder_exactly_once() {
        let bundled =
            INDEX_HTML.replacen(WASM_PLACEHOLDER, "const WASM_BASE64 = \"TESTPAYLOAD\";", 1);
        assert!(!bundled.contains(WASM_PLACEHOLDER));
        assert_eq!(
            bundled
                .matches("const WASM_BASE64 = \"TESTPAYLOAD\";")
                .count(),
            1,
        );
        assert_eq!(
            bundled.len(),
            INDEX_HTML.len() - WASM_PLACEHOLDER.len()
                + "const WASM_BASE64 = \"TESTPAYLOAD\";".len(),
        );
    }
}
```

Notes:
- Logic byte-identical to `chela-serve/src/bin/chela-bundle.rs`.
- Tests preserved verbatim — they're the source-of-truth that the placeholder rewrite stays correct.
- Multi-line module/function docstrings collapsed to one line; the "Pay-off:" / "Why split:" rationale lines in the original removed. Tests' inline doc comments collapsed.

---

### Task A5: Add `chela-bundle` to the workspace and verify it builds

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add `chela-bundle` to workspace members**

Edit `Cargo.toml` (workspace root). The `members` list currently ends with `"chela-serve",`. Add `"chela-bundle",` on the line above. After the edit the members list should contain both for now:

```toml
[workspace]
resolver = "2"
members = [
    "chela-primitives",
    "chela-field",
    "chela-sss",
    "chela-bip39",
    "chela-share",
    "chela-engine",
    "chela-tui",
    "chela-cli",
    "chela-wasm",
    "chela-bundle",
    "chela-serve",
]
```

- [ ] **Step 2: Build the new crate**

Run:
```sh
cargo build --release -p chela-bundle
```
Expected: success. The build will be slow first time — it triggers the inner wasm32 build.

- [ ] **Step 3: Run the crate's tests**

Run:
```sh
cargo test -p chela-bundle
```
Expected: 4 tests pass (`empty`, `rfc4648_vectors`, `always_padded_to_quartet`, `source_html_contains_placeholder`, `rewrite_replaces_placeholder_exactly_once`).

---

### Task A6: Verify the new bundle is byte-identical to the old one

**Files:** none modified.

- [ ] **Step 1: Build a new chela.html via the new crate**

Run:
```sh
./target/release/chela-bundle /tmp/chela-new.html
sha256sum /tmp/chela-new.html
```

- [ ] **Step 2: Compare to the baseline from Task A1**

Run:
```sh
diff /tmp/chela-baseline.html /tmp/chela-new.html && echo OK
```
Expected: `OK` (zero output from diff). Hashes must also match the baseline saved in Task A1.

If they differ: investigate before proceeding. The two binaries source the same HTML asset and the same WASM bytes, so the only ways they can diverge are (a) a stray edit to the HTML during copy, or (b) the build picked up a different `chela-wasm` artefact. Re-check `chela-bundle/assets/chela.html` vs `chela-serve/assets/chela.html`.

- [ ] **Step 3: Commit**

```sh
git add Cargo.toml chela-bundle/
git commit -m "add chela-bundle crate (will replace chela-serve's bundle binary)"
```

---

### Task A7: Update `.github/workflows/release.yml`

**Files:**
- Modify: `.github/workflows/release.yml`

The current release workflow builds `chela-tui chela-cli chela-serve`, lists `chela chela-cli chela-serve chela-bundle` for hashing and staging, and has a `bundle-web` job that already runs `chela-bundle`. After this task, `chela-serve` is gone from every reference; `chela-bundle` is still produced by `bundle-web`.

- [ ] **Step 1: Drop `-p chela-serve` from both build passes**

In `.github/workflows/release.yml`, find the two `Build (pass 1)` / `Build (pass 2)` steps. Each currently ends with:
```yaml
            -p chela-tui -p chela-cli -p chela-serve
```
Change both to:
```yaml
            -p chela-tui -p chela-cli
```

- [ ] **Step 2: Drop `chela-serve` from the reproducibility check loop**

In the `Verify reproducibility (hash both passes)` step, find:
```bash
          for bin in chela chela-cli chela-serve chela-bundle; do
```
Change to:
```bash
          for bin in chela chela-cli; do
```
(`chela-bundle` is built in the `bundle-web` job, not the per-target binary matrix. The original list was wrong; this fixes it.)

- [ ] **Step 3: Drop `chela-serve` / `chela-bundle` from the staging copy loop**

In the `Stage release artifacts` step, find:
```bash
          for bin in chela chela-cli chela-serve chela-bundle; do
```
Change to:
```bash
          for bin in chela chela-cli; do
```

- [ ] **Step 4: Drop `chela-serve` and `chela-bundle` lines from the staged README**

In the same `Stage release artifacts` step, the embedded `README.txt` heredoc currently lists:
```
            chela          Wizard TUI (default front-end)
            chela-cli      Non-interactive CLI for scripting / piping
            chela-serve    Localhost webserver hosting the WASM UI
            chela-bundle   Builds a single-file chela.html (offline browser UI)
```
Replace with:
```
            chela          Wizard TUI (default front-end)
            chela-cli      Non-interactive CLI for scripting / piping
```
(`chela-bundle` isn't shipped per-target either; the standalone HTML it produces is the web release artifact.)

- [ ] **Step 5: Drop the wasm32-target install for the build job**

Currently:
```yaml
      # chela-serve's build script invokes an inner `cargo build --target wasm32-...`
      # to embed the WASM blob via include_bytes!. Only the linux runner needs the
      # wasm32 toolchain installed.
      - name: Install wasm32 target
        if: matrix.target == 'x86_64-unknown-linux-gnu'
        run: rustup target add wasm32-unknown-unknown
```
After Task A8, `chela-serve` is gone, no native-binary target builds the wasm32 toolchain. Delete this entire step; the `bundle-web` job installs the wasm target itself.

- [ ] **Step 6: Drop the `chela-serve` mention from the release notes body**

Currently in the `Build release notes body with inline SHA256SUMS` step the heredoc contains:
```
          standalone browser bundle is \`chela-${TAG}-web.html\` — no install, open in
          any modern browser. \`chela-serve\` prints the SHA-256 of its embedded HTML
          and WASM at startup so you can cross-check against the values below.
```
Replace those three lines with:
```
          standalone browser bundle is \`chela-${TAG}-web.html\` — no install, open in
          any modern browser. The SHA-256 of \`chela-${TAG}-web.html\` is in the
          SHA256SUMS block below; verify before opening.
```

- [ ] **Step 7: Drop the `chela-serve` mention from the workflow header comment**

The file's top comment block currently lists `chela-serve` as one of the four binaries. Update to two:
```yaml
#   1. Build all binaries (chela, chela-cli) twice in
#      independent target directories.
```
(The original line said "four binaries (chela, chela-cli, chela-serve, chela-bundle)". `chela-bundle` is in the separate `bundle-web` job.)

- [ ] **Step 8: Verify the YAML is well-formed**

Run:
```sh
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))" && echo OK
```
Expected: `OK`.

- [ ] **Step 9: Commit**

```sh
git add .github/workflows/release.yml
git commit -m "release: drop chela-serve from build/hash/stage; bundle-web job already builds chela-bundle"
```

---

### Task A8: Delete `chela-serve` and remove it from the workspace

**Files:**
- Delete: `chela-serve/` (recursive)
- Modify: `Cargo.toml`

- [ ] **Step 1: Drop `chela-serve` from workspace members**

Edit `Cargo.toml`. The members list should now read:
```toml
members = [
    "chela-primitives",
    "chela-field",
    "chela-sss",
    "chela-bip39",
    "chela-share",
    "chela-engine",
    "chela-tui",
    "chela-cli",
    "chela-wasm",
    "chela-bundle",
]
```

- [ ] **Step 2: Delete the directory**

Run:
```sh
git rm -r chela-serve/
```

- [ ] **Step 3: Confirm the workspace still builds and tests pass**

Run:
```sh
cargo test --workspace
```
Expected: all crates pass.

- [ ] **Step 4: Confirm `chela-bundle` still produces a matching bundle**

Run:
```sh
cargo build --release -p chela-bundle
./target/release/chela-bundle /tmp/chela-postdelete.html
diff /tmp/chela-baseline.html /tmp/chela-postdelete.html && echo OK
```
Expected: `OK`.

- [ ] **Step 5: Commit**

```sh
git add Cargo.toml
git commit -m "remove chela-serve: replaced by chela-bundle for standalone HTML production"
```

---

### Task A9: Update `.github/workflows/ci.yml` — no chela-serve references to change

**Files:**
- Modify: `.github/workflows/ci.yml` (small edit only)

The current `ci.yml` doesn't name `chela-serve` directly — `cargo test --workspace` covers it transitively. After A8 the file still works, but the `wasm` job's per-package builds are worth extending to include `chela-bundle` as a smoke check.

- [ ] **Step 1: Verify ci.yml mentions no chela-serve**

Run:
```sh
grep -n chela-serve .github/workflows/ci.yml
```
Expected: no output.

- [ ] **Step 2: Add a chela-bundle build smoke test**

In the `test` job, after the existing `Run tests` step, add:
```yaml
      - name: Build chela-bundle and produce chela.html (smoke)
        run: |
          cargo build --release --locked --bin chela-bundle
          ./target/release/chela-bundle /tmp/chela.html
          test -s /tmp/chela.html
```

- [ ] **Step 3: Verify YAML is well-formed**

Run:
```sh
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))" && echo OK
```
Expected: `OK`.

- [ ] **Step 4: Commit**

```sh
git add .github/workflows/ci.yml
git commit -m "ci: smoke-test chela-bundle on every PR"
```

---

## Phase B — Docs

### Task B1: Update `README.md`

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Drop `chela-serve` from the "Produces" table**

In `README.md`, find:
```markdown
| `target/release/chela-serve`  | Localhost browser UI                         |
| `target/release/chela-bundle` | Builds the standalone `chela.html`           |
```
Replace with:
```markdown
| `target/release/chela-bundle` | Builds the standalone `chela.html`           |
```

- [ ] **Step 2: Drop the "Run — browser server" section**

Find the `## Run — browser` section. It contains:
```sh
./target/release/chela-serve              # localhost server
./target/release/chela-bundle chela.html  # standalone, offline file
```
Plus a paragraph mentioning "localhost only — no LAN exposure" etc. Replace the whole section with:
```markdown
## Run — browser

```sh
./target/release/chela-bundle chela.html  # standalone, offline file
```

The standalone bundle is one self-contained HTML file. Open it in any modern browser
— no install, no network.
```

- [ ] **Step 3: Drop the chela-serve mention from "Verifying a release"**

Find the paragraph:
```
`chela-serve` additionally prints `SHA-256(chela.html)` and `SHA-256(chela.wasm)`
to stderr at startup so you can cross-check the embedded bundle against the
release values without leaving your terminal.
```
Delete the entire paragraph.

- [ ] **Step 4: Slim "Where to find the hashes" to one path**

In the "Verifying a release" section, the current "Where to find the hashes" block lists three options (inlined in release notes, `SHA256SUMS` file, per-artifact `.sha256` files). Replace the whole numbered list with:
```markdown
### Where to find the hashes

`SHA256SUMS` and `SHA256SUMS.minisig` are attached to every release.

```sh
minisign -V -p chela.pub -m SHA256SUMS
sha256sum -c SHA256SUMS
```
```

- [ ] **Step 5: Drop `chela-serve` from the `Reproduce a release locally` example**

Find:
```sh
sha256sum target/release/chela target/release/chela-cli \
          target/release/chela-serve target/release/chela-bundle
```
Replace with:
```sh
sha256sum target/release/chela target/release/chela-cli target/release/chela-bundle
```

- [ ] **Step 6: Commit**

```sh
git add README.md
git commit -m "docs(readme): drop chela-serve; slim SHA256SUMS section"
```

---

### Task B2: Update `RELEASING.md`

**Files:**
- Modify: `RELEASING.md`

- [ ] **Step 1: Slim the "What ships per release" list**

Find:
```markdown
- `chela-<version>-<target>.tar.gz` (or `.zip` on Windows) — the binaries
- `<file>.sha256` — single-artifact hash
- `<file>.minisig` — minisign signature
- `chela-<version>-web.html` + `.sha256` + `.minisig` — standalone browser bundle
- `SHA256SUMS` — every artifact's hash, sorted, signed (`SHA256SUMS.minisig`)
```
Replace with:
```markdown
- `chela-<version>-<target>.tar.gz` (or `.zip` on Windows) — `chela` + `chela-cli` binaries
- `chela-<version>-web.html` — standalone browser bundle
- `SHA256SUMS` and `SHA256SUMS.minisig` — every artifact's hash, signed
```

- [ ] **Step 2: Drop the "release notes body includes the SHA256SUMS block inline" line**

Find:
```markdown
The release notes body includes the `SHA256SUMS` block inline so verifiers can compare
without downloading the aggregate.
```
Delete it. (Information stays in `release.yml`; the runbook doesn't need to re-state it.)

- [ ] **Step 3: Verify there are no other `chela-serve` references**

Run:
```sh
grep -n chela-serve RELEASING.md
```
Expected: no output. If any remain, delete the lines.

- [ ] **Step 4: Commit**

```sh
git add RELEASING.md
git commit -m "docs(releasing): chela-serve gone; trim per-artifact hash variants"
```

---

### Task B3: Delete `TODO.md`

**Files:**
- Delete: `TODO.md`

- [ ] **Step 1: Delete the file**

Run:
```sh
git rm TODO.md
```

- [ ] **Step 2: Commit**

```sh
git commit -m "docs: remove TODO.md (project state, not documentation)"
```

---

### Task B4: Rewrite the SHA-256-by-hand section in `MANUAL_RECOVERY.md`

**Files:**
- Modify: `MANUAL_RECOVERY.md`

The file is ~1058 lines. The bulk of the size is the SHA-256-by-hand walkthrough — the spec calls for removing it and replacing with a 30-line "skip the checksum" section.

- [ ] **Step 1: Read the file once to locate the SHA-256 section**

Open `MANUAL_RECOVERY.md`. The section to remove starts around line 473 (`The chela tool uses SHA-256 to figure out which is right…`) and runs through the end of the SHA-256 walkthrough — read the file to find the exact boundaries.

- [ ] **Step 2: Replace the SHA-256-by-hand section**

Delete every line from the section heading that introduces SHA-256 hand-computation through the end of the worked SHA-256 verification example. Replace with the following:

```markdown
### Step N: Discard the last two checksum bytes

The last 2 bytes of each share's bit stream are a SHA-256 checksum. The chela
recovery tool verifies them automatically; **doing it by hand is not feasible**
(one SHA-256 hash is a full day's work with paper and pencil).

For manual recovery, the procedure is:

1. Confirm the 4-hex identifier (`<ID>`) is the same on every card you have.
   Cards with different identifiers come from different splits; mixing them
   recovers garbage.
2. Once you have the bit stream for one share, take the last 16 bits (2 bytes)
   off the end and **discard them**. The remaining bytes are the share payload
   that goes into Lagrange combination.
3. Continue with the next step (Lagrange interpolation).

If you have any doubt about a card, type its words back into the chela tool
later — the tool will verify the checksum and tell you exactly which share is
corrupt. Manual recovery without the tool trusts the words; the tool catches
typos.
```

(Adjust "Step N:" to whatever the next numbered step is in the surrounding context.)

- [ ] **Step 3: Update any worked example that included SHA-256 verification**

If the worked example downstream of this section walks through computing SHA-256 of a sample share, drop those compute-by-hand lines but keep the surrounding Lagrange example. The final recovered secret should remain the same.

- [ ] **Step 4: Verify the file is still well-formed Markdown**

Open it in a Markdown previewer (or `glow MANUAL_RECOVERY.md` / `mdcat MANUAL_RECOVERY.md`) and confirm the section headers still flow, no orphan numbered list items, no broken cross-references.

- [ ] **Step 5: Commit**

```sh
git add MANUAL_RECOVERY.md
git commit -m "docs(manual recovery): skip SHA-256-by-hand; checksum verification stays in the tool"
```

---

### Task B5: Slim `SPEC.md`

**Files:**
- Modify: `SPEC.md`

The spec calls for slimming SPEC.md to roughly 60% of current length by dropping justification prose. The wire-format tables and normative rules stay.

- [ ] **Step 1: Identify keep / drop sections**

Keep verbatim (these are normative):
- Section 1.1 SHA-256 (already one paragraph)
- Section 1.2 GF(2^8) — the algorithm, KAT, and reference
- Section 1.3 BIP-39 wordlist
- Section 2 Bundle layout — tables and rules
- Section 3 Shamir split / combine — formulas and rules
- Section 4 Share encoding (BIP-39 wordlist scheme) — bit-packing, checksum, word-count ambiguity
- Section 5 Wire formats — share text, JSON, HTML embedding
- Section 6 Wire-format normative rules — MUST / MAY list
- Section 7 Test vectors
- Section 8 Versioning
- Section 9 Out of scope

Drop in this pass:
- Any paragraph that justifies a decision in prose ("Pay-off:", "We chose this because…", trade-off discussion). Justification belongs in `AUDITORS.md`.
- The "Quick reference" intro paragraph if it duplicates table content.
- Per-section closing summaries.

- [ ] **Step 2: Apply the cuts**

Walk SPEC.md top to bottom; delete the paragraphs identified in step 1. Keep every table, every formula, every KAT, every MUST / MAY rule.

- [ ] **Step 3: Verify**

Run:
```sh
wc -l SPEC.md
```
Target: roughly 60% of the original 363 lines (so ~210 lines, give or take). If you're far from target either way, re-check whether you dropped too much (re-check § 2-§ 6 are intact) or too little (more prose to cut).

Confirm the file still defines a complete, implementable wire format — an engineer who reads only this file should be able to write a compatible implementation.

- [ ] **Step 4: Commit**

```sh
git add SPEC.md
git commit -m "docs(spec): drop justification prose; keep normative rules and tables"
```

---

### Task B6: Rewrite `AGENTS.md`

**Files:**
- Modify: `AGENTS.md` (full rewrite)

New purpose (from spec § 4): reference for an AI agent that a user has pointed at the repo to verify chela is secure and well packaged. Not a contributor guide.

- [ ] **Step 1: Overwrite the file**

Replace the entire contents of `AGENTS.md` with the following skeleton, then fill in the audit queries from the current file (they already exist — they're scattered through the old AGENTS.md and AUDITORS.md):

```markdown
# AGENTS.md — auditing chela with an AI agent

You have been pointed at the chela repository and asked to verify it is secure
and well packaged. This file tells you what to check and how to check it.

chela splits a BIP-39 wallet seed or short password into N shares; any M of them
recover the original. The cryptographic core is in-tree — no third-party crates
beyond the OS RNG. A human auditor uses `AUDITORS.md` to walk the codebase; this
file is for an agent that can run shell commands.

## Repo orientation

```
chela-primitives/   SHA-256, ct_eq, volatile zeroize, OS RNG
chela-field/        constant-time GF(2^8)
chela-sss/          Shamir split / combine
chela-bip39/        BIP-0039 codec + English wordlist
chela-share/        share text format + paper-backup HTML
chela-engine/       bundle codec + split / recover orchestration
chela-tui/          interactive wizard binary
chela-cli/          scriptable CLI binary
chela-wasm/         no_std FFI for the browser bundle
chela-bundle/       builds the standalone chela.html
```

`chela-share/fuzz/` is excluded from the main workspace. It depends on
`libfuzzer-sys` — the only crates.io dep in the repo, test-harness-only.

## Security checks

### No crates.io dependencies in the cryptographic core

```sh
grep '^name = ' Cargo.lock | sort -u
```
Expected: only workspace members. Any third-party crate is a finding.

### unsafe_code is denied workspace-wide

```sh
grep -rn '#!\[forbid(unsafe_code)\]\|#!\[deny(unsafe_code)\]\|allow(unsafe_code)' chela-*/src
```
Expected: every opt-in is module-level `#[allow(unsafe_code)]` in one of:
- `chela-primitives/src/rng.rs` (OS RNG syscall externs)
- `chela-primitives/src/zeroize.rs` (`core::ptr::write_volatile`)
- `chela-sss/src/lib.rs` (one cast to wipe polynomial coefficients)
- `chela-tui/src/term.rs` (termios FFI)
- `chela-wasm/src/lib.rs` (linear-memory slice FFI)

Each `unsafe` block must carry a `// SAFETY:` comment.

### Secret-bearing buffers are wiped via volatile_set

```sh
grep -rn 'volatile_set\|\.zeroize()\|impl Drop' chela-*/src
```
Plain `fill(0)` or `= [0; N]` on a buffer that held secret bytes is a finding —
the optimiser may elide either. `chela-primitives::zeroize::volatile_set` is
the only sanctioned wipe.

### Crypto test vectors come from a primary source

Every `#[test]` involving cryptographic output should either cite its source
(FIPS 180-2, FIPS 197, BIP-39, NIST CAVP) in the test name or a comment, or be
a property test. Spot-check ten tests.

### Pinned third-party GitHub Actions

```sh
grep -rn 'uses:' .github/workflows/
```
Expected: every `uses:` value is a 40-character commit SHA, not `@v4` or
`@stable`. Trailing `# tag` comment is informational.

## Packaging checks

### Release signing

`.github/workflows/release.yml` signs every artifact with minisign and produces
a signed `SHA256SUMS` aggregate. The public key is in `README.md`.

### Reproducible builds

The release workflow builds every binary twice in independent target
directories and fails if they hash-differ. Pre-conditions (deterministic linker
flags, `SOURCE_DATE_EPOCH`) live in `release.yml` and `Cargo.toml`.

### Pre-push hook

`scripts/git-hooks/pre-push` runs the CI matrix locally before push. Mirrors
`.github/workflows/ci.yml` step for step.

### Fuzz harness

`chela-share/fuzz/` fuzzes the share-text parser, the only externally-supplied
input. A smoke run executes on every PR via `.github/workflows/fuzz.yml`.

## What this file is not

- A contributor onboarding guide. See `CONTRIBUTING.md`.
- A code walkthrough. See `AUDITORS.md`.
- The wire-format spec. See `SPEC.md`.
```

- [ ] **Step 2: Verify no stray "D1..D8" or "load-bearing" references survived**

Run:
```sh
grep -nE 'D[1-9]\b|load-bearing|Pay-off|Why split' AGENTS.md
```
Expected: no output.

- [ ] **Step 3: Commit**

```sh
git add AGENTS.md
git commit -m "docs(agents): reframe as AI-agent audit reference; drop contributor framing"
```

---

### Task B7: Restructure `AUDITORS.md`

**Files:**
- Modify: `AUDITORS.md` (restructure, content mostly preserved)

New purpose (from spec § 5): an auditor sits with the repo open and reads top to bottom. By the end they have read every crypto source file and understand why each decision was made.

- [ ] **Step 1: Move content into the new shape**

Replace `AUDITORS.md` with this structure. Where the current file has the same content, paste it in (mostly the threat model, the unsafe table, the zeroize table, the release-verification commands). The reading list and per-file rationale are new wrapping prose:

```markdown
# AUDITORS.md — reading chela end-to-end

You're here to convince yourself chela's cryptographic core does what it
claims, and that the claims are sound. The fastest path is to open every file
in `chela-primitives/`, `chela-field/`, `chela-sss/`, `chela-bip39/`, and
`chela-engine/` in the order below and read them with this document in the
other window.

## Threat model

[paste the existing "## Threat model" section verbatim from the current AUDITORS.md]

## Reading order

Read the files in this order. Each section tells you what the file does, the
spec it implements, what to verify yourself, and the reasoning behind any
choice that isn't obvious from the spec.

### 1. `chela-primitives/src/sha256.rs` — SHA-256

Implements FIPS 180-4 § 6.2.

- The 8 initial hash values, the 64 round constants, the message schedule, and
  the compression function should all match the FIPS document verbatim.
- The `impl Drop` block wipes the 64-byte input buffer and the 8-word state.
  The 256-byte message schedule `w` is wiped at the end of `compress` (a stack
  variable; relies on `volatile_set`).
- Test vectors: empty string, "abc", 56-byte, 112-byte, 1M-of-'a' — FIPS 180-2
  App B + NIST CAVP. Confirm the literal expected digests against the FIPS
  document; do not trust the file's annotations alone.

Working variables `a..h` (32 bytes on the stack) are not wiped after each
compression call — they're overwritten on the next call but remain in stack
memory between calls. Documented limitation.

### 2. `chela-primitives/src/ct.rs` — constant-time equality

One function (`ct_eq`) — the standard XOR-OR-reduce idiom. Verify it compiles
to a constant-time sequence in release builds (no early return).

### 3. `chela-primitives/src/zeroize.rs` — volatile wipe

`volatile_set` is `core::ptr::write_volatile` per byte plus a
`compiler_fence(SeqCst)`. The fence is the load-bearing part — without it the
compiler can elide the writes since the buffer is "dead" after the call.

Plain `.fill(0)` is forbidden and not present anywhere in `chela-*/src` that
touches a secret-bearing buffer. Audit query:
```sh
grep -rn '\.fill(0)' chela-*/src
```
Any hit must operate on a non-secret buffer.

### 4. `chela-primitives/src/rng.rs` — OS RNG

Per-platform syscalls. macOS: `getentropy` in 256-byte chunks. Linux:
`getrandom` looping on short reads. Windows: `BCryptGenRandom`. wasm32: a JS
host import `chela.random_bytes(ptr, len) -> i32` that the embedder wires to
`crypto.getRandomValues`. No fallback on unsupported targets — `RngError::Unsupported`.

`OsRng` is the only entropy source. Confirm:
```sh
grep -rn 'thread_rng\|rand::\|OsRng::default' chela-*/src
```
Must be empty.

### 5. `chela-field/src/gf256.rs` — constant-time GF(2^8)

Add is XOR. Multiply is 8 unconditional rounds of mask-driven shift + mask-
driven reduction mod `0x11b` (Rijndael polynomial, AES). Inverse via the
fixed-shape squaring chain `x^254` (Fermat in GF(2^8) since `|F*| = 255`).
`inv(0) == 0` is intentional so `inv` is total — callers must ensure `x = 0`
never reaches Lagrange (`chela-sss::combine` rejects it).

No tables. Tables would leak data-dependent timing via the CPU cache.

KAT: `mul(0x57, 0x83) = 0xc1` — FIPS 197 § 4.1.

### 6. `chela-sss/src/lib.rs` — Shamir split / combine

`split` samples fresh coefficients per byte position from the injected
`RandomSource`. The `rng.fill_random` call sits inside the per-byte loop, so
each byte gets independent coefficients.

`combine` rejects duplicate x-coordinates and `x = 0` (the secret's
coordinate). Lagrange interpolation at `x = 0`: compute the coefficients once,
then apply per byte.

Allocation-free — callers pass in `out_x: &mut [u8]` and
`out_shares: &mut [&mut [u8]]`. Allocation lives one level up in `chela-engine`,
which always has a real allocator. Cost: std callers have to build a
`Vec<&mut [u8]>` of slice refs.

### 7. `chela-bip39/src/lib.rs` — BIP-0039 codec

Entropy ↔ 11-bit indices with the BIP-39 checksum byte (top `checksum_bits`
bits of `SHA-256(entropy)`). Implements BIP-39 § 4 verbatim. Vectors come from
the Trezor python-mnemonic `vectors.json` (12/18/24-word) and derived 15/21-word
zero-entropy cases.

### 8. `chela-bip39/src/wordlist.rs` — vendored English wordlist

2048 words, in order, verbatim from BIP-0039. Verify against the canonical
hash `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`:

```sh
diff \
  <(curl -sL https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt) \
  <(awk -F'"' '/^    "/ {print $2}' chela-bip39/src/wordlist.rs)
```

### 9. `chela-engine/src/lib.rs` — bundle codec, identifier, per-share checksum

The orchestration layer. Five things matter here:

1. **What SSS splits is just the body.** No magic byte, no in-bundle version,
   no in-bundle kind tag, no in-bundle checksum. For BIP-39: raw entropy
   followed by optional passphrase bytes. For text: raw UTF-8.
2. **The 16-bit identifier is `SHA-256(body || kind_byte)[..2]`.** `kind_byte`
   is a 1-byte tag (payload type × entropy length × passphrase presence) mixed
   into the hash but never written into the body. At recover time the engine
   enumerates the ≤11 candidate `kind_byte` values that fit the observed body
   length, recomputes the identifier, and picks the match. False-positive rate
   ≈ 11/65 536.
3. **The 16-bit per-share checksum is `SHA-256(share || identifier || x)[..2]`.**
   Without it, a single transcription error propagates through Lagrange into a
   wrong but identifier-validating secret. Binding to `identifier` and `x`
   also catches a card swapped between positions of the same split, or between
   two splits.
4. **Word-count ambiguity.** Several byte counts pack into the same 11-bit
   word count (e.g. 36 and 37 bytes both pack into 27 words). Recovery
   enumerates the candidate byte counts and picks the one whose per-share
   checksum verifies for every share.
5. **Allocation lives here, not in `chela-sss`.** The engine builds the
   `Vec<&mut [u8]>` of slice refs that `chela-sss::split` needs.

### 10. `chela-share/` — share text format + JSON + paper-backup HTML

`parse_share` / `parse_shares` is the only parser that ingests externally-
supplied text. Fuzzed via `chela-share/fuzz`; a smoke run executes on every
PR. The `is_ascii()` guard at the byte slice in `parse_share` is load-bearing —
its absence is what the fuzz harness originally tripped.

`html::render_paper_html` produces a single self-contained HTML document with
embedded CSS. The user prints to PDF from the browser. A PDF library would
have pulled in dependencies; static HTML survives offline indefinitely.

The JSON share schema (`chela.share.v1` / `chela.shares.v1`) is documented in
`SPEC.md` § 5.2.

### 11. `chela-wasm/src/lib.rs` — browser FFI

`no_std` + `alloc`. Exposes a C-ABI a HTML/JS page calls to split secrets,
recover them, and render paper backups. Five `unsafe` blocks (the only ones in
this crate), each with a `// SAFETY:` comment. `impl Drop` on every
secret-bearing request type; `chela_dealloc` volatile-wipes every buffer it
frees.

## Cross-cutting concerns

### Secret-bearing buffers and where they're wiped

[paste the existing § 5 / S3 table verbatim, dropping the "S3" framing in the
section title]

### The five `unsafe` opt-ins

[paste the existing § 4 table verbatim]

### No crates.io dependencies

[paste the existing § S7 audit command]

## Release verification

[paste the existing § 6 verbatim]
```

- [ ] **Step 2: Fill in the placeholder `[paste …]` blocks**

Open the original `AUDITORS.md` (or recover via `git show HEAD~N:AUDITORS.md` if already committed) and paste in the threat model, the zeroize table, the unsafe table, the no-deps audit, and the release verification block. Drop the "S1..S7" / "load-bearing" framing.

- [ ] **Step 3: Verify framing is clean**

Run:
```sh
grep -nE '\bS[1-9]\b|\bD[1-9]\b|load-bearing|trade-offs we accept' AUDITORS.md
```
Expected: no output. (`grep` may match "S3" or similar inside e.g. `SeqCst` — eyeball the hits and only delete the rhetorical ones; keep the technical ones.)

- [ ] **Step 4: Commit**

```sh
git add AUDITORS.md
git commit -m "docs(auditors): restructure as a file-by-file walkthrough"
```

---

## Phase C — Source prose pass

Common ground for every Phase C task. Apply these rules to every `.rs` file in the targeted crate:

1. Module / file docstring: collapse to one sentence. No headers, no multi-paragraph essays.
2. Function `///` docstrings on internal items: keep only if the function does something non-obvious. Public items can keep terse one-liners.
3. Inline `//` comments: delete those that restate the code. Keep notes about hidden invariants. Every `// SAFETY:` block is preserved verbatim. Every comment that justifies a zeroize call is preserved.
4. Cross-references (`// see AGENTS.md § X`, `// See AUDITORS.md`, `// See SPEC.md`): delete the cross-reference. The information stays in the doc; the per-line reminder goes.
5. Section dividers (`// ---`, `// === Foo ===` inside code): delete.
6. Marketing-style phrases — delete every instance:
   - "Pay-off:"
   - "Why split:" (when not a function name)
   - "load-bearing"
   - "trade-offs we accept for"
   - "by construction"
   - "Bias toward action"
   - Aphorisms like "If termios isn't available…" intro paragraphs
7. Numbered design-decision references (D1..D8, S1..S7): delete the numbers; if the surrounding sentence makes sense without them, keep the sentence.
8. Test names: keep. They're descriptive.

After every prose pass:
```sh
cargo fmt --all
cargo test -p <crate>
cargo clippy -p <crate> --all-targets --all-features -- -D warnings
```
All three must pass. If `cargo test` fails on a doctest after a prose edit, the doctest used a comment that was actually load-bearing — restore it.

---

### Task C1: Prose pass — `chela-primitives`

**Files:**
- Modify: `chela-primitives/src/lib.rs`, `ct.rs`, `rng.rs`, `sha256.rs`, `zeroize.rs`
- Modify: `chela-primitives/Cargo.toml` (drop AI-flavored comments)

- [ ] **Step 1: Read each file end to end first**

Don't start editing until you've seen every file. Crypto code can have non-obvious comments that look chatty but document a real constraint.

- [ ] **Step 2: Apply the rules from the Phase C intro to each file**

Specific things to look for in `chela-primitives`:
- `rng.rs` has a long header comment about per-platform syscall choices — collapse, but keep the per-platform syscall name itself in a comment.
- `zeroize.rs` has commentary on why `volatile_set` over `fill(0)` — keep the **reason**, slim the prose.
- `sha256.rs` has commentary on the working-variables wipe limitation — keep verbatim (it's an audit-facing limitation note).
- `ct.rs` has commentary on the constant-time idiom — keep one sentence.

- [ ] **Step 3: Run the verification trio**

```sh
cargo fmt --all
cargo test -p chela-primitives
cargo clippy -p chela-primitives --all-targets --all-features -- -D warnings
```

- [ ] **Step 4: Commit**

```sh
git add chela-primitives/
git commit -m "chela-primitives: prose pass"
```

---

### Task C2: Prose pass — `chela-field`

**Files:**
- Modify: `chela-field/src/lib.rs`, `gf256.rs`
- Modify: `chela-field/Cargo.toml`

- [ ] **Step 1: Apply Phase C rules**

`gf256.rs` has notes on why GF is constant-time and not table-based — keep one sentence (it's a security claim).

- [ ] **Step 2: Verify**

```sh
cargo fmt --all
cargo test -p chela-field
cargo clippy -p chela-field --all-targets --all-features -- -D warnings
```

- [ ] **Step 3: Commit**

```sh
git add chela-field/
git commit -m "chela-field: prose pass"
```

---

### Task C3: Prose pass — `chela-sss`

**Files:**
- Modify: `chela-sss/src/lib.rs`
- Modify: `chela-sss/Cargo.toml`

- [ ] **Step 1: Apply Phase C rules**

Things to preserve in `chela-sss/src/lib.rs`:
- The `// SAFETY:` block on the `wipe_coeffs` cast — verbatim.
- The comment explaining why the file is allocation-free / why allocation lives in `chela-engine` — keep the reason, drop the "load-bearing" framing.

- [ ] **Step 2: Verify**

```sh
cargo fmt --all
cargo test -p chela-sss
cargo clippy -p chela-sss --all-targets --all-features -- -D warnings
```

- [ ] **Step 3: Commit**

```sh
git add chela-sss/
git commit -m "chela-sss: prose pass"
```

---

### Task C4: Prose pass — `chela-bip39`

**Files:**
- Modify: `chela-bip39/src/lib.rs`, `wordlist.rs`
- Modify: `chela-bip39/Cargo.toml`

- [ ] **Step 1: Apply Phase C rules**

`wordlist.rs` — DO NOT edit the wordlist itself. Only the file-level docstring is in scope (and even that should keep the canonical SHA-256 of the wordlist as a comment, since auditors verify against it).

`lib.rs` — the BIP-39 § 4 reference in comments stays; it's the citation.

- [ ] **Step 2: Verify**

```sh
cargo fmt --all
cargo test -p chela-bip39
cargo clippy -p chela-bip39 --all-targets --all-features -- -D warnings
```

- [ ] **Step 3: Commit**

```sh
git add chela-bip39/
git commit -m "chela-bip39: prose pass"
```

---

### Task C5: Prose pass — `chela-share`

**Files:**
- Modify: `chela-share/src/lib.rs`, `export.rs`, `html.rs`, `import.rs`, `json.rs`
- Modify: `chela-share/Cargo.toml`

- [ ] **Step 1: Apply Phase C rules**

Things to preserve:
- The `is_ascii()` guard comment in `import.rs` (the parser's load-bearing safety check) — keep the reason, drop the "load-bearing" word.
- The XSS escape comments around `<` in JSON serialization (`json.rs`) — keep verbatim, that's documenting a defence.

- [ ] **Step 2: Verify**

```sh
cargo fmt --all
cargo test -p chela-share
cargo clippy -p chela-share --all-targets --all-features -- -D warnings
```

- [ ] **Step 3: Commit**

```sh
git add chela-share/
git commit -m "chela-share: prose pass"
```

---

### Task C6: Prose pass — `chela-engine`

**Files:**
- Modify: `chela-engine/src/lib.rs`
- Modify: `chela-engine/Cargo.toml`

- [ ] **Step 1: Apply Phase C rules**

`chela-engine/src/lib.rs` is the highest-density target — 844 lines, lots of "See AGENTS.md § D7" / "See AGENTS.md § D11" cross-refs. Delete every one of those cross-refs. Keep the substantive comments that explain what each function does in a single line.

Specific things to preserve:
- The `// Pre-size `body` to its final length so `extend_from_slice` cannot trigger a Vec reallocation.` comment block in `build_bundle` (documents a zeroize-correctness invariant — the entire reason for the pre-size). Keep verbatim minus the "Pay-off:" / "load-bearing" framing if present.
- The word-count-ambiguity comment in `recover_secret`. Keep the reason, slim the prose.
- The `expect("…")` strings — those are visible at panic time; keep meaningful, drop chatty.

- [ ] **Step 2: Verify**

```sh
cargo fmt --all
cargo test -p chela-engine
cargo clippy -p chela-engine --all-targets --all-features -- -D warnings
```

- [ ] **Step 3: Commit**

```sh
git add chela-engine/
git commit -m "chela-engine: prose pass"
```

---

### Task C7: Prose pass — `chela-tui`

**Files:**
- Modify: `chela-tui/src/main.rs`, `screen.rs`, `term.rs`, `wizard.rs`
- Modify: `chela-tui/Cargo.toml`

- [ ] **Step 1: Apply Phase C rules**

`chela-tui` is the largest crate by source lines (2400+). Most of that is wizard flow, not comments — the actual prose to cut is smaller than the line count suggests.

Things to preserve:
- The `// SAFETY:` block in `term.rs::raw_termios` — verbatim.
- The "hybrid TUI" rationale, IF a comment block explains why the menu is in raw mode but the wizards aren't — keep the reason, slim.
- The recovery-reveal alt-screen rationale (scrollback hygiene) — keep.

DO NOT change wizard UI text strings. Anything inside `print!`, `println!`, `eprint!`, `eprintln!`, or `writeln!(out, …)` that produces user-facing output is out of scope.

- [ ] **Step 2: Verify**

```sh
cargo fmt --all
cargo test -p chela-tui
cargo clippy -p chela-tui --all-targets --all-features -- -D warnings
```

- [ ] **Step 3: Commit**

```sh
git add chela-tui/
git commit -m "chela-tui: prose pass"
```

---

### Task C8: Prose pass — `chela-cli`

**Files:**
- Modify: `chela-cli/src/main.rs`
- Modify: `chela-cli/Cargo.toml`
- Modify: `chela-cli/tests/e2e.rs` (only top-level / module comments)

- [ ] **Step 1: Apply Phase C rules**

DO NOT change CLI output text (printed strings, help text, error messages — those are user-facing).

The `argv copies in the OS process listing still leak — CLI-inherent` comment in `chela-cli` is a documented limitation; keep verbatim.

- [ ] **Step 2: Verify**

```sh
cargo fmt --all
cargo test -p chela-cli
cargo clippy -p chela-cli --all-targets --all-features -- -D warnings
```

- [ ] **Step 3: Commit**

```sh
git add chela-cli/
git commit -m "chela-cli: prose pass"
```

---

### Task C9: Prose pass — `chela-wasm`

**Files:**
- Modify: `chela-wasm/src/lib.rs`, `json.rs`, `request.rs`
- Modify: `chela-wasm/Cargo.toml`

- [ ] **Step 1: Apply Phase C rules**

`chela-wasm/src/lib.rs` has five `unsafe` blocks — every `// SAFETY:` comment is preserved verbatim. The `impl Drop` blocks on request types are load-bearing for zeroize; their comments stay.

- [ ] **Step 2: Verify**

```sh
cargo fmt --all
cargo test -p chela-wasm
cargo clippy -p chela-wasm --all-targets --all-features -- -D warnings
```

Also confirm the wasm target still builds:
```sh
cargo build --target wasm32-unknown-unknown -p chela-wasm
```

- [ ] **Step 3: Commit**

```sh
git add chela-wasm/
git commit -m "chela-wasm: prose pass"
```

---

### Task C10: Prose pass — `chela-bundle`

**Files:**
- Modify: `chela-bundle/src/main.rs`, `build.rs`
- Modify: `chela-bundle/Cargo.toml`

This crate was already authored in Phase A with the prose rules in mind, but re-check.

- [ ] **Step 1: Apply Phase C rules**

The `WASM_PLACEHOLDER` constant has a comment in the original chela-serve copy explaining why it's a constant — slim or delete; the constant name is self-documenting.

- [ ] **Step 2: Verify**

```sh
cargo fmt --all
cargo test -p chela-bundle
cargo clippy -p chela-bundle --all-targets --all-features -- -D warnings
```

- [ ] **Step 3: Commit**

```sh
git add chela-bundle/
git commit -m "chela-bundle: prose pass"
```

---

### Task C11: Prose pass — workspace `Cargo.toml` and `RECOVERY.md`

**Files:**
- Modify: `Cargo.toml` (workspace-level comments)
- Modify: `RECOVERY.md` (light pass)

- [ ] **Step 1: Slim the workspace `Cargo.toml` comments**

The workspace `Cargo.toml` has comment blocks explaining the `unsafe_code` lint, the per-crate opt-ins, the release profile choices (panic-unwind to preserve `Drop`, codegen-units, etc.). Apply rules:
- The lint comments: collapse to one sentence per group.
- The release-profile comment about `panic = "unwind"`: keep verbatim — it documents a security-relevant choice.
- The exclude comment about `chela-share/fuzz`: collapse to one sentence.
- The "build / run lives in README.md" header comment: delete (it's not load-bearing).

- [ ] **Step 2: Light pass on `RECOVERY.md`**

This file is user-facing — keep the friendly, instructional voice. Cuts to make:
- Any "Take your time" / "Don't worry" callouts: keep one, drop duplicates.
- Cross-references to other docs at the bottom: keep but ensure they're accurate post-cleanup (e.g. AUDITORS.md still exists, MANUAL_RECOVERY.md still exists).

- [ ] **Step 3: Verify**

```sh
cargo build --workspace
```
The workspace `Cargo.toml` changes shouldn't affect anything, but build to be safe.

- [ ] **Step 4: Commit**

```sh
git add Cargo.toml RECOVERY.md
git commit -m "workspace: prose pass on root Cargo.toml + RECOVERY.md"
```

---

## Phase D — Final verification

### Task D1: Run the full verification matrix

**Files:** none modified.

- [ ] **Step 1: Format check**

```sh
cargo fmt --all --check
```
Expected: no output (exit 0).

- [ ] **Step 2: Clippy across the workspace**

```sh
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
Expected: no warnings.

- [ ] **Step 3: Full test suite**

```sh
cargo test --workspace
```
Expected: every test passes.

- [ ] **Step 4: Wasm builds**

```sh
cargo build --target wasm32-unknown-unknown -p chela-primitives
cargo build --target wasm32-unknown-unknown -p chela-field
cargo build --target wasm32-unknown-unknown -p chela-sss
cargo build --target wasm32-unknown-unknown -p chela-bip39
cargo build --target wasm32-unknown-unknown -p chela-share
cargo build --target wasm32-unknown-unknown -p chela-engine
```
Expected: each succeeds.

- [ ] **Step 5: Bundle produces a working HTML**

```sh
cargo build --release -p chela-bundle
./target/release/chela-bundle /tmp/chela-final.html
test -s /tmp/chela-final.html && echo OK
```
Expected: `OK`. File should be roughly the same size as the baseline from Task A1 (within a few hundred bytes).

- [ ] **Step 6: Audit grep for AI-flavored prose**

Run each of these and look for surviving instances:
```sh
grep -rn 'load-bearing' chela-*/src AGENTS.md AUDITORS.md README.md SPEC.md RECOVERY.md MANUAL_RECOVERY.md RELEASING.md
grep -rn 'Pay-off' chela-*/src AGENTS.md AUDITORS.md README.md SPEC.md
grep -rn 'see AGENTS.md\|See AGENTS.md\|see AUDITORS.md\|See AUDITORS.md\|see SPEC.md\|See SPEC.md' chela-*/src
grep -rnE '\bD[1-9]\b' AGENTS.md
grep -rnE '\bS[1-9]\b' AUDITORS.md
```

Acceptable surviving hits:
- "load-bearing" inside a doc that explicitly defines it as a technical term (none expected).
- D1..D8 / S1..S7 only if they're inside a quote or example.
- "see X" cross-references in README / RELEASING are fine — those are user-facing.

For any remaining instance not on the allow-list, edit it out.

- [ ] **Step 7: Commit any cleanup from step 6**

```sh
git add -u
git diff --cached --stat
# If the diff is nontrivial:
git commit -m "final pass: remove remaining AI-flavored prose"
```

If step 6 produced no changes, nothing to commit — done.

---

## Notes for the implementer

- The plan is sized for a single sitting if you have the focus, or for two or three sittings split at the Phase boundaries. Phases are independent.
- If `cargo test --workspace` fails mid-task, stop, isolate, fix or revert. Do not move on with a red suite.
- The HTML asset move in Task A3 is a `cp` not a `mv` — the source survives until `chela-serve` is deleted in Task A8. If you skip A3 and try to delete chela-serve first, the new crate has no template.
- If you find yourself adding new comments during the prose pass, you're going the wrong direction. The pass is delete-only (with the exception of replacement docstrings the Phase A code blocks specify).
- One commit per task is the norm. Two commits in a task is fine if the diff is genuinely two unrelated edits.
