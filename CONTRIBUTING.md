# Contributing

For non-trivial changes, open an issue first so we can align on approach before you
write code.

## One-time setup — install the pre-push hook

```sh
./scripts/install-hooks.sh
```

This installs a git pre-push hook that runs the same checks
[`.github/workflows/ci.yml`](./.github/workflows/ci.yml) runs on every push —
`cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`, the
wasm32 library build, and `cargo doc` with `RUSTDOCFLAGS=-D warnings`. Catches CI
failures locally so you don't push red. Skip in a pinch with
`git push --no-verify`.

## Pull requests

One change per PR. The pre-push hook covers the basics; the canonical command set
if you want to run things by hand:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

If you're touching crypto, add a test vector from a primary source (RFC, FIPS, BIP).
See [AGENTS.md](./AGENTS.md) for code conventions and [AUDITORS.md](./AUDITORS.md) for
load-bearing invariants you must not break.

## Issues

Search before filing. Include a reproducer for runtime bugs; cite the file path and
line number for code concerns.
