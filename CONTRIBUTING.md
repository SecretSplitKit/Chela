# Contributing

For non-trivial changes, open an issue first so we can align on approach before you
write code.

## Pull requests

One change per PR. Before opening, run:

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
