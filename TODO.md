# chela TODO

## Before v1.0

1. **Generate the minisign keypair** off-CI on a machine you trust:

   ```sh
   minisign -G -p chela.pub -s minisign.key   # prompts for a passphrase
   ```

   Then:
   - Paste the contents of `chela.pub` into `README.md`, replacing the
     `RWQ_REPLACE_ME_WITH_ACTUAL_PUBLIC_KEY_AFTER_GENERATION` placeholder.
   - Install the `MINISIGN_PRIVATE_KEY` (full file contents) and
     `MINISIGN_PASSWORD` (passphrase) repo secrets under
     **Settings → Secrets and variables → Actions**.

   Full operator runbook in `RELEASING.md`.

2. **Cut the release.**

   ```sh
   git tag v1.0.0
   git push origin v1.0.0
   ```

   The `.github/workflows/release.yml` workflow builds every artifact twice,
   hash-diffs the two passes for reproducibility, signs each one + a
   `SHA256SUMS` aggregate with minisign, and publishes the lot to a GitHub
   release.
