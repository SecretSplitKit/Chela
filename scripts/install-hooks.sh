#!/usr/bin/env bash
#
# Install chela git hooks. Run once after cloning the repo.
#
# Sets up:
#   - .git/hooks/pre-push → scripts/git-hooks/pre-push (symlink)
#
# The pre-push hook runs the GitHub-Actions CI matrix locally so failures
# surface before you push, not after. See `scripts/git-hooks/pre-push`.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

src="scripts/git-hooks/pre-push"
dst=".git/hooks/pre-push"

if [ ! -f "$src" ]; then
  echo "error: $src not found — are you in the chela repo root?" >&2
  exit 1
fi

chmod +x "$src"

if [ -e "$dst" ] && [ ! -L "$dst" ]; then
  echo "warning: $dst exists and isn't a symlink — moving to $dst.bak" >&2
  mv "$dst" "$dst.bak"
fi

# Use a relative symlink so the hook keeps working after moving the worktree.
ln -sf "../../$src" "$dst"
echo "✓ installed $dst → $src"
echo "  Next push will run rustfmt + clippy + tests + wasm + docs. Skip with --no-verify."
