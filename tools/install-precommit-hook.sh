#!/bin/sh
# Install the tracked pre-commit hook for this checkout without replacing
# another hook or changing the repository's hook directory.
set -eu

repo_root=$(git rev-parse --show-toplevel)
hook_path=$(git rev-parse --git-path hooks/pre-commit)
tracked_hook="$repo_root/.githooks/pre-commit"

if [ -n "$(git config --get core.hooksPath || true)" ]; then
    echo 'A custom core.hooksPath is configured; refusing to replace it.' >&2
    exit 1
fi
if [ -e "$hook_path" ] || [ -L "$hook_path" ]; then
    echo "A pre-commit hook already exists at $hook_path; refusing to replace it." >&2
    exit 1
fi
if [ ! -x "$tracked_hook" ]; then
    echo "Tracked hook is missing or not executable: $tracked_hook" >&2
    exit 1
fi

mkdir -p "$(dirname "$hook_path")"
# Hooks are shared by linked Git worktrees. Copy the wrapper so removing the
# worktree that ran this installer cannot leave a dangling hook; the wrapper
# resolves the worktree being committed at run time.
cp "$tracked_hook" "$hook_path"
chmod +x "$hook_path"
echo "Installed pre-commit hook at $hook_path"
