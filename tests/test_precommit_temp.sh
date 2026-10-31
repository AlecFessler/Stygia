#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/precommit_temp.sh"

test_root=$(mktemp -d)
trap 'precommit_temp_cleanup; rm -rf "$test_root"' EXIT
STYGIA_ROOT="$test_root/worktree"
mkdir -p "$STYGIA_ROOT"
precommit_temp_init
[[ "$TMPDIR" == "$STYGIA_ROOT/.precommit-tmp/"* ]]
[[ "$(mktemp)" == "$TMPDIR/"* ]]
run_dir="$TMPDIR"
precommit_temp_cleanup
[[ ! -e "$run_dir" ]]
PRECOMMIT_TMP_DIR=""

STYGIA_ROOT="$test_root/blocked"
printf 'not a directory' > "$STYGIA_ROOT"
if precommit_temp_init 2>"$test_root/error"; then
    echo "expected temp setup failure" >&2
    exit 1
fi
grep -q 'cannot create precommit temp directory' "$test_root/error"

if precommit_capture_log /dev/full printf 'serial bytes\n' 2>"$test_root/error"; then
    echo "expected log write failure" >&2
    exit 1
fi
grep -q 'could not write complete precommit log' "$test_root/error"
echo "precommit temp tests passed"
