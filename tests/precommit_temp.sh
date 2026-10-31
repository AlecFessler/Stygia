#!/bin/bash
# Source this from precommit.sh after STYGIA_ROOT has been set.

precommit_temp_init() {
    local base="$STYGIA_ROOT/.precommit-tmp"
    if ! mkdir -p "$base"; then
        echo "error: cannot create precommit temp directory: $base" >&2
        return 1
    fi
    if ! PRECOMMIT_TMP_DIR=$(mktemp -d "$base/run.XXXXXXXX"); then
        echo "error: cannot allocate precommit temp directory in $base" >&2
        return 1
    fi
    export TMPDIR="$PRECOMMIT_TMP_DIR"
}

precommit_temp_cleanup() {
    if [[ -n "${PRECOMMIT_TMP_DIR:-}" ]]; then
        rm -rf -- "$PRECOMMIT_TMP_DIR"
    fi
}

precommit_new_log() {
    local log
    if ! log=$(mktemp); then
        echo "[FAIL] could not allocate precommit log in $TMPDIR" >&2
        return 1
    fi
    printf '%s\n' "$log"
}

# Check both the command and tee: a full filesystem can otherwise leave a
# truncated serial log while QEMU itself exits successfully.
precommit_capture_log() {
    local log="$1"
    shift
    "$@" 2>&1 | tee "$log" >/dev/null
    local statuses=("${PIPESTATUS[@]}")
    if [[ ${statuses[1]} -ne 0 ]]; then
        echo "[FAIL] could not write complete precommit log: $log" >&2
        return 1
    fi
    return "${statuses[0]}"
}
