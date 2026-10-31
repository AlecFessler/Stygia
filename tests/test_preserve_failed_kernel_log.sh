#!/bin/bash
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/preserve_failed_kernel_log.sh"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
FAILED_KERNEL_LOG_DIR="$work_dir/failed runs"

for rep in $(seq 1 21); do
    source_log="$work_dir/raw-$rep"
    printf 'raw serial bytes for rep %s\n[runner] MISS snapshot_10\n' "$rep" > "$source_log"
    message=$(preserve_failed_kernel_log "$source_log" x86 "$rep")
    archived=${message#*raw log: }
    test -f "$archived"
    test ! -e "$source_log"
    cmp -s "$archived" <(printf 'raw serial bytes for rep %s\n[runner] MISS snapshot_10\n' "$rep")
done

test "$(find "$FAILED_KERNEL_LOG_DIR" -maxdepth 1 -type f -name '*.log' | wc -l)" -eq 20
test ! -e "$FAILED_KERNEL_LOG_DIR"/x86-rep1-*.log
printf '[PASS] failed kernel log retention and 20-log limit\n'
