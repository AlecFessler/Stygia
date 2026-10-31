#!/usr/bin/env bash
# Regression for x64 pull-side stealing when other cores run idle-priority
# restart workers. Before the fix, the idle workers made their local queues
# nonempty, so scheduler_balance_01's normal-priority workers stayed on one
# core and its result timed out.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
zig_bin=${STYGIA_ZIG:-zig}
if [[ "$($zig_bin version)" != 0.15.2 ]]; then
    echo "Zig 0.15.2 is required" >&2
    exit 1
fi

(cd "$root/tests/suite" && "$zig_bin" build \
    -Dtests='scheduler_balance_01,snapshot_mixed_page_sizes' -Drepeat=10)
rm -rf "$root/zig-out"
(cd "$root" && "$zig_bin" build -Dprofile=test)

mkdir -p "$root/out/scheduler-idle-steal"
log=$(mktemp "$root/out/scheduler-idle-steal/run.XXXXXX.log")
(cd "$root" && timeout 180 "$zig_bin" build run -Dprofile=test) > "$log" 2>&1 || {
    cat "$log"
    echo "serial log preserved: $log" >&2
    exit 1
}

summary=$(tr -d '~' < "$log" | grep -E '^\[runner\] === aggregate over 10 runs:' | tail -1)
if [[ "$summary" != *'20 pass / 0 fail / 0 miss'* ]]; then
    cat "$log"
    echo "scheduler idle-steal regression failed: ${summary:-no aggregate summary}" >&2
    echo "serial log preserved: $log" >&2
    exit 1
fi
echo "$summary"
rm -f "$log"
