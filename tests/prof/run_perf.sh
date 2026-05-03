#!/bin/bash
# Kernel-trace perf regression gate.
#
# For each workload:
#   1. Build tests/prof/bin/root_service.elf for that workload.
#   2. Build the kernel with `-Dkernel_profile=trace -Doptimize=ReleaseFast`
#      (ReleaseFast so the measured paths aren't dominated by safety
#      checks; the kernel build picks this by default when kprof is
#      enabled).
#   3. Boot in QEMU with -display none for a fixed window. The kernel's
#      rolling dump fires every time a per-CPU log fills, so a few
#      seconds is enough to get multiple [KPROF] begin…done cycles
#      into the serial capture.
#   4. Feed the capture through tests/prof/parse_kprof.py --json.
#   5. Compare the scope medians to the committed baseline under
#      tests/prof/baselines/<workload>.json.
#
# Flags:
#   --update-baseline   Overwrite baselines/<workload>.json with the
#                       current run. Use after an intentional perf
#                       change.
#   --compare-baseline  Default. Runs the workload, compares, exits
#                       non-zero on regression.
#
# Positional args are workload names. Default set (cheap + stable):
#   yield ipc fault spawn
#
# Rationale for trace over sampling: sampling only tells you where the
# CPU was when the timer fired; our question is "how did known
# scheduler/IPC/fault scopes change." Enter/exit pairs with PMU
# deltas answer that directly without post-hoc symbolization.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZAG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PARSE_KPROF="$SCRIPT_DIR/parse_kprof.py"
COMPARE="$SCRIPT_DIR/compare_baseline.py"
BASELINE_DIR="$SCRIPT_DIR/baselines"
CURRENT_DIR="$SCRIPT_DIR/current"

RUN_SECONDS="${RUN_SECONDS:-20}"
THRESHOLD="${THRESHOLD:-0.20}"

MODE="compare"
WORKLOADS=()
for arg in "$@"; do
    case "$arg" in
        --compare-baseline) MODE="compare" ;;
        --update-baseline) MODE="update" ;;
        --help|-h)
            sed -n '2,35p' "$0"
            exit 0
            ;;
        --*)
            echo "unknown flag: $arg" >&2
            exit 2
            ;;
        *) WORKLOADS+=("$arg") ;;
    esac
done

if [[ ${#WORKLOADS[@]} -eq 0 ]]; then
    WORKLOADS=(yield ipc fault spawn)
fi

mkdir -p "$BASELINE_DIR" "$CURRENT_DIR"

run_workload() {
    local workload="$1"
    echo ""
    echo "── workload: $workload ────────────────────────────────"

    if ! (cd "$SCRIPT_DIR" && zig build "-Dworkload=$workload"); then
        echo "[FAIL] prof build failed for $workload"
        return 1
    fi
    if ! (cd "$ZAG_ROOT" && zig build \
            -Dprofile=prof \
            -Dkernel_profile=trace \
            -Doptimize=ReleaseFast); then
        echo "[FAIL] kernel build failed for $workload"
        return 1
    fi

    # Boot for RUN_SECONDS, capturing serial. Killing QEMU truncates the
    # tail mid-record — that's fine, parse_kprof.py treats the last
    # incomplete [KPROF] begin…done pair as a warning, not an error,
    # and we only use fully-closed cycles for stats.
    local qemu_log
    qemu_log=$(mktemp)
    (cd "$ZAG_ROOT" && timeout --kill-after=5 "$RUN_SECONDS" \
        zig build run \
            -Dprofile=prof \
            -Dkernel_profile=trace \
            -Doptimize=ReleaseFast \
            -- -display none \
        > "$qemu_log" 2>&1) || true
    pkill -f "qemu-system-x86_64" 2>/dev/null || true

    if ! grep -q '^\[KPROF\] begin' "$qemu_log"; then
        echo "[FAIL] $workload: no [KPROF] begin lines in capture"
        tail -20 "$qemu_log"
        rm -f "$qemu_log"
        return 1
    fi

    local current_json="$CURRENT_DIR/$workload.json"
    if ! python3 "$PARSE_KPROF" "$qemu_log" --json > "$current_json"; then
        echo "[FAIL] $workload: parse_kprof --json failed"
        rm -f "$qemu_log"
        return 1
    fi
    rm -f "$qemu_log"

    local baseline_json="$BASELINE_DIR/$workload.json"
    if [[ "$MODE" == "update" ]]; then
        cp "$current_json" "$baseline_json"
        echo "[UPDATED] $baseline_json"
        return 0
    fi

    if [[ ! -f "$baseline_json" ]]; then
        echo "[FAIL] no baseline at $baseline_json."
        echo "       Bootstrap with: $0 --update-baseline $workload"
        return 1
    fi

    if python3 "$COMPARE" "$baseline_json" "$current_json" --threshold "$THRESHOLD"; then
        echo "[PASS] $workload"
        return 0
    else
        echo "[FAIL] $workload: regression vs baseline"
        return 1
    fi
}

FAILED=()
for w in "${WORKLOADS[@]}"; do
    if ! run_workload "$w"; then
        FAILED+=("$w")
    fi
done

echo ""
echo "================================================================"
if [[ ${#FAILED[@]} -eq 0 ]]; then
    echo "kprof regression gate: all ${#WORKLOADS[@]} workloads clean."
    exit 0
else
    echo "kprof regression gate FAILED on: ${FAILED[*]}"
    exit 1
fi
