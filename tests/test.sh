#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Defaults
TARGET="all"
PYTEST_K=""
PYTEST_FILE=""
FAIL_FAST=""
ITERATIONS="100000"
SEED="42"

usage() {
    cat <<'EOF'
Usage: ./test.sh [target] [options]

Targets:
  kernel          Run kernel integration tests (QEMU, 475 tests)
  router          Run router integration tests (pytest)
  linux           Boot Linux guest in hyprvOS (x86_64), verify shell prompt
  linux-arm       Boot Linux guest in hyprvOS (aarch64 TCG), verify 'hello from guest'
  genlock         Run gen-lock static analyzer (gates on err-severity findings)
  dead-code       Run dead-code static analyzer (gates on any findings)
  callgraph       Run callgraph_http + callgraph_mcp smoke tests against the per-commit DB
  pre-commit      Run genlock + dead-code + callgraph + kernel + linux + router (gate before commit)
  perf            Run kernel performance benchmarks (sequential)
  kernel-fuzz     Run all kernel fuzzers (buddy, heap, vmm, rbt)
  router-fuzz     Run router packet processing fuzzer
  all             Run kernel + linux + router tests (default)

Options:
  -h, --help        Show this help
  -k EXPR           Pass -k filter to pytest (router tests only)
  -f FILE           Run specific pytest file (router tests only)
  -x                Exit after first test failure (router tests only)
  --iterations N    Fuzzer iteration count (default: 100000)
  --seed N          Fuzzer seed (default: 42)

Examples:
  ./test.sh                              # run all tests
  ./test.sh kernel                       # kernel tests only
  ./test.sh router -k test_dns           # router DNS tests only
  ./test.sh router -f test_nat.py        # single test file
  ./test.sh router-fuzz --iterations 50000 --seed 123
EOF
}

# ── Argument parsing ──────────────────────────────────────────────────

# First positional arg is the target (if it doesn't start with -)
if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
    TARGET="$1"
    shift
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -k)
            PYTEST_K="$2"
            shift 2
            ;;
        -f)
            PYTEST_FILE="$2"
            shift 2
            ;;
        -x)
            FAIL_FAST="-x"
            shift
            ;;
        --iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        --seed)
            SEED="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# ── Network setup (router/router-fuzz/all) ───────────────────────────

ensure_network() {
    if ! ip link show tap0 &>/dev/null || ! ip link show tap1 &>/dev/null; then
        echo "tap0/tap1 not found — running network setup (requires sudo)..."
        sudo "$SCRIPT_DIR/routerOS/tests/setup_network.sh"
    fi
}

ensure_venv() {
    local venv="$SCRIPT_DIR/routerOS/tests/.venv"
    if [[ ! -d "$venv" ]]; then
        echo "Creating Python venv for router tests..."
        python3 -m venv "$venv"
        "$venv/bin/pip" install --quiet pytest pexpect
    fi
}

# ── Test runners ──────────────────────────────────────────────────────

clean_nvvars() {
    # Remove OVMF NvVars if root-owned (leftover from sudo passthrough tests)
    local nv="$SCRIPT_DIR/zig-out/img/NvVars"
    if [[ -f "$nv" ]] && [[ "$(stat -c %U "$nv" 2>/dev/null)" == "root" ]]; then
        rm -f "$nv"
    fi
}

run_kernel_tests() {
    echo "=== Kernel Tests ==="
    clean_nvvars
    PARALLEL="${PARALLEL:-8}" bash "$SCRIPT_DIR/tests/tests/run_tests.sh"
}

# Build the per-(arch, commit_sha) callgraph DB if it isn't present yet.
# Both genlock and dead-code analyzers consume it, so we share the build.
ensure_callgraph_db() {
    (cd "$SCRIPT_DIR/tools/indexer" && zig build) \
        || { echo "[FAIL] indexer build failed"; return 1; }

    local sha
    sha="$(cd "$SCRIPT_DIR" && git rev-parse --short HEAD)"
    CALLGRAPH_DB="$SCRIPT_DIR/tools/callgraph_http/test/dbs/x86_64-${sha}.db"

    if [[ ! -f "$CALLGRAPH_DB" ]]; then
        # Need .ll AND an x86_64-flavored kernel.elf. A previous
        # `-Darch=arm` build leaves an ARM ELF in zig-out/, which would
        # make objdump fail silently in the indexer's stage-4 pass.
        local need_rebuild=0
        if [[ ! -f "$SCRIPT_DIR/zig-out/kernel.x86_64.ll" || ! -f "$SCRIPT_DIR/zig-out/bin/kernel.elf" ]]; then
            need_rebuild=1
        elif ! file "$SCRIPT_DIR/zig-out/bin/kernel.elf" 2>/dev/null | grep -q "x86-64"; then
            echo "  zig-out/bin/kernel.elf is not x86_64 — rebuilding"
            need_rebuild=1
        fi
        if [[ $need_rebuild -eq 1 ]]; then
            echo "  building kernel with -Darch=x64 -Demit_ir=true (needed by indexer)"
            (cd "$SCRIPT_DIR" && zig build -Dprofile=test -Darch=x64 -Demit_ir=true) \
                || { echo "[FAIL] kernel build for IR/ELF failed"; return 1; }
        fi
        (cd "$SCRIPT_DIR" && tools/indexer/zig-out/bin/indexer \
            --kernel-root kernel \
            --extra-source-root routerOS \
            --extra-source-root hyprvOS \
            --extra-source-root bootloader \
            --extra-source-root tools \
            --extra-source-root tests \
            --out "$CALLGRAPH_DB" \
            --arch x86_64 \
            --commit-sha "$(git rev-parse HEAD)" \
            --ir zig-out/kernel.x86_64.ll \
            --elf zig-out/bin/kernel.elf) \
            || { echo "[FAIL] callgraph DB build failed"; return 1; }
    fi
}

run_genlock_check() {
    echo "=== Gen-lock Static Analyzer ==="
    (cd "$SCRIPT_DIR/tools/check_gen_lock" && zig build) \
        || { echo "[FAIL] check_gen_lock build failed"; return 1; }
    ensure_callgraph_db || return 1
    (cd "$SCRIPT_DIR" && tools/check_gen_lock/zig-out/bin/check_gen_lock --db "$CALLGRAPH_DB" --summary) \
        || { echo "[FAIL] gen-lock analyzer reported err-severity findings"; return 1; }
    echo "[PASS] gen-lock analyzer clean"
}

run_dead_code_check() {
    echo "=== Dead-code Analyzer ==="
    (cd "$SCRIPT_DIR/tools/dead_code_zig" && zig build) \
        || { echo "[FAIL] dead_code_zig build failed"; return 1; }
    # Fixture suite first — exercises the analyzer on synthetic trees
    # that don't depend on the kernel build.
    if ! bash "$SCRIPT_DIR/tools/dead_code_zig/test/run_tests.sh"; then
        echo "[FAIL] dead-code fixture suite failed"
        return 1
    fi
    ensure_callgraph_db || return 1
    local detector="$SCRIPT_DIR/tools/dead_code_zig/zig-out/bin/dead_code_zig"
    if ! (cd "$SCRIPT_DIR" && "$detector" --db "$CALLGRAPH_DB" --target kernel); then
        echo "[FAIL] dead-code analyzer findings"
        return 1
    fi
    echo "[PASS] dead-code analyzer clean"
}

run_callgraph_smokes() {
    echo "=== Callgraph HTTP + MCP smoke ==="
    (cd "$SCRIPT_DIR/tools/callgraph_http" && zig build) \
        || { echo "[FAIL] callgraph_http build failed"; return 1; }
    (cd "$SCRIPT_DIR/tools/callgraph_mcp" && zig build) \
        || { echo "[FAIL] callgraph_mcp build failed"; return 1; }
    ensure_callgraph_db || return 1
    if ! bash "$SCRIPT_DIR/tools/callgraph_http/test/smoke.sh" "$CALLGRAPH_DB"; then
        echo "[FAIL] callgraph_http smoke failed"
        return 1
    fi
    if ! bash "$SCRIPT_DIR/tools/callgraph_mcp/test/smoke.sh" "$CALLGRAPH_DB"; then
        echo "[FAIL] callgraph_mcp smoke failed"
        return 1
    fi
    echo "[PASS] callgraph daemons clean"
}

run_linux_boot_test() {
    echo "=== Linux VM Boot Test ==="
    clean_nvvars

    # Build the hyprvos profile in ReleaseSafe. A Debug-mode Zig codegen
    # issue in the kernel's in-kernel LAPIC MMIO path triggers a null-pointer
    # dereference in mmio_decode on the first guest LAPIC access, crashing
    # the kernel before Linux reaches userspace. ReleaseSafe still retains
    # runtime safety checks but avoids the bad codegen.
    (cd "$SCRIPT_DIR/hyprvOS" && zig build) || { echo "hyprvOS build failed"; return 1; }
    (cd "$SCRIPT_DIR" && zig build -Dprofile=hyprvos -Diommu=amd -Doptimize=ReleaseSafe) || { echo "kernel build failed"; return 1; }

    local qemu_log
    qemu_log=$(mktemp)
    (cd "$SCRIPT_DIR" && timeout 90 zig build run -Dprofile=hyprvos -Diommu=amd -Doptimize=ReleaseSafe -- -display none) > "$qemu_log" 2>&1 &
    local qemu_pid=$!

    local found=0
    for _ in $(seq 1 90); do
        if grep -q "=== Zag VM Shell ===" "$qemu_log" 2>/dev/null; then
            found=1
            break
        fi
        sleep 1
    done

    kill -TERM $qemu_pid 2>/dev/null || true
    pkill -f "qemu-system-x86_64" 2>/dev/null || true
    wait $qemu_pid 2>/dev/null || true

    if [[ $found -eq 1 ]]; then
        echo "[PASS] Linux booted to shell"
        rm -f "$qemu_log"
        return 0
    else
        echo "[FAIL] Linux did not reach shell within 90s"
        echo "--- last 30 lines of QEMU output ---"
        tail -30 "$qemu_log"
        echo "--- end ---"
        rm -f "$qemu_log"
        return 1
    fi
}

run_linux_boot_arm_test() {
    echo "=== Linux VM Boot Test (aarch64) ==="
    clean_nvvars

    (cd "$SCRIPT_DIR/hyprvOS" && zig build -Darch=arm) \
        || { echo "hyprvOS-arm build failed"; return 1; }
    (cd "$SCRIPT_DIR" && zig build -Darch=arm -Dprofile=hyprvos -Dkvm=false \
        -Doptimize=ReleaseSafe -Droot-service=hyprvOS/bin/hyprvOS-arm.elf) \
        || { echo "kernel arm build failed"; return 1; }

    local workdir qemu_log
    workdir=$(mktemp -d)
    qemu_log=$(mktemp)
    mkdir -p "$workdir/efi/boot"
    ln -s "$SCRIPT_DIR/zig-out/img/efi/boot/BOOTAA64.EFI" "$workdir/efi/boot/"
    ln -s "$SCRIPT_DIR/zig-out/img/kernel.elf" "$workdir/"
    cp "$SCRIPT_DIR/zig-out/img/NvVars" "$workdir/" 2>/dev/null || true
    cp "$SCRIPT_DIR/hyprvOS/bin/hyprvOS-arm.elf" "$workdir/root_service.elf"

    timeout 300 qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3 -m 2G \
        -bios /usr/share/AAVMF/AAVMF_CODE.fd \
        -serial stdio -display none -no-reboot \
        -machine accel=tcg -cpu cortex-a72 -smp cores=4 \
        -drive "file=fat:rw:$workdir,format=raw" \
        > "$qemu_log" 2>&1 &
    local qemu_pid=$!

    local found=0
    for _ in $(seq 1 300); do
        if grep -q "hello from guest" "$qemu_log" 2>/dev/null; then
            found=1
            break
        fi
        if ! kill -0 $qemu_pid 2>/dev/null; then break; fi
        sleep 1
    done

    kill -TERM $qemu_pid 2>/dev/null || true
    pkill -f "qemu-system-aarch64.*root_service.elf" 2>/dev/null || true
    wait $qemu_pid 2>/dev/null || true
    rm -rf "$workdir"

    if [[ $found -eq 1 ]]; then
        echo "[PASS] Linux booted to busybox init (aarch64)"
        rm -f "$qemu_log"
        return 0
    else
        echo "[FAIL] Linux did not reach 'hello from guest' within 300s"
        echo "--- last 50 lines of QEMU output ---"
        tail -50 "$qemu_log"
        echo "--- end ---"
        rm -f "$qemu_log"
        return 1
    fi
}

run_router_tests() {
    ensure_network
    ensure_venv

    echo "=== Building RouterOS ==="
    (cd "$SCRIPT_DIR/routerOS" && zig build -Dnic=e1000)
    zig build -Dprofile=router
    clean_nvvars

    echo "=== Router Integration Tests ==="
    local pytest_args=("-v")
    if [[ -n "$FAIL_FAST" ]]; then
        pytest_args+=("-x")
    fi
    if [[ -n "$PYTEST_K" ]]; then
        pytest_args+=("-k" "$PYTEST_K")
    fi
    if [[ -n "$PYTEST_FILE" ]]; then
        pytest_args+=("$SCRIPT_DIR/routerOS/tests/$PYTEST_FILE")
    else
        pytest_args+=("$SCRIPT_DIR/routerOS/tests/")
    fi
    "$SCRIPT_DIR/routerOS/tests/.venv/bin/pytest" "${pytest_args[@]}"
}

run_perf_tests() {
    echo "=== Performance Tests ==="
    clean_nvvars
    bash "$SCRIPT_DIR/ktests/perf/run_perf.sh"
}

run_kernel_fuzzers() {
    local fuzz_args=("--" "-s" "$SEED" "-i" "$ITERATIONS")
    local fuzzers=(buddy_allocator vmm)

    for fuzzer in "${fuzzers[@]}"; do
        echo "=== Fuzzing: $fuzzer ==="
        (cd "$SCRIPT_DIR/fuzzing/$fuzzer" && zig build fuzz "${fuzz_args[@]}")
    done
}

run_router_fuzzer() {
    echo "=== Router Fuzzer ==="
    (cd "$SCRIPT_DIR/fuzzing/router" && zig build run -- -s "$SEED" -i "$ITERATIONS")
}

# ── Dispatch ──────────────────────────────────────────────────────────

case "$TARGET" in
    kernel)
        run_kernel_tests
        ;;
    router)
        run_router_tests
        ;;
    linux)
        run_linux_boot_test
        ;;
    linux-arm)
        run_linux_boot_arm_test
        ;;
    perf)
        run_perf_tests
        ;;
    kernel-fuzz)
        run_kernel_fuzzers
        ;;
    router-fuzz)
        run_router_fuzzer
        ;;
    genlock)
        run_genlock_check || exit 1
        ;;
    dead-code)
        run_dead_code_check || exit 1
        ;;
    callgraph)
        run_callgraph_smokes || exit 1
        ;;
    pre-commit)
        # Required gate before any agent commits — fails fast on the first failure.
        run_genlock_check || exit 1
        run_dead_code_check || exit 1
        run_callgraph_smokes || exit 1
        run_kernel_tests || exit 1
        run_linux_boot_test || exit 1
        run_router_tests || exit 1
        ;;
    all)
        run_kernel_tests
        run_linux_boot_test
        run_router_tests
        ;;
    *)
        echo "Unknown target: $TARGET"
        usage
        exit 1
        ;;
esac

echo ""
echo "=== Done ==="
