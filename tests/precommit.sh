#!/bin/bash
# Mega precommit: run the full cross-arch gauntlet before a commit.
#
# Stages:
#   0. arch layering lint          (grep — arch-specific / generic boundaries)
#   0b. dead-code report            (advisory — manual review)
#   0c. gen-lock analyzer           (gating — fat-pointer + bracketing invariants)
#   1. x86-64 kernel test suite   (KVM on this dev PC)
#   2. aarch64 kernel test suite  (KVM on the Pi 5 @ 192.168.86.106 via SSH)
#   3. hyprvOS Linux boot          (x86-64, KVM on this PC)
#   4. hyprvOS Linux boot          (aarch64, KVM on Pi via SSH)
#   5. red-team regression PoCs   (tests/redteam/run_all.sh)
#   6. kernel perf regression gate (tests/prof/run_perf.sh, kprof trace)
#
# Usage:
#   ./tests/precommit.sh
#
# Env knobs:
#   PARALLEL=8           # x86 kernel test concurrency (default 8)
#   PI_HOST=user@ip      # override Pi SSH target
#   PI_LIMIT=N           # cap aarch64 test count (default: all)
#   PI_TIMEOUT=N         # per-test timeout on Pi in seconds (default 15)

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZAG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PARALLEL="${PARALLEL:-8}"
PI_HOST="${PI_HOST:-alecfessler@192.168.86.106}"
PI_REMOTE_DIR="${PI_REMOTE_DIR:-\$HOME/zag-test}"
PI_LIMIT="${PI_LIMIT:-0}"
PI_TIMEOUT="${PI_TIMEOUT:-15}"

FAILURES=()

# ── Stage runners ─────────────────────────────────────────────────────

stage_arch_layering_lint() {
    echo ""
    echo "=================================================="
    echo "[0] Arch layering lint (grep)"
    echo "=================================================="
    local violations=0

    local up_leak
    up_leak=$(grep -rn 'zag\.arch\.dispatch' "$ZAG_ROOT/kernel/arch/x64" "$ZAG_ROOT/kernel/arch/aarch64" 2>/dev/null || true)
    if [[ -n "$up_leak" ]]; then
        echo "arch-specific code imports zag.arch.dispatch (must not):"
        echo "$up_leak"
        violations=$((violations + 1))
    fi

    local down_leak
    down_leak=$(grep -rln 'zag\.arch\.\(x64\|aarch64\)\.' "$ZAG_ROOT/kernel" "$ZAG_ROOT/bootloader" 2>/dev/null | grep -v '/kernel/arch/' || true)
    if [[ -n "$down_leak" ]]; then
        echo "generic code reaches into zag.arch.x64/aarch64 (must go through dispatch):"
        echo "$down_leak"
        violations=$((violations + 1))
    fi

    if [[ $violations -eq 0 ]]; then
        echo "[PASS] arch boundaries clean"
        return 0
    fi
    FAILURES+=("arch layering lint")
    return 1
}

# Build the per-(arch, commit_sha) callgraph DB if it isn't present yet.
# Both the dead-code analyzer and the gen-lock analyzer read from it.
ensure_callgraph_db() {
    if ! (cd "$ZAG_ROOT/tools/indexer" && zig build 2>&1); then
        FAILURES+=("callgraph indexer build")
        return 1
    fi
    local sha
    sha="$(cd "$ZAG_ROOT" && git rev-parse --short HEAD)"
    CALLGRAPH_DB="$ZAG_ROOT/tools/callgraph_http/test/dbs/x86_64-${sha}.db"
    if [[ -f "$CALLGRAPH_DB" ]]; then return 0; fi
    # Need .ll AND an x86_64-flavored kernel.elf. If a previous aarch64
    # build left an ARM ELF in zig-out/, the indexer's objdump pass would
    # fail silently and produce an empty bin_inst table.
    local need_rebuild=0
    if [[ ! -f "$ZAG_ROOT/zig-out/kernel.x86_64.ll" || ! -f "$ZAG_ROOT/zig-out/bin/kernel.elf" ]]; then
        need_rebuild=1
    elif ! file "$ZAG_ROOT/zig-out/bin/kernel.elf" 2>/dev/null | grep -q "x86-64"; then
        echo "  zig-out/bin/kernel.elf is not x86_64 — rebuilding"
        need_rebuild=1
    fi
    if [[ $need_rebuild -eq 1 ]]; then
        echo "  building kernel with -Darch=x64 -Demit_ir=true (needed by indexer)"
        if ! (cd "$ZAG_ROOT" && zig build -Dprofile=test -Darch=x64 -Demit_ir=true 2>&1); then
            FAILURES+=("kernel build for IR/ELF")
            return 1
        fi
    fi
    if ! (cd "$ZAG_ROOT" && tools/indexer/zig-out/bin/indexer \
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
        --elf zig-out/bin/kernel.elf 2>&1); then
        FAILURES+=("callgraph DB build")
        return 1
    fi
}

stage_dead_code_report() {
    echo ""
    echo "=================================================="
    echo "[0b] Dead-code detector (gating)"
    echo "=================================================="
    if ! (cd "$ZAG_ROOT/tools/dead_code_zig" && zig build 2>&1); then
        FAILURES+=("dead-code detector build")
        return 1
    fi
    if ! bash "$ZAG_ROOT/tools/dead_code_zig/test/run_tests.sh"; then
        FAILURES+=("dead-code fixture suite")
        return 1
    fi
    ensure_callgraph_db || return 1
    local detector="$ZAG_ROOT/tools/dead_code_zig/zig-out/bin/dead_code_zig"
    if ! (cd "$ZAG_ROOT" && "$detector" --db "$CALLGRAPH_DB" --target kernel); then
        FAILURES+=("dead-code findings")
        return 1
    fi
}

stage_callgraph_smokes() {
    echo ""
    echo "=================================================="
    echo "[0d] Callgraph HTTP + MCP smoke (per-commit DB)"
    echo "=================================================="
    if ! (cd "$ZAG_ROOT/tools/callgraph_http" && zig build 2>&1); then
        FAILURES+=("callgraph_http build")
        return 1
    fi
    if ! (cd "$ZAG_ROOT/tools/callgraph_mcp" && zig build 2>&1); then
        FAILURES+=("callgraph_mcp build")
        return 1
    fi
    ensure_callgraph_db || return 1
    if ! bash "$ZAG_ROOT/tools/callgraph_http/test/smoke.sh" "$CALLGRAPH_DB"; then
        FAILURES+=("callgraph_http smoke")
        return 1
    fi
    if ! bash "$ZAG_ROOT/tools/callgraph_mcp/test/smoke.sh" "$CALLGRAPH_DB"; then
        FAILURES+=("callgraph_mcp smoke")
        return 1
    fi
}

stage_gen_lock_analyzer() {
    echo ""
    echo "=================================================="
    echo "[0c] Gen-lock analyzer (fat-pointer invariants)"
    echo "=================================================="
    if ! (cd "$ZAG_ROOT/tools/check_gen_lock" && zig build 2>&1); then
        FAILURES+=("gen-lock analyzer build")
        return 1
    fi
    ensure_callgraph_db || return 1
    local analyzer="$ZAG_ROOT/tools/check_gen_lock/zig-out/bin/check_gen_lock"
    if ! (cd "$ZAG_ROOT" && "$analyzer" --db "$CALLGRAPH_DB" --summary); then
        FAILURES+=("gen-lock analyzer findings")
        return 1
    fi
}

clean_nvvars() {
    local nv="$ZAG_ROOT/zig-out/img/NvVars"
    if [[ -f "$nv" ]] && [[ "$(stat -c %U "$nv" 2>/dev/null)" == "root" ]]; then
        rm -f "$nv"
    fi
}

stage_x86_kernel_tests() {
    echo ""
    echo "=================================================="
    echo "[1/4] x86-64 kernel test suite (local KVM)"
    echo "=================================================="
    clean_nvvars
    if ! PARALLEL="$PARALLEL" bash "$SCRIPT_DIR/tests/run_tests.sh"; then
        FAILURES+=("x86-64 kernel tests")
        return 1
    fi
}

stage_aarch64_kernel_tests_pi() {
    echo ""
    echo "=================================================="
    echo "[2/4] aarch64 kernel test suite (Pi KVM via SSH)"
    echo "=================================================="

    echo "Building aarch64 test ELFs..."
    if ! (cd "$SCRIPT_DIR/tests" && zig build -Darch=arm); then
        FAILURES+=("aarch64 test ELF build")
        return 1
    fi

    # Kernel build needs a placeholder root_service.elf.
    local first_elf
    first_elf=$(find "$SCRIPT_DIR/tests/bin" -name 's*.elf' | head -1)
    cp "$first_elf" "$SCRIPT_DIR/tests/bin/root_service.elf"

    echo "Building aarch64 kernel..."
    if ! (cd "$ZAG_ROOT" && zig build -Darch=arm -Dprofile=test); then
        FAILURES+=("aarch64 kernel build")
        return 1
    fi

    echo "Syncing artifacts to $PI_HOST..."
    # Create target dirs on Pi (expands $HOME there). Wipe stale test ELFs
    # so a removed test on this box doesn't keep running on the Pi (the
    # equivalent of rsync --delete, scoped to the filename patterns we
    # actually push).
    ssh "$PI_HOST" "mkdir -p $PI_REMOTE_DIR/tests/bin $PI_REMOTE_DIR/img/efi/boot && rm -f $PI_REMOTE_DIR/tests/bin/s*.elf $PI_REMOTE_DIR/tests/bin/root_service.elf" || {
        FAILURES+=("ssh mkdir on Pi")
        return 1
    }

    # Test ELFs. tar-over-ssh keeps the per-file filter (s*.elf +
    # root_service.elf) without needing rsync on this box. The dev box
    # only needs `tar` + `ssh`; rsync stays on the Pi runner side, which
    # is fine because we don't call rsync there.
    local elf_list
    elf_list=$(cd "$SCRIPT_DIR/tests/bin" && ls s*.elf root_service.elf 2>/dev/null) || {
        FAILURES+=("no aarch64 test ELFs to sync")
        return 1
    }
    if ! tar -C "$SCRIPT_DIR/tests/bin" -cf - $elf_list \
        | ssh "$PI_HOST" "tar -C zag-test/tests/bin -xf -"; then
        FAILURES+=("tar/ssh test ELFs to Pi")
        return 1
    fi

    # Kernel + EFI loader.
    if ! scp -q "$ZAG_ROOT/zig-out/img/kernel.elf" \
        "$PI_HOST:zag-test/img/kernel.elf"; then
        FAILURES+=("scp kernel.elf to Pi")
        return 1
    fi
    if ! scp -q "$ZAG_ROOT/zig-out/img/efi/boot/BOOTAA64.EFI" \
        "$PI_HOST:zag-test/img/efi/boot/BOOTAA64.EFI"; then
        FAILURES+=("scp BOOTAA64.EFI to Pi")
        return 1
    fi

    # Build runner invocation: if PI_LIMIT=0, run everything by passing a huge LIMIT.
    local remote_limit="$PI_LIMIT"
    if [[ "$remote_limit" == "0" ]]; then
        remote_limit=100000
    fi

    echo "Running aarch64 tests on Pi (TIMEOUT=${PI_TIMEOUT}s, LIMIT=${remote_limit})..."
    echo "(Many aarch64 tests are expected to fail during port bring-up.)"
    if ! ssh "$PI_HOST" "cd zag-test && TIMEOUT=$PI_TIMEOUT LIMIT=$remote_limit PARALLEL=1 bash runner.sh"; then
        # The Pi runner exits 0 even on failures (it's a progress report), but
        # catch SSH / infra errors here.
        FAILURES+=("aarch64 kernel runner (Pi SSH/infra error)")
        return 1
    fi
}

stage_hyprvos_x86_linux_boot() {
    echo ""
    echo "=================================================="
    echo "[3/4] hyprvOS Linux boot (x86-64 KVM)"
    echo "=================================================="
    clean_nvvars

    # ReleaseSafe: Debug mode triggers a known LAPIC MMIO codegen issue.
    if ! (cd "$ZAG_ROOT/hyprvOS" && zig build); then
        FAILURES+=("hyprvOS build")
        return 1
    fi
    if ! (cd "$ZAG_ROOT" && zig build -Dprofile=hyprvos -Diommu=amd -Doptimize=ReleaseSafe); then
        FAILURES+=("hyprvos kernel build")
        return 1
    fi

    local qemu_log
    qemu_log=$(mktemp)
    (cd "$ZAG_ROOT" && timeout 90 zig build run -Dprofile=hyprvos -Diommu=amd -Doptimize=ReleaseSafe -- -display none) \
        > "$qemu_log" 2>&1 &
    local qemu_pid=$!

    local found=0
    for _ in $(seq 1 90); do
        if grep -q "=== Zag VM Shell ===" "$qemu_log" 2>/dev/null; then
            found=1
            break
        fi
        sleep 1
    done

    kill -TERM "$qemu_pid" 2>/dev/null || true
    pkill -f "qemu-system-x86_64" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true

    if [[ $found -eq 1 ]]; then
        echo "[PASS] Linux booted to shell (x86-64)"
        rm -f "$qemu_log"
        return 0
    else
        echo "[FAIL] Linux did not reach shell within 90s (x86-64)"
        echo "--- last 30 lines of QEMU output ---"
        tail -30 "$qemu_log"
        echo "--- end ---"
        rm -f "$qemu_log"
        FAILURES+=("hyprvOS Linux boot (x86-64)")
        return 1
    fi
}

stage_hyprvos_aarch64_linux_boot() {
    echo ""
    echo "=================================================="
    echo "[4/4] hyprvOS Linux boot (aarch64, local TCG)"
    echo "=================================================="
    # TCG, not KVM-on-Pi: the Pi 5 does not expose nested virt, and Pi
    # KVM only supports gic-version=2 while our driver is GICv3. The
    # aarch64 hyprvOS path puts Zag at EL2, so it has to run under TCG
    # with `virtualization=on`. The aarch64 kernel test suite still
    # runs on Pi KVM (stage 2) because those tests don't take the
    # kernel into EL2.
    #
    # Delegate to tests/test.sh linux-arm — it has the canonical QEMU
    # incantation + build flags (-Dkvm=false, cpu cortex-a72, etc.)
    # and the "hello from guest" marker. Single source of truth.
    if ! bash "$SCRIPT_DIR/test.sh" linux-arm; then
        FAILURES+=("hyprvOS Linux boot (aarch64 TCG)")
        return 1
    fi
}

stage_redteam_regressions() {
    echo ""
    echo "=================================================="
    echo "[5] Red-team regression PoCs"
    echo "=================================================="
    # tests/redteam/run_all.sh iterates every PoC that emits a
    # `POC-<id>: PATCHED` marker, reusing the per-PoC run.sh pipeline.
    # SKIPPED outcomes (e.g. no VMX) are allowed; VULNERABLE or a
    # missing marker (kernel panic before AFTER) fails the gate.

    # Stages 3 and 4 overwrite zig-out/img/kernel.elf with hyprvos
    # builds (x86 then aarch64). run.sh copies whatever kernel.elf
    # is present; without rebuilding, the PoCs would boot an aarch64
    # kernel under x86 QEMU and die in the bootloader. Rebuild the
    # x86 test-profile kernel before the red-team run.
    clean_nvvars
    if ! (cd "$ZAG_ROOT" && zig build -Dprofile=test 2>&1); then
        FAILURES+=("red-team kernel rebuild")
        return 1
    fi

    if ! bash "$SCRIPT_DIR/redteam/run_all.sh"; then
        FAILURES+=("red-team regressions")
        return 1
    fi
}

stage_kernel_perf() {
    echo ""
    echo "=================================================="
    echo "[6] Kernel perf regression (kprof trace)"
    echo "=================================================="
    # tests/prof/run_perf.sh boots each workload with
    # `-Dkernel_profile=trace` and compares scope medians against
    # tests/prof/baselines/<workload>.json. Sampling doesn't fit this
    # job — we're gating known scheduler/IPC/fault scopes, not
    # hunting unknown hot paths. Enter/exit pairs with PMU deltas
    # give a direct per-scope answer.
    if ! bash "$SCRIPT_DIR/prof/run_perf.sh" --compare-baseline; then
        FAILURES+=("kernel perf regression")
        return 1
    fi
}

# ── Dispatch ──────────────────────────────────────────────────────────

stage_arch_layering_lint        || true
stage_dead_code_report          || true
stage_gen_lock_analyzer         || true
stage_callgraph_smokes          || true
stage_x86_kernel_tests          || true
stage_aarch64_kernel_tests_pi   || true
stage_hyprvos_x86_linux_boot    || true
stage_hyprvos_aarch64_linux_boot || true
stage_redteam_regressions       || true
stage_kernel_perf               || true

echo ""
echo "=================================================="
if [[ ${#FAILURES[@]} -eq 0 ]]; then
    echo "All precommit stages passed."
    exit 0
else
    echo "Precommit FAILED. Failing stages:"
    for f in "${FAILURES[@]}"; do
        echo "  - $f"
    done
    exit 1
fi
