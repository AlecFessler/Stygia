#!/bin/bash
# Mega precommit: run the full cross-arch gauntlet before a commit.
#
# Stages:
#   0. arch layering lint          (gating — arch-specific / generic boundaries)
#   0b. dead-code report            (gating — skip-list checked into the tree)
#   0c. gen-lock analyzer           (gating — fat-pointer + bracketing invariants)
#   1. x86-64 kernel test suite   (KVM on this dev PC)
#   2. aarch64 kernel test suite  (KVM on the Pi 5 @ 192.168.86.106 via SSH)
#   3. hyprvOS Linux boot          (x86-64, KVM on this PC)
#   4. hyprvOS Linux boot          (aarch64, KVM on Pi via SSH)
#   5. red-team regression PoCs   (tests/redteam/run_all.sh)
#   6. kernel perf regression gate (tests/prof/run_perf.sh, kprof trace)
#
# Usage:
#   ./tests/precommit.sh             # full gauntlet (all stages, including optional)
#   ./tests/precommit.sh --git-hook  # only required stages — used by .githooks/pre-commit
#
# Env knobs:
#   PI_HOST=user@ip      # override Pi SSH target
#   PI_REMOTE_DIR=path   # override Pi-side artifact dir (default \$HOME/zag-test)

set -u

REQUIRED_ONLY=0
case "${1:-}" in
    --git-hook) REQUIRED_ONLY=1 ;;
    "" )       ;;
    *) echo "usage: $0 [--git-hook]" >&2; exit 2 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZAG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PI_HOST="${PI_HOST:-alecfessler@192.168.86.106}"
# Stays as a relative path so both ssh-shell-expansion contexts
# (`cd $PI_REMOTE_DIR …`) and scp destinations (`host:$PI_REMOTE_DIR/x`,
# which scp treats relative to login dir, NOT through a shell) resolve
# to the same place. Don't add a leading $HOME or `~` here — scp
# wouldn't expand `$HOME` (no remote shell) and `~` only works
# unquoted, which would break the ssh contexts.
PI_REMOTE_DIR="${PI_REMOTE_DIR:-zag-test}"

FAILURES=()

# Stages flagged here are blockers: --git-hook runs only these and exits
# 1 if any fail, so `git commit` refuses. The rest run in the full
# manual invocation but don't gate the hook.
REQUIRED_STAGES=(
    arch_layering_lint
    dead_code_report
    gen_lock_analyzer
    verify_coverage
    x86_kernel_tests
    aarch64_kernel_tests_pi
    aarch64_vm_tests_tcg
)
# Stages tagged as currently-failing-but-meant-to-be-required. Move
# entries back into REQUIRED_STAGES above as their underlying issues land:
#   hyprvos_x86_linux_boot      — blocked on reply-syscall ABI redesign (user is on this)
#   hyprvos_aarch64_linux_boot  — same upstream blocker
#
# Stages explicitly NOT meant for this gate (each runs in the full
# manual invocation only):
#   redteam_regressions         — too slow + scope mismatch for per-commit gate
#   kernel_perf                 — same

is_required() {
    local s
    for s in "${REQUIRED_STAGES[@]}"; do
        [[ "$s" == "$1" ]] && return 0
    done
    return 1
}

run_stage() {
    local name="$1"
    if [[ $REQUIRED_ONLY -eq 1 ]] && ! is_required "$name"; then
        return 0
    fi
    "stage_$name" || true
}

# ── Stage runners ─────────────────────────────────────────────────────

stage_arch_layering_lint() {
    echo ""
    echo "=================================================="
    echo "[0] Arch layering lint (token-aware analyzer)"
    echo "=================================================="
    if ! (cd "$ZAG_ROOT/tools/check_arch_layering" && zig build 2>&1); then
        FAILURES+=("arch-layering analyzer build")
        return 1
    fi
    ensure_callgraph_db || return 1
    local analyzer="$ZAG_ROOT/tools/check_arch_layering/zig-out/bin/check_arch_layering"
    if ! (cd "$ZAG_ROOT" && "$analyzer" --db "$CALLGRAPH_DB"); then
        FAILURES+=("arch layering lint")
        return 1
    fi
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
    if ! (cd "$ZAG_ROOT" && "$detector" --db "$CALLGRAPH_DB" --target kernel --skip "$ZAG_ROOT/kernel/.dead-code-skip.txt"); then
        FAILURES+=("dead-code findings")
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

stage_verify_coverage() {
    echo ""
    echo "=================================================="
    echo "[0e] Spec ↔ test coverage (verify_coverage.py)"
    echo "=================================================="
    # Cross-checks docs/kernel/specv3.md `[test NN]` tags against
    # tests/tests/tests/<section>_NN.zig files; exits 1 on duplicate
    # tags, missing files, orphan files, or any non-zero mismatch.
    if ! python3 "$SCRIPT_DIR/tests/verify_coverage.py"; then
        FAILURES+=("spec/test coverage mismatch")
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
    echo "[1/4] x86-64 kernel test suite (in-kernel runner, local KVM, 3 reps)"
    echo "=================================================="
    clean_nvvars

    echo "Building x86 root_service (in-kernel runner with embedded test ELFs)..."
    if ! (cd "$SCRIPT_DIR/tests" && rm -rf bin/ .zig-cache && zig build); then
        FAILURES+=("x86 root_service build")
        return 1
    fi

    echo "Building x86 kernel..."
    if ! (cd "$ZAG_ROOT" && zig build -Dprofile=test); then
        FAILURES+=("x86 kernel build")
        return 1
    fi

    # Three boots in a row, fail the whole stage on the first miss/fail.
    # Catches flakes that a single run wouldn't surface.
    local rep
    for rep in 1 2 3; do
        echo "Boot ${rep}/3 under QEMU+KVM..."
        local qemu_log
        qemu_log=$(mktemp)
        if ! (cd "$ZAG_ROOT" && timeout 240 zig build run -Dprofile=test) > "$qemu_log" 2>&1; then
            echo "[FAIL] qemu run ${rep}/3 failed or timed out"
            echo "--- last 30 lines of QEMU output ---"
            tail -30 "$qemu_log"
            echo "--- end ---"
            rm -f "$qemu_log"
            FAILURES+=("x86 kernel runner timeout/qemu error (rep ${rep}/3)")
            return 1
        fi

        local total
        total=$(grep -E '^\[runner\] [0-9]+ total' "$qemu_log" | tail -1)
        if [[ -z "$total" ]]; then
            echo "[FAIL] rep ${rep}/3: in-kernel runner did not report a total — kernel didn't reach summarize()"
            echo "--- last 30 lines of QEMU output ---"
            tail -30 "$qemu_log"
            echo "--- end ---"
            rm -f "$qemu_log"
            FAILURES+=("x86 kernel tests (no [runner] total, rep ${rep}/3)")
            return 1
        fi

        if ! echo "$total" | grep -qE '0 fail / 0 miss'; then
            echo "[FAIL] rep ${rep}/3: $total"
            grep -E '^\[runner\] (FAIL|MISS)' "$qemu_log" | head -20
            rm -f "$qemu_log"
            FAILURES+=("x86 kernel tests rep ${rep}/3: ${total#'[runner] '}")
            return 1
        fi

        echo "[OK]   rep ${rep}/3: ${total#'[runner] '}"
        rm -f "$qemu_log"
    done

    echo "[PASS] x86 kernel tests — 3/3 green"
    return 0
}

aarch64_pi_reachable() {
    # 5s connect timeout, batch mode (no password prompt). Returns
    # 0 if SSH succeeded, non-zero otherwise.
    ssh -o ConnectTimeout=5 -o BatchMode=yes "$PI_HOST" 'true' 2>/dev/null
}

# Run an aarch64 in-kernel test bundle 3× under local QEMU+TCG and
# report PASS/FAIL the same shape as the Pi path. Caller has already
# built kernel.elf + the bundled root_service.elf in zig-out/img and
# tests/tests/bin respectively. label = stage description for logs;
# fail_tag = prefix for FAILURES entries on this stage.
run_aarch64_tcg_3reps() {
    local label="$1"
    local fail_tag="$2"
    # Stage a clean FAT image dir so per-rep boots don't share state.
    local fat
    fat=$(mktemp -d)
    mkdir -p "$fat/img/efi/boot"
    cp "$ZAG_ROOT/zig-out/img/kernel.elf" "$fat/img/"
    cp "$SCRIPT_DIR/tests/bin/root_service.elf" "$fat/img/"
    cp "$ZAG_ROOT/zig-out/img/efi/boot/BOOTAA64.EFI" "$fat/img/efi/boot/"

    local rep
    for rep in 1 2 3; do
        echo "Boot ${rep}/3 under qemu-system-aarch64 + TCG (${label})..."
        local tcg_log
        tcg_log=$(mktemp)
        if ! timeout 600 qemu-system-aarch64 \
            -M virt,gic-version=3 -m 2G \
            -bios /usr/share/AAVMF/AAVMF_CODE.fd \
            -serial stdio -display none -no-reboot \
            -machine accel=tcg -cpu cortex-a72,pmu=on \
            -smp cores=4 \
            -drive file=fat:rw:"$fat/img",format=raw > "$tcg_log" 2>&1; then
            echo "[FAIL] TCG run ${rep}/3 failed or timed out (${label})"
            echo "--- last 30 lines of QEMU output ---"
            tail -30 "$tcg_log"
            echo "--- end ---"
            rm -f "$tcg_log"
            rm -rf "$fat"
            FAILURES+=("${fail_tag}: tcg run timeout/qemu error (rep ${rep}/3)")
            return 1
        fi
        local total
        total=$(grep -E '^\[runner\] [0-9]+ total' "$tcg_log" | tail -1)
        if [[ -z "$total" ]]; then
            echo "[FAIL] rep ${rep}/3 (${label}): no [runner] total — kernel didn't reach summarize()"
            echo "--- last 30 lines of QEMU output ---"
            tail -30 "$tcg_log"
            echo "--- end ---"
            rm -f "$tcg_log"
            rm -rf "$fat"
            FAILURES+=("${fail_tag}: no [runner] total (rep ${rep}/3)")
            return 1
        fi
        if ! echo "$total" | grep -qE '0 fail / 0 miss'; then
            echo "[FAIL] rep ${rep}/3 (${label}): $total"
            grep -E '^\[runner\] (FAIL|MISS)' "$tcg_log" | head -20
            rm -f "$tcg_log"
            rm -rf "$fat"
            FAILURES+=("${fail_tag} rep ${rep}/3: ${total#'[runner] '}")
            return 1
        fi
        echo "[OK]   rep ${rep}/3: ${total#'[runner] '}"
        rm -f "$tcg_log"
    done

    rm -rf "$fat"
    echo "[PASS] ${label} — 3/3 green"
    return 0
}

# §[vm_exit_state] / vCPU-execution coverage on aarch64 must be
# exercised against the real EL2/VHE path, not the spec's E_NODEV
# degraded-pass branch the Pi 5 KVM gets. Pi 5 KVM doesn't expose
# nested virt + only supports gic-version=2, so vCPU execution paths
# can't run there. Build root_service with just the 6 VM-related spec
# tests and run them under local TCG (gic-version=3). When aarch64
# kernel-side VM dispatch graduates from stub to real, this gate
# catches regressions on the real path.
stage_aarch64_vm_tests_tcg() {
    echo ""
    echo "=================================================="
    echo "[2a/4] aarch64 VM spec tests (local TCG, gic-version=3, 3 reps)"
    echo "=================================================="
    echo "Building aarch64 root_service (6-test VM bundle)..."
    if ! (cd "$SCRIPT_DIR/tests" && rm -rf bin/ .zig-cache && \
          zig build -Darch=arm \
          -Dtests='acquire_ecs_07,create_vcpu_03,create_vcpu_06,create_vcpu_07,create_virtual_machine_06,create_virtual_machine_07'); then
        FAILURES+=("aarch64 vm-tests root_service build")
        return 1
    fi
    echo "Building aarch64 kernel..."
    if ! (cd "$ZAG_ROOT" && zig build -Darch=arm -Dprofile=test); then
        FAILURES+=("aarch64 vm-tests kernel build")
        return 1
    fi
    run_aarch64_tcg_3reps "aarch64 VM spec tests (TCG)" "aarch64 vm-tests"
}

stage_aarch64_kernel_tests_pi() {
    echo ""
    echo "=================================================="
    echo "[2/4] aarch64 kernel test suite (in-kernel runner; Pi KVM, TCG fallback)"
    echo "=================================================="

    echo "Building aarch64 root_service (in-kernel runner with embedded test ELFs)..."
    if ! (cd "$SCRIPT_DIR/tests" && rm -rf bin/ .zig-cache && zig build -Darch=arm); then
        FAILURES+=("aarch64 root_service build")
        return 1
    fi

    echo "Building aarch64 kernel..."
    if ! (cd "$ZAG_ROOT" && zig build -Darch=arm -Dprofile=test); then
        FAILURES+=("aarch64 kernel build")
        return 1
    fi

    if ! aarch64_pi_reachable; then
        echo ""
        echo "Pi (${PI_HOST}) unreachable via SSH — falling back to local TCG."
        echo "(Full 477-test suite under emulation; expect this to take longer.)"
        run_aarch64_tcg_3reps "aarch64 kernel tests (TCG fallback)" "aarch64 kernel tests"
        return $?
    fi

    echo "Syncing artifacts to $PI_HOST..."
    if ! ssh "$PI_HOST" "mkdir -p $PI_REMOTE_DIR/img/efi/boot"; then
        FAILURES+=("ssh mkdir on Pi")
        return 1
    fi
    if ! scp -q "$ZAG_ROOT/zig-out/img/kernel.elf" \
        "$PI_HOST:$PI_REMOTE_DIR/img/kernel.elf"; then
        FAILURES+=("scp kernel.elf to Pi")
        return 1
    fi
    if ! scp -q "$ZAG_ROOT/zig-out/img/efi/boot/BOOTAA64.EFI" \
        "$PI_HOST:$PI_REMOTE_DIR/img/efi/boot/BOOTAA64.EFI"; then
        FAILURES+=("scp BOOTAA64.EFI to Pi")
        return 1
    fi
    if ! scp -q "$SCRIPT_DIR/tests/bin/root_service.elf" \
        "$PI_HOST:$PI_REMOTE_DIR/root_service.elf"; then
        FAILURES+=("scp root_service.elf to Pi")
        return 1
    fi

    # Three boots in a row, fail the whole stage on the first miss/fail.
    # Catches flakes that a single run wouldn't surface.
    local rep
    for rep in 1 2 3; do
        echo "Boot ${rep}/3 under qemu-system-aarch64 + KVM on Pi..."
        local pi_log
        pi_log=$(mktemp)
        if ! ssh "$PI_HOST" "cd $PI_REMOTE_DIR && wd=\$(mktemp -d) && mkdir -p \$wd/efi/boot && cp img/efi/boot/BOOTAA64.EFI \$wd/efi/boot/ && cp img/kernel.elf \$wd/ && cp root_service.elf \$wd/ && timeout 240 qemu-system-aarch64 -M virt,gic-version=2 -m 2G -bios /usr/share/AAVMF/AAVMF_CODE.fd -serial stdio -display none -no-reboot -machine accel=kvm -cpu host -smp cores=4 -drive file=fat:rw:\$wd,format=raw 2>&1; rm -rf \$wd" > "$pi_log" 2>&1; then
            echo "[FAIL] Pi qemu run ${rep}/3 failed or timed out"
            echo "--- last 30 lines of Pi output ---"
            tail -30 "$pi_log"
            echo "--- end ---"
            rm -f "$pi_log"
            FAILURES+=("aarch64 kernel runner timeout/qemu error (rep ${rep}/3)")
            return 1
        fi

        local total
        total=$(grep -E '^\[runner\] [0-9]+ total' "$pi_log" | tail -1)
        if [[ -z "$total" ]]; then
            echo "[FAIL] rep ${rep}/3: in-kernel runner did not report a total — kernel didn't reach summarize()"
            echo "--- last 30 lines of Pi output ---"
            tail -30 "$pi_log"
            echo "--- end ---"
            rm -f "$pi_log"
            FAILURES+=("aarch64 kernel tests (no [runner] total, rep ${rep}/3)")
            return 1
        fi

        if ! echo "$total" | grep -qE '0 fail / 0 miss'; then
            echo "[FAIL] rep ${rep}/3: $total"
            grep -E '^\[runner\] (FAIL|MISS)' "$pi_log" | head -20
            rm -f "$pi_log"
            FAILURES+=("aarch64 kernel tests rep ${rep}/3: ${total#'[runner] '}")
            return 1
        fi

        echo "[OK]   rep ${rep}/3: ${total#'[runner] '}"
        rm -f "$pi_log"
    done

    echo "[PASS] aarch64 kernel tests — 3/3 green"
    return 0
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

run_stage arch_layering_lint
run_stage dead_code_report
run_stage gen_lock_analyzer
run_stage verify_coverage
run_stage x86_kernel_tests
run_stage aarch64_kernel_tests_pi
run_stage aarch64_vm_tests_tcg
run_stage hyprvos_x86_linux_boot
run_stage hyprvos_aarch64_linux_boot
run_stage redteam_regressions
run_stage kernel_perf

echo ""
echo "=================================================="
if [[ ${#FAILURES[@]} -eq 0 ]]; then
    if [[ $REQUIRED_ONLY -eq 1 ]]; then
        echo "All required precommit stages passed (commit allowed)."
    else
        echo "All precommit stages passed."
    fi
    exit 0
else
    if [[ $REQUIRED_ONLY -eq 1 ]]; then
        echo "Required precommit stages FAILED — commit BLOCKED. Failing stages:"
    else
        echo "Precommit FAILED. Failing stages:"
    fi
    for f in "${FAILURES[@]}"; do
        echo "  - $f"
    done
    exit 1
fi
