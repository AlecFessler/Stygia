#!/bin/bash
# Mega precommit: run the full cross-arch gauntlet before a commit.
#
# Stages (all gated except [0d], which is report-only):
#   0. arch layering lint           (arch-specific / generic boundaries)
#   0b. dead-code report             (skip-list checked into the tree)
#   0c. gen-lock analyzer            (fat-pointer + bracketing invariants)
#   0d. EC-closure analyzer          (REPORT-ONLY — never affects exit status)
#   0e. spec ↔ test coverage         (verify_coverage.py)
#   1. x86_64 kernel test suite      (KVM on this dev PC, 3 reps)
#   2. aarch64 kernel test suite     (Pi 5 bare-metal tryboot @ .107; QEMU/KVM fallback on .106/.104)
#   2a. aarch64 VM-TCG vCPU subset   (local TCG, gic-version=3, EL2 exposed)
#   2b. aarch64 VM E_NODEV negative  (Pi-hosted QEMU/KVM, no nested EL2)
#   3. linux_guest VMM boot          (x86-64, KVM on this PC)
#   4. linux_guest VMM boot          (aarch64, local TCG with virtualization=on)
#
# Usage:
#   ./tests/precommit.sh             # full gauntlet (all stages, including optional)
#   ./tests/precommit.sh --git-hook  # only required stages — used by .githooks/pre-commit
#
# Env knobs:
#   PI_BARE_HOST=user@ip       # Pi 5 bare-metal tryboot SSH target (default .107)
#   PI_BARE_SERIAL_DEV=path    # local USB serial device for the .107 console
#   PI_QEMU_HOSTS='user@ip ...' # Pi-hosted aarch64 QEMU/KVM fallback targets (default .106 .104)
#   PI_HOST=user@ip            # legacy override for the first QEMU/KVM target
#   PI_REMOTE_DIR=path         # override Pi-side QEMU/KVM artifact dir (default \$HOME/stygia-test)

set -u

REQUIRED_ONLY=0
case "${1:-}" in
    --git-hook) REQUIRED_ONLY=1 ;;
    "" )       ;;
    *) echo "usage: $0 [--git-hook]" >&2; exit 2 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STYGIA_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Per-worktree Zig global cache ─────────────────────────────────────
#
# Every `zig build` invocation in this gauntlet (kernel, tools, test suite,
# and Linux guest on x64 and arm) would otherwise share the user's
# default global cache at `~/.cache/zig/`. With the orchestrator running
# up to 3 worker dispatches in parallel, multiple gauntlets fire `zig
# build` concurrently against the same module-hash directories in that
# global cache, racing on hash-dir creation and producing intermittent
# non-zero exits. The most visible failure was `ensure_callgraph_db`'s
# "kernel build for IR/ELF" stage flapping on N≥3 concurrent gauntlets.
#
# Pinning $ZIG_GLOBAL_CACHE_DIR to a worktree-local path gives each
# gauntlet its own private cache; child `zig build` processes inherit
# the env var, so this single export covers every invocation in the
# gauntlet without per-call shell prefixing. `.zig-cache/` (with and
# without `**/`) is already in .gitignore at project root so the
# directory never shows up in `git status`.
#
# Cost: each worktree's first gauntlet pays a cold-cache rebuild cost
# (no sharing with `~/.cache/zig/`). Subsequent runs in the same
# worktree warm-cache normally. Disk: each worktree's cache pulls in
# all of std + every kernel module touched by the gauntlet — expect a
# few hundred MB per worktree.
#
# Scope: the export only affects child processes of this script.
# Interactive `zig build` outside the gauntlet keeps using
# `~/.cache/zig/` via Zig's default. This intentionally does not blow
# away the existing user cache.
export ZIG_GLOBAL_CACHE_DIR="$STYGIA_ROOT/.zig-cache"

# ── Zig toolchain pin ────────────────────────────────────────────────
# This tree does not build with Zig 0.16: `process.args`,
# heap.GeneralPurposeAllocator, `linkLibrary`, and
# array_list.AlignedManaged.writer all changed incompatibly, and the
# first things to break are the analyzer tools in tools/ — so a 0.16
# gauntlet fails with a wall of API errors in code the commit never
# touched, which reads exactly like a regression and is not one.
#
# This matters most when the gauntlet runs as a git hook: hooks inherit a
# login PATH, which typically resolves `zig` to a distro package
# (/usr/bin/zig) rather than whatever the interactive shell uses. So
# resolve and verify the toolchain here instead of trusting PATH.
#
# Resolution order:
#   1. $STYGIA_ZIG, if set — explicit override, must be the right version.
#   2. `zig` as PATH already resolves it, if the version matches.
#   3. A pinned toolchain directory in a conventional location.
REQUIRED_ZIG="0.15.2"

resolve_zig() {
    local found=""

    if [[ -n "${STYGIA_ZIG:-}" ]]; then
        if [[ ! -x "$STYGIA_ZIG" ]]; then
            echo "error: \$STYGIA_ZIG is set to '$STYGIA_ZIG', which is not executable." >&2
            return 1
        fi
        if [[ "$("$STYGIA_ZIG" version 2>/dev/null)" != "$REQUIRED_ZIG" ]]; then
            echo "error: \$STYGIA_ZIG is Zig $("$STYGIA_ZIG" version 2>/dev/null), but this tree requires $REQUIRED_ZIG." >&2
            return 1
        fi
        found="$STYGIA_ZIG"
    elif [[ "$(zig version 2>/dev/null)" == "$REQUIRED_ZIG" ]]; then
        return 0  # PATH is already correct; leave it alone.
    else
        local cand
        for cand in \
            "$HOME/.local/opt/zig-x86_64-linux-$REQUIRED_ZIG/zig" \
            "$HOME/.local/opt/zig-$REQUIRED_ZIG/zig" \
            "/opt/zig-x86_64-linux-$REQUIRED_ZIG/zig" \
            "/opt/zig-$REQUIRED_ZIG/zig"
        do
            if [[ -x "$cand" ]] && [[ "$("$cand" version 2>/dev/null)" == "$REQUIRED_ZIG" ]]; then
                found="$cand"
                break
            fi
        done
    fi

    if [[ -z "$found" ]]; then
        echo "" >&2
        echo "error: no Zig $REQUIRED_ZIG toolchain found." >&2
        echo "" >&2
        echo "  PATH resolves \`zig\` to: $(command -v zig 2>/dev/null || echo '<none>')" >&2
        echo "  which reports version : $(zig version 2>/dev/null || echo '<none>')" >&2
        echo "" >&2
        echo "This tree does not build with Zig 0.16 — the tools/ analyzers fail" >&2
        echo "first, with API errors unrelated to whatever you are committing." >&2
        echo "" >&2
        echo "Point the gauntlet at the right toolchain, e.g.:" >&2
        echo "  STYGIA_ZIG=\$HOME/.local/opt/zig-x86_64-linux-$REQUIRED_ZIG/zig ./tests/precommit.sh" >&2
        echo "" >&2
        return 1
    fi

    # Prepend the resolved toolchain's directory so every `zig` in every
    # stage — including the ones that re-exec with a modified PATH for the
    # qemu shim — picks it up.
    PATH="$(cd "$(dirname "$found")" && pwd):$PATH"
    export PATH
    echo "[zig] using $found ($REQUIRED_ZIG)"
}

if ! resolve_zig; then
    exit 1
fi

PI_BARE_HOST="${PI_BARE_HOST:-alecfessler@192.168.86.107}"
PI_BARE_SERIAL_DEV="${PI_BARE_SERIAL_DEV:-/dev/serial/by-id/usb-FTDI_FT232R_USB_UART_BG03CX6R-if00-port0}"
PI_BARE_SERIAL_BAUD="${PI_BARE_SERIAL_BAUD:-115200}"
PI_BARE_SERIAL_DRAIN_TIMEOUT="${PI_BARE_SERIAL_DRAIN_TIMEOUT:-2}"
PI_BARE_REPEAT="${PI_BARE_REPEAT:-3}"
PI_BARE_RETURN_TIMEOUT="${PI_BARE_RETURN_TIMEOUT:-900}"
PI_BARE_DEPLOY_SCRIPT="${PI_BARE_DEPLOY_SCRIPT:-~/stygia-tools/deploy_stub.sh}"
PI_BARE_LOG_DIR="${PI_BARE_LOG_DIR:-$STYGIA_ROOT/out/precommit/pi5-bare}"

# PI_HOST is kept as a compatibility knob, but it is a QEMU/KVM host, not
# the bare-metal tryboot target. The hv=false proof must not silently move
# onto .107, where Stygia runs on real EL2 and hardware virtualization is
# present.
PI_HOST="${PI_HOST:-alecfessler@192.168.86.106}"
PI_QEMU_HOSTS="${PI_QEMU_HOSTS:-$PI_HOST alecfessler@192.168.86.104}"
# Stays as a relative path so both ssh-shell-expansion contexts
# (`cd $PI_REMOTE_DIR …`) and scp destinations (`host:$PI_REMOTE_DIR/x`,
# which scp treats relative to login dir, NOT through a shell) resolve
# to the same place. Don't add a leading $HOME or `~` here — scp
# wouldn't expand `$HOME` (no remote shell) and `~` only works
# unquoted, which would break the ssh contexts.
PI_REMOTE_DIR="${PI_REMOTE_DIR:-stygia-test}"

FAILURES=()

# ── QEMU gdbstub-suppression wrapper ──────────────────────────────────
#
# The kernel's root build.zig pins `-s` (shorthand for `-gdb tcp::1234`)
# in the x86_64 qemu cmdline. That bind is harmless for a single
# interactive `zig build run`, but the gauntlet is now driven in parallel
# (orchestrator runs up to 3 worker dispatches + reviewer + merger
# pipelines on the same host), and every concurrent qemu process tries to
# bind port 1234. The 2nd+ aborts with
# "Failed to find an available port: Address already in use", masquerading
# as an unrelated stage failure.
#
# The fix is in this script (test-runner scope) rather than build.zig
# (no subsystem owns the root build.zig): we install a thin shim named
# `qemu-system-x86_64` that drops `-s` from argv and exec's the real
# binary, then prepend the shim dir to PATH for every stage that invokes
# `zig build run` (= stages 1, 3, 5). Interactive use of build.zig
# outside the gauntlet still gets `-s` and port 1234 — the gauntlet just
# stops fighting for that port.
#
# aarch64 stages (2, 2a, 2b, 4) launch qemu-system-aarch64 directly
# without `-s` (locally or over SSH), so no shim is needed there.
QEMU_SHIM_DIR=$(mktemp -d -t stygia-qemu-shim.XXXXXX)
QEMU_REAL_X86="$(command -v qemu-system-x86_64 || echo /usr/bin/qemu-system-x86_64)"
cat > "$QEMU_SHIM_DIR/qemu-system-x86_64" <<EOF
#!/bin/bash
# Auto-generated by tests/precommit.sh — strips '-s' (gdbstub on port
# 1234) from argv so concurrent gauntlets don't collide on that port,
# then exec's the real qemu binary. See precommit.sh for rationale.
args=()
for a in "\$@"; do
    [[ "\$a" == "-s" ]] && continue
    args+=("\$a")
done
exec "$QEMU_REAL_X86" "\${args[@]}"
EOF
chmod +x "$QEMU_SHIM_DIR/qemu-system-x86_64"
trap '[[ -d "$QEMU_SHIM_DIR" ]] && rm -rf "$QEMU_SHIM_DIR"' EXIT
# PATH override callers must use when invoking `zig build run` for any
# x86 stage. Caller usage:
#   PATH="$QEMU_SHIM_PATH" zig build run -Dprofile=test
QEMU_SHIM_PATH="$QEMU_SHIM_DIR:$PATH"

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
    aarch64_vm_nodev_pi_kvm
    linux_guest_x86_boot
    linux_guest_aarch64_boot
)
#
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

# ── Pre-stage suite warmup ────────────────────────────────────────────
#
# The kernel build's default install step has a hard dependency on
# tests/suite/bin/root_service.elf: build.zig's install_root_service step
# (`addInstallFile` from `tests/suite/bin/root_service.elf`) is wired into
# `b.getInstallStep()`, so any `zig build -Dprofile=test ...` invocation
# that runs the install step errors out with FileNotFound on a worktree
# where that artifact hasn't been built yet.
#
# The artifact is normally produced by stages [1]/[2]/[2a]'s
# `cd tests/suite && rm -rf bin/ && zig build` step, but the analyzer
# stages [0]/[0b]/[0c] run first and call ensure_callgraph_db which
# triggers the kernel build before any of those stages get the chance.
# On a freshly-cloned worktree this races: the analyzer-stage kernel
# build hits FileNotFound and the analyzer never runs.
#
# Fix: prebuild the suite if root_service.elf isn't present, before any
# stage runs. The build is no-op on warm worktrees (file exists check)
# and only pays the full cost on the very first gauntlet run after a
# fresh checkout. Stages [1]/[2]/[2a] still rm -rf bin/ and rebuild with
# their per-stage -Dtests/-Dtests_exclude knobs, so the warmup is purely
# throwaway from their perspective — but it satisfies the install-step's
# existence check on first-run-from-clean worktrees.
ensure_suite_root_service_elf() {
    if [[ -f "$SCRIPT_DIR/suite/bin/root_service.elf" ]]; then
        return 0
    fi
    echo ""
    echo "=================================================="
    echo "[warmup] Building tests/suite/bin/root_service.elf"
    echo "=================================================="
    if ! (cd "$SCRIPT_DIR/suite" && zig build); then
        FAILURES+=("warmup: tests/suite root_service build")
        return 1
    fi
}

# ── Stage runners ─────────────────────────────────────────────────────

stage_arch_layering_lint() {
    echo ""
    echo "=================================================="
    echo "[0] Arch layering lint (token-aware analyzer)"
    echo "=================================================="
    if ! (cd "$STYGIA_ROOT/tools/check_arch_layering" && zig build 2>&1); then
        FAILURES+=("arch-layering analyzer build")
        return 1
    fi
    ensure_callgraph_db || return 1
    local analyzer="$STYGIA_ROOT/tools/check_arch_layering/zig-out/bin/check_arch_layering"
    if ! (cd "$STYGIA_ROOT" && "$analyzer" --db "$CALLGRAPH_DB"); then
        FAILURES+=("arch layering lint")
        return 1
    fi
}

# Build the per-(arch, commit_sha, working_tree_hash) callgraph DBs if
# they aren't present yet.
#
# Produces both x86_64 and aarch64 DBs in tools/callgraph_http/test/dbs/.
# Both are exposed as $CALLGRAPH_DB and $CALLGRAPH_DB_AARCH64 so callers
# can opt into either or both.
#
# Today only the dead-code analyzer (stage_dead_code_report) consumes the
# aarch64 DB — the arch-layering and gen-lock analyzers are x86_64-only
# semantics and pass just $CALLGRAPH_DB. Future stages that need
# cross-arch alive-set coverage can read $CALLGRAPH_DB_AARCH64 directly.
#
# The aarch64 DB skips the indexer's --elf argument: tools/indexer/src/
# bin_pass.zig hardcodes `objdump -M intel`, so an aarch64 ELF would
# silently fail at the bin pass. The dead-code analyzer's alive-set CTE
# only needs entry_reaches + ir_call rows (both populated from --ir), so
# Stage 4 in the indexer logs as "skipped (no --elf argument)" — that is
# expected. If a future analyzer needs aarch64 bin_inst rows, extending
# bin_pass for aarch64 ELF disasm is a kernel-tooling concern (file a
# separate bd).
#
# The working_tree_hash suffix on each arch's DB filename makes the cache
# honest about uncommitted edits. Pre-c70g the cache keyed only on HEAD:
# a worker running the gauntlet pre-commit got a cache hit on the last-
# committed-source DB even when their on-disk source had moved past it,
# and source-content-sensitive analyzers (dead_code_zig.validateSkipEntry's
# sha256-anchored skip.txt check) ran against stale .source rows. Item-14
# violations were structurally invisible at the worker and cycle-1 reviewer
# pre-commit gates; only the merger's post-rebase run (which moves HEAD →
# new filename → cache miss) caught them. Hashing the indexer's source-
# root view of the working tree into the key forces a cache miss on any
# uncommitted content change while letting multiple analyzer stages within
# a single dirty state share one DB. The suffix is applied to BOTH arches
# (per a332's dual-arch plumbing) so the aarch64 alive-set is also fresh
# on every dirty iteration. See bd-Zag-Subsystems-Agents-c70g.
ensure_callgraph_db() {
    if ! (cd "$STYGIA_ROOT/tools/indexer" && zig build 2>&1); then
        FAILURES+=("callgraph indexer build")
        return 1
    fi
    local sha tree_hash suffix
    sha="$(cd "$STYGIA_ROOT" && git rev-parse --short HEAD)"
    # Hash the diff against HEAD plus the content of every untracked-
    # but-not-ignored file under the indexer's source roots
    # (kernel/, bootloader/, tools/, tests/, libz/). Restricting to
    # those roots keeps the hash stable across gauntlet runs that touch
    # untracked artifacts elsewhere — notably .stygia-perf/_pending.json
    # written by stage [5] — so two clean-tree gauntlets share the same
    # cached DB.
    tree_hash=$(
        cd "$STYGIA_ROOT" && {
            git diff HEAD -- kernel bootloader tools tests libz
            git ls-files --others --exclude-standard -- \
                kernel bootloader tools tests libz \
                | while IFS= read -r f; do
                    [[ -f "$f" ]] && cat -- "$f"
                done
        } | sha256sum | cut -c1-12
    )
    # sha256 of empty input is e3b0c44298fc... — clean tree → omit the
    # suffix so existing on-HEAD-clean caches still hit.
    if [[ "$tree_hash" == "e3b0c44298fc" ]]; then
        suffix=""
    else
        suffix="-${tree_hash}"
    fi
    CALLGRAPH_DB="$STYGIA_ROOT/tools/callgraph_http/test/dbs/x86_64-${sha}${suffix}.db"
    CALLGRAPH_DB_AARCH64="$STYGIA_ROOT/tools/callgraph_http/test/dbs/aarch64-${sha}${suffix}.db"

    # ── IR freshness stamps ──────────────────────────────────────────
    #
    # The DB filename keys on (HEAD, working_tree_hash), so a dirty tree
    # correctly forces a cache MISS and the indexer reruns. But the
    # rebuild predicates below used to test only EXISTENCE (and ELF arch)
    # of zig-out/kernel.<arch>.ll — never freshness. So the indexer got
    # rerun against a STALE .ll and produced a DB *named for the current
    # tree* whose ir_fn/ir_call rows describe older source, while its
    # entity/ast_node/token rows (read straight from the working tree by
    # the indexer) are current. Internally inconsistent, and completely
    # silent: every analyzer that joins entity→ir_call — check_gen_lock's
    # bracketing, dead_code_zig's alive-set, check_ec_closure's Rule B —
    # reasons over a mixture of two source states and reports findings
    # that are neither tree's truth.
    #
    # The concrete trigger is the ordinary edit loop: run the gauntlet,
    # edit a kernel file, run it again. Second run's tree_hash changes →
    # new DB name → miss → but kernel.x86_64.ll still exists from run 1,
    # so `[[ ! -f ... ]]` was false and the build was skipped entirely.
    # The staler the .ll, the more confident and wrong the analyzers get.
    #
    # Fix: stamp the emitted artifacts with the SAME identity string the
    # DB name is keyed on, and treat a missing/mismatched stamp as a
    # rebuild trigger. The stamp lives in zig-out/ so it is destroyed by
    # the `rm -rf zig-out` in stage [1] together with the artifacts it
    # describes — a stamp can never outlive its .ll. See bd stygia-8qz.
    local ir_want ir_stamp_x86 ir_stamp_arm
    ir_want="${sha}${suffix}"
    ir_stamp_x86="$STYGIA_ROOT/zig-out/.ir-stamp.x86_64"
    ir_stamp_arm="$STYGIA_ROOT/zig-out/.ir-stamp.aarch64"

    # ── x86_64 DB ────────────────────────────────────────────────────
    if [[ ! -f "$CALLGRAPH_DB" ]]; then
        # Need .ll AND an x86_64-flavored kernel.elf. If a previous aarch64
        # build left an ARM ELF in zig-out/, the indexer's objdump pass would
        # fail silently and produce an empty bin_inst table.
        local need_rebuild_x86=0
        if [[ ! -f "$STYGIA_ROOT/zig-out/kernel.x86_64.ll" || ! -f "$STYGIA_ROOT/zig-out/bin/kernel.elf" ]]; then
            need_rebuild_x86=1
        elif [[ ! -f "$ir_stamp_x86" || "$(cat "$ir_stamp_x86" 2>/dev/null)" != "$ir_want" ]]; then
            # Artifacts exist but were emitted from a different tree state.
            echo "  zig-out/kernel.x86_64.ll is stale (want $ir_want, have $(cat "$ir_stamp_x86" 2>/dev/null || echo '<none>')) — rebuilding"
            need_rebuild_x86=1
        elif ! file "$STYGIA_ROOT/zig-out/bin/kernel.elf" 2>/dev/null | grep -q "x86-64"; then
            # Belt-and-braces: the aarch64 leg below overwrites
            # zig-out/bin/kernel.elf with an ARM ELF *after* the x86 stamp
            # is written, so a same-identity rerun can hit a matching stamp
            # beside a wrong-arch ELF. Keep this guard independent of the
            # stamp check for exactly that case.
            echo "  zig-out/bin/kernel.elf is not x86_64 — rebuilding"
            need_rebuild_x86=1
        fi
        if [[ $need_rebuild_x86 -eq 1 ]]; then
            echo "  building x86_64 kernel with -Darch=x64 -Demit_ir=true (needed by indexer)"
            # -Dimage_check=false: this build and the aarch64 one below run
            # back-to-back for opposite arches and consume only kernel.elf /
            # kernel.{arch}.ll. Neither boots the image, so build.zig's
            # arch-mixed-image guards would reject a pairing that does not
            # matter here. Every stage that DOES boot leaves them on.
            if ! (cd "$STYGIA_ROOT" && zig build -Dprofile=test -Darch=x64 -Demit_ir=true -Dimage_check=false 2>&1); then
                FAILURES+=("kernel build for IR/ELF (x86_64)")
                return 1
            fi
            # Only after a SUCCESSFUL build — a failed build leaves the old
            # .ll in place, and stamping it would launder stale IR as fresh.
            printf '%s' "$ir_want" > "$ir_stamp_x86"
        fi
        if ! (cd "$STYGIA_ROOT" && tools/indexer/zig-out/bin/indexer \
            --kernel-root kernel \
            --extra-source-root bootloader \
            --extra-source-root tools \
            --extra-source-root tests \
            --extra-source-root libz \
            --out "$CALLGRAPH_DB" \
            --arch x86_64 \
            --commit-sha "$(git rev-parse HEAD)" \
            --ir zig-out/kernel.x86_64.ll \
            --elf zig-out/bin/kernel.elf 2>&1); then
            FAILURES+=("callgraph DB build (x86_64)")
            return 1
        fi
    fi

    # ── aarch64 DB ───────────────────────────────────────────────────
    if [[ ! -f "$CALLGRAPH_DB_AARCH64" ]]; then
        # The aarch64 kernel test stage [2/4] currently builds without
        # -Demit_ir=true, so the .ll file isn't amortized — this is the
        # first/only aarch64 IR-emit invocation per gauntlet. Cost: one
        # extra ~30-60s build on cold worktree cache; warm-cache subsequent
        # gauntlets in the same worktree reuse it via the per-worktree
        # ZIG_GLOBAL_CACHE_DIR pin.
        local need_rebuild_arm=0
        if [[ ! -f "$STYGIA_ROOT/zig-out/kernel.aarch64.ll" ]]; then
            need_rebuild_arm=1
        elif [[ ! -f "$ir_stamp_arm" || "$(cat "$ir_stamp_arm" 2>/dev/null)" != "$ir_want" ]]; then
            echo "  zig-out/kernel.aarch64.ll is stale (want $ir_want, have $(cat "$ir_stamp_arm" 2>/dev/null || echo '<none>')) — rebuilding"
            need_rebuild_arm=1
        fi
        if [[ $need_rebuild_arm -eq 1 ]]; then
            echo "  building aarch64 kernel with -Darch=arm -Demit_ir=true (needed by indexer)"
            if ! (cd "$STYGIA_ROOT" && zig build -Darch=arm -Dprofile=test -Demit_ir=true -Dimage_check=false 2>&1); then
                FAILURES+=("kernel build for IR (aarch64)")
                return 1
            fi
            printf '%s' "$ir_want" > "$ir_stamp_arm"
        fi
        # No --elf for aarch64: bin_pass is x86-only (see function header
        # comment). Indexer's stage 4 logs "skipped (no --elf argument)";
        # entry_reaches + ir_call (the only tables the dead-code alive-set
        # augmentation reads) come from --ir.
        if ! (cd "$STYGIA_ROOT" && tools/indexer/zig-out/bin/indexer \
            --kernel-root kernel \
            --extra-source-root bootloader \
            --extra-source-root tools \
            --extra-source-root tests \
            --extra-source-root libz \
            --out "$CALLGRAPH_DB_AARCH64" \
            --arch aarch64 \
            --commit-sha "$(git rev-parse HEAD)" \
            --ir zig-out/kernel.aarch64.ll 2>&1); then
            FAILURES+=("callgraph DB build (aarch64)")
            return 1
        fi
    fi
}

stage_dead_code_report() {
    echo ""
    echo "=================================================="
    echo "[0b] Dead-code detector (gating)"
    echo "=================================================="
    if ! (cd "$STYGIA_ROOT/tools/dead_code_zig" && zig build 2>&1); then
        FAILURES+=("dead-code detector build")
        return 1
    fi
    if ! bash "$STYGIA_ROOT/tools/dead_code_zig/test/run_tests.sh"; then
        FAILURES+=("dead-code fixture suite")
        return 1
    fi
    ensure_callgraph_db || return 1
    local detector="$STYGIA_ROOT/tools/dead_code_zig/zig-out/bin/dead_code_zig"
    # Pass both arches' DBs: the analyzer treats the first as the primary
    # (skip-file resolution + lint_finding writeback) and unions every
    # subsequent --db's alive-set by qualified_name. Without the aarch64
    # DB the analyzer falsely flags entities that are dead under x86_64
    # entry_reaches but alive under aarch64 (e.g. arch-specific dispatch
    # arms). bd-Zag-Subsystems-Agents-l82
    # landed the multi-DB plumbing; this stage finally feeds it both.
    if ! (cd "$STYGIA_ROOT" && "$detector" \
        --db "$CALLGRAPH_DB" \
        --db "$CALLGRAPH_DB_AARCH64" \
        --target kernel \
        --skip "$STYGIA_ROOT/tools/dead_code_zig/skip.txt"); then
        FAILURES+=("dead-code findings")
        return 1
    fi
}

stage_gen_lock_analyzer() {
    echo ""
    echo "=================================================="
    echo "[0c] Gen-lock analyzer (IRQ discipline)"
    echo "=================================================="
    if ! (cd "$STYGIA_ROOT/tools/check_gen_lock" && zig build 2>&1); then
        FAILURES+=("gen-lock analyzer build")
        return 1
    fi
    # Self-tests for the analyzer first — a regression in the analyzer
    # itself silently weakens every kernel finding it produces, so gate
    # on the fixture suite before turning it loose on the real DB.
    if ! bash "$STYGIA_ROOT/tools/check_gen_lock/tests/run_tests.sh"; then
        FAILURES+=("gen-lock analyzer self-tests")
        return 1
    fi
    ensure_callgraph_db || return 1
    local analyzer="$STYGIA_ROOT/tools/check_gen_lock/zig-out/bin/check_gen_lock"
    # Both arches, like stage [0b] — but note the SHAPE DIFFERS. The
    # dead-code detector accepts repeated `--db` flags and unions the
    # alive-set across them; check_gen_lock's `--db` is single-valued
    # (`args.db_path = v`), so a second `--db` would silently overwrite
    # the first and analyze only one arch. Hence two invocations.
    #
    # Why both are needed: check 6's IRQ-discipline pass defers any
    # acquire site under `kernel/arch/<other-arch>/` to the run for the
    # arch that actually compiles it — that code is behind a resolved
    # comptime arch branch and contributes zero ir_fn/ir_call rows here,
    # so this DB has no evidence about it and every conclusion would rest
    # on short-name text matching. The deferral is only sound because the
    # other arch's run covers those sites; running one arch alone leaves
    # them unanalyzed. The analyzer prints the deferred count on its
    # summary line so a single-arch invocation can't hide them silently.
    #
    # Both runs execute even if the first fails, so one arch's findings
    # don't mask the other's.
    local genlock_rc=0
    if ! (cd "$STYGIA_ROOT" && "$analyzer" --db "$CALLGRAPH_DB" --target kernel --summary --rule irq_discipline); then
        FAILURES+=("gen-lock IRQ-discipline findings (x86_64)")
        genlock_rc=1
    fi
    if ! (cd "$STYGIA_ROOT" && "$analyzer" --db "$CALLGRAPH_DB_AARCH64" --target kernel --summary --rule irq_discipline); then
        FAILURES+=("gen-lock IRQ-discipline findings (aarch64)")
        genlock_rc=1
    fi
    return $genlock_rc
}

# ── [0d] EC-lifecycle closure analyzer — REPORT-ONLY, NOT GATING ──────
#
# GATING IS A PENDING MAINTAINER DECISION. Do not "promote" this stage to
# gating without them saying so.
#
# Rationale for report-only: `check_ec_closure` mechanizes two enumerations
# that docs/kernel/systems.md otherwise maintains by hand, and its Rule B
# is what the design doc's enforcement story leans on — but neither rule
# has been through a full triage pass against the real tree yet. Rule A's
# call graph deliberately over-approximates (a syntactic overlay on top of
# `ir_call`, so calls through monomorphized generics and address-taken
# callbacks are not silently missing), and Rule B's `ec` / `async-irq`
# context labels inherit that over-approximation. Both biases cost false
# positives, which is the right bias for a "did we miss one" tool and the
# wrong bias for a gate. Turning it red would block every commit on
# findings nobody has classified yet.
#
# So: print everything, contribute nothing to $FAILURES, and leave the
# gating call to a human who has read a full report.
#
# Deliberately NOT in REQUIRED_STAGES — that list is documented as
# blockers, and `--git-hook` runs only those. This stage therefore runs in
# the full manual gauntlet and is skipped by the commit hook, which is
# what "informational" should mean here.
#
# One `check_ec_closure` invocation covers both arches. Note the SHAPE
# DIFFERS from stage [0c]: check_gen_lock's `--db` is single-valued
# (`args.db_path = v`), so a repeated flag silently overwrites and it must
# be invoked twice. check_ec_closure's `--db` is genuinely repeatable — it
# appends to a list (`try dbs.append(a, …)`) and loops over every DB,
# printing a banner and a `Summary[<arch>]:` line per DB. Verified by
# reading the arg parser, not assumed from [0c]'s shape.
stage_ec_closure_report() {
    echo ""
    echo "=================================================="
    echo "[0d] EC-lifecycle closure analyzer (REPORT-ONLY — does not gate)"
    echo "=================================================="
    if ! (cd "$STYGIA_ROOT/tools/check_ec_closure" && zig build 2>&1); then
        echo "[0d] analyzer build failed — skipping report (stage does not gate)"
        return 0
    fi
    # Self-tests first: a regression in the analyzer silently weakens every
    # finding below. Report-only, so a failure is loud but not fatal.
    if ! bash "$STYGIA_ROOT/tools/check_ec_closure/tests/run_tests.sh"; then
        echo "[0d] WARNING: check_ec_closure fixture suite FAILED — findings below are untrustworthy"
    fi
    # Deliberately does NOT call ensure_callgraph_db. That helper appends
    # to $FAILURES on error, which would let a report-only stage turn the
    # gauntlet red — the one thing this stage must never do. Stages [0],
    # [0b] and [0c] all run before this one and all call it, so the two
    # globals are already set and the DBs already built; if they are not,
    # the gauntlet is red for that reason already and this stage has
    # nothing to add.
    if [[ ! -f "${CALLGRAPH_DB:-}" || ! -f "${CALLGRAPH_DB_AARCH64:-}" ]]; then
        echo "[0d] callgraph DBs not present — skipping report (stage does not gate)"
        return 0
    fi
    # No --target flag: check_ec_closure's arg parser rejects unknown flags
    # with exit 2. Its kernel-scope filter is built in (`inKernelScope`).
    local analyzer="$STYGIA_ROOT/tools/check_ec_closure/zig-out/bin/check_ec_closure"
    (cd "$STYGIA_ROOT" && "$analyzer" \
        --db "$CALLGRAPH_DB" \
        --db "$CALLGRAPH_DB_AARCH64") || true
    echo "[0d] report-only: findings above do NOT affect precommit's exit status."
    return 0
}

stage_verify_coverage() {
    echo ""
    echo "=================================================="
    echo "[0e] Spec ↔ test coverage (verify_coverage.py)"
    echo "=================================================="
    # Cross-checks docs/kernel/specv3.md `[test NN]` tags against
    # tests/suite/cases/<section>_NN.zig files; exits 1 on duplicate
    # tags, missing files, orphan files, or any non-zero mismatch.
    if ! python3 "$SCRIPT_DIR/suite/verify_coverage.py"; then
        FAILURES+=("spec/test coverage mismatch")
        return 1
    fi
}

clean_nvvars() {
    local nv="$STYGIA_ROOT/zig-out/img/NvVars"
    if [[ -f "$nv" ]] && [[ "$(stat -c %U "$nv" 2>/dev/null)" == "root" ]]; then
        rm -f "$nv"
    fi
}

# Refuse to boot an arch-MIXED image.
#
# `zig-out/img/` is not cleaned when the target arch changes, and the root
# build COPIES tests/suite/bin/root_service.elf rather than re-deriving it.
# So an aarch64 build followed by an x86 build leaves an x86-64 kernel.elf
# beside an ARM aarch64 root_service.elf (plus a stale BOOTAA64.EFI). Every
# build exits 0 and nothing else detects it. This gauntlet alternates arches
# (the indexer stage builds -Darch=arm), and an interactive build in the same
# checkout can interleave too.
#
# The resulting boot failure looks exactly like a kernel scheduler bug and is
# NOT one — the loader jumps into a zeroed page, whose 00 00 bytes decode as
# `add %al,(%rax)` with rax=0:
#
#   [USR-PF] rip=0x...901 addr=0x0 err=0x6 w=true x=false no-vmar
#   [USR-PF] insn=00 00 00 00 ...
#   [HANG] core=0 ... state=RUN on_cpu=1 ; all run_queues empty, ONE live EC
#
# That is the signature filed as stygia-gms ("pristine main wedges at boot
# under concurrent-gauntlet contention"), which this check would have
# classified instantly. See tests/precommit.sh:285 for the same guard already
# applied to zig-out/bin/kernel.elf for the indexer's benefit.
#
# $1 = expected arch as `file` spells it: "x86-64" or "ARM aarch64"
verify_image_arch() {
    local want="$1"
    local bad=0 f got
    for f in "$STYGIA_ROOT/zig-out/img/kernel.elf" \
             "$STYGIA_ROOT/zig-out/img/root_service.elf"; do
        if [[ ! -f "$f" ]]; then
            echo "  [arch-guard] missing: $f"
            bad=1
            continue
        fi
        got=$(file -b "$f" | grep -oE "x86-64|ARM aarch64" | head -1)
        if [[ "$got" != "$want" ]]; then
            echo "  [arch-guard] $f is '${got:-unknown}', expected '$want'"
            bad=1
        fi
    done
    # A leftover bootloader for the other arch is the same staleness tell.
    case "$want" in
        "x86-64")      [[ -f "$STYGIA_ROOT/zig-out/img/efi/boot/BOOTAA64.EFI" ]] && {
                           echo "  [arch-guard] stale BOOTAA64.EFI in an x86 image"; bad=1; } ;;
        "ARM aarch64") [[ -f "$STYGIA_ROOT/zig-out/img/efi/boot/BOOTX64.EFI" ]] && {
                           echo "  [arch-guard] stale BOOTX64.EFI in an aarch64 image"; bad=1; } ;;
    esac
    if [[ "$bad" != 0 ]]; then
        echo "  [arch-guard] zig-out/img is arch-mixed — 'rm -rf zig-out' and rebuild."
        return 1
    fi
    return 0
}

# Scan a captured qemu/serial log for kernel-level faults that the runner's
# own summary line cannot see.
#
# This closes a real hole in the gate. The suite verdict was taken purely
# from `[runner] N total / … / 0 fail / 0 miss`, but that line is printed by
# the runner EC, which keeps going when *another* core dies. A run was
# observed reporting "485 total / 469 pass / 0 fail / 16 miss" with a
# `KERNEL PANIC: kernel page fault on user VA with no current EC` sitting in
# the middle of the log — and because 16 MISS was the only visible symptom,
# the panic went unnoticed. A run that panics on one core and still reports a
# clean summary used to PASS this gate outright.
#
# Marker choice is measured against a known-clean x86 run (485/485):
#   KERNEL PANIC  0   Zig `panic:`  0   [NOROUTE]  0
#   [USR-PF]    102  <-- NOT a marker; the map_pf tests fault on purpose.
# `[NOROUTE]` means an event fired with no bound route and the EC parked
# forever, so a result that should exist never will — abnormal by
# construction, and zero in healthy runs.
#
# `[HANG]` is diagnostic rather than conclusively terminal: the x86 hang
# detector can dump once after a long no-newline window, then the runner can
# resume and report a clean per-run summary or final repeat aggregate. Keep
# terminal hangs blocking, but do not fail a recovered dump that is followed by
# a clean runner verdict.
#
# $1 = path to the captured log, $2 = label for the FAILURES entry
verify_no_kernel_faults() {
    local log="$1" label="$2"
    [[ -f "$log" ]] || return 0
    # The runner's per-test progress ticks interleave `~` into output, so
    # strip them before matching (same reason the summary greps do).
    local hard_hits
    hard_hits=$(tr -d '~' < "$log" | grep -aE 'KERNEL PANIC|^panic: |\[NOROUTE\]' | head -10)
    if [[ -n "$hard_hits" ]]; then
        echo "[FAIL] $label: kernel-level fault in the log (runner summary cannot see this)"
        echo "$hard_hits" | sed 's/^/    /'
        FAILURES+=("$label: kernel fault (panic/noroute) in serial log")
        return 1
    fi

    local hang_hits
    hang_hits=$(tr -d '~' < "$log" | grep -aE '\[HANG\]' | head -10)
    if [[ -n "$hang_hits" ]]; then
        if tr -d '~' < "$log" | awk '
            /\[HANG\]/ { last_hang = NR }
            /^\[runner\] [0-9]+ total .* \/ 0 fail \/ 0 miss$/ {
                if (NR > last_hang) clean_after_hang = 1
            }
            /^\[runner\] === aggregate over [0-9]+ runs: .* \/ 0 fail \/ 0 miss ===$/ {
                if (NR > last_hang) clean_after_hang = 1
            }
            END { exit !(last_hang > 0 && clean_after_hang) }
        '; then
            echo "[WARN] $label: recovered [HANG] diagnostic followed by clean runner verdict"
            echo "$hang_hits" | sed 's/^/    /'
            return 0
        fi

        echo "[FAIL] $label: terminal [HANG] in the log (no later clean runner verdict)"
        echo "$hang_hits" | sed 's/^/    /'
        FAILURES+=("$label: terminal hang in serial log")
        return 1
    fi

    return 0
}

stage_x86_kernel_tests() {
    echo ""
    echo "=================================================="
    echo "[1/4] x86-64 kernel test suite (in-kernel runner, local KVM, 3 reps)"
    echo "=================================================="
    clean_nvvars

    echo "Building x86 root_service (in-kernel runner with embedded test ELFs)..."
    if ! (cd "$SCRIPT_DIR/suite" && rm -rf bin/ .zig-cache && zig build); then
        FAILURES+=("x86 root_service build")
        return 1
    fi

    # zig-out is not pruned on an arch switch, and the indexer stage above
    # builds both arches back-to-back, so clear it before producing an image
    # that will actually be booted (build.zig also refuses a mixed one).
    rm -rf "$STYGIA_ROOT/zig-out"
    echo "Building x86 kernel..."
    if ! (cd "$STYGIA_ROOT" && zig build -Dprofile=test); then
        FAILURES+=("x86 kernel build")
        return 1
    fi

    if ! verify_image_arch "x86-64"; then
        FAILURES+=("x86 image is arch-mixed (see arch-guard output)")
        return 1
    fi

    # Three boots in a row, fail the whole stage on the first miss/fail.
    # Catches flakes that a single run wouldn't surface.
    local rep
    for rep in 1 2 3; do
        echo "Boot ${rep}/3 under QEMU+KVM..."
        local qemu_log
        qemu_log=$(mktemp)
        if ! (cd "$STYGIA_ROOT" && PATH="$QEMU_SHIM_PATH" timeout 240 zig build run -Dprofile=test) > "$qemu_log" 2>&1; then
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

        # A clean summary is not proof the kernel survived — another core
        # can die while the runner keeps reporting. See verify_no_kernel_faults.
        if ! verify_no_kernel_faults "$qemu_log" "x86 kernel tests (rep ${rep}/3)"; then
            rm -f "$qemu_log"
            return 1
        fi
        echo "[OK]   rep ${rep}/3: ${total#'[runner] '}"
        rm -f "$qemu_log"
    done

    echo "[PASS] x86 kernel tests — 3/3 green"
    return 0
}

aarch64_pi_reachable() {
    local host="${1:-$PI_HOST}"
    # 5s connect timeout, batch mode (no password prompt). Returns
    # 0 if SSH succeeded, non-zero otherwise.
    ssh -o ConnectTimeout=5 -o BatchMode=yes "$host" 'true' 2>/dev/null
}

select_aarch64_qemu_host() {
    local host
    for host in $PI_QEMU_HOSTS; do
        # .107 is the bare-metal tryboot rig. It is intentionally excluded
        # from Pi-hosted QEMU/KVM selection so the only hv=false aarch64 path
        # remains nested-EL2-missing QEMU/KVM on .106/.104.
        [[ "$host" == "$PI_BARE_HOST" ]] && continue
        if aarch64_pi_reachable "$host"; then
            echo "$host"
            return 0
        fi
    done
    return 1
}

wait_for_ssh_up() {
    local host="$1" timeout_s="$2" waited=0
    while [[ $waited -lt $timeout_s ]]; do
        if aarch64_pi_reachable "$host"; then
            return 0
        fi
        sleep 5
        waited=$((waited + 5))
    done
    return 1
}

wait_for_ssh_down() {
    local host="$1" timeout_s="$2" waited=0
    while [[ $waited -lt $timeout_s ]]; do
        if ! aarch64_pi_reachable "$host"; then
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done
    return 1
}

start_pi5_serial_capture() {
    local log="$1"
    if [[ ! -r "$PI_BARE_SERIAL_DEV" ]]; then
        echo "[FAIL] Pi5 serial device '$PI_BARE_SERIAL_DEV' is not readable" >&2
        echo "       Set PI_BARE_SERIAL_DEV to the local USB serial adapter for $PI_BARE_HOST." >&2
        return 1
    fi
    if ! stty -F "$PI_BARE_SERIAL_DEV" "$PI_BARE_SERIAL_BAUD" raw -echo -echoe -echok -echoctl -echoke -icanon min 0 time 1; then
        echo "[FAIL] could not configure Pi5 serial device '$PI_BARE_SERIAL_DEV'" >&2
        return 1
    fi
    # Drop bytes already sitting in the tty buffer. Freshness is enforced by
    # requiring the reboot command to drop SSH and then accepting only an
    # ordered Pi5-loader -> runner-start -> clean-verdict sequence from this
    # drained capture.
    timeout "$PI_BARE_SERIAL_DRAIN_TIMEOUT" cat "$PI_BARE_SERIAL_DEV" >/dev/null 2>&1 || true
    if ! stty -F "$PI_BARE_SERIAL_DEV" "$PI_BARE_SERIAL_BAUD" raw -echo -echoe -echok -echoctl -echoke -icanon min 1 time 0; then
        echo "[FAIL] could not configure blocking Pi5 serial capture on '$PI_BARE_SERIAL_DEV'" >&2
        return 1
    fi
    stdbuf -o0 cat "$PI_BARE_SERIAL_DEV" >> "$log" &
    PI5_SERIAL_PID="$!"
}

stop_pi5_serial_capture() {
    local pid="${1:-}"
    [[ -z "$pid" ]] && return 0
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

verify_aarch64_bare_tryboot_log() {
    local serial_log="$1" label="$2"
    local current_log verdict=""

    current_log=$(mktemp)
    LC_ALL=C tr -d '~\000' < "$serial_log" > "$current_log"

    verdict=$(LC_ALL=C awk -v repeat="$PI_BARE_REPEAT" '
        index($0, "[stygia pi5 loader] entering kernel") {
            if (state == 0) state = 1
            next
        }
        index($0, "[runner] starting ") == 1 {
            if (state == 1) {
                if (repeat > 1) {
                    suffix = " x " repeat " runs"
                    if (substr($0, length($0) - length(suffix) + 1) == suffix) {
                        state = 2
                    }
                } else {
                    state = 2
                }
            }
            next
        }
        index($0, "[runner] === aggregate over ") == 1 {
            if (state == 2 && repeat > 1) {
                prefix = "[runner] === aggregate over " repeat " runs:"
                suffix = " / 0 fail / 0 miss ==="
                if (index($0, prefix) == 1 && substr($0, length($0) - length(suffix) + 1) == suffix) {
                    print
                    found = 1
                    exit
                }
            }
            next
        }
        index($0, "[runner] ") == 1 {
            if (state == 2 && repeat <= 1) {
                suffix = " / 0 fail / 0 miss"
                if (index($0, " total / ") > 0 && substr($0, length($0) - length(suffix) + 1) == suffix) {
                    print
                    found = 1
                    exit
                }
            }
        }
        END { exit found ? 0 : 1 }
    ' "$current_log" || true)
    if [[ -z "$verdict" ]]; then
        echo "[FAIL] $label: no ordered current-run tryboot verdict"
        echo "       Required order after observed SSH-down reboot: Pi5 loader handoff -> runner start -> clean verdict."
        echo "--- Pi5 serial tail ---"
        tail -40 "$current_log"
        echo "--- end ---"
        rm -f "$current_log"
        FAILURES+=("$label: no ordered current-run bare-metal verdict")
        return 1
    fi
    if ! verify_no_kernel_faults "$current_log" "$label"; then
        rm -f "$current_log"
        return 1
    fi
    rm -f "$current_log"
    echo "[OK]   $label: ${verdict#'[runner] '}"
    return 0
}

run_aarch64_bare_tryboot() {
    local label="$1"
    local serial_log deploy_log reboot_log serial_pid run_log_dir
    mkdir -p "$PI_BARE_LOG_DIR"
    run_log_dir="$PI_BARE_LOG_DIR/$(date +%Y%m%d_%H%M%S)-$$"
    mkdir -p "$run_log_dir"
    serial_log="$run_log_dir/serial.log"
    deploy_log="$run_log_dir/deploy.log"
    reboot_log="$run_log_dir/reboot.log"
    : > "$serial_log"
    : > "$deploy_log"
    : > "$reboot_log"
    serial_pid=""

    echo "Checking $PI_BARE_HOST tryboot helpers..."
    if ! ssh "$PI_BARE_HOST" "test -f $PI_BARE_DEPLOY_SCRIPT && command -v stygia-reboot >/dev/null"; then
        echo "[FAIL] $PI_BARE_HOST is reachable but missing tryboot helpers"
        echo "       Need $PI_BARE_DEPLOY_SCRIPT and stygia-reboot from the Pi5 stability rig."
        echo "       logs: $run_log_dir"
        FAILURES+=("aarch64 bare-metal tryboot helpers unavailable")
        return 1
    fi

    echo "Staging Pi5 bare-metal image on $PI_BARE_HOST..."
    if ! scp -q "$STYGIA_ROOT/zig-out/pi5/kernel_stygia.img" "$PI_BARE_HOST:/tmp/kernel_stygia.img"; then
        echo "[FAIL] scp kernel_stygia.img to $PI_BARE_HOST failed"
        echo "       logs: $run_log_dir"
        FAILURES+=("aarch64 bare-metal image scp")
        return 1
    fi

    if ! ssh "$PI_BARE_HOST" "bash $PI_BARE_DEPLOY_SCRIPT" > "$deploy_log" 2>&1; then
        echo "[FAIL] tryboot deploy on $PI_BARE_HOST failed"
        echo "--- deploy output ---"
        tail -60 "$deploy_log"
        echo "--- end ---"
        echo "       logs: $run_log_dir"
        FAILURES+=("aarch64 bare-metal tryboot deploy")
        return 1
    fi

    PI5_SERIAL_PID=""
    if ! start_pi5_serial_capture "$serial_log"; then
        echo "       logs: $run_log_dir"
        FAILURES+=("aarch64 bare-metal serial capture unavailable")
        return 1
    fi
    serial_pid="$PI5_SERIAL_PID"

    echo "Booting $PI_BARE_HOST into one-shot tryboot; waiting for Pi OS fallback..."
    ssh "$PI_BARE_HOST" 'stygia-reboot tryboot' > "$reboot_log" 2>&1
    local reboot_rc=$?
    if [[ $reboot_rc -ne 0 ]] && ! grep -qE 'one-shot boot into tryboot|closed by remote host' "$reboot_log"; then
        stop_pi5_serial_capture "$serial_pid"
        echo "[FAIL] stygia-reboot tryboot failed before reboot"
        echo "--- reboot output ---"
        tail -60 "$reboot_log"
        echo "--- end ---"
        echo "       logs: $run_log_dir"
        FAILURES+=("aarch64 bare-metal tryboot reboot command")
        return 1
    fi

    if ! wait_for_ssh_down "$PI_BARE_HOST" 60; then
        stop_pi5_serial_capture "$serial_pid"
        echo "[FAIL] $PI_BARE_HOST did not drop SSH after stygia-reboot tryboot"
        echo "--- reboot output ---"
        tail -60 "$reboot_log"
        echo "--- end ---"
        echo "       logs: $run_log_dir"
        FAILURES+=("aarch64 bare-metal tryboot did not reboot")
        return 1
    fi
    if ! wait_for_ssh_up "$PI_BARE_HOST" "$PI_BARE_RETURN_TIMEOUT"; then
        stop_pi5_serial_capture "$serial_pid"
        echo "[FAIL] $PI_BARE_HOST did not return to Pi OS within ${PI_BARE_RETURN_TIMEOUT}s"
        echo "--- last 40 lines of Pi5 serial output ---"
        LC_ALL=C tr -d '~\000' < "$serial_log" | tail -40
        echo "--- end ---"
        echo "       logs: $run_log_dir"
        FAILURES+=("aarch64 bare-metal tryboot did not return")
        return 1
    fi
    # Let the last UART bytes drain after SSH comes back.
    sleep 2
    stop_pi5_serial_capture "$serial_pid"

    if ! verify_aarch64_bare_tryboot_log "$serial_log" "$label"; then
        echo "       logs: $run_log_dir"
        return 1
    fi

    rm -rf "$run_log_dir"
    echo "[PASS] $label on Pi5 bare metal tryboot"
    return 0
}

# Run an aarch64 in-kernel test bundle 3× under local QEMU+TCG and
# report PASS/FAIL the same shape as the Pi path. Caller has already
# built kernel.elf + the bundled root_service.elf in zig-out/img and
# tests/suite/bin respectively. label = stage description for logs;
# fail_tag = prefix for FAILURES entries on this stage.
run_aarch64_tcg_3reps() {
    local label="$1"
    local fail_tag="$2"
    # Stage a clean FAT image dir so per-rep boots don't share state.
    local fat
    fat=$(mktemp -d)
    mkdir -p "$fat/img/efi/boot"
    cp "$STYGIA_ROOT/zig-out/img/kernel.elf" "$fat/img/"
    cp "$SCRIPT_DIR/suite/bin/root_service.elf" "$fat/img/"
    cp "$STYGIA_ROOT/zig-out/img/efi/boot/BOOTAA64.EFI" "$fat/img/efi/boot/"

    local rep
    for rep in 1 2 3; do
        echo "Boot ${rep}/3 under qemu-system-aarch64 + TCG (${label})..."
        local tcg_log
        tcg_log=$(mktemp)
        # virtualization=on so qemu exposes EL2; required by the VM-
        # related spec tests (acquire_ecs_07, create_vcpu_03/06/07,
        # create_virtual_machine_*) which would otherwise hit
        # `vmSupported() == false` and surface E_NODEV from
        # create_virtual_machine. Pi 5 KVM cannot host these tests
        # (no nested virt + GICv2 only) so the TCG fallback is the
        # canonical aarch64 path for the VM-touching subset.
        if ! timeout 600 qemu-system-aarch64 \
            -M virt,gic-version=3,virtualization=on -m 2G \
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
        # A clean summary is not proof the kernel survived — another core
        # can die while the runner keeps reporting. See verify_no_kernel_faults.
        if ! verify_no_kernel_faults "$tcg_log" "${label} (rep ${rep}/3)"; then
            rm -f "$tcg_log"
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
    if ! (cd "$SCRIPT_DIR/suite" && rm -rf bin/ .zig-cache && \
          zig build -Darch=arm \
          -Dtests='acquire_ecs_07,create_vcpu_03,create_vcpu_06,create_vcpu_07,create_virtual_machine_06,create_virtual_machine_07'); then
        FAILURES+=("aarch64 vm-tests root_service build")
        return 1
    fi
    # zig-out is not pruned on an arch switch, and the indexer stage above
    # builds both arches back-to-back, so clear it before producing an image
    # that will actually be booted (build.zig also refuses a mixed one).
    rm -rf "$STYGIA_ROOT/zig-out"
    echo "Building aarch64 kernel..."
    if ! (cd "$STYGIA_ROOT" && zig build -Darch=arm -Dprofile=test); then
        FAILURES+=("aarch64 vm-tests kernel build")
        return 1
    fi
    run_aarch64_tcg_3reps "aarch64 VM spec tests (TCG)" "aarch64 vm-tests"
}

stage_aarch64_vm_nodev_pi_kvm() {
    echo ""
    echo "=================================================="
    echo "[2b/4] aarch64 create_virtual_machine_03 E_NODEV test (Pi QEMU/KVM, no nested EL2, 3 reps)"
    echo "=================================================="
    local qemu_host
    if ! qemu_host=$(select_aarch64_qemu_host); then
        echo "[FAIL] no Pi QEMU/KVM host reachable in PI_QEMU_HOSTS='$PI_QEMU_HOSTS'"
        echo "       This focused hv=false proof must run on .106/.104-style QEMU/KVM, not bare-metal $PI_BARE_HOST."
        FAILURES+=("aarch64 create_virtual_machine_03 Pi KVM proof unavailable")
        return 1
    fi

    echo "Building aarch64 root_service (create_virtual_machine_03 only, runner diagnostics on)..."
    if ! (cd "$SCRIPT_DIR/suite" && rm -rf bin/ .zig-cache && \
          zig build -Darch=arm -Dtests='create_virtual_machine_03' -Drunner_diag=true -Dexpect_hv=false); then
        FAILURES+=("aarch64 create_virtual_machine_03 root_service build")
        return 1
    fi
    # Build a fresh aarch64 image after the positive-EL2 TCG stage. This
    # stage runs it under Pi-hosted QEMU/KVM, which does not expose
    # nested EL2 to Stygia. That is the matrix's legitimate
    # no-hardware-virtualization environment for
    # create_virtual_machine_03's exact E_NODEV assertion.
    rm -rf "$STYGIA_ROOT/zig-out"
    echo "Building aarch64 kernel..."
    if ! (cd "$STYGIA_ROOT" && zig build -Darch=arm -Dprofile=test); then
        FAILURES+=("aarch64 create_virtual_machine_03 kernel build")
        return 1
    fi

    echo "Syncing focused E_NODEV artifacts to $qemu_host..."
    if ! ssh "$qemu_host" "mkdir -p $PI_REMOTE_DIR/img/efi/boot"; then
        FAILURES+=("ssh mkdir on Pi for create_virtual_machine_03")
        return 1
    fi
    if ! scp -q "$STYGIA_ROOT/zig-out/img/kernel.elf" \
        "$qemu_host:$PI_REMOTE_DIR/img/kernel.elf"; then
        FAILURES+=("scp kernel.elf to Pi for create_virtual_machine_03")
        return 1
    fi
    if ! scp -q "$STYGIA_ROOT/zig-out/img/efi/boot/BOOTAA64.EFI" \
        "$qemu_host:$PI_REMOTE_DIR/img/efi/boot/BOOTAA64.EFI"; then
        FAILURES+=("scp BOOTAA64.EFI to Pi for create_virtual_machine_03")
        return 1
    fi
    if ! scp -q "$SCRIPT_DIR/suite/bin/root_service.elf" \
        "$qemu_host:$PI_REMOTE_DIR/root_service-nodev.elf"; then
        FAILURES+=("scp root_service-nodev.elf to Pi")
        return 1
    fi

    local rep
    for rep in 1 2 3; do
        echo "Boot ${rep}/3 under qemu-system-aarch64 + KVM on $qemu_host (no nested EL2)..."
        local pi_log
        pi_log=$(mktemp)
        if ! ssh "$qemu_host" "cd $PI_REMOTE_DIR && wd=\$(mktemp -d) && mkdir -p \$wd/efi/boot && cp img/efi/boot/BOOTAA64.EFI \$wd/efi/boot/ && cp img/kernel.elf \$wd/ && cp root_service-nodev.elf \$wd/root_service.elf && timeout 240 qemu-system-aarch64 -M virt,gic-version=2 -m 2G -bios /usr/share/AAVMF/AAVMF_CODE.fd -serial stdio -display none -no-reboot -machine accel=kvm -cpu host -smp cores=4 -drive file=fat:rw:\$wd,format=raw 2>&1; rc=\$?; rm -rf \$wd; exit \$rc" > "$pi_log" 2>&1; then
            echo "[FAIL] Pi KVM run ${rep}/3 on $qemu_host failed or timed out"
            echo "--- last 30 lines of Pi output ---"
            tail -30 "$pi_log"
            echo "--- end ---"
            rm -f "$pi_log"
            FAILURES+=("aarch64 create_virtual_machine_03: Pi KVM run timeout/qemu error (rep ${rep}/3)")
            return 1
        fi
        local total
        total=$(grep -E '^\[runner\] [0-9]+ total' "$pi_log" | tail -1)
        if [[ -z "$total" ]]; then
            echo "[FAIL] rep ${rep}/3 (create_virtual_machine_03 Pi KVM on $qemu_host): no [runner] total"
            echo "--- last 30 lines of Pi output ---"
            tail -30 "$pi_log"
            echo "--- end ---"
            rm -f "$pi_log"
            FAILURES+=("aarch64 create_virtual_machine_03: no [runner] total (rep ${rep}/3)")
            return 1
        fi
        if ! echo "$total" | grep -qE '0 fail / 0 miss'; then
            echo "[FAIL] rep ${rep}/3 (create_virtual_machine_03 Pi KVM on $qemu_host): $total"
            grep -E '^\[runner\] (FAIL|MISS)' "$pi_log" | head -20
            rm -f "$pi_log"
            FAILURES+=("aarch64 create_virtual_machine_03 Pi KVM rep ${rep}/3: ${total#'[runner] '}")
            return 1
        fi
        if ! grep -Eq '^\[runner\] deliver [0-9]+:create_virtual_machine_03 .* code=1 aid=8 -> record$' "$pi_log"; then
            echo "[FAIL] rep ${rep}/3: create_virtual_machine_03 did not report PASS aid=8 (E_NODEV)"
            echo "--- runner diagnostics ---"
            grep -E '^\[runner\] (deliver|PASS|FAIL|MISS|[0-9]+ total)' "$pi_log" | tail -20
            echo "--- end ---"
            rm -f "$pi_log"
            FAILURES+=("aarch64 create_virtual_machine_03 Pi KVM rep ${rep}/3: missing PASS aid=8 evidence")
            return 1
        fi
        if ! verify_no_kernel_faults "$pi_log" "aarch64 create_virtual_machine_03 Pi KVM on $qemu_host (rep ${rep}/3)"; then
            rm -f "$pi_log"
            return 1
        fi
        echo "[OK]   rep ${rep}/3: ${total#'[runner] '} (PASS aid=8/E_NODEV observed)"
        rm -f "$pi_log"
    done

    echo "[PASS] aarch64 create_virtual_machine_03 E_NODEV on Pi KVM ($qemu_host) - 3/3 green"
    return 0
}

stage_aarch64_kernel_tests_pi() {
    echo ""
    echo "=================================================="
    echo "[2/4] aarch64 kernel test suite (Pi5 bare-metal tryboot; QEMU/KVM fallback)"
    echo "=================================================="

    local bare_reachable=0
    if aarch64_pi_reachable "$PI_BARE_HOST"; then
        bare_reachable=1
    fi

    echo "Building aarch64 root_service (full suite with embedded test ELFs)..."
    local suite_args=(-Darch=arm)
    if [[ $bare_reachable -eq 1 ]]; then
        # Bare metal gets one tryboot cycle; repeat inside the runner preserves
        # this stage's historical three-suite coverage without three remote
        # firmware reboot cycles. The QEMU/KVM fallback keeps the current
        # three separate boots and therefore does not use this repeat knob.
        suite_args+=("-Drepeat=$PI_BARE_REPEAT")
    else
        # Pi-hosted QEMU/KVM does not expose nested EL2 to the guest.
        suite_args+=("-Dexpect_hv=false")
    fi
    if ! (cd "$SCRIPT_DIR/suite" && rm -rf bin/ .zig-cache && zig build "${suite_args[@]}"); then
        FAILURES+=("aarch64 root_service build")
        return 1
    fi

    # zig-out is not pruned on an arch switch, and the indexer stage above
    # builds both arches back-to-back, so clear it before producing an image
    # that will actually be booted (build.zig also refuses a mixed one).
    rm -rf "$STYGIA_ROOT/zig-out"
    echo "Building aarch64 UEFI/QEMU kernel artifacts..."
    if ! (cd "$STYGIA_ROOT" && zig build -Darch=arm -Dprofile=test); then
        FAILURES+=("aarch64 kernel build")
        return 1
    fi

    if [[ $bare_reachable -eq 1 ]]; then
        echo ""
        echo "(Full suite first targets bare-metal Pi5 tryboot on $PI_BARE_HOST; hv=true, real EL2.)"
        # The pi5 build embeds the already-built full-suite root_service into
        # zig-out/pi5/kernel_stygia.img for the existing .107 deploy_stub.sh +
        # stygia-reboot tryboot workflow. The UEFI/QEMU artifacts above remain
        # available in zig-out/img for the fallback topology when .107 is down.
        echo "Building aarch64 Pi5 bare-metal image..."
        if ! (cd "$STYGIA_ROOT" && zig build -Darch=arm -Dprofile=test pi5); then
            FAILURES+=("aarch64 bare-metal pi5 image build")
            return 1
        fi
        run_aarch64_bare_tryboot "aarch64 kernel tests (bare-metal tryboot)"
        return $?
    fi

    local qemu_host
    if ! qemu_host=$(select_aarch64_qemu_host); then
        echo "[FAIL] bare-metal Pi5 ($PI_BARE_HOST) unreachable, and no QEMU/KVM fallback host reachable in PI_QEMU_HOSTS='$PI_QEMU_HOSTS'"
        FAILURES+=("aarch64 kernel tests unavailable")
        return 1
    fi

    echo ""
    echo "Bare-metal Pi5 ($PI_BARE_HOST) unreachable — falling back to Pi-hosted QEMU/KVM on $qemu_host."
    echo "(Fallback is hv=false: QEMU/KVM on Pi has no nested EL2. Stage [2b/4] still pins create_virtual_machine_03 explicitly.)"

    echo "Syncing artifacts to $qemu_host..."
    if ! ssh "$qemu_host" "mkdir -p $PI_REMOTE_DIR/img/efi/boot"; then
        FAILURES+=("ssh mkdir on Pi")
        return 1
    fi
    if ! scp -q "$STYGIA_ROOT/zig-out/img/kernel.elf" \
        "$qemu_host:$PI_REMOTE_DIR/img/kernel.elf"; then
        FAILURES+=("scp kernel.elf to Pi")
        return 1
    fi
    if ! scp -q "$STYGIA_ROOT/zig-out/img/efi/boot/BOOTAA64.EFI" \
        "$qemu_host:$PI_REMOTE_DIR/img/efi/boot/BOOTAA64.EFI"; then
        FAILURES+=("scp BOOTAA64.EFI to Pi")
        return 1
    fi
    if ! scp -q "$SCRIPT_DIR/suite/bin/root_service.elf" \
        "$qemu_host:$PI_REMOTE_DIR/root_service.elf"; then
        FAILURES+=("scp root_service.elf to Pi")
        return 1
    fi

    # Three boots in a row, fail the whole stage on the first miss/fail.
    # Catches flakes that a single run wouldn't surface.
    local rep
    for rep in 1 2 3; do
        echo "Boot ${rep}/3 under qemu-system-aarch64 + KVM on $qemu_host..."
        local pi_log
        pi_log=$(mktemp)
        if ! ssh "$qemu_host" "cd $PI_REMOTE_DIR && wd=\$(mktemp -d) && mkdir -p \$wd/efi/boot && cp img/efi/boot/BOOTAA64.EFI \$wd/efi/boot/ && cp img/kernel.elf \$wd/ && cp root_service.elf \$wd/ && timeout 240 qemu-system-aarch64 -M virt,gic-version=2 -m 2G -bios /usr/share/AAVMF/AAVMF_CODE.fd -serial stdio -display none -no-reboot -machine accel=kvm -cpu host -smp cores=4 -drive file=fat:rw:\$wd,format=raw 2>&1; rc=\$?; rm -rf \$wd; exit \$rc" > "$pi_log" 2>&1; then
            echo "[FAIL] Pi qemu run ${rep}/3 on $qemu_host failed or timed out"
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

        # A clean summary is not proof the kernel survived — another core
        # can die while the runner keeps reporting. See verify_no_kernel_faults.
        if ! verify_no_kernel_faults "$pi_log" "aarch64 kernel tests on $qemu_host (rep ${rep}/3)"; then
            rm -f "$pi_log"
            return 1
        fi
        echo "[OK]   rep ${rep}/3: ${total#'[runner] '}"
        rm -f "$pi_log"
    done

    echo "[PASS] aarch64 kernel tests — 3/3 green"
    return 0
}

stage_linux_guest_x86_boot() {
    echo ""
    echo "=================================================="
    echo "[3/4] linux_guest VMM boot (x86-64 KVM)"
    echo "=================================================="
    clean_nvvars

    # ReleaseSafe: Debug mode triggers a known LAPIC MMIO codegen issue.
    if ! (cd "$STYGIA_ROOT/tests/linux_guest" && zig build); then
        FAILURES+=("linux_guest build")
        return 1
    fi
    # zig-out is not pruned on an arch switch, and stages [2/4]+[2a/4]
    # leave an aarch64 image behind, so clear it before producing an
    # image that will actually be booted (build.zig also refuses a mixed
    # one). Every other booting stage does this; [3/4] was the one miss.
    rm -rf "$STYGIA_ROOT/zig-out"
    if ! (cd "$STYGIA_ROOT" && zig build -Dprofile=linux_guest -Diommu=amd -Doptimize=ReleaseSafe); then
        FAILURES+=("linux_guest kernel build")
        return 1
    fi

    local qemu_log
    qemu_log=$(mktemp)
    # setsid + process-group kill: each linux_guest stage runs in its own
    # session/PGID so the [3/4] cleanup reaps ONLY this stage's qemu (and
    # its zig-build / timeout parents), not any other worktree's qemu of
    # the same arch. The previous `pkill -f "qemu-system-x86_64"` matched
    # host-wide and could SIGTERM a parallel worker's in-flight reproducer
    # mid-rep (bd-Zag-Subsystems-Agents-l2wf).
    setsid bash -c "cd \"$STYGIA_ROOT\" && PATH=\"$QEMU_SHIM_PATH\" timeout 360 zig build run -Dprofile=linux_guest -Diommu=amd -Doptimize=ReleaseSafe -- -display none" \
        > "$qemu_log" 2>&1 &
    local qemu_pid=$!

    # Smoke test only — we look for `entering exit loop` (printed by the
    # VMM right before it dispatches its first VMEXIT) to confirm kernel
    # + bootloader + VMM root service + VM/vCPU/port creation + Linux
    # configuration all came up cleanly. Earlier markers (`=== linux_guest
    # (spec-v3) ===`, `VM handle=`) can interleave with concurrent
    # `[ap N] entering sched.run` prints during AP bring-up — both the
    # VMM (userspace, MMIO COM1 writes) and the kernel-side scheduler
    # banner write the same UART without a shared lock, and on faster
    # boots the VMM hits its first prints before AP3 has finished its
    # banner. `entering exit loop` fires after createPort + createVcpu
    # + ACPI/Linux setup — many ms of single-threaded VMM activity past
    # the end of AP bring-up — so it survives intact. Full Linux boot
    # to a guest shell is blocked on aarch64 typed-reply parity and the
    # in-flight reply debugging; promote this to a stronger marker once
    # that lands.
    local found=0
    for _ in $(seq 1 360); do
        if grep -q "entering exit loop" "$qemu_log" 2>/dev/null; then
            found=1
            break
        fi
        sleep 1
    done

    kill -TERM -- "-$qemu_pid" 2>/dev/null || true
    sleep 2
    kill -KILL -- "-$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true

    if [[ $found -eq 1 ]]; then
        echo "[PASS] linux_guest VMM came up (x86-64)"
        rm -f "$qemu_log"
        return 0
    else
        echo "[FAIL] linux_guest VMM did not reach exit loop within 360s (x86-64)"
        echo "--- last 30 lines of QEMU output ---"
        tail -30 "$qemu_log"
        echo "--- end ---"
        rm -f "$qemu_log"
        FAILURES+=("linux_guest VMM boot (x86-64)")
        return 1
    fi
}

stage_linux_guest_aarch64_boot() {
    echo ""
    echo "=================================================="
    echo "[4/4] linux_guest VMM boot (aarch64, local TCG)"
    echo "=================================================="
    # TCG, not KVM-on-Pi: the Pi 5 does not expose nested virt, and Pi
    # KVM only supports gic-version=2 while our driver is GICv3. The
    # aarch64 linux_guest path puts Stygia at EL2, so it has to run under
    # TCG with `virtualization=on`. The aarch64 kernel test suite still
    # runs on Pi KVM (stage 2) because those tests don't take the
    # kernel into EL2.

    if ! (cd "$STYGIA_ROOT/tests/linux_guest" && zig build -Darch=arm); then
        FAILURES+=("aarch64 linux_guest build")
        return 1
    fi
    # zig-out is not pruned on an arch switch, and the indexer stage above
    # builds both arches back-to-back, so clear it before producing an image
    # that will actually be booted (build.zig also refuses a mixed one).
    rm -rf "$STYGIA_ROOT/zig-out"
    if ! (cd "$STYGIA_ROOT" && zig build -Darch=arm -Dprofile=linux_guest -Dkvm=false -Doptimize=ReleaseSafe); then
        FAILURES+=("aarch64 linux_guest kernel build")
        return 1
    fi

    # Stage a clean FAT image dir so this boot doesn't share state
    # with the aarch64 kernel-tests stage's image.
    local fat
    fat=$(mktemp -d)
    mkdir -p "$fat/img/efi/boot"
    cp "$STYGIA_ROOT/zig-out/img/kernel.elf" "$fat/img/"
    cp "$STYGIA_ROOT/tests/linux_guest/bin/linux_guest-arm.elf" "$fat/img/root_service.elf"
    cp "$STYGIA_ROOT/zig-out/img/efi/boot/BOOTAA64.EFI" "$fat/img/efi/boot/"

    local qemu_log
    qemu_log=$(mktemp)
    # setsid + process-group kill: see x86 stage comment. Wrapping qemu
    # in its own session means cleanup reaps only this stage's qemu, not
    # any other worktree's aarch64 qemu (bd-Zag-Subsystems-Agents-l2wf).
    setsid timeout 600 qemu-system-aarch64 \
        -M virt,gic-version=3,virtualization=on -m 2G \
        -bios /usr/share/AAVMF/AAVMF_CODE.fd \
        -serial stdio -display none -no-reboot \
        -machine accel=tcg -cpu cortex-a72,pmu=on \
        -smp cores=1 \
        -drive file=fat:rw:"$fat/img",format=raw \
        > "$qemu_log" 2>&1 &
    local qemu_pid=$!

    # End-to-end marker — the busybox initramfs `init` script prints
    # "hello from guest" once Linux has reached userspace. Anything short
    # of that means Linux didn't actually run.
    local found=0
    for _ in $(seq 1 600); do
        if grep -q "hello from guest" "$qemu_log" 2>/dev/null; then
            found=1
            break
        fi
        sleep 1
    done

    kill -TERM -- "-$qemu_pid" 2>/dev/null || true
    sleep 2
    kill -KILL -- "-$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true

    if [[ $found -eq 1 ]]; then
        echo "[PASS] linux_guest aarch64 booted Linux to busybox init"
        rm -f "$qemu_log"
        rm -rf "$fat"
        return 0
    else
        echo "[FAIL] linux_guest aarch64 did not reach busybox init within 600s"
        echo "--- last 30 lines of QEMU output ---"
        tail -30 "$qemu_log"
        echo "--- end ---"
        rm -f "$qemu_log"
        rm -rf "$fat"
        FAILURES+=("aarch64 linux_guest VMM boot")
        return 1
    fi
}


# ── Dispatch ──────────────────────────────────────────────────────────

ensure_suite_root_service_elf || true

run_stage arch_layering_lint
run_stage dead_code_report
run_stage gen_lock_analyzer
run_stage ec_closure_report
run_stage verify_coverage
run_stage x86_kernel_tests
run_stage aarch64_kernel_tests_pi
run_stage aarch64_vm_tests_tcg
run_stage aarch64_vm_nodev_pi_kvm
run_stage linux_guest_x86_boot
run_stage linux_guest_aarch64_boot

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
