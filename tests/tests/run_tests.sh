#!/bin/bash
# Run kernel test suite with per-assertion QEMU isolation.
# Each assertion gets its own QEMU boot. Tests run in parallel.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZAG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
## Per-test QEMU wall-clock budget. Individual tests are tiny (boot kernel,
## run one assertion, shutdown), so ~2s is plenty on an idle host — but
## under `PARALLEL=8` on a 16-core / 32-thread box, 8x4=32 vCPUs oversubscribe
## the host and a single assertion has been observed to take >30s to reach
## its first serial write. The timeout needs to be large enough to absorb
## that scheduling delay without masking real regressions; 120s is well
## above anything a healthy assertion has produced in practice.
TIMEOUT=120
# Default to a single QEMU instance to keep agent runs from blowing up RAM.
# Override interactively with `PARALLEL=16 bash run_tests.sh` for fast local runs.
PARALLEL="${PARALLEL:-1}"
# Target architecture:
#   x64 — x86_64 via OVMF UEFI + KVM (default)
#   arm — aarch64 via AAVMF UEFI + TCG, virtualization=on (real EL2 for KVM tests)
ARCH="${ARCH:-x64}"

if [ "$ARCH" = "arm" ]; then
    QEMU_CMD="qemu-system-aarch64 -M virt,virtualization=on,gic-version=3 -m 1G -bios /usr/share/AAVMF/AAVMF_CODE.fd -serial stdio -display none -no-reboot -machine accel=tcg -cpu cortex-a72 -smp cores=4"
    BUILD_ARCH_FLAG="-Darch=arm"
    LOADER="BOOTAA64.EFI"
else
    QEMU_CMD="qemu-system-x86_64 -m 2G -bios /usr/share/ovmf/x64/OVMF.4m.fd -serial stdio -display none -no-reboot -enable-kvm -cpu host,+invtsc -machine q35 -device intel-iommu,intremap=off -net none -smp cores=4"
    BUILD_ARCH_FLAG=""
    LOADER="BOOTX64.EFI"
fi

# Verify spec coverage before running tests
echo "Verifying spec/test coverage..."
if ! python3 "$SCRIPT_DIR/verify_coverage.py"; then
    echo "ABORT: Spec/test mismatch. Fix before running tests."
    exit 1
fi
echo ""

IMG_DIR="$ZAG_ROOT/zig-out/img"
BIN_DIR="$SCRIPT_DIR/bin"
RESULTS_DIR=$(mktemp -d)

# Build all test ELFs
echo "Building test ELFs ($ARCH)..."
cd "$SCRIPT_DIR"
if [ -n "$BUILD_ARCH_FLAG" ]; then
    zig build $BUILD_ARCH_FLAG 2>/dev/null
else
    zig build 2>/dev/null
fi

# Create placeholder root_service.elf for kernel build
first_elf=$(find "$BIN_DIR" -name 's*.elf' | head -1)
cp "$first_elf" "$BIN_DIR/root_service.elf"

# Build kernel (creates zig-out/img/ with kernel.elf, efi/, etc.)
echo "Building kernel ($ARCH)..."
cd "$ZAG_ROOT"
if [ -n "$BUILD_ARCH_FLAG" ]; then
    zig build $BUILD_ARCH_FLAG -Dprofile=test 2>/dev/null
else
    zig build -Dprofile=test 2>/dev/null
fi
echo ""

run_one_test() {
    local elf="$1"
    local name=$(basename "$elf" .elf)
    local workdir=$(mktemp -d)
    local output

    # Per-test root_service.elf is swapped via the FAT boot drive; the
    # kernel reads it via the bootloader.
    mkdir -p "$workdir/efi/boot"
    ln -s "$IMG_DIR/efi/boot/$LOADER" "$workdir/efi/boot/"
    ln -s "$IMG_DIR/kernel.elf" "$workdir/"
    cp "$IMG_DIR/NvVars" "$workdir/" 2>/dev/null || true
    cp "$elf" "$workdir/root_service.elf"

    output=$(timeout "$TIMEOUT" $QEMU_CMD -drive "file=fat:rw:$workdir,format=raw" 2>/dev/null || true)

    # Extract result line
    local result
    result=$(echo "$output" | grep -m1 '\[PASS\]\|\[FAIL\]\|\[SKIP\]' || true)
    # Strip ANSI escape codes
    result=$(echo "$result" | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g')

    if [ -z "$result" ]; then
        echo "[FAIL] $name (no output)" > "$RESULTS_DIR/$name"
    else
        echo "$result" > "$RESULTS_DIR/$name"
    fi

    rm -rf "$workdir"
}

export -f run_one_test
export IMG_DIR TIMEOUT QEMU_CMD RESULTS_DIR LOADER

# Collect all test ELFs, sorted
mapfile -t test_elfs < <(find "$BIN_DIR" -name '*.elf' ! -name 'root_service.elf' | sort)
total=${#test_elfs[@]}

echo "Running $total tests ($PARALLEL parallel)..."
echo ""

# Run in parallel
printf '%s\n' "${test_elfs[@]}" | xargs -P "$PARALLEL" -I{} bash -c 'run_one_test "$@"' _ {}

# Aggregate results
pass=0
fail=0
skip=0
failures=""
skips=""

for f in $(ls "$RESULTS_DIR"/ | sort); do
    result=$(cat "$RESULTS_DIR/$f")
    if echo "$result" | grep -q '\[PASS\]'; then
        pass=$((pass + 1))
    elif echo "$result" | grep -q '\[SKIP\]'; then
        skip=$((skip + 1))
        skips="$skips\n  $result"
    else
        fail=$((fail + 1))
        failures="$failures\n  $result"
    fi
done

rm -rf "$RESULTS_DIR"

echo "================================"
echo "Total: $pass pass, $skip skip, $fail fail out of $((pass + skip + fail))"
if [ "$skip" -gt 0 ]; then
    echo -e "Skipped:$skips"
fi
if [ "$fail" -eq 0 ]; then
    echo "All tests passed!"
else
    echo -e "Failures:$failures"
fi

exit $( [ "$fail" -eq 0 ] && echo 0 || echo 1 )
