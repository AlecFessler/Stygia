#!/bin/bash
# Reproduce + capture the smp=4 silent-failure flake on the kernel
# test suite. Wraps the `zig build run -Dprofile=test` QEMU invocation
# with `-d cpu_reset,guest_errors -D <qemu.log>` so triple-fault /
# guest-error reasons land in /tmp/qemu_run_<id>.log and the serial
# stream lands in /tmp/zag_run_<id>.log. Builds must be present
# already (do `(cd tests/suite && zig build) && zig build -Dprofile=test`
# beforehand).
#
# Usage:
#   tools/repro_smp4_hang.sh <run_id>
#   for i in $(seq 1 30); do tools/repro_smp4_hang.sh $i; done
#
# Observed failure modes on l4-ipc-fast-path @ 3293824e2 (~16% rate):
#   A) silent KVM exit at "[runner] spawned 4/4 [" partial line, dur~5s,
#      rc=0, qemu.log shows only the 8 boot CPU resets (4 cores × 2
#      rounds). Triple-fault hits before the kernel emits any panic
#      text — neither @panic nor an exception handler fires before the
#      core resets. Affects the L4 IPC fast-path window per
#      project_l4_smp4_kstack_lifetime.md.
#   B) hard hang ~30s no progress, rc=124 (timeout), kernel stalled
#      mid-batch but serial drained intact up to the stall.
#   C) (rare) boot-time hang at "[ZAG] exit BS" — kernel never
#      reached "[boot] root EC ready". Possibly distinct from A/B.

set -u
INSTALL=$(cd "$(dirname "$0")/.." && pwd)/zig-out
RUN=$1
QEMULOG=/tmp/qemu_run_${RUN}.log
SERIAL=/tmp/zag_run_${RUN}.log
rm -f "$QEMULOG" "$SERIAL"

timeout 90 qemu-system-x86_64 \
  -m 4G \
  -bios /usr/share/ovmf/x64/OVMF.4m.fd \
  -drive file=fat:rw:${INSTALL}/img,format=raw \
  -serial mon:stdio \
  -display none \
  -no-reboot \
  -d cpu_reset,guest_errors \
  -D ${QEMULOG} \
  -enable-kvm \
  -cpu host,+invtsc \
  -machine q35 \
  -device intel-iommu,intremap=off \
  -net none \
  -smp cores=4 \
  > "$SERIAL" 2>&1
echo $?
