# Stygia

Stygia is a capability-based microkernel for building secure, fast, and reliable operating systems.

## Kernel Objects

Userspace interacts with the kernel through handles to typed kernel objects. Each row links to the relevant section of [the spec](docs/kernel/specv3.md) for the full handle ABI, capability bits, and syscall surface.

| Object | Role | Spec |
|---|---|---|
| **Capability Domain** | A set of capabilities usable by the threads bound to the domain. The process-equivalent boundary in Stygia. | [§[capability_domain]](docs/kernel/specv3.md#capability_domain-capability-domain) |
| **Thread** | A schedulable unit of executable state bound to a capability domain. The thread-equivalent. | [§[thread]](docs/kernel/specv3.md#thread-thread) |
| **VMAR** | A virtual memory address region: a contiguous span of virtual address space bound to a capability domain, available for demand-paged memory or for installing page frames and device regions. | [§[vmar]](docs/kernel/specv3.md#vmar-virtual-memory-address-region) |
| **Page Frame** | A reference to physical memory. Installing the same page frame into multiple capability domains creates shared memory. | [§[page_frame]](docs/kernel/specv3.md#page_frame-page-frame) |
| **Device Region** | A reference to a device's MMIO region or x86-64 I/O port range. Installing it into a VMAR makes the device directly accessible to threads in that capability domain. | [§[device_region]](docs/kernel/specv3.md#device_region-device-region) |
| **Virtual Machine** | A guest execution environment with its own guest physical address space. Threads enter guest mode within a VM to run. | [§[virtual_machine]](docs/kernel/specv3.md#virtual_machine-virtual-machine) |
| **Port** | A rendezvous point between a calling thread and a receiving thread. Used for IDC, capability transfer, and event delivery. | [§[port]](docs/kernel/specv3.md#port-port) |
| **Reply** | A one-shot capability referencing a suspended thread dequeued from a port by a receive. Consuming the handle is the only way to resume or abandon the suspended sender. | [§[reply]](docs/kernel/specv3.md#reply-reply) |

## Scope

**Memory.** Demand-paged virtual memory address regions (VMARs), page table management, shared mappings (the same page frame mapped into multiple capability domains), and direct MMIO BAR mapping for userspace device access. DMA always routes through the IOMMU, so a misbehaving or compromised device cannot escape the buffer it was given.

**Scheduling.** Preemptive round-robin scheduler. Per-thread core affinities and priorities that propagate through ports and futex waitlists. Futex primitive that integrates with the scheduler so a waiter blocks rather than spins.

**IPC.** Capability-gated ports for suspend / receive / reply between capability domains. When the payload fits in architectural general-purpose registers and carries data only (no capability transfer), the rendezvous runs through an L4-style zero-register-copy fast path that does a direct context switch and bypasses the Zig dispatch table. Current round-trip cost is around 1,600 cycles for suspend → receive → reply on a Ryzen 9 7950X3D.

**Kernel-event routing.** Per-thread events (memory faults, thread faults, breakpoints) can be bound to ports so that debuggers and supervisors handle them as IPC messages. Suspension events and VM exits are always delivered to a port by construction.

**Time.** A monotonic clock primitive. Internal scheduler ticks and deadline checks drive preemption and timed waits.

**Virtual machines.** KVM-style guest containers. vCPUs are threads in a VM-flavored capability domain; userspace maps guest-physical memory, sets per-VM policies, and injects IRQs.

## Status

The kernel test suite has one ELF per retained spec assertion. Run the suite on each supported architecture to check the current implementation.

## Building

The kernel boots a single user-supplied ELF as its root service. The build is two-stage: build a root service ELF, then build the kernel pointing at it.

### Build and run the test suite

```bash
cd tests/suite && zig build && cd ..        # produces tests/suite/bin/root_service.elf
zig build run -Dprofile=test                # build the kernel and boot it under QEMU/KVM
```

The `test` profile sets the root service path and other defaults. The in-kernel runner prints per-test pass/fail lines plus a final summary like `[runner] N total / N pass / 0 fail / 0 miss`.

For aarch64 (KVM is unavailable for aarch64 guests on most x86 dev hosts, so fall back to TCG):

```bash
cd tests/suite && zig build -Darch=arm && cd ..
zig build run -Darch=arm -Dprofile=test -Dkvm=false
```

### Install your own root service

A root service is a freestanding ELF that imports [`libz`](libz/) and uses whichever syscalls it needs. The `app` profile boots one:

```bash
zig build run -Dprofile=app -Droot-service=path/to/your_root.elf
```

The profile sets sensible defaults (LLVM backend, KVM on, intel IOMMU, user-mode networking, headless display). Override individual flags with `-Dkvm`, `-Diommu`, `-Dnet`, `-Ddisplay`, `-Darch`, etc. See `tests/suite/runner/` and `tests/linux_guest/vmm/` for working examples of root services.

### Boot Linux as a guest VM

The `tests/linux_guest` directory contains a userspace VMM that boots the bundled Linux image:

```bash
cd tests/linux_guest && zig build && cd ..
zig build run -Dprofile=linux_guest
```

## Repo Layout

```
kernel/                Kernel proper
  arch/                  Arch dispatch (dispatch/) + per-arch backends (x64, aarch64)
  boot/                  UEFI handoff and userspace bringup
  caps/                  Capability and handle types, capability domain
  devices/               Device region registry
  hv/                    Vendor-neutral hypervisor (Virtual Machine kernel object)
  memory/                PMM, VMM, VMARs, page frames, paging, allocators/ (SecureSlab lives here)
  sched/                 Scheduler, thread, futex, port, FPU
  syscall/               Per-object syscall handlers and dispatch
  utils/                 Sync primitives, ELF and DWARF debug info, generic Range
  stygia.zig                Root module (every kernel file imports through this)

bootloader/            UEFI bootloader (KASLR, kernel + root-service load)

libz/                  Userspace library (caps, errors, syscall*, loader, libc compat)

slab_proof/            Lean proof of GenLock + SecureSlab safety

tests/
  suite/                 Spec test runner
    runner/              In-kernel orchestrator + libz testing helpers
    cases/               One ELF per spec assertion (recv_07.zig, etc.)
    build.zig            Authoritative test manifest (-Dtests=<glob> for subsets)
    verify_coverage.py   Spec to test parity check
  linux_guest/           Linux VMM root service (with bundled bzImage + initramfs)
  precommit.sh           Cross-arch precommit gauntlet

tools/                 Dev tooling (see the Tooling section)

docs/
  kernel/                specv3.md (single source of truth) + systems.md
  x86/                   Intel SDM, VMX, VT-d, AMD SVM, AMD-Vi PDFs
  aarch64/               ARM ARM, GICv3, SMMUv3, PSCI, IORT, PL011 PDFs
  devices/               NVMe, xHCI, virtio, x550 datasheets
  tools/                 Tool screenshots
```

## License

Stygia is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.

Copyright 2026 Alec Fessler.
