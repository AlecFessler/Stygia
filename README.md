# Zag

A capability-based microkernel written in Zig, currently mid-rebuild against [spec v3](docs/kernel/specv3.md). The new kernel surface is implemented and the test runner is on its second generation; gaps are being closed test-by-test against the spec.

## Architecture

The kernel exposes a small set of typed capability objects. Userspace gets things done by holding handles to them and invoking syscalls.

| Object | Role |
|---|---|
| **Capability Domain** | Process-equivalent. Owns a 4096-entry handle table and the static caps that gate every syscall. |
| **Execution Context** | Thread-equivalent. Runnable, suspendable, attachable to vregs for IPC. |
| **VMAR** (Virtual Memory Address Region) | Mapped region in a domain's address space. Backed by page frames or device regions. |
| **Page Frame** | Contiguous physical memory, allocated and revocable. |
| **Device Region** | MMIO/port-IO range gated by a capability. |
| **Virtual Machine** | KVM-style guest container; vCPUs are ECs in a VM domain. |
| **Port** | IPC endpoint. ECs suspend on it; senders deliver vreg payloads. |
| **Event Route** | Kernel-event → port routing (faults, timers, exits). |
| **Reply** | One-shot capability minted on suspension; resolves a waiting EC. |
| **Timer** | Programmable one-shot/periodic wake on a port. |

Syscall ABI uses **128 virtual registers** (low ones backed by GPRs, the rest spill to the user stack), with an L4-style IPC fast path for suspend/reply that runs a 2-instruction classifier in `syscallEntry` and bypasses the Zig dispatch table for the hot rendezvous case. See [`docs/kernel/specv3.md`](docs/kernel/specv3.md) for the full spec.

## Repo layout

```
kernel/                Kernel proper
  arch/                  Arch dispatch + per-arch impls (x64, aarch64); hv/ for in-kernel hypervisor
  boot/                  UEFI handoff + userspace bringup
  caps/                  Capability/handle types, capability domain, derivation tree
  devices/               Device region registry
  hv/                    Vendor-neutral hypervisor (Virtual Machine kernel object)
  memory/                PMM, VMM, VMARs (vmar.zig), page frames, paging, fault, allocators/
  sched/                 Scheduler, EC, futex, port, timer, perfmon, FPU lazy save/restore, priority queue
  syscall/               Per-object syscall handlers + dispatch
  kprof/                 In-kernel tracing/sampling profiler + MMIO dump
  utils/                 sync primitives, ELF, DWARF debug info, generic Range
  zag.zig                Root module (every kernel file imports through this)
  .dead-code-skip.txt    Hash-validated allowlist for tools/dead_code_zig

bootloader/            UEFI bootloader (KASLR, kernel + root-service load)

libz/                  Canonical userspace library (caps.zig, errors.zig, syscall*.zig,
                       loader.zig). Top-level — sub-projects import from here, no per-project copies.

tests/
  suite/                 Spec v3 test runner
    runner/                primary.zig (in-kernel orchestrator) + lib.zig + start.zig + serial
    cases/                 one ELF per spec assertion (e.g. recv_07.zig)
    build.zig              authoritative test manifest (-Dtests=<glob> for subset builds)
    verify_coverage.py     enforces spec ↔ test parity
  linux_guest/           Linux VM hypervisor (the host VMM); active root service for VM testing
  perf/                  kprof-driven kernel perf workload (idc_pp) + scripts/
  precommit.sh           Cross-arch precommit gauntlet (also wired through .githooks/)

tools/                 Dev tooling (see Tools)

docs/
  kernel/                specv3.md (observable behavior — single source of truth)
  x86/                   Intel SDM / VMX / VT-d / AMD SVM / AMD-Vi PDFs
  aarch64/               ARM ARM, GICv3, SMMUv3, PSCI, IORT, PL011 PDFs
  devices/               NVMe, xHCI, virtio, x550 datasheets
  tools/                 Tool screenshots
```

## Test runner architecture

The kernel test suite runs entirely in-kernel — no host shell harness loops over QEMU boots. One QEMU boot runs the full suite via kernel SMP.

- The **primary** (root service, `tests/suite/runner/primary.zig`) owns all rights and drives the suite.
- It mints a single **result port** and spawns each test as its own child capability domain, passing the port handle with `bind | xfer` caps.
- Each test ELF is embedded into the primary at build time (`tests/suite/build.zig` is the manifest). Each test asserts spec behavior, then calls `libz.testing.report`, which suspends the initial EC on the result port with vregs encoding `{result_code, assertion_id, tag}`.
- The kernel scheduler/SMP gives parallelism for free. The primary `recv`s suspension events and writes them into a tag-indexed table; the tag is the manifest index, so result join is order-independent.
- A final pass over the manifest joins names with results and prints pass/fail per test plus a summary line: `[runner] N total / N pass / 0 fail / 0 miss`.

Test discovery is build-time: add an ELF under `tests/suite/cases/<slug>_NN.zig`, append an entry to `test_entries` in `tests/suite/build.zig`, and the runner picks it up.

## Building

Each root-service sub-project builds its own ELF first; the top-level kernel build references the resulting binary path through `-Dprofile=...`.

```bash
# Kernel test suite (x86_64, default)
cd tests/suite && zig build && cd ..        # builds root_service.elf with embedded test ELFs
zig build -Dprofile=test                    # builds the kernel
zig build run -Dprofile=test                # boot under QEMU/KVM, run the suite

# Cross-arch (aarch64)
cd tests/suite && zig build -Darch=arm && cd ..
zig build -Darch=arm -Dprofile=test -Dkvm=false

# Linux guest VMM (boots Linux under Zag)
cd tests/linux_guest && zig build && cd ..
zig build run -Dprofile=linux_guest -Doptimize=ReleaseSafe -- -display none
```

Useful build flags: `-Darch=x64|arm`, `-Dprofile=test|linux_guest`, `-Dkvm=true|false`, `-Diommu=intel|amd`, `-Dkernel_fastpath=false` (disable the L4 classifier for A/B perf comparison), `-Dkernel_profile=trace|sample` (compile in kprof; forces ReleaseFast + retains debug info), `-Demit_ir=true` (consumed by tools/indexer), `-Demit_index=true` (also rebuilds the callgraph DB).

## Tools

All under [`tools/`](tools/). Each builds with `zig build` from its own directory.

### callgraph DB — indexed callgraph + analyzer pipeline

The kernel is indexed into a per-(arch, commit_sha) SQLite DB built by [`tools/indexer/`](tools/indexer/) and queried by two daemons. The DB carries entities, ir_calls, AST, entry points, alias chains, type refs, binary symbols + disasm + DWARF lines, and analyzer findings — one schema, every consumer.

![callgraph trace view](docs/tools/callgraph_trace_view.png)

```bash
# Build the DB after a kernel build:
cd tools/indexer && zig build && cd ../..
zig build -Dprofile=test -Demit_ir=true   # gives us .ll + .elf
tools/indexer/zig-out/bin/indexer \
    --kernel-root kernel \
    --extra-source-root bootloader --extra-source-root tools \
    --extra-source-root tests --extra-source-root libz \
    --out tools/callgraph_http/test/dbs/x86_64-$(git rev-parse --short HEAD).db \
    --arch x86_64 --commit-sha $(git rev-parse HEAD) \
    --ir zig-out/kernel.x86_64.ll --elf zig-out/img/kernel.elf

# Then either daemon — both auto-discover DBs in their --db-dir:
cd tools/callgraph_http && zig build && ./zig-out/bin/callgraph_http \
    --db-dir ../callgraph_http/test/dbs --port 8080   # HTTP API + browser UI
cd tools/callgraph_mcp  && zig build && ./zig-out/bin/callgraph_mcp \
    --db-dir ../callgraph_http/test/dbs               # stdio MCP server
```

The MCP server speaks the production `callgraph_*` tool surface (callgraph_trace, callgraph_callers, callgraph_findings, …). The HTTP server has the matching /api/* routes plus a graph view, source/diff endpoints, and `/api/findings` for analyzer output.

### check_arch_layering — three-tier dispatch enforcement

[`tools/check_arch_layering/`](tools/check_arch_layering/) — verifies that kernel-proper code never reaches into `zag.arch.x64`/`zag.arch.aarch64` directly (must go through `zag.arch.dispatch`), and that arch-specific code doesn't call back through `dispatch`. Gating stage in precommit.

### check_gen_lock — SecureSlab gen-lock analyzer

[`tools/check_gen_lock/`](tools/check_gen_lock/) — token-based static analyzer that enforces the kernel's generational-lock invariant: every pointer to a slab-backed object (Execution Context, Capability Domain, VMAR, Port, …) is stored as `SlabRef(T)` and every dereference goes through a `lock()`/`unlock()` bracket, with a `// caller-pinned` annotation exempting fields and `.ptr` accesses where the caller already holds a stable reference. Gating stage in precommit.

### dead_code_zig — dead-code detector

[`tools/dead_code_zig/`](tools/dead_code_zig/) — `std.zig.Tokenizer`-based dead-code finder. Comment- and string-aware, alias-chain aware (`pub const X = mod.X;` re-exports are caught when nothing consumes them). Hash-validated skip file at `kernel/.dead-code-skip.txt` whitelists hardware-spec layouts and scaffold-with-rationale entries.

### gdb_mcp — kernel-symbol-aware gdb attach

[`tools/gdb_mcp/`](tools/gdb_mcp/) — MCP server backing kernel-symbol-aware gdb attachment to the QEMU stub. Symbol/field resolution is backed by the callgraph DB, so qualified Zig names like `sched.scheduler.core_states` resolve directly to (addr, size).

## Local CI — `tests/precommit.sh`

Cross-arch gauntlet, run by `.githooks/pre-commit` on commit. Stages run independently and failures are summarized at the end. The slow x86 Linux-guest boot is launched in the background so it overlaps with the rest of the gauntlet.

| Stage | Gate |
|---|---|
| arch layering lint | `zag.arch.dispatch` not bypassed in either direction. |
| dead-code detector | `tools/dead_code_zig` exits non-zero on any unwhitelisted finding. |
| gen-lock analyzer | `tools/check_gen_lock` exits non-zero on any err-severity finding. |
| spec ↔ test coverage | `tests/suite/verify_coverage.py` — every `[test NN]` tag in the spec must have a matching `<section>_NN.zig` and vice versa. |
| x86_64 kernel tests | Full suite under local KVM, 3 reps. |
| aarch64 kernel tests | Same suite, on a Pi 5 over SSH (`PI_HOST=user@ip` overridable; falls back to local TCG). 3 reps. |
| aarch64 VM-TCG | 6 vCPU-execution tests under local TCG (Pi 5 KVM lacks gic-version=3 + nested virt). |
| x86 linux_guest boot | KVM Linux-guest boots to userspace shell within 360s (background-launched). |

Stages below the gate but in the manual `./tests/precommit.sh` invocation: aarch64 linux_guest boot (blocked on aarch64 typed-reply parity), perf regression (`idc_pp` workload diffed against parent commit's measurement, 5% threshold; the `.zag-perf/` cache is rotated by `.githooks/post-commit`).

```bash
./tests/precommit.sh --git-hook   # required-only (matches the hook)
./tests/precommit.sh              # full manual gauntlet
```

When iterating on a subset of kernel tests, use `tests/suite/build.zig`'s `-Dtests=<list>` flag — comma-separated names or `*`-glob patterns (e.g. `cd tests/suite && zig build -Dtests='recv_*,reply_01'`). Omit the flag to embed all spec tests.

## Documentation

- [`docs/kernel/specv3.md`](docs/kernel/specv3.md) — observable behavior from userspace (syscalls, capabilities, error codes, limits). The single authoritative spec; rationale that doesn't belong in the spec lives in commit messages.
- [`docs/x86/`](docs/x86/), [`docs/aarch64/`](docs/aarch64/), [`docs/devices/`](docs/devices/) — vendor reference PDFs cited from kernel hardware code.
- [`docs/tools/`](docs/tools/) — tool screenshots.
