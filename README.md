# Zag

Zag is a capability-based microkernel for building secure, fast, and reliable operating systems.

## Kernel Objects

Userspace interacts with the kernel through handles to typed kernel objects. Each row links to the relevant section of [the spec](docs/kernel/specv3.md) for the full handle ABI, capability bits, and syscall surface.

| Object | Role | Spec |
|---|---|---|
| **Capability Domain** | A set of capabilities usable by the execution contexts bound to the domain. The process-equivalent boundary in Zag. | [§[capability_domain]](docs/kernel/specv3.md#capability_domain-capability-domain) |
| **Execution Context** | A schedulable unit of executable state bound to a capability domain. The thread-equivalent. | [§[execution_context]](docs/kernel/specv3.md#execution_context-execution-context) |
| **VMAR** | A virtual memory address region: a contiguous span of virtual address space bound to a capability domain, available for demand-paged memory or for installing page frames and device regions. | [§[vmar]](docs/kernel/specv3.md#vmar-virtual-memory-address-region) |
| **Page Frame** | A reference to physical memory. Installing the same page frame into multiple capability domains creates shared memory. | [§[page_frame]](docs/kernel/specv3.md#page_frame-page-frame) |
| **Device Region** | A reference to a device's MMIO region or x86-64 I/O port range. Installing it into a VMAR makes the device directly accessible to execution contexts in that capability domain. | [§[device_region]](docs/kernel/specv3.md#device_region-device-region) |
| **Virtual Machine** | A guest execution environment with its own guest physical address space. Execution contexts enter guest mode within a VM to run. | [§[virtual_machine]](docs/kernel/specv3.md#virtual_machine-virtual-machine) |
| **Port** | A rendezvous point between a calling execution context and a receiving execution context. Used for IDC, capability transfer, and event delivery. | [§[port]](docs/kernel/specv3.md#port-port) |
| **Reply** | A one-shot capability referencing a suspended execution context dequeued from a port by a receive. Consuming the handle is the only way to resume or abandon the suspended sender. | [§[reply]](docs/kernel/specv3.md#reply-reply) |
| **Timer** | A kernel object that fires once or periodically. Each fire increments a u64 counter exposed in the timer's handle; userspace polls the counter or waits on it via `futex_wait_val`. | [§[timer]](docs/kernel/specv3.md#timer-timer) |

## Scope

**Memory.** Demand-paged virtual memory address regions (VMARs), page table management, shared mappings (the same page frame mapped into multiple capability domains), and direct MMIO BAR mapping for userspace device access. DMA always routes through the IOMMU, so a misbehaving or compromised device cannot escape the buffer it was given.

**Scheduling.** Preemptive round-robin scheduler. Per-EC core affinities and priorities that propagate through ports and futex waitlists. Futex primitive that integrates with the scheduler so a waiter blocks rather than spins.

**IPC.** Capability-gated ports for suspend / receive / reply between capability domains. When the payload fits in architectural general-purpose registers and carries data only (no capability transfer), the rendezvous runs through an L4-style zero-register-copy fast path that does a direct context switch and bypasses the Zig dispatch table. Current round-trip cost is around 1,600 cycles for suspend → receive → reply on a Ryzen 9 7950X3D.

**Kernel-event routing.** Per-EC events (memory faults, thread faults, breakpoints, PMU overflow) can be bound to ports so that debuggers and supervisors handle them as IPC messages. Suspension events and VM exits are always delivered to a port by construction.

**Time.** Monotonic and wall-clock primitives. Programmable one-shot and periodic timers; each fire increments a u64 counter exposed in the timer's handle, and userspace either polls the counter or waits on it via `futex_wait_val`.

**Virtual machines.** KVM-style guest containers. vCPUs are execution contexts in a VM-flavored capability domain; userspace maps guest-physical memory, sets per-VM policies, and injects IRQs.

**Performance counters.** Hardware PMU counters exposed to userspace through the perfmon syscalls (info, start, read, stop).

**Power management.** Per-core CPU frequency and idle policy controls, plus system-wide shutdown, reboot, sleep, and screen-off.

## Tooling

### The Indexer

This tool processes all compilation stages (the tokenizer, AST, and LLVM IR) and compiles them into a SQL database. Most of our other tools are built on top of this database.

### Arch Layering Tool

This enforces a three-tier layering between generic kernel code, the arch dispatch layer, and architecture-specific code (x86 and ARM). Generic code must reach arch-specific code through dispatch, and arch-specific code must not reach up into dispatch.

### CheckGenLock

This is a static analyzer that enforces the correct use of the generation lock primitive in the kernel. Proper usage ensures concurrent safety and use-after-free safety for slab-backed objects. The kernel allocates all of its dynamic state out of slabs, with the page allocator itself as the only exception, so gen-lock discipline gates nearly every reference into kernel objects.

### Dead Code Linter

This ensures there is no unreachable code or unused functions left in the kernel.

### Call Graph Tool

This provides an HTTP frontend for humans and an MCP frontend for models. It enumerates kernel entry points and traces the code flow, stripping out data to show only the control flow structure (call hierarchies, loops, and branches). It is designed to help you quickly understand how code runs before you dig into the files. It also includes features for catting source code, viewing source-to-machine code translations via DWARF info, and a trace view in the HTTP frontend.

![callgraph trace view](docs/tools/callgraph_trace_view.png)

### GDB MCP Tool

A wrapper that extends GDB for worker agents. It includes Kernel Address Space Layout Randomization (KASLR) aware symbol resolution to make debugging smoother for the agents.

### Kprof

The kernel includes internal trace points and a sampling profiler used during development. Kprof is excluded from the kernel binary entirely unless `-Dkernel_profile=trace|sample` is passed at build time, and is not part of the userspace surface.

## Slab Allocator

Zag allocates all dynamic kernel state from per-type slab allocators. Each slab serves a single type `T`, and slots are type-stable: once a slot is mapped, its address belongs to the same `T` for the slot's entire lifetime, regardless of how many alloc/free cycles pass through it.

A slab-backed object has two correctness obligations under arbitrary concurrent kernel work:

1. Multiple kernel paths can hold pointers to the same object on different cores. Every dereference must be safe regardless of how alloc and free interleave with that access.
2. When an object is freed, every outstanding pointer to it must atomically become unusable. There are no GC sweeps and no per-pointer revocation passes.

The gen-lock primitive solves both. The rest of this section walks through the primitive, the proof that it is correct, and the static analyzer that ensures the kernel uses it correctly. The slab allocator also has two additional security features (out-of-band metadata and random-walk cursors) which are described at the end.

### GenLock

Every slab-backed type embeds a 64-bit `_gen_lock` word at a fixed offset, partitioned into a 1-bit lock and a 63-bit generation counter. The counter follows a parity invariant: odd means the slot is live, even means the slot is freed. Allocation flips the gen from even to odd via a `publish` step that runs only after the caller has fully initialized `T`'s fields. Free flips it back to even, fused with the lock release. Every transition is a `setGenRelease` of a strictly larger gen than the previous one.

Every kernel pointer to a slab-backed object is a fat pointer (`SlabRef(T)`) carrying `*T` plus a snapshot of the generation taken when the pointer was minted. Dereference always goes through `SlabRef.lock`, which calls `GenLock.lockWithGen(expected_gen)`. That does a single atomic compare-and-swap from `(expected_gen << 1) | 0` to `(expected_gen << 1) | 1`, verifying the slot is still at the caller's expected gen and acquiring the lock bit in one indivisible step. If the slot has been freed since the pointer was minted (gen flipped to even, possibly back to a new odd for a reallocated lifetime), the CAS fails and `lock` returns `StaleHandle`. The caller never sees the slot.

This is what makes invalidation atomic. A single `setGenRelease(gen + 1)` on free poisons every outstanding `SlabRef` to that slot at once, with no fan-out and no synchronization beyond the store itself.

### The Lean proof

The proof in [`slab_proof/`](slab_proof/) mechanises the gen-lock primitive against an x86-TSO operational memory model. The headline theorem is `durable_run_uaf_safe`: once the slot's gen has advanced past a `SlabRef`'s snapshot gen, no further trace (drains, payload stores, release-stores of higher gens, locked CAS attempts by other cores, reader unlocks) can let that ref's `lockWithGen` succeed. A stale ref is rejected at every prefix of every reachable run.

The proof reduces UAF safety to one obligation about the surrounding kernel: every `setGenRelease` is monotone, that is, it stores a strictly larger gen than any value previously visible at the slot's word. Every gen-bump in the implementation is structurally monotone, because it is either issued under the slot's own gen-lock at the current odd gen, or issued during the create-to-publish window held exclusive by the allocator's own spinlock. During that window the slot's gen is even, which `lockWithGen` cannot succeed against.

The proof states its scope explicitly. Out of scope: u63 wraparound (over 10² years of churn at the kernel's destroy rate), and the no-gen `GenLock.lock` / `forEachAlive` reader paths whose safety rests on caller-side discipline rather than the proof. ARM64's RCsc release-acquire model is also not currently mechanised. The same Zig source compiles correctly on aarch64, but the operational argument would have to be re-stated against an axiomatic ARMv8 model. Extending the proof to ARM64 is noted future work.

### The static analyzer

The proof's safety claim is conditional on the kernel using the primitive correctly. [CheckGenLock](#checkgenlock) is the static analyzer that ensures it does. It runs against the indexer database and applies six checks:

1. **Slab-backed type discovery.** Types whose first field is `_gen_lock: GenLock` are tagged.
2. **Fat-pointer invariant.** Bare `*T`, `?*T`, `[N]*T`, and `[]*T` for slab-backed `T` are violations; the only sanctioned form is `SlabRef(T)`.
3. **`.ptr` bypass.** Any chain reaching `slabref.ptr` outside an explicit `lock()`/`unlock()` bracket is flagged. A `// caller-pinned` annotation is the explicit-exemption surface for sites that already hold a stable reference.
4. **Per-entry bracketing.** Every access to a slab-typed local in a syscall or exception handler must be tight-preceded by a `lock` and tight-followed by an `unlock` on the same identifier.
5. **Per-path release coverage.** For every lock acquired in an entry body, every reachable exit between the lock and its release must be covered by an explicit `unlock`, a `defer ref.unlock(...)`, or, for error exits, an `errdefer ref.unlock(...)`. `@panic` and `unreachable` impose no obligation.
6. **IRQ-acquired lock-class discipline.** A class is IRQ-acquired iff some IRQ, NMI, or async-trap entry can transitively reach an acquire of it. Process-context acquires of an IRQ-acquired class must use the IRQ-saving variant; pairing variants must match.

Checks 1 through 3 ensure every kernel pointer to a slab-backed object goes through the proven primitive at all. Checks 4 through 6 ensure the tight-bracketing and IRQ discipline that the proof's safety claim requires. Together with the proof, this closes the safety loop: the primitive is mechanically proven correct, and the analyzer mechanically enforces that the kernel uses it correctly.

### Comparison to Rust

Rust enforces mutual exclusion entirely at compile time. The borrow checker rules out shared mutable access by construction, and lifetimes prove that a borrow cannot outlive its referent. No runtime check is required.

Zag splits the same guarantee across compile-time and runtime enforcement. The static analyzer plays the role of the borrow checker. It enforces the patterns: every pointer to a slab-backed object is a `SlabRef`, and every dereference is bracketed by `lock`/`unlock`. What Rust gets for free from lifetimes is the proof that the referent is still alive at access time. Zag cannot prove that statically, because slab slots can be freed by other cores asynchronously while a `SlabRef` is in flight. The gen-lock CAS supplies that check at runtime: the verify-and-acquire either succeeds (live, exclusive access) or returns `StaleHandle` (stale, caller does not touch the slot).

The end safety property is the same. The split is between the static enforcement of pattern (you have a `SlabRef`, and you bracket every access) and the runtime check of liveness (the gen still matches).

### Additional security features

Beyond gen-lock, the slab allocator has two structural defenses orthogonal to the multi-pointer and invalidation safety story.

**Out-of-band metadata.** The allocator's bookkeeping lives in vaddr regions separate from the slot data. Each slab class reserves three comptime regions: the dense `T`-slot array, a parallel array of `*T`, and a parallel array of `LinkPair { prev, next }` indices for the freelist. An out-of-bounds write on a slab-backed object cannot corrupt allocator state, because the metadata isn't there to corrupt.

**Random-walk cursors.** The freelist is a circular doubly-linked list of indices. Two cursors (pop and push) each take a hardware-random `[-N, N]` step on every alloc and every free system-wide. The cursor walk is seeded from RDRAND/RNDR mixed with a timestamp, and `N` is fixed at compile time (256 by default). An attacker cannot predict which slot their next free-then-alloc sequence will reclaim, because the cursor state is a function of every prior alloc and free in the system.

## How Zag is Developed

Zag makes use of AI code generation tooling. Where Zag does not sacrifice the human touch is in design. Every core architectural decision is carefully considered and drafted into the spec. The spec drives the test suite, with the goal being to exercise and assert the correctness of every userspace-observable behavior. The spec and tests are human-driven.

The kernel is split into ~30 subsystems, and each one is provided with various forms of persistent memory including a changelog and a SYSTEMS.md file that describes the subsystem. The pipeline makes use of [Steve Yegge's Beads](https://github.com/steveyegge/beads) for queue and state management. An orchestrator agent pulls beads from the queue and dispatches a worker agent. The worker first runs the precommit CI to prove a clean baseline before writing its code. On commit, precommit CI runs again, and the worker fails if anything regressed. Once clean, the commit is handed to a reviewer agent, and once passing, to a merger agent that lands it. Throughout this, agents working in a subsystem can flag bugs, which are automatically queued up as an issue bead, or feature proposals, which are *always* human reviewed since they change the spec.

## Contributing

The way Zag's kernel is developed (see [How Zag is Developed](#how-zag-is-developed)) means it doesn't really need contributors to submit code. The kernel is not going to accept external code contributions.

Issue reports and bug reports are good, and feature requests are also excellent contributions.

However, you can contribute code by building userspace apps. Zag is a microkernel; the operating system around it is built out of userspace processes, and that surface is open to anyone who wants to build something on top of the kernel.

## License

Zag is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.

Copyright 2026 Alec Fessler.
