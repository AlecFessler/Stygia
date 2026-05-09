// Lockdep-style runtime deadlock detector — kernel wiring.
//
// Pure logic (HeldStack / PairRegistry / ClassTable / acquireOn /
// releaseOn / checkIrqModeOn) lives in debug_core.zig and is host-testable
// via `zig test kernel/utils/sync/debug_core.zig`. This file owns the
// per-core globals, the IRQ-handler-depth counter, the panic-path printers,
// and the `acquire` / `release` wrappers wired into SpinLock / GenLock.
//
// Limitations:
//   - Per-core held stack (no global view); cross-core migration between
//     acquire and release is silently tolerated by release().
//   - Recursive-acquire detection still catches the same-core same-lock
//     case, which is what matters for kernel deadlock prevention.
//   - Pair registry has fixed capacity; on overflow new edges are
//     silently dropped.
//   - Panic path uses arch.boot.printRaw to avoid recursing through
//     print_lock (which itself is detector-instrumented).

const builtin = @import("builtin");
const std = @import("std");
const stygia = @import("stygia");

const arch = stygia.arch.dispatch;
const core = @import("debug_core.zig");

pub const SrcLoc = core.SrcLoc;
pub const HeldStack = core.HeldStack;
pub const CheckOutcome = core.CheckOutcome;
pub const PairRegistry = core.PairRegistry;
pub const ClassTable = core.ClassTable;
pub const acquireOn = core.acquireOn;
pub const releaseOn = core.releaseOn;
pub const checkIrqModeOn = core.checkIrqModeOn;

const MAX_CORES = core.MAX_CORES;

const active = builtin.mode == .Debug and !builtin.is_test;

var held_stacks: [MAX_CORES]HeldStack align(64) = [_]HeldStack{.{}} ** MAX_CORES;
var pair_registry: PairRegistry = .{};
var class_table: ClassTable = .{};

/// Per-core async-IRQ-handler nesting depth. Single-writer per slot — only
/// the local core ever writes its own slot, between IRQ entry and IRQ exit
/// on that same core — so plain `u8` (no atomics) is sufficient. The
/// counter counts NESTED IRQ entries, which on x86 is normally 0 or 1
/// (IRQs stay masked in handlers) but on aarch64 can climb if a handler
/// explicitly re-enables IRQs.
///
/// All step logic lives on `core.IrqDepth` for host-testability — see
/// `debug_core.zig` `IrqDepth` tests. The wrappers below add the kernel-
/// only gates (`active` flag, `smp_ready` ordering, coreID acquisition).
var irq_depth: core.IrqDepth align(64) = .{};

/// Increment the local core's IRQ-handler depth. Call at the very top of
/// every async-IRQ entry point (NOT for synchronous exceptions like page
/// faults, GP faults, syscalls). Paired with `exitIrqContext` at exit.
pub fn enterIrqContext() void {
    if (!active) return;
    if (@atomicLoad(u32, &smp_ready, .acquire) == 0) return;
    irq_depth.enter(@intCast(arch.smp.coreID()));
}

/// Decrement the local core's IRQ-handler depth. Must mirror every prior
/// `enterIrqContext` call on the same core in nesting order.
pub fn exitIrqContext() void {
    if (!active) return;
    if (@atomicLoad(u32, &smp_ready, .acquire) == 0) return;
    irq_depth.exit(@intCast(arch.smp.coreID()));
}

/// Reset this core's IRQ-handler depth to 0. Called from arch context-switch
/// paths just before a noreturn jmp that abandons the current call stack —
/// the matching `exitIrqContext` defers in the IRQ entry function would
/// never run, so without this the counter would drift upward by one for
/// every IRQ-driven preemption.
///
/// On non-IRQ context-switch paths (yield-from-syscall, IPC block, etc.)
/// the depth is already 0 and this is a no-op.
pub fn resetIrqContextOnSwitch() void {
    if (!active) return;
    if (@atomicLoad(u32, &smp_ready, .acquire) == 0) return;
    irq_depth.reset(@intCast(arch.smp.coreID()));
}

/// Set by the kernel boot path once `arch.smp.coreID()` is safe to call
/// (after APIC/GIC init). Until then, acquire/release are no-ops — early
/// boot uses SpinLocks for serial print and PMM init, before any SMP
/// machinery is up.
var smp_ready: u32 align(64) = 0;

pub fn markSmpReady() void {
    @atomicStore(u32, &smp_ready, 1, .release);
}

pub fn acquire(
    lock_ptr: *const anyopaque,
    class: [*:0]const u8,
    ordered_group: u32,
    src: SrcLoc,
) void {
    if (!active) return;
    if (@atomicLoad(u32, &smp_ready, .acquire) == 0) return;
    const core_id = arch.smp.coreID();
    if (core_id >= MAX_CORES) return;
    const stack = &held_stacks[@intCast(core_id)];

    // IRQ-mode mix check: a class taken inside an async IRQ handler AND from
    // process context with IRQs enabled is the textbook deadlock vector
    // (handler spins on the lock the interrupted code holds). Run BEFORE
    // acquireOn so we report the bug at first detection, before the held
    // stack rolls forward and obscures the situation.
    const in_irq = irq_depth.inIrq(@intCast(core_id));
    const irqs_enabled = arch.cpu.interruptsEnabled();
    const irq_outcome = checkIrqModeOn(&class_table, class, in_irq, irqs_enabled, src);
    if (irq_outcome.result != .ok) {
        handleOutcome(irq_outcome, core_id, lock_ptr, class, src);
    }

    const outcome = acquireOn(stack, &pair_registry, lock_ptr, class, ordered_group, src);
    handleOutcome(outcome, core_id, lock_ptr, class, src);
}

pub fn release(lock_ptr: *const anyopaque) void {
    if (!active) return;
    if (@atomicLoad(u32, &smp_ready, .acquire) == 0) return;
    const core_id = arch.smp.coreID();
    if (core_id >= MAX_CORES) return;
    const stack = &held_stacks[@intCast(core_id)];
    _ = releaseOn(stack, lock_ptr);
}

/// Drain the per-core lockdep held-stack. Call when a kernel stack
/// frame is being abandoned without normal unwinding — e.g. when a
/// page fault on a user VA inside a syscall fires a memory_fault
/// event and yields, leaving the original syscall's defer chain
/// unrun. Without this, lockdep keeps the stale acquire entries on
/// the per-core stack and the next syscall on this core sees them as
/// "held", spuriously closing AB-BA cycles against unrelated paths.
pub fn dropAllHeldOnAbandonedStack() void {
    if (!active) return;
    if (@atomicLoad(u32, &smp_ready, .acquire) == 0) return;
    const core_id = arch.smp.coreID();
    if (core_id >= MAX_CORES) return;
    const stack = &held_stacks[@intCast(core_id)];
    stack.depth = 0;
}

/// Panic if the current core has any SpinLock held. Wire this into scheduler
/// block/yield entry points: holding a SpinLock across a context switch can
/// deadlock the kernel — the next thread spinning on the same lock won't
/// observe the holder's release until the holder runs again.
///
/// This assertion is also load-bearing for `releaseOn` correctness. The
/// per-core `HeldStack` design assumes acquire and release happen on the
/// same core; by panicking on yield-with-locks here, migration-with-locks
/// becomes structurally impossible upstream, which is why `releaseOn` can
/// safely return false for "lock not on this stack" instead of panicking.
/// See `releaseOn` in debug_core.zig for the full invariant chain.
fn handleOutcome(
    outcome: CheckOutcome,
    core_id: u64,
    lock_ptr: *const anyopaque,
    class: [*:0]const u8,
    src: SrcLoc,
) void {
    switch (outcome.result) {
        .ok => return,
        .panic_recursive => {
            const prior = outcome.prior.?;
            printDecimal("lockdep: recursive acquire core=", core_id);
            arch.boot.printRaw(" lock_ptr=0x");
            printHex(@intFromPtr(lock_ptr));
            arch.boot.printRaw(" class=");
            printClass(class);
            arch.boot.printRaw("\n  prior at ");
            printSlice(prior.src.file);
            arch.boot.printRaw(":");
            printDecimal("", prior.src.line);
            arch.boot.printRaw(" in ");
            printSlice(prior.src.fn_name);
            arch.boot.printRaw("\n  this at ");
            printSlice(src.file);
            arch.boot.printRaw(":");
            printDecimal("", src.line);
            arch.boot.printRaw(" in ");
            printSlice(src.fn_name);
            arch.boot.printRaw("\n");
            @panic("lockdep: recursive acquire");
        },
        .panic_same_class => {
            const prior = outcome.prior.?;
            printDecimal("lockdep: same-class overlap core=", core_id);
            arch.boot.printRaw(" class=");
            printClass(class);
            arch.boot.printRaw("\n  outer at ");
            printSlice(prior.src.file);
            arch.boot.printRaw(":");
            printDecimal("", prior.src.line);
            arch.boot.printRaw("\n  inner at ");
            printSlice(src.file);
            arch.boot.printRaw(":");
            printDecimal("", src.line);
            arch.boot.printRaw("\n  fix: use lockPair / unlockPair to acquire same-class instances atomically\n");
            @panic("lockdep: same-class overlap");
        },
        .panic_irq_mode_mix => {
            arch.boot.printRaw("lockdep: IRQ-mode mix on class=");
            printClass(class);
            arch.boot.printRaw(" core=");
            printDecimal("", core_id);
            arch.boot.printRaw("\n  IRQ-handler acquire at ");
            printSlice(outcome.irq_handler_src.file);
            arch.boot.printRaw(":");
            printDecimal("", outcome.irq_handler_src.line);
            arch.boot.printRaw(" in ");
            printSlice(outcome.irq_handler_src.fn_name);
            arch.boot.printRaw("\n  process-context acquire (IRQs ENABLED) at ");
            printSlice(outcome.process_enabled_src.file);
            arch.boot.printRaw(":");
            printDecimal("", outcome.process_enabled_src.line);
            arch.boot.printRaw(" in ");
            printSlice(outcome.process_enabled_src.fn_name);
            arch.boot.printRaw("\n  triggering acquire at ");
            printSlice(src.file);
            arch.boot.printRaw(":");
            printDecimal("", src.line);
            arch.boot.printRaw(" in ");
            printSlice(src.fn_name);
            arch.boot.printRaw("\n  fix: an IRQ landing while the process-context site holds this lock\n");
            arch.boot.printRaw("       will deadlock when the handler tries to take the same class.\n");
            arch.boot.printRaw("       Switch the process-context site to lockIrqSave/unlockIrqRestore.\n");
            @panic("lockdep: IRQ-mode mix");
        },
        .panic_cycle => {
            if (outcome.cycle_transitive) {
                arch.boot.printRaw("lockdep: transitive cycle ");
                printClass(outcome.cycle_inner);
                arch.boot.printRaw(" -> ... -> ");
                printClass(outcome.cycle_outer);
                arch.boot.printRaw("\n  closing edge at ");
                printSlice(src.file);
                arch.boot.printRaw(":");
                printDecimal("", src.line);
                arch.boot.printRaw(" in ");
                printSlice(src.fn_name);
                arch.boot.printRaw("\n  (intermediate path is in pair_registry; inspect with debugger)\n");
                @panic("lockdep: transitive cycle");
            }
            arch.boot.printRaw("lockdep: AB-BA cycle ");
            printClass(outcome.cycle_inner);
            arch.boot.printRaw(" -> ");
            printClass(outcome.cycle_outer);
            arch.boot.printRaw("\n  prior A->B at ");
            printSlice(outcome.cycle_prior_inner_src.file);
            arch.boot.printRaw(":");
            printDecimal("", outcome.cycle_prior_inner_src.line);
            arch.boot.printRaw("\n  this B->A at ");
            printSlice(src.file);
            arch.boot.printRaw(":");
            printDecimal("", src.line);
            arch.boot.printRaw("\n");
            @panic("lockdep: AB-BA cycle");
        },
    }
}

/// Lowest valid kernel-half virtual address on x86_64 / aarch64 TTBR1 layouts
/// the kernel actually runs in. Anything below this — and anything in the
/// canonical hole — is rejected by `printClass` / `printSlice` in favour of
/// a `<null:0xPTR>` placeholder so a corrupt class-string pointer can't
/// page-fault the panic printer (which would recurse through `handlePageFault`
/// and obscure the original lockdep finding entirely).
const KERNEL_HALF_BASE: usize = 0xffff_8000_0000_0000;

/// Print a NUL-terminated lockdep class string. If the pointer is null or
/// outside the kernel-half canonical range, prints `<null:0xPTR>` instead
/// of walking memory from a junk address. The class field on `SpinLock` /
/// `GenLock` is `[*:0]const u8` with no null wrapper — every panic-print
/// site funnels through this helper so the formatter stays alive even when
/// a held-stack entry was populated with an unintialized or recycled class
/// pointer (the failure mode that turned 261/590 x86 tests into a recursive
/// kernel page-fault hang).
fn printClass(s: [*:0]const u8) void {
    const addr = @intFromPtr(s);
    if (addr < KERNEL_HALF_BASE) {
        arch.boot.printRaw("<null:0x");
        printHex(addr);
        arch.boot.printRaw(">");
        return;
    }
    arch.boot.printRaw("\"");
    arch.boot.printRaw(std.mem.span(s));
    arch.boot.printRaw("\"");
}

/// Print a slice (e.g. `SrcLoc.file`, `SrcLoc.fn_name`). Same defense as
/// `printClass`: if the slice's data pointer is null / non-canonical or its
/// length is implausibly huge, fall back to `<null:0xPTR>` rather than
/// dereferencing junk and recursing through the page-fault handler.
fn printSlice(s: []const u8) void {
    const addr = @intFromPtr(s.ptr);
    // 4 KiB ceiling: every legitimate `SrcLoc.file` / `SrcLoc.fn_name` is a
    // compile-time string literal well under a page; an undefined slice is
    // overwhelmingly likely to have a junk length far above this.
    if (addr < KERNEL_HALF_BASE or s.len > 4096) {
        arch.boot.printRaw("<null:0x");
        printHex(addr);
        arch.boot.printRaw(">");
        return;
    }
    arch.boot.printRaw(s);
}

fn printDecimal(prefix: []const u8, n: u64) void {
    arch.boot.printRaw(prefix);
    var buf: [20]u8 = undefined;
    var i: usize = buf.len;
    var v = n;
    if (v == 0) {
        i -= 1;
        buf[i] = '0';
    } else {
        while (v != 0) {
            i -= 1;
            buf[i] = @as(u8, @intCast(v % 10)) + '0';
            v /= 10;
        }
    }
    arch.boot.printRaw(buf[i..]);
}

fn printHex(n: u64) void {
    var buf: [16]u8 = undefined;
    var i: usize = buf.len;
    var v = n;
    if (v == 0) {
        i -= 1;
        buf[i] = '0';
    } else {
        while (v != 0) {
            i -= 1;
            const d = @as(u8, @intCast(v & 0xF));
            buf[i] = if (d < 10) d + '0' else d - 10 + 'a';
            v >>= 4;
        }
    }
    arch.boot.printRaw(buf[i..]);
}
