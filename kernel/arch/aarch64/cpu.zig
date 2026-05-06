//! AArch64 CPU primitives and system register access.
//!
//! Provides low-level CPU operations: system register read/write via MRS/MSR,
//! feature detection via ID registers, memory barriers, and instruction helpers.
//!
//! Key responsibilities:
//! - halt(): WFI (Wait For Interrupt) — equivalent of x86 HLT.
//! - enableInterrupts() / saveAndDisableInterrupts() / restoreInterrupts():
//!   DAIF flag manipulation (PSTATE.{D,A,I,F} mask bits).
//!   ARM ARM D1.7.3 "Interrupt masking" — clear/set PSTATE.I via MSR DAIFClr/DAIFSet.
//! - PAN (Privileged Access Never) toggle for userAccessBegin/End:
//!   ARM ARM D5.4.6 — set/clear PSTATE.PAN to control kernel access to user pages.
//! - RNDR instruction for hardware random number generation:
//!   ARM ARM C5.2.14 (ARMv8.5-RNG) — reads from a TRNG; returns NZCV.Z=1 on failure.
//! - Feature detection via ID_AA64ISAR0_EL1, ID_AA64MMFR1_EL1, etc.
//! - Memory/instruction barriers: DMB, DSB, ISB.
//!
//! References:
//! - ARM ARM DDI 0487 (Architecture Reference Manual for A-profile)
//! - ARM ARM C5.2: AArch64 System Instructions
//! - ARM ARM D1.7: Interrupt masking

const std = @import("std");
const builtin = @import("builtin");
const zag = @import("zag");


const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const VAddr = zag.memory.address.VAddr;

/// True when the target CPU advertises the ARMv8.1 PAN (Privileged
/// Access Never) feature. Cortex-A72 is ARMv8.0 and lacks PAN; the
/// `msr pan, #imm` mnemonic is UNDEFINED there and must not execute.
const has_pan = std.Target.aarch64.featureSetHas(
    builtin.cpu.features,
    .pan,
);

pub fn halt() noreturn {
    while (true) {
        asm volatile ("wfi");
    }
}

/// Align a stack pointer for the AAPCS64 calling convention:
/// SP must be 16-byte aligned at all times.
pub fn alignStack(stack_top: VAddr) VAddr {
    return VAddr.fromInt(std.mem.alignBackward(u64, stack_top.addr, 16));
}

pub fn enableInterrupts() void {
    // DAIFClr: clear PSTATE.I (bit 1) to unmask IRQs.
    // ARM ARM C5.2.3: MSR DAIFClr, #imm
    asm volatile ("msr daifclr, #0x2");
}

/// Read PSTATE.DAIF without modifying it. Returns true if PSTATE.I (bit 7
/// of DAIF) is clear — i.e., IRQs are currently unmasked. Used by lockdep
/// to detect IRQ-vs-process context at lock acquire sites.
/// ARM ARM D5.2.1 (PSTATE), DAIF mask layout.
pub fn interruptsEnabled() bool {
    var daif: u64 = undefined;
    asm volatile ("mrs %[daif], daif"
        : [daif] "=r" (daif),
    );
    return (daif & (1 << 7)) == 0;
}

pub fn saveAndDisableInterrupts() u64 {
    // Read DAIF, then set PSTATE.I to mask IRQs.
    var daif: u64 = undefined;
    asm volatile ("mrs %[daif], daif"
        : [daif] "=r" (daif),
    );
    asm volatile ("msr daifset, #0x2");
    return daif;
}

pub fn restoreInterrupts(state: u64) void {
    asm volatile ("msr daif, %[state]"
        :
        : [state] "r" (state),
    );
}

/// Disable PAN — allow kernel to access user pages.
/// ARM ARM D5.4.6: MSR PAN, #0 clears PSTATE.PAN.
/// No-op on ARMv8.0 targets without PAN (kernel always can access
/// user pages, no SMAP-equivalent enforcement).
pub inline fn panDisable() void {
    if (has_pan) asm volatile ("msr pan, #0");
}

/// Enable PAN — block kernel access to user pages.
/// ARM ARM D5.4.6: MSR PAN, #1 sets PSTATE.PAN.
/// No-op on ARMv8.0 targets without PAN.
pub inline fn panEnable() void {
    if (has_pan) asm volatile ("msr pan, #1");
}

/// Read the virtual counter (CNTVCT_EL0).
/// ARM ARM D11.2.3: monotonically incrementing at CNTFRQ_EL0 Hz.
/// Equivalent of x86 RDTSC — a high-resolution timestamp source.
pub inline fn readCntvct() u64 {
    var val: u64 = undefined;
    asm volatile ("mrs %[val], cntvct_el0"
        : [val] "=r" (val),
    );
    return val;
}

/// Software PRNG state used as a fallback when ARMv8.5-RNG is unavailable.
/// Seeded lazily from CNTVCT_EL0 on first use; subsequently advanced by
/// xorshift64* with additional mixing from the virtual counter so that
/// successive calls within a tight loop still diverge.
/// Not cryptographically strong — adequate for the behavioural contract
/// of `getrandom` (non-zero bytes, non-blocking) on platforms lacking a
/// true hardware TRNG.
var prng_state: u64 = 0;

fn prngNext() u64 {
    if (prng_state == 0) {
        // Lazy seed: mix CNTVCT twice spread across a handful of cycles.
        const s0 = readCntvct();
        const s1 = readCntvct();
        prng_state = (s0 ^ (s1 << 13) ^ 0x9E3779B97F4A7C15);
        if (prng_state == 0) prng_state = 0x9E3779B97F4A7C15;
    }
    var x = prng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    prng_state = x;
    // Mix with current CNTVCT to resist accidental state replay if the
    // state word is ever observed externally.
    return (x *% 0x2545F4914F6CDD1D) ^ readCntvct();
}

/// Hardware random number via RNDR (ARMv8.5-RNG), falling back to a
/// software PRNG seeded from CNTVCT_EL0 on cores that lack the feature.
/// ARM ARM C5.2.14: RNDR returns NZCV.Z=1 on entropy exhaustion.
/// Feature detection: ID_AA64ISAR0_EL1 bits [63:60] (RNDR field) >= 1.
/// The Cortex-A72/A76 cores Zag currently targets do not implement RNG,
/// so the PRNG path is the common case on our reference hardware.
pub fn rndr() ?u64 {
    // Feature detection: ID_AA64ISAR0_EL1 bits [63:60] (RNDR field). A
    // value >= 1 indicates that the RNDR/RNDRRS system registers are
    // implemented. On hosts without the feature, MRS RNDR traps as
    // UNDEFINED, so we must gate every access on this probe.
    var isar0: u64 = undefined;
    asm volatile ("mrs %[v], ID_AA64ISAR0_EL1"
        : [v] "=r" (isar0),
    );
    if (((isar0 >> 60) & 0xF) != 0) {
        // MRS Xt, RNDR — reads 64 bits from the TRNG. On success
        // NZCV.Z=0 and Xt holds a random value; on entropy exhaustion
        // NZCV.Z=1 and Xt is zero. Read NZCV via MRS to determine
        // success (Zig aarch64 inline asm does not expose flag-output
        // clobbers reliably). ARM ARM C5.2.14.
        var val: u64 = undefined;
        var nzcv: u64 = undefined;
        asm volatile (
            \\mrs %[val], S3_3_C2_C4_0
            \\mrs %[nzcv], nzcv
            : [val] "=r" (val),
              [nzcv] "=r" (nzcv),
            :
            : .{ .nzcv = true });
        // NZCV bit 30 is Z. If Z == 1 the TRNG was exhausted this cycle
        // — fall through to the software PRNG rather than returning
        // E_AGAIN, so userspace `getrandom` still makes forward progress
        // on platforms where RNDR occasionally fails.
        if ((nzcv & (1 << 30)) == 0) return val;
    }
    return prngNext();
}

// ── Lazy FPU primitives ────────────────────────────────────────────
//
// FPSIMD register file layout in `Thread.fpu_state` (576 bytes, only
// the first 528 used; the rest is forward-compat headroom):
//   [0   ..512)  V0..V31      — 32 × 128-bit vector regs (16B each)
//   [512..520)   FPCR         — Floating-Point Control Register
//   [520..528)   FPSR         — Floating-Point Status Register
//
// The kernel itself is built without NEON/fp_armv8 (see build.zig
// cpu_features_sub) so it never emits FPSIMD instructions and never
// disturbs userspace V regs. CPACR_EL1.FPEN is held at 0b01 (trap EL0
// only) when the local thread isn't the FPU owner on this core, and
// 0b11 (no trap) when it is. ARM ARM D13.2.30.

/// Initialise an FPU buffer to the architectural reset state for a
/// brand-new thread. Per ARM ARM B4.1.36, FPCR resets to 0 (round to
/// nearest, no exceptions enabled, default NaN off, FZ off) and FPSR
/// resets to 0 (no sticky exception flags). All zeros suffices.
pub fn fpuStateInit(area: *[576]u8) void {
    @memset(area, 0);
}

/// Save V0-V31, FPCR, FPSR into `area`. The kernel has no NEON regs
/// of its own to preserve (built without fp-armv8/neon — see
/// build.zig cpu_features_sub), so this captures purely userspace
/// state. The `.arch_extension fp+neon` directive locally re-enables
/// the assembler so it accepts the SIMD/FP instructions; the kernel
/// at large still can't emit them.
pub fn fpuSave(area: *[576]u8) void {
    asm volatile (
        \\stp  q0,  q1,  [%[a], #0]
        \\stp  q2,  q3,  [%[a], #32]
        \\stp  q4,  q5,  [%[a], #64]
        \\stp  q6,  q7,  [%[a], #96]
        \\stp  q8,  q9,  [%[a], #128]
        \\stp  q10, q11, [%[a], #160]
        \\stp  q12, q13, [%[a], #192]
        \\stp  q14, q15, [%[a], #224]
        \\stp  q16, q17, [%[a], #256]
        \\stp  q18, q19, [%[a], #288]
        \\stp  q20, q21, [%[a], #320]
        \\stp  q22, q23, [%[a], #352]
        \\stp  q24, q25, [%[a], #384]
        \\stp  q26, q27, [%[a], #416]
        \\stp  q28, q29, [%[a], #448]
        \\stp  q30, q31, [%[a], #480]
        \\mrs  x0, fpcr
        \\str  x0, [%[a], #512]
        \\mrs  x0, fpsr
        \\str  x0, [%[a], #520]
        :
        : [a] "r" (area),
        : .{ .memory = true, .x0 = true });
}

/// Restore V0-V31, FPCR, FPSR from `area`. Inverse of `fpuSave`.
pub fn fpuRestore(area: *[576]u8) void {
    asm volatile (
        \\ldp  q0,  q1,  [%[a], #0]
        \\ldp  q2,  q3,  [%[a], #32]
        \\ldp  q4,  q5,  [%[a], #64]
        \\ldp  q6,  q7,  [%[a], #96]
        \\ldp  q8,  q9,  [%[a], #128]
        \\ldp  q10, q11, [%[a], #160]
        \\ldp  q12, q13, [%[a], #192]
        \\ldp  q14, q15, [%[a], #224]
        \\ldp  q16, q17, [%[a], #256]
        \\ldp  q18, q19, [%[a], #288]
        \\ldp  q20, q21, [%[a], #320]
        \\ldp  q22, q23, [%[a], #352]
        \\ldp  q24, q25, [%[a], #384]
        \\ldp  q26, q27, [%[a], #416]
        \\ldp  q28, q29, [%[a], #448]
        \\ldp  q30, q31, [%[a], #480]
        \\ldr  x0, [%[a], #512]
        \\msr  fpcr, x0
        \\ldr  x0, [%[a], #520]
        \\msr  fpsr, x0
        :
        : [a] "r" (area),
        : .{ .memory = true, .x0 = true });
}

/// Set CPACR_EL1.FPEN bits [21:20] = 0b11 — no FP/SIMD trap at any EL.
/// Called at the end of the lazy-FPU trap handler.
/// ARM ARM D13.2.30.
pub fn fpuClearTrap() void {
    var cpacr: u64 = undefined;
    asm volatile ("mrs %[v], cpacr_el1"
        : [v] "=r" (cpacr),
    );
    cpacr |= (@as(u64, 0b11) << 20);
    asm volatile ("msr cpacr_el1, %[v]"
        :
        : [v] "r" (cpacr),
    );
    asm volatile ("isb" ::: .{ .memory = true });
}

/// Per-core mailbox for the lazy-FPU cross-core flush IPI (SGI 2).
/// Mirrors the x64 layout in `arch/x64/interrupts.zig`'s mailbox — one
/// slot per *target* core. Requester writes the thread, sends the SGI,
/// spins on `done`. Receiver reads the thread, saves its FP regs, acks.
/// See the SGI-2 arm of `exceptions.dispatchIrq` for the receiver.
pub const FpuFlushMailbox = struct {
    requested_thread: ?*anyopaque align(64) = null,
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),

    pub fn ackDone(self: *FpuFlushMailbox) void {
        self.done.store(true, .release);
    }
};

pub var fpu_flush_mailbox: [64]FpuFlushMailbox align(64) = [_]FpuFlushMailbox{.{}} ** 64;

/// DC ZVA block size in bytes. Captured at boot from DCZID_EL0.BS. When
/// `DCZID_EL0.DZP` is set the instruction is disabled at EL1 (or the
/// implementation chose not to support it) and we must use the `@memset`
/// fallback path.
///
/// ARM ARM D7.2.23 "DC ZVA, Data Cache Zero by Virtual Address":
///   DC ZVA writes `4 << BS` bytes of zeros starting at a natural block
///   boundary at or below the provided address. The block size is uniform
///   across a system; typical Cortex-A implementations report BS=4 → 64B.
/// ARM ARM D7.2.36 "DCZID_EL0":
///   Bits [3:0] = BS (log2(words/4) of block size);
///   Bit  4     = DZP (1 = DC ZVA prohibited).
var dc_zva_block_size: usize = 0;
var dc_zva_enabled: bool = false;

/// Read DCZID_EL0 and cache the block size / enable bit. Called once from
/// the PMM init path on the boot core; safe to call again on APs (all
/// cores in a valid system report the same BS field).
pub fn initZeroPageFeatures() void {
    var dczid: u64 = undefined;
    asm volatile ("mrs %[v], DCZID_EL0"
        : [v] "=r" (dczid),
    );
    // DZP == 1 means DC ZVA is prohibited — fall back to @memset.
    if ((dczid & (1 << 4)) != 0) {
        dc_zva_enabled = false;
        dc_zva_block_size = 0;
        return;
    }
    const bs: u6 = @truncate(dczid & 0xF);
    // Block size in bytes = 4 << BS (ARM ARM D7.2.36, DCZID_EL0.BS field).
    dc_zva_block_size = @as(usize, 4) << bs;
    dc_zva_enabled = true;
}

/// Zero a 4 KiB page at `ptr` using DC ZVA when available, otherwise
/// fall back to `@memset`. DC ZVA zeroes one naturally aligned block
/// per instruction without a read-for-ownership, which is the critical
/// property for the PMM-free path where the freshly freed page is
/// typically not in cache.
///
/// ARM ARM D7.2.23 "DC ZVA, Data Cache Zero by Virtual Address":
///   The instruction operates on the aligned block containing the
///   supplied VA. Callers must step by the block size reported via
///   DCZID_EL0.BS for the full region to be covered.
pub fn zeroPage4K(ptr: *anyopaque) void {
    if (dc_zva_enabled and dc_zva_block_size > 0 and 4096 % dc_zva_block_size == 0) {
        const base: usize = @intFromPtr(ptr);
        const end: usize = base + 4096;
        // Ensure the starting VA is aligned to the block size. Callers
        // pass a 4 KiB-aligned pointer and typical block sizes are
        // 32/64/128 bytes (all divisors of 4096), so this is a no-op
        // assertion in the common path.
        std.debug.assert(base % dc_zva_block_size == 0);
        var addr: usize = base;
        while (addr < end) {
            asm volatile ("dc zva, %[a]"
                :
                : [a] "r" (addr),
                : .{ .memory = true });
            addr += dc_zva_block_size;
        }
        // DC ZVA is a cache maintenance op; callers expect the zeros to
        // be observable by subsequent loads on this core, which requires
        // a DSB to drain the CMO completion.
        asm volatile ("dsb ish" ::: .{ .memory = true });
        return;
    }
    const bytes: [*]u8 = @ptrCast(ptr);
    @memset(bytes[0..4096], 0);
}

// ── Spec v3 EC dispatch primitives ────────────────────────────────────

/// SPSR_EL1.M[3:0] selector — EL1h (kernel, dedicated SP).
/// ARM ARM DDI 0487 §C5.2.18 SPSR_EL1, M[3:0] = 0b0101 = EL1h.
const SPSR_M_EL1H: u64 = 0b0101;
/// SPSR_EL1.M[3:0] selector — EL0t (user-mode AArch64).
/// ARM ARM DDI 0487 §C5.2.18 SPSR_EL1, M[3:0] = 0b0000 = EL0t.
const SPSR_M_EL0T: u64 = 0b0000;

/// Naked tail of `loadEcContextAndReturn` — receives the saved
/// ArchCpuContext base pointer in x0, sets sp to it, restores x0..x30,
/// SP_EL0, ELR_EL1, SPSR_EL1, and ERETs. Splitting the prologue (Zig
/// helper) from the restore path (this naked stub) ensures the compiler
/// cannot insert a frame setup that clobbers x0 between the swap and
/// the asm sequence. ARM ARM DDI 0487 §D1.10.1.
export fn restoreContextAndEret() callconv(.naked) noreturn {
    asm volatile (
        \\mov sp, x0

        // Restore ELR_EL1 / SPSR_EL1 from the context.
        \\ldp x10, x11, [sp, #256]
        \\msr elr_el1, x10
        \\msr spsr_el1, x11

        // Restore SP_EL0 (user banked SP).
        \\ldr x10, [sp, #248]
        \\msr sp_el0, x10

        // Restore x30 from offset 240.
        \\ldr x30, [sp, #240]

        // Restore x0..x29 via ldp pairs.
        \\ldp x28, x29, [sp, #224]
        \\ldp x26, x27, [sp, #208]
        \\ldp x24, x25, [sp, #192]
        \\ldp x22, x23, [sp, #176]
        \\ldp x20, x21, [sp, #160]
        \\ldp x18, x19, [sp, #144]
        \\ldp x16, x17, [sp, #128]
        \\ldp x14, x15, [sp, #112]
        \\ldp x12, x13, [sp, #96]
        \\ldp x10, x11, [sp, #80]
        \\ldp x8, x9, [sp, #64]
        \\ldp x6, x7, [sp, #48]
        \\ldp x4, x5, [sp, #32]
        \\ldp x2, x3, [sp, #16]
        \\ldp x0, x1, [sp, #0]

        // Deallocate the ArchCpuContext frame (272 bytes) PLUS the
        // 16-byte vector-stub save area sat above it on entry. This
        // matches the trampoline's "+288" deallocation so that
        // SP_EL1 lands at `kstack.top`, where the next exception's
        // vector-stub `stp x0,x30,[sp,#-16]!` will write — keeping
        // dispatch and exception entry framings aligned.
        \\add sp, sp, #288
        \\eret
    );
}

/// Restore `ec.ctx` into the live register file and ERET to either EL0
/// (user) or EL1 (kernel-mode init EC) depending on the saved SPSR_EL1.
/// Mirrors the restore-and-ERET tail of `arch/aarch64/exceptions.zig
/// exceptionTrampoline`. Spec §[execution_context] dispatch; ARM ARM
/// DDI 0487 §D1.10.1 (ERET) restores PC from ELR_EL1 and PSTATE from
/// SPSR_EL1, switching exception level per SPSR.M.
pub fn loadEcContextAndReturn(ec: *ExecutionContext) noreturn {
    // Drain pending zombies parked on this core's slab. Walks all
    // per-poster columns; under cross-core load multiple peers can
    // queue zombies here simultaneously and single-take would let the
    // backlog grow unbounded. Mirrors the x86 reaper in
    // arch/x64/interrupts.zig switchTo. The per-core lock serializes
    // the read-modify-write against remote postZombie writers; we drop
    // the lock before finalize so its own locks aren't nested.
    {
        const cid: u8 = @truncate(zag.arch.aarch64.gic.coreID());
        const sched_mod = zag.sched.scheduler;
        while (true) {
            const zombie_to_reap: ?*ExecutionContext = blk: {
                const lock = &sched_mod.core_locks[cid];
                const irq = lock.lockIrqSaveOrdered(@src(), sched_mod.SCHED_CORE_GROUP);
                defer lock.unlockIrqRestore(irq);
                const slots = &(&sched_mod.core_states[cid]).pending_zombie;
                const sp_addr = asm volatile ("mov %[out], sp"
                    : [out] "=r" (-> u64),
                );
                var i: u8 = 0;
                while (i < sched_mod.MAX_CORES) : (i += 1) {
                    const zr = slots[i] orelse continue;
                    const z = zr.ptr;
                    const z_top = z.kernel_stack.top.addr;
                    const z_base = z.kernel_stack.base.addr;
                    const standing_on_zombie = sp_addr >= z_base and sp_addr < z_top;
                    if (standing_on_zombie or ec == z) continue;
                    slots[i] = null;
                    break :blk z;
                }
                break :blk null;
            };
            const z = zombie_to_reap orelse break;
            zag.sched.execution_context.finalizeDestroyMarkedDead(z);
        }
    }

    // Swap TTBR0_EL1 to the EC's domain root so the post-ERET user-half
    // translation walks the right tree. Kernel half lives in TTBR1 and
    // is shared, so no kernel-side TLBI is needed.
    //
    // caller-pinned: `ec` was selected by the scheduler for this core; its
    // domain is held live by the EC through the dispatch window (the EC
    // carries a SlabRef into the domain), so reading addr_space_root /
    // addr_space_id directly off the deref'd pointer without re-locking
    // the SlabRef is sound here. Mirrors the matching exemption in
    // arch/x64/interrupts.zig switchTo.
    const dom = ec.domain.ptr;
    const new_root = dom.addr_space_root;
    if (new_root.addr != zag.arch.aarch64.paging.getAddrSpaceRoot().addr) {
        zag.arch.aarch64.paging.swapAddrSpace(new_root, dom.addr_space_id);
    }

    // Spec §[syscall_abi]: flush the recv-deferred syscall word into
    // user `[ec.ctx.sp_el0 + 0]` while we are guaranteed to be in the
    // EC's address space. `port.deliverEvent` stages the value when the
    // receiver is parked (rendezvous wake) — at that moment the kernel
    // is still running in the sender's TTBR0, so the write must be
    // deferred to the resume path. Flush after the TTBR0 swap above and
    // before the ERET trampoline. Spec §[event_state] vreg 14 = saved
    // PC; on aarch64 vreg 14 is GPR-backed at x13 — write into the
    // saved frame so ERET surfaces it. Mirrors arch/x64/interrupts.zig
    // switchTo.
    if (ec.pending_event_word_valid) {
        zag.arch.aarch64.interrupts.writeUserSyscallWord(ec.ctx, ec.pending_event_word);
        ec.pending_event_word = 0;
        ec.pending_event_word_valid = false;

        if (ec.pending_event_rip_valid) {
            zag.arch.aarch64.interrupts.writeUserVreg14(ec.ctx, ec.pending_event_rip);
            ec.pending_event_rip = 0;
            ec.pending_event_rip_valid = false;
        }
    }

    const ctx_addr: u64 = @intFromPtr(ec.ctx);
    asm volatile (
        \\mov x0, %[ctx]
        \\b restoreContextAndEret
        :
        : [ctx] "r" (ctx_addr),
        : .{ .x0 = true });
    unreachable;
}

/// Build a first-dispatch ERET frame on the kernel stack so a
/// subsequent `loadEcContextAndReturn` lands at `entry` with x0=arg
/// and SP_EL0=ustack_top in EL0 (user) or, when `ustack_top` is null,
/// stays in EL1 with sp=kstack_top for kernel-mode init ECs.
///
/// The frame layout matches `arch/aarch64/interrupts.zig
/// ArchCpuContext` (272 bytes — Registers 0..240, sp_el0@248,
/// elr_el1@256, spsr_el1@264). AAPCS64 (ARM IHI 0055) places the
/// first integer arg in x0; x30 is left zero — `_start` has no return
/// address. SPSR.M selects the post-ERET exception level (ARM ARM
/// DDI 0487 §D1.10.1).
pub fn prepareEcContext(
    kstack_top: zag.memory.address.VAddr,
    ustack_top: ?zag.memory.address.VAddr,
    entry: zag.memory.address.VAddr,
    arg: u64,
) *zag.arch.aarch64.interrupts.ArchCpuContext {
    @setRuntimeSafety(false);
    const ArchCpuContext = zag.arch.aarch64.interrupts.ArchCpuContext;

    // Place the frame at `kstack_top - 288`, matching the layout the
    // exception trampoline produces on subsequent kernel entries
    // (`exceptionTrampoline` consumes 16 bytes at `[sp, #-16]!` for
    // the vector stub's `stp x0,x30` save plus 272 bytes for its own
    // ArchCpuContext frame, totaling 288). Aligning the first-dispatch
    // frame to the same window means ec.ctx still points at the saved
    // frame after the next user→kernel transition.
    const frame_size: u64 = @sizeOf(ArchCpuContext);
    const stub_save: u64 = 16;
    const ctx_addr: u64 = std.mem.alignBackward(u64, kstack_top.addr - frame_size - stub_save, 16);
    const ctx: *ArchCpuContext = @ptrFromInt(ctx_addr);

    @memset(std.mem.asBytes(ctx), 0);

    ctx.regs.x0 = arg;
    ctx.elr_el1 = entry.addr;

    if (ustack_top) |us| {
        // Reserve a 16-byte slot at the top of the user stack for the
        // kernel-staged syscall return word. Spec §[syscall_abi]: vreg
        // 0 lives at `[sp_el0 + 0]` when a syscall executes, and the
        // resume path (loadEcContextAndReturn) flushes the recv-deferred
        // syscall word into that slot before the ERET. A freshly-prepared
        // EC that suspends before its entry runs (e.g. a sender stashed
        // by `suspend(W, port)` and then resumed via reply / reply_transfer)
        // would otherwise have sp_el0 == stack_top, putting `[sp_el0 + 0]`
        // one byte past the last mapped user-stack page — the kernel write
        // would page-fault. Mirrors x86-64's `rsp - 8` skew rationale; 16
        // here keeps AAPCS64's 16-byte SP alignment requirement.
        ctx.sp_el0 = us.addr - 16;
        ctx.spsr_el1 = SPSR_M_EL0T;
    } else {
        // Kernel-mode init EC: stay at EL1h with the kernel stack as SP.
        // SP_EL0 is unused at EL1h but mirror the kernel SP for safety.
        ctx.sp_el0 = kstack_top.addr;
        ctx.spsr_el1 = SPSR_M_EL1H;
    }

    return ctx;
}

/// Re-patch a previously-built first-dispatch frame for user-mode entry.
/// Used when an EC was allocated without a user stack (so
/// `prepareEcContext` left the frame in EL1h kernel-mode shape) and the
/// caller is wiring in the user stack and entry afterward.
pub fn patchUserModeIretFrame(
    ctx: *zag.arch.aarch64.interrupts.ArchCpuContext,
    entry: zag.memory.address.VAddr,
    user_stack_top: zag.memory.address.VAddr,
    arg: u64,
) void {
    ctx.elr_el1 = entry.addr;
    ctx.sp_el0 = user_stack_top.addr;
    ctx.spsr_el1 = SPSR_M_EL0T;
    ctx.regs.x0 = arg;
}

/// Halt the local core with DAIF.{I,F} clear until the next IRQ (WFI).
/// Spec §[execution_context] idle EC. ARM ARM DDI 0487 §C5.2.4 WFI.
pub fn idle() void {
    asm volatile (
        \\msr daifclr, #2
        \\wfi
        ::: .{ .memory = true });
}

/// aarch64 stub for the cross-arch `parkPerCoreCaches` contract. The
/// scheduler's park path is currently x86-64-only (no analogous TSS or
/// SyscallScratch caches on aarch64). When aarch64 grows equivalent
/// per-core scratch, fill this in.
pub fn parkPerCoreCaches(core_id: u64, park_top: u64) void {
    _ = core_id;
    _ = park_top;
}

pub fn parkAndAwaitIRQ(park_top: u64) noreturn {
    _ = park_top;
    asm volatile (
        \\msr daifclr, #2
        \\wfi
        \\msr daifset, #2
        \\b scheduler_run_after_park
        ::: .{ .memory = true });
    unreachable;
}
