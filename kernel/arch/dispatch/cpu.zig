const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const BootInfo = zag.boot.protocol.BootInfo;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const VAddr = zag.memory.address.VAddr;

// --- Fault / context types ---------------------------------------------

pub const ArchCpuContext = switch (builtin.cpu.arch) {
    .x86_64 => x64.interrupts.ArchCpuContext,
    .aarch64 => aarch64.interrupts.ArchCpuContext,
    else => unreachable,
};

pub const PageFaultContext = switch (builtin.cpu.arch) {
    .x86_64 => x64.interrupts.PageFaultContext,
    .aarch64 => aarch64.interrupts.PageFaultContext,
    else => unreachable,
};

// --- Calling convention / entry ----------------------------------------

pub fn cc() std.builtin.CallingConvention {
    return switch (builtin.cpu.arch) {
        .x86_64 => .{ .x86_64_sysv = .{} },
        .aarch64 => .{ .aarch64_aapcs = .{} },
        else => unreachable,
    };
}

/// Called by the kernel entry point after the bootloader has already set SP
/// to the kernel stack (via switchStackAndCall). Jumps to the trampoline
/// with boot_info as the first argument.
pub inline fn kEntry(boot_info: *BootInfo, ktrampoline: *const fn (*BootInfo) callconv(cc()) noreturn) noreturn {
    // The bootloader already switched SP. Just tail-call the trampoline.
    ktrampoline(boot_info);
}

/// Switch SP to a new stack and call a function. Used by the bootloader to
/// switch from the UEFI stack (which may be invalid after exitBootServices)
/// to the kernel stack before entering the kernel.
pub inline fn switchStackAndCall(stack_top: VAddr, arg: u64, entry: u64) noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            asm volatile (
                \\movq %[sp], %%rsp
                \\movq %%rsp, %%rbp
                \\movq %[arg], %%rdi
                \\jmp *%[entry]
                :
                : [sp] "r" (stack_top.addr),
                  [arg] "r" (arg),
                  [entry] "r" (entry),
                : .{ .rsp = true, .rbp = true, .rdi = true });
        },
        .aarch64 => {
            // Follow Linux arm64's rule: MAIR_EL1 is only ever written
            // with the MMU disabled. We stay on UEFI's MAIR here —
            // changing it while the MMU is on and stale WB cache lines
            // may exist at our physical pages produces "constrained
            // unpredictable" reads on Cortex-A72 KVM (head.S:85-131,
            // proc.S:__cpu_setup). Our kernel-side page tables use
            // attr_indx=1 which under UEFI's MAIR is Normal NC — that
            // is slower but correct. If/when the kernel needs Write-
            // Back performance, it must perform the proper MMU-off →
            // clean → MAIR write → MMU-on cycle from its own code.
            //
            // Mask IRQ/FIQ/SError so no stale firmware interrupt can
            // reach its VBAR between here and the kernel installing
            // its real exception vectors.
            asm volatile (
                \\msr daifset, #0x7
                \\isb
                \\mov sp, %[sp]
                \\mov x0, %[arg]
                \\br %[entry]
                :
                : [sp] "r" (stack_top.addr),
                  [arg] "r" (arg),
                  [entry] "r" (entry),
                : .{ .x0 = true, .memory = true });
        },
        else => unreachable,
    }
    unreachable;
}

// --- Control primitives ------------------------------------------------

/// Spin-loop hint. Reduces power and inter-core memory traffic while
/// busy-waiting on an atomic.
pub inline fn cpuRelax() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("pause" ::: .{ .memory = true }),
        .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
        else => unreachable,
    }
}

/// Read the current stack pointer. Used by the deferred-destroy reaper
/// in scheduler.takeOwnPendingZombie / arch.switchTo to test whether
/// the running rsp is still inside a zombie EC's kernel stack — if it
/// is, finalize must defer to a later switch.
pub inline fn currentSp() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("movq %%rsp, %[out]"
            : [out] "=r" (-> u64),
        ),
        .aarch64 => asm volatile ("mov %[out], sp"
            : [out] "=r" (-> u64),
        ),
        else => unreachable,
    };
}

pub fn halt() noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.halt(),
        .aarch64 => aarch64.cpu.halt(),
        else => unreachable,
    }
}

/// Send a kprof-dump IPI to every core except the caller. Invoked by
/// the dumping core inside `kprof.dump.end()` to quiesce every other
/// CPU before serial-dumping. Per-arch backend resolves the IPI vector
/// (x86: `IntVecs.kprof_dump`; aarch64: SGI 1).
pub fn broadcastKprofIpi() void {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            const lapics = x64.apic.lapics orelse return;
            const self_id = x64.apic.coreID();
            const vec = @intFromEnum(x64.interrupts.IntVecs.kprof_dump);
            for (lapics, 0..) |la, i| {
                if (i == self_id) continue;
                x64.apic.sendIpi(@intCast(la.apic_id), vec);
            }
        },
        .aarch64 => {
            const self_id = aarch64.gic.coreID();
            const n = aarch64.gic.coreCount();
            var i: u64 = 0;
            while (i < n) {
                if (i != self_id) {
                    aarch64.gic.sendIpiToCore(i, 1);
                }
                i += 1;
            }
        },
        else => unreachable,
    }
}

/// Align a stack pointer for the target architecture's calling convention.
/// x86-64: 16-byte aligned minus 8 (simulates the return address push by `call`).
/// aarch64: 16-byte aligned (SP must be 16-byte aligned at all times).
pub fn alignStack(stack_top: VAddr) VAddr {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.alignStack(stack_top),
        .aarch64 => aarch64.cpu.alignStack(stack_top),
        else => unreachable,
    };
}

// --- Interrupt enable state (CPU IF / DAIF) ----------------------------

pub fn enableInterrupts() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.enableInterrupts(),
        .aarch64 => aarch64.cpu.enableInterrupts(),
        else => unreachable,
    }
}

pub fn interruptsEnabled() bool {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.interruptsEnabled(),
        .aarch64 => aarch64.cpu.interruptsEnabled(),
        else => unreachable,
    };
}

pub fn saveAndDisableInterrupts() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.saveAndDisableInterrupts(),
        .aarch64 => aarch64.cpu.saveAndDisableInterrupts(),
        else => unreachable,
    };
}

pub fn restoreInterrupts(state: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.restoreInterrupts(state),
        .aarch64 => aarch64.cpu.restoreInterrupts(state),
        else => unreachable,
    }
}

// --- User-memory access gate (SMAP / PAN) ------------------------------

/// Temporarily allow kernel access to user pages.
/// x86: STAC (clear AC flag, disabling SMAP).
/// aarch64: clear PSTATE.PAN (disabling Privileged Access Never).
pub inline fn userAccessBegin() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.stac(),
        .aarch64 => aarch64.cpu.panDisable(),
        else => unreachable,
    }
}

/// Re-enable kernel protection from user page access.
/// x86: CLAC (set AC flag, enabling SMAP).
/// aarch64: set PSTATE.PAN (enabling Privileged Access Never).
pub inline fn userAccessEnd() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.clac(),
        .aarch64 => aarch64.cpu.panEnable(),
        else => unreachable,
    }
}

// --- Cache maintenance -------------------------------------------------

/// Synchronize the instruction cache with the data cache after writing
/// new executable code to memory. On x86-64 this is a no-op (coherent
/// I-cache). On aarch64 the I/D caches are separate and loader code must
/// explicitly invalidate the I-cache before fetching freshly written
/// instructions, or stale bytes can be decoded as garbage.
pub fn syncInstructionCache() void {
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => asm volatile (
            \\ic ialluis
            \\dsb ish
            \\isb
            ::: .{ .memory = true }),
        else => unreachable,
    }
}

/// Clean the data cache over the given byte range to the Point of
/// Unification. On x86-64 this is a no-op (coherent caches). On aarch64
/// this is required after writing freshly loaded ELF code through the
/// physmap (D-cache) view: until the lines are pushed past the unified
/// PoU, a subsequent `ic ivau`/`ic ialluis` cannot make the new
/// instruction bytes visible to instruction fetch, and the user's
/// entry point fetches stale (typically zero) bytes — manifesting as
/// repeating instruction-abort exceptions on every ERET.
///
/// ARM ARM B2.4.6 / D5.10.2: data-to-instruction cache coherency.
/// Clean + invalidate the data cache over the given byte range to the
/// point of coherency. On x86-64 this is a no-op (coherent D-cache). On
/// aarch64 this is required when memory is reconfigured from Normal
/// Non-cacheable to Normal Write-Back (e.g., when the kernel installs
/// its own MAIR_EL1 over UEFI's), otherwise stale cache lines from a
/// prior cacheable view can shadow freshly written NC data.
pub fn cleanInvalidateDcacheRange(start: u64, len: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => {
            // Drain any pending Normal Non-cacheable stores from the
            // write buffer to RAM before we start cleaning the cache.
            // Without this, NC writes may still be in flight when DC
            // CIVAC runs, and subsequent WB reads can race past the
            // pending writes.
            asm volatile ("dsb sy" ::: .{ .memory = true });
            // 64-byte cache line on Cortex-A72. Use a conservative
            // fixed line size rather than reading CTR_EL0 here.
            const line: u64 = 64;
            const end = start + len;
            var addr = start & ~(line - 1);
            while (addr < end) : (addr += line) {
                asm volatile ("dc civac, %[a]"
                    :
                    : [a] "r" (addr),
                    : .{ .memory = true });
            }
            asm volatile (
                \\dsb sy
                \\isb
                ::: .{ .memory = true });
        },
        else => unreachable,
    }
}

// --- FPU state (per-thread FP/SIMD save/restore) -----------------------

/// Initialise an FPU buffer to the architectural reset state for a
/// brand-new thread (FCW/MXCSR defaults on x64; FPCR/FPSR defaults
/// on aarch64). Called once from `Thread.create`.
pub fn fpuStateInit(area: *[576]u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.fpuStateInit(area),
        .aarch64 => aarch64.cpu.fpuStateInit(area),
        else => unreachable,
    }
}

/// Save the current core's FP/SIMD register file into `area`.
/// `area` must be 64-byte aligned and at least 576 bytes (FXSAVE format
/// on x64; V0-V31 + FPCR + FPSR on aarch64).
pub fn fpuSave(area: *[576]u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.fpuSave(area),
        .aarch64 => aarch64.cpu.fpuSave(area),
        else => unreachable,
    }
}

/// Restore the FP/SIMD register file from `area`. Same alignment and
/// format requirements as `fpuSave`.
pub fn fpuRestore(area: *[576]u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.fpuRestore(area),
        .aarch64 => aarch64.cpu.fpuRestore(area),
        else => unreachable,
    }
}

/// Re-enable user-mode FP access on the local core after a trap was
/// serviced. x64: clear CR0.TS via CLTS. aarch64: set CPACR_EL1.FPEN
/// to 0b11 (EL0 and EL1 both allowed).
pub fn fpuClearTrap() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.fpuClearTrap(),
        .aarch64 => aarch64.cpu.fpuClearTrap(),
        else => unreachable,
    }
}

// --- Power / shutdown / entropy ----------------------------------------

pub const PowerAction = switch (builtin.cpu.arch) {
    .x86_64 => x64.power.PowerAction,
    .aarch64 => aarch64.power.PowerAction,
    else => unreachable,
};

pub const CpuPowerAction = switch (builtin.cpu.arch) {
    .x86_64 => x64.power.CpuPowerAction,
    .aarch64 => aarch64.power.CpuPowerAction,
    else => unreachable,
};

pub fn powerAction(action: PowerAction) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.power.powerAction(action),
        .aarch64 => aarch64.power.powerAction(action),
        else => unreachable,
    };
}

pub fn cpuPowerAction(action: CpuPowerAction, value: u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.power.cpuPowerAction(action, value),
        .aarch64 => aarch64.power.cpuPowerAction(action, value),
        else => unreachable,
    };
}

/// Read a hardware-random word. RDRAND on x86-64, RNDR on aarch64.
/// Returns null if the instruction failed (entropy pool stall) or is
/// unsupported on this CPU.
pub fn getRandom() ?u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.rdrand(),
        .aarch64 => aarch64.cpu.rndr(),
        else => unreachable,
    };
}

/// Probe CPU feature bits backing `arch.memory.zeroPage`. Called once
/// from the PMM initialization path before any freed page is zeroed.
pub fn initZeroPageFeatures() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.initZeroPageFeatures(),
        .aarch64 => aarch64.cpu.initZeroPageFeatures(),
        else => unreachable,
    }
}

// --- Per-core hardware state (freq / temp / C-state) -------------------

/// One-time bring-up on the bootstrap core. Called from `kMain` after
/// pmuInit and before `sched.globalInit`.
pub fn sysInfoInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.sysinfo.sysInfoInit(),
        .aarch64 => aarch64.sysinfo.sysInfoInit(),
        else => unreachable,
    }
}

// ── Spec v3 EC dispatch primitives ───────────────────────────────────
// FPU-trap arming, register-bank load, and TLS-base accessors used by
// the ExecutionContext dispatch path. Spec §[execution_context].

/// Restore `ec.ctx` into the live register file and return to userspace
/// via iretq / eret. Never returns to the caller. Used by the scheduler
/// `switchTo` path after lazy-FPU bookkeeping.
pub fn loadEcContextAndReturn(ec: *ExecutionContext) noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.loadEcContextAndReturn(ec),
        .aarch64 => aarch64.cpu.loadEcContextAndReturn(ec),
        else => unreachable,
    }
}

/// Build the first-dispatch iret frame at the top of an EC's kernel
/// stack. Returns the *ArchCpuContext pointer that scheduler.switchTo
/// will pass to loadEcContextAndReturn. `entry` is the user-mode RIP;
/// `ustack_top` is the user RSP (or null for kernel-mode init ECs);
/// `arg` is loaded into the first argument register (vreg 1 / rdi on
/// x86-64) so create_capability_domain can pass `cap_table_base`.
pub fn prepareEcContext(
    kstack_top: VAddr,
    ustack_top: ?VAddr,
    entry: VAddr,
    arg: u64,
) *ArchCpuContext {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.prepareEcContext(kstack_top, ustack_top, entry, arg),
        .aarch64 => aarch64.cpu.prepareEcContext(kstack_top, ustack_top, entry, arg),
        else => unreachable,
    };
}


/// Re-patch a previously-built iret frame from kernel-mode shape to
/// user-mode shape. Used when an EC was allocated without a user stack
/// (so `prepareEcContext` left the frame in kernel mode) and the
/// caller is wiring in the user stack and entry afterward — the root
/// service's primordial EC and freshly-spawned domain ECs both follow
/// this pattern. Writes user code/data selectors, the user stack
/// pointer (with the SysV `rsp%16==8` skew baked in), the entry RIP,
/// and the first-arg register.
pub fn patchUserModeIretFrame(
    ctx: *ArchCpuContext,
    entry: VAddr,
    user_stack_top: VAddr,
    arg: u64,
) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.patchUserModeIretFrame(ctx, entry, user_stack_top, arg),
        .aarch64 => aarch64.cpu.patchUserModeIretFrame(ctx, entry, user_stack_top, arg),
        else => unreachable,
    }
}

/// Read the user-mode stack pointer captured on syscall entry from a
/// saved EC context. x86_64 stashes it in `ctx.rsp`; aarch64 stashes
/// it in `ctx.sp_el0` (the user SP banked register). Used by syscall
/// paths that need to re-read vreg overflow entries off the user stack
/// per spec §[syscall_abi].
pub fn userStackPointer(ctx: *const ArchCpuContext) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => ctx.rsp,
        .aarch64 => ctx.sp_el0,
        else => unreachable,
    };
}

/// Index of the first stack-backed vreg per spec §[syscall_abi]. x86-64:
/// vregs 1..13 = GPRs, vreg 14 is the first `[rsp + ...]` slot. aarch64:
/// vregs 1..31 = x0..x30, vreg 32 is the first `[sp + ...]` slot. The
/// stack offset for any vreg N >= firstStackVreg() is
/// `(N - firstStackVreg() + 1) * 8` from the syscall-time user SP —
/// vreg 14 / 32 lands at `[sp + 8]`, vreg 127 at the top of the per-arch
/// reserved frame. Used by §[handle_attachments] readers to locate the
/// pair-entry band at vregs `[128-N..127]`.
pub fn firstStackVreg() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => 14,
        .aarch64 => 32,
        else => unreachable,
    };
}

/// Halt the local core in an interrupts-enabled state until the next
/// interrupt (HLT with IF=1 on x86-64, WFI with DAIF cleared on
/// aarch64). Used by the per-core idle EC.
pub fn idle() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.idle(),
        .aarch64 => aarch64.cpu.idle(),
        else => unreachable,
    }
}

/// Update per-core caches (per-CPU scratch + TSS.RSP0 equivalent) to
/// "no EC dispatched" / park-state. Called by the scheduler before
/// swapping rsp to the per-core park kstack and idling. See arch impls
/// for what fields get cleared / pointed at the park kstack top.
pub fn parkPerCoreCaches(core_id: u64, park_top: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.parkPerCoreCaches(core_id, park_top),
        .aarch64 => aarch64.cpu.parkPerCoreCaches(core_id, park_top),
        else => unreachable,
    }
}
