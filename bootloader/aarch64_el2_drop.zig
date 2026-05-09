//! aarch64 EL2 → EL1 drop for the UEFI bootloader.
//!
//! When QEMU is invoked with `-M virt,virtualization=on -bios AAVMF`,
//! AAVMF boots and runs its entire DXE/BDS phase at EL2. Our Stygia UEFI
//! bootloader is therefore called at EL2 and inherits an EL2 MMU
//! (SCTLR_EL2.M=1, TTBR0_EL2 identity-mapping firmware + the loaded
//! bootloader image). If we simply `br kEntry` into the kernel from
//! EL2, two things break:
//!
//!   (a) kEntry lives at a TTBR1 high VA; TTBR1_EL1 is not consulted
//!       by the EL2 translation regime, so the fetch faults.
//!   (b) The Stygia kernel unconditionally assumes it runs at EL1 and
//!       operates TTBR0/TTBR1_EL1, SCTLR_EL1, MAIR_EL1, CPACR_EL1,
//!       VBAR_EL1 — none of which govern an EL2 MMU.
//!
//! So right before `switchStackAndCall` (which is where the bootloader
//! hands off control), we:
//!
//!   1. Read TTBR0_EL2 / TCR_EL2 / MAIR_EL2 / SCTLR_EL2 — the MMU state
//!      the firmware set up and that our currently-executing bootloader
//!      code depends on.
//!   2. Mirror that state into the corresponding EL1 sysregs. TTBR0_EL1
//!      is a direct copy (identity-mapped PA==VA in the low half). TCR
//!      needs field rearrangement because TCR_EL2 is a single-regime
//!      layout and TCR_EL1 is two-regime; we preserve T0SZ/IRGN0/ORGN0/
//!      SH0/TG0, translate PS→IPS, and OR in T1SZ/TG1/... that the
//!      bootloader's TTBR1 kernel_code mappings need.
//!   3. Install a minimal EL2 hyp stub vector table at VBAR_EL2 so an
//!      EL1 `hvc` trap has somewhere to land. The kernel replaces this
//!      with its own `__hyp_vectors` (kernel/arch/aarch64/boot/start.S)
//!      during `vmInit` / world-switch setup.
//!   4. Give the dispatcher a dedicated SP_EL2 and a clean TPIDR_EL2.
//!   5. ERET into EL1 (SPSR_EL2 = 0x3C5 = EL1h + DAIF masked, ELR_EL2 =
//!      label after the ERET sequence), setting SP_EL1 first so EL1
//!      exceptions have a stack.
//!
//! After the ERET the bootloader resumes at EL1 with the same logical
//! state — same MMU contents (identity low half + kernel high half),
//! same calling conventions — and `switchStackAndCall(kEntry, ...)`
//! proceeds as in the normal UEFI-at-EL1 path.
//!
//! The bootloader records `arrived_at_el2 = 1` in BootInfo so the
//! kernel knows to set `vm.hyp_stub_installed = true` after it runs,
//! unlocking `vmSupported()` and the s4_2_* VM syscall tests.
//!
//! References:
//!   ARM ARM K.a
//!     D13.2.28  HCR_EL2
//!     D13.2.29  HSTR_EL2
//!     D13.2.51  MAIR_EL1 / D13.2.52 MAIR_EL2
//!     D13.2.117 SCTLR_EL1 / D13.2.118 SCTLR_EL2
//!     D13.2.131 TCR_EL1 / D13.2.132 TCR_EL2
//!     D13.2.144 TTBR0_EL1 / D13.2.145 TTBR0_EL2
//!   Linux arm64 `arch/arm64/kernel/head.S` (`el2_setup` path) for the
//!   same idea, though Linux additionally disables+re-enables the MMU
//!   because its boot protocol requires MMU-off at entry. We keep the
//!   MMU on across the drop so the bootloader can continue executing
//!   without setting up a fresh identity map of its own code.

const std = @import("std");

const uefi = std.os.uefi;

/// Dedicated SP_EL2 stack, 16-byte aligned per AAPCS64. Sits in the
/// bootloader's .bss. Lives long enough for `dropToEl1` to ERET — the
/// kernel's own `__hyp_vectors` never references this stack because the
/// kernel installs a fresh SP_EL2 of its own on world-switch entry.
var hyp_stack: [0x2000]u8 align(16) = undefined;

// ===========================================================================
// Bootloader EL2 hyp stub — runtime-allocated.
//
// The stub exposes a tiny HVC dispatcher that the EL1 kernel uses to
// install its own `__hyp_vectors` at VBAR_EL2. Only the sync-lower-A64
// vector (offset 0x400) does real work — on HVC imm16 ==
// `HVC_IMM_INSTALL_VBAR_EL2` (0xE112) it writes x0 into VBAR_EL2 and
// ERETs; on any other imm it falls through to a bare ERET so EL1 resumes
// at the instruction after the HVC.
//
// We allocate the stub in a fresh RuntimeServicesCode page at runtime
// rather than embedding it in the bootloader PE's `.text` section.
// Empirically, AAVMF's EL2 MMU drops execute permission on bootloader
// LoaderCode pages once ExitBootServices runs, which turned the earlier
// static `bootloader_hyp_vectors` export into an IFSC=0xF prefetch abort
// loop as soon as the kernel's first HVC landed on the stub. A
// RuntimeServicesCode page is preserved and remains executable across
// ExitBootServices, matching how runtime drivers keep running at EL2
// after firmware hands off.
//
// Every vector entry is a `b .` stall except sync-lower-A64; stray traps
// simply hang the core in a tight loop that the test runner catches as
// a timeout rather than running off into random memory.
// ===========================================================================

/// The stub is 0x800 bytes (a full ARM exception vector table). We
/// allocate a single 4 KiB RuntimeServicesCode page for it. The vector
/// table must be 2 KiB-aligned (ARM ARM D13.2.148 VBAR_EL2); a fresh
/// page from AllocatePages is 4 KiB-aligned so the start of the page
/// is automatically a legal VBAR_EL2 value.
const HYP_VECTORS_SIZE: usize = 0x800;

/// Precomputed machine code for the hyp vector stub. Each vector slot
/// is 0x80 bytes; only the sync-lower-A64 slot at offset 0x400 contains
/// a real handler, every other slot is a single `b .` branch followed
/// by padding. Generating the bytes once at comptime lets us memcpy
/// them into any runtime-allocated code page without relying on
/// section-relative linker placement of an inline-asm symbol.
///
/// The sync-lower-A64 handler at offset 0x400 decodes ESR_EL2.ISS[15:0]
/// (the HVC imm16) and, on `HVC_IMM_INSTALL_VBAR_EL2`, writes x0 into
/// VBAR_EL2. Any other imm falls through to a bare ERET. Assembled
/// bytes verified against `zig build-obj -target aarch64-freestanding`:
///
///   mrs  x9, esr_el2              0xD53C5209
///   mov  x10, #0xFFFF             0xD29FFFEA  (MOVZ)
///   and  x9, x9, x10              0x8A0A0129
///   mov  x10, #0xE112             0xD29C224A  (MOVZ)
///   cmp  x9, x10                  0xEB0A013F
///   b.ne +12 (-> eret)            0x54000061
///   msr  vbar_el2, x0             0xD51CC000
///   isb                           0xD5033FDF
///   eret                          0xD69F03E0
///
/// We deliberately avoid touching SP_EL2 in this handler — hyp_stack
/// lives in the bootloader .bss and its EL2 access attributes post-
/// ExitBootServices are unreliable (same reason we moved the vector
/// page out of the PE `.text`). Clobbering x9/x10 is fine because
/// `kernel/arch/aarch64/vm.zig :: installHypVectors` marks them
/// clobbered in its inline asm around the HVC instruction.
const hyp_vectors_bytes: [HYP_VECTORS_SIZE]u8 = blk: {
    @setEvalBranchQuota(100000);
    var out: [HYP_VECTORS_SIZE]u8 = [_]u8{0} ** HYP_VECTORS_SIZE;

    // `b .` — an A64 unconditional branch to self. Opcode 0x14000000.
    const b_dot: u32 = 0x14000000;

    // Vector slots 0x000..0x3FF (8 slots) and 0x480..0x7FF (7 slots)
    // all contain a single `b .` at their base. Only the slot at
    // 0x400 (sync lower A64) holds the actual HVC dispatcher below.
    const stall_offsets = [_]usize{
        0x000, 0x080, 0x100, 0x180, 0x200, 0x280, 0x300, 0x380,
        0x480, 0x500, 0x580, 0x600, 0x680, 0x700, 0x780,
    };
    for (stall_offsets) |off| {
        std.mem.writeInt(u32, out[off..][0..4], b_dot, .little);
    }

    const handler: [9]u32 = .{
        0xD53C5209, // mrs  x9, esr_el2
        0xD29FFFEA, // mov  x10, #0xFFFF  (movz)
        0x8A0A0129, // and  x9, x9, x10
        0xD29C224A, // mov  x10, #0xE112  (movz)
        0xEB0A013F, // cmp  x9, x10
        0x54000061, // b.ne +12 -> eret
        0xD51CC000, // msr  vbar_el2, x0
        0xD5033FDF, // isb
        0xD69F03E0, // eret
    };
    const base = 0x400;
    for (handler, 0..) |insn, i| {
        std.mem.writeInt(u32, out[base + i * 4 ..][0..4], insn, .little);
    }

    break :blk out;
};

/// Allocate a fresh RuntimeServicesCode page, copy the hyp vector stub
/// into its base, clean+invalidate the D-cache over it (Point of
/// Coherency) so the CPU can fetch the freshly written instructions at
/// EL2, and return the physical address to pass as VBAR_EL2. Must be
/// called before `dropToEl1` and before ExitBootServices.
pub fn allocateHypVectorStub(bs: *uefi.tables.BootServices) !u64 {
    const pages = try bs.allocatePages(.any, .runtime_services_code, 1);
    const page_ptr: [*]u8 = @ptrCast(pages);
    const dst = page_ptr[0..HYP_VECTORS_SIZE];
    @memcpy(dst, &hyp_vectors_bytes);
    // Zero the tail of the page (0x800..0x1000) so any stray exception
    // that somehow lands past the vector table decodes as an undefined
    // instruction rather than a stale value from whatever previously
    // occupied the page.
    @memset(page_ptr[HYP_VECTORS_SIZE..0x1000], 0);

    // Clean+invalidate the D-cache over the stub page so the CPU's
    // I-cache fill after VBAR_EL2 is updated sees the freshly written
    // instruction bytes from RAM, not stale D-cache lines. Pair this
    // with an instruction-cache invalidate below. Linux arm64 does the
    // same in `arch/arm64/kernel/head.S :: __inval_cache_range`.
    asm volatile (
        \\mov x0, %[base]
        \\mov x1, %[end]
        \\1:
        \\dc  cvau, x0
        \\add x0, x0, #64
        \\cmp x0, x1
        \\b.lt 1b
        \\dsb ish
        \\mov x0, %[base]
        \\2:
        \\ic  ivau, x0
        \\add x0, x0, #64
        \\cmp x0, x1
        \\b.lt 2b
        \\dsb ish
        \\isb
        :
        : [base] "r" (@intFromPtr(page_ptr)),
          [end] "r" (@intFromPtr(page_ptr) + 0x1000),
        : .{ .memory = true, .x0 = true, .x1 = true });

    return @intFromPtr(page_ptr);
}

/// Read CurrentEL.EL (bits [3:2]). 0=EL0, 1=EL1, 2=EL2, 3=EL3.
pub fn currentEl() u8 {
    var v: u64 = 0;
    asm volatile ("mrs %[v], CurrentEL"
        : [v] "=r" (v),
    );
    return @intCast((v >> 2) & 0x3);
}

/// Drop from EL2 to EL1 in place, preserving the active MMU state.
///
/// Must be called:
///   - with the MMU enabled at EL2 (firmware configuration),
///   - AFTER `setKernelAddrSpace()` has loaded a kernel table into
///     TTBR1_EL1 (TTBR0_EL1 is populated here from TTBR0_EL2), and
///   - BEFORE `switchStackAndCall(kEntry, ...)`.
///
/// On return, we are at EL1h, with MMU still on, same identity mapping
/// in TTBR0_EL1 and the kernel-side mappings in TTBR1_EL1. `sp` has
/// been preserved across the drop via SP_EL1. All GP regs other than
/// x0..x9 clobbered by the drop sequence itself are preserved by
/// saving them to the stack around the call because we compile with
/// `callconv(.c)`.
pub fn dropToEl1(hyp_vbar: u64) void {
    // Pre-resolve the dedicated EL2 stack top in pure Zig so the asm
    // below doesn't have to relocate it. `hyp_vbar` is the PA of the
    // kernel's already-loaded `__hyp_vectors` table (must be 2 KiB
    // aligned per ARM ARM D13.2.148). The bootloader resolves it via
    // the kernel ELF's symbol table during section mapping, and this
    // routine is the sole writer of VBAR_EL2 on the boot path.
    std.debug.assert(hyp_vbar & 0x7FF == 0);
    const hyp_sp_top: u64 = @intFromPtr(&hyp_stack) + hyp_stack.len;

    asm volatile (
    // -------------------------------------------------------------
    // 1. Mirror EL2 MMU state into EL1 sysregs.
    //
    //    TTBR0_EL1 <- TTBR0_EL2         (identity map covering us)
    //    MAIR_EL1  <- MAIR_EL2          (same attribute indices)
    //    TCR_EL1   <- TCR_EL2 low half  + T1SZ/TG1/SH1/IRGN1/ORGN1
    //                                    + IPS in bits [34:32]
    //    SCTLR_EL1 <- RES1 | (SCTLR_EL2 & {M,C,I,SA})
    //    VBAR_EL1  <- VBAR_EL2          (stray EL1 traps land
    //                                    somewhere observable until
    //                                    early_fault installs ours)
    // -------------------------------------------------------------
        \\        mrs     x9,  ttbr0_el2
        \\        msr     ttbr0_el1, x9
        \\
        \\        mrs     x9,  mair_el2
        \\        msr     mair_el1, x9
        \\
        // Build TCR_EL1 from TCR_EL2.
        //
        // TCR_EL2 layout (single regime, bits we care about):
        //   [5:0]    T0SZ
        //   [9:8]    IRGN0
        //   [11:10]  ORGN0
        //   [13:12]  SH0
        //   [15:14]  TG0
        //   [18:16]  PS  (physical address size)
        //   [20]     TBI
        //
        // TCR_EL1 layout (two regimes):
        //   [5:0]    T0SZ
        //   [9:8]    IRGN0
        //   [11:10]  ORGN0
        //   [13:12]  SH0
        //   [15:14]  TG0
        //   [21:16]  T1SZ
        //   [23]     A1
        //   [25:24]  IRGN1
        //   [27:26]  ORGN1
        //   [29:28]  SH1
        //   [31:30]  TG1  (0b10 = 4KB)
        //   [34:32]  IPS
        //   [37:36]  AS, [38] TBI0, [39] TBI1 (leave zero)
        //
        // Low 16 bits transfer directly. Extract PS from [18:16] of
        // TCR_EL2 and place it at [34:32] of TCR_EL1. OR in the
        // standard kernel TTBR1 configuration (same values the Stygia
        // kernel would write via enableKernelTranslation()):
        //   T1SZ  = 16
        //   IRGN1 = 0b01 (WB-WA)
        //   ORGN1 = 0b01 (WB-WA)
        //   SH1   = 0b11 (Inner Shareable)
        //   TG1   = 0b10 (4KB)
        \\        mrs     x9,  tcr_el2
        \\        and     x10, x9, #0xFFFF            // T0SZ/IRGN0/ORGN0/SH0/TG0
        \\        and     x11, x9, #(0x7 << 16)       // PS in [18:16]
        \\        lsl     x11, x11, #16               // move to [34:32]
        \\        orr     x10, x10, x11
        \\        mov     x11, #(16 << 16)            // T1SZ
        \\        orr     x10, x10, x11
        \\        mov     x11, #(0x1 << 24)           // IRGN1[0]
        \\        orr     x10, x10, x11
        \\        mov     x11, #(0x1 << 26)           // ORGN1[0]
        \\        orr     x10, x10, x11
        \\        mov     x11, #(0x3 << 28)           // SH1
        \\        orr     x10, x10, x11
        \\        mov     x11, #(0x2 << 30)           // TG1 = 4KB
        \\        orr     x10, x10, x11
        \\        msr     tcr_el1, x10
        \\
        // SCTLR_EL1: start from the RES1 reset pattern (bits 29,28,23,
        // 22,20,11 set) and OR in the {M,C,I,SA} bits from SCTLR_EL2
        // so the EL1 regime inherits whatever enable flags firmware
        // had turned on. Linux uses the same trick (init_el2_state ->
        // __cpu_setup). Bit positions:
        //   [0]  M   MMU enable
        //   [2]  C   Data cache enable
        //   [3]  SA  SP alignment check enable
        //   [12] I   Instruction cache enable
        //
        // RES1 mask = (1<<29)|(1<<28)|(1<<23)|(1<<22)|(1<<20)|(1<<11)
        //           = 0x30D0_0800
        \\        mrs     x9,  sctlr_el2
        \\        mov     x10, #0x0800                // bit 11
        \\        movk    x10, #0x30D0, lsl #16       // bits 29,28,23,22,20
        \\        mov     x11, #((1<<0)|(1<<2)|(1<<3)|(1<<12))
        \\        and     x9,  x9, x11
        \\        orr     x9,  x9, x10
        \\        msr     sctlr_el1, x9
        \\
        \\        mrs     x9,  vbar_el2
        \\        msr     vbar_el1, x9
        \\
        \\        isb
        \\
        // -------------------------------------------------------------
        // 2. HCR_EL2.RW = 1 so EL1 executes A64. Leave the rest as
        //    reset defaults — the kernel reconfigures HCR_EL2 when it
        //    starts a guest.
        // -------------------------------------------------------------
        \\        mov     x9, #1
        \\        lsl     x9, x9, #31
        \\        msr     hcr_el2, x9
        \\
        // CPTR_EL2: don't trap FP/SIMD to EL2. Matches Linux.
        \\        mov     x9, #0x33FF
        \\        msr     cptr_el2, x9
        \\
        // CPACR_EL1.FPEN = 0b11 (don't trap EL0/EL1 FP/SIMD to EL1).
        // Without this the first FP/SIMD use in the kernel (Zig's
        // struct copies etc.) raises EC=0x07 at EL1.
        \\        mov     x9, #(0x3 << 20)
        \\        msr     cpacr_el1, x9
        \\
        // -------------------------------------------------------------
        // 3. Disable the EL2 MMU before handing off. AAVMF's firmware
        //    EL2 page tables cover firmware memory only, so any EL2
        //    instruction fetch into kernel-allocated pages (our own
        //    HVC stub, and the kernel's `__hyp_vectors` table once it
        //    is installed later) translates to an IFSC=0xF permission
        //    fault — the pages exist in the EL2 walk but they land on
        //    stale / unexecutable attributes. Turning SCTLR_EL2.M off
        //    makes EL2 instruction/data accesses use PAs directly and
        //    become Normal Write-Back cacheable, Outer Shareable
        //    (ARM ARM D5.2.7 "When the stage of translation is
        //    disabled"), which is exactly what the kernel's EL2-only
        //    world-switch path needs.
        //
        //    We pair this with:
        //      - DSB SY + ISB so the MMU disable takes effect before
        //        the next instruction fetch.
        //      - `ic iallu` then `tlbi alle2` to drop any stale
        //        cached translations the previous MMU-on regime
        //        might have left behind.
        //      - A second DSB SY + ISB to wait for the IC/TLBI to
        //        complete system-wide.
        //
        //    Then install VBAR_EL2 and clear TPIDR_EL2 as before.
        \\        mrs     x9,  sctlr_el2
        \\        mov     x10, #0x1005                // bits 0 (M), 2 (C), 12 (I)
        \\        bic     x9,  x9,  x10
        \\        msr     sctlr_el2, x9
        \\        dsb     sy
        \\        isb
        \\        ic      iallu
        \\        tlbi    alle2
        \\        dsb     sy
        \\        isb
        \\
        \\        msr     vbar_el2, %[hyp_vbar]
        \\        msr     tpidr_el2, xzr
        \\        isb
        \\
        // -------------------------------------------------------------
        // 4. ERET to EL1h with DAIF masked. Before the eret, write
        //    SP_EL1 = our current (EL2) sp so that after the exception
        //    return, the EL1 CPU (using SP_EL1 because PSTATE.SP=1 via
        //    EL1h) resumes on the exact same C stack frame. Then repoint
        //    the active SP at the dedicated hyp stack — that becomes
        //    SP_EL2 and will be used by any future exception taken to
        //    EL2 (e.g. the kernel's world switch once it reinstalls
        //    its own __hyp_vectors).
        // -------------------------------------------------------------
        \\        mov     x9,  sp
        \\        msr     sp_el1, x9
        \\        msr     sp_el0, xzr
        \\
        \\        mov     sp, %[hyp_sp_top]           // SP_EL2 = hyp_stack_top
        \\
        \\        adr     x9, 1f
        \\        msr     elr_el2, x9
        \\        mov     x9, #0x3C5                  // EL1h + DAIF masked
        \\        msr     spsr_el2, x9
        \\        isb
        \\        eret
        \\1:
        :
        : [hyp_vbar] "r" (hyp_vbar),
          [hyp_sp_top] "r" (hyp_sp_top),
        : .{ .memory = true, .x9 = true, .x10 = true, .x11 = true });
}
