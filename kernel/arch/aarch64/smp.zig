//! AArch64 SMP (Symmetric Multi-Processing) initialization via PSCI.
//!
//! ARM secondary core bringup uses PSCI CPU_ON, which is fundamentally
//! different from x86's INIT-SIPI-SIPI sequence. PSCI takes a target MPIDR
//! and a physical entry point address, and firmware brings the core to that
//! entry in EL1 with the MMU off.
//!
//! Because the secondary starts with MMU disabled, a trampoline is needed
//! to configure TTBR0 (identity mapping), TTBR1 (kernel mapping), TCR,
//! MAIR, and SCTLR before jumping to kernel VA code. This is analogous
//! to Linux's __secondary_switch / __enable_mmu sequence (arch/arm64/kernel/head.S).
//!
//! Boot sequence:
//! 1. BSP discovers cores from ACPI MADT GIC CPU Interface structures.
//! 2. BSP creates a minimal identity mapping (TTBR0) covering the trampoline PA.
//! 3. BSP captures system register state (TCR, MAIR, SCTLR, TTBR1, VBAR).
//! 4. For each secondary core:
//!    a. Allocate a per-core kernel stack.
//!    b. Fill SecondaryBootParams with stack VA and core index.
//!    c. Call PSCI CPU_ON with the trampoline PA as entry and params PA
//!       as context_id (delivered in x0).
//!    d. Trampoline enables MMU, then branches to kernel VA secondarySetup.
//!
//! PSCI CPU_ON return values (DEN0022D, Table 10):
//!   0            = SUCCESS
//!   -1           = NOT_SUPPORTED
//!   -2           = INVALID_PARAMETERS
//!   -4           = ALREADY_ON
//!   -5           = ON_PENDING
//!   -9           = INTERNAL_FAILURE
//!
//! References:
//! - ARM DEN 0022D: PSCI 1.1, Section 5.4 (CPU_ON)
//! - ACPI 6.5, Table 5-45: MADT GIC CPU Interface Structure
//! - ARM ARM D13.2.118: SCTLR_EL1
//! - ARM ARM D13.2.131: TCR_EL1
//! - ARM ARM D13.2.97: MAIR_EL1
//! - ARM ARM D13.2.136: TTBR0_EL1, TTBR1_EL1

const std = @import("std");
const zag = @import("zag");

// Module aliases — alphabetical
const aarch64_paging = zag.arch.aarch64.paging;
const cpu = zag.arch.aarch64.cpu;
const gic = zag.arch.aarch64.gic;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const power = zag.arch.aarch64.power;
const sched = zag.sched.scheduler;
const stack_mod = zag.memory.stack;

// Type aliases — alphabetical
const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageEntry = aarch64_paging.PageEntry;
const VAddr = zag.memory.address.VAddr;

/// Maximum number of cores supported.
const MAX_CORES: usize = 256;

/// MPIDR affinity values for each core, indexed by logical core ID.
/// Populated by ACPI MADT parsing (GIC CPU Interface structures, ACPI 6.5 Table 5-45).
/// Entry 0 is the BSP; entries 1..N-1 are secondary cores.
var mpidr_table: [MAX_CORES]u64 = [_]u64{0} ** MAX_CORES;

/// Whether each MPIDR entry has been set by ACPI parsing.
var mpidr_valid: [MAX_CORES]bool = [_]bool{false} ** MAX_CORES;

/// Number of secondary cores successfully brought online.
var cores_online: std.atomic.Value(u32) = std.atomic.Value(u32).init(1);

const KERNEL_PERMS = MemoryPerms{ .read = true, .write = true };

/// Boot parameters passed to secondary cores via PSCI context_id (x0).
/// The secondary reads this struct at its physical address with MMU off,
/// then uses the values to configure system registers and enable the MMU.
///
/// Field offsets must match the assembly in secondaryEntry exactly.
const SecondaryBootParams = extern struct {
    ttbr0: u64, // offset 0:  Identity mapping page table PA (TTBR0_EL1)
    ttbr1: u64, // offset 8:  Kernel page table PA (TTBR1_EL1)
    tcr: u64, // offset 16: TCR_EL1 value
    mair: u64, // offset 24: MAIR_EL1 value
    sctlr: u64, // offset 32: SCTLR_EL1 value (MMU enabled)
    sp: u64, // offset 40: Stack pointer (kernel VA, 16-byte aligned)
    entry: u64, // offset 48: secondarySetup function pointer (kernel VA)
    core_idx: u64, // offset 56: Logical core index
    vbar: u64, // offset 64: VBAR_EL1 value (exception vector table)
};

/// Boot params — static global, PA resolved via page table walk.
/// Using a static avoids potential PMM/physmap VA→PA translation issues.
var boot_params_storage: SecondaryBootParams align(64) = std.mem.zeroes(SecondaryBootParams);
var boot_params_pa: u64 = 0;

/// Store the MPIDR affinity value for a core. Called by ACPI MADT parsing
/// when processing GIC CPU Interface structures (ACPI 6.5, Table 5-45).
///
/// The MPIDR value contains the affinity fields (Aff3:Aff2:Aff1:Aff0) that
/// uniquely identify the core for PSCI CPU_ON calls.
pub fn setMpidr(core_idx: usize, mpidr: u64) void {
    if (core_idx >= MAX_CORES) return;
    mpidr_table[core_idx] = mpidr;
    mpidr_valid[core_idx] = true;
}

/// Get the MPIDR for a core index. Returns null if not set by ACPI.
/// Falls back to flat topology derivation (Aff0 = core_idx) if ACPI
/// did not populate the table.
fn getMpidr(core_idx: usize) u64 {
    if (core_idx >= MAX_CORES) return core_idx;
    if (mpidr_valid[core_idx]) return mpidr_table[core_idx];
    // Fallback: flat topology where MPIDR Aff0 = core index.
    // This works for simple platforms (e.g., QEMU virt) but not
    // for real hardware with multi-cluster topologies.
    return core_idx;
}

// ── System register readers ─────────────────────────────────────────────

/// ARM ARM D13.2.131: TCR_EL1 — Translation Control Register.
fn readTcr() u64 {
    return asm volatile ("mrs %[ret], tcr_el1"
        : [ret] "=r" (-> u64),
    );
}

/// ARM ARM D13.2.97: MAIR_EL1 — Memory Attribute Indirection Register.
fn readMair() u64 {
    return asm volatile ("mrs %[ret], mair_el1"
        : [ret] "=r" (-> u64),
    );
}

/// ARM ARM D13.2.118: SCTLR_EL1 — System Control Register.
fn readSctlr() u64 {
    return asm volatile ("mrs %[ret], sctlr_el1"
        : [ret] "=r" (-> u64),
    );
}

/// ARM ARM D1.10.2: VBAR_EL1 — Vector Base Address Register.
fn readVbar() u64 {
    return asm volatile ("mrs %[ret], vbar_el1"
        : [ret] "=r" (-> u64),
    );
}

// ── Identity mapping ────────────────────────────────────────────────────

/// Create a minimal identity mapping for the trampoline's physical address
/// and the first 1GB (containing PL011 UART at PA 0x09000000).
///
/// Allocates two pages: an L0 (PGD) table and an L1 (PUD) table. The L1
/// table contains 1GB block descriptors that identity-map the GB containing
/// the trampoline PA as Normal memory, and the [0, 1GB) range as Device
/// memory (for PL011 UART access via earlyDebugChar).
///
/// This identity mapping is loaded into TTBR0_EL1 on the secondary so that
/// after the MMU is enabled, instruction fetch continues at the same PA
/// and early debug output via PL011 at 0x09000000 still works.
///
/// ARM ARM D5.3, Table D5-15: Level 1 block descriptors map 1GB regions.
fn createIdentityMapping(trampoline_pa: u64) !u64 {
    const pmm_mgr = &pmm.global_pmm.?;

    // Allocate L0 table (PGD) — comes back already zeroed from the PMM.
    const l0_page = try pmm_mgr.create(paging.PageMem(.page4k));
    const l0_va = @intFromPtr(l0_page);
    const l0_pa = PAddr.fromVAddr(VAddr.fromInt(l0_va), null).addr;

    // Allocate L1 table (PUD) — comes back already zeroed from the PMM.
    const l1_page = try pmm_mgr.create(paging.PageMem(.page4k));
    const l1_va = @intFromPtr(l1_page);
    const l1_pa = PAddr.fromVAddr(VAddr.fromInt(l1_va), null).addr;

    // L0 table descriptor pointing to L1.
    // ARM ARM D5.3: Table descriptor at level 0 — bits [1:0] = 0b11.
    const l0_idx: usize = @intCast(trampoline_pa >> 39);
    const l0_table: *[512]PageEntry = @ptrFromInt(l0_va);
    var l0_entry = PageEntry{
        .valid = true,
        .is_table = true,
        .af = true,
    };
    l0_entry.setPAddr(PAddr.fromInt(l1_pa));
    l0_table[l0_idx] = l0_entry;

    const l1_table: *[512]PageEntry = @ptrFromInt(l1_va);

    // L1 block descriptor: 1GB identity mapping for the trampoline code.
    // ARM ARM D5.3: Block descriptor at level 1 — bits [1:0] = 0b01.
    // AttrIndx=1 (Normal WB, matching our MAIR layout).
    const l1_idx: usize = @intCast((trampoline_pa >> 30) & 0x1FF);
    const block_pa = trampoline_pa & ~@as(u64, 0x3FFFFFFF); // 1GB aligned
    var l1_entry = PageEntry{
        .valid = true,
        .is_table = false, // Block descriptor, not table
        .attr_indx = aarch64_paging.mair_normal, // Normal Write-Back
        .ap = 0b00, // EL1 RW, EL0 no access
        .sh = 0b11, // Inner Shareable
        .af = true, // Access Flag set
    };
    l1_entry.setPAddr(PAddr.fromInt(block_pa));
    l1_table[l1_idx] = l1_entry;

    // Also identity-map [0, 1GB) as Device memory so earlyDebugChar can
    // write to PL011 at PA 0x09000000 after the secondary enables MMU.
    // On QEMU virt, the [0, 1GB) range contains MMIO devices, not RAM.
    if (l1_idx != 0) {
        var dev_entry = PageEntry{
            .valid = true,
            .is_table = false, // Block descriptor
            .attr_indx = aarch64_paging.mair_device, // Device-nGnRnE
            .ap = 0b00, // EL1 RW, EL0 no access
            .sh = 0b00, // Non-shareable (device memory)
            .af = true, // Access Flag set
            .xn = true, // Execute Never (device MMIO)
            .pxn = true, // Privileged Execute Never
        };
        dev_entry.setPAddr(PAddr.fromInt(0));
        l1_table[0] = dev_entry;
    }

    // The secondary core reads these pages with the MMU disabled, which on
    // AArch64 is Normal Non-Cacheable. Clean the two table pages to the
    // Point of Coherency so the secondary sees the descriptors we just wrote.
    // ARM ARM D5.9: DC CVAC + DSB ISH makes cacheable stores visible to
    // non-cacheable observers at PoC.
    const page_size = paging.PAGE4K;
    var clean_va: u64 = l0_va;
    while (clean_va < l0_va + page_size) {
        asm volatile ("dc cvac, %[va]"
            :
            : [va] "r" (clean_va),
            : .{ .memory = true });
        clean_va += 64;
    }
    clean_va = l1_va;
    while (clean_va < l1_va + page_size) {
        asm volatile ("dc cvac, %[va]"
            :
            : [va] "r" (clean_va),
            : .{ .memory = true });
        clean_va += 64;
    }
    asm volatile ("dsb ish" ::: .{ .memory = true });

    return l0_pa;
}

/// Boot all secondary cores discovered by ACPI via PSCI CPU_ON.
///
/// For each secondary core (1..N-1):
/// 1. Allocate and map a per-core kernel stack.
/// 2. Issue PSCI CPU_ON with the core's MPIDR and the trampoline entry point.
/// 3. Wait for the core to signal it is online.
///
/// DEN0022D, Section 5.1.4: CPU_ON takes target_mpidr, entry_point, context_id.
/// The entry_point is the physical address of secondaryEntry; context_id carries
/// the physical address of SecondaryBootParams so the secondary can configure
/// its MMU before accessing kernel VA code.
///
pub fn smpInit() !void {
    try smpInitFull();
}

fn smpInitFull() !void {
    const core_count = gic.coreCount();
    const pmm_mgr = &pmm.global_pmm.?;

    // Resolve the trampoline's physical address. secondaryEntry is linked at
    // a kernel VA (TTBR1 range) — walk the kernel page tables to find the PA
    // that PSCI needs for the entry_point argument.
    const entry_vaddr = @intFromPtr(&secondaryEntry);
    const entry_page_paddr = aarch64_paging.resolveVaddr(
        memory_init.kernel_addr_space_root,
        VAddr.fromInt(entry_vaddr),
    ) orelse return;
    const entry_paddr = entry_page_paddr.addr | (entry_vaddr & 0xFFF);

    // Create a minimal identity mapping so the trampoline can still execute
    // after enabling the MMU (TTBR0 maps the trampoline PA as VA == PA).
    const idmap_ttbr0 = createIdentityMapping(entry_paddr) catch return;

    // Resolve the PA of the static boot params struct by walking the
    // kernel page tables. This avoids relying on physmap VA→PA arithmetic
    // which may produce a PA the secondary can't read with MMU off.
    const params_vaddr = @intFromPtr(&boot_params_storage);
    const params_page_paddr = aarch64_paging.resolveVaddr(
        memory_init.kernel_addr_space_root,
        VAddr.fromInt(params_vaddr),
    ) orelse return;
    boot_params_pa = params_page_paddr.addr | (params_vaddr & 0xFFF);

    // Capture BSP system register state for secondaries.
    //
    // The TTBR1 page-table hierarchy lives in kernel memory and has been
    // touched by the BSP under its live MMU with TCR walker attrs
    // IRGN1/ORGN1 = Normal WB cacheable. Those dirty lines sit in the
    // BSP's caches and are *not* guaranteed to be visible to a freshly
    // powered secondary whose HW table walker does a cached fetch —
    // especially on TCG, which models inner-shareable snoop only
    // loosely. Force the secondary's walker to bypass caches entirely
    // by clearing IRGN1/ORGN1/IRGN0/ORGN0 and SH0/SH1 so the tables are
    // read directly from the PoC. The TCR the BSP keeps running under
    // is unchanged. ARM ARM D13.2.131 — TCR_EL1.{IRGN,ORGN,SH}.
    boot_params_storage.ttbr0 = idmap_ttbr0;
    boot_params_storage.ttbr1 = aarch64_paging.readTtbr1();
    var tcr_for_ap: u64 = readTcr();
    // IRGN0/ORGN0/SH0 at bits [13:8], IRGN1/ORGN1/SH1 at bits [29:24].
    tcr_for_ap &= ~@as(u64, (0x3F << 8) | (0x3F << 24));
    // Leave SH=0 (non-shareable), IRGN/ORGN=0b00 (Normal NC).
    boot_params_storage.tcr = tcr_for_ap;
    boot_params_storage.mair = readMair();
    boot_params_storage.sctlr = readSctlr();
    boot_params_storage.entry = @intFromPtr(&secondarySetup);
    boot_params_storage.vbar = readVbar();

    // Flush the params to main memory so the secondary can read them
    // with MMU off. DC CVAC cleans the cache line to the Point of Coherency.
    var clean_addr = params_vaddr;
    while (clean_addr < params_vaddr + @sizeOf(SecondaryBootParams)) {
        asm volatile ("dc cvac, %[va]"
            :
            : [va] "r" (clean_addr),
            : .{ .memory = true });
        clean_addr += 64;
    }
    asm volatile ("dsb ish" ::: .{ .memory = true });

    // PSCI conduit (SMC vs HVC) was selected from the FADT ARM Boot
    // Architecture Flags during ACPI parsing. See acpi.zig parseFadt
    // and ACPI 6.5, Section 5.2.9, Table 5-34.

    var core_idx: usize = 1;
    while (core_idx < core_count) {
        const target_mpidr = getMpidr(core_idx);

        // Allocate a kernel stack for this secondary core.
        const ap_stack = stack_mod.createKernel() catch {
            core_idx += 1;
            continue;
        };

        // Map physical pages for the stack.
        var page_addr = ap_stack.base.addr;
        var map_ok = true;
        while (page_addr < ap_stack.top.addr) {
            const kpage = pmm_mgr.create(paging.PageMem(.page4k)) catch {
                map_ok = false;
                break;
            };
            const kphys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(kpage)), null);
            aarch64_paging.mapPage(memory_init.kernel_addr_space_root, kphys, VAddr.fromInt(page_addr), KERNEL_PERMS, .kernel_data) catch {
                pmm_mgr.destroy(kpage);
                map_ok = false;
                break;
            };
            page_addr += paging.PAGE4K;
        }

        if (!map_ok) {
            stack_mod.destroyKernel(ap_stack, memory_init.kernel_addr_space_root);
            core_idx += 1;
            continue;
        }

        // Fill in per-core boot params. AArch64 requires 16-byte stack
        // alignment (AAPCS64, Section 6.2.2).
        boot_params_storage.sp = cpu.alignStack(ap_stack.top).addr;
        boot_params_storage.core_idx = core_idx;

        // Flush the updated params to main memory so the secondary can
        // read them with MMU off (non-cacheable access).
        {
            const pva = @intFromPtr(&boot_params_storage);
            var ca = pva;
            while (ca < pva + @sizeOf(SecondaryBootParams)) {
                asm volatile ("dc cvac, %[va]"
                    :
                    : [va] "r" (ca),
                    : .{ .memory = true });
                ca += 64;
            }
        }
        asm volatile ("dsb ish" ::: .{ .memory = true });

        // DEN0022D, Section 5.1.4: CPU_ON — context_id (x3) is passed to the
        // target core in x0. We pass the PA of the boot params struct.
        const expected = cores_online.load(.acquire);
        const ret = power.cpuOn(target_mpidr, entry_paddr, boot_params_pa);

        if (ret != 0) {
            // CPU_ON failed — clean up the stack.
            stack_mod.destroyKernel(ap_stack, memory_init.kernel_addr_space_root);
            core_idx += 1;
            continue;
        }

        // Spin-wait for the secondary to signal it is online.
        //
        // PSCI CPU_ON is asynchronous (DEN0022D §5.1.4): a SUCCESS
        // return only confirms that the firmware accepted the
        // request, not that the target core has begun executing the
        // entry point. The actual wakeup latency depends on whether
        // the core was previously powered down or just halted in
        // WFI; on a real Cortex-A76 + KVM (Pi 5) we have measured
        // several milliseconds before the AP increments
        // `cores_online`.
        //
        // The previous 500 k-iteration cap completed in microseconds
        // on KVM — well under the AP's startup latency — and was the
        // actual cause of "secondaries deaf to interrupts" on Pi 5:
        // the BSP gave up before the AP could ack, then started
        // `cpuOn(core_idx + 1)` while the previous AP was still
        // setting up its GIC CPU interface, so the AP missed the
        // first scheduler tick and the workaround broadcast (SGI 7)
        // could not run on a vGICv2 view that was never enabled.
        // 50 M iterations is ~tens of milliseconds on Cortex-A76 and
        // hundreds of milliseconds on TCG, well above any realistic
        // PSCI CPU_ON latency.
        var spin_count: u64 = 0;
        const max_spins: u64 = 50_000_000;
        while (cores_online.load(.acquire) == expected) {
            if (spin_count >= max_spins) {
                stack_mod.destroyKernel(ap_stack, memory_init.kernel_addr_space_root);
                break;
            }
            std.atomic.spinLoopHint();
            spin_count += 1;
        }

        core_idx += 1;
    }
}

/// Secondary core MMU-enable trampoline (naked).
///
/// Called by firmware after PSCI CPU_ON with MMU off. x0 holds the
/// physical address of SecondaryBootParams (passed as context_id).
///
/// DEN0022D, Section 5.1.4: The target core begins execution at the entry
/// point address with context_id in x0, in AArch64 at the caller's EL
/// with MMU off. On QEMU `-M virt,virtualization=on`, CPU_ON ignores the
/// caller EL and delivers the secondary at EL2 even when the BSP called
/// from EL1; the trampoline detects EL2 at entry and drops to EL1h via
/// ERET before programming any EL1 sysreg.
///
/// The trampoline:
/// 1. Drops to EL1h if still at EL2.
/// 2. Loads all boot params from the struct at PA in x0.
/// 3. Configures MAIR, TCR, TTBR0 (identity mapping), TTBR1 (kernel),
///    VBAR, TLB, CPACR, I-cache.
/// 4. Enables the MMU via SCTLR_EL1.
/// 5. Sets SP and branches to secondarySetup at its kernel VA.
fn secondaryEntry() callconv(.naked) noreturn {
    asm volatile (
    // x0 = PA of SecondaryBootParams (from PSCI context_id).
    // MMU is off — all memory access uses physical addresses and is
    // treated as Normal Non-Cacheable (ARM ARM D5.2.9).
    //
    // Mask DAIF (SError, IRQ, FIQ, Debug). We do not want any
    // interrupt delivered while the MMU is off and VBAR still
    // points where firmware left it.
        \\msr daifset, #0xF
        \\
        // PSCI CPU_ON is *supposed* to bring the target CPU up at
        // the same EL as the caller (DEN0022D §5.1.4), but on QEMU's
        // `-M virt,virtualization=on` the PSCI firmware brings
        // secondaries online at EL2 regardless of caller EL — the
        // BSP transitioned EL2→EL1 inside the bootloader before
        // calling CPU_ON, so each secondary now lands at EL2 while
        // our sysreg programming below (SCTLR_EL1, TTBR*_EL1,
        // TCR_EL1, …) configures stage-1 translation for EL1&0. If
        // we stay at EL2 the EL1 MMU is never consulted, and the BR
        // to a TTBR1 kernel VA data-aborts at EL2 into VBAR_EL2=0
        // with no vector installed (and no output). Detect EL2 at
        // entry and ERET down to EL1h before touching any EL1
        // sysreg. ARM ARM D1.9 — SPSR_EL2 / ELR_EL2; D13.2.48 —
        // HCR_EL2.RW; D13.2.27 — CNTHCTL_EL2; D13.2.33 — CPTR_EL2.
        \\mrs x12, CurrentEL
        \\lsr x12, x12, #2
        \\cmp x12, #2
        \\b.ne 1f
        \\
        // HCR_EL2.RW=1 so EL1 runs AArch64.
        \\mov x12, #(1 << 31)
        \\msr hcr_el2, x12
        \\
        // Let EL1 access the physical counter/timer without trapping.
        \\mrs x12, cnthctl_el2
        \\orr x12, x12, #(3 << 0)
        \\msr cnthctl_el2, x12
        \\msr cntvoff_el2, xzr
        \\
        // Don't trap FP/SIMD to EL2.
        \\mov x12, #0x33ff
        \\msr cptr_el2, x12
        \\msr hstr_el2, xzr
        \\
        // ELR_EL2 = label 1f (next instruction after the ERET).
        // SPSR_EL2 = EL1h with DAIF masked (0x3c5).
        \\adr x12, 1f
        \\msr elr_el2, x12
        \\mov x12, #0x3c5
        \\msr spsr_el2, x12
        \\isb
        \\eret
        \\1:
        \\
        // Load all params into registers before touching system registers.
        // SecondaryBootParams layout: ttbr0(0), ttbr1(8), tcr(16), mair(24),
        // sctlr(32), sp(40), entry(48), core_idx(56), vbar(64).
        \\ldp x1, x2, [x0, #0]
        \\ldp x3, x4, [x0, #16]
        \\ldp x5, x6, [x0, #32]
        \\ldp x7, x8, [x0, #48]
        \\ldr x9, [x0, #64]
        \\
        // Configure memory attributes (ARM ARM D13.2.97).
        \\msr mair_el1, x4
        \\
        // Configure translation control (ARM ARM D13.2.131).
        \\msr tcr_el1, x3
        \\
        // Install page tables (ARM ARM D13.2.136).
        // TTBR0: identity mapping (VA == PA for this trampoline).
        // TTBR1: kernel mapping (same as BSP).
        \\msr ttbr0_el1, x1
        \\msr ttbr1_el1, x2
        \\
        // Install the kernel's EL1 exception vector so any fault
        // after MMU enable is reported via the normal kernel vector
        // table. ARM ARM D13.2.143 — VBAR_EL1.
        \\msr vbar_el1, x9
        \\isb
        \\
        // Invalidate local TLB for EL1&0 to drop any stale entries
        // inherited from firmware. ARM ARM D5.10.2.
        \\tlbi vmalle1
        \\dsb nsh
        \\isb
        \\
        // Enable Advanced SIMD / FP at EL0 + EL1 (CPACR_EL1.FPEN = 0b11).
        // PSCI CPU_ON hands the secondary off with CPACR_EL1 at its reset
        // value (on real hardware this traps all FP/SIMD). LLVM emits
        // q-register accesses for ordinary 16-byte struct copies inside
        // Zig code, so FPEN must be on before any kernel-VA Zig call.
        // ARM ARM D13.2.30 — CPACR_EL1, bits [21:20].
        \\mrs x12, cpacr_el1
        \\orr x12, x12, #(3 << 20)
        \\msr cpacr_el1, x12
        \\isb
        \\
        // Invalidate local I-cache so any stale lines from PSCI reset
        // do not shadow the freshly-programmed page tables once the
        // MMU turns on. ARM ARM D8.11.1 — IC IALLU affects only the
        // local PE.
        \\ic iallu
        \\dsb ish
        \\isb
        \\
        // Enable MMU. SCTLR_EL1 from the BSP already has M|C|I set.
        \\msr sctlr_el1, x5
        \\isb
        \\
        // MMU is on. PC is still at the trampoline's PA, which is
        // identity-mapped via TTBR0. Set the kernel stack, place the
        // core index in x0 for the C-ABI call, and branch to
        // secondarySetup at its kernel VA (resolved via TTBR1).
        \\mov sp, x6
        \\mov x0, x8
        \\br x7
    );
}

/// Secondary core setup after MMU is enabled and stack is established.
/// Called from secondaryEntry with core_idx in x0, running at kernel VA.
fn secondarySetup(core_idx: u64) callconv(.c) noreturn {
    // Initialize the GIC redistributor and CPU interface for this core.
    // This MUST complete before we increment `cores_online`: the BSP
    // moves on to the next CPU_ON (and ultimately to perCoreInit /
    // armSchedTimer) as soon as the counter advances, and any IRQ it
    // routes here before our GIC CPU interface is enabled would be
    // silently dropped. ARM IHI 0048B §4.4.1 (GICC_CTLR) — the CPU
    // interface only forwards interrupts after `Enable` is set.
    gic.initSecondaryCoreGic(@intCast(core_idx));

    // Signal to the BSP that this core is online. The release store
    // is paired with the BSP's acquire load in `smpInitFull`.
    _ = cores_online.fetchAdd(1, .release);

    // Initialize per-core scheduler state (idle thread, running thread).
    sched.perCoreInit();

    // Enter the idle loop.
    cpu.halt();
}
