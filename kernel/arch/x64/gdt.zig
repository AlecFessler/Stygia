const stygia = @import("stygia");

const arch_paging = stygia.arch.x64.paging;
const cpu = stygia.arch.x64.cpu;
const memory_init = stygia.memory.init;
const paging = stygia.memory.paging;
const pmm = stygia.memory.pmm;
const stack_mod = stygia.memory.stack;

const MemoryPerms = stygia.memory.address.MemoryPerms;
const PAddr = stygia.memory.address.PAddr;
const PrivilegeLevel = stygia.arch.x64.cpu.PrivilegeLevel;
const VAddr = stygia.memory.address.VAddr;

/// Intel SDM Vol 3A §3.5.1 — GDTR holds base address and limit of the GDT.
const GdtPtr = packed struct {
    limit: u16,
    base: u64,
};

/// Intel SDM Vol 3A §10.7, Figure 10-11 — 64-Bit TSS Format.
/// Hardware task-switching is not supported in 64-bit mode, but a TSS must
/// still exist to provide RSP values for privilege-level changes and IST
/// pointers for the interrupt stack table mechanism (§7.14.5).
pub const Tss = packed struct {
    _res0: u32 = 0,
    /// Stack pointers loaded on privilege-level switches to ring 0-2.
    rsp0: u64 = 0,
    rsp1: u64 = 0,
    rsp2: u64 = 0,
    _res1: u64 = 0,
    /// Interrupt Stack Table entries 1-7 (§7.14.5). IST0 is unused;
    /// a zero IST field in a gate descriptor means "use legacy mechanism."
    ist1: u64 = 0,
    ist2: u64 = 0,
    ist3: u64 = 0,
    ist4: u64 = 0,
    ist5: u64 = 0,
    ist6: u64 = 0,
    ist7: u64 = 0,
    _res2: u64 = 0,
    _res3: u16 = 0,
    /// 16-bit offset from TSS base to the I/O permission bit map.
    iomap_base: u16 = @sizeOf(@This()),
};

/// Intel SDM Vol 3A §3.4.5, Figure 3-8 — Segment Descriptor.
/// Bit layout: base[31:24] | G | D/B | L | AVL | limit[19:16] | P | DPL | S | Type | base[23:16] || base[15:0] | limit[15:0]
/// For code/data segments (S=1), the Type sub-fields are defined in §3.4.5.1, Table 3-1:
///   bit 3 (executable): 0 = data, 1 = code
///   bit 2 (direction/conforming): expand-down (data) or conforming (code)
///   bit 1 (read_write): writable (data) or readable (code)
///   bit 0 (accessed): set by processor on access
const GdtEntry = packed struct(u64) {
    limit_low: u16,
    base_low: u24,
    accessed: bool,
    read_write: bool,
    direction_confirming: bool,
    executable: bool,
    /// S flag — 0 = system segment (TSS/LDT), 1 = code or data segment.
    descriptor: bool,
    privilege: PrivilegeLevel,
    present: bool,
    limit_high: u4,
    _res0: u1 = 0,
    /// L flag — 64-bit code segment when set (must have is_32_bit=0). §3.4.5.
    is_64_bit: bool,
    /// D/B flag — default operation size (0 = 16-bit, 1 = 32-bit). §3.4.5.
    is_32_bit: bool,
    /// G flag — 0 = byte granularity, 1 = 4 KiB granularity. §3.4.5.
    granularity: u1,
    base_high: u8,
};

pub const KERNEL_CODE_OFFSET: u16 = 0x08;
pub const KERNEL_DATA_OFFSET: u16 = 0x10;
/// User data must precede user code for SYSRET segment arithmetic.
/// Intel SDM Vol 2B, SYSRET: SS.Selector = (IA32_STAR[63:48]+8) | 3,
/// CS.Selector = (IA32_STAR[63:48]+16) | 3. This forces user data at +8
/// and user code at +16 relative to the STAR selector base.
pub const USER_DATA_OFFSET: u16 = 0x18;
pub const USER_CODE_OFFSET: u16 = 0x20;
/// Intel SDM Vol 3A §10.2.3, Figure 10-4 — TSS descriptor is 16 bytes
/// in 64-bit mode (occupies two GDT slots).
pub const TSS_OFFSET: u16 = 0x28;

const NULL_SEGMENT: GdtEntry = .{
    .limit_low = 0,
    .base_low = 0,
    .accessed = false,
    .read_write = false,
    .direction_confirming = false,
    .executable = false,
    .descriptor = false,
    .privilege = .ring_0,
    .present = false,
    .limit_high = 0,
    ._res0 = 0,
    .is_64_bit = false,
    .is_32_bit = false,
    .granularity = 0,
    .base_high = 0,
};

const KERNEL_SEGMENT_CODE: GdtEntry = .{
    .limit_low = 0,
    .base_low = 0,
    .accessed = false,
    .read_write = true,
    .direction_confirming = false,
    .executable = true,
    .descriptor = true,
    .privilege = .ring_0,
    .present = true,
    .limit_high = 0,
    ._res0 = 0,
    .is_64_bit = true,
    .is_32_bit = false,
    .granularity = 1,
    .base_high = 0,
};

const KERNEL_SEGMENT_DATA: GdtEntry = .{
    .limit_low = 0,
    .base_low = 0,
    .accessed = false,
    .read_write = true,
    .direction_confirming = false,
    .executable = false,
    .descriptor = true,
    .privilege = .ring_0,
    .present = true,
    .limit_high = 0,
    ._res0 = 0,
    .is_64_bit = false,
    .is_32_bit = false,
    .granularity = 1,
    .base_high = 0,
};

const USER_SEGMENT_CODE: GdtEntry = .{
    .limit_low = 0,
    .base_low = 0,
    .accessed = false,
    .read_write = true,
    .direction_confirming = false,
    .executable = true,
    .descriptor = true,
    .privilege = .ring_3,
    .present = true,
    .limit_high = 0,
    ._res0 = 0,
    .is_64_bit = true,
    .is_32_bit = false,
    .granularity = 1,
    .base_high = 0,
};

const USER_SEGMENT_DATA: GdtEntry = .{
    .limit_low = 0,
    .base_low = 0,
    .accessed = false,
    .read_write = true,
    .direction_confirming = false,
    .executable = false,
    .descriptor = true,
    .privilege = .ring_3,
    .present = true,
    .limit_high = 0,
    ._res0 = 0,
    .is_64_bit = false,
    .is_32_bit = false,
    .granularity = 1,
    .base_high = 0,
};

const MAX_CORES = 64;
const NUM_GDT_ENTRIES: u16 = 7;
const TABLE_SIZE: u16 = @sizeOf(GdtEntry) * NUM_GDT_ENTRIES - 1;

const base_gdt_entries: [7]GdtEntry = blk: {
    var tmp: [7]GdtEntry = undefined;
    tmp[0] = NULL_SEGMENT;
    tmp[1] = KERNEL_SEGMENT_CODE;
    tmp[2] = KERNEL_SEGMENT_DATA;
    tmp[3] = USER_SEGMENT_DATA;
    tmp[4] = USER_SEGMENT_CODE;
    tmp[5] = NULL_SEGMENT;
    tmp[6] = NULL_SEGMENT;
    break :blk tmp;
};

var tss_entries: [MAX_CORES]Tss = [_]Tss{.{}} ** MAX_CORES;
var per_core_gdts: [MAX_CORES][7]GdtEntry = [_][7]GdtEntry{base_gdt_entries} ** MAX_CORES;
var per_core_gdt_ptrs: [MAX_CORES]GdtPtr = [_]GdtPtr{.{ .limit = TABLE_SIZE, .base = 0 }} ** MAX_CORES;

pub fn init() void {
    initForCore(0);
    loadGdt(0);
    reloadSegments();
    cpu.ltr(TSS_OFFSET);
}

pub fn initForCore(core_id: u64) void {
    // `tss_entries` is zero-initialized at module scope; do not reset
    // here so that `initIst` (run after memory init) can populate the
    // IST fields and have them survive a re-entry into `initForCore`
    // from the smpInit per-core loop.
    writeTssDescriptor(core_id);
    // Pointer-index `per_core_gdt_ptrs[]` to avoid Debug-mode
    // codegen copying the array onto the per-core init stack frame.
    // See the matching note in sched.scheduler on `core_states[]`.
    (&per_core_gdt_ptrs[core_id]).base = @intFromPtr(&per_core_gdts[core_id]);
}

/// IST slot assignments (Intel SDM Vol 3A §7.14.5). Each non-IF-gated
/// exception gets its own kernel stack so that the CPU's hardware stack
/// switch cannot scribble onto another in-flight kernel routine's rsp
/// window. Vector → IST index follows the Linux convention.
pub const IST_DOUBLE_FAULT: u3 = 1;
pub const IST_NMI: u3 = 2;
pub const IST_MACHINE_CHECK: u3 = 3;
pub const IST_PAGE_FAULT: u3 = 4;

const IST_KERNEL_PERMS = MemoryPerms{ .read = true, .write = true };

/// Allocate the four IST kernel stacks for `core_id` and write their
/// tops into `tss_entries[core_id].ist1..ist4`. Must run after memory
/// init (PMM + kernel address space) and before the gate's IST index
/// is patched via `idt.setIst`.
///
/// The four stacks are allocated through `stack_mod.createKernel` so
/// they share the kernel-stack guard-page discipline (`isKernelStackPage`
/// detects overflow into the guard during fault handling).
pub fn initIst(core_id: u64) !void {
    const tss = &tss_entries[core_id];

    // No partial cleanup on failure — at boot a `try` failure here is
    // fatal and the caller propagates the error to `kMain`'s panic.
    tss.ist1 = try mapIstStack();
    tss.ist2 = try mapIstStack();
    tss.ist3 = try mapIstStack();
    tss.ist4 = try mapIstStack();
}

/// Allocate one kernel-stack slot, populate it with PMM-backed pages,
/// and return the stack-top virtual address (suitable for direct
/// assignment into a TSS IST field).
fn mapIstStack() !u64 {
    const stack = try stack_mod.createKernel();
    const pmm_mgr = &pmm.global_pmm.?;

    var page_addr = stack.base.addr;
    while (page_addr < stack.top.addr) {
        const kpage = try pmm_mgr.create(paging.PageMem(.page4k));
        const kphys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(kpage)), null);
        try arch_paging.mapPage(
            memory_init.kernel_addr_space_root,
            kphys,
            VAddr.fromInt(page_addr),
            IST_KERNEL_PERMS,
            .kernel_data,
        );
        page_addr += paging.PAGE4K;
    }

    return stack.top.addr;
}

pub fn loadGdt(core_id: u64) void {
    cpu.lgdt(&per_core_gdt_ptrs[core_id]);
}

pub fn coreTss(core_id: u64) *Tss {
    return &tss_entries[core_id];
}

pub fn reloadSegments() void {
    asm volatile (
        \\pushq %[cs_sel]
        \\leaq 1f(%%rip), %%rax
        \\pushq %%rax
        \\lretq
        \\1:
        \\movw %[ds_sel], %%ax
        \\movw %%ax, %%ds
        \\movw %%ax, %%es
        \\movw %%ax, %%ss
        :
        : [cs_sel] "i" (KERNEL_CODE_OFFSET),
          [ds_sel] "i" (KERNEL_DATA_OFFSET),
        : .{ .rax = true, .ax = true, .memory = true });
}

/// Write the 16-byte TSS descriptor into two consecutive GDT slots.
/// Intel SDM Vol 3A §10.2.3, Figure 10-4 — In 64-bit mode the TSS
/// descriptor is 16 bytes: the low 8 bytes follow the standard system-
/// segment format (Table 3-2, type 9 = 64-bit TSS Available), and the
/// high 8 bytes hold base[63:32] with reserved upper bits.
fn writeTssDescriptor(core_id: u64) void {
    const base: u64 = @intFromPtr(&tss_entries[core_id]);
    const limit: u20 = @truncate(@sizeOf(Tss) - 1);

    const tss_low_idx: u64 = @intCast((TSS_OFFSET >> 3));
    const tss_high_idx: u64 = tss_low_idx + 1;

    var low: GdtEntry = NULL_SEGMENT;
    low.limit_low = @truncate(limit);
    low.limit_high = @truncate(limit >> 16);
    low.base_low = @truncate(base);
    low.base_high = @truncate(base >> 24);
    low.accessed = true;
    low.read_write = false;
    low.direction_confirming = false;
    low.executable = true;
    low.descriptor = false;
    low.privilege = .ring_0;
    low.present = true;
    low.is_64_bit = false;
    low.is_32_bit = false;
    low.granularity = 0;

    per_core_gdts[core_id][tss_low_idx] = low;

    const raw: *[7]u64 = @ptrCast(&per_core_gdts[core_id]);
    raw[tss_high_idx] = base >> 32;
}
