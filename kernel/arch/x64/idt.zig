const std = @import("std");
const zag = @import("zag");

const cpu = zag.arch.x64.cpu;

const PrivilegeLevel = zag.arch.x64.cpu.PrivilegeLevel;

/// Intel SDM Vol 3A, Table 3-2 — System-Segment and Gate-Descriptor Types.
/// In IA-32e mode: 0xE = 64-bit Interrupt Gate, 0xF = 64-bit Trap Gate.
/// Task gates (0x5) are reserved/unsupported in IA-32e mode.
pub const GateType = enum(u4) {
    task_gate = 0x5,
    interrupt_gate = 0xE,
    trap_gate = 0xF,
};

/// Intel SDM Vol 3A §7.14.1, Figure 7-8 — 64-Bit IDT Gate Descriptor.
/// Each entry is 16 bytes (128 bits), holding a full 64-bit offset to
/// the interrupt service routine and an IST index for stack switching.
/// The IDT index is formed by scaling the interrupt vector by 16 (§7.10).
const IDTEntry = packed struct(u128) {
    isr_base_low: u16,
    code_segment: u16,
    /// Interrupt Stack Table index (§7.14.5). 0 = use legacy stack switch.
    ist: u3 = 0,
    _res0: u5 = 0,
    gate_type: GateType,
    /// Must be 0 for interrupt/trap gates in IA-32e mode.
    storage_segment: u1,
    privilege: PrivilegeLevel,
    present: bool,
    isr_base_mid: u16,
    isr_base_high: u32,
    _res1: u32 = 0,
};

/// Intel SDM Vol 3A §7.10, Figure 7-1 — IDTR holds base and limit of the IDT.
const IDTPtr = packed struct {
    limit: u16,
    base: u64,
};

pub const interruptHandler = *const fn () callconv(.naked) void;

/// Intel SDM Vol 3A §7.10 — The IDT can contain up to 256 entries,
/// one per interrupt/exception vector.
const num_idt_entries: u64 = 256;
const table_size: u16 = @sizeOf(IDTEntry) * num_idt_entries - 1;

var idt: [num_idt_entries]IDTEntry = [_]IDTEntry{.{
    .isr_base_low = 0,
    .code_segment = 0,
    .gate_type = .interrupt_gate,
    .storage_segment = 0,
    .privilege = .ring_0,
    .present = false,
    .isr_base_mid = 0,
    .isr_base_high = 0,
}} ** num_idt_entries;

pub var idt_ptr: IDTPtr = .{
    .limit = table_size,
    .base = 0,
};

pub fn init() void {
    idt_ptr.base = @intFromPtr(&idt);
    cpu.lidt(&idt_ptr);
}

pub fn openInterruptGate(
    int_num: u8,
    handler: interruptHandler,
    code_segment: u16,
    privilege: PrivilegeLevel,
    gate_type: GateType,
) void {
    std.debug.assert(int_num < num_idt_entries);
    std.debug.assert(idt[int_num].present == false);

    const addr = @intFromPtr(handler);

    idt[int_num] = .{
        .isr_base_low = @truncate(addr),
        .code_segment = code_segment,
        .gate_type = gate_type,
        .storage_segment = 0,
        .privilege = privilege,
        .present = true,
        .isr_base_mid = @truncate(addr >> 16),
        .isr_base_high = @truncate(addr >> 32),
    };
}

/// Patch the IST index on an existing gate descriptor. Intel SDM Vol 3A
/// §7.14.5 — when the IST field is non-zero, the CPU unconditionally
/// loads RSP from `TSS.IST[N]` before pushing the iret frame, regardless
/// of the rsp value at the time of the exception. Used to give #PF, #NMI,
/// #MC, and #DF private kernel stacks so they cannot scribble over an
/// in-progress kernel routine's rsp window (e.g., the L4 IPC fast path
/// running with rsp at ec.kstack.top, where ec.ctx is one frame below).
pub fn setIst(int_num: u8, ist_index: u3) void {
    std.debug.assert(int_num < num_idt_entries);
    std.debug.assert(idt[int_num].present);
    idt[int_num].ist = ist_index;
}
