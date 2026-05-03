/// MMIO instruction decoder for x86-64 long mode.
/// Decodes MOV instructions at guest RIP to emulate LAPIC/IOAPIC MMIO.
/// Handles the instruction patterns Linux writel()/readl() compile to.
///
/// Supported opcodes:
///   0x89 MOV r/m32, r32    (MMIO write from register)
///   0x8B MOV r32, r/m32    (MMIO read to register)
///   0xC7 MOV r/m32, imm32  (MMIO write immediate)
///   0x88 MOV r/m8, r8      (MMIO write byte)
///   0x8A MOV r8, r/m8      (MMIO read byte)
///
/// Guest virtual -> physical translation via the guest's CR3 page-table
/// walk; guest physical memory is read through the kernel physmap (SMAP
/// does not gate kernel-mode VAs).
const zag = @import("zag");

const virtual_machine = zag.hv.virtual_machine;

const GuestState = zag.arch.x64.vm.GuestState;
const VirtualMachine = zag.hv.virtual_machine.VirtualMachine;

/// Result of decoding an MMIO instruction.
pub const MmioOp = struct {
    is_write: bool,
    size: u8, // 1, 2, or 4 bytes
    reg: u4, // GPR index (destination for reads, source for register writes)
    value: u32, // Write value (from register or immediate)
    len: u8, // Total instruction length for RIP advancement
    is_immediate: bool = false, // true for MOV imm (0xC7), false for register-source writes
};

pub const DecodeError = error{
    UnsupportedInstruction,
    IncompleteDecode,
};

// --- Guest virtual -> physical page table walk ---

/// Translate guest virtual address to guest physical using CR3 4-level
/// paging. Intel SDM Vol 3A §4.5 / AMD APM Vol 2 §5.3.
/// Reads guest page-table entries via the VM's `installs[]` mapping.
fn guestVirtToPhys(vm: *const VirtualMachine, cr3: u64, vaddr: u64) ?u64 {
    const pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;
    const pml4_idx = (vaddr >> 39) & 0x1FF;
    const pml4e = readGuestPhysU64(vm, pml4_base + pml4_idx * 8) orelse return null;
    if (pml4e & 1 == 0) return null;

    const pdpt_base = pml4e & 0x000F_FFFF_FFFF_F000;
    const pdpt_idx = (vaddr >> 30) & 0x1FF;
    const pdpte = readGuestPhysU64(vm, pdpt_base + pdpt_idx * 8) orelse return null;
    if (pdpte & 1 == 0) return null;
    if (pdpte & 0x80 != 0) // 1 GiB page
        return (pdpte & 0x000F_FFFF_C000_0000) | (vaddr & 0x3FFF_FFFF);

    const pd_base = pdpte & 0x000F_FFFF_FFFF_F000;
    const pd_idx = (vaddr >> 21) & 0x1FF;
    const pde = readGuestPhysU64(vm, pd_base + pd_idx * 8) orelse return null;
    if (pde & 1 == 0) return null;
    if (pde & 0x80 != 0) // 2 MiB page
        return (pde & 0x000F_FFFF_FFE0_0000) | (vaddr & 0x1F_FFFF);

    const pt_base = pde & 0x000F_FFFF_FFFF_F000;
    const pt_idx = (vaddr >> 12) & 0x1FF;
    const pte = readGuestPhysU64(vm, pt_base + pt_idx * 8) orelse return null;
    if (pte & 1 == 0) return null;

    return (pte & 0x000F_FFFF_FFFF_F000) | (vaddr & 0xFFF);
}

/// Read a u64 from guest physical memory through the VM's `installs[]`
/// bookkeeping. The host pointer returned by `guestPhysToHost` is a
/// kernel-mode physmap VA, so the dereference does not need SMAP
/// bracketing.
fn readGuestPhysU64(vm: *const VirtualMachine, phys: u64) ?u64 {
    const ptr = virtual_machine.guestPhysToHost(vm, phys, 8) orelse return null;
    const u64_ptr: *const align(1) u64 = @ptrCast(ptr);
    return u64_ptr.*;
}

/// Fetch up to 15 instruction bytes from guest virtual address `rip`,
/// crossing a page boundary if needed. Returns the number of bytes
/// actually fetched, or null if neither half of the fetch translates.
fn fetchInsn(vm: *const VirtualMachine, cr0: u64, cr3: u64, rip: u64, buf: *[15]u8) ?u8 {
    // CR0.PG=0 ⇒ guest virtual = guest physical (paging disabled).
    const phys = if (cr0 & (1 << 31) == 0) rip else (guestVirtToPhys(vm, cr3, rip) orelse return null);
    const page_off = phys & 0xFFF;
    const avail: u64 = 4096 - page_off;
    const first: u8 = @intCast(@min(15, avail));

    const slice_ptr = virtual_machine.guestPhysToHost(vm, phys, first) orelse return null;
    @memcpy(buf[0..first], slice_ptr[0..first]);

    if (first < 15) {
        const next_vaddr = (rip & ~@as(u64, 0xFFF)) + 4096;
        const next_phys = if (cr0 & (1 << 31) == 0) next_vaddr else (guestVirtToPhys(vm, cr3, next_vaddr) orelse return first);
        const remaining: u8 = 15 - first;
        if (virtual_machine.guestPhysToHost(vm, next_phys, remaining)) |next_ptr| {
            @memcpy(buf[first..15], next_ptr[0..remaining]);
            return 15;
        }
        return first;
    }
    return first;
}

/// Decode the MMIO instruction at guest RIP. Wraps `fetchInsn` +
/// `decodeBytes`; for register-source writes, fills in `value` from the
/// matching guest GPR so the caller doesn't have to read it again.
pub fn decode(vm: *const VirtualMachine, gs: *const GuestState) ?MmioOp {
    var insn: [15]u8 = undefined;
    const fetched = fetchInsn(vm, gs.cr0, gs.cr3, gs.rip, &insn) orelse return null;
    if (fetched < 2) return null;

    var op = decodeBytes(insn[0..fetched]) catch return null;

    if (op.is_write and !op.is_immediate) {
        op.value = @truncate(readGpr(gs, op.reg));
    }
    return op;
}

pub fn readGpr(gs: *const GuestState, reg: u4) u64 {
    return switch (reg) {
        0 => gs.rax,
        1 => gs.rcx,
        2 => gs.rdx,
        3 => gs.rbx,
        4 => gs.rsp,
        5 => gs.rbp,
        6 => gs.rsi,
        7 => gs.rdi,
        8 => gs.r8,
        9 => gs.r9,
        10 => gs.r10,
        11 => gs.r11,
        12 => gs.r12,
        13 => gs.r13,
        14 => gs.r14,
        15 => gs.r15,
    };
}

/// Write a value to a guest GPR slot in `GuestState`.
pub fn writeGpr(gs: *GuestState, reg: u4, value: u64) void {
    switch (reg) {
        0 => gs.rax = value,
        1 => gs.rcx = value,
        2 => gs.rdx = value,
        3 => gs.rbx = value,
        4 => gs.rsp = value,
        5 => gs.rbp = value,
        6 => gs.rsi = value,
        7 => gs.rdi = value,
        8 => gs.r8 = value,
        9 => gs.r9 = value,
        10 => gs.r10 = value,
        11 => gs.r11 = value,
        12 => gs.r12 = value,
        13 => gs.r13 = value,
        14 => gs.r14 = value,
        15 => gs.r15 = value,
    }
}

// --- Instruction decode ---

/// Decode MMIO/port I/O instruction from a pre-fetched byte buffer.
/// Returns the decoded operation or an error if the instruction is
/// unsupported or the buffer is too short.
///
/// Follows the general 64-bit instruction format from Intel SDM Vol 2A
/// §2.1 "Instruction Format":
///   [Legacy Prefix][REX Prefix][Opcode][ModR/M][SIB][Displacement][Immediate]
///
/// For register-source writes (0x89, 0x88), `is_immediate` is false and
/// `value` is 0 — the caller must read the source register via `reg`.
pub fn decodeBytes(buf: []const u8) DecodeError!MmioOp {
    if (buf.len < 2) return DecodeError.IncompleteDecode;

    var i: u8 = 0;
    var rex: u8 = 0;
    var has_66: bool = false;
    var has_rex_w: bool = false;

    // Parse legacy + REX prefixes.
    // REX: Intel SDM Vol 2A §2.2.1 Table 2-4 (REX.W is bit 3 of the
    // 0x40..0x4F prefix byte; promotes the operand to 64-bit).
    // 0x66: operand-size override (SDM Vol 2A §2.1.1) — switches 32-bit
    // default to 16-bit in this context.
    // 0x67/0xF0/0xF2/0xF3/segment-overrides: skipped per SDM Vol 2A §2.1.1
    // "Instruction Prefixes" — they don't affect the MOV opcodes we decode.
    while (i < buf.len) {
        switch (buf[i]) {
            0x40...0x4F => {
                rex = buf[i];
                has_rex_w = (rex & 0x08) != 0;
                i += 1;
            },
            0x66 => {
                has_66 = true;
                i += 1;
            },
            // Address size, lock, rep, segment overrides -- skip
            0x67, 0xF0, 0xF2, 0xF3, 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65 => {
                i += 1;
            },
            else => break,
        }
    }

    if (i >= buf.len) return DecodeError.IncompleteDecode;
    const opcode = buf[i];
    i += 1;

    if (i >= buf.len) return DecodeError.IncompleteDecode;
    const modrm = buf[i];
    i += 1;

    // ModR/M decomposition — Intel SDM Vol 2A §2.1.5, Table 2-1
    // (32-bit addressing forms with the ModR/M byte) and Table 2-2
    // (addressing forms reference for SIB). Bits: mod[7:6] reg[5:3] r/m[2:0].
    const mod_field: u2 = @truncate(modrm >> 6);
    // REX.R extends ModR/M.reg (SDM Vol 2A §2.2.1 Table 2-4). REX is
    // bit 2 of the REX prefix byte.
    const reg_field: u4 = @as(u4, @truncate((modrm >> 3) & 7)) | (if (rex & 0x04 != 0) @as(u4, 8) else 0);
    const rm_field: u3 = @truncate(modrm & 7);

    // SIB byte present when mod != 11 AND r/m == 100 (SDM Vol 2A §2.1.5
    // Table 2-2 "32-Bit Addressing Forms with the SIB Byte"). Layout:
    // scale[7:6] index[5:3] base[2:0].
    var has_sib_disp32 = false;
    if (mod_field != 0b11 and rm_field == 0b100) {
        if (i >= buf.len) return DecodeError.IncompleteDecode;
        const sib = buf[i];
        i += 1; // SIB
        const sib_base: u3 = @truncate(sib & 7);
        // SIB base==101 combined with mod==00 replaces the base
        // register with an absolute disp32 (SDM Vol 2A §2.1.5,
        // footnote to Table 2-2).
        if (mod_field == 0b00 and sib_base == 0b101) {
            has_sib_disp32 = true;
        }
    }

    // Displacement size derived from ModR/M.mod (SDM Vol 2A Table 2-1)
    // and the SIB corner case. Special case: mod==00 r/m==101 is
    // RIP-relative disp32 in 64-bit mode (SDM Vol 2A §2.2.1.6).
    if (has_sib_disp32) {
        i += 4; // SIB base=101 + mod=00 -> absolute disp32
    } else if (mod_field == 0b00 and rm_field == 0b101) {
        i += 4; // RIP-relative disp32
    } else if (mod_field == 0b01) {
        i += 1; // disp8
    } else if (mod_field == 0b10) {
        i += 4; // disp32
    }

    if (i > buf.len) return DecodeError.IncompleteDecode;

    return switch (opcode) {
        // MOV r/m32, r32 -- write from register
        0x89 => if (has_rex_w) DecodeError.UnsupportedInstruction else MmioOp{
            .is_write = true,
            .size = if (has_66) 2 else 4,
            .reg = reg_field,
            .value = 0,
            .len = i,
            .is_immediate = false,
        },
        // MOV r32, r/m32 -- read to register
        0x8B => if (has_rex_w) DecodeError.UnsupportedInstruction else MmioOp{
            .is_write = false,
            .size = if (has_66) 2 else 4,
            .reg = reg_field,
            .value = 0,
            .len = i,
        },
        // MOV r/m8, imm8 -- write byte immediate
        0xC6 => blk: {
            if (i + 1 > buf.len) break :blk DecodeError.IncompleteDecode;
            const imm: u32 = buf[i];
            i += 1;
            break :blk MmioOp{
                .is_write = true,
                .size = 1,
                .reg = 0,
                .value = imm,
                .len = i,
                .is_immediate = true,
            };
        },
        // MOV r/m32, imm32 -- write immediate
        0xC7 => blk: {
            if (has_rex_w) break :blk DecodeError.UnsupportedInstruction;
            const imm_size: u8 = if (has_66) 2 else 4;
            if (i + imm_size > buf.len) break :blk DecodeError.IncompleteDecode;
            var imm: u32 = 0;
            if (imm_size >= 1) imm |= @as(u32, buf[i]);
            if (imm_size >= 2) imm |= @as(u32, buf[i + 1]) << 8;
            if (imm_size >= 3) imm |= @as(u32, buf[i + 2]) << 16;
            if (imm_size >= 4) imm |= @as(u32, buf[i + 3]) << 24;
            i += imm_size;
            break :blk MmioOp{
                .is_write = true,
                .size = imm_size,
                .reg = 0,
                .value = imm,
                .len = i,
                .is_immediate = true,
            };
        },
        // MOV r/m8, r8 -- write byte from register
        0x88 => MmioOp{
            .is_write = true,
            .size = 1,
            .reg = reg_field,
            .value = 0,
            .len = i,
            .is_immediate = false,
        },
        // MOV r8, r/m8 -- read byte to register
        0x8A => MmioOp{
            .is_write = false,
            .size = 1,
            .reg = reg_field,
            .value = 0,
            .len = i,
        },
        else => DecodeError.UnsupportedInstruction,
    };
}

