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
/// Guest virtual → physical translation via 4-level page table walk.
const log = @import("log.zig");
const mem = @import("mem.zig");

const GuestState = @import("main.zig").GuestState;

/// Result of decoding an MMIO instruction.
pub const MmioOp = struct {
    is_write: bool,
    size: u8, // 1, 2, or 4 bytes
    reg: u4, // GPR index (destination for reads, source for register writes)
    value: u32, // Write value (from register or immediate)
    len: u8, // Total instruction length for RIP advancement
    is_immediate: bool, // true = write value is an immediate, not from a register
};

// --- Guest virtual → physical page table walk ---

/// Translate guest virtual address to guest physical using CR3 4-level paging.
/// AMD APM Vol 2, Section 5.3: Long-Mode Page Translation.
fn guestVirtToPhys(cr3: u64, vaddr: u64) ?u64 {
    const pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;
    const pml4_idx = (vaddr >> 39) & 0x1FF;
    const pml4e = readGuestU64(pml4_base + pml4_idx * 8) orelse return null;
    if (pml4e & 1 == 0) return null;

    const pdpt_base = pml4e & 0x000F_FFFF_FFFF_F000;
    const pdpt_idx = (vaddr >> 30) & 0x1FF;
    const pdpte = readGuestU64(pdpt_base + pdpt_idx * 8) orelse return null;
    if (pdpte & 1 == 0) return null;
    if (pdpte & 0x80 != 0) // 1 GB page (PS bit)
        return (pdpte & 0x000F_FFFF_C000_0000) | (vaddr & 0x3FFF_FFFF);

    const pd_base = pdpte & 0x000F_FFFF_FFFF_F000;
    const pd_idx = (vaddr >> 21) & 0x1FF;
    const pde = readGuestU64(pd_base + pd_idx * 8) orelse return null;
    if (pde & 1 == 0) return null;
    if (pde & 0x80 != 0) // 2 MB page (PS bit)
        return (pde & 0x000F_FFFF_FFE0_0000) | (vaddr & 0x1F_FFFF);

    const pt_base = pde & 0x000F_FFFF_FFFF_F000;
    const pt_idx = (vaddr >> 12) & 0x1FF;
    const pte = readGuestU64(pt_base + pt_idx * 8) orelse return null;
    if (pte & 1 == 0) return null;

    return (pte & 0x000F_FFFF_FFFF_F000) | (vaddr & 0xFFF);
}

fn readGuestU64(phys: u64) ?u64 {
    if (phys + 8 > 128 * 1024 * 1024) return null;
    const slice = mem.readGuestSlice(phys, 8);
    return @as(*align(1) const u64, @ptrCast(slice.ptr)).*;
}

// --- Instruction fetch ---

/// Fetch up to 15 instruction bytes from guest virtual address.
/// Returns number of bytes actually fetched, or null on translation failure.
fn fetchInsn(cr3: u64, rip: u64, buf: *[15]u8) ?u8 {
    const phys = guestVirtToPhys(cr3, rip) orelse return null;
    const page_off = phys & 0xFFF;
    const avail: u64 = 4096 - page_off;
    const first: u8 = @intCast(@min(15, avail));

    const slice = mem.readGuestSlice(phys, first);
    @memcpy(buf[0..first], slice);

    if (first < 15) {
        const next_vaddr = (rip & ~@as(u64, 0xFFF)) + 4096;
        if (guestVirtToPhys(cr3, next_vaddr)) |next_phys| {
            const remaining: u8 = 15 - first;
            const next_slice = mem.readGuestSlice(next_phys, remaining);
            @memcpy(buf[first..15], next_slice);
            return 15;
        }
        return first;
    }
    return first;
}

// --- Instruction decode ---

var decode_fail_count: u32 = 0;

/// Decode the MMIO instruction at guest RIP.
/// Returns the decoded operation, or null if the instruction is unrecognized.
pub noinline fn decode(gs: *const GuestState) ?MmioOp {
    var insn: [15]u8 = undefined;
    const fetched = fetchInsn(gs.cr3, gs.rip, &insn) orelse {
        if (decode_fail_count < 5) {
            decode_fail_count += 1;
            log.print("mmio: VA->PA failed RIP=0x");
            log.hex64(gs.rip);
            log.print(" CR3=0x");
            log.hex64(gs.cr3);
            log.print("\n");
        }
        return null;
    };
    if (fetched < 2) return null;

    var i: u8 = 0;
    var rex: u8 = 0;
    var has_66: bool = false;

    // Parse legacy + REX prefixes
    while (i < fetched) {
        switch (insn[i]) {
            0x40...0x4F => {
                rex = insn[i];
                i += 1;
            },
            0x66 => {
                has_66 = true;
                i += 1;
            },
            // Address size, lock, rep, segment overrides — skip
            0x67, 0xF0, 0xF2, 0xF3, 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65 => {
                i += 1;
            },
            else => break,
        }
    }

    if (i >= fetched) return null;
    const opcode = insn[i];
    i += 1;

    if (i >= fetched) return null;
    const modrm = insn[i];
    i += 1;

    const mod_field: u2 = @truncate(modrm >> 6);
    // REX.R extends ModRM.reg (bit 2 of REX = R)
    const reg_field: u4 = @as(u4, @truncate((modrm >> 3) & 7)) | (if (rex & 0x04 != 0) @as(u4, 8) else 0);
    const rm_field: u3 = @truncate(modrm & 7);

    // Skip SIB byte if present (mod != 11 and r/m == 100)
    var has_sib_disp32 = false;
    if (mod_field != 0b11 and rm_field == 0b100) {
        if (i >= fetched) return null;
        const sib = insn[i];
        i += 1; // SIB
        // SIB base=101 (0b101) with mod=00 means disp32, no base register
        const sib_base: u3 = @truncate(sib & 7);
        if (mod_field == 0b00 and sib_base == 0b101) {
            has_sib_disp32 = true;
        }
    }

    // Skip displacement
    if (has_sib_disp32) {
        i += 4; // SIB base=101 + mod=00 → absolute disp32
    } else if (mod_field == 0b00 and rm_field == 0b101) {
        i += 4; // RIP-relative disp32
    } else if (mod_field == 0b01) {
        i += 1; // disp8
    } else if (mod_field == 0b10) {
        i += 4; // disp32
    }

    if (i > fetched) return null;

    return switch (opcode) {
        // MOV r/m32, r32 — MMIO write from register
        0x89 => blk: {
            const size: u8 = if (has_66) 2 else 4;
            break :blk MmioOp{
                .is_write = true,
                .size = size,
                .reg = reg_field,
                .value = @truncate(readGpr(gs, reg_field)),
                .len = i,
                .is_immediate = false,
            };
        },
        // MOV r32, r/m32 — MMIO read to register
        0x8B => blk: {
            const size: u8 = if (has_66) 2 else 4;
            break :blk MmioOp{
                .is_write = false,
                .size = size,
                .reg = reg_field,
                .value = 0,
                .len = i,
                .is_immediate = false,
            };
        },
        // MOV r/m32, imm32 — MMIO write immediate
        0xC7 => blk: {
            const imm_size: u8 = if (has_66) 2 else 4;
            if (i + imm_size > fetched) break :blk null;
            var imm: u32 = 0;
            if (imm_size >= 1) imm |= @as(u32, insn[i]);
            if (imm_size >= 2) imm |= @as(u32, insn[i + 1]) << 8;
            if (imm_size >= 3) imm |= @as(u32, insn[i + 2]) << 16;
            if (imm_size >= 4) imm |= @as(u32, insn[i + 3]) << 24;
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
        // MOV r/m8, r8 — MMIO write byte
        0x88 => MmioOp{
            .is_write = true,
            .size = 1,
            .reg = reg_field,
            .value = @truncate(readGpr(gs, reg_field) & 0xFF),
            .len = i,
            .is_immediate = false,
        },
        // MOV r8, r/m8 — MMIO read byte
        0x8A => MmioOp{
            .is_write = false,
            .size = 1,
            .reg = reg_field,
            .value = 0,
            .len = i,
            .is_immediate = false,
        },
        else => blk: {
            if (decode_fail_count < 10) {
                decode_fail_count += 1;
                log.print("mmio: unknown opcode=0x");
                log.hex8(opcode);
                log.print(" at RIP=0x");
                log.hex64(gs.rip);
                log.print(" bytes:");
                var j: u8 = 0;
                while (j < @min(fetched, 10)) : (j += 1) {
                    log.print(" ");
                    log.hex8(insn[j]);
                }
                log.print("\n");
            }
            break :blk null;
        },
    };
}

fn readGpr(gs: *const GuestState, reg: u4) u64 {
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
