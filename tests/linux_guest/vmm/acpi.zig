/// ACPI table generation for Linux guest boot.
/// Builds RSDP, XSDT, MADT, FADT, and DSDT with proper checksums.
/// Tables are placed at guest physical 0xE0000 (RSDP) and 0xE1000 (table area).
///
/// References:
///   ACPI Specification 6.4, sections 5.2 (RSDP), 5.2.6 (XSDT),
///   5.2.12 (MADT), 5.2.9 (FADT), 5.2.11 (DSDT)
const log = @import("log.zig");
const mem = @import("mem.zig");

// Guest physical addresses
const RSDP_ADDR: u64 = 0xE0000;
const TABLE_BASE: u64 = 0xE1000;

// Table offsets within the table area
const XSDT_OFFSET: u64 = 0;
const MADT_OFFSET: u64 = 256;
const FADT_OFFSET: u64 = 512;
const DSDT_OFFSET: u64 = 1024;

// Guest physical addresses of each table
const XSDT_ADDR: u64 = TABLE_BASE + XSDT_OFFSET;
const MADT_ADDR: u64 = TABLE_BASE + MADT_OFFSET;
const FADT_ADDR: u64 = TABLE_BASE + FADT_OFFSET;
const DSDT_ADDR: u64 = TABLE_BASE + DSDT_OFFSET;

// ACPI PM I/O port addresses (handled via I/O exit interception)
const PM1A_EVT_BLK: u32 = 0x600;
const PM1A_CNT_BLK: u32 = 0x604;

// File-scope table buffers (must not be stack locals)
var rsdp_buf: [36]u8 = .{0} ** 36;
var table_buf: [2048]u8 = .{0} ** 2048;

/// Compute ACPI checksum: sum of all bytes mod 256 must equal 0.
/// Returns the value to store in the checksum field.
fn acpiChecksum(data: []const u8) u8 {
    var sum: u8 = 0;
    for (data) |b| {
        sum +%= b;
    }
    return 0 -% sum;
}

/// Write a standard 36-byte ACPI SDT header.
/// Fields: signature(4), length(4), revision(1), checksum(1),
///         OEMID(6), OEM table ID(8), OEM revision(4),
///         creator ID(4), creator revision(4)
fn writeHeader(buf: []u8, sig: *const [4]u8, length: u32, revision: u8) void {
    @memcpy(buf[0..4], sig);
    writeU32(buf, 4, length);
    buf[8] = revision;
    buf[9] = 0; // checksum — filled in after table is complete
    @memcpy(buf[10..16], "ZAGVMM");
    @memcpy(buf[16..24], "ZAGKERML");
    writeU32(buf, 24, 1); // OEM revision
    @memcpy(buf[28..32], "ZAG ");
    writeU32(buf, 32, 1); // ASL compiler revision
}

/// Finalize a table's checksum (byte at offset 9).
fn finalizeChecksum(buf: []u8, length: u32) void {
    buf[9] = 0;
    buf[9] = acpiChecksum(buf[0..length]);
}

// --- RSDP (Root System Description Pointer) ---
// ACPI 6.4 Table 5.2.5.3 — RSDP Structure (revision 2)
// Offset  Field
//   0     Signature "RSD PTR " (8 bytes)
//   8     Checksum (covers bytes 0-19)
//   9     OEMID (6 bytes)
//  15     Revision (2 for ACPI 2.0+)
//  16     RsdtAddress (u32) — we set 0, Linux prefers XSDT with rev 2
//  20     Length (u32) — 36 for revision 2
//  24     XsdtAddress (u64)
//  32     Extended Checksum (covers bytes 0-35)
//  33     Reserved (3 bytes)

noinline fn buildRsdp() void {
    @memset(&rsdp_buf, 0);
    @memcpy(rsdp_buf[0..8], "RSD PTR ");
    @memcpy(rsdp_buf[9..15], "ZAGVMM");
    rsdp_buf[15] = 2; // Revision 2 (ACPI 2.0+)
    writeU32(&rsdp_buf, 16, 0); // RsdtAddress — 0, Linux uses XSDT for rev 2
    writeU32(&rsdp_buf, 20, 36); // Length
    writeU64(&rsdp_buf, 24, XSDT_ADDR); // XsdtAddress

    // V1 checksum covers bytes 0-19
    rsdp_buf[8] = 0;
    rsdp_buf[8] = acpiChecksum(rsdp_buf[0..20]);

    // Extended checksum covers bytes 0-35
    rsdp_buf[32] = 0;
    rsdp_buf[32] = acpiChecksum(rsdp_buf[0..36]);
}

// --- DSDT (Differentiated System Description Table) ---
// Minimal DSDT with AML bytecode defining:
//   \_SB scope (System Bus)
//   \_SB.CPU0 processor object (ACPI ID 0, PBLK addr 0, PBLK len 0)
//   \_S5 package for shutdown support (SLP_TYP values)
//
// AML opcodes reference (ACPI 6.4 section 20):
//   DefScope:    0x10 PkgLength NameString
//   ProcessorOp: 0x5B 0x83 PkgLength NameString ProcID PblkAddr PblkLen
//   DefName:     0x08 NameString DataRefObject
//   DefPackage:  0x12 PkgLength NumElements PackageElementList
//   ByteConst:   0x0A byte
//   ZeroOp:      0x00

const dsdt_aml = [_]u8{
    // Scope(\_SB) { Processor(CPU0, 0, 0, 0) {} }
    // PkgLength encoding: single byte, value includes PkgLength byte + all contents.
    0x10, // ScopeOp
    0x12, // PkgLength = 18 (1 + "_SB_"(4) + ProcessorOp(2+11=13))
    '_', 'S', 'B', '_', // NameString "\_SB"

    // Processor(\_SB.CPU0, 0, 0x00000000, 0)
    0x5B, 0x83, // ProcessorOp (extended opcode)
    0x0B, // PkgLength = 11 (1 + "CPU0"(4) + ProcID(1) + PblkAddr(4) + PblkLen(1))
    'C', 'P', 'U', '0', // NameString
    0x00, // ProcID = 0
    0x00, 0x00, 0x00, 0x00, // PblkAddr = 0
    0x00, // PblkLen = 0

    // Name(\_S5, Package(){ 5, 0, 0, 0 }) — at root scope
    // Tells Linux SLP_TYPa=5 for S5 (shutdown via ACPI)
    0x08, // NameOp
    '_', 'S', '5', '_', // NameString "\_S5"
    0x12, // PackageOp
    0x07, // PkgLength = 7 (1 + NumElements(1) + ByteConst(2) + 3*ZeroOp(3))
    0x04, // NumElements = 4
    0x0A, 0x05, // ByteConst: SLP_TYPa = 5
    0x00, // ZeroOp: SLP_TYPb = 0
    0x00, // ZeroOp: reserved
    0x00, // ZeroOp: reserved
};

const DSDT_TOTAL_LEN: u32 = 36 + dsdt_aml.len;

noinline fn buildDsdt() void {
    const base = DSDT_OFFSET;
    const buf = table_buf[base..];
    writeHeader(buf, "DSDT", DSDT_TOTAL_LEN, 2);
    @memcpy(buf[36..][0..dsdt_aml.len], &dsdt_aml);
    finalizeChecksum(buf, DSDT_TOTAL_LEN);
}

// --- MADT (Multiple APIC Description Table) ---
// ACPI 6.4 section 5.2.12
// Header(36) + LocalApicAddr(4) + Flags(4) + entries
//
// Entry types:
//   0: Processor Local APIC (8 bytes)
//   1: I/O APIC (12 bytes)
//   2: Interrupt Source Override (10 bytes)
//   4: Local APIC NMI (6 bytes)

const LOCAL_APIC_ENTRY_LEN: u32 = 8;
const IO_APIC_ENTRY_LEN: u32 = 12;
const INT_SRC_OVERRIDE_LEN: u32 = 10;
const LOCAL_APIC_NMI_LEN: u32 = 6;

const MADT_TOTAL_LEN: u32 = 44 // header(36) + local APIC addr(4) + flags(4)
    + LOCAL_APIC_ENTRY_LEN // CPU0 local APIC
    + IO_APIC_ENTRY_LEN // I/O APIC
    + INT_SRC_OVERRIDE_LEN // IRQ0 -> GSI2 (timer)
    + INT_SRC_OVERRIDE_LEN // IRQ9 -> GSI9 (ACPI SCI)
    + LOCAL_APIC_NMI_LEN; // LINT1 NMI

noinline fn buildMadt() void {
    const base = MADT_OFFSET;
    const buf = table_buf[base..];
    writeHeader(buf, "APIC", MADT_TOTAL_LEN, 3);

    // Local APIC address (offset 36)
    writeU32(buf, 36, 0xFEE00000);
    // Flags (offset 40): PCAT_COMPAT (bit 0) — dual-8259 setup
    writeU32(buf, 40, 1);

    var off: usize = 44;

    // Type 0: Processor Local APIC
    // ACPI processor ID=0, APIC ID=0, flags=enabled
    buf[off + 0] = 0; // type
    buf[off + 1] = 8; // length
    buf[off + 2] = 0; // ACPI processor ID
    buf[off + 3] = 0; // APIC ID
    writeU32(buf[off..], 4, 1); // flags: enabled (bit 0)
    off += LOCAL_APIC_ENTRY_LEN;

    // Type 1: I/O APIC
    // ID=1, address=0xFEC00000, GSI base=0
    buf[off + 0] = 1; // type
    buf[off + 1] = 12; // length
    buf[off + 2] = 1; // I/O APIC ID
    buf[off + 3] = 0; // reserved
    writeU32(buf[off..], 4, 0xFEC00000); // I/O APIC address
    writeU32(buf[off..], 8, 0); // Global System Interrupt base
    off += IO_APIC_ENTRY_LEN;

    // Type 2: Interrupt Source Override — IRQ0 -> GSI2
    // Without this, Linux assumes IRQ0=GSI0 and timer routing breaks.
    // Bus=0 (ISA), Source=0 (IRQ0), GSI=2, Flags=0 (conforming)
    buf[off + 0] = 2; // type
    buf[off + 1] = 10; // length
    buf[off + 2] = 0; // bus (ISA)
    buf[off + 3] = 0; // source (IRQ0)
    writeU32(buf[off..], 4, 2); // global system interrupt (GSI 2)
    writeU16(buf[off..], 8, 0); // flags: conforming polarity & trigger
    off += INT_SRC_OVERRIDE_LEN;

    // Type 2: Interrupt Source Override — IRQ9 -> GSI9
    // ACPI SCI interrupt, level-triggered active-low
    // Flags: polarity=active-low (3), trigger=level (3<<2) = 0x000D
    buf[off + 0] = 2; // type
    buf[off + 1] = 10; // length
    buf[off + 2] = 0; // bus (ISA)
    buf[off + 3] = 9; // source (IRQ9)
    writeU32(buf[off..], 4, 9); // global system interrupt (GSI 9)
    writeU16(buf[off..], 8, 0x000D); // flags: active-low, level-triggered
    off += INT_SRC_OVERRIDE_LEN;

    // Type 4: Local APIC NMI
    // ACPI processor ID=0xFF (all processors), LINT#1, flags=0 (conforming)
    buf[off + 0] = 4; // type
    buf[off + 1] = 6; // length
    buf[off + 2] = 0xFF; // ACPI processor UID (0xFF = all processors)
    writeU16(buf[off..], 3, 0); // flags: conforming
    buf[off + 5] = 1; // LINT# (1 = LINT1)
    finalizeChecksum(buf, MADT_TOTAL_LEN);
}

// --- FADT (Fixed ACPI Description Table) ---
// ACPI 6.4 section 5.2.9 — "FACP" signature
// We use revision 5 (ACPI 5.0) with a 276-byte table to include
// the X_DSDT field (offset 140) and hypervisor vendor identity (offset 268).

const FADT_TOTAL_LEN: u32 = 276;

noinline fn buildFadt() void {
    const base = FADT_OFFSET;
    const buf = table_buf[base..];
    writeHeader(buf, "FACP", FADT_TOTAL_LEN, 5);

    // FIRMWARE_CTRL (offset 36, u32): 0 — no FACS
    writeU32(buf, 36, 0);

    // DSDT (offset 40, u32): 32-bit DSDT pointer
    writeU32(buf, 40, @intCast(DSDT_ADDR));

    // Reserved / INT_MODEL (offset 44, u8): not used in rev 5+
    buf[44] = 0;

    // Preferred_PM_Profile (offset 45, u8): 0 = Unspecified
    buf[45] = 0;

    // SCI_INT (offset 46, u16): IRQ 9
    writeU16(buf, 46, 9);

    // SMI_CMD (offset 48, u32): 0 — no SMI support
    writeU32(buf, 48, 0);

    // ACPI_ENABLE (offset 52, u8): 0
    buf[52] = 0;
    // ACPI_DISABLE (offset 53, u8): 0
    buf[53] = 0;
    // S4BIOS_REQ (offset 54, u8): 0
    buf[54] = 0;
    // PSTATE_CNT (offset 55, u8): 0
    buf[55] = 0;

    // PM1a_EVT_BLK (offset 56, u32)
    writeU32(buf, 56, PM1A_EVT_BLK);
    // PM1b_EVT_BLK (offset 60, u32): 0 — not present
    writeU32(buf, 60, 0);
    // PM1a_CNT_BLK (offset 64, u32)
    writeU32(buf, 64, PM1A_CNT_BLK);
    // PM1b_CNT_BLK (offset 68, u32): 0 — not present
    writeU32(buf, 68, 0);
    // PM2_CNT_BLK (offset 72, u32): 0
    writeU32(buf, 72, 0);
    // PM_TMR_BLK (offset 76, u32): 0 — no PM timer
    writeU32(buf, 76, 0);
    // GPE0_BLK (offset 80, u32): 0
    writeU32(buf, 80, 0);
    // GPE1_BLK (offset 84, u32): 0
    writeU32(buf, 84, 0);

    // PM1_EVT_LEN (offset 88, u8): 4
    buf[88] = 4;
    // PM1_CNT_LEN (offset 89, u8): 2
    buf[89] = 2;
    // PM2_CNT_LEN (offset 90, u8): 0
    buf[90] = 0;
    // PM_TMR_LEN (offset 91, u8): 0
    buf[91] = 0;
    // GPE0_BLK_LEN (offset 92, u8): 0
    buf[92] = 0;
    // GPE1_BLK_LEN (offset 93, u8): 0
    buf[93] = 0;
    // GPE1_BASE (offset 94, u8): 0
    buf[94] = 0;

    // CST_CNT (offset 95, u8): 0
    buf[95] = 0;
    // P_LVL2_LAT (offset 96, u16): 0xFFFF (C2 not supported)
    writeU16(buf, 96, 0xFFFF);
    // P_LVL3_LAT (offset 98, u16): 0xFFFF (C3 not supported)
    writeU16(buf, 98, 0xFFFF);
    // FLUSH_SIZE (offset 100, u16): 0
    writeU16(buf, 100, 0);
    // FLUSH_STRIDE (offset 102, u16): 0
    writeU16(buf, 102, 0);
    // DUTY_OFFSET (offset 104, u8): 0
    buf[104] = 0;
    // DUTY_WIDTH (offset 105, u8): 0
    buf[105] = 0;

    // Day/Month alarm fields (offsets 106-108): 0
    buf[106] = 0; // DAY_ALRM
    buf[107] = 0; // MON_ALRM
    buf[108] = 0; // CENTURY

    // IAPC_BOOT_ARCH (offset 109, u16):
    //   bit 0: LEGACY_DEVICES (8042, etc.)
    //   bit 1: 8042 present
    writeU16(buf, 109, 0x0003);

    // Reserved (offset 111, u8)
    buf[111] = 0;

    // Flags (offset 112, u32):
    //   bit 0: WBINVD — WBINVD instruction works correctly
    //   bit 4: TMR_VAL_EXT — not set (no PM timer)
    //   bit 10: RESET_REG_SUP — not set
    //   Do NOT set HW_REDUCED_ACPI (bit 20) — we provide full LAPIC/IOAPIC
    writeU32(buf, 112, 1 << 0); // WBINVD only

    // RESET_REG (offset 116): Generic Address Structure (12 bytes) — all zeros
    // RESET_VALUE (offset 128, u8): 0

    // X_FIRMWARE_CTRL (offset 132, u64): 0 — no FACS
    writeU64(buf, 132, 0);

    // X_DSDT (offset 140, u64): 64-bit DSDT pointer
    writeU64(buf, 140, DSDT_ADDR);

    // X_PM1a_EVT_BLK (offset 148): GAS — 12 bytes
    // Address Space ID = 1 (System I/O), bit width = 32, bit offset = 0, access size = 3 (Dword)
    writeGas(buf[148..], 1, 32, 0, 3, PM1A_EVT_BLK);

    // X_PM1b_EVT_BLK (offset 160): GAS — not present
    writeGas(buf[160..], 0, 0, 0, 0, 0);

    // X_PM1a_CNT_BLK (offset 172): GAS
    writeGas(buf[172..], 1, 16, 0, 2, PM1A_CNT_BLK); // Word access

    // X_PM1b_CNT_BLK (offset 184): GAS — not present
    writeGas(buf[184..], 0, 0, 0, 0, 0);

    // X_PM2_CNT_BLK (offset 196): GAS — not present
    writeGas(buf[196..], 0, 0, 0, 0, 0);

    // X_PM_TMR_BLK (offset 208): GAS — not present
    writeGas(buf[208..], 0, 0, 0, 0, 0);

    // Hypervisor Vendor Identity (offset 268, 8 bytes) — ACPI 6.0+
    @memcpy(buf[268..276], "ZAGVMM\x00\x00");

    finalizeChecksum(buf, FADT_TOTAL_LEN);
}

/// Write a Generic Address Structure (12 bytes) per ACPI 6.4 section 5.2.3.2.
fn writeGas(buf: []u8, addr_space: u8, bit_width: u8, bit_offset: u8, access_size: u8, address: u64) void {
    buf[0] = addr_space;
    buf[1] = bit_width;
    buf[2] = bit_offset;
    buf[3] = access_size;
    writeU64(buf, 4, address);
}

// --- XSDT (Extended System Description Table) ---
// Header(36) + array of 64-bit pointers to other tables.
// FADT must be the first entry per ACPI spec recommendation.

const XSDT_NUM_ENTRIES: u32 = 2; // FADT, MADT
const XSDT_TOTAL_LEN: u32 = 36 + XSDT_NUM_ENTRIES * 8;

noinline fn buildXsdt() void {
    const base = XSDT_OFFSET;
    const buf = table_buf[base..];
    writeHeader(buf, "XSDT", XSDT_TOTAL_LEN, 1);

    // Entry 0: FADT (should be first per spec)
    writeU64(buf, 36, FADT_ADDR);
    // Entry 1: MADT
    writeU64(buf, 44, MADT_ADDR);

    finalizeChecksum(buf, XSDT_TOTAL_LEN);
}

// --- Public entry point ---

/// Build all ACPI tables and write them to guest physical memory.
/// Must be called after guest memory is set up via mem.setupGuestMemory().
pub noinline fn setupTables() void {
    @memset(&table_buf, 0);

    // Build tables in dependency order: DSDT first (FADT points to it),
    // then MADT, FADT, and finally XSDT (which points to FADT + MADT).
    buildDsdt();
    buildMadt();
    buildFadt();
    buildXsdt();
    buildRsdp();

    mem.writeGuest(RSDP_ADDR, &rsdp_buf);
    mem.writeGuest(TABLE_BASE, &table_buf);

    log.print("ACPI: RSDP at 0x");
    log.hex64(RSDP_ADDR);
    log.print(", tables at 0x");
    log.hex64(TABLE_BASE);
    log.print(" (XSDT+");
    log.dec(XSDT_TOTAL_LEN);
    log.print(" MADT+");
    log.dec(MADT_TOTAL_LEN);
    log.print(" FADT+");
    log.dec(FADT_TOTAL_LEN);
    log.print(" DSDT+");
    log.dec(DSDT_TOTAL_LEN);
    log.print(")\n");
}

// --- Little-endian write helpers ---

fn writeU16(buf: []u8, offset: usize, val: u16) void {
    @as(*align(1) u16, @ptrCast(buf.ptr + offset)).* = val;
}

fn writeU32(buf: []u8, offset: usize, val: u32) void {
    @as(*align(1) u32, @ptrCast(buf.ptr + offset)).* = val;
}

fn writeU64(buf: []u8, offset: usize, val: u64) void {
    @as(*align(1) u64, @ptrCast(buf.ptr + offset)).* = val;
}
