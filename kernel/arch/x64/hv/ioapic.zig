/// In-kernel I/O APIC emulation for guest VMs.
/// Intel 82093AA datasheet (Order Number: 290566-001).
/// The IOAPIC is accessed via indirect register addressing:
///   IOREGSEL at 0xFEC00000 (selects register index)
///   IOWIN at 0xFEC00010 (reads/writes selected register)
/// Section 3.0: Register Description.
const zag = @import("zag");

const Lapic = zag.arch.x64.hv.lapic.Lapic;

// Memory-mapped register offsets (Table 1)
const IOREGSEL_OFF: u32 = 0x00;
const IOWIN_OFF: u32 = 0x10;

// IOAPIC register indices (Table 2)
const REG_ID: u8 = 0x00; // IOAPICID -- R/W, bits 27:24
const REG_VER: u8 = 0x01; // IOAPICVER -- RO, version + max redir
const REG_ARB: u8 = 0x02; // IOAPICARB -- RO, arbitration ID
const REG_REDTBL_BASE: u8 = 0x10; // IOREDTBL[0] lo, 0x11 = IOREDTBL[0] hi, etc.

/// Number of redirection table entries (24 IRQ pins).
pub const NUM_REDIR_ENTRIES: u5 = 24;

pub const Ioapic = struct {
    /// IOREGSEL: currently selected register index.
    ioregsel: u8 = 0,
    /// IOAPIC ID register. Only bits 27:24 are meaningful (Section 3.2.1).
    ioapic_id: u32 = 0,
    /// 24-entry redirection table, 64 bits each (Section 3.2.4).
    /// Reset default: bit 16 (mask) set = all masked.
    redir_table: [NUM_REDIR_ENTRIES]u64 = .{@as(u64, 1) << 16} ** NUM_REDIR_ENTRIES,
    /// IRQ line state for level-triggered interrupt tracking.
    irq_level: u32 = 0,
    /// Pointer to the associated LAPIC for interrupt delivery.
    lapic: *Lapic = undefined,

    /// Initialize the IOAPIC to reset state.
    pub fn init(self: *Ioapic, lapic_ptr: *Lapic) void {
        self.* = .{};
        self.lapic = lapic_ptr;
    }

    /// Handle MMIO read at offset from IOAPIC base 0xFEC00000.
    /// Only IOREGSEL (offset 0x00) and IOWIN (offset 0x10) are accessible.
    pub fn mmioRead(self: *const Ioapic, offset: u32) u32 {
        return switch (offset) {
            IOREGSEL_OFF => self.ioregsel,
            IOWIN_OFF => self.readRegister(self.ioregsel),
            else => 0,
        };
    }

    /// Handle MMIO write at offset from IOAPIC base 0xFEC00000.
    pub fn mmioWrite(self: *Ioapic, offset: u32, value: u32) void {
        switch (offset) {
            IOREGSEL_OFF => self.ioregsel = @truncate(value & 0xFF),
            IOWIN_OFF => self.writeRegister(self.ioregsel, value),
            else => {},
        }
    }

    /// Assert an IRQ line. Routes through the redirection table to the LAPIC.
    /// Section 3.2.4: Redirection table entry format.
    ///
    /// Atomic-load on the redirection-table entry so a concurrent
    /// `mmioWrite(REG_REDTBL_*)` on another core (Linux's GIC/IOAPIC
    /// programming runs on whichever vCPU drives boot) cannot tear the
    /// 64-bit entry across the assert path. Atomic-or on `irq_level`
    /// is the cross-core race fix for `vm_inject_irq` from any core
    /// vs. the owning vCPU run loop.
    pub fn assertIrq(self: *Ioapic, irq: u5) void {
        if (irq >= NUM_REDIR_ENTRIES) return;
        const entry = @atomicLoad(u64, &self.redir_table[irq], .acquire);

        // Bit 16: mask. If masked, ignore.
        if (entry & (1 << 16) != 0) return;

        const trigger_mode = (entry >> 15) & 1; // 0=edge, 1=level
        const irq_bit = @as(u32, 1) << irq;

        if (trigger_mode == 0) {
            // Edge-triggered: deliver on rising edge (transition from 0 to 1).
            const prev = @atomicRmw(u32, &self.irq_level, .Or, irq_bit, .acq_rel);
            if ((prev & irq_bit) != 0) return;
        } else {
            // Level-triggered: deliver if not already pending (remote IRR = 0).
            if (entry & (1 << 14) != 0) return;
            _ = @atomicRmw(u32, &self.irq_level, .Or, irq_bit, .release);
            _ = @atomicRmw(u64, &self.redir_table[irq], .Or, @as(u64, 1 << 14), .release);
        }

        self.deliverInterrupt(entry);
    }

    /// De-assert an IRQ line.
    ///
    /// Spec §[vm_inject_irq] test 05: after a deassert immediately
    /// following an assert, "no interrupt vm_exit corresponding to
    /// line [2] is delivered to any vCPU even when the vCPU's
    /// interrupt window opens or it becomes runnable with the line
    /// unmasked." Honor that by also dropping the matching pending
    /// IRR/ISR bit from the LAPIC (the assert path called
    /// `deliverInterrupt` → `lapic.injectExternal` which set IRR;
    /// without this the next `deliverPendingInterrupts` would surface
    /// the interrupt anyway), and clearing Remote IRR on every
    /// redirection entry that shares the vector so a follow-up
    /// `assertIrq` re-delivers cleanly. Atomic-and on `irq_level`
    /// matches the assertIrq atomic-or so cross-core `vm_inject_irq`
    /// calls never race a vCPU run-loop scan.
    pub fn deassertIrq(self: *Ioapic, irq: u5) void {
        if (irq >= NUM_REDIR_ENTRIES) return;
        const irq_bit: u32 = @as(u32, 1) << irq;
        _ = @atomicRmw(u32, &self.irq_level, .And, ~irq_bit, .release);

        // Capture the deasserted line's vector once, then clear remote
        // IRR (bit 14) on every entry sharing that vector. Mirrors
        // `handleEOI`'s shared-vector loop because Linux maps multiple
        // GSIs onto a single LAPIC vector.
        const entry_irq = @atomicLoad(u64, &self.redir_table[irq], .acquire);
        const vector: u8 = @truncate(entry_irq & 0xFF);
        for (&self.redir_table) |*entry_ptr| {
            const entry = @atomicLoad(u64, entry_ptr, .acquire);
            const entry_vector: u8 = @truncate(entry & 0xFF);
            if (entry_vector == vector) {
                _ = @atomicRmw(u64, entry_ptr, .And, ~@as(u64, 1 << 14), .release);
            }
        }
        self.lapic.clearPendingVector(vector);
    }

    /// Handle EOI from LAPIC for a level-triggered interrupt.
    /// Clears Remote IRR (bit 14) in all redirection-table entries that
    /// map to this vector. Linux shares vectors across GSIs, so we must
    /// scan every entry rather than stopping after the first match.
    ///
    /// Atomic ops on each entry mirror `assertIrq` / `mmioWrite` so a
    /// concurrent re-program of the redirection table from another
    /// core cannot lose the Remote-IRR clear or the re-deliver edge.
    pub fn handleEOI(self: *Ioapic, vector: u8) void {
        for (&self.redir_table, 0..) |*entry_ptr, i| {
            const entry = @atomicLoad(u64, entry_ptr, .acquire);
            const entry_vector: u8 = @truncate(entry & 0xFF);
            if (entry_vector == vector and (entry & (1 << 14) != 0)) {
                // Clear Remote IRR.
                _ = @atomicRmw(u64, entry_ptr, .And, ~@as(u64, 1 << 14), .release);
                // If the IRQ line is still asserted (level-sensitive),
                // re-set Remote IRR and re-deliver.
                const level = @atomicLoad(u32, &self.irq_level, .acquire);
                if (level & (@as(u32, 1) << @as(u5, @truncate(i))) != 0) {
                    _ = @atomicRmw(u64, entry_ptr, .Or, @as(u64, 1 << 14), .release);
                    self.deliverInterrupt(entry);
                }
                // Do not return — continue scanning for other entries
                // sharing this vector.
            }
        }
    }

    // --- Internal helpers ---

    /// Read an IOAPIC register by index (via IOREGSEL).
    fn readRegister(self: *const Ioapic, index: u8) u32 {
        return switch (index) {
            REG_ID => self.ioapic_id,
            // Section 3.2.2: Version=0x11, max redir entry=23 (0x17)
            REG_VER => 0x00170011,
            // Section 3.2.3: Arbitration ID (same as IOAPIC ID)
            REG_ARB => self.ioapic_id,
            // Redirection table: 0x10-0x3F
            REG_REDTBL_BASE...0x3F => blk: {
                const reg_off = index - REG_REDTBL_BASE;
                const entry_idx = reg_off / 2;
                if (entry_idx >= NUM_REDIR_ENTRIES) break :blk 0;
                const entry = @atomicLoad(u64, &self.redir_table[entry_idx], .acquire);
                if (reg_off & 1 == 0) {
                    break :blk @truncate(entry);
                } else {
                    break :blk @truncate(entry >> 32);
                }
            },
            else => 0,
        };
    }

    /// Write an IOAPIC register by index (via IOREGSEL).
    ///
    /// Redirection-table edits use a CAS loop so a concurrent
    /// `assertIrq` / `handleEOI` on another core cannot lose the
    /// Remote-IRR/level-state preservation across the half-update.
    fn writeRegister(self: *Ioapic, index: u8, value: u32) void {
        switch (index) {
            REG_ID => self.ioapic_id = value & 0x0F000000,
            REG_VER, REG_ARB => {},
            REG_REDTBL_BASE...0x3F => {
                const reg_off = index - REG_REDTBL_BASE;
                const entry_idx = reg_off / 2;
                if (entry_idx >= NUM_REDIR_ENTRIES) return;
                // Bits 12 (delivery status) and 14 (remote IRR) are read-only.
                const ro_mask_lo: u64 = (1 << 12) | (1 << 14);
                while (true) {
                    const old = @atomicLoad(u64, &self.redir_table[entry_idx], .acquire);
                    const new_val: u64 = if (reg_off & 1 == 0) blk: {
                        const preserved = old & (ro_mask_lo | 0xFFFFFFFF_00000000);
                        const written = @as(u64, value) & ~ro_mask_lo;
                        break :blk preserved | written;
                    } else
                        (old & 0x00000000_FFFFFFFF) | (@as(u64, value) << 32);
                    const r = @cmpxchgWeak(u64, &self.redir_table[entry_idx], old, new_val, .release, .monotonic);
                    if (r == null) break;
                }
            },
            else => {},
        }
    }

    /// Deliver an interrupt from a redirection table entry to the LAPIC.
    fn deliverInterrupt(self: *Ioapic, entry: u64) void {
        const vector: u8 = @truncate(entry & 0xFF);
        const delivery_mode: u3 = @truncate((entry >> 8) & 0x7);

        switch (delivery_mode) {
            0b000, 0b001 => {
                // Fixed / Lowest Priority -- deliver vector to LAPIC.
                if (vector < 16) return; // Illegal vector, ignore
                self.lapic.injectExternal(vector);
            },
            0b111 => {
                // ExtINT -- deliver as external interrupt
                self.lapic.injectExternal(vector);
            },
            else => {}, // SMI, NMI, INIT -- stubbed
        }
    }
};
