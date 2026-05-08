/// In-kernel Local APIC emulation for guest VMs.
/// Intel SDM Vol 3, Chapter 13 -- xAPIC mode, single vCPU (APIC ID 0).
/// APIC registers are memory-mapped at base 0xFEE00000, 4 KiB region.
/// All registers are 32-bit, aligned on 128-bit (16-byte) boundaries.
/// Table 13-1: Local APIC Register Address Map.
const zag = @import("zag");

const Ioapic = zag.arch.x64.hv.ioapic.Ioapic;

// Register offsets from APIC base (Table 13-1)
const REG_ID: u32 = 0x020; // Local APIC ID Register -- R/W
const REG_VERSION: u32 = 0x030; // Local APIC Version Register -- RO
const REG_TPR: u32 = 0x080; // Task Priority Register -- R/W
const REG_APR: u32 = 0x090; // Arbitration Priority Register -- RO
const REG_PPR: u32 = 0x0A0; // Processor Priority Register -- RO
const REG_EOI: u32 = 0x0B0; // EOI Register -- WO
const REG_LDR: u32 = 0x0D0; // Logical Destination Register -- R/W
const REG_DFR: u32 = 0x0E0; // Destination Format Register -- R/W
const REG_SVR: u32 = 0x0F0; // Spurious Interrupt Vector Register -- R/W
const REG_ISR_BASE: u32 = 0x100; // ISR bits 31:0 through 255:224 (8 regs) -- RO
const REG_TMR_BASE: u32 = 0x180; // TMR bits 31:0 through 255:224 (8 regs) -- RO
const REG_IRR_BASE: u32 = 0x200; // IRR bits 31:0 through 255:224 (8 regs) -- RO
const REG_ESR: u32 = 0x280; // Error Status Register -- R/W
const REG_ICR_LO: u32 = 0x300; // Interrupt Command Register bits 0-31 -- R/W
const REG_ICR_HI: u32 = 0x310; // Interrupt Command Register bits 32-63 -- R/W
const REG_LVT_TIMER: u32 = 0x320; // LVT Timer Register -- R/W
const REG_LVT_THERMAL: u32 = 0x330; // LVT Thermal Sensor Register -- R/W
const REG_LVT_PERF: u32 = 0x340; // LVT Performance Monitoring Register -- R/W
const REG_LVT_LINT0: u32 = 0x350; // LVT LINT0 Register -- R/W
const REG_LVT_LINT1: u32 = 0x360; // LVT LINT1 Register -- R/W
const REG_LVT_ERROR: u32 = 0x370; // LVT Error Register -- R/W
const REG_TIMER_ICR: u32 = 0x380; // Timer Initial Count Register -- R/W
const REG_TIMER_CCR: u32 = 0x390; // Timer Current Count Register -- RO
const REG_TIMER_DCR: u32 = 0x3E0; // Timer Divide Configuration Register -- R/W

pub const Lapic = struct {
    /// APIC ID register (Figure 13-6). Bits 31:24 = APIC ID, rest reserved.
    apic_id: u32 = 0,
    /// Task Priority Register. Bits 7:0 = task priority, rest reserved.
    tpr: u32 = 0,
    /// Logical Destination Register. Bits 31:24 = logical APIC ID.
    ldr: u32 = 0,
    /// Destination Format Register. Reset to all 1s (Section 13.4.7.1).
    dfr: u32 = 0xFFFFFFFF,
    /// Spurious Interrupt Vector Register. Reset to 0x000000FF (Section 13.4.7.1).
    /// Bit 8 = APIC software enable, bits 7:0 = spurious vector.
    svr: u32 = 0x000000FF,
    /// Error Status Register.
    esr: u32 = 0,
    esr_shadow: u32 = 0,
    /// Interrupt Command Register (64 bits, accessed as two 32-bit halves).
    icr_lo: u32 = 0,
    icr_hi: u32 = 0,
    /// LVT registers. Reset to 0x00010000 (masked). Section 13.4.7.1.
    lvt_timer: u32 = 0x00010000,
    lvt_thermal: u32 = 0x00010000,
    lvt_perf: u32 = 0x00010000,
    lvt_lint0: u32 = 0x00010000,
    lvt_lint1: u32 = 0x00010000,
    lvt_error: u32 = 0x00010000,
    /// Timer registers. All reset to 0.
    timer_initial_count: u32 = 0,
    timer_current_count: u32 = 0,
    timer_divide_config: u32 = 0,
    /// Timer accumulator: fractional nanoseconds carried between tick() calls.
    timer_accum_ns: u64 = 0,
    /// 256-bit vector registers: ISR, TMR, IRR (8 x 32-bit words each).
    isr: [8]u32 = .{0} ** 8,
    tmr: [8]u32 = .{0} ** 8,
    irr: [8]u32 = .{0} ** 8,
    /// Pointer to the associated IOAPIC for EOI notification.
    ioapic: *Ioapic = undefined,

    /// Initialize all APIC registers to power-up/reset state (Section 13.4.7.1).
    pub fn init(self: *Lapic, ioapic_ptr: *Ioapic) void {
        self.* = .{};
        self.ioapic = ioapic_ptr;
    }

    /// Handle MMIO read at offset from APIC base 0xFEE00000.
    /// All APIC registers are 32-bit, 128-bit aligned (Table 13-1).
    pub fn mmioRead(self: *const Lapic, offset: u32) u32 {
        return switch (offset) {
            REG_ID => self.apic_id,
            REG_VERSION => 0x00050014, // Version 0x14, Max LVT Entry = 5 (6 entries)
            REG_TPR => self.tpr,
            REG_APR => 0, // APR not used in xAPIC on modern processors
            REG_PPR => self.computePPR(),
            REG_EOI => 0, // EOI is write-only; reads return 0
            REG_LDR => self.ldr,
            REG_DFR => self.dfr,
            REG_SVR => self.svr,
            // ISR: 8 registers at 0x100-0x170
            REG_ISR_BASE,
            REG_ISR_BASE + 0x10,
            REG_ISR_BASE + 0x20,
            REG_ISR_BASE + 0x30,
            REG_ISR_BASE + 0x40,
            REG_ISR_BASE + 0x50,
            REG_ISR_BASE + 0x60,
            REG_ISR_BASE + 0x70,
            => self.isr[(offset - REG_ISR_BASE) >> 4],
            // TMR: 8 registers at 0x180-0x1F0
            REG_TMR_BASE,
            REG_TMR_BASE + 0x10,
            REG_TMR_BASE + 0x20,
            REG_TMR_BASE + 0x30,
            REG_TMR_BASE + 0x40,
            REG_TMR_BASE + 0x50,
            REG_TMR_BASE + 0x60,
            REG_TMR_BASE + 0x70,
            => self.tmr[(offset - REG_TMR_BASE) >> 4],
            // IRR: 8 registers at 0x200-0x270
            REG_IRR_BASE,
            REG_IRR_BASE + 0x10,
            REG_IRR_BASE + 0x20,
            REG_IRR_BASE + 0x30,
            REG_IRR_BASE + 0x40,
            REG_IRR_BASE + 0x50,
            REG_IRR_BASE + 0x60,
            REG_IRR_BASE + 0x70,
            => self.irr[(offset - REG_IRR_BASE) >> 4],
            REG_ESR => self.esr,
            REG_ICR_LO => self.icr_lo,
            REG_ICR_HI => self.icr_hi,
            REG_LVT_TIMER => self.lvt_timer,
            REG_LVT_THERMAL => self.lvt_thermal,
            REG_LVT_PERF => self.lvt_perf,
            REG_LVT_LINT0 => self.lvt_lint0,
            REG_LVT_LINT1 => self.lvt_lint1,
            REG_LVT_ERROR => self.lvt_error,
            REG_TIMER_ICR => self.timer_initial_count,
            REG_TIMER_CCR => self.timer_current_count,
            REG_TIMER_DCR => self.timer_divide_config,
            else => 0,
        };
    }

    /// Handle MMIO write at offset from APIC base 0xFEE00000.
    pub fn mmioWrite(self: *Lapic, offset: u32, value: u32) void {
        switch (offset) {
            REG_ID => self.apic_id = value & 0xFF000000, // Only bits 31:24 writable
            REG_TPR => self.tpr = value & 0xFF,
            REG_EOI => self.handleEOI(),
            REG_LDR => self.ldr = value & 0xFF000000,
            REG_DFR => self.dfr = value | 0x0FFFFFFF, // Bits 27:0 are all 1s (reserved)
            REG_SVR => self.svr = value & 0x1FF, // Bits 8:0 writable (enable + vector)
            REG_ESR => {
                // Section 13.5.3: Write to ESR clears it and latches accumulated errors.
                self.esr = self.esr_shadow;
                self.esr_shadow = 0;
            },
            REG_ICR_LO => {
                self.icr_lo = value;
                self.handleICR();
            },
            REG_ICR_HI => self.icr_hi = value,
            REG_LVT_TIMER => self.lvt_timer = value,
            REG_LVT_THERMAL => self.lvt_thermal = value,
            REG_LVT_PERF => self.lvt_perf = value,
            REG_LVT_LINT0 => self.lvt_lint0 = value,
            REG_LVT_LINT1 => self.lvt_lint1 = value,
            REG_LVT_ERROR => self.lvt_error = value,
            REG_TIMER_ICR => {
                self.timer_initial_count = value;
                self.timer_current_count = value;
                self.timer_accum_ns = 0;
            },
            REG_TIMER_DCR => self.timer_divide_config = value & 0x0B, // Only bits 3, 1:0 used
            else => {},
        }
    }

    /// Advance the APIC timer by elapsed_ns nanoseconds.
    /// Called from the vCPU entry loop before VMRUN. If the timer fires,
    /// sets the IRR bit for the vector in the LVT timer register.
    /// Section 13.5.4: APIC Timer.
    pub fn tick(self: *Lapic, elapsed_ns: u64) void {
        // Timer stopped if initial count is 0
        if (self.timer_initial_count == 0) return;
        // Timer stopped if current count already 0 in one-shot mode
        const timer_mode: u2 = @truncate((self.lvt_timer >> 17) & 0x3);
        if (timer_mode == 0 and self.timer_current_count == 0) return;
        // TSC-deadline mode (0b10) -- stubbed
        if (timer_mode == 2) return;

        const divisor = self.getTimerDivisor();
        // Each "tick" of the APIC timer = divisor bus cycles.
        // We treat the bus clock as 1 GHz (1 ns per cycle) for simplicity.
        const total_ns = self.timer_accum_ns + elapsed_ns;
        const ticks_elapsed = total_ns / divisor;
        self.timer_accum_ns = total_ns % divisor;

        if (ticks_elapsed == 0) return;

        if (timer_mode == 0) {
            // One-shot: count down to 0, fire once
            if (ticks_elapsed >= self.timer_current_count) {
                self.timer_current_count = 0;
                self.fireTimerInterrupt();
            } else {
                self.timer_current_count -= @truncate(ticks_elapsed);
            }
        } else if (timer_mode == 1) {
            // Periodic: use O(1) modular arithmetic instead of iterating
            // per-tick to prevent guest DoS (divisor=1, initial_count=1
            // would otherwise cause ~1 billion iterations per second).
            if (ticks_elapsed >= self.timer_current_count) {
                // First period completes the current countdown.
                const after_first = ticks_elapsed - self.timer_current_count;
                // Remaining full periods after the first reload.
                // Guard against initial_count == 0 (should not happen since
                // we return early above, but be defensive).
                const ic: u64 = self.timer_initial_count;
                if (ic == 0) return;
                const extra_fires = after_first / ic;
                const leftover = after_first % ic;
                // Total fires = 1 (first) + extra_fires.
                // The interrupt only needs to fire once (or a small
                // bounded number) — the IRR bit is idempotent.
                _ = extra_fires;
                self.timer_current_count = @truncate(ic - leftover);
                self.fireTimerInterrupt();
            } else {
                self.timer_current_count -= @truncate(ticks_elapsed);
            }
        }
    }

    /// Return the highest-priority pending interrupt vector that can be
    /// delivered (IRR set, ISR not set for that vector, priority > TPR).
    /// Returns null if no deliverable interrupt is pending.
    pub fn getPendingVector(self: *const Lapic) ?u8 {
        // APIC must be software-enabled (SVR bit 8)
        if (self.svr & 0x100 == 0) return null;

        const irr_vec = highestSetBit(&self.irr) orelse return null;
        const isr_vec = highestSetBit(&self.isr) orelse 0;

        const irr_prio = irr_vec >> 4;
        const isr_prio = isr_vec >> 4;
        const tpr_prio: u8 = @truncate((self.tpr >> 4) & 0xF);

        if (irr_prio > isr_prio and irr_prio > tpr_prio) {
            return irr_vec;
        }
        return null;
    }

    /// Accept an interrupt vector: move from IRR to ISR.
    pub fn acceptInterrupt(self: *Lapic, vector: u8) void {
        clearBit(&self.irr, vector);
        setBit(&self.isr, vector);
    }

    /// Set the IRR bit for an external interrupt vector.
    /// Used by the IOAPIC to deliver interrupts to this LAPIC.
    pub fn injectExternal(self: *Lapic, vector: u8) void {
        setBit(&self.irr, vector);
    }

    /// Clear the IRR (and ISR) bit for `vector` so a deasserted IOAPIC
    /// pin doesn't leave a stale pending interrupt on the LAPIC.
    /// Spec §[vm_inject_irq] test 05.
    pub fn clearPendingVector(self: *Lapic, vector: u8) void {
        clearBit(&self.irr, vector);
        clearBit(&self.isr, vector);
    }

    // --- Internal helpers ---

    /// Compute Processor Priority Register (PPR).
    /// PPR = max(TPR, highest ISR priority class : 0). Section 13.8.3.1.
    fn computePPR(self: *const Lapic) u32 {
        const isr_vec = highestSetBit(&self.isr) orelse 0;
        const isr_class: u32 = isr_vec >> 4;
        const tpr_class: u32 = (self.tpr >> 4) & 0xF;
        if (tpr_class >= isr_class) {
            return self.tpr;
        }
        return isr_class << 4;
    }

    /// EOI handling (Section 13.8.5): clear the highest-priority bit in ISR.
    /// For level-triggered interrupts, also clear remote IRR in the IOAPIC.
    fn handleEOI(self: *Lapic) void {
        const vec = highestSetBit(&self.isr) orelse return;
        clearBit(&self.isr, vec);
        // If this was a level-triggered interrupt (TMR bit set), notify IOAPIC
        if (getBit(&self.tmr, vec)) {
            self.ioapic.handleEOI(vec);
        }
    }

    /// Handle ICR write -- IPI delivery (Section 13.6.1).
    /// For single-vCPU emulation, only self-IPIs and broadcast are relevant.
    fn handleICR(self: *Lapic) void {
        const vector: u8 = @truncate(self.icr_lo & 0xFF);
        const delivery_mode: u3 = @truncate((self.icr_lo >> 8) & 0x7);
        const shorthand: u2 = @truncate((self.icr_lo >> 18) & 0x3);

        switch (shorthand) {
            0b01 => {
                // Self IPI
                if (delivery_mode == 0b000) { // Fixed
                    setBit(&self.irr, vector);
                }
            },
            else => {},
        }
        // Clear delivery status bit (bit 12) -- delivery is always "complete"
        self.icr_lo &= ~@as(u32, 1 << 12);
    }

    /// Fire a timer interrupt: set IRR bit for the LVT timer vector.
    fn fireTimerInterrupt(self: *Lapic) void {
        // Masked? (bit 16 of LVT timer)
        if (self.lvt_timer & 0x10000 != 0) return;
        const vector: u8 = @truncate(self.lvt_timer & 0xFF);
        if (vector < 16) {
            // Illegal vector -- set ESR bit 5 (send illegal vector)
            self.esr_shadow |= (1 << 5);
            return;
        }
        setBit(&self.irr, vector);
    }

    /// Decode the timer divide configuration register (Figure 13-10).
    /// Returns the divisor as a u64.
    fn getTimerDivisor(self: *const Lapic) u64 {
        const bits10: u3 = @truncate(self.timer_divide_config & 0x3);
        const bit3: u3 = @truncate((self.timer_divide_config >> 3) & 0x1);
        const code: u3 = (bit3 << 2) | bits10;
        return switch (code) {
            0b000 => 2,
            0b001 => 4,
            0b010 => 8,
            0b011 => 16,
            0b100 => 32,
            0b101 => 64,
            0b110 => 128,
            0b111 => 1,
        };
    }
};

/// Find the highest set bit across a 256-bit vector (8 x 32-bit words).
/// Returns the bit index (0-255) or null if no bits are set. Atomic
/// loads so a concurrent `setBit` / `clearBit` from another core
/// produces a consistent snapshot of each word at read time.
fn highestSetBit(vec: *const [8]u32) ?u8 {
    var i: u8 = 8;
    while (i > 0) {
        i -= 1;
        const w = @atomicLoad(u32, &vec[i], .acquire);
        if (w != 0) {
            var bit: u5 = 31;
            while (true) {
                if (w & (@as(u32, 1) << bit) != 0) {
                    return @as(u8, i) * 32 + bit;
                }
                if (bit == 0) break;
                bit -= 1;
            }
        }
    }
    return null;
}

/// Set a bit in a 256-bit vector. Atomic-or so a cross-core
/// `vm_inject_irq` (which lands here via IOAPIC.assertIrq →
/// deliverInterrupt → injectExternal) cannot lose updates against the
/// owning vCPU's run-loop reads/clears.
fn setBit(vec: *[8]u32, bit_index: u8) void {
    const word: u3 = @truncate(bit_index >> 5);
    const bit: u5 = @truncate(bit_index & 0x1F);
    _ = @atomicRmw(u32, &vec[word], .Or, @as(u32, 1) << bit, .release);
}

/// Clear a bit in a 256-bit vector. Atomic-and counterpart to
/// `setBit` for cross-core deassert / EOI / accept paths.
fn clearBit(vec: *[8]u32, bit_index: u8) void {
    const word: u3 = @truncate(bit_index >> 5);
    const bit: u5 = @truncate(bit_index & 0x1F);
    _ = @atomicRmw(u32, &vec[word], .And, ~(@as(u32, 1) << bit), .release);
}

/// Test a bit in a 256-bit vector.
fn getBit(vec: *const [8]u32, bit_index: u8) bool {
    const word: u3 = @truncate(bit_index >> 5);
    const bit: u5 = @truncate(bit_index & 0x1F);
    const w = @atomicLoad(u32, &vec[word], .acquire);
    return (w & (@as(u32, 1) << bit)) != 0;
}
