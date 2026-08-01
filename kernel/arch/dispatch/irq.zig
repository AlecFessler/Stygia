const builtin = @import("builtin");
const stygia = @import("stygia");

const aarch64 = stygia.arch.aarch64;
const x64 = stygia.arch.x64;

/// Mask an IRQ line at the interrupt controller. `irq_line` is the
/// kernel-internal IRQ-source key (the value `device_region.irq_source`
/// stores) — the x86 IOAPIC pin (GSI) on x86, the SPI line offset
/// (`intid - 32`) on aarch64. Width is `u32` so the full GIC SPI range
/// (intids 32..1019 → lines 0..987) survives without truncation.
///
/// x86: I/O APIC redirection table mask bit at register `0x10 + line*2`.
/// aarch64: GICD_ICENABLER keyed on the GIC INTID derived from `irq_line`
/// (SPI base 32).
pub fn maskIrq(irq_line: u32) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.maskIrq(irq_line),
        .aarch64 => aarch64.gic.maskIrq(irq_line + 32),
        else => unreachable,
    }
}

/// Unmask an IRQ line at the interrupt controller. `irq_line` follows
/// the same kernel-internal-key convention as `maskIrq`. x86: clear I/O
/// APIC redirection table mask. aarch64: GICD_ISENABLER keyed on the
/// GIC INTID derived from `irq_line` (SPI base 32).
pub fn unmaskIrq(irq_line: u32) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.unmaskIrq(irq_line),
        .aarch64 => aarch64.gic.unmaskIrq(irq_line + 32),
        else => unreachable,
    }
}

/// Signal end-of-interrupt to the interrupt controller. x86: APIC EOI
/// (writes the EOI register; vector implicit, `irq_line` unused).
/// aarch64: ICC_EOIR1_EL1 keyed on the GIC INTID derived from `irq_line`
/// (SPI base 32).
pub fn endOfInterrupt(irq_line: u32) void {
    switch (builtin.cpu.arch) {
        // x86 LAPIC EOI register is implicit on the in-service vector;
        // `irq_line` is unused on this branch.
        .x86_64 => x64.apic.endOfInterrupt(),
        .aarch64 => aarch64.gic.endOfInterrupt(irq_line + 32),
        else => unreachable,
    }
}

/// EOI issued by the scheduler's noreturn `run()` escapes (yieldTo's
/// disowned-current arm, and every post-suspend `hopParkRun` reached
/// from an IRQ-context caller). Those escapes abandon
/// the IRQ epilogue, so on x86 the in-service sched vector (0xFE) would
/// otherwise never be EOI'd — and because 0xFE outranks both the wake
/// IPI and tlb_shootdown (0xFD) vectors, a core that parks in that
/// state goes deaf to all of them: stranded-RDY-EC hangs and shootdown
/// initiators spinning forever on a missing ack. LAPIC EOI with an
/// empty ISR is a no-op (every syscall-path `interrupts.switchTo`
/// already issues one), so calling this from a non-IRQ yieldTo is safe.
///
/// aarch64 is a no-op: `handleIrqCurrentEl` writes ICC_EOIR1_EL1 /
/// GICC_EOIR BEFORE invoking `dispatchIrq` (early-EOI discipline, see
/// exceptions.zig), so the escape never abandons a pending EOI there —
/// and a second EOIR write for a stale INTID would corrupt GIC state.
pub fn schedulerEscapeEoi() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.apic.endOfInterrupt(),
        .aarch64 => {},
        else => unreachable,
    }
}

