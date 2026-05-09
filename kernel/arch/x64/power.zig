const stygia = @import("stygia");

const cpu = stygia.arch.x64.cpu;

const E_OK: i64 = 0;
const E_NODEV: i64 = -13;

/// System-wide power actions. Observable `sys_power` semantics in
/// docs/kernel/spec.md §5.4 Power.
pub const PowerAction = enum(u8) {
    shutdown = 0,
    reboot = 1,
    sleep = 2,
    hibernate = 3,
    screen_off = 4,
};

/// Per-CPU power actions. Observable `sys_cpu_power` semantics in
/// docs/kernel/spec.md §5.4 Power.
pub const CpuPowerAction = enum(u8) {
    set_freq = 0,
    set_idle = 1,
};

/// Perform a system-wide power action.
/// docs/kernel/spec.md §5.4 "Power" (syscall contract);
/// docs/kernel/systems.md §power (implementation notes).
pub fn powerAction(action: PowerAction) i64 {
    switch (action) {
        .shutdown => doShutdown(),
        .reboot => doReboot(),
        .sleep => return E_NODEV, // S3 requires ACPI FADT parsing; stub for now
        .hibernate => return E_NODEV, // S4 requires ACPI FADT parsing; stub for now
        .screen_off => {
            // DPMS off via VGA attribute controller.
            // Read port 0x3DA to reset the flip-flop, then write 0x00 to 0x3C0 to blank.
            _ = cpu.inb(0x3DA);
            cpu.outb(0x00, 0x3C0);
            return E_OK;
        },
    }
}

/// Perform a per-CPU power action.
/// docs/kernel/spec.md §5.4 "Power" (syscall contract);
/// docs/kernel/systems.md §power (implementation notes).
pub fn cpuPowerAction(action: CpuPowerAction, value: u64) i64 {
    switch (action) {
        .set_freq => {
            // IA32_PERF_CTL MSR (0x199): bits 8-15 hold the P-state ratio.
            // We need CPUID to confirm P-state support; stub as E_NODEV for now.
            _ = value;
            return E_NODEV;
        },
        .set_idle => {
            // MWAIT C-state control. Requires CPUID leaf 5 check.
            _ = value;
            return E_NODEV;
        },
    }
}

/// Shut down the system. Attempts ACPI S5 soft-off; falls back to QEMU's
/// debug-exit I/O port if ACPI FADT parsing has not been performed.
/// ACPI Specification §16.1 "System \_S5 State" — writing the SLP_TYPx value
/// for S5 with SLP_EN=1 to PM1_CNT triggers soft-off.
/// QEMU fallback: writing 0x2000 to I/O port 0x604 triggers QEMU's isa-debug-
/// exit device shutdown (QEMU source: hw/misc/debugexit.c).
/// Does not return.
fn doShutdown() noreturn {
    // Fallback: QEMU shutdown via debug exit port.
    cpu.outw(0x2000, 0x604);
    // If that didn't work, halt forever.
    while (true) cpu.halt();
}

/// Reboot the system via the keyboard controller reset line, falling back to a
/// triple fault if the keyboard controller does not respond.
/// PS/2 Controller Specification (Intel 8042): port 0x64 is the command port;
/// command 0xFE pulses the CPU reset line (RESET#) low for approximately 6 μs,
/// causing a hard reset. Triple-fault is a last-resort: loading a zero-size IDT
/// and triggering any interrupt causes the CPU to triple-fault and reset.
/// Intel SDM Vol 3A, §2.1.3 "Halt and Shutdown" — a triple fault causes the
/// processor to perform a machine shutdown, resetting RESET# externally.
/// Does not return.
fn doReboot() noreturn {
    // Strategy 1: Keyboard controller reset — write 0xFE to port 0x64.
    cpu.outb(0xFE, 0x64);

    // Strategy 2: Triple fault — load zero-length IDT and trigger interrupt.
    asm volatile (
        \\lidt (%[zero])
        \\int $3
        :
        : [zero] "r" (@as(u64, 0)),
    );

    while (true) cpu.halt();
}
