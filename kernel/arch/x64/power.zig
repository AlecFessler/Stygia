const stygia = @import("stygia");

const cpu = stygia.arch.x64.cpu;

/// Internal reboot path used when the test-profile boot root finishes.
pub const PowerAction = enum(u8) {
    reboot = 1,
};

/// Reboot the test system after the root service reports its verdict.
pub fn powerAction(action: PowerAction) i64 {
    switch (action) {
        .reboot => doReboot(),
    }
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
