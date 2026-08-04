pub const ArchCpuContext = struct { pc: u64 = 0 };

/// The aarch64 exception vector table: one naked function whose entries
/// `adrp` each handler out of the inline-asm operand list. Nothing calls
/// these handlers, so only the `&handler` operand binding roots them.
fn exceptionVectorTable() align(2048) callconv(.naked) void {
    asm volatile (
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[sync_current]
        \\b %[trampoline]
        :
        : [trampoline] "S" (&exceptionTrampoline),
          [unexpected] "S" (&handleUnexpected),
          [sync_current] "S" (&handleSyncCurrentEl),
          [irq_current] "S" (&handleIrqCurrentEl),
          [sync_lower] "S" (&handleSyncLowerEl),
          [irq_lower] "S" (&handleIrqLowerEl),
          [irq_extra] "S" (&handleIrqSpecial),
    );
}

fn exceptionTrampoline() callconv(.naked) void {
    asm volatile (
        \\mov x30, x0
        \\ret
    );
}

fn handleSyncLowerEl(_: *ArchCpuContext) callconv(.c) void {}
fn handleIrqLowerEl(_: *ArchCpuContext) callconv(.c) void {}
fn handleSyncCurrentEl(_: *ArchCpuContext) callconv(.c) void {}
fn handleIrqCurrentEl(_: *ArchCpuContext) callconv(.c) void {}
fn handleUnexpected(_: *ArchCpuContext) callconv(.c) void {}

/// Not in the legacy name list, so its row can only come from the
/// naked-operand rule — and its `Irq` infix is what makes it `irq`
/// rather than `exception`.
fn handleIrqSpecial(_: *ArchCpuContext) callconv(.c) void {}

/// Address-taken outside a naked fn — a plain callback, not a vector.
/// It must NOT be rooted as an interrupt entry.
pub fn install() void {
    const p = &handleSyncLowerEl;
    _ = p;
    const q = &notAVector;
    _ = q;
}

fn notAVector(_: *ArchCpuContext) callconv(.c) void {}
