const stygia = @import("stygia");

const PAddr = stygia.memory.address.PAddr;
const VAddr = stygia.memory.address.VAddr;

/// Write a u64 to a physical address via the kernel physmap. Used by
/// kernel-side propagators of handle field0/field1 updates that must
/// land in every domain-local copy of a handle (Timer counter,
/// device_region irq_count, etc.). Spec §[device_irq] §[timer].
pub fn writeU64ViaPhysmap(target_paddr: PAddr, value: u64) void {
    const vaddr = VAddr.fromPAddr(target_paddr, null);
    const ptr: *volatile u64 = @ptrFromInt(vaddr.addr);
    ptr.* = value;
}

/// Atomically add `delta` to a u64 at `target_paddr`, saturating at
/// `ceiling`. Returns the post-addition value. Used by the device IRQ
/// path to bump irq_count saturating at u64::MAX. Spec §[device_irq].
pub fn atomicAddU64Saturating(target_paddr: PAddr, delta: u64, ceiling: u64) u64 {
    const vaddr = VAddr.fromPAddr(target_paddr, null);
    const ptr: *u64 = @ptrFromInt(vaddr.addr);
    while (true) {
        const current = @atomicLoad(u64, ptr, .seq_cst);
        if (current >= ceiling) return ceiling;
        const remaining = ceiling - current;
        const add = if (delta > remaining) remaining else delta;
        const next = current + add;
        if (@cmpxchgWeak(u64, ptr, current, next, .seq_cst, .seq_cst) == null) {
            return next;
        }
    }
}
