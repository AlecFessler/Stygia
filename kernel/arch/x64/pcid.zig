const std = @import("std");
const stygia = @import("stygia");

const cpu = stygia.arch.x64.cpu;
const paging = stygia.arch.x64.paging;

const SpinLock = stygia.utils.sync.SpinLock;

/// Bitmap-based PCID (Process Context Identifier) allocator.
///
/// Intel SDM Vol 3A, Section 5.10.1 — Process-Context Identifiers (PCIDs).
/// PCIDs are 12-bit IDs (0..4095) placed in CR3[11:0] (when CR4.PCIDE=1) to
/// tag TLB entries so address-space switches do not flush the TLB.
///
/// Bit convention: 1 = allocated, 0 = free.
/// Id 0 is reserved as the boot/kernel sentinel (the value CR3 uses when
/// CR4.PCIDE=0) and is never handed out.
///
/// The allocator owns the full lifecycle: `free(id)` is the only release
/// path, and it invalidates every TLB entry tagged with `id` on the local
/// core before returning the slot to the bitmap. A future re-allocation
/// of the same id therefore cannot inherit stale mappings from the
/// previous owner.

const pcid_bits: u16 = 12;
const pcid_count: u16 = 1 << pcid_bits;
const word_bits: u16 = 64;
const word_count: u16 = pcid_count / word_bits;

var bitmap: [word_count]u64 = init: {
    var b = [_]u64{0} ** word_count;
    b[0] = 1;
    break :init b;
};
var hint: u16 = 0;
var lock: SpinLock = .{ .class = "pcid.lock" };

pub fn allocate() ?u16 {
    const irq_state = lock.lockIrqSave(@src());
    defer lock.unlockIrqRestore(irq_state);

    var scanned: u16 = 0;
    var w: u16 = hint;
    while (scanned < word_count) {
        const word = bitmap[w];
        if (word != ~@as(u64, 0)) {
            const free_bit: u6 = @intCast(@ctz(~word));
            bitmap[w] = word | (@as(u64, 1) << free_bit);
            hint = w;
            return w * word_bits + @as(u16, free_bit);
        }
        w = (w + 1) % word_count;
        scanned += 1;
    }
    return null;
}

pub fn free(id: u16) void {
    std.debug.assert(id != 0);
    std.debug.assert(id < pcid_count);

    // Flush remote cores' TLB entries for this PCID before recycling.
    // A core that previously ran the dying domain may still hold stale
    // PCID-tagged entries; if the PCID is reused for a new domain
    // before those clear naturally, the new domain's user-half VAs
    // can resolve to the dying domain's freed physical pages —
    // particularly dangerous now that the destroy path returns those
    // pages to PMM via `freeUserAddrSpace` (vs the prior leak-style
    // teardown that left them quiescent). See SDM Vol 2A INVPCID type
    // 1 (single-PCID, all addresses).
    paging.flushRemotePcid(id);
    invalidateTlb(id);

    const irq_state = lock.lockIrqSave(@src());
    defer lock.unlockIrqRestore(irq_state);

    const w: u16 = id / word_bits;
    const b: u6 = @intCast(id % word_bits);
    const mask = @as(u64, 1) << b;
    std.debug.assert((bitmap[w] & mask) != 0);
    bitmap[w] &= ~mask;
    if (w < hint) hint = w;
}

/// Invalidate every TLB entry tagged with `id` on the local core. Called
/// by `free` before the id returns to the bitmap so a future owner of the
/// same id does not inherit stale mappings.
///
/// Uses INVPCID type 1 (single PCID, all addresses). Intel SDM Vol 2A —
/// INVPCID; Vol 3A §5.10.4.1.
///
/// TODO: SMP shootdown. Other cores may still hold TLB entries for `id`
/// from prior runs of the dying process. Until the existing per-page IPI
/// shootdown is extended with a per-PCID variant, recycling a freed PCID
/// onto a different core can read a stale mapping. The current
/// single-core / pinned-process workloads are correct.
fn invalidateTlb(id: u16) void {
    if (!cpu.pcid_enabled) return;
    const desc: [2]u64 align(16) = .{ @as(u64, id) & 0xFFF, 0 };
    asm volatile ("invpcid (%[desc]), %[type]"
        :
        : [desc] "r" (&desc),
          [type] "r" (@as(u64, 1)),
        : .{ .memory = true });
}
