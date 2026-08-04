const std = @import("std");
const stygia = @import("stygia");

const trampoline_code = @import("embedded_bins").trampoline;

const apic = stygia.arch.x64.apic;
const arch_paging = stygia.arch.x64.paging;
const cpu = stygia.arch.x64.cpu;
const exceptions = stygia.arch.x64.exceptions;
const gdt = stygia.arch.x64.gdt;
const idt = stygia.arch.x64.idt;
const interrupts = stygia.arch.x64.interrupts;
const memory_init = stygia.memory.init;
const paging = stygia.memory.paging;
const pmm = stygia.memory.pmm;
const sched = stygia.sched.scheduler;
const serial = stygia.arch.x64.serial;
const stack_mod = stygia.memory.stack;
const timers = stygia.arch.x64.timers;

const MemoryPerms = stygia.memory.address.MemoryPerms;
const PAddr = stygia.memory.address.PAddr;
const VAddr = stygia.memory.address.VAddr;

const TrampolineParams = extern struct {
    cr3: u64,
    stack_top: u64,
    entry_point: u64,
};

/// Trampoline must reside below 1 MiB — the SIPI vector encodes the page-aligned
/// start address as VV in 000VV000H.
/// Intel SDM Vol 3A, §11.4.4 "MP Initialization Example", step 10.
const TRAMPOLINE_PHYS: u64 = 0x8000;
const TRAMPOLINE_VECTOR: u8 = @intCast(TRAMPOLINE_PHYS >> 12);
const params_offset = trampoline_code.len - @sizeOf(TrampolineParams);

const KERNEL_PERMS = MemoryPerms{ .read = true, .write = true };

var cores_online: std.atomic.Value(u32) = std.atomic.Value(u32).init(1);

/// Boots all application processors via the INIT-SIPI-SIPI sequence.
/// Intel SDM Vol 3A, §11.4.3 "MP Initialization Protocol Algorithm for MP Systems"
/// Intel SDM Vol 3A, §11.4.4 "MP Initialization Example", Table 11-1 — INIT-SIPI-SIPI
/// sequence with 10 ms delay between INIT and first SIPI.
pub fn smpInit() !void {
    // Write the BSP's IA32_TSC_AUX so its later `coreID()` calls can
    // use the RDPID fast path. APs do the same in `coreInit` after
    // they discover their core_id via the slow path. After every core
    // has run, `enableRdpidFastPath()` below flips the global switch.
    apic.writeTscAuxCoreId(apic.coreIDSlow());

    for (0..apic.coreCount()) |i| {
        gdt.initForCore(i);
        // Allocate the per-core IST kernel stacks for #DF/#NMI/#MC/#PF
        // and write the tops into TSS.IST[1..4]. The CPU re-reads
        // these fields from TSS memory on every IST-using exception
        // (Intel SDM Vol 3A §7.14.5), so writes are visible to the
        // current core without an `ltr` reload — and to APs once they
        // run `loadGdt`/`ltr` in `coreInit`. We must not patch any
        // IDT gate to reference an IST slot until every core's TSS
        // is populated, which is why `wireIstGates` runs after the
        // loop completes.
        try gdt.initIst(i);
    }

    // Patch the IDT gate descriptors for #DF/#NMI/#MC/#PF so the CPU
    // hardware-switches to the per-core IST stack on entry. From this
    // point forward those exceptions cannot land on the L4 fast path's
    // `rsp = ec.kstack.top` window and corrupt `ec.ctx`.
    exceptions.wireIstGates();

    const trampoline_phys = PAddr.fromInt(TRAMPOLINE_PHYS);
    const trampoline_virt = VAddr.fromInt(TRAMPOLINE_PHYS);

    try arch_paging.mapPage(
        memory_init.kernel_addr_space_root,
        trampoline_phys,
        trampoline_virt,
        .{ .read = true, .write = true, .exec = true },
        .kernel_data,
    );

    const dest: [*]u8 = @ptrFromInt(trampoline_virt.addr);
    @memcpy(dest[0..trampoline_code.len], trampoline_code);

    const params: *TrampolineParams = @ptrFromInt(trampoline_virt.addr + params_offset);
    params.cr3 = stygia.arch.x64.paging.getAddrSpaceRoot().addr;
    params.entry_point = @intFromPtr(&coreInit);

    const bsp_id = apic.rawApicId();

    const pmm_mgr = &pmm.global_pmm.?;
    var hpet = &timers.hpet_timer;
    const hpet_iface = hpet.timer();

    for (apic.lapics.?) |la| {
        if (la.apic_id == bsp_id) {
            continue;
        }

        const ap_stack = try stack_mod.createKernel();

        var page_addr = ap_stack.base.addr;
        var map_ok = true;
        while (page_addr < ap_stack.top.addr) {
            const kpage = pmm_mgr.create(paging.PageMem(.page4k)) catch {
                map_ok = false;
                break;
            };
            const kphys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(kpage)), null);
            arch_paging.mapPage(memory_init.kernel_addr_space_root, kphys, VAddr.fromInt(page_addr), KERNEL_PERMS, .kernel_data) catch {
                pmm_mgr.destroy(kpage);
                map_ok = false;
                break;
            };
            page_addr += paging.PAGE4K;
        }

        if (!map_ok) {
            stack_mod.destroyKernel(ap_stack);
            continue;
        }

        params.stack_top = stygia.memory.address.alignStack(ap_stack.top).addr;

        const expected = cores_online.load(.acquire);
        // Intel SDM Vol 3A, §11.4.4, Table 11-1: send INIT IPI, wait 10 ms,
        // then send SIPI. A second SIPI is not sent; we rely on the 100 ms
        // timeout to detect APs that fail to come online.
        apic.sendInitIpi(la.apic_id);

        const start = hpet_iface.now();
        while (hpet_iface.now() - start < 10_000_000) {
            std.atomic.spinLoopHint();
        }

        apic.sendSipi(la.apic_id, TRAMPOLINE_VECTOR);

        const timeout = hpet_iface.now();
        while (cores_online.load(.acquire) == expected) {
            if (hpet_iface.now() - timeout > 100_000_000) {
                // Deliberately LEAK the stack instead of reclaiming it.
                // The SIPI above was already delivered and is never
                // rescinded, so this AP is not stopped — merely late. It
                // is somewhere between the trampoline's first instruction
                // and `coreInit`, and `params.stack_top` still points into
                // `ap_stack`. `destroyKernel` unmaps those pages and hands
                // them back to the PMM, where `stack.zig`'s LIFO freelist
                // makes the reuse deterministic: the very next
                // `createKernel` gets the same pages. That turns "AP is
                // late" into a live core executing on someone else's
                // kernel stack, on a core the BSP has stopped accounting
                // for — silent cross-core stack corruption rather than a
                // clean failure.
                //
                // This mirrors the aarch64 bring-up path, which already
                // leaks here for exactly this reason after it was measured
                // on the bare-metal Pi 5 (all three APs timed out, then
                // faulted their way into the log hundreds of batches
                // later, two concurrently). QEMU/KVM brings APs up fast
                // enough that the x86 timeout effectively never fires,
                // which is why this side kept the unsafe reclaim.
                //
                // A bounded, one-time leak of one kstack, paid only on a
                // bring-up failure that has already gone wrong.
                serial.print(
                    "[smp] core (apic {d}): SIPI sent but core never signalled online" ++
                        " (kstack leaked; it may still arrive)\n",
                    .{la.apic_id},
                );
                break;
            }
            std.atomic.spinLoopHint();
        }
    }

    // All online APs have run `writeTscAuxCoreId` on themselves before
    // bumping `cores_online` (see coreInit below); the BSP did the same
    // at the top of this function. Safe to flip the global RDPID flag.
    apic.enableRdpidFastPath();

    // Every AP that is going to come up has come up, so an ack-waiting
    // remote shootdown can no longer block on a core that was never
    // started. Arms `paging.publishKernelUnmapEpoch`'s remote half —
    // before this point it degrades to a local flush, which is exactly
    // what the bring-up path above needs when it tears down a kstack
    // whose mapping failed.
    arch_paging.armRemoteShootdown();
}

/// AP initialization entry point — corresponds to the "Typical AP Initialization Sequence"
/// in Intel SDM Vol 3A, §11.4.4.2.
fn coreInit() callconv(.c) noreturn {
    gdt.loadGdt(0);
    gdt.reloadSegments();
    cpu.lidt(&idt.idt_ptr);

    if (apic.x2_apic) {
        _ = cpu.enableX2Apic(@intFromEnum(interrupts.IntVecs.spurious));
    } else {
        apic.enableSpuriousVector(@intFromEnum(interrupts.IntVecs.spurious));
    }

    const core_id = apic.coreIDSlow();
    apic.writeTscAuxCoreId(core_id);
    gdt.loadGdt(core_id);
    cpu.ltr(gdt.TSS_OFFSET);

    cpu.initSyscall(@intFromPtr(&interrupts.syscallEntry));
    interrupts.initSyscallScratch(core_id);
    cpu.initPat();
    cpu.enableSmapSmep();
    cpu.enablePcid();
    cpu.enableSpeculationBarriers();
    _ = cores_online.fetchAdd(1, .release);
    sched.perCoreInit();

    // Visual confirmation that this AP reached the scheduler. Printed
    // from inside the AP — serial driver is multi-core safe via its
    // print_lock (see arch/x64/serial.zig).
    serial.print("[ap {}] entering sched.run\n", .{core_id});

    // Drop into the scheduler loop. APs start with empty run queues
    // and no per-core idle EC, so `sched.run` will fall through to
    // `sti+hlt` and wait for a cross-core wake / preempt IPI from
    // `enqueueOnCore`. `sched.run` is `noreturn`.
    sched.run();
}
