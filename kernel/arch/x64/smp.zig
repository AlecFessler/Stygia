const std = @import("std");
const zag = @import("zag");

const trampoline_code = @import("embedded_bins").trampoline;

const apic = zag.arch.x64.apic;
const arch_paging = zag.arch.x64.paging;
const cpu = zag.arch.x64.cpu;
const gdt = zag.arch.x64.gdt;
const idt = zag.arch.x64.idt;
const interrupts = zag.arch.x64.interrupts;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const sched = zag.sched.scheduler;
const serial = zag.arch.x64.serial;
const stack_mod = zag.memory.stack;
const timers = zag.arch.x64.timers;

const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

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
    }

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
    params.cr3 = zag.arch.x64.paging.getAddrSpaceRoot().addr;
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
            stack_mod.destroyKernel(ap_stack, memory_init.kernel_addr_space_root);
            continue;
        }

        params.stack_top = zag.memory.address.alignStack(ap_stack.top).addr;

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
                stack_mod.destroyKernel(ap_stack, memory_init.kernel_addr_space_root);
                break;
            }
            std.atomic.spinLoopHint();
        }
    }

    // All online APs have run `writeTscAuxCoreId` on themselves before
    // bumping `cores_online` (see coreInit below); the BSP did the same
    // at the top of this function. Safe to flip the global RDPID flag.
    apic.enableRdpidFastPath();
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
