const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const debug_info = zag.utils.debug_info;
const kprof_log = zag.kprof.log;
const memory = zag.memory.init;
const sched = zag.sched.scheduler;
const userspace_init = zag.boot.userspace_init;

const BootInfo = zag.boot.protocol.BootInfo;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

pub fn panic(
    msg: []const u8,
    error_return_trace: ?*std.builtin.StackTrace,
    ret_addr: ?usize,
) noreturn {
    zag.panic.panic(msg, error_return_trace, ret_addr);
}

// Override compiler-rt's `memset` (which on aarch64 is implemented with
// NEON `dup`/`stp q0,q0` instructions). The kernel's exception entry path
// does NOT save/restore Q-registers, so a page fault during the SIMD
// memset corrupts V0 across the exception, and the re-executed `stp`
// then writes whatever garbage V0 holds back into memory instead of the
// intended fill byte. The corruption is silent and hangs early boot
// when slab-allocator zero-init reads back nonzero values it just
// "wrote".
//
// Provide a non-NEON byte/word loop the linker can resolve before
// pulling in compiler-rt's SIMD version.
export fn memset(dest: [*]u8, c: u8, n: usize) [*]u8 {
    var i: usize = 0;
    while (i < n) : (i += 1) dest[i] = c;
    return dest;
}

export fn memcpy(dest: [*]u8, src: [*]const u8, n: usize) [*]u8 {
    var i: usize = 0;
    while (i < n) : (i += 1) dest[i] = src[i];
    return dest;
}

export fn memmove(dest: [*]u8, src: [*]const u8, n: usize) [*]u8 {
    if (@intFromPtr(dest) < @intFromPtr(src)) {
        var i: usize = 0;
        while (i < n) : (i += 1) dest[i] = src[i];
    } else {
        var i: usize = n;
        while (i > 0) {
            i -= 1;
            dest[i] = src[i];
        }
    }
    return dest;
}

export fn kEntry(boot_info: *BootInfo) callconv(arch.cpu.cc()) noreturn {
    arch.cpu.kEntry(boot_info, &kTrampoline);
}

export fn kTrampoline(boot_info: *BootInfo) callconv(arch.cpu.cc()) noreturn {
    kMain(boot_info) catch |err| {
        @panic(@errorName(err));
    };
    unreachable;
}

fn grantBootFramebuffer(fb: zag.boot.protocol.Framebuffer) void {
    if (fb.size == 0) return;
    const dr = zag.devices.device_region.registerFramebuffer(
        fb.base,
        fb.size,
        fb.width,
        fb.height,
        fb.stride,
        @enumFromInt(@intFromEnum(fb.pixel_format)),
    ) catch {
        arch.boot.print("[boot] WARNING: framebuffer registerFramebuffer failed\n", .{});
        return;
    };
    zag.devices.device_region.appendBootGrant(dr);
}

fn kMain(boot_info: *BootInfo) !void {
    arch.boot.init();
    try memory.init(boot_info.mmap);
    debug_info.init(boot_info.elf_blob.ptr, boot_info.elf_blob.len, boot_info.kaslr_slide);
    try arch.boot.parseFirmwareTables(boot_info.xsdp_phys);
    // Promote getMonotonicClock() from HPET MMIO to invariant TSC if the
    // CPU advertises it. Must run after parseFirmwareTables (HPET base
    // mapped) and before any code reads getMonotonicClock() — most
    // critically, schedTimerHandler reads the clock on every preempt-IPI
    // tick (§2.2.34), and a HPET vm-exit there blows the wake-to-pinned
    // budget by orders of magnitude.
    arch.time.initMonotonicClock();
    // Wall-clock anchor latches RTC against the monotonic clock once,
    // here, while IRQs are naturally off — keeps the slow x86 CMOS
    // UIP-clear loop out of the syscall path. Spec §[time].time_getwall.
    zag.syscall.system.init();
    // Hang detector — start ticking once the monotonic clock is up. Until
    // armed, every detector hook is a no-op so the very-early boot path
    // doesn't trip the threshold.
    zag.utils.hang_detector.arm();
    // Optional HPET-NMI watchdog. When `-Dkernel_hang_watchdog=true`,
    // programs HPET timer 0 in periodic FSB-NMI mode (~500 ms) so the
    // detector dump still fires when every core is parked in a user-
    // mode idle hlt loop with the LAPIC tick disarmed (the smp=4
    // lost-wakeup signature). No-op when build-disabled.
    arch.time.initHangWatchdog();
    arch.vm.vmInit();
    arch.vm.bspBootHandoff(boot_info.arrived_at_el2 != 0);
    arch.pmu.pmuInit();
    arch.cpu.sysInfoInit();
    grantBootFramebuffer(boot_info.framebuffer);
    try sched.globalInit();
    const rs_phys = PAddr.fromInt(@intFromPtr(boot_info.root_service.ptr));
    const rs_virt = VAddr.fromPAddr(rs_phys, null);
    const rs_ptr: [*]const u8 = @ptrFromInt(rs_virt.addr);
    try userspace_init.init(rs_ptr[0..boot_info.root_service.len]);
    try arch.smp.smpInit();
    zag.utils.sync.debug.markSmpReady();
    sched.perCoreInit();
    try kprof_log.init();
    kprof_log.start();
    // Spec v3: BSP enters the scheduler loop. Root EC was enqueued by
    // userspace_init.init; sched.run picks it up and dispatches.
    sched.run();
}
