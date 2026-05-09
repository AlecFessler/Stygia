//! linux_guest — VMM for booting Linux on Stygia.
//!
//! Spec-v3 port. The lifecycle:
//!   1. Discover COM1 device_region (log.init).
//!   2. Allocate a page_frame for the VmPolicy struct; map it locally
//!      via createVmar + mapPf so we can write the policy bytes.
//!   3. createVirtualMachine(caps, policy_pf).
//!   4. mem.setupGuestMemory: createPageFrame for guest RAM; map_guest
//!      into the VM at gpa 0; createVmar + mapPf locally so the VMM can
//!      read/write guest memory by host VA.
//!   5. Optional: vm_set_policy to seed CPUID + CR tables (skipped for
//!      now; all CPUID/CR exits route to userspace).
//!   6. createPort.
//!   7. createVcpu(caps, vm, affinity = 0, exit_port = port).
//!   8. recvVmExit returns the initial-state synthetic exit (zeroed
//!      guest state, subcode = 0). Populate VmExitState with the Linux
//!      boot-protocol initial state and replyVmExit.
//!   9. Loop on recvVmExit; dispatch to per-subcode handlers; reply
//!      with mods.
//!  10. On fatal exit (triple_fault / shutdown), powerShutdown.

const lib = @import("lib");

const acpi = @import("acpi.zig");
const assets = @import("assets");
const boot = @import("boot.zig");
const cpuid = @import("cpuid.zig");
const disk = @import("disk.zig");
const io = @import("io.zig");
const log = @import("log.zig");
const mem = @import("mem.zig");
const msr = @import("msr.zig");
const serial = @import("serial.zig");
const vm_exit = @import("vm_exit.zig");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;

const HandleId = caps.HandleId;
const PortCap = caps.PortCap;

/// Re-export VmExitState as `GuestState` so the per-exit handler
/// modules (cpuid.zig, io.zig, msr.zig, …) — which read/write
/// `state.rax` / `state.rip` / `state.cr0` etc. — keep compiling
/// without per-call changes. The new vreg-backed VmExitState carries
/// the same canonical-name GPR/CR/segment fields as the old kernel-IPC
/// extern struct.
pub const GuestState = vm_exit.VmExitState;
pub const SegmentReg = vm_exit.SegmentReg;

/// VmExit subcode constants — kept around for callsites that match by
/// number rather than the enum (a handful of legacy switch-style sites
/// in handlers).
pub const EXIT_CPUID: u8 = @intFromEnum(vm_exit.VmExitSubcode.cpuid);
pub const EXIT_IO: u8 = @intFromEnum(vm_exit.VmExitSubcode.io);
pub const EXIT_MMIO: u8 = @intFromEnum(vm_exit.VmExitSubcode.mmio);
pub const EXIT_CR: u8 = @intFromEnum(vm_exit.VmExitSubcode.cr);
pub const EXIT_MSR_R: u8 = @intFromEnum(vm_exit.VmExitSubcode.msr_r);
pub const EXIT_MSR_W: u8 = @intFromEnum(vm_exit.VmExitSubcode.msr_w);
pub const EXIT_EPT: u8 = @intFromEnum(vm_exit.VmExitSubcode.ept);
pub const EXIT_EXCEPT: u8 = @intFromEnum(vm_exit.VmExitSubcode.except);
pub const EXIT_INTWIN: u8 = @intFromEnum(vm_exit.VmExitSubcode.intwin);
pub const EXIT_HLT: u8 = @intFromEnum(vm_exit.VmExitSubcode.hlt);
pub const EXIT_SHUTDOWN: u8 = @intFromEnum(vm_exit.VmExitSubcode.shutdown);
pub const EXIT_TRIPLE: u8 = @intFromEnum(vm_exit.VmExitSubcode.triple);
pub const EXIT_UNKNOWN: u8 = @intFromEnum(vm_exit.VmExitSubcode.unknown);

// Guest physical memory layout
const GUEST_RAM_LINUX: u64 = 128 * 1024 * 1024;
const TEMP_ADDR: u64 = 0x2000000;

// Globals (must not be on stack — Debug-mode probes overflow 32KB).
var bp_buf: [4096]u8 align(8) = .{0} ** 4096;

pub var vm_handle: HandleId = 0;
pub var vcpu_handle: HandleId = 0;
pub var exit_port: HandleId = 0;
pub var first_exit_pending: bool = true;
pub var guest_state: GuestState = .{};

var exit_count: u64 = 0;
var cpuid_count: u64 = 0;
var io_count: u64 = 0;
var msr_r_count: u64 = 0;
var msr_w_count: u64 = 0;
var cr_count: u64 = 0;
var hlt_count: u64 = 0;
var ept_count: u64 = 0;
var intr_count: u64 = 0;
var other_count: u64 = 0;

pub fn main(cap_table_base: u64) void {
    log.init(cap_table_base);
    log.print("\n=== linux_guest (spec-v3) ===\n");

    // Step 1 — Allocate VmPolicy page_frame. The kernel reads it on VM
    // creation to validate (sizeof, num_*) and retains a ref. We zero
    // the whole frame; CPUID/CR policies stay empty so all such exits
    // route to userspace handlers.
    const policy_pf = mem.allocPolicyPageFrame() orelse {
        log.print("policy_pf alloc failed\n");
        _ = syscall.powerShutdown();
        while (true) asm volatile ("hlt");
    };

    // Step 2 — createVirtualMachine.
    //   caps.policy = bit 0 of cap word (we'd want this for vm_set_policy
    //   later). Ceiling check is against the calling domain's vm_ceiling.
    const vm_caps_word: u64 = (1 << 0); // policy
    const vm_r = syscall.createVirtualMachine(vm_caps_word, policy_pf);
    if (vm_r.v1 < 16) {
        log.print("createVirtualMachine failed: ");
        log.dec(vm_r.v1);
        log.print("\n");
        _ = syscall.powerShutdown();
        while (true) asm volatile ("hlt");
    }
    vm_handle = @truncate(vm_r.v1 & 0xFFF);
    log.print("VM handle=");
    log.dec(vm_handle);
    log.print("\n");

    // Step 3 — Allocate guest RAM, map into VM, and map locally for
    // VMM-side reads/writes.
    if (!mem.setupGuestMemory(GUEST_RAM_LINUX)) {
        log.print("guest RAM setup failed\n");
        _ = syscall.powerShutdown();
        while (true) asm volatile ("hlt");
    }

    // Step 4 — Discover host serial (already done by log.init for
    // output) and bridge for guest RX.
    serial.init(cap_table_base);

    // Step 5 — Boot Linux. Try NVMe asset, fall back to embedded
    // bzImage/initramfs from the assets module.
    if (disk.init(cap_table_base)) {
        bootLinux();
    } else {
        bootLinuxEmbedded();
    }

    // Step 6 — createPort for vCPU exit delivery. `bind` is required so
    // create_vcpu can attach this as the vCPU's exit_port (spec §
    // [virtual_machine] create_vcpu test on port_caps.bind).
    const port_caps_word: u64 = @as(u64, (PortCap{
        .recv = true,
        .bind = true,
    }).toU16());
    const port_r = syscall.createPort(port_caps_word);
    if (port_r.v1 < 16) {
        log.print("createPort failed: ");
        log.dec(port_r.v1);
        log.print("\n");
        _ = syscall.powerShutdown();
        while (true) asm volatile ("hlt");
    }
    exit_port = @truncate(port_r.v1 & 0xFFF);
    log.print("exit_port=");
    log.dec(exit_port);
    log.print("\n");

    // Step 7 — createVcpu bound to the VM and exit_port. The kernel
    // immediately enqueues an initial-state synthetic vm_exit on
    // exit_port.
    //   caps: rwx + read + write (gating event-state vreg read/write
    //   on recv/reply). Priority defaults to 0.
    const vcpu_caps_word: u64 = 0; // no special caps for vcpu EC handle
    const vcpu_r = syscall.createVcpu(vcpu_caps_word, vm_handle, 0, exit_port);
    if (vcpu_r.v1 < 16) {
        log.print("createVcpu failed: ");
        log.dec(vcpu_r.v1);
        log.print("\n");
        _ = syscall.powerShutdown();
        while (true) asm volatile ("hlt");
    }
    vcpu_handle = @truncate(vcpu_r.v1 & 0xFFF);
    log.print("vcpu=");
    log.dec(vcpu_handle);
    log.print("\n");

    // Step 8/9 — Run the exit loop.
    exitLoop();

    // Stats
    log.print("\n=== ");
    log.dec(exit_count);
    log.print(" exits (CPUID/IO/MSR_R/MSR_W/CR/HLT/EPT/other: ");
    log.dec(cpuid_count);
    log.print("/");
    log.dec(io_count);
    log.print("/");
    log.dec(msr_r_count);
    log.print("/");
    log.dec(msr_w_count);
    log.print("/");
    log.dec(cr_count);
    log.print("/");
    log.dec(hlt_count);
    log.print("/");
    log.dec(ept_count);
    log.print("/");
    log.dec(other_count);
    log.print(") ===\n");

    _ = syscall.powerShutdown();
    while (true) asm volatile ("hlt");
}

/// Linux boot setup — NVMe path. Stack-isolated so the VMM driver
/// stack frames don't pin into our caller.
noinline fn bootLinux() void {
    const hdr = disk.readHeader() orelse {
        log.print("Bad disk header\n");
        _ = syscall.powerShutdown();
        while (true) asm volatile ("hlt");
    };

    mem.mapMmioStubs();

    log.print("Loading bzImage");
    if (!disk.loadToGuest(hdr.bzimage_offset, hdr.bzimage_size, TEMP_ADDR)) {
        log.print(" FAILED\n");
        _ = syscall.powerShutdown();
        while (true) asm volatile ("hlt");
    }
    log.print(" done\n");

    log.print("Loading initramfs");
    if (!disk.loadToGuest(hdr.initramfs_offset, hdr.initramfs_size, boot.INITRAMFS_ADDR)) {
        log.print(" FAILED\n");
        _ = syscall.powerShutdown();
        while (true) asm volatile ("hlt");
    }
    log.print(" done\n");

    const m0 = mem.readGuestByte(boot.INITRAMFS_ADDR);
    const m1 = mem.readGuestByte(boot.INITRAMFS_ADDR + 1);
    log.print("initramfs magic: ");
    log.hex8(m0);
    log.print(" ");
    log.hex8(m1);
    log.print(" size=");
    log.dec(hdr.initramfs_size);
    log.print("\n");

    const ss = mem.readGuestByte(TEMP_ADDR + 0x1F1);
    const setup_sects: u32 = if (ss == 0) 4 else @as(u32, ss);
    const setup_size: u64 = (@as(u64, setup_sects) + 1) * 512;
    log.print("setup_sects=");
    log.dec(setup_sects);
    log.print("\n");

    mem.copyGuest(boot.KERNEL_ADDR, TEMP_ADDR + setup_size, hdr.bzimage_size - setup_size);

    buildBootParams(hdr.initramfs_size);
    boot.setupCmdline("console=ttyS0,115200n8 earlycon=uart,io,0x3f8,115200n8 earlyprintk=serial,ttyS0,115200,keep nokaslr nohpet maxcpus=1 tsc=reliable lpj=5000000 ignore_loglevel");
    acpi.setupTables();
    setupLinuxState();
    log.print("Linux configured\n");
}

/// Embedded-asset fallback when NVMe is unavailable.
noinline fn bootLinuxEmbedded() void {
    log.print("Using embedded assets\n");
    mem.mapMmioStubs();

    const bzimage = assets.bzimage;
    const initramfs_data = assets.initramfs;

    const ss = bzimage[0x1F1];
    const setup_sects: u32 = if (ss == 0) 4 else @as(u32, ss);
    const setup_size: u64 = (@as(u64, setup_sects) + 1) * 512;
    log.print("setup_sects=");
    log.dec(setup_sects);
    log.print("\n");

    const pm_kernel = bzimage[setup_size..];
    mem.writeGuest(boot.KERNEL_ADDR, pm_kernel);
    mem.writeGuest(TEMP_ADDR, bzimage[0..setup_size]);
    mem.writeGuest(boot.INITRAMFS_ADDR, initramfs_data);
    log.print("initramfs size=");
    log.dec(initramfs_data.len);
    log.print("\n");

    buildBootParams(initramfs_data.len);
    boot.setupCmdline("console=ttyS0,115200n8 earlycon=uart,io,0x3f8,115200n8 earlyprintk=serial,ttyS0,115200,keep nokaslr nohpet maxcpus=1 tsc=reliable lpj=5000000 ignore_loglevel");
    acpi.setupTables();
    setupLinuxState();
    log.print("Linux configured (embedded)\n");
}

noinline fn buildBootParams(initramfs_size: u64) void {
    @memset(&bp_buf, 0);
    const hdr_src = mem.readGuestSlice(TEMP_ADDR + 0x1F1, 0x290 - 0x1F1);
    @memcpy(bp_buf[0x1F1..0x290], hdr_src);

    bp_buf[0x210] = 0xFF; // type_of_loader
    bp_buf[0x211] = bp_buf[0x211] | 0x01 | 0x40 | 0x80; // LOADED_HIGH | KEEP_SEGMENTS | CAN_USE_HEAP

    writeU32(&bp_buf, 0x228, @intCast(boot.CMDLINE_ADDR));
    writeU16(&bp_buf, 0x224, 0xDE00);
    writeU16(&bp_buf, 0x1FA, 0xFFFF); // vid_mode

    writeU32(&bp_buf, 0x218, @intCast(boot.INITRAMFS_ADDR));
    writeU32(&bp_buf, 0x21C, @intCast(initramfs_size));

    // E820 memory map
    const e: usize = 0x2D0;
    writeU64(&bp_buf, e, 0);
    writeU64(&bp_buf, e + 8, 0x9FC00);
    writeU32(&bp_buf, e + 16, 1);
    writeU64(&bp_buf, e + 20, 0x9FC00);
    writeU64(&bp_buf, e + 28, 0x400);
    writeU32(&bp_buf, e + 36, 2);
    writeU64(&bp_buf, e + 40, 0xE0000);
    writeU64(&bp_buf, e + 48, 0x20000);
    writeU32(&bp_buf, e + 56, 2);
    writeU64(&bp_buf, e + 60, 0x100000);
    writeU64(&bp_buf, e + 68, GUEST_RAM_LINUX - 0x100000);
    writeU32(&bp_buf, e + 76, 1);
    bp_buf[0x1E8] = 4;

    mem.writeGuest(boot.BOOT_PARAMS_ADDR, &bp_buf);
    log.print("boot_params OK\n");
}

noinline fn setupLinuxState() void {
    guest_state = .{};
    // 32-bit protected mode, paging off — Linux boot protocol entry
    // (https://hv.smallkirby.com/en/vmm/linux_boot).
    guest_state.rip = boot.KERNEL_ADDR; // 0x100000
    guest_state.rsi = boot.BOOT_PARAMS_ADDR; // 0x10000
    guest_state.rflags = 0x2;
    guest_state.cr0 = 0x11; // PE + ET
    guest_state.cr4 = 0;
    guest_state.efer = 0;

    guest_state.cs = .{ .base = 0, .limit = 0xFFFFFFFF, .selector = 0, .access_rights = 0x0C9B };
    const ds = SegmentReg{ .base = 0, .limit = 0xFFFFFFFF, .selector = 0, .access_rights = 0x0C93 };
    guest_state.ds = ds;
    guest_state.es = ds;
    guest_state.fs = ds;
    guest_state.gs = ds;
    guest_state.ss = ds;
    guest_state.rsp = 0x0FFF0;
    guest_state.tr = .{ .base = 0, .limit = 0xFFFF, .selector = 0, .access_rights = 0x008B };
    guest_state.ldtr = .{ .base = 0, .limit = 0xFFFF, .selector = 0, .access_rights = 0x0082 };
    guest_state.pat = 0x0007040600070406;
    guest_state.dr6 = 0xFFFF0FF0;
    guest_state.dr7 = 0x400;
}

/// VM exit handling loop. Runs until a fatal subcode (shutdown / triple)
/// or a recv error.
noinline fn exitLoop() void {
    log.print("entering exit loop\n");
    // Timeout-based polling cadence: when the guest is idle (HLT or busy
    // doing pure compute that doesn't trap), recv returns E_TIMEOUT after
    // the given window so the VMM can tick the emulated PIT and poll
    // host serial RX. Linux's `check_timer` waits ~100ms for PIT IRQ0
    // fires; 1 ms is well below that threshold and gives plenty of
    // periodic-timer fires within Linux's measurement window.
    const RECV_POLL_NS: u64 = 1_000_000; // 1 ms
    while (true) {
        const r = vm_exit.recvVmExit(exit_port, RECV_POLL_NS);
        if (r.err == @intFromEnum(errors.Error.E_TIMEOUT) or r.event_type == 0) {
            // No exit pending; tick PIT + serial RX and re-poll.
            io.pitCheckIrq();
            if (serial.irq_pending) {
                serial.irq_pending = false;
                _ = syscall.vmInjectIrq(vm_handle, 4, 1);
                _ = syscall.vmInjectIrq(vm_handle, 4, 0);
            }
            continue;
        }
        if (r.err != 0) {
            log.print("recvVmExit err=");
            log.dec(r.err);
            log.print("\n");
            break;
        }

        exit_count += 1;
        if (exit_count <= 5 or exit_count % 25 == 0) {
            log.print("exit#");
            log.dec(exit_count);
            log.print(" et=");
            log.dec(r.event_type);
            log.print(" subcode=");
            log.dec(r.state.exit_subcode);
            log.print(" rip=0x");
            log.hex64(r.state.rip);
            log.print("\n");
        }

        if (first_exit_pending) {
            // Initial-state synthetic exit — kernel hands us zeroed
            // guest state; we install the Linux boot-protocol state
            // and reply.
            first_exit_pending = false;
            log.print("reply#1 rip=0x");
            log.hex64(guest_state.rip);
            log.print(" cs.base=0x");
            log.hex64(guest_state.cs.base);
            log.print(" cr0=0x");
            log.hex64(guest_state.cr0);
            log.print("\n");
            const reply_err = vm_exit.replyVmExit(r.reply_handle_id, guest_state);
            if (reply_err != 0) {
                log.print("initial replyVmExit err=");
                log.dec(reply_err);
                log.print("\n");
                break;
            }
            continue;
        }

        var state = r.state;
        // recvVmExit projects vreg 64 from `vm_exit_buf`, which retains
        // whatever the VMM wrote on the prior reply. Clear it so a
        // stale value can't sneak back as a fresh injection request —
        // the kernel-emulated LAPIC drives all timer/EOI delivery now,
        // and the VMM only sets vreg 64 if it has a real interrupt to
        // inject (currently nothing does).
        state.vcpu_event_intr_nmi = 0;
        const subcode: u8 = @truncate(state.exit_subcode);
        const kill = handleSubcode(subcode, &state);

        if (kill) {
            // Drop the reply handle implicitly by replying with the
            // current state (the kernel will re-enter; subsequent exits
            // will walk back here). For a clean exit we just break out.
            // SPEC AMBIGUITY: spec doesn't define "kill" — a reply still
            // resumes the guest. For triple-fault / shutdown we just
            // drop out of the loop and shut the VMM down.
            break;
        }

        // Route serial RX → IRQ 4 if the host serial polled some bytes.
        if (serial.irq_pending) {
            serial.irq_pending = false;
            _ = syscall.vmInjectIrq(vm_handle, 4, 1);
            _ = syscall.vmInjectIrq(vm_handle, 4, 0);
        }

        // PIT tick — fires IRQ0 via the in-kernel IOAPIC for guests that
        // still listen to the 8254. Linux runs with full APIC, so it
        // mostly uses the LAPIC timer (driven by the kernel's per-
        // iteration `vm_ptr.lapic.tick(elapsed_ns)` inside the run
        // loop), but `check_timer` still expects PIT ticks during boot.
        io.pitCheckIrq();

        const reply_err = vm_exit.replyVmExit(r.reply_handle_id, state);
        if (reply_err != 0) {
            log.print("replyVmExit err=");
            log.dec(reply_err);
            log.print("\n");
            break;
        }
    }
}

/// Dispatch a single exit. Returns true iff this is a fatal subcode
/// (triple_fault / shutdown) and the loop should terminate.
noinline fn handleSubcode(subcode: u8, state: *GuestState) bool {
    if (subcode == EXIT_CPUID) {
        cpuid_count += 1;
        cpuid.handle(state);
        return false;
    }
    if (subcode == EXIT_IO) {
        io_count += 1;
        // §[vm_exit_state] x86-64 IO payload:
        //   exit_payload[0] = next_rip
        //   exit_payload[1] = {value u32 [0..31], port u16 [32..47],
        //                      size u8 [48..55], is_write u8 [56..63]}
        const next_rip = state.exit_payload[0];
        const ioword = state.exit_payload[1];
        const value: u32 = @truncate(ioword);
        const port: u16 = @truncate(ioword >> 32);
        const size: u8 = @truncate(ioword >> 48);
        const is_write: bool = ((ioword >> 56) & 1) != 0;
        if (is_write) {
            io.handleOut(port, size, value, state);
        } else {
            const v = io.handleIn(port, size, state);
            if (size == 1) state.rax = (state.rax & ~@as(u64, 0xFF)) | @as(u64, v & 0xFF) else if (size == 2) state.rax = (state.rax & ~@as(u64, 0xFFFF)) | @as(u64, v & 0xFFFF) else state.rax = v;
        }
        state.rip = next_rip;
        return false;
    }
    if (subcode == EXIT_MSR_R) {
        msr_r_count += 1;
        const idx: u32 = @truncate(state.exit_payload[1]);
        msr.handleRead(idx, state);
        return false;
    }
    if (subcode == EXIT_MSR_W) {
        msr_w_count += 1;
        const idx: u32 = @truncate(state.exit_payload[1]);
        msr.handleWrite(idx, state);
        return false;
    }
    if (subcode == EXIT_CR) {
        cr_count += 1;
        // §[vm_exit_state] x86-64 CR payload:
        //   exit_payload[0] = value
        //   exit_payload[1] = packed {cr_num u4, is_write u1, gpr u4}
        const cr_val = state.exit_payload[0];
        const info = state.exit_payload[1];
        const cr_num: u4 = @truncate(info);
        const is_write = ((info >> 4) & 1) != 0;
        const gpr: u4 = @truncate(info >> 5);
        if (is_write) {
            switch (cr_num) {
                0 => state.cr0 = cr_val | 0x10,
                3 => state.cr3 = cr_val,
                4 => state.cr4 = cr_val,
                else => {},
            }
        } else {
            const v = switch (cr_num) {
                0 => state.cr0,
                2 => state.cr2,
                3 => state.cr3,
                4 => state.cr4,
                else => @as(u64, 0),
            };
            writeGpr(state, gpr, v);
        }
        state.rip += 3;
        return false;
    }
    if (subcode == EXIT_INTWIN) {
        return false;
    }
    if (subcode == EXIT_HLT) {
        hlt_count += 1;
        state.rip += 1;
        return false;
    }
    if (subcode == EXIT_TRIPLE or subcode == EXIT_SHUTDOWN) {
        log.print("FATAL at RIP=0x");
        log.hex64(state.rip);
        log.print(" CR0=0x");
        log.hex64(state.cr0);
        log.print(" CR3=0x");
        log.hex64(state.cr3);
        log.print(" CR4=0x");
        log.hex64(state.cr4);
        log.print(" EFER=0x");
        log.hex64(state.efer);
        log.print("\n");
        return true;
    }
    if (subcode == EXIT_EPT) {
        ept_count += 1;
        const guest_phys = state.exit_payload[0];
        return handleEpt(guest_phys, state);
    }
    if (subcode == EXIT_EXCEPT) {
        log.print("#");
        log.dec(state.exit_payload[0]);
        log.print(" RIP=0x");
        log.hex64(state.rip);
        log.print("\n");
        return true;
    }
    if (subcode == EXIT_UNKNOWN) {
        const code = state.exit_payload[0];
        if (code == 0x060 or code == 0x061) {
            intr_count += 1;
            return false;
        }
        log.print("UNK 0x");
        log.hex64(code);
        log.print("\n");
        return true;
    }
    other_count += 1;
    log.print("subcode=");
    log.dec(subcode);
    log.print("\n");
    return true;
}

noinline fn handleEpt(guest_phys: u64, state: *GuestState) bool {
    _ = state;
    if (ept_count <= 10) {
        log.print("EPT@0x");
        log.hex64(guest_phys);
        log.print("\n");
    }
    if (ept_count > 1000) return true;
    return false;
}

fn writeGpr(s: *GuestState, gpr: u4, val: u64) void {
    switch (gpr) {
        0 => s.rax = val,
        1 => s.rcx = val,
        2 => s.rdx = val,
        3 => s.rbx = val,
        4 => s.rsp = val,
        5 => s.rbp = val,
        6 => s.rsi = val,
        7 => s.rdi = val,
        8 => s.r8 = val,
        9 => s.r9 = val,
        10 => s.r10 = val,
        11 => s.r11 = val,
        12 => s.r12 = val,
        13 => s.r13 = val,
        14 => s.r14 = val,
        15 => s.r15 = val,
    }
}

fn writeU16(buf: []u8, off: usize, val: u16) void {
    @as(*align(1) u16, @ptrCast(buf.ptr + off)).* = val;
}
fn writeU32(buf: []u8, off: usize, val: u32) void {
    @as(*align(1) u32, @ptrCast(buf.ptr + off)).* = val;
}
fn writeU64(buf: []u8, off: usize, val: u64) void {
    @as(*align(1) u64, @ptrCast(buf.ptr + off)).* = val;
}
