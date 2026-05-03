//! aarch64 linux_guest VMM — spec-v3 port.
//!
//! Mirrors `vmm/main.zig` (x86 spec-v3 reference) for the aarch64
//! boot path:
//!   1. Allocate a page_frame for VmPolicy + map locally to zero it.
//!   2. createVirtualMachine.
//!   3. mem.setupGuestMemory: page_frames + mapGuest at GUEST_RAM_BASE
//!      + local VAR for VMM-side @memcpy access.
//!   4. Load arm64 Linux Image + initramfs + FDT into guest RAM.
//!   5. createPort + createVcpu(vm, exit_port).
//!   6. recv loop on exit_port; first exit is initial_state — install
//!      Linux boot-protocol state (PC, X0=FDT, PSTATE=EL1h-DAIF) and
//!      reply. Subsequent exits route to per-subcode handlers and
//!      reply with mods.
//!
//! Stage-2 fault handlers route PL011 / GICD / GICR MMIO traps; HVCs
//! route to the in-kernel PSCI inline-handle path (so PSCI calls don't
//! reach the VMM at all today). Other exits are surfaced for
//! diagnostics — Linux only needs PSCI + PL011 + GIC traps to reach
//! init.

const lib = @import("lib");
const assets = @import("assets");

const fdt = @import("fdt.zig");
const initramfs = @import("initramfs.zig");
const linux_image = @import("linux_image.zig");
const log = @import("log.zig");
const mem = @import("mem.zig");
const pl011 = @import("pl011.zig");
const psci_mod = @import("psci.zig");
const vm_exit = @import("vm_exit.zig");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;

const HandleId = caps.HandleId;
const PortCap = caps.PortCap;
const VmCap = caps.VmCap;
const VmExitState = vm_exit.VmExitState;
const VmExitSubcode = vm_exit.VmExitSubcode;

// Reference-import the non-syscall support modules (fdt, linux_image,
// initramfs, pl011) so they stay in the dependency graph during the
// boot-path build-out.
comptime {
    _ = fdt;
    _ = initramfs;
    _ = linux_image;
    _ = pl011;
    _ = psci_mod;
}

// Guest layout — must fit inside the kernel's 1 GiB stage-2 IPA
// window (T0SZ=34 in `kernel/arch/aarch64/stage2.zig`).
const GUEST_RAM_SIZE: u64 = 128 * 1024 * 1024; // 128 MiB
const FDT_LOAD_ADDR: u64 = mem.GUEST_RAM_BASE + 0x80_0000; // +8 MiB
const INITRAMFS_LOAD_ADDR: u64 = mem.GUEST_RAM_BASE + 0x100_0000; // +16 MiB

const GICD_BASE: u64 = 0x0800_0000;
const GICD_SIZE: u64 = 0x0001_0000;
const GICR_BASE: u64 = 0x080A_0000;
const GICR_SIZE: u64 = 0x0002_0000;

var fdt_buf: [4096]u8 align(8) = .{0} ** 4096;
var linux_load_addr: u64 = 0;

pub var vm_handle: HandleId = 0;
pub var vcpu_handle: HandleId = 0;
pub var exit_port: HandleId = 0;
pub var first_exit_pending: bool = true;
pub var guest_state: VmExitState = .{};

var exit_count: u64 = 0;

pub fn main(cap_table_base: u64) void {
    log.init(cap_table_base);
    log.print("\n=== linux_guest aarch64 (spec-v3) ===\n");

    // Step 1 — Allocate VmPolicy page_frame.
    const policy_pf = mem.allocPolicyPageFrame() orelse {
        log.print("policy_pf alloc failed\n");
        return;
    };
    log.print("policy_pf=");
    log.dec(@as(u64, policy_pf));
    log.print("\n");

    // Step 2 — createVirtualMachine. caps.policy = bit 0 lets us call
    // vm_set_policy later (not used yet but no reason to deny).
    const vm_caps_word: u64 = @as(u64, (VmCap{ .policy = true }).toU16());
    const vm_r = syscall.createVirtualMachine(vm_caps_word, policy_pf);
    if (vm_r.v1 < 16) {
        log.print("createVirtualMachine failed: ");
        log.dec(vm_r.v1);
        log.print("\n");
        return;
    }
    vm_handle = @truncate(vm_r.v1 & 0xFFF);
    log.print("vm_handle=");
    log.dec(@as(u64, vm_handle));
    log.print("\n");

    // Step 3 — Allocate guest RAM and map it at GUEST_RAM_BASE.
    if (!mem.setupGuestMemory(GUEST_RAM_SIZE)) {
        log.print("setupGuestMemory failed\n");
        return;
    }
    log.print("guest RAM ready\n");

    // Step 4 — Load Linux + initramfs + FDT into guest RAM.
    if (!loadGuestImages()) {
        log.print("loadGuestImages failed\n");
        return;
    }
    log.print("guest images loaded\n");

    // Step 5 — Stage initial Linux boot-protocol state (applied on the
    // first reply when the kernel hands us the initial-state synthetic
    // exit). arm64 booting.rst: PC = load addr, X0 = FDT phys, PSTATE
    // = EL1h with DAIF masked.
    setupVcpuState();

    // Step 6 — createPort for vCPU exit delivery.
    const port_caps_word: u64 = @as(u64, (PortCap{
        .recv = true,
        .bind = true,
    }).toU16());
    const port_r = syscall.createPort(port_caps_word);
    if (port_r.v1 < 16) {
        log.print("createPort failed\n");
        return;
    }
    exit_port = @truncate(port_r.v1 & 0xFFF);

    // Step 7 — createVcpu bound to (vm, exit_port). The kernel
    // immediately enqueues an initial_state synthetic vm_exit on
    // exit_port.
    const vcpu_caps_word: u64 = 0;
    const vcpu_r = syscall.createVcpu(vcpu_caps_word, vm_handle, 0, exit_port);
    if (vcpu_r.v1 < 16) {
        log.print("createVcpu failed: ");
        log.dec(vcpu_r.v1);
        log.print("\n");
        return;
    }
    vcpu_handle = @truncate(vcpu_r.v1 & 0xFFF);
    log.print("vcpu_handle=");
    log.dec(@as(u64, vcpu_handle));
    log.print("\n");

    // Step 8 — Run the exit loop.
    log.print("entering exit loop\n");
    exitLoop();
    log.print("exit loop ended\n");
}

/// Parse the arm64 Image header, copy the kernel + initramfs into
/// guest RAM, and build the FDT that /chosen will point the kernel at.
fn loadGuestImages() bool {
    const hdr = linux_image.parse(assets.image) catch return false;

    linux_load_addr = mem.GUEST_RAM_BASE + hdr.text_offset;
    if (hdr.image_size > GUEST_RAM_SIZE - hdr.text_offset) return false;
    if (assets.image.len > hdr.image_size) return false;

    // Linux arm64 booting.rst: image_size is the total in-memory
    // footprint (head + text + data + BSS). The loader must zero the
    // BSS tail past the on-disk file bytes — early init pg-tables and
    // init_task stack live there and rely on post-loader zeroing.
    mem.writeGuest(linux_load_addr, assets.image);
    mem.zeroGuest(linux_load_addr + assets.image.len, hdr.image_size - assets.image.len);

    const idst = mem.guestToHost(INITRAMFS_LOAD_ADDR) orelse return false;
    const initrd = initramfs.load(idst, INITRAMFS_LOAD_ADDR);

    const cfg = fdt.Config{
        .ram_base = mem.GUEST_RAM_BASE,
        .ram_size = GUEST_RAM_SIZE,
        .initrd_start = initrd.start,
        .initrd_end = initrd.end,
        .bootargs = "console=ttyAMA0 earlycon=pl011,mmio32,0x09000000 maxcpus=1 nokaslr lpj=5000000 keep_bootcon ignore_loglevel panic=-1",
        .gicd_base = GICD_BASE,
        .gicd_size = GICD_SIZE,
        .gicr_base = GICR_BASE,
        .gicr_size = GICR_SIZE,
        .uart_base = pl011.UART_BASE,
        .uart_size = pl011.UART_SIZE,
    };

    const dtb_len = fdt.build(&fdt_buf, cfg) catch return false;
    mem.writeGuest(FDT_LOAD_ADDR, fdt_buf[0..dtb_len]);
    return true;
}

/// Initialize the vCPU to the arm64 boot protocol entry state.
fn setupVcpuState() void {
    guest_state = .{};
    guest_state.pc = linux_load_addr;
    guest_state.x0 = FDT_LOAD_ADDR;
    guest_state.x1 = 0;
    guest_state.x2 = 0;
    guest_state.x3 = 0;
    // PSTATE: EL1h (M[3:0]=0b0101), DAIF all set.
    guest_state.pstate = 0x3C5;
    // SCTLR_EL1 reset value (RES1 pattern, MMU off).
    guest_state.sctlr_el1 = 0x30C50830;
}

fn exitLoop() void {
    const RECV_POLL_NS: u64 = 0; // block indefinitely
    while (true) {
        log.print("recv...");
        const r = vm_exit.recvVmExit(exit_port, RECV_POLL_NS);
        log.print(" et=");
        log.dec(@as(u64, r.event_type));
        log.print(" err=");
        log.dec(r.err);
        log.print(" subcode=");
        log.dec(r.state.exit_subcode);
        log.print("\n");
        if (r.event_type == 0) {
            if (r.err == @intFromEnum(errors.Error.E_TIMEOUT)) continue;
            return;
        }

        exit_count += 1;

        if (first_exit_pending) {
            // Initial-state synthetic exit — kernel hands us zeroed
            // guest state; install the Linux boot-protocol state and
            // reply.
            first_exit_pending = false;
            log.print("reply#1 pc=0x");
            log.hex64(guest_state.pc);
            log.print("...");
            const reply_err = vm_exit.replyVmExit(r.reply_handle_id, guest_state);
            log.print(" ret=");
            log.dec(reply_err);
            log.print("\n");
            if (reply_err != 0) return;
            continue;
        }

        var state = r.state;
        const subcode: u8 = @truncate(state.exit_subcode);
        const kill = handleSubcode(subcode, &state);
        if (kill) return;

        const reply_err = vm_exit.replyVmExit(r.reply_handle_id, state);
        if (reply_err != 0) return;
    }
}

fn handleSubcode(subcode: u8, state: *VmExitState) bool {
    switch (@as(VmExitSubcode, @enumFromInt(subcode))) {
        .stage2_fault => return handleStage2Fault(state),
        .hvc, .smc => {
            // PSCI HVCs are inline-handled by the kernel today
            // (`kernel/arch/aarch64/vm_runloop.zig` enterGuest loop
            // calls `psci.dispatch` before returning to userspace).
            // A non-PSCI HVC reaching here is non-PSCI SMCCC; advance
            // PC and continue. Linux's only HVC path is PSCI.
            advancePc(state);
            return false;
        },
        .sysreg => {
            // Sysreg trap — read returns 0, write is dropped, advance PC.
            handleSysregTrap(state);
            return false;
        },
        .wfi_wfe => {
            // Guest idle — advance past the WFI and let it retry.
            advancePc(state);
            return false;
        },
        .halt, .shutdown => return true,
        .unknown_ec, .sync_el1, .unknown => {
            advancePc(state);
            return false;
        },
        .initial_state => {
            // Shouldn't reach here — first_exit_pending handled above.
            return true;
        },
        _ => return false,
    }
}

fn handleStage2Fault(state: *VmExitState) bool {
    const guest_phys = state.exit_payload[0];
    if (pl011.contains(guest_phys)) {
        return pl011.handleFault(state, guest_phys);
    }
    if (guest_phys >= GICD_BASE and guest_phys < GICD_BASE + GICD_SIZE) {
        // GIC distributor MMIO — emulated in-kernel via vGIC, but our
        // VMM-side dispatch isn't wired to it yet. For now drop the
        // access and advance PC so the guest progresses. Linux's GIC
        // init path tolerates spurious zero reads on GICD probes.
        const flags: u8 = @truncate(state.exit_payload[2] >> 24);
        if ((flags & 0x02) == 0) {
            // Read — write 0 into the destination register.
            const access_size: u8 = @truncate(state.exit_payload[2]);
            _ = access_size;
            const srt: u8 = @truncate(state.exit_payload[2] >> 8);
            writeGpr(state, srt, 0);
        }
        advancePc(state);
        return false;
    }
    if (guest_phys >= GICR_BASE and guest_phys < GICR_BASE + GICR_SIZE) {
        const flags: u8 = @truncate(state.exit_payload[2] >> 24);
        if ((flags & 0x02) == 0) {
            const srt: u8 = @truncate(state.exit_payload[2] >> 8);
            writeGpr(state, srt, 0);
        }
        advancePc(state);
        return false;
    }
    // Unknown MMIO — drop and continue.
    advancePc(state);
    return false;
}

fn handleSysregTrap(state: *VmExitState) void {
    // ISS layout per the spec §[vm_exit_state] aarch64 sysreg payload:
    //   exit_payload[0] bits 0..31 = ISS, bits 32..33 = op0, ...,
    //   bits 48..52 = rt, bit 53 = is_read.
    const info = state.exit_payload[0];
    const rt: u8 = @truncate((info >> 48) & 0x1F);
    const is_read = ((info >> 53) & 1) != 0;
    if (is_read) writeGpr(state, rt, 0);
    advancePc(state);
}

fn advancePc(state: *VmExitState) void {
    state.pc += 4;
}

fn writeGpr(state: *VmExitState, idx: u8, val: u64) void {
    switch (idx) {
        0 => state.x0 = val,
        1 => state.x1 = val,
        2 => state.x2 = val,
        3 => state.x3 = val,
        4 => state.x4 = val,
        5 => state.x5 = val,
        6 => state.x6 = val,
        7 => state.x7 = val,
        8 => state.x8 = val,
        9 => state.x9 = val,
        10 => state.x10 = val,
        11 => state.x11 = val,
        12 => state.x12 = val,
        13 => state.x13 = val,
        14 => state.x14 = val,
        15 => state.x15 = val,
        16 => state.x16 = val,
        17 => state.x17 = val,
        18 => state.x18 = val,
        19 => state.x19 = val,
        20 => state.x20 = val,
        21 => state.x21 = val,
        22 => state.x22 = val,
        23 => state.x23 = val,
        24 => state.x24 = val,
        25 => state.x25 = val,
        26 => state.x26 = val,
        27 => state.x27 = val,
        28 => state.x28 = val,
        29 => state.x29 = val,
        30 => state.x30 = val,
        else => {},
    }
}
