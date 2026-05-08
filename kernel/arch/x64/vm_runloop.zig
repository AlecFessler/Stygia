//! x86-64 vCPU run-loop driver.
//!
//! Stitches the per-arch VMX/SVM `vmResume` to the kernel's per-vCPU
//! storage (`hv.vcpu.VcpuArchState`) and the per-VM control state
//! (VMCS on Intel, VMCB on AMD) pinned on `VirtualMachine.arch_state`
//! via `hv.vm.allocVmArchState`. Exit reasons are decoded by the
//! per-arch backend into the cross-arch `vm_hw.VmExitInfo`; this module
//! folds that into the spec-v3 §[vm_exit_state] sub-code + 3-vreg
//! payload the scheduler hands to `sched.port.fireVmExit`.

const zag = @import("zag");

const cpu = zag.arch.x64.cpu;
const hv_vcpu = zag.arch.x64.hv.vcpu;
const hv_vm = zag.arch.x64.hv.vm;
const kprof = zag.kprof.trace_id;
const mmio_decode = zag.arch.x64.mmio_decode;
const timers = zag.arch.x64.timers;
const vm_hw = zag.arch.x64.vm;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GuestState = vm_hw.GuestState;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;
const VirtualMachine = zag.hv.virtual_machine.VirtualMachine;

/// VM-exit delivery descriptor returned by `enterGuest`. Mirror of the
/// dispatch-tier alias in `zag.arch.dispatch.vm.VmExitDelivery` — the
/// type lives here in the x64 backend so the dispatch layer remains a
/// pure aliasing shim and arch-specific code doesn't need to import
/// dispatch. Layout follows spec §[vm_exit_state] x86-64 sub-codes.
pub const VmExitDelivery = struct {
    subcode: u8,
    payload: [3]u64,
};

// §[vm_exit_state] x86-64 sub-codes (mirror of the table in the spec).
const SUBCODE_CPUID: u8 = 0;
const SUBCODE_IO: u8 = 1;
const SUBCODE_MMIO: u8 = 2;
const SUBCODE_CR: u8 = 3;
const SUBCODE_MSR_R: u8 = 4;
const SUBCODE_MSR_W: u8 = 5;
const SUBCODE_EPT: u8 = 6;
const SUBCODE_EXCEPT: u8 = 7;
const SUBCODE_INTWIN: u8 = 8;
const SUBCODE_HLT: u8 = 9;
const SUBCODE_SHUTDOWN: u8 = 10;
const SUBCODE_TRIPLE: u8 = 11;
const SUBCODE_UNKNOWN: u8 = 12;

/// Enter the guest bound to `vcpu_ec` and return on the next VM exit.
/// Returns `null` if the VM or its arch state is missing (creator
/// teardown raced us, or the platform doesn't support hardware virt).
pub fn enterGuest(vcpu_ec: *ExecutionContext) ?VmExitDelivery {
    kprof.enter(.vm_enter);
    defer kprof.exit(.vm_enter);

    if (!vm_hw.vmSupported()) return null;

    // Resolve the VM's per-vCPU state and the VM's control-state PAddr.
    const arch_state = hv_vcpu.archStateOf(vcpu_ec) orelse return null;

    // Defer real VMLAUNCH/VMRUN until the VMM has supplied initial
    // guest state via reply. Otherwise we would VM-enter with a zeroed
    // GuestState and trip VM-entry consistency checks. The synthetic-
    // exit fallback is the spec-test path before reply→GuestState
    // writeback is wired; once that lands, this guard flips on reply.
    if (!arch_state.started) return null;

    const vm_ref = vcpu_ec.vm orelse return null;
    // caller-pinned: the vCPU EC holds a SlabRef on its VM for its lifetime;
    // the run loop is the only consumer that needs the live pointer.
    const vm_ptr = vm_ref.lock(@src()) catch return null;
    const ctrl_phys = ctrlPhysFor(vm_ptr);
    vm_ref.unlock();

    const vmcs_paddr = ctrl_phys orelse return null;

    // Inline-handle EPT violations against the kernel-emulated LAPIC /
    // IOAPIC pages. Linux's xAPIC + I/O APIC code hits these MMIO
    // ranges thousands of times during boot (timer programming, EOI,
    // ICR writes); punting each one to the VMM as a vm_exit would burn
    // a full recv→reply round-trip per access. Loop here, handling
    // them in-kernel until the guest hits a non-MMIO exit, then
    // deliver to the VMM. The per-iteration deliverPendingInterrupts
    // call is intentional — handling LAPIC writes can ack/queue new
    // vectors that should be injected on the next entry.
    var exit_info: vm_hw.VmExitInfo = undefined;
    while (true) {
        // Advance the emulated LAPIC timer by the wall-clock time that
        // elapsed since the last pre-VMRUN tick. Linux's local timer is
        // the LAPIC timer; without this, programmed initial-counts
        // never countdown to zero and the guest spins forever in
        // interrupt-window exits waiting for a tick that won't come.
        const now_ns = timers.getMonotonicClock().now();
        if (arch_state.last_tick_ns != 0) {
            vm_ptr.arch_devices.lapic.tick(now_ns - arch_state.last_tick_ns);
        }
        arch_state.last_tick_ns = now_ns;

        // Kernel-side PIT IRQ pulse @ 100 Hz. PIT emulation lives in the
        // VMM (port 0x40-0x43 OUT exits decoded there), but with the
        // kernel-emulated IOAPIC the VMM only sees those IO exits during
        // PIT setup — afterwards Linux is busy-waiting on jiffies and
        // the VMM gets no exits to drive `pitCheckIrq` from. Linux's
        // `check_timer` panics if jiffies don't advance. Pulse IOAPIC
        // pin 2 (ISA IRQ0 via INT_SRC_OVR) inline so jiffies progress
        // without the VMM round trip. Mask check inside `assertIrq`
        // means asserts before Linux unmasks the entry are no-ops.
        if (now_ns -% arch_state.last_auto_inject_ns >= 1_000_000) { // 1ms = 1000Hz
            arch_state.last_auto_inject_ns = now_ns;
            vm_ptr.arch_devices.ioapic.assertIrq(2);
            vm_ptr.arch_devices.ioapic.deassertIrq(2);
        }

        // Auto-inject the guest's PIC-IRQ0 vector at a fixed 4ms
        // cadence so /init makes scheduler progress even when the
        // guest is in user-mode busy-loops that don't generate vm
        // exits. This is the kernel-side equivalent of the OLD VMM's
        // out-of-band `vcpu_interrupt` syscall — which spec-v3
        // doesn't expose — and unblocks the busybox path that needs
        // jiffies to advance during /init's mount syscalls.
        // Vector hardcoded to 0x30 because that's what Linux 6.18
        // remaps the 8259 PIC's IRQ0 to under our `nolapic noapic
        // acpi=off` cmdline. Skip while a prior EVENTINJ is still
        // outstanding (consumed by the next VMRUN before this fires).
        if (arch_state.auto_inject_vector != 0 and
            arch_state.guest_state.pending_eventinj == 0)
        {
            const since_inject = now_ns -% arch_state.last_auto_inject_ns;
            if (since_inject >= 4_000_000) { // 4ms = 250Hz, matches Linux CONFIG_HZ
                arch_state.last_auto_inject_ns = now_ns;
                arch_state.guest_state.pending_eventinj =
                    @as(u64, arch_state.auto_inject_vector) | (1 << 31);
            }
        }

        // Pre-VMRUN: deliver any pending interrupt vector queued in
        // the VM's emulated LAPIC (driven by IOAPIC pin asserts via
        // `vm_inject_irq`, or the local APIC timer above). The LAPIC
        // tracks IRR/ISR per Intel SDM Vol 3 §13; if a deliverable
        // vector is pending and the guest is interruptible
        // (RFLAGS.IF=1, no prior EVENTINJ on AMD), `injectInterrupt`
        // sets up the VMCS/VMCB event-injection field and acknowledges
        // the LAPIC.
        deliverPendingInterrupts(vm_ptr, &arch_state.guest_state);

        exit_info = vm_hw.vmResume(&arch_state.guest_state, vmcs_paddr, &arch_state.guest_fxsave);
        arch_state.last_exit = exit_info;

        switch (exit_info) {
            .ept_violation => |ept| {
                if (!hv_vm.tryHandleMmio(vm_ptr, vcpu_ec, ept.guest_phys)) break;
                // Handled inline — re-enter the guest immediately.
            },
            // §[vm_policy] CPUID lookup — keyed on (leaf, subleaf) per
            // the spec. On match, write the canned (eax, ebx, ecx, edx)
            // into the guest GPRs, advance RIP past the CPUID
            // (Intel SDM Vol 3C §27.2 / AMD APM Vol 2 §15.7.1), and
            // re-enter the guest without delivering vm_exit. On miss,
            // fall through to the existing decodeDelivery path so the
            // VMM observes a CPUID exit per §[vm_exit_state].
            .cpuid => |c| {
                if (tryHandleCpuidPolicy(vm_ptr, &arch_state.guest_state, c)) continue;
                break;
            },
            // §[vm_policy] CR-access lookup — keyed on cr_num per the
            // spec. Read: write read_value into the destination GPR.
            // Write: apply masked value to the kernel's GuestState CR
            // field. Either branch advances RIP past the trapping mov.
            // On miss, fall through to vm_exit delivery.
            .cr_access => |cr| {
                if (tryHandleCrPolicy(vm_ptr, &arch_state.guest_state, cr)) continue;
                break;
            },
            // EXIT_REASON_EXTERNAL_INT — a host IRQ was pending when the
            // guest tried to enter (or fired during guest execution).
            // The exit happened with host IRQs masked (see scheduler.zig
            // `saveAndDisableInterrupts` around enterGuest). The pending
            // interrupt is still latched in the LAPIC; if we just re-
            // entered the guest, VMX would EXTERNAL_INT-exit again on
            // the very next instruction boundary, an infinite loop.
            // Crack the IRQ window open here so the host IDT actually
            // services the interrupt (timer tick, IPI, device IRQ),
            // then re-mask before re-entering. (vmx.zig labels this
            // variant `.interrupt_window` for historical reasons; today
            // it only originates from EXIT_REASON_EXTERNAL_INT.)
            .interrupt_window => {
                asm volatile (
                    \\sti
                    \\nop
                    \\cli
                    ::: .{ .memory = true });
            },
            else => break,
        }
    }

    return decodeDelivery(exit_info, &arch_state.guest_state);
}

// ---------------------------------------------------------------------------
// §[vm_exit_state] vreg layout (x86-64)
// ---------------------------------------------------------------------------
//
// Receiver-side stack layout after recv with sufficient reservation: the
// kernel writes [user_rsp + (N-13)*8] = vreg N for 14 ≤ N ≤ 127. The
// applyReplyStateToVcpu / populateVmExitVregs helpers below read/write
// the matching offsets to project guest state onto the receiver and
// commit receiver modifications back to GuestState.

const VREG14_RIP_OFF: u64 = 8; // (14-13)*8
const VREG15_RFLAGS_OFF: u64 = 16;
const VREG16_RSP_OFF: u64 = 24;
const VREG17_RCX_OFF: u64 = 32;
const VREG18_R11_OFF: u64 = 40;
const VREG19_CR0_OFF: u64 = 48;
const VREG20_CR2_OFF: u64 = 56;
const VREG21_CR3_OFF: u64 = 64;
const VREG22_CR4_OFF: u64 = 72;
// vreg 23 = CR8 (not in GuestState; read-write but ignored)
// vreg 24 = EFER, vreg 25 = APIC_BASE
const VREG24_EFER_OFF: u64 = 88;
// Segment band: vregs 26..41 = 8 segs × 2 vregs each.
// Layout: vreg(26+2i) = base, vreg(26+2i+1) = {limit u32, selector u16, access_rights u16}.
const VREG26_CS_BASE_OFF: u64 = 104;
// GDTR/IDTR band: vregs 42..43, 44..45.
const VREG42_GDTR_BASE_OFF: u64 = 232;
const VREG43_GDTR_LIMIT_OFF: u64 = 240;
const VREG44_IDTR_BASE_OFF: u64 = 248;
const VREG45_IDTR_LIMIT_OFF: u64 = 256;
// MSR band: vregs 46..55.
const VREG46_STAR_OFF: u64 = 264;
const VREG47_LSTAR_OFF: u64 = 272;
const VREG48_CSTAR_OFF: u64 = 280;
const VREG49_SFMASK_OFF: u64 = 288;
const VREG50_KERNEL_GS_BASE_OFF: u64 = 296;
const VREG51_SYSENTER_CS_OFF: u64 = 304;
const VREG52_SYSENTER_ESP_OFF: u64 = 312;
const VREG53_SYSENTER_EIP_OFF: u64 = 320;
const VREG54_PAT_OFF: u64 = 328;
// vreg 55 = TSC_AUX (not in GuestState)
// DR band: vregs 56..61. Only DR6/DR7 are stored in GuestState; DR0..DR3
// (vregs 56..59) are wired to user reads/writes once the debug-register
// passthrough path is restored.
const VREG60_DR6_OFF: u64 = 376;
const VREG61_DR7_OFF: u64 = 384;
// vcpu_events band: vregs 62..65 = exception/intr/sipi packed slots.
// vreg 64 = interrupt/nmi packed: SVM-EVENTINJ-format word the VMM
// writes to inject a pending external IRQ on next entry.
const VREG64_INTR_NMI_OFF: u64 = 408;
// Exit sub-code + payload: vregs 70..73.
const VREG70_EXIT_SUBCODE_OFF: u64 = 456;
const VREG71_EXIT_PAYLOAD_0_OFF: u64 = 464;
const VREG72_EXIT_PAYLOAD_1_OFF: u64 = 472;
const VREG73_EXIT_PAYLOAD_2_OFF: u64 = 480;

fn loadU64(rsp: u64, off: u64) u64 {
    const ptr: *const u64 = @ptrFromInt(rsp + off);
    return ptr.*;
}
fn storeU64(rsp: u64, off: u64, value: u64) void {
    const ptr: *u64 = @ptrFromInt(rsp + off);
    ptr.* = value;
}

/// Plain-data snapshot of the receiver's §[vm_exit_state] vregs,
/// captured outside the sender EC's `_gen_lock` so a fault on the
/// SMAP-bracketed user-stack reads can't strand the lock bit.
/// `applyReplyStateToVcpu` projects this snapshot onto the vCPU's
/// GuestState under the sender lock.
pub const ReplyVregSnapshot = extern struct {
    rax: u64 = 0,
    rbx: u64 = 0,
    rcx: u64 = 0,
    rdx: u64 = 0,
    rbp: u64 = 0,
    rsi: u64 = 0,
    rdi: u64 = 0,
    rsp: u64 = 0,
    rip: u64 = 0,
    r8: u64 = 0,
    r9: u64 = 0,
    r10: u64 = 0,
    r11: u64 = 0,
    r12: u64 = 0,
    r13: u64 = 0,
    r14: u64 = 0,
    r15: u64 = 0,
    rflags: u64 = 0,
    cr0: u64 = 0,
    cr2: u64 = 0,
    cr3: u64 = 0,
    cr4: u64 = 0,
    efer: u64 = 0,
    cs: GuestState.SegmentReg = .{},
    ds: GuestState.SegmentReg = .{},
    es: GuestState.SegmentReg = .{},
    fs: GuestState.SegmentReg = .{},
    gs: GuestState.SegmentReg = .{},
    ss: GuestState.SegmentReg = .{},
    tr: GuestState.SegmentReg = .{},
    ldtr: GuestState.SegmentReg = .{},
    gdtr_base: u64 = 0,
    gdtr_limit: u32 = 0,
    idtr_base: u64 = 0,
    idtr_limit: u32 = 0,
    star: u64 = 0,
    lstar: u64 = 0,
    cstar: u64 = 0,
    sfmask: u64 = 0,
    kernel_gs_base: u64 = 0,
    sysenter_cs: u64 = 0,
    sysenter_esp: u64 = 0,
    sysenter_eip: u64 = 0,
    pat: u64 = 0,
    dr6: u64 = 0,
    dr7: u64 = 0,
    intr_nmi: u64 = 0,
    /// Exit sub-code the receiver wrote at vreg 70 — the spec
    /// `initial_state` value (13 on x86-64) signals "stay not-started"
    /// and `applyReplyStateToVcpu` keeps `arch_state.started = false`
    /// so the next `enterGuest` falls back to synthetic-exit re-delivery.
    /// Any other value flips `started = true` and the next enter does
    /// VMLAUNCH/VMRUN with the projected state.
    exit_subcode: u64 = 0,
};

// Last byte of the wide §[vm_exit_state] reply window read by
// snapshotReplyVregs. VREG64_INTR_NMI_OFF + 8 covers the highest u64
// the snapshot reads. Receivers that haven't reserved at least this
// much stack above their `user_rsp` cannot supply a full snapshot
// without faulting on the trailing pages.
const WIDE_VREG_END_OFF: u64 = VREG64_INTR_NMI_OFF + 8;

/// Snapshot the receiver's §[vm_exit_state] vregs into a kernel-stack
/// buffer. Reads receiver-side state only — kernel-saved iret frame for
/// vregs 1..13 and the receiver's user stack (gated by SMAP STAC/CLAC)
/// for vregs 14..73. Receiver MUST be the running EC on the current
/// core (so CR3 already references the receiver's address space).
///
/// Caller MUST only invoke this for vm_exit-typed replies (per the
/// originating event_type captured at recv time). The receiver opted
/// in to the wide §[vm_exit_state] window contract by recv'ing a
/// vm_exit; if their stack reservation is too small the SMAP-bracketed
/// reads fault and `memory.fault.handlePageFault` aborts the syscall —
/// safe because we run BEFORE acquiring the sender's `_gen_lock`.
pub fn snapshotReplyVregs(receiver: *ExecutionContext) ReplyVregSnapshot {
    var snap: ReplyVregSnapshot = .{};
    const recv_frame = receiver.iret_frame orelse receiver.ctx;

    snap.rax = recv_frame.regs.rax;
    snap.rbx = recv_frame.regs.rbx;
    snap.rdx = recv_frame.regs.rdx;
    snap.rbp = recv_frame.regs.rbp;
    snap.rsi = recv_frame.regs.rsi;
    snap.rdi = recv_frame.regs.rdi;
    snap.r8 = recv_frame.regs.r8;
    snap.r9 = recv_frame.regs.r9;
    snap.r10 = recv_frame.regs.r10;
    snap.r12 = recv_frame.regs.r12;
    snap.r13 = recv_frame.regs.r13;
    snap.r14 = recv_frame.regs.r14;
    snap.r15 = recv_frame.regs.r15;

    const rsp = recv_frame.rsp;

    cpu.stac();
    defer cpu.clac();

    snap.rip = loadU64(rsp, VREG14_RIP_OFF);
    snap.rflags = loadU64(rsp, VREG15_RFLAGS_OFF);
    snap.rsp = loadU64(rsp, VREG16_RSP_OFF);
    snap.rcx = loadU64(rsp, VREG17_RCX_OFF);
    snap.r11 = loadU64(rsp, VREG18_R11_OFF);
    snap.cr0 = loadU64(rsp, VREG19_CR0_OFF);
    snap.cr2 = loadU64(rsp, VREG20_CR2_OFF);
    snap.cr3 = loadU64(rsp, VREG21_CR3_OFF);
    snap.cr4 = loadU64(rsp, VREG22_CR4_OFF);
    snap.efer = loadU64(rsp, VREG24_EFER_OFF);

    loadSegment(rsp, VREG26_CS_BASE_OFF + 0 * 16, &snap.cs);
    loadSegment(rsp, VREG26_CS_BASE_OFF + 1 * 16, &snap.ds);
    loadSegment(rsp, VREG26_CS_BASE_OFF + 2 * 16, &snap.es);
    loadSegment(rsp, VREG26_CS_BASE_OFF + 3 * 16, &snap.fs);
    loadSegment(rsp, VREG26_CS_BASE_OFF + 4 * 16, &snap.gs);
    loadSegment(rsp, VREG26_CS_BASE_OFF + 5 * 16, &snap.ss);
    loadSegment(rsp, VREG26_CS_BASE_OFF + 6 * 16, &snap.tr);
    loadSegment(rsp, VREG26_CS_BASE_OFF + 7 * 16, &snap.ldtr);

    snap.gdtr_base = loadU64(rsp, VREG42_GDTR_BASE_OFF);
    snap.gdtr_limit = @truncate(loadU64(rsp, VREG43_GDTR_LIMIT_OFF));
    snap.idtr_base = loadU64(rsp, VREG44_IDTR_BASE_OFF);
    snap.idtr_limit = @truncate(loadU64(rsp, VREG45_IDTR_LIMIT_OFF));

    snap.star = loadU64(rsp, VREG46_STAR_OFF);
    snap.lstar = loadU64(rsp, VREG47_LSTAR_OFF);
    snap.cstar = loadU64(rsp, VREG48_CSTAR_OFF);
    snap.sfmask = loadU64(rsp, VREG49_SFMASK_OFF);
    snap.kernel_gs_base = loadU64(rsp, VREG50_KERNEL_GS_BASE_OFF);
    snap.sysenter_cs = loadU64(rsp, VREG51_SYSENTER_CS_OFF);
    snap.sysenter_esp = loadU64(rsp, VREG52_SYSENTER_ESP_OFF);
    snap.sysenter_eip = loadU64(rsp, VREG53_SYSENTER_EIP_OFF);
    snap.pat = loadU64(rsp, VREG54_PAT_OFF);

    snap.dr6 = loadU64(rsp, VREG60_DR6_OFF);
    snap.dr7 = loadU64(rsp, VREG61_DR7_OFF);

    snap.intr_nmi = loadU64(rsp, VREG64_INTR_NMI_OFF);

    snap.exit_subcode = loadU64(rsp, VREG70_EXIT_SUBCODE_OFF);
    return snap;
}

/// Project a `ReplyVregSnapshot` onto the vCPU's GuestState. Pure
/// memory writes — no user-VA access, so safe under the sender's
/// `_gen_lock`. Called from `port.consumeReply` after `snapshotReplyVregs`
/// for vm_exit-typed replies only.
///
/// Spec §[reply] initial-state handshake: when the receiver wrote
/// `initial_state` (sub-code 13 on x86-64) into vreg 70, the kernel
/// keeps `arch_state.started = false` so the next `switchTo` falls back
/// to synthetic-exit re-delivery instead of VMLAUNCHing with the
/// zero-initialized state. Any other sub-code projects the full state
/// and flips `started = true` so the next `enterGuest` does a real
/// VMRUN.
pub fn applyReplyStateToVcpu(vcpu_ec: *ExecutionContext, snap: *const ReplyVregSnapshot) void {
    const arch_state = hv_vcpu.archStateOf(vcpu_ec) orelse return;
    const gs = &arch_state.guest_state;

    gs.rax = snap.rax;
    gs.rbx = snap.rbx;
    gs.rcx = snap.rcx;
    gs.rdx = snap.rdx;
    gs.rbp = snap.rbp;
    gs.rsi = snap.rsi;
    gs.rdi = snap.rdi;
    gs.rsp = snap.rsp;
    gs.rip = snap.rip;
    gs.r8 = snap.r8;
    gs.r9 = snap.r9;
    gs.r10 = snap.r10;
    gs.r11 = snap.r11;
    gs.r12 = snap.r12;
    gs.r13 = snap.r13;
    gs.r14 = snap.r14;
    gs.r15 = snap.r15;
    gs.rflags = snap.rflags;
    gs.cr0 = snap.cr0;
    gs.cr2 = snap.cr2;
    gs.cr3 = snap.cr3;
    gs.cr4 = snap.cr4;
    gs.efer = snap.efer;

    gs.cs = snap.cs;
    gs.ds = snap.ds;
    gs.es = snap.es;
    gs.fs = snap.fs;
    gs.gs = snap.gs;
    gs.ss = snap.ss;
    gs.tr = snap.tr;
    gs.ldtr = snap.ldtr;

    gs.gdtr_base = snap.gdtr_base;
    gs.gdtr_limit = snap.gdtr_limit;
    gs.idtr_base = snap.idtr_base;
    gs.idtr_limit = snap.idtr_limit;

    gs.star = snap.star;
    gs.lstar = snap.lstar;
    gs.cstar = snap.cstar;
    gs.sfmask = snap.sfmask;
    gs.kernel_gs_base = snap.kernel_gs_base;
    gs.sysenter_cs = snap.sysenter_cs;
    gs.sysenter_esp = snap.sysenter_esp;
    gs.sysenter_eip = snap.sysenter_eip;
    gs.pat = snap.pat;

    gs.dr6 = snap.dr6;
    gs.dr7 = snap.dr7;

    // VMM-supplied vreg 64 — both armed as a one-shot
    // `gs.pending_eventinj` (delivered on next VMRUN) AND latched as
    // the kernel's `auto_inject_vector` for the periodic re-injection
    // hook. The OLD VMM had a separate `vcpu_interrupt` syscall that
    // could kick a running vCPU out-of-band; spec-v3 doesn't expose
    // that path, so the kernel mimics it by re-firing the vector
    // every ~4 ms once the VMM has armed it.
    if (snap.intr_nmi != 0) {
        gs.pending_eventinj = snap.intr_nmi;
        if ((snap.intr_nmi & (1 << 31)) != 0) {
            arch_state.auto_inject_vector = @truncate(snap.intr_nmi & 0xFF);
        }
    }

    // Spec §[reply] initial-state handshake — sub-code `initial_state`
    // (13 on x86-64) means "stay not-started"; the receiver has not yet
    // supplied real guest state. Leave `started = false` so the next
    // switchTo synthesizes another initial vm_exit instead of attempting
    // VMRUN with whatever zero/garbage values landed in GuestState.
    if (snap.exit_subcode == zag.hv.virtual_machine.INITIAL_STATE_SUBCODE) return;
    arch_state.started = true;
}

fn loadSegment(rsp: u64, off: u64, seg: *GuestState.SegmentReg) void {
    seg.base = loadU64(rsp, off);
    const packed_word = loadU64(rsp, off + 8);
    seg.limit = @truncate(packed_word);
    seg.selector = @truncate(packed_word >> 32);
    seg.access_rights = @truncate(packed_word >> 48);
}

fn storeSegment(rsp: u64, off: u64, seg: *const GuestState.SegmentReg) void {
    storeU64(rsp, off, seg.base);
    const packed_word: u64 =
        @as(u64, seg.limit) |
        (@as(u64, seg.selector) << 32) |
        (@as(u64, seg.access_rights) << 48);
    storeU64(rsp, off + 8, packed_word);
}

/// Write the suspending vCPU's GuestState onto the receiver's
/// §[vm_exit_state] vreg slots. Called from `port.deliverEvent` when
/// the suspending event is vm_exit. Receiver MUST be the running EC on
/// the current core (CR3 = receiver's address space; SMAP STAC/CLAC
/// brackets the user-stack stores).
///
/// Companion to `applyReplyStateToVcpu`. Together they implement the
/// spec-v3 cross-domain guest-state-via-vregs contract.
pub fn populateVmExitVregs(
    receiver: *ExecutionContext,
    vcpu_ec: *ExecutionContext,
    subcode: u8,
    payload: [3]u64,
) void {
    const arch_state = hv_vcpu.archStateOf(vcpu_ec) orelse return;
    const gs = &arch_state.guest_state;
    const recv_frame = receiver.iret_frame orelse receiver.ctx;

    // vregs 1..13 — register-backed.
    recv_frame.regs.rax = gs.rax;
    recv_frame.regs.rbx = gs.rbx;
    recv_frame.regs.rdx = gs.rdx;
    recv_frame.regs.rbp = gs.rbp;
    recv_frame.regs.rsi = gs.rsi;
    recv_frame.regs.rdi = gs.rdi;
    recv_frame.regs.r8 = gs.r8;
    recv_frame.regs.r9 = gs.r9;
    recv_frame.regs.r10 = gs.r10;
    recv_frame.regs.r12 = gs.r12;
    recv_frame.regs.r13 = gs.r13;
    recv_frame.regs.r14 = gs.r14;
    recv_frame.regs.r15 = gs.r15;

    const rsp = recv_frame.rsp;
    cpu.stac();
    defer cpu.clac();

    storeU64(rsp, VREG14_RIP_OFF, gs.rip);
    storeU64(rsp, VREG15_RFLAGS_OFF, gs.rflags);
    storeU64(rsp, VREG16_RSP_OFF, gs.rsp);
    storeU64(rsp, VREG17_RCX_OFF, gs.rcx);
    storeU64(rsp, VREG18_R11_OFF, gs.r11);
    storeU64(rsp, VREG19_CR0_OFF, gs.cr0);
    storeU64(rsp, VREG20_CR2_OFF, gs.cr2);
    storeU64(rsp, VREG21_CR3_OFF, gs.cr3);
    storeU64(rsp, VREG22_CR4_OFF, gs.cr4);
    storeU64(rsp, VREG24_EFER_OFF, gs.efer);

    storeSegment(rsp, VREG26_CS_BASE_OFF + 0 * 16, &gs.cs);
    storeSegment(rsp, VREG26_CS_BASE_OFF + 1 * 16, &gs.ds);
    storeSegment(rsp, VREG26_CS_BASE_OFF + 2 * 16, &gs.es);
    storeSegment(rsp, VREG26_CS_BASE_OFF + 3 * 16, &gs.fs);
    storeSegment(rsp, VREG26_CS_BASE_OFF + 4 * 16, &gs.gs);
    storeSegment(rsp, VREG26_CS_BASE_OFF + 5 * 16, &gs.ss);
    storeSegment(rsp, VREG26_CS_BASE_OFF + 6 * 16, &gs.tr);
    storeSegment(rsp, VREG26_CS_BASE_OFF + 7 * 16, &gs.ldtr);

    storeU64(rsp, VREG42_GDTR_BASE_OFF, gs.gdtr_base);
    storeU64(rsp, VREG43_GDTR_LIMIT_OFF, @as(u64, gs.gdtr_limit));
    storeU64(rsp, VREG44_IDTR_BASE_OFF, gs.idtr_base);
    storeU64(rsp, VREG45_IDTR_LIMIT_OFF, @as(u64, gs.idtr_limit));

    storeU64(rsp, VREG46_STAR_OFF, gs.star);
    storeU64(rsp, VREG47_LSTAR_OFF, gs.lstar);
    storeU64(rsp, VREG48_CSTAR_OFF, gs.cstar);
    storeU64(rsp, VREG49_SFMASK_OFF, gs.sfmask);
    storeU64(rsp, VREG50_KERNEL_GS_BASE_OFF, gs.kernel_gs_base);
    storeU64(rsp, VREG51_SYSENTER_CS_OFF, gs.sysenter_cs);
    storeU64(rsp, VREG52_SYSENTER_ESP_OFF, gs.sysenter_esp);
    storeU64(rsp, VREG53_SYSENTER_EIP_OFF, gs.sysenter_eip);
    storeU64(rsp, VREG54_PAT_OFF, gs.pat);

    storeU64(rsp, VREG60_DR6_OFF, gs.dr6);
    storeU64(rsp, VREG61_DR7_OFF, gs.dr7);

    storeU64(rsp, VREG70_EXIT_SUBCODE_OFF, @as(u64, subcode));
    storeU64(rsp, VREG71_EXIT_PAYLOAD_0_OFF, payload[0]);
    storeU64(rsp, VREG72_EXIT_PAYLOAD_1_OFF, payload[1]);
    storeU64(rsp, VREG73_EXIT_PAYLOAD_2_OFF, payload[2]);
}

/// Dispatch-shim entrypoint: project the vCPU's full §[vm_exit_state]
/// onto the receiver's vregs only when the VMM has supplied initial
/// state (post-first-reply). Synthetic pre-started exits skip the
/// broad projection so receivers without a 488-byte recv stack window
/// aren't stomped. Reads `arch_state.last_exit_payload` for the
/// per-subcode payload tuple.
///
/// Side-effect: clears `receiver.pending_event_rip_valid`. The
/// generic event-state pipeline stages vreg 14 (`[user_rsp+8]`) for
/// flushing at iretq time via `writeUserVreg14`, sourcing the value
/// from `sender.event_rip` which is the sender EC's *host* RIP — for
/// a vCPU EC that's a kernel-mode address from the run-loop hook,
/// not the guest's RIP. Without this clear, the iretq writeback
/// stomps the guest RIP we just wrote at offset VREG14_RIP_OFF.
pub fn populateVmExitVregsIfStarted(
    receiver: *ExecutionContext,
    sender: *ExecutionContext,
    subcode: u8,
) void {
    const arch_state = hv_vcpu.archStateOf(sender) orelse return;
    if (!arch_state.started) return;
    populateVmExitVregs(receiver, sender, subcode, arch_state.last_exit_payload);
    receiver.pending_event_rip = 0;
    receiver.pending_event_rip_valid = false;
}

fn deliverPendingInterrupts(vm_ptr: *zag.hv.virtual_machine.VirtualMachine, gs: *vm_hw.GuestState) void {
    // Skip if guest interrupts are masked. On AMD, also skip if a prior
    // EVENTINJ is still pending (the guest hasn't entered yet).
    if ((gs.rflags & (1 << 9)) == 0) return;
    if (gs.pending_eventinj != 0) return;

    const vector = vm_ptr.arch_devices.lapic.getPendingVector() orelse return;
    vm_hw.injectInterrupt(gs, .{
        .vector = vector,
        .interrupt_type = 0, // external interrupt
        .error_code_valid = false,
    });
    vm_ptr.arch_devices.lapic.acceptInterrupt(vector);
}

fn ctrlPhysFor(vm_ptr: *zag.hv.virtual_machine.VirtualMachine) ?PAddr {
    const erased = vm_ptr.arch_state orelse return null;
    const cell: *hv_vm.CtrlStateCell = @ptrCast(@alignCast(erased));
    return cell.ctrl_phys;
}

/// Resolve the live `VmPolicy` table backing `vm`. Returns `null` when
/// no policy page frame has been seeded (pre-create_virtual_machine
/// scaffolding paths) — caller treats that as "no inline policy
/// configured". The page frame's physical pages are exposed through the
/// kernel physmap; the seeded `VmPolicy` lives at offset 0 per
/// §[create_virtual_machine] and §[vm_set_policy].
fn vmPolicyFor(vm_ptr: *VirtualMachine) ?*const vm_hw.VmPolicy {
    const pf_ref = vm_ptr.policy_pf orelse return null;
    const pf = pf_ref.ptr;
    const phys_va = VAddr.fromPAddr(pf.phys_base, null);
    return @ptrFromInt(phys_va.addr);
}

/// §[vm_policy] x86-64 CPUID lookup. Returns true if `(leaf, subleaf)`
/// matches an entry in `cpuid_responses[0..num_cpuid_responses]`; the
/// caller re-enters the guest after the canned (eax, ebx, ecx, edx)
/// have been projected onto guest GPRs and RIP has advanced past the
/// CPUID. Returns false on miss — caller delivers `.cpuid` to the VMM
/// per §[vm_exit_state].
fn tryHandleCpuidPolicy(
    vm_ptr: *VirtualMachine,
    gs: *GuestState,
    c: vm_hw.VmExitInfo.CpuidExit,
) bool {
    const policy = vmPolicyFor(vm_ptr) orelse return false;
    const n = policy.num_cpuid_responses;
    if (n == 0) return false;
    // Bound-check num_* against the array bound — `validateVmPolicy`
    // already rejects out-of-range counts at create_virtual_machine
    // time, but `applyVmPolicyTable` writes the same field at runtime.
    // Defensive clamp here mirrors that bound so a miswritten count
    // can't read past the entries array.
    const max: u32 = vm_hw.VmPolicy.MAX_CPUID_POLICIES;
    const limit: u32 = if (n > max) max else n;
    var i: u32 = 0;
    while (i < limit) : (i += 1) {
        const e = policy.cpuid_responses[i];
        if (e.leaf == c.leaf and e.subleaf == c.subleaf) {
            // x86 CPUID writes results to (rax, rbx, rcx, rdx); the
            // upper 32 bits of each are zeroed per Intel SDM Vol 2A
            // "CPUID — CPU Identification" (the canonical "32-bit
            // result, zero-extended to 64-bit" rule for arch
            // operations writing 32-bit GPR sub-registers).
            gs.rax = @as(u64, e.eax);
            gs.rbx = @as(u64, e.ebx);
            gs.rcx = @as(u64, e.ecx);
            gs.rdx = @as(u64, e.edx);
            gs.rip = c.next_rip;
            return true;
        }
    }
    return false;
}

/// §[vm_policy] x86-64 CR-access lookup. Returns true if `cr_num`
/// matches an entry in `cr_policies[0..num_cr_policies]`. On a write,
/// the kernel applies `value & write_mask` into the corresponding
/// GuestState CR field (bits not set in `write_mask` are ignored per
/// the spec's "applied masked by write_mask" rule). On a read, the
/// kernel writes `read_value` into the destination GPR. RIP advances
/// past the trapping `mov`. Returns false on miss — caller delivers
/// `.cr_access` to the VMM.
///
/// CR8 has no GuestState slot (it tracks the LAPIC TPR shadow on the
/// fly); writes are silently dropped when `cr_num == 8` and the masked
/// value is unused — matching the spec's "no separate CR8 backing"
/// shape for the inline policy path.
fn tryHandleCrPolicy(
    vm_ptr: *VirtualMachine,
    gs: *GuestState,
    cr: vm_hw.VmExitInfo.CrAccessExit,
) bool {
    const policy = vmPolicyFor(vm_ptr) orelse return false;
    const n = policy.num_cr_policies;
    if (n == 0) return false;
    const max: u32 = vm_hw.VmPolicy.MAX_CR_POLICIES;
    const limit: u32 = if (n > max) max else n;
    var i: u32 = 0;
    while (i < limit) : (i += 1) {
        const e = policy.cr_policies[i];
        if (e.cr_num != @as(u8, cr.cr_num)) continue;

        if (cr.is_write) {
            const masked = cr.value & e.write_mask;
            switch (cr.cr_num) {
                0 => gs.cr0 = (gs.cr0 & ~e.write_mask) | masked,
                3 => gs.cr3 = (gs.cr3 & ~e.write_mask) | masked,
                4 => gs.cr4 = (gs.cr4 & ~e.write_mask) | masked,
                // CR2 is the page-fault address — never a CR-access
                // exit target on real hardware (mov to CR2 doesn't
                // intercept). CR8 has no GuestState backing — the
                // hardware TPR shadow handles it. Other indices are
                // reserved. Drop the write inline; on a real CR8
                // write the LAPIC TPR is the affected register and
                // the VMM hooks LAPIC MMIO instead.
                else => {},
            }
        } else {
            mmio_decode.writeGpr(gs, cr.gpr, e.read_value);
        }
        gs.rip = cr.next_rip;
        return true;
    }
    return false;
}

fn decodeDelivery(exit: vm_hw.VmExitInfo, gs: *const vm_hw.GuestState) VmExitDelivery {
    return switch (exit) {
        .cpuid => |c| .{
            .subcode = SUBCODE_CPUID,
            .payload = .{
                (@as(u64, c.subleaf) << 32) | @as(u64, c.leaf),
                0,
                0,
            },
        },
        .io => |io| .{
            .subcode = SUBCODE_IO,
            .payload = .{
                io.next_rip,
                // {value u32, port u16, size u8, is_write u8}
                @as(u64, io.value) |
                    (@as(u64, io.port) << 32) |
                    (@as(u64, io.size) << 48) |
                    (@as(u64, @intFromBool(io.is_write)) << 56),
                0,
            },
        },
        .mmio => |m| .{
            .subcode = SUBCODE_MMIO,
            .payload = .{
                m.addr,
                m.value,
                @as(u64, m.size) | (@as(u64, @intFromBool(m.is_write)) << 8),
            },
        },
        .cr_access => |cr| .{
            .subcode = SUBCODE_CR,
            .payload = .{
                cr.value,
                @as(u64, cr.cr_num) |
                    (@as(u64, @intFromBool(cr.is_write)) << 4) |
                    (@as(u64, cr.gpr) << 5),
                0,
            },
        },
        .msr_read => |m| .{
            .subcode = SUBCODE_MSR_R,
            .payload = .{ m.value, @as(u64, m.msr), 0 },
        },
        .msr_write => |m| .{
            .subcode = SUBCODE_MSR_W,
            .payload = .{ m.value, @as(u64, m.msr), 0 },
        },
        .ept_violation => |e| .{
            .subcode = SUBCODE_EPT,
            .payload = .{
                e.guest_phys,
                @as(u64, @intFromBool(e.is_read)) |
                    (@as(u64, @intFromBool(e.is_write)) << 1) |
                    (@as(u64, @intFromBool(e.is_exec)) << 2),
                0,
            },
        },
        .exception => |e| .{
            .subcode = SUBCODE_EXCEPT,
            .payload = .{ @as(u64, e.vector), e.error_code, 0 },
        },
        .interrupt_window => .{
            .subcode = SUBCODE_INTWIN,
            .payload = .{ 0, 0, 0 },
        },
        .hlt => .{
            .subcode = SUBCODE_HLT,
            .payload = .{ gs.rip, 0, 0 },
        },
        .shutdown => .{
            .subcode = SUBCODE_SHUTDOWN,
            .payload = .{ 0, 0, 0 },
        },
        .triple_fault => .{
            .subcode = SUBCODE_TRIPLE,
            .payload = .{ 0, 0, 0 },
        },
        .unknown => |code| .{
            .subcode = SUBCODE_UNKNOWN,
            .payload = .{ code, 0, 0 },
        },
    };
}
