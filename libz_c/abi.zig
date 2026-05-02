// libz_c/abi.zig — C-ABI bridge layer + dynamic-symbol exports.
//
// libz_c.elf is built with this file as its root source. Every public
// libz wrapper from ../libz/syscall.zig is re-exposed here as a `*_c`
// bridge function with `callconv(.c)`, then exported as a global
// dynamic symbol.
//
// Type adaptations at the boundary:
//   - Sub-byte-power-of-two integer types in libz/ (u12 for handles,
//     u1 for the vm policy kind bit) widen to u16 / u8 here. Bodies
//     @truncate back before forwarding into libz/syscall.zig.
//   - Slice arguments in libz/ degrade to ptr+len pairs; the body
//     reconstitutes the slice via ptr[0..len].
//   - Regs / RecvReturn are converted between the regular-struct
//     libz/ versions and the extern-struct libz_c/ versions via the
//     toCRegs / toCRecvReturn helpers below. Layouts are identical
//     (all u64), so the conversion is a no-op at machine level.

const syscall = @import("libz_syscall");
const c = @import("types.zig");

inline fn toCRegs(r: syscall.Regs) c.Regs {
    return .{
        .v1 = r.v1,
        .v2 = r.v2,
        .v3 = r.v3,
        .v4 = r.v4,
        .v5 = r.v5,
        .v6 = r.v6,
        .v7 = r.v7,
        .v8 = r.v8,
        .v9 = r.v9,
        .v10 = r.v10,
        .v11 = r.v11,
        .v12 = r.v12,
        .v13 = r.v13,
    };
}

inline fn toCRecvReturn(rr: syscall.RecvReturn) c.RecvReturn {
    return .{ .word = rr.word, .regs = toCRegs(rr.regs) };
}

// ── stdlib stub ─────────────────────────────────────────────────────
//
// Targeting `os_tag = .linux` to coax Zig into emitting a real shared
// object drags in a single std-lib reference: `getauxval`. It's
// reachable from std.heap's page-size lookup, std/os/linux/vdso, etc.
// We never call any of those code paths from libz_c (all our entry
// points are pure forwarders into inline-asm syscall wrappers), but
// the linker still wants the symbol resolved.
//
// Provide a local definition that returns 0. It satisfies the linker,
// occupies a few bytes, and never executes during normal use. If
// something *does* end up calling it, returning 0 (AT_NULL) is the
// correct sentinel for "auxv entry not found".

// Hidden visibility keeps the stub out of libz_c.elf's public dynsym
// surface — only the linker's local resolver sees it.
fn getauxvalStub(_: c_ulong) callconv(.c) c_ulong {
    return 0;
}
comptime {
    @export(&getauxvalStub, .{ .name = "getauxval", .visibility = .hidden });
}

// ── C-ABI bridges ───────────────────────────────────────────────────

pub fn restrict_c(handle: u16, new_caps: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.restrict(@truncate(handle), new_caps));
}

pub fn delete_c(handle: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.delete(@truncate(handle)));
}

pub fn revoke_c(handle: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.revoke(@truncate(handle)));
}

pub fn sync_c(handle: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.sync(@truncate(handle)));
}

pub fn createCapabilityDomain_c(
    caps: u64,
    ceilings_inner: u64,
    ceilings_outer: u64,
    elf_pf: u16,
    initial_ec_affinity: u64,
    passed_handles_ptr: [*]const u64,
    passed_handles_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.createCapabilityDomain(
        caps,
        ceilings_inner,
        ceilings_outer,
        @truncate(elf_pf),
        initial_ec_affinity,
        passed_handles_ptr[0..passed_handles_len],
    ));
}

pub fn acquireEcs_c(target: u16) callconv(.c) c.RecvReturn {
    return toCRecvReturn(syscall.acquireEcs(@truncate(target)));
}

pub fn acquireVars_c(target: u16) callconv(.c) c.RecvReturn {
    return toCRecvReturn(syscall.acquireVars(@truncate(target)));
}

pub fn createExecutionContext_c(
    caps: u64,
    entry: u64,
    stack_pages: u64,
    target: u64,
    affinity_mask: u64,
) callconv(.c) c.Regs {
    return toCRegs(syscall.createExecutionContext(caps, entry, stack_pages, target, affinity_mask));
}

pub fn self_c() callconv(.c) c.Regs {
    return toCRegs(syscall.self());
}

pub fn terminate_c(target: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.terminate(@truncate(target)));
}

pub fn yieldEc_c(target: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.yieldEc(target));
}

pub fn priority_c(target: u16, new_priority: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.priority(@truncate(target), new_priority));
}

pub fn affinity_c(target: u16, new_affinity: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.affinity(@truncate(target), new_affinity));
}

pub fn perfmonInfo_c() callconv(.c) c.Regs {
    return toCRegs(syscall.perfmonInfo());
}

pub fn perfmonStart_c(
    target: u16,
    num_configs: u64,
    configs_ptr: [*]const u64,
    configs_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.perfmonStart(@truncate(target), num_configs, configs_ptr[0..configs_len]));
}

pub fn perfmonRead_c(target: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.perfmonRead(@truncate(target)));
}

pub fn perfmonStop_c(target: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.perfmonStop(@truncate(target)));
}

pub fn createVar_c(
    caps: u64,
    props: u64,
    pages: u64,
    preferred_base: u64,
    device_region: u64,
) callconv(.c) c.Regs {
    return toCRegs(syscall.createVar(caps, props, pages, preferred_base, device_region));
}

pub fn mapPf_c(
    var_handle: u16,
    pairs_ptr: [*]const u64,
    pairs_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.mapPf(@truncate(var_handle), pairs_ptr[0..pairs_len]));
}

pub fn mapMmio_c(var_handle: u16, device_region: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.mapMmio(@truncate(var_handle), @truncate(device_region)));
}

pub fn unmap_c(
    var_handle: u16,
    selectors_ptr: [*]const u64,
    selectors_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.unmap(@truncate(var_handle), selectors_ptr[0..selectors_len]));
}

pub fn remap_c(var_handle: u16, new_cur_rwx: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.remap(@truncate(var_handle), new_cur_rwx));
}

pub fn snapshot_c(target_var: u16, source_var: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.snapshot(@truncate(target_var), @truncate(source_var)));
}

pub fn idcRead_c(var_handle: u16, offset: u64, count: u8) callconv(.c) c.Regs {
    return toCRegs(syscall.idcRead(@truncate(var_handle), offset, count));
}

pub fn idcWrite_c(
    var_handle: u16,
    offset: u64,
    qwords_ptr: [*]const u64,
    qwords_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.idcWrite(@truncate(var_handle), offset, qwords_ptr[0..qwords_len]));
}

pub fn createPageFrame_c(caps: u64, props: u64, pages: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.createPageFrame(caps, props, pages));
}

pub fn ack_c(device_region: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.ack(@truncate(device_region)));
}

pub fn createVirtualMachine_c(caps: u64, policy_pf: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.createVirtualMachine(caps, @truncate(policy_pf)));
}

pub fn createVcpu_c(
    caps: u64,
    vm_handle: u16,
    affinity_mask: u64,
    exit_port: u16,
) callconv(.c) c.Regs {
    return toCRegs(syscall.createVcpu(caps, @truncate(vm_handle), affinity_mask, @truncate(exit_port)));
}

pub fn mapGuest_c(
    vm_handle: u16,
    pairs_ptr: [*]const u64,
    pairs_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.mapGuest(@truncate(vm_handle), pairs_ptr[0..pairs_len]));
}

pub fn unmapGuest_c(
    vm_handle: u16,
    page_frames_ptr: [*]const u64,
    page_frames_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.unmapGuest(@truncate(vm_handle), page_frames_ptr[0..page_frames_len]));
}

pub fn vmSetPolicy_c(
    vm_handle: u16,
    kind: u8,
    count: u8,
    entries_ptr: [*]const u64,
    entries_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.vmSetPolicy(
        @truncate(vm_handle),
        @truncate(kind),
        count,
        entries_ptr[0..entries_len],
    ));
}

pub fn vmInjectIrq_c(vm_handle: u16, irq_num: u64, assert_word: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.vmInjectIrq(@truncate(vm_handle), irq_num, assert_word));
}

pub fn createPort_c(caps: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.createPort(caps));
}

pub fn suspendEc_c(
    target: u16,
    port: u16,
    attachments_ptr: [*]const u64,
    attachments_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.suspendEc(
        @truncate(target),
        @truncate(port),
        attachments_ptr[0..attachments_len],
    ));
}

pub fn recv_c(port: u16, timeout_ns: u64) callconv(.c) c.RecvReturn {
    return toCRecvReturn(syscall.recv(@truncate(port), timeout_ns));
}

pub fn bindEventRoute_c(target: u16, event_type: u64, port: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.bindEventRoute(@truncate(target), event_type, @truncate(port)));
}

pub fn clearEventRoute_c(target: u16, event_type: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.clearEventRoute(@truncate(target), event_type));
}

pub fn reply_c(reply_handle: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.reply(@truncate(reply_handle)));
}

pub fn replyTransfer_c(
    reply_handle: u16,
    attachments_ptr: [*]const u64,
    attachments_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.replyTransfer(@truncate(reply_handle), attachments_ptr[0..attachments_len]));
}

pub fn timerArm_c(caps: u64, deadline_ns: u64, flags: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.timerArm(caps, deadline_ns, flags));
}

pub fn timerRearm_c(timer_handle: u16, deadline_ns: u64, flags: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.timerRearm(@truncate(timer_handle), deadline_ns, flags));
}

pub fn timerCancel_c(timer_handle: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.timerCancel(@truncate(timer_handle)));
}

pub fn futexWaitVal_c(
    timeout_ns: u64,
    pairs_ptr: [*]const u64,
    pairs_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.futexWaitVal(timeout_ns, pairs_ptr[0..pairs_len]));
}

pub fn futexWaitChange_c(
    timeout_ns: u64,
    pairs_ptr: [*]const u64,
    pairs_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.futexWaitChange(timeout_ns, pairs_ptr[0..pairs_len]));
}

pub fn futexWake_c(addr: u64, count: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.futexWake(addr, count));
}

pub fn timeMonotonic_c() callconv(.c) c.Regs {
    return toCRegs(syscall.timeMonotonic());
}

pub fn timeGetwall_c() callconv(.c) c.Regs {
    return toCRegs(syscall.timeGetwall());
}

pub fn timeSetwall_c(ns_since_epoch: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.timeSetwall(ns_since_epoch));
}

pub fn random_c(count: u8) callconv(.c) c.Regs {
    return toCRegs(syscall.random(count));
}

pub fn infoSystem_c() callconv(.c) c.Regs {
    return toCRegs(syscall.infoSystem());
}

pub fn infoCores_c(core_id: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.infoCores(core_id));
}

pub fn powerShutdown_c() callconv(.c) c.Regs {
    return toCRegs(syscall.powerShutdown());
}

pub fn powerReboot_c() callconv(.c) c.Regs {
    return toCRegs(syscall.powerReboot());
}

pub fn powerSleep_c(depth: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.powerSleep(depth));
}

pub fn powerScreenOff_c() callconv(.c) c.Regs {
    return toCRegs(syscall.powerScreenOff());
}

pub fn powerSetFreq_c(core_id: u64, hz: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.powerSetFreq(core_id, hz));
}

pub fn powerSetIdle_c(core_id: u64, policy: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.powerSetIdle(core_id, policy));
}

// ── Dynamic-symbol exports ──────────────────────────────────────────

comptime {
    @export(&restrict_c, .{ .name = "restrict_c" });
    @export(&delete_c, .{ .name = "delete_c" });
    @export(&revoke_c, .{ .name = "revoke_c" });
    @export(&sync_c, .{ .name = "sync_c" });
    @export(&createCapabilityDomain_c, .{ .name = "createCapabilityDomain_c" });
    @export(&acquireEcs_c, .{ .name = "acquireEcs_c" });
    @export(&acquireVars_c, .{ .name = "acquireVars_c" });
    @export(&createExecutionContext_c, .{ .name = "createExecutionContext_c" });
    @export(&self_c, .{ .name = "self_c" });
    @export(&terminate_c, .{ .name = "terminate_c" });
    @export(&yieldEc_c, .{ .name = "yieldEc_c" });
    @export(&priority_c, .{ .name = "priority_c" });
    @export(&affinity_c, .{ .name = "affinity_c" });
    @export(&perfmonInfo_c, .{ .name = "perfmonInfo_c" });
    @export(&perfmonStart_c, .{ .name = "perfmonStart_c" });
    @export(&perfmonRead_c, .{ .name = "perfmonRead_c" });
    @export(&perfmonStop_c, .{ .name = "perfmonStop_c" });
    @export(&createVar_c, .{ .name = "createVar_c" });
    @export(&mapPf_c, .{ .name = "mapPf_c" });
    @export(&mapMmio_c, .{ .name = "mapMmio_c" });
    @export(&unmap_c, .{ .name = "unmap_c" });
    @export(&remap_c, .{ .name = "remap_c" });
    @export(&snapshot_c, .{ .name = "snapshot_c" });
    @export(&idcRead_c, .{ .name = "idcRead_c" });
    @export(&idcWrite_c, .{ .name = "idcWrite_c" });
    @export(&createPageFrame_c, .{ .name = "createPageFrame_c" });
    @export(&ack_c, .{ .name = "ack_c" });
    @export(&createVirtualMachine_c, .{ .name = "createVirtualMachine_c" });
    @export(&createVcpu_c, .{ .name = "createVcpu_c" });
    @export(&mapGuest_c, .{ .name = "mapGuest_c" });
    @export(&unmapGuest_c, .{ .name = "unmapGuest_c" });
    @export(&vmSetPolicy_c, .{ .name = "vmSetPolicy_c" });
    @export(&vmInjectIrq_c, .{ .name = "vmInjectIrq_c" });
    @export(&createPort_c, .{ .name = "createPort_c" });
    @export(&suspendEc_c, .{ .name = "suspendEc_c" });
    @export(&recv_c, .{ .name = "recv_c" });
    @export(&bindEventRoute_c, .{ .name = "bindEventRoute_c" });
    @export(&clearEventRoute_c, .{ .name = "clearEventRoute_c" });
    @export(&reply_c, .{ .name = "reply_c" });
    @export(&replyTransfer_c, .{ .name = "replyTransfer_c" });
    @export(&timerArm_c, .{ .name = "timerArm_c" });
    @export(&timerRearm_c, .{ .name = "timerRearm_c" });
    @export(&timerCancel_c, .{ .name = "timerCancel_c" });
    @export(&futexWaitVal_c, .{ .name = "futexWaitVal_c" });
    @export(&futexWaitChange_c, .{ .name = "futexWaitChange_c" });
    @export(&futexWake_c, .{ .name = "futexWake_c" });
    @export(&timeMonotonic_c, .{ .name = "timeMonotonic_c" });
    @export(&timeGetwall_c, .{ .name = "timeGetwall_c" });
    @export(&timeSetwall_c, .{ .name = "timeSetwall_c" });
    @export(&random_c, .{ .name = "random_c" });
    @export(&infoSystem_c, .{ .name = "infoSystem_c" });
    @export(&infoCores_c, .{ .name = "infoCores_c" });
    @export(&powerShutdown_c, .{ .name = "powerShutdown_c" });
    @export(&powerReboot_c, .{ .name = "powerReboot_c" });
    @export(&powerSleep_c, .{ .name = "powerSleep_c" });
    @export(&powerScreenOff_c, .{ .name = "powerScreenOff_c" });
    @export(&powerSetFreq_c, .{ .name = "powerSetFreq_c" });
    @export(&powerSetIdle_c, .{ .name = "powerSetIdle_c" });
}
