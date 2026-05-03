// libz/abi.zig — C-ABI export shim used to build libz.elf, the kernel-
// shipped userspace shared library.
//
// libz.elf is built with this file as its root source. Every public
// libz wrapper from syscall.zig is re-exposed here as a `callconv(.c)`
// bridge function and exported as a global dynamic symbol under the
// same name as the Zig-native API. The "C-ABI" naming is internal-
// only — consumers never see a `_c` suffix in their dynsym lookups.
//
// Why a C-ABI shim is necessary at all: Zig 0.15 refuses to `@export`
// a function with the default Zig calling convention. To emit a real
// shared object whose dynsym entries can be linked against, every
// exported symbol must use `callconv(.c)`, which in turn forbids
// slices, sub-power-of-two integers, and plain (non-extern) structs
// in its signature. This shim performs the shape translation:
//
//   - u12 / u1 → widen to u16 / u8 here. Bodies @truncate back
//     before forwarding into syscall.zig.
//   - Slice arguments degrade to ptr+len pairs; the body
//     reconstitutes the slice via ptr[0..len].
//   - Regs / RecvReturn use the extern-struct mirrors from types.zig.
//     Layouts are identical (all u64 fields), so the conversion is a
//     no-op at machine level.

const syscall = @import("syscall.zig");
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
// libz never calls any of those code paths (every entry is a forwarder
// into an inline-asm syscall wrapper), but the linker still wants the
// symbol resolved. Hidden visibility keeps the stub out of the public
// dynsym surface.
fn getauxvalStub(_: c_ulong) callconv(.c) c_ulong {
    return 0;
}
comptime {
    @export(&getauxvalStub, .{ .name = "getauxval", .visibility = .hidden });
}

// ── C-ABI bridge bodies ─────────────────────────────────────────────
//
// Local function names match the Zig-native names in syscall.zig.
// They live in this file's namespace, so `createPort` here and
// `syscall.createPort` referenced inside the body are unambiguously
// distinct. The exported dynsym name (set in the @export block at the
// bottom of this file) is also the bare name — no `_c` suffix.

pub fn restrict(handle: u16, new_caps: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.restrict(@truncate(handle), new_caps));
}

pub fn delete(handle: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.delete(@truncate(handle)));
}

pub fn revoke(handle: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.revoke(@truncate(handle)));
}

pub fn sync(handle: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.sync(@truncate(handle)));
}

pub fn createCapabilityDomain(
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

pub fn acquireEcs(target: u16) callconv(.c) c.RecvReturn {
    return toCRecvReturn(syscall.acquireEcs(@truncate(target)));
}

pub fn acquireVmars(target: u16) callconv(.c) c.RecvReturn {
    return toCRecvReturn(syscall.acquireVmars(@truncate(target)));
}

pub fn createExecutionContext(
    caps: u64,
    entry: u64,
    stack_pages: u64,
    target: u64,
    affinity_mask: u64,
) callconv(.c) c.Regs {
    return toCRegs(syscall.createExecutionContext(caps, entry, stack_pages, target, affinity_mask));
}

pub fn self() callconv(.c) c.Regs {
    return toCRegs(syscall.self());
}

pub fn terminate(target: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.terminate(@truncate(target)));
}

pub fn yieldEc(target: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.yieldEc(target));
}

pub fn priority(target: u16, new_priority: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.priority(@truncate(target), new_priority));
}

pub fn affinity(target: u16, new_affinity: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.affinity(@truncate(target), new_affinity));
}

pub fn perfmonInfo() callconv(.c) c.Regs {
    return toCRegs(syscall.perfmonInfo());
}

pub fn perfmonStart(
    target: u16,
    num_configs: u64,
    configs_ptr: [*]const u64,
    configs_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.perfmonStart(@truncate(target), num_configs, configs_ptr[0..configs_len]));
}

pub fn perfmonRead(target: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.perfmonRead(@truncate(target)));
}

pub fn perfmonStop(target: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.perfmonStop(@truncate(target)));
}

pub fn createVmar(
    caps: u64,
    props: u64,
    pages: u64,
    preferred_base: u64,
    device_region: u64,
) callconv(.c) c.Regs {
    return toCRegs(syscall.createVmar(caps, props, pages, preferred_base, device_region));
}

pub fn mapPf(
    vmar_handle: u16,
    pairs_ptr: [*]const u64,
    pairs_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.mapPf(@truncate(vmar_handle), pairs_ptr[0..pairs_len]));
}

pub fn mapMmio(vmar_handle: u16, device_region: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.mapMmio(@truncate(vmar_handle), @truncate(device_region)));
}

pub fn unmap(
    vmar_handle: u16,
    selectors_ptr: [*]const u64,
    selectors_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.unmap(@truncate(vmar_handle), selectors_ptr[0..selectors_len]));
}

pub fn remap(vmar_handle: u16, new_cur_rwx: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.remap(@truncate(vmar_handle), new_cur_rwx));
}

pub fn snapshot(target_vmar: u16, source_vmar: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.snapshot(@truncate(target_vmar), @truncate(source_vmar)));
}

pub fn idcRead(vmar_handle: u16, offset: u64, count: u8) callconv(.c) c.Regs {
    return toCRegs(syscall.idcRead(@truncate(vmar_handle), offset, count));
}

pub fn idcWrite(
    vmar_handle: u16,
    offset: u64,
    qwords_ptr: [*]const u64,
    qwords_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.idcWrite(@truncate(vmar_handle), offset, qwords_ptr[0..qwords_len]));
}

pub fn createPageFrame(caps: u64, props: u64, pages: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.createPageFrame(caps, props, pages));
}

pub fn ack(device_region: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.ack(@truncate(device_region)));
}

pub fn createVirtualMachine(caps: u64, policy_pf: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.createVirtualMachine(caps, @truncate(policy_pf)));
}

pub fn createVcpu(
    caps: u64,
    vm_handle: u16,
    affinity_mask: u64,
    exit_port: u16,
) callconv(.c) c.Regs {
    return toCRegs(syscall.createVcpu(caps, @truncate(vm_handle), affinity_mask, @truncate(exit_port)));
}

pub fn mapGuest(
    vm_handle: u16,
    pairs_ptr: [*]const u64,
    pairs_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.mapGuest(@truncate(vm_handle), pairs_ptr[0..pairs_len]));
}

pub fn unmapGuest(
    vm_handle: u16,
    page_frames_ptr: [*]const u64,
    page_frames_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.unmapGuest(@truncate(vm_handle), page_frames_ptr[0..page_frames_len]));
}

pub fn vmSetPolicy(
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

pub fn vmInjectIrq(vm_handle: u16, irq_num: u64, assert_word: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.vmInjectIrq(@truncate(vm_handle), irq_num, assert_word));
}

pub fn createPort(caps: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.createPort(caps));
}

pub fn suspendEc(
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

pub fn recv(port: u16, timeout_ns: u64) callconv(.c) c.RecvReturn {
    return toCRecvReturn(syscall.recv(@truncate(port), timeout_ns));
}

pub fn bindEventRoute(target: u16, event_type: u64, port: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.bindEventRoute(@truncate(target), event_type, @truncate(port)));
}

pub fn clearEventRoute(target: u16, event_type: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.clearEventRoute(@truncate(target), event_type));
}

pub fn reply(reply_handle: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.reply(@truncate(reply_handle)));
}

pub fn replyTransfer(
    reply_handle: u16,
    attachments_ptr: [*]const u64,
    attachments_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.replyTransfer(@truncate(reply_handle), attachments_ptr[0..attachments_len]));
}

pub fn replyRecv(reply_handle: u16, recv_port: u16) callconv(.c) c.RecvReturn {
    return toCRecvReturn(syscall.replyRecv(@truncate(reply_handle), @truncate(recv_port)));
}

pub fn replyTransferRecv(
    reply_handle: u16,
    attachments_ptr: [*]const u64,
    attachments_len: usize,
    recv_port: u16,
) callconv(.c) c.RecvReturn {
    return toCRecvReturn(syscall.replyTransferRecv(
        @truncate(reply_handle),
        attachments_ptr[0..attachments_len],
        @truncate(recv_port),
    ));
}

pub fn timerArm(caps: u64, deadline_ns: u64, flags: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.timerArm(caps, deadline_ns, flags));
}

pub fn timerRearm(timer_handle: u16, deadline_ns: u64, flags: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.timerRearm(@truncate(timer_handle), deadline_ns, flags));
}

pub fn timerCancel(timer_handle: u16) callconv(.c) c.Regs {
    return toCRegs(syscall.timerCancel(@truncate(timer_handle)));
}

pub fn futexWaitVal(
    timeout_ns: u64,
    pairs_ptr: [*]const u64,
    pairs_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.futexWaitVal(timeout_ns, pairs_ptr[0..pairs_len]));
}

pub fn futexWaitChange(
    timeout_ns: u64,
    pairs_ptr: [*]const u64,
    pairs_len: usize,
) callconv(.c) c.Regs {
    return toCRegs(syscall.futexWaitChange(timeout_ns, pairs_ptr[0..pairs_len]));
}

pub fn futexWake(addr: u64, count: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.futexWake(addr, count));
}

pub fn timeMonotonic() callconv(.c) c.Regs {
    return toCRegs(syscall.timeMonotonic());
}

pub fn timeGetwall() callconv(.c) c.Regs {
    return toCRegs(syscall.timeGetwall());
}

pub fn timeSetwall(ns_since_epoch: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.timeSetwall(ns_since_epoch));
}

pub fn random(count: u8) callconv(.c) c.Regs {
    return toCRegs(syscall.random(count));
}

pub fn infoSystem() callconv(.c) c.Regs {
    return toCRegs(syscall.infoSystem());
}

pub fn infoCores(core_id: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.infoCores(core_id));
}

pub fn powerShutdown() callconv(.c) c.Regs {
    return toCRegs(syscall.powerShutdown());
}

pub fn powerReboot() callconv(.c) c.Regs {
    return toCRegs(syscall.powerReboot());
}

pub fn powerSleep(depth: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.powerSleep(depth));
}

pub fn powerScreenOff() callconv(.c) c.Regs {
    return toCRegs(syscall.powerScreenOff());
}

pub fn powerSetFreq(core_id: u64, hz: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.powerSetFreq(core_id, hz));
}

pub fn powerSetIdle(core_id: u64, policy: u64) callconv(.c) c.Regs {
    return toCRegs(syscall.powerSetIdle(core_id, policy));
}

// ── Dynamic-symbol exports ──────────────────────────────────────────
//
// Names match the Zig-native API in syscall.zig — no `_c` suffix.
// Test ELFs and other dynamic consumers declare extern wrappers using
// these unsuffixed names and resolve them via libz_loader.relocateSelf
// against the libz.elf image staged at LIBZ_SLIDE.

comptime {
    @export(&restrict, .{ .name = "restrict" });
    @export(&delete, .{ .name = "delete" });
    @export(&revoke, .{ .name = "revoke" });
    @export(&sync, .{ .name = "sync" });
    @export(&createCapabilityDomain, .{ .name = "createCapabilityDomain" });
    @export(&acquireEcs, .{ .name = "acquireEcs" });
    @export(&acquireVmars, .{ .name = "acquireVmars" });
    @export(&createExecutionContext, .{ .name = "createExecutionContext" });
    @export(&self, .{ .name = "self" });
    @export(&terminate, .{ .name = "terminate" });
    @export(&yieldEc, .{ .name = "yieldEc" });
    @export(&priority, .{ .name = "priority" });
    @export(&affinity, .{ .name = "affinity" });
    @export(&perfmonInfo, .{ .name = "perfmonInfo" });
    @export(&perfmonStart, .{ .name = "perfmonStart" });
    @export(&perfmonRead, .{ .name = "perfmonRead" });
    @export(&perfmonStop, .{ .name = "perfmonStop" });
    @export(&createVmar, .{ .name = "createVmar" });
    @export(&mapPf, .{ .name = "mapPf" });
    @export(&mapMmio, .{ .name = "mapMmio" });
    @export(&unmap, .{ .name = "unmap" });
    @export(&remap, .{ .name = "remap" });
    @export(&snapshot, .{ .name = "snapshot" });
    @export(&idcRead, .{ .name = "idcRead" });
    @export(&idcWrite, .{ .name = "idcWrite" });
    @export(&createPageFrame, .{ .name = "createPageFrame" });
    @export(&ack, .{ .name = "ack" });
    @export(&createVirtualMachine, .{ .name = "createVirtualMachine" });
    @export(&createVcpu, .{ .name = "createVcpu" });
    @export(&mapGuest, .{ .name = "mapGuest" });
    @export(&unmapGuest, .{ .name = "unmapGuest" });
    @export(&vmSetPolicy, .{ .name = "vmSetPolicy" });
    @export(&vmInjectIrq, .{ .name = "vmInjectIrq" });
    @export(&createPort, .{ .name = "createPort" });
    @export(&suspendEc, .{ .name = "suspendEc" });
    @export(&recv, .{ .name = "recv" });
    @export(&bindEventRoute, .{ .name = "bindEventRoute" });
    @export(&clearEventRoute, .{ .name = "clearEventRoute" });
    @export(&reply, .{ .name = "reply" });
    @export(&replyTransfer, .{ .name = "replyTransfer" });
    @export(&replyRecv, .{ .name = "replyRecv" });
    @export(&replyTransferRecv, .{ .name = "replyTransferRecv" });
    @export(&timerArm, .{ .name = "timerArm" });
    @export(&timerRearm, .{ .name = "timerRearm" });
    @export(&timerCancel, .{ .name = "timerCancel" });
    @export(&futexWaitVal, .{ .name = "futexWaitVal" });
    @export(&futexWaitChange, .{ .name = "futexWaitChange" });
    @export(&futexWake, .{ .name = "futexWake" });
    @export(&timeMonotonic, .{ .name = "timeMonotonic" });
    @export(&timeGetwall, .{ .name = "timeGetwall" });
    @export(&timeSetwall, .{ .name = "timeSetwall" });
    @export(&random, .{ .name = "random" });
    @export(&infoSystem, .{ .name = "infoSystem" });
    @export(&infoCores, .{ .name = "infoCores" });
    @export(&powerShutdown, .{ .name = "powerShutdown" });
    @export(&powerReboot, .{ .name = "powerReboot" });
    @export(&powerSleep, .{ .name = "powerSleep" });
    @export(&powerScreenOff, .{ .name = "powerScreenOff" });
    @export(&powerSetFreq, .{ .name = "powerSetFreq" });
    @export(&powerSetIdle, .{ .name = "powerSetIdle" });
}
