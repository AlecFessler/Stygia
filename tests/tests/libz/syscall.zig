// Spec v3 vreg-ABI syscall wrappers — TEST ELF flavor.
//
// Each high-level wrapper (createPort, recv, mapPf, …) is now an
// extern declaration that resolves at runtime against libz.elf via
// `libz_loader.relocateSelf` patching this ELF's JUMP_SLOT/GLOB_DAT
// relocations. The Zig-native call signatures (slices, u12, u1, native
// Regs/RecvReturn) used by the 475 test source files are preserved as
// thin wrappers that translate to/from the C-ABI shapes that libz.elf
// actually exports (see libz/abi.zig).
//
// Raw inline-asm primitives (issueRawNoStack / issueRegDiscard /
// issueRawCaptureWord / replyTransferAsm) are still statically compiled
// into every test ELF so that start.zig's libz bootstrap can issue
// `create_var` + `map_pf` BEFORE the relocateSelf pass runs (i.e.
// before any extern call would be safe to make).
//
// The companion top-level `libz/syscall.zig` is the source-of-truth
// implementation that ends up inside libz.elf via abi.zig — that file
// keeps the full static bodies and is unchanged.

const std = @import("std");
const builtin = @import("builtin");

const arch_impl = switch (builtin.cpu.arch) {
    .x86_64 => @import("syscall_x64.zig"),
    .aarch64 => @import("syscall_aarch64.zig"),
    else => @compileError("unsupported target architecture for libz syscall"),
};

// ── Public Zig-native types ─────────────────────────────────────────
//
// These are the shapes the test sources see. `Regs` and `RecvReturn`
// remain plain (non-extern) structs with default field values so test
// call sites can keep using `.{ .v1 = … }` literals.

pub const Regs = struct {
    v1: u64 = 0,
    v2: u64 = 0,
    v3: u64 = 0,
    v4: u64 = 0,
    v5: u64 = 0,
    v6: u64 = 0,
    v7: u64 = 0,
    v8: u64 = 0,
    v9: u64 = 0,
    v10: u64 = 0,
    v11: u64 = 0,
    v12: u64 = 0,
    v13: u64 = 0,
};

pub const RecvReturn = struct {
    word: u64,
    regs: Regs,
};

pub const SyscallNum = enum(u12) {
    restrict = 0,
    delete = 1,
    revoke = 2,
    sync = 3,
    create_capability_domain = 4,
    acquire_ecs = 5,
    acquire_vars = 6,
    create_execution_context = 7,
    self = 8,
    terminate = 9,
    yield = 10,
    priority = 11,
    affinity = 12,
    perfmon_info = 13,
    perfmon_start = 14,
    perfmon_read = 15,
    perfmon_stop = 16,
    create_var = 17,
    map_pf = 18,
    map_mmio = 19,
    unmap = 20,
    remap = 21,
    snapshot = 22,
    idc_read = 23,
    idc_write = 24,
    create_page_frame = 25,
    ack = 26,
    create_virtual_machine = 27,
    create_vcpu = 28,
    map_guest = 29,
    unmap_guest = 30,
    vm_set_policy = 31,
    vm_inject_irq = 32,
    create_port = 33,
    @"suspend" = 34,
    recv = 35,
    bind_event_route = 36,
    clear_event_route = 37,
    reply = 38,
    reply_transfer = 39,
    timer_arm = 40,
    timer_rearm = 41,
    timer_cancel = 42,
    futex_wait_val = 43,
    futex_wait_change = 44,
    futex_wake = 45,
    time_monotonic = 46,
    time_getwall = 47,
    time_setwall = 48,
    random = 49,
    info_system = 50,
    info_cores = 51,
    power_shutdown = 52,
    power_reboot = 53,
    power_sleep = 54,
    power_screen_off = 55,
    power_set_freq = 56,
    power_set_idle = 57,
};

// ── Syscall-word encoding helpers ───────────────────────────────────
//
// SPEC AMBIGUITY: spec §[syscall_abi] does not pin which bits of the
// syscall word carry syscall_num. Several syscalls put `pair_count` /
// `count` in bits 12-19 and `tstart` / sub-fields in bits 20-31, which
// places syscall_num in bits 0-11 by elimination. Treating that as the
// stable encoding here.
pub fn buildWord(num: SyscallNum, extra: u64) u64 {
    return (@as(u64, @intFromEnum(num)) & 0xFFF) | (extra & ~@as(u64, 0xFFF));
}

pub fn extraCount(count: u8) u64 {
    return (@as(u64, count) & 0xFF) << 12;
}

pub fn extraTstart(tstart: u12) u64 {
    return (@as(u64, tstart) & 0xFFF) << 20;
}

pub fn extraVmKind(kind: u1, count: u8) u64 {
    return (@as(u64, kind) << 12) | ((@as(u64, count) & 0xFF) << 13);
}

/// Spec §[reply]: reply_handle_id rides in syscall-word bits 12-23.
pub fn extraReplyHandle(handle: u12) u64 {
    return (@as(u64, handle) & 0xFFF) << 12;
}

/// Spec §[reply_transfer]: reply_handle_id rides in syscall-word bits
/// 20-31 (with N at bits 12-19).
pub fn extraReplyTransferHandle(handle: u12) u64 {
    return (@as(u64, handle) & 0xFFF) << 20;
}

// ── Raw issue primitives — statically compiled, no extern dispatch ──
//
// Bootstrap code in start.zig calls into these BEFORE relocateSelf has
// patched the JUMP_SLOT entries. Keeping them static means the early
// `create_var` + `map_pf` that establishes the LIBZ_SLIDE mapping is
// always callable.

fn issueRawNoStack(word: u64, in: Regs) Regs {
    return arch_impl.issueRawNoStack(word, in);
}

pub fn issueReg(num: SyscallNum, extra: u64, in: Regs) Regs {
    return issueRawNoStack(buildWord(num, extra), in);
}

pub fn issueRegDiscard(num: SyscallNum, extra: u64, in: Regs) void {
    arch_impl.issueRegDiscard(buildWord(num, extra), in);
}

// Stack-arg path. SPEC AMBIGUITY: spec lists vreg 14 at [rsp + 8] when
// the syscall executes (x86) / vreg 32 at [sp + 8] (aarch64), but does
// not pin who is responsible for stack alignment / red-zone discipline.
// The v0 mock runner exercises only register-only syscalls; the stack
// path is bounded at 16 slots so the pad size is fixed and call sites
// typecheck without a runtime memcpy. Bump the bound when a stack-arg
// syscall is actually used.
pub fn issueStack(num: SyscallNum, extra: u64, in: Regs, stack_vregs: []const u64) Regs {
    if (stack_vregs.len == 0) return issueReg(num, extra, in);
    if (stack_vregs.len > 16) @panic("issueStack: vreg count exceeds bounded stack pad");

    var slots: [16]u64 = .{0} ** 16;
    var i: usize = 0;
    while (i < stack_vregs.len) {
        slots[i] = stack_vregs[i];
        i += 1;
    }

    return arch_impl.issueRawWithSlots(buildWord(num, extra), in, &slots, stack_vregs.len);
}

// ── C-ABI shape mirrors and conversions ─────────────────────────────
//
// libz/abi.zig exports its bridge functions with `extern struct`
// returns (so they pass through callconv(.c)). These mirrors duplicate
// types.zig's layout locally so this file doesn't pull in a libz/types
// import path through the test build graph.

const CRegs = extern struct {
    v1: u64 = 0,
    v2: u64 = 0,
    v3: u64 = 0,
    v4: u64 = 0,
    v5: u64 = 0,
    v6: u64 = 0,
    v7: u64 = 0,
    v8: u64 = 0,
    v9: u64 = 0,
    v10: u64 = 0,
    v11: u64 = 0,
    v12: u64 = 0,
    v13: u64 = 0,
};

const CRecvReturn = extern struct {
    word: u64,
    regs: CRegs,
};

const c = struct {
    pub const Regs = CRegs;
    pub const RecvReturn = CRecvReturn;
};

inline fn fromCRegs(r: c.Regs) Regs {
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

inline fn fromCRecvReturn(rr: c.RecvReturn) RecvReturn {
    return .{ .word = rr.word, .regs = fromCRegs(rr.regs) };
}

// ── Extern declarations resolved against libz.elf at runtime ────────
//
// Names match libz/abi.zig's @export block exactly (no `_c` suffix).
// They live in a struct namespace so the local Zig identifiers don't
// clash with the public wrapper names below — only the dynsym name
// (which is the bare `extern fn` identifier) matters at link time.

const ext = struct {
    extern fn restrict(handle: u16, new_caps: u64) callconv(.c) c.Regs;
    extern fn delete(handle: u16) callconv(.c) c.Regs;
    extern fn revoke(handle: u16) callconv(.c) c.Regs;
    extern fn sync(handle: u16) callconv(.c) c.Regs;
    extern fn createCapabilityDomain(
        caps: u64,
        ceilings_inner: u64,
        ceilings_outer: u64,
        elf_pf: u16,
        initial_ec_affinity: u64,
        passed_handles_ptr: [*]const u64,
        passed_handles_len: usize,
    ) callconv(.c) c.Regs;
    extern fn acquireEcs(target: u16) callconv(.c) c.RecvReturn;
    extern fn acquireVars(target: u16) callconv(.c) c.RecvReturn;
    extern fn createExecutionContext(
        caps: u64,
        entry: u64,
        stack_pages: u64,
        target: u64,
        affinity_mask: u64,
    ) callconv(.c) c.Regs;
    extern fn self() callconv(.c) c.Regs;
    extern fn terminate(target: u16) callconv(.c) c.Regs;
    extern fn yieldEc(target: u64) callconv(.c) c.Regs;
    extern fn priority(target: u16, new_priority: u64) callconv(.c) c.Regs;
    extern fn affinity(target: u16, new_affinity: u64) callconv(.c) c.Regs;
    extern fn perfmonInfo() callconv(.c) c.Regs;
    extern fn perfmonStart(
        target: u16,
        num_configs: u64,
        configs_ptr: [*]const u64,
        configs_len: usize,
    ) callconv(.c) c.Regs;
    extern fn perfmonRead(target: u16) callconv(.c) c.Regs;
    extern fn perfmonStop(target: u16) callconv(.c) c.Regs;
    extern fn createVar(
        caps: u64,
        props: u64,
        pages: u64,
        preferred_base: u64,
        device_region: u64,
    ) callconv(.c) c.Regs;
    extern fn mapPf(
        var_handle: u16,
        pairs_ptr: [*]const u64,
        pairs_len: usize,
    ) callconv(.c) c.Regs;
    extern fn mapMmio(var_handle: u16, device_region: u16) callconv(.c) c.Regs;
    extern fn unmap(
        var_handle: u16,
        selectors_ptr: [*]const u64,
        selectors_len: usize,
    ) callconv(.c) c.Regs;
    extern fn remap(var_handle: u16, new_cur_rwx: u64) callconv(.c) c.Regs;
    extern fn snapshot(target_var: u16, source_var: u16) callconv(.c) c.Regs;
    extern fn idcRead(var_handle: u16, offset: u64, count: u8) callconv(.c) c.Regs;
    extern fn idcWrite(
        var_handle: u16,
        offset: u64,
        qwords_ptr: [*]const u64,
        qwords_len: usize,
    ) callconv(.c) c.Regs;
    extern fn createPageFrame(caps: u64, props: u64, pages: u64) callconv(.c) c.Regs;
    extern fn ack(device_region: u16) callconv(.c) c.Regs;
    extern fn createVirtualMachine(caps: u64, policy_pf: u16) callconv(.c) c.Regs;
    extern fn createVcpu(
        caps: u64,
        vm_handle: u16,
        affinity_mask: u64,
        exit_port: u16,
    ) callconv(.c) c.Regs;
    extern fn mapGuest(
        vm_handle: u16,
        pairs_ptr: [*]const u64,
        pairs_len: usize,
    ) callconv(.c) c.Regs;
    extern fn unmapGuest(
        vm_handle: u16,
        page_frames_ptr: [*]const u64,
        page_frames_len: usize,
    ) callconv(.c) c.Regs;
    extern fn vmSetPolicy(
        vm_handle: u16,
        kind: u8,
        count: u8,
        entries_ptr: [*]const u64,
        entries_len: usize,
    ) callconv(.c) c.Regs;
    extern fn vmInjectIrq(vm_handle: u16, irq_num: u64, assert_word: u64) callconv(.c) c.Regs;
    extern fn createPort(caps: u64) callconv(.c) c.Regs;
    extern fn suspendEc(
        target: u16,
        port: u16,
        attachments_ptr: [*]const u64,
        attachments_len: usize,
    ) callconv(.c) c.Regs;
    extern fn recv(port: u16, timeout_ns: u64) callconv(.c) c.RecvReturn;
    extern fn bindEventRoute(target: u16, event_type: u64, port: u16) callconv(.c) c.Regs;
    extern fn clearEventRoute(target: u16, event_type: u64) callconv(.c) c.Regs;
    extern fn reply(reply_handle: u16) callconv(.c) c.Regs;
    extern fn replyTransfer(
        reply_handle: u16,
        attachments_ptr: [*]const u64,
        attachments_len: usize,
    ) callconv(.c) c.Regs;
    extern fn timerArm(caps: u64, deadline_ns: u64, flags: u64) callconv(.c) c.Regs;
    extern fn timerRearm(timer_handle: u16, deadline_ns: u64, flags: u64) callconv(.c) c.Regs;
    extern fn timerCancel(timer_handle: u16) callconv(.c) c.Regs;
    extern fn futexWaitVal(
        timeout_ns: u64,
        pairs_ptr: [*]const u64,
        pairs_len: usize,
    ) callconv(.c) c.Regs;
    extern fn futexWaitChange(
        timeout_ns: u64,
        pairs_ptr: [*]const u64,
        pairs_len: usize,
    ) callconv(.c) c.Regs;
    extern fn futexWake(addr: u64, count: u64) callconv(.c) c.Regs;
    extern fn timeMonotonic() callconv(.c) c.Regs;
    extern fn timeGetwall() callconv(.c) c.Regs;
    extern fn timeSetwall(ns_since_epoch: u64) callconv(.c) c.Regs;
    extern fn random(count: u8) callconv(.c) c.Regs;
    extern fn infoSystem() callconv(.c) c.Regs;
    extern fn infoCores(core_id: u64) callconv(.c) c.Regs;
    extern fn powerShutdown() callconv(.c) c.Regs;
    extern fn powerReboot() callconv(.c) c.Regs;
    extern fn powerSleep(depth: u64) callconv(.c) c.Regs;
    extern fn powerScreenOff() callconv(.c) c.Regs;
    extern fn powerSetFreq(core_id: u64, hz: u64) callconv(.c) c.Regs;
    extern fn powerSetIdle(core_id: u64, policy: u64) callconv(.c) c.Regs;
};

// ── Public Zig-native wrappers ──────────────────────────────────────
//
// Signatures match the historical syscall.zig contract exactly so the
// 475 test sources don't have to change. Each wrapper widens
// u12/u1 → u16/u8, decomposes slices into ptr+len, and converts the
// extern struct return back to the native `Regs` / `RecvReturn`.

// 0..3: cap-table-wide ops

pub fn restrict(handle: u12, new_caps: u64) Regs {
    return fromCRegs(ext.restrict(@as(u16, handle), new_caps));
}

pub fn delete(handle: u12) Regs {
    return fromCRegs(ext.delete(@as(u16, handle)));
}

pub fn revoke(handle: u12) Regs {
    return fromCRegs(ext.revoke(@as(u16, handle)));
}

pub fn sync(handle: u12) Regs {
    return fromCRegs(ext.sync(@as(u16, handle)));
}

// 4..6: capability-domain ops

pub fn createCapabilityDomain(
    caps: u64,
    ceilings_inner: u64,
    ceilings_outer: u64,
    elf_pf: u12,
    initial_ec_affinity: u64,
    passed_handles: []const u64,
) Regs {
    return fromCRegs(ext.createCapabilityDomain(
        caps,
        ceilings_inner,
        ceilings_outer,
        @as(u16, elf_pf),
        initial_ec_affinity,
        passed_handles.ptr,
        passed_handles.len,
    ));
}

pub fn acquireEcs(target: u12) RecvReturn {
    return fromCRecvReturn(ext.acquireEcs(@as(u16, target)));
}

pub fn acquireVars(target: u12) RecvReturn {
    return fromCRecvReturn(ext.acquireVars(@as(u16, target)));
}

// 7..16: execution-context ops

pub fn createExecutionContext(
    caps: u64,
    entry: u64,
    stack_pages: u64,
    target: u64,
    affinity_mask: u64,
) Regs {
    return fromCRegs(ext.createExecutionContext(caps, entry, stack_pages, target, affinity_mask));
}

pub fn self() Regs {
    return fromCRegs(ext.self());
}

pub fn terminate(target: u12) Regs {
    return fromCRegs(ext.terminate(@as(u16, target)));
}

pub fn yieldEc(target: u64) Regs {
    return fromCRegs(ext.yieldEc(target));
}

pub fn priority(target: u12, new_priority: u64) Regs {
    return fromCRegs(ext.priority(@as(u16, target), new_priority));
}

pub fn affinity(target: u12, new_affinity: u64) Regs {
    return fromCRegs(ext.affinity(@as(u16, target), new_affinity));
}

pub fn perfmonInfo() Regs {
    return fromCRegs(ext.perfmonInfo());
}

pub fn perfmonStart(target: u12, num_configs: u64, configs: []const u64) Regs {
    return fromCRegs(ext.perfmonStart(@as(u16, target), num_configs, configs.ptr, configs.len));
}

pub fn perfmonRead(target: u12) Regs {
    return fromCRegs(ext.perfmonRead(@as(u16, target)));
}

pub fn perfmonStop(target: u12) Regs {
    return fromCRegs(ext.perfmonStop(@as(u16, target)));
}

// 17..24: VAR ops

pub fn createVar(
    caps: u64,
    props: u64,
    pages: u64,
    preferred_base: u64,
    device_region: u64,
) Regs {
    return fromCRegs(ext.createVar(caps, props, pages, preferred_base, device_region));
}

pub fn mapPf(var_handle: u12, pairs: []const u64) Regs {
    return fromCRegs(ext.mapPf(@as(u16, var_handle), pairs.ptr, pairs.len));
}

pub fn mapMmio(var_handle: u12, device_region: u12) Regs {
    return fromCRegs(ext.mapMmio(@as(u16, var_handle), @as(u16, device_region)));
}

pub fn unmap(var_handle: u12, selectors: []const u64) Regs {
    return fromCRegs(ext.unmap(@as(u16, var_handle), selectors.ptr, selectors.len));
}

pub fn remap(var_handle: u12, new_cur_rwx: u64) Regs {
    return fromCRegs(ext.remap(@as(u16, var_handle), new_cur_rwx));
}

pub fn snapshot(target_var: u12, source_var: u12) Regs {
    return fromCRegs(ext.snapshot(@as(u16, target_var), @as(u16, source_var)));
}

pub fn idcRead(var_handle: u12, offset: u64, count: u8) Regs {
    return fromCRegs(ext.idcRead(@as(u16, var_handle), offset, count));
}

pub fn idcWrite(var_handle: u12, offset: u64, qwords: []const u64) Regs {
    return fromCRegs(ext.idcWrite(@as(u16, var_handle), offset, qwords.ptr, qwords.len));
}

// 25: page frame

pub fn createPageFrame(caps: u64, props: u64, pages: u64) Regs {
    return fromCRegs(ext.createPageFrame(caps, props, pages));
}

// 26: device region

pub fn ack(device_region: u12) Regs {
    return fromCRegs(ext.ack(@as(u16, device_region)));
}

// 27..32: virtual machine

pub fn createVirtualMachine(caps: u64, policy_pf: u12) Regs {
    return fromCRegs(ext.createVirtualMachine(caps, @as(u16, policy_pf)));
}

pub fn createVcpu(caps: u64, vm_handle: u12, affinity_mask: u64, exit_port: u12) Regs {
    return fromCRegs(ext.createVcpu(caps, @as(u16, vm_handle), affinity_mask, @as(u16, exit_port)));
}

pub fn mapGuest(vm_handle: u12, pairs: []const u64) Regs {
    return fromCRegs(ext.mapGuest(@as(u16, vm_handle), pairs.ptr, pairs.len));
}

pub fn unmapGuest(vm_handle: u12, page_frames: []const u64) Regs {
    return fromCRegs(ext.unmapGuest(@as(u16, vm_handle), page_frames.ptr, page_frames.len));
}

pub fn vmSetPolicy(vm_handle: u12, kind: u1, count: u8, entries: []const u64) Regs {
    return fromCRegs(ext.vmSetPolicy(
        @as(u16, vm_handle),
        @as(u8, kind),
        count,
        entries.ptr,
        entries.len,
    ));
}

pub fn vmInjectIrq(vm_handle: u12, irq_num: u64, assert_word: u64) Regs {
    return fromCRegs(ext.vmInjectIrq(@as(u16, vm_handle), irq_num, assert_word));
}

// 33..39: port / IDC / event-route / reply

pub fn createPort(caps: u64) Regs {
    return fromCRegs(ext.createPort(caps));
}

pub fn suspendEc(target: u12, port: u12, attachments: []const u64) Regs {
    return fromCRegs(ext.suspendEc(
        @as(u16, target),
        @as(u16, port),
        attachments.ptr,
        attachments.len,
    ));
}

pub fn recv(port: u12, timeout_ns: u64) RecvReturn {
    return fromCRecvReturn(ext.recv(@as(u16, port), timeout_ns));
}

pub fn bindEventRoute(target: u12, event_type: u64, port: u12) Regs {
    return fromCRegs(ext.bindEventRoute(@as(u16, target), event_type, @as(u16, port)));
}

pub fn clearEventRoute(target: u12, event_type: u64) Regs {
    return fromCRegs(ext.clearEventRoute(@as(u16, target), event_type));
}

pub fn reply(reply_handle: u12) Regs {
    return fromCRegs(ext.reply(@as(u16, reply_handle)));
}

pub fn replyTransfer(reply_handle: u12, attachments: []const u64) Regs {
    return fromCRegs(ext.replyTransfer(
        @as(u16, reply_handle),
        attachments.ptr,
        attachments.len,
    ));
}

// 40..42: timer

pub fn timerArm(caps: u64, deadline_ns: u64, flags: u64) Regs {
    return fromCRegs(ext.timerArm(caps, deadline_ns, flags));
}

pub fn timerRearm(timer_handle: u12, deadline_ns: u64, flags: u64) Regs {
    return fromCRegs(ext.timerRearm(@as(u16, timer_handle), deadline_ns, flags));
}

pub fn timerCancel(timer_handle: u12) Regs {
    return fromCRegs(ext.timerCancel(@as(u16, timer_handle)));
}

// 43..45: futex

pub fn futexWaitVal(timeout_ns: u64, pairs: []const u64) Regs {
    return fromCRegs(ext.futexWaitVal(timeout_ns, pairs.ptr, pairs.len));
}

pub fn futexWaitChange(timeout_ns: u64, pairs: []const u64) Regs {
    return fromCRegs(ext.futexWaitChange(timeout_ns, pairs.ptr, pairs.len));
}

pub fn futexWake(addr: u64, count: u64) Regs {
    return fromCRegs(ext.futexWake(addr, count));
}

// 46..51: time / rng / sysinfo

pub fn timeMonotonic() Regs {
    return fromCRegs(ext.timeMonotonic());
}

pub fn timeGetwall() Regs {
    return fromCRegs(ext.timeGetwall());
}

pub fn timeSetwall(ns_since_epoch: u64) Regs {
    return fromCRegs(ext.timeSetwall(ns_since_epoch));
}

pub fn random(count: u8) Regs {
    return fromCRegs(ext.random(count));
}

pub fn infoSystem() Regs {
    return fromCRegs(ext.infoSystem());
}

pub fn infoCores(core_id: u64) Regs {
    return fromCRegs(ext.infoCores(core_id));
}

// 52..57: power

pub fn powerShutdown() Regs {
    return fromCRegs(ext.powerShutdown());
}

pub fn powerReboot() Regs {
    return fromCRegs(ext.powerReboot());
}

pub fn powerSleep(depth: u64) Regs {
    return fromCRegs(ext.powerSleep(depth));
}

pub fn powerScreenOff() Regs {
    return fromCRegs(ext.powerScreenOff());
}

pub fn powerSetFreq(core_id: u64, hz: u64) Regs {
    return fromCRegs(ext.powerSetFreq(core_id, hz));
}

pub fn powerSetIdle(core_id: u64, policy: u64) Regs {
    return fromCRegs(ext.powerSetIdle(core_id, policy));
}

// Compile-time guard against accidentally reordering the SyscallNum
// enum above. Matches the spec assignments verbatim.
comptime {
    std.debug.assert(@intFromEnum(SyscallNum.power_set_idle) == 57);
    std.debug.assert(@intFromEnum(SyscallNum.create_capability_domain) == 4);
    std.debug.assert(@intFromEnum(SyscallNum.@"suspend") == 34);
    std.debug.assert(@intFromEnum(SyscallNum.recv) == 35);
    std.debug.assert(@intFromEnum(SyscallNum.reply) == 38);
}
