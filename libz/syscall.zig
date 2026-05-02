// Spec v3 vreg-ABI syscall wrappers. Architecture dispatch lives in
// the arch backends (`syscall_x64.zig`, `syscall_aarch64.zig`). This
// file owns the public API, the syscall-word encoding, and the per-
// syscall wrappers — all of which are arch-neutral.
//
// `Regs` carries the lowest 13 vregs (v1..v13). On x86-64 these are
// the only register-backed vregs; on aarch64 vregs 14..31 are also
// register-backed (x13..x30) but no current libz call site populates
// them, so `Regs` is intentionally not widened. A future spec tweak
// that exposes vregs 14..31 to userspace would lift the API; until
// then the narrow shape keeps both backends symmetric.

const std = @import("std");
const builtin = @import("builtin");

const arch_impl = switch (builtin.cpu.arch) {
    .x86_64 => @import("syscall_x64.zig"),
    .aarch64 => @import("syscall_aarch64.zig"),
    else => @compileError("unsupported target architecture for libz syscall"),
};

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

/// Spec §[reply]: reply_handle_id rides in syscall-word bits 12-23 so
/// the GPR-backed event-state vregs survive intact across the syscall
/// and the L4-style fast path is preserved.
pub fn extraReplyHandle(handle: u12) u64 {
    return (@as(u64, handle) & 0xFFF) << 12;
}

/// Spec §[reply_transfer]: reply_handle_id rides in syscall-word bits
/// 20-31 (with N at bits 12-19).
pub fn extraReplyTransferHandle(handle: u12) u64 {
    return (@as(u64, handle) & 0xFFF) << 20;
}

pub const RecvReturn = struct {
    word: u64,
    regs: Regs,
};

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

// Per-syscall wrappers below. Each returns the kernel's vreg snapshot
// (Regs) plus, where applicable, the syscall word (some recv paths
// depend on the returned syscall word for reply_handle_id / event_type
// / pair_count / tstart). For those cases we issue with a peek of the
// word via a dedicated helper.

// ---------------------------------------------------------------
// 0..3: cap-table-wide ops
// ---------------------------------------------------------------

pub fn restrict(handle: u12, new_caps: u64) Regs {
    return issueReg(.restrict, 0, .{ .v1 = handle, .v2 = new_caps });
}

pub fn delete(handle: u12) Regs {
    return issueReg(.delete, 0, .{ .v1 = handle });
}

pub fn revoke(handle: u12) Regs {
    return issueReg(.revoke, 0, .{ .v1 = handle });
}

pub fn sync(handle: u12) Regs {
    return issueReg(.sync, 0, .{ .v1 = handle });
}

// ---------------------------------------------------------------
// 4..6: capability-domain ops
// ---------------------------------------------------------------

pub fn createCapabilityDomain(
    caps: u64,
    ceilings_inner: u64,
    ceilings_outer: u64,
    elf_pf: u12,
    initial_ec_affinity: u64,
    passed_handles: []const u64,
) Regs {
    // Spec §[create_capability_domain]: [5] is the initial EC affinity
    // mask, passed handles start at [6+]. Up to 8 passed handles fit
    // in register vregs 6..13; beyond that issueStack handles spill.
    var in = Regs{
        .v1 = caps,
        .v2 = ceilings_inner,
        .v3 = ceilings_outer,
        .v4 = elf_pf,
        .v5 = initial_ec_affinity,
    };
    if (passed_handles.len >= 1) in.v6 = passed_handles[0];
    if (passed_handles.len >= 2) in.v7 = passed_handles[1];
    if (passed_handles.len >= 3) in.v8 = passed_handles[2];
    if (passed_handles.len >= 4) in.v9 = passed_handles[3];
    if (passed_handles.len >= 5) in.v10 = passed_handles[4];
    if (passed_handles.len >= 6) in.v11 = passed_handles[5];
    if (passed_handles.len >= 7) in.v12 = passed_handles[6];
    if (passed_handles.len >= 8) in.v13 = passed_handles[7];
    if (passed_handles.len > 8) {
        return issueStack(.create_capability_domain, 0, in, passed_handles[8..]);
    }
    return issueReg(.create_capability_domain, 0, in);
}

pub fn acquireEcs(target: u12) RecvReturn {
    // count is set by the kernel on return in syscall word bits 12-19.
    const word = buildWord(.acquire_ecs, 0);
    return arch_impl.issueRawCaptureWord(word, .{ .v1 = target });
}

pub fn acquireVars(target: u12) RecvReturn {
    const word = buildWord(.acquire_vars, 0);
    return arch_impl.issueRawCaptureWord(word, .{ .v1 = target });
}

// ---------------------------------------------------------------
// 7..16: execution-context ops
// ---------------------------------------------------------------

pub fn createExecutionContext(
    caps: u64,
    entry: u64,
    stack_pages: u64,
    target: u64,
    affinity_mask: u64,
) Regs {
    return issueReg(.create_execution_context, 0, .{
        .v1 = caps,
        .v2 = entry,
        .v3 = stack_pages,
        .v4 = target,
        .v5 = affinity_mask,
    });
}

pub fn self() Regs {
    return issueReg(.self, 0, .{});
}

pub fn terminate(target: u12) Regs {
    return issueReg(.terminate, 0, .{ .v1 = target });
}

pub fn yieldEc(target: u64) Regs {
    return issueReg(.yield, 0, .{ .v1 = target });
}

pub fn priority(target: u12, new_priority: u64) Regs {
    return issueReg(.priority, 0, .{ .v1 = target, .v2 = new_priority });
}

pub fn affinity(target: u12, new_affinity: u64) Regs {
    return issueReg(.affinity, 0, .{ .v1 = target, .v2 = new_affinity });
}

pub fn perfmonInfo() Regs {
    return issueReg(.perfmon_info, 0, .{});
}

pub fn perfmonStart(target: u12, num_configs: u64, configs: []const u64) Regs {
    var in = Regs{ .v1 = target, .v2 = num_configs };
    if (configs.len >= 1) in.v3 = configs[0];
    if (configs.len >= 2) in.v4 = configs[1];
    if (configs.len >= 3) in.v5 = configs[2];
    if (configs.len >= 4) in.v6 = configs[3];
    if (configs.len >= 5) in.v7 = configs[4];
    if (configs.len >= 6) in.v8 = configs[5];
    if (configs.len >= 7) in.v9 = configs[6];
    if (configs.len >= 8) in.v10 = configs[7];
    if (configs.len >= 9) in.v11 = configs[8];
    if (configs.len >= 10) in.v12 = configs[9];
    if (configs.len >= 11) in.v13 = configs[10];
    if (configs.len > 11) {
        return issueStack(.perfmon_start, 0, in, configs[11..]);
    }
    return issueReg(.perfmon_start, 0, in);
}

pub fn perfmonRead(target: u12) Regs {
    return issueReg(.perfmon_read, 0, .{ .v1 = target });
}

pub fn perfmonStop(target: u12) Regs {
    return issueReg(.perfmon_stop, 0, .{ .v1 = target });
}

// ---------------------------------------------------------------
// 17..24: VAR ops
// ---------------------------------------------------------------

pub fn createVar(
    caps: u64,
    props: u64,
    pages: u64,
    preferred_base: u64,
    device_region: u64,
) Regs {
    return issueReg(.create_var, 0, .{
        .v1 = caps,
        .v2 = props,
        .v3 = pages,
        .v4 = preferred_base,
        .v5 = device_region,
    });
}

pub fn mapPf(var_handle: u12, pairs: []const u64) Regs {
    const n: u8 = @intCast(pairs.len / 2);
    var in = Regs{ .v1 = var_handle };
    if (pairs.len >= 1) in.v2 = pairs[0];
    if (pairs.len >= 2) in.v3 = pairs[1];
    if (pairs.len >= 3) in.v4 = pairs[2];
    if (pairs.len >= 4) in.v5 = pairs[3];
    if (pairs.len >= 5) in.v6 = pairs[4];
    if (pairs.len >= 6) in.v7 = pairs[5];
    if (pairs.len >= 7) in.v8 = pairs[6];
    if (pairs.len >= 8) in.v9 = pairs[7];
    if (pairs.len >= 9) in.v10 = pairs[8];
    if (pairs.len >= 10) in.v11 = pairs[9];
    if (pairs.len >= 11) in.v12 = pairs[10];
    if (pairs.len >= 12) in.v13 = pairs[11];
    const extra = extraCount(n);
    if (pairs.len > 12) {
        return issueStack(.map_pf, extra, in, pairs[12..]);
    }
    return issueReg(.map_pf, extra, in);
}

pub fn mapMmio(var_handle: u12, device_region: u12) Regs {
    return issueReg(.map_mmio, 0, .{ .v1 = var_handle, .v2 = device_region });
}

pub fn unmap(var_handle: u12, selectors: []const u64) Regs {
    const n: u8 = @intCast(selectors.len);
    var in = Regs{ .v1 = var_handle };
    if (selectors.len >= 1) in.v2 = selectors[0];
    if (selectors.len >= 2) in.v3 = selectors[1];
    if (selectors.len >= 3) in.v4 = selectors[2];
    if (selectors.len >= 4) in.v5 = selectors[3];
    if (selectors.len >= 5) in.v6 = selectors[4];
    if (selectors.len >= 6) in.v7 = selectors[5];
    if (selectors.len >= 7) in.v8 = selectors[6];
    if (selectors.len >= 8) in.v9 = selectors[7];
    if (selectors.len >= 9) in.v10 = selectors[8];
    if (selectors.len >= 10) in.v11 = selectors[9];
    if (selectors.len >= 11) in.v12 = selectors[10];
    if (selectors.len >= 12) in.v13 = selectors[11];
    const extra = extraCount(n);
    if (selectors.len > 12) {
        return issueStack(.unmap, extra, in, selectors[12..]);
    }
    return issueReg(.unmap, extra, in);
}

pub fn remap(var_handle: u12, new_cur_rwx: u64) Regs {
    return issueReg(.remap, 0, .{ .v1 = var_handle, .v2 = new_cur_rwx });
}

pub fn snapshot(target_var: u12, source_var: u12) Regs {
    return issueReg(.snapshot, 0, .{ .v1 = target_var, .v2 = source_var });
}

pub fn idcRead(var_handle: u12, offset: u64, count: u8) Regs {
    return issueReg(.idc_read, extraCount(count), .{ .v1 = var_handle, .v2 = offset });
}

pub fn idcWrite(var_handle: u12, offset: u64, qwords: []const u64) Regs {
    const n: u8 = @intCast(qwords.len);
    var in = Regs{ .v1 = var_handle, .v2 = offset };
    if (qwords.len >= 1) in.v3 = qwords[0];
    if (qwords.len >= 2) in.v4 = qwords[1];
    if (qwords.len >= 3) in.v5 = qwords[2];
    if (qwords.len >= 4) in.v6 = qwords[3];
    if (qwords.len >= 5) in.v7 = qwords[4];
    if (qwords.len >= 6) in.v8 = qwords[5];
    if (qwords.len >= 7) in.v9 = qwords[6];
    if (qwords.len >= 8) in.v10 = qwords[7];
    if (qwords.len >= 9) in.v11 = qwords[8];
    if (qwords.len >= 10) in.v12 = qwords[9];
    if (qwords.len >= 11) in.v13 = qwords[10];
    const extra = extraCount(n);
    if (qwords.len > 11) {
        return issueStack(.idc_write, extra, in, qwords[11..]);
    }
    return issueReg(.idc_write, extra, in);
}

// ---------------------------------------------------------------
// 25: page frame
// ---------------------------------------------------------------

pub fn createPageFrame(caps: u64, props: u64, pages: u64) Regs {
    return issueReg(.create_page_frame, 0, .{
        .v1 = caps,
        .v2 = props,
        .v3 = pages,
    });
}

// ---------------------------------------------------------------
// 26: device region
// ---------------------------------------------------------------

pub fn ack(device_region: u12) Regs {
    return issueReg(.ack, 0, .{ .v1 = device_region });
}

// ---------------------------------------------------------------
// 27..32: virtual machine
// ---------------------------------------------------------------

pub fn createVirtualMachine(caps: u64, policy_pf: u12) Regs {
    return issueReg(.create_virtual_machine, 0, .{ .v1 = caps, .v2 = policy_pf });
}

pub fn createVcpu(caps: u64, vm_handle: u12, affinity_mask: u64, exit_port: u12) Regs {
    return issueReg(.create_vcpu, 0, .{
        .v1 = caps,
        .v2 = vm_handle,
        .v3 = affinity_mask,
        .v4 = exit_port,
    });
}

pub fn mapGuest(vm_handle: u12, pairs: []const u64) Regs {
    const n: u8 = @intCast(pairs.len / 2);
    var in = Regs{ .v1 = vm_handle };
    if (pairs.len >= 1) in.v2 = pairs[0];
    if (pairs.len >= 2) in.v3 = pairs[1];
    if (pairs.len >= 3) in.v4 = pairs[2];
    if (pairs.len >= 4) in.v5 = pairs[3];
    if (pairs.len >= 5) in.v6 = pairs[4];
    if (pairs.len >= 6) in.v7 = pairs[5];
    if (pairs.len >= 7) in.v8 = pairs[6];
    if (pairs.len >= 8) in.v9 = pairs[7];
    if (pairs.len >= 9) in.v10 = pairs[8];
    if (pairs.len >= 10) in.v11 = pairs[9];
    if (pairs.len >= 11) in.v12 = pairs[10];
    if (pairs.len >= 12) in.v13 = pairs[11];
    const extra = extraCount(n);
    if (pairs.len > 12) {
        return issueStack(.map_guest, extra, in, pairs[12..]);
    }
    return issueReg(.map_guest, extra, in);
}

pub fn unmapGuest(vm_handle: u12, page_frames: []const u64) Regs {
    const n: u8 = @intCast(page_frames.len);
    var in = Regs{ .v1 = vm_handle };
    if (page_frames.len >= 1) in.v2 = page_frames[0];
    if (page_frames.len >= 2) in.v3 = page_frames[1];
    if (page_frames.len >= 3) in.v4 = page_frames[2];
    if (page_frames.len >= 4) in.v5 = page_frames[3];
    if (page_frames.len >= 5) in.v6 = page_frames[4];
    if (page_frames.len >= 6) in.v7 = page_frames[5];
    if (page_frames.len >= 7) in.v8 = page_frames[6];
    if (page_frames.len >= 8) in.v9 = page_frames[7];
    if (page_frames.len >= 9) in.v10 = page_frames[8];
    if (page_frames.len >= 10) in.v11 = page_frames[9];
    if (page_frames.len >= 11) in.v12 = page_frames[10];
    if (page_frames.len >= 12) in.v13 = page_frames[11];
    const extra = extraCount(n);
    if (page_frames.len > 12) {
        return issueStack(.unmap_guest, extra, in, page_frames[12..]);
    }
    return issueReg(.unmap_guest, extra, in);
}

pub fn vmSetPolicy(vm_handle: u12, kind: u1, count: u8, entries: []const u64) Regs {
    var in = Regs{ .v1 = vm_handle };
    if (entries.len >= 1) in.v2 = entries[0];
    if (entries.len >= 2) in.v3 = entries[1];
    if (entries.len >= 3) in.v4 = entries[2];
    if (entries.len >= 4) in.v5 = entries[3];
    if (entries.len >= 5) in.v6 = entries[4];
    if (entries.len >= 6) in.v7 = entries[5];
    if (entries.len >= 7) in.v8 = entries[6];
    if (entries.len >= 8) in.v9 = entries[7];
    if (entries.len >= 9) in.v10 = entries[8];
    if (entries.len >= 10) in.v11 = entries[9];
    if (entries.len >= 11) in.v12 = entries[10];
    if (entries.len >= 12) in.v13 = entries[11];
    const extra = extraVmKind(kind, count);
    if (entries.len > 12) {
        return issueStack(.vm_set_policy, extra, in, entries[12..]);
    }
    return issueReg(.vm_set_policy, extra, in);
}

pub fn vmInjectIrq(vm_handle: u12, irq_num: u64, assert_word: u64) Regs {
    return issueReg(.vm_inject_irq, 0, .{
        .v1 = vm_handle,
        .v2 = irq_num,
        .v3 = assert_word,
    });
}

// ---------------------------------------------------------------
// 33..39: port / IDC / event-route / reply
// ---------------------------------------------------------------

pub fn createPort(caps: u64) Regs {
    return issueReg(.create_port, 0, .{ .v1 = caps });
}

pub fn suspendEc(target: u12, port: u12, attachments: []const u64) Regs {
    const n: u8 = @intCast(attachments.len);
    const extra = extraCount(n);
    if (attachments.len == 0) {
        return issueReg(.@"suspend", extra, .{ .v1 = target, .v2 = port });
    }
    // SPEC AMBIGUITY: §[handle_attachments] places pair entries at
    // vregs [128-N..127] — the *high* end of the vreg space, not vregs
    // 3..3+N-1. Implementing the high-vreg path needs a stack-pad
    // sized analogously to replyTransfer; the runner v0 doesn't attach
    // handles on suspend, so this branch is left as a stub.
    @panic("suspend with attachments: high-vreg layout not yet wired");
}

pub fn recv(port: u12, timeout_ns: u64) RecvReturn {
    const word = buildWord(.recv, 0);
    return arch_impl.issueRawCaptureWord(word, .{ .v1 = port, .v2 = timeout_ns });
}

pub fn bindEventRoute(target: u12, event_type: u64, port: u12) Regs {
    return issueReg(.bind_event_route, 0, .{
        .v1 = target,
        .v2 = event_type,
        .v3 = port,
    });
}

pub fn clearEventRoute(target: u12, event_type: u64) Regs {
    return issueReg(.clear_event_route, 0, .{ .v1 = target, .v2 = event_type });
}

pub fn reply(reply_handle: u12) Regs {
    // Spec §[reply]: reply_handle_id rides in syscall-word bits 12-23.
    // Pass empty regs — vregs 1..13 are receiver-side state mods that
    // survive the syscall as-is when the receiver hasn't modified them.
    return issueReg(.reply, extraReplyHandle(reply_handle), .{});
}

pub fn replyTransfer(reply_handle: u12, attachments: []const u64) Regs {
    // Spec §[handle_attachments]: pair entries occupy vregs `[128-N..127]`
    // — the *high* end of the vreg space. The arch backend handles the
    // platform-specific stack reservation and high-vreg slot layout
    // (different on x86-64 vs aarch64 because their GPR-backed vreg
    // bands differ in width). The reply handle id rides in syscall-word
    // bits 20-31; N rides in bits 12-19; syscall_num in bits 0-11. See
    // §[reply_transfer].
    const n: u8 = @intCast(attachments.len);
    if (n == 0 or n > 63) @panic("reply_transfer: N must be 1..63");
    const word: u64 =
        (@as(u64, @intFromEnum(SyscallNum.reply_transfer)) & 0xFFF) |
        (@as(u64, n) << 12) |
        (@as(u64, reply_handle) << 20);
    return arch_impl.replyTransferAsm(word, attachments.ptr, @as(u64, n));
}

// ---------------------------------------------------------------
// 40..42: timer
// ---------------------------------------------------------------

pub fn timerArm(caps: u64, deadline_ns: u64, flags: u64) Regs {
    return issueReg(.timer_arm, 0, .{ .v1 = caps, .v2 = deadline_ns, .v3 = flags });
}

pub fn timerRearm(timer_handle: u12, deadline_ns: u64, flags: u64) Regs {
    return issueReg(.timer_rearm, 0, .{ .v1 = timer_handle, .v2 = deadline_ns, .v3 = flags });
}

pub fn timerCancel(timer_handle: u12) Regs {
    return issueReg(.timer_cancel, 0, .{ .v1 = timer_handle });
}

// ---------------------------------------------------------------
// 43..45: futex
// ---------------------------------------------------------------

pub fn futexWaitVal(timeout_ns: u64, pairs: []const u64) Regs {
    const n: u8 = @intCast(pairs.len / 2);
    var in = Regs{ .v1 = timeout_ns };
    if (pairs.len >= 1) in.v2 = pairs[0];
    if (pairs.len >= 2) in.v3 = pairs[1];
    if (pairs.len >= 3) in.v4 = pairs[2];
    if (pairs.len >= 4) in.v5 = pairs[3];
    if (pairs.len >= 5) in.v6 = pairs[4];
    if (pairs.len >= 6) in.v7 = pairs[5];
    if (pairs.len >= 7) in.v8 = pairs[6];
    if (pairs.len >= 8) in.v9 = pairs[7];
    if (pairs.len >= 9) in.v10 = pairs[8];
    if (pairs.len >= 10) in.v11 = pairs[9];
    if (pairs.len >= 11) in.v12 = pairs[10];
    if (pairs.len >= 12) in.v13 = pairs[11];
    const extra = extraCount(n);
    if (pairs.len > 12) {
        return issueStack(.futex_wait_val, extra, in, pairs[12..]);
    }
    return issueReg(.futex_wait_val, extra, in);
}

pub fn futexWaitChange(timeout_ns: u64, pairs: []const u64) Regs {
    const n: u8 = @intCast(pairs.len / 2);
    var in = Regs{ .v1 = timeout_ns };
    if (pairs.len >= 1) in.v2 = pairs[0];
    if (pairs.len >= 2) in.v3 = pairs[1];
    if (pairs.len >= 3) in.v4 = pairs[2];
    if (pairs.len >= 4) in.v5 = pairs[3];
    if (pairs.len >= 5) in.v6 = pairs[4];
    if (pairs.len >= 6) in.v7 = pairs[5];
    if (pairs.len >= 7) in.v8 = pairs[6];
    if (pairs.len >= 8) in.v9 = pairs[7];
    if (pairs.len >= 9) in.v10 = pairs[8];
    if (pairs.len >= 10) in.v11 = pairs[9];
    if (pairs.len >= 11) in.v12 = pairs[10];
    if (pairs.len >= 12) in.v13 = pairs[11];
    const extra = extraCount(n);
    if (pairs.len > 12) {
        return issueStack(.futex_wait_change, extra, in, pairs[12..]);
    }
    return issueReg(.futex_wait_change, extra, in);
}

pub fn futexWake(addr: u64, count: u64) Regs {
    return issueReg(.futex_wake, 0, .{ .v1 = addr, .v2 = count });
}

// ---------------------------------------------------------------
// 46..51: time / rng / sysinfo
// ---------------------------------------------------------------

pub fn timeMonotonic() Regs {
    return issueReg(.time_monotonic, 0, .{});
}

pub fn timeGetwall() Regs {
    return issueReg(.time_getwall, 0, .{});
}

pub fn timeSetwall(ns_since_epoch: u64) Regs {
    return issueReg(.time_setwall, 0, .{ .v1 = ns_since_epoch });
}

pub fn random(count: u8) Regs {
    return issueReg(.random, extraCount(count), .{});
}

pub fn infoSystem() Regs {
    return issueReg(.info_system, 0, .{});
}

pub fn infoCores(core_id: u64) Regs {
    return issueReg(.info_cores, 0, .{ .v1 = core_id });
}

// ---------------------------------------------------------------
// 52..57: power
// ---------------------------------------------------------------

pub fn powerShutdown() Regs {
    return issueReg(.power_shutdown, 0, .{});
}

pub fn powerReboot() Regs {
    return issueReg(.power_reboot, 0, .{});
}

pub fn powerSleep(depth: u64) Regs {
    return issueReg(.power_sleep, 0, .{ .v1 = depth });
}

pub fn powerScreenOff() Regs {
    return issueReg(.power_screen_off, 0, .{});
}

pub fn powerSetFreq(core_id: u64, hz: u64) Regs {
    return issueReg(.power_set_freq, 0, .{ .v1 = core_id, .v2 = hz });
}

pub fn powerSetIdle(core_id: u64, policy: u64) Regs {
    return issueReg(.power_set_idle, 0, .{ .v1 = core_id, .v2 = policy });
}

