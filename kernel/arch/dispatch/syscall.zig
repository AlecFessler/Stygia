const builtin = @import("builtin");
const stygia = @import("stygia");

const aarch64 = stygia.arch.aarch64;
const x64 = stygia.arch.x64;

const ArchCpuContext = stygia.arch.dispatch.cpu.ArchCpuContext;

pub fn setSyscallReturn(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setSyscallReturn(ctx, value),
        .aarch64 => aarch64.interrupts.setSyscallReturn(ctx, value),
        else => unreachable,
    }
}

/// Write the syscall return word to vreg 0 (`[user_sp + 0]`) — the
/// per Spec §[syscall_abi] location for syscalls whose return payload
/// (e.g. recv's reply_handle_id / event_type / pair_count / tstart)
/// lives in the syscall word rather than vreg 1. MUST be called with
/// the caller's address space active — the syscall epilogue runs in
/// the caller's CR3 / TTBR0; the resume path must `switchTo` first.
/// Write syscall-return vreg 2 — used by handle-creating syscalls to
/// deliver the new handle's field0 snapshot alongside the slot id in
/// vreg 1. Reuses the same physical reg as `setEventSubcode` (rbx on
/// x86-64; x1 on aarch64) since both ABIs back vreg 2 with the same
/// register; the names disambiguate intent at the call site.
pub fn setSyscallVreg2(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setEventSubcode(ctx, value),
        .aarch64 => aarch64.interrupts.setEventSubcode(ctx, value),
        else => unreachable,
    }
}

/// Write syscall-return vreg 3 — used by handle-creating syscalls to
/// deliver the new handle's field1 snapshot. Same physical reg as
/// `setEventAddr` (rdx on x86-64; x2 on aarch64); see `setSyscallVreg2`.
pub fn setSyscallVreg3(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setEventAddr(ctx, value),
        .aarch64 => aarch64.interrupts.setEventAddr(ctx, value),
        else => unreachable,
    }
}

/// Write syscall-return vreg 4 — used by syscalls (e.g. info_system)
/// that surface multi-vreg payloads. Same physical reg as event-state
/// vreg 4 (rbp on x86-64; x3 on aarch64).
pub fn setSyscallVreg4(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setEventVreg4(ctx, value),
        .aarch64 => aarch64.interrupts.setEventVreg4(ctx, value),
        else => unreachable,
    }
}

/// Write a syscall-return vreg by index per Spec §[syscall_abi]
/// (`docs/kernel/specv3.md` §[syscall_abi]). Indices 1..N route to the
/// architecture's GPR-backed register; indices above N spill to the
/// caller's user stack at `[user_sp + (idx - N) * 8]`.
///
///   x86-64: vregs 1..13 are GPRs (rax, rbx, rdx, rbp, rsi, rdi, r8,
///           r9, r10, r12, r13, r14, r15); vregs 14..127 land at
///           `[ctx.rsp + (idx - 13) * 8]`.
///   aarch64: vregs 1..31 are x0..x30; vregs 32..127 land at
///            `[ctx.sp_el0 + (idx - 31) * 8]`.
///
/// Used by syscalls that surface a packed array of return values
/// (e.g. `random`, `idc_read`/`idc_write`, `info_cores`,
/// `acquire_ecs`/`acquire_vmars`, `create_ecs`, `create_vmars`)
/// where the count exceeds the small fixed set covered by the
/// `setSyscallVreg{2,3,4}` helpers.
///
/// Caller contract for the stack-spill range:
///   - The caller's address space (CR3 on x86-64 / TTBR0_EL1 on
///     aarch64) MUST already be active so the user stack pages are
///     mapped — same contract as `writeUserSyscallWord`. The kernel's
///     own kernel stack is not touched; the write goes to user memory.
///   - SMAP / PAN gating is applied internally via
///     `arch.dispatch.cpu.userAccessBegin`/`End`.
///   - Vreg 0 is the syscall word at `[user_sp + 0]` and is written
///     by `writeUserSyscallWord`; this helper accepts only `idx >= 1`
///     (vreg 0 panics) and rejects `idx >= 128` (out of vreg range).
pub fn setSyscallVreg(ctx: *ArchCpuContext, idx: u8, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setSyscallVreg(ctx, idx, value),
        .aarch64 => aarch64.interrupts.setSyscallVreg(ctx, idx, value),
        else => unreachable,
    }
}

/// Write event-state vreg 2 — the per-event-type sub-code (Spec
/// §[event_state]). x86-64: rbx; aarch64: x1.
pub fn setEventSubcode(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setEventSubcode(ctx, value),
        .aarch64 => aarch64.interrupts.setEventSubcode(ctx, value),
        else => unreachable,
    }
}

/// Write event-state vreg 5 on a receiving EC — companion to
/// `getEventVreg5`.
pub fn setEventVreg5(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setEventVreg5(ctx, value),
        .aarch64 => aarch64.interrupts.setEventVreg5(ctx, value),
        else => unreachable,
    }
}

/// Read the saved instruction pointer from a suspending EC — used to
/// snapshot the sender's RIP/PC at suspend time for delivery as Spec
/// §[event_state] vreg 14 (x86-64 `[rsp+8]`) / vreg 32 (aarch64
/// `[sp+8]`) at recv time. For an EC that has never executed this
/// returns the entry point set up by `prepareEcContext`; for one
/// suspended mid-execution it returns the saved iret-frame RIP/PC.
pub fn getEventRip(ctx: *const ArchCpuContext) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.getEventRip(ctx),
        .aarch64 => aarch64.interrupts.getEventRip(ctx),
        else => unreachable,
    };
}

/// Write the saved instruction pointer on a resumed sender's frame.
/// Used by reply_transfer §[reply] test 14 to commit a write-cap
/// receiver's vreg 14 modification onto the suspended EC's iret frame
/// before `resumeFromReply` re-enqueues it.
pub fn setEventRip(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setEventRip(ctx, value),
        .aarch64 => aarch64.interrupts.setEventRip(ctx, value),
        else => unreachable,
    }
}

/// Read the event-state vreg 14 (x86-64 `[user_rsp + 8]`) / vreg 32
/// (aarch64 `[user_sp + 8]`) slot on the receiving EC — used by
/// reply_transfer §[reply] test 14 to harvest a receiver-side RIP
/// modification and commit it onto the resumed sender's saved frame.
/// Companion to `writeUserVreg14`; the same CR3/TTBR0 contract
/// applies (caller MUST be in the receiver's address space).
pub fn readUserVreg14(ctx: *const ArchCpuContext) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.readUserVreg14(ctx),
        .aarch64 => aarch64.interrupts.readUserVreg14(ctx),
        else => unreachable,
    };
}

/// Copy the §[event_state] GPR-backed vregs from `src` (the receiver's
/// in-flight syscall frame) to `dst` (the suspended sender's saved
/// frame). Used by `reply` (Spec §[reply] test 05) to commit receiver-
/// side vreg writes back to the resumed EC's user state when the
/// originating EC handle had the `write` cap. x86-64: vregs 1..13 =
/// rax/rbx/rdx/rbp/rsi/rdi/r8/r9/r10/r12/r13/r14/r15. aarch64: vregs
/// 1..31 = x0..x30.
pub fn copyEventStateGprs(dst: *ArchCpuContext, src: *const ArchCpuContext) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.copyEventStateGprs(dst, src),
        .aarch64 => aarch64.interrupts.copyEventStateGprs(dst, src),
        else => unreachable,
    }
}

/// Read the §[event_state] GPR-backed vregs 1..13 from a suspending EC
/// in canonical vreg order. Snapshotted in `suspendOnPort` and
/// re-applied on the receiver in `port.deliverEvent` when the
/// originating EC handle carries the `read` cap (Spec §[suspend] test
/// 10). x86-64 ordering matches the vreg → GPR table:
/// rax, rbx, rdx, rbp, rsi, rdi, r8, r9, r10, r12, r13, r14, r15.
/// aarch64 ordering: x0..x12 (vregs 1..13).
pub fn getEventStateGprs(ctx: *const ArchCpuContext) [13]u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.getEventStateGprs(ctx),
        .aarch64 => aarch64.interrupts.getEventStateGprs(ctx),
        else => unreachable,
    };
}

/// Write the §[event_state] GPR-backed vregs 1..13 onto a receiving
/// EC's frame in canonical vreg order. Companion to
/// `getEventStateGprs`; used by `port.deliverEvent` to project the
/// suspended sender's snapshotted GPR set onto the recv-side vregs
/// when the originating handle carries the `read` cap.
pub fn setEventStateGprs(ctx: *ArchCpuContext, gprs: [13]u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setEventStateGprs(ctx, gprs),
        .aarch64 => aarch64.interrupts.setEventStateGprs(ctx, gprs),
        else => unreachable,
    }
}

