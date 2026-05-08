// Spec §[reply] reply — test 26.
//
// "[test 26] on success when both `pair_count > 0` and
//  `recv_port_handle_id != 0`, both effects are applied atomically:
//  the resumed EC receives the attached handles, then the caller parks
//  on the named port for the next event."
//
// Strategy
//   The combo path stacks reply_transfer's pair-attachment effect on
//   top of reply_24's recv-mode park. We need THREE actors in the same
//   domain so that we can witness BOTH effects in one test:
//
//     - Test EC mints port_A (caps={bind,recv,xfer}). xfer is the
//       cap that makes the kernel mint the resulting reply handle
//       with `xfer = 1` (per §[reply] handle-ABI prose), which is in
//       turn required to attach pair entries via the unified reply.
//     - Test EC mints port_B (caps={bind,recv}). xfer is unnecessary
//       on port_B — pair_count=0 across the X→test wakeup leg.
//     - Test EC mints sibling W (caps={susp,term}, priority 1). W
//       self-suspends on port_A via raw asm so its post-resume
//       syscall word lands at the kernel's chosen syscall pad (an
//       externally-suspended EC has no pad to write — same trick as
//       reply_transfer_12.zig).
//     - Test EC mints sibling X (caps={susp,term}, priority 1). X
//       gates on g_ready_x and self-suspends on port_B AFTER the
//       test EC has parked itself on port_B via replyTransferRecv,
//       so the wakeup the test EC observes is X's suspension event.
//     - Test EC mints a page frame whose handle rides as the single
//       pair entry attached to the W-resume side. Page frame is a
//       non-IDC type, so the install caps land verbatim — no
//       idc_rx intersection to disentangle (matches
//       reply_transfer_12.zig's reasoning).
//     - W and the test EC share a domain, so the kernel-chosen
//       tstart slot is visible to us through the read-only cap
//       table mapping. W stashes its captured post-resume syscall
//       word into a shared global so the test EC can decode
//       pair_count / tstart on the W side.
//
// Action
//   1. create_port(caps={bind,recv,xfer})         — port_A
//   2. create_port(caps={bind,recv})              — port_B
//   3. create_page_frame(caps={move,r,w}, sz=4K)  — pair-entry source
//   4. create_execution_context W                 — gates on g_ready_w
//   5. create_execution_context X                 — gates on g_ready_x
//   6. release W via g_ready_w                    — W self-suspends on A
//   7. recv(port_A, 0)                            — get reply_handle_A
//   8. release X via g_ready_x                    — X gated, will susp B
//   9. replyTransferRecv(reply_handle_A, [pf_pair], port_B)
//      — atomically: resume W with pf installed, park test EC on B,
//        wake when X suspends on B with the recv contract
//   10. validate W's post-resume word: pair_count == 1, tstart names
//       a slot containing the page_frame handle with caps verbatim
//   11. validate test EC's post-recv word: event_type == suspension,
//       new reply_handle_id != 0 (kernel minted X's reply handle in
//       our table), pair_count == 0 (X attached nothing)
//
// SPEC AMBIGUITY: spec §[reply] does not pin error precedence between
// the pair-validation gates (§[reply_transfer] tests 02-09) and the
// recv-port-validation gates (§[reply] tests 22-23). The combo libz
// wrapper passes both arguments together, so an unexpected E_PERM /
// E_BADCAP from this test could indicate a precedence question rather
// than a real bug — re-read the failing assertion against the spec
// before assuming a kernel break.
//
// SPEC AMBIGUITY: spec §[event_state] tabulates the receiver-side
// recv return word's _reserved low 12 bits and reserved bits 49-63.
// We treat those as zero-or-don't-care; assertions key off
// pair_count / tstart / reply_handle_id / event_type only. The
// resumed sender's post-resume word (W's side) reuses the same field
// positions — same assumption as reply_transfer_12.zig.
//
// SPEC AMBIGUITY: spec §[event_type] enumerates `suspension = 4`,
// but libz does not export the EventType enum. The test hard-codes 4
// with a comment per §[event_type] until libz grows a typed wrapper.
//
// Assertions
//   1: setup — create_port for port_A returned an error word
//   2: setup — create_port for port_B returned an error word
//   3: setup — create_page_frame returned an error word
//   4: setup — create_execution_context for W returned an error
//   5: setup — create_execution_context for X returned an error
//   6: recv on port_A did not return OK
//   7: recv on port_A returned reply_handle_id == 0
//   8: replyTransferRecv did not return OK in vreg 1
//   9: W's post-resume syscall word reports pair_count != 1
//  10: W's post-resume tstart slot does not contain a page_frame
//      handle, or its caps differ from the entry's caps
//  11: post-recv syscall word event_type field != suspension (4)
//  12: post-recv syscall word reply_handle_id field == 0 (kernel
//      did not mint a fresh reply handle for X's suspension event)
//  13: post-recv syscall word pair_count field != 0 (X attached
//      nothing, but the kernel populated pair_count anyway)

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[event_type]: suspension = 4. libz does not export EventType.
const EVENT_TYPE_SUSPENSION: u8 = 4;

// Caps minted on the page frame whose handle we attach via the pair
// entry. Captured at module scope so the post-resume verification can
// confirm the kernel installed the handle "verbatim" per
// §[handle_attachments] (page_frame is a non-IDC type, so no idc_rx
// intersection is applied — caps land exactly as written).
const ATTACH_PF_CAPS: caps.PfCap = .{ .move = true, .r = true, .w = true };

// Cross-EC mailbox. Test EC + siblings share the same address space
// (single domain, single ELF). Same in-process pattern as
// reply_24.zig / reply_transfer_12.zig.
var g_port_a_handle: u64 = 0;
var g_port_b_handle: u64 = 0;
var g_w_self_handle: u64 = 0;
var g_x_self_handle: u64 = 0;
var g_ready_w: u32 = 0;
var g_ready_x: u32 = 0;
var g_w_observed_word: u64 = 0;
var g_w_done: u32 = 0;

fn parkForever() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfe"),
            else => @compileError("unsupported target architecture"),
        }
    }
}

fn siblingW_entry() callconv(.c) noreturn {
    while (@atomicLoad(u32, &g_ready_w, .acquire) == 0) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("pause" ::: .{ .memory = true }),
            .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
            else => @compileError("unsupported target architecture"),
        }
    }

    const port_id: u64 = g_port_a_handle;
    const self_ec_id: u64 = g_w_self_handle;

    // Self-suspend on port_A. syscall_num = 14 (.suspend); no
    // attachments from the sender side. Capture the post-resume
    // syscall word so we can read pair_count / tstart on the W side
    // (same trick as reply_transfer_12.zig's sibling).
    const word_in: u64 = @intFromEnum(syscall.SyscallNum.@"suspend");
    var word_out: u64 = undefined;
    switch (builtin.cpu.arch) {
        .x86_64 => {
            var rax_out: u64 = undefined;
            var rbx_out: u64 = undefined;
            asm volatile (
                \\ pushq %%rcx
                \\ syscall
                \\ popq %%rcx
                : [wo] "={rcx}" (word_out),
                  [v1o] "={rax}" (rax_out),
                  [v2o] "={rbx}" (rbx_out),
                : [wi] "{rcx}" (word_in),
                  [v1i] "{rax}" (self_ec_id),
                  [v2i] "{rbx}" (port_id),
                : .{
                    .rdx = true,
                    .rbp = true,
                    .rsi = true,
                    .rdi = true,
                    .r8 = true,
                    .r9 = true,
                    .r10 = true,
                    .r11 = true,
                    .r12 = true,
                    .r13 = true,
                    .r14 = true,
                    .r15 = true,
                    .memory = true,
                });
        },
        .aarch64 => {
            var x0_out: u64 = undefined;
            var x1_out: u64 = undefined;
            asm volatile (
                \\ sub sp, sp, #16
                \\ str %[wi], [sp]
                \\ svc #0
                \\ ldr %[wo], [sp]
                \\ add sp, sp, #16
                : [wo] "=&r" (word_out),
                  [v1o] "={x0}" (x0_out),
                  [v2o] "={x1}" (x1_out),
                : [wi] "r" (word_in),
                  [v1i] "{x0}" (self_ec_id),
                  [v2i] "{x1}" (port_id),
                : .{ .x2 = true, .x3 = true, .x4 = true, .x5 = true, .x6 = true,
                     .x7 = true, .x8 = true, .x9 = true, .x10 = true, .x11 = true,
                     .x12 = true, .x13 = true, .x14 = true, .x15 = true, .x16 = true,
                     .x17 = true, .x19 = true, .x20 = true, .x21 = true, .x22 = true,
                     .x23 = true, .x24 = true, .x25 = true, .x26 = true, .x27 = true,
                     .x28 = true, .x29 = true, .x30 = true, .memory = true });
        },
        else => @compileError("unsupported target architecture"),
    }

    @atomicStore(u64, &g_w_observed_word, word_out, .release);
    @atomicStore(u32, &g_w_done, 1, .release);

    parkForever();
}

fn siblingX_entry() callconv(.c) noreturn {
    while (@atomicLoad(u32, &g_ready_x, .acquire) == 0) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("pause" ::: .{ .memory = true }),
            .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
            else => @compileError("unsupported target architecture"),
        }
    }

    const port_id: u64 = g_port_b_handle;
    const self_ec_id: u64 = g_x_self_handle;

    // X's self-suspend on port_B. We don't care about the post-resume
    // word on this side — the test EC verifies the wakeup contract
    // through its own recv-side return.
    const word_in: u64 = @intFromEnum(syscall.SyscallNum.@"suspend");
    switch (builtin.cpu.arch) {
        .x86_64 => {
            asm volatile (
                \\ pushq %%rcx
                \\ syscall
                \\ popq %%rcx
                :
                : [wi] "{rcx}" (word_in),
                  [v1i] "{rax}" (self_ec_id),
                  [v2i] "{rbx}" (port_id),
                : .{
                    .rcx = true,
                    .rax = true,
                    .rbx = true,
                    .rdx = true,
                    .rbp = true,
                    .rsi = true,
                    .rdi = true,
                    .r8 = true,
                    .r9 = true,
                    .r10 = true,
                    .r11 = true,
                    .r12 = true,
                    .r13 = true,
                    .r14 = true,
                    .r15 = true,
                    .memory = true,
                });
        },
        .aarch64 => {
            asm volatile (
                \\ sub sp, sp, #16
                \\ str %[wi], [sp]
                \\ svc #0
                \\ add sp, sp, #16
                :
                : [wi] "r" (word_in),
                  [v1i] "{x0}" (self_ec_id),
                  [v2i] "{x1}" (port_id),
                : .{ .x0 = true, .x1 = true, .x2 = true, .x3 = true, .x4 = true,
                     .x5 = true, .x6 = true, .x7 = true, .x8 = true, .x9 = true,
                     .x10 = true, .x11 = true, .x12 = true, .x13 = true, .x14 = true,
                     .x15 = true, .x16 = true, .x17 = true, .x19 = true, .x20 = true,
                     .x21 = true, .x22 = true, .x23 = true, .x24 = true, .x25 = true,
                     .x26 = true, .x27 = true, .x28 = true, .x29 = true, .x30 = true,
                     .memory = true });
        },
        else => @compileError("unsupported target architecture"),
    }

    parkForever();
}

pub fn main(cap_table_base: u64) void {
    // 1. Mint port_A with bind|recv|xfer. xfer is what makes the
    //    kernel mint the resulting reply handle with xfer set, which
    //    the unified reply requires to attach pair entries (cf.
    //    §[reply_transfer] test 02 / handle-ABI prose).
    const port_a_caps = caps.PortCap{
        .xfer = true,
        .recv = true,
        .bind = true,
        .@"suspend" = true,
    };
    const cp_a = syscall.createPort(@as(u64, port_a_caps.toU16()));
    if (testing.isHandleError(cp_a.v1)) {
        testing.fail(1);
        return;
    }
    const port_a: HandleId = @truncate(cp_a.v1 & 0xFFF);

    // 2. Mint port_B with bind|recv. xfer not needed — pair_count = 0
    //    across the X→test wakeup leg.
    const port_b_caps = caps.PortCap{ .recv = true, .bind = true, .@"suspend" = true };
    const cp_b = syscall.createPort(@as(u64, port_b_caps.toU16()));
    if (testing.isHandleError(cp_b.v1)) {
        testing.fail(2);
        return;
    }
    const port_b: HandleId = @truncate(cp_b.v1 & 0xFFF);

    // 3. Mint the page frame attached as the single pair entry. A
    //    page frame is a non-IDC type, so the receiver's idc_rx does
    //    NOT mask the entry's caps — they land verbatim, which is the
    //    branch we assert in step 10 (matches reply_transfer_12.zig).
    const cpf = syscall.createPageFrame(
        @as(u64, ATTACH_PF_CAPS.toU16()),
        0, // props: sz = 0 (4 KiB)
        1,
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(3);
        return;
    }
    const pf_handle: HandleId = @truncate(cpf.v1 & 0xFFF);

    // 4. Mint sibling W with susp|term, priority 1, restart_policy = 0.
    //    susp authorizes W's self-suspend on port_A; priority 1 lets W
    //    be dispatched alongside the test EC (also priority 1) so it
    //    can reach its self-suspend.
    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, ec_caps.toU16()) | (@as(u64, 1) << 32);
    const cec_w = syscall.createExecutionContext(
        ec_caps_word,
        @intFromPtr(&siblingW_entry),
        1, // stack_pages
        0, // target = self (this domain)
        0, // affinity_mask
    );
    if (testing.isHandleError(cec_w.v1)) {
        testing.fail(4);
        return;
    }
    const w_ec: HandleId = @truncate(cec_w.v1 & 0xFFF);

    // 5. Mint sibling X with the same cap profile.
    const cec_x = syscall.createExecutionContext(
        ec_caps_word,
        @intFromPtr(&siblingX_entry),
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec_x.v1)) {
        testing.fail(5);
        return;
    }
    const x_ec: HandleId = @truncate(cec_x.v1 & 0xFFF);

    // Hand the siblings their handle ids before unleashing them.
    @atomicStore(u64, &g_port_a_handle, @as(u64, port_a), .release);
    @atomicStore(u64, &g_port_b_handle, @as(u64, port_b), .release);
    @atomicStore(u64, &g_w_self_handle, @as(u64, w_ec), .release);
    @atomicStore(u64, &g_x_self_handle, @as(u64, x_ec), .release);

    // 6. Release W. W self-suspends on port_A; the kernel queues the
    //    suspension event. X stays gated on g_ready_x — we don't want
    //    X to race onto port_B before the test EC has had a chance to
    //    park itself there via the recv-mode reply.
    @atomicStore(u32, &g_ready_w, 1, .release);

    // 7. recv on port_A. Returns the reply_handle for W's suspension.
    //    §[recv] return word: reply_handle_id at bits 32-43.
    const got_a = syscall.recv(port_a, 0);
    if (got_a.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }
    const reply_handle_a: HandleId = @truncate((got_a.word >> 32) & 0xFFF);
    if (reply_handle_a == 0) {
        testing.fail(7);
        return;
    }

    // 8. Release X. X self-suspends on port_B, which is the wakeup
    //    the test EC observes once it parks via replyTransferRecv.
    //    Release here (not earlier) keeps the sequencing readable —
    //    the kernel will buffer X's suspension event on port_B even
    //    if X reaches its syscall before the test EC parks, so the
    //    timing window is loose.
    @atomicStore(u32, &g_ready_x, 1, .release);

    // 9. Combo unified reply: pair_count=1 (pf attached) AND
    //    recv_port_handle_id=port_b. Per spec test 26 the kernel
    //    atomically (a) resumes W with the page_frame installed in
    //    its (= our) domain at a kernel-chosen tstart slot, and
    //    (b) parks the test EC on port_B for the next event. X's
    //    self-suspend on port_B feeds that recv.
    const pair_entry = caps.PairEntry{
        .id = pf_handle,
        .caps = ATTACH_PF_CAPS.toU16(),
        .move = true, // remove from our table on resume; matches PfCap.move = true
    };
    const entry_u64: u64 = pair_entry.toU64();
    const rr = syscall.replyTransferRecv(
        reply_handle_a,
        &.{entry_u64},
        port_b,
    );
    if (rr.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(8);
        return;
    }

    // 10. Wait for W to report its post-resume syscall word, then
    //     decode pair_count / tstart on the W side.
    while (@atomicLoad(u32, &g_w_done, .acquire) == 0) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("pause" ::: .{ .memory = true }),
            .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
            else => @compileError("unsupported target architecture"),
        }
    }
    const w_word = @atomicLoad(u64, &g_w_observed_word, .acquire);

    // §[event_state] receiver-side word layout (also applied to the
    // resumed sender's syscall word per the SPEC AMBIGUITY note in
    // reply_transfer_12.zig):
    //   bits 12-19: pair_count
    //   bits 20-31: tstart
    const w_pair_count: u8 = @truncate((w_word >> 12) & 0xFF);
    const w_tstart: u12 = @truncate((w_word >> 20) & 0xFFF);
    if (w_pair_count != 1) {
        testing.fail(9);
        return;
    }

    // The next N=1 slot at S=tstart in the resumed EC's domain (== ours)
    // must hold the inserted page_frame handle with caps verbatim
    // (no idc_rx intersection — page_frame is non-IDC).
    const installed = caps.readCap(cap_table_base, @as(u32, w_tstart));
    if (installed.handleType() != .page_frame or
        installed.caps() != ATTACH_PF_CAPS.toU16())
    {
        testing.fail(10);
        return;
    }

    // 11. Decode the test EC's recv-side return word for the X→test
    //     wakeup. §[event_state] return-word layout:
    //       bits 12-19: pair_count
    //       bits 32-43: reply_handle_id (the new one for X's event)
    //       bits 44-48: event_type
    const event_type: u8 = @truncate((rr.word >> 44) & 0x1F);
    const new_reply_handle_id: u12 = @truncate((rr.word >> 32) & 0xFFF);
    const pair_count_2: u8 = @truncate((rr.word >> 12) & 0xFF);

    // event_type must be `suspension` (X self-suspended).
    if (event_type != EVENT_TYPE_SUSPENSION) {
        testing.fail(11);
        return;
    }
    // The kernel must have minted a fresh reply handle for X's
    // suspension event in the test EC's table.
    if (new_reply_handle_id == 0) {
        testing.fail(12);
        return;
    }
    // X attached nothing on its self-suspend, so pair_count == 0.
    if (pair_count_2 != 0) {
        testing.fail(13);
        return;
    }

    testing.pass();
}
