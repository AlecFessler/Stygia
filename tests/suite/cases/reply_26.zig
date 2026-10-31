// Spec §[reply] reply — test 26.
//
// "[test 26] on success when both `pair_count > 0` and
//  `recv_port_handle_id != 0`, both effects are applied atomically:
//  the resumed thread receives the attached handles, then the caller parks
//  on the named port for the next event."
//
// Strategy
//   The combo path stacks reply_transfer's pair-attachment effect on
//   top of reply_24's recv-mode park. We need THREE actors in the same
//   domain so that we can witness BOTH effects in one test:
//
//     - Test thread mints port_A (caps={bind,recv,xfer}). xfer is the
//       cap that makes the kernel mint the resulting reply handle
//       with `xfer = 1` (per §[reply] handle-ABI prose), which is in
//       turn required to attach pair entries via the unified reply.
//     - Test thread mints port_B (caps={bind,recv}). xfer is unnecessary
//       on port_B — pair_count=0 across the X→test wakeup leg.
//     - Test thread pins itself to its current core for this scenario, then
//       mints sibling W (caps={susp,term}, priority 1,
//       affinity=same core). W
//       self-suspends on port_A via libz's raw capture helper so its post-resume
//       syscall word lands at the kernel's chosen syscall pad (an
//       externally-suspended thread has no pad to write — same trick as
//       reply_transfer_12.zig). W stays at normal priority: it is
//       gated by test-published globals before suspension, so making it
//       higher priority can starve that setup path. Pinning the test thread
//       and W to the same single core prevents W from running
//       concurrently with the test thread while the combo syscall is still
//       between its resume and recv halves.
//     - Test thread mints sibling X (caps={susp,term}, priority 1,
//       affinity=same core). X gates on g_ready_x. W releases that
//       gate only after W returns from the replyTransferRecv resume,
//       then keeps yielding to X until X has entered its suspend path,
//       so X cannot queue its port_B event before the combo syscall
//       has resumed W and armed the test thread's recv-mode park on
//       port_B.
//     - Test thread mints a page frame whose handle rides as the single
//       pair entry attached to the W-resume side. Page frame is a
//       non-IDC type, so the install caps land verbatim — no
//       idc_rx intersection to disentangle (matches
//       reply_transfer_12.zig's reasoning).
//     - W and the test thread share a domain, so the kernel-chosen
//       tstart slot is visible to us through the read-only cap
//       table mapping. W stashes its captured post-resume syscall
//       word into a shared global so the test thread can decode
//       pair_count / tstart on the W side.
//
// Action
//   1. create_port(caps={bind,recv,xfer})         — port_A
//   2. create_port(caps={bind,recv})              — port_B
//   3. create_page_frame(caps={move,r,w}, sz=4K)  — pair-entry source
//   4. pin test thread to current core
//   5. create_thread W                 — gates on g_ready_w
//   6. create_thread X                 — gates on g_ready_x
//   7. release W via g_ready_w                    — W self-suspends on A
//   8. recv(port_A, 0)                            — get reply_handle_A
//   9. replyTransferRecv(reply_handle_A, [pf_pair], port_B)
//      — atomically: resume W with pf installed, park test thread on B,
//        wake when X suspends on B with the recv contract
//  10. W returns from suspend and releases X via g_ready_x
//  11. validate W's post-resume word: pair_count == 1, tstart names
//       a slot containing the page_frame handle with caps verbatim
//  12. validate test thread's post-recv word: event_type == suspension,
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
//   4: setup — self-affinity pin failed, or create_thread
//      for W returned an error
//   5: setup — create_thread for X returned an error
//   6: recv on port_A did not return OK
//   7: recv on port_A returned reply_handle_id == 0
//   8: replyTransferRecv did not return OK in vreg 1
//   9: W did not publish its post-resume syscall word, or that word
//      reports pair_count != 1
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

// Cross-thread mailbox. Test thread + siblings share the same address space
// (single domain, single ELF). Same in-process pattern as
// reply_24.zig / reply_transfer_12.zig.
var g_port_a_handle: u64 = 0;
var g_port_b_handle: u64 = 0;
var g_w_self_handle: u64 = 0;
var g_x_self_handle: u64 = 0;
var g_ready_w: u32 = 0;
var g_ready_x: u32 = 0;
var g_x_entered: u32 = 0;
var g_w_observed_word: u64 = 0;
var g_w_done: u32 = 0;

fn parkForever() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
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

    const port_id = @atomicLoad(u64, &g_port_a_handle, .acquire);
    const self_thread_id = @atomicLoad(u64, &g_w_self_handle, .acquire);

    // Raw word 0 selects the no-attachment fast-suspend ABI. Capture the
    // post-resume syscall word so we can read pair_count / tstart on the
    // W side (same trick as reply_transfer_12.zig's sibling).
    const suspended = syscall.issueRawCaptureWord(0, .{
        .v1 = self_thread_id,
        .v2 = port_id,
    });
    const word_out = suspended.word;

    @atomicStore(u64, &g_w_observed_word, word_out, .release);
    @atomicStore(u32, &g_w_done, 1, .release);
    @atomicStore(u32, &g_ready_x, 1, .release);
    const x_thread = @atomicLoad(u64, &g_x_self_handle, .acquire);
    while (@atomicLoad(u32, &g_x_entered, .acquire) == 0) {
        _ = syscall.yieldThread(x_thread);
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("pause" ::: .{ .memory = true }),
            .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
            else => @compileError("unsupported target architecture"),
        }
    }

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

    const port_id = @atomicLoad(u64, &g_port_b_handle, .acquire);
    const self_thread_id = @atomicLoad(u64, &g_x_self_handle, .acquire);
    @atomicStore(u32, &g_x_entered, 1, .release);

    // X's self-suspend on port_B. We don't care about the post-resume
    // word on this side — the test thread verifies the wakeup contract
    // through its own recv-side return.
    _ = syscall.suspendThread(@truncate(self_thread_id), @truncate(port_id), &.{});

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
    //    branch we assert in step 11 (matches reply_transfer_12.zig).
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

    const pinned_core = testing.currentCoreId();
    const sibling_affinity: u64 = @as(u64, 1) << @truncate(pinned_core);
    var self_pinned = false;
    defer {
        if (self_pinned) {
            _ = syscall.affinity(caps.SLOT_INITIAL_THREAD, 0);
        }
    }

    const self_aff = syscall.affinity(caps.SLOT_INITIAL_THREAD, sibling_affinity);
    if (self_aff.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    self_pinned = true;
    const self_yield = syscall.yieldThread(0);
    if (self_yield.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    const observed_core = testing.currentCoreId();
    if ((sibling_affinity & (@as(u64, 1) << @truncate(observed_core))) == 0) {
        testing.fail(4);
        return;
    }

    // 5. Mint sibling W with susp|term, priority 1, restart_policy = 0.
    //    susp authorizes W's self-suspend on port_A. W is a required
    //    progress helper after reply_transfer resumes it, but before
    //    g_ready_w is published it is just a gated spinner; normal
    //    priority lets the test thread finish setup. The test thread is pinned
    //    to the same core so W cannot run concurrently with it between
    //    the combo syscall's reply-transfer and recv-mode park phases.
    const thread_caps = caps.ThreadCap{
        .susp = true,
        .term = true,
        .restart_policy = 0,
    };
    const thread_caps_word: u64 = @as(u64, thread_caps.toU16()) | (@as(u64, 1) << 32);
    const created_thread_w = syscall.createThread(
        thread_caps_word,
        @intFromPtr(&siblingW_entry),
        1, // stack_pages
        0, // target = self (this domain)
        sibling_affinity,
    );
    if (testing.isHandleError(created_thread_w.v1)) {
        testing.fail(4);
        return;
    }
    const w_thread: HandleId = @truncate(created_thread_w.v1 & 0xFFF);

    // 6. Mint sibling X with the same cap profile at normal priority
    //    and the same single-core affinity.
    const created_thread_x = syscall.createThread(
        thread_caps_word,
        @intFromPtr(&siblingX_entry),
        1,
        0,
        sibling_affinity,
    );
    if (testing.isHandleError(created_thread_x.v1)) {
        testing.fail(5);
        return;
    }
    const x_thread: HandleId = @truncate(created_thread_x.v1 & 0xFFF);

    // Hand the siblings their handle ids before unleashing them.
    @atomicStore(u64, &g_port_a_handle, @as(u64, port_a), .release);
    @atomicStore(u64, &g_port_b_handle, @as(u64, port_b), .release);
    @atomicStore(u64, &g_w_self_handle, @as(u64, w_thread), .release);
    @atomicStore(u64, &g_x_self_handle, @as(u64, x_thread), .release);

    // 7. Release W. W self-suspends on port_A; the kernel queues the
    //    suspension event. X stays gated on g_ready_x — we don't want
    //    X to race onto port_B before the test thread has had a chance to
    //    park itself there via the recv-mode reply.
    @atomicStore(u32, &g_ready_w, 1, .release);

    // 8. recv on port_A. Returns the reply_handle for W's suspension.
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

    // 9. Combo unified reply: pair_count=1 (pf attached) AND
    //    recv_port_handle_id=port_b. Per spec test 26 the kernel
    //    atomically (a) resumes W with the page_frame installed in
    //    its (= our) domain at a kernel-chosen tstart slot, and
    //    (b) parks the test thread on port_B for the next event. X remains
    //    gated until W returns from this resume path, so X cannot
    //    prequeue the port_B event before the combo syscall.
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

    // 11. Wait for W to report its post-resume syscall word, then
    //     decode pair_count / tstart on the W side.
    var wait_w: usize = 0;
    while (wait_w < 1024 and @atomicLoad(u32, &g_w_done, .acquire) == 0) : (wait_w += 1) {
        _ = syscall.yieldThread(@as(u64, w_thread));
    }
    if (@atomicLoad(u32, &g_w_done, .acquire) == 0) {
        testing.fail(9);
        return;
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

    // The next N=1 slot at S=tstart in the resumed thread's domain (== ours)
    // must hold the inserted page_frame handle with caps verbatim
    // (no idc_rx intersection — page_frame is non-IDC).
    const installed = caps.readCap(cap_table_base, @as(u32, w_tstart));
    if (installed.handleType() != .page_frame or
        installed.caps() != ATTACH_PF_CAPS.toU16())
    {
        testing.fail(10);
        return;
    }

    // 12. Decode the test thread's recv-side return word for the X→test
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
    // suspension event in the test thread's table.
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
