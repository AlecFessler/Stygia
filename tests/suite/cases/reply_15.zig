// Spec §[reply] reply — test 15.
//
// "[test 15] returns E_PERM if any pair entry with `move = 0` references
//  a source handle that lacks the `copy` cap."
//
// Strategy
//   reply with pair_count > 0 takes a reply handle plus N pair entries
//   in the high vregs [128-N..127]. Test 15 demands the kernel reject
//   any pair entry that asks for a copy (move = 0) of a source handle
//   that does not carry the `copy` cap on its slot in the caller's
//   table.
//
//   To witness that path we need:
//     (a) A live reply handle in this process. The reply handle must
//         carry `xfer` so test 09 (E_PERM, xfer missing) cannot fire
//         instead of test 15. Per spec the kernel mints the reply at
//         recv time with xfer = 1 iff the recv'ing port had `xfer`, so
//         the pipeline below hands back a reply handle whose caps
//         include xfer.
//     (b) A source handle in our table whose caps lack `copy`. Any
//         freshly created port whose caps word omits the `copy` bit
//         qualifies — every other check (test 12 BADCAP, test 13 caps
//         subset, test 14 move-cap, test 16 same-source) is dodged by
//         the construction below.
//     (c) A pair entry value that survives the earlier guards in spec
//         test order:
//           - test 11 reserved bits clear   → bits 12-15 = 33-63 = 0
//           - test 12 valid source slot     → fresh port slot
//           - test 13 caps subset           → entry.caps ⊆ source.caps
//                                              (set entry.caps = {recv})
//           - test 14 move = 0 dodges this  → move bit cleared
//           - test 15 source lacks `copy`   → fires here
//
//   The libz `replyTransfer` wrapper places the pair entry in the
//   architecture-specific high-vreg slot (vreg 127 for N=1), so the
//   test source does not carry its own syscall ABI asm.
//
// Pipeline
//   1. create_port(p_recv, caps={bind, recv, xfer}) — host-side port:
//      bind so W can self-suspend on it, recv so we dequeue the event,
//      xfer so the minted reply handle carries xfer.
//   2. create_port(p_src,  caps={recv})              — pair-entry source:
//      no `copy`, no `move`. recv keeps the caps word non-zero so the
//      entry's caps subset check (test 13) has a real cap to subset.
//   3. pin self to the current core, then create same-core W
//   4. release W; W self-suspends on p_recv          — queues W
//   5. recv(p_recv)                                  — yields reply id
//   6. reply with one pair entry (p_src, caps={recv}, move=0).
//      Spec demands E_PERM in vreg 1 from test 15.
//
// Assertions
//   1: setup — create_port(p_recv) returned an error word
//   2: setup — create_port(p_src)  returned an error word
//   3: setup — same-core pin or create_thread failed
//   5: setup — recv(p_recv) did not return OK
//   6: reply returned something other than E_PERM (i.e. the kernel
//      did not surface the missing-`copy`/move=0 contract this test
//      exercises)

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

var g_port_handle: u64 = 0;
var g_self_handle: u64 = 0;
var g_ready: u32 = 0;

fn spinHint() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("pause" ::: .{ .memory = true }),
        .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
        else => @compileError("unsupported target architecture"),
    }
}

fn parkForever() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
            else => @compileError("unsupported target architecture"),
        }
    }
}

fn siblingEntry() callconv(.c) noreturn {
    while (@atomicLoad(u32, &g_ready, .acquire) == 0) {
        spinHint();
    }

    const self_thread_id = @atomicLoad(u64, &g_self_handle, .acquire);
    const port_id = @atomicLoad(u64, &g_port_handle, .acquire);
    _ = syscall.suspendThread(@truncate(self_thread_id), @truncate(port_id), &.{});

    parkForever();
}

// §[handle_attachments] entry layout, packed into one u64:
//   bits 0-11  source handle id
//   bits 12-15 _reserved (must be 0)
//   bits 16-31 caps to install in the receiver
//   bit  32    move
//   bits 33-63 _reserved (must be 0)
fn pairEntry(id: u12, caps_word: u16, move: bool) u64 {
    return (caps.PairEntry{
        .id = id,
        .caps = caps_word,
        .move = move,
    }).toU64();
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: host-side port. bind queues W as a suspended sender;
    // recv dequeues the event and mints the reply handle in our table.
    // xfer must be set so the minted reply handle carries xfer —
    // otherwise test 09's E_PERM gate fires before test 15.
    const p_recv_caps = caps.PortCap{
        .xfer = true,
        .recv = true,
        .bind = true,
        .@"suspend" = true,
    };
    const cp_recv = syscall.createPort(@as(u64, p_recv_caps.toU16()));
    if (testing.isHandleError(cp_recv.v1)) {
        testing.fail(1);
        return;
    }
    const p_recv: HandleId = @truncate(cp_recv.v1 & 0xFFF);

    // Step 2: source port for the pair entry. Caps lack `copy`, `move`
    // — this is the "lacks the `copy` cap" condition test 15 demands.
    // `bind` is added to satisfy create_port's structural rule (must
    // include `recv` and one of `{suspend, bind}`); the entry caps
    // subset (test 13) still holds because entry.caps = {recv} ⊆
    // {recv, bind}.
    const p_src_caps = caps.PortCap{
        .recv = true,
        .bind = true,
    };
    const cp_src = syscall.createPort(@as(u64, p_src_caps.toU16()));
    if (testing.isHandleError(cp_src.v1)) {
        testing.fail(2);
        return;
    }
    const p_src: HandleId = @truncate(cp_src.v1 & 0xFFF);

    // Step 3: pin this test thread to the core where W will be created.
    // This removes cross-core progress from the setup: once we block in
    // recv, the same scheduler queue can run W until it self-suspends.
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
        testing.fail(3);
        return;
    }
    self_pinned = true;
    const self_yield = syscall.yieldThread(0);
    if (self_yield.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }
    const observed_core = testing.currentCoreId();
    if ((sibling_affinity & (@as(u64, 1) << @truncate(observed_core))) == 0) {
        testing.fail(3);
        return;
    }

    // Step 4: sibling thread W. susp authorizes W's self-suspend; term lets
    // the spec test_07 cleanup happen if needed (not required here, but
    // mirrors terminate_07's recipe). restart_policy = 0 keeps the thread
    // inside the runner's ceiling and prevents any restart fallback.
    // Priority 1 lets W make progress after this thread parks in recv.
    const w_caps = caps.ThreadCap{
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    const thread_caps_word: u64 = @as(u64, w_caps.toU16()) | (@as(u64, 1) << 32);
    const cec = syscall.createThread(
        thread_caps_word,
        @intFromPtr(&siblingEntry),
        1, // stack_pages
        0, // target = self
        sibling_affinity,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(3);
        return;
    }
    const w_handle: HandleId = @truncate(cec.v1 & 0xFFF);

    @atomicStore(u64, &g_port_handle, @as(u64, p_recv), .release);
    @atomicStore(u64, &g_self_handle, @as(u64, w_handle), .release);
    @atomicStore(u32, &g_ready, 1, .release);

    // Step 5: recv. If W has not reached suspend yet this blocks until
    // W self-suspends on p_recv. The resulting event carries the reply
    // handle id in syscall-word bits 32-43 (per §[recv]).
    const got = syscall.recv(p_recv, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }
    const reply_handle: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 6: build the malformed pair entry. caps = {recv} (subset of
    // p_src's {recv}, dodging test 13), move = 0 (dodges test 14). The
    // source p_src has copy = 0, so test 15 must fire.
    const entry_caps = caps.PortCap{ .recv = true };
    const pe = pairEntry(p_src, entry_caps.toU16(), false);

    const result = syscall.replyTransfer(reply_handle, &.{pe});
    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(6);
        return;
    }

    testing.pass();
}
