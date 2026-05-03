// Spec §[recv] recv — test 06.
//
// "[test 06] returns E_FULL if the caller's handle table cannot
//  accommodate the reply handle and pair_count attached handles."
//
// Strategy
//   `recv` only allocates table slots once it has a sender to dequeue:
//   the reply handle is minted on dequeue, plus N attached-handle slots
//   per §[handle_attachments]. The pre-block gates (E_BADCAP, E_PERM,
//   E_INVAL on [1], E_CLOSED on a structurally dead port) all fire
//   before E_FULL would be considered. Triggering E_FULL therefore
//   requires:
//     1. a port whose pre-block gates pass (valid handle, recv cap,
//        clean reserved bits, at least one bind-cap holder so E_CLOSED
//        does not fire), and
//     2. at least one suspended sender on the port at the moment recv
//        wakes, and
//     3. zero free slots in the receiver's handle table at that moment.
//
//   The simplest faithful construction in a child capability domain
//   (per runner/primary.zig spawnOne):
//     - The test holds the result port at SLOT_FIRST_PASSED with
//       bind+xfer; the runner holds bind on its own copy too. We mint
//       a fresh `port` here for the recv target so we can give
//       ourselves the `recv` cap (the result port's caps as forwarded
//       by the runner do not include `recv` by spec — the runner is
//       the receiver of result events, not the test).
//     - We spawn a helper EC inside this same capability domain. The
//       helper, on entry, calls `self()` to obtain its own EC handle
//       id, then `suspend(self_handle, port, &.{})` so it queues as
//       a sender on `port` with pair_count = 0. The handle table is
//       shared between the test and helper ECs because they share a
//       capability domain; `port` and the helper's EC handle live in
//       the same table.
//     - The test EC, after spawning the helper, saturates its handle
//       table by repeated `create_port` until E_FULL is returned.
//       With zero free slots, recv cannot mint the reply handle.
//     - The test EC then calls `recv(port)`. recv blocks until the
//       helper's suspend lands on the queue (no race window matters:
//       recv waits for a sender regardless). When the helper is
//       dequeued the kernel attempts to allocate a slot for the reply
//       handle in the test's table, finds none, and returns E_FULL.
//
//   pair_count = 0 is sufficient: spec test 06 lumps "the reply handle
//   and pair_count attached handles" — when the table cannot fit even
//   the reply handle alone, the contract still holds.
//
//   Other failure paths neutralized:
//     - test 01 (BADCAP): port handle is freshly minted and valid.
//     - test 02 (PERM): port_caps include `recv`.
//     - test 03 (INVAL on [1]): no reserved bits set.
//     - test 04 (CLOSED, no holders): the test EC keeps its bind-cap
//       holding port handle live across the recv.
//     - test 05 (CLOSED while blocked): the test never releases the
//       port between spawn and recv.
//
//   Helper entry uses the shared address space — both ECs run in the
//   same capability domain, so a top-level `var` storing the port
//   handle is visible to the helper. Stack pages are kernel-allocated
//   per `create_execution_context` so the helper's stack does not
//   collide with the test's.
//
// Action
//   1. create_port(caps={bind, recv, xfer}) — mint port for the recv.
//      Store the slot id in a top-level var so the helper EC can read
//      it.
//   2. create_execution_context(caps={susp}, entry=&helperEntry,
//      stack_pages=1, target=0, affinity=0) — spawn the helper EC in
//      this same domain.
//   3. Saturate the handle table: loop create_port(0) until E_FULL.
//   4. recv(port) — must return E_FULL in regs.v1.
//
// Assertions
//   1: create_port for the recv target failed.
//   2: create_execution_context for the helper failed.
//   3: handle table did not saturate before HANDLE_TABLE_MAX
//      iterations.
//   4: recv returned something other than E_FULL.

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Visible to both the test EC and the helper EC: they share a
// capability domain (and thus an address space) per
// `create_execution_context([4] target = 0)`.
var helper_port: u12 = 0;

fn helperEntry() callconv(.c) noreturn {
    // Resolve the helper's own EC handle id. By §[self], `self()`
    // returns a handle in the caller's table referencing the calling
    // EC; the helper's own handle was minted by the test's
    // `create_execution_context` call into this shared table.
    const sf = syscall.self();
    const helper_ec: u12 = @truncate(sf.v1 & 0xFFF);

    // Suspend ourselves on the test's recv-target port with no
    // attachments (pair_count = 0). This queues the helper as a
    // sender; the test's recv will dequeue it and attempt to mint a
    // reply handle in the (now-saturated) handle table.
    _ = syscall.suspendEc(helper_ec, helper_port, &.{});

    // If the kernel ever resumes us, halt deterministically so the
    // helper does not race the test's reporting path.
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => @compileError("unsupported arch"),
        }
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint a fresh port with `bind | recv | xfer`. `bind`
    // keeps the port from being structurally closed (test 04/05);
    // `recv` is required for the recv call itself (test 02);
    // `xfer` is harmless and preserves symmetry with the runner's
    // result port. No restart_policy bit is set so restart_semantics
    // test 05 cannot fire.
    const port_caps = caps.PortCap{
        .bind = true,
        .recv = true,
        .xfer = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    helper_port = @truncate(cp.v1 & 0xFFF);

    // Step 2: spawn a helper EC in this same capability domain. The
    // EC handle is minted into our table at some slot. Caps include
    // `susp` so the helper's `suspend(self_handle, port)` passes the
    // EC-cap check. Stack pages = 1 satisfies test 08; affinity = 0
    // (any core) and priority = 0 keep tests 06/09 quiet.
    const helper_caps = caps.EcCap{ .susp = true };
    const caps_word: u64 = @as(u64, helper_caps.toU16());
    const cec = syscall.createExecutionContext(
        caps_word,
        @intFromPtr(&helperEntry),
        1, // stack_pages
        0, // target = self
        0, // affinity = any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }

    // Step 3: saturate the handle table. Use a no-cap port for the
    // filler — `create_port` mints a slot with no extra side effects.
    // Bound the loop at HANDLE_TABLE_MAX so a misbehaving kernel
    // cannot hang the test.
    const filler_caps_word: u64 = @as(u64, (caps.PortCap{}).toU16());
    var saturated: bool = false;
    var i: u32 = 0;
    while (i < caps.HANDLE_TABLE_MAX) {
        const fp = syscall.createPort(filler_caps_word);
        if (fp.v1 == @intFromEnum(errors.Error.E_FULL)) {
            saturated = true;
            break;
        }
        i += 1;
    }
    if (!saturated) {
        testing.fail(3);
        return;
    }

    // Step 4: recv on the recv-target port. The helper's suspend
    // queues a sender on `helper_port`; the kernel attempts to mint
    // a reply handle in our table, finds zero free slots, and must
    // return E_FULL per §[recv] test 06.
    const result = syscall.recv(helper_port, 0);
    if (result.regs.v1 != @intFromEnum(errors.Error.E_FULL)) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
