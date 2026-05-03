// Spec §[recv] recv — test 10.
//
// "[test 10] on success when the sender attached no handles, pair_count = 0."
//
// Strategy
//   Stage a recv whose dequeued sender attached zero handles, then
//   inspect the receiver's syscall word to confirm pair_count = 0.
//   The sender side and the receiver side both run inside the test's
//   own capability domain so no IDC dance is required.
//
//   Setup:
//     1. create_port(caps={bind, recv}) — the test holds the bind cap
//        so §[recv] test 04 (E_CLOSED with no bind-cap holders) cannot
//        fire while the recv is parked, and holds the recv cap so
//        §[recv] test 02 (E_PERM) cannot fire on the receive call.
//        `xfer` is intentionally withheld: a port without `xfer` makes
//        any sender attaching N>0 handles trip §[handle_attachments]
//        test 01 with E_PERM, so the suspend path is forced down the
//        zero-attachment branch by the cap shape alone.
//     2. create_execution_context(target = self, caps = {susp},
//        entry = &senderEntry, stack_pages = 1, affinity = 0) — mints a
//        sibling EC inside this same domain. Since both ECs share the
//        domain's address space and handle table, the test EC can
//        publish the port's slot id and the sibling's own slot id into
//        process globals before the sibling's first syscall, and the
//        sibling can reach those values through ordinary memory loads.
//        The EC handle carries `susp` so §[suspend] test 03 (E_PERM)
//        does not fire when the sibling suspends itself; no other EC
//        cap is needed for the suspend path used here.
//
//   Synchronization:
//     The test EC stores `port_handle` and `sender_ec_handle` to a
//     shared global with release ordering, then immediately calls
//     `recv` on the port. The sibling's entry function loads those
//     globals with acquire ordering and calls `suspend(sender_ec,
//     port, attachments = &.{})`. The empty attachments slice maps
//     to syscall-word `pair_count = 0` on the suspend side
//     (§[handle_attachments] places the entries in vregs [128-N..127]
//     and `N = 0` puts no entries into the kernel's bookkeeping). The
//     kernel suspends the sibling, queues a suspension event on the
//     port, and unblocks the test EC's recv.
//
//   Assertion:
//     Per §[recv]'s syscall-word layout, pair_count occupies bits 12-19
//     of the returned word. Test 10 says: when the sender attached no
//     handles, pair_count = 0. So we mask bits 12-19 and require zero.
//     We also gate on a successful recv (the kernel must have actually
//     reached the success branch — E_CLOSED, E_FULL, or any other error
//     would make the pair_count assertion vacuous). §[recv]'s success
//     branch is signaled by the dequeued sender's vreg snapshot being
//     written into our vregs and the syscall word carrying the new
//     reply_handle_id; vreg 1 carries the snapshot of the suspended
//     EC's vreg 1 (per §[event_state]) rather than an error code, so
//     the discriminator we use is the syscall word's reply_handle_id
//     being a legal table slot (id < HANDLE_TABLE_MAX). A spec-conformant
//     success allocates a reply handle in our table; a failure leaves
//     reply_handle_id at zero or returns an error code in vreg 1 before
//     we ever read the word.
//
//   Other §[recv] error gates neutralized:
//     - test 01 (E_BADCAP for invalid port): port_handle is the freshly
//       minted handle from create_port.
//     - test 02 (E_PERM for missing recv cap): port has `recv`.
//     - test 03 (E_INVAL for reserved bits): the wrapper takes a u12
//       handle id zero-extended to u64.
//     - test 04 (E_CLOSED, no bind-cap holders): the test holds bind.
//     - test 05 (E_CLOSED while blocked): no other holder of the bind
//       cap exists, and the test does not release its bind copy.
//     - test 06 (E_FULL, table can't fit reply + N pair handles): the
//       child domain's table has slot 4 onward free; reply takes one
//       slot, N = 0 pair handles, plenty of headroom.
//
// Action
//   1. create_port(caps={bind, recv}) — must succeed.
//   2. publish port_handle and reserve a global for the sender's own
//      handle id.
//   3. create_execution_context(target=self, caps={susp}, &senderEntry,
//      stack_pages=1, affinity=0) — must succeed.
//   4. publish sender_ec_handle into the shared global with release
//      ordering so the sibling's acquire load sees it.
//   5. recv(port_handle) — blocks until the sibling suspends; on
//      return, the syscall word carries pair_count in bits 12-19 and
//      reply_handle_id in bits 32-43.
//   6. assert reply_handle_id != 0 (sanity gate that recv took the
//      success branch and inserted a reply handle in our table).
//   7. assert (word >> 12) & 0xFF == 0 — the spec line under test.
//
// Assertions
//   1: setup syscall failed (create_port or create_execution_context
//      returned an error word in vreg 1). The test 10 spec line
//      cannot be exercised if the precondition is broken.
//   2: recv did not reach a success branch — reply_handle_id in the
//      returned syscall word is zero, indicating no reply handle was
//      installed in the caller's table.
//   3: pair_count (bits 12-19 of the returned syscall word) was
//      nonzero even though the sender attached no handles — the spec
//      line under test is violated.

const builtin = @import("builtin");
const std = @import("std");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Shared globals between the test EC and the sibling sender EC. Both
// run in the same capability domain (same address space and handle
// table), so plain process-global storage is the simplest channel.
// The test EC writes with release ordering before entering recv; the
// sibling's first action is an acquire load, so the dependency edge
// from the writes to the sibling's first syscall is well-formed.
var shared_port_handle: u64 = 0;
var shared_sender_ec: u64 = 0;
var shared_ready: u64 = 0;

fn senderEntry() callconv(.c) noreturn {
    // Wait for the test EC to publish handle ids. The test EC writes
    // shared_ready last with release ordering; an acquire load that
    // observes shared_ready == 1 sees the prior writes to
    // shared_port_handle and shared_sender_ec.
    while (@atomicLoad(u64, &shared_ready, .acquire) != 1) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("pause"),
            .aarch64 => asm volatile ("yield"),
            else => @compileError("unsupported arch"),
        }
    }

    const port: u12 = @truncate(shared_port_handle & 0xFFF);
    const ec: u12 = @truncate(shared_sender_ec & 0xFFF);

    // §[suspend]: target = own EC handle, port = the result port.
    // Empty attachments slice means the syscall word's pair_count = 0
    // and no §[handle_attachments] entries are encoded. The kernel
    // queues a suspension event on the port; the test EC's recv
    // dequeues it and unblocks. After reply, the sibling resumes
    // here and halts; the test domain exits when the test EC returns.
    _ = syscall.suspendEc(ec, port, &.{});

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

    // Mint a port with bind+recv. Bind keeps the port alive for recv
    // (test 04 inert) and is required by §[suspend] test 04 on the
    // sender side. Recv is required by §[recv] test 02 on the
    // receive side. xfer is omitted — see header.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: caps.HandleId = @truncate(cp.v1 & 0xFFF);

    // Stash the port handle now; the sibling EC's first syscall is
    // suspend on this port. Use release-ordered stores so the sibling's
    // acquire load on shared_ready sees these writes.
    @atomicStore(u64, &shared_port_handle, @as(u64, port_handle), .release);

    // Mint a sibling EC. caps = {susp} so §[suspend] test 03 cannot
    // fire when the sibling suspends itself. priority = 0 stays under
    // the runner-granted pri = 3 ceiling. restart_policy = 0 keeps
    // restart_semantics test 01 inert.
    const ec_caps = caps.EcCap{ .susp = true };
    const ec_caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&senderEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const sender_ec: caps.HandleId = @truncate(cec.v1 & 0xFFF);

    // Publish the sender's own handle id, then signal the sibling.
    @atomicStore(u64, &shared_sender_ec, @as(u64, sender_ec), .release);
    @atomicStore(u64, &shared_ready, 1, .release);

    // Block on recv. The sibling will eventually call
    // suspend(sender_ec, port, attachments=&.{}); the kernel queues
    // the suspension event and unblocks this recv. The returned
    // syscall word carries reply_handle_id in bits 32-43 and
    // pair_count in bits 12-19 per §[recv] / §[event_state].
    const got = syscall.recv(port_handle, 0);

    // Sanity: the recv must have taken the success branch. A zero
    // reply_handle_id means the kernel did not install a reply handle
    // in our table — i.e. some error gate fired and pair_count is
    // meaningless for the spec line under test.
    const reply_handle_id: u64 = (got.word >> 32) & 0xFFF;
    if (reply_handle_id == 0) {
        testing.fail(2);
        return;
    }

    // §[recv] test 10: pair_count = 0 when the sender attached no
    // handles. pair_count occupies bits 12-19 of the syscall word.
    const pair_count: u64 = (got.word >> 12) & 0xFF;
    if (pair_count != 0) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
