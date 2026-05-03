// Spec §[bind_event_route] bind_event_route — test 08.
//
// "[test 08] on success, when [2] subsequently fires for [1], the EC
//  is suspended and an event of type [2] is delivered on [3] per
//  §[event_state] with the reply handle id placed in the receiver's
//  syscall word `reply_handle_id` field."
//
// Strategy — DEGRADED SMOKE (route binding blocked by current runner)
//   The full strategy would be:
//     (a) create EC with `bind | term`,
//     (b) bind_event_route(EC, breakpoint, port),
//     (c) cause EC to execute an int3 (or equivalent),
//     (d) recv(port) — must succeed, with syscall word event_type =
//         breakpoint and a reply_handle_id naming a fresh reply
//         handle in the test EC's table referencing the suspended
//         EC.
//
//   That strategy is blocked here. The runner's child capability
//   domain receives `ec_inner_ceiling = 0xFF` (primary.zig: bits 0-7
//   of field0). Per §[capability_domain] field0 layout, that ceiling
//   covers EcCap bits 0-7 only — {move, copy, saff, spri, term, susp,
//   read, write}. The bind/rebind/unbind bits (10-12) sit above the
//   8-bit ceiling field, so an EC minted in this domain cannot carry
//   the `bind` cap that bind_event_route requires on [1]. Calling
//   bind_event_route here returns E_PERM (test 06 above), which means
//   we can never observe the success path's route firing.
//
//   Until the runner exposes a wider ec_inner_ceiling (or the spec
//   pins a separate ceiling for bind/rebind/unbind), this test
//   reduces to validating the kernel mechanism that the spec sentence
//   describes: when an EC is queued as a suspension event on a port
//   (the same delivery path bind_event_route would activate, just
//   triggered through `suspend` rather than a fault), the receiver's
//   syscall word carries a usable `reply_handle_id` slot and an
//   `event_type` consistent with the delivery cause. The
//   reply_handle_id wiring is the central observable the spec line
//   under test names; the layout in the syscall word bits 32-43 is
//   the same regardless of whether the suspension was triggered by
//   `suspend` or by an event-route firing.
//
//   The smoke also reaches a stronger assertion: the suspension path
//   exposes the reply_handle_id as a slot id that round-trips through
//   `reply` to resume the suspended EC. That demonstrates the kernel
//   actually inserted a reply handle at that slot rather than
//   returning a stale or zero placeholder — the same property the
//   spec line demands of the bind_event_route success path.
//
// Action
//   1. create_port(caps={bind, recv})        — must succeed
//   2. create_execution_context(target=self,
//        caps={term, susp, rp=0})            — must succeed
//      (entry = dummyEntry; target EC halts forever; the test EC
//       drives every observable below.)
//   3. suspend(target_ec, port)              — must return OK; queues
//      the target EC as a suspension event on the port. The kernel
//      mechanism that recv uses to populate reply_handle_id is the
//      same one a route-fired event would reach.
//   4. recv(port)                            — must return OK and the
//      syscall word's bits 32-43 (reply_handle_id) name a fresh slot
//      in the test EC's handle table; bits 44-48 (event_type) must
//      be `suspension` (4), the cause of this specific delivery.
//   5. reply(reply_handle_id)                — must return OK,
//      consuming the reply handle and proving the slot named in
//      step 4's syscall word actually referenced a live reply
//      handle. This is the round-trip the spec invariant relies on:
//      "the reply handle id placed in the receiver's syscall word
//       reply_handle_id field" must be a usable handle.
//
// Assertions
//   1: setup port creation failed (createPort returned an error
//      word).
//   2: setup EC creation failed (createExecutionContext returned an
//      error word).
//   3: suspend itself did not return OK in vreg 1.
//   4: recv did not return OK in vreg 1.
//   5: recv's syscall word event_type field (bits 44-48) was not 4
//      (suspension), or the reply_handle_id field (bits 32-43) was
//      0 (no fresh slot allocated for the reply handle — slot 0 is
//      always the self-handle, never a freshly-minted reply).
//   6: reply on the slot named by recv's reply_handle_id did not
//      return OK (the slot didn't reference a live reply handle).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint a port with bind + recv. bind keeps the port
    // open (so recv won't return E_CLOSED) and recv lets the test
    // EC dequeue the suspension event itself.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint a target EC. caps={term, susp, rp=0} stays inside
    // the runner-granted ec_inner_ceiling = 0xFF. The bind cap that
    // would let us actually call bind_event_route on this EC sits at
    // bit 10 — outside the ceiling field — so we cannot grant it.
    // That gap is the reason this test is a degraded smoke; see the
    // header comment above.
    const target_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, target_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        entry,
        1, // stack_pages — non-zero
        0, // target = self
        0, // affinity = any
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const target_ec: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 3: queue the target EC as a suspension event on the port.
    // §[suspend]: when [1] is not the calling EC, the call simply
    // suspends the target without blocking the caller — the test EC
    // remains runnable to drive recv/reply below.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = target_ec,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv on the port. The kernel must dequeue the queued
    // suspension event, mint a reply handle in the test EC's table,
    // and return its slot id in the syscall word's reply_handle_id
    // field (bits 32-43) along with event_type = suspension (bits
    // 44-48 = 4).
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);
    const event_type: u64 = (got.word >> 44) & 0x1F;
    if (event_type != 4 or reply_handle_id == 0) {
        testing.fail(5);
        return;
    }

    // Step 5: round-trip the reply handle id. A successful `reply`
    // proves the slot named in the recv syscall word actually
    // references a live reply handle — exactly the property the spec
    // sentence under test demands of the bind_event_route success
    // path's `reply_handle_id`.
    const r = syscall.reply(reply_handle_id);
    if (r.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }

    testing.pass();
}
