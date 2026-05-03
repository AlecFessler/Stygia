// Spec §[bind_event_route] — test 04.
//
// "[test 04] returns E_INVAL if any reserved bits are set in [1], [2],
//  or [3]."
//
// Strategy
//   §[bind_event_route] takes three args:
//
//     bind_event_route([1] target, [2] event_type, [3] port) -> void
//
//   Per §[capabilities] / §[handle_layout], handle arguments carry
//   only the 12-bit handle id in bits 0-11 with bits 12-63 _reserved.
//   Per §[event_type], the registerable event types are {1, 2, 3, 6};
//   per §[recv]'s syscall word layout, event_type occupies a 5-bit
//   field (bits 44-48), so values that fit in 5 bits are sufficient
//   to denote the registerable set, and any bit beyond the value's
//   5-bit window in [2] is _reserved. Per §[syscall_abi] line 41:
//   "Bits not assigned by the invoked syscall must be zero on entry;
//   the kernel returns E_INVAL if a reserved bit is set." That gate
//   fires at the ABI layer — before the per-syscall semantic checks
//   (E_BADCAP, E_PERM in this section's tests 01, 02, 05, 06, 07).
//
//   The test exercises three branches, one per reserved-bit reservoir,
//   asserting E_INVAL each time. To isolate the reserved-bit gate from
//   §[bind_event_route]'s other failure paths:
//     - test 01 (E_BADCAP on [1]):  use SLOT_INITIAL_EC, which the
//                                    runner installs as a valid EC
//                                    handle in every spawned child.
//     - test 02 (E_BADCAP on [3]):  use SLOT_FIRST_PASSED, which the
//                                    runner installs as the result
//                                    port handle with bind + xfer caps.
//     - test 03 (E_INVAL on [2]):   use event_type = 1 (memory_fault),
//                                    a registerable type per
//                                    §[event_type].
//     - test 05 (E_PERM, no bind):  SLOT_FIRST_PASSED carries the
//                                    `bind` cap (set by the runner).
//   The remaining gates — test 06 (no `bind` on [1]) and test 07
//   (no `rebind` when a prior route exists) — can't both be neutralized
//   from within this test: the runner mints the initial EC handle with
//   caps = `ec_inner_ceiling` (bits 0-7 of self_caps), which excludes
//   `bind` (bit 10) and `rebind` (bit 11). Per §[syscall_abi]'s ABI-
//   layer reserved-bit gate, however, the reserved-bit check fires
//   strictly before the per-syscall E_PERM check, so test 06 cannot
//   preempt the reserved-bit observation here.
//
//   SPEC AMBIGUITY: Branch B sets bit 5 of [2] on top of value 1.
//   Spec §[event_type] does not pin the exact width of [2]'s value
//   field; the recv syscall-word layout uses 5 bits (44-48), and we
//   adopt the same width here for the value/reserved boundary. An
//   implementation that treats bits 3-63 as reserved (3-bit value
//   space, since {1,2,3,6} fits in 3 bits) would also fire test 04 on
//   bit 5; an implementation that treats the entire u64 as the value
//   would fire test 03 instead, since 0x21 ∉ {1,2,3,6}. Either way the
//   observable kernel response is E_INVAL, which is what test 04
//   asserts.
//
//   The libz `syscall.bindEventRoute` wrapper takes `target: u12` and
//   `port: u12`, which would truncate any reserved bits before they
//   reach the kernel. We bypass the wrapper via `syscall.issueReg`
//   directly so reserved bits in v1, v2, and v3 reach the ABI gate
//   verbatim.
//
// Action
//   Branch A: reserved bit 12 of [1] (target) set.
//     issueReg(.bind_event_route,
//              .{ .v1 = SLOT_INITIAL_EC | (1<<12),
//                 .v2 = 1,
//                 .v3 = SLOT_FIRST_PASSED })
//     — must return E_INVAL.
//
//   Branch B: reserved bit 5 of [2] (event_type) set on top of value 1.
//     issueReg(.bind_event_route,
//              .{ .v1 = SLOT_INITIAL_EC,
//                 .v2 = 1 | (1<<5),
//                 .v3 = SLOT_FIRST_PASSED })
//     — must return E_INVAL.
//
//   Branch C: reserved bit 12 of [3] (port) set.
//     issueReg(.bind_event_route,
//              .{ .v1 = SLOT_INITIAL_EC,
//                 .v2 = 1,
//                 .v3 = SLOT_FIRST_PASSED | (1<<12) })
//     — must return E_INVAL.
//
// Assertions
//   1: branch A returned something other than E_INVAL.
//   2: branch B returned something other than E_INVAL.
//   3: branch C returned something other than E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const ec_slot: u64 = @as(u64, caps.SLOT_INITIAL_EC);
    const port_slot: u64 = @as(u64, caps.SLOT_FIRST_PASSED);
    const valid_event_type: u64 = 1; // memory_fault, per §[event_type]

    // Branch A: reserved bit 12 of [1] (target).
    {
        const target_with_reserved: u64 = ec_slot | (@as(u64, 1) << 12);
        const r = syscall.issueReg(.bind_event_route, 0, .{
            .v1 = target_with_reserved,
            .v2 = valid_event_type,
            .v3 = port_slot,
        });
        if (r.v1 != @intFromEnum(errors.Error.E_INVAL)) {
            testing.fail(1);
            return;
        }
    }

    // Branch B: reserved bit 5 of [2] (event_type) above value 1.
    {
        const event_type_with_reserved: u64 = valid_event_type | (@as(u64, 1) << 5);
        const r = syscall.issueReg(.bind_event_route, 0, .{
            .v1 = ec_slot,
            .v2 = event_type_with_reserved,
            .v3 = port_slot,
        });
        if (r.v1 != @intFromEnum(errors.Error.E_INVAL)) {
            testing.fail(2);
            return;
        }
    }

    // Branch C: reserved bit 12 of [3] (port).
    {
        const port_with_reserved: u64 = port_slot | (@as(u64, 1) << 12);
        const r = syscall.issueReg(.bind_event_route, 0, .{
            .v1 = ec_slot,
            .v2 = valid_event_type,
            .v3 = port_with_reserved,
        });
        if (r.v1 != @intFromEnum(errors.Error.E_INVAL)) {
            testing.fail(3);
            return;
        }
    }

    testing.pass();
}
