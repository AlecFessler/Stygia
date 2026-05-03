// Spec §[time] / §[time_setwall] time — test 03.
//
// "[test 03] returns E_PERM if the caller's self-handle lacks `setwall`."
//
// Strategy
//   `time_setwall` requires the `setwall` bit on the caller's
//   self-handle. To exercise the no-setwall path we read the current
//   slot-0 self caps, clear only `setwall` (preserving every other
//   bool and the `pri` numeric field), then `restrict` the self-handle
//   to the reduced cap word. Restrict accepts the call because the new
//   caps are a subset of the current caps for every bitwise field, and
//   `pri` is unchanged.
//
//   The argument to `time_setwall` is 0 — a clean ns-since-epoch with
//   no reserved bits set. The setwall cap check fires before any
//   reserved-bit validation per the spec ordering of [test 03], so the
//   call must return E_PERM.
//
// Action
//   1. read self cap at slot 0; build new caps = current with setwall=0
//   2. restrict(slot 0, new caps) — must succeed
//   3. time_setwall(0) — must return E_PERM
//
// Assertions
//   1: restrict to drop setwall returned a non-OK error word
//   2: time_setwall returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const cur_caps_u16: u16 = self_cap.caps();
    const cur_self: caps.SelfCap = @bitCast(cur_caps_u16);

    var reduced = cur_self;
    reduced.setwall = false;
    const new_caps_word: u64 = @as(u64, reduced.toU16());

    const restrict_result = syscall.restrict(caps.SLOT_SELF, new_caps_word);
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    const result = syscall.timeSetwall(0);

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
