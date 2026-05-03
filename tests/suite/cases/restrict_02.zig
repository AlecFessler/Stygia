// Spec §[capabilities] restrict — test 02.
//
// "[test 02] returns E_PERM if any cap field in [2].caps using bitwise
//  semantics has a bit set that is not set in the handle's current caps."
//
// Strategy
//   Use a port handle so failure mode is unambiguously the bitwise
//   subset check. Port caps have no field that uses the alternate
//   numeric semantics (those exist only on EC and VAR handles, which
//   tests 03 and 04 cover separately).
//
//   Mint a port with `bind` only. Then call restrict to install a
//   superset {bind, recv}: the recv bit is set in new but not in
//   current, so the subset check must reject with E_PERM.
//
// Action
//   1. create_port(caps={bind})        — must succeed
//   2. restrict(port, caps={bind,recv}) — must return E_PERM
//
// Assertions
//   1: setup syscall failed (create_port returned an error word)
//   2: restrict returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const initial = caps.PortCap{ .bind = true };
    const cp = syscall.createPort(@as(u64, initial.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    const expanded = caps.PortCap{ .bind = true, .recv = true };
    const new_caps_word: u64 = @as(u64, expanded.toU16());
    const result = syscall.restrict(port_handle, new_caps_word);

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
