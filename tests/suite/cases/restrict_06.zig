// Spec §[capabilities] restrict — test 06.
//
// "[test 06] on success, the handle's caps field equals [2].caps."
//
// Strategy
//   Mint a port handle with multi-bit caps {bind, recv, xfer} so a
//   strict-subset reduction is well-defined. Port caps use bitwise
//   subset semantics — no `restart_policy` numeric corner here — so
//   the success path of restrict applies cleanly.
//
//   Then call `restrict(port, {bind})`, dropping `recv` and `xfer`.
//   The new caps {bind} are a strict subset of the current caps;
//   reserved bits are clean; the handle is valid. Restrict must
//   succeed.
//
//   To assert the post-condition, read the cap directly out of the
//   read-only-mapped cap table (§[capabilities]: word0 carries caps
//   in bits 48-63). The caps field is part of the static handle
//   layout — not a kernel-mutable snapshot in field0/field1 — so a
//   fresh `readCap` is authoritative without calling `sync`.
//
// Action
//   1. create_port(caps={bind,recv,xfer})  — must succeed
//   2. restrict(port, caps={bind})         — must succeed
//   3. readCap(cap_table_base, port)       — verify caps == {bind}
//
// Assertions
//   1: setup syscall failed (create_port returned an error word)
//   2: restrict itself returned non-success in vreg 1
//   3: handle's caps field after restrict does not equal {bind}

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const initial = caps.PortCap{ .bind = true, .recv = true, .xfer = true };
    const cp = syscall.createPort(@as(u64, initial.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    const reduced = caps.PortCap{ .bind = true };
    const new_caps_word: u64 = @as(u64, reduced.toU16());
    const result = syscall.restrict(port_handle, new_caps_word);

    if (result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const cap = caps.readCap(cap_table_base, port_handle);
    if (cap.caps() != reduced.toU16()) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
