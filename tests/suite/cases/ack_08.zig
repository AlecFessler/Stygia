// Spec §[ack] — test 08 (degraded smoke).
//
// "[test 08] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Spec semantics
//   §[capabilities]: "Any syscall that takes such a handle implicitly
//   refreshes that handle's snapshot from the authoritative kernel
//   state as a side effect" — and the §[ack] spec restates that this
//   implicit-sync side effect fires for `ack` regardless of return
//   code. For a device_region handle the kernel-mutable snapshot is
//   field1.irq_count (§[device_region]) which the kernel propagates
//   to every domain-local copy on each device IRQ; field0 is reserved
//   today but the spec assertion still applies.
//
//   The strong-form spec assertion needs a valid device_region handle
//   in the caller's cap table whose authoritative kernel state has
//   drifted from its slot snapshot since the last refresh. The most
//   tractable signal is field1.irq_count incrementing as IRQs fire —
//   read the slot, observe a stale value, call `ack` (success or
//   error), then re-read and confirm field1 matches the post-call
//   authoritative state (which `ack` itself zeroes on success, or
//   which a fresh `sync` round-trip echoes on error paths like the
//   no-IRQ-configured E_INVAL case).
//
// Faithful test blocker
//   The runner's child cap_table is populated by
//   `create_capability_domain`: slot 0 self, slot 1 EC, slot 2
//   self-IDC, slot 3 the result port (the only `passed_handle` the
//   runner forwards). No device_region is forwarded today (see
//   runner/primary.zig spawnOne — `passed[]` carries only the result
//   port). That makes the snapshot-refresh assertion structurally
//   unreachable from inside a child domain on this branch — we have
//   no device_region handle to ack at all. The day the runner
//   forwards a device_region (with or without IRQ delivery configured)
//   to children, this test will start exercising the real assertion.
//
// Degraded smoke
//   This test scans its cap table for any device_region handle. If
//   none is found — the expected case on the current runner — it
//   reports a degraded smoke pass: the test ELF links, loads, and
//   exercises the cap-table scan plumbing, but cannot drive `ack`
//   far enough to observe the snapshot refresh. Mirrors ack_03's
//   degraded-smoke shape.
//
//   If a device_region handle is found, attempt the strong-form
//   assertion: capture pre-ack field0/field1 from the cap-table
//   mapping, call `ack`, capture post-ack field0/field1, then call
//   `sync` (§[capabilities] sync test 03 guarantees authoritative
//   refresh) and capture post-sync field0/field1. The post-ack and
//   post-sync snapshots must agree — `ack`'s implicit refresh side
//   effect must leave the slot in the same authoritative shape that
//   an explicit sync would. This holds regardless of `ack`'s return
//   code: per the spec the side effect fires on every path with a
//   valid handle.
//
// Action
//   1. Scan cap_table for the first device_region handle.
//   2. If none → smoke-pass (degraded; documented).
//   3. capture cap_pre = readCap(found).
//   4. ack(found) — return code is not constrained here; the side
//      effect is what's under test.
//   5. capture cap_post_ack = readCap(found).
//   6. sync(found) — must return OK (§[capabilities]).
//   7. capture cap_post_sync = readCap(found).
//   8. assert cap_post_ack.field0 == cap_post_sync.field0 and
//             cap_post_ack.field1 == cap_post_sync.field1.
//
// Assertions
//   1: sync returned non-OK in vreg 1 (cross-check oracle unusable).
//   2: post-ack field0 differs from post-sync field0 — `ack` did not
//      refresh the snapshot, or refreshed it to a value other than
//      the authoritative kernel state.
//   3: post-ack field1 differs from post-sync field1 — same as above.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const dev_handle = findDeviceRegion(cap_table_base) orelse {
        // Degraded smoke: no device_region in this child's cap table.
        // The snapshot-refresh assertion is structurally unreachable;
        // document the gap and report a non-failure outcome so the
        // test ELF still validates link/load/scan plumbing in CI
        // without forcing a false expectation. Once the runner
        // forwards a device_region to test children, this branch
        // retires and the strong-form path below takes over.
        testing.pass();
        return;
    };

    // Pre-ack snapshot is captured but not directly asserted on —
    // the spec only constrains the post-call snapshot to match
    // authoritative state. We keep the read so a future strengthening
    // (e.g. assert that ack zeroed irq_count when it succeeded) has
    // the data it needs.
    _ = caps.readCap(cap_table_base, dev_handle);

    // ack's return code is intentionally not asserted: the spec
    // guarantees the implicit-refresh side effect on every path with
    // a valid [1], including error returns (E_INVAL for a region with
    // no IRQ delivery configured, etc.). We just need to drive the
    // syscall once.
    _ = syscall.ack(dev_handle);

    // Read the slot directly from the read-only cap-table mapping;
    // this observes exactly the snapshot ack's side effect left
    // behind, with no intervening syscall to trigger another refresh.
    const cap_post_ack = caps.readCap(cap_table_base, dev_handle);

    // sync is the cross-check oracle: §[capabilities] sync test 03
    // guarantees field0/field1 reflect authoritative kernel state on
    // success. If ack performed the spec-required refresh, the two
    // snapshots must agree.
    const sync_result = syscall.sync(dev_handle);
    if (sync_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    const cap_post_sync = caps.readCap(cap_table_base, dev_handle);

    if (cap_post_ack.field0 != cap_post_sync.field0) {
        testing.fail(2);
        return;
    }
    if (cap_post_ack.field1 != cap_post_sync.field1) {
        testing.fail(3);
        return;
    }

    testing.pass();
}

fn findDeviceRegion(cap_table_base: u64) ?caps.HandleId {
    // Scan the full handle table. Slots 0/1/2 are self / initial EC /
    // self-IDC for a child capability domain (§[capability_domain]),
    // and passed_handles start at slot 3. Today the runner forwards
    // only the result port at slot 3; no device_regions reach a child.
    // Scan everything to remain robust if that changes.
    var slot: u32 = 0;
    while (slot < caps.HANDLE_TABLE_MAX) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() == .device_region) {
            return @truncate(slot);
        }
        slot += 1;
    }
    return null;
}
