// Spec §[priority] priority — test 08.
//
// "[test 08] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error code."
//
// Spec semantics
//   §[execution_context] places kernel-mutable snapshots in the EC
//   handle's field0 (bits 0-1 = current scheduling priority) and
//   field1 (bits 0-63 = current core affinity mask). §[capabilities]:
//   "Any syscall that takes such a handle implicitly refreshes that
//   handle's snapshot from the authoritative kernel state as a side
//   effect" — and the priority spec restates that this implicit-sync
//   side effect fires regardless of return code.
//
//   The strong-form spec assertion needs two distinguishing snapshots:
//   one taken before the implicit refresh and one taken after, with
//   the kernel's authoritative state having drifted in between. In
//   practice that requires two cap-table slots aliasing the same EC
//   (so an operation on slot A leaves slot B stale until something
//   touches B), which in turn needs an `acquire_ecs` round-trip into
//   a sibling capability domain. The current test infrastructure
//   spawns each test as a single-domain child with no sibling, so the
//   alias-slot path is not yet wired.
//
// Degraded variant (this file)
//   With only one slot per EC, the strongest property we can pin
//   locally is that the implicit-sync side effect on the failure path
//   does not corrupt or zero field0/field1 — i.e. after a `priority`
//   call that returns E_INVAL, the slot still reflects the kernel's
//   authoritative state for that EC. We exercise both fields:
//
//     1. Create EC1 with priority = 2, affinity = 1 (core 0 only).
//        At return, the kernel writes the authoritative snapshot into
//        the new slot: field0 lo bits = 2, field1 = 1.
//     2. Call priority(EC1, 99) — out-of-range, so the kernel rejects
//        with E_INVAL (§[priority] test 04). On this *failure* path
//        the kernel must still refresh field0/field1 from authoritative
//        state, leaving them equal to (2, 1).
//     3. readCap(EC1) and verify field0 lo bits == 2 and field1 == 1.
//
//   This is strictly weaker than the spec assertion: an implementation
//   that simply leaves the slot untouched on the E_INVAL path would
//   also pass, because the slot was already in sync from creation. It
//   does, however, catch any implementation that *clobbers* the
//   snapshot on the error path (e.g., zeroing the field before the
//   pri-bound check fails), which is the most likely failure mode.
//
// Action
//   1. create_execution_context(caps={susp,term} | (priority=2 << 32),
//                               entry, stack_pages=1, target=0,
//                               affinity=1)                  — must succeed
//   2. priority(ec, 99)                                       — must return E_INVAL
//   3. readCap(ec).field0 & 0x3 == 2 and readCap(ec).field1 == 1
//
// Assertions
//   1: create_execution_context returned an error word in vreg 1
//   2: priority with out-of-range new_priority did not return E_INVAL
//   3: handle's field0 priority bits do not equal authoritative 2
//   4: handle's field1 affinity mask does not equal authoritative 1

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. priority = 2 is non-zero so an implementation that
    // zeroes field0 on the E_INVAL path would be observably wrong.
    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
    };
    const seeded_priority: u64 = 2;
    const caps_word: u64 =
        @as(u64, ec_caps.toU16()) |
        (seeded_priority << 32);

    // affinity = 1 → bit 0 set, runnable on core 0 only. Single-bit
    // mask gives a pinpoint authoritative value field1 must match.
    const seeded_affinity: u64 = 1;

    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        seeded_affinity,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // §[priority] test 04: new_priority > 3 → E_INVAL. Pick a value
    // well outside the 0..3 range so a kernel that masked low bits
    // before the check (treating 99 as 99 & 3 = 3, in range) would
    // still see it as out of range. 99 = 0b110_0011, also exceeds
    // any 2-bit mask. The handle is valid (test 01 OK), the spri
    // cap was granted at creation (test 02 OK), the caller's
    // self-handle pri ceiling = 3 in the runner so test 03 doesn't
    // fire either, and [1] has clean reserved bits (test 05 OK).
    const result = syscall.priority(ec_handle, 99);
    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    // §[execution_context] field layout: field0 bits 0-1 = pri,
    // field1 bits 0-63 = affinity mask. Read the cap entry directly
    // out of the read-only-mapped handle table. The implicit-sync
    // side effect is required by the spec to have run during the
    // E_INVAL call above, so this read sees the kernel's
    // authoritative state regardless of the failure return.
    const cap = caps.readCap(cap_table_base, ec_handle);
    if ((cap.field0 & 0x3) != seeded_priority) {
        testing.fail(3);
        return;
    }
    if (cap.field1 != seeded_affinity) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
