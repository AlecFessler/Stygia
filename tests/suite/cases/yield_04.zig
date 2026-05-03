// Spec §[yield] yield — test 04.
//
// "[test 04] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Strategy
//   yield's implicit-sync side effect mirrors the rule sync_03 covers
//   for the explicit `sync` syscall: any syscall that takes a handle
//   refreshes that handle's kernel-mutable field0/field1 snapshot. For
//   an EC handle (§[execution_context]):
//     field0 bits 0-1   = pri
//     field0 bits 2-63  = _reserved
//     field1 bits 0-63  = affinity
//   Both are kernel-mutable; a fresh `readCap` after the syscall must
//   match the values the kernel recorded at create_execution_context
//   time (the only path that has set them on this EC so far).
//
//   Mint a fresh EC with a known priority and a known single-bit
//   affinity mask:
//     - priority = 2 (well below the child domain's pri ceiling of 3,
//       see runner/primary.zig `child_self.pri = 3`).
//     - affinity = 0x1 (core 0 always exists per §[affinity] test 03;
//       avoids the `affinity = 0 → kernel chooses` ambiguity in the
//       authoritative-mask encoding).
//   Per §[create_execution_context] tests 13 and 14, the EC's runtime
//   priority is set to `[1].priority` and its affinity is set to `[5]`,
//   so the authoritative kernel state for this EC is unambiguously
//   pri=2, affinity=0x1 immediately after creation and remains so
//   through the yield (yield does not mutate priority or affinity).
//
//   Pass that EC handle to `yield`. Per §[yield] the call has no
//   error-path on a valid handle once reserved bits are clean, so it
//   returns OK; the implicit-sync side effect must update the local
//   snapshot regardless. After the call, read the cap out of the
//   read-only-mapped cap table and assert field0 == 2 and
//   field1 == 0x1.
//
//   Other failure paths neutralized:
//     - test 01 (E_BADCAP if nonzero handle invalid): handle id comes
//       from a successful create_execution_context.
//     - test 02 (E_INVAL on reserved bits in [1]): the handle id is
//       zero-extended to u64 with no bits above bit 11 set.
//
//   The new EC begins executing at `dummyEntry` (halts forever); its
//   runnability is irrelevant to test 04 — the spec mandates the
//   refresh "regardless of whether the call returns success or another
//   error code", and pri/affinity are set at create time and not
//   touched by yield itself.
//
// Action
//   1. create_execution_context(caps={...}, entry=&dummyEntry,
//                               stack_pages=1, target=0,
//                               affinity=0x1, priority=2)
//      — must succeed, returns EC handle.
//   2. yield(ec_handle)
//      — must return OK (no error path applies on a valid handle
//        with clean reserved bits).
//   3. readCap(cap_table_base, ec_handle) must show
//      field0 == 2 and field1 == 0x1.
//
// Assertions
//   1: setup syscall failed (create_execution_context returned an
//      error word in vreg 1)
//   2: yield returned non-OK in vreg 1
//   3: post-yield field0 or field1 do not match the authoritative
//      kernel state (pri=2, affinity=0x1)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[create_execution_context] caps word layout:
    //   bits  0-15: caps          (we set susp+term for a non-zero,
    //                              well-defined cap pattern; both fit
    //                              in the child's ec_inner_ceiling)
    //   bits 16-31: target_caps   (ignored when target = self)
    //   bits 32-33: priority      = 2
    //   bits 34-63: _reserved     = 0
    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
        .restart_policy = 0,
    };
    const priority: u64 = 2;
    const caps_word: u64 = @as(u64, ec_caps.toU16()) | (priority << 32);

    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const affinity_mask: u64 = 0x1;
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        affinity_mask,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    const result = syscall.yieldEc(@as(u64, ec_handle));
    if (result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const cap = caps.readCap(cap_table_base, ec_handle);
    // §[execution_context]: field0 bits 0-1 = pri (rest reserved/zero);
    // field1 bits 0-63 = affinity. Authoritative state for this EC is
    // pri=2, affinity=0x1 (set at create time, untouched by yield).
    if (cap.field0 != priority or cap.field1 != affinity_mask) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
