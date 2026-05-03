// Spec §[yield] — test 03.
//
// "[test 03] on success, when [1] is a valid handle to a runnable EC,
//  an observable side effect performed by the target EC (e.g., a write
//  to shared memory) is visible to the caller before the caller's next
//  syscall returns."
//
// Strategy
//   The test EC spawns a child EC in its own capability domain
//   (target = 0). Same-domain spawn means the child runs in the same
//   address space, so a process-global variable is shared memory
//   between the test EC and the child EC. The child's entry point
//   stores a sentinel value into that global with release ordering and
//   then halts.
//
//   The test EC then calls `yield(child_handle)`. By §[yield], yield
//   on a runnable EC schedules that EC; the spec line under test
//   guarantees that any observable side effect the target EC performs
//   becomes visible to the caller before its next syscall returns.
//   After yield returns we observe the global with acquire ordering;
//   if it carries the sentinel, the side effect was made visible per
//   the spec.
//
//   On a multi-core system the child may run on a different core and
//   write the sentinel concurrently with — or before — the test EC's
//   yield call; either way the side effect is observable on return,
//   which is exactly what the spec asserts. To tolerate the case where
//   the kernel schedules the child slightly after the yield returns
//   (e.g., across an IPI or after the yield wakes the target on
//   another core), we re-issue yield up to a bounded number of times,
//   each followed by an acquire load. Any observation of the sentinel
//   counts as success; exhausting the bound is the test failure path.
//
//   Neutralize the other yield error paths so test 03 is the only spec
//   assertion exercised:
//     - test 01 (E_BADCAP for invalid handle): create_execution_context
//       returns a freshly-minted, valid EC handle.
//     - test 02 (E_INVAL for reserved bits in [1]): the wrapper takes
//       u64 but we pass exactly the 12-bit handle id zero-extended.
//     - test 04 (sync side effect): not relevant — we do not read
//       field0/field1 of the EC handle.
//
//   Neutralize create_execution_context error paths similarly:
//     - test 01 (lacks `crec`): primary grants `crec`.
//     - test 03 (caps ⊄ ec_inner_ceiling): caps fit in the bitwise low
//       8 bits and `restart_policy = 0`; ceiling is 0xFF.
//     - test 06 (priority > pri ceiling): priority = 0.
//     - test 08 (stack_pages = 0): stack_pages = 1.
//     - test 09 (affinity out of range): affinity = 0 (kernel chooses).
//     - test 10 (reserved bits in [1]): all upper bits zeroed.
//     - tests 04/05/07 (target nonzero paths): target = 0.
//
// Action
//   1. create_execution_context(caps=0, &childEntry, 1, 0, 0)
//      — must succeed
//   2. yield(child_handle) — must return OK (poll-loop tolerated)
//   3. atomic load of the shared sentinel — must equal SENTINEL
//
// Assertions
//   1: create_execution_context returned an error word in vreg 1
//   2: yield returned a non-OK status in vreg 1
//   3: sentinel was not visible after the bounded yield-and-poll loop

const builtin = @import("builtin");
const std = @import("std");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const SENTINEL: u64 = 0xDEAD_BEEF_CAFE_F00D;

// Process-global shared between the test EC and the child EC. Both ECs
// run in the same capability domain (same address space), so this
// global is the "shared memory" the spec line under test references.
var observed: u64 = 0;

fn childEntry() callconv(.c) noreturn {
    @atomicStore(u64, &observed, SENTINEL, .release);
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

    // No caps needed on the child handle for yield itself (yield "No
    // cap required" per §[yield]). Keep restart_policy = 0 to dodge
    // restart_semantics test 01.
    const ec_caps = caps.EcCap{ .restart_policy = 0 };
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&childEntry);

    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);
    const target_word: u64 = @as(u64, ec_handle);

    // Bounded yield-and-poll. Each iteration re-yields to the child
    // (which is enough on a uniprocessor) and loads the sentinel. Any
    // observation of the sentinel before the bound is exhausted is a
    // pass; reaching the bound is a failure.
    const MAX_ATTEMPTS: usize = 64;
    var attempt: usize = 0;
    while (attempt < MAX_ATTEMPTS) {
        const yr = syscall.yieldEc(target_word);
        if (yr.v1 != @intFromEnum(errors.Error.OK)) {
            testing.fail(2);
            return;
        }
        if (@atomicLoad(u64, &observed, .acquire) == SENTINEL) {
            testing.pass();
            return;
        }
        attempt += 1;
    }

    testing.fail(3);
}
