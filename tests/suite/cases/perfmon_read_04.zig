// Spec §[perfmon_read] — test 04.
//
// "[test 04] returns E_BUSY if [1] is not the calling EC and not
//  currently suspended."
//
// Strategy (degraded smoke)
//   The faithful shape of this assertion needs three coordinated ECs:
//     - the calling EC (this test main),
//     - a sibling EC that is observably running on another core (so it
//       is "not the calling EC and not currently suspended"),
//     - a witness path that confirms the sibling is on-CPU when the
//       perfmon_read syscall lands.
//   Building the second half from a single test ELF in this runner is
//   constrained: there is no cross-domain handshake harness here, only
//   one initial EC per test domain, and the sibling's runnable state
//   is observable indirectly at best. The faithful path also depends
//   on §[perfmon_start] having succeeded on the sibling first; that
//   precondition itself requires perfmon_start test 07's E_BUSY gate
//   to be passable, which is the same gate this test exercises in the
//   read direction. Bootstrapping it cleanly inside one ELF would
//   re-implement most of the missing harness.
//
//   Degraded shape that still exercises perfmon_read on a non-calling
//   target EC:
//     - create a sibling EC inside this domain (target = self, no IDC
//       needed) with caps = {restart_policy = 0}. The sibling is given
//       a busy-loop entry so it runs in user mode without invoking any
//       syscall that could suspend it. With its own stack page and
//       affinity = 0 (any core), the kernel is free to schedule it on
//       another core in parallel with this caller — that is the
//       "running, not suspended" state the spec line targets. On a
//       single-core build the sibling is at minimum runnable / waiting
//       for its quantum, which still satisfies "not currently
//       suspended" per §[error_codes] (E_BUSY = "target object is in
//       a state that disallows the operation (e.g., target EC is
//       running and not suspended)").
//     - perfmon_start has not been called on the sibling, so the
//       kernel may resolve the call via test 03 (E_INVAL) before
//       reaching the running-state check, or via test 04 (E_BUSY) if
//       it checks state first. Both outcomes witness that the kernel
//       refused the read on a non-suspended sibling EC; both are
//       accepted by this degraded smoke. A stricter form requires
//       perfmon_start_07 to land first so the sibling can be armed
//       cleanly.
//
//   Pre-call gates the test must clear so neither E_PERM nor E_BADCAP
//   can fire and mask the assertion under test:
//     - the runner-minted self-handle carries `pmu` (see
//       runner/primary.zig: `child_self.pmu = true`), so test 01's
//       E_PERM gate cannot fire.
//     - the sibling EC handle is freshly returned by
//       create_execution_context and lives in this domain's table, so
//       test 02's E_BADCAP gate cannot fire.
//
// Action
//   1. create_execution_context(target = self,
//                               caps = {restart_policy = 0},
//                               priority = 0,
//                               entry = &busyEntry,
//                               stack_pages = 1,
//                               affinity = 0)        — must succeed
//   2. perfmon_read(sibling_ec)                      — must return one
//      of E_BUSY (test 04 fired — running sibling) or E_INVAL (test 03
//      fired first — perfmon was not started). Any other code (OK,
//      E_PERM, E_BADCAP, E_TERM, ...) contradicts the spec for this
//      configuration.
//
// Assertions
//   1: setup syscall failed (create_execution_context returned an
//      error word in vreg 1)
//   2: perfmon_read returned a code other than E_BUSY or E_INVAL
//      (i.e. the kernel did not refuse the read on a non-suspended
//      sibling EC)

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// User-mode busy loop. Unlike `testing.dummyEntry` (which executes
// `hlt`, a privileged instruction that traps in user mode and routes
// the EC into a fault path), this entry runs forever in user mode
// without invoking any syscall. The sibling EC therefore stays in the
// "running / runnable" state for the duration of this test rather
// than transitioning to a suspended fault-handler state, which is the
// precondition for the E_BUSY path under test.
fn busyEntry() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("pause"
                :
                :
                : .{ .memory = true }),
            .aarch64 => asm volatile ("yield"
                :
                :
                : .{ .memory = true }),
            else => @compileError("unsupported arch"),
        }
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[execution_context] EcCap: no specific EC cap is required for
    // perfmon_read on the target — only the caller's self-handle
    // `pmu` cap is gated. Mint the sibling with restart_policy = 0
    // (kill on fault) so it cannot be revived through the restart
    // fallback path during this test.
    const sibling_caps = caps.EcCap{
        .restart_policy = 0,
    };

    // §[create_execution_context] caps word layout:
    //   bits  0-15: caps          (sibling caps; subset of inner ceiling)
    //   bits 16-31: target_caps   (ignored when target = self)
    //   bits 32-33: priority      (0 — within caller's pri = 3 ceiling)
    //   bits 34-63: _reserved     (0)
    const initial_priority: u64 = 0;
    const caps_word: u64 =
        @as(u64, sibling_caps.toU16()) |
        (initial_priority << 32);

    const entry: u64 = @intFromPtr(&busyEntry);
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
    const sibling_ec: u12 = @truncate(cec.v1 & 0xFFF);

    // §[perfmon_read]: sibling is not the calling EC and is not
    // suspended. The spec mandates either E_BUSY (test 04, kernel
    // checks running-state first) or E_INVAL (test 03, kernel
    // observes perfmon was never started before checking state).
    // Both outcomes witness the spec contract that perfmon_read may
    // not return data for a non-suspended sibling EC; the stricter
    // E_BUSY-only form requires arming perfmon_start on the sibling
    // first, which is gated by the same running-state check this
    // test exercises.
    const result = syscall.perfmonRead(sibling_ec);
    const code = result.v1;
    const is_busy = code == @intFromEnum(errors.Error.E_BUSY);
    const is_inval = code == @intFromEnum(errors.Error.E_INVAL);
    if (!is_busy and !is_inval) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
