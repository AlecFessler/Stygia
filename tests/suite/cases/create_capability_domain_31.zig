// Spec §[create_capability_domain] create_capability_domain — test 31.
//
// "[test 31] on success, the new domain's initial EC has affinity
//  equal to `[5]` (any-core when 0)."
//
// Strategy
//   §[execution_context] field layout: an EC handle's field1 bits 0-63
//   carry the EC's current 64-bit affinity mask. Per §[capabilities],
//   the field1 snapshot is refreshed from kernel-authoritative state
//   by an explicit `sync` call (or as a side effect of any syscall
//   taking the handle).
//
//   The kernel mints the new domain's slot-1 initial-EC handle with
//   field1 = 0 (zero-init at mint time); a fresh `sync` is required
//   to read the authoritative current value. This is the spec's
//   blessed observation channel for the child's initial-EC affinity.
//
//   Cross-domain `acquire_ecs` is not implemented in the kernel as of
//   this writing — `kernel/caps/capability_domain.zig:acquireEcs`
//   bails with E_BADCAP on any IDC whose target is a different domain
//   than the caller's. So the parent cannot reach across the domain
//   boundary to read the child EC's field1; the assertion has to be
//   made *inside* the child via its own SLOT_INITIAL_EC handle (slot
//   1 by §[capability_domain] / §[create_capability_domain] [test
//   21]).
//
//   Pattern (mirrors create_execution_context_03):
//     - The runner stages this ELF and passes its page frame at
//       SLOT_TEST_ELF_PF. The parent path spawns a sub-domain from
//       the same ELF with `[5] = TARGET_AFFINITY`. Parent and child
//       carry the same build-time test tag; the runner indexes
//       results by tag, so whichever side reports first records the
//       outcome.
//     - The child path is selected by reading its own self-handle
//       `ec_inner_ceiling`: bit 7 cleared marks the child (the
//       parent constructs the sub-domain with ec_inner_ceiling =
//       0x7F). The child syncs SLOT_INITIAL_EC and asserts that the
//       refreshed field1 equals TARGET_AFFINITY. Only the child
//       reports; the parent returns silently after spawning.
//
//   The TARGET_AFFINITY constant is hardcoded into both paths because
//   the kernel does not provide a userspace channel for the parent
//   to whisper a runtime value to the child outside of structured
//   IPC (which would be more setup than the assertion warrants).
//
//   TARGET_AFFINITY = 0b0010 (single bit, core 1) is in range on the
//   4-core CI runner so test 32's E_INVAL gate doesn't fire, and
//   non-zero so a kernel that left field1 = 0 would visibly fail.
//
// Action
//   parent path:
//     1. createCapabilityDomain(... ec_inner_ceiling = 0x7F,
//        [5] = TARGET_AFFINITY)                              — must succeed
//     2. return — child reports
//   child path:
//     1. sync(SLOT_INITIAL_EC)                               — must succeed
//     2. readCap(SLOT_INITIAL_EC).field1 == TARGET_AFFINITY  — the assertion
//
// Assertions
//   parent path:
//     1: createCapabilityDomain returned an error word
//   child path:
//     2: sync(SLOT_INITIAL_EC) returned non-OK
//     3: child SLOT_INITIAL_EC's field1 != TARGET_AFFINITY  ← THE SPEC ASSERTION

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const SLOT_RESULT_PORT: caps.HandleId = caps.SLOT_FIRST_PASSED; // 3
const SLOT_TEST_ELF_PF: caps.HandleId = caps.SLOT_FIRST_PASSED + 1; // 4
// Mirrors libz_loader.LIBZ_PF_SLOT — the runner places the staged libz
// page frame here for every spawned test domain so its _start can
// mapPf libz at LIBZ_SLIDE.
const SLOT_LIBZ_PF: caps.HandleId = caps.SLOT_FIRST_PASSED + 2; // 5

// Single-bit, in-range, non-zero affinity. CI runner is 4-core
// (`-smp cores=4` per build.zig), so bit 1 is well in range.
const TARGET_AFFINITY: u64 = 0b0010;

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const ec_inner_ceiling: u8 = @truncate(self_cap.field0 & 0xFF);

    // bit 7 of ec_inner_ceiling distinguishes the parent (runner-spawned,
    // ceiling = 0xFF) from the child (parent-spawned, ceiling = 0x7F).
    if ((ec_inner_ceiling & 0x80) == 0) {
        // ── Child path ──────────────────────────────────────────────
        // The kernel mints SLOT_INITIAL_EC's field1 = 0 at create-time
        // (see kernel/caps/capability_domain.zig: child_cd.user_table[1]
        // .field1 = 0). The authoritative current affinity must be
        // refreshed via a sync syscall before reading.
        const sync_result = syscall.sync(caps.SLOT_INITIAL_EC);
        if (sync_result.v1 != @intFromEnum(errors.Error.OK)) {
            testing.fail(2);
            return;
        }

        // §[execution_context] field layout: field1 bits 0-63 = current
        // affinity mask. Per §[create_capability_domain] test 31 the
        // initial EC's affinity must equal [5] = TARGET_AFFINITY (which
        // the parent passed at spawn time below).
        const ec_cap = caps.readCap(cap_table_base, caps.SLOT_INITIAL_EC);
        if (ec_cap.field1 != TARGET_AFFINITY) {
            testing.fail(3);
            return;
        }

        testing.pass();
        return;
    }

    // ── Parent path ─────────────────────────────────────────────────
    // Spawn a sub-domain that re-enters this same ELF with
    // ec_inner_ceiling = 0x7F (bit 7 cleared). The sub-domain takes
    // the child branch above, syncs its SLOT_INITIAL_EC, and asserts
    // field1 == TARGET_AFFINITY.
    //
    // Mirror runner/primary.zig's child_self caps so the spawned
    // sub-domain has the cap budget needed to walk through libz
    // bootstrap (crvr for createVmar at LIBZ_SLIDE) and to call
    // sync (no cap required, but other path-shaped checks on the
    // child's self-handle and IDC ceiling subset shapes hold).
    const child_self = caps.SelfCap{
        .crec = true,
        .crvr = true,
        .pri = 3,
    };

    // §[create_capability_domain] [2] ceilings_inner sub-fields:
    //   bits  0-7   ec_inner_ceiling   = 0x7F (bit 7 cleared)
    //   bits  8-23  vmar_inner_ceiling  = 0x01FF (matches runner)
    //   bits 24-31  cridc_ceiling      = 0x3F  (matches runner)
    //   bits 32-39  pf_ceiling         = 0x1F  (matches runner)
    //   bits 40-47  vm_ceiling         = 0x01  (matches runner)
    //   bits 48-55  port_ceiling       = 0x1C  (matches runner)
    const ceilings_inner: u64 =
        @as(u64, 0x7F) |
        (@as(u64, 0x01FF) << 8) |
        (@as(u64, 0x3F) << 24) |
        (@as(u64, 0x1F) << 32) |
        (@as(u64, 0x01) << 40) |
        (@as(u64, 0x1C) << 48);

    const ceilings_outer: u64 = 0x0000_003F_03FE_FFFF;

    // Pass through the runner-supplied handles so the sub-domain can
    // bootstrap libz and report on the shared port.
    const port_caps_word = (caps.PortCap{
        .xfer = true,
        .bind = true,
    }).toU16();
    const pf_caps_word = (caps.PfCap{
        .r = true,
    }).toU16();
    const libz_pf_cap = caps.readCap(cap_table_base, SLOT_LIBZ_PF);
    const libz_pf_id = libz_pf_cap.id();
    const libz_pf_caps_word = (caps.PfCap{
        .r = true,
        .x = true,
    }).toU16();
    const passed: [3]u64 = .{
        (caps.PassedHandle{
            .id = SLOT_RESULT_PORT,
            .caps = port_caps_word,
            .move = false,
        }).toU64(),
        (caps.PassedHandle{
            .id = SLOT_TEST_ELF_PF,
            .caps = pf_caps_word,
            .move = false,
        }).toU64(),
        (caps.PassedHandle{
            .id = libz_pf_id,
            .caps = libz_pf_caps_word,
            .move = false,
        }).toU64(),
    };

    const r = syscall.createCapabilityDomain(
        @as(u64, child_self.toU16()),
        ceilings_inner,
        ceilings_outer,
        SLOT_TEST_ELF_PF,
        TARGET_AFFINITY,
        passed[0..],
    );
    if (testing.isHandleError(r.v1)) {
        testing.fail(1);
        return;
    }

    // Parent returns. The child is the sole reporter; the runner
    // indexes results by build-time test tag so a single report from
    // the child satisfies this test's slot. Returning lets `_start`
    // invoke `delete(SLOT_SELF)` and tear the parent CD down — without
    // it the parent CD stayed alive indefinitely and ~10 reps of the
    // test runner exhausted the CD slab class. The child sub-domain
    // is independent (top-level CDs are not parent-linked under v3),
    // so destroying the parent here does not affect the child's
    // ability to report.
    return;
}
