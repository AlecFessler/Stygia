// Spec §[create_capability_domain] — test 25.
//
// "[test 25] a passed handle entry with `move = 0` remains in the
//  caller's handle table after the call."
//
// Strategy
//   The post-condition only fires on a *successful* call. The pre-v3
//   shape of this test issued the call with an unspecified-bytes page
//   frame for `[4]` and treated the move=0 invariant as orthogonal
//   to the call's outcome, but §[create_capability_domain] [test 16a]
//   correctly E_INVAL's a missing PT_DYNAMIC and the post-condition
//   under spec test 25 is then vacuous. The runner already forwards
//   this test's own ELF pf at SLOT_TEST_ELF_PF (= 4); reusing it as
//   `[4]` lands the call on the success path and lets the move=0
//   probe assert cleanly.
//
//   Donor: a fresh port with `{copy, recv, bind}`. `copy` is required
//   on the source for a `move = 0` transfer (§[handle_attachments]
//   [test 05]). We pass the donor with `caps = {bind, recv}`
//   (subset of the donor's current caps, satisfying [test 03]) and
//   `move = 0`.
//
//   Probe: spec §[capabilities] `restrict` test 03 establishes that
//   restricting on a vacated slot returns E_BADCAP. Conversely, when
//   the slot is still occupied, `restrict(donor, 0)` cannot return
//   E_BADCAP. With `new_caps = 0` reserved bits are clean and any
//   prior caps subset the request, so the call's other reject paths
//   are unreachable. Any non-E_BADCAP outcome is evidence the slot
//   is still resident.
//
//   Child path: the spawned sub-domain re-enters this same ELF and
//   takes a silent-return branch (discriminator: cridc_ceiling byte
//   in self-handle field0 != 0x3F). libz `_start` then issues
//   delete(SLOT_SELF) and the child CD tears down. No report from
//   the child; the parent is the sole reporter.
//
// Action
//   parent path:
//     1. create_port({copy, recv, bind}) — donor                  — must succeed
//     2. createCapabilityDomain(... [4] = SLOT_TEST_ELF_PF,
//        passed = [donor, caps={bind,recv}, move=0])              — must succeed
//     3. restrict(donor, 0)                                        — must NOT return E_BADCAP
//   child path:
//     - silent return; libz `_start` reaps the CD via delete(SLOT_SELF)
//
// Assertions
//   1: create_port returned an error word
//   2: createCapabilityDomain returned an error word in vreg 1
//   3: post-call restrict on the donor port returned E_BADCAP, i.e.
//      the move=0 source handle was incorrectly vacated
//      ← THE SPEC ASSERTION

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const SLOT_RESULT_PORT: caps.HandleId = caps.SLOT_FIRST_PASSED; // 3
const SLOT_TEST_ELF_PF: caps.HandleId = caps.SLOT_FIRST_PASSED + 1; // 4
const SLOT_LIBZ_PF: caps.HandleId = caps.SLOT_FIRST_PASSED + 2; // 5

// Strict-subset cridc_ceiling for the spawned sub-domain. Distinct
// from the runner-installed 0x3F so the child path can detect itself
// via the field0 cridc_ceiling byte.
const CHILD_CRIDC: u8 = 0x07;

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    // §[capability_domain] Self handle field0: cridc_ceiling at bits 24-31.
    const my_cridc_ceiling: u8 = @truncate((self_cap.field0 >> 24) & 0xFF);

    if (my_cridc_ceiling != 0x3F) {
        // ── Child path ──────────────────────────────────────────────
        // We're the spawned sub-domain. Test 25's assertion lives in
        // the parent (it observes the caller's own table); the child
        // has no work to do. Returning lets libz `_start` invoke
        // delete(SLOT_SELF).
        return;
    }

    // ── Parent path ─────────────────────────────────────────────────

    // Step 1 — donor port with `copy` (required by move=0 gating)
    // plus bind+recv so the donor is non-trivial.
    const donor_caps = caps.PortCap{
        .copy = true,
        .recv = true,
        .bind = true,
    };
    const cp = syscall.createPort(@as(u64, donor_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const donor: caps.HandleId = @truncate(cp.v1 & 0xFFF);

    // Step 2 — spawn a sub-domain using the runner-forwarded test ELF
    // as `[4]`. The child takes the silent-return branch above.
    const child_self = caps.SelfCap{
        .crec = true,
        .crvr = true,
        .pri = 3,
    };

    // §[create_capability_domain] [2] ceilings_inner sub-fields:
    //   bits  0-7   ec_inner_ceiling   = 0xFF   (matches runner)
    //   bits  8-23  vmar_inner_ceiling  = 0x01FF (matches runner)
    //   bits 24-31  cridc_ceiling      = CHILD_CRIDC (discriminator)
    //   bits 32-39  pf_ceiling         = 0x1F  (matches runner)
    //   bits 40-47  vm_ceiling         = 0x01  (matches runner)
    //   bits 48-55  port_ceiling       = 0x5C  (matches runner)
    const ceilings_inner: u64 =
        @as(u64, 0xFF) |
        (@as(u64, 0x01FF) << 8) |
        (@as(u64, CHILD_CRIDC) << 24) |
        (@as(u64, 0x1F) << 32) |
        (@as(u64, 0x01) << 40) |
        (@as(u64, 0x5C) << 48);

    const ceilings_outer: u64 = 0x0000_003F_03FE_FFFF;

    const port_caps_word = (caps.PortCap{
        .xfer = true,
        .bind = true,
        .@"suspend" = true,
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
    // The donor entry under test: caps {bind, recv} (subset of donor's
    // current caps, satisfying §[handle_attachments] [test 03]) and
    // move = 0 (donor's `copy` cap is set, satisfying [test 05]).
    const donor_passed_caps_word = (caps.PortCap{
        .bind = true,
        .recv = true,
    }).toU16();
    const passed: [4]u64 = .{
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
        (caps.PassedHandle{
            .id = donor,
            .caps = donor_passed_caps_word,
            .move = false,
        }).toU64(),
    };

    const r = syscall.createCapabilityDomain(
        @as(u64, child_self.toU16()),
        ceilings_inner,
        ceilings_outer,
        SLOT_TEST_ELF_PF,
        0, // initial_ec_affinity = any core
        passed[0..],
    );
    if (testing.isHandleError(r.v1)) {
        testing.fail(2);
        return;
    }

    // Step 3 — probe the donor slot. After a successful call with
    // move = 0, the donor's slot must remain occupied. `restrict`
    // on a vacated slot returns E_BADCAP; any other return value —
    // OK on success, etc. — is evidence the handle is still
    // resident.
    const probe = syscall.restrict(donor, 0);
    if (probe.v1 == @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
