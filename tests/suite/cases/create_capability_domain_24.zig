// Spec §[create_capability_domain] create_capability_domain — test 24.
//
// "[test 24] a passed handle entry with `move = 1` is removed from the
//  caller's handle table after the call."
//
// Strategy
//   The post-condition only fires on a *successful* call. The pre-v3
//   shape of this test built a tiny inline ELF that lacked PT_DYNAMIC,
//   which §[create_capability_domain] [test 16a] correctly rejects
//   with E_INVAL — the call never succeeded and the move=1 invariant
//   was never exercised. A working full ELF is already in our hand:
//   the runner forwards this test's own ELF page frame at
//   SLOT_TEST_ELF_PF (= 4) for exactly the parent-spawn-child pattern
//   used by tests like create_capability_domain_31. We reuse it as
//   `[4]` here, so the call lands on the success path, and the
//   move=1 post-condition becomes assertable cleanly.
//
//   Donor: a fresh port handle minted by `create_port` with
//   `{move, copy, xfer, recv, bind, suspend}`. We pass it with
//   `caps = {xfer, bind}` and `move = 1` so the entry sits cleanly
//   inside the move=1 sweet spot of §[handle_attachments] [test 04].
//
//   Probe: spec §[capabilities] `restrict` test 03 establishes that
//   restricting on a vacated slot returns E_BADCAP. With `new_caps =
//   0` the call is unambiguous: any prior caps subset the request,
//   reserved bits are clean, so the only reject path that fires on
//   a released slot is E_BADCAP.
//
//   Child path: the spawned sub-domain re-enters this same ELF. We
//   discriminate parent vs. child by reading the caller's own
//   self-handle field0 `cridc_ceiling` (bits 24-31). The runner
//   installs 0x3F; the parent path passes a strict-subset 0x07 to
//   the sub-domain so the child branch can detect itself and silently
//   return — the runner's libz `_start` then issues
//   delete(SLOT_SELF) and the child CD tears down. No report from
//   the child; the parent is the sole reporter.
//
// Action
//   parent path:
//     1. create_port(...) — donor with full caps                  — must succeed
//     2. createCapabilityDomain(... [4] = SLOT_TEST_ELF_PF,
//        passed = [donor, caps={xfer,bind}, move=1])              — must succeed
//     3. restrict(donor, 0)                                        — must return E_BADCAP
//   child path:
//     - silent return; libz `_start` reaps the CD via delete(SLOT_SELF)
//
// Assertions
//   1: create_port returned an error word
//   2: createCapabilityDomain returned an error word in vreg 1
//   3: post-call restrict on the donor port did not return E_BADCAP
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
        // We're the spawned sub-domain. Test 24's assertion lives in
        // the parent (it observes the caller's own table); the child
        // has no work to do. Returning lets libz `_start` invoke
        // delete(SLOT_SELF) so the CD slab slot returns to the
        // freelist.
        return;
    }

    // ── Parent path ─────────────────────────────────────────────────

    // Step 1 — donor port. Full caps so the move=1 transfer with
    // requested caps {xfer, bind} sits cleanly inside test 24's
    // sweet spot.
    const donor_caps = caps.PortCap{
        .move = true,
        .copy = true,
        .xfer = true,
        .recv = true,
        .bind = true,
        .@"suspend" = true,
    };
    const cp = syscall.createPort(@as(u64, donor_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const donor: caps.HandleId = @truncate(cp.v1 & 0xFFF);

    // Step 2 — spawn a sub-domain using the runner-forwarded test ELF
    // as `[4]`. Mirror runner/primary.zig's child_self caps so libz
    // bootstrap (crvr) succeeds; the child takes the silent-return
    // branch above.
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

    // Standard pass-through: result port (so the child *could* report,
    // even though it doesn't), the test ELF pf (forwarded for symmetry),
    // the libz pf (mandatory for child `_start` libz bootstrap), and
    // the donor port we are exercising the move=1 transfer on.
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
    // The donor entry under test: caps {xfer, bind} (subset of donor's
    // current caps, satisfying §[handle_attachments] [test 03]) and
    // move = 1 (donor's `move` cap is set, satisfying [test 04]).
    const donor_passed_caps_word = (caps.PortCap{
        .xfer = true,
        .bind = true,
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
            .move = true,
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
    // move = 1, the donor's slot must be released; restrict on a
    // released slot returns E_BADCAP (cf. §[capabilities] restrict
    // test 03). `new_caps = 0` is a subset of any prior caps, so no
    // E_PERM, and reserved bits are clean, so no E_INVAL — the only
    // remaining reject is E_BADCAP.
    const probe = syscall.restrict(donor, 0);
    if (probe.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
