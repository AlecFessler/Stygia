// Spec §[create_capability_domain] create_capability_domain — test 22.
//
// "[test 22] on success, the new domain's handle table contains an IDC
//  handle to itself at slot 2 with caps = the passed `cridc_ceiling`."
//
// Strategy
//   The new domain's slot-2 self-IDC is mapped read-only into the new
//   domain's own address space and is not addressable from the parent.
//   The faithful assertion has to run inside the child. We use the
//   parent-spawn + child-probe pattern (mirrors
//   create_capability_domain_31): the parent spawns a sub-domain with
//   the same test ELF, the parent and the child are distinguished by
//   a discriminator carried in `cridc_ceiling`, the child reads its
//   own SLOT_SELF_IDC cap word, and asserts `caps()` matches the
//   `cridc_ceiling` the parent passed.
//
//   Discriminator: the runner spawns this test with `cridc_ceiling =
//   0x3F` (matches runner/primary.zig). The parent restricts the
//   sub-domain's `cridc_ceiling` to a strict subset (0x07 = move|copy
//   |crec, the 3 lowest IDC cap bits). The child detects "I'm the
//   spawned child" by observing its own self-handle field0
//   `cridc_ceiling` byte != 0x3F. The child then reads slot
//   SLOT_SELF_IDC (= 2) via `caps.readCap(cap_table_base, 2)`, pulls
//   out the cap field via `Cap.caps()` (word0 bits 48-63), and
//   asserts equality with the chosen sub-domain `cridc_ceiling` byte
//   (low 8 bits of the 16-bit cap word; bits 8-15 are reserved per
//   §[capability_domain] IDC handle cap layout).
//
//   Pass-through handles mirror test 31's pattern: result port (so
//   the child can `report` over the shared port), the test ELF pf
//   (forwarded for symmetry — the parent uses it as `[4]`), and the
//   libz pf (mandatory: the child's `_start` mapPfs libz at
//   LIBZ_SLIDE before any test code runs).
//
// Action
//   parent path:
//     1. createCapabilityDomain(... cridc_ceiling=CHILD_CRIDC, ...) — must succeed
//     2. return — child reports
//   child path:
//     1. read SLOT_SELF_IDC slot via caps.readCap                 — observation only
//     2. assert idc.caps() & 0xFF == CHILD_CRIDC                 — the spec assertion
//
// Assertions
//   parent path:
//     1: createCapabilityDomain returned an error word
//   child path:
//     2: SLOT_SELF_IDC caps != CHILD_CRIDC  ← THE SPEC ASSERTION

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

const SLOT_RESULT_PORT: caps.HandleId = caps.SLOT_FIRST_PASSED; // 3
const SLOT_TEST_ELF_PF: caps.HandleId = caps.SLOT_FIRST_PASSED + 1; // 4
// Mirrors libz_loader.LIBZ_PF_SLOT — the runner places the staged libz
// page frame here for every spawned test domain so its _start can
// mapPf libz at LIBZ_SLIDE.
const SLOT_LIBZ_PF: caps.HandleId = caps.SLOT_FIRST_PASSED + 2; // 5

// Sub-domain cridc_ceiling. Strict subset of the runner-installed
// 0x3F so the [test 09] subset check accepts the spawn, distinct
// from 0x3F so the child can discriminate its branch by reading
// the cridc_ceiling byte out of its own self-handle field0.
const CHILD_CRIDC: u8 = 0x07; // move | copy | crec

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    // §[capability_domain] Self handle field0: cridc_ceiling at bits 24-31.
    const my_cridc_ceiling: u8 = @truncate((self_cap.field0 >> 24) & 0xFF);

    if (my_cridc_ceiling != 0x3F) {
        // ── Child path ──────────────────────────────────────────────
        // We're the spawned sub-domain. Read our SLOT_SELF_IDC and
        // assert its cap word matches the cridc_ceiling the parent
        // passed.
        //
        // §[capability_domain] IDC handle cap bits live in word0
        // bits 48-63. IdcCap is defined over bits 0-5 (move/copy/
        // crec/aqec/aqvr/restart_policy); upper bits in the 16-bit
        // cap word are reserved and zero. The kernel mints SLOT_SELF_IDC
        // with caps = `cridc_ceiling`, so the low 8 bits of caps()
        // must equal CHILD_CRIDC (and the high 8 bits must be zero).
        const idc_cap = caps.readCap(cap_table_base, caps.SLOT_SELF_IDC);
        const installed: u16 = idc_cap.caps();
        if (installed != @as(u16, CHILD_CRIDC)) {
            testing.fail(2);
            return;
        }

        testing.pass();
        return;
    }

    // ── Parent path ─────────────────────────────────────────────────
    // Spawn a sub-domain that re-enters this same ELF with
    // cridc_ceiling = CHILD_CRIDC. Mirror runner/primary.zig's
    // child_self caps so the spawned sub-domain has the cap budget
    // needed to walk through libz bootstrap (crvr for createVmar at
    // LIBZ_SLIDE) and to call testing.report (no extra cap required).
    const child_self = caps.SelfCap{
        .crec = true,
        .crvr = true,
        .pri = 3,
    };

    // §[create_capability_domain] [2] ceilings_inner sub-fields:
    //   bits  0-7   ec_inner_ceiling   = 0xFF   (matches runner)
    //   bits  8-23  vmar_inner_ceiling  = 0x01FF (matches runner)
    //   bits 24-31  cridc_ceiling      = CHILD_CRIDC (the bit under test)
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

    // Pass through the runner-supplied handles so the sub-domain can
    // bootstrap libz and report on the shared port. The `suspend` cap
    // is required because `testing.report` delivers results via a
    // fast-suspend on the shared port.
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
        0, // initial_ec_affinity = any core
        passed[0..],
    );
    if (testing.isHandleError(r.v1)) {
        testing.fail(1);
        return;
    }

    // Parent returns. The child is the sole reporter; the runner
    // indexes results by build-time test tag so a single report from
    // the child satisfies this test's slot. Returning lets `_start`
    // invoke `delete(SLOT_SELF)` and tear the parent CD down.
    return;
}
