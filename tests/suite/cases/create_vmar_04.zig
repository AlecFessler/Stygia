// Spec §[create_vmar] create_vmar — test 04.
//
// "[test 04] returns E_PERM if caps.mmio = 1 and the caller's
//  `vmar_inner_ceiling` does not permit mmio."
//
// Strategy
//   The runner mints every spawned test domain with `vmar_inner_ceiling
//   = 0x01FF` (mmio bit set; see runner/primary.zig). A test running
//   as a runner-spawned child therefore cannot construct the E_PERM
//   condition directly — the only ceiling exceedance available to it
//   is widening, not narrowing. Per §[create_capability_domain] [2]
//   the child's `vmar_inner_ceiling` must be a subset of the parent's,
//   so a sub-domain can install a stricter ceiling.
//
//   This test mirrors create_capability_domain_31's parent-spawn +
//   child-probe pattern. The runner-spawned parent re-enters this same
//   ELF as a sub-domain whose `vmar_inner_ceiling` clears the mmio
//   bit. The sub-domain takes the child branch below and calls
//   `create_vmar` with `caps.mmio = 1`. Per §[create_vmar] [test 04]
//   the kernel must return E_PERM.
//
//   Path differentiation: the child path is selected by reading its
//   own self-handle field0, extracting `vmar_inner_ceiling` (bits
//   8-23), and checking the mmio sub-bit (VmarCap bit 5). Parent has
//   it set (0x01FF); child has it cleared (0x01DF). Per §[capabilities]
//   the field0 snapshot is install-at-create for ceilings, so no
//   `sync` is needed before the read.
//
//   Other guards in the child's `create_vmar` call are dodged the
//   same way the other create_vmar tests dodge them (see header in
//   create_vmar_03):
//     - test 01 (no `crvr`): child_self carries `crvr`.
//     - test 02 (caps r/w/x ⊄ ceiling.r/w/x): caps.r,w only.
//     - test 03 (caps.max_sz > ceiling.max_sz): caps.max_sz = 0.
//     - test 05 (pages = 0): pages = 1.
//     - test 06 (preferred_base misaligned): preferred_base = 0.
//     - test 07 (caps.max_sz = 3): caps.max_sz = 0.
//     - test 08 (mmio + props.sz != 0): props.sz = 0 — the spec-
//                  mandated arrangement when mmio = 1.
//     - test 09 (props.sz = 3): props.sz = 0.
//     - test 10 (props.sz > caps.max_sz): props.sz = 0 = caps.max_sz.
//     - test 11 (mmio + caps.x): caps.x = 0.
//     - test 12 (dma + caps.x): caps.dma = 0; caps.x = 0.
//     - test 13 (mmio + dma): caps.dma = 0.
//     - test 14/15 (dma+device_region): caps.dma = 0; [5] = 0.
//     - test 16 (cur_rwx ⊄ caps.r/w/x): cur_rwx = r|w ⊆ caps.r|w.
//     - test 17 (reserved bits): all unused fields zero.
//
// Action
//   parent path:
//     1. createCapabilityDomain(... vmar_inner_ceiling stripped of
//        mmio, [5] = 0 any-core)                                — must succeed
//     2. return — child reports
//   child path:
//     1. createVmar(caps={r,w,mmio}, props={cur_rwx=r|w, sz=0,
//        cch=0}, pages=1, preferred_base=0, device_region=0)   — must
//        return E_PERM
//
// Assertions
//   parent path:
//     1: createCapabilityDomain returned an error word
//   child path:
//     2: createVmar did not return E_PERM  ← THE SPEC ASSERTION

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

// VmarCap bit 5 (mmio) within the 16-bit `vmar_inner_ceiling` (which
// in turn occupies ceilings_inner bits 8-23 per §[capability_domain]).
// The runner ceiling is 0x01FF (every defined VmarCap bit set);
// stripping bit 5 yields 0x01DF, the child's restricted ceiling.
const VMAR_INNER_CEILING_CHILD: u64 = 0x01DF; // 0x01FF & ~(1 << 5)

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const vmar_inner_ceiling: u64 = (self_cap.field0 >> 8) & 0xFFFF;

    // VmarCap bit 5 = mmio. Cleared marks the child (parent-spawned
    // sub-domain whose ceiling stripped mmio); set marks the parent
    // (runner-spawned, ceiling = 0x01FF).
    if ((vmar_inner_ceiling & (1 << 5)) == 0) {
        // ── Child path ──────────────────────────────────────────────
        // §[create_vmar] [test 04]: caps.mmio = 1 against a ceiling
        // that does not permit mmio must return E_PERM. props.sz = 0
        // (the only legal sz when mmio = 1, dodging test 08); caps.x
        // = 0 (dodging test 11); caps.dma = 0 (dodging tests 12/13);
        // pages = 1 (dodging test 05); preferred_base = 0 (kernel
        // chooses, dodging test 06); cur_rwx = r|w ⊆ caps.r|w
        // (dodging test 16).
        const vmar_caps = caps.VmarCap{
            .r = true,
            .w = true,
            .mmio = true,
        };
        // props layout per §[create_vmar] [2]:
        //   bits 0-2: cur_rwx
        //   bits 3-4: sz
        //   bits 5-6: cch
        //   bits 7-63: reserved
        // sz = 0 (4 KiB; spec-mandated when mmio = 1), cch = 0 (wb),
        // cur_rwx = r|w (subset of caps.r|w).
        const props: u64 = 0b011; // cur_rwx = r|w
        const result = syscall.createVmar(
            @as(u64, vmar_caps.toU16()),
            props,
            1, // pages — nonzero (test 05 guard)
            0, // preferred_base — kernel chooses (test 06 guard)
            0, // device_region — caps.dma = 0 so this is ignored
        );

        if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
            testing.fail(2);
            return;
        }

        testing.pass();
        return;
    }

    // ── Parent path ─────────────────────────────────────────────────
    // Spawn a sub-domain that re-enters this same ELF with
    // `vmar_inner_ceiling = 0x01DF` (mmio bit cleared). The sub-
    // domain takes the child branch above and asserts that
    // create_vmar with caps.mmio = 1 returns E_PERM.
    //
    // Mirror runner/primary.zig's child_self caps so the spawned
    // sub-domain has the cap budget needed to walk through libz
    // bootstrap (crvr for createVmar at LIBZ_SLIDE).
    const child_self = caps.SelfCap{
        .crec = true,
        .crvr = true,
        .pri = 3,
    };

    // §[create_capability_domain] [2] ceilings_inner sub-fields:
    //   bits  0-7   ec_inner_ceiling   = 0xFF   (matches runner)
    //   bits  8-23  vmar_inner_ceiling  = 0x01DF (mmio bit 5 cleared)
    //   bits 24-31  cridc_ceiling      = 0x3F   (matches runner)
    //   bits 32-39  pf_ceiling         = 0x1F   (matches runner)
    //   bits 40-47  vm_ceiling         = 0x01   (matches runner)
    //   bits 48-55  port_ceiling       = 0x5C   (matches runner: xfer|recv|bind|suspend)
    const ceilings_inner: u64 =
        @as(u64, 0xFF) |
        (VMAR_INNER_CEILING_CHILD << 8) |
        (@as(u64, 0x3F) << 24) |
        (@as(u64, 0x1F) << 32) |
        (@as(u64, 0x01) << 40) |
        (@as(u64, 0x5C) << 48);

    const ceilings_outer: u64 = 0x0000_003F_03FE_FFFF;

    // Pass through the runner-supplied handles so the sub-domain can
    // bootstrap libz and report on the shared port. The `suspend` cap
    // is required because `testing.report` (and all spec tests under
    // the in-kernel runner) deliver results via a fast-suspend on the
    // shared port — without it the syscall returns E_PERM at the
    // §[suspend] test 04 gate and the runner sees no event.
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
        0, // initial_ec_affinity — any-core (matches runner)
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
    // it the parent CD would stay alive indefinitely and reps of the
    // test runner would exhaust the CD slab class. The child sub-
    // domain is independent (top-level CDs are not parent-linked
    // under v3), so destroying the parent here does not affect the
    // child's ability to report.
    return;
}
