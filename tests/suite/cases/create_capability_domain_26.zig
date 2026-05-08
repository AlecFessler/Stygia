// Spec §[create_capability_domain] create_capability_domain — test 26.
//
// "[test 26] on success, the new domain's `ec_inner_ceiling`,
//  `vmar_inner_ceiling`, `cridc_ceiling`, `idc_rx`, `pf_ceiling`,
//  `vm_ceiling`, and `port_ceiling` in field0 are set to the values
//  supplied in [2] and [1]."
//
// Spec §[capability_domain] Self handle field0 layout:
//   bits  0-7   ec_inner_ceiling   <- from [2] ceilings_inner bits  0-7
//   bits  8-23  vmar_inner_ceiling  <- from [2] ceilings_inner bits  8-23
//   bits 24-31  cridc_ceiling      <- from [2] ceilings_inner bits 24-31
//   bits 32-39  idc_rx             <- from [1] caps           bits 16-23
//   bits 40-47  pf_ceiling         <- from [2] ceilings_inner bits 32-39
//   bits 48-55  vm_ceiling         <- from [2] ceilings_inner bits 40-47
//   bits 56-63  port_ceiling       <- from [2] ceilings_inner bits 48-55
//
// Strategy
//   The new domain's slot-0 self-handle is mapped read-only into the
//   new domain's own address space; the parent cannot reach across the
//   boundary to read it. We use the parent-spawn + child-probe pattern
//   (mirrors create_capability_domain_31): the parent spawns a
//   sub-domain with a chosen set of ceiling sub-fields and idc_rx
//   byte, and the child reads its own slot-0 self-handle field0 and
//   asserts every sub-field landed at the expected bit position.
//
//   Discriminator: the parent observes its own self-handle's
//   `port_ceiling` byte (field0 bits 56-63 = 0x5C, runner-installed
//   value); the spawned sub-domain is created with port_ceiling =
//   CHILD_PORT_CLG (0x14, a strict subset). The child detects "I'm
//   the spawned sub-domain" by observing port_ceiling != 0x5C in its
//   own field0.
//
//   Cross-domain `acquire_*` is not implemented in v3 for foreign
//   IDC handles, so the assertion has to live inside the child.
//   `caps.readCap(cap_table_base, SLOT_SELF)` directly reads the
//   read-only-mapped table at the kernel-supplied base; spec
//   §[capabilities] guarantees this is the kernel-authoritative
//   field at create-time (no `sync` is needed for this slot — only
//   slots backed by mutable kernel state need a sync, and the
//   self-handle's ceilings are immutable for the lifetime of the
//   domain).
//
// Action
//   parent path:
//     1. createCapabilityDomain(... ceilings_inner=CHILD_INNER,
//        idc_rx=CHILD_IDC_RX, ...)                          — must succeed
//     2. return — child reports
//   child path:
//     1. read SLOT_SELF cap                                  — observation only
//     2. assert each sub-field of field0 matches the value
//        the parent passed
//
// Assertions
//   parent path:
//     1: createCapabilityDomain returned an error word
//   child path:
//     2: ec_inner_ceiling sub-field mismatch
//     3: vmar_inner_ceiling sub-field mismatch
//     4: cridc_ceiling sub-field mismatch
//     5: idc_rx sub-field mismatch
//     6: pf_ceiling sub-field mismatch
//     7: vm_ceiling sub-field mismatch
//     8: port_ceiling sub-field mismatch  ← any of 2..8 fail = THE SPEC ASSERTION

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

const SLOT_RESULT_PORT: caps.HandleId = caps.SLOT_FIRST_PASSED; // 3
const SLOT_TEST_ELF_PF: caps.HandleId = caps.SLOT_FIRST_PASSED + 1; // 4
const SLOT_LIBZ_PF: caps.HandleId = caps.SLOT_FIRST_PASSED + 2; // 5

// Sub-domain ceiling sub-fields. Each is a strict subset of the
// runner-installed value so the [test 03/05/09/10/11/12] subset
// checks accept the spawn, and each carries a distinct non-trivial
// pattern so a kernel that mis-laid-out field0 would visibly fail
// against at least one assertion.
//
// CHILD_EC_INNER must include `susp` (bit 5), `read` (bit 6), and
// `write` (bit 7): the runner's testing.report path suspends the
// child's SLOT_INITIAL_EC on the result port, which §[suspend]
// gates on `susp` on the target EC handle, and the kernel's L4
// fast-suspend predicate additionally requires read+write set so
// recv-time §[event_state] vregs 1..13 carry the assertion id /
// result code back to the runner. The child mints SLOT_INITIAL_EC
// with caps = ec_inner_ceiling per spec §[create_capability_domain]
// [test 21] — without these bits the child silently returns from
// `testing.report` with E_PERM and the runner times out (MISS).
const CHILD_EC_INNER: u8 = 0xE5; // bits 0/2/5/6/7 of EC inner caps (susp+read+write set)
const CHILD_VMAR_INNER: u16 = 0x00AA; // strict subset of runner 0x01FF
const CHILD_CRIDC: u8 = 0x15; // strict subset of runner 0x3F (move|crec|aqvr)
const CHILD_IDC_RX: u8 = 0xA3; // arbitrary 8-bit mask (no ceiling subset to satisfy)
const CHILD_PF_CLG: u8 = 0x0F; // strict subset of runner 0x1F (max_rwx all + max_sz=01)
const CHILD_VM_CLG: u8 = 0x01; // matches runner 0x01 (only valid bit is bit 0 = policy)
const CHILD_PORT_CLG: u8 = 0x14; // strict subset of runner 0x5C (recv | bind), discriminator

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    // §[capability_domain] Self handle field0: port_ceiling at bits 56-63.
    const my_port_ceiling: u8 = @truncate((self_cap.field0 >> 56) & 0xFF);

    if (my_port_ceiling != 0x5C) {
        // ── Child path ──────────────────────────────────────────────
        // We're the spawned sub-domain. Read our self-handle and
        // verify each field0 sub-field landed at the expected bit
        // position with the expected value.
        const f0 = self_cap.field0;
        const got_ec_inner: u8 = @truncate(f0 & 0xFF);
        const got_vmar_inner: u16 = @truncate((f0 >> 8) & 0xFFFF);
        const got_cridc: u8 = @truncate((f0 >> 24) & 0xFF);
        const got_idc_rx: u8 = @truncate((f0 >> 32) & 0xFF);
        const got_pf_clg: u8 = @truncate((f0 >> 40) & 0xFF);
        const got_vm_clg: u8 = @truncate((f0 >> 48) & 0xFF);
        const got_port_clg: u8 = @truncate((f0 >> 56) & 0xFF);

        if (got_ec_inner != CHILD_EC_INNER) {
            testing.fail(2);
            return;
        }
        if (got_vmar_inner != CHILD_VMAR_INNER) {
            testing.fail(3);
            return;
        }
        if (got_cridc != CHILD_CRIDC) {
            testing.fail(4);
            return;
        }
        if (got_idc_rx != CHILD_IDC_RX) {
            testing.fail(5);
            return;
        }
        if (got_pf_clg != CHILD_PF_CLG) {
            testing.fail(6);
            return;
        }
        if (got_vm_clg != CHILD_VM_CLG) {
            testing.fail(7);
            return;
        }
        if (got_port_clg != CHILD_PORT_CLG) {
            testing.fail(8);
            return;
        }

        testing.pass();
        return;
    }

    // ── Parent path ─────────────────────────────────────────────────
    // Spawn a sub-domain with the chosen ceiling/idc_rx mix. Self caps
    // must include `crec`/`crvr` so libz bootstrap and downstream
    // syscalls work. The runner-installed self caps are wider than
    // CHILD_EC_INNER and friends; what matters here is that the
    // ceilings_inner [2] sub-fields each fit inside the runner's
    // installed ceilings.
    const child_self = caps.SelfCap{
        .crec = true,
        .crvr = true,
        .pri = 3,
    };

    // [1] caps word = self_caps (low 16 bits) | idc_rx (bits 16-23).
    const caps_word: u64 =
        @as(u64, child_self.toU16()) |
        (@as(u64, CHILD_IDC_RX) << 16);

    // §[create_capability_domain] [2] ceilings_inner — packed per
    // syscall ABI (NB: pf/vm/port_ceiling shift to field0 bits 40-63
    // in the new domain to make room for idc_rx at field0 bits 32-39):
    //   bits  0-7   ec_inner_ceiling   = CHILD_EC_INNER
    //   bits  8-23  vmar_inner_ceiling  = CHILD_VMAR_INNER
    //   bits 24-31  cridc_ceiling      = CHILD_CRIDC
    //   bits 32-39  pf_ceiling         = CHILD_PF_CLG
    //   bits 40-47  vm_ceiling         = CHILD_VM_CLG
    //   bits 48-55  port_ceiling       = CHILD_PORT_CLG
    const ceilings_inner: u64 =
        @as(u64, CHILD_EC_INNER) |
        (@as(u64, CHILD_VMAR_INNER) << 8) |
        (@as(u64, CHILD_CRIDC) << 24) |
        (@as(u64, CHILD_PF_CLG) << 32) |
        (@as(u64, CHILD_VM_CLG) << 40) |
        (@as(u64, CHILD_PORT_CLG) << 48);

    // [3] ceilings_outer — match the runner-installed values so no
    // outer subset check fires.
    const ceilings_outer: u64 = 0x0000_003F_03FE_FFFF;

    // Pass through the runner-supplied handles so the sub-domain can
    // bootstrap libz and report on the shared port.
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
        caps_word,
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

    // Parent returns. The child is the sole reporter.
    return;
}
