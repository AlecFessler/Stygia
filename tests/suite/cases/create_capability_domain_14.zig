// Spec §[create_capability_domain] — test 14.
//
// "[test 14] returns E_BADCAP if any passed handle id is not a valid
//  handle in the caller's table."
//
// Strategy
//   Issue a create_capability_domain call where every other check is
//   structured to pass:
//     - self-handle has `crcd` (the runner grants this in primary.zig)
//     - `self_caps` (bits 0-15 of [1]) and `idc_rx` (bits 16-23 of [1])
//       are 0, which is a subset of whatever the caller has (test 02)
//     - all ceiling fields in [2] and [3] are 0, which is a subset of
//       any caller ceiling (tests 03-12), and `restart_policy_ceiling`
//       fields all 0 satisfy the "does not exceed" check (test 07)
//     - `fut_wait_max` (bits 32-37 of [3]) is 0, which does not exceed
//       any caller value (test 08)
//     - reserved bits in [1], [2], [3], and the passed entry are clean
//       (test 17)
//     - `elf_page_frame` ([4]) is a freshly-minted, valid page frame
//       handle (so test 13's E_BADCAP doesn't fire)
//     - exactly one passed handle entry, so test 18 (duplicate source
//       handles) does not apply
//
//   The single passed handle entry uses id = HANDLE_TABLE_MAX - 1 =
//   4095, which is the maximum 12-bit slot. By construction the
//   freshly-spawned domain's table is sparsely populated (slots 0,1,2
//   and slot 3 for the passed result port), so slot 4095 is guaranteed
//   to be empty. The kernel must surface that as E_BADCAP per test 14.
//
//   The ELF/page-frame check (test 13) fires before test 14 in the
//   error-priority structure, so we must mint a real page frame. The
//   page frame contents do NOT need to be a valid ELF: test 15 (ELF
//   header malformed -> E_INVAL) is checked AFTER test 14 — by the
//   time the kernel inspects ELF bytes, the passed-handle BADCAP would
//   have already returned. We allocate one page (smallest allowed) and
//   leave it zeroed.
//
// Action
//   1. create_page_frame(caps={r,w}, props=0, pages=1)
//      -> elf_pf_handle (must succeed)
//   2. create_capability_domain(
//          caps         = 0,                     // self_caps=0, idc_rx=0
//          ceilings_inner = 0,                   // all ceilings 0
//          ceilings_outer = 0,                   // all ceilings 0
//          elf_pf       = elf_pf_handle,
//          passed       = [ { id=4095, caps=0, move=0 } ],
//      )
//      -> must return E_BADCAP in vreg 1.
//
// Assertions
//   1: create_page_frame setup failed.
//   2: create_capability_domain returned something other than E_BADCAP.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Mint a valid page frame so test 13 (E_BADCAP for elf_page_frame)
    // does not fire. r|w is the minimal cap set the caller needs to
    // hold to surface a non-error handle word; the kernel does not
    // require any particular cap on the page frame to read its bytes.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const elf_pf_handle: caps.HandleId = @truncate(cpf.v1 & 0xFFF);

    // Single passed handle entry whose id is the maximum 12-bit slot.
    // The freshly-spawned test domain's handle table only populates
    // slots 0..3 (self, initial EC, self-IDC, result port), so slot
    // HANDLE_TABLE_MAX - 1 = 4095 is empty by construction.
    const invalid_slot: caps.HandleId = @intCast(caps.HANDLE_TABLE_MAX - 1);
    const passed: [1]u64 = .{
        (caps.PassedHandle{
            .id = invalid_slot,
            .caps = 0,
            .move = false,
        }).toU64(),
    };

    const result = syscall.createCapabilityDomain(
        0, // [1] self_caps=0, idc_rx=0, reserved=0
        0, // [2] ceilings_inner: all fields 0
        0, // [3] ceilings_outer: all fields 0 (incl. restart_policy_ceiling, fut_wait_max)
        elf_pf_handle,
        0, // [5] initial_ec_affinity: any-core
        passed[0..],
    );

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
