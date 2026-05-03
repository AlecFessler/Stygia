// Spec §[acquire_ecs] — test 06.
//
// "[test 06] on success, vregs `[1..N]` contain handles in the caller's
//  table referencing those ECs, each with caps = target's
//  `ec_outer_ceiling` intersected with the IDC's `ec_cap_ceiling`."
//
// Strategy
//   The runner spawns each test as a fresh capability domain. By the
//   §[capability_domain] / §[create_capability_domain] layout the
//   child's handle table is populated as:
//     slot 0  → self (capability_domain_self)
//     slot 1  → initial EC (this test's running EC)
//     slot 2  → self-IDC (an IDC handle to this same domain)
//     slot 3  → result port
//   Slot 2 is therefore an IDC handle whose target is the calling
//   domain. Calling `acquire_ecs(SLOT_SELF_IDC)` asks the kernel for
//   handles to every non-vCPU EC in this domain — at minimum the
//   initial EC at slot 1 (test 07 isolates the vCPU exclusion; here
//   we make no claim about exact N, only the per-handle caps
//   post-condition).
//
//   The runner sets the test domain's `ec_outer_ceiling = 0xFF` (low
//   8 bits of ceilings_outer; see runner/primary.zig). The slot-2
//   self-IDC carries a per-IDC `ec_cap_ceiling` set by the kernel at
//   `create_capability_domain` time per §[idc_handle] field0 bits
//   0-15. Both fields live in the read-only-mapped cap table, so the
//   test computes the spec-mandated intersection at read time rather
//   than relying on a hard-coded value.
//
//   Per §[acquire_ecs] success contract:
//     - The syscall word's count field (bits 12-19) holds N.
//     - Vregs `[1..N]` each hold a handle id in the caller's table.
//     - Each returned handle has caps =
//         target.ec_outer_ceiling ∩ IDC.ec_cap_ceiling.
//
// Action
//   1. acquire_ecs(SLOT_SELF_IDC)          — must succeed
//   2. Read N from the returned syscall word's count field; the
//      first returned handle id is in vreg 1 (also where errors land
//      on failure — disambiguated via testing.isHandleError, since
//      §[error_codes] confines error values to 1..15).
//   3. For each returned handle in vregs [1..N], read its cap-table
//      entry and verify caps equals the expected intersection.
//
// Assertions
//   1: acquire_ecs returned an error code in vreg 1 (1..15)
//   2: count returned in the syscall word is 0 — contradicts the
//      always-present initial EC of the test domain
//   3: a returned handle's caps field did not equal the expected
//      intersection

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

// §[idc_handle] field0 bits 0-15 carry the per-IDC ec_cap_ceiling.
fn idcEcCapCeiling(c: caps.Cap) u16 {
    return @truncate(c.field0 & 0xFFFF);
}

// §[capability_domain] self-handle field1 bits 0-7 carry
// ec_outer_ceiling. ec_outer_ceiling is an 8-bit field that
// zero-extends to a 16-bit caps mask when intersected with the IDC's
// 16-bit ec_cap_ceiling.
fn selfEcOuterCeiling(c: caps.Cap) u16 {
    return @as(u16, @truncate(c.field1 & 0xFF));
}

pub fn main(cap_table_base: u64) void {
    const result = syscall.acquireEcs(caps.SLOT_SELF_IDC);

    // §[error_codes]: error codes occupy 1..15. A handle word's caps
    // field (bits 48-63) is non-zero on any minted EC handle, so any
    // value in 1..15 in vreg 1 is unambiguously an error.
    if (testing.isHandleError(result.regs.v1)) {
        testing.fail(1);
        return;
    }

    // §[acquire_ecs] places count in the syscall word's bits 12-19.
    const count: u8 = @truncate((result.word >> 12) & 0xFF);
    if (count == 0) {
        testing.fail(2);
        return;
    }

    // Compute the expected caps from the authoritative cap-table
    // entries that defined the intersection at acquire time.
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const idc_cap = caps.readCap(cap_table_base, caps.SLOT_SELF_IDC);
    const expected: u16 = selfEcOuterCeiling(self_cap) & idcEcCapCeiling(idc_cap);

    // Vregs [1..N] carry the returned handle ids. Up to 13 are
    // register-backed; runner v0 spawns one EC per test domain so
    // N is expected to be 1. Bound the loop at the register-backed
    // count; if a future runner enlarges the test domain to N > 13
    // this test grows a stack-spilled read path.
    const reg_slots: [13]u64 = .{
        result.regs.v1,
        result.regs.v2,
        result.regs.v3,
        result.regs.v4,
        result.regs.v5,
        result.regs.v6,
        result.regs.v7,
        result.regs.v8,
        result.regs.v9,
        result.regs.v10,
        result.regs.v11,
        result.regs.v12,
        result.regs.v13,
    };

    var idx: u8 = 0;
    while (idx < count and idx < reg_slots.len) {
        const handle_id: u12 = @truncate(reg_slots[idx] & 0xFFF);
        const got = caps.readCap(cap_table_base, handle_id);
        if (got.caps() != expected) {
            testing.fail(3);
            return;
        }
        idx += 1;
    }

    testing.pass();
}
