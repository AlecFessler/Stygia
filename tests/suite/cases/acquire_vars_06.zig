// Spec §[acquire_vars] — test 06.
//
// "[test 06] on success, vregs `[1..N]` contain handles in the caller's
//  table referencing those VARs, each with caps = target's
//  `var_outer_ceiling` intersected with the IDC's `var_cap_ceiling`."
//
// Strategy
//   The runner spawns each test as its own capability domain. Slot 2
//   (`SLOT_SELF_IDC`) holds the new domain's self-IDC handle, which by
//   construction targets this very domain. The self-handle at slot 0
//   carries the domain's `var_outer_ceiling` in field1 bits 8-15;
//   the self-IDC at slot 2 carries `var_cap_ceiling` in its field0
//   bits 16-23.
//
//   We mint a `map=1` VAR (regular VAR with caps.r=true plus a single
//   `map_pf` call to install one page) so the target domain has at
//   least one acquire-able VAR (per test 07: only `map=1` and `map=3`
//   VARs are returned). Then we call `acquire_vars(SLOT_SELF_IDC)`.
//
//   The post-condition: every returned handle's caps field equals
//   `var_outer_ceiling ∩ var_cap_ceiling`. We read both values out of
//   the read-only cap table mapping (§[capabilities]) so we don't have
//   to encode a static value the runner is free to change.
//
//   SPEC AMBIGUITY: spec does not pin the initial `var_cap_ceiling` /
//   `ec_cap_ceiling` of the self-IDC minted by `create_capability_domain`
//   (only the cap word is described, via `cridc_ceiling`). We treat
//   whatever the kernel has placed in field0 bits 16-23 as authoritative
//   and compare against it. If the kernel never sets it, the field
//   reads as zero, the intersection is zero, and the check still has
//   bite (every returned handle must have caps = 0).
//
//   SPEC AMBIGUITY: spec says "all ECs in the target domain are paused"
//   while acquire_vars is in flight. For a self-IDC call the calling EC
//   _is_ in the target domain. The kernel's behavior in that corner is
//   not pinned by the spec; for the v0 mock kernel we accept whatever
//   it returns and only verify the post-condition on success.
//
// Action
//   1. create_page_frame(r|w, 1 page)              — must succeed
//   2. create_var(caps={r,w}, props.cur_rwx=r|w,
//      pages=1)                                    — must succeed
//   3. map_pf(var, [{offset=0, pf=pf_handle}])     — transitions
//                                                    var.map 0 -> 1
//   4. acquire_vars(SLOT_SELF_IDC)                 — must succeed
//   5. Decode count from syscall word bits 12-19;
//      iterate vregs 1..count and verify each handle's caps equals
//      `var_outer_ceiling ∩ var_cap_ceiling`.
//
// Assertions
//   1: create_page_frame returned an error word
//   2: create_var returned an error word
//   3: map_pf returned non-success in vreg 1
//   4: acquire_vars returned non-success in vreg 1
//   5: count was 0 — no VARs were returned but at least the one we
//      just minted with map=1 is bound to this domain
//   6: a returned handle id resolves to an empty/wrong-typed slot in
//      the caller's cap table
//   7: a returned handle's caps did not equal the expected intersection
//      var_outer_ceiling ∩ var_cap_ceiling
//
// We bound the count loop to 13 — the number of register-backed vregs
// libz exposes in `Regs`. Per spec the kernel may return up to 127, but
// the v0 path here doesn't reach into stack-spilled vregs.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const MAX_INSPECTED: u8 = 13;

pub fn main(cap_table_base: u64) void {
    // 1. Mint a page frame to back our acquire-able VAR.
    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props.sz = 0 (4 KiB)
        1, // pages
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    // 2. Mint a regular VAR (mmio=0, dma=0). caps.r|w with cur_rwx=r|w
    //    keeps create_var off the E_INVAL paths (cur_rwx must be a
    //    subset of caps r/w/x, sz=0 keeps mmio/dma constraints inert).
    const var_caps = caps.VarCap{ .r = true, .w = true };
    // §[create_var] props: cur_rwx in bits 0-2, sz bits 3-4, cch bits 5-6.
    const var_props: u64 = 0b011; // cur_rwx = r|w; sz=0 (4 KiB); cch=0 (wb)
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        var_props,
        1, // pages
        0, // preferred_base — kernel chooses
        0, // device_region — ignored when caps.dma = 0
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const var_handle: u12 = @truncate(cvar.v1 & 0xFFF);

    // 3. Install the page frame at offset 0 to flip var.map 0 -> 1.
    const map_result = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (map_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Read the var_outer_ceiling out of the self-handle's field1
    // (bits 8-15) and the self-IDC's var_cap_ceiling out of its
    // field0 (bits 16-23). Both fields are part of the static handle
    // layout — no `sync` needed.
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const var_outer_ceiling: u8 = @truncate((self_cap.field1 >> 8) & 0xFF);

    const self_idc_cap = caps.readCap(cap_table_base, caps.SLOT_SELF_IDC);
    const var_cap_ceiling: u8 = @truncate((self_idc_cap.field0 >> 16) & 0xFF);

    const expected_caps: u16 = @as(u16, var_outer_ceiling) & @as(u16, var_cap_ceiling);

    // 4. Acquire VARs through the self-IDC.
    const got = syscall.acquireVars(caps.SLOT_SELF_IDC);
    if (got.regs.v1 != 0 and got.regs.v1 < 16) {
        // vreg 1 carries an error code on failure (the success path
        // writes a handle word there, which has high bits set).
        testing.fail(4);
        return;
    }

    // §[acquire_vars] syscall word bits 12-19: count.
    const count: u8 = @truncate((got.word >> 12) & 0xFF);
    if (count == 0) {
        testing.fail(5);
        return;
    }

    // Iterate the returned handles. Up to MAX_INSPECTED fit in
    // register-backed vregs; beyond that, the v0 libz syscall path
    // doesn't surface them. Treat that as "out of scope for this test".
    const inspect: u8 = if (count < MAX_INSPECTED) count else MAX_INSPECTED;
    const handles = [_]u64{
        got.regs.v1, got.regs.v2, got.regs.v3,  got.regs.v4,
        got.regs.v5, got.regs.v6, got.regs.v7,  got.regs.v8,
        got.regs.v9, got.regs.v10, got.regs.v11, got.regs.v12,
        got.regs.v13,
    };

    var i: u8 = 0;
    while (i < inspect) {
        const handle_id: u12 = @truncate(handles[i] & 0xFFF);
        const cap = caps.readCap(cap_table_base, handle_id);

        // The slot must reference a VAR (handle type 4 per
        // §[capabilities] type tag table); empty slots and
        // wrong-typed slots indicate the kernel didn't actually
        // install the handle.
        if (cap.handleType() != caps.HandleType.virtual_address_range) {
            testing.fail(6);
            return;
        }

        if (cap.caps() != expected_caps) {
            testing.fail(7);
            return;
        }

        i += 1;
    }

    testing.pass();
}
