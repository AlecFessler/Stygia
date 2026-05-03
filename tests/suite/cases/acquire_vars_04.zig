// Spec §[capabilities] acquire_vars — test 04.
//
// "[test 04] returns E_FULL if the caller's handle table cannot
//  accommodate all returned handles."
//
// Strategy
//   The child capability domain's table is populated by the kernel at
//   `create_capability_domain` time:
//     slot 0  → self
//     slot 1  → initial EC
//     slot 2  → self-IDC (from primary.zig: cridc_ceiling = 0x3F,
//               which sets aqvr; this IDC is a valid `acquire_vars`
//               target referencing this child's own domain)
//     slot 3  → result port passed in by the primary
//   To trigger E_FULL we need (a) the target IDC to reference a
//   domain with at least one `map=1` or `map=3` VAR, and (b) the
//   caller's handle table to lack the room for the resulting handle(s).
//
//   We use the self-IDC at slot 2 as the target so the target domain
//   IS this domain. We mint exactly one map=1 VAR by:
//     1. create_page_frame with caps.r|w
//     2. create_var with caps.r|w and props.cur_rwx = r|w (map = 0)
//     3. map_pf installing the page_frame at offset 0 (transitions
//        VAR.field1.map from 0 to 1 per §[map_pf] test 11)
//   That guarantees `acquire_vars` would return at least one handle.
//
//   Then we exhaust the handle table by spinning create_port until it
//   returns E_FULL — the §[create_port] error path for a full table.
//   With zero free slots and at least one map=1 VAR in the target,
//   `acquire_vars` cannot accommodate any returned handle and must
//   surface E_FULL.
//
// Action
//   1. create_page_frame(caps={r,w})           — must succeed
//   2. create_var(caps={r,w}, props.cur_rwx=rw) — must succeed
//   3. map_pf(var, [{offset=0, pf}])           — must succeed
//   4. spin create_port(caps={bind}) until it returns E_FULL — fills
//      the handle table to exhaustion
//   5. acquire_vars(SLOT_SELF_IDC)             — must return E_FULL
//
// Assertions
//   1: setup syscall create_page_frame returned an error
//   2: setup syscall create_var returned an error
//   3: setup syscall map_pf returned an error
//   4: handle table never filled within HANDLE_TABLE_MAX iterations
//      (defensive bound — the kernel must surface E_FULL well before
//      this since slots 0..3 are pre-filled)
//   5: acquire_vars returned something other than E_FULL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: page frame to back the VAR.
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
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    // Step 2: VAR with cur_rwx = r|w. caps.r and caps.w are required
    // for cur_rwx.r|w to satisfy §[create_var] test 16.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        0b011, // props.cur_rwx = r|w, sz = 0, cch = 0
        1, // pages
        0, // preferred_base = kernel chooses
        0, // device_region = none
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const var_handle: u12 = @truncate(cvar.v1 & 0xFFF);

    // Step 3: install the page frame; this transitions VAR.field1.map
    // from 0 to 1, so the VAR is now in the `acquire_vars`-eligible
    // set per §[acquire_vars] test 05.
    const mp = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (mp.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: exhaust the caller's handle table. create_port returns
    // E_FULL once no free slot remains in the caller's table. The
    // bound below is the absolute maximum table size — in practice the
    // loop terminates after roughly HANDLE_TABLE_MAX - 6 iterations
    // (slots 0..3 plus pf and var slots are already occupied).
    const port_caps = caps.PortCap{ .bind = true };
    const port_caps_word: u64 = @as(u64, port_caps.toU16());
    var filled = false;
    var i: u32 = 0;
    while (i < caps.HANDLE_TABLE_MAX) {
        const cp = syscall.createPort(port_caps_word);
        if (cp.v1 == @intFromEnum(errors.Error.E_FULL)) {
            filled = true;
            break;
        }
        i += 1;
    }
    if (!filled) {
        testing.fail(4);
        return;
    }

    // Step 5: with zero free slots and at least one eligible VAR in the
    // target domain (this domain), the kernel cannot mint the returned
    // handle and must surface E_FULL.
    const result = syscall.acquireVars(caps.SLOT_SELF_IDC);
    if (result.regs.v1 != @intFromEnum(errors.Error.E_FULL)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
