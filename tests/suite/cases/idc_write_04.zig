// Spec §[idc_write] — test 04.
//
// "[test 04] returns E_INVAL if count is 0 or count > 125."
//
// Strategy
//   The §[idc_write] gate order mirrors §[idc_read]:
//     test 01 — [1] BADCAP
//     test 02 — [1].caps lacks `w`
//     test 03 — [2] offset not 8-byte aligned
//     test 04 — count == 0 or count > 125
//   To isolate test 04's E_INVAL we need [1] to be a valid VAR handle
//   with the `w` cap, [2] to be 8-byte aligned (we use 0), and count
//   set to one of the two boundary values that violate the spec range
//   `1 <= count <= 125`.
//
//   Per §[create_var] / §[map_pf] the simplest setup that yields a
//   writable VAR is:
//     - createPageFrame(caps={r,w,move}, props.sz=0, pages=1)
//     - createVar(caps={r,w}, props.cur_rwx=r|w, pages=1)
//     - mapPf(var, [{offset=0, pf=pf_handle}])
//   This flips var.map 0 -> 1 so [2] + count*8 lies inside the VAR
//   for test 05 — but here we only need a valid `w`-capable VAR to
//   reach the count gate. We wire the page frame in for parity with
//   peers in this section (idc_read_04).
//
//   The libz `syscall.idcWrite` wrapper accepts a `qwords: []const u64`
//   slice and derives `count = qwords.len`. For count == 0 we pass an
//   empty slice. For count == 126 we cannot drive the wrapper directly —
//   it would attempt to spill 115 qwords through `issueStack`, whose
//   bounded 16-slot pad would panic at runtime. Instead we bypass the
//   wrapper via `syscall.issueReg` with `extraCount(126)` so the count
//   reaches the kernel verbatim. The count == 126 gate fires before any
//   qword is read, so omitting the per-vreg qword payload is sound.
//
// Action
//   1. createPageFrame(caps={r,w,move}, props.sz=0, pages=1)  — must succeed
//   2. createVar(caps={r,w}, props.cur_rwx=r|w, pages=1)      — must succeed
//   3. mapPf(var, [{offset=0, pf=pf_handle}])                 — must succeed
//   4. idcWrite(var, 0, &.{})  — count == 0,  must return E_INVAL  (id 1)
//   5. issueReg(.idc_write, count=126, .{v1=var, v2=0})
//                              — count > 125, must return E_INVAL  (id 2)
//
// Assertions
//   1: count == 0 path did not return E_INVAL.
//   2: count == 126 path did not return E_INVAL.
//
//   Prelude failures (createPageFrame / createVar / mapPf) report
//   distinct fail ids (3, 4, 5) so a broken prelude is debuggable
//   without conflating with the spec assertions under test.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // 1. Mint a page frame to back the VAR.
    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props.sz = 0 (4 KiB)
        1, // pages
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(3);
        return;
    }
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    // 2. Mint a regular VAR with caps {r, w} and cur_rwx = r|w.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0 (wb)

    const cv = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base — kernel chooses
        0, // device_region — ignored when caps.dma = 0
    );
    if (testing.isHandleError(cv.v1)) {
        testing.fail(4);
        return;
    }
    const var_handle: u12 = @truncate(cv.v1 & 0xFFF);

    // 3. Install the page frame at offset 0 to flip var.map 0 -> 1.
    const map_result = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (map_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    // 4. count == 0 must return E_INVAL.
    const r_zero = syscall.idcWrite(var_handle, 0, &.{});
    if (r_zero.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    // 5. count == 126 (> 125) must return E_INVAL. Bypass the libz
    // wrapper since it would attempt to spill 115 qwords through
    // issueStack and panic against the bounded 16-slot pad. The
    // kernel's count gate fires before any qword vreg is touched.
    const r_over = syscall.issueReg(.idc_write, syscall.extraCount(126), .{
        .v1 = @as(u64, var_handle),
        .v2 = 0,
    });
    if (r_over.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
