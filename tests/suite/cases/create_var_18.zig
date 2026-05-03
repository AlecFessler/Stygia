// Spec §[create_var] — test 18.
//
// "[test 18] on success, the caller receives a VAR handle with caps
// = `[1].caps`."
//
// Strategy
//   Drive create_var down its success path with the same prelude as
//   create_var_05/runner/serial.zig — the root domain's self-handle
//   carries `crvr`, the var_inner_ceiling permits {r, w}, max_sz = 0
//   keeps every max_sz check satisfied, mmio = 0 and dma = 0 close
//   off all device-binding error paths, props.sz = 0 / cur_rwx = 0b011
//   matches caps.{r,w}, preferred_base = 0 lets the kernel pick a
//   valid base, and reserved bits stay clean. That isolates the
//   success-path post-condition this test asserts.
//
//   Use multi-bit caps {r, w} so the assertion exercises a non-trivial
//   bit pattern and is sensitive to either bit being dropped or any
//   stray bit being set on the way through the kernel.
//
//   The caps field of a handle lives in word0 bits 48-63 of the cap
//   table entry — part of the static handle layout, not a kernel-
//   mutable field0/field1 snapshot — so a fresh `readCap` against the
//   read-only-mapped table is authoritative without `sync` (same
//   pattern as restrict_06).
//
// Action
//   1. createVar(caps={r,w}, props={sz=0, cch=0, cur_rwx=0b011},
//                pages=1, preferred_base=0, device_region=0)
//      — must succeed.
//   2. readCap(cap_table_base, returned_handle) — verify caps == {r,w}.
//
// Assertions
//   1: createVar returned an error word in vreg 1 (success path failed).
//   2: returned handle's caps field does not equal the requested caps.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const requested = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0

    const cv = syscall.createVar(
        @as(u64, requested.toU16()),
        props,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cv.v1)) {
        testing.fail(1);
        return;
    }
    const var_handle: u12 = @truncate(cv.v1 & 0xFFF);

    const cap = caps.readCap(cap_table_base, var_handle);
    if (cap.caps() != requested.toU16()) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
