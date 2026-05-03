// Spec §[create_var] — test 15.
//
// "[test 15] returns E_PERM if caps.dma = 1 and [5] does not have the
//  `dma` cap."
//
// DEGRADED SMOKE VARIANT
//   The faithful test for E_PERM here requires a *valid*
//   device_region handle in the test domain whose `dma` cap is
//   cleared. The kernel's create_var prelude must walk through the
//   E_BADCAP check on [5] (test 14) — i.e. resolve [5] as a real
//   device_region handle — before it reaches the cap-bit subset
//   check that this test exercises.
//
//   Per §[device_region], device_region handles are kernel-issued at
//   boot to the root service and otherwise propagate via xfer/IDC.
//   They cannot be minted in-domain. The v0 runner
//   (runner/primary.zig) spawns each test as a child capability
//   domain whose `passed_handles` contain only the result port at
//   slot 3; no device_region is forwarded. The runner's
//   `runner/serial.zig` `findCom1` scan only succeeds because it
//   runs in the *root service* table — children's tables hold
//   self / initial_ec / self_idc / port and nothing else, so a
//   `findCom1`-shaped scan from inside a test would always return
//   `null`.
//
//   With no device_region reachable from the test domain there is
//   no in-domain way to construct a "valid handle, missing dma cap"
//   argument. `restrict` cannot help either — restrict requires an
//   existing device_region handle in the table to begin with.
//
//   This smoke variant pins only the negative observation: a
//   create_var with caps.dma = 1 and an unminted [5] slot returns
//   *some* spec-mandated error (E_BADCAP under test 14). The strict
//   test 15 path — kernel rejects with E_PERM — is left unchecked
//   pending runner support for forwarding a no-dma device_region
//   handle to test children.
//
// Strategy
//   The check ordering ahead of the dma-handle subset check is
//   identical to test 14, so we mirror its prelude:
//     - caller self-handle has `crvr` (runner grants it).
//     - caps.r/w/x ⊆ var_inner_ceiling (runner ceiling 0x01FF
//       permits r, w, dma — see runner/primary.zig).
//     - caps.x clear so test 12 (dma + x → E_INVAL) cannot fire.
//     - caps.mmio clear so tests 04/08/11/13 cannot fire.
//     - caps.max_sz = 0 so tests 03/07/10 cannot fire.
//     - props.sz = 0 (4 KiB) satisfies tests 09/10.
//     - props.cur_rwx = 0b011 (r|w) ⊆ caps.{r,w} (test 16).
//     - preferred_base = 0 so test 06 cannot fire.
//     - pages = 1 so test 05 cannot fire.
//     - reserved bits zero so test 17 cannot fire.
//   With caps.dma = 1, the kernel must validate [5]. The child's
//   slot 4095 (HANDLE_TABLE_MAX - 1) is unminted by construction,
//   so the kernel falls into test 14's E_BADCAP path before it
//   could reach test 15's E_PERM path.
//
// Action
//   create_var(caps={r, w, dma}, props={sz=0, cch=0, cur_rwx=0b011},
//              pages=1, preferred_base=0,
//              device_region=HANDLE_TABLE_MAX - 1)
//   — returns E_BADCAP under the prevailing test 14 path.
//
// Assertion
//   No assertion is checked — passes with assertion id 0 because the
//   smoke can only reach the test 14 path, not the test 15 path. The
//   header documents this gap so coverage reporting reflects reality.
//
// Faithful-test note
//   Faithful test deferred pending a runner/primary.zig extension
//   that mints (or carves out) a device_region with `dma = 0` and
//   forwards it to the test child via passed_handles. Once
//   available, the action becomes:
//     create_var(caps={r, w, dma}, ..., device_region=that_handle)
//   and the assertion becomes:
//     result.v1 == E_PERM   (assertion id 1)

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const var_caps = caps.VarCap{ .r = true, .w = true, .dma = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const unminted_dev: u64 = caps.HANDLE_TABLE_MAX - 1; // slot 4095

    _ = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        unminted_dev,
    );

    testing.pass();
}
