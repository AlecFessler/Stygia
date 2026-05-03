// Spec §[handle_attachments] — test 01.
//
// "[test 01] returns E_PERM if `N > 0` and the port handle does not
//  have the `xfer` cap."
//
// Strategy
//   §[handle_attachments] places `pair_count` `N` in the suspend
//   syscall word's bits 12-19. Per the spec line under test, when
//   `N > 0` the kernel must verify the `[2]` port handle carries the
//   `xfer` cap before delivering the suspension event; absent that
//   cap the call must surface E_PERM.
//
//   To isolate the xfer check we make every other prelude check pass
//   on its own terms:
//     - §[suspend] test 01 (E_BADCAP on bad EC) — use SLOT_INITIAL_EC,
//       a valid EC handle the runner installed at spawn time.
//     - §[suspend] test 02 (E_BADCAP on bad port) — mint a fresh port
//       below and use its handle.
//     - §[suspend] test 03 (E_PERM, no `susp` on EC) — slot 1's EC
//       handle was minted with `ec_inner_ceiling = 0xFF`, which
//       covers `susp` (bit 5).
//     - §[suspend] test 04 (E_PERM, no `bind` on port) — mint the
//       port with `bind` set so this prior gate is satisfied.
//     - §[suspend] test 05 (E_INVAL on reserved bits) — set only the
//       handle id bits in [1] and [2] and only `pair_count` in the
//       extra-bits range of the syscall word; everything else zero.
//     - §[suspend] test 06 (E_INVAL on vCPU target) — slot 1 is a
//       plain EC, not a vCPU.
//     - §[suspend] test 07 (E_INVAL on already-suspended) — slot 1 is
//       the calling EC, currently running, so it is not suspended.
//
//   The mint uses `caps = bind` only — no `xfer`. The runner's
//   `port_ceiling = 0x1C` covers bind/recv/xfer (bit positions 4/3/2
//   on the field-internal layout in §[capability_domain]), so a
//   bind-only mint is strictly within the ceiling and trivially
//   passes §[create_port] tests 02-03. The runner grants the test's
//   self-handle the `crpt` cap (§[create_port] test 01).
//
//   With the bind-only port in hand we issue the suspend syscall
//   directly via `issueReg`, building the syscall word ourselves so
//   the pair_count field (bits 12-19 per §[handle_attachments]) is
//   non-zero. We choose `N = 1` — the smallest value that satisfies
//   `N > 0` and avoids any ambiguity about a zero-conditional check.
//
//   SPEC AMBIGUITY: §[handle_attachments] places the actual pair
//   entry at vreg 127 (high vreg band [128 - N .. 127]). The libz
//   syscall path can address up to vreg 29 today (issueStack pad is
//   16 quadwords starting at vreg 14); vreg 127 is unreachable from
//   userspace via the current wrapper. This test does not populate
//   the pair entry — it only sets pair_count in the syscall word —
//   and relies on §[handle_attachments]'s test ordering: the xfer
//   check (test 01) is gated on `N > 0` alone, prior to any entry
//   validation (tests 02-07 inspect entry contents). Per that
//   ordering, the kernel must observe `N = 1`, find no `xfer` cap
//   on [2], and return E_PERM without ever reading vreg 127.
//
// Action
//   1. create_port(caps = {bind})       — must succeed
//   2. issueReg(.suspend, extra = pair_count(1) << 12, [1] = SLOT_INITIAL_EC,
//      [2] = port_handle)               — must return E_PERM
//
// Assertions
//   1: setup port creation failed (createPort returned an error word)
//   2: suspend with N = 1 on a bind-only (no xfer) port returned
//      something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint a port with `bind` only (no `xfer`). bind is
    // required to satisfy §[suspend] test 04; xfer is intentionally
    // absent so §[handle_attachments] test 01 is the live failure
    // mode when pair_count > 0.
    const port_caps = caps.PortCap{ .bind = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: issue suspend with pair_count = 1 in the syscall word.
    // §[syscall_abi] / §[handle_attachments]: pair_count occupies bits
    // 12-19 of the syscall word. `extraCount` packs a u8 into that
    // range; `issueReg` ORs syscall_num into bits 0-11 and dispatches.
    //
    // [1] = SLOT_INITIAL_EC — a valid EC handle to the calling EC
    //   with caps = ec_inner_ceiling = 0xFF (susp/read/write all set).
    // [2] = port_handle — the bind-only port minted above.
    const extra = syscall.extraCount(1);
    const r = syscall.issueReg(.@"suspend", extra, .{
        .v1 = caps.SLOT_INITIAL_EC,
        .v2 = port_handle,
    });
    if (r.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
