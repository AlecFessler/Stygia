// Spec §[capability_domain] create_capability_domain — test 18.
//
// "[test 18] returns E_INVAL if any two entries in [4+] reference the
// same source handle."
//
// (The [4+] in the test text refers to the passed_handles slice,
// which the syscall argument list lays out at [5+]; the test condition
// is "two passed-handle entries name the same source handle id".)
//
// Strategy
//   The duplicate-source check must fire when two entries in the
//   passed_handles slice carry the same `id` field, regardless of
//   whether each entry's `move`/`caps` differ. To isolate that check
//   from the other E_PERM / E_BADCAP / E_INVAL paths, every other
//   argument must be valid:
//
//     [1] self_caps      — strict subset of caller's self-handle
//                          (caller is a runner-spawned child whose
//                          self-handle was minted with the wide
//                          ceiling set in primary.zig). Reserved
//                          bits clean (test 17).
//     [2] ceilings_inner — all-zero (subset of any non-zero
//                          ceiling) with reserved bits clean.
//     [3] ceilings_outer — all-zero with reserved bits clean.
//     [4] elf_page_frame — a freshly created page frame handle
//                          (so test 13 / E_BADCAP cannot fire). The
//                          spec does not pin a fixed ordering for
//                          test 15 (malformed ELF) vs test 18, but
//                          test 18 names a structural error in the
//                          arg list itself, which the kernel can
//                          surface before parsing the ELF bytes.
//                          The kernel implementation is expected to
//                          validate the passed-handle entries
//                          (reserved bits, duplicate ids) before
//                          touching the page frame's contents.
//     [5+] passed_handles — two entries naming the SAME source
//                          handle id. The first names the result
//                          port at SLOT_FIRST_PASSED with `move=0,
//                          caps={bind}`; the second names the same
//                          slot with `move=0, caps={xfer}`. Both
//                          source caps are subsets of the result
//                          port's caps as minted by primary.zig
//                          ({move, copy, xfer, recv, bind}), so the
//                          per-entry subset check (test 17 / handle
//                          attachments parity) passes. Reserved bits
//                          are clean. Both entries are `move=0` so
//                          the source's `copy` cap (held) gates
//                          them, not `move`. The only spec violation
//                          that remains is the duplicate `id` field.
//
// Action
//   1. create_page_frame(caps={r}, props.sz=0, pages=1) → pf_handle
//   2. create_capability_domain(self_caps=0,
//                               ceilings_inner=0,
//                               ceilings_outer=0,
//                               pf_handle,
//                               passed=[entryA, entryB])
//      where entryA.id == entryB.id == SLOT_FIRST_PASSED.
//   3. Expect vreg 1 == E_INVAL.
//
// Assertions
//   1: setup syscall failed (create_page_frame returned an error
//      word in vreg 1).
//   2: create_capability_domain did not return E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: stage a valid page frame so [4] / test 13 cannot fire.
    // Minimal sized: 1 page at sz=0 (4 KiB). Caps {r} is enough — the
    // kernel only needs to recognize the handle as a page frame for
    // the BADCAP check; a real test 18 implementation must succeed
    // even if the ELF is malformed because the duplicate-source check
    // is structural in the arg list.
    const pf_caps = caps.PfCap{ .r = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: caps.HandleId = @truncate(cpf.v1 & 0xFFF);

    // Step 2: build two passed-handle entries that both name
    // SLOT_FIRST_PASSED (the result port). Different cap sets and same
    // move flag — the only collision is on `id`.
    const port_slot: caps.HandleId = caps.SLOT_FIRST_PASSED;

    const entry_a = caps.PassedHandle{
        .id = port_slot,
        .caps = (caps.PortCap{ .bind = true }).toU16(),
        .move = false,
    };
    const entry_b = caps.PassedHandle{
        .id = port_slot,
        .caps = (caps.PortCap{ .xfer = true }).toU16(),
        .move = false,
    };
    const passed: [2]u64 = .{ entry_a.toU64(), entry_b.toU64() };

    // Step 3: issue create_capability_domain. self_caps = 0 and
    // ceilings = 0 trivially satisfy the subset checks; reserved bits
    // are clean; the page frame handle is valid; only the duplicate
    // source id remains as a spec violation.
    const result = syscall.createCapabilityDomain(0, 0, 0, pf_handle, 0, // initial_ec_affinity
        passed[0..]);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
