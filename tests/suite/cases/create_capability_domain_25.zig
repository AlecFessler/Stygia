// Spec §[create_capability_domain] — test 25.
//
// "[test 25] a passed handle entry with `move = 0` remains in the
//  caller's handle table after the call."
//
// Strategy
//   The contract under test: when an entry in [4+] passed_handles has
//   move = 0, the kernel must copy (not transfer) the source handle
//   into the new domain — the source slot in the caller's table must
//   still resolve to the same capability after the call returns.
//
//   To probe that, mint a port handle in the test EC's table with
//   caps {bind, recv, copy} so the move=0 path is valid (per
//   §[handle_attachments] [test 05], move=0 requires `copy` on the
//   source). Issue create_capability_domain passing that port handle
//   with move = 0. Then verify the original slot is still occupied
//   by calling `restrict(port, 0)`:
//     - new caps = 0 is a subset of any prior caps (no E_PERM),
//     - reserved bits are clean (no E_INVAL),
//   so the only error path that fires if the slot were vacated is
//   E_BADCAP. Any non-E_BADCAP outcome — success or otherwise — is
//   evidence the handle is still resident.
//
//   SPEC AMBIGUITY / DEGRADED SHAPE: a fully faithful test would
//   pass on the success path of create_capability_domain, requiring
//   the test ELF to embed a second valid v3-capable child ELF for
//   the kernel to load. The v0 runner does not surface a child-ELF
//   builder to individual tests, and constructing a self-hosted
//   ELF64 image inline would inflate this test beyond what the
//   single-test ELF target supports today. As a degraded smoke
//   variant, this test passes a freshly-allocated page frame whose
//   contents are unspecified — the kernel may return E_INVAL
//   (malformed ELF) or E_NOMEM rather than success. The
//   post-condition we verify (the handle still resolves) is
//   strictly weaker than [test 25]'s "after a successful call",
//   but it is a necessary condition for [test 25] to hold and a
//   stronger statement than the trivial: it forbids the kernel
//   from removing move=0 entries on *any* path. Once the runner
//   exposes a child-ELF builder this test should be promoted to
//   the success-path shape.
//
// Action
//   1. create_port(caps={bind, recv, copy}) — must succeed
//   2. create_page_frame(1 page)            — must succeed (ELF stand-in)
//   3. create_capability_domain(..., passed=[port, move=0])
//   4. restrict(port, 0)                    — must NOT return E_BADCAP
//
// Assertions
//   1: create_port returned an error word (setup failure)
//   2: create_page_frame returned an error word (setup failure)
//   3: post-call restrict on the passed port returned E_BADCAP,
//      i.e. the move=0 source handle was incorrectly vacated

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint a port with bind + recv + copy. `copy` is required
    // so passing it with move = 0 is permitted by the move/copy gating
    // in §[handle_attachments]. bind + recv keep the handle non-trivial
    // so a follow-up restrict has a real cap word to subset.
    const initial = caps.PortCap{
        .copy = true,
        .bind = true,
        .recv = true,
    };
    const cp = syscall.createPort(@as(u64, initial.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: a page frame to stand in for the ELF image. v0 does not
    // expose a child-ELF builder; the kernel may reject this with
    // E_INVAL/E_NOMEM but the move=0 invariant under test must hold
    // regardless of the call's outcome.
    const pf_caps = caps.PfCap{ .move = true, .r = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props.sz = 0 → 4 KiB pages
        1, // pages
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(2);
        return;
    }
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    // Step 3: build ceiling words that any-bit-valid for the child.
    // Mirrors runner/primary.zig's encoding so reserved bits stay zero
    // and §[create_capability_domain] [test 17] can't fire on them.
    const ceilings_inner: u64 = 0x001C_011F_3F01_FFFF;
    const ceilings_outer: u64 = 0x0000_003F_03FE_FFFF;

    const child_self = caps.SelfCap{
        .crcd = true,
        .crec = true,
        .crvr = true,
        .crpf = true,
        .crpt = true,
        .pri = 3,
    };
    const self_caps_word: u64 = @as(u64, child_self.toU16());

    // The entry under test: move = 0, caps subset of port's current
    // caps, reserved bits zero. caps = {bind, recv} drops `copy` to
    // illustrate that the installed-in-child caps need not equal the
    // source caps.
    const child_port_caps = caps.PortCap{
        .bind = true,
        .recv = true,
    };
    const passed: [1]u64 = .{
        (caps.PassedHandle{
            .id = port_handle,
            .caps = child_port_caps.toU16(),
            .move = false,
        }).toU64(),
    };

    // Issue the call. The return value (vreg 1) is intentionally
    // ignored: the move = 0 contract is independent of whether the
    // call succeeds or fails. See the doc comment above for the
    // degraded-shape rationale.
    _ = syscall.createCapabilityDomain(self_caps_word, ceilings_inner, ceilings_outer, pf_handle, 0, // initial_ec_affinity
        passed[0..]);

    // Step 4: probe the original slot. If the move = 0 entry was
    // vacated, restrict returns E_BADCAP. Any other return value —
    // OK on success, E_PERM on a (here-impossible) caps mismatch —
    // is evidence the handle still resides in our table.
    const probe = syscall.restrict(port_handle, 0);
    if (probe.v1 == @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
