// Spec §[create_capability_domain] — test 15.
//
// "[test 15] returns E_INVAL if the ELF header is malformed."
//
// Strategy
//   `create_capability_domain` reads the ELF image from `[4]
//   elf_page_frame` starting at byte 0. If the bytes there are not a
//   well-formed ELF header (first the 16-byte e_ident — magic 0x7F 'E'
//   'L' 'F', class, data, version, OS ABI, etc., then the typed
//   header), the kernel must reject the call with E_INVAL rather than
//   try to interpret garbage as code.
//
//   We mint a fresh page frame and write zero bytes into the first
//   page. Zero bytes have a magic of 0x00 0x00 0x00 0x00 — not 0x7F
//   'E' 'L' 'F' — so the e_ident check fails on the first byte and
//   nothing the kernel could read further changes the verdict.
//
//   Other create_capability_domain reject paths must NOT fire, or the
//   kernel could return one of those instead of E_INVAL:
//     - test 01 (E_PERM no `crcd`): the runner grants the child
//       `crcd` on its self-handle (see runner/primary.zig
//       `child_self`), so this test's caller has it.
//     - tests 02-12 (E_PERM caps/ceilings not subset): we pass 0 for
//       [1], [2], and [3], which is a subset of any field.
//     - test 13 (E_BADCAP not a valid page frame): we pass a page
//       frame we just minted via create_page_frame.
//     - test 14 (E_BADCAP passed handle id invalid): we pass an empty
//       passed_handles slice.
//     - test 17 (E_INVAL reserved bits set): all reserved fields in
//       [1] / [2] / [3] are 0 because we pass 0.
//     - test 18 (E_INVAL duplicate passed handles): the slice is
//       empty, so duplicates are vacuously absent.
//
// SPEC AMBIGUITY: spec test 13 specifies E_BADCAP for "not a valid
//   page frame handle"; spec test 16 specifies E_INVAL for a page
//   frame "smaller than the declared ELF image size". When the bytes
//   at offset 0 aren't a valid ELF header at all (this test), there's
//   no declared size yet; the spec puts that case under test 15
//   (malformed header), which is the path we exercise.
//
// SPEC AMBIGUITY: §[create_capability_domain] doesn't pin whether the
//   kernel reads the page frame via its own kernel mapping or via the
//   caller's VAR. Following the runner pattern, we keep the staging
//   VAR mapped while we write, then unmap before the syscall. If the
//   kernel actually requires a live VAR mapping during the call, the
//   kernel-side handler will need its own kernel mapping and the test
//   will still observe E_INVAL — we never assert OK.
//
// Action
//   1. create_page_frame(caps={r,w,move}, props=0, pages=1)
//   2. create_var(caps={r,w}, props={cur_rwx=r|w}, pages=1) — staging
//   3. map_pf(var, [{0, pf}])
//   4. zero the first page through the VAR mapping (clobbers the
//      ELF magic)
//   5. delete(var)                                — drop staging map
//   6. create_capability_domain(caps=0, ceilings_inner=0,
//      ceilings_outer=0, elf_pf=pf, passed_handles={})
//   7. expect vreg 1 == E_INVAL
//
// Assertions
//   1: create_page_frame returned an error word
//   2: create_var returned an error word
//   3: map_pf returned non-OK
//   4: create_capability_domain didn't return E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[page_frame] mint a 1-page (4 KiB) page frame. caps include
    // r|w so the staging VAR can map it for write; move is set so the
    // create_capability_domain call below — which conceptually
    // consumes the frame's contents — can do whatever transfer
    // semantics it needs without an extra cap-bit hurdle.
    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB), restart_policy = 0
        1, // pages
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    // §[var] mint a temporary VAR to gain a writable mapping over the
    // page frame. caps.r|w; props.cur_rwx = r|w (subset of caps);
    // pages = 1; preferred_base = 0 (kernel chooses); device_region
    // = 0 (caps.dma = 0 so it's ignored).
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        0b011, // cur_rwx = r|w
        1, // pages
        0, // preferred_base
        0, // device_region
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const var_handle: u12 = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    // §[map_pf] pairs encoding: each pair is {var_offset_pages,
    // pf_handle}. Map the entire frame at offset 0.
    const mp = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (mp.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Zero the first page so the bytes at offset 0 cannot be a valid
    // ELF header. ELF requires e_ident[0..4] = { 0x7F, 'E', 'L', 'F' };
    // zeros fail that check on the first byte. Writing the full page
    // (rather than just the first 4 bytes) is defensive: it ensures
    // no residual garbage from a recycled physical frame happens to
    // form a legible ELF prefix.
    const dst: [*]u8 = @ptrFromInt(var_base);
    var i: usize = 0;
    while (i < 4096) {
        dst[i] = 0;
        i += 1;
    }

    // Drop the staging VAR. Per the runner's spawnOne path this is
    // optimistic: if the kernel needs a live VAR mapping during
    // create_capability_domain it will surface a different error and
    // assertion 4 will fire. The faithful E_INVAL path is unaffected
    // since the page frame itself still holds the zeroed bytes.
    _ = syscall.delete(var_handle);

    // [1] caps = 0, [2] ceilings_inner = 0, [3] ceilings_outer = 0
    // — all-zero is a subset of every ceiling, dodging tests 02-12,
    // and keeps every reserved field clean, dodging test 17. The
    // empty passed_handles slice avoids tests 14 and 18.
    const result = syscall.createCapabilityDomain(
        0, // caps (self_caps + idc_rx + reserved all zero)
        0, // ceilings_inner
        0, // ceilings_outer
        pf_handle,
        0, // initial_ec_affinity
        &.{}, // no passed handles
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
