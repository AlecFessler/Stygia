// Spec §[create_capability_domain] create_capability_domain — test 12.
//
// "[test 12] returns E_PERM if `port_ceiling` is not a subset of the
//  caller's `port_ceiling`."
//
// Strategy
//   `port_ceiling` lives in ceilings_inner ([2]) bits 48-55. Within
//   that 8-bit sub-field the spec defines:
//     bit 50: xfer
//     bit 51: recv
//     bit 52: bind
//     bits 48-49, 53-55: _reserved
//
//   The runner (runner/primary.zig) installs ceilings_inner =
//   0x001C_011F_3F01_FFFF, so the test domain's port_ceiling sub-field
//   = 0x1C — bits 2/3/4 set (xfer/recv/bind), bits 0/1 clear. (The
//   sub-field bits are numbered relative to the byte; in field0 bits
//   the runner's value covers bits 50/51/52.)
//
//   We construct a ceilings_inner whose port_ceiling sub-field equals
//   the caller's value with one additional clear bit set. Setting the
//   sub-field's bit 0 (field0 bit 48) yields 0x1D — a strict superset
//   of the caller's 0x1C, so the subset check must reject with E_PERM.
//
//   SPEC AMBIGUITY: bits 48-49 of field0 (the sub-field's bits 0-1)
//   are documented as `_reserved` within port_ceiling. Test 17 covers
//   the reserved-bits-set rejection with E_INVAL. The spec does not
//   pin which check (subset vs reserved) the kernel evaluates first,
//   so a spec-compliant kernel could return E_INVAL here instead of
//   E_PERM. To keep this test exercising the subset path
//   unambiguously, we'd prefer to flip a documented sub-field bit
//   that is clear in the caller — but bits 50/51/52 are all set, so
//   there is no documented bit available. We accept the ambiguity and
//   target E_PERM on the assumption the kernel performs subset
//   checking before reserved-bits validation for this sub-field.
//
//   Other arguments (caps, ceilings_outer, elf_page_frame,
//   passed_handles) are constructed to be valid in isolation so the
//   kernel's only intended reject reason is the port_ceiling subset
//   check.
//
// Action
//   1. create_capability_domain(self_caps subset, ceilings_inner with
//        port_ceiling = 0x1D (caller's 0x1C | bit 0),
//        ceilings_outer subset, valid pf, no passed)
//      — must return E_PERM
//
// Assertions
//   1: page-frame setup syscall failed
//   2: createCapabilityDomain returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Stage a minimal, valid page frame for [4]. The kernel must
    // reject on the port_ceiling subset check before parsing the ELF,
    // so the page frame contents are immaterial.
    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props.sz = 0 (4 KiB)
        1, // 1 page
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    // [1] caps: strict subset of the runner-installed self_caps.
    const self_caps = caps.SelfCap{
        .crcd = true,
    };
    const v1_caps: u64 = @as(u64, self_caps.toU16());

    // [2] ceilings_inner: build the violator. The caller (test domain)
    // has port_ceiling = 0x1C in the sub-field at field0 bits 48-55,
    // i.e. field0 bits 50/51/52 set (xfer/recv/bind). Set the
    // sub-field's bit 0 (field0 bit 48) to make a strict superset:
    //
    //   port_ceiling sub-field = 0x1C | 0x01 = 0x1D
    //
    // All other sub-fields of ceilings_inner echo the caller's
    // values to remain subsets:
    //   bits  0-7  ec_inner_ceiling   = 0xFF
    //   bits  8-23 var_inner_ceiling  = 0x01FF
    //   bits 24-31 cridc_ceiling      = 0x3F
    //   bits 32-39 pf_ceiling         = 0x1F
    //   bits 40-47 vm_ceiling         = 0x01
    //   bits 48-55 port_ceiling       = 0x1D  <-- violator
    //   bits 56-63 _reserved          = 0
    const port_ceiling_violator: u64 = 0x1D;
    const ceilings_inner: u64 =
        (port_ceiling_violator << 48) |
        (@as(u64, 0x01) << 40) |
        (@as(u64, 0x1F) << 32) |
        (@as(u64, 0x3F) << 24) |
        (@as(u64, 0x01FF) << 8) |
        @as(u64, 0xFF);

    // [3] ceilings_outer: zero is always a subset of any caller
    // ceiling, and zero in restart_policy_ceiling subfields encodes
    // "kill / free / drop" — all valid sub-bounds. fut_wait_max = 0
    // is a subset of the caller's 63.
    const ceilings_outer: u64 = 0;

    // No passed handles.
    const passed_handles: [0]u64 = .{};

    const result = syscall.createCapabilityDomain(v1_caps, ceilings_inner, ceilings_outer, pf_handle, 0, // initial_ec_affinity
        passed_handles[0..]);

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
