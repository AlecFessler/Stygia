// Spec §[create_process] create_process — test 12.
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
//   The runner installs port_ceiling = 0x1C for this test: xfer, recv,
//   and bind are granted, while the documented suspend bit is clear.
//
//   Requesting suspend too makes the child port ceiling 0x5C. Those
//   bits are all valid, but 0x5C is not a subset of the caller's 0x1C,
//   so the kernel must return E_PERM.
//
//   Other arguments (caps, ceilings_outer, elf_page_frame,
//   passed_handles) are constructed to be valid in isolation so the
//   kernel's only intended reject reason is the port_ceiling subset
//   check.
//
// Action
//   1. create_process(self_caps subset, ceilings_inner with
//        port_ceiling = 0x5C (caller's 0x1C | suspend),
//        ceilings_outer subset, valid pf, no passed)
//      — must return E_PERM
//
// Assertions
//   1: page-frame setup syscall failed
//   2: createProcess returned something other than E_PERM

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
        .crproc = true,
    };
    const v1_caps: u64 = @as(u64, self_caps.toU16());

    // [2] ceilings_inner: build the violator. The caller (test process)
    // has port_ceiling = 0x1C (xfer/recv/bind). Add the documented
    // suspend bit (field0 bit 54) to make a strict superset:
    //
    //   port_ceiling sub-field = 0x1C | 0x40 = 0x5C
    //
    // All other sub-fields of ceilings_inner echo the caller's
    // values to remain subsets:
    //   bits  0-7  thread_inner_ceiling   = 0xFF
    //   bits  8-23 vmar_inner_ceiling  = 0x01FF
    //   bits 24-31 cripc_ceiling      = 0x27
    //   bits 32-39 pf_ceiling         = 0x1F
    //   bits 40-47 vm_ceiling         = 0x01
    //   bits 48-55 port_ceiling       = 0x5C  <-- violator
    //   bits 56-63 _reserved          = 0
    const port_ceiling_violator: u64 = 0x5C;
    const ceilings_inner: u64 =
        (port_ceiling_violator << 48) |
        (@as(u64, 0x01) << 40) |
        (@as(u64, 0x1F) << 32) |
        (@as(u64, 0x27) << 24) |
        (@as(u64, 0x01FF) << 8) |
        @as(u64, 0xFF);

    // [3] ceilings_outer: zero is always a subset of any caller
    // ceiling, and zero in restart_policy_ceiling subfields encodes
    // "kill / free / drop" — all valid sub-bounds. fut_wait_max = 0
    // is a subset of the caller's 63.
    const ceilings_outer: u64 = 0;

    // No passed handles.
    const passed_handles: [0]u64 = .{};

    const result = syscall.createProcess(v1_caps, ceilings_inner, ceilings_outer, pf_handle, 0, // initial_thread_affinity
        passed_handles[0..]);

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
