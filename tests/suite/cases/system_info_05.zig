// Spec §[system_info] info_cores — test 05.
//
// "[test 05] returns E_INVAL if any reserved bits are set in [1]."
//
// Strategy
//   `info_cores([1] core_id) -> ...` (§[system_info]) takes `core_id`
//   in [1]; the spec does not call out an explicit bit-width for the
//   core_id field. §[syscall_abi] therefore controls: "Bits not
//   assigned by the invoked syscall must be zero on entry; the kernel
//   returns E_INVAL if a reserved bit is set."
//
//   info_cores's failure paths are:
//     [test 04] E_INVAL if [1] core_id >= `info_system`'s `cores`.
//     [test 05] E_INVAL if any reserved bits are set in [1].
//
//   To isolate the reserved-bit check we make every other check pass.
//   `info_cores` requires no cap (§[system_info] "No cap required."),
//   so there is no E_PERM path. We need core_id to refer to a valid
//   core, so the low bits hold 0 — every supported platform has at
//   least one online core (core 0). [test 01] guarantees `info_system`'s
//   `cores` is the platform's online count, which is >= 1.
//
//   We then dispatch info_cores with reserved bit 63 of [1] set while
//   the low bits hold core_id 0. Bit 63 is well past any plausible
//   core_id field width (the host has at most a small number of cores)
//   so it is unambiguously in the _reserved range regardless of how
//   wide the implementation chooses to make the core_id field. The
//   libz `syscall.infoCores` wrapper takes `core_id: u64` and forwards
//   it verbatim, so the typed wrapper carries the reserved bit through
//   to the kernel.
//
// Action
//   info_cores(core_id = 0 | (1 << 63))
//     — must return E_INVAL (reserved bit 63 of [1] set; low bits hold
//       core 0, which is always a valid core, so test 04 cannot fire).
//
// Assertion
//   1: info_cores with reserved bit 63 of [1] returned something other
//      than E_INVAL.

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const core_id_with_reserved: u64 = @as(u64, 0) | (@as(u64, 1) << 63);

    const result = syscall.infoCores(core_id_with_reserved);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
