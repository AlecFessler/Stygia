// Spec §[create_vcpu] — test 07.
//
// "[test 07] returns E_INVAL if any reserved bits are set in [1]."
//
// Strategy
//   §[create_vcpu] pins the layout of [1] explicitly:
//     [1] caps:  bits  0-15 = caps (EcCap on the EC handle returned)
//                bits 32-33 = priority (0..3, bounded by caller's
//                             priority ceiling)
//                bits 16-31, 34-63 = _reserved.
//   Setting any bit in those reserved ranges must surface E_INVAL at
//   the syscall ABI layer regardless of whether the rest of the call
//   would otherwise have succeeded (§[syscall_abi]).
//
//   To isolate the reserved-bit check we make every other create_vcpu
//   prelude check pass — same shape as create_virtual_machine_05's
//   defusing approach — and then dial in a single reserved bit on top
//   of an otherwise-valid caps word. We use bit 63 of [1] (the top of
//   the bits 34-63 reserved range) which sits well above the priority
//   field (bits 32-33) and the EcCap field (bits 0-15), so it cannot
//   be mistaken for a real cap that the kernel would reject for a
//   different reason.
//
//   The libz `syscall.createVcpu` wrapper takes u64 args, so it does
//   not strip upper bits. We still bypass it via `syscall.issueReg` to
//   mirror the create_var_17 reference pattern and keep the call shape
//   explicit at the ABI layer.
//
// Defusing other create_vcpu error paths
//   - test 01 (E_PERM no `crec`): runner spawns the child with `crec`
//     in `child_self` (see runner/primary.zig spawnOne).
//   - test 02 (E_PERM caps not subset of ec_inner_ceiling): runner
//     grants `ec_inner_ceiling = 0xFF` (EcCap bits 0-7). Our valid
//     caps below stay within that subset.
//   - test 03 (E_PERM priority exceeds ceiling): runner grants
//     `pri = 3`. We set priority = 0, well under the ceiling.
//   - test 04 (E_BADCAP not a valid VM handle): we mint a real VM via
//     create_virtual_machine and pass its handle.
//   - test 05 (E_BADCAP not a valid port handle): we mint a real port
//     via create_port and pass its handle.
//   - test 06 (E_INVAL affinity bits outside core count): affinity = 0
//     means "any core", which §[create_vcpu] explicitly accepts.
//
//   Setup chain mirrors create_virtual_machine_05: smallest valid page
//   frame (1 page, sz=0) is larger than sizeof(VmPolicy), and the
//   kernel zero-fills the frame, so all VmPolicy num_* fields read 0
//   (well under their max bounds) and the VM construction itself
//   carries no reserved-bit traps.
//
// Action
//   1. create_page_frame(caps={r,w,move}, props=0, pages=1) —
//      backing store for VmPolicy.
//   2. create_virtual_machine(caps=0, policy_pf) — mint a valid VM.
//   3. create_port(caps={recv, bind}) — mint a valid port for the
//      vCPU's exit_port arg.
//   4. issueReg(.create_vcpu) with [1] = (valid_caps | (1<<63)),
//      [2] = vm_handle, [3] = 0, [4] = port_handle —
//      must return E_INVAL.
//
// Assertions
//   1: setup — create_page_frame returned an error word.
//   2: setup — create_virtual_machine returned an error word.
//   3: setup — create_port returned an error word.
//   4: reserved bit set in [1] did not return E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1 — page frame backing the VmPolicy struct. 1 page (4 KiB)
    // is larger than sizeof(VmPolicy) on both x86-64 (976 B) and
    // aarch64 (1776 B), so the size check passes. The frame is zeroed
    // by the kernel, so num_*_responses = 0 stays well under the
    // MAX_*_POLICIES bounds that test 06/07 of create_virtual_machine
    // would otherwise trip on.
    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1,
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const policy_pf: HandleId = @truncate(cpf.v1 & 0xFFF);

    // Step 2 — mint a valid VM. caps = 0 stays a subset of every
    // ceiling and leaves all reserved bits clear, so test 02 / test 08
    // of create_virtual_machine cannot fire ahead of us.
    const cvm = syscall.createVirtualMachine(0, policy_pf);
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(2);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // Step 3 — mint a valid port. The runner grants `crpt` and
    // port_ceiling = 0x1C (xfer | recv | bind at field-bits 2-4 of
    // PortCap), so `bind | recv` stays within the ceiling.
    const port_caps = caps.PortCap{ .recv = true, .bind = true };
    const cport = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cport.v1)) {
        testing.fail(3);
        return;
    }
    const exit_port: HandleId = @truncate(cport.v1 & 0xFFF);

    // EcCap subset of ec_inner_ceiling = 0xFF (bits 0-7). `read|write`
    // is well within that subset and is the same shape used by other
    // create_ec test setups in the suite.
    const ec_caps = caps.EcCap{ .read = true, .write = true };
    const valid_caps_word: u64 = @as(u64, ec_caps.toU16());
    // priority = 0 — under the runner-granted pri = 3 ceiling.
    const caps_with_reserved: u64 = valid_caps_word | (@as(u64, 1) << 63);

    // Step 4 — issue with bit 63 of [1] set. affinity = 0 selects
    // "any core" per §[create_vcpu], so test 06 (E_INVAL affinity
    // outside core count) cannot fire either.
    const r = syscall.issueReg(.create_vcpu, 0, .{
        .v1 = caps_with_reserved,
        .v2 = vm_handle,
        .v3 = 0,
        .v4 = exit_port,
    });
    if (r.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
