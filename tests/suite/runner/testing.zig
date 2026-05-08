// Test reporting helpers for spec v3 model tests.
//
// Each test ELF is spawned by the primary as its own capability domain
// with the result port at `SLOT_FIRST_PASSED`. A test reports its
// outcome by calling `pass()` or `fail(id)`, which suspends the
// initial EC on the port with the result encoding loaded into vregs
// 3 (result_code), 4 (assertion_id), and 5 (test tag — build-time
// stable identity used by the runner to attribute the result to a
// specific manifest entry). The kernel snapshots the suspended EC's
// GPRs as part of §[event_state]; the primary recv's, reads vregs
// 3-5, records into a tag-indexed table, and replies.

const caps = @import("caps");
const syscall = @import("syscall");
const test_tag = @import("test_tag");

pub const PASS_CODE: u64 = 1;
pub const FAIL_CODE: u64 = 0;

pub fn report(result_code: u64, assertion_id: u64) void {
    _ = syscall.issueRawNoStack(0, .{
        .v1 = caps.SLOT_INITIAL_EC,
        .v2 = caps.SLOT_FIRST_PASSED,
        .v3 = result_code,
        .v4 = assertion_id,
        .v5 = test_tag.TAG,
    });
}

pub fn pass() void {
    report(PASS_CODE, 0);
}

pub fn fail(assertion_id: u64) void {
    report(FAIL_CODE, assertion_id);
}

// Discriminator for syscalls that return either a handle word or an
// error code in vreg 1. Handle words always carry the type tag in
// bits 12-15 (non-zero for the create_* paths) plus a caps field in
// bits 48-63, so any value <= 15 is unambiguously an error code per
// §[error_codes].
pub fn isHandleError(v: u64) bool {
    return v > 0 and v < 16;
}

// A no-op EC entry. Tests that need an EC handle but don't care about
// what the EC executes pass `&dummyEntry` as the entry argument to
// `create_execution_context`. The EC will halt forever; the test EC
// reads/restricts/etc. the handle without interference.
pub fn dummyEntry() noreturn {
    while (true) {
        switch (@import("builtin").cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => @compileError("unsupported arch"),
        }
    }
}

// Read the calling EC's currently-dispatched logical core id. On x86
// this comes from RDPID (IA32_TSC_AUX MSR), which the kernel primes at
// `apic.writeTscAuxCoreId` with the per-core index, NOT the raw APIC
// id. On aarch64 it comes from MPIDR_EL1.Aff0 (single-cluster topology
// which matches the smp=4 test rig). Returns the core id as a u64 so
// callers can compare directly against an affinity bit position.
//
// Used by affinity tests to verify the scheduler honored a cap-driven
// affinity restriction by sampling RDPID after a yield: the kernel
// preempts on the timer tick or an explicit yield, re-evaluates the
// run queue, and dispatches on a satisfying core. The RDPID read after
// resume names that core.
pub inline fn currentCoreId() u64 {
    switch (@import("builtin").cpu.arch) {
        .x86_64 => {
            // RDPID is gated on CPUID.07H:0H ECX[22]. KVM-host targets
            // (Skylake / Zen 2+ Intel; Zen 2+ AMD) all expose it. The
            // kernel writes the per-core index into IA32_TSC_AUX at
            // SMP bring-up (`apic.writeTscAuxCoreId`) so RDPID returns
            // the logical core id, not the raw APIC id.
            var idx: u64 = undefined;
            asm volatile (
                \\rdpid %[idx]
                : [idx] "=r" (idx),
            );
            return idx;
        },
        .aarch64 => {
            var mpidr: u64 = undefined;
            asm volatile ("mrs %[v], MPIDR_EL1"
                : [v] "=r" (mpidr),
            );
            return mpidr & 0xFF;
        },
        else => @compileError("unsupported arch"),
    }
}
