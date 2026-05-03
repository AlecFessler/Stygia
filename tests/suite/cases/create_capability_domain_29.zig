// Spec §[create_capability_domain] create_capability_domain — test 29.
//
// "[test 29] the initial EC begins executing at the entry point
//  declared in the ELF header."
//
// Strategy
//   This test runs inside a freshly-spawned child capability domain.
//   The runner builds each test as its own ELF (`tests/build.zig`:
//   `buildTestElf` sets `exe.entry = .{ .symbol_name = "_start" }`),
//   embeds that ELF into the runner's manifest, stages it into a page
//   frame at `create_capability_domain` time, and the kernel is
//   expected to honor the ELF header's `e_entry` when binding the
//   initial EC. `libz/start.zig` defines `_start` as the only exported
//   symbol — it dispatches into `app.main(cap_table_base)`, which is
//   this file's `main`.
//
//   Reaching `main` therefore proves the kernel jumped to the address
//   declared as `e_entry` in this ELF's header: any other landing
//   site (kernel jumping to address 0, to the ELF base, or to some
//   other section) would not transit through `_start` into `main` —
//   the runner would never see a `pass`/`fail` event delivered on
//   the result port and would hang or surface an unrelated fault.
//
//   To make the entry-point observation slightly less tautological we
//   also assert that the kernel passed a non-zero `cap_table_base`
//   into vreg/rdi at entry. Per §[create_capability_domain]: "The
//   pointer to the new domain's read-only view of its capability
//   table is passed as the first argument to the initial EC's entry
//   point." A zero base would mean the kernel either skipped the
//   ELF-prescribed entry path or invoked it without the documented
//   argument convention; either deviation contradicts test 29.
//
//   The runner-side machinery already exercises tests 19-25 of this
//   section as a precondition for any test running at all (the child
//   would not exist without the `create_capability_domain` syscall
//   succeeding). This test is the narrow assertion that the kernel,
//   having decided to spawn the domain, does so at the ELF-declared
//   entry rather than at some other address.
//
// Action
//   None. The mere fact that `main` is invoked is the observation.
//
// Assertions
//   1: cap_table_base is zero (kernel did not honor the entry-point
//      argument convention; the entry path is suspect).

const lib = @import("lib");

const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    if (cap_table_base == 0) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
