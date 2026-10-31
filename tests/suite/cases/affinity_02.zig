// Spec §[affinity] affinity — test 02.
//
// "[test 02] returns E_PERM if [1] does not have the `saff` cap."
//
// Strategy
//   Mint a fresh thread handle whose cap set deliberately omits `saff`
//   (the cap that gates the `affinity` syscall, §[thread]
//   table entry "saff — set affinity"). Then call `affinity(thread, 0)`.
//
//   With every other failure mode neutralized, E_PERM is the only
//   spec-mandated error path that applies:
//     - test 01 (E_BADCAP, invalid handle): the thread handle is freshly
//       inserted by the kernel via create_thread, so it is
//       valid in our process.
//     - test 03 (E_INVAL, [2] has out-of-range core bits): pass
//       new_affinity = 0, the "any core" sentinel, which by
//       construction has no bits set above the system's core count.
//     - test 04 (E_INVAL, reserved bits in [1]): the libz wrapper
//       takes `target: u12`, so the upper 52 reserved bits of vreg 1
//       are guaranteed zero.
//
//   The new thread must also clear the create_thread spec
//   ceilings:
//     - caps subset of thread_inner_ceiling: runner/primary configures
//       thread_inner_ceiling = 0xFF (low 8 bitwise thread cap bits). We pick
//       caps from {susp, term, read, write} — all in the low 8 bits,
//       and crucially none of them is `saff` (bit 2).
//     - restart_policy = 0 keeps the numeric restart_policy ceiling
//       check (§[restart_semantics]) trivially satisfied.
//     - priority = 0 stays under the priority ceiling.
//     - target = 0 (self) avoids the IDC-target paths.
//
//   The new thread begins executing immediately at `dummyEntry`, which
//   halts forever; the test thread continues independently. No
//   synchronization is required: the affinity call only consults the
//   handle's caps slot in our process's handle table — not the
//   running thread's state.
//
// Action
//   1. create_thread(caps={susp, term, read, write, rp=0},
//      entry=&dummyEntry, stack_pages=1, target=0, affinity=0)
//      — must succeed.
//   2. affinity(thread, 0) — must return E_PERM.
//
// Assertions
//   1: setup syscall failed (create_thread returned an
//      error word in vreg 1).
//   2: affinity returned something other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // thread caps explicitly without `saff`. Stay within the low 8 bits
    // (thread_inner_ceiling = 0xFF) and keep restart_policy = 0.
    const thread_caps = caps.ThreadCap{
        .susp = true,
        .term = true,
        .read = true,
        .write = true,
        .restart_policy = 0,
    };
    // §[create_thread] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. Set caps only; priority = 0 stays under the ceiling.
    const caps_word: u64 = @as(u64, thread_caps.toU16());

    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createThread(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = any core (avoids test 09 of create_thread)
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const thread_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // affinity(thread, 0): handle valid, [2] = 0 (no out-of-range bits),
    // upper bits of [1] guaranteed clean by the u12 wrapper. With
    // `saff` absent, the only applicable spec error is E_PERM.
    const result = syscall.affinity(thread_handle, 0);

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
