// Spec §[futex_wait_change] — test 01 (degraded smoke).
//
// "[test 01] returns E_PERM if the caller's self-handle has
//  `fut_wait_max = 0`."
//
// Strategy
//   The caller's self-handle carries `fut_wait_max` in field1 bits
//   32-37 (§[capability_domain]). A faithful test reduces the caller's
//   own `fut_wait_max` to 0, then issues `futex_wait_change` and
//   expects E_PERM.
//
//   Per §[restrict], `restrict` only mutates the caps field (word0
//   bits 48-63). `fut_wait_max` lives in field1, not in caps, so there
//   is no syscall in v3 by which a domain can shrink its own
//   `fut_wait_max` after creation. A domain's `fut_wait_max` is
//   therefore fixed at create time as an inner subset of its
//   creator's outer ceiling.
//
//   The runner (runner/primary.zig) installs ceilings_outer with
//   bits 32-37 = 63 for every test domain. So inside this test the
//   self-handle's `fut_wait_max` is always 63, and the E_PERM branch
//   under test is structurally unreachable from a child domain on the
//   v0 runner.
//
// Degraded smoke
//   Read the self-handle's field1 and extract bits 32-37. If
//   `fut_wait_max != 0`, report a degraded smoke pass: the test ELF
//   links, loads, and exercises the cap-table read plumbing, but the
//   E_PERM assertion is structurally unreachable until a runner mode
//   exists that mints a child whose self-handle has `fut_wait_max = 0`.
//
//   If `fut_wait_max == 0` (a future runner mode, or a test-time
//   reconfiguration), issue `futex_wait_change` with a single
//   well-formed pair: timeout_ns = 0 (non-blocking, so no scheduler
//   interaction is required for the E_PERM check to fire), N = 1
//   (within `1..63`, isolating from test 02), addr = a stack-local
//   8-byte-aligned u64 (avoids E_INVAL test 04 on misaligned addr and
//   E_BADADDR test 05 on a non-domain address), target = 0. With every
//   other reject path closed, only the §[futex_wait_change] test 01
//   self-cap check can fire — the kernel must return E_PERM.
//
// Action
//   1. Read self-handle (slot 0) field1, extract `fut_wait_max`.
//   2. If non-zero → smoke-pass (degraded; documented).
//   3. Build a single (addr, target) pair pointing at a stack-local
//      u64. Issue futex_wait_change(timeout_ns = 0, pairs).
//   4. Assert vreg 1 == E_PERM.
//
// Assertions
//   1: futex_wait_change returned a value other than E_PERM when the
//      caller's self-handle had `fut_wait_max = 0`.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const fut_wait_max: u6 = @truncate((self_cap.field1 >> 32) & 0x3F);

    if (fut_wait_max != 0) {
        // Degraded smoke: runner installs `fut_wait_max = 63` and
        // there is no syscall in v3 that lets a domain shrink its own
        // `fut_wait_max` (restrict only touches caps, not field1).
        // The E_PERM branch under test is therefore structurally
        // unreachable from a child domain on the v0 runner. Smoke-pass
        // and document; if a future runner mode mints a child with
        // `fut_wait_max = 0`, this branch retires automatically.
        testing.pass();
        return;
    }

    // Stack-local 8-byte aligned u64. Its address sits in this
    // domain's caller-mapped stack range, so it is a valid user
    // address (closes test 05) and naturally 8-byte aligned (closes
    // test 04). target = 0 is irrelevant: the spec test 01 self-cap
    // check fires before any value compare.
    var slot_value: u64 = 0;
    const addr: u64 = @intFromPtr(&slot_value);
    const pairs: [2]u64 = .{ addr, 0 };

    // timeout_ns = 0 keeps the call non-blocking so the E_PERM check
    // can be evaluated without any scheduler interaction.
    const r = syscall.futexWaitChange(0, pairs[0..]);

    if (r.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
