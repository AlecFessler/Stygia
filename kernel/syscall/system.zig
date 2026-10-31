const stygia = @import("stygia");

const cpu = stygia.arch.dispatch.cpu;
const errors = stygia.syscall.errors;
const smp = stygia.arch.dispatch.smp;
const sync = stygia.utils.sync;
const time = stygia.arch.dispatch.time;

const CapabilityDomainCaps = stygia.caps.capability_domain.CapabilityDomainCaps;
const ExecutionContext = stygia.sched.execution_context.ExecutionContext;
const SpinLock = sync.spin_lock.SpinLock;
const Word0 = stygia.caps.capability.Word0;

// ── Wall-clock state ─────────────────────────────────────────────────
//
// Spec §[time].time_getwall / time_setwall describe a wall-clock value
// that callers can both read (no cap) and rewrite (`setwall` cap). The
// platform RTC has 1-second resolution and (on x86-64) is not yet wired
// for writes, so the kernel maintains an in-memory wall-clock origin
// expressed as a (wall_ns_at_anchor, monotonic_ns_at_anchor) pair. The
// effective wall time at the moment of a `time_getwall` is
//   wall_now = wall_at_anchor + (monotonic_now - monotonic_at_anchor),
// which preserves nanosecond resolution and advances at the same rate
// as the monotonic clock between updates.
//
// The pair is read/written together under `wall_lock` so a concurrent
// `time_setwall` cannot tear the relationship between the two values.
//
// The anchor is established once at boot by `init()` while IRQs are
// naturally off; running the slow x86 CMOS UIP-clear loop with IRQs
// disabled in syscall context (the previous lazy-init path) starved
// preempt and timer interrupts for milliseconds on every cold boot's
// first `time_getwall`.
var wall_lock: SpinLock = .{ .class = "wall_clock" };
var wall_at_anchor_ns: u64 = 0;
var monotonic_at_anchor_ns: u64 = 0;

/// One-time wall-clock anchor bring-up, called from `kMain` after the
/// monotonic clock is initialized. Latches the platform RTC reading
/// against the current monotonic time so subsequent `time_getwall`
/// calls can return a nanosecond-resolution wall value without
/// re-touching the RTC's slow read path.
pub fn init() void {
    wall_at_anchor_ns = time.readRtc();
    monotonic_at_anchor_ns = time.currentMonotonicNs();
}

fn currentWallNs() u64 {
    const state = wall_lock.lockIrqSave(@src());
    defer wall_lock.unlockIrqRestore(state);

    const mono_now = time.currentMonotonicNs();
    const elapsed = mono_now -% monotonic_at_anchor_ns;
    return wall_at_anchor_ns +% elapsed;
}

fn setWallNs(ns_since_epoch: u64) void {
    const state = wall_lock.lockIrqSave(@src());
    defer wall_lock.unlockIrqRestore(state);

    wall_at_anchor_ns = ns_since_epoch;
    monotonic_at_anchor_ns = time.currentMonotonicNs();
}

/// Returns nanoseconds since boot.
///
/// ```
/// time_monotonic() -> [1] ns
///   syscall_num = 46
/// ```
///
/// No cap required.
///
/// [test 01] on success, [1] is a u64 nanosecond count strictly greater than the value returned by any prior call to `time_monotonic`.
pub fn timeMonotonic(caller: *anyopaque) i64 {
    _ = caller;
    return @bitCast(time.currentMonotonicNs());
}

/// Returns wall-clock time as nanoseconds since the Unix epoch.
///
/// ```
/// time_getwall() -> [1] ns_since_epoch
///   syscall_num = 47
/// ```
///
/// No cap required.
///
/// [test 02] after `time_setwall(X)` succeeds, a subsequent `time_getwall` returns a value within a small bounded delta of X.
pub fn timeGetwall(caller: *anyopaque) i64 {
    _ = caller;
    return @bitCast(currentWallNs());
}

/// Sets the wall-clock time to the given nanoseconds-since-epoch.
///
/// ```
/// time_setwall([1] ns_since_epoch) -> void
///   syscall_num = 48
///
///   [1] ns_since_epoch: new wall-clock value (nanoseconds since Unix epoch)
/// ```
///
/// Self-handle cap required: `setwall`.
///
/// [test 03] returns E_PERM if the caller's self-handle lacks `setwall`.
/// [test 04] returns E_INVAL if any reserved bits are set in [1].
/// [test 05] on success, a subsequent `time_getwall` returns a value within a small bounded delta of [1].
pub fn timeSetwall(caller: *anyopaque, ns_since_epoch: u64) i64 {
    // Spec §[time_setwall] test 04: bit 63 of [1] is reserved (a clean
    // ns_since_epoch fits in i63 — ~292 years past the Unix epoch),
    // and any reserved bit set must surface E_INVAL. Validate before
    // the rights check so a malformed argument is rejected uniformly.
    if (ns_since_epoch & (@as(u64, 1) << 63) != 0) return errors.E_INVAL;
    const self_caps = readSelfCaps(caller) orelse return errors.E_BADCAP;
    if (!self_caps.setwall) return errors.E_PERM;
    setWallNs(ns_since_epoch);
    // Best-effort sync to the platform RTC; a stub on x86-64 today,
    // but lets aarch64's writeRtc() persist across reboots once wired.
    _ = time.writeRtc(ns_since_epoch);
    return errors.OK;
}

/// Fills the requested number of vregs with cryptographically random
/// qwords.
///
/// ```
/// random() -> [1..count] qwords
///   syscall_num = 49
///
///   syscall word bits 12-19: count (1..127)
/// ```
///
/// No cap required.
///
/// [test 01] returns E_INVAL if count is 0 or count > 127.
/// [test 02] on success, vregs `[1..count]` contain qwords (the CSPRNG-source guarantee in the prose above is a kernel implementation contract, not a black-box-testable assertion).
pub fn random(caller: *anyopaque, count: u8) i64 {
    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    // Spec §[rng] test 01: count must be in [1, 127], otherwise E_INVAL.
    if (count == 0 or count > 127) return errors.E_INVAL;

    // Fill vregs [1..count] with hardware-random qwords. `cpu.getRandom`
    // is x86-64 RDRAND or aarch64 RNDR (with a CNTVCT-seeded software
    // PRNG fallback on cores lacking RNG support — see
    // `arch.aarch64.cpu.rndr`). RDRAND can transiently fail (entropy
    // pool empty, CF=0); on null we fold a small TSC-derived diffuser
    // into a per-call PRNG state so the syscall always makes forward
    // progress. The CSPRNG-quality contract is best-effort per spec.
    //
    // Vreg landing: indices 1..N route to GPRs (x86-64: 1..13 →
    // rax/rbx/rdx/rbp/rsi/rdi/r8/r9/r10/r12/r13/r14/r15; aarch64:
    // 1..31 → x0..x30). Higher indices spill to `[user_sp + (idx-N)*8]`.
    // Stack-spill writes go through SMAP/PAN-gated user accesses inside
    // `setSyscallVreg`, which assume the caller's address space is
    // active — the syscall epilogue runs in the caller's CR3/TTBR0, so
    // that contract holds here.
    var fallback_state: u64 = 0;
    var i: u8 = 1;
    while (i <= count) : (i += 1) {
        const v: u64 = blk: {
            if (cpu.getRandom()) |r| break :blk r;
            // Hardware entropy unavailable this attempt — diffuse a
            // monotonic timestamp through xorshift to avoid emitting a
            // stream of zeros while still surfacing a non-blocking
            // value. Userspace CSPRNGs that depend on this path treat
            // it as a low-entropy reseed source, not a primary feed.
            if (fallback_state == 0) fallback_state = time.currentMonotonicNs() ^ 0x9E3779B97F4A7C15;
            var x = fallback_state;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            fallback_state = x;
            break :blk x *% 0x2545F4914F6CDD1D;
        };
        stygia.arch.dispatch.syscall.setSyscallVreg(ec.ctx, i, v);
    }
    return 0;
}

/// Read the `cap` field from the caller domain's slot-0 self-handle.
/// Returns null if the underlying domain ref is stale (caller's domain
/// was torn down concurrently — should not happen in practice for an
/// in-syscall caller, but guards against UAF on the slab path).
fn readSelfCaps(caller: *anyopaque) ?CapabilityDomainCaps {
    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return null;
    const cd = lr.ptr;
    defer cd_ref.unlockIrqRestore(lr.irq_state);
    const caps_bits = Word0.caps(cd.user_table[0].word0);
    return @bitCast(caps_bits);
}
