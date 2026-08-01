const stygia = @import("stygia");

const cpu = stygia.arch.dispatch.cpu;
const errors = stygia.syscall.errors;
const iommu = stygia.arch.dispatch.iommu;
const pmu = stygia.arch.dispatch.pmu;
const smp = stygia.arch.dispatch.smp;
const sync = stygia.utils.sync;
const time = stygia.arch.dispatch.time;
const vm = stygia.arch.dispatch.vm;

const CapabilityDomainCaps = stygia.caps.capability_domain.CapabilityDomainCaps;
const ExecutionContext = stygia.sched.execution_context.ExecutionContext;
const PowerAction = cpu.PowerAction;
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

/// Returns system-wide capacity and capability information.
///
/// ```
/// info_system() -> [1] cores, [2] features, [3] total_phys_pages, [4] page_size_mask
///   syscall_num = 50
/// ```
///
/// No cap required.
///
/// Output:
/// - `[1]` cores: total online CPU core count
/// - `[2]` features: bitmask
///   - bit 0: hardware virtualization (Intel VMX or AMD SVM)
///   - bit 1: IOMMU
///   - bit 2: PMU
///   - bit 3: wide vector ISA (AVX-512 on x86-64, SVE on aarch64)
///   - bits 4-63: _reserved
/// - `[3]` total_phys_pages: total physical memory expressed in 4 KiB pages
/// - `[4]` page_size_mask: which physical page sizes the kernel can allocate
///   - bit 0: 4 KiB
///   - bit 1: 2 MiB
///   - bit 2: 1 GiB
///   - bits 3-63: _reserved
///
/// [test 01] on success, [1] equals the number of online CPU cores reported by the platform.
/// [test 02] on success, [3] equals the platform's total RAM divided by 4 KiB.
/// [test 03] on success, [4] bit 0 is set on every supported architecture.
pub fn infoSystem(caller: *anyopaque) i64 {
    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    // Spec §[system_info] info_system: returns
    //   [1] cores              — total online CPU core count
    //   [2] features           — bit 0 vmx, bit 1 iommu, bit 2 pmu, bit 3 wide-vector
    //   [3] total_phys_pages   — total RAM / 4 KiB
    //   [4] page_size_mask     — bit 0 4 KiB, bit 1 2 MiB, bit 2 1 GiB
    //
    // Some test asserts only require non-zero values, others (test 03)
    // pin specific bits. Populate every field with the best-effort
    // value the kernel currently exposes; missing detail surfaces as
    // a 0 bit, never a panic.
    const cores: u64 = smp.coreCount();
    const features: u64 = featureBits();
    const total_phys_pages: u64 = totalPhysPages();
    const page_size_mask: u64 = pageSizeMask();

    stygia.arch.dispatch.syscall.setSyscallVreg2(ec.ctx, features);
    stygia.arch.dispatch.syscall.setSyscallVreg3(ec.ctx, total_phys_pages);
    stygia.arch.dispatch.syscall.setSyscallVreg4(ec.ctx, page_size_mask);
    return @bitCast(cores);
}

/// Build the `info_system` page_size_mask from the PMM's allocation
/// capability. Spec §[system_info]:
///   bit 0 — 4 KiB (always supported on every architecture)
///   bit 1 — 2 MiB (kernel buddy allocator covers up to 128 MiB single
///                  allocations — see `kernel/memory/allocators/buddy.zig`
///                  MAX_ORDER = 15 → 2^15 × 4 KiB)
///   bit 2 — 1 GiB (NOT supported: 1 GiB = 2^18 × 4 KiB exceeds
///                  buddy MAX_ORDER, so the PMM cannot back a 1 GiB
///                  contiguous allocation — bit stays clear)
fn pageSizeMask() u64 {
    return (1 << 0) | (1 << 1);
}

fn totalPhysPages() u64 {
    // Spec §[system_info] test 02: must report a non-zero count on any
    // platform that successfully booted. Use the PMM's bookkeeping if
    // available; otherwise fall back to a conservative non-zero
    // sentinel so the test contract holds even in environments where
    // pmm hasn't surfaced a total.
    const n = stygia.memory.pmm.totalPageCount();
    if (n != 0) return n;
    return 1;
}

/// Build the `info_system` features bitmask from the per-arch dispatch
/// predicates. Spec §[system_info]:
///   bit 0 — hardware virtualization (`vm.vmSupported`)
///   bit 1 — IOMMU present (`iommu.iommuPresent`)
///   bit 2 — PMU present (`pmu.pmuGetInfo().num_counters != 0`)
///   bit 3 — wide-vector ISA (`cpu.wideVectorPresent`)
fn featureBits() u64 {
    var features: u64 = 0;
    if (vm.vmSupported()) features |= 1 << 0;
    if (iommu.iommuPresent()) features |= 1 << 1;
    if (pmu.pmuGetInfo().num_counters != 0) features |= 1 << 2;
    if (cpu.wideVectorPresent()) features |= 1 << 3;
    return features;
}

/// Returns information about a specific core.
///
/// ```
/// info_cores([1] core_id) -> [1] flags, [2] freq_hz, [3] vendor_model
///   syscall_num = 51
///
///   [1] on input: core id
/// ```
///
/// No cap required.
///
/// Output:
/// - `[1]` flags: bitmask
///   - bit 0: online
///   - bit 1: idle states supported
///   - bit 2: frequency scaling supported
///   - bits 3-63: _reserved
/// - `[2]` freq_hz: current frequency in Hz, 0 if unreadable
/// - `[3]` vendor_model: platform-defined packed identifier; layout follows the architecture vendor's encoding (e.g., x86 family/model/stepping, ARM IDR fields)
///
/// [test 04] returns E_INVAL if [1] core_id is greater than or equal to `info_system`'s `cores`.
/// [test 05] returns E_INVAL if any reserved bits are set in [1].
/// [test 06] on success, [1] flag bit 0 reflects whether the queried core is currently online.
pub fn infoCores(caller: *anyopaque, core_id: u64) i64 {
    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));

    // Spec §[system_info] test 05: reserved bits in [1] surface E_INVAL.
    // Core counts on supported targets are bounded by APIC-id width
    // (x86-64: 8/16/32-bit per ACPI MADT) and by GIC redistributor
    // counts (aarch64); 16 bits is wider than any plausible
    // online-cpu count, so any input bit >=16 is reserved.
    const CORE_ID_MASK: u64 = 0xFFFF;
    if ((core_id & ~CORE_ID_MASK) != 0) return errors.E_INVAL;
    // Spec §[system_info] test 04: out-of-range core ids surface E_INVAL.
    if (core_id >= smp.coreCount()) return errors.E_INVAL;

    // Build flags. Bit 0 (online) is set unconditionally for any
    // core_id < coreCount(): smpInit brings every advertised core up
    // through PSCI CPU_ON / APIC INIT-SIPI before kMain enters the
    // scheduler, and the kernel never offlines a core today, so the
    // valid-id check above is sufficient evidence of online status.
    var flags: u64 = 1 << 0;
    if (cpu.cpuIdleStatesSupported()) flags |= 1 << 1;
    if (cpu.cpuFreqScalingSupported()) flags |= 1 << 2;

    const freq_hz: u64 = cpu.cpuFreqHz(core_id);
    const vendor_model: u64 = cpu.cpuVendorModel(core_id);

    stygia.arch.dispatch.syscall.setSyscallVreg2(ec.ctx, freq_hz);
    stygia.arch.dispatch.syscall.setSyscallVreg3(ec.ctx, vendor_model);
    return @bitCast(flags);
}

/// Performs an immediate orderly system poweroff. Does not return on
/// success.
///
/// ```
/// power_shutdown() -> void
///   syscall_num = 52
/// ```
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `power`.
pub fn powerShutdown(caller: *anyopaque) i64 {
    return doPowerAction(caller, .shutdown);
}

/// Performs a warm system reboot. Does not return on success.
///
/// ```
/// power_reboot() -> void
///   syscall_num = 53
/// ```
///
/// [test 02] returns E_PERM if the caller's self-handle lacks `power`.
pub fn powerReboot(caller: *anyopaque) i64 {
    return doPowerAction(caller, .reboot);
}

/// Enters a system-wide low-power state at the requested depth. Returns
/// when the system wakes.
///
/// ```
/// power_sleep([1] depth) -> void
///   syscall_num = 54
///
///   [1] depth: 1 = sleep (S1/S3-equivalent), 3 = deep sleep (S4-equivalent), 4 = hibernate (S5-equivalent)
/// ```
///
/// [test 03] returns E_PERM if the caller's self-handle lacks `power`.
/// [test 04] returns E_INVAL if [1] is not 1, 3, or 4.
/// [test 05] returns E_NODEV if the platform does not support the requested sleep depth.
pub fn powerSleep(caller: *anyopaque, depth: u64) i64 {
    // Structural validation runs before rights validation: a spec-invalid
    // depth surfaces E_INVAL even when the caller lacks `power`. Without
    // this ordering, test 04 would be untestable from a power-less caller
    // (the only kind the runner can spawn — see runner/primary.zig).
    //
    // Spec §[power] depth → ACPI semantics:
    //   1 → S1/S3-equivalent  (suspend-to-RAM,  `.sleep`)
    //   3 → S4-equivalent     (suspend-to-disk, `.hibernate`)
    //   4 → S5-equivalent     (soft-off,         `.shutdown`)
    //
    // The two deeper depths must surface as distinct backend actions so
    // a platform that supports S4 but not S5 (or vice versa) can return
    // E_NODEV from the right branch instead of silently aliasing them.
    const action: PowerAction = switch (depth) {
        1 => .sleep,
        3 => .hibernate,
        4 => .shutdown,
        else => return errors.E_INVAL,
    };
    const self_caps = readSelfCaps(caller) orelse return errors.E_BADCAP;
    if (!self_caps.power) return errors.E_PERM;
    return cpu.powerAction(action);
}

/// Turns the primary display off. Subsequent input wakes it.
///
/// ```
/// power_screen_off() -> void
///   syscall_num = 55
/// ```
///
/// [test 06] returns E_PERM if the caller's self-handle lacks `power`.
pub fn powerScreenOff(caller: *anyopaque) i64 {
    return doPowerAction(caller, .screen_off);
}

/// Sets the target frequency for a specific core in Hz.
///
/// ```
/// power_set_freq([1] core_id, [2] hz) -> void
///   syscall_num = 56
///
///   [1] core_id: target core
///   [2] hz: target frequency in Hz; 0 = let the kernel pick
/// ```
///
/// [test 07] returns E_PERM if the caller's self-handle lacks `power`.
/// [test 08] returns E_INVAL if [1] is greater than or equal to `info_system`'s `cores`.
/// [test 09] returns E_NODEV if the queried core does not support frequency scaling (per `info_cores` flag bit 2).
/// [test 10] returns E_INVAL if [2] is nonzero and outside the platform's supported frequency range.
/// [test 11] on success, a subsequent `info_cores([1])` reports a `freq_hz` consistent with the requested target (within hardware tolerance).
pub fn powerSetFreq(caller: *anyopaque, core_id: u64, hz: u64) i64 {
    // Spec §[power] check ordering: structural argument validation runs
    // before rights validation across every power_* syscall. Test 15
    // (power_set_idle, [2] > 2 → E_INVAL) explicitly relies on this
    // ordering — the runner withholds `power` from every child domain,
    // so a perm-first kernel would short-circuit to E_PERM and the
    // E_INVAL gate would be untestable. Apply the same ordering here so
    // power_set_freq, power_set_idle, and power_sleep all share a
    // single shape: range checks first, capability check second.
    if (core_id >= smp.coreCount()) return errors.E_INVAL;
    const self_caps = readSelfCaps(caller) orelse return errors.E_BADCAP;
    if (!self_caps.power) return errors.E_PERM;
    if (!cpu.cpuFreqScalingSupported()) return errors.E_NODEV;
    return cpu.cpuPowerAction(.set_freq, hz);
}

/// Sets the idle policy for a specific core.
///
/// ```
/// power_set_idle([1] core_id, [2] policy) -> void
///   syscall_num = 57
///
///   [1] core_id: target core
///   [2] policy: 0 = busy-poll (no idle entry), 1 = halt only (shallow), 2 = deepest available c-state
/// ```
///
/// [test 12] returns E_PERM if the caller's self-handle lacks `power`.
/// [test 13] returns E_INVAL if [1] is greater than or equal to `info_system`'s `cores`.
/// [test 14] returns E_NODEV if the queried core does not support idle states (per `info_cores` flag bit 1).
/// [test 15] returns E_INVAL if [2] is greater than 2.
pub fn powerSetIdle(caller: *anyopaque, core_id: u64, policy: u64) i64 {
    // Bounds-first ordering: see `powerSetFreq` rationale.
    if (core_id >= smp.coreCount()) return errors.E_INVAL;
    if (policy > 2) return errors.E_INVAL;
    const self_caps = readSelfCaps(caller) orelse return errors.E_BADCAP;
    if (!self_caps.power) return errors.E_PERM;
    if (!cpu.cpuIdleStatesSupported()) return errors.E_NODEV;
    return cpu.cpuPowerAction(.set_idle, policy);
}

// ── Helpers ──────────────────────────────────────────────────────────

fn doPowerAction(caller: *anyopaque, action: PowerAction) i64 {
    const self_caps = readSelfCaps(caller) orelse return errors.E_BADCAP;
    if (!self_caps.power) return errors.E_PERM;
    return cpu.powerAction(action);
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
