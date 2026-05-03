const zag = @import("zag");

const capability = zag.caps.capability;
const capability_domain = zag.caps.capability_domain;
const errors = zag.syscall.errors;
const execution_context = zag.sched.execution_context;

const CapabilityDomainCaps = capability_domain.CapabilityDomainCaps;
const ExecutionContext = execution_context.ExecutionContext;
const IdcCaps = capability_domain.IdcCaps;
const Word0 = capability.Word0;

/// `caps` argument: bits 0-23 valid (self_caps + idc_rx); bits 24-63 reserved.
const CREATE_CAPS_MASK: u64 = 0x0000_0000_00FF_FFFF;

/// Self-handle is always slot 0 in the calling domain. Spec §[capability_domain].
const SELF_HANDLE_SLOT: u12 = 0;

/// Per-handle entry mask in `passed_handles`: bits 0-11 (handle id), 16-31
/// (caps), 32 (move). Bits 12-15 and 33-63 are reserved per spec.
const PASSED_HANDLE_MASK: u64 = 0x0000_0001_FFFF_0FFF;

/// Creates a new capability domain from an ELF image carried in a page
/// frame. The caller receives back an IDC handle to the new domain.
///
/// ```
/// create_capability_domain([1] caps, [2] ceilings_inner, [3] ceilings_outer, [4] elf_page_frame, [5] initial_ec_affinity, [6+] passed_handles)
///   -> [1] idc_handle
///   syscall_num = 4
///
///   [1] caps: u64 packed as
///     bits  0-15: self_caps          — caps on the new domain's slot-0 self-handle
///     bits 16-23: idc_rx             — new domain's idc_rx (see §[capability_domain] Self handle)
///     bits 24-63: _reserved
///
///   [2] ceilings_inner: u64 packed as (matches self-handle field0)
///     bits  0-7:  ec_inner_ceiling
///     bits  8-23: var_inner_ceiling:
///                    bit  8:     move
///                    bit  9:     copy
///                    bits 10-12: r/w/x
///                    bit 13:     mmio
///                    bits 14-15: max_sz (enum)
///                    bit 16:     dma
///                    bits 17-23: _reserved
///     bits 24-31: cridc_ceiling      — new domain's cridc_ceiling (see §[capability_domain] Self handle)
///     bits 32-39: pf_ceiling:
///                    bits 32-34: max_rwx (r/w/x)
///                    bits 35-36: max_sz (enum)
///                    bits 37-39: _reserved
///     bits 40-47: vm_ceiling:
///                    bit 40:     policy
///                    bits 41-47: _reserved
///     bits 48-55: port_ceiling:
///                    bit 50:     xfer
///                    bit 51:     recv
///                    bit 52:     bind
///                    bits 48-49, 53-55: _reserved
///     bits 56-63: _reserved
///
///   [3] ceilings_outer: u64 packed as (matches self-handle field1)
///     bits  0-7: ec_outer_ceiling
///     bits  8-15: var_outer_ceiling
///     bits 16-31: restart_policy_ceiling:
///                    bits 16-17: ec_restart_max     (kill / restart_at_entry / persist / _reserved)
///                    bits 18-19: var_restart_max    (free / decommit / preserve / snapshot)
///                    bit 20:     pf_restart_max     (drop / keep)
///                    bit 21:     dr_restart_max     (drop / keep)
///                    bit 22:     port_restart_max   (drop / keep)
///                    bit 23:     vm_restart_max     (drop / keep)
///                    bit 24:     idc_restart_max    (drop / keep)
///                    bit 25:     tm_restart_max     (drop / keep)
///                    bits 26-31: _reserved
///     bits 32-37: fut_wait_max         — max addresses per `futex_wait_*` call (0..63); 0 disables futex wait
///     bits 38-63: _reserved
///
///   [4] elf_page_frame: page frame handle containing the ELF image from offset 0
///
///   [5] initial_ec_affinity: u64 core mask for the new domain's initial EC.
///       Same encoding as `create_execution_context` `[6] affinity`.
///       0 = any core (kernel chooses).
///
///   [6+] passed_handles: each entry is a u64 packed as
///     bits  0-11: handle id (12-bit handle in the caller's table)
///     bits 12-15: _reserved
///     bits 16-31: caps to install on the handle inserted into the new domain
///     bit     32: move (1 = remove from caller; 0 = copy, both retain)
///     bits 33-63: _reserved
/// ```
///
/// Self-handle cap required: `crcd`.
///
/// The ELF image is read from `elf_page_frame` starting at byte 0. The
/// pointer to the new domain's read-only view of its capability table is
/// passed as the first argument to the initial EC's entry point.
///
/// The caller receives an IDC handle to the new domain with caps = the
/// caller's own `cridc_ceiling`. The new domain's slot-2 self-IDC handle
/// is minted with caps = the `cridc_ceiling` passed in [2]. The new
/// domain's slot-1 initial-EC handle is minted with caps = the new
/// domain's `ec_inner_ceiling` from [2].
///
/// Returns E_NOMEM if insufficient kernel memory; returns E_FULL if the
/// caller's handle table has no free slot for the returned IDC handle.
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `crcd`.
/// [test 02] returns E_PERM if `self_caps` is not a subset of the caller's self-handle caps.
/// [test 03] returns E_PERM if `ec_inner_ceiling` is not a subset of the caller's `ec_inner_ceiling`.
/// [test 04] returns E_PERM if `ec_outer_ceiling` is not a subset of the caller's `ec_outer_ceiling`.
/// [test 05] returns E_PERM if `var_inner_ceiling` is not a subset of the caller's `var_inner_ceiling`.
/// [test 06] returns E_PERM if `var_outer_ceiling` is not a subset of the caller's `var_outer_ceiling`.
/// [test 07] returns E_PERM if any field in `restart_policy_ceiling` exceeds the caller's corresponding field.
/// [test 08] returns E_PERM if `fut_wait_max` exceeds the caller's `fut_wait_max`.
/// [test 09] returns E_PERM if `cridc_ceiling` is not a subset of the caller's `cridc_ceiling`.
/// [test 10] returns E_PERM if `pf_ceiling` is not a subset of the caller's `pf_ceiling`.
/// [test 11] returns E_PERM if `vm_ceiling` is not a subset of the caller's `vm_ceiling`.
/// [test 12] returns E_PERM if `port_ceiling` is not a subset of the caller's `port_ceiling`.
/// [test 13] returns E_BADCAP if `elf_page_frame` is not a valid page frame handle.
/// [test 14] returns E_BADCAP if any passed handle id is not a valid handle in the caller's table.
/// [test 15] returns E_INVAL if the ELF header is malformed.
/// [test 16] returns E_INVAL if `elf_page_frame` is smaller than the declared ELF image size.
/// [test 17] returns E_INVAL if any reserved bits are set in [1], [2], or a passed handle entry.
/// [test 18] returns E_INVAL if any two entries in [6+] reference the same source handle.
/// [test 19] on success, the caller receives an IDC handle to the new domain with caps = the caller's `cridc_ceiling`.
/// [test 20] on success, the new domain's handle table contains the self-handle at slot 0 with caps = `self_caps`.
/// [test 21] on success, the new domain's handle table contains the initial EC at slot 1 with caps = the `ec_inner_ceiling` supplied in [2].
/// [test 22] on success, the new domain's handle table contains an IDC handle to itself at slot 2 with caps = the passed `cridc_ceiling`.
/// [test 23] on success, passed handles occupy slots 3+ of the new domain's handle table in the order supplied, each with the caps specified in its entry.
/// [test 24] a passed handle entry with `move = 1` is removed from the caller's handle table after the call.
/// [test 25] a passed handle entry with `move = 0` remains in the caller's handle table after the call.
/// [test 26] on success, the new domain's `ec_inner_ceiling`, `var_inner_ceiling`, `cridc_ceiling`, `idc_rx`, `pf_ceiling`, `vm_ceiling`, and `port_ceiling` in field0 are set to the values supplied in [2] and [1].
/// [test 27] on success, the new domain's `ec_outer_ceiling` and `var_outer_ceiling` in field1 are set to the values supplied in [3].
/// [test 28] on success, the new domain's `idc_rx` in field0 is set to the value supplied in [1].
/// [test 29] the initial EC begins executing at the entry point declared in the ELF header.
/// [test 31] on success, the new domain's initial EC has affinity equal to `[5]`.
/// [test 32] returns E_INVAL if `[5]` has bits set outside the system's core count.
pub fn createCapabilityDomain(
    caller: *anyopaque,
    caps: u64,
    ceilings_inner: u64,
    ceilings_outer: u64,
    elf_pf_slot: u64,
    initial_ec_affinity: u64,
    passed_handles: []const u64,
) i64 {
    if (caps & ~CREATE_CAPS_MASK != 0) return errors.E_INVAL;
    if (elf_pf_slot & ~@as(u64, capability.HANDLE_ARG_MASK) != 0) return errors.E_INVAL;
    // Spec §[create_capability_domain]: passed_handles uses an all-zero
    // entry as end-of-list sentinel (matches the convention the kernel
    // caps layer follows). The aarch64 SVC ABI passes vregs 1..31 in
    // x0..x30, so trailing reserved-vreg slots above the caller's last
    // populated entry contain whatever the user-side syscall asm left
    // in those GPRs. Stop reserved-bit validation at the first zero.
    for (passed_handles) |entry| {
        if (entry == 0) break;
        if (entry & ~PASSED_HANDLE_MASK != 0) return errors.E_INVAL;
    }

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    const irq_state = lr.irq_state;

    // CRCD lives in the self-handle's cap word at slot 0. Lock the
    // domain just long enough to read the cap and validate the elf
    // handle resolves; the heavy lifting (ceiling-subset checks, ELF
    // load, table mint) happens in caps under its own locking.
    const self_caps_word = Word0.caps(cd.user_table[SELF_HANDLE_SLOT].word0);
    const self_caps: CapabilityDomainCaps = @bitCast(self_caps_word);
    if (!self_caps.crcd) {
        cd_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }

    // Spec §[create_capability_domain] test 02: requested self_caps
    // (bits 0-15 of [1]) must be a bitwise subset of the caller's
    // current self-handle caps. Otherwise the call would let a domain
    // mint a child with rights it doesn't itself hold, breaking the
    // monotonic-rights invariant.
    const requested_self_caps: u16 = @truncate(caps & 0xFFFF);
    if (requested_self_caps & ~self_caps_word != 0) {
        cd_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }

    // Spec §[create_capability_domain] test 07: every field in
    // `restart_policy_ceiling` (bits 16-31 of [3]) must be ≤ the
    // caller's corresponding field on its self-handle field1. The
    // sub-field is partitioned per the syscall doc above:
    //   bits 16-17 ec_restart_max   (2-bit numeric, 0..3)
    //   bits 18-19 var_restart_max  (2-bit numeric, 0..3)
    //   bit 20     pf_restart_max   (bool)
    //   bit 21     dr_restart_max   (bool)
    //   bit 22     port_restart_max (bool)
    //   bit 23     vm_restart_max   (bool)
    //   bit 24     idc_restart_max  (bool)
    //   bit 25     tm_restart_max   (bool)
    //   bits 26-31 _reserved
    // For numeric fields "exceeds" means a strict numeric greater-than;
    // for bool fields it reduces to the bitwise-superset case (a 1-bit
    // requested value with the caller's bit clear). Reserved bit
    // violations belong to test 17 (E_INVAL) and are out of scope here.
    const caller_field1 = cd.user_table[SELF_HANDLE_SLOT].field1;
    const caller_rpc: u16 = @truncate((caller_field1 >> 16) & 0xFFFF);
    const requested_rpc: u16 = @truncate((ceilings_outer >> 16) & 0xFFFF);
    const caller_ec_rmax: u2 = @truncate(caller_rpc & 0x3);
    const requested_ec_rmax: u2 = @truncate(requested_rpc & 0x3);
    const caller_var_rmax: u2 = @truncate((caller_rpc >> 2) & 0x3);
    const requested_var_rmax: u2 = @truncate((requested_rpc >> 2) & 0x3);
    const caller_bools: u8 = @truncate((caller_rpc >> 4) & 0x3F);
    const requested_bools: u8 = @truncate((requested_rpc >> 4) & 0x3F);
    if (requested_ec_rmax > caller_ec_rmax or
        requested_var_rmax > caller_var_rmax or
        (requested_bools & ~caller_bools) != 0)
    {
        cd_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }

    // Spec §[create_capability_domain] test 12: requested `port_ceiling`
    // (bits 48-55 of [2]) must be a bitwise subset of the caller's own
    // `port_ceiling` on its self-handle field0 (bits 56-63 — shifted
    // up by 8 from the [2] layout to make room for idc_rx at bits
    // 32-39 in field0). Otherwise the new domain could mint port
    // handles with caps the parent doesn't itself hold, breaking the
    // monotonic-rights invariant. Reserved bit violations (sub-field
    // bits 0-1, 5-7) belong to test 17 (E_INVAL) and are out of scope here.
    const caller_field0 = cd.user_table[SELF_HANDLE_SLOT].field0;
    const caller_port_ceiling: u8 = @truncate((caller_field0 >> 56) & 0xFF);
    const requested_port_ceiling: u8 = @truncate((ceilings_inner >> 48) & 0xFF);
    if (requested_port_ceiling & ~caller_port_ceiling != 0) {
        cd_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }

    const elf_slot: u12 = @truncate(elf_pf_slot);
    if (capability.resolveHandleOnDomain(cd, elf_slot, .page_frame) == null) {
        cd_ref.unlockIrqRestore(irq_state);
        return errors.E_BADCAP;
    }

    // Spec §[create_capability_domain] test 14: every entry in
    // `passed_handles` must reference a slot that holds a valid handle
    // in the caller's table. This check fires BEFORE the ELF parse
    // (test 15 / 16) per the spec test ordering — userspace can pre-
    // validate its source slots without having to also stage a valid
    // ELF image. The all-zero entry sentinel mirrors caps's
    // convention: an entry of 0 means "end of list" (no handle 0 has
    // caps=0 / move=0 — the canonical termination pattern).
    for (passed_handles) |entry| {
        if (entry == 0) break;
        const src_slot: u12 = @truncate(entry & 0xFFF);
        if (capability.resolveHandleOnDomain(cd, src_slot, null) == null) {
            cd_ref.unlockIrqRestore(irq_state);
            return errors.E_BADCAP;
        }
    }

    cd_ref.unlockIrqRestore(irq_state);

    return capability_domain.createCapabilityDomain(
        ec,
        caps,
        ceilings_inner,
        ceilings_outer,
        elf_pf_slot,
        initial_ec_affinity,
        passed_handles,
    );
}

/// Returns handles to all non-vCPU execution contexts bound to the target
/// domain referenced by an IDC handle.
///
/// ```
/// acquire_ecs([1] target) -> [1..N] handles
///   syscall_num = 5
///
///   syscall word bits 12-19: count (set by the kernel on return; 0 on entry)
///
///   [1] target: IDC handle
/// ```
///
/// IDC cap required on [1]: `aqec`.
///
/// Each returned handle has caps = `target.ec_outer_ceiling` ∩
/// `target.ec_cap_ceiling` of the IDC handle in [1]. The kernel sets the
/// syscall word's count field to N, the number of handles returned, and
/// writes them to vregs `[1..N]`.
///
/// Returns E_FULL if the caller's handle table cannot accommodate all
/// returned handles.
///
/// [test 01] returns E_BADCAP if [1] is not a valid IDC handle.
/// [test 02] returns E_PERM if [1] does not have the `aqec` cap.
/// [test 03] returns E_INVAL if any reserved bits are set in [1].
/// [test 04] returns E_FULL if the caller's handle table cannot accommodate all returned handles.
/// [test 05] on success, the syscall word's count field equals the number of non-vCPU ECs bound to the target domain.
/// [test 06] on success, vregs `[1..N]` contain handles in the caller's table referencing those ECs, each with caps = target's `ec_outer_ceiling` intersected with the IDC's `ec_cap_ceiling`.
/// [test 07] vCPUs in the target domain are not included in the returned handles.
pub fn acquireEcs(caller: *anyopaque, target: u64) i64 {
    return acquireDispatch(caller, target, .aqec);
}

/// Returns handles to all `map=1` (pf) and `map=3` (demand) VARs bound to
/// the target domain referenced by an IDC handle. MMIO and DMA VARs are
/// excluded.
///
/// ```
/// acquire_vars([1] target) -> [1..N] handles
///   syscall_num = 6
///
///   syscall word bits 12-19: count (set by the kernel on return; 0 on entry)
///
///   [1] target: IDC handle
/// ```
///
/// IDC cap required on [1]: `aqvr`.
///
/// Each returned handle has caps = `target.var_outer_ceiling` ∩ the IDC's
/// `var_cap_ceiling`. While in flight, all ECs in the target domain are
/// paused — `acquire_vars` and the resulting `idc_read`/`idc_write`
/// traffic is intended as a debugger primitive, not a performance path.
///
/// [test 01] returns E_BADCAP if [1] is not a valid IDC handle.
/// [test 02] returns E_PERM if [1] does not have the `aqvr` cap.
/// [test 03] returns E_INVAL if any reserved bits are set in [1].
/// [test 04] returns E_FULL if the caller's handle table cannot accommodate all returned handles.
/// [test 05] on success, the syscall word's count field equals the number of `map=1` and `map=3` VARs bound to the target domain.
/// [test 06] on success, vregs `[1..N]` contain handles in the caller's table referencing those VARs, each with caps = target's `var_outer_ceiling` intersected with the IDC's `var_cap_ceiling`.
/// [test 07] MMIO and DMA VARs in the target domain are not included in the returned handles.
pub fn acquireVars(caller: *anyopaque, target: u64) i64 {
    return acquireDispatch(caller, target, .aqvr);
}

/// IDC cap selector for `acquireDispatch`. Distinguishes which cap bit
/// gates the call (`aqec` for ECs, `aqvr` for VARs) and which caps
/// entry point handles enumeration.
const AcquireKind = enum { aqec, aqvr };

/// Shared trampoline body for `acquire_ecs` / `acquire_vars`. Both
/// validate the IDC handle, gate on the kind-specific cap bit, then
/// hand off to caps.
fn acquireDispatch(caller: *anyopaque, target: u64, kind: AcquireKind) i64 {
    if (target & ~@as(u64, capability.HANDLE_ARG_MASK) != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    const irq_state = lr.irq_state;

    const slot: u12 = @truncate(target);
    if (capability.resolveHandleOnDomain(cd, slot, .capability_domain) == null) {
        cd_ref.unlockIrqRestore(irq_state);
        return errors.E_BADCAP;
    }

    const idc_caps: IdcCaps = @bitCast(Word0.caps(cd.user_table[slot].word0));
    const has_cap = switch (kind) {
        .aqec => idc_caps.aqec,
        .aqvr => idc_caps.aqvr,
    };
    cd_ref.unlockIrqRestore(irq_state);
    if (!has_cap) return errors.E_PERM;

    return switch (kind) {
        .aqec => capability_domain.acquireEcs(ec, target),
        .aqvr => capability_domain.acquireVars(ec, target),
    };
}
