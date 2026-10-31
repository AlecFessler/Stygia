const stygia = @import("stygia");

const capability = stygia.caps.capability;
const process_mod = stygia.caps.process;
const errors = stygia.syscall.errors;
const thread_mod = stygia.sched.thread;

const ProcessCaps = process_mod.ProcessCaps;
const Thread = thread_mod.Thread;
const Word0 = capability.Word0;

/// `caps` argument: self-cap bit 7 is reserved; bits 16-23 carry idc_rx;
/// bits 24-63 are reserved.
const CREATE_CAPS_MASK: u64 = 0x0000_0000_00FF_FF7F;

/// Self-handle is always slot 0 in the calling process. Spec §[process].
const SELF_HANDLE_SLOT: u12 = 0;

/// Per-handle entry mask in `passed_handles`: bits 0-11 (handle id), 16-31
/// (caps), 32 (move). Bits 12-15 and 33-63 are reserved per spec.
const PASSED_HANDLE_MASK: u64 = 0x0000_0001_FFFF_0FFF;

/// Creates a new process from an ELF image carried in a page
/// frame. The caller receives back an IDC handle to the new process.
///
/// ```
/// create_process([1] caps, [2] ceilings_inner, [3] ceilings_outer, [4] elf_page_frame, [5] initial_thread_affinity, [6+] passed_handles)
///   -> [1] idc_handle
///   syscall_num = 4
///
///   [1] caps: u64 packed as
///     bits  0-15: self_caps          — caps on the new process's slot-0 self-handle
///     bits 16-23: idc_rx             — new process's idc_rx (see §[process] Self handle)
///     bits 24-63: _reserved
///
///   [2] ceilings_inner: u64 packed as (matches self-handle field0)
///     bits  0-7:  thread_inner_ceiling
///     bits  8-23: vmar_inner_ceiling:
///                    bit  8:     move
///                    bit  9:     copy
///                    bits 10-12: r/w/x
///                    bit 13:     mmio
///                    bits 14-15: max_sz (enum)
///                    bit 16:     dma
///                    bits 17-23: _reserved
///     bits 24-31: cridc_ceiling      — new process's cridc_ceiling (see §[process] Self handle)
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
///     bits  0-7: thread_outer_ceiling
///     bits  8-15: vmar_outer_ceiling
///     bits 16-31: restart_policy_ceiling:
///                    bits 16-17: thread_restart_max     (kill / restart_at_entry / persist / _reserved)
///                    bits 18-19: vmar_restart_max    (free / decommit / preserve / snapshot)
///                    bit 20:     pf_restart_max     (drop / keep)
///                    bit 21:     dr_restart_max     (drop / keep)
///                    bit 22:     port_restart_max   (drop / keep)
///                    bit 23:     vm_restart_max     (drop / keep)
///                    bit 24:     idc_restart_max    (drop / keep)
///                    bits 25-31: _reserved
///     bits 32-37: fut_wait_max         — max addresses per `futex_wait_*` call (0..63); 0 disables futex wait
///     bits 38-63: _reserved
///
///   [4] elf_page_frame: page frame handle containing the ELF image from offset 0
///
///   [5] initial_thread_affinity: u64 core mask for the new process's initial thread.
///       Same encoding as `create_thread` `[6] affinity`.
///       0 = any core (kernel chooses).
///
///   [6+] passed_handles: each entry is a u64 packed as
///     bits  0-11: handle id (12-bit handle in the caller's table)
///     bits 12-15: _reserved
///     bits 16-31: caps to install on the handle inserted into the new process
///     bit     32: move (1 = remove from caller; 0 = copy, both retain)
///     bits 33-63: _reserved
/// ```
///
/// Self-handle cap required: `crproc`.
///
/// The ELF image is read from `elf_page_frame` starting at byte 0. The
/// pointer to the new process's read-only view of its capability table is
/// passed as the first argument to the initial thread's entry point.
///
/// The caller receives an IDC handle to the new process with caps = the
/// caller's own `cridc_ceiling`. The new process's slot-2 self-IDC handle
/// is minted with caps = the `cridc_ceiling` passed in [2]. The new
/// process's slot-1 initial-thread handle is minted with caps = the new
/// process's `thread_inner_ceiling` from [2].
///
/// Returns E_NOMEM if insufficient kernel memory; returns E_FULL if the
/// caller's handle table has no free slot for the returned IDC handle.
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `crproc`.
/// [test 02] returns E_PERM if `self_caps` is not a subset of the caller's self-handle caps.
/// [test 03] returns E_PERM if `thread_inner_ceiling` is not a subset of the caller's `thread_inner_ceiling`.
/// [test 04] returns E_PERM if `thread_outer_ceiling` is not a subset of the caller's `thread_outer_ceiling`.
/// [test 05] returns E_PERM if `vmar_inner_ceiling` is not a subset of the caller's `vmar_inner_ceiling`.
/// [test 06] returns E_PERM if `vmar_outer_ceiling` is not a subset of the caller's `vmar_outer_ceiling`.
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
/// [test 19] on success, the caller receives an IDC handle to the new process with caps = the caller's `cridc_ceiling`.
/// [test 20] on success, the new process's handle table contains the self-handle at slot 0 with caps = `self_caps`.
/// [test 21] on success, the new process's handle table contains the initial thread at slot 1 with caps = the `thread_inner_ceiling` supplied in [2].
/// [test 22] on success, the new process's handle table contains an IDC handle to itself at slot 2 with caps = the passed `cridc_ceiling`.
/// [test 23] on success, passed handles occupy slots 3+ of the new process's handle table in the order supplied, each with the caps specified in its entry.
/// [test 24] a passed handle entry with `move = 1` is removed from the caller's handle table after the call.
/// [test 25] a passed handle entry with `move = 0` remains in the caller's handle table after the call.
/// [test 26] on success, the new process's `thread_inner_ceiling`, `vmar_inner_ceiling`, `cridc_ceiling`, `idc_rx`, `pf_ceiling`, `vm_ceiling`, and `port_ceiling` in field0 are set to the values supplied in [2] and [1].
/// [test 27] on success, the new process's `thread_outer_ceiling` and `vmar_outer_ceiling` in field1 are set to the values supplied in [3].
/// [test 28] on success, the new process's `idc_rx` in field0 is set to the value supplied in [1].
/// [test 29] the initial thread begins executing at the entry point declared in the ELF header.
/// [test 31] on success, the new process's initial thread has affinity equal to `[5]`.
/// [test 32] returns E_INVAL if `[5]` has bits set outside the system's core count.
pub fn createProcess(
    caller: *anyopaque,
    caps: u64,
    ceilings_inner: u64,
    ceilings_outer: u64,
    elf_pf_slot: u64,
    initial_thread_affinity: u64,
    passed_handles: []const u64,
) i64 {
    if (caps & ~CREATE_CAPS_MASK != 0) return errors.E_INVAL;
    if (elf_pf_slot & ~@as(u64, capability.HANDLE_ARG_MASK) != 0) return errors.E_INVAL;
    // Spec §[create_process]: passed_handles uses an all-zero
    // entry as end-of-list sentinel (matches the convention the kernel
    // caps layer follows). The aarch64 SVC ABI passes vregs 1..31 in
    // x0..x30, so trailing reserved-vreg slots above the caller's last
    // populated entry contain whatever the user-side syscall asm left
    // in those GPRs. Stop reserved-bit validation at the first zero.
    for (passed_handles) |entry| {
        if (entry == 0) break;
        if (entry & ~PASSED_HANDLE_MASK != 0) return errors.E_INVAL;
    }

    const thread: *Thread = @ptrCast(@alignCast(caller));
    const process_ref = thread.process;
    const lr = process_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const process = lr.ptr;
    const irq_state = lr.irq_state;

    // CRCD lives in the self-handle's cap word at slot 0. Lock the
    // process just long enough to read the cap and validate the elf
    // handle resolves; the heavy lifting (ceiling-subset checks, ELF
    // load, table mint) happens in caps under its own locking.
    const self_caps_word = Word0.caps(process.user_table[SELF_HANDLE_SLOT].word0);
    const self_caps: ProcessCaps = @bitCast(self_caps_word);
    if (!self_caps.crproc) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }

    // Spec §[create_process] test 02: requested self_caps
    // (bits 0-15 of [1]) must be a bitwise subset of the caller's
    // current self-handle caps. Otherwise the call would let a process
    // mint a child with rights it doesn't itself hold, breaking the
    // monotonic-rights invariant.
    const requested_self_caps: u16 = @truncate(caps & 0xFFFF);
    if (requested_self_caps & ~self_caps_word != 0) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }

    // Spec §[create_process] test 07: every field in
    // `restart_policy_ceiling` (bits 16-31 of [3]) must be ≤ the
    // caller's corresponding field on its self-handle field1. The
    // sub-field is partitioned per the syscall doc above:
    //   bits 16-17 thread_restart_max   (2-bit numeric, 0..3)
    //   bits 18-19 vmar_restart_max  (2-bit numeric, 0..3)
    //   bit 20     pf_restart_max   (bool)
    //   bit 21     dr_restart_max   (bool)
    //   bit 22     port_restart_max (bool)
    //   bit 23     vm_restart_max   (bool)
    //   bit 24     idc_restart_max  (bool)
    //   bits 25-31 _reserved
    // For numeric fields "exceeds" means a strict numeric greater-than;
    // for bool fields it reduces to the bitwise-superset case (a 1-bit
    // requested value with the caller's bit clear). Reserved bit
    // violations belong to test 17 (E_INVAL) and are out of scope here.
    const caller_field1 = process.user_table[SELF_HANDLE_SLOT].field1;
    const caller_rpc: u16 = @truncate((caller_field1 >> 16) & 0xFFFF);
    const requested_rpc: u16 = @truncate((ceilings_outer >> 16) & 0xFFFF);
    const caller_thread_rmax: u2 = @truncate(caller_rpc & 0x3);
    const requested_thread_rmax: u2 = @truncate(requested_rpc & 0x3);
    const caller_vmar_rmax: u2 = @truncate((caller_rpc >> 2) & 0x3);
    const requested_vmar_rmax: u2 = @truncate((requested_rpc >> 2) & 0x3);
    if (requested_rpc & ~@as(u16, 0x01FF) != 0) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_INVAL;
    }
    const caller_bools: u8 = @truncate((caller_rpc >> 4) & 0x1F);
    const requested_bools: u8 = @truncate((requested_rpc >> 4) & 0x1F);
    if (requested_thread_rmax > caller_thread_rmax or
        requested_vmar_rmax > caller_vmar_rmax or
        (requested_bools & ~caller_bools) != 0)
    {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }

    // Spec §[create_process] tests 03/05/06/08/09/10/11/12:
    // every ceiling field requested in [2]/[3] must be a bitwise subset
    // (or numeric ≤ for the fut_wait_max counter) of the caller's
    // corresponding self-handle field. Layout note: [2] ceilings_inner
    // is the syscall-arg shape (pf/vm/port live at bits 32-55), while
    // self-handle field0 inserts idc_rx at bits 32-39 and shifts pf/vm/
    // port up by 8 bits to land at 40-63. The reads below hit the
    // field0 offsets per spec §[process] field0 layout.
    // Reserved-bit violations belong to test 17 (E_INVAL) and are
    // separate from the subset rule.
    const caller_field0 = process.user_table[SELF_HANDLE_SLOT].field0;

    // [test 03] thread_inner_ceiling: [2] bits 0-7 ⊆ field0 bits 0-7.
    const caller_thread_inner_ceiling: u8 = @truncate(caller_field0 & 0xFF);
    const requested_thread_inner_ceiling: u8 = @truncate(ceilings_inner & 0xFF);
    if (requested_thread_inner_ceiling & ~caller_thread_inner_ceiling != 0) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }

    // [test 05] vmar_inner_ceiling: [2] bits 8-23 ⊆ field0 bits 8-23.
    const caller_vmar_inner_ceiling: u16 = @truncate((caller_field0 >> 8) & 0xFFFF);
    const requested_vmar_inner_ceiling: u16 = @truncate((ceilings_inner >> 8) & 0xFFFF);
    if (requested_vmar_inner_ceiling & ~caller_vmar_inner_ceiling != 0) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }

    // [test 09] cridc_ceiling: [2] bits 24-31 ⊆ field0 bits 24-31.
    const caller_cridc_ceiling: u8 = @truncate((caller_field0 >> 24) & 0xFF);
    const requested_cridc_ceiling: u8 = @truncate((ceilings_inner >> 24) & 0xFF);
    if (requested_cridc_ceiling & ~caller_cridc_ceiling != 0) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }

    // [test 10] pf_ceiling: [2] bits 32-39 ⊆ field0 bits 40-47.
    const caller_pf_ceiling: u8 = @truncate((caller_field0 >> 40) & 0xFF);
    const requested_pf_ceiling: u8 = @truncate((ceilings_inner >> 32) & 0xFF);
    if (requested_pf_ceiling & ~caller_pf_ceiling != 0) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }

    // [test 11] vm_ceiling: [2] bits 40-47 ⊆ field0 bits 48-55.
    const caller_vm_ceiling: u8 = @truncate((caller_field0 >> 48) & 0xFF);
    const requested_vm_ceiling: u8 = @truncate((ceilings_inner >> 40) & 0xFF);
    if (requested_vm_ceiling & ~caller_vm_ceiling != 0) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }

    // [test 12] port_ceiling: [2] bits 48-55 ⊆ field0 bits 56-63.
    const caller_port_ceiling: u8 = @truncate((caller_field0 >> 56) & 0xFF);
    const requested_port_ceiling: u8 = @truncate((ceilings_inner >> 48) & 0xFF);
    if (requested_port_ceiling & ~caller_port_ceiling != 0) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }

    // [test 04] thread_outer_ceiling: [3] bits 0-7 ⊆ field1 bits 0-7.
    // [test 06] vmar_outer_ceiling: [3] bits 8-15 ⊆ field1 bits 8-15.
    // [test 08] fut_wait_max: [3] bits 32-37 ≤ field1 bits 32-37 (numeric).
    const caller_thread_outer_ceiling: u8 = @truncate(caller_field1 & 0xFF);
    const requested_thread_outer_ceiling: u8 = @truncate(ceilings_outer & 0xFF);
    if (requested_thread_outer_ceiling & ~caller_thread_outer_ceiling != 0) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }
    const caller_vmar_outer_ceiling: u8 = @truncate((caller_field1 >> 8) & 0xFF);
    const requested_vmar_outer_ceiling: u8 = @truncate((ceilings_outer >> 8) & 0xFF);
    if (requested_vmar_outer_ceiling & ~caller_vmar_outer_ceiling != 0) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }
    const caller_fut_wait_max: u6 = @truncate((caller_field1 >> 32) & 0x3F);
    const requested_fut_wait_max: u6 = @truncate((ceilings_outer >> 32) & 0x3F);
    if (requested_fut_wait_max > caller_fut_wait_max) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }

    const elf_slot: u12 = @truncate(elf_pf_slot);
    if (capability.resolveHandleOnProcess(process, elf_slot, .page_frame) == null) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_BADCAP;
    }

    // Spec §[create_process] test 14: every entry in
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
        if (capability.resolveHandleOnProcess(process, src_slot, null) == null) {
            process_ref.unlockIrqRestore(irq_state);
            return errors.E_BADCAP;
        }
    }

    process_ref.unlockIrqRestore(irq_state);

    return process_mod.createProcess(
        thread,
        caps,
        ceilings_inner,
        ceilings_outer,
        elf_pf_slot,
        initial_thread_affinity,
        passed_handles,
    );
}
