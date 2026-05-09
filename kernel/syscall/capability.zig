const stygia = @import("stygia");

const capability = stygia.caps.capability;
const errors = stygia.syscall.errors;

const HANDLE_MASK: u64 = 0xFFF;
const CAPS_MASK: u64 = 0xFFFF;

/// Reduces the caps on a handle in place. The new caps must be a subset of
/// the current caps. No self-handle cap is required — reducing authority
/// never requires authority.
///
/// ```
/// restrict([1] handle, [2] caps) -> void
///   syscall_num = 0
///
///   [1] handle: handle in the caller's table (bits 0-11; upper bits _reserved)
///   [2] caps: u64 packed as
///     bits  0-15: new caps
///     bits 16-63: _reserved
/// ```
///
/// Most cap fields use bitwise subset semantics: a bit set in `[2].caps`
/// must also be set in the handle's current caps. The `restart_policy`
/// field on EC handles (bits 8-9) and VMAR handles (bits 9-10) is a 2-bit
/// enum ordered by privilege (lowest privilege = numeric 0); for these
/// fields "reducing" means the new numeric value is less than or equal to
/// the current value, not bitwise subset.
///
/// [test 01] returns E_BADCAP if [1] is not a valid handle.
/// [test 02] returns E_PERM if any cap field in [2].caps using bitwise semantics has a bit set that is not set in the handle's current caps.
/// [test 03] returns E_PERM if the handle is an EC handle and [2].caps' `restart_policy` (bits 8-9) numeric value exceeds the handle's current `restart_policy`.
/// [test 04] returns E_PERM if the handle is a VMAR handle and [2].caps' `restart_policy` (bits 9-10) numeric value exceeds the handle's current `restart_policy`.
/// [test 05] returns E_INVAL if any reserved bits are set in [1] or [2].
/// [test 06] on success, the handle's caps field equals [2].caps.
/// [test 07] on success, syscalls gated by caps cleared by restrict return E_PERM when invoked via this handle.
pub fn restrict(caller: *anyopaque, handle: u64, caps: u64) i64 {
    if (handle & ~HANDLE_MASK != 0) return errors.E_INVAL;
    if (caps & ~CAPS_MASK != 0) return errors.E_INVAL;
    return capability.restrict(caller, handle, caps);
}

/// Releases a handle from the calling domain's handle table. Type-specific
/// side effects apply.
///
/// ```
/// delete([1] handle) -> void
///   syscall_num = 1
///
///   [1] handle: handle in the caller's table (bits 0-11; upper bits _reserved)
/// ```
///
/// No self-handle cap required.
///
/// | Handle type | Observable delete behavior |
/// |---|---|
/// | `capability_domain_self` | The calling domain is cleaned up; each handle in its table is released with its type-specific delete behavior applied |
/// | `capability_domain` (IDC) | Release handle. Domain has system lifetime; it does not terminate when IDC handles drop |
/// | `execution_context` | Release handle. ECs have capability-domain lifetime; they are not destroyed by handle drops |
/// | `page_frame` | Release handle. When the last handle to a page frame is released, the physical memory returns to the free pool |
/// | `virtual_memory_address_region` | Non-transferable; exactly one handle exists. Delete unmaps everything installed, frees the address range, releases the handle |
/// | `device_region` | Release handle. When the last handle to a device region is released, the region returns to the root service |
/// | `port` | Decrement the send refcount if this handle has `bind`; decrement the recv refcount if this handle has `recv`. When the recv refcount hits zero, suspended senders resume with `E_CLOSED`. When the send refcount hits zero and no event routes target the port, receivers suspended on the port resume with `E_CLOSED`. Release handle |
/// | `reply` | If the suspended sender is still waiting, resume them with `E_ABANDONED`. Release handle |
/// | `virtual_machine` | Non-transferable; exactly one handle exists. Destroy the VM: all vCPU ECs terminate, guest memory is freed, kernel-emulated LAPIC/IOAPIC/timer state is torn down. Release handle |
/// | `timer` | Release handle. When the last handle to the timer is released, the kernel cancels the timer if armed and reclaims its kernel state |
///
/// [test 01] returns E_BADCAP if [1] is not a valid handle.
/// [test 02] returns E_INVAL if any reserved bits are set in [1].
/// [test 03] on success, the handle is released and subsequent operations on it return E_BADCAP.
pub fn delete(caller: *anyopaque, handle: u64) i64 {
    if (handle & ~HANDLE_MASK != 0) return errors.E_INVAL;
    return capability.delete(caller, handle);
}

/// Releases every handle transitively derived from the target via `copy`,
/// across all capability domains. The target handle itself is not
/// released — use `delete` for that.
///
/// ```
/// revoke([1] handle) -> void
///   syscall_num = 2
///
///   [1] handle: handle in the caller's table (bits 0-11; upper bits _reserved)
/// ```
///
/// No self-handle cap required.
///
/// A handle that was copied from the target and then subsequently moved is
/// still a derivation of the target — moving a handle keeps it on the copy
/// ancestry chain rather than orphaning it. A domain that has moved a
/// handle elsewhere no longer holds it and cannot revoke it; whoever holds
/// the copy ancestor still can, and the revoke will reach the moved
/// descendant through the preserved chain.
///
/// Each released descendant is processed with the type-specific behavior
/// defined for `delete`.
///
/// [test 01] returns E_BADCAP if [1] is not a valid handle.
/// [test 02] returns E_INVAL if any reserved bits are set in [1].
/// [test 03] on success, every handle transitively derived via copy from [1] is released from its holder with the type-specific delete behavior applied.
/// [test 04] a handle that was copied from [1] and then subsequently moved is released by revoke([1]).
/// [test 05] revoke([1]) does not release [1] itself.
/// [test 06] revoke([1]) does not release any handle on the copy ancestor side of [1].
pub fn revoke(caller: *anyopaque, handle: u64) i64 {
    if (handle & ~HANDLE_MASK != 0) return errors.E_INVAL;
    return capability.revoke(caller, handle);
}

/// Refreshes a handle's kernel-mutable field0/field1 snapshot. No-op for
/// handles whose state does not drift.
///
/// ```
/// sync([1] handle) -> void
///   syscall_num = 3
///
///   [1] handle: handle in the caller's table
/// ```
///
/// [test 01] returns E_BADCAP if [1] is not a valid handle.
/// [test 02] returns E_INVAL if any reserved bits are set in [1].
/// [test 03] on success, [1]'s field0 and field1 reflect the authoritative kernel state at the moment of the call.
pub fn sync(caller: *anyopaque, handle: u64) i64 {
    if (handle & ~HANDLE_MASK != 0) return errors.E_INVAL;
    return capability.sync(caller, handle);
}
