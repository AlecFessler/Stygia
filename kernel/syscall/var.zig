const zag = @import("zag");

const capability = zag.caps.capability;
const errors = zag.syscall.errors;
const var_range = zag.memory.var_range;

const CapabilityDomainCaps = zag.caps.capability_domain.CapabilityDomainCaps;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const Word0 = capability.Word0;

/// Self-handle slot. Spec §[capability_domain]: slot 0 is reserved for
/// the domain's self-handle and carries the per-domain caps the kernel
/// gates the create_* syscalls on.
const SELF_HANDLE_SLOT: u12 = 0;

/// Reserved-bit masks for `create_var` arguments. Spec §[var].create_var
/// returns E_INVAL when bits outside the documented fields are set.
const CREATE_VAR_CAPS_MASK: u64 = 0xFFFF;
const CREATE_VAR_PROPS_MASK: u64 = 0x7F;

/// Reserved-bit masks for handle args carried in slot-id form (bits 0-11).
const HANDLE_ARG_MASK: u64 = 0xFFF;

/// Reserved-bit mask for `remap`'s new_cur_rwx (bits 0-2 only).
const REMAP_RWX_MASK: u64 = 0x7;

/// Maximum qwords transferable per `idc_read` / `idc_write`. Spec §[var]
/// caps the syscall word's count subfield at 125 to fit the available
/// vreg payload window.
const IDC_QWORDS_MAX: u64 = 125;

/// Reserves a range of virtual address space bound to the caller's
/// domain.
///
/// ```
/// create_var([1] caps, [2] props, [3] pages, [4] preferred_base, [5] device_region) -> [1] handle
///   syscall_num = 17
///
///   [1] caps: u64 packed as
///     bits  0-15: caps        — caps on the VAR handle returned to the caller
///     bits 16-63: _reserved
///
///   [2] props: u64 packed as
///     bits 0-2: cur_rwx       — initial current rwx
///     bits 3-4: sz            — page size (immutable; must be 0 when caps.mmio = 1)
///     bits 5-6: cch           — cache type (immutable)
///     bits 7-63: _reserved
///
///   [3] pages:          number of `sz` pages to reserve
///   [4] preferred_base: 0 = kernel chooses
///   [5] device_region:  device_region handle to bind for the IOMMU mapping
///                       (required when caps.dma = 1; ignored otherwise)
/// ```
///
/// Self-handle cap required: `crvr`.
///
/// Returns E_NOMEM if insufficient kernel memory; returns E_NOSPC if the
/// address space has no room for the requested range; returns E_FULL if
/// the caller's handle table has no free slot.
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `crvr`.
/// [test 02] returns E_PERM if caps' r/w/x bits are not a subset of the caller's `var_inner_ceiling`'s r/w/x bits.
/// [test 03] returns E_PERM if caps.max_sz exceeds the caller's `var_inner_ceiling`'s max_sz.
/// [test 04] returns E_PERM if caps.mmio = 1 and the caller's `var_inner_ceiling` does not permit mmio.
/// [test 05] returns E_INVAL if [3] pages is 0.
/// [test 06] returns E_INVAL if [4] preferred_base is nonzero and not aligned to the page size encoded in props.sz.
/// [test 07] returns E_INVAL if caps.max_sz is 3 (reserved).
/// [test 08] returns E_INVAL if caps.mmio = 1 and props.sz != 0.
/// [test 09] returns E_INVAL if props.sz is 3 (reserved).
/// [test 10] returns E_INVAL if props.sz exceeds caps.max_sz.
/// [test 11] returns E_INVAL if caps.mmio = 1 and caps.x is set.
/// [test 12] returns E_INVAL if caps.dma = 1 and caps.x is set.
/// [test 13] returns E_INVAL if caps.mmio = 1 and caps.dma = 1.
/// [test 14] returns E_BADCAP if caps.dma = 1 and [5] is not a valid device_region handle.
/// [test 15] returns E_PERM if caps.dma = 1 and [5] does not have the `dma` cap.
/// [test 16] returns E_INVAL if props.cur_rwx is not a subset of caps.r/w/x.
/// [test 17] returns E_INVAL if any reserved bits are set in [1] or [2].
/// [test 18] on success, the caller receives a VAR handle with caps = `[1].caps`.
/// [test 19] on success, field0 contains the assigned base address.
/// [test 20] on success, field1 contains `[2].props` together with `[3]` pages.
/// [test 21] on success, when [4] preferred_base is nonzero and the range is available, the assigned base address equals `[4]`.
/// [test 22] on success, when caps.dma = 1, field1's `device` field equals [5]'s handle id, and a subsequent `map_pf` into this VAR routes the bound device's accesses at field0 + offset to the installed page_frame.
pub fn createVar(
    caller: *anyopaque,
    caps: u64,
    props: u64,
    pages: u64,
    preferred_base: u64,
    device_region: u64,
) i64 {
    if (caps & ~CREATE_VAR_CAPS_MASK != 0) return errors.E_INVAL;
    if (props & ~CREATE_VAR_PROPS_MASK != 0) return errors.E_INVAL;
    // device_region's reserved bits are only meaningful when caps.dma=1
    // (spec: "ignored otherwise"); var_range.createVar gates that based
    // on the decoded caps word.

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    const self_caps: CapabilityDomainCaps = @bitCast(Word0.caps(cd.user_table[SELF_HANDLE_SLOT].word0));
    cd_ref.unlockIrqRestore(lr.irq_state);

    // Spec §[create_var] test 01: caller's self-handle must carry `crvr`.
    if (!self_caps.crvr) return errors.E_PERM;

    return var_range.createVar(ec, caps, props, pages, preferred_base, device_region);
}

/// Installs page_frames into a regular or DMA-flagged VAR. The kernel
/// dispatches based on `caps.dma`:
/// - Regular VAR (`caps.dma = 0`): pages are mapped into the CPU's
///   virtual address space at `VAR.base + offset`.
/// - DMA VAR (`caps.dma = 1`): pages are mapped into the bound device's
///   IOMMU page tables at `VAR.base + offset` (an IOVA).
///
/// ```
/// map_pf([1] var, [2 + 2i] offset, [2 + 2i + 1] page_frame) -> void
///   syscall_num = 18
///
///   syscall word bits 12-19: N (number of (offset, page_frame) pairs)
///
///   [1] var: VAR handle
///   [2 + 2i] offset: byte offset within the VAR
///   [2 + 2i + 1] page_frame: page_frame handle to install at that offset
///
///   for i in 0..N-1.
/// ```
///
/// [test 01] returns E_BADCAP if [1] is not a valid VAR handle.
/// [test 02] returns E_BADCAP if any [2 + 2i + 1] is not a valid page_frame handle.
/// [test 03] returns E_PERM if [1].caps has `mmio` set (mmio VARs accept only `map_mmio`).
/// [test 04] returns E_INVAL if N is 0.
/// [test 05] returns E_INVAL if any offset is not aligned to the VAR's `sz` page size.
/// [test 06] returns E_INVAL if any page_frame's `sz` is smaller than the VAR's `sz`.
/// [test 07] returns E_INVAL if any pair's range exceeds the VAR's size.
/// [test 08] returns E_INVAL if any two pairs' ranges overlap.
/// [test 09] returns E_INVAL if any pair's range overlaps an existing mapping in the VAR.
/// [test 10] returns E_INVAL if [1].field1 `map` is 2 (mmio) or 3 (demand) — pf installation requires `map = 0` or `map = 1`.
/// [test 11] on success, [1].field1 `map` becomes 1 if it was 0; otherwise stays 1.
/// [test 12] on success, when [1].caps.dma = 0, CPU accesses to `VAR.base + offset` use effective permissions = `VAR.cur_rwx` ∩ `page_frame.r/w/x` per page.
/// [test 13] on success, when [1].caps.dma = 1, a DMA read by the bound device from `VAR.base + offset` returns the installed page_frame's contents, and a DMA access whose access type is not in `VAR.cur_rwx` ∩ `page_frame.r/w/x` is rejected by the IOMMU rather than reaching the page_frame.
/// [test 14] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn mapPf(caller: *anyopaque, var_handle: u64, pairs: []const u64) i64 {
    if (var_handle & ~HANDLE_ARG_MASK != 0) return errors.E_INVAL;
    // Pairs slice always carries a (offset, page_frame) tuple per i — odd
    // length means the dispatcher mis-parsed N from the syscall word.
    if (pairs.len % 2 != 0) return errors.E_INVAL;
    if (pairs.len == 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    return var_range.mapPf(ec, var_handle, pairs);
}

/// Installs a device_region as an MMIO mapping into an MMIO-flagged VAR.
///
/// ```
/// map_mmio([1] var, [2] device_region) -> void
///   syscall_num = 19
///
///   [1] var: VAR handle (must have `mmio` cap)
///   [2] device_region: device_region handle
/// ```
///
/// VAR cap required on [1]: `mmio`.
///
/// [test 01] returns E_BADCAP if [1] is not a valid VAR handle.
/// [test 02] returns E_BADCAP if [2] is not a valid device_region handle.
/// [test 03] returns E_PERM if [1] does not have the `mmio` cap.
/// [test 04] returns E_INVAL if [1].field1 `map` is not 0 (mmio mappings are atomic; the VAR must be unmapped).
/// [test 05] returns E_INVAL if [2]'s size does not equal [1]'s size.
/// [test 06] on success, [1].field1 `map` becomes 2.
/// [test 07] on success, [1].field1 `device` is set to [2]'s handle id.
/// [test 08] on success, CPU accesses to the VAR's range use effective permissions = `VAR.cur_rwx`.
/// [test 09] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn mapMmio(caller: *anyopaque, var_handle: u64, device_region: u64) i64 {
    if (var_handle & ~HANDLE_ARG_MASK != 0) return errors.E_INVAL;
    if (device_region & ~HANDLE_ARG_MASK != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    return var_range.mapMmio(ec, var_handle, device_region);
}

/// Removes mappings from a VAR. Dispatches on the VAR's `map` field. With
/// `N = 0`, unmaps everything; with `N > 0`, the selectors specify which
/// mappings to remove and depend on `map`.
///
/// ```
/// unmap([1] var, [2..N+1] selectors) -> void
///   syscall_num = 20
///
///   syscall word bits 12-19: N (number of selectors; 0 = unmap everything)
///
///   [1] var: VAR handle
///   [2..N+1] selectors:
///     - map = 1 (pf):     page_frame handles to unmap
///     - map = 3 (demand): byte offsets into the VAR
///     - map = 2 (mmio):   N must be 0
/// ```
///
/// [test 01] returns E_BADCAP if [1] is not a valid VAR handle.
/// [test 02] returns E_INVAL if [1].field1 `map` is 0 (nothing to unmap).
/// [test 03] returns E_INVAL if [1].field1 `map` is 2 (mmio) and N > 0.
/// [test 04] returns E_BADCAP if [1].field1 `map` is 1 and any selector is not a valid page_frame handle.
/// [test 05] returns E_NOENT if [1].field1 `map` is 1 and any page_frame selector is not currently installed in [1].
/// [test 06] returns E_INVAL if [1].field1 `map` is 3 and any offset selector is not aligned to [1]'s `sz`.
/// [test 07] returns E_NOENT if [1].field1 `map` is 3 and no demand-allocated page exists at any offset selector.
/// [test 08] on success, when N is 0, all installations or demand-allocated pages are removed and `map` is set to 0.
/// [test 09] on success, when N is 0 and `map` was 2, the device_region installation is removed and `device` is cleared to 0.
/// [test 10] on success, when N > 0 and `map` is 1, only the specified page_frames are removed; `map` stays 1 unless every installed page_frame has been removed, in which case it becomes 0.
/// [test 11] on success, when N > 0 and `map` is 3, only the pages at the specified offsets are freed; `map` stays 3 unless every demand-allocated page has been freed, in which case it becomes 0.
/// [test 12] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn unmap(caller: *anyopaque, var_handle: u64, selectors: []const u64) i64 {
    if (var_handle & ~HANDLE_ARG_MASK != 0) return errors.E_INVAL;

    // Selectors are either page_frame handles (map=1) or byte offsets
    // (map=3); validation depends on the VAR's current map type, which
    // only var_range can read under _gen_lock. Forward without per-element
    // checks here.
    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    return var_range.unmap(ec, var_handle, selectors);
}

/// Updates a VAR's `cur_rwx`, changing the effective permissions on its
/// currently-mapped pages. Applies to pf and demand mappings only.
///
/// ```
/// remap([1] var, [2] new_cur_rwx) -> void
///   syscall_num = 21
///
///   [1] var: VAR handle
///   [2] new_cur_rwx: u64 packed as
///     bits 0-2: new r/w/x
///     bits 3-63: _reserved
/// ```
///
/// [test 01] returns E_BADCAP if [1] is not a valid VAR handle.
/// [test 02] returns E_INVAL if [1].field1 `map` is 0 or 2 (no pf or demand mapping to remap).
/// [test 03] returns E_INVAL if [2] new_cur_rwx is not a subset of [1]'s caps r/w/x.
/// [test 04] returns E_INVAL if [1].field1 `map` is 1 and [2] new_cur_rwx is not a subset of the intersection of all installed page_frames' r/w/x caps.
/// [test 05] returns E_INVAL if [1].caps.dma = 1 and [2] new_cur_rwx has bit 2 (x) set.
/// [test 06] returns E_INVAL if any reserved bits are set in [2].
/// [test 07] on success, [1].field1 `cur_rwx` is set to [2] new_cur_rwx.
/// [test 08] on success, subsequent accesses to mapped pages use effective permissions = `cur_rwx` ∩ `page_frame.r/w/x` (for map=1) or `cur_rwx` (for map=3).
/// [test 09] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn remap(caller: *anyopaque, var_handle: u64, new_cur_rwx: u64) i64 {
    if (var_handle & ~HANDLE_ARG_MASK != 0) return errors.E_INVAL;
    if (new_cur_rwx & ~REMAP_RWX_MASK != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    return var_range.remap(ec, var_handle, new_cur_rwx);
}

/// Binds a source VAR to a target VAR. On the owning domain's restart,
/// the kernel copies the source's contents into the target before the
/// domain resumes. Used together with `restart_policy = snapshot` on the
/// target VAR — see §[restart_semantics].
///
/// ```
/// snapshot([1] target_var, [2] source_var) -> void
///   syscall_num = 22
///
///   [1] target_var: VAR handle (must have `caps.restart_policy = snapshot` (3))
///   [2] source_var: VAR handle (must have `caps.restart_policy = preserve` (2))
/// ```
///
/// Calling `snapshot` again replaces any prior binding for `[1]`.
///
/// At restart time, the source-to-target copy succeeds only if the source
/// is stable:
/// - For `[2].field1.map = 1` (page_frame-backed): every backing
///   page_frame has `field1.mapcnt = 1` AND the source's effective write
///   permission is 0 (`[2].field1.cur_rwx` write bit ∩ each page_frame's
///   `caps.w` is 0).
/// - For `[2].field1.map = 3` (demand-paged): the source's `cur_rwx.w =
///   0`. Demand-paged pages are kernel-allocated and not exposed
///   elsewhere, so `mapcnt = 1` is implicit.
///
/// If the source's stability cannot be verified at restart, the restart
/// fails and the domain is terminated.
///
/// [test 01] returns E_BADCAP if [1] is not a valid VAR handle.
/// [test 02] returns E_BADCAP if [2] is not a valid VAR handle.
/// [test 03] returns E_INVAL if [1].caps.restart_policy is not 3 (snapshot).
/// [test 04] returns E_INVAL if [2].caps.restart_policy is not 2 (preserve).
/// [test 05] returns E_INVAL if [1] and [2] have different sizes (`page_count` × `sz`).
/// [test 06] returns E_INVAL if any reserved bits are set in [1] or [2].
/// [test 07] calling `snapshot` a second time on the same target replaces the prior source binding.
/// [test 08] if the source [2] is deleted before restart, the binding is cleared; on restart with no source bound, the domain is terminated rather than restarted.
/// [test 09] on domain restart, when the source's stability constraints hold, [1]'s contents are replaced by a copy of [2]'s contents before the domain resumes.
/// [test 10] on domain restart, when [2].map = 1 and any backing page_frame has `mapcnt > 1` or the source's effective write permission is nonzero, the restart fails and the domain is terminated.
/// [test 11] on domain restart, when [2].map = 3 and `[2].cur_rwx.w = 1`, the restart fails and the domain is terminated.
pub fn snapshot(caller: *anyopaque, target_var: u64, source_var: u64) i64 {
    if (target_var & ~HANDLE_ARG_MASK != 0) return errors.E_INVAL;
    if (source_var & ~HANDLE_ARG_MASK != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    return var_range.snapshot(ec, target_var, source_var);
}

/// Reads qwords from a VAR into the caller's vregs. Used for cross-domain
/// memory inspection (e.g., debugger reads of an acquired VAR's
/// contents). The kernel pauses every EC in the VAR's owning domain for
/// the duration of the call so the read returns a consistent snapshot;
/// this is intended as a debugger primitive, not a performance path.
///
/// ```
/// idc_read([1] var, [2] offset) -> [3..2+count] qwords
///   syscall_num = 23
///
///   syscall word bits 12-19: count (number of qwords; max 125)
///
///   [1] var:    VAR handle
///   [2] offset: byte offset within the VAR (must be 8-byte aligned)
/// ```
///
/// VAR cap required on [1]: `r`.
///
/// [test 01] returns E_BADCAP if [1] is not a valid VAR handle.
/// [test 02] returns E_PERM if [1] does not have the `r` cap.
/// [test 03] returns E_INVAL if [2] offset is not 8-byte aligned.
/// [test 04] returns E_INVAL if count is 0 or count > 125.
/// [test 05] returns E_INVAL if [2] + count*8 exceeds the VAR's size.
/// [test 06] returns E_INVAL if any reserved bits are set in [1] or [2].
/// [test 07] on success, vregs `[3..2+count]` contain the qwords from the VAR starting at [2] offset.
/// [test 08] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn idcRead(caller: *anyopaque, var_handle: u64, offset: u64, count: u8) i64 {
    if (var_handle & ~HANDLE_ARG_MASK != 0) return errors.E_INVAL;
    // Offset must be 8-byte aligned per spec [test 03].
    if (offset & 0x7 != 0) return errors.E_INVAL;
    if (count == 0) return errors.E_INVAL;
    if (count > IDC_QWORDS_MAX) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    return var_range.idcRead(ec, var_handle, offset, count);
}

/// Writes qwords from the caller's vregs into a VAR. Used for
/// cross-domain memory writes (e.g., debugger writes of an acquired VAR's
/// contents). The kernel pauses every EC in the VAR's owning domain for
/// the duration of the call so the write commits without observable
/// interleaving; this is intended as a debugger primitive, not a
/// performance path.
///
/// ```
/// idc_write([1] var, [2] offset, [3..2+count] qwords) -> void
///   syscall_num = 24
///
///   syscall word bits 12-19: count (number of qwords; max 125)
///
///   [1] var:    VAR handle
///   [2] offset: byte offset within the VAR (must be 8-byte aligned)
///   [3..2+count] qwords: bytes to write into the VAR
/// ```
///
/// VAR cap required on [1]: `w`.
///
/// [test 01] returns E_BADCAP if [1] is not a valid VAR handle.
/// [test 02] returns E_PERM if [1] does not have the `w` cap.
/// [test 03] returns E_INVAL if [2] offset is not 8-byte aligned.
/// [test 04] returns E_INVAL if count is 0 or count > 125.
/// [test 05] returns E_INVAL if [2] + count*8 exceeds the VAR's size.
/// [test 06] returns E_INVAL if any reserved bits are set in [1] or [2].
/// [test 07] on success, the qwords from vregs `[3..2+count]` are written into the VAR starting at [2] offset.
/// [test 08] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn idcWrite(caller: *anyopaque, var_handle: u64, offset: u64, count: u8, qwords: []const u64) i64 {
    if (var_handle & ~HANDLE_ARG_MASK != 0) return errors.E_INVAL;
    if (offset & 0x7 != 0) return errors.E_INVAL;
    // The raw count comes straight from the syscall word so we can gate
    // count > 125 even though the args slice tops out at the 13-vreg
    // register window. The qwords slice carries only the payload that
    // was actually delivered (≤ 11 register-vreg qwords today).
    if (count == 0) return errors.E_INVAL;
    if (count > IDC_QWORDS_MAX) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    return var_range.idcWrite(ec, var_handle, offset, count, qwords);
}
