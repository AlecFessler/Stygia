const stygia = @import("stygia");

const page_frame = stygia.memory.page_frame;

/// Allocates physical memory and returns a page frame handle.
///
/// ```
/// create_page_frame([1] caps, [2] props, [3] pages) -> [1] handle
///   syscall_num = 25
///
///   [1] caps: u64 packed as
///     bits  0-15: caps        — caps on the page frame handle returned to the caller
///     bits 16-63: _reserved
///
///   [2] props: u64 packed as
///     bits  0-1: sz           — page size (immutable)
///     bits  2-63: _reserved
///
///   [3] pages: number of `sz` pages to allocate
/// ```
///
/// Self-handle cap required: `crpf`.
///
/// Returns E_NOMEM if insufficient physical memory; returns E_FULL if the
/// caller's handle table has no free slot.
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `crpf`.
/// [test 02] returns E_PERM if caps' r/w/x bits are not a subset of the caller's `pf_ceiling.max_rwx`.
/// [test 03] returns E_PERM if caps.max_sz exceeds the caller's `pf_ceiling.max_sz`.
/// [test 04] returns E_INVAL if [3] pages is 0.
/// [test 05] returns E_INVAL if caps.max_sz is 3 (reserved).
/// [test 06] returns E_INVAL if props.sz is 3 (reserved).
/// [test 07] returns E_INVAL if props.sz exceeds caps.max_sz.
/// [test 08] returns E_INVAL if any reserved bits are set in [1] or [2].
/// [test 09] on success, the caller receives a page frame handle with caps = `[1].caps`.
/// [test 10] on success, field0 contains `[3]` pages and `[2].props.sz`.
pub fn createPageFrame(caller: *anyopaque, caps: u64, props: u64, pages: u64) i64 {
    return page_frame.createPageFrame(caller, caps, props, pages);
}
