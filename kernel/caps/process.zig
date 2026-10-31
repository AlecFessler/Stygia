//! Process — set of capabilities usable by threads
//! bound to the process. See docs/kernel/specv3.md §[process].
//!
//! Owns:
//!   - Address space (page tables + PCID/ASID)
//!   - Two parallel handle tables (user-visible + kernel-side mirror)
//!   - Flat list of bound VARs
//!   - Optional bound VM
//!
//! All per-process ceilings (thread_inner/outer, var_inner/outer, cripc, ipc_rx,
//! pf, vm, port, restart_policy, fut_wait_max) live in the self-handle at
//! slot 0 of the handle table — kernel reads them from `user_table[0]`
//! like anyone else, no duplication on the struct.
//!
//! Threads bound to this process are reachable through the handle table (walk
//! looking for type = thread) and through whatever pins them
//! (run queue, port wait queue, etc.). No separate Threads array.
//!
//! STUB. Forward refs to VMAR and VirtualMachine point at intended future
//! paths.

const std = @import("std");
const stygia = @import("stygia");
const build_options = @import("build_options");

const arch = stygia.arch.dispatch;
const elf_util = stygia.utils.elf;
const errors = stygia.syscall.errors;
const thread_mod = stygia.sched.thread;
const pmm = stygia.memory.pmm;
const scheduler = stygia.sched.scheduler;
const userspace_init = stygia.boot.userspace_init;

const Capability = stygia.caps.capability.Capability;
const CapabilityType = stygia.caps.capability.CapabilityType;
const ErasedSlabRef = stygia.caps.capability.ErasedSlabRef;
const Thread = stygia.sched.thread.Thread;
const GenLock = stygia.memory.allocators.secure_slab.GenLock;
const KernelHandle = stygia.caps.capability.KernelHandle;
const PAddr = stygia.memory.address.PAddr;
const PageFrame = stygia.memory.page_frame.PageFrame;
const ParsedElf = stygia.utils.elf.ParsedElf;
const SecureSlab = stygia.memory.allocators.secure_slab.SecureSlab;
const SlabRef = stygia.memory.allocators.secure_slab.SlabRef;
const VMAR = stygia.memory.vmar.VMAR;
const VAddr = stygia.memory.address.VAddr;
const VirtualMachine = stygia.hv.virtual_machine.VirtualMachine;
const Word0 = stygia.caps.capability.Word0;

/// Cap bits in `Capability.word0[48..63]` for the process
/// self-handle (slot 0). Spec §[process] self handle.
pub const ProcessCaps = packed struct(u16) {
    crproc: bool = false,
    crec: bool = false,
    crvr: bool = false,
    crpf: bool = false,
    crvm: bool = false,
    crpt: bool = false,
    _reserved_6: u1 = 0,
    _reserved_7: u1 = 0,
    _reserved_8: u1 = 0,
    restart: bool = false,
    reply_policy: bool = false,
    fut_wake: bool = false,
    _reserved: u2 = 0,
    pri: u2 = 0,
};

/// Cap bits in `Capability.word0[48..63]` for IPC (process)
/// handles. Spec §[process] IPC handle.
pub const IpcCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    crec: bool = false,
    _reserved_3_4: u2 = 0,
    restart_policy: u1 = 0,
    _reserved: u10 = 0,
};

const MAX_HANDLES_PER_PROCESS = stygia.caps.capability.MAX_HANDLES_PER_PROCESS;
const FREE_LIST_TAIL = stygia.caps.capability.FREE_LIST_TAIL;

/// Start of the per-process VMAR bump-allocator range. Placed at 64 GiB
/// so it lives above the boot path's hand-mapped text/data/stack/
/// cap_table regions (which top out near 0x80000000) but inside the
/// 47-bit user half. v0 expedient — see `next_var_base` doc.
pub const NEXT_VAR_BASE_START: u64 = 0x0000_0010_0000_0000;

/// Maximum VARs bindable to a single process. 512 × 8 bytes
/// = 4 KiB inline. Coarse upper bound; well above realistic per-process
/// VMAR counts (a process with even a few dozen VARs is unusual).
pub const MAX_VARS_PER_PROCESS: u16 = 512;

pub const Process = struct {
    /// Slab generation lock. Validates `SlabRef(Process)`
    /// liveness AND guards every mutable field below.
    _gen_lock: GenLock = .{},

    /// Set while the restart owner has stopped dispatch into this address
    /// space. The process generation stays live so IPC handles and the
    /// handle table retain their identity across the restart.
    restarting: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// First exit/fault owner decides from the self-handle caps while the
    /// process lock serializes with restrict(SLOT_SELF). Reset only after a
    /// successful restart has finished its handle and thread policy pass.
    exit_decision: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),

    /// Original initial-thread entry ABI, needed if slot 1 is restarted.
    initial_stack_top: u64 = 0,
    initial_table_base: u64 = 0,

    // ── Address space ─────────────────────────────────────────────────

    /// Physical address of this process's top-level page table (PML4 on
    /// x86-64, TTBR on aarch64). Set at create; immutable.
    addr_space_root: PAddr,

    /// PCID (x86-64) / ASID (aarch64) tag. Set at create; immutable.
    /// Used as the low 12 bits of CR3 (with PCIDE=1) so address-space
    /// switches don't flush TLB entries from other processes.
    addr_space_id: u16,

    // ── Handle tables ────────────────────────────────────────────────
    //
    // Two parallel arrays of MAX_HANDLES_PER_PROCESS entries, indexed by
    // the same 12-bit handle id.
    //
    //   user_table   — 96 KiB. Mapped read-only into this process so
    //                  userspace can read cap word + field0/field1 of
    //                  any handle without a syscall. Kernel writes
    //                  field0/field1 to refresh kernel-mutable
    //                  snapshots (thread priority/affinity, VMAR cur_rwx,
    //                  device IRQ counters, etc.) directly through
    //                  the kernel R/W view of the same physical pages.
    //
    //   kernel_table — kernel-only. Holds ErasedSlabRef + revoke
    //                  ancestry tree links (parent / first_child /
    //                  next_sibling) when used, with `parent` doubling
    //                  as the free-slot list link when free.
    //
    // Pointer-based rather than inline so the process struct itself
    // stays slab-allocatable. Tables are page-aligned PMM allocations
    // made at create_process time.

    user_table: *[MAX_HANDLES_PER_PROCESS]Capability,
    kernel_table: *[MAX_HANDLES_PER_PROCESS]KernelHandle,

    /// Head of the free-slot list. `FREE_LIST_TAIL` (0xFFFF) when the
    /// table is full. Free entries store the next-free slot index in
    /// `kernel_table[i].parent.slot` (see `KernelHandle` doc), terminated
    /// by `FREE_LIST_TAIL`.
    free_head: u16 = FREE_LIST_TAIL,

    /// Number of free slots. Lets `copy`/`acquire_*` early-bail with
    /// `E_FULL` without walking the free list.
    free_count: u16 = MAX_HANDLES_PER_PROCESS,

    // ── Bound VARs ───────────────────────────────────────────────────

    /// Flat array of VARs bound to this process. Used for:
    ///   - VA-range overlap check at `create_vmar` (linear scan)
    ///   - Walk-and-free at process destroy
    /// Entries `[0..var_count)` are populated; entries beyond are null.
    /// On removal the tail is moved into the freed slot to keep the
    /// populated prefix dense (no holes to skip).
    vars: [MAX_VARS_PER_PROCESS]?SlabRef(VMAR) = .{null} ** MAX_VARS_PER_PROCESS,

    /// Number of populated entries in `vars`. Range 0..MAX_VARS_PER_PROCESS.
    var_count: u16 = 0,

    /// Bump pointer for VMAR base allocation when the caller passes
    /// `preferred_base = 0`. v0 sub-allocator: starts at 64 GiB (well
    /// above the ELF segment / stack / cap_table region used by the
    /// boot path) and grows upward. Spec §[var].create_vmar doesn't
    /// pin layout; this just needs to avoid colliding with other
    /// VARs and the boot-mapped text/stack/cap_table mappings that
    /// don't have backing VARs.
    next_var_base: u64 = NEXT_VAR_BASE_START,

    // ── Bound VM ─────────────────────────────────────────────────────

    /// VM bound to this process. Process lifetime; at most
    /// one per spec (the VM handle is non-transferable, exactly one
    /// holder = the binding process). `null` on non-VM processes.
    vm: ?SlabRef(VirtualMachine) = null,

    /// Backing of the eagerly-mapped user stack as one contiguous PMM
    /// buddy block. Set by `mapUserStack`; freed wholesale at process
    /// teardown so the buddy can rejoin a single 4 MiB block instead of
    /// fragmenting into 1024 single-page frees (which broke
    /// `pmm.allocBlock(USER_TABLE_BYTES)` after a few hundred reps when
    /// the test runner kept spawning new processes). 0 when the stack is
    /// not allocated yet (transient init state) or has already been
    /// freed. `freeUserAddrSpace` skips this range so the per-page walk
    /// doesn't double-free.
    user_stack_phys: u64 = 0,
    user_stack_bytes: u64 = 0,

    /// TEMP DIAGNOSTIC (Rawls x86 MISS attribution, REMOVE). Kernel-only
    /// test identity inferred from the child ELF. Does not touch cap
    /// words, handle metadata, affinity, or any user-visible ABI.
    diag_test_tag: u64 = 0,
    diag_elf_pf_slot: u12 = 0,
    diag_elf_pf_ptr: u64 = 0,
};

pub const Allocator = SecureSlab(Process, 256);
/// TEMP DIAGNOSTIC (stygia-2u0, REMOVE) — print budget for handle-table
/// exhaustion reports; see `allocFreeSlot`.
var slot_full_prints: u32 = 0;
const DIAG_TEST_TAG_MAGIC: u32 = 0x8000;
const DIAG_TEST_TAG_LIMIT: u32 = 0x9000;
const DIAG_TEST_TAG_COUNT: usize = DIAG_TEST_TAG_LIMIT - DIAG_TEST_TAG_MAGIC;
const SPAWN_CHILD_PRINT_BUDGET: u32 = 4096;
var spawn_child_prints: u32 = 0;

pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: stygia.utils.range.Range,
    ptrs_range: stygia.utils.range.Range,
    links_range: stygia.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

// ── External API ─────────────────────────────────────────────────────

/// `create_process` syscall handler.
/// Spec §[process].create_process.
///
/// v0 implementation focused on getting the test runner's spawnOne path
/// working end-to-end. Behavior:
///   1. Resolve `elf_pf` in the caller's table; bail E_BADCAP if missing.
///   2. Read ELF bytes from the page frame's kernel mapping (physmap VA).
///   3. allocProcess with self caps from `caps[0..15]` and the
///      passed ceilings_inner/outer.
///   4. loadElfSegments / mapUserStack / mapUserTableView from boot
///      reused — the child gets the ELF segments mapped at their
///      p_vaddr, a fresh user stack at ROOT_USER_STACK_TOP, and a
///      read-only view of the cap table at ROOT_USER_TABLE_BASE.
///   5. allocThread for the initial thread; patch its iret frame
///      so RDI = ROOT_USER_TABLE_BASE (per spec — the entry point's
///      first arg is a pointer to the read-only cap-table view).
///   6. For each entry in passed_handles[0..], derive into child slot
///      3+ via mintHandle. `move = 1` releases the source handle.
///   7. Mint the IPC handle into the caller's process pointing at the
///      new child; return its slot in vreg 1 / via i64.
///   8. Enqueue the initial thread for dispatch.
///
/// Spec validation tests 01-18 are NOT exhaustively enforced yet —
/// reserved-bit and ceiling-subset checks are coarse. The runner exercises
/// the success path; the per-test E_INVAL/E_PERM coverage lands once the
/// boot loop demonstrably runs assertions.
pub fn createProcess(
    caller: *Thread,
    caps: u64,
    ceilings_inner: u64,
    ceilings_outer: u64,
    elf_pf: u64,
    initial_thread_affinity: u64,
    passed_handles: []const u64,
) i64 {
    if (elf_pf & ~@as(u64, 0xFFF) != 0) return errors.E_INVAL;

    const caller_dom = caller.process.ptr; // caller-pinned: caller is the running thread; its process stays alive across this syscall

    // Resolve the ELF page frame in the caller's table. Spec §[14].
    const pf_slot: u12 = @truncate(elf_pf & 0xFFF);
    const pf: *PageFrame = blk: {
        const caller_lr = caller.process.lockIrqSave(@src()) catch return errors.E_BADCAP;
        defer caller.process.unlockIrqRestore(caller_lr.irq_state);
        const pf_kh = stygia.caps.capability.resolveHandleOnProcess(
            caller_lr.ptr,
            pf_slot,
            .page_frame,
        ) orelse return errors.E_BADCAP;
        const resolved_pf: *PageFrame = @ptrCast(@alignCast(pf_kh.ref.ptr.?));
        stygia.memory.page_frame.incHandleRef(resolved_pf) catch return errors.E_BADCAP;
        break :blk resolved_pf;
    };
    defer stygia.memory.page_frame.releaseHandle(pf);

    // Spec §[create_process] test 18: duplicate source slots in
    // passed_handles are structural E_INVAL inputs. Validate them before
    // parsing the ELF or minting/bumping any aliases, so early exits have
    // no partially-created child state to clean up.
    var seen_passed_slots: [MAX_HANDLES_PER_PROCESS]bool = .{false} ** MAX_HANDLES_PER_PROCESS;
    var validate_pass_idx: usize = 0;
    while (validate_pass_idx < passed_handles.len) : (validate_pass_idx += 1) {
        const entry = passed_handles[validate_pass_idx];
        if (entry == 0) break;

        const src_slot: u12 = @truncate(entry & 0xFFF);
        if (seen_passed_slots[src_slot]) return errors.E_INVAL;
        seen_passed_slots[src_slot] = true;
    }

    // Read the ELF bytes through the kernel physmap mapping of the page
    // frame's backing pages. The page frame's contents are contiguous in
    // physical memory (allocBlock returned a power-of-two block) so a
    // single physmap-VA pointer covers it.
    const pf_bytes_total: u64 = @as(u64, pf.page_count) * pageFrameSizeBytes(pf.sz);
    const pf_kernel_va = VAddr.fromPAddr(pf.phys_base, null).addr;
    const elf_bytes = @as([*]u8, @ptrFromInt(pf_kernel_va))[0..pf_bytes_total];

    var parsed: ParsedElf = undefined;
    elf_util.parseElf(&parsed, elf_bytes) catch return errors.E_INVAL;

    // Spec §[create_process] test 16a: ELF must be PIE
    // (e_type == ET_DYN) so the kernel can place it at a randomized
    // base in the ASLR zone (§[address_space]).
    if (parsed.e_type != @intFromEnum(std.elf.ET.DYN)) return errors.E_INVAL;

    // Spec §[address_space]: pick randomized non-overlapping bases
    // for the ELF image, the user stack, and the read-only cap-table
    // view. Each lives inside the ASLR zone.
    //   - ElfPhdrFileSizeExceeds → spec §[create_process]
    //     [test 16]: a PT_LOAD declares more file bytes than the
    //     staged page frame supplies. Surfaces as E_INVAL.
    //   - ElfHasNoLoadableSegments / parse errors are also INVAL inputs.
    //   - OutOfMemory (no slot in ASLR zone) is the only NOMEM here.
    const layout = userspace_init.resolveProcessLayout(elf_bytes) catch |err| switch (err) {
        error.OutOfMemory => return errors.E_NOMEM,
        else => return errors.E_INVAL,
    };
    const slid_entry = VAddr.fromInt(parsed.entry.addr + layout.elf_slide);
    const diag_test_tag = extractDiagTestTag(elf_bytes);

    // Allocate the child process. Self caps come from caps[0..15];
    // self-handle field0 layout differs from the [2] ceilings_inner shape —
    // §[process] Self handle puts ipc_rx at field0 bits 32-39,
    // sourced from [1] caps bits 16-23, with pf/vm/port ceilings shifted
    // up by 8 bits relative to ceilings_inner. See spec
    // §[create_process] doc for the [2] layout vs §[process]
    // for the field0 layout.
    const self_caps: u16 = @truncate(caps & 0xFFFF);
    const ipc_rx: u64 = (caps >> 16) & 0xFF;
    const thread_var_cripc: u64 = ceilings_inner & 0x0000_0000_FFFF_FFFF;
    const pf_vm_port: u64 = (ceilings_inner >> 32) & 0x0000_0000_00FF_FFFF;
    const self_field0: u64 = thread_var_cripc | (ipc_rx << 32) | (pf_vm_port << 40);
    const child_process = allocProcess(
        self_caps,
        self_field0,
        ceilings_outer,
        slid_entry,
    ) catch return errors.E_NOMEM;
    child_process.diag_test_tag = diag_test_tag;
    child_process.diag_elf_pf_slot = pf_slot;
    child_process.diag_elf_pf_ptr = @intFromPtr(pf);

    // Re-mirror kernel-half PML4 entries into the child's PML4 (per
    // boot's userspace_init — fresh L3/L2 paging structures the kernel
    // installs for its own data only land in the kernel root; without
    // this re-mirror the child's iret epilogue's stack pop faults on
    // the kernel stack VA).
    const child_root_virt = VAddr.fromPAddr(child_process.addr_space_root, null);
    stygia.arch.dispatch.paging.copyKernelMappings(child_root_virt);

    // Past this point, every error must tear `child_process` down. The process's
    // gen-lock is published-live (alloc returned successfully), so a
    // bare `return errors.E_NOMEM` without cleanup leaks the
    // user_table / kernel_table PMM blocks plus any Threads that were
    // allocated before the failing step. Spec-test runs that exercise
    // the failure paths in `loadElfSegments` / `mapUserStack` /
    // `allocThread` / `mintHandle` accumulated ~5 leaked processes
    // per rep before this teardown was added — slabs filled and the
    // 11th rep wedged at a later test batch once handle-table /
    // PCID exhaustion gated the next createPort.

    // Load ELF segments into the child's address space.
    userspace_init.loadElfSegments(child_process, elf_bytes, &parsed, layout.elf_slide) catch {
        cleanupPartiallyCreatedCd(child_process, null);
        return errors.E_NOMEM;
    };
    userspace_init.mapUserStack(child_process, layout.stack_top) catch {
        cleanupPartiallyCreatedCd(child_process, null);
        return errors.E_NOMEM;
    };
    userspace_init.mapUserTableView(child_process, layout.table_base) catch {
        cleanupPartiallyCreatedCd(child_process, null);
        return errors.E_NOMEM;
    };

    // Allocate the initial thread bound to the child process. Entry =
    // slid_entry; affinity from spec §[create_process] [5];
    // priority = normal.
    const child_thread = thread_mod.allocThread(
        child_process,
        slid_entry,
        16, // user stack pages — same as boot's root stack reservation
        initial_thread_affinity,
        .normal,
        null,
        null,
    ) catch {
        cleanupPartiallyCreatedCd(child_process, null);
        return errors.E_NOMEM;
    };
    child_thread.diag_test_tag = diag_test_tag;
    child_thread.diag_report_entered = false;
    child_process.initial_stack_top = layout.stack_top;
    child_process.initial_table_base = layout.table_base;

    // Patch the initial thread's iret frame for user-mode dispatch.
    stygia.arch.dispatch.cpu.patchUserModeIretFrame(
        child_thread.ctx,
        slid_entry,
        VAddr.fromInt(layout.stack_top),
        layout.table_base,
    );

    // Mint slot-1 thread handle in the child for the initial thread. Caps =
    // thread_inner_ceiling from ceilings_inner bits 0-7 per spec §[20].
    const thread_inner: u16 = @truncate(ceilings_inner & 0xFF);
    child_process.user_table[1].word0 = Word0.pack(1, .thread, thread_inner);
    child_process.user_table[1].field0 = 0;
    child_process.user_table[1].field1 = 0;
    child_process.kernel_table[1].ref = .{
        .ptr = child_thread,
        .gen = @intCast(child_thread._gen_lock.currentGen()),
    };
    child_process.kernel_table[1].parent = .{};
    child_process.kernel_table[1].first_child = .{};
    child_process.kernel_table[1].next_sibling = .{};

    // Process passed_handles into child slots 3+.
    //
    // SPEC AMBIGUITY: spec §[create_process] declares
    // `[5+] passed_handles` but does not encode a count anywhere
    // (no syscall-word count subfield, no terminator). The kernel
    // dispatcher hands us the full vreg-5..13 slice unconditionally.
    // Convention adopted here: an all-zero entry terminates the list.
    // The runner always passes a non-zero packed-entry (caps != 0 or
    // move != 0) for live entries, so this is unambiguous in practice.
    // Spec §[ipc_rx] test 01: IPC handles delivered into the new
    // child's table get caps ∩ child.ipc_rx. ipc_rx lives in the child
    // self-handle's field0 at bits 32-39 — already populated by
    // `allocProcess` from `[1] caps[16:24]` above.
    const child_ipc_rx: u16 = @truncate((child_process.user_table[0].field0 >> 32) & 0xFF);
    const DeriveRecord = struct {
        caller_ref: ErasedSlabRef,
        src_slot: u12,
        src_ref: ErasedSlabRef,
        src_type: CapabilityType,
        src_caps: u16,
        src_instance: u64,
        child_ref: ErasedSlabRef,
        child_slot: u12,
    };
    var moved_sources: [128]stygia.caps.derivation.ExpectedDelete = undefined;
    var moved_count: usize = 0;
    var derive_records: [128]DeriveRecord = undefined;
    var derive_count: usize = 0;
    var pass_idx: usize = 0;
    const caller_dom_ref = caller.process;
    const caller_ref: ErasedSlabRef = @bitCast(caller_dom_ref);
    const child_ref: ErasedSlabRef = .{
        .ptr = child_process,
        .gen = @intCast(child_process._gen_lock.currentGen()),
    };
    const caller_lr = caller_dom_ref.lockIrqSave(@src()) catch {
        cleanupPartiallyCreatedCd(child_process, child_thread);
        return errors.E_BADCAP;
    };
    const caller_irq_state = caller_lr.irq_state;
    while (pass_idx < passed_handles.len) {
        const entry = passed_handles[pass_idx];
        if (entry == 0) break;
        const src_slot: u12 = @truncate(entry & 0xFFF);
        const new_caps: u16 = @truncate((entry >> 16) & 0xFFFF);
        const move = ((entry >> 32) & 0x1) != 0;

        const src_kh = stygia.caps.capability.resolveHandleOnProcess(
            caller_dom,
            src_slot,
            null,
        ) orelse {
            caller_dom_ref.unlockIrqRestore(caller_irq_state);
            cleanupPartiallyCreatedCd(child_process, child_thread);
            return errors.E_BADCAP;
        };

        const src_user = caller_dom.user_table[src_slot];
        const src_type = Word0.typeTag(src_user.word0);
        const src_ref = src_kh.ref;
        const src_instance = src_kh.instance;
        const installed_caps: u16 = if (src_type == .process)
            new_caps & child_ipc_rx
        else
            new_caps;

        const minted = mintHandleReporting(
            child_process,
            src_kh.ref,
            src_type,
            installed_caps,
            src_user.field0,
            src_user.field1,
        ) catch {
            caller_dom_ref.unlockIrqRestore(caller_irq_state);
            cleanupPartiallyCreatedCd(child_process, child_thread);
            return errors.E_FULL;
        };

        // Spec §[capabilities].revoke: hang the new alias under the
        // source handle in the caller's process so a future revoke on
        // any ancestor of `(caller_dom, src_slot)` reaches the alias.
        // Coalesced aliases do not install a new child handle, so they
        // also do not get an extra derivation edge or object-side ref.
        if (minted.installed_new) {
            derive_records[derive_count] = .{
                .caller_ref = caller_ref,
                .src_slot = src_slot,
                .src_ref = src_ref,
                .src_type = src_type,
                .src_caps = Word0.caps(src_user.word0),
                .src_instance = src_instance,
                .child_ref = child_ref,
                .child_slot = minted.slot,
            };
            derive_count += 1;
        }

        // For refcount-lifetime types (page_frame, port,
        // device_region per spec proposal §3) the new alias is a real
        // lifetime contributor: bump the object-side refcount so the
        // child's destroyPhase2 kernel_table walk sees a balanced
        // mint/release pair and a `delete` of the source handle in
        // the caller cannot destroy the object out from under the
        // child. observed_zero is structurally impossible here — the
        // caller's source handle pins the object — so failures are
        // unreachable.
        if (minted.installed_new) {
            switch (src_type) {
                .page_frame => {
                    const alias_pf: *stygia.memory.page_frame.PageFrame = @ptrCast(@alignCast(src_kh.ref.ptr.?));
                    stygia.memory.page_frame.incHandleRef(alias_pf) catch unreachable;
                },
                .port => {
                    const alias_p: *stygia.sched.port.Port = @ptrCast(@alignCast(src_kh.ref.ptr.?));
                    const port_irq = alias_p._gen_lock.lockIrqSave(@src());
                    defer alias_p._gen_lock.unlockIrqRestore(port_irq);
                    stygia.sched.port.onHandleAcquire(alias_p, new_caps) catch unreachable;
                },
                .device_region => {
                    const alias_dr: *stygia.devices.device_region.DeviceRegion = @ptrCast(@alignCast(src_kh.ref.ptr.?));
                    stygia.devices.device_region.incHandleRef(alias_dr) catch unreachable;
                },
                else => {},
            }
        }

        if (move) {
            moved_sources[moved_count] = .{
                .slot = src_slot,
                .ref = src_ref,
                .type_tag = src_type,
                .caps = Word0.caps(src_user.word0),
                .instance = src_instance,
            };
            moved_count += 1;
        }

        pass_idx += 1;
    }

    // Reserve the caller's returned IPC slot before deleting moved
    // sources. Because moved source slots are still occupied here, the
    // returned IPC cannot reuse one. Because the slot remains unpublished
    // until after move cleanup, another thread in the caller's process cannot
    // observe both the moved source and the new child IPC alias.
    const caller_cripc: u16 = @truncate((readSelfField0(caller_dom) >> 24) & 0xFF);
    const ipc_slot = reserveHandleSlot(caller_dom) catch {
        caller_dom_ref.unlockIrqRestore(caller_irq_state);
        cleanupPartiallyCreatedCd(child_process, child_thread);
        return errors.E_FULL;
    };
    caller_dom_ref.unlockIrqRestore(caller_irq_state);

    var derive_idx: usize = 0;
    while (derive_idx < derive_count) : (derive_idx += 1) {
        const rec = derive_records[derive_idx];
        if (!stygia.caps.derivation.deriveExpected(
            rec.caller_ref,
            rec.src_slot,
            rec.src_ref,
            rec.src_type,
            rec.src_caps,
            rec.src_instance,
            rec.child_ref,
            rec.child_slot,
        )) {
            const cleanup_lr = caller_dom_ref.lockIrqSave(@src()) catch null;
            if (cleanup_lr) |lr| {
                releaseReservedHandleSlot(lr.ptr, ipc_slot);
                caller_dom_ref.unlockIrqRestore(lr.irq_state);
            }
            cleanupPartiallyCreatedCd(child_process, child_thread);
            return errors.E_BADCAP;
        }
    }

    // move=1: remove all sources through the normal delete path so their
    // derivation children are reparented, per-type release semantics run
    // once, each slot rejoins the free list, and each per-slot instance
    // witness advances. The batch delete prevalidates every moved source
    // under tree_mutex -> caller process before consuming any of them; therefore
    // this failure path does not return after partially moving the caller's
    // source handles. The caller's return IPC slot was already reserved
    // above, so these deletes cannot make the returned handle reuse a moved
    // source slot.
    const delete_result = stygia.caps.derivation.deleteAndDetachExpectedBatch(
        caller_ref,
        moved_sources[0..moved_count],
    );
    if (delete_result != 0) {
        const cleanup_lr = caller_dom_ref.lockIrqSave(@src()) catch null;
        if (cleanup_lr) |lr| {
            releaseReservedHandleSlot(lr.ptr, ipc_slot);
            caller_dom_ref.unlockIrqRestore(lr.irq_state);
        }
        cleanupPartiallyCreatedCd(child_process, child_thread);
        return delete_result;
    }

    // Publish the returned IPC in the pre-reserved caller slot only after
    // all moved source handles have been deleted. Per spec §[19]: caps =
    // caller's cripc_ceiling.
    const publish_lr = caller_dom_ref.lockIrqSave(@src()) catch {
        cleanupPartiallyCreatedCd(child_process, child_thread);
        return errors.E_BADCAP;
    };
    if (!stygia.caps.capability.isReservedHandleSlot(&publish_lr.ptr.kernel_table[ipc_slot])) {
        caller_dom_ref.unlockIrqRestore(publish_lr.irq_state);
        cleanupPartiallyCreatedCd(child_process, child_thread);
        return errors.E_BADCAP;
    }
    mintHandleAt(
        publish_lr.ptr,
        ipc_slot,
        .{
            .ptr = child_process,
            .gen = @intCast(child_process._gen_lock.currentGen()),
        },
        .process,
        caller_cripc,
        0,
        0,
    );
    caller_dom_ref.unlockIrqRestore(publish_lr.irq_state);
    maybePrintSpawnChild(child_process, child_thread);

    // Enqueue the initial thread on a core that satisfies its affinity
    // mask. With affinity = 0 (any core) or a mask containing the
    // calling core, prefer the calling core; otherwise use the lowest
    // bit set in the mask. Spec §[create_process] [5].
    //
    // NOTE: this is only initial placement. `affinity == 0` remains
    // local-biased here and on ordinary re-enqueue, but x64's scheduler
    // pull path may later steal the ready thread to any core. aarch64 keeps
    // stealing disabled until thread migration has FP-state parity.
    //
    // That matters most for a single spawner: the test runner creates
    // every test process from one thread with affinity 0, so the entire suite
    // executes on one core while the rest idle. See stygia-yxj and
    // docs/kernel/open-design-questions.md.
    //
    // (An earlier version of this comment claimed "the scheduler's pull
    // path can still migrate it later". No such path exists.)
    const calling_core: u64 = arch.smp.coreID();
    const enqueue_core: u64 = blk: {
        if (initial_thread_affinity == 0) break :blk calling_core;
        if ((initial_thread_affinity >> @intCast(calling_core)) & 1 != 0) {
            break :blk calling_core;
        }
        break :blk @ctz(initial_thread_affinity);
    };
    scheduler.enqueueOnCore(@intCast(enqueue_core), child_thread);

    // Spec §[error_codes] / §[capabilities]: success returns the
    // packed Word0 (id | type<<12 | caps<<48) so the type tag in bits
    // 12..15 always disambiguates a real handle word from the error
    // range 1..15. Returning the bare slot would alias slots 1..15
    // with the spec error codes, so userspace's standard error check
    // would treat valid handle slots as failures.
    return @intCast(Word0.pack(ipc_slot, .process, caller_cripc));
}

inline fn pageFrameSizeBytes(sz: stygia.memory.vmar.PageSize) u64 {
    return switch (sz) {
        .sz_4k => 0x1000,
        .sz_2m => 0x200000,
        .sz_1g => 0x40000000,
        ._reserved => unreachable,
    };
}

fn extractDiagTestTag(elf_bytes: []const u8) u64 {
    if (!build_options.kernel_spawn_diag) return 0;

    const aarch64_tag = extractAarch64DiagTestTag(elf_bytes);
    if (aarch64_tag != 0) return aarch64_tag;

    var mov_imm_seen: [DIAG_TEST_TAG_COUNT]bool = .{false} ** DIAG_TEST_TAG_COUNT;
    var i: usize = 0;
    while (i + 4 <= elf_bytes.len) : (i += 1) {
        const v = readLeU32(elf_bytes, i);
        if (v < DIAG_TEST_TAG_MAGIC or v >= DIAG_TEST_TAG_LIMIT) continue;
        if (i >= 1 and elf_bytes[i - 1] >= 0xB8 and elf_bytes[i - 1] <= 0xBF) {
            mov_imm_seen[v - DIAG_TEST_TAG_MAGIC] = true;
        }
    }

    // x86 ReleaseSmall test ELFs can contain many unrelated 0x8xxx-looking
    // immediates (stack offsets, displacements, embedded child ELFs). The
    // report helper's tag is the only candidate that appears both as the
    // report-entry marker's `mov r32, imm32` and as the `Regs.v5` immediate
    // store (`48 c7 /0 + disp8=0x20 + imm32`). If that shape is absent or
    // ambiguous, leave the child untagged.
    var found: u32 = 0;
    i = 0;
    while (i + 4 <= elf_bytes.len) : (i += 1) {
        const v = readLeU32(elf_bytes, i);
        if (v < DIAG_TEST_TAG_MAGIC or v >= DIAG_TEST_TAG_LIMIT) continue;
        if (!mov_imm_seen[v - DIAG_TEST_TAG_MAGIC]) continue;
        if (!(i >= 4 and
            elf_bytes[i - 4] == 0x48 and
            elf_bytes[i - 3] == 0xC7 and
            elf_bytes[i - 1] == 0x20))
        {
            continue;
        }

        if (found == 0) {
            found = v;
        } else if (found != v) {
            return 0;
        }
    }
    return found;
}

fn extractAarch64DiagTestTag(elf_bytes: []const u8) u32 {
    var found: u32 = 0;
    var i: usize = 0;
    while (i + 4 <= elf_bytes.len) : (i += 4) {
        const insn = readLeU32(elf_bytes, i);
        if ((insn & 0x7F80_0000) != 0x5280_0000) continue;

        const v = (insn >> 5) & 0xFFFF;
        if (v < DIAG_TEST_TAG_MAGIC or v >= DIAG_TEST_TAG_LIMIT) continue;
        if (found == 0) {
            found = v;
        } else if (found != v) {
            return 0;
        }
    }
    return found;
}

inline fn readLeU32(bytes: []const u8, i: usize) u32 {
    return @as(u32, bytes[i]) |
        (@as(u32, bytes[i + 1]) << 8) |
        (@as(u32, bytes[i + 2]) << 16) |
        (@as(u32, bytes[i + 3]) << 24);
}

fn maybePrintSpawnChild(process: *Process, thread: *Thread) void {
    if (!build_options.kernel_spawn_diag) return;
    if (process.diag_test_tag == 0) return;

    thread_mod.recordSpawnTrace(thread, process, .spawn_child, 0);

    const n = @atomicRmw(u32, &spawn_child_prints, .Add, 1, .monotonic);
    if (n >= SPAWN_CHILD_PRINT_BUDGET) return;

    arch.boot.print(
        "[spawn-child] tag=0x{x} index={x} process=0x{x} thread=0x{x} elf_slot={x} elf_pf=0x{x}\n",
        .{
            process.diag_test_tag,
            process.diag_test_tag - DIAG_TEST_TAG_MAGIC,
            @intFromPtr(process),
            @intFromPtr(thread),
            process.diag_elf_pf_slot,
            process.diag_elf_pf_ptr,
        },
    );
}

/// Tear down a partially-constructed process whose `createProcess`
/// hit a post-`allocProcess` error. The process is published-live
/// at this point (gen-lock is odd / unlocked), so the destroy follows
/// the standard `destroyPhase1` → `destroyPhase2` path. The optional
/// `partial_thread` is the initial thread that was alloc'd before the failing
/// step but never published into a handle (slot 1 of the child's table
/// may or may not have been written). Phase 2's `destroyThreadsInProcess`
/// walks the thread slab matching `(process, gen)` and reaps every thread bound to
/// this process — so even the still-`.ready`-but-not-yet-enqueued initial
/// thread is reaped here. Spec §[create_process] failure paths
/// must not leak the freshly-allocated process; without this cleanup the
/// kernel slab class fills after ~10 reps of the test runner and any
/// subsequent `createPort` returns E_NOMEM.
fn cleanupPartiallyCreatedCd(process: *Process, partial_thread: ?*Thread) void {
    thread_mod.printPreReportTerminal(partial_thread, process, "partial_create_cleanup", null);
    // `partial_thread` itself is covered by destroyThreadsInProcess's slab-walk match.
    const process_gen = process._gen_lock.currentGen();
    const process_ref: SlabRef(Process) = .{ .ptr = process, .gen = @intCast(process_gen) };

    // `destroyPhase1` invariant: caller holds `tree_mutex` (so
    // `detachDyingProcessFromTree`'s tree walk runs under it) AND
    // `process._gen_lock`. Mirrors the SLOT_SELF arm in
    // `caps.derivation.deleteAndDetach` and the fault-path SLOT_SELF
    // teardown in `port.fireMemoryFault`.
    const tree_irq = stygia.caps.derivation.tree_mutex.lockIrqSaveOrdered(
        @src(),
        stygia.caps.derivation.TREE_MUTEX_GROUP,
    );

    // Tag the process acquire with `TREE_PROCESS_GROUP` so the
    // `detachDyingProcessFromTree` walk (which re-locks cross-process processes
    // under the same group inside `lockEntrySkip`) does not trip
    // lockdep's same-class overlap check. See
    // `caps.derivation.TREE_PROCESS_GROUP` doc comment.
    const lr = process_ref.lockOrderedIrqSave(stygia.caps.derivation.TREE_PROCESS_GROUP, @src()) catch {
        stygia.caps.derivation.tree_mutex.unlockIrqRestore(tree_irq);
        return;
    };
    // destroyPhase1 runs under process._gen_lock and ends by releasing it
    // via destroyLocked (gen flips to even). Restore IRQ state
    // manually because the deferred unlockIrqRestore would assert on
    // the just-cleared lock bit. Mirrors the slot==0 SLOT_SELF path
    // in derivation.deleteAndDetach.
    const deferred = destroyPhase1(process, null);
    arch.cpu.restoreInterrupts(lr.irq_state);

    stygia.caps.derivation.tree_mutex.unlockIrqRestore(tree_irq);

    destroyPhase2(deferred);
}

fn handleTableBlockBytes(comptime T: type) u64 {
    const raw: u64 = @as(u64, MAX_HANDLES_PER_PROCESS) * @sizeOf(T);
    const pages: u64 = (raw + 0xFFF) / 0x1000;
    var pow: u64 = 1;
    while (pow < pages) pow <<= 1;
    return pow * 0x1000;
}

const USER_TABLE_BYTES: u64 = handleTableBlockBytes(Capability);
const KERNEL_TABLE_BYTES: u64 = handleTableBlockBytes(KernelHandle);

/// Allocate a new Process — slab slot, handle tables from PMM,
/// address-space root, slot-0 self-handle, slot-1 placeholder for the
/// initial thread handle (filled by caller via `mintHandle`), slot-2 self-IPC.
/// Spec §[process].
pub fn allocProcess(
    self_caps: u16,
    field0_ceilings: u64,
    field1_ceilings: u64,
    initial_entry: VAddr,
) !*Process {
    _ = initial_entry;

    const pending = try slab_instance.create();
    const process = pending.ptr;
    const process_gen = pending.pending_gen;
    // Pending slot is off the freelist but at even gen — return it
    // via `destroyAlreadyMarked` (which expects even gen) on any
    // initialization-time error before `publish`.
    errdefer slab_instance.destroyAlreadyMarked(process);

    const pmm_mgr = if (pmm.global_pmm) |*p| p else return error.OutOfMemory;

    // Handle tables live in kernel physmap RAM. Start from an explicit
    // zero base before rebuilding free-list links so a recycled table
    // block cannot carry stale refs into `mintHandle`'s coalescing scan.
    const user_buf = pmm_mgr.allocBlock(USER_TABLE_BYTES) orelse return error.OutOfMemory;
    errdefer pmm_mgr.freeBlock(user_buf[0..USER_TABLE_BYTES]);
    const kernel_buf = pmm_mgr.allocBlock(KERNEL_TABLE_BYTES) orelse return error.OutOfMemory;
    errdefer pmm_mgr.freeBlock(kernel_buf[0..KERNEL_TABLE_BYTES]);

    const user_table: *[MAX_HANDLES_PER_PROCESS]Capability = @ptrCast(@alignCast(user_buf));
    const kernel_table: *[MAX_HANDLES_PER_PROCESS]KernelHandle = @ptrCast(@alignCast(kernel_buf));

    process.user_table = user_table;
    process.kernel_table = kernel_table;

    @memset(user_table[0..], .{ .word0 = 0, .field0 = 0, .field1 = 0 });
    @memset(kernel_table[0..], .{});

    // Free-list links cover slots 3..MAX-1; slots 0/1/2 are reserved by
    // spec and are NOT on the free list.
    var i: u16 = 3;
    while (i < MAX_HANDLES_PER_PROCESS - 1) {
        kernel_table[i].parent = stygia.caps.capability.encodeFreeNext(i + 1);
        i += 1;
    }
    kernel_table[MAX_HANDLES_PER_PROCESS - 1].parent =
        stygia.caps.capability.encodeFreeNext(stygia.caps.capability.FREE_LIST_TAIL);
    process.free_head = 3;
    process.free_count = MAX_HANDLES_PER_PROCESS - 3;
    process.var_count = 0;
    process.next_var_base = NEXT_VAR_BASE_START;
    process.vm = null;
    @memset(process.vars[0..], null);

    // Address space root + ASID. The new process needs a fresh page-table
    // root so the ELF + handle tables can be installed; the ASID tags TLB
    // entries.
    process.addr_space_root = try arch.paging.allocAddrSpaceRoot();
    process.addr_space_id = arch.paging.allocAddrSpaceId() orelse 0;

    // Slot 0 — self-handle. Carries ceilings + caps; the rest of the
    // kernel reads them back through `user_table[0]` per the doc on
    // `Process.user_table`.
    user_table[0].word0 = Word0.pack(0, .process_self, self_caps);
    user_table[0].field0 = field0_ceilings;
    user_table[0].field1 = field1_ceilings;
    kernel_table[0].ref = .{
        .ptr = process,
        .gen = @intCast(process_gen),
    };

    // Slot 1 — placeholder for the initial thread handle; populated by the
    // caller (root bringup or `create_process`).
    user_table[1] = .{ .word0 = 0, .field0 = 0, .field1 = 0 };
    kernel_table[1].ref = .{};

    // Slot 2 — self-IPC. Caps come from the process's cripc ceiling.
    const cripc_ceiling: u16 = @truncate((field0_ceilings >> 24) & 0xFF);
    user_table[2].word0 = Word0.pack(2, .process, cripc_ceiling);
    user_table[2].field0 = 0;
    user_table[2].field1 = 0;
    kernel_table[2].ref = .{
        .ptr = process,
        .gen = @intCast(process_gen),
    };

    _ = slab_instance.publish(pending);
    return process;
}

/// Final teardown — walks `vars` freeing each VMAR, walks
/// `kernel_table` releasing every used slot per type, tears down the
/// address space, frees the table pages, frees slab.
///
/// Step 10 minimal teardown. SLOT_SELF and unhandled-fault teardown callers
/// invoke this AFTER the calling thread has been retired via
/// `parkSelfFaulted` (it is the bound initial thread by spec —
/// `delete(SLOT_SELF)` from inside the child runs on this very thread). At
/// entry the thread is no longer the current_thread on its core; its kernel stack
/// frame is the one we are currently executing on, so we MUST not free
/// the kernel stack pages here. The scheduler's noreturn dispatch will
/// iretq off this stack once we return; the next preemption tick observes
/// the thread as `terminated` and reaps it via the slab generation flip.
///
/// What this does free now: the user/kernel handle-table PMM blocks,
/// the address-space PCID, and the process slab slot itself. What is
/// deliberately leaked for later: page-table page frames (need an
/// arch.paging walk), page_frame slab refcount drops for handle-table
/// entries (refcounted PFs survive), VARs (require process.vars[] walk
/// + per-VMAR unmap + slab destroy). These are smaller per-test than
/// the table blocks and don't push the full-475-test runner past the
/// PMM budget on a 1 GB QEMU instance.
/// Snapshot the destroy state captured under the process's `_gen_lock` for
/// later sibling-slab tear-down. Carrying this between `destroyPhase1`
/// and `destroyPhase2` lets the caller release outer locks (process's
/// `_gen_lock`, `tree_mutex`) before the thread / VM destroys lock their
/// own slab classes — without it, lockdep records `tree_mutex →
/// thread._gen_lock` and `process._gen_lock → thread._gen_lock` edges and any
/// inverse path closes an AB-BA cycle.
pub const DestroyDeferred = struct {
    /// process identity captured under process._gen_lock at phase-1 entry. The gen
    /// is the live odd value at capture; phase-2's thread walk uses
    /// `process_ref.ptr` / `process_ref.gen` for identity-only comparison against
    /// `thread.process` (no deref of the freed process).
    process_ref: SlabRef(Process),
    process_addr_space_root: PAddr,
    vm_ref: ?SlabRef(VirtualMachine),
    user_buf: [*]u8,
    kernel_buf: [*]u8,
    addr_space_id: u16,
    /// VMAR refs captured while the process is still gen-live. Phase 2 walks this
    /// snapshot instead of dereferencing the dead-marked process's `vars[]` /
    /// `var_count` fields.
    vars: [MAX_VARS_PER_PROCESS]?SlabRef(VMAR),
    var_count: u16,
    /// Phys base + size of the contiguous user-stack buddy block.
    /// `pmm.freeBlock`'d wholesale at destroy and skipped by the
    /// per-page `freeUserAddrSpace` walk (the leaves point into this
    /// range). 0/0 means the stack wasn't allocated for this process.
    user_stack_phys: u64,
    user_stack_bytes: u64,
    /// Caller-running thread (the one that invoked `delete(SLOT_SELF)`).
    /// Skipped by phase-2's thread walk because its kernel stack is in
    /// active use. The gen is captured before `parkSelfFaulted`; the
    /// walk only uses it for pointer-identity comparison.
    caller_thread: ?SlabRef(Thread),
};

pub const ExitDecision = enum(u8) { already_claimed = 0, restart = 1, retire = 2 };

/// The trigger caller holds the process gen-lock. Its cap snapshot and
/// first-owner claim linearize against restrict(SLOT_SELF) at the actual
/// exit/fault, before the scheduler queues deferred teardown. A second
/// trigger parks its own thread and leaves the queued owner in charge.
pub fn claimExitLocked(process: *Process) ExitDecision {
    if (process.exit_decision.load(.acquire) != 0) return .already_claimed;
    const self_caps: ProcessCaps = @bitCast(Word0.caps(process.user_table[0].word0));
    const decision: ExitDecision = if (self_caps.restart) .restart else .retire;
    if (decision == .restart) process.restarting.store(true, .release);
    process.exit_decision.store(@intFromEnum(decision), .release);
    return decision;
}

fn restartHandleKept(tag: CapabilityType, caps: u16, keep_replies: bool) bool {
    return switch (tag) {
        .process_self, .thread, .virtual_memory_address_region => true,
        .process, .port => ((caps >> 5) & 1) != 0,
        .page_frame => ((caps >> 7) & 1) != 0,
        .device_region => ((caps >> 4) & 1) != 0,
        .virtual_machine => ((caps >> 1) & 1) != 0,
        .reply => keep_replies,
        else => false,
    };
}

/// Restart may relaunch the same process repeatedly. Once every core has
/// left its address space, reclaim the old private thread stack pages so
/// each policy-1 relaunch does not permanently consume physical memory.
fn releaseRestartUserStack(process: *Process, stack: stygia.memory.stack.Stack) void {
    const pmm_mgr = if (pmm.global_pmm) |*manager| manager else return;
    var va = stack.base.addr;
    while (va < stack.top.addr) : (va += 4096) {
        // The process will run again with the same PCID/ASID. Clear cached
        // translations before returning the frame to PMM.
        const phys = arch.paging.unmapPage(process.addr_space_root, VAddr.fromInt(va)) orelse continue;
        const page: [*]u8 = @ptrFromInt(VAddr.fromPAddr(phys, null).addr);
        pmm_mgr.freePage(page);
    }
}

/// Execute the restart after the caller has left its kernel stack. The
/// dispatch gate stops new commitments; scheduler IPIs evict cores already
/// running this address space before any mapping or thread stack changes.
/// Returns false only when a required allocation fails, in which case the
/// caller falls through to the normal process destroy path.
pub fn restartProcess(process_ref: SlabRef(Process)) bool {
    const process = process_ref.ptr;
    const root = process.addr_space_root;
    const self_core = arch.smp.coreID();
    var core: u64 = 0;
    while (core < arch.smp.coreCount()) : (core += 1) {
        if (core != self_core) arch.smp.triggerSchedulerInterrupt(core);
    }
    if (arch.paging.detachDyingUserRoot(root, stygia.memory.init.kernel_addr_space_root)) {
        scheduler.publishActiveRoot(@truncate(self_core), 0);
    }
    scheduler.awaitProcessQuiesced(root.addr, process);

    // A stopped thread can still have an outstanding reply in another
    // process. Retiring its generation before relaunch makes that reply
    // resolve E_TERM; a persist thread is left untouched.
    var survivors: u16 = 0;
    var slot: u16 = 1;
    while (slot < MAX_HANDLES_PER_PROCESS) : (slot += 1) {
        const kh = &process.kernel_table[slot];
        const old_ptr = kh.ref.ptr orelse continue;
        if (Word0.typeTag(process.user_table[slot].word0) != .thread) continue;
        const old: *Thread = @ptrCast(@alignCast(old_ptr));
        const old_ref = SlabRef(Thread).init(old, kh.ref.gen);
        // A foreign process may hold a thread handle and terminate it
        // concurrently. Validate and copy metadata under its generation
        // lock; never read a bare slab after the generation can be reused.
        const old_lr = old_ref.lockIrqSave(@src()) catch continue;
        if (old_lr.ptr.process.ptr != process or old_lr.ptr.process.gen != process_ref.gen) {
            old_ref.unlockIrqRestore(old_lr.irq_state);
            continue;
        }
        const caps_word = Word0.caps(process.user_table[slot].word0);
        const policy: u2 = @truncate(caps_word >> 8);
        if (policy == 2) {
            survivors += 1;
            old_ref.unlockIrqRestore(old_lr.irq_state);
            continue;
        }

        const entry = old_lr.ptr.entry_point;
        const affinity = old_lr.ptr.affinity;
        const priority = old_lr.ptr.priority;
        const old_stack = old_lr.ptr.user_stack;
        const stack_pages: u32 = if (old_stack) |us|
            @intCast((us.top.addr - us.base.addr) / 4096)
        else
            1;
        old_ref.unlockIrqRestore(old_lr.irq_state);
        if (!thread_mod.destroyThreadForRestart(old_ref)) continue;
        if (old_stack) |stack| releaseRestartUserStack(process, stack);
        if (policy == 0) continue;

        const fresh = thread_mod.allocThread(process, entry, stack_pages, affinity, priority, null, null) catch return false;
        survivors += 1;
        if (slot == 1 and process.initial_stack_top != 0) {
            arch.cpu.patchUserModeIretFrame(
                fresh.ctx,
                entry,
                VAddr.fromInt(process.initial_stack_top),
                process.initial_table_base,
            );
        }
        // A process may hold more than one alias to the thread. All local
        // aliases keep their slots and caps; foreign reply/thread aliases
        // retain the old generation and fail with E_TERM.
        var alias: u16 = slot;
        while (alias < MAX_HANDLES_PER_PROCESS) : (alias += 1) {
            const e = &process.kernel_table[alias];
            if (e.ref.ptr == @as(*anyopaque, @ptrCast(old)) and e.ref.gen == old_ref.gen and
                Word0.typeTag(process.user_table[alias].word0) == .thread)
            {
                e.ref.ptr = fresh;
                e.ref.gen = @intCast(fresh._gen_lock.currentGen());
            }
        }
    }
    // If a foreign terminate won the last relaunch candidate before its
    // generation flip, finish through ordinary teardown. A restart with no
    // surviving thread would otherwise leave the process gate live forever.
    if (survivors == 0) return false;

    slot = 3;
    while (slot < MAX_HANDLES_PER_PROCESS) : (slot += 1) {
        if (process.kernel_table[slot].ref.ptr == null) continue;
        if (Word0.typeTag(process.user_table[slot].word0) != .virtual_memory_address_region) continue;
        const policy: u2 = @truncate(Word0.caps(process.user_table[slot].word0) >> 9);
        switch (policy) {
            0 => {
                _ = stygia.caps.derivation.deleteAndDetach(@bitCast(process_ref), @intCast(slot));
            },
            1 => stygia.memory.vmar.restartDecommit(process, @intCast(slot)),
            2 => {},
            3 => if (!stygia.memory.vmar.restartSnapshot(process, @intCast(slot))) return false,
        }
    }

    const keep_replies: bool = (Word0.caps(process.user_table[0].word0) & (1 << 10)) != 0;
    slot = 2;
    while (slot < MAX_HANDLES_PER_PROCESS) : (slot += 1) {
        if (process.kernel_table[slot].ref.ptr == null) continue;
        const word0 = process.user_table[slot].word0;
        const tag = Word0.typeTag(word0);
        if (restartHandleKept(tag, Word0.caps(word0), keep_replies)) continue;
        if (tag == .reply) {
            _ = stygia.caps.derivation.dropReplyForRestart(@bitCast(process_ref), @intCast(slot));
        } else {
            _ = stygia.caps.derivation.deleteAndDetach(@bitCast(process_ref), @intCast(slot));
        }
    }

    process.exit_decision.store(0, .release);
    process.restarting.store(false, .release);
    slot = 1;
    while (slot < MAX_HANDLES_PER_PROCESS) : (slot += 1) {
        const kh = &process.kernel_table[slot];
        const ptr = kh.ref.ptr orelse continue;
        if (Word0.typeTag(process.user_table[slot].word0) != .thread) continue;
        const thread: *Thread = @ptrCast(@alignCast(ptr));
        if (thread._gen_lock.currentGen() != kh.ref.gen) continue;
        if (stygia.sched.lifecycle.load(thread) == .ready and
            thread.current_queue_core.load(.acquire) == thread_mod.NOT_IN_RUN_QUEUE)
        {
            scheduler.enqueue(thread);
        }
    }
    return true;
}

/// Phase-1 destroy: runs WITH the process's `_gen_lock` held by the caller
/// AND with `caps.derivation.tree_mutex` held by the caller. Disarms
/// snapshots all process.* fields the phase-2 tear-down needs, and releases the process
/// slab slot via `destroyLocked` (clears the lock bit + bumps gen →
/// even in one store). On return the process's `_gen_lock` is no longer
/// held — the caller MUST drop `tree_mutex` (and any other locks)
/// BEFORE invoking `destroyPhase2`.
///
/// The caller's `process._gen_lock` MUST be acquired with
/// `caps.derivation.TREE_PROCESS_GROUP` (and `tree_mutex` with
/// `caps.derivation.TREE_MUTEX_GROUP`). Without those tags,
/// `detachDyingProcessFromTree`'s cross-process process acquires inside
/// `lockEntrySkip` (also `TREE_PROCESS_GROUP`) trip lockdep's
/// same-class overlap check.
pub fn destroyPhase1(process: *Process, caller_thread: ?SlabRef(Thread)) DestroyDeferred {
    // Spec §[capabilities].revoke / Lifetimes: every live handle in
    // the dying process may sit on the cross-process copy-derivation
    // tree (parent in another process, children in another process,
    // siblings in another process). Splice each one out before the
    // kernel_table memory is freed in Phase 2; otherwise the OTHER
    // processes hold dangling links into a freed slot. detachForDelete
    // reparents children to grandparent so a future revoke on a
    // surviving ancestor still reaches the orphaned subtree (Spec
    // §[capabilities].revoke test 04 generalized to process destroy).
    stygia.caps.derivation.detachDyingProcessFromTree(process);

    // NOTE (stygia-1im): the `process.vars[]` teardown deliberately does NOT
    // run here. It moved to `destroyPhase2`, immediately after
    // `awaitProcessQuiesced`. Unmapping in phase 1 was unsound: phase 1
    // only dead-marks the process, and this function's callers hold locks
    // that forbid the quiesce barrier, so at this point a still-live thread
    // of this process can be executing on ANOTHER core — typically
    // sitting in the kernel mid-syscall, about to `sysretq` back to
    // user. Clearing its leaf PTEs here pulls the user text out from
    // under it, and the moment it returns to user mode it takes an
    // instruction-fetch fault on an address with no VMAR. The resulting
    // `memory_fault` is then unroutable (this process's gen is already even,
    // so the fault port cannot be resolved) and the thread is parked with
    // `[UNHANDLED] ... why=unbound`.
    //
    // Observed on x86-64 with the suite spread across 4 cores: the
    // victim faults at the return address of libz's syscall stub
    // (`syscall.issueRawNoStack` + 0x20) or at the `memcpy` it calls two
    // instructions later, depending on which page was still TLB-hot.
    // The old single-core test placement serialized the runner against
    // its children and hid it entirely.
    //
    // The per-page-shootdown skip that the destroy-path VMAR teardown
    // relies on ("no core has the dying process's CR3 active") is likewise
    // only TRUE after the barrier — so the unmap belongs there and
    // nowhere else.
    const process_gen = process._gen_lock.currentGen();
    var vars_snapshot: [MAX_VARS_PER_PROCESS]?SlabRef(VMAR) = undefined;
    @memcpy(vars_snapshot[0..], process.vars[0..]);
    const deferred = DestroyDeferred{
        .process_ref = SlabRef(Process).init(process, process_gen),
        .process_addr_space_root = process.addr_space_root,
        .vm_ref = process.vm,
        .user_buf = @ptrCast(process.user_table),
        .kernel_buf = @ptrCast(process.kernel_table),
        .addr_space_id = process.addr_space_id,
        .vars = vars_snapshot,
        .var_count = process.var_count,
        .user_stack_phys = process.user_stack_phys,
        .user_stack_bytes = process.user_stack_bytes,
        .caller_thread = caller_thread,
    };

    // Dead-mark ONLY (gen → even, bytes intact, off the freelist).
    // The actual zero + freelist push runs at the END of destroyPhase2
    // (`destroyAlreadyMarked`), after every thread of this process has been
    // gen-bumped and evicted. Freeing (and zeroing) here opened the
    // phase1→phase2 gap that killed CPU0 in the stygia-rs6 corpses:
    // the process's Threads are still gen-live and dispatchable in this
    // window, and `switchTo` derefs `thread.process.ptr.addr_space_root`
    // raw — a dispatch racing this window read the zeroed root and
    // loaded CR3 = 0 (KVM vCPU preemption stretches the gap to
    // milliseconds). With bump-only, that read returns the REAL root
    // (bytes intact), so an in-gap dispatch runs correctly and the
    // phase-2 translation barrier sees its true `active_root`; the
    // even gen simultaneously makes handle resolution fail fast and
    // lets the dispatch filter drop dying-process Threads by process-gen
    // mismatch before their own gens are bumped.
    slab_instance.bumpDeadGenLocked(process, process_gen);

    return deferred;
}

/// Phase-2 destroy: runs with NO outer locks held. Tears down every
/// thread bound to the destroyed process, the optional per-process VM, and
/// releases the table-backing PMM blocks and the address-space ID.
/// The visitor matches Threads by `thread.process.ptr == process && gen == process_gen`;
/// the gen check rejects any new process that lands on the freed slab slot
/// between phase 1 and phase 2.
/// TEMP DIAGNOSTIC (stygia-afo, REMOVE). Frame-abandonment discriminator.
/// The standing hypothesis is that `destroyThreadsInProcess` re-enables IRQs
/// (via `destroyThreadLocked`'s postZombie spin), a preempt
/// lands, the phase-2 frame is abandoned mid-walk, and every not-yet-
/// visited thread of the already-dead-marked process is stranded forever.
/// If that is true, `p2_enter` must exceed `p2_walk_done`. If the three
/// counters stay equal the whole premise is dead regardless of how many
/// Threads leak. `p2_residue` counts Threads that STILL match the dying process after
/// the walk returned — a completed-but-incomplete walk, a different bug.
/// TEMP DIAGNOSTIC (stygia-afo, REMOVE). ATOMIC, deliberately: the first
/// version of these were plain `+= 1` and four cores raced them, which
/// showed up as `p2_exit` (4876) EXCEEDING `p2_walk_done` (4874) — an
/// ordering that is impossible in the code and proved increments were
/// being lost. A lossy counter cannot discriminate "the walk was
/// abandoned" from "the increment evaporated", so the whole 22%-gap
/// reading rested on nothing. Monotonic RMW makes the gap real evidence.
pub var p2_enter: u64 = 0;
/// TEMP DIAGNOSTIC (stygia-afo, REMOVE). Reached only if the caller-thread
/// reap returned. `p2_enter - p2_after_reap` isolates the abandonment to
/// that reap; `p2_after_reap - p2_walk_done` isolates it to the walk.
pub var p2_after_reap: u64 = 0;
pub var p2_walk_done: u64 = 0;
pub var p2_exit: u64 = 0;
pub var p2_residue: u64 = 0;

fn bump(counter: *u64, n: u64) void { // TEMP DIAGNOSTIC (stygia-afo, REMOVE)
    _ = @atomicRmw(u64, counter, .Add, n, .monotonic);
}

/// TEMP DIAGNOSTIC (stygia-afo, REMOVE). Per-core "this core's C stack is
/// currently inside `destroyPhase2`". Set on entry, cleared on the normal
/// exit path. `scheduler.yieldTo` consults it at the ONE point where a
/// frame is provably lost — `current_thread == null` and we `switchTo` some
/// other thread, which never returns — so an abandonment is COUNTED at the
/// moment it happens rather than inferred from a gap between two
/// counters. Plain bools: each entry is written only by its own core.
pub var in_phase2: [stygia.sched.scheduler.MAX_CORES]bool =
    [_]bool{false} ** stygia.sched.scheduler.MAX_CORES;
/// TEMP DIAGNOSTIC (stygia-afo, REMOVE). Frames abandoned while inside
/// phase 2, and frames abandoned outside it (those are harmless: the
/// disowned frames of a parking thread, which has nothing left to run).
pub var abandoned_in_p2: u64 = 0;
pub var abandoned_other: u64 = 0;

/// TEMP DIAGNOSTIC (stygia-afo, REMOVE). Called by `scheduler.yieldTo`
/// immediately before a `switchTo` that cannot return to this stack.
pub fn noteFrameAbandoned() void {
    const core: usize = @truncate(arch.smp.coreID());
    if (core < in_phase2.len and in_phase2[core]) {
        bump(&abandoned_in_p2, 1);
        // The stack that owned this flag is gone; whatever runs on this
        // core next is not in phase 2.
        in_phase2[core] = false;
    } else {
        bump(&abandoned_other, 1);
    }
}

pub fn destroyPhase2(deferred: DestroyDeferred) void {
    bump(&p2_enter, 1); // TEMP DIAGNOSTIC (stygia-afo, REMOVE)
    // Mask IRQs across the whole of phase 2. With the deferred caller_thread
    // reap, freeUserAddrSpace, and per-handle release walk, the
    // post-Phase1 work is no longer trivially short — a preempt landing
    // mid-phase-2 would enter yieldTo, find current_thread=null (from the
    // earlier parkSelfFaulted), dequeue a runnable thread, and switchTo
    // away. The destroyPhase2 frame is abandoned, so the rest of the
    // cleanup never runs and resources accumulate across reps.
    const irq = arch.cpu.saveAndDisableInterrupts();
    defer arch.cpu.restoreInterrupts(irq);

    // TEMP DIAGNOSTIC (stygia-afo, REMOVE). Mark this core's stack as a
    // phase-2 frame for `scheduler.yieldTo`'s abandonment detector.
    {
        const dcore: usize = @truncate(arch.smp.coreID());
        if (dcore < in_phase2.len) in_phase2[dcore] = true;
    }
    defer {
        const dcore: usize = @truncate(arch.smp.coreID());
        if (dcore < in_phase2.len) in_phase2[dcore] = false;
    }

    // The mask above is NOT sufficient on its own, and the reason is
    // worth stating precisely because the obvious repair does not work.
    // `destroyPhase2` calls `destroyThreadLocked` — once for
    // the caller thread just below, then once per victim inside
    // `destroyThreadsInProcess` — and that helper used to re-enable
    // interrupts UNCONDITIONALLY around its `postZombie` spin. Each such
    // window is a chance for a preempt tick to land on a frame whose
    // `current_thread` was already cleared by `parkSelfFaulted`, at which
    // point `yieldTo` dispatches something else and hops to the park
    // kstack — this frame's remaining teardown never runs, and because
    // the process is already dead-marked, nothing ever walks it again.
    //
    // REFUTED REPAIR (do not re-try): a `preempt_block` depth counter on
    // `PerCore` that made `yieldTo` return instead of switching. It
    // deadlocks the machine inside the FIRST suite pass. Blocking the
    // switch also blocks the two protocols that are *implemented by*
    // switching: `PerCore.pending_kstack_release` is consumed only by
    // the park-kstack hop, so a stashed thread keeps `on_cpu == true`
    // forever and every peer in `markReady`'s kstack barrier spins
    // without bound; and a core only publishes `active_root = 0` on its
    // way through `run()`, so a peer in `awaitNoActiveRoot` waits on a
    // core that has been told never to leave. Measured: wedge at run
    // 1, batch 16..32, no output thereafter.
    //
    // The window is closed at its source instead — see the two escapes in
    // `destroyThreadLocked`. Stage one (stygia-afo cycle 1): try
    // `postZombie` ONCE under the caller's mask, and only pay for the
    // IRQ-enabling spin when that fails. That closed the caller-thread reap
    // completely (`p2_enter == p2_after_reap` over 10428 destroys, against
    // 1354/6228 abandoned before) but left the walk leaking.
    //
    // Stage two (cycle 2) is what closed the walk, and the measurement is
    // the interesting part: the failing posts were not contention at all.
    // Phase 2 pins THIS core's own `pending_zombie` slot with the caller
    // thread it reaps at the top, and this frame stands on that thread's kstack
    // until it returns, so the drain can never evict it. Every same-core
    // victim post from `destroyThreadsInProcess` then spun on a condition that
    // could not change: over 25 aarch64 TCG passes, 1176 of 1176 failing
    // posts were same-core and 0 of 1176 ever completed. Each one hung
    // until a preempt abandoned this frame. `claimOwnZombieInline` skips
    // the column when this core is provably off the victim's kstack.
    //
    // Do NOT read the mask above as an invariant even so: the cross-core
    // fallback still enables IRQs, by design, because only the target core
    // drains its own column and it may itself be blocked on us. That path
    // has never once been observed to execute; if it ever does, the frame
    // it runs on is abandonable and the teardown below is skippable again.

    // Self-destroy hazard (stygia-rs6 layer 2): when the caller thread is
    // destroying its OWN process, this core is still executing with the
    // dying process's translation root active (x86-64 CR3 covers both
    // halves). Everything below — and `freeUserAddrSpace` especially —
    // tears down the very tables that root points at; TLB retention
    // hides it most runs, then one cold miss mid-teardown makes even
    // kernel text/rodata unwalkable: recursive panic into triple
    // fault. Detach to the kernel root first and publish the detach so
    // the barrier below can't wait on ourselves. No-op when the active
    // root is not the dying one (cross-process destroy — the destroyer
    // keeps publishing its own, unrelated root) and on aarch64 (kernel
    // translation lives in TTBR1).
    if (arch.paging.detachDyingUserRoot(
        deferred.process_addr_space_root,
        stygia.memory.init.kernel_addr_space_root,
    )) {
        stygia.sched.scheduler.publishActiveRoot(
            @truncate(arch.smp.coreID()),
            0,
        );
    }

    const pmm_mgr = if (pmm.global_pmm) |*p| p else return;

    // Reap the caller thread FIRST, before anything that can drop the IRQ
    // mask (stygia-2u0).
    //
    // The mask taken above is what keeps this frame alive — its own
    // comment warns that an abandoned frame means "the rest of the
    // cleanup never runs and resources accumulate across reps". But
    // `destroyThreadsInProcess` below reaches `destroyThreadLocked`,
    // which deliberately RE-ENABLES interrupts around its `postZombie`
    // spin (otherwise a cross-core spin here would block the very IPIs
    // it is waiting on). That reopens the preempt window mid-phase-2:
    // `yieldTo` sees `current_thread == null` — cleared by the earlier
    // `parkSelfFaulted` — dequeues something else and switches away, and
    // this frame never resumes. Everything below the abandonment point
    // is silently skipped.
    //
    // The caller thread used to be reaped at the END of phase 2, so it was
    // the most likely casualty: left exactly as `parkSelfFaulted` made
    // it (state `.exited`, gen still ODD, never posted as a zombie), it
    // is then invisible to every reap path forever. Measured at ~8
    // orphaned Threads per suite pass — a per-writer tag showed 100% of the
    // leaked population came from `parkSelfFaulted` — accumulating until
    // the run stops delivering results around pass 11.
    //
    // Doing it here costs nothing and cannot be skipped: the reap only
    // dead-marks and posts a zombie (the finalize is deferred to a core
    // that is provably off the kstack), and the `destroyThreadsInProcess`
    // walk below then skips this thread on its now-even gen rather than via
    // `keep_ref`.
    if (deferred.caller_thread) |caller_ref| {
        // caller-pinned: `deferred.process_ref.ptr` is an identity-only key
        // for the pending-reply comparison inside the destroy helper;
        // the process slot is dead-marked but bytes-intact and is never
        // dereferenced through here.
        stygia.sched.thread.destroyThreadRefLocked(
            caller_ref,
            deferred.process_ref.ptr, // caller-pinned: identity-only key, never dereferenced
        );
    }
    bump(&p2_after_reap, 1); // TEMP DIAGNOSTIC (stygia-afo, REMOVE)

    stygia.sched.thread.destroyThreadsInProcess(
        deferred.process_ref,
        deferred.process_addr_space_root,
        deferred.caller_thread,
    );
    // TEMP DIAGNOSTIC (stygia-afo, REMOVE).
    bump(&p2_walk_done, 1);
    bump(&p2_residue, stygia.sched.thread.countThreadsInProcess(deferred.process_ref));

    // Translation barrier (stygia-rs6): the thread walk above only POSTS
    // zombies + wake IPIs for victims still executing on remote cores.
    // Everything after this point tears down state those victims'
    // cores may still be translating through — `freeUserAddrSpace`
    // most lethally (a core whose CR3/TTBR0 names the dying root dies
    // on its first cold walk once the tables are recycled; reproduced
    // as silent triple faults). Wait until no core has the dying root
    // LOADED (published active_root) nor a dying-process thread COMMITTED
    // in its dispatch slot (current_thread — set before the root load, so
    // it covers in-flight dispatches the publish can't see yet).
    // Victim cores converge within one IRQ delivery: the wake IPI
    // drives them through yieldTo's disowned-current escape into
    // `run()`, which publishes either the next thread's root or 0 (park /
    // kernel root) strictly AFTER the hardware load. Self cannot
    // deadlock this: the detach above published 0 for the self-destroy
    // case, the caller thread is not part of the current_thread clause's
    // process membership (its slot was cleared by parkSelfFaulted or
    // names the caller which IS expected to keep running), and a
    // cross-process destroyer publishes its own (non-dying) root.
    stygia.sched.scheduler.awaitProcessQuiesced(
        deferred.process_addr_space_root.addr,
        // caller-pinned: raw pointer passed as an identity-only key —
        // the barrier compares it against per-core `process.ptr` values
        // and never derefs the (dead-marked, bytes-intact) process slot.
        deferred.process_ref.ptr,
    );

    // Tear down every VMAR bound to the process (stygia-1im: moved here
    // from destroyPhase1 — see the note there). The destroy-path
    // variant clears leaf PTEs (so `freeUserAddrSpace` below can
    // distinguish PF-backed leaves from singleton PMM leaves) and
    // decrements `pf.mapcnt` for every still-installed page_frame, but
    // skips the per-page TLB shootdown. That skip is sound precisely
    // BECAUSE the barrier above has already run: no core has the dying
    // process's root loaded and no core holds a dying-process thread in its
    // dispatch slot, so there is no live translation left to shoot
    // down. Running it before the barrier is what produced the
    // spurious user instruction-fetch faults this ordering fixes.
    //
    // Phase 1 captured `vars[]`, `var_count`, and `addr_space_root` before
    // dead-marking the process. Walk only that snapshot here: after
    // `bumpDeadGenLocked`, the process pointer may be used as an identity token
    // for thread/barrier comparisons, but phase 2 must not dereference it to
    // rediscover teardown work.
    var var_idx = deferred.var_count;
    while (var_idx > 0) {
        var_idx -= 1;
        const v_ref = deferred.vars[var_idx] orelse continue;
        stygia.memory.vmar.destroyVmarDuringProcessTeardown(v_ref, deferred.process_addr_space_root);
    }

    // NOTE (stygia-2u0): the caller-thread reap used to live HERE, at the end
    // of phase 2. It moved to the top of this function — see the long
    // comment there. Anything below the first point that drops the IRQ
    // mask can be skipped entirely by a preempt abandoning this frame,
    // and this reap was the casualty that leaked ~8 Threads per suite pass.
    // `destroyThreadLocked` early-returns on an already-even
    // gen, so the move is safe even if some path reaches both.

    if (deferred.vm_ref) |vm_slab_ref| {
        stygia.hv.virtual_machine.releaseHandleAfterProcessDestroyed(vm_slab_ref.ptr);
    }

    // Walk slots [3..MAX) and apply per-handle release semantics for
    // refcount-lifetime object types (page_frame, port,
    // device_region per spec proposal §3). With the alias-side
    // `incHandleRef`/`onHandleAcquire` in passed_handles processing,
    // every such handle is a real lifetime contributor and must be
    // released here. VMARs are owned by destroyPhase2's `process.vars[]`
    // walk; process / thread / reply / vm are
    // process-or-system-lifetime and have nothing to release here.
    //
    // The gen-validate-under-lock dance: destroyPhase2 runs after
    // destroyPhase1 dropped the process's gen-lock, so concurrent destroys
    // on a port / page_frame / device_region handle can
    // complete in the window. Take the slot's `_gen_lock`; if the
    // stamped `entry.ref.gen` no longer matches the live slab's gen,
    // skip — the object has already been destroyed (and possibly
    // reallocated) by another path.
    const user_table: [*]Capability = @ptrCast(@alignCast(deferred.user_buf));
    const kernel_table: [*]KernelHandle = @ptrCast(@alignCast(deferred.kernel_buf));
    var slot: u16 = 3;
    while (slot < MAX_HANDLES_PER_PROCESS) : (slot += 1) {
        const entry = &kernel_table[slot];
        const obj_ptr = entry.ref.ptr orelse continue;
        const tag = Word0.typeTag(user_table[slot].word0);
        switch (tag) {
            .page_frame => {
                const pf: *stygia.memory.page_frame.PageFrame = @ptrCast(@alignCast(obj_ptr));
                const slot_irq = pf._gen_lock.lockIrqSave(@src());
                if (pf._gen_lock.currentGen() != entry.ref.gen) {
                    pf._gen_lock.unlockIrqRestore(slot_irq);
                    continue;
                }
                stygia.memory.page_frame.releaseHandleLocked(pf, slot_irq);
            },
            .port => {
                const p: *stygia.sched.port.Port = @ptrCast(@alignCast(obj_ptr));
                const slot_irq = p._gen_lock.lockIrqSave(@src());
                if (p._gen_lock.currentGen() != entry.ref.gen) {
                    p._gen_lock.unlockIrqRestore(slot_irq);
                    continue;
                }
                const caps_word = Word0.caps(user_table[slot].word0);
                stygia.sched.port.releaseHandleLocked(p, caps_word, slot_irq);
            },
            .device_region => {
                const dr: *stygia.devices.device_region.DeviceRegion = @ptrCast(@alignCast(obj_ptr));
                const slot_irq = dr._gen_lock.lockIrqSave(@src());
                if (dr._gen_lock.currentGen() != entry.ref.gen) {
                    // Slab slot was already torn down by another path;
                    // our embedded `dr_node` cannot still be on its
                    // (non-existent) handle_list_head. Skip both the
                    // unlink and the dec.
                    dr._gen_lock.unlockIrqRestore(slot_irq);
                    continue;
                }
                // Unlink before the dec so we don't leak a node whose
                // backing handle-table memory is about to be freed by
                // `pmm_mgr.freeBlock(deferred.kernel_buf)` below.
                stygia.devices.device_region.removeHandleListNodeLocked(dr, &entry.dr_node);
                stygia.devices.device_region.releaseHandleLocked(dr, slot_irq);
            },
            else => {},
        }
    }

    // Reclaim user-half page tables and the eagerly-mapped user-stack /
    // ELF / table-view leaves that landed in this address space. The
    // page-table walker frees PT/PD/PDPT/PML4 pages and any leaf
    // physical page that came from a single-page PMM.create — i.e.
    // mapUserStack and loadElfSegments allocations. Page-frame leaves
    // were already cleared by the destroyPhase2 vars[] walk above; the leaves
    // shared with `user_buf` (mapUserTableView aliases the user_buf
    // pages into user space at `table_base`) are skipped via the
    // [user_buf_phys, user_buf_phys + USER_TABLE_BYTES) range so the
    // wholesale freeBlock below isn't double-freeing them.
    const user_buf_phys = stygia.memory.address.PAddr.fromVAddr(
        stygia.memory.address.VAddr.fromInt(@intFromPtr(deferred.user_buf)),
        null,
    );
    arch.paging.freeUserAddrSpace(
        deferred.process_addr_space_root,
        user_buf_phys.addr,
        USER_TABLE_BYTES,
        deferred.user_stack_phys,
        deferred.user_stack_bytes,
    );

    pmm_mgr.freeBlock(deferred.user_buf[0..USER_TABLE_BYTES]);
    pmm_mgr.freeBlock(deferred.kernel_buf[0..KERNEL_TABLE_BYTES]);

    if (deferred.addr_space_id != 0) arch.paging.freeAddrSpaceId(deferred.addr_space_id);

    // Finish the process slot destroy deferred from phase 1 (bumpDeadGenLocked):
    // zero the bytes and return the slot to the freelist. Every thread of the
    // process is gen-dead and evicted (destroyThreadsInProcess + the translation
    // barrier above), so no dispatch or handle path can deref the slot's
    // fields anymore — identity-compare users (`process_for_identity`, the
    // barrier's clause 2) only ever used the raw pointer value.
    // caller-pinned: a lock bracket is impossible by design here — the
    // gen has been even (dead) since phase 1; destroyAlreadyMarked
    // asserts exactly that and this phase-2 tail is the slot's sole
    // owner.
    slab_instance.destroyAlreadyMarked(deferred.process_ref.ptr);
    bump(&p2_exit, 1); // TEMP DIAGNOSTIC (stygia-afo, REMOVE)
}

/// Pop the head of the free-slot list. Returns `null` (E_FULL) if the
/// table is full.
fn allocFreeSlot(process: *Process) ?u12 {
    // TEMP DIAGNOSTIC (stygia-2u0, REMOVE). Handle-table exhaustion is
    // silent: this returns null, the caller maps it to E_FULL, and the
    // suite reports MISS with no marker. MAX_HANDLES_PER_PROCESS is 4096
    // and the runner spawns ~427 processes per pass, so its own table
    // would be exhausted at ~pass 10 — exactly where the collapse
    // starts, and without any allocBlock ever failing (the buddy probe
    // stayed silent through a full collapse).
    if (process.free_count == 0 or process.free_head == stygia.caps.capability.FREE_LIST_TAIL) {
        if (slot_full_prints < 8) {
            slot_full_prints += 1;
            arch.boot.print(
                "[2u0] handle table FULL process=0x{x} free_count={d} free_head={d}\n",
                .{ @intFromPtr(process), process.free_count, process.free_head },
            );
        }
    }
    if (process.free_count == 0) return null;
    const head = process.free_head;
    if (head == stygia.caps.capability.FREE_LIST_TAIL) return null;
    const slot: u12 = @truncate(head);
    const next = stygia.caps.capability.decodeFreeNext(process.kernel_table[slot].parent);
    process.free_head = next;
    process.free_count -= 1;
    return slot;
}

/// Remove one free slot from `process` without publishing a handle into it
/// yet. The non-null reserved sentinel keeps both free-list and
/// contiguous-scan allocators from treating the slot as free, while
/// `resolveHandleOnProcess` keeps it invisible to callers until
/// `mintHandleAt` overwrites it with the returned IPC handle.
fn reserveHandleSlot(process: *Process) !u12 {
    const slot = allocFreeSlot(process) orelse return error.OutOfHandles;
    process.user_table[slot] = .{ .word0 = 0, .field0 = 0, .field1 = 0 };
    process.kernel_table[slot].ref = .{
        .ptr = stygia.caps.capability.RESERVED_HANDLE_SLOT_PTR,
        .gen = 0,
    };
    process.kernel_table[slot].parent = .{};
    process.kernel_table[slot].first_child = .{};
    process.kernel_table[slot].next_sibling = .{};
    process.kernel_table[slot].dr_node = .{};
    return slot;
}

fn releaseReservedHandleSlot(process: *Process, slot: u12) void {
    const entry = &process.kernel_table[slot];
    if (!stygia.caps.capability.isReservedHandleSlot(entry)) return;
    entry.instance +%= 1;
    process.user_table[slot] = .{ .word0 = 0, .field0 = 0, .field1 = 0 };
    entry.ref = .{};
    entry.parent = stygia.caps.capability.encodeFreeNext(process.free_head);
    entry.first_child = .{};
    entry.next_sibling = .{};
    entry.dr_node = .{};
    process.free_head = @as(u16, slot);
    process.free_count += 1;
}

/// Linear scan for an existing handle to `obj` in this process, used
/// to enforce the at-most-one-per-(process, object) invariant.
/// Returns the existing slot id if found.
fn findExistingHandle(process: *Process, obj: ErasedSlabRef, t: CapabilityType) ?u12 {
    var i: u16 = 0;
    while (i < MAX_HANDLES_PER_PROCESS) {
        const entry = &process.kernel_table[i];
        if (entry.ref.ptr != null and entry.ref.ptr == obj.ptr and entry.ref.gen == obj.gen) {
            const tag = Word0.typeTag(process.user_table[i].word0);
            if (tag == t) return @truncate(i);
        }
        i += 1;
    }
    return null;
}

const MintHandleResult = struct {
    slot: u12,
    installed_new: bool,
};

fn mintHandleReporting(
    process: *Process,
    obj: ErasedSlabRef,
    obj_type: CapabilityType,
    caps: u16,
    field0: u64,
    field1: u64,
) !MintHandleResult {
    if (findExistingHandle(process, obj, obj_type)) |existing| {
        return .{ .slot = existing, .installed_new = false };
    }

    const slot = allocFreeSlot(process) orelse return error.OutOfHandles;
    writeHandleSlot(process, slot, obj, obj_type, caps, field0, field1);
    return .{ .slot = slot, .installed_new = true };
}

/// Mint a handle into `process`'s table at a fresh slot. Allocates from the
/// free list, writes both halves, returns the slot id. Coalesces with
/// existing handle to the same object per the at-most-one invariant.
pub fn mintHandle(
    process: *Process,
    obj: ErasedSlabRef,
    obj_type: CapabilityType,
    caps: u16,
    field0: u64,
    field1: u64,
) !u12 {
    return (try mintHandleReporting(process, obj, obj_type, caps, field0, field1)).slot;
}

/// Variant of `mintHandle` that bypasses the at-most-one-per-(process,
/// object) coalescing. Used by §[handle_attachments] recv-time delivery
/// where the spec mandates N contiguous NEW slots `[tstart, tstart+N)`
/// even when the receiver already holds a handle to the same object.
/// Allocates from the free list and writes the slot unconditionally.
pub fn mintHandleAlwaysNew(
    process: *Process,
    obj: ErasedSlabRef,
    obj_type: CapabilityType,
    caps: u16,
    field0: u64,
    field1: u64,
) !u12 {
    const slot = allocFreeSlot(process) orelse return error.OutOfHandles;
    writeHandleSlot(process, slot, obj, obj_type, caps, field0, field1);
    return slot;
}

/// Mint a handle into a specific pre-reserved free slot. Used by the
/// contiguous-slot allocator in `allocContiguousFreeSlots` where the
/// caller has already unlinked the slot from the free list. Bypasses
/// coalescing — the caller has explicitly committed to placing the
/// handle at this slot id (spec §[handle_attachments] tstart..tstart+N).
pub fn mintHandleAt(
    process: *Process,
    slot: u12,
    obj: ErasedSlabRef,
    obj_type: CapabilityType,
    caps: u16,
    field0: u64,
    field1: u64,
) void {
    writeHandleSlot(process, slot, obj, obj_type, caps, field0, field1);
}

fn writeHandleSlot(
    process: *Process,
    slot: u12,
    obj: ErasedSlabRef,
    obj_type: CapabilityType,
    caps: u16,
    field0: u64,
    field1: u64,
) void {
    process.user_table[slot].word0 = Word0.pack(slot, obj_type, caps);
    process.user_table[slot].field0 = field0;
    process.user_table[slot].field1 = field1;
    process.kernel_table[slot].ref = obj;
    process.kernel_table[slot].parent = .{};
    process.kernel_table[slot].first_child = .{};
    process.kernel_table[slot].next_sibling = .{};
    process.kernel_table[slot].dr_node = .{};

    // Spec §[device_irq]: every process-local copy of a device_region
    // handle gets an IRQ-propagation list entry on the parent region.
    // Use the embedded per-handle node so the storage tracks the slot
    // lifetime. `field1_paddr` is the kernel physaddr of the user-table
    // entry's `field1` slot — the futex address userspace recv-blocks
    // on. The user_table block came from `pmm.allocBlock`, so its
    // kernel-VA points into the physmap; `PAddr.fromVAddr(.., null)`
    // recovers the physaddr.
    if (obj_type == .device_region) {
        const dr: *stygia.devices.device_region.DeviceRegion = @ptrCast(@alignCast(obj.ptr.?));
        const field1_va = stygia.memory.address.VAddr.fromInt(
            @intFromPtr(&process.user_table[slot].field1),
        );
        const field1_paddr = stygia.memory.address.PAddr.fromVAddr(field1_va, null);
        stygia.devices.device_region.appendHandleListNode(
            dr,
            &process.kernel_table[slot].dr_node,
            field1_paddr,
        );
    }
}

/// Reserve N contiguous free slots `[base, base+N)` and unlink each
/// from the free-slot list. Returns the starting slot id, or
/// `error.OutOfHandles` if no contiguous run of N slots is available.
/// Used by §[handle_attachments] recv-time delivery; the spec requires
/// the inserted handles occupy a contiguous range and the receiver's
/// syscall word reports `tstart`.
///
/// Walk strategy: scan kernel_table from slot 3 upward for runs of
/// `ref.ptr == null` entries (free slots), then for each candidate run
/// of length ≥ N, splice all N out of the free list. Slots 0/1/2 are
/// reserved and never on the free list. O(N + free_list_walk) per
/// attempted run.
pub fn allocContiguousFreeSlots(process: *Process, n: u8) !u12 {
    if (n == 0) return 0;
    if (process.free_count < n) return error.OutOfHandles;

    var run_start: u16 = 3;
    var i: u16 = 3;
    while (i < MAX_HANDLES_PER_PROCESS) {
        if (process.kernel_table[i].ref.ptr == null) {
            const run_len = i + 1 - run_start;
            if (run_len >= n) {
                // Found a run [run_start, run_start + n). Splice each
                // slot out of the free list. The list is singly-linked;
                // walk it removing matching nodes.
                var k: u16 = 0;
                while (k < n) {
                    const target_slot = run_start + k;
                    unlinkFreeSlot(process, @intCast(target_slot));
                    k += 1;
                }
                return @intCast(run_start);
            }
            i += 1;
        } else {
            run_start = i + 1;
            i += 1;
        }
    }
    return error.OutOfHandles;
}

/// Unlink a specific slot from the free-slot list. Caller has verified
/// the slot is on the list (`kernel_table[slot].ref.ptr == null`).
fn unlinkFreeSlot(process: *Process, slot: u12) void {
    const slot_u16: u16 = slot;
    if (process.free_head == slot_u16) {
        process.free_head = stygia.caps.capability.decodeFreeNext(process.kernel_table[slot].parent);
        process.free_count -= 1;
        return;
    }
    var prev: u16 = process.free_head;
    while (prev != stygia.caps.capability.FREE_LIST_TAIL) {
        const prev_idx: u12 = @truncate(prev);
        const next = stygia.caps.capability.decodeFreeNext(process.kernel_table[prev_idx].parent);
        if (next == slot_u16) {
            const after = stygia.caps.capability.decodeFreeNext(process.kernel_table[slot].parent);
            process.kernel_table[prev_idx].parent = stygia.caps.capability.encodeFreeNext(after);
            process.free_count -= 1;
            return;
        }
        prev = next;
    }
    // Slot was not on the free list — caller violated precondition.
    // Leave free_count unchanged; downstream handle write will still
    // succeed but the slot may double-link next free.
}

/// Read a self-handle ceiling sub-field. All ceilings live in slot-0's
/// `field0`/`field1`; centralized here so future spec changes touch
/// one place.
fn readSelfField0(process: *const Process) u64 {
    return process.user_table[0].field0;
}

/// Append `v` to `vars[var_count]`. Returns E_FULL when at MAX.
pub fn appendVar(process: *Process, v: *VMAR) i64 {
    if (process.var_count >= process.vars.len) return errors.E_FULL;
    process.vars[process.var_count] = SlabRef(VMAR).init(v, v._gen_lock.currentGen());
    process.var_count += 1;
    return 0;
}

/// Remove `v` from `vars` by tail-swap; decrements var_count.
pub fn removeVar(process: *Process, v: *VMAR) void {
    var i: u16 = 0;
    while (i < process.var_count) {
        if (process.vars[i]) |v_ref| {
            // Identity compare: SlabRef.ptr == raw pointer.
            if (v_ref.ptr == v) {
                process.var_count -= 1;
                process.vars[i] = process.vars[process.var_count];
                process.vars[process.var_count] = null;
                return;
            }
        }
        i += 1;
    }
}

/// Linear-scan `vars[]` for any range overlapping `[base, base + bytes)`.
/// Returns E_NOSPC on overlap, 0 otherwise. Spec §[var].create_vmar.
pub fn checkVaRangeOverlap(process: *const Process, base: VAddr, bytes: u64) i64 {
    const new_start = base.addr;
    const new_end = new_start + bytes;
    var i: u16 = 0;
    while (i < process.var_count) {
        const v_ref = process.vars[i] orelse {
            i += 1;
            continue;
        };
        // caller-pinned: VMAR's process ref pins it; process is the owner here.
        const v = v_ref.ptr;
        const sz_bytes: u64 = switch (v.sz) {
            .sz_4k => 0x1000,
            .sz_2m => 0x20_0000,
            .sz_1g => 0x4000_0000,
            ._reserved => 0,
        };
        const v_start = v.base_vaddr.addr;
        const v_end = v_start + @as(u64, v.page_count) * sz_bytes;
        if (new_start < v_end and v_start < new_end) return errors.E_NOSPC;
        i += 1;
    }
    return 0;
}
