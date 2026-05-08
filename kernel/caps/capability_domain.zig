//! Capability domain — set of capabilities usable by execution contexts
//! bound to the domain. See docs/kernel/specv3.md §[capability_domain].
//!
//! Owns:
//!   - Address space (page tables + PCID/ASID)
//!   - Two parallel handle tables (user-visible + kernel-side mirror)
//!   - Flat list of bound VARs
//!   - Optional bound VM
//!
//! All per-domain ceilings (ec_inner/outer, var_inner/outer, cridc, idc_rx,
//! pf, vm, port, restart_policy, fut_wait_max) live in the self-handle at
//! slot 0 of the handle table — kernel reads them from `user_table[0]`
//! like anyone else, no duplication on the struct.
//!
//! ECs bound to this domain are reachable through the handle table (walk
//! looking for type = execution_context) and through whatever pins them
//! (run queue, port wait queue, etc.). No separate ECs array — the spec's
//! `acquire_ecs` is an explicitly slow debugger primitive, the linear walk
//! is fine for it.
//!
//! STUB. Forward refs to VMAR and VirtualMachine point at intended future
//! paths.

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const elf_util = zag.utils.elf;
const errors = zag.syscall.errors;
const execution_context_mod = zag.sched.execution_context;
const pmm = zag.memory.pmm;
const scheduler = zag.sched.scheduler;
const userspace_init = zag.boot.userspace_init;

const Capability = zag.caps.capability.Capability;
const CapabilityType = zag.caps.capability.CapabilityType;
const ErasedSlabRef = zag.caps.capability.ErasedSlabRef;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const KernelHandle = zag.caps.capability.KernelHandle;
const PAddr = zag.memory.address.PAddr;
const PageFrame = zag.memory.page_frame.PageFrame;
const ParsedElf = zag.utils.elf.ParsedElf;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const VMAR = zag.memory.vmar.VMAR;
const VAddr = zag.memory.address.VAddr;
const VirtualMachine = zag.hv.virtual_machine.VirtualMachine;
const Word0 = zag.caps.capability.Word0;

/// Cap bits in `Capability.word0[48..63]` for the capability_domain
/// self-handle (slot 0). Spec §[capability_domain] self handle.
pub const CapabilityDomainCaps = packed struct(u16) {
    crcd: bool = false,
    crec: bool = false,
    crvr: bool = false,
    crpf: bool = false,
    crvm: bool = false,
    crpt: bool = false,
    pmu: bool = false,
    setwall: bool = false,
    power: bool = false,
    restart: bool = false,
    reply_policy: bool = false,
    fut_wake: bool = false,
    timer: bool = false,
    _reserved: u1 = 0,
    pri: u2 = 0,
};

/// Cap bits in `Capability.word0[48..63]` for IDC (capability_domain)
/// handles. Spec §[capability_domain] IDC handle.
pub const IdcCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    crec: bool = false,
    aqec: bool = false,
    aqvr: bool = false,
    restart_policy: u1 = 0,
    _reserved: u10 = 0,
};

const MAX_HANDLES_PER_DOMAIN = zag.caps.capability.MAX_HANDLES_PER_DOMAIN;
const FREE_LIST_TAIL = zag.caps.capability.FREE_LIST_TAIL;

/// Start of the per-domain VMAR bump-allocator range. Placed at 64 GiB
/// so it lives above the boot path's hand-mapped text/data/stack/
/// cap_table regions (which top out near 0x80000000) but inside the
/// 47-bit user half. v0 expedient — see `next_var_base` doc.
pub const NEXT_VAR_BASE_START: u64 = 0x0000_0010_0000_0000;

/// Maximum VARs bindable to a single capability domain. 512 × 8 bytes
/// = 4 KiB inline. Coarse upper bound; well above realistic per-domain
/// VMAR counts (a domain with even a few dozen VARs is unusual).
pub const MAX_VARS_PER_DOMAIN: u16 = 512;

pub const CapabilityDomain = struct {
    /// Slab generation lock. Validates `SlabRef(CapabilityDomain)`
    /// liveness AND guards every mutable field below.
    _gen_lock: GenLock = .{},

    // ── Address space ─────────────────────────────────────────────────

    /// Physical address of this domain's top-level page table (PML4 on
    /// x86-64, TTBR on aarch64). Set at create; immutable.
    addr_space_root: PAddr,

    /// PCID (x86-64) / ASID (aarch64) tag. Set at create; immutable.
    /// Used as the low 12 bits of CR3 (with PCIDE=1) so address-space
    /// switches don't flush TLB entries from other domains.
    addr_space_id: u16,

    // ── Handle tables ────────────────────────────────────────────────
    //
    // Two parallel arrays of MAX_HANDLES_PER_DOMAIN entries, indexed by
    // the same 12-bit handle id.
    //
    //   user_table   — 96 KiB. Mapped read-only into this domain so
    //                  userspace can read cap word + field0/field1 of
    //                  any handle without a syscall. Kernel writes
    //                  field0/field1 to refresh kernel-mutable
    //                  snapshots (EC priority/affinity, VMAR cur_rwx,
    //                  device IRQ counters, etc.) directly through
    //                  the kernel R/W view of the same physical pages.
    //
    //   kernel_table — kernel-only. Holds ErasedSlabRef + revoke
    //                  ancestry tree links (parent / first_child /
    //                  next_sibling) when used, with `parent` doubling
    //                  as the free-slot list link when free.
    //
    // Pointer-based rather than inline so the domain struct itself
    // stays slab-allocatable. Tables are page-aligned PMM allocations
    // made at create_capability_domain time.

    user_table: *[MAX_HANDLES_PER_DOMAIN]Capability,
    kernel_table: *[MAX_HANDLES_PER_DOMAIN]KernelHandle,

    /// Head of the free-slot list. `FREE_LIST_TAIL` (0xFFFF) when the
    /// table is full. Free entries store the next-free slot index in
    /// `kernel_table[i].parent.slot` (see `KernelHandle` doc), terminated
    /// by `FREE_LIST_TAIL`.
    free_head: u16 = FREE_LIST_TAIL,

    /// Number of free slots. Lets `copy`/`acquire_*` early-bail with
    /// `E_FULL` without walking the free list.
    free_count: u16 = MAX_HANDLES_PER_DOMAIN,

    // ── Bound VARs ───────────────────────────────────────────────────

    /// Flat array of VARs bound to this domain. Used for:
    ///   - VA-range overlap check at `create_vmar` (linear scan)
    ///   - Enumeration via `acquire_vmars` (debugger primitive)
    ///   - Walk-and-free at domain destroy
    /// Entries `[0..var_count)` are populated; entries beyond are null.
    /// On removal the tail is moved into the freed slot to keep the
    /// populated prefix dense (no holes to skip).
    vars: [MAX_VARS_PER_DOMAIN]?SlabRef(VMAR) = .{null} ** MAX_VARS_PER_DOMAIN,

    /// Number of populated entries in `vars`. Range 0..MAX_VARS_PER_DOMAIN.
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

    /// VM bound to this domain. Capability-domain lifetime; at most
    /// one per spec (the VM handle is non-transferable, exactly one
    /// holder = the binding domain). `null` on non-VM domains.
    vm: ?SlabRef(VirtualMachine) = null,

    /// Backing of the eagerly-mapped user stack as one contiguous PMM
    /// buddy block. Set by `mapUserStack`; freed wholesale at domain
    /// teardown so the buddy can rejoin a single 4 MiB block instead of
    /// fragmenting into 1024 single-page frees (which broke
    /// `pmm.allocBlock(USER_TABLE_BYTES)` after a few hundred reps when
    /// the test runner kept spawning new domains). 0 when the stack is
    /// not allocated yet (transient init state) or has already been
    /// freed. `freeUserAddrSpace` skips this range so the per-page walk
    /// doesn't double-free.
    user_stack_phys: u64 = 0,
    user_stack_bytes: u64 = 0,
};

pub const Allocator = SecureSlab(CapabilityDomain, 256);
pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

// ── External API ─────────────────────────────────────────────────────

/// `create_capability_domain` syscall handler.
/// Spec §[capability_domain].create_capability_domain.
///
/// v0 implementation focused on getting the test runner's spawnOne path
/// working end-to-end. Behavior:
///   1. Resolve `elf_pf` in the caller's table; bail E_BADCAP if missing.
///   2. Read ELF bytes from the page frame's kernel mapping (physmap VA).
///   3. allocCapabilityDomain with self caps from `caps[0..15]` and the
///      passed ceilings_inner/outer.
///   4. loadElfSegments / mapUserStack / mapUserTableView from boot
///      reused — the child gets the ELF segments mapped at their
///      p_vaddr, a fresh user stack at ROOT_USER_STACK_TOP, and a
///      read-only view of the cap table at ROOT_USER_TABLE_BASE.
///   5. allocExecutionContext for the initial EC; patch its iret frame
///      so RDI = ROOT_USER_TABLE_BASE (per spec — the entry point's
///      first arg is a pointer to the read-only cap-table view).
///   6. For each entry in passed_handles[0..], derive into child slot
///      3+ via mintHandle. `move = 1` releases the source handle.
///   7. Mint the IDC handle into the caller's domain pointing at the
///      new child; return its slot in vreg 1 / via i64.
///   8. Enqueue the initial EC for dispatch.
///
/// Spec validation tests 01-18 are NOT exhaustively enforced yet —
/// reserved-bit and ceiling-subset checks are coarse. The runner exercises
/// the success path; the per-test E_INVAL/E_PERM coverage lands once the
/// boot loop demonstrably runs assertions.
pub fn createCapabilityDomain(
    caller: *ExecutionContext,
    caps: u64,
    ceilings_inner: u64,
    ceilings_outer: u64,
    elf_pf: u64,
    initial_ec_affinity: u64,
    passed_handles: []const u64,
) i64 {
    if (elf_pf & ~@as(u64, 0xFFF) != 0) return errors.E_INVAL;

    const caller_dom = caller.domain.ptr; // caller-pinned: caller is the running EC; its domain stays alive across this syscall

    // Resolve the ELF page frame in the caller's table. Spec §[14].
    const pf_slot: u12 = @truncate(elf_pf & 0xFFF);
    const pf_kh = zag.caps.capability.resolveHandleOnDomain(
        caller_dom,
        pf_slot,
        .page_frame,
    ) orelse return errors.E_BADCAP;
    const pf: *PageFrame = @ptrCast(@alignCast(pf_kh.ref.ptr.?));

    // Read the ELF bytes through the kernel physmap mapping of the page
    // frame's backing pages. The page frame's contents are contiguous in
    // physical memory (allocBlock returned a power-of-two block) so a
    // single physmap-VA pointer covers it.
    const pf_bytes_total: u64 = @as(u64, pf.page_count) * pageFrameSizeBytes(pf.sz);
    const pf_kernel_va = VAddr.fromPAddr(pf.phys_base, null).addr;
    const elf_bytes = @as([*]u8, @ptrFromInt(pf_kernel_va))[0..pf_bytes_total];

    var parsed: ParsedElf = undefined;
    elf_util.parseElf(&parsed, elf_bytes) catch return errors.E_INVAL;

    // Spec §[create_capability_domain] test 16a: ELF must be PIE
    // (e_type == ET_DYN) so the kernel can place it at a randomized
    // base in the ASLR zone (§[address_space]).
    if (parsed.e_type != @intFromEnum(std.elf.ET.DYN)) return errors.E_INVAL;

    // Spec §[address_space]: pick randomized non-overlapping bases
    // for the ELF image, the user stack, and the read-only cap-table
    // view. Each lives inside the ASLR zone.
    //   - ElfPhdrFileSizeExceeds → spec §[create_capability_domain]
    //     [test 16]: a PT_LOAD declares more file bytes than the
    //     staged page frame supplies. Surfaces as E_INVAL.
    //   - ElfHasNoLoadableSegments / parse errors are also INVAL inputs.
    //   - OutOfMemory (no slot in ASLR zone) is the only NOMEM here.
    const layout = userspace_init.resolveDomainLayout(elf_bytes) catch |err| switch (err) {
        error.OutOfMemory => return errors.E_NOMEM,
        else => return errors.E_INVAL,
    };
    const slid_entry = VAddr.fromInt(parsed.entry.addr + layout.elf_slide);

    // Allocate the child capability domain. Self caps come from caps[0..15];
    // self-handle field0 layout differs from the [2] ceilings_inner shape —
    // §[capability_domain] Self handle puts idc_rx at field0 bits 32-39,
    // sourced from [1] caps bits 16-23, with pf/vm/port ceilings shifted
    // up by 8 bits relative to ceilings_inner. See spec
    // §[create_capability_domain] doc for the [2] layout vs §[capability_domain]
    // for the field0 layout.
    const self_caps: u16 = @truncate(caps & 0xFFFF);
    const idc_rx: u64 = (caps >> 16) & 0xFF;
    const ec_var_cridc: u64 = ceilings_inner & 0x0000_0000_FFFF_FFFF;
    const pf_vm_port: u64 = (ceilings_inner >> 32) & 0x0000_0000_00FF_FFFF;
    const self_field0: u64 = ec_var_cridc | (idc_rx << 32) | (pf_vm_port << 40);
    const child_cd = allocCapabilityDomain(
        self_caps,
        self_field0,
        ceilings_outer,
        slid_entry,
    ) catch return errors.E_NOMEM;

    // Re-mirror kernel-half PML4 entries into the child's PML4 (per
    // boot's userspace_init — fresh L3/L2 paging structures the kernel
    // installs for its own data only land in the kernel root; without
    // this re-mirror the child's iret epilogue's stack pop faults on
    // the kernel stack VA).
    const child_root_virt = VAddr.fromPAddr(child_cd.addr_space_root, null);
    zag.arch.dispatch.paging.copyKernelMappings(child_root_virt);

    // Past this point, every error must tear `child_cd` down. The CD's
    // gen-lock is published-live (alloc returned successfully), so a
    // bare `return errors.E_NOMEM` without cleanup leaks the
    // user_table / kernel_table PMM blocks plus any ECs that were
    // allocated before the failing step. Spec-test runs that exercise
    // the failure paths in `loadElfSegments` / `mapUserStack` /
    // `allocExecutionContext` / `mintHandle` accumulated ~5 leaked CDs
    // per rep before this teardown was added — slabs filled and the
    // 11th rep wedged at `timer_rearm_05..08` once handle-table /
    // PCID exhaustion gated the next createPort/createTimer.

    // Load ELF segments into the child's address space.
    userspace_init.loadElfSegments(child_cd, elf_bytes, &parsed, layout.elf_slide) catch {
        cleanupPartiallyCreatedCd(child_cd, null);
        return errors.E_NOMEM;
    };
    userspace_init.mapUserStack(child_cd, layout.stack_top) catch {
        cleanupPartiallyCreatedCd(child_cd, null);
        return errors.E_NOMEM;
    };
    userspace_init.mapUserTableView(child_cd, layout.table_base) catch {
        cleanupPartiallyCreatedCd(child_cd, null);
        return errors.E_NOMEM;
    };

    // Allocate the initial EC bound to the child domain. Entry =
    // slid_entry; affinity from spec §[create_capability_domain] [5];
    // priority = normal.
    const child_ec = execution_context_mod.allocExecutionContext(
        child_cd,
        slid_entry,
        16, // user stack pages — same as boot's root stack reservation
        initial_ec_affinity,
        .normal,
        null,
        null,
    ) catch {
        cleanupPartiallyCreatedCd(child_cd, null);
        return errors.E_NOMEM;
    };

    // Patch the initial EC's iret frame for user-mode dispatch.
    zag.arch.dispatch.cpu.patchUserModeIretFrame(
        child_ec.ctx,
        slid_entry,
        VAddr.fromInt(layout.stack_top),
        layout.table_base,
    );

    // Mint slot-1 EC handle in the child for the initial EC. Caps =
    // ec_inner_ceiling from ceilings_inner bits 0-7 per spec §[20].
    const ec_inner: u16 = @truncate(ceilings_inner & 0xFF);
    child_cd.user_table[1].word0 = Word0.pack(1, .execution_context, ec_inner);
    child_cd.user_table[1].field0 = 0;
    child_cd.user_table[1].field1 = 0;
    child_cd.kernel_table[1].ref = .{
        .ptr = child_ec,
        .gen = @intCast(child_ec._gen_lock.currentGen()),
    };
    child_cd.kernel_table[1].parent = .{};
    child_cd.kernel_table[1].first_child = .{};
    child_cd.kernel_table[1].next_sibling = .{};

    // Process passed_handles into child slots 3+.
    //
    // SPEC AMBIGUITY: spec §[create_capability_domain] declares
    // `[5+] passed_handles` but does not encode a count anywhere
    // (no syscall-word count subfield, no terminator). The kernel
    // dispatcher hands us the full vreg-5..13 slice unconditionally.
    // Convention adopted here: an all-zero entry terminates the list.
    // The runner always passes a non-zero packed-entry (caps != 0 or
    // move != 0) for live entries, so this is unambiguous in practice.
    var pass_idx: usize = 0;
    while (pass_idx < passed_handles.len) {
        const entry = passed_handles[pass_idx];
        if (entry == 0) break;
        const src_slot: u12 = @truncate(entry & 0xFFF);
        const new_caps: u16 = @truncate((entry >> 16) & 0xFFFF);
        const move = ((entry >> 32) & 0x1) != 0;

        const src_kh = zag.caps.capability.resolveHandleOnDomain(
            caller_dom,
            src_slot,
            null,
        ) orelse {
            cleanupPartiallyCreatedCd(child_cd, child_ec);
            return errors.E_BADCAP;
        };

        const src_user = caller_dom.user_table[src_slot];
        const src_type = Word0.typeTag(src_user.word0);

        _ = mintHandle(
            child_cd,
            src_kh.ref,
            src_type,
            new_caps,
            src_user.field0,
            src_user.field1,
        ) catch {
            cleanupPartiallyCreatedCd(child_cd, child_ec);
            return errors.E_FULL;
        };

        // For refcount-lifetime types (page_frame, timer, port,
        // device_region per spec proposal §3) the new alias is a real
        // lifetime contributor: bump the object-side refcount so the
        // child's destroyPhase2 kernel_table walk sees a balanced
        // mint/release pair and a `delete` of the source handle in
        // the caller cannot destroy the object out from under the
        // child. observed_zero is structurally impossible here — the
        // caller's source handle pins the object — so failures are
        // unreachable.
        switch (src_type) {
            .page_frame => {
                const alias_pf: *zag.memory.page_frame.PageFrame = @ptrCast(@alignCast(src_kh.ref.ptr.?));
                zag.memory.page_frame.incHandleRef(alias_pf) catch unreachable;
            },
            .timer => {
                const alias_t: *zag.sched.timer.Timer = @ptrCast(@alignCast(src_kh.ref.ptr.?));
                zag.sched.timer.incHandleRef(alias_t) catch unreachable;
            },
            .port => {
                const alias_p: *zag.sched.port.Port = @ptrCast(@alignCast(src_kh.ref.ptr.?));
                const port_irq = alias_p._gen_lock.lockIrqSave(@src());
                defer alias_p._gen_lock.unlockIrqRestore(port_irq);
                zag.sched.port.onHandleAcquire(alias_p, new_caps) catch unreachable;
            },
            .device_region => {
                const alias_dr: *zag.devices.device_region.DeviceRegion = @ptrCast(@alignCast(src_kh.ref.ptr.?));
                zag.devices.device_region.incHandleRef(alias_dr) catch unreachable;
            },
            else => {},
        }

        if (move) {
            // move=1: remove the source handle from the caller's table.
            // The alias bump above is the new owner's ref; the caller's
            // old handle goes away, so balance with a matching release.
            switch (src_type) {
                .page_frame => zag.memory.page_frame.releaseHandle(@ptrCast(@alignCast(src_kh.ref.ptr.?))),
                .timer => zag.sched.timer.decHandleRef(@ptrCast(@alignCast(src_kh.ref.ptr.?))),
                .port => {
                    const p: *zag.sched.port.Port = @ptrCast(@alignCast(src_kh.ref.ptr.?));
                    const src_caps_word: u16 = @truncate(src_user.word0 >> 48);
                    zag.sched.port.releaseHandle(p, src_caps_word);
                },
                .device_region => {
                    // Unlink the source slot's IRQ-propagation node
                    // before dropping the per-handle refcount; see the
                    // matching path in `caps.capability.releaseHandle`.
                    const dr: *zag.devices.device_region.DeviceRegion =
                        @ptrCast(@alignCast(src_kh.ref.ptr.?));
                    const dr_irq = dr._gen_lock.lockIrqSave(@src());
                    zag.devices.device_region.removeHandleListNodeLocked(dr, &caller_dom.kernel_table[src_slot].dr_node);
                    zag.devices.device_region.releaseHandleLocked(dr, dr_irq);
                },
                else => {},
            }
            caller_dom.user_table[src_slot] = .{ .word0 = 0, .field0 = 0, .field1 = 0 };
            caller_dom.kernel_table[src_slot].ref = .{};
        }

        pass_idx += 1;
    }

    // Mint the IDC handle in the CALLER's table that references the new
    // child domain. Per spec §[19]: caps = caller's cridc_ceiling.
    const caller_cridc: u16 = @truncate((readSelfField0(caller_dom) >> 24) & 0xFF);
    const idc_slot = mintHandle(
        caller_dom,
        .{
            .ptr = child_cd,
            .gen = @intCast(child_cd._gen_lock.currentGen()),
        },
        .capability_domain,
        caller_cridc,
        0,
        0,
    ) catch {
        cleanupPartiallyCreatedCd(child_cd, child_ec);
        return errors.E_FULL;
    };

    // Enqueue the initial EC on a core that satisfies its affinity
    // mask. With affinity = 0 (any core) or a mask containing the
    // calling core, prefer the calling core; otherwise use the lowest
    // bit set in the mask. The scheduler's pull path can still migrate
    // it later. Spec §[create_capability_domain] [5].
    const calling_core: u64 = arch.smp.coreID();
    const enqueue_core: u64 = blk: {
        if (initial_ec_affinity == 0) break :blk calling_core;
        if ((initial_ec_affinity >> @intCast(calling_core)) & 1 != 0) {
            break :blk calling_core;
        }
        break :blk @ctz(initial_ec_affinity);
    };
    scheduler.enqueueOnCore(@intCast(enqueue_core), child_ec);

    // Spec §[error_codes] / §[capabilities]: success returns the
    // packed Word0 (id | type<<12 | caps<<48) so the type tag in bits
    // 12..15 always disambiguates a real handle word from the error
    // range 1..15. Returning the bare slot would alias slots 1..15
    // with the spec error codes, so userspace's standard error check
    // would treat valid handle slots as failures.
    return @intCast(Word0.pack(idc_slot, .capability_domain, caller_cridc));
}

inline fn pageFrameSizeBytes(sz: zag.memory.vmar.PageSize) u64 {
    return switch (sz) {
        .sz_4k => 0x1000,
        .sz_2m => 0x200000,
        .sz_1g => 0x40000000,
        ._reserved => unreachable,
    };
}

/// Tear down a partially-constructed CD whose `createCapabilityDomain`
/// hit a post-`allocCapabilityDomain` error. The CD is published-live
/// at this point (gen-lock is odd / unlocked), so the destroy follows
/// the standard `destroyPhase1` → `destroyPhase2` path. The optional
/// `partial_ec` is the initial EC that was alloc'd before the failing
/// step but never published into a handle (slot 1 of the child's table
/// may or may not have been written). Phase 2's `destroyEcsInDomain`
/// walks the EC slab matching `(cd, gen)` and reaps every EC bound to
/// this CD — so even the still-`.ready`-but-not-yet-enqueued initial
/// EC is reaped here. Spec §[create_capability_domain] failure paths
/// must not leak the freshly-allocated CD; without this cleanup the
/// kernel slab class fills after ~10 reps of the test runner and any
/// subsequent `createPort` / `createTimer` returns E_NOMEM.
fn cleanupPartiallyCreatedCd(cd: *CapabilityDomain, partial_ec: ?*ExecutionContext) void {
    _ = partial_ec; // covered by destroyEcsInDomain's slab-walk match
    const cd_gen = cd._gen_lock.currentGen();
    const cd_ref: SlabRef(CapabilityDomain) = .{ .ptr = cd, .gen = @intCast(cd_gen) };
    const lr = cd_ref.lockIrqSave(@src()) catch return;
    // destroyPhase1 runs under cd._gen_lock and ends by releasing it
    // via destroyLocked (gen flips to even). Restore IRQ state
    // manually because the deferred unlockIrqRestore would assert on
    // the just-cleared lock bit. Mirrors the slot==0 SLOT_SELF path
    // in derivation.deleteAndDetach.
    const deferred = destroyPhase1(cd, null);
    arch.cpu.restoreInterrupts(lr.irq_state);
    destroyPhase2(deferred);
}


/// `acquire_ecs` syscall handler.
/// Spec §[capability_domain].acquire_ecs.
///
/// Walks the target IDC's referenced domain enumerating non-vCPU ECs,
/// mints a handle in the caller's table for each (caps =
/// `target.ec_outer_ceiling` ∩ `idc.ec_cap_ceiling`), writes the slot
/// ids into vregs `[1..N]`, and returns N in the syscall word's count
/// field (bits 12-19).
///
/// On the wire:
///   - Vreg 1 (rax / x0) carries the first handle word (caps + type +
///     slot via Word0.pack); userspace disambiguates against the
///     §[error_codes] 1..15 range using the type tag in bits 12-15.
///     N == 0 surfaces as `errors.OK` in vreg 1 and count=0 in the
///     syscall word — no handles to write back.
///   - Vregs 2..min(N, 5) reuse the existing `setSyscallVreg{2,3,4,5}`
///     helpers. v0 spawns one EC per test domain, so N is bounded at 1
///     in the spec test surface; vregs 6+ remain TODO until a test
///     spawns a multi-EC domain through acquire_ecs.
pub fn acquireEcs(caller: *ExecutionContext, target_idc: u64) i64 {
    const cd_ref = caller.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    defer cd_ref.unlockIrqRestore(lr.irq_state);

    // Re-resolve the IDC handle's referenced domain. acquireDispatch
    // already validated the slot's type tag and the aqec cap; we need
    // the kernel-side ref to walk the target's handle table.
    const slot: u12 = @truncate(target_idc & 0xFFF);
    const target_ref_ptr = cd.kernel_table[slot].ref.ptr orelse return errors.E_BADCAP;
    const target_cd: *CapabilityDomain = @ptrCast(@alignCast(target_ref_ptr));

    // Self-IDC is the only target shape exercised by spec tests 04-07
    // (the runner provisions slot 2 to point at the caller's own
    // domain). Cross-domain acquire requires a second GenLock acquire
    // with a stable ordering against the caller's lock and is left for
    // when a non-self-IDC test surfaces it. For now bail E_BADCAP so
    // an unimplemented call site is loud rather than silently wrong.
    if (target_cd != cd) return errors.E_BADCAP;

    // Spec §[acquire_ecs] [test 06]: each minted EC handle gets caps =
    // `target.ec_outer_ceiling` ∩ `idc.ec_cap_ceiling`.
    //   - target.ec_outer_ceiling lives in slot-0 self-handle field1
    //     bits 0-7 (ceilings_outer layout).
    //   - idc.ec_cap_ceiling lives in user_table[slot].field0 bits 0-15.
    const ec_outer_ceiling: u16 = @truncate(target_cd.user_table[0].field1 & 0xFF);
    const idc_ec_cap_ceiling: u16 = @truncate(cd.user_table[slot].field0 & 0xFFFF);
    const minted_caps: u16 = ec_outer_ceiling & idc_ec_cap_ceiling;

    // EC enumeration. Handle-table walks find every EC bound to the
    // target whose handle is still alive; the calling EC is always a
    // non-vCPU member of its own domain even when its self-handle has
    // been deleted (spec §[self] [test 01] — the test exercises that
    // exact shape via `acquire_ecs(SLOT_SELF_IDC)` after dropping the
    // initial-EC handle). Track seen EC pointers so we don't double-
    // mint the calling EC if its handle still exists.
    //
    // E_FULL pre-check ([test 04]): scan once to count, ensuring no
    // partial-mint state if the table is too small. The mint loop
    // re-walks rather than caching pointers because the count loop
    // reads through user_table whose word0 type tag is the
    // discriminator, while mint needs the kernel_table ref.
    var ec_count: u32 = 0;
    {
        var j: u16 = 0;
        var caller_seen: bool = false;
        while (j < zag.caps.capability.MAX_HANDLES_PER_DOMAIN) : (j += 1) {
            const tag = Word0.typeTag(target_cd.user_table[j].word0);
            if (tag != .execution_context) continue;
            const ec_ptr = target_cd.kernel_table[j].ref.ptr orelse continue;
            const ec_obj: *ExecutionContext = @ptrCast(@alignCast(ec_ptr));
            if (ec_obj.vm != null) continue;
            if (ec_obj == caller) caller_seen = true;
            ec_count += 1;
        }
        if (!caller_seen and target_cd == cd and caller.vm == null) ec_count += 1;
    }
    if (cd.free_count < ec_count) return errors.E_FULL;

    var minted_slots: [13]u12 = undefined;
    var n: u8 = 0;
    var seen_caller: bool = false;

    var i: u16 = 0;
    while (i < zag.caps.capability.MAX_HANDLES_PER_DOMAIN) : (i += 1) {
        const tag = Word0.typeTag(target_cd.user_table[i].word0);
        if (tag != .execution_context) continue;
        const ec_ref = target_cd.kernel_table[i].ref;
        const ec_ptr = ec_ref.ptr orelse continue;
        const ec_obj: *ExecutionContext = @ptrCast(@alignCast(ec_ptr));
        if (ec_obj.vm != null) continue; // [test 07] excludes vCPUs

        if (ec_obj == caller) seen_caller = true;
        if (n >= minted_slots.len) break; // TODO: vreg 6+ writeback
        const new_slot = mintHandle(
            cd,
            ec_ref,
            .execution_context,
            minted_caps,
            0, // EC handle field0/field1 carry priority/affinity/etc.
            0, // refreshed lazily by `sync`; zero-init is fine for v0.
        ) catch return errors.E_FULL;
        minted_slots[n] = new_slot;
        n += 1;
    }

    // Always include the calling EC when its domain matches the target.
    // The handle-table scan above misses an EC that has had every
    // handle to it deleted (the at-most-one invariant + prior `delete`
    // → no handle in the table → no scan hit), but the EC object is
    // still bound to the domain and the spec requires its enumeration.
    if (!seen_caller and target_cd == cd and caller.vm == null and n < minted_slots.len) {
        // Coalescing in `mintHandle.findExistingHandle` matches by
        // (ptr, gen, type) — must use the EC's own gen so subsequent
        // ops via the minted handle resolve correctly through SlabRef.
        const caller_ref: ErasedSlabRef = .{
            .ptr = @ptrCast(caller),
            .gen = @intCast(caller._gen_lock.currentGen()),
        };
        const new_slot = mintHandle(
            cd,
            caller_ref,
            .execution_context,
            minted_caps,
            0,
            0,
        ) catch return errors.E_FULL;
        minted_slots[n] = new_slot;
        n += 1;
    }

    // Stage the syscall-word count writeback. The dispatch path flushes
    // `pending_event_word` to user `[rsp+0]` after the handler returns,
    // matching how recv delivers its composed return word.
    const count_field: u64 = @as(u64, n) << 12;
    caller.pending_event_word = count_field;
    caller.pending_event_word_valid = true;

    // Vregs 2..N — use the existing helpers for the secondary slots.
    // Vreg 1 rides the i64 return value below.
    if (n >= 2) arch.syscall.setSyscallVreg2(caller.ctx, packHandleWord(minted_slots[1], minted_caps));
    if (n >= 3) arch.syscall.setSyscallVreg3(caller.ctx, packHandleWord(minted_slots[2], minted_caps));
    if (n >= 4) arch.syscall.setSyscallVreg4(caller.ctx, packHandleWord(minted_slots[3], minted_caps));
    if (n >= 5) arch.syscall.setEventVreg5(caller.ctx, packHandleWord(minted_slots[4], minted_caps));

    if (n == 0) return @bitCast(@as(i64, errors.OK));
    return @intCast(packHandleWord(minted_slots[0], minted_caps));
}

inline fn packHandleWord(slot: u12, caps_word: u16) u64 {
    return Word0.pack(slot, .execution_context, caps_word);
}

/// `acquire_vmars` syscall handler.
/// Spec §[capability_domain].acquire_vmars.
///
/// Enumerates `map=1` (page_frame) and `map=3` (demand) VARs bound to the
/// target IDC's referenced domain. MMIO and DMA-only VARs (`map=0` / `map=2`)
/// are excluded — see §[acquire_vmars] [test 07].
pub fn acquireVmars(caller: *ExecutionContext, target_idc: u64) i64 {
    const cd_ref = caller.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    defer cd_ref.unlockIrqRestore(lr.irq_state);

    // Re-resolve the IDC handle's referenced domain. acquireDispatch
    // already validated the slot's type tag and the aqvr cap.
    const slot: u12 = @truncate(target_idc & 0xFFF);
    const target_ref_ptr = cd.kernel_table[slot].ref.ptr orelse return errors.E_BADCAP;
    const target_cd: *CapabilityDomain = @ptrCast(@alignCast(target_ref_ptr));

    // Self-IDC is the only target shape exercised by spec tests 04-07
    // (the runner provisions slot 2 to point at the caller's own domain).
    // Cross-domain acquire requires a second GenLock acquire with stable
    // ordering against the caller's lock and is left for when a non-self-
    // IDC test surfaces it.
    if (target_cd != cd) return errors.E_BADCAP;

    // Spec §[acquire_vmars] [test 06]: each minted VMAR handle gets caps =
    // `target.vmar_outer_ceiling` ∩ `idc.vmar_cap_ceiling`.
    //   - target.vmar_outer_ceiling lives in slot-0 self-handle field1
    //     bits 8-15 (ceilings_outer layout).
    //   - idc.vmar_cap_ceiling lives in user_table[slot].field0 bits 16-23.
    const vmar_outer_ceiling: u16 = @truncate((target_cd.user_table[0].field1 >> 8) & 0xFF);
    const idc_var_cap_ceiling: u16 = @truncate((cd.user_table[slot].field0 >> 16) & 0xFF);
    const minted_caps: u16 = vmar_outer_ceiling & idc_var_cap_ceiling;

    // E_FULL pre-check ([test 04]): count eligible VARs once. Eligible =
    // map ∈ {page_frame, demand}. The `vars[]` array tracks every VMAR
    // bound to the domain; coalescing in `mintHandle` deduplicates against
    // any existing handle in the caller's table.
    var var_count: u32 = 0;
    {
        var j: u16 = 0;
        while (j < target_cd.var_count) : (j += 1) {
            const v_ref = target_cd.vars[j] orelse continue;
            // caller-pinned: VMAR's domain ref pins it for the
            // duration of this walk (target_cd's gen-lock is held).
            const v = v_ref.ptr;
            switch (v.map) {
                .page_frame, .demand => var_count += 1,
                else => {},
            }
        }
    }
    if (cd.free_count < var_count) return errors.E_FULL;

    var minted_slots: [13]u12 = undefined;
    var n: u8 = 0;

    var i: u16 = 0;
    while (i < target_cd.var_count) : (i += 1) {
        const v_ref = target_cd.vars[i] orelse continue;
        // caller-pinned: see prior loop.
        const v = v_ref.ptr;
        switch (v.map) {
            .page_frame, .demand => {},
            else => continue, // [test 07]: exclude MMIO and unmapped/DMA-only
        }

        if (n >= minted_slots.len) break; // TODO: vreg 6+ writeback

        const var_field0: u64 = v.base_vaddr.addr;
        const vmar_field1: u64 = zag.memory.vmar.packField1(
            v.page_count,
            v.sz,
            v.cch,
            v.cur_rwx,
            v.map,
            0, // device_id: VARs eligible here are pf/demand, not MMIO/DMA
        );

        const var_ref: ErasedSlabRef = .{
            .ptr = @ptrCast(v),
            .gen = @intCast(v._gen_lock.currentGen()),
        };
        // Spec §[acquire_vmars] [test 06] says the returned handle has
        // caps = `vmar_outer_ceiling ∩ vmar_cap_ceiling`. If a handle
        // to this VMAR already exists in the caller's table (the
        // at-most-one-per-(domain,object) invariant + self-IDC case
        // means the create_vmar-minted handle is already there), the
        // coalescing path in mintHandle returns that existing slot
        // with its original caps. Detect that case and overwrite caps
        // / field0 / field1 to the spec-required intersection so the
        // handle reflects what acquire_vmars promises.
        const new_slot = mintHandle(
            cd,
            var_ref,
            .virtual_memory_address_region,
            minted_caps,
            var_field0,
            vmar_field1,
        ) catch return errors.E_FULL;
        cd.user_table[new_slot].word0 = Word0.pack(new_slot, .virtual_memory_address_region, minted_caps);
        cd.user_table[new_slot].field0 = var_field0;
        cd.user_table[new_slot].field1 = vmar_field1;
        minted_slots[n] = new_slot;
        n += 1;
    }

    // Stage the syscall-word count writeback. The dispatch path flushes
    // `pending_event_word` to user `[rsp+0]` after the handler returns.
    const count_field: u64 = @as(u64, n) << 12;
    caller.pending_event_word = count_field;
    caller.pending_event_word_valid = true;

    // Vregs 2..5 — Vreg 1 rides the i64 return value below.
    if (n >= 2) arch.syscall.setSyscallVreg2(caller.ctx, packHandleWord(minted_slots[1], minted_caps));
    if (n >= 3) arch.syscall.setSyscallVreg3(caller.ctx, packHandleWord(minted_slots[2], minted_caps));
    if (n >= 4) arch.syscall.setSyscallVreg4(caller.ctx, packHandleWord(minted_slots[3], minted_caps));
    if (n >= 5) arch.syscall.setEventVreg5(caller.ctx, packHandleWord(minted_slots[4], minted_caps));

    if (n == 0) return @bitCast(@as(i64, errors.OK));
    return @intCast(packHandleWord(minted_slots[0], minted_caps));
}

// ── Internal API ─────────────────────────────────────────────────────

/// Round handle-table size up to a power-of-two-page block. Buddy
/// `allocBlock` requires power-of-two multiples of 4 KiB. Wastes some
/// memory at the tail but keeps the alloc path simple.
fn handleTableBlockBytes(comptime T: type) u64 {
    const raw: u64 = @as(u64, MAX_HANDLES_PER_DOMAIN) * @sizeOf(T);
    const pages: u64 = (raw + 0xFFF) / 0x1000;
    var pow: u64 = 1;
    while (pow < pages) pow <<= 1;
    return pow * 0x1000;
}

const USER_TABLE_BYTES: u64 = handleTableBlockBytes(Capability);
const KERNEL_TABLE_BYTES: u64 = handleTableBlockBytes(KernelHandle);

/// Allocate a new CapabilityDomain — slab slot, handle tables from PMM,
/// address-space root, slot-0 self-handle, slot-1 placeholder for the
/// initial EC handle (filled by caller via `mintHandle`), slot-2 self-IDC.
/// Spec §[capability_domain].
pub fn allocCapabilityDomain(
    self_caps: u16,
    field0_ceilings: u64,
    field1_ceilings: u64,
    initial_entry: VAddr,
) !*CapabilityDomain {
    _ = initial_entry;

    const pending = try slab_instance.create();
    const cd = pending.ptr;
    const cd_gen = pending.pending_gen;
    // Pending slot is off the freelist but at even gen — return it
    // via `destroyAlreadyMarked` (which expects even gen) on any
    // initialization-time error before `publish`.
    errdefer slab_instance.destroyAlreadyMarked(cd);

    const pmm_mgr = if (pmm.global_pmm) |*p| p else return error.OutOfMemory;

    // Handle tables live in kernel physmap RAM. PMM zero-on-free
    // guarantees the pages come up cleared.
    const user_buf = pmm_mgr.allocBlock(USER_TABLE_BYTES) orelse return error.OutOfMemory;
    errdefer pmm_mgr.freeBlock(user_buf[0..USER_TABLE_BYTES]);
    const kernel_buf = pmm_mgr.allocBlock(KERNEL_TABLE_BYTES) orelse return error.OutOfMemory;
    errdefer pmm_mgr.freeBlock(kernel_buf[0..KERNEL_TABLE_BYTES]);

    const user_table: *[MAX_HANDLES_PER_DOMAIN]Capability = @ptrCast(@alignCast(user_buf));
    const kernel_table: *[MAX_HANDLES_PER_DOMAIN]KernelHandle = @ptrCast(@alignCast(kernel_buf));

    cd.user_table = user_table;
    cd.kernel_table = kernel_table;

    // Free-list links cover slots 3..MAX-1; slots 0/1/2 are reserved by
    // spec and are NOT on the free list.
    var i: u16 = 3;
    while (i < MAX_HANDLES_PER_DOMAIN - 1) {
        kernel_table[i].parent = zag.caps.capability.encodeFreeNext(i + 1);
        i += 1;
    }
    kernel_table[MAX_HANDLES_PER_DOMAIN - 1].parent =
        zag.caps.capability.encodeFreeNext(zag.caps.capability.FREE_LIST_TAIL);
    cd.free_head = 3;
    cd.free_count = MAX_HANDLES_PER_DOMAIN - 3;
    cd.var_count = 0;
    cd.next_var_base = NEXT_VAR_BASE_START;
    cd.vm = null;
    @memset(cd.vars[0..], null);

    // Address space root + ASID. The new domain needs a fresh page-table
    // root so the ELF + handle tables can be installed; the ASID tags TLB
    // entries.
    cd.addr_space_root = try arch.paging.allocAddrSpaceRoot();
    cd.addr_space_id = arch.paging.allocAddrSpaceId() orelse 0;

    // Slot 0 — self-handle. Carries ceilings + caps; the rest of the
    // kernel reads them back through `user_table[0]` per the doc on
    // `CapabilityDomain.user_table`.
    user_table[0].word0 = Word0.pack(0, .capability_domain_self, self_caps);
    user_table[0].field0 = field0_ceilings;
    user_table[0].field1 = field1_ceilings;
    kernel_table[0].ref = .{
        .ptr = cd,
        .gen = @intCast(cd_gen),
    };

    // Slot 1 — placeholder for the initial EC handle; populated by the
    // caller (root bringup or `create_capability_domain`).
    user_table[1] = .{ .word0 = 0, .field0 = 0, .field1 = 0 };
    kernel_table[1].ref = .{};

    // Slot 2 — self-IDC. Caps = `cridc_ceiling` from field0_ceilings
    // bits 24-31 per spec §[cridc_ceiling]. The IDC's per-handle
    // `ec_cap_ceiling` (field0 bits 0-15) and `vmar_cap_ceiling` (field0
    // bits 16-23) are not constrained by the spec at create time; pick
    // a permissive default so `acquire_ecs` / `acquire_vmars` through the
    // self-IDC mint EC/VMAR handles whose cap masks are limited only by
    // the domain's `*_outer_ceiling`. Spec §[idc_handle] / §[acquire_ecs]
    // ([test 06]) use this self-IDC to enumerate the calling domain's
    // own ECs; without a permissive `ec_cap_ceiling` the intersection
    // is zero and the minted handles carry no caps.
    //
    // vmar_cap_ceiling clears VmarCap bit 5 (mmio) — at field0 bit 21 —
    // so the §[acquire_vmars] [test 06] intersection naturally satisfies
    // [test 07]'s "MMIO and DMA VARs are not included" invariant. mmio
    // and dma describe the VMAR object (§[var]); minting an mmio cap on
    // a non-MMIO VMAR (the only kind acquire_vmars returns) would
    // misadvertise the handle. dma at VmarCap bit 8 falls outside the
    // 8-bit vmar_cap_ceiling field, so it is implicitly excluded.
    const cridc_ceiling: u16 = @truncate((field0_ceilings >> 24) & 0xFF);
    const idc_self_field0: u64 = 0x0000_0000_00DF_FFFF; // ec_cap_ceiling=0xFFFF, vmar_cap_ceiling=0xDF (mmio cleared)
    user_table[2].word0 = Word0.pack(2, .capability_domain, cridc_ceiling);
    user_table[2].field0 = idc_self_field0;
    user_table[2].field1 = 0;
    kernel_table[2].ref = .{
        .ptr = cd,
        .gen = @intCast(cd_gen),
    };

    _ = slab_instance.publish(pending);
    return cd;
}

/// Final teardown — walks `vars` freeing each VMAR, walks
/// `kernel_table` releasing every used slot per type, tears down the
/// address space, frees the table pages, frees slab.
///
/// Step 10 minimal teardown. The caller invokes this from `releaseSelf`
/// AFTER the calling EC has been retired via `parkSelfFaulted` (it is
/// the bound initial EC by spec — `delete(SLOT_SELF)` from inside the
/// child runs on this very EC). At entry the EC is no longer the
/// current_ec on its core; its kernel stack frame is the one we are
/// currently executing on, so we MUST not free the kernel stack pages
/// here. The scheduler's noreturn dispatch will iretq off this stack
/// once we return; the next preemption tick observes the EC as
/// `terminated` and reaps it via the slab generation flip.
///
/// What this does free now: the user/kernel handle-table PMM blocks,
/// the address-space PCID, and the CD slab slot itself. What is
/// deliberately leaked for later: page-table page frames (need an
/// arch.paging walk), page_frame slab refcount drops for handle-table
/// entries (refcounted PFs survive), VARs (require domain.vars[] walk
/// + per-VMAR unmap + slab destroy). These are smaller per-test than
/// the table blocks and don't push the full-475-test runner past the
/// PMM budget on a 1 GB QEMU instance.
/// Snapshot the destroy state captured under the CD's `_gen_lock` for
/// later sibling-slab tear-down. Carrying this between `destroyPhase1`
/// and `destroyPhase2` lets the caller release outer locks (CD's
/// `_gen_lock`, `tree_mutex`) before the EC / VM destroys lock their
/// own slab classes — without it, lockdep records `tree_mutex →
/// EC._gen_lock` and `CD._gen_lock → EC._gen_lock` edges and any
/// inverse path closes an AB-BA cycle.
pub const DestroyDeferred = struct {
    /// CD identity captured under cd._gen_lock at phase-1 entry. The gen
    /// is the live odd value at capture; phase-2's EC walk uses
    /// `cd_ref.ptr` / `cd_ref.gen` for identity-only comparison against
    /// `ec.domain` (no deref of the freed CD).
    cd_ref: SlabRef(CapabilityDomain),
    cd_addr_space_root: PAddr,
    vm_ref: ?SlabRef(VirtualMachine),
    user_buf: [*]u8,
    kernel_buf: [*]u8,
    addr_space_id: u16,
    /// Phys base + size of the contiguous user-stack buddy block.
    /// `pmm.freeBlock`'d wholesale at destroy and skipped by the
    /// per-page `freeUserAddrSpace` walk (the leaves point into this
    /// range). 0/0 means the stack wasn't allocated for this CD.
    user_stack_phys: u64,
    user_stack_bytes: u64,
    /// Caller-running EC (the one that invoked `delete(SLOT_SELF)`).
    /// Skipped by phase-2's EC walk because its kernel stack is in
    /// active use. The gen is captured before `parkSelfFaulted`; the
    /// walk only uses it for pointer-identity comparison.
    caller_ec: ?SlabRef(ExecutionContext),
};

/// Phase-1 destroy: runs WITH the CD's `_gen_lock` held by the caller.
/// Disarms every Timer reachable through the domain's handle table,
/// snapshots all cd.* fields the phase-2 tear-down needs, and releases
/// the CD slab slot via `destroyLocked` (clears the lock bit + bumps
/// gen → even in one store). On return the CD's `_gen_lock` is no
/// longer held — the caller MUST drop any other locks (notably
/// `caps.derivation.tree_mutex`) BEFORE invoking `destroyPhase2`.
pub fn destroyPhase1(cd: *CapabilityDomain, caller_ec: ?*ExecutionContext) DestroyDeferred {
    zag.sched.timer.disarmTimerHandlesInDomain(cd);

    // Tear down every VMAR bound to the domain. The destroy-path
    // variant clears leaf PTEs (so `freeUserAddrSpace` can distinguish
    // PF-backed leaves from singleton PMM leaves) and decrements
    // `pf.mapcnt` for every still-installed page_frame, but skips the
    // per-page TLB shootdown — no core has the dying CD's CR3 active.
    // removeVar tail-swaps so iterating from the tail each step lets
    // the array shrink under us without reordering un-walked entries.
    while (cd.var_count > 0) {
        const last = cd.var_count - 1;
        const v_ref = cd.vars[last] orelse {
            cd.var_count = last;
            continue;
        };
        // caller-pinned: VMAR's domain.ptr is cd; we hold cd._gen_lock.
        zag.memory.vmar.destroyVmarDuringDomainTeardown(v_ref.ptr);
    }

    const cd_gen = cd._gen_lock.currentGen();
    const deferred = DestroyDeferred{
        .cd_ref = SlabRef(CapabilityDomain).init(cd, cd_gen),
        .cd_addr_space_root = cd.addr_space_root,
        .vm_ref = cd.vm,
        .user_buf = @ptrCast(cd.user_table),
        .kernel_buf = @ptrCast(cd.kernel_table),
        .addr_space_id = cd.addr_space_id,
        .user_stack_phys = cd.user_stack_phys,
        .user_stack_bytes = cd.user_stack_bytes,
        .caller_ec = if (caller_ec) |ec|
            SlabRef(ExecutionContext).init(ec, ec._gen_lock.currentGen())
        else
            null,
    };

    slab_instance.destroyLocked(cd, cd_gen);

    return deferred;
}

/// Phase-2 destroy: runs with NO outer locks held. Tears down every
/// EC bound to the destroyed domain, the optional per-domain VM, and
/// releases the table-backing PMM blocks and the address-space ID.
/// The visitor matches ECs by `ec.domain.ptr == cd && gen == cd_gen`;
/// the gen check rejects any new CD that lands on the freed slab slot
/// between phase 1 and phase 2.
pub fn destroyPhase2(deferred: DestroyDeferred) void {
    // Mask IRQs across the whole of phase 2. With the deferred caller_ec
    // reap, freeUserAddrSpace, and per-handle release walk, the
    // post-Phase1 work is no longer trivially short — a preempt landing
    // mid-phase-2 would enter yieldTo, find current_ec=null (from the
    // earlier parkSelfFaulted), dequeue a runnable EC, and switchTo
    // away. The destroyPhase2 frame is abandoned, so the rest of the
    // cleanup never runs and resources accumulate across reps.
    const irq = arch.cpu.saveAndDisableInterrupts();
    defer arch.cpu.restoreInterrupts(irq);

    const pmm_mgr = if (pmm.global_pmm) |*p| p else return;

    zag.sched.execution_context.destroyEcsInDomain(
        deferred.cd_ref,
        deferred.cd_addr_space_root,
        deferred.caller_ec,
    );

    // Reap the destroying-domain's caller EC's slab slot. `parkSelfFaulted`
    // left it at gen=odd / state=.exited / off-freelist — `destroyEcsInDomain`
    // skipped it via `keep_ref` because we are still standing on its kstack.
    // Route through the standard deferred-destroy path: `bumpDeadGenLocked`
    // flips gen → even immediately, `postZombie` hands the EC to this
    // core's pending_zombie column, and the next dispatch
    // (`yieldTo` / `parkAndAwaitIRQ` / `switchTo` `takeOwnPendingZombie`)
    // finalizes it once `rsp` is no longer in the EC's kstack range.
    // Without this, every domain-destroy leaks one EC slab slot — slabs
    // are capped at 256 unique indices, so the test runner's
    // ~481 destroys/rep starve `allocExecutionContext` at ~rep 5.
    if (deferred.caller_ec) |caller_ref| {
        // caller-pinned: `deferred.cd_ref.ptr` is passed for identity-only
        // comparison against `ec.pending_reply_domain.ptr` inside
        // `destroyExecutionContextLocked`; the CD slab slot is already
        // freed (Phase 1 ran `destroyLocked`) and we only use the raw
        // pointer value as a key, never deref it.
        const cd_for_identity = deferred.cd_ref.ptr;
        zag.sched.execution_context.destroyExecutionContextLocked(
            caller_ref.ptr,
            deferred.cd_addr_space_root,
            cd_for_identity,
        );
    }

    if (deferred.vm_ref) |vm_slab_ref| {
        zag.hv.virtual_machine.releaseHandleAfterDomainDestroyed(vm_slab_ref.ptr);
    }

    // Walk slots [3..MAX) and apply per-handle release semantics for
    // refcount-lifetime object types (page_frame, timer, port,
    // device_region per spec proposal §3). With the alias-side
    // `incHandleRef`/`onHandleAcquire` in passed_handles processing,
    // every such handle is a real lifetime contributor and must be
    // released here. VMARs are owned by destroyPhase1's `cd.vars[]`
    // walk; capability_domain / execution_context / reply / vm are
    // domain-or-system-lifetime and have nothing to release here.
    //
    // The gen-validate-under-lock dance: destroyPhase2 runs after
    // destroyPhase1 dropped the CD's gen-lock, so concurrent destroys
    // on a port / page_frame / timer / device_region handle can
    // complete in the window. Take the slot's `_gen_lock`; if the
    // stamped `entry.ref.gen` no longer matches the live slab's gen,
    // skip — the object has already been destroyed (and possibly
    // reallocated) by another path.
    const user_table: [*]Capability = @ptrCast(@alignCast(deferred.user_buf));
    const kernel_table: [*]KernelHandle = @ptrCast(@alignCast(deferred.kernel_buf));
    var slot: u16 = 3;
    while (slot < MAX_HANDLES_PER_DOMAIN) : (slot += 1) {
        const entry = &kernel_table[slot];
        const obj_ptr = entry.ref.ptr orelse continue;
        const tag = Word0.typeTag(user_table[slot].word0);
        switch (tag) {
            .page_frame => {
                const pf: *zag.memory.page_frame.PageFrame = @ptrCast(@alignCast(obj_ptr));
                const slot_irq = pf._gen_lock.lockIrqSave(@src());
                if (pf._gen_lock.currentGen() != entry.ref.gen) {
                    pf._gen_lock.unlockIrqRestore(slot_irq);
                    continue;
                }
                zag.memory.page_frame.releaseHandleLocked(pf, slot_irq);
            },
            .timer => {
                const t: *zag.sched.timer.Timer = @ptrCast(@alignCast(obj_ptr));
                const slot_irq = t._gen_lock.lockIrqSave(@src());
                if (t._gen_lock.currentGen() != entry.ref.gen) {
                    t._gen_lock.unlockIrqRestore(slot_irq);
                    continue;
                }
                zag.sched.timer.decHandleRefLocked(t, slot_irq);
            },
            .port => {
                const p: *zag.sched.port.Port = @ptrCast(@alignCast(obj_ptr));
                const slot_irq = p._gen_lock.lockIrqSave(@src());
                if (p._gen_lock.currentGen() != entry.ref.gen) {
                    p._gen_lock.unlockIrqRestore(slot_irq);
                    continue;
                }
                const caps_word = Word0.caps(user_table[slot].word0);
                zag.sched.port.releaseHandleLocked(p, caps_word, slot_irq);
            },
            .device_region => {
                const dr: *zag.devices.device_region.DeviceRegion = @ptrCast(@alignCast(obj_ptr));
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
                zag.devices.device_region.removeHandleListNodeLocked(dr, &entry.dr_node);
                zag.devices.device_region.releaseHandleLocked(dr, slot_irq);
            },
            else => {},
        }
    }

    // Reclaim user-half page tables and the eagerly-mapped user-stack /
    // ELF / table-view leaves that landed in this address space. The
    // page-table walker frees PT/PD/PDPT/PML4 pages and any leaf
    // physical page that came from a single-page PMM.create — i.e.
    // mapUserStack and loadElfSegments allocations. Page-frame leaves
    // were already cleared by the destroyPhase1 vars[] walk; the leaves
    // shared with `user_buf` (mapUserTableView aliases the user_buf
    // pages into user space at `table_base`) are skipped via the
    // [user_buf_phys, user_buf_phys + USER_TABLE_BYTES) range so the
    // wholesale freeBlock below isn't double-freeing them.
    const user_buf_phys = zag.memory.address.PAddr.fromVAddr(
        zag.memory.address.VAddr.fromInt(@intFromPtr(deferred.user_buf)),
        null,
    );
    arch.paging.freeUserAddrSpace(
        deferred.cd_addr_space_root,
        user_buf_phys.addr,
        USER_TABLE_BYTES,
        deferred.user_stack_phys,
        deferred.user_stack_bytes,
    );

    pmm_mgr.freeBlock(deferred.user_buf[0..USER_TABLE_BYTES]);
    pmm_mgr.freeBlock(deferred.kernel_buf[0..KERNEL_TABLE_BYTES]);

    if (deferred.addr_space_id != 0) arch.paging.freeAddrSpaceId(deferred.addr_space_id);
}

/// Pop the head of the free-slot list. Returns `null` (E_FULL) if the
/// table is full.
fn allocFreeSlot(cd: *CapabilityDomain) ?u12 {
    if (cd.free_count == 0) return null;
    const head = cd.free_head;
    if (head == zag.caps.capability.FREE_LIST_TAIL) return null;
    const slot: u12 = @truncate(head);
    const next = zag.caps.capability.decodeFreeNext(cd.kernel_table[slot].parent);
    cd.free_head = next;
    cd.free_count -= 1;
    return slot;
}

/// Linear scan for an existing handle to `obj` in this domain, used
/// to enforce the at-most-one-per-(domain, object) invariant.
/// Returns the existing slot id if found.
fn findExistingHandle(cd: *CapabilityDomain, obj: ErasedSlabRef, t: CapabilityType) ?u12 {
    var i: u16 = 0;
    while (i < MAX_HANDLES_PER_DOMAIN) {
        const entry = &cd.kernel_table[i];
        if (entry.ref.ptr != null and entry.ref.ptr == obj.ptr and entry.ref.gen == obj.gen) {
            const tag = Word0.typeTag(cd.user_table[i].word0);
            if (tag == t) return @truncate(i);
        }
        i += 1;
    }
    return null;
}

/// Mint a handle into `cd`'s table at a fresh slot. Allocates from the
/// free list, writes both halves, returns the slot id. Coalesces with
/// existing handle to the same object per the at-most-one invariant.
pub fn mintHandle(
    cd: *CapabilityDomain,
    obj: ErasedSlabRef,
    obj_type: CapabilityType,
    caps: u16,
    field0: u64,
    field1: u64,
) !u12 {
    if (findExistingHandle(cd, obj, obj_type)) |existing| {
        // Coalesce: keep the original entry, return its slot. Spec
        // semantics: at most one handle per (domain, object).
        return existing;
    }

    const slot = allocFreeSlot(cd) orelse return error.OutOfHandles;
    writeHandleSlot(cd, slot, obj, obj_type, caps, field0, field1);
    return slot;
}

/// Variant of `mintHandle` that bypasses the at-most-one-per-(domain,
/// object) coalescing. Used by §[handle_attachments] recv-time delivery
/// where the spec mandates N contiguous NEW slots `[tstart, tstart+N)`
/// even when the receiver already holds a handle to the same object.
/// Allocates from the free list and writes the slot unconditionally.
pub fn mintHandleAlwaysNew(
    cd: *CapabilityDomain,
    obj: ErasedSlabRef,
    obj_type: CapabilityType,
    caps: u16,
    field0: u64,
    field1: u64,
) !u12 {
    const slot = allocFreeSlot(cd) orelse return error.OutOfHandles;
    writeHandleSlot(cd, slot, obj, obj_type, caps, field0, field1);
    return slot;
}

/// Mint a handle into a specific pre-reserved free slot. Used by the
/// contiguous-slot allocator in `allocContiguousFreeSlots` where the
/// caller has already unlinked the slot from the free list. Bypasses
/// coalescing — the caller has explicitly committed to placing the
/// handle at this slot id (spec §[handle_attachments] tstart..tstart+N).
pub fn mintHandleAt(
    cd: *CapabilityDomain,
    slot: u12,
    obj: ErasedSlabRef,
    obj_type: CapabilityType,
    caps: u16,
    field0: u64,
    field1: u64,
) void {
    writeHandleSlot(cd, slot, obj, obj_type, caps, field0, field1);
}

fn writeHandleSlot(
    cd: *CapabilityDomain,
    slot: u12,
    obj: ErasedSlabRef,
    obj_type: CapabilityType,
    caps: u16,
    field0: u64,
    field1: u64,
) void {
    cd.user_table[slot].word0 = Word0.pack(slot, obj_type, caps);
    cd.user_table[slot].field0 = field0;
    cd.user_table[slot].field1 = field1;
    cd.kernel_table[slot].ref = obj;
    cd.kernel_table[slot].parent = .{};
    cd.kernel_table[slot].first_child = .{};
    cd.kernel_table[slot].next_sibling = .{};
    cd.kernel_table[slot].dr_node = .{};

    // Spec §[device_irq]: every domain-local copy of a device_region
    // handle gets an IRQ-propagation list entry on the parent region.
    // Use the embedded per-handle node so the storage tracks the slot
    // lifetime. `field1_paddr` is the kernel physaddr of the user-table
    // entry's `field1` slot — the futex address userspace recv-blocks
    // on. The user_table block came from `pmm.allocBlock`, so its
    // kernel-VA points into the physmap; `PAddr.fromVAddr(.., null)`
    // recovers the physaddr.
    if (obj_type == .device_region) {
        const dr: *zag.devices.device_region.DeviceRegion = @ptrCast(@alignCast(obj.ptr.?));
        const field1_va = zag.memory.address.VAddr.fromInt(
            @intFromPtr(&cd.user_table[slot].field1),
        );
        const field1_paddr = zag.memory.address.PAddr.fromVAddr(field1_va, null);
        zag.devices.device_region.appendHandleListNode(
            dr,
            &cd.kernel_table[slot].dr_node,
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
pub fn allocContiguousFreeSlots(cd: *CapabilityDomain, n: u8) !u12 {
    if (n == 0) return 0;
    if (cd.free_count < n) return error.OutOfHandles;

    var run_start: u16 = 3;
    var i: u16 = 3;
    while (i < MAX_HANDLES_PER_DOMAIN) {
        if (cd.kernel_table[i].ref.ptr == null) {
            const run_len = i + 1 - run_start;
            if (run_len >= n) {
                // Found a run [run_start, run_start + n). Splice each
                // slot out of the free list. The list is singly-linked;
                // walk it removing matching nodes.
                var k: u16 = 0;
                while (k < n) {
                    const target_slot = run_start + k;
                    unlinkFreeSlot(cd, @intCast(target_slot));
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
fn unlinkFreeSlot(cd: *CapabilityDomain, slot: u12) void {
    const slot_u16: u16 = slot;
    if (cd.free_head == slot_u16) {
        cd.free_head = zag.caps.capability.decodeFreeNext(cd.kernel_table[slot].parent);
        cd.free_count -= 1;
        return;
    }
    var prev: u16 = cd.free_head;
    while (prev != zag.caps.capability.FREE_LIST_TAIL) {
        const prev_idx: u12 = @truncate(prev);
        const next = zag.caps.capability.decodeFreeNext(cd.kernel_table[prev_idx].parent);
        if (next == slot_u16) {
            const after = zag.caps.capability.decodeFreeNext(cd.kernel_table[slot].parent);
            cd.kernel_table[prev_idx].parent = zag.caps.capability.encodeFreeNext(after);
            cd.free_count -= 1;
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
fn readSelfField0(cd: *const CapabilityDomain) u64 {
    return cd.user_table[0].field0;
}

/// Append `v` to `vars[var_count]`. Returns E_FULL when at MAX.
pub fn appendVar(cd: *CapabilityDomain, v: *VMAR) i64 {
    if (cd.var_count >= cd.vars.len) return errors.E_FULL;
    cd.vars[cd.var_count] = SlabRef(VMAR).init(v, v._gen_lock.currentGen());
    cd.var_count += 1;
    return 0;
}

/// Remove `v` from `vars` by tail-swap; decrements var_count.
pub fn removeVar(cd: *CapabilityDomain, v: *VMAR) void {
    var i: u16 = 0;
    while (i < cd.var_count) {
        if (cd.vars[i]) |v_ref| {
            // Identity compare: SlabRef.ptr == raw pointer.
            if (v_ref.ptr == v) {
                cd.var_count -= 1;
                cd.vars[i] = cd.vars[cd.var_count];
                cd.vars[cd.var_count] = null;
                return;
            }
        }
        i += 1;
    }
}

/// Linear-scan `vars[]` for any range overlapping `[base, base + bytes)`.
/// Returns E_NOSPC on overlap, 0 otherwise. Spec §[var].create_vmar.
pub fn checkVaRangeOverlap(cd: *const CapabilityDomain, base: VAddr, bytes: u64) i64 {
    const new_start = base.addr;
    const new_end = new_start + bytes;
    var i: u16 = 0;
    while (i < cd.var_count) {
        const v_ref = cd.vars[i] orelse {
            i += 1;
            continue;
        };
        // caller-pinned: VMAR's domain ref pins it; cd is the owner here.
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

/// Phase-1 entry for SLOT_SELF tear-down. The caller
/// (`caps.derivation.deleteAndDetach`) holds `tree_mutex` and the CD's
/// `_gen_lock`; this returns a `DestroyDeferred` capturing the work
/// the caller must finish via `destroyPhase2` AFTER releasing both.
///
/// `delete(SLOT_SELF)` runs on an EC bound to the very domain being
/// destroyed (commonly the initial EC, which on test ELFs falls
/// through to start.zig's `_start`-tail `delete(SLOT_SELF)` after main
/// returns). We cannot reclaim the kernel stack of the calling EC
/// from here — it is the stack we are currently executing on — so
/// this path frees the heaviest per-domain allocations (handle-table
/// PMM blocks, slab slot, PCID) and lets the EC frame iretq off into
/// scheduler.run() via the normal post-syscall fall-through. The
/// caller's `_start` then enters its `while(true) hlt` until the next
/// tick preempts; the EC is no longer reachable from any handle (its
/// owning domain's slab gen flipped) so it is unrunnable past that.
///
/// Without this, every child domain spawned by the test runner leaks
/// ~256 KiB of buddy-allocated handle-table pages and a slab slot. By
/// ~iteration 416 the runner exhausts buddy-allocator capacity, and
/// further `createCapabilityDomain` syscalls hang on the failed
/// allocBlock (no E_NOMEM is currently surfaced from that path —
/// see TODO in allocCapabilityDomain).
pub fn releaseSelf(cd: *CapabilityDomain) DestroyDeferred {
    // Park the calling EC before tearing the domain down. The caller
    // is the running EC of `cd` (delete(SLOT_SELF) is dispatched on
    // its own kernel stack); without this `parkSelfFaulted` it would
    // continue executing user-mode code at the post-syscall RIP after
    // iretq, but the `user_table` PMM block has just been freed and
    // the user-mode pages backing the read-only cap-table view are
    // unmapped. Park as `.exited` so syscallDispatch's
    // `scheduler.run()` epilogue picks up the next ready EC instead
    // of iretq'ing the now-doomed test EC. Mirrors the
    // `fireThreadFault` no-route fallback.
    //
    // Capture the caller EC BEFORE `parkSelfFaulted` clears it from
    // `current_ec`; the phase-2 EC walk must skip this EC.
    const caller_ec = zag.sched.scheduler.currentEc();
    if (caller_ec) |ec| {
        zag.sched.execution_context.parkSelfFaulted(ec);
    }
    return destroyPhase1(cd, caller_ec);
}
