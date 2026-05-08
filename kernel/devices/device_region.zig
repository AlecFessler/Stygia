//! Spec-v3 device_region object. A reference to a physical device's MMIO
//! region or x86-64 I/O port range. Holders use it to install device
//! memory into a VMAR, take IRQs, and (with the `dma` cap) authorize an
//! IOMMU mapping. Spec §[device_region] §[device_irq]
//! §[port_io_virtualization].

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const futex = zag.sched.futex;
const irq = zag.arch.dispatch.irq;
const secure_slab = zag.memory.allocators.secure_slab;
const userio = zag.arch.dispatch.userio;

const GenLock = secure_slab.GenLock;
const PAddr = zag.memory.address.PAddr;
const Refcount = zag.utils.refcount.Refcount;
const SecureSlab = secure_slab.SecureSlab;
const SpinLock = zag.utils.sync.SpinLock;

/// Maximum concurrently-live DeviceRegion slabs. Sized for the
/// boot-time device enumerators (PCI BARs, framebuffer, IOAPIC) that
/// run before any holder ever drops a reference.
pub const MAX_DEVICE_REGIONS: usize = 256;

/// Cap on the IRQ-source lookup table. The x86 IOAPIC exposes 24 lines
/// per chip; the GIC SPI range tops out at INTID 1019. We pick a single
/// dense table sized for the worst case so `findDeviceByIrqSource` is
/// O(1).
pub const MAX_IRQ_SOURCES: usize = 1024;

pub const DeviceType = enum(u8) {
    mmio = 0,
    port_io = 1,
    framebuffer = 2,
};

/// Pixel layout for a `framebuffer` device_region. Mirrors the
/// `boot_protocol.PixelFormat` the UEFI bootloader hands the kernel —
/// kept verbatim across the cap so userspace doesn't have to import
/// boot-protocol types just to interpret a pixel.
pub const PixelFormat = enum(u8) {
    bgr8 = 0,
    rgb8 = 1,
    bitmask = 2,
    blt_only = 3,
    none = 0xFF,
};

/// Optional PCI requester identifier for an MMIO region. Set when the
/// region was registered via `registerMmioPci`/`registerPortIoPci`
/// during PCI enumeration; left zero with `valid=false` for non-PCI
/// device regions (platform UARTs, IOAPICs, etc.). The IOMMU drivers
/// (`arch/x64/intel/vtd.zig`, `arch/x64/amd/vi.zig`) read this when
/// lazily provisioning a per-device translation domain on first
/// `iommuMapPage`.
pub const PciAddress = extern struct {
    bus: u8 = 0,
    /// Packed `dev[4:0] << 3 | func[2:0]` — the standard PCI devfn
    /// encoding the IOMMU drivers index context tables / device tables
    /// with.
    devfn: u8 = 0,
    valid: u8 = 0,
    _pad: [5]u8 = [_]u8{0} ** 5,

    pub fn make(b: u8, d: u5, f: u3) PciAddress {
        return .{
            .bus = b,
            .devfn = (@as(u8, d) << 3) | @as(u8, f),
            .valid = 1,
        };
    }

    pub fn isValid(self: PciAddress) bool {
        return self.valid != 0;
    }

    pub fn dev(self: PciAddress) u5 {
        return @truncate(self.devfn >> 3);
    }

    pub fn func(self: PciAddress) u3 {
        return @truncate(self.devfn & 0x7);
    }

    /// Standard 16-bit BDF requester ID.
    pub fn bdf(self: PciAddress) u16 {
        return (@as(u16, self.bus) << 8) | @as(u16, self.devfn);
    }
};

/// Cap bits in `Capability.word0[48..63]` for device_region handles.
/// Spec §[device_region] cap layout (table at bits 0-4).
pub const DeviceRegionCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    dma: bool = false,
    irq: bool = false,
    restart_policy: u1 = 0,
    _reserved: u11 = 0,
};

pub const Mmio = extern struct {
    phys_base: PAddr,
    size: u64,
};

pub const PortIo = extern struct {
    base_port: u16,
    port_count: u16,
    _pad: [12]u8 = [_]u8{0} ** 12,
};

/// Linear UEFI GOP framebuffer surfaced to userspace through a
/// device_region cap. `phys_base`/`size` cover the pixel buffer in
/// physical address space; `width`/`height`/`stride` describe the
/// pixel grid (`stride` is in pixels, not bytes — matches GOP's
/// `pixels_per_scan_line`). `pixel_format` selects the byte layout
/// userspace shaders should write.
pub const Framebuffer = extern struct {
    phys_base: PAddr,
    size: u64,
    width: u32,
    height: u32,
    stride: u32,
    pixel_format: PixelFormat,
    _pad: [3]u8 = [_]u8{0} ** 3,
};

pub const Access = extern union {
    mmio: Mmio,
    port_io: PortIo,
    framebuffer: Framebuffer,
};

/// Refcount-lifetime kernel object. Every holder of a SlabRef
/// (handle-table entry, in-flight syscall, IRQ table) owns one
/// increment of `refcount`; the decrementer that drops it to zero owns
/// teardown (slab-destroy + IRQ table eviction). All mutable fields —
/// `refcount`, `irq_source`, the per-handle propagation list — are
/// guarded by `_gen_lock`. Spec §[device_region].
pub const DeviceRegion = extern struct {
    /// SlabRef gen + per-instance mutex. Must be the first field; see
    /// `secure_slab.SlabRef`.
    _gen_lock: GenLock = .{},

    /// Holder count. Lifetime invariant: object alive iff
    /// `refcount > 0` and not Sticky'd. CAS-loop atomic with sticky
    /// observed-zero marker; the dec that transitions 1→Sticky owns
    /// teardown.
    refcount: Refcount = .{},

    device_type: DeviceType,
    _pad0: [3]u8 = [_]u8{0} ** 3,

    access: Access,

    /// Hardware IRQ source bound to this region (LAPIC vector / GIC
    /// INTID), or `IRQ_SOURCE_NONE` if no IRQ delivery is configured.
    irq_source: u32 = IRQ_SOURCE_NONE,

    /// Linker-language: head of the singly-linked list of every
    /// `KernelHandle` that names this region. Used by
    /// `propagateIrqAndWake` to bump every domain-local copy of
    /// `field1.irq_count`. Stored type-erased to avoid a
    /// caps-module dependency cycle.
    handle_list_head: ?*HandleListNode = null,

    /// PCI requester identifier (bus / dev / func). `valid=0` for
    /// non-PCI regions. Populated by `registerMmioPci` /
    /// `registerPortIoPci` from the ACPI PCI enumerator. The IOMMU
    /// drivers consume `bdf()` / `bus`/`devfn` accessors when
    /// provisioning a per-device translation domain.
    pci: PciAddress = .{},

    /// IOMMU per-device side-state opaque slot. The active arch
    /// IOMMU driver allocates and stores its per-device translation
    /// state (e.g. SL-PT root + domain id for VT-d, page-table root
    /// for AMD-Vi) here on first `iommuMapPage`, and reuses it on
    /// subsequent map/unmap/invalidate. Stored type-erased so the
    /// devices module doesn't pull in arch-specific IOMMU types.
    /// Lifetime is tied to the DeviceRegion: side-state is freed
    /// when the IOMMU driver tears the region down (currently never
    /// — DMA-bearing regions live for the boot lifetime).
    iommu_state: ?*anyopaque = null,
};

pub const IRQ_SOURCE_NONE: u32 = std.math.maxInt(u32);

/// Per-handle propagation entry. One node per `KernelHandle` to a
/// device_region. `field1_paddr` is the physical address of the handle
/// entry's `field1` slot in its owning capability domain's user_table —
/// i.e. the futex address Spec §[device_irq] step 3 wakes on. Owned by
/// the handle table; threaded through `next` into the parent region's
/// `handle_list_head`. Caps module (or its stub) appends/removes nodes
/// under `DeviceRegion._gen_lock`.
pub const HandleListNode = extern struct {
    field1_paddr: PAddr,
    next: ?*HandleListNode = null,
};

const DeviceRegionSlab = SecureSlab(DeviceRegion, MAX_DEVICE_REGIONS);

var device_region_slab: DeviceRegionSlab = undefined;
var slab_initialized: bool = false;

/// Reverse map: hardware IRQ source → owning DeviceRegion. The IRQ ISR
/// hits this table from interrupt context, so it is guarded by a
/// dedicated SpinLock instead of any per-object GenLock — taking a
/// GenLock from an ISR is forbidden by the kernel's lock ordering.
var irq_table: [MAX_IRQ_SOURCES]?*DeviceRegion = [_]?*DeviceRegion{null} ** MAX_IRQ_SOURCES;
var irq_table_lock: SpinLock = .{ .class = "device_region.irq_table" };

/// Boot-time list of DeviceRegions that platform enumerators (PCI scan,
/// serial port probe, GIC/IOAPIC) wanted minted into the root capability
/// domain's handle table. The enumerators run during ACPI parse —
/// before the root domain exists — so they stage refs here and
/// `userspace_init.grantDevices` drains the list after allocating the
/// root domain. Each entry transfers the registerXxx caller-ref onto
/// the minted root_cd handle (no incRef needed; refcount stays 1 and
/// is owned by the handle slot). Spec §[device_region].
var boot_grant_list: [MAX_DEVICE_REGIONS]?*DeviceRegion = [_]?*DeviceRegion{null} ** MAX_DEVICE_REGIONS;
var boot_grant_count: usize = 0;
var boot_grant_lock: SpinLock = .{ .class = "device_region.boot_grant_list" };

pub fn appendBootGrant(dr: *DeviceRegion) void {
    const irq_state = boot_grant_lock.lockIrqSave(@src());
    defer boot_grant_lock.unlockIrqRestore(irq_state);
    if (boot_grant_count >= boot_grant_list.len) return;
    boot_grant_list[boot_grant_count] = dr;
    boot_grant_count += 1;
}

pub fn forEachBootGrant(
    ctx: anytype,
    comptime visit: fn (@TypeOf(ctx), *DeviceRegion) void,
) void {
    const irq_state = boot_grant_lock.lockIrqSave(@src());
    const n = boot_grant_count;
    boot_grant_lock.unlockIrqRestore(irq_state);
    var i: usize = 0;
    while (i < n) {
        if (boot_grant_list[i]) |dr| visit(ctx, dr);
        i += 1;
    }
}

pub fn initSlab(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    device_region_slab = DeviceRegionSlab.init(data_range, ptrs_range, links_range);
    slab_initialized = true;
}

fn allocRegion() !DeviceRegionSlab.Pending {
    std.debug.assert(slab_initialized);
    return try device_region_slab.create();
}

/// Allocate an MMIO device_region covering `[base_paddr, base_paddr +
/// size)`. Returned with `refcount = 1` representing the caller's
/// initial reference — the boot-time device registry, or whichever
/// kernel agent enumerated it. Non-PCI regions (platform UARTs,
/// IOAPIC, framebuffer) use this entry point; PCI BARs go through
/// `registerMmioPci`. Spec §[device_region].
pub fn registerMmio(base_paddr: PAddr, size: u64) !*DeviceRegion {
    return registerMmioPci(base_paddr, size, .{});
}

/// PCI-aware variant: stamps the region's `pci` field with the
/// device's BDF so IOMMU drivers can derive the requester ID without
/// rescanning config space.
pub fn registerMmioPci(base_paddr: PAddr, size: u64, pci: PciAddress) !*DeviceRegion {
    const pending = try allocRegion();
    const dr = pending.ptr;
    dr.refcount = .{};
    if (dr.refcount.inc() == .observed_zero) unreachable;
    dr.device_type = .mmio;
    dr.access = .{ .mmio = .{ .phys_base = base_paddr, .size = size } };
    dr.irq_source = IRQ_SOURCE_NONE;
    dr.pci = pci;
    dr.iommu_state = null;
    _ = device_region_slab.publish(pending);
    return dr;
}

/// Allocate a port-io device_region covering `[base_port, base_port +
/// port_count)`. x86-64 only by spec — callers on other arches must
/// reject before reaching here. Spec §[port_io_virtualization].
pub fn registerPortIo(base_port: u16, port_count: u16) !*DeviceRegion {
    return registerPortIoPci(base_port, port_count, .{});
}

/// Allocate a framebuffer device_region. Returned with `refcount = 1`
/// owned by the boot enumerator that called us; the typical pattern
/// is to immediately `appendBootGrant(dr)` so userspace_init mints it
/// into the root capability domain. The geometry fields ride the cap
/// itself (encoded into `Capability.field1` by `mintBootDevice`) so
/// userspace doesn't need a side-channel page_frame to discover the
/// resolution.
pub fn registerFramebuffer(
    phys_base: PAddr,
    size: u64,
    width: u32,
    height: u32,
    stride: u32,
    pixel_format: PixelFormat,
) !*DeviceRegion {
    const pending = try allocRegion();
    const dr = pending.ptr;
    dr.refcount = .{};
    if (dr.refcount.inc() == .observed_zero) unreachable;
    dr.device_type = .framebuffer;
    dr.access = .{ .framebuffer = .{
        .phys_base = phys_base,
        .size = size,
        .width = width,
        .height = height,
        .stride = stride,
        .pixel_format = pixel_format,
    } };
    dr.irq_source = IRQ_SOURCE_NONE;
    dr.pci = .{};
    dr.iommu_state = null;
    _ = device_region_slab.publish(pending);
    return dr;
}

/// PCI-aware variant for port-io BARs. Stamps the region's `pci`
/// field with the requester BDF; IOMMU drivers ignore port-io
/// regions today (no DMA), but the metadata stays consistent across
/// region types.
pub fn registerPortIoPci(base_port: u16, port_count: u16, pci: PciAddress) !*DeviceRegion {
    const pending = try allocRegion();
    const dr = pending.ptr;
    dr.refcount = .{};
    if (dr.refcount.inc() == .observed_zero) unreachable;
    dr.device_type = .port_io;
    dr.access = .{ .port_io = .{ .base_port = base_port, .port_count = port_count } };
    dr.irq_source = IRQ_SOURCE_NONE;
    dr.pci = pci;
    dr.iommu_state = null;
    _ = device_region_slab.publish(pending);
    return dr;
}

/// Public release-handle entry point invoked from the cross-cutting
/// `caps.capability.delete` path. Acquires `dr._gen_lock` and routes
/// through the standard `decHandleRef` which owns the teardown
/// transition.
pub fn releaseHandle(dr: *DeviceRegion) void {
    const irq_state = dr._gen_lock.lockIrqSave(@src());
    decHandleRef(dr, irq_state);
}

/// `releaseHandle` for callers that already hold `dr._gen_lock`.
pub fn releaseHandleLocked(dr: *DeviceRegion, held_irq: u64) void {
    decHandleRef(dr, held_irq);
}

/// Bump the per-handle refcount when an alias of an existing
/// DeviceRegion is minted into a fresh slot (e.g. `passed_handles`
/// into a child domain). Returns `error.BadCap` if a concurrent
/// destroy already Sticky'd the refcount.
pub fn incHandleRef(dr: *DeviceRegion) error{BadCap}!void {
    const irq_state = dr._gen_lock.lockIrqSave(@src());
    defer dr._gen_lock.unlockIrqRestore(irq_state);
    if (dr.refcount.inc() == .observed_zero) return error.BadCap;
}

/// Decrement the refcount. The decrementer-to-zero owns teardown:
/// evicts the IRQ-table entry (if any), then destroys the slab slot.
/// Caller must hold `dr._gen_lock` (acquired via `lockIrqSave` and
/// passing the captured IRQ state via `held_irq_state`). On the
/// zero-transition this function passes the held lock to
/// `destroyLocked`, which bumps gen to the next even value and
/// releases — avoiding the unlock/relock race window where a
/// concurrent path could observe a still-odd gen.
pub fn decHandleRef(dr: *DeviceRegion, held_irq_state: u64) void {
    const result = dr.refcount.dec();
    if (result != .observed_zero) {
        dr._gen_lock.unlockIrqRestore(held_irq_state);
        return;
    }

    if (dr.irq_source != IRQ_SOURCE_NONE) {
        const src = dr.irq_source;
        dr.irq_source = IRQ_SOURCE_NONE;
        const irq_irq = irq_table_lock.lockIrqSave(@src());
        if (src < MAX_IRQ_SOURCES) irq_table[src] = null;
        irq_table_lock.unlockIrqRestore(irq_irq);
    }

    const gen = dr._gen_lock.currentGen();
    device_region_slab.destroyLocked(dr, gen);
    // destroyLocked released the lock via setGenRelease without
    // touching IRQ state — restore explicitly here.
    arch.cpu.restoreInterrupts(held_irq_state);
}

/// O(1) reverse lookup keyed by the hardware IRQ source identifier the
/// per-arch ISR delivered. Returns null when no region is bound — the
/// ISR drops the spurious interrupt. Spec §[device_irq].
pub fn findDeviceByIrqSource(irq_source: u32) ?*DeviceRegion {
    if (irq_source >= MAX_IRQ_SOURCES) return null;
    const irq_irq = irq_table_lock.lockIrqSave(@src());
    defer irq_table_lock.unlockIrqRestore(irq_irq);
    return irq_table[irq_source];
}

/// Acknowledge accumulated IRQs from `dr`: atomically reads the IRQ
/// counter on every domain-local copy back to zero, signals EOI to the
/// interrupt controller, and unmasks the line. Spec §[device_region].ack.
///
/// Returns the prior counter value observed on the caller's own handle
/// (the only value the syscall surface promises to report; other copies
/// converge within a bounded delay per Spec §[device_irq]).
pub fn ack(dr: *DeviceRegion, callers_field1_paddr: PAddr) u64 {
    var prior: u64 = 0;
    var cursor = dr.handle_list_head;
    while (cursor) |node| {
        const observed = userio.atomicAddU64Saturating(node.field1_paddr, 0, 0);
        if (node.field1_paddr.addr == callers_field1_paddr.addr) prior = observed;
        userio.writeU64ViaPhysmap(node.field1_paddr, 0);
        cursor = node.next;
    }

    if (dr.irq_source == IRQ_SOURCE_NONE) return prior;
    const line: u8 = @intCast(dr.irq_source & 0xFF);
    irq.endOfInterrupt(line);
    irq.unmaskIrq(line);
    return prior;
}

/// Hardware IRQ entry. Per Spec §[device_irq]:
///   1. Mask the line (kept masked until `ack` to coalesce duplicates).
///   2. Bump every domain-local copy's `irq_count` (saturating u64).
///   3. Wake recv-blocked ECs that may be sitting in `futex_wait_val`
///      against any of those counters.
///
/// Called from per-arch ISR context. The caller must already have
/// looked the region up via `findDeviceByIrqSource`. Does NOT take
/// `dr._gen_lock` — the IRQ source binding is stable for the lifetime
/// of `dr`'s entry in the IRQ table (entry installed under the lock at
/// bind, evicted under the lock at refcount-zero teardown), and the
/// handle list is append-mostly with futex semantics that tolerate a
/// missed late-add wake (the next IRQ will catch it).
pub fn onIrq(dr: *DeviceRegion) void {
    if (dr.irq_source != IRQ_SOURCE_NONE) {
        const line: u8 = @intCast(dr.irq_source & 0xFF);
        irq.maskIrq(line);
    }
    propagateIrqAndWake(dr);
}

/// Step 2+3 of `onIrq`. Walks the per-region handle list; for each
/// domain-local copy bumps `field1.irq_count` saturating at u64::MAX
/// via `userio.atomicAddU64Saturating` and futex-wakes every waiter
/// parked in `futex_wait_val` on that paddr. Idle remote cores
/// hosting a recv-blocked EC are kicked from inside `futex.wake`
/// via `scheduler.enqueueOnCore` -> `arch.smp.sendWakeIpi`, so this
/// path doesn't need its own IPI fan-out.
///
/// IRQ-context safety: called with IRQs masked. `futex.wake` takes
/// `Bucket.lock` (and transitively `core_locks` / `timed_lock`) via
/// `lockIrqSaveOrdered`, which preserves the masked state across
/// the critical section. The same path is exercised every timer
/// tick by `futex.expireTimedWaiters` and by `timer.zig`'s field0
/// `futex.wake(paddr, maxInt(u32))` propagation, both of which
/// run in IRQ context.
///
/// Spec §[device_irq] steps 1+3.
pub fn propagateIrqAndWake(dr: *DeviceRegion) void {
    var cursor = dr.handle_list_head;
    while (cursor) |node| {
        _ = userio.atomicAddU64Saturating(node.field1_paddr, 1, std.math.maxInt(u64));
        _ = futex.wake(node.field1_paddr, std.math.maxInt(u32));
        cursor = node.next;
    }
}
