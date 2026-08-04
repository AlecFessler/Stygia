const std = @import("std");
const stygia = @import("stygia");

const paging = stygia.memory.paging;
const uefi = std.os.uefi;

const ConfigurationTable = uefi.tables.ConfigurationTable;
const Guid = uefi.Guid;
const PAddr = stygia.memory.address.PAddr;
const VAddr = stygia.memory.address.VAddr;

pub const MMapEntryType = enum {
    acpi,
    free,
    reserved,
};

pub const Blob = extern struct {
    ptr: [*]u8,
    len: u64,
};

pub const PixelFormat = enum(u8) {
    bgr8 = 0,
    rgb8 = 1,
    bitmask = 2,
    blt_only = 3,
    none = 0xFF,
};

pub const Framebuffer = extern struct {
    base: PAddr,
    size: u64,
    width: u32,
    height: u32,
    stride: u32,
    pixel_format: PixelFormat,
    _pad: [3]u8 = .{ 0, 0, 0 },
};

pub const BootInfo = extern struct {
    elf_blob: Blob,
    root_service: Blob,
    stack_top: VAddr,
    xsdp_phys: PAddr,
    kaslr_slide: u64,
    mmap: MMap,
    framebuffer: Framebuffer,
    /// Set to 1 by the aarch64 UEFI bootloader when AAVMF handed off at
    /// EL2 (i.e. QEMU was run with `-M virt,virtualization=on`) and the
    /// bootloader successfully installed an EL2 hyp stub before ERETing
    /// to EL1. Read by the aarch64 kernel entry path to set
    /// `vm.hyp_stub_installed`, unlocking `vmSupported()`. 0 otherwise
    /// (x86 boots, aarch64 UEFI without virtualization=on, direct-kernel
    /// boot which uses its own hyp stub install path).
    arrived_at_el2: u8 = 0,
    _pad_ael2: [7]u8 = .{ 0, 0, 0, 0, 0, 0, 0 },
    /// Physical address of a flattened devicetree blob, or 0 when the
    /// platform describes itself through ACPI instead.
    ///
    /// The aarch64 kernel needs SOME firmware description to find its GIC
    /// and its UART, and on boards with no ACPI (Raspberry Pi 5) the DTB
    /// is the only one there is. `arch.boot.parseFirmwareTables` prefers
    /// `xsdp_phys` when both are set, so a UEFI/ACPI boot behaves exactly
    /// as before.
    ///
    /// Every loader MUST assign this explicitly. `BootInfo` is built
    /// field-by-field onto uninitialized stack memory (see
    /// `bootloader/main.zig`), so struct-default values never run and an
    /// unwritten field is whatever the stack happened to hold — which the
    /// kernel would then map and parse as a devicetree.
    ///
    /// Appended after `_pad_ael2` deliberately: `arrived_at_el2` plus its
    /// 7 bytes of padding ends 8-aligned, so a `PAddr` lands here without
    /// shifting the offset of any existing field.
    dtb_phys: PAddr = PAddr.fromInt(0),
    /// Physical base of a console UART the LOADER already resolved and
    /// verified, or 0 for "I have no opinion, discover one yourself".
    ///
    /// This exists because on some boards firmware discovery cannot reach
    /// the UART that is physically observable. The Raspberry Pi 5 is the
    /// motivating case: its devicetree describes seven PL011s, and the only
    /// one wired to a connector that exists (RP1 `uart0` — the DT `serial0`
    /// alias, Linux's `ttyAMA0`, the GPIO 14/15 header) sits behind the RP1
    /// southbridge's PCIe bus at CPU PA 0x1F_0003_0000. Reaching it from
    /// the DTB means translating a PCI address through two `ranges`
    /// properties, which `boot.fdt` deliberately refuses to do — and it is
    /// only alive at all because the pi5 loader trained the link. The
    /// loader therefore already knows the answer, and has probed the
    /// registers to confirm something answers there; re-deriving it in the
    /// kernel would be strictly worse-informed.
    ///
    /// When nonzero, `arch.boot.parseFirmwareTables` maps this page as
    /// device memory and points the serial driver at it BEFORE running
    /// firmware discovery, and suppresses the devicetree UART search so
    /// nothing displaces it. Zero reproduces the previous behaviour
    /// exactly: no new code runs on any x86 or QEMU-aarch64 boot.
    ///
    /// Same explicit-assignment requirement as `dtb_phys` above, and for
    /// the same reason — a garbage value here is an MMIO mapping of an
    /// arbitrary physical page that the kernel then writes characters into.
    ///
    /// Appended after `dtb_phys`, which is 8-aligned and 8 bytes wide, so
    /// this shifts no existing field's offset.
    console_base: PAddr = PAddr.fromInt(0),
};

pub const MMap = extern struct {
    key: uefi.tables.MemoryMapKey,
    mmap: [*]uefi.tables.MemoryDescriptor,
    mmap_size: u64,
    descriptor_size: u64,
    num_descriptors: u64,
};

pub const MMapEntry = struct {
    start_paddr: u64,
    num_pages: u64,
    type: MMapEntryType,
};

pub const STACK_SIZE: u64 = paging.PAGE4K * 8;
pub const MAX_MMAP_ENTRIES = 256;

pub fn collapseMMap(
    map: *const MMap,
    mmap_entries: *[MAX_MMAP_ENTRIES]MMapEntry,
) []MMapEntry {
    std.debug.assert(map.num_descriptors <= MAX_MMAP_ENTRIES);

    var idx: u64 = 0;
    for (0..map.num_descriptors) |i| {
        const descriptor: *uefi.tables.MemoryDescriptor = @ptrFromInt(i * map.descriptor_size + @intFromPtr(map.mmap));

        const t: MMapEntryType = switch (descriptor.type) {
            .conventional_memory,
            .loader_code,
            .loader_data,
            .boot_services_code,
            .boot_services_data,
            => .free,
            .acpi_reclaim_memory => .acpi,
            else => .reserved,
        };

        if (idx == 0) {
            mmap_entries[0].start_paddr = descriptor.physical_start;
            mmap_entries[0].num_pages = descriptor.number_of_pages;
            mmap_entries[0].type = t;
            idx = 1;
            continue;
        }

        const prev = &mmap_entries[idx - 1];
        const prev_end = prev.start_paddr + prev.num_pages * 4096;

        if (t == prev.type and descriptor.physical_start == prev_end) {
            prev.num_pages += descriptor.number_of_pages;
        } else {
            std.debug.assert(idx < MAX_MMAP_ENTRIES);
            mmap_entries[idx].start_paddr = descriptor.physical_start;
            mmap_entries[idx].num_pages = descriptor.number_of_pages;
            mmap_entries[idx].type = t;
            idx += 1;
        }
    }

    return mmap_entries[0..idx];
}

pub fn getMmap(
    boot_services: *uefi.tables.BootServices,
) ?MMap {
    var mmap_size: u64 = 0;
    var mmap: ?[*]uefi.tables.MemoryDescriptor = null;
    var key: uefi.tables.MemoryMapKey = undefined;
    var descriptor_size: u64 = undefined;
    var descriptor_version: u32 = undefined;

    var status = boot_services._getMemoryMap(
        &mmap_size,
        null,
        &key,
        &descriptor_size,
        &descriptor_version,
    );
    if (status != .buffer_too_small) return null;

    mmap_size += 2 * descriptor_size;

    status = boot_services._allocatePool(
        .loader_data,
        mmap_size,
        @ptrCast(&mmap),
    );
    if (status != .success) return null;

    status = boot_services._getMemoryMap(
        &mmap_size,
        @ptrCast(mmap),
        &key,
        &descriptor_size,
        &descriptor_version,
    );
    switch (status) {
        .success => return MMap{
            .key = key,
            .mmap = mmap.?,
            .mmap_size = mmap_size,
            .descriptor_size = descriptor_size,
            .num_descriptors = @divExact(mmap_size, descriptor_size),
        },
        else => {
            return null;
        },
    }
}

pub fn findXSDP() !u64 {
    for (0..uefi.system_table.number_of_table_entries) |i| {
        const ct = uefi.system_table.configuration_table[i];
        if (guidEq(
            ct.vendor_guid,
            ConfigurationTable.acpi_20_table_guid,
        )) {
            return @intFromPtr(ct.vendor_table);
        }
    }
    return uefi.Error.Aborted;
}

fn guidEq(a: Guid, b: Guid) bool {
    return a.time_low == b.time_low and a.time_mid == b.time_mid and a.time_high_and_version == b.time_high_and_version and a.clock_seq_high_and_reserved == b.clock_seq_high_and_reserved and a.clock_seq_low == b.clock_seq_low and std.mem.eql(
        u8,
        &a.node,
        &b.node,
    );
}
