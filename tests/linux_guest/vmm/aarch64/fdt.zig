//! Minimal flattened device tree (FDT/DTB) generator.
//!
//! Emits a DTB compliant with Devicetree Specification v0.4 §5 "Flattened
//! Devicetree (DTB) Format". The output is just enough to let a Linux
//! arm64 kernel come up on top of Stygia's aarch64 VM layer:
//!
//!   /                       (compatible "linux,dummy-virt")
//!   /chosen                 (bootargs + initrd range)
//!   /cpus/cpu@0             (PSCI enable method, single vCPU)
//!   /psci                   (PSCI 1.0 via HVC conduit)
//!   /memory@40000000        (single RAM bank starting at 0x40000000)
//!   /intc@8000000           (GICv3 — matches kernel vgic base constants)
//!   /timer                  (armv8 arch timer, virtual PPI 27)
//!   /pl011@9000000          (emulated UART — see pl011.zig)
//!
//! The binary format is:
//!   fdt_header (40 bytes, big-endian)
//!   reserve map (FDT_RESERVE_ENTRY terminator)
//!   structure block (FDT_BEGIN_NODE / FDT_PROP / FDT_END_NODE / FDT_END)
//!   strings block
//!
//! DeviceTree Specification v0.4 references:
//!   §5.2   Header
//!   §5.3   Memory reservation block
//!   §5.4   Structure block
//!   §5.5   Strings block
//!   §2.3   Standard properties ("compatible", "reg", "#address-cells", …)
//!   §3.7   /chosen node
//!   §3.8   /cpus node
//!
//! PSCI bindings: Linux `Documentation/devicetree/bindings/arm/psci.yaml`.
//! GICv3 bindings: Linux `Documentation/devicetree/bindings/interrupt-controller/arm,gic-v3.yaml`.
//! armv8 timer bindings: Linux `Documentation/devicetree/bindings/timer/arm,arch_timer.yaml`.
//! PL011 bindings: Linux `Documentation/devicetree/bindings/serial/arm,pl011.yaml`.

const std = @import("std");

pub const FDT_MAGIC: u32 = 0xd00dfeed;
pub const FDT_VERSION: u32 = 17;
pub const FDT_LAST_COMP_VERSION: u32 = 16;

const FDT_BEGIN_NODE: u32 = 0x00000001;
const FDT_END_NODE: u32 = 0x00000002;
const FDT_PROP: u32 = 0x00000003;
const FDT_NOP: u32 = 0x00000004;
const FDT_END: u32 = 0x00000009;

pub const Config = struct {
    /// Guest physical base of main RAM (e.g. 0x4000_0000).
    ram_base: u64,
    /// Size of main RAM bank in bytes.
    ram_size: u64,
    /// Guest physical address where the initramfs was loaded.
    initrd_start: u64,
    /// Exclusive upper bound of the initramfs range.
    initrd_end: u64,
    /// Kernel command line passed via /chosen/bootargs.
    bootargs: []const u8,
    /// GICv3 distributor base (Devicetree v0.4 §2.3.6 "reg").
    gicd_base: u64,
    gicd_size: u64,
    /// GICv3 redistributor base.
    gicr_base: u64,
    gicr_size: u64,
    /// PL011 UART base.
    uart_base: u64,
    uart_size: u64,
};

pub const BuildError = error{
    OutOfSpace,
};

/// Builder that writes a DTB into a caller-provided buffer. Caller must
/// ensure the buffer is large enough; we fail with OutOfSpace rather than
/// overrun. A 16 KiB buffer is more than sufficient for the layout above.
pub const Builder = struct {
    buf: []u8,
    struct_off: usize = 0,
    strings_off: usize = 0,
    strings_len: usize = 0,
    struct_start: usize = 0,
    strings_start: usize = 0,

    pub fn init(buf: []u8) Builder {
        return .{ .buf = buf };
    }

    fn writeU32BE(self: *Builder, off: usize, val: u32) BuildError!void {
        if (off + 4 > self.buf.len) return error.OutOfSpace;
        self.buf[off + 0] = @intCast((val >> 24) & 0xFF);
        self.buf[off + 1] = @intCast((val >> 16) & 0xFF);
        self.buf[off + 2] = @intCast((val >> 8) & 0xFF);
        self.buf[off + 3] = @intCast(val & 0xFF);
    }

    fn writeU64BE(self: *Builder, off: usize, val: u64) BuildError!void {
        try self.writeU32BE(off, @intCast(val >> 32));
        try self.writeU32BE(off + 4, @intCast(val & 0xFFFFFFFF));
    }

    fn appendU32(self: *Builder, val: u32) BuildError!void {
        try self.writeU32BE(self.struct_off, val);
        self.struct_off += 4;
    }

    fn appendBytes(self: *Builder, data: []const u8) BuildError!void {
        if (self.struct_off + data.len > self.buf.len) return error.OutOfSpace;
        @memcpy(self.buf[self.struct_off..][0..data.len], data);
        self.struct_off += data.len;
    }

    fn alignStruct(self: *Builder) BuildError!void {
        while (self.struct_off & 3 != 0) {
            if (self.struct_off >= self.buf.len) return error.OutOfSpace;
            self.buf[self.struct_off] = 0;
            self.struct_off += 1;
        }
    }

    /// Intern a property name in the strings block. Duplicates are folded
    /// by a linear scan — cheap for the small number of props we emit.
    fn internString(self: *Builder, name: []const u8) BuildError!u32 {
        // Scan existing strings.
        var i: usize = 0;
        while (i < self.strings_len) {
            const slice_start = self.strings_start + i;
            var j: usize = 0;
            while (self.buf[slice_start + j] != 0) : (j += 1) {}
            const existing = self.buf[slice_start .. slice_start + j];
            if (std.mem.eql(u8, existing, name)) return @intCast(i);
            i += j + 1;
        }
        const required = name.len + 1;
        if (self.strings_start + self.strings_len + required > self.buf.len) return error.OutOfSpace;
        const out_off = self.strings_start + self.strings_len;
        @memcpy(self.buf[out_off..][0..name.len], name);
        self.buf[out_off + name.len] = 0;
        const result: u32 = @intCast(self.strings_len);
        self.strings_len += required;
        return result;
    }

    pub fn beginNode(self: *Builder, name: []const u8) BuildError!void {
        try self.appendU32(FDT_BEGIN_NODE);
        try self.appendBytes(name);
        try self.appendBytes(&.{0});
        try self.alignStruct();
    }

    pub fn endNode(self: *Builder) BuildError!void {
        try self.appendU32(FDT_END_NODE);
    }

    fn propHeader(self: *Builder, name: []const u8, data_len: u32) BuildError!void {
        const name_off = try self.internString(name);
        try self.appendU32(FDT_PROP);
        try self.appendU32(data_len);
        try self.appendU32(name_off);
    }

    pub fn propString(self: *Builder, name: []const u8, value: []const u8) BuildError!void {
        const total: u32 = @intCast(value.len + 1);
        try self.propHeader(name, total);
        try self.appendBytes(value);
        try self.appendBytes(&.{0});
        try self.alignStruct();
    }

    /// Emit a "stringlist" property: multiple NUL-terminated strings
    /// concatenated. Used for `compatible`.
    pub fn propStringList(self: *Builder, name: []const u8, values: []const []const u8) BuildError!void {
        var total: u32 = 0;
        for (values) |v| total += @intCast(v.len + 1);
        try self.propHeader(name, total);
        for (values) |v| {
            try self.appendBytes(v);
            try self.appendBytes(&.{0});
        }
        try self.alignStruct();
    }

    pub fn propU32(self: *Builder, name: []const u8, val: u32) BuildError!void {
        try self.propHeader(name, 4);
        try self.appendU32(val);
    }

    pub fn propU64(self: *Builder, name: []const u8, val: u64) BuildError!void {
        try self.propHeader(name, 8);
        try self.appendU32(@intCast(val >> 32));
        try self.appendU32(@intCast(val & 0xFFFFFFFF));
    }

    pub fn propCells(self: *Builder, name: []const u8, cells: []const u32) BuildError!void {
        const total: u32 = @intCast(cells.len * 4);
        try self.propHeader(name, total);
        for (cells) |c| try self.appendU32(c);
    }

    pub fn propEmpty(self: *Builder, name: []const u8) BuildError!void {
        try self.propHeader(name, 0);
    }

    /// Finalize the DTB: write FDT_END, move the strings block to sit
    /// directly after the structure block, and emit the 40-byte header.
    /// Returns the total DTB size in bytes.
    pub fn finalize(self: *Builder) BuildError!usize {
        try self.appendU32(FDT_END);

        // Move strings block to sit directly after the structure block.
        const struct_size = self.struct_off - self.struct_start;
        const strings_relocate_to = self.struct_off;
        if (strings_relocate_to + self.strings_len > self.buf.len) return error.OutOfSpace;

        // The strings block was staged at the tail of the buffer; copy it
        // down to its final position right after the structure block.
        var i: usize = 0;
        while (i < self.strings_len) : (i += 1) {
            self.buf[strings_relocate_to + i] = self.buf[self.strings_start + i];
        }

        const total_size = strings_relocate_to + self.strings_len;

        // Header — Devicetree Specification §5.2.
        try self.writeU32BE(0, FDT_MAGIC);
        try self.writeU32BE(4, @intCast(total_size));
        try self.writeU32BE(8, @intCast(self.struct_start));
        try self.writeU32BE(12, @intCast(strings_relocate_to));
        // off_mem_rsvmap points to the start of the memory reservation
        // block, which must end with a 16-byte (addr=0, size=0) terminator.
        // We reserve exactly 16 bytes after the 40-byte header for the
        // terminator (struct_start = 40 + 16 = 56), so the reserve block
        // begins at offset 40 — NOT 48. Setting off_mem_rsvmap = 48 leaves
        // only 8 bytes for the terminator and lets the size-half overlap
        // FDT_BEGIN_NODE (0x00000001 BE), which Linux reads as size =
        // 0x100000000 → it never sees a terminator and walks past the FDT.
        try self.writeU32BE(16, 40);
        try self.writeU32BE(20, FDT_VERSION);
        try self.writeU32BE(24, FDT_LAST_COMP_VERSION);
        try self.writeU32BE(28, 0); // boot_cpuid_phys
        try self.writeU32BE(32, @intCast(self.strings_len));
        try self.writeU32BE(36, @intCast(struct_size));

        return total_size;
    }
};

/// Emit a full DTB describing a Linux-virt-ish aarch64 guest into `out`.
/// Returns the number of bytes written. Caller-provided buffer should be
/// >= 8 KiB; the layout above fits comfortably under 2 KiB.
pub fn build(out: []u8, cfg: Config) BuildError!usize {
    var b = Builder.init(out);

    // Header placeholder (40 bytes) + reservation map (one empty entry
    // = 16 zero bytes) precede the structure block. §5.3 requires the
    // reservation block to end with an entry of {0, 0}.
    b.struct_start = 40 + 16;
    // Stage the strings block at the tail of the buffer; `finalize`
    // relocates it to sit right after the structure block.
    b.strings_start = out.len - 1024;
    b.struct_off = b.struct_start;

    // Zero the reservation map terminator.
    var i: usize = 40;
    while (i < b.struct_start) : (i += 1) out[i] = 0;

    // Root node — DTSpec §3.1.
    try b.beginNode("");
    try b.propU32("#address-cells", 2);
    try b.propU32("#size-cells", 2);
    try b.propString("compatible", "linux,dummy-virt");
    try b.propString("model", "linux_guest-arm64");

    // /chosen — Linux consumes bootargs and initrd range here.
    // DTSpec §3.7; Linux `Documentation/arm64/booting.rst`.
    try b.beginNode("chosen");
    try b.propString("bootargs", cfg.bootargs);
    try b.propU64("linux,initrd-start", cfg.initrd_start);
    try b.propU64("linux,initrd-end", cfg.initrd_end);
    try b.propString("stdout-path", "/pl011@9000000");
    try b.endNode();

    // /psci — method=hvc matches the kernel's HVC trap classifier in
    // kernel/arch/aarch64/kvm/psci.zig. Function IDs are SMC64 aliases
    // (DEN 0022F Table 5.1); we advertise the subset the VMM handles.
    try b.beginNode("psci");
    try b.propStringList("compatible", &.{ "arm,psci-1.0", "arm,psci-0.2", "arm,psci" });
    try b.propString("method", "hvc");
    try b.propU32("cpu_on", 0xC4000003);
    try b.propU32("cpu_off", 0x84000002);
    try b.propU32("sys_reset", 0x84000009);
    try b.propU32("sys_poweroff", 0x84000008);
    try b.propU32("migrate", 0xC4000005);
    try b.endNode();

    // /cpus/cpu@0 — single vCPU enabled via PSCI.
    try b.beginNode("cpus");
    try b.propU32("#address-cells", 1);
    try b.propU32("#size-cells", 0);

    try b.beginNode("cpu@0");
    try b.propString("device_type", "cpu");
    try b.propString("compatible", "arm,armv8");
    try b.propU32("reg", 0);
    try b.propString("enable-method", "psci");
    try b.endNode(); // cpu@0
    try b.endNode(); // cpus

    // /memory@<base> — DTSpec §3.4. reg is <addr-hi addr-lo size-hi size-lo>.
    try b.beginNode("memory@40000000");
    try b.propString("device_type", "memory");
    try b.propCells("reg", &.{
        @intCast(cfg.ram_base >> 32),
        @intCast(cfg.ram_base & 0xFFFFFFFF),
        @intCast(cfg.ram_size >> 32),
        @intCast(cfg.ram_size & 0xFFFFFFFF),
    });
    try b.endNode();

    // /intc@8000000 — GICv3. bindings: arm,gic-v3.yaml.
    // reg = <dist_base_hi dist_base_lo dist_size_hi dist_size_lo
    //        redist_base_hi redist_base_lo redist_size_hi redist_size_lo>.
    try b.beginNode("intc@8000000");
    try b.propString("compatible", "arm,gic-v3");
    try b.propU32("#interrupt-cells", 3);
    try b.propEmpty("interrupt-controller");
    try b.propU32("#address-cells", 2);
    try b.propU32("#size-cells", 2);
    try b.propCells("reg", &.{
        @intCast(cfg.gicd_base >> 32),
        @intCast(cfg.gicd_base & 0xFFFFFFFF),
        @intCast(cfg.gicd_size >> 32),
        @intCast(cfg.gicd_size & 0xFFFFFFFF),
        @intCast(cfg.gicr_base >> 32),
        @intCast(cfg.gicr_base & 0xFFFFFFFF),
        @intCast(cfg.gicr_size >> 32),
        @intCast(cfg.gicr_size & 0xFFFFFFFF),
    });
    try b.propU32("phandle", 1);
    try b.endNode();

    // /timer — armv8 arch timer. Interrupts are PPIs 13..10 for the four
    // timer flavours; `interrupts` uses 3-cell format <type intid flags>
    // where type=1 (PPI), intid = GIC_PPI number - 16, flags=8 (level low
    // as typically used by kvmtool/qemu virt).
    try b.beginNode("timer");
    try b.propString("compatible", "arm,armv8-timer");
    try b.propEmpty("always-on");
    try b.propCells("interrupts", &.{
        1, 13, 8, // secure-phys PPI 29
        1, 14, 8, // non-secure-phys PPI 30
        1, 11, 8, // virt PPI 27
        1, 10, 8, // hyp-phys PPI 26
    });
    try b.endNode();

    // /apb-pclk — fixed-rate clock for the PL011. The Linux pl011 driver
    // requires both `clocks` AND `clock-names` to be present and resolvable
    // before it will probe; without it we get "Warning: unable to open an
    // initial console" from init. A single fixed-clock advertised under
    // both phandles works for the simple driver path.
    try b.beginNode("apb-pclk");
    try b.propString("compatible", "fixed-clock");
    try b.propU32("#clock-cells", 0);
    try b.propU32("clock-frequency", 24_000_000);
    try b.propString("clock-output-names", "clk24mhz");
    try b.propU32("phandle", 2);
    try b.endNode();

    // /pl011@9000000 — emulated UART. interrupts = <0 1 4> (SPI 1, level
    // high). Matches the IRQ the VMM asserts from pl011.zig on TX.
    try b.beginNode("pl011@9000000");
    try b.propStringList("compatible", &.{ "arm,pl011", "arm,primecell" });
    try b.propCells("reg", &.{
        @intCast(cfg.uart_base >> 32),
        @intCast(cfg.uart_base & 0xFFFFFFFF),
        @intCast(cfg.uart_size >> 32),
        @intCast(cfg.uart_size & 0xFFFFFFFF),
    });
    try b.propCells("interrupts", &.{ 0, 1, 4 });
    try b.propU32("interrupt-parent", 1);
    try b.propCells("clocks", &.{ 2, 2 });
    try b.propStringList("clock-names", &.{ "uartclk", "apb_pclk" });
    try b.endNode();

    try b.endNode(); // root

    return b.finalize();
}
