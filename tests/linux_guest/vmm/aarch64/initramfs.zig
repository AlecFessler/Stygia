//! Initramfs loader for the aarch64 guest.
//!
//! The arm64 Linux boot protocol (Documentation/arm64/booting.rst
//! §"Kernel image format") lets the bootloader hand off an initramfs
//! blob by writing `linux,initrd-start` / `linux,initrd-end` properties
//! into /chosen — the fdt.zig generator emits those properties from the
//! values returned here.
//!
//! We copy the embedded cpio archive from `assets.initramfs` into guest
//! RAM at the caller-supplied destination, and report back the resulting
//! guest-physical range.

const assets = @import("assets");

pub const Range = struct {
    start: u64,
    end: u64,
};

/// Copy the embedded initramfs into guest memory at `dst` (the host VA
/// corresponding to `load_addr`) and return the guest-physical range so
/// the FDT generator can wire /chosen/linux,initrd-{start,end}.
///
/// If the asset is empty we return an empty range starting at `load_addr`;
/// Linux interprets that as "no initrd".
pub fn load(dst: [*]u8, load_addr: u64) Range {
    const src = assets.initramfs;
    var i: usize = 0;
    while (i < src.len) : (i += 1) dst[i] = src[i];
    return .{ .start = load_addr, .end = load_addr + src.len };
}
