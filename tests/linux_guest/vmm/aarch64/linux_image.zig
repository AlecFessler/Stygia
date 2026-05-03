//! Linux arm64 Image header parser.
//!
//! The Linux arm64 boot wrapper prepends every `arch/arm64/boot/Image` with
//! a 64-byte header whose fields describe how the bootloader should drop
//! the image into RAM. The format is documented in the Linux source tree
//! at `Documentation/arm64/booting.rst` §"Call the kernel image"; the
//! authoritative field layout lives in `arch/arm64/kernel/head.S` under
//! the `_head` block.
//!
//! Header layout (little-endian, offset from image start):
//!   0x00  u32  code0          — executable code or NOP
//!   0x04  u32  code1          — executable code
//!   0x08  u64  text_offset    — load offset from 2 MiB aligned base of RAM
//!   0x10  u64  image_size     — effective image size (head + text + bss)
//!   0x18  u64  flags          — bit 3: endianness, bits 1..2: page size,
//!                               bit 3 (since v3.17): physical placement
//!   0x20  u64  res2           — reserved, 0
//!   0x28  u64  res3           — reserved, 0
//!   0x30  u64  res4           — reserved, 0
//!   0x38  u32  magic          — 'ARM\x64' (0x644d5241 LE)
//!   0x3C  u32  res5           — reserved, 0
//!
//! Linux arm64 is always little-endian in our guest universe; we assert
//! the magic and otherwise ignore the flags field (see task brief M7.2).

pub const HEADER_SIZE: usize = 64;

/// Magic value at offset 0x38 of a valid Image header. Spelled as an ASCII
/// sequence "ARM\x64" stored little-endian.
pub const IMAGE_MAGIC: u32 = 0x644d5241; // 'A','R','M',0x64 in LE

pub const ParseError = error{
    TooShort,
    BadMagic,
};

pub const ImageHeader = struct {
    /// Offset from the 2-MiB-aligned RAM base at which Linux wants to be
    /// loaded. Standard value is 0x80000 (the historical TEXT_OFFSET).
    text_offset: u64,
    /// Total bytes of contiguous memory the kernel needs: covers the
    /// loaded image plus BSS. Useful for placing the FDT / initramfs
    /// beyond the kernel's end.
    image_size: u64,
    /// Entry PC relative to the image load address. Linux's entry is
    /// always the very first instruction of Image, so this is 0.
    entry_offset: u64,
};

fn readU32LE(buf: []const u8, off: usize) u32 {
    return @as(*align(1) const u32, @ptrCast(buf.ptr + off)).*;
}

fn readU64LE(buf: []const u8, off: usize) u64 {
    return @as(*align(1) const u64, @ptrCast(buf.ptr + off)).*;
}

/// Parse the 64-byte header at the start of an arm64 Image. Returns the
/// values the VMM needs to place the image in guest RAM.
pub fn parse(image_bytes: []const u8) ParseError!ImageHeader {
    if (image_bytes.len < HEADER_SIZE) return error.TooShort;

    const magic = readU32LE(image_bytes, 0x38);
    if (magic != IMAGE_MAGIC) return error.BadMagic;

    return ImageHeader{
        .text_offset = readU64LE(image_bytes, 0x08),
        .image_size = readU64LE(image_bytes, 0x10),
        .entry_offset = 0,
    };
}
