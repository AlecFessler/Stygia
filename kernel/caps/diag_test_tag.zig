// Test-only ELF attribution for the serial fault oracle. The test report
// helper materializes its manifest tag in a 32-bit MOVZ immediate on ARM.
pub fn extractAarch64(elf_bytes: []const u8) u32 {
    var found: u32 = 0;
    var i: usize = 0;
    while (i + 4 <= elf_bytes.len) : (i += 4) {
        const insn = readLeU32(elf_bytes, i);
        // Match MOVZ Wn only. Omitting bit 31 also matches MOVZ Xn; the
        // unrelated 0x8be1 immediate in vmar_restart/snapshot test ELFs
        // then makes their real report tag appear ambiguous.
        if ((insn & 0xFF80_0000) != 0x5280_0000) continue;

        const v = (insn >> 5) & 0xFFFF;
        if (v < 0x8000 or v >= 0x9000) continue;
        if (found == 0) {
            found = v;
        } else if (found != v) {
            return 0;
        }
    }
    return found;
}

fn readLeU32(bytes: []const u8, i: usize) u32 {
    return @as(u32, bytes[i]) |
        (@as(u32, bytes[i + 1]) << 8) |
        (@as(u32, bytes[i + 2]) << 16) |
        (@as(u32, bytes[i + 3]) << 24);
}

test "AArch64 tag parser ignores a misleading MOVZ X immediate" {
    const std = @import("std");
    // MOVZ W8, #0x8110 (manifest tag); MOVZ X9, #0x8be1 (ordinary data).
    const elf = [_]u8{ 0x08, 0x22, 0x90, 0x52, 0x29, 0x7c, 0x91, 0xd2 };
    try std.testing.expectEqual(@as(u32, 0x8110), extractAarch64(&elf));
    // The old 0x7F80_0000 mask matches both instructions and returns zero.
    try std.testing.expectEqual(@as(u32, 0x5280_0000), readLeU32(&elf, 4) & 0x7F80_0000);
}

test "AArch64 tag parser still rejects two distinct MOVZ W tags" {
    const std = @import("std");
    const elf = [_]u8{ 0x08, 0x22, 0x90, 0x52, 0x48, 0x22, 0x90, 0x52 };
    try std.testing.expectEqual(@as(u32, 0), extractAarch64(&elf));
}
