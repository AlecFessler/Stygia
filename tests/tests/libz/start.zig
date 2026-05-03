// libz/start.zig — process entry point shared by both the static
// runner and the dynamic test ELFs.
//
// Test ELFs reach this entry with their R_*_RELATIVE relocs already
// applied by the kernel ELF loader, but their R_*_GLOB_DAT and
// R_*_JUMP_SLOT slots (referencing libz.so symbols) still pointing
// at zero. Before app.main runs we have to:
//
//   1. Read the libz page_frame handle from cap-table slot
//      LIBZ_PF_SLOT (= 5; the runner places it there in spawnOne).
//   2. createVar with R+X covering the libz image, preferred_base =
//      LIBZ_SLIDE so the kernel-chosen base matches the runner's
//      pre-applied RELATIVE relocs.
//   3. mapPf the libz pf into that var. After this the libz code at
//      LIBZ_SLIDE+offset is callable.
//   4. libz_loader.relocateSelf(slide, LIBZ_SLIDE) — walks our own
//      .rela.dyn / .rela.plt and patches each missing slot against
//      the libz image's exported symbol table.
//
// Steps 2 and 3 must use the raw inline-asm primitives (`issueReg`,
// not the high-level wrappers) — the high-level wrappers in
// tests/tests/libz/syscall.zig are now extern decls resolved against
// libz.elf, so calling them before relocateSelf would hit unpatched
// JUMP_SLOTs and crash.
//
// The runner (root_service.elf) shares this file but is statically
// linked. It has no libz_pf in its cap table — bootstrap must be a
// no-op. The `is_runner` gate keys off whether the app module
// declares the runner-only marker `RUNNER_STATIC`.

const builtin = @import("builtin");

const app = @import("app");
const lib = @import("lib");
const libz_loader = @import("libz_loader");

// Linker-defined symbol at the ELF load base. ld.lld emits this for
// every PIE binary as a hidden internal symbol — its runtime address
// equals our ELF's slide. We don't need it in dynsym; the reference
// is satisfied at link time and the kernel's RELATIVE-reloc pass
// patches the captured pointer with the chosen slide.
extern const __ehdr_start: u8;

const is_runner = @hasDecl(app, "RUNNER_STATIC");

// `pub` is required for `@hasDecl(root, "_start")` in std/start.zig
// to see this decl when test ELFs build with os_tag = .linux. Without
// pub, std would emit its own _start and collide.
//
// Per §[create_capability_domain]: "The pointer to the new domain's
// read-only view of its capability table is passed as the first
// argument to the initial EC's entry point." On x86-64 SysV that's
// rdi at entry; on AAPCS64 that's x0 at entry. The kernel ELF loader
// jumps to e_entry + slide as an ordinary function call after
// applying R_*_RELATIVE relocs.
pub export fn _start(cap_table_base: u64) noreturn {
    if (!is_runner) {
        bootstrapLibz(cap_table_base);
        const slide = @intFromPtr(&__ehdr_start);
        _ = libz_loader.relocateSelf(slide, libz_loader.LIBZ_SLIDE);
    }
    app.main(cap_table_base);
    // Fall-through: drop the self-handle, which per spec §[delete]
    // cleans up the calling capability domain.
    //
    // Must use `issueRegDiscard` directly. ReleaseSmall LLVM otherwise
    // strips the entire `issueReg → issueRawNoStack` chain when the
    // returned `Regs` is unused — the chain has 13 output operands
    // none of which feed any side-effecting consumer downstream, so
    // the optimizer proves the chain dead and removes the inner
    // `asm volatile` along with it.
    lib.syscall.issueRegDiscard(.delete, 0, .{ .v1 = lib.caps.SLOT_SELF });
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => @compileError("unsupported target architecture for _start halt"),
        }
    }
}

// Stub to satisfy std/start.zig's `@TypeOf(root.main)` lookup on the
// .linux target. std's posix-startup chain references `root.main`
// even when its `_start` isn't exported (because we provide ours),
// and Zig type-checks the chain regardless. This stub is never
// called — our `_start` is the real entry.
pub fn main() void {}

fn bootstrapLibz(cap_table_base: u64) void {
    // Read the libz pf handle out of cap-table slot LIBZ_PF_SLOT.
    // The runner installed it there as the third entry of
    // passed_handles in spawnOne. Kernel-mutable snapshot in
    // `field0` (bits 0-31) carries the pf's page count — we use
    // it to size the Var rather than baking a constant.
    const cap = lib.caps.readCap(cap_table_base, libz_loader.LIBZ_PF_SLOT);
    const pf_handle: u64 = @as(u64, cap.id());
    const page_count: u64 = @as(u64, @truncate(cap.field0 & 0xFFFF_FFFF));

    // createVar(caps={r,x}, props={cur_rwx=r|x, sz=0}, pages=page_count,
    //           preferred_base=LIBZ_SLIDE, device_region=0)
    //
    // libz.elf is built with read-only PT_LOADs only after pre-link
    // (no writable .data referenced by syscall wrappers), so R+X is
    // sufficient. Pinning preferred_base = LIBZ_SLIDE is what makes
    // the runner's pre-applied RELATIVE relocs land correctly.
    const var_caps = lib.caps.VarCap{ .r = true, .x = true };
    const var_caps_word: u64 = @as(u64, var_caps.toU16());
    const props: u64 = 0b101; // cur_rwx = r|x

    const cvar = lib.syscall.issueReg(.create_var, 0, .{
        .v1 = var_caps_word,
        .v2 = props,
        .v3 = page_count,
        .v4 = libz_loader.LIBZ_SLIDE,
        .v5 = 0,
    });
    // Successful createVar returns a handle word with caps in bits
    // 48-63 + handle id in bits 0-11; errors (errors.Error variants)
    // return a small value < 16 in v1. Bootstrap is fatal: if libz
    // can't be staged, no extern call works — park on hlt and let
    // the runner's recv timeout MISS-record the test.
    if (cvar.v1 < 16) haltForever();
    const var_handle: u64 = cvar.v1 & 0xFFF;

    const mp = lib.syscall.issueReg(
        .map_pf,
        lib.syscall.extraCount(1),
        .{
            .v1 = var_handle,
            .v2 = 0,
            .v3 = pf_handle,
        },
    );
    // map_pf returns OK (0) on success, error code in v1 on failure.
    if (mp.v1 != 0) haltForever();
}

fn haltForever() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => @compileError("unsupported target architecture"),
        }
    }
}
