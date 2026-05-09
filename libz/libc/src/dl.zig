// dl — dynamic-loader stubs.
//
// The cross-compiled Zig+LLVM is statically linked. dlopen returns
// NULL (no shared object loading), dlsym likewise. dl_iterate_phdr
// could in principle walk our own ELF (the Stygia-target binary's PHDR
// table is at AUXV AT_PHDR / AT_PHNUM if we wired one), but for now
// returns 0 immediately so libgcc/libunwind treat us as no-modules.
//
// dladdr is a debug helper; returning 0 means "not in any module"
// which makes backtrace machinery emit "??" frames — fine for us.

const empty: [*:0]const u8 = "";

export fn dlopen(name: ?[*:0]const u8, flags: c_int) callconv(.c) ?*anyopaque {
    _ = .{ name, flags };
    return null;
}

export fn dlclose(handle: ?*anyopaque) callconv(.c) c_int {
    _ = handle;
    return 0;
}

export fn dlsym(handle: ?*anyopaque, name: [*:0]const u8) callconv(.c) ?*anyopaque {
    _ = .{ handle, name };
    return null;
}

export fn dlerror() callconv(.c) ?[*:0]const u8 {
    return null;
}

export fn dladdr(addr: ?*const anyopaque, info: ?*anyopaque) callconv(.c) c_int {
    _ = .{ addr, info };
    return 0;
}

export fn dl_iterate_phdr(
    callback: ?*const fn (?*const anyopaque, usize, ?*anyopaque) callconv(.c) c_int,
    data: ?*anyopaque,
) callconv(.c) c_int {
    _ = .{ callback, data };
    return 0;
}

export fn _dl_find_object(addr: ?*const anyopaque, info: ?*anyopaque) callconv(.c) c_int {
    _ = .{ addr, info };
    return -1;
}
