// network — pure ENOSYS stubs.
//
// The Zig compiler doesn't open sockets; LLVM/clang only reach for
// hostname lookup and getsockopt in pretty narrow places. Returning
// errors is correct for all of them — the caller treats networking
// as unavailable and falls back to non-network paths.

const ENOSYS: c_int = 38;
const EAFNOSUPPORT: c_int = 97;

extern fn __errno_location() callconv(.c) *c_int;

fn fail(err: c_int) c_int {
    __errno_location().* = err;
    return -1;
}

export fn socket(domain: c_int, kind: c_int, protocol: c_int) callconv(.c) c_int {
    _ = .{ domain, kind, protocol };
    return fail(EAFNOSUPPORT);
}

export fn bind(sock: c_int, addr: ?*const anyopaque, addrlen: c_uint) callconv(.c) c_int {
    _ = .{ sock, addr, addrlen };
    return fail(ENOSYS);
}

export fn listen(sock: c_int, backlog: c_int) callconv(.c) c_int {
    _ = .{ sock, backlog };
    return fail(ENOSYS);
}

export fn accept(sock: c_int, addr: ?*anyopaque, addrlen: ?*c_uint) callconv(.c) c_int {
    _ = .{ sock, addr, addrlen };
    return fail(ENOSYS);
}

export fn accept4(sock: c_int, addr: ?*anyopaque, addrlen: ?*c_uint, flags: c_int) callconv(.c) c_int {
    _ = .{ sock, addr, addrlen, flags };
    return fail(ENOSYS);
}

export fn connect(sock: c_int, addr: ?*const anyopaque, addrlen: c_uint) callconv(.c) c_int {
    _ = .{ sock, addr, addrlen };
    return fail(ENOSYS);
}

export fn getsockname(sock: c_int, addr: ?*anyopaque, addrlen: ?*c_uint) callconv(.c) c_int {
    _ = .{ sock, addr, addrlen };
    return fail(ENOSYS);
}

export fn getsockopt(sock: c_int, level: c_int, optname: c_int, optval: ?*anyopaque, optlen: ?*c_uint) callconv(.c) c_int {
    _ = .{ sock, level, optname, optval, optlen };
    return fail(ENOSYS);
}

export fn setsockopt(sock: c_int, level: c_int, optname: c_int, optval: ?*const anyopaque, optlen: c_uint) callconv(.c) c_int {
    _ = .{ sock, level, optname, optval, optlen };
    return fail(ENOSYS);
}

export fn sendmsg(sock: c_int, msg: ?*const anyopaque, flags: c_int) callconv(.c) isize {
    _ = .{ sock, msg, flags };
    _ = fail(ENOSYS);
    return -1;
}

export fn getaddrinfo(node: ?[*:0]const u8, service: ?[*:0]const u8, hints: ?*const anyopaque, res: ?*?*anyopaque) callconv(.c) c_int {
    _ = .{ node, service, hints, res };
    return -2; // EAI_AGAIN
}

export fn freeaddrinfo(res: ?*anyopaque) callconv(.c) void {
    _ = res;
}

export fn gethostname(name: [*]u8, len: usize) callconv(.c) c_int {
    if (len > 0) name[0] = 0;
    return 0;
}
