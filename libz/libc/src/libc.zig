// libz/libc — minimal C-ABI compatibility layer for Stygia userspace.
//
// This file is the root of the static archive that Zig+LLVM (cross-
// compiled for x86_64-stygia-none) links against. Each submodule emits
// a focused subset of the libc surface via `comptime` `@export` blocks.
//
// Sub-module layout:
//   errno.zig   — errno (global; single-threaded first cut)
//   string.zig  — memcpy/memmove/memset/memcmp/memchr + str*
//   ctype.zig   — isalpha/isdigit/etc + glibc __ctype_*_loc tables
//   cxxabi.zig  — __cxa_atexit/finalize/pure_virtual/guard_*
//   pthread.zig — single-threaded no-op pthread surface
//   stdlib.zig  — exit/abort/abs/getenv/strto*/qsort/rand
//
// Submodules will be added incrementally as Phase 4c.2 lands.
// PORT_CHECKLIST.md tracks what's left.

// Override std's default panic so debug-mode safety checks (integer
// overflow, bounds, etc.) compile cleanly. The stock defaultPanic
// pulls in dumpStackTrace → selfExePath, neither of which the
// patched stdlib supports on Stygia. For a static-archive that's never
// invoked from Zig's own runtime, panics being abort()-shaped is
// fine — the consuming C/C++ code has its own crash machinery.
pub const panic = std.debug.no_panic;

const std = @import("std");

comptime {
    _ = @import("errno.zig");
    _ = @import("string.zig");
    _ = @import("ctype.zig");
    _ = @import("cxxabi.zig");
    _ = @import("pthread.zig");
    _ = @import("stdlib.zig");
    _ = @import("math.zig");
    _ = @import("locale.zig");
    _ = @import("signal.zig");
    _ = @import("dl.zig");
    _ = @import("network.zig");
    _ = @import("wide.zig");
    _ = @import("process.zig");
    _ = @import("strings_extra.zig");
    _ = @import("fortify.zig");
    _ = @import("mman.zig");
    _ = @import("malloc.zig");
    _ = @import("time.zig");
    _ = @import("posix_io.zig");
    _ = @import("stdio.zig");
}
