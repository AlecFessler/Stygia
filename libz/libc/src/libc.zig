// libz/libc — minimal C-ABI compatibility layer for Zag userspace.
//
// This file is the root of the static archive that Zig+LLVM (cross-
// compiled for x86_64-zag-none) links against. Each submodule emits
// a focused subset of the libc surface via `comptime` `@export` blocks.
//
// Sub-module layout:
//   errno.zig   — errno (global; single-threaded first cut)
//   string.zig  — memcpy/memmove/memset/memcmp/memchr + str*
//
// Submodules will be added incrementally as Phase 4c.2 lands.
// PORT_CHECKLIST.md tracks what's left.

// Override std's default panic so debug-mode safety checks (integer
// overflow, bounds, etc.) compile cleanly. The stock defaultPanic
// pulls in dumpStackTrace → selfExePath, neither of which the
// patched stdlib supports on Zag. For a static-archive that's never
// invoked from Zig's own runtime, panics being abort()-shaped is
// fine — the consuming C/C++ code has its own crash machinery.
pub const panic = std.debug.no_panic;

const std = @import("std");

comptime {
    _ = @import("errno.zig");
    _ = @import("string.zig");
}
