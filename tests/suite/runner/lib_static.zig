// lib_static.zig — runner-side libz entry point.
//
// The test runner (root_service.elf) is statically linked, so the
// `syscall` module aliased into this build target points at the
// top-level libz/syscall.zig (full inline-asm bodies, no externs).
// Test ELFs use the same `lib` import name but get the extern-decl
// flavor of syscall via their build target.

pub const caps = @import("caps");
pub const errors = @import("errors");
pub const syscall = @import("syscall");
pub const testing = @import("testing.zig");
