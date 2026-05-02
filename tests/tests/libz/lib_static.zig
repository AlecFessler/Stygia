// lib_static.zig — runner-side libz entry point.
//
// The test runner (root_service.elf) is statically linked, so it
// can't depend on the extern declarations that the dynamic test ELFs'
// libz/syscall.zig now uses. Instead, point the `syscall` namespace
// at the static source-of-truth at /home/alec/Zag-libz/libz/syscall.zig
// — that file carries full inline-asm wrapper bodies for every
// high-level call. The build wires it in as the `static_syscall`
// module dep.
//
// caps / errors / testing remain shared with the dynamic test ELFs
// (no syscall path conflicts: testing only uses `issueReg`, which
// stays statically compiled in either flavor of syscall.zig).

pub const caps = @import("caps.zig");
pub const errors = @import("errors.zig");
pub const syscall = @import("static_syscall");
pub const testing = @import("testing.zig");
