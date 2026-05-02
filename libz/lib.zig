// libz: kernel-shipped userspace library — spec-v3 syscall wrappers.
//
// This file is the static-link entry point. Consumers that statically
// link libz (root_service, the test runner) import this module and get
// function bodies inlined into their own ELF. Consumers that
// dynamically link libz (hyprvOS apps) import libz/api.zig instead,
// which exposes the same surface as `pub extern fn` declarations the
// userspace rtld resolves against the libz.elf shared object.
//
// Keep the surface here in lock-step with api.zig and the @export
// block at the bottom of syscall.zig: the three together define the
// libz ABI.

pub const syscall = @import("syscall.zig");

pub const Regs = syscall.Regs;
pub const RecvReturn = syscall.RecvReturn;
pub const SyscallNum = syscall.SyscallNum;
