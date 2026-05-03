// Spec §[create_capability_domain] — test 16a.
//
// "[test 16a] returns E_INVAL if the ELF image is not position-
//  independent (no PT_DYNAMIC, or e_type != ET_DYN)."
//
// Strategy
//   Build a structurally valid ELF64 header with `e_type = ET_EXEC`
//   (2) instead of `ET_DYN` (3). The kernel must reject the image at
//   create_capability_domain time so it never proceeds to load
//   non-relocatable segments at randomized bases.
//
//   Other create_capability_domain failure paths neutralized:
//     - test 01 (E_PERM no `crcd`): runner grants `crcd` on the
//       child's self-handle.
//     - tests 02-12 (ceiling subset / restart_policy / fut_wait_max):
//       pass caps=0, ceilings_inner=0, ceilings_outer=0.
//     - test 13 (BADCAP): pass a freshly-minted page frame.
//     - test 14 (BADCAP passed handle): empty passed_handles slice.
//     - test 15 (malformed header): the Ehdr is well-formed.
//     - test 16 (declared size > frame): p_filesz fits the frame.
//     - test 17 (reserved bits): all caps/ceiling words are zero.
//     - test 18 (duplicate passed handles): empty slice.
//
// Action
//   1. create_page_frame(pages=1, sz=0)
//   2. create_var(pages=1, cur_rwx=rw)         — staging
//   3. map_pf(var, offset=0, pf)
//   4. write Ehdr (ET_EXEC) + minimal Phdr into the VAR
//   5. delete(var)                              — drop staging map
//   6. create_capability_domain(0,0,0, pf, []) — must return E_INVAL
//
// Assertions
//   1: create_page_frame returned an error
//   2: create_var returned an error
//   3: map_pf returned a non-OK status
//   4: create_capability_domain didn't return E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const EI_NIDENT: usize = 16;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const ELFOSABI_SYSV: u8 = 0;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PF_R: u32 = 0x4;
const PF_X: u32 = 0x1;

const Elf64Ehdr = extern struct {
    e_ident: [EI_NIDENT]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

const Elf64Phdr = extern struct {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

comptime {
    if (@sizeOf(Elf64Ehdr) != 64) @compileError("Elf64Ehdr size != 64");
    if (@sizeOf(Elf64Phdr) != 56) @compileError("Elf64Phdr size != 56");
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0,
        1,
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    const var_caps_word = caps.VarCap{ .r = true, .w = true };
    const cvar = syscall.createVar(
        @as(u64, var_caps_word.toU16()),
        0b011,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const var_handle: u12 = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    const map_result = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (map_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    const ehdr_ptr: *Elf64Ehdr = @ptrFromInt(var_base);
    ehdr_ptr.* = .{
        .e_ident = .{
            0x7F,       'E',         'L',        'F',
            ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_SYSV,
            0,          0,           0,          0,
            0,          0,           0,          0,
        },
        .e_type = ET_EXEC, // not PIE — the trigger for test 16a
        .e_machine = EM_X86_64,
        .e_version = EV_CURRENT,
        .e_entry = 0x400000,
        .e_phoff = 64,
        .e_shoff = 0,
        .e_flags = 0,
        .e_ehsize = 64,
        .e_phentsize = 56,
        .e_phnum = 1,
        .e_shentsize = 0,
        .e_shnum = 0,
        .e_shstrndx = 0,
    };

    const phdr_ptr: *Elf64Phdr = @ptrFromInt(var_base + 64);
    phdr_ptr.* = .{
        .p_type = PT_LOAD,
        .p_flags = PF_R | PF_X,
        .p_offset = 0,
        .p_vaddr = 0x400000,
        .p_paddr = 0x400000,
        .p_filesz = 256,
        .p_memsz = 256,
        .p_align = 0x1000,
    };

    _ = syscall.delete(var_handle);

    const result = syscall.createCapabilityDomain(0, 0, 0, pf_handle, 0, // initial_ec_affinity
        &.{});

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
