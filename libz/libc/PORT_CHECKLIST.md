# Zig+LLVM-on-Zag libc surface — categorized checklist

## How this list was built

`nm -D --undefined-only` over `~/.local/zag-toolchains/zig-0.15.2-bin` plus its loaded `.so` cluster (libLLVM, libclang-cpp, liblld{ELF,COFF,Wasm,Common}, libstdc++, libgcc_s), then subtracted symbols defined inside that cluster. Result: 444 symbols this binary cluster reaches OUT to. Raw lists in `work/`:

- `work/zig_bin_undef.txt` — direct undefineds of the zig ELF
- `work/transitive_undef.txt` — undefineds across the loaded `.so`s
- `work/internal_defined.txt` — defineds across the loaded `.so`s
- `work/external_undef.txt` — `(zig_bin ∪ transitive) − internal` ⇒ the libc/system surface

The 444 includes Arch Linux *system-package* deps that the upstream **static** Zig tarball does NOT have (libxml2 / libedit / libicu / libffi / zlib / zstd / iconv / gettext bundled into the static binary, never reaching out). When the upstream tarball download finishes, we'll re-run the same procedure and drop those rows. The buckets below ALREADY mark them clearly so downstream agents can skip.

## Buckets

### A — Trivially-implementable in Zig (string / mem / ctype / qsort / rand)

`memchr memcmp memcpy memmove memset` (plus FORTIFY `_chk` variants — needed only if libstdc++ build emits them; `-D_FORTIFY_SOURCE=0` avoids them entirely)
`strchr strcmp strcpy strncpy strdup strerror strerror_r strlen strncmp strnlen strpbrk strrchr strsignal strspn strstr strtok_r`
`isalnum isalpha isblank islower isspace isupper isxdigit tolower toupper`
`__ctype_b_loc __ctype_get_mb_cur_max __ctype_tolower_loc __ctype_toupper_loc` — glibc-internal table-pointer accessors; one-line: return pointer to a static 384-entry table (ctype tables can be lifted verbatim, public domain).
`qsort` — straightforward introsort.
`rand srand` — trivial LCG; only used by LLVM `init_random_state` smoke paths.
`arc4random getrandom getentropy` — back via `/dev/urandom`-equivalent or constant-seed (NOT cryptographic, used for hash randomization).

### B — Thin syscall wrappers (kernel ECs, mmap via VMAR, proc info)

`mmap mmap64 munmap mprotect madvise posix_madvise` — VMAR + page_frame
`brk sbrk` — not in this list, good (LLVM doesn't use it)
`getpid getuid getsid getpagesize getauxval` — return constants/PerCore-derived
`uname` — fill in struct utsname with constants
`getrlimit getrlimit64 setrlimit setrlimit64` — stub: report large limits; setrlimit no-op
`getrusage` — return zeros (LLVM uses for `-time-passes`)
`get_nprocs sched_getaffinity __sched_cpucount` — query SMP core count via sysreg/syscall
`sched_yield` — yield to scheduler
`sysconf` — switch over a tiny set of `_SC_*` selectors
`nanosleep usleep alarm` — over kernel timer object
`clock_gettime gettimeofday time` — over kernel monotonic timer
`gmtime gmtime_r localtime localtime_r strftime __strftime_l` — pure-Zig from epoch (no zoneinfo at first; assume UTC)

### C — fs_client IPC wrappers (the SQL-FS in desktopOS/fs)

`open open64 openat openat64 __openat_2 close read readv __read_chk write writev lseek lseek64 pread pread64 preadv64 pwrite64 pwritev64`
`stat stat64 lstat lstat64 fstat fstat64 fstatfs statfs statvfs`
`access faccessat chdir fchdir chmod fchmod fchmodat fchown ftruncate ftruncate64 truncate futimens utimensat`
`link unlink unlinkat symlink symlinkat rename renameat mkdir mkdirat mknod readlink readlinkat realpath __realpath_chk getcwd umask`
`opendir closedir readdir dirfd fdopendir`
`dup2 pipe pipe2 sendfile sendfile64 copy_file_range` — only if Zig/LLVM use them
`fcntl ioctl flock` — only F_SETFD/FD_CLOEXEC, F_GETFL/F_SETFL nonblock matter; rest stub-EINVAL
`shm_open shm_unlink` — stub (we don't have shm)
`inotify_init1 inotify_add_watch inotify_rm_watch` — stub; LLVM caches don't strictly need watching

### D — Futex-backed pthread (kernel futex; semantics in libz)

`pthread_attr_init pthread_attr_destroy pthread_attr_setguardsize pthread_attr_setstacksize`
`pthread_create pthread_join pthread_detach pthread_self pthread_setname_np pthread_getname_np pthread_setschedparam`
`pthread_mutex_lock pthread_mutex_unlock` (+ init/destroy not seen because static-init macro path)
`pthread_cond_wait pthread_cond_signal pthread_cond_broadcast pthread_cond_destroy`
`pthread_rwlock_rdlock pthread_rwlock_wrlock pthread_rwlock_unlock`
`pthread_key_create pthread_key_delete pthread_getspecific pthread_setspecific`
`pthread_once`
`pthread_sigmask` — stub (no signal delivery in Zag)
`__libc_single_threaded` — flag

### E — Stubbable / not-needed

`signal sigaction sigaddset sigemptyset sigfillset sigprocmask sigaltstack raise kill` — stub: ignore handler installs, kill→noop
`setjmp _setjmp longjmp __longjmp_chk siglongjmp` — REAL impl needed; LLVM uses for crash recovery and (in some passes) error escape. Pure-asm context save/restore.
`fork execv execve wait wait4 waitpid posix_spawn posix_spawn_file_actions_*` — stub-ENOSYS. Static Zig+LLVM doesn't shell out (we configure `-fno-lld`-ish equivalents and use Zig's in-process LLD link).
`pipe pipe2 socket bind listen connect accept accept4 getsockname getsockopt setsockopt sendmsg getaddrinfo freeaddrinfo gethostname getpwnam_r getpwuid_r` — stub-ENOSYS / EINVAL. Compiler doesn't network.
`dlopen dlsym dlclose dlerror dladdr _dl_find_object dl_iterate_phdr` — static binary; stub everything (dlopen→NULL, dl_iterate_phdr→walk our own ELF PHDRs once)
`backtrace` — stub: return 0 frames
`__assert_fail abort _exit exit _Exit` — print + halt; atexit runners over `__cxa_atexit` table
`bindtextdomain bind_textdomain_codeset dgettext gettext` — stub: return passed string unchanged (no i18n)
`__stack_chk_fail` — stub: print and halt
`__morestack` — stub (split-stack support; not used)
`__register_atfork` — stub: return 0
`_ITM_*` (transactional memory: `_ITM_RU1 _ITM_RU8 _ITM_addUserCommitAction _ITM_deregisterTMCloneTable _ITM_memcpyRnWt _ITM_memcpyRtWn _ITM_registerTMCloneTable`) — stub; ITM only used if LLVM is built with TM passes enabled (default off)
`_dl_find_object` — stub (used by libgcc unwinder; we're no-exceptions)
`__gmon_start__` — weak stub for gprof hook

### F — Non-trivial own implementations

#### F.1 — startup + exit (foundations)
`__libc_start_main` — replace with our own `_start` that calls main() with argv/envp parsed from the cap-table-base IPC; CRT init runs `.init_array` (calls `__cxa_atexit` registrants); on return runs `.fini_array` and atexit chain.
`__cxa_atexit __cxa_finalize __cxa_thread_atexit_impl` — atexit registry, walked at exit
`__cxa_pure_virtual` — abort
`__cxa_guard_acquire __cxa_guard_release __cxa_guard_abort` — thread-safe local statics; one-byte-per-guard FSM with futex wait

#### F.2 — errno (TLS — required by basically every wrapper above)
`__errno_location` — returns `&__thread errno`. Implies static-TLS support across all our binaries.

#### F.3 — TLS infrastructure
`__tls_get_addr` — if any `.so` got into the link this matters; for fully static, `_start` initializes a static TLS block per EC and FS-base is set via Zag syscall.

#### F.4 — stdio (FILE struct + buffering + format)
`stdin stdout stderr` — global FILE*s wired to fd 0/1/2 (0/1 over fs_client; 2 over COM1 for now, retarget later)
`fopen fdopen fclose fflush fread fwrite fputc fputs getc putc ungetc setvbuf fileno fseeko64 ftello64 freopen` — implement around `FILE { fd: i32, buf: []u8, head, tail, flags }`
`getwc putwc ungetwc` — wide variants over UTF-8 transcoding
`sprintf snprintf vsnprintf __sprintf_chk __snprintf_chk __vsnprintf_chk __printf_chk __fprintf_chk vfprintf vprintf` — wire to `std.fmt.format`. C printf format spec → Zig formatter mapping is the only delicate part.
`__isoc23_scanf __isoc23_sscanf __isoc23_strtol __isoc23_strtoll __isoc23_strtoul __isoc23_strtoull` — scanf is non-trivial; strto* is tractable. (LLVM uses these in command-line parsing.)
`perror remove tmpfile tmpnam` — minor

#### F.5 — malloc front-end
`malloc free calloc realloc posix_memalign aligned_alloc malloc_usable_size mallinfo2` — wrap `std.heap.PageAllocator` with metadata header for `usable_size`. Real malloc (size class buckets) only if perf demands; first cut is straight page alloc + 16-byte align.

#### F.6 — locale (one global C/POSIX locale)
`setlocale newlocale __newlocale freelocale __freelocale duplocale __duplocale uselocale __uselocale nl_langinfo __nl_langinfo_l nl_langinfo_l` — single static `C` locale; setlocale(category, "C")|"POSIX" succeed, anything else fails.
`__strcoll_l __strxfrm_l __wcscoll_l __wcsxfrm_l __towlower_l __towupper_l __iswctype_l __wctype_l __strftime_l __wcsftime_l __strtod_l __strtof_l` — `_l` suffix variants ignore the locale arg, defer to non-`_l` impl.

#### F.7 — multibyte / wide
`btowc wctob mbrtowc mbsnrtowcs __mbsrtowcs_chk wcrtomb wcsnrtombs wcscmp wcslen wmemchr wmemcmp wmemcpy __wmemcpy_chk wmemmove wmemset __wmemset_chk` — UTF-8 ↔ UTF-32 conversion; `wchar_t` = u32. Most clang/LLVM hot paths don't touch these; std::filesystem might.

#### F.8 — math (libm)
`acos asin atan atan2 cos cosh erf exp floor fmod fmodf frexp frexpf frexpl log log10 log1p log2 log2f logb modf pow round sin sinh sqrt tan tanh` — almost all in `std.math`. `frexpl strtold` are 80-bit long-double; if LLVM's host build uses `long double = double` we can alias, otherwise need x87/extended-precision.
`feclearexcept fegetround fesetround fetestexcept` — fenv; small wrappers around x86 MXCSR.

#### F.9 — env / argv
`getenv secure_getenv environ __environ` — environ string array set from IPC at startup.

### Z — Skip (system-package-only deps; not in upstream static tarball)

`xmlAddChild xmlCopyNamespace xmlDocDumpFormatMemoryEnc xmlDocGetRootElement xmlDocSetRootElement xmlFree xmlFreeDoc xmlFreeNode xmlFreeNs xmlNewDoc xmlNewNs xmlNewProp xmlReadMemory xmlSetGenericErrorFunc xmlStrdup xmlUnlinkNode` — libxml2 (skip)
`el_end el_get el_gets el_init el_insertstr el_line el_push el_set history history_end history_init` — libedit/readline (skip)
`ffi_call ffi_prep_cif ffi_type_*` — libffi (skip; static build inlines compiler-rt-equivalents)
`adler32 adler32_combine compress2 compressBound crc32 deflate deflateEnd deflateInit2_ uncompress` — zlib (skip; bundled in static)
`ZSTD_*` — zstd (skip; bundled in static)
`iconv iconv_close iconv_open` — iconv (skip; bundled or stub)
`bindtextdomain bind_textdomain_codeset dgettext gettext` — gettext (stub-passthrough)

### Notes for the static-tarball re-run

Upstream tarball at `https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz` (~47 MB) downloading to `work/`. Once extracted, `nm -D --undefined-only` against the *fully static* binary will give the closed surface — no `.so` cluster math needed. If musl-static, expect ~150 syms (musl resolves most internally). If glibc-static, expect ~500 (glibc has more interface-level imports). The bucketing above won't change shape, it just shrinks list Z and confirms the rest.

## Strategy decision: single-threaded first (added 2026-05-06)

Zag has no userspace primitive to set FS_BASE — the only FS_BASE references in the kernel are inside VMX/SVM for guest save/restore on VM entry/exit. Three options:

- (i) Add a kernel syscall `set_tls(addr)` (≈10 lines of kernel work)
- (ii) Enable CR4.FSGSBASE and use `wrfsbase` from userspace
- (iii) **Cross-compile Zig+LLVM with `-fsingle-threaded`** — sidestep TLS entirely

We pick **(iii)** for the first cut. errno becomes a global var, pthread mutex/cond/rwlock become no-ops, pthread_key_create maps to a tiny static slot table, pthread_create stubs `EAGAIN`. This collapses three of the original 10 foundation steps. Threading is a follow-up — once the real compiler runs on Zag we can graduate to (i) or (ii). LLVM/Zig compile will be slower, fine for first proof.

## Foundation order (Phase 4c.2 sub-steps)

Pre-fan-out, post the single-threaded simplification:

1. **`libz/libc/` build scaffold** — Zig static library targeting `x86_64-zag-none` with `-fsingle-threaded`, output `libc.a`. The cross-compile in 4c.4 links against this `.a` plus the LLVM/clang object cluster.
2. **errno** as a global `c_int`. `__errno_location` returns `&errno`.
3. **fs_client wrappers** (open/close/read/write/lseek/stat/fstat/unlink) over the existing fs IPC. Patched stdlib's `os/zag.zig` already does most of this — we add C-ABI exports on top.
4. **mmap/munmap/mprotect** — already shaped in `os/zag.zig` via `zag_mmap_anon`/`zag_munmap`. Add C-ABI exports.
5. **`__cxa_atexit` table + `_start` running `.init_array`/`.fini_array`**.
6. **malloc front-end** — wrap `std.heap.PageAllocator`; the patched stdlib already wires PageAllocator over VMAR+page_frame.
7. **`FILE` struct + `fread`/`fwrite`/`fputc`/`fputs`** — minimal stdio.
8. **`stdout`/`stderr` globals + `fprintf`/`vfprintf`** — wire `std.fmt.format` to C format spec.
9. **pthread no-op layer** (single-threaded): mutex/cond/rwlock/once succeed without doing anything; pthread_create/join return `EAGAIN`; pthread_self returns 1; pthread_key/get/setspecific over a fixed-size static slot table.

Phase 4c.3 fans out the rest of the buckets (string, ctype, math, locale, wide, signals/setjmp, dl_*, env) to parallel agents.
