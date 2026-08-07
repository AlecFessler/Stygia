# busybox static-musl syscall ground truth — authoritative work queue

Produced per `POSIX_TRANSITION_PLAN.md` §5.1. **This list supersedes §6 wherever
they disagree.** Everything here is observed, not predicted; every count is
reproducible from `raw/` with `harness/analyze.py`.

| | |
| --- | --- |
| Target | busybox 1.37.0, static, musl, x86-64 |
| sha256 (source) | `3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4` |
| Toolchain | zig 0.15.2 → clang 20.1.2 + LLD 20.1.2, `-target x86_64-linux-musl` |
| Binary | 193504 bytes, `ELF 64-bit LSB executable, statically linked, stripped` |
| ELF type | `EXEC` — **non-PIE**, no `PT_INTERP`, no dynamic segment |
| Tracer | strace 7.0, `-ff -v -s 256 -qq` |
| Traced | 5 canonical shapes (§5.1) + 2 supplementary, all under a pty |
| Date | 2026-08-07 |

## The union — 29 syscalls, 345 calls (canonical five shapes)

`shapes` = how many of the five invocation shapes issued it. A syscall present
in 5/5 is on the unconditional startup/teardown path; a syscall in 1/5 is
feature-specific and can be sequenced later.

| n | syscall | shapes | notes for the implementer |
| ---: | --- | :---: | --- |
| 38 | `rt_sigaction` | 5/5 | SIGINT/QUIT/TERM/HUP/CHLD only. `SA_RESTORER` always set |
| 36 | `mmap` | 5/5 | only 2 arg shapes — see below |
| 29 | `rt_sigprocmask` | 5/5 | `SIG_SETMASK` 16, `SIG_BLOCK` 8, `SIG_UNBLOCK` 5 |
| 22 | `stat` | 5/5 | **legacy #4**, not `newfstatat`. Also the PATH-search probe |
| 18 | `brk` | 5/5 | `brk(NULL)` ×9 then one extension per process — see §Corrections |
| 18 | `writev` | 4/5 | musl stdio's write path. **`readv` never fires** |
| 15 | `set_tid_address` | 5/5 | called twice per forked child (fork resets, exec re-inits) |
| 14 | `ioctl` | 4/5 | `TIOCGWINSZ` **only** — see §Multiplexers |
| 14 | `read` | 4/5 | plain `read`, never `readv` |
| 13 | `close` | 5/5 | |
| 12 | `lstat` | 2/5 | **legacy #6**. `ls` uses lstat, not stat |
| 11 | `arch_prctl` | 5/5 | `ARCH_SET_FS` only. TLS setup, first call after execve |
| 11 | `execve` | 5/5 | incl. strace's own initial exec |
| 11 | `write` | 4/5 | |
| 10 | `fcntl` | 5/5 | `F_SETFD` 7, `F_DUPFD_CLOEXEC` 3 |
| 9 | `exit_group` | 5/5 | status 0 in every observed case |
| 7 | `munmap` | 3/5 | |
| 7 | `wait4` | 3/5 | options `0` ×4, `WNOHANG` ×3. Returns `ECHILD` ×3 |
| 6 | `getdents64` | 3/5 | buffer always 2048 |
| 6 | `open` | 5/5 | **legacy #2**, not `openat` — see §Flags |
| 5 | `dup2` | 2/5 | pipeline + redirection. `dup`/`dup3` never fire |
| 5 | `geteuid` | 5/5 | `getuid`/`getgid`/`getegid` never fire |
| 5 | `getpid` | 5/5 | |
| 5 | `getppid` | 5/5 | |
| 5 | `uname` | 5/5 | ash reads it at startup unconditionally |
| 4 | `chdir` | 2/5 | `fchdir` never fires |
| 4 | `fork` | 3/5 | **`fork` #57, never `clone` #56** — see §Corrections |
| 4 | `rt_sigreturn` | 3/5 | consequence of SIGCHLD delivery |
| 1 | `pipe` | 1/5 | legacy `pipe`, not `pipe2` |

### Supplementary — 3 more syscalls, 32 total

`raw/supplementary/` covers two blind spots in the five shapes. Both are real
and Stygia will hit them; they are listed separately because they are outside
the §5.1 canonical set, not because they are hypothetical.

| n | syscall | source | notes |
| ---: | --- | --- | --- |
| 2 | `lseek` | `ls -l` | `SEEK_CUR` with a **negative** offset (rewind of `/etc/passwd`) |
| 1 | `getcwd` | `pwd` **applet** | buffer 192, returns length incl. NUL |
| 1 | `fstat` | `ls -l` | on the `/etc/passwd` fd |

## Multiplexer sub-commands

This is the actionable part. Bare `ioctl` is not a work item; `ioctl(TIOCGWINSZ)`
is.

```
ioctl        14  TIOCGWINSZ            fd 1 (×10), fd 0 (×4)   -> 0 on tty, ENOTTY on file
fcntl         7  F_SETFD    FD_CLOEXEC on fd 3 (×4), fd 10 (×3)
              3  F_DUPFD_CLOEXEC  arg 10, on fds 3, 1, 0
arch_prctl   11  ARCH_SET_FS
prctl         -  NOT OBSERVED
futex         -  NOT OBSERVED   (busybox ash is single-threaded; no contention)
clone         -  NOT OBSERVED   (musl uses SYS_fork on x86-64)
```

Three consequences worth stating plainly:

1. **`TIOCGWINSZ` is the entire tty surface.** §6 predicted `TCGETS`,
   `TCSETS`/`TCSETSW`, `TIOCGPGRP`/`TIOCSPGRP` would also be needed. With the
   §5.1 config (`FEATURE_EDITING=n`, job control off) **none of them fire.**
   §5.1's config choice is what removes them, so the config is load-bearing:
   turning editing or job control back on re-introduces the whole termios path.
2. **`ENOTTY` is required, not optional.** `ioctl(TIOCGWINSZ)` must return `0`
   with a filled `winsize` on the console object and `-ENOTTY` on a regular
   file. That is `isatty()`, and it is how ash decides it is interactive.
   Two `ENOTTY` returns were observed.
3. **`F_DUPFD_CLOEXEC` targets fd 10.** ash parks the shell's own copies of
   redirected fds at ≥10. A `F_DUPFD_CLOEXEC` that ignores the `arg` floor
   silently corrupts redirection.

## Flag/argument detail

```
open()   O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_DIRECTORY   3   (opendir)
         O_RDONLY|O_LARGEFILE|O_CLOEXEC               1   (script.sh)
         O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE, 0666   1   (> redirection)
         O_RDONLY|O_LARGEFILE                         1   (< redirection)

mmap()   PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS         27
         PROT_NONE,            MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS 9

wait4()  options 0 (×4), WNOHANG (×3)
dup2()   3->0, 3->1, 10->1, 4->1
getdents64() buffer 2048
```

`O_LARGEFILE` is set on **every** open — musl adds it unconditionally on 32/64
mixed ABIs. Accepting-and-ignoring it is correct here; rejecting it breaks
everything. Only two `mmap` argument shapes exist, and `mprotect` never fires,
so the initial mm can be extremely simple.

## Errnos the binary actually depends on

| errno | from | why it matters |
| --- | --- | --- |
| `ENOTTY` | `ioctl(TIOCGWINSZ)` on a file | ash's interactive/non-interactive decision |
| `ECHILD` | `wait4` | ash's "no more children" loop terminator |
| `ENOENT` | `stat` during PATH search | 6× in supplementary; see below |

**PATH search is `stat`, not `open`/`access`.** With a realistic multi-entry
PATH, ash `stat()`s `<dir>/<cmd>` for every entry until one succeeds. Each miss
must return `-ENOENT`. `access`/`faccessat` never fire.

## Signals

`SIGCHLD` was the only signal *delivered* (4×), each followed by
`rt_sigreturn`. Dispositions installed: SIGCHLD→handler, SIGINT→handler,
SIGQUIT→`SIG_IGN`, SIGTERM→`SIG_IGN`, SIGHUP→`SIG_DFL`. So a working
signal-frame build/consume path for exactly one asynchronous signal (`SIGCHLD`)
is enough to run the shell.

## Diff against §6

### What §6 missed

**At the syscall-name level: nothing.** All 29 traced syscalls appear somewhere
in §6's tiers. §6's *naming* is sound. Its *semantics* are wrong in four places,
and these are the corrections that matter:

1. **`fork`, not `clone`.** §6 says "`clone` (alias `fork`)", implying clone is
   the primary. Empirically musl on x86-64 issues **`SYS_fork` (57) exclusively**;
   `clone` (56) never fires in any shape. Implementing only `clone` and aliasing
   fork to it is backwards — `fork` is the one the binary demands.

2. **`brk` is on the hot startup path, and a fake-success `brk` is fatal.**
   §6 says "`brk` (stub-fail; mallocng is mmap-only)". Two errors:
   - The brk user is `__simple_malloc` in musl `src/malloc/lite_malloc.c`, not
     mallocng. It fires 18× across 5/5 shapes.
   - **Stub-failing is nonetheless safe** — `lite_malloc.c:67-89` guards on
     `__syscall(SYS_brk, brk+req)==brk+req` and falls through to `__mmap` when
     that does not hold. So §6's advice happens to be correct for the wrong
     reason.
   - The trap: a `brk` that returns *success* without actually extending the
     break hands musl a heap that does not exist. That is exactly the §5.3
     `Ignored` bucket. **`brk` must either work or fail; it must never lie.**

3. **`getcwd` is not reachable through the shell.** §6 lists it Tier 2. ash
   resolves `pwd` as a **builtin** from its own `PWD` tracking — `getcwd` fires
   only when the standalone `pwd` *applet* is exec'd. Same for `true`/`false`,
   which are builtins and whose applets never run. Sequencing `getcwd` early
   because "pwd needs it" is wasted work.

4. **`readv` never fires.** §6 flags `readv`/`writev` together with "musl stdio
   uses these, not plain read/write — missing them breaks printf mysteriously".
   Half right: `writev` fires 18×, `readv` **0×**; reads go through plain `read`.

Also absent from §6 but required by `ls -l`: **`/etc/passwd`, `/etc/group` and
`/etc/localtime` must exist** (or `ls -l` degrades). §7 mentions `/dev/null`
but not these.

### What §6 predicted that never fired

61 of §6's 90 kernel+routed syscalls never fired. Not all are wrong — many are
genuinely needed by *later* targets — but none of them belongs in the first
milestone.

- **Tier 0** (4/11 unused): `mprotect`, `madvise`, `mremap`, `exit`
- **Tier 1** (21/30 unused): `clone`, `kill`, `tkill`, `tgkill`, `rt_sigsuspend`,
  `gettid`, `setpgid`, `getpgid`, `getpgrp`, `setsid`, `getuid`, `getgid`,
  `getegid`, `futex`, `clock_gettime`, `nanosleep`, `sched_yield`, `umask`,
  `prlimit64`, `getrlimit`, `times`
- **Tier 2** (14/27 unused): `readv`, `openat`, `lseek`, `dup`, `dup3`, `pipe2`,
  `newfstatat`, `fstat`, `getcwd`, `fchdir`, `access`, `faccessat`, `poll`,
  `ppoll`
- **Tier 2.5** (22/22 unused): the entire tier — `unlink*`, `mkdir*`, `rename*`,
  `link*`, `symlink*`, `readlink*`, `chmod*`, `chown*`, `utimensat`,
  `ftruncate`, `getrandom`

Four of these are worth calling out because §6 ties them to a specific claim
that the trace refutes:

- **`futex`** — §6 Tier 1 "(WAIT/WAKE)". busybox ash is single-threaded and
  never contends. Zero calls. Not milestone-1 work.
- **`clock_gettime`/`nanosleep`/`times`** — no time source is needed to run the
  shell at all.
- **`umask`** — never queried or set; the `0666` mode on the `>` redirection is
  passed literally.
- **`getrandom`** — never fires. musl takes the stack canary from `AT_RANDOM`
  in auxv, exactly as §7.1 predicts, so §7.1 is confirmed and `getrandom` is
  not on the critical path.

### §6's "safe to -ENOSYS" list

Holds completely. None of `statx`, `sendfile`, `select`/`pselect6`,
`set_robust_list`, `rseq`, `sysinfo`, `epoll_*`, the socket family, or
`sigaltstack` fired in any shape.

> Caveat, because it nearly poisoned this result: an early supplementary run
> used a PATH containing `/usr/bin`, so ash found **GNU coreutils** `ls`/`cat`
> before busybox. Those are dynamic glibc binaries and they contributed
> `rseq`, `statx`, `set_robust_list`, `prctl`, `getrandom`, `mprotect`,
> `newfstatat`, `openat` and `fadvise64` to the trace. All of that is glibc
> behavior, **not** busybox, and it is excluded. If a future trace shows those
> syscalls, check for exactly this contamination first.

## Suggested implementation order

Derived from shape-coverage, not from §6's tiering. Everything in group 1 is on
the unconditional path of every process; nothing in group 4 is needed to reach
an interactive prompt.

1. **Process bring-up (5/5 shapes):** `execve`, `arch_prctl(ARCH_SET_FS)`,
   `set_tid_address`, `brk`, `mmap`(2 shapes), `munmap`, `exit_group`,
   `uname`, `getpid`, `getppid`, `geteuid`
2. **Console + stdio:** `writev`, `write`, `read`, `ioctl(TIOCGWINSZ)` incl.
   `ENOTTY`, `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `close`
3. **Filesystem for the shell:** `stat`(+`ENOENT`), `lstat`, `open`, `chdir`,
   `getdents64`, `fcntl`(`F_SETFD`, `F_DUPFD_CLOEXEC`)
4. **Job machinery:** `fork`, `wait4`(+`ECHILD`), `pipe`, `dup2`

Group 4 last: shapes 03 and 04 (redirection, glob) run to completion without
`fork` at all.
