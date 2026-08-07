# POSIX ground truth — static-musl busybox trace

Segment 1 of the POSIX transition (`POSIX_TRANSITION_PLAN.md` §5.1): build the
exact target binary, trace it on Linux, and commit the evidence. The result is
the authoritative work queue for the syscall implementation effort.

**Read [`SYSCALL_UNION.md`](SYSCALL_UNION.md) — that is the deliverable.**
Everything else here is the evidence behind it and the means to reproduce it.

## Layout

```
SYSCALL_UNION.md                the work queue: union, counts, multiplexer
                                sub-commands, and the diff against §6
build/
  build.sh                      exact working recipe, runnable
  busybox-1.37.0.config         the resolved .config actually used
  zigcc-musl                    CC shim (see below)
harness/
  trace.sh                      the five canonical §5.1 shapes
  supp.sh                       two supplementary shapes
  analyze.py                    union + counts + multiplexers + §6 diff
  flags.py                      argument-level flag detail
raw/
  01-interactive/ .. 05-script/ per-shape raw strace output
  supplementary/                PATH search, direct applet exec
analysis/
  union.txt flags.txt flags_supplementary.txt   generated, checked in
```

Each `raw/<shape>/` holds `ARGV` (exact argv, one element per line), `stdin`
(what was fed to the shell), `console.log` (what the shell printed),
`summary.txt` (`strace -c` counts) and `t.<pid>` files — one per process, from
`strace -ff`.

## Reproducing

```sh
./build/build.sh /some/scratch/dir     # fetches, verifies sha256, configures, builds
./harness/trace.sh                     # five canonical shapes
./harness/supp.sh                      # supplementary shapes
python3 harness/analyze.py traces
python3 harness/flags.py   traces
```

The harnesses have the scratchpad path baked into `$S`; edit it or re-point it
before re-running elsewhere. Raw traces contain absolute scratchpad paths — that
is deliberate, they are verbatim evidence.

## Method, and why it is shaped this way

**The binary.** busybox 1.37.0, static, musl, x86-64, built with the pinned
zig 0.15.2 as a cross compiler. Configured per §5.1: `FEATURE_SH_STANDALONE=n`,
`FEATURE_EDITING=n`, `ASH_JOB_CONTROL=n`, applets `sh`/`echo`/`cat`/`ls`/`pwd`/
`true`/`false`. Started from `allnoconfig` and enabled up, rather than
`defconfig` and disabled down: with ~390 applets, defconfig against musl has a
large build-breakage surface that contributes nothing to the trace, since only
the applets actually invoked emit syscalls.

**Statically linked, verified three ways** — `file` reports `statically
linked`, there is no `PT_INTERP`, and `ldd` reports `not a dynamic executable`.
musl-linked confirmed positively: zero `glibc`/`GLIBC_2`/`GNU C Library`
strings, `.comment` shows zig's clang 20.1.2 + LLD, and a control binary from
the same shim contains `/lib/ld-musl-x86_64.so.1`. The ELF is type `EXEC`, i.e.
non-PIE — the simplest case for Stygia's loader.

**Everything runs under a pty.** `script(1)` allocates one. Without a tty ash
never takes the interactive path, and `TIOCGWINSZ` — the ioctl that *is*
`isatty()`, and the one §6 correctly calls critical — never fires. A
console-attached shell is also the actual Stygia target, so this is the
faithful configuration rather than a trick to inflate coverage.

**Minimal environment.** `env -i` with only `PATH`, `HOME`, `PWD`, `TERM`,
`SHELL` — as close to a fresh PID 1 as the host allows.

**`FEATURE_SH_STANDALONE=n` is doing real work here.** With it off, ash resolves
external commands by searching `PATH` and `execve`ing a separate process, which
is what produces the `stat`→`ENOENT` probing and the `fork`/`wait4`/`execve`
traffic. With it on, busybox would short-circuit to an internal applet call and
none of that would appear.

## Two traps worth knowing about

Both of these silently produced *wrong* ground truth before being caught, and
both would do so again.

1. **Shell metacharacters must not reach the outer shell.** Interpolating a
   command into `script -c "..."` lets the *outer* shell perform the pipeline,
   redirection and glob — busybox then never issues `pipe`, `dup2` or
   `getdents64`, and the trace looks plausible while being meaningless. The
   harness materialises each shape into its own `run.sh` with `printf %q`
   quoting to prevent this.

2. **A `PATH` containing `/usr/bin` traces GNU coreutils, not busybox.** ash
   finds the real dynamic glibc `ls`/`cat` first. That contributed `rseq`,
   `statx`, `set_robust_list`, `prctl`, `getrandom`, `mprotect`, `newfstatat`,
   `openat` and `fadvise64` — all glibc, none busybox. The supplementary PATH
   shape now probes nonexistent directories instead.

## The build shim

busybox's `scripts/trylink` (line 99, `INFO_OPTS()`) unconditionally appends
three diagnostic-only linker flags that zig's LLD rejects:
`-Wl,--warn-common`, `-Wl,-Map,<exe>.map`, `-Wl,--verbose`. Every object
compiles fine and only the final link fails, with
`error: unsupported linker arg: --warn-common`.

`build/zigcc-musl` filters those three out. None affects the produced binary,
and trylink never reads the `.map` it asks for. This keeps the busybox source
tree unpatched, so the recipe is "unmodified upstream 1.37.0 + this shim".

## Scope of the claim

These are the syscalls busybox issues **for these seven invocations**. It is a
lower bound, not a closed set — §5.4/§5.5's runtime NYI and unknown-syscall
logging exist to extend it continuously from Stygia's own kernel, which is the
part that will catch whatever these shapes did not reach. Notably untouched
here: anything that writes to the filesystem beyond one `O_CREAT`, any
multi-threaded path (hence no `futex`), and all of §6's Tier 2.5.
