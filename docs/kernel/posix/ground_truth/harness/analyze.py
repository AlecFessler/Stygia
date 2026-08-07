#!/usr/bin/env python3
"""Analyze strace output for the Stygia POSIX segment-1 ground truth.

Emits: per-shape syscall counts, the deduplicated union with counts, the
multiplexer sub-command inventory, and a diff against POSIX_TRANSITION_PLAN.md
section 6's predicted inventory.
"""
import os
import re
import sys
from collections import Counter, defaultdict

TRACES = sys.argv[1]
SHAPES = sorted(d for d in os.listdir(TRACES) if os.path.isdir(os.path.join(TRACES, d)))

CALL_RE = re.compile(r'^(?:\[pid\s+\d+\]\s*)?([a-z_][a-z0-9_]*)\((.*)$', re.I)
RESUMED_RE = re.compile(r'<\.\.\.\s+([a-z_0-9]+)\s+resumed>')
SIG_RE = re.compile(r'^---\s+(SIG\w+)')


def split_args(s):
    """Split a strace argument list at top-level commas."""
    out, depth, i, start, instr, esc = [], 0, 0, 0, False, False
    for i, c in enumerate(s):
        if esc:
            esc = False
            continue
        if c == '\\':
            esc = True
            continue
        if instr:
            if c == '"':
                instr = False
            continue
        if c == '"':
            instr = True
        elif c in '([{':
            depth += 1
        elif c in ')]}':
            if depth == 0:      # closing paren of the call itself
                out.append(s[start:i])
                return out, s[i + 1:]
            depth -= 1
        elif c == ',' and depth == 0:
            out.append(s[start:i])
            start = i + 1
    out.append(s[start:])
    return out, ''


per_shape = defaultdict(Counter)
union = Counter()
signals = Counter()
# multiplexer name -> Counter of sub-command
mux = defaultdict(Counter)
mux_shapes = defaultdict(lambda: defaultdict(set))
errnos = defaultdict(Counter)

MUX_ARGIDX = {
    'ioctl': 1, 'fcntl': 1, 'fcntl64': 1, 'prctl': 0,
    'arch_prctl': 0, 'futex': 1,
}

for shape in SHAPES:
    d = os.path.join(TRACES, shape)
    for fn in sorted(os.listdir(d)):
        if not fn.startswith('t.'):
            continue
        for line in open(os.path.join(d, fn), errors='replace'):
            line = line.rstrip('\n')
            m = SIG_RE.match(line)
            if m:
                signals[m.group(1)] += 1
                continue
            r = RESUMED_RE.search(line)
            if r:
                # resumed half: already counted at <unfinished>
                continue
            m = CALL_RE.match(line)
            if not m:
                continue
            name, rest = m.group(1), m.group(2)
            if name in ('exited', 'killed'):
                continue
            per_shape[shape][name] += 1
            union[name] += 1
            args, tail = split_args(rest)
            args = [a.strip() for a in args]
            # errno on failure
            em = re.search(r'=\s*-?\d+\s+(E[A-Z0-9]+)', tail)
            if em:
                errnos[name][em.group(1)] += 1
            if name in MUX_ARGIDX:
                idx = MUX_ARGIDX[name]
                if len(args) > idx:
                    sub = args[idx]
                    if name == 'clone':
                        pass
                    mux[name][sub] += 1
                    mux_shapes[name][sub].add(shape)
            if name in ('clone', 'clone3'):
                fm = re.search(r'flags=([A-Z_|0-9x]+)', rest)
                if fm:
                    mux['clone'][fm.group(1)] += 1
                    mux_shapes['clone'][fm.group(1)].add(shape)

W = 78
def hdr(t):
    print('\n' + '=' * W + '\n' + t + '\n' + '=' * W)

hdr('PER-SHAPE SYSCALL COUNTS')
allnames = sorted(union)
colw = max(len(n) for n in allnames) + 1
print(' ' * colw + ''.join(f'{s.split("-")[0]:>7}' for s in SHAPES) + f'{"UNION":>8}')
for n in allnames:
    row = ''.join(f'{per_shape[s][n] or "":>7}' for s in SHAPES)
    print(f'{n:<{colw}}{row}{union[n]:>8}')

hdr(f'DEDUPLICATED UNION  ({len(union)} distinct syscalls, {sum(union.values())} calls)')
for n, c in sorted(union.items(), key=lambda kv: (-kv[1], kv[0])):
    shapes_hit = sum(1 for s in SHAPES if per_shape[s][n])
    print(f'{c:>6}  {n:<20} (in {shapes_hit}/{len(SHAPES)} shapes)')

hdr('MULTIPLEXER SUB-COMMANDS')
for mname in ('ioctl', 'fcntl', 'prctl', 'arch_prctl', 'futex', 'clone'):
    if mname not in mux:
        print(f'\n-- {mname}: NOT OBSERVED')
        continue
    print(f'\n-- {mname}')
    for sub, c in sorted(mux[mname].items(), key=lambda kv: -kv[1]):
        sh = ','.join(sorted(x.split('-')[0] for x in mux_shapes[mname][sub]))
        print(f'   {c:>4}  {sub:<44} [{sh}]')

hdr('OBSERVED ERRNOS (failure paths the binary depends on)')
for n in sorted(errnos):
    for e, c in sorted(errnos[n].items(), key=lambda kv: -kv[1]):
        print(f'   {c:>4}  {n}() -> {e}')

hdr('SIGNALS DELIVERED')
for s, c in sorted(signals.items(), key=lambda kv: -kv[1]):
    print(f'   {c:>4}  {s}')

# ----------------------------------------------------------------- section 6
S6 = {
 'Tier0': """arch_prctl set_tid_address mmap munmap mprotect madvise brk mremap
            exit_group exit rt_sigprocmask""".split(),
 'Tier1': """clone fork execve wait4 kill tkill tgkill rt_sigaction rt_sigreturn
            rt_sigsuspend getpid getppid gettid setpgid getpgid getpgrp setsid
            getuid geteuid getgid getegid futex clock_gettime nanosleep
            sched_yield umask uname prlimit64 getrlimit times""".split(),
 'Tier2': """read write readv writev open openat close lseek fcntl dup dup2 dup3
            pipe pipe2 ioctl newfstatat stat lstat fstat getdents64 getcwd
            chdir fchdir access faccessat poll ppoll""".split(),
 'Tier2.5': """unlink unlinkat mkdir mkdirat rename renameat link linkat symlink
            symlinkat readlink readlinkat chmod fchmod fchmodat chown fchown
            lchown fchownat utimensat ftruncate getrandom""".split(),
 'ENOSYS-ok': """statx sendfile select pselect6 set_robust_list rseq sysinfo
            epoll_create epoll_create1 epoll_ctl epoll_wait epoll_pwait socket
            socketpair bind listen accept connect sendto recvfrom
            sigaltstack""".split(),
}
predicted = {n: tier for tier, names in S6.items() for n in names}

hdr('DIFF vs PLAN SECTION 6')
missed = sorted(n for n in union if n not in predicted)
print(f'\n-- SECTION 6 MISSED IT: traced but absent from the section 6 prior '
      f'({len(missed)})')
for n in missed:
    print(f'   {union[n]:>4}  {n}')

print('\n-- SECTION 6 PREDICTED, NEVER FIRED')
for tier in ('Tier0', 'Tier1', 'Tier2', 'Tier2.5'):
    nf = [n for n in S6[tier] if n not in union]
    print(f'   [{tier}] ({len(nf)}/{len(S6[tier])} unused)')
    for n in nf:
        print(f'        {n}')

fired_enosys_ok = [n for n in S6['ENOSYS-ok'] if n in union]
print('\n-- SECTION 6 SAID "SAFE TO -ENOSYS" BUT IT FIRED ANYWAY')
if fired_enosys_ok:
    for n in fired_enosys_ok:
        print(f'   {union[n]:>4}  {n}   <-- CANNOT SAFELY ENOSYS')
else:
    print('   (none -- the ENOSYS-safe list holds for these five shapes)')

hdr('SUMMARY')
hit = [n for n in union if n in predicted]
print(f'distinct syscalls traced      : {len(union)}')
print(f'  covered by section 6 prior  : {len(hit)}')
print(f'  missing from section 6      : {len(missed)}')
allpred = [n for t in ('Tier0','Tier1','Tier2','Tier2.5') for n in S6[t]]
print(f'section 6 kernel+routed prior : {len(allpred)}')
print(f'  never fired in these shapes : {len([n for n in allpred if n not in union])}')
