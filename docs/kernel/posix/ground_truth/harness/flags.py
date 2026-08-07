#!/usr/bin/env python3
"""Argument-level detail for the traced syscalls: flag/mode combinations that an
implementer must actually support, beyond the multiplexer sub-commands."""
import os, re, sys
from collections import Counter

roots = sys.argv[1:]
lines = []
for root in roots:
    for d, _, fs in os.walk(root):
        for f in sorted(fs):
            if f.startswith('t.'):
                lines += open(os.path.join(d, f), errors='replace').read().splitlines()

def grab(pat, label):
    c = Counter()
    for ln in lines:
        m = re.match(pat, ln)
        if m:
            c[m.group(1)] += 1
    print(f'\n-- {label}')
    if not c:
        print('   (none)')
    for k, v in sorted(c.items(), key=lambda kv: -kv[1]):
        print(f'   {v:>4}  {k}')

print('=' * 78); print('ARGUMENT-LEVEL DETAIL'); print('=' * 78)
grab(r'open\("[^"]*",\s*([^,)]+)', 'open() flags')
grab(r'openat\([^,]+,\s*"[^"]*",\s*([^,)]+)', 'openat() flags')
grab(r'mmap\([^,]+,\s*[^,]+,\s*([^,]+,\s*[^,]+)', 'mmap() prot, flags')
grab(r'mprotect\([^,]+,\s*[^,]+,\s*([^,)]+)', 'mprotect() prot')
grab(r'lseek\([^,]+,\s*[^,]+,\s*([^,)]+)', 'lseek() whence')
grab(r'wait4\([^,]+,\s*[^,]+,\s*([^,]+)', 'wait4() options')
grab(r'rt_sigprocmask\(([A-Z_]+)', 'rt_sigprocmask() how')
grab(r'rt_sigaction\((SIG[A-Z0-9]+|RT[A-Z_0-9]*)', 'rt_sigaction() signals')
grab(r'ioctl\((\d+),\s*[A-Z]', 'ioctl() fd')
grab(r'ioctl\(\d+,\s*([A-Z_0-9]+)', 'ioctl() request')
grab(r'fcntl\(\d+,\s*([A-Z_0-9]+)', 'fcntl() cmd')
grab(r'fcntl\((\d+,\s*[A-Z_0-9]+,\s*[^)]*)\)', 'fcntl() full arg triple')
grab(r'dup2\(([^)]+)\)', 'dup2() oldfd,newfd')
grab(r'(pipe|pipe2)\(', 'pipe variant')
grab(r'(fork|clone|clone3|vfork)\(', 'process-creation variant')
grab(r'(stat|lstat|fstat|newfstatat|statx)\(', 'stat family variant')
grab(r'(read|readv|pread64|write|writev|pwrite64)\(', 'read/write family variant')
grab(r'getdents64\(.*,\s*([0-9]+)\)', 'getdents64() bufsize')
grab(r'brk\(([^)]*)\)', 'brk() arg')
grab(r'exit_group\(([^)]*)\)', 'exit_group() status')
grab(r'set_tid_address\(([^)]*)\)', 'set_tid_address() arg')
grab(r'arch_prctl\(([A-Z_0-9]+)', 'arch_prctl() code')
grab(r'(uname)\(', 'uname')
grab(r'(geteuid|getuid|getegid|getgid)\(', 'cred variant')

print('\n' + '=' * 78); print('SIGNAL DISPOSITIONS INSTALLED (sa_handler kind)'); print('=' * 78)
c = Counter()
for ln in lines:
    m = re.match(r'rt_sigaction\((SIG[A-Z0-9]+|RT[A-Z_0-9]*),\s*\{sa_handler=([^,]+)', ln)
    if m:
        kind = m.group(2)
        kind = kind if kind.startswith('SIG_') else 'handler'
        c[(m.group(1), kind)] += 1
for (s, k), v in sorted(c.items()):
    print(f'   {v:>4}  {s:<10} -> {k}')
