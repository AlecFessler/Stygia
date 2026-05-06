#!/bin/bash
# Cross-compile demonstration: clang-20 + zig linker + our libc.a + Zag
# runtime → working Zag-target ELF.
#
# Same pattern will scale to LLVM/clang/lld C++ source: each .cpp
# compiled with clang-20 -target x86_64-unknown-elf -nostdlib, then
# archived into libLLVM.a / libclang.a / liblld.a using llvm-ar
# (after archive-format compatibility is sorted), then linked with
# our libc.a + libz/libc/runtime into the cross-compiled zig binary.
set -euo pipefail

ZAG_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PATCHED_ZIG="$HOME/.local/zag-toolchains/zig-0.15.2-src/zig-out/bin/zig"
PATCHED_LIB="$HOME/.local/zag-toolchains/zig-0.15.2-src/lib"
LIBC_A="$ZAG_ROOT/libz/libc/zig-out/lib/libc.a"
CLANG="/usr/lib/llvm20/bin/clang"

# 1. Ensure libc.a is built
[ -f "$LIBC_A" ] || (cd "$ZAG_ROOT/libz/libc" && "$PATCHED_ZIG" build --zig-lib-dir "$PATCHED_LIB")

# 2. Build the C demo (compiled by clang-20 for x86_64-unknown-elf —
#    ANY freestanding C/C++ source compiles this way; this is the
#    pattern we'll use for LLVM source)
cat > /tmp/c_smoke.c <<'EOF'
extern int puts(const char *s);
extern void exit(int);

void _start(unsigned long cap_table_base) {
    (void)cap_table_base;
    puts("[c_smoke] hello from clang-20-compiled C, libc.a-linked, Zag runtime-spawned");
    exit(0);
}
EOF
"$CLANG" -target x86_64-unknown-elf -nostdlib -fPIC -fPIE -O2 \
    -c /tmp/c_smoke.c -o /tmp/c_smoke.o

# 3. Link with the patched zig + our libc.a + the runtime stub.
#    zig as the linker handles its own archive format correctly (ld.lld
#    chokes on Zig's archive layout).
cd /tmp && "$PATCHED_ZIG" build-exe \
    --zig-lib-dir "$PATCHED_LIB" \
    -target x86_64-zag-none -fno-llvm -fno-lld \
    -fsingle-threaded -fstrip -OReleaseSmall -fPIC -fPIE -fomit-frame-pointer \
    -mcpu baseline \
    --name c_smoke \
    /tmp/c_smoke.o \
    "$ZAG_ROOT/desktopOS/libc_smoke/runtime.zig" \
    "$LIBC_A"

echo "Built: /tmp/c_smoke ($(stat -c%s /tmp/c_smoke) bytes)"
file /tmp/c_smoke
