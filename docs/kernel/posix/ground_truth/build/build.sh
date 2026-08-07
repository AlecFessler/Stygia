#!/bin/bash
# Exact, working recipe for the static-musl busybox used as Stygia's POSIX
# ground-truth target (POSIX_TRANSITION_PLAN.md §5.1).
#
# Verified 2026-08-07 on Arch, producing a 193504-byte static non-PIE ELF64.
#
#   busybox     1.37.0   sha256 3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4
#   toolchain   zig 0.15.2 (clang 20.1.2 + LLD 20.1.2), target x86_64-linux-musl
#
# Usage:  ./build.sh <workdir>
set -euo pipefail

WORK=${1:?usage: build.sh <workdir>}
HERE="$(cd "$(dirname "$0")" && pwd)"
VER=1.37.0
SHA=3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4

# The pinned Zig. /usr/bin/zig is 0.16 and breaks the build.
export PATH=/home/alec/.local/opt/zig-x86_64-linux-0.15.2:$PATH
zig version | grep -qx '0.15.2' || { echo "need zig 0.15.2, got $(zig version)"; exit 1; }

mkdir -p "$WORK"
cd "$WORK"

[ -f "busybox-$VER.tar.bz2" ] || curl -fsSO "https://busybox.net/downloads/busybox-$VER.tar.bz2"
echo "$SHA  busybox-$VER.tar.bz2" | sha256sum -c -
rm -rf "busybox-$VER"
tar xf "busybox-$VER.tar.bz2"
cd "busybox-$VER"

# Config: allnoconfig + exactly the applets §5.1 names, minus the three features
# §5.1 requires off. See ../busybox-1.37.0.config for the resolved result.
cp "$HERE/busybox-$VER.config" .config
yes '' | make oldconfig >/dev/null 2>&1 || true

# CC shim: drops the three diagnostic-only linker flags busybox's scripts/trylink
# appends unconditionally (--warn-common, -Map, --verbose) which zig's LLD rejects.
# Without it the compile succeeds and only the FINAL LINK fails.
make -j"$(nproc)" CC="$HERE/zigcc-musl" HOSTCC=gcc SKIP_STRIP=y

# Verify: must be static, must not be dynamic, must not be glibc.
file busybox | grep -q 'statically linked'
! readelf -l busybox | grep -qi interp
[ "$(strings -a busybox | grep -icE 'glibc|GNU C Library|GLIBC_2')" = 0 ]
echo "OK: $(file -b busybox)"
