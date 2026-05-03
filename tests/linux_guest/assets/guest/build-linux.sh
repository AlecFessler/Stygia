#!/usr/bin/env bash
# Build a minimal arm64 Linux kernel Image for linux_guest guest boot.
#
# Output: $OUT_DIR/linux-arm64-Image
#
# Requires: aarch64-linux-gnu-gcc, make, bison, flex, libssl-dev, bc, curl, tar.
# See README.md in this directory.

set -euo pipefail

LINUX_VERSION="${LINUX_VERSION:-6.6.74}"
LINUX_MAJOR="v6.x"
LINUX_TARBALL="linux-${LINUX_VERSION}.tar.xz"
LINUX_URL="https://cdn.kernel.org/pub/linux/kernel/${LINUX_MAJOR}/${LINUX_TARBALL}"
# sha256 of linux-6.6.74.tar.xz (kernel.org). Verify at
# https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc before bumping.
LINUX_SHA256="${LINUX_SHA256:-0000000000000000000000000000000000000000000000000000000000000000}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-${SCRIPT_DIR}/out}"
SRC_DIR="${SRC_DIR:-${SCRIPT_DIR}/src}"
DEFCONFIG_FRAG="${SCRIPT_DIR}/linux.defconfig"

export ARCH=arm64
export CROSS_COMPILE="${CROSS_COMPILE:-aarch64-linux-gnu-}"

mkdir -p "${OUT_DIR}" "${SRC_DIR}"
cd "${SRC_DIR}"

if [ ! -f "${LINUX_TARBALL}" ]; then
    echo "[linux] fetching ${LINUX_URL}"
    curl -fLO "${LINUX_URL}"
fi

if [ "${LINUX_SHA256}" != "0000000000000000000000000000000000000000000000000000000000000000" ]; then
    echo "${LINUX_SHA256}  ${LINUX_TARBALL}" | sha256sum -c -
else
    echo "[linux] WARNING: LINUX_SHA256 unset; skipping checksum verification" >&2
fi

if [ ! -d "linux-${LINUX_VERSION}" ]; then
    echo "[linux] extracting"
    tar -xf "${LINUX_TARBALL}"
fi

cd "linux-${LINUX_VERSION}"

# Start from tinyconfig and layer the fragment on top. tinyconfig is the
# smallest functional kernel; we only enable what PL011 + initramfs + virt
# boot needs.
make tinyconfig
./scripts/kconfig/merge_config.sh -m .config "${DEFCONFIG_FRAG}"
make olddefconfig

make -j"$(nproc)" Image

cp arch/arm64/boot/Image "${OUT_DIR}/linux-arm64-Image"
echo "[linux] wrote ${OUT_DIR}/linux-arm64-Image"
