# linux_guest aarch64 guest artifacts (M8.1)

Reproducible build recipe for the minimal arm64 Linux + busybox guest that
linux_guest boots under its VM layer on aarch64.

Outputs (written to `./out/`):

- `linux-arm64-Image` — raw arm64 Linux kernel Image (NOT zImage/gzipped).
- `rootfs.cpio.gz` — gzip-compressed newc cpio initramfs whose `/init`
  prints `hello from guest` and then halts / idles.

Pinned versions:

- Linux `6.6.74` (6.6 LTS). Override with `LINUX_VERSION=...`.
- Busybox `1.36.1`. Override with `BUSYBOX_VERSION=...`.

## Prerequisites

An aarch64 cross toolchain and the usual kernel build deps. On Arch:

    sudo pacman -S --needed aarch64-linux-gnu-gcc make bison flex bc cpio gzip tar curl openssl

On Debian/Ubuntu:

    sudo apt install -y gcc-aarch64-linux-gnu make bison flex bc cpio gzip tar curl libssl-dev

The scripts assume `aarch64-linux-gnu-gcc` is on `$PATH`. Override the
prefix via `CROSS_COMPILE=...-` if your toolchain uses a different tuple.

## Build

From this directory:

    ./build-linux.sh      # -> out/linux-arm64-Image
    ./build-busybox.sh    # -> out/rootfs.cpio.gz

Both scripts are idempotent: they cache tarballs and extracted trees under
`./src/` and only rebuild what's needed. Running offline works after the
first successful fetch.

## Config deltas

We deliberately keep the kernel config tiny. The recipe starts from
`make tinyconfig` and merges `linux.defconfig` on top. That fragment only
enables:

- `ARCH_VIRT` (covers the tests/linux_guest/qemu-virt memory map)
- PL011 UART + earlycon at `0x9000000`
- Built-in command line: `console=ttyAMA0 earlycon=pl011,0x9000000`
- `BLK_DEV_INITRD` + `RD_GZIP` for the cpio rootfs
- `DEVTMPFS`, `TMPFS`, `PROC_FS`, `SYSFS` so `/init` can mount the
  standard pseudo-filesystems
- `BINFMT_ELF` + `BINFMT_SCRIPT` so busybox and the `#!/bin/sh` init run

No networking, no block devices, no USB, no MMU-less quirks, no SMP.
Re-enable options as the VM layer grows.

Busybox starts from `make defconfig` and only forces `CONFIG_STATIC=y` so
the initramfs needs no libc — everything else is the upstream default,
which keeps this recipe short and easy to audit.

## Checksums

`build-linux.sh` currently ships with `LINUX_SHA256` unset (zeros); set it
to the upstream `sha256sums.asc` value before committing the artifact to
CI. `build-busybox.sh` pins `1.36.1` against its upstream hash. Override
either via env var.

## Open questions

- Linux LTS choice: this pins 6.6 LTS. If linux_guest needs a newer KVM-guest
  feature (e.g. SME, newer GICv3 LPI behaviour), bump to 6.12 LTS by
  setting `LINUX_VERSION=6.12.x` and updating `LINUX_SHA256`.
- Whether we want the kernel Image raw vs. gzipped: the script emits the
  raw `Image` per the task spec. linux_guest will need to handle decompression
  itself if we ever switch.
