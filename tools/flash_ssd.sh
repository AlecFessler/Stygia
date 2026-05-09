#!/bin/bash
set -euo pipefail

SSD_PART="/dev/nvme0n1p1"
MNT="/mnt/desktopOS"
REPO_ROOT="$(dirname "$0")/.."
BOOT_EFI="$REPO_ROOT/zig-out/img/efi/boot/BOOTX64.EFI"
KERNEL="$REPO_ROOT/zig-out/img/kernel.elf"
ROOT_SVC="$REPO_ROOT/../Stygia-desktopOS/bin/desktopOS.elf"

for f in "$BOOT_EFI" "$KERNEL" "$ROOT_SVC"; do
    if [ ! -f "$f" ]; then
        echo "Error: $f not found."
        exit 1
    fi
done

mkdir -p "$MNT"
mount "$SSD_PART" "$MNT"

mkdir -p "$MNT/efi/boot"
cp "$BOOT_EFI" "$MNT/efi/boot/BOOTX64.EFI"
cp "$KERNEL" "$MNT/kernel.elf"
cp "$ROOT_SVC" "$MNT/root_service.elf"

sync
umount "$MNT"

echo "Done. SSD is ready to boot."
