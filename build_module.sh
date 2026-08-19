#!/usr/bin/env bash
set -e
# Local (PC) build helper.
#   export KDIR=/path/to/android15-6.6-kernel   KDIR=/... ./build_module.sh
# Requirements: clang-18/llvm-18 (or AOSP prebuilt clang), flex, bison, bc, libssl-dev, libelf-dev
KDIR="${KDIR:?set KDIR to the android15-6.6 kernel source tree}"
export ARCH=arm64
cd "$KDIR"
make LLVM=1 LLVM_IAS=1 gki_defconfig
make LLVM=1 LLVM_IAS=1 -j"$(nproc)" modules_prepare
cd - >/dev/null
make ARCH=arm64 LLVM=1 -C "$KDIR" M="$PWD" modules
echo "OK: $(pwd)/smaps_hide.ko"
