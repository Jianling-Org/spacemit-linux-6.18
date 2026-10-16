#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Run on K3 from the separately verified and patched source tree.
set -euo pipefail
test "$(uname -m)" = riscv64
test -f .config
mkdir -p prefer-a100-evidence
uname -a > prefer-a100-evidence/build-host.txt
gcc --version > prefer-a100-evidence/compiler.txt
scripts/config --set-str LOCALVERSION '-prefer-a100' --disable LOCALVERSION_AUTO
scripts/config --set-str INITRAMFS_SOURCE ''
# Existing helpers_chimera.c uses arch_uprobe definitions unconditionally.
scripts/config --enable UPROBE_EVENTS
make olddefconfig > prefer-a100-evidence/config.log 2>&1
make -j8 drivers/soc/spacemit/hmp.o kernel/sched/core.o kernel/sched/fair.o \
    kernel/bpf/helpers_chimera.o fs/exec.o fs/proc/array.o \
    > prefer-a100-evidence/objects.log 2>&1
printf '0\n' > prefer-a100-evidence/objects.rc
make -j8 Image modules > prefer-a100-evidence/build.log 2>&1
printf '0\n' > prefer-a100-evidence/build.rc
make -s kernelrelease > prefer-a100-evidence/kernelrelease.txt
sha256sum arch/riscv/boot/Image > prefer-a100-evidence/Image.sha256
gcc -O2 -march=rv64gc -mabi=lp64d -fno-tree-vectorize \
    tools/testing/selftests/riscv/prefer_a100/scalar.c \
    -o tools/testing/selftests/riscv/prefer_a100/scalar
