# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# Check for EAPI 4+
case "${EAPI:-0}" in
4|5|6|7) ;;
*) die "unsupported EAPI (${EAPI}) in eclass (${ECLASS})" ;;
esac

# @ECLASS-VARIABLE: COREBOOT_SDK_PREFIX
# @DESCRIPTION:
#   Path where the coreboot SDK can be found.
COREBOOT_SDK_PREFIX=/opt/coreboot-sdk

# @ECLASS-VARIABLE: COREBOOT_SDK_PREFIX_arm
# @DESCRIPTION:
#   Prefix of coreboot SDK binaries for 32-bit arm.
COREBOOT_SDK_PREFIX_arm=${COREBOOT_SDK_PREFIX}/bin/arm-eabi-

# @ECLASS-VARIABLE: COREBOOT_SDK_PREFIX_arm64
# @DESCRIPTION:
#   Prefix of coreboot SDK binaries for 64-bit arm.
COREBOOT_SDK_PREFIX_arm64=${COREBOOT_SDK_PREFIX}/bin/aarch64-elf-

# @ECLASS-VARIABLE: COREBOOT_SDK_PREFIX_mips
# @DESCRIPTION:
#   Prefix of coreboot SDK binaries for MIPS.
COREBOOT_SDK_PREFIX_mips=${COREBOOT_SDK_PREFIX}/bin/mipsel-elf-

# @ECLASS-VARIABLE: COREBOOT_SDK_PREFIX_nds32
# @DESCRIPTION:
#   Prefix of coreboot SDK binaries for NDS32.
COREBOOT_SDK_PREFIX_nds32=${COREBOOT_SDK_PREFIX}/bin/nds32le-elf-

# @ECLASS-VARIABLE: COREBOOT_SDK_PREFIX_riscv
# @DESCRIPTION:
#   Prefix of coreboot SDK binaries for RISC-V.
COREBOOT_SDK_PREFIX_riscv=${COREBOOT_SDK_PREFIX}/bin/riscv64-elf-

# @ECLASS-VARIABLE: COREBOOT_SDK_PREFIX_x86_32
# @DESCRIPTION:
#   Prefix of coreboot SDK binaries for 32-bit x86.
COREBOOT_SDK_PREFIX_x86_32=${COREBOOT_SDK_PREFIX}/bin/i386-elf-

# @ECLASS-VARIABLE: COREBOOT_SDK_PREFIX_x86_64
# @DESCRIPTION:
#   Prefix of coreboot SDK binaries for 64-bit x86.
COREBOOT_SDK_PREFIX_x86_64=${COREBOOT_SDK_PREFIX}/bin/x86_64-elf-
