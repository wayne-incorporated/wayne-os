# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_PROJECT="chromiumos/third_party/kernel"
CROS_WORKON_LOCALNAME="kernel/v5.10"
CROS_WORKON_EGIT_BRANCH="chromeos-5.10"

# This must be inherited *after* EGIT/CROS_WORKON variables defined
inherit cros-workon cros-kernel2

DESCRIPTION="Mini-kernel that is kexeced during panics"
KEYWORDS="~*"
# u-root + lvm2 + kernel licenses.
LICENSE="GPL-2 BSD-2 LGPL-2.1 BSD"

DEPEND="
	sys-boot/kdump-ramfs
"

src_configure() {
	# shellcheck disable=SC2154 # CHROMEOS_KERNEL_SPLITCONFIG defined in cros-kernel2
	CHROMEOS_KERNEL_FAMILY="kdump" chromeos/scripts/prepareconfig "${CHROMEOS_KERNEL_SPLITCONFIG}" "$(get_build_cfg)" || die
	echo "CONFIG_INITRAMFS_SOURCE=\"${SYSROOT}/usr/share/kdump/boot/kdump-rfs.cpio\"" >> "$(get_build_cfg)"
	kmake olddefconfig
}

KDUMP_FOLDER="/usr/share/kdump"

src_install() {
	cros-kernel2_src_install "${KDUMP_FOLDER}"

	# Image type used by kexec, depending on the architecture.
	case "${ARCH}" in
	arm | arm64)
		IMAGE=Image
		;;
	*)
		IMAGE=vmlinuz
		;;
	esac

	dosym "${KDUMP_FOLDER}"/boot/"${IMAGE}" "${KDUMP_FOLDER}"/boot/kdump-image
}
