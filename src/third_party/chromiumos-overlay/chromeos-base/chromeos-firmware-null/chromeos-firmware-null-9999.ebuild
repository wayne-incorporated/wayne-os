# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_LOCALNAME="platform/firmware"
CROS_WORKON_PROJECT="chromiumos/platform/firmware"

inherit cros-workon cros-firmware

DESCRIPTION="Chrome OS Firmware (Template - change to board name)"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/firmware/"
LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="~*"

RDEPEND=""

### FIRMWARE IMAGES ###
# Specify the firmware images to update. You can use file path or URLs (in
# ebuild SRC_URI syntax). Most projects will use Binary Component Server (BCS)
# links. To do that, archive only the image file as a tbz2 and upload to CPFE
# web site (http://www.google.com/chromeos/partner/fe/) with relative path
# chromeos-base/chromeos-firmware-${BOARD}. Then you can refer to the file as
# "bcs://filename.tbz2".
#
# MAIN_IMAGE controls AP RO firmware (also RW if MAIN_RW_IMAGE is empty).
# MAIN_RW_IMAGE controls AP RW firmware when you need different RO & RW.
# EC_IMAGE controls EC RO firmware (RW will be synced from MAIN_[RW_]IMAGE).
# For more details, read
# https://chromium.googlesource.com/chromiumos/platform/firmware/+/master/README.md
#
# When you modify any image files below, please also update manifest file:
#  (chroot) ebuild chromeos-firmware-${BOARD}-9999.ebuild manifest
CROS_FIRMWARE_MAIN_IMAGE=""
CROS_FIRMWARE_MAIN_RW_IMAGE=""
CROS_FIRMWARE_EC_IMAGE=""

### EXTRA FILES ###
# ${FILESDIR}/extra will be automatically merged into updater package.
# ${FILESDIR}/sbin will be automatically installed to /usr/sbin on rootfs.
# Put board customization (updater_custom.sh) in ${FILESDIR}/extra.
# If you need more files, define a CROS_FIRMWARE_EXTRA_LIST with the file names
# and directory names to include, delimited by semicolon.

cros-firmware_setup_source

# Remove/Adapt script below here when using the template.
src_unpack() {
	einfo "Stub implementation to replace cros-firmware.eclass"
	cros-workon_src_unpack
}

src_compile() {
	einfo "Stub implementation to replace cros-firmware.eclass"
}

src_install() {
	einfo "Stub implementation to replace cros-firmware.eclass"
}
