# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cros-binary cros-cellular udev user

DESCRIPTION="Chrome OS Modem Update Helpers (brya)"
HOMEPAGE="http://src.chromium.org"
MIRROR_PATH="gs://chromeos-localmirror/distfiles"
SRC_URI="
	${MIRROR_PATH}/cellular-firmware-fibocom-l850-18500.5001.00.05.27.12_Secureboot.tar.xz
	${MIRROR_PATH}/cellular-firmware-fibocom-l850-18500.5001.00.05.27.16_Secureboot.tar.xz
	${MIRROR_PATH}/cellular-firmware-fibocom-l850-brya-carriers_OEM_6001-r6.tar.xz
	${MIRROR_PATH}/cellular-firmware-fibocom-l850-OEM_cust.6001.04.tar.xz
	${MIRROR_PATH}/cellular-firmware-fibocom-fm350-81600.0000.00.29.19.16.tar.xz
	${MIRROR_PATH}/cellular-firmware-fibocom-fm350-FM350.C82.tar.xz
	${MIRROR_PATH}/cellular-firmware-fibocom-fm350-DEV_OTA_5001.000F.0000_Default_001.000.000.001.img.tar.xz
	${MIRROR_PATH}/cellular-firmware-fibocom-fm350-DEV_OTA_5001.0001.0000_Default_001.000.000.015.img.tar.xz
	${MIRROR_PATH}/cellular-firmware-fibocom-fm350-OP_OTA_000.037.img.tar.xz
	${MIRROR_PATH}/cellular-firmware-fibocom-fm350-OEM_OTA_6001.0000.001.img.tar.xz
	${MIRROR_PATH}/cellular-firmware-fibocom-fm101-brya-19500.0000.00.01.01.52_A54.tar.xz
	"

RESTRICT="mirror"
LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}"
DEPEND="
	chromeos-base/modem-fw-dlc-anahera-l850
	chromeos-base/modem-fw-dlc-brya-fm350
	chromeos-base/modem-fw-dlc-brya-l850
	chromeos-base/modem-fw-dlc-bryati50-fm350
	chromeos-base/modem-fw-dlc-crota-fm101
	chromeos-base/modem-fw-dlc-primus-l850
	chromeos-base/modem-fw-dlc-redrix-fm350
	chromeos-base/modem-fw-dlc-redrix-l850
	chromeos-base/modem-fw-dlc-vell-fm350
	net-misc/qdl
"
RDEPEND="${DEPEND}"

src_install() {
	cellular_domanifest "${FILESDIR}/helper_manifest.textproto"

	# TODO(b/71870985): remove these after b/71870985 is fixed and we can
	# use MBIM commands to reset the modem instead of toggling GPIOs
	insinto /etc/init/
	doins "${FILESDIR}/modemfwd-helpers.conf"

	udev_dorules "${FILESDIR}/94-usb-modem-gpio.rules"

	cellular_dofirmware "${FILESDIR}/firmware_manifest.textproto"
	# cellular_dofirmware cannot handle this case yet (multiple directories/modems)
	insinto "$(_cellular_get_firmwaredir)/l850"
	for f in cellular-firmware-fibocom-l850-*; do
		doins -r "${f}"/*
	done
	insinto "$(_cellular_get_firmwaredir)/fm101"
	for f in cellular-firmware-fibocom-fm101-*; do
		doins -r "${f}"/*
	done
	insinto "$(_cellular_get_firmwaredir)/fm350"
	for f in cellular-firmware-fibocom-fm350-*; do
		doins -r "${f}"/*
	done

	# Create symbolic link to allow FM350 firmware to be accessible with
	# /lib/firmware as root directory. This is required for devlink to be able
	# to flash firmware to the modem.
	dosym "$(_cellular_get_firmwaredir)/fm350" "/lib/firmware/fm350"
}

pkg_preinst() {
	enewgroup gpio
}
