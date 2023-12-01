# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit cros-cellular udev user

DESCRIPTION="Chrome OS Modem Update Helpers (nautilus)"
HOMEPAGE="http://src.chromium.org"
MIRROR_PATH="gs://chromeos-localmirror/distfiles"
SRC_URI="
	${MIRROR_PATH}/cellular-firmware-fibocom-l850-18500.5001.00.04.26.01_6006.03_Secureboot.tar.xz
	${MIRROR_PATH}/cellular-firmware-fibocom-l850-nautilus-carriers_OEM_6006-r2.tar.xz
"
LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}"
DEPEND=""
RDEPEND="${DEPEND}"

src_install() {
	cellular_domanifest "${FILESDIR}/helper_manifest.textproto"

	# TODO(ejcaruso): remove these after b/71870985 is fixed and we can
	# use MBIM commands to reset the modem instead of toggling GPIOs
	insinto /etc/init/
	doins "${FILESDIR}/modemfwd-helpers.conf"

	udev_dorules "${FILESDIR}/94-l850gl-gpio.rules"

	cellular_dofirmware "${FILESDIR}/firmware_manifest.prototxt"
	# cellular_dofirmware cannot handle this case yet (multiple directories/modems)
	insinto "$(_cellular_get_firmwaredir)/l850"
	doins -r cellular-firmware-fibocom-l850-*/*
}

pkg_preinst() {
	enewgroup gpio
}
