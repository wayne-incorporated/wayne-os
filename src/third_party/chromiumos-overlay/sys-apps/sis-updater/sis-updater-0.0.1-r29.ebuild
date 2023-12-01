# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="0e41acf19950b8c60d1e0c46ff7b64a24c51dea1"
CROS_WORKON_TREE="b0181a9a8689259b43aaa8f3a42d2ffe5126176f"
CROS_WORKON_PROJECT="chromiumos/third_party/sis-updater"

inherit cros-workon cros-common.mk libchrome udev user

DESCRIPTION="A tool to update SiS firmware on Mimo from Chromium OS."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/third_party/sis-updater"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

DEPEND="chromeos-base/libbrillo:="

RDEPEND="${DEPEND}"

src_install() {
	dosbin "${OUT}/sis-updater"
	udev_dorules conf/99-sis-usb.rules
}

pkg_preinst() {
	enewuser cfm-firmware-updaters
	enewgroup cfm-firmware-updaters
}
