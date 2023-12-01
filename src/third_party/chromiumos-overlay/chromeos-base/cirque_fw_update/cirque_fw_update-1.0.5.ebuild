# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="5"

inherit toolchain-funcs

DESCRIPTION="Cirque Touchpad Firmware Updater"
HOMEPAGE="https://github.com/cirque-corp/chromeos_cirque_fw_update"
SRC_URI="https://github.com/cirque-corp/chromeos_cirque_fw_update/archive/${PV}.tar.gz -> ${P}.tar.gz"
S="${WORKDIR}/chromeos_${P}/cirque_fw_update"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"

src_configure() {
	tc-export CXX
}

src_install() {
	dosbin cirque_touch_fw_update
}
