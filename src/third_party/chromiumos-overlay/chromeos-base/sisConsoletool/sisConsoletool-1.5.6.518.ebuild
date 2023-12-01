# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="SiS Consoletool for Firmware Update"
HOMEPAGE="https://github.com/jason10071/sisConsoletool"
SRC_URI="https://github.com/jason10071/sisConsoletool/archive/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

src_install() {
	dosbin bin/SiSGetFirmwareId
	dosbin bin/SiSUpdateFW
}
