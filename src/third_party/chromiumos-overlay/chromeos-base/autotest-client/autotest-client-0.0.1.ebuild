# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cros-constants

DESCRIPTION="Client portion of autotest installed at image creation time"
HOMEPAGE="http://src.chromium.org"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE="-moblab"

DEPEND="
	chromeos-base/autotest
"

S=${WORKDIR}

src_install() {
	AUTOTEST_INSTALL_DIR="/usr/local/autotest"
	use moblab && AUTOTEST_INSTALL_DIR="/usr/local/autodir"

	dodir "${AUTOTEST_INSTALL_DIR}"
	tar xvf "${SYSROOT}/${AUTOTEST_BASE}/packages/client-autotest.tar.bz2" \
		-C "${D}/${AUTOTEST_INSTALL_DIR}" || die
}
