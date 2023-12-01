# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=4

DESCRIPTION="Install configuration data for Atmel chips"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

TOUCH_CONFIG_PATH="/opt/google/touch/config"
TS_CONFIG_FILE="2405T2.raw"
TS_CONFIG_LINK="/lib/firmware/maxtouch-ts.cfg"
TP_CONFIG_FILE="337t.raw"
TP_CONFIG_LINK="/lib/firmware/maxtouch-tp.cfg"

S=${WORKDIR}

DEPEND=""

RDEPEND="${DEPEND}
	 chromeos-base/touch_updater"

src_install() {
	insinto "${TOUCH_CONFIG_PATH}"
        doins "${FILESDIR}/${TS_CONFIG_FILE}"
	dosym "${TOUCH_CONFIG_PATH}/${TS_CONFIG_FILE}" "${TS_CONFIG_LINK}"
	doins "${FILESDIR}/${TP_CONFIG_FILE}"
	dosym "${TOUCH_CONFIG_PATH}/${TP_CONFIG_FILE}" "${TP_CONFIG_LINK}"
}
