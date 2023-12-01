# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=4

inherit cros-constants

DESCRIPTION="Install software codec configurations on ARC++"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
S="${WORKDIR}"

src_install() {
	insinto "${ARC_VENDOR_DIR}/etc/"
	doins "${FILESDIR}/media_codecs.xml"
}
