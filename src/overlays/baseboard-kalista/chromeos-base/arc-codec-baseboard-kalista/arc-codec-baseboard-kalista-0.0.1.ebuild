# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit cros-constants

DESCRIPTION="Install codec configuration for ARC++"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
S="${WORKDIR}"
RDEPEND="!chromeos-base/arc-codec-chipset-kbl"

src_install() {
	insinto "${ARC_VENDOR_DIR}/etc/"
	doins "${FILESDIR}/media_codecs.xml"
	doins "${FILESDIR}/media_codecs_c2.xml"
	doins "${FILESDIR}/media_codecs_performance.xml"
	doins "${FILESDIR}/media_codecs_performance_c2.xml"
}
