# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Qualcomm libraries required by the 7c-gen3 camera ISP"
SRC_URI="gs://chromeos-localmirror/distfiles/qti-7c-gen3-camera-bins-${PV}.tbz2"

LICENSE="LICENSE.qcom"
SLOT="0"
KEYWORDS="-* arm64 arm"

DEPEND=""

RDEPEND="${DEPEND}"

S="${WORKDIR}"

src_install() {
	insinto /usr/lib
	doins -r "${WORKDIR}/lib/"*
	insinto /lib/firmware/qcom
	doins -r "${WORKDIR}/firmware/"*
}
