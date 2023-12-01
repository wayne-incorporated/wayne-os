# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Proprietary binaries for ADSP on Qualcomm SC7280 platforms"
SRC_URI="
gs://chromeos-localmirror/distfiles/adsp-tplg-base-${PV}.tar.bz2
gs://chromeos-localmirror/distfiles/adsp-pbn-base-${PV}.tar.bz2
"

# TODO(b/268144374) Update the correct LICENSE.
LICENSE="TAINTED"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}"

src_install() {
	insinto /lib/firmware/qcom/SC7280
	doins adsp-tplg-base-${PV}/*.bin

	insinto /lib/firmware
	doins adsp-pbn-base-${PV}/*.pbn
}
