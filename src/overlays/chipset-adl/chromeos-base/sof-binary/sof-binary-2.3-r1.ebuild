# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="Alder Lake SOF firmware binary"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-adl-${PV}.tar.bz2"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	media-libs/adl-cs35l41-dsm-param-brya
	media-libs/adl-max98390-dsm-param-brya
	media-libs/adl-dsm-param
	media-libs/adl-hotword-support
	media-libs/adl-bandsplit-eq-param
	media-libs/adl-aec-param
"
DEPEND="${RDEPEND}"

S=${WORKDIR}/${PN}-adl-${PV}

src_install() {
	insinto /lib/firmware/intel/sof/community
	doins sof-adl.ri
	doins sof-adl.ldc

	dosym ./sof-adl.ri /lib/firmware/intel/sof/community/sof-rpl.ri
	dosym ./sof-adl.ldc /lib/firmware/intel/sof/community/sof-rpl.ldc
}
