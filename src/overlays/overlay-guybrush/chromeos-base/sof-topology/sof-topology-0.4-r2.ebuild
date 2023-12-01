# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="SOF topology files for Guybrush"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-guybrush-${PV}.tar.bz2"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"

S=${WORKDIR}/${PN}-guybrush-${PV}

src_install() {
	insinto /lib/firmware/amd/sof-tplg
	doins ./*.tplg
	dodoc README

	dosym sof-acp.tplg /lib/firmware/amd/sof-tplg/sof-rn-rt5682-max98360.tplg
	dosym sof-acp.tplg /lib/firmware/amd/sof-tplg/sof-rn-rt5682-rt1019.tplg
}
