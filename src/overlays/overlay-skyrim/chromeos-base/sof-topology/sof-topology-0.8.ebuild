# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="SOF topology files for Skyrim"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-skyrim-${PV}.tar.bz2"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"

S=${WORKDIR}/${PN}-skyrim-${PV}

src_install() {
	insinto /lib/firmware/amd/sof-tplg
	doins ./*.tplg
	dodoc README

	dosym sof-acp-rmb.tplg /lib/firmware/amd/sof-tplg/sof-rmb-rt5682s-rt1019.tplg
}
