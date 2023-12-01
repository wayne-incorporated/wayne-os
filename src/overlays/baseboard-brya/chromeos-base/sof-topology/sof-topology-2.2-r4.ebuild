# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="SOF topology files for Brya"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-brya-${PV}.tar.bz2"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"

S=${WORKDIR}/${PN}-brya-${PV}

src_install() {
	insinto /lib/firmware/intel/sof-tplg
	doins ./*.tplg
	insinto /lib/firmware/intel/sof-tplg/pdm1
	doins ./pdm1/*.tplg

	dosym ./sof-adl-max98360a-rt5682.tplg /lib/firmware/intel/sof-tplg/sof-adl-max98360a-cs42l42.tplg
	dosym ./sof-adl-max98360a-rt5682.tplg /lib/firmware/intel/sof-tplg/sof-rpl-max98360a-rt5682.tplg
	dosym ./sof-adl-rt1019-rt5682.tplg /lib/firmware/intel/sof-tplg/sof-rpl-rt1019-rt5682.tplg
}
