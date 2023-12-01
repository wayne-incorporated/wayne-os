# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="SOF topology file for Dedede board"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-dedede-${PV}.tar.xz"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"

S=${WORKDIR}/${PN}-dedede-${PV}

src_install() {
	insinto /lib/firmware/intel/sof-tplg
	doins ./*.tplg
	dosym ./sof-jsl-rt5682-rt1015.tplg /lib/firmware/intel/sof-tplg/sof-jsl-rt5682-rt1019.tplg
}
