# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="SOF topology file for Puff board"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-puff-${PV}.tar.xz"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"

S=${WORKDIR}/${PN}-puff-${PV}

src_install() {
	insinto /lib/firmware/intel/sof-tplg
	doins ./*.tplg
	dodoc README
}
