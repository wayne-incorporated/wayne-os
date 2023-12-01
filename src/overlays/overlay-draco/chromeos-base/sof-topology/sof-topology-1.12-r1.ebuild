# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=6

DESCRIPTION="SOF topology files for Draco"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-brya-${PV}.tar.bz2"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"

S=${WORKDIR}/${PN}-brya-${PV}

src_install() {
		insinto /lib/firmware/intel/sof-tplg
		doins ./*.tplg
		dodoc README
}
