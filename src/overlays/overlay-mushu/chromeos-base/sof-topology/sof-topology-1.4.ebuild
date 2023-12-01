# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=5

DESCRIPTION="SOF topology file for Hatch board"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}-hatch.tar.xz"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"

S=${WORKDIR}/${P}-hatch

src_install() {
	insinto /lib/firmware/intel/sof-tplg
	doins ./*.tplg
	dodoc README
}
