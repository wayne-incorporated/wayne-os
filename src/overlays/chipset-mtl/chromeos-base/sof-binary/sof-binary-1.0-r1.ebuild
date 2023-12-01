# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="Meteor Lake SOF firmware binary"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-mtl-${PV}.tar.gz"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"

S=${WORKDIR}/${PN}-mtl-${PV}

src_install() {
	insinto /lib/firmware/intel/sof-ipc4/mtl/community
	doins sof-mtl.ri
	doins sof-mtl.ldc
}
