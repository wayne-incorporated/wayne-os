# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="AMD Mendocino SOF firmware binary"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-mendocino-${PV}.tar.bz2"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"

S=${WORKDIR}/${PN}-mendocino-${PV}

src_install() {
	insinto /lib/firmware/amd/sof/community
	doins sof-rmb.ri
	doins sof-rmb.ldc
	dodoc README.md
}
