# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="AMD Cezanne SOF firmware binary"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-cezanne-${PV}.tar.bz2"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"

S=${WORKDIR}/${PN}-cezanne-${PV}

src_install() {
	insinto /lib/firmware/amd/sof/community
	doins sof-rn.ri
	doins sof-rn.ldc
	dodoc README
}
