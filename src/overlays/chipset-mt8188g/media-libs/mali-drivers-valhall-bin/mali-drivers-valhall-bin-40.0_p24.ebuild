# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

inherit unpacker

DESCRIPTION="Mali Valhall user space prebuilt binaries for external builds"
HOMEPAGE=""
SRC_URI="http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/mali-drivers-valhall-geralt-${PV}.run"

LICENSE="Google-TOS"
SLOT="0"
KEYWORDS="-* arm64"

RDEPEND="
	>=x11-libs/libdrm-2.4.97
	!media-libs/mali-drivers-valhall
	!media-libs/mesa
"

S=${WORKDIR}

src_install() {
	cp -pPR "${S}"/* "${D}/" || die "Install failed!"
}
