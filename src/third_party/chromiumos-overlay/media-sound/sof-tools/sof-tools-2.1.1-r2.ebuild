# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

inherit cmake

DESCRIPTION="Tools for Sound Open Firmware"
HOMEPAGE="https://github.com/thesofproject/sof"
SRC_URI="https://github.com/thesofproject/sof/archive/refs/tags/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"

DEPEND="
	media-libs/alsa-lib
"
RDEPEND="${DEPEND}"

S="${WORKDIR}/sof-${PV}/tools"

PATCHES=(
	"${FILESDIR}"/0001-sof-ctl-Fix-Wformat-Wsometimes-uninitialized.patch
)

src_compile() {
	cmake_build sof-logger sof-ctl
}

src_install() {
	dobin "${BUILD_DIR}/logger/sof-logger"
	dobin "${BUILD_DIR}/ctl/sof-ctl"
}
