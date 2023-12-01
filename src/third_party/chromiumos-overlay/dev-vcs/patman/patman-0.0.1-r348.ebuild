# Copyright 2012 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_COMMIT="372a0e417dc7ca68c1e7a620ed9619c65eb31ec1"
CROS_WORKON_TREE="ddca2c910e68089db8323f870fe3132c60ce03db"
CROS_WORKON_PROJECT="chromiumos/third_party/u-boot"
CROS_WORKON_LOCALNAME="u-boot/files"
CROS_WORKON_SUBTREE="tools/patman"
CROS_WORKON_EGIT_BRANCH="chromeos-v2020.01"

PYTHON_COMPAT=( python3_{6..9} )

inherit cros-workon distutils-r1

DESCRIPTION="Patman tool (from U-Boot) for sending patches upstream"
HOMEPAGE="https://www.denx.de/wiki/U-Boot"

LICENSE="GPL-2"
SLOT="0/0"
KEYWORDS="*"
IUSE=""

BDEPEND="dev-python/setuptools[${PYTHON_USEDEP}]"
RDEPEND=""

src_prepare() {
	cd tools/patman
	distutils-r1_src_prepare
}

src_compile() {
	cd tools/patman
	distutils-r1_src_compile
}

src_install() {
	cd tools/patman
	distutils-r1_src_install
}
