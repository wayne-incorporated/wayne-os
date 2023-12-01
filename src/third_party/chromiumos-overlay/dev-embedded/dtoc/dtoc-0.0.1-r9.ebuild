# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_COMMIT="527f7efdcc37ffceddbde73bcfe28a914994bd5b"
CROS_WORKON_TREE="2cdb71f82079d3ea0e6032de1dba7a63332ad21f"
CROS_WORKON_PROJECT="chromiumos/third_party/u-boot"
CROS_WORKON_LOCALNAME="u-boot/files"
CROS_WORKON_SUBTREE="tools/dtoc"
CROS_WORKON_EGIT_BRANCH="chromeos-v2020.01"

PYTHON_COMPAT=( python3_{6..9} )

inherit cros-workon distutils-r1

DESCRIPTION="Dtoc tool (from U-Boot) for converting devicetree files to C"
HOMEPAGE="https://www.denx.de/wiki/U-Boot"

LICENSE="GPL-2"
SLOT="0/0"
KEYWORDS="*"
IUSE=""

BDEPEND="dev-python/setuptools[${PYTHON_USEDEP}]"
RDEPEND="dev-vcs/patman"

src_unpack() {
	cros-workon_src_unpack

	S+=/tools/dtoc
}
