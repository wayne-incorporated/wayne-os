# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7
PYTHON_COMPAT=( python3_{6,7} )

inherit distutils-r1

DESCRIPTION="Utils for reading/writing to /dev/mem"
HOMEPAGE="http://chromium.org"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

BDEPEND="dev-python/setuptools[${PYTHON_USEDEP}]"
RDEPEND=""
DEPEND="${RDEPEND}"

src_unpack() {
	S=${WORKDIR}
	cp -r "${FILESDIR}/"* "${S}" || die
}
