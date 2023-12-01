# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7
PYTHON_COMPAT=( python3_{6..9} )

inherit distutils-r1

DESCRIPTION="Utils for measuring SC7180 clock frequencies via /dev/mem"
HOMEPAGE="http://chromium.org"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
IUSE=""

BDEPEND="dev-python/setuptools[${PYTHON_USEDEP}]"
RDEPEND="dev-util/mem"

src_unpack() {
	S=${WORKDIR}
	cp -r "${FILESDIR}/"* "${S}" || die
}
