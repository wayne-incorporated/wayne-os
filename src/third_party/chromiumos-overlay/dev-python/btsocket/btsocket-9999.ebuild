# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"
CROS_WORKON_PROJECT="chromiumos/platform/btsocket"
CROS_WORKON_LOCALNAME="../platform/btsocket"

PYTHON_COMPAT=( python3_{6..9} )

inherit cros-sanitizers cros-workon distutils-r1

DESCRIPTION="Bluetooth Socket support module"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/btsocket/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="~*"
IUSE="-asan"

DEPEND="dev-python/setuptools[${PYTHON_USEDEP}]"
RDEPEND=""

src_configure() {
	sanitizers-setup-env
	default
}
