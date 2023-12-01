# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"
CROS_WORKON_COMMIT="d52a38ffface8988da342133161c8a6b462437a0"
CROS_WORKON_TREE="452823ccec67536342fff3d263a6a3d1be44a0ce"
CROS_WORKON_PROJECT="chromiumos/platform/btsocket"
CROS_WORKON_LOCALNAME="../platform/btsocket"

PYTHON_COMPAT=( python3_{6..9} )

inherit cros-sanitizers cros-workon distutils-r1

DESCRIPTION="Bluetooth Socket support module"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/btsocket/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="-asan"

DEPEND="dev-python/setuptools[${PYTHON_USEDEP}]"
RDEPEND=""

src_configure() {
	sanitizers-setup-env
	default
}
