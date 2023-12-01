# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="36e36575ca053ff30cdd29ee9bce01def40b7c5e"
CROS_WORKON_TREE="b0f121faef567b7be3620e5ddf9b7b1a6d6b5bee"
PYTHON_COMPAT=( python3_{6..9} )

CROS_WORKON_PROJECT="chromiumos/platform/usi-test"
CROS_WORKON_LOCALNAME="platform/usi-test"

inherit cros-workon distutils-r1

DESCRIPTION="Universal Stylus Initiative (USI) Certification Tool"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/usi-test/"
SRC_URI=""

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="-"

RDEPEND="~dev-python/hid-tools-0.2[${PYTHON_USEDEP}]"
DEPEND="${RDEPEND}"
