# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

PYTHON_COMPAT=( python3_{6..9} )

CROS_WORKON_PROJECT="chromiumos/third_party/autotest"
CROS_WORKON_LOCALNAME="third_party/autotest/files"

inherit cros-workon autotest python-any-r1

DESCRIPTION="Autotest tests for Bluetooth"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/third_party/autotest/"
SRC_URI=""
LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~*"

# Enable autotest by default.
IUSE="+autotest"

RDEPEND="
	chromeos-base/autotest-client
	dev-python/btsocket
"

CLIENT_IUSE_TESTS="
	+tests_bluetooth_AVLHCI
	+tests_bluetooth_AVLDriver
	+tests_bluetooth_AdapterQuickHealthClient
"

IUSE_TESTS="${IUSE_TESTS}
	${CLIENT_IUSE_TESTS}
"

IUSE="${IUSE} ${IUSE_TESTS}"

AUTOTEST_FILE_MASK="*.a *.tar.bz2 *.tbz2 *.tgz *.tar.gz"
