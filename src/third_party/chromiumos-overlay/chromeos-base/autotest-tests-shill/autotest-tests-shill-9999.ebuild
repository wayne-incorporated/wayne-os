# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_PROJECT="chromiumos/third_party/autotest"
CROS_WORKON_LOCALNAME="third_party/autotest/files"

inherit cros-workon autotest

DESCRIPTION="shill autotests"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/third_party/autotest/"
SRC_URI=""

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~*"
# Enable autotest by default.
IUSE="+autotest +tpm tpm2"

RDEPEND="
	!<chromeos-base/autotest-tests-0.0.3
	chromeos-base/shill-test-scripts
"
DEPEND="${RDEPEND}"

IUSE_TESTS="
	+tests_network_WiFiResume
	+tests_network_WlanPresent
"

IUSE="${IUSE} ${IUSE_TESTS}"

AUTOTEST_FILE_MASK="*.a *.tar.bz2 *.tbz2 *.tgz *.tar.gz"
