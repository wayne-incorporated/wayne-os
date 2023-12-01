# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="5f42449f06f8ffe6aa5f6d0d3103a4ec2a77b5ad"
CROS_WORKON_TREE="5431d1ce55f0560c46a975ca3c9b08d04b122e6f"
CROS_WORKON_PROJECT="chromiumos/third_party/autotest"
CROS_WORKON_LOCALNAME="third_party/autotest/files"

PYTHON_COMPAT=( python3_{6..9} )

inherit cros-workon autotest python-any-r1

DESCRIPTION="Compilation and runtime tests for toolchain"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/third_party/autotest/"

LICENSE="GPL-2"
SLOT=0
KEYWORDS="*"
# Enable autotest by default.
IUSE="+autotest"

RDEPEND="
	!<chromeos-base/autotest-tests-0.0.3
	chromeos-base/toolchain-tests
"
DEPEND="${RDEPEND}"

IUSE_TESTS="
	+tests_platform_ToolchainTests
"

IUSE="${IUSE} ${IUSE_TESTS}"

AUTOTEST_FILE_MASK="*.a *.tar.bz2 *.tbz2 *.tgz *.tar.gz"
