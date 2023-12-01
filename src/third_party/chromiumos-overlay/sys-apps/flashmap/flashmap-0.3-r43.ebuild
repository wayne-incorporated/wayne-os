# Copyright 2011 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
# $Header:

EAPI=7
CROS_WORKON_COMMIT="e3fc969bdf4e744e2478aeb4d0f5cd5a7fc80f70"
CROS_WORKON_TREE="bc7aa5f7cd6ba338b028e2c2f3a695a887fe7164"
CROS_WORKON_PROJECT="chromiumos/third_party/flashmap"

PYTHON_COMPAT=( python3_{6..9} )

inherit cros-workon toolchain-funcs python-r1

DESCRIPTION="Utility for manipulating firmware ROM mapping data structure"
HOMEPAGE="http://flashmap.googlecode.com"
SRC_URI=""

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="python"

RDEPEND="python? ( ${PYTHON_DEPS} )"
DEPEND="${RDEPEND}"

# Disable unit testing for now because one of the test cases for detecting
# buffer overflow causes emake to fail when fmap_test is run.
# RESTRICT="test" will override FEATURES="test" and will also cause
# src_test() to be ignored by relevant scripts.
RESTRICT="test"

src_configure() {
	tc-export AR CC LD NM STRIP OBJCOPY
}

src_test() {
	# default "test" target uses lcov, so "test_only" was added to only
	# build and run the test without generating coverage statistics
	emake test_only
}

src_install() {
	emake LIBDIR=$(get_libdir) DESTDIR="${D}" USE_PKG_CONFIG=1 install

	if use python; then
		install_python() {
			insinto "$(python_get_sitedir)"
			doins "fmap.py"
		}
		python_foreach_impl install_python
	fi
}
