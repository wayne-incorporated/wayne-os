# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# This ebuild is for running tast DLC test in the lab and local dev setup.
# For future DLC autotests, a new installation process needs to be re-designed.

EAPI=6

CROS_WORKON_COMMIT="0b83dd091e7843e72cd531ce9ee2de84aaf5b1e1"
CROS_WORKON_TREE="ee50c6e65353dc3ca8aff8b43c1c634c5973f37f"
PYTHON_COMPAT=( python3_{6..9} )

CROS_WORKON_PROJECT="chromiumos/platform/dev-util"
CROS_WORKON_LOCALNAME="platform/dev"
CROS_WORKON_OUTOFTREE_BUILD="1"
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_SUBTREE="nebraska"

inherit cros-workon python-r1

DESCRIPTION="A set of utilities for updating Chrome OS."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/dev-util/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

RDEPEND="${PYTHON_DEPS}
	!chromeos-base/gmerge"
DEPEND="${PYTHON_DEPS}"

# Add an empty src_compile() so we bypass compile stage.
src_compile() { :; }

src_install() {
	into /usr/local
	dobin nebraska/nebraska.py

	insinto /etc/init
	doins nebraska/nebraska.conf
	sed -i "s:@LIBDIR@:$(get_libdir):g" "${ED}"/etc/init/nebraska.conf || die
}

src_test() {
	# Run the unit tests.
	python_test() {
		"${PYTHON}" nebraska/nebraska_unittest.py || die
	}
	python_foreach_impl python_test
}
