# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_SUBTREE="shill/test-scripts"

PYTHON_COMPAT=( python3_{6..9} )

inherit cros-workon python-single-r1

DESCRIPTION="shill's test scripts"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/shill/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="~*"
IUSE=""

RDEPEND="${PYTHON_DEPS}
	$(python_gen_cond_dep 'dev-python/dbus-python[${PYTHON_USEDEP}]')
	>=chromeos-base/shill-0.0.1-r2205
	net-dns/dnsmasq
	sys-apps/iproute2"

src_compile() {
	# We only install scripts here, so no need to compile.
	:
}

src_install() {
	exeinto /usr/lib/flimflam/test
	doexe shill/test-scripts/*
}
