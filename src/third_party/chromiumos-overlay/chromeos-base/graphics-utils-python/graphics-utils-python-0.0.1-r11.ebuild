# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_WORKON_COMMIT="ace6cbe0dbec46ff659c4ca4a97542e422222484"
CROS_WORKON_TREE="83e1f66d67cc0b9ee1acda334a3f3d1c2a5dfbcd"
CROS_WORKON_PROJECT="chromiumos/platform/graphics"
CROS_WORKON_LOCALNAME="platform/graphics"
CROS_WORKON_SUBTREE="src/results_database"

PYTHON_COMPAT=( python3_{6..9} )

inherit cros-workon distutils-r1

DESCRIPTION="Graphics utilities written in python"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/graphics/"

LICENSE="BSD-Google"
SLOT=0
KEYWORDS="*"
IUSE=""

RDEPEND="chromeos-base/cros-config-api"

DEPEND="
	${RDEPEND}
"

BDEPEND="
	dev-python/setuptools[${PYTHON_USEDEP}]
"

src_unpack() {
	cros-workon_src_unpack
	S+="/src/results_database"
}

src_install() {
	dobin bq_insert_pb.py
	dobin generate_trace_info.py
	dobin record_machine_info.py
	dobin record_package_override.py
	dobin record_software_config.py
	dobin summarize_apitrace_log.py

	distutils-r1_src_install
}
