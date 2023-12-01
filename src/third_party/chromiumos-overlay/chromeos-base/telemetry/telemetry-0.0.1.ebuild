# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="6"

PYTHON_COMPAT=( python3_{6..9} )

inherit python-r1 cros-constants

DESCRIPTION="Chromium telemetry dep"
HOMEPAGE="http://www.chromium.org/"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"

# Ensure the telemetry dep tarball is created already.
DEPEND="${PYTHON_DEPS}
	chromeos-base/chromeos-chrome"
RDEPEND="${PYTHON_DEPS}
	dev-python/psutil[${PYTHON_USEDEP}]"

S=${WORKDIR}

src_unpack() {
	ln -s "${SYSROOT}${AUTOTEST_BASE}/packages/dep-telemetry_dep.tar.bz2" .
	unpack ./dep-telemetry_dep.tar.bz2
	# Some telemetry code hardcodes in 'src'
	mv test_src src || die
}

src_install() {
	insinto /usr/local/telemetry
	doins -r "${WORKDIR}"/*

	install_python() {
		# TODO(crbug.com/771085): Figure out this SYSROOT business.
		insinto "$(python_get_sitedir | sed "s:^${SYSROOT}::")"
		# Add telemetry to the python path.
		echo "/usr/local/telemetry/src/third_party/catapult/telemetry" | \
			newins - telemetry.pth
	}
	python_foreach_impl install_python
}
