# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_PROJECT="chromiumos/platform/touch_firmware_test"
CROS_WORKON_LOCALNAME="platform/touch_firmware_test"

PYTHON_COMPAT=( python3_{6..9} )
inherit cros-sanitizers cros-workon cros-constants cros-debug distutils-r1

DESCRIPTION="Chromium OS multitouch utilities"

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="~*"
IUSE="-asan"

RDEPEND=""

DEPEND=${RDEPEND}

src_configure() {
	sanitizers-setup-env
	cros-debug-add-NDEBUG
	default
}

src_install() {
	# install the remote package
	distutils-r1_src_install

	# install the webplot script
	exeinto /usr/local/bin
	newexe webplot/chromeos_wrapper.sh webplot

	# install the heatmapplot script
	newexe heatmap/chromeos_heatmapplot_wrapper.sh heatmapplot

	# install to autotest deps directory for dependency
	DESTDIR="${D}${AUTOTEST_BASE}/client/deps/touchpad-tests/touch_firmware_test"
	mkdir -p "${DESTDIR}"
	echo "CMD:" cp -Rp "${S}"/* "${DESTDIR}"
	cp -Rp "${S}"/* "${DESTDIR}"
}
