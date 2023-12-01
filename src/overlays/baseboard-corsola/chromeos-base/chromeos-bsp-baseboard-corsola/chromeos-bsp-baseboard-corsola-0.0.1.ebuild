# Copyright 2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit arc-build-constants udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."
HOMEPAGE=""
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
S="${WORKDIR}"
IUSE="cheets"

# Add dependencies on other ebuilds from within this board overlay
DEPEND="
	chromeos-base/chromeos-scp-firmware-corsola
	chromeos-base/lte_power_control
"
RDEPEND="${DEPEND}"
BDEPEND=""

src_install() {
	# Override default CPU clock speed governor.
	insinto "/etc"
	doins "${FILESDIR}/cpufreq.conf"

	# udev rules for codecs
	insinto "/etc/init"
	doins "${FILESDIR}/udev-trigger-codec.conf"
	udev_dorules "${FILESDIR}/50-media.rules"

	# Install cpuset adjustments.
	if use cheets; then
		arc-build-constants-configure

		insinto "${ARC_PREFIX:?}/vendor/etc/init"
		doins "${FILESDIR}/init.cpusets.rc"
	fi
}
