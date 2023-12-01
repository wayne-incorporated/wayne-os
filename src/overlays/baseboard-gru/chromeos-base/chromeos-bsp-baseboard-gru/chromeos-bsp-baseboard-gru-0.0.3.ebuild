# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit appid udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
IUSE="cheets"
S="${WORKDIR}"

RDEPEND="
	x11-drivers/mali-rules
	media-libs/vpd-hdcpkey-install
	!media-libs/media-rules
	!<chromeos-base/chromeos-bsp-kevin-0.0.3
"
DEPEND="${RDEPEND}"

src_install() {
	# Override default CPU clock speed governor.
	insinto "/etc"
	doins "${FILESDIR}/5.10/cpufreq.conf"

	# Install cpuset adjustments.
	if use cheets; then
		insinto "/opt/google/containers/android/vendor/etc/init/"
		doins "${FILESDIR}/5.10/init.cpusets.rc"
	fi

	# Install platform specific triggers and udev rules for codecs.
	insinto "/etc/init"
	doins "${FILESDIR}/udev-trigger-codec.conf"
	udev_dorules "${FILESDIR}/50-media.rules"
}
