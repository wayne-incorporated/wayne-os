# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=5

inherit arc-build-constants udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
S="${WORKDIR}"
IUSE="cheets"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/chromeos-scp-firmware-asurada
"
DEPEND="${RDEPEND}"

src_install() {
	# Override default CPU clock speed governor.
	insinto "/etc"
	doins "${FILESDIR}/cpufreq.conf"

	# Install cpuset adjustments.
	if use cheets; then
		arc-build-constants-configure

		insinto "${ARC_PREFIX:?}/vendor/etc/init"
		doins "${FILESDIR}/init.cpusets.rc"
	fi

	# udev rules for codecs
	insinto "/etc/init"
	doins "${FILESDIR}/udev-trigger-codec.conf"
	udev_dorules "${FILESDIR}/50-media.rules"
}
