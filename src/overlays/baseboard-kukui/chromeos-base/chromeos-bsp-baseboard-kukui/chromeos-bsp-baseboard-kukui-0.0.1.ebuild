# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=5

inherit udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
S="${WORKDIR}"
IUSE="arcvm kernel-5_10"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/chromeos-scp-firmware-kukui
"
DEPEND="${RDEPEND}"

src_install() {
	local kernel="5_10"

	# Override default CPU clock speed governor.
	insinto "/etc"
	doins "${FILESDIR}/cpufreq.conf"

	# Install cpuset adjustments.
	if use arcvm; then
		insinto "/opt/google/vms/android/vendor/etc/init/"
	else
		insinto "/opt/google/containers/android/vendor/etc/init/"
	fi
	newins "${FILESDIR}/init.cpusets-${kernel}.rc" init.cpusets.rc

	# udev rules for codecs
	insinto "/etc/init"
	doins "${FILESDIR}/udev-trigger-codec.conf"
	udev_dorules "${FILESDIR}/50-media.rules"
}
