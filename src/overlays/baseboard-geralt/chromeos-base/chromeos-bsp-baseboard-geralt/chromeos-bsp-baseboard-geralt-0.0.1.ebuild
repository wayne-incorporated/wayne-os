# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
EAPI=7

inherit udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."
HOMEPAGE=""
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
S="${WORKDIR}"
IUSE=""

# Add dependencies on other ebuilds from within this board overlay
DEPEND="
	chromeos-base/chromeos-scp-firmware-geralt
"
RDEPEND="${DEPEND}"
BDEPEND=""

src_install() {
	# Override default CPUFreq governor
	insinto "/etc"
	doins "${FILESDIR}/cpufreq.conf"

	# Install udev rules for codecs
	insinto "/etc/init"
	doins "${FILESDIR}/udev-trigger-codec.conf"
	udev_dorules "${FILESDIR}/50-media.rules"
}
