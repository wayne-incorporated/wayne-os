# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit udev

DESCRIPTION="Install power governor for chipset-cml"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
S="${WORKDIR}"

src_install() {
	# Install a rule to switch to performance mode on AC
	# and powersave mode on Battery.
	udev_dorules "${FILESDIR}"/*.rules

	insinto /etc
	doins "${FILESDIR}"/cpufreq.conf
}
