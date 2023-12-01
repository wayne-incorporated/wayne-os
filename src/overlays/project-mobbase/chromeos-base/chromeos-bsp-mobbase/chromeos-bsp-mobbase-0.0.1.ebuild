# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="4"

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies or portage actions"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

# These packages are meant to set up the Chromium OS Basic environment to
# properly handle the services required by all mobbase infrastructure projects.
RDEPEND="
	chromeos-base/chromeos-init
	virtual/chromeos-test-testauthkeys
"

DEPEND=""

S=${WORKDIR}

src_install() {
	insinto /etc/init
	doins "${FILESDIR}"/init/*.conf

	insinto "/usr/share/power_manager/board_specific"
	doins "${FILESDIR}"/powerd_prefs/*

	# TODO (crbug.com/348172) - This is a temporary fix to not wipe
	# stateful when booting off USB as a base image.
	dodir "/mnt/stateful_partition"
	touch "${D}/mnt/stateful_partition/.developer_mode"
}
