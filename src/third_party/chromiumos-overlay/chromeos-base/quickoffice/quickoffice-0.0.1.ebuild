# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Initialization files for Quickoffice on Chrome OS"
HOMEPAGE="https://www.chromium.org"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
S="${WORKDIR}"


src_install() {
	local qo_install_root="/usr/share/chromeos-assets/quickoffice"
	insinto /etc/init
	# Create the directory where the Quickoffice squashfs will be mounted.
	keepdir "${qo_install_root}"/_platform_specific

	# Upstart script that will automatically mount/unmount the Quickoffice
	# squashfs when the device starts/stops
	doins "${FILESDIR}/quickoffice.conf"
}
