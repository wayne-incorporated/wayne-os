# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit appid
inherit cros-unibuild

DESCRIPTION="Pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE="grunt-arc-r grunt-kernelnext"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	!<chromeos-base/gestures-conf-0.0.2
	chromeos-base/chromeos-bsp-baseboard-grunt
	chromeos-base/chromeos-config
	chromeos-base/touch_updater
"
DEPEND="${RDEPEND}"

src_install() {
	insinto "/etc/gesture"
	doins "${FILESDIR}"/gesture/*

	if use grunt-arc-r; then
		doappid "{602B22F1-BA1A-443E-9C4B-389E513DF9C0}" "CHROMEBOOK"
	elif use grunt-kernelnext; then
		doappid "{F7007D90-E551-11E9-B865-1F6941885301}" "CHROMEBOOK"
	else
		doappid "{9496CDE8-85E6-4118-960F-E26DC0C69FD6}" "CHROMEBOOK"
	fi

	unibuild_install_files audio-files
	unibuild_install_touch_files

	# Install platform-specific bluetooth sysprops.
	insinto "/etc/bluetooth/sysprops.conf.d"
	insopts -m0640
	doins "${FILESDIR}/grunt-bluetooth-sysprops.conf"
	insopts -m0644
}
