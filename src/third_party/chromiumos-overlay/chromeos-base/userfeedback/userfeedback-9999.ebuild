# Copyright 2010 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_DESTDIR="${S}"
CROS_WORKON_SUBTREE="userfeedback"

inherit cros-workon systemd

DESCRIPTION="Log scripts used by userfeedback to report cros system information"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/userfeedback/"

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="~*"
IUSE="systemd"

RDEPEND="chromeos-base/chromeos-init
	chromeos-base/crash-reporter
	chromeos-base/modem-utilities
	chromeos-base/vboot_reference
	media-libs/fontconfig
	media-sound/alsa-utils
	sys-apps/coreboot-utils
	sys-apps/net-tools
	sys-apps/pciutils
	sys-apps/usbutils"

DEPEND=""

src_unpack() {
	cros-workon_src_unpack
	S+="/userfeedback"
}

src_install() {
	exeinto /usr/share/userfeedback/scripts
	doexe scripts/*

	# Install init scripts.
	if use systemd; then
		local units=("firmware-version.service")
		systemd_dounit init/*.service
		for unit in "${units[@]}"; do
			systemd_enable_service system-services.target ${unit}
		done
	else
		insinto /etc/init
		doins init/*.conf
	fi
}
