# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit systemd

DESCRIPTION="ChromeOS scripts to periodically update machine-id"
HOMEPAGE="http://src.chromium.org"
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="systemd"

RDEPEND="
	>=sys-apps/dbus-1.6.8-r9
"

S="${WORKDIR}"

src_install() {
	# cros-machine-id-regen - http://crbug.com/431337
	dosbin "${FILESDIR}"/cros-machine-id-regen

	# Install init scripts.
	if use systemd; then
		systemd_dounit "${FILESDIR}"/*.service
		systemd_enable_service shill-disconnected.target cros-machine-id-regen-network.service
		systemd_dounit "${FILESDIR}"/cros-machine-id-regen-periodic.timer
		systemd_enable_service system-services.target cros-machine-id-regen-periodic.timer
	else
		insinto /etc/init
		doins "${FILESDIR}"/*.conf
	fi
}
