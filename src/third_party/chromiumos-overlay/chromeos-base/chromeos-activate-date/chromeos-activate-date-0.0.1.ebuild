# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit systemd

DESCRIPTION="Chrome OS activate date mechanism"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="systemd"

RDEPEND="
	!<chromeos-base/chromeos-bsp-spring-private-0.0.1-r15
	!<chromeos-base/chromeos-bsp-pit-private-0.0.1-r11
	!<chromeos-base/chromeos-bsp-daisy-private-0.0.1-r26
	!<chromeos-base/chromeos-bsp-alex-0.0.1-r11
	!<chromeos-base/chromeos-bsp-lumpy-private-0.0.5-r22
	!<chromeos-base/chromeos-bsp-lumpy-0.0.5-r14
	!<chromeos-base/chromeos-bsp-stumpy-0.0.3-r8
"

S=${WORKDIR}

src_install() {
	dosbin "${FILESDIR}/activate_date"

	if use systemd; then
		systemd_dounit "${FILESDIR}/activate_date.service"
		systemd_enable_service system-services.target activate_date.service
	else
		insinto "/etc/init"
		doins "${FILESDIR}/activate_date.conf"
	fi
	exeinto /usr/share/cros/init
	doexe "${FILESDIR}/activate_date.sh"
}
