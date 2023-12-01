# Copyright 2012 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit systemd

DESCRIPTION="Install the upstart job that launches the openssh-server."
HOMEPAGE="https://dev.chromium.org/chromium-os"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="systemd"

S=${WORKDIR}

RDEPEND="
	chromeos-base/chromeos-sshd-init
	net-misc/openssh
	virtual/chromeos-firewall
"

src_install() {
	if use systemd; then
		systemd_enable_service multi-user.target sshd.service
	else
		dosym /usr/share/chromeos-ssh-config/init/openssh-server.conf \
		      /etc/init/openssh-server.conf
	fi
}
