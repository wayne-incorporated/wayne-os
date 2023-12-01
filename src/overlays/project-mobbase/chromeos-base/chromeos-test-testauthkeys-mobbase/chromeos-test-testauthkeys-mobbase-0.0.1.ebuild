# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="4"

DESCRIPTION="Install Chromium OS test public keys for root user outbound SSH."
HOMEPAGE="http://www.chromium.org/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}"

RDEPEND="
	chromeos-base/chromeos-ssh-testkeys
	!chromeos-base/chromeos-test-testauthkeys-moblab
"

src_install() {
	# Sets up the outbound SSH access for root user.
	insinto /root/.ssh
	newins "${EROOT}"/usr/share/chromeos-ssh-config/keys/id_rsa \
		mobbase_id_rsa
	newins "${FILESDIR}"/ssh_config config
	fperms 600 /root/.ssh/config
	fperms 600 /root/.ssh/mobbase_id_rsa
}
