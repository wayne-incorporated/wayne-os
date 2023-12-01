# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="4"

DESCRIPTION="Install Chromium OS test public keys for ssh clients on test image"
HOMEPAGE="http://www.chromium.org/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}"

RDEPEND="
	chromeos-base/chromeos-ssh-testkeys
"

src_install() {
	local filenames=(
		authorized_keys
		id_rsa
		id_rsa.pub
	)
	local filename

	for filename in "${filenames[@]}"; do
		dosym /usr/share/chromeos-ssh-config/keys/"${filename}" \
		      /root/.ssh/"${filename}"
	done
}
