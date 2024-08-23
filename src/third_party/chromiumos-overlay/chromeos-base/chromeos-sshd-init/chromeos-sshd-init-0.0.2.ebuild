# Copyright 2014 The Chromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI="7"

DESCRIPTION="Install Chromium OS sshd Upstart file to a shared location."
HOMEPAGE="http://www.chromium.org/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}"

src_install() {
	exeinto /usr/share/chromeos-ssh-config
	doexe "${FILESDIR}"/sshd-pre
	doexe "${FILESDIR}"/sshd-post

	insinto /usr/lib/systemd/system/sshd.service.d
	doins "${FILESDIR}"/chromeos-sshd.conf

	insinto /usr/share/chromeos-ssh-config/init
	doins "${FILESDIR}"/openssh-server.conf

	insinto /etc/init
	doins "${FILESDIR}"/openssh-server.conf.README
}
