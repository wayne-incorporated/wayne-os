# Copyright 2017 The Chromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI="5"

inherit user

DESCRIPTION="Run sslh on port 22 to multiplex adb/ssh connections"
HOMEPAGE="http://www.chromium.org/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="!<chromeos-base/chromeos-sshd-init-0.0.2
	chromeos-base/minijail
"

DEPEND="${RDEPEND}"

S="${WORKDIR}"

src_install() {
	insinto /etc
	doins "${FILESDIR}"/sslh.conf

	insinto /etc/init
	doins "${FILESDIR}"/upstart/*

	insinto /usr/share/policy
	newins "${FILESDIR}/sslh-seccomp-${ARCH}.policy" sslh-seccomp.policy
}

pkg_preinst() {
	enewuser "sslh"
	enewgroup "sslh"
}
