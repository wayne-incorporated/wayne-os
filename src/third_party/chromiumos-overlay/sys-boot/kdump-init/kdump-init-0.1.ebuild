# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI="7"

DESCRIPTION="ChromeOS Kdump init files"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"

RDEPEND="sys-apps/kexec-lite"

src_install() {
	insinto /etc/init
	doins "${FILESDIR}/upstart/kdump-init.conf"

	insinto /etc/sysctl.d
	doins "${FILESDIR}"/20-kexec-limits.conf

	exeinto /usr/share/kdump
	doexe "${FILESDIR}/kdump-init.sh"
}
