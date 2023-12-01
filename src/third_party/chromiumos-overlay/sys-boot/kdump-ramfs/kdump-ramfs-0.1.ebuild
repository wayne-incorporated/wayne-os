# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="u-root based ramfs for kdump"

# u-root + lvm2 licenses.
LICENSE="GPL-2 BSD-2 LGPL-2.1 BSD"
SLOT="0"
KEYWORDS="*"

BDEPEND="dev-go/u-root"
DEPEND="
	sys-fs/lvm2
	sys-apps/makedumpfile
"
S="${WORKDIR}"

UROOTGOPATH="/usr/share/u-root"
UROOTDIR="${UROOTGOPATH}/src/github.com/u-root/u-root"

src_compile() {
	# Build u-root image.
	export GOARCH="${ARCH}"
	export GO111MODULE="off"
	export GOPATH=$(go env GOPATH):"${UROOTGOPATH}"
	UROOTCMDS="core"
	LVM="${SYSROOT}/sbin/lvm:/sbin/lvm"
	MAKEDUMPFILE="${SYSROOT}/usr//sbin/makedumpfile:/usr/sbin/makedumpfile"
	u-root -uroot-source "${UROOTDIR}" -o kdump-rfs.cpio -files "${LVM}" -files "${MAKEDUMPFILE}" ${UROOTCMDS} || die
}

src_install() {
	insinto /usr/share/kdump/boot
	doins kdump-rfs.cpio
}
