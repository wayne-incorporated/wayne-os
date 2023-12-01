# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="6"

inherit toolchain-funcs

SEPOL_VER="2.7"

DESCRIPTION="SELinux policy compiler"
HOMEPAGE="http://userspace.selinuxproject.org"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"

SRC_URI="https://android.googlesource.com/platform/system/sepolicy/+archive/refs/tags/android-cts-9.0_r7/tools/sepolicy-analyze.tar.gz -> ${P}.tar.gz"
S="${WORKDIR}"

DEPEND=">=sys-libs/libsepol-${SEPOL_VER}"

src_compile() {
	"$(tc-getCC)" *.c -lsepol -static ${CFLAGS} ${LDFLAGS} -o sepolicy-analyze
}

src_install() {
	dobin sepolicy-analyze
}

