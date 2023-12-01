# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI="7"

DESCRIPTION="Ebuild for Android toolchain (compilers, linker, libraries, headers)."

# The source tarball contains files collected from the sources below.
#
#   # from ab/7274194
#   bertha_arm64-target_files-8467082.zip
#   bertha_x86_64-target_files-8467082.zip
#
#   # from ab/8466650
#   deapexer
#   debugfs_static
#
#   platform/bionic revision: 0d0b0441703b1371876a2afbc870096956305033
#
SRC_URI="http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/${P}.tar.gz"

LICENSE="GPL-3 LGPL-3 GPL-3 libgcc libstdc++ gcc-runtime-library-exception-3.1 FDL-1.2 UoI-NCSA"
SLOT="0"
KEYWORDS="-* amd64"
IUSE=""

# Block the internal arc-toolchain-t package
RDEPEND="
	sys-libs/ncurses:5
	sys-libs/readline:6
	!chromeos-base/arc-toolchain-t
"

S="${WORKDIR}"
INSTALL_DIR="/opt/android-t"

# These prebuilts are already properly stripped.
RESTRICT="strip"
QA_PREBUILT="*"

src_install() {
	dodir "${INSTALL_DIR}"
	cp -pPR ./* "${D}/${INSTALL_DIR}/" || die
}
