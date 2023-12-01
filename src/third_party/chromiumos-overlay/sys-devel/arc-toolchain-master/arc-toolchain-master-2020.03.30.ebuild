# Copyright 1999-2017 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI="7"

DESCRIPTION="Ebuild for Android toolchain (compilers, linker, libraries, headers)."

# The source tarball contains files collected from the sources below.
#
#   # from ab/6322724
#   cheets_arm64-target_files-6322724.zip
#   cheets_x86_64-target_files-6322724.zip
#
SRC_URI="http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/${P}.tar.gz"

LICENSE="GPL-3 LGPL-3 GPL-3 libgcc libstdc++ gcc-runtime-library-exception-3.1 FDL-1.2 UoI-NCSA"
SLOT="0"
KEYWORDS="-* amd64"
IUSE=""

RDEPEND="sys-libs/ncurses:5
	sys-libs/readline:6"

S="${WORKDIR}"
INSTALL_DIR="/opt/android-master"

# These prebuilts are already properly stripped.
RESTRICT="strip"
QA_PREBUILT="*"

src_install() {
	dodir "${INSTALL_DIR}"
	cp -pPR ./* "${D}/${INSTALL_DIR}/" || die
}
