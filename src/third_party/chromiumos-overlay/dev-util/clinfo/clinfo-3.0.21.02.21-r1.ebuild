# Copyright 1999-2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

if [[ ${PV} == "9999" ]] ; then
	EGIT_REPO_URI="https://github.com/Oblomov/clinfo.git"
	inherit git-r3
	SRC_URI=""
else
	SRC_URI="https://github.com/Oblomov/clinfo/archive/${PV}.tar.gz -> ${P}.tar.gz"
	KEYWORDS="*"
fi

DESCRIPTION="A tool to display info about the system's OpenCL capabilities"
HOMEPAGE="https://github.com/Oblomov/clinfo"
LICENSE="CC0-1.0"
SLOT="0"

DEPEND=">=media-libs/clvk-0.0.1"
RDEPEND="${DEPEND}"

src_install() {
	emake MANDIR="${ED}"/usr/share/man PREFIX="${ED}"/usr install
}
