# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Utility to change the Mesa OpenGL driver being used"
HOMEPAGE="https://www.gentoo.org/"
SRC_URI="mirror://gentoo/${P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND=""
RDEPEND=">=app-admin/eselect-1.2.4"

src_install() {
	insinto /usr/share/eselect/modules
	doins mesa.eselect
}
