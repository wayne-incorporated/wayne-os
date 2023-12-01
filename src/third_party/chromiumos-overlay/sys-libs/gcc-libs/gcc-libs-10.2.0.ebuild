# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/sys-devel/gcc/gcc-4.4.3-r3.ebuild,v 1.1 2010/06/19 01:53:09 zorry Exp $

# TODO(b/234782625): This package is empty as no GCC libraries are installed
# to devices. It should be removed once all dependencies
# on it are removed.

EAPI=7

DESCRIPTION="The GNU Compiler Collection. This builds and installs the libgcc, libstdc++, and libgo libraries.  It is board-specific."
SRC_URI=""

LICENSE="GPL-3 LGPL-3 FDL-1.2"
SLOT="0"
KEYWORDS="*"
if [[ "${PV}" == "9999" ]]; then
	KEYWORDS="~*"
fi
IUSE="go hardened hardfp libatomic +thumb vtable_verify +libunwind"

RDEPEND=""
DEPEND=""
