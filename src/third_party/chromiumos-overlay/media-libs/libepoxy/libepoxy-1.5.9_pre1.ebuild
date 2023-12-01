# Copyright 1999-2017 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI=7

EGIT_REPO_URI="git://github.com/anholt/libepoxy.git"

GIT_SHA1="ecfa8e0f083084181d36966fa084aca9a6c97d53"

if [[ ${PV} = 9999* ]]; then
	GIT_ECLASS="git-r3"
	KEYWORDS="*"
	SRC_URI=""
else
	KEYWORDS="*"
	SRC_URI="https://github.com/anholt/${PN}/archive/${GIT_SHA1}.tar.gz -> ${P}.tar.gz"
fi

# Uncomment the following line temporarily to update the manifest when updating
# the pinned version via: ebuild $(equery w libepoxy) manifest
#RESTRICT=mirror

PYTHON_COMPAT=( python3_{6,7,8,9} )
PYTHON_REQ_USE='xml(+)'
inherit meson ${GIT_ECLASS} python-any-r1

DESCRIPTION="Epoxy is a library for handling OpenGL function pointer management for you"
HOMEPAGE="https://github.com/anholt/libepoxy"


LICENSE="MIT"
SLOT="0"
IUSE="test"

DEPEND="${PYTHON_DEPS}
	x11-drivers/opengles-headers
	x11-misc/util-macros
	x11-libs/libX11"
RDEPEND="virtual/opengles"

src_unpack() {
	default
	[[ ${PV} = 9999* ]] && git-r3_src_unpack
}

src_configure() {
	local emesonargs=(
		-Dtests=false
	)
	meson_src_configure
}
