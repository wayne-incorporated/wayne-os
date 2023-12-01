# Copyright 1999-2011 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/x11-libs/libXft/libXft-2.2.0.ebuild,v 1.10 2011/02/14 23:22:40 xarthisius Exp $

EAPI=4
inherit xorg-2 flag-o-matic

DESCRIPTION="X.Org Xft library"

KEYWORDS="*"
IUSE=""

RDEPEND=">=x11-libs/libXrender-0.8.2
	x11-libs/libX11
	x11-libs/libXext
	media-libs/freetype
	media-libs/fontconfig
	x11-proto/xproto"
DEPEND="${RDEPEND}"

PATCHES=( "${FILESDIR}/${PN}-2.3.1-compile_fix.patch" )
