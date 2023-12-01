# Copyright 1999-2017 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=5

DESCRIPTION="Install OEM specific data for Genius app"
HOMEPAGE=""
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE=""
S=${WORKDIR}

DEPEND="!chromeos-base/genius-app-oem"
RDEPEND="${DEPEND}"

src_install() {
		insinto "/usr/share/chromeos-assets/genius_app/embedded_device_content"

		doins -r "${FILESDIR}"/*
}
