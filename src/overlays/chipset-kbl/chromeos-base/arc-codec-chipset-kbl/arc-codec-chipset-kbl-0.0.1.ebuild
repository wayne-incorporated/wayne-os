# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit arc-build-constants

DESCRIPTION="Install codec configuration for ARC++"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"
RDEPEND="!chromeos-base/arc-codec-software"

src_install() {
	arc-build-constants-configure
	insinto "${ARC_CONTAINER_VENDOR_DIR}/etc"
	doins "${FILESDIR}"/pic/*
}
