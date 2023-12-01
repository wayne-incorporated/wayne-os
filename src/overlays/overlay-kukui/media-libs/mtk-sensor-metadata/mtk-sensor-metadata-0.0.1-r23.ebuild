# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

DESCRIPTION="MediaTek sensor metadata required by the MediaTek camera HAL"

LICENSE="LICENCE.mediatek"
SLOT="0"
KEYWORDS="-* arm arm64"

S="${WORKDIR}"

src_install() {
	local INCLUDE_DIR="/usr/include/cros-camera/custom"
	insinto "${INCLUDE_DIR}"
	doins -r "${FILESDIR}"/*
}
