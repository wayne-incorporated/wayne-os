# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

DESCRIPTION="MediaTek config files required by the MediaTek camera HAL"

LICENSE="LICENCE.mediatek"
SLOT="0"
KEYWORDS="-* arm arm64"

RDEPEND="!media-libs/mtk-hal-config"

S="${WORKDIR}"

IUSE="kernel-5_10"

src_install() {
	local kernel=$(usex kernel-5_10 5_10 4_19)
	local CONFIG_DIR="/etc/camera"
	insinto "${CONFIG_DIR}"
	doins "${FILESDIR}"/*.json

	newins "${FILESDIR}/post-start-hooks-${kernel}.sh" post-start-hooks.sh
	newins "${FILESDIR}/post-start-hooks-algo-${kernel}.sh" post-start-hooks-algo.sh

	doins "${FILESDIR}/setup-hooks-algo.sh"
	doins "${FILESDIR}/setup-hooks.sh"
}
