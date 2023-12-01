# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=7
CROS_WORKON_COMMIT="12f0f0058b96030226951a1bc4986bddc9be669d"
CROS_WORKON_TREE="09ade29a3cc0d1229226f34dba708d69d6c638dd"
CROS_WORKON_PROJECT="chromiumos/platform/jabra_vold"
CROS_WORKON_LOCALNAME="jabra_vold"

inherit cros-workon toolchain-funcs udev user

DESCRIPTION="A simple daemon to handle Jabra speakerphone volume change"
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="*"

COMMON_DEPEND=">=media-libs/alsa-lib-1.0:="
RDEPEND="${COMMON_DEPEND}"
DEPEND="${COMMON_DEPEND}"

src_compile() {
	tc-export CC PKG_CONFIG

	emake
}

src_install() {
	dosbin jabra_vold

	udev_dorules 99-jabra{,-usbmon}.rules
}

pkg_preinst() {
	enewuser "volume"
	enewgroup "volume"
}
