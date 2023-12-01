# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="87084d72d466cc7b6089d56b7c553c4e2ded0f00"
CROS_WORKON_TREE="3792c938b9ab462546a4620952b72cdb584c8896"
CROS_WORKON_PROJECT="chromiumos/third_party/libqrtr-glib"

inherit meson cros-sanitizers cros-workon

DESCRIPTION="QRTR modem protocol helper library"
# TODO(andrewlassalle): replace the homepage once one is created.
HOMEPAGE="https://gitlab.freedesktop.org/mobile-broadband/libqrtr-glib"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND=">=dev-libs/glib-2.36:2"
BDEPEND="virtual/pkgconfig"
DEPEND="${RDEPEND}"

src_configure() {
	sanitizers-setup-env

	local emesonargs=(
		--prefix='/usr'
		-Dlibexecdir='/usr/libexec'
		-Dgtk_doc=false
		-Dintrospection=false
	)
	meson_src_configure
}
