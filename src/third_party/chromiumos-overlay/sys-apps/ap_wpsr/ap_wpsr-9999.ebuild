# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
# $Header:

EAPI=7
CROS_WORKON_PROJECT="chromiumos/third_party/ap_wpsr"

inherit cros-workon toolchain-funcs meson cros-sanitizers

DESCRIPTION="Utility for generating AP WP masks and values"
HOMEPAGE=""
SRC_URI=""

LICENSE="GPL-2"
SLOT="0/0"
KEYWORDS="~*"
IUSE=""

RDEPEND=""
DEPEND=""

src_configure() {
	sanitizers-setup-env
	meson_src_configure
}

src_install() {
	meson_src_install
}

src_test() {
	meson_src_test
}
