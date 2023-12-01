# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit toolchain-funcs eutils

DESCRIPTION="Dump capabilities of VA-API device/driver"
HOMEPAGE="https://github.com/fhvwy/vadumpcaps"

GIT_SHA1="fb4dfef76c0fa08f853af377d5d4945d5fb3001c"
SRC_URI="https://github.com/fhvwy/vadumpcaps/archive/${GIT_SHA1}.tar.gz -> ${P}.tar.gz"

DOCS="README.md"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	>=x11-libs/libva-2.1.0
	>=x11-libs/libdrm-2.4"

DEPEND="${RDEPEND}
	virtual/pkgconfig"

src_prepare() {
	epatch "${FILESDIR}"/avoid_using_VAProcFilterHighDynamicRangeToneMapping.patch
	epatch "${FILESDIR}"/do_not_use_shell_pkg-config.patch
	default
}

src_compile() {
	append-ldflags "$($(tc-getPKG_CONFIG) --libs libva-drm libva)"
	emake vadumpcaps
}

src_install () {
	dobin vadumpcaps
}
