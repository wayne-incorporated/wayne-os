# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit cros-common.mk cros-debug flag-o-matic

DESCRIPTION="YUV library"
HOMEPAGE="https://chromium.googlesource.com/libyuv/libyuv"
GIT_SHA1="b9adaef1133ee835efc8970d1dcdcf23a5b68eba"
SRC_URI="https://chromium.googlesource.com/libyuv/libyuv/+archive/${GIT_SHA1}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

DEPEND="virtual/jpeg:0"

RDEPEND="${DEPEND}"

S="${WORKDIR}"

src_unpack() {
	append-lfs-flags

	default
	cp -a "${FILESDIR}"/* "${S}"/ || die
}

src_install() {
	insinto /usr/include
	doins -r include/*

	dolib.a libyuv.pic.a

	insinto "/usr/$(get_libdir)/pkgconfig"
	sed -e "s:@LIB@:$(get_libdir):g" libyuv.pc.in | newins - libyuv.pc
}
