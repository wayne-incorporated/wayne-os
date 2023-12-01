# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit cros-constants

CROS_WORKON_COMMIT="630e05b6af5f76bd7f063840e543186bde40ff0a"
CROS_WORKON_TREE="42c814a9b71ac7619efa0d47b68cb55fef759095"
CROS_WORKON_MANUAL_UPREV=1
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform/core"
CROS_WORKON_PROJECT="platform/system/core"
CROS_WORKON_EGIT_BRANCH="master"
CROS_WORKON_REPO="${CROS_GIT_AOSP_URL}"

inherit cros-workon

DESCRIPTION="Library and cli tools for Android sparse files"
HOMEPAGE="https://android.googlesource.com/platform/system/core"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	sys-libs/zlib:=
"
DEPEND="${RDEPEND}"

src_unpack() {
	cros-workon_src_unpack
	S+="/${PN}"
}

src_prepare() {
	default
	cp "${FILESDIR}/Makefile" "${S}" || die "Copying Makefile"
}

src_configure() {
	export GENTOO_LIBDIR=$(get_libdir)
	tc-export CC
	default
}
