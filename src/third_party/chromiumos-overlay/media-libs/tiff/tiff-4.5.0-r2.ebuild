# Copyright 1999-2023 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# shellcheck disable=SC2034
QA_PKGCONFIG_VERSION="$(ver_cut 1-3)"

inherit autotools multilib-minimal libtool flag-o-matic

MY_P="${P/_rc/rc}"
DESCRIPTION="Tag Image File Format (TIFF) library"
HOMEPAGE="http://libtiff.maptools.org"
SRC_URI="https://download.osgeo.org/libtiff/${MY_P}.tar.xz"
SRC_URI+=" verify-sig? ( https://download.osgeo.org/libtiff/${MY_P}.tar.xz.sig )"
S="${WORKDIR}/${PN}-$(ver_cut 1-3)"

LICENSE="libtiff"
SLOT="0/6"
if [[ ${PV} != *_rc* ]] ; then
	KEYWORDS="*"
fi
IUSE="cros_host +cxx jbig jpeg lzma static-libs test verify-sig webp zlib zstd"
RESTRICT="!test? ( test )"

# bug #483132
REQUIRED_USE="test? ( jpeg )"

RDEPEND="jbig? ( >=media-libs/jbigkit-2.1:=[${MULTILIB_USEDEP}] )
	jpeg? ( media-libs/libjpeg-turbo:=[${MULTILIB_USEDEP}] )
	lzma? ( >=app-arch/xz-utils-5.0.5-r1[${MULTILIB_USEDEP}] )
	webp? ( media-libs/libwebp:=[${MULTILIB_USEDEP}] )
	zlib? ( >=sys-libs/zlib-1.2.8-r1[${MULTILIB_USEDEP}] )
	zstd? ( >=app-arch/zstd-1.3.7-r1:=[${MULTILIB_USEDEP}] )"
DEPEND="${RDEPEND}"
BDEPEND="verify-sig? ( sec-keys/openpgp-keys-evenrouault )"

MULTILIB_WRAPPED_HEADERS=(
	/usr/include/tiffconf.h
)

PATCHES=(
	"${FILESDIR}"/${PN}-4.5.0_rc1-skip-tools-tests-multilib.patch
	"${FILESDIR}"/${PN}-4.5.0-CVE-2022-48281.patch
	"${FILESDIR}"/${PN}-4.5.0-CVE-2023-0795-CVE-2023-0796-CVE-2023-0797-CVE-2023-0798-CVE-2023-0799.patch
	"${FILESDIR}"/${PN}-4.5.0-CVE-2023-0800-CVE-2023-0801-CVE-2023-0802-CVE-2023-0803-CVE-2023-0804.patch
)

src_prepare() {
	default
	# ChromeOS: generate configure script since we aren't using the pre-configured tar.gz
	eautoreconf
	elibtoolize
}

multilib_src_configure() {
	append-lfs-flags

	local myeconfargs=(
		--disable-sphinx
		--without-x
		--with-docdir="${EPREFIX}"/usr/share/doc/${PF}
		$(use_enable cxx)
		$(use_enable jbig)
		$(use_enable jpeg)
		$(use_enable lzma)
		$(use_enable static-libs static)
		$(use_enable webp)
		$(use_enable zlib)
		$(use_enable zstd)
		--disable-docs
	)

	# ChromeOS: install utilities to /usr/local unless installing to the SDK.
	if ! use cros_host ; then
		myeconfargs+=( --bindir="${EPREFIX}/usr/local/bin" )
	fi

	ECONF_SOURCE="${S}" econf "${myeconfargs[@]}"

	# Remove components (like tools) that are irrelevant for the multilib
	# build which we only want libraries for.
	# TODO: upstream options to disable these properly
	if ! multilib_is_native_abi ; then
		sed -i \
			-e 's/ tools//' \
			-e 's/ contrib//' \
			-e 's/ man//' \
			-e 's/ html//' \
			Makefile || die
	fi
}

multilib_src_test() {
	if ! multilib_is_native_abi ; then
		emake -C tools
	fi

	emake check
}

multilib_src_install_all() {
	find "${ED}" -type f -name '*.la' -delete || die
	# ChromeOS: COPYRIGHT doesn't exist in the top-of-tree version of libtiff.
	rm -f "${ED}"/usr/share/doc/${PF}/{README*,RELEASE-DATE,TODO,VERSION} || die
}
