# Copyright 1999-2020 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit autotools toolchain-funcs multilib flag-o-matic usr-ldscript

DESCRIPTION="Light-weight 'standard library' of C functions"
HOMEPAGE="https://launchpad.net/libnih"
SRC_URI="https://launchpad.net/${PN}/$(ver_cut 1-2)/${PV}/+download/${P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE="+dbus nls static-libs +threads"

# The configure phase will check for valgrind headers, and the tests will use
# that header, but only to do dynamic valgrind detection.  The tests aren't
# run directly through valgrind, only by developers directly.  So don't bother
# depending on valgrind here. #559830
RDEPEND="dbus? ( dev-libs/expat >=sys-apps/dbus-1.2.16 )"
DEPEND="${RDEPEND}
	sys-devel/gettext
	virtual/pkgconfig"
PATCHES=(
	"${FILESDIR}"/${P}-optional-dbus.patch
	"${FILESDIR}"/${P}-pkg-config.patch
	"${FILESDIR}"/${P}-signal-race.patch
	"${FILESDIR}"/${P}-fno-common.patch
	"${FILESDIR}"/${P}-expat-2.2.5.patch
	"${FILESDIR}"/${P}-glibc-2.24.patch
	"${FILESDIR}"/${P}-fix-assert-not-reach-logic.patch
	"${FILESDIR}"/${P}-fix-test-to-reflect-changes-in-outputs.patch
	"${FILESDIR}"/${P}-test_main-Disable-textdomain-test.patch
	"${FILESDIR}"/${P}-avoid-a-nih_assert-var-NULL-on-empty-null-ter.patch
	"${FILESDIR}"/${P}-Update-tests-for-previous-change.patch
	"${FILESDIR}"/${P}-Before-iterating-through-an-array-check-that-it-s-no.patch
	"${FILESDIR}"/${P}-Update-tests.patch
	"${FILESDIR}"/${P}-Update-test_method-too.patch
	"${FILESDIR}"/${P}-test_option-Remove-check-for-EOF.patch
)

src_prepare() {
	default
	eautoreconf
}

src_configure() {
	append-lfs-flags
	econf \
		$(use_with dbus) \
		$(use_enable nls) \
		$(use_enable static-libs static) \
		$(use_enable threads) \
		$(use_enable threads threading)
}

src_install() {
	default

	# we need to be in / because upstart needs libnih
	gen_usr_ldscript -a nih "$(use dbus && echo nih-dbus)"
	use static-libs || rm "${ED}/usr/$(get_libdir)/*.la"
}

src_test() {
	if ! use x86 && ! use amd64; then
		ewarn "Skipping unittests for non-native arches"
		return
	fi
	default
}
