# Copyright 1999-2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit pax-utils

# We build & install newer libs that this prebuilt needs to unblock the move from
# Python 2 to Python 3.  This tool is only used to bootstrap the real pypy3-exe,
# so bundling these libs isn't a problem in general.  It's not a pattern that we
# want to repeat though.
# TODO(cros-build): Upgrade libffi & ncurses in the SDK.
LIBFFI_PV="3.3"
NCURSES_PV="6.1"

MY_P=pypy3-exe-${PV}-1
DESCRIPTION="PyPy3 executable (pre-built version)"
HOMEPAGE="https://www.pypy.org/"
SRC_URI="
	https://github.com/libffi/libffi/releases/download/v${LIBFFI_PV}/libffi-${LIBFFI_PV}.tar.gz
	mirror://gnu/ncurses/ncurses-${NCURSES_PV}.tar.gz
	amd64? (
		https://dev.gentoo.org/~mgorny/binpkg/amd64/pypy/dev-python/pypy3-exe/${MY_P}.xpak
			-> ${MY_P}.amd64.xpak
	)
	x86? (
		https://dev.gentoo.org/~mgorny/binpkg/x86/pypy/dev-python/pypy3-exe/${MY_P}.xpak
			-> ${MY_P}.x86.xpak
	)"
S="${WORKDIR}"

LICENSE="MIT"
SLOT="${PV%_p*}"
KEYWORDS="*"

#	|| (
#		dev-libs/libffi-compat:7
#		dev-libs/libffi:0/7
#	)
#	sys-libs/ncurses:0/6
RDEPEND=">=sys-libs/zlib-1.1.3:0/1
	virtual/libintl:0/0
	dev-libs/expat:0/0
	app-arch/bzip2:0/1
	!dev-python/pypy-exe:${SLOT}"

PYPY_PV=${SLOT%_p*}
QA_PREBUILT="
	usr/bin/pypy3-c-${PYPY_PV}"

src_unpack() {
	ebegin "Unpacking ${MY_P}.${ARCH}.xpak"
	tar -x < <(xz -c -d --single-stream "${DISTDIR}/${MY_P}.${ARCH}.xpak")
	eend ${?} || die "Unpacking ${MY_P} failed"

	unpack libffi-${LIBFFI_PV}.tar.gz ncurses-${NCURSES_PV}.tar.gz
}

src_configure() {
	cd "${WORKDIR}"/ncurses-${NCURSES_PV} || die
	econf \
		--with-terminfo-dirs="${EPREFIX}/etc/terminfo:${EPREFIX}/usr/share/terminfo" \
		--with-shared \
		--without-hashed-db \
		--without-ada \
		--without-cxx \
		--without-cxx-binding \
		--with-cxx-shared \
		--without-debug \
		--without-profile \
		--without-gpm \
		--without-term-driver \
		--disable-termcap \
		--enable-symlinks \
		--with-rcs-ids \
		--without-manpages \
		--enable-const \
		--enable-colorfgbg \
		--enable-hard-tabs \
		--enable-echo \
		--enable-warnings \
		--without-assertions \
		--enable-leaks \
		--without-expanded \
		--with-macros \
		--without-progs \
		--without-tests \
		--without-trace \
		--with-termlib \
		--disable-stripping \
		--enable-widec &

	cd "${WORKDIR}"/libffi-${LIBFFI_PV} || die
	econf

	# If ncurses failed, econf will trigger die for us.
	wait
}

src_compile() {
	emake -C "${WORKDIR}"/ncurses-${NCURSES_PV}
	emake -C "${WORKDIR}"/libffi-${LIBFFI_PV}
}

src_install() {
	insinto /
	doins -r usr
	# Rename pypy3-c binary as .bin
	mv "${ED}/usr/lib/pypy3.6/pypy3-c-${PYPY_PV}"{,.bin}
	fperms +x "/usr/lib/pypy3.6/pypy3-c-${PYPY_PV}.bin"
	pax-mark m "${ED}/usr/lib/pypy3-c-${PYPY_PV}.bin"


	# Create loader script inside /usr/lib/pypy3.6
	# Use --argv0 since loader script is now located inside the
	# directory which also contains stdlibs.
	insinto "/usr/lib/pypy3.6"
	cat <<EOF | newins - "pypy3-c-${PYPY_PV}"
#!/bin/sh
exec /lib64/ld-linux-x86-64.so.2 \
	--library-path /usr/libexec/${PN} \
	--argv0 "\$0" \
	"/usr/lib/pypy3.6/pypy3-c-${PYPY_PV}.bin" "\$@"
EOF
	fperms +x "/usr/lib/pypy3.6/pypy3-c-${PYPY_PV}"

	# Create /usr/bin symlink to loader script under /usr/lib/pypy3.6
	dosym "/usr/lib/pypy3.6/pypy3-c-${PYPY_PV}" "/usr/bin/pypy3-c-${PYPY_PV}"

	exeinto /usr/libexec/${PN}

	cd "${WORKDIR}"/ncurses-${NCURSES_PV} || die
	doexe lib/lib{ncurses,tinfo}w.so.6

	cd "${WORKDIR}"/libffi-${LIBFFI_PV} || die
	emake install DESTDIR="${PWD}/root"
	doexe root/usr/*/libffi.so.7
}
