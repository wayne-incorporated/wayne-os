# Copyright 1999-2013 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI=5

FINDLIB_USE="ocaml"

inherit findlib eutils multilib toolchain-funcs java-pkg-opt-2 flag-o-matic \
	autotools udev user cros-sanitizers

DESCRIPTION="Daemon that provides access to the Linux/Unix console for a blind person"
HOMEPAGE="http://brltty.app/"
SRC_URI="http://brltty.app/archive/${P}.tar.xz"

LICENSE="GPL-2 LGPL-2.1"
SLOT="0"
KEYWORDS="*"
IUSE="+api +beeper bluetooth +contracted-braille +fm gpm iconv icu
		java +midi ncurses nls ocaml +pcm python usb +speech
		tcl X"
REQUIRED_USE="
	java? ( api )
	ocaml? ( api )
	python? ( api )
	tcl? ( api )
"

COMMON_DEP="bluetooth? ( net-wireless/bluez )
	gpm? ( >=sys-libs/gpm-1.20 )
	iconv? ( virtual/libiconv )
	icu? ( dev-libs/icu )
	ncurses? ( sys-libs/ncurses )
	nls? ( virtual/libintl )
	python? ( >=dev-python/cython-0.16 )
	tcl? ( >=dev-lang/tcl-8.4.15 )
	usb? ( virtual/libusb:0 )
	X? ( x11-libs/libXaw )"
DEPEND="virtual/pkgconfig
	java? ( >=virtual/jdk-1.4 )
	${COMMON_DEP}"
RDEPEND="java? ( >=virtual/jre-1.4 )
	${COMMON_DEP}"

PATCHES=(
	"${FILESDIR}/${PN}-6.3-configure.ac-fix-LD-STRIP-and-RANLIB-hardcoding.patch"
)

src_prepare() {
	java-pkg-opt-2_src_prepare

	epatch "${FILESDIR}/${PN}-6.3-configure.ac-fix-LD-STRIP-and-RANLIB-hardcoding.patch"

	# The code runs `pkg-config` directly instead of locating a suitable
	# pkg-config wrapper (or respecting $PKG_CONFIG).
	sed -i \
		-e 's/\<pkg-config\>/${PKG_CONFIG:-pkg-config}/' \
		aclocal.m4 configure.ac || die

	# We run eautoconf instead of using eautoreconf because brltty uses
	# a custom build system that uses autoconf without the rest of the
	# autotools.
	eautoconf
}

src_configure() {
	sanitizers-setup-env
	tc-export AR LD PKG_CONFIG
	# override prefix in order to install into /
	# braille terminal needs to be available as soon in the boot process as
	# possible
	# Also override localstatedir so that the lib/brltty directory is installed
	# correctly.
	# Disable stripping since we do that ourselves.
	# Change the directory for the api unix socket from its default
	# (under /var/lib) to a location under /run because the latter
	# is backed by tmpfs.
	local myconf=(
		--prefix=/
		--includedir=/usr/include
		--localstatedir=/var
		--disable-stripping
		--without-attributes-table
		--without-text-table
		--with-install-root="${D}"
		--with-writable-directory=/run/brltty
		--with-api-socket-path=/run/brltty/BrlAPI
		$(use_enable api)
		$(use_with beeper beep-package)
		$(use_enable contracted-braille)
		$(use_with fm fm-package)
		$(use_enable gpm)
		$(use_enable iconv)
		$(use_enable icu)
		$(use_enable java java-bindings)
		$(use_enable python python-bindings)
		$(use_with midi midi-package)
		$(use_enable nls i18n)
		$(use_enable ocaml ocaml-bindings)
		$(use_with pcm pcm-package)
		$(use_enable speech speech-support)
		$(use_enable tcl tcl-bindings)
		$(use_enable X x)
		$(use_with bluetooth bluetooth-package)
		$(use_with ncurses curses)
		$(use_with usb usb-package) )

	econf "${myconf[@]}"
}

src_compile() {
	local JAVAC_CONF=""
	local OUR_JNI_FLAGS=""
	if use java; then
		OUR_JNI_FLAGS="$(java-pkg_get-jni-cflags)"
		JAVAC_CONF="${JAVAC} -encoding UTF-8 $(java-pkg_javac-args)"
	fi

	# workaround for parallel build failure, bug #340903.
	emake JAVA_JNI_FLAGS="${OUR_JNI_FLAGS}" JAVAC="${JAVAC_CONF}"
}

src_install() {
	# TODO(https://crbug.com/1336815): remove workaround when bug is fixed.
	dodir /bin

	if use ocaml; then
		findlib_src_preinst
	fi

	emake OCAML_LDCONF= install

	if use java; then
		# make install puts the _java.so there, and no it's not $(get_libdir)
		rm -rf "${D}/usr/lib/java"
		java-pkg_doso Bindings/Java/libbrlapi_java.so
		java-pkg_dojar Bindings/Java/brlapi.jar
	fi

	insinto /etc
	doins Documents/brltty.conf
	udev_newrules Autostart/Udev/device.rules 70-brltty-device.rules
	udev_newrules Autostart/Udev/uinput.rules 70-brltty-uinput.rules
	newinitd "${FILESDIR}"/brltty.rc brltty

	libdir="$(get_libdir)"
	mkdir -p "${D}"/usr/${libdir}/
	mv "${D}"/${libdir}/*.a "${D}"/usr/${libdir}/
	gen_usr_ldscript libbrlapi.so

	insinto /etc/init
	doins "${FILESDIR}"/etc/init/brltty.conf
	insinto /etc/dbus-1/system.d
	doins "${FILESDIR}"/etc/dbus-1/org.chromium.Brltty.conf
}

pkg_preinst() {
	enewgroup brltty
	enewuser brltty
}
