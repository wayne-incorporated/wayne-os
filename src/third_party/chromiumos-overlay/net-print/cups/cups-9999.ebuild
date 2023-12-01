# Copyright 1999-2016 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI=7

CROS_WORKON_PROJECT="chromiumos/third_party/cups"
CROS_WORKON_EGIT_BRANCH="chromeos"

inherit cros-debug cros-workon autotools flag-o-matic multilib multilib-minimal pam user systemd toolchain-funcs cros-fuzzer cros-sanitizers tmpfiles

MY_P=${P/_rc/rc}
MY_P=${MY_P/_beta/b}
MY_PV=${PV/_rc/rc}
MY_PV=${MY_PV/_beta/b}

KEYWORDS="~*"

DESCRIPTION="The Common Unix Printing System"
HOMEPAGE="http://www.cups.org/"

LICENSE="Apache-2.0"
IUSE="acl dbus debug kerberos pam
	+seccomp selinux +ssl static-libs systemd test +threads upstart usb X xinetd zeroconf
	asan fuzzer"

CDEPEND="
	app-text/libpaper
	acl? (
		kernel_linux? (
			sys-apps/acl
			sys-apps/attr
		)
	)
	dbus? ( >=sys-apps/dbus-1.6.18-r1[${MULTILIB_USEDEP}] )
	kerberos? ( >=virtual/krb5-0-r1[${MULTILIB_USEDEP}] )
	!net-print/lprng
	pam? ( virtual/pam )
	ssl? (
		>=dev-libs/libgcrypt-1.5.3:0=[${MULTILIB_USEDEP}]
		>=net-libs/gnutls-2.12.23-r6:=[${MULTILIB_USEDEP}]
	)
	systemd? ( sys-apps/systemd )
	usb? ( virtual/libusb:1 )
	X? ( x11-misc/xdg-utils )
	xinetd? ( sys-apps/xinetd )
	zeroconf? ( >=net-dns/avahi-0.6.31-r2[${MULTILIB_USEDEP}] )
	abi_x86_32? (
		!<=app-emulation/emul-linux-x86-baselibs-20140508
		!app-emulation/emul-linux-x86-baselibs[-abi_x86_32(-)]
	)
"

DEPEND="${CDEPEND}
	test? (
		dev-cpp/gtest:=
		>=chromeos-base/libchrome-0.0.1-r31:0=[cros-debug=]
		>=chromeos-base/libbrillo-0.0.1-r1651:=
	)
"

BDEPEND="
	>=virtual/pkgconfig-0-r1[${MULTILIB_USEDEP}]
"

RDEPEND="${CDEPEND}
	selinux? ( sec-policy/selinux-cups )
"

REQUIRED_USE="
	usb? ( threads )
	?? ( systemd upstart )
"

S="${WORKDIR}/${PN}-release-${MY_PV}"

MULTILIB_CHOST_TOOLS=(
	/usr/bin/cups-config
)

pkg_setup() {
	enewgroup lp
	enewuser lp -1 -1 -1 "lp,ippusb"
	enewgroup lpadmin
	enewuser lpadmin -1 -1 -1 "lpadmin,ippusb"
	enewgroup cups
	enewuser cups -1 -1 -1 cups
}

src_prepare() {
	default

	# Remove ".SILENT" rule for verbose output (bug 524338).
	sed 's#^.SILENT:##g' -i "${S}"/Makedefs.in || die "sed failed"

	# Fix install-sh, posix sh does not have 'function'.
	sed 's#function gzipcp#gzipcp()#g' -i "${S}/install-sh"

	AT_M4DIR=config-scripts eaclocal
	eautoconf

	# custom Makefiles
	multilib_copy_sources
}

multilib_src_configure() {
	sanitizers-setup-env
	append-lfs-flags

	export DSOFLAGS="${LDFLAGS}"

	local myconf=()

	if tc-is-static-only; then
		myconf+=(
			--disable-shared
		)
	fi

	# engages the Chrome-OS-specific "minimal" build.
	# We perform further cleanup in multilib_src_install_all().
	myconf+=( "--with-components=cros-minimal" )

	# Default pkgconfig path is /usr/lib, which isn't correct for 64-bit.
	myconf+=( "--with-pkgconfpath=/usr/$(get_libdir)/pkgconfig" )

	# Allow non-root to run cupsd so the launcher can access it.
	myconf+=( "--with-cupsd-file-perm=0555" )

	# Enable compiling extra debug messages.  Only printed when the cupsd
	# debug level is increased.
	myconf+=( "--enable-debug-printfs" )

	# The tests use googletest (C++), so make sure correct C++ version is
	# enabled.
	append-cxxflags -std=gnu++17

	# explicitly specify compiler wrt bug 524340
	#
	# need to override KRB5CONFIG for proper flags
	# https://www.cups.org/str.php?L4423
	econf \
		CC="$(tc-getCC)" \
		CXX="$(tc-getCXX)" \
		LIBS="-lstdc++" \
		KRB5CONFIG="${EPREFIX}/usr/bin/${CHOST}-krb5-config" \
		PKGCONFIG="$(tc-getPKG_CONFIG)" \
		--libdir="${EPREFIX}/usr/$(get_libdir)" \
		--localstatedir="${EPREFIX}"/var \
		--with-rundir="${EPREFIX}"/run/cups \
		--with-printerroot="${EPREFIX}"/var/cache/cups/printers \
		--with-cups-user=nobody \
		--with-cups-group=cups \
		--with-docdir="${EPREFIX}"/usr/share/cups/html \
		--with-languages=none \
		--with-system-groups=lpadmin \
		--with-xinetd=/etc/xinetd.d \
		"$(multilib_native_use_enable acl)" \
		$(use_enable dbus) \
		$(use_enable debug) \
		$(use_enable debug debug-guards) \
		$(use_enable debug debug-printfs) \
		$(use_enable kerberos gssapi) \
		"$(multilib_native_use_enable pam)" \
		$(use_enable static-libs static) \
		$(use_enable threads) \
		$(use_with ssl tls gnutls) \
		$(use_with systemd ondemand systemd) \
		$(use_with upstart ondemand upstart) \
		"$(multilib_native_use_enable usb libusb)" \
		--without-dnssd \
		"$(multilib_is_native_abi && echo --enable-libpaper || echo --disable-libpaper)" \
		"${myconf[@]}"

	# install in /usr/libexec always, instead of using /usr/lib/cups, as that
	# makes more sense when facing multilib support.
	sed -i -e "s:SERVERBIN.*:SERVERBIN = \"\$\(BUILDROOT\)${EPREFIX}/usr/libexec/cups\":" Makedefs || die
	sed -i -e "s:#define CUPS_SERVERBIN.*:#define CUPS_SERVERBIN \"${EPREFIX}/usr/libexec/cups\":" config.h || die
	sed -i -e "s:cups_serverbin=.*:cups_serverbin=\"${EPREFIX}/usr/libexec/cups\":" cups-config || die
	sed -i -e "s:cups_serverbin=.*:cups_serverbin=\"${EPREFIX}/usr/libexec/cups\":" cups.pc || die
}

multilib_src_compile() {
	if multilib_is_native_abi; then
		default
		if use test; then
			tc-export PKG_CONFIG
			cros-debug-add-NDEBUG
			emake compile-test
		fi
	else
		emake libs
	fi

	# Suppress warning for quoting because we want these to expand into
	# multiple arguments.
	# shellcheck disable=SC2086
	"$(tc-getCC)" ${CFLAGS} ${CPPFLAGS} ${LDFLAGS} -o cups_launcher \
		"${S}/chromeos/cups_launcher.c"
}

multilib_src_test() {
	multilib_is_native_abi || return 0
	local tests=(
		./cups/googletests
		./scheduler/googletests
	)
	local t

	if use cros_host; then
		test_args=( --host )
	else
		test_args=( --sysroot="${SYSROOT}" )
	fi

	for t in "${tests[@]}"; do
		ASAN_OPTIONS=log_path=stderr \
		UBSAN_OPTIONS=print_stacktrace=1:log_path=stderr \
		/mnt/host/source/src/platform2/common-mk/platform2_test.py \
		"${test_args[@]}" -- "${t}" || die "${t} failed"
	done
}

multilib_src_install() {
	# Set STRIPPROG to a no-op so we can use portage split debug instead.
	if multilib_is_native_abi; then
		emake BUILDROOT="${D}" STRIPPROG=true install
	else
		emake BUILDROOT="${D}" STRIPPROG=true install-libs install-headers
		dobin cups-config
	fi
	dosbin cups_launcher
}

multilib_src_install_all() {
	# install tmpfiles.d
	dotmpfiles "${FILESDIR}/tmpfiles.d/cupsd.conf"
	insinto /usr/lib/tmpfiles.d/on-demand/
	doins "${FILESDIR}/tmpfiles.d/on-demand/"*.conf

	# move the default config file to docs
	dodoc "${ED}"/etc/cups/cupsd.conf.default
	rm -f "${ED}"/etc/cups/cupsd.conf.default

	# clean out cups init scripts
	rm -rf "${ED}"/etc/{init.d/cups,rc*,pam.d/cups}

	# install our init script
	local neededservices
	use zeroconf && neededservices+=" avahi-daemon"
	use dbus && neededservices+=" dbus"
	[[ -n ${neededservices} ]] && neededservices="need${neededservices}"
	cp "${FILESDIR}"/cupsd.init.d-r1 "${T}"/cupsd || die
	sed -i \
		-e "s/@neededservices@/${neededservices}/" \
		"${T}"/cupsd || die
	doinitd "${T}"/cupsd

	# install our pam script
	pamd_mimic_system cups auth account

	if use xinetd ; then
		# correct path
		sed -i \
			-e "s:server = .*:server = /usr/libexec/cups/daemon/cups-lpd:" \
			"${ED}"/etc/xinetd.d/cups-lpd || die
		# it is safer to disable this by default, bug #137130
		grep -w 'disable' "${ED}"/etc/xinetd.d/cups-lpd || \
			{ sed -i -e "s:}:\tdisable = yes\n}:" "${ED}"/etc/xinetd.d/cups-lpd || die ; }
		# write permission for file owner (root), bug #296221
		fperms u+w /etc/xinetd.d/cups-lpd || die "fperms failed"
	else
		# always configure with --with-xinetd= and clean up later,
		# bug #525604
		rm -rf "${ED}"/etc/xinetd.d
	fi

	keepdir /usr/libexec/cups/driver /usr/share/cups/{model,profiles} \
		/var/spool/cups/tmp

	keepdir /etc/cups/{interfaces,ppd,ssl}

	# create /etc/cups/client.conf, bug #196967 and #266678
	echo "ServerName ${EPREFIX}/run/cups/cups.sock" >> "${ED}"/etc/cups/client.conf
	# Cap TLS per https://crbug.com/1088032
	echo "MaxTLS1.2" >> "${ED}/etc/cups/client.conf"

	# the following file is now provided by cups-filters:
	rm -r "${ED}"/usr/share/cups/banners || die

	# the following are created by the init script
	rm -r "${ED}"/var/cache/cups || die
	rm -r "${ED}"/run || die

	# we're sending logs to syslog, not /var/log/cups/*
	rmdir "${ED}"/var/log/cups || die

	# CUPS tries to install these as root-only executables, for
	# IPP/Kerberos support, and for "privileged port" listening. We don't
	# need the former, and the latter is handled by Linux capabilities.
	# Discussion here:
	# http://www.cups.org/pipermail/cups/2016-February/027499.html
	chmod 0755 "${ED}"/usr/libexec/cups/backend/{dnssd,ipp,lpd}

	# Starting with CUPS v2.4, the usb backend is installed as root owned 0744
	# because most Linux distros run it as root, even though running as non-root
	# is a valid use case (CrOS runs it as user cups), so we install it as 0755 as
	# done in CUPS < v2.4.
	# Upstream discussion: https://github.com/OpenPrinting/cups/issues/121
	# Also see b:279508819
	chmod 0755 "${ED}"/usr/libexec/cups/backend/usb

	# Create a symbolic link from "ippusb' to the ipp backend.
	dosym ipp /usr/libexec/cups/backend/ippusb

	# Install our own conf files
	insinto /etc/cups
	doins "${FILESDIR}"/{cupsd,cupsd-debug,cups-files}.conf
	if use upstart; then
		insinto /etc/init
		doins "${FILESDIR}"/init/cupsd.conf
	fi

	# CUPS wants the daemon user to own these
	chown cups:cups "${ED}"/etc/cups/{cupsd.conf,cups-files.conf,ssl}
	# CUPS also wants some specific permissions
	chmod 640 "${ED}"/etc/cups/{cupsd,cups-files}.conf
	chmod 700 "${ED}"/etc/cups/ssl

	if use seccomp; then
		# Install seccomp policy files.
		insinto /usr/share/policy
		newins "${FILESDIR}/cupsd-seccomp-${ARCH}.policy" cupsd-seccomp.policy
		newins "${FILESDIR}/cupstestppd-seccomp-${ARCH}.policy" cupstestppd-seccomp.policy
		newins "${FILESDIR}/lpadmin-seccomp-${ARCH}.policy" lpadmin-seccomp.policy
		newins "${FILESDIR}/lpstat-seccomp-${ARCH}.policy" lpstat-seccomp.policy
	else
		sed -i '/^env seccomp_flags=/s:=.*:="":' "${ED}"/etc/init/cupsd.conf
	fi

	# Removes files and directories not used by Chrome OS.
	rm -rv \
		"${ED}"/usr/share/cups/ppdc/ \
			|| die "failed to remove some directories"
	rm -v \
		"${ED}"/etc/cups/*.default \
		"${ED}"/etc/cups/snmp.conf \
		"${ED}"/usr/bin/cancel \
		"${ED}"/usr/libexec/cups/backend/snmp \
		"${ED}"/usr/sbin/cupsctl \
		"${ED}"/usr/sbin/cupsreject \
		"${ED}"/usr/sbin/lpmove \
			|| die "failed to remove some files"
}
