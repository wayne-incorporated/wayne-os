# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit autotools eutils user cros-sanitizers

DESCRIPTION="The USBGuard software framework helps to protect your computer against rogue USB devices (a.k.a. BadUSB) by implementing basic whitelisting and blacklisting capabilities based on device attributes."
HOMEPAGE="https://usbguard.github.io/"
GIT_REV="ad904f4645c79a20a7542fed7f24a9c8c2146e5a"
CATCH_REV="35f510545d55a831372d3113747bf1314ff4f2ef"
PEGTL_REV="7d039707cf835cea63daa78a717e18fcc5bcf95b"
SRC_URI="https://github.com/USBGuard/usbguard/archive/${GIT_REV}.tar.gz -> ${P}.tar.gz
https://github.com/catchorg/Catch2/archive/${CATCH_REV}.tar.gz -> ${PN}-201807-catch.tar.gz
https://github.com/taocpp/PEGTL/archive/${PEGTL_REV}.tar.gz -> ${PN}-pegtl-20210115.tar.gz"

LICENSE="GPL-2"
SLOT="0/${PVR}"
KEYWORDS="*"
IUSE="cfm_enabled_device hammerd dbus"

COMMON_DEPEND="
	dev-libs/openssl:=
	dev-libs/protobuf:=
	sys-cluster/libqb"

DEPEND="${COMMON_DEPEND}"

RDEPEND="${COMMON_DEPEND}"

S="${WORKDIR}/usbguard-${GIT_REV}/"

PATCHES=(
	"${FILESDIR}/daemon_conf.patch"
)

src_prepare() {
	rm -rf "${S}/src/ThirdParty/Catch"
	mv "${WORKDIR}/Catch2-${CATCH_REV}" "${S}/src/ThirdParty/Catch"

	rm -rf "${S}/src/ThirdParty/PEGTL"
	mv "${WORKDIR}/PEGTL-${PEGTL_REV}" "${S}/src/ThirdParty/PEGTL"

	default
	eautoreconf
}

src_configure() {
	sanitizers-setup-env
	cros_enable_cxx_exceptions
	econf \
		$(use_with dbus) \
		--without-polkit \
		--without-ldap \
		--with-bundled-catch \
		--with-bundled-pegtl \
		--with-crypto-library=openssl \
		--disable-audit \
		--disable-libcapng \
		--disable-seccomp \
		--disable-umockdev
}

src_install() {
	emake DESTDIR="${D}" install
	# Cleanup unwanted files from the emake install command.
	if use dbus; then
		rm "${D}/etc/usbguard/rules.conf" || die
		rm "${D}/usr/share/dbus-1/system.d/org.usbguard1.conf" || die

		insinto /usr/share/dbus-1/interfaces
		newins "${S}/src/DBus/DBusInterface.xml" org.usbguard1.xml

		insinto /etc/dbus-1/system.d
		doins "${FILESDIR}/org.usbguard1.conf"
	fi

	insinto /etc/usbguard/rules.d
	use cfm_enabled_device && doins "${FILESDIR}/50-cfm-rules.conf"
	use hammerd && doins "${FILESDIR}/50-hammer-rules.conf"
	doins "${FILESDIR}/90-modalias-rules.conf"
	doins "${FILESDIR}/99-rules.conf"

	insinto /usr/share/policy
	newins "${FILESDIR}/usbguard-daemon-seccomp-${ARCH}.policy" usbguard-daemon-seccomp.policy

	insinto /etc/init
	doins "${FILESDIR}"/usbguard.conf
	doins "${FILESDIR}"/usbguard-wrapper.conf

	insinto /etc/usbguard
	insopts -o usbguard -g usbguard -m600
	doins usbguard-daemon.conf
}

pkg_setup() {
	enewuser usbguard
	enewgroup usbguard
}
