# Copyright 1999-2012 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/net-wireless/bluez/bluez-4.99.ebuild,v 1.7 2012/04/15 16:53:41 maekke Exp $

EAPI="7"
# To support choosing between current and next versions, two cros-workon
# projects are declared. During emerge, both project sources are copied to
# their respective destination directories, and one is chosen as the
# "working directory" in src_unpack() below based on bluez-next USE flag.
CROS_WORKON_COMMIT=("85a25f041d14ba47b2ab6f9dba78eb69468f2f78" "85a25f041d14ba47b2ab6f9dba78eb69468f2f78" "ddd09531e936508ba9ea620f9caaf3402c54496f")
CROS_WORKON_TREE=("d62f9dd702a5e099f29d6d04ed617b783fac089c" "d62f9dd702a5e099f29d6d04ed617b783fac089c" "04e7c56c9e1d976546ec83929a20654a45c0f419")
CROS_WORKON_LOCALNAME=("bluez/current" "bluez/next" "bluez/upstream")
CROS_WORKON_PROJECT=("chromiumos/third_party/bluez" "chromiumos/third_party/bluez" "chromiumos/third_party/bluez")
CROS_WORKON_OPTIONAL_CHECKOUT=(
	"use !bluez-next && use !bluez-upstream"
	"use bluez-next"
	"use bluez-upstream"
)
CROS_WORKON_DESTDIR=("${S}/bluez/current" "${S}/bluez/next" "${S}/bluez/upstream")
CROS_WORKON_EGIT_BRANCH=("chromeos-5.54" "chromeos-5.54" "upstream/master")

inherit autotools multilib eutils systemd udev user libchrome cros-fuzzer cros-sanitizers cros-workon flag-o-matic tmpfiles

DESCRIPTION="Bluetooth Tools and System Daemons for Linux"
HOMEPAGE="http://www.bluez.org/"
#SRC_URI not defined because we get our source locally

LICENSE="GPL-2 LGPL-2.1"
KEYWORDS="*"
IUSE="asan bluez-next bluez-upstream cups debug fuzzer hid2hci systemd readline bt_deprecated_tools"
IUSE="${IUSE} bluez_default_conn_int"		# b/219537522
IUSE="${IUSE} bluez_disallow_bqr"		# b/231741170
REQUIRED_USE="?? ( bluez-next bluez-upstream )"

CDEPEND="
	>=dev-libs/glib-2.14:2=
	app-arch/bzip2:=
	sys-apps/dbus:=
	virtual/libudev:=
	cups? ( net-print/cups:= )
	readline? ( sys-libs/readline:= )
	>=chromeos-base/metrics-0.0.1-r3152:=
"
DEPEND="${CDEPEND}"

RDEPEND="${CDEPEND}
	!net-wireless/bluez-hcidump
	!net-wireless/bluez-libs
	!net-wireless/bluez-test
	!net-wireless/bluez-utils
"
BDEPEND="${CDEPEND}
	sys-devel/flex:=
"

PATCHES=(
	"${FILESDIR}"/bluez-hid2hci.patch
)

DOCS=( AUTHORS ChangeLog README )

src_unpack() {
	cros-workon_src_unpack

	# Setting S has the effect of changing the temporary build directory
	# here onwards. Choose "bluez/next" or "bluez/current" subdir depending on
	# the USE flag.
	local checkout="bluez/$(usex bluez-next next $(usex bluez-upstream upstream current))"
	S+="/${checkout}"
	local version="$("${FILESDIR}"/chromeos-version.sh "${S}")"
	einfo "Using checkout ${checkout} (version ${version})"
}

src_prepare() {
	default

	eautoreconf

	if use cups; then
		sed -i \
			-e "s:cupsdir = \$(libdir)/cups:cupsdir = $(cups-config --serverbin):" \
			Makefile.tools Makefile.in || die
	fi
}

src_configure() {
	sanitizers-setup-env
	# Workaround a global-buffer-overflow warning in asan build.
	# See crbug.com/748216 for details.
	if use asan; then
		append-flags '-mllvm -asan-globals=0'
	fi

	use readline || export ac_cv_header_readline_readline_h=no

	export BASE_VER="$(libchrome_ver)"
	econf \
		--enable-tools \
		--localstatedir=/var \
		$(use_enable cups) \
		--enable-datafiles \
		$(use_enable debug) \
		--disable-test \
		--enable-library \
		--disable-systemd \
		--disable-obex \
		--enable-sixaxis \
		--disable-network \
		--disable-datafiles \
		--enable-admin \
		$(use_enable fuzzer) \
		$(use_enable hid2hci) \
		$(use_enable bt_deprecated_tools deprecated)
}

src_test() {
	# TODO(armansito): Run unit tests for non-x86 platforms.
	[[ "${ARCH}" == "x86" || "${ARCH}" == "amd64" ]] && \
		emake check VERBOSE=1
}

src_install() {
	default

	dobin tools/btmgmt tools/btgatt-client tools/btgatt-server

	# Install scripts
	dobin "${FILESDIR}/dbus_send_blutooth_class.awk"
	dobin "${FILESDIR}/get_bluetooth_device_class.sh"
	dobin "${FILESDIR}/start_bluetoothd.sh"
	dobin "${FILESDIR}/start_bluetoothlog.sh"
	dobin "${FILESDIR}/set_bluetooth_coredump.sh"

	# Install init scripts.
	if use systemd; then
		systemd_dounit "${FILESDIR}/bluetoothd.service"
		systemd_enable_service system-services.target bluetoothd.service
	else
		insinto /etc/init
		newins "${FILESDIR}/${PN}-upstart.conf" bluetoothd.conf
		newins "${FILESDIR}/bluetoothlog-upstart.conf" bluetoothlog.conf
	fi

	# Install tmpfiles.d config
	dotmpfiles "${FILESDIR}/bluetoothlog-directories.conf"
	dotmpfiles "${FILESDIR}/tmpfiles.d/bluez.conf"

	# Install D-Bus config
	insinto /etc/dbus-1/system.d
	doins "${FILESDIR}/org.bluez.conf"

	# Install udev files
	udev_dorules "${FILESDIR}/99-uhid.rules"
	udev_dorules "${FILESDIR}/99-ps3-gamepad.rules"
	udev_dorules "${FILESDIR}/99-bluetooth-quirks.rules"
	udev_dorules "${FILESDIR}/99-bluetooth-devcoredump.rules"

	# Install the config files.
	cp "${FILESDIR}/main.conf" main.conf || die
	# Some boards require the default LE connection intervals, so remove the
	# Min/Max ConnectionInterval overrides.
	if use bluez_default_conn_int; then
		sed -i 's/MinConnectionInterval/#MinConnectionInterval/g' main.conf
		sed -i 's/MaxConnectionInterval/#MaxConnectionInterval/g' main.conf
	fi

	# Temporary fix for b/231741170: don't enable BQR on specific platforms
	# to prevent device can't suspend issue.
	if use bluez_disallow_bqr; then
		sed -i 's/#DisallowBQR/DisallowBQR/g' main.conf
	fi

	insinto "/etc/bluetooth"
	doins main.conf
	doins "${FILESDIR}/input.conf"

	# Install the fuzzer binaries.
	local fuzzer_component_id="167317"
	fuzzer_install "${S}/fuzzer/OWNERS" fuzzer/bluez_pattern_match_fuzzer \
		--comp "${fuzzer_component_id}"
	fuzzer_install "${S}/fuzzer/OWNERS" fuzzer/bluez_pattern_new_fuzzer \
		--comp "${fuzzer_component_id}"

	# We don't preserve /var/lib in images, so nuke anything we preseed.
	rm -rf "${D}"/var/lib/bluetooth

	rm "${D}/lib/udev/rules.d/97-bluetooth.rules"

	find "${D}" -name "*.la" -delete
}

pkg_postinst() {
	enewuser "bluetooth" "218"
	enewgroup "bluetooth" "218"

	udev_reload
}
