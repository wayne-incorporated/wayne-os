# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI="7"
CROS_WORKON_PROJECT="chromiumos/third_party/hostap"
CROS_WORKON_EGIT_BRANCH="wpa_supplicant-2.10.0"
CROS_WORKON_LOCALNAME="../third_party/wpa_supplicant-cros/current"

PYTHON_COMPAT=( python3_{6..9} )

inherit cros-sanitizers cros-workon distutils-r1 flag-o-matic toolchain-funcs

DESCRIPTION="Test package for the hostap project, intended for a VM"
HOMEPAGE="https://w1.fi"

LICENSE="BSD"
SLOT="0"
KEYWORDS="~*"
IUSE="dbus"

REQUIRED_USE="${PYTHON_REQUIRED_USE}"

DEPEND="
	dev-libs/libnl:3=
	dev-libs/openssl:0=
	net-libs/libpcap:=
"

# pygobject with python3 support requires recent versions (e.g., 3.28.3 --
# http://crrev.com/c/1869550), but recent versions are more difficult to
# cross-compile (gobject-introspection, in particular). Leave this behind an
# optional 'dbus' USE flag for now. Hwsim tests will skip D-Bus tests if
# libraries aren't available.
RDEPEND="${DEPEND}
	${PYTHON_DEPS}
	dbus? (
		dev-python/dbus-python[${PYTHON_USEDEP}]
		dev-python/pygobject[${PYTHON_USEDEP}]
		sys-apps/dbus
	)
	dev-python/pycryptodome[${PYTHON_USEDEP}]
	dev-python/pyrad[${PYTHON_USEDEP}]
	net-analyzer/wireshark

	net-wireless/crda
"

src_unpack() {
	cros-workon_src_unpack
}

src_configure() {
	sanitizers-setup-env
	# Toolchain setup
	append-flags -Werror
	tc-export CC

	cp tests/hwsim/example-wpa_supplicant.config wpa_supplicant/.config || die
	cp tests/hwsim/example-hostapd.config hostapd/.config || die

	# Disable WPA_TRACE_BFD, and kill any hard-coded /usr/include paths.
	# TODO(https://crbug.com/1013471): re-enable BFD to run additional
	# trace-based tests.
	sed -i \
		-e '/^CONFIG_WPA_TRACE_BFD=/d' \
		-e '/^CFLAGS .*\/usr\/include/d' \
		wpa_supplicant/.config \
		hostapd/.config || die
}

# Clean in-between builds, because common code may be built with different
# configs. See also tests/hwsim/build.sh.
src_compile() {
	einfo "Building wlantest"
	emake -C wlantest V=1

	einfo "Building hostapd"
	emake -C hostapd clean
	emake -C hostapd hostapd hostapd_cli hlr_auc_gw V=1

	einfo "Building wpa_supplicant"
	emake -C wpa_supplicant clean
	emake -C wpa_supplicant V=1
}

src_install() {
	local install_dir="/usr/libexec/hostap"
	exeinto "${install_dir}"/wlantest
	doexe wlantest/wlantest wlantest/wlantest_cli wlantest/test_vectors

	dodir "${install_dir}"/tests
	cp -pPR "${S}"/tests/hwsim "${D}/${install_dir}"/tests || die
	cp -pPR "${S}"/wpaspy "${D}/${install_dir}" || die

	exeinto "${install_dir}"/hostapd
	local exe
	for exe in hostapd hostapd_cli hlr_auc_gw; do
		doexe "hostapd/${exe}"
	done
	exeinto "${install_dir}"/wpa_supplicant
	for exe in wpa_supplicant wpa_cli; do
		doexe "wpa_supplicant/${exe}"
	done
}
