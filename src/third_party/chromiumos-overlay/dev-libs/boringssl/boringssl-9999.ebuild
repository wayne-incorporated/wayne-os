# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cros-constants

CROS_WORKON_PROJECT=("external/gob/boringssl/boringssl")
CROS_WORKON_LOCALNAME="boringssl"


inherit flag-o-matic cros-go cmake-utils cros-workon

DESCRIPTION="BoringSSL is a fork of OpenSSL that is designed to meet Google's needs."
HOMEPAGE="https://chromium.googlesource.com/external/gob/boringssl/boringssl/+/refs/heads/upstream/master"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="bssl test"

RDEPEND=""
DEPEND="${RDEPEND}
	test? ( >=dev-go/crypto-0.7.0_p67-r2 )
"

INSTALL_PREFIX="/opt/boringssl"

HEADER_TAINT="#ifdef CHROMEOS_OPENSSL_IS_OPENSSL
#error \"Do not mix OpenSSL and BoringSSL headers.\"
#endif
#define CHROMEOS_OPENSSL_IS_BORINGSSL\n"

src_prepare() {
	cmake-utils_src_prepare
	# TODO(allenwebb) Disable SSLTest.HostMatching until it is fixed
	sed -i -e 's/^TEST(SSLTest, HostMatching)/TEST(SSLTest, DISABLED_HostMatching)/' "${S}/ssl/ssl_test.cc" || die

	# Taint BoringSSL headers so they don't silently mix with OpenSSL.
	find "${S}/include/openssl" -type f -exec awk -i inplace -v \
		"taint=${HEADER_TAINT}" 'NR == 1 {print taint} {print}' {} \;
}

src_configure() {
	# Build and install the static libraries and headers only.
	# /opt/boringssl is the installation directory to avoid conflicts with
	# OpenSSL.
	#
	# Do not use this with without checking with the security team first.
	local mycmakeargs=(
		"-DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}"
		"-DCMAKE_BUILD_TYPE=Release"
		"-DCMAKE_SYSTEM_PROCESSOR=${CHOST%%-*}"
		"-DBUILD_SHARED_LIBS=OFF"
	)

	export GO111MODULE=off

	# Hack together a conforming gopath for "${S}".
	local gopath_hack="${WORKDIR}/gopath/"
	local bssl_path="${gopath_hack}/src/boringssl.googlesource.com"
	mkdir -p "${bssl_path}" || die
	ln -s "${S}" "${bssl_path}/boringssl" || die
	export GOPATH="${gopath_hack}:$(cros-go_gopath)"

	cmake-utils_src_configure
}

src_test() {
	if ! use x86 && ! use amd64 ; then
		elog "Skipping unit tests on non-x86 platform"
		return
	fi

	eninja -C "${BUILD_DIR}" run_tests || die
}

src_install() {
	cmake-utils_src_install
	# Only install the bssl binary if the use flag is set.
	if ! use bssl; then
		rm "${ED}/${INSTALL_PREFIX}/bin/bssl" || die
	fi
}
