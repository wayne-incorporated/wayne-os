# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT=("e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd" "49dfc58d6c4c66f5d0b0d06f0161da4e602a1293")
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "fca302ad0c7652f979dd46a130b29dad529e968d" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6" "6dbc19849752c206e135ab59349ebb1cc62bb435")
inherit cros-constants

CROS_WORKON_INCREMENTAL_BUILD="1"
CROS_WORKON_PROJECT=("chromiumos/platform2" "platform/system/keymaster")
CROS_WORKON_REPO=(
	"${CROS_GIT_HOST_URL}"
	"${CROS_GIT_AOSP_URL}"
)
CROS_WORKON_EGIT_BRANCH=("master" "pie-release")
CROS_WORKON_LOCALNAME=("platform2" "aosp/system/keymaster")
CROS_WORKON_DESTDIR=("${S}/platform2" "${S}/aosp/system/keymaster")
CROS_WORKON_SUBTREE=("common-mk arc/keymaster .gn" "")

PLATFORM_SUBDIR="arc/keymaster"

# This BoringSSL integration follows go/boringssl-cros.
# DO NOT COPY TO OTHER PACKAGES WITHOUT CONSULTING SECURITY TEAM.
BORINGSSL_PN="boringssl"
BORINGSSL_PV="3a667d10e94186fd503966f5638e134fe9fb4080"
BORINGSSL_P="${BORINGSSL_PN}-${BORINGSSL_PV}"
BORINGSSL_OUTDIR="${WORKDIR}/boringssl_outputs/"

CMAKE_USE_DIR="${WORKDIR}/${BORINGSSL_P}"
BUILD_DIR="${WORKDIR}/${BORINGSSL_P}_build"

inherit flag-o-matic cmake-utils cros-workon platform user

DESCRIPTION="Android keymaster service in Chrome OS."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/arc/keymaster"
SRC_URI="https://github.com/google/${BORINGSSL_PN}/archive/${BORINGSSL_PV}.tar.gz -> ${BORINGSSL_P}.tar.gz"

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="+seccomp"

RDEPEND="
	chromeos-base/chaps:=
	chromeos-base/cryptohome:=
	chromeos-base/cryptohome-client:=
	chromeos-base/minijail:=
	dev-libs/protobuf:=
"

DEPEND="
	${RDEPEND}
	chromeos-base/session_manager-client:=
	chromeos-base/system_api:=
"

HEADER_TAINT="#ifdef CHROMEOS_OPENSSL_IS_OPENSSL
#error \"Do not mix OpenSSL and BoringSSL headers.\"
#endif
#define CHROMEOS_OPENSSL_IS_BORINGSSL\n"

src_unpack() {
	platform_src_unpack
	unpack "${BORINGSSL_P}.tar.gz"
	# Taint BoringSSL headers so they don't silently mix with OpenSSL.
	find "${BORINGSSL_P}/include/openssl" -type f -exec awk -i inplace -v \
		"taint=${HEADER_TAINT}" 'NR == 1 {print taint} {print}' {} \;
}

src_prepare() {
	cmake-utils_src_prepare

	# Expose libhardware headers from arc-toolchain-p.
	local arc_arch="${ARCH}"
	# arm needs to use arm64 directory, which provides combined arm/arm64
	# headers.
	if [[ "${ARCH}" == "arm" ]]; then
		arc_arch="arm64"
	fi
	mkdir -p "${WORKDIR}/libhardware/include" || die
	cp -rfp "/opt/android-p/${arc_arch}/usr/include/hardware" "${WORKDIR}/libhardware/include" || die
	append-cxxflags "-I${WORKDIR}/libhardware/include"

	# Expose BoringSSL headers and outputs.
	append-cxxflags "-I${WORKDIR}/${BORINGSSL_P}/include"
	append-ldflags "-L${BORINGSSL_OUTDIR}"
	# Verify upstream hasn't changed relevant context code.
	cd "${WORKDIR}/${P}/aosp/system/keymaster" || die
	eapply --dry-run "${FILESDIR}/keymaster-context-hooks.patch"
	# Fix C++17 compilation. Can be removed once we update to newer version of
	# keymaster that contains https://r.android.com/1412947.
	cd "${WORKDIR}/${P}/aosp/system/keymaster" || die
	eapply "${FILESDIR}/0001-keymaster-fix-C-17-compilation.patch"
	# Make P Keymaster compatible with latest BoringSSL.
	eapply "${FILESDIR}/keymaster-boringssl-update.patch"
}

src_configure() {
	local mycmakeargs=(
		"-DCMAKE_BUILD_TYPE=Release"
		"-DCMAKE_SYSTEM_PROCESSOR=${CHOST%%-*}"
		"-DBUILD_SHARED_LIBS=OFF"
	)
	cmake-utils_src_configure
	platform_src_configure
}

src_compile() {
	# The build is banned from accessing internet, thus turn off Go Modules
	# to prevent Go from trying to fetch package.
	export GO111MODULE=off
	# Compile BoringSSL and expose libcrypto.a.
	cmake-utils_src_compile
	mkdir -p "${BORINGSSL_OUTDIR}" || die
	cp -p "${BUILD_DIR}/crypto/libcrypto.a" "${BORINGSSL_OUTDIR}/libboringcrypto.a" || die

	platform_src_compile
}

src_install() {
	platform_src_install

	insinto /etc/init
	doins init/arc-keymasterd.conf

	# Install DBUS configuration file.
	insinto /etc/dbus-1/system.d
	doins dbus_permissions/org.chromium.ArcKeymaster.conf

	# Install seccomp policy file.
	insinto /usr/share/policy
	use seccomp && newins \
		"seccomp/arc-keymasterd-seccomp-${ARCH}.policy" \
		arc-keymasterd-seccomp.policy

	# Install shared libs and binary.
	dolib.so "${OUT}/lib/libarckeymaster_context.so"
	dolib.so "${OUT}/lib/libkeymaster.so"
	dosbin "${OUT}/arc-keymasterd"

	local fuzzer_component_id="157100"
	platform_fuzzer_install "${S}"/OWNERS "${OUT}"/arc_keymasterd_fuzzer \
		--comp "${fuzzer_component_id}"
}

pkg_preinst() {
	enewuser "arc-keymasterd"
	enewgroup "arc-keymasterd"
}

platform_pkg_test() {
	platform_test "run" "${OUT}/arc-keymasterd_testrunner"
}
