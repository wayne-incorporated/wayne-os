# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=6

inherit cros-unibuild cmake-utils toolchain-funcs

DESCRIPTION="Intel(R) Dynamic Platform & Thermal Framework"
HOMEPAGE="https://01.org/dptf/"
SRC_URI="https://github.com/intel/dptf/archive/${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="Apache-2.0 GPL-2 BSD"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE="debug"

# Makefile for DPTF policies
CMAKE_USE_DIR="${S}/DPTF/Linux"
# Makefile for ESIF daemon
ESIF_BUILD_DIR="ESIF/Products/ESIF_UF/Linux"
# Makefile for ESIF compression library
ESIFCMP_BUILD_DIR="ESIF/Products/ESIF_CMP/Linux"
# Makefile for ESIF web server
ESIFWS_BUILD_DIR="ESIF/Products/ESIF_WS/Linux"
# Makefile location for IPF
IPF_BUILD_DIR="IPF/Linux/"

DEPEND="
	chromeos-base/chromeos-config-tools
	sys-apps/dbus
	dev-libs/libedit"
RDEPEND="${DEPEND}"

src_configure() {
	# cmake configuration for DPTF policy shared libraries
	# TODO(crbug.com/1044735): Temporary disable the warning. Remove when fixed.
	append-flags -Wno-unsequenced
	local mycmakeargs=( -DCHROMIUM_BUILD=YES )
	use x86 && mycmakeargs+=( -DBUILD_ARCH=32bit )
	use amd64 && mycmakeargs+=( -DBUILD_ARCH=64bit )
	cmake-utils_src_configure
}

src_compile() {
	# Build ESIF daemon
	local extra_cflags=""
	use debug && extra_cflags="Debug"

	for build_dir in "${ESIF_BUILD_DIR}" "${ESIFCMP_BUILD_DIR}" "${ESIFWS_BUILD_DIR}" "${IPF_BUILD_DIR}"; do
		emake \
			-C ${build_dir} \
			CC="$(tc-getCC)" \
			BUILD="${extra_cflags}" \
			OS=Chrome
	done

	# Build DPTF policy shared libraries
	cmake-utils_src_compile
}

src_install() {
	# Install ESIF daemon and configuration files
	local startcmd_src_dir="ESIF/Packages/Installers/chrome"
	dobin "${ESIF_BUILD_DIR}/ipf_ufd"
	dobin "${IPF_BUILD_DIR}/ipfhostd"
	insinto "/etc/dptf"
	doins ESIF/Packages/DSP/dsp.dv
	insinto "/etc/init"
	doins "${startcmd_src_dir}/dtt.conf"
	doins "${startcmd_src_dir}/ipf.conf"

	# Install ESIF loadable libraries
	dolib.so "${ESIFCMP_BUILD_DIR}/ipf_cmp.so"
	dolib.so "${ESIFWS_BUILD_DIR}/ipf_ws.so"
	dolib.so "${IPF_BUILD_DIR}/ipfsrv.so"
	dolib.so "${IPF_BUILD_DIR}/ipfipc.so"

	# Install DPTF policy shared libraries
	local policy_build_dir="${BUILD_DIR}"/$(usex amd64 x64 x32)
	dolib.so "${policy_build_dir}/Dptf.so"
	dolib.so "${policy_build_dir}/DptfPolicyActive.so"
	dolib.so "${policy_build_dir}/DptfPolicyCritical.so"
	dolib.so "${policy_build_dir}/DptfPolicyPassive.so"
}
