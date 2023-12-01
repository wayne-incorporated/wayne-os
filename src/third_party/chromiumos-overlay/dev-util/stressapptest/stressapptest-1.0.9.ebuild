# Copyright 1999-2018 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI="6"

inherit eutils flag-o-matic binutils-funcs toolchain-funcs

DESCRIPTION="Stressful Application Test"
HOMEPAGE="https://github.com/stressapptest/stressapptest"
SRC_URI="https://github.com/stressapptest/stressapptest/archive/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"

# By assigning USE="cros_arm64" in private overlay, we'll build 64-bits version
# of stressapptest.
IUSE="debug cros_arm64"

RDEPEND="dev-libs/libaio"
DEPEND="${RDEPEND}"

need_static_arm64() {
	use cros_arm64 && use arm
}

src_prepare() {
	eapply "${FILESDIR}"/${PN}-gnu_cxx-namespace.patch
	eapply "${FILESDIR}"/0001-include-stdint.h.patch
	eapply "${FILESDIR}"/0002-use-memfd_create-instead-of-shm_open.patch
	eapply_user

	# To build 64-bit version for arm64.
	if need_static_arm64; then
		export S64="${S}_64"
		cp -r "${S}" "${S64}" || die
	fi
}

src_configure() {
	append-lfs-flags

	# Matches the configure & sat.cc logic.
	use debug || append-cppflags -DNDEBUG -DCHECKOPTS
	econf --disable-default-optimizations
}

build_static_arm64() {
	unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS

	# Use headers and libraries from "/" instead of "/build/${BOARD}"
	export SYSROOT=""

	# The following logic is copied from cros-kernel2.eclass
	export CHOST=aarch64-cros-linux-gnu
	export CTARGET=aarch64-cros-linux-gnu
	export ABI=arm64
	unset CC CXX LD STRIP OBJCOPY PKG_CONFIG

	tc-export_build_env BUILD_{CC,CXX}

	export LD="${CHOST}-ld.lld"
	export CC="${CHOST}-clang"
	export CXX="${CHOST}-clang++"

	cd "${S64}" || die
	use debug || append-cppflags -DNDEBUG -DCHECKOPTS
	econf --disable-default-optimizations --with-static
	emake
}

src_compile() {
	default

	if need_static_arm64; then
		build_static_arm64
	fi
}

src_install() {
	default

	if need_static_arm64; then
		newbin "${S64}/src/stressapptest" "stressapptest64"
	fi
}
