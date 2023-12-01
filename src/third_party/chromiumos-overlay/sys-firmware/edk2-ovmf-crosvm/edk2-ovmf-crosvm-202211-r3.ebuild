# Copyright 1999-2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..11} )

inherit python-any-r1 readme.gentoo-r1

DESCRIPTION="UEFI firmware for crosvm"
HOMEPAGE="https://github.com/tianocore/edk2"

BUNDLED_OPENSSL_SUBMODULE_SHA="d82e959e621a3d597f1e0d50ff8c2d8b96915fd7"
BUNDLED_BROTLI_SUBMODULE_SHA="f4153a09f87cbb9c826d8fc12c74642bb2d879ea"

SRC_URI="
	https://github.com/tianocore/edk2/archive/edk2-stable${PV}.tar.gz
	https://github.com/openssl/openssl/archive/${BUNDLED_OPENSSL_SUBMODULE_SHA}.tar.gz -> openssl-${BUNDLED_OPENSSL_SUBMODULE_SHA}.tar.gz
	https://github.com/google/brotli/archive/${BUNDLED_BROTLI_SUBMODULE_SHA}.tar.gz -> brotli-${BUNDLED_BROTLI_SUBMODULE_SHA}.tar.gz
"

# BSD-2: edk2
# MIT: bundled brotli submodule
# openssl: bundled openssl submodule
LICENSE="BSD-2 MIT openssl"
SLOT="0"
KEYWORDS="-* amd64"

BDEPEND=">=dev-lang/nasm-2.0.7
	>=sys-power/iasl-20160729
	${PYTHON_DEPS}"

PATCHES=(
	"${FILESDIR}/0001-BaseTools-Use-BUILD_CC-when-checking-gcc-version-in-.patch"
	"${FILESDIR}/0002-crosvm-create-new-dsc-for-Crosvm.patch"
	"${FILESDIR}/0003-re-enable-RTC-now-that-crosvm-is-fixed.patch"
	"${FILESDIR}/0004-crosvm-swap-CR-and-LF-characters-for-serial.patch"
	"${FILESDIR}/0005-crosvm-always-use-CloudHv-ACPI-tables.patch"
	"${FILESDIR}/0006-crosvm-search-for-RSD-PTR-manually.patch"
	"${FILESDIR}/0007-crosvm-always-use-Xen-platform-console.patch"
	"${FILESDIR}/0008-crosvm-fix-SMBIOS-table-entry-for-crosvm.patch"
	"${FILESDIR}/0009-crosvm-remove-shell-app.patch"
)

S="${WORKDIR}/edk2-edk2-stable${PV}"

DISABLE_AUTOFORMATTING=true

pkg_setup() {
	python-any-r1_pkg_setup
}

src_prepare() {
	# Bundled submodules
	cp -rl "${WORKDIR}/openssl-${BUNDLED_OPENSSL_SUBMODULE_SHA}"/* "CryptoPkg/Library/OpensslLib/openssl/"
	cp -rl "${WORKDIR}/brotli-${BUNDLED_BROTLI_SUBMODULE_SHA}"/* "BaseTools/Source/C/BrotliCompress/brotli/"
	cp -rl "${WORKDIR}/brotli-${BUNDLED_BROTLI_SUBMODULE_SHA}"/* "MdeModulePkg/Library/BrotliCustomDecompressLib/brotli/"

	sed -i -r \
		-e "/function SetupPython3/,/\}/{s,\\\$\(whereis python3\),${EPYTHON},g}" \
		"${S}"/edksetup.sh || die "Fixing for correct Python3 support failed"

	default
}

src_compile() {
	tc-export BUILD_CC

	emake -C BaseTools

	. ./edksetup.sh

	# Used by tools_def.template as the toolchain prefix
	# TODO(b/275426220): switch to clang
	export GCC5_BIN="${CHOST}-"

	cros_allow_gnu_build_tools

	build \
		-p OvmfPkg/Crosvm/CrosvmX64.dsc \
		-t GCC5 \
		-a X64 \
		-b RELEASE \
		-D SECURE_BOOT_ENABLE \
		-D FD_SIZE_4MB || die "OvmfPkg build failed"
}

src_install() {
	# Install CROSVM_CODE.fd (BIOS ROM) and CROSVM_VARS.fd (pflash).
	# These are installed into /build so they are not included in the base image.
	# They are intended to be consumed by chromeos-base/edk2-ovmf-dlc.
	insinto /build/share/${PN}
	doins Build/CrosvmX64/*/FV/CROSVM_{CODE,VARS}.fd
}
