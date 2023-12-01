# Copyright 2021-2023 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..9} )

inherit meson python-any-r1 toolchain-funcs

DESCRIPTION="EFI executable for fwupd"
HOMEPAGE="https://fwupd.org"

if [[ ${PV} = *9999 ]]; then
	inherit git-r3
	EGIT_REPO_URI="https://github.com/fwupd/fwupd-efi.git"
else
	SRC_URI="https://github.com/fwupd/${PN}/releases/download/${PV}/${P}.tar.xz"
	KEYWORDS="*"
fi

LICENSE="LGPL-2.1+"
SLOT="0"
IUSE=""

BDEPEND="$(python_gen_any_dep '
		dev-python/pefile[${PYTHON_USEDEP}]
	')
	virtual/pkgconfig"

DEPEND="sys-boot/gnu-efi"

RDEPEND="!<sys-apps/fwupd-1.6.0"

PATCHES=(
	"${FILESDIR}"/${PN}-1.4-efi_ld_override.patch	# Bug #892339
)

python_check_deps() {
	python_has_version "dev-python/pefile[${PYTHON_USEDEP}]"
}

src_prepare() {
	default

	python_fix_shebang "${S}/efi"
}

src_configure() {
	# TODO(b/273518305): llvm-objcopy doesn't support `--target
	# efi-app-x86_64` or `--section-alignment` (see
	# efi/generate_binary.py in the fwupd-efi source). For now use
	# GNU binutils objcopy instead.
	cros_allow_gnu_build_tools
	export OBJCOPY="${CHOST}"-objcopy

	local emesonargs=(
		-Defi-ld="$(tc-getLD)"
		-Defi-libdir="${SYSROOT}"/usr/"$(get_libdir)"
		-Defi-includedir="${SYSROOT}"/usr/include/efi
		-Defi_sbat_distro_id="chromeos"
		-Defi_sbat_distro_summary="ChromeOS"
		-Defi_sbat_distro_pkgname="${PN}"
		-Defi_sbat_distro_version="${PVR}"
		-Defi_sbat_distro_url="https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/sys-apps/fwupd-efi/"
	)

	meson_src_configure
}
