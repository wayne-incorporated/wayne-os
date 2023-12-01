# Copyright 2010 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_PROJECT="chromiumos/third_party/bootstub"

inherit eutils toolchain-funcs cros-workon

DESCRIPTION="Chrome OS embedded bootstub"
LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~*"
IUSE=""
DEPEND="sys-boot/gnu-efi"

src_compile() {
	# Use GNU objcopy as llvm-objcopy does not support
	# efi-app-x86_64 bfdname (https://crbug.com/1150055) .
	export OBJCOPY="${CHOST}-objcopy"
	emake -j1 CC="$(tc-getCC)" LD="$(tc-getLD)" \
              || die "${SRCPATH} compile failed."
}

src_install() {
	LIBDIR=$(get_libdir)
	emake DESTDIR="${D}/${LIBDIR}/bootstub" install || \
              die "${SRCPATH} install failed."
}
