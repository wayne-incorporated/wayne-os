# Copyright 1999-2012 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit autotools eutils

DESCRIPTION="Intel hybrid driver provides support for WebM project VPx codecs. GPU acceleration
is provided via media kernels executed on Intel GEN GPUs.  The hybrid driver provides the CPU
bound entropy (e.g., CPBAC) decoding and manages the GEN GPU media kernel parameters and buffers."
HOMEPAGE="https://github.com/01org/intel-hybrid-driver"
SRC_URI="https://github.com/01org/intel-hybrid-driver/archive/${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="MIT"
SLOT="0"
KEYWORDS="-* amd64 x86"

RDEPEND="x11-libs/libva
	x11-libs/libdrm
	media-libs/cmrt"

DEPEND="${RDEPEND}
	virtual/pkgconfig"

PATCHES=(
	"${FILESDIR}/${P}-respect-wayland-configure-flags.patch"
	"${FILESDIR}/0001-Remove-blitter-usage.patch"
	"${FILESDIR}/0002-vp9hdec-fix-pCurrFrame-pMdfSurface-NULL-pointer-issu.patch"
)

src_prepare() {
	epatch "${PATCHES[@]}"
	eautoreconf
}

src_configure() {
	cros_optimize_package_for_speed

	# Explicitly restrict configuration for Ozone/Freon.
	econf \
		--enable-drm \
		--disable-x11 \
		--disable-wayland
}

src_install() {
	default
	prune_libtool_files
}
