# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="76d462ddd20251c22a6a6e88d66393da74fbb5f7"
CROS_WORKON_TREE="f910997f222e65f71744c70fdf9d05188eedc22f"
CROS_WORKON_PROJECT="chromiumos/platform/frecon"
CROS_WORKON_LOCALNAME="../platform/frecon"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_INCREMENTAL_BUILD=1

inherit cros-sanitizers cros-workon cros-common.mk

DESCRIPTION="Chrome OS KMS console (without DBUS/UDEV support)"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/frecon"

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="-asan"

BDEPEND="virtual/pkgconfig"

COMMON_DEPEND="media-libs/libpng:0=
	sys-apps/libtsm:="

RDEPEND="${COMMON_DEPEND}"

DEPEND="${COMMON_DEPEND}
	media-sound/adhd:=
	x11-libs/libdrm:="

src_configure() {
	export FRECON_LITE=1
	sanitizers-setup-env
	cros-common.mk_src_configure
}
