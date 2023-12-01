# Copyright 1999-2017 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI=7

XORG_DOC=doc
XORG_EAUTORECONF="yes"
inherit xorg-3 flag-o-matic

MY_P="xorg-server-${PV}"
SRC_URI="https://www.x.org/releases/individual/xserver/${MY_P}.tar.xz"
DESCRIPTION="XWayland"
SLOT="0/${PV}"
KEYWORDS="*"
IUSE="kvm_guest minimal"

# This ebuild and source is based on x11-base/xorg-server so conflicts may occur
# depending on USE flags.
RDEPEND="
	!x11-base/xorg-server
	dev-libs/openssl:0=
	>=dev-libs/wayland-1.3.0
	>=media-libs/mesa-10.3.4-r1
	>=x11-libs/libXfont2-2.0.1
	>=x11-libs/libxshmfence-1.1
	>=x11-libs/pixman-0.27.2
	>=x11-misc/xkeyboard-config-2.4.1-r3
	>=x11-apps/xkbcomp-1.2.3"

DEPEND="${RDEPEND}
	>=dev-libs/wayland-protocols-1.1
	>=sys-kernel/linux-headers-4.4-r16
	media-fonts/font-util
	media-libs/libepoxy
	>=x11-libs/libdrm-2.4.46
	>=x11-libs/libxkbfile-1.0.4
	>=x11-libs/xtrans-1.3.5
	>=x11-misc/xbitmaps-1.0.1
	>=x11-base/xorg-proto-2018.3"

S="${WORKDIR}/${MY_P}"

PATCHES=(
	"${FILESDIR}"/0001-HACK-make-monotonic-detection-always-succeed-on-cros.patch
	"${FILESDIR}"/0001-xwayland-virtwl-with-dmabuf-for-1.20.1.patch
	"${FILESDIR}"/0001-Eliminate-conflict-with-X11-Xlib.h-with-khronos-eglp.patch
	"${FILESDIR}"/0001-xwayland-sysmacros.patch
	"${FILESDIR}"/0001-xwayland-Fall-back-to-gbm_bo_create-if-no-modifiers-.patch
	"${FILESDIR}"/0001-Revert-xwayland-Use-a-fixed-DPI-value-for-core-proto.patch
	"${FILESDIR}"/0001-Use-toolchain-pkg-config.patch
	"${FILESDIR}"/0001-xkb-switch-to-array-index-loops-to-moving-pointers.patch
	# CVE-2022-2319
	"${FILESDIR}"/0002-xkb-swap-XkbSetDeviceInfo-and-XkbSetDeviceInfoCheck.patch
	# CVE-2022-2320
	"${FILESDIR}"/0003-xkb-add-request-length-validation-for-XkbSetGeometry.patch
	# CVE-2022-3550
	"${FILESDIR}"/0004-xkb-proof-GetCountedString-against-request-length-at.patch
	# CVE-2022-3551
	"${FILESDIR}"/0005-xkb-fix-some-possible-memleaks-in-XkbGetKbdByName.patch

	# CVE-2022-46340
	"${FILESDIR}"/0001-Xtest-disallow-GenericEvents-in-XTestSwapFakeInput.patch
	# related to CVE-2022-46344
	"${FILESDIR}"/0002-Xi-return-an-error-from-XI-property-changes-if-verif.patch
	# CVE-2022-46344
	"${FILESDIR}"/0003-Xi-avoid-integer-truncation-in-length-check-of-ProcX.patch
	# CVE-2022-46341
	"${FILESDIR}"/0004-Xi-disallow-passive-grabs-with-a-detail-255.patch
	# CVE-2022-46343
	"${FILESDIR}"/0005-Xext-free-the-screen-saver-resource-when-replacing-i.patch
	# CVE-2022-46342
	"${FILESDIR}"/0006-Xext-free-the-XvRTVideoNotify-when-turning-off-from-.patch
	# CVE-2022-46283
	"${FILESDIR}"/0007-xkb-reset-the-radio_groups-pointer-to-NULL-after-fre.patch
	# Fix for buggy patch to CVE-2022-46340
	"${FILESDIR}"/0008-Xext-fix-invalid-event-type-mask-in-XTestSwapFakeInp.patch

	# CVE-2023-1393
	"${FILESDIR}"/0001-composite-Fix-use-after-free-of-the-COW.patch
	# CVE-2023-0494
	"${FILESDIR}"/0001-Xi-fix-potential-use-after-free-in-DeepCopyPointerCl.patch
)

src_prepare() {
	default

	# Needed for patches that modify configure.ac
	eautoreconf
}

src_configure() {
	XORG_CONFIGURE_OPTIONS=(
		--enable-xwayland
		--disable-config-hal
		--disable-devel-docs
		--disable-docs
		--disable-linux-acpi
		--disable-xnest
		--disable-xorg
		--disable-xquartz
		--disable-xvfb
		--disable-xwin
		--sysconfdir="${EPREFIX}"/etc/X11
		--localstatedir="${EPREFIX}"/var
		--with-fontrootdir="${EPREFIX}"/usr/share/fonts
		--with-xkb-output="${EPREFIX}"/var/lib/xkb
		--without-dtrace
		--without-fop
		--with-os-vendor=Gentoo
		--with-sha1=libcrypto
		$(use_enable !minimal dri)
		$(use_enable !minimal dri2)
		$(use_enable !minimal glx)
	)

	if use kvm_guest; then
		XORG_CONFIGURE_OPTIONS+=(
			--with-xkb-bin-directory="/opt/google/cros-containers/bin"
		)
	fi

	append-lfs-flags

	xorg-3_src_configure
}
