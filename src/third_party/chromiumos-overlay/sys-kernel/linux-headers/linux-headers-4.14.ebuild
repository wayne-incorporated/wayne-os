# Copyright 1999-2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# shellcheck disable=SC2034
ETYPE="headers"
# shellcheck disable=SC2034
H_SUPPORTEDARCH="alpha amd64 arc arm arm64 avr32 bfin cris frv hexagon hppa ia64 m32r m68k metag microblaze mips mn10300 nios2 openrisc ppc ppc64 s390 score sh sparc tile x86 xtensa"
inherit kernel-2
detect_version

PATCH_VER="1"
SRC_URI="mirror://gentoo/gentoo-headers-base-${PV}.tar.xz
	${PATCH_VER:+mirror://gentoo/gentoo-headers-${PV}-${PATCH_VER}.tar.xz}"
S="${WORKDIR}/gentoo-headers-base-${PV}"

KEYWORDS="*"

BDEPEND="
	app-arch/xz-utils
	dev-lang/perl"

[[ -n ${PATCH_VER} ]] && PATCHES=( "${WORKDIR}"/${PV} )

#
# NOTE: All the patches must be applicable using patch -p1.
#
PATCHES+=(
	"${FILESDIR}/0001-UPSTREAM-media-videodev2.h-Add-v4l2-definition-for-HEVC.patch"
	"${FILESDIR}/0002-BACKPORT-media-uapi-Move-parsed-H264-pixel-format-ou.patch"
	"${FILESDIR}/0003-BACKPORT-media-uapi-Move-parsed-VP8-pixel-format-out.patch"
	"${FILESDIR}/0004-CHROMIUM-v4l-Add-VP9-low-level-decoder-API-controls.patch"
	"${FILESDIR}/0007-media-videodev2.h-add-IPU3-raw10-color.patch"
	"${FILESDIR}/0008-videodev2.h-add-IPU3-meta-buffer-format.patch"
	"${FILESDIR}/0009-uapi-intel-ipu3-Add-user-space-ABI-definitions.patch"
	"${FILESDIR}/0010-virtwl-add-virtwl-driver.patch"
	"${FILESDIR}/0011-BACKPORT-FROMLIST-v4l-Add-support-for-V4L2_BUF_TYPE_.patch"
	"${FILESDIR}/0012-FROMLIST-media-rkisp1-Add-user-space-ABI-definitions.patch"
	"${FILESDIR}/0013-FROMLIST-media-videodev2.h-v4l2-ioctl-add-rkisp1-met.patch"
	"${FILESDIR}/0014-BACKPORT-add-qrtr-header-file.patch"
	"${FILESDIR}/0015-BACKPORT-FROMGIT-media-v4l2-ctrl-Change-control-for-.patch"
	"${FILESDIR}/0016-BACKPORT-FROMGIT-media-v4l2-ctrl-Add-control-for-VP9.patch"
	"${FILESDIR}/0019-BACKPORT-media-uapi-linux-media.h-add-request-API.patch"
	"${FILESDIR}/0020-BACKPORT-media-videodev2.h-add-request_fd-field-to-v.patch"
	"${FILESDIR}/0021-BACKPORT-media-videodev2.h-Add-request_fd-field-to-v.patch"
	"${FILESDIR}/0022-BACKPORT-media-videodev2.h-add-new-capabilities-for-.patch"
	"${FILESDIR}/0023-FROMGIT-media-videodev2.h-add-v4l2_timeval_to_ns-inl.patch"
	"${FILESDIR}/0024-UPSTREAM-nl80211-mac80211-mesh-add-hop-count-to-mpath.patch"
	"${FILESDIR}/0025-UPSTREAM-nl80211-mac80211-mesh-add-mesh-path-change-c.patch"
	"${FILESDIR}/0026-FROMLIST-Input_add_KEY_KBD_LAYOUT_NEXT.patch"
	"${FILESDIR}/0030-BACKPORT-sync-nl80211.h-to-v5.8.patch"
	"${FILESDIR}/0031-FROMLIST-media-pixfmt-Add-Mediatek-ISP-P1-image-meta.patch"
	"${FILESDIR}/0032-BACKPORT-add-udmabuf-header.patch"
	"${FILESDIR}/0033-FROMGIT-Input-add-privacy-screen-toggle-keycode.patch"
	"${FILESDIR}/0034-UPSTREAM-Input-add-REL_WHEEL_HI_RES-and-REL_HWHEEL_H.patch"
	"${FILESDIR}/0035-BACKPORT-Input-Add-FULL_SCREEN-ASPECT_RATIO-SELECTIV.patch"
	"${FILESDIR}/0036-CHROMIUM-Add-fscrypt-header.patch"
	"${FILESDIR}/0038-BACKPORT-Add-io_uring-IO-interface.patch"
	"${FILESDIR}/0039-BACKPORT-net-qualcomm-rmnet-Export-mux_id-and-flags-to-netlink.patch"
	"${FILESDIR}/0040-CHROMIUM-v4l2-add-upstream-V4L2-H.264-stateless-cont.patch"
	"${FILESDIR}/0040-BACKPORT-y2038-add-64-bit-time_t-syscalls-to-all-32-.patch"
	"${FILESDIR}/0042-CHROMIUM-linux-headers-update-headers-with-UVC-1.5-R.patch"
	"${FILESDIR}/0043-BACKPORT-vfs-add-faccessat2-syscall.patch"
	"${FILESDIR}/0044-CHROMIUM-v4l2-controls-use-very-high-ID-for-ROI-auto.patch"
	"${FILESDIR}/0045-CHROMIUM-media-add-vb2-buffer-memory-coherency-hints.patch"
	"${FILESDIR}/0046-CHROMIUM-v4l2-add-upstream-V4L2-VP8-stateless-contro.patch"
	"${FILESDIR}/0047-BACKPORT-drm-add-panfrost_drm.h.patch"
	"${FILESDIR}/0048-ASoC-SOF-Add-userspace-ABI-support.patch"
	"${FILESDIR}/0049-CHROMIUM-v4l2-add-finalized-upstream-V4L2-VP9-statel.patch"
	"${FILESDIR}/0051-BACKPORT-FROMGIT-media-Add-AV1-uAPI.patch"
	"${FILESDIR}/0052-BACKPORT-add-rseq-syscall-definitions.patch"
	"${FILESDIR}/0053-BACKPORT-fanotify-add-support-for-create-attrib-move.patch"
	"${FILESDIR}/0054-BACKPORT-LoadPin-Enable-loading-from-trusted-dm-veri.patch"
	"${FILESDIR}/0055-CHROMIUM-v4l2-add-upstream-V4L2-HEVC-stateless-contr.patch"
	"${FILESDIR}/0056-BACKPORT-add-close_range-syscall-definitions.patch"
	"${FILESDIR}/0057-BACKPORT-fanotify-add-API-to-attach-detach-super-blo.patch"
	"${FILESDIR}/0058-BACKPORT-kexec-file-load.patch"
	"${FILESDIR}/0059-BACKPORT-media-v4l2-Add-v4l2-control-IDs-for-HEVC-encoder.patch"
	"${FILESDIR}/0060-CHROMIUM-Add-dma-heap-header.patch"
	# Only needed for RK3399 libv4lplugins
	"${FILESDIR}/0099-CHROMIUM-v4l-Add-config-store-support.patch"
	"${FILESDIR}/0100-BACKPORT-add-pidfd_open-syscall-definitions.patch"
)

src_unpack() {
	# avoid kernel-2_src_unpack
	default
}

src_prepare() {
	# avoid kernel-2_src_prepare
	default
}

src_install() {
	kernel-2_src_install

	find "${ED}" \( -name '.install' -o -name '*.cmd' \) -delete || die
	# delete empty directories
	find "${ED}" -empty -type d -delete || die
}

src_test() {
	# Make sure no uapi/ include paths are used by accident.
	grep -E -r \
		-e '# *include.*["<]uapi/' \
		"${D}" && die "#include uapi/xxx detected"

	einfo "Possible unescaped attribute/type usage"
	grep -E -r \
		-e '(^|[[:space:](])(asm|volatile|inline)[[:space:](]' \
		-e '\<([us](8|16|32|64))\>' \
		.

	einfo "Missing linux/types.h include"
	grep -E -l -r -e '__[us](8|16|32|64)' "${ED}" | xargs grep -L linux/types.h

	emake ARCH="$(tc-arch-kernel)" headers_check
}
