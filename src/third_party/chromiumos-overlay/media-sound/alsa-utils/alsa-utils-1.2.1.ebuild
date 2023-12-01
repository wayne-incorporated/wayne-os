# Copyright 1999-2020 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
inherit systemd udev

DESCRIPTION="Advanced Linux Sound Architecture Utils (alsactl, alsamixer, etc.)"
HOMEPAGE="https://alsa-project.org/"
SRC_URI="https://www.alsa-project.org/files/pub/utils/${P}.tar.bz2"

LICENSE="GPL-2"
SLOT="0.9"
KEYWORDS="*"
IUSE="bat doc +libsamplerate +ncurses nls selinux"

CDEPEND=">=media-libs/alsa-lib-${PV}
	libsamplerate? ( media-libs/libsamplerate )
	ncurses? ( >=sys-libs/ncurses-5.7-r7:0= )
	bat? ( sci-libs/fftw:= )"
DEPEND="${CDEPEND}
	doc? ( app-text/xmlto )"
RDEPEND="${CDEPEND}
	selinux? ( sec-policy/selinux-alsa )"
BDEPEND="virtual/pkgconfig"

PATCHES=(
	"${FILESDIR}"/${PN}-1.1.8-missing_header.patch
	"${FILESDIR}"/${PN}-1.2.1-alsaucm-Fix-ending-with-quotes-commands.patch
	"${FILESDIR}"/${PN}-1.2.1-aplay-Fix-conversion-of-unsigned-samples.patch
	"${FILESDIR}"/${PN}-1.2.1-aplay-Handle-16bit-sample-negative-overf.patch
	"${FILESDIR}"/${PN}-1.2.1-aplay-Don-t-pass-most-negative-integer-t.patch
	"${FILESDIR}"/${PN}-1.2.1-aplay-Handle-upper-bound-in-peak-calcula.patch
	"${FILESDIR}"/${PN}-1.2.1-aplay-Fix-out-of-bound-access-in-stereo-.patch
)

src_configure() {
	local myeconfargs=(
		# --disable-alsaconf because it doesn't work with sys-apps/kmod wrt #456214
		--disable-alsaconf
		--disable-maintainer-mode
		--with-asound-state-dir="${EPREFIX}"/var/lib/alsa
		--with-systemdsystemunitdir="$(systemd_get_systemunitdir)"
		--with-udev-rules-dir="${EPREFIX}/$(get_udevdir)"/rules.d
		$(use_enable bat)
		$(use_enable libsamplerate alsaloop)
		$(use_enable ncurses alsamixer)
		$(use_enable nls)
		$(usex doc '' --disable-xmlto)
	)
	econf "${myeconfargs[@]}"
}

src_install() {
	default
	dodoc seq/*/README.*

	newinitd "${FILESDIR}"/alsasound.initd-r8 alsasound
	newconfd "${FILESDIR}"/alsasound.confd-r4 alsasound

	insinto /etc/modprobe.d
	newins "${FILESDIR}"/alsa-modules.conf-rc alsa.conf

	keepdir /var/lib/alsa

	# ALSA lib parser.c:1266:(uc_mgr_scan_master_configs) error: could not
	# scan directory /usr/share/alsa/ucm: No such file or directory
	# alsaucm: unable to obtain card list: No such file or directory
	keepdir /usr/share/alsa/ucm
}
