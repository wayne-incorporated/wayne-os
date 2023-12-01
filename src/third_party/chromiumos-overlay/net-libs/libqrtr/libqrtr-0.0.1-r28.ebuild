# Copyright 1999-2012 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI="5"
CROS_WORKON_COMMIT="ba87335b33afcc0c1e0860ed41d0a98abc804184"
CROS_WORKON_TREE="9fc5b98c54615474f4c167d5034b6eb15475e046"
CROS_WORKON_PROJECT="chromiumos/third_party/libqrtr"

inherit autotools cros-sanitizers cros-workon user

DESCRIPTION="QRTR userspace helper library"
HOMEPAGE="https://github.com/andersson/qrtr"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE="-asan -qrtr_ns"

DEPEND="
	sys-kernel/linux-headers
	virtual/pkgconfig
"

src_prepare() {
	default
	sed -i "/^libdir/s:/lib:/$(get_libdir):" Makefile || die
}

src_configure() {
	sanitizers-setup-env
}

src_install() {
	emake DESTDIR="${D}" prefix="${EPREFIX}/usr" install

	if use qrtr_ns; then
		insinto /etc/init
		doins "${FILESDIR}/qrtr-ns.conf"

		insinto /usr/share/policy
		newins "${FILESDIR}/qrtr-ns-seccomp-${ARCH}.policy" \
			qrtr-ns-seccomp.policy
	fi
}

src_test() {
	# TODO(ejcaruso): upstream some tests for this thing
	:
}

pkg_preinst() {
	if use qrtr_ns; then
		enewuser "qrtr"
		enewgroup "qrtr"
	fi
}
