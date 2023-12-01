# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit cros-sanitizers

DESCRIPTION="DIAG channel diagnostics communication tool"
HOMEPAGE="https://github.com/andersson/diag"
GIT_SHA1="d06e599d197790c9e84ac41a51bf124a69768c4f"
SRC_URI="https://github.com/andersson/diag/archive/${GIT_SHA1}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="
	net-libs/libqrtr:=
	virtual/udev:=
"

DEPEND="${RDEPEND}
	net-misc/libdiagcfg:=
"

S="${WORKDIR}/${PN}-${GIT_SHA1}"

src_prepare() {
	default
	eapply "${FILESDIR}/patches/0001-ODL-support-on-Open-Source-Diag-Router.patch"
	eapply "${FILESDIR}/patches/0002-Send_data-Fix-for-Timeout-Error-in-DIAG-output.patch"
	eapply "${FILESDIR}/patches/0003-Add-static-library-with-default-config-file-and-embe.patch"
}

src_configure() {
	sanitizers-setup-env
	default
}

src_compile() {
	# The public libdiagcfg package (version <= 0.1) is a dummy.
	if has_version ">=net-misc/libdiagcfg-0.1"; then
		has_libdiagcfg=1
	else
		has_libdiagcfg=0
	fi

	emake HAVE_LIBUDEV=1 HAVE_LIBQRTR=1 "HAVE_LIBDIAGCFG=${has_libdiagcfg}"
}

src_install() {
	emake DESTDIR="${D}" prefix="${EPREFIX}/usr" install
}
