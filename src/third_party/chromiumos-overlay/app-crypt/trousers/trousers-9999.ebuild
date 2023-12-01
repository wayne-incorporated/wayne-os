# Copyright 1999-2009 Gentoo Foundation
# Copyright 2010 Google, Inc.
# Distributed under the terms of the GNU General Public License v2
# $Header$

EAPI="7"
CROS_WORKON_PROJECT="chromiumos/third_party/trousers"
CROS_WORKON_EGIT_BRANCH="chromeos-0.3.13"

inherit autotools cros-debug cros-sanitizers cros-workon flag-o-matic libchrome systemd tmpfiles user

DESCRIPTION="An open-source TCG Software Stack (TSS) v1.1 implementation"
HOMEPAGE="http://trousers.sf.net"
LICENSE="CPL-1.0"
KEYWORDS="~*"
SLOT="0"
IUSE="asan doc mocktpm systemd tpm_dynamic tss_trace"

COMMON_DEPEND="
	chromeos-base/libhwsec-foundation
	>=chromeos-base/metrics-0.0.1-r3152
	>=dev-libs/openssl-0.9.7:0="

RDEPEND="${COMMON_DEPEND}"

DEPEND="${COMMON_DEPEND}"

## TODO: Check if this patch is useful for us.
## PATCHES=(	"${FILESDIR}/${PN}-0.2.3-nouseradd.patch" )

pkg_setup() {
	# New user/group for the daemon
	enewgroup tss
	enewuser tss
}

src_prepare() {
	sed -e "s/-Werror //" -i configure.in
	export FUZZER="$(usev fuzzer)"
	eautoreconf

	default
}

src_configure() {
	sanitizers-setup-env
	use tss_trace && append-cppflags -DTSS_TRACE
	use mocktpm && append-cppflags -DMOCK_TPM
	use fuzzer && append-cppflags -DFUZZED_TPM

	cros-debug-add-NDEBUG
	export BASE_VER="$(libchrome_ver)"
	econf
}

src_install() {
	default
	dodoc NICETOHAVES
	use doc && dodoc doc/*

	# Install the empty system.data files
	dodir /etc/trousers
	insinto /etc/trousers
	doins "${S}"/dist/system.data.*

	# Install the init scripts
	if use systemd; then
		systemd_dounit init/*.service
		systemd_enable_service boot-services.target tcsd.service
		systemd_enable_service boot-services.target tpm-probe.service
	else
		insinto /etc/init
		doins init/*.conf

		if use tpm_dynamic; then
			sed -i '/env TPM_DYNAMIC=/s:=.*:=true:' \
				"${D}/etc/init/tpm-probe.conf" ||
				die "Can't activate tpm_dynamic in tpm-probe.conf"
		fi
	fi
	exeinto /usr/share/cros/init
	doexe init/tcsd-pre-start.sh
	dotmpfiles tmpfiles.d/tcsd.conf
}

pkg_postinst() {
	elog "If you have problems starting tcsd, please check permissions and"
	elog "ownership on /dev/tpm* and ~tss/system.data"
}
