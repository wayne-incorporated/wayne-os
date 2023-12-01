# Copyright 1999-2015 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/net-misc/dhcpcd/dhcpcd-6.8.2.ebuild,v 1.1 2015/05/05 13:20:12 williamh Exp $

EAPI=7

MY_P="${P/_alpha/-alpha}"
MY_P="${MY_P/_beta/-beta}"
MY_P="${MY_P/_rc/-rc}"
SRC_URI="https://github.com/NetworkConfiguration/${PN}/archive/refs/tags/${MY_P}.tar.xz"
KEYWORDS="*"
S="${WORKDIR}/${MY_P}"

inherit cros-sanitizers eutils systemd toolchain-funcs user

DESCRIPTION="A fully featured, yet light weight RFC2131 compliant DHCP client"
HOMEPAGE="http://roy.marples.name/projects/dhcpcd/"
LICENSE="BSD-2"
SLOT="0"
IUSE="elibc_glibc +embedded kernel_linux +udev +dbus"

COMMON_DEPEND="udev? ( virtual/udev )
		dbus? ( sys-apps/dbus )"
DEPEND="${COMMON_DEPEND}"
RDEPEND="${COMMON_DEPEND}"

src_prepare()
{
	eapply "${FILESDIR}"/patches/${P}-Optionally-ARP-for-gateway-IP-address.patch
	eapply "${FILESDIR}"/patches/${P}-Teach-DHCP-client-to-do-unicast-ARP-for-gateway.patch
	eapply "${FILESDIR}"/patches/${P}-Fix-dhcpcd-running-as-a-regular-user.patch
	eapply "${FILESDIR}"/patches/${P}-Allow-lease-file-to-be-set-on-command-line.patch
	eapply "${FILESDIR}"/patches/${P}-Be-more-permissive-on-NAKs.patch
	eapply "${FILESDIR}"/patches/${P}-Accept-an-ACK-after-a-NAK.patch
	eapply "${FILESDIR}"/patches/${P}-Track-and-validate-disputed-addresses.patch
	eapply "${FILESDIR}"/patches/${P}-Fix-OOB-read-in-dhcpcd.patch
	eapply "${FILESDIR}"/patches/${P}-Merge-in-DHCP-options-from-the-original-offer.patch
	eapply "${FILESDIR}"/patches/${P}-Add-RPC-support-for-DHCPv4-client.patch
	eapply "${FILESDIR}"/patches/${P}-Add-ability-to-disable-hook-scripts.patch
	eapply "${FILESDIR}"/patches/${P}-Improve-debugability.patch
	eapply "${FILESDIR}"/patches/${P}-Add-DBus-RPC-support.patch
	eapply "${FILESDIR}"/patches/${P}-Ensure-gateway-probe-is-broadcast.patch
	eapply "${FILESDIR}"/patches/${P}-Change-vendor_encapsulated_options-to-binhex.patch
	eapply "${FILESDIR}"/patches/${P}-Handle-DHCP-iSNS-option.patch
	eapply "${FILESDIR}"/patches/${P}-Add-more-ARP-related-info-to-logs.patch
	eapply "${FILESDIR}"/patches/${P}-Stop-only-active-interfaces-via-DBus.patch
	eapply "${FILESDIR}"/patches/${P}-Include-frame-header-in-buffer-length.patch
	eapply "${FILESDIR}"/patches/${P}-Correct-length-check-in-BPF-ARP-filter.patch
	eapply "${FILESDIR}"/patches/${P}-More-robust-checks-for-packet-reception.patch
	eapply "${FILESDIR}"/patches/${P}-Additional-ARP-packet-checks.patch
	eapply "${FILESDIR}"/patches/${P}-Fix-handling-of-hostname-argument.patch
	eapply "${FILESDIR}"/patches/${P}-Drop-ARP-on-DHCP-drop.patch
	eapply "${FILESDIR}"/patches/${P}-Implement-IPv6-Only-Preferred-option-RFC-8925.patch
	eapply "${FILESDIR}"/patches/${P}-Notify-dbus-upon-receiving-RFC8925-option-108.patch
	eapply "${FILESDIR}"/patches/${P}-Protect-against-crash-in-get_lease.patch

	default
}

src_configure()
{
	sanitizers-setup-env

	local dev hooks
	use udev || dev="--without-dev --without-udev"
	if ! use dbus ; then
		hooks="--with-hook=ntp.conf"
		use elibc_glibc && hooks="${hooks} --with-hook=yp.conf"
	fi
	econf \
		--prefix= \
		--libexecdir=/lib/dhcpcd \
		--dbdir=/var/lib/dhcpcd \
		--rundir=/run/dhcpcd \
		"$(use_enable embedded)" \
		"$(use_enable dbus)" \
		${dev} \
		--disable-inet6 \
		CC="$(tc-getCC)" \
		${hooks}
	# Update DUID file path so it is writable by dhcp user.
	echo '#define DUID DBDIR "/" PACKAGE ".duid"' >> "${S}/config.h"
}

src_install()
{
	default
	newinitd "${FILESDIR}"/${PN}.initd ${PN}
	systemd_dounit "${FILESDIR}"/${PN}.service
}

pkg_preinst()
{
	enewuser "dhcp"
	enewgroup "dhcp"
}

pkg_postinst()
{
	# Upgrade the duid file to the new format if needed
	local old_duid="${ROOT}"/var/lib/dhcpcd/dhcpcd.duid
	local new_duid="${ROOT}"/etc/dhcpcd.duid
	if [ -e "${old_duid}" ] && ! grep -q '..:..:..:..:..:..' "${old_duid}"; then
		sed -i -e 's/\(..\)/\1:/g; s/:$//g' "${old_duid}"
	fi

	# Move the duid to /etc, a more sensible location
	if [[ -e "${old_duid}" && ! -e "${new_duid}" ]]; then
		cp -p "${old_duid}" "${new_duid}"
	fi

	if [ -z "${REPLACING_VERSIONS}" ]; then
		elog
		elog "dhcpcd has zeroconf support active by default."
		elog "This means it will always obtain an IP address even if no"
		elog "DHCP server can be contacted, which will break any existing"
		elog "failover support you may have configured in your net configuration."
		elog "This behaviour can be controlled with the noipv4ll configuration"
		elog "file option or the -L command line switch."
		elog "See the dhcpcd and dhcpcd.conf man pages for more details."

		elog
		elog "Dhcpcd has duid enabled by default, and this may cause issues"
		elog "with some dhcp servers. For more information, see"
		elog "https://bugs.gentoo.org/show_bug.cgi?id=477356"
	fi

	if ! has_version net-dns/bind-tools; then
		elog
		elog "If you activate the lookup-hostname hook to look up your hostname"
		elog "using the dns, you need to install net-dns/bind-tools."
	fi
}
