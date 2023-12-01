# Copyright 1999-2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="6"
inherit linux-info systemd user

DESCRIPTION="IPsec-based VPN solution, supporting IKEv1/IKEv2 and MOBIKE"
HOMEPAGE="https://www.strongswan.org/"
SRC_URI="https://download.strongswan.org/${P}.tar.bz2"

LICENSE="GPL-2 RSA DES"
SLOT="0"
KEYWORDS="*"
IUSE="+caps curl +constraints debug dhcp eap farp gcrypt +gmp ldap mysql networkmanager +non-root +openssl selinux sqlite systemd pam pkcs11"

STRONGSWAN_PLUGINS_STD="lookip systime-fix unity vici"
STRONGSWAN_PLUGINS_OPT="aesni blowfish bypass-lan ccm chapoly ctr forecast gcm
ha ipseckey newhope ntru padlock rdrand save-keys unbound whitelist
xauth-noauth"
for mod in $STRONGSWAN_PLUGINS_STD; do
	IUSE="${IUSE} +strongswan_plugins_${mod}"
done

for mod in $STRONGSWAN_PLUGINS_OPT; do
	IUSE="${IUSE} strongswan_plugins_${mod}"
done

COMMON_DEPEND="!net-misc/openswan
	gmp? ( >=dev-libs/gmp-4.1.5:= )
	gcrypt? ( dev-libs/libgcrypt:0 )
	caps? ( sys-libs/libcap )
	curl? ( net-misc/curl )
	ldap? ( net-nds/openldap )
	openssl? ( >=dev-libs/openssl-0.9.8:=[-bindist(-)] )
	mysql? ( dev-db/mysql-connector-c:= )
	sqlite? ( >=dev-db/sqlite-3.3.1 )
	systemd? ( sys-apps/systemd )
	networkmanager? ( net-misc/networkmanager )
	pam? ( sys-libs/pam )
	strongswan_plugins_unbound? ( net-dns/unbound:= net-libs/ldns )"
DEPEND="${COMMON_DEPEND}
	virtual/linux-sources
	sys-kernel/linux-headers"
RDEPEND="${COMMON_DEPEND}
	virtual/logger
	sys-apps/iproute2
	!net-vpn/libreswan
	selinux? ( sec-policy/selinux-ipsec )"

UGID="vpn"

pkg_setup() {
	linux-info_pkg_setup

	elog "Linux kernel version: ${KV_FULL}"

	if ! kernel_is -ge 2 6 16; then
		eerror
		eerror "This ebuild currently only supports ${PN} with the"
		eerror "native Linux 2.6 IPsec stack on kernels >= 2.6.16."
		eerror
	fi

	if kernel_is -lt 2 6 34; then
		ewarn
		ewarn "IMPORTANT KERNEL NOTES: Please read carefully..."
		ewarn

		if kernel_is -lt 2 6 29; then
			ewarn "[ < 2.6.29 ] Due to a missing kernel feature, you have to"
			ewarn "include all required IPv6 modules even if you just intend"
			ewarn "to run on IPv4 only."
			ewarn
			ewarn "This has been fixed with kernels >= 2.6.29."
			ewarn
		fi

		if kernel_is -lt 2 6 33; then
			ewarn "[ < 2.6.33 ] Kernels prior to 2.6.33 include a non-standards"
			ewarn "compliant implementation for SHA-2 HMAC support in ESP and"
			ewarn "miss SHA384 and SHA512 HMAC support altogether."
			ewarn
			ewarn "If you need any of those features, please use kernel >= 2.6.33."
			ewarn
		fi

		if kernel_is -lt 2 6 34; then
			ewarn "[ < 2.6.34 ] Support for the AES-GMAC authentification-only"
			ewarn "ESP cipher is only included in kernels >= 2.6.34."
			ewarn
			ewarn "If you need it, please use kernel >= 2.6.34."
			ewarn
		fi
	fi

	if use non-root; then
		enewgroup ${UGID}
		enewuser ${UGID} -1 -1 -1 ${UGID}
	fi
}

src_prepare() {
	epatch "${FILESDIR}/${PN}-5.5.0-5.9.4_eap_success.patch"
	epatch "${FILESDIR}/${PN}-5.1.0-5.9.7_cert_online_validate.patch"
	default
}

src_configure() {
	append-flags "-DSTARTER_ALLOW_NON_ROOT" "-DSKIP_KERNEL_IPSEC_MODPROBES"
	local myconf=""

	if use non-root; then
		# `with-user` and `with-group` options are removed since charon is
		# already started as vpn:vpn user and group, and it does not need to
		# change user and group by itself. This allows us to remove CAP_SETGID
		# when running it.
		myconf="${myconf} --with-piddir=/run/ipsec"
	fi

	# If a user has already enabled db support, those plugins will
	# most likely be desired as well. Besides they don't impose new
	# dependencies and come at no cost (except for space).
	if use mysql || use sqlite; then
		myconf="${myconf} --enable-attr-sql --enable-sql"
	fi

	# strongSwan builds and installs static libs by default which are
	# useless to the user (and to strongSwan for that matter) because no
	# header files or alike get installed... so disabling them is safe.
	if use pam && use eap; then
		myconf="${myconf} --enable-eap-gtc"
	else
		myconf="${myconf} --disable-eap-gtc"
	fi

	for mod in $STRONGSWAN_PLUGINS_STD; do
		if use strongswan_plugins_${mod}; then
			myconf+=" --enable-${mod}"
		fi
	done

	for mod in $STRONGSWAN_PLUGINS_OPT; do
		if use strongswan_plugins_${mod}; then
			myconf+=" --enable-${mod}"
		fi
	done

	# Some of the unneeded options are disabled or removed.
	# See https://crrev.com/c/3418633 and https://crrev.com/c/3934003
	econf \
		--disable-static \
		--enable-ikev1 \
		--enable-ikev2 \
		--enable-swanctl \
		--enable-socket-dynamic \
		--disable-stroke \
		--disable-updown \
		$(use_enable curl) \
		$(use_enable constraints) \
		$(use_enable ldap) \
		$(use_enable debug leak-detective) \
		$(use_enable dhcp) \
		$(use_enable eap eap-identity) \
		$(use_enable eap eap-mschapv2) \
		$(use_enable farp) \
		$(use_enable gmp) \
		$(use_enable gcrypt) \
		$(use_enable mysql) \
		$(use_enable networkmanager nm) \
		$(use_enable openssl) \
		$(use_enable pam xauth-pam) \
		$(use_enable pkcs11) \
		$(use_enable sqlite) \
		$(use_enable systemd) \
		$(use_with caps capabilities libcap) \
		--with-piddir=/run \
		--with-systemdsystemunitdir="$(systemd_get_systemunitdir)" \
		${myconf}
}

src_install() {
	emake DESTDIR="${D}" install

	if ! use systemd; then
		rm -rf "${ED}"/lib/systemd || die "Failed removing systemd lib."
	fi

	doinitd "${FILESDIR}"/ipsec

	local dir_ugid
	if use non-root; then
		fowners ${UGID}:${UGID} \
			/etc/strongswan.conf

		dir_ugid="${UGID}"
	else
		dir_ugid="root"
	fi

	diropts -m 0750 -o ${dir_ugid} -g ${dir_ugid}
	dodir /etc/ipsec.d \
		/etc/ipsec.d/aacerts \
		/etc/ipsec.d/acerts \
		/etc/ipsec.d/cacerts \
		/etc/ipsec.d/certs \
		/etc/ipsec.d/crls \
		/etc/ipsec.d/ocspcerts \
		/etc/ipsec.d/private \
		/etc/ipsec.d/reqs

	# Replace various IPsec files with symbolic links to runtime generated
	# files (by l2tpipsec_vpn) in /run on Chromium OS.
	local link_path=/run/l2tpipsec_vpn/current
	for cfg_file in \
		/etc/ipsec.secrets \
		/etc/ipsec.d/cacerts/cacert.der \
		/etc/strongswan.conf; do
		rm -f "${D}${cfg_file}"
		dosym "${link_path}/$(basename $cfg_file)" "${cfg_file}"
	done

	dodoc NEWS README TODO

	# shared libs are used only internally and there are no static libs,
	# so it's safe to get rid of the .la files
	find "${D}" -name '*.la' -delete || die "Failed to remove .la files."
}
