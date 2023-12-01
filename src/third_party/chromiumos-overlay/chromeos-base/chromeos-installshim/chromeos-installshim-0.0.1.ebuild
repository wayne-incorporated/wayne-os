# Copyright 2012 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Chrome OS Install Shim (meta package)"
HOMEPAGE="https://dev.chromium.org/chromium-os"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"

IUSE="
	cr50_onboard
	+network_time
	tpm_slb9645
	tpm_slb9655
	tpm_slb9655_v4_31
	tpm_slb9670
	internal
	+shill
	ti50_onboard
	tpm2"

X86_DEPEND="
	sys-boot/syslinux
"

# Factory installer
RDEPEND="
	x86? ( ${X86_DEPEND} )
	amd64? ( ${X86_DEPEND} )
	arm? (
		chromeos-base/u-boot-scripts
	)
	app-arch/sharutils
	!tpm2? ( app-crypt/trousers )
	app-shells/bash
	app-shells/dash
	chromeos-base/chromeos-base
	chromeos-base/chromeos-init
	chromeos-base/dev-install
	chromeos-base/factory_installer
	internal? (
		tpm_slb9645? ( chromeos-base/infineon-firmware )
		tpm_slb9655? ( chromeos-base/infineon-firmware )
		tpm_slb9655_v4_31? ( chromeos-base/infineon-firmware )
		tpm_slb9670? ( chromeos-base/infineon-firmware )
	)
	chromeos-base/power_manager
	shill? ( chromeos-base/shill )
	!shill? ( net-misc/dhcpcd )
	chromeos-base/vboot_reference
	cr50_onboard? ( media-gfx/qrencode )
	net-firewall/iptables
	network_time? ( net-misc/tlsdate )
	>=sys-apps/baselayout-2.0.0
	sys-apps/coreutils
	sys-apps/dbus
	sys-apps/flashrom
	sys-apps/grep
	sys-apps/kmod[tools]
	sys-apps/iproute2
	sys-apps/mawk
	sys-apps/mosys
	sys-apps/net-tools
	sys-apps/pv
	sys-apps/rootdev
	sys-apps/sed
	sys-apps/shadow
	sys-apps/upstart
	sys-apps/util-linux
	sys-apps/which
	sys-auth/pam_pwdfile
	sys-fs/e2fsprogs
	sys-libs/gcc-libs
	sys-libs/libcxx
	sys-process/lsof
	sys-process/procps
	ti50_onboard? ( media-gfx/qrencode )
	virtual/chromeos-auth-config
	virtual/chromeos-bsp
	virtual/udev
"

S=${WORKDIR}
