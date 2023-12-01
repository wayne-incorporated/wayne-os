# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit tmpfiles udev

DESCRIPTION="Op-Tee non-secure side client library and tee-supplicant"
HOMEPAGE="https://github.com/OP-TEE/optee_client"
SRC_URI="https://github.com/OP-TEE/optee_client/archive/refs/tags/${PV}.zip -> ${P}.zip"

LICENSE="BSD"
KEYWORDS="*"
SLOT="0"
IUSE=""

src_configure() {
	export CFG_TEE_FS_PARENT_PATH="/var/lib/oemcrypto/tee-supplicant"
	export LIBDIR="/usr/$(get_libdir)"
}

src_install() {
	default_src_install

	# Install the init script.
	insinto /etc/init
	doins "${FILESDIR}"/init/tee-supplicant.conf

	# Install tmpfiles script for generating the necessary directory.
	dotmpfiles "${FILESDIR}"/tmpfiles.d/tee-supplicant.conf

	# Setup udev rules.
	udev_dorules "${FILESDIR}"/udev/*-optee.rules
}
