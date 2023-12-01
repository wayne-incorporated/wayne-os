# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_DESTDIR="${S}/platform2"
# TODO(crbug.com/809389): Avoid directly including headers from other packages.
CROS_WORKON_SUBTREE="common-mk libpasswordprovider smbfs .gn"

PLATFORM_SUBDIR="smbfs"

inherit cros-workon platform user

DESCRIPTION="FUSE filesystem to mount SMB shares."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/smbfs/"

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="~*"

COMMON_DEPEND="
	=sys-fs/fuse-2.9*:=
	net-fs/samba:=
"

RDEPEND="${COMMON_DEPEND}"
DEPEND="
	${COMMON_DEPEND}
	chromeos-base/system_api:=
	chromeos-base/libpasswordprovider:=
"

pkg_setup() {
	# Has to be done in pkg_setup() instead of pkg_preinst() since
	# src_install() needs <daemon_user> and <daemon_group>.
	enewuser "fuse-smbfs"
	enewgroup "fuse-smbfs"
	cros-workon_pkg_setup
}

src_install() {
	platform_src_install

	dosbin "${OUT}"/smbfs

	local daemon_store="/etc/daemon-store/smbfs"
	dodir "${daemon_store}"
	fperms 0700 "${daemon_store}"
	fowners fuse-smbfs:fuse-smbfs "${daemon_store}"
}

platform_pkg_test() {
	local tests=(
		smbfs_test
	)

	local test_bin
	for test_bin in "${tests[@]}"; do
		platform_test "run" "${OUT}/${test_bin}"
	done
}
