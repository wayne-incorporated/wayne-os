# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "083569b82e5bcbfefd8700a2cd52ea619e712f7a" "2d35bb62ab011b4878b494d24cf5e26cb0d9ebc1" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
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
KEYWORDS="*"

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
