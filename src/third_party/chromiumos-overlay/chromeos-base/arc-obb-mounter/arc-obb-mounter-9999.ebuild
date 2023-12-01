# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_INCREMENTAL_BUILD="1"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk arc/container/obb-mounter .gn"

PLATFORM_SUBDIR="arc/container/obb-mounter"

inherit cros-workon platform

DESCRIPTION="D-Bus service to mount OBB files"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/arc/container/obb-mounter"

LICENSE="BSD-Google"
KEYWORDS="~*"

RDEPEND="
	sys-fs/fuse:=
	sys-libs/libcap:=
"

DEPEND="${RDEPEND}"

BDEPEND="
	virtual/pkgconfig
"


CONTAINER_DIR="/opt/google/containers/arc-obb-mounter"

src_install() {
	platform_src_install

	# Keep the parent directory of mountpoints inaccessible from non-root
	# users because mountpoints themselves are often world-readable but we
	# do not want to expose them.
	# container-root is where the root filesystem of the container in which
	# arc-obb-mounter daemon runs is mounted.
	diropts --mode=0700 --owner=root --group=root
	keepdir "${CONTAINER_DIR}"/mountpoints/
	keepdir "${CONTAINER_DIR}"/mountpoints/container-root

	local fuzzer_component_id="516669"
	platform_fuzzer_install "${S}"/OWNERS "${OUT}"/mount-obb_fuzzer \
		--comp "${fuzzer_component_id}"
}

platform_pkg_test() {
	platform test_all
}
