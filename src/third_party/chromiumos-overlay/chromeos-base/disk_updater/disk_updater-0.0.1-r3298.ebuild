# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"
CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "6e679bfa3186b8aed73e85f74ce2063929d906ec" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk disk_updater .gn"

PLATFORM_SUBDIR="disk_updater"

inherit cros-workon platform

DESCRIPTION="Root disk firmware updater"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/disk_updater/"
SRC_URI=""

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="+sata mmc nvme"

DEPEND="
	test? (
		sys-apps/diffutils
	)
"

RDEPEND="
	chromeos-base/chromeos-common-script
	dev-util/shflags
	sata? ( sys-apps/hdparm )
	mmc? ( sys-apps/mmc-utils )
	nvme? ( sys-apps/nvme-cli )
"

platform_pkg_test() {
	# We can test all, even if mmc or nvme are not installed.
	local tests=( 'ata' 'mmc' 'nvme')

	local test_type
	for test_type in "${tests[@]}"; do
		platform_test "run" "tests/chromeos-disk-firmware-${test_type}-test.sh"
	done
}
