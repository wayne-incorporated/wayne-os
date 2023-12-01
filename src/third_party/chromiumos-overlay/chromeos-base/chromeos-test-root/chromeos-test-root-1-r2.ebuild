# Copyright 2012 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# 1) Normally, test image packages are merged into the stateful partition
# 2) Some test packages require files in the root file system (e.g.
#    upstart jobs must live in /etc/init).
# 3) There's an extra emerge command for this package in
#    build_library/test_image_util.sh that specifically merges this
#    package into the root before merging the remaining test packages
#    into stateful.

EAPI="7"

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit cros-workon

DESCRIPTION="Install packages that must live in the rootfs in test images"
HOMEPAGE="https://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
# Include bootchart in the test image unless explicitly disabled. Bootchart is
# disabled by default and enabled by the "cros_bootchart" kernel arg.
IUSE="
	asan
	+bootchart
	dlc
	hps
	pvs
	ubsan
"

RDEPEND="
	bootchart? ( app-benchmarks/bootchart )
	chromeos-base/chromeos-test-init
	chromeos-base/update-utils
	dlc? ( chromeos-base/test-dlc )
	hps? (
		!asan? (
			!ubsan? ( chromeos-base/hps-firmware-images-latest )
		)
	)
	media-libs/cros-camera-hal-fake
	pvs? ( chromeos-base/chromeos-docker )
	chromeos-base/node_exporter
	virtual/chromeos-test-testauthkeys
	virtual/chromeos-bsp-test-root
"
