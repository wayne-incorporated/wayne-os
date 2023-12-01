# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
inherit cros-workon dlc

# No git repo for this so use empty-project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

DESCRIPTION="DLC of Jens Axboe's Flexible IO tester"
HOMEPAGE=""
SRC_URI=""

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
S="${WORKDIR}"

IUSE="dlc"
REQUIRED_USE="dlc"

DEPEND="
	sys-block/fio:=
"

# fio is about 1.4MB. Provides a generous buffer of 2 MiB.
# Since the physical extents in CrOS is 4MiB, we can directly set 4MiB.
# 4MiB = 4 * 256 * (4KiB blocks).
DLC_PREALLOC_BLOCKS="$((4 * 256))"
DLC_NAME="Fio DLC"

# Tast tests for healthd's disk performance routine.
DLC_PRELOAD=true

# Enabled scaled design.
DLC_SCALED=true

# Don't need to unpack anything.
src_unpack() {
	:
}

src_install() {
	# Install into DLC path.
	into "$(dlc_add_path /)"

	dobin "${SYSROOT}/usr/bin/fio"

	dlc_src_install
}
