# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="../platform/empty-project"

inherit cros-workon cros-fwupd

DESCRIPTION="Installs eMMC firmware update files used by fwupd."
HOMEPAGE="https://fwupd.org/downloads"

KEYWORDS="~*"

FILENAMES=(
	"ee85c8b40e538cd41ecbdd0d10ef7ef6f48c12eddffe1c934c988ef8f77f375e-MCEM131.cab"
)
SRC_URI="${FILENAMES[*]/#/${CROS_FWUPD_URL}/}"
LICENSE="LVFS-Vendor-Agreement-v1"

DEPEND=""
RDEPEND="sys-apps/fwupd"
