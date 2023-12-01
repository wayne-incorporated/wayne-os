# Copyright 2022 The ChromiumOS Authors
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
	"be2c9146ff4cfac5d647376c39ce0b78151e9f1a785a287e93ac3968aff2ed50-GenesysLogic_GL3590_64.17.cab"
)
SRC_URI="${FILENAMES[*]/#/${CROS_FWUPD_URL}/}"
LICENSE="LVFS-Vendor-Agreement-v1"

DEPEND=""
RDEPEND="sys-apps/fwupd"
