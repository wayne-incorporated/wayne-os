# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Keeby board-specific ebuild to override
Chrome OS BSP virtual package"
HOMEPAGE="http://src.chromium.org"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="-* amd64 x86"

RDEPEND="chromeos-base/chromeos-bsp-keeby"
DEPEND="${RDEPEND}"
