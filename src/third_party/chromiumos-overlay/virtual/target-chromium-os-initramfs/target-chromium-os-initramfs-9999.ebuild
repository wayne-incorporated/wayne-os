# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="../platform/empty-project"

inherit cros-workon

DESCRIPTION="List of packages that are needed inside the Chromium OS initramfs"
HOMEPAGE="https://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="~*"

IUSE="
	minios
"

RDEPEND="
	minios? ( chromeos-base/minios )
"
