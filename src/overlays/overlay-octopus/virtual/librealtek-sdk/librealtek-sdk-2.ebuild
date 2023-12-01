# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Virtual for librealtek-sdk packages (source or prebuilt binaries)"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="-* amd64 x86"

RDEPEND="
	media-libs/librealtek-sdk-bin
"
DEPEND="${RDEPEND}"
