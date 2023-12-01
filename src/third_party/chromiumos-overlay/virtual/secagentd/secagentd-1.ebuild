# Copyright 2012 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Chrome OS Security Agent virtual package that will only install secagentd on
platforms with a supported kernel."
HOMEPAGE="http://src.chromium.org"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"

IUSE="kernel-4_4 kernel-4_14 kernel-4_19 kernel-5_4 "

# Bring in secagentd only on newer kernels.
RDEPEND="!kernel-4_4? ( !kernel-4_14? ( !kernel-4_19? ( !kernel-5_4? ( chromeos-base/secagentd ) ) ) )
"
