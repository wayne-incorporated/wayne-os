# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Prevent needing to build dev-rust/bindgen for each board."
# For ebuilds that need to BDEPEND on dev-rust/bindgen, add:
#     DEPEND="virtual/bindgen:="
# This will trigger a rebuild when the slot of dev-rust/bindgen changes
# without requiring the package to DEPEND on dev-rust/bindgen directly.

LICENSE="metapackage"
KEYWORDS="*"

SLOT="0/${PVR}"

# The versions of this ebuild needs to closely match the versions of
# dev-rust/bindgen.
BDEPEND="~dev-rust/bindgen-${PV}"
