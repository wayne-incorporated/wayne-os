# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# Changing the revision (-rX) of this ebuild causes a rebuild of
# all Rust code in Chromium OS. This can be used to force rebuilds
# for changes that Portage otherwise wouldn't think necessitate a
# rebuild, such as changes to cros-rust.eclass.

EAPI=7

DESCRIPTION="Virtual for the Rust language"
LICENSE="metapackage"
SLOT="0/${PVR}"
KEYWORDS="*"
