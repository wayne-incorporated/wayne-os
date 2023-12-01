# This file is Copyright 2020 The ChromiumOS Authors
# This file is distributed under the terms of the BSD license.

EAPI="7"

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit cros-workon

DESCRIPTION="Novatek TCON firmware updater config files for Atlas."

LICENSE="BSD-Novatek"
SLOT="0/0"
KEYWORDS="~*"

src_install() {
	insinto /opt/google/tcon/configs
	doins "${FILESDIR}"/*.ini
}
