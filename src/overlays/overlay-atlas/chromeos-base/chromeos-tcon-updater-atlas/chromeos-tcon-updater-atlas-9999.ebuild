# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the BSD license.

EAPI="7"

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit cros-workon

DESCRIPTION="TCON firmware updater entry point for Atlas."

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="~*"

RDEPEND="
	chromeos-base/chromeos-nvt-tcon-updater
	chromeos-base/chromeos-tcon-updater-configs-atlas
	sys-firmware/chromeos-tcon-firmware-atlas-fhd
	sys-firmware/chromeos-tcon-firmware-atlas-uhd
"

src_install() {
	exeinto /opt/google/tcon/scripts
	doexe "${FILESDIR}/chromeos-tcon-update.sh"
}
