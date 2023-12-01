# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# See https://crbug.com/386603 for why we download a prebuilt binary instead of
# compiling it ourselves.

EAPI="7"

# When the time comes to roll to a new version, download the new gn binary at
# https://chrome-infra-packages.appspot.com/p/gn/gn/linux-amd64/+/
# and run `gn --version` to get the right version number for the ebuild.
#
# After that, update INSTANCE_ID below with the new cipd version.
# Finally, run `FEATURES=-force-mirror ebuild <ebuild file name> manifest` to
# download the archive & update the Manifest file.

INSTANCE_ID="qVwpVE5YG1bB0_GSBjep9RiYmzt0TWsiNP6N5jSs3fEC"

DESCRIPTION="GN (generate ninja) meta-build system"
HOMEPAGE="https://gn.googlesource.com/gn/"
SRC_URI="cipd://gn/gn/linux-amd64:${INSTANCE_ID} -> ${P}-amd64.zip"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64"
IUSE=""

# We control the cipd infra, so it's fine to not require it to be mirrored.
RESTRICT="mirror"

S="${WORKDIR}"

src_install() {
	dobin gn
}
