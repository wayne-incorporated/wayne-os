# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
#
# To update this ebuild, you should first run files/gather.sh which
# will update the binary in the bucket. Then, you can change the
# ebuild to the current date.

EAPI=7

DESCRIPTION="Ebuild for Android mk_payload tool."

# Files will be uploaded here by gather.sh
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="-* amd64"
IUSE=""

S="${WORKDIR}"

QA_PREBUILT="*"

src_install() {
	# Install mk_payload into /opt/bin alongside the other prebuilt
	# binaries.
	into '/opt'
	newbin "${P}" 'mk_payload'
}
