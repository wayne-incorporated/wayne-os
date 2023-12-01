# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/klauspost/compress v${PV}"

CROS_GO_PACKAGES=(
	"github.com/klauspost/compress/..."
)

inherit cros-go

DESCRIPTION="Provides various compression algorithms in Go."
HOMEPAGE="https://github.com/klauspost/compress"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND=""
RDEPEND="${DEPEND}"
