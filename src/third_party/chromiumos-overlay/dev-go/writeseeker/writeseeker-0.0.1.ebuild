# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/orcaman/writerseeker 1d3f536ff85e22cb6225ccc454728facfcb70531"

CROS_GO_PACKAGES=(
	"github.com/orcaman/writerseeker"
)

inherit cros-go

DESCRIPTION="WriterSeeker is the in-memory io.WriteSeeker implementation missing in the standard lib"
HOMEPAGE="https://github.com/orcaman/writerseeker"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND="${DEPEND}"
