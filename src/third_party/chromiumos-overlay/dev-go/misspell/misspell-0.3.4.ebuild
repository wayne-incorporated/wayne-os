# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/client9/misspell v${PV}"

CROS_GO_PACKAGES=(
	"github.com/client9/misspell"
)

inherit cros-go

DESCRIPTION="Correct commonly misspelled English words... quickly."
HOMEPAGE="https://github.com/client9/misspell"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
