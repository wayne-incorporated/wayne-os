# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/google/uuid v${PV}"

CROS_GO_PACKAGES=(
	"github.com/google/uuid/..."
)

inherit cros-go

DESCRIPTION="Go package for UUIDs based on RFC 4122 and DCE 1.1: Authentication and Security Services."
HOMEPAGE="https://github.com/google/uuid"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
