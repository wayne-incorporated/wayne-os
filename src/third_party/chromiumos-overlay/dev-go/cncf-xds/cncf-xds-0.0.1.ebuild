# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/cncf/xds:github.com/cncf/xds 01c748900fbb8fd467c4f091385123c4715312fb"

CROS_GO_PACKAGES=(
	"github.com/cncf/xds/go/udpa/annotations"
	"github.com/cncf/xds/go/xds/annotations/v3"
	"github.com/cncf/xds/go/xds/core/v3"
	"github.com/cncf/xds/go/xds/data/orca/v3"
	"github.com/cncf/xds/go/xds/type/matcher/v3"
	"github.com/cncf/xds/go/xds/type/v3"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="xDS API Working Group (xDS-WG)"
HOMEPAGE="https://github.com/cncf/xds"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks"

DEPEND="
	dev-go/ep-pvg
"
RDEPEND="${DEPEND}"
