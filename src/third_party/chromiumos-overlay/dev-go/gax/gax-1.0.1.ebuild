# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

# these are v1.0 compatible bindings implemented using the v2 API
# and shipped together with v2, see the dev-go/gax:0 dependency
CROS_GO_SOURCE="github.com/googleapis/gax-go v2.7.0"

CROS_GO_PACKAGES=(
	"github.com/googleapis/gax-go"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="Google API Extensions for Go"
HOMEPAGE="https://github.com/googleapis/gax-go"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="1"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/gax:0
"
RDEPEND="${DEPEND}"
