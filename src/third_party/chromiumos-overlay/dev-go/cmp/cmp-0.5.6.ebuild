# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/google/go-cmp v${PV}"

CROS_GO_PACKAGES=(
	"github.com/google/go-cmp/..."
)

inherit cros-go

DESCRIPTION="Package for comparing Go values in tests"
HOMEPAGE="https://github.com/google/go-cmp"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="dev-go/xerrors"
RDEPEND=""
