# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="go.googlesource.com/exp:golang.org/x/exp 316c7553db56"

CROS_GO_PACKAGES=(
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/slices"
	"golang.org/x/exp/maps"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="Go experimental libraries"
HOMEPAGE="https://golang.org/x/exp"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/cmp
	dev-go/mod
	dev-go/go-tools
"
