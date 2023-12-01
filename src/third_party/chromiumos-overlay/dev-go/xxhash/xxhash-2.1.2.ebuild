# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/cespare/xxhash:github.com/cespare/xxhash/v2 v${PV}"

CROS_GO_PACKAGES=(
	"github.com/cespare/xxhash/v2"
)

inherit cros-go

DESCRIPTION="A Go implementation of the 64-bit xxHash algorithm (XXH64)"
HOMEPAGE="https://github.com/cespare/xxhash"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND="${DEPEND}"
