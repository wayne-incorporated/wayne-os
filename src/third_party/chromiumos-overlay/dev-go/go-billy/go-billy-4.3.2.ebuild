# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/src-d/go-billy:gopkg.in/src-d/go-billy.v4 v${PV}"

CROS_GO_PACKAGES=(
	"gopkg.in/src-d/go-billy.v4/..."
)

PATCHES=(
	"${FILESDIR}/0001-build-with-latest-go-versions-and-clean-go.mod.patch"
)

inherit cros-go

DESCRIPTION="The missing interface filesystem abstraction for Go"
HOMEPAGE="https://github.com/src-d/go-billy"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/pretty
	dev-go/pty
	dev-go/go-sys
	dev-go/check
"
RDEPEND="${DEPEND}"
