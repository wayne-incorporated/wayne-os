# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/kisielk/errcheck v${PV}"

CROS_GO_PACKAGES=(
	"github.com/kisielk/errcheck"
	"github.com/kisielk/errcheck/errcheck"
)

CROS_GO_BINARIES=(
	"github.com/kisielk/errcheck"
)

inherit cros-go

DESCRIPTION=" errcheck checks that you checked errors. "
HOMEPAGE="https://github.com/kisielk/errcheck"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"
DEPEND="
	dev-go/go-tools
"
RDEPEND="!<=dev-go/docker-20.10.8-r1"
