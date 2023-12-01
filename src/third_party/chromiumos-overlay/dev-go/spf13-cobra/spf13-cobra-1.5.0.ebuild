# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/spf13/cobra v${PV}"

CROS_GO_PACKAGES=(
	"github.com/spf13/cobra"
)

inherit cros-go

DESCRIPTION="Cobra is a library for creating powerful modern CLI applications.

Cobra is a library providing a simple interface to create powerful modern CLI
interfaces similar to git & go tools.
"
HOMEPAGE="https://github.com/spf13/cobra"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/spf13-pflag
	dev-go/go-md2man
	dev-go/mousetrap
"
RDEPEND=""
