# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/urfave/cli v${PV}"

CROS_GO_PACKAGES=(
	"github.com/urfave/cli"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="A simple, fast, and fun package for building command line apps in Go"
HOMEPAGE="https://github.com/urfave/cli"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND="
	dev-go/toml
	dev-go/yaml:0
	dev-go/go-md2man
"
RDEPEND=""
