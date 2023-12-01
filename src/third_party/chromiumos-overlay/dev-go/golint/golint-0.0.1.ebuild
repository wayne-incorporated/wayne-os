# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="go.googlesource.com/lint:golang.org/x/lint 6edffad5e6160f5949cdefc81710b2706fbcd4f6"

CROS_GO_BINARIES=(
	"golang.org/x/lint/golint"
)

CROS_GO_PACKAGES=(
	"golang.org/x/lint"
	"golang.org/x/lint/golint"
)

inherit cros-go

DESCRIPTION="A linter for Go source code"
HOMEPAGE="https://github.com/golang/lint"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="dev-go/go-tools"
RDEPEND=""
