# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/golang/mock v${PV}"

CROS_GO_PACKAGES=(
	"github.com/golang/mock/gomock"
	"github.com/golang/mock/gomock/internal/mock_gomock"
	"github.com/golang/mock/mockgen/model"
)

CROS_GO_BINARIES=(
	"github.com/golang/mock/mockgen"
)

inherit cros-go

DESCRIPTION="A mocking framework for the Go programming language"
HOMEPAGE="https://github.com/golang/mock"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/mod
	dev-go/go-tools
"
RDEPEND=""
