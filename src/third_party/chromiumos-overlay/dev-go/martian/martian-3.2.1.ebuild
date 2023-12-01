# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/google/martian:github.com/google/martian/v3 v${PV}"

CROS_GO_PACKAGES=(
	"github.com/google/martian/v3/..."
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="Martian Proxy is a programmable HTTP proxy designed to be used for testing."
HOMEPAGE="https://github.com/google/martian"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/protobuf
	dev-go/protobuf-legacy-api
	dev-go/snappy
	dev-go/net
	dev-go/grpc
"
RDEPEND=""
