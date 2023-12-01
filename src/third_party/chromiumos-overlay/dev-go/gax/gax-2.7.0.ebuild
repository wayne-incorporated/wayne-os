# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/googleapis/gax-go v${PV}"

CROS_GO_PACKAGES=(
	"github.com/googleapis/gax-go/v2"
	"github.com/googleapis/gax-go/v2/internal"
	"github.com/googleapis/gax-go/v2/apierror"
	"github.com/googleapis/gax-go/v2/apierror/internal/proto"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="Google API Extensions for Go"
HOMEPAGE="https://github.com/googleapis/gax-go"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/gapi
	dev-go/genproto
	dev-go/go-tools
	dev-go/golint
	dev-go/grpc
	dev-go/net
	dev-go/protobuf
	dev-go/yaml:0
"
RDEPEND="${DEPEND}"
