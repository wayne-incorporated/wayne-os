# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

# The dev-go/grpc* packages are all built from this repo.  They should
# be updated together.
CROS_GO_SOURCE="github.com/grpc/grpc-go:google.golang.org/grpc v${PV}"

CROS_GO_PACKAGES=(
	"google.golang.org/grpc/cmd/protoc-gen-go-grpc"
)

CROS_GO_BINARIES=(
	"google.golang.org/grpc/cmd/protoc-gen-go-grpc"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="This tool generates Go language bindings of services in protobuf definition files for gRPC."
HOMEPAGE="https://grpc.io/"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="dev-go/protobuf"
RDEPEND=""
